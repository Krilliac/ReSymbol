//! The safe live-debug session worker.
//!
//! `LinuxDebugSession` drives execution control, register/memory access, and
//! software breakpoints over any [`PtraceOps`] implementation. It contains no
//! `unsafe` code: the real backend performs FFI, and tests substitute an
//! in-memory mock. The breakpoint algorithm follows the same
//! compare-before-write discipline the debugger crate's
//! `SoftwareBreakpointStateMachine` encodes (save the original byte, write
//! `INT3` only after confirming the expected byte, and on a hit restore the
//! original byte, rewind `RIP`, single-step, then re-arm).

use std::collections::BTreeMap;

use crate::types::{
    BREAKPOINT_BYTE, DR_ADDRESS_OFFSETS, DR6_OFFSET, DR7_OFFSET, HARDWARE_SLOTS, HardwareKind,
    HostError, MAX_MEMORY_TRANSFER_BYTES, MAX_SOFTWARE_BREAKPOINTS, PtraceOps, StopEvent,
    WaitOutcome, X64Registers,
};

/// One armed software breakpoint: its address and the original byte it hides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArmedBreakpoint {
    original_byte: u8,
}

/// One occupied hardware debug-register slot (`DR0`-`DR3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HardwareSlot {
    /// The watched / breakpoint address programmed into `DRn`.
    address: u64,
    /// The condition (execute / write / read-write) encoded in `DR7`.
    kind: HardwareKind,
}

/// A live debug session over a stopped, ptrace-controlled target.
#[derive(Debug)]
pub struct LinuxDebugSession<O: PtraceOps> {
    ops: O,
    breakpoints: BTreeMap<u64, ArmedBreakpoint>,
    /// The four hardware slots, indexed by `DRn`; `None` means free.
    hardware: [Option<HardwareSlot>; HARDWARE_SLOTS],
    alive: bool,
}

impl<O: PtraceOps> LinuxDebugSession<O> {
    /// Wrap a backend whose target is already in its initial ptrace-stop.
    #[must_use]
    pub fn new(ops: O) -> Self {
        Self {
            ops,
            breakpoints: BTreeMap::new(),
            hardware: [None; HARDWARE_SLOTS],
            alive: true,
        }
    }

    /// The target process id.
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.ops.pid()
    }

    /// Whether the target is still alive.
    #[must_use]
    pub const fn is_alive(&self) -> bool {
        self.alive
    }

    /// The addresses of all currently armed software breakpoints, sorted.
    #[must_use]
    pub fn armed_breakpoints(&self) -> Vec<u64> {
        self.breakpoints.keys().copied().collect()
    }

    /// The `(address, kind)` of every occupied hardware slot, in slot order.
    #[must_use]
    pub fn hardware_slots(&self) -> Vec<(u64, HardwareKind)> {
        self.hardware
            .iter()
            .flatten()
            .map(|slot| (slot.address, slot.kind))
            .collect()
    }

    /// Arm a hardware *execute* breakpoint at `address` (`DR7` condition `00`,
    /// length 1). Fails with [`HostError::NoHardwareSlot`] when all four slots
    /// are occupied.
    pub fn set_hw_breakpoint(&mut self, address: u64) -> Result<(), HostError> {
        self.arm_hardware(address, 1, HardwareKind::Execute)
    }

    /// Arm a hardware data watchpoint of `len` bytes (one of `{1, 2, 4, 8}`) at
    /// `address` with the given [`HardwareKind`] (`Write` or `ReadWrite`).
    pub fn set_watchpoint(
        &mut self,
        address: u64,
        len: u64,
        kind: HardwareKind,
    ) -> Result<(), HostError> {
        self.arm_hardware(address, len, kind)
    }

    /// Release the hardware slot armed at `address` (breakpoint or watchpoint):
    /// clear its `DR7` enable/condition/length bits and zero its `DRn`.
    pub fn clear_hw(&mut self, address: u64) -> Result<(), HostError> {
        self.require_alive()?;
        let slot = self
            .hardware
            .iter()
            .position(|slot| slot.is_some_and(|slot| slot.address == address))
            .ok_or(HostError::HardwareBreakpointMissing { address })?;

        let mut dr7 = self.ops.peek_user(DR7_OFFSET)?;
        dr7 = clear_dr7_slot(dr7, slot);
        self.ops.poke_user(DR7_OFFSET, dr7)?;
        self.ops.poke_user(DR_ADDRESS_OFFSETS[slot], 0)?;
        self.hardware[slot] = None;
        Ok(())
    }

    /// Allocate a free `DRn` slot, program the address, and set the slot's
    /// enable, condition, and length bits in `DR7`.
    fn arm_hardware(
        &mut self,
        address: u64,
        len: u64,
        kind: HardwareKind,
    ) -> Result<(), HostError> {
        self.require_alive()?;
        if self
            .hardware
            .iter()
            .any(|slot| slot.is_some_and(|slot| slot.address == address))
        {
            return Err(HostError::HardwareBreakpointExists { address });
        }
        let length_bits = encode_length(kind, len)?;
        let condition_bits = encode_condition(kind);
        let slot =
            self.hardware
                .iter()
                .position(Option::is_none)
                .ok_or(HostError::NoHardwareSlot {
                    limit: HARDWARE_SLOTS,
                })?;

        self.ops.poke_user(DR_ADDRESS_OFFSETS[slot], address)?;
        let mut dr7 = self.ops.peek_user(DR7_OFFSET)?;
        dr7 = clear_dr7_slot(dr7, slot);
        // Local-enable bit for this slot: bit 2*n.
        dr7 |= 1u64 << (2 * slot);
        // Condition (bits 16+4n..) and length (bits 18+4n..) nibble.
        let nibble = u64::from(condition_bits) | (u64::from(length_bits) << 2);
        dr7 |= nibble << (16 + 4 * slot);
        self.ops.poke_user(DR7_OFFSET, dr7)?;

        self.hardware[slot] = Some(HardwareSlot { address, kind });
        Ok(())
    }

    /// Read the full register file.
    pub fn read_registers(&mut self) -> Result<X64Registers, HostError> {
        self.require_alive()?;
        self.ops.read_registers()
    }

    /// Write the full register file.
    pub fn write_registers(&mut self, registers: &X64Registers) -> Result<(), HostError> {
        self.require_alive()?;
        self.ops.write_registers(registers)
    }

    /// Read `len` bytes at `address`, transparently substituting the original
    /// bytes hidden by any armed breakpoints that overlap the range.
    pub fn read_memory(&mut self, address: u64, len: usize) -> Result<Vec<u8>, HostError> {
        self.require_alive()?;
        if len > MAX_MEMORY_TRANSFER_BYTES {
            return Err(HostError::TransferTooLarge {
                requested: len,
                limit: MAX_MEMORY_TRANSFER_BYTES,
            });
        }
        let mut bytes = self.ops.read_memory(address, len)?;
        for (&bp_address, armed) in &self.breakpoints {
            if bp_address >= address && bp_address < address.saturating_add(len as u64) {
                let offset = (bp_address - address) as usize;
                if let Some(slot) = bytes.get_mut(offset) {
                    *slot = armed.original_byte;
                }
            }
        }
        Ok(bytes)
    }

    /// Write `bytes` at `address` (bypassing page protections). Overlapping
    /// armed breakpoints keep their `INT3` in the target but have their saved
    /// original byte updated so a later removal restores the new value.
    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), HostError> {
        self.require_alive()?;
        if bytes.len() > MAX_MEMORY_TRANSFER_BYTES {
            return Err(HostError::TransferTooLarge {
                requested: bytes.len(),
                limit: MAX_MEMORY_TRANSFER_BYTES,
            });
        }
        self.ops.write_memory(address, bytes)?;
        for (&bp_address, armed) in &mut self.breakpoints {
            if bp_address >= address && bp_address < address.saturating_add(bytes.len() as u64) {
                let offset = (bp_address - address) as usize;
                armed.original_byte = bytes[offset];
                // Re-assert the INT3 the caller's write just clobbered.
                self.ops.write_memory(bp_address, &[BREAKPOINT_BYTE])?;
            }
        }
        Ok(())
    }

    /// Arm a software breakpoint at `address`. Reads the current byte, requires
    /// it to differ from `INT3` (already-armed guard), saves it, and writes
    /// `INT3`, verifying the write took effect.
    pub fn set_breakpoint(&mut self, address: u64) -> Result<(), HostError> {
        self.require_alive()?;
        if self.breakpoints.contains_key(&address) {
            return Err(HostError::BreakpointExists { address });
        }
        if self.breakpoints.len() >= MAX_SOFTWARE_BREAKPOINTS {
            return Err(HostError::BreakpointCapacity {
                limit: MAX_SOFTWARE_BREAKPOINTS,
            });
        }
        let original_byte = self.read_raw_byte(address)?;
        if original_byte == BREAKPOINT_BYTE {
            return Err(HostError::UnexpectedByte {
                address,
                found: original_byte,
                expected: 0x00,
            });
        }
        self.ops.write_memory(address, &[BREAKPOINT_BYTE])?;
        let written = self.read_raw_byte(address)?;
        if written != BREAKPOINT_BYTE {
            // Best-effort rollback before failing closed.
            let _ = self.ops.write_memory(address, &[original_byte]);
            return Err(HostError::UnexpectedByte {
                address,
                found: written,
                expected: BREAKPOINT_BYTE,
            });
        }
        self.breakpoints
            .insert(address, ArmedBreakpoint { original_byte });
        Ok(())
    }

    /// Remove a software breakpoint, restoring the original byte with a
    /// compare-before-write check that the `INT3` is still present.
    pub fn clear_breakpoint(&mut self, address: u64) -> Result<(), HostError> {
        self.require_alive()?;
        let armed = self
            .breakpoints
            .get(&address)
            .copied()
            .ok_or(HostError::BreakpointMissing { address })?;
        let current = self.read_raw_byte(address)?;
        if current != BREAKPOINT_BYTE {
            return Err(HostError::UnexpectedByte {
                address,
                found: current,
                expected: BREAKPOINT_BYTE,
            });
        }
        self.ops.write_memory(address, &[armed.original_byte])?;
        self.breakpoints.remove(&address);
        Ok(())
    }

    /// Resume the target until it next stops. If it stops on an armed
    /// breakpoint, `RIP` is rewound to the breakpoint address and
    /// [`WaitOutcome::BreakpointHit`] is returned.
    pub fn continue_execution(&mut self) -> Result<WaitOutcome, HostError> {
        self.require_alive()?;
        self.ops.cont(0)?;
        self.wait_and_classify()
    }

    /// Single-step one instruction. If currently stopped at an armed
    /// breakpoint, the original byte is restored for the step and the `INT3`
    /// is re-armed afterward.
    pub fn single_step(&mut self) -> Result<WaitOutcome, HostError> {
        self.require_alive()?;
        let registers = self.ops.read_registers()?;
        let at_breakpoint = self
            .breakpoints
            .contains_key(&registers.instruction_pointer());
        if at_breakpoint {
            let event = self.step_off_breakpoint(registers.instruction_pointer())?;
            return Ok(if event.is_terminal() {
                WaitOutcome::Finished(event)
            } else {
                WaitOutcome::Stopped(event)
            });
        }
        self.ops.single_step(0)?;
        self.wait_and_classify()
    }

    /// Detach, leaving every breakpoint removed and the target running.
    pub fn detach(mut self) -> Result<(), HostError> {
        if self.alive {
            let addresses: Vec<u64> = self.breakpoints.keys().copied().collect();
            for address in addresses {
                let _ = self.clear_breakpoint(address);
            }
            let hardware: Vec<u64> = self
                .hardware
                .iter()
                .flatten()
                .map(|slot| slot.address)
                .collect();
            for address in hardware {
                let _ = self.clear_hw(address);
            }
            self.ops.detach()?;
        }
        Ok(())
    }

    /// Kill the target.
    pub fn kill(mut self) -> Result<(), HostError> {
        if self.alive {
            self.ops.kill()?;
            self.alive = false;
        }
        Ok(())
    }

    /// If any hardware slot fired, read `DR6`, map the lowest set status bit to
    /// its slot's address/kind, clear `DR6`, and return the outcome. Returns
    /// `Ok(None)` when no slots are armed or none fired.
    fn check_hardware_hit(&mut self) -> Result<Option<WaitOutcome>, HostError> {
        if self.hardware.iter().all(Option::is_none) {
            return Ok(None);
        }
        let status = self.ops.peek_user(DR6_OFFSET)?;
        let mut outcome = None;
        for (slot, armed) in self.hardware.iter().enumerate() {
            if status & (1u64 << slot) == 0 {
                continue;
            }
            if let Some(armed) = armed {
                outcome = Some(match armed.kind {
                    HardwareKind::Execute => WaitOutcome::BreakpointHit {
                        address: armed.address,
                    },
                    HardwareKind::Write | HardwareKind::ReadWrite => WaitOutcome::WatchpointHit {
                        address: armed.address,
                    },
                });
                break;
            }
        }
        if outcome.is_some() {
            // Acknowledge the stop by clearing the DR6 status bits.
            self.ops.poke_user(DR6_OFFSET, 0)?;
        }
        Ok(outcome)
    }

    fn wait_and_classify(&mut self) -> Result<WaitOutcome, HostError> {
        let event = self.ops.wait()?;
        match event {
            StopEvent::Exited { .. } | StopEvent::Terminated { .. } => {
                self.alive = false;
                Ok(WaitOutcome::Finished(event))
            }
            StopEvent::Stopped { signal } if signal == crate::types::SIGTRAP => {
                // A hardware stop is signalled by DR6; check it before the
                // software-breakpoint RIP heuristic, since a hardware execute
                // trap fires with RIP already at the breakpoint (no rewind).
                if let Some(outcome) = self.check_hardware_hit()? {
                    return Ok(outcome);
                }
                let mut registers = self.ops.read_registers()?;
                let candidate = registers.instruction_pointer().wrapping_sub(1);
                if self.breakpoints.contains_key(&candidate) {
                    registers.set_instruction_pointer(candidate);
                    self.ops.write_registers(&registers)?;
                    Ok(WaitOutcome::BreakpointHit { address: candidate })
                } else {
                    Ok(WaitOutcome::Stopped(event))
                }
            }
            StopEvent::Stopped { .. } => Ok(WaitOutcome::Stopped(event)),
        }
    }

    /// Restore the original byte, single-step over the instruction, then
    /// re-arm the `INT3`. Requires `RIP` to already sit at `address`. Returns
    /// the stop event produced by the step.
    fn step_off_breakpoint(&mut self, address: u64) -> Result<StopEvent, HostError> {
        let armed = self
            .breakpoints
            .get(&address)
            .copied()
            .ok_or(HostError::BreakpointMissing { address })?;
        self.ops.write_memory(address, &[armed.original_byte])?;
        self.ops.single_step(0)?;
        let event = self.ops.wait()?;
        if event.is_terminal() {
            self.alive = false;
            return Ok(event);
        }
        // Re-arm the breakpoint the target just stepped past.
        self.ops.write_memory(address, &[BREAKPOINT_BYTE])?;
        Ok(event)
    }

    fn read_raw_byte(&mut self, address: u64) -> Result<u8, HostError> {
        let bytes = self.ops.read_memory(address, 1)?;
        bytes.first().copied().ok_or(HostError::Syscall {
            operation: "read_memory",
            errno: 0,
        })
    }

    fn require_alive(&self) -> Result<(), HostError> {
        if self.alive {
            Ok(())
        } else {
            Err(HostError::TargetNotAlive)
        }
    }
}

/// Clear a slot's enable bit (`2*n`) and its four-bit condition/length nibble
/// (`16+4*n`), leaving the other slots' `DR7` bits untouched.
fn clear_dr7_slot(dr7: u64, slot: usize) -> u64 {
    let mut cleared = dr7;
    // Local-enable bit for this slot.
    cleared &= !(1u64 << (2 * slot));
    // Condition (2 bits) + length (2 bits) nibble for this slot.
    cleared &= !(0b1111u64 << (16 + 4 * slot));
    cleared
}

/// The two-bit `DR7` `R/W` condition encoding for a [`HardwareKind`].
fn encode_condition(kind: HardwareKind) -> u8 {
    match kind {
        HardwareKind::Execute => 0b00,
        HardwareKind::Write => 0b01,
        HardwareKind::ReadWrite => 0b11,
    }
}

/// The two-bit `DR7` `LEN` encoding for a `(kind, len)` pair. Execute
/// breakpoints must use length 1; watchpoints accept `{1, 2, 4, 8}`.
fn encode_length(kind: HardwareKind, len: u64) -> Result<u8, HostError> {
    if matches!(kind, HardwareKind::Execute) {
        return if len == 1 {
            Ok(0b00)
        } else {
            Err(HostError::InvalidWatchpointLength { length: len })
        };
    }
    match len {
        1 => Ok(0b00),
        2 => Ok(0b01),
        4 => Ok(0b11),
        8 => Ok(0b10),
        _ => Err(HostError::InvalidWatchpointLength { length: len }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic in-memory ptrace target for exercising the worker.
    struct MockTarget {
        pid: i32,
        memory: BTreeMap<u64, u8>,
        registers: X64Registers,
        alive: bool,
        /// Queue of stop events the next `wait` calls will return.
        pending: Vec<StopEvent>,
        /// The ptrace USER area, keyed by byte offset (the debug registers).
        user: BTreeMap<usize, u64>,
    }

    impl MockTarget {
        fn new(base: u64, code: &[u8]) -> Self {
            let mut memory = BTreeMap::new();
            for (offset, byte) in code.iter().enumerate() {
                memory.insert(base + offset as u64, *byte);
            }
            let mut registers = X64Registers::default();
            registers.set_instruction_pointer(base);
            Self {
                pid: 4242,
                memory,
                registers,
                alive: true,
                pending: Vec::new(),
                user: BTreeMap::new(),
            }
        }

        fn byte(&self, address: u64) -> u8 {
            self.memory.get(&address).copied().unwrap_or(0)
        }

        fn user(&self, offset: usize) -> u64 {
            self.user.get(&offset).copied().unwrap_or(0)
        }
    }

    impl PtraceOps for MockTarget {
        fn pid(&self) -> i32 {
            self.pid
        }

        fn cont(&mut self, _signal: i32) -> Result<(), HostError> {
            // Simulate running to the next breakpoint byte at or after RIP.
            let mut address = self.registers.instruction_pointer();
            loop {
                match self.byte(address) {
                    BREAKPOINT_BYTE => {
                        // Stop as if INT3 executed: RIP advances past the 0xCC.
                        self.registers.set_instruction_pointer(address + 1);
                        self.pending.push(StopEvent::Stopped {
                            signal: crate::types::SIGTRAP,
                        });
                        return Ok(());
                    }
                    _ if !self.memory.contains_key(&address) => {
                        self.alive = false;
                        self.pending.push(StopEvent::Exited { code: 0 });
                        return Ok(());
                    }
                    _ => address += 1,
                }
            }
        }

        fn single_step(&mut self, _signal: i32) -> Result<(), HostError> {
            let next = self.registers.instruction_pointer() + 1;
            self.registers.set_instruction_pointer(next);
            self.pending.push(StopEvent::Stopped {
                signal: crate::types::SIGTRAP,
            });
            Ok(())
        }

        fn wait(&mut self) -> Result<StopEvent, HostError> {
            Ok(self.pending.pop().unwrap_or(StopEvent::Stopped {
                signal: crate::types::SIGTRAP,
            }))
        }

        fn read_registers(&mut self) -> Result<X64Registers, HostError> {
            Ok(self.registers)
        }

        fn write_registers(&mut self, registers: &X64Registers) -> Result<(), HostError> {
            self.registers = *registers;
            Ok(())
        }

        fn read_memory(&mut self, address: u64, len: usize) -> Result<Vec<u8>, HostError> {
            Ok((0..len as u64).map(|i| self.byte(address + i)).collect())
        }

        fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), HostError> {
            for (i, byte) in bytes.iter().enumerate() {
                self.memory.insert(address + i as u64, *byte);
            }
            Ok(())
        }

        fn peek_user(&mut self, offset: usize) -> Result<u64, HostError> {
            Ok(self.user(offset))
        }

        fn poke_user(&mut self, offset: usize, value: u64) -> Result<(), HostError> {
            self.user.insert(offset, value);
            Ok(())
        }

        fn detach(&mut self) -> Result<(), HostError> {
            Ok(())
        }

        fn kill(&mut self) -> Result<(), HostError> {
            self.alive = false;
            Ok(())
        }
    }

    #[test]
    fn set_breakpoint_saves_original_and_writes_int3() {
        let base = 0x1000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0x90, 0x90, 0xC3]));
        session.set_breakpoint(base + 1).unwrap();
        assert_eq!(session.armed_breakpoints(), vec![base + 1]);
        // The raw target byte is now INT3...
        assert_eq!(session.ops.byte(base + 1), BREAKPOINT_BYTE);
        // ...but a memory read transparently restores the original 0x90.
        assert_eq!(session.read_memory(base + 1, 1).unwrap(), vec![0x90]);
    }

    #[test]
    fn duplicate_breakpoint_is_rejected() {
        let base = 0x2000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0x90, 0xC3]));
        session.set_breakpoint(base).unwrap();
        assert_eq!(
            session.set_breakpoint(base),
            Err(HostError::BreakpointExists { address: base })
        );
    }

    #[test]
    fn clear_breakpoint_restores_original_byte() {
        let base = 0x3000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0x90, 0xC3]));
        session.set_breakpoint(base).unwrap();
        session.clear_breakpoint(base).unwrap();
        assert!(session.armed_breakpoints().is_empty());
        assert_eq!(session.ops.byte(base), 0x90);
    }

    #[test]
    fn continue_reports_breakpoint_hit_with_rewound_rip() {
        let base = 0x4000;
        // nop; nop; ret
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0x90, 0x90, 0xC3]));
        session.set_breakpoint(base + 1).unwrap();
        match session.continue_execution().unwrap() {
            WaitOutcome::BreakpointHit { address } => assert_eq!(address, base + 1),
            other => panic!("expected breakpoint hit, got {other:?}"),
        }
        // RIP was rewound to the breakpoint address.
        assert_eq!(
            session.read_registers().unwrap().instruction_pointer(),
            base + 1
        );
    }

    #[test]
    fn single_step_off_breakpoint_rearms_it() {
        let base = 0x5000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0x90, 0x90, 0xC3]));
        session.set_breakpoint(base).unwrap();
        // RIP starts at the breakpoint; stepping restores, steps, re-arms.
        session.single_step().unwrap();
        assert_eq!(session.ops.byte(base), BREAKPOINT_BYTE);
        assert_eq!(session.armed_breakpoints(), vec![base]);
    }

    #[test]
    fn register_round_trip() {
        let base = 0x6000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0xC3]));
        let mut regs = session.read_registers().unwrap();
        regs.rax = 0xDEAD_BEEF;
        regs.set_instruction_pointer(base + 0x10);
        session.write_registers(&regs).unwrap();
        let read_back = session.read_registers().unwrap();
        assert_eq!(read_back.rax, 0xDEAD_BEEF);
        assert_eq!(read_back.instruction_pointer(), base + 0x10);
    }

    #[test]
    fn write_memory_over_breakpoint_keeps_int3_and_updates_saved_byte() {
        let base = 0x7000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0x90, 0x90, 0xC3]));
        session.set_breakpoint(base + 1).unwrap();
        // Overwrite the two bytes covering the breakpoint slot.
        session.write_memory(base, &[0x50, 0x51]).unwrap();
        // The INT3 is re-asserted in the target...
        assert_eq!(session.ops.byte(base + 1), BREAKPOINT_BYTE);
        // ...and a read shows the new logical byte, not the INT3.
        assert_eq!(session.read_memory(base + 1, 1).unwrap(), vec![0x51]);
        // Clearing restores the freshly written byte.
        session.clear_breakpoint(base + 1).unwrap();
        assert_eq!(session.ops.byte(base + 1), 0x51);
    }

    #[test]
    fn operations_fail_closed_after_target_exits() {
        let base = 0x8000;
        // A single ret with no breakpoint: continue runs off the end -> exit.
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0x90]));
        match session.continue_execution().unwrap() {
            WaitOutcome::Finished(StopEvent::Exited { code }) => assert_eq!(code, 0),
            other => panic!("expected exit, got {other:?}"),
        }
        assert!(!session.is_alive());
        assert_eq!(session.read_registers(), Err(HostError::TargetNotAlive));
    }

    #[test]
    fn hw_execute_breakpoint_programs_dr0_and_dr7() {
        use crate::types::{DR_ADDRESS_OFFSETS, DR7_OFFSET};
        let base = 0x40_0000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0x90, 0xC3]));
        session.set_hw_breakpoint(base).unwrap();

        // DR0 holds the address; slot 0's local-enable bit (bit 0) is set.
        assert_eq!(session.ops.user(DR_ADDRESS_OFFSETS[0]), base);
        let dr7 = session.ops.user(DR7_OFFSET);
        assert_eq!(dr7 & 0b1, 0b1, "L0 enable bit set");
        // Execute condition (00) + length 1 (00) => nibble at bit 16 is 0.
        assert_eq!((dr7 >> 16) & 0b1111, 0b0000);
        assert_eq!(
            session.hardware_slots(),
            vec![(base, HardwareKind::Execute)]
        );
    }

    #[test]
    fn write_watchpoint_programs_condition_and_length() {
        use crate::types::DR7_OFFSET;
        let base = 0x50_0000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0xC3]));
        session
            .set_watchpoint(base + 0x100, 4, HardwareKind::Write)
            .unwrap();

        let dr7 = session.ops.user(DR7_OFFSET);
        assert_eq!(dr7 & 0b1, 0b1, "L0 enable bit set");
        // Write condition (01) + length 4 (11) => nibble 0b1101 at bit 16.
        assert_eq!((dr7 >> 16) & 0b1111, 0b1101);
    }

    #[test]
    fn read_write_watchpoint_encodes_len_eight() {
        use crate::types::DR7_OFFSET;
        let base = 0x51_0000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0xC3]));
        session
            .set_watchpoint(base, 8, HardwareKind::ReadWrite)
            .unwrap();
        let dr7 = session.ops.user(DR7_OFFSET);
        // ReadWrite condition (11) + length 8 (10) => nibble 0b1011.
        assert_eq!((dr7 >> 16) & 0b1111, 0b1011);
    }

    #[test]
    fn invalid_watchpoint_length_is_rejected() {
        let base = 0x52_0000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0xC3]));
        assert_eq!(
            session.set_watchpoint(base, 3, HardwareKind::Write),
            Err(HostError::InvalidWatchpointLength { length: 3 })
        );
        // An execute breakpoint may only cover one byte.
        assert_eq!(
            session.set_watchpoint(base, 2, HardwareKind::Execute),
            Err(HostError::InvalidWatchpointLength { length: 2 })
        );
    }

    #[test]
    fn clear_hw_frees_slot_and_dr7_bits() {
        use crate::types::{DR_ADDRESS_OFFSETS, DR7_OFFSET};
        let base = 0x60_0000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0xC3]));
        session.set_hw_breakpoint(base).unwrap();
        session.clear_hw(base).unwrap();

        assert!(session.hardware_slots().is_empty());
        assert_eq!(session.ops.user(DR_ADDRESS_OFFSETS[0]), 0);
        // Every enable/condition/length bit for slot 0 is cleared.
        let dr7 = session.ops.user(DR7_OFFSET);
        assert_eq!(dr7 & 0b1, 0);
        assert_eq!((dr7 >> 16) & 0b1111, 0);
        // Clearing an unarmed address reports the missing error.
        assert_eq!(
            session.clear_hw(base),
            Err(HostError::HardwareBreakpointMissing { address: base })
        );
    }

    #[test]
    fn duplicate_hw_breakpoint_is_rejected() {
        let base = 0x61_0000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0xC3]));
        session.set_hw_breakpoint(base).unwrap();
        assert_eq!(
            session.set_hw_breakpoint(base),
            Err(HostError::HardwareBreakpointExists { address: base })
        );
    }

    #[test]
    fn fifth_hardware_allocation_is_rejected() {
        let base = 0x70_0000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0xC3]));
        for index in 0..4u64 {
            session.set_hw_breakpoint(base + index * 8).unwrap();
        }
        assert_eq!(session.hardware_slots().len(), 4);
        assert_eq!(
            session.set_hw_breakpoint(base + 0x1000),
            Err(HostError::NoHardwareSlot { limit: 4 })
        );
    }

    #[test]
    fn dr6_status_maps_execute_hit_to_breakpoint_outcome() {
        use crate::types::{DR6_OFFSET, SIGTRAP};
        let base = 0x80_0000;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0x90, 0xC3]));
        session.set_hw_breakpoint(base).unwrap();
        // Simulate the kernel: slot 0 fired (DR6 bit 0) and a SIGTRAP is pending.
        // RIP already sits at the breakpoint for a hardware execute trap.
        session.ops.user.insert(DR6_OFFSET, 0b0001);
        session
            .ops
            .pending
            .push(StopEvent::Stopped { signal: SIGTRAP });
        match session.wait_and_classify().unwrap() {
            WaitOutcome::BreakpointHit { address } => assert_eq!(address, base),
            other => panic!("expected hardware breakpoint hit, got {other:?}"),
        }
        // DR6 status bits were acknowledged (cleared).
        assert_eq!(session.ops.user(DR6_OFFSET), 0);
    }

    #[test]
    fn dr6_status_maps_watchpoint_hit_to_watchpoint_outcome() {
        use crate::types::{DR6_OFFSET, SIGTRAP};
        let base = 0x90_0000;
        let watched = base + 0x200;
        let mut session = LinuxDebugSession::new(MockTarget::new(base, &[0x90, 0xC3]));
        // Occupy slot 0 with an execute breakpoint, slot 1 with the watchpoint.
        session.set_hw_breakpoint(base).unwrap();
        session
            .set_watchpoint(watched, 4, HardwareKind::Write)
            .unwrap();
        // Slot 1 (DR6 bit 1) fired.
        session.ops.user.insert(DR6_OFFSET, 0b0010);
        session
            .ops
            .pending
            .push(StopEvent::Stopped { signal: SIGTRAP });
        match session.wait_and_classify().unwrap() {
            WaitOutcome::WatchpointHit { address } => assert_eq!(address, watched),
            other => panic!("expected watchpoint hit, got {other:?}"),
        }
    }
}
