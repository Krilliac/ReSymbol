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
    BREAKPOINT_BYTE, HostError, MAX_MEMORY_TRANSFER_BYTES, MAX_SOFTWARE_BREAKPOINTS, PtraceOps,
    StopEvent, WaitOutcome, X64Registers,
};

/// One armed software breakpoint: its address and the original byte it hides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArmedBreakpoint {
    original_byte: u8,
}

/// A live debug session over a stopped, ptrace-controlled target.
#[derive(Debug)]
pub struct LinuxDebugSession<O: PtraceOps> {
    ops: O,
    breakpoints: BTreeMap<u64, ArmedBreakpoint>,
    alive: bool,
}

impl<O: PtraceOps> LinuxDebugSession<O> {
    /// Wrap a backend whose target is already in its initial ptrace-stop.
    #[must_use]
    pub fn new(ops: O) -> Self {
        Self {
            ops,
            breakpoints: BTreeMap::new(),
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

    fn wait_and_classify(&mut self) -> Result<WaitOutcome, HostError> {
        let event = self.ops.wait()?;
        match event {
            StopEvent::Exited { .. } | StopEvent::Terminated { .. } => {
                self.alive = false;
                Ok(WaitOutcome::Finished(event))
            }
            StopEvent::Stopped { signal } if signal == crate::types::SIGTRAP => {
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
            }
        }

        fn byte(&self, address: u64) -> u8 {
            self.memory.get(&address).copied().unwrap_or(0)
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
}
