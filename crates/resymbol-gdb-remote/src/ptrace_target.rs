//! A [`RemoteTarget`] adapter over the Linux ptrace host, so the RSP server can
//! expose a live ptrace-controlled process to any GDB-compatible client.
//!
//! This module is Linux-only: it wraps
//! [`resymbol_linux_debug_host::LinuxDebugSession`] and translates between the
//! host's [`X64Registers`] and the amd64 `g`-packet, and between the host's
//! [`WaitOutcome`]/[`StopEvent`] and RSP [`StopReply`]s. It performs no FFI of
//! its own; all `unsafe` remains in the ptrace host and this crate's serial
//! module.

use crate::target::{Amd64CoreRegisters, RemoteTarget, StopReply, TargetError, WatchKind};
use resymbol_linux_debug_host::{
    HardwareKind, HostError, LinuxDebugSession, PtraceBackend, SIGTRAP, StopEvent, WaitOutcome,
    X64Registers,
};

/// GDB's `SIGTRAP` value, reported for breakpoint and single-step stops.
const GDB_SIGTRAP: u8 = 5;

/// Adapts a ptrace [`LinuxDebugSession`] to the [`RemoteTarget`] contract.
#[derive(Debug)]
pub struct PtraceRemoteTarget {
    session: LinuxDebugSession<PtraceBackend>,
    last_stop: StopReply,
}

impl PtraceRemoteTarget {
    /// Wrap a live ptrace session whose target is stopped at its entry.
    #[must_use]
    pub fn new(session: LinuxDebugSession<PtraceBackend>) -> Self {
        Self {
            session,
            last_stop: StopReply::Signal(GDB_SIGTRAP),
        }
    }

    /// Borrow the underlying session (e.g. to detach or kill it).
    #[must_use]
    pub fn session(&self) -> &LinuxDebugSession<PtraceBackend> {
        &self.session
    }

    /// Take back the underlying session.
    #[must_use]
    pub fn into_session(self) -> LinuxDebugSession<PtraceBackend> {
        self.session
    }

    /// Record and return the [`StopReply`] for a [`WaitOutcome`].
    fn record(&mut self, outcome: WaitOutcome) -> StopReply {
        let reply = outcome_to_reply(outcome);
        self.last_stop = reply;
        reply
    }
}

impl RemoteTarget for PtraceRemoteTarget {
    fn read_registers(&mut self) -> Result<Vec<u8>, TargetError> {
        let registers = self.session.read_registers().map_err(register_error)?;
        Ok(to_core(&registers).to_gpacket())
    }

    fn write_registers(&mut self, raw: &[u8]) -> Result<(), TargetError> {
        // Read-modify-write so the fields absent from the g-packet
        // (orig_rax, fs_base, gs_base) are preserved.
        let current = self.session.read_registers().map_err(register_error)?;
        let mut core = to_core(&current);
        core.apply_gpacket(raw)?;
        self.session
            .write_registers(&from_core(&core))
            .map_err(register_error)
    }

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, TargetError> {
        self.session.read_memory(addr, len).map_err(memory_error)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), TargetError> {
        self.session.write_memory(addr, data).map_err(memory_error)
    }

    fn cont(&mut self) -> Result<StopReply, TargetError> {
        let outcome = self.session.continue_execution().map_err(exec_error)?;
        Ok(self.record(outcome))
    }

    fn step(&mut self) -> Result<StopReply, TargetError> {
        let outcome = self.session.single_step().map_err(exec_error)?;
        Ok(self.record(outcome))
    }

    fn set_sw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError> {
        self.session.set_breakpoint(addr).map_err(breakpoint_error)
    }

    fn remove_sw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError> {
        self.session
            .clear_breakpoint(addr)
            .map_err(breakpoint_error)
    }

    fn set_hw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError> {
        self.session
            .set_hw_breakpoint(addr)
            .map_err(breakpoint_error)
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError> {
        self.session.clear_hw(addr).map_err(breakpoint_error)
    }

    fn set_watchpoint(&mut self, addr: u64, len: u64, kind: WatchKind) -> Result<(), TargetError> {
        self.session
            .set_watchpoint(addr, len, watch_to_hardware(kind))
            .map_err(breakpoint_error)
    }

    fn remove_watchpoint(
        &mut self,
        addr: u64,
        _len: u64,
        _kind: WatchKind,
    ) -> Result<(), TargetError> {
        // A slot is keyed by address; the length/kind are not needed to release
        // it (they must match what was armed).
        self.session.clear_hw(addr).map_err(breakpoint_error)
    }

    fn stop_reason(&mut self) -> StopReply {
        self.last_stop
    }
}

/// Map an RSP [`WatchKind`] onto a host [`HardwareKind`]. x86-64 debug registers
/// have no read-only condition, so a GDB read watchpoint (`Z3`) and an access
/// watchpoint (`Z4`) both become a read/write condition.
fn watch_to_hardware(kind: WatchKind) -> HardwareKind {
    match kind {
        WatchKind::Write => HardwareKind::Write,
        WatchKind::Read | WatchKind::Access => HardwareKind::ReadWrite,
    }
}

/// Translate a ptrace [`WaitOutcome`] to an RSP [`StopReply`].
fn outcome_to_reply(outcome: WaitOutcome) -> StopReply {
    match outcome {
        WaitOutcome::BreakpointHit { .. } | WaitOutcome::WatchpointHit { .. } => {
            StopReply::Signal(GDB_SIGTRAP)
        }
        WaitOutcome::Stopped(event) | WaitOutcome::Finished(event) => event_to_reply(event),
    }
}

/// Translate a ptrace [`StopEvent`] to an RSP [`StopReply`].
fn event_to_reply(event: StopEvent) -> StopReply {
    match event {
        StopEvent::Stopped { signal } => StopReply::Signal(signal_to_u8(signal)),
        StopEvent::Exited { code } => StopReply::Exited(clamp_u8(code)),
        StopEvent::Terminated { signal } => StopReply::Terminated(signal_to_u8(signal)),
    }
}

/// Map a signal number to a `u8`, defaulting `SIGTRAP` to GDB's value.
fn signal_to_u8(signal: i32) -> u8 {
    if signal == SIGTRAP {
        GDB_SIGTRAP
    } else {
        clamp_u8(signal)
    }
}

/// Clamp a signal/exit code into a `u8`.
fn clamp_u8(value: i32) -> u8 {
    u8::try_from(value & 0xff).unwrap_or(0)
}

/// Copy the host register file into the dependency-free core layout.
fn to_core(regs: &X64Registers) -> Amd64CoreRegisters {
    Amd64CoreRegisters {
        r15: regs.r15,
        r14: regs.r14,
        r13: regs.r13,
        r12: regs.r12,
        rbp: regs.rbp,
        rbx: regs.rbx,
        r11: regs.r11,
        r10: regs.r10,
        r9: regs.r9,
        r8: regs.r8,
        rax: regs.rax,
        rcx: regs.rcx,
        rdx: regs.rdx,
        rsi: regs.rsi,
        rdi: regs.rdi,
        orig_rax: regs.orig_rax,
        rip: regs.rip,
        cs: regs.cs,
        eflags: regs.eflags,
        rsp: regs.rsp,
        ss: regs.ss,
        fs_base: regs.fs_base,
        gs_base: regs.gs_base,
        ds: regs.ds,
        es: regs.es,
        fs: regs.fs,
        gs: regs.gs,
    }
}

/// Copy the core layout back into the host register file.
fn from_core(core: &Amd64CoreRegisters) -> X64Registers {
    X64Registers {
        r15: core.r15,
        r14: core.r14,
        r13: core.r13,
        r12: core.r12,
        rbp: core.rbp,
        rbx: core.rbx,
        r11: core.r11,
        r10: core.r10,
        r9: core.r9,
        r8: core.r8,
        rax: core.rax,
        rcx: core.rcx,
        rdx: core.rdx,
        rsi: core.rsi,
        rdi: core.rdi,
        orig_rax: core.orig_rax,
        rip: core.rip,
        cs: core.cs,
        eflags: core.eflags,
        rsp: core.rsp,
        ss: core.ss,
        fs_base: core.fs_base,
        gs_base: core.gs_base,
        ds: core.ds,
        es: core.es,
        fs: core.fs,
        gs: core.gs,
    }
}

fn register_error(error: HostError) -> TargetError {
    TargetError::Register(error.to_string())
}

fn memory_error(error: HostError) -> TargetError {
    TargetError::Memory(error.to_string())
}

fn exec_error(error: HostError) -> TargetError {
    TargetError::Execution(error.to_string())
}

fn breakpoint_error(error: HostError) -> TargetError {
    TargetError::Breakpoint(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breakpoint_hit_maps_to_sigtrap() {
        assert_eq!(
            outcome_to_reply(WaitOutcome::BreakpointHit { address: 0x1000 }),
            StopReply::Signal(GDB_SIGTRAP)
        );
    }

    #[test]
    fn exit_maps_to_w_reply() {
        assert_eq!(
            outcome_to_reply(WaitOutcome::Finished(StopEvent::Exited { code: 7 })),
            StopReply::Exited(7)
        );
    }

    #[test]
    fn termination_maps_to_x_reply() {
        assert_eq!(
            outcome_to_reply(WaitOutcome::Finished(StopEvent::Terminated { signal: 9 })),
            StopReply::Terminated(9)
        );
    }

    #[test]
    fn register_layout_round_trips_through_core() {
        let regs = X64Registers {
            rax: 0xaaaa,
            rip: 0x0040_1000,
            fs_base: 0x1234,
            ..X64Registers::default()
        };
        let core = to_core(&regs);
        let back = from_core(&core);
        assert_eq!(back, regs);
    }
}
