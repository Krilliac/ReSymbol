//! Linux ptrace live execution-control host for ReSymbol.
//!
//! This crate provides *real* live debugging on Linux: launching or attaching
//! to a process and driving continue / single-step / software breakpoints /
//! register and memory access via `ptrace(2)`. It is a deliberately narrow
//! exception to the workspace `unsafe_code = "forbid"` rule — all FFI is
//! confined to [`linux`] and each block carries a `// SAFETY:` justification.
//! The worker core ([`LinuxDebugSession`]) is `unsafe`-free and unit-tested
//! against an in-memory mock; on non-Linux targets the crate still compiles
//! (as capability metadata only) so the whole workspace builds everywhere.
//!
//! Software breakpoints follow the same compare-before-write discipline the
//! debugger crate's `SoftwareBreakpointStateMachine` encodes: the original
//! byte is saved, `INT3` is written only after the expected byte is confirmed,
//! and on a hit the original byte is restored, `RIP` is rewound, the target is
//! single-stepped, and the breakpoint is re-armed.
//!
//! This host performs live control, not offline image analysis or OS-level
//! sandboxing; a launched or attached target runs with the caller's ambient
//! authority. Hardware breakpoints and sandbox provisioning are not yet
//! implemented.

#[cfg(target_os = "linux")]
mod linux;
mod session;
mod types;

pub use session::LinuxDebugSession;
pub use types::{
    BREAKPOINT_BYTE, HostError, LaunchSpec, MAX_MEMORY_TRANSFER_BYTES, MAX_SOFTWARE_BREAKPOINTS,
    PtraceOps, SIGTRAP, StopEvent, WaitOutcome, X64Registers,
};

#[cfg(target_os = "linux")]
pub use linux::PtraceBackend;

use resymbol_debugger::{
    CapabilityAvailability, CapabilityReport, CapabilityStatus, CapabilityUnavailableCode,
    DebugCapability,
};

/// Launch `spec` as a new traced child and return a ready-to-drive session.
///
/// The child is stopped at its `execve` entry before the first user
/// instruction runs.
#[cfg(target_os = "linux")]
pub fn launch(spec: &LaunchSpec) -> Result<LinuxDebugSession<PtraceBackend>, HostError> {
    Ok(LinuxDebugSession::new(PtraceBackend::launch(spec)?))
}

/// Attach to an already-running process, stopping it, and return a session.
#[cfg(target_os = "linux")]
pub fn attach(pid: i32) -> Result<LinuxDebugSession<PtraceBackend>, HostError> {
    Ok(LinuxDebugSession::new(PtraceBackend::attach(pid)?))
}

/// The complete, deterministic capability report for this host.
///
/// On Linux the execution-control, stepping (step-into), register, software
/// breakpoint, live memory, launch, and attach capabilities are available. On
/// other platforms every capability is reported unavailable.
#[must_use]
pub fn capability_report() -> CapabilityReport {
    let statuses = DebugCapability::ALL
        .into_iter()
        .map(|capability| CapabilityStatus {
            capability,
            availability: availability_for(capability),
        })
        .collect();
    CapabilityReport { statuses }
}

#[cfg(target_os = "linux")]
fn availability_for(capability: DebugCapability) -> CapabilityAvailability {
    use DebugCapability as C;
    let unavailable = |code, reason: &str| CapabilityAvailability::Unavailable {
        code,
        reason: reason.to_owned(),
    };
    match capability {
        C::LiveMemoryRead
        | C::LiveMemoryWrite
        | C::ExecutionControl
        | C::StepInto
        | C::RegisterRead
        | C::RegisterWrite
        | C::SoftwareBreakpoints
        | C::HostLaunch
        | C::HostAttach => CapabilityAvailability::Available,
        C::StepOver | C::StepOut => unavailable(
            CapabilityUnavailableCode::ProviderUnavailable,
            "step-over and step-out are not yet implemented; use single-step",
        ),
        C::HardwareBreakpoints => unavailable(
            CapabilityUnavailableCode::ProviderUnavailable,
            "hardware breakpoints and debug registers are not yet implemented",
        ),
        C::SandboxedLaunch => unavailable(
            CapabilityUnavailableCode::BackendUnavailable,
            "this host performs no sandbox provisioning; launches share the caller's authority",
        ),
        C::OfflineAnalysis | C::DumpRead | C::SnapshotRead | C::ObserveProcess => unavailable(
            CapabilityUnavailableCode::BackendUnavailable,
            "this host performs live execution control, not offline or snapshot analysis",
        ),
    }
}

#[cfg(not(target_os = "linux"))]
fn availability_for(_capability: DebugCapability) -> CapabilityAvailability {
    CapabilityAvailability::Unavailable {
        code: CapabilityUnavailableCode::UnsupportedPlatform,
        reason: "the ptrace live-debug host is available only on Linux".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_report_is_complete_and_valid() {
        let report = capability_report();
        assert_eq!(report.statuses.len(), DebugCapability::ALL.len());
        report.validate().expect("capability report must validate");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_advertises_execution_control() {
        let report = capability_report();
        let status = report
            .statuses
            .iter()
            .find(|status| status.capability == DebugCapability::ExecutionControl)
            .expect("execution control status present");
        assert_eq!(status.availability, CapabilityAvailability::Available);
    }
}
