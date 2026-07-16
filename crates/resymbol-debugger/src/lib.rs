//! Backend-neutral debugger contracts and static image intelligence.
//!
//! This crate deliberately contains no platform handles and performs no live
//! process operations. A backend owns those resources on its worker thread and
//! exchanges only the bounded commands and events defined here.

mod address_space;
pub mod host_wire;
mod protection;
pub mod protocol;
pub mod sandbox;

pub use address_space::{
    AddressRange, FileBacking, MemoryAccess, RelativeAddress, StaticAddressSpace,
    StaticAddressSpaceError, StaticRegion, StaticRegionKind,
};
pub use protection::{
    EvidenceStrength, ProtectionEvidence, ProtectionFinding, ProtectionKind, ProtectionReport,
    ProtectionScanError, ProtectionSeverity, scan_pe_protections,
};
pub use protocol::{
    AttachMode, AttachScope, AttachTarget, BreakpointChange, BreakpointId, BreakpointKind,
    BreakpointScope, BreakpointSpec, CapabilityAvailability, CapabilityReport, CapabilityStatus,
    CapabilityUnavailableCode, CommandEnvelope, CommandId, CommandOutcome, DebugCapability,
    DebugCommand, DebugEvent, DebugTargetRequest, DumpTarget, EventEnvelope, EventSequence,
    EventSequenceCursor, ExecutionToken, HardwareAccess, LaunchEnvironment, LaunchTarget,
    LiveToken, MAX_CAPABILITY_STATUSES, MAX_LAUNCH_ARGUMENT_BYTES, MAX_LAUNCH_ARGUMENTS,
    MAX_MEMORY_READ_BYTES, MAX_MEMORY_WRITE_BYTES, MAX_REASON_BYTES, MemoryAddress, OfflineTarget,
    ProcessId, ProtocolValidationError, ProtocolVersion, ReadViewToken, RunId, RunToken, SessionId,
    SessionState, SnapshotId, StateGeneration, StateToken, StepKind, StopId, StopReason, StopToken,
    ThreadId,
};
pub use sandbox::{
    AttestationMismatch, BoundedValueError, ChildProcessProfile, CleanupOutcome,
    CleanupReceiptError, CleanupResidual, CleanupResidualKind, DiagnosticText, DynamicCodeProfile,
    ExpectedSandboxAttestation, IsolationBoundary, PolicyDigest, PolicyDigestError,
    PolicyValidationError, ProcessMitigationProfile, ProviderUnavailable,
    ProviderUnavailableReason, ResourceLimitError, RiskAcknowledgementId, SandboxAttestation,
    SandboxCleanupReceipt, SandboxFailure, SandboxFailureKind, SandboxFailureStage,
    SandboxFallbackPolicy, SandboxGuarantee, SandboxLifecycleEvent, SandboxLifecycleState,
    SandboxNetworkMode, SandboxPolicy, SandboxProviderSelection, SandboxResourceLimits,
    Win32kProfile,
};
