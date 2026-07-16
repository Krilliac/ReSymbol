//! Backend-neutral debugger contracts and static image intelligence.
//!
//! This crate deliberately contains no platform handles and performs no live
//! process operations. A backend owns those resources on its worker thread and
//! exchanges only the bounded commands and events defined here.

mod address_space;
mod authorization;
mod host_client;
mod host_codec;
pub mod host_wire;
mod identity;
mod protection;
pub mod protocol;
mod provider_probe;
pub mod sandbox;
mod session_machine;

pub use address_space::{
    AddressRange, FileBacking, MemoryAccess, RelativeAddress, StaticAddressSpace,
    StaticAddressSpaceError, StaticRegion, StaticRegionKind,
};
pub use authorization::{
    HostRiskLease, HostRiskOperation, SandboxOwnershipBinding, SandboxOwnershipLease,
};
pub use host_client::{
    ClientConnectionState, CommandReceipt, DebugHostClient, DebugHostClientError,
    HostFrameExchange, HostTransportError, InMemoryDebugHost, MAX_PENDING_COMMANDS,
    MAX_RESPONSE_FRAMES,
};
pub use host_codec::{
    HostCodecError, HostFrame, decode_command_frame, decode_event_frame, encode_command_frame,
    encode_event_frame,
};
pub use identity::{
    HostRiskLeaseId, HostRiskLeaseIdError, ProvisioningEpoch, ProvisioningEpochError,
    SandboxOwnershipLeaseId, SandboxOwnershipLeaseIdError, SessionIdError,
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
    ProcessId, ProcessIdentity, ProcessStartKey, ProtocolValidationError, ProtocolVersion,
    ReadViewToken, RunId, RunToken, SessionId, SessionState, SessionStateKind, SnapshotId,
    StateGeneration, StateToken, StepKind, StopId, StopReason, StopToken, ThreadId,
};
pub use provider_probe::{
    MAX_PROBE_GUARANTEES, MAX_PROBE_REQUIREMENTS, ProviderProbeObservation,
    ProviderProbeValidationError, SandboxProviderProbeBackend, SandboxProviderProbeRequest,
    SandboxProviderReadiness, SandboxProviderReadinessReason, SandboxProviderReadinessReport,
    SandboxProviderReadinessService, SandboxProviderRequirement, SystemSandboxProviderProbe,
    WindowsOptionalFeature,
};
pub use sandbox::{
    AttestationMismatch, AuthenticatedChannelNonce, AuthenticatedChannelNonceError,
    BoundedValueError, ChildProcessProfile, CleanupOutcome, CleanupReceiptError, CleanupResidual,
    CleanupResidualKind, DiagnosticText, DifferencingDiskId, DynamicCodeProfile,
    ExpectedSandboxAttestation, HelperBuildId, IsolationBoundary, PolicyDigest, PolicyDigestError,
    PolicyValidationError, ProcessMitigationProfile, ProviderUnavailable,
    ProviderUnavailableReason, ResourceLimitError, SANDBOX_POLICY_DIGEST_VERSION,
    SandboxAttestation, SandboxCleanupReceipt, SandboxFailure, SandboxFailureKind,
    SandboxFailureStage, SandboxGuarantee, SandboxLifecycleEvent, SandboxLifecycleState,
    SandboxMachine, SandboxMachineError, SandboxNetworkMode, SandboxPolicy,
    SandboxPolicyApprovalId, SandboxProviderDescriptor, SandboxProviderSelection,
    SandboxResourceLimits, SealedImageDigest, SealedImageDigestError, SealedImageId,
    VmIsolationIdentity, Win32kProfile,
};
pub use session_machine::{
    MAX_REGISTERED_AUTHORIZATION_LEASES, SessionMachine, SessionMachineError,
};
