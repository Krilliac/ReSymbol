//! Backend-neutral debugger commands, state tokens, and correlated events.
//!
//! Platform handles and debugger APIs deliberately stay outside this module.
//! Every state-sensitive command carries the exact token issued by the backend;
//! a controller must validate the envelope against its current state before any
//! target operation is attempted.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

pub use crate::identity::{HostRiskLeaseId, SandboxOwnershipLeaseId, SessionId};
use crate::sandbox::{
    CleanupAttemptFailureError, SandboxAttestation, SandboxLifecycleEvent, SandboxPolicy,
};
use resymbol_core::BinaryId;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 2;
pub const MAX_LAUNCH_ARGUMENTS: usize = 128;
pub const MAX_LAUNCH_ARGUMENT_BYTES: usize = 256 * 1024;
pub const MAX_MEMORY_READ_BYTES: u32 = 1024 * 1024;
pub const MAX_MEMORY_WRITE_BYTES: usize = 64 * 1024;
pub const MAX_REASON_BYTES: usize = 1024;
pub const MAX_CAPABILITY_STATUSES: usize = 64;

macro_rules! nonzero_id {
    ($name:ident, $raw:ty, $kind:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name($raw);

        impl $name {
            pub fn new(value: $raw) -> Result<Self, ProtocolValidationError> {
                (value != 0)
                    .then_some(Self(value))
                    .ok_or(ProtocolValidationError::ZeroIdentifier { kind: $kind })
            }

            #[must_use]
            pub const fn get(self) -> $raw {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = <$raw>::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

nonzero_id!(CommandId, u64, "command");
nonzero_id!(EventSequence, u64, "event sequence");
nonzero_id!(StateGeneration, u64, "state generation");
nonzero_id!(StopId, u64, "stop");
nonzero_id!(RunId, u64, "run");
nonzero_id!(ProcessId, u32, "process");
nonzero_id!(ProcessStartKey, u64, "process start key");
nonzero_id!(ThreadId, u32, "thread");
nonzero_id!(BreakpointId, u64, "breakpoint");
nonzero_id!(SnapshotId, u64, "snapshot");

impl StateGeneration {
    pub fn checked_next(self) -> Result<Self, ProtocolValidationError> {
        let next = self
            .0
            .checked_add(1)
            .ok_or(ProtocolValidationError::StateGenerationOverflow)?;
        Self::new(next)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    #[must_use]
    pub const fn current() -> Self {
        Self {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }
    }

    pub fn validate(self) -> Result<(), ProtocolValidationError> {
        if self == Self::current() {
            Ok(())
        } else {
            Err(ProtocolValidationError::UnsupportedProtocolVersion {
                major: self.major,
                minor: self.minor,
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateToken {
    pub session_id: SessionId,
    pub generation: StateGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopToken {
    pub state: StateToken,
    pub stop_id: StopId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunToken {
    pub state: StateToken,
    pub run_id: RunId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MemoryAddress(u64);

impl MemoryAddress {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn validate_span(self, size: usize) -> Result<(), ProtocolValidationError> {
        let size = u64::try_from(size).map_err(|_| ProtocolValidationError::AddressOverflow {
            address: self.0,
            size: u64::MAX,
        })?;
        self.0
            .checked_add(size)
            .ok_or(ProtocolValidationError::AddressOverflow {
                address: self.0,
                size,
            })?;
        Ok(())
    }
}

/// Stable identity for one concrete process instance, not merely a reusable
/// operating-system PID. Providers derive `start_key` from a trusted process
/// creation identity (for example, Windows creation `FILETIME`) and verify the
/// executable bytes against `binary_id` before registering an attach lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub process_id: ProcessId,
    pub start_key: ProcessStartKey,
    pub binary_id: BinaryId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchTarget {
    /// Exact SHA-256 identity that the backend must re-verify after staging and
    /// before target-controlled code is allowed to run.
    pub binary_id: BinaryId,
    pub executable: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<PathBuf>,
    pub environment: LaunchEnvironment,
    /// The backend must create the target suspended and attest containment
    /// before target-controlled entry-point or TLS code is allowed to run.
    pub stop_before_entry: bool,
}

impl LaunchTarget {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_path(&self.executable)?;
        if self
            .working_directory
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ProtocolValidationError::EmptyPath);
        }
        if self.arguments.len() > MAX_LAUNCH_ARGUMENTS {
            return Err(ProtocolValidationError::TooManyLaunchArguments {
                actual: self.arguments.len(),
                maximum: MAX_LAUNCH_ARGUMENTS,
            });
        }
        let mut bytes = 0usize;
        for argument in &self.arguments {
            if argument.contains('\0') {
                return Err(ProtocolValidationError::NulLaunchArgument);
            }
            bytes = bytes.checked_add(argument.len()).ok_or(
                ProtocolValidationError::LaunchArgumentsTooLarge {
                    actual: usize::MAX,
                    maximum: MAX_LAUNCH_ARGUMENT_BYTES,
                },
            )?;
        }
        if bytes > MAX_LAUNCH_ARGUMENT_BYTES {
            return Err(ProtocolValidationError::LaunchArgumentsTooLarge {
                actual: bytes,
                maximum: MAX_LAUNCH_ARGUMENT_BYTES,
            });
        }
        if !self.stop_before_entry {
            return Err(ProtocolValidationError::LaunchMustStopBeforeEntry);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "environment", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LaunchEnvironment {
    Sandboxed { policy: SandboxPolicy },
    Host { risk_lease: HostRiskLeaseId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttachMode {
    Debug,
    ObserveReadOnly,
    Snapshot,
}

/// Existing host processes and processes already owned by a sandbox are never
/// conflated. An arbitrary PID cannot be relabeled as sandboxed after launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AttachScope {
    Host {
        process: ProcessIdentity,
        risk_lease: HostRiskLeaseId,
    },
    OwnedSandbox {
        process: ProcessIdentity,
        ownership_lease: SandboxOwnershipLeaseId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachTarget {
    pub scope: AttachScope,
    pub mode: AttachMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DumpTarget {
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineTarget {
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "target",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum DebugTargetRequest {
    Launch(LaunchTarget),
    Attach(AttachTarget),
    Dump(DumpTarget),
    Offline(OfflineTarget),
}

impl DebugTargetRequest {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        match self {
            Self::Launch(target) => target.validate(),
            Self::Attach(_) => Ok(()),
            Self::Dump(target) => validate_path(&target.path),
            Self::Offline(target) => validate_path(&target.path),
        }
    }
}

fn validate_path(path: &Path) -> Result<(), ProtocolValidationError> {
    if path.as_os_str().is_empty() {
        Err(ProtocolValidationError::EmptyPath)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebugCapability {
    OfflineAnalysis,
    DumpRead,
    SnapshotRead,
    ObserveProcess,
    LiveMemoryRead,
    LiveMemoryWrite,
    ExecutionControl,
    RegisterRead,
    RegisterWrite,
    SoftwareBreakpoints,
    HardwareBreakpoints,
    SandboxedLaunch,
    HostLaunch,
    HostAttach,
}

impl DebugCapability {
    /// Complete, stable protocol order for capability negotiation.
    pub const ALL: [Self; 14] = [
        Self::OfflineAnalysis,
        Self::DumpRead,
        Self::SnapshotRead,
        Self::ObserveProcess,
        Self::LiveMemoryRead,
        Self::LiveMemoryWrite,
        Self::ExecutionControl,
        Self::RegisterRead,
        Self::RegisterWrite,
        Self::SoftwareBreakpoints,
        Self::HardwareBreakpoints,
        Self::SandboxedLaunch,
        Self::HostLaunch,
        Self::HostAttach,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityUnavailableCode {
    UnsupportedPlatform,
    ProviderUnavailable,
    PolicyConflict,
    TargetModeReadOnly,
    TargetArchitectureUnsupported,
    InsufficientAuthority,
    BackendUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "availability", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CapabilityAvailability {
    Available,
    Unavailable {
        code: CapabilityUnavailableCode,
        reason: String,
    },
}

impl CapabilityAvailability {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if let Self::Unavailable { reason, .. } = self {
            validate_reason(reason)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityStatus {
    pub capability: DebugCapability,
    pub availability: CapabilityAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReport {
    pub statuses: Vec<CapabilityStatus>,
}

impl CapabilityReport {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.statuses.len() > MAX_CAPABILITY_STATUSES {
            return Err(ProtocolValidationError::TooManyCapabilityStatuses {
                actual: self.statuses.len(),
                maximum: MAX_CAPABILITY_STATUSES,
            });
        }
        let mut seen = BTreeSet::new();
        for status in &self.statuses {
            status.availability.validate()?;
            if !seen.insert(status.capability) {
                return Err(ProtocolValidationError::DuplicateCapability {
                    capability: status.capability,
                });
            }
        }
        Ok(())
    }
}

fn validate_reason(reason: &str) -> Result<(), ProtocolValidationError> {
    if reason.is_empty() || reason.len() > MAX_REASON_BYTES || reason.chars().any(char::is_control)
    {
        Err(ProtocolValidationError::InvalidReason)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HardwareAccess {
    Execute,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BreakpointKind {
    Software,
    Hardware { access: HardwareAccess, size: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BreakpointScope {
    Process,
    Thread { thread_id: ThreadId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakpointSpec {
    pub id: BreakpointId,
    pub address: MemoryAddress,
    pub kind: BreakpointKind,
    pub scope: BreakpointScope,
}

impl BreakpointSpec {
    pub fn validate(self) -> Result<(), ProtocolValidationError> {
        let size = match self.kind {
            BreakpointKind::Software => 1,
            BreakpointKind::Hardware { access, size } => {
                if !matches!(size, 1 | 2 | 4 | 8) {
                    return Err(ProtocolValidationError::InvalidHardwareBreakpointSize { size });
                }
                if access == HardwareAccess::Execute && size != 1 {
                    return Err(ProtocolValidationError::InvalidExecuteBreakpointSize { size });
                }
                if access != HardwareAccess::Execute && self.address.get() % u64::from(size) != 0 {
                    return Err(ProtocolValidationError::UnalignedHardwareBreakpoint {
                        address: self.address.get(),
                        size,
                    });
                }
                usize::from(size)
            }
        };
        self.address.validate_span(size)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "view", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ReadViewToken {
    Offline {
        state: StateToken,
    },
    Dump {
        state: StateToken,
    },
    Snapshot {
        state: StateToken,
        snapshot_id: SnapshotId,
    },
    Observing {
        state: StateToken,
    },
    Stopped {
        stop: StopToken,
    },
}

impl ReadViewToken {
    #[must_use]
    pub const fn state(self) -> StateToken {
        match self {
            Self::Offline { state }
            | Self::Dump { state }
            | Self::Snapshot { state, .. }
            | Self::Observing { state } => state,
            Self::Stopped { stop } => stop.state,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "execution", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExecutionToken {
    Stopped { stop: StopToken },
    Running { run: RunToken },
}

impl ExecutionToken {
    #[must_use]
    pub const fn state(self) -> StateToken {
        match self {
            Self::Stopped { stop } => stop.state,
            Self::Running { run } => run.state,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "live", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LiveToken {
    Stopped { stop: StopToken },
    Running { run: RunToken },
    Observing { state: StateToken },
}

impl LiveToken {
    #[must_use]
    pub const fn state(self) -> StateToken {
        match self {
            Self::Stopped { stop } => stop.state,
            Self::Running { run } => run.state,
            Self::Observing { state } => state,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepKind {
    Into,
    Over,
    Out,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "command",
    content = "parameters",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum DebugCommand {
    ProbeCapabilities,
    Open(DebugTargetRequest),
    Continue {
        stop: StopToken,
    },
    Pause {
        run: RunToken,
    },
    Step {
        stop: StopToken,
        thread_id: ThreadId,
        kind: StepKind,
    },
    ReadMemory {
        view: ReadViewToken,
        address: MemoryAddress,
        size: u32,
    },
    WriteMemory {
        stop: StopToken,
        address: MemoryAddress,
        expected: Vec<u8>,
        replacement: Vec<u8>,
    },
    SetBreakpoint {
        stop: StopToken,
        breakpoint: BreakpointSpec,
    },
    RemoveBreakpoint {
        stop: StopToken,
        breakpoint_id: BreakpointId,
    },
    CaptureSnapshot {
        live: LiveToken,
    },
    Detach {
        live: LiveToken,
    },
    Terminate {
        execution: ExecutionToken,
    },
    Close {
        state: StateToken,
    },
}

impl DebugCommand {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        match self {
            Self::Open(target) => target.validate(),
            Self::ReadMemory {
                address, size: 0, ..
            } => {
                let _ = address;
                Err(ProtocolValidationError::EmptyMemoryRead)
            }
            Self::ReadMemory { address, size, .. } => {
                if *size > MAX_MEMORY_READ_BYTES {
                    return Err(ProtocolValidationError::MemoryReadTooLarge {
                        actual: *size,
                        maximum: MAX_MEMORY_READ_BYTES,
                    });
                }
                address.validate_span(*size as usize)
            }
            Self::WriteMemory {
                address,
                expected,
                replacement,
                ..
            } => validate_memory_write(*address, expected, replacement),
            Self::SetBreakpoint { breakpoint, .. } => breakpoint.validate(),
            Self::ProbeCapabilities
            | Self::Continue { .. }
            | Self::Pause { .. }
            | Self::Step { .. }
            | Self::RemoveBreakpoint { .. }
            | Self::CaptureSnapshot { .. }
            | Self::Detach { .. }
            | Self::Terminate { .. }
            | Self::Close { .. } => Ok(()),
        }
    }

    fn state_context(&self) -> Option<StateToken> {
        match self {
            Self::ProbeCapabilities | Self::Open(_) => None,
            Self::Continue { stop }
            | Self::Step { stop, .. }
            | Self::WriteMemory { stop, .. }
            | Self::SetBreakpoint { stop, .. }
            | Self::RemoveBreakpoint { stop, .. } => Some(stop.state),
            Self::Pause { run } => Some(run.state),
            Self::ReadMemory { view, .. } => Some(view.state()),
            Self::CaptureSnapshot { live } | Self::Detach { live } => Some(live.state()),
            Self::Terminate { execution } => Some(execution.state()),
            Self::Close { state } => Some(*state),
        }
    }

    pub fn verify_observed_memory(&self, observed: &[u8]) -> Result<(), ProtocolValidationError> {
        let Self::WriteMemory { expected, .. } = self else {
            return Err(ProtocolValidationError::NotMemoryWriteCommand);
        };
        if observed == expected {
            Ok(())
        } else {
            Err(ProtocolValidationError::MemoryWriteConflict)
        }
    }
}

fn validate_memory_write(
    address: MemoryAddress,
    expected: &[u8],
    replacement: &[u8],
) -> Result<(), ProtocolValidationError> {
    if expected.is_empty() {
        return Err(ProtocolValidationError::EmptyMemoryWrite);
    }
    if expected.len() != replacement.len() {
        return Err(ProtocolValidationError::MemoryWriteLengthMismatch {
            expected: expected.len(),
            replacement: replacement.len(),
        });
    }
    if expected.len() > MAX_MEMORY_WRITE_BYTES {
        return Err(ProtocolValidationError::MemoryWriteTooLarge {
            actual: expected.len(),
            maximum: MAX_MEMORY_WRITE_BYTES,
        });
    }
    address.validate_span(expected.len())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandEnvelope {
    pub version: ProtocolVersion,
    pub command_id: CommandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state: Option<StateToken>,
    pub command: DebugCommand,
}

impl CommandEnvelope {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        self.version.validate()?;
        self.command.validate()?;
        if matches!(&self.command, DebugCommand::ProbeCapabilities) {
            if self.session_id.is_some() || self.expected_state.is_some() {
                return Err(ProtocolValidationError::UnexpectedSessionContext);
            }
            return Ok(());
        }
        let session_id = self
            .session_id
            .ok_or(ProtocolValidationError::MissingSessionContext)?;
        let expected = self
            .expected_state
            .ok_or(ProtocolValidationError::MissingStateToken)?;
        if expected.session_id != session_id {
            return Err(ProtocolValidationError::StaleSession);
        }
        if let Some(command_state) = self.command.state_context() {
            if command_state != expected {
                return Err(ProtocolValidationError::StaleStateToken);
            }
        }
        Ok(())
    }

    pub fn validate_against(&self, state: &SessionState) -> Result<(), ProtocolValidationError> {
        self.validate()?;
        if matches!(&self.command, DebugCommand::ProbeCapabilities) {
            return Ok(());
        }
        let actual = state.state_token();
        if self.session_id != Some(actual.session_id) {
            return Err(ProtocolValidationError::StaleSession);
        }
        if self.expected_state != Some(actual) {
            return Err(ProtocolValidationError::StaleStateToken);
        }
        let allowed = match (&self.command, state) {
            (DebugCommand::Open(_), SessionState::Idle { .. }) => true,
            (DebugCommand::Continue { stop }, SessionState::Stopped { token, .. })
            | (DebugCommand::Step { stop, .. }, SessionState::Stopped { token, .. })
            | (DebugCommand::WriteMemory { stop, .. }, SessionState::Stopped { token, .. })
            | (DebugCommand::SetBreakpoint { stop, .. }, SessionState::Stopped { token, .. })
            | (DebugCommand::RemoveBreakpoint { stop, .. }, SessionState::Stopped { token, .. }) => {
                stop == token
            }
            (DebugCommand::Pause { run }, SessionState::Running { token }) => run == token,
            (DebugCommand::ReadMemory { view, .. }, _) => state.matches_read_view(*view),
            (DebugCommand::CaptureSnapshot { live }, _) | (DebugCommand::Detach { live }, _) => {
                state.matches_live(*live)
            }
            (DebugCommand::Terminate { execution }, _) => state.matches_execution(*execution),
            (DebugCommand::Close { .. }, state) => !matches!(state, SessionState::Closed { .. }),
            _ => false,
        };
        if allowed {
            Ok(())
        } else if matches!(&self.command, DebugCommand::Close { .. }) {
            Err(ProtocolValidationError::CommandNotAllowedInState)
        } else if self.command.state_context().is_some() {
            Err(ProtocolValidationError::StaleExecutionToken)
        } else {
            Err(ProtocolValidationError::CommandNotAllowedInState)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StopReason {
    Initial,
    UserPause,
    Breakpoint {
        breakpoint_id: BreakpointId,
    },
    SingleStep,
    Exception {
        code: u32,
        first_chance: bool,
        address: MemoryAddress,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SessionState {
    Idle {
        token: StateToken,
    },
    Opening {
        token: StateToken,
        target: DebugTargetRequest,
    },
    AwaitingAttestation {
        token: StateToken,
    },
    AttestationAccepted {
        token: StateToken,
    },
    Offline {
        token: StateToken,
    },
    Dump {
        token: StateToken,
    },
    Snapshot {
        token: StateToken,
        snapshot_id: SnapshotId,
    },
    Observing {
        token: StateToken,
        process_id: ProcessId,
    },
    Stopped {
        token: StopToken,
        reason: StopReason,
        thread_id: ThreadId,
    },
    Running {
        token: RunToken,
    },
    Pausing {
        token: StateToken,
    },
    Closing {
        token: StateToken,
    },
    Detached {
        token: StateToken,
    },
    Exited {
        token: StateToken,
        exit_code: u32,
    },
    Failed {
        token: StateToken,
        message: String,
    },
    Closed {
        token: StateToken,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionStateKind {
    Idle,
    Opening,
    AwaitingAttestation,
    AttestationAccepted,
    Offline,
    Dump,
    Snapshot,
    Observing,
    Stopped,
    Running,
    Pausing,
    Closing,
    Detached,
    Exited,
    Failed,
    Closed,
}

impl SessionState {
    #[must_use]
    pub const fn state_token(&self) -> StateToken {
        match self {
            Self::Idle { token }
            | Self::Opening { token, .. }
            | Self::AwaitingAttestation { token }
            | Self::AttestationAccepted { token }
            | Self::Offline { token }
            | Self::Dump { token }
            | Self::Snapshot { token, .. }
            | Self::Observing { token, .. }
            | Self::Pausing { token }
            | Self::Closing { token }
            | Self::Detached { token }
            | Self::Exited { token, .. }
            | Self::Failed { token, .. }
            | Self::Closed { token } => *token,
            Self::Stopped { token, .. } => token.state,
            Self::Running { token } => token.state,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> SessionStateKind {
        match self {
            Self::Idle { .. } => SessionStateKind::Idle,
            Self::Opening { .. } => SessionStateKind::Opening,
            Self::AwaitingAttestation { .. } => SessionStateKind::AwaitingAttestation,
            Self::AttestationAccepted { .. } => SessionStateKind::AttestationAccepted,
            Self::Offline { .. } => SessionStateKind::Offline,
            Self::Dump { .. } => SessionStateKind::Dump,
            Self::Snapshot { .. } => SessionStateKind::Snapshot,
            Self::Observing { .. } => SessionStateKind::Observing,
            Self::Stopped { .. } => SessionStateKind::Stopped,
            Self::Running { .. } => SessionStateKind::Running,
            Self::Pausing { .. } => SessionStateKind::Pausing,
            Self::Closing { .. } => SessionStateKind::Closing,
            Self::Detached { .. } => SessionStateKind::Detached,
            Self::Exited { .. } => SessionStateKind::Exited,
            Self::Failed { .. } => SessionStateKind::Failed,
            Self::Closed { .. } => SessionStateKind::Closed,
        }
    }

    /// Validates one externally observed reducer transition. This is the
    /// consumer-side contract for state events; it rejects impossible state
    /// jumps even when a forged event carries the next numeric generation.
    pub fn validate_successor(&self, next: &Self) -> Result<(), ProtocolValidationError> {
        let current_token = self.state_token();
        let next_token = next.state_token();
        if next_token.session_id != current_token.session_id {
            return Err(ProtocolValidationError::StaleSession);
        }
        let expected_generation = current_token
            .generation
            .get()
            .checked_add(1)
            .ok_or(ProtocolValidationError::StateGenerationOverflow)?;
        if next_token.generation.get() != expected_generation {
            return Err(ProtocolValidationError::UnexpectedStateGeneration {
                expected: expected_generation,
                actual: next_token.generation.get(),
            });
        }
        let from = self.kind();
        let to = next.kind();
        let allowed = match from {
            SessionStateKind::Idle => matches!(
                to,
                SessionStateKind::Opening | SessionStateKind::Closing | SessionStateKind::Failed
            ),
            SessionStateKind::Opening => matches!(
                to,
                SessionStateKind::AwaitingAttestation
                    | SessionStateKind::Offline
                    | SessionStateKind::Dump
                    | SessionStateKind::Observing
                    | SessionStateKind::Stopped
                    | SessionStateKind::Closing
                    | SessionStateKind::Failed
            ),
            SessionStateKind::AwaitingAttestation => matches!(
                to,
                SessionStateKind::AttestationAccepted
                    | SessionStateKind::Closing
                    | SessionStateKind::Failed
            ),
            SessionStateKind::AttestationAccepted => matches!(
                to,
                SessionStateKind::Stopped
                    | SessionStateKind::Exited
                    | SessionStateKind::Closing
                    | SessionStateKind::Failed
            ),
            SessionStateKind::Offline | SessionStateKind::Dump | SessionStateKind::Snapshot => {
                matches!(to, SessionStateKind::Closing | SessionStateKind::Failed)
            }
            SessionStateKind::Observing => matches!(
                to,
                SessionStateKind::Detached | SessionStateKind::Closing | SessionStateKind::Failed
            ),
            SessionStateKind::Stopped => matches!(
                to,
                SessionStateKind::Stopped
                    | SessionStateKind::Running
                    | SessionStateKind::Detached
                    | SessionStateKind::Exited
                    | SessionStateKind::Closing
                    | SessionStateKind::Failed
            ),
            SessionStateKind::Running => matches!(
                to,
                SessionStateKind::Stopped
                    | SessionStateKind::Pausing
                    | SessionStateKind::Detached
                    | SessionStateKind::Exited
                    | SessionStateKind::Closing
                    | SessionStateKind::Failed
            ),
            SessionStateKind::Pausing => matches!(
                to,
                SessionStateKind::Stopped
                    | SessionStateKind::Exited
                    | SessionStateKind::Closing
                    | SessionStateKind::Failed
            ),
            SessionStateKind::Detached | SessionStateKind::Exited => {
                matches!(to, SessionStateKind::Closing | SessionStateKind::Failed)
            }
            SessionStateKind::Failed => {
                matches!(to, SessionStateKind::Failed | SessionStateKind::Closing)
            }
            SessionStateKind::Closing => {
                matches!(to, SessionStateKind::Closed | SessionStateKind::Failed)
            }
            SessionStateKind::Closed => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(ProtocolValidationError::InvalidSessionStateTransition { from, to })
        }
    }

    fn matches_read_view(&self, view: ReadViewToken) -> bool {
        match (view, self) {
            (ReadViewToken::Offline { state }, Self::Offline { token })
            | (ReadViewToken::Dump { state }, Self::Dump { token })
            | (ReadViewToken::Observing { state }, Self::Observing { token, .. }) => {
                state == *token
            }
            (
                ReadViewToken::Snapshot { state, snapshot_id },
                Self::Snapshot {
                    token,
                    snapshot_id: actual,
                },
            ) => state == *token && snapshot_id == *actual,
            (ReadViewToken::Stopped { stop }, Self::Stopped { token, .. }) => stop == *token,
            _ => false,
        }
    }

    fn matches_live(&self, live: LiveToken) -> bool {
        match (live, self) {
            (LiveToken::Stopped { stop }, Self::Stopped { token, .. }) => stop == *token,
            (LiveToken::Running { run }, Self::Running { token }) => run == *token,
            (LiveToken::Observing { state }, Self::Observing { token, .. }) => state == *token,
            _ => false,
        }
    }

    fn matches_execution(&self, execution: ExecutionToken) -> bool {
        match (execution, self) {
            (ExecutionToken::Stopped { stop }, Self::Stopped { token, .. }) => stop == *token,
            (ExecutionToken::Running { run }, Self::Running { token }) => run == *token,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BreakpointChange {
    Set,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CommandOutcome {
    Succeeded,
    Rejected { code: String, message: String },
}

impl CommandOutcome {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if let Self::Rejected { code, message } = self {
            validate_reason(code)?;
            validate_reason(message)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "event",
    content = "payload",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum DebugEvent {
    Capabilities(CapabilityReport),
    StateChanged(SessionState),
    MemoryRead {
        view: ReadViewToken,
        address: MemoryAddress,
        bytes: Vec<u8>,
    },
    MemoryWritten {
        stop: StopToken,
        address: MemoryAddress,
        before: Vec<u8>,
        after: Vec<u8>,
    },
    BreakpointChanged {
        stop: StopToken,
        breakpoint: BreakpointSpec,
        change: BreakpointChange,
    },
    SandboxAttested(SandboxAttestation),
    SandboxLifecycle(SandboxLifecycleEvent),
    CommandResult {
        command_id: CommandId,
        outcome: CommandOutcome,
    },
    Warning {
        code: String,
        message: String,
    },
}

impl DebugEvent {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        match self {
            Self::Capabilities(report) => report.validate(),
            Self::StateChanged(SessionState::Failed { message, .. }) => validate_reason(message),
            Self::SandboxLifecycle(SandboxLifecycleEvent::CleanupAttemptFailed(attempt)) => {
                attempt.validate()?;
                Ok(())
            }
            Self::StateChanged(_) | Self::SandboxAttested(_) | Self::SandboxLifecycle(_) => Ok(()),
            Self::MemoryRead { address, bytes, .. } => {
                if bytes.is_empty() || bytes.len() > MAX_MEMORY_READ_BYTES as usize {
                    return Err(ProtocolValidationError::InvalidMemoryReadResult);
                }
                address.validate_span(bytes.len())
            }
            Self::MemoryWritten {
                address,
                before,
                after,
                ..
            } => validate_memory_write(*address, before, after),
            Self::BreakpointChanged { breakpoint, .. } => breakpoint.validate(),
            Self::CommandResult { outcome, .. } => outcome.validate(),
            Self::Warning { code, message } => {
                validate_reason(code)?;
                validate_reason(message)
            }
        }
    }

    fn state_context(&self) -> Option<StateToken> {
        match self {
            Self::StateChanged(state) => Some(state.state_token()),
            Self::MemoryRead { view, .. } => Some(view.state()),
            Self::MemoryWritten { stop, .. } | Self::BreakpointChanged { stop, .. } => {
                Some(stop.state)
            }
            Self::SandboxAttested(_) | Self::SandboxLifecycle(_) => None,
            Self::Capabilities(_) | Self::CommandResult { .. } | Self::Warning { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub version: ProtocolVersion,
    pub sequence: EventSequence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caused_by: Option<CommandId>,
    pub event: DebugEvent,
}

impl EventEnvelope {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        self.version.validate()?;
        self.event.validate()?;
        if let DebugEvent::CommandResult { command_id, .. } = &self.event {
            if self.caused_by != Some(*command_id) {
                return Err(ProtocolValidationError::MismatchedCommandCorrelation);
            }
        }
        if let Some(event_state) = self.event.state_context() {
            if self.session_id != Some(event_state.session_id) {
                return Err(ProtocolValidationError::StaleSession);
            }
            if self.state != Some(event_state) {
                return Err(ProtocolValidationError::StaleStateToken);
            }
        }
        let sandbox_event = matches!(
            &self.event,
            DebugEvent::SandboxAttested(_) | DebugEvent::SandboxLifecycle(_)
        );
        if sandbox_event && (self.session_id.is_none() || self.state.is_none()) {
            return Err(ProtocolValidationError::MissingSessionContext);
        }
        if sandbox_event {
            let outer_session = self
                .session_id
                .expect("sandbox context presence was checked above");
            let outer_state = self
                .state
                .expect("sandbox context presence was checked above");
            if outer_state.session_id != outer_session {
                return Err(ProtocolValidationError::StaleStateToken);
            }
            let inner_session = match &self.event {
                DebugEvent::SandboxAttested(attestation) => attestation.session_id,
                DebugEvent::SandboxLifecycle(lifecycle) => match lifecycle {
                    SandboxLifecycleEvent::State { session_id, .. } => *session_id,
                    SandboxLifecycleEvent::Attested(attestation) => attestation.session_id,
                    SandboxLifecycleEvent::ProviderUnavailable(unavailable) => {
                        unavailable.session_id
                    }
                    SandboxLifecycleEvent::Failed(failure) => failure.session_id,
                    SandboxLifecycleEvent::CleanupAttemptFailed(attempt) => {
                        attempt.failure.session_id
                    }
                    SandboxLifecycleEvent::Closed(receipt) => receipt.session_id,
                },
                _ => unreachable!("sandbox event was matched above"),
            };
            if inner_session != outer_session {
                return Err(ProtocolValidationError::StaleSession);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EventSequenceCursor {
    last: Option<EventSequence>,
}

impl EventSequenceCursor {
    pub fn observe(&mut self, sequence: EventSequence) -> Result<(), ProtocolValidationError> {
        let expected = match self.last {
            Some(last) => last
                .get()
                .checked_add(1)
                .ok_or(ProtocolValidationError::EventSequenceOverflow)?,
            None => 1,
        };
        if sequence.get() != expected {
            return Err(ProtocolValidationError::UnexpectedEventSequence {
                expected,
                actual: sequence.get(),
            });
        }
        self.last = Some(sequence);
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolValidationError {
    #[error(transparent)]
    CleanupAttemptFailure(#[from] CleanupAttemptFailureError),
    #[error("{kind} identifier must be nonzero")]
    ZeroIdentifier { kind: &'static str },
    #[error("unsupported debugger protocol version {major}.{minor}")]
    UnsupportedProtocolVersion { major: u16, minor: u16 },
    #[error("state generation overflow")]
    StateGenerationOverflow,
    #[error("expected state generation {expected}, received {actual}")]
    UnexpectedStateGeneration { expected: u64, actual: u64 },
    #[error("invalid session state transition from {from:?} to {to:?}")]
    InvalidSessionStateTransition {
        from: SessionStateKind,
        to: SessionStateKind,
    },
    #[error("path cannot be empty")]
    EmptyPath,
    #[error("launch has {actual} arguments; maximum is {maximum}")]
    TooManyLaunchArguments { actual: usize, maximum: usize },
    #[error("launch arguments occupy {actual} bytes; maximum is {maximum}")]
    LaunchArgumentsTooLarge { actual: usize, maximum: usize },
    #[error("launch argument contains a NUL character")]
    NulLaunchArgument,
    #[error("launch must stop before target-controlled entry-point code")]
    LaunchMustStopBeforeEntry,
    #[error("capability report has {actual} entries; maximum is {maximum}")]
    TooManyCapabilityStatuses { actual: usize, maximum: usize },
    #[error("duplicate capability status for {capability:?}")]
    DuplicateCapability { capability: DebugCapability },
    #[error("reason must be nonempty, single-line, and at most 1024 UTF-8 bytes")]
    InvalidReason,
    #[error("memory read cannot be empty")]
    EmptyMemoryRead,
    #[error("memory read is {actual} bytes; maximum is {maximum}")]
    MemoryReadTooLarge { actual: u32, maximum: u32 },
    #[error("memory write cannot be empty")]
    EmptyMemoryWrite,
    #[error(
        "memory write expected length {expected} differs from replacement length {replacement}"
    )]
    MemoryWriteLengthMismatch { expected: usize, replacement: usize },
    #[error("memory write is {actual} bytes; maximum is {maximum}")]
    MemoryWriteTooLarge { actual: usize, maximum: usize },
    #[error("address {address:#x} plus size {size:#x} overflows")]
    AddressOverflow { address: u64, size: u64 },
    #[error("observed memory no longer matches the compare-before-write expectation")]
    MemoryWriteConflict,
    #[error("command is not a memory-write command")]
    NotMemoryWriteCommand,
    #[error("hardware breakpoint size {size} is not 1, 2, 4, or 8")]
    InvalidHardwareBreakpointSize { size: u8 },
    #[error("execute hardware breakpoint size must be one, not {size}")]
    InvalidExecuteBreakpointSize { size: u8 },
    #[error("hardware breakpoint at {address:#x} is not aligned to {size} bytes")]
    UnalignedHardwareBreakpoint { address: u64, size: u8 },
    #[error("global command unexpectedly carried session state")]
    UnexpectedSessionContext,
    #[error("session command is missing its session context")]
    MissingSessionContext,
    #[error("session command is missing its expected state token")]
    MissingStateToken,
    #[error("session identifier is stale or mismatched")]
    StaleSession,
    #[error("state generation is stale or mismatched")]
    StaleStateToken,
    #[error("stop/run/view token is stale or mismatched")]
    StaleExecutionToken,
    #[error("command is not valid in the current session state")]
    CommandNotAllowedInState,
    #[error("memory-read event has an empty or oversized payload")]
    InvalidMemoryReadResult,
    #[error("command result does not match the envelope correlation id")]
    MismatchedCommandCorrelation,
    #[error("expected event sequence {expected}, received {actual}")]
    UnexpectedEventSequence { expected: u64, actual: u64 },
    #[error("event sequence exhausted its u64 identifier space")]
    EventSequenceOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ProvisioningEpoch;
    use crate::sandbox::{
        CleanupOutcome, CleanupReceiptId, CleanupResidual, CleanupResidualKind, DiagnosticText,
        PolicyDigest, SandboxCleanupAttemptFailure, SandboxCleanupReceipt, SandboxFailure,
        SandboxFailureKind, SandboxFailureStage, SandboxProviderSelection,
    };

    fn session(value: u64) -> SessionId {
        SessionId::new(value).unwrap()
    }

    fn generation(value: u64) -> StateGeneration {
        StateGeneration::new(value).unwrap()
    }

    fn state(session_value: u64, generation_value: u64) -> StateToken {
        StateToken {
            session_id: session(session_value),
            generation: generation(generation_value),
        }
    }

    fn stop(session_value: u64, generation_value: u64, stop_value: u64) -> StopToken {
        StopToken {
            state: state(session_value, generation_value),
            stop_id: StopId::new(stop_value).unwrap(),
        }
    }

    fn stopped_state(token: StopToken) -> SessionState {
        SessionState::Stopped {
            token,
            reason: StopReason::Initial,
            thread_id: ThreadId::new(3).unwrap(),
        }
    }

    fn command(command: DebugCommand, expected: StateToken) -> CommandEnvelope {
        CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(9).unwrap(),
            session_id: Some(expected.session_id),
            expected_state: Some(expected),
            command,
        }
    }

    fn cleanup_attempt_event() -> EventEnvelope {
        let session_id = session(1);
        let receipt = SandboxCleanupReceipt {
            receipt_id: CleanupReceiptId::new("cleanup-attempt-1").expect("receipt id"),
            session_id,
            provisioning_epoch: ProvisioningEpoch::new("a".repeat(64)).expect("epoch"),
            provider: SandboxProviderSelection::LocalAppContainer,
            policy_digest: PolicyDigest::new("b".repeat(64)).expect("policy digest"),
            process: None,
            outcome: CleanupOutcome::Incomplete,
            process_tree_terminated_and_reaped: true,
            handles_closed: false,
            file_system_rolled_back: true,
            registry_rolled_back: true,
            network_torn_down: true,
            owned_paths_deleted: true,
            appcontainer_profile_deleted: Some(true),
            differencing_disk_discarded: None,
            control_channel_closed: None,
            terminated_processes: 1,
            residuals: vec![CleanupResidual {
                kind: CleanupResidualKind::Handles,
                detail: DiagnosticText::new("provider handle remains open").expect("detail"),
            }],
        };
        EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(1).expect("sequence"),
            session_id: Some(session_id),
            state: Some(state(1, 2)),
            caused_by: Some(CommandId::new(7).expect("command id")),
            event: DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::CleanupAttemptFailed(
                SandboxCleanupAttemptFailure {
                    failure: SandboxFailure {
                        session_id,
                        provider: SandboxProviderSelection::LocalAppContainer,
                        stage: SandboxFailureStage::Cleanup,
                        kind: SandboxFailureKind::CleanupIncomplete,
                        retryable: true,
                        detail: DiagnosticText::new("cleanup requires a retry").expect("detail"),
                    },
                    receipt,
                },
            )),
        }
    }

    #[test]
    fn observed_state_successors_require_exact_generation_and_legal_edges() {
        let idle = SessionState::Idle { token: state(1, 1) };
        idle.validate_successor(&SessionState::Closing { token: state(1, 2) })
            .unwrap();
        assert_eq!(
            idle.validate_successor(&SessionState::Closed { token: state(1, 2) }),
            Err(ProtocolValidationError::InvalidSessionStateTransition {
                from: SessionStateKind::Idle,
                to: SessionStateKind::Closed,
            })
        );
        assert_eq!(
            idle.validate_successor(&SessionState::Closing { token: state(1, 3) }),
            Err(ProtocolValidationError::UnexpectedStateGeneration {
                expected: 2,
                actual: 3,
            })
        );
        assert_eq!(
            idle.validate_successor(&SessionState::Closing { token: state(2, 2) }),
            Err(ProtocolValidationError::StaleSession)
        );
    }

    #[test]
    fn nonzero_ids_are_enforced_during_construction_and_deserialization() {
        assert!(SessionId::new(0).is_err());
        assert!(serde_json::from_str::<CommandId>("0").is_err());
        assert_eq!(serde_json::from_str::<CommandId>("7").unwrap().get(), 7);
    }

    #[test]
    fn stale_sessions_generations_and_stop_ids_are_rejected() {
        let current_stop = stop(1, 4, 20);
        let current = stopped_state(current_stop);
        let valid = command(
            DebugCommand::Continue { stop: current_stop },
            current_stop.state,
        );
        valid.validate_against(&current).unwrap();

        let mut wrong_session = valid.clone();
        wrong_session.session_id = Some(session(2));
        assert_eq!(
            wrong_session.validate_against(&current),
            Err(ProtocolValidationError::StaleSession)
        );

        let stale_stop = stop(1, 4, 19);
        let stale = command(
            DebugCommand::Continue { stop: stale_stop },
            stale_stop.state,
        );
        assert_eq!(
            stale.validate_against(&current),
            Err(ProtocolValidationError::StaleExecutionToken)
        );

        let stale_generation = command(
            DebugCommand::Continue {
                stop: stop(1, 3, 20),
            },
            state(1, 3),
        );
        assert_eq!(
            stale_generation.validate_against(&current),
            Err(ProtocolValidationError::StaleStateToken)
        );
    }

    #[test]
    fn compare_before_write_rejects_length_conflicts_observed_conflicts_and_overflow() {
        let token = stop(1, 2, 3);
        let mismatch = DebugCommand::WriteMemory {
            stop: token,
            address: MemoryAddress::new(0x1000),
            expected: vec![1, 2],
            replacement: vec![3],
        };
        assert_eq!(
            mismatch.validate(),
            Err(ProtocolValidationError::MemoryWriteLengthMismatch {
                expected: 2,
                replacement: 1,
            })
        );

        let write = DebugCommand::WriteMemory {
            stop: token,
            address: MemoryAddress::new(0x1000),
            expected: vec![1, 2],
            replacement: vec![3, 4],
        };
        write.validate().unwrap();
        write.verify_observed_memory(&[1, 2]).unwrap();
        assert_eq!(
            write.verify_observed_memory(&[1, 9]),
            Err(ProtocolValidationError::MemoryWriteConflict)
        );

        let overflow = DebugCommand::WriteMemory {
            stop: token,
            address: MemoryAddress::new(u64::MAX),
            expected: vec![1],
            replacement: vec![2],
        };
        assert_eq!(
            overflow.validate(),
            Err(ProtocolValidationError::AddressOverflow {
                address: u64::MAX,
                size: 1,
            })
        );
    }

    #[test]
    fn breakpoints_validate_hardware_shape_alignment_and_address_span() {
        let base = BreakpointSpec {
            id: BreakpointId::new(1).unwrap(),
            address: MemoryAddress::new(0x1002),
            kind: BreakpointKind::Hardware {
                access: HardwareAccess::Write,
                size: 4,
            },
            scope: BreakpointScope::Thread {
                thread_id: ThreadId::new(8).unwrap(),
            },
        };
        assert_eq!(
            base.validate(),
            Err(ProtocolValidationError::UnalignedHardwareBreakpoint {
                address: 0x1002,
                size: 4,
            })
        );
        assert_eq!(
            BreakpointSpec {
                address: MemoryAddress::new(0x1000),
                kind: BreakpointKind::Hardware {
                    access: HardwareAccess::Execute,
                    size: 8,
                },
                ..base
            }
            .validate(),
            Err(ProtocolValidationError::InvalidExecuteBreakpointSize { size: 8 })
        );
    }

    #[test]
    fn offline_snapshot_observation_and_stop_views_are_state_exact() {
        let offline_token = state(1, 2);
        let offline = SessionState::Offline {
            token: offline_token,
        };
        let read = command(
            DebugCommand::ReadMemory {
                view: ReadViewToken::Offline {
                    state: offline_token,
                },
                address: MemoryAddress::new(0),
                size: 16,
            },
            offline_token,
        );
        read.validate_against(&offline).unwrap();

        let wrong_view = command(
            DebugCommand::ReadMemory {
                view: ReadViewToken::Observing {
                    state: offline_token,
                },
                address: MemoryAddress::new(0),
                size: 16,
            },
            offline_token,
        );
        assert_eq!(
            wrong_view.validate_against(&offline),
            Err(ProtocolValidationError::StaleExecutionToken)
        );
    }

    #[test]
    fn capability_unavailability_is_bounded_and_duplicate_free() {
        CapabilityReport {
            statuses: DebugCapability::ALL
                .map(|capability| CapabilityStatus {
                    capability,
                    availability: CapabilityAvailability::Available,
                })
                .into(),
        }
        .validate()
        .expect("complete capability catalog is unique and bounded");

        let status = CapabilityStatus {
            capability: DebugCapability::LiveMemoryWrite,
            availability: CapabilityAvailability::Unavailable {
                code: CapabilityUnavailableCode::TargetModeReadOnly,
                reason: "snapshot sessions are immutable".to_owned(),
            },
        };
        CapabilityReport {
            statuses: vec![status.clone()],
        }
        .validate()
        .unwrap();
        assert_eq!(
            CapabilityReport {
                statuses: vec![status.clone(), status],
            }
            .validate(),
            Err(ProtocolValidationError::DuplicateCapability {
                capability: DebugCapability::LiveMemoryWrite,
            })
        );
    }

    #[test]
    fn command_results_are_correlated_and_event_sequences_are_exact() {
        let command_id = CommandId::new(5).unwrap();
        let event = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(1).unwrap(),
            session_id: None,
            state: None,
            caused_by: Some(command_id),
            event: DebugEvent::CommandResult {
                command_id,
                outcome: CommandOutcome::Succeeded,
            },
        };
        event.validate().unwrap();

        let mut cursor = EventSequenceCursor::default();
        cursor.observe(EventSequence::new(1).unwrap()).unwrap();
        cursor.observe(EventSequence::new(2).unwrap()).unwrap();
        assert_eq!(
            cursor.observe(EventSequence::new(4).unwrap()),
            Err(ProtocolValidationError::UnexpectedEventSequence {
                expected: 3,
                actual: 4,
            })
        );

        let mut exhausted = EventSequenceCursor {
            last: Some(EventSequence::new(u64::MAX).unwrap()),
        };
        assert_eq!(
            exhausted.observe(EventSequence::new(u64::MAX).unwrap()),
            Err(ProtocolValidationError::EventSequenceOverflow)
        );
    }

    #[test]
    fn sandbox_evidence_is_bound_to_the_outer_session_envelope() {
        let envelope = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(1).unwrap(),
            session_id: Some(session(1)),
            state: Some(state(1, 2)),
            caused_by: Some(CommandId::new(7).unwrap()),
            event: DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::State {
                session_id: session(2),
                state: crate::sandbox::SandboxLifecycleState::Provisioning,
            }),
        };
        assert_eq!(
            envelope.validate(),
            Err(ProtocolValidationError::StaleSession)
        );

        let mut mismatched_state = envelope;
        mismatched_state.session_id = Some(session(2));
        assert_eq!(
            mismatched_state.validate(),
            Err(ProtocolValidationError::StaleStateToken)
        );
    }

    #[test]
    fn cleanup_attempt_failure_round_trips_and_rejects_unknown_fields() {
        let envelope = cleanup_attempt_event();
        envelope.validate().expect("valid outer binding");
        let encoded = serde_json::to_value(&envelope).expect("serialize cleanup attempt");
        let decoded: EventEnvelope =
            serde_json::from_value(encoded.clone()).expect("deserialize cleanup attempt");
        assert_eq!(decoded, envelope);

        let mut unknown = encoded;
        unknown["event"]["payload"]
            .as_object_mut()
            .expect("cleanup-attempt payload")
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<EventEnvelope>(unknown).is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let token = state(1, 1);
        let mut value = serde_json::to_value(CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(1).unwrap(),
            session_id: Some(token.session_id),
            expected_state: Some(token),
            command: DebugCommand::Close { state: token },
        })
        .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<CommandEnvelope>(value).is_err());
    }
}
