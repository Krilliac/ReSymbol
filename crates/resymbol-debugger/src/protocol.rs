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
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

pub use crate::identity::{HostRiskLeaseId, SandboxOwnershipLeaseId, SessionId};
use crate::sandbox::{
    CleanupAttemptFailureError, SandboxAttestation, SandboxFailureValidationError,
    SandboxLifecycleEvent, SandboxPolicy,
};
use resymbol_core::BinaryId;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 7;
pub const MAX_LAUNCH_ARGUMENTS: usize = 128;
pub const MAX_LAUNCH_ARGUMENT_BYTES: usize = 256 * 1024;
pub const MAX_MEMORY_READ_BYTES: u32 = 1024 * 1024;
pub const MAX_MEMORY_WRITE_BYTES: usize = 64 * 1024;
pub const MAX_REASON_BYTES: usize = 1024;
pub const MAX_CAPABILITY_STATUSES: usize = 64;
pub const MAX_REGISTERS: usize = 256;
pub const MAX_REGISTER_NAME_BYTES: usize = 32;
pub const MEMORY_WRITE_FAILURE_REJECTION_CODE: &str = "memory-write-failed";

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

/// Exact identity and runtime image mapping for the main module of one live
/// process instance.
///
/// Providers must derive the process freshness key and actual image base from
/// the same trusted process handle used for the launch or attach. Static RVAs may be
/// translated only through this validated binding; a PID, preferred PE image
/// base, or matching path is not sufficient evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveTargetBinding {
    process: ProcessIdentity,
    main_module_binary_id: BinaryId,
    actual_image_base: MemoryAddress,
    size_of_image: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveTargetBindingWire {
    process: ProcessIdentity,
    main_module_binary_id: BinaryId,
    actual_image_base: MemoryAddress,
    size_of_image: u32,
}

impl LiveTargetBinding {
    pub fn new(
        process: ProcessIdentity,
        main_module_binary_id: BinaryId,
        actual_image_base: MemoryAddress,
        size_of_image: u32,
    ) -> Result<Self, LiveTargetBindingError> {
        if process.binary_id != main_module_binary_id {
            return Err(LiveTargetBindingError::MainModuleIdentityMismatch);
        }
        if actual_image_base.get() == 0 {
            return Err(LiveTargetBindingError::ZeroImageBase);
        }
        if size_of_image == 0 {
            return Err(LiveTargetBindingError::EmptyImage);
        }
        actual_image_base
            .get()
            .checked_add(u64::from(size_of_image))
            .ok_or(LiveTargetBindingError::ImageAddressOverflow {
                base: actual_image_base.get(),
                size_of_image,
            })?;
        Ok(Self {
            process,
            main_module_binary_id,
            actual_image_base,
            size_of_image,
        })
    }

    #[must_use]
    pub const fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    #[must_use]
    pub const fn main_module_binary_id(&self) -> &BinaryId {
        &self.main_module_binary_id
    }

    #[must_use]
    pub const fn actual_image_base(&self) -> MemoryAddress {
        self.actual_image_base
    }

    #[must_use]
    pub const fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    /// Returns the exclusive end of the validated runtime image range.
    #[must_use]
    pub fn image_end(&self) -> MemoryAddress {
        MemoryAddress::new(
            self.actual_image_base
                .get()
                .checked_add(u64::from(self.size_of_image))
                .expect("LiveTargetBinding construction validates its image range"),
        )
    }

    /// Translates one byte at a static RVA into the actual ASLR-adjusted VA.
    pub fn address_for_rva(&self, rva: u64) -> Result<MemoryAddress, LiveTargetBindingError> {
        self.address_for_rva_span(rva, 1)
    }

    /// Translates a nonempty static RVA span wholly contained in SizeOfImage.
    pub fn address_for_rva_span(
        &self,
        rva: u64,
        size: u64,
    ) -> Result<MemoryAddress, LiveTargetBindingError> {
        if size == 0 {
            return Err(LiveTargetBindingError::EmptySpan);
        }
        if rva >= u64::from(self.size_of_image) {
            return Err(LiveTargetBindingError::RvaOutOfImage {
                rva,
                size_of_image: self.size_of_image,
            });
        }
        let span_end = rva
            .checked_add(size)
            .ok_or(LiveTargetBindingError::RvaSpanOverflow { rva, size })?;
        if span_end > u64::from(self.size_of_image) {
            return Err(LiveTargetBindingError::SpanOutOfImage {
                rva,
                size,
                size_of_image: self.size_of_image,
            });
        }
        let address = self.actual_image_base.get().checked_add(rva).ok_or(
            LiveTargetBindingError::ImageAddressOverflow {
                base: self.actual_image_base.get(),
                size_of_image: self.size_of_image,
            },
        )?;
        Ok(MemoryAddress::new(address))
    }

    /// Translates one actual ASLR-adjusted VA into its static main-image RVA.
    pub fn rva_for_address(&self, address: MemoryAddress) -> Result<u64, LiveTargetBindingError> {
        self.rva_for_address_span(address, 1)
    }

    /// Translates a nonempty actual-VA span wholly contained in SizeOfImage.
    ///
    /// Providers should use this checked inverse instead of subtracting the
    /// image base themselves before calling an RVA-bound live-memory backend.
    pub fn rva_for_address_span(
        &self,
        address: MemoryAddress,
        size: u64,
    ) -> Result<u64, LiveTargetBindingError> {
        if size == 0 {
            return Err(LiveTargetBindingError::EmptySpan);
        }
        let address = address.get();
        let base = self.actual_image_base.get();
        let rva = address
            .checked_sub(base)
            .ok_or(LiveTargetBindingError::AddressBeforeImage { address, base })?;
        if rva >= u64::from(self.size_of_image) {
            return Err(LiveTargetBindingError::AddressOutOfImage {
                address,
                base,
                size_of_image: self.size_of_image,
            });
        }
        let span_end = address
            .checked_add(size)
            .ok_or(LiveTargetBindingError::AddressSpanOverflow { address, size })?;
        let image_end = self.image_end().get();
        if span_end > image_end {
            return Err(LiveTargetBindingError::AddressSpanOutOfImage {
                address,
                size,
                image_end,
            });
        }
        Ok(rva)
    }
}

impl<'de> Deserialize<'de> for LiveTargetBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LiveTargetBindingWire::deserialize(deserializer)?;
        Self::new(
            wire.process,
            wire.main_module_binary_id,
            wire.actual_image_base,
            wire.size_of_image,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum LiveTargetBindingError {
    #[error("main-module binary identity differs from the live process identity")]
    MainModuleIdentityMismatch,
    #[error("live image base must be nonzero")]
    ZeroImageBase,
    #[error("live SizeOfImage must be nonzero")]
    EmptyImage,
    #[error("live image base {base:#x} plus SizeOfImage {size_of_image:#x} overflows")]
    ImageAddressOverflow { base: u64, size_of_image: u32 },
    #[error("RVA span must be nonempty")]
    EmptySpan,
    #[error("RVA {rva:#x} is outside SizeOfImage {size_of_image:#x}")]
    RvaOutOfImage { rva: u64, size_of_image: u32 },
    #[error("RVA {rva:#x} plus span size {size:#x} overflows")]
    RvaSpanOverflow { rva: u64, size: u64 },
    #[error("RVA {rva:#x} plus span size {size:#x} exceeds SizeOfImage {size_of_image:#x}")]
    SpanOutOfImage {
        rva: u64,
        size: u64,
        size_of_image: u32,
    },
    #[error("actual address {address:#x} precedes live image base {base:#x}")]
    AddressBeforeImage { address: u64, base: u64 },
    #[error(
        "actual address {address:#x} is outside live image {base:#x} + SizeOfImage {size_of_image:#x}"
    )]
    AddressOutOfImage {
        address: u64,
        base: u64,
        size_of_image: u32,
    },
    #[error("actual address {address:#x} plus span size {size:#x} overflows")]
    AddressSpanOverflow { address: u64, size: u64 },
    #[error(
        "actual address {address:#x} plus span size {size:#x} exceeds live image end {image_end:#x}"
    )]
    AddressSpanOutOfImage {
        address: u64,
        size: u64,
        image_end: u64,
    },
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

macro_rules! define_debug_capabilities {
    ($($variant:ident),+ $(,)?) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(rename_all = "kebab-case")]
        pub enum DebugCapability {
            $($variant,)+
        }

        impl DebugCapability {
            /// Complete, stable protocol order for capability negotiation.
            pub const ALL: [Self; define_debug_capabilities!(@count $($variant),+)] = [
                $(Self::$variant,)+
            ];
        }
    };
    (@count $($variant:ident),+) => {
        <[()]>::len(&[$(define_debug_capabilities!(@unit $variant)),+])
    };
    (@unit $variant:ident) => { () };
}

define_debug_capabilities! {
    OfflineAnalysis,
    DumpRead,
    SnapshotRead,
    ObserveProcess,
    LiveMemoryRead,
    LiveMemoryWrite,
    ExecutionControl,
    StepInto,
    StepOver,
    StepOut,
    RegisterRead,
    RegisterWrite,
    SoftwareBreakpoints,
    HardwareBreakpoints,
    SandboxedLaunch,
    HostLaunch,
    HostAttach,
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
        for capability in DebugCapability::ALL {
            if !seen.contains(&capability) {
                return Err(ProtocolValidationError::MissingCapability { capability });
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

/// Whether a breakpoint remains registered after its first hit.
///
/// This policy is carried by the set command and echoed by correlated host
/// evidence. `Temporary` is the typed policy used by higher-level operations
/// such as Run to Cursor; it does not itself authorize a continue command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BreakpointPersistence {
    /// Keep the logical breakpoint registered after an acknowledged hit.
    Persistent,
    /// Remove the logical breakpoint after its first acknowledged hit.
    Temporary,
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

/// Self-describing target architecture that tags every register payload so a
/// register set or write can be interpreted without out-of-band context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RegisterArch {
    #[serde(rename = "x86")]
    X86,
    #[serde(rename = "x86-64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
    #[serde(rename = "arm")]
    Arm,
    #[serde(rename = "mips32")]
    Mips32,
    #[serde(rename = "mips64")]
    Mips64,
    #[serde(rename = "riscv32")]
    Riscv32,
    #[serde(rename = "riscv64")]
    Riscv64,
    #[serde(rename = "powerpc32")]
    PowerPc32,
    #[serde(rename = "powerpc64")]
    PowerPc64,
}

/// Bounded, validated register identifier newtype.
///
/// Names are nonempty, at most [`MAX_REGISTER_NAME_BYTES`] bytes, and restricted
/// to ASCII alphanumerics plus `_` and `.` so a set is deterministic on the wire.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegisterName(String);

impl RegisterName {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolValidationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REGISTER_NAME_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        {
            return Err(ProtocolValidationError::InvalidRegisterName);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for RegisterName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RegisterName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// One register name bound to its exact 64-bit value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterValue {
    pub name: RegisterName,
    pub value: u64,
}

fn validate_register_list(registers: &[RegisterValue]) -> Result<(), ProtocolValidationError> {
    if registers.len() > MAX_REGISTERS {
        return Err(ProtocolValidationError::TooManyRegisters {
            actual: registers.len(),
            maximum: MAX_REGISTERS,
        });
    }
    let mut seen = BTreeSet::new();
    for register in registers {
        if !seen.insert(register.name.as_str()) {
            return Err(ProtocolValidationError::DuplicateRegisterName {
                name: register.name.as_str().to_owned(),
            });
        }
    }
    Ok(())
}

/// Arch-tagged snapshot of register values reported by a backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterSet {
    pub arch: RegisterArch,
    pub registers: Vec<RegisterValue>,
}

impl RegisterSet {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_register_list(&self.registers)
    }
}

/// Arch-tagged subset of registers a controller intends to overwrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterWrite {
    pub arch: RegisterArch,
    pub registers: Vec<RegisterValue>,
}

impl RegisterWrite {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_register_list(&self.registers)
    }
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
    ReadRegisters {
        view: ReadViewToken,
        thread_id: ThreadId,
    },
    WriteRegisters {
        stop: StopToken,
        thread_id: ThreadId,
        registers: RegisterWrite,
    },
    SetBreakpoint {
        stop: StopToken,
        breakpoint: BreakpointSpec,
        persistence: BreakpointPersistence,
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
            Self::WriteRegisters { registers, .. } => registers.validate(),
            Self::SetBreakpoint { breakpoint, .. } => breakpoint.validate(),
            Self::ProbeCapabilities
            | Self::Continue { .. }
            | Self::Pause { .. }
            | Self::Step { .. }
            | Self::ReadRegisters { .. }
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
            | Self::WriteRegisters { stop, .. }
            | Self::SetBreakpoint { stop, .. }
            | Self::RemoveBreakpoint { stop, .. } => Some(stop.state),
            Self::Pause { run } => Some(run.state),
            Self::ReadMemory { view, .. } | Self::ReadRegisters { view, .. } => Some(view.state()),
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
            | (DebugCommand::WriteRegisters { stop, .. }, SessionState::Stopped { token, .. })
            | (DebugCommand::SetBreakpoint { stop, .. }, SessionState::Stopped { token, .. })
            | (DebugCommand::RemoveBreakpoint { stop, .. }, SessionState::Stopped { token, .. }) => {
                stop == token
            }
            (DebugCommand::Pause { run }, SessionState::Running { token }) => run == token,
            (DebugCommand::ReadMemory { view, .. }, _)
            | (DebugCommand::ReadRegisters { view, .. }, _) => state.matches_read_view(*view),
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
        /// Exact suspended process created for this provisioning attempt.
        /// Attestation and cleanup must retain this PID/start-key/image tuple.
        process: ProcessIdentity,
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
            | Self::AwaitingAttestation { token, .. }
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

/// Provider-neutral stage at which a compare-before-write mutation failed.
///
/// The stage names describe observable protocol boundaries rather than any
/// platform API. A platform adapter maps its calls onto these boundaries and
/// reports recovery separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum MemoryWriteStage {
    ChangeProtection,
    ProtectionRace,
    RevalidateExpectedBytes,
    WriteReplacement,
    FlushReplacement,
    RestoreProtection,
    VerifyReplacement,
    ValidateFinalBinding,
}

/// Bounded recovery evidence for a failed compare-before-write mutation.
///
/// `Restored` means the provider proved the original bytes, instruction-cache
/// flush, and original protection. Boolean fields record only independently
/// proven facts; an indeterminate result is never inferred to be safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "recovery", rename_all = "kebab-case", deny_unknown_fields)]
pub enum MemoryWriteRecovery {
    NoWriteAttempted {
        protection_restored: bool,
    },
    Restored,
    Indeterminate {
        bytes_restored: bool,
        instruction_cache_flushed: bool,
        protection_restored: bool,
    },
}

impl MemoryWriteRecovery {
    /// Whether the remote-command checkpoint may be restored without hiding a
    /// target-side effect.
    #[must_use]
    pub const fn is_rollback_safe(self) -> bool {
        matches!(
            self,
            Self::NoWriteAttempted {
                protection_restored: true
            } | Self::Restored
        )
    }
}

/// Exact command-correlated diagnostic for one failed memory-write attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryWriteFailure {
    pub stop: StopToken,
    pub address: MemoryAddress,
    pub size: u32,
    pub stage: MemoryWriteStage,
    pub recovery: MemoryWriteRecovery,
    pub detail: String,
}

impl MemoryWriteFailure {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.size == 0 {
            return Err(ProtocolValidationError::EmptyMemoryWrite);
        }
        let size = usize::try_from(self.size).map_err(|_| {
            ProtocolValidationError::MemoryWriteTooLarge {
                actual: usize::MAX,
                maximum: MAX_MEMORY_WRITE_BYTES,
            }
        })?;
        if size > MAX_MEMORY_WRITE_BYTES {
            return Err(ProtocolValidationError::MemoryWriteTooLarge {
                actual: size,
                maximum: MAX_MEMORY_WRITE_BYTES,
            });
        }
        self.address.validate_span(size)?;
        validate_reason(&self.detail)?;

        let before_write = matches!(
            self.stage,
            MemoryWriteStage::ChangeProtection
                | MemoryWriteStage::ProtectionRace
                | MemoryWriteStage::RevalidateExpectedBytes
        );
        let canonical = match self.recovery {
            MemoryWriteRecovery::NoWriteAttempted { .. } => before_write,
            MemoryWriteRecovery::Restored => !before_write,
            MemoryWriteRecovery::Indeterminate {
                bytes_restored,
                instruction_cache_flushed,
                protection_restored,
            } => {
                !(before_write
                    || (bytes_restored && instruction_cache_flushed && protection_restored))
            }
        };
        if canonical {
            Ok(())
        } else {
            Err(
                ProtocolValidationError::MemoryWriteFailureRecoveryMismatch {
                    stage: self.stage,
                    recovery: self.recovery,
                },
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum BreakpointChange {
    /// A breakpoint was set with the exact policy echoed from its command.
    Set { persistence: BreakpointPersistence },
    /// A breakpoint was removed. Removal evidence makes no lifetime claim.
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
    LiveTargetBound {
        state: StateToken,
        binding: LiveTargetBinding,
    },
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
    RegistersRead {
        view: ReadViewToken,
        thread_id: ThreadId,
        registers: RegisterSet,
    },
    RegistersWritten {
        stop: StopToken,
        thread_id: ThreadId,
        before: RegisterSet,
        after: RegisterSet,
    },
    MemoryWriteFailed(MemoryWriteFailure),
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
            Self::LiveTargetBound { .. } => Ok(()),
            Self::StateChanged(SessionState::Failed { message, .. }) => validate_reason(message),
            Self::SandboxLifecycle(SandboxLifecycleEvent::Failed(failure)) => {
                failure.validate_stage_kind()?;
                Ok(())
            }
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
            Self::RegistersRead { registers, .. } => registers.validate(),
            Self::RegistersWritten { before, after, .. } => {
                before.validate()?;
                after.validate()
            }
            Self::MemoryWriteFailed(failure) => failure.validate(),
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
            Self::LiveTargetBound { state, .. } => Some(*state),
            Self::MemoryRead { view, .. } | Self::RegistersRead { view, .. } => Some(view.state()),
            Self::MemoryWritten { stop, .. }
            | Self::RegistersWritten { stop, .. }
            | Self::BreakpointChanged { stop, .. } => Some(stop.state),
            Self::MemoryWriteFailed(failure) => Some(failure.stop.state),
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
    #[error(transparent)]
    SandboxFailure(#[from] SandboxFailureValidationError),
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
    #[error("capability report is missing an explicit status for {capability:?}")]
    MissingCapability { capability: DebugCapability },
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
    #[error("memory-write failure stage {stage:?} is incompatible with recovery {recovery:?}")]
    MemoryWriteFailureRecoveryMismatch {
        stage: MemoryWriteStage,
        recovery: MemoryWriteRecovery,
    },
    #[error("command is not a memory-write command")]
    NotMemoryWriteCommand,
    #[error("register name is empty, too long, or contains disallowed characters")]
    InvalidRegisterName,
    #[error("register payload has {actual} registers; maximum is {maximum}")]
    TooManyRegisters { actual: usize, maximum: usize },
    #[error("duplicate register name {name}")]
    DuplicateRegisterName { name: String },
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
        HelperBuildId, IsolationBoundary, PolicyDigest, SandboxAttestation,
        SandboxCleanupAttemptFailure, SandboxCleanupReceipt, SandboxFailure, SandboxFailureContext,
        SandboxFailureKind, SandboxFailureStage, SandboxGuarantee, SandboxProviderSelection,
        SandboxTargetCreationOutcome,
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

    fn process(binary_id: BinaryId) -> ProcessIdentity {
        ProcessIdentity {
            process_id: ProcessId::new(4100).expect("process id"),
            start_key: ProcessStartKey::new(27).expect("process start key"),
            binary_id,
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
                        provisioning_epoch: receipt.provisioning_epoch.clone(),
                        policy_digest: receipt.policy_digest.clone(),
                        provider: SandboxProviderSelection::LocalAppContainer,
                        context: SandboxFailureContext::Launch {
                            binary_id: BinaryId::digest(b"cleanup-attempt binary"),
                            helper_build: HelperBuildId::new("cleanup-attempt-helper")
                                .expect("helper build"),
                            target_creation: SandboxTargetCreationOutcome::NotCreated,
                        },
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
    fn created_process_identity_is_mandatory_in_state_and_attestation_payloads() {
        let binary_id = BinaryId::digest(b"sandboxed protocol target");
        let process = process(binary_id.clone());
        let awaiting = SessionState::AwaitingAttestation {
            token: state(1, 2),
            process: process.clone(),
        };
        let mut state_value = serde_json::to_value(&awaiting).expect("serialize state");
        state_value
            .as_object_mut()
            .expect("state object")
            .remove("process");
        assert!(serde_json::from_value::<SessionState>(state_value).is_err());

        let attestation = SandboxAttestation {
            binary_id,
            process,
            session_id: session(1),
            provisioning_epoch: ProvisioningEpoch::new("a".repeat(64)).expect("epoch"),
            policy_digest: PolicyDigest::new("b".repeat(64)).expect("policy digest"),
            provider: SandboxProviderSelection::LocalAppContainer,
            boundary: IsolationBoundary::UserMode,
            guarantees: BTreeSet::from([SandboxGuarantee::JobAssignmentAtCreation]),
            job_assigned_at_creation: true,
            helper_build: HelperBuildId::new("protocol-test-helper").expect("helper build"),
            vm_identity: None,
        };
        let mut attestation_value =
            serde_json::to_value(&attestation).expect("serialize attestation");
        attestation_value
            .as_object_mut()
            .expect("attestation object")
            .remove("process");
        assert!(serde_json::from_value::<SandboxAttestation>(attestation_value).is_err());
    }

    #[test]
    fn live_target_binding_translates_only_valid_aslr_adjusted_image_spans() {
        let binary_id = BinaryId::digest(b"live target binding image");
        let binding = LiveTargetBinding::new(
            process(binary_id.clone()),
            binary_id,
            MemoryAddress::new(0x0000_7ff7_4000_0000),
            0x2_0000,
        )
        .expect("valid live target binding");

        assert_eq!(
            binding.address_for_rva(0x1234).expect("in-image RVA"),
            MemoryAddress::new(0x0000_7ff7_4000_1234)
        );
        assert_eq!(
            binding
                .address_for_rva_span(0x1_ff00, 0x100)
                .expect("span ending at SizeOfImage"),
            MemoryAddress::new(0x0000_7ff7_4001_ff00)
        );
        assert_eq!(binding.image_end().get(), 0x0000_7ff7_4002_0000);
        assert_eq!(
            binding.address_for_rva(0x2_0000),
            Err(LiveTargetBindingError::RvaOutOfImage {
                rva: 0x2_0000,
                size_of_image: 0x2_0000,
            })
        );
        assert_eq!(
            binding.address_for_rva_span(0x1_ffff, 2),
            Err(LiveTargetBindingError::SpanOutOfImage {
                rva: 0x1_ffff,
                size: 2,
                size_of_image: 0x2_0000,
            })
        );
        assert_eq!(
            binding.address_for_rva_span(1, u64::MAX),
            Err(LiveTargetBindingError::RvaSpanOverflow {
                rva: 1,
                size: u64::MAX,
            })
        );
        assert_eq!(
            binding.address_for_rva_span(0, 0),
            Err(LiveTargetBindingError::EmptySpan)
        );
        assert_eq!(
            binding
                .rva_for_address(MemoryAddress::new(0x0000_7ff7_4000_1234))
                .expect("in-image actual address"),
            0x1234
        );
        assert_eq!(
            binding
                .rva_for_address_span(MemoryAddress::new(0x0000_7ff7_4001_ff00), 0x100)
                .expect("actual span ending at SizeOfImage"),
            0x1_ff00
        );
        assert_eq!(
            binding
                .rva_for_address_span(MemoryAddress::new(0x0000_7ff7_4000_0000), 0x2_0000)
                .expect("whole image span"),
            0
        );
        for (rva, size) in [(0, 1), (0x1234, 0x40), (0x1_ffff, 1)] {
            let address = binding
                .address_for_rva_span(rva, size)
                .expect("valid forward translation");
            assert_eq!(
                binding
                    .rva_for_address_span(address, size)
                    .expect("valid inverse translation"),
                rva
            );
        }
        assert_eq!(
            binding.rva_for_address(MemoryAddress::new(0x0000_7ff7_3fff_ffff)),
            Err(LiveTargetBindingError::AddressBeforeImage {
                address: 0x0000_7ff7_3fff_ffff,
                base: 0x0000_7ff7_4000_0000,
            })
        );
        assert_eq!(
            binding.rva_for_address(MemoryAddress::new(0x0000_7ff7_4002_0000)),
            Err(LiveTargetBindingError::AddressOutOfImage {
                address: 0x0000_7ff7_4002_0000,
                base: 0x0000_7ff7_4000_0000,
                size_of_image: 0x2_0000,
            })
        );
        assert_eq!(
            binding.rva_for_address_span(MemoryAddress::new(0x0000_7ff7_4001_ffff), 2),
            Err(LiveTargetBindingError::AddressSpanOutOfImage {
                address: 0x0000_7ff7_4001_ffff,
                size: 2,
                image_end: 0x0000_7ff7_4002_0000,
            })
        );
        assert_eq!(
            binding.rva_for_address_span(MemoryAddress::new(0x0000_7ff7_4000_0001), u64::MAX,),
            Err(LiveTargetBindingError::AddressSpanOverflow {
                address: 0x0000_7ff7_4000_0001,
                size: u64::MAX,
            })
        );
        assert_eq!(
            binding.rva_for_address_span(MemoryAddress::new(0x0000_7ff7_4000_0000), 0),
            Err(LiveTargetBindingError::EmptySpan)
        );
        assert_eq!(
            binding.rva_for_address_span(MemoryAddress::new(u64::MAX), 0),
            Err(LiveTargetBindingError::EmptySpan)
        );

        let upper_binary_id = BinaryId::digest(b"upper-bound live target binding image");
        let upper_bound = LiveTargetBinding::new(
            ProcessIdentity {
                process_id: ProcessId::new(10).expect("process id"),
                start_key: ProcessStartKey::new(11).expect("process start key"),
                binary_id: upper_binary_id.clone(),
            },
            upper_binary_id,
            MemoryAddress::new(u64::MAX - 0x1_0000),
            0x1_0000,
        )
        .expect("image whose exclusive end is u64::MAX");
        assert_eq!(
            upper_bound
                .rva_for_address(MemoryAddress::new(u64::MAX - 1))
                .expect("last mapped byte"),
            0xffff
        );
        assert_eq!(
            upper_bound.rva_for_address(MemoryAddress::new(u64::MAX)),
            Err(LiveTargetBindingError::AddressOutOfImage {
                address: u64::MAX,
                base: u64::MAX - 0x1_0000,
                size_of_image: 0x1_0000,
            })
        );
    }

    #[test]
    fn live_target_binding_rejects_wrong_identity_empty_and_overflowing_images() {
        let binary_id = BinaryId::digest(b"expected live image");
        let identity = process(binary_id.clone());
        assert_eq!(
            LiveTargetBinding::new(
                identity.clone(),
                BinaryId::digest(b"wrong live image"),
                MemoryAddress::new(0x0001_4000_0000),
                0x1000,
            ),
            Err(LiveTargetBindingError::MainModuleIdentityMismatch)
        );
        assert_eq!(
            LiveTargetBinding::new(
                identity.clone(),
                binary_id.clone(),
                MemoryAddress::new(0),
                0x1000,
            ),
            Err(LiveTargetBindingError::ZeroImageBase)
        );
        assert_eq!(
            LiveTargetBinding::new(
                identity.clone(),
                binary_id.clone(),
                MemoryAddress::new(0x0001_4000_0000),
                0,
            ),
            Err(LiveTargetBindingError::EmptyImage)
        );
        assert_eq!(
            LiveTargetBinding::new(
                identity,
                binary_id,
                MemoryAddress::new(u64::MAX - 0xff),
                0x100,
            ),
            Err(LiveTargetBindingError::ImageAddressOverflow {
                base: u64::MAX - 0xff,
                size_of_image: 0x100,
            })
        );
    }

    #[test]
    fn live_target_binding_deserialization_and_event_context_are_strict() {
        let binary_id = BinaryId::digest(b"strict live image");
        let binding = LiveTargetBinding::new(
            process(binary_id.clone()),
            binary_id,
            MemoryAddress::new(0x0001_8000_0000),
            0x5000,
        )
        .expect("valid binding");
        let mut malformed = serde_json::to_value(&binding).expect("serialize binding");
        malformed["main_module_binary_id"] =
            serde_json::to_value(BinaryId::digest(b"substituted module")).expect("binary id");
        assert!(serde_json::from_value::<LiveTargetBinding>(malformed).is_err());

        let event = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(1).expect("event sequence"),
            session_id: Some(session(1)),
            state: Some(state(1, 3)),
            caused_by: Some(CommandId::new(1).expect("command id")),
            event: DebugEvent::LiveTargetBound {
                state: state(1, 2),
                binding,
            },
        };
        assert_eq!(
            event.validate(),
            Err(ProtocolValidationError::StaleStateToken)
        );
        let mut wrong_session = event;
        wrong_session.session_id = Some(session(2));
        assert_eq!(
            wrong_session.validate(),
            Err(ProtocolValidationError::StaleSession)
        );
    }

    #[test]
    fn step_capability_report_is_complete_and_previous_minor_is_rejected() {
        assert_eq!(DebugCapability::ALL.len(), 17);
        for capability in [
            DebugCapability::StepInto,
            DebugCapability::StepOver,
            DebugCapability::StepOut,
        ] {
            assert!(DebugCapability::ALL.contains(&capability));
        }
        let report = CapabilityReport {
            statuses: DebugCapability::ALL
                .into_iter()
                .map(|capability| CapabilityStatus {
                    capability,
                    availability: CapabilityAvailability::Available,
                })
                .collect(),
        };
        report.validate().expect("complete capability report");
        assert_eq!(
            ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR - 1,
            }
            .validate(),
            Err(ProtocolValidationError::UnsupportedProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR - 1,
            })
        );
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
    fn memory_write_failure_evidence_is_strict_canonical_and_state_bound() {
        let stop = stop(1, 2, 3);
        let address = MemoryAddress::new(0x2000);
        let detail = "target memory mutation failed".to_owned();
        let valid = [
            (
                MemoryWriteStage::ChangeProtection,
                MemoryWriteRecovery::NoWriteAttempted {
                    protection_restored: true,
                },
            ),
            (
                MemoryWriteStage::ProtectionRace,
                MemoryWriteRecovery::NoWriteAttempted {
                    protection_restored: false,
                },
            ),
            (
                MemoryWriteStage::RevalidateExpectedBytes,
                MemoryWriteRecovery::NoWriteAttempted {
                    protection_restored: true,
                },
            ),
            (
                MemoryWriteStage::WriteReplacement,
                MemoryWriteRecovery::Restored,
            ),
            (
                MemoryWriteStage::FlushReplacement,
                MemoryWriteRecovery::Indeterminate {
                    bytes_restored: true,
                    instruction_cache_flushed: false,
                    protection_restored: true,
                },
            ),
            (
                MemoryWriteStage::RestoreProtection,
                MemoryWriteRecovery::Indeterminate {
                    bytes_restored: false,
                    instruction_cache_flushed: true,
                    protection_restored: false,
                },
            ),
            (
                MemoryWriteStage::VerifyReplacement,
                MemoryWriteRecovery::Restored,
            ),
            (
                MemoryWriteStage::ValidateFinalBinding,
                MemoryWriteRecovery::Indeterminate {
                    bytes_restored: false,
                    instruction_cache_flushed: false,
                    protection_restored: false,
                },
            ),
        ];

        for (sequence, (stage, recovery)) in valid.into_iter().enumerate() {
            let failure = MemoryWriteFailure {
                stop,
                address,
                size: 2,
                stage,
                recovery,
                detail: detail.clone(),
            };
            failure.validate().expect("canonical write failure");
            let envelope = EventEnvelope {
                version: ProtocolVersion::current(),
                sequence: EventSequence::new(sequence as u64 + 1).expect("event sequence"),
                session_id: Some(stop.state.session_id),
                state: Some(stop.state),
                caused_by: Some(CommandId::new(9).expect("command id")),
                event: DebugEvent::MemoryWriteFailed(failure),
            };
            envelope.validate().expect("state-bound failure event");
            let encoded = serde_json::to_value(&envelope).expect("serialize failure event");
            assert_eq!(
                serde_json::from_value::<EventEnvelope>(encoded)
                    .expect("deserialize failure event"),
                envelope
            );
        }

        let base = MemoryWriteFailure {
            stop,
            address,
            size: 2,
            stage: MemoryWriteStage::WriteReplacement,
            recovery: MemoryWriteRecovery::Restored,
            detail,
        };
        let mut unknown = serde_json::to_value(&base).expect("serialize failure");
        unknown
            .as_object_mut()
            .expect("failure object")
            .insert("future".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<MemoryWriteFailure>(unknown).is_err());
        let mut missing = serde_json::to_value(&base).expect("serialize failure");
        missing
            .as_object_mut()
            .expect("failure object")
            .remove("detail");
        assert!(serde_json::from_value::<MemoryWriteFailure>(missing).is_err());

        let mut wrong_state = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(20).expect("event sequence"),
            session_id: Some(stop.state.session_id),
            state: Some(state(1, 3)),
            caused_by: Some(CommandId::new(9).expect("command id")),
            event: DebugEvent::MemoryWriteFailed(base),
        };
        assert_eq!(
            wrong_state.validate(),
            Err(ProtocolValidationError::StaleStateToken)
        );
        wrong_state.session_id = Some(session(2));
        assert_eq!(
            wrong_state.validate(),
            Err(ProtocolValidationError::StaleSession)
        );
    }

    #[test]
    fn memory_write_failure_recovery_classification_rejects_ambiguous_shapes() {
        assert!(
            MemoryWriteRecovery::NoWriteAttempted {
                protection_restored: true
            }
            .is_rollback_safe()
        );
        assert!(MemoryWriteRecovery::Restored.is_rollback_safe());
        assert!(
            !MemoryWriteRecovery::NoWriteAttempted {
                protection_restored: false
            }
            .is_rollback_safe()
        );
        assert!(
            !MemoryWriteRecovery::Indeterminate {
                bytes_restored: true,
                instruction_cache_flushed: true,
                protection_restored: false,
            }
            .is_rollback_safe()
        );

        let stop = stop(1, 2, 3);
        let failure = |stage, recovery| MemoryWriteFailure {
            stop,
            address: MemoryAddress::new(0x2000),
            size: 1,
            stage,
            recovery,
            detail: "target memory mutation failed".to_owned(),
        };
        for invalid in [
            failure(
                MemoryWriteStage::ChangeProtection,
                MemoryWriteRecovery::Restored,
            ),
            failure(
                MemoryWriteStage::WriteReplacement,
                MemoryWriteRecovery::NoWriteAttempted {
                    protection_restored: true,
                },
            ),
            failure(
                MemoryWriteStage::WriteReplacement,
                MemoryWriteRecovery::Indeterminate {
                    bytes_restored: true,
                    instruction_cache_flushed: true,
                    protection_restored: true,
                },
            ),
        ] {
            assert!(matches!(
                invalid.validate(),
                Err(ProtocolValidationError::MemoryWriteFailureRecoveryMismatch { .. })
            ));
        }

        let mut empty = failure(
            MemoryWriteStage::ChangeProtection,
            MemoryWriteRecovery::NoWriteAttempted {
                protection_restored: true,
            },
        );
        empty.size = 0;
        assert_eq!(
            empty.validate(),
            Err(ProtocolValidationError::EmptyMemoryWrite)
        );
        empty.size = u32::try_from(MAX_MEMORY_WRITE_BYTES).expect("write maximum") + 1;
        assert!(matches!(
            empty.validate(),
            Err(ProtocolValidationError::MemoryWriteTooLarge { .. })
        ));
        empty.size = 1;
        empty.address = MemoryAddress::new(u64::MAX);
        assert!(matches!(
            empty.validate(),
            Err(ProtocolValidationError::AddressOverflow { .. })
        ));
        empty.address = MemoryAddress::new(0x2000);
        empty.detail.clear();
        assert_eq!(
            empty.validate(),
            Err(ProtocolValidationError::InvalidReason)
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
    fn capability_report_is_complete_bounded_and_duplicate_free() {
        let status = CapabilityStatus {
            capability: DebugCapability::LiveMemoryWrite,
            availability: CapabilityAvailability::Unavailable {
                code: CapabilityUnavailableCode::TargetModeReadOnly,
                reason: "snapshot sessions are immutable".to_owned(),
            },
        };
        let report = CapabilityReport {
            statuses: DebugCapability::ALL
                .map(|capability| {
                    if capability == status.capability {
                        status.clone()
                    } else {
                        CapabilityStatus {
                            capability,
                            availability: CapabilityAvailability::Available,
                        }
                    }
                })
                .into(),
        };
        report
            .validate()
            .expect("complete capability catalog is unique and bounded");

        let mut missing = report.clone();
        missing
            .statuses
            .retain(|entry| entry.capability != DebugCapability::SnapshotRead);
        assert_eq!(
            missing.validate(),
            Err(ProtocolValidationError::MissingCapability {
                capability: DebugCapability::SnapshotRead,
            })
        );

        let mut duplicate = report;
        duplicate.statuses.push(status);
        assert_eq!(
            duplicate.validate(),
            Err(ProtocolValidationError::DuplicateCapability {
                capability: DebugCapability::LiveMemoryWrite,
            })
        );
    }

    #[test]
    fn capability_catalog_preserves_protocol_order_and_wire_names() {
        assert_eq!(
            serde_json::to_value(DebugCapability::ALL).expect("capability catalog serializes"),
            serde_json::json!([
                "offline-analysis",
                "dump-read",
                "snapshot-read",
                "observe-process",
                "live-memory-read",
                "live-memory-write",
                "execution-control",
                "step-into",
                "step-over",
                "step-out",
                "register-read",
                "register-write",
                "software-breakpoints",
                "hardware-breakpoints",
                "sandboxed-launch",
                "host-launch",
                "host-attach",
            ])
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

        let mut missing_outcome = encoded.clone();
        missing_outcome["event"]["payload"]["failure"]["context"]
            .as_object_mut()
            .expect("launch failure context")
            .remove("target_creation");
        assert!(serde_json::from_value::<EventEnvelope>(missing_outcome).is_err());

        let mut unknown = encoded;
        unknown["event"]["payload"]
            .as_object_mut()
            .expect("cleanup-attempt payload")
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<EventEnvelope>(unknown).is_err());
    }

    #[test]
    fn generic_sandbox_failure_rejects_incoherent_stage_kind_at_protocol_boundary() {
        let mut envelope = cleanup_attempt_event();
        let DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::CleanupAttemptFailed(attempt)) =
            envelope.event
        else {
            unreachable!("cleanup-attempt fixture")
        };
        let mut failure = attempt.failure;
        failure.kind = SandboxFailureKind::HelperFailure;
        envelope.event = DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::Failed(failure));

        assert_eq!(
            envelope.validate(),
            Err(ProtocolValidationError::SandboxFailure(
                SandboxFailureValidationError::StageKind {
                    stage: SandboxFailureStage::Cleanup,
                    kind: SandboxFailureKind::HelperFailure,
                }
            ))
        );
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

    fn register_value(name: &str, value: u64) -> RegisterValue {
        RegisterValue {
            name: RegisterName::new(name).expect("valid register name"),
            value,
        }
    }

    #[test]
    fn register_payloads_validate_bounds_uniqueness_and_names() {
        RegisterSet {
            arch: RegisterArch::X86_64,
            registers: vec![],
        }
        .validate()
        .expect("empty register set is valid");

        RegisterSet {
            arch: RegisterArch::Aarch64,
            registers: vec![register_value("x0", 1), register_value("x1", 2)],
        }
        .validate()
        .expect("distinct registers are valid");

        assert_eq!(
            RegisterWrite {
                arch: RegisterArch::X86_64,
                registers: vec![register_value("rax", 1), register_value("rax", 2)],
            }
            .validate(),
            Err(ProtocolValidationError::DuplicateRegisterName {
                name: "rax".to_owned(),
            })
        );

        assert_eq!(
            RegisterSet {
                arch: RegisterArch::X86_64,
                registers: (0..=MAX_REGISTERS)
                    .map(|index| register_value(&format!("r{index}"), index as u64))
                    .collect(),
            }
            .validate(),
            Err(ProtocolValidationError::TooManyRegisters {
                actual: MAX_REGISTERS + 1,
                maximum: MAX_REGISTERS,
            })
        );

        assert!(RegisterName::new("").is_err());
        assert!(RegisterName::new("bad name").is_err());
        assert!(RegisterName::new("a".repeat(MAX_REGISTER_NAME_BYTES + 1)).is_err());
        RegisterName::new("a".repeat(MAX_REGISTER_NAME_BYTES)).expect("max-length name is valid");
    }

    #[test]
    fn read_registers_is_gated_by_the_exact_read_view() {
        let offline_token = state(1, 2);
        let offline = SessionState::Offline {
            token: offline_token,
        };
        let read = command(
            DebugCommand::ReadRegisters {
                view: ReadViewToken::Offline {
                    state: offline_token,
                },
                thread_id: ThreadId::new(7).unwrap(),
            },
            offline_token,
        );
        read.validate_against(&offline).unwrap();

        let wrong_view = command(
            DebugCommand::ReadRegisters {
                view: ReadViewToken::Observing {
                    state: offline_token,
                },
                thread_id: ThreadId::new(7).unwrap(),
            },
            offline_token,
        );
        assert_eq!(
            wrong_view.validate_against(&offline),
            Err(ProtocolValidationError::StaleExecutionToken)
        );
    }

    #[test]
    fn write_registers_requires_stopped_state_with_matching_stop() {
        let current_stop = stop(1, 4, 20);
        let current = stopped_state(current_stop);
        let registers = RegisterWrite {
            arch: RegisterArch::X86_64,
            registers: vec![register_value("rax", 0x1234)],
        };
        let valid = command(
            DebugCommand::WriteRegisters {
                stop: current_stop,
                thread_id: ThreadId::new(3).unwrap(),
                registers: registers.clone(),
            },
            current_stop.state,
        );
        valid.validate_against(&current).unwrap();

        let stale = command(
            DebugCommand::WriteRegisters {
                stop: stop(1, 4, 19),
                thread_id: ThreadId::new(3).unwrap(),
                registers: registers.clone(),
            },
            state(1, 4),
        );
        assert_eq!(
            stale.validate_against(&current),
            Err(ProtocolValidationError::StaleExecutionToken)
        );

        let running_token = RunToken {
            state: state(2, 5),
            run_id: RunId::new(9).unwrap(),
        };
        let running = SessionState::Running {
            token: running_token,
        };
        let against_running = command(
            DebugCommand::WriteRegisters {
                stop: stop(2, 5, 8),
                thread_id: ThreadId::new(3).unwrap(),
                registers,
            },
            state(2, 5),
        );
        assert_eq!(
            against_running.validate_against(&running),
            Err(ProtocolValidationError::StaleExecutionToken)
        );

        let invalid = DebugCommand::WriteRegisters {
            stop: current_stop,
            thread_id: ThreadId::new(3).unwrap(),
            registers: RegisterWrite {
                arch: RegisterArch::X86_64,
                registers: vec![register_value("rax", 1), register_value("rax", 2)],
            },
        };
        assert_eq!(
            invalid.validate(),
            Err(ProtocolValidationError::DuplicateRegisterName {
                name: "rax".to_owned(),
            })
        );
    }

    #[test]
    fn register_commands_and_events_round_trip_and_reject_unknown_fields() {
        let stop = stop(1, 2, 3);
        let write_command = command(
            DebugCommand::WriteRegisters {
                stop,
                thread_id: ThreadId::new(4).unwrap(),
                registers: RegisterWrite {
                    arch: RegisterArch::Aarch64,
                    registers: vec![register_value("x0", 42)],
                },
            },
            stop.state,
        );
        let encoded = serde_json::to_value(&write_command).expect("serialize write-registers");
        assert_eq!(
            serde_json::from_value::<CommandEnvelope>(encoded.clone()).expect("round-trip command"),
            write_command
        );
        let mut unknown = encoded;
        unknown["command"]["parameters"]["registers"]["registers"][0]
            .as_object_mut()
            .expect("register value object")
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<CommandEnvelope>(unknown).is_err());

        let read_event = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(1).unwrap(),
            session_id: Some(stop.state.session_id),
            state: Some(stop.state),
            caused_by: Some(CommandId::new(9).unwrap()),
            event: DebugEvent::RegistersRead {
                view: ReadViewToken::Stopped { stop },
                thread_id: ThreadId::new(4).unwrap(),
                registers: RegisterSet {
                    arch: RegisterArch::X86_64,
                    registers: vec![register_value("rip", 0xdead_beef)],
                },
            },
        };
        read_event.validate().expect("valid registers-read event");
        let encoded = serde_json::to_value(&read_event).expect("serialize registers-read");
        assert_eq!(
            serde_json::from_value::<EventEnvelope>(encoded).expect("round-trip read event"),
            read_event
        );

        let written_event = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(1).unwrap(),
            session_id: Some(stop.state.session_id),
            state: Some(stop.state),
            caused_by: Some(CommandId::new(9).unwrap()),
            event: DebugEvent::RegistersWritten {
                stop,
                thread_id: ThreadId::new(4).unwrap(),
                before: RegisterSet {
                    arch: RegisterArch::X86_64,
                    registers: vec![register_value("rax", 1)],
                },
                after: RegisterSet {
                    arch: RegisterArch::X86_64,
                    registers: vec![register_value("rax", 2)],
                },
            },
        };
        written_event
            .validate()
            .expect("valid registers-written event");
        let encoded = serde_json::to_value(&written_event).expect("serialize registers-written");
        assert_eq!(
            serde_json::from_value::<EventEnvelope>(encoded).expect("round-trip written event"),
            written_event
        );
    }

    #[test]
    fn protocol_minor_is_seven_and_register_arch_wire_names_are_stable() {
        assert_eq!(PROTOCOL_MINOR, 7);
        assert_eq!(
            serde_json::to_value(RegisterArch::X86_64).unwrap(),
            serde_json::json!("x86-64")
        );
        assert_eq!(
            serde_json::to_value(RegisterArch::PowerPc64).unwrap(),
            serde_json::json!("powerpc64")
        );
    }
}
