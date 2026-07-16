//! Backend-neutral, fail-closed sandbox policy and attestation contracts.

use std::{collections::BTreeSet, fmt};

use resymbol_core::BinaryId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::identity::{ProvisioningEpoch, SessionId};
use crate::protocol::{AttachMode, ProcessIdentity};

const MAX_PROVIDER_ID_BYTES: usize = 96;
const MAX_ACK_ID_BYTES: usize = 128;
const MAX_BUILD_ID_BYTES: usize = 128;
const MAX_RECEIPT_ID_BYTES: usize = 128;
const MAX_VM_ID_BYTES: usize = 128;
const MAX_DIAGNOSTIC_BYTES: usize = 512;
const MAX_CLEANUP_RESIDUALS: usize = 32;

pub const SANDBOX_POLICY_DIGEST_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BoundedValueError {
    #[error("{field} cannot be empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its {maximum}-byte limit")]
    TooLong { field: &'static str, maximum: usize },
    #[error("{field} contains a disallowed character")]
    InvalidCharacter { field: &'static str },
}

fn validate_identifier(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), BoundedValueError> {
    if value.is_empty() {
        return Err(BoundedValueError::Empty { field });
    }
    if value.len() > maximum {
        return Err(BoundedValueError::TooLong { field, maximum });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'+')
    }) {
        return Err(BoundedValueError::InvalidCharacter { field });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $maximum:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, BoundedValueError> {
                let value = value.into();
                validate_identifier(&value, $field, $maximum)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

bounded_identifier!(ProviderId, "provider id", MAX_PROVIDER_ID_BYTES);
bounded_identifier!(
    SandboxPolicyApprovalNonce,
    "sandbox policy approval id",
    MAX_ACK_ID_BYTES
);
bounded_identifier!(HelperBuildId, "helper build id", MAX_BUILD_ID_BYTES);
bounded_identifier!(CleanupReceiptId, "cleanup receipt id", MAX_RECEIPT_ID_BYTES);
bounded_identifier!(SealedImageId, "sealed image id", MAX_VM_ID_BYTES);
bounded_identifier!(DifferencingDiskId, "differencing disk id", MAX_VM_ID_BYTES);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicyApprovalId {
    session_id: SessionId,
    nonce: SandboxPolicyApprovalNonce,
}

impl SandboxPolicyApprovalId {
    pub fn new(session_id: SessionId, nonce: impl Into<String>) -> Result<Self, BoundedValueError> {
        Ok(Self {
            session_id,
            nonce: SandboxPolicyApprovalNonce::new(nonce)?,
        })
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyDigest(String);

impl PolicyDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, PolicyDigestError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(PolicyDigestError);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for PolicyDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PolicyDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("policy digest must be 64 lowercase hexadecimal characters")]
pub struct PolicyDigestError;

macro_rules! lowercase_hex_value {
    ($name:ident, $error:ident, $message:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, $error> {
                let value = value.into();
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                {
                    return Err($error);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
        #[error($message)]
        pub struct $error;
    };
}

lowercase_hex_value!(
    SealedImageDigest,
    SealedImageDigestError,
    "sealed image digest must be 64 lowercase hexadecimal characters"
);
lowercase_hex_value!(
    AuthenticatedChannelNonce,
    AuthenticatedChannelNonceError,
    "authenticated channel nonce must be 64 lowercase hexadecimal characters"
);

/// Authenticated description returned by provider discovery. A registered
/// provider can satisfy only the guarantees explicitly listed here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxProviderDescriptor {
    pub id: ProviderId,
    pub boundary: IsolationBoundary,
    pub guarantees: BTreeSet<SandboxGuarantee>,
    pub build_identity: HelperBuildId,
}

impl SandboxProviderDescriptor {
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        if self.guarantees.is_empty() {
            return Err(PolicyValidationError::EmptyProviderGuarantees);
        }
        if is_reserved_provider_id(self.id.as_str()) {
            return Err(PolicyValidationError::ReservedProviderId);
        }
        Ok(())
    }
}

struct CanonicalPolicyDigest(Sha256);

impl CanonicalPolicyDigest {
    fn new() -> Self {
        Self(Sha256::new())
    }

    fn bytes(&mut self, value: &[u8]) {
        let length = u32::try_from(value.len()).expect("bounded canonical field fits u32");
        self.u32(length);
        self.0.update(value);
    }

    fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn u16(&mut self, value: u16) {
        self.0.update(value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.update(value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }

    fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn boundary(&mut self, value: IsolationBoundary) {
        self.u8(match value {
            IsolationBoundary::UserMode => 1,
            IsolationBoundary::Hypervisor => 2,
        });
    }

    fn network(&mut self, value: SandboxNetworkMode) {
        self.u8(match value {
            SandboxNetworkMode::Disabled => 1,
            SandboxNetworkMode::IsolatedSimulation => 2,
        });
    }

    fn mitigations(&mut self, value: ProcessMitigationProfile) {
        self.u8(match value {
            ProcessMitigationProfile::StrictV1 => 1,
            ProcessMitigationProfile::CompatibilityV1 => 2,
        });
    }

    fn children(&mut self, value: ChildProcessProfile) {
        self.u8(match value {
            ChildProcessProfile::Deny => 1,
            ChildProcessProfile::SameSandboxOnly => 2,
        });
    }

    fn dynamic_code(&mut self, value: DynamicCodeProfile) {
        self.u8(match value {
            DynamicCodeProfile::Prohibit => 1,
            DynamicCodeProfile::MicrosoftSignedOnly => 2,
            DynamicCodeProfile::Allow => 3,
        });
    }

    fn win32k(&mut self, value: Win32kProfile) {
        self.u8(match value {
            Win32kProfile::Disable => 1,
            Win32kProfile::Allow => 2,
        });
    }

    fn guarantee(&mut self, value: SandboxGuarantee) {
        self.u8(match value {
            SandboxGuarantee::FileSystemRedirection => 1,
            SandboxGuarantee::RegistryRedirection => 2,
            SandboxGuarantee::DisposableFileSystem => 3,
            SandboxGuarantee::DisposableRegistry => 4,
            SandboxGuarantee::RollbackOnClose => 5,
            SandboxGuarantee::NetworkDisabled => 6,
            SandboxGuarantee::IsolatedNetworkSimulation => 7,
            SandboxGuarantee::ResourceLimits => 8,
            SandboxGuarantee::ChildProcessControl => 9,
            SandboxGuarantee::ProcessMitigations => 10,
            SandboxGuarantee::JobAssignmentAtCreation => 11,
            SandboxGuarantee::HypervisorBoundary => 12,
        });
    }

    fn guarantees(&mut self, values: &BTreeSet<SandboxGuarantee>) {
        self.u32(u32::try_from(values.len()).expect("bounded guarantee count fits u32"));
        for value in values {
            self.guarantee(*value);
        }
    }

    fn provider(&mut self, provider: &SandboxProviderSelection) {
        match provider {
            SandboxProviderSelection::LocalAppContainer => self.u8(1),
            SandboxProviderSelection::WindowsSandbox => self.u8(2),
            SandboxProviderSelection::HyperV => self.u8(3),
            SandboxProviderSelection::Registered { descriptor } => {
                self.u8(4);
                self.text(descriptor.id.as_str());
                self.boundary(descriptor.boundary);
                self.guarantees(&descriptor.guarantees);
                self.text(descriptor.build_identity.as_str());
            }
        }
    }

    fn finish(self) -> PolicyDigest {
        let digest = self.0.finalize();
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        PolicyDigest::new(encoded).expect("SHA-256 is lowercase hexadecimal")
    }
}

/// Exact disposable-VM identity requested before any sample bytes are sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmIsolationIdentity {
    pub sealed_image_id: SealedImageId,
    pub sealed_image_digest: SealedImageDigest,
    pub differencing_disk_id: DifferencingDiskId,
    pub channel_nonce: AuthenticatedChannelNonce,
    pub channel_protocol_version: u16,
    pub guest_agent_build: HelperBuildId,
}

impl VmIsolationIdentity {
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        if self.channel_protocol_version == 0 {
            return Err(PolicyValidationError::InvalidVmChannelVersion);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SandboxProviderSelection {
    LocalAppContainer,
    WindowsSandbox,
    HyperV,
    Registered {
        descriptor: SandboxProviderDescriptor,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationBoundary {
    UserMode,
    Hypervisor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxGuarantee {
    FileSystemRedirection,
    RegistryRedirection,
    DisposableFileSystem,
    DisposableRegistry,
    RollbackOnClose,
    NetworkDisabled,
    IsolatedNetworkSimulation,
    ResourceLimits,
    ChildProcessControl,
    ProcessMitigations,
    JobAssignmentAtCreation,
    HypervisorBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxNetworkMode {
    Disabled,
    IsolatedSimulation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessMitigationProfile {
    StrictV1,
    CompatibilityV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChildProcessProfile {
    Deny,
    SameSandboxOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DynamicCodeProfile {
    Prohibit,
    MicrosoftSignedOnly,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Win32kProfile {
    Disable,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxResourceLimits {
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub active_process_limit: u32,
    pub cpu_rate_basis_points: u16,
    pub wall_clock_millis: u64,
}

impl SandboxResourceLimits {
    pub fn validate(&self) -> Result<(), ResourceLimitError> {
        const MIB: u64 = 1024 * 1024;
        const GIB: u64 = 1024 * MIB;
        if !(32 * MIB..=128 * GIB).contains(&self.memory_bytes) {
            return Err(ResourceLimitError::Memory);
        }
        if !(16 * MIB..=512 * GIB).contains(&self.disk_bytes) {
            return Err(ResourceLimitError::Disk);
        }
        if !(1..=128).contains(&self.active_process_limit) {
            return Err(ResourceLimitError::ProcessCount);
        }
        if !(1..=10_000).contains(&self.cpu_rate_basis_points) {
            return Err(ResourceLimitError::CpuRate);
        }
        if !(1_000..=86_400_000).contains(&self.wall_clock_millis) {
            return Err(ResourceLimitError::WallClock);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ResourceLimitError {
    #[error("sandbox memory limit is outside the supported range")]
    Memory,
    #[error("sandbox disk limit is outside the supported range")]
    Disk,
    #[error("sandbox process limit is outside the supported range")]
    ProcessCount,
    #[error("sandbox CPU rate is outside the supported range")]
    CpuRate,
    #[error("sandbox wall-clock limit is outside the supported range")]
    WallClock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicy {
    pub session_id: SessionId,
    /// Audit identity for the exact policy digest. This is not a host-execution
    /// authorization; live host operations require a registered one-use lease.
    pub policy_approval: SandboxPolicyApprovalId,
    pub provider: SandboxProviderSelection,
    pub required_boundary: IsolationBoundary,
    pub required_guarantees: BTreeSet<SandboxGuarantee>,
    pub network: SandboxNetworkMode,
    pub resources: SandboxResourceLimits,
    pub process_mitigations: ProcessMitigationProfile,
    pub child_processes: ChildProcessProfile,
    pub dynamic_code: DynamicCodeProfile,
    pub win32k: Win32kProfile,
    pub rollback_on_close: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_identity: Option<VmIsolationIdentity>,
}

impl SandboxPolicy {
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        self.resources.validate()?;
        if !self.rollback_on_close {
            return Err(PolicyValidationError::RollbackRequired);
        }
        if self.policy_approval.session_id() != self.session_id {
            return Err(PolicyValidationError::ApprovalSessionMismatch);
        }
        if let SandboxProviderSelection::Registered { descriptor } = &self.provider {
            descriptor.validate()?;
        }
        if provider_boundary(&self.provider) != self.required_boundary {
            return Err(PolicyValidationError::ProviderBoundaryMismatch);
        }
        if matches!(self.provider, SandboxProviderSelection::LocalAppContainer)
            && self.network == SandboxNetworkMode::IsolatedSimulation
        {
            return Err(PolicyValidationError::LocalSimulationUnsupported);
        }
        if self.process_mitigations == ProcessMitigationProfile::StrictV1
            && (self.dynamic_code != DynamicCodeProfile::Prohibit
                || self.win32k != Win32kProfile::Disable)
        {
            return Err(PolicyValidationError::StrictProfileConflict);
        }

        for guarantee in [
            SandboxGuarantee::RollbackOnClose,
            SandboxGuarantee::ResourceLimits,
            SandboxGuarantee::ChildProcessControl,
            SandboxGuarantee::ProcessMitigations,
            SandboxGuarantee::JobAssignmentAtCreation,
        ] {
            require_guarantee(&self.required_guarantees, guarantee)?;
        }
        let network_guarantee = match self.network {
            SandboxNetworkMode::Disabled => SandboxGuarantee::NetworkDisabled,
            SandboxNetworkMode::IsolatedSimulation => SandboxGuarantee::IsolatedNetworkSimulation,
        };
        require_guarantee(&self.required_guarantees, network_guarantee)?;
        let conflicting_network = match self.network {
            SandboxNetworkMode::Disabled => SandboxGuarantee::IsolatedNetworkSimulation,
            SandboxNetworkMode::IsolatedSimulation => SandboxGuarantee::NetworkDisabled,
        };
        if self.required_guarantees.contains(&conflicting_network) {
            return Err(PolicyValidationError::ConflictingNetworkGuarantees);
        }

        match self.required_boundary {
            IsolationBoundary::UserMode => {
                require_guarantee(
                    &self.required_guarantees,
                    SandboxGuarantee::FileSystemRedirection,
                )?;
                require_guarantee(
                    &self.required_guarantees,
                    SandboxGuarantee::RegistryRedirection,
                )?;
                if self
                    .required_guarantees
                    .contains(&SandboxGuarantee::HypervisorBoundary)
                {
                    return Err(PolicyValidationError::ImpossibleBoundaryGuarantee);
                }
            }
            IsolationBoundary::Hypervisor => {
                for guarantee in [
                    SandboxGuarantee::DisposableFileSystem,
                    SandboxGuarantee::DisposableRegistry,
                    SandboxGuarantee::HypervisorBoundary,
                ] {
                    require_guarantee(&self.required_guarantees, guarantee)?;
                }
            }
        }
        match (self.required_boundary, &self.vm_identity) {
            (IsolationBoundary::UserMode, None) => {}
            (IsolationBoundary::UserMode, Some(_)) => {
                return Err(PolicyValidationError::UnexpectedVmIdentity);
            }
            (IsolationBoundary::Hypervisor, Some(identity)) => identity.validate()?,
            (IsolationBoundary::Hypervisor, None) => {
                return Err(PolicyValidationError::MissingVmIdentity);
            }
        }
        for guarantee in &self.required_guarantees {
            if !provider_supports(&self.provider, *guarantee) {
                return Err(PolicyValidationError::UnsupportedGuarantee(*guarantee));
            }
        }
        Ok(())
    }

    /// Computes the canonical v1 policy digest and binds it to the exact
    /// target artifact. Callers cannot inject a precomputed digest.
    pub fn digest(&self, binary_id: &BinaryId) -> Result<PolicyDigest, PolicyValidationError> {
        self.validate()?;
        let mut canonical = CanonicalPolicyDigest::new();
        canonical.text("resymbol-sandbox-policy");
        canonical.u16(SANDBOX_POLICY_DIGEST_VERSION);
        canonical.text(binary_id.as_str());
        canonical.u64(self.session_id.get());
        canonical.text(self.policy_approval.nonce.as_str());
        canonical.provider(&self.provider);
        canonical.boundary(self.required_boundary);
        canonical.guarantees(&self.required_guarantees);
        canonical.network(self.network);
        canonical.u64(self.resources.memory_bytes);
        canonical.u64(self.resources.disk_bytes);
        canonical.u32(self.resources.active_process_limit);
        canonical.u16(self.resources.cpu_rate_basis_points);
        canonical.u64(self.resources.wall_clock_millis);
        canonical.mitigations(self.process_mitigations);
        canonical.children(self.child_processes);
        canonical.dynamic_code(self.dynamic_code);
        canonical.win32k(self.win32k);
        canonical.boolean(self.rollback_on_close);
        match &self.vm_identity {
            Some(identity) => {
                canonical.boolean(true);
                canonical.text(identity.sealed_image_id.as_str());
                canonical.text(identity.sealed_image_digest.as_str());
                canonical.text(identity.differencing_disk_id.as_str());
                canonical.text(identity.channel_nonce.as_str());
                canonical.u16(identity.channel_protocol_version);
                canonical.text(identity.guest_agent_build.as_str());
            }
            None => canonical.boolean(false),
        }
        Ok(canonical.finish())
    }
}

fn require_guarantee(
    guarantees: &BTreeSet<SandboxGuarantee>,
    required: SandboxGuarantee,
) -> Result<(), PolicyValidationError> {
    if guarantees.contains(&required) {
        Ok(())
    } else {
        Err(PolicyValidationError::MissingGuarantee(required))
    }
}

pub(crate) fn provider_boundary(provider: &SandboxProviderSelection) -> IsolationBoundary {
    match provider {
        SandboxProviderSelection::LocalAppContainer => IsolationBoundary::UserMode,
        SandboxProviderSelection::WindowsSandbox | SandboxProviderSelection::HyperV => {
            IsolationBoundary::Hypervisor
        }
        SandboxProviderSelection::Registered { descriptor } => descriptor.boundary,
    }
}

pub(crate) fn provider_supports(
    provider: &SandboxProviderSelection,
    guarantee: SandboxGuarantee,
) -> bool {
    match provider {
        SandboxProviderSelection::LocalAppContainer => matches!(
            guarantee,
            SandboxGuarantee::FileSystemRedirection
                | SandboxGuarantee::RegistryRedirection
                | SandboxGuarantee::RollbackOnClose
                | SandboxGuarantee::NetworkDisabled
                | SandboxGuarantee::ResourceLimits
                | SandboxGuarantee::ChildProcessControl
                | SandboxGuarantee::ProcessMitigations
                | SandboxGuarantee::JobAssignmentAtCreation
        ),
        SandboxProviderSelection::WindowsSandbox | SandboxProviderSelection::HyperV => !matches!(
            guarantee,
            SandboxGuarantee::FileSystemRedirection | SandboxGuarantee::RegistryRedirection
        ),
        SandboxProviderSelection::Registered { descriptor } => {
            descriptor.guarantees.contains(&guarantee)
        }
    }
}

fn is_reserved_provider_id(id: &str) -> bool {
    matches!(
        id.to_ascii_lowercase().as_str(),
        "local-appcontainer" | "windows-sandbox" | "hyper-v"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyValidationError {
    #[error(transparent)]
    Resource(#[from] ResourceLimitError),
    #[error("rollback on close is mandatory")]
    RollbackRequired,
    #[error("sandbox policy approval belongs to another session")]
    ApprovalSessionMismatch,
    #[error("selected provider cannot satisfy the required isolation boundary")]
    ProviderBoundaryMismatch,
    #[error("local AppContainer v1 does not provide isolated network simulation")]
    LocalSimulationUnsupported,
    #[error("strict mitigation profile requires prohibited dynamic code and disabled win32k")]
    StrictProfileConflict,
    #[error("required guarantee is missing: {0:?}")]
    MissingGuarantee(SandboxGuarantee),
    #[error("network guarantees conflict")]
    ConflictingNetworkGuarantees,
    #[error("user-mode policy requires an impossible hypervisor guarantee")]
    ImpossibleBoundaryGuarantee,
    #[error("registered provider id aliases a built-in provider")]
    ReservedProviderId,
    #[error("registered provider descriptor must declare at least one guarantee")]
    EmptyProviderGuarantees,
    #[error("hypervisor sandbox policy is missing its sealed VM identity")]
    MissingVmIdentity,
    #[error("user-mode sandbox policy unexpectedly carries a VM identity")]
    UnexpectedVmIdentity,
    #[error("authenticated VM channel protocol version must be nonzero")]
    InvalidVmChannelVersion,
    #[error("selected provider cannot supply guarantee: {0:?}")]
    UnsupportedGuarantee(SandboxGuarantee),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSandboxAttestation {
    pub binary_id: BinaryId,
    pub session_id: SessionId,
    pub provisioning_epoch: ProvisioningEpoch,
    pub policy_digest: PolicyDigest,
    pub provider: SandboxProviderSelection,
    pub boundary: IsolationBoundary,
    pub guarantees: BTreeSet<SandboxGuarantee>,
    pub job_assigned_at_creation: bool,
    pub helper_build: HelperBuildId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_identity: Option<VmIsolationIdentity>,
}

impl ExpectedSandboxAttestation {
    pub fn from_policy(
        binary_id: BinaryId,
        policy: &SandboxPolicy,
        helper_build: HelperBuildId,
        provisioning_epoch: ProvisioningEpoch,
    ) -> Result<Self, PolicyValidationError> {
        let policy_digest = policy.digest(&binary_id)?;
        Ok(Self {
            binary_id,
            session_id: policy.session_id,
            provisioning_epoch,
            policy_digest,
            provider: policy.provider.clone(),
            boundary: policy.required_boundary,
            guarantees: policy.required_guarantees.clone(),
            job_assigned_at_creation: true,
            helper_build,
            vm_identity: policy.vm_identity.clone(),
        })
    }

    pub fn validate_exact(&self, actual: &SandboxAttestation) -> Result<(), AttestationMismatch> {
        if self.binary_id != actual.binary_id {
            return Err(AttestationMismatch::BinaryIdentity);
        }
        if self.session_id != actual.session_id {
            return Err(AttestationMismatch::Session);
        }
        if self.provisioning_epoch != actual.provisioning_epoch {
            return Err(AttestationMismatch::ProvisioningEpoch);
        }
        if self.policy_digest != actual.policy_digest {
            return Err(AttestationMismatch::PolicyDigest);
        }
        if self.provider != actual.provider {
            return Err(AttestationMismatch::Provider);
        }
        if self.boundary != actual.boundary {
            return Err(AttestationMismatch::Boundary);
        }
        if self.guarantees != actual.guarantees {
            return Err(AttestationMismatch::Guarantees);
        }
        if self.job_assigned_at_creation != actual.job_assigned_at_creation {
            return Err(AttestationMismatch::JobAssignment);
        }
        if self.helper_build != actual.helper_build {
            return Err(AttestationMismatch::HelperBuild);
        }
        if self.vm_identity != actual.vm_identity {
            return Err(AttestationMismatch::VmIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxAttestation {
    pub binary_id: BinaryId,
    pub session_id: SessionId,
    pub provisioning_epoch: ProvisioningEpoch,
    pub policy_digest: PolicyDigest,
    pub provider: SandboxProviderSelection,
    pub boundary: IsolationBoundary,
    pub guarantees: BTreeSet<SandboxGuarantee>,
    pub job_assigned_at_creation: bool,
    pub helper_build: HelperBuildId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_identity: Option<VmIsolationIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AttestationMismatch {
    #[error("binary identity attestation mismatch")]
    BinaryIdentity,
    #[error("sandbox session attestation mismatch")]
    Session,
    #[error("sandbox provisioning epoch attestation mismatch")]
    ProvisioningEpoch,
    #[error("policy digest attestation mismatch")]
    PolicyDigest,
    #[error("provider attestation mismatch")]
    Provider,
    #[error("isolation boundary attestation mismatch")]
    Boundary,
    #[error("guarantee-set attestation mismatch")]
    Guarantees,
    #[error("job-at-creation attestation mismatch")]
    JobAssignment,
    #[error("helper build attestation mismatch")]
    HelperBuild,
    #[error("sealed VM or authenticated channel identity mismatch")]
    VmIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticText(String);

impl DiagnosticText {
    pub fn new(value: impl Into<String>) -> Result<Self, BoundedValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(BoundedValueError::Empty {
                field: "diagnostic",
            });
        }
        if value.len() > MAX_DIAGNOSTIC_BYTES {
            return Err(BoundedValueError::TooLong {
                field: "diagnostic",
                maximum: MAX_DIAGNOSTIC_BYTES,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(BoundedValueError::InvalidCharacter {
                field: "diagnostic",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for DiagnosticText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DiagnosticText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxFailureStage {
    Policy,
    Discovery,
    Provisioning,
    Attestation,
    Launch,
    Runtime,
    Cleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxFailureKind {
    InvalidPolicy,
    ProviderUnavailable,
    AttestationRejected,
    LaunchDenied,
    ResourceLimitReached,
    HelperFailure,
    CleanupIncomplete,
    ProtocolViolation,
}

/// Exact controller-held operation context for one sandbox failure.
///
/// This is evidence, never authority. A launch binds the binary and helper
/// build that produced the sandbox expectation, even if discovery failed
/// before resources existed. An inherited attach binds the stable process
/// identity and attach mode from the provider-issued ownership lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SandboxFailureContext {
    Launch {
        binary_id: BinaryId,
        helper_build: HelperBuildId,
    },
    InheritedAttach {
        process: ProcessIdentity,
        mode: AttachMode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxFailure {
    pub session_id: SessionId,
    pub provisioning_epoch: ProvisioningEpoch,
    pub policy_digest: PolicyDigest,
    pub provider: SandboxProviderSelection,
    pub context: SandboxFailureContext,
    pub stage: SandboxFailureStage,
    pub kind: SandboxFailureKind,
    pub retryable: bool,
    pub detail: DiagnosticText,
}

impl SandboxFailure {
    /// Rejects semantically incoherent stage/kind pairs before command phase
    /// or ownership context is considered.
    pub fn validate_stage_kind(&self) -> Result<(), SandboxFailureValidationError> {
        let compatible = match self.stage {
            SandboxFailureStage::Policy => matches!(
                self.kind,
                SandboxFailureKind::InvalidPolicy | SandboxFailureKind::ProtocolViolation
            ),
            SandboxFailureStage::Discovery => matches!(
                self.kind,
                SandboxFailureKind::ProviderUnavailable
                    | SandboxFailureKind::HelperFailure
                    | SandboxFailureKind::ProtocolViolation
            ),
            SandboxFailureStage::Provisioning => matches!(
                self.kind,
                SandboxFailureKind::ProviderUnavailable
                    | SandboxFailureKind::ResourceLimitReached
                    | SandboxFailureKind::HelperFailure
                    | SandboxFailureKind::ProtocolViolation
            ),
            SandboxFailureStage::Attestation => matches!(
                self.kind,
                SandboxFailureKind::AttestationRejected
                    | SandboxFailureKind::HelperFailure
                    | SandboxFailureKind::ProtocolViolation
            ),
            SandboxFailureStage::Launch => matches!(
                self.kind,
                SandboxFailureKind::LaunchDenied
                    | SandboxFailureKind::ResourceLimitReached
                    | SandboxFailureKind::HelperFailure
                    | SandboxFailureKind::ProtocolViolation
            ),
            SandboxFailureStage::Runtime => matches!(
                self.kind,
                SandboxFailureKind::ResourceLimitReached
                    | SandboxFailureKind::HelperFailure
                    | SandboxFailureKind::ProtocolViolation
            ),
            SandboxFailureStage::Cleanup => {
                matches!(self.kind, SandboxFailureKind::CleanupIncomplete)
            }
        };
        if compatible {
            Ok(())
        } else {
            Err(SandboxFailureValidationError::StageKind {
                stage: self.stage,
                kind: self.kind,
            })
        }
    }

    pub(crate) fn validate_against_expected(
        &self,
        expected: &ExpectedSandboxAttestation,
    ) -> Result<(), SandboxFailureValidationError> {
        self.validate_stage_kind()?;
        if self.session_id != expected.session_id {
            return Err(SandboxFailureValidationError::Session);
        }
        if self.provisioning_epoch != expected.provisioning_epoch {
            return Err(SandboxFailureValidationError::ProvisioningEpoch);
        }
        if self.policy_digest != expected.policy_digest {
            return Err(SandboxFailureValidationError::PolicyDigest);
        }
        if self.provider != expected.provider {
            return Err(SandboxFailureValidationError::Provider);
        }
        match &self.context {
            SandboxFailureContext::Launch {
                binary_id,
                helper_build,
            } if binary_id == &expected.binary_id && helper_build == &expected.helper_build => {
                Ok(())
            }
            SandboxFailureContext::Launch { binary_id, .. } if binary_id != &expected.binary_id => {
                Err(SandboxFailureValidationError::BinaryIdentity)
            }
            SandboxFailureContext::Launch { .. } => Err(SandboxFailureValidationError::HelperBuild),
            SandboxFailureContext::InheritedAttach { .. } => {
                Err(SandboxFailureValidationError::ContextKind)
            }
        }
    }

    pub(crate) fn validate_against_inherited(
        &self,
        session_id: SessionId,
        provisioning_epoch: &ProvisioningEpoch,
        policy_digest: &PolicyDigest,
        provider: &SandboxProviderSelection,
        process: &ProcessIdentity,
        mode: AttachMode,
    ) -> Result<(), SandboxFailureValidationError> {
        self.validate_stage_kind()?;
        if self.session_id != session_id {
            return Err(SandboxFailureValidationError::Session);
        }
        if &self.provisioning_epoch != provisioning_epoch {
            return Err(SandboxFailureValidationError::ProvisioningEpoch);
        }
        if &self.policy_digest != policy_digest {
            return Err(SandboxFailureValidationError::PolicyDigest);
        }
        if &self.provider != provider {
            return Err(SandboxFailureValidationError::Provider);
        }
        match &self.context {
            SandboxFailureContext::InheritedAttach {
                process: actual,
                mode: actual_mode,
            } if actual == process && *actual_mode == mode => Ok(()),
            SandboxFailureContext::InheritedAttach {
                process: actual, ..
            } if actual != process => Err(SandboxFailureValidationError::ProcessIdentity),
            SandboxFailureContext::InheritedAttach { .. } => {
                Err(SandboxFailureValidationError::AttachMode)
            }
            SandboxFailureContext::Launch { .. } => Err(SandboxFailureValidationError::ContextKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SandboxFailureValidationError {
    #[error("sandbox failure stage {stage:?} is incompatible with kind {kind:?}")]
    StageKind {
        stage: SandboxFailureStage,
        kind: SandboxFailureKind,
    },
    #[error("sandbox failure belongs to another session")]
    Session,
    #[error("sandbox failure belongs to another provisioning epoch")]
    ProvisioningEpoch,
    #[error("sandbox failure policy digest mismatch")]
    PolicyDigest,
    #[error("sandbox failure provider mismatch")]
    Provider,
    #[error("sandbox failure operation-context kind mismatch")]
    ContextKind,
    #[error("sandbox failure binary identity mismatch")]
    BinaryIdentity,
    #[error("sandbox failure helper build mismatch")]
    HelperBuild,
    #[error("sandbox failure inherited process identity mismatch")]
    ProcessIdentity,
    #[error("sandbox failure inherited attach mode mismatch")]
    AttachMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderUnavailableReason {
    NotInstalled,
    FeatureDisabled,
    AdministrativePolicy,
    UnsupportedPolicy,
    ResourceUnavailable,
    VersionMismatch,
    BackendOffline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderUnavailable {
    pub session_id: SessionId,
    pub provider: SandboxProviderSelection,
    pub reason: ProviderUnavailableReason,
    pub retryable: bool,
    pub detail: DiagnosticText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupOutcome {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupResidualKind {
    Process,
    FileSystem,
    Registry,
    Network,
    Handles,
    AppContainerProfile,
    DifferencingDisk,
    ControlChannel,
    Provider,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupResidual {
    pub kind: CleanupResidualKind,
    pub detail: DiagnosticText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCleanupReceipt {
    pub receipt_id: CleanupReceiptId,
    pub session_id: SessionId,
    pub provisioning_epoch: ProvisioningEpoch,
    pub provider: SandboxProviderSelection,
    pub policy_digest: PolicyDigest,
    /// Exact target identity for cleanup inherited from an existing sandbox.
    /// Provider-created launch cleanup has no separately trusted process
    /// binding and therefore leaves this field absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessIdentity>,
    pub outcome: CleanupOutcome,
    pub process_tree_terminated_and_reaped: bool,
    pub handles_closed: bool,
    pub file_system_rolled_back: bool,
    pub registry_rolled_back: bool,
    pub network_torn_down: bool,
    pub owned_paths_deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appcontainer_profile_deleted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub differencing_disk_discarded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_channel_closed: Option<bool>,
    pub terminated_processes: u32,
    pub residuals: Vec<CleanupResidual>,
}

/// Audited evidence from a cleanup attempt that failed without releasing
/// sandbox ownership.
///
/// This is deliberately distinct from [`SandboxLifecycleEvent::Closed`]: an
/// incomplete attempt records recoverable residuals but never proves cleanup
/// completion or permits session release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCleanupAttemptFailure {
    pub failure: SandboxFailure,
    pub receipt: SandboxCleanupReceipt,
}

impl SandboxCleanupAttemptFailure {
    /// Validates the self-contained shape of failure evidence. Exact sandbox
    /// ownership binding is validated separately against controller-held state.
    pub fn validate(&self) -> Result<(), CleanupAttemptFailureError> {
        if self.failure.stage != SandboxFailureStage::Cleanup {
            return Err(CleanupAttemptFailureError::WrongStage);
        }
        if self.failure.kind != SandboxFailureKind::CleanupIncomplete {
            return Err(CleanupAttemptFailureError::WrongKind);
        }
        if self.failure.session_id != self.receipt.session_id
            || self.failure.provisioning_epoch != self.receipt.provisioning_epoch
            || self.failure.policy_digest != self.receipt.policy_digest
            || self.failure.provider != self.receipt.provider
        {
            return Err(CleanupAttemptFailureError::FailureReceiptMismatch);
        }
        let context_matches = match (&self.failure.context, &self.receipt.process) {
            (SandboxFailureContext::Launch { .. }, None) => true,
            (SandboxFailureContext::InheritedAttach { process, .. }, Some(receipt_process)) => {
                process == receipt_process
            }
            _ => false,
        };
        if !context_matches {
            return Err(CleanupAttemptFailureError::FailureReceiptMismatch);
        }
        if self.receipt.outcome != CleanupOutcome::Incomplete {
            return Err(CleanupAttemptFailureError::ReceiptNotIncomplete);
        }
        self.receipt
            .validate_for_boundary(provider_boundary(&self.receipt.provider))?;
        Ok(())
    }
}

impl SandboxCleanupReceipt {
    pub fn validate_against(
        &self,
        expected: &ExpectedSandboxAttestation,
    ) -> Result<(), CleanupReceiptError> {
        if self.session_id != expected.session_id
            || self.provisioning_epoch != expected.provisioning_epoch
            || self.provider != expected.provider
            || self.policy_digest != expected.policy_digest
            || self.process.is_some()
        {
            return Err(CleanupReceiptError::BindingMismatch);
        }
        self.validate_for_boundary(expected.boundary)
    }

    /// Validates the provider-independent completion claims for a known
    /// isolation boundary. Callers must validate the receipt's ownership
    /// binding before invoking this helper.
    pub(crate) fn validate_for_boundary(
        &self,
        boundary: IsolationBoundary,
    ) -> Result<(), CleanupReceiptError> {
        if self.residuals.len() > MAX_CLEANUP_RESIDUALS {
            return Err(CleanupReceiptError::TooManyResiduals);
        }
        let common_clean = self.process_tree_terminated_and_reaped
            && self.handles_closed
            && self.file_system_rolled_back
            && self.registry_rolled_back
            && self.network_torn_down
            && self.owned_paths_deleted;
        let provider_clean = match boundary {
            IsolationBoundary::UserMode => {
                self.appcontainer_profile_deleted == Some(true)
                    && self.differencing_disk_discarded.is_none()
                    && self.control_channel_closed.is_none()
            }
            IsolationBoundary::Hypervisor => {
                self.appcontainer_profile_deleted.is_none()
                    && self.differencing_disk_discarded == Some(true)
                    && self.control_channel_closed == Some(true)
            }
        };
        let all_clean = common_clean && provider_clean;
        match self.outcome {
            CleanupOutcome::Complete if !all_clean || !self.residuals.is_empty() => {
                Err(CleanupReceiptError::FalseComplete)
            }
            CleanupOutcome::Incomplete if self.residuals.is_empty() => {
                Err(CleanupReceiptError::MissingResidual)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CleanupReceiptError {
    #[error("cleanup receipt does not match the sandbox session")]
    BindingMismatch,
    #[error("cleanup receipt exceeds the residual limit")]
    TooManyResiduals,
    #[error("cleanup receipt claims completion without complete rollback")]
    FalseComplete,
    #[error("incomplete cleanup receipt must identify a residual")]
    MissingResidual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CleanupAttemptFailureError {
    #[error("cleanup-attempt failure must report the cleanup stage")]
    WrongStage,
    #[error("cleanup-attempt failure must report incomplete cleanup")]
    WrongKind,
    #[error("cleanup-attempt failure and receipt bindings differ")]
    FailureReceiptMismatch,
    #[error("cleanup-attempt failure must carry an incomplete receipt")]
    ReceiptNotIncomplete,
    #[error(transparent)]
    Receipt(#[from] CleanupReceiptError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxLifecycleState {
    Requested,
    Provisioning,
    TargetCreatedSuspended,
    AttestationAccepted,
    Running,
    Cleanup,
    Closed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SandboxLifecycleEvent {
    State {
        session_id: SessionId,
        state: SandboxLifecycleState,
    },
    Attested(SandboxAttestation),
    ProviderUnavailable(ProviderUnavailable),
    Failed(SandboxFailure),
    CleanupAttemptFailed(SandboxCleanupAttemptFailure),
    Closed(SandboxCleanupReceipt),
}

/// Single-owner, value-only sandbox lifecycle reducer.
///
/// This type owns no handles and performs no I/O. It may be moved between
/// threads, but callers must serialize mutation. An active lifecycle is
/// intentionally non-hot-reloadable; close it with an exact cleanup receipt
/// before replacing provider code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxMachine {
    expected: ExpectedSandboxAttestation,
    state: SandboxLifecycleState,
    attestation_accepted: bool,
}

impl SandboxMachine {
    pub fn new(expected: ExpectedSandboxAttestation) -> Result<Self, SandboxMachineError> {
        let vm_shape_valid = match expected.boundary {
            IsolationBoundary::UserMode => expected.vm_identity.is_none(),
            IsolationBoundary::Hypervisor => expected
                .vm_identity
                .as_ref()
                .is_some_and(|identity| identity.validate().is_ok()),
        };
        let provider_valid = match &expected.provider {
            SandboxProviderSelection::Registered { descriptor } => descriptor.validate().is_ok(),
            _ => true,
        } && expected
            .guarantees
            .iter()
            .all(|guarantee| provider_supports(&expected.provider, *guarantee));
        if !expected.job_assigned_at_creation
            || !expected
                .guarantees
                .contains(&SandboxGuarantee::JobAssignmentAtCreation)
            || provider_boundary(&expected.provider) != expected.boundary
            || !provider_valid
            || !vm_shape_valid
        {
            return Err(SandboxMachineError::InvalidExpectedAttestation);
        }
        Ok(Self {
            expected,
            state: SandboxLifecycleState::Requested,
            attestation_accepted: false,
        })
    }

    #[must_use]
    pub const fn state(&self) -> SandboxLifecycleState {
        self.state
    }

    #[must_use]
    pub const fn attestation_accepted(&self) -> bool {
        self.attestation_accepted
    }

    #[must_use]
    pub const fn expected_attestation(&self) -> &ExpectedSandboxAttestation {
        &self.expected
    }

    pub fn begin_provisioning(&mut self) -> Result<SandboxLifecycleState, SandboxMachineError> {
        self.transition(
            "begin provisioning",
            &[SandboxLifecycleState::Requested],
            SandboxLifecycleState::Provisioning,
        )
    }

    pub fn target_created_suspended(
        &mut self,
    ) -> Result<SandboxLifecycleState, SandboxMachineError> {
        self.transition(
            "record suspended target",
            &[SandboxLifecycleState::Provisioning],
            SandboxLifecycleState::TargetCreatedSuspended,
        )
    }

    pub fn accept_attestation(
        &mut self,
        actual: &SandboxAttestation,
    ) -> Result<SandboxLifecycleState, SandboxMachineError> {
        self.require_state(
            "accept attestation",
            &[SandboxLifecycleState::TargetCreatedSuspended],
        )?;
        self.expected.validate_exact(actual)?;
        self.attestation_accepted = true;
        self.state = SandboxLifecycleState::AttestationAccepted;
        Ok(self.state)
    }

    pub fn mark_running(&mut self) -> Result<SandboxLifecycleState, SandboxMachineError> {
        if !self.attestation_accepted {
            return Err(SandboxMachineError::AttestationNotAccepted);
        }
        self.transition(
            "mark target running",
            &[
                SandboxLifecycleState::AttestationAccepted,
                SandboxLifecycleState::Running,
            ],
            SandboxLifecycleState::Running,
        )
    }

    pub fn mark_failed(&mut self) -> Result<SandboxLifecycleState, SandboxMachineError> {
        if self.state == SandboxLifecycleState::Closed {
            return Err(SandboxMachineError::InvalidTransition {
                from: self.state,
                action: "mark failed",
            });
        }
        self.state = SandboxLifecycleState::Failed;
        Ok(self.state)
    }

    pub fn begin_cleanup(&mut self) -> Result<SandboxLifecycleState, SandboxMachineError> {
        if self.state == SandboxLifecycleState::Cleanup {
            return Ok(self.state);
        }
        if self.state == SandboxLifecycleState::Closed {
            return Err(SandboxMachineError::InvalidTransition {
                from: self.state,
                action: "begin cleanup",
            });
        }
        self.state = SandboxLifecycleState::Cleanup;
        Ok(self.state)
    }

    pub fn close(
        &mut self,
        receipt: &SandboxCleanupReceipt,
    ) -> Result<SandboxLifecycleState, SandboxMachineError> {
        self.require_state("close", &[SandboxLifecycleState::Cleanup])?;
        receipt.validate_against(&self.expected)?;
        if receipt.outcome != CleanupOutcome::Complete {
            return Err(SandboxMachineError::CleanupIncomplete);
        }
        self.state = SandboxLifecycleState::Closed;
        Ok(self.state)
    }

    fn transition(
        &mut self,
        action: &'static str,
        allowed: &[SandboxLifecycleState],
        next: SandboxLifecycleState,
    ) -> Result<SandboxLifecycleState, SandboxMachineError> {
        self.require_state(action, allowed)?;
        self.state = next;
        Ok(self.state)
    }

    fn require_state(
        &self,
        action: &'static str,
        allowed: &[SandboxLifecycleState],
    ) -> Result<(), SandboxMachineError> {
        if allowed.contains(&self.state) {
            Ok(())
        } else {
            Err(SandboxMachineError::InvalidTransition {
                from: self.state,
                action,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SandboxMachineError {
    #[error("sandbox expected attestation is internally inconsistent")]
    InvalidExpectedAttestation,
    #[error("sandbox attestation has not been accepted")]
    AttestationNotAccepted,
    #[error("cannot {action} from sandbox lifecycle state {from:?}")]
    InvalidTransition {
        from: SandboxLifecycleState,
        action: &'static str,
    },
    #[error(transparent)]
    Attestation(#[from] AttestationMismatch),
    #[error(transparent)]
    Cleanup(#[from] CleanupReceiptError),
    #[error("sandbox cleanup remains incomplete")]
    CleanupIncomplete,
}

#[cfg(test)]
mod tests {
    use super::*;
    use resymbol_analysis::{BinaryAnalysis, analyze_bytes};

    const FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");

    fn binary_id() -> BinaryId {
        let BinaryAnalysis::Pe(pe) = analyze_bytes(FIXTURE).expect("fixture analysis") else {
            panic!("fixture must remain PE")
        };
        pe.identity.id
    }

    fn provisioning_epoch() -> ProvisioningEpoch {
        ProvisioningEpoch::new("e".repeat(64)).expect("provisioning epoch")
    }

    fn local_guarantees() -> BTreeSet<SandboxGuarantee> {
        [
            SandboxGuarantee::FileSystemRedirection,
            SandboxGuarantee::RegistryRedirection,
            SandboxGuarantee::RollbackOnClose,
            SandboxGuarantee::NetworkDisabled,
            SandboxGuarantee::ResourceLimits,
            SandboxGuarantee::ChildProcessControl,
            SandboxGuarantee::ProcessMitigations,
            SandboxGuarantee::JobAssignmentAtCreation,
        ]
        .into_iter()
        .collect()
    }

    fn local_policy() -> SandboxPolicy {
        let session_id = SessionId::new(1).expect("session id");
        SandboxPolicy {
            policy_approval: SandboxPolicyApprovalId::new(session_id, "ack-1")
                .expect("acknowledgement"),
            session_id,
            provider: SandboxProviderSelection::LocalAppContainer,
            required_boundary: IsolationBoundary::UserMode,
            required_guarantees: local_guarantees(),
            network: SandboxNetworkMode::Disabled,
            resources: SandboxResourceLimits {
                memory_bytes: 512 * 1024 * 1024,
                disk_bytes: 2 * 1024 * 1024 * 1024,
                active_process_limit: 8,
                cpu_rate_basis_points: 5_000,
                wall_clock_millis: 300_000,
            },
            process_mitigations: ProcessMitigationProfile::StrictV1,
            child_processes: ChildProcessProfile::Deny,
            dynamic_code: DynamicCodeProfile::Prohibit,
            win32k: Win32kProfile::Disable,
            rollback_on_close: true,
            vm_identity: None,
        }
    }

    #[test]
    fn bounded_ids_and_digests_reject_ambiguous_values() {
        assert!(ProviderId::new("").is_err());
        assert!(ProviderId::new("provider with spaces").is_err());
        assert!(ProviderId::new("p".repeat(MAX_PROVIDER_ID_BYTES + 1)).is_err());
        assert!(PolicyDigest::new("A".repeat(64)).is_err());
        assert!(PolicyDigest::new("a".repeat(63)).is_err());
        assert!(PolicyDigest::new("a".repeat(64)).is_ok());
    }

    #[test]
    fn local_v1_policy_is_exact_and_fail_closed() {
        let policy = local_policy();
        policy.validate().expect("valid local policy");

        let mut simulation = policy.clone();
        simulation.network = SandboxNetworkMode::IsolatedSimulation;
        simulation
            .required_guarantees
            .remove(&SandboxGuarantee::NetworkDisabled);
        simulation
            .required_guarantees
            .insert(SandboxGuarantee::IsolatedNetworkSimulation);
        assert_eq!(
            simulation.validate(),
            Err(PolicyValidationError::LocalSimulationUnsupported)
        );
    }

    #[test]
    fn policy_rejects_missing_or_impossible_guarantees_and_wrong_ack() {
        let mut policy = local_policy();
        policy
            .required_guarantees
            .remove(&SandboxGuarantee::RollbackOnClose);
        assert_eq!(
            policy.validate(),
            Err(PolicyValidationError::MissingGuarantee(
                SandboxGuarantee::RollbackOnClose
            ))
        );

        let mut policy = local_policy();
        policy
            .required_guarantees
            .insert(SandboxGuarantee::HypervisorBoundary);
        assert_eq!(
            policy.validate(),
            Err(PolicyValidationError::ImpossibleBoundaryGuarantee)
        );

        let mut policy = local_policy();
        policy.policy_approval =
            SandboxPolicyApprovalId::new(SessionId::new(2).expect("other session"), "ack-2")
                .expect("acknowledgement");
        assert_eq!(
            policy.validate(),
            Err(PolicyValidationError::ApprovalSessionMismatch)
        );
    }

    #[test]
    fn resource_and_mitigation_profiles_are_bounded() {
        let mut policy = local_policy();
        policy.resources.active_process_limit = 0;
        assert_eq!(
            policy.validate(),
            Err(PolicyValidationError::Resource(
                ResourceLimitError::ProcessCount
            ))
        );

        let mut policy = local_policy();
        policy.dynamic_code = DynamicCodeProfile::Allow;
        assert_eq!(
            policy.validate(),
            Err(PolicyValidationError::StrictProfileConflict)
        );
    }

    fn expected_attestation() -> ExpectedSandboxAttestation {
        ExpectedSandboxAttestation::from_policy(
            binary_id(),
            &local_policy(),
            HelperBuildId::new("helper-1.0.0+abc").expect("helper build"),
            provisioning_epoch(),
        )
        .expect("expected attestation")
    }

    fn actual_from(expected: &ExpectedSandboxAttestation) -> SandboxAttestation {
        SandboxAttestation {
            binary_id: expected.binary_id.clone(),
            session_id: expected.session_id,
            provisioning_epoch: expected.provisioning_epoch.clone(),
            policy_digest: expected.policy_digest.clone(),
            provider: expected.provider.clone(),
            boundary: expected.boundary,
            guarantees: expected.guarantees.clone(),
            job_assigned_at_creation: expected.job_assigned_at_creation,
            helper_build: expected.helper_build.clone(),
            vm_identity: expected.vm_identity.clone(),
        }
    }

    fn complete_receipt(expected: &ExpectedSandboxAttestation) -> SandboxCleanupReceipt {
        SandboxCleanupReceipt {
            receipt_id: CleanupReceiptId::new("receipt-1").expect("receipt id"),
            session_id: expected.session_id,
            provisioning_epoch: expected.provisioning_epoch.clone(),
            provider: expected.provider.clone(),
            policy_digest: expected.policy_digest.clone(),
            process: None,
            outcome: CleanupOutcome::Complete,
            process_tree_terminated_and_reaped: true,
            handles_closed: true,
            file_system_rolled_back: true,
            registry_rolled_back: true,
            network_torn_down: true,
            owned_paths_deleted: true,
            appcontainer_profile_deleted: Some(true),
            differencing_disk_discarded: None,
            control_channel_closed: None,
            terminated_processes: 2,
            residuals: Vec::new(),
        }
    }

    fn incomplete_receipt(expected: &ExpectedSandboxAttestation) -> SandboxCleanupReceipt {
        let mut receipt = complete_receipt(expected);
        receipt.outcome = CleanupOutcome::Incomplete;
        receipt.network_torn_down = false;
        receipt.residuals.push(CleanupResidual {
            kind: CleanupResidualKind::Network,
            detail: DiagnosticText::new("isolated switch cleanup pending").expect("detail"),
        });
        receipt
    }

    fn failure_for_expected(
        expected: &ExpectedSandboxAttestation,
        stage: SandboxFailureStage,
        kind: SandboxFailureKind,
    ) -> SandboxFailure {
        SandboxFailure {
            session_id: expected.session_id,
            provisioning_epoch: expected.provisioning_epoch.clone(),
            policy_digest: expected.policy_digest.clone(),
            provider: expected.provider.clone(),
            context: SandboxFailureContext::Launch {
                binary_id: expected.binary_id.clone(),
                helper_build: expected.helper_build.clone(),
            },
            stage,
            kind,
            retryable: false,
            detail: DiagnosticText::new("sandbox operation failed").expect("detail"),
        }
    }

    fn vm_policy() -> SandboxPolicy {
        let session_id = SessionId::new(7).expect("session id");
        SandboxPolicy {
            session_id,
            policy_approval: SandboxPolicyApprovalId::new(session_id, "vm-ack")
                .expect("acknowledgement"),
            provider: SandboxProviderSelection::HyperV,
            required_boundary: IsolationBoundary::Hypervisor,
            required_guarantees: [
                SandboxGuarantee::DisposableFileSystem,
                SandboxGuarantee::DisposableRegistry,
                SandboxGuarantee::RollbackOnClose,
                SandboxGuarantee::NetworkDisabled,
                SandboxGuarantee::ResourceLimits,
                SandboxGuarantee::ChildProcessControl,
                SandboxGuarantee::ProcessMitigations,
                SandboxGuarantee::JobAssignmentAtCreation,
                SandboxGuarantee::HypervisorBoundary,
            ]
            .into_iter()
            .collect(),
            network: SandboxNetworkMode::Disabled,
            resources: SandboxResourceLimits {
                memory_bytes: 1024 * 1024 * 1024,
                disk_bytes: 4 * 1024 * 1024 * 1024,
                active_process_limit: 8,
                cpu_rate_basis_points: 5_000,
                wall_clock_millis: 300_000,
            },
            process_mitigations: ProcessMitigationProfile::StrictV1,
            child_processes: ChildProcessProfile::Deny,
            dynamic_code: DynamicCodeProfile::Prohibit,
            win32k: Win32kProfile::Disable,
            rollback_on_close: true,
            vm_identity: Some(VmIsolationIdentity {
                sealed_image_id: SealedImageId::new("base-image-v1").expect("image id"),
                sealed_image_digest: SealedImageDigest::new("b".repeat(64)).expect("image digest"),
                differencing_disk_id: DifferencingDiskId::new("session-disk-7").expect("disk id"),
                channel_nonce: AuthenticatedChannelNonce::new("c".repeat(64))
                    .expect("channel nonce"),
                channel_protocol_version: 1,
                guest_agent_build: HelperBuildId::new("guest-1.0.0+abc").expect("guest build"),
            }),
        }
    }

    #[test]
    fn attestation_requires_an_exact_contract_match() {
        let expected = expected_attestation();
        let actual = actual_from(&expected);
        expected.validate_exact(&actual).expect("exact match");

        let mut changed = actual.clone();
        changed.job_assigned_at_creation = false;
        assert_eq!(
            expected.validate_exact(&changed),
            Err(AttestationMismatch::JobAssignment)
        );
        let mut changed = actual.clone();
        changed
            .guarantees
            .remove(&SandboxGuarantee::NetworkDisabled);
        assert_eq!(
            expected.validate_exact(&changed),
            Err(AttestationMismatch::Guarantees)
        );
        let mut changed = actual;
        changed.helper_build = HelperBuildId::new("helper-other").expect("helper build");
        assert_eq!(
            expected.validate_exact(&changed),
            Err(AttestationMismatch::HelperBuild)
        );
    }

    #[test]
    fn prior_provisioning_evidence_cannot_replay_into_an_identical_policy() {
        let policy = local_policy();
        let binary = binary_id();
        let helper = HelperBuildId::new("helper-1.0.0+abc").expect("helper build");
        let prior = ExpectedSandboxAttestation::from_policy(
            binary.clone(),
            &policy,
            helper.clone(),
            ProvisioningEpoch::new("1".repeat(64)).expect("prior epoch"),
        )
        .expect("prior expected attestation");
        let prior_attestation = actual_from(&prior);
        let prior_cleanup = complete_receipt(&prior);

        let current = ExpectedSandboxAttestation::from_policy(
            binary,
            &policy,
            helper,
            ProvisioningEpoch::new("2".repeat(64)).expect("current epoch"),
        )
        .expect("current expected attestation");
        assert_eq!(
            current.validate_exact(&prior_attestation),
            Err(AttestationMismatch::ProvisioningEpoch)
        );
        assert_eq!(
            prior_cleanup.validate_against(&current),
            Err(CleanupReceiptError::BindingMismatch)
        );
    }

    #[test]
    fn cleanup_receipt_cannot_claim_false_completion() {
        let expected = expected_attestation();
        let mut receipt = complete_receipt(&expected);
        receipt
            .validate_against(&expected)
            .expect("complete cleanup");

        receipt.network_torn_down = false;
        assert_eq!(
            receipt.validate_against(&expected),
            Err(CleanupReceiptError::FalseComplete)
        );
        receipt.outcome = CleanupOutcome::Incomplete;
        assert_eq!(
            receipt.validate_against(&expected),
            Err(CleanupReceiptError::MissingResidual)
        );
        receipt.residuals.push(CleanupResidual {
            kind: CleanupResidualKind::Network,
            detail: DiagnosticText::new("isolated switch cleanup pending").expect("detail"),
        });
        receipt
            .validate_against(&expected)
            .expect("audited incomplete cleanup");
    }

    #[test]
    fn cleanup_attempt_failure_validates_bounded_incomplete_evidence() {
        let expected = expected_attestation();
        let receipt = incomplete_receipt(&expected);
        let attempt = SandboxCleanupAttemptFailure {
            failure: SandboxFailure {
                session_id: receipt.session_id,
                provisioning_epoch: receipt.provisioning_epoch.clone(),
                policy_digest: receipt.policy_digest.clone(),
                provider: receipt.provider.clone(),
                context: SandboxFailureContext::Launch {
                    binary_id: expected.binary_id.clone(),
                    helper_build: expected.helper_build.clone(),
                },
                stage: SandboxFailureStage::Cleanup,
                kind: SandboxFailureKind::CleanupIncomplete,
                retryable: true,
                detail: DiagnosticText::new("cleanup requires a retry").expect("detail"),
            },
            receipt,
        };
        attempt.validate().expect("exact incomplete attempt");

        let mut wrong_stage = attempt.clone();
        wrong_stage.failure.stage = SandboxFailureStage::Runtime;
        assert_eq!(
            wrong_stage.validate(),
            Err(CleanupAttemptFailureError::WrongStage)
        );

        let mut wrong_kind = attempt.clone();
        wrong_kind.failure.kind = SandboxFailureKind::HelperFailure;
        assert_eq!(
            wrong_kind.validate(),
            Err(CleanupAttemptFailureError::WrongKind)
        );

        let mut not_retryable = attempt.clone();
        not_retryable.failure.retryable = false;
        not_retryable
            .validate()
            .expect("retryability is advisory; failure remains fail-closed");

        let mut mismatched = attempt.clone();
        mismatched.failure.session_id = SessionId::new(99).expect("other session");
        assert_eq!(
            mismatched.validate(),
            Err(CleanupAttemptFailureError::FailureReceiptMismatch)
        );

        let mut complete = attempt.clone();
        complete.receipt = complete_receipt(&expected);
        assert_eq!(
            complete.validate(),
            Err(CleanupAttemptFailureError::ReceiptNotIncomplete)
        );

        let mut missing_residual = attempt.clone();
        missing_residual.receipt.residuals.clear();
        assert_eq!(
            missing_residual.validate(),
            Err(CleanupAttemptFailureError::Receipt(
                CleanupReceiptError::MissingResidual
            ))
        );

        let mut oversized = attempt;
        while oversized.receipt.residuals.len() <= MAX_CLEANUP_RESIDUALS {
            oversized.receipt.residuals.push(CleanupResidual {
                kind: CleanupResidualKind::Provider,
                detail: DiagnosticText::new("provider cleanup pending").expect("detail"),
            });
        }
        assert_eq!(
            oversized.validate(),
            Err(CleanupAttemptFailureError::Receipt(
                CleanupReceiptError::TooManyResiduals
            ))
        );
    }

    #[test]
    fn sandbox_failure_stage_kind_matrix_is_exact() {
        let expected = expected_attestation();
        let stages = [
            SandboxFailureStage::Policy,
            SandboxFailureStage::Discovery,
            SandboxFailureStage::Provisioning,
            SandboxFailureStage::Attestation,
            SandboxFailureStage::Launch,
            SandboxFailureStage::Runtime,
            SandboxFailureStage::Cleanup,
        ];
        let kinds = [
            SandboxFailureKind::InvalidPolicy,
            SandboxFailureKind::ProviderUnavailable,
            SandboxFailureKind::AttestationRejected,
            SandboxFailureKind::LaunchDenied,
            SandboxFailureKind::ResourceLimitReached,
            SandboxFailureKind::HelperFailure,
            SandboxFailureKind::CleanupIncomplete,
            SandboxFailureKind::ProtocolViolation,
        ];
        for stage in stages {
            for kind in kinds {
                let compatible = match stage {
                    SandboxFailureStage::Policy => matches!(
                        kind,
                        SandboxFailureKind::InvalidPolicy | SandboxFailureKind::ProtocolViolation
                    ),
                    SandboxFailureStage::Discovery => matches!(
                        kind,
                        SandboxFailureKind::ProviderUnavailable
                            | SandboxFailureKind::HelperFailure
                            | SandboxFailureKind::ProtocolViolation
                    ),
                    SandboxFailureStage::Provisioning => matches!(
                        kind,
                        SandboxFailureKind::ProviderUnavailable
                            | SandboxFailureKind::ResourceLimitReached
                            | SandboxFailureKind::HelperFailure
                            | SandboxFailureKind::ProtocolViolation
                    ),
                    SandboxFailureStage::Attestation => matches!(
                        kind,
                        SandboxFailureKind::AttestationRejected
                            | SandboxFailureKind::HelperFailure
                            | SandboxFailureKind::ProtocolViolation
                    ),
                    SandboxFailureStage::Launch => matches!(
                        kind,
                        SandboxFailureKind::LaunchDenied
                            | SandboxFailureKind::ResourceLimitReached
                            | SandboxFailureKind::HelperFailure
                            | SandboxFailureKind::ProtocolViolation
                    ),
                    SandboxFailureStage::Runtime => matches!(
                        kind,
                        SandboxFailureKind::ResourceLimitReached
                            | SandboxFailureKind::HelperFailure
                            | SandboxFailureKind::ProtocolViolation
                    ),
                    SandboxFailureStage::Cleanup => kind == SandboxFailureKind::CleanupIncomplete,
                };
                let actual = failure_for_expected(&expected, stage, kind).validate_stage_kind();
                assert_eq!(
                    actual.is_ok(),
                    compatible,
                    "unexpected compatibility for {stage:?}/{kind:?}"
                );
            }
        }
    }

    #[test]
    fn sandbox_failure_launch_binding_rejects_every_freshness_mutation() {
        let expected = expected_attestation();
        let failure = failure_for_expected(
            &expected,
            SandboxFailureStage::Provisioning,
            SandboxFailureKind::HelperFailure,
        );
        failure
            .validate_against_expected(&expected)
            .expect("exact failure binding");

        let mut changed = failure.clone();
        changed.session_id = SessionId::new(expected.session_id.get() + 1).expect("session");
        assert_eq!(
            changed.validate_against_expected(&expected),
            Err(SandboxFailureValidationError::Session)
        );
        let mut changed = failure.clone();
        changed.provisioning_epoch = ProvisioningEpoch::new("f".repeat(64)).expect("epoch");
        assert_eq!(
            changed.validate_against_expected(&expected),
            Err(SandboxFailureValidationError::ProvisioningEpoch)
        );
        let mut changed = failure.clone();
        changed.policy_digest = PolicyDigest::new("f".repeat(64)).expect("digest");
        assert_eq!(
            changed.validate_against_expected(&expected),
            Err(SandboxFailureValidationError::PolicyDigest)
        );
        let mut changed = failure.clone();
        changed.provider = SandboxProviderSelection::HyperV;
        assert_eq!(
            changed.validate_against_expected(&expected),
            Err(SandboxFailureValidationError::Provider)
        );
        let mut changed = failure.clone();
        let SandboxFailureContext::Launch { binary_id, .. } = &mut changed.context else {
            unreachable!("launch context")
        };
        *binary_id = BinaryId::digest(b"another image");
        assert_eq!(
            changed.validate_against_expected(&expected),
            Err(SandboxFailureValidationError::BinaryIdentity)
        );
        let mut changed = failure.clone();
        let SandboxFailureContext::Launch { helper_build, .. } = &mut changed.context else {
            unreachable!("launch context")
        };
        *helper_build = HelperBuildId::new("another-helper").expect("helper");
        assert_eq!(
            changed.validate_against_expected(&expected),
            Err(SandboxFailureValidationError::HelperBuild)
        );
        let mut changed = failure;
        changed.context = SandboxFailureContext::InheritedAttach {
            process: ProcessIdentity {
                process_id: crate::protocol::ProcessId::new(9).expect("process"),
                start_key: crate::protocol::ProcessStartKey::new(10).expect("start key"),
                binary_id: BinaryId::digest(b"another image"),
            },
            mode: AttachMode::Debug,
        };
        assert_eq!(
            changed.validate_against_expected(&expected),
            Err(SandboxFailureValidationError::ContextKind)
        );
    }

    #[test]
    fn canonical_policy_digest_is_deterministic_and_identity_bound() {
        let policy = local_policy();
        let binary = binary_id();
        let first = policy.digest(&binary).expect("digest");
        let second = policy.digest(&binary).expect("digest");
        assert_eq!(first, second);

        let other_binary = BinaryId::digest(b"other exact target");
        assert_ne!(first, policy.digest(&other_binary).expect("digest"));

        let mut changed = policy;
        changed.resources.wall_clock_millis += 1;
        assert_ne!(first, changed.digest(&binary).expect("digest"));
    }

    #[test]
    fn registered_provider_support_is_descriptor_bounded() {
        let mut policy = local_policy();
        let mut supported = local_guarantees();
        supported.remove(&SandboxGuarantee::NetworkDisabled);
        policy.provider = SandboxProviderSelection::Registered {
            descriptor: SandboxProviderDescriptor {
                id: ProviderId::new("vendor.sandbox").expect("provider id"),
                boundary: IsolationBoundary::UserMode,
                guarantees: supported,
                build_identity: HelperBuildId::new("vendor-1.0.0").expect("provider build"),
            },
        };
        assert_eq!(
            policy.validate(),
            Err(PolicyValidationError::UnsupportedGuarantee(
                SandboxGuarantee::NetworkDisabled
            ))
        );

        let SandboxProviderSelection::Registered { descriptor } = &mut policy.provider else {
            unreachable!("registered provider")
        };
        descriptor.guarantees.clear();
        assert_eq!(
            policy.validate(),
            Err(PolicyValidationError::EmptyProviderGuarantees)
        );
    }

    #[test]
    fn hypervisor_policy_requires_exact_vm_and_channel_identity() {
        let policy = vm_policy();
        policy.validate().expect("valid VM policy");

        let mut missing = policy.clone();
        missing.vm_identity = None;
        assert_eq!(
            missing.validate(),
            Err(PolicyValidationError::MissingVmIdentity)
        );

        let mut invalid = policy.clone();
        invalid
            .vm_identity
            .as_mut()
            .expect("VM identity")
            .channel_protocol_version = 0;
        assert_eq!(
            invalid.validate(),
            Err(PolicyValidationError::InvalidVmChannelVersion)
        );

        let expected = ExpectedSandboxAttestation::from_policy(
            binary_id(),
            &policy,
            HelperBuildId::new("helper-vm").expect("helper build"),
            provisioning_epoch(),
        )
        .expect("expected attestation");
        let mut actual = actual_from(&expected);
        actual
            .vm_identity
            .as_mut()
            .expect("VM identity")
            .channel_nonce = AuthenticatedChannelNonce::new("d".repeat(64)).expect("nonce");
        assert_eq!(
            expected.validate_exact(&actual),
            Err(AttestationMismatch::VmIdentity)
        );
    }

    #[test]
    fn sandbox_machine_rejects_illegal_order_and_requires_complete_cleanup() {
        let expected = expected_attestation();
        let actual = actual_from(&expected);
        let receipt = complete_receipt(&expected);
        let mut machine = SandboxMachine::new(expected).expect("machine");

        assert_eq!(
            machine.mark_running(),
            Err(SandboxMachineError::AttestationNotAccepted)
        );
        assert!(matches!(
            machine.target_created_suspended(),
            Err(SandboxMachineError::InvalidTransition { .. })
        ));
        assert_eq!(
            machine.begin_provisioning().expect("provisioning"),
            SandboxLifecycleState::Provisioning
        );
        assert_eq!(
            machine
                .target_created_suspended()
                .expect("suspended target"),
            SandboxLifecycleState::TargetCreatedSuspended
        );
        assert_eq!(
            machine.accept_attestation(&actual).expect("attestation"),
            SandboxLifecycleState::AttestationAccepted
        );
        assert_eq!(
            machine.mark_running().expect("running"),
            SandboxLifecycleState::Running
        );
        machine.begin_cleanup().expect("cleanup");
        assert_eq!(
            machine.close(&receipt).expect("closed"),
            SandboxLifecycleState::Closed
        );
        assert!(matches!(
            machine.begin_cleanup(),
            Err(SandboxMachineError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn sandbox_contracts_reject_unknown_fields_and_invalid_bounded_text() {
        let mut value = serde_json::to_value(local_policy()).expect("serialize policy");
        value
            .as_object_mut()
            .expect("policy object")
            .insert("future-dangerous-field".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<SandboxPolicy>(value).is_err());

        let overlong =
            serde_json::to_value("x".repeat(MAX_DIAGNOSTIC_BYTES + 1)).expect("serialize text");
        assert!(serde_json::from_value::<DiagnosticText>(overlong).is_err());
    }
}
