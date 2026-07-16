//! Backend-neutral, fail-closed sandbox policy and attestation contracts.

use std::{collections::BTreeSet, fmt};

use resymbol_core::BinaryId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const MAX_PROVIDER_ID_BYTES: usize = 96;
const MAX_SESSION_ID_BYTES: usize = 96;
const MAX_ACK_ID_BYTES: usize = 128;
const MAX_BUILD_ID_BYTES: usize = 128;
const MAX_RECEIPT_ID_BYTES: usize = 128;
const MAX_DIAGNOSTIC_BYTES: usize = 512;
const MAX_CLEANUP_RESIDUALS: usize = 32;

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
bounded_identifier!(SandboxSessionId, "sandbox session id", MAX_SESSION_ID_BYTES);
bounded_identifier!(
    RiskAcknowledgementNonce,
    "risk acknowledgement id",
    MAX_ACK_ID_BYTES
);
bounded_identifier!(HelperBuildId, "helper build id", MAX_BUILD_ID_BYTES);
bounded_identifier!(CleanupReceiptId, "cleanup receipt id", MAX_RECEIPT_ID_BYTES);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RiskAcknowledgementId {
    session_id: SandboxSessionId,
    nonce: RiskAcknowledgementNonce,
}

impl RiskAcknowledgementId {
    pub fn new(
        session_id: SandboxSessionId,
        nonce: impl Into<String>,
    ) -> Result<Self, BoundedValueError> {
        Ok(Self {
            session_id,
            nonce: RiskAcknowledgementNonce::new(nonce)?,
        })
    }

    #[must_use]
    pub fn session_id(&self) -> &SandboxSessionId {
        &self.session_id
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SandboxProviderSelection {
    LocalAppContainer,
    WindowsSandbox,
    HyperV,
    Registered { id: ProviderId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationBoundary {
    UserMode,
    Hypervisor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxFallbackPolicy {
    FailClosed,
    AllowHostExecution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct SandboxPolicy {
    pub session_id: SandboxSessionId,
    pub risk_acknowledgement: RiskAcknowledgementId,
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
    pub fallback: SandboxFallbackPolicy,
}

impl SandboxPolicy {
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        self.resources.validate()?;
        if !self.rollback_on_close {
            return Err(PolicyValidationError::RollbackRequired);
        }
        if self.fallback != SandboxFallbackPolicy::FailClosed {
            return Err(PolicyValidationError::HostFallbackForbidden);
        }
        if self.risk_acknowledgement.session_id() != &self.session_id {
            return Err(PolicyValidationError::AcknowledgementSessionMismatch);
        }
        if let Some(boundary) = fixed_boundary(&self.provider) {
            if boundary != self.required_boundary {
                return Err(PolicyValidationError::ProviderBoundaryMismatch);
            }
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
        if let SandboxProviderSelection::Registered { id } = &self.provider {
            if is_reserved_provider_id(id.as_str()) {
                return Err(PolicyValidationError::ReservedProviderId);
            }
        }
        for guarantee in &self.required_guarantees {
            if !provider_supports(&self.provider, *guarantee) {
                return Err(PolicyValidationError::UnsupportedGuarantee(*guarantee));
            }
        }
        Ok(())
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

fn fixed_boundary(provider: &SandboxProviderSelection) -> Option<IsolationBoundary> {
    match provider {
        SandboxProviderSelection::LocalAppContainer => Some(IsolationBoundary::UserMode),
        SandboxProviderSelection::WindowsSandbox | SandboxProviderSelection::HyperV => {
            Some(IsolationBoundary::Hypervisor)
        }
        SandboxProviderSelection::Registered { .. } => None,
    }
}

fn provider_supports(provider: &SandboxProviderSelection, guarantee: SandboxGuarantee) -> bool {
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
        SandboxProviderSelection::Registered { .. } => true,
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
    #[error("host execution fallback is forbidden")]
    HostFallbackForbidden,
    #[error("risk acknowledgement belongs to another session")]
    AcknowledgementSessionMismatch,
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
    #[error("selected provider cannot supply guarantee: {0:?}")]
    UnsupportedGuarantee(SandboxGuarantee),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedSandboxAttestation {
    pub binary_id: BinaryId,
    pub session_id: SandboxSessionId,
    pub policy_digest: PolicyDigest,
    pub provider: SandboxProviderSelection,
    pub boundary: IsolationBoundary,
    pub guarantees: BTreeSet<SandboxGuarantee>,
    pub job_assigned_at_creation: bool,
    pub helper_build: HelperBuildId,
}

impl ExpectedSandboxAttestation {
    pub fn from_policy(
        binary_id: BinaryId,
        policy: &SandboxPolicy,
        policy_digest: PolicyDigest,
        helper_build: HelperBuildId,
    ) -> Result<Self, PolicyValidationError> {
        policy.validate()?;
        Ok(Self {
            binary_id,
            session_id: policy.session_id.clone(),
            policy_digest,
            provider: policy.provider.clone(),
            boundary: policy.required_boundary,
            guarantees: policy.required_guarantees.clone(),
            job_assigned_at_creation: true,
            helper_build,
        })
    }

    pub fn validate_exact(&self, actual: &SandboxAttestation) -> Result<(), AttestationMismatch> {
        if self.binary_id != actual.binary_id {
            return Err(AttestationMismatch::BinaryIdentity);
        }
        if self.session_id != actual.session_id {
            return Err(AttestationMismatch::Session);
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
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxAttestation {
    pub binary_id: BinaryId,
    pub session_id: SandboxSessionId,
    pub policy_digest: PolicyDigest,
    pub provider: SandboxProviderSelection,
    pub boundary: IsolationBoundary,
    pub guarantees: BTreeSet<SandboxGuarantee>,
    pub job_assigned_at_creation: bool,
    pub helper_build: HelperBuildId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AttestationMismatch {
    #[error("binary identity attestation mismatch")]
    BinaryIdentity,
    #[error("sandbox session attestation mismatch")]
    Session,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxFailure {
    pub session_id: SandboxSessionId,
    pub provider: SandboxProviderSelection,
    pub stage: SandboxFailureStage,
    pub kind: SandboxFailureKind,
    pub retryable: bool,
    pub detail: DiagnosticText,
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
pub struct ProviderUnavailable {
    pub session_id: SandboxSessionId,
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
    Provider,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupResidual {
    pub kind: CleanupResidualKind,
    pub detail: DiagnosticText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxCleanupReceipt {
    pub receipt_id: CleanupReceiptId,
    pub session_id: SandboxSessionId,
    pub provider: SandboxProviderSelection,
    pub policy_digest: PolicyDigest,
    pub outcome: CleanupOutcome,
    pub job_closed: bool,
    pub file_system_rolled_back: bool,
    pub registry_rolled_back: bool,
    pub network_torn_down: bool,
    pub terminated_processes: u32,
    pub residuals: Vec<CleanupResidual>,
}

impl SandboxCleanupReceipt {
    pub fn validate_against(
        &self,
        expected: &ExpectedSandboxAttestation,
    ) -> Result<(), CleanupReceiptError> {
        if self.session_id != expected.session_id
            || self.provider != expected.provider
            || self.policy_digest != expected.policy_digest
        {
            return Err(CleanupReceiptError::BindingMismatch);
        }
        if self.residuals.len() > MAX_CLEANUP_RESIDUALS {
            return Err(CleanupReceiptError::TooManyResiduals);
        }
        let all_clean = self.job_closed
            && self.file_system_rolled_back
            && self.registry_rolled_back
            && self.network_torn_down;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxLifecycleState {
    Requested,
    Provisioning,
    Attested,
    TargetCreatedSuspended,
    Running,
    Cleanup,
    Closed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum SandboxLifecycleEvent {
    State {
        session_id: SandboxSessionId,
        state: SandboxLifecycleState,
    },
    Attested(SandboxAttestation),
    ProviderUnavailable(ProviderUnavailable),
    Failed(SandboxFailure),
    Closed(SandboxCleanupReceipt),
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
        let session_id = SandboxSessionId::new("session-1").expect("session id");
        SandboxPolicy {
            risk_acknowledgement: RiskAcknowledgementId::new(session_id.clone(), "ack-1")
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
            fallback: SandboxFallbackPolicy::FailClosed,
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

        let mut fallback = policy.clone();
        fallback.fallback = SandboxFallbackPolicy::AllowHostExecution;
        assert_eq!(
            fallback.validate(),
            Err(PolicyValidationError::HostFallbackForbidden)
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
        policy.risk_acknowledgement = RiskAcknowledgementId::new(
            SandboxSessionId::new("other-session").expect("other session"),
            "ack-2",
        )
        .expect("acknowledgement");
        assert_eq!(
            policy.validate(),
            Err(PolicyValidationError::AcknowledgementSessionMismatch)
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
            PolicyDigest::new("a".repeat(64)).expect("digest"),
            HelperBuildId::new("helper-1.0.0+abc").expect("helper build"),
        )
        .expect("expected attestation")
    }

    fn actual_from(expected: &ExpectedSandboxAttestation) -> SandboxAttestation {
        SandboxAttestation {
            binary_id: expected.binary_id.clone(),
            session_id: expected.session_id.clone(),
            policy_digest: expected.policy_digest.clone(),
            provider: expected.provider.clone(),
            boundary: expected.boundary,
            guarantees: expected.guarantees.clone(),
            job_assigned_at_creation: expected.job_assigned_at_creation,
            helper_build: expected.helper_build.clone(),
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
    fn cleanup_receipt_cannot_claim_false_completion() {
        let expected = expected_attestation();
        let mut receipt = SandboxCleanupReceipt {
            receipt_id: CleanupReceiptId::new("receipt-1").expect("receipt id"),
            session_id: expected.session_id.clone(),
            provider: expected.provider.clone(),
            policy_digest: expected.policy_digest.clone(),
            outcome: CleanupOutcome::Complete,
            job_closed: true,
            file_system_rolled_back: true,
            registry_rolled_back: true,
            network_torn_down: true,
            terminated_processes: 2,
            residuals: Vec::new(),
        };
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
}
