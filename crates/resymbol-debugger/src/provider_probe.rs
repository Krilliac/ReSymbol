//! Read-only sandbox provider discovery and readiness contracts.
//!
//! Readiness is only permission to attempt provisioning. It is never a
//! containment guarantee and never replaces the exact post-creation
//! attestation required by [`crate::SandboxMachine`].

use std::collections::BTreeSet;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::sandbox::{ProviderId, provider_boundary, provider_supports};
use crate::{
    DiagnosticText, HelperBuildId, IsolationBoundary, PolicyValidationError, SandboxGuarantee,
    SandboxProviderSelection,
};

pub const MAX_PROBE_GUARANTEES: usize = 32;
pub const MAX_PROBE_REQUIREMENTS: usize = 32;

/// A Windows optional feature whose enabled state must be confirmed by a
/// platform adapter before provisioning is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsOptionalFeature {
    ContainersDisposableClientVm,
    MicrosoftHyperVAll,
}

impl WindowsOptionalFeature {
    /// Returns the stable Windows optional-feature identifier.
    #[must_use]
    pub const fn feature_name(self) -> &'static str {
        match self {
            Self::ContainersDisposableClientVm => "Containers-DisposableClientVM",
            Self::MicrosoftHyperVAll => "Microsoft-Hyper-V-All",
        }
    }
}

/// An unresolved prerequisite for a provider readiness decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "requirement", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SandboxProviderRequirement {
    WindowsOperatingSystem,
    StableReadOnlyCapabilityProbe,
    AppContainerApiAvailability,
    WindowsOptionalFeature {
        feature: WindowsOptionalFeature,
    },
    HardwareVirtualization,
    HypervisorActive,
    AdministrativePolicyApproval,
    ProviderHelperAvailable,
    SealedVmImageAvailable,
    RegisteredProviderProbe {
        id: ProviderId,
        build_identity: HelperBuildId,
    },
    ExactProviderIdentity,
    ProviderMatchingBoundary {
        boundary: IsolationBoundary,
    },
    ProviderSupportingRequiredGuarantees,
}

/// A readiness result deliberately weaker than a runtime attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxProviderReadiness {
    /// A read-only probe observed the requested provider and prerequisites.
    /// Provisioning must still create the target suspended and attest it.
    ReadyForProvisioningAttempt,
    Unavailable,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxProviderReadinessReason {
    ConfirmedByReadOnlyProbe,
    UnsupportedPlatform,
    FeatureDisabled,
    AdministrativePolicy,
    ResourceUnavailable,
    ProbeBackendUnavailable,
    CapabilitiesUnverified,
    ProviderIdentityMismatch,
    BoundaryMismatch,
    MissingRequiredGuarantees,
    InvalidProbeObservation,
}

/// Exact provider and capability request presented to the discovery service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxProviderProbeRequest {
    provider: SandboxProviderSelection,
    required_boundary: IsolationBoundary,
    required_guarantees: BTreeSet<SandboxGuarantee>,
}

impl SandboxProviderProbeRequest {
    pub fn new(
        provider: SandboxProviderSelection,
        required_boundary: IsolationBoundary,
        required_guarantees: BTreeSet<SandboxGuarantee>,
    ) -> Result<Self, ProviderProbeValidationError> {
        let request = Self {
            provider,
            required_boundary,
            required_guarantees,
        };
        request.validate()?;
        Ok(request)
    }

    #[must_use]
    pub const fn provider(&self) -> &SandboxProviderSelection {
        &self.provider
    }

    #[must_use]
    pub const fn required_boundary(&self) -> IsolationBoundary {
        self.required_boundary
    }

    #[must_use]
    pub const fn required_guarantees(&self) -> &BTreeSet<SandboxGuarantee> {
        &self.required_guarantees
    }

    fn validate(&self) -> Result<(), ProviderProbeValidationError> {
        if self.required_guarantees.is_empty() {
            return Err(ProviderProbeValidationError::EmptyRequiredGuarantees);
        }
        if self.required_guarantees.len() > MAX_PROBE_GUARANTEES {
            return Err(ProviderProbeValidationError::TooManyGuarantees);
        }
        if let SandboxProviderSelection::Registered { descriptor } = &self.provider {
            descriptor.validate()?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxProviderProbeRequestWire {
    provider: SandboxProviderSelection,
    required_boundary: IsolationBoundary,
    required_guarantees: BTreeSet<SandboxGuarantee>,
}

impl<'de> Deserialize<'de> for SandboxProviderProbeRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SandboxProviderProbeRequestWire::deserialize(deserializer)?;
        Self::new(
            wire.provider,
            wire.required_boundary,
            wire.required_guarantees,
        )
        .map_err(D::Error::custom)
    }
}

/// A bounded observation returned by an injected platform probe.
///
/// This is deliberately not serializable: it is a local backend-to-service
/// value, not a transport-level attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderProbeObservation {
    provider: SandboxProviderSelection,
    disposition: ProviderProbeDisposition,
    boundary: Option<IsolationBoundary>,
    observed_guarantees: BTreeSet<SandboxGuarantee>,
    reason: SandboxProviderReadinessReason,
    requirements: BTreeSet<SandboxProviderRequirement>,
    detail: DiagnosticText,
}

impl ProviderProbeObservation {
    pub fn ready(
        provider: SandboxProviderSelection,
        boundary: IsolationBoundary,
        observed_guarantees: BTreeSet<SandboxGuarantee>,
        detail: DiagnosticText,
    ) -> Result<Self, ProviderProbeValidationError> {
        if observed_guarantees.is_empty() {
            return Err(ProviderProbeValidationError::EmptyObservedGuarantees);
        }
        if observed_guarantees.len() > MAX_PROBE_GUARANTEES {
            return Err(ProviderProbeValidationError::TooManyGuarantees);
        }
        Ok(Self {
            provider,
            disposition: ProviderProbeDisposition::Ready,
            boundary: Some(boundary),
            observed_guarantees,
            reason: SandboxProviderReadinessReason::ConfirmedByReadOnlyProbe,
            requirements: BTreeSet::new(),
            detail,
        })
    }

    pub fn unavailable(
        provider: SandboxProviderSelection,
        reason: SandboxProviderReadinessReason,
        requirements: BTreeSet<SandboxProviderRequirement>,
        detail: DiagnosticText,
    ) -> Result<Self, ProviderProbeValidationError> {
        Self::not_ready(
            provider,
            ProviderProbeDisposition::Unavailable,
            reason,
            requirements,
            detail,
        )
    }

    pub fn indeterminate(
        provider: SandboxProviderSelection,
        reason: SandboxProviderReadinessReason,
        requirements: BTreeSet<SandboxProviderRequirement>,
        detail: DiagnosticText,
    ) -> Result<Self, ProviderProbeValidationError> {
        Self::not_ready(
            provider,
            ProviderProbeDisposition::Indeterminate,
            reason,
            requirements,
            detail,
        )
    }

    fn not_ready(
        provider: SandboxProviderSelection,
        disposition: ProviderProbeDisposition,
        reason: SandboxProviderReadinessReason,
        requirements: BTreeSet<SandboxProviderRequirement>,
        detail: DiagnosticText,
    ) -> Result<Self, ProviderProbeValidationError> {
        if reason == SandboxProviderReadinessReason::ConfirmedByReadOnlyProbe {
            return Err(ProviderProbeValidationError::InvalidNotReadyReason);
        }
        validate_requirements(&requirements)?;
        Ok(Self {
            provider,
            disposition,
            boundary: None,
            observed_guarantees: BTreeSet::new(),
            reason,
            requirements,
            detail,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderProbeDisposition {
    Ready,
    Unavailable,
    Indeterminate,
}

/// Injectable, read-only capability observation boundary.
///
/// Implementations may be called on any thread and must be thread-safe. They
/// must not provision resources, create profiles or VMs, execute targets,
/// enable features, request elevation, or weaken a requested provider.
pub trait SandboxProviderProbeBackend: Send + Sync {
    fn probe(&self, request: &SandboxProviderProbeRequest) -> ProviderProbeObservation;
}

/// Value-only discovery service. It owns no platform handle and is safe to
/// replace between calls.
#[derive(Debug, Clone)]
pub struct SandboxProviderReadinessService<B> {
    backend: B,
}

impl<B> SandboxProviderReadinessService<B>
where
    B: SandboxProviderProbeBackend,
{
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Performs one bounded, read-only readiness query.
    ///
    /// A ready result only authorizes a provisioning attempt. Runtime use is
    /// still gated on exact suspended-target attestation.
    #[must_use]
    pub fn probe(&self, request: &SandboxProviderProbeRequest) -> SandboxProviderReadinessReport {
        if provider_boundary(request.provider()) != request.required_boundary() {
            return report_not_ready(
                request,
                SandboxProviderReadiness::Unavailable,
                SandboxProviderReadinessReason::BoundaryMismatch,
                [SandboxProviderRequirement::ProviderMatchingBoundary {
                    boundary: request.required_boundary(),
                }],
                "The selected provider declares a different isolation boundary.",
            );
        }

        if request
            .required_guarantees()
            .iter()
            .any(|guarantee| !provider_supports(request.provider(), *guarantee))
        {
            return report_not_ready(
                request,
                SandboxProviderReadiness::Unavailable,
                SandboxProviderReadinessReason::MissingRequiredGuarantees,
                [SandboxProviderRequirement::ProviderSupportingRequiredGuarantees],
                "The selected provider cannot declare every required policy guarantee.",
            );
        }

        let observation = self.backend.probe(request);
        if observation.provider != *request.provider() {
            return report_not_ready(
                request,
                SandboxProviderReadiness::Indeterminate,
                SandboxProviderReadinessReason::ProviderIdentityMismatch,
                [
                    SandboxProviderRequirement::ExactProviderIdentity,
                    SandboxProviderRequirement::StableReadOnlyCapabilityProbe,
                ],
                "The probe reported a different provider identity; readiness was rejected.",
            );
        }

        match observation.disposition {
            ProviderProbeDisposition::Ready => {
                if observation.boundary != Some(request.required_boundary()) {
                    return report_not_ready(
                        request,
                        SandboxProviderReadiness::Indeterminate,
                        SandboxProviderReadinessReason::BoundaryMismatch,
                        [SandboxProviderRequirement::ProviderMatchingBoundary {
                            boundary: request.required_boundary(),
                        }],
                        "The probe did not confirm the requested isolation boundary.",
                    );
                }
                if !observation
                    .observed_guarantees
                    .is_superset(request.required_guarantees())
                {
                    return report_not_ready(
                        request,
                        SandboxProviderReadiness::Indeterminate,
                        SandboxProviderReadinessReason::MissingRequiredGuarantees,
                        [SandboxProviderRequirement::ProviderSupportingRequiredGuarantees],
                        "The probe did not observe every capability required by the policy.",
                    );
                }
                SandboxProviderReadinessReport::new(
                    request.clone(),
                    SandboxProviderReadiness::ReadyForProvisioningAttempt,
                    SandboxProviderReadinessReason::ConfirmedByReadOnlyProbe,
                    BTreeSet::new(),
                    observation.detail,
                )
                .expect("a validated ready observation creates a valid report")
            }
            ProviderProbeDisposition::Unavailable => SandboxProviderReadinessReport::new(
                request.clone(),
                SandboxProviderReadiness::Unavailable,
                observation.reason,
                observation.requirements,
                observation.detail,
            )
            .expect("observation constructors enforce report bounds"),
            ProviderProbeDisposition::Indeterminate => SandboxProviderReadinessReport::new(
                request.clone(),
                SandboxProviderReadiness::Indeterminate,
                observation.reason,
                observation.requirements,
                observation.detail,
            )
            .expect("observation constructors enforce report bounds"),
        }
    }
}

/// Conservative system backend with no mutating behavior.
///
/// It uses only Rust's compile-time target platform. Off Windows it reports a
/// definitive platform mismatch. On Windows it reports typed requirements as
/// indeterminate because this backend intentionally does not trust environment
/// variables, registry implementation details, localized command output, or
/// feature activation side effects.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSandboxProviderProbe;

impl SandboxProviderProbeBackend for SystemSandboxProviderProbe {
    fn probe(&self, request: &SandboxProviderProbeRequest) -> ProviderProbeObservation {
        if !cfg!(target_os = "windows") {
            return ProviderProbeObservation::unavailable(
                request.provider().clone(),
                SandboxProviderReadinessReason::UnsupportedPlatform,
                BTreeSet::from([SandboxProviderRequirement::WindowsOperatingSystem]),
                diagnostic(
                    "Built-in ReSymbol sandbox providers require Windows; no capability was assumed.",
                ),
            )
            .expect("static system observation is valid");
        }

        ProviderProbeObservation::indeterminate(
            request.provider().clone(),
            SandboxProviderReadinessReason::CapabilitiesUnverified,
            windows_requirements(request.provider()),
            diagnostic(
                "Windows was detected, but provider prerequisites require a stable read-only platform adapter before provisioning.",
            ),
        )
        .expect("static system observation is valid")
    }
}

fn windows_requirements(
    provider: &SandboxProviderSelection,
) -> BTreeSet<SandboxProviderRequirement> {
    let mut requirements = BTreeSet::from([
        SandboxProviderRequirement::StableReadOnlyCapabilityProbe,
        SandboxProviderRequirement::AdministrativePolicyApproval,
        SandboxProviderRequirement::ProviderHelperAvailable,
    ]);
    match provider {
        SandboxProviderSelection::LocalAppContainer => {
            requirements.insert(SandboxProviderRequirement::AppContainerApiAvailability);
        }
        SandboxProviderSelection::WindowsSandbox => {
            requirements.insert(SandboxProviderRequirement::WindowsOptionalFeature {
                feature: WindowsOptionalFeature::ContainersDisposableClientVm,
            });
            requirements.insert(SandboxProviderRequirement::HardwareVirtualization);
            requirements.insert(SandboxProviderRequirement::HypervisorActive);
        }
        SandboxProviderSelection::HyperV => {
            requirements.insert(SandboxProviderRequirement::WindowsOptionalFeature {
                feature: WindowsOptionalFeature::MicrosoftHyperVAll,
            });
            requirements.insert(SandboxProviderRequirement::HardwareVirtualization);
            requirements.insert(SandboxProviderRequirement::HypervisorActive);
            requirements.insert(SandboxProviderRequirement::SealedVmImageAvailable);
        }
        SandboxProviderSelection::Registered { descriptor } => {
            requirements.insert(SandboxProviderRequirement::RegisteredProviderProbe {
                id: descriptor.id.clone(),
                build_identity: descriptor.build_identity.clone(),
            });
        }
    }
    requirements
}

/// Serializable readiness report. The requested guarantees are requirements,
/// not claims about a created sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxProviderReadinessReport {
    provider: SandboxProviderSelection,
    required_boundary: IsolationBoundary,
    required_guarantees: BTreeSet<SandboxGuarantee>,
    readiness: SandboxProviderReadiness,
    reason: SandboxProviderReadinessReason,
    requirements: BTreeSet<SandboxProviderRequirement>,
    detail: DiagnosticText,
}

impl SandboxProviderReadinessReport {
    fn new(
        request: SandboxProviderProbeRequest,
        readiness: SandboxProviderReadiness,
        reason: SandboxProviderReadinessReason,
        requirements: BTreeSet<SandboxProviderRequirement>,
        detail: DiagnosticText,
    ) -> Result<Self, ProviderProbeValidationError> {
        let report = Self {
            provider: request.provider,
            required_boundary: request.required_boundary,
            required_guarantees: request.required_guarantees,
            readiness,
            reason,
            requirements,
            detail,
        };
        report.validate()?;
        Ok(report)
    }

    #[must_use]
    pub const fn provider(&self) -> &SandboxProviderSelection {
        &self.provider
    }

    #[must_use]
    pub const fn required_boundary(&self) -> IsolationBoundary {
        self.required_boundary
    }

    #[must_use]
    pub const fn required_guarantees(&self) -> &BTreeSet<SandboxGuarantee> {
        &self.required_guarantees
    }

    #[must_use]
    pub const fn readiness(&self) -> SandboxProviderReadiness {
        self.readiness
    }

    #[must_use]
    pub const fn reason(&self) -> SandboxProviderReadinessReason {
        self.reason
    }

    #[must_use]
    pub const fn requirements(&self) -> &BTreeSet<SandboxProviderRequirement> {
        &self.requirements
    }

    #[must_use]
    pub const fn detail(&self) -> &DiagnosticText {
        &self.detail
    }

    fn validate(&self) -> Result<(), ProviderProbeValidationError> {
        SandboxProviderProbeRequest {
            provider: self.provider.clone(),
            required_boundary: self.required_boundary,
            required_guarantees: self.required_guarantees.clone(),
        }
        .validate()?;

        match self.readiness {
            SandboxProviderReadiness::ReadyForProvisioningAttempt => {
                if self.reason != SandboxProviderReadinessReason::ConfirmedByReadOnlyProbe {
                    return Err(ProviderProbeValidationError::InvalidReadyReason);
                }
                if !self.requirements.is_empty() {
                    return Err(ProviderProbeValidationError::ReadyHasRequirements);
                }
            }
            SandboxProviderReadiness::Unavailable | SandboxProviderReadiness::Indeterminate => {
                if self.reason == SandboxProviderReadinessReason::ConfirmedByReadOnlyProbe {
                    return Err(ProviderProbeValidationError::InvalidNotReadyReason);
                }
                validate_requirements(&self.requirements)?;
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxProviderReadinessReportWire {
    provider: SandboxProviderSelection,
    required_boundary: IsolationBoundary,
    required_guarantees: BTreeSet<SandboxGuarantee>,
    readiness: SandboxProviderReadiness,
    reason: SandboxProviderReadinessReason,
    requirements: BTreeSet<SandboxProviderRequirement>,
    detail: DiagnosticText,
}

impl<'de> Deserialize<'de> for SandboxProviderReadinessReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SandboxProviderReadinessReportWire::deserialize(deserializer)?;
        let request = SandboxProviderProbeRequest::new(
            wire.provider,
            wire.required_boundary,
            wire.required_guarantees,
        )
        .map_err(D::Error::custom)?;
        Self::new(
            request,
            wire.readiness,
            wire.reason,
            wire.requirements,
            wire.detail,
        )
        .map_err(D::Error::custom)
    }
}

fn report_not_ready(
    request: &SandboxProviderProbeRequest,
    readiness: SandboxProviderReadiness,
    reason: SandboxProviderReadinessReason,
    requirements: impl IntoIterator<Item = SandboxProviderRequirement>,
    detail: &'static str,
) -> SandboxProviderReadinessReport {
    SandboxProviderReadinessReport::new(
        request.clone(),
        readiness,
        reason,
        requirements.into_iter().collect(),
        diagnostic(detail),
    )
    .expect("static fail-closed report is valid")
}

fn validate_requirements(
    requirements: &BTreeSet<SandboxProviderRequirement>,
) -> Result<(), ProviderProbeValidationError> {
    if requirements.is_empty() {
        return Err(ProviderProbeValidationError::MissingRequirements);
    }
    if requirements.len() > MAX_PROBE_REQUIREMENTS {
        return Err(ProviderProbeValidationError::TooManyRequirements);
    }
    Ok(())
}

fn diagnostic(value: &'static str) -> DiagnosticText {
    DiagnosticText::new(value).expect("static provider diagnostic is bounded")
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderProbeValidationError {
    #[error("provider readiness requires at least one guarantee")]
    EmptyRequiredGuarantees,
    #[error("provider readiness exceeds the guarantee count limit")]
    TooManyGuarantees,
    #[error("a ready observation must include at least one observed guarantee")]
    EmptyObservedGuarantees,
    #[error("a non-ready result must identify at least one unresolved requirement")]
    MissingRequirements,
    #[error("provider readiness exceeds the requirement count limit")]
    TooManyRequirements,
    #[error("a ready result cannot carry unresolved requirements")]
    ReadyHasRequirements,
    #[error("a ready result requires a confirmed-by-read-only-probe reason")]
    InvalidReadyReason,
    #[error("a non-ready result cannot claim read-only-probe confirmation")]
    InvalidNotReadyReason,
    #[error(transparent)]
    InvalidProviderDescriptor(#[from] PolicyValidationError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct FakeProbeBackend {
        observation: ProviderProbeObservation,
    }

    impl SandboxProviderProbeBackend for FakeProbeBackend {
        fn probe(&self, _request: &SandboxProviderProbeRequest) -> ProviderProbeObservation {
            self.observation.clone()
        }
    }

    fn local_request() -> SandboxProviderProbeRequest {
        SandboxProviderProbeRequest::new(
            SandboxProviderSelection::LocalAppContainer,
            IsolationBoundary::UserMode,
            BTreeSet::from([
                SandboxGuarantee::FileSystemRedirection,
                SandboxGuarantee::NetworkDisabled,
            ]),
        )
        .expect("valid request")
    }

    fn ready_observation(provider: SandboxProviderSelection) -> ProviderProbeObservation {
        ProviderProbeObservation::ready(
            provider,
            IsolationBoundary::UserMode,
            BTreeSet::from([
                SandboxGuarantee::FileSystemRedirection,
                SandboxGuarantee::NetworkDisabled,
            ]),
            diagnostic("The fake backend observed every requested prerequisite."),
        )
        .expect("valid observation")
    }

    #[test]
    fn exact_fake_observation_allows_only_a_provisioning_attempt() {
        let service = SandboxProviderReadinessService::new(FakeProbeBackend {
            observation: ready_observation(SandboxProviderSelection::LocalAppContainer),
        });
        let report = service.probe(&local_request());

        assert_eq!(
            report.readiness(),
            SandboxProviderReadiness::ReadyForProvisioningAttempt
        );
        assert_eq!(
            report.reason(),
            SandboxProviderReadinessReason::ConfirmedByReadOnlyProbe
        );
        assert!(report.requirements().is_empty());
    }

    #[test]
    fn provider_identity_mismatch_fails_closed() {
        let observation = ProviderProbeObservation::ready(
            SandboxProviderSelection::WindowsSandbox,
            IsolationBoundary::Hypervisor,
            BTreeSet::from([
                SandboxGuarantee::FileSystemRedirection,
                SandboxGuarantee::NetworkDisabled,
            ]),
            diagnostic("The fake backend returned the wrong provider."),
        )
        .expect("valid observation");
        let service = SandboxProviderReadinessService::new(FakeProbeBackend { observation });
        let report = service.probe(&local_request());

        assert_eq!(report.readiness(), SandboxProviderReadiness::Indeterminate);
        assert_eq!(
            report.reason(),
            SandboxProviderReadinessReason::ProviderIdentityMismatch
        );
        assert!(
            report
                .requirements()
                .contains(&SandboxProviderRequirement::ExactProviderIdentity)
        );
    }

    #[test]
    fn missing_observed_guarantee_fails_closed() {
        let observation = ProviderProbeObservation::ready(
            SandboxProviderSelection::LocalAppContainer,
            IsolationBoundary::UserMode,
            BTreeSet::from([SandboxGuarantee::FileSystemRedirection]),
            diagnostic("The fake backend observed only one capability."),
        )
        .expect("valid observation");
        let service = SandboxProviderReadinessService::new(FakeProbeBackend { observation });
        let report = service.probe(&local_request());

        assert_eq!(report.readiness(), SandboxProviderReadiness::Indeterminate);
        assert_eq!(
            report.reason(),
            SandboxProviderReadinessReason::MissingRequiredGuarantees
        );
    }

    #[test]
    fn typed_backend_unavailability_is_preserved() {
        let observation = ProviderProbeObservation::unavailable(
            SandboxProviderSelection::LocalAppContainer,
            SandboxProviderReadinessReason::AdministrativePolicy,
            BTreeSet::from([SandboxProviderRequirement::AdministrativePolicyApproval]),
            diagnostic("Administrative policy blocks the provider."),
        )
        .expect("valid observation");
        let service = SandboxProviderReadinessService::new(FakeProbeBackend { observation });
        let report = service.probe(&local_request());

        assert_eq!(report.readiness(), SandboxProviderReadiness::Unavailable);
        assert_eq!(
            report.reason(),
            SandboxProviderReadinessReason::AdministrativePolicy
        );
    }

    #[test]
    fn system_probe_never_claims_provider_guarantees() {
        let report = SandboxProviderReadinessService::new(SystemSandboxProviderProbe)
            .probe(&local_request());

        assert_ne!(
            report.readiness(),
            SandboxProviderReadiness::ReadyForProvisioningAttempt
        );
        if cfg!(target_os = "windows") {
            assert_eq!(
                report.reason(),
                SandboxProviderReadinessReason::CapabilitiesUnverified
            );
            assert!(
                report
                    .requirements()
                    .contains(&SandboxProviderRequirement::AppContainerApiAvailability)
            );
        } else {
            assert_eq!(
                report.reason(),
                SandboxProviderReadinessReason::UnsupportedPlatform
            );
        }
    }

    #[test]
    fn serde_is_strict_and_revalidates_invariants() {
        let service = SandboxProviderReadinessService::new(FakeProbeBackend {
            observation: ready_observation(SandboxProviderSelection::LocalAppContainer),
        });
        let report = service.probe(&local_request());
        let mut value = serde_json::to_value(&report).expect("serialize report");
        value
            .as_object_mut()
            .expect("object")
            .insert("future-field".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<SandboxProviderReadinessReport>(value).is_err());

        let mut value = serde_json::to_value(&report).expect("serialize report");
        value.as_object_mut().expect("object").insert(
            "requirements".to_owned(),
            serde_json::json!([{
                "requirement": "stable-read-only-capability-probe"
            }]),
        );
        assert!(serde_json::from_value::<SandboxProviderReadinessReport>(value).is_err());

        let mut request = serde_json::to_value(local_request()).expect("serialize request");
        request
            .as_object_mut()
            .expect("object")
            .insert("unexpected".to_owned(), serde_json::json!(0));
        assert!(serde_json::from_value::<SandboxProviderProbeRequest>(request).is_err());
    }

    #[test]
    fn empty_requirement_sets_are_rejected() {
        assert_eq!(
            SandboxProviderProbeRequest::new(
                SandboxProviderSelection::LocalAppContainer,
                IsolationBoundary::UserMode,
                BTreeSet::new(),
            ),
            Err(ProviderProbeValidationError::EmptyRequiredGuarantees)
        );
        assert_eq!(
            ProviderProbeObservation::indeterminate(
                SandboxProviderSelection::LocalAppContainer,
                SandboxProviderReadinessReason::CapabilitiesUnverified,
                BTreeSet::new(),
                diagnostic("No requirements were provided."),
            ),
            Err(ProviderProbeValidationError::MissingRequirements)
        );
    }
}
