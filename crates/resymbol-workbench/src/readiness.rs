//! Framework-independent model for the non-executing debugger/sandbox tab.

use std::collections::BTreeSet;

use resymbol_core::BinaryId;
use resymbol_debugger::{
    IsolationBoundary, ProviderProbeValidationError, SandboxGuarantee, SandboxProviderProbeRequest,
    SandboxProviderReadinessReport, SandboxProviderSelection,
};
use thiserror::Error;

use crate::model::{LoadedProject, ProtectionAssessment};

/// The three built-in providers users may inspect without activating them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum SandboxProviderChoice {
    #[default]
    LocalAppContainer,
    WindowsSandbox,
    HyperV,
}

impl SandboxProviderChoice {
    pub(crate) const ALL: [Self; 3] = [Self::LocalAppContainer, Self::WindowsSandbox, Self::HyperV];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::LocalAppContainer => "Local AppContainer",
            Self::WindowsSandbox => "Windows Sandbox",
            Self::HyperV => "Hyper-V",
        }
    }

    pub(crate) const fn boundary_label(self) -> &'static str {
        match self {
            Self::LocalAppContainer => "User mode / shared Windows kernel",
            Self::WindowsSandbox | Self::HyperV => "Hypervisor boundary",
        }
    }

    pub(crate) const fn selection(self) -> SandboxProviderSelection {
        match self {
            Self::LocalAppContainer => SandboxProviderSelection::LocalAppContainer,
            Self::WindowsSandbox => SandboxProviderSelection::WindowsSandbox,
            Self::HyperV => SandboxProviderSelection::HyperV,
        }
    }

    pub(crate) const fn boundary(self) -> IsolationBoundary {
        match self {
            Self::LocalAppContainer => IsolationBoundary::UserMode,
            Self::WindowsSandbox | Self::HyperV => IsolationBoundary::Hypervisor,
        }
    }

    pub(crate) fn required_guarantees(self) -> BTreeSet<SandboxGuarantee> {
        match self {
            Self::LocalAppContainer => BTreeSet::from([
                SandboxGuarantee::FileSystemRedirection,
                SandboxGuarantee::RegistryRedirection,
                SandboxGuarantee::RollbackOnClose,
                SandboxGuarantee::NetworkDisabled,
                SandboxGuarantee::ResourceLimits,
                SandboxGuarantee::ChildProcessControl,
                SandboxGuarantee::ProcessMitigations,
                SandboxGuarantee::JobAssignmentAtCreation,
            ]),
            Self::WindowsSandbox | Self::HyperV => BTreeSet::from([
                SandboxGuarantee::DisposableFileSystem,
                SandboxGuarantee::DisposableRegistry,
                SandboxGuarantee::RollbackOnClose,
                SandboxGuarantee::NetworkDisabled,
                SandboxGuarantee::ResourceLimits,
                SandboxGuarantee::ChildProcessControl,
                SandboxGuarantee::ProcessMitigations,
                SandboxGuarantee::JobAssignmentAtCreation,
                SandboxGuarantee::HypervisorBoundary,
            ]),
        }
    }

    pub(crate) fn probe_request(
        self,
    ) -> Result<SandboxProviderProbeRequest, ProviderProbeValidationError> {
        SandboxProviderProbeRequest::new(
            self.selection(),
            self.boundary(),
            self.required_guarantees(),
        )
    }
}

/// Static evidence snapshot to which one readiness observation is bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DebuggerReadinessEvidence {
    binary_id: BinaryId,
    file_size: u64,
    source_status: ReadinessSourceStatus,
    protection_status: ReadinessProtectionStatus,
}

impl DebuggerReadinessEvidence {
    pub(crate) fn from_project(project: &LoadedProject) -> Self {
        let source_status = if project.snapshot.has_verified_source() {
            ReadinessSourceStatus::ExactSourceVerified
        } else {
            ReadinessSourceStatus::PackageIdentityOnly
        };
        let protection_status = match &project.protection_assessment {
            ProtectionAssessment::Available(report) => ReadinessProtectionStatus::Available {
                findings: report.findings().len(),
                requires_acknowledgement: report.requires_acknowledgement(),
            },
            ProtectionAssessment::ExactSourceRequired => {
                ReadinessProtectionStatus::ExactSourceRequired
            }
            ProtectionAssessment::UnsupportedFormat => ReadinessProtectionStatus::UnsupportedFormat,
        };
        Self {
            binary_id: project.identity.sha256.clone(),
            file_size: project.identity.file_size,
            source_status,
            protection_status,
        }
    }

    pub(crate) fn matches_project(&self, project: &LoadedProject) -> bool {
        self == &Self::from_project(project)
    }

    pub(crate) const fn binary_id(&self) -> &BinaryId {
        &self.binary_id
    }

    pub(crate) const fn file_size(&self) -> u64 {
        self.file_size
    }

    pub(crate) const fn source_status(&self) -> ReadinessSourceStatus {
        self.source_status
    }

    pub(crate) const fn protection_status(&self) -> ReadinessProtectionStatus {
        self.protection_status
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadinessSourceStatus {
    ExactSourceVerified,
    PackageIdentityOnly,
}

impl ReadinessSourceStatus {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ExactSourceVerified => "Exact source bytes verified",
            Self::PackageIdentityOnly => "Package identity only; executable bytes unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadinessProtectionStatus {
    Available {
        findings: usize,
        requires_acknowledgement: bool,
    },
    ExactSourceRequired,
    UnsupportedFormat,
}

impl ReadinessProtectionStatus {
    pub(crate) fn label(self) -> String {
        match self {
            Self::Available {
                findings,
                requires_acknowledgement,
            } => format!(
                "Static scan available: {findings} finding(s){}",
                if requires_acknowledgement {
                    "; offline review required"
                } else {
                    ""
                }
            ),
            Self::ExactSourceRequired => {
                "Static protection scan requires exact source bytes".to_owned()
            }
            Self::UnsupportedFormat => {
                "Static protection scan is unsupported for this format".to_owned()
            }
        }
    }
}

/// One worker-produced readiness report bound to exact static project evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DebuggerReadinessOutcome {
    evidence: DebuggerReadinessEvidence,
    choice: SandboxProviderChoice,
    report: SandboxProviderReadinessReport,
}

impl DebuggerReadinessOutcome {
    pub(crate) fn new(
        evidence: DebuggerReadinessEvidence,
        choice: SandboxProviderChoice,
        report: SandboxProviderReadinessReport,
    ) -> Result<Self, DebuggerReadinessOutcomeError> {
        if report.provider() != &choice.selection() {
            return Err(DebuggerReadinessOutcomeError::Provider);
        }
        if report.required_boundary() != choice.boundary() {
            return Err(DebuggerReadinessOutcomeError::Boundary);
        }
        if report.required_guarantees() != &choice.required_guarantees() {
            return Err(DebuggerReadinessOutcomeError::Guarantees);
        }
        Ok(Self {
            evidence,
            choice,
            report,
        })
    }

    pub(crate) fn matches(&self, project: &LoadedProject, choice: SandboxProviderChoice) -> bool {
        self.choice == choice && self.evidence.matches_project(project)
    }

    pub(crate) const fn evidence(&self) -> &DebuggerReadinessEvidence {
        &self.evidence
    }

    pub(crate) const fn choice(&self) -> SandboxProviderChoice {
        self.choice
    }

    pub(crate) const fn report(&self) -> &SandboxProviderReadinessReport {
        &self.report
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum DebuggerReadinessOutcomeError {
    #[error("readiness report provider does not match the requested provider")]
    Provider,
    #[error("readiness report boundary does not match the requested provider")]
    Boundary,
    #[error("readiness report guarantees do not match the requested provider policy")]
    Guarantees,
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use resymbol_app::AppServices;
    use resymbol_debugger::{SandboxProviderReadinessService, SystemSandboxProviderProbe};
    use tempfile::NamedTempFile;

    use super::*;

    const STRIPPED_FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");

    fn project() -> LoadedProject {
        let mut source = NamedTempFile::new().expect("temporary PE");
        source.write_all(STRIPPED_FIXTURE).expect("write PE");
        let snapshot = AppServices::default()
            .analyze_binary(source.path())
            .expect("analyze fixture");
        LoadedProject::from_snapshot(snapshot).expect("loaded project")
    }

    #[test]
    fn built_in_choices_map_to_exact_providers_without_fallback() {
        let mappings = [
            (
                SandboxProviderChoice::LocalAppContainer,
                SandboxProviderSelection::LocalAppContainer,
                IsolationBoundary::UserMode,
            ),
            (
                SandboxProviderChoice::WindowsSandbox,
                SandboxProviderSelection::WindowsSandbox,
                IsolationBoundary::Hypervisor,
            ),
            (
                SandboxProviderChoice::HyperV,
                SandboxProviderSelection::HyperV,
                IsolationBoundary::Hypervisor,
            ),
        ];

        for (choice, provider, boundary) in mappings {
            let request = choice.probe_request().expect("valid built-in request");
            assert_eq!(request.provider(), &provider);
            assert_eq!(request.required_boundary(), boundary);
            assert!(!request.required_guarantees().is_empty());
        }
    }

    #[test]
    fn evidence_binds_source_and_protection_state_as_well_as_binary_identity() {
        let project = project();
        let evidence = DebuggerReadinessEvidence::from_project(&project);

        assert!(evidence.matches_project(&project));
        assert_eq!(evidence.binary_id(), &project.identity.sha256);
        assert_eq!(evidence.file_size(), project.identity.file_size);
        assert_eq!(
            evidence.source_status(),
            ReadinessSourceStatus::ExactSourceVerified
        );
        assert!(matches!(
            evidence.protection_status(),
            ReadinessProtectionStatus::Available { .. }
        ));
    }

    #[test]
    fn outcome_rejects_report_relabeling() {
        let project = project();
        let evidence = DebuggerReadinessEvidence::from_project(&project);
        let local = SandboxProviderChoice::LocalAppContainer;
        let request = local.probe_request().expect("request");
        let report =
            SandboxProviderReadinessService::new(SystemSandboxProviderProbe).probe(&request);

        assert_eq!(
            DebuggerReadinessOutcome::new(evidence, SandboxProviderChoice::WindowsSandbox, report,),
            Err(DebuggerReadinessOutcomeError::Provider)
        );
    }
}
