//! Framework-independent state used by the desktop workbench.
//!
//! The UI deliberately consumes the same validated analysis session and export
//! projection as the CLI.  This module adds presentation indexes and detail
//! records, but never reconciles claims independently or reorders the canonical
//! projection.

#[cfg(feature = "screenshot")]
use std::path::Path;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

use resymbol_analysis::{AnalysisSession, BinaryAnalysis, SessionValidationError};
use resymbol_app::{AppError, AppServices, ProjectSnapshot, ReviewSubject, ReviewValidationError};
use resymbol_core::{
    BinaryId, ClaimProducer, ControlFlowTarget, SymbolAssertion, SymbolClaim, SymbolSubject,
};
use resymbol_debugger::{
    ProtectionFinding, ProtectionReport, ProtectionScanError, StaticAddressSpace,
    StaticAddressSpaceError, scan_pe_protections,
};
use resymbol_export::{
    AttributedText, ExportAttribution, ExportBinaryFormat, ExportFunction, ExportProducer,
    ExportProjection, ProjectionValidationError,
};
use thiserror::Error;

/// Exact identity and address-space metadata for the active binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectIdentity {
    pub path: PathBuf,
    pub display_name: String,
    pub sha256: BinaryId,
    pub file_size: u64,
    pub format: ExportBinaryFormat,
    pub architecture: String,
    pub image_base: u64,
    pub image_size: u64,
}

/// Epistemic status shown independently from confidence and producer identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FunctionStatus {
    Conflict,
    Reviewed,
    Inferred,
    Extracted,
    EvidenceBacked,
    AutomaticFallback,
}

impl FunctionStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Conflict => "Conflict",
            Self::Reviewed => "Reviewed",
            Self::Inferred => "Inferred",
            Self::Extracted => "Extracted",
            Self::EvidenceBacked => "Evidence-backed",
            Self::AutomaticFallback => "Automatic fallback",
        }
    }
}

/// Stable producer identity retained without assigning it an epistemic status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProducerSource {
    Core { component: String, version: String },
    Plugin { id: String, version: String },
    User { reviewer: Option<String> },
}

impl ProducerSource {
    /// Compact producer label suitable for a table source column.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Core { component, version } => format!("{component} {version}"),
            Self::Plugin { id, version } => format!("{id} {version}"),
            Self::User {
                reviewer: Some(reviewer),
            } => format!("User: {reviewer}"),
            Self::User { reviewer: None } => "User review".to_owned(),
        }
    }

    #[must_use]
    const fn is_user(&self) -> bool {
        matches!(self, Self::User { .. })
    }
}

/// One selected or competing name with independent confidence and provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionNameCandidate {
    pub name: String,
    pub confidence: f64,
    pub producer: ProducerSource,
    pub method: String,
    pub run_id: Option<String>,
}

/// Stable row inventory. `projection_index` always addresses the canonical
/// `ExportProjection::functions` vector and is never changed by view sorting.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionRow {
    pub projection_index: usize,
    pub rva: u64,
    pub display_name: String,
    pub status: FunctionStatus,
    pub confidence: Option<f64>,
    pub source: String,
    pub size: Option<u64>,
    pub selected_name: Option<FunctionNameCandidate>,
    pub alternate_names: Vec<FunctionNameCandidate>,
}

/// Claim categories useful to the contextual inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionClaimKind {
    Name,
    Prototype,
    Boundary,
    Entry,
    DirectCall,
    ThunkTarget,
    DataReference,
    ClassMembership,
    Comment,
    Other,
}

/// One evidence card copied from the canonical combined graph.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceDetail {
    pub kind: String,
    pub summary: String,
    pub confidence: Option<f64>,
    pub artifacts: BTreeMap<String, String>,
}

/// One uncollapsed claim shown in the contextual inspector.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionClaimDetail {
    pub kind: FunctionClaimKind,
    pub value: String,
    pub subject_size: Option<u64>,
    pub confidence: f64,
    pub producer: ProducerSource,
    pub method: String,
    pub run_id: Option<String>,
    pub evidence: Vec<EvidenceDetail>,
    review_subject: Option<ReviewSubject>,
}

impl FunctionClaimDetail {
    /// Exact, fingerprinted review key for name claims. Other claim kinds are
    /// deliberately read-only until their own durable decision semantics exist.
    #[must_use]
    pub const fn review_subject(&self) -> Option<&ReviewSubject> {
        self.review_subject.as_ref()
    }
}

/// Inspector data for one canonical projection row.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDetail {
    pub projection_index: usize,
    pub rva: u64,
    pub claims: Vec<FunctionClaimDetail>,
}

/// Function table sort key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionSortKey {
    Rva,
    Name,
    Confidence,
    Source,
    Size,
}

/// Function table sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

/// Sort specification for a function-table view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionSort {
    pub key: FunctionSortKey,
    pub direction: SortDirection,
}

impl Default for FunctionSort {
    fn default() -> Self {
        Self {
            key: FunctionSortKey::Rva,
            direction: SortDirection::Ascending,
        }
    }
}

/// Search and multi-status filter for the function table. An empty status set
/// means all statuses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionFilter {
    pub search: String,
    pub statuses: BTreeSet<FunctionStatus>,
}

/// Result of the byte-dependent static protection scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionAssessment {
    /// The exact source bytes were retained and scanned.
    Available(ProtectionReport),
    /// A package can provide a static image layout without carrying executable
    /// bytes. The scan must remain unavailable until those bytes are verified.
    ExactSourceRequired,
    /// The open analysis format has no implemented protection scanner.
    UnsupportedFormat,
}

impl ProtectionAssessment {
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    #[must_use]
    pub fn findings(&self) -> &[ProtectionFinding] {
        match self {
            Self::Available(report) => report.findings(),
            Self::ExactSourceRequired | Self::UnsupportedFormat => &[],
        }
    }

    #[must_use]
    pub fn requires_acknowledgement(&self) -> bool {
        match self {
            Self::Available(report) => report.requires_acknowledgement(),
            Self::ExactSourceRequired | Self::UnsupportedFormat => false,
        }
    }

    #[must_use]
    pub const fn unavailable_reason(&self) -> Option<&'static str> {
        match self {
            Self::Available(_) => None,
            Self::ExactSourceRequired => {
                Some("Protection assessment unavailable until the exact source binary is verified")
            }
            Self::UnsupportedFormat => {
                Some("Protection assessment is not implemented for this binary format")
            }
        }
    }
}

/// Validated state for one open binary/package and its read-only workbench indexes.
#[derive(Debug)]
pub struct LoadedProject {
    pub snapshot: Arc<ProjectSnapshot>,
    pub identity: ProjectIdentity,
    pub projection: Arc<ExportProjection>,
    pub static_address_space: StaticAddressSpace,
    pub protection_assessment: ProtectionAssessment,
    pub functions: Vec<FunctionRow>,
    function_details: Vec<FunctionDetail>,
}

impl LoadedProject {
    /// Read and analyze an exact binary through the bounded application service.
    #[cfg(feature = "screenshot")]
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ModelError> {
        let snapshot = AppServices::default().analyze_binary(path)?;
        Self::from_snapshot(snapshot)
    }

    /// Build presentation indexes around one immutable application snapshot.
    pub fn from_snapshot(snapshot: Arc<ProjectSnapshot>) -> Result<Self, ModelError> {
        let projection = snapshot.projection_arc();
        Self::from_snapshot_with_projection(snapshot, projection)
    }

    /// Build presentation indexes around a reviewed projection of the same
    /// immutable project. Exact identity is rechecked before any UI state is
    /// constructed, so a stale or foreign worker result cannot be displayed.
    pub fn from_snapshot_with_projection(
        snapshot: Arc<ProjectSnapshot>,
        projection: Arc<ExportProjection>,
    ) -> Result<Self, ModelError> {
        snapshot.session().validate()?;
        projection.validate()?;
        let base_analysis = snapshot.session().base_analysis();
        let expected = base_analysis.identity();
        if projection.binary.id != expected.id || projection.binary.file_size != expected.size {
            return Err(ModelError::ProjectionIdentityMismatch {
                expected_sha256: expected.id.clone(),
                expected_size: expected.size,
                found_sha256: projection.binary.id.clone(),
                found_size: projection.binary.file_size,
            });
        }
        let static_address_space = StaticAddressSpace::from_analysis(base_analysis)?;
        let protection_assessment = match (base_analysis, snapshot.verified_source_bytes()) {
            (BinaryAnalysis::Pe(analysis), Some(bytes)) => {
                ProtectionAssessment::Available(scan_pe_protections(analysis, bytes)?)
            }
            (BinaryAnalysis::Pe(_), None) => ProtectionAssessment::ExactSourceRequired,
            (_, _) => ProtectionAssessment::UnsupportedFormat,
        };
        let combined_graph = snapshot.session().combined_symbol_graph()?;
        let (functions, function_details) =
            build_function_inventory(&projection.functions, combined_graph.claims())?;
        let binary = &projection.binary;
        let path = snapshot.origin_path().to_path_buf();
        let display_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("<memory>")
            .to_owned();
        let identity = ProjectIdentity {
            path,
            display_name,
            sha256: binary.id.clone(),
            file_size: binary.file_size,
            format: binary.format.clone(),
            architecture: binary.architecture.clone(),
            image_base: binary.image_base,
            image_size: binary.image_size,
        };

        Ok(Self {
            snapshot,
            identity,
            projection,
            static_address_space,
            protection_assessment,
            functions,
            function_details,
        })
    }

    /// Empty-plugin analysis session bound inside the current package.
    #[must_use]
    pub fn session(&self) -> &AnalysisSession {
        self.snapshot.session()
    }

    /// Inspector details for a canonical row index.
    #[must_use]
    pub fn function_detail(&self, projection_index: usize) -> Option<&FunctionDetail> {
        self.function_details.get(projection_index)
    }

    /// Produce view indexes without moving or mutating canonical rows.
    #[must_use]
    pub fn visible_function_indices(
        &self,
        filter: &FunctionFilter,
        sort: FunctionSort,
    ) -> Vec<usize> {
        visible_function_indices(&self.functions, filter, sort)
    }
}

/// Search, filter, and sort canonical row indexes without reordering `rows`.
#[must_use]
pub fn visible_function_indices(
    rows: &[FunctionRow],
    filter: &FunctionFilter,
    sort: FunctionSort,
) -> Vec<usize> {
    let normalized_search = filter.search.trim().to_lowercase();
    let mut indices = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row_matches_filter(row, filter, &normalized_search))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();

    indices.sort_by(|left_index, right_index| {
        let left = &rows[*left_index];
        let right = &rows[*right_index];
        let primary = compare_rows(left, right, sort.key);
        let directed = match sort.direction {
            SortDirection::Ascending => primary,
            SortDirection::Descending => primary.reverse(),
        };
        directed.then_with(|| left_index.cmp(right_index))
    });
    indices
}

fn row_matches_filter(row: &FunctionRow, filter: &FunctionFilter, normalized_search: &str) -> bool {
    if !filter.statuses.is_empty() && !filter.statuses.contains(&row.status) {
        return false;
    }
    if normalized_search.is_empty() {
        return true;
    }

    let rva = format!("{:#x}", row.rva);
    row.display_name.to_lowercase().contains(normalized_search)
        || row.source.to_lowercase().contains(normalized_search)
        || row
            .status
            .label()
            .to_lowercase()
            .contains(normalized_search)
        || rva.contains(normalized_search)
        || row
            .alternate_names
            .iter()
            .any(|alternate| alternate.name.to_lowercase().contains(normalized_search))
}

fn compare_rows(left: &FunctionRow, right: &FunctionRow, key: FunctionSortKey) -> Ordering {
    match key {
        FunctionSortKey::Rva => left.rva.cmp(&right.rva),
        FunctionSortKey::Name => compare_text(&left.display_name, &right.display_name),
        FunctionSortKey::Confidence => compare_optional_f64(left.confidence, right.confidence),
        FunctionSortKey::Source => compare_text(&left.source, &right.source),
        FunctionSortKey::Size => left.size.cmp(&right.size),
    }
}

fn compare_text(left: &str, right: &str) -> Ordering {
    left.to_lowercase()
        .cmp(&right.to_lowercase())
        .then_with(|| left.cmp(right))
}

fn compare_optional_f64(left: Option<f64>, right: Option<f64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.total_cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn build_function_inventory(
    projected_functions: &[ExportFunction],
    claims: &[SymbolClaim],
) -> Result<(Vec<FunctionRow>, Vec<FunctionDetail>), ReviewValidationError> {
    let mut claims_by_rva = BTreeMap::<u64, Vec<FunctionClaimDetail>>::new();
    for claim in claims {
        let SymbolSubject::Function { rva, size, .. } = claim.subject() else {
            continue;
        };
        claims_by_rva
            .entry(*rva)
            .or_default()
            .push(claim_detail(claim, *size)?);
    }

    let mut rows = Vec::with_capacity(projected_functions.len());
    let mut details = Vec::with_capacity(projected_functions.len());
    for (projection_index, function) in projected_functions.iter().enumerate() {
        let claims = claims_by_rva.remove(&function.rva).unwrap_or_default();
        let selected_name = function
            .selected_name
            .as_ref()
            .map(|name| name_candidate(&name.source));
        let alternate_names = function
            .alternate_names
            .iter()
            .map(name_candidate)
            .collect::<Vec<_>>();
        let status = derive_function_status(function, &claims);
        let primary_attribution = primary_attribution(function);
        let confidence = primary_attribution.map(|attribution| attribution.confidence);
        let source = primary_attribution.map_or_else(
            || "Automatic fallback".to_owned(),
            |attribution| producer_from_export(&attribution.provenance.producer).label(),
        );
        let display_name = selected_name.as_ref().map_or_else(
            || format!("sub_{:08x}", function.rva),
            |candidate| candidate.name.clone(),
        );

        rows.push(FunctionRow {
            projection_index,
            rva: function.rva,
            display_name,
            status,
            confidence,
            source,
            size: function.size,
            selected_name,
            alternate_names,
        });
        details.push(FunctionDetail {
            projection_index,
            rva: function.rva,
            claims,
        });
    }
    Ok((rows, details))
}

fn primary_attribution(function: &ExportFunction) -> Option<&ExportAttribution> {
    function
        .selected_name
        .as_ref()
        .map(|name| &name.source.attribution)
        .or(function.entry_attribution.as_ref())
        .or(function.size_attribution.as_ref())
}

fn name_candidate(value: &AttributedText) -> FunctionNameCandidate {
    FunctionNameCandidate {
        name: value.text.clone(),
        confidence: value.attribution.confidence,
        producer: producer_from_export(&value.attribution.provenance.producer),
        method: value.attribution.provenance.method.clone(),
        run_id: value.attribution.provenance.run_id.clone(),
    }
}

fn claim_detail(
    claim: &SymbolClaim,
    subject_size: Option<u64>,
) -> Result<FunctionClaimDetail, ReviewValidationError> {
    let (kind, value) = assertion_detail(claim.assertion());
    let review_subject = matches!(claim.assertion(), SymbolAssertion::Name { .. })
        .then(|| ReviewSubject::from_name_claim(claim))
        .transpose()?;
    Ok(FunctionClaimDetail {
        kind,
        value,
        subject_size,
        confidence: claim.confidence().get(),
        producer: producer_from_claim(&claim.provenance().producer),
        method: claim.provenance().method.clone(),
        run_id: claim.provenance().run_id.clone(),
        evidence: claim
            .evidence()
            .iter()
            .map(|evidence| EvidenceDetail {
                kind: evidence.kind.as_str().to_owned(),
                summary: evidence.summary.clone(),
                confidence: evidence.confidence.map(|confidence| confidence.get()),
                artifacts: evidence.artifacts.clone(),
            })
            .collect(),
        review_subject,
    })
}

fn assertion_detail(assertion: &SymbolAssertion) -> (FunctionClaimKind, String) {
    match assertion {
        SymbolAssertion::Name { name } => (FunctionClaimKind::Name, name.clone()),
        SymbolAssertion::FunctionPrototype { declaration } => {
            (FunctionClaimKind::Prototype, declaration.clone())
        }
        SymbolAssertion::FunctionBoundary { size } => {
            (FunctionClaimKind::Boundary, format!("{size:#x} bytes"))
        }
        SymbolAssertion::FunctionEntry => (FunctionClaimKind::Entry, "Function entry".to_owned()),
        SymbolAssertion::DirectCall {
            call_site_rva,
            target,
        } => (
            FunctionClaimKind::DirectCall,
            format!(
                "call at {call_site_rva:#x} to {}",
                control_flow_target_label(target)
            ),
        ),
        SymbolAssertion::ThunkTarget { target } => (
            FunctionClaimKind::ThunkTarget,
            format!("thunk to {}", control_flow_target_label(target)),
        ),
        SymbolAssertion::DataReference {
            instruction_rva,
            instruction_size,
            target_rva,
        } => (
            FunctionClaimKind::DataReference,
            format!(
                "{instruction_size}-byte instruction at {instruction_rva:#x} references {target_rva:#x}"
            ),
        ),
        SymbolAssertion::ClassMembership { class_name } => {
            (FunctionClaimKind::ClassMembership, class_name.clone())
        }
        SymbolAssertion::Comment { text } => (FunctionClaimKind::Comment, text.clone()),
        _ => (FunctionClaimKind::Other, format!("{assertion:?}")),
    }
}

fn control_flow_target_label(target: &ControlFlowTarget) -> String {
    match target {
        ControlFlowTarget::Function { rva } => format!("function {rva:#x}"),
        ControlFlowTarget::ImportIat { iat_rva } => format!("import slot {iat_rva:#x}"),
        ControlFlowTarget::FunctionPointer { slot_rva, rva } => {
            format!("function {rva:#x} through slot {slot_rva:#x}")
        }
        _ => format!("{target:?}"),
    }
}

fn derive_function_status(
    function: &ExportFunction,
    claims: &[FunctionClaimDetail],
) -> FunctionStatus {
    if function.selected_name.as_ref().is_some_and(|name| {
        matches!(
            &name.source.attribution.provenance.producer,
            ExportProducer::User { .. }
        )
    }) {
        return FunctionStatus::Reviewed;
    }
    if !function.alternate_names.is_empty() {
        return FunctionStatus::Conflict;
    }

    let Some(selected_name) = function
        .selected_name
        .as_ref()
        .map(|name| name.source.text.as_str())
    else {
        return FunctionStatus::AutomaticFallback;
    };
    let selected_claims = claims.iter().filter(|claim| {
        claim.kind == FunctionClaimKind::Name && claim.value.as_str() == selected_name
    });
    let selected_claims = selected_claims.collect::<Vec<_>>();

    if selected_claims.iter().any(|claim| {
        claim.producer.is_user()
            || claim
                .evidence
                .iter()
                .any(|evidence| evidence.kind == "user-confirmed")
    }) {
        return FunctionStatus::Reviewed;
    }
    if selected_claims.iter().any(|claim| {
        claim
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "model-inference")
    }) {
        return FunctionStatus::Inferred;
    }
    if selected_claims.iter().any(|claim| {
        claim
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "metadata")
    }) {
        return FunctionStatus::Extracted;
    }
    FunctionStatus::EvidenceBacked
}

fn producer_from_claim(producer: &ClaimProducer) -> ProducerSource {
    match producer {
        ClaimProducer::Core { component, version } => ProducerSource::Core {
            component: component.clone(),
            version: version.clone(),
        },
        ClaimProducer::Plugin { id, version } => ProducerSource::Plugin {
            id: id.as_str().to_owned(),
            version: version.clone(),
        },
        ClaimProducer::User { reviewer } => ProducerSource::User {
            reviewer: reviewer.clone(),
        },
        _ => ProducerSource::Core {
            component: "unknown".to_owned(),
            version: "unknown".to_owned(),
        },
    }
}

fn producer_from_export(producer: &ExportProducer) -> ProducerSource {
    match producer {
        ExportProducer::Core { component, version } => ProducerSource::Core {
            component: component.clone(),
            version: version.clone(),
        },
        ExportProducer::Plugin { id, version } => ProducerSource::Plugin {
            id: id.clone(),
            version: version.clone(),
        },
        ExportProducer::User { reviewer } => ProducerSource::User {
            reviewer: reviewer.clone(),
        },
        _ => ProducerSource::Core {
            component: "unknown".to_owned(),
            version: "unknown".to_owned(),
        },
    }
}

/// Workbench model construction failure.
#[derive(Debug, Error)]
pub enum ModelError {
    #[error("application service failed: {0}")]
    App(#[from] AppError),
    #[error("analysis session is invalid: {0}")]
    Session(#[from] SessionValidationError),
    #[error("static address-space analysis failed: {0}")]
    StaticAddressSpace(#[from] StaticAddressSpaceError),
    #[error("protection assessment failed: {0}")]
    Protection(#[from] ProtectionScanError),
    #[error("review subject construction failed: {0}")]
    Review(#[from] ReviewValidationError),
    #[error("reviewed export projection is invalid: {0}")]
    Projection(#[from] ProjectionValidationError),
    #[error(
        "reviewed projection identity mismatch: expected {expected_sha256}/{expected_size} bytes, found {found_sha256}/{found_size} bytes"
    )]
    ProjectionIdentityMismatch {
        expected_sha256: BinaryId,
        expected_size: u64,
        found_sha256: BinaryId,
        found_size: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use resymbol_export::ExportProvenance;
    use std::io::Write as _;
    use tempfile::{NamedTempFile, tempdir};

    const STRIPPED_FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");

    fn loaded_fixture(bytes: &[u8]) -> LoadedProject {
        let mut source = NamedTempFile::new().expect("temporary PE");
        source.write_all(bytes).expect("write temporary PE");
        let snapshot = AppServices::default()
            .analyze_binary(source.path())
            .expect("service-backed fixture analysis");
        LoadedProject::from_snapshot(snapshot).expect("fixture model")
    }

    fn producer() -> ProducerSource {
        ProducerSource::Core {
            component: "test".to_owned(),
            version: "0.1.0".to_owned(),
        }
    }

    fn row(
        projection_index: usize,
        rva: u64,
        name: &str,
        status: FunctionStatus,
        confidence: f64,
        source: &str,
        size: Option<u64>,
    ) -> FunctionRow {
        FunctionRow {
            projection_index,
            rva,
            display_name: name.to_owned(),
            status,
            confidence: Some(confidence),
            source: source.to_owned(),
            size,
            selected_name: Some(FunctionNameCandidate {
                name: name.to_owned(),
                confidence,
                producer: producer(),
                method: "test".to_owned(),
                run_id: None,
            }),
            alternate_names: Vec::new(),
        }
    }

    fn export_function(name: Option<&str>, alternate: bool) -> ExportFunction {
        let attribution = ExportAttribution {
            confidence: 1.0,
            provenance: ExportProvenance {
                producer: ExportProducer::Core {
                    component: "test".to_owned(),
                    version: "0.1.0".to_owned(),
                },
                method: "test".to_owned(),
                run_id: None,
            },
        };
        let attributed = |text: &str| AttributedText {
            text: text.to_owned(),
            attribution: attribution.clone(),
        };
        ExportFunction {
            rva: 0x1000,
            entry_attribution: Some(attribution.clone()),
            size: Some(0x20),
            size_attribution: None,
            selected_name: name.map(|name| resymbol_export::ExportName {
                source: attributed(name),
                output_name: name.to_owned(),
            }),
            alternate_names: alternate
                .then(|| attributed("alternate"))
                .into_iter()
                .collect(),
            prototypes: Vec::new(),
            class_memberships: Vec::new(),
        }
    }

    fn name_claim(
        name: &str,
        confidence: f64,
        producer: ProducerSource,
        evidence_kind: &str,
    ) -> FunctionClaimDetail {
        FunctionClaimDetail {
            kind: FunctionClaimKind::Name,
            value: name.to_owned(),
            subject_size: None,
            confidence,
            producer,
            method: "test".to_owned(),
            run_id: Some("run-1".to_owned()),
            evidence: vec![EvidenceDetail {
                kind: evidence_kind.to_owned(),
                summary: "test evidence".to_owned(),
                confidence: Some(confidence),
                artifacts: BTreeMap::new(),
            }],
            review_subject: None,
        }
    }

    #[test]
    fn checked_in_fixture_builds_one_bound_shared_model() {
        let project = loaded_fixture(STRIPPED_FIXTURE);

        assert_eq!(
            &project.identity.sha256,
            project.snapshot.package().binary_sha256()
        );
        assert_eq!(
            project.static_address_space.binary_id,
            project.identity.sha256
        );
        let ProtectionAssessment::Available(report) = &project.protection_assessment else {
            panic!("an exact source must receive a protection assessment");
        };
        assert_eq!(report.binary_id, project.identity.sha256);
        project
            .snapshot
            .package()
            .ensure_payload_binding()
            .expect("package binding");
        assert!(project.session().plugin_runs().is_empty());
        assert!(project.session().plugin_claims().is_empty());
        assert_eq!(project.functions.len(), project.projection.functions.len());
        assert!(!project.functions.is_empty());
        for (index, row) in project.functions.iter().enumerate() {
            assert_eq!(row.projection_index, index);
            assert_eq!(row.rva, project.projection.functions[index].rva);
            assert_eq!(
                project.function_detail(index).map(|detail| detail.rva),
                Some(row.rva)
            );
            if let Some(detail) = project.function_detail(index) {
                for claim in &detail.claims {
                    assert_eq!(
                        claim.review_subject().is_some(),
                        claim.kind == FunctionClaimKind::Name,
                        "only exact name claims should expose review subjects"
                    );
                }
            }
        }
    }

    #[test]
    fn reviewed_model_rejects_a_foreign_projection_identity() {
        let project = loaded_fixture(STRIPPED_FIXTURE);
        let snapshot = Arc::clone(&project.snapshot);
        let mut projection = project.projection.as_ref().clone();
        projection.binary.id = BinaryId::digest(b"foreign-reviewed-projection");

        assert!(matches!(
            LoadedProject::from_snapshot_with_projection(snapshot, Arc::new(projection)),
            Err(ModelError::ProjectionIdentityMismatch { .. })
        ));
    }

    #[test]
    fn package_without_verified_source_reports_protection_unavailability() {
        let directory = tempdir().expect("temporary project directory");
        let source_path = directory.path().join("fixture.exe");
        std::fs::write(&source_path, STRIPPED_FIXTURE).expect("write fixture PE");
        let services = AppServices::default();
        let analyzed = services
            .analyze_binary(&source_path)
            .expect("analyze exact source");
        let package_path = directory.path().join("fixture.resym");
        services
            .save_package_new(&analyzed, &package_path)
            .expect("save package");
        let package_only = services
            .open_package(&package_path)
            .expect("open package without source");

        let project = LoadedProject::from_snapshot(package_only).expect("package model");

        assert!(matches!(
            &project.protection_assessment,
            ProtectionAssessment::ExactSourceRequired
        ));
        assert!(project.protection_assessment.findings().is_empty());
        assert!(
            !project.protection_assessment.requires_acknowledgement(),
            "an unavailable offline scan must not block ordinary package inspection"
        );
        assert!(project.protection_assessment.unavailable_reason().is_some());
        assert!(!project.snapshot.has_verified_source());
        assert_eq!(
            project.static_address_space.binary_id,
            project.identity.sha256
        );
    }

    #[test]
    fn filtering_and_sorting_return_stable_indexes_without_mutating_rows() {
        let rows = vec![
            row(
                0,
                0x3000,
                "Zulu",
                FunctionStatus::Extracted,
                0.9,
                "core-b",
                Some(32),
            ),
            row(
                1,
                0x1000,
                "alpha",
                FunctionStatus::Conflict,
                0.7,
                "core-a",
                None,
            ),
            row(
                2,
                0x2000,
                "Alpha",
                FunctionStatus::Conflict,
                0.8,
                "core-a",
                Some(64),
            ),
        ];
        let original = rows.clone();
        let filter = FunctionFilter {
            search: "alpha".to_owned(),
            statuses: BTreeSet::from([FunctionStatus::Conflict]),
        };

        assert_eq!(
            visible_function_indices(
                &rows,
                &filter,
                FunctionSort {
                    key: FunctionSortKey::Name,
                    direction: SortDirection::Ascending,
                },
            ),
            vec![2, 1]
        );
        assert_eq!(rows, original);
        assert_eq!(
            visible_function_indices(
                &rows,
                &FunctionFilter::default(),
                FunctionSort {
                    key: FunctionSortKey::Confidence,
                    direction: SortDirection::Descending,
                },
            ),
            vec![0, 2, 1]
        );
    }

    #[test]
    fn statuses_follow_semantics_not_confidence_or_plugin_origin() {
        let plugin = ProducerSource::Plugin {
            id: "dev.example.plugin".to_owned(),
            version: "1.0.0".to_owned(),
        };
        let high_confidence = vec![name_claim("name", 1.0, plugin.clone(), "signature-match")];
        assert_eq!(
            derive_function_status(&export_function(Some("name"), false), &high_confidence),
            FunctionStatus::EvidenceBacked
        );

        let extracted = vec![name_claim("name", 0.5, plugin, "metadata")];
        assert_eq!(
            derive_function_status(&export_function(Some("name"), false), &extracted),
            FunctionStatus::Extracted
        );
        let inferred = vec![name_claim("name", 0.99, producer(), "model-inference")];
        assert_eq!(
            derive_function_status(&export_function(Some("name"), false), &inferred),
            FunctionStatus::Inferred
        );
        let reviewed = vec![name_claim(
            "name",
            0.6,
            ProducerSource::User {
                reviewer: Some("analyst".to_owned()),
            },
            "user-confirmed",
        )];
        assert_eq!(
            derive_function_status(&export_function(Some("name"), false), &reviewed),
            FunctionStatus::Reviewed
        );
        assert_eq!(
            derive_function_status(&export_function(Some("name"), true), &reviewed),
            FunctionStatus::Conflict
        );
        assert_eq!(
            derive_function_status(&export_function(None, false), &[]),
            FunctionStatus::AutomaticFallback
        );
    }
}
