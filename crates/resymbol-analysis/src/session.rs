use std::collections::{BTreeMap, BTreeSet};

use resymbol_core::{
    BinaryId, ClaimProducer, ClaimValidationError, ControlFlowTarget, GraphValidationError,
    StringEncoding, SymbolAssertion, SymbolClaim, SymbolGraph, SymbolSubject, plugin_api::PluginId,
};
use semver::Version;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{AnalysisError, BinaryAnalysis};

const MAX_PLUGIN_VERSION_BYTES: usize = 128;
const MAX_RUN_ID_BYTES: usize = 128;
const SHA256_HEX_BYTES: usize = 64;

/// Terminal outcome recorded for one isolated plugin execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginRunStatus {
    Succeeded,
    Failed,
}

impl PluginRunStatus {
    #[must_use]
    pub const fn is_successful(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

/// Auditable identity and outcome for one plugin execution.
///
/// `artifact_sha256` fingerprints the exact plugin artifact that produced the
/// run. It is deliberately separate from the analyzed binary's identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginRunRecord {
    plugin_id: PluginId,
    plugin_version: String,
    run_id: String,
    artifact_sha256: String,
    status: PluginRunStatus,
    accepted_claim_count: u64,
}

impl PluginRunRecord {
    pub fn new(
        plugin_id: PluginId,
        plugin_version: impl Into<String>,
        run_id: impl Into<String>,
        artifact_sha256: impl Into<String>,
        status: PluginRunStatus,
        accepted_claim_count: u64,
    ) -> Result<Self, SessionValidationError> {
        let record = Self {
            plugin_id,
            plugin_version: plugin_version.into(),
            run_id: run_id.into(),
            artifact_sha256: artifact_sha256.into(),
            status,
            accepted_claim_count,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validate the run's canonical identity and internally consistent outcome.
    pub fn validate(&self) -> Result<(), SessionValidationError> {
        if !is_canonical_text(&self.plugin_version, MAX_PLUGIN_VERSION_BYTES) {
            return Err(SessionValidationError::InvalidPluginVersion);
        }
        let Ok(version) = Version::parse(&self.plugin_version) else {
            return Err(SessionValidationError::InvalidPluginVersion);
        };
        if version.to_string() != self.plugin_version {
            return Err(SessionValidationError::InvalidPluginVersion);
        }
        if !is_canonical_text(&self.run_id, MAX_RUN_ID_BYTES) {
            return Err(SessionValidationError::InvalidRunId);
        }
        if !is_canonical_sha256(&self.artifact_sha256) {
            return Err(SessionValidationError::InvalidPluginFingerprint);
        }
        if !self.status.is_successful() && self.accepted_claim_count != 0 {
            return Err(SessionValidationError::FailedRunAcceptedClaims {
                run_id: self.run_id.clone(),
                count: self.accepted_claim_count,
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    #[must_use]
    pub const fn status(&self) -> PluginRunStatus {
        self.status
    }

    #[must_use]
    pub const fn accepted_claim_count(&self) -> u64 {
        self.accepted_claim_count
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPluginRunRecord {
    plugin_id: PluginId,
    plugin_version: String,
    run_id: String,
    artifact_sha256: String,
    status: PluginRunStatus,
    accepted_claim_count: u64,
}

impl<'de> Deserialize<'de> for PluginRunRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let record = UncheckedPluginRunRecord::deserialize(deserializer)?;
        Self::new(
            record.plugin_id,
            record.plugin_version,
            record.run_id,
            record.artifact_sha256,
            record.status,
            record.accepted_claim_count,
        )
        .map_err(D::Error::custom)
    }
}

/// One exact binary analysis plus validated claims produced by plugin runs.
///
/// Plugin claims remain outside `base_analysis`. This preserves the PE
/// analysis invariant that its embedded graph is derived solely from exact PE
/// metadata, while [`Self::combined_symbol_graph`] provides the append-only
/// view used by later reconciliation and export stages.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AnalysisSession {
    base_analysis: BinaryAnalysis,
    plugin_runs: Vec<PluginRunRecord>,
    plugin_claims: Vec<SymbolClaim>,
}

impl AnalysisSession {
    pub fn new(
        base_analysis: BinaryAnalysis,
        plugin_runs: Vec<PluginRunRecord>,
        plugin_claims: Vec<SymbolClaim>,
    ) -> Result<Self, SessionValidationError> {
        let session = Self {
            base_analysis,
            plugin_runs,
            plugin_claims,
        };
        session.validate()?;
        Ok(session)
    }

    /// Validate run identity, claim provenance, binary binding, image ranges,
    /// and the per-run accepted-claim ledger.
    pub fn validate(&self) -> Result<(), SessionValidationError> {
        self.base_analysis
            .validate()
            .map_err(SessionValidationError::InvalidBaseAnalysis)?;

        let mut runs_by_id = BTreeMap::<&str, &PluginRunRecord>::new();
        for run in &self.plugin_runs {
            run.validate()?;
            if runs_by_id.insert(run.run_id.as_str(), run).is_some() {
                return Err(SessionValidationError::DuplicateRunId {
                    run_id: run.run_id.clone(),
                });
            }
        }

        let mut accepted_counts = BTreeMap::<&str, u64>::new();
        let expected_binary = &self.base_analysis.identity().id;
        let image_size = self.base_analysis.image_size();
        let import_iat_rvas = import_iat_rvas(&self.base_analysis);

        for (index, claim) in self.plugin_claims.iter().enumerate() {
            claim
                .validate()
                .map_err(|source| SessionValidationError::InvalidPluginClaim { index, source })?;

            let found_binary = claim.subject().binary();
            if found_binary != expected_binary {
                return Err(SessionValidationError::WrongBinary {
                    index,
                    expected: expected_binary.clone(),
                    found: found_binary.clone(),
                });
            }
            validate_claim_ranges(index, claim, image_size, &import_iat_rvas)?;
            validate_claim_section_policy(index, claim, &self.base_analysis)?;

            let ClaimProducer::Plugin {
                id: producer_id,
                version: producer_version,
            } = &claim.provenance().producer
            else {
                return Err(SessionValidationError::NonPluginProducer { index });
            };
            let run_id = claim
                .provenance()
                .run_id
                .as_deref()
                .ok_or(SessionValidationError::MissingRunId { index })?;
            let run = runs_by_id.get(run_id).copied().ok_or_else(|| {
                SessionValidationError::UnknownRun {
                    index,
                    run_id: run_id.to_owned(),
                }
            })?;
            if !run.status.is_successful() {
                return Err(SessionValidationError::UnsuccessfulRun {
                    index,
                    run_id: run_id.to_owned(),
                });
            }
            if producer_id != &run.plugin_id || producer_version != &run.plugin_version {
                return Err(SessionValidationError::ProducerRunMismatch {
                    index,
                    run_id: run_id.to_owned(),
                });
            }

            let count = accepted_counts.entry(run_id).or_default();
            *count = count
                .checked_add(1)
                .ok_or(SessionValidationError::AcceptedClaimCountOverflow)?;
        }

        for run in &self.plugin_runs {
            let actual = accepted_counts
                .get(run.run_id.as_str())
                .copied()
                .unwrap_or(0);
            if run.accepted_claim_count != actual {
                return Err(SessionValidationError::AcceptedClaimCountMismatch {
                    run_id: run.run_id.clone(),
                    recorded: run.accepted_claim_count,
                    actual,
                });
            }
        }

        Ok(())
    }

    #[must_use]
    pub const fn base_analysis(&self) -> &BinaryAnalysis {
        &self.base_analysis
    }

    #[must_use]
    pub fn plugin_runs(&self) -> &[PluginRunRecord] {
        &self.plugin_runs
    }

    #[must_use]
    pub fn plugin_claims(&self) -> &[SymbolClaim] {
        &self.plugin_claims
    }

    /// Return the deterministic base graph followed by validated plugin claims
    /// in their recorded order.
    pub fn combined_symbol_graph(&self) -> Result<SymbolGraph, SessionValidationError> {
        self.validate()?;
        let mut graph = self.base_analysis.symbol_graph().clone();
        for claim in &self.plugin_claims {
            graph
                .submit_claim(claim.clone())
                .map_err(SessionValidationError::CombinedGraph)?;
        }
        Ok(graph)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedAnalysisSession {
    base_analysis: BinaryAnalysis,
    plugin_runs: Vec<PluginRunRecord>,
    plugin_claims: Vec<SymbolClaim>,
}

impl<'de> Deserialize<'de> for AnalysisSession {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let session = UncheckedAnalysisSession::deserialize(deserializer)?;
        Self::new(
            session.base_analysis,
            session.plugin_runs,
            session.plugin_claims,
        )
        .map_err(D::Error::custom)
    }
}

/// Failure to validate a persisted or newly assembled analysis session.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionValidationError {
    #[error("base analysis is invalid: {0}")]
    InvalidBaseAnalysis(#[source] AnalysisError),
    #[error("plugin version must be canonical SemVer text of 1..=128 bytes")]
    InvalidPluginVersion,
    #[error("plugin run id must be canonical non-control text of 1..=128 bytes")]
    InvalidRunId,
    #[error("plugin artifact fingerprint must be exactly 64 lowercase hexadecimal characters")]
    InvalidPluginFingerprint,
    #[error("failed plugin run `{run_id}` records {count} accepted claim(s)")]
    FailedRunAcceptedClaims { run_id: String, count: u64 },
    #[error("plugin run id `{run_id}` is duplicated")]
    DuplicateRunId { run_id: String },
    #[error("plugin claim {index} is invalid: {source}")]
    InvalidPluginClaim {
        index: usize,
        #[source]
        source: ClaimValidationError,
    },
    #[error("plugin claim {index} targets binary {found}, expected {expected}")]
    WrongBinary {
        index: usize,
        expected: BinaryId,
        found: BinaryId,
    },
    #[error(
        "plugin claim {index} {field} range at RVA {rva:#x} with size {size:#x} exceeds image size {image_size:#x}"
    )]
    AddressOutsideImage {
        index: usize,
        field: &'static str,
        rva: u64,
        size: u64,
        image_size: u64,
    },
    #[error("plugin claim {index} uses an unsupported subject kind")]
    UnsupportedSubject { index: usize },
    #[error("plugin claim {index} has a function-boundary assertion on a non-function subject")]
    FunctionBoundaryRequiresFunction { index: usize },
    #[error("plugin claim {index} has a function-entry assertion on a non-function subject")]
    FunctionEntryRequiresFunction { index: usize },
    #[error("plugin claim {index} has a direct-call assertion on a non-function subject")]
    DirectCallRequiresFunction { index: usize },
    #[error("plugin claim {index} has a thunk-target assertion on a non-function subject")]
    ThunkTargetRequiresFunction { index: usize },
    #[error("plugin claim {index} has a string-literal assertion on a non-global subject")]
    StringLiteralRequiresGlobal { index: usize },
    #[error("plugin claim {index} string-literal subject must record its exact encoded size")]
    StringLiteralRequiresSize { index: usize },
    #[error(
        "plugin claim {index} global size {subject_size:#x} does not match encoded string size {encoded_size:#x}"
    )]
    StringLiteralSizeMismatch {
        index: usize,
        subject_size: u64,
        encoded_size: u64,
    },
    #[error("plugin claim {index} uses an unsupported recovered-string encoding")]
    UnsupportedStringEncoding { index: usize },
    #[error("plugin claim {index} encoded string size overflows the supported address model")]
    EncodedStringSizeOverflow { index: usize },
    #[error(
        "plugin claim {index} string literal is not fully backed readable initialized non-executable PE data"
    )]
    StringLiteralUnsupportedSection { index: usize },
    #[error("plugin claim {index} has a data-reference assertion on a non-function subject")]
    DataReferenceRequiresFunction { index: usize },
    #[error(
        "plugin claim {index} data-reference instruction size {instruction_size} is not a valid x64 instruction size"
    )]
    DataReferenceInstructionSizeUnsupported { index: usize, instruction_size: u8 },
    #[error(
        "plugin claim {index} data-reference instruction {instruction_rva:#x} precedes caller function {function_rva:#x}"
    )]
    DataReferenceSiteBeforeFunction {
        index: usize,
        instruction_rva: u64,
        function_rva: u64,
    },
    #[error(
        "plugin claim {index} data-reference instruction {instruction_rva:#x} lies outside caller range {function_rva:#x}..{function_end_rva:#x}"
    )]
    DataReferenceSiteOutsideFunction {
        index: usize,
        instruction_rva: u64,
        function_rva: u64,
        function_end_rva: u64,
    },
    #[error("plugin claim {index} data-reference instruction is not backed by executable PE data")]
    DataReferenceSourceNotExecutable { index: usize },
    #[error(
        "plugin claim {index} data-reference target is not backed by readable initialized non-executable PE data"
    )]
    DataReferenceTargetNotData { index: usize },
    #[error(
        "plugin claim {index} function size {subject_size:#x} does not match asserted boundary {boundary_size:#x}"
    )]
    FunctionBoundarySizeMismatch {
        index: usize,
        subject_size: u64,
        boundary_size: u64,
    },
    #[error(
        "plugin claim {index} direct-call site {call_site_rva:#x} precedes caller function {function_rva:#x}"
    )]
    DirectCallSiteBeforeFunction {
        index: usize,
        call_site_rva: u64,
        function_rva: u64,
    },
    #[error(
        "plugin claim {index} direct-call site {call_site_rva:#x} lies outside caller range {function_rva:#x}..{function_end_rva:#x}"
    )]
    DirectCallSiteOutsideFunction {
        index: usize,
        call_site_rva: u64,
        function_rva: u64,
        function_end_rva: u64,
    },
    #[error("plugin claim {index} thunk at {rva:#x} targets itself as an internal function")]
    ThunkSelfTarget { index: usize, rva: u64 },
    #[error(
        "plugin claim {index} {assertion} targets import-IAT RVA {iat_rva:#x}, which is not present in the parsed PE imports"
    )]
    UnknownImportIatTarget {
        index: usize,
        assertion: &'static str,
        iat_rva: u64,
    },
    #[error("plugin claim {index} provenance is not plugin-owned")]
    NonPluginProducer { index: usize },
    #[error("plugin claim {index} provenance has no run id")]
    MissingRunId { index: usize },
    #[error("plugin claim {index} references unknown run `{run_id}`")]
    UnknownRun { index: usize, run_id: String },
    #[error("plugin claim {index} references unsuccessful run `{run_id}`")]
    UnsuccessfulRun { index: usize, run_id: String },
    #[error("plugin claim {index} producer does not match run `{run_id}`")]
    ProducerRunMismatch { index: usize, run_id: String },
    #[error("accepted plugin claim count overflowed")]
    AcceptedClaimCountOverflow,
    #[error(
        "plugin run `{run_id}` records {recorded} accepted claim(s), but the session contains {actual}"
    )]
    AcceptedClaimCountMismatch {
        run_id: String,
        recorded: u64,
        actual: u64,
    },
    #[error("combined symbol graph is invalid: {0}")]
    CombinedGraph(#[source] GraphValidationError),
}

fn validate_claim_ranges(
    index: usize,
    claim: &SymbolClaim,
    image_size: u64,
    import_iat_rvas: &BTreeSet<u64>,
) -> Result<(), SessionValidationError> {
    match claim.subject() {
        SymbolSubject::Function { rva, size, .. } | SymbolSubject::Global { rva, size, .. } => {
            let size = size.unwrap_or(1);
            validate_image_range(index, "subject", *rva, size, image_size)?;
        }
        SymbolSubject::Type { .. } => {}
        _ => return Err(SessionValidationError::UnsupportedSubject { index }),
    }

    match claim.assertion() {
        SymbolAssertion::FunctionBoundary {
            size: boundary_size,
        } => {
            let SymbolSubject::Function {
                rva,
                size: subject_size,
                ..
            } = claim.subject()
            else {
                return Err(SessionValidationError::FunctionBoundaryRequiresFunction { index });
            };
            validate_image_range(index, "function boundary", *rva, *boundary_size, image_size)?;
            if let Some(subject_size) = subject_size {
                if subject_size != boundary_size {
                    return Err(SessionValidationError::FunctionBoundarySizeMismatch {
                        index,
                        subject_size: *subject_size,
                        boundary_size: *boundary_size,
                    });
                }
            }
        }
        SymbolAssertion::FunctionEntry => {
            if !matches!(claim.subject(), SymbolSubject::Function { .. }) {
                return Err(SessionValidationError::FunctionEntryRequiresFunction { index });
            }
        }
        SymbolAssertion::DirectCall {
            call_site_rva,
            target,
        } => {
            let SymbolSubject::Function {
                rva: function_rva,
                size: function_size,
                ..
            } = claim.subject()
            else {
                return Err(SessionValidationError::DirectCallRequiresFunction { index });
            };
            validate_image_range(index, "direct-call site", *call_site_rva, 1, image_size)?;
            if *call_site_rva < *function_rva {
                return Err(SessionValidationError::DirectCallSiteBeforeFunction {
                    index,
                    call_site_rva: *call_site_rva,
                    function_rva: *function_rva,
                });
            }
            if let Some(function_size) = function_size {
                let function_end_rva = function_rva.checked_add(*function_size).ok_or(
                    SessionValidationError::AddressOutsideImage {
                        index,
                        field: "caller function",
                        rva: *function_rva,
                        size: *function_size,
                        image_size,
                    },
                )?;
                if *call_site_rva >= function_end_rva {
                    return Err(SessionValidationError::DirectCallSiteOutsideFunction {
                        index,
                        call_site_rva: *call_site_rva,
                        function_rva: *function_rva,
                        function_end_rva,
                    });
                }
            }
            let target_field = if target.is_function() {
                "direct-call function target"
            } else {
                "direct-call import-IAT target"
            };
            validate_image_range(index, target_field, target.rva(), 1, image_size)?;
            validate_import_iat_target(index, "direct-call assertion", target, import_iat_rvas)?;
        }
        SymbolAssertion::ThunkTarget { target } => {
            let SymbolSubject::Function {
                rva: function_rva, ..
            } = claim.subject()
            else {
                return Err(SessionValidationError::ThunkTargetRequiresFunction { index });
            };
            let target_field = if target.is_function() {
                "thunk function target"
            } else {
                "thunk import-IAT target"
            };
            validate_image_range(index, target_field, target.rva(), 1, image_size)?;
            validate_import_iat_target(index, "thunk-target assertion", target, import_iat_rvas)?;
            if target.is_function_at(*function_rva) {
                return Err(SessionValidationError::ThunkSelfTarget {
                    index,
                    rva: *function_rva,
                });
            }
        }
        SymbolAssertion::StringLiteral { encoding, value } => {
            let SymbolSubject::Global {
                rva,
                size: subject_size,
                ..
            } = claim.subject()
            else {
                return Err(SessionValidationError::StringLiteralRequiresGlobal { index });
            };
            let Some(subject_size) = subject_size else {
                return Err(SessionValidationError::StringLiteralRequiresSize { index });
            };
            let encoded_size = encoded_string_size(index, *encoding, value)?;
            validate_image_range(index, "string literal", *rva, encoded_size, image_size)?;
            if *subject_size != encoded_size {
                return Err(SessionValidationError::StringLiteralSizeMismatch {
                    index,
                    subject_size: *subject_size,
                    encoded_size,
                });
            }
        }
        SymbolAssertion::DataReference {
            instruction_rva,
            instruction_size,
            target_rva,
        } => {
            let SymbolSubject::Function {
                rva: function_rva,
                size: function_size,
                ..
            } = claim.subject()
            else {
                return Err(SessionValidationError::DataReferenceRequiresFunction { index });
            };
            if !(1..=15).contains(instruction_size) {
                return Err(
                    SessionValidationError::DataReferenceInstructionSizeUnsupported {
                        index,
                        instruction_size: *instruction_size,
                    },
                );
            }
            validate_image_range(
                index,
                "data-reference instruction",
                *instruction_rva,
                u64::from(*instruction_size),
                image_size,
            )?;
            validate_image_range(index, "data-reference target", *target_rva, 1, image_size)?;
            if *instruction_rva < *function_rva {
                return Err(SessionValidationError::DataReferenceSiteBeforeFunction {
                    index,
                    instruction_rva: *instruction_rva,
                    function_rva: *function_rva,
                });
            }
            if let Some(function_size) = function_size {
                let function_end_rva = function_rva.checked_add(*function_size).ok_or(
                    SessionValidationError::AddressOutsideImage {
                        index,
                        field: "data-reference caller function",
                        rva: *function_rva,
                        size: *function_size,
                        image_size,
                    },
                )?;
                let instruction_end_rva = instruction_rva
                    .checked_add(u64::from(*instruction_size))
                    .ok_or(SessionValidationError::AddressOutsideImage {
                        index,
                        field: "data-reference instruction",
                        rva: *instruction_rva,
                        size: u64::from(*instruction_size),
                        image_size,
                    })?;
                if instruction_end_rva > function_end_rva {
                    return Err(SessionValidationError::DataReferenceSiteOutsideFunction {
                        index,
                        instruction_rva: *instruction_rva,
                        function_rva: *function_rva,
                        function_end_rva,
                    });
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn encoded_string_size(
    index: usize,
    encoding: StringEncoding,
    value: &str,
) -> Result<u64, SessionValidationError> {
    match encoding {
        StringEncoding::Ascii => u64::try_from(value.len())
            .ok()
            .and_then(|size| size.checked_add(1)),
        StringEncoding::Utf16Le => u64::try_from(value.encode_utf16().count())
            .ok()
            .and_then(|units| units.checked_mul(2))
            .and_then(|size| size.checked_add(2)),
        _ => return Err(SessionValidationError::UnsupportedStringEncoding { index }),
    }
    .ok_or(SessionValidationError::EncodedStringSizeOverflow { index })
}

fn validate_claim_section_policy(
    index: usize,
    claim: &SymbolClaim,
    analysis: &BinaryAnalysis,
) -> Result<(), SessionValidationError> {
    let BinaryAnalysis::Pe(analysis) = analysis;
    match claim.assertion() {
        SymbolAssertion::StringLiteral { .. } => {
            let SymbolSubject::Global {
                rva,
                size: Some(size),
                ..
            } = claim.subject()
            else {
                return Ok(());
            };
            let (Ok(rva), Ok(size)) = (u32::try_from(*rva), u32::try_from(*size)) else {
                return Err(SessionValidationError::StringLiteralUnsupportedSection { index });
            };
            if !crate::code_recovery::model_range_is_backed_readable_initialized_data(
                analysis, rva, size,
            ) {
                return Err(SessionValidationError::StringLiteralUnsupportedSection { index });
            }
        }
        SymbolAssertion::DataReference {
            instruction_rva,
            instruction_size,
            target_rva,
        } => {
            let (Ok(instruction_rva), Ok(target_rva)) =
                (u32::try_from(*instruction_rva), u32::try_from(*target_rva))
            else {
                return Err(SessionValidationError::DataReferenceSourceNotExecutable { index });
            };
            if !crate::code_recovery::model_range_is_backed_executable(
                analysis,
                instruction_rva,
                u32::from(*instruction_size),
            ) {
                return Err(SessionValidationError::DataReferenceSourceNotExecutable { index });
            }
            if !crate::code_recovery::model_range_is_backed_readable_initialized_data(
                analysis, target_rva, 1,
            ) {
                return Err(SessionValidationError::DataReferenceTargetNotData { index });
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_import_iat_target(
    index: usize,
    assertion: &'static str,
    target: &ControlFlowTarget,
    import_iat_rvas: &BTreeSet<u64>,
) -> Result<(), SessionValidationError> {
    if let ControlFlowTarget::ImportIat { iat_rva } = target {
        if !import_iat_rvas.contains(iat_rva) {
            return Err(SessionValidationError::UnknownImportIatTarget {
                index,
                assertion,
                iat_rva: *iat_rva,
            });
        }
    }
    Ok(())
}

fn import_iat_rvas(analysis: &BinaryAnalysis) -> BTreeSet<u64> {
    match analysis {
        BinaryAnalysis::Pe(analysis) => analysis
            .imports
            .iter()
            .flat_map(|library| library.entries.iter())
            .map(|entry| u64::from(entry.iat_rva))
            .collect(),
    }
}

fn validate_image_range(
    index: usize,
    field: &'static str,
    rva: u64,
    size: u64,
    image_size: u64,
) -> Result<(), SessionValidationError> {
    if rva >= image_size || rva.checked_add(size).is_none_or(|end| end > image_size) {
        return Err(SessionValidationError::AddressOutsideImage {
            index,
            field,
            rva,
            size,
            image_size,
        });
    }
    Ok(())
}

fn is_canonical_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use resymbol_core::{
        BinaryId, ClaimProvenance, Confidence, Evidence, EvidenceKind, SymbolAssertion,
        SymbolClaim, SymbolSubject,
    };

    use super::{
        SessionValidationError, validate_claim_ranges as validate_claim_ranges_with_imports,
    };

    fn validate_claim_ranges(
        index: usize,
        claim: &SymbolClaim,
        image_size: u64,
    ) -> Result<(), SessionValidationError> {
        validate_claim_ranges_with_imports(
            index,
            claim,
            image_size,
            &BTreeSet::from([0x100, 0x300]),
        )
    }

    fn assertion(value: serde_json::Value) -> SymbolAssertion {
        serde_json::from_value(value).expect("valid control-flow assertion")
    }

    fn claim(subject: SymbolSubject, assertion: SymbolAssertion) -> SymbolClaim {
        SymbolClaim::new(
            subject,
            assertion,
            Confidence::new(0.9).expect("valid confidence"),
            vec![
                Evidence::new(
                    EvidenceKind::new(EvidenceKind::CONTROL_FLOW).expect("valid evidence kind"),
                    "decoded control-flow relationship",
                )
                .expect("valid evidence"),
            ],
            ClaimProvenance {
                producer: resymbol_core::ClaimProducer::Core {
                    component: "session-test".to_owned(),
                    version: "0.1.0".to_owned(),
                },
                method: "unit-test".to_owned(),
                run_id: None,
            },
        )
        .expect("valid claim")
    }

    fn function_subject(rva: u64, size: Option<u64>) -> SymbolSubject {
        SymbolSubject::Function {
            binary: BinaryId::digest(b"session-test-binary"),
            rva,
            size,
        }
    }

    fn global_subject() -> SymbolSubject {
        SymbolSubject::Global {
            binary: BinaryId::digest(b"session-test-binary"),
            rva: 0x100,
            size: Some(0x20),
        }
    }

    #[test]
    fn control_flow_assertions_require_function_subjects() {
        let entry = claim(
            global_subject(),
            assertion(serde_json::json!({"kind": "function-entry"})),
        );
        assert!(matches!(
            validate_claim_ranges(0, &entry, 0x400),
            Err(SessionValidationError::FunctionEntryRequiresFunction { index: 0 })
        ));

        let direct_call = claim(
            global_subject(),
            assertion(serde_json::json!({
                "kind": "direct-call",
                "call_site_rva": 0x110,
                "target": {"kind": "function", "rva": 0x200}
            })),
        );
        assert!(matches!(
            validate_claim_ranges(1, &direct_call, 0x400),
            Err(SessionValidationError::DirectCallRequiresFunction { index: 1 })
        ));

        let thunk = claim(
            SymbolSubject::Type {
                binary: BinaryId::digest(b"session-test-binary"),
                key: "type-key".to_owned(),
            },
            assertion(serde_json::json!({
                "kind": "thunk-target",
                "target": {"kind": "import-iat", "iat_rva": 0x300}
            })),
        );
        assert!(matches!(
            validate_claim_ranges(2, &thunk, 0x400),
            Err(SessionValidationError::ThunkTargetRequiresFunction { index: 2 })
        ));
    }

    #[test]
    fn direct_call_sites_must_belong_to_the_caller_when_its_size_is_known() {
        let before = claim(
            function_subject(0x100, Some(0x20)),
            assertion(serde_json::json!({
                "kind": "direct-call",
                "call_site_rva": 0xff,
                "target": {"kind": "function", "rva": 0x200}
            })),
        );
        assert!(matches!(
            validate_claim_ranges(0, &before, 0x400),
            Err(SessionValidationError::DirectCallSiteBeforeFunction {
                call_site_rva: 0xff,
                function_rva: 0x100,
                ..
            })
        ));

        let at_end = claim(
            function_subject(0x100, Some(0x20)),
            assertion(serde_json::json!({
                "kind": "direct-call",
                "call_site_rva": 0x120,
                "target": {"kind": "function", "rva": 0x200}
            })),
        );
        assert!(matches!(
            validate_claim_ranges(1, &at_end, 0x400),
            Err(SessionValidationError::DirectCallSiteOutsideFunction {
                call_site_rva: 0x120,
                function_rva: 0x100,
                function_end_rva: 0x120,
                ..
            })
        ));

        let last_byte = claim(
            function_subject(0x100, Some(0x20)),
            assertion(serde_json::json!({
                "kind": "direct-call",
                "call_site_rva": 0x11f,
                "target": {"kind": "function", "rva": 0x200}
            })),
        );
        validate_claim_ranges(2, &last_byte, 0x400).expect("last caller byte is in range");

        let unbounded = claim(
            function_subject(0x100, None),
            assertion(serde_json::json!({
                "kind": "direct-call",
                "call_site_rva": 0x300,
                "target": {"kind": "function", "rva": 0x200}
            })),
        );
        validate_claim_ranges(3, &unbounded, 0x400)
            .expect("an unbounded caller only constrains the lower call-site address");
    }

    #[test]
    fn control_flow_sites_and_targets_must_lie_inside_the_image() {
        let outside_site = claim(
            function_subject(0x100, None),
            assertion(serde_json::json!({
                "kind": "direct-call",
                "call_site_rva": 0x400,
                "target": {"kind": "function", "rva": 0x200}
            })),
        );
        assert!(matches!(
            validate_claim_ranges(0, &outside_site, 0x400),
            Err(SessionValidationError::AddressOutsideImage {
                field: "direct-call site",
                rva: 0x400,
                ..
            })
        ));

        let outside_function_target = claim(
            function_subject(0x100, None),
            assertion(serde_json::json!({
                "kind": "direct-call",
                "call_site_rva": 0x110,
                "target": {"kind": "function", "rva": 0x400}
            })),
        );
        assert!(matches!(
            validate_claim_ranges(1, &outside_function_target, 0x400),
            Err(SessionValidationError::AddressOutsideImage {
                field: "direct-call function target",
                rva: 0x400,
                ..
            })
        ));

        let outside_iat_target = claim(
            function_subject(0x100, Some(1)),
            assertion(serde_json::json!({
                "kind": "thunk-target",
                "target": {"kind": "import-iat", "iat_rva": 0x400}
            })),
        );
        assert!(matches!(
            validate_claim_ranges(2, &outside_iat_target, 0x400),
            Err(SessionValidationError::AddressOutsideImage {
                field: "thunk import-IAT target",
                rva: 0x400,
                ..
            })
        ));
    }

    #[test]
    fn internal_thunks_cannot_target_themselves() {
        let self_target = claim(
            function_subject(0x100, Some(6)),
            assertion(serde_json::json!({
                "kind": "thunk-target",
                "target": {"kind": "function", "rva": 0x100}
            })),
        );
        assert!(matches!(
            validate_claim_ranges(0, &self_target, 0x400),
            Err(SessionValidationError::ThunkSelfTarget {
                index: 0,
                rva: 0x100
            })
        ));

        let other_function = claim(
            function_subject(0x100, Some(6)),
            assertion(serde_json::json!({
                "kind": "thunk-target",
                "target": {"kind": "function", "rva": 0x200}
            })),
        );
        validate_claim_ranges(1, &other_function, 0x400)
            .expect("an internal thunk may target another function");

        let same_numeric_iat = claim(
            function_subject(0x100, Some(6)),
            assertion(serde_json::json!({
                "kind": "thunk-target",
                "target": {"kind": "import-iat", "iat_rva": 0x100}
            })),
        );
        validate_claim_ranges(2, &same_numeric_iat, 0x400)
            .expect("self-target rejection applies only to internal functions");
    }

    #[test]
    fn import_iat_targets_must_match_a_parsed_import_slot() {
        let unknown_direct_call_iat = claim(
            function_subject(0x100, Some(0x20)),
            assertion(serde_json::json!({
                "kind": "direct-call",
                "call_site_rva": 0x110,
                "target": {"kind": "import-iat", "iat_rva": 0x350}
            })),
        );
        assert!(matches!(
            validate_claim_ranges(0, &unknown_direct_call_iat, 0x400),
            Err(SessionValidationError::UnknownImportIatTarget {
                index: 0,
                assertion: "direct-call assertion",
                iat_rva: 0x350,
            })
        ));

        let unknown_thunk_iat = claim(
            function_subject(0x100, Some(6)),
            assertion(serde_json::json!({
                "kind": "thunk-target",
                "target": {"kind": "import-iat", "iat_rva": 0x350}
            })),
        );
        assert!(matches!(
            validate_claim_ranges(1, &unknown_thunk_iat, 0x400),
            Err(SessionValidationError::UnknownImportIatTarget {
                index: 1,
                assertion: "thunk-target assertion",
                iat_rva: 0x350,
            })
        ));

        let exact_iat = claim(
            function_subject(0x100, Some(6)),
            assertion(serde_json::json!({
                "kind": "thunk-target",
                "target": {"kind": "import-iat", "iat_rva": 0x300}
            })),
        );
        validate_claim_ranges(2, &exact_iat, 0x400)
            .expect("an exact parsed import-IAT slot is accepted");
    }

    #[test]
    fn string_literals_require_an_exactly_sized_global_subject() {
        let binary = BinaryId::digest(b"session-test-binary");
        let valid_ascii = claim(
            SymbolSubject::Global {
                binary: binary.clone(),
                rva: 0x100,
                size: Some(6),
            },
            assertion(serde_json::json!({
                "kind": "string-literal",
                "encoding": "ascii",
                "value": "Hello"
            })),
        );
        validate_claim_ranges(0, &valid_ascii, 0x400).expect("ASCII size includes one NUL byte");

        let valid_utf16 = claim(
            SymbolSubject::Global {
                binary: binary.clone(),
                rva: 0x120,
                size: Some(10),
            },
            assertion(serde_json::json!({
                "kind": "string-literal",
                "encoding": "utf-16-le",
                "value": "Ab世界"
            })),
        );
        validate_claim_ranges(1, &valid_utf16, 0x400)
            .expect("UTF-16 size includes its two-byte NUL terminator");

        let missing_size = claim(
            SymbolSubject::Global {
                binary: binary.clone(),
                rva: 0x140,
                size: None,
            },
            assertion(serde_json::json!({
                "kind": "string-literal",
                "encoding": "ascii",
                "value": "Hello"
            })),
        );
        assert!(matches!(
            validate_claim_ranges(2, &missing_size, 0x400),
            Err(SessionValidationError::StringLiteralRequiresSize { index: 2 })
        ));

        let wrong_size = claim(
            SymbolSubject::Global {
                binary: binary.clone(),
                rva: 0x160,
                size: Some(5),
            },
            assertion(serde_json::json!({
                "kind": "string-literal",
                "encoding": "ascii",
                "value": "Hello"
            })),
        );
        assert!(matches!(
            validate_claim_ranges(3, &wrong_size, 0x400),
            Err(SessionValidationError::StringLiteralSizeMismatch {
                subject_size: 5,
                encoded_size: 6,
                ..
            })
        ));

        let wrong_subject = claim(
            function_subject(0x180, Some(6)),
            assertion(serde_json::json!({
                "kind": "string-literal",
                "encoding": "ascii",
                "value": "Hello"
            })),
        );
        assert!(matches!(
            validate_claim_ranges(4, &wrong_subject, 0x400),
            Err(SessionValidationError::StringLiteralRequiresGlobal { index: 4 })
        ));
    }

    #[test]
    fn data_reference_sites_belong_to_function_subjects_and_targets_stay_in_image() {
        let valid = claim(
            function_subject(0x100, Some(0x20)),
            assertion(serde_json::json!({
                "kind": "data-reference",
                "instruction_rva": 0x110,
                "instruction_size": 7,
                "target_rva": 0x300
            })),
        );
        validate_claim_ranges(0, &valid, 0x400).expect("bounded data reference is valid");

        let wrong_subject = claim(
            global_subject(),
            assertion(serde_json::json!({
                "kind": "data-reference",
                "instruction_rva": 0x110,
                "instruction_size": 7,
                "target_rva": 0x300
            })),
        );
        assert!(matches!(
            validate_claim_ranges(1, &wrong_subject, 0x400),
            Err(SessionValidationError::DataReferenceRequiresFunction { index: 1 })
        ));

        let before = claim(
            function_subject(0x100, Some(0x20)),
            assertion(serde_json::json!({
                "kind": "data-reference",
                "instruction_rva": 0xff,
                "instruction_size": 7,
                "target_rva": 0x300
            })),
        );
        assert!(matches!(
            validate_claim_ranges(2, &before, 0x400),
            Err(SessionValidationError::DataReferenceSiteBeforeFunction { .. })
        ));

        let at_end = claim(
            function_subject(0x100, Some(0x20)),
            assertion(serde_json::json!({
                "kind": "data-reference",
                "instruction_rva": 0x120,
                "instruction_size": 7,
                "target_rva": 0x300
            })),
        );
        assert!(matches!(
            validate_claim_ranges(3, &at_end, 0x400),
            Err(SessionValidationError::DataReferenceSiteOutsideFunction { .. })
        ));

        let unsupported_instruction_size = claim(
            function_subject(0x100, Some(0x20)),
            assertion(serde_json::json!({
                "kind": "data-reference",
                "instruction_rva": 0x110,
                "instruction_size": 16,
                "target_rva": 0x300
            })),
        );
        assert!(matches!(
            validate_claim_ranges(4, &unsupported_instruction_size, 0x400),
            Err(
                SessionValidationError::DataReferenceInstructionSizeUnsupported {
                    index: 4,
                    instruction_size: 16,
                }
            )
        ));

        let outside_target = claim(
            function_subject(0x100, None),
            assertion(serde_json::json!({
                "kind": "data-reference",
                "instruction_rva": 0x110,
                "instruction_size": 7,
                "target_rva": 0x400
            })),
        );
        assert!(matches!(
            validate_claim_ranges(5, &outside_target, 0x400),
            Err(SessionValidationError::AddressOutsideImage {
                field: "data-reference target",
                ..
            })
        ));
    }
}
