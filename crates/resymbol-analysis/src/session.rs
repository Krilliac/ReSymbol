use std::collections::BTreeMap;

use resymbol_core::{
    BinaryId, ClaimProducer, ClaimValidationError, GraphValidationError, SymbolAssertion,
    SymbolClaim, SymbolGraph, SymbolSubject,
    plugin_api::PluginId,
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
            validate_claim_ranges(index, claim, image_size)?;

            let ClaimProducer::Plugin {
                id: producer_id,
                version: producer_version,
            } = &claim.provenance().producer
            else {
                return Err(SessionValidationError::NonPluginProducer { index });
            };
            let run_id = claim.provenance().run_id.as_deref().ok_or(
                SessionValidationError::MissingRunId {
                    index,
                },
            )?;
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
            let actual = accepted_counts.get(run.run_id.as_str()).copied().unwrap_or(0);
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
        "plugin claim {index} range at RVA {rva:#x} with size {size:#x} exceeds image size {image_size:#x}"
    )]
    AddressOutsideImage {
        index: usize,
        rva: u64,
        size: u64,
        image_size: u64,
    },
    #[error("plugin claim {index} uses an unsupported subject kind")]
    UnsupportedSubject { index: usize },
    #[error("plugin claim {index} has a function-boundary assertion on a non-function subject")]
    FunctionBoundaryRequiresFunction { index: usize },
    #[error(
        "plugin claim {index} function size {subject_size:#x} does not match asserted boundary {boundary_size:#x}"
    )]
    FunctionBoundarySizeMismatch {
        index: usize,
        subject_size: u64,
        boundary_size: u64,
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
) -> Result<(), SessionValidationError> {
    match claim.subject() {
        SymbolSubject::Function { rva, size, .. } | SymbolSubject::Global { rva, size, .. } => {
            let size = size.unwrap_or(1);
            validate_image_range(index, *rva, size, image_size)?;
        }
        SymbolSubject::Type { .. } => {}
        _ => return Err(SessionValidationError::UnsupportedSubject { index }),
    }

    if let SymbolAssertion::FunctionBoundary {
        size: boundary_size,
    } = claim.assertion()
    {
        let SymbolSubject::Function {
            rva,
            size: subject_size,
            ..
        } = claim.subject()
        else {
            return Err(SessionValidationError::FunctionBoundaryRequiresFunction { index });
        };
        validate_image_range(index, *rva, *boundary_size, image_size)?;
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
    Ok(())
}

fn validate_image_range(
    index: usize,
    rva: u64,
    size: u64,
    image_size: u64,
) -> Result<(), SessionValidationError> {
    if rva >= image_size || rva.checked_add(size).is_none_or(|end| end > image_size) {
        return Err(SessionValidationError::AddressOutsideImage {
            index,
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
