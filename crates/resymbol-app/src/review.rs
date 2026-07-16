use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use resymbol_analysis::{AnalysisSession, BinaryAnalysis, SessionValidationError};
use resymbol_core::{
    BinaryId, BinaryIdentity, ClaimProducer, ClaimProvenance, ClaimValidationError, Confidence,
    Evidence, EvidenceKind, GraphValidationError, SymbolAssertion, SymbolClaim, SymbolGraph,
    SymbolSubject,
};
use resymbol_export::{ExportError, ExportProjection};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use tempfile::Builder;
use thiserror::Error;

/// Current schema for a persisted ReSymbol review sidecar.
pub const REVIEW_LEDGER_SCHEMA_VERSION: u32 = 1;

/// Maximum retained undo/redo entries in one sidecar.
pub const MAX_REVIEW_DECISIONS: usize = 262_144;

/// Maximum encoded JSON bytes accepted for one review sidecar.
pub const MAX_REVIEW_SIDECAR_BYTES: u64 = 128 * 1024 * 1024;

/// Maximum UTF-8 bytes accepted for one reviewer identity.
pub const MAX_REVIEWER_BYTES: usize = 1_024;

/// Maximum UTF-8 bytes accepted for one review annotation or rationale.
pub const MAX_REVIEW_ANNOTATION_BYTES: usize = 16_384;
const REVIEW_ACCEPT_METHOD: &str = "review.accept";

/// A stable logical key for one exact name claim.
///
/// The SHA-256 is computed over canonical `serde_json` serialization of the
/// complete validated [`SymbolClaim`]. Struct field order is fixed by the core
/// schema and evidence artifact maps are ordered, so confidence, evidence, and
/// provenance drift produces an orphan instead of inheriting an old decision.
/// Semantic fields remain alongside the fingerprint for display and lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewSubject {
    claim_sha256: BinaryId,
    symbol: SymbolSubject,
    name: String,
    producer: ClaimProducer,
    method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
}

impl ReviewSubject {
    /// Build an exact review key from a name claim.
    pub fn from_name_claim(claim: &SymbolClaim) -> Result<Self, ReviewValidationError> {
        let SymbolAssertion::Name { name } = claim.assertion() else {
            return Err(ReviewValidationError::NotNameClaim);
        };
        let canonical_claim = serde_json::to_vec(claim)
            .map_err(ReviewValidationError::ClaimFingerprintSerialization)?;
        let subject = Self {
            claim_sha256: BinaryId::digest(&canonical_claim),
            symbol: claim.subject().clone(),
            name: name.clone(),
            producer: claim.provenance().producer.clone(),
            method: claim.provenance().method.clone(),
            run_id: claim.provenance().run_id.clone(),
        };
        subject.validate()?;
        Ok(subject)
    }

    #[must_use]
    pub const fn claim_sha256(&self) -> &BinaryId {
        &self.claim_sha256
    }

    #[must_use]
    pub const fn symbol(&self) -> &SymbolSubject {
        &self.symbol
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn producer(&self) -> &ClaimProducer {
        &self.producer
    }

    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
    }

    fn validate(&self) -> Result<(), ReviewValidationError> {
        // Reconstruct a harmless claim to reuse the core's canonical subject,
        // assertion, producer, and provenance validation instead of creating a
        // second set of subtly different rules in the UI layer.
        let evidence = Evidence::new(
            EvidenceKind::new(EvidenceKind::USER_CONFIRMED)
                .map_err(ReviewValidationError::InvalidReviewSubject)?,
            "Review sidecar subject validation",
        )
        .map_err(ReviewValidationError::InvalidReviewSubject)?;
        SymbolClaim::new(
            self.symbol.clone(),
            SymbolAssertion::Name {
                name: self.name.clone(),
            },
            Confidence::new(1.0).map_err(ReviewValidationError::InvalidReviewSubject)?,
            vec![evidence],
            ClaimProvenance {
                producer: self.producer.clone(),
                method: self.method.clone(),
                run_id: self.run_id.clone(),
            },
        )
        .map_err(ReviewValidationError::InvalidReviewSubject)?;
        self.canonical_key()?;
        Ok(())
    }

    fn canonical_key(&self) -> Result<String, ReviewValidationError> {
        let mut key = String::new();
        push_key_part(&mut key, self.claim_sha256.as_str());
        match &self.symbol {
            SymbolSubject::Function { binary, rva, size } => {
                push_key_part(&mut key, "function");
                push_key_part(&mut key, binary.as_str());
                push_key_part(&mut key, &rva.to_string());
                push_optional_u64(&mut key, *size);
            }
            SymbolSubject::Global { binary, rva, size } => {
                push_key_part(&mut key, "global");
                push_key_part(&mut key, binary.as_str());
                push_key_part(&mut key, &rva.to_string());
                push_optional_u64(&mut key, *size);
            }
            SymbolSubject::Type {
                binary,
                key: type_key,
            } => {
                push_key_part(&mut key, "type");
                push_key_part(&mut key, binary.as_str());
                push_key_part(&mut key, type_key);
            }
            _ => return Err(ReviewValidationError::UnsupportedSubject),
        }
        push_key_part(&mut key, &self.name);
        match &self.producer {
            ClaimProducer::Core { component, version } => {
                push_key_part(&mut key, "core");
                push_key_part(&mut key, component);
                push_key_part(&mut key, version);
            }
            ClaimProducer::Plugin { id, version } => {
                push_key_part(&mut key, "plugin");
                push_key_part(&mut key, id.as_str());
                push_key_part(&mut key, version);
            }
            ClaimProducer::User { reviewer } => {
                push_key_part(&mut key, "user");
                push_optional_str(&mut key, reviewer.as_deref());
            }
            _ => return Err(ReviewValidationError::UnsupportedProducer),
        }
        push_key_part(&mut key, &self.method);
        push_optional_str(&mut key, self.run_id.as_deref());
        Ok(key)
    }

    fn entity_key(&self) -> Result<String, ReviewValidationError> {
        let mut key = String::new();
        match &self.symbol {
            SymbolSubject::Function { binary, rva, size } => {
                push_key_part(&mut key, "function");
                push_key_part(&mut key, binary.as_str());
                push_key_part(&mut key, &rva.to_string());
                push_optional_u64(&mut key, *size);
            }
            SymbolSubject::Global { binary, rva, size } => {
                push_key_part(&mut key, "global");
                push_key_part(&mut key, binary.as_str());
                push_key_part(&mut key, &rva.to_string());
                push_optional_u64(&mut key, *size);
            }
            SymbolSubject::Type {
                binary,
                key: type_key,
            } => {
                push_key_part(&mut key, "type");
                push_key_part(&mut key, binary.as_str());
                push_key_part(&mut key, type_key);
            }
            _ => return Err(ReviewValidationError::UnsupportedSubject),
        }
        Ok(key)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedReviewSubject {
    claim_sha256: BinaryId,
    symbol: SymbolSubject,
    name: String,
    producer: ClaimProducer,
    method: String,
    #[serde(default)]
    run_id: Option<String>,
}

impl<'de> Deserialize<'de> for ReviewSubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedReviewSubject::deserialize(deserializer)?;
        let subject = Self {
            claim_sha256: value.claim_sha256,
            symbol: value.symbol,
            name: value.name,
            producer: value.producer,
            method: value.method,
            run_id: value.run_id,
        };
        subject.validate().map_err(D::Error::custom)?;
        Ok(subject)
    }
}

/// User action recorded in the ordered review history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DecisionAction {
    AcceptPrimary,
    KeepAlias,
    Reject,
    Annotation { text: String },
}

impl DecisionAction {
    fn validate(&self) -> Result<(), ReviewValidationError> {
        if let Self::Annotation { text } = self {
            validate_text(
                text,
                MAX_REVIEW_ANNOTATION_BYTES,
                ReviewValidationError::InvalidAnnotation,
            )?;
        }
        Ok(())
    }

    const fn is_disposition(&self) -> bool {
        matches!(self, Self::AcceptPrimary | Self::KeepAlias | Self::Reject)
    }
}

/// One immutable entry in a ledger's ordered undo/redo history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewDecision {
    sequence: u64,
    subject: ReviewSubject,
    action: DecisionAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reviewer: Option<String>,
}

impl ReviewDecision {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn subject(&self) -> &ReviewSubject {
        &self.subject
    }

    #[must_use]
    pub const fn action(&self) -> &DecisionAction {
        &self.action
    }

    #[must_use]
    pub fn reviewer(&self) -> Option<&str> {
        self.reviewer.as_deref()
    }

    fn validate(&self) -> Result<(), ReviewValidationError> {
        if self.sequence == 0 {
            return Err(ReviewValidationError::InvalidSequence {
                index: 0,
                expected: 1,
                found: 0,
            });
        }
        self.subject.validate()?;
        self.action.validate()?;
        if let Some(reviewer) = &self.reviewer {
            validate_text(
                reviewer,
                MAX_REVIEWER_BYTES,
                ReviewValidationError::InvalidReviewer,
            )?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedReviewDecision {
    sequence: u64,
    subject: ReviewSubject,
    action: DecisionAction,
    #[serde(default)]
    reviewer: Option<String>,
}

impl<'de> Deserialize<'de> for ReviewDecision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedReviewDecision::deserialize(deserializer)?;
        let decision = Self {
            sequence: value.sequence,
            subject: value.subject,
            action: value.action,
            reviewer: value.reviewer,
        };
        decision.validate().map_err(D::Error::custom)?;
        Ok(decision)
    }
}

/// Binary-bound, persistent review decisions with an ordered undo/redo cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewLedger {
    schema_version: u32,
    binary_sha256: BinaryId,
    binary_size: u64,
    history: Vec<ReviewDecision>,
    applied_decision_count: usize,
}

impl ReviewLedger {
    /// Create an empty ledger bound to an exact binary hash and file size.
    #[must_use]
    pub fn new(binary: &BinaryIdentity) -> Self {
        Self {
            schema_version: REVIEW_LEDGER_SCHEMA_VERSION,
            binary_sha256: binary.id.clone(),
            binary_size: binary.size,
            history: Vec::new(),
            applied_decision_count: 0,
        }
    }

    /// Create a ledger after validating its source analysis session.
    pub fn for_session(session: &AnalysisSession) -> Result<Self, ReviewError> {
        session.validate().map_err(ReviewError::InvalidSession)?;
        Ok(Self::new(session.base_analysis().identity()))
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub const fn binary_sha256(&self) -> &BinaryId {
        &self.binary_sha256
    }

    #[must_use]
    pub const fn binary_size(&self) -> u64 {
        self.binary_size
    }

    /// Complete history, including entries currently available to redo.
    #[must_use]
    pub fn history(&self) -> &[ReviewDecision] {
        &self.history
    }

    /// Prefix of history currently applied to projections.
    #[must_use]
    pub fn applied_history(&self) -> &[ReviewDecision] {
        &self.history[..self.applied_decision_count]
    }

    /// Suffix of history currently available to redo.
    #[must_use]
    pub fn redo_history(&self) -> &[ReviewDecision] {
        &self.history[self.applied_decision_count..]
    }

    #[must_use]
    pub const fn can_undo(&self) -> bool {
        self.applied_decision_count != 0
    }

    #[must_use]
    pub fn can_redo(&self) -> bool {
        self.applied_decision_count < self.history.len()
    }

    /// Undo the most recently applied history entry.
    pub fn undo(&mut self) -> Option<&ReviewDecision> {
        self.applied_decision_count = self.applied_decision_count.checked_sub(1)?;
        self.history.get(self.applied_decision_count)
    }

    /// Reapply the next history entry.
    pub fn redo(&mut self) -> Option<&ReviewDecision> {
        let decision = self.history.get(self.applied_decision_count)?;
        self.applied_decision_count += 1;
        Some(decision)
    }

    /// Append a decision. Recording after undo discards the redo suffix.
    pub fn record(
        &mut self,
        subject: ReviewSubject,
        action: DecisionAction,
        reviewer: Option<String>,
    ) -> Result<&ReviewDecision, ReviewValidationError> {
        self.validate()?;
        if subject.symbol().binary() != &self.binary_sha256 {
            return Err(ReviewValidationError::DecisionBinaryMismatch {
                expected: self.binary_sha256.clone(),
                found: subject.symbol().binary().clone(),
            });
        }
        self.history.truncate(self.applied_decision_count);
        if self.history.len() >= MAX_REVIEW_DECISIONS {
            return Err(ReviewValidationError::DecisionLimitExceeded);
        }
        let sequence = self.history.last().map_or(Ok(1), |decision| {
            decision
                .sequence
                .checked_add(1)
                .ok_or(ReviewValidationError::SequenceOverflow)
        })?;
        let decision = ReviewDecision {
            sequence,
            subject,
            action,
            reviewer,
        };
        decision.validate()?;
        self.history.push(decision);
        self.applied_decision_count = self.history.len();
        self.history
            .last()
            .ok_or(ReviewValidationError::SequenceOverflow)
    }

    pub fn accept_primary(
        &mut self,
        claim: &SymbolClaim,
        reviewer: Option<String>,
    ) -> Result<&ReviewDecision, ReviewValidationError> {
        self.record(
            ReviewSubject::from_name_claim(claim)?,
            DecisionAction::AcceptPrimary,
            reviewer,
        )
    }

    pub fn keep_alias(
        &mut self,
        claim: &SymbolClaim,
        reviewer: Option<String>,
    ) -> Result<&ReviewDecision, ReviewValidationError> {
        self.record(
            ReviewSubject::from_name_claim(claim)?,
            DecisionAction::KeepAlias,
            reviewer,
        )
    }

    pub fn reject(
        &mut self,
        claim: &SymbolClaim,
        reviewer: Option<String>,
    ) -> Result<&ReviewDecision, ReviewValidationError> {
        self.record(
            ReviewSubject::from_name_claim(claim)?,
            DecisionAction::Reject,
            reviewer,
        )
    }

    pub fn annotate(
        &mut self,
        claim: &SymbolClaim,
        text: impl Into<String>,
        reviewer: Option<String>,
    ) -> Result<&ReviewDecision, ReviewValidationError> {
        self.record(
            ReviewSubject::from_name_claim(claim)?,
            DecisionAction::Annotation { text: text.into() },
            reviewer,
        )
    }

    /// Return the latest applied disposition for an exact review subject.
    #[must_use]
    pub fn latest_disposition(&self, subject: &ReviewSubject) -> Option<&ReviewDecision> {
        self.applied_history()
            .iter()
            .rev()
            .find(|decision| &decision.subject == subject && decision.action.is_disposition())
    }

    /// Applied decisions whose exact source claims are absent from this session.
    ///
    /// Orphans remain in history for audit and undo/redo, but projection never
    /// applies them to a merely similar candidate.
    pub fn orphaned_decisions<'a>(
        &'a self,
        session: &AnalysisSession,
    ) -> Result<Vec<&'a ReviewDecision>, ReviewError> {
        session.validate().map_err(ReviewError::InvalidSession)?;
        self.validate_for_binary(session.base_analysis().identity())
            .map_err(ReviewError::InvalidLedger)?;
        let available_keys = session
            .combined_symbol_graph()
            .map_err(ReviewError::InvalidSession)?
            .claims()
            .iter()
            .filter_map(|claim| match claim.assertion() {
                SymbolAssertion::Name { .. } => Some(ReviewSubject::from_name_claim(claim)),
                _ => None,
            })
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .map(ReviewSubject::canonical_key)
            .collect::<Result<BTreeSet<_>, _>>()?;
        self.applied_history()
            .iter()
            .filter_map(|decision| {
                decision
                    .subject
                    .canonical_key()
                    .map(|key| (!available_keys.contains(&key)).then_some(decision))
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(ReviewError::InvalidLedger)
    }

    pub fn orphaned_decision_count(&self, session: &AnalysisSession) -> Result<usize, ReviewError> {
        self.orphaned_decisions(session)
            .map(|decisions| decisions.len())
    }

    /// Validate schema, binding, ordered history, cursor, and decision text.
    pub fn validate(&self) -> Result<(), ReviewValidationError> {
        if self.schema_version != REVIEW_LEDGER_SCHEMA_VERSION {
            return Err(ReviewValidationError::UnsupportedSchema {
                found: self.schema_version,
            });
        }
        if self.history.len() > MAX_REVIEW_DECISIONS {
            return Err(ReviewValidationError::DecisionLimitExceeded);
        }
        if self.applied_decision_count > self.history.len() {
            return Err(ReviewValidationError::InvalidHistoryCursor {
                applied: self.applied_decision_count,
                history: self.history.len(),
            });
        }
        for (index, decision) in self.history.iter().enumerate() {
            decision.validate()?;
            let expected = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(ReviewValidationError::SequenceOverflow)?;
            if decision.sequence != expected {
                return Err(ReviewValidationError::InvalidSequence {
                    index,
                    expected,
                    found: decision.sequence,
                });
            }
            if decision.subject.symbol().binary() != &self.binary_sha256 {
                return Err(ReviewValidationError::DecisionBinaryMismatch {
                    expected: self.binary_sha256.clone(),
                    found: decision.subject.symbol().binary().clone(),
                });
            }
        }
        Ok(())
    }

    /// Ensure this sidecar belongs to the supplied exact binary.
    pub fn validate_for_binary(
        &self,
        binary: &BinaryIdentity,
    ) -> Result<(), ReviewValidationError> {
        self.validate()?;
        if self.binary_sha256 != binary.id || self.binary_size != binary.size {
            return Err(ReviewValidationError::BinaryBindingMismatch {
                expected_sha256: binary.id.clone(),
                expected_size: binary.size,
                found_sha256: self.binary_sha256.clone(),
                found_size: self.binary_size,
            });
        }
        Ok(())
    }

    /// Load and strictly validate a JSON review sidecar.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ReviewError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| ReviewError::Io {
            operation: "open",
            path: path.to_path_buf(),
            source,
        })?;
        let read_limit =
            MAX_REVIEW_SIDECAR_BYTES
                .checked_add(1)
                .ok_or(ReviewError::SidecarTooLarge {
                    path: path.to_path_buf(),
                    limit: MAX_REVIEW_SIDECAR_BYTES,
                })?;
        let mut encoded = Vec::new();
        BufReader::new(file)
            .take(read_limit)
            .read_to_end(&mut encoded)
            .map_err(|source| ReviewError::Io {
                operation: "read",
                path: path.to_path_buf(),
                source,
            })?;
        if u64::try_from(encoded.len()).map_or(true, |length| length > MAX_REVIEW_SIDECAR_BYTES) {
            return Err(ReviewError::SidecarTooLarge {
                path: path.to_path_buf(),
                limit: MAX_REVIEW_SIDECAR_BYTES,
            });
        }
        serde_json::from_slice(&encoded).map_err(|source| ReviewError::Deserialize {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Load a sidecar and verify it belongs to the supplied session.
    pub fn load_for_session(
        path: impl AsRef<Path>,
        session: &AnalysisSession,
    ) -> Result<Self, ReviewError> {
        session.validate().map_err(ReviewError::InvalidSession)?;
        let ledger = Self::load(path)?;
        ledger
            .validate_for_binary(session.base_analysis().identity())
            .map_err(ReviewError::InvalidLedger)?;
        Ok(ledger)
    }

    /// Atomically replace a sidecar after flushing its complete new contents.
    ///
    /// `tempfile` performs a same-directory atomic replace on both Unix and
    /// Windows, so readers observe either the previous valid ledger or the new
    /// valid ledger, never a partially written JSON document.
    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<(), ReviewError> {
        let path = path.as_ref();
        let (temporary, parent) = self.stage_sidecar(path)?;
        temporary.persist(path).map_err(|error| ReviewError::Io {
            operation: "replace",
            path: path.to_path_buf(),
            source: error.error,
        })?;

        #[cfg(not(unix))]
        let _ = parent;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ReviewError::Io {
                operation: "synchronize parent directory for",
                path: path.to_path_buf(),
                source,
            })?;
        Ok(())
    }

    /// Publish a completely staged sidecar without replacing an existing path.
    ///
    /// Validation, encoding, flushing, and the encoded-size gate all complete
    /// before the operating system's create-new publication step. Existing
    /// files, directories, and links are never replaced or truncated.
    pub fn save_new(&self, path: impl AsRef<Path>) -> Result<(), ReviewError> {
        let path = path.as_ref();
        let (temporary, _) = self.stage_sidecar(path)?;
        match temporary.persist_noclobber(path) {
            Ok(_) => Ok(()),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(ReviewError::TargetAlreadyExists {
                    path: path.to_path_buf(),
                })
            }
            Err(error) => Err(ReviewError::Io {
                operation: "publish new",
                path: path.to_path_buf(),
                source: error.error,
            }),
        }
    }

    fn stage_sidecar<'a>(
        &self,
        path: &'a Path,
    ) -> Result<(tempfile::NamedTempFile, &'a Path), ReviewError> {
        self.validate().map_err(ReviewError::InvalidLedger)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = Builder::new()
            .prefix(".resymbol-review-")
            .suffix(".tmp")
            .tempfile_in(parent)
            .map_err(|source| ReviewError::Io {
                operation: "create temporary file for",
                path: path.to_path_buf(),
                source,
            })?;
        {
            let mut writer = BufWriter::new(temporary.as_file_mut());
            serde_json::to_writer_pretty(&mut writer, self).map_err(|source| {
                ReviewError::Serialize {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            writer.write_all(b"\n").map_err(|source| ReviewError::Io {
                operation: "write",
                path: path.to_path_buf(),
                source,
            })?;
            writer.flush().map_err(|source| ReviewError::Io {
                operation: "flush",
                path: path.to_path_buf(),
                source,
            })?;
        }
        temporary
            .as_file()
            .sync_all()
            .map_err(|source| ReviewError::Io {
                operation: "synchronize",
                path: path.to_path_buf(),
                source,
            })?;
        let encoded_size = temporary
            .as_file()
            .metadata()
            .map_err(|source| ReviewError::Io {
                operation: "inspect temporary file for",
                path: path.to_path_buf(),
                source,
            })?
            .len();
        if encoded_size > MAX_REVIEW_SIDECAR_BYTES {
            return Err(ReviewError::SidecarTooLarge {
                path: path.to_path_buf(),
                limit: MAX_REVIEW_SIDECAR_BYTES,
            });
        }
        Ok((temporary, parent))
    }

    /// Project the session through applied review decisions without mutating it.
    pub fn reviewed_projection(
        &self,
        session: &AnalysisSession,
    ) -> Result<ExportProjection, ReviewError> {
        session.validate().map_err(ReviewError::InvalidSession)?;
        self.validate_for_binary(session.base_analysis().identity())
            .map_err(ReviewError::InvalidLedger)?;
        let source_graph = session
            .combined_symbol_graph()
            .map_err(ReviewError::InvalidSession)?;

        let available_subjects = source_graph
            .claims()
            .iter()
            .filter_map(|claim| match claim.assertion() {
                SymbolAssertion::Name { .. } => Some(ReviewSubject::from_name_claim(claim)),
                _ => None,
            })
            .collect::<Result<Vec<_>, _>>()?;
        let available_keys = available_subjects
            .iter()
            .map(ReviewSubject::canonical_key)
            .collect::<Result<BTreeSet<_>, _>>()?;

        let mut dispositions = BTreeMap::<String, &ReviewDecision>::new();
        for decision in self.applied_history() {
            let key = decision.subject.canonical_key()?;
            if !available_keys.contains(&key) {
                continue;
            }
            if decision.action.is_disposition() {
                dispositions.insert(key, decision);
            }
        }

        let mut graph = SymbolGraph::default();
        graph
            .insert_binary(session.base_analysis().identity().clone())
            .map_err(ReviewError::InvalidClaim)?;
        for claim in source_graph.claims() {
            let rejected = if matches!(claim.assertion(), SymbolAssertion::Name { .. }) {
                let subject = ReviewSubject::from_name_claim(claim)?;
                dispositions
                    .get(&subject.canonical_key()?)
                    .is_some_and(|decision| matches!(decision.action(), DecisionAction::Reject))
            } else {
                false
            };
            if !rejected {
                graph
                    .submit_claim(claim.clone())
                    .map_err(ReviewError::InvalidGraph)?;
            }
        }

        // Accept Primary is unique per symbol entity. If history contains more
        // than one still-active acceptance, the latest decision is primary and
        // the original earlier proposals remain as aliases in the source graph.
        let mut accepted_by_entity = BTreeMap::<String, &ReviewDecision>::new();
        for decision in dispositions.values().copied() {
            if !matches!(decision.action(), DecisionAction::AcceptPrimary) {
                continue;
            }
            let entity_key = decision.subject.entity_key()?;
            let replace = accepted_by_entity
                .get(&entity_key)
                .is_none_or(|current| current.sequence < decision.sequence);
            if replace {
                accepted_by_entity.insert(entity_key, decision);
            }
        }
        let mut accepted = accepted_by_entity.into_values().collect::<Vec<_>>();
        accepted.sort_by_key(|decision| decision.sequence);
        for decision in accepted {
            graph
                .submit_claim(accepted_user_claim(decision)?)
                .map_err(ReviewError::InvalidGraph)?;
        }

        let image_size = match session.base_analysis() {
            BinaryAnalysis::Pe(analysis) => u64::from(analysis.size_of_image),
            _ => return Err(ReviewError::UnsupportedAnalysisFormat),
        };
        ExportProjection::from_symbol_graph(session.base_analysis().identity(), image_size, &graph)
            .map_err(ReviewError::Export)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedReviewLedger {
    schema_version: u32,
    binary_sha256: BinaryId,
    binary_size: u64,
    history: Vec<ReviewDecision>,
    applied_decision_count: usize,
}

impl<'de> Deserialize<'de> for ReviewLedger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedReviewLedger::deserialize(deserializer)?;
        let ledger = Self {
            schema_version: value.schema_version,
            binary_sha256: value.binary_sha256,
            binary_size: value.binary_size,
            history: value.history,
            applied_decision_count: value.applied_decision_count,
        };
        ledger.validate().map_err(D::Error::custom)?;
        Ok(ledger)
    }
}

fn accepted_user_claim(decision: &ReviewDecision) -> Result<SymbolClaim, ReviewError> {
    let confidence = Confidence::new(1.0).map_err(ReviewError::InvalidClaim)?;
    let mut evidence = Evidence::new(
        EvidenceKind::new(EvidenceKind::USER_CONFIRMED).map_err(ReviewError::InvalidClaim)?,
        "Accepted as the primary name by an explicit ReSymbol review decision",
    )
    .map_err(ReviewError::InvalidClaim)?;
    evidence.confidence = Some(confidence);
    evidence
        .artifacts
        .insert("review.sequence".to_owned(), decision.sequence.to_string());
    SymbolClaim::new(
        decision.subject.symbol.clone(),
        SymbolAssertion::Name {
            name: decision.subject.name.clone(),
        },
        confidence,
        vec![evidence],
        ClaimProvenance {
            producer: ClaimProducer::User {
                reviewer: decision.reviewer.clone(),
            },
            method: REVIEW_ACCEPT_METHOD.to_owned(),
            run_id: Some(format!("review-{}", decision.sequence)),
        },
    )
    .map_err(ReviewError::InvalidClaim)
}

fn push_key_part(key: &mut String, value: &str) {
    key.push_str(&value.len().to_string());
    key.push(':');
    key.push_str(value);
    key.push('|');
}

fn push_optional_str(key: &mut String, value: Option<&str>) {
    match value {
        Some(value) => {
            push_key_part(key, "some");
            push_key_part(key, value);
        }
        None => push_key_part(key, "none"),
    }
}

fn push_optional_u64(key: &mut String, value: Option<u64>) {
    match value {
        Some(value) => {
            push_key_part(key, "some");
            push_key_part(key, &value.to_string());
        }
        None => push_key_part(key, "none"),
    }
}

fn validate_text(
    value: &str,
    max_bytes: usize,
    error: ReviewValidationError,
) -> Result<(), ReviewValidationError> {
    let canonical_controls = value
        .chars()
        .all(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'));
    if value.trim().is_empty() || value.len() > max_bytes || !canonical_controls {
        Err(error)
    } else {
        Ok(())
    }
}

/// Failure to validate review sidecar structure or decision content.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReviewValidationError {
    #[error("review sidecar schema {found} is unsupported")]
    UnsupportedSchema { found: u32 },
    #[error("review sidecar exceeds the decision limit")]
    DecisionLimitExceeded,
    #[error("review history cursor {applied} exceeds history length {history}")]
    InvalidHistoryCursor { applied: usize, history: usize },
    #[error("review decision {index} has sequence {found}, expected {expected}")]
    InvalidSequence {
        index: usize,
        expected: u64,
        found: u64,
    },
    #[error("review decision sequence overflowed")]
    SequenceOverflow,
    #[error("review subject must refer to a name claim")]
    NotNameClaim,
    #[error("could not serialize a claim for exact review fingerprinting: {0}")]
    ClaimFingerprintSerialization(#[source] serde_json::Error),
    #[error("review subject uses a symbol kind this version does not support")]
    UnsupportedSubject,
    #[error("review subject uses a producer kind this version does not support")]
    UnsupportedProducer,
    #[error("review subject is invalid: {0}")]
    InvalidReviewSubject(#[source] ClaimValidationError),
    #[error("reviewer must be bounded, non-empty canonical text")]
    InvalidReviewer,
    #[error("annotation must be bounded, non-empty canonical text")]
    InvalidAnnotation,
    #[error("review decision targets binary {found}, but its ledger is bound to {expected}")]
    DecisionBinaryMismatch { expected: BinaryId, found: BinaryId },
    #[error(
        "review ledger binding {found_sha256}/{found_size} does not match binary {expected_sha256}/{expected_size}"
    )]
    BinaryBindingMismatch {
        expected_sha256: BinaryId,
        expected_size: u64,
        found_sha256: BinaryId,
        found_size: u64,
    },
}

/// I/O, validation, or projection failure in a review workflow.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReviewError {
    #[error("could not {operation} review sidecar `{path}`: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not decode review sidecar `{path}`: {source}")]
    Deserialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("could not encode review sidecar `{path}`: {source}")]
    Serialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("review sidecar `{path}` exceeds the encoded size limit of {limit} bytes")]
    SidecarTooLarge { path: PathBuf, limit: u64 },
    #[error("review sidecar target `{path}` already exists")]
    TargetAlreadyExists { path: PathBuf },
    #[error("review ledger is invalid: {0}")]
    InvalidLedger(#[from] ReviewValidationError),
    #[error("analysis session is invalid: {0}")]
    InvalidSession(#[source] SessionValidationError),
    #[error("review claim is invalid: {0}")]
    InvalidClaim(#[source] ClaimValidationError),
    #[error("reviewed graph is invalid: {0}")]
    InvalidGraph(#[source] GraphValidationError),
    #[error("this analysis format does not yet support reviewed export")]
    UnsupportedAnalysisFormat,
    #[error("could not project reviewed symbols: {0}")]
    Export(#[source] ExportError),
}
