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
    SymbolSubject, plugin_api::PluginId,
};
use resymbol_export::{ExportError, ExportProjection, NameSelection};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use tempfile::Builder;
use thiserror::Error;

/// Current schema for a persisted ReSymbol review sidecar.
pub const REVIEW_LEDGER_SCHEMA_VERSION: u32 = 2;

/// Current domain-separated semantic encoding for exact claim fingerprints.
pub const REVIEW_CLAIM_FINGERPRINT_VERSION: u32 = 2;

const LEGACY_CLAIM_FINGERPRINT_VERSION: u32 = 1;

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
/// Version 2 hashes a domain-separated, length-prefixed semantic encoding of
/// the complete validated name claim. The encoding is independent of serde
/// field order and JSON formatting. Version 1 remains readable and matchable
/// only for migration of existing sidecars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewSubject {
    fingerprint_version: u32,
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
        Self::from_name_claim_with_version(claim, REVIEW_CLAIM_FINGERPRINT_VERSION)
    }

    fn from_name_claim_with_version(
        claim: &SymbolClaim,
        fingerprint_version: u32,
    ) -> Result<Self, ReviewValidationError> {
        let SymbolAssertion::Name { name } = claim.assertion() else {
            return Err(ReviewValidationError::NotNameClaim);
        };
        let subject = Self {
            fingerprint_version,
            claim_sha256: claim_fingerprint(claim, fingerprint_version)?,
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
    pub const fn fingerprint_version(&self) -> u32 {
        self.fingerprint_version
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
        if !matches!(
            self.fingerprint_version,
            LEGACY_CLAIM_FINGERPRINT_VERSION | REVIEW_CLAIM_FINGERPRINT_VERSION
        ) {
            return Err(ReviewValidationError::UnsupportedFingerprintVersion {
                found: self.fingerprint_version,
            });
        }
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
        push_key_part(&mut key, &self.fingerprint_version.to_string());
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
    fingerprint_version: u32,
    claim_sha256: BinaryId,
    symbol: SymbolSubject,
    name: String,
    producer: StrictClaimProducer,
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
            fingerprint_version: value.fingerprint_version,
            claim_sha256: value.claim_sha256,
            symbol: value.symbol,
            name: value.name,
            producer: value.producer.into_claim_producer(),
            method: value.method,
            run_id: value.run_id,
        };
        subject.validate().map_err(D::Error::custom)?;
        Ok(subject)
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LegacyReviewSubject {
    claim_sha256: BinaryId,
    symbol: SymbolSubject,
    name: String,
    producer: StrictClaimProducer,
    method: String,
    #[serde(default)]
    run_id: Option<String>,
}

impl LegacyReviewSubject {
    fn migrate(self) -> Result<ReviewSubject, ReviewValidationError> {
        let subject = ReviewSubject {
            fingerprint_version: LEGACY_CLAIM_FINGERPRINT_VERSION,
            claim_sha256: self.claim_sha256,
            symbol: self.symbol,
            name: self.name,
            producer: self.producer.into_claim_producer(),
            method: self.method,
            run_id: self.run_id,
        };
        subject.validate()?;
        Ok(subject)
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum StrictClaimProducer {
    Core {
        component: String,
        version: String,
    },
    Plugin {
        id: PluginId,
        version: String,
    },
    User {
        #[serde(default)]
        reviewer: Option<String>,
    },
}

impl StrictClaimProducer {
    fn into_claim_producer(self) -> ClaimProducer {
        match self {
            Self::Core { component, version } => ClaimProducer::Core { component, version },
            Self::Plugin { id, version } => ClaimProducer::Plugin { id, version },
            Self::User { reviewer } => ClaimProducer::User { reviewer },
        }
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
    transaction_id: u64,
    sequence: u64,
    subject: ReviewSubject,
    action: DecisionAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reviewer: Option<String>,
}

impl ReviewDecision {
    #[must_use]
    pub const fn transaction_id(&self) -> u64 {
        self.transaction_id
    }

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
        if self.transaction_id == 0 {
            return Err(ReviewValidationError::InvalidTransactionId {
                index: 0,
                expected: 1,
                found: 0,
            });
        }
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
    transaction_id: u64,
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
            transaction_id: value.transaction_id,
            sequence: value.sequence,
            subject: value.subject,
            action: value.action,
            reviewer: value.reviewer,
        };
        decision.validate().map_err(D::Error::custom)?;
        Ok(decision)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyReviewDecision {
    sequence: u64,
    subject: LegacyReviewSubject,
    action: DecisionAction,
    #[serde(default)]
    reviewer: Option<String>,
}

impl LegacyReviewDecision {
    fn migrate(self, transaction_id: u64) -> Result<ReviewDecision, ReviewValidationError> {
        let decision = ReviewDecision {
            transaction_id,
            sequence: self.sequence,
            subject: self.subject.migrate()?,
            action: self.action,
            reviewer: self.reviewer,
        };
        decision.validate()?;
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

    /// Undo the most recently applied persisted transaction.
    pub fn undo(&mut self) -> Option<&ReviewDecision> {
        let last_index = self.applied_decision_count.checked_sub(1)?;
        let transaction_id = self.history.get(last_index)?.transaction_id;
        self.applied_decision_count = last_index;
        while self.applied_decision_count != 0
            && self.history[self.applied_decision_count - 1].transaction_id == transaction_id
        {
            self.applied_decision_count -= 1;
        }
        self.history.get(self.applied_decision_count)
    }

    /// Reapply the next persisted transaction.
    pub fn redo(&mut self) -> Option<&ReviewDecision> {
        let first_index = self.applied_decision_count;
        let transaction_id = self.history.get(first_index)?.transaction_id;
        while self.applied_decision_count < self.history.len()
            && self.history[self.applied_decision_count].transaction_id == transaction_id
        {
            self.applied_decision_count += 1;
        }
        self.history.get(first_index)
    }

    /// Append one decision as its own transaction.
    ///
    /// All validation completes before recording after undo discards the redo
    /// suffix, so an error never mutates existing history.
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
        if self.applied_decision_count >= MAX_REVIEW_DECISIONS {
            return Err(ReviewValidationError::DecisionLimitExceeded);
        }
        let (sequence, transaction_id) = self.next_history_position()?;
        let decision = ReviewDecision {
            transaction_id,
            sequence,
            subject,
            action,
            reviewer,
        };
        decision.validate()?;
        validate_transaction(std::slice::from_ref(&decision))?;
        self.history.truncate(self.applied_decision_count);
        self.history.push(decision);
        self.applied_decision_count = self.history.len();
        self.history
            .last()
            .ok_or(ReviewValidationError::SequenceOverflow)
    }

    /// Record one disposition and its optional rationale as one undo/redo unit.
    pub fn record_disposition_with_rationale(
        &mut self,
        subject: ReviewSubject,
        action: DecisionAction,
        reviewer: Option<String>,
        rationale: Option<String>,
    ) -> Result<&ReviewDecision, ReviewValidationError> {
        self.validate()?;
        if !action.is_disposition() {
            return Err(ReviewValidationError::InvalidTransactionShape);
        }
        if subject.symbol().binary() != &self.binary_sha256 {
            return Err(ReviewValidationError::DecisionBinaryMismatch {
                expected: self.binary_sha256.clone(),
                found: subject.symbol().binary().clone(),
            });
        }
        let decision_count = if rationale.is_some() { 2 } else { 1 };
        if self
            .applied_decision_count
            .checked_add(decision_count)
            .is_none_or(|count| count > MAX_REVIEW_DECISIONS)
        {
            return Err(ReviewValidationError::DecisionLimitExceeded);
        }
        let (sequence, transaction_id) = self.next_history_position()?;
        let mut decisions = vec![ReviewDecision {
            transaction_id,
            sequence,
            subject: subject.clone(),
            action,
            reviewer: reviewer.clone(),
        }];
        if let Some(text) = rationale {
            decisions.push(ReviewDecision {
                transaction_id,
                sequence: sequence
                    .checked_add(1)
                    .ok_or(ReviewValidationError::SequenceOverflow)?,
                subject,
                action: DecisionAction::Annotation { text },
                reviewer,
            });
        }
        for decision in &decisions {
            decision.validate()?;
        }
        validate_transaction(&decisions)?;

        let first_index = self.applied_decision_count;
        self.history.truncate(first_index);
        self.history.extend(decisions);
        self.applied_decision_count = self.history.len();
        self.history
            .get(first_index)
            .ok_or(ReviewValidationError::SequenceOverflow)
    }

    fn next_history_position(&self) -> Result<(u64, u64), ReviewValidationError> {
        let previous = self
            .applied_decision_count
            .checked_sub(1)
            .and_then(|index| self.history.get(index));
        let sequence = previous.map_or(Ok(1), |decision| {
            decision
                .sequence
                .checked_add(1)
                .ok_or(ReviewValidationError::SequenceOverflow)
        })?;
        let transaction_id = previous.map_or(Ok(1), |decision| {
            decision
                .transaction_id
                .checked_add(1)
                .ok_or(ReviewValidationError::TransactionOverflow)
        })?;
        Ok((sequence, transaction_id))
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
        let graph = session
            .combined_symbol_graph()
            .map_err(ReviewError::InvalidSession)?;
        let available_keys = available_review_keys(&graph)?;
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
        if self.applied_decision_count != 0
            && self.applied_decision_count < self.history.len()
            && self.history[self.applied_decision_count - 1].transaction_id
                == self.history[self.applied_decision_count].transaction_id
        {
            return Err(ReviewValidationError::InvalidTransactionCursor {
                applied: self.applied_decision_count,
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
        let mut transaction_start = 0_usize;
        let mut expected_transaction = 1_u64;
        while transaction_start < self.history.len() {
            let found = self.history[transaction_start].transaction_id;
            if found != expected_transaction {
                return Err(ReviewValidationError::InvalidTransactionId {
                    index: transaction_start,
                    expected: expected_transaction,
                    found,
                });
            }
            let mut transaction_end = transaction_start + 1;
            while transaction_end < self.history.len()
                && self.history[transaction_end].transaction_id == found
            {
                transaction_end += 1;
            }
            validate_transaction(&self.history[transaction_start..transaction_end])?;
            transaction_start = transaction_end;
            expected_transaction = expected_transaction
                .checked_add(1)
                .ok_or(ReviewValidationError::TransactionOverflow)?;
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
        let mut ledger = Self::load(path)?;
        ledger
            .validate_for_binary(session.base_analysis().identity())
            .map_err(ReviewError::InvalidLedger)?;
        ledger.upgrade_legacy_subjects(session)?;
        Ok(ledger)
    }

    fn upgrade_legacy_subjects(&mut self, session: &AnalysisSession) -> Result<(), ReviewError> {
        let graph = session
            .combined_symbol_graph()
            .map_err(ReviewError::InvalidSession)?;
        let mut migrations = BTreeMap::<String, ReviewSubject>::new();
        for claim in graph.claims() {
            if !matches!(claim.assertion(), SymbolAssertion::Name { .. }) {
                continue;
            }
            let legacy = ReviewSubject::from_name_claim_with_version(
                claim,
                LEGACY_CLAIM_FINGERPRINT_VERSION,
            )?;
            migrations.insert(
                legacy.canonical_key()?,
                ReviewSubject::from_name_claim(claim)?,
            );
        }
        for decision in &mut self.history {
            if decision.subject.fingerprint_version != LEGACY_CLAIM_FINGERPRINT_VERSION {
                continue;
            }
            let key = decision.subject.canonical_key()?;
            if let Some(subject) = migrations.get(&key) {
                decision.subject = subject.clone();
            }
        }
        self.validate().map_err(ReviewError::InvalidLedger)
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
    /// Validation, bounded encoding, flushing, and file synchronization complete
    /// before `tempfile`'s path-based no-clobber publication. Existing targets
    /// are not replaced. `persist_noclobber` is not universally atomic and is
    /// intended for a trusted destination directory that an attacker or
    /// temporary-file cleaner cannot rewrite while this operation is pending.
    /// Unix parent-directory metadata is synchronized after publication; a
    /// synchronization error is reported after the target has become visible
    /// and does not roll that publication back.
    pub fn save_new(&self, path: impl AsRef<Path>) -> Result<(), ReviewError> {
        let path = path.as_ref();
        let (temporary, parent) = self.stage_sidecar(path)?;
        match temporary.persist_noclobber(path) {
            Ok(_) => sync_parent_directory(parent, path),
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
        self.stage_sidecar_with_limit(path, MAX_REVIEW_SIDECAR_BYTES)
    }

    fn stage_sidecar_with_limit<'a>(
        &self,
        path: &'a Path,
        encoded_limit: u64,
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
            let buffered = BufWriter::new(temporary.as_file_mut());
            let mut writer = CappedWriter::new(buffered, encoded_limit);
            if let Err(source) = serde_json::to_writer_pretty(&mut writer, self) {
                if writer.limit_exceeded() {
                    let _ = writer.into_inner().into_parts();
                    return Err(ReviewError::SidecarTooLarge {
                        path: path.to_path_buf(),
                        limit: encoded_limit,
                    });
                }
                return Err(ReviewError::Serialize {
                    path: path.to_path_buf(),
                    source,
                });
            }
            if let Err(source) = writer.write_all(b"\n") {
                if writer.limit_exceeded() {
                    let _ = writer.into_inner().into_parts();
                    return Err(ReviewError::SidecarTooLarge {
                        path: path.to_path_buf(),
                        limit: encoded_limit,
                    });
                }
                return Err(ReviewError::Io {
                    operation: "write",
                    path: path.to_path_buf(),
                    source,
                });
            }
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

        let mut dispositions = BTreeMap::<String, &ReviewDecision>::new();
        for decision in self.applied_history() {
            let key = decision.subject.canonical_key()?;
            if decision.action.is_disposition() {
                dispositions.insert(key, decision);
            }
        }

        let mut graph = SymbolGraph::default();
        graph
            .insert_binary(session.base_analysis().identity().clone())
            .map_err(ReviewError::InvalidClaim)?;
        let mut name_selections = Vec::with_capacity(source_graph.claims().len());
        let mut active_dispositions = BTreeMap::<u64, &ReviewDecision>::new();
        for claim in source_graph.claims() {
            let disposition = if matches!(claim.assertion(), SymbolAssertion::Name { .. }) {
                active_disposition_for_claim(claim, &dispositions)?
            } else {
                None
            };
            if let Some(decision) = disposition {
                active_dispositions.insert(decision.sequence, decision);
            }
            if !disposition
                .is_some_and(|decision| matches!(decision.action(), DecisionAction::Reject))
            {
                graph
                    .submit_claim(claim.clone())
                    .map_err(ReviewError::InvalidGraph)?;
                name_selections.push(
                    if disposition.is_some_and(|decision| {
                        matches!(decision.action(), DecisionAction::KeepAlias)
                    }) {
                        NameSelection::AliasOnly
                    } else {
                        NameSelection::PrimaryEligible
                    },
                );
            }
        }

        // Accept Primary is unique per symbol entity. If history contains more
        // than one still-active acceptance, the latest decision is primary and
        // the original earlier proposals remain as aliases in the source graph.
        let mut accepted_by_entity = BTreeMap::<String, &ReviewDecision>::new();
        for decision in active_dispositions.values().copied() {
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
            name_selections.push(NameSelection::PrimaryEligible);
        }

        let image_size = match session.base_analysis() {
            BinaryAnalysis::Pe(analysis) => u64::from(analysis.size_of_image),
            BinaryAnalysis::Elf(analysis) => analysis.image_size,
            _ => return Err(ReviewError::UnsupportedAnalysisFormat),
        };
        ExportProjection::from_symbol_graph_with_name_selections(
            session.base_analysis().identity(),
            image_size,
            &graph,
            &name_selections,
        )
        .map_err(ReviewError::Export)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedReviewLedger {
    schema_version: u32,
    binary_sha256: BinaryId,
    binary_size: u64,
    history: Vec<VersionedUncheckedReviewDecision>,
    applied_decision_count: usize,
}

struct LegacyUncheckedReviewLedger {
    schema_version: u32,
    binary_sha256: BinaryId,
    binary_size: u64,
    history: Vec<LegacyReviewDecision>,
    applied_decision_count: usize,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum VersionedUncheckedReviewDecision {
    Current(ReviewDecision),
    Legacy(LegacyReviewDecision),
}

impl<'de> Deserialize<'de> for ReviewLedger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedReviewLedger::deserialize(deserializer)?;
        let ledger = match value.schema_version {
            REVIEW_LEDGER_SCHEMA_VERSION => Self {
                schema_version: value.schema_version,
                binary_sha256: value.binary_sha256,
                binary_size: value.binary_size,
                history: value
                    .history
                    .into_iter()
                    .map(|decision| match decision {
                        VersionedUncheckedReviewDecision::Current(decision) => Ok(decision),
                        VersionedUncheckedReviewDecision::Legacy(_) => Err(D::Error::custom(
                            "review sidecar schema 2 requires transaction and fingerprint metadata",
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                applied_decision_count: value.applied_decision_count,
            },
            1 => migrate_legacy_ledger(LegacyUncheckedReviewLedger {
                schema_version: value.schema_version,
                binary_sha256: value.binary_sha256,
                binary_size: value.binary_size,
                history: value
                    .history
                    .into_iter()
                    .map(|decision| match decision {
                        VersionedUncheckedReviewDecision::Legacy(decision) => Ok(decision),
                        VersionedUncheckedReviewDecision::Current(_) => Err(D::Error::custom(
                            "review sidecar schema 1 cannot contain schema 2 decision metadata",
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                applied_decision_count: value.applied_decision_count,
            })
            .map_err(D::Error::custom)?,
            found => {
                return Err(D::Error::custom(ReviewValidationError::UnsupportedSchema {
                    found,
                }));
            }
        };
        ledger.validate().map_err(D::Error::custom)?;
        Ok(ledger)
    }
}

fn migrate_legacy_ledger(
    value: LegacyUncheckedReviewLedger,
) -> Result<ReviewLedger, ReviewValidationError> {
    if value.schema_version != 1 {
        return Err(ReviewValidationError::UnsupportedSchema {
            found: value.schema_version,
        });
    }
    if value.applied_decision_count > value.history.len() {
        return Err(ReviewValidationError::InvalidHistoryCursor {
            applied: value.applied_decision_count,
            history: value.history.len(),
        });
    }

    let mut applied_decision_count = value.applied_decision_count;
    let mut history = Vec::with_capacity(value.history.len());
    let mut legacy = value.history.into_iter().peekable();
    let mut legacy_index = 0_usize;
    let mut transaction_id = 1_u64;
    while let Some(decision) = legacy.next() {
        // Schema 1 had no transaction marker. The v1 workbench always wrote a
        // rationale immediately after its disposition with the same subject
        // and reviewer, which is the only legacy shape grouped during upgrade.
        let pair_rationale = decision.action.is_disposition()
            && legacy.peek().is_some_and(|next| {
                matches!(next.action, DecisionAction::Annotation { .. })
                    && next.subject == decision.subject
                    && next.reviewer == decision.reviewer
            });
        history.push(decision.migrate(transaction_id)?);
        legacy_index += 1;
        if pair_rationale {
            if applied_decision_count == legacy_index {
                // Legacy undo could split a UI disposition from its rationale.
                // Preserve the applied disposition while restoring the rationale
                // to the same indivisible transaction.
                applied_decision_count += 1;
            }
            history.push(
                legacy
                    .next()
                    .expect("peeked legacy rationale remains present")
                    .migrate(transaction_id)?,
            );
            legacy_index += 1;
        }
        transaction_id = transaction_id
            .checked_add(1)
            .ok_or(ReviewValidationError::TransactionOverflow)?;
    }

    Ok(ReviewLedger {
        schema_version: REVIEW_LEDGER_SCHEMA_VERSION,
        binary_sha256: value.binary_sha256,
        binary_size: value.binary_size,
        history,
        applied_decision_count,
    })
}

fn review_subject_versions(
    claim: &SymbolClaim,
) -> Result<[ReviewSubject; 2], ReviewValidationError> {
    Ok([
        ReviewSubject::from_name_claim_with_version(claim, LEGACY_CLAIM_FINGERPRINT_VERSION)?,
        ReviewSubject::from_name_claim(claim)?,
    ])
}

fn available_review_keys(graph: &SymbolGraph) -> Result<BTreeSet<String>, ReviewError> {
    let mut keys = BTreeSet::new();
    for claim in graph.claims() {
        if !matches!(claim.assertion(), SymbolAssertion::Name { .. }) {
            continue;
        }
        for subject in review_subject_versions(claim)? {
            keys.insert(subject.canonical_key()?);
        }
    }
    Ok(keys)
}

fn active_disposition_for_claim<'a>(
    claim: &SymbolClaim,
    dispositions: &BTreeMap<String, &'a ReviewDecision>,
) -> Result<Option<&'a ReviewDecision>, ReviewError> {
    let mut active = None;
    for subject in review_subject_versions(claim)? {
        if let Some(decision) = dispositions.get(&subject.canonical_key()?).copied() {
            if active.is_none_or(|current: &ReviewDecision| current.sequence < decision.sequence) {
                active = Some(decision);
            }
        }
    }
    Ok(active)
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

fn validate_transaction(decisions: &[ReviewDecision]) -> Result<(), ReviewValidationError> {
    let Some(first) = decisions.first() else {
        return Err(ReviewValidationError::InvalidTransactionShape);
    };
    if decisions.len() > 2
        || decisions
            .iter()
            .any(|decision| decision.transaction_id != first.transaction_id)
    {
        return Err(ReviewValidationError::InvalidTransactionShape);
    }
    if let [disposition, rationale] = decisions {
        if !disposition.action.is_disposition()
            || !matches!(rationale.action, DecisionAction::Annotation { .. })
            || disposition.subject != rationale.subject
            || disposition.reviewer != rationale.reviewer
        {
            return Err(ReviewValidationError::InvalidTransactionShape);
        }
    }
    Ok(())
}

fn claim_fingerprint(claim: &SymbolClaim, version: u32) -> Result<BinaryId, ReviewValidationError> {
    match version {
        LEGACY_CLAIM_FINGERPRINT_VERSION => serde_json::to_vec(claim)
            .map(|encoded| BinaryId::digest(&encoded))
            .map_err(ReviewValidationError::ClaimFingerprintSerialization),
        REVIEW_CLAIM_FINGERPRINT_VERSION => {
            semantic_name_claim_encoding(claim).map(|encoded| BinaryId::digest(&encoded))
        }
        found => Err(ReviewValidationError::UnsupportedFingerprintVersion { found }),
    }
}

fn semantic_name_claim_encoding(claim: &SymbolClaim) -> Result<Vec<u8>, ReviewValidationError> {
    // This is a persisted protocol, not a convenient serialization. Adding a
    // semantic SymbolClaim field requires a new fingerprint version and a
    // parallel encoder; never change the version-2 byte layout in place.
    claim
        .validate()
        .map_err(ReviewValidationError::InvalidReviewSubject)?;
    let SymbolAssertion::Name { name } = claim.assertion() else {
        return Err(ReviewValidationError::NotNameClaim);
    };

    let mut encoded = b"ReSymbol.review.claim\0".to_vec();
    encode_u32(&mut encoded, REVIEW_CLAIM_FINGERPRINT_VERSION);
    encode_subject(&mut encoded, claim.subject())?;
    encode_string(&mut encoded, name)?;
    encode_confidence(&mut encoded, claim.confidence());
    encode_provenance(&mut encoded, claim.provenance())?;

    let mut evidence = claim
        .evidence()
        .iter()
        .map(encode_evidence)
        .collect::<Result<Vec<_>, _>>()?;
    evidence.sort();
    encode_length(&mut encoded, evidence.len())?;
    for item in evidence {
        encode_bytes(&mut encoded, &item)?;
    }
    Ok(encoded)
}

fn encode_subject(
    encoded: &mut Vec<u8>,
    subject: &SymbolSubject,
) -> Result<(), ReviewValidationError> {
    match subject {
        SymbolSubject::Function { binary, rva, size } => {
            encoded.push(1);
            encode_string(encoded, binary.as_str())?;
            encode_u64(encoded, *rva);
            encode_optional_u64(encoded, *size);
        }
        SymbolSubject::Global { binary, rva, size } => {
            encoded.push(2);
            encode_string(encoded, binary.as_str())?;
            encode_u64(encoded, *rva);
            encode_optional_u64(encoded, *size);
        }
        SymbolSubject::Type { binary, key } => {
            encoded.push(3);
            encode_string(encoded, binary.as_str())?;
            encode_string(encoded, key)?;
        }
        _ => return Err(ReviewValidationError::UnsupportedSubject),
    }
    Ok(())
}

fn encode_provenance(
    encoded: &mut Vec<u8>,
    provenance: &ClaimProvenance,
) -> Result<(), ReviewValidationError> {
    match &provenance.producer {
        ClaimProducer::Core { component, version } => {
            encoded.push(1);
            encode_string(encoded, component)?;
            encode_string(encoded, version)?;
        }
        ClaimProducer::Plugin { id, version } => {
            encoded.push(2);
            encode_string(encoded, id.as_str())?;
            encode_string(encoded, version)?;
        }
        ClaimProducer::User { reviewer } => {
            encoded.push(3);
            encode_optional_string(encoded, reviewer.as_deref())?;
        }
        _ => return Err(ReviewValidationError::UnsupportedProducer),
    }
    encode_string(encoded, &provenance.method)?;
    encode_optional_string(encoded, provenance.run_id.as_deref())
}

fn encode_evidence(evidence: &Evidence) -> Result<Vec<u8>, ReviewValidationError> {
    let mut encoded = Vec::new();
    encode_string(&mut encoded, evidence.kind.as_str())?;
    encode_string(&mut encoded, &evidence.summary)?;
    match evidence.confidence {
        Some(confidence) => {
            encoded.push(1);
            encode_confidence(&mut encoded, confidence);
        }
        None => encoded.push(0),
    }
    encode_length(&mut encoded, evidence.artifacts.len())?;
    for (key, value) in &evidence.artifacts {
        encode_string(&mut encoded, key)?;
        encode_string(&mut encoded, value)?;
    }
    Ok(encoded)
}

fn encode_confidence(encoded: &mut Vec<u8>, confidence: Confidence) {
    let value = confidence.get();
    let canonical = if value == 0.0 { 0.0 } else { value };
    encode_u64(encoded, canonical.to_bits());
}

fn encode_optional_u64(encoded: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            encoded.push(1);
            encode_u64(encoded, value);
        }
        None => encoded.push(0),
    }
}

fn encode_optional_string(
    encoded: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), ReviewValidationError> {
    match value {
        Some(value) => {
            encoded.push(1);
            encode_string(encoded, value)
        }
        None => {
            encoded.push(0);
            Ok(())
        }
    }
}

fn encode_string(encoded: &mut Vec<u8>, value: &str) -> Result<(), ReviewValidationError> {
    encode_bytes(encoded, value.as_bytes())
}

fn encode_bytes(encoded: &mut Vec<u8>, value: &[u8]) -> Result<(), ReviewValidationError> {
    encode_length(encoded, value.len())?;
    encoded.extend_from_slice(value);
    Ok(())
}

fn encode_length(encoded: &mut Vec<u8>, length: usize) -> Result<(), ReviewValidationError> {
    encode_u64(
        encoded,
        u64::try_from(length)
            .map_err(|_| ReviewValidationError::ClaimFingerprintEncodingOverflow)?,
    );
    Ok(())
}

fn encode_u32(encoded: &mut Vec<u8>, value: u32) {
    encoded.extend_from_slice(&value.to_le_bytes());
}

fn encode_u64(encoded: &mut Vec<u8>, value: u64) {
    encoded.extend_from_slice(&value.to_le_bytes());
}

fn sync_parent_directory(parent: &Path, path: &Path) -> Result<(), ReviewError> {
    #[cfg(not(unix))]
    let _ = (parent, path);
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

struct CappedWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
    limit_exceeded: bool,
}

impl<W> CappedWriter<W> {
    const fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            written: 0,
            limit,
            limit_exceeded: false,
        }
    }

    const fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CappedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.saturating_sub(self.written);
        if remaining == 0 {
            self.limit_exceeded = true;
            return Err(std::io::Error::other("review sidecar size limit exceeded"));
        }
        let allowed = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let written = self.inner.write(&buffer[..allowed])?;
        self.written = self
            .written
            .checked_add(u64::try_from(written).expect("written byte count fits u64"))
            .ok_or_else(|| std::io::Error::other("review sidecar byte count overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
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
    #[error("review history cursor {applied} splits a persisted transaction")]
    InvalidTransactionCursor { applied: usize },
    #[error("review decision {index} has sequence {found}, expected {expected}")]
    InvalidSequence {
        index: usize,
        expected: u64,
        found: u64,
    },
    #[error("review decision sequence overflowed")]
    SequenceOverflow,
    #[error("review transaction {index} has id {found}, expected {expected}")]
    InvalidTransactionId {
        index: usize,
        expected: u64,
        found: u64,
    },
    #[error("review transaction id overflowed")]
    TransactionOverflow,
    #[error(
        "review transaction must contain one decision or a disposition followed by its rationale"
    )]
    InvalidTransactionShape,
    #[error("review subject must refer to a name claim")]
    NotNameClaim,
    #[error("could not serialize a claim for exact review fingerprinting: {0}")]
    ClaimFingerprintSerialization(#[source] serde_json::Error),
    #[error("review claim fingerprint version {found} is unsupported")]
    UnsupportedFingerprintVersion { found: u32 },
    #[error("review claim fingerprint encoding exceeded its integer domain")]
    ClaimFingerprintEncodingOverflow,
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

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn staged_encoding_stops_at_the_configured_limit_before_publication() {
        let binary = BinaryIdentity {
            id: BinaryId::digest(b"bounded-review-sidecar"),
            size: 1,
            format: resymbol_core::BinaryFormat::Pe,
            architecture: "x86_64".to_owned(),
            image_base: 0x0000_0001_4000_0000,
        };
        let ledger = ReviewLedger::new(&binary);
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("bounded.review.json");

        assert!(matches!(
            ledger.stage_sidecar_with_limit(&path, 32),
            Err(ReviewError::SidecarTooLarge { limit: 32, .. })
        ));
        assert!(!path.exists());
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("read temporary directory")
                .count(),
            0,
            "failed bounded staging left a temporary file"
        );
    }

    #[derive(Default)]
    struct FlushTrackingWriter {
        bytes: Vec<u8>,
        flush_count: usize,
    }

    impl Write for FlushTrackingWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flush_count += 1;
            Ok(())
        }
    }

    #[test]
    fn capped_writer_reports_max_plus_one_without_flushing() {
        let mut sink = FlushTrackingWriter::default();
        {
            let mut writer = CappedWriter::new(&mut sink, 4);
            writer
                .write_all(b"12345")
                .expect_err("fifth byte exceeds the cap");
            assert!(writer.limit_exceeded());
        }
        assert_eq!(sink.bytes, b"1234");
        assert_eq!(sink.flush_count, 0);
    }
}
