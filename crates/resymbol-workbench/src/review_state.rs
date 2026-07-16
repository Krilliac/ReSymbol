//! UI-independent ownership for the review ledger bound to the open project.

use std::path::{Path, PathBuf};

use resymbol_analysis::AnalysisSession;
use resymbol_app::{
    DecisionAction, MAX_REVIEW_ANNOTATION_BYTES, MAX_REVIEWER_BYTES, ReviewLedger, ReviewSubject,
    ReviewValidationError,
};
use thiserror::Error;

/// The single durable review ledger associated with the current project.
///
/// The workbench owns this value on the UI thread. Worker jobs receive clones,
/// so a stale save can never roll newer decisions back into the live ledger.
#[derive(Debug, Clone)]
pub struct BoundReviewLedger {
    ledger: ReviewLedger,
    saved_ledger: ReviewLedger,
    persisted_path: Option<PathBuf>,
}

impl BoundReviewLedger {
    /// Create an empty ledger bound to the exact open analysis identity.
    pub fn for_session(session: &AnalysisSession) -> Result<Self, ReviewStateError> {
        let ledger = ReviewLedger::for_session(session)
            .map_err(|error| ReviewStateError::Binding(error.to_string()))?;
        Ok(Self {
            saved_ledger: ledger.clone(),
            ledger,
            persisted_path: None,
        })
    }

    /// Adopt a strictly loaded ledger only after rechecking its binary binding.
    pub fn from_loaded(
        session: &AnalysisSession,
        ledger: ReviewLedger,
        path: PathBuf,
    ) -> Result<Self, ReviewStateError> {
        session
            .validate()
            .map_err(|error| ReviewStateError::Binding(error.to_string()))?;
        ledger
            .validate_for_binary(session.base_analysis().identity())
            .map_err(ReviewStateError::Ledger)?;
        Ok(Self {
            saved_ledger: ledger.clone(),
            ledger,
            persisted_path: Some(path),
        })
    }

    #[must_use]
    pub const fn ledger(&self) -> &ReviewLedger {
        &self.ledger
    }

    #[must_use]
    pub const fn persisted_path(&self) -> Option<&Path> {
        self.persisted_path.as_deref()
    }

    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.ledger != self.saved_ledger
    }

    #[must_use]
    pub fn applied_count(&self) -> usize {
        self.ledger.applied_history().len()
    }

    #[must_use]
    pub fn history_count(&self) -> usize {
        self.ledger.history().len()
    }

    #[must_use]
    pub fn redo_count(&self) -> usize {
        self.ledger.redo_history().len()
    }

    #[must_use]
    pub const fn can_undo(&self) -> bool {
        self.ledger.can_undo()
    }

    #[must_use]
    pub fn can_redo(&self) -> bool {
        self.ledger.can_redo()
    }

    pub fn orphaned_count(&self, session: &AnalysisSession) -> Result<usize, ReviewStateError> {
        self.ledger
            .orphaned_decision_count(session)
            .map_err(|error| ReviewStateError::Binding(error.to_string()))
    }

    /// Apply one exact-name disposition and, when supplied, its rationale as a
    /// second immutable annotation. A cloned ledger makes the compound edit
    /// transactional even at history or validation limits.
    pub fn apply_disposition(
        &mut self,
        subject: &ReviewSubject,
        action: DecisionAction,
        reviewer: &str,
        rationale: &str,
    ) -> Result<(), ReviewStateError> {
        if !matches!(
            action,
            DecisionAction::AcceptPrimary | DecisionAction::KeepAlias | DecisionAction::Reject
        ) {
            return Err(ReviewStateError::UnsupportedDisposition);
        }
        let reviewer = normalized_optional(reviewer, MAX_REVIEWER_BYTES, "reviewer")?;
        let rationale =
            normalized_optional(rationale, MAX_REVIEW_ANNOTATION_BYTES, "review rationale")?;
        let mut next = self.ledger.clone();
        next.record(subject.clone(), action, reviewer.clone())?;
        if let Some(rationale) = rationale {
            next.record(
                subject.clone(),
                DecisionAction::Annotation { text: rationale },
                reviewer,
            )?;
        }
        self.ledger = next;
        Ok(())
    }

    /// Undo one applied history entry without discarding its redo suffix.
    pub fn undo(&mut self) -> bool {
        self.ledger.undo().is_some()
    }

    /// Reapply one history entry.
    pub fn redo(&mut self) -> bool {
        self.ledger.redo().is_some()
    }

    /// Record the exact snapshot completed by the worker.
    ///
    /// Returns `true` only when it matches the current ledger. A user edit made
    /// while the worker was saving therefore remains visibly dirty.
    pub fn mark_saved(&mut self, saved: &ReviewLedger, path: PathBuf) -> bool {
        if saved.binary_sha256() != self.ledger.binary_sha256()
            || saved.binary_size() != self.ledger.binary_size()
        {
            return false;
        }
        self.saved_ledger = saved.clone();
        self.persisted_path = Some(path);
        !self.is_dirty()
    }
}

fn normalized_optional(
    value: &str,
    maximum_bytes: usize,
    field: &'static str,
) -> Result<Option<String>, ReviewStateError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > maximum_bytes {
        return Err(ReviewStateError::InputTooLong {
            field,
            maximum_bytes,
            actual_bytes: value.len(),
        });
    }
    Ok(Some(value.to_owned()))
}

#[derive(Debug, Error)]
pub enum ReviewStateError {
    #[error("review ledger could not be bound to this project: {0}")]
    Binding(String),
    #[error("review ledger is invalid: {0}")]
    Ledger(#[from] ReviewValidationError),
    #[error("only Accept, Keep as Alias, and Reject are disposition controls")]
    UnsupportedDisposition,
    #[error("{field} is {actual_bytes} UTF-8 bytes; the limit is {maximum_bytes}")]
    InputTooLong {
        field: &'static str,
        maximum_bytes: usize,
        actual_bytes: usize,
    },
}

#[cfg(test)]
mod tests {
    use resymbol_analysis::{AnalysisSession, PluginRunRecord, PluginRunStatus, analyze_bytes};
    use resymbol_app::ReviewSubject;
    use resymbol_core::{
        ClaimProducer, ClaimProvenance, Confidence, Evidence, EvidenceKind, SymbolAssertion,
        SymbolClaim, SymbolSubject, plugin_api::PluginId,
    };

    use super::*;

    const PE_OFFSET: usize = 0x80;
    const COFF_OFFSET: usize = PE_OFFSET + 4;
    const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
    const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 0xf0;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture(marker: u8) -> (AnalysisSession, SymbolClaim) {
        let mut bytes = vec![0_u8; 0x400];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[2] = marker;
        put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        put_u16(&mut bytes, COFF_OFFSET, 0x8664);
        put_u16(&mut bytes, COFF_OFFSET + 2, 1);
        put_u16(&mut bytes, COFF_OFFSET + 16, 0xf0);
        put_u16(&mut bytes, COFF_OFFSET + 18, 0x2022);
        put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1000);
        put_u64(&mut bytes, OPTIONAL_OFFSET + 24, 0x0000_0001_4000_0000);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x2000);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x200);
        put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
        put_u16(&mut bytes, OPTIONAL_OFFSET + 70, 0x8160);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 108, 16);
        bytes[SECTION_OFFSET..SECTION_OFFSET + 6].copy_from_slice(b".text\0");
        put_u32(&mut bytes, SECTION_OFFSET + 8, 0x200);
        put_u32(&mut bytes, SECTION_OFFSET + 12, 0x1000);
        put_u32(&mut bytes, SECTION_OFFSET + 16, 0x200);
        put_u32(&mut bytes, SECTION_OFFSET + 20, 0x200);
        put_u32(&mut bytes, SECTION_OFFSET + 36, 0x6000_0020);
        bytes[0x200] = 0xc3;

        let analysis = analyze_bytes(&bytes).expect("valid synthetic PE");
        let plugin_id = PluginId::new("dev.resymbol.workbench-review").expect("plugin id");
        let claim = SymbolClaim::new(
            SymbolSubject::Function {
                binary: analysis.identity().id.clone(),
                rva: 0x1000,
                size: None,
            },
            SymbolAssertion::Name {
                name: "candidate_name".to_owned(),
            },
            Confidence::new(0.75).expect("confidence"),
            vec![
                Evidence::new(
                    EvidenceKind::new(EvidenceKind::MODEL_INFERENCE).expect("evidence kind"),
                    "review-state fixture",
                )
                .expect("evidence"),
            ],
            ClaimProvenance {
                producer: ClaimProducer::Plugin {
                    id: plugin_id.clone(),
                    version: "1.0.0".to_owned(),
                },
                method: "fixture.name".to_owned(),
                run_id: Some("fixture-run".to_owned()),
            },
        )
        .expect("name claim");
        let run = PluginRunRecord::new(
            plugin_id,
            "1.0.0",
            "fixture-run",
            "ab".repeat(32),
            PluginRunStatus::Succeeded,
            1,
        )
        .expect("plugin run");
        let session = AnalysisSession::new(analysis, vec![run], vec![claim.clone()])
            .expect("analysis session");
        (session, claim)
    }

    #[test]
    fn dispositions_and_optional_rationale_are_transactional() {
        let (session, claim) = fixture(0);
        let subject = ReviewSubject::from_name_claim(&claim).expect("review subject");
        let mut state = BoundReviewLedger::for_session(&session).expect("bound ledger");

        state
            .apply_disposition(
                &subject,
                DecisionAction::Reject,
                "Ada",
                "Evidence contradicts this proposal",
            )
            .expect("reject with rationale");
        assert_eq!(state.ledger().history().len(), 2);
        assert!(matches!(
            state
                .ledger()
                .latest_disposition(&subject)
                .map(|decision| decision.action()),
            Some(DecisionAction::Reject)
        ));
        assert!(state.is_dirty());
    }

    #[test]
    fn each_supported_control_records_its_exact_durable_action() {
        let (session, claim) = fixture(0);
        let subject = ReviewSubject::from_name_claim(&claim).expect("review subject");

        for action in [
            DecisionAction::AcceptPrimary,
            DecisionAction::KeepAlias,
            DecisionAction::Reject,
        ] {
            let mut state = BoundReviewLedger::for_session(&session).expect("bound ledger");
            state
                .apply_disposition(&subject, action.clone(), "", "")
                .expect("supported disposition");
            assert_eq!(
                state
                    .ledger()
                    .latest_disposition(&subject)
                    .map(|decision| decision.action()),
                Some(&action)
            );
        }
    }

    #[test]
    fn oversized_reviewer_or_rationale_is_rejected_without_partial_history() {
        let (session, claim) = fixture(0);
        let subject = ReviewSubject::from_name_claim(&claim).expect("review subject");
        let mut state = BoundReviewLedger::for_session(&session).expect("bound ledger");

        assert!(matches!(
            state.apply_disposition(
                &subject,
                DecisionAction::AcceptPrimary,
                &"r".repeat(MAX_REVIEWER_BYTES + 1),
                "",
            ),
            Err(ReviewStateError::InputTooLong {
                field: "reviewer",
                ..
            })
        ));
        assert!(matches!(
            state.apply_disposition(
                &subject,
                DecisionAction::Reject,
                "",
                &"x".repeat(MAX_REVIEW_ANNOTATION_BYTES + 1),
            ),
            Err(ReviewStateError::InputTooLong {
                field: "review rationale",
                ..
            })
        ));
        assert!(state.ledger().history().is_empty());
        assert!(!state.is_dirty());
    }

    #[test]
    fn stale_save_never_clears_newer_review_edits() {
        let (session, claim) = fixture(0);
        let subject = ReviewSubject::from_name_claim(&claim).expect("review subject");
        let mut state = BoundReviewLedger::for_session(&session).expect("bound ledger");
        let queued = state.ledger().clone();
        state
            .apply_disposition(&subject, DecisionAction::AcceptPrimary, "", "")
            .expect("accept claim");

        assert!(!state.mark_saved(&queued, PathBuf::from("old.review.json")));
        assert!(state.is_dirty());
        let current = state.ledger().clone();
        assert!(state.mark_saved(&current, PathBuf::from("new.review.json")));
        assert!(!state.is_dirty());
    }

    #[test]
    fn loaded_ledger_must_match_the_open_binary() {
        let (first, _) = fixture(0);
        let (second, _) = fixture(1);
        let ledger = ReviewLedger::for_session(&first).expect("first ledger");

        assert!(matches!(
            BoundReviewLedger::from_loaded(&second, ledger, PathBuf::from("mismatch.review.json")),
            Err(ReviewStateError::Ledger(_))
        ));
    }

    #[test]
    fn exact_decision_becomes_an_orphan_when_its_claim_is_absent() {
        let (full, claim) = fixture(0);
        let reduced = AnalysisSession::new(full.base_analysis().clone(), Vec::new(), Vec::new())
            .expect("reduced session with the same binary");
        let subject = ReviewSubject::from_name_claim(&claim).expect("review subject");
        let mut state = BoundReviewLedger::for_session(&full).expect("bound ledger");
        state
            .apply_disposition(&subject, DecisionAction::Reject, "", "")
            .expect("exact rejected claim");

        assert_eq!(state.orphaned_count(&full).expect("full orphan count"), 0);
        assert_eq!(
            state
                .orphaned_count(&reduced)
                .expect("reduced orphan count"),
            1
        );
        state
            .ledger()
            .reviewed_projection(&reduced)
            .expect("orphan is ignored rather than inherited");
    }
}
