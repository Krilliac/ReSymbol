use std::fs;

use resymbol_analysis::{AnalysisSession, PluginRunRecord, PluginRunStatus, analyze_bytes};
use resymbol_app::{
    DecisionAction, MAX_REVIEWER_BYTES, REVIEW_CLAIM_FINGERPRINT_VERSION,
    REVIEW_LEDGER_SCHEMA_VERSION, ReviewError, ReviewLedger, ReviewSubject, ReviewValidationError,
};
use resymbol_core::{
    ClaimProducer, ClaimProvenance, Confidence, Evidence, EvidenceKind, SymbolAssertion,
    SymbolClaim, SymbolSubject, plugin_api::PluginId,
};
use resymbol_export::ExportProducer;
use tempfile::tempdir;

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

fn minimal_pe(marker: u8) -> Vec<u8> {
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
    bytes
}

fn name_claim(
    binary: resymbol_core::BinaryId,
    plugin_id: &PluginId,
    name: &str,
    confidence: f64,
) -> SymbolClaim {
    SymbolClaim::new(
        SymbolSubject::Function {
            binary,
            rva: 0x1000,
            size: None,
        },
        SymbolAssertion::Name {
            name: name.to_owned(),
        },
        Confidence::new(confidence).expect("valid confidence"),
        vec![
            Evidence::new(
                EvidenceKind::new(EvidenceKind::MODEL_INFERENCE).expect("valid evidence kind"),
                "Deterministic review integration fixture",
            )
            .expect("valid evidence"),
        ],
        ClaimProvenance {
            producer: ClaimProducer::Plugin {
                id: plugin_id.clone(),
                version: "1.2.3".to_owned(),
            },
            method: "fixture.name-proposal".to_owned(),
            run_id: Some("review-fixture-run".to_owned()),
        },
    )
    .expect("valid name claim")
}

fn fixture(marker: u8, names: &[(&str, f64)]) -> (AnalysisSession, Vec<SymbolClaim>) {
    let analysis = analyze_bytes(&minimal_pe(marker)).expect("valid synthetic PE");
    let plugin_id = PluginId::new("dev.resymbol.review-fixture").expect("valid plugin id");
    let claims = names
        .iter()
        .map(|(name, confidence)| {
            name_claim(
                analysis.identity().id.clone(),
                &plugin_id,
                name,
                *confidence,
            )
        })
        .collect::<Vec<_>>();
    let run = PluginRunRecord::new(
        plugin_id,
        "1.2.3",
        "review-fixture-run",
        "ab".repeat(32),
        PluginRunStatus::Succeeded,
        u64::try_from(claims.len()).expect("claim count fits u64"),
    )
    .expect("valid plugin run");
    let session =
        AnalysisSession::new(analysis, vec![run], claims.clone()).expect("valid analysis session");
    (session, claims)
}

fn projected_function(
    projection: &resymbol_export::ExportProjection,
) -> &resymbol_export::ExportFunction {
    projection
        .functions
        .iter()
        .find(|function| function.rva == 0x1000)
        .expect("projected fixture function")
}

fn legacy_sidecar(
    session: &AnalysisSession,
    claim: &SymbolClaim,
    applied_decision_count: usize,
) -> serde_json::Value {
    let SymbolAssertion::Name { name } = claim.assertion() else {
        unreachable!("fixture creates names")
    };
    let legacy_fingerprint = resymbol_core::BinaryId::digest(
        &serde_json::to_vec(claim).expect("serialize legacy fingerprint input"),
    );
    let subject = serde_json::json!({
        "claim_sha256": legacy_fingerprint,
        "symbol": claim.subject(),
        "name": name,
        "producer": &claim.provenance().producer,
        "method": &claim.provenance().method,
        "run_id": &claim.provenance().run_id,
    });
    serde_json::json!({
        "schema_version": 1,
        "binary_sha256": &session.base_analysis().identity().id,
        "binary_size": session.base_analysis().identity().size,
        "history": [
            {
                "sequence": 1,
                "subject": subject.clone(),
                "action": { "kind": "reject" },
                "reviewer": "Ada",
            },
            {
                "sequence": 2,
                "subject": subject,
                "action": {
                    "kind": "annotation",
                    "text": "Legacy rationale",
                },
                "reviewer": "Ada",
            },
        ],
        "applied_decision_count": applied_decision_count,
    })
}

#[test]
fn accept_primary_overlays_user_provenance_without_mutating_session() {
    let (session, claims) = fixture(0, &[("strong_original", 0.95), ("reviewed_name", 0.20)]);
    let original_graph = session.combined_symbol_graph().expect("valid source graph");
    let mut ledger = ReviewLedger::for_session(&session).expect("valid ledger");

    ledger
        .accept_primary(&claims[1], Some("Ada".to_owned()))
        .expect("accept review decision");
    let projection = ledger
        .reviewed_projection(&session)
        .expect("reviewed projection");

    let function = projected_function(&projection);
    let selected = function.selected_name.as_ref().expect("selected name");
    assert_eq!(selected.source.text, "reviewed_name");
    assert_eq!(selected.source.attribution.confidence, 1.0);
    assert_eq!(
        selected.source.attribution.provenance.method,
        "review.accept"
    );
    assert!(matches!(
        &selected.source.attribution.provenance.producer,
        ExportProducer::User { reviewer } if reviewer.as_deref() == Some("Ada")
    ));
    assert!(
        function
            .alternate_names
            .iter()
            .any(|candidate| candidate.text == "strong_original")
    );
    assert_eq!(
        session
            .combined_symbol_graph()
            .expect("source graph remains valid"),
        original_graph
    );
}

#[test]
fn reject_is_exact_and_keep_alias_or_undo_restore_the_proposal_as_alias_only() {
    let (session, claims) = fixture(0, &[("candidate_a", 0.90), ("candidate_b", 0.80)]);
    let mut ledger = ReviewLedger::for_session(&session).expect("valid ledger");

    ledger
        .reject(&claims[0], Some("Grace".to_owned()))
        .expect("reject exact claim");
    let projection = ledger
        .reviewed_projection(&session)
        .expect("projection after reject");
    let function = projected_function(&projection);
    assert_eq!(
        function
            .selected_name
            .as_ref()
            .expect("remaining name")
            .source
            .text,
        "candidate_b"
    );
    assert!(
        function
            .alternate_names
            .iter()
            .all(|candidate| candidate.text != "candidate_a")
    );

    ledger
        .keep_alias(&claims[0], Some("Grace".to_owned()))
        .expect("restore as alias");
    let restored = ledger
        .reviewed_projection(&session)
        .expect("projection with alias restored");
    assert_eq!(
        projected_function(&restored)
            .selected_name
            .as_ref()
            .expect("eligible name remains primary")
            .source
            .text,
        "candidate_b"
    );
    assert!(
        projected_function(&restored)
            .alternate_names
            .iter()
            .any(|candidate| candidate.text == "candidate_a")
    );

    assert!(matches!(
        ledger.undo().map(|decision| decision.action()),
        Some(DecisionAction::KeepAlias)
    ));
    assert!(ledger.can_redo());
    let rejected_again = ledger
        .reviewed_projection(&session)
        .expect("undo reapplies prior reject state");
    assert_eq!(
        projected_function(&rejected_again)
            .selected_name
            .as_ref()
            .expect("remaining name")
            .source
            .text,
        "candidate_b"
    );
    ledger.redo().expect("redo keep-alias decision");
}

#[test]
fn only_alias_proposal_remains_attributed_without_becoming_primary() {
    let (session, claims) = fixture(0, &[("alias_only", 0.90)]);
    let mut ledger = ReviewLedger::for_session(&session).expect("valid ledger");
    ledger
        .keep_alias(&claims[0], Some("Grace".to_owned()))
        .expect("keep sole proposal as alias");

    let projection = ledger
        .reviewed_projection(&session)
        .expect("alias-only projection");
    let function = projected_function(&projection);
    assert!(
        function.selected_name.is_none(),
        "no primary name was approved"
    );
    assert_eq!(function.alternate_names.len(), 1);
    assert_eq!(function.alternate_names[0].text, "alias_only");
    assert_eq!(function.alternate_names[0].attribution.confidence, 0.90);
}

#[test]
fn latest_accept_primary_wins_independent_of_subject_key_order() {
    let (session, claims) = fixture(0, &[("candidate_a", 0.90), ("candidate_b", 0.80)]);
    let subjects = claims
        .iter()
        .map(|claim| ReviewSubject::from_name_claim(claim).expect("review subject"))
        .collect::<Vec<_>>();
    let (lexically_first, lexically_last) =
        if subjects[0].claim_sha256() < subjects[1].claim_sha256() {
            (0, 1)
        } else {
            (1, 0)
        };

    for (older, newer) in [
        (lexically_last, lexically_first),
        (lexically_first, lexically_last),
    ] {
        let mut ledger = ReviewLedger::for_session(&session).expect("valid ledger");
        ledger
            .accept_primary(&claims[older], None)
            .expect("older acceptance");
        ledger
            .accept_primary(&claims[newer], None)
            .expect("newer acceptance");
        let projection = ledger
            .reviewed_projection(&session)
            .expect("reviewed projection");
        let SymbolAssertion::Name { name } = claims[newer].assertion() else {
            unreachable!("fixture creates names")
        };
        assert_eq!(
            projected_function(&projection)
                .selected_name
                .as_ref()
                .expect("reviewed primary")
                .source
                .text
                .as_str(),
            name.as_str()
        );
    }
}

#[test]
fn recording_after_undo_truncates_redo_but_preserves_order() {
    let (session, claims) = fixture(0, &[("candidate", 0.75)]);
    let mut ledger = ReviewLedger::for_session(&session).expect("valid ledger");
    ledger
        .accept_primary(&claims[0], None)
        .expect("accept decision");
    ledger
        .annotate(&claims[0], "First note", None)
        .expect("annotation decision");
    ledger.undo().expect("undo annotation");

    ledger
        .annotate(&claims[0], "Replacement note", None)
        .expect("replacement annotation");
    assert!(!ledger.can_redo());
    assert_eq!(ledger.history().len(), 2);
    assert_eq!(ledger.history()[0].sequence(), 1);
    assert_eq!(ledger.history()[1].sequence(), 2);
    assert!(matches!(
        ledger.history()[1].action(),
        DecisionAction::Annotation { text } if text == "Replacement note"
    ));
    ledger.validate().expect("ordered history remains valid");
}

#[test]
fn failed_record_after_undo_preserves_the_complete_redo_suffix() {
    let (session, claims) = fixture(0, &[("candidate", 0.75)]);
    let mut ledger = ReviewLedger::for_session(&session).expect("valid ledger");
    ledger
        .accept_primary(&claims[0], None)
        .expect("accept decision");
    ledger
        .annotate(&claims[0], "redo must survive", None)
        .expect("annotation decision");
    ledger.undo().expect("undo annotation");
    let before = ledger.clone();

    let error = ledger
        .record(
            ReviewSubject::from_name_claim(&claims[0]).expect("review subject"),
            DecisionAction::Reject,
            Some("x".repeat(MAX_REVIEWER_BYTES + 1)),
        )
        .expect_err("oversized reviewer is rejected");
    assert!(matches!(error, ReviewValidationError::InvalidReviewer));
    assert_eq!(ledger, before);
    assert_eq!(ledger.redo_history().len(), 1);
}

#[test]
fn disposition_and_rationale_remain_one_transaction_after_round_trip() {
    let (session, claims) = fixture(0, &[("candidate", 0.75)]);
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("transaction.review.json");
    let mut ledger = ReviewLedger::for_session(&session).expect("valid ledger");
    ledger
        .record_disposition_with_rationale(
            ReviewSubject::from_name_claim(&claims[0]).expect("review subject"),
            DecisionAction::Reject,
            Some("Ada".to_owned()),
            Some("Contradicted by exact source evidence".to_owned()),
        )
        .expect("transactional rationale");
    assert_eq!(ledger.history().len(), 2);
    assert_eq!(
        ledger.history()[0].transaction_id(),
        ledger.history()[1].transaction_id()
    );
    ledger.save_new(&path).expect("save transaction");

    let mut loaded = ReviewLedger::load_for_session(&path, &session).expect("load transaction");
    assert_eq!(loaded, ledger);
    loaded.undo().expect("undo complete transaction");
    assert!(loaded.applied_history().is_empty());
    assert_eq!(loaded.redo_history().len(), 2);
    loaded.redo().expect("redo complete transaction");
    assert_eq!(loaded.applied_history().len(), 2);

    let mut split_cursor = serde_json::to_value(&ledger).expect("encode transaction");
    split_cursor["applied_decision_count"] = serde_json::json!(1);
    assert!(
        serde_json::from_value::<ReviewLedger>(split_cursor).is_err(),
        "schema v2 accepted a cursor inside a transaction"
    );
}

#[test]
fn atomic_save_replaces_and_strict_load_rejects_drift() {
    let (session, claims) = fixture(0, &[("candidate", 0.75)]);
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("fixture.review.json");
    let mut ledger = ReviewLedger::for_session(&session).expect("valid ledger");
    ledger
        .accept_primary(&claims[0], Some("Lin".to_owned()))
        .expect("review decision");
    ledger.save_atomic(&path).expect("first atomic save");
    assert_eq!(ReviewLedger::load(&path).expect("load first save"), ledger);

    ledger
        .annotate(&claims[0], "Verified against the matching build", None)
        .expect("annotation");
    ledger.save_atomic(&path).expect("atomic replacement");
    assert_eq!(
        ReviewLedger::load_for_session(&path, &session).expect("bound load"),
        ledger
    );
    let directory_entries = fs::read_dir(directory.path())
        .expect("read sidecar directory")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert_eq!(directory_entries.len(), 1, "temporary file was removed");

    let (different_session, _) = fixture(1, &[("candidate", 0.75)]);
    assert!(matches!(
        ReviewLedger::load_for_session(&path, &different_session),
        Err(ReviewError::InvalidLedger(
            ReviewValidationError::BinaryBindingMismatch { .. }
        ))
    ));

    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read sidecar")).expect("valid JSON");
    value
        .as_object_mut()
        .expect("ledger object")
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
    fs::write(
        &path,
        serde_json::to_vec(&value).expect("serialize malformed sidecar"),
    )
    .expect("write malformed sidecar");
    assert!(matches!(
        ReviewLedger::load(&path),
        Err(ReviewError::Deserialize { .. })
    ));
}

#[test]
fn create_new_save_never_replaces_an_existing_sidecar() {
    let (session, claims) = fixture(0, &[("candidate", 0.75)]);
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("fixture.review.json");
    let mut first = ReviewLedger::for_session(&session).expect("valid first ledger");
    first
        .accept_primary(&claims[0], None)
        .expect("first review decision");
    first.save_new(&path).expect("first create-new save");
    let original = fs::read(&path).expect("read first sidecar");

    let mut second = first.clone();
    second
        .annotate(&claims[0], "must not replace the first sidecar", None)
        .expect("second review decision");
    assert!(matches!(
        second.save_new(&path),
        Err(ReviewError::TargetAlreadyExists { .. })
    ));
    assert_eq!(fs::read(&path).expect("read preserved sidecar"), original);
}

#[test]
fn projection_reports_and_ignores_orphaned_exact_claims() {
    let (full_session, claims) = fixture(0, &[("available", 0.9), ("missing", 0.8)]);
    let (reduced_session, _) = fixture(0, &[("available", 0.9)]);
    let mut ledger = ReviewLedger::for_session(&full_session).expect("valid ledger");
    ledger
        .reject(&claims[1], None)
        .expect("decision for second claim");

    let orphans = ledger
        .orphaned_decisions(&reduced_session)
        .expect("orphan inspection");
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].sequence(), 1);
    assert_eq!(
        ledger
            .orphaned_decision_count(&reduced_session)
            .expect("orphan count"),
        1
    );
    ledger
        .reviewed_projection(&reduced_session)
        .expect("orphan is ignored rather than inherited");

    let (recalibrated_session, _) = fixture(0, &[("available", 0.9), ("missing", 0.7)]);
    assert_eq!(
        ledger
            .orphaned_decision_count(&recalibrated_session)
            .expect("changed confidence changes exact fingerprint"),
        1
    );
}

#[test]
fn legacy_sidecar_migrates_fingerprint_and_rationale_transaction_strictly() {
    let (session, claims) = fixture(0, &[("candidate", 0.75)]);
    let directory = tempdir().expect("temporary directory");
    let legacy_path = directory.path().join("legacy.review.json");
    fs::write(
        &legacy_path,
        serde_json::to_vec_pretty(&legacy_sidecar(&session, &claims[0], 2))
            .expect("encode legacy sidecar"),
    )
    .expect("write legacy sidecar");

    let mut migrated =
        ReviewLedger::load_for_session(&legacy_path, &session).expect("migrate legacy sidecar");
    assert_eq!(migrated.schema_version(), REVIEW_LEDGER_SCHEMA_VERSION);
    assert!(migrated.history().iter().all(|decision| {
        decision.subject().fingerprint_version() == REVIEW_CLAIM_FINGERPRINT_VERSION
    }));
    assert_eq!(
        migrated.history()[0].transaction_id(),
        migrated.history()[1].transaction_id()
    );
    migrated.undo().expect("undo migrated transaction");
    assert!(migrated.applied_history().is_empty());

    let migrated_path = directory.path().join("migrated.review.json");
    migrated
        .save_new(&migrated_path)
        .expect("save schema v2 sidecar");
    assert_eq!(
        ReviewLedger::load_for_session(&migrated_path, &session).expect("reload schema v2"),
        migrated
    );
}

#[test]
fn empty_legacy_sidecar_still_dispatches_through_schema_one_migration() {
    let (session, _) = fixture(0, &[]);
    let migrated = serde_json::from_value::<ReviewLedger>(serde_json::json!({
        "schema_version": 1,
        "binary_sha256": &session.base_analysis().identity().id,
        "binary_size": session.base_analysis().identity().size,
        "history": [],
        "applied_decision_count": 0,
    }))
    .expect("empty schema-v1 ledger migrates");

    assert_eq!(migrated.schema_version(), REVIEW_LEDGER_SCHEMA_VERSION);
    assert!(migrated.history().is_empty());
    migrated.validate().expect("migrated empty ledger");
}

#[test]
fn legacy_cursor_between_disposition_and_rationale_preserves_applied_disposition() {
    let (session, claims) = fixture(0, &[("candidate", 0.75)]);
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("legacy-split.review.json");
    fs::write(
        &path,
        serde_json::to_vec(&legacy_sidecar(&session, &claims[0], 1))
            .expect("encode split legacy sidecar"),
    )
    .expect("write split legacy sidecar");

    let mut migrated =
        ReviewLedger::load_for_session(&path, &session).expect("migrate split cursor");
    assert_eq!(migrated.applied_history().len(), 2);
    assert_eq!(
        migrated.history()[0].transaction_id(),
        migrated.history()[1].transaction_id()
    );
    assert_eq!(
        projected_function(
            &migrated
                .reviewed_projection(&session)
                .expect("migrated rejected projection")
        )
        .selected_name,
        None
    );
    migrated
        .undo()
        .expect("undo indivisible migrated transaction");
    assert!(migrated.applied_history().is_empty());
}

#[test]
fn schema_v2_requires_explicit_fingerprint_and_transaction_metadata() {
    let (session, claims) = fixture(0, &[("candidate", 0.75)]);
    let mut ledger = ReviewLedger::for_session(&session).expect("valid ledger");
    ledger
        .reject(&claims[0], Some("Ada".to_owned()))
        .expect("review decision");
    let encoded = serde_json::to_value(&ledger).expect("encode current ledger");

    for field in ["transaction_id", "fingerprint_version"] {
        let mut malformed = encoded.clone();
        let decision = malformed["history"][0]
            .as_object_mut()
            .expect("decision object");
        if field == "transaction_id" {
            decision.remove(field);
        } else {
            decision["subject"]
                .as_object_mut()
                .expect("subject object")
                .remove(field);
        }
        assert!(
            serde_json::from_value::<ReviewLedger>(malformed).is_err(),
            "schema v2 accepted missing {field}"
        );
    }

    for mut malformed in [encoded, legacy_sidecar(&session, &claims[0], 2)] {
        malformed["history"][0]["subject"]["producer"]
            .as_object_mut()
            .expect("producer object")
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<ReviewLedger>(malformed).is_err(),
            "versioned sidecar accepted an unknown nested producer field"
        );
    }
}

#[test]
fn semantic_claim_fingerprint_is_versioned_and_stable() {
    let (session, claims) = fixture(0, &[("candidate", 0.75)]);
    let subject = ReviewSubject::from_name_claim(&claims[0]).expect("review subject");
    assert_eq!(
        subject.fingerprint_version(),
        REVIEW_CLAIM_FINGERPRINT_VERSION
    );
    assert_eq!(
        subject.claim_sha256().as_str(),
        "d3c558fe7c21f88d3b779acba7883ba81deff6649ce6f08d3f24b3e11dc8853b"
    );
    assert_eq!(
        resymbol_core::BinaryId::digest(
            &serde_json::to_vec(&claims[0]).expect("legacy fingerprint serialization")
        )
        .as_str(),
        "f3bcfdc579f465d9126a2a18b6e81b36f5e3a8e7388fe784ccfb8f194474d057",
        "legacy fingerprint encoding remains frozen for schema-v1 migration"
    );

    let mut first = Evidence::new(
        EvidenceKind::new(EvidenceKind::MODEL_INFERENCE).expect("evidence kind"),
        "First evidence",
    )
    .expect("first evidence");
    first.artifacts.insert("zeta".to_owned(), "2".to_owned());
    first.artifacts.insert("alpha".to_owned(), "1".to_owned());
    let second = Evidence::new(
        EvidenceKind::new(EvidenceKind::CONTROL_FLOW).expect("evidence kind"),
        "Second evidence",
    )
    .expect("second evidence");
    let make = |evidence, confidence| {
        SymbolClaim::new(
            claims[0].subject().clone(),
            SymbolAssertion::Name {
                name: "stable_candidate".to_owned(),
            },
            Confidence::new(confidence).expect("confidence"),
            evidence,
            claims[0].provenance().clone(),
        )
        .expect("stable claim")
    };
    let ordered = make(vec![first.clone(), second.clone()], 0.0);
    let reordered = make(vec![second, first], -0.0);
    assert_eq!(
        ReviewSubject::from_name_claim(&ordered).expect("ordered subject"),
        ReviewSubject::from_name_claim(&reordered).expect("reordered subject"),
        "evidence order, artifact insertion order, and signed zero are not semantic"
    );
    assert_eq!(
        subject.symbol().binary(),
        &session.base_analysis().identity().id
    );
}
