use std::fs;

use resymbol_analysis::{AnalysisSession, PluginRunRecord, PluginRunStatus, analyze_bytes};
use resymbol_app::{DecisionAction, ReviewError, ReviewLedger, ReviewValidationError};
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
fn reject_is_exact_and_keep_alias_or_undo_restore_the_proposal() {
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
            .expect("strong name restored")
            .source
            .text,
        "candidate_a"
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
