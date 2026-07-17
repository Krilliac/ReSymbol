#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fs,
    sync::{Arc, Barrier},
    thread,
};

use resymbol_analysis::BinaryAnalysis;
use resymbol_app::{
    AppServices, MAX_STATIC_PATCH_EDITS, StaticPatchEditRequest, StaticPatchError, StaticPatchPlan,
    StaticPatchWarning,
};
use tempfile::TempDir;

const EXACT_PE: &[u8] =
    include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-symbolized.exe");
const THUNK_RVA: u32 = 0x1184;
const THUNK_FILE_OFFSET: usize = 0x584;
const THUNK_FILE_OFFSET_U64: u64 = 0x584;
const THUNK_BYTES: [u8; 5] = [0xe9, 0x03, 0x00, 0x00, 0x00];

fn write_source(temp: &TempDir) -> std::path::PathBuf {
    let path = temp.path().join("source.exe");
    fs::write(&path, EXACT_PE).expect("write exact PE fixture");
    path
}

fn directory_entries(path: &std::path::Path) -> BTreeSet<std::ffi::OsString> {
    fs::read_dir(path)
        .expect("read test directory")
        .map(|entry| entry.expect("read directory entry").file_name())
        .collect()
}

#[test]
fn nops_a_known_executable_instruction_without_mutating_the_source() {
    let temp = TempDir::new().expect("create temp directory");
    let source = write_source(&temp);
    let services = AppServices::default();
    let project = services.analyze_binary(&source).expect("analyze exact PE");
    let identity = project.session().base_analysis().identity();
    let request = StaticPatchEditRequest::nop_instruction(
        THUNK_RVA,
        THUNK_BYTES,
        "Disable internal jump thunk",
    )
    .expect("valid NOP request");
    let plan = StaticPatchPlan::new(identity, project.session().base_analysis(), vec![request])
        .expect("valid exact patch plan");

    assert_eq!(plan.edits().len(), 1);
    assert_eq!(plan.edits()[0].file_offset(), THUNK_FILE_OFFSET_U64);
    assert_eq!(plan.total_patch_bytes(), THUNK_BYTES.len());
    let patched = services
        .apply_static_patch(&project, &plan)
        .expect("apply compare-before-write patch");

    assert_eq!(
        &patched.bytes()[THUNK_FILE_OFFSET..THUNK_FILE_OFFSET + 5],
        &[0x90; 5]
    );
    assert_eq!(patched.bytes().len(), EXACT_PE.len());
    assert_eq!(project.verified_source_bytes(), Some(EXACT_PE));
    assert_eq!(
        fs::read(&source).expect("read source after patch"),
        EXACT_PE
    );
    assert_eq!(patched.source_identity(), identity);
    assert_ne!(patched.output_identity().id, identity.id);
    assert_eq!(patched.output_identity().size, identity.size);
    assert_eq!(
        patched.warnings(),
        &[
            StaticPatchWarning::AuthenticodeMayBeInvalid,
            StaticPatchWarning::PeChecksumMayBeInvalid,
        ]
    );
    assert!(patched.warnings().iter().all(|warning| {
        let warning = warning.to_string();
        warning.contains("may invalidate") && warning.contains("does not")
    }));

    let limited = AppServices::default()
        .with_binary_size_limit(EXACT_PE.len() as u64 - 1)
        .expect("valid smaller service limit");
    assert!(matches!(
        limited.apply_static_patch(&project, &plan),
        Err(StaticPatchError::SourceTooLarge { .. })
    ));
}

#[test]
fn stale_expected_bytes_fail_before_any_output_is_modified() {
    let temp = TempDir::new().expect("create temp directory");
    let source = write_source(&temp);
    let services = AppServices::default();
    let project = services.analyze_binary(&source).expect("analyze exact PE");
    let mut stale = THUNK_BYTES;
    stale[1] = 0x04;
    let request = StaticPatchEditRequest::nop_instruction(THUNK_RVA, stale, "Stale jump")
        .expect("shape-valid stale request");
    let plan = StaticPatchPlan::new(
        project.session().base_analysis().identity(),
        project.session().base_analysis(),
        vec![request],
    )
    .expect("address-valid plan");

    assert!(matches!(
        services.apply_static_patch(&project, &plan),
        Err(StaticPatchError::StaleExpectedBytes {
            rva: THUNK_RVA,
            file_offset: THUNK_FILE_OFFSET_U64,
            ..
        })
    ));
    let mut wrong_identity = EXACT_PE.to_vec();
    *wrong_identity.last_mut().expect("fixture is not empty") ^= 0x5a;
    let wrong_identity_snapshot = wrong_identity.clone();
    assert!(matches!(
        plan.apply(&wrong_identity),
        Err(StaticPatchError::SourceIdentityMismatch { .. })
    ));
    assert_eq!(wrong_identity, wrong_identity_snapshot);
    assert_eq!(project.verified_source_bytes(), Some(EXACT_PE));
    assert_eq!(fs::read(&source).expect("read unchanged source"), EXACT_PE);
}

#[test]
fn plans_reject_duplicate_overlap_bounds_and_non_executable_ranges() {
    let temp = TempDir::new().expect("create temp directory");
    let source = write_source(&temp);
    let services = AppServices::default();
    let project = services.analyze_binary(&source).expect("analyze exact PE");
    let analysis = project.session().base_analysis();
    let identity = analysis.identity();

    let repeated = StaticPatchEditRequest::replace_bytes(0x1000, [0x48], [0x90], "bounded edit")
        .expect("valid repeated request");
    assert!(matches!(
        StaticPatchPlan::new(
            identity,
            analysis,
            vec![repeated; MAX_STATIC_PATCH_EDITS + 1]
        ),
        Err(StaticPatchError::TooManyEdits {
            actual,
            maximum: MAX_STATIC_PATCH_EDITS,
        }) if actual == MAX_STATIC_PATCH_EDITS + 1
    ));

    let duplicate = vec![
        StaticPatchEditRequest::replace_bytes(0x1000, [0x48], [0x90], "first")
            .expect("first request"),
        StaticPatchEditRequest::replace_bytes(0x1000, [0x48], [0xcc], "duplicate")
            .expect("duplicate request"),
    ];
    assert!(matches!(
        StaticPatchPlan::new(identity, analysis, duplicate),
        Err(StaticPatchError::DuplicateEdit { rva: 0x1000 })
    ));

    let overlap = vec![
        StaticPatchEditRequest::replace_bytes(0x1000, [0x48, 0x8d], [0x90, 0x90], "first")
            .expect("first overlap request"),
        StaticPatchEditRequest::replace_bytes(0x1001, [0x8d], [0xcc], "second")
            .expect("second overlap request"),
    ];
    assert!(matches!(
        StaticPatchPlan::new(identity, analysis, overlap),
        Err(StaticPatchError::OverlappingEdits {
            first_rva: 0x1000,
            second_rva: 0x1001,
        })
    ));

    let image_size = match analysis {
        BinaryAnalysis::Pe(pe) => pe.size_of_image,
        _ => panic!("fixture has a supported PE analysis"),
    };
    let outside =
        StaticPatchEditRequest::replace_bytes(image_size, [0x00], [0x90], "outside image")
            .expect("shape-valid range");
    assert!(matches!(
        StaticPatchPlan::new(identity, analysis, vec![outside]),
        Err(StaticPatchError::RangeOutsideImage { .. })
    ));

    let non_executable = StaticPatchEditRequest::replace_bytes(0x2000, [0x00], [0x90], "data byte")
        .expect("shape-valid data range");
    assert!(matches!(
        StaticPatchPlan::new(identity, analysis, vec![non_executable]),
        Err(StaticPatchError::RangeNotExecutable { .. })
    ));
}

#[test]
fn plan_order_and_patched_identity_are_deterministic() {
    let temp = TempDir::new().expect("create temp directory");
    let source = write_source(&temp);
    let services = AppServices::default();
    let project = services.analyze_binary(&source).expect("analyze exact PE");
    let identity = project.session().base_analysis().identity();
    let first = || {
        StaticPatchEditRequest::replace_bytes(0x1000, [0x48], [0x90], "entry byte")
            .expect("valid entry edit")
    };
    let second = || {
        StaticPatchEditRequest::nop_instruction(THUNK_RVA, THUNK_BYTES, "jump thunk")
            .expect("valid thunk edit")
    };

    let forward = StaticPatchPlan::new(
        identity,
        project.session().base_analysis(),
        vec![first(), second()],
    )
    .expect("forward plan");
    let reverse = StaticPatchPlan::new(
        identity,
        project.session().base_analysis(),
        vec![second(), first()],
    )
    .expect("reverse plan");
    assert_eq!(forward, reverse);
    assert_eq!(
        forward
            .edits()
            .iter()
            .map(|edit| edit.rva())
            .collect::<Vec<_>>(),
        vec![0x1000, THUNK_RVA]
    );

    let first_image = forward.apply(EXACT_PE).expect("apply forward plan");
    let second_image = reverse.apply(EXACT_PE).expect("apply reverse plan");
    assert_eq!(first_image.bytes(), second_image.bytes());
    assert_eq!(
        first_image.output_identity(),
        second_image.output_identity()
    );
}

#[test]
fn publication_is_create_new_and_cleans_staging_on_failure() {
    let temp = TempDir::new().expect("create temp directory");
    let source = write_source(&temp);
    let services = AppServices::default();
    let project = services.analyze_binary(&source).expect("analyze exact PE");
    let request = StaticPatchEditRequest::nop_instruction(THUNK_RVA, THUNK_BYTES, "Disable jump")
        .expect("valid NOP request");
    let plan = StaticPatchPlan::new(
        project.session().base_analysis().identity(),
        project.session().base_analysis(),
        vec![request],
    )
    .expect("valid patch plan");
    let output = temp.path().join("patched.exe");

    let receipt = services
        .publish_static_patch_new(&project, &plan, &output)
        .expect("publish new patched image");
    assert_eq!(receipt.path(), output);
    assert_eq!(
        receipt.output_identity().id,
        resymbol_core::BinaryId::digest(&fs::read(&output).expect("read output"))
    );
    assert_eq!(
        fs::read(&source).expect("read source after publish"),
        EXACT_PE
    );
    let before_failed_publish = directory_entries(temp.path());

    assert!(matches!(
        services.publish_static_patch_new(&project, &plan, &output),
        Err(StaticPatchError::TargetAlreadyExists { .. })
    ));
    assert_eq!(directory_entries(temp.path()), before_failed_publish);
    assert_eq!(
        &fs::read(&output).expect("read unchanged published output")
            [THUNK_FILE_OFFSET..THUNK_FILE_OFFSET + 5],
        &[0x90; 5]
    );
    assert_eq!(fs::read(&source).expect("read unchanged source"), EXACT_PE);
}

#[test]
fn competing_publications_create_exactly_one_deterministic_output() {
    let temp = TempDir::new().expect("create temp directory");
    let source = write_source(&temp);
    let services = AppServices::default();
    let project = services.analyze_binary(&source).expect("analyze exact PE");
    let identity = project.session().base_analysis().identity();
    let nop_plan = StaticPatchPlan::new(
        identity,
        project.session().base_analysis(),
        vec![
            StaticPatchEditRequest::nop_instruction(THUNK_RVA, THUNK_BYTES, "Disable jump")
                .expect("valid NOP request"),
        ],
    )
    .expect("valid NOP plan");
    let breakpoint_plan = StaticPatchPlan::new(
        identity,
        project.session().base_analysis(),
        vec![
            StaticPatchEditRequest::replace_bytes(0x1000, [0x48], [0xcc], "Set entry breakpoint")
                .expect("valid breakpoint request"),
        ],
    )
    .expect("valid breakpoint plan");
    let expected_images = [
        services
            .apply_static_patch(&project, &nop_plan)
            .expect("apply deterministic NOP plan"),
        services
            .apply_static_patch(&project, &breakpoint_plan)
            .expect("apply deterministic breakpoint plan"),
    ];
    assert_ne!(
        expected_images[0].output_identity(),
        expected_images[1].output_identity()
    );

    let output = temp.path().join("competing-patched.exe");
    assert!(!output.exists());
    let entries_before_race = directory_entries(temp.path());
    let barrier = Arc::new(Barrier::new(3));
    let first = {
        let services = services.clone();
        let project = Arc::clone(&project);
        let plan = nop_plan.clone();
        let output = output.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            services
                .publish_static_patch_new(&project, &plan, output)
                .map(|receipt| (0usize, receipt))
        })
    };
    let second = {
        let services = services.clone();
        let project = Arc::clone(&project);
        let plan = breakpoint_plan.clone();
        let output = output.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            services
                .publish_static_patch_new(&project, &plan, output)
                .map(|receipt| (1usize, receipt))
        })
    };

    barrier.wait();
    let outcomes = [
        first.join().expect("first publisher did not panic"),
        second.join().expect("second publisher did not panic"),
    ];
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "exactly one competing create-new publication must succeed: {outcomes:?}"
    );
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );

    let (winner, receipt) = outcomes
        .iter()
        .find_map(|outcome| outcome.as_ref().ok())
        .expect("one publisher succeeded");
    let expected = &expected_images[*winner];
    let published_bytes = fs::read(&output).expect("read winning publication");
    assert_eq!(published_bytes, expected.bytes());
    assert_eq!(receipt.path(), output);
    assert_eq!(receipt.output_identity(), expected.output_identity());
    assert_eq!(
        receipt.output_identity().id,
        resymbol_core::BinaryId::digest(&published_bytes)
    );

    match outcomes.iter().find_map(|outcome| outcome.as_ref().err()) {
        Some(StaticPatchError::TargetAlreadyExists { path }) => assert_eq!(path, &output),
        other => panic!("losing publication did not report no-clobber failure: {other:?}"),
    }
    assert_eq!(fs::read(&source).expect("read unchanged source"), EXACT_PE);

    let mut expected_entries = entries_before_race;
    expected_entries.insert(
        output
            .file_name()
            .expect("output has a file name")
            .to_os_string(),
    );
    assert_eq!(
        directory_entries(temp.path()),
        expected_entries,
        "competing publication left staging residue"
    );
}
