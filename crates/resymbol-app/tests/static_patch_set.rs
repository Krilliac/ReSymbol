#![forbid(unsafe_code)]

use std::fs;

use resymbol_app::{
    AppServices, MAX_STATIC_PATCH_SET_FILE_BYTES, STATIC_PATCH_SET_SCHEMA_VERSION,
    StaticPatchEditRequest, StaticPatchError, StaticPatchPlan, StaticPatchSetError,
    StaticPatchSetManifest,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const EXACT_PE: &[u8] =
    include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-symbolized.exe");
const ENTRY_RVA: u32 = 0x1000;
const THUNK_RVA: u32 = 0x1184;
const THUNK_BYTES: [u8; 5] = [0xe9, 0x03, 0x00, 0x00, 0x00];

fn project(temp: &TempDir) -> (AppServices, std::sync::Arc<resymbol_app::ProjectSnapshot>) {
    let source = temp.path().join("source.exe");
    fs::write(&source, EXACT_PE).expect("write exact source fixture");
    let services = AppServices::default();
    let project = services.analyze_binary(source).expect("analyze exact PE");
    (services, project)
}

fn requests_reversed() -> Vec<StaticPatchEditRequest> {
    vec![
        StaticPatchEditRequest::nop_instruction(THUNK_RVA, THUNK_BYTES, "Disable jump thunk")
            .expect("valid NOP request"),
        StaticPatchEditRequest::replace_bytes(
            ENTRY_RVA,
            [0x48],
            [0xcc],
            "Replace entry instruction byte",
        )
        .expect("valid replacement request"),
    ]
}

fn write_value(path: &std::path::Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).expect("encode test JSON")).expect("write test JSON");
}

#[test]
fn pure_manifest_construction_is_sorted_bounded_and_rederives_offsets() {
    let temp = TempDir::new().expect("temporary directory");
    let (_services, project) = project(&temp);
    let analysis = project.session().base_analysis();
    let manifest = StaticPatchSetManifest::new(analysis.identity(), analysis, requests_reversed())
        .expect("valid pure manifest");

    assert_eq!(manifest.source_identity(), analysis.identity());
    assert_eq!(manifest.edit_count(), 2);
    assert_eq!(manifest.requests()[0].rva(), ENTRY_RVA);
    assert_eq!(manifest.requests()[1].rva(), THUNK_RVA);

    let plan = StaticPatchPlan::new(
        manifest.source_identity(),
        analysis,
        manifest.requests().to_vec(),
    )
    .expect("fresh plan rederives file offsets");
    assert_eq!(plan.edits().len(), 2);
    assert!(plan.edits().iter().all(|edit| edit.file_offset() > 0));

    let overlapping = vec![
        StaticPatchEditRequest::replace_bytes(THUNK_RVA, [0xe9, 0x03], [0x90, 0x90], "first")
            .expect("first request"),
        StaticPatchEditRequest::replace_bytes(THUNK_RVA + 1, [0x03], [0xcc], "overlap")
            .expect("overlapping request shape"),
    ];
    assert!(matches!(
        StaticPatchSetManifest::new(analysis.identity(), analysis, overlapping),
        Err(StaticPatchSetError::InvalidPatchSet(
            StaticPatchError::OverlappingEdits { .. }
        ))
    ));
}

#[test]
fn appservices_save_is_reproducible_offset_free_and_loads_exact_requests() {
    let temp = TempDir::new().expect("temporary directory");
    let (services, project) = project(&temp);
    let first = temp.path().join("first.respatch.json");
    let second = temp.path().join("second.respatch.json");

    let saved = services
        .save_static_patch_set_new(&project, requests_reversed(), &first)
        .expect("save first patch set");
    services
        .save_static_patch_set_new(&project, requests_reversed(), &second)
        .expect("save second patch set");
    let first_bytes = fs::read(&first).expect("read first patch set");
    let second_bytes = fs::read(&second).expect("read second patch set");
    assert_eq!(first_bytes, second_bytes);
    let encoded = std::str::from_utf8(&first_bytes).expect("UTF-8 patch set");
    assert!(encoded.ends_with('\n'));
    assert!(encoded.contains(&format!(
        "\"schema_version\":{STATIC_PATCH_SET_SCHEMA_VERSION}"
    )));
    assert!(encoded.contains("\"source_identity\""));
    assert!(!encoded.contains("file_offset"));
    assert!(!encoded.contains("assembly"));
    assert!(
        encoded.find("\"rva\":4096").expect("entry RVA")
            < encoded.find("\"rva\":4484").expect("thunk RVA")
    );

    let loaded = services
        .load_static_patch_set(&project, &first)
        .expect("strict load");
    assert_eq!(loaded, saved);
    assert_eq!(
        loaded.source_identity(),
        project.session().base_analysis().identity()
    );
}

#[test]
fn strict_load_denies_unknown_fields_and_non_v1_schema() {
    let temp = TempDir::new().expect("temporary directory");
    let (services, project) = project(&temp);
    let valid = temp.path().join("valid.respatch.json");
    services
        .save_static_patch_set_new(&project, requests_reversed(), &valid)
        .expect("save strict fixture");
    let original: Value = serde_json::from_slice(&fs::read(&valid).expect("read strict fixture"))
        .expect("decode strict fixture");

    for (name, mut document) in [
        ("root", original.clone()),
        ("source", original.clone()),
        ("edit", original.clone()),
    ] {
        match name {
            "root" => {
                document["unexpected"] = json!(true);
            }
            "source" => {
                document["source_identity"]["unexpected"] = json!(true);
            }
            "edit" => {
                document["edits"][0]["unexpected"] = json!(true);
            }
            _ => unreachable!(),
        }
        let path = temp.path().join(format!("unknown-{name}.respatch.json"));
        write_value(&path, &document);
        assert!(matches!(
            services.load_static_patch_set(&project, &path),
            Err(StaticPatchSetError::Deserialize { source, .. })
                if source.to_string().contains("unknown field")
        ));
    }

    let mut future = original;
    future["schema_version"] = json!(STATIC_PATCH_SET_SCHEMA_VERSION + 1);
    let future_path = temp.path().join("future.respatch.json");
    write_value(&future_path, &future);
    assert!(matches!(
        services.load_static_patch_set(&project, &future_path),
        Err(StaticPatchSetError::UnsupportedSchemaVersion {
            expected: STATIC_PATCH_SET_SCHEMA_VERSION,
            found,
            ..
        }) if found == STATIC_PATCH_SET_SCHEMA_VERSION + 1
    ));
}

#[test]
fn import_requires_complete_current_identity_and_exact_nop_replacement() {
    let temp = TempDir::new().expect("temporary directory");
    let (services, project) = project(&temp);
    let valid = temp.path().join("valid.respatch.json");
    services
        .save_static_patch_set_new(&project, requests_reversed(), &valid)
        .expect("save strict fixture");
    let original: Value = serde_json::from_slice(&fs::read(&valid).expect("read strict fixture"))
        .expect("decode strict fixture");

    for (name, field, value) in [
        (
            "architecture",
            "architecture",
            json!("same-hash-wrong-arch"),
        ),
        ("image-base", "image_base", json!(0x1234_u64)),
        ("format", "format", json!("elf")),
    ] {
        let mut document = original.clone();
        document["source_identity"][field] = value;
        let path = temp.path().join(format!("wrong-{name}.respatch.json"));
        write_value(&path, &document);
        assert!(matches!(
            services.load_static_patch_set(&project, &path),
            Err(StaticPatchSetError::SourceIdentityMismatch { .. })
        ));
    }

    let mut wrong_nop = original;
    let nop_index = wrong_nop["edits"]
        .as_array()
        .expect("edit array")
        .iter()
        .position(|edit| edit["kind"] == "nop-instruction")
        .expect("NOP edit");
    wrong_nop["edits"][nop_index]["replacement"] = json!([0xcc, 0xcc, 0xcc, 0xcc, 0xcc]);
    let wrong_nop_path = temp.path().join("wrong-nop.respatch.json");
    write_value(&wrong_nop_path, &wrong_nop);
    assert!(matches!(
        services.load_static_patch_set(&project, &wrong_nop_path),
        Err(StaticPatchSetError::InvalidSerializedNopReplacement { rva: THUNK_RVA })
    ));
}

#[test]
fn patch_set_io_is_bounded_create_new_and_suffix_strict() {
    let temp = TempDir::new().expect("temporary directory");
    let (services, project) = project(&temp);
    let output = temp.path().join("patches.respatch.json");
    services
        .save_static_patch_set_new(&project, requests_reversed(), &output)
        .expect("create patch set");
    let original = fs::read(&output).expect("read original patch set");

    assert!(matches!(
        services.save_static_patch_set_new(&project, requests_reversed(), &output),
        Err(StaticPatchSetError::TargetAlreadyExists { .. })
    ));
    assert_eq!(fs::read(&output).expect("read preserved target"), original);

    let oversized = temp.path().join("oversized.respatch.json");
    let file = fs::File::create(&oversized).expect("create oversized file");
    file.set_len(MAX_STATIC_PATCH_SET_FILE_BYTES + 1)
        .expect("size oversized file");
    drop(file);
    assert!(matches!(
        services.load_static_patch_set(&project, &oversized),
        Err(StaticPatchSetError::DocumentTooLarge {
            limit: MAX_STATIC_PATCH_SET_FILE_BYTES,
            ..
        })
    ));

    let wrong_suffix = temp.path().join("patches.json");
    assert!(matches!(
        services.save_static_patch_set_new(&project, requests_reversed(), &wrong_suffix),
        Err(StaticPatchSetError::InvalidPath { .. })
    ));
    assert!(!wrong_suffix.exists());
}
