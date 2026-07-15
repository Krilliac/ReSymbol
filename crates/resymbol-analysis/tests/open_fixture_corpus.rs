use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use resymbol_analysis::{
    ImportTarget, PeAnalysis, PeControlFlowTarget, PeStringEncoding, analyze_pe,
    inspect_pe_codeview,
};
use resymbol_core::BinaryId;
use serde::Deserialize;

const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/pe-x64-msvc");
const ORACLE_JSON: &str = include_str!("../../../fixtures/pe-x64-msvc/expected.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Oracle {
    schema_version: u32,
    toolchain: Toolchain,
    artifacts: Vec<Artifact>,
    minimum_counts: MinimumCounts,
    imports: BTreeSet<String>,
    exports: BTreeSet<String>,
    strings: Vec<ExpectedString>,
    rtti_type_names: BTreeSet<String>,
    required_unwind_exports: Vec<String>,
    required_calls: Vec<ExpectedCall>,
    required_data_references: Vec<ExpectedDataReference>,
    required_thunks: Vec<ExpectedThunk>,
    required_rtti_vftables: Vec<ExpectedRttiVftable>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Toolchain {
    family: String,
    target: String,
    toolset: String,
    windows_sdk: String,
    cl_file_version: String,
    link_file_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    file: String,
    sha256: String,
    file_size: usize,
    has_codeview_rsds: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MinimumCounts {
    sections: usize,
    runtime_functions: usize,
    direct_calls: usize,
    thunks: usize,
    strings: usize,
    data_references: usize,
    msvc_rtti_vftables: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedString {
    encoding: PeStringEncoding,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedThunk {
    source_export: String,
    instruction_size: u8,
    target: ExpectedControlFlowTarget,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedCall {
    caller_export: String,
    call_site_offset: u32,
    instruction_size: u8,
    target: ExpectedControlFlowTarget,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedDataReference {
    caller_export: String,
    target_export: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedRttiVftable {
    rva: u32,
    class_name: String,
    base_class_names: Vec<String>,
    virtual_function_rvas: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ExpectedControlFlowTarget {
    Export { name: String },
    Import { name: String },
}

fn oracle() -> Oracle {
    serde_json::from_str(ORACLE_JSON).expect("fixture oracle is valid")
}

fn artifact_path(artifact: &Artifact) -> PathBuf {
    Path::new(FIXTURE_ROOT).join(&artifact.file)
}

fn verify_artifact_bytes(artifact: &Artifact, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != artifact.file_size {
        return Err(format!(
            "{} has {} bytes; expected {}",
            artifact.file,
            bytes.len(),
            artifact.file_size
        ));
    }
    let actual = BinaryId::digest(bytes).to_string();
    if actual != artifact.sha256 {
        return Err(format!(
            "{} has SHA-256 {actual}; expected {}",
            artifact.file, artifact.sha256
        ));
    }
    Ok(())
}

fn export_rvas(analysis: &PeAnalysis) -> BTreeMap<String, u32> {
    let mut exports = BTreeMap::new();
    for export in &analysis.exports {
        let Some(rva) = export.address_rva else {
            continue;
        };
        for name in &export.names {
            assert!(
                exports.insert(name.name.clone(), rva).is_none(),
                "fixture contains duplicate export name {}",
                name.name
            );
        }
    }
    exports
}

fn resolve_expected_target(
    expected: &ExpectedControlFlowTarget,
    exports: &BTreeMap<String, u32>,
    imports: &BTreeMap<String, u32>,
) -> PeControlFlowTarget {
    match expected {
        ExpectedControlFlowTarget::Export { name } => PeControlFlowTarget::Function {
            rva: *exports
                .get(name)
                .unwrap_or_else(|| panic!("oracle names unknown export {name}")),
        },
        ExpectedControlFlowTarget::Import { name } => PeControlFlowTarget::ImportIat {
            iat_rva: *imports
                .get(name)
                .unwrap_or_else(|| panic!("oracle names unknown import {name}")),
        },
    }
}

fn assert_semantic_oracle(oracle: &Oracle, artifact: &Artifact, analysis: &PeAnalysis) {
    assert!(!analysis.code_recovery_scan_truncated);
    assert!(!analysis.string_recovery_scan_truncated);
    assert!(!analysis.data_reference_scan_truncated);
    assert!(!analysis.msvc_rtti_scan_truncated);
    assert!(analysis.sections.len() >= oracle.minimum_counts.sections);
    assert!(analysis.runtime_functions.len() >= oracle.minimum_counts.runtime_functions);
    assert!(analysis.direct_calls.len() >= oracle.minimum_counts.direct_calls);
    assert!(analysis.thunks.len() >= oracle.minimum_counts.thunks);
    assert!(analysis.strings.len() >= oracle.minimum_counts.strings);
    assert!(analysis.data_references.len() >= oracle.minimum_counts.data_references);
    assert!(analysis.msvc_rtti_vftables.len() >= oracle.minimum_counts.msvc_rtti_vftables);

    let mut imports = BTreeMap::new();
    let mut import_entry_count = 0_usize;
    for entry in analysis.imports.iter().flat_map(|library| &library.entries) {
        import_entry_count += 1;
        match &entry.target {
            ImportTarget::Name { name, .. } => assert!(
                imports.insert(name.clone(), entry.iat_rva).is_none(),
                "fixture contains duplicate import name {name}"
            ),
            ImportTarget::Ordinal { ordinal } => {
                panic!("fixture unexpectedly imports ordinal {ordinal}")
            }
        }
    }
    assert_eq!(import_entry_count, oracle.imports.len());
    assert_eq!(
        imports.keys().cloned().collect::<BTreeSet<_>>(),
        oracle.imports
    );

    let exports = export_rvas(analysis);
    let export_name_count = analysis
        .exports
        .iter()
        .map(|export| export.names.len())
        .sum::<usize>();
    assert_eq!(export_name_count, oracle.exports.len());
    assert_eq!(
        exports.keys().cloned().collect::<BTreeSet<_>>(),
        oracle.exports
    );

    for expected in &oracle.strings {
        assert!(
            analysis
                .strings
                .iter()
                .any(|value| value.encoding == expected.encoding && value.value == expected.value),
            "{} did not recover {:?} string {:?}",
            artifact.file,
            expected.encoding,
            expected.value
        );
    }

    let mut rtti_types = BTreeSet::new();
    for vftable in &analysis.msvc_rtti_vftables {
        rtti_types.insert(vftable.class_name.clone());
        rtti_types.extend(vftable.base_classes.iter().map(|base| base.name.clone()));
    }
    assert_eq!(rtti_types, oracle.rtti_type_names);

    for export_name in &oracle.required_unwind_exports {
        let begin_rva = exports[export_name];
        assert!(
            analysis
                .runtime_functions
                .iter()
                .any(|function| function.begin_rva == begin_rva),
            "{} did not retain unwind coverage for {export_name}",
            artifact.file
        );
    }

    for expected in &oracle.required_calls {
        let caller_rva = exports[&expected.caller_export];
        let call_site_rva = caller_rva
            .checked_add(expected.call_site_offset)
            .expect("oracle call-site offset fits RVA");
        let target = resolve_expected_target(&expected.target, &exports, &imports);
        assert!(
            analysis.direct_calls.iter().any(|call| {
                call.caller_rva == caller_rva
                    && call.call_site_rva == call_site_rva
                    && call.instruction_size == expected.instruction_size
                    && call.target == target
            }),
            "{} did not retain the required call from {} at +{:#x}",
            artifact.file,
            expected.caller_export,
            expected.call_site_offset
        );
    }

    for expected in &oracle.required_data_references {
        let caller_rva = exports[&expected.caller_export];
        let target_rva = exports[&expected.target_export];
        assert!(
            analysis.data_references.iter().any(|reference| {
                reference.caller_rva == caller_rva && reference.target_rva == target_rva
            }),
            "{} did not retain the required data reference from {} to {}",
            artifact.file,
            expected.caller_export,
            expected.target_export
        );
    }

    for expected in &oracle.required_thunks {
        let source_rva = exports[&expected.source_export];
        let thunk = analysis
            .thunks
            .iter()
            .find(|thunk| thunk.rva == source_rva)
            .unwrap_or_else(|| {
                panic!(
                    "{} did not retain thunk {}",
                    artifact.file, expected.source_export
                )
            });
        assert_eq!(thunk.instruction_size, expected.instruction_size);
        assert_eq!(
            thunk.target,
            resolve_expected_target(&expected.target, &exports, &imports)
        );
    }

    for expected in &oracle.required_rtti_vftables {
        let actual = analysis
            .msvc_rtti_vftables
            .iter()
            .find(|vftable| vftable.rva == expected.rva)
            .unwrap_or_else(|| {
                panic!(
                    "{} did not retain RTTI vftable at RVA {:#x}",
                    artifact.file, expected.rva
                )
            });
        assert_eq!(actual.class_name, expected.class_name);
        assert_eq!(
            actual
                .base_classes
                .iter()
                .map(|base| base.name.clone())
                .collect::<Vec<_>>(),
            expected.base_class_names
        );
        assert_eq!(actual.virtual_function_rvas, expected.virtual_function_rvas);
    }

    if artifact.has_codeview_rsds {
        let inspection = inspect_pe_codeview(&fs::read(artifact_path(artifact)).expect("fixture"))
            .expect("symbolized fixture has one valid RSDS record");
        assert_eq!(inspection.rsds().pdb_path(), b"milestone2-symbolized.pdb");
    } else {
        let error = inspect_pe_codeview(&fs::read(artifact_path(artifact)).expect("fixture"))
            .expect_err("stripped fixture has no CodeView RSDS identity");
        let message = error.to_string();
        assert!(
            message.contains("no IMAGE_DEBUG_TYPE_CODEVIEW RSDS")
                || message.contains("no debug-directory entry"),
            "unexpected stripped-fixture CodeView error: {message}"
        );
    }
}

#[test]
fn open_msvc_corpus_matches_hashes_and_semantic_oracle() {
    let oracle = oracle();
    assert_eq!(oracle.schema_version, 2);
    assert_eq!(oracle.toolchain.family, "Microsoft Visual C++");
    assert_eq!(oracle.toolchain.target, "x86_64-pc-windows-msvc");
    assert!(!oracle.toolchain.toolset.is_empty());
    assert!(!oracle.toolchain.windows_sdk.is_empty());
    assert!(!oracle.toolchain.cl_file_version.is_empty());
    assert!(!oracle.toolchain.link_file_version.is_empty());
    assert_eq!(oracle.artifacts.len(), 2);

    for artifact in &oracle.artifacts {
        let bytes = fs::read(artifact_path(artifact)).expect("checked-in fixture is readable");
        verify_artifact_bytes(artifact, &bytes).expect("checked-in fixture matches its oracle");
        let analysis = analyze_pe(&bytes).expect("checked-in fixture is a supported PE");
        assert_semantic_oracle(&oracle, artifact, &analysis);
    }
}

#[test]
fn fixture_oracle_rejects_tampered_bytes_before_analysis() {
    let oracle = oracle();
    let artifact = &oracle.artifacts[0];
    let mut bytes = fs::read(artifact_path(artifact)).expect("checked-in fixture is readable");
    let last = bytes.last_mut().expect("fixture is nonempty");
    *last ^= 0x01;

    let error = verify_artifact_bytes(artifact, &bytes).expect_err("tampering changes identity");
    assert!(error.contains("SHA-256"));
}
