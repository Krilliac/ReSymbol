use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use resymbol_analysis::{
    ImportTarget, PeAnalysis, PeControlFlowTarget, PeDataReference, PeDirectCall, PeStringEncoding,
    PeThunk, analyze_pe, inspect_pe_codeview,
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
    shared_expectations: SharedExpectations,
    configurations: Vec<Configuration>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedExpectations {
    imports: BTreeSet<String>,
    exports: BTreeSet<String>,
    strings: Vec<ExpectedString>,
    rtti_type_names: BTreeSet<String>,
    required_unwind_exports: Vec<String>,
    required_data_references: Vec<ExpectedDataReference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    name: String,
    compile_flags: Vec<String>,
    artifacts: Vec<Artifact>,
    expectations: ConfigurationExpectations,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationExpectations {
    minimum_counts: MinimumCounts,
    required_calls: Vec<ExpectedCall>,
    required_thunks: Vec<ExpectedThunk>,
    required_internal_thunks: Vec<ExpectedInternalThunk>,
    forbidden_thunks: Vec<String>,
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
    codeview: ExpectedCodeView,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ExpectedCodeView {
    Rsds { pdb_path: String },
    Absent,
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
struct ExpectedInternalThunk {
    rva: u32,
    instruction_size: u8,
    target_rva: u32,
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

#[derive(Debug, PartialEq, Eq)]
struct NormalizedString {
    rva: u32,
    byte_size: u32,
    encoding: PeStringEncoding,
    value: String,
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedRuntimeFunction {
    begin_rva: u32,
    end_rva: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedRttiBaseClass {
    array_index: u32,
    decorated_name: String,
    name: String,
    num_contained_bases: u32,
    member_displacement: i32,
    vbtable_displacement: i32,
    displacement_inside_vbtable: i32,
    attributes: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedRttiVftable {
    rva: u32,
    offset: u32,
    constructor_displacement_offset: u32,
    decorated_class_name: String,
    class_name: String,
    hierarchy_attributes: u32,
    base_classes: Vec<NormalizedRttiBaseClass>,
    virtual_function_rvas: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedSemantics {
    imports: BTreeMap<String, u32>,
    exports: BTreeMap<String, u32>,
    runtime_functions: Vec<NormalizedRuntimeFunction>,
    direct_calls: Vec<PeDirectCall>,
    thunks: Vec<PeThunk>,
    strings: Vec<NormalizedString>,
    data_references: Vec<PeDataReference>,
    msvc_rtti_vftables: Vec<NormalizedRttiVftable>,
}

fn oracle() -> Oracle {
    serde_json::from_str(ORACLE_JSON).expect("fixture oracle is valid")
}

fn artifact_path(artifact: &Artifact) -> PathBuf {
    Path::new(FIXTURE_ROOT).join(&artifact.file)
}

fn checked_in_artifact_inventory() -> BTreeSet<String> {
    let directory = Path::new(FIXTURE_ROOT).join("artifacts");
    fs::read_dir(&directory)
        .expect("fixture artifact directory is readable")
        .map(|entry| {
            let entry = entry.expect("fixture artifact directory entry is readable");
            assert!(
                entry
                    .file_type()
                    .expect("fixture artifact type is readable")
                    .is_file(),
                "fixture artifact directory contains non-file entry {}",
                entry.path().display()
            );
            let name = entry
                .file_name()
                .into_string()
                .expect("fixture artifact filename is UTF-8");
            format!("artifacts/{name}")
        })
        .collect()
}

fn derived_pdb_path(artifact: &Artifact) -> String {
    let stem = Path::new(&artifact.file)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("fixture artifact has a UTF-8 filename stem");
    format!("{stem}.pdb")
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

fn import_rvas(analysis: &PeAnalysis) -> BTreeMap<String, u32> {
    let mut imports = BTreeMap::new();
    for entry in analysis.imports.iter().flat_map(|library| &library.entries) {
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
    imports
}

fn normalized_semantics(shared: &SharedExpectations, analysis: &PeAnalysis) -> NormalizedSemantics {
    let strings = analysis
        .strings
        .iter()
        .filter(|actual| {
            shared.strings.iter().any(|expected| {
                actual.encoding == expected.encoding && actual.value == expected.value
            })
        })
        .map(|string| NormalizedString {
            rva: string.rva,
            byte_size: string.byte_size,
            encoding: string.encoding,
            value: string.value.clone(),
        })
        .collect();

    NormalizedSemantics {
        imports: import_rvas(analysis),
        exports: export_rvas(analysis),
        runtime_functions: analysis
            .runtime_functions
            .iter()
            .map(|function| NormalizedRuntimeFunction {
                begin_rva: function.begin_rva,
                end_rva: function.end_rva,
            })
            .collect(),
        direct_calls: analysis.direct_calls.clone(),
        thunks: analysis.thunks.clone(),
        strings,
        data_references: analysis.data_references.clone(),
        msvc_rtti_vftables: analysis
            .msvc_rtti_vftables
            .iter()
            .map(|vftable| NormalizedRttiVftable {
                rva: vftable.rva,
                offset: vftable.offset,
                constructor_displacement_offset: vftable.constructor_displacement_offset,
                decorated_class_name: vftable.decorated_class_name.clone(),
                class_name: vftable.class_name.clone(),
                hierarchy_attributes: vftable.hierarchy_attributes,
                base_classes: vftable
                    .base_classes
                    .iter()
                    .map(|base| NormalizedRttiBaseClass {
                        array_index: base.array_index,
                        decorated_name: base.decorated_name.clone(),
                        name: base.name.clone(),
                        num_contained_bases: base.num_contained_bases,
                        member_displacement: base.member_displacement,
                        vbtable_displacement: base.vbtable_displacement,
                        displacement_inside_vbtable: base.displacement_inside_vbtable,
                        attributes: base.attributes,
                    })
                    .collect(),
                virtual_function_rvas: vftable.virtual_function_rvas.clone(),
            })
            .collect(),
    }
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

fn assert_shared_expectations(
    shared: &SharedExpectations,
    artifact: &Artifact,
    analysis: &PeAnalysis,
) {
    assert!(!analysis.code_recovery_scan_truncated);
    assert!(!analysis.string_recovery_scan_truncated);
    assert!(!analysis.data_reference_scan_truncated);
    assert!(!analysis.msvc_rtti_scan_truncated);

    let imports = import_rvas(analysis);
    assert_eq!(imports.len(), shared.imports.len());
    assert_eq!(
        imports.keys().cloned().collect::<BTreeSet<_>>(),
        shared.imports
    );

    let exports = export_rvas(analysis);
    let export_name_count = analysis
        .exports
        .iter()
        .map(|export| export.names.len())
        .sum::<usize>();
    assert_eq!(export_name_count, shared.exports.len());
    assert_eq!(
        exports.keys().cloned().collect::<BTreeSet<_>>(),
        shared.exports
    );

    for expected in &shared.strings {
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
    assert_eq!(rtti_types, shared.rtti_type_names);

    for export_name in &shared.required_unwind_exports {
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

    for expected in &shared.required_data_references {
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
}

fn assert_configuration_expectations(
    configuration: &Configuration,
    artifact: &Artifact,
    analysis: &PeAnalysis,
) {
    let expected = &configuration.expectations;
    let minimum = &expected.minimum_counts;
    for (label, actual, required) in [
        ("sections", analysis.sections.len(), minimum.sections),
        (
            "runtime functions",
            analysis.runtime_functions.len(),
            minimum.runtime_functions,
        ),
        (
            "direct calls",
            analysis.direct_calls.len(),
            minimum.direct_calls,
        ),
        ("thunks", analysis.thunks.len(), minimum.thunks),
        ("strings", analysis.strings.len(), minimum.strings),
        (
            "data references",
            analysis.data_references.len(),
            minimum.data_references,
        ),
        (
            "MSVC RTTI vftables",
            analysis.msvc_rtti_vftables.len(),
            minimum.msvc_rtti_vftables,
        ),
    ] {
        assert!(
            actual >= required,
            "{} {} configuration retained {actual} {label}; expected at least {required}",
            artifact.file,
            configuration.name
        );
    }

    let imports = import_rvas(analysis);
    let exports = export_rvas(analysis);
    for expected in &expected.required_calls {
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

    for expected in &expected.required_thunks {
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

    for expected in &expected.required_internal_thunks {
        assert!(
            exports.values().all(|rva| *rva != expected.rva),
            "{} declares exported RVA {:#x} as an internal thunk",
            artifact.file,
            expected.rva
        );
        let thunk = analysis
            .thunks
            .iter()
            .find(|thunk| thunk.rva == expected.rva)
            .unwrap_or_else(|| {
                panic!(
                    "{} did not retain internal thunk at RVA {:#x}",
                    artifact.file, expected.rva
                )
            });
        assert_eq!(thunk.instruction_size, expected.instruction_size);
        assert_eq!(
            thunk.target,
            PeControlFlowTarget::Function {
                rva: expected.target_rva
            }
        );
    }

    for export_name in &expected.forbidden_thunks {
        let source_rva = exports[export_name];
        assert!(
            analysis.thunks.iter().all(|thunk| thunk.rva != source_rva),
            "{} unexpectedly classified {export_name} as a thunk for {}",
            artifact.file,
            configuration.name
        );
    }

    for expected in &expected.required_rtti_vftables {
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
}

fn assert_codeview_expectation(artifact: &Artifact, bytes: &[u8]) {
    match &artifact.codeview {
        ExpectedCodeView::Rsds { pdb_path } => {
            assert_eq!(pdb_path, &derived_pdb_path(artifact));
            let inspection =
                inspect_pe_codeview(bytes).expect("symbolized fixture has one valid RSDS record");
            assert_eq!(inspection.rsds().pdb_path(), pdb_path.as_bytes());
        }
        ExpectedCodeView::Absent => {
            let error = inspect_pe_codeview(bytes)
                .expect_err("stripped fixture has no CodeView RSDS identity");
            let message = error.to_string();
            assert!(
                message.contains("no IMAGE_DEBUG_TYPE_CODEVIEW RSDS")
                    || message.contains("no debug-directory entry"),
                "unexpected stripped-fixture CodeView error: {message}"
            );
        }
    }
}

#[test]
fn open_msvc_corpus_matches_hashes_and_semantic_oracle() {
    let oracle = oracle();
    assert_eq!(oracle.schema_version, 3);
    assert_eq!(oracle.toolchain.family, "Microsoft Visual C++");
    assert_eq!(oracle.toolchain.target, "x86_64-pc-windows-msvc");
    assert!(!oracle.toolchain.toolset.is_empty());
    assert!(!oracle.toolchain.windows_sdk.is_empty());
    assert!(!oracle.toolchain.cl_file_version.is_empty());
    assert!(!oracle.toolchain.link_file_version.is_empty());

    assert_eq!(
        oracle
            .configurations
            .iter()
            .map(|configuration| configuration.name.as_str())
            .collect::<Vec<_>>(),
        ["optimized", "unoptimized"]
    );
    for configuration in &oracle.configurations {
        let actual_flags = configuration
            .compile_flags
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        match configuration.name.as_str() {
            "optimized" => assert_eq!(actual_flags, ["/O2", "/Ob1", "/Oi"]),
            "unoptimized" => assert_eq!(actual_flags, ["/Od", "/Ob0", "/Oi-"]),
            other => panic!("unexpected fixture configuration {other}"),
        }
        assert_eq!(configuration.artifacts.len(), 2);
        assert_eq!(
            configuration
                .artifacts
                .iter()
                .filter(|artifact| matches!(&artifact.codeview, ExpectedCodeView::Rsds { .. }))
                .count(),
            1
        );
        assert_eq!(
            configuration
                .artifacts
                .iter()
                .filter(|artifact| matches!(&artifact.codeview, ExpectedCodeView::Absent))
                .count(),
            1
        );
    }

    let expected_artifacts = BTreeSet::from([
        "artifacts/milestone2-stripped.exe".to_owned(),
        "artifacts/milestone2-symbolized.exe".to_owned(),
        "artifacts/milestone2-unoptimized-stripped.exe".to_owned(),
        "artifacts/milestone2-unoptimized-symbolized.exe".to_owned(),
    ]);
    let declared_artifact_count = oracle
        .configurations
        .iter()
        .map(|configuration| configuration.artifacts.len())
        .sum::<usize>();
    let declared_artifacts = oracle
        .configurations
        .iter()
        .flat_map(|configuration| &configuration.artifacts)
        .map(|artifact| artifact.file.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(declared_artifact_count, 4);
    assert_eq!(declared_artifacts.len(), declared_artifact_count);
    assert_eq!(declared_artifacts, expected_artifacts);
    assert_eq!(checked_in_artifact_inventory(), expected_artifacts);

    for configuration in &oracle.configurations {
        let mut analyzed = Vec::new();
        for artifact in &configuration.artifacts {
            let bytes = fs::read(artifact_path(artifact)).expect("checked-in fixture is readable");
            verify_artifact_bytes(artifact, &bytes).expect("checked-in fixture matches its oracle");
            assert_codeview_expectation(artifact, &bytes);
            let analysis = analyze_pe(&bytes).expect("checked-in fixture is a supported PE");
            assert_shared_expectations(&oracle.shared_expectations, artifact, &analysis);
            assert_configuration_expectations(configuration, artifact, &analysis);
            analyzed.push((artifact, analysis));
        }

        let symbolized = analyzed
            .iter()
            .find(|(artifact, _)| matches!(&artifact.codeview, ExpectedCodeView::Rsds { .. }))
            .expect("configuration has one symbolized fixture");
        let stripped = analyzed
            .iter()
            .find(|(artifact, _)| matches!(&artifact.codeview, ExpectedCodeView::Absent))
            .expect("configuration has one stripped fixture");
        assert_eq!(
            normalized_semantics(&oracle.shared_expectations, &symbolized.1),
            normalized_semantics(&oracle.shared_expectations, &stripped.1),
            "{} symbolized and stripped fixtures diverged semantically",
            configuration.name
        );
    }
}

#[test]
fn fixture_oracle_rejects_tampered_bytes_before_analysis() {
    let oracle = oracle();
    let artifact = &oracle.configurations[0].artifacts[0];
    let mut bytes = fs::read(artifact_path(artifact)).expect("checked-in fixture is readable");
    let last = bytes.last_mut().expect("fixture is nonempty");
    *last ^= 0x01;

    let error = verify_artifact_bytes(artifact, &bytes).expect_err("tampering changes identity");
    assert!(error.contains("SHA-256"));
}
