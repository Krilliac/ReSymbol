use resymbol_core::BinaryId;
use resymbol_export::{
    AttributedText, ExportAttribution, ExportBinary, ExportBinaryFormat, ExportFunction,
    ExportGlobal, ExportLossCode, ExportLossReport, ExportName, ExportProducer, ExportProjection,
    ExportProvenance, ExportTarget, ExportType, MAX_EXPORT_LOSS_ITEMS,
    MAX_EXPORT_LOSS_MESSAGE_BYTES, ProjectionWarning, ProjectionWarningCode, render_ghidra_java,
    render_ida_python,
};

fn attribution() -> ExportAttribution {
    ExportAttribution {
        confidence: 0.9,
        provenance: ExportProvenance {
            producer: ExportProducer::Core {
                component: "loss-report-test".to_owned(),
                version: "1.0.0".to_owned(),
            },
            method: "fixture".to_owned(),
            run_id: None,
        },
    }
}

fn text(value: impl Into<String>) -> AttributedText {
    AttributedText {
        text: value.into(),
        attribution: attribution(),
    }
}

fn name(source: &str, output: &str) -> ExportName {
    ExportName {
        source: text(source),
        output_name: output.to_owned(),
    }
}

fn empty_projection() -> ExportProjection {
    ExportProjection {
        schema_version: 6,
        binary: ExportBinary {
            id: BinaryId::digest(b"target loss report fixture"),
            file_size: 0x800,
            format: ExportBinaryFormat::Pe,
            architecture: "x86_64".to_owned(),
            image_base: 0x1_4000_0000,
            image_size: 0x4000,
        },
        functions: Vec::new(),
        globals: Vec::new(),
        types: Vec::new(),
        direct_calls: Vec::new(),
        thunks: Vec::new(),
        strings: Vec::new(),
        data_references: Vec::new(),
        warnings: Vec::new(),
    }
}

fn occurrence(report: &ExportLossReport, code: ExportLossCode) -> u64 {
    report
        .items()
        .iter()
        .find(|item| item.code() == code)
        .map_or(0, |item| item.occurrences())
}

#[test]
fn machine_codes_have_stable_bounded_serialized_spellings() {
    let codes = [
        ExportLossCode::ProjectionMetadataOmitted,
        ExportLossCode::ReportRowOmitted,
        ExportLossCode::CandidateDetailOmitted,
        ExportLossCode::TextTruncated,
        ExportLossCode::AttributionOmitted,
        ExportLossCode::FunctionOmitted,
        ExportLossCode::FunctionSizeOmitted,
        ExportLossCode::GlobalOmitted,
        ExportLossCode::GlobalSizeOmitted,
        ExportLossCode::AddressKindCollision,
        ExportLossCode::OriginalNameOmitted,
        ExportLossCode::AlternateNameOmitted,
        ExportLossCode::PrototypeOmitted,
        ExportLossCode::ClassMembershipOmitted,
        ExportLossCode::TypeOmitted,
        ExportLossCode::TypeDefinitionOmitted,
        ExportLossCode::DirectCallOmitted,
        ExportLossCode::ThunkOmitted,
        ExportLossCode::StringOmitted,
        ExportLossCode::DataReferenceOmitted,
        ExportLossCode::ProjectionWarningOmitted,
    ];
    assert_eq!(codes.len(), MAX_EXPORT_LOSS_ITEMS);
    for code in codes {
        assert_eq!(
            serde_json::to_string(&code).expect("serialize machine code"),
            format!("\"{}\"", code.as_str())
        );
    }
}

fn collision_projection() -> ExportProjection {
    let mut projection = empty_projection();
    projection.functions = vec![
        ExportFunction {
            rva: 0x100,
            entry_attribution: Some(attribution()),
            size: None,
            size_attribution: None,
            selected_name: Some(name("original::function", "original__function")),
            alternate_names: vec![text("function_alias")],
            prototypes: vec![text("void function()")],
            class_memberships: vec![text("ExampleClass")],
        },
        ExportFunction {
            rva: 0x200,
            entry_attribution: Some(attribution()),
            size: Some(0x20),
            size_attribution: Some(attribution()),
            selected_name: None,
            alternate_names: Vec::new(),
            prototypes: Vec::new(),
            class_memberships: Vec::new(),
        },
    ];
    projection.globals = vec![
        ExportGlobal {
            rva: 0x100,
            size: None,
            size_attribution: None,
            selected_name: Some(name("same_rva_global", "same_rva_global")),
            alternate_names: Vec::new(),
        },
        ExportGlobal {
            rva: 0x300,
            size: Some(8),
            size_attribution: Some(attribution()),
            selected_name: None,
            alternate_names: Vec::new(),
        },
    ];
    projection.types = vec![ExportType {
        key: "type.Example".to_owned(),
        selected_name: Some(name("Example", "Example")),
        alternate_names: vec![text("ExampleAlias")],
        definitions: vec![text("struct Example {};")],
    }];
    projection
}

#[test]
fn json_is_the_loss_aware_reference_target() {
    let mut projection = collision_projection();
    projection.warnings.push(ProjectionWarning {
        code: ProjectionWarningCode::UnsupportedAssertion,
        subject: None,
        occurrences: 3,
        message: "claim assertion is not representable in the neutral export model".to_owned(),
    });
    let report = ExportLossReport::for_projection(ExportTarget::Json, &projection)
        .expect("valid loss report");

    assert!(report.is_empty());
    assert_eq!(report.occurrence_count(), 0);
}

#[test]
fn public_symbol_targets_follow_named_selection_and_collision_rules() {
    let projection = collision_projection();
    for target in [ExportTarget::Map, ExportTarget::Pdb] {
        let report = ExportLossReport::for_projection(target, &projection).expect("loss report");
        assert_eq!(occurrence(&report, ExportLossCode::FunctionOmitted), 1);
        assert_eq!(occurrence(&report, ExportLossCode::FunctionSizeOmitted), 1);
        assert_eq!(occurrence(&report, ExportLossCode::GlobalOmitted), 2);
        assert_eq!(occurrence(&report, ExportLossCode::AddressKindCollision), 1);
        assert_eq!(occurrence(&report, ExportLossCode::GlobalSizeOmitted), 1);
        assert_eq!(occurrence(&report, ExportLossCode::OriginalNameOmitted), 1);
    }
}

#[test]
fn mutation_targets_retain_unnamed_sizes_but_omit_entry_only_functions() {
    let mut projection = collision_projection();
    projection.functions.push(ExportFunction {
        rva: 0x400,
        entry_attribution: Some(attribution()),
        size: None,
        size_attribution: None,
        selected_name: None,
        alternate_names: Vec::new(),
        prototypes: Vec::new(),
        class_memberships: Vec::new(),
    });

    for target in [ExportTarget::IdaPython, ExportTarget::GhidraJava] {
        let report = ExportLossReport::for_projection(target, &projection).expect("loss report");
        assert_eq!(occurrence(&report, ExportLossCode::FunctionOmitted), 1);
        assert_eq!(occurrence(&report, ExportLossCode::FunctionSizeOmitted), 0);
        assert_eq!(occurrence(&report, ExportLossCode::AddressKindCollision), 1);
        assert_eq!(occurrence(&report, ExportLossCode::GlobalOmitted), 2);
    }

    let ida = render_ida_python(&projection).expect("IDA script");
    let ghidra = render_ghidra_java(&projection, "ReSymbolLossRules").expect("Ghidra script");
    assert!(ida.contains("(0x200, 0x20, None)"));
    assert!(!ida.contains("0x400"));
    assert!(ghidra.contains("F,200,20,"));
    assert!(!ghidra.contains("F,400,"));
}

#[test]
fn entry_only_function_does_not_suppress_a_same_rva_named_global() {
    let mut projection = empty_projection();
    projection.functions.push(ExportFunction {
        rva: 0x100,
        entry_attribution: Some(attribution()),
        size: None,
        size_attribution: None,
        selected_name: None,
        alternate_names: Vec::new(),
        prototypes: Vec::new(),
        class_memberships: Vec::new(),
    });
    projection.globals.push(ExportGlobal {
        rva: 0x100,
        size: None,
        size_attribution: None,
        selected_name: Some(name("retained_global", "retained_global")),
        alternate_names: Vec::new(),
    });

    for target in [ExportTarget::IdaPython, ExportTarget::GhidraJava] {
        let report = ExportLossReport::for_projection(target, &projection).expect("loss report");
        assert_eq!(occurrence(&report, ExportLossCode::FunctionOmitted), 1);
        assert_eq!(occurrence(&report, ExportLossCode::GlobalOmitted), 0);
        assert_eq!(occurrence(&report, ExportLossCode::AddressKindCollision), 0);
    }
    let ida = render_ida_python(&projection).expect("IDA script");
    assert!(ida.contains("(0x100, \"retained_global\")"));
}

#[test]
fn narrow_targets_report_unsupported_semantics_by_stable_category() {
    let projection = collision_projection();
    for target in [
        ExportTarget::Map,
        ExportTarget::Pdb,
        ExportTarget::IdaPython,
        ExportTarget::GhidraJava,
    ] {
        let report = ExportLossReport::for_projection(target, &projection).expect("loss report");
        assert_eq!(occurrence(&report, ExportLossCode::AlternateNameOmitted), 2);
        assert_eq!(occurrence(&report, ExportLossCode::PrototypeOmitted), 1);
        assert_eq!(
            occurrence(&report, ExportLossCode::ClassMembershipOmitted),
            1
        );
        assert_eq!(occurrence(&report, ExportLossCode::TypeOmitted), 1);
        assert_eq!(
            occurrence(&report, ExportLossCode::TypeDefinitionOmitted),
            1
        );
    }
}

#[test]
fn markdown_reports_only_its_actual_candidate_and_text_limits() {
    let mut projection = empty_projection();
    projection.functions.push(ExportFunction {
        rva: 0x100,
        entry_attribution: Some(attribution()),
        size: None,
        size_attribution: None,
        selected_name: None,
        alternate_names: vec![text("a".repeat(81)), text("b"), text("c"), text("d")],
        prototypes: Vec::new(),
        class_memberships: Vec::new(),
    });
    let report =
        ExportLossReport::for_projection(ExportTarget::Markdown, &projection).expect("loss report");

    assert_eq!(
        occurrence(&report, ExportLossCode::CandidateDetailOmitted),
        1
    );
    assert_eq!(occurrence(&report, ExportLossCode::TextTruncated), 1);
    assert_eq!(occurrence(&report, ExportLossCode::AttributionOmitted), 4);
    assert_eq!(occurrence(&report, ExportLossCode::FunctionOmitted), 0);
}

#[test]
fn reports_are_deterministic_bounded_and_never_expand_per_symbol() {
    let mut projection = empty_projection();
    projection.binary.image_size = 0x10_000;
    projection.functions = (1_u64..=1_025)
        .map(|rva| ExportFunction {
            rva,
            entry_attribution: Some(attribution()),
            size: None,
            size_attribution: None,
            selected_name: None,
            alternate_names: Vec::new(),
            prototypes: Vec::new(),
            class_memberships: Vec::new(),
        })
        .collect();

    for target in [
        ExportTarget::Json,
        ExportTarget::Markdown,
        ExportTarget::Map,
        ExportTarget::Pdb,
        ExportTarget::IdaPython,
        ExportTarget::GhidraJava,
    ] {
        let first = ExportLossReport::for_projection(target, &projection).expect("loss report");
        let second = ExportLossReport::for_projection(target, &projection).expect("loss report");
        assert_eq!(first, second);
        assert!(first.items().len() <= MAX_EXPORT_LOSS_ITEMS);
        assert!(
            first
                .items()
                .iter()
                .all(|item| item.message().len() <= MAX_EXPORT_LOSS_MESSAGE_BYTES)
        );
        let json = serde_json::to_string(&first).expect("serialize report");
        assert!(
            json.len() < 8_192,
            "unbounded report for {target}: {}",
            json.len()
        );
        assert!(!json.contains("\"rva\""));
    }

    let markdown = ExportLossReport::for_projection(ExportTarget::Markdown, &projection)
        .expect("Markdown loss report");
    assert_eq!(occurrence(&markdown, ExportLossCode::ReportRowOmitted), 1);
}

#[test]
fn invalid_projection_is_rejected_before_loss_analysis() {
    let mut projection = empty_projection();
    projection.schema_version = 5;
    assert!(ExportLossReport::for_projection(ExportTarget::Json, &projection).is_err());
}
