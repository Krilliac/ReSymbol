use resymbol_core::BinaryId;
use resymbol_export::{
    AttributedText, ExportAttribution, ExportBinary, ExportBinaryFormat, ExportControlFlowTarget,
    ExportDirectCall, ExportFunction, ExportGlobal, ExportName, ExportProducer, ExportProjection,
    ExportProvenance, ExportSubject, ExportThunk, ExportType, MarkdownError, ProjectionWarning,
    ProjectionWarningCode, render_markdown,
};

fn attribution(method: &str) -> ExportAttribution {
    ExportAttribution {
        confidence: 0.925,
        provenance: ExportProvenance {
            producer: ExportProducer::Core {
                component: "resymbol-analysis".to_owned(),
                version: "0.1.0".to_owned(),
            },
            method: method.to_owned(),
            run_id: Some("analysis-001".to_owned()),
        },
    }
}

fn text(value: &str, method: &str) -> AttributedText {
    AttributedText {
        text: value.to_owned(),
        attribution: attribution(method),
    }
}

fn name(source: &str, output_name: &str, method: &str) -> ExportName {
    ExportName {
        source: text(source, method),
        output_name: output_name.to_owned(),
    }
}

fn base_projection() -> ExportProjection {
    ExportProjection {
        schema_version: 3,
        binary: ExportBinary {
            id: BinaryId::digest(b"public Markdown integration fixture"),
            file_size: 0x1800,
            format: ExportBinaryFormat::Pe,
            architecture: "x86_64".to_owned(),
            image_base: 0x0000_0001_4000_0000,
            image_size: 0x8000,
        },
        functions: Vec::new(),
        globals: Vec::new(),
        types: Vec::new(),
        direct_calls: Vec::new(),
        thunks: Vec::new(),
        warnings: Vec::new(),
    }
}

fn realistic_projection() -> ExportProjection {
    let mut projection = base_projection();
    projection.functions = vec![
        ExportFunction {
            rva: 0x100,
            entry_attribution: Some(attribution("runtime-function")),
            size: Some(0x20),
            size_attribution: Some(attribution("runtime-function")),
            selected_name: Some(name(
                "ReSymbol::recover_symbols",
                "ReSymbol__recover_symbols",
                "export-name",
            )),
            alternate_names: vec![text("ResolveSymbols", "pattern-match")],
            prototypes: vec![text(
                "void recover_symbols(SymbolRecord* record)",
                "prototype-recovery",
            )],
            class_memberships: vec![text("ReSymbolEngine", "msvc-rtti")],
        },
        ExportFunction {
            rva: 0x200,
            entry_attribution: Some(attribution("runtime-function")),
            size: Some(0x10),
            size_attribution: Some(attribution("runtime-function")),
            selected_name: Some(name("ResolvedTarget", "ResolvedTarget", "export-name")),
            alternate_names: Vec::new(),
            prototypes: Vec::new(),
            class_memberships: Vec::new(),
        },
        ExportFunction {
            rva: 0x300,
            entry_attribution: Some(attribution("thunk-seed")),
            size: Some(0x5),
            size_attribution: Some(attribution("thunk-seed")),
            selected_name: Some(name("ImportThunk", "ImportThunk", "export-name")),
            alternate_names: Vec::new(),
            prototypes: Vec::new(),
            class_memberships: Vec::new(),
        },
    ];
    projection.globals = vec![ExportGlobal {
        rva: 0x500,
        size: Some(8),
        size_attribution: Some(attribution("data-directory")),
        selected_name: Some(name("g_symbol_count", "g_symbol_count", "global-name")),
        alternate_names: vec![text("SymbolCount", "pattern-match")],
    }];
    projection.types = vec![ExportType {
        key: "type.SymbolRecord".to_owned(),
        selected_name: Some(name("SymbolRecord", "SymbolRecord", "rtti-name")),
        alternate_names: vec![text("RecoveredSymbol", "type-alias")],
        definitions: vec![text(
            "struct SymbolRecord { unsigned long long rva; };",
            "type-recovery",
        )],
    }];
    projection.direct_calls = vec![ExportDirectCall {
        caller_rva: 0x100,
        call_site_rva: 0x108,
        target: ExportControlFlowTarget::Function { rva: 0x200 },
        attribution: attribution("direct-call"),
    }];
    projection.thunks = vec![ExportThunk {
        rva: 0x300,
        target: ExportControlFlowTarget::ImportIat { iat_rva: 0x600 },
        attribution: attribution("import-thunk"),
    }];
    projection.warnings = vec![ProjectionWarning {
        code: ProjectionWarningCode::NameRewritten,
        subject: Some(ExportSubject::Function { rva: 0x100 }),
        occurrences: 1,
        message: "selected name was rewritten to a portable debugger identifier".to_owned(),
    }];
    projection
}

#[test]
fn public_writer_renders_every_category_deterministically() {
    let projection = realistic_projection();
    projection.validate().expect("fixture projection is valid");

    let first = render_markdown(&projection).expect("render realistic report");
    let second = render_markdown(&projection).expect("render realistic report again");

    assert_eq!(first, second);
    assert!(first.starts_with("# ReSymbol Analysis Report\n"));
    for expected in [
        "| Functions | 3 |",
        "| Warning groups | 1 |",
        r"ReSymbol::recover\_symbols → ReSymbol\_\_recover\_symbols",
        "aliases: ResolveSymbols",
        "struct SymbolRecord { unsigned long long rva; };",
        r"| 0x500 | 0x8 | g\_symbol\_count |",
        "| 0x100 | 0x108 | function 0x200 |",
        "| 0x300 | import IAT 0x600 |",
        "name-rewritten",
        "function 0x100",
    ] {
        assert!(
            first.contains(expected),
            "missing report content: {expected}"
        );
    }
}

#[test]
fn public_writer_enforces_the_exact_function_row_limit() {
    let mut projection = base_projection();
    projection.functions = (0_u64..1_025)
        .map(|index| ExportFunction {
            rva: 0x100 + index * 0x10,
            entry_attribution: Some(attribution("runtime-function")),
            size: None,
            size_attribution: None,
            selected_name: None,
            alternate_names: Vec::new(),
            prototypes: Vec::new(),
            class_memberships: Vec::new(),
        })
        .collect();
    projection.validate().expect("1,025 functions are valid");

    let report = render_markdown(&projection).expect("render bounded report");
    let rendered_function_rows = report
        .lines()
        .filter(|line| line.starts_with("| 0x"))
        .count();

    assert_eq!(rendered_function_rows, 1_024);
    assert!(report.contains("| 0x40f0 |"));
    assert!(!report.contains("| 0x4100 |"));
    assert!(
        report.contains("_Showing 1024 of 1025 rows; 1 omitted by the 1,024-row report limit._")
    );
}

#[test]
fn public_writer_escapes_hostile_markdown_and_raw_html() {
    let mut projection = realistic_projection();
    projection.binary.architecture = "<script>alert(1)</script>|*arch*".to_owned();
    let function = &mut projection.functions[0];
    let selected_name = function.selected_name.as_mut().expect("selected name");
    selected_name.source.attribution.provenance.method = "<method>|*entry*".to_owned();
    selected_name.source.text = "<img src=x>|`*_[]()!~\\safe".to_owned();
    function.prototypes[0].text = "<svg onload=alert(1)>|**prototype**".to_owned();
    projection.globals[0]
        .selected_name
        .as_mut()
        .expect("selected global name")
        .source
        .text = "<iframe>|_global_".to_owned();
    projection.types[0].key = "<details>|type".to_owned();
    projection
        .validate()
        .expect("hostile text remains valid text");

    let report = render_markdown(&projection).expect("render escaped report");

    for raw in ["<script>", "<img", "<svg", "<iframe>", "<details>"] {
        assert!(!report.contains(raw), "raw markup leaked: {raw}");
    }
    for escaped in [
        "&lt;script&gt;alert\\(1\\)&lt;/script&gt;",
        "&lt;img src=x&gt;",
        "&lt;svg onload=alert\\(1\\)&gt;",
        "&lt;iframe&gt;\\|\\_global\\_",
        "&lt;details&gt;\\|type",
        "method=&lt;method&gt;\\|\\*entry\\*",
    ] {
        assert!(report.contains(escaped), "missing escaping: {escaped}");
    }
}

#[test]
fn public_writer_truncates_utf8_cells_on_a_scalar_boundary() {
    let mut projection = realistic_projection();
    projection.functions[0]
        .selected_name
        .as_mut()
        .expect("selected name")
        .source
        .text = format!("{}{}", "a".repeat(237), "終".repeat(20));
    projection
        .validate()
        .expect("long UTF-8 source name remains projection-valid");

    let report = render_markdown(&projection).expect("render truncated UTF-8 cell");
    let complete_boundary_marker = format!("{}終{}", "a".repeat(237), r"… \[truncated\]");

    assert!(report.contains(&complete_boundary_marker));
    assert!(!report.contains('�'));
    assert!(!report.contains(&format!("{}終終…", "a".repeat(237))));
}

#[test]
fn public_writer_rejects_an_invalid_projection() {
    let mut projection = realistic_projection();
    projection.schema_version = 2;

    assert!(matches!(
        render_markdown(&projection),
        Err(MarkdownError::InvalidProjection(_))
    ));
}
