use resymbol_core::{
    BinaryFormat, BinaryId, BinaryIdentity, ClaimProducer, ClaimProvenance, Confidence, Evidence,
    EvidenceKind, SymbolAssertion, SymbolClaim, SymbolGraph, SymbolSubject, plugin_api::PluginId,
};
use resymbol_export::{
    ExportError, ExportProducer, ExportProjection, ExportSubject, MAX_NAME_BYTES,
    MAX_OUTPUT_NAME_BYTES, ProjectionWarningCode,
};

fn binary() -> BinaryIdentity {
    BinaryIdentity {
        id: BinaryId::digest(b"projection fixture binary"),
        size: 0x800,
        format: BinaryFormat::Pe,
        architecture: "x86_64".to_owned(),
        image_base: 0x0000_0001_4000_0000,
    }
}

fn core(method: &str) -> ClaimProvenance {
    ClaimProvenance {
        producer: ClaimProducer::Core {
            component: "resymbol-analysis".to_owned(),
            version: "0.1.0".to_owned(),
        },
        method: method.to_owned(),
        run_id: None,
    }
}

fn plugin(method: &str) -> ClaimProvenance {
    ClaimProvenance {
        producer: ClaimProducer::Plugin {
            id: PluginId::new("dev.resymbol.projection-test").expect("valid plugin id"),
            version: "1.2.3".to_owned(),
        },
        method: method.to_owned(),
        run_id: Some("run-001".to_owned()),
    }
}

fn claim(
    subject: SymbolSubject,
    assertion: SymbolAssertion,
    confidence: f64,
    provenance: ClaimProvenance,
) -> SymbolClaim {
    SymbolClaim::new(
        subject,
        assertion,
        Confidence::new(confidence).expect("valid confidence"),
        vec![
            Evidence::new(
                EvidenceKind::new(EvidenceKind::METADATA).expect("valid evidence kind"),
                "deterministic projection test evidence",
            )
            .expect("valid evidence"),
        ],
        provenance,
    )
    .expect("valid claim")
}

fn function_name(
    rva: u64,
    size: Option<u64>,
    name: &str,
    confidence: f64,
    core_claim: bool,
) -> SymbolClaim {
    claim(
        SymbolSubject::Function {
            binary: binary().id,
            rva,
            size,
        },
        SymbolAssertion::Name {
            name: name.to_owned(),
        },
        confidence,
        if core_claim {
            core("function-name")
        } else {
            plugin("function-name")
        },
    )
}

fn boundary(rva: u64, size: u64, confidence: f64, core_claim: bool, method: &str) -> SymbolClaim {
    claim(
        SymbolSubject::Function {
            binary: binary().id,
            rva,
            size: Some(size),
        },
        SymbolAssertion::FunctionBoundary { size },
        confidence,
        if core_claim {
            core(method)
        } else {
            plugin(method)
        },
    )
}

fn graph(claims: impl IntoIterator<Item = SymbolClaim>) -> SymbolGraph {
    let mut graph = SymbolGraph::default();
    graph
        .insert_binary(binary())
        .expect("valid binary identity");
    for claim in claims {
        graph.submit_claim(claim).expect("known binary");
    }
    graph
}

fn project(claims: impl IntoIterator<Item = SymbolClaim>) -> ExportProjection {
    ExportProjection::from_symbol_graph(&binary(), 0x2_000, &graph(claims))
        .expect("valid projection")
}

#[test]
fn projection_is_stable_across_claim_order_and_core_names_outrank_plugins() {
    let claims = vec![
        function_name(0x300, None, "LaterFunction", 0.8, true),
        function_name(0x100, Some(0x20), "PluginGuess", 1.0, false),
        function_name(0x100, Some(0x20), "CoreExact", 0.8, true),
        function_name(0x100, Some(0x20), "CoreAlias", 0.7, true),
        claim(
            SymbolSubject::Global {
                binary: binary().id,
                rva: 0x500,
                size: Some(8),
            },
            SymbolAssertion::Name {
                name: "GlobalValue".to_owned(),
            },
            0.9,
            core("global-name"),
        ),
        claim(
            SymbolSubject::Type {
                binary: binary().id,
                key: "type.packet".to_owned(),
            },
            SymbolAssertion::TypeDefinition {
                declaration: "struct Packet { unsigned size; };".to_owned(),
            },
            0.85,
            plugin("type-definition"),
        ),
    ];
    let forward = project(claims.clone());
    let reverse = project(claims.into_iter().rev());

    assert_eq!(forward, reverse);
    assert_eq!(forward.functions[0].rva, 0x100);
    let selected = forward.functions[0]
        .selected_name
        .as_ref()
        .expect("selected function name");
    assert_eq!(selected.source.text, "CoreExact");
    assert_eq!(selected.source.attribution.confidence, 0.8);
    assert!(matches!(
        selected.source.attribution.provenance.producer,
        ExportProducer::Core { .. }
    ));
    assert_eq!(
        forward.functions[0]
            .alternate_names
            .iter()
            .map(|value| value.text.as_str())
            .collect::<Vec<_>>(),
        ["CoreAlias", "PluginGuess"]
    );
    assert_eq!(forward.functions[1].rva, 0x300);
    assert_eq!(forward.globals[0].rva, 0x500);
    assert_eq!(forward.types[0].key, "type.packet");
    assert_eq!(
        serde_json::to_vec(&forward).expect("serialize projection"),
        serde_json::to_vec(&reverse).expect("serialize projection")
    );
}

#[test]
fn entities_group_by_kind_and_rva_and_equal_authority_size_conflicts_are_omitted() {
    let projection = project([
        function_name(0x100, Some(0x20), "First", 0.9, true),
        function_name(0x100, Some(0x30), "Second", 0.7, true),
        claim(
            SymbolSubject::Global {
                binary: binary().id,
                rva: 0x100,
                size: Some(4),
            },
            SymbolAssertion::Name {
                name: "SameAddressGlobal".to_owned(),
            },
            1.0,
            core("global-name"),
        ),
    ]);

    assert_eq!(projection.functions.len(), 1);
    assert_eq!(projection.globals.len(), 1);
    assert_eq!(projection.functions[0].size, None);
    assert_eq!(projection.functions[0].size_attribution, None);
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::AmbiguousSize
            && warning.subject == Some(ExportSubject::Function { rva: 0x100 })
    }));
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::AddressKindCollision
            && warning.subject == Some(ExportSubject::Global { rva: 0x100 })
    }));
}

#[test]
fn selected_names_become_portable_identifiers_without_losing_source_text() {
    let projection = project([
        function_name(0x100, None, "NetworkSession::Decode-Packet ☃", 0.9, true),
        function_name(0x200, None, "42Start", 0.8, true),
    ]);

    let first = projection.functions[0]
        .selected_name
        .as_ref()
        .expect("first name");
    assert_eq!(first.source.text, "NetworkSession::Decode-Packet ☃");
    assert_eq!(
        first.output_name,
        "NetworkSession__Decode_x2d_Packet_x20__u2603_"
    );
    assert_eq!(
        projection.functions[1]
            .selected_name
            .as_ref()
            .expect("second name")
            .output_name,
        "rs_42Start"
    );
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::NameRewritten
            && warning.subject == Some(ExportSubject::Function { rva: 0x100 })
    }));
}

#[test]
fn sanitizer_collisions_are_disambiguated_after_rewriting() {
    let projection = project([
        function_name(0x100, None, "A::B", 0.9, true),
        function_name(0x200, None, "A__B", 0.8, true),
    ]);

    let names = projection
        .functions
        .iter()
        .map(|value| {
            value
                .selected_name
                .as_ref()
                .expect("selected name")
                .output_name
                .as_str()
        })
        .collect::<Vec<_>>();
    assert_eq!(names[0], "A__B");
    assert!(names[1].ends_with("__rs_f_0000000000000200"));
    assert!(
        projection
            .warnings
            .iter()
            .any(|warning| warning.code == ProjectionWarningCode::NameCollision)
    );
}

#[test]
fn debugger_names_respect_idas_fixed_name_buffer() {
    let raw = "x".repeat(MAX_NAME_BYTES);
    let projection = project([function_name(0x100, None, &raw, 0.9, true)]);
    let selected = projection.functions[0]
        .selected_name
        .as_ref()
        .expect("selected name");

    assert_eq!(selected.source.text, raw);
    assert!(selected.output_name.len() <= MAX_OUTPUT_NAME_BYTES);
    assert!(selected.output_name.contains("__rs_h_"));
    assert!(
        projection
            .warnings
            .iter()
            .any(|warning| warning.code == ProjectionWarningCode::NameRewritten)
    );
}

#[test]
fn equally_ranked_competing_names_are_selected_deterministically_and_warn() {
    let projection = project([
        function_name(0x100, None, "Zulu", 0.9, true),
        function_name(0x100, None, "Alpha", 0.9, true),
    ]);

    assert_eq!(
        projection.functions[0]
            .selected_name
            .as_ref()
            .expect("selected name")
            .source
            .text,
        "Alpha"
    );
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::AmbiguousName
            && warning.subject == Some(ExportSubject::Function { rva: 0x100 })
    }));
}

#[test]
fn core_size_outranks_plugin_size_even_when_plugin_confidence_is_higher() {
    let projection = project([
        boundary(0x100, 0x20, 0.7, true, "exception-directory"),
        boundary(0x100, 0x30, 1.0, false, "model-boundary"),
    ]);

    assert_eq!(projection.functions[0].size, Some(0x20));
    assert!(matches!(
        projection.functions[0]
            .size_attribution
            .as_ref()
            .expect("selected size")
            .provenance
            .producer,
        ExportProducer::Core { .. }
    ));
    assert!(
        projection
            .warnings
            .iter()
            .any(|warning| warning.code == ProjectionWarningCode::ConflictingSize)
    );
}

#[test]
fn overlapping_weaker_function_boundary_is_omitted() {
    let projection = project([
        boundary(0x100, 0x100, 0.8, true, "exception-directory"),
        boundary(0x180, 0x20, 1.0, false, "model-boundary"),
    ]);

    assert_eq!(projection.functions.len(), 1);
    assert_eq!(projection.functions[0].rva, 0x100);
    assert_eq!(projection.functions[0].size, Some(0x100));
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::OverlappingFunctionRange
            && warning.subject == Some(ExportSubject::Function { rva: 0x180 })
    }));
}

#[test]
fn selected_name_collisions_receive_stable_bounded_suffixes() {
    let projection = project([
        function_name(0x100, None, "SharedName", 0.9, true),
        claim(
            SymbolSubject::Global {
                binary: binary().id,
                rva: 0x300,
                size: None,
            },
            SymbolAssertion::Name {
                name: "SharedName".to_owned(),
            },
            0.9,
            core("function-name"),
        ),
    ]);

    let function_name = projection.functions[0]
        .selected_name
        .as_ref()
        .expect("function name");
    let global_name = projection.globals[0]
        .selected_name
        .as_ref()
        .expect("global name");
    assert_eq!(function_name.output_name, "SharedName");
    assert_ne!(global_name.output_name, "SharedName");
    assert!(global_name.output_name.ends_with("__rs_g_0000000000000300"));
    assert!(global_name.output_name.len() <= MAX_NAME_BYTES);
    assert!(
        projection
            .warnings
            .iter()
            .any(|warning| warning.code == ProjectionWarningCode::NameCollision)
    );
}

#[test]
fn hostile_and_oversized_text_is_not_copied_into_the_projection() {
    let oversized = "x".repeat(MAX_NAME_BYTES + 1);
    let hostile = ["line1\nline2", "ansi\u{1b}[31m", "bidi\u{202e}name"];
    let mut claims = hostile
        .iter()
        .enumerate()
        .map(|(index, name)| {
            function_name(
                0x100 + u64::try_from(index).expect("small index") * 0x10,
                None,
                name,
                1.0,
                false,
            )
        })
        .collect::<Vec<_>>();
    claims.push(function_name(0x200, None, &oversized, 1.0, false));
    let projection = project(claims);

    assert!(projection.functions.is_empty());
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::InvalidText && warning.occurrences == 1
    }));
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::TextLimitExceeded && warning.occurrences == 1
    }));
    let json = serde_json::to_string(&projection).expect("serialize projection");
    for value in hostile {
        assert!(!json.contains(value));
    }
    assert!(!json.contains(&oversized));
}

#[test]
fn negative_zero_confidence_is_canonicalized() {
    let negative = project([function_name(0x100, None, "Zero", -0.0, false)]);
    let positive = project([function_name(0x100, None, "Zero", 0.0, false)]);

    assert_eq!(negative, positive);
    let confidence = negative.functions[0]
        .selected_name
        .as_ref()
        .expect("selected name")
        .source
        .attribution
        .confidence;
    assert_eq!(confidence.to_bits(), 0.0_f64.to_bits());
}

#[test]
fn unsupported_claims_are_aggregated_as_structured_warnings() {
    let comments = ["one", "two"].map(|text| {
        claim(
            SymbolSubject::Function {
                binary: binary().id,
                rva: 0x100,
                size: None,
            },
            SymbolAssertion::Comment {
                text: text.to_owned(),
            },
            0.5,
            plugin("comment"),
        )
    });
    let projection = project(comments);

    assert!(projection.functions.is_empty());
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::UnsupportedAssertion
            && warning.subject == Some(ExportSubject::Function { rva: 0x100 })
            && warning.occurrences == 2
    }));
}

#[test]
fn claims_outside_the_image_warn_and_are_omitted() {
    let projection = project([function_name(0x2_000, None, "Outside", 0.9, true)]);
    assert!(projection.functions.is_empty());
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::AddressOutsideImage
            && warning.subject == Some(ExportSubject::Function { rva: 0x2_000 })
    }));
}

#[test]
fn graph_identity_must_exactly_match_the_requested_binary() {
    let graph = graph([]);
    let mut wrong = binary();
    wrong.id = BinaryId::digest(b"different exact binary");
    let error = ExportProjection::from_symbol_graph(&wrong, 0x2_000, &graph)
        .expect_err("identity mismatch must fail");
    assert!(matches!(error, ExportError::BinaryIdentityMismatch { .. }));
}
