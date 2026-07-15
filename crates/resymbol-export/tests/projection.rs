use resymbol_core::{
    BinaryFormat, BinaryId, BinaryIdentity, ClaimProducer, ClaimProvenance, Confidence,
    ControlFlowTarget, Evidence, EvidenceKind, StringEncoding, SymbolAssertion, SymbolClaim,
    SymbolGraph, SymbolSubject, plugin_api::PluginId,
};
use resymbol_export::{
    ExportControlFlowTarget, ExportError, ExportProducer, ExportProjection, ExportStringEncoding,
    ExportSubject, MAX_CLASS_MEMBERSHIPS_PER_FUNCTION, MAX_DIRECT_CALLS, MAX_NAME_BYTES,
    MAX_OUTPUT_NAME_BYTES, MAX_THUNKS, ProjectionValidationError, ProjectionWarningCode,
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

fn function_prototype(
    rva: u64,
    declaration: &str,
    confidence: f64,
    core_claim: bool,
) -> SymbolClaim {
    claim(
        SymbolSubject::Function {
            binary: binary().id,
            rva,
            size: None,
        },
        SymbolAssertion::FunctionPrototype {
            declaration: declaration.to_owned(),
        },
        confidence,
        if core_claim {
            core("function-prototype")
        } else {
            plugin("function-prototype")
        },
    )
}

fn class_membership(rva: u64, class_name: &str, confidence: f64, core_claim: bool) -> SymbolClaim {
    claim(
        SymbolSubject::Function {
            binary: binary().id,
            rva,
            size: None,
        },
        SymbolAssertion::ClassMembership {
            class_name: class_name.to_owned(),
        },
        confidence,
        if core_claim {
            core("class-membership")
        } else {
            plugin("class-membership")
        },
    )
}

fn function_entry(rva: u64, confidence: f64, core_claim: bool) -> SymbolClaim {
    claim(
        SymbolSubject::Function {
            binary: binary().id,
            rva,
            size: None,
        },
        SymbolAssertion::FunctionEntry,
        confidence,
        if core_claim {
            core("function-entry")
        } else {
            plugin("function-entry")
        },
    )
}

fn direct_call(
    caller_rva: u64,
    call_site_rva: u64,
    target: ControlFlowTarget,
    confidence: f64,
    core_claim: bool,
) -> SymbolClaim {
    claim(
        SymbolSubject::Function {
            binary: binary().id,
            rva: caller_rva,
            size: None,
        },
        SymbolAssertion::DirectCall {
            call_site_rva,
            target,
        },
        confidence,
        if core_claim {
            core("direct-call")
        } else {
            plugin("direct-call")
        },
    )
}

fn thunk(rva: u64, target: ControlFlowTarget, confidence: f64, core_claim: bool) -> SymbolClaim {
    claim(
        SymbolSubject::Function {
            binary: binary().id,
            rva,
            size: None,
        },
        SymbolAssertion::ThunkTarget { target },
        confidence,
        if core_claim {
            core("thunk")
        } else {
            plugin("thunk")
        },
    )
}

fn string_literal(
    rva: u64,
    encoding: StringEncoding,
    value: &str,
    confidence: f64,
    core_claim: bool,
) -> SymbolClaim {
    let byte_size = match encoding {
        StringEncoding::Ascii => u64::try_from(value.len()).expect("test string length") + 1,
        StringEncoding::Utf16Le => {
            u64::try_from(value.encode_utf16().count()).expect("test string length") * 2 + 2
        }
        _ => panic!("test only uses supported string encodings"),
    };
    claim(
        SymbolSubject::Global {
            binary: binary().id,
            rva,
            size: Some(byte_size),
        },
        SymbolAssertion::StringLiteral {
            encoding,
            value: value.to_owned(),
        },
        confidence,
        if core_claim {
            core("string-literal")
        } else {
            plugin("string-literal")
        },
    )
}

fn data_reference(
    caller_rva: u64,
    caller_size: Option<u64>,
    instruction_rva: u64,
    instruction_size: u8,
    target_rva: u64,
    confidence: f64,
    core_claim: bool,
) -> SymbolClaim {
    claim(
        SymbolSubject::Function {
            binary: binary().id,
            rva: caller_rva,
            size: caller_size,
        },
        SymbolAssertion::DataReference {
            instruction_rva,
            instruction_size,
            target_rva,
        },
        confidence,
        if core_claim {
            core("data-reference")
        } else {
            plugin("data-reference")
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
fn represented_function_assertions_set_the_strongest_entry_attribution() {
    let projection = project([
        function_name(0x100, None, "NamedFunction", 0.6, true),
        function_prototype(0x200, "void PrototypeOnly(void)", 0.9, false),
        boundary(0x300, 0x20, 0.7, true, "exception-directory"),
        class_membership(0x400, "demo::ClassOnly", 0.75, true),
        function_name(0x500, None, "PluginName", 1.0, false),
        function_prototype(0x500, "void Ranked(void)", 0.5, true),
        class_membership(0x500, "demo::Ranked", 0.7, true),
        boundary(0x500, 0x20, 0.8, true, "ranked-boundary"),
    ]);

    for (rva, method, confidence) in [
        (0x100, "function-name", 0.6),
        (0x200, "function-prototype", 0.9),
        (0x300, "exception-directory", 0.7),
        (0x400, "class-membership", 0.75),
        (0x500, "ranked-boundary", 0.8),
    ] {
        let attribution = projection
            .functions
            .iter()
            .find(|function| function.rva == rva)
            .and_then(|function| function.entry_attribution.as_ref())
            .expect("represented function assertion contributes entry attribution");
        assert_eq!(attribution.provenance.method, method);
        assert_eq!(attribution.confidence, confidence);
    }
    assert!(matches!(
        projection
            .functions
            .iter()
            .find(|function| function.rva == 0x500)
            .and_then(|function| function.entry_attribution.as_ref())
            .expect("ranked entry attribution")
            .provenance
            .producer,
        ExportProducer::Core { .. }
    ));
}

#[test]
fn mismatched_and_unsupported_function_assertions_do_not_create_entries() {
    let projection = project([
        claim(
            SymbolSubject::Function {
                binary: binary().id,
                rva: 0x100,
                size: Some(0x20),
            },
            SymbolAssertion::FunctionBoundary { size: 0x30 },
            1.0,
            core("mismatched-boundary"),
        ),
        claim(
            SymbolSubject::Function {
                binary: binary().id,
                rva: 0x200,
                size: None,
            },
            SymbolAssertion::TypeDefinition {
                declaration: "struct WrongSubject {};".to_owned(),
            },
            1.0,
            core("mismatched-type-definition"),
        ),
        claim(
            SymbolSubject::Function {
                binary: binary().id,
                rva: 0x300,
                size: None,
            },
            SymbolAssertion::Comment {
                text: "unsupported comment".to_owned(),
            },
            1.0,
            plugin("comment"),
        ),
    ]);

    assert!(projection.functions.is_empty());
    assert_eq!(
        projection
            .warnings
            .iter()
            .filter(|warning| warning.code == ProjectionWarningCode::AssertionSubjectMismatch)
            .map(|warning| warning.occurrences)
            .sum::<u64>(),
        2
    );
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::UnsupportedAssertion
            && warning.subject == Some(ExportSubject::Function { rva: 0x300 })
    }));
}

#[test]
fn control_flow_projection_is_canonical_and_keeps_strongest_attribution() {
    let claims = vec![
        function_entry(0x100, 1.0, false),
        function_entry(0x100, 0.6, true),
        direct_call(
            0x100,
            0x120,
            ControlFlowTarget::ImportIat { iat_rva: 0x900 },
            0.7,
            true,
        ),
        direct_call(
            0x100,
            0x110,
            ControlFlowTarget::Function { rva: 0x200 },
            1.0,
            false,
        ),
        direct_call(
            0x100,
            0x110,
            ControlFlowTarget::Function { rva: 0x200 },
            0.8,
            true,
        ),
        thunk(
            0x300,
            ControlFlowTarget::ImportIat { iat_rva: 0x900 },
            1.0,
            false,
        ),
        thunk(0x300, ControlFlowTarget::Function { rva: 0x200 }, 0.7, true),
    ];

    let forward = project(claims.clone());
    let reverse = project(claims.into_iter().rev());

    assert_eq!(forward, reverse);
    assert_eq!(forward.schema_version, 6);
    assert_eq!(
        forward
            .functions
            .iter()
            .map(|function| function.rva)
            .collect::<Vec<_>>(),
        [0x100, 0x200, 0x300]
    );
    assert!(forward.functions.iter().all(|function| {
        function.entry_attribution.is_some()
            && function.size.is_none()
            && function.selected_name.is_none()
    }));
    assert_eq!(forward.direct_calls.len(), 2);
    assert_eq!(forward.direct_calls[0].call_site_rva, 0x110);
    assert_eq!(
        forward.direct_calls[0].target,
        ExportControlFlowTarget::Function { rva: 0x200 }
    );
    assert!(matches!(
        forward.direct_calls[0].attribution.provenance.producer,
        ExportProducer::Core { .. }
    ));
    assert_eq!(forward.direct_calls[0].attribution.confidence, 0.8);
    assert_eq!(forward.direct_calls[1].call_site_rva, 0x120);
    assert_eq!(forward.thunks.len(), 1);
    assert_eq!(forward.thunks[0].rva, 0x300);
    assert_eq!(
        forward.thunks[0].target,
        ExportControlFlowTarget::Function { rva: 0x200 }
    );
    assert!(
        forward
            .warnings
            .iter()
            .all(|warning| warning.code != ProjectionWarningCode::UnsupportedAssertion)
    );
}

#[test]
fn exact_thunk_chains_and_connected_cycles_preserve_each_hop() {
    let chain = project([
        thunk(
            0x100,
            ControlFlowTarget::Function { rva: 0x200 },
            0.95,
            true,
        ),
        thunk(
            0x200,
            ControlFlowTarget::FunctionPointer {
                slot_rva: 0x900,
                rva: 0x300,
            },
            0.95,
            true,
        ),
    ]);

    assert_eq!(chain.schema_version, 6);
    assert_eq!(
        chain
            .functions
            .iter()
            .map(|function| function.rva)
            .collect::<Vec<_>>(),
        [0x100, 0x200, 0x300]
    );
    assert_eq!(chain.thunks.len(), 2);
    assert_eq!(chain.thunks[0].rva, 0x100);
    assert_eq!(
        chain.thunks[0].target,
        ExportControlFlowTarget::Function { rva: 0x200 }
    );
    assert_eq!(chain.thunks[1].rva, 0x200);
    assert_eq!(
        chain.thunks[1].target,
        ExportControlFlowTarget::FunctionPointer {
            slot_rva: 0x900,
            rva: 0x300,
        }
    );
    assert!(chain.thunks.iter().all(|thunk| {
        !(thunk.rva == 0x100 && thunk.target == ExportControlFlowTarget::Function { rva: 0x300 })
    }));
    chain.validate().expect("an exact thunk chain is valid");

    let cycle = project([
        thunk(
            0x100,
            ControlFlowTarget::Function { rva: 0x200 },
            0.95,
            true,
        ),
        thunk(
            0x200,
            ControlFlowTarget::Function { rva: 0x100 },
            0.95,
            true,
        ),
    ]);
    assert_eq!(cycle.thunks.len(), 2);
    assert_eq!(
        cycle
            .thunks
            .iter()
            .map(|thunk| (thunk.rva, thunk.target.clone()))
            .collect::<Vec<_>>(),
        [
            (0x100, ExportControlFlowTarget::Function { rva: 0x200 }),
            (0x200, ExportControlFlowTarget::Function { rva: 0x100 }),
        ]
    );
    cycle
        .validate()
        .expect("a connected exact thunk cycle is valid");
}

#[test]
fn function_pointer_targets_project_losslessly_and_sort_deterministically() {
    let claims = vec![
        direct_call(
            0x100,
            0x110,
            ControlFlowTarget::FunctionPointer {
                slot_rva: 0x700,
                rva: 0x300,
            },
            0.9,
            true,
        ),
        data_reference(0x100, Some(0x80), 0x110, 6, 0x700, 0.9, true),
        direct_call(
            0x100,
            0x110,
            ControlFlowTarget::ImportIat { iat_rva: 0x900 },
            0.8,
            true,
        ),
        direct_call(
            0x100,
            0x110,
            ControlFlowTarget::Function { rva: 0x200 },
            0.7,
            true,
        ),
        thunk(
            0x400,
            ControlFlowTarget::FunctionPointer {
                slot_rva: 0x708,
                rva: 0x300,
            },
            0.9,
            true,
        ),
    ];

    let forward = project(claims.clone());
    let reverse = project(claims.into_iter().rev());

    assert_eq!(forward, reverse);
    assert_eq!(forward.schema_version, 6);
    assert_eq!(
        forward
            .direct_calls
            .iter()
            .map(|call| call.target.clone())
            .collect::<Vec<_>>(),
        [
            ExportControlFlowTarget::Function { rva: 0x200 },
            ExportControlFlowTarget::ImportIat { iat_rva: 0x900 },
            ExportControlFlowTarget::FunctionPointer {
                slot_rva: 0x700,
                rva: 0x300,
            },
        ]
    );
    assert_eq!(
        forward
            .functions
            .iter()
            .map(|function| function.rva)
            .collect::<Vec<_>>(),
        [0x100, 0x200, 0x300, 0x400]
    );
    assert!(
        forward
            .functions
            .iter()
            .find(|function| function.rva == 0x300)
            .expect("resolved pointer target function")
            .entry_attribution
            .is_some()
    );
    assert_eq!(
        forward.thunks[0].target,
        ExportControlFlowTarget::FunctionPointer {
            slot_rva: 0x708,
            rva: 0x300,
        }
    );

    let wire = serde_json::to_value(&forward).expect("serialize function-pointer projection");
    assert_eq!(wire["schema_version"], serde_json::json!(6));
    assert_eq!(
        wire["direct_calls"][2]["target"],
        serde_json::json!({
            "kind": "function-pointer",
            "slot_rva": 0x700,
            "rva": 0x300
        })
    );
    assert_eq!(
        serde_json::to_vec(&forward).expect("serialize forward projection"),
        serde_json::to_vec(&reverse).expect("serialize reverse projection")
    );
}

#[test]
fn function_pointer_projection_validates_slot_and_resolved_function_addresses() {
    let projection = project([
        direct_call(
            0x100,
            0x110,
            ControlFlowTarget::FunctionPointer {
                slot_rva: 0x700,
                rva: 0x200,
            },
            0.9,
            true,
        ),
        data_reference(0x100, Some(0x80), 0x110, 6, 0x700, 0.9, true),
    ]);

    let mut outside_slot = projection.clone();
    outside_slot.direct_calls[0].target = ExportControlFlowTarget::FunctionPointer {
        slot_rva: 0x2_000,
        rva: 0x200,
    };
    assert!(matches!(
        outside_slot.validate(),
        Err(ProjectionValidationError::AddressOutsideImage { rva: 0x2_000, .. })
    ));

    let mut short_slot = projection.clone();
    short_slot.direct_calls[0].target = ExportControlFlowTarget::FunctionPointer {
        slot_rva: 0x1ff9,
        rva: 0x200,
    };
    assert!(matches!(
        short_slot.validate(),
        Err(ProjectionValidationError::AddressOutsideImage {
            rva: 0x1ff9,
            size: Some(8),
        })
    ));

    let mut outside_function = projection.clone();
    outside_function.direct_calls[0].target = ExportControlFlowTarget::FunctionPointer {
        slot_rva: 0x700,
        rva: 0x2_000,
    };
    assert!(matches!(
        outside_function.validate(),
        Err(ProjectionValidationError::AddressOutsideImage { rva: 0x2_000, .. })
    ));

    let mut missing_function_entry = projection.clone();
    missing_function_entry
        .functions
        .retain(|function| function.rva != 0x200);
    assert!(matches!(
        missing_function_entry.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "control_flow.function_entry"
        })
    ));

    let mut missing_reference = projection.clone();
    missing_reference.data_references.clear();
    assert!(matches!(
        missing_reference.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "direct_call.function_pointer_reference"
        })
    ));

    let rejected = project([
        direct_call(
            0x100,
            0x110,
            ControlFlowTarget::FunctionPointer {
                slot_rva: 0x2_000,
                rva: 0x200,
            },
            0.9,
            true,
        ),
        direct_call(
            0x100,
            0x120,
            ControlFlowTarget::FunctionPointer {
                slot_rva: 0x700,
                rva: 0x2_000,
            },
            0.9,
            true,
        ),
        direct_call(
            0x100,
            0x130,
            ControlFlowTarget::FunctionPointer {
                slot_rva: 0x1ff9,
                rva: 0x200,
            },
            0.9,
            true,
        ),
        data_reference(0x100, Some(0x80), 0x130, 6, 0x1ff9, 0.9, true),
    ]);
    assert!(rejected.direct_calls.is_empty());
    assert_eq!(
        rejected
            .warnings
            .iter()
            .filter(|warning| warning.code == ProjectionWarningCode::AddressOutsideImage)
            .map(|warning| warning.occurrences)
            .sum::<u64>(),
        3
    );
}

#[test]
fn pointer_call_is_omitted_when_data_reference_conflict_loses_its_companion() {
    let projection = project([
        direct_call(
            0x100,
            0x110,
            ControlFlowTarget::FunctionPointer {
                slot_rva: 0x700,
                rva: 0x200,
            },
            0.9,
            true,
        ),
        data_reference(0x100, Some(0x80), 0x110, 6, 0x700, 0.8, true),
        data_reference(0x100, Some(0x80), 0x110, 7, 0x710, 1.0, true),
    ]);

    assert!(projection.direct_calls.is_empty());
    assert_eq!(projection.data_references.len(), 1);
    assert_eq!(projection.data_references[0].target_rva, 0x710);
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::UnsupportedAssertion
            && warning.subject == Some(ExportSubject::Function { rva: 0x100 })
    }));
}

#[test]
fn strings_and_data_references_are_canonical_and_claim_order_invariant() {
    let claims = vec![
        string_literal(0x500, StringEncoding::Ascii, "World", 1.0, false),
        string_literal(0x500, StringEncoding::Ascii, "Hello", 0.8, true),
        string_literal(0x502, StringEncoding::Ascii, "Overlap", 1.0, false),
        string_literal(0x600, StringEncoding::Utf16Le, "Wide", 0.9, true),
        // The core claim wins this duplicate site before correlation runs.
        data_reference(0x100, Some(0x80), 0x108, 7, 0x600, 1.0, false),
        data_reference(0x100, Some(0x80), 0x108, 7, 0x500, 0.8, true),
        // ASCII content accepts byte-granular interior references.
        data_reference(0x100, Some(0x80), 0x110, 7, 0x503, 0.9, true),
        // Boundary and unrelated targets remain explicitly uncorrelated.
        data_reference(0x100, Some(0x80), 0x118, 7, 0x4ff, 0.9, true),
        data_reference(0x100, Some(0x80), 0x120, 7, 0x505, 0.9, true),
        data_reference(0x100, Some(0x80), 0x128, 7, 0x506, 0.9, true),
        // This target lies only in the tail of the discarded overlapping string.
        data_reference(0x100, Some(0x80), 0x130, 7, 0x508, 0.9, true),
        // UTF-16LE references must be aligned within encoded content.
        data_reference(0x100, Some(0x80), 0x138, 7, 0x602, 0.9, true),
        data_reference(0x100, Some(0x80), 0x140, 7, 0x603, 0.9, true),
        data_reference(0x100, Some(0x80), 0x148, 7, 0x608, 0.9, true),
        data_reference(0x100, Some(0x80), 0x150, 7, 0x700, 0.9, true),
    ];

    let forward = project(claims.clone());
    let reverse = project(claims.into_iter().rev());

    assert_eq!(forward, reverse);
    assert_eq!(forward.schema_version, 6);
    assert_eq!(forward.strings.len(), 2);
    assert_eq!(forward.strings[0].rva, 0x500);
    assert_eq!(forward.strings[0].byte_size, 6);
    assert_eq!(forward.strings[0].encoding, ExportStringEncoding::Ascii);
    assert_eq!(forward.strings[0].value, "Hello");
    assert!(matches!(
        forward.strings[0].attribution.provenance.producer,
        ExportProducer::Core { .. }
    ));
    assert_eq!(forward.strings[1].rva, 0x600);
    assert_eq!(forward.strings[1].byte_size, 10);
    assert_eq!(forward.strings[1].encoding, ExportStringEncoding::Utf16Le);
    assert_eq!(forward.data_references.len(), 10);
    assert_eq!(forward.data_references[0].caller_rva, 0x100);
    assert_eq!(forward.data_references[0].instruction_rva, 0x108);
    assert_eq!(forward.data_references[0].instruction_size, 7);
    assert_eq!(forward.data_references[0].target_rva, 0x500);
    assert_eq!(
        forward.data_references[0].referenced_string_rva,
        Some(0x500)
    );
    assert!(matches!(
        forward.data_references[0].attribution.provenance.producer,
        ExportProducer::Core { .. }
    ));
    assert_eq!(
        forward
            .data_references
            .iter()
            .map(|reference| (reference.target_rva, reference.referenced_string_rva))
            .collect::<Vec<_>>(),
        [
            (0x500, Some(0x500)),
            (0x503, Some(0x500)),
            (0x4ff, None),
            (0x505, None),
            (0x506, None),
            (0x508, None),
            (0x602, Some(0x600)),
            (0x603, None),
            (0x608, None),
            (0x700, None),
        ]
    );
    assert!(forward.functions[0].entry_attribution.is_some());
    let wire = serde_json::to_value(&forward).expect("serialize schema-6 projection");
    assert_eq!(wire["schema_version"], serde_json::json!(6));
    assert_eq!(
        wire["data_references"][0]["referenced_string_rva"],
        serde_json::json!(0x500)
    );
    assert_eq!(
        wire["data_references"][2]["referenced_string_rva"],
        serde_json::Value::Null
    );
    assert_eq!(
        serde_json::to_vec(&forward).expect("serialize schema-6 projection"),
        serde_json::to_vec(&reverse).expect("serialize reversed schema-6 projection")
    );
}

#[test]
fn string_and_data_reference_validation_rejects_tampering_and_caps_growth() {
    let projection = project([
        string_literal(0x500, StringEncoding::Ascii, "Hello", 0.8, true),
        string_literal(0x600, StringEncoding::Utf16Le, "Wide", 0.9, true),
        data_reference(0x100, Some(0x40), 0x108, 7, 0x500, 0.8, true),
        data_reference(0x100, Some(0x40), 0x110, 7, 0x700, 0.8, true),
    ]);

    let mut unsorted_strings = projection.clone();
    unsorted_strings.strings.swap(0, 1);
    assert!(matches!(
        unsorted_strings.validate(),
        Err(ProjectionValidationError::UnsortedCollection {
            collection: "strings"
        })
    ));

    let mut wrong_string_size = projection.clone();
    wrong_string_size.strings[0].byte_size += 1;
    assert!(matches!(
        wrong_string_size.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "string.byte_size"
        })
    ));

    let mut overlapping_strings = projection.clone();
    overlapping_strings.strings[1].rva = 0x502;
    assert!(matches!(
        overlapping_strings.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "strings.overlap"
        })
    ));

    let mut hostile_string = projection.clone();
    hostile_string.strings[0].value = "bad\nvalue".to_owned();
    assert!(matches!(
        hostile_string.validate(),
        Err(ProjectionValidationError::InvalidText {
            field: "string.value"
        })
    ));

    let mut oversized_string = projection.clone();
    oversized_string.strings[0].value = "A".repeat(16 * 1024 + 1);
    oversized_string.strings[0].byte_size = 16 * 1024 + 2;
    assert!(matches!(
        oversized_string.validate(),
        Err(ProjectionValidationError::InvalidText {
            field: "string.value"
        })
    ));

    let mut too_many_strings = projection.clone();
    too_many_strings
        .strings
        .resize(65_537, projection.strings[0].clone());
    assert!(matches!(
        too_many_strings.validate(),
        Err(ProjectionValidationError::CollectionLimit {
            collection: "strings"
        })
    ));

    let mut zero_instruction_size = projection.clone();
    zero_instruction_size.data_references[0].instruction_size = 0;
    assert!(matches!(
        zero_instruction_size.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "data_reference.instruction_size"
        })
    ));

    let mut before_caller = projection.clone();
    before_caller.data_references[0].instruction_rva = 0x80;
    assert!(matches!(
        before_caller.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "data_reference.instruction_rva"
        })
    ));

    let mut duplicate_site = projection.clone();
    let mut competing = duplicate_site.data_references[0].clone();
    competing.target_rva = 0x600;
    duplicate_site.data_references.push(competing);
    assert!(matches!(
        duplicate_site.validate(),
        Err(ProjectionValidationError::UnsortedCollection {
            collection: "data_references"
        })
    ));

    let mut missing_string_link = projection.clone();
    missing_string_link.data_references[0].referenced_string_rva = None;
    assert!(matches!(
        missing_string_link.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "data_reference.referenced_string_rva"
        })
    ));

    let mut wrong_string_link = projection.clone();
    wrong_string_link.data_references[0].referenced_string_rva = Some(0x600);
    assert!(matches!(
        wrong_string_link.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "data_reference.referenced_string_rva"
        })
    ));

    let mut spurious_string_link = projection.clone();
    spurious_string_link.data_references[1].referenced_string_rva = Some(0x500);
    assert!(matches!(
        spurious_string_link.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "data_reference.referenced_string_rva"
        })
    ));

    let mut missing_caller = projection.clone();
    missing_caller.functions.clear();
    assert!(matches!(
        missing_caller.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "control_flow.function_entry"
        })
    ));
}

#[test]
fn recovered_string_encoding_uses_the_canonical_wire_spelling() {
    assert_eq!(
        serde_json::to_value(ExportStringEncoding::Ascii).expect("serialize ASCII encoding"),
        serde_json::json!("ascii")
    );
    assert_eq!(
        serde_json::to_value(ExportStringEncoding::Utf16Le).expect("serialize UTF-16LE encoding"),
        serde_json::json!("utf-16-le")
    );
}

#[test]
fn string_and_data_reference_assertions_on_wrong_subjects_warn_and_are_omitted() {
    let projection = project([
        claim(
            SymbolSubject::Function {
                binary: binary().id,
                rva: 0x100,
                size: Some(6),
            },
            SymbolAssertion::StringLiteral {
                encoding: StringEncoding::Ascii,
                value: "Hello".to_owned(),
            },
            0.9,
            core("wrong-string-subject"),
        ),
        claim(
            SymbolSubject::Global {
                binary: binary().id,
                rva: 0x500,
                size: Some(8),
            },
            SymbolAssertion::DataReference {
                instruction_rva: 0x500,
                instruction_size: 7,
                target_rva: 0x600,
            },
            0.9,
            core("wrong-reference-subject"),
        ),
    ]);

    assert!(projection.strings.is_empty());
    assert!(projection.data_references.is_empty());
    assert_eq!(
        projection
            .warnings
            .iter()
            .filter(|warning| warning.code == ProjectionWarningCode::AssertionSubjectMismatch)
            .map(|warning| warning.occurrences)
            .sum::<u64>(),
        2
    );
}

#[test]
fn control_flow_projection_validation_rejects_noncanonical_or_dangling_relations() {
    let projection = project([
        direct_call(
            0x100,
            0x110,
            ControlFlowTarget::Function { rva: 0x200 },
            0.8,
            true,
        ),
        direct_call(
            0x100,
            0x120,
            ControlFlowTarget::ImportIat { iat_rva: 0x900 },
            0.8,
            true,
        ),
        thunk(0x300, ControlFlowTarget::Function { rva: 0x200 }, 0.8, true),
    ]);

    let mut unsorted_calls = projection.clone();
    unsorted_calls.direct_calls.swap(0, 1);
    assert!(matches!(
        unsorted_calls.validate(),
        Err(ProjectionValidationError::UnsortedCollection {
            collection: "direct_calls"
        })
    ));

    let mut old_schema = projection.clone();
    old_schema.schema_version = 5;
    assert!(matches!(
        old_schema.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "schema_version"
        })
    ));

    let mut duplicate_thunk_source = projection.clone();
    duplicate_thunk_source
        .thunks
        .push(duplicate_thunk_source.thunks[0].clone());
    assert!(matches!(
        duplicate_thunk_source.validate(),
        Err(ProjectionValidationError::UnsortedCollection {
            collection: "thunks"
        })
    ));

    let mut dangling_target = projection.clone();
    dangling_target
        .functions
        .retain(|function| function.rva != 0x200);
    assert!(matches!(
        dangling_target.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "control_flow.function_entry"
        })
    ));

    let mut missing_entry_attribution = projection.clone();
    missing_entry_attribution.functions[0].entry_attribution = None;
    assert!(matches!(
        missing_entry_attribution.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "control_flow.function_entry"
        })
    ));

    let mut outside_call_site = projection.clone();
    outside_call_site.direct_calls[1].call_site_rva = 0x2_000;
    assert!(matches!(
        outside_call_site.validate(),
        Err(ProjectionValidationError::AddressOutsideImage { rva: 0x2_000, .. })
    ));

    let mut before_caller = projection.clone();
    before_caller.direct_calls[0].call_site_rva = 0x80;
    assert!(matches!(
        before_caller.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "direct_call.call_site"
        })
    ));

    let mut outside_known_caller = projection.clone();
    outside_known_caller.functions[0].size = Some(0x10);
    outside_known_caller.functions[0].size_attribution =
        outside_known_caller.functions[0].entry_attribution.clone();
    assert!(matches!(
        outside_known_caller.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "direct_call.call_site"
        })
    ));

    let mut outside_iat = projection.clone();
    outside_iat.direct_calls[1].target = ExportControlFlowTarget::ImportIat { iat_rva: 0x2_000 };
    assert!(matches!(
        outside_iat.validate(),
        Err(ProjectionValidationError::AddressOutsideImage { rva: 0x2_000, .. })
    ));

    let mut self_thunk = projection.clone();
    self_thunk.thunks[0].target = ExportControlFlowTarget::Function { rva: 0x300 };
    assert!(matches!(
        self_thunk.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "thunk.target"
        })
    ));

    let mut pointer_self_thunk = projection;
    pointer_self_thunk.thunks[0].target = ExportControlFlowTarget::FunctionPointer {
        slot_rva: 0x700,
        rva: 0x300,
    };
    assert!(matches!(
        pointer_self_thunk.validate(),
        Err(ProjectionValidationError::InvalidBinaryField {
            field: "thunk.target"
        })
    ));

    assert_eq!(MAX_DIRECT_CALLS, 262_144);
    assert_eq!(MAX_THUNKS, 65_536);
}

#[test]
fn control_flow_assertions_on_non_functions_warn_as_subject_mismatches() {
    let projection = project([
        claim(
            SymbolSubject::Global {
                binary: binary().id,
                rva: 0x100,
                size: None,
            },
            SymbolAssertion::FunctionEntry,
            0.8,
            core("mismatched-function-entry"),
        ),
        claim(
            SymbolSubject::Global {
                binary: binary().id,
                rva: 0x200,
                size: None,
            },
            SymbolAssertion::DirectCall {
                call_site_rva: 0x210,
                target: ControlFlowTarget::Function { rva: 0x300 },
            },
            0.8,
            core("mismatched-direct-call"),
        ),
        claim(
            SymbolSubject::Type {
                binary: binary().id,
                key: "type.mismatch".to_owned(),
            },
            SymbolAssertion::ThunkTarget {
                target: ControlFlowTarget::ImportIat { iat_rva: 0x900 },
            },
            0.8,
            core("mismatched-thunk"),
        ),
    ]);

    assert!(projection.functions.is_empty());
    assert!(projection.direct_calls.is_empty());
    assert!(projection.thunks.is_empty());
    assert_eq!(
        projection
            .warnings
            .iter()
            .filter(|warning| warning.code == ProjectionWarningCode::AssertionSubjectMismatch)
            .map(|warning| warning.occurrences)
            .sum::<u64>(),
        3
    );
    assert!(
        projection
            .warnings
            .iter()
            .all(|warning| warning.code != ProjectionWarningCode::UnsupportedAssertion)
    );
}

#[test]
fn function_class_memberships_survive_projection_with_attribution() {
    let projection = project([
        class_membership(0x100, "demo::Base", 1.0, false),
        class_membership(0x100, "demo::Widget", 0.9, true),
        class_membership(0x100, "demo::Base", 0.8, true),
    ]);

    assert_eq!(projection.schema_version, 6);
    assert_eq!(projection.functions.len(), 1);
    assert_eq!(
        projection.functions[0]
            .class_memberships
            .iter()
            .map(|value| value.text.as_str())
            .collect::<Vec<_>>(),
        ["demo::Widget", "demo::Base"]
    );
    assert!(
        projection.functions[0]
            .class_memberships
            .iter()
            .all(|value| matches!(
                value.attribution.provenance.producer,
                ExportProducer::Core { .. }
            ))
    );
    assert!(
        !projection
            .warnings
            .iter()
            .any(|warning| warning.code == ProjectionWarningCode::UnsupportedAssertion)
    );
    assert!(
        serde_json::to_string(&projection)
            .expect("serialize projection")
            .contains("\"class_memberships\"")
    );

    let mut invalid = projection;
    invalid.functions[0].class_memberships[0].text = "x".repeat(MAX_NAME_BYTES + 1);
    assert!(matches!(
        invalid.validate(),
        Err(ProjectionValidationError::InvalidText {
            field: "function.class_membership"
        })
    ));
}

#[test]
fn function_accepts_more_class_memberships_than_the_name_candidate_cap() {
    let projection = project(
        (0..257).map(|index| class_membership(0x100, &format!("demo::Class{index:03}"), 0.9, true)),
    );

    assert_eq!(projection.functions[0].class_memberships.len(), 257);
    assert!(
        projection
            .warnings
            .iter()
            .all(|warning| { warning.code != ProjectionWarningCode::ClassMembershipLimitExceeded })
    );
}

#[test]
fn class_membership_overflow_is_skipped_and_aggregated_as_a_warning() {
    let projection = project(
        (0..MAX_CLASS_MEMBERSHIPS_PER_FUNCTION + 2)
            .map(|index| class_membership(0x100, &format!("demo::Class{index:04}"), 0.9, true)),
    );

    assert_eq!(
        projection.functions[0].class_memberships.len(),
        MAX_CLASS_MEMBERSHIPS_PER_FUNCTION
    );
    assert!(
        projection.functions[0]
            .class_memberships
            .iter()
            .all(|membership| membership.text != "demo::Class4096"
                && membership.text != "demo::Class4097")
    );
    assert!(projection.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::ClassMembershipLimitExceeded
            && warning.subject == Some(ExportSubject::Function { rva: 0x100 })
            && warning.occurrences == 2
    }));

    let mut invalid = projection;
    let mut extra = invalid.functions[0].class_memberships[0].clone();
    extra.text = "demo::Overflow".to_owned();
    invalid.functions[0].class_memberships.push(extra);
    assert!(matches!(
        invalid.validate(),
        Err(ProjectionValidationError::CollectionLimit {
            collection: "function.class_membership"
        })
    ));
}

#[test]
fn class_membership_overflow_is_invariant_under_adversarial_claim_order() {
    let mut claims = (0..MAX_CLASS_MEMBERSHIPS_PER_FUNCTION)
        .map(|index| class_membership(0x100, &format!("demo::Base{index:04}"), 0.5, true))
        .collect::<Vec<_>>();
    claims.push(class_membership(0x100, "demo::Target", 0.1, false));
    claims.push(class_membership(0x100, "demo::Target", 1.0, true));

    let forward = project(claims.clone());
    claims.reverse();
    let reverse = project(claims);

    assert_eq!(forward, reverse);
    assert_eq!(
        forward.functions[0].class_memberships.len(),
        MAX_CLASS_MEMBERSHIPS_PER_FUNCTION
    );
    assert!(
        forward.functions[0]
            .class_memberships
            .iter()
            .any(|membership| membership.text == "demo::Target")
    );
    assert!(forward.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::ClassMembershipLimitExceeded
            && warning.subject == Some(ExportSubject::Function { rva: 0x100 })
            && warning.occurrences == 1
    }));
}

#[test]
fn repeated_omitted_class_membership_counts_once_in_any_claim_order() {
    let mut claims = (0..MAX_CLASS_MEMBERSHIPS_PER_FUNCTION)
        .map(|index| class_membership(0x100, &format!("demo::Retained{index:04}"), 0.9, true))
        .collect::<Vec<_>>();
    claims.push(class_membership(0x100, "demo::Omitted", 0.1, false));
    claims.push(class_membership(0x100, "demo::Omitted", 0.2, false));

    let forward = project(claims.clone());
    claims.reverse();
    let reverse = project(claims);

    assert_eq!(forward, reverse);
    assert!(
        forward.functions[0]
            .class_memberships
            .iter()
            .all(|membership| membership.text != "demo::Omitted")
    );
    assert!(forward.warnings.iter().any(|warning| {
        warning.code == ProjectionWarningCode::ClassMembershipLimitExceeded
            && warning.subject == Some(ExportSubject::Function { rva: 0x100 })
            && warning.occurrences == 1
    }));
}

#[test]
fn class_memberships_on_non_function_subjects_warn_as_mismatches() {
    let projection = project([
        claim(
            SymbolSubject::Global {
                binary: binary().id,
                rva: 0x100,
                size: None,
            },
            SymbolAssertion::ClassMembership {
                class_name: "demo::Widget".to_owned(),
            },
            0.9,
            core("class-membership"),
        ),
        claim(
            SymbolSubject::Type {
                binary: binary().id,
                key: "type.widget".to_owned(),
            },
            SymbolAssertion::ClassMembership {
                class_name: "demo::Widget".to_owned(),
            },
            0.9,
            core("class-membership"),
        ),
    ]);

    assert!(projection.globals.is_empty());
    assert!(projection.types.is_empty());
    assert_eq!(
        projection
            .warnings
            .iter()
            .filter(|warning| warning.code == ProjectionWarningCode::AssertionSubjectMismatch)
            .map(|warning| warning.occurrences)
            .sum::<u64>(),
        2
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
    let collision = projection
        .warnings
        .iter()
        .find(|warning| warning.code == ProjectionWarningCode::AddressKindCollision)
        .expect("address-kind collision warning");
    assert_eq!(
        collision.subject,
        Some(ExportSubject::Global { rva: 0x100 })
    );
    assert_eq!(collision.occurrences, 1);
    assert_eq!(
        collision.message,
        "function and global claims share an RVA; debugger bridges suppress the global only when they emit a function record"
    );
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
fn overlapping_weaker_function_boundary_loses_size_but_keeps_its_entry() {
    let projection = project([
        boundary(0x100, 0x100, 0.8, true, "exception-directory"),
        boundary(0x180, 0x20, 1.0, false, "model-boundary"),
    ]);

    assert_eq!(projection.functions.len(), 2);
    assert_eq!(projection.functions[0].rva, 0x100);
    assert_eq!(projection.functions[0].size, Some(0x100));
    assert_eq!(projection.functions[1].rva, 0x180);
    assert!(projection.functions[1].entry_attribution.is_some());
    assert_eq!(projection.functions[1].size, None);
    assert!(projection.functions[1].selected_name.is_none());
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
