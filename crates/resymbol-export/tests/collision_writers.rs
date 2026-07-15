use resymbol_analysis::{AnalysisSession, PluginRunRecord, PluginRunStatus, analyze_bytes};
use resymbol_core::{
    BinaryId, ClaimProducer, ClaimProvenance, Confidence, Evidence, EvidenceKind, SymbolAssertion,
    SymbolClaim, SymbolSubject, plugin_api::PluginId,
};
use resymbol_export::{
    ExportProjection, ExportSubject, ProjectionWarningCode, render_ghidra_java, render_ida_python,
};

const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 0xf0;
const COLLISION_RVA: u64 = 0x1000;
const GLOBAL_NAME: &str = "same_rva_global";
const FUNCTION_NAME: &str = "named_function";
const PLUGIN_VERSION: &str = "1.2.3";
const RUN_ID: &str = "collision-run-001";

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn minimal_pe() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 1);
    put_u16(&mut bytes, COFF_OFFSET + 16, 0xf0);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x2022);

    put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, COLLISION_RVA as u32);
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
    put_u32(&mut bytes, SECTION_OFFSET + 12, COLLISION_RVA as u32);
    put_u32(&mut bytes, SECTION_OFFSET + 16, 0x200);
    put_u32(&mut bytes, SECTION_OFFSET + 20, 0x200);
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x6000_0020);
    bytes
}

fn plugin_id() -> PluginId {
    PluginId::new("dev.resymbol.collision-writer-test").expect("valid plugin id")
}

fn plugin_claim(
    binary: &BinaryId,
    subject: SymbolSubject,
    assertion: SymbolAssertion,
) -> SymbolClaim {
    SymbolClaim::new(
        subject,
        assertion,
        Confidence::new(0.9).expect("valid confidence"),
        vec![
            Evidence::new(
                EvidenceKind::new(EvidenceKind::METADATA).expect("valid evidence kind"),
                "deterministic address-kind collision fixture",
            )
            .expect("valid evidence"),
        ],
        ClaimProvenance {
            producer: ClaimProducer::Plugin {
                id: plugin_id(),
                version: PLUGIN_VERSION.to_owned(),
            },
            method: "collision-writer-test".to_owned(),
            run_id: Some(RUN_ID.to_owned()),
        },
    )
    .unwrap_or_else(|error| panic!("valid plugin claim for {binary}: {error}"))
}

fn collision_session(include_function_name: bool) -> AnalysisSession {
    let analysis = analyze_bytes(&minimal_pe()).expect("valid synthetic PE");
    let binary = analysis.identity().id.clone();
    let mut claims = vec![plugin_claim(
        &binary,
        SymbolSubject::Global {
            binary: binary.clone(),
            rva: COLLISION_RVA,
            size: None,
        },
        SymbolAssertion::Name {
            name: GLOBAL_NAME.to_owned(),
        },
    )];
    if include_function_name {
        claims.push(plugin_claim(
            &binary,
            SymbolSubject::Function {
                binary: binary.clone(),
                rva: COLLISION_RVA,
                size: None,
            },
            SymbolAssertion::Name {
                name: FUNCTION_NAME.to_owned(),
            },
        ));
    }

    let run = PluginRunRecord::new(
        plugin_id(),
        PLUGIN_VERSION,
        RUN_ID,
        BinaryId::digest(b"exact collision writer test plugin").to_string(),
        PluginRunStatus::Succeeded,
        u64::try_from(claims.len()).expect("fixture claim count fits u64"),
    )
    .expect("valid plugin run");
    AnalysisSession::new(analysis, vec![run], claims).expect("valid analysis session")
}

fn assert_collision_warning(projection: &ExportProjection) {
    let warnings = projection
        .warnings
        .iter()
        .filter(|warning| warning.code == ProjectionWarningCode::AddressKindCollision)
        .collect::<Vec<_>>();
    assert_eq!(warnings.len(), 1);
    assert_eq!(
        warnings[0].subject,
        Some(ExportSubject::Global { rva: COLLISION_RVA })
    );
    assert_eq!(warnings[0].occurrences, 1);
    assert_eq!(
        warnings[0].message,
        "function and global claims share an RVA; debugger bridges suppress the global only when they emit a function record"
    );
}

#[test]
fn entry_only_function_keeps_same_rva_global_in_both_debugger_writers() {
    let session = collision_session(false);
    let graph = session
        .combined_symbol_graph()
        .expect("combined session graph");
    assert!(graph.claims().iter().any(|claim| {
        matches!(
            (claim.subject(), claim.assertion()),
            (
                SymbolSubject::Function {
                    rva: COLLISION_RVA,
                    ..
                },
                SymbolAssertion::FunctionEntry
            )
        )
    }));
    assert!(graph.claims().iter().any(|claim| {
        matches!(
            (claim.subject(), claim.assertion()),
            (
                SymbolSubject::Global {
                    rva: COLLISION_RVA,
                    ..
                },
                SymbolAssertion::Name { name }
            ) if name == GLOBAL_NAME
        )
    }));

    let projection = ExportProjection::from_session(&session).expect("session projection");
    assert_collision_warning(&projection);
    let function = projection
        .functions
        .iter()
        .find(|function| function.rva == COLLISION_RVA)
        .expect("entry-point function");
    assert_eq!(
        function
            .entry_attribution
            .as_ref()
            .expect("function-entry attribution")
            .provenance
            .method,
        "pe-entry-point"
    );
    assert!(function.size.is_none());
    assert!(function.selected_name.is_none());

    let ida = render_ida_python(&projection).expect("IDA script");
    assert!(
        ida.contains("FUNCTIONS = (\n)\n\nGLOBALS = (\n    (0x1000, \"same_rva_global\"),\n)\n\n")
    );
    assert!(!ida.contains("(0x1000, None,"));

    let ghidra =
        render_ghidra_java(&projection, "ReSymbolCollisionEntryOnly").expect("Ghidra script");
    assert!(ghidra.contains("applyGlobalRecord(\"1000,c2FtZV9ydmFfZ2xvYmFs\");"));
    assert!(!ghidra.contains("applyFunctionRecord(\"1000,"));
}

#[test]
fn named_function_suppresses_same_rva_global_in_both_debugger_writers() {
    let session = collision_session(true);
    let projection = ExportProjection::from_session(&session).expect("session projection");
    assert_collision_warning(&projection);

    let ida = render_ida_python(&projection).expect("IDA script");
    assert!(ida.contains("    (0x1000, None, \"named_function\"),"));
    assert!(!ida.contains("    (0x1000, \"same_rva_global\"),"));

    let ghidra = render_ghidra_java(&projection, "ReSymbolCollisionNamed").expect("Ghidra script");
    assert!(ghidra.contains("applyFunctionRecord(\"1000,,bmFtZWRfZnVuY3Rpb24=\");"));
    assert!(!ghidra.contains("applyGlobalRecord(\"1000,c2FtZV9ydmFfZ2xvYmFs\");"));
}
