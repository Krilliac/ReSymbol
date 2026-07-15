use resymbol_analysis::{AnalysisSession, BinaryAnalysis, analyze_bytes};
use resymbol_core::BinaryId;
use resymbol_export::{
    ExportBinaryFormat, ExportControlFlowTarget, ExportProjection, ProjectionWarningCode,
    render_ghidra_java, render_ida_python,
};

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

fn put_c_string(bytes: &mut [u8], offset: usize, value: &str) {
    bytes[offset..offset + value.len()].copy_from_slice(value.as_bytes());
    bytes[offset + value.len()] = 0;
}

fn put_text_rel8(bytes: &mut [u8], rva: u32, opcode: u8, target_rva: u32) {
    let next_rva = rva.checked_add(2).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i8::try_from(displacement).expect("fixture rel8 displacement");
    let offset = 0x200 + usize::try_from(rva - 0x1000).expect("fixture text RVA");
    bytes[offset..offset + 2].copy_from_slice(&[opcode, displacement.to_le_bytes()[0]]);
}

fn put_text_rel32(bytes: &mut [u8], rva: u32, opcode: u8, target_rva: u32) {
    let next_rva = rva.checked_add(5).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i32::try_from(displacement).expect("fixture rel32 displacement");
    let offset = 0x200 + usize::try_from(rva - 0x1000).expect("fixture text RVA");
    bytes[offset] = opcode;
    bytes[offset + 1..offset + 5].copy_from_slice(&displacement.to_le_bytes());
}

fn put_text_conditional_rel32(bytes: &mut [u8], rva: u32, condition_opcode: u8, target_rva: u32) {
    let next_rva = rva.checked_add(6).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i32::try_from(displacement).expect("fixture rel32 displacement");
    let offset = 0x200 + usize::try_from(rva - 0x1000).expect("fixture text RVA");
    bytes[offset..offset + 2].copy_from_slice(&[0x0f, condition_opcode]);
    bytes[offset + 2..offset + 6].copy_from_slice(&displacement.to_le_bytes());
}

fn put_text_lea(bytes: &mut [u8], rva: u32, target_rva: u32) {
    let next_rva = rva.checked_add(7).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i32::try_from(displacement).expect("fixture RIP displacement");
    let offset = 0x200 + usize::try_from(rva - 0x1000).expect("fixture text RVA");
    bytes[offset..offset + 3].copy_from_slice(&[0x48, 0x8d, 0x05]);
    bytes[offset + 3..offset + 7].copy_from_slice(&displacement.to_le_bytes());
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
    bytes
}

fn control_flow_pe() -> Vec<u8> {
    let mut bytes = minimal_pe();
    let exception_directory = OPTIONAL_OFFSET + 112 + 3 * 8;
    put_u32(&mut bytes, exception_directory, 0x1100);
    put_u32(&mut bytes, exception_directory + 4, 12);

    bytes[0x200..0x205].copy_from_slice(&[0xe8, 0x1b, 0x00, 0x00, 0x00]);
    bytes[0x205] = 0xc3;
    bytes[0x220] = 0xc3;
    put_u32(&mut bytes, 0x300, 0x1000);
    put_u32(&mut bytes, 0x304, 0x1010);
    put_u32(&mut bytes, 0x308, 0x1130);
    bytes
}

fn string_and_data_reference_pe() -> Vec<u8> {
    const RDATA_RVA: u32 = 0x2000;
    const RDATA_OFFSET: usize = 0x400;

    let mut bytes = minimal_pe();
    bytes.resize(0x800, 0);
    put_u16(&mut bytes, COFF_OFFSET + 2, 2);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x3000);

    let rdata_section = SECTION_OFFSET + 40;
    bytes[rdata_section..rdata_section + 7].copy_from_slice(b".rdata\0");
    put_u32(&mut bytes, rdata_section + 8, 0x400);
    put_u32(&mut bytes, rdata_section + 12, RDATA_RVA);
    put_u32(&mut bytes, rdata_section + 16, 0x400);
    put_u32(&mut bytes, rdata_section + 20, RDATA_OFFSET as u32);
    put_u32(&mut bytes, rdata_section + 36, 0x4000_0040);

    let exception_directory = OPTIONAL_OFFSET + 112 + 3 * 8;
    put_u32(&mut bytes, exception_directory, 0x2080);
    put_u32(&mut bytes, exception_directory + 4, 12);
    put_u32(&mut bytes, RDATA_OFFSET + 0x80, 0x1000);
    put_u32(&mut bytes, RDATA_OFFSET + 0x84, 0x1020);
    put_u32(&mut bytes, RDATA_OFFSET + 0x88, 0x2060);

    let put_lea = |bytes: &mut [u8], raw_offset: usize, instruction_rva: u32, target_rva: u32| {
        let next_rva = instruction_rva + 7;
        let displacement = i64::from(target_rva) - i64::from(next_rva);
        let displacement = i32::try_from(displacement).expect("fixture RIP displacement");
        bytes[raw_offset..raw_offset + 3].copy_from_slice(&[0x48, 0x8d, 0x05]);
        bytes[raw_offset + 3..raw_offset + 7].copy_from_slice(&displacement.to_le_bytes());
    };
    put_lea(&mut bytes, 0x200, 0x1000, 0x2000);
    put_lea(&mut bytes, 0x207, 0x1007, 0x2004);
    put_lea(&mut bytes, 0x20e, 0x100e, 0x2022);
    put_lea(&mut bytes, 0x215, 0x1015, 0x2021);
    bytes[0x21c] = 0xc3;

    put_c_string(&mut bytes, RDATA_OFFSET, "Recovered ASCII");
    let mut offset = RDATA_OFFSET + 0x20;
    for unit in "Recovered 世界".encode_utf16() {
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        offset += 2;
    }
    bytes[offset..offset + 2].fill(0);
    bytes
}

fn cfg_control_flow_pe() -> Vec<u8> {
    const RDATA_OFFSET: usize = 0x400;

    let mut bytes = string_and_data_reference_pe();
    bytes[0x200..0x400].fill(0x90);

    // Extend the one runtime-function record installed by the base fixture.
    put_u32(&mut bytes, RDATA_OFFSET + 0x80, 0x1000);
    put_u32(&mut bytes, RDATA_OFFSET + 0x84, 0x1080);
    put_u32(&mut bytes, RDATA_OFFSET + 0x88, 0x2060);

    put_text_rel8(&mut bytes, 0x1000, 0xeb, 0x1004);
    bytes[0x202..0x204].copy_from_slice(&[0xf0, 0x90]);
    put_text_rel32(&mut bytes, 0x1004, 0xe8, 0x1100);
    put_text_lea(&mut bytes, 0x1009, 0x2000);
    put_text_rel8(&mut bytes, 0x1010, 0xeb, 0x1040);

    put_text_rel8(&mut bytes, 0x1040, 0x75, 0x1050);
    put_text_rel32(&mut bytes, 0x1042, 0xe8, 0x1120);
    put_text_rel8(&mut bytes, 0x1047, 0xeb, 0x1060);
    put_text_rel32(&mut bytes, 0x1050, 0xe8, 0x1140);
    put_text_rel8(&mut bytes, 0x1055, 0xeb, 0x1060);
    put_text_rel32(&mut bytes, 0x1060, 0xe8, 0x1160);
    put_text_rel8(&mut bytes, 0x1065, 0x75, 0x1040);
    put_text_conditional_rel32(&mut bytes, 0x1067, 0x85, 0x1180);

    // The valid fallthrough reaches a RET. These relation-shaped bytes follow
    // that reachable terminator and therefore remain unreachable.
    put_text_rel32(&mut bytes, 0x106d, 0xe8, 0x1170);
    bytes[0x272] = 0xc3;
    put_text_rel32(&mut bytes, 0x1073, 0xe8, 0x11a0);
    put_text_lea(&mut bytes, 0x1078, 0x2020);

    // The jump target is backed but outside the runtime-function interval.
    put_text_rel32(&mut bytes, 0x1180, 0xe8, 0x11c0);
    put_text_lea(&mut bytes, 0x1185, 0x2040);
    for rva in [0x1100, 0x1120, 0x1140, 0x1160, 0x1170, 0x11a0, 0x11c0] {
        let offset = 0x200 + usize::try_from(rva - 0x1000).expect("fixture target RVA");
        bytes[offset] = 0xc3;
    }
    put_c_string(&mut bytes, RDATA_OFFSET, "reachable CFG data");
    put_c_string(&mut bytes, RDATA_OFFSET + 0x20, "post RET fake data");
    put_c_string(&mut bytes, RDATA_OFFSET + 0x40, "out of range fake data");
    bytes
}

fn msvc_rtti_pe() -> Vec<u8> {
    const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
    const RDATA_RVA: u32 = 0x2000;
    const RDATA_OFFSET: usize = 0x400;
    let rdata_offset =
        |rva: u32| RDATA_OFFSET + usize::try_from(rva - RDATA_RVA).expect("fixture RVA fits usize");
    let mut bytes = vec![0_u8; 0x800];
    bytes[..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 2);
    put_u16(&mut bytes, COFF_OFFSET + 16, 0xf0);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x2022);

    put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
    // Keep the RTTI virtual slot independent of PE entry-point evidence so the
    // projection proves that class membership alone establishes the function.
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 24, IMAGE_BASE);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x3000);
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

    let rdata_section = SECTION_OFFSET + 40;
    bytes[rdata_section..rdata_section + 7].copy_from_slice(b".rdata\0");
    put_u32(&mut bytes, rdata_section + 8, 0x400);
    put_u32(&mut bytes, rdata_section + 12, RDATA_RVA);
    put_u32(&mut bytes, rdata_section + 16, 0x400);
    put_u32(&mut bytes, rdata_section + 20, RDATA_OFFSET as u32);
    put_u32(&mut bytes, rdata_section + 36, 0x4000_0040);
    bytes[0x200] = 0xc3;

    put_u64(&mut bytes, rdata_offset(0x2100), IMAGE_BASE + 0x2050);
    put_u64(&mut bytes, rdata_offset(0x2108), 0);
    put_c_string(&mut bytes, rdata_offset(0x2110), ".?AVWidget@@");

    put_u32(&mut bytes, rdata_offset(0x2180), 1);
    put_u32(&mut bytes, rdata_offset(0x2184), 0);
    put_u32(&mut bytes, rdata_offset(0x2188), 0);
    put_u32(&mut bytes, rdata_offset(0x218c), 0x2100);
    put_u32(&mut bytes, rdata_offset(0x2190), 0x21c0);
    put_u32(&mut bytes, rdata_offset(0x2194), 0x2180);

    put_u32(&mut bytes, rdata_offset(0x21c0), 0);
    put_u32(&mut bytes, rdata_offset(0x21c4), 0);
    put_u32(&mut bytes, rdata_offset(0x21c8), 1);
    put_u32(&mut bytes, rdata_offset(0x21cc), 0x2200);
    put_u32(&mut bytes, rdata_offset(0x2200), 0x2220);

    put_u32(&mut bytes, rdata_offset(0x2220), 0x2100);
    put_u32(&mut bytes, rdata_offset(0x2224), 0);
    put_u32(&mut bytes, rdata_offset(0x2228), 0);
    put_u32(&mut bytes, rdata_offset(0x222c), u32::MAX);
    put_u32(&mut bytes, rdata_offset(0x2230), 0);
    put_u32(&mut bytes, rdata_offset(0x2234), 0x40);
    put_u32(&mut bytes, rdata_offset(0x2238), 0x21c0);

    put_u64(&mut bytes, rdata_offset(0x2280), IMAGE_BASE + 0x2180);
    put_u64(&mut bytes, rdata_offset(0x2288), IMAGE_BASE + 0x1000);
    bytes
}

#[test]
fn analysis_session_projects_exact_identity_and_keeps_entry_only_writers_empty() {
    let bytes = minimal_pe();
    let analysis = analyze_bytes(&bytes).expect("valid synthetic PE");
    let session = AnalysisSession::new(analysis, Vec::new(), Vec::new()).expect("valid session");

    let projection = ExportProjection::from_session(&session).expect("session projection");
    assert_eq!(projection.binary.id, BinaryId::digest(&bytes));
    assert_eq!(projection.binary.file_size, bytes.len() as u64);
    assert_eq!(projection.binary.format, ExportBinaryFormat::Pe);
    assert_eq!(projection.binary.architecture, "x86_64");
    assert_eq!(projection.binary.image_base, 0x0000_0001_4000_0000);
    assert_eq!(projection.binary.image_size, 0x2000);
    assert_eq!(projection.functions.len(), 1);
    assert_eq!(projection.functions[0].rva, 0x1000);
    assert_eq!(
        projection.functions[0]
            .entry_attribution
            .as_ref()
            .expect("PE entry-point attribution")
            .provenance
            .method,
        "pe-entry-point"
    );
    assert!(projection.functions[0].size.is_none());
    assert!(projection.functions[0].selected_name.is_none());
    assert!(projection.globals.is_empty());
    assert!(projection.types.is_empty());
    assert!(projection.direct_calls.is_empty());
    assert!(projection.thunks.is_empty());
    projection.validate().expect("projection remains valid");

    let ida = render_ida_python(&projection).expect("IDA entry-only script");
    assert!(ida.contains("FUNCTIONS = (\n)\n\nGLOBALS = (\n)"));
    assert!(!ida.contains("    (0x1000,"));

    let ghidra = render_ghidra_java(&projection, "ReSymbolEntryOnlyFixture")
        .expect("Ghidra entry-only script");
    assert!(!ghidra.contains("applyBatch0();"));
    assert!(!ghidra.contains("1000,"));
}

#[test]
fn recovered_direct_call_survives_json_but_entry_only_target_skips_writers() {
    let bytes = control_flow_pe();
    let analysis = analyze_bytes(&bytes).expect("valid PE with a direct call");
    let session = AnalysisSession::new(analysis, Vec::new(), Vec::new()).expect("valid session");
    let projection = ExportProjection::from_session(&session).expect("session projection");

    assert_eq!(projection.schema_version, 6);
    assert_eq!(projection.direct_calls.len(), 1);
    assert_eq!(projection.direct_calls[0].caller_rva, 0x1000);
    assert_eq!(projection.direct_calls[0].call_site_rva, 0x1000);
    assert_eq!(
        projection.direct_calls[0].target,
        ExportControlFlowTarget::Function { rva: 0x1020 }
    );
    let target = projection
        .functions
        .iter()
        .find(|function| function.rva == 0x1020)
        .expect("direct target function entry");
    assert!(target.entry_attribution.is_some());
    assert!(target.size.is_none());
    assert!(target.selected_name.is_none());
    assert!(
        projection
            .warnings
            .iter()
            .all(|warning| warning.code != ProjectionWarningCode::UnsupportedAssertion)
    );

    let json = serde_json::to_string(&projection).expect("JSON projection");
    assert!(json.contains("\"direct_calls\""));
    assert!(json.contains("\"rva\":4128"));

    let ida = render_ida_python(&projection).expect("IDA script");
    assert!(ida.contains("(0x1000, 0x10, None)"));
    assert!(!ida.contains("    (0x1020,"));

    let ghidra =
        render_ghidra_java(&projection, "ReSymbolControlFlowFixture").expect("Ghidra script");
    assert!(ghidra.contains("1000,10,"));
    assert!(!ghidra.contains("1020,"));
}

#[test]
fn cfg_recovery_keeps_session_and_projection_shapes_stable() {
    let bytes = cfg_control_flow_pe();
    let analysis = analyze_bytes(&bytes).expect("valid PE with reachable CFG relationships");
    let session = AnalysisSession::new(analysis, Vec::new(), Vec::new()).expect("valid session");
    let projection = ExportProjection::from_session(&session).expect("session projection");
    projection.validate().expect("projection remains valid");

    assert_eq!(projection.schema_version, 6);
    assert_eq!(
        projection
            .direct_calls
            .iter()
            .map(|call| (call.caller_rva, call.call_site_rva, call.target.clone()))
            .collect::<Vec<_>>(),
        [
            (
                0x1000,
                0x1004,
                ExportControlFlowTarget::Function { rva: 0x1100 },
            ),
            (
                0x1000,
                0x1042,
                ExportControlFlowTarget::Function { rva: 0x1120 },
            ),
            (
                0x1000,
                0x1050,
                ExportControlFlowTarget::Function { rva: 0x1140 },
            ),
            (
                0x1000,
                0x1060,
                ExportControlFlowTarget::Function { rva: 0x1160 },
            ),
            (
                0x1000,
                0x106d,
                ExportControlFlowTarget::Function { rva: 0x1170 },
            ),
        ]
    );
    assert_eq!(projection.data_references.len(), 1);
    assert_eq!(projection.data_references[0].caller_rva, 0x1000);
    assert_eq!(projection.data_references[0].instruction_rva, 0x1009);
    assert_eq!(projection.data_references[0].instruction_size, 7);
    assert_eq!(projection.data_references[0].target_rva, 0x2000);
    assert_eq!(
        projection.data_references[0].referenced_string_rva,
        Some(0x2000)
    );
    assert!(
        projection
            .direct_calls
            .iter()
            .all(|call| !matches!(call.call_site_rva, 0x1073 | 0x1180))
    );
    assert!(
        projection
            .data_references
            .iter()
            .all(|reference| !matches!(reference.instruction_rva, 0x1078 | 0x1185))
    );

    let session_json = serde_json::to_string(&session).expect("serialize CFG session");
    let decoded_session =
        serde_json::from_str::<AnalysisSession>(&session_json).expect("deserialize CFG session");
    let decoded_projection =
        ExportProjection::from_session(&decoded_session).expect("project decoded CFG session");
    assert_eq!(projection, decoded_projection);

    let projection_json = serde_json::to_value(&projection).expect("serialize CFG projection");
    assert_eq!(projection_json["schema_version"], serde_json::json!(6));
    assert_eq!(
        projection_json["direct_calls"][0],
        serde_json::json!({
            "caller_rva": 0x1000,
            "call_site_rva": 0x1004,
            "target": { "kind": "function", "rva": 0x1100 },
            "attribution": projection_json["direct_calls"][0]["attribution"].clone(),
        })
    );
    assert_eq!(
        projection_json["data_references"][0],
        serde_json::json!({
            "caller_rva": 0x1000,
            "instruction_rva": 0x1009,
            "instruction_size": 7,
            "target_rva": 0x2000,
            "referenced_string_rva": 0x2000,
            "attribution": projection_json["data_references"][0]["attribution"].clone(),
        })
    );
}

#[test]
fn recovered_strings_and_data_references_flow_through_the_session_projection() {
    let bytes = string_and_data_reference_pe();
    let analysis = analyze_bytes(&bytes).expect("valid PE with strings and data references");
    let BinaryAnalysis::Pe(pe) = &analysis else {
        panic!("fixture must parse as PE");
    };
    assert_eq!(
        pe.strings
            .iter()
            .filter(|value| matches!(value.rva, 0x2000 | 0x2020))
            .map(|value| (value.rva, value.byte_size, value.value.as_str()))
            .collect::<Vec<_>>(),
        [
            (0x2000, 16, "Recovered ASCII"),
            (0x2020, 26, "Recovered 世界"),
        ]
    );
    assert_eq!(pe.data_references.len(), 4);

    let session = AnalysisSession::new(analysis, Vec::new(), Vec::new()).expect("valid session");
    let projection = ExportProjection::from_session(&session).expect("session projection");
    projection.validate().expect("projection remains valid");

    assert_eq!(projection.schema_version, 6);
    assert_eq!(projection.strings.len(), 2);
    assert_eq!(projection.strings[0].rva, 0x2000);
    assert_eq!(projection.strings[0].value, "Recovered ASCII");
    assert_eq!(projection.strings[1].rva, 0x2020);
    assert_eq!(projection.strings[1].value, "Recovered 世界");
    assert_eq!(projection.data_references.len(), 4);
    assert_eq!(projection.data_references[0].caller_rva, 0x1000);
    assert_eq!(projection.data_references[0].instruction_rva, 0x1000);
    assert_eq!(projection.data_references[0].instruction_size, 7);
    assert_eq!(projection.data_references[0].target_rva, 0x2000);
    assert_eq!(
        projection.data_references[0].referenced_string_rva,
        Some(0x2000)
    );
    assert_eq!(projection.data_references[1].instruction_rva, 0x1007);
    assert_eq!(projection.data_references[1].target_rva, 0x2004);
    assert_eq!(
        projection.data_references[1].referenced_string_rva,
        Some(0x2000)
    );
    assert_eq!(projection.data_references[2].instruction_rva, 0x100e);
    assert_eq!(projection.data_references[2].target_rva, 0x2022);
    assert_eq!(
        projection.data_references[2].referenced_string_rva,
        Some(0x2020)
    );
    assert_eq!(projection.data_references[3].instruction_rva, 0x1015);
    assert_eq!(projection.data_references[3].target_rva, 0x2021);
    assert_eq!(projection.data_references[3].referenced_string_rva, None);
    assert!(projection.strings.iter().all(|value| {
        value.attribution.provenance.method == "pe-string-recovery"
            && value.attribution.confidence == 0.90
    }));
    assert!(projection.data_references.iter().all(|value| {
        value.attribution.provenance.method == "pe-x64-data-reference"
            && value.attribution.confidence == 0.90
    }));

    let projection_json = serde_json::to_value(&projection).expect("JSON projection");
    assert_eq!(
        projection_json["data_references"][0]["referenced_string_rva"],
        serde_json::json!(0x2000)
    );
    assert_eq!(
        projection_json["data_references"][3]["referenced_string_rva"],
        serde_json::Value::Null
    );
    let json = serde_json::to_string(&projection_json).expect("serialized JSON projection");
    assert!(json.contains("\"utf-16-le\""));
    assert!(json.contains("\"data_references\""));
    render_ida_python(&projection).expect("IDA ignores new relationships safely");
    render_ghidra_java(&projection, "ReSymbolStringReferenceFixture")
        .expect("Ghidra ignores new relationships safely");
}

#[test]
fn msvc_rtti_names_and_relationships_flow_into_all_export_inputs() {
    let bytes = msvc_rtti_pe();
    let analysis = analyze_bytes(&bytes).expect("valid PE with MSVC RTTI");
    let BinaryAnalysis::Pe(pe) = &analysis else {
        panic!("fixture must parse as PE");
    };
    assert_eq!(pe.msvc_rtti_vftables.len(), 1);
    assert_eq!(pe.msvc_rtti_vftables[0].class_name, "Widget");

    let session = AnalysisSession::new(analysis, Vec::new(), Vec::new()).expect("valid session");
    let projection = ExportProjection::from_session(&session).expect("session projection");
    projection.validate().expect("projection remains valid");

    assert_eq!(projection.schema_version, 6);
    assert_eq!(projection.types.len(), 1);
    assert_eq!(
        projection.types[0].key,
        "msvc-rtti:type-descriptor:00002100"
    );
    assert_eq!(
        projection.types[0]
            .selected_name
            .as_ref()
            .expect("RTTI type name")
            .source
            .text,
        "Widget"
    );
    assert_eq!(projection.globals.len(), 1);
    assert_eq!(projection.globals[0].rva, 0x2288);
    assert!(projection.globals[0].size.is_none());
    let vftable_name = projection.globals[0]
        .selected_name
        .as_ref()
        .expect("vftable name");
    assert_eq!(vftable_name.source.text, "Widget::vftable");
    assert_eq!(projection.functions.len(), 1);
    assert_eq!(projection.functions[0].rva, 0x1000);
    assert!(projection.functions[0].entry_attribution.is_some());
    assert_eq!(
        projection.functions[0]
            .entry_attribution
            .as_ref()
            .expect("RTTI slot establishes a function entry")
            .provenance
            .method,
        "msvc-rtti-vftable-slot"
    );
    assert_eq!(projection.functions[0].class_memberships.len(), 1);
    assert_eq!(projection.functions[0].class_memberships[0].text, "Widget");
    assert!(
        projection
            .warnings
            .iter()
            .all(|warning| warning.code != ProjectionWarningCode::UnsupportedAssertion)
    );

    let json = serde_json::to_string(&projection).expect("JSON projection");
    assert!(json.contains("Widget::vftable"));
    assert!(json.contains("class_memberships"));

    let ida = render_ida_python(&projection).expect("IDA script");
    assert!(ida.contains("0x2288"));
    assert!(ida.contains(&vftable_name.output_name));
    assert!(!ida.contains("    (0x1000,"));

    let ghidra = render_ghidra_java(&projection, "ReSymbolRttiFixture").expect("Ghidra script");
    assert!(ghidra.contains("2288,"));
    assert!(!ghidra.contains("1000,"));
}
