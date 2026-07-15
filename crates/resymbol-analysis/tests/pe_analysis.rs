use resymbol_analysis::{
    AnalysisError, AnalysisSession, BinaryAnalysis, ImportTarget, PluginRunRecord, PluginRunStatus,
    SessionValidationError, analyze_bytes, analyze_pe,
};
use resymbol_core::{
    BinaryId, ClaimProducer, ClaimProvenance, Confidence, Evidence, EvidenceKind, SymbolAssertion,
    SymbolClaim, SymbolSubject, plugin_api::PluginId,
};
use resymbol_package::BinaryBoundPayload;

const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 0xf0;
const RAW_OFFSET: usize = 0x200;
const SECTION_RVA: u32 = 0x1000;

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
    let encoded = value.as_bytes();
    bytes[offset..offset + encoded.len()].copy_from_slice(encoded);
    bytes[offset + encoded.len()] = 0;
}

fn file_offset(rva: u32) -> usize {
    RAW_OFFSET + usize::try_from(rva - SECTION_RVA).expect("fixture RVA fits usize")
}

fn set_directory(bytes: &mut [u8], index: usize, rva: u32, size: u32) {
    let offset = OPTIONAL_OFFSET + 112 + index * 8;
    put_u32(bytes, offset, rva);
    put_u32(bytes, offset + 4, size);
}

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x800];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(
        &mut bytes,
        0x3c,
        u32::try_from(PE_OFFSET).expect("fixture offset"),
    );
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 1);
    put_u32(&mut bytes, COFF_OFFSET + 4, 0x1234_5678);
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
    set_directory(&mut bytes, 0, 0x1100, 0x90);
    set_directory(&mut bytes, 1, 0x1200, 40);
    set_directory(&mut bytes, 3, 0x1300, 12);

    bytes[SECTION_OFFSET..SECTION_OFFSET + 5].copy_from_slice(b".all\0");
    put_u32(&mut bytes, SECTION_OFFSET + 8, 0x600);
    put_u32(&mut bytes, SECTION_OFFSET + 12, SECTION_RVA);
    put_u32(&mut bytes, SECTION_OFFSET + 16, 0x600);
    put_u32(
        &mut bytes,
        SECTION_OFFSET + 20,
        u32::try_from(RAW_OFFSET).expect("fixture raw offset"),
    );
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x6000_0020);

    let export = file_offset(0x1100);
    put_u32(&mut bytes, export + 12, 0x1180);
    put_u32(&mut bytes, export + 16, 1);
    put_u32(&mut bytes, export + 20, 2);
    put_u32(&mut bytes, export + 24, 2);
    put_u32(&mut bytes, export + 28, 0x1140);
    put_u32(&mut bytes, export + 32, 0x1148);
    put_u32(&mut bytes, export + 36, 0x1150);
    put_u32(&mut bytes, file_offset(0x1140), 0x1000);
    put_u32(&mut bytes, file_offset(0x1144), 0);
    put_u32(&mut bytes, file_offset(0x1148), 0x1160);
    put_u32(&mut bytes, file_offset(0x114c), 0x1168);
    put_u16(&mut bytes, file_offset(0x1150), 0);
    put_u16(&mut bytes, file_offset(0x1152), 0);
    put_c_string(&mut bytes, file_offset(0x1160), "ExportA");
    put_c_string(&mut bytes, file_offset(0x1168), "Alias");
    put_c_string(&mut bytes, file_offset(0x1180), "fixture.dll");

    let import = file_offset(0x1200);
    put_u32(&mut bytes, import, 0x1240);
    put_u32(&mut bytes, import + 4, 0x1111_1111);
    put_u32(&mut bytes, import + 8, 0xffff_ffff);
    put_u32(&mut bytes, import + 12, 0x1280);
    put_u32(&mut bytes, import + 16, 0x1260);
    put_u64(&mut bytes, file_offset(0x1240), 0x1290);
    put_u64(&mut bytes, file_offset(0x1248), (1_u64 << 63) | 42);
    put_u64(&mut bytes, file_offset(0x1250), 0);
    put_c_string(&mut bytes, file_offset(0x1280), "KERNEL32.dll");
    put_u16(&mut bytes, file_offset(0x1290), 7);
    put_c_string(&mut bytes, file_offset(0x1292), "Imported");

    let exception = file_offset(0x1300);
    put_u32(&mut bytes, exception, 0x1000);
    put_u32(&mut bytes, exception + 4, 0x1020);
    put_u32(&mut bytes, exception + 8, 0x1350);
    bytes
}

const RTTI_TEXT_RAW_OFFSET: usize = 0x200;
const RTTI_TEXT_RVA: u32 = 0x1000;
const RTTI_RDATA_RAW_OFFSET: usize = 0x400;
const RTTI_RDATA_RVA: u32 = 0x2000;
const RTTI_DATA_RAW_OFFSET: usize = 0x800;
const RTTI_DATA_RVA: u32 = 0x3000;
const RTTI_IMAGE_BASE: u64 = 0x0000_0001_4000_0000;

fn rtti_file_offset(rva: u32) -> usize {
    if (RTTI_TEXT_RVA..RTTI_TEXT_RVA + 0x200).contains(&rva) {
        RTTI_TEXT_RAW_OFFSET
            + usize::try_from(rva - RTTI_TEXT_RVA).expect("fixture text RVA fits usize")
    } else if (RTTI_RDATA_RVA..RTTI_RDATA_RVA + 0x400).contains(&rva) {
        RTTI_RDATA_RAW_OFFSET
            + usize::try_from(rva - RTTI_RDATA_RVA).expect("fixture rdata RVA fits usize")
    } else {
        panic!("RVA 0x{rva:x} is outside the RTTI fixture")
    }
}

fn put_rtti_rva_u32(bytes: &mut [u8], rva: u32, value: u32) {
    put_u32(bytes, rtti_file_offset(rva), value);
}

fn put_rtti_rva_u64(bytes: &mut [u8], rva: u32, value: u64) {
    put_u64(bytes, rtti_file_offset(rva), value);
}

fn rtti_data_file_offset(rva: u32) -> usize {
    RTTI_DATA_RAW_OFFSET
        + usize::try_from(rva - RTTI_DATA_RVA).expect("fixture data RVA fits usize")
}

fn put_writable_type_descriptor(bytes: &mut [u8], rva: u32, name: &str) {
    let offset = rtti_data_file_offset(rva);
    put_u64(bytes, offset, RTTI_IMAGE_BASE + 0x2050);
    put_u64(bytes, offset + 8, 0);
    put_c_string(bytes, offset + 16, name);
}

fn put_complete_object_locator(
    bytes: &mut [u8],
    rva: u32,
    type_descriptor_rva: u32,
    class_hierarchy_descriptor_rva: u32,
) {
    put_rtti_rva_u32(bytes, rva, 1);
    put_rtti_rva_u32(bytes, rva + 4, 0);
    put_rtti_rva_u32(bytes, rva + 8, 0);
    put_rtti_rva_u32(bytes, rva + 12, type_descriptor_rva);
    put_rtti_rva_u32(bytes, rva + 16, class_hierarchy_descriptor_rva);
    put_rtti_rva_u32(bytes, rva + 20, rva);
}

fn put_class_hierarchy_descriptor(
    bytes: &mut [u8],
    rva: u32,
    base_count: u32,
    base_class_array_rva: u32,
) {
    put_rtti_rva_u32(bytes, rva, 0);
    put_rtti_rva_u32(bytes, rva + 4, 0);
    put_rtti_rva_u32(bytes, rva + 8, base_count);
    put_rtti_rva_u32(bytes, rva + 12, base_class_array_rva);
}

fn put_base_class_descriptor(
    bytes: &mut [u8],
    rva: u32,
    type_descriptor_rva: u32,
    num_contained_bases: u32,
    class_hierarchy_descriptor_rva: u32,
) {
    put_rtti_rva_u32(bytes, rva, type_descriptor_rva);
    put_rtti_rva_u32(bytes, rva + 4, num_contained_bases);
    put_rtti_rva_u32(bytes, rva + 8, 0);
    put_rtti_rva_u32(bytes, rva + 12, u32::MAX);
    put_rtti_rva_u32(bytes, rva + 16, 0);
    put_rtti_rva_u32(bytes, rva + 20, 0x40);
    put_rtti_rva_u32(bytes, rva + 24, class_hierarchy_descriptor_rva);
}

fn rtti_fixture() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x800];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(
        &mut bytes,
        0x3c,
        u32::try_from(PE_OFFSET).expect("fixture offset"),
    );
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 2);
    put_u32(&mut bytes, COFF_OFFSET + 4, 0x1234_5678);
    put_u16(&mut bytes, COFF_OFFSET + 16, 0xf0);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x2022);

    put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, RTTI_TEXT_RVA);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 24, RTTI_IMAGE_BASE);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x3000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 70, 0x8160);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 108, 16);
    set_directory(&mut bytes, 3, 0x2000, 24);

    bytes[SECTION_OFFSET..SECTION_OFFSET + 6].copy_from_slice(b".text\0");
    put_u32(&mut bytes, SECTION_OFFSET + 8, 0x200);
    put_u32(&mut bytes, SECTION_OFFSET + 12, RTTI_TEXT_RVA);
    put_u32(&mut bytes, SECTION_OFFSET + 16, 0x200);
    put_u32(
        &mut bytes,
        SECTION_OFFSET + 20,
        u32::try_from(RTTI_TEXT_RAW_OFFSET).expect("fixture text raw offset"),
    );
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x6000_0020);

    let rdata_section = SECTION_OFFSET + 40;
    bytes[rdata_section..rdata_section + 7].copy_from_slice(b".rdata\0");
    put_u32(&mut bytes, rdata_section + 8, 0x400);
    put_u32(&mut bytes, rdata_section + 12, RTTI_RDATA_RVA);
    put_u32(&mut bytes, rdata_section + 16, 0x400);
    put_u32(
        &mut bytes,
        rdata_section + 20,
        u32::try_from(RTTI_RDATA_RAW_OFFSET).expect("fixture rdata raw offset"),
    );
    put_u32(&mut bytes, rdata_section + 36, 0x4000_0040);

    bytes[rtti_file_offset(0x1000)] = 0xc3;
    bytes[rtti_file_offset(0x1020)] = 0xc3;
    put_rtti_rva_u32(&mut bytes, 0x2000, 0x1000);
    put_rtti_rva_u32(&mut bytes, 0x2004, 0x1010);
    put_rtti_rva_u32(&mut bytes, 0x2008, 0x2080);
    put_rtti_rva_u32(&mut bytes, 0x200c, 0x1020);
    put_rtti_rva_u32(&mut bytes, 0x2010, 0x1030);
    put_rtti_rva_u32(&mut bytes, 0x2014, 0x2084);

    put_rtti_rva_u64(&mut bytes, 0x2100, RTTI_IMAGE_BASE + 0x2050);
    put_rtti_rva_u64(&mut bytes, 0x2108, 0);
    put_c_string(&mut bytes, rtti_file_offset(0x2110), ".?AVDerived@@");
    put_rtti_rva_u64(&mut bytes, 0x2140, RTTI_IMAGE_BASE + 0x2050);
    put_rtti_rva_u64(&mut bytes, 0x2148, 0);
    put_c_string(&mut bytes, rtti_file_offset(0x2150), ".?AVBase@@");

    put_complete_object_locator(&mut bytes, 0x2180, 0x2100, 0x21c0);
    put_complete_object_locator(&mut bytes, 0x21a0, 0x2140, 0x21e0);
    put_class_hierarchy_descriptor(&mut bytes, 0x21c0, 2, 0x2200);
    put_class_hierarchy_descriptor(&mut bytes, 0x21e0, 1, 0x2210);

    put_rtti_rva_u32(&mut bytes, 0x2200, 0x2220);
    put_rtti_rva_u32(&mut bytes, 0x2204, 0x2240);
    put_rtti_rva_u32(&mut bytes, 0x2210, 0x2240);
    put_base_class_descriptor(&mut bytes, 0x2220, 0x2100, 1, 0x21c0);
    put_base_class_descriptor(&mut bytes, 0x2240, 0x2140, 0, 0x21e0);

    put_rtti_rva_u64(&mut bytes, 0x2280, RTTI_IMAGE_BASE + 0x2180);
    put_rtti_rva_u64(&mut bytes, 0x2288, RTTI_IMAGE_BASE + 0x1000);
    put_rtti_rva_u64(&mut bytes, 0x2290, RTTI_IMAGE_BASE + 0x1020);

    put_rtti_rva_u64(&mut bytes, 0x22a0, RTTI_IMAGE_BASE + 0x21a0);
    put_rtti_rva_u64(&mut bytes, 0x22a8, RTTI_IMAGE_BASE + 0x1020);

    put_rtti_rva_u64(&mut bytes, 0x22c0, RTTI_IMAGE_BASE + 0x2180);
    put_rtti_rva_u64(&mut bytes, 0x22c8, RTTI_IMAGE_BASE + 0x1000);
    bytes
}

fn rtti_fixture_with_writable_type_descriptors() -> Vec<u8> {
    let mut bytes = rtti_fixture();
    bytes.resize(0xa00, 0);

    put_u16(&mut bytes, COFF_OFFSET + 2, 3);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x4000);

    let data_section = SECTION_OFFSET + 80;
    bytes[data_section..data_section + 6].copy_from_slice(b".data\0");
    put_u32(&mut bytes, data_section + 8, 0x200);
    put_u32(&mut bytes, data_section + 12, RTTI_DATA_RVA);
    put_u32(&mut bytes, data_section + 16, 0x200);
    put_u32(
        &mut bytes,
        data_section + 20,
        u32::try_from(RTTI_DATA_RAW_OFFSET).expect("fixture data raw offset"),
    );
    put_u32(&mut bytes, data_section + 36, 0xc000_0040);

    bytes[rtti_file_offset(0x2100)..rtti_file_offset(0x2160)].fill(0);
    put_writable_type_descriptor(&mut bytes, 0x3000, ".?AVDerived@@");
    put_writable_type_descriptor(&mut bytes, 0x3040, ".?AVBase@@");

    put_rtti_rva_u32(&mut bytes, 0x218c, 0x3000);
    put_rtti_rva_u32(&mut bytes, 0x21ac, 0x3040);
    put_rtti_rva_u32(&mut bytes, 0x2220, 0x3000);
    put_rtti_rva_u32(&mut bytes, 0x2240, 0x3040);
    bytes
}

fn plugin_id() -> PluginId {
    PluginId::new("dev.resymbol.session-test").expect("valid plugin id")
}

fn plugin_run(status: PluginRunStatus, accepted_claim_count: u64) -> PluginRunRecord {
    PluginRunRecord::new(
        plugin_id(),
        "1.2.3",
        "run-001",
        BinaryId::digest(b"exact plugin artifact").to_string(),
        status,
        accepted_claim_count,
    )
    .expect("valid plugin run")
}

fn plugin_claim(
    subject: SymbolSubject,
    assertion: SymbolAssertion,
    producer: ClaimProducer,
    run_id: Option<&str>,
) -> SymbolClaim {
    SymbolClaim::new(
        subject,
        assertion,
        Confidence::new(0.75).expect("valid confidence"),
        vec![
            Evidence::new(
                EvidenceKind::new(EvidenceKind::SIGNATURE_MATCH).expect("valid evidence kind"),
                "matched a deterministic test signature",
            )
            .expect("valid evidence"),
        ],
        ClaimProvenance {
            producer,
            method: "session-test".to_owned(),
            run_id: run_id.map(str::to_owned),
        },
    )
    .expect("valid core claim")
}

fn valid_plugin_claim(binary: BinaryId) -> SymbolClaim {
    plugin_claim(
        SymbolSubject::Function {
            binary,
            rva: 0x1040,
            size: Some(0x10),
        },
        SymbolAssertion::Name {
            name: "PluginRecoveredName".to_owned(),
        },
        ClaimProducer::Plugin {
            id: plugin_id(),
            version: "1.2.3".to_owned(),
        },
        Some("run-001"),
    )
}

#[test]
fn analyzes_minimal_pe_with_imports_exports_and_runtime_functions() {
    let bytes = fixture();
    let analysis = analyze_pe(&bytes).expect("valid synthetic PE");

    assert_eq!(analysis.identity.id, BinaryId::digest(&bytes));
    assert_eq!(analysis.identity.image_base, 0x0000_0001_4000_0000);
    assert_eq!(analysis.pe_header_offset, 0x80);
    assert_eq!(analysis.entry_point_rva, 0x1000);
    assert_eq!(analysis.sections.len(), 1);
    assert_eq!(analysis.sections[0].name, ".all");
    assert_eq!(analysis.export_library_name.as_deref(), Some("fixture.dll"));

    assert_eq!(analysis.imports.len(), 1);
    assert_eq!(analysis.imports[0].name, "KERNEL32.dll");
    assert_eq!(analysis.imports[0].entries.len(), 2);
    assert_eq!(
        analysis.imports[0].entries[0].target,
        ImportTarget::Name {
            hint: 7,
            name: "Imported".to_owned(),
        }
    );
    assert_eq!(
        analysis.imports[0].entries[1].target,
        ImportTarget::Ordinal { ordinal: 42 }
    );

    assert_eq!(analysis.exports.len(), 2);
    assert_eq!(analysis.exports[0].ordinal, 1);
    assert_eq!(analysis.exports[0].address_rva, Some(0x1000));
    assert_eq!(analysis.exports[0].names.len(), 2);
    assert_eq!(analysis.exports[0].names[0].name, "ExportA");
    assert_eq!(analysis.exports[0].names[1].name, "Alias");
    assert_eq!(analysis.exports[1].address_rva, None);

    assert_eq!(analysis.runtime_functions.len(), 1);
    assert_eq!(analysis.runtime_functions[0].begin_rva, 0x1000);
    assert_eq!(analysis.runtime_functions[0].end_rva, 0x1020);
    assert_eq!(analysis.symbol_graph.binaries().len(), 1);
    assert_eq!(analysis.symbol_graph.claims().len(), 3);
    assert!(matches!(
        analysis.symbol_graph.claims()[0].assertion(),
        SymbolAssertion::Name { name } if name == "ExportA"
    ));
    assert_eq!(analysis.symbol_graph.claims()[0].confidence().get(), 0.99);
    assert_eq!(
        analysis.symbol_graph.claims()[0].evidence()[0]
            .confidence
            .expect("exact export evidence")
            .get(),
        1.0
    );
}

#[test]
fn extracts_msvc_rtti_with_shared_locators_and_reused_base_descriptors() {
    let bytes = rtti_fixture();
    let analysis = analyze_pe(&bytes).expect("valid PE with MSVC x64 RTTI");

    assert_eq!(analysis.sections.len(), 2);
    assert_eq!(analysis.runtime_functions.len(), 2);
    assert!(!analysis.msvc_rtti_scan_truncated);
    assert_eq!(analysis.msvc_rtti_vftables.len(), 3);

    let derived = &analysis.msvc_rtti_vftables[0];
    assert_eq!(derived.rva, 0x2288);
    assert_eq!(derived.complete_object_locator_rva, 0x2180);
    assert_eq!(derived.type_descriptor_rva, 0x2100);
    assert_eq!(derived.class_hierarchy_descriptor_rva, 0x21c0);
    assert_eq!(derived.base_class_array_rva, 0x2200);
    assert_eq!(derived.decorated_class_name, ".?AVDerived@@");
    assert_eq!(derived.class_name, "Derived");
    assert_eq!(derived.virtual_function_rvas, [0x1000, 0x1020]);
    assert_eq!(derived.base_classes.len(), 2);
    assert_eq!(derived.base_classes[0].array_index, 0);
    assert_eq!(derived.base_classes[0].descriptor_rva, 0x2220);
    assert_eq!(derived.base_classes[0].name, "Derived");
    assert_eq!(derived.base_classes[0].num_contained_bases, 1);
    assert_eq!(derived.base_classes[1].array_index, 1);
    assert_eq!(derived.base_classes[1].descriptor_rva, 0x2240);
    assert_eq!(derived.base_classes[1].name, "Base");
    assert_eq!(derived.base_classes[1].num_contained_bases, 0);

    let base = &analysis.msvc_rtti_vftables[1];
    assert_eq!(base.rva, 0x22a8);
    assert_eq!(base.complete_object_locator_rva, 0x21a0);
    assert_eq!(base.type_descriptor_rva, 0x2140);
    assert_eq!(base.class_name, "Base");
    assert_eq!(base.base_classes.len(), 1);
    assert_eq!(base.virtual_function_rvas, [0x1020]);

    let second_derived = &analysis.msvc_rtti_vftables[2];
    assert_eq!(second_derived.rva, 0x22c8);
    assert_eq!(second_derived.class_name, "Derived");
    assert_eq!(second_derived.virtual_function_rvas, [0x1000]);

    assert_eq!(
        derived.complete_object_locator_rva, second_derived.complete_object_locator_rva,
        "multiple vftables may share one complete object locator",
    );
    assert_eq!(
        derived.base_classes[1].descriptor_rva, base.base_classes[0].descriptor_rva,
        "one base descriptor may occur in multiple hierarchy arrays",
    );
    assert_eq!(
        analysis.rebuild_symbol_graph().expect("rebuild RTTI graph"),
        analysis.symbol_graph
    );
    assert!(analysis.symbol_graph.claims().iter().all(|claim| {
        !matches!(
            (claim.subject(), claim.assertion()),
            (SymbolSubject::Function { .. }, SymbolAssertion::Name { .. })
        )
    }));

    let json = serde_json::to_string(&analysis).expect("serialize RTTI analysis");
    let decoded = serde_json::from_str(&json).expect("deserialize RTTI analysis");
    assert_eq!(analysis, decoded);
}

#[test]
fn accepts_writable_non_executable_msvc_type_descriptors() {
    let bytes = rtti_fixture_with_writable_type_descriptors();
    let analysis = analyze_pe(&bytes).expect("writable TypeDescriptors are valid MSVC metadata");

    assert_eq!(analysis.sections.len(), 3);
    assert_eq!(analysis.sections[2].name, ".data");
    assert_eq!(analysis.sections[2].characteristics, 0xc000_0040);
    assert!(!analysis.msvc_rtti_scan_truncated);
    assert_eq!(analysis.msvc_rtti_vftables.len(), 3);
    assert_eq!(analysis.msvc_rtti_vftables[0].type_descriptor_rva, 0x3000);
    assert_eq!(analysis.msvc_rtti_vftables[0].class_name, "Derived");
    assert_eq!(analysis.msvc_rtti_vftables[1].type_descriptor_rva, 0x3040);
    assert_eq!(analysis.msvc_rtti_vftables[1].class_name, "Base");
    assert_eq!(analysis.msvc_rtti_vftables[2].type_descriptor_rva, 0x3000);

    let json = serde_json::to_string(&analysis).expect("serialize writable-TypeDescriptor RTTI");
    let decoded = serde_json::from_str(&json).expect("validate writable-TypeDescriptor RTTI");
    assert_eq!(analysis, decoded);
}

#[test]
fn validated_deserialization_rejects_executable_type_descriptors_and_writable_rtti_anchors() {
    let analysis = analyze_pe(&rtti_fixture_with_writable_type_descriptors())
        .expect("valid PE with writable TypeDescriptors");

    let mut executable_type_descriptors =
        serde_json::to_value(&analysis).expect("serialize analysis");
    executable_type_descriptors["sections"][2]["characteristics"] =
        serde_json::json!(0xe000_0040_u32);
    let error =
        serde_json::from_value::<resymbol_analysis::PeAnalysis>(executable_type_descriptors)
            .expect_err("TypeDescriptors in executable data must not enter the trusted model");
    assert!(
        error.to_string().contains("MSVC RTTI type descriptor"),
        "unexpected validation error: {error}"
    );

    let mut writable_anchors = serde_json::to_value(analysis).expect("serialize analysis");
    writable_anchors["sections"][1]["characteristics"] = serde_json::json!(0xc000_0040_u32);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(writable_anchors)
        .expect_err("writable vftable and locator storage must remain invalid");
    assert!(
        error.to_string().contains("MSVC RTTI back-pointer"),
        "unexpected validation error: {error}"
    );
}

#[test]
fn preserves_duplicate_descriptors_inside_one_base_class_array() {
    let mut bytes = rtti_fixture();
    put_rtti_rva_u32(&mut bytes, 0x21c8, 3);
    put_rtti_rva_u32(&mut bytes, 0x2224, 2);
    put_rtti_rva_u32(&mut bytes, 0x2208, 0x2240);

    let analysis = analyze_pe(&bytes).expect("duplicate BCA entries are valid ABI metadata");
    let derived_tables = analysis
        .msvc_rtti_vftables
        .iter()
        .filter(|vftable| vftable.class_name == "Derived")
        .collect::<Vec<_>>();
    assert_eq!(derived_tables.len(), 2);
    for vftable in derived_tables {
        assert_eq!(
            vftable
                .base_classes
                .iter()
                .map(|base| (base.array_index, base.descriptor_rva))
                .collect::<Vec<_>>(),
            [(0, 0x2220), (1, 0x2240), (2, 0x2240)]
        );
    }
}

#[test]
fn rejects_only_a_vftable_whose_first_slot_is_not_file_backed_executable_code() {
    let mut bytes = rtti_fixture();
    put_rtti_rva_u64(&mut bytes, 0x22c8, RTTI_IMAGE_BASE + 0x2100);

    let analysis = analyze_pe(&bytes).expect("a bad RTTI candidate is non-fatal");
    assert_eq!(
        analysis
            .msvc_rtti_vftables
            .iter()
            .map(|vftable| vftable.rva)
            .collect::<Vec<_>>(),
        [0x2288, 0x22a8]
    );
}

#[test]
fn an_rtti_free_pe_produces_no_rtti_records() {
    let mut bytes = rtti_fixture();
    let metadata_start = rtti_file_offset(0x2100);
    let metadata_end = rtti_file_offset(0x2300);
    bytes[metadata_start..metadata_end].fill(0);

    let analysis = analyze_pe(&bytes).expect("RTTI is optional PE metadata");
    assert!(!analysis.msvc_rtti_scan_truncated);
    assert!(analysis.msvc_rtti_vftables.is_empty());
    assert_eq!(analysis.runtime_functions.len(), 2);
}

#[test]
fn skips_a_corrupt_rtti_locator_without_partially_retaining_its_vftables() {
    let mut bytes = rtti_fixture();
    put_rtti_rva_u32(&mut bytes, 0x2220 + 20, 0);

    let analysis = analyze_pe(&bytes).expect("invalid RTTI candidates are non-fatal");
    assert_eq!(analysis.msvc_rtti_vftables.len(), 1);
    assert_eq!(analysis.msvc_rtti_vftables[0].rva, 0x22a8);
    assert_eq!(analysis.msvc_rtti_vftables[0].class_name, "Base");
    assert!(
        analysis
            .msvc_rtti_vftables
            .iter()
            .all(|vftable| vftable.complete_object_locator_rva != 0x2180),
        "both candidates sharing the corrupt locator must be discarded",
    );
}

#[test]
fn validated_deserialization_rejects_tampered_msvc_rtti() {
    let analysis = analyze_pe(&rtti_fixture()).expect("valid PE with RTTI");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    value["msvc_rtti_vftables"][0]["base_classes"][1]["name"] = serde_json::json!("ForgedBase");

    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect_err("tampered demangled RTTI names must not enter the trusted model");
    assert!(error.to_string().contains("MSVC RTTI"));
}

#[test]
fn validated_deserialization_rejects_contradictory_shared_rtti_locators() {
    let analysis = analyze_pe(&rtti_fixture()).expect("valid PE with shared RTTI locator");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    value["msvc_rtti_vftables"][2]["offset"] = serde_json::json!(8);

    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect_err("one locator RVA cannot describe contradictory offsets");
    assert!(
        error.to_string().contains("shared complete object locator"),
        "unexpected validation error: {error}"
    );
}

#[test]
fn validated_deserialization_rejects_contradictory_shared_class_hierarchies() {
    let analysis = analyze_pe(&rtti_fixture()).expect("valid PE with shared class hierarchy");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    value["msvc_rtti_vftables"][2]["hierarchy_attributes"] = serde_json::json!(1);

    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect_err("one CHD RVA cannot describe contradictory hierarchy attributes");
    assert!(
        error.to_string().contains("shared class hierarchy"),
        "unexpected validation error: {error}"
    );
}

#[test]
fn validated_deserialization_accepts_shared_base_class_array_suffixes() {
    let analysis = analyze_pe(&rtti_fixture()).expect("valid PE with distinct base-class arrays");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    value["msvc_rtti_vftables"][1]["base_class_array_rva"] = serde_json::json!(0x2204);

    let decoded = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect("the Base hierarchy may reuse the matching suffix of Derived's BCA");
    assert_eq!(decoded.msvc_rtti_vftables[1].base_class_array_rva, 0x2204);
    assert_eq!(decoded.msvc_rtti_vftables[1].base_classes.len(), 1);
    assert_eq!(
        decoded.msvc_rtti_vftables[1].base_classes[0].descriptor_rva,
        0x2240
    );
}

#[test]
fn validated_deserialization_rejects_contradictory_shared_base_class_arrays() {
    let analysis = analyze_pe(&rtti_fixture()).expect("valid PE with distinct base-class arrays");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    value["msvc_rtti_vftables"][1]["base_class_array_rva"] = serde_json::json!(0x2200);

    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect_err("one BCA RVA cannot describe contradictory descriptor order");
    assert!(
        error.to_string().contains("shared base-class array"),
        "unexpected validation error: {error}"
    );
}

#[test]
fn validated_deserialization_rejects_contradictory_shared_base_descriptors() {
    let analysis = analyze_pe(&rtti_fixture()).expect("valid PE with reused base descriptor");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    value["msvc_rtti_vftables"][0]["base_classes"][1]["member_displacement"] = serde_json::json!(8);

    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect_err("one BCD RVA cannot describe contradictory PMD fields");
    assert!(
        error.to_string().contains("shared base-class descriptor"),
        "unexpected validation error: {error}"
    );
}

#[test]
fn analyze_bytes_exposes_format_independent_accessors() {
    let bytes = fixture();
    let analysis = analyze_bytes(&bytes).expect("recognized PE");
    assert_eq!(analysis.identity().id, BinaryId::digest(&bytes));
    assert_eq!(analysis.binary_id(), &BinaryId::digest(&bytes));
    assert_eq!(analysis.symbol_graph().claims().len(), 3);
    assert!(matches!(analysis, BinaryAnalysis::Pe(_)));
}

#[test]
fn analysis_round_trips_through_serde() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");
    let json = serde_json::to_string(&analysis).expect("serialize analysis");
    let decoded = serde_json::from_str(&json).expect("deserialize analysis");
    assert_eq!(analysis, decoded);
    assert_eq!(
        analysis.rebuild_symbol_graph().expect("rebuild"),
        analysis.symbol_graph
    );
}

#[test]
fn rejects_bad_dos_and_pe_signatures() {
    let mut bad_dos = fixture();
    bad_dos[0..2].copy_from_slice(b"ZZ");
    assert!(matches!(
        analyze_pe(&bad_dos),
        Err(AnalysisError::InvalidDosSignature { .. })
    ));

    let mut bad_pe = fixture();
    bad_pe[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PX\0\0");
    assert!(matches!(
        analyze_pe(&bad_pe),
        Err(AnalysisError::InvalidPeSignature { .. })
    ));
}

#[test]
fn every_truncated_prefix_is_rejected_without_panicking() {
    let bytes = fixture();
    for length in 0..bytes.len() {
        assert!(
            analyze_pe(&bytes[..length]).is_err(),
            "prefix of length {length} unexpectedly parsed"
        );
    }
}

#[test]
fn rejects_unmapped_rvas_with_context() {
    let mut bytes = fixture();
    put_u32(&mut bytes, file_offset(0x1200) + 12, 0x3000);
    let error = analyze_pe(&bytes).expect_err("DLL name RVA is outside the image");
    assert!(matches!(
        error,
        AnalysisError::UnmappedRva {
            context: "import DLL name",
            rva: 0x3000,
            ..
        }
    ));
}

#[test]
fn rejects_unmapped_iat_slots_and_unwind_info() {
    let mut bad_iat = fixture();
    put_u32(&mut bad_iat, file_offset(0x1200) + 16, 0x3000);
    assert!(matches!(
        analyze_pe(&bad_iat),
        Err(AnalysisError::UnmappedRva {
            context: "import address thunk",
            rva: 0x3000,
            ..
        })
    ));

    let mut bad_unwind = fixture();
    put_u32(&mut bad_unwind, file_offset(0x1300) + 8, 0x1700);
    assert!(matches!(
        analyze_pe(&bad_unwind),
        Err(AnalysisError::UnmappedRva {
            context: "runtime-function unwind info",
            rva: 0x1700,
            ..
        })
    ));
}

#[test]
fn validated_deserialization_rejects_reversed_runtime_ranges() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    value["runtime_functions"][0]["end_rva"] = serde_json::json!(0x0fff);

    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect_err("reversed range must not enter the trusted model");
    assert!(error.to_string().contains("runtime-function range"));
}

#[test]
fn validated_deserialization_accepts_prior_generator_provenance_versions() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");
    let mut value = serde_json::to_value(&analysis).expect("serialize analysis");
    for claim in value["symbol_graph"]["claims"]
        .as_array_mut()
        .expect("serialized claims")
    {
        claim["provenance"]["producer"]["version"] = serde_json::json!("0.0.9-alpha.1");
    }

    let decoded = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect("older producer version remains semantically compatible");
    assert_eq!(decoded.identity, analysis.identity);
    assert_eq!(decoded.symbol_graph.claims().len(), 3);
}

#[test]
fn validated_deserialization_rejects_noncanonical_provenance_versions() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    value["symbol_graph"]["claims"][0]["provenance"]["producer"]["version"] =
        serde_json::json!("0.1.0\n");

    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect_err("control characters must not enter trusted provenance");
    assert!(error.to_string().contains("symbol graph"));
}

#[test]
fn validated_deserialization_rejects_noncontiguous_import_metadata() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");

    let mut descriptor = serde_json::to_value(&analysis).expect("serialize analysis");
    descriptor["imports"][0]["descriptor_rva"] = serde_json::json!(0x1214);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(descriptor)
        .expect_err("descriptor source order must be preserved");
    assert!(error.to_string().contains("import descriptor"));

    let mut thunk = serde_json::to_value(analysis).expect("serialize analysis");
    thunk["imports"][0]["entries"][1]["lookup_rva"] = serde_json::json!(0x1250);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(thunk)
        .expect_err("thunk source order must be preserved");
    assert!(error.to_string().contains("import thunk"));
}

#[test]
fn validated_deserialization_rejects_inconsistent_export_metadata() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");

    let mut ordinal = serde_json::to_value(&analysis).expect("serialize analysis");
    ordinal["exports"][1]["ordinal"] = serde_json::json!(4);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(ordinal)
        .expect_err("EAT ordinals must stay contiguous");
    assert!(error.to_string().contains("export ordinal"));

    let mut forwarder = serde_json::to_value(analysis).expect("serialize analysis");
    forwarder["exports"][0]["forwarded_to"] = serde_json::json!("OTHER.Forwarded");
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(forwarder)
        .expect_err("forwarder text requires an in-directory address");
    assert!(error.to_string().contains("export forwarder"));
}

#[test]
fn preserves_duplicate_and_overlapping_runtime_metadata() {
    let mut bytes = fixture();
    set_directory(&mut bytes, 3, 0x1300, 36);
    let table = file_offset(0x1300);
    put_u32(&mut bytes, table + 12, 0x1000);
    put_u32(&mut bytes, table + 16, 0x1020);
    put_u32(&mut bytes, table + 20, 0x1350);
    put_u32(&mut bytes, table + 24, 0x1010);
    put_u32(&mut bytes, table + 28, 0x1030);
    put_u32(&mut bytes, table + 32, 0x1360);

    let analysis = analyze_pe(&bytes).expect("overlap is evidence, not parser ambiguity");
    assert_eq!(analysis.runtime_functions.len(), 3);
    assert_eq!(
        analysis.runtime_functions[0].begin_rva,
        analysis.runtime_functions[1].begin_rva
    );
    assert_eq!(
        analysis.runtime_functions[0].end_rva,
        analysis.runtime_functions[1].end_rva
    );
    assert_eq!(
        analysis.runtime_functions[0].unwind_info_rva,
        analysis.runtime_functions[1].unwind_info_rva
    );
    assert_eq!(analysis.runtime_functions[0].table_index, 0);
    assert_eq!(analysis.runtime_functions[1].table_index, 1);
    assert_eq!(analysis.symbol_graph.claims().len(), 5);
}

#[test]
fn preserves_duplicate_export_name_claims_in_source_order() {
    let mut bytes = fixture();
    put_u32(&mut bytes, file_offset(0x114c), 0x1160);
    let analysis = analyze_pe(&bytes).expect("duplicate export metadata is valid");
    assert_eq!(analysis.exports[0].names[0].name, "ExportA");
    assert_eq!(analysis.exports[0].names[1].name, "ExportA");
    let claims = analysis.symbol_graph.claims();
    assert!(matches!(
        claims[0].assertion(),
        SymbolAssertion::Name { name } if name == "ExportA"
    ));
    assert!(matches!(
        claims[1].assertion(),
        SymbolAssertion::Name { name } if name == "ExportA"
    ));
    assert_ne!(
        claims[0].evidence()[0].artifacts["name_table_index"],
        claims[1].evidence()[0].artifacts["name_table_index"]
    );
}

#[test]
fn classifies_export_names_against_all_runtime_function_starts() {
    let mut bytes = fixture();
    put_u32(&mut bytes, file_offset(0x1144), 0x1010);
    put_u16(&mut bytes, file_offset(0x1152), 1);
    set_directory(&mut bytes, 3, 0x1300, 24);
    let table = file_offset(0x1300);
    put_u32(&mut bytes, table + 12, 0x1010);
    put_u32(&mut bytes, table + 16, 0x1030);
    put_u32(&mut bytes, table + 20, 0x1360);

    let analysis = analyze_pe(&bytes).expect("valid exports at two runtime starts");
    let claims = analysis.symbol_graph.claims();
    assert!(matches!(
        claims[0].subject(),
        SymbolSubject::Function { rva: 0x1000, .. }
    ));
    assert!(matches!(
        claims[1].subject(),
        SymbolSubject::Function { rva: 0x1010, .. }
    ));
    assert!(matches!(
        claims[0].assertion(),
        SymbolAssertion::Name { name } if name == "ExportA"
    ));
    assert!(matches!(
        claims[1].assertion(),
        SymbolAssertion::Name { name } if name == "Alias"
    ));
}

#[test]
fn classifies_non_executable_exports_as_globals() {
    let mut bytes = fixture();
    set_directory(&mut bytes, 3, 0, 0);
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x4000_0040);

    let analysis = analyze_pe(&bytes).expect("valid data export");
    assert_eq!(analysis.symbol_graph.claims().len(), 2);
    assert!(
        analysis
            .symbol_graph
            .claims()
            .iter()
            .all(|claim| matches!(claim.subject(), SymbolSubject::Global { rva: 0x1000, .. }))
    );
}

#[test]
fn rejects_zero_export_name_rvas() {
    let mut bytes = fixture();
    put_u32(&mut bytes, file_offset(0x1148), 0);
    assert!(matches!(
        analyze_pe(&bytes),
        Err(AnalysisError::InvalidField {
            field: "export name RVA",
            ..
        })
    ));
}

#[test]
fn retains_forwarded_exports_without_creating_local_function_claims() {
    let mut bytes = fixture();
    put_u32(&mut bytes, file_offset(0x1140), 0x1170);
    put_c_string(&mut bytes, file_offset(0x1170), "OTHER.Forwarded");

    let analysis = analyze_pe(&bytes).expect("valid forwarded export");
    assert_eq!(
        analysis.exports[0].forwarded_to.as_deref(),
        Some("OTHER.Forwarded")
    );
    assert_eq!(analysis.symbol_graph.claims().len(), 1);
    assert!(matches!(
        analysis.symbol_graph.claims()[0].assertion(),
        SymbolAssertion::FunctionBoundary { .. }
    ));
}

#[test]
fn rejects_an_import_directory_without_a_zero_descriptor() {
    let mut bytes = fixture();
    set_directory(&mut bytes, 1, 0x1200, 20);
    assert!(matches!(
        analyze_pe(&bytes),
        Err(AnalysisError::MissingTerminator {
            context: "import directory"
        })
    ));
}

#[test]
fn rejects_pe32_and_non_amd64_images_explicitly() {
    let mut pe32 = fixture();
    put_u16(&mut pe32, OPTIONAL_OFFSET, 0x010b);
    assert!(matches!(
        analyze_pe(&pe32),
        Err(AnalysisError::UnsupportedOptionalHeader {
            magic: 0x010b,
            expected: 0x020b,
        })
    ));

    let mut x86 = fixture();
    put_u16(&mut x86, COFF_OFFSET, 0x014c);
    assert!(matches!(
        analyze_pe(&x86),
        Err(AnalysisError::UnsupportedMachine {
            machine: 0x014c,
            expected: 0x8664,
        })
    ));
}

#[test]
fn enforces_section_count_limit_before_allocating() {
    let mut bytes = fixture();
    put_u16(&mut bytes, COFF_OFFSET + 2, 97);
    assert!(matches!(
        analyze_pe(&bytes),
        Err(AnalysisError::LimitExceeded {
            kind: "section",
            count: 97,
            limit: 96,
        })
    ));
}

#[test]
fn rejects_unknown_formats_without_guessing() {
    assert!(matches!(
        analyze_bytes(b"\x7fELFtest"),
        Err(AnalysisError::UnsupportedBinaryFormat { .. })
    ));
}

#[test]
fn analysis_session_round_trips_and_combines_without_mutating_the_base_graph() {
    let base_analysis = analyze_bytes(&fixture()).expect("valid PE");
    let base_claims = base_analysis.symbol_graph().claims().to_vec();
    let plugin_claim = valid_plugin_claim(base_analysis.identity().id.clone());
    let session = AnalysisSession::new(
        base_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![plugin_claim.clone()],
    )
    .expect("valid session");

    assert_eq!(session.binary_id(), &session.base_analysis().identity().id);
    assert_eq!(session.base_analysis().symbol_graph().claims(), base_claims);
    let combined = session.combined_symbol_graph().expect("combined graph");
    assert_eq!(combined.claims().len(), base_claims.len() + 1);
    assert_eq!(&combined.claims()[..base_claims.len()], base_claims);
    assert_eq!(combined.claims().last(), Some(&plugin_claim));

    let json = serde_json::to_string(&session).expect("serialize session");
    let decoded: AnalysisSession = serde_json::from_str(&json).expect("deserialize session");
    assert_eq!(decoded, session);
}

#[test]
fn session_deserialization_preserves_the_exact_pe_base_graph_invariant() {
    let base_analysis = analyze_bytes(&fixture()).expect("valid PE");
    let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
        .expect("valid base-only session");
    let mut json = serde_json::to_value(session).expect("serialize session");
    json["base_analysis"]["analysis"]["symbol_graph"]["claims"][0]["confidence"] =
        serde_json::json!(0.25);

    let error = serde_json::from_value::<AnalysisSession>(json)
        .expect_err("tampered deterministic base graph must fail");
    assert!(error.to_string().contains("symbol graph"));
}

#[test]
fn session_rejects_noncanonical_plugin_fingerprints_and_duplicate_runs() {
    let run = plugin_run(PluginRunStatus::Succeeded, 0);
    assert_eq!(run.plugin_id(), &plugin_id());
    assert_eq!(run.plugin_version(), "1.2.3");
    assert_eq!(run.run_id(), "run-001");
    assert_eq!(run.status(), PluginRunStatus::Succeeded);
    assert_eq!(run.accepted_claim_count(), 0);
    assert_eq!(run.artifact_sha256().len(), 64);

    let mut json = serde_json::to_value(&run).expect("serialize run");
    json["artifact_sha256"] = serde_json::json!("A".repeat(64));
    let error = serde_json::from_value::<PluginRunRecord>(json)
        .expect_err("uppercase fingerprint is not canonical");
    assert!(error.to_string().contains("lowercase hexadecimal"));

    let base_analysis = analyze_bytes(&fixture()).expect("valid PE");
    let error = AnalysisSession::new(base_analysis, vec![run.clone(), run], Vec::new())
        .expect_err("duplicate run ids are ambiguous");
    assert!(matches!(
        error,
        SessionValidationError::DuplicateRunId { .. }
    ));

    let error = PluginRunRecord::new(
        plugin_id(),
        "1.2",
        "run-002",
        BinaryId::digest(b"plugin").to_string(),
        PluginRunStatus::Succeeded,
        0,
    )
    .expect_err("plugin version must be canonical SemVer");
    assert!(matches!(
        error,
        SessionValidationError::InvalidPluginVersion
    ));

    let error = PluginRunRecord::new(
        plugin_id(),
        "1.2.3",
        "run-002",
        BinaryId::digest(b"plugin").to_string(),
        PluginRunStatus::Failed,
        1,
    )
    .expect_err("failed runs cannot record accepted claims");
    assert!(matches!(
        error,
        SessionValidationError::FailedRunAcceptedClaims { count: 1, .. }
    ));
}

#[test]
fn session_rejects_claims_for_a_different_binary_or_outside_the_image() {
    let base_analysis = analyze_bytes(&fixture()).expect("valid PE");
    let wrong_binary_claim = valid_plugin_claim(BinaryId::digest(b"different binary"));
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![wrong_binary_claim],
    )
    .expect_err("cross-binary claim must fail");
    assert!(matches!(error, SessionValidationError::WrongBinary { .. }));

    let outside_claim = plugin_claim(
        SymbolSubject::Function {
            binary: base_analysis.identity().id.clone(),
            rva: 0x1fff,
            size: Some(2),
        },
        SymbolAssertion::Name {
            name: "OutsideImage".to_owned(),
        },
        ClaimProducer::Plugin {
            id: plugin_id(),
            version: "1.2.3".to_owned(),
        },
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![outside_claim],
    )
    .expect_err("subject range beyond SizeOfImage must fail");
    assert!(matches!(
        error,
        SessionValidationError::AddressOutsideImage { .. }
    ));

    let outside_boundary = plugin_claim(
        SymbolSubject::Function {
            binary: base_analysis.identity().id.clone(),
            rva: 0x1ff0,
            size: None,
        },
        SymbolAssertion::FunctionBoundary { size: 0x20 },
        ClaimProducer::Plugin {
            id: plugin_id(),
            version: "1.2.3".to_owned(),
        },
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        base_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![outside_boundary],
    )
    .expect_err("asserted boundary beyond SizeOfImage must fail");
    assert!(matches!(
        error,
        SessionValidationError::AddressOutsideImage { .. }
    ));
}

#[test]
fn session_requires_successful_matching_plugin_provenance_and_exact_counts() {
    let base_analysis = analyze_bytes(&fixture()).expect("valid PE");
    let binary = base_analysis.identity().id.clone();

    let core_claim = plugin_claim(
        SymbolSubject::Function {
            binary: binary.clone(),
            rva: 0x1040,
            size: Some(4),
        },
        SymbolAssertion::Comment {
            text: "not plugin-owned".to_owned(),
        },
        ClaimProducer::Core {
            component: "forged".to_owned(),
            version: "1".to_owned(),
        },
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![core_claim],
    )
    .expect_err("core provenance cannot appear in plugin claims");
    assert!(matches!(
        error,
        SessionValidationError::NonPluginProducer { .. }
    ));

    let missing_run = plugin_claim(
        SymbolSubject::Function {
            binary: binary.clone(),
            rva: 0x1040,
            size: Some(4),
        },
        SymbolAssertion::Comment {
            text: "missing run".to_owned(),
        },
        ClaimProducer::Plugin {
            id: plugin_id(),
            version: "1.2.3".to_owned(),
        },
        None,
    );
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![missing_run],
    )
    .expect_err("plugin provenance requires a run id");
    assert!(matches!(error, SessionValidationError::MissingRunId { .. }));

    let unknown_run = plugin_claim(
        SymbolSubject::Function {
            binary: binary.clone(),
            rva: 0x1040,
            size: Some(4),
        },
        SymbolAssertion::Comment {
            text: "unknown run".to_owned(),
        },
        ClaimProducer::Plugin {
            id: plugin_id(),
            version: "1.2.3".to_owned(),
        },
        Some("run-999"),
    );
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![unknown_run],
    )
    .expect_err("claim must reference a recorded run");
    assert!(matches!(error, SessionValidationError::UnknownRun { .. }));

    let mismatched_producer = plugin_claim(
        SymbolSubject::Function {
            binary: binary.clone(),
            rva: 0x1040,
            size: Some(4),
        },
        SymbolAssertion::Comment {
            text: "mismatched producer".to_owned(),
        },
        ClaimProducer::Plugin {
            id: PluginId::new("dev.resymbol.different-plugin").expect("valid plugin id"),
            version: "1.2.3".to_owned(),
        },
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![mismatched_producer],
    )
    .expect_err("producer identity must match its run");
    assert!(matches!(
        error,
        SessionValidationError::ProducerRunMismatch { .. }
    ));

    let valid_claim = valid_plugin_claim(binary);
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Failed, 0)],
        vec![valid_claim.clone()],
    )
    .expect_err("failed runs cannot own accepted claims");
    assert!(matches!(
        error,
        SessionValidationError::UnsuccessfulRun { .. }
    ));

    let error = AnalysisSession::new(
        base_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 2)],
        vec![valid_claim],
    )
    .expect_err("recorded count must equal retained claims");
    assert!(matches!(
        error,
        SessionValidationError::AcceptedClaimCountMismatch {
            recorded: 2,
            actual: 1,
            ..
        }
    ));
}

#[test]
fn function_boundaries_require_function_subjects_and_matching_sizes() {
    let base_analysis = analyze_bytes(&fixture()).expect("valid PE");
    let binary = base_analysis.identity().id.clone();
    let producer = || ClaimProducer::Plugin {
        id: plugin_id(),
        version: "1.2.3".to_owned(),
    };

    let global_boundary = plugin_claim(
        SymbolSubject::Global {
            binary: binary.clone(),
            rva: 0x1040,
            size: Some(4),
        },
        SymbolAssertion::FunctionBoundary { size: 4 },
        producer(),
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![global_boundary],
    )
    .expect_err("function boundaries cannot describe globals");
    assert!(matches!(
        error,
        SessionValidationError::FunctionBoundaryRequiresFunction { .. }
    ));

    let type_boundary = plugin_claim(
        SymbolSubject::Type {
            binary: binary.clone(),
            key: "type-key".to_owned(),
        },
        SymbolAssertion::FunctionBoundary { size: 4 },
        producer(),
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![type_boundary],
    )
    .expect_err("function boundaries cannot describe types");
    assert!(matches!(
        error,
        SessionValidationError::FunctionBoundaryRequiresFunction { .. }
    ));

    let mismatched_size = plugin_claim(
        SymbolSubject::Function {
            binary,
            rva: 0x1040,
            size: Some(8),
        },
        SymbolAssertion::FunctionBoundary { size: 4 },
        producer(),
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![mismatched_size],
    )
    .expect_err("subject and boundary sizes must agree");
    assert!(matches!(
        error,
        SessionValidationError::FunctionBoundarySizeMismatch {
            subject_size: 8,
            boundary_size: 4,
            ..
        }
    ));

    let matching_boundary = plugin_claim(
        SymbolSubject::Function {
            binary: base_analysis.identity().id.clone(),
            rva: 0x1040,
            size: Some(4),
        },
        SymbolAssertion::FunctionBoundary { size: 4 },
        producer(),
        Some("run-001"),
    );
    AnalysisSession::new(
        base_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![matching_boundary],
    )
    .expect("matching function boundary is valid");
}
