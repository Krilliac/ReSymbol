use resymbol_analysis::{AnalysisSession, BinaryAnalysis, analyze_bytes};
use resymbol_core::BinaryId;
use resymbol_export::{
    ExportBinaryFormat, ExportProjection, ProjectionWarningCode, render_ghidra_java,
    render_ida_python,
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
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1000);
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
fn analysis_session_projects_exact_pe_identity_and_virtual_image() {
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
    assert!(projection.functions.is_empty());
    assert!(projection.globals.is_empty());
    assert!(projection.types.is_empty());
    projection.validate().expect("projection remains valid");
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

    assert_eq!(projection.schema_version, 2);
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

    let ghidra = render_ghidra_java(&projection, "ReSymbolRttiFixture").expect("Ghidra script");
    assert!(ghidra.contains("2288,"));
}
