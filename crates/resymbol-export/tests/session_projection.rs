use resymbol_analysis::{AnalysisSession, analyze_bytes};
use resymbol_core::BinaryId;
use resymbol_export::{ExportBinaryFormat, ExportProjection};

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
