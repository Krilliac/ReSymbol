use std::{env, fs, path::Path};

use resymbol_analysis::{AnalysisSession, analyze_bytes};
use resymbol_export::{
    AttributedText, ExportGlobal, ExportName, ExportProjection, PdbError, render_pdb,
};

const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 0xf0;
const IMAGE_BASE: u64 = 0x0000_0001_8000_0000;
const DEBUG_DIRECTORY_INDEX: usize = 6;
const DEBUG_DIRECTORY_RVA: u32 = 0x2100;
const CODEVIEW_RVA: u32 = 0x2180;
const GUID: [u8; 16] = [
    0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn rdata_file_offset(rva: u32) -> usize {
    0x400 + usize::try_from(rva - 0x2000).expect("fixture RVA fits usize")
}

fn exact_rsds_pe() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x800];
    bytes[..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 2);
    put_u32(&mut bytes, COFF_OFFSET + 4, 0x1234_abcd);
    put_u16(&mut bytes, COFF_OFFSET + 16, 0xf0);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x2022);

    put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1020);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 24, IMAGE_BASE);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x3000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 70, 0x8160);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 108, 16);

    let debug_directory = OPTIONAL_OFFSET + 112 + DEBUG_DIRECTORY_INDEX * 8;
    put_u32(&mut bytes, debug_directory, DEBUG_DIRECTORY_RVA);
    put_u32(&mut bytes, debug_directory + 4, 28);

    bytes[SECTION_OFFSET..SECTION_OFFSET + 8].copy_from_slice(b".text\0\0\0");
    put_u32(&mut bytes, SECTION_OFFSET + 8, 0x200);
    put_u32(&mut bytes, SECTION_OFFSET + 12, 0x1000);
    put_u32(&mut bytes, SECTION_OFFSET + 16, 0x200);
    put_u32(&mut bytes, SECTION_OFFSET + 20, 0x200);
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x6000_0020);

    let rdata = SECTION_OFFSET + 40;
    bytes[rdata..rdata + 8].copy_from_slice(b".rdata\0\0");
    // The debug directory and complete RSDS record are initialized bytes inside
    // VirtualSize. The remaining SizeOfRawData suffix is file-alignment padding.
    put_u32(&mut bytes, rdata + 8, 0x1c0);
    put_u32(&mut bytes, rdata + 12, 0x2000);
    put_u32(&mut bytes, rdata + 16, 0x200);
    put_u32(&mut bytes, rdata + 20, 0x400);
    put_u32(&mut bytes, rdata + 36, 0x4000_0040);

    // The entry point is a minimal RET at section 1, offset 0x20.
    bytes[0x220] = 0xc3;

    let mut record = Vec::new();
    record.extend_from_slice(b"RSDS");
    record.extend_from_slice(&GUID);
    record.extend_from_slice(&7_u32.to_le_bytes());
    record.extend_from_slice(b"resymbol-rsds-x64.pdb\0");

    let debug_entry = rdata_file_offset(DEBUG_DIRECTORY_RVA);
    put_u32(&mut bytes, debug_entry + 4, 0x65aa_55aa);
    put_u16(&mut bytes, debug_entry + 8, 1);
    put_u16(&mut bytes, debug_entry + 10, 2);
    put_u32(&mut bytes, debug_entry + 12, 2);
    put_u32(&mut bytes, debug_entry + 16, record.len() as u32);
    put_u32(&mut bytes, debug_entry + 20, CODEVIEW_RVA);
    put_u32(
        &mut bytes,
        debug_entry + 24,
        rdata_file_offset(CODEVIEW_RVA) as u32,
    );
    let record_offset = rdata_file_offset(CODEVIEW_RVA);
    bytes[record_offset..record_offset + record.len()].copy_from_slice(&record);
    bytes
}

fn fixture() -> (Vec<u8>, AnalysisSession, ExportProjection) {
    let bytes = exact_rsds_pe();
    let analysis = analyze_bytes(&bytes).expect("valid exact-RSDS PE fixture");
    let session = AnalysisSession::new(analysis, Vec::new(), Vec::new()).expect("valid session");
    let mut projection = ExportProjection::from_session(&session).expect("session projection");
    let function = projection
        .functions
        .iter_mut()
        .find(|function| function.rva == 0x1020)
        .expect("entry-point function");
    let attribution = function
        .entry_attribution
        .clone()
        .expect("entry-point attribution");
    function.selected_name = Some(ExportName {
        source: AttributedText {
            text: "reconstructed_function".to_owned(),
            attribution: attribution.clone(),
        },
        output_name: "reconstructed_function".to_owned(),
    });
    projection.globals.push(ExportGlobal {
        rva: 0x2010,
        size: None,
        size_attribution: None,
        selected_name: Some(ExportName {
            source: AttributedText {
                text: "reconstructed_global".to_owned(),
                attribution,
            },
            output_name: "reconstructed_global".to_owned(),
        }),
        alternate_names: Vec::new(),
    });
    projection
        .validate()
        .expect("valid compatibility projection");
    (bytes, session, projection)
}

fn compatibility_pdb() -> Vec<u8> {
    let (bytes, session, projection) = fixture();
    render_pdb(&session, &projection, &bytes).expect("PDB export")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn renders_deterministic_exact_identity_public_symbol_pdb() {
    let first = compatibility_pdb();
    let second = compatibility_pdb();

    assert_eq!(first, second);
    assert!(first.starts_with(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"));
    assert_eq!(first.len() % 4_096, 0);
    assert!(contains(&first, &GUID));
    assert!(contains(&first, b"reconstructed_function\0"));
    assert!(contains(&first, b"reconstructed_global\0"));
}

#[test]
fn rejects_a_different_source_file_before_writing_pdb_bytes() {
    let (mut bytes, session, projection) = fixture();
    bytes[..2].copy_from_slice(b"ZZ");
    assert!(matches!(
        render_pdb(&session, &projection, &bytes),
        Err(PdbError::SourceSessionMismatch { field: "binary.id" })
    ));
}

/// Writes the fixed cross-reader fixture only when requested by compatibility CI.
#[test]
fn writes_external_compatibility_fixture() {
    let Some(output) = env::var_os("RESYMBOL_PDB_COMPAT_OUTPUT") else {
        eprintln!("RESYMBOL_PDB_COMPAT_OUTPUT is unset; external compatibility write skipped");
        return;
    };
    let output = Path::new(&output);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).expect("create PDB compatibility output directory");
    }
    let pdb = compatibility_pdb();
    fs::write(output, &pdb).expect("write PDB compatibility fixture");
    assert_eq!(fs::read(output).expect("read compatibility fixture"), pdb);
}
