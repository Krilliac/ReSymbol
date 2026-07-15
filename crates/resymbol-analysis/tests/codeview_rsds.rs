use resymbol_analysis::{AnalysisError, inspect_pe_codeview};
use resymbol_core::{BinaryFormat, BinaryId};

const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 0xf0;
const RAW_OFFSET: usize = 0x200;
const SECTION_RVA: u32 = 0x1000;
const DEBUG_DIRECTORY_RVA: u32 = 0x1100;
const CODEVIEW_RVA: u32 = 0x1200;
const OVERLAY_OFFSET: usize = 0x800;
const DEBUG_DIRECTORY_INDEX: usize = 6;
const GUID: [u8; 16] = [
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
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

fn file_offset(rva: u32) -> usize {
    RAW_OFFSET + usize::try_from(rva - SECTION_RVA).expect("fixture RVA fits usize")
}

fn set_directory(bytes: &mut [u8], rva: u32, size: u32) {
    let offset = OPTIONAL_OFFSET + 112 + DEBUG_DIRECTORY_INDEX * 8;
    put_u32(bytes, offset, rva);
    put_u32(bytes, offset + 4, size);
}

fn put_debug_entry(
    bytes: &mut [u8],
    index: usize,
    data_rva: u32,
    data_offset: usize,
    data_size: usize,
) {
    let offset = file_offset(DEBUG_DIRECTORY_RVA) + index * 28;
    put_u32(bytes, offset + 4, 0x65aa_55aa);
    put_u16(bytes, offset + 8, 1);
    put_u16(bytes, offset + 10, 2);
    put_u32(bytes, offset + 12, 2);
    put_u32(
        bytes,
        offset + 16,
        u32::try_from(data_size).expect("fixture CodeView size"),
    );
    put_u32(bytes, offset + 20, data_rva);
    put_u32(
        bytes,
        offset + 24,
        u32::try_from(data_offset).expect("fixture CodeView offset"),
    );
}

fn rsds_record(guid: [u8; 16], age: u32, path: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(25 + path.len());
    record.extend_from_slice(b"RSDS");
    record.extend_from_slice(&guid);
    record.extend_from_slice(&age.to_le_bytes());
    record.extend_from_slice(path);
    record.push(0);
    record
}

fn put_record(bytes: &mut [u8], offset: usize, record: &[u8]) {
    bytes[offset..offset + record.len()].copy_from_slice(record);
}

fn fixture(path: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x900];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(
        &mut bytes,
        0x3c,
        u32::try_from(PE_OFFSET).expect("fixture PE offset"),
    );
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 1);
    put_u32(&mut bytes, COFF_OFFSET + 4, 0x1234_5678);
    put_u16(&mut bytes, COFF_OFFSET + 16, 0xf0);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x2022);

    put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, SECTION_RVA);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 24, 0x0000_0001_4000_0000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x2000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 70, 0x8160);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 108, 16);
    set_directory(&mut bytes, DEBUG_DIRECTORY_RVA, 28);

    bytes[SECTION_OFFSET..SECTION_OFFSET + 8].copy_from_slice(b".rdata\0\0");
    put_u32(&mut bytes, SECTION_OFFSET + 8, 0x600);
    put_u32(&mut bytes, SECTION_OFFSET + 12, SECTION_RVA);
    put_u32(&mut bytes, SECTION_OFFSET + 16, 0x600);
    put_u32(
        &mut bytes,
        SECTION_OFFSET + 20,
        u32::try_from(RAW_OFFSET).expect("fixture raw offset"),
    );
    // Populate otherwise-unconsumed source fields so byte-exact retention is tested.
    put_u32(&mut bytes, SECTION_OFFSET + 24, 0x4433_2211);
    put_u32(&mut bytes, SECTION_OFFSET + 28, 0x8877_6655);
    put_u16(&mut bytes, SECTION_OFFSET + 32, 7);
    put_u16(&mut bytes, SECTION_OFFSET + 34, 9);
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x4000_0040);

    let record = rsds_record(GUID, 7, path);
    put_debug_entry(
        &mut bytes,
        0,
        CODEVIEW_RVA,
        file_offset(CODEVIEW_RVA),
        record.len(),
    );
    put_record(&mut bytes, file_offset(CODEVIEW_RVA), &record);
    bytes
}

#[test]
fn inspection_binds_exact_bytes_and_retains_raw_pe_metadata() {
    let bytes = fixture(b"C:\\symbols\\fixture.pdb");
    let expected_header: [u8; 40] = bytes[SECTION_OFFSET..SECTION_OFFSET + 40]
        .try_into()
        .expect("exact section header");

    let inspection = inspect_pe_codeview(&bytes).expect("valid CodeView inspection");

    assert_eq!(inspection.identity().id, BinaryId::digest(&bytes));
    assert_eq!(inspection.identity().size, bytes.len() as u64);
    assert_eq!(inspection.identity().format, BinaryFormat::Pe);
    assert_eq!(inspection.identity().architecture, "x86_64");
    assert_eq!(inspection.identity().image_base, 0x0000_0001_4000_0000);
    assert_eq!(inspection.machine(), 0x8664);
    assert_eq!(inspection.section_headers(), [expected_header]);
    assert_eq!(inspection.rsds().debug_directory_index(), 0);
    assert_eq!(inspection.rsds().guid(), GUID);
    assert_eq!(inspection.rsds().age(), 7);
    assert_eq!(inspection.rsds().pdb_path(), b"C:\\symbols\\fixture.pdb");
}

#[test]
fn non_utf8_advisory_path_is_preserved_without_decoding() {
    let path = [b'C', b':', b'\\', 0xff, 0x80, b'.', b'p', b'd', b'b'];
    let inspection = inspect_pe_codeview(&fixture(&path)).expect("non-UTF-8 path is advisory");
    assert_eq!(inspection.rsds().pdb_path(), path);
}

#[test]
fn pointer_only_overlay_rsds_is_accepted() {
    let mut bytes = fixture(b"mapped.pdb");
    let record = rsds_record(GUID, 11, b"overlay.pdb");
    put_debug_entry(&mut bytes, 0, 0, OVERLAY_OFFSET, record.len());
    put_record(&mut bytes, OVERLAY_OFFSET, &record);

    let inspection = inspect_pe_codeview(&bytes).expect("pointer-only overlay is valid");
    assert_eq!(inspection.rsds().age(), 11);
    assert_eq!(inspection.rsds().pdb_path(), b"overlay.pdb");
}

#[test]
fn conflicting_rva_and_file_pointer_are_rejected() {
    let mut bytes = fixture(b"mapped.pdb");
    let record = rsds_record(GUID, 11, b"overlay.pdb");
    put_debug_entry(&mut bytes, 0, CODEVIEW_RVA, OVERLAY_OFFSET, record.len());
    put_record(&mut bytes, OVERLAY_OFFSET, &record);

    let error = inspect_pe_codeview(&bytes).expect_err("locations conflict");
    assert!(matches!(error, AnalysisError::InvalidField { .. }));
    assert!(error.to_string().contains("PointerToRawData"));
}

#[test]
fn multiple_rsds_records_are_rejected_even_when_identity_matches() {
    let mut bytes = fixture(b"first.pdb");
    set_directory(&mut bytes, DEBUG_DIRECTORY_RVA, 56);
    let second_rva = 0x1280;
    let second = rsds_record(GUID, 7, b"second.pdb");
    put_debug_entry(
        &mut bytes,
        1,
        second_rva,
        file_offset(second_rva),
        second.len(),
    );
    put_record(&mut bytes, file_offset(second_rva), &second);

    let error = inspect_pe_codeview(&bytes).expect_err("multiple RSDS records are ambiguous");
    assert!(matches!(error, AnalysisError::InvalidField { .. }));
    assert!(error.to_string().contains("multiple RSDS records"));
}

#[test]
fn missing_or_legacy_codeview_identity_is_explicit() {
    let mut missing = fixture(b"fixture.pdb");
    set_directory(&mut missing, 0, 0);
    let error = inspect_pe_codeview(&missing).expect_err("debug directory is required");
    assert!(error.to_string().contains("no debug-directory entry"));

    let mut legacy = fixture(b"fixture.pdb");
    let data = file_offset(CODEVIEW_RVA);
    legacy[data..data + 4].copy_from_slice(b"NB10");
    let error = inspect_pe_codeview(&legacy).expect_err("legacy CodeView is not RSDS");
    assert!(
        error
            .to_string()
            .contains("no IMAGE_DEBUG_TYPE_CODEVIEW RSDS")
    );
}

#[test]
fn malformed_debug_directory_and_rsds_ranges_fail_before_allocation() {
    let mut misaligned = fixture(b"fixture.pdb");
    set_directory(&mut misaligned, DEBUG_DIRECTORY_RVA, 29);
    let error = inspect_pe_codeview(&misaligned).expect_err("entry table is misaligned");
    assert!(error.to_string().contains("28-byte"));

    let mut short = fixture(b"fixture.pdb");
    let entry = file_offset(DEBUG_DIRECTORY_RVA);
    put_u32(&mut short, entry + 16, 23);
    let error = inspect_pe_codeview(&short).expect_err("RSDS header is truncated");
    assert!(error.to_string().contains("at least 24"));

    let mut outside = fixture(b"fixture.pdb");
    put_u32(&mut outside, entry + 24, 0x8f8);
    put_u32(&mut outside, entry + 20, 0);
    put_u32(&mut outside, entry + 16, 32);
    let error = inspect_pe_codeview(&outside).expect_err("raw range leaves the file");
    assert!(matches!(error, AnalysisError::Truncated { .. }));
}

#[test]
fn declared_debug_directory_entry_count_is_bounded_before_mapping() {
    let mut bytes = fixture(b"fixture.pdb");
    set_directory(&mut bytes, DEBUG_DIRECTORY_RVA, 28 * 4_097);

    let error = inspect_pe_codeview(&bytes)
        .expect_err("the declared entry count is rejected before mapping its table");
    assert!(matches!(
        error,
        AnalysisError::LimitExceeded {
            kind: "debug-directory entry",
            count: 4_097,
            limit: 4_096,
        }
    ));
}

#[test]
fn declared_codeview_byte_limits_are_explicit() {
    let mut oversized_debug_data = fixture(b"fixture.pdb");
    let entry = file_offset(DEBUG_DIRECTORY_RVA);
    put_u32(&mut oversized_debug_data, entry + 16, 67_108_865);
    let error = inspect_pe_codeview(&oversized_debug_data)
        .expect_err("the debug-data size is rejected before reading its bytes");
    assert!(matches!(
        error,
        AnalysisError::LimitExceeded {
            kind: "CodeView debug-data byte",
            count: 67_108_865,
            limit: 67_108_864,
        }
    ));

    let record_size = 65_537;
    let mut oversized_rsds = fixture(b"fixture.pdb");
    oversized_rsds.resize(OVERLAY_OFFSET + record_size, 0);
    put_debug_entry(&mut oversized_rsds, 0, 0, OVERLAY_OFFSET, record_size);
    oversized_rsds[OVERLAY_OFFSET..OVERLAY_OFFSET + 4].copy_from_slice(b"RSDS");
    let error = inspect_pe_codeview(&oversized_rsds)
        .expect_err("the identified RSDS record size is bounded");
    assert!(matches!(
        error,
        AnalysisError::LimitExceeded {
            kind: "RSDS record byte",
            count: 65_537,
            limit: 65_536,
        }
    ));
}

#[test]
fn absent_file_pointer_and_oversized_advisory_path_are_rejected() {
    let mut no_pointer = fixture(b"fixture.pdb");
    let entry = file_offset(DEBUG_DIRECTORY_RVA);
    put_u32(&mut no_pointer, entry + 24, 0);
    let error = inspect_pe_codeview(&no_pointer).expect_err("disk record needs a file pointer");
    assert!(error.to_string().contains("PointerToRawData"));

    let mut long_path_fixture = fixture(b"fixture.pdb");
    let path = vec![b'a'; 4_097];
    let record = rsds_record(GUID, 9, &path);
    long_path_fixture.resize(0x1600, 0);
    put_u32(&mut long_path_fixture, SECTION_OFFSET + 8, 0x1400);
    put_u32(&mut long_path_fixture, SECTION_OFFSET + 16, 0x1400);
    put_u32(&mut long_path_fixture, OPTIONAL_OFFSET + 56, 0x3000);
    put_debug_entry(
        &mut long_path_fixture,
        0,
        CODEVIEW_RVA,
        file_offset(CODEVIEW_RVA),
        record.len(),
    );
    put_record(&mut long_path_fixture, file_offset(CODEVIEW_RVA), &record);
    let error = inspect_pe_codeview(&long_path_fixture).expect_err("path budget is explicit");
    assert!(matches!(
        error,
        AnalysisError::LimitExceeded {
            kind: "RSDS PDB-path byte",
            count: 4_097,
            limit: 4_096,
        }
    ));
}

#[test]
fn unterminated_advisory_path_is_rejected_within_the_declared_record() {
    let mut bytes = fixture(b"fixture.pdb");
    let entry = file_offset(DEBUG_DIRECTORY_RVA);
    let declared_size = u32::from_le_bytes(
        bytes[entry + 16..entry + 20]
            .try_into()
            .expect("debug-data size field"),
    );
    put_u32(
        &mut bytes,
        entry + 16,
        declared_size.checked_sub(1).expect("fixture includes NUL"),
    );

    let error = inspect_pe_codeview(&bytes).expect_err("RSDS path needs an in-record NUL");
    assert!(error.to_string().contains("not NUL-terminated"));
}
