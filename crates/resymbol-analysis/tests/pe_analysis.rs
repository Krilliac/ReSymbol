use resymbol_analysis::{
    AnalysisError, AnalysisSession, BinaryAnalysis, ImportTarget, PeControlFlowTarget,
    PeDataReference, PeDirectCall, PeGuardAddressTakenIatEntry, PeGuardCfFunction,
    PeGuardEhContinuationTarget, PeGuardLongJumpTarget, PeLoadConfigGuardMemcpyAnchor,
    PeLoadConfigSecurityAnchors, PeLoadConfigXfgAnchors, PeRecoveredString, PeStringEncoding,
    PeThunk, PeTlsCallback, PluginRunRecord, PluginRunStatus, SessionValidationError,
    analyze_bytes, analyze_pe,
};
use resymbol_core::{
    BinaryId, ClaimProducer, ClaimProvenance, Confidence, ControlFlowTarget, Evidence,
    EvidenceKind, SymbolAssertion, SymbolClaim, SymbolSubject, plugin_api::PluginId,
};
use resymbol_package::{BinaryBoundPayload, DEFAULT_MAX_PACKAGE_BYTES, ResymPackage, to_vec_bound};

const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 0xf0;
const RAW_OFFSET: usize = 0x200;
const SECTION_RVA: u32 = 0x1000;
const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
const TLS_DIRECTORY_RVA: u32 = 0x1380;
const TLS_CALLBACK_TABLE_RVA: u32 = 0x13c0;
const TLS_CALLBACK_LIMIT: usize = 4_096;
const LOAD_CONFIG_DIRECTORY_RVA: u32 = 0x1380;
const LOAD_CONFIG_SECURITY_COOKIE_FIELDS_SIZE: u32 = 96;
const LOAD_CONFIG_GUARD_CF_CHECK_POINTER_FIELDS_SIZE: u32 = 120;
const LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE: u32 = 128;
const LOAD_CONFIG_GUARD_FIELDS_SIZE: u32 = 148;
const LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_FIELDS_SIZE: u32 = 176;
const LOAD_CONFIG_GUARD_LONG_JUMP_FIELDS_SIZE: u32 = 192;
const LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE: u32 = 280;
const LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_FIELDS_SIZE: u32 = 288;
const LOAD_CONFIG_GUARD_XFG_DISPATCH_POINTER_FIELDS_SIZE: u32 = 296;
const LOAD_CONFIG_GUARD_XFG_TABLE_DISPATCH_POINTER_FIELDS_SIZE: u32 = 304;
const LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE: u32 = 312;
const LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE: u32 = 320;
const GUARD_CF_FUNCTION_TABLE_RVA: u32 = 0x1480;
const EXTENDED_GUARD_CF_FUNCTION_TABLE_RVA: u32 = 0x14a0;
const GUARD_ADDRESS_TAKEN_IAT_TABLE_RVA: u32 = 0x14c0;
const GUARD_LONG_JUMP_TARGET_TABLE_RVA: u32 = 0x14e0;
const GUARD_EH_CONTINUATION_TABLE_RVA: u32 = 0x1500;
const SECURITY_COOKIE_RVA: u32 = 0x1520;
const GUARD_CF_CHECK_FUNCTION_POINTER_RVA: u32 = 0x1528;
const GUARD_CF_DISPATCH_FUNCTION_POINTER_RVA: u32 = 0x1530;
const GUARD_XFG_CHECK_FUNCTION_POINTER_RVA: u32 = 0x1540;
const GUARD_XFG_DISPATCH_FUNCTION_POINTER_RVA: u32 = 0x1548;
const GUARD_XFG_TABLE_DISPATCH_FUNCTION_POINTER_RVA: u32 = 0x1550;
const CAST_GUARD_OS_DETERMINED_FAILURE_MODE_RVA: u32 = 0x1558;
const GUARD_MEMCPY_FUNCTION_POINTER_RVA: u32 = 0x1560;
const GUARD_CF_FUNCTION_LIMIT: u64 = 262_144;
const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
const IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
const IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
const IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
const DELAY_IMPORT_DIRECTORY_RVA: u32 = 0x1400;
const DELAY_IMPORT_NAME_RVA: u32 = 0x1440;
const DELAY_IMPORT_MODULE_HANDLE_RVA: u32 = 0x1450;
const DELAY_IMPORT_INT_RVA: u32 = 0x1460;
const DELAY_IMPORT_IAT_RVA: u32 = 0x1480;
const DELAY_IMPORT_HINT_NAME_RVA: u32 = 0x14a0;
const DELAY_IMPORT_BOUND_IAT_RVA: u32 = 0x14c0;
const DELAY_IMPORT_UNLOAD_IAT_RVA: u32 = 0x14e0;
const DELAY_IMPORT_CODE_IAT_RVA: u32 = 0x2000;
const DELAY_IMPORT_CODE_IAT_RAW_OFFSET: usize = 0x800;
const DIRECT_CALL_EVIDENCE_SUMMARY: &str = concat!(
    "exact supported x64 call encoding observed during a bounded ",
    "control-flow-guided traversal of a file-backed runtime-function range",
);
const LEGACY_DIRECT_CALL_EVIDENCE_SUMMARY: &str = concat!(
    "exact supported x64 call encoding observed during a bounded linear sweep ",
    "of a file-backed runtime-function range",
);
const READ_ONLY_POINTER_CALL_EVIDENCE_SUMMARY: &str = concat!(
    "exact RIP-relative x64 indirect call resolved through one fully backed read-only ",
    "in-image pointer slot during bounded runtime traversal",
);
const READ_ONLY_POINTER_THUNK_EVIDENCE_SUMMARY: &str = concat!(
    "exact RIP-relative x64 indirect jump resolved through one fully backed read-only ",
    "in-image pointer slot in the first instruction of a seeded executable candidate",
);
const THUNK_EVIDENCE_SUMMARY: &str =
    "exact unconditional x64 jump in the first instruction of a seeded executable candidate";
const LEGACY_THUNK_EVIDENCE_SUMMARY: &str = concat!(
    "exact unconditional x64 jump in the first instruction of a metadata-seeded ",
    "executable candidate",
);

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

fn expand_single_section(bytes: &mut Vec<u8>, raw_size: u32) {
    assert!(raw_size >= 0x600);
    assert_eq!(raw_size % 0x200, 0, "fixture raw size stays file-aligned");
    bytes.resize(
        RAW_OFFSET + usize::try_from(raw_size).expect("expanded fixture size"),
        0,
    );
    let image_end = SECTION_RVA
        .checked_add(raw_size)
        .expect("expanded section image end");
    let size_of_image = image_end.checked_add(0xfff).expect("aligned image size") & !0xfff;
    put_u32(bytes, OPTIONAL_OFFSET + 56, size_of_image);
    put_u32(bytes, SECTION_OFFSET + 8, raw_size);
    put_u32(bytes, SECTION_OFFSET + 16, raw_size);
}

fn delay_import_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    set_directory(&mut bytes, 13, DELAY_IMPORT_DIRECTORY_RVA, 64);

    let descriptor = file_offset(DELAY_IMPORT_DIRECTORY_RVA);
    put_u32(&mut bytes, descriptor, 1);
    put_u32(&mut bytes, descriptor + 4, DELAY_IMPORT_NAME_RVA);
    put_u32(&mut bytes, descriptor + 8, DELAY_IMPORT_MODULE_HANDLE_RVA);
    put_u32(&mut bytes, descriptor + 12, DELAY_IMPORT_IAT_RVA);
    put_u32(&mut bytes, descriptor + 16, DELAY_IMPORT_INT_RVA);
    put_u32(&mut bytes, descriptor + 28, 0x2222_3333);
    // The second 32-byte descriptor remains the required all-zero terminator.

    put_c_string(
        &mut bytes,
        file_offset(DELAY_IMPORT_NAME_RVA),
        "DELAYED.dll",
    );
    put_u64(&mut bytes, file_offset(DELAY_IMPORT_MODULE_HANDLE_RVA), 0);

    put_u64(
        &mut bytes,
        file_offset(DELAY_IMPORT_INT_RVA),
        u64::from(DELAY_IMPORT_HINT_NAME_RVA),
    );
    put_u64(
        &mut bytes,
        file_offset(DELAY_IMPORT_INT_RVA + 8),
        (1_u64 << 63) | 77,
    );
    put_u64(&mut bytes, file_offset(DELAY_IMPORT_INT_RVA + 16), 0);

    put_u64(
        &mut bytes,
        file_offset(DELAY_IMPORT_IAT_RVA),
        IMAGE_BASE + 0x1040,
    );
    put_u64(
        &mut bytes,
        file_offset(DELAY_IMPORT_IAT_RVA + 8),
        IMAGE_BASE + 0x1080,
    );
    put_u64(&mut bytes, file_offset(DELAY_IMPORT_IAT_RVA + 16), 0);

    put_u16(&mut bytes, file_offset(DELAY_IMPORT_HINT_NAME_RVA), 13);
    put_c_string(
        &mut bytes,
        file_offset(DELAY_IMPORT_HINT_NAME_RVA + 2),
        "DelayedEntry",
    );
    bytes
}

fn delay_import_fixture_with_zero_descriptor_padding() -> Vec<u8> {
    const NAME_RVA: u32 = 0x1500;
    const MODULE_HANDLE_RVA: u32 = 0x1510;
    const INT_RVA: u32 = 0x1520;
    const IAT_RVA: u32 = 0x1540;
    const HINT_NAME_RVA: u32 = 0x1560;

    let mut bytes = delay_import_fixture();
    set_directory(&mut bytes, 13, DELAY_IMPORT_DIRECTORY_RVA, 96);
    bytes[file_offset(DELAY_IMPORT_DIRECTORY_RVA + 32)
        ..file_offset(DELAY_IMPORT_DIRECTORY_RVA + 96)]
        .fill(0);

    let descriptor = file_offset(DELAY_IMPORT_DIRECTORY_RVA);
    put_u32(&mut bytes, descriptor + 4, NAME_RVA);
    put_u32(&mut bytes, descriptor + 8, MODULE_HANDLE_RVA);
    put_u32(&mut bytes, descriptor + 12, IAT_RVA);
    put_u32(&mut bytes, descriptor + 16, INT_RVA);
    put_c_string(&mut bytes, file_offset(NAME_RVA), "DELAYED.dll");
    put_u64(&mut bytes, file_offset(MODULE_HANDLE_RVA), 0);
    put_u64(&mut bytes, file_offset(INT_RVA), u64::from(HINT_NAME_RVA));
    put_u64(&mut bytes, file_offset(INT_RVA + 8), (1_u64 << 63) | 77);
    put_u64(&mut bytes, file_offset(INT_RVA + 16), 0);
    put_u64(&mut bytes, file_offset(IAT_RVA), IMAGE_BASE + 0x1040);
    put_u64(&mut bytes, file_offset(IAT_RVA + 8), IMAGE_BASE + 0x1080);
    put_u64(&mut bytes, file_offset(IAT_RVA + 16), 0);
    put_u16(&mut bytes, file_offset(HINT_NAME_RVA), 13);
    put_c_string(&mut bytes, file_offset(HINT_NAME_RVA + 2), "DelayedEntry");
    bytes
}

fn delay_import_fixture_with_auxiliary_tables() -> Vec<u8> {
    let mut bytes = delay_import_fixture();
    let descriptor = file_offset(DELAY_IMPORT_DIRECTORY_RVA);
    put_u32(&mut bytes, descriptor + 20, DELAY_IMPORT_BOUND_IAT_RVA);
    put_u32(&mut bytes, descriptor + 24, DELAY_IMPORT_UNLOAD_IAT_RVA);

    put_u64(
        &mut bytes,
        file_offset(DELAY_IMPORT_BOUND_IAT_RVA),
        IMAGE_BASE + 0x1050,
    );
    put_u64(
        &mut bytes,
        file_offset(DELAY_IMPORT_BOUND_IAT_RVA + 8),
        IMAGE_BASE + 0x1090,
    );
    put_u64(&mut bytes, file_offset(DELAY_IMPORT_BOUND_IAT_RVA + 16), 0);

    let iat = file_offset(DELAY_IMPORT_IAT_RVA);
    let unload_iat = file_offset(DELAY_IMPORT_UNLOAD_IAT_RVA);
    bytes.copy_within(iat..iat + 24, unload_iat);
    bytes
}

fn delay_import_code_recovery_fixture() -> Vec<u8> {
    let mut bytes = delay_import_fixture();
    bytes.resize(0xa00, 0);
    put_u16(&mut bytes, COFF_OFFSET + 2, 2);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x3000);

    let rdata_section = SECTION_OFFSET + 40;
    bytes[rdata_section..rdata_section + 7].copy_from_slice(b".rdata\0");
    put_u32(&mut bytes, rdata_section + 8, 0x200);
    put_u32(&mut bytes, rdata_section + 12, DELAY_IMPORT_CODE_IAT_RVA);
    put_u32(&mut bytes, rdata_section + 16, 0x200);
    put_u32(
        &mut bytes,
        rdata_section + 20,
        u32::try_from(DELAY_IMPORT_CODE_IAT_RAW_OFFSET).expect("fixture raw offset"),
    );
    put_u32(&mut bytes, rdata_section + 36, 0x4000_0040);

    put_u32(
        &mut bytes,
        file_offset(DELAY_IMPORT_DIRECTORY_RVA) + 12,
        DELAY_IMPORT_CODE_IAT_RVA,
    );
    put_u64(
        &mut bytes,
        DELAY_IMPORT_CODE_IAT_RAW_OFFSET,
        IMAGE_BASE + 0x1040,
    );
    put_u64(
        &mut bytes,
        DELAY_IMPORT_CODE_IAT_RAW_OFFSET + 8,
        IMAGE_BASE + 0x1080,
    );
    put_u64(&mut bytes, DELAY_IMPORT_CODE_IAT_RAW_OFFSET + 16, 0);

    bytes[file_offset(0x1000)..file_offset(0x1020)].fill(0x90);
    put_rip_relative_instruction(&mut bytes, 0x1000, 0x15, DELAY_IMPORT_CODE_IAT_RVA);
    put_rel32_instruction(&mut bytes, 0x1006, 0xe8, 0x1040);
    bytes[file_offset(0x100b)] = 0xc3;
    put_rip_relative_instruction(&mut bytes, 0x1040, 0x25, DELAY_IMPORT_CODE_IAT_RVA + 8);
    bytes
}

fn combined_import_library_budget_fixture() -> Vec<u8> {
    const ACTIVE_NORMAL_LIBRARIES: usize = 4_096;
    const DIRECTORY_RVA: u32 = 0x2000;
    const SECTION_SIZE: u32 = 0x16000;

    let mut bytes = delay_import_fixture();
    expand_single_section(&mut bytes, SECTION_SIZE);
    let descriptor_count = ACTIVE_NORMAL_LIBRARIES + 1;
    let directory_size = u32::try_from(descriptor_count * 20).expect("import directory size");
    set_directory(&mut bytes, 1, DIRECTORY_RVA, directory_size);
    for index in 0..ACTIVE_NORMAL_LIBRARIES {
        let descriptor = file_offset(DIRECTORY_RVA) + index * 20;
        put_u32(&mut bytes, descriptor + 12, 0x1280);
        put_u32(&mut bytes, descriptor + 16, 0x1250);
    }
    bytes
}

fn combined_import_symbol_budget_fixture() -> Vec<u8> {
    const ACTIVE_NORMAL_SYMBOLS: usize = 65_536;
    const LOOKUP_RVA: u32 = 0x2000;
    const IAT_RVA: u32 = 0x83000;
    const SECTION_SIZE: u32 = 0x110000;

    let mut bytes = delay_import_fixture();
    expand_single_section(&mut bytes, SECTION_SIZE);
    let descriptor = file_offset(0x1200);
    put_u32(&mut bytes, descriptor, LOOKUP_RVA);
    put_u32(&mut bytes, descriptor + 16, IAT_RVA);
    for index in 0..ACTIVE_NORMAL_SYMBOLS {
        let delta = u32::try_from(index * 8).expect("import thunk delta");
        put_u64(
            &mut bytes,
            file_offset(LOOKUP_RVA + delta),
            (1_u64 << 63) | 42,
        );
    }
    bytes
}

fn combined_import_name_budget_fixture() -> Vec<u8> {
    const ACTIVE_NORMAL_SYMBOLS: usize = 4_096;
    const LONG_HINT_NAME_RVA: u32 = 0x2000;
    const LOOKUP_RVA: u32 = 0x4000;
    const IAT_RVA: u32 = 0xd000;
    const DELAY_NAME_RVA: u32 = 0x3010;
    const DELAY_HINT_NAME_RVA: u32 = 0x3020;
    const SECTION_SIZE: u32 = 0x16000;

    let mut bytes = delay_import_fixture();
    expand_single_section(&mut bytes, SECTION_SIZE);
    let normal_descriptor = file_offset(0x1200);
    put_u32(&mut bytes, normal_descriptor, LOOKUP_RVA);
    put_u32(&mut bytes, normal_descriptor + 12, LONG_HINT_NAME_RVA + 2);
    put_u32(&mut bytes, normal_descriptor + 16, IAT_RVA);
    put_u16(&mut bytes, file_offset(LONG_HINT_NAME_RVA), 7);
    let long_name = file_offset(LONG_HINT_NAME_RVA + 2);
    bytes[long_name..long_name + 4_095].fill(b'A');
    bytes[long_name + 4_095] = 0;
    for index in 0..ACTIVE_NORMAL_SYMBOLS {
        let delta = u32::try_from(index * 8).expect("import thunk delta");
        put_u64(
            &mut bytes,
            file_offset(LOOKUP_RVA + delta),
            u64::from(LONG_HINT_NAME_RVA),
        );
    }

    let delay_descriptor = file_offset(DELAY_IMPORT_DIRECTORY_RVA);
    put_u32(&mut bytes, delay_descriptor + 4, DELAY_NAME_RVA);
    put_c_string(&mut bytes, file_offset(DELAY_NAME_RVA), "D");
    put_u64(
        &mut bytes,
        file_offset(DELAY_IMPORT_INT_RVA),
        u64::from(DELAY_HINT_NAME_RVA),
    );
    put_u16(&mut bytes, file_offset(DELAY_HINT_NAME_RVA), 1);
    put_c_string(&mut bytes, file_offset(DELAY_HINT_NAME_RVA + 2), "X");
    bytes
}

fn set_guard_cf_load_config(
    bytes: &mut [u8],
    directory_size: u32,
    load_config_size: u32,
    table_va: u64,
    function_count: u64,
    guard_flags: u32,
) {
    set_directory(bytes, 10, LOAD_CONFIG_DIRECTORY_RVA, directory_size);
    let load_config = file_offset(LOAD_CONFIG_DIRECTORY_RVA);
    put_u32(bytes, load_config, load_config_size);
    put_u64(bytes, load_config + 128, table_va);
    put_u64(bytes, load_config + 136, function_count);
    put_u32(bytes, load_config + 144, guard_flags);
}

fn set_load_config_security_anchors(
    bytes: &mut [u8],
    directory_size: u32,
    load_config_size: u32,
    security_cookie_va: u64,
    guard_cf_check_function_pointer_va: u64,
    guard_cf_dispatch_function_pointer_va: u64,
) {
    set_directory(bytes, 10, LOAD_CONFIG_DIRECTORY_RVA, directory_size);
    let load_config = file_offset(LOAD_CONFIG_DIRECTORY_RVA);
    put_u32(bytes, load_config, load_config_size);
    put_u64(bytes, load_config + 88, security_cookie_va);
    put_u64(bytes, load_config + 112, guard_cf_check_function_pointer_va);
    put_u64(
        bytes,
        load_config + 120,
        guard_cf_dispatch_function_pointer_va,
    );
}

fn load_config_security_anchor_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    set_load_config_security_anchors(
        &mut bytes,
        LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE,
        IMAGE_BASE + u64::from(SECURITY_COOKIE_RVA),
        IMAGE_BASE + u64::from(GUARD_CF_CHECK_FUNCTION_POINTER_RVA),
        IMAGE_BASE + u64::from(GUARD_CF_DISPATCH_FUNCTION_POINTER_RVA),
    );
    bytes
}

fn set_load_config_xfg_anchors(
    bytes: &mut [u8],
    directory_size: u32,
    load_config_size: u32,
    guard_xfg_check_function_pointer_va: u64,
    guard_xfg_dispatch_function_pointer_va: u64,
    guard_xfg_table_dispatch_function_pointer_va: u64,
    cast_guard_os_determined_failure_mode_va: u64,
) {
    set_directory(bytes, 10, LOAD_CONFIG_DIRECTORY_RVA, directory_size);
    let load_config = file_offset(LOAD_CONFIG_DIRECTORY_RVA);
    put_u32(bytes, load_config, load_config_size);
    put_u64(
        bytes,
        load_config + 280,
        guard_xfg_check_function_pointer_va,
    );
    put_u64(
        bytes,
        load_config + 288,
        guard_xfg_dispatch_function_pointer_va,
    );
    put_u64(
        bytes,
        load_config + 296,
        guard_xfg_table_dispatch_function_pointer_va,
    );
    put_u64(
        bytes,
        load_config + 304,
        cast_guard_os_determined_failure_mode_va,
    );
}

fn load_config_xfg_anchor_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    set_load_config_xfg_anchors(
        &mut bytes,
        LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE,
        LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE,
        IMAGE_BASE + u64::from(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
        IMAGE_BASE + u64::from(GUARD_XFG_DISPATCH_FUNCTION_POINTER_RVA),
        IMAGE_BASE + u64::from(GUARD_XFG_TABLE_DISPATCH_FUNCTION_POINTER_RVA),
        IMAGE_BASE + u64::from(CAST_GUARD_OS_DETERMINED_FAILURE_MODE_RVA),
    );
    bytes
}

fn set_load_config_guard_memcpy_anchor(
    bytes: &mut [u8],
    directory_size: u32,
    load_config_size: u32,
    guard_memcpy_function_pointer_va: u64,
) {
    set_directory(bytes, 10, LOAD_CONFIG_DIRECTORY_RVA, directory_size);
    let load_config = file_offset(LOAD_CONFIG_DIRECTORY_RVA);
    put_u32(bytes, load_config, load_config_size);
    put_u64(bytes, load_config + 312, guard_memcpy_function_pointer_va);
}

fn load_config_guard_memcpy_anchor_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    set_load_config_guard_memcpy_anchor(
        &mut bytes,
        LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
        IMAGE_BASE + u64::from(GUARD_MEMCPY_FUNCTION_POINTER_RVA),
    );
    bytes
}

fn write_guard_cf_records<const N: usize>(
    bytes: &mut [u8],
    table_rva: u32,
    entries: &[(u32, [u8; N])],
) {
    assert!(N <= 15, "GuardFlags can encode at most 15 metadata bytes");
    let record_size = 4 + N;
    for (index, (rva, metadata)) in entries.iter().enumerate() {
        let record = file_offset(table_rva) + index * record_size;
        put_u32(bytes, record, *rva);
        bytes[record + 4..record + record_size].copy_from_slice(metadata);
    }
}

fn guard_cf_fixture<const N: usize>(entries: &[(u32, [u8; N])]) -> Vec<u8> {
    assert!(N <= 15, "GuardFlags can encode at most 15 metadata bytes");
    let mut bytes = fixture();
    let metadata_size = u32::try_from(N).expect("GuardCF metadata size fits u32");
    let guard_flags = IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT | (metadata_size << 28);
    let table_va = if entries.is_empty() {
        0
    } else {
        IMAGE_BASE + u64::from(GUARD_CF_FUNCTION_TABLE_RVA)
    };
    set_guard_cf_load_config(
        &mut bytes,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        table_va,
        u64::try_from(entries.len()).expect("GuardCF fixture count fits u64"),
        guard_flags,
    );
    write_guard_cf_records(&mut bytes, GUARD_CF_FUNCTION_TABLE_RVA, entries);
    bytes
}

#[derive(Clone, Copy)]
struct ExtendedGuardLoadConfig {
    guard_flags: u32,
    guard_cf_table_va: u64,
    guard_cf_count: u64,
    address_taken_iat_table_va: u64,
    address_taken_iat_count: u64,
    long_jump_table_va: u64,
    long_jump_count: u64,
    eh_continuation_table_va: u64,
    eh_continuation_count: u64,
}

fn empty_extended_guard_load_config(guard_flags: u32) -> ExtendedGuardLoadConfig {
    ExtendedGuardLoadConfig {
        guard_flags,
        guard_cf_table_va: 0,
        guard_cf_count: 0,
        address_taken_iat_table_va: 0,
        address_taken_iat_count: 0,
        long_jump_table_va: 0,
        long_jump_count: 0,
        eh_continuation_table_va: 0,
        eh_continuation_count: 0,
    }
}

fn set_extended_guard_load_config(
    bytes: &mut [u8],
    directory_size: u32,
    load_config_size: u32,
    fields: ExtendedGuardLoadConfig,
) {
    set_guard_cf_load_config(
        bytes,
        directory_size,
        load_config_size,
        fields.guard_cf_table_va,
        fields.guard_cf_count,
        fields.guard_flags,
    );
    let load_config = file_offset(LOAD_CONFIG_DIRECTORY_RVA);
    put_u64(bytes, load_config + 160, fields.address_taken_iat_table_va);
    put_u64(bytes, load_config + 168, fields.address_taken_iat_count);
    put_u64(bytes, load_config + 176, fields.long_jump_table_va);
    put_u64(bytes, load_config + 184, fields.long_jump_count);
    put_u64(bytes, load_config + 264, fields.eh_continuation_table_va);
    put_u64(bytes, load_config + 272, fields.eh_continuation_count);
}

fn valid_extended_guard_load_config() -> ExtendedGuardLoadConfig {
    ExtendedGuardLoadConfig {
        guard_flags: 0x1000_0000
            | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
            | IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT
            | IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT
            | IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT,
        guard_cf_table_va: IMAGE_BASE + u64::from(EXTENDED_GUARD_CF_FUNCTION_TABLE_RVA),
        guard_cf_count: 1,
        address_taken_iat_table_va: IMAGE_BASE + u64::from(GUARD_ADDRESS_TAKEN_IAT_TABLE_RVA),
        address_taken_iat_count: 2,
        long_jump_table_va: IMAGE_BASE + u64::from(GUARD_LONG_JUMP_TARGET_TABLE_RVA),
        long_jump_count: 2,
        eh_continuation_table_va: IMAGE_BASE + u64::from(GUARD_EH_CONTINUATION_TABLE_RVA),
        eh_continuation_count: 2,
    }
}

fn extended_guard_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    set_extended_guard_load_config(
        &mut bytes,
        LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE,
        valid_extended_guard_load_config(),
    );
    write_guard_cf_records(
        &mut bytes,
        EXTENDED_GUARD_CF_FUNCTION_TABLE_RVA,
        &[(0x1040, [0x00])],
    );
    write_guard_cf_records(
        &mut bytes,
        GUARD_ADDRESS_TAKEN_IAT_TABLE_RVA,
        &[(0x1260, [0x00]), (0x1268, [0x00])],
    );
    write_guard_cf_records(
        &mut bytes,
        GUARD_LONG_JUMP_TARGET_TABLE_RVA,
        &[(0x1060, [0x00]), (0x1080, [0x00])],
    );
    write_guard_cf_records(
        &mut bytes,
        GUARD_EH_CONTINUATION_TABLE_RVA,
        &[(0x1050, [0x00]), (0x1070, [0x00])],
    );
    bytes
}

fn set_tls_directory(bytes: &mut [u8], directory_rva: u32, directory_size: u32, callbacks_va: u64) {
    set_directory(bytes, 9, directory_rva, directory_size);
    put_u64(bytes, file_offset(directory_rva) + 24, callbacks_va);
}

fn tls_callbacks_fixture(callback_rvas: &[u32]) -> Vec<u8> {
    let mut bytes = fixture();
    set_tls_directory(
        &mut bytes,
        TLS_DIRECTORY_RVA,
        40,
        IMAGE_BASE + u64::from(TLS_CALLBACK_TABLE_RVA),
    );
    for (index, callback_rva) in callback_rvas.iter().copied().enumerate() {
        let slot = file_offset(TLS_CALLBACK_TABLE_RVA) + index * 8;
        put_u64(&mut bytes, slot, IMAGE_BASE + u64::from(callback_rva));
    }
    let terminator = file_offset(TLS_CALLBACK_TABLE_RVA) + callback_rvas.len() * 8;
    put_u64(&mut bytes, terminator, 0);
    bytes
}

fn expanded_tls_callbacks_fixture(callback_count: usize, next_slot_nonzero: bool) -> Vec<u8> {
    const EXPANDED_SECTION_SIZE: u32 = 0x9000;

    assert!(callback_count <= TLS_CALLBACK_LIMIT);
    let mut bytes = fixture();
    bytes.resize(
        RAW_OFFSET + usize::try_from(EXPANDED_SECTION_SIZE).expect("expanded TLS fixture size"),
        0,
    );
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0xa000);
    put_u32(&mut bytes, SECTION_OFFSET + 8, EXPANDED_SECTION_SIZE);
    put_u32(&mut bytes, SECTION_OFFSET + 16, EXPANDED_SECTION_SIZE);
    set_tls_directory(
        &mut bytes,
        TLS_DIRECTORY_RVA,
        40,
        IMAGE_BASE + u64::from(TLS_CALLBACK_TABLE_RVA),
    );
    for index in 0..callback_count {
        put_u64(
            &mut bytes,
            file_offset(TLS_CALLBACK_TABLE_RVA) + index * 8,
            IMAGE_BASE + 0x1040,
        );
    }
    put_u64(
        &mut bytes,
        file_offset(TLS_CALLBACK_TABLE_RVA) + callback_count * 8,
        if next_slot_nonzero {
            IMAGE_BASE + 0x1060
        } else {
            0
        },
    );
    bytes
}

fn put_rel32_instruction(bytes: &mut [u8], rva: u32, opcode: u8, target_rva: u32) {
    let next_rva = rva.checked_add(5).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i32::try_from(displacement).expect("fixture rel32 displacement");
    let offset = file_offset(rva);
    bytes[offset] = opcode;
    bytes[offset + 1..offset + 5].copy_from_slice(&displacement.to_le_bytes());
}

fn put_rel8_instruction(bytes: &mut [u8], rva: u32, opcode: u8, target_rva: u32) {
    let next_rva = rva.checked_add(2).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i8::try_from(displacement).expect("fixture rel8 displacement");
    let offset = file_offset(rva);
    bytes[offset..offset + 2].copy_from_slice(&[opcode, displacement.to_le_bytes()[0]]);
}

fn put_rip_relative_instruction(bytes: &mut [u8], rva: u32, modrm: u8, target_rva: u32) {
    let next_rva = rva.checked_add(6).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i32::try_from(displacement).expect("fixture RIP displacement");
    let offset = file_offset(rva);
    bytes[offset..offset + 2].copy_from_slice(&[0xff, modrm]);
    bytes[offset + 2..offset + 6].copy_from_slice(&displacement.to_le_bytes());
}

fn put_rex_w_rip_relative_instruction(bytes: &mut [u8], rva: u32, modrm: u8, target_rva: u32) {
    let next_rva = rva.checked_add(7).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i32::try_from(displacement).expect("fixture RIP displacement");
    let offset = file_offset(rva);
    bytes[offset..offset + 3].copy_from_slice(&[0x48, 0xff, modrm]);
    bytes[offset + 3..offset + 7].copy_from_slice(&displacement.to_le_bytes());
}

fn code_recovery_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    bytes[file_offset(0x1000)..file_offset(0x1020)].fill(0x90);

    put_rel32_instruction(&mut bytes, 0x1000, 0xe8, 0x1040);
    put_rip_relative_instruction(&mut bytes, 0x1005, 0x15, 0x1260);
    put_rel32_instruction(&mut bytes, 0x100b, 0xe8, 0x1080);
    put_rel32_instruction(&mut bytes, 0x1010, 0xe8, 0x10a0);
    put_rip_relative_instruction(&mut bytes, 0x1015, 0x15, 0x1270);
    bytes[file_offset(0x101b)] = 0xc3;

    put_rel32_instruction(&mut bytes, 0x1040, 0xe9, 0x1060);
    bytes[file_offset(0x1060)] = 0xc3;
    put_rip_relative_instruction(&mut bytes, 0x1080, 0x25, 0x1268);
    bytes[file_offset(0x10a0)..file_offset(0x10a2)].copy_from_slice(&[0xeb, 0x0e]);
    bytes[file_offset(0x10b0)] = 0xc3;
    bytes
}

fn transitive_thunk_chain_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    bytes[file_offset(0x1000)..file_offset(0x1020)].fill(0x90);

    put_rel32_instruction(&mut bytes, 0x1000, 0xe8, 0x1040);
    bytes[file_offset(0x1005)] = 0xc3;
    put_rel32_instruction(&mut bytes, 0x1040, 0xe9, 0x1060);
    put_rel8_instruction(&mut bytes, 0x1060, 0xeb, 0x1080);
    bytes[file_offset(0x1080)] = 0xc3;

    // This valid-looking thunk is not metadata-seeded or reachable from a
    // retained call/thunk edge, so recovery must leave it undiscovered.
    put_rel32_instruction(&mut bytes, 0x10c0, 0xe9, 0x10e0);
    bytes[file_offset(0x10e0)] = 0xc3;
    bytes
}

fn descending_transitive_thunk_chain_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    bytes[file_offset(0x1000)..file_offset(0x1020)].fill(0x90);

    put_rel32_instruction(&mut bytes, 0x1000, 0xe8, 0x10a0);
    bytes[file_offset(0x1005)] = 0xc3;
    put_rel32_instruction(&mut bytes, 0x10a0, 0xe9, 0x1080);
    put_rel32_instruction(&mut bytes, 0x1080, 0xe9, 0x1060);
    bytes[file_offset(0x1060)] = 0xc3;
    bytes
}

fn cyclic_transitive_thunk_chain_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    bytes[file_offset(0x1000)..file_offset(0x1020)].fill(0x90);

    put_rel32_instruction(&mut bytes, 0x1000, 0xe8, 0x1040);
    bytes[file_offset(0x1005)] = 0xc3;
    put_rel32_instruction(&mut bytes, 0x1040, 0xe9, 0x1060);
    put_rel32_instruction(&mut bytes, 0x1060, 0xe9, 0x1040);
    bytes
}

fn control_flow_suppression_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1040);
    set_directory(&mut bytes, 3, 0x1300, 24);
    let exception = file_offset(0x1300);
    put_u32(&mut bytes, exception + 4, 0x1005);
    put_u32(&mut bytes, exception + 12, 0x1010);
    put_u32(&mut bytes, exception + 16, 0x1020);
    put_u32(&mut bytes, exception + 20, 0x1360);

    bytes[file_offset(0x1000)..file_offset(0x1020)].fill(0x90);
    put_rel32_instruction(&mut bytes, 0x1000, 0xe8, 0x1005);
    put_rel32_instruction(&mut bytes, 0x1010, 0xe8, 0x1018);
    put_rel32_instruction(&mut bytes, 0x1015, 0xe8, 0x1060);
    bytes[file_offset(0x101a)] = 0xc3;
    put_rel32_instruction(&mut bytes, 0x1040, 0xe9, 0x1018);
    bytes[file_offset(0x1060)] = 0xc3;
    bytes
}

fn direct_call_cap_fixture(call_count: usize) -> Vec<u8> {
    const TARGET_RVA: u32 = 0xb100;
    const EXCEPTION_RVA: u32 = 0xb200;
    const UNWIND_INFO_RVA: u32 = 0xb220;
    const SECTION_RAW_SIZE: u32 = 0xa400;

    let raw_size = usize::try_from(SECTION_RAW_SIZE).expect("fixture raw size");
    let mut bytes = vec![0_u8; RAW_OFFSET + raw_size];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(
        &mut bytes,
        0x3c,
        u32::try_from(PE_OFFSET).expect("fixture offset"),
    );
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 1);
    put_u16(&mut bytes, COFF_OFFSET + 16, 0xf0);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x2022);

    put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 24, 0x0000_0001_4000_0000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0xc000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 70, 0x8160);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 108, 16);
    set_directory(&mut bytes, 3, EXCEPTION_RVA, 12);

    bytes[SECTION_OFFSET..SECTION_OFFSET + 6].copy_from_slice(b".text\0");
    put_u32(&mut bytes, SECTION_OFFSET + 8, SECTION_RAW_SIZE);
    put_u32(&mut bytes, SECTION_OFFSET + 12, SECTION_RVA);
    put_u32(&mut bytes, SECTION_OFFSET + 16, SECTION_RAW_SIZE);
    put_u32(
        &mut bytes,
        SECTION_OFFSET + 20,
        u32::try_from(RAW_OFFSET).expect("fixture raw offset"),
    );
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x6000_0020);

    for index in 0..call_count {
        let byte_offset = index.checked_mul(5).expect("fixture call offset");
        let call_rva = SECTION_RVA
            .checked_add(u32::try_from(byte_offset).expect("fixture call RVA"))
            .expect("fixture call RVA");
        put_rel32_instruction(&mut bytes, call_rva, 0xe8, TARGET_RVA);
    }
    let code_size = call_count.checked_mul(5).expect("fixture code size");
    let code_end_rva = SECTION_RVA
        .checked_add(u32::try_from(code_size).expect("fixture code size RVA"))
        .expect("fixture code end RVA");
    bytes[file_offset(TARGET_RVA)] = 0xc3;

    let exception = file_offset(EXCEPTION_RVA);
    put_u32(&mut bytes, exception, SECTION_RVA);
    put_u32(&mut bytes, exception + 4, code_end_rva);
    put_u32(&mut bytes, exception + 8, UNWIND_INFO_RVA);
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

fn put_rel32_instruction_at_rtti_rva(bytes: &mut [u8], rva: u32, opcode: u8, target_rva: u32) {
    let next_rva = rva.checked_add(5).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i32::try_from(displacement).expect("fixture rel32 displacement");
    let offset = rtti_file_offset(rva);
    bytes[offset] = opcode;
    bytes[offset + 1..offset + 5].copy_from_slice(&displacement.to_le_bytes());
}

fn put_rel32_conditional_at_rtti_rva(
    bytes: &mut [u8],
    rva: u32,
    condition_opcode: u8,
    target_rva: u32,
) {
    let next_rva = rva.checked_add(6).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i32::try_from(displacement).expect("fixture rel32 displacement");
    let offset = rtti_file_offset(rva);
    bytes[offset..offset + 2].copy_from_slice(&[0x0f, condition_opcode]);
    bytes[offset + 2..offset + 6].copy_from_slice(&displacement.to_le_bytes());
}

fn put_lea_rip_relative_at_rtti_rva(bytes: &mut [u8], rva: u32, target_rva: u32) {
    let next_rva = rva.checked_add(7).expect("fixture instruction end");
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    let displacement = i32::try_from(displacement).expect("fixture RIP displacement");
    let offset = rtti_file_offset(rva);
    bytes[offset..offset + 3].copy_from_slice(&[0x48, 0x8d, 0x05]);
    bytes[offset + 3..offset + 7].copy_from_slice(&displacement.to_le_bytes());
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

fn put_legacy_base_class_descriptor(
    bytes: &mut [u8],
    rva: u32,
    type_descriptor_rva: u32,
    num_contained_bases: u32,
) {
    put_rtti_rva_u32(bytes, rva, type_descriptor_rva);
    put_rtti_rva_u32(bytes, rva + 4, num_contained_bases);
    put_rtti_rva_u32(bytes, rva + 8, 0);
    put_rtti_rva_u32(bytes, rva + 12, u32::MAX);
    put_rtti_rva_u32(bytes, rva + 16, 0);
    put_rtti_rva_u32(bytes, rva + 20, 0);
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

fn legacy_base_class_rtti_fixture() -> Vec<u8> {
    let mut bytes = rtti_fixture();
    put_legacy_base_class_descriptor(&mut bytes, 0x2220, 0x2100, 1);
    put_rtti_rva_u32(&mut bytes, 0x2238, 0xffff_fffc);
    put_legacy_base_class_descriptor(&mut bytes, 0x2240, 0x2140, 0);
    put_rtti_rva_u32(&mut bytes, 0x2258, 0xffff_fffc);
    bytes
}

fn mixed_base_class_rtti_fixture() -> Vec<u8> {
    let mut bytes = rtti_fixture();
    put_legacy_base_class_descriptor(&mut bytes, 0x2240, 0x2140, 0);
    put_rtti_rva_u32(&mut bytes, 0x2258, 0xffff_fffc);
    bytes
}

fn last_backed_legacy_base_class_rtti_fixture() -> Vec<u8> {
    let mut bytes = rtti_fixture();
    put_rtti_rva_u32(&mut bytes, 0x2204, 0x23e8);
    put_rtti_rva_u32(&mut bytes, 0x2210, 0x23e8);
    put_legacy_base_class_descriptor(&mut bytes, 0x23e8, 0x2140, 0);
    bytes
}

fn rtti_fixture_with_rex_w_iat_control_flow() -> Vec<u8> {
    let mut bytes = rtti_fixture();
    set_directory(&mut bytes, 1, 0x2300, 40);

    put_rtti_rva_u32(&mut bytes, 0x2300, 0x2330);
    put_rtti_rva_u32(&mut bytes, 0x230c, 0x2350);
    put_rtti_rva_u32(&mut bytes, 0x2310, 0x2340);
    put_rtti_rva_u64(&mut bytes, 0x2330, 0x2360);
    put_rtti_rva_u64(&mut bytes, 0x2340, 0x2360);
    put_c_string(&mut bytes, rtti_file_offset(0x2350), "KERNEL32.dll");
    put_u16(&mut bytes, rtti_file_offset(0x2360), 0);
    put_c_string(&mut bytes, rtti_file_offset(0x2362), "Imported");

    bytes[rtti_file_offset(0x1000)..rtti_file_offset(0x1010)].fill(0x90);
    put_rex_w_rip_relative_instruction(&mut bytes, 0x1000, 0x15, 0x2340);
    bytes[rtti_file_offset(0x1007)] = 0xc3;
    bytes[rtti_file_offset(0x1020)..rtti_file_offset(0x1030)].fill(0x90);
    put_rex_w_rip_relative_instruction(&mut bytes, 0x1020, 0x25, 0x2340);
    bytes
}

fn read_only_pointer_call_fixture() -> Vec<u8> {
    let mut bytes = rtti_fixture();
    bytes[rtti_file_offset(0x2100)..rtti_file_offset(0x2300)].fill(0);
    bytes[rtti_file_offset(0x1000)..rtti_file_offset(0x1010)].fill(0x90);
    put_rip_relative_instruction(&mut bytes, 0x1000, 0x15, 0x2301);
    put_rex_w_rip_relative_instruction(&mut bytes, 0x1006, 0x15, 0x2311);
    bytes[rtti_file_offset(0x100d)] = 0xc3;
    put_rtti_rva_u64(&mut bytes, 0x2301, RTTI_IMAGE_BASE + 0x1020);
    put_rtti_rva_u64(&mut bytes, 0x2311, RTTI_IMAGE_BASE + 0x1020);
    bytes
}

fn single_pointer_call_fixture(slot_rva: u32, target_va: u64) -> Vec<u8> {
    let mut bytes = rtti_fixture();
    bytes[rtti_file_offset(0x2100)..rtti_file_offset(0x2300)].fill(0);
    bytes[rtti_file_offset(0x1000)..rtti_file_offset(0x1010)].fill(0x90);
    put_rip_relative_instruction(&mut bytes, 0x1000, 0x15, slot_rva);
    bytes[rtti_file_offset(0x1006)] = 0xc3;
    put_rtti_rva_u64(&mut bytes, slot_rva, target_va);
    bytes
}

fn prefixed_pointer_call_fixture(prefix: u8, slot_rva: u32, target_va: u64) -> Vec<u8> {
    let mut bytes = rtti_fixture();
    bytes[rtti_file_offset(0x2100)..rtti_file_offset(0x2300)].fill(0);
    bytes[rtti_file_offset(0x1000)..rtti_file_offset(0x1010)].fill(0x90);

    let call_rva = 0x1000_u32;
    let call_end_rva = call_rva.checked_add(7).expect("fixture call end");
    let displacement = i64::from(slot_rva) - i64::from(call_end_rva);
    let displacement = i32::try_from(displacement).expect("fixture RIP displacement");
    let offset = rtti_file_offset(call_rva);
    bytes[offset..offset + 3].copy_from_slice(&[prefix, 0xff, 0x15]);
    bytes[offset + 3..offset + 7].copy_from_slice(&displacement.to_le_bytes());
    bytes[rtti_file_offset(call_end_rva)] = 0xc3;
    put_rtti_rva_u64(&mut bytes, slot_rva, target_va);
    bytes
}

fn read_only_pointer_thunk_fixture() -> Vec<u8> {
    let mut bytes = rtti_fixture();
    bytes[rtti_file_offset(0x2100)..rtti_file_offset(0x2300)].fill(0);
    bytes[rtti_file_offset(0x1000)..rtti_file_offset(0x1010)].fill(0x90);
    bytes[rtti_file_offset(0x1020)..rtti_file_offset(0x1030)].fill(0x90);
    put_rip_relative_instruction(&mut bytes, 0x1000, 0x25, 0x2301);
    put_rex_w_rip_relative_instruction(&mut bytes, 0x1020, 0x25, 0x2311);
    bytes[rtti_file_offset(0x1040)] = 0xc3;
    put_rtti_rva_u64(&mut bytes, 0x2301, RTTI_IMAGE_BASE + 0x1040);
    put_rtti_rva_u64(&mut bytes, 0x2311, RTTI_IMAGE_BASE + 0x1040);
    bytes
}

fn mixed_transitive_pointer_thunk_chain_fixture() -> Vec<u8> {
    let mut bytes = rtti_fixture();
    bytes[rtti_file_offset(0x1000)..rtti_file_offset(0x1010)].fill(0x90);

    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x1000, 0xe8, 0x1040);
    bytes[rtti_file_offset(0x1005)] = 0xc3;
    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x1040, 0xe9, 0x1060);
    put_rip_relative_instruction(&mut bytes, 0x1060, 0x25, 0x2301);
    bytes[rtti_file_offset(0x1080)] = 0xc3;
    put_rtti_rva_u64(&mut bytes, 0x2301, RTTI_IMAGE_BASE + 0x1080);
    bytes
}

fn single_pointer_thunk_fixture(slot_rva: u32, target_va: u64) -> Vec<u8> {
    let mut bytes = rtti_fixture();
    bytes[rtti_file_offset(0x2100)..rtti_file_offset(0x2300)].fill(0);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1040);
    bytes[rtti_file_offset(0x1040)..rtti_file_offset(0x1050)].fill(0x90);
    put_rip_relative_instruction(&mut bytes, 0x1040, 0x25, slot_rva);
    bytes[rtti_file_offset(0x1060)] = 0xc3;
    put_rtti_rva_u64(&mut bytes, slot_rva, target_va);
    bytes
}

fn prefixed_pointer_thunk_fixture(prefix: u8, slot_rva: u32, target_va: u64) -> Vec<u8> {
    let mut bytes = rtti_fixture();
    bytes[rtti_file_offset(0x2100)..rtti_file_offset(0x2300)].fill(0);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1040);
    bytes[rtti_file_offset(0x1040)..rtti_file_offset(0x1050)].fill(0x90);

    let thunk_rva = 0x1040_u32;
    let thunk_end_rva = thunk_rva.checked_add(7).expect("fixture thunk end");
    let displacement = i64::from(slot_rva) - i64::from(thunk_end_rva);
    let displacement = i32::try_from(displacement).expect("fixture RIP displacement");
    let offset = rtti_file_offset(thunk_rva);
    bytes[offset..offset + 3].copy_from_slice(&[prefix, 0xff, 0x25]);
    bytes[offset + 3..offset + 7].copy_from_slice(&displacement.to_le_bytes());
    bytes[rtti_file_offset(0x1060)] = 0xc3;
    put_rtti_rva_u64(&mut bytes, slot_rva, target_va);
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

fn string_and_data_reference_fixture() -> Vec<u8> {
    let mut bytes = rtti_fixture();
    put_lea_rip_relative_at_rtti_rva(&mut bytes, 0x1000, 0x2300);
    put_lea_rip_relative_at_rtti_rva(&mut bytes, 0x1007, 0x2320);
    bytes[rtti_file_offset(0x100e)] = 0xc3;
    put_c_string(&mut bytes, rtti_file_offset(0x2300), "Recovered ASCII");

    let utf16 = "Recovered 世界".encode_utf16().collect::<Vec<_>>();
    let mut offset = rtti_file_offset(0x2320);
    for unit in utf16 {
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        offset += 2;
    }
    bytes[offset..offset + 2].fill(0);
    bytes
}

/// One runtime-function range containing reachable and deliberately unreachable
/// x64 blocks. The layout exercises work-list traversal without relying on an
/// assembler or a checked-in binary fixture.
fn cfg_recovery_fixture() -> Vec<u8> {
    let mut bytes = rtti_fixture();

    // Replace the two small runtime functions with one range. Keep the second
    // table entry on disk but outside the declared directory so it cannot seed
    // traversal independently.
    set_directory(&mut bytes, 3, 0x2000, 12);
    put_rtti_rva_u32(&mut bytes, 0x2000, 0x1000);
    put_rtti_rva_u32(&mut bytes, 0x2004, 0x1080);
    put_rtti_rva_u32(&mut bytes, 0x2008, 0x2080);
    bytes[rtti_file_offset(0x1000)..=rtti_file_offset(0x11ff)].fill(0x90);

    // Jump over an invalid instruction pair, then recover a real call and data
    // reference from the reachable target block.
    put_rel8_instruction(&mut bytes, 0x1000, 0xeb, 0x1004);
    bytes[rtti_file_offset(0x1002)..rtti_file_offset(0x1004)].copy_from_slice(&[0xf0, 0x90]);
    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x1004, 0xe8, 0x1100);
    put_lea_rip_relative_at_rtti_rva(&mut bytes, 0x1009, 0x2300);
    put_rel8_instruction(&mut bytes, 0x1010, 0xeb, 0x1040);

    // Both arms are reachable. They converge on one call, then a conditional
    // backedge revisits the branch block without creating duplicate records.
    put_rel8_instruction(&mut bytes, 0x1040, 0x75, 0x1050);
    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x1042, 0xe8, 0x1120);
    put_rel8_instruction(&mut bytes, 0x1047, 0xeb, 0x1060);
    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x1050, 0xe8, 0x1140);
    put_rel8_instruction(&mut bytes, 0x1055, 0xeb, 0x1060);
    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x1060, 0xe8, 0x1160);
    put_rel8_instruction(&mut bytes, 0x1065, 0x75, 0x1040);

    // The taken target is backed executable code but outside this runtime
    // function. Its valid fallthrough reaches a RET, and valid-looking bytes
    // immediately after that terminator must not be decoded.
    put_rel32_conditional_at_rtti_rva(&mut bytes, 0x1067, 0x85, 0x1180);
    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x106d, 0xe8, 0x1170);
    bytes[rtti_file_offset(0x1072)] = 0xc3;
    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x1073, 0xe8, 0x11a0);
    put_lea_rip_relative_at_rtti_rva(&mut bytes, 0x1078, 0x2320);
    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x1180, 0xe8, 0x11c0);
    put_lea_rip_relative_at_rtti_rva(&mut bytes, 0x1185, 0x2340);

    for rva in [0x1100, 0x1120, 0x1140, 0x1160, 0x1170, 0x11a0, 0x11c0] {
        bytes[rtti_file_offset(rva)] = 0xc3;
    }
    put_c_string(&mut bytes, rtti_file_offset(0x2300), "reachable CFG data");
    put_c_string(&mut bytes, rtti_file_offset(0x2320), "post RET fake data");
    put_c_string(
        &mut bytes,
        rtti_file_offset(0x2340),
        "out of range fake data",
    );
    bytes
}

fn cfg_interior_overlap_fixture() -> Vec<u8> {
    let mut bytes = rtti_fixture();
    set_directory(&mut bytes, 3, 0x2000, 12);
    put_rtti_rva_u32(&mut bytes, 0x2000, 0x1000);
    put_rtti_rva_u32(&mut bytes, 0x2004, 0x1040);
    put_rtti_rva_u32(&mut bytes, 0x2008, 0x2080);
    bytes[rtti_file_offset(0x1000)..=rtti_file_offset(0x11ff)].fill(0x90);

    // The taken target, 0x1004, is inside the fallthrough MOV's immediate.
    // Its bytes deliberately spell a fake E8 so decoding the overlapping target
    // would invent a second direct call.
    put_rel8_instruction(&mut bytes, 0x1000, 0x75, 0x1004);
    bytes[rtti_file_offset(0x1002)..rtti_file_offset(0x1004)].copy_from_slice(&[0x48, 0xb8]);
    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x1004, 0xe8, 0x1140);
    bytes[rtti_file_offset(0x1009)..rtti_file_offset(0x100c)].fill(0);

    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x100c, 0xe8, 0x1120);
    put_lea_rip_relative_at_rtti_rva(&mut bytes, 0x1011, 0x2300);
    bytes[rtti_file_offset(0x1018)] = 0xc3;
    bytes[rtti_file_offset(0x1120)] = 0xc3;
    bytes[rtti_file_offset(0x1140)] = 0xc3;
    put_c_string(
        &mut bytes,
        rtti_file_offset(0x2300),
        "canonical fallthrough data",
    );
    bytes
}

fn fred_return_fixture(prefix: u8) -> Vec<u8> {
    let mut bytes = rtti_fixture();
    bytes[rtti_file_offset(0x1000)..rtti_file_offset(0x1010)].fill(0x90);
    bytes[rtti_file_offset(0x1000)..rtti_file_offset(0x1004)]
        .copy_from_slice(&[prefix, 0x0f, 0x01, 0xca]);
    put_rel32_instruction_at_rtti_rva(&mut bytes, 0x1004, 0xe8, 0x1100);
    bytes[rtti_file_offset(0x1009)] = 0xc3;
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
    assert_eq!(analysis.directories.load_config, None);
    assert_eq!(analysis.load_config_size, None);
    assert!(analysis.load_config_security_anchors.is_empty());
    assert!(analysis.load_config_xfg_anchors.is_empty());
    assert!(analysis.load_config_guard_memcpy_anchor.is_empty());
    assert_eq!(analysis.guard_flags, None);
    assert_eq!(analysis.guard_cf_function_table_rva, None);
    assert!(analysis.guard_cf_functions.is_empty());
    assert_eq!(analysis.guard_address_taken_iat_entry_table_rva, None);
    assert!(analysis.guard_address_taken_iat_entries.is_empty());
    assert_eq!(analysis.guard_long_jump_target_table_rva, None);
    assert!(analysis.guard_long_jump_targets.is_empty());
    assert_eq!(analysis.guard_eh_continuation_table_rva, None);
    assert!(analysis.guard_eh_continuation_targets.is_empty());
    assert_eq!(analysis.symbol_graph.binaries().len(), 1);
    assert_eq!(analysis.symbol_graph.claims().len(), 5);
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
fn rejects_noncanonical_section_order_while_parsing_exact_bytes() {
    let mut reversed_rvas = rtti_fixture();
    put_u32(&mut reversed_rvas, SECTION_OFFSET + 12, RTTI_RDATA_RVA);
    put_u32(&mut reversed_rvas, SECTION_OFFSET + 40 + 12, RTTI_TEXT_RVA);
    assert!(matches!(
        analyze_pe(&reversed_rvas),
        Err(AnalysisError::InvalidField {
            field: "section table order",
            ..
        })
    ));

    let mut reversed_raw_data = rtti_fixture();
    put_u32(&mut reversed_raw_data, SECTION_OFFSET + 20, 0x600);
    put_u32(&mut reversed_raw_data, SECTION_OFFSET + 40 + 20, 0x200);
    assert!(matches!(
        analyze_pe(&reversed_raw_data),
        Err(AnalysisError::InvalidField {
            field: "section raw-data order",
            ..
        })
    ));
}

#[test]
fn validated_deserialization_rejects_noncanonical_section_order() {
    let analysis = analyze_pe(&rtti_fixture()).expect("valid ordered RTTI fixture");
    let original = serde_json::to_value(analysis).expect("serialize ordered analysis");

    let mut reversed_rvas = original.clone();
    reversed_rvas["sections"][0]["virtual_address"] = serde_json::json!(RTTI_RDATA_RVA);
    reversed_rvas["sections"][1]["virtual_address"] = serde_json::json!(RTTI_TEXT_RVA);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(reversed_rvas)
        .expect_err("persisted section headers must remain in RVA order");
    assert!(error.to_string().contains("section table order"));

    let mut reversed_raw_data = original;
    reversed_raw_data["sections"][0]["raw_data_offset"] = serde_json::json!(0x600);
    reversed_raw_data["sections"][1]["raw_data_offset"] = serde_json::json!(0x200);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(reversed_raw_data)
        .expect_err("persisted section data must remain in RVA-corresponding file order");
    assert!(error.to_string().contains("section raw-data order"));
}

#[test]
fn parses_modern_delay_imports_alongside_normal_imports() {
    let analysis = analyze_pe(&delay_import_fixture()).expect("valid modern delay imports");

    assert_eq!(analysis.imports.len(), 1);
    assert_eq!(analysis.imports[0].name, "KERNEL32.dll");
    assert_eq!(
        analysis.directories.delay_imports,
        Some(resymbol_analysis::DataDirectory {
            rva: DELAY_IMPORT_DIRECTORY_RVA,
            size: 64,
        })
    );
    assert_eq!(analysis.delay_imports.len(), 1);
    let library = &analysis.delay_imports[0];
    assert_eq!(library.name, "DELAYED.dll");
    assert_eq!(library.descriptor_rva, DELAY_IMPORT_DIRECTORY_RVA);
    assert_eq!(library.attributes, 1);
    assert_eq!(library.name_rva, DELAY_IMPORT_NAME_RVA);
    assert_eq!(library.module_handle_rva, DELAY_IMPORT_MODULE_HANDLE_RVA);
    assert_eq!(library.iat_rva, DELAY_IMPORT_IAT_RVA);
    assert_eq!(library.int_rva, DELAY_IMPORT_INT_RVA);
    assert_eq!(library.bound_iat_rva, None);
    assert_eq!(library.unload_iat_rva, None);
    assert_eq!(library.timestamp, 0x2222_3333);
    assert_eq!(library.entries.len(), 2);
    assert_eq!(library.entries[0].lookup_rva, DELAY_IMPORT_INT_RVA);
    assert_eq!(library.entries[0].iat_rva, DELAY_IMPORT_IAT_RVA);
    assert_eq!(
        library.entries[0].target,
        ImportTarget::Name {
            hint: 13,
            name: "DelayedEntry".to_owned(),
        }
    );
    assert_eq!(library.entries[1].lookup_rva, DELAY_IMPORT_INT_RVA + 8);
    assert_eq!(library.entries[1].iat_rva, DELAY_IMPORT_IAT_RVA + 8);
    assert_eq!(
        library.entries[1].target,
        ImportTarget::Ordinal { ordinal: 77 }
    );
}

#[test]
fn accepts_delay_import_module_handle_storage_in_a_zero_filled_virtual_tail() {
    const VIRTUAL_MODULE_HANDLE_RVA: u32 = 0x1600;

    let mut bytes = delay_import_fixture();
    put_u32(&mut bytes, SECTION_OFFSET + 8, 0x608);
    put_u32(
        &mut bytes,
        file_offset(DELAY_IMPORT_DIRECTORY_RVA) + 8,
        VIRTUAL_MODULE_HANDLE_RVA,
    );

    let analysis = analyze_pe(&bytes)
        .expect("an eight-byte HMOD range wholly inside a mapped virtual tail is valid");
    assert_eq!(
        analysis.delay_imports[0].module_handle_rva,
        VIRTUAL_MODULE_HANDLE_RVA
    );
    let section = &analysis.sections[0];
    let raw_end_rva = section
        .virtual_address
        .checked_add(section.raw_data_size)
        .expect("fixture raw end RVA");
    let virtual_end_rva = section
        .virtual_address
        .checked_add(section.virtual_size)
        .expect("fixture virtual end RVA");
    assert_eq!(raw_end_rva, VIRTUAL_MODULE_HANDLE_RVA);
    assert_eq!(virtual_end_rva, VIRTUAL_MODULE_HANDLE_RVA + 8);

    let encoded = serde_json::to_value(&analysis).expect("serialize virtual-tail HMOD analysis");
    assert_eq!(
        serde_json::from_value::<resymbol_analysis::PeAnalysis>(encoded)
            .expect("validated deserialization accepts the mapped virtual-tail HMOD range"),
        analysis
    );
}

#[test]
fn rejects_delay_import_module_handle_ranges_crossing_or_outside_the_section_virtual_span() {
    const VIRTUAL_MODULE_HANDLE_RVA: u32 = 0x1600;

    for (label, virtual_size) in [
        ("crosses the virtual end", 0x607_u32),
        ("starts at the virtual end", 0x600),
    ] {
        let mut bytes = delay_import_fixture();
        put_u32(&mut bytes, SECTION_OFFSET + 8, virtual_size);
        put_u32(
            &mut bytes,
            file_offset(DELAY_IMPORT_DIRECTORY_RVA) + 8,
            VIRTUAL_MODULE_HANDLE_RVA,
        );

        let error = analyze_pe(&bytes)
            .expect_err("the complete eight-byte HMOD range must stay in one mapped section");
        assert!(
            error.to_string().contains("module-handle storage"),
            "{label}: {error}"
        );
    }
}

#[test]
fn rejects_nonzero_delay_descriptor_after_the_null_terminator() {
    let mut bytes = delay_import_fixture();
    set_directory(&mut bytes, 13, DELAY_IMPORT_DIRECTORY_RVA, 96);

    let error = analyze_pe(&bytes)
        .expect_err("descriptors after the first all-zero delay descriptor are forbidden");
    assert!(
        matches!(
            &error,
            AnalysisError::InvalidField {
                field: "delay-import directory",
                reason,
            } if reason.contains("nonzero after the null terminator")
        ),
        "{error}"
    );
}

#[test]
fn rejects_legacy_or_unknown_delay_attributes_and_zero_required_rvas() {
    for attributes in [0_u32, 2, 3] {
        let mut bytes = delay_import_fixture();
        put_u32(
            &mut bytes,
            file_offset(DELAY_IMPORT_DIRECTORY_RVA),
            attributes,
        );
        let error =
            analyze_pe(&bytes).expect_err("only the exact modern dlattrRva value is supported");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: "delay-import attributes",
                    ..
                }
            ),
            "attributes {attributes:#x}: {error}"
        );
    }

    for (field, descriptor_offset) in [
        ("DLL name", 4_usize),
        ("module handle", 8),
        ("IAT", 12),
        ("INT", 16),
    ] {
        let mut bytes = delay_import_fixture();
        put_u32(
            &mut bytes,
            file_offset(DELAY_IMPORT_DIRECTORY_RVA) + descriptor_offset,
            0,
        );
        let error = analyze_pe(&bytes).expect_err("required descriptor RVAs must be nonzero");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: "delay-import descriptor",
                    ..
                }
            ),
            "zero {field} RVA: {error}"
        );
    }
}

#[test]
fn rejects_reserved_bits_in_pe32_plus_named_import_thunks() {
    for (name, mut bytes, thunk_rva) in [
        ("conventional", fixture(), 0x1240),
        ("delay", delay_import_fixture(), DELAY_IMPORT_INT_RVA),
    ] {
        put_u64(&mut bytes, file_offset(thunk_rva), (1_u64 << 31) | 0x1290);
        let error = analyze_pe(&bytes).expect_err("PE32+ named-thunk bit 31 is reserved");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: "name import thunk",
                    reason,
                } if reason.contains("reserved bits")
            ),
            "{name} import: {error}"
        );
    }
}

#[test]
fn rejects_malformed_or_unbacked_delay_import_directories() {
    let mut misaligned = delay_import_fixture();
    set_directory(&mut misaligned, 13, DELAY_IMPORT_DIRECTORY_RVA, 63);
    assert!(matches!(
        analyze_pe(&misaligned),
        Err(AnalysisError::InvalidField {
            field: "delay-import directory size",
            ..
        })
    ));

    let mut unbacked = delay_import_fixture();
    set_directory(&mut unbacked, 13, 0x15f0, 64);
    assert!(matches!(
        analyze_pe(&unbacked),
        Err(AnalysisError::UnmappedRva {
            context: "delay-import directory",
            rva: 0x15f0,
            size: 64,
        })
    ));

    let mut missing_terminator = delay_import_fixture();
    set_directory(&mut missing_terminator, 13, DELAY_IMPORT_DIRECTORY_RVA, 32);
    assert!(matches!(
        analyze_pe(&missing_terminator),
        Err(AnalysisError::MissingTerminator {
            context: "delay-import directory",
        })
    ));

    analyze_pe(&delay_import_fixture_with_zero_descriptor_padding())
        .expect("multiple all-zero descriptors are valid declared tail padding");
    let mut nonzero_after_terminator = delay_import_fixture_with_zero_descriptor_padding();
    put_u32(
        &mut nonzero_after_terminator,
        file_offset(DELAY_IMPORT_DIRECTORY_RVA + 64),
        1,
    );
    let error = analyze_pe(&nonzero_after_terminator)
        .expect_err("declared delay-import tail padding must remain all zero");
    assert!(matches!(
        &error,
        AnalysisError::InvalidField {
            field: "delay-import directory",
            reason,
        } if reason.contains("nonzero after the null terminator")
    ));

    let mut short_optional_header = delay_import_fixture();
    put_u16(&mut short_optional_header, COFF_OFFSET + 16, 223);
    put_u32(&mut short_optional_header, OPTIONAL_OFFSET + 108, 14);
    assert!(matches!(
        analyze_pe(&short_optional_header),
        Err(AnalysisError::OptionalHeaderTooSmall {
            actual: 223,
            minimum: 224,
        })
    ));
}

#[test]
fn rejects_overlapping_delay_import_tables() {
    let mut overlapping_int_and_iat = delay_import_fixture();
    put_u32(
        &mut overlapping_int_and_iat,
        file_offset(DELAY_IMPORT_DIRECTORY_RVA) + 12,
        DELAY_IMPORT_INT_RVA,
    );
    let error = analyze_pe(&overlapping_int_and_iat)
        .expect_err("the delay INT and IAT must occupy distinct ranges");
    assert!(
        matches!(
            &error,
            AnalysisError::InvalidField {
                field: "delay-import tables",
                reason,
            } if reason.contains("delay-import INT overlaps delay-import IAT")
        ),
        "{error}"
    );

    let mut overlapping_bound_and_unload = delay_import_fixture_with_auxiliary_tables();
    put_u32(
        &mut overlapping_bound_and_unload,
        file_offset(DELAY_IMPORT_DIRECTORY_RVA) + 20,
        DELAY_IMPORT_UNLOAD_IAT_RVA,
    );
    let error = analyze_pe(&overlapping_bound_and_unload)
        .expect_err("the optional bound and unload tables must occupy distinct ranges");
    assert!(
        matches!(
            &error,
            AnalysisError::InvalidField {
                field: "delay-import tables",
                reason,
            } if reason.contains("bound delay-import table overlaps unload delay-import table")
        ),
        "{error}"
    );
}

#[test]
fn rejects_duplicate_iat_slots_across_normal_and_delay_imports() {
    const ORDINARY_IMPORT_IAT_RVA: u32 = 0x1260;

    let mut bytes = delay_import_fixture();
    put_u32(
        &mut bytes,
        file_offset(DELAY_IMPORT_DIRECTORY_RVA) + 12,
        ORDINARY_IMPORT_IAT_RVA,
    );
    put_u64(
        &mut bytes,
        file_offset(ORDINARY_IMPORT_IAT_RVA),
        IMAGE_BASE + 0x1040,
    );
    put_u64(
        &mut bytes,
        file_offset(ORDINARY_IMPORT_IAT_RVA + 8),
        IMAGE_BASE + 0x1080,
    );
    put_u64(&mut bytes, file_offset(ORDINARY_IMPORT_IAT_RVA + 16), 0);

    let error =
        analyze_pe(&bytes).expect_err("ordinary and delay imports cannot claim the same IAT slot");
    assert!(
        matches!(
            &error,
            AnalysisError::InvalidField {
                field: "import IAT slot",
                reason,
            } if reason.contains("RVA 0x1260")
                && reason.contains("more than one import entry")
        ),
        "{error}"
    );
}

#[test]
fn requires_delay_int_and_iat_to_terminate_at_the_same_index() {
    let mut early_int_terminator = delay_import_fixture();
    put_u64(
        &mut early_int_terminator,
        file_offset(DELAY_IMPORT_INT_RVA + 8),
        0,
    );
    let error = analyze_pe(&early_int_terminator)
        .expect_err("a nonzero IAT entry cannot outlive its matching INT entry");
    assert!(error.to_string().contains("delay-import IAT"));

    let mut early_iat_terminator = delay_import_fixture();
    put_u64(
        &mut early_iat_terminator,
        file_offset(DELAY_IMPORT_IAT_RVA + 8),
        0,
    );
    let error = analyze_pe(&early_iat_terminator)
        .expect_err("a nonzero INT entry cannot outlive its matching IAT entry");
    assert!(error.to_string().contains("delay-import IAT"));
}

#[test]
fn validates_optional_bound_and_unload_delay_iat_tables() {
    let analysis = analyze_pe(&delay_import_fixture_with_auxiliary_tables())
        .expect("fully backed BIAT and exact UIAT copy");
    assert_eq!(analysis.delay_imports[0].bound_iat_rva, Some(0x14c0));
    assert_eq!(analysis.delay_imports[0].unload_iat_rva, Some(0x14e0));

    for (name, descriptor_offset) in [("BIAT", 20_usize), ("UIAT", 24)] {
        let mut bytes = delay_import_fixture_with_auxiliary_tables();
        put_u32(
            &mut bytes,
            file_offset(DELAY_IMPORT_DIRECTORY_RVA) + descriptor_offset,
            0x15f0,
        );
        let error = analyze_pe(&bytes).expect_err("an auxiliary table must be fully backed");
        assert!(
            matches!(&error, AnalysisError::UnmappedRva { rva: 0x15f0, .. }),
            "unbacked {name}: {error}"
        );
    }

    for (name, table_rva) in [
        ("BIAT", DELAY_IMPORT_BOUND_IAT_RVA),
        ("UIAT", DELAY_IMPORT_UNLOAD_IAT_RVA),
    ] {
        let mut bytes = delay_import_fixture_with_auxiliary_tables();
        put_u64(&mut bytes, file_offset(table_rva + 16), IMAGE_BASE + 0x10c0);
        let error = analyze_pe(&bytes)
            .expect_err("an auxiliary table must terminate at the matching entry count");
        assert!(
            error.to_string().contains("delay-import table"),
            "nonterminated {name}: {error}"
        );
    }

    let mut stale_unload_copy = delay_import_fixture_with_auxiliary_tables();
    put_u64(
        &mut stale_unload_copy,
        file_offset(DELAY_IMPORT_UNLOAD_IAT_RVA),
        IMAGE_BASE + 0x10e0,
    );
    let error = analyze_pe(&stale_unload_copy)
        .expect_err("the UIAT must be an exact copy of the original delay IAT");
    assert!(error.to_string().contains("unload delay-import table"));

    for (name, descriptor_offset, table_rva) in [
        ("BIAT aliases IAT", 20_usize, DELAY_IMPORT_IAT_RVA),
        ("BIAT partially overlaps IAT", 20, DELAY_IMPORT_IAT_RVA + 8),
        ("UIAT aliases IAT", 24, DELAY_IMPORT_IAT_RVA),
    ] {
        let mut bytes = delay_import_fixture();
        put_u32(
            &mut bytes,
            file_offset(DELAY_IMPORT_DIRECTORY_RVA) + descriptor_offset,
            table_rva,
        );
        let error = analyze_pe(&bytes).expect_err("delay-import tables must be pairwise disjoint");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: "delay-import tables",
                    ..
                }
            ),
            "{name}: {error}"
        );
    }
}

#[test]
fn shares_import_library_symbol_and_name_budgets_across_both_directories() {
    for (name, bytes, expected_kind, expected_count, expected_limit) in [
        (
            "library",
            combined_import_library_budget_fixture(),
            "import library",
            4_097,
            4_096,
        ),
        (
            "symbol",
            combined_import_symbol_budget_fixture(),
            "import symbol",
            65_537,
            65_536,
        ),
        (
            "name byte",
            combined_import_name_budget_fixture(),
            "import-name byte",
            16_777_217,
            16_777_216,
        ),
    ] {
        let error = analyze_pe(&bytes).expect_err("the aggregate import budget must be enforced");
        assert!(
            matches!(
                &error,
                AnalysisError::LimitExceeded { kind, count, limit }
                    if *kind == expected_kind
                        && *count == expected_count
                        && *limit == expected_limit
            ),
            "shared {name} budget: {error}"
        );
    }
}

#[test]
fn classifies_delay_iat_calls_and_thunks_without_data_reference_duplicates() {
    let analysis = analyze_pe(&delay_import_code_recovery_fixture())
        .expect("delay IAT slots participate in control-flow recovery");

    assert!(analysis.direct_calls.contains(&PeDirectCall {
        caller_rva: 0x1000,
        call_site_rva: 0x1000,
        instruction_size: 6,
        target: PeControlFlowTarget::ImportIat {
            iat_rva: DELAY_IMPORT_CODE_IAT_RVA,
        },
    }));
    assert!(analysis.thunks.contains(&PeThunk {
        rva: 0x1040,
        instruction_size: 6,
        target: PeControlFlowTarget::ImportIat {
            iat_rva: DELAY_IMPORT_CODE_IAT_RVA + 8,
        },
    }));
    assert!(analysis.data_references.iter().all(|reference| {
        !matches!(reference.instruction_rva, 0x1000 | 0x1040)
            && reference.target_rva != DELAY_IMPORT_CODE_IAT_RVA
            && reference.target_rva != DELAY_IMPORT_CODE_IAT_RVA + 8
    }));
}

#[test]
fn validated_deserialization_rejects_tampered_delay_import_state() {
    let analysis =
        analyze_pe(&delay_import_code_recovery_fixture()).expect("valid delay-import analysis");
    let original = serde_json::to_value(analysis).expect("serialize delay-import analysis");

    let mut missing_directory = original.clone();
    missing_directory["directories"]["delay_imports"] = serde_json::Value::Null;
    serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_directory)
        .expect_err("delay-import records require their source directory");

    let mut noncanonical_descriptor = original.clone();
    noncanonical_descriptor["delay_imports"][0]["descriptor_rva"] = serde_json::json!(0x1420);
    serde_json::from_value::<resymbol_analysis::PeAnalysis>(noncanonical_descriptor)
        .expect_err("delay-import descriptors remain contiguous from the directory start");

    let mut noncanonical_thunk = original.clone();
    noncanonical_thunk["delay_imports"][0]["entries"][1]["lookup_rva"] =
        serde_json::json!(DELAY_IMPORT_INT_RVA + 16);
    serde_json::from_value::<resymbol_analysis::PeAnalysis>(noncanonical_thunk)
        .expect_err("delay-import thunk source order is validated");

    let mut overlapping_table = original.clone();
    overlapping_table["delay_imports"][0]["bound_iat_rva"] =
        serde_json::json!(DELAY_IMPORT_CODE_IAT_RVA);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(overlapping_table)
        .expect_err("deserialized delay-import tables must remain pairwise disjoint");
    assert!(error.to_string().contains("delay-import tables"));

    let mut unknown_iat = original.clone();
    unknown_iat["direct_calls"][0]["target"]["iat_rva"] =
        serde_json::json!(DELAY_IMPORT_CODE_IAT_RVA + 24);
    serde_json::from_value::<resymbol_analysis::PeAnalysis>(unknown_iat)
        .expect_err("persisted ImportIat targets must name exact parsed delay-IAT slots");

    let auxiliary_analysis = analyze_pe(&delay_import_fixture_with_auxiliary_tables())
        .expect("valid auxiliary delay-import tables");
    let mut overlapping_auxiliary =
        serde_json::to_value(auxiliary_analysis).expect("serialize auxiliary delay-import state");
    overlapping_auxiliary["delay_imports"][0]["bound_iat_rva"] =
        serde_json::json!(DELAY_IMPORT_UNLOAD_IAT_RVA);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(overlapping_auxiliary)
        .expect_err("persisted bound and unload delay tables cannot overlap");
    assert!(error.to_string().contains("delay-import tables"));

    let mut short_optional_header = original;
    short_optional_header["coff"]["optional_header_size"] = serde_json::json!(223);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(short_optional_header)
        .expect_err("data-directory entry 13 requires at least 224 optional-header bytes");
    assert!(error.to_string().contains("optional header"));
    assert!(error.to_string().contains("224"));
}

#[test]
fn recovers_guard_cf_functions_with_exact_metadata_suppression_and_graph_evidence() {
    let entries = [
        (0x1040, [0x00, 0xa0]),
        (0x1060, [0x01, 0xa1]),
        (0x1080, [0x02, 0xa2]),
        (0x10a0, [0x03, 0xa3]),
        (0x10c0, [0x80, 0xa4]),
    ];
    let analysis = analyze_pe(&guard_cf_fixture(&entries)).expect("valid sorted GuardCF table");

    assert_eq!(
        analysis.directories.load_config,
        Some(resymbol_analysis::DataDirectory {
            rva: LOAD_CONFIG_DIRECTORY_RVA,
            size: LOAD_CONFIG_GUARD_FIELDS_SIZE,
        })
    );
    assert_eq!(
        analysis.load_config_size,
        Some(LOAD_CONFIG_GUARD_FIELDS_SIZE)
    );
    assert_eq!(analysis.guard_flags, Some(0x2000_0400));
    assert_eq!(
        analysis.guard_cf_function_table_rva,
        Some(GUARD_CF_FUNCTION_TABLE_RVA)
    );
    assert_eq!(
        analysis.guard_cf_functions,
        [
            PeGuardCfFunction {
                table_index: 0,
                rva: 0x1040,
                metadata: vec![0x00, 0xa0],
            },
            PeGuardCfFunction {
                table_index: 1,
                rva: 0x1060,
                metadata: vec![0x01, 0xa1],
            },
            PeGuardCfFunction {
                table_index: 2,
                rva: 0x1080,
                metadata: vec![0x02, 0xa2],
            },
            PeGuardCfFunction {
                table_index: 3,
                rva: 0x10a0,
                metadata: vec![0x03, 0xa3],
            },
            PeGuardCfFunction {
                table_index: 4,
                rva: 0x10c0,
                metadata: vec![0x80, 0xa4],
            },
        ]
    );
    assert_eq!(
        analysis
            .guard_cf_functions
            .iter()
            .map(PeGuardCfFunction::is_fid_suppressed)
            .collect::<Vec<_>>(),
        [false, true, false, true, false]
    );
    assert_eq!(
        analysis
            .guard_cf_functions
            .iter()
            .map(PeGuardCfFunction::is_export_suppressed)
            .collect::<Vec<_>>(),
        [false, false, true, true, false]
    );

    let claims = analysis
        .symbol_graph
        .claims()
        .iter()
        .filter(|claim| claim.provenance().method == "pe-guard-cf-function")
        .collect::<Vec<_>>();
    assert_eq!(claims.len(), 5);
    assert_eq!(
        claims
            .iter()
            .map(|claim| match claim.subject() {
                SymbolSubject::Function { rva, .. } => *rva,
                other => panic!("unexpected GuardCF claim subject {other:?}"),
            })
            .collect::<Vec<_>>(),
        [0x1040, 0x1060, 0x1080, 0x10a0, 0x10c0]
    );
    let export_suppressed = claims
        .iter()
        .copied()
        .find(|claim| matches!(claim.subject(), SymbolSubject::Function { rva: 0x1080, .. }))
        .expect("export suppression alone retains a function candidate");
    assert!(matches!(
        export_suppressed.assertion(),
        SymbolAssertion::FunctionEntry
    ));
    assert_eq!(export_suppressed.confidence().get(), 0.99);
    assert_eq!(
        export_suppressed.evidence()[0].summary,
        "exact executable function target from the sorted PE GuardCF function table"
    );
    assert_eq!(
        export_suppressed.evidence()[0]
            .confidence
            .expect("exact GuardCF evidence")
            .get(),
        1.0
    );
    assert_eq!(
        export_suppressed.evidence()[0].artifacts["load_config_rva"],
        "0x1380"
    );
    assert_eq!(
        export_suppressed.evidence()[0].artifacts["function_table_rva"],
        "0x1480"
    );
    assert_eq!(
        export_suppressed.evidence()[0].artifacts["guard_flags"],
        "0x20000400"
    );
    assert_eq!(
        export_suppressed.evidence()[0].artifacts["table_index"],
        "2"
    );
    assert_eq!(
        export_suppressed.evidence()[0].artifacts["target_rva"],
        "0x1080"
    );
    assert_eq!(
        export_suppressed.evidence()[0].artifacts["metadata"],
        "02 a2"
    );
    assert_eq!(
        export_suppressed.evidence()[0].artifacts["fid_suppressed"],
        "false"
    );
    assert_eq!(
        export_suppressed.evidence()[0].artifacts["export_suppressed"],
        "true"
    );
    assert_eq!(
        export_suppressed.evidence()[0].artifacts["section_index"],
        "0"
    );
    assert_eq!(
        export_suppressed.evidence()[0].artifacts["section_name"],
        ".all"
    );
    assert!(matches!(
        &export_suppressed.provenance().producer,
        ClaimProducer::Core { component, version }
            if component == "resymbol-analysis" && !version.is_empty()
    ));
    let fid_suppressed = claims
        .iter()
        .copied()
        .find(|claim| matches!(claim.subject(), SymbolSubject::Function { rva: 0x1060, .. }))
        .expect("FID suppression retains the exact GuardCF function claim");
    assert_eq!(
        fid_suppressed.evidence()[0].artifacts["fid_suppressed"],
        "true"
    );
    assert_eq!(
        fid_suppressed.evidence()[0].artifacts["export_suppressed"],
        "false"
    );
    let both_suppressed = claims
        .iter()
        .copied()
        .find(|claim| matches!(claim.subject(), SymbolSubject::Function { rva: 0x10a0, .. }))
        .expect("combined suppression retains the exact GuardCF function claim");
    assert_eq!(
        both_suppressed.evidence()[0].artifacts["fid_suppressed"],
        "true"
    );
    assert_eq!(
        both_suppressed.evidence()[0].artifacts["export_suppressed"],
        "true"
    );
    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild GuardCF graph"),
        analysis.symbol_graph
    );

    let encoded = serde_json::to_string(&analysis).expect("serialize GuardCF analysis");
    let decoded = serde_json::from_str::<resymbol_analysis::PeAnalysis>(&encoded)
        .expect("deserialize GuardCF analysis");
    assert_eq!(decoded, analysis);
    let session = AnalysisSession::new(BinaryAnalysis::Pe(decoded), Vec::new(), Vec::new())
        .expect("GuardCF analysis remains a valid session base");
    assert_eq!(
        serde_json::from_str::<AnalysisSession>(
            &serde_json::to_string(&session).expect("serialize GuardCF session")
        )
        .expect("deserialize GuardCF session"),
        session
    );
}

#[test]
fn guard_cf_stride_extremes_preserve_exact_record_boundaries() {
    let no_metadata = analyze_pe(&guard_cf_fixture(&[(0x1040, []), (0x1080, [])]))
        .expect("zero-byte GuardCF metadata stride");
    assert_eq!(
        no_metadata.guard_flags,
        Some(IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT)
    );
    assert_eq!(
        no_metadata.guard_cf_functions,
        [
            PeGuardCfFunction {
                table_index: 0,
                rva: 0x1040,
                metadata: Vec::new(),
            },
            PeGuardCfFunction {
                table_index: 1,
                rva: 0x1080,
                metadata: Vec::new(),
            },
        ]
    );

    let one_byte = analyze_pe(&guard_cf_fixture(&[(0x1040, [0x00]), (0x1080, [0x02])]))
        .expect("one-byte GuardCF metadata stride");
    assert_eq!(one_byte.guard_flags, Some(0x1000_0400));
    assert_eq!(one_byte.guard_cf_functions[1].table_index, 1);
    assert_eq!(one_byte.guard_cf_functions[1].rva, 0x1080);
    assert_eq!(one_byte.guard_cf_functions[1].metadata, [0x02]);

    let maximum_metadata = analyze_pe(&guard_cf_fixture(&[
        (0x1040, [0x10; 15]),
        (0x1080, [0x22; 15]),
    ]))
    .expect("maximum fifteen-byte GuardCF metadata stride");
    assert_eq!(maximum_metadata.guard_flags, Some(0xf000_0400));
    assert_eq!(maximum_metadata.guard_cf_functions[1].table_index, 1);
    assert_eq!(maximum_metadata.guard_cf_functions[1].rva, 0x1080);
    assert_eq!(maximum_metadata.guard_cf_functions[1].metadata, [0x22; 15]);
}

#[test]
fn rejects_misaligned_export_suppressed_guard_cf_targets() {
    let error = analyze_pe(&guard_cf_fixture(&[(0x1041, [0x02])]))
        .expect_err("export-suppressed GFIDS entries must be sixteen-byte aligned");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "GuardCF function target",
            reason,
        } if reason.contains("export-suppressed") && reason.contains("16-byte aligned")
    ));

    let fid_suppressed = analyze_pe(&guard_cf_fixture(&[(0x1041, [0x01])]))
        .expect("FID suppression alone does not impose export-suppression alignment");
    assert!(fid_suppressed.guard_cf_functions[0].is_fid_suppressed());
    assert!(!fid_suppressed.guard_cf_functions[0].is_export_suppressed());
}

#[test]
fn rejects_unsorted_and_duplicate_guard_cf_function_rvas() {
    for (label, entries) in [
        ("descending", [(0x1080, []), (0x1040, [])]),
        ("duplicate", [(0x1040, []), (0x1040, [])]),
    ] {
        let error = analyze_pe(&guard_cf_fixture(&entries))
            .expect_err("GuardCF function RVAs must be strictly increasing and unique");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: "GuardCF function table",
                    reason,
                } if reason.contains("strictly increasing and unique")
            ),
            "{label}: {error}"
        );
    }
}

#[test]
fn recovers_load_config_security_anchors_without_inventing_control_flow_evidence() {
    let baseline = analyze_pe(&fixture()).expect("valid baseline fixture");
    let analysis = analyze_pe(&load_config_security_anchor_fixture())
        .expect("valid load-config security anchors");

    assert_eq!(
        analysis.load_config_size,
        Some(LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE)
    );
    assert_eq!(
        analysis.load_config_security_anchors,
        PeLoadConfigSecurityAnchors {
            security_cookie_rva: Some(SECURITY_COOKIE_RVA),
            guard_cf_check_function_pointer_rva: Some(GUARD_CF_CHECK_FUNCTION_POINTER_RVA),
            guard_cf_dispatch_function_pointer_rva: Some(GUARD_CF_DISPATCH_FUNCTION_POINTER_RVA),
        }
    );
    assert_eq!(analysis.guard_flags, None);
    assert_eq!(
        analysis.symbol_graph.claims().len(),
        baseline.symbol_graph.claims().len()
    );
    assert_eq!(analysis.thunks.len(), baseline.thunks.len());

    let encoded = serde_json::to_string(&analysis).expect("serialize security anchors");
    assert!(encoded.contains("\"load_config_security_anchors\""));
    let decoded: resymbol_analysis::PeAnalysis =
        serde_json::from_str(&encoded).expect("deserialize security anchors");
    assert_eq!(decoded, analysis);
}

#[test]
fn respects_each_load_config_security_anchor_size_boundary() {
    for (load_config_size, expected) in [
        (
            LOAD_CONFIG_SECURITY_COOKIE_FIELDS_SIZE - 1,
            PeLoadConfigSecurityAnchors::default(),
        ),
        (
            LOAD_CONFIG_SECURITY_COOKIE_FIELDS_SIZE,
            PeLoadConfigSecurityAnchors {
                security_cookie_rva: Some(SECURITY_COOKIE_RVA),
                ..PeLoadConfigSecurityAnchors::default()
            },
        ),
        (
            LOAD_CONFIG_GUARD_CF_CHECK_POINTER_FIELDS_SIZE - 1,
            PeLoadConfigSecurityAnchors {
                security_cookie_rva: Some(SECURITY_COOKIE_RVA),
                ..PeLoadConfigSecurityAnchors::default()
            },
        ),
        (
            LOAD_CONFIG_GUARD_CF_CHECK_POINTER_FIELDS_SIZE,
            PeLoadConfigSecurityAnchors {
                security_cookie_rva: Some(SECURITY_COOKIE_RVA),
                guard_cf_check_function_pointer_rva: Some(GUARD_CF_CHECK_FUNCTION_POINTER_RVA),
                ..PeLoadConfigSecurityAnchors::default()
            },
        ),
        (
            LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE - 1,
            PeLoadConfigSecurityAnchors {
                security_cookie_rva: Some(SECURITY_COOKIE_RVA),
                guard_cf_check_function_pointer_rva: Some(GUARD_CF_CHECK_FUNCTION_POINTER_RVA),
                ..PeLoadConfigSecurityAnchors::default()
            },
        ),
        (
            LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE,
            PeLoadConfigSecurityAnchors {
                security_cookie_rva: Some(SECURITY_COOKIE_RVA),
                guard_cf_check_function_pointer_rva: Some(GUARD_CF_CHECK_FUNCTION_POINTER_RVA),
                guard_cf_dispatch_function_pointer_rva: Some(
                    GUARD_CF_DISPATCH_FUNCTION_POINTER_RVA,
                ),
            },
        ),
    ] {
        let mut bytes = fixture();
        set_load_config_security_anchors(
            &mut bytes,
            LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE,
            load_config_size,
            IMAGE_BASE + u64::from(SECURITY_COOKIE_RVA),
            IMAGE_BASE + u64::from(GUARD_CF_CHECK_FUNCTION_POINTER_RVA),
            IMAGE_BASE + u64::from(GUARD_CF_DISPATCH_FUNCTION_POINTER_RVA),
        );
        let analysis =
            analyze_pe(&bytes).expect("bytes past the declared load-config size remain opaque");
        assert_eq!(analysis.load_config_security_anchors, expected);
        assert_eq!(analysis.guard_flags, None);
    }
}

#[test]
fn rejects_invalid_load_config_security_anchor_vas_and_layouts() {
    for (label, field, security_cookie_va, check_va, dispatch_va, expected_reason) in [
        (
            "below image base",
            "SecurityCookie",
            IMAGE_BASE - 1,
            0,
            0,
            "below preferred image base",
        ),
        (
            "outside image",
            "GuardCFDispatchFunctionPointer",
            0,
            0,
            IMAGE_BASE + 0x2000,
            "outside the declared image",
        ),
        (
            "header anchor",
            "security cookie",
            IMAGE_BASE + 0x100,
            0,
            0,
            "within one mapped section",
        ),
        (
            "crosses section end",
            "security cookie",
            IMAGE_BASE + 0x15fc,
            0,
            0,
            "within one mapped section",
        ),
        (
            "overlaps load config",
            "security cookie",
            IMAGE_BASE + u64::from(LOAD_CONFIG_DIRECTORY_RVA),
            0,
            0,
            "overlaps the declared load-config directory",
        ),
    ] {
        let mut bytes = fixture();
        set_load_config_security_anchors(
            &mut bytes,
            LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE,
            LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE,
            security_cookie_va,
            check_va,
            dispatch_va,
        );
        let error = analyze_pe(&bytes).expect_err("invalid security anchor must be rejected");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: actual_field,
                    reason,
                } if *actual_field == field && reason.contains(expected_reason)
            ),
            "{label}: {error}"
        );
    }

    let mut pairwise_overlap = fixture();
    set_load_config_security_anchors(
        &mut pairwise_overlap,
        LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE,
        IMAGE_BASE + u64::from(SECURITY_COOKIE_RVA),
        IMAGE_BASE + u64::from(SECURITY_COOKIE_RVA + 4),
        0,
    );
    let error = analyze_pe(&pairwise_overlap)
        .expect_err("security-anchor storage ranges must be pairwise disjoint");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "load-config security anchors",
            reason,
        } if reason.contains("security cookie overlaps GuardCF check-function pointer slot")
    ));

    let mut virtual_tail = fixture();
    put_u32(&mut virtual_tail, SECTION_OFFSET + 8, 0x800);
    set_load_config_security_anchors(
        &mut virtual_tail,
        LOAD_CONFIG_SECURITY_COOKIE_FIELDS_SIZE,
        LOAD_CONFIG_SECURITY_COOKIE_FIELDS_SIZE,
        IMAGE_BASE + 0x17f8,
        0,
        0,
    );
    let analysis = analyze_pe(&virtual_tail)
        .expect("an eight-byte anchor may live wholly inside a mapped zero-fill tail");
    assert_eq!(
        analysis.load_config_security_anchors.security_cookie_rva,
        Some(0x17f8)
    );
}

#[test]
fn validated_deserialization_rejects_tampered_load_config_security_anchors() {
    let analysis = analyze_pe(&load_config_security_anchor_fixture())
        .expect("valid load-config security anchors");
    let original = serde_json::to_value(analysis).expect("serialize security anchors");

    let mut legacy_absence = original.clone();
    legacy_absence
        .as_object_mut()
        .expect("analysis object")
        .remove("load_config_security_anchors");
    let decoded: resymbol_analysis::PeAnalysis = serde_json::from_value(legacy_absence)
        .expect("legacy analyses default the security-anchor object to empty");
    assert!(decoded.load_config_security_anchors.is_empty());

    for (field, shortened_size, expected_field) in [
        (
            "security_cookie_rva",
            LOAD_CONFIG_SECURITY_COOKIE_FIELDS_SIZE - 1,
            "security cookie",
        ),
        (
            "guard_cf_check_function_pointer_rva",
            LOAD_CONFIG_GUARD_CF_CHECK_POINTER_FIELDS_SIZE - 1,
            "GuardCF check-function pointer slot",
        ),
        (
            "guard_cf_dispatch_function_pointer_rva",
            LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE - 1,
            "GuardCF dispatch-function pointer slot",
        ),
    ] {
        let mut shortened = original.clone();
        shortened["load_config_size"] = serde_json::json!(shortened_size);
        for other_field in [
            "security_cookie_rva",
            "guard_cf_check_function_pointer_rva",
            "guard_cf_dispatch_function_pointer_rva",
        ] {
            if other_field != field {
                shortened["load_config_security_anchors"]
                    .as_object_mut()
                    .expect("security-anchor object")
                    .remove(other_field);
            }
        }
        let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(shortened)
            .expect_err("retained anchor requires its load-config structure prefix");
        assert!(
            error.to_string().contains(expected_field),
            "{field}: {error}"
        );
    }

    let mut missing_directory = original.clone();
    missing_directory["directories"]["load_config"] = serde_json::Value::Null;
    missing_directory["load_config_size"] = serde_json::Value::Null;
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_directory)
        .expect_err("security-anchor state cannot outlive its load-config directory");
    assert!(error.to_string().contains("load-config security anchors"));

    let mut header_anchor = original.clone();
    header_anchor["load_config_security_anchors"]["security_cookie_rva"] = serde_json::json!(0x100);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(header_anchor)
        .expect_err("persisted anchors remain mapped into one section");
    assert!(error.to_string().contains("within one mapped section"));

    let mut directory_overlap = original.clone();
    directory_overlap["load_config_security_anchors"]["security_cookie_rva"] =
        serde_json::json!(LOAD_CONFIG_DIRECTORY_RVA);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(directory_overlap)
        .expect_err("persisted anchors remain disjoint from the load-config directory");
    assert!(
        error
            .to_string()
            .contains("overlaps the declared load-config")
    );

    let mut pairwise_overlap = original.clone();
    pairwise_overlap["load_config_security_anchors"]["guard_cf_check_function_pointer_rva"] =
        serde_json::json!(SECURITY_COOKIE_RVA);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(pairwise_overlap)
        .expect_err("persisted security-anchor ranges remain pairwise disjoint");
    assert!(error.to_string().contains("security cookie overlaps"));

    let mut unknown_inner_field = original;
    unknown_inner_field["load_config_security_anchors"]["unexpected"] = serde_json::json!(1);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(unknown_inner_field)
        .expect_err("unknown fields inside the security-anchor marker are rejected");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn recovers_load_config_xfg_anchors_without_inventing_control_flow_evidence() {
    let baseline = analyze_pe(&fixture()).expect("valid baseline fixture");
    let analysis =
        analyze_pe(&load_config_xfg_anchor_fixture()).expect("valid load-config XFG anchors");

    assert_eq!(
        analysis.load_config_size,
        Some(LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE)
    );
    assert!(analysis.load_config_security_anchors.is_empty());
    assert_eq!(
        analysis.load_config_xfg_anchors,
        PeLoadConfigXfgAnchors {
            guard_xfg_check_function_pointer_rva: Some(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
            guard_xfg_dispatch_function_pointer_rva: Some(GUARD_XFG_DISPATCH_FUNCTION_POINTER_RVA,),
            guard_xfg_table_dispatch_function_pointer_rva: Some(
                GUARD_XFG_TABLE_DISPATCH_FUNCTION_POINTER_RVA,
            ),
            cast_guard_os_determined_failure_mode_rva: Some(
                CAST_GUARD_OS_DETERMINED_FAILURE_MODE_RVA,
            ),
        }
    );
    assert_eq!(analysis.guard_flags, Some(0));
    assert_eq!(
        analysis.symbol_graph.claims().len(),
        baseline.symbol_graph.claims().len()
    );
    assert_eq!(analysis.thunks.len(), baseline.thunks.len());

    let encoded = serde_json::to_string(&analysis).expect("serialize XFG anchors");
    assert!(encoded.contains("\"load_config_xfg_anchors\""));
    let decoded: resymbol_analysis::PeAnalysis =
        serde_json::from_str(&encoded).expect("deserialize XFG anchors");
    assert_eq!(decoded, analysis);
}

#[test]
fn respects_each_load_config_xfg_anchor_size_boundary() {
    for (load_config_size, expected) in [
        (
            LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_FIELDS_SIZE - 1,
            PeLoadConfigXfgAnchors::default(),
        ),
        (
            LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_FIELDS_SIZE,
            PeLoadConfigXfgAnchors {
                guard_xfg_check_function_pointer_rva: Some(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
                ..PeLoadConfigXfgAnchors::default()
            },
        ),
        (
            LOAD_CONFIG_GUARD_XFG_DISPATCH_POINTER_FIELDS_SIZE - 1,
            PeLoadConfigXfgAnchors {
                guard_xfg_check_function_pointer_rva: Some(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
                ..PeLoadConfigXfgAnchors::default()
            },
        ),
        (
            LOAD_CONFIG_GUARD_XFG_DISPATCH_POINTER_FIELDS_SIZE,
            PeLoadConfigXfgAnchors {
                guard_xfg_check_function_pointer_rva: Some(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
                guard_xfg_dispatch_function_pointer_rva: Some(
                    GUARD_XFG_DISPATCH_FUNCTION_POINTER_RVA,
                ),
                ..PeLoadConfigXfgAnchors::default()
            },
        ),
        (
            LOAD_CONFIG_GUARD_XFG_TABLE_DISPATCH_POINTER_FIELDS_SIZE - 1,
            PeLoadConfigXfgAnchors {
                guard_xfg_check_function_pointer_rva: Some(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
                guard_xfg_dispatch_function_pointer_rva: Some(
                    GUARD_XFG_DISPATCH_FUNCTION_POINTER_RVA,
                ),
                ..PeLoadConfigXfgAnchors::default()
            },
        ),
        (
            LOAD_CONFIG_GUARD_XFG_TABLE_DISPATCH_POINTER_FIELDS_SIZE,
            PeLoadConfigXfgAnchors {
                guard_xfg_check_function_pointer_rva: Some(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
                guard_xfg_dispatch_function_pointer_rva: Some(
                    GUARD_XFG_DISPATCH_FUNCTION_POINTER_RVA,
                ),
                guard_xfg_table_dispatch_function_pointer_rva: Some(
                    GUARD_XFG_TABLE_DISPATCH_FUNCTION_POINTER_RVA,
                ),
                ..PeLoadConfigXfgAnchors::default()
            },
        ),
        (
            LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE - 1,
            PeLoadConfigXfgAnchors {
                guard_xfg_check_function_pointer_rva: Some(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
                guard_xfg_dispatch_function_pointer_rva: Some(
                    GUARD_XFG_DISPATCH_FUNCTION_POINTER_RVA,
                ),
                guard_xfg_table_dispatch_function_pointer_rva: Some(
                    GUARD_XFG_TABLE_DISPATCH_FUNCTION_POINTER_RVA,
                ),
                ..PeLoadConfigXfgAnchors::default()
            },
        ),
        (
            LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE,
            PeLoadConfigXfgAnchors {
                guard_xfg_check_function_pointer_rva: Some(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
                guard_xfg_dispatch_function_pointer_rva: Some(
                    GUARD_XFG_DISPATCH_FUNCTION_POINTER_RVA,
                ),
                guard_xfg_table_dispatch_function_pointer_rva: Some(
                    GUARD_XFG_TABLE_DISPATCH_FUNCTION_POINTER_RVA,
                ),
                cast_guard_os_determined_failure_mode_rva: Some(
                    CAST_GUARD_OS_DETERMINED_FAILURE_MODE_RVA,
                ),
            },
        ),
    ] {
        let mut bytes = fixture();
        set_load_config_xfg_anchors(
            &mut bytes,
            LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE,
            load_config_size,
            IMAGE_BASE + u64::from(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
            IMAGE_BASE + u64::from(GUARD_XFG_DISPATCH_FUNCTION_POINTER_RVA),
            IMAGE_BASE + u64::from(GUARD_XFG_TABLE_DISPATCH_FUNCTION_POINTER_RVA),
            IMAGE_BASE + u64::from(CAST_GUARD_OS_DETERMINED_FAILURE_MODE_RVA),
        );
        let analysis =
            analyze_pe(&bytes).expect("bytes past the declared load-config size remain opaque");
        assert_eq!(analysis.load_config_xfg_anchors, expected);
        assert_eq!(analysis.guard_flags, Some(0));
    }
}

#[test]
fn rejects_invalid_load_config_xfg_anchor_vas_and_layouts() {
    for (label, field, check_va, dispatch_va, table_dispatch_va, cast_guard_va, reason) in [
        (
            "below image base",
            "GuardXFGCheckFunctionPointer",
            IMAGE_BASE - 1,
            0,
            0,
            0,
            "below preferred image base",
        ),
        (
            "outside image",
            "CastGuardOsDeterminedFailureMode",
            0,
            0,
            0,
            IMAGE_BASE + 0x2000,
            "outside the declared image",
        ),
        (
            "header anchor",
            "Guard XFG check-function pointer slot",
            IMAGE_BASE + 0x100,
            0,
            0,
            0,
            "within one mapped section",
        ),
        (
            "crosses section end",
            "Guard XFG check-function pointer slot",
            IMAGE_BASE + 0x15fc,
            0,
            0,
            0,
            "within one mapped section",
        ),
        (
            "overlaps load config",
            "Guard XFG check-function pointer slot",
            IMAGE_BASE + 0x14b0,
            0,
            0,
            0,
            "overlaps the declared load-config directory",
        ),
    ] {
        let mut bytes = fixture();
        set_load_config_xfg_anchors(
            &mut bytes,
            LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE,
            LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE,
            check_va,
            dispatch_va,
            table_dispatch_va,
            cast_guard_va,
        );
        let error = analyze_pe(&bytes).expect_err("invalid XFG anchor must be rejected");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: actual_field,
                    reason: actual_reason,
                } if *actual_field == field && actual_reason.contains(reason)
            ),
            "{label}: {error}"
        );
    }

    let mut pairwise_overlap = fixture();
    set_load_config_xfg_anchors(
        &mut pairwise_overlap,
        LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE,
        LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE,
        IMAGE_BASE + u64::from(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA),
        IMAGE_BASE + u64::from(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA + 4),
        0,
        0,
    );
    let error = analyze_pe(&pairwise_overlap)
        .expect_err("XFG-anchor storage ranges must be pairwise disjoint");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "load-config security anchors",
            reason,
        } if reason.contains(
            "Guard XFG check-function pointer slot overlaps Guard XFG dispatch-function pointer slot"
        )
    ));

    let mut cross_family_overlap = fixture();
    set_load_config_xfg_anchors(
        &mut cross_family_overlap,
        LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE,
        LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE,
        IMAGE_BASE + u64::from(SECURITY_COOKIE_RVA),
        0,
        0,
        0,
    );
    let load_config = file_offset(LOAD_CONFIG_DIRECTORY_RVA);
    put_u64(
        &mut cross_family_overlap,
        load_config + 88,
        IMAGE_BASE + u64::from(SECURITY_COOKIE_RVA),
    );
    let error = analyze_pe(&cross_family_overlap)
        .expect_err("schema-11 and schema-12 anchor ranges must remain disjoint");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "load-config security anchors",
            reason,
        } if reason.contains("security cookie overlaps Guard XFG check-function pointer slot")
    ));

    let mut virtual_tail = fixture();
    put_u32(&mut virtual_tail, SECTION_OFFSET + 8, 0x800);
    set_load_config_xfg_anchors(
        &mut virtual_tail,
        LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_FIELDS_SIZE,
        IMAGE_BASE + 0x17f8,
        0,
        0,
        0,
    );
    let analysis = analyze_pe(&virtual_tail)
        .expect("an eight-byte XFG anchor may live wholly inside a mapped zero-fill tail");
    assert_eq!(
        analysis
            .load_config_xfg_anchors
            .guard_xfg_check_function_pointer_rva,
        Some(0x17f8)
    );
}

#[test]
fn validated_deserialization_rejects_tampered_load_config_xfg_anchors() {
    let analysis =
        analyze_pe(&load_config_xfg_anchor_fixture()).expect("valid load-config XFG anchors");
    let original = serde_json::to_value(analysis).expect("serialize XFG anchors");

    let mut legacy_absence = original.clone();
    legacy_absence
        .as_object_mut()
        .expect("analysis object")
        .remove("load_config_xfg_anchors");
    let decoded: resymbol_analysis::PeAnalysis = serde_json::from_value(legacy_absence)
        .expect("legacy analyses default the XFG-anchor object to empty");
    assert!(decoded.load_config_xfg_anchors.is_empty());

    for (field, shortened_size, expected_field) in [
        (
            "guard_xfg_check_function_pointer_rva",
            LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_FIELDS_SIZE - 1,
            "Guard XFG check-function pointer slot",
        ),
        (
            "guard_xfg_dispatch_function_pointer_rva",
            LOAD_CONFIG_GUARD_XFG_DISPATCH_POINTER_FIELDS_SIZE - 1,
            "Guard XFG dispatch-function pointer slot",
        ),
        (
            "guard_xfg_table_dispatch_function_pointer_rva",
            LOAD_CONFIG_GUARD_XFG_TABLE_DISPATCH_POINTER_FIELDS_SIZE - 1,
            "Guard XFG table-dispatch function-pointer slot",
        ),
        (
            "cast_guard_os_determined_failure_mode_rva",
            LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE - 1,
            "CastGuard OS-determined failure-mode storage",
        ),
    ] {
        let mut shortened = original.clone();
        shortened["load_config_size"] = serde_json::json!(shortened_size);
        for other_field in [
            "guard_xfg_check_function_pointer_rva",
            "guard_xfg_dispatch_function_pointer_rva",
            "guard_xfg_table_dispatch_function_pointer_rva",
            "cast_guard_os_determined_failure_mode_rva",
        ] {
            if other_field != field {
                shortened["load_config_xfg_anchors"]
                    .as_object_mut()
                    .expect("XFG-anchor object")
                    .remove(other_field);
            }
        }
        let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(shortened)
            .expect_err("retained XFG anchor requires its load-config structure prefix");
        assert!(
            error.to_string().contains(expected_field),
            "{field}: {error}"
        );
    }

    let mut missing_directory = original.clone();
    missing_directory["directories"]["load_config"] = serde_json::Value::Null;
    missing_directory["load_config_size"] = serde_json::Value::Null;
    missing_directory["guard_flags"] = serde_json::Value::Null;
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_directory)
        .expect_err("XFG-anchor state cannot outlive its load-config directory");
    assert!(error.to_string().contains("load-config security anchors"));

    let mut header_anchor = original.clone();
    header_anchor["load_config_xfg_anchors"]["guard_xfg_check_function_pointer_rva"] =
        serde_json::json!(0x100);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(header_anchor)
        .expect_err("persisted XFG anchors remain mapped into one section");
    assert!(error.to_string().contains("within one mapped section"));

    let mut directory_overlap = original.clone();
    directory_overlap["load_config_xfg_anchors"]["guard_xfg_check_function_pointer_rva"] =
        serde_json::json!(0x14b0);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(directory_overlap)
        .expect_err("persisted XFG anchors remain disjoint from the load-config directory");
    assert!(
        error
            .to_string()
            .contains("overlaps the declared load-config")
    );

    let mut pairwise_overlap = original.clone();
    pairwise_overlap["load_config_xfg_anchors"]["guard_xfg_dispatch_function_pointer_rva"] =
        serde_json::json!(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(pairwise_overlap)
        .expect_err("persisted XFG-anchor ranges remain pairwise disjoint");
    assert!(
        error
            .to_string()
            .contains("Guard XFG check-function pointer slot overlaps")
    );

    let mut cross_family_overlap = original.clone();
    cross_family_overlap["load_config_security_anchors"]["security_cookie_rva"] =
        serde_json::json!(GUARD_XFG_CHECK_FUNCTION_POINTER_RVA);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(cross_family_overlap)
        .expect_err("persisted schema-11 and schema-12 anchor ranges remain disjoint");
    assert!(
        error
            .to_string()
            .contains("security cookie overlaps Guard XFG check-function pointer slot")
    );

    let mut unknown_inner_field = original;
    unknown_inner_field["load_config_xfg_anchors"]["unexpected"] = serde_json::json!(1);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(unknown_inner_field)
        .expect_err("unknown fields inside the XFG-anchor marker are rejected");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn recovers_guard_memcpy_pointer_slot_without_inventing_control_flow_evidence() {
    let baseline = analyze_pe(&fixture()).expect("valid baseline fixture");
    let analysis = analyze_pe(&load_config_guard_memcpy_anchor_fixture())
        .expect("valid GuardMemcpy function-pointer slot");

    assert_eq!(
        analysis.load_config_size,
        Some(LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE)
    );
    assert!(analysis.load_config_security_anchors.is_empty());
    assert!(analysis.load_config_xfg_anchors.is_empty());
    assert_eq!(
        analysis.load_config_guard_memcpy_anchor,
        PeLoadConfigGuardMemcpyAnchor {
            guard_memcpy_function_pointer_rva: Some(GUARD_MEMCPY_FUNCTION_POINTER_RVA),
        }
    );
    assert_eq!(analysis.guard_flags, Some(0));
    assert_eq!(
        analysis.symbol_graph.claims().len(),
        baseline.symbol_graph.claims().len()
    );
    assert_eq!(analysis.thunks.len(), baseline.thunks.len());

    let encoded = serde_json::to_string(&analysis).expect("serialize GuardMemcpy anchor");
    assert!(encoded.contains("\"load_config_guard_memcpy_anchor\""));
    assert!(encoded.contains("\"guard_memcpy_function_pointer_rva\""));
    let decoded: resymbol_analysis::PeAnalysis =
        serde_json::from_str(&encoded).expect("deserialize GuardMemcpy anchor");
    assert_eq!(decoded, analysis);
}

#[test]
fn respects_guard_memcpy_pointer_size_boundary_and_zero_semantics() {
    for (load_config_size, expected) in [
        (
            LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE - 1,
            PeLoadConfigGuardMemcpyAnchor::default(),
        ),
        (
            LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
            PeLoadConfigGuardMemcpyAnchor {
                guard_memcpy_function_pointer_rva: Some(GUARD_MEMCPY_FUNCTION_POINTER_RVA),
            },
        ),
    ] {
        let mut bytes = fixture();
        set_load_config_guard_memcpy_anchor(
            &mut bytes,
            LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
            load_config_size,
            IMAGE_BASE + u64::from(GUARD_MEMCPY_FUNCTION_POINTER_RVA),
        );
        let analysis =
            analyze_pe(&bytes).expect("bytes past the declared load-config size remain opaque");
        assert_eq!(analysis.load_config_guard_memcpy_anchor, expected);
        assert_eq!(analysis.guard_flags, Some(0));
    }

    let mut zero = fixture();
    set_load_config_guard_memcpy_anchor(
        &mut zero,
        LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
        0,
    );
    let analysis = analyze_pe(&zero).expect("a zero GuardMemcpy VA means no advertised slot");
    assert!(analysis.load_config_guard_memcpy_anchor.is_empty());
}

#[test]
fn rejects_invalid_guard_memcpy_pointer_vas_and_layouts() {
    for (label, pointer_va, field, reason) in [
        (
            "below image base",
            IMAGE_BASE - 1,
            "GuardMemcpyFunctionPointer",
            "below preferred image base",
        ),
        (
            "outside image",
            IMAGE_BASE + 0x2000,
            "GuardMemcpyFunctionPointer",
            "outside the declared image",
        ),
        (
            "header anchor",
            IMAGE_BASE + 0x100,
            "GuardMemcpy function-pointer slot",
            "within one mapped section",
        ),
        (
            "crosses section end",
            IMAGE_BASE + 0x15fc,
            "GuardMemcpy function-pointer slot",
            "within one mapped section",
        ),
        (
            "overlaps load config",
            IMAGE_BASE + 0x14b8,
            "GuardMemcpy function-pointer slot",
            "overlaps the declared load-config directory",
        ),
    ] {
        let mut bytes = fixture();
        set_load_config_guard_memcpy_anchor(
            &mut bytes,
            LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
            LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
            pointer_va,
        );
        let error = analyze_pe(&bytes).expect_err("invalid GuardMemcpy anchor must be rejected");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: actual_field,
                    reason: actual_reason,
                } if *actual_field == field && actual_reason.contains(reason)
            ),
            "{label}: {error}"
        );
    }

    let mut cross_family_overlap = fixture();
    set_load_config_xfg_anchors(
        &mut cross_family_overlap,
        LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
        0,
        0,
        0,
        IMAGE_BASE + u64::from(GUARD_MEMCPY_FUNCTION_POINTER_RVA),
    );
    let load_config = file_offset(LOAD_CONFIG_DIRECTORY_RVA);
    put_u64(
        &mut cross_family_overlap,
        load_config + 312,
        IMAGE_BASE + u64::from(GUARD_MEMCPY_FUNCTION_POINTER_RVA),
    );
    let error = analyze_pe(&cross_family_overlap)
        .expect_err("schema-12 and schema-13 anchor ranges must remain disjoint");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "load-config security anchors",
            reason,
        } if reason.contains(
            "CastGuard OS-determined failure-mode storage overlaps GuardMemcpy function-pointer slot"
        )
    ));

    let mut virtual_tail = fixture();
    put_u32(&mut virtual_tail, SECTION_OFFSET + 8, 0x800);
    set_load_config_guard_memcpy_anchor(
        &mut virtual_tail,
        LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE,
        IMAGE_BASE + 0x17f8,
    );
    let analysis = analyze_pe(&virtual_tail)
        .expect("an eight-byte GuardMemcpy slot may live wholly inside a mapped zero-fill tail");
    assert_eq!(
        analysis
            .load_config_guard_memcpy_anchor
            .guard_memcpy_function_pointer_rva,
        Some(0x17f8)
    );
}

#[test]
fn validated_deserialization_rejects_tampered_guard_memcpy_anchor() {
    let analysis = analyze_pe(&load_config_guard_memcpy_anchor_fixture())
        .expect("valid GuardMemcpy function-pointer slot");
    let original = serde_json::to_value(analysis).expect("serialize GuardMemcpy anchor");

    let mut legacy_absence = original.clone();
    legacy_absence
        .as_object_mut()
        .expect("analysis object")
        .remove("load_config_guard_memcpy_anchor");
    let decoded: resymbol_analysis::PeAnalysis = serde_json::from_value(legacy_absence)
        .expect("legacy analyses default the GuardMemcpy-anchor object to empty");
    assert!(decoded.load_config_guard_memcpy_anchor.is_empty());

    let mut shortened = original.clone();
    shortened["load_config_size"] =
        serde_json::json!(LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE - 1);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(shortened)
        .expect_err("a retained GuardMemcpy anchor requires its load-config structure prefix");
    assert!(
        error
            .to_string()
            .contains("GuardMemcpy function-pointer slot")
    );

    let mut missing_directory = original.clone();
    missing_directory["directories"]["load_config"] = serde_json::Value::Null;
    missing_directory["load_config_size"] = serde_json::Value::Null;
    missing_directory["guard_flags"] = serde_json::Value::Null;
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_directory)
        .expect_err("GuardMemcpy-anchor state cannot outlive its load-config directory");
    assert!(error.to_string().contains("load-config security anchors"));

    let mut header_anchor = original.clone();
    header_anchor["load_config_guard_memcpy_anchor"]["guard_memcpy_function_pointer_rva"] =
        serde_json::json!(0x100);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(header_anchor)
        .expect_err("persisted GuardMemcpy anchors remain mapped into one section");
    assert!(error.to_string().contains("within one mapped section"));

    let mut directory_overlap = original.clone();
    directory_overlap["load_config_guard_memcpy_anchor"]["guard_memcpy_function_pointer_rva"] =
        serde_json::json!(0x14b8);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(directory_overlap)
        .expect_err("persisted GuardMemcpy anchors remain disjoint from load config");
    assert!(
        error
            .to_string()
            .contains("overlaps the declared load-config")
    );

    let mut cross_family_overlap = original.clone();
    cross_family_overlap["load_config_xfg_anchors"]["cast_guard_os_determined_failure_mode_rva"] =
        serde_json::json!(GUARD_MEMCPY_FUNCTION_POINTER_RVA);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(cross_family_overlap)
        .expect_err("persisted schema-12 and schema-13 anchor ranges remain disjoint");
    assert!(
        error
            .to_string()
            .contains("CastGuard OS-determined failure-mode storage overlaps GuardMemcpy")
    );

    let mut unknown_inner_field = original;
    unknown_inner_field["load_config_guard_memcpy_anchor"]["unexpected"] = serde_json::json!(1);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(unknown_inner_field)
        .expect_err("unknown fields inside the GuardMemcpy-anchor marker are rejected");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn handles_versioned_empty_and_malformed_load_config_structures() {
    let mut short_version = fixture();
    set_guard_cf_load_config(
        &mut short_version,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_FIELDS_SIZE - 1,
        IMAGE_BASE + u64::from(GUARD_CF_FUNCTION_TABLE_RVA),
        1,
        IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
    );
    let short_version = analyze_pe(&short_version)
        .expect("a versioned load config shorter than the GuardCF prefix is retained opaquely");
    assert_eq!(
        short_version.load_config_size,
        Some(LOAD_CONFIG_GUARD_FIELDS_SIZE - 1)
    );
    assert_eq!(short_version.guard_flags, None);
    assert_eq!(short_version.guard_cf_function_table_rva, None);
    assert!(short_version.guard_cf_functions.is_empty());

    let mut empty = fixture();
    set_guard_cf_load_config(
        &mut empty,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        0,
        0,
        0xf000_0400,
    );
    let empty = analyze_pe(&empty)
        .expect("zero table and count are a valid empty inventory even with table-present set");
    assert_eq!(empty.guard_flags, Some(0xf000_0400));
    assert_eq!(empty.guard_cf_function_table_rva, None);
    assert!(empty.guard_cf_functions.is_empty());

    let mut too_short_directory = fixture();
    set_guard_cf_load_config(&mut too_short_directory, 3, 3, 0, 0, 0);
    let error = analyze_pe(&too_short_directory)
        .expect_err("the directory must back the four-byte structure-size field");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "load-config directory size",
            ..
        }
    ));

    let mut too_small_structure = fixture();
    set_guard_cf_load_config(
        &mut too_small_structure,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        3,
        0,
        0,
        0,
    );
    let error = analyze_pe(&too_small_structure)
        .expect_err("a present load-config structure declares at least its size field");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "load-config size",
            ..
        }
    ));

    let mut structure_exceeds_directory = fixture();
    set_guard_cf_load_config(
        &mut structure_exceeds_directory,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_FIELDS_SIZE + 1,
        0,
        0,
        0,
    );
    let error = analyze_pe(&structure_exceeds_directory)
        .expect_err("the internal size cannot exceed the directory range");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "load-config size",
            ..
        }
    ));
}

#[test]
fn rejects_inconsistent_overlapping_and_unbacked_guard_cf_tables() {
    for (label, table_va, count, guard_flags) in [
        (
            "count without table",
            0,
            1,
            IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
        ),
        (
            "table without count",
            IMAGE_BASE + u64::from(GUARD_CF_FUNCTION_TABLE_RVA),
            0,
            IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
        ),
        (
            "table without presence flag",
            IMAGE_BASE + u64::from(GUARD_CF_FUNCTION_TABLE_RVA),
            1,
            0,
        ),
    ] {
        let mut bytes = fixture();
        set_guard_cf_load_config(
            &mut bytes,
            LOAD_CONFIG_GUARD_FIELDS_SIZE,
            LOAD_CONFIG_GUARD_FIELDS_SIZE,
            table_va,
            count,
            guard_flags,
        );
        let error = analyze_pe(&bytes).expect_err("GuardCF table fields must be self-consistent");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: "GuardCF function table",
                    ..
                }
            ),
            "{label}: {error}"
        );
    }

    for (label, table_va, expected_reason) in [
        (
            "below image base",
            IMAGE_BASE - 1,
            "below preferred image base",
        ),
        (
            "outside image",
            IMAGE_BASE + 0x2000,
            "outside the declared image",
        ),
        (
            "wider than an RVA",
            IMAGE_BASE + u64::from(u32::MAX) + 1,
            "does not fit a 32-bit image RVA",
        ),
    ] {
        let mut bytes = fixture();
        set_guard_cf_load_config(
            &mut bytes,
            LOAD_CONFIG_GUARD_FIELDS_SIZE,
            LOAD_CONFIG_GUARD_FIELDS_SIZE,
            table_va,
            1,
            IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
        );
        let error = analyze_pe(&bytes).expect_err("GuardCFFunctionTable stores an image VA");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: "GuardCFFunctionTable",
                    reason,
                } if reason.contains(expected_reason)
            ),
            "{label}: {error}"
        );
    }

    let mut overlapping = fixture();
    set_guard_cf_load_config(
        &mut overlapping,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        IMAGE_BASE + u64::from(LOAD_CONFIG_DIRECTORY_RVA),
        1,
        IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
    );
    let error = analyze_pe(&overlapping)
        .expect_err("the function table cannot alias its load-config structure");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "GuardCF function table",
            reason,
        } if reason.contains("overlaps")
    ));

    let mut unbacked_directory = fixture();
    set_directory(&mut unbacked_directory, 10, 0x15f0, 148);
    let error = analyze_pe(&unbacked_directory)
        .expect_err("the complete load-config directory range must be file-backed");
    assert!(matches!(
        error,
        AnalysisError::UnmappedRva {
            context: "load-config directory",
            rva: 0x15f0,
            size: 148,
        }
    ));

    let mut one_byte_short = fixture();
    set_guard_cf_load_config(
        &mut one_byte_short,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        IMAGE_BASE + 0x15ee,
        1,
        0xf000_0400,
    );
    let error = analyze_pe(&one_byte_short)
        .expect_err("the final metadata byte of each GuardCF record must be file-backed");
    assert!(matches!(
        error,
        AnalysisError::UnmappedRva {
            context: "GuardCF function table",
            rva: 0x15ee,
            size: 19,
        }
    ));

    let mut exact_tail = fixture();
    set_guard_cf_load_config(
        &mut exact_tail,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        IMAGE_BASE + 0x15ed,
        1,
        0xf000_0400,
    );
    write_guard_cf_records(&mut exact_tail, 0x15ed, &[(0x1040, [0x22; 15])]);
    let exact_tail = analyze_pe(&exact_tail)
        .expect("the final nineteen fully backed bytes may hold one maximum-stride record");
    assert_eq!(exact_tail.guard_cf_function_table_rva, Some(0x15ed));
    assert_eq!(exact_tail.guard_cf_functions[0].rva, 0x1040);
    assert_eq!(exact_tail.guard_cf_functions[0].metadata, [0x22; 15]);
}

#[test]
fn rejects_non_executable_unbacked_and_suppressed_invalid_guard_cf_targets() {
    let mut non_executable = guard_cf_fixture(&[(0x2000, [])]);
    non_executable.resize(0xa00, 0);
    put_u16(&mut non_executable, COFF_OFFSET + 2, 2);
    put_u32(&mut non_executable, OPTIONAL_OFFSET + 56, 0x3000);
    let data_section = SECTION_OFFSET + 40;
    non_executable[data_section..data_section + 6].copy_from_slice(b".data\0");
    put_u32(&mut non_executable, data_section + 8, 0x200);
    put_u32(&mut non_executable, data_section + 12, 0x2000);
    put_u32(&mut non_executable, data_section + 16, 0x200);
    put_u32(&mut non_executable, data_section + 20, 0x800);
    put_u32(&mut non_executable, data_section + 36, 0x4000_0040);

    let mut virtual_tail = guard_cf_fixture(&[(0x1600, [])]);
    put_u32(&mut virtual_tail, SECTION_OFFSET + 8, 0x700);

    let cases = [
        ("non-executable section", non_executable),
        ("executable virtual tail", virtual_tail),
        ("outside image", guard_cf_fixture(&[(0x2000, [])])),
        (
            "FID-suppressed invalid target",
            guard_cf_fixture(&[(0x0100, [0x01])]),
        ),
    ];
    for (label, bytes) in cases {
        let error = analyze_pe(&bytes)
            .expect_err("every GFIDS record remains a backed executable RVA structurally");
        assert!(
            matches!(
                &error,
                AnalysisError::InvalidField {
                    field: "GuardCF function target",
                    ..
                }
            ),
            "{label}: {error}"
        );
    }
}

#[test]
fn enforces_guard_cf_function_count_before_mapping_or_allocating_the_table() {
    let mut bytes = fixture();
    set_guard_cf_load_config(
        &mut bytes,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_FIELDS_SIZE,
        IMAGE_BASE + u64::from(GUARD_CF_FUNCTION_TABLE_RVA),
        GUARD_CF_FUNCTION_LIMIT + 1,
        0xf000_0400,
    );
    let error = analyze_pe(&bytes)
        .expect_err("the declared GuardCF count cap is checked before the table is mapped");
    assert!(matches!(
        error,
        AnalysisError::LimitExceeded {
            kind: "GuardCF function",
            count: 262_145,
            limit: 262_144,
        }
    ));
}

#[test]
fn seeds_thunks_from_every_guard_cf_function_record() {
    let mut bytes = guard_cf_fixture(&[(0x1040, [0x00]), (0x1080, [0x02]), (0x10c0, [0x01])]);
    put_rel32_instruction(&mut bytes, 0x1040, 0xe9, 0x1060);
    put_rel8_instruction(&mut bytes, 0x1060, 0xeb, 0x1070);
    bytes[file_offset(0x1070)] = 0xc3;
    put_rel32_instruction(&mut bytes, 0x1080, 0xe9, 0x10a0);
    bytes[file_offset(0x10a0)] = 0xc3;
    put_rel32_instruction(&mut bytes, 0x10c0, 0xe9, 0x10e0);
    bytes[file_offset(0x10e0)] = 0xc3;

    let analysis = analyze_pe(&bytes).expect("GuardCF candidates seed exact thunk recovery");
    assert_eq!(
        analysis.thunks,
        [
            PeThunk {
                rva: 0x1040,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1060 },
            },
            PeThunk {
                rva: 0x1060,
                instruction_size: 2,
                target: PeControlFlowTarget::Function { rva: 0x1070 },
            },
            PeThunk {
                rva: 0x1080,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x10a0 },
            },
            PeThunk {
                rva: 0x10c0,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x10e0 },
            },
        ]
    );
    assert_eq!(
        analysis
            .symbol_graph
            .claims()
            .iter()
            .filter(|claim| claim.provenance().method == "pe-guard-cf-function")
            .count(),
        3
    );
    assert!(analysis.symbol_graph.claims().iter().any(|claim| {
        claim.provenance().method == "pe-guard-cf-function"
            && matches!(claim.subject(), SymbolSubject::Function { rva: 0x10c0, .. })
    }));
    assert!(analysis.symbol_graph.claims().iter().any(|claim| matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Function { rva: 0x1080, .. },
            SymbolAssertion::ThunkTarget {
                target: ControlFlowTarget::Function { rva: 0x10a0 },
            },
        )
    )));
    assert!(analysis.symbol_graph.claims().iter().any(|claim| matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Function { rva: 0x10c0, .. },
            SymbolAssertion::ThunkTarget {
                target: ControlFlowTarget::Function { rva: 0x10e0 },
            },
        )
    )));
}

#[test]
fn every_guard_cf_record_authorizes_a_runtime_interior_target() {
    let mut bytes = guard_cf_fixture(&[(0x1080, [0x00])]);
    put_u32(&mut bytes, file_offset(0x1300) + 4, 0x1100);
    put_rel32_instruction(&mut bytes, 0x1000, 0xe9, 0x1080);
    bytes[file_offset(0x1080)] = 0xc3;

    let analysis = analyze_pe(&bytes)
        .expect("GFIDS proves an alternate function start inside unwind-covered code");
    assert!(analysis.thunks.iter().any(|thunk| {
        thunk.rva == 0x1000 && thunk.target == PeControlFlowTarget::Function { rva: 0x1080 }
    }));

    let mut suppressed = guard_cf_fixture(&[(0x1080, [0x01])]);
    put_u32(&mut suppressed, file_offset(0x1300) + 4, 0x1100);
    put_rel32_instruction(&mut suppressed, 0x1000, 0xe9, 0x1080);
    suppressed[file_offset(0x1080)] = 0xc3;

    let suppressed = analyze_pe(&suppressed)
        .expect("FID-suppressed GFIDS still proves an interior function start");
    assert!(suppressed.thunks.iter().any(|thunk| {
        thunk.rva == 0x1000 && thunk.target == PeControlFlowTarget::Function { rva: 0x1080 }
    }));
}

#[test]
fn validated_deserialization_rejects_tampered_guard_cf_state_and_graphs() {
    let analysis = analyze_pe(&guard_cf_fixture(&[
        (0x1040, [0x00, 0xa0]),
        (0x1080, [0x01, 0xa1]),
        (0x10c0, [0x02, 0xa2]),
    ]))
    .expect("valid GuardCF analysis");
    let original = serde_json::to_value(analysis).expect("serialize GuardCF analysis");

    let mut missing_directory = original.clone();
    missing_directory["directories"]["load_config"] = serde_json::Value::Null;
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_directory)
        .expect_err("GuardCF state cannot outlive its load-config directory");
    assert!(error.to_string().contains("load-config directory"));

    let mut missing_size = original.clone();
    missing_size["load_config_size"] = serde_json::Value::Null;
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_size)
        .expect_err("a load-config directory requires its internal size");
    assert!(error.to_string().contains("load-config size"));

    let mut missing_flags = original.clone();
    missing_flags["guard_flags"] = serde_json::Value::Null;
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_flags)
        .expect_err("the GuardCF-capable prefix requires GuardFlags");
    assert!(error.to_string().contains("GuardFlags"));

    let mut missing_table = original.clone();
    missing_table["guard_cf_function_table_rva"] = serde_json::Value::Null;
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_table)
        .expect_err("GuardCF records require their function-table RVA");
    assert!(error.to_string().contains("without a table RVA"));

    let mut empty_table = original.clone();
    empty_table["guard_cf_functions"] = serde_json::json!([]);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(empty_table)
        .expect_err("a persisted nonzero table RVA requires retained records");
    assert!(error.to_string().contains("without any records"));

    let mut table_flag_cleared = original.clone();
    table_flag_cleared["guard_flags"] = serde_json::json!(0x2000_0000_u32);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(table_flag_cleared)
        .expect_err("a persisted nonempty table requires the table-present flag");
    assert!(
        error
            .to_string()
            .contains("IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT is clear")
    );

    let mut short_guard_prefix = original.clone();
    short_guard_prefix["load_config_size"] = serde_json::json!(LOAD_CONFIG_GUARD_FIELDS_SIZE - 1);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(short_guard_prefix)
        .expect_err("GuardCF state cannot survive a shortened load-config prefix");
    assert!(
        error
            .to_string()
            .contains("too short to contain GuardCF fields")
    );

    let mut short_optional_header = original.clone();
    short_optional_header["coff"]["optional_header_size"] = serde_json::json!(199);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(short_optional_header)
        .expect_err("data-directory entry 10 requires at least 200 optional-header bytes");
    assert!(error.to_string().contains("at least 200 bytes"));

    let mut noncanonical_index = original.clone();
    noncanonical_index["guard_cf_functions"][1]["table_index"] = serde_json::json!(7);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(noncanonical_index)
        .expect_err("GuardCF table indices preserve exact source order");
    assert!(error.to_string().contains("function-table index"));

    let mut changed_stride = original.clone();
    changed_stride["guard_flags"] = serde_json::json!(0x3000_0400_u32);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(changed_stride)
        .expect_err("retained metadata lengths must match the GuardFlags high nibble");
    assert!(error.to_string().contains("function metadata"));

    let mut unsorted = original.clone();
    unsorted["guard_cf_functions"][1]["rva"] = serde_json::json!(0x1030);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(unsorted)
        .expect_err("persisted GFIDS RVAs remain strictly sorted");
    assert!(error.to_string().contains("strictly increasing and unique"));

    let mut invalid_target = original.clone();
    invalid_target["guard_cf_functions"][0]["rva"] = serde_json::json!(0x100);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(invalid_target)
        .expect_err("persisted GuardCF targets remain backed executable RVAs");
    assert!(error.to_string().contains("GuardCF function target"));

    let mut misaligned_export_suppressed = original.clone();
    misaligned_export_suppressed["guard_cf_functions"][0]["rva"] = serde_json::json!(0x1041);
    misaligned_export_suppressed["guard_cf_functions"][0]["metadata"][0] = serde_json::json!(0x02);
    let error =
        serde_json::from_value::<resymbol_analysis::PeAnalysis>(misaligned_export_suppressed)
            .expect_err("persisted export-suppressed GFIDS entries retain alignment invariants");
    assert!(error.to_string().contains("16-byte aligned"));

    let mut changed_suppression = original.clone();
    changed_suppression["guard_cf_functions"][0]["metadata"][0] = serde_json::json!(1);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(changed_suppression)
        .expect_err("suppression changes must invalidate the deterministic base graph");
    assert!(error.to_string().contains("symbol graph"));

    let mut stale_evidence = original;
    let guard_claim = stale_evidence["symbol_graph"]["claims"]
        .as_array_mut()
        .expect("claim array")
        .iter_mut()
        .find(|claim| claim["provenance"]["method"] == "pe-guard-cf-function")
        .expect("GuardCF claim");
    guard_claim["evidence"][0]["artifacts"]["metadata"] = serde_json::json!("ff ff");
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(stale_evidence)
        .expect_err("persisted GuardCF evidence remains bound to exact metadata bytes");
    assert!(error.to_string().contains("symbol graph"));
}

#[test]
fn recovers_modern_guard_target_inventories_without_inventing_function_claims_or_seeds() {
    let mut bytes = extended_guard_fixture();
    put_rel32_instruction(&mut bytes, 0x1050, 0xe9, 0x10a0);
    put_rel32_instruction(&mut bytes, 0x1060, 0xe9, 0x10b0);
    put_rel32_instruction(&mut bytes, 0x1070, 0xe9, 0x10c0);
    put_rel32_instruction(&mut bytes, 0x1080, 0xe9, 0x10d0);

    let analysis = analyze_pe(&bytes).expect("valid modern Guard target tables");
    assert_eq!(
        analysis.load_config_size,
        Some(LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE)
    );
    assert_eq!(
        analysis.guard_cf_function_table_rva,
        Some(EXTENDED_GUARD_CF_FUNCTION_TABLE_RVA)
    );
    assert_eq!(analysis.guard_cf_functions.len(), 1);
    assert_eq!(
        analysis.guard_address_taken_iat_entry_table_rva,
        Some(GUARD_ADDRESS_TAKEN_IAT_TABLE_RVA)
    );
    assert_eq!(
        analysis.guard_address_taken_iat_entries,
        [
            PeGuardAddressTakenIatEntry {
                table_index: 0,
                iat_rva: 0x1260,
                metadata: vec![0],
            },
            PeGuardAddressTakenIatEntry {
                table_index: 1,
                iat_rva: 0x1268,
                metadata: vec![0],
            },
        ]
    );
    assert_eq!(
        analysis.guard_long_jump_target_table_rva,
        Some(GUARD_LONG_JUMP_TARGET_TABLE_RVA)
    );
    assert_eq!(
        analysis.guard_long_jump_targets,
        [
            PeGuardLongJumpTarget {
                table_index: 0,
                target_rva: 0x1060,
                metadata: vec![0],
            },
            PeGuardLongJumpTarget {
                table_index: 1,
                target_rva: 0x1080,
                metadata: vec![0],
            },
        ]
    );
    assert_eq!(
        analysis.guard_eh_continuation_table_rva,
        Some(GUARD_EH_CONTINUATION_TABLE_RVA)
    );
    assert_eq!(
        analysis.guard_eh_continuation_targets,
        [
            PeGuardEhContinuationTarget {
                table_index: 0,
                target_rva: 0x1050,
                metadata: vec![0],
            },
            PeGuardEhContinuationTarget {
                table_index: 1,
                target_rva: 0x1070,
                metadata: vec![0],
            },
        ]
    );

    assert_eq!(
        analysis
            .symbol_graph
            .claims()
            .iter()
            .filter(|claim| claim.provenance().method == "pe-guard-cf-function")
            .count(),
        1
    );
    for target_rva in [0x1050_u32, 0x1060, 0x1070, 0x1080] {
        assert!(
            analysis.symbol_graph.claims().iter().all(|claim| !matches!(
                (claim.subject(), claim.assertion()),
                (
                    SymbolSubject::Function { rva, .. },
                    SymbolAssertion::FunctionEntry
                    ) if *rva == u64::from(target_rva)
            )),
            "continuation target {target_rva:#x} must remain an inventory entry"
        );
        assert!(
            analysis.thunks.iter().all(|thunk| thunk.rva != target_rva),
            "continuation target {target_rva:#x} must not seed thunk recovery"
        );
    }

    let encoded = serde_json::to_value(&analysis).expect("serialize modern Guard inventories");
    for marker in [
        "guard_address_taken_iat_entries",
        "guard_long_jump_targets",
        "guard_eh_continuation_targets",
    ] {
        assert!(
            encoded.get(marker).is_some(),
            "missing schema marker {marker}"
        );
    }
    let decoded = serde_json::from_value::<resymbol_analysis::PeAnalysis>(encoded)
        .expect("validated modern Guard inventory round trip");
    assert_eq!(decoded, analysis);
}

#[test]
fn guard_address_taken_iat_inventory_accepts_exact_delay_import_slots() {
    const LOAD_CONFIG_RVA: u32 = 0x1500;
    const GIAT_TABLE_RVA: u32 = 0x15b0;

    let mut bytes = delay_import_fixture();
    set_directory(
        &mut bytes,
        10,
        LOAD_CONFIG_RVA,
        LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_FIELDS_SIZE,
    );
    let load_config = file_offset(LOAD_CONFIG_RVA);
    put_u32(
        &mut bytes,
        load_config,
        LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_FIELDS_SIZE,
    );
    put_u32(
        &mut bytes,
        load_config + 144,
        0x1000_0000 | IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT,
    );
    put_u64(
        &mut bytes,
        load_config + 160,
        IMAGE_BASE + u64::from(GIAT_TABLE_RVA),
    );
    put_u64(&mut bytes, load_config + 168, 1);
    write_guard_cf_records(&mut bytes, GIAT_TABLE_RVA, &[(DELAY_IMPORT_IAT_RVA, [0])]);

    let analysis = analyze_pe(&bytes).expect("a parsed delay-IAT slot is valid GIAT evidence");
    assert_eq!(analysis.delay_imports.len(), 1);
    assert_eq!(
        analysis.guard_address_taken_iat_entry_table_rva,
        Some(GIAT_TABLE_RVA)
    );
    assert_eq!(
        analysis.guard_address_taken_iat_entries,
        [PeGuardAddressTakenIatEntry {
            table_index: 0,
            iat_rva: DELAY_IMPORT_IAT_RVA,
            metadata: vec![0],
        }]
    );
}

#[test]
fn enforces_modern_guard_table_presence_bounds_storage_and_record_invariants() {
    for (label, size, flag, expected) in [
        (
            "address-taken IAT",
            LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_FIELDS_SIZE - 1,
            IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT,
            "address-taken IAT fields",
        ),
        (
            "long-jump",
            LOAD_CONFIG_GUARD_LONG_JUMP_FIELDS_SIZE - 1,
            IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT,
            "long-jump fields",
        ),
        (
            "EH continuation",
            LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE - 1,
            IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT,
            "EH-continuation fields",
        ),
    ] {
        let mut bytes = fixture();
        set_extended_guard_load_config(
            &mut bytes,
            LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE,
            size,
            empty_extended_guard_load_config(flag),
        );
        let error = analyze_pe(&bytes)
            .expect_err("a presence bit requires a structure containing its table fields");
        assert!(error.to_string().contains(expected), "{label}: {error}");
    }

    for (label, count_offset, expected) in [
        ("address-taken IAT", 168, "address-taken IAT table"),
        ("long-jump", 184, "long-jump target table"),
        ("EH continuation", 272, "EH-continuation table"),
    ] {
        let mut bytes = extended_guard_fixture();
        put_u64(
            &mut bytes,
            file_offset(LOAD_CONFIG_DIRECTORY_RVA) + count_offset,
            0,
        );
        let error =
            analyze_pe(&bytes).expect_err("a nonzero Guard table VA requires a nonzero count");
        assert!(error.to_string().contains(expected), "{label}: {error}");
    }

    for (label, flag, expected) in [
        (
            "address-taken IAT",
            IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT,
            "IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT is clear",
        ),
        (
            "long-jump",
            IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT,
            "IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT is clear",
        ),
        (
            "EH continuation",
            IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT,
            "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT is clear",
        ),
    ] {
        let mut bytes = extended_guard_fixture();
        let guard_flags = valid_extended_guard_load_config().guard_flags & !flag;
        put_u32(
            &mut bytes,
            file_offset(LOAD_CONFIG_DIRECTORY_RVA) + 144,
            guard_flags,
        );
        let error =
            analyze_pe(&bytes).expect_err("a nonempty Guard table requires its presence bit");
        assert!(error.to_string().contains(expected), "{label}: {error}");
    }

    for (label, count_offset, kind) in [
        ("address-taken IAT", 168, "Guard address-taken IAT entry"),
        ("long-jump", 184, "Guard long-jump target"),
        ("EH continuation", 272, "Guard EH-continuation target"),
    ] {
        let mut bytes = extended_guard_fixture();
        put_u64(
            &mut bytes,
            file_offset(LOAD_CONFIG_DIRECTORY_RVA) + count_offset,
            GUARD_CF_FUNCTION_LIMIT + 1,
        );
        let error = analyze_pe(&bytes)
            .expect_err("Guard target count caps are checked before table mapping or allocation");
        assert!(
            matches!(
                error,
                AnalysisError::LimitExceeded {
                    kind: actual,
                    count: 262_145,
                    limit: 262_144,
                } if actual == kind
            ),
            "{label}: {error}"
        );
    }

    for (label, table_rva, expected) in [
        (
            "address-taken IAT",
            GUARD_ADDRESS_TAKEN_IAT_TABLE_RVA,
            "address-taken IAT metadata",
        ),
        (
            "long-jump",
            GUARD_LONG_JUMP_TARGET_TABLE_RVA,
            "long-jump metadata",
        ),
        (
            "EH continuation",
            GUARD_EH_CONTINUATION_TABLE_RVA,
            "EH-continuation metadata",
        ),
    ] {
        let mut bytes = extended_guard_fixture();
        bytes[file_offset(table_rva) + 4] = 1;
        let error = analyze_pe(&bytes).expect_err("modern Guard metadata bytes are reserved zero");
        assert!(error.to_string().contains(expected), "{label}: {error}");
    }

    let mut unknown_iat = extended_guard_fixture();
    put_u32(
        &mut unknown_iat,
        file_offset(GUARD_ADDRESS_TAKEN_IAT_TABLE_RVA),
        0x1261,
    );
    let error = analyze_pe(&unknown_iat)
        .expect_err("GIAT records must name exact conventional or delay-import IAT slots");
    assert!(error.to_string().contains("exact parsed import IAT slot"));

    for (label, second_record_rva, record_size, expected) in [
        (
            "address-taken IAT",
            GUARD_ADDRESS_TAKEN_IAT_TABLE_RVA,
            5,
            "address-taken IAT table",
        ),
        (
            "long-jump",
            GUARD_LONG_JUMP_TARGET_TABLE_RVA,
            5,
            "long-jump target table",
        ),
        (
            "EH continuation",
            GUARD_EH_CONTINUATION_TABLE_RVA,
            5,
            "EH-continuation table",
        ),
    ] {
        let mut bytes = extended_guard_fixture();
        let first = u32::from_le_bytes(
            bytes[file_offset(second_record_rva)..file_offset(second_record_rva) + 4]
                .try_into()
                .expect("four-byte fixture record"),
        );
        put_u32(
            &mut bytes,
            file_offset(second_record_rva) + record_size,
            first,
        );
        let error = analyze_pe(&bytes).expect_err("Guard target RVAs remain sorted and unique");
        assert!(error.to_string().contains(expected), "{label}: {error}");
    }

    for (label, table_rva, expected) in [
        (
            "long-jump",
            GUARD_LONG_JUMP_TARGET_TABLE_RVA,
            "long-jump target",
        ),
        (
            "EH continuation",
            GUARD_EH_CONTINUATION_TABLE_RVA,
            "EH-continuation target",
        ),
    ] {
        let mut bytes = extended_guard_fixture();
        put_u32(&mut bytes, file_offset(table_rva), 0x1600);
        let error = analyze_pe(&bytes)
            .expect_err("continuation inventories require file-backed executable targets");
        assert!(error.to_string().contains(expected), "{label}: {error}");
    }

    let mut load_config_overlap = fixture();
    let mut fields = empty_extended_guard_load_config(
        0x1000_0000 | IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT,
    );
    fields.address_taken_iat_table_va = IMAGE_BASE + u64::from(LOAD_CONFIG_DIRECTORY_RVA + 0x98);
    fields.address_taken_iat_count = 1;
    set_extended_guard_load_config(
        &mut load_config_overlap,
        LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE,
        fields,
    );
    let error = analyze_pe(&load_config_overlap)
        .expect_err("Guard target tables cannot alias the load-config structure");
    assert!(
        error
            .to_string()
            .contains("overlaps the declared load-config")
    );

    let mut table_overlap = extended_guard_fixture();
    put_u64(
        &mut table_overlap,
        file_offset(LOAD_CONFIG_DIRECTORY_RVA) + 176,
        IMAGE_BASE + u64::from(GUARD_ADDRESS_TAKEN_IAT_TABLE_RVA),
    );
    let error = analyze_pe(&table_overlap)
        .expect_err("nonempty load-config Guard target tables must be pairwise disjoint");
    assert!(error.to_string().contains("load-config guard tables"));

    let mut one_byte_short = extended_guard_fixture();
    put_u64(
        &mut one_byte_short,
        file_offset(LOAD_CONFIG_DIRECTORY_RVA) + 160,
        IMAGE_BASE + 0x15fc,
    );
    put_u64(
        &mut one_byte_short,
        file_offset(LOAD_CONFIG_DIRECTORY_RVA) + 168,
        1,
    );
    let error = analyze_pe(&one_byte_short)
        .expect_err("the complete GIAT record including metadata must be file-backed");
    assert!(matches!(
        error,
        AnalysisError::UnmappedRva {
            context: "Guard address-taken IAT table",
            rva: 0x15fc,
            size: 5,
        }
    ));

    let mut versioned_empty = fixture();
    set_extended_guard_load_config(
        &mut versioned_empty,
        LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE,
        empty_extended_guard_load_config(
            IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT
                | IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT
                | IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT,
        ),
    );
    let empty = analyze_pe(&versioned_empty)
        .expect("presence flags distinguish supported empty tables from legacy structures");
    assert!(empty.guard_address_taken_iat_entries.is_empty());
    assert!(empty.guard_long_jump_targets.is_empty());
    assert!(empty.guard_eh_continuation_targets.is_empty());
}

#[test]
fn validated_deserialization_rejects_tampered_modern_guard_target_state() {
    let analysis = analyze_pe(&extended_guard_fixture()).expect("valid modern Guard inventories");
    let original = serde_json::to_value(analysis).expect("serialize modern Guard inventories");

    let mut empty_fixture = fixture();
    set_extended_guard_load_config(
        &mut empty_fixture,
        LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE,
        LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE,
        empty_extended_guard_load_config(
            IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT
                | IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT
                | IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT,
        ),
    );
    let empty_analysis = analyze_pe(&empty_fixture).expect("valid empty modern Guard inventories");
    let empty_original =
        serde_json::to_value(empty_analysis).expect("serialize empty modern Guard inventories");

    for (size, expected) in [
        (
            LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_FIELDS_SIZE - 1,
            "Guard address-taken IAT fields",
        ),
        (
            LOAD_CONFIG_GUARD_LONG_JUMP_FIELDS_SIZE - 1,
            "Guard long-jump fields",
        ),
        (
            LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE - 1,
            "Guard EH-continuation fields",
        ),
    ] {
        let mut shortened = empty_original.clone();
        shortened["load_config_size"] = serde_json::json!(size);
        let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(shortened)
            .expect_err("a presence flag requires its load-config table fields even when empty");
        assert!(error.to_string().contains(expected));
        assert!(error.to_string().contains("presence flag"));
    }

    let mut legacy = original.clone();
    let legacy_object = legacy
        .as_object_mut()
        .expect("PE analysis serializes as an object");
    for field in [
        "guard_address_taken_iat_entry_table_rva",
        "guard_address_taken_iat_entries",
        "guard_long_jump_target_table_rva",
        "guard_long_jump_targets",
        "guard_eh_continuation_table_rva",
        "guard_eh_continuation_targets",
    ] {
        legacy_object.remove(field);
    }
    let legacy = serde_json::from_value::<resymbol_analysis::PeAnalysis>(legacy)
        .expect("schema-nine analyses default absent schema-ten inventories");
    assert!(legacy.guard_address_taken_iat_entries.is_empty());
    assert!(legacy.guard_long_jump_targets.is_empty());
    assert!(legacy.guard_eh_continuation_targets.is_empty());

    for (table_field, entries_field, expected) in [
        (
            "guard_address_taken_iat_entry_table_rva",
            "guard_address_taken_iat_entries",
            "address-taken IAT table",
        ),
        (
            "guard_long_jump_target_table_rva",
            "guard_long_jump_targets",
            "long-jump target table",
        ),
        (
            "guard_eh_continuation_table_rva",
            "guard_eh_continuation_targets",
            "EH-continuation table",
        ),
    ] {
        let mut missing_rva = original.clone();
        missing_rva[table_field] = serde_json::Value::Null;
        let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_rva)
            .expect_err("persisted Guard target entries require their table RVA");
        assert!(error.to_string().contains(expected));

        let mut empty_records = original.clone();
        empty_records[entries_field] = serde_json::json!([]);
        let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(empty_records)
            .expect_err("a persisted nonzero Guard target table RVA requires records");
        assert!(error.to_string().contains("without any records"));
    }

    for (flag, expected) in [
        (
            IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT,
            "IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT is clear",
        ),
        (
            IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT,
            "IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT is clear",
        ),
        (
            IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT,
            "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT is clear",
        ),
    ] {
        let mut cleared = original.clone();
        cleared["guard_flags"] =
            serde_json::json!(valid_extended_guard_load_config().guard_flags & !flag);
        let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(cleared)
            .expect_err("persisted Guard target tables require their presence bits");
        assert!(error.to_string().contains(expected));
    }

    for (size, expected) in [
        (
            LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_FIELDS_SIZE - 1,
            "address-taken IAT table",
        ),
        (
            LOAD_CONFIG_GUARD_LONG_JUMP_FIELDS_SIZE - 1,
            "long-jump target table",
        ),
        (
            LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE - 1,
            "EH-continuation table",
        ),
    ] {
        let mut shortened = original.clone();
        shortened["load_config_size"] = serde_json::json!(size);
        let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(shortened)
            .expect_err("persisted Guard target state requires its structure version");
        assert!(error.to_string().contains(expected));
    }

    let mut noncanonical_giat_index = original.clone();
    noncanonical_giat_index["guard_address_taken_iat_entries"][1]["table_index"] =
        serde_json::json!(7);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(noncanonical_giat_index)
        .expect_err("GIAT indices preserve exact source order");
    assert!(error.to_string().contains("address-taken IAT table index"));

    let mut invalid_giat = original.clone();
    invalid_giat["guard_address_taken_iat_entries"][0]["iat_rva"] = serde_json::json!(0x1261);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(invalid_giat)
        .expect_err("persisted GIAT records remain tied to exact parsed import slots");
    assert!(error.to_string().contains("exact parsed import IAT slot"));

    for inventory in [
        "guard_address_taken_iat_entries",
        "guard_long_jump_targets",
        "guard_eh_continuation_targets",
    ] {
        let mut nonzero_reserved_metadata = original.clone();
        nonzero_reserved_metadata[inventory][0]["metadata"][0] = serde_json::json!(1);
        let error =
            serde_json::from_value::<resymbol_analysis::PeAnalysis>(nonzero_reserved_metadata)
                .expect_err("persisted modern Guard metadata remains reserved zero");
        assert!(error.to_string().contains("nonzero reserved metadata"));

        let mut wrong_metadata_stride = original.clone();
        wrong_metadata_stride[inventory][0]["metadata"] = serde_json::json!([]);
        let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(wrong_metadata_stride)
            .expect_err("persisted modern Guard metadata lengths follow GuardFlags");
        assert!(error.to_string().contains("GuardFlags-selected"));
    }

    let mut unsorted_long_jump = original.clone();
    unsorted_long_jump["guard_long_jump_targets"][1]["target_rva"] = serde_json::json!(0x1060);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(unsorted_long_jump)
        .expect_err("persisted long-jump targets remain sorted and unique");
    assert!(error.to_string().contains("strictly increasing and unique"));

    let mut invalid_eh_target = original.clone();
    invalid_eh_target["guard_eh_continuation_targets"][0]["target_rva"] = serde_json::json!(0x1600);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(invalid_eh_target)
        .expect_err("persisted EH continuation targets remain backed executable RVAs");
    assert!(error.to_string().contains("EH-continuation target"));

    let mut overlapping_tables = original;
    overlapping_tables["guard_long_jump_target_table_rva"] =
        serde_json::json!(GUARD_ADDRESS_TAKEN_IAT_TABLE_RVA);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(overlapping_tables)
        .expect_err("persisted Guard target tables remain pairwise disjoint");
    assert!(error.to_string().contains("load-config guard tables"));
}

#[test]
fn emits_one_metadata_claim_for_a_file_backed_executable_pe_entry_point() {
    let analysis = analyze_pe(&fixture()).expect("valid PE entry point");
    let entry_claims = analysis
        .symbol_graph
        .claims()
        .iter()
        .filter(|claim| claim.provenance().method == "pe-entry-point")
        .collect::<Vec<_>>();

    assert_eq!(entry_claims.len(), 1);
    let entry = entry_claims[0];
    assert!(matches!(
        (entry.subject(), entry.assertion()),
        (
            SymbolSubject::Function {
                rva: 0x1000,
                size: None,
                ..
            },
            SymbolAssertion::FunctionEntry,
        )
    ));
    assert_eq!(entry.confidence().get(), 0.99);
    assert_eq!(entry.evidence()[0].kind.as_str(), EvidenceKind::METADATA);
    assert_eq!(entry.evidence()[0].artifacts["entry_point_rva"], "0x1000");
}

#[test]
fn distinguishes_absent_zero_and_empty_tls_callback_tables() {
    let absent = analyze_pe(&fixture()).expect("PE without a TLS directory");
    assert_eq!(absent.directories.tls, None);
    assert_eq!(absent.tls_callback_table_rva, None);
    assert!(absent.tls_callbacks.is_empty());
    assert!(!absent.tls_callback_scan_truncated);

    let mut zero = fixture();
    set_tls_directory(&mut zero, TLS_DIRECTORY_RVA, 40, 0);
    let zero = analyze_pe(&zero).expect("zero AddressOfCallbacks is an absent table");
    assert_eq!(
        zero.directories.tls,
        Some(resymbol_analysis::DataDirectory {
            rva: TLS_DIRECTORY_RVA,
            size: 40,
        })
    );
    assert_eq!(zero.tls_callback_table_rva, None);
    assert!(zero.tls_callbacks.is_empty());
    assert!(!zero.tls_callback_scan_truncated);

    let empty = analyze_pe(&tls_callbacks_fixture(&[]))
        .expect("a file-backed null callback slot is an empty table");
    assert_eq!(empty.tls_callback_table_rva, Some(TLS_CALLBACK_TABLE_RVA));
    assert!(empty.tls_callbacks.is_empty());
    assert!(!empty.tls_callback_scan_truncated);
    assert!(
        empty
            .symbol_graph
            .claims()
            .iter()
            .all(|claim| claim.provenance().method != "pe-tls-callback")
    );
}

#[test]
fn recovers_tls_callbacks_with_exact_evidence_and_round_trips_the_graph() {
    let analysis =
        analyze_pe(&tls_callbacks_fixture(&[0x1040, 0x1080])).expect("two exact TLS callbacks");

    assert_eq!(
        analysis.tls_callbacks,
        [
            PeTlsCallback {
                table_index: 0,
                callback_rva: 0x1040,
            },
            PeTlsCallback {
                table_index: 1,
                callback_rva: 0x1080,
            },
        ]
    );
    assert_eq!(
        analysis.tls_callback_table_rva,
        Some(TLS_CALLBACK_TABLE_RVA)
    );
    assert!(!analysis.tls_callback_scan_truncated);

    let callback_claims = analysis
        .symbol_graph
        .claims()
        .iter()
        .filter(|claim| claim.provenance().method == "pe-tls-callback")
        .collect::<Vec<_>>();
    assert_eq!(callback_claims.len(), 2);
    let second = callback_claims
        .iter()
        .copied()
        .find(|claim| {
            matches!(
                (claim.subject(), claim.assertion()),
                (
                    SymbolSubject::Function {
                        rva: 0x1080,
                        size: None,
                        ..
                    },
                    SymbolAssertion::FunctionEntry,
                )
            )
        })
        .expect("second callback has one function-entry claim");
    assert_eq!(second.confidence().get(), 0.99);
    assert_eq!(second.evidence()[0].kind.as_str(), EvidenceKind::METADATA);
    assert_eq!(
        second.evidence()[0].summary,
        "exact executable callback address from the PE32+ TLS callback table"
    );
    assert_eq!(
        second.evidence()[0]
            .confidence
            .expect("exact callback evidence")
            .get(),
        1.0
    );
    assert_eq!(
        second.evidence()[0].artifacts["tls_directory_rva"],
        "0x1380"
    );
    assert_eq!(
        second.evidence()[0].artifacts["callback_table_rva"],
        "0x13c0"
    );
    assert_eq!(
        second.evidence()[0].artifacts["callback_slot_rva"],
        "0x13c8"
    );
    assert_eq!(second.evidence()[0].artifacts["table_index"], "1");
    assert_eq!(second.evidence()[0].artifacts["callback_rva"], "0x1080");
    assert_eq!(second.evidence()[0].artifacts["section_index"], "0");
    assert_eq!(second.evidence()[0].artifacts["section_name"], ".all");
    assert!(matches!(
        &second.provenance().producer,
        ClaimProducer::Core { component, version }
            if component == "resymbol-analysis" && !version.is_empty()
    ));
    assert_eq!(second.provenance().method, "pe-tls-callback");
    assert_eq!(second.provenance().run_id, None);
    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild TLS callback graph"),
        analysis.symbol_graph
    );

    let encoded = serde_json::to_string(&analysis).expect("serialize TLS callback analysis");
    let decoded = serde_json::from_str::<resymbol_analysis::PeAnalysis>(&encoded)
        .expect("deserialize TLS callback analysis");
    assert_eq!(decoded, analysis);
    let session = AnalysisSession::new(BinaryAnalysis::Pe(decoded), Vec::new(), Vec::new())
        .expect("TLS callback analysis remains a valid session base");
    let encoded = serde_json::to_string(&session).expect("serialize TLS callback session");
    assert_eq!(
        serde_json::from_str::<AnalysisSession>(&encoded)
            .expect("deserialize TLS callback session"),
        session
    );
}

#[test]
fn preserves_duplicate_tls_callback_records_and_emits_one_entry_claim_per_slot() {
    let analysis = analyze_pe(&tls_callbacks_fixture(&[0x1040, 0x1040]))
        .expect("duplicate TLS callbacks retain loader order");

    assert_eq!(
        analysis.tls_callbacks,
        [
            PeTlsCallback {
                table_index: 0,
                callback_rva: 0x1040,
            },
            PeTlsCallback {
                table_index: 1,
                callback_rva: 0x1040,
            },
        ]
    );
    let entry_claims = analysis
        .symbol_graph
        .claims()
        .iter()
        .filter(|claim| {
            claim.provenance().method == "pe-tls-callback"
                && matches!(claim.subject(), SymbolSubject::Function { rva: 0x1040, .. })
        })
        .collect::<Vec<_>>();
    assert_eq!(entry_claims.len(), 2);
    assert_eq!(entry_claims[0].evidence()[0].artifacts["table_index"], "0");
    assert_eq!(entry_claims[1].evidence()[0].artifacts["table_index"], "1");
    assert_eq!(
        entry_claims[0].evidence()[0].artifacts["callback_slot_rva"],
        "0x13c0"
    );
    assert_eq!(
        entry_claims[1].evidence()[0].artifacts["callback_slot_rva"],
        "0x13c8"
    );
    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild per-slot TLS graph"),
        analysis.symbol_graph
    );
}

#[test]
fn seeds_jump_thunks_from_tls_callbacks_without_other_metadata_predecessors() {
    let mut bytes = tls_callbacks_fixture(&[0x1040]);
    put_rel32_instruction(&mut bytes, 0x1040, 0xe9, 0x1060);
    put_rel8_instruction(&mut bytes, 0x1060, 0xeb, 0x1080);
    bytes[file_offset(0x1080)] = 0xc3;
    put_rel32_instruction(&mut bytes, 0x10a0, 0xe9, 0x10c0);
    bytes[file_offset(0x10c0)] = 0xc3;

    let analysis = analyze_pe(&bytes).expect("TLS callback is a trusted thunk root");
    assert_eq!(
        analysis.thunks,
        [
            PeThunk {
                rva: 0x1040,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1060 },
            },
            PeThunk {
                rva: 0x1060,
                instruction_size: 2,
                target: PeControlFlowTarget::Function { rva: 0x1080 },
            },
        ]
    );
    assert!(analysis.thunks.iter().all(|thunk| thunk.rva != 0x10a0));
    assert!(analysis.symbol_graph.claims().iter().any(|claim| matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Function { rva: 0x1040, .. },
            SymbolAssertion::ThunkTarget {
                target: ControlFlowTarget::Function { rva: 0x1060 },
            },
        )
    )));
    assert!(analysis.symbol_graph.claims().iter().any(|claim| matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Function { rva: 0x1060, .. },
            SymbolAssertion::ThunkTarget {
                target: ControlFlowTarget::Function { rva: 0x1080 },
            },
        )
    )));
}

#[test]
fn rejects_malformed_tls_directories_tables_and_callback_endpoints() {
    let mut short_directory = fixture();
    set_tls_directory(
        &mut short_directory,
        TLS_DIRECTORY_RVA,
        39,
        IMAGE_BASE + u64::from(TLS_CALLBACK_TABLE_RVA),
    );
    let error = analyze_pe(&short_directory).expect_err("PE32+ TLS directory needs 40 bytes");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "TLS directory size",
            ..
        }
    ));

    let mut padded_directory = tls_callbacks_fixture(&[]);
    set_directory(&mut padded_directory, 9, TLS_DIRECTORY_RVA, 48);
    let padded = analyze_pe(&padded_directory)
        .expect("a fully backed forward-compatible TLS directory may exceed 40 bytes");
    assert_eq!(padded.directories.tls.expect("TLS directory").size, 48);

    let mut over_limit_directory = fixture();
    set_directory(
        &mut over_limit_directory,
        9,
        TLS_DIRECTORY_RVA,
        64 * 1024 * 1024 + 1,
    );
    let error = analyze_pe(&over_limit_directory)
        .expect_err("TLS directory bytes remain subject to the global directory cap");
    assert!(matches!(
        error,
        AnalysisError::LimitExceeded {
            kind: "TLS-directory byte",
            count: 67_108_865,
            limit: 67_108_864,
        }
    ));

    let mut unbacked_directory = fixture();
    set_directory(&mut unbacked_directory, 9, 0x15f0, 40);
    let error = analyze_pe(&unbacked_directory).expect_err("TLS directory must be file-backed");
    assert!(matches!(
        error,
        AnalysisError::UnmappedRva {
            context: "TLS directory",
            rva: 0x15f0,
            size: 40,
        }
    ));

    let mut below_base_table = fixture();
    set_tls_directory(&mut below_base_table, TLS_DIRECTORY_RVA, 40, IMAGE_BASE - 1);
    let error = analyze_pe(&below_base_table)
        .expect_err("AddressOfCallbacks is a preferred-base VA, not an RVA");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "TLS AddressOfCallbacks",
            ..
        }
    ));

    let mut unbacked_table = fixture();
    set_tls_directory(
        &mut unbacked_table,
        TLS_DIRECTORY_RVA,
        40,
        IMAGE_BASE + 0x1600,
    );
    let error = analyze_pe(&unbacked_table).expect_err("callback table must be file-backed");
    assert!(matches!(
        error,
        AnalysisError::UnmappedRva {
            context: "TLS callback slot",
            rva: 0x1600,
            size: 8,
        }
    ));

    let mut below_base_callback = tls_callbacks_fixture(&[]);
    put_u64(
        &mut below_base_callback,
        file_offset(TLS_CALLBACK_TABLE_RVA),
        IMAGE_BASE - 1,
    );
    let error = analyze_pe(&below_base_callback).expect_err("callback entries are VAs, not RVAs");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "TLS callback VA",
            ..
        }
    ));

    let mut non_executable_callback = tls_callbacks_fixture(&[]);
    put_u64(
        &mut non_executable_callback,
        file_offset(TLS_CALLBACK_TABLE_RVA),
        IMAGE_BASE + 0x100,
    );
    put_u64(
        &mut non_executable_callback,
        file_offset(TLS_CALLBACK_TABLE_RVA) + 8,
        0,
    );
    let error = analyze_pe(&non_executable_callback)
        .expect_err("a backed PE header byte is not an executable callback endpoint");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "TLS callback target",
            ..
        }
    ));

    let mut unbacked_executable_callback = tls_callbacks_fixture(&[]);
    put_u32(&mut unbacked_executable_callback, SECTION_OFFSET + 8, 0x700);
    put_u64(
        &mut unbacked_executable_callback,
        file_offset(TLS_CALLBACK_TABLE_RVA),
        IMAGE_BASE + 0x1600,
    );
    put_u64(
        &mut unbacked_executable_callback,
        file_offset(TLS_CALLBACK_TABLE_RVA) + 8,
        0,
    );
    let error = analyze_pe(&unbacked_executable_callback)
        .expect_err("an executable virtual tail is not a file-backed callback endpoint");
    assert!(matches!(
        error,
        AnalysisError::InvalidField {
            field: "TLS callback target",
            ..
        }
    ));

    let mut missing_terminator = fixture();
    set_tls_directory(
        &mut missing_terminator,
        TLS_DIRECTORY_RVA,
        40,
        IMAGE_BASE + 0x15f8,
    );
    put_u64(
        &mut missing_terminator,
        file_offset(0x15f8),
        IMAGE_BASE + 0x1040,
    );
    let error = analyze_pe(&missing_terminator)
        .expect_err("an unterminated callback table cannot run past file backing");
    assert!(matches!(
        error,
        AnalysisError::UnmappedRva {
            context: "TLS callback slot",
            rva: 0x1600,
            size: 8,
        }
    ));
}

#[test]
fn rejects_tls_table_and_callback_vas_outside_the_declared_image_or_rva_width() {
    let too_wide_va = IMAGE_BASE + u64::from(u32::MAX) + 1;
    for (label, table_va, expected_reason) in [
        (
            "table outside image",
            IMAGE_BASE + 0x2000,
            "outside the declared image",
        ),
        (
            "table RVA wider than u32",
            too_wide_va,
            "does not fit a 32-bit image RVA",
        ),
    ] {
        let mut bytes = fixture();
        set_tls_directory(&mut bytes, TLS_DIRECTORY_RVA, 40, table_va);
        let error = analyze_pe(&bytes).expect_err(label);
        assert!(matches!(
            error,
            AnalysisError::InvalidField {
                field: "TLS AddressOfCallbacks",
                reason,
            } if reason.contains(expected_reason)
        ));
    }

    for (label, callback_va, expected_reason) in [
        (
            "callback outside image",
            IMAGE_BASE + 0x2000,
            "outside the declared image",
        ),
        (
            "callback RVA wider than u32",
            too_wide_va,
            "does not fit a 32-bit image RVA",
        ),
    ] {
        let mut bytes = tls_callbacks_fixture(&[]);
        put_u64(&mut bytes, file_offset(TLS_CALLBACK_TABLE_RVA), callback_va);
        let error = analyze_pe(&bytes).expect_err(label);
        assert!(matches!(
            error,
            AnalysisError::InvalidField {
                field: "TLS callback VA",
                reason,
            } if reason.contains(expected_reason)
        ));
    }
}

#[test]
fn tls_callback_cap_distinguishes_exact_completion_from_partial_recovery() {
    let complete = analyze_pe(&expanded_tls_callbacks_fixture(TLS_CALLBACK_LIMIT, false))
        .expect("exactly-cap callbacks followed by null are complete");
    assert_eq!(complete.tls_callbacks.len(), TLS_CALLBACK_LIMIT);
    assert_eq!(complete.tls_callbacks[0].table_index, 0);
    assert_eq!(
        complete.tls_callbacks[TLS_CALLBACK_LIMIT - 1].table_index,
        u32::try_from(TLS_CALLBACK_LIMIT - 1).expect("TLS callback limit fits u32")
    );
    assert!(!complete.tls_callback_scan_truncated);
    assert_eq!(
        complete
            .symbol_graph
            .claims()
            .iter()
            .filter(|claim| claim.provenance().method == "pe-tls-callback")
            .count(),
        TLS_CALLBACK_LIMIT
    );

    let partial = analyze_pe(&expanded_tls_callbacks_fixture(TLS_CALLBACK_LIMIT, true))
        .expect("the first non-null slot after the cap proves partial recovery");
    assert_eq!(partial.tls_callbacks.len(), TLS_CALLBACK_LIMIT);
    assert!(partial.tls_callback_scan_truncated);
    assert!(
        partial
            .tls_callbacks
            .iter()
            .all(|callback| callback.callback_rva == 0x1040)
    );
    assert_eq!(
        partial
            .symbol_graph
            .claims()
            .iter()
            .filter(|claim| claim.provenance().method == "pe-tls-callback")
            .count(),
        TLS_CALLBACK_LIMIT,
        "every retained metadata slot keeps its own exact evidence claim"
    );
    let callback_claims = partial
        .symbol_graph
        .claims()
        .iter()
        .filter(|claim| claim.provenance().method == "pe-tls-callback")
        .collect::<Vec<_>>();
    assert_eq!(
        callback_claims[0].evidence()[0].artifacts["callback_slot_rva"],
        "0x13c0"
    );
    assert_eq!(
        callback_claims[TLS_CALLBACK_LIMIT - 1].evidence()[0].artifacts["table_index"],
        (TLS_CALLBACK_LIMIT - 1).to_string()
    );
}

#[test]
fn tls_callback_cap_probe_does_not_resolve_or_retain_its_nonzero_value() {
    let mut bytes = expanded_tls_callbacks_fixture(TLS_CALLBACK_LIMIT, false);
    put_u64(
        &mut bytes,
        file_offset(TLS_CALLBACK_TABLE_RVA) + TLS_CALLBACK_LIMIT * 8,
        IMAGE_BASE + u64::from(u32::MAX),
    );

    let analysis = analyze_pe(&bytes)
        .expect("a nonzero out-of-image probe proves truncation without endpoint validation");
    assert_eq!(analysis.tls_callbacks.len(), TLS_CALLBACK_LIMIT);
    assert!(analysis.tls_callback_scan_truncated);
    assert!(
        analysis
            .tls_callbacks
            .iter()
            .all(|callback| callback.callback_rva == 0x1040)
    );
    assert_eq!(
        analysis
            .symbol_graph
            .claims()
            .iter()
            .filter(|claim| claim.provenance().method == "pe-tls-callback")
            .count(),
        TLS_CALLBACK_LIMIT
    );
}

#[test]
fn validated_deserialization_rejects_tampered_tls_callback_state_and_graphs() {
    let analysis =
        analyze_pe(&tls_callbacks_fixture(&[0x1040, 0x1080])).expect("valid TLS callback analysis");
    let original = serde_json::to_value(analysis).expect("serialize TLS callback analysis");

    let mut missing_directory = original.clone();
    missing_directory["directories"]["tls"] = serde_json::Value::Null;
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_directory)
        .expect_err("callback state cannot outlive its TLS directory");
    assert!(error.to_string().contains("without a TLS directory"));

    let mut short_optional_header = original.clone();
    short_optional_header["coff"]["optional_header_size"] = serde_json::json!(112);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(short_optional_header)
        .expect_err("persisted TLS state requires optional-header directory entry 9");
    assert!(error.to_string().contains("at least 192 bytes"));

    let mut missing_table = original.clone();
    missing_table["tls_callback_table_rva"] = serde_json::Value::Null;
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_table)
        .expect_err("callback entries require their table RVA");
    assert!(error.to_string().contains("without a callback-table RVA"));

    let mut noncanonical_index = original.clone();
    noncanonical_index["tls_callbacks"][1]["table_index"] = serde_json::json!(7);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(noncanonical_index)
        .expect_err("callback table indices preserve exact source order");
    assert!(error.to_string().contains("TLS callback table index"));

    let mut impossible_partial = original.clone();
    impossible_partial["tls_callback_scan_truncated"] = serde_json::json!(true);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(impossible_partial)
        .expect_err("partial state requires the full retained cap");
    assert!(error.to_string().contains("TLS callback scan state"));

    let mut non_executable_target = original.clone();
    non_executable_target["tls_callbacks"][0]["callback_rva"] = serde_json::json!(0x100);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(non_executable_target)
        .expect_err("persisted callback targets remain file-backed executable");
    assert!(error.to_string().contains("TLS callback target"));

    let mut stale_graph = original;
    stale_graph["tls_callbacks"][0]["callback_rva"] = serde_json::json!(0x1060);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(stale_graph)
        .expect_err("the deterministic graph must bind the exact callback model");
    assert!(error.to_string().contains("symbol graph"));

    let analysis =
        analyze_pe(&tls_callbacks_fixture(&[0x1040, 0x1080])).expect("valid TLS callback analysis");
    let mut stale_evidence = serde_json::to_value(analysis).expect("serialize callback graph");
    let callback_claim = stale_evidence["symbol_graph"]["claims"]
        .as_array_mut()
        .expect("claim array")
        .iter_mut()
        .find(|claim| claim["provenance"]["method"] == "pe-tls-callback")
        .expect("TLS callback claim");
    callback_claim["evidence"][0]["artifacts"]["callback_slot_rva"] = serde_json::json!("0x13d0");
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(stale_evidence)
        .expect_err("persisted callback evidence must match its exact table slot");
    assert!(error.to_string().contains("symbol graph"));
}

#[test]
fn follows_transitive_thunk_targets_without_discovering_unrelated_executable_jumps() {
    let analysis = analyze_pe(&transitive_thunk_chain_fixture())
        .expect("valid PE with a direct-call-seeded thunk chain");

    assert!(!analysis.code_recovery_scan_truncated);
    assert_eq!(
        analysis.direct_calls,
        [PeDirectCall {
            caller_rva: 0x1000,
            call_site_rva: 0x1000,
            instruction_size: 5,
            target: PeControlFlowTarget::Function { rva: 0x1040 },
        }]
    );
    assert_eq!(
        analysis.thunks,
        [
            PeThunk {
                rva: 0x1040,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1060 },
            },
            PeThunk {
                rva: 0x1060,
                instruction_size: 2,
                target: PeControlFlowTarget::Function { rva: 0x1080 },
            },
        ]
    );
    assert!(analysis.thunks.iter().all(|thunk| thunk.rva != 0x10c0));

    let claims = analysis.symbol_graph.claims();
    assert!(claims.iter().any(|claim| matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Function { rva: 0x1060, .. },
            SymbolAssertion::ThunkTarget {
                target: ControlFlowTarget::Function { rva: 0x1080 },
            },
        )
    )));
    assert!(claims.iter().any(|claim| {
        claim.provenance().method == "pe-x64-recovered-function-target"
            && matches!(
                (claim.subject(), claim.assertion()),
                (
                    SymbolSubject::Function { rva: 0x1080, .. },
                    SymbolAssertion::FunctionEntry,
                )
            )
    }));
    assert!(claims.iter().all(|claim| !matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Function {
                rva: 0x10c0 | 0x10e0,
                ..
            },
            SymbolAssertion::ThunkTarget { .. } | SymbolAssertion::FunctionEntry,
        )
    )));
    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild thunk graph"),
        analysis.symbol_graph
    );

    let session =
        AnalysisSession::new(BinaryAnalysis::Pe(analysis.clone()), Vec::new(), Vec::new())
            .expect("valid transitive-thunk session");
    let encoded = serde_json::to_string(&session).expect("serialize transitive-thunk session");
    let decoded = serde_json::from_str::<AnalysisSession>(&encoded)
        .expect("deserialize transitive-thunk session");
    assert_eq!(decoded, session);
}

#[test]
fn follows_mixed_internal_and_read_only_pointer_thunk_targets() {
    let analysis = analyze_pe(&mixed_transitive_pointer_thunk_chain_fixture())
        .expect("valid PE with a mixed transitive thunk chain");

    assert!(!analysis.code_recovery_scan_truncated);
    assert_eq!(
        analysis.thunks,
        [
            PeThunk {
                rva: 0x1040,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1060 },
            },
            PeThunk {
                rva: 0x1060,
                instruction_size: 6,
                target: PeControlFlowTarget::FunctionPointer {
                    slot_rva: 0x2301,
                    rva: 0x1080,
                },
            },
        ]
    );
    assert!(analysis.data_references.iter().all(|reference| {
        reference.instruction_rva != 0x1060 || reference.target_rva != 0x2301
    }));
    assert!(analysis.symbol_graph.claims().iter().any(|claim| {
        claim.provenance().method == "pe-x64-read-only-pointer-thunk"
            && matches!(
                (claim.subject(), claim.assertion()),
                (
                    SymbolSubject::Function { rva: 0x1060, .. },
                    SymbolAssertion::ThunkTarget {
                        target: ControlFlowTarget::FunctionPointer {
                            slot_rva: 0x2301,
                            rva: 0x1080,
                        },
                    },
                )
            )
    }));
}

#[test]
fn transitive_thunk_validation_is_independent_of_canonical_source_order() {
    let analysis = analyze_pe(&descending_transitive_thunk_chain_fixture())
        .expect("valid descending-RVA thunk chain");

    assert_eq!(
        analysis.thunks,
        [
            PeThunk {
                rva: 0x1080,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1060 },
            },
            PeThunk {
                rva: 0x10a0,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1080 },
            },
        ]
    );
    let encoded = serde_json::to_string(&analysis).expect("serialize descending thunk chain");
    let decoded = serde_json::from_str::<resymbol_analysis::PeAnalysis>(&encoded)
        .expect("deserialize descending thunk chain");
    assert_eq!(decoded, analysis);
}

#[test]
fn connected_transitive_thunk_cycles_terminate_and_retain_each_exact_edge() {
    let analysis = analyze_pe(&cyclic_transitive_thunk_chain_fixture())
        .expect("valid PE with a reachable thunk cycle");

    assert!(!analysis.code_recovery_scan_truncated);
    assert_eq!(
        analysis.thunks,
        [
            PeThunk {
                rva: 0x1040,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1060 },
            },
            PeThunk {
                rva: 0x1060,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1040 },
            },
        ]
    );
    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild cyclic graph"),
        analysis.symbol_graph
    );
}

#[test]
fn recovers_bounded_direct_calls_and_exact_jump_thunks() {
    let bytes = code_recovery_fixture();
    let analysis = analyze_pe(&bytes).expect("valid PE with recoverable control flow");

    assert!(!analysis.code_recovery_scan_truncated);
    assert_eq!(
        analysis.direct_calls,
        [
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x1000,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1040 },
            },
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x1005,
                instruction_size: 6,
                target: PeControlFlowTarget::ImportIat { iat_rva: 0x1260 },
            },
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x100b,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1080 },
            },
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x1010,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x10a0 },
            },
        ]
    );
    assert_eq!(
        analysis.thunks,
        [
            PeThunk {
                rva: 0x1040,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1060 },
            },
            PeThunk {
                rva: 0x1080,
                instruction_size: 6,
                target: PeControlFlowTarget::ImportIat { iat_rva: 0x1268 },
            },
            PeThunk {
                rva: 0x10a0,
                instruction_size: 2,
                target: PeControlFlowTarget::Function { rva: 0x10b0 },
            },
        ]
    );

    let claims = analysis.symbol_graph.claims();
    let direct_edge = claims
        .iter()
        .find(|claim| {
            matches!(
                claim.assertion(),
                SymbolAssertion::DirectCall {
                    call_site_rva: 0x1000,
                    ..
                }
            )
        })
        .expect("retained direct edge claim");
    assert_eq!(direct_edge.confidence().get(), 0.90);
    assert_eq!(
        direct_edge.evidence()[0].summary,
        DIRECT_CALL_EVIDENCE_SUMMARY
    );

    let thunk_edge = claims
        .iter()
        .find(|claim| {
            matches!(
                (claim.subject(), claim.assertion()),
                (
                    SymbolSubject::Function { rva: 0x1040, .. },
                    SymbolAssertion::ThunkTarget { .. },
                )
            )
        })
        .expect("retained thunk edge claim");
    assert_eq!(thunk_edge.confidence().get(), 0.95);
    assert_eq!(thunk_edge.evidence()[0].summary, THUNK_EVIDENCE_SUMMARY);

    let recovered_target = claims
        .iter()
        .find(|claim| {
            claim.provenance().method == "pe-x64-recovered-function-target"
                && matches!(
                    (claim.subject(), claim.assertion()),
                    (
                        SymbolSubject::Function { rva: 0x1060, .. },
                        SymbolAssertion::FunctionEntry,
                    )
                )
        })
        .expect("conservative recovered target entry");
    assert_eq!(recovered_target.confidence().get(), 0.85);
    assert!(claims.iter().any(|claim| matches!(
        claim.assertion(),
        SymbolAssertion::DirectCall {
            call_site_rva: 0x1005,
            target: ControlFlowTarget::ImportIat { iat_rva: 0x1260 },
        }
    )));
    assert!(claims.iter().any(|claim| matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Function {
                rva: 0x1040,
                size: None,
                ..
            },
            SymbolAssertion::ThunkTarget {
                target: ControlFlowTarget::Function { rva: 0x1060 },
            },
        )
    )));
    assert!(claims.iter().any(|claim| matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Function {
                rva: 0x10b0,
                size: None,
                ..
            },
            SymbolAssertion::FunctionEntry,
        )
    )));
    assert!(
        claims
            .iter()
            .filter(|claim| matches!(
                claim.assertion(),
                SymbolAssertion::DirectCall { .. } | SymbolAssertion::ThunkTarget { .. }
            ))
            .all(|claim| claim.evidence()[0].kind.as_str() == EvidenceKind::CONTROL_FLOW)
    );
    assert!(claims.iter().all(|claim| {
        !matches!(
            (claim.subject(), claim.assertion()),
            (
                SymbolSubject::Function {
                    rva: 0x1040 | 0x1060 | 0x1080 | 0x10a0 | 0x10b0,
                    ..
                },
                SymbolAssertion::Name { .. } | SymbolAssertion::FunctionBoundary { .. },
            )
        )
    }));

    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild recovery graph"),
        analysis.symbol_graph
    );
    let encoded = serde_json::to_string(&analysis).expect("serialize recovered control flow");
    let decoded = serde_json::from_str(&encoded).expect("deserialize recovered control flow");
    assert_eq!(analysis, decoded);
}

#[test]
fn recovers_msvc_rex_w_prefixed_import_calls_and_thunks() {
    let mut bytes = fixture();
    bytes[file_offset(0x1000)..file_offset(0x1050)].fill(0x90);
    put_rex_w_rip_relative_instruction(&mut bytes, 0x1000, 0x15, 0x1260);
    bytes[file_offset(0x1007)] = 0xc3;
    put_u32(&mut bytes, file_offset(0x1144), 0x1040);
    put_rex_w_rip_relative_instruction(&mut bytes, 0x1040, 0x25, 0x1268);

    let analysis = analyze_pe(&bytes).expect("valid PE with MSVC import encodings");
    assert_eq!(
        analysis.direct_calls,
        [PeDirectCall {
            caller_rva: 0x1000,
            call_site_rva: 0x1000,
            instruction_size: 7,
            target: PeControlFlowTarget::ImportIat { iat_rva: 0x1260 },
        }]
    );
    assert_eq!(
        analysis.thunks,
        [PeThunk {
            rva: 0x1040,
            instruction_size: 7,
            target: PeControlFlowTarget::ImportIat { iat_rva: 0x1268 },
        }]
    );

    let json = serde_json::to_value(&analysis).expect("serialize REX.W recovery");
    let decoded = serde_json::from_value(json).expect("validate REX.W recovery");
    assert_eq!(analysis, decoded);
}

#[test]
fn rex_w_iat_control_flow_is_not_duplicated_as_data_flow() {
    let analysis = analyze_pe(&rtti_fixture_with_rex_w_iat_control_flow())
        .expect("valid PE with an IAT in non-executable data");

    assert_eq!(
        analysis.direct_calls,
        [PeDirectCall {
            caller_rva: 0x1000,
            call_site_rva: 0x1000,
            instruction_size: 7,
            target: PeControlFlowTarget::ImportIat { iat_rva: 0x2340 },
        }]
    );
    assert_eq!(
        analysis.thunks,
        [PeThunk {
            rva: 0x1020,
            instruction_size: 7,
            target: PeControlFlowTarget::ImportIat { iat_rva: 0x2340 },
        }]
    );
    assert!(
        analysis.data_references.is_empty(),
        "IAT control flow must not be duplicated as data flow"
    );
}

#[test]
fn resolves_exact_six_and_seven_byte_calls_through_unaligned_read_only_pointer_slots() {
    let analysis = analyze_pe(&read_only_pointer_call_fixture())
        .expect("valid PE with read-only function-pointer calls");

    assert_eq!(
        analysis.direct_calls,
        [
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x1000,
                instruction_size: 6,
                target: PeControlFlowTarget::FunctionPointer {
                    slot_rva: 0x2301,
                    rva: 0x1020,
                },
            },
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x1006,
                instruction_size: 7,
                target: PeControlFlowTarget::FunctionPointer {
                    slot_rva: 0x2311,
                    rva: 0x1020,
                },
            },
        ]
    );
    assert_eq!(
        analysis.data_references,
        [
            PeDataReference {
                caller_rva: 0x1000,
                instruction_rva: 0x1000,
                instruction_size: 6,
                target_rva: 0x2301,
            },
            PeDataReference {
                caller_rva: 0x1000,
                instruction_rva: 0x1006,
                instruction_size: 7,
                target_rva: 0x2311,
            },
        ]
    );

    let pointer_claim = analysis
        .symbol_graph
        .claims()
        .iter()
        .find(|claim| {
            matches!(
                claim.assertion(),
                SymbolAssertion::DirectCall {
                    call_site_rva: 0x1000,
                    target: ControlFlowTarget::FunctionPointer {
                        slot_rva: 0x2301,
                        rva: 0x1020,
                    },
                }
            )
        })
        .expect("typed read-only pointer-call claim");
    assert_eq!(
        pointer_claim.provenance().method,
        "pe-x64-read-only-pointer-call"
    );
    assert_eq!(
        pointer_claim.evidence()[0].summary,
        READ_ONLY_POINTER_CALL_EVIDENCE_SUMMARY
    );
    assert_eq!(
        pointer_claim.evidence()[0].artifacts.get("slot_rva"),
        Some(&"0x2301".to_owned())
    );

    let recovered_entry = analysis
        .symbol_graph
        .claims()
        .iter()
        .find(|claim| {
            claim.provenance().method == "pe-x64-recovered-function-target"
                && matches!(
                    (claim.subject(), claim.assertion()),
                    (
                        SymbolSubject::Function { rva: 0x1020, .. },
                        SymbolAssertion::FunctionEntry,
                    )
                )
                && claim.evidence()[0].artifacts.get("slot_rva") == Some(&"0x2301".to_owned())
        })
        .expect("pointer-derived recovered entry preserves its slot");
    assert_eq!(
        recovered_entry.evidence()[0].artifacts.get("edge_kind"),
        Some(&"read-only-pointer-call".to_owned())
    );

    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild pointer graph"),
        analysis.symbol_graph
    );
    let encoded = serde_json::to_string(&analysis).expect("serialize pointer-call analysis");
    let decoded = serde_json::from_str(&encoded).expect("deserialize pointer-call analysis");
    assert_eq!(analysis, decoded);
}

#[test]
fn prefixed_ff15_near_misses_remain_data_flow_instead_of_pointer_calls() {
    for prefix in [0x40, 0x66, 0xf2, 0xf3] {
        let analysis = analyze_pe(&prefixed_pointer_call_fixture(
            prefix,
            0x2301,
            RTTI_IMAGE_BASE + 0x1020,
        ))
        .unwrap_or_else(|error| panic!("prefix 0x{prefix:02x}: {error}"));

        assert!(
            analysis
                .direct_calls
                .iter()
                .all(|call| !matches!(call.target, PeControlFlowTarget::FunctionPointer { .. })),
            "prefix 0x{prefix:02x}"
        );
        assert_eq!(
            analysis.data_references,
            [PeDataReference {
                caller_rva: 0x1000,
                instruction_rva: 0x1000,
                instruction_size: 7,
                target_rva: 0x2301,
            }],
            "prefix 0x{prefix:02x}"
        );
    }
}

#[test]
fn exact_iat_membership_precedes_read_only_pointer_resolution() {
    let mut bytes = rtti_fixture_with_rex_w_iat_control_flow();
    put_rtti_rva_u64(&mut bytes, 0x2340, RTTI_IMAGE_BASE + 0x1020);

    let analysis = analyze_pe(&bytes).expect("valid PE with executable-looking IAT contents");
    assert_eq!(
        analysis.direct_calls,
        [PeDirectCall {
            caller_rva: 0x1000,
            call_site_rva: 0x1000,
            instruction_size: 7,
            target: PeControlFlowTarget::ImportIat { iat_rva: 0x2340 },
        }]
    );
    assert_eq!(
        analysis.thunks,
        [PeThunk {
            rva: 0x1020,
            instruction_size: 7,
            target: PeControlFlowTarget::ImportIat { iat_rva: 0x2340 },
        }]
    );
    assert!(analysis.data_references.is_empty());
}

#[test]
fn read_only_pointer_resolution_rejects_invalid_slots_and_targets_without_hiding_data_flow() {
    for (label, bytes) in [
        (
            "preferred VA below image base",
            single_pointer_call_fixture(0x2301, RTTI_IMAGE_BASE - 1),
        ),
        (
            "preferred VA at image end",
            single_pointer_call_fixture(0x2301, RTTI_IMAGE_BASE + 0x3000),
        ),
        (
            "non-executable target",
            single_pointer_call_fixture(0x2301, RTTI_IMAGE_BASE + 0x2300),
        ),
        (
            "runtime-function interior target",
            single_pointer_call_fixture(0x2301, RTTI_IMAGE_BASE + 0x1008),
        ),
        (
            "call-end target",
            single_pointer_call_fixture(0x2301, RTTI_IMAGE_BASE + 0x1006),
        ),
    ] {
        let analysis = analyze_pe(&bytes).unwrap_or_else(|error| panic!("{label}: {error}"));
        assert!(analysis.direct_calls.is_empty(), "{label}");
        assert_eq!(analysis.data_references.len(), 1, "{label}");
        assert_eq!(analysis.data_references[0].target_rva, 0x2301, "{label}");
    }

    let mut writable = single_pointer_call_fixture(0x2301, RTTI_IMAGE_BASE + 0x1020);
    put_u32(&mut writable, SECTION_OFFSET + 40 + 36, 0xc000_0040);
    let analysis = analyze_pe(&writable).expect("writable slot remains ordinary data flow");
    assert!(analysis.direct_calls.is_empty());
    assert_eq!(analysis.data_references.len(), 1);

    let mut short = rtti_fixture();
    short[rtti_file_offset(0x1000)..rtti_file_offset(0x1010)].fill(0x90);
    put_rip_relative_instruction(&mut short, 0x1000, 0x15, 0x23fc);
    short[rtti_file_offset(0x1006)] = 0xc3;
    put_u32(&mut short, rtti_file_offset(0x23fc), 0x1020);
    let analysis = analyze_pe(&short).expect("short slot remains ordinary data flow");
    assert!(analysis.direct_calls.is_empty());
    assert_eq!(analysis.data_references.len(), 1);
    assert_eq!(analysis.data_references[0].target_rva, 0x23fc);
}

#[test]
fn read_only_pointer_resolution_rejects_executable_virtual_tail_targets() {
    let mut bytes = single_pointer_call_fixture(0x2301, RTTI_IMAGE_BASE + 0x1200);
    // Extend .text virtually but leave its 0x200-byte raw extent unchanged.
    // RVA 0x1200 is therefore executable in-image metadata without file bytes.
    put_u32(&mut bytes, SECTION_OFFSET + 8, 0x400);

    let analysis = analyze_pe(&bytes)
        .expect("pointer target in executable virtual tail remains ordinary data flow");
    assert!(analysis.direct_calls.is_empty());
    assert_eq!(
        analysis.data_references,
        [PeDataReference {
            caller_rva: 0x1000,
            instruction_rva: 0x1000,
            instruction_size: 6,
            target_rva: 0x2301,
        }]
    );
}

#[test]
fn resolves_exact_six_and_seven_byte_thunks_through_unaligned_read_only_pointer_slots() {
    let analysis = analyze_pe(&read_only_pointer_thunk_fixture())
        .expect("valid PE with read-only function-pointer thunks");

    assert_eq!(
        analysis.thunks,
        [
            PeThunk {
                rva: 0x1000,
                instruction_size: 6,
                target: PeControlFlowTarget::FunctionPointer {
                    slot_rva: 0x2301,
                    rva: 0x1040,
                },
            },
            PeThunk {
                rva: 0x1020,
                instruction_size: 7,
                target: PeControlFlowTarget::FunctionPointer {
                    slot_rva: 0x2311,
                    rva: 0x1040,
                },
            },
        ]
    );

    let pointer_claim = analysis
        .symbol_graph
        .claims()
        .iter()
        .find(|claim| {
            matches!(
                (claim.subject(), claim.assertion()),
                (
                    SymbolSubject::Function { rva: 0x1000, .. },
                    SymbolAssertion::ThunkTarget {
                        target: ControlFlowTarget::FunctionPointer {
                            slot_rva: 0x2301,
                            rva: 0x1040,
                        },
                    },
                )
            )
        })
        .expect("typed read-only pointer-thunk claim");
    assert_eq!(
        pointer_claim.provenance().method,
        "pe-x64-read-only-pointer-thunk"
    );
    assert_eq!(
        pointer_claim.evidence()[0].summary,
        READ_ONLY_POINTER_THUNK_EVIDENCE_SUMMARY
    );
    assert_eq!(
        pointer_claim.evidence()[0].artifacts.get("slot_rva"),
        Some(&"0x2301".to_owned())
    );

    let recovered_entry = analysis
        .symbol_graph
        .claims()
        .iter()
        .find(|claim| {
            claim.provenance().method == "pe-x64-recovered-function-target"
                && matches!(
                    (claim.subject(), claim.assertion()),
                    (
                        SymbolSubject::Function { rva: 0x1040, .. },
                        SymbolAssertion::FunctionEntry,
                    )
                )
                && claim.evidence()[0].artifacts.get("slot_rva") == Some(&"0x2301".to_owned())
        })
        .expect("pointer-thunk-derived recovered entry preserves its slot");
    assert_eq!(
        recovered_entry.evidence()[0].artifacts.get("edge_kind"),
        Some(&"read-only-pointer-thunk".to_owned())
    );

    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild pointer-thunk graph"),
        analysis.symbol_graph
    );
    let encoded = serde_json::to_string(&analysis).expect("serialize pointer-thunk analysis");
    let decoded = serde_json::from_str(&encoded).expect("deserialize pointer-thunk analysis");
    assert_eq!(analysis, decoded);
}

#[test]
fn prefixed_ff25_near_misses_are_not_resolved_as_pointer_thunks() {
    for prefix in [0x40, 0x49, 0x66, 0x67, 0xf2, 0xf3] {
        let analysis = analyze_pe(&prefixed_pointer_thunk_fixture(
            prefix,
            0x2301,
            RTTI_IMAGE_BASE + 0x1060,
        ))
        .unwrap_or_else(|error| panic!("prefix 0x{prefix:02x}: {error}"));

        assert!(
            analysis
                .thunks
                .iter()
                .all(|thunk| !matches!(thunk.target, PeControlFlowTarget::FunctionPointer { .. })),
            "prefix 0x{prefix:02x}"
        );
    }
}

#[test]
fn read_only_pointer_thunks_reject_invalid_slots_and_targets() {
    let mut pointer_chain = single_pointer_thunk_fixture(0x2301, RTTI_IMAGE_BASE + 0x2320);
    put_rtti_rva_u64(&mut pointer_chain, 0x2320, RTTI_IMAGE_BASE + 0x1060);
    for (label, bytes) in [
        (
            "preferred VA below image base",
            single_pointer_thunk_fixture(0x2301, RTTI_IMAGE_BASE - 1),
        ),
        (
            "preferred VA at image end",
            single_pointer_thunk_fixture(0x2301, RTTI_IMAGE_BASE + 0x3000),
        ),
        (
            "non-executable target",
            single_pointer_thunk_fixture(0x2301, RTTI_IMAGE_BASE + 0x2300),
        ),
        ("pointer chain", pointer_chain),
        (
            "runtime-function interior target",
            single_pointer_thunk_fixture(0x2301, RTTI_IMAGE_BASE + 0x1008),
        ),
        (
            "self target",
            single_pointer_thunk_fixture(0x2301, RTTI_IMAGE_BASE + 0x1040),
        ),
    ] {
        let analysis = analyze_pe(&bytes).unwrap_or_else(|error| panic!("{label}: {error}"));
        assert!(
            analysis
                .thunks
                .iter()
                .all(|thunk| !matches!(thunk.target, PeControlFlowTarget::FunctionPointer { .. })),
            "{label}"
        );
    }

    for (label, characteristics) in [
        ("writable slot", 0xc000_0040),
        ("executable slot", 0x6000_0040),
        ("unreadable slot", 0x0000_0040),
        ("uninitialized slot", 0x4000_0000),
    ] {
        let mut bytes = single_pointer_thunk_fixture(0x2301, RTTI_IMAGE_BASE + 0x1060);
        put_u32(&mut bytes, SECTION_OFFSET + 40 + 36, characteristics);
        let analysis = analyze_pe(&bytes).unwrap_or_else(|error| panic!("{label}: {error}"));
        assert!(analysis.thunks.is_empty(), "{label}");
    }

    let mut short = rtti_fixture();
    put_u32(&mut short, OPTIONAL_OFFSET + 16, 0x1040);
    short[rtti_file_offset(0x1040)..rtti_file_offset(0x1050)].fill(0x90);
    put_rip_relative_instruction(&mut short, 0x1040, 0x25, 0x23fc);
    put_u32(&mut short, rtti_file_offset(0x23fc), 0x1060);
    let analysis = analyze_pe(&short).expect("short pointer slot remains unresolved");
    assert!(analysis.thunks.is_empty());

    let mut virtual_tail = single_pointer_thunk_fixture(0x2301, RTTI_IMAGE_BASE + 0x1200);
    put_u32(&mut virtual_tail, SECTION_OFFSET + 8, 0x400);
    let analysis =
        analyze_pe(&virtual_tail).expect("executable virtual-tail target remains unresolved");
    assert!(analysis.thunks.is_empty());
}

#[test]
fn read_only_pointer_thunk_accepts_the_last_fully_backed_eight_byte_slot() {
    let analysis = analyze_pe(&single_pointer_thunk_fixture(
        0x23f8,
        RTTI_IMAGE_BASE + 0x1060,
    ))
    .expect("last fully backed eight-byte slot is valid");
    assert_eq!(
        analysis.thunks,
        [PeThunk {
            rva: 0x1040,
            instruction_size: 6,
            target: PeControlFlowTarget::FunctionPointer {
                slot_rva: 0x23f8,
                rva: 0x1060,
            },
        }]
    );
}

#[test]
fn validated_deserialization_accepts_exact_legacy_direct_call_evidence_summary() {
    let analysis = analyze_pe(&code_recovery_fixture()).expect("valid recovered control flow");
    let direct_call_count = analysis.direct_calls.len();
    let mut value = serde_json::to_value(analysis).expect("serialize recovered control flow");
    let mut legacy_summary_count = 0;

    for claim in value["symbol_graph"]["claims"]
        .as_array_mut()
        .expect("serialized claims")
    {
        if claim["provenance"]["method"].as_str() == Some("pe-x64-direct-call") {
            assert_eq!(
                claim["evidence"][0]["summary"].as_str(),
                Some(DIRECT_CALL_EVIDENCE_SUMMARY)
            );
            claim["evidence"][0]["summary"] =
                serde_json::json!(LEGACY_DIRECT_CALL_EVIDENCE_SUMMARY);
            legacy_summary_count += 1;
        }
    }
    assert_eq!(legacy_summary_count, direct_call_count);

    let decoded = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect("the exact prior direct-call summary remains package-compatible");
    assert_eq!(decoded.direct_calls.len(), direct_call_count);
    assert!(
        decoded
            .symbol_graph
            .claims()
            .iter()
            .filter(|claim| claim.provenance().method == "pe-x64-direct-call")
            .all(|claim| claim.evidence()[0].summary == LEGACY_DIRECT_CALL_EVIDENCE_SUMMARY)
    );
}

#[test]
fn validated_deserialization_accepts_exact_legacy_thunk_evidence_summary() {
    let analysis = analyze_pe(&code_recovery_fixture()).expect("valid recovered control flow");
    let thunk_count = analysis.thunks.len();
    let mut value = serde_json::to_value(analysis).expect("serialize recovered control flow");
    let mut legacy_summary_count = 0;

    for claim in value["symbol_graph"]["claims"]
        .as_array_mut()
        .expect("serialized claims")
    {
        if claim["provenance"]["method"].as_str() == Some("pe-x64-jump-thunk") {
            assert_eq!(
                claim["evidence"][0]["summary"].as_str(),
                Some(THUNK_EVIDENCE_SUMMARY)
            );
            claim["evidence"][0]["summary"] = serde_json::json!(LEGACY_THUNK_EVIDENCE_SUMMARY);
            legacy_summary_count += 1;
        }
    }
    assert_eq!(legacy_summary_count, thunk_count);

    let decoded = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect("the exact prior seeded-thunk summary remains package-compatible");
    assert_eq!(decoded.thunks.len(), thunk_count);
    assert!(
        decoded
            .symbol_graph
            .claims()
            .iter()
            .filter(|claim| claim.provenance().method == "pe-x64-jump-thunk")
            .all(|claim| claim.evidence()[0].summary == LEGACY_THUNK_EVIDENCE_SUMMARY)
    );
}

#[test]
fn validated_deserialization_rejects_other_direct_call_evidence_changes() {
    let analysis = analyze_pe(&code_recovery_fixture()).expect("valid recovered control flow");
    let mut legacy = serde_json::to_value(analysis).expect("serialize recovered control flow");
    let direct_call_claim = legacy["symbol_graph"]["claims"]
        .as_array_mut()
        .expect("serialized claims")
        .iter_mut()
        .find(|claim| claim["provenance"]["method"] == "pe-x64-direct-call")
        .expect("direct-call claim");
    direct_call_claim["evidence"][0]["summary"] =
        serde_json::json!(LEGACY_DIRECT_CALL_EVIDENCE_SUMMARY);

    let mut arbitrary_summary = legacy.clone();
    let direct_call_claim = arbitrary_summary["symbol_graph"]["claims"]
        .as_array_mut()
        .expect("serialized claims")
        .iter_mut()
        .find(|claim| claim["provenance"]["method"] == "pe-x64-direct-call")
        .expect("direct-call claim");
    direct_call_claim["evidence"][0]["summary"] =
        serde_json::json!("bounded control-flow traversal with untrusted wording");
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(arbitrary_summary)
        .expect_err("only the exact legacy evidence summary may differ");
    assert!(error.to_string().contains("symbol graph"));

    let direct_call_claim = legacy["symbol_graph"]["claims"]
        .as_array_mut()
        .expect("serialized claims")
        .iter_mut()
        .find(|claim| claim["provenance"]["method"] == "pe-x64-direct-call")
        .expect("direct-call claim");
    direct_call_claim["evidence"][0]["artifacts"]["instruction_size"] = serde_json::json!("99");
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(legacy)
        .expect_err("legacy wording must not relax any other evidence field");
    assert!(error.to_string().contains("symbol graph"));
}

#[test]
fn recovers_bounded_strings_and_exact_rip_relative_data_references() {
    let analysis = analyze_pe(&string_and_data_reference_fixture())
        .expect("valid PE with recoverable strings and data references");

    assert!(!analysis.string_recovery_scan_truncated);
    assert!(!analysis.data_reference_scan_truncated);
    let selected_strings = analysis
        .strings
        .iter()
        .filter(|value| matches!(value.rva, 0x2300 | 0x2320))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        selected_strings,
        [
            PeRecoveredString {
                rva: 0x2300,
                byte_size: 16,
                encoding: PeStringEncoding::Ascii,
                value: "Recovered ASCII".to_owned(),
            },
            PeRecoveredString {
                rva: 0x2320,
                byte_size: 26,
                encoding: PeStringEncoding::Utf16Le,
                value: "Recovered 世界".to_owned(),
            },
        ]
    );
    assert_eq!(
        analysis.data_references,
        [
            PeDataReference {
                caller_rva: 0x1000,
                instruction_rva: 0x1000,
                instruction_size: 7,
                target_rva: 0x2300,
            },
            PeDataReference {
                caller_rva: 0x1000,
                instruction_rva: 0x1007,
                instruction_size: 7,
                target_rva: 0x2320,
            },
        ]
    );

    let ascii_claim = analysis
        .symbol_graph
        .claims()
        .iter()
        .find(|claim| {
            matches!(
                (claim.subject(), claim.assertion()),
                (
                    SymbolSubject::Global {
                        rva: 0x2300,
                        size: Some(16),
                        ..
                    },
                    SymbolAssertion::StringLiteral {
                        encoding: resymbol_core::StringEncoding::Ascii,
                        value,
                    },
                ) if value == "Recovered ASCII"
            )
        })
        .expect("ASCII string claim");
    assert_eq!(ascii_claim.confidence().get(), 0.90);
    assert_eq!(
        ascii_claim.evidence()[0].kind.as_str(),
        EvidenceKind::STRING_LITERAL
    );
    assert_eq!(ascii_claim.provenance().method, "pe-string-recovery");

    let data_claim = analysis
        .symbol_graph
        .claims()
        .iter()
        .find(|claim| {
            matches!(
                (claim.subject(), claim.assertion()),
                (
                    SymbolSubject::Function { rva: 0x1000, .. },
                    SymbolAssertion::DataReference {
                        instruction_rva: 0x1007,
                        instruction_size: 7,
                        target_rva: 0x2320,
                    },
                )
            )
        })
        .expect("RIP-relative data-reference claim");
    assert_eq!(data_claim.confidence().get(), 0.90);
    assert_eq!(
        data_claim.evidence()[0].kind.as_str(),
        EvidenceKind::DATA_FLOW
    );
    assert_eq!(data_claim.provenance().method, "pe-x64-data-reference");

    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild string and data-reference graph"),
        analysis.symbol_graph
    );
    let encoded = serde_json::to_string(&analysis).expect("serialize recovered analysis");
    let decoded = serde_json::from_str(&encoded).expect("deserialize recovered analysis");
    assert_eq!(analysis, decoded);
}

#[test]
fn validated_deserialization_rejects_tampered_string_and_data_recovery() {
    let analysis = analyze_pe(&string_and_data_reference_fixture())
        .expect("valid PE with strings and data references");
    let original = serde_json::to_value(analysis).expect("serialize recovered analysis");

    let explicit_string_index = original["strings"]
        .as_array()
        .expect("string array")
        .iter()
        .position(|value| value["rva"] == serde_json::json!(0x2300))
        .expect("explicit string record");
    let mut wrong_string_size = original.clone();
    wrong_string_size["strings"][explicit_string_index]["byte_size"] = serde_json::json!(15);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(wrong_string_size)
        .expect_err("persisted encoded string size must be exact");
    assert!(error.to_string().contains("encoded content plus NUL"));

    let mut executable_string = original.clone();
    let mut executable_record = executable_string["strings"][explicit_string_index].clone();
    executable_record["rva"] = serde_json::json!(0x1000);
    executable_string["strings"] = serde_json::Value::Array(vec![executable_record]);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(executable_string)
        .expect_err("persisted strings must remain in eligible data");
    assert!(error.to_string().contains("recovered string range"));

    let mut bad_instruction_size = original.clone();
    bad_instruction_size["data_references"][0]["instruction_size"] = serde_json::json!(0);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(bad_instruction_size)
        .expect_err("persisted data-reference instruction size must be valid");
    assert!(error.to_string().contains("instruction size"));

    let mut executable_target = original.clone();
    executable_target["data_references"][0]["target_rva"] = serde_json::json!(0x1000);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(executable_target)
        .expect_err("persisted data-reference targets must remain in eligible data");
    assert!(error.to_string().contains("data-reference target"));

    let mut stale_graph = original;
    stale_graph["data_references"][0]["target_rva"] = serde_json::json!(0x2310);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(stale_graph)
        .expect_err("persisted data references and graph claims must agree");
    assert!(error.to_string().contains("symbol graph"));
}

#[test]
fn deduplicates_recovered_function_entries_with_deterministic_edge_evidence() {
    let mut bytes = code_recovery_fixture();
    put_rel32_instruction(&mut bytes, 0x100b, 0xe8, 0x1040);
    put_rel8_instruction(&mut bytes, 0x10a0, 0xeb, 0x1060);

    let analysis = analyze_pe(&bytes).expect("valid repeated recovered targets");
    assert_eq!(
        analysis
            .direct_calls
            .iter()
            .filter(|call| call.target == PeControlFlowTarget::Function { rva: 0x1040 })
            .count(),
        2
    );
    assert_eq!(
        analysis
            .thunks
            .iter()
            .filter(|thunk| thunk.target == PeControlFlowTarget::Function { rva: 0x1060 })
            .count(),
        2
    );

    let recovered_entry = |target_rva| {
        analysis
            .symbol_graph
            .claims()
            .iter()
            .filter(|claim| {
                claim.provenance().method == "pe-x64-recovered-function-target"
                    && matches!(
                        (claim.subject(), claim.assertion()),
                        (
                            SymbolSubject::Function { rva, .. },
                            SymbolAssertion::FunctionEntry,
                        ) if *rva == target_rva
                    )
            })
            .collect::<Vec<_>>()
    };
    let call_target_entries = recovered_entry(0x1040);
    assert_eq!(call_target_entries.len(), 1);
    assert_eq!(
        call_target_entries[0].evidence()[0].artifacts["call_site_rva"],
        "0x1000"
    );
    let thunk_target_entries = recovered_entry(0x1060);
    assert_eq!(thunk_target_entries.len(), 1);
    assert_eq!(
        thunk_target_entries[0].evidence()[0].artifacts["source_rva"],
        "0x1040"
    );
}

#[test]
fn direct_call_retention_cap_bounds_graph_and_default_package_size() {
    const ATTEMPTED_CALLS: usize = 8_193;
    const RETAINED_CALLS: usize = 8_192;

    let analysis = analyze_pe(&direct_call_cap_fixture(ATTEMPTED_CALLS))
        .expect("valid PE reaching the direct-call cap");
    assert!(analysis.code_recovery_scan_truncated);
    assert_eq!(analysis.direct_calls.len(), RETAINED_CALLS);
    assert_eq!(analysis.direct_calls[0].call_site_rva, 0x1000);
    assert_eq!(
        analysis
            .direct_calls
            .last()
            .expect("retained canonical call prefix")
            .call_site_rva,
        0xaffb
    );
    assert_eq!(
        analysis
            .symbol_graph
            .claims()
            .iter()
            .filter(|claim| {
                claim.provenance().method == "pe-x64-recovered-function-target"
                    && matches!(
                        (claim.subject(), claim.assertion()),
                        (
                            SymbolSubject::Function { rva: 0xb100, .. },
                            SymbolAssertion::FunctionEntry,
                        )
                    )
            })
            .count(),
        1
    );

    let session = AnalysisSession::new(BinaryAnalysis::Pe(analysis), Vec::new(), Vec::new())
        .expect("valid capped analysis session");
    let package = ResymPackage::from_bound_payload(env!("CARGO_PKG_VERSION"), session)
        .expect("valid bound analysis package");
    let canonical = to_vec_bound(&package).expect("capped package fits the default limit");
    assert!(canonical.len() < DEFAULT_MAX_PACKAGE_BYTES);
}

#[test]
fn suppresses_call_next_and_runtime_interior_call_and_jump_targets() {
    let analysis = analyze_pe(&control_flow_suppression_fixture())
        .expect("valid PE with adversarial internal control flow");

    assert_eq!(
        analysis.direct_calls,
        [PeDirectCall {
            caller_rva: 0x1010,
            call_site_rva: 0x1015,
            instruction_size: 5,
            target: PeControlFlowTarget::Function { rva: 0x1060 },
        }]
    );
    assert!(analysis.thunks.is_empty());
    assert!(!analysis.code_recovery_scan_truncated);
    assert!(analysis.symbol_graph.claims().iter().all(|claim| {
        !matches!(
            claim.subject(),
            SymbolSubject::Function {
                rva: 0x1005 | 0x1018,
                ..
            }
        )
    }));
}

#[test]
fn seeds_thunks_from_runtime_starts_entry_point_and_local_exports() {
    let mut bytes = fixture();
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1040);
    put_u32(&mut bytes, file_offset(0x1144), 0x1080);
    bytes[file_offset(0x1000)..file_offset(0x1020)].fill(0x90);
    bytes[file_offset(0x1000)..file_offset(0x1002)].copy_from_slice(&[0xeb, 0x6e]);
    put_rel32_instruction(&mut bytes, 0x1040, 0xe9, 0x1060);
    put_rip_relative_instruction(&mut bytes, 0x1080, 0x25, 0x1260);

    let analysis = analyze_pe(&bytes).expect("valid thunk seed sources");
    assert_eq!(
        analysis.thunks,
        [
            PeThunk {
                rva: 0x1000,
                instruction_size: 2,
                target: PeControlFlowTarget::Function { rva: 0x1070 },
            },
            PeThunk {
                rva: 0x1040,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1060 },
            },
            PeThunk {
                rva: 0x1080,
                instruction_size: 6,
                target: PeControlFlowTarget::ImportIat { iat_rva: 0x1260 },
            },
        ]
    );
}

#[test]
fn invalid_decode_is_candidate_local_and_partially_backed_ranges_are_skipped() {
    let mut invalid = rtti_fixture();
    invalid[rtti_file_offset(0x1000)..rtti_file_offset(0x1002)].copy_from_slice(&[0xf0, 0x90]);
    put_rel32_instruction_at_rtti_rva(&mut invalid, 0x1020, 0xe8, 0x1040);
    invalid[rtti_file_offset(0x1040)] = 0xc3;
    let analysis = analyze_pe(&invalid).expect("one invalid candidate does not reject the PE");
    assert_eq!(analysis.direct_calls.len(), 1);
    assert_eq!(analysis.direct_calls[0].caller_rva, 0x1020);

    let mut partial = fixture();
    put_u32(&mut partial, SECTION_OFFSET + 8, 0x700);
    set_directory(&mut partial, 3, 0x1300, 24);
    let table = file_offset(0x1300);
    put_u32(&mut partial, table + 12, 0x15f0);
    put_u32(&mut partial, table + 16, 0x1610);
    put_u32(&mut partial, table + 20, 0x1354);
    put_rel32_instruction(&mut partial, 0x15f0, 0xe8, 0x1040);
    let analysis =
        analyze_pe(&partial).expect("virtual-only function tail is retained as metadata");
    assert_eq!(analysis.runtime_functions.len(), 2);
    assert!(analysis.direct_calls.is_empty());
    assert!(!analysis.code_recovery_scan_truncated);
}

#[test]
fn cfg_recovery_follows_only_reachable_blocks_and_terminates_backedges() {
    let analysis = analyze_pe(&cfg_recovery_fixture())
        .expect("valid PE with synthetic reachable control-flow blocks");

    assert!(!analysis.code_recovery_scan_truncated);
    assert!(!analysis.data_reference_scan_truncated);
    assert_eq!(
        analysis.direct_calls,
        [
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x1004,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1100 },
            },
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x1042,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1120 },
            },
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x1050,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1140 },
            },
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x1060,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1160 },
            },
            PeDirectCall {
                caller_rva: 0x1000,
                call_site_rva: 0x106d,
                instruction_size: 5,
                target: PeControlFlowTarget::Function { rva: 0x1170 },
            },
        ]
    );
    assert_eq!(
        analysis.data_references,
        [PeDataReference {
            caller_rva: 0x1000,
            instruction_rva: 0x1009,
            instruction_size: 7,
            target_rva: 0x2300,
        }]
    );

    assert!(
        analysis
            .direct_calls
            .iter()
            .all(|call| !matches!(call.call_site_rva, 0x1073 | 0x1180)),
        "post-RET and out-of-range blocks must not contribute calls",
    );
    assert!(
        analysis
            .data_references
            .iter()
            .all(|reference| !matches!(reference.instruction_rva, 0x1078 | 0x1185)),
        "post-RET and out-of-range blocks must not contribute data references",
    );

    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild reachable CFG graph"),
        analysis.symbol_graph
    );
    let encoded = serde_json::to_string(&analysis).expect("serialize CFG analysis");
    let decoded = serde_json::from_str(&encoded).expect("deserialize CFG analysis");
    assert_eq!(analysis, decoded);
}

#[test]
fn cfg_recovery_skips_interior_targets_but_keeps_canonical_fallthrough() {
    let analysis = analyze_pe(&cfg_interior_overlap_fixture())
        .expect("valid PE with an interior branch target");

    assert!(!analysis.code_recovery_scan_truncated);
    assert!(!analysis.data_reference_scan_truncated);
    assert_eq!(
        analysis.direct_calls,
        [PeDirectCall {
            caller_rva: 0x1000,
            call_site_rva: 0x100c,
            instruction_size: 5,
            target: PeControlFlowTarget::Function { rva: 0x1120 },
        }]
    );
    assert_eq!(
        analysis.data_references,
        [PeDataReference {
            caller_rva: 0x1000,
            instruction_rva: 0x1011,
            instruction_size: 7,
            target_rva: 0x2300,
        }]
    );
    assert!(
        analysis
            .direct_calls
            .iter()
            .all(|call| call.call_site_rva != 0x1004),
        "the fake E8 inside the MOV immediate must never be decoded",
    );
}

#[test]
fn cfg_recovery_stops_at_fred_returns() {
    for (prefix, name) in [(0xf2, "ERETS"), (0xf3, "ERETU")] {
        let analysis = analyze_pe(&fred_return_fixture(prefix))
            .unwrap_or_else(|error| panic!("valid PE with {name}: {error}"));

        assert!(
            analysis
                .direct_calls
                .iter()
                .all(|call| call.call_site_rva != 0x1004),
            "the fake E8 after {name} must remain unreachable",
        );
        assert!(!analysis.code_recovery_scan_truncated);
        assert!(!analysis.data_reference_scan_truncated);
    }
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
fn accepts_legacy_24_byte_msvc_base_class_descriptors_without_reading_pchd_bytes() {
    let analysis = analyze_pe(&legacy_base_class_rtti_fixture())
        .expect("valid PE with legacy 24-byte MSVC base descriptors");

    assert_eq!(analysis.msvc_rtti_vftables.len(), 3);
    let derived = &analysis.msvc_rtti_vftables[0];
    assert_eq!(derived.class_name, "Derived");
    assert_eq!(derived.base_classes.len(), 2);
    assert!(derived.base_classes.iter().all(|base| {
        base.attributes & 0x40 == 0 && base.class_hierarchy_descriptor_rva.is_none()
    }));
    let base = &analysis.msvc_rtti_vftables[1];
    assert_eq!(base.class_name, "Base");
    assert_eq!(base.base_classes[0].descriptor_rva, 0x2240);
    assert_eq!(base.base_classes[0].class_hierarchy_descriptor_rva, None);
    assert_eq!(
        derived.base_classes[1].descriptor_rva, base.base_classes[0].descriptor_rva,
        "a shared legacy descriptor remains canonical across hierarchy arrays",
    );
    assert_eq!(
        analysis
            .rebuild_symbol_graph()
            .expect("rebuild legacy RTTI graph"),
        analysis.symbol_graph
    );

    let json = serde_json::to_string(&analysis).expect("serialize legacy RTTI analysis");
    let decoded = serde_json::from_str(&json).expect("deserialize legacy RTTI analysis");
    assert_eq!(analysis, decoded);
}

#[test]
fn accepts_mixed_24_and_28_byte_msvc_base_class_descriptors() {
    let analysis = analyze_pe(&mixed_base_class_rtti_fixture())
        .expect("valid PE with mixed MSVC base-descriptor layouts");

    assert_eq!(analysis.msvc_rtti_vftables.len(), 3);
    let derived = &analysis.msvc_rtti_vftables[0];
    assert_eq!(
        derived.base_classes[0].class_hierarchy_descriptor_rva,
        Some(0x21c0)
    );
    assert_eq!(derived.base_classes[1].class_hierarchy_descriptor_rva, None);
    assert_eq!(
        analysis.msvc_rtti_vftables[1].base_classes[0].class_hierarchy_descriptor_rva,
        None
    );
}

#[test]
fn legacy_base_class_descriptor_requires_exactly_24_backed_bytes() {
    let exact = analyze_pe(&last_backed_legacy_base_class_rtti_fixture())
        .expect("exact final 24-byte legacy descriptor is fully backed");
    assert_eq!(exact.msvc_rtti_vftables.len(), 3);
    assert_eq!(
        exact.msvc_rtti_vftables[0].base_classes[1].descriptor_rva,
        0x23e8
    );
    assert_eq!(
        exact.msvc_rtti_vftables[0].base_classes[1].class_hierarchy_descriptor_rva,
        None
    );

    let mut truncated = last_backed_legacy_base_class_rtti_fixture();
    put_u32(&mut truncated, SECTION_OFFSET + 40 + 8, 0x3ff);
    let analysis = analyze_pe(&truncated).expect("truncated RTTI candidates are skipped safely");
    assert!(analysis.msvc_rtti_vftables.is_empty());

    let mut modern_at_legacy_boundary = last_backed_legacy_base_class_rtti_fixture();
    put_rtti_rva_u32(&mut modern_at_legacy_boundary, 0x23fc, 0x40);
    let analysis = analyze_pe(&modern_at_legacy_boundary)
        .expect("a 28-byte descriptor requires its full pCHD field");
    assert!(analysis.msvc_rtti_vftables.is_empty());
}

#[test]
fn validated_deserialization_rejects_base_descriptor_layout_bit_mismatches() {
    let legacy = analyze_pe(&legacy_base_class_rtti_fixture()).expect("valid legacy RTTI analysis");
    let legacy_value = serde_json::to_value(legacy).expect("serialize legacy RTTI analysis");

    let mut bit_without_field = legacy_value.clone();
    bit_without_field["msvc_rtti_vftables"][0]["base_classes"][0]["attributes"] =
        serde_json::json!(0x40);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(bit_without_field)
        .expect_err("BCD_HASPCHD requires a nested hierarchy RVA");
    assert!(error.to_string().contains("base-class attributes"));

    let mut field_without_bit = legacy_value;
    field_without_bit["msvc_rtti_vftables"][0]["base_classes"][0]["class_hierarchy_descriptor_rva"] =
        serde_json::json!(0x21c0);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(field_without_bit)
        .expect_err("a legacy descriptor cannot carry a hidden pCHD field");
    assert!(error.to_string().contains("base-class attributes"));

    let modern = analyze_pe(&rtti_fixture()).expect("valid modern RTTI analysis");
    let mut missing_modern_field = serde_json::to_value(modern).expect("serialize modern RTTI");
    missing_modern_field["msvc_rtti_vftables"][0]["base_classes"][0]["class_hierarchy_descriptor_rva"] =
        serde_json::Value::Null;
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_modern_field)
        .expect_err("a modern descriptor cannot omit its pCHD field");
    assert!(error.to_string().contains("base-class attributes"));
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
    put_rtti_rva_u32(&mut bytes, 0x2220 + 20, 0x80);

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
    assert_eq!(analysis.symbol_graph().claims().len(), 5);
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
fn validated_deserialization_rejects_tampered_code_recovery() {
    let analysis = analyze_pe(&code_recovery_fixture()).expect("valid recovered control flow");
    let original = serde_json::to_value(analysis).expect("serialize analysis");

    let mut wrong_size = original.clone();
    wrong_size["direct_calls"][0]["instruction_size"] = serde_json::json!(6);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(wrong_size)
        .expect_err("an internal E8 call must retain its exact size");
    assert!(error.to_string().contains("direct-call instruction size"));

    let mut unknown_iat = original.clone();
    unknown_iat["direct_calls"][1]["target"]["iat_rva"] = serde_json::json!(0x1270);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(unknown_iat)
        .expect_err("an indirect call must target an exact parsed IAT slot");
    assert!(error.to_string().contains("direct-call target"));

    let mut outside_runtime = original.clone();
    outside_runtime["direct_calls"][3]["call_site_rva"] = serde_json::json!(0x101f);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(outside_runtime)
        .expect_err("the decoded call must fit its matching runtime range");
    assert!(
        error
            .to_string()
            .contains("matching runtime-function range")
    );

    let mut unsorted = original.clone();
    unsorted["direct_calls"]
        .as_array_mut()
        .expect("direct-call array")
        .swap(0, 1);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(unsorted)
        .expect_err("retained calls must stay canonical");
    assert!(error.to_string().contains("strictly sorted"));

    let mut duplicate_site = original.clone();
    let calls = duplicate_site["direct_calls"]
        .as_array_mut()
        .expect("direct-call array");
    let mut duplicate = calls[0].clone();
    duplicate["target"]["rva"] = serde_json::json!(0x1041);
    calls.insert(1, duplicate);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(duplicate_site)
        .expect_err("one instruction cannot retain multiple targets");
    assert!(error.to_string().contains("one caller and call site"));

    let mut self_thunk = original.clone();
    self_thunk["thunks"][0]["target"]["rva"] = serde_json::json!(0x1040);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(self_thunk)
        .expect_err("an internal thunk cannot target itself");
    assert!(error.to_string().contains("must differ"));

    let mut unseeded_thunk = original.clone();
    unseeded_thunk["thunks"][2]["rva"] = serde_json::json!(0x10c0);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(unseeded_thunk)
        .expect_err("thunks must originate at retained candidates");
    assert!(error.to_string().contains("thunk source"));

    let mut interior_call_target = original.clone();
    interior_call_target["direct_calls"][0]["target"]["rva"] = serde_json::json!(0x1010);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(interior_call_target)
        .expect_err("a recovered call target cannot be a runtime-function interior label");
    assert!(error.to_string().contains("runtime-function metadata"));

    let mut interior_thunk_target = original.clone();
    interior_thunk_target["thunks"][0]["target"]["rva"] = serde_json::json!(0x1010);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(interior_thunk_target)
        .expect_err("a recovered jump target cannot be a runtime-function interior label");
    assert!(error.to_string().contains("runtime-function metadata"));

    let mut stale_graph = original;
    stale_graph["direct_calls"][1]["target"]["iat_rva"] = serde_json::json!(0x1268);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(stale_graph)
        .expect_err("the symbol graph must rebuild from retained control flow");
    assert!(error.to_string().contains("symbol graph"));
}

#[test]
fn validated_deserialization_rejects_missing_thunk_predecessors_and_disconnected_cycles() {
    let analysis = analyze_pe(&transitive_thunk_chain_fixture())
        .expect("valid analysis with transitive thunk recovery");
    let original = serde_json::to_value(analysis).expect("serialize transitive thunk analysis");

    let mut missing_predecessor = original.clone();
    missing_predecessor["thunks"]
        .as_array_mut()
        .expect("thunk array")
        .remove(0);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_predecessor)
        .expect_err("a transitive thunk source cannot outlive its retained predecessor");
    assert!(error.to_string().contains("thunk source"));
    assert!(error.to_string().contains("not reachable"));

    let mut disconnected_cycle = original;
    disconnected_cycle["thunks"] = serde_json::json!([
        {
            "rva": 0x10a0,
            "instruction_size": 5,
            "target": { "kind": "function", "rva": 0x10c0 }
        },
        {
            "rva": 0x10c0,
            "instruction_size": 5,
            "target": { "kind": "function", "rva": 0x10a0 }
        }
    ]);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(disconnected_cycle)
        .expect_err("a disconnected thunk cycle has no trusted root seed");
    assert!(error.to_string().contains("thunk source"));
    assert!(error.to_string().contains("not reachable"));
}

#[test]
fn validated_deserialization_rejects_tampered_read_only_pointer_calls() {
    let analysis = analyze_pe(&read_only_pointer_call_fixture())
        .expect("valid read-only pointer-call analysis");
    let original = serde_json::to_value(analysis).expect("serialize pointer-call analysis");

    let mut missing_reference = original.clone();
    missing_reference["data_references"]
        .as_array_mut()
        .expect("data-reference array")
        .remove(0);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(missing_reference)
        .expect_err("a pointer call cannot outlive its exact slot reference");
    assert!(error.to_string().contains("direct-call data reference"));

    let mut mismatched_reference = original.clone();
    mismatched_reference["data_references"][0]["target_rva"] = serde_json::json!(0x2302);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(mismatched_reference)
        .expect_err("a nearby data reference cannot satisfy the pointer-call dependency");
    assert!(error.to_string().contains("direct-call data reference"));

    let mut wrong_size = original.clone();
    wrong_size["direct_calls"][0]["instruction_size"] = serde_json::json!(5);
    wrong_size["data_references"][0]["instruction_size"] = serde_json::json!(5);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(wrong_size)
        .expect_err("a pointer call must retain its exact supported size");
    assert!(error.to_string().contains("direct-call instruction size"));

    let mut interior_target = original.clone();
    interior_target["direct_calls"][0]["target"]["rva"] = serde_json::json!(0x1008);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(interior_target)
        .expect_err("a pointer call cannot promote a runtime-function interior");
    assert!(error.to_string().contains("runtime-function metadata"));

    let mut writable_slot = original.clone();
    writable_slot["sections"][1]["characteristics"] = serde_json::json!(0xc000_0040_u32);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(writable_slot)
        .expect_err("a persisted pointer slot must remain read-only");
    assert!(error.to_string().contains("eight fully backed bytes"));

    let iat_analysis =
        analyze_pe(&rtti_fixture_with_rex_w_iat_control_flow()).expect("valid IAT analysis");
    let mut iat_collision = serde_json::to_value(iat_analysis).expect("serialize IAT analysis");
    iat_collision["direct_calls"][0]["target"] = serde_json::json!({
        "kind": "function-pointer",
        "slot_rva": 0x2340,
        "rva": 0x1020,
    });
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(iat_collision)
        .expect_err("IAT membership must take precedence in persisted models");
    assert!(error.to_string().contains("import-address-table slot"));
}

#[test]
fn validated_deserialization_rejects_tampered_read_only_pointer_thunks() {
    let analysis = analyze_pe(&read_only_pointer_thunk_fixture())
        .expect("valid read-only pointer-thunk analysis");
    let original = serde_json::to_value(analysis).expect("serialize pointer-thunk analysis");

    let mut wrong_size = original.clone();
    wrong_size["thunks"][0]["instruction_size"] = serde_json::json!(5);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(wrong_size)
        .expect_err("a pointer thunk must retain its exact supported size");
    assert!(error.to_string().contains("thunk instruction size"));

    let mut interior_target = original.clone();
    interior_target["thunks"][0]["target"]["rva"] = serde_json::json!(0x1008);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(interior_target)
        .expect_err("a pointer thunk cannot promote a runtime-function interior");
    assert!(error.to_string().contains("runtime-function metadata"));

    let mut self_target = original.clone();
    self_target["thunks"][0]["target"]["rva"] = serde_json::json!(0x1000);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(self_target)
        .expect_err("a pointer thunk cannot target its own source");
    assert!(error.to_string().contains("must differ"));

    let mut writable_slot = original.clone();
    writable_slot["sections"][1]["characteristics"] = serde_json::json!(0xc000_0040_u32);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(writable_slot)
        .expect_err("a persisted pointer-thunk slot must remain read-only");
    assert!(error.to_string().contains("eight fully backed bytes"));

    let iat_analysis =
        analyze_pe(&rtti_fixture_with_rex_w_iat_control_flow()).expect("valid IAT analysis");
    let mut iat_collision = serde_json::to_value(iat_analysis).expect("serialize IAT analysis");
    iat_collision["thunks"][0]["target"] = serde_json::json!({
        "kind": "function-pointer",
        "slot_rva": 0x2340,
        "rva": 0x1040,
    });
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(iat_collision)
        .expect_err("IAT membership must take precedence for persisted pointer thunks");
    assert!(error.to_string().contains("import-address-table slot"));
}

#[test]
fn validated_deserialization_rejects_call_next_outside_runtime_coverage() {
    let analysis = analyze_pe(&control_flow_suppression_fixture())
        .expect("valid analysis with a suppressed call-next encoding");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    let forged_call = serde_json::to_value(PeDirectCall {
        caller_rva: 0x1000,
        call_site_rva: 0x1000,
        instruction_size: 5,
        target: PeControlFlowTarget::Function { rva: 0x1005 },
    })
    .expect("serialize forged call-next record");
    value["direct_calls"]
        .as_array_mut()
        .expect("direct-call array")
        .insert(0, forged_call);

    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect_err("a forged call-next model must fail validation before graph rebuild");
    assert!(error.to_string().contains("call-next"));
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
    assert_eq!(decoded.symbol_graph.claims().len(), 5);
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

fn runtime_function_pair_fixture(first: (u32, u32), second: (u32, u32)) -> Vec<u8> {
    let mut bytes = fixture();
    set_directory(&mut bytes, 3, 0x1300, 24);
    let table = file_offset(0x1300);
    put_u32(&mut bytes, table, first.0);
    put_u32(&mut bytes, table + 4, first.1);
    put_u32(&mut bytes, table + 8, 0x1350);
    put_u32(&mut bytes, table + 12, second.0);
    put_u32(&mut bytes, table + 16, second.1);
    put_u32(&mut bytes, table + 20, 0x1360);
    bytes
}

#[test]
fn raw_runtime_function_table_rejects_duplicate_decreasing_and_overlapping_ranges() {
    let cases = [
        (
            "duplicate",
            (0x1000, 0x1020),
            (0x1000, 0x1020),
            "table order",
        ),
        (
            "decreasing",
            (0x1020, 0x1030),
            (0x1000, 0x1010),
            "table order",
        ),
        (
            "partial overlap",
            (0x1000, 0x1020),
            (0x1010, 0x1030),
            "overlap",
        ),
        ("contained", (0x1000, 0x1040), (0x1010, 0x1020), "overlap"),
    ];

    for (label, first, second, expected) in cases {
        let error = match analyze_pe(&runtime_function_pair_fixture(first, second)) {
            Ok(_) => panic!("{label} runtime-function ranges must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(expected),
            "{label}: unexpected error: {error}"
        );
    }
}

#[test]
fn deserialized_runtime_function_table_rejects_duplicate_decreasing_and_overlapping_ranges() {
    let adjacent = analyze_pe(&runtime_function_pair_fixture(
        (0x1000, 0x1020),
        (0x1020, 0x1040),
    ))
    .expect("adjacent source table is valid");
    let cases = [
        (
            "duplicate",
            (0x1000, 0x1020),
            (0x1000, 0x1020),
            "table order",
        ),
        (
            "decreasing",
            (0x1020, 0x1030),
            (0x1000, 0x1010),
            "table order",
        ),
        (
            "partial overlap",
            (0x1000, 0x1020),
            (0x1010, 0x1030),
            "overlap",
        ),
        ("contained", (0x1000, 0x1040), (0x1010, 0x1020), "overlap"),
    ];

    for (label, first, second, expected) in cases {
        let mut value = serde_json::to_value(&adjacent).expect("serialize adjacent analysis");
        value["runtime_functions"][0]["begin_rva"] = serde_json::json!(first.0);
        value["runtime_functions"][0]["end_rva"] = serde_json::json!(first.1);
        value["runtime_functions"][1]["begin_rva"] = serde_json::json!(second.0);
        value["runtime_functions"][1]["end_rva"] = serde_json::json!(second.1);
        let error = match serde_json::from_value::<resymbol_analysis::PeAnalysis>(value) {
            Ok(_) => panic!("{label} runtime-function ranges must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(expected),
            "{label}: unexpected error: {error}"
        );
    }
}

#[test]
fn raw_and_deserialized_runtime_function_tables_accept_adjacent_ranges_in_source_order() {
    let analysis = analyze_pe(&runtime_function_pair_fixture(
        (0x1000, 0x1020),
        (0x1020, 0x1040),
    ))
    .expect("adjacent runtime-function ranges are valid");
    assert_eq!(analysis.runtime_functions.len(), 2);
    assert_eq!(analysis.runtime_functions[0].table_index, 0);
    assert_eq!(analysis.runtime_functions[1].table_index, 1);
    assert_eq!(analysis.runtime_functions[1].begin_rva, 0x1020);

    let decoded = serde_json::from_value::<resymbol_analysis::PeAnalysis>(
        serde_json::to_value(&analysis).expect("serialize adjacent analysis"),
    )
    .expect("deserialize adjacent analysis");
    assert_eq!(decoded.runtime_functions, analysis.runtime_functions);
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
    put_u32(&mut bytes, table + 4, 0x1010);
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
fn classifies_executable_local_exports_without_unwind_metadata_as_function_candidates() {
    let mut bytes = fixture();
    put_u32(&mut bytes, file_offset(0x1144), 0x1040);
    put_u16(&mut bytes, file_offset(0x1152), 1);

    let analysis = analyze_pe(&bytes).expect("valid executable export candidate");
    assert!(analysis.symbol_graph.claims().iter().any(|claim| matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Function {
                rva: 0x1040,
                size: None,
                ..
            },
            SymbolAssertion::Name { name },
        ) if name == "Alias"
    )));
    assert!(analysis.symbol_graph.claims().iter().any(|claim| matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Function {
                rva: 0x1040,
                size: None,
                ..
            },
            SymbolAssertion::FunctionEntry,
        )
    )));
}

#[test]
fn classifies_non_executable_exports_as_globals() {
    let mut bytes = fixture();
    set_directory(&mut bytes, 3, 0, 0);
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x4000_0040);

    let analysis = analyze_pe(&bytes).expect("valid data export");
    let export_name_claims = analysis
        .symbol_graph
        .claims()
        .iter()
        .filter(|claim| claim.provenance().method == "pe-export-directory")
        .collect::<Vec<_>>();
    assert_eq!(export_name_claims.len(), 2);
    assert!(export_name_claims.iter().all(|claim| matches!(
        (claim.subject(), claim.assertion()),
        (
            SymbolSubject::Global { rva: 0x1000, .. },
            SymbolAssertion::Name { .. },
        )
    )));
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
    assert_eq!(analysis.symbol_graph.claims().len(), 2);
    assert!(analysis.symbol_graph.claims().iter().all(|claim| {
        !matches!(
            claim.provenance().method.as_str(),
            "pe-export-directory" | "pe-export-function-candidate"
        )
    }));
    assert!(
        analysis
            .symbol_graph
            .claims()
            .iter()
            .any(|claim| matches!(claim.assertion(), SymbolAssertion::FunctionBoundary { .. }))
    );
    assert!(
        analysis
            .symbol_graph
            .claims()
            .iter()
            .any(|claim| claim.provenance().method == "pe-entry-point")
    );
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
fn enforces_declared_pe_limits_before_allocating() {
    #[derive(Debug)]
    enum ExpectedError {
        PeHeaderOffset {
            offset: u32,
            limit: u32,
        },
        LimitExceeded {
            kind: &'static str,
            count: u64,
            limit: u64,
        },
    }

    struct Case {
        name: &'static str,
        mutate: fn(&mut [u8]),
        expected: ExpectedError,
    }

    fn exceed_pe_header_offset(bytes: &mut [u8]) {
        put_u32(bytes, 0x3c, 16_777_217);
    }

    fn exceed_data_directory_count(bytes: &mut [u8]) {
        put_u32(bytes, OPTIONAL_OFFSET + 108, 17);
    }

    fn exceed_import_directory_size(bytes: &mut [u8]) {
        set_directory(bytes, 1, 0x1200, 67_108_865);
    }

    fn exceed_import_descriptor_count(bytes: &mut [u8]) {
        set_directory(bytes, 1, 0x1200, 4_098 * 20);
    }

    fn exceed_delay_import_descriptor_count(bytes: &mut [u8]) {
        set_directory(bytes, 13, 0x1400, 4_098 * 32);
    }

    fn exceed_export_directory_size(bytes: &mut [u8]) {
        set_directory(bytes, 0, 0x1100, 67_108_865);
    }

    fn exceed_export_function_count(bytes: &mut [u8]) {
        put_u32(bytes, file_offset(0x1100) + 20, 65_537);
    }

    fn exceed_export_name_count(bytes: &mut [u8]) {
        put_u32(bytes, file_offset(0x1100) + 24, 65_537);
    }

    fn exceed_exception_record_count(bytes: &mut [u8]) {
        set_directory(bytes, 3, 0x1300, 262_145 * 12);
    }

    fn exceed_exception_directory_size(bytes: &mut [u8]) {
        set_directory(bytes, 3, 0x1300, 67_108_865);
    }

    let cases = [
        Case {
            name: "PE header offset",
            mutate: exceed_pe_header_offset,
            expected: ExpectedError::PeHeaderOffset {
                offset: 16_777_217,
                limit: 16_777_216,
            },
        },
        Case {
            name: "data-directory count",
            mutate: exceed_data_directory_count,
            expected: ExpectedError::LimitExceeded {
                kind: "data-directory",
                count: 17,
                limit: 16,
            },
        },
        Case {
            name: "import-directory byte size",
            mutate: exceed_import_directory_size,
            expected: ExpectedError::LimitExceeded {
                kind: "import-directory byte",
                count: 67_108_865,
                limit: 67_108_864,
            },
        },
        Case {
            name: "import descriptor count",
            mutate: exceed_import_descriptor_count,
            expected: ExpectedError::LimitExceeded {
                kind: "import-library descriptor",
                count: 4_098,
                limit: 4_097,
            },
        },
        Case {
            name: "delay-import descriptor count",
            mutate: exceed_delay_import_descriptor_count,
            expected: ExpectedError::LimitExceeded {
                kind: "delay-import-library descriptor",
                count: 4_098,
                limit: 4_097,
            },
        },
        Case {
            name: "export-directory byte size",
            mutate: exceed_export_directory_size,
            expected: ExpectedError::LimitExceeded {
                kind: "export-directory byte",
                count: 67_108_865,
                limit: 67_108_864,
            },
        },
        Case {
            name: "export function count",
            mutate: exceed_export_function_count,
            expected: ExpectedError::LimitExceeded {
                kind: "export function",
                count: 65_537,
                limit: 65_536,
            },
        },
        Case {
            name: "export name count",
            mutate: exceed_export_name_count,
            expected: ExpectedError::LimitExceeded {
                kind: "export name",
                count: 65_537,
                limit: 65_536,
            },
        },
        Case {
            name: "exception-directory byte size",
            mutate: exceed_exception_directory_size,
            expected: ExpectedError::LimitExceeded {
                kind: "exception-directory byte",
                count: 67_108_865,
                limit: 67_108_864,
            },
        },
        Case {
            name: "exception record count",
            mutate: exceed_exception_record_count,
            expected: ExpectedError::LimitExceeded {
                kind: "runtime function",
                count: 262_145,
                limit: 262_144,
            },
        },
    ];

    for case in cases {
        let mut bytes = fixture();
        (case.mutate)(&mut bytes);

        match (analyze_pe(&bytes), case.expected) {
            (
                Err(AnalysisError::PeHeaderOffsetLimit { offset, limit }),
                ExpectedError::PeHeaderOffset {
                    offset: expected_offset,
                    limit: expected_limit,
                },
            ) => {
                assert_eq!(offset, expected_offset, "{} offset", case.name);
                assert_eq!(limit, expected_limit, "{} limit", case.name);
            }
            (
                Err(AnalysisError::LimitExceeded { kind, count, limit }),
                ExpectedError::LimitExceeded {
                    kind: expected_kind,
                    count: expected_count,
                    limit: expected_limit,
                },
            ) => assert_eq!(
                (kind, count, limit),
                (expected_kind, expected_count, expected_limit),
                "{}",
                case.name
            ),
            (Ok(_), expected) => {
                panic!(
                    "{} unexpectedly succeeded; expected {expected:?}",
                    case.name
                )
            }
            (Err(error), expected) => {
                panic!("{} returned {error:?}; expected {expected:?}", case.name)
            }
        }
    }
}

#[test]
fn enforces_raw_and_validated_pe_string_limits() {
    const LONG_NAME_RVA: u32 = 0x1400;
    const STRING_SCAN_LIMIT: usize = 4_096;
    const EXPANDED_SECTION_SIZE: u32 = 0x1600;

    let mut unterminated = fixture();
    unterminated.resize(
        RAW_OFFSET + usize::try_from(EXPANDED_SECTION_SIZE).expect("fixture section size"),
        0,
    );
    put_u32(&mut unterminated, OPTIONAL_OFFSET + 56, 0x3000);
    put_u32(&mut unterminated, SECTION_OFFSET + 8, EXPANDED_SECTION_SIZE);
    put_u32(
        &mut unterminated,
        SECTION_OFFSET + 16,
        EXPANDED_SECTION_SIZE,
    );
    put_u32(&mut unterminated, file_offset(0x1200) + 12, LONG_NAME_RVA);
    let name_offset = file_offset(LONG_NAME_RVA);
    unterminated[name_offset..name_offset + STRING_SCAN_LIMIT].fill(b'a');
    unterminated[name_offset + STRING_SCAN_LIMIT] = 0;

    let error = analyze_pe(&unterminated).expect_err("the raw C-string scan is bounded");
    assert!(matches!(
        error,
        AnalysisError::UnterminatedString {
            context: "import DLL name",
            rva: LONG_NAME_RVA,
            limit: STRING_SCAN_LIMIT,
        }
    ));

    let mut analysis = analyze_pe(&fixture()).expect("the base fixture is valid");
    analysis.export_library_name = Some("a".repeat(STRING_SCAN_LIMIT));
    let error = analysis
        .validate()
        .expect_err("a decoded string cannot consume the NUL-inclusive scan limit");
    assert!(matches!(
        error,
        AnalysisError::LimitExceeded {
            kind: "export DLL-name byte",
            count: 4_096,
            limit: 4_095,
        }
    ));
}

#[test]
fn recognizes_elf_magic_but_still_rejects_unknown_formats_without_guessing() {
    assert!(matches!(
        analyze_bytes(b"\x7fELFtest"),
        Err(AnalysisError::Truncated {
            context: "ELF32 header",
            ..
        })
    ));
    assert!(matches!(
        analyze_bytes(b"\x7fXYZtest"),
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
fn session_enforces_pe_section_policy_for_plugin_strings_and_data_references() {
    let base_analysis = analyze_bytes(&string_and_data_reference_fixture())
        .expect("valid PE with eligible code and data");
    let binary = base_analysis.identity().id.clone();
    let producer = || ClaimProducer::Plugin {
        id: plugin_id(),
        version: "1.2.3".to_owned(),
    };
    let string_claim = plugin_claim(
        SymbolSubject::Global {
            binary: binary.clone(),
            rva: 0x2300,
            size: Some(16),
        },
        SymbolAssertion::StringLiteral {
            encoding: resymbol_core::StringEncoding::Ascii,
            value: "Recovered ASCII".to_owned(),
        },
        producer(),
        Some("run-001"),
    );
    let reference_claim = plugin_claim(
        SymbolSubject::Function {
            binary: binary.clone(),
            rva: 0x1000,
            size: Some(0x10),
        },
        SymbolAssertion::DataReference {
            instruction_rva: 0x1000,
            instruction_size: 7,
            target_rva: 0x2300,
        },
        producer(),
        Some("run-001"),
    );
    AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 2)],
        vec![string_claim, reference_claim],
    )
    .expect("eligible plugin string and data reference are accepted");

    let executable_string = plugin_claim(
        SymbolSubject::Global {
            binary: binary.clone(),
            rva: 0x1000,
            size: Some(16),
        },
        SymbolAssertion::StringLiteral {
            encoding: resymbol_core::StringEncoding::Ascii,
            value: "Recovered ASCII".to_owned(),
        },
        producer(),
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![executable_string],
    )
    .expect_err("plugin strings must remain in eligible PE data");
    assert!(matches!(
        error,
        SessionValidationError::StringLiteralUnsupportedSection { index: 0 }
    ));

    let executable_target = plugin_claim(
        SymbolSubject::Function {
            binary: binary.clone(),
            rva: 0x1000,
            size: Some(0x10),
        },
        SymbolAssertion::DataReference {
            instruction_rva: 0x1000,
            instruction_size: 7,
            target_rva: 0x1000,
        },
        producer(),
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![executable_target],
    )
    .expect_err("plugin data-reference targets must remain in eligible PE data");
    assert!(matches!(
        error,
        SessionValidationError::DataReferenceTargetNotData { index: 0 }
    ));

    let data_source = plugin_claim(
        SymbolSubject::Function {
            binary,
            rva: 0x2300,
            size: Some(0x20),
        },
        SymbolAssertion::DataReference {
            instruction_rva: 0x2300,
            instruction_size: 7,
            target_rva: 0x2320,
        },
        producer(),
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        base_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![data_source],
    )
    .expect_err("plugin data-reference instructions must remain in executable PE data");
    assert!(matches!(
        error,
        SessionValidationError::DataReferenceSourceNotExecutable { index: 0 }
    ));
}

#[test]
fn session_validates_read_only_pointer_call_targets_slots_and_companions() {
    let base_analysis = analyze_bytes(&read_only_pointer_call_fixture())
        .expect("valid PE with a base pointer-call companion");
    let binary = base_analysis.identity().id.clone();
    let producer = || ClaimProducer::Plugin {
        id: plugin_id(),
        version: "1.2.3".to_owned(),
    };
    let pointer_claim = |call_site_rva, slot_rva, rva| {
        plugin_claim(
            SymbolSubject::Function {
                binary: binary.clone(),
                rva: 0x1000,
                size: Some(0x10),
            },
            SymbolAssertion::DirectCall {
                call_site_rva,
                target: ControlFlowTarget::FunctionPointer { slot_rva, rva },
            },
            producer(),
            Some("run-001"),
        )
    };

    AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![pointer_claim(0x1000, 0x2301, 0x1020)],
    )
    .expect("a valid base data-reference claim may satisfy the pointer-call dependency");

    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![pointer_claim(0x1001, 0x2301, 0x1020)],
    )
    .expect_err("a different call site cannot borrow the base companion");
    assert!(matches!(
        error,
        SessionValidationError::FunctionPointerMissingDataReference {
            index: 0,
            slot_rva: 0x2301,
        }
    ));

    let error = AnalysisSession::new(
        base_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![pointer_claim(0x1000, 0x2301, 0x2300)],
    )
    .expect_err("the resolved pointer target must be executable");
    assert!(matches!(
        error,
        SessionValidationError::FunctionPointerTargetNotExecutable { index: 0 }
    ));

    let mut writable_bytes = read_only_pointer_call_fixture();
    put_u32(&mut writable_bytes, SECTION_OFFSET + 40 + 36, 0xc000_0040);
    let writable_analysis = analyze_bytes(&writable_bytes)
        .expect("writable pointer slots remain valid ordinary data references");
    let writable_claim = plugin_claim(
        SymbolSubject::Function {
            binary: writable_analysis.identity().id.clone(),
            rva: 0x1000,
            size: Some(0x10),
        },
        SymbolAssertion::DirectCall {
            call_site_rva: 0x1000,
            target: ControlFlowTarget::FunctionPointer {
                slot_rva: 0x2301,
                rva: 0x1020,
            },
        },
        producer(),
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        writable_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![writable_claim],
    )
    .expect_err("plugin pointer slots must be read-only");
    assert!(matches!(
        error,
        SessionValidationError::FunctionPointerSlotNotReadOnly { index: 0 }
    ));

    let iat_analysis = analyze_bytes(&rtti_fixture_with_rex_w_iat_control_flow())
        .expect("valid PE with parsed imports");
    let iat_binary = iat_analysis.identity().id.clone();
    let iat_claim = plugin_claim(
        SymbolSubject::Function {
            binary: iat_binary,
            rva: 0x1000,
            size: Some(0x10),
        },
        SymbolAssertion::DirectCall {
            call_site_rva: 0x1000,
            target: ControlFlowTarget::FunctionPointer {
                slot_rva: 0x2340,
                rva: 0x1020,
            },
        },
        producer(),
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        iat_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![iat_claim],
    )
    .expect_err("a plugin cannot reinterpret an exact IAT slot as a function pointer");
    assert!(matches!(
        error,
        SessionValidationError::FunctionPointerSlotIsImportIat {
            index: 0,
            slot_rva: 0x2340,
        }
    ));
}

#[test]
fn session_validates_pointer_thunks_without_requiring_data_reference_companions() {
    let base_analysis = analyze_bytes(&single_pointer_thunk_fixture(
        0x2301,
        RTTI_IMAGE_BASE + 0x1060,
    ))
    .expect("valid PE with a metadata-only pointer-thunk seed");
    let BinaryAnalysis::Pe(base_pe) = &base_analysis else {
        panic!("synthetic pointer-thunk fixture must parse as PE");
    };
    assert!(
        base_pe.data_references.is_empty(),
        "the seeded thunk must prove that no runtime-sweep companion is required"
    );
    let binary = base_analysis.identity().id.clone();
    let producer = || ClaimProducer::Plugin {
        id: plugin_id(),
        version: "1.2.3".to_owned(),
    };
    let pointer_claim = |subject_rva, slot_rva, rva| {
        plugin_claim(
            SymbolSubject::Function {
                binary: binary.clone(),
                rva: subject_rva,
                size: Some(0x10),
            },
            SymbolAssertion::ThunkTarget {
                target: ControlFlowTarget::FunctionPointer { slot_rva, rva },
            },
            producer(),
            Some("run-001"),
        )
    };

    AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![pointer_claim(0x1040, 0x2301, 0x1060)],
    )
    .expect("a valid pointer thunk needs no same-site data-reference claim");

    let error = AnalysisSession::new(
        base_analysis.clone(),
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![pointer_claim(0x1040, 0x2301, 0x2300)],
    )
    .expect_err("a pointer-thunk endpoint must be executable");
    assert!(matches!(
        error,
        SessionValidationError::FunctionPointerTargetNotExecutable { index: 0 }
    ));

    let error = AnalysisSession::new(
        base_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![pointer_claim(0x1040, 0x2301, 0x1040)],
    )
    .expect_err("a pointer thunk cannot target itself");
    assert!(matches!(
        error,
        SessionValidationError::ThunkSelfTarget {
            index: 0,
            rva: 0x1040,
        }
    ));

    let mut writable_bytes = single_pointer_thunk_fixture(0x2301, RTTI_IMAGE_BASE + 0x1060);
    put_u32(&mut writable_bytes, SECTION_OFFSET + 40 + 36, 0xc000_0040);
    let writable_analysis = analyze_bytes(&writable_bytes)
        .expect("writable pointer slots remain analyzable as ordinary data");
    let writable_claim = plugin_claim(
        SymbolSubject::Function {
            binary: writable_analysis.identity().id.clone(),
            rva: 0x1040,
            size: Some(0x10),
        },
        SymbolAssertion::ThunkTarget {
            target: ControlFlowTarget::FunctionPointer {
                slot_rva: 0x2301,
                rva: 0x1060,
            },
        },
        producer(),
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        writable_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![writable_claim],
    )
    .expect_err("plugin pointer-thunk slots must be read-only");
    assert!(matches!(
        error,
        SessionValidationError::FunctionPointerSlotNotReadOnly { index: 0 }
    ));

    let iat_analysis = analyze_bytes(&rtti_fixture_with_rex_w_iat_control_flow())
        .expect("valid PE with parsed imports");
    let iat_claim = plugin_claim(
        SymbolSubject::Function {
            binary: iat_analysis.identity().id.clone(),
            rva: 0x1020,
            size: Some(0x10),
        },
        SymbolAssertion::ThunkTarget {
            target: ControlFlowTarget::FunctionPointer {
                slot_rva: 0x2340,
                rva: 0x1040,
            },
        },
        producer(),
        Some("run-001"),
    );
    let error = AnalysisSession::new(
        iat_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![iat_claim],
    )
    .expect_err("a plugin cannot reinterpret an IAT thunk slot as a function pointer");
    assert!(matches!(
        error,
        SessionValidationError::FunctionPointerSlotIsImportIat {
            index: 0,
            slot_rva: 0x2340,
        }
    ));

    let data_source_analysis = analyze_bytes(&single_pointer_thunk_fixture(
        0x2301,
        RTTI_IMAGE_BASE + 0x1060,
    ))
    .expect("valid PE for a non-executable plugin source rejection");
    let error = AnalysisSession::new(
        data_source_analysis,
        vec![plugin_run(PluginRunStatus::Succeeded, 1)],
        vec![pointer_claim(0x2300, 0x2301, 0x1060)],
    )
    .expect_err("a plugin pointer thunk must originate in executable PE data");
    assert!(matches!(
        error,
        SessionValidationError::FunctionPointerThunkSourceNotExecutable { index: 0 }
    ));
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
