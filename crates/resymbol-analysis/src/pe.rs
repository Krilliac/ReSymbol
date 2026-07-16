use std::{
    collections::{BTreeMap, BTreeSet},
    str,
};

use resymbol_core::{
    BinaryFormat, BinaryId, BinaryIdentity, ClaimProducer, ClaimProvenance, Confidence,
    ControlFlowTarget, Evidence, EvidenceKind, SymbolAssertion, SymbolClaim, SymbolGraph,
    SymbolSubject,
};

use crate::{
    AnalysisError, CoffHeader, DataDirectory, ImportTarget, MsvcRttiVftable, PeAnalysis,
    PeControlFlowTarget, PeDataDirectories, PeDataReference, PeDelayImportLibrary, PeDirectCall,
    PeExport, PeExportName, PeGuardAddressTakenIatEntry, PeGuardCfFunction,
    PeGuardEhContinuationTarget, PeGuardLongJumpTarget, PeImport, PeImportLibrary,
    PeLoadConfigGuardMemcpyAnchor, PeLoadConfigSecurityAnchors, PeLoadConfigXfgAnchors,
    PeRecoveredString, PeSection, PeThunk, PeTlsCallback, RuntimeFunction,
    code_recovery::{
        CodeRecoveryInput, recover_code, validate_code_recovery, validate_data_references,
    },
    msvc_rtti::{parse_msvc_rtti, validate_msvc_rtti},
    string_recovery::{recover_strings, validate_recovered_strings},
};

const DOS_HEADER_SIZE: usize = 64;
const DOS_HEADER_SIZE_U32: u32 = 64;
const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
const PE_AND_COFF_HEADER_SIZE_U64: u64 = 24;
const OPTIONAL_HEADER_MIN_SIZE: usize = 112;
const SECTION_HEADER_SIZE: usize = 40;
const SECTION_HEADER_SIZE_U64: u64 = 40;
const X64_PAGE_SIZE: u32 = 0x1000;
const MIN_STANDARD_FILE_ALIGNMENT: u32 = 0x200;
const MAX_FILE_ALIGNMENT: u32 = 0x1_0000;
const DATA_DIRECTORY_SIZE: usize = 8;
const DEBUG_DIRECTORY_ENTRY_SIZE: usize = 28;
const DEBUG_DIRECTORY_ENTRY_SIZE_U32: u32 = 28;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const IMPORT_DESCRIPTOR_SIZE_U32: u32 = 20;
const DELAY_IMPORT_DESCRIPTOR_SIZE: usize = 32;
const DELAY_IMPORT_DESCRIPTOR_SIZE_U32: u32 = 32;
const RUNTIME_FUNCTION_SIZE: usize = 12;
const RUNTIME_FUNCTION_SIZE_U32: u32 = 12;
const TLS_DIRECTORY_SIZE_U32: u32 = 40;
const LOAD_CONFIG_SECURITY_ANCHOR_SIZE_U32: u32 = 8;
const LOAD_CONFIG_SECURITY_COOKIE_FIELDS_SIZE_U32: u32 = 96;
const LOAD_CONFIG_SECURITY_COOKIE_OFFSET: usize = 88;
const LOAD_CONFIG_GUARD_CF_CHECK_POINTER_FIELDS_SIZE_U32: u32 = 120;
const LOAD_CONFIG_GUARD_CF_CHECK_POINTER_OFFSET: usize = 112;
const LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE_U32: u32 = 128;
const LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_OFFSET: usize = 120;
const LOAD_CONFIG_GUARD_FIELDS_SIZE_U32: u32 = 148;
const LOAD_CONFIG_GUARD_CF_FUNCTION_TABLE_OFFSET: usize = 128;
const LOAD_CONFIG_GUARD_CF_FUNCTION_COUNT_OFFSET: usize = 136;
const LOAD_CONFIG_GUARD_FLAGS_OFFSET: usize = 144;
const LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_FIELDS_SIZE_U32: u32 = 176;
const LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_TABLE_OFFSET: usize = 160;
const LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_COUNT_OFFSET: usize = 168;
const LOAD_CONFIG_GUARD_LONG_JUMP_FIELDS_SIZE_U32: u32 = 192;
const LOAD_CONFIG_GUARD_LONG_JUMP_TABLE_OFFSET: usize = 176;
const LOAD_CONFIG_GUARD_LONG_JUMP_COUNT_OFFSET: usize = 184;
const LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE_U32: u32 = 280;
const LOAD_CONFIG_GUARD_EH_CONTINUATION_TABLE_OFFSET: usize = 264;
const LOAD_CONFIG_GUARD_EH_CONTINUATION_COUNT_OFFSET: usize = 272;
const LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_FIELDS_SIZE_U32: u32 = 288;
const LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_OFFSET: usize = 280;
const LOAD_CONFIG_GUARD_XFG_DISPATCH_POINTER_FIELDS_SIZE_U32: u32 = 296;
const LOAD_CONFIG_GUARD_XFG_DISPATCH_POINTER_OFFSET: usize = 288;
const LOAD_CONFIG_GUARD_XFG_TABLE_DISPATCH_POINTER_FIELDS_SIZE_U32: u32 = 304;
const LOAD_CONFIG_GUARD_XFG_TABLE_DISPATCH_POINTER_OFFSET: usize = 296;
const LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE_U32: u32 = 312;
const LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_OFFSET: usize = 304;
const LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE_U32: u32 = 320;
const LOAD_CONFIG_GUARD_MEMCPY_POINTER_OFFSET: usize = 312;

const MACHINE_AMD64: u16 = 0x8664;
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x020b;
const IMPORT_BY_ORDINAL_64: u64 = 1_u64 << 63;
const DELAY_IMPORT_ATTRIBUTE_RVA: u32 = 1;
const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
const IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
const IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
const IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xf000_0000;
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;
const GUARD_CF_EXPORT_SUPPRESSED_ALIGNMENT: u32 = 16;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

const MAX_PE_HEADER_OFFSET: u32 = 16 * 1024 * 1024;
const MAX_SECTIONS: u64 = 96;
const MAX_DATA_DIRECTORIES: u64 = 16;
const MAX_DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPORT_LIBRARIES: u64 = 4_096;
const MAX_IMPORT_DESCRIPTORS: u64 = MAX_IMPORT_LIBRARIES + 1;
const MAX_IMPORT_SYMBOLS: u64 = 65_536;
const MAX_IMPORT_NAME_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXPORT_FUNCTIONS: u64 = 65_536;
const MAX_EXPORT_NAMES: u64 = 65_536;
const MAX_EXPORT_NAME_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RUNTIME_FUNCTIONS: u64 = 262_144;
const MAX_GUARD_CF_FUNCTIONS: u64 = 262_144;
const MAX_GUARD_ADDRESS_TAKEN_IAT_ENTRIES: u64 = 262_144;
const MAX_GUARD_LONG_JUMP_TARGETS: u64 = 262_144;
const MAX_GUARD_EH_CONTINUATION_TARGETS: u64 = 262_144;
const MAX_TLS_CALLBACKS: u64 = 4_096;
const MAX_DEBUG_DIRECTORY_ENTRIES: u64 = 4_096;
const MAX_CODEVIEW_RECORD_BYTES: u64 = 64 * 1_024;
const MAX_CODEVIEW_PATH_BYTES: u64 = 4_096;
const MAX_STRING_BYTES: usize = 4_096;
const MAX_STRING_CONTENT_BYTES: u64 = 4_095;
const MAX_PROVENANCE_VERSION_BYTES: usize = 128;

const DIRECT_CALL_EVIDENCE_SUMMARY: &str = concat!(
    "exact supported x64 call encoding observed during a bounded ",
    "control-flow-guided traversal of a file-backed runtime-function range",
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
const LEGACY_DIRECT_CALL_EVIDENCE_SUMMARY: &str = concat!(
    "exact supported x64 call encoding observed during a bounded linear sweep ",
    "of a file-backed runtime-function range",
);

const EXPORT_DIRECTORY_INDEX: usize = 0;
const IMPORT_DIRECTORY_INDEX: usize = 1;
const EXCEPTION_DIRECTORY_INDEX: usize = 3;
const DEBUG_DIRECTORY_INDEX: usize = 6;
const TLS_DIRECTORY_INDEX: usize = 9;
const LOAD_CONFIG_DIRECTORY_INDEX: usize = 10;
const DELAY_IMPORT_DIRECTORY_INDEX: usize = 13;

const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const CODEVIEW_RSDS_HEADER_SIZE: usize = 24;

/// Exact byte-backed PE metadata required to build a PDB for one input image.
///
/// This inspection is intentionally ephemeral: callers must retain or reopen
/// the original binary and compare [`identity`](Self::identity) with the
/// analysis session before exporting. The raw section headers are copied
/// byte-for-byte from the validated PE section table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeCodeViewInspection {
    identity: BinaryIdentity,
    machine: u16,
    section_headers: Vec<[u8; 40]>,
    rsds: PeCodeViewRsds,
}

impl PeCodeViewInspection {
    pub const fn identity(&self) -> &BinaryIdentity {
        &self.identity
    }

    pub const fn machine(&self) -> u16 {
        self.machine
    }

    pub fn section_headers(&self) -> &[[u8; 40]] {
        &self.section_headers
    }

    pub const fn rsds(&self) -> &PeCodeViewRsds {
        &self.rsds
    }
}

/// One unambiguous CodeView PDB 7.0 (`RSDS`) identity from a PE debug directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeCodeViewRsds {
    /// Zero-based position in the PE `IMAGE_DEBUG_DIRECTORY` array.
    debug_directory_index: u32,
    /// Exact 16 bytes stored after the `RSDS` signature; no GUID byte swapping is applied.
    guid: [u8; 16],
    age: u32,
    /// Advisory PDB path bytes before the first NUL, retained without assuming an encoding.
    pdb_path: Vec<u8>,
}

impl PeCodeViewRsds {
    pub const fn debug_directory_index(&self) -> u32 {
        self.debug_directory_index
    }

    pub const fn guid(&self) -> [u8; 16] {
        self.guid
    }

    pub const fn age(&self) -> u32 {
        self.age
    }

    pub fn pdb_path(&self) -> &[u8] {
        &self.pdb_path
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RecoveredEntrySource {
    DirectCall {
        caller_rva: u32,
        call_site_rva: u32,
        instruction_size: u8,
        slot_rva: Option<u32>,
    },
    Thunk {
        source_rva: u32,
        instruction_size: u8,
        slot_rva: Option<u32>,
    },
}

struct ParsedHeaders {
    pe_header_offset: u32,
    coff: CoffHeader,
    entry_point_rva: u32,
    image_base: u64,
    size_of_image: u32,
    size_of_headers: u32,
    section_alignment: u32,
    file_alignment: u32,
    subsystem: u16,
    dll_characteristics: u16,
    directories: PeDataDirectories,
    debug_directory: Option<DataDirectory>,
    sections: Vec<PeSection>,
}

struct ParsedLoadConfigMetadata {
    load_config_size: Option<u32>,
    security_anchors: PeLoadConfigSecurityAnchors,
    xfg_anchors: PeLoadConfigXfgAnchors,
    guard_memcpy_anchor: PeLoadConfigGuardMemcpyAnchor,
    guard_flags: Option<u32>,
    function_table_rva: Option<u32>,
    functions: Vec<PeGuardCfFunction>,
    address_taken_iat_entry_table_rva: Option<u32>,
    address_taken_iat_entries: Vec<PeGuardAddressTakenIatEntry>,
    long_jump_target_table_rva: Option<u32>,
    long_jump_targets: Vec<PeGuardLongJumpTarget>,
    eh_continuation_table_rva: Option<u32>,
    eh_continuation_targets: Vec<PeGuardEhContinuationTarget>,
}

struct ParsedGuardCfMetadata {
    load_config_size: Option<u32>,
    guard_flags: Option<u32>,
    function_table_rva: Option<u32>,
    functions: Vec<PeGuardCfFunction>,
}

#[derive(Clone, Copy)]
struct GuardTableParseContext {
    directory: DataDirectory,
    image_base: u64,
    size_of_image: u32,
    guard_flags: u32,
}

#[derive(Default)]
struct ImportBudget {
    libraries: u64,
    symbols: u64,
    name_bytes: u64,
    iat_rvas: BTreeSet<u32>,
}

pub(crate) struct SymbolGraphInput<'a> {
    pub identity: &'a BinaryIdentity,
    pub entry_point_rva: u32,
    pub sections: &'a [PeSection],
    pub exports: &'a [PeExport],
    pub runtime_functions: &'a [RuntimeFunction],
    pub load_config_rva: Option<u32>,
    pub guard_flags: Option<u32>,
    pub guard_cf_function_table_rva: Option<u32>,
    pub guard_cf_functions: &'a [PeGuardCfFunction],
    pub tls_directory_rva: Option<u32>,
    pub tls_callback_table_rva: Option<u32>,
    pub tls_callbacks: &'a [PeTlsCallback],
    pub direct_calls: &'a [PeDirectCall],
    pub thunks: &'a [PeThunk],
    pub strings: &'a [PeRecoveredString],
    pub data_references: &'a [PeDataReference],
    pub msvc_rtti_vftables: &'a [MsvcRttiVftable],
}

/// Parse a PE32+ x86-64 image without loading or executing it.
pub fn analyze_pe(bytes: &[u8]) -> Result<PeAnalysis, AnalysisError> {
    let reader = Reader::new(bytes);
    let headers = parse_headers(&reader)?;
    let mapper = RvaMap::new(bytes, headers.size_of_headers, &headers.sections);
    let string_recovery = recover_strings(bytes, &headers.sections);

    let mut import_budget = ImportBudget::default();
    let imports = parse_imports(
        &reader,
        &mapper,
        headers.directories.imports,
        &mut import_budget,
    )?;
    let delay_imports = parse_delay_imports(
        &reader,
        &mapper,
        headers.directories.delay_imports,
        &mut import_budget,
    )?;
    let (export_library_name, exports) = parse_exports(
        &reader,
        &mapper,
        headers.directories.exports,
        headers.size_of_image,
    )?;
    let runtime_functions = parse_runtime_functions(
        &reader,
        &mapper,
        headers.directories.exceptions,
        headers.size_of_image,
    )?;
    let ParsedLoadConfigMetadata {
        load_config_size,
        security_anchors: load_config_security_anchors,
        xfg_anchors: load_config_xfg_anchors,
        guard_memcpy_anchor: load_config_guard_memcpy_anchor,
        guard_flags,
        function_table_rva: guard_cf_function_table_rva,
        functions: guard_cf_functions,
        address_taken_iat_entry_table_rva: guard_address_taken_iat_entry_table_rva,
        address_taken_iat_entries: guard_address_taken_iat_entries,
        long_jump_target_table_rva: guard_long_jump_target_table_rva,
        long_jump_targets: guard_long_jump_targets,
        eh_continuation_table_rva: guard_eh_continuation_table_rva,
        eh_continuation_targets: guard_eh_continuation_targets,
    } = parse_load_config_metadata(
        &reader,
        &mapper,
        headers.directories.load_config,
        headers.image_base,
        headers.size_of_image,
        &headers.sections,
        &import_budget.iat_rvas,
    )?;
    let (tls_callback_table_rva, tls_callbacks, tls_callback_scan_truncated) = parse_tls_callbacks(
        &reader,
        &mapper,
        headers.directories.tls,
        headers.image_base,
        headers.size_of_image,
        &headers.sections,
    )?;
    let (msvc_rtti_vftables, msvc_rtti_scan_truncated) = parse_msvc_rtti(
        &mapper,
        &headers.sections,
        headers.image_base,
        headers.size_of_image,
    )?;
    let code_recovery = recover_code(CodeRecoveryInput {
        mapper: &mapper,
        image_base: headers.image_base,
        size_of_image: headers.size_of_image,
        entry_point_rva: headers.entry_point_rva,
        sections: &headers.sections,
        imports: &imports,
        delay_imports: &delay_imports,
        exports: &exports,
        runtime_functions: &runtime_functions,
        guard_cf_functions: &guard_cf_functions,
        tls_callbacks: &tls_callbacks,
        msvc_rtti_vftables: &msvc_rtti_vftables,
    });

    let identity = pe_binary_identity(bytes, headers.image_base)?;
    let symbol_graph = build_symbol_graph(SymbolGraphInput {
        identity: &identity,
        entry_point_rva: headers.entry_point_rva,
        sections: &headers.sections,
        exports: &exports,
        runtime_functions: &runtime_functions,
        load_config_rva: headers
            .directories
            .load_config
            .map(|directory| directory.rva),
        guard_flags,
        guard_cf_function_table_rva,
        guard_cf_functions: &guard_cf_functions,
        tls_directory_rva: headers.directories.tls.map(|directory| directory.rva),
        tls_callback_table_rva,
        tls_callbacks: &tls_callbacks,
        direct_calls: &code_recovery.direct_calls,
        thunks: &code_recovery.thunks,
        strings: &string_recovery.strings,
        data_references: &code_recovery.data_references,
        msvc_rtti_vftables: &msvc_rtti_vftables,
    })?;

    let analysis = PeAnalysis {
        identity,
        pe_header_offset: headers.pe_header_offset,
        coff: headers.coff,
        entry_point_rva: headers.entry_point_rva,
        size_of_image: headers.size_of_image,
        size_of_headers: headers.size_of_headers,
        section_alignment: headers.section_alignment,
        file_alignment: headers.file_alignment,
        subsystem: headers.subsystem,
        dll_characteristics: headers.dll_characteristics,
        directories: headers.directories,
        sections: headers.sections,
        imports,
        delay_imports,
        export_library_name,
        exports,
        runtime_functions,
        load_config_size,
        load_config_security_anchors,
        load_config_xfg_anchors,
        load_config_guard_memcpy_anchor,
        guard_flags,
        guard_cf_function_table_rva,
        guard_cf_functions,
        guard_address_taken_iat_entry_table_rva,
        guard_address_taken_iat_entries,
        guard_long_jump_target_table_rva,
        guard_long_jump_targets,
        guard_eh_continuation_table_rva,
        guard_eh_continuation_targets,
        tls_callback_table_rva,
        tls_callback_scan_truncated,
        tls_callbacks,
        code_recovery_scan_truncated: code_recovery.scan_truncated,
        direct_calls: code_recovery.direct_calls,
        thunks: code_recovery.thunks,
        string_recovery_scan_truncated: string_recovery.scan_truncated,
        strings: string_recovery.strings,
        data_reference_scan_truncated: code_recovery.data_reference_scan_truncated,
        data_references: code_recovery.data_references,
        msvc_rtti_scan_truncated,
        msvc_rtti_vftables,
        symbol_graph,
    };
    analysis.validate()?;
    Ok(analysis)
}

/// Inspect the exact original PE bytes for one unambiguous CodeView `RSDS` identity.
///
/// The same strict PE32+ x86-64 header and section invariants used by
/// [`analyze_pe`] are applied. The debug-directory table and CodeView payload
/// are bounded independently. A missing, malformed, or second `RSDS` record is
/// rejected instead of selecting a candidate heuristically. When both
/// `AddressOfRawData` and `PointerToRawData` are present they must resolve to
/// the same file offset; a pointer-only overlay record is accepted when its RVA
/// is zero.
pub fn inspect_pe_codeview(bytes: &[u8]) -> Result<PeCodeViewInspection, AnalysisError> {
    let reader = Reader::new(bytes);
    let headers = parse_headers(&reader)?;
    let identity = pe_binary_identity(bytes, headers.image_base)?;
    let section_headers = copy_raw_section_headers(&reader, &headers)?;
    let mapper = RvaMap::new(bytes, headers.size_of_headers, &headers.sections);
    let rsds = parse_single_codeview_rsds(&reader, &mapper, headers.debug_directory)?;

    Ok(PeCodeViewInspection {
        identity,
        machine: headers.coff.machine,
        section_headers,
        rsds,
    })
}

fn pe_binary_identity(bytes: &[u8], image_base: u64) -> Result<BinaryIdentity, AnalysisError> {
    Ok(BinaryIdentity {
        id: BinaryId::digest(bytes),
        size: u64::try_from(bytes.len())
            .map_err(|_| AnalysisError::IntegerConversion("binary size"))?,
        format: BinaryFormat::Pe,
        architecture: "x86_64".to_owned(),
        image_base,
    })
}

fn copy_raw_section_headers(
    reader: &Reader<'_>,
    headers: &ParsedHeaders,
) -> Result<Vec<[u8; 40]>, AnalysisError> {
    let pe_offset = usize::try_from(headers.pe_header_offset)
        .map_err(|_| AnalysisError::IntegerConversion("PE header offset"))?;
    let coff_offset = checked_add(pe_offset, PE_SIGNATURE_SIZE, "COFF header offset")?;
    let optional_offset = checked_add(coff_offset, COFF_HEADER_SIZE, "optional-header offset")?;
    let sections_offset = checked_add(
        optional_offset,
        usize::from(headers.coff.optional_header_size),
        "section-table offset",
    )?;
    let mut section_headers = Vec::with_capacity(headers.sections.len());
    for index in 0..headers.sections.len() {
        let offset = checked_add(
            sections_offset,
            checked_mul(index, SECTION_HEADER_SIZE, "section-header position")?,
            "section-header offset",
        )?;
        let mut raw = [0_u8; SECTION_HEADER_SIZE];
        raw.copy_from_slice(reader.bytes(offset, SECTION_HEADER_SIZE, "section header")?);
        section_headers.push(raw);
    }
    Ok(section_headers)
}

fn parse_single_codeview_rsds(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    directory: Option<DataDirectory>,
) -> Result<PeCodeViewRsds, AnalysisError> {
    let directory = directory.ok_or_else(|| AnalysisError::InvalidField {
        field: "PE CodeView debug directory",
        reason: "the exact binary has no debug-directory entry".to_owned(),
    })?;
    enforce_directory_size("debug-directory byte", directory.size)?;
    if directory.size % DEBUG_DIRECTORY_ENTRY_SIZE_U32 != 0 {
        return invalid_field(
            "debug directory size",
            "must be a multiple of the 28-byte IMAGE_DEBUG_DIRECTORY size",
        );
    }
    let entry_count = u64::from(directory.size / DEBUG_DIRECTORY_ENTRY_SIZE_U32);
    enforce_limit(
        "debug-directory entry",
        entry_count,
        MAX_DEBUG_DIRECTORY_ENTRIES,
    )?;
    let directory_size = usize::try_from(directory.size)
        .map_err(|_| AnalysisError::IntegerConversion("debug-directory size"))?;
    let directory_offset = mapper.offset(directory.rva, directory_size, "PE debug directory")?;

    let mut rsds = None;
    for index in 0..usize::try_from(entry_count)
        .map_err(|_| AnalysisError::IntegerConversion("debug-directory entry count"))?
    {
        let entry_offset = checked_add(
            directory_offset,
            checked_mul(
                index,
                DEBUG_DIRECTORY_ENTRY_SIZE,
                "debug-directory entry position",
            )?,
            "debug-directory entry offset",
        )?;
        let characteristics = reader.u32(entry_offset, "debug-directory characteristics")?;
        let debug_type = reader.u32(entry_offset + 12, "debug-directory type")?;
        if debug_type != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }
        if characteristics != 0 {
            return invalid_field(
                "CodeView debug-directory characteristics",
                format!("entry {index} uses non-zero reserved characteristics"),
            );
        }

        let size_of_data = reader.u32(entry_offset + 16, "CodeView data size")?;
        enforce_limit(
            "CodeView debug-data byte",
            u64::from(size_of_data),
            MAX_DIRECTORY_BYTES,
        )?;
        if size_of_data < 4 {
            return invalid_field(
                "CodeView debug data",
                format!("entry {index} is too small to contain a signature"),
            );
        }
        let address_of_raw_data = reader.u32(entry_offset + 20, "CodeView data RVA")?;
        let pointer_to_raw_data = reader.u32(entry_offset + 24, "CodeView data file offset")?;
        if pointer_to_raw_data == 0 {
            return invalid_field(
                "CodeView data file offset",
                format!("entry {index} has no file-backed PointerToRawData"),
            );
        }
        let data_size = usize::try_from(size_of_data)
            .map_err(|_| AnalysisError::IntegerConversion("CodeView data size"))?;
        let data_offset = usize::try_from(pointer_to_raw_data)
            .map_err(|_| AnalysisError::IntegerConversion("CodeView data file offset"))?;
        let data = reader.bytes(data_offset, data_size, "CodeView debug data")?;

        if address_of_raw_data != 0 {
            let mapped_offset =
                mapper.offset(address_of_raw_data, data_size, "CodeView debug data")?;
            if mapped_offset != data_offset {
                return invalid_field(
                    "CodeView debug-data location",
                    format!(
                        "entry {index} maps AddressOfRawData to file offset {mapped_offset:#x}, but PointerToRawData is {data_offset:#x}"
                    ),
                );
            }
        }

        if data.get(..4) != Some(b"RSDS".as_slice()) {
            continue;
        }
        enforce_limit(
            "RSDS record byte",
            u64::from(size_of_data),
            MAX_CODEVIEW_RECORD_BYTES,
        )?;
        if data.len() < CODEVIEW_RSDS_HEADER_SIZE {
            return invalid_field(
                "RSDS record",
                format!(
                    "entry {index} is {} bytes; at least {CODEVIEW_RSDS_HEADER_SIZE} are required",
                    data.len()
                ),
            );
        }
        if rsds.is_some() {
            return invalid_field(
                "RSDS identity",
                format!(
                    "multiple RSDS records are ambiguous; a second record appears at debug-directory index {index}"
                ),
            );
        }

        let mut guid = [0_u8; 16];
        guid.copy_from_slice(&data[4..20]);
        let mut age = [0_u8; 4];
        age.copy_from_slice(&data[20..24]);
        let raw_path = &data[CODEVIEW_RSDS_HEADER_SIZE..];
        let path_end = raw_path.iter().position(|byte| *byte == 0).ok_or_else(|| {
            AnalysisError::InvalidField {
                field: "RSDS PDB path",
                reason: format!(
                    "entry {index} is not NUL-terminated within its declared CodeView record"
                ),
            }
        })?;
        enforce_limit(
            "RSDS PDB-path byte",
            u64::try_from(path_end)
                .map_err(|_| AnalysisError::IntegerConversion("RSDS PDB-path length"))?,
            MAX_CODEVIEW_PATH_BYTES,
        )?;
        rsds = Some(PeCodeViewRsds {
            debug_directory_index: u32::try_from(index)
                .map_err(|_| AnalysisError::IntegerConversion("debug-directory index"))?,
            guid,
            age: u32::from_le_bytes(age),
            pdb_path: raw_path[..path_end].to_vec(),
        });
    }

    rsds.ok_or_else(|| AnalysisError::InvalidField {
        field: "RSDS identity",
        reason: "the exact binary has no IMAGE_DEBUG_TYPE_CODEVIEW RSDS record".to_owned(),
    })
}

pub(crate) fn validate_pe_analysis(analysis: &PeAnalysis) -> Result<(), AnalysisError> {
    analysis.identity.validate()?;
    if !matches!(&analysis.identity.format, BinaryFormat::Pe) {
        return invalid_field(
            "binary format",
            "PE analysis must use the PE identity format",
        );
    }
    if analysis.identity.architecture != "x86_64" {
        return invalid_field(
            "binary architecture",
            "PE analysis currently supports only x86_64",
        );
    }
    if analysis.size_of_image == 0
        || analysis.size_of_headers == 0
        || analysis.size_of_headers > analysis.size_of_image
    {
        return invalid_field("PE image sizes", "header and image sizes are inconsistent");
    }
    validate_image_alignment(
        analysis.section_alignment,
        analysis.file_alignment,
        analysis.size_of_image,
        analysis.size_of_headers,
    )?;
    if analysis.entry_point_rva != 0 && analysis.entry_point_rva >= analysis.size_of_image {
        return invalid_field("entry-point RVA", "lies outside the declared image");
    }
    if u64::from(analysis.size_of_headers) > analysis.identity.size {
        return invalid_field("size of headers", "exceeds the exact binary size");
    }
    if analysis.pe_header_offset < DOS_HEADER_SIZE_U32 {
        return invalid_field("DOS e_lfanew", "PE header overlaps the DOS header");
    }
    if analysis.pe_header_offset > MAX_PE_HEADER_OFFSET {
        return Err(AnalysisError::PeHeaderOffsetLimit {
            offset: analysis.pe_header_offset,
            limit: MAX_PE_HEADER_OFFSET,
        });
    }
    if analysis.coff.machine != MACHINE_AMD64 {
        return Err(AnalysisError::UnsupportedMachine {
            machine: analysis.coff.machine,
            expected: MACHINE_AMD64,
        });
    }
    if usize::from(analysis.coff.optional_header_size) < OPTIONAL_HEADER_MIN_SIZE {
        return Err(AnalysisError::OptionalHeaderTooSmall {
            actual: usize::from(analysis.coff.optional_header_size),
            minimum: OPTIONAL_HEADER_MIN_SIZE,
        });
    }
    let required_optional_header_size = [
        (analysis.directories.exports, EXPORT_DIRECTORY_INDEX),
        (analysis.directories.imports, IMPORT_DIRECTORY_INDEX),
        (analysis.directories.exceptions, EXCEPTION_DIRECTORY_INDEX),
        (analysis.directories.tls, TLS_DIRECTORY_INDEX),
        (
            analysis.directories.load_config,
            LOAD_CONFIG_DIRECTORY_INDEX,
        ),
        (
            analysis.directories.delay_imports,
            DELAY_IMPORT_DIRECTORY_INDEX,
        ),
    ]
    .into_iter()
    .filter_map(|(directory, index)| {
        directory.map(|_| OPTIONAL_HEADER_MIN_SIZE + (index + 1) * DATA_DIRECTORY_SIZE)
    })
    .max()
    .unwrap_or(OPTIONAL_HEADER_MIN_SIZE);
    if usize::from(analysis.coff.optional_header_size) < required_optional_header_size {
        return Err(AnalysisError::OptionalHeaderTooSmall {
            actual: usize::from(analysis.coff.optional_header_size),
            minimum: required_optional_header_size,
        });
    }
    let section_count = u64::try_from(analysis.sections.len())
        .map_err(|_| AnalysisError::IntegerConversion("section count"))?;
    enforce_limit("section", section_count, MAX_SECTIONS)?;
    if usize::from(analysis.coff.number_of_sections) != analysis.sections.len() {
        return invalid_field(
            "COFF section count",
            "does not match the deserialized section table",
        );
    }

    let section_table_end = u64::from(analysis.pe_header_offset)
        .checked_add(PE_AND_COFF_HEADER_SIZE_U64)
        .and_then(|value| value.checked_add(u64::from(analysis.coff.optional_header_size)))
        .and_then(|value| value.checked_add(section_count.checked_mul(SECTION_HEADER_SIZE_U64)?))
        .ok_or(AnalysisError::ArithmeticOverflow(
            "deserialized section-table range",
        ))?;
    if section_table_end > u64::from(analysis.size_of_headers) {
        return invalid_field("section table", "extends beyond the declared PE headers");
    }

    for (name, directory) in [
        ("export directory", analysis.directories.exports),
        ("import directory", analysis.directories.imports),
        ("exception directory", analysis.directories.exceptions),
        ("TLS directory", analysis.directories.tls),
        ("load-config directory", analysis.directories.load_config),
        ("delay-import directory", analysis.directories.delay_imports),
    ] {
        if let Some(directory) = directory {
            if directory.rva == 0 || directory.size == 0 {
                return invalid_field(name, "RVA and size must be non-zero");
            }
            enforce_directory_size("data-directory byte", directory.size)?;
            let end = u64::from(directory.rva)
                .checked_add(u64::from(directory.size))
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "data-directory RVA range",
                ))?;
            if end > u64::from(analysis.size_of_image) {
                return invalid_field(name, "extends outside the declared image");
            }
        }
    }

    for (index, section) in analysis.sections.iter().enumerate() {
        if section.name != display_section_name(&section.raw_name) {
            return invalid_field(
                "section name",
                format!("section {index} does not match its exact raw name bytes"),
            );
        }
        validate_section_alignment(
            index,
            section,
            analysis.section_alignment,
            analysis.file_alignment,
        )?;
        let virtual_span = section.loaded_size();
        let virtual_end = u64::from(section.virtual_address)
            .checked_add(u64::from(virtual_span))
            .ok_or(AnalysisError::ArithmeticOverflow("section virtual range"))?;
        if virtual_end > u64::from(analysis.size_of_image) {
            return invalid_field(
                "section virtual range",
                format!("section {index} extends outside the declared image"),
            );
        }
        if virtual_span != 0 && section.virtual_address < analysis.size_of_headers {
            return invalid_field(
                "section virtual range",
                format!("section {index} overlaps the PE headers"),
            );
        }
        let raw_end = u64::from(section.raw_data_offset)
            .checked_add(u64::from(section.raw_data_size))
            .ok_or(AnalysisError::ArithmeticOverflow("section raw range"))?;
        if raw_end > analysis.identity.size {
            return invalid_field(
                "section raw range",
                format!("section {index} extends outside the exact binary"),
            );
        }
        if section.raw_data_size != 0 && section.raw_data_offset < analysis.size_of_headers {
            return invalid_field(
                "section raw range",
                format!("section {index} overlaps the PE headers"),
            );
        }
    }
    validate_section_overlaps(&analysis.sections)?;
    for (name, directory) in [
        ("export directory", analysis.directories.exports),
        ("import directory", analysis.directories.imports),
        ("exception directory", analysis.directories.exceptions),
        ("TLS directory", analysis.directories.tls),
        ("load-config directory", analysis.directories.load_config),
        ("delay-import directory", analysis.directories.delay_imports),
    ] {
        if let Some(directory) = directory {
            if !model_rva_is_backed(analysis, directory.rva, directory.size) {
                return invalid_field(name, "is not fully backed by file data");
            }
        }
    }

    let import_library_count = u64::try_from(analysis.imports.len())
        .map_err(|_| AnalysisError::IntegerConversion("import-library count"))?;
    let delay_import_library_count = u64::try_from(analysis.delay_imports.len())
        .map_err(|_| AnalysisError::IntegerConversion("delay-import-library count"))?;
    let total_import_library_count = import_library_count
        .checked_add(delay_import_library_count)
        .ok_or(AnalysisError::ArithmeticOverflow(
            "total import-library count",
        ))?;
    enforce_limit(
        "import library",
        total_import_library_count,
        MAX_IMPORT_LIBRARIES,
    )?;
    let mut import_symbol_count = 0_u64;
    let mut import_name_bytes = 0_u64;
    let mut import_iat_rvas = BTreeSet::new();
    if !analysis.imports.is_empty() && analysis.directories.imports.is_none() {
        return invalid_field("imports", "entries exist without an import directory");
    }
    if let Some(directory) = analysis.directories.imports {
        if directory.size % IMPORT_DESCRIPTOR_SIZE_U32 != 0 {
            return invalid_field(
                "import directory size",
                "must be a multiple of the 20-byte descriptor size",
            );
        }
        let descriptor_count = u64::from(directory.size / IMPORT_DESCRIPTOR_SIZE_U32);
        enforce_limit(
            "import-library descriptor",
            descriptor_count,
            MAX_IMPORT_DESCRIPTORS,
        )?;
        let required_descriptors =
            import_library_count
                .checked_add(1)
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "import descriptor count including terminator",
                ))?;
        if required_descriptors > descriptor_count {
            return invalid_field(
                "imports",
                "the import directory does not leave room for its zero terminator",
            );
        }
    }
    for (library_index, library) in analysis.imports.iter().enumerate() {
        if library.name.is_empty() {
            return invalid_field("import DLL name", "must not be empty");
        }
        enforce_string_length("import DLL-name byte", &library.name)?;
        consume_string_budget(
            &mut import_name_bytes,
            &library.name,
            "import-name byte",
            MAX_IMPORT_NAME_BYTES,
        )?;
        let directory =
            analysis
                .directories
                .imports
                .ok_or_else(|| AnalysisError::InvalidField {
                    field: "imports",
                    reason: "entry exists without an import directory".to_owned(),
                })?;
        let descriptor_delta = checked_u32_mul(
            u32::try_from(library_index)
                .map_err(|_| AnalysisError::IntegerConversion("import descriptor index"))?,
            IMPORT_DESCRIPTOR_SIZE_U32,
            "import descriptor RVA",
        )?;
        let expected_descriptor_rva =
            checked_u32_add(directory.rva, descriptor_delta, "import descriptor RVA")?;
        if library.descriptor_rva != expected_descriptor_rva
            || !model_rva_is_backed(analysis, library.descriptor_rva, IMPORT_DESCRIPTOR_SIZE_U32)
        {
            return invalid_field(
                "import descriptor",
                "source RVAs are not contiguous from the import-directory start",
            );
        }
        let first_lookup_rva = library.entries.first().map(|entry| entry.lookup_rva);
        let first_iat_rva = library.entries.first().map(|entry| entry.iat_rva);
        for (entry_index, entry) in library.entries.iter().enumerate() {
            import_symbol_count = import_symbol_count
                .checked_add(1)
                .ok_or(AnalysisError::ArithmeticOverflow("import-symbol count"))?;
            enforce_limit("import symbol", import_symbol_count, MAX_IMPORT_SYMBOLS)?;
            let thunk_delta = checked_u32_mul(
                u32::try_from(entry_index)
                    .map_err(|_| AnalysisError::IntegerConversion("import thunk index"))?,
                8,
                "import thunk position",
            )?;
            let expected_lookup_rva = checked_u32_add(
                first_lookup_rva.ok_or_else(|| AnalysisError::InvalidField {
                    field: "import thunk",
                    reason: "non-empty table has no first lookup RVA".to_owned(),
                })?,
                thunk_delta,
                "import lookup RVA",
            )?;
            let expected_iat_rva = checked_u32_add(
                first_iat_rva.ok_or_else(|| AnalysisError::InvalidField {
                    field: "import thunk",
                    reason: "non-empty table has no first IAT RVA".to_owned(),
                })?,
                thunk_delta,
                "import IAT RVA",
            )?;
            if entry.lookup_rva != expected_lookup_rva
                || entry.iat_rva != expected_iat_rva
                || !model_rva_is_backed(analysis, entry.lookup_rva, 8)
                || !model_rva_is_backed(analysis, entry.iat_rva, 8)
            {
                return invalid_field(
                    "import thunk",
                    "lookup and address-table RVAs must be contiguous and file-backed",
                );
            }
            if !import_iat_rvas.insert(entry.iat_rva) {
                return invalid_field(
                    "import IAT slot",
                    format!(
                        "RVA {:#x} is claimed by more than one import entry",
                        entry.iat_rva
                    ),
                );
            }
            if let ImportTarget::Name { name, .. } = &entry.target {
                if name.is_empty() {
                    return invalid_field("import symbol name", "must not be empty");
                }
                enforce_string_length("import symbol-name byte", name)?;
                consume_string_budget(
                    &mut import_name_bytes,
                    name,
                    "import-name byte",
                    MAX_IMPORT_NAME_BYTES,
                )?;
            }
        }
        if let (Some(lookup_rva), Some(iat_rva)) = (first_lookup_rva, first_iat_rva) {
            let terminator_delta = checked_u32_mul(
                u32::try_from(library.entries.len())
                    .map_err(|_| AnalysisError::IntegerConversion("import thunk count"))?,
                8,
                "import thunk terminator position",
            )?;
            let lookup_terminator =
                checked_u32_add(lookup_rva, terminator_delta, "import lookup terminator RVA")?;
            let iat_terminator =
                checked_u32_add(iat_rva, terminator_delta, "import IAT terminator RVA")?;
            if !model_rva_is_backed(analysis, lookup_terminator, 8)
                || !model_rva_is_backed(analysis, iat_terminator, 8)
            {
                return invalid_field(
                    "import thunk terminator",
                    "lookup or address-table terminator RVA is not backed by file data",
                );
            }
        }
    }
    validate_delay_imports(
        analysis,
        delay_import_library_count,
        &mut import_symbol_count,
        &mut import_name_bytes,
        &mut import_iat_rvas,
    )?;

    if analysis
        .export_library_name
        .as_ref()
        .is_some_and(|name| name.is_empty())
    {
        return invalid_field("export DLL name", "must not be empty");
    }
    let export_count = u64::try_from(analysis.exports.len())
        .map_err(|_| AnalysisError::IntegerConversion("export function count"))?;
    enforce_limit("export function", export_count, MAX_EXPORT_FUNCTIONS)?;
    let mut export_name_count = 0_u64;
    let mut export_name_bytes = 0_u64;
    let mut export_name_indices = BTreeSet::new();
    if (!analysis.exports.is_empty() || analysis.export_library_name.is_some())
        && analysis.directories.exports.is_none()
    {
        return invalid_field("exports", "entries exist without an export directory");
    }
    if analysis
        .directories
        .exports
        .is_some_and(|directory| directory.size < 40)
    {
        return invalid_field("export directory size", "must be at least 40 bytes");
    }
    if let Some(name) = &analysis.export_library_name {
        enforce_string_length("export DLL-name byte", name)?;
        consume_string_budget(
            &mut export_name_bytes,
            name,
            "export-name byte",
            MAX_EXPORT_NAME_BYTES,
        )?;
    }
    let mut previous_export_ordinal: Option<u32> = None;
    for export in &analysis.exports {
        if let Some(previous) = previous_export_ordinal {
            let expected = previous
                .checked_add(1)
                .ok_or(AnalysisError::ArithmeticOverflow("export ordinal"))?;
            if export.ordinal != expected {
                return invalid_field(
                    "export ordinal",
                    "export-address-table ordinals are not contiguous",
                );
            }
        }
        previous_export_ordinal = Some(export.ordinal);
        if let Some(address) = export.address_rva {
            if address >= analysis.size_of_image {
                return invalid_field("export address", "lies outside the declared image");
            }
        }
        let address_is_forwarder = match (analysis.directories.exports, export.address_rva) {
            (Some(directory), Some(address)) => {
                let directory_end = u64::from(directory.rva) + u64::from(directory.size);
                (u64::from(directory.rva)..directory_end).contains(&u64::from(address))
            }
            _ => false,
        };
        if export.forwarded_to.is_some() != address_is_forwarder {
            return invalid_field(
                "export forwarder",
                "forwarder text must be present exactly when its address points into the export directory",
            );
        }
        if let Some(forwarder) = &export.forwarded_to {
            if forwarder.is_empty() {
                return invalid_field("export forwarder", "must not be empty");
            }
            enforce_string_length("export-forwarder byte", forwarder)?;
            let Some(directory) = analysis.directories.exports else {
                return invalid_field("export forwarder", "has no export directory");
            };
            let Some(address) = export.address_rva else {
                return invalid_field("export forwarder", "has no export address");
            };
            let directory_end = u64::from(directory.rva) + u64::from(directory.size);
            if !(u64::from(directory.rva)..directory_end).contains(&u64::from(address)) {
                return invalid_field(
                    "export forwarder",
                    "address does not point into the export directory",
                );
            }
            consume_string_budget(
                &mut export_name_bytes,
                forwarder,
                "export-name byte",
                MAX_EXPORT_NAME_BYTES,
            )?;
        }
        for name in &export.names {
            if name.name.is_empty() {
                return invalid_field("export symbol name", "must not be empty");
            }
            enforce_string_length("export symbol-name byte", &name.name)?;
            export_name_count = export_name_count
                .checked_add(1)
                .ok_or(AnalysisError::ArithmeticOverflow("export-name count"))?;
            enforce_limit("export name", export_name_count, MAX_EXPORT_NAMES)?;
            if !export_name_indices.insert(name.name_table_index) {
                return invalid_field("export name-table index", "duplicate source-table index");
            }
            consume_string_budget(
                &mut export_name_bytes,
                &name.name,
                "export-name byte",
                MAX_EXPORT_NAME_BYTES,
            )?;
        }
    }
    for expected_index in 0..u32::try_from(export_name_count)
        .map_err(|_| AnalysisError::IntegerConversion("export name count"))?
    {
        if !export_name_indices.contains(&expected_index) {
            return invalid_field(
                "export name-table index",
                "source-table indexes are not contiguous from zero",
            );
        }
    }

    let runtime_count = u64::try_from(analysis.runtime_functions.len())
        .map_err(|_| AnalysisError::IntegerConversion("runtime-function count"))?;
    enforce_limit("runtime function", runtime_count, MAX_RUNTIME_FUNCTIONS)?;
    if !analysis.runtime_functions.is_empty() && analysis.directories.exceptions.is_none() {
        return invalid_field(
            "runtime functions",
            "entries exist without an exception directory",
        );
    }
    if let Some(directory) = analysis.directories.exceptions {
        if directory.size % RUNTIME_FUNCTION_SIZE_U32 != 0
            || u64::from(directory.size / RUNTIME_FUNCTION_SIZE_U32) != runtime_count
        {
            return invalid_field(
                "exception directory size",
                "does not match the deserialized runtime-function table",
            );
        }
    }
    for (index, function) in analysis.runtime_functions.iter().enumerate() {
        if function.table_index
            != u32::try_from(index)
                .map_err(|_| AnalysisError::IntegerConversion("runtime-function index"))?
        {
            return invalid_field(
                "runtime-function table index",
                "does not match source-table order",
            );
        }
        if function.begin_rva >= function.end_rva || function.end_rva > analysis.size_of_image {
            return invalid_field(
                "runtime-function range",
                "is empty, reversed, or out of image",
            );
        }
        let inclusive_end_rva =
            function
                .end_rva
                .checked_sub(1)
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "runtime-function inclusive end RVA",
                ))?;
        let begin_section = section_for_rva(function.begin_rva, &analysis.sections);
        let end_section = section_for_rva(inclusive_end_rva, &analysis.sections);
        if begin_section.map(|(section_index, _)| section_index)
            != end_section.map(|(section_index, _)| section_index)
            || begin_section
                .is_none_or(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0)
        {
            return invalid_field(
                "runtime-function range",
                "does not stay within one executable section",
            );
        }
        if function.unwind_info_rva == 0
            || function.unwind_info_rva % 4 != 0
            || !model_rva_is_backed(analysis, function.unwind_info_rva, 4)
        {
            return invalid_field(
                "runtime-function unwind-info RVA",
                "is zero, unaligned, or not backed by file data",
            );
        }
    }

    validate_tls_callbacks(analysis)?;
    validate_load_config_metadata(analysis, &import_iat_rvas)?;
    validate_msvc_rtti(analysis)?;
    validate_code_recovery(analysis)?;
    validate_recovered_strings(
        &analysis.sections,
        analysis.size_of_image,
        &analysis.strings,
    )?;
    validate_data_references(analysis, &analysis.data_references)?;

    analysis.symbol_graph.validate()?;
    let rebuilt = build_symbol_graph(SymbolGraphInput {
        identity: &analysis.identity,
        entry_point_rva: analysis.entry_point_rva,
        sections: &analysis.sections,
        exports: &analysis.exports,
        runtime_functions: &analysis.runtime_functions,
        load_config_rva: analysis
            .directories
            .load_config
            .map(|directory| directory.rva),
        guard_flags: analysis.guard_flags,
        guard_cf_function_table_rva: analysis.guard_cf_function_table_rva,
        guard_cf_functions: &analysis.guard_cf_functions,
        tls_directory_rva: analysis.directories.tls.map(|directory| directory.rva),
        tls_callback_table_rva: analysis.tls_callback_table_rva,
        tls_callbacks: &analysis.tls_callbacks,
        direct_calls: &analysis.direct_calls,
        thunks: &analysis.thunks,
        strings: &analysis.strings,
        data_references: &analysis.data_references,
        msvc_rtti_vftables: &analysis.msvc_rtti_vftables,
    })?;
    if !symbol_graph_semantically_matches(&rebuilt, &analysis.symbol_graph) {
        return invalid_field(
            "symbol graph",
            "does not semantically match claims derived from the PE metadata",
        );
    }
    Ok(())
}

fn validate_delay_imports(
    analysis: &PeAnalysis,
    library_count: u64,
    import_symbol_count: &mut u64,
    import_name_bytes: &mut u64,
    import_iat_rvas: &mut BTreeSet<u32>,
) -> Result<(), AnalysisError> {
    let Some(directory) = analysis.directories.delay_imports else {
        if analysis.delay_imports.is_empty() {
            return Ok(());
        }
        return invalid_field(
            "delay imports",
            "entries exist without a delay-import directory",
        );
    };
    if directory.size % DELAY_IMPORT_DESCRIPTOR_SIZE_U32 != 0 {
        return invalid_field(
            "delay-import directory size",
            "must be a multiple of the 32-byte descriptor size",
        );
    }
    let descriptor_count = u64::from(directory.size / DELAY_IMPORT_DESCRIPTOR_SIZE_U32);
    enforce_limit(
        "delay-import-library descriptor",
        descriptor_count,
        MAX_IMPORT_DESCRIPTORS,
    )?;
    let required_descriptors =
        library_count
            .checked_add(1)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "delay-import descriptor count including terminator",
            ))?;
    if required_descriptors > descriptor_count {
        return invalid_field(
            "delay imports",
            "the delay-import directory does not leave room for its zero terminator",
        );
    }

    for (library_index, library) in analysis.delay_imports.iter().enumerate() {
        if library.attributes != DELAY_IMPORT_ATTRIBUTE_RVA {
            return invalid_field(
                "delay-import attributes",
                format!(
                    "descriptor {library_index} uses {:#x}; only the modern dlattrRva value {DELAY_IMPORT_ATTRIBUTE_RVA:#x} is supported",
                    library.attributes
                ),
            );
        }
        if library.name.is_empty() {
            return invalid_field("delay-import DLL name", "must not be empty");
        }
        enforce_string_length("delay-import DLL-name byte", &library.name)?;
        consume_string_budget(
            import_name_bytes,
            &library.name,
            "import-name byte",
            MAX_IMPORT_NAME_BYTES,
        )?;
        let descriptor_delta = checked_u32_mul(
            u32::try_from(library_index)
                .map_err(|_| AnalysisError::IntegerConversion("delay-import descriptor index"))?,
            DELAY_IMPORT_DESCRIPTOR_SIZE_U32,
            "delay-import descriptor RVA",
        )?;
        let expected_descriptor_rva = checked_u32_add(
            directory.rva,
            descriptor_delta,
            "delay-import descriptor RVA",
        )?;
        if library.descriptor_rva != expected_descriptor_rva
            || !model_rva_is_backed(
                analysis,
                library.descriptor_rva,
                DELAY_IMPORT_DESCRIPTOR_SIZE_U32,
            )
        {
            return invalid_field(
                "delay-import descriptor",
                "source RVAs are not contiguous from the delay-import-directory start",
            );
        }
        if library.name_rva == 0
            || library.module_handle_rva == 0
            || library.iat_rva == 0
            || library.int_rva == 0
        {
            return invalid_field(
                "delay-import descriptor",
                format!(
                    "descriptor {library_index} has a zero DLL-name, module-handle, IAT, or INT RVA"
                ),
            );
        }
        let name_size =
            library
                .name
                .len()
                .checked_add(1)
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "delay-import DLL-name size",
                ))?;
        let name_size = u32::try_from(name_size)
            .map_err(|_| AnalysisError::IntegerConversion("delay-import DLL-name size"))?;
        if !model_rva_is_backed(analysis, library.name_rva, name_size) {
            return invalid_field(
                "delay-import descriptor",
                "DLL name is not fully backed by file data",
            );
        }
        if !model_rva_is_mapped_section_range(analysis, library.module_handle_rva, 8) {
            return invalid_field(
                "delay-import descriptor",
                "module-handle storage is not wholly mapped inside one section",
            );
        }

        for (entry_index, entry) in library.entries.iter().enumerate() {
            *import_symbol_count = (*import_symbol_count)
                .checked_add(1)
                .ok_or(AnalysisError::ArithmeticOverflow("import-symbol count"))?;
            enforce_limit("import symbol", *import_symbol_count, MAX_IMPORT_SYMBOLS)?;
            let thunk_delta = checked_u32_mul(
                u32::try_from(entry_index)
                    .map_err(|_| AnalysisError::IntegerConversion("delay-import thunk index"))?,
                8,
                "delay-import thunk position",
            )?;
            let expected_lookup_rva =
                checked_u32_add(library.int_rva, thunk_delta, "delay-import lookup RVA")?;
            let expected_iat_rva =
                checked_u32_add(library.iat_rva, thunk_delta, "delay-import IAT RVA")?;
            if entry.lookup_rva != expected_lookup_rva
                || entry.iat_rva != expected_iat_rva
                || !model_rva_is_backed(analysis, entry.lookup_rva, 8)
                || !model_rva_is_backed(analysis, entry.iat_rva, 8)
            {
                return invalid_field(
                    "delay-import thunk",
                    "INT and IAT RVAs must be contiguous and file-backed",
                );
            }
            if !import_iat_rvas.insert(entry.iat_rva) {
                return invalid_field(
                    "import IAT slot",
                    format!(
                        "RVA {:#x} is claimed by more than one import entry",
                        entry.iat_rva
                    ),
                );
            }
            if let ImportTarget::Name { name, .. } = &entry.target {
                if name.is_empty() {
                    return invalid_field("delay-import symbol name", "must not be empty");
                }
                enforce_string_length("delay-import symbol-name byte", name)?;
                consume_string_budget(
                    import_name_bytes,
                    name,
                    "import-name byte",
                    MAX_IMPORT_NAME_BYTES,
                )?;
            }
        }

        let terminator_delta = checked_u32_mul(
            u32::try_from(library.entries.len())
                .map_err(|_| AnalysisError::IntegerConversion("delay-import thunk count"))?,
            8,
            "delay-import thunk terminator position",
        )?;
        let int_terminator = checked_u32_add(
            library.int_rva,
            terminator_delta,
            "delay-import INT terminator RVA",
        )?;
        let iat_terminator = checked_u32_add(
            library.iat_rva,
            terminator_delta,
            "delay-import IAT terminator RVA",
        )?;
        if !model_rva_is_backed(analysis, int_terminator, 8)
            || !model_rva_is_backed(analysis, iat_terminator, 8)
        {
            return invalid_field(
                "delay-import thunk terminator",
                "INT or IAT terminator RVA is not backed by file data",
            );
        }
        let table_size =
            terminator_delta
                .checked_add(8)
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "delay-import table byte size",
                ))?;
        for (table_rva, field) in [
            (library.bound_iat_rva, "bound delay-import table"),
            (library.unload_iat_rva, "unload delay-import table"),
        ] {
            if let Some(table_rva) = table_rva {
                if table_rva == 0 || !model_rva_is_backed(analysis, table_rva, table_size) {
                    return invalid_field(field, "is not fully backed by file data");
                }
            }
        }
        let table_ranges = [
            ("delay-import INT", Some(library.int_rva)),
            ("delay-import IAT", Some(library.iat_rva)),
            ("bound delay-import table", library.bound_iat_rva),
            ("unload delay-import table", library.unload_iat_rva),
        ];
        for first in 0..table_ranges.len() {
            let Some(first_rva) = table_ranges[first].1 else {
                continue;
            };
            for second in first + 1..table_ranges.len() {
                let Some(second_rva) = table_ranges[second].1 else {
                    continue;
                };
                if ranges_overlap(
                    u64::from(first_rva),
                    u64::from(table_size),
                    u64::from(second_rva),
                    u64::from(table_size),
                )? {
                    return invalid_field(
                        "delay-import tables",
                        format!(
                            "{} overlaps {}",
                            table_ranges[first].0, table_ranges[second].0
                        ),
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_load_config_metadata(
    analysis: &PeAnalysis,
    import_iat_rvas: &BTreeSet<u32>,
) -> Result<(), AnalysisError> {
    validate_guard_cf_functions(analysis)?;

    let has_security_anchor_state = !analysis.load_config_security_anchors.is_empty()
        || !analysis.load_config_xfg_anchors.is_empty()
        || !analysis.load_config_guard_memcpy_anchor.is_empty();
    let has_address_taken_iat_state = analysis.guard_address_taken_iat_entry_table_rva.is_some()
        || !analysis.guard_address_taken_iat_entries.is_empty();
    let has_long_jump_state = analysis.guard_long_jump_target_table_rva.is_some()
        || !analysis.guard_long_jump_targets.is_empty();
    let has_eh_continuation_state = analysis.guard_eh_continuation_table_rva.is_some()
        || !analysis.guard_eh_continuation_targets.is_empty();
    let has_extended_state =
        has_address_taken_iat_state || has_long_jump_state || has_eh_continuation_state;

    let Some(directory) = analysis.directories.load_config else {
        if has_security_anchor_state {
            return invalid_field(
                "load-config security anchors",
                "anchor state exists without a load-config directory",
            );
        }
        if has_extended_state {
            return invalid_field(
                "load-config guard target metadata",
                "table state exists without a load-config directory",
            );
        }
        return Ok(());
    };
    let load_config_size = analysis
        .load_config_size
        .expect("load-config validation requires a declared structure size");
    validate_load_config_anchors(analysis, directory, load_config_size)?;

    let mut table_ranges = Vec::new();
    if let Some(table_rva) = analysis.guard_cf_function_table_rva {
        let guard_flags = analysis
            .guard_flags
            .expect("GuardCF table validation requires GuardFlags");
        let metadata_size = guard_table_metadata_size(guard_flags)?;
        let record_size =
            4_usize
                .checked_add(metadata_size)
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "GuardCF function-record size",
                ))?;
        let table_size = u64::try_from(analysis.guard_cf_functions.len())
            .map_err(|_| AnalysisError::IntegerConversion("GuardCF function count"))?
            .checked_mul(
                u64::try_from(record_size)
                    .map_err(|_| AnalysisError::IntegerConversion("GuardCF record size"))?,
            )
            .ok_or(AnalysisError::ArithmeticOverflow(
                "GuardCF function-table byte size",
            ))?;
        table_ranges.push(("GuardCF function table", table_rva, table_size));
    }

    if load_config_size < LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_FIELDS_SIZE_U32 {
        if has_address_taken_iat_state {
            return invalid_field(
                "Guard address-taken IAT table",
                "state exists in a load-config structure too short to contain its fields",
            );
        }
        if analysis
            .guard_flags
            .is_some_and(|flags| flags & IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT != 0)
        {
            return invalid_field(
                "Guard address-taken IAT fields",
                "the presence flag is set in a load-config structure too short to contain the table fields",
            );
        }
    } else {
        let guard_flags = analysis
            .guard_flags
            .expect("extended load-config validation requires GuardFlags");
        if let Some(range) = validate_guard_address_taken_iat_table(
            analysis,
            directory,
            guard_flags,
            import_iat_rvas,
        )? {
            table_ranges.push(range);
        }
    }

    if load_config_size < LOAD_CONFIG_GUARD_LONG_JUMP_FIELDS_SIZE_U32 {
        if has_long_jump_state {
            return invalid_field(
                "Guard long-jump target table",
                "state exists in a load-config structure too short to contain its fields",
            );
        }
        if analysis
            .guard_flags
            .is_some_and(|flags| flags & IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT != 0)
        {
            return invalid_field(
                "Guard long-jump fields",
                "the presence flag is set in a load-config structure too short to contain the table fields",
            );
        }
    } else {
        let guard_flags = analysis
            .guard_flags
            .expect("extended load-config validation requires GuardFlags");
        if let Some(range) = validate_guard_long_jump_table(analysis, directory, guard_flags)? {
            table_ranges.push(range);
        }
    }

    if load_config_size < LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE_U32 {
        if has_eh_continuation_state {
            return invalid_field(
                "Guard EH-continuation table",
                "state exists in a load-config structure too short to contain its fields",
            );
        }
        if analysis
            .guard_flags
            .is_some_and(|flags| flags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT != 0)
        {
            return invalid_field(
                "Guard EH-continuation fields",
                "the presence flag is set in a load-config structure too short to contain the table fields",
            );
        }
    } else {
        let guard_flags = analysis
            .guard_flags
            .expect("extended load-config validation requires GuardFlags");
        if let Some(range) = validate_guard_eh_continuation_table(analysis, directory, guard_flags)?
        {
            table_ranges.push(range);
        }
    }

    for first in 0..table_ranges.len() {
        for second in first + 1..table_ranges.len() {
            if ranges_overlap(
                u64::from(table_ranges[first].1),
                table_ranges[first].2,
                u64::from(table_ranges[second].1),
                table_ranges[second].2,
            )? {
                return invalid_field(
                    "load-config guard tables",
                    format!(
                        "{} overlaps {}",
                        table_ranges[first].0, table_ranges[second].0
                    ),
                );
            }
        }
    }
    Ok(())
}

fn validate_load_config_anchors(
    analysis: &PeAnalysis,
    directory: DataDirectory,
    load_config_size: u32,
) -> Result<(), AnalysisError> {
    let anchors = &analysis.load_config_security_anchors;
    let xfg_anchors = &analysis.load_config_xfg_anchors;
    let guard_memcpy_anchor = &analysis.load_config_guard_memcpy_anchor;
    if load_config_size < LOAD_CONFIG_SECURITY_COOKIE_FIELDS_SIZE_U32
        && anchors.security_cookie_rva.is_some()
    {
        return invalid_field(
            "security cookie",
            "anchor state exists in a load-config structure too short to contain the SecurityCookie field",
        );
    }
    if load_config_size < LOAD_CONFIG_GUARD_CF_CHECK_POINTER_FIELDS_SIZE_U32
        && anchors.guard_cf_check_function_pointer_rva.is_some()
    {
        return invalid_field(
            "GuardCF check-function pointer slot",
            "anchor state exists in a load-config structure too short to contain the GuardCFCheckFunctionPointer field",
        );
    }
    if load_config_size < LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE_U32
        && anchors.guard_cf_dispatch_function_pointer_rva.is_some()
    {
        return invalid_field(
            "GuardCF dispatch-function pointer slot",
            "anchor state exists in a load-config structure too short to contain the GuardCFDispatchFunctionPointer field",
        );
    }
    if load_config_size < LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_FIELDS_SIZE_U32
        && xfg_anchors.guard_xfg_check_function_pointer_rva.is_some()
    {
        return invalid_field(
            "Guard XFG check-function pointer slot",
            "anchor state exists in a load-config structure too short to contain the GuardXFGCheckFunctionPointer field",
        );
    }
    if load_config_size < LOAD_CONFIG_GUARD_XFG_DISPATCH_POINTER_FIELDS_SIZE_U32
        && xfg_anchors
            .guard_xfg_dispatch_function_pointer_rva
            .is_some()
    {
        return invalid_field(
            "Guard XFG dispatch-function pointer slot",
            "anchor state exists in a load-config structure too short to contain the GuardXFGDispatchFunctionPointer field",
        );
    }
    if load_config_size < LOAD_CONFIG_GUARD_XFG_TABLE_DISPATCH_POINTER_FIELDS_SIZE_U32
        && xfg_anchors
            .guard_xfg_table_dispatch_function_pointer_rva
            .is_some()
    {
        return invalid_field(
            "Guard XFG table-dispatch function-pointer slot",
            "anchor state exists in a load-config structure too short to contain the GuardXFGTableDispatchFunctionPointer field",
        );
    }
    if load_config_size < LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE_U32
        && xfg_anchors
            .cast_guard_os_determined_failure_mode_rva
            .is_some()
    {
        return invalid_field(
            "CastGuard OS-determined failure-mode storage",
            "anchor state exists in a load-config structure too short to contain the CastGuardOsDeterminedFailureMode field",
        );
    }
    if load_config_size < LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE_U32
        && guard_memcpy_anchor
            .guard_memcpy_function_pointer_rva
            .is_some()
    {
        return invalid_field(
            "GuardMemcpy function-pointer slot",
            "anchor state exists in a load-config structure too short to contain the GuardMemcpyFunctionPointer field",
        );
    }

    validate_load_config_anchor_layout(
        anchors,
        xfg_anchors,
        guard_memcpy_anchor,
        directory,
        &analysis.sections,
    )
}

fn validate_guard_cf_functions(analysis: &PeAnalysis) -> Result<(), AnalysisError> {
    let Some(directory) = analysis.directories.load_config else {
        if analysis.load_config_size.is_some()
            || analysis.guard_flags.is_some()
            || analysis.guard_cf_function_table_rva.is_some()
            || !analysis.guard_cf_functions.is_empty()
        {
            return invalid_field(
                "GuardCF metadata",
                "load-config state exists without a load-config directory",
            );
        }
        return Ok(());
    };

    if directory.size < 4 {
        return invalid_field(
            "load-config directory size",
            "must contain the four-byte structure-size field",
        );
    }
    let load_config_size =
        analysis
            .load_config_size
            .ok_or_else(|| AnalysisError::InvalidField {
                field: "load-config size",
                reason: "a load-config directory exists without its declared structure size"
                    .to_owned(),
            })?;
    if load_config_size > directory.size {
        return invalid_field(
            "load-config size",
            "the structure declares more bytes than its data-directory entry",
        );
    }
    if load_config_size < 4 {
        return invalid_field(
            "load-config size",
            "must be at least four bytes when a load-config directory is present",
        );
    }
    if load_config_size < LOAD_CONFIG_GUARD_FIELDS_SIZE_U32 {
        if analysis.guard_flags.is_some()
            || analysis.guard_cf_function_table_rva.is_some()
            || !analysis.guard_cf_functions.is_empty()
        {
            return invalid_field(
                "GuardCF metadata",
                "state exists in a load-config structure too short to contain GuardCF fields",
            );
        }
        return Ok(());
    }

    let guard_flags = analysis
        .guard_flags
        .ok_or_else(|| AnalysisError::InvalidField {
            field: "GuardFlags",
            reason: "the load-config structure contains GuardCF fields but GuardFlags is absent"
                .to_owned(),
        })?;
    let table_present = guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT != 0;
    let metadata_size = usize::try_from(
        (guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
            >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT,
    )
    .map_err(|_| AnalysisError::IntegerConversion("GuardCF metadata size"))?;
    let record_size =
        4_usize
            .checked_add(metadata_size)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "GuardCF function-record size",
            ))?;

    let Some(table_rva) = analysis.guard_cf_function_table_rva else {
        if !analysis.guard_cf_functions.is_empty() {
            return invalid_field(
                "GuardCF function table",
                "entries exist without a table RVA",
            );
        }
        return Ok(());
    };
    if !table_present {
        return invalid_field(
            "GuardCF function table",
            "a table RVA exists while IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT is clear",
        );
    }
    if analysis.guard_cf_functions.is_empty() {
        return invalid_field(
            "GuardCF function table",
            "a nonzero table RVA exists without any records",
        );
    }

    let function_count = u64::try_from(analysis.guard_cf_functions.len())
        .map_err(|_| AnalysisError::IntegerConversion("GuardCF function count"))?;
    enforce_limit("GuardCF function", function_count, MAX_GUARD_CF_FUNCTIONS)?;
    let table_size = function_count
        .checked_mul(
            u64::try_from(record_size)
                .map_err(|_| AnalysisError::IntegerConversion("GuardCF record size"))?,
        )
        .ok_or(AnalysisError::ArithmeticOverflow(
            "GuardCF function-table byte size",
        ))?;
    enforce_limit(
        "GuardCF function-table byte",
        table_size,
        MAX_DIRECTORY_BYTES,
    )?;
    let table_size_u32 = u32::try_from(table_size)
        .map_err(|_| AnalysisError::IntegerConversion("GuardCF function-table byte size"))?;
    if !model_rva_is_backed(analysis, table_rva, table_size_u32) {
        return invalid_field("GuardCF function table", "is not fully backed by file data");
    }
    if ranges_overlap(
        u64::from(directory.rva),
        u64::from(directory.size),
        u64::from(table_rva),
        table_size,
    )? {
        return invalid_field(
            "GuardCF function table",
            "overlaps the declared load-config directory range",
        );
    }

    let mut previous_rva = None;
    for (index, function) in analysis.guard_cf_functions.iter().enumerate() {
        let expected_index = u32::try_from(index)
            .map_err(|_| AnalysisError::IntegerConversion("GuardCF function-table index"))?;
        if function.table_index != expected_index {
            return invalid_field(
                "GuardCF function-table index",
                "does not match source-table order",
            );
        }
        if function.metadata.len() != metadata_size {
            return invalid_field(
                "GuardCF function metadata",
                format!(
                    "entry {index} retains {} bytes instead of the GuardFlags-selected {metadata_size}",
                    function.metadata.len()
                ),
            );
        }
        if previous_rva.is_some_and(|previous| previous >= function.rva) {
            return invalid_field(
                "GuardCF function table",
                "RVAs must be strictly increasing and unique",
            );
        }
        let executable = section_for_rva(function.rva, &analysis.sections)
            .is_some_and(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            && model_rva_is_backed(analysis, function.rva, 1);
        if !executable {
            return invalid_field(
                "GuardCF function target",
                format!(
                    "entry {index} has RVA {:#x}, which is not fully file-backed executable data",
                    function.rva
                ),
            );
        }
        if function.is_export_suppressed()
            && function.rva % GUARD_CF_EXPORT_SUPPRESSED_ALIGNMENT != 0
        {
            return invalid_field(
                "GuardCF function target",
                format!(
                    "entry {index} has export-suppressed RVA {:#x}, which is not 16-byte aligned",
                    function.rva
                ),
            );
        }
        previous_rva = Some(function.rva);
    }
    Ok(())
}

fn guard_table_metadata_size(guard_flags: u32) -> Result<usize, AnalysisError> {
    usize::try_from(
        (guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
            >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT,
    )
    .map_err(|_| AnalysisError::IntegerConversion("Guard table metadata size"))
}

fn validated_guard_table_size(
    count: u64,
    record_size: usize,
    count_kind: &'static str,
    count_limit: u64,
    byte_kind: &'static str,
    overflow_context: &'static str,
) -> Result<u64, AnalysisError> {
    enforce_limit(count_kind, count, count_limit)?;
    let table_size = count
        .checked_mul(
            u64::try_from(record_size)
                .map_err(|_| AnalysisError::IntegerConversion("Guard table record size"))?,
        )
        .ok_or(AnalysisError::ArithmeticOverflow(overflow_context))?;
    enforce_limit(byte_kind, table_size, MAX_DIRECTORY_BYTES)?;
    Ok(table_size)
}

fn validate_guard_table_storage(
    analysis: &PeAnalysis,
    directory: DataDirectory,
    table_rva: u32,
    table_size: u64,
    field: &'static str,
) -> Result<(), AnalysisError> {
    let table_size_u32 = u32::try_from(table_size)
        .map_err(|_| AnalysisError::IntegerConversion("Guard table byte size"))?;
    if !model_rva_is_backed(analysis, table_rva, table_size_u32) {
        return invalid_field(field, "is not fully backed by file data");
    }
    if ranges_overlap(
        u64::from(directory.rva),
        u64::from(directory.size),
        u64::from(table_rva),
        table_size,
    )? {
        return invalid_field(field, "overlaps the declared load-config directory range");
    }
    Ok(())
}

fn validate_guard_address_taken_iat_table(
    analysis: &PeAnalysis,
    directory: DataDirectory,
    guard_flags: u32,
    import_iat_rvas: &BTreeSet<u32>,
) -> Result<Option<(&'static str, u32, u64)>, AnalysisError> {
    let Some(table_rva) = analysis.guard_address_taken_iat_entry_table_rva else {
        if !analysis.guard_address_taken_iat_entries.is_empty() {
            return invalid_field(
                "Guard address-taken IAT table",
                "entries exist without a table RVA",
            );
        }
        return Ok(None);
    };
    if guard_flags & IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT == 0 {
        return invalid_field(
            "Guard address-taken IAT table",
            "a table RVA exists while IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT is clear",
        );
    }
    if analysis.guard_address_taken_iat_entries.is_empty() {
        return invalid_field(
            "Guard address-taken IAT table",
            "a nonzero table RVA exists without any records",
        );
    }

    let metadata_size = guard_table_metadata_size(guard_flags)?;
    let record_size =
        4_usize
            .checked_add(metadata_size)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "Guard address-taken IAT record size",
            ))?;
    let count = u64::try_from(analysis.guard_address_taken_iat_entries.len())
        .map_err(|_| AnalysisError::IntegerConversion("Guard address-taken IAT entry count"))?;
    let table_size = validated_guard_table_size(
        count,
        record_size,
        "Guard address-taken IAT entry",
        MAX_GUARD_ADDRESS_TAKEN_IAT_ENTRIES,
        "Guard address-taken IAT table byte",
        "Guard address-taken IAT table byte size",
    )?;
    validate_guard_table_storage(
        analysis,
        directory,
        table_rva,
        table_size,
        "Guard address-taken IAT table",
    )?;

    let mut previous_rva = None;
    for (index, entry) in analysis.guard_address_taken_iat_entries.iter().enumerate() {
        let expected_index = u32::try_from(index)
            .map_err(|_| AnalysisError::IntegerConversion("Guard address-taken IAT index"))?;
        if entry.table_index != expected_index {
            return invalid_field(
                "Guard address-taken IAT table index",
                "does not match source-table order",
            );
        }
        if entry.metadata.len() != metadata_size {
            return invalid_field(
                "Guard address-taken IAT metadata",
                format!(
                    "entry {index} retains {} bytes instead of the GuardFlags-selected {metadata_size}",
                    entry.metadata.len()
                ),
            );
        }
        if entry.metadata.iter().any(|byte| *byte != 0) {
            return invalid_field(
                "Guard address-taken IAT metadata",
                format!("entry {index} has nonzero reserved metadata"),
            );
        }
        if previous_rva.is_some_and(|previous| previous >= entry.iat_rva) {
            return invalid_field(
                "Guard address-taken IAT table",
                "RVAs must be strictly increasing and unique",
            );
        }
        if !import_iat_rvas.contains(&entry.iat_rva) {
            return invalid_field(
                "Guard address-taken IAT entry",
                format!(
                    "entry {index} names RVA {:#x}, which is not an exact parsed import IAT slot",
                    entry.iat_rva
                ),
            );
        }
        previous_rva = Some(entry.iat_rva);
    }
    Ok(Some((
        "Guard address-taken IAT table",
        table_rva,
        table_size,
    )))
}

fn validate_guard_long_jump_table(
    analysis: &PeAnalysis,
    directory: DataDirectory,
    guard_flags: u32,
) -> Result<Option<(&'static str, u32, u64)>, AnalysisError> {
    let Some(table_rva) = analysis.guard_long_jump_target_table_rva else {
        if !analysis.guard_long_jump_targets.is_empty() {
            return invalid_field(
                "Guard long-jump target table",
                "entries exist without a table RVA",
            );
        }
        return Ok(None);
    };
    if guard_flags & IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT == 0 {
        return invalid_field(
            "Guard long-jump target table",
            "a table RVA exists while IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT is clear",
        );
    }
    if analysis.guard_long_jump_targets.is_empty() {
        return invalid_field(
            "Guard long-jump target table",
            "a nonzero table RVA exists without any records",
        );
    }

    let metadata_size = guard_table_metadata_size(guard_flags)?;
    let record_size =
        4_usize
            .checked_add(metadata_size)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "Guard long-jump record size",
            ))?;
    let count = u64::try_from(analysis.guard_long_jump_targets.len())
        .map_err(|_| AnalysisError::IntegerConversion("Guard long-jump target count"))?;
    let table_size = validated_guard_table_size(
        count,
        record_size,
        "Guard long-jump target",
        MAX_GUARD_LONG_JUMP_TARGETS,
        "Guard long-jump table byte",
        "Guard long-jump table byte size",
    )?;
    validate_guard_table_storage(
        analysis,
        directory,
        table_rva,
        table_size,
        "Guard long-jump target table",
    )?;

    let mut previous_rva = None;
    for (index, target) in analysis.guard_long_jump_targets.iter().enumerate() {
        let expected_index = u32::try_from(index)
            .map_err(|_| AnalysisError::IntegerConversion("Guard long-jump target index"))?;
        if target.table_index != expected_index {
            return invalid_field(
                "Guard long-jump target-table index",
                "does not match source-table order",
            );
        }
        if target.metadata.len() != metadata_size {
            return invalid_field(
                "Guard long-jump metadata",
                format!(
                    "entry {index} retains {} bytes instead of the GuardFlags-selected {metadata_size}",
                    target.metadata.len()
                ),
            );
        }
        if target.metadata.iter().any(|byte| *byte != 0) {
            return invalid_field(
                "Guard long-jump metadata",
                format!("entry {index} has nonzero reserved metadata"),
            );
        }
        if previous_rva.is_some_and(|previous| previous >= target.target_rva) {
            return invalid_field(
                "Guard long-jump target table",
                "RVAs must be strictly increasing and unique",
            );
        }
        let executable = section_for_rva(target.target_rva, &analysis.sections)
            .is_some_and(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            && model_rva_is_backed(analysis, target.target_rva, 1);
        if !executable {
            return invalid_field(
                "Guard long-jump target",
                format!(
                    "entry {index} has RVA {:#x}, which is not fully file-backed executable data",
                    target.target_rva
                ),
            );
        }
        previous_rva = Some(target.target_rva);
    }
    Ok(Some((
        "Guard long-jump target table",
        table_rva,
        table_size,
    )))
}

fn validate_guard_eh_continuation_table(
    analysis: &PeAnalysis,
    directory: DataDirectory,
    guard_flags: u32,
) -> Result<Option<(&'static str, u32, u64)>, AnalysisError> {
    let Some(table_rva) = analysis.guard_eh_continuation_table_rva else {
        if !analysis.guard_eh_continuation_targets.is_empty() {
            return invalid_field(
                "Guard EH-continuation table",
                "entries exist without a table RVA",
            );
        }
        return Ok(None);
    };
    if guard_flags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT == 0 {
        return invalid_field(
            "Guard EH-continuation table",
            "a table RVA exists while IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT is clear",
        );
    }
    if analysis.guard_eh_continuation_targets.is_empty() {
        return invalid_field(
            "Guard EH-continuation table",
            "a nonzero table RVA exists without any records",
        );
    }

    let metadata_size = guard_table_metadata_size(guard_flags)?;
    let record_size =
        4_usize
            .checked_add(metadata_size)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "Guard EH-continuation record size",
            ))?;
    let count = u64::try_from(analysis.guard_eh_continuation_targets.len())
        .map_err(|_| AnalysisError::IntegerConversion("Guard EH-continuation target count"))?;
    let table_size = validated_guard_table_size(
        count,
        record_size,
        "Guard EH-continuation target",
        MAX_GUARD_EH_CONTINUATION_TARGETS,
        "Guard EH-continuation table byte",
        "Guard EH-continuation table byte size",
    )?;
    validate_guard_table_storage(
        analysis,
        directory,
        table_rva,
        table_size,
        "Guard EH-continuation table",
    )?;

    let mut previous_rva = None;
    for (index, target) in analysis.guard_eh_continuation_targets.iter().enumerate() {
        let expected_index = u32::try_from(index)
            .map_err(|_| AnalysisError::IntegerConversion("Guard EH-continuation index"))?;
        if target.table_index != expected_index {
            return invalid_field(
                "Guard EH-continuation table index",
                "does not match source-table order",
            );
        }
        if target.metadata.len() != metadata_size {
            return invalid_field(
                "Guard EH-continuation metadata",
                format!(
                    "entry {index} retains {} bytes instead of the GuardFlags-selected {metadata_size}",
                    target.metadata.len()
                ),
            );
        }
        if target.metadata.iter().any(|byte| *byte != 0) {
            return invalid_field(
                "Guard EH-continuation metadata",
                format!("entry {index} has nonzero reserved metadata"),
            );
        }
        if previous_rva.is_some_and(|previous| previous >= target.target_rva) {
            return invalid_field(
                "Guard EH-continuation table",
                "RVAs must be strictly increasing and unique",
            );
        }
        let executable = section_for_rva(target.target_rva, &analysis.sections)
            .is_some_and(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            && model_rva_is_backed(analysis, target.target_rva, 1);
        if !executable {
            return invalid_field(
                "Guard EH-continuation target",
                format!(
                    "entry {index} has RVA {:#x}, which is not fully file-backed executable data",
                    target.target_rva
                ),
            );
        }
        previous_rva = Some(target.target_rva);
    }
    Ok(Some(("Guard EH-continuation table", table_rva, table_size)))
}

fn validate_tls_callbacks(analysis: &PeAnalysis) -> Result<(), AnalysisError> {
    match analysis.directories.tls {
        Some(directory) => {
            if directory.size < TLS_DIRECTORY_SIZE_U32 {
                return invalid_field(
                    "TLS directory size",
                    "must be at least the 40-byte PE32+ TLS directory size",
                );
            }
        }
        None => {
            if analysis.tls_callback_table_rva.is_some()
                || !analysis.tls_callbacks.is_empty()
                || analysis.tls_callback_scan_truncated
            {
                return invalid_field(
                    "TLS callbacks",
                    "a callback table, entries, or a partial scan exists without a TLS directory",
                );
            }
            return Ok(());
        }
    }

    let Some(table_rva) = analysis.tls_callback_table_rva else {
        if !analysis.tls_callbacks.is_empty() || analysis.tls_callback_scan_truncated {
            return invalid_field(
                "TLS callbacks",
                "entries or a partial scan exist without a callback-table RVA",
            );
        }
        return Ok(());
    };

    let callback_count = u64::try_from(analysis.tls_callbacks.len())
        .map_err(|_| AnalysisError::IntegerConversion("TLS callback count"))?;
    enforce_limit("TLS callback", callback_count, MAX_TLS_CALLBACKS)?;
    if analysis.tls_callback_scan_truncated && callback_count != MAX_TLS_CALLBACKS {
        return invalid_field(
            "TLS callback scan state",
            "can be partial only after retaining the full callback cap",
        );
    }

    for (index, callback) in analysis.tls_callbacks.iter().enumerate() {
        let expected_index = u32::try_from(index)
            .map_err(|_| AnalysisError::IntegerConversion("TLS callback table index"))?;
        if callback.table_index != expected_index {
            return invalid_field(
                "TLS callback table index",
                format!(
                    "entry {index} records index {} instead of {expected_index}",
                    callback.table_index
                ),
            );
        }
        let slot_delta = expected_index
            .checked_mul(8)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "TLS callback slot position",
            ))?;
        let slot_rva = table_rva
            .checked_add(slot_delta)
            .ok_or(AnalysisError::ArithmeticOverflow("TLS callback slot RVA"))?;
        if !model_rva_is_backed(analysis, slot_rva, 8) {
            return invalid_field(
                "TLS callback slot",
                format!("entry {index} at RVA {slot_rva:#x} is not fully backed by file data"),
            );
        }
        let executable = section_for_rva(callback.callback_rva, &analysis.sections)
            .is_some_and(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            && model_rva_is_backed(analysis, callback.callback_rva, 1);
        if !executable {
            return invalid_field(
                "TLS callback target",
                format!(
                    "entry {index} resolves to RVA {:#x}, which is not fully file-backed executable data",
                    callback.callback_rva
                ),
            );
        }
    }

    let next_index = u32::try_from(analysis.tls_callbacks.len())
        .map_err(|_| AnalysisError::IntegerConversion("TLS callback terminator index"))?;
    let next_delta = next_index
        .checked_mul(8)
        .ok_or(AnalysisError::ArithmeticOverflow(
            "TLS callback terminator position",
        ))?;
    let next_slot_rva =
        table_rva
            .checked_add(next_delta)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "TLS callback terminator RVA",
            ))?;
    if !model_rva_is_backed(analysis, next_slot_rva, 8) {
        return invalid_field(
            "TLS callback terminator",
            format!(
                "slot at RVA {next_slot_rva:#x} after the retained callbacks is not fully backed by file data"
            ),
        );
    }
    Ok(())
}

fn symbol_graph_semantically_matches(expected: &SymbolGraph, actual: &SymbolGraph) -> bool {
    if expected.binaries() != actual.binaries() || expected.claims().len() != actual.claims().len()
    {
        return false;
    }
    expected
        .claims()
        .iter()
        .zip(actual.claims())
        .all(|(expected, actual)| {
            let provenance_method_matches =
                expected.provenance().method == actual.provenance().method;
            expected.subject() == actual.subject()
                && expected.assertion() == actual.assertion()
                && expected.confidence() == actual.confidence()
                && provenance_method_matches
                && evidence_semantically_matches(
                    expected.evidence(),
                    actual.evidence(),
                    &expected.provenance().method,
                )
                && expected.provenance().run_id == actual.provenance().run_id
                && producers_semantically_match(
                    &expected.provenance().producer,
                    &actual.provenance().producer,
                )
        })
}

fn evidence_semantically_matches(
    expected: &[Evidence],
    actual: &[Evidence],
    provenance_method: &str,
) -> bool {
    expected.len() == actual.len()
        && expected.iter().zip(actual).all(|(expected, actual)| {
            expected == actual
                || (provenance_method == "pe-x64-direct-call"
                    && expected.summary == DIRECT_CALL_EVIDENCE_SUMMARY
                    && actual.summary == LEGACY_DIRECT_CALL_EVIDENCE_SUMMARY
                    && expected.kind == actual.kind
                    && expected.confidence == actual.confidence
                    && expected.artifacts == actual.artifacts)
                || (provenance_method == "pe-x64-jump-thunk"
                    && expected.summary == THUNK_EVIDENCE_SUMMARY
                    && actual.summary == LEGACY_THUNK_EVIDENCE_SUMMARY
                    && expected.kind == actual.kind
                    && expected.confidence == actual.confidence
                    && expected.artifacts == actual.artifacts)
        })
}

fn producers_semantically_match(expected: &ClaimProducer, actual: &ClaimProducer) -> bool {
    match (expected, actual) {
        (
            ClaimProducer::Core {
                component: expected_component,
                ..
            },
            ClaimProducer::Core {
                component: actual_component,
                version: actual_version,
            },
        ) => expected_component == actual_component && valid_provenance_version(actual_version),
        _ => expected == actual,
    }
}

fn valid_provenance_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_PROVENANCE_VERSION_BYTES
        && version.trim() == version
        && !version.chars().any(char::is_control)
}

fn model_rva_is_backed(analysis: &PeAnalysis, rva: u32, size: u32) -> bool {
    let end = u64::from(rva).checked_add(u64::from(size));
    let Some(end) = end else {
        return false;
    };
    if rva < analysis.size_of_headers
        && end <= u64::from(analysis.size_of_headers)
        && end <= analysis.identity.size
    {
        return true;
    }
    analysis.sections.iter().any(|section| {
        let start = u64::from(section.virtual_address);
        let backed_end = start.saturating_add(u64::from(section.file_backed_size()));
        u64::from(rva) >= start && end <= backed_end
    })
}

fn model_rva_is_mapped_section_range(analysis: &PeAnalysis, rva: u32, size: u32) -> bool {
    section_for_rva_range(rva, size, &analysis.sections).is_some()
}

fn parse_headers(reader: &Reader<'_>) -> Result<ParsedHeaders, AnalysisError> {
    if reader.len() < 2 || reader.bytes(0, 2, "DOS signature")? != b"MZ" {
        let found = reader
            .data
            .get(..reader.len().min(2))
            .map_or_else(String::new, format_hex);
        return Err(AnalysisError::InvalidDosSignature { found });
    }
    reader.bytes(0, DOS_HEADER_SIZE, "DOS header")?;

    let pe_offset_u32 = reader.u32(0x3c, "DOS e_lfanew")?;
    if pe_offset_u32 > MAX_PE_HEADER_OFFSET {
        return Err(AnalysisError::PeHeaderOffsetLimit {
            offset: pe_offset_u32,
            limit: MAX_PE_HEADER_OFFSET,
        });
    }
    let pe_offset = usize::try_from(pe_offset_u32)
        .map_err(|_| AnalysisError::IntegerConversion("PE header offset"))?;
    if pe_offset < DOS_HEADER_SIZE {
        return invalid_field("DOS e_lfanew", "PE header overlaps the DOS header");
    }
    if reader.bytes(pe_offset, PE_SIGNATURE_SIZE, "PE signature")? != b"PE\0\0" {
        return Err(AnalysisError::InvalidPeSignature { offset: pe_offset });
    }

    let coff_offset = checked_add(pe_offset, PE_SIGNATURE_SIZE, "COFF header offset")?;
    reader.bytes(coff_offset, COFF_HEADER_SIZE, "COFF header")?;
    let machine = reader.u16(coff_offset, "COFF machine")?;
    if machine != MACHINE_AMD64 {
        return Err(AnalysisError::UnsupportedMachine {
            machine,
            expected: MACHINE_AMD64,
        });
    }
    let number_of_sections = reader.u16(coff_offset + 2, "COFF section count")?;
    enforce_limit("section", u64::from(number_of_sections), MAX_SECTIONS)?;
    let timestamp = reader.u32(coff_offset + 4, "COFF timestamp")?;
    let symbol_table_offset = reader.u32(coff_offset + 8, "COFF symbol-table offset")?;
    let number_of_symbols = reader.u32(coff_offset + 12, "COFF symbol count")?;
    let optional_header_size = reader.u16(coff_offset + 16, "COFF optional-header size")?;
    let optional_size = usize::from(optional_header_size);
    let characteristics = reader.u16(coff_offset + 18, "COFF characteristics")?;
    if optional_size < OPTIONAL_HEADER_MIN_SIZE {
        return Err(AnalysisError::OptionalHeaderTooSmall {
            actual: optional_size,
            minimum: OPTIONAL_HEADER_MIN_SIZE,
        });
    }

    let optional_offset = checked_add(coff_offset, COFF_HEADER_SIZE, "optional-header offset")?;
    reader.bytes(optional_offset, optional_size, "PE32+ optional header")?;
    let optional_magic = reader.u16(optional_offset, "optional-header magic")?;
    if optional_magic != OPTIONAL_MAGIC_PE32_PLUS {
        return Err(AnalysisError::UnsupportedOptionalHeader {
            magic: optional_magic,
            expected: OPTIONAL_MAGIC_PE32_PLUS,
        });
    }

    let entry_point_rva = reader.u32(optional_offset + 16, "entry-point RVA")?;
    let image_base = reader.u64(optional_offset + 24, "image base")?;
    let section_alignment = reader.u32(optional_offset + 32, "section alignment")?;
    let file_alignment = reader.u32(optional_offset + 36, "file alignment")?;
    let size_of_image = reader.u32(optional_offset + 56, "size of image")?;
    let size_of_headers = reader.u32(optional_offset + 60, "size of headers")?;
    let subsystem = reader.u16(optional_offset + 68, "subsystem")?;
    let dll_characteristics = reader.u16(optional_offset + 70, "DLL characteristics")?;
    if size_of_image == 0 {
        return invalid_field("size of image", "must be non-zero");
    }
    if size_of_headers == 0 {
        return invalid_field("size of headers", "must be non-zero");
    }
    if size_of_headers > size_of_image {
        return invalid_field("size of headers", "must not exceed the declared image size");
    }
    validate_image_alignment(
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
    )?;
    if entry_point_rva >= size_of_image && entry_point_rva != 0 {
        return invalid_field("entry-point RVA", "lies outside the declared image");
    }
    let headers_size = usize::try_from(size_of_headers)
        .map_err(|_| AnalysisError::IntegerConversion("size of headers"))?;
    reader.bytes(0, headers_size, "declared PE headers")?;

    let directory_count = reader.u32(optional_offset + 108, "data-directory count")?;
    enforce_limit(
        "data-directory",
        u64::from(directory_count),
        MAX_DATA_DIRECTORIES,
    )?;
    let directories_size = checked_mul(
        usize::try_from(directory_count)
            .map_err(|_| AnalysisError::IntegerConversion("data-directory count"))?,
        DATA_DIRECTORY_SIZE,
        "data-directory table size",
    )?;
    let required_optional_size = checked_add(
        OPTIONAL_HEADER_MIN_SIZE,
        directories_size,
        "required optional-header size",
    )?;
    if optional_size < required_optional_size {
        return Err(AnalysisError::OptionalHeaderTooSmall {
            actual: optional_size,
            minimum: required_optional_size,
        });
    }

    let directories = PeDataDirectories {
        exports: read_directory(
            reader,
            optional_offset,
            directory_count,
            EXPORT_DIRECTORY_INDEX,
            "export directory",
        )?,
        imports: read_directory(
            reader,
            optional_offset,
            directory_count,
            IMPORT_DIRECTORY_INDEX,
            "import directory",
        )?,
        exceptions: read_directory(
            reader,
            optional_offset,
            directory_count,
            EXCEPTION_DIRECTORY_INDEX,
            "exception directory",
        )?,
        load_config: read_directory(
            reader,
            optional_offset,
            directory_count,
            LOAD_CONFIG_DIRECTORY_INDEX,
            "load-config directory",
        )?,
        tls: read_directory(
            reader,
            optional_offset,
            directory_count,
            TLS_DIRECTORY_INDEX,
            "TLS directory",
        )?,
        delay_imports: read_directory(
            reader,
            optional_offset,
            directory_count,
            DELAY_IMPORT_DIRECTORY_INDEX,
            "delay-import directory",
        )?,
    };
    let debug_directory = read_directory(
        reader,
        optional_offset,
        directory_count,
        DEBUG_DIRECTORY_INDEX,
        "debug directory",
    )?;

    let sections_offset = checked_add(optional_offset, optional_size, "section-table offset")?;
    let section_table_size = checked_mul(
        usize::from(number_of_sections),
        SECTION_HEADER_SIZE,
        "section-table size",
    )?;
    let section_table_end = checked_add(sections_offset, section_table_size, "section-table end")?;
    if section_table_end > headers_size {
        return invalid_field("section table", "extends beyond the declared PE headers");
    }
    reader.bytes(sections_offset, section_table_size, "section table")?;
    let mut sections = Vec::with_capacity(usize::from(number_of_sections));
    for index in 0..usize::from(number_of_sections) {
        let offset = checked_add(
            sections_offset,
            checked_mul(index, SECTION_HEADER_SIZE, "section-header position")?,
            "section-header offset",
        )?;
        let raw_name_slice = reader.bytes(offset, 8, "section name")?;
        let mut raw_name = [0_u8; 8];
        raw_name.copy_from_slice(raw_name_slice);
        let virtual_size = reader.u32(offset + 8, "section virtual size")?;
        let virtual_address = reader.u32(offset + 12, "section virtual address")?;
        let raw_data_size = reader.u32(offset + 16, "section raw-data size")?;
        let raw_data_offset = reader.u32(offset + 20, "section raw-data offset")?;
        let characteristics = reader.u32(offset + 36, "section characteristics")?;

        let section = PeSection {
            name: display_section_name(&raw_name),
            raw_name,
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size,
            characteristics,
        };
        validate_section_alignment(index, &section, section_alignment, file_alignment)?;
        let virtual_span = section.loaded_size();
        let virtual_end =
            virtual_address
                .checked_add(virtual_span)
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "section virtual-address range",
                ))?;
        if virtual_end > size_of_image {
            return invalid_field(
                "section virtual range",
                format!("section {index} extends outside the declared image"),
            );
        }
        if virtual_span != 0 && virtual_address < size_of_headers {
            return invalid_field(
                "section virtual range",
                format!("section {index} overlaps the PE headers"),
            );
        }
        if raw_data_size != 0 {
            let raw_offset = usize::try_from(raw_data_offset)
                .map_err(|_| AnalysisError::IntegerConversion("section raw-data offset"))?;
            let raw_size = usize::try_from(raw_data_size)
                .map_err(|_| AnalysisError::IntegerConversion("section raw-data size"))?;
            reader.bytes(raw_offset, raw_size, "section raw data")?;
            if raw_data_offset < size_of_headers {
                return invalid_field(
                    "section raw range",
                    format!("section {index} overlaps the PE headers"),
                );
            }
        }

        sections.push(section);
    }
    validate_section_overlaps(&sections)?;

    Ok(ParsedHeaders {
        pe_header_offset: pe_offset_u32,
        coff: CoffHeader {
            machine,
            number_of_sections,
            timestamp,
            symbol_table_offset,
            number_of_symbols,
            optional_header_size,
            characteristics,
        },
        entry_point_rva,
        image_base,
        size_of_image,
        size_of_headers,
        section_alignment,
        file_alignment,
        subsystem,
        dll_characteristics,
        directories,
        debug_directory,
        sections,
    })
}

fn read_directory(
    reader: &Reader<'_>,
    optional_offset: usize,
    count: u32,
    index: usize,
    field: &'static str,
) -> Result<Option<DataDirectory>, AnalysisError> {
    if u32::try_from(index).map_err(|_| AnalysisError::IntegerConversion(field))? >= count {
        return Ok(None);
    }
    let directory_table_offset = checked_add(
        optional_offset,
        OPTIONAL_HEADER_MIN_SIZE,
        "data-directory table offset",
    )?;
    let offset = checked_add(
        directory_table_offset,
        checked_mul(index, DATA_DIRECTORY_SIZE, "data-directory position")?,
        "data-directory offset",
    )?;
    let rva = reader.u32(offset, field)?;
    let size = reader.u32(offset + 4, field)?;
    match (rva, size) {
        (0, 0) => Ok(None),
        (0, _) | (_, 0) => invalid_field(
            field,
            "RVA and size must either both be zero or both be non-zero",
        ),
        _ => Ok(Some(DataDirectory { rva, size })),
    }
}

fn parse_imports(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    directory: Option<DataDirectory>,
    budget: &mut ImportBudget,
) -> Result<Vec<PeImportLibrary>, AnalysisError> {
    let Some(directory) = directory else {
        return Ok(Vec::new());
    };
    enforce_directory_size("import-directory byte", directory.size)?;
    if directory.size % IMPORT_DESCRIPTOR_SIZE_U32 != 0 {
        return invalid_field(
            "import directory size",
            "must be a multiple of the 20-byte descriptor size",
        );
    }
    let descriptor_count = u64::from(directory.size) / u64::from(IMPORT_DESCRIPTOR_SIZE_U32);
    enforce_limit(
        "import-library descriptor",
        descriptor_count,
        MAX_IMPORT_DESCRIPTORS,
    )?;
    let directory_size = usize::try_from(directory.size)
        .map_err(|_| AnalysisError::IntegerConversion("import-directory size"))?;
    let directory_offset = mapper.offset(directory.rva, directory_size, "import directory")?;

    let mut libraries = Vec::new();
    let mut terminated = false;
    for index in 0..usize::try_from(descriptor_count)
        .map_err(|_| AnalysisError::IntegerConversion("import descriptor count"))?
    {
        let offset = checked_add(
            directory_offset,
            checked_mul(index, IMPORT_DESCRIPTOR_SIZE, "import-descriptor position")?,
            "import-descriptor offset",
        )?;
        let original_first_thunk = reader.u32(offset, "import lookup-table RVA")?;
        let timestamp = reader.u32(offset + 4, "import timestamp")?;
        let forwarder_chain = reader.u32(offset + 8, "import forwarder chain")?;
        let name_rva = reader.u32(offset + 12, "import DLL-name RVA")?;
        let first_thunk = reader.u32(offset + 16, "import address-table RVA")?;
        if original_first_thunk == 0
            && timestamp == 0
            && forwarder_chain == 0
            && name_rva == 0
            && first_thunk == 0
        {
            terminated = true;
            break;
        }
        if name_rva == 0 || first_thunk == 0 {
            return invalid_field(
                "import descriptor",
                format!("descriptor {index} has a zero DLL-name or IAT RVA"),
            );
        }
        consume_count_budget(
            &mut budget.libraries,
            "import library",
            MAX_IMPORT_LIBRARIES,
        )?;
        let name = mapper.c_string(name_rva, "import DLL name", MAX_STRING_BYTES)?;
        if name.is_empty() {
            return invalid_field(
                "import DLL name",
                format!("descriptor {index} has an empty name"),
            );
        }
        consume_string_budget(
            &mut budget.name_bytes,
            &name,
            "import-name byte",
            MAX_IMPORT_NAME_BYTES,
        )?;
        let lookup_table_rva = if original_first_thunk == 0 {
            first_thunk
        } else {
            original_first_thunk
        };
        let entries =
            parse_import_thunks(reader, mapper, lookup_table_rva, first_thunk, budget, false)?;
        let descriptor_delta = checked_u32_mul(
            u32::try_from(index)
                .map_err(|_| AnalysisError::IntegerConversion("import descriptor index"))?,
            IMPORT_DESCRIPTOR_SIZE_U32,
            "import descriptor RVA",
        )?;
        libraries.push(PeImportLibrary {
            name,
            descriptor_rva: checked_u32_add(
                directory.rva,
                descriptor_delta,
                "import descriptor RVA",
            )?,
            timestamp,
            forwarder_chain,
            entries,
        });
    }
    if !terminated {
        return Err(AnalysisError::MissingTerminator {
            context: "import directory",
        });
    }
    Ok(libraries)
}

fn parse_delay_imports(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    directory: Option<DataDirectory>,
    budget: &mut ImportBudget,
) -> Result<Vec<PeDelayImportLibrary>, AnalysisError> {
    let Some(directory) = directory else {
        return Ok(Vec::new());
    };
    enforce_directory_size("delay-import-directory byte", directory.size)?;
    if directory.size % DELAY_IMPORT_DESCRIPTOR_SIZE_U32 != 0 {
        return invalid_field(
            "delay-import directory size",
            "must be a multiple of the 32-byte descriptor size",
        );
    }
    let descriptor_count = u64::from(directory.size) / u64::from(DELAY_IMPORT_DESCRIPTOR_SIZE_U32);
    enforce_limit(
        "delay-import-library descriptor",
        descriptor_count,
        MAX_IMPORT_DESCRIPTORS,
    )?;
    let directory_size = usize::try_from(directory.size)
        .map_err(|_| AnalysisError::IntegerConversion("delay-import-directory size"))?;
    let directory_offset =
        mapper.offset(directory.rva, directory_size, "delay-import directory")?;

    let mut libraries = Vec::new();
    let mut terminated = false;
    for index in 0..usize::try_from(descriptor_count)
        .map_err(|_| AnalysisError::IntegerConversion("delay-import descriptor count"))?
    {
        let offset = checked_add(
            directory_offset,
            checked_mul(
                index,
                DELAY_IMPORT_DESCRIPTOR_SIZE,
                "delay-import-descriptor position",
            )?,
            "delay-import-descriptor offset",
        )?;
        let attributes = reader.u32(offset, "delay-import attributes")?;
        let name_rva = reader.u32(offset + 4, "delay-import DLL-name RVA")?;
        let module_handle_rva = reader.u32(offset + 8, "delay-import module-handle RVA")?;
        let iat_rva = reader.u32(offset + 12, "delay-import address-table RVA")?;
        let int_rva = reader.u32(offset + 16, "delay-import name-table RVA")?;
        let bound_iat_rva = reader.u32(offset + 20, "bound delay-import table RVA")?;
        let unload_iat_rva = reader.u32(offset + 24, "unload delay-import table RVA")?;
        let timestamp = reader.u32(offset + 28, "delay-import timestamp")?;
        if attributes == 0
            && name_rva == 0
            && module_handle_rva == 0
            && iat_rva == 0
            && int_rva == 0
            && bound_iat_rva == 0
            && unload_iat_rva == 0
            && timestamp == 0
        {
            terminated = true;
            continue;
        }
        if terminated {
            return invalid_field(
                "delay-import directory",
                format!("descriptor {index} is nonzero after the null terminator"),
            );
        }
        if attributes != DELAY_IMPORT_ATTRIBUTE_RVA {
            return invalid_field(
                "delay-import attributes",
                format!(
                    "descriptor {index} uses {attributes:#x}; only the modern dlattrRva value {DELAY_IMPORT_ATTRIBUTE_RVA:#x} is supported"
                ),
            );
        }
        if name_rva == 0 || module_handle_rva == 0 || iat_rva == 0 || int_rva == 0 {
            return invalid_field(
                "delay-import descriptor",
                format!("descriptor {index} has a zero DLL-name, module-handle, IAT, or INT RVA"),
            );
        }
        consume_count_budget(
            &mut budget.libraries,
            "import library",
            MAX_IMPORT_LIBRARIES,
        )?;
        let name = mapper.c_string(name_rva, "delay-import DLL name", MAX_STRING_BYTES)?;
        if name.is_empty() {
            return invalid_field(
                "delay-import DLL name",
                format!("descriptor {index} has an empty name"),
            );
        }
        consume_string_budget(
            &mut budget.name_bytes,
            &name,
            "import-name byte",
            MAX_IMPORT_NAME_BYTES,
        )?;
        if section_for_rva_range(module_handle_rva, 8, mapper.sections).is_none() {
            return invalid_field(
                "delay-import module-handle storage",
                format!(
                    "descriptor {index} has an eight-byte range that is not wholly mapped inside one section"
                ),
            );
        }
        let entries = parse_import_thunks(reader, mapper, int_rva, iat_rva, budget, true)?;
        let table_slots = entries
            .len()
            .checked_add(1)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "delay-import auxiliary table slot count",
            ))?;
        let table_size = checked_mul(table_slots, 8, "delay-import auxiliary table byte size")?;
        let iat_table_offset = mapper.offset(iat_rva, table_size, "delay-import address table")?;
        let iat_table = reader.bytes(iat_table_offset, table_size, "delay-import address table")?;
        for (table_rva, context) in [
            (bound_iat_rva, "bound delay-import table"),
            (unload_iat_rva, "unload delay-import table"),
        ] {
            if table_rva != 0 {
                let table_offset = mapper.offset(table_rva, table_size, context)?;
                let terminator_offset = checked_add(
                    table_offset,
                    checked_mul(
                        entries.len(),
                        8,
                        "delay-import auxiliary terminator position",
                    )?,
                    "delay-import auxiliary terminator offset",
                )?;
                if reader.u64(terminator_offset, context)? != 0 {
                    return invalid_field(context, "does not end at the matching thunk index");
                }
                if table_rva == unload_iat_rva
                    && reader.bytes(table_offset, table_size, context)? != iat_table
                {
                    return invalid_field(
                        "unload delay-import table",
                        "must be an exact copy of the original delay IAT",
                    );
                }
            }
        }
        let table_size = u64::try_from(table_size)
            .map_err(|_| AnalysisError::IntegerConversion("delay-import table byte size"))?;
        let table_ranges = [
            ("delay-import INT", Some(int_rva)),
            ("delay-import IAT", Some(iat_rva)),
            (
                "bound delay-import table",
                (bound_iat_rva != 0).then_some(bound_iat_rva),
            ),
            (
                "unload delay-import table",
                (unload_iat_rva != 0).then_some(unload_iat_rva),
            ),
        ];
        for first in 0..table_ranges.len() {
            let Some(first_rva) = table_ranges[first].1 else {
                continue;
            };
            for second in first + 1..table_ranges.len() {
                let Some(second_rva) = table_ranges[second].1 else {
                    continue;
                };
                if ranges_overlap(
                    u64::from(first_rva),
                    table_size,
                    u64::from(second_rva),
                    table_size,
                )? {
                    return invalid_field(
                        "delay-import tables",
                        format!(
                            "{} overlaps {}",
                            table_ranges[first].0, table_ranges[second].0
                        ),
                    );
                }
            }
        }
        let descriptor_delta = checked_u32_mul(
            u32::try_from(index)
                .map_err(|_| AnalysisError::IntegerConversion("delay-import descriptor index"))?,
            DELAY_IMPORT_DESCRIPTOR_SIZE_U32,
            "delay-import descriptor RVA",
        )?;
        libraries.push(PeDelayImportLibrary {
            name,
            descriptor_rva: checked_u32_add(
                directory.rva,
                descriptor_delta,
                "delay-import descriptor RVA",
            )?,
            attributes,
            name_rva,
            module_handle_rva,
            iat_rva,
            int_rva,
            bound_iat_rva: (bound_iat_rva != 0).then_some(bound_iat_rva),
            unload_iat_rva: (unload_iat_rva != 0).then_some(unload_iat_rva),
            timestamp,
            entries,
        });
    }
    if !terminated {
        return Err(AnalysisError::MissingTerminator {
            context: "delay-import directory",
        });
    }
    Ok(libraries)
}

fn parse_import_thunks(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    lookup_table_rva: u32,
    first_thunk_rva: u32,
    budget: &mut ImportBudget,
    require_iat_terminator: bool,
) -> Result<Vec<PeImport>, AnalysisError> {
    let mut entries = Vec::new();
    loop {
        enforce_limit("import symbol", budget.symbols, MAX_IMPORT_SYMBOLS)?;
        let index = u32::try_from(entries.len())
            .map_err(|_| AnalysisError::IntegerConversion("import thunk index"))?;
        let delta = checked_u32_mul(index, 8, "import thunk position")?;
        let lookup_rva = checked_u32_add(lookup_table_rva, delta, "import lookup RVA")?;
        let iat_rva = checked_u32_add(first_thunk_rva, delta, "import IAT RVA")?;
        let lookup_offset = mapper.offset(lookup_rva, 8, "import lookup thunk")?;
        let iat_offset = mapper.offset(iat_rva, 8, "import address thunk")?;
        let value = reader.u64(lookup_offset, "import lookup thunk")?;
        let delay_iat_value = require_iat_terminator
            .then(|| reader.u64(iat_offset, "delay-import IAT thunk"))
            .transpose()?;
        if value == 0 {
            if delay_iat_value.is_some_and(|value| value != 0) {
                return invalid_field(
                    "delay-import IAT terminator",
                    "must be zero at the same index as the INT terminator",
                );
            }
            break;
        }
        if delay_iat_value == Some(0) {
            return invalid_field(
                "delay-import IAT thunk",
                "must be nonzero while the corresponding INT entry is present",
            );
        }
        consume_count_budget(&mut budget.symbols, "import symbol", MAX_IMPORT_SYMBOLS)?;
        if !budget.iat_rvas.insert(iat_rva) {
            return invalid_field(
                "import IAT slot",
                format!("RVA {iat_rva:#x} is claimed by more than one import entry"),
            );
        }

        let target = if value & IMPORT_BY_ORDINAL_64 != 0 {
            if value & 0x7fff_ffff_ffff_0000 != 0 {
                return invalid_field(
                    "ordinal import thunk",
                    format!("reserved bits are set in {value:#018x}"),
                );
            }
            ImportTarget::Ordinal {
                ordinal: u16::try_from(value & 0xffff)
                    .map_err(|_| AnalysisError::IntegerConversion("import ordinal"))?,
            }
        } else {
            if value & 0x7fff_ffff_8000_0000 != 0 {
                return invalid_field(
                    "name import thunk",
                    format!("reserved bits are set in {value:#018x}"),
                );
            }
            let hint_name_rva = u32::try_from(value).map_err(|_| AnalysisError::InvalidField {
                field: "name import thunk",
                reason: format!("RVA {value:#x} does not fit in 32 bits"),
            })?;
            let hint_offset = mapper.offset(hint_name_rva, 2, "import hint")?;
            let hint = reader.u16(hint_offset, "import hint")?;
            let symbol_name_rva = checked_u32_add(hint_name_rva, 2, "import-name RVA")?;
            let name = mapper.c_string(symbol_name_rva, "import symbol name", MAX_STRING_BYTES)?;
            if name.is_empty() {
                return invalid_field("import symbol name", "must not be empty");
            }
            consume_string_budget(
                &mut budget.name_bytes,
                &name,
                "import-name byte",
                MAX_IMPORT_NAME_BYTES,
            )?;
            ImportTarget::Name { hint, name }
        };

        entries.push(PeImport {
            lookup_rva,
            iat_rva,
            target,
        });
    }
    Ok(entries)
}

fn parse_exports(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    directory: Option<DataDirectory>,
    size_of_image: u32,
) -> Result<(Option<String>, Vec<PeExport>), AnalysisError> {
    let Some(directory) = directory else {
        return Ok((None, Vec::new()));
    };
    enforce_directory_size("export-directory byte", directory.size)?;
    if directory.size < 40 {
        return invalid_field("export directory size", "must be at least 40 bytes");
    }
    let directory_size = usize::try_from(directory.size)
        .map_err(|_| AnalysisError::IntegerConversion("export-directory size"))?;
    let directory_offset = mapper.offset(directory.rva, directory_size, "export directory")?;
    let library_name_rva = reader.u32(directory_offset + 12, "export DLL-name RVA")?;
    let ordinal_base = reader.u32(directory_offset + 16, "export ordinal base")?;
    let function_count = reader.u32(directory_offset + 20, "export function count")?;
    let name_count = reader.u32(directory_offset + 24, "export name count")?;
    let function_table_rva = reader.u32(directory_offset + 28, "export address-table RVA")?;
    let name_table_rva = reader.u32(directory_offset + 32, "export name-table RVA")?;
    let ordinal_table_rva = reader.u32(directory_offset + 36, "export ordinal-table RVA")?;
    enforce_limit(
        "export function",
        u64::from(function_count),
        MAX_EXPORT_FUNCTIONS,
    )?;
    enforce_limit("export name", u64::from(name_count), MAX_EXPORT_NAMES)?;
    if name_count != 0 && function_count == 0 {
        return invalid_field(
            "export directory",
            "contains names but no export-address-table entries",
        );
    }
    if function_count != 0 && function_table_rva == 0 {
        return invalid_field("export address table", "RVA must be non-zero");
    }
    if name_count != 0 && (name_table_rva == 0 || ordinal_table_rva == 0) {
        return invalid_field("export name tables", "RVAs must be non-zero");
    }

    let mut total_name_bytes = 0_u64;
    let export_library_name = if library_name_rva == 0 {
        None
    } else {
        let name = mapper.c_string(library_name_rva, "export DLL name", MAX_STRING_BYTES)?;
        if name.is_empty() {
            return invalid_field("export DLL name", "must not be empty");
        }
        consume_string_budget(
            &mut total_name_bytes,
            &name,
            "export-name byte",
            MAX_EXPORT_NAME_BYTES,
        )?;
        Some(name)
    };

    let function_count_usize = usize::try_from(function_count)
        .map_err(|_| AnalysisError::IntegerConversion("export function count"))?;
    let function_bytes = checked_mul(function_count_usize, 4, "export address-table size")?;
    let function_offset = if function_bytes == 0 {
        0
    } else {
        mapper.offset(function_table_rva, function_bytes, "export address table")?
    };
    let mut exports = Vec::with_capacity(function_count_usize);
    for index in 0..function_count_usize {
        let address = reader.u32(
            checked_add(
                function_offset,
                checked_mul(index, 4, "export address position")?,
                "export address offset",
            )?,
            "export address",
        )?;
        let index_u32 = u32::try_from(index)
            .map_err(|_| AnalysisError::IntegerConversion("export function index"))?;
        let ordinal = ordinal_base
            .checked_add(index_u32)
            .ok_or(AnalysisError::ArithmeticOverflow("export ordinal"))?;
        exports.push(PeExport {
            ordinal,
            address_rva: (address != 0).then_some(address),
            names: Vec::new(),
            forwarded_to: None,
        });
    }

    let name_count_usize = usize::try_from(name_count)
        .map_err(|_| AnalysisError::IntegerConversion("export name count"))?;
    if name_count_usize != 0 {
        let name_pointer_bytes = checked_mul(name_count_usize, 4, "export name-table size")?;
        let ordinal_bytes = checked_mul(name_count_usize, 2, "export ordinal-table size")?;
        let name_pointer_offset = mapper.offset(
            name_table_rva,
            name_pointer_bytes,
            "export name-pointer table",
        )?;
        let ordinal_offset =
            mapper.offset(ordinal_table_rva, ordinal_bytes, "export ordinal table")?;
        for index in 0..name_count_usize {
            let name_rva = reader.u32(
                checked_add(
                    name_pointer_offset,
                    checked_mul(index, 4, "export name-pointer position")?,
                    "export name-pointer offset",
                )?,
                "export name RVA",
            )?;
            if name_rva == 0 {
                return invalid_field("export name RVA", "must be non-zero");
            }
            let ordinal_index = usize::from(reader.u16(
                checked_add(
                    ordinal_offset,
                    checked_mul(index, 2, "export ordinal position")?,
                    "export ordinal offset",
                )?,
                "export ordinal index",
            )?);
            let Some(export) = exports.get_mut(ordinal_index) else {
                return invalid_field(
                    "export ordinal index",
                    format!("index {ordinal_index} is outside {function_count} EAT entries"),
                );
            };
            let name = mapper.c_string(name_rva, "export symbol name", MAX_STRING_BYTES)?;
            if name.is_empty() {
                return invalid_field("export symbol name", "must not be empty");
            }
            consume_string_budget(
                &mut total_name_bytes,
                &name,
                "export-name byte",
                MAX_EXPORT_NAME_BYTES,
            )?;
            export.names.push(PeExportName {
                name,
                name_table_index: u32::try_from(index)
                    .map_err(|_| AnalysisError::IntegerConversion("export name-table index"))?,
            });
        }
    }

    let directory_end = u64::from(directory.rva)
        .checked_add(u64::from(directory.size))
        .ok_or(AnalysisError::ArithmeticOverflow(
            "export-directory RVA range",
        ))?;
    for export in &mut exports {
        let Some(address) = export.address_rva else {
            continue;
        };
        if u64::from(address) >= u64::from(directory.rva) && u64::from(address) < directory_end {
            let bytes_remaining = usize::try_from(directory_end - u64::from(address))
                .map_err(|_| AnalysisError::IntegerConversion("export forwarder length"))?;
            let forwarder = mapper.c_string(
                address,
                "export forwarder",
                bytes_remaining.min(MAX_STRING_BYTES),
            )?;
            if forwarder.is_empty() {
                return invalid_field("export forwarder", "must not be empty");
            }
            consume_string_budget(
                &mut total_name_bytes,
                &forwarder,
                "export-name byte",
                MAX_EXPORT_NAME_BYTES,
            )?;
            export.forwarded_to = Some(forwarder);
        } else if address >= size_of_image {
            return invalid_field(
                "export address",
                format!("RVA {address:#x} lies outside the declared image"),
            );
        }
    }

    Ok((export_library_name, exports))
}

fn parse_load_config_metadata(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    directory: Option<DataDirectory>,
    image_base: u64,
    size_of_image: u32,
    sections: &[PeSection],
    import_iat_rvas: &BTreeSet<u32>,
) -> Result<ParsedLoadConfigMetadata, AnalysisError> {
    let parsed_guard_cf = parse_guard_cf_functions(
        reader,
        mapper,
        directory,
        image_base,
        size_of_image,
        sections,
    )?;
    let mut parsed = ParsedLoadConfigMetadata {
        load_config_size: parsed_guard_cf.load_config_size,
        security_anchors: PeLoadConfigSecurityAnchors::default(),
        xfg_anchors: PeLoadConfigXfgAnchors::default(),
        guard_memcpy_anchor: PeLoadConfigGuardMemcpyAnchor::default(),
        guard_flags: parsed_guard_cf.guard_flags,
        function_table_rva: parsed_guard_cf.function_table_rva,
        functions: parsed_guard_cf.functions,
        address_taken_iat_entry_table_rva: None,
        address_taken_iat_entries: Vec::new(),
        long_jump_target_table_rva: None,
        long_jump_targets: Vec::new(),
        eh_continuation_table_rva: None,
        eh_continuation_targets: Vec::new(),
    };

    let (Some(directory), Some(load_config_size)) = (directory, parsed.load_config_size) else {
        return Ok(parsed);
    };
    let directory_size = usize::try_from(directory.size)
        .map_err(|_| AnalysisError::IntegerConversion("load-config-directory size"))?;
    let directory_offset = mapper.offset(directory.rva, directory_size, "load-config directory")?;
    parsed.security_anchors = parse_load_config_security_anchors(
        reader,
        directory_offset,
        load_config_size,
        image_base,
        size_of_image,
    )?;
    parsed.xfg_anchors = parse_load_config_xfg_anchors(
        reader,
        directory_offset,
        load_config_size,
        image_base,
        size_of_image,
    )?;
    parsed.guard_memcpy_anchor = parse_load_config_guard_memcpy_anchor(
        reader,
        directory_offset,
        load_config_size,
        image_base,
        size_of_image,
    )?;
    validate_load_config_anchor_layout(
        &parsed.security_anchors,
        &parsed.xfg_anchors,
        &parsed.guard_memcpy_anchor,
        directory,
        sections,
    )?;
    let Some(guard_flags) = parsed.guard_flags else {
        return Ok(parsed);
    };
    let guard_table_context = GuardTableParseContext {
        directory,
        image_base,
        size_of_image,
        guard_flags,
    };

    if load_config_size < LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_FIELDS_SIZE_U32 {
        if guard_flags & IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT != 0 {
            return invalid_field(
                "Guard address-taken IAT fields",
                "the presence flag is set in a load-config structure too short to contain the table fields",
            );
        }
    } else {
        let table_va = reader.u64(
            checked_add(
                directory_offset,
                LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_TABLE_OFFSET,
                "Guard address-taken IAT table field offset",
            )?,
            "GuardAddressTakenIatEntryTable",
        )?;
        let count = reader.u64(
            checked_add(
                directory_offset,
                LOAD_CONFIG_GUARD_ADDRESS_TAKEN_IAT_COUNT_OFFSET,
                "Guard address-taken IAT count field offset",
            )?,
            "GuardAddressTakenIatEntryCount",
        )?;
        let (table_rva, entries) = parse_guard_address_taken_iat_table(
            reader,
            mapper,
            guard_table_context,
            table_va,
            count,
            import_iat_rvas,
        )?;
        parsed.address_taken_iat_entry_table_rva = table_rva;
        parsed.address_taken_iat_entries = entries;
    }

    if load_config_size < LOAD_CONFIG_GUARD_LONG_JUMP_FIELDS_SIZE_U32 {
        if guard_flags & IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT != 0 {
            return invalid_field(
                "Guard long-jump fields",
                "the presence flag is set in a load-config structure too short to contain the table fields",
            );
        }
    } else {
        let table_va = reader.u64(
            checked_add(
                directory_offset,
                LOAD_CONFIG_GUARD_LONG_JUMP_TABLE_OFFSET,
                "Guard long-jump table field offset",
            )?,
            "GuardLongJumpTargetTable",
        )?;
        let count = reader.u64(
            checked_add(
                directory_offset,
                LOAD_CONFIG_GUARD_LONG_JUMP_COUNT_OFFSET,
                "Guard long-jump count field offset",
            )?,
            "GuardLongJumpTargetCount",
        )?;
        let (table_rva, targets) = parse_guard_long_jump_table(
            reader,
            mapper,
            guard_table_context,
            table_va,
            count,
            sections,
        )?;
        parsed.long_jump_target_table_rva = table_rva;
        parsed.long_jump_targets = targets;
    }

    if load_config_size < LOAD_CONFIG_GUARD_EH_CONTINUATION_FIELDS_SIZE_U32 {
        if guard_flags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT != 0 {
            return invalid_field(
                "Guard EH-continuation fields",
                "the presence flag is set in a load-config structure too short to contain the table fields",
            );
        }
    } else {
        let table_va = reader.u64(
            checked_add(
                directory_offset,
                LOAD_CONFIG_GUARD_EH_CONTINUATION_TABLE_OFFSET,
                "Guard EH-continuation table field offset",
            )?,
            "GuardEHContinuationTable",
        )?;
        let count = reader.u64(
            checked_add(
                directory_offset,
                LOAD_CONFIG_GUARD_EH_CONTINUATION_COUNT_OFFSET,
                "Guard EH-continuation count field offset",
            )?,
            "GuardEHContinuationCount",
        )?;
        let (table_rva, targets) = parse_guard_eh_continuation_table(
            reader,
            mapper,
            guard_table_context,
            table_va,
            count,
            sections,
        )?;
        parsed.eh_continuation_table_rva = table_rva;
        parsed.eh_continuation_targets = targets;
    }

    let metadata_size = guard_table_metadata_size(guard_flags)?;
    let record_size = 4_usize
        .checked_add(metadata_size)
        .ok_or(AnalysisError::ArithmeticOverflow("Guard table record size"))?;
    let mut table_ranges = Vec::new();
    if let Some(table_rva) = parsed.function_table_rva {
        let size = u64::try_from(parsed.functions.len())
            .map_err(|_| AnalysisError::IntegerConversion("GuardCF function count"))?
            .checked_mul(
                u64::try_from(record_size)
                    .map_err(|_| AnalysisError::IntegerConversion("Guard table record size"))?,
            )
            .ok_or(AnalysisError::ArithmeticOverflow(
                "GuardCF function-table byte size",
            ))?;
        table_ranges.push(("GuardCF function table", table_rva, size));
    }
    if let Some(table_rva) = parsed.address_taken_iat_entry_table_rva {
        let size = u64::try_from(parsed.address_taken_iat_entries.len())
            .map_err(|_| AnalysisError::IntegerConversion("Guard address-taken IAT count"))?
            .checked_mul(
                u64::try_from(record_size)
                    .map_err(|_| AnalysisError::IntegerConversion("Guard table record size"))?,
            )
            .ok_or(AnalysisError::ArithmeticOverflow(
                "Guard address-taken IAT table byte size",
            ))?;
        table_ranges.push(("Guard address-taken IAT table", table_rva, size));
    }
    if let Some(table_rva) = parsed.long_jump_target_table_rva {
        let size = u64::try_from(parsed.long_jump_targets.len())
            .map_err(|_| AnalysisError::IntegerConversion("Guard long-jump target count"))?
            .checked_mul(
                u64::try_from(record_size)
                    .map_err(|_| AnalysisError::IntegerConversion("Guard table record size"))?,
            )
            .ok_or(AnalysisError::ArithmeticOverflow(
                "Guard long-jump table byte size",
            ))?;
        table_ranges.push(("Guard long-jump target table", table_rva, size));
    }
    if let Some(table_rva) = parsed.eh_continuation_table_rva {
        let size = u64::try_from(parsed.eh_continuation_targets.len())
            .map_err(|_| AnalysisError::IntegerConversion("Guard EH-continuation target count"))?
            .checked_mul(
                u64::try_from(record_size)
                    .map_err(|_| AnalysisError::IntegerConversion("Guard table record size"))?,
            )
            .ok_or(AnalysisError::ArithmeticOverflow(
                "Guard EH-continuation table byte size",
            ))?;
        table_ranges.push(("Guard EH-continuation table", table_rva, size));
    }
    for first in 0..table_ranges.len() {
        for second in first + 1..table_ranges.len() {
            if ranges_overlap(
                u64::from(table_ranges[first].1),
                table_ranges[first].2,
                u64::from(table_ranges[second].1),
                table_ranges[second].2,
            )? {
                return invalid_field(
                    "load-config guard tables",
                    format!(
                        "{} overlaps {}",
                        table_ranges[first].0, table_ranges[second].0
                    ),
                );
            }
        }
    }

    Ok(parsed)
}

fn parse_load_config_security_anchors(
    reader: &Reader<'_>,
    directory_offset: usize,
    load_config_size: u32,
    image_base: u64,
    size_of_image: u32,
) -> Result<PeLoadConfigSecurityAnchors, AnalysisError> {
    let read_anchor = |minimum_size: u32,
                       field_offset: usize,
                       offset_context: &'static str,
                       field_context: &'static str|
     -> Result<Option<u32>, AnalysisError> {
        if load_config_size < minimum_size {
            return Ok(None);
        }
        let field_va = reader.u64(
            checked_add(directory_offset, field_offset, offset_context)?,
            field_context,
        )?;
        if field_va == 0 {
            Ok(None)
        } else {
            image_va_to_rva(field_va, image_base, size_of_image, field_context).map(Some)
        }
    };

    Ok(PeLoadConfigSecurityAnchors {
        security_cookie_rva: read_anchor(
            LOAD_CONFIG_SECURITY_COOKIE_FIELDS_SIZE_U32,
            LOAD_CONFIG_SECURITY_COOKIE_OFFSET,
            "SecurityCookie field offset",
            "SecurityCookie",
        )?,
        guard_cf_check_function_pointer_rva: read_anchor(
            LOAD_CONFIG_GUARD_CF_CHECK_POINTER_FIELDS_SIZE_U32,
            LOAD_CONFIG_GUARD_CF_CHECK_POINTER_OFFSET,
            "GuardCF check-function pointer field offset",
            "GuardCFCheckFunctionPointer",
        )?,
        guard_cf_dispatch_function_pointer_rva: read_anchor(
            LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_FIELDS_SIZE_U32,
            LOAD_CONFIG_GUARD_CF_DISPATCH_POINTER_OFFSET,
            "GuardCF dispatch-function pointer field offset",
            "GuardCFDispatchFunctionPointer",
        )?,
    })
}

fn parse_load_config_xfg_anchors(
    reader: &Reader<'_>,
    directory_offset: usize,
    load_config_size: u32,
    image_base: u64,
    size_of_image: u32,
) -> Result<PeLoadConfigXfgAnchors, AnalysisError> {
    let read_anchor = |minimum_size: u32,
                       field_offset: usize,
                       offset_context: &'static str,
                       field_context: &'static str|
     -> Result<Option<u32>, AnalysisError> {
        if load_config_size < minimum_size {
            return Ok(None);
        }
        let field_va = reader.u64(
            checked_add(directory_offset, field_offset, offset_context)?,
            field_context,
        )?;
        if field_va == 0 {
            Ok(None)
        } else {
            image_va_to_rva(field_va, image_base, size_of_image, field_context).map(Some)
        }
    };

    Ok(PeLoadConfigXfgAnchors {
        guard_xfg_check_function_pointer_rva: read_anchor(
            LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_FIELDS_SIZE_U32,
            LOAD_CONFIG_GUARD_XFG_CHECK_POINTER_OFFSET,
            "Guard XFG check-function pointer field offset",
            "GuardXFGCheckFunctionPointer",
        )?,
        guard_xfg_dispatch_function_pointer_rva: read_anchor(
            LOAD_CONFIG_GUARD_XFG_DISPATCH_POINTER_FIELDS_SIZE_U32,
            LOAD_CONFIG_GUARD_XFG_DISPATCH_POINTER_OFFSET,
            "Guard XFG dispatch-function pointer field offset",
            "GuardXFGDispatchFunctionPointer",
        )?,
        guard_xfg_table_dispatch_function_pointer_rva: read_anchor(
            LOAD_CONFIG_GUARD_XFG_TABLE_DISPATCH_POINTER_FIELDS_SIZE_U32,
            LOAD_CONFIG_GUARD_XFG_TABLE_DISPATCH_POINTER_OFFSET,
            "Guard XFG table-dispatch function-pointer field offset",
            "GuardXFGTableDispatchFunctionPointer",
        )?,
        cast_guard_os_determined_failure_mode_rva: read_anchor(
            LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_FIELDS_SIZE_U32,
            LOAD_CONFIG_CAST_GUARD_FAILURE_MODE_OFFSET,
            "CastGuard OS-determined failure-mode field offset",
            "CastGuardOsDeterminedFailureMode",
        )?,
    })
}

fn parse_load_config_guard_memcpy_anchor(
    reader: &Reader<'_>,
    directory_offset: usize,
    load_config_size: u32,
    image_base: u64,
    size_of_image: u32,
) -> Result<PeLoadConfigGuardMemcpyAnchor, AnalysisError> {
    if load_config_size < LOAD_CONFIG_GUARD_MEMCPY_POINTER_FIELDS_SIZE_U32 {
        return Ok(PeLoadConfigGuardMemcpyAnchor::default());
    }

    let field_va = reader.u64(
        checked_add(
            directory_offset,
            LOAD_CONFIG_GUARD_MEMCPY_POINTER_OFFSET,
            "GuardMemcpy function-pointer field offset",
        )?,
        "GuardMemcpyFunctionPointer",
    )?;
    let guard_memcpy_function_pointer_rva = if field_va == 0 {
        None
    } else {
        Some(image_va_to_rva(
            field_va,
            image_base,
            size_of_image,
            "GuardMemcpyFunctionPointer",
        )?)
    };

    Ok(PeLoadConfigGuardMemcpyAnchor {
        guard_memcpy_function_pointer_rva,
    })
}

fn validate_load_config_anchor_layout(
    anchors: &PeLoadConfigSecurityAnchors,
    xfg_anchors: &PeLoadConfigXfgAnchors,
    guard_memcpy_anchor: &PeLoadConfigGuardMemcpyAnchor,
    directory: DataDirectory,
    sections: &[PeSection],
) -> Result<(), AnalysisError> {
    let anchor_ranges = [
        ("security cookie", anchors.security_cookie_rva),
        (
            "GuardCF check-function pointer slot",
            anchors.guard_cf_check_function_pointer_rva,
        ),
        (
            "GuardCF dispatch-function pointer slot",
            anchors.guard_cf_dispatch_function_pointer_rva,
        ),
        (
            "Guard XFG check-function pointer slot",
            xfg_anchors.guard_xfg_check_function_pointer_rva,
        ),
        (
            "Guard XFG dispatch-function pointer slot",
            xfg_anchors.guard_xfg_dispatch_function_pointer_rva,
        ),
        (
            "Guard XFG table-dispatch function-pointer slot",
            xfg_anchors.guard_xfg_table_dispatch_function_pointer_rva,
        ),
        (
            "CastGuard OS-determined failure-mode storage",
            xfg_anchors.cast_guard_os_determined_failure_mode_rva,
        ),
        (
            "GuardMemcpy function-pointer slot",
            guard_memcpy_anchor.guard_memcpy_function_pointer_rva,
        ),
    ];

    for (label, rva) in anchor_ranges {
        let Some(rva) = rva else {
            continue;
        };
        if section_for_rva_range(rva, LOAD_CONFIG_SECURITY_ANCHOR_SIZE_U32, sections).is_none() {
            return invalid_field(
                label,
                format!("RVA {rva:#x} does not name an eight-byte range within one mapped section"),
            );
        }
        if ranges_overlap(
            u64::from(directory.rva),
            u64::from(directory.size),
            u64::from(rva),
            u64::from(LOAD_CONFIG_SECURITY_ANCHOR_SIZE_U32),
        )? {
            return invalid_field(label, "overlaps the declared load-config directory range");
        }
    }

    for first in 0..anchor_ranges.len() {
        let Some(first_rva) = anchor_ranges[first].1 else {
            continue;
        };
        for second in first + 1..anchor_ranges.len() {
            let Some(second_rva) = anchor_ranges[second].1 else {
                continue;
            };
            if ranges_overlap(
                u64::from(first_rva),
                u64::from(LOAD_CONFIG_SECURITY_ANCHOR_SIZE_U32),
                u64::from(second_rva),
                u64::from(LOAD_CONFIG_SECURITY_ANCHOR_SIZE_U32),
            )? {
                return invalid_field(
                    "load-config security anchors",
                    format!(
                        "{} overlaps {}",
                        anchor_ranges[first].0, anchor_ranges[second].0
                    ),
                );
            }
        }
    }

    Ok(())
}

fn parse_guard_cf_functions(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    directory: Option<DataDirectory>,
    image_base: u64,
    size_of_image: u32,
    sections: &[PeSection],
) -> Result<ParsedGuardCfMetadata, AnalysisError> {
    let Some(directory) = directory else {
        return Ok(ParsedGuardCfMetadata {
            load_config_size: None,
            guard_flags: None,
            function_table_rva: None,
            functions: Vec::new(),
        });
    };
    enforce_directory_size("load-config-directory byte", directory.size)?;
    if directory.size < 4 {
        return invalid_field(
            "load-config directory size",
            "must contain the four-byte structure-size field",
        );
    }
    let directory_size = usize::try_from(directory.size)
        .map_err(|_| AnalysisError::IntegerConversion("load-config-directory size"))?;
    let directory_offset = mapper.offset(directory.rva, directory_size, "load-config directory")?;
    let load_config_size = reader.u32(directory_offset, "load-config structure size")?;
    if load_config_size > directory.size {
        return invalid_field(
            "load-config size",
            "the structure declares more bytes than its data-directory entry",
        );
    }
    if load_config_size < 4 {
        return invalid_field(
            "load-config size",
            "must be at least four bytes when a load-config directory is present",
        );
    }
    if load_config_size < LOAD_CONFIG_GUARD_FIELDS_SIZE_U32 {
        return Ok(ParsedGuardCfMetadata {
            load_config_size: Some(load_config_size),
            guard_flags: None,
            function_table_rva: None,
            functions: Vec::new(),
        });
    }

    let table_va = reader.u64(
        checked_add(
            directory_offset,
            LOAD_CONFIG_GUARD_CF_FUNCTION_TABLE_OFFSET,
            "GuardCF function-table field offset",
        )?,
        "GuardCFFunctionTable",
    )?;
    let function_count = reader.u64(
        checked_add(
            directory_offset,
            LOAD_CONFIG_GUARD_CF_FUNCTION_COUNT_OFFSET,
            "GuardCF function-count field offset",
        )?,
        "GuardCFFunctionCount",
    )?;
    let guard_flags = reader.u32(
        checked_add(
            directory_offset,
            LOAD_CONFIG_GUARD_FLAGS_OFFSET,
            "GuardFlags field offset",
        )?,
        "GuardFlags",
    )?;
    let table_present = guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT != 0;

    if table_va == 0 && function_count == 0 {
        return Ok(ParsedGuardCfMetadata {
            load_config_size: Some(load_config_size),
            guard_flags: Some(guard_flags),
            function_table_rva: None,
            functions: Vec::new(),
        });
    }
    if table_va == 0 || function_count == 0 {
        return invalid_field(
            "GuardCF function table",
            "table VA and function count must either both be zero or both be nonzero",
        );
    }
    if !table_present {
        return invalid_field(
            "GuardCF function table",
            "table VA and count are nonzero while IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT is clear",
        );
    }

    enforce_limit("GuardCF function", function_count, MAX_GUARD_CF_FUNCTIONS)?;
    let metadata_size = usize::try_from(
        (guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
            >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT,
    )
    .map_err(|_| AnalysisError::IntegerConversion("GuardCF metadata size"))?;
    let record_size =
        4_usize
            .checked_add(metadata_size)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "GuardCF function-record size",
            ))?;
    let table_size = function_count
        .checked_mul(
            u64::try_from(record_size)
                .map_err(|_| AnalysisError::IntegerConversion("GuardCF record size"))?,
        )
        .ok_or(AnalysisError::ArithmeticOverflow(
            "GuardCF function-table byte size",
        ))?;
    enforce_limit(
        "GuardCF function-table byte",
        table_size,
        MAX_DIRECTORY_BYTES,
    )?;
    let table_size_usize = usize::try_from(table_size)
        .map_err(|_| AnalysisError::IntegerConversion("GuardCF function-table byte size"))?;
    let table_rva = image_va_to_rva(table_va, image_base, size_of_image, "GuardCFFunctionTable")?;
    let table_offset = mapper.offset(table_rva, table_size_usize, "GuardCF function table")?;
    if ranges_overlap(
        u64::from(directory.rva),
        u64::from(directory.size),
        u64::from(table_rva),
        table_size,
    )? {
        return invalid_field(
            "GuardCF function table",
            "overlaps the declared load-config directory range",
        );
    }

    let capacity = usize::try_from(function_count)
        .map_err(|_| AnalysisError::IntegerConversion("GuardCF function count"))?;
    let mut functions = Vec::with_capacity(capacity);
    let mut previous_rva = None;
    for index in 0..capacity {
        let record_offset = checked_add(
            table_offset,
            checked_mul(index, record_size, "GuardCF function-record position")?,
            "GuardCF function-record offset",
        )?;
        let rva = reader.u32(record_offset, "GuardCF function RVA")?;
        if previous_rva.is_some_and(|previous| previous >= rva) {
            return invalid_field(
                "GuardCF function table",
                "RVAs must be strictly increasing and unique",
            );
        }
        let executable = section_for_rva(rva, sections)
            .is_some_and(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            && mapper.is_backed(rva, 1);
        if !executable {
            return invalid_field(
                "GuardCF function target",
                format!(
                    "entry {index} has RVA {rva:#x}, which is not fully file-backed executable data"
                ),
            );
        }
        let metadata_offset = checked_add(record_offset, 4, "GuardCF metadata offset")?;
        let metadata = reader
            .bytes(metadata_offset, metadata_size, "GuardCF function metadata")?
            .to_vec();
        let function = PeGuardCfFunction {
            table_index: u32::try_from(index)
                .map_err(|_| AnalysisError::IntegerConversion("GuardCF function-table index"))?,
            rva,
            metadata,
        };
        if function.is_export_suppressed()
            && function.rva % GUARD_CF_EXPORT_SUPPRESSED_ALIGNMENT != 0
        {
            return invalid_field(
                "GuardCF function target",
                format!(
                    "entry {index} has export-suppressed RVA {rva:#x}, which is not 16-byte aligned"
                ),
            );
        }
        functions.push(function);
        previous_rva = Some(rva);
    }

    Ok(ParsedGuardCfMetadata {
        load_config_size: Some(load_config_size),
        guard_flags: Some(guard_flags),
        function_table_rva: Some(table_rva),
        functions,
    })
}

fn parse_guard_address_taken_iat_table(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    context: GuardTableParseContext,
    table_va: u64,
    entry_count: u64,
    import_iat_rvas: &BTreeSet<u32>,
) -> Result<(Option<u32>, Vec<PeGuardAddressTakenIatEntry>), AnalysisError> {
    let GuardTableParseContext {
        directory,
        image_base,
        size_of_image,
        guard_flags,
    } = context;
    if table_va == 0 && entry_count == 0 {
        return Ok((None, Vec::new()));
    }
    if table_va == 0 || entry_count == 0 {
        return invalid_field(
            "Guard address-taken IAT table",
            "table VA and entry count must either both be zero or both be nonzero",
        );
    }
    if guard_flags & IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT == 0 {
        return invalid_field(
            "Guard address-taken IAT table",
            "table VA and count are nonzero while IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT is clear",
        );
    }

    let metadata_size = guard_table_metadata_size(guard_flags)?;
    let record_size =
        4_usize
            .checked_add(metadata_size)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "Guard address-taken IAT record size",
            ))?;
    let table_size = validated_guard_table_size(
        entry_count,
        record_size,
        "Guard address-taken IAT entry",
        MAX_GUARD_ADDRESS_TAKEN_IAT_ENTRIES,
        "Guard address-taken IAT table byte",
        "Guard address-taken IAT table byte size",
    )?;
    let table_size_usize = usize::try_from(table_size)
        .map_err(|_| AnalysisError::IntegerConversion("Guard address-taken IAT table byte size"))?;
    let table_rva = image_va_to_rva(
        table_va,
        image_base,
        size_of_image,
        "GuardAddressTakenIatEntryTable",
    )?;
    let table_offset =
        mapper.offset(table_rva, table_size_usize, "Guard address-taken IAT table")?;
    if ranges_overlap(
        u64::from(directory.rva),
        u64::from(directory.size),
        u64::from(table_rva),
        table_size,
    )? {
        return invalid_field(
            "Guard address-taken IAT table",
            "overlaps the declared load-config directory range",
        );
    }

    let capacity = usize::try_from(entry_count)
        .map_err(|_| AnalysisError::IntegerConversion("Guard address-taken IAT entry count"))?;
    let mut entries = Vec::with_capacity(capacity);
    let mut previous_rva = None;
    for index in 0..capacity {
        let record_offset = checked_add(
            table_offset,
            checked_mul(
                index,
                record_size,
                "Guard address-taken IAT record position",
            )?,
            "Guard address-taken IAT record offset",
        )?;
        let iat_rva = reader.u32(record_offset, "Guard address-taken IAT RVA")?;
        if previous_rva.is_some_and(|previous| previous >= iat_rva) {
            return invalid_field(
                "Guard address-taken IAT table",
                "RVAs must be strictly increasing and unique",
            );
        }
        let metadata_offset =
            checked_add(record_offset, 4, "Guard address-taken IAT metadata offset")?;
        let metadata = reader
            .bytes(
                metadata_offset,
                metadata_size,
                "Guard address-taken IAT metadata",
            )?
            .to_vec();
        if metadata.iter().any(|byte| *byte != 0) {
            return invalid_field(
                "Guard address-taken IAT metadata",
                format!("entry {index} has nonzero reserved metadata"),
            );
        }
        if !import_iat_rvas.contains(&iat_rva) {
            return invalid_field(
                "Guard address-taken IAT entry",
                format!(
                    "entry {index} names RVA {iat_rva:#x}, which is not an exact parsed import IAT slot"
                ),
            );
        }
        entries.push(PeGuardAddressTakenIatEntry {
            table_index: u32::try_from(index).map_err(|_| {
                AnalysisError::IntegerConversion("Guard address-taken IAT table index")
            })?,
            iat_rva,
            metadata,
        });
        previous_rva = Some(iat_rva);
    }
    Ok((Some(table_rva), entries))
}

fn parse_guard_long_jump_table(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    context: GuardTableParseContext,
    table_va: u64,
    target_count: u64,
    sections: &[PeSection],
) -> Result<(Option<u32>, Vec<PeGuardLongJumpTarget>), AnalysisError> {
    let GuardTableParseContext {
        directory,
        image_base,
        size_of_image,
        guard_flags,
    } = context;
    if table_va == 0 && target_count == 0 {
        return Ok((None, Vec::new()));
    }
    if table_va == 0 || target_count == 0 {
        return invalid_field(
            "Guard long-jump target table",
            "table VA and target count must either both be zero or both be nonzero",
        );
    }
    if guard_flags & IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT == 0 {
        return invalid_field(
            "Guard long-jump target table",
            "table VA and count are nonzero while IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT is clear",
        );
    }

    let metadata_size = guard_table_metadata_size(guard_flags)?;
    let record_size =
        4_usize
            .checked_add(metadata_size)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "Guard long-jump record size",
            ))?;
    let table_size = validated_guard_table_size(
        target_count,
        record_size,
        "Guard long-jump target",
        MAX_GUARD_LONG_JUMP_TARGETS,
        "Guard long-jump table byte",
        "Guard long-jump table byte size",
    )?;
    let table_size_usize = usize::try_from(table_size)
        .map_err(|_| AnalysisError::IntegerConversion("Guard long-jump table byte size"))?;
    let table_rva = image_va_to_rva(
        table_va,
        image_base,
        size_of_image,
        "GuardLongJumpTargetTable",
    )?;
    let table_offset =
        mapper.offset(table_rva, table_size_usize, "Guard long-jump target table")?;
    if ranges_overlap(
        u64::from(directory.rva),
        u64::from(directory.size),
        u64::from(table_rva),
        table_size,
    )? {
        return invalid_field(
            "Guard long-jump target table",
            "overlaps the declared load-config directory range",
        );
    }

    let capacity = usize::try_from(target_count)
        .map_err(|_| AnalysisError::IntegerConversion("Guard long-jump target count"))?;
    let mut targets = Vec::with_capacity(capacity);
    let mut previous_rva = None;
    for index in 0..capacity {
        let record_offset = checked_add(
            table_offset,
            checked_mul(index, record_size, "Guard long-jump record position")?,
            "Guard long-jump record offset",
        )?;
        let target_rva = reader.u32(record_offset, "Guard long-jump target RVA")?;
        if previous_rva.is_some_and(|previous| previous >= target_rva) {
            return invalid_field(
                "Guard long-jump target table",
                "RVAs must be strictly increasing and unique",
            );
        }
        let executable = section_for_rva(target_rva, sections)
            .is_some_and(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            && mapper.is_backed(target_rva, 1);
        if !executable {
            return invalid_field(
                "Guard long-jump target",
                format!(
                    "entry {index} has RVA {target_rva:#x}, which is not fully file-backed executable data"
                ),
            );
        }
        let metadata_offset = checked_add(record_offset, 4, "Guard long-jump metadata offset")?;
        let metadata = reader
            .bytes(metadata_offset, metadata_size, "Guard long-jump metadata")?
            .to_vec();
        if metadata.iter().any(|byte| *byte != 0) {
            return invalid_field(
                "Guard long-jump metadata",
                format!("entry {index} has nonzero reserved metadata"),
            );
        }
        targets.push(PeGuardLongJumpTarget {
            table_index: u32::try_from(index).map_err(|_| {
                AnalysisError::IntegerConversion("Guard long-jump target-table index")
            })?,
            target_rva,
            metadata,
        });
        previous_rva = Some(target_rva);
    }
    Ok((Some(table_rva), targets))
}

fn parse_guard_eh_continuation_table(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    context: GuardTableParseContext,
    table_va: u64,
    target_count: u64,
    sections: &[PeSection],
) -> Result<(Option<u32>, Vec<PeGuardEhContinuationTarget>), AnalysisError> {
    let GuardTableParseContext {
        directory,
        image_base,
        size_of_image,
        guard_flags,
    } = context;
    if table_va == 0 && target_count == 0 {
        return Ok((None, Vec::new()));
    }
    if table_va == 0 || target_count == 0 {
        return invalid_field(
            "Guard EH-continuation table",
            "table VA and target count must either both be zero or both be nonzero",
        );
    }
    if guard_flags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT == 0 {
        return invalid_field(
            "Guard EH-continuation table",
            "table VA and count are nonzero while IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT is clear",
        );
    }

    let metadata_size = guard_table_metadata_size(guard_flags)?;
    let record_size =
        4_usize
            .checked_add(metadata_size)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "Guard EH-continuation record size",
            ))?;
    let table_size = validated_guard_table_size(
        target_count,
        record_size,
        "Guard EH-continuation target",
        MAX_GUARD_EH_CONTINUATION_TARGETS,
        "Guard EH-continuation table byte",
        "Guard EH-continuation table byte size",
    )?;
    let table_size_usize = usize::try_from(table_size)
        .map_err(|_| AnalysisError::IntegerConversion("Guard EH-continuation table byte size"))?;
    let table_rva = image_va_to_rva(
        table_va,
        image_base,
        size_of_image,
        "GuardEHContinuationTable",
    )?;
    let table_offset = mapper.offset(table_rva, table_size_usize, "Guard EH-continuation table")?;
    if ranges_overlap(
        u64::from(directory.rva),
        u64::from(directory.size),
        u64::from(table_rva),
        table_size,
    )? {
        return invalid_field(
            "Guard EH-continuation table",
            "overlaps the declared load-config directory range",
        );
    }

    let capacity = usize::try_from(target_count)
        .map_err(|_| AnalysisError::IntegerConversion("Guard EH-continuation target count"))?;
    let mut targets = Vec::with_capacity(capacity);
    let mut previous_rva = None;
    for index in 0..capacity {
        let record_offset = checked_add(
            table_offset,
            checked_mul(index, record_size, "Guard EH-continuation record position")?,
            "Guard EH-continuation record offset",
        )?;
        let target_rva = reader.u32(record_offset, "Guard EH-continuation target RVA")?;
        if previous_rva.is_some_and(|previous| previous >= target_rva) {
            return invalid_field(
                "Guard EH-continuation table",
                "RVAs must be strictly increasing and unique",
            );
        }
        let executable = section_for_rva(target_rva, sections)
            .is_some_and(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            && mapper.is_backed(target_rva, 1);
        if !executable {
            return invalid_field(
                "Guard EH-continuation target",
                format!(
                    "entry {index} has RVA {target_rva:#x}, which is not fully file-backed executable data"
                ),
            );
        }
        let metadata_offset =
            checked_add(record_offset, 4, "Guard EH-continuation metadata offset")?;
        let metadata = reader
            .bytes(
                metadata_offset,
                metadata_size,
                "Guard EH-continuation metadata",
            )?
            .to_vec();
        if metadata.iter().any(|byte| *byte != 0) {
            return invalid_field(
                "Guard EH-continuation metadata",
                format!("entry {index} has nonzero reserved metadata"),
            );
        }
        targets.push(PeGuardEhContinuationTarget {
            table_index: u32::try_from(index).map_err(|_| {
                AnalysisError::IntegerConversion("Guard EH-continuation table index")
            })?,
            target_rva,
            metadata,
        });
        previous_rva = Some(target_rva);
    }
    Ok((Some(table_rva), targets))
}

fn parse_tls_callbacks(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    directory: Option<DataDirectory>,
    image_base: u64,
    size_of_image: u32,
    sections: &[PeSection],
) -> Result<(Option<u32>, Vec<PeTlsCallback>, bool), AnalysisError> {
    let Some(directory) = directory else {
        return Ok((None, Vec::new(), false));
    };
    enforce_directory_size("TLS-directory byte", directory.size)?;
    if directory.size < TLS_DIRECTORY_SIZE_U32 {
        return invalid_field(
            "TLS directory size",
            "must be at least the 40-byte PE32+ TLS directory size",
        );
    }
    let directory_size = usize::try_from(directory.size)
        .map_err(|_| AnalysisError::IntegerConversion("TLS-directory size"))?;
    let directory_offset = mapper.offset(directory.rva, directory_size, "TLS directory")?;
    let callbacks_va = reader.u64(
        checked_add(directory_offset, 24, "TLS AddressOfCallbacks file offset")?,
        "TLS AddressOfCallbacks",
    )?;
    if callbacks_va == 0 {
        return Ok((None, Vec::new(), false));
    }
    let callbacks_rva = image_va_to_rva(
        callbacks_va,
        image_base,
        size_of_image,
        "TLS AddressOfCallbacks",
    )?;

    let retained_capacity = usize::try_from(MAX_TLS_CALLBACKS)
        .map_err(|_| AnalysisError::IntegerConversion("TLS callback limit"))?;
    let mut callbacks = Vec::with_capacity(retained_capacity);
    for table_index in 0..=MAX_TLS_CALLBACKS {
        let slot_delta = table_index
            .checked_mul(8)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "TLS callback slot position",
            ))?;
        let slot_delta = u32::try_from(slot_delta)
            .map_err(|_| AnalysisError::IntegerConversion("TLS callback slot position"))?;
        let slot_rva = callbacks_rva
            .checked_add(slot_delta)
            .ok_or(AnalysisError::ArithmeticOverflow("TLS callback slot RVA"))?;
        let slot_offset = mapper.offset(slot_rva, 8, "TLS callback slot")?;
        let callback_va = reader.u64(slot_offset, "TLS callback VA")?;
        if callback_va == 0 {
            return Ok((Some(callbacks_rva), callbacks, false));
        }
        if table_index == MAX_TLS_CALLBACKS {
            return Ok((Some(callbacks_rva), callbacks, true));
        }

        let callback_rva =
            image_va_to_rva(callback_va, image_base, size_of_image, "TLS callback VA")?;
        let executable = section_for_rva(callback_rva, sections)
            .is_some_and(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            && mapper.is_backed(callback_rva, 1);
        if !executable {
            return invalid_field(
                "TLS callback target",
                format!(
                    "table entry {table_index} resolves to RVA {callback_rva:#x}, which is not fully file-backed executable data"
                ),
            );
        }
        callbacks.push(PeTlsCallback {
            table_index: u32::try_from(table_index)
                .map_err(|_| AnalysisError::IntegerConversion("TLS callback table index"))?,
            callback_rva,
        });
    }
    unreachable!("the bounded TLS callback loop always returns")
}

fn image_va_to_rva(
    va: u64,
    image_base: u64,
    size_of_image: u32,
    field: &'static str,
) -> Result<u32, AnalysisError> {
    let rva = va
        .checked_sub(image_base)
        .ok_or_else(|| AnalysisError::InvalidField {
            field,
            reason: format!("VA {va:#x} is below preferred image base {image_base:#x}"),
        })?;
    let rva = u32::try_from(rva).map_err(|_| AnalysisError::InvalidField {
        field,
        reason: format!("VA {va:#x} does not fit a 32-bit image RVA"),
    })?;
    if rva >= size_of_image {
        return invalid_field(
            field,
            format!("VA {va:#x} resolves outside the declared image"),
        );
    }
    Ok(rva)
}

fn parse_runtime_functions(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    directory: Option<DataDirectory>,
    size_of_image: u32,
) -> Result<Vec<RuntimeFunction>, AnalysisError> {
    let Some(directory) = directory else {
        return Ok(Vec::new());
    };
    enforce_directory_size("exception-directory byte", directory.size)?;
    if directory.size % RUNTIME_FUNCTION_SIZE_U32 != 0 {
        return invalid_field(
            "exception directory size",
            "must be a multiple of the 12-byte RUNTIME_FUNCTION size",
        );
    }
    let count = directory.size / RUNTIME_FUNCTION_SIZE_U32;
    enforce_limit("runtime function", u64::from(count), MAX_RUNTIME_FUNCTIONS)?;
    let byte_count = usize::try_from(directory.size)
        .map_err(|_| AnalysisError::IntegerConversion("exception-directory size"))?;
    let table_offset = mapper.offset(directory.rva, byte_count, "exception directory")?;
    let mut functions = Vec::with_capacity(
        usize::try_from(count)
            .map_err(|_| AnalysisError::IntegerConversion("runtime-function count"))?,
    );
    for index in 0..count {
        let offset = checked_add(
            table_offset,
            checked_mul(
                usize::try_from(index)
                    .map_err(|_| AnalysisError::IntegerConversion("runtime-function index"))?,
                RUNTIME_FUNCTION_SIZE,
                "runtime-function position",
            )?,
            "runtime-function offset",
        )?;
        let begin_rva = reader.u32(offset, "runtime-function begin RVA")?;
        let end_rva = reader.u32(offset + 4, "runtime-function end RVA")?;
        let unwind_info_rva = reader.u32(offset + 8, "runtime-function unwind-info RVA")?;
        if begin_rva >= end_rva {
            return invalid_field(
                "runtime-function range",
                format!("entry {index} has {begin_rva:#x}..{end_rva:#x}"),
            );
        }
        if end_rva > size_of_image {
            return invalid_field(
                "runtime-function range",
                format!("entry {index} ends outside the declared image"),
            );
        }
        let inclusive_end_rva = end_rva
            .checked_sub(1)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "runtime-function inclusive end RVA",
            ))?;
        let begin_section = section_for_rva(begin_rva, mapper.sections);
        let end_section = section_for_rva(inclusive_end_rva, mapper.sections);
        if begin_section.map(|(section_index, _)| section_index)
            != end_section.map(|(section_index, _)| section_index)
            || begin_section
                .is_none_or(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0)
        {
            return invalid_field(
                "runtime-function range",
                format!("entry {index} does not stay within one executable section"),
            );
        }
        if unwind_info_rva == 0 || unwind_info_rva >= size_of_image {
            return invalid_field(
                "runtime-function unwind-info RVA",
                format!("entry {index} has out-of-image RVA {unwind_info_rva:#x}"),
            );
        }
        if unwind_info_rva % 4 != 0 {
            return invalid_field(
                "runtime-function unwind-info RVA",
                format!("entry {index} has unaligned RVA {unwind_info_rva:#x}"),
            );
        }
        let _ = mapper.offset(unwind_info_rva, 4, "runtime-function unwind info")?;
        functions.push(RuntimeFunction {
            begin_rva,
            end_rva,
            unwind_info_rva,
            table_index: index,
        });
    }
    Ok(functions)
}

pub(crate) fn build_symbol_graph(
    input: SymbolGraphInput<'_>,
) -> Result<SymbolGraph, AnalysisError> {
    let SymbolGraphInput {
        identity,
        entry_point_rva,
        sections,
        exports,
        runtime_functions,
        load_config_rva,
        guard_flags,
        guard_cf_function_table_rva,
        guard_cf_functions,
        tls_directory_rva,
        tls_callback_table_rva,
        tls_callbacks,
        direct_calls,
        thunks,
        strings,
        data_references,
        msvc_rtti_vftables,
    } = input;
    let mut graph = SymbolGraph::default();
    let _ = graph.insert_binary(identity.clone())?;
    let exact_metadata_confidence = Confidence::new(1.0)?;
    let export_subject_confidence = Confidence::new(0.99)?;
    let runtime_boundary_confidence = Confidence::new(0.99)?;
    let entry_point_confidence = Confidence::new(0.99)?;
    let guard_cf_confidence = Confidence::new(0.99)?;
    let function_candidate_confidence = Confidence::new(0.95)?;
    let direct_call_confidence = Confidence::new(0.90)?;
    let recovered_string_confidence = Confidence::new(0.90)?;
    let data_reference_confidence = Confidence::new(0.90)?;
    let recovered_target_confidence = Confidence::new(0.85)?;
    let thunk_confidence = Confidence::new(0.95)?;
    let rtti_vftable_confidence = Confidence::new(0.99)?;
    let rtti_slot_confidence = Confidence::new(0.95)?;
    let metadata_kind = EvidenceKind::new(EvidenceKind::METADATA)?;
    let control_flow_kind = EvidenceKind::new(EvidenceKind::CONTROL_FLOW)?;
    let string_literal_kind = EvidenceKind::new(EvidenceKind::STRING_LITERAL)?;
    let data_flow_kind = EvidenceKind::new(EvidenceKind::DATA_FLOW)?;
    let provenance = |method: &str| ClaimProvenance {
        producer: ClaimProducer::Core {
            component: "resymbol-analysis".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        method: method.to_owned(),
        run_id: None,
    };
    let runtime_function_starts = runtime_functions
        .iter()
        .map(|function| function.begin_rva)
        .collect::<BTreeSet<_>>();

    let mut export_names = Vec::new();
    for export in exports {
        if export.address_rva.is_some() && export.forwarded_to.is_none() {
            for name in &export.names {
                export_names.push((name.name_table_index, export, name));
            }
        }
    }
    export_names.sort_by_key(|(index, _, _)| *index);
    for (_, export, name) in export_names {
        let address_rva = export
            .address_rva
            .ok_or_else(|| AnalysisError::InvalidField {
                field: "export graph claim",
                reason: "local export unexpectedly lacks an address".to_owned(),
            })?;
        let Some((section_index, section)) = section_for_rva(address_rva, sections) else {
            continue;
        };
        let is_executable = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let is_runtime_function_start = runtime_function_starts.contains(&address_rva);
        let mut evidence = Evidence::new(
            metadata_kind.clone(),
            "exact name from the PE export name-pointer table",
        )?;
        evidence.confidence = Some(exact_metadata_confidence);
        evidence
            .artifacts
            .insert("export_ordinal".to_owned(), export.ordinal.to_string());
        evidence.artifacts.insert(
            "name_table_index".to_owned(),
            name.name_table_index.to_string(),
        );
        evidence
            .artifacts
            .insert("source_rva".to_owned(), format!("{address_rva:#x}"));
        evidence
            .artifacts
            .insert("section_index".to_owned(), section_index.to_string());
        if !section.name.is_empty() {
            evidence
                .artifacts
                .insert("section_name".to_owned(), section.name.clone());
        }
        let is_function = is_executable;
        let subject_kind = if is_function { "function" } else { "global" };
        evidence
            .artifacts
            .insert("subject_kind".to_owned(), subject_kind.to_owned());
        evidence.artifacts.insert(
            "classification_basis".to_owned(),
            if is_function {
                if is_runtime_function_start {
                    "x64-runtime-function-start"
                } else {
                    "executable-local-export"
                }
            } else {
                "non-executable-section"
            }
            .to_owned(),
        );
        let subject = if is_function {
            SymbolSubject::Function {
                binary: identity.id.clone(),
                rva: u64::from(address_rva),
                size: None,
            }
        } else {
            SymbolSubject::Global {
                binary: identity.id.clone(),
                rva: u64::from(address_rva),
                size: None,
            }
        };
        graph.submit_claim(SymbolClaim::new(
            subject,
            SymbolAssertion::Name {
                name: name.name.clone(),
            },
            export_subject_confidence,
            vec![evidence],
            provenance("pe-export-directory"),
        )?)?;
    }

    if entry_point_rva != 0 {
        if let Some((section_index, section)) =
            file_backed_executable_section_for_rva(identity, entry_point_rva, sections)
        {
            let mut evidence = Evidence::new(
                metadata_kind.clone(),
                "nonzero file-backed executable address from the PE AddressOfEntryPoint field",
            )?;
            evidence.confidence = Some(entry_point_confidence);
            evidence.artifacts.insert(
                "entry_point_rva".to_owned(),
                format!("{entry_point_rva:#x}"),
            );
            evidence
                .artifacts
                .insert("section_index".to_owned(), section_index.to_string());
            if !section.name.is_empty() {
                evidence
                    .artifacts
                    .insert("section_name".to_owned(), section.name.clone());
            }
            graph.submit_claim(SymbolClaim::new(
                SymbolSubject::Function {
                    binary: identity.id.clone(),
                    rva: u64::from(entry_point_rva),
                    size: None,
                },
                SymbolAssertion::FunctionEntry,
                entry_point_confidence,
                vec![evidence],
                provenance("pe-entry-point"),
            )?)?;
        }
    }

    if !guard_cf_functions.is_empty() {
        let load_config_rva = load_config_rva.ok_or_else(|| AnalysisError::InvalidField {
            field: "GuardCF metadata",
            reason: "entries exist without a load-config directory".to_owned(),
        })?;
        let guard_flags = guard_flags.ok_or_else(|| AnalysisError::InvalidField {
            field: "GuardFlags",
            reason: "GuardCF entries exist without GuardFlags".to_owned(),
        })?;
        let function_table_rva =
            guard_cf_function_table_rva.ok_or_else(|| AnalysisError::InvalidField {
                field: "GuardCF function table",
                reason: "entries exist without a table RVA".to_owned(),
            })?;
        for function in guard_cf_functions {
            let (section_index, section) = file_backed_executable_section_for_rva(
                identity,
                function.rva,
                sections,
            )
            .ok_or_else(|| AnalysisError::InvalidField {
                field: "GuardCF function target",
                reason: format!(
                    "entry {} has RVA {:#x}, which is not fully file-backed executable data",
                    function.table_index, function.rva
                ),
            })?;
            let mut evidence = Evidence::new(
                metadata_kind.clone(),
                "exact executable function target from the sorted PE GuardCF function table",
            )?;
            evidence.confidence = Some(exact_metadata_confidence);
            evidence.artifacts.insert(
                "load_config_rva".to_owned(),
                format!("{load_config_rva:#x}"),
            );
            evidence.artifacts.insert(
                "function_table_rva".to_owned(),
                format!("{function_table_rva:#x}"),
            );
            evidence
                .artifacts
                .insert("guard_flags".to_owned(), format!("{guard_flags:#010x}"));
            evidence
                .artifacts
                .insert("table_index".to_owned(), function.table_index.to_string());
            evidence
                .artifacts
                .insert("target_rva".to_owned(), format!("{:#x}", function.rva));
            evidence.artifacts.insert(
                "metadata".to_owned(),
                if function.metadata.is_empty() {
                    "none".to_owned()
                } else {
                    format_hex(&function.metadata)
                },
            );
            evidence.artifacts.insert(
                "fid_suppressed".to_owned(),
                function.is_fid_suppressed().to_string(),
            );
            evidence.artifacts.insert(
                "export_suppressed".to_owned(),
                function.is_export_suppressed().to_string(),
            );
            evidence
                .artifacts
                .insert("section_index".to_owned(), section_index.to_string());
            if !section.name.is_empty() {
                evidence
                    .artifacts
                    .insert("section_name".to_owned(), section.name.clone());
            }
            graph.submit_claim(SymbolClaim::new(
                SymbolSubject::Function {
                    binary: identity.id.clone(),
                    rva: u64::from(function.rva),
                    size: None,
                },
                SymbolAssertion::FunctionEntry,
                guard_cf_confidence,
                vec![evidence],
                provenance("pe-guard-cf-function"),
            )?)?;
        }
    }

    if !tls_callbacks.is_empty() {
        let tls_directory_rva = tls_directory_rva.ok_or_else(|| AnalysisError::InvalidField {
            field: "TLS callbacks",
            reason: "entries exist without a TLS directory".to_owned(),
        })?;
        let callback_table_rva =
            tls_callback_table_rva.ok_or_else(|| AnalysisError::InvalidField {
                field: "TLS callbacks",
                reason: "entries exist without a callback-table RVA".to_owned(),
            })?;
        for callback in tls_callbacks {
            let slot_delta =
                callback
                    .table_index
                    .checked_mul(8)
                    .ok_or(AnalysisError::ArithmeticOverflow(
                        "TLS callback slot position",
                    ))?;
            let callback_slot_rva = callback_table_rva
                .checked_add(slot_delta)
                .ok_or(AnalysisError::ArithmeticOverflow("TLS callback slot RVA"))?;
            let (section_index, section) = file_backed_executable_section_for_rva(
                identity,
                callback.callback_rva,
                sections,
            )
            .ok_or_else(|| AnalysisError::InvalidField {
                field: "TLS callback target",
                reason: format!(
                    "entry {} resolves to RVA {:#x}, which is not fully file-backed executable data",
                    callback.table_index, callback.callback_rva
                ),
            })?;
            let mut evidence = Evidence::new(
                metadata_kind.clone(),
                "exact executable callback address from the PE32+ TLS callback table",
            )?;
            evidence.confidence = Some(exact_metadata_confidence);
            evidence.artifacts.insert(
                "tls_directory_rva".to_owned(),
                format!("{tls_directory_rva:#x}"),
            );
            evidence.artifacts.insert(
                "callback_table_rva".to_owned(),
                format!("{callback_table_rva:#x}"),
            );
            evidence.artifacts.insert(
                "callback_slot_rva".to_owned(),
                format!("{callback_slot_rva:#x}"),
            );
            evidence
                .artifacts
                .insert("table_index".to_owned(), callback.table_index.to_string());
            evidence.artifacts.insert(
                "callback_rva".to_owned(),
                format!("{:#x}", callback.callback_rva),
            );
            evidence
                .artifacts
                .insert("section_index".to_owned(), section_index.to_string());
            if !section.name.is_empty() {
                evidence
                    .artifacts
                    .insert("section_name".to_owned(), section.name.clone());
            }
            graph.submit_claim(SymbolClaim::new(
                SymbolSubject::Function {
                    binary: identity.id.clone(),
                    rva: u64::from(callback.callback_rva),
                    size: None,
                },
                SymbolAssertion::FunctionEntry,
                entry_point_confidence,
                vec![evidence],
                provenance("pe-tls-callback"),
            )?)?;
        }
    }

    for export in exports {
        if export.forwarded_to.is_some() {
            continue;
        }
        let Some(address_rva) = export.address_rva else {
            continue;
        };
        let Some((section_index, section)) = section_for_rva(address_rva, sections) else {
            continue;
        };
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let mut evidence = Evidence::new(
            metadata_kind.clone(),
            "executable function candidate from a local PE export-address-table entry",
        )?;
        evidence.confidence = Some(function_candidate_confidence);
        evidence
            .artifacts
            .insert("export_ordinal".to_owned(), export.ordinal.to_string());
        evidence
            .artifacts
            .insert("source_rva".to_owned(), format!("{address_rva:#x}"));
        evidence
            .artifacts
            .insert("section_index".to_owned(), section_index.to_string());
        graph.submit_claim(SymbolClaim::new(
            SymbolSubject::Function {
                binary: identity.id.clone(),
                rva: u64::from(address_rva),
                size: None,
            },
            SymbolAssertion::FunctionEntry,
            function_candidate_confidence,
            vec![evidence],
            provenance("pe-export-function-candidate"),
        )?)?;
    }

    for function in runtime_functions {
        let size_u32 = function
            .end_rva
            .checked_sub(function.begin_rva)
            .ok_or_else(|| AnalysisError::InvalidField {
                field: "runtime-function range",
                reason: format!(
                    "entry {} has {:#x}..{:#x}",
                    function.table_index, function.begin_rva, function.end_rva
                ),
            })?;
        if size_u32 == 0 {
            return invalid_field(
                "runtime-function range",
                format!("entry {} has an empty range", function.table_index),
            );
        }
        let size = u64::from(size_u32);
        let mut artifacts = BTreeMap::new();
        artifacts.insert("begin_rva".to_owned(), format!("{:#x}", function.begin_rva));
        artifacts.insert("end_rva".to_owned(), format!("{:#x}", function.end_rva));
        artifacts.insert("table_index".to_owned(), function.table_index.to_string());
        artifacts.insert(
            "unwind_info_rva".to_owned(),
            format!("{:#x}", function.unwind_info_rva),
        );
        let mut evidence = Evidence::new(
            metadata_kind.clone(),
            "exact function range from the x64 PE exception table",
        )?;
        evidence.confidence = Some(runtime_boundary_confidence);
        evidence.artifacts = artifacts;
        graph.submit_claim(SymbolClaim::new(
            SymbolSubject::Function {
                binary: identity.id.clone(),
                rva: u64::from(function.begin_rva),
                size: Some(size),
            },
            SymbolAssertion::FunctionBoundary { size },
            runtime_boundary_confidence,
            vec![evidence],
            provenance("pe-exception-directory"),
        )?)?;
    }

    for recovered in strings {
        let mut evidence = Evidence::new(
            string_literal_kind.clone(),
            "complete NUL-terminated literal recovered by a bounded scan of fully file-backed readable initialized non-executable PE data",
        )?;
        evidence.confidence = Some(recovered_string_confidence);
        evidence
            .artifacts
            .insert("source_rva".to_owned(), format!("{:#x}", recovered.rva));
        evidence
            .artifacts
            .insert("byte_size".to_owned(), recovered.byte_size.to_string());
        evidence.artifacts.insert(
            "encoding".to_owned(),
            recovered.encoding.as_str().to_owned(),
        );
        if let Some((section_index, section)) = section_for_rva(recovered.rva, sections) {
            evidence
                .artifacts
                .insert("section_index".to_owned(), section_index.to_string());
            if !section.name.is_empty() {
                evidence
                    .artifacts
                    .insert("section_name".to_owned(), section.name.clone());
            }
        }
        graph.submit_claim(SymbolClaim::new(
            SymbolSubject::Global {
                binary: identity.id.clone(),
                rva: u64::from(recovered.rva),
                size: Some(u64::from(recovered.byte_size)),
            },
            SymbolAssertion::StringLiteral {
                encoding: recovered.encoding,
                value: recovered.value.clone(),
            },
            recovered_string_confidence,
            vec![evidence],
            provenance("pe-string-recovery"),
        )?)?;
    }

    for reference in data_references {
        let mut evidence = Evidence::new(
            data_flow_kind.clone(),
            "exact x64 RIP-relative memory reference decoded during a bounded sweep of a fully file-backed runtime-function range",
        )?;
        evidence.confidence = Some(data_reference_confidence);
        evidence.artifacts.insert(
            "caller_rva".to_owned(),
            format!("{:#x}", reference.caller_rva),
        );
        evidence.artifacts.insert(
            "instruction_rva".to_owned(),
            format!("{:#x}", reference.instruction_rva),
        );
        evidence.artifacts.insert(
            "instruction_size".to_owned(),
            reference.instruction_size.to_string(),
        );
        evidence.artifacts.insert(
            "target_rva".to_owned(),
            format!("{:#x}", reference.target_rva),
        );
        graph.submit_claim(SymbolClaim::new(
            SymbolSubject::Function {
                binary: identity.id.clone(),
                rva: u64::from(reference.caller_rva),
                size: None,
            },
            SymbolAssertion::DataReference {
                instruction_rva: u64::from(reference.instruction_rva),
                instruction_size: reference.instruction_size,
                target_rva: u64::from(reference.target_rva),
            },
            data_reference_confidence,
            vec![evidence],
            provenance("pe-x64-data-reference"),
        )?)?;
    }

    let mut recovered_entry_sources = BTreeMap::<u32, RecoveredEntrySource>::new();
    for call in direct_calls {
        let target = core_control_flow_target(&call.target);
        let (evidence_summary, provenance_method, slot_rva) = match call.target {
            PeControlFlowTarget::FunctionPointer { slot_rva, .. } => (
                READ_ONLY_POINTER_CALL_EVIDENCE_SUMMARY,
                "pe-x64-read-only-pointer-call",
                Some(slot_rva),
            ),
            PeControlFlowTarget::Function { .. } | PeControlFlowTarget::ImportIat { .. } => {
                (DIRECT_CALL_EVIDENCE_SUMMARY, "pe-x64-direct-call", None)
            }
        };
        let mut evidence = Evidence::new(control_flow_kind.clone(), evidence_summary)?;
        evidence.confidence = Some(direct_call_confidence);
        evidence
            .artifacts
            .insert("caller_rva".to_owned(), format!("{:#x}", call.caller_rva));
        evidence.artifacts.insert(
            "call_site_rva".to_owned(),
            format!("{:#x}", call.call_site_rva),
        );
        evidence.artifacts.insert(
            "instruction_size".to_owned(),
            call.instruction_size.to_string(),
        );
        evidence
            .artifacts
            .insert("target_rva".to_owned(), format!("{:#x}", target.rva()));
        if let Some(slot_rva) = slot_rva {
            evidence
                .artifacts
                .insert("slot_rva".to_owned(), format!("{slot_rva:#x}"));
        }
        graph.submit_claim(SymbolClaim::new(
            SymbolSubject::Function {
                binary: identity.id.clone(),
                rva: u64::from(call.caller_rva),
                size: None,
            },
            SymbolAssertion::DirectCall {
                call_site_rva: u64::from(call.call_site_rva),
                target,
            },
            direct_call_confidence,
            vec![evidence],
            provenance(provenance_method),
        )?)?;

        if let PeControlFlowTarget::Function { rva }
        | PeControlFlowTarget::FunctionPointer { rva, .. } = call.target
        {
            let source = RecoveredEntrySource::DirectCall {
                caller_rva: call.caller_rva,
                call_site_rva: call.call_site_rva,
                instruction_size: call.instruction_size,
                slot_rva,
            };
            recovered_entry_sources
                .entry(rva)
                .and_modify(|retained| *retained = (*retained).min(source))
                .or_insert(source);
        }
    }

    for thunk in thunks {
        let target = core_control_flow_target(&thunk.target);
        let (evidence_summary, provenance_method, slot_rva) = match thunk.target {
            PeControlFlowTarget::FunctionPointer { slot_rva, .. } => (
                READ_ONLY_POINTER_THUNK_EVIDENCE_SUMMARY,
                "pe-x64-read-only-pointer-thunk",
                Some(slot_rva),
            ),
            PeControlFlowTarget::Function { .. } | PeControlFlowTarget::ImportIat { .. } => {
                (THUNK_EVIDENCE_SUMMARY, "pe-x64-jump-thunk", None)
            }
        };
        let mut evidence = Evidence::new(control_flow_kind.clone(), evidence_summary)?;
        evidence.confidence = Some(thunk_confidence);
        evidence
            .artifacts
            .insert("source_rva".to_owned(), format!("{:#x}", thunk.rva));
        evidence.artifacts.insert(
            "instruction_size".to_owned(),
            thunk.instruction_size.to_string(),
        );
        evidence
            .artifacts
            .insert("target_rva".to_owned(), format!("{:#x}", target.rva()));
        if let Some(slot_rva) = slot_rva {
            evidence
                .artifacts
                .insert("slot_rva".to_owned(), format!("{slot_rva:#x}"));
        }
        graph.submit_claim(SymbolClaim::new(
            SymbolSubject::Function {
                binary: identity.id.clone(),
                rva: u64::from(thunk.rva),
                size: None,
            },
            SymbolAssertion::ThunkTarget { target },
            thunk_confidence,
            vec![evidence],
            provenance(provenance_method),
        )?)?;

        if let PeControlFlowTarget::Function { rva }
        | PeControlFlowTarget::FunctionPointer { rva, .. } = thunk.target
        {
            let source = RecoveredEntrySource::Thunk {
                source_rva: thunk.rva,
                instruction_size: thunk.instruction_size,
                slot_rva,
            };
            recovered_entry_sources
                .entry(rva)
                .and_modify(|retained| *retained = (*retained).min(source))
                .or_insert(source);
        }
    }

    for (target_rva, source) in recovered_entry_sources {
        let mut evidence = match source {
            RecoveredEntrySource::DirectCall {
                caller_rva,
                call_site_rva,
                instruction_size,
                slot_rva,
            } => {
                let (summary, edge_kind) = if slot_rva.is_some() {
                    (
                        "conservative internal function candidate inferred from the deterministic first retained read-only pointer-call edge",
                        "read-only-pointer-call",
                    )
                } else {
                    (
                        "conservative internal function candidate inferred from the deterministic first retained direct-call edge",
                        "direct-call",
                    )
                };
                let mut evidence = Evidence::new(control_flow_kind.clone(), summary)?;
                evidence
                    .artifacts
                    .insert("edge_kind".to_owned(), edge_kind.to_owned());
                evidence
                    .artifacts
                    .insert("caller_rva".to_owned(), format!("{caller_rva:#x}"));
                evidence
                    .artifacts
                    .insert("call_site_rva".to_owned(), format!("{call_site_rva:#x}"));
                evidence
                    .artifacts
                    .insert("instruction_size".to_owned(), instruction_size.to_string());
                if let Some(slot_rva) = slot_rva {
                    evidence
                        .artifacts
                        .insert("slot_rva".to_owned(), format!("{slot_rva:#x}"));
                }
                evidence
            }
            RecoveredEntrySource::Thunk {
                source_rva,
                instruction_size,
                slot_rva,
            } => {
                let (summary, edge_kind) = if slot_rva.is_some() {
                    (
                        "conservative internal function candidate inferred from the deterministic first retained read-only pointer-thunk edge",
                        "read-only-pointer-thunk",
                    )
                } else {
                    (
                        "conservative internal function candidate inferred from the deterministic first retained seeded-thunk edge",
                        "seeded-thunk",
                    )
                };
                let mut evidence = Evidence::new(control_flow_kind.clone(), summary)?;
                evidence
                    .artifacts
                    .insert("edge_kind".to_owned(), edge_kind.to_owned());
                evidence
                    .artifacts
                    .insert("source_rva".to_owned(), format!("{source_rva:#x}"));
                evidence
                    .artifacts
                    .insert("instruction_size".to_owned(), instruction_size.to_string());
                if let Some(slot_rva) = slot_rva {
                    evidence
                        .artifacts
                        .insert("slot_rva".to_owned(), format!("{slot_rva:#x}"));
                }
                evidence
            }
        };
        evidence.confidence = Some(recovered_target_confidence);
        evidence
            .artifacts
            .insert("target_rva".to_owned(), format!("{target_rva:#x}"));
        graph.submit_claim(SymbolClaim::new(
            SymbolSubject::Function {
                binary: identity.id.clone(),
                rva: u64::from(target_rva),
                size: None,
            },
            SymbolAssertion::FunctionEntry,
            recovered_target_confidence,
            vec![evidence],
            provenance("pe-x64-recovered-function-target"),
        )?)?;
    }

    let mut rtti_types = BTreeMap::<u32, (&str, &str, u32)>::new();
    for vftable in msvc_rtti_vftables {
        rtti_types.entry(vftable.type_descriptor_rva).or_insert((
            &vftable.decorated_class_name,
            &vftable.class_name,
            vftable.rva,
        ));
        for base in &vftable.base_classes {
            rtti_types.entry(base.type_descriptor_rva).or_insert((
                &base.decorated_name,
                &base.name,
                vftable.rva,
            ));
        }
    }
    for (type_descriptor_rva, (decorated_name, name, source_vftable_rva)) in rtti_types {
        let mut evidence = Evidence::new(
            metadata_kind.clone(),
            "exact class name from a validated MSVC RTTI type descriptor",
        )?;
        evidence.confidence = Some(exact_metadata_confidence);
        evidence.artifacts.insert(
            "type_descriptor_rva".to_owned(),
            format!("{type_descriptor_rva:#x}"),
        );
        evidence
            .artifacts
            .insert("decorated_name".to_owned(), decorated_name.to_owned());
        evidence.artifacts.insert(
            "source_vftable_rva".to_owned(),
            format!("{source_vftable_rva:#x}"),
        );
        graph.submit_claim(SymbolClaim::new(
            SymbolSubject::Type {
                binary: identity.id.clone(),
                key: format!("msvc-rtti:type-descriptor:{type_descriptor_rva:08x}"),
            },
            SymbolAssertion::Name {
                name: name.to_owned(),
            },
            exact_metadata_confidence,
            vec![evidence],
            provenance("msvc-rtti-type-descriptor"),
        )?)?;
    }

    for vftable in msvc_rtti_vftables {
        let mut evidence = Evidence::new(
            metadata_kind.clone(),
            "validated MSVC x64 Rev1 RTTI vftable back-pointer and object locator",
        )?;
        evidence.confidence = Some(rtti_vftable_confidence);
        evidence.artifacts.insert(
            "complete_object_locator_rva".to_owned(),
            format!("{:#x}", vftable.complete_object_locator_rva),
        );
        evidence.artifacts.insert(
            "type_descriptor_rva".to_owned(),
            format!("{:#x}", vftable.type_descriptor_rva),
        );
        evidence.artifacts.insert(
            "class_hierarchy_descriptor_rva".to_owned(),
            format!("{:#x}", vftable.class_hierarchy_descriptor_rva),
        );
        evidence.artifacts.insert(
            "slot_count".to_owned(),
            vftable.virtual_function_rvas.len().to_string(),
        );
        graph.submit_claim(SymbolClaim::new(
            SymbolSubject::Global {
                binary: identity.id.clone(),
                rva: u64::from(vftable.rva),
                size: None,
            },
            SymbolAssertion::Name {
                name: rtti_vftable_name(vftable),
            },
            rtti_vftable_confidence,
            vec![evidence],
            provenance("msvc-rtti-vftable"),
        )?)?;

        for (slot_index, function_rva) in vftable.virtual_function_rvas.iter().enumerate() {
            let mut evidence = Evidence::new(
                metadata_kind.clone(),
                "contiguous executable slot candidate following a validated MSVC RTTI vftable address point",
            )?;
            evidence.confidence = Some(rtti_slot_confidence);
            evidence
                .artifacts
                .insert("vftable_rva".to_owned(), format!("{:#x}", vftable.rva));
            evidence
                .artifacts
                .insert("slot_index".to_owned(), slot_index.to_string());
            evidence
                .artifacts
                .insert("target_rva".to_owned(), format!("{function_rva:#x}"));
            graph.submit_claim(SymbolClaim::new(
                SymbolSubject::Function {
                    binary: identity.id.clone(),
                    rva: u64::from(*function_rva),
                    size: None,
                },
                SymbolAssertion::ClassMembership {
                    class_name: vftable.class_name.clone(),
                },
                rtti_slot_confidence,
                vec![evidence],
                provenance("msvc-rtti-vftable-slot"),
            )?)?;
        }
    }
    Ok(graph)
}

fn core_control_flow_target(target: &PeControlFlowTarget) -> ControlFlowTarget {
    match *target {
        PeControlFlowTarget::Function { rva } => ControlFlowTarget::Function {
            rva: u64::from(rva),
        },
        PeControlFlowTarget::ImportIat { iat_rva } => ControlFlowTarget::ImportIat {
            iat_rva: u64::from(iat_rva),
        },
        PeControlFlowTarget::FunctionPointer { slot_rva, rva } => {
            ControlFlowTarget::FunctionPointer {
                slot_rva: u64::from(slot_rva),
                rva: u64::from(rva),
            }
        }
    }
}

fn rtti_vftable_name(vftable: &MsvcRttiVftable) -> String {
    if vftable.offset == 0 && vftable.constructor_displacement_offset == 0 {
        format!("{}::vftable", vftable.class_name)
    } else {
        let mut name = format!("{}::vftable@0x{:x}", vftable.class_name, vftable.offset);
        if vftable.constructor_displacement_offset != 0 {
            name.push_str(&format!(
                "_cd_0x{:x}",
                vftable.constructor_displacement_offset
            ));
        }
        name
    }
}

fn file_backed_executable_section_for_rva<'a>(
    identity: &BinaryIdentity,
    rva: u32,
    sections: &'a [PeSection],
) -> Option<(usize, &'a PeSection)> {
    let (section_index, section) = section_for_rva(rva, sections)?;
    if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
        return None;
    }
    let delta = rva.checked_sub(section.virtual_address)?;
    if delta >= section.file_backed_size() {
        return None;
    }
    let file_offset = u64::from(section.raw_data_offset).checked_add(u64::from(delta))?;
    (file_offset < identity.size).then_some((section_index, section))
}

pub(crate) fn section_for_rva(rva: u32, sections: &[PeSection]) -> Option<(usize, &PeSection)> {
    sections.iter().enumerate().find(|(_, section)| {
        let start = u64::from(section.virtual_address);
        let size = u64::from(section.loaded_size());
        let end = start.saturating_add(size);
        (start..end).contains(&u64::from(rva))
    })
}

fn section_for_rva_range(
    rva: u32,
    size: u32,
    sections: &[PeSection],
) -> Option<(usize, &PeSection)> {
    if size == 0 {
        return None;
    }
    let start = u64::from(rva);
    let end = start.checked_add(u64::from(size))?;
    sections.iter().enumerate().find(|(_, section)| {
        let section_start = u64::from(section.virtual_address);
        let section_size = u64::from(section.loaded_size());
        let section_end = section_start.saturating_add(section_size);
        start >= section_start && end <= section_end
    })
}

pub(crate) struct RvaMap<'a> {
    bytes: &'a [u8],
    size_of_headers: u32,
    sections: &'a [PeSection],
}

impl<'a> RvaMap<'a> {
    const fn new(bytes: &'a [u8], size_of_headers: u32, sections: &'a [PeSection]) -> Self {
        Self {
            bytes,
            size_of_headers,
            sections,
        }
    }

    fn offset(&self, rva: u32, size: usize, context: &'static str) -> Result<usize, AnalysisError> {
        let size_u64 =
            u64::try_from(size).map_err(|_| AnalysisError::IntegerConversion("RVA range size"))?;
        let end = u64::from(rva)
            .checked_add(size_u64)
            .ok_or(AnalysisError::ArithmeticOverflow("RVA range"))?;
        if rva < self.size_of_headers && end <= u64::from(self.size_of_headers) {
            let offset =
                usize::try_from(rva).map_err(|_| AnalysisError::IntegerConversion("header RVA"))?;
            ensure_slice(self.bytes, offset, size, context)?;
            return Ok(offset);
        }

        for section in self.sections {
            let section_start = u64::from(section.virtual_address);
            let backed_end = section_start
                .checked_add(u64::from(section.file_backed_size()))
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "section-backed RVA range",
                ))?;
            if u64::from(rva) >= section_start && end <= backed_end {
                let delta = u64::from(rva) - section_start;
                let offset_u64 = u64::from(section.raw_data_offset)
                    .checked_add(delta)
                    .ok_or(AnalysisError::ArithmeticOverflow("RVA file offset"))?;
                let offset = usize::try_from(offset_u64)
                    .map_err(|_| AnalysisError::IntegerConversion("RVA file offset"))?;
                ensure_slice(self.bytes, offset, size, context)?;
                return Ok(offset);
            }
        }
        Err(AnalysisError::UnmappedRva { context, rva, size })
    }

    pub(crate) fn read_u32(&self, rva: u32, context: &'static str) -> Option<u32> {
        let offset = self.offset(rva, 4, context).ok()?;
        let mut value = [0_u8; 4];
        value.copy_from_slice(self.bytes.get(offset..offset + 4)?);
        Some(u32::from_le_bytes(value))
    }

    pub(crate) fn read_i32(&self, rva: u32, context: &'static str) -> Option<i32> {
        self.read_u32(rva, context)
            .map(|value| i32::from_le_bytes(value.to_le_bytes()))
    }

    pub(crate) fn read_u64(&self, rva: u32, context: &'static str) -> Option<u64> {
        let offset = self.offset(rva, 8, context).ok()?;
        let mut value = [0_u8; 8];
        value.copy_from_slice(self.bytes.get(offset..offset + 8)?);
        Some(u64::from_le_bytes(value))
    }

    pub(crate) fn is_backed(&self, rva: u32, size: usize) -> bool {
        self.offset(rva, size, "file-backed RVA check").is_ok()
    }

    pub(crate) fn bytes(
        &self,
        rva: u32,
        size: usize,
        context: &'static str,
    ) -> Result<&'a [u8], AnalysisError> {
        let offset = self.offset(rva, size, context)?;
        ensure_slice(self.bytes, offset, size, context)
    }

    pub(crate) fn contiguous_bytes(
        &self,
        rva: u32,
        context: &'static str,
    ) -> Result<&'a [u8], AnalysisError> {
        if rva < self.size_of_headers {
            let offset = usize::try_from(rva)
                .map_err(|_| AnalysisError::IntegerConversion("header string RVA"))?;
            let declared_end = usize::try_from(self.size_of_headers)
                .map_err(|_| AnalysisError::IntegerConversion("size of headers"))?;
            let end = declared_end.min(self.bytes.len());
            return self
                .bytes
                .get(offset..end)
                .ok_or(AnalysisError::UnmappedRva {
                    context,
                    rva,
                    size: 1,
                });
        }
        for section in self.sections {
            let start = u64::from(section.virtual_address);
            let file_backed_size = section.file_backed_size();
            let end = start.checked_add(u64::from(file_backed_size)).ok_or(
                AnalysisError::ArithmeticOverflow("section-backed RVA range"),
            )?;
            if u64::from(rva) >= start && u64::from(rva) < end {
                let delta = u64::from(rva) - start;
                let offset = u64::from(section.raw_data_offset)
                    .checked_add(delta)
                    .ok_or(AnalysisError::ArithmeticOverflow("string file offset"))?;
                let raw_end = u64::from(section.raw_data_offset)
                    .checked_add(u64::from(file_backed_size))
                    .ok_or(AnalysisError::ArithmeticOverflow("section raw range"))?;
                let offset = usize::try_from(offset)
                    .map_err(|_| AnalysisError::IntegerConversion("string file offset"))?;
                let raw_end = usize::try_from(raw_end)
                    .map_err(|_| AnalysisError::IntegerConversion("section raw end"))?;
                return self
                    .bytes
                    .get(offset..raw_end)
                    .ok_or(AnalysisError::UnmappedRva {
                        context,
                        rva,
                        size: 1,
                    });
            }
        }
        Err(AnalysisError::UnmappedRva {
            context,
            rva,
            size: 1,
        })
    }

    pub(crate) fn c_string(
        &self,
        rva: u32,
        context: &'static str,
        limit: usize,
    ) -> Result<String, AnalysisError> {
        if limit == 0 {
            return Err(AnalysisError::UnterminatedString {
                context,
                rva,
                limit,
            });
        }
        let bytes = self.contiguous_bytes(rva, context)?;
        let bounded_length = bytes.len().min(limit);
        let bounded = &bytes[..bounded_length];
        let Some(end) = bounded.iter().position(|byte| *byte == 0) else {
            return Err(AnalysisError::UnterminatedString {
                context,
                rva,
                limit: bounded_length,
            });
        };
        str::from_utf8(&bounded[..end])
            .map(str::to_owned)
            .map_err(|_| AnalysisError::InvalidUtf8 { context, rva })
    }
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    const fn len(&self) -> usize {
        self.data.len()
    }

    fn bytes(
        &self,
        offset: usize,
        size: usize,
        context: &'static str,
    ) -> Result<&'a [u8], AnalysisError> {
        ensure_slice(self.data, offset, size, context)
    }

    fn u16(&self, offset: usize, context: &'static str) -> Result<u16, AnalysisError> {
        let mut value = [0_u8; 2];
        value.copy_from_slice(self.bytes(offset, 2, context)?);
        Ok(u16::from_le_bytes(value))
    }

    fn u32(&self, offset: usize, context: &'static str) -> Result<u32, AnalysisError> {
        let mut value = [0_u8; 4];
        value.copy_from_slice(self.bytes(offset, 4, context)?);
        Ok(u32::from_le_bytes(value))
    }

    fn u64(&self, offset: usize, context: &'static str) -> Result<u64, AnalysisError> {
        let mut value = [0_u8; 8];
        value.copy_from_slice(self.bytes(offset, 8, context)?);
        Ok(u64::from_le_bytes(value))
    }
}

fn ensure_slice<'a>(
    bytes: &'a [u8],
    offset: usize,
    size: usize,
    context: &'static str,
) -> Result<&'a [u8], AnalysisError> {
    let end = offset
        .checked_add(size)
        .ok_or(AnalysisError::ArithmeticOverflow("file byte range"))?;
    bytes.get(offset..end).ok_or(AnalysisError::Truncated {
        context,
        offset,
        needed: size,
        available: bytes.len().saturating_sub(offset),
    })
}

fn checked_add(left: usize, right: usize, context: &'static str) -> Result<usize, AnalysisError> {
    left.checked_add(right)
        .ok_or(AnalysisError::ArithmeticOverflow(context))
}

fn checked_mul(left: usize, right: usize, context: &'static str) -> Result<usize, AnalysisError> {
    left.checked_mul(right)
        .ok_or(AnalysisError::ArithmeticOverflow(context))
}

fn checked_u32_add(left: u32, right: u32, context: &'static str) -> Result<u32, AnalysisError> {
    left.checked_add(right)
        .ok_or(AnalysisError::ArithmeticOverflow(context))
}

fn checked_u32_mul(left: u32, right: u32, context: &'static str) -> Result<u32, AnalysisError> {
    left.checked_mul(right)
        .ok_or(AnalysisError::ArithmeticOverflow(context))
}

fn enforce_limit(kind: &'static str, count: u64, limit: u64) -> Result<(), AnalysisError> {
    if count > limit {
        Err(AnalysisError::LimitExceeded { kind, count, limit })
    } else {
        Ok(())
    }
}

fn enforce_directory_size(kind: &'static str, size: u32) -> Result<(), AnalysisError> {
    enforce_limit(kind, u64::from(size), MAX_DIRECTORY_BYTES)
}

fn enforce_string_length(kind: &'static str, value: &str) -> Result<(), AnalysisError> {
    let length = u64::try_from(value.len())
        .map_err(|_| AnalysisError::IntegerConversion("decoded string length"))?;
    enforce_limit(kind, length, MAX_STRING_CONTENT_BYTES)
}

fn consume_count_budget(
    consumed: &mut u64,
    kind: &'static str,
    limit: u64,
) -> Result<(), AnalysisError> {
    *consumed = (*consumed)
        .checked_add(1)
        .ok_or(AnalysisError::ArithmeticOverflow("record count budget"))?;
    enforce_limit(kind, *consumed, limit)
}

fn consume_string_budget(
    consumed: &mut u64,
    value: &str,
    kind: &'static str,
    limit: u64,
) -> Result<(), AnalysisError> {
    let length = u64::try_from(value.len())
        .map_err(|_| AnalysisError::IntegerConversion("decoded string length"))?;
    *consumed = (*consumed)
        .checked_add(length)
        .ok_or(AnalysisError::ArithmeticOverflow("decoded string budget"))?;
    enforce_limit(kind, *consumed, limit)
}

fn invalid_field<T>(field: &'static str, reason: impl Into<String>) -> Result<T, AnalysisError> {
    Err(AnalysisError::InvalidField {
        field,
        reason: reason.into(),
    })
}

fn validate_image_alignment(
    section_alignment: u32,
    file_alignment: u32,
    size_of_image: u32,
    size_of_headers: u32,
) -> Result<(), AnalysisError> {
    if !section_alignment.is_power_of_two() {
        return invalid_field("section alignment", "must be a non-zero power of two");
    }
    if !file_alignment.is_power_of_two() {
        return invalid_field("file alignment", "must be a non-zero power of two");
    }
    if section_alignment < file_alignment {
        return invalid_field(
            "section alignment",
            "must be greater than or equal to file alignment",
        );
    }
    if !(MIN_STANDARD_FILE_ALIGNMENT..=MAX_FILE_ALIGNMENT).contains(&file_alignment) {
        return invalid_field(
            "file alignment",
            format!("must be between {MIN_STANDARD_FILE_ALIGNMENT:#x} and {MAX_FILE_ALIGNMENT:#x}"),
        );
    }
    if section_alignment < X64_PAGE_SIZE && file_alignment != section_alignment {
        return invalid_field(
            "file alignment",
            "must equal section alignment for sub-page images",
        );
    }
    if size_of_image % section_alignment != 0 {
        return invalid_field("size of image", "must be aligned to section alignment");
    }
    if size_of_headers % file_alignment != 0 {
        return invalid_field("size of headers", "must be aligned to file alignment");
    }
    Ok(())
}

fn validate_section_alignment(
    index: usize,
    section: &PeSection,
    section_alignment: u32,
    file_alignment: u32,
) -> Result<(), AnalysisError> {
    if section.loaded_size() != 0 && section.virtual_address % section_alignment != 0 {
        return invalid_field(
            "section virtual alignment",
            format!(
                "section {index} VirtualAddress {:#x} is not aligned to SectionAlignment {section_alignment:#x}",
                section.virtual_address
            ),
        );
    }
    if section.raw_data_size != 0 && section.raw_data_size % file_alignment != 0 {
        return invalid_field(
            "section raw-data alignment",
            format!(
                "section {index} SizeOfRawData {:#x} is not aligned to FileAlignment {file_alignment:#x}",
                section.raw_data_size
            ),
        );
    }
    if section.raw_data_offset != 0 && section.raw_data_offset % file_alignment != 0 {
        return invalid_field(
            "section raw-data alignment",
            format!(
                "section {index} PointerToRawData {:#x} is not aligned to FileAlignment {file_alignment:#x}",
                section.raw_data_offset
            ),
        );
    }
    if section_alignment < X64_PAGE_SIZE
        && section.raw_data_size != 0
        && section.raw_data_offset != section.virtual_address
    {
        return invalid_field(
            "sub-page section layout",
            format!(
                "section {index} PointerToRawData {:#x} must equal VirtualAddress {:#x}",
                section.raw_data_offset, section.virtual_address
            ),
        );
    }
    Ok(())
}

fn validate_section_overlaps(sections: &[PeSection]) -> Result<(), AnalysisError> {
    for first in 0..sections.len() {
        for second in first + 1..sections.len() {
            let left = &sections[first];
            let right = &sections[second];
            let left_virtual_size = left.loaded_size();
            let right_virtual_size = right.loaded_size();
            if ranges_overlap(
                u64::from(left.virtual_address),
                u64::from(left_virtual_size),
                u64::from(right.virtual_address),
                u64::from(right_virtual_size),
            )? {
                return Err(AnalysisError::OverlappingSections {
                    first,
                    second,
                    space: "virtual",
                });
            }
            if ranges_overlap(
                u64::from(left.raw_data_offset),
                u64::from(left.raw_data_size),
                u64::from(right.raw_data_offset),
                u64::from(right.raw_data_size),
            )? {
                return Err(AnalysisError::OverlappingSections {
                    first,
                    second,
                    space: "file",
                });
            }
        }
    }
    Ok(())
}

fn ranges_overlap(
    left_start: u64,
    left_size: u64,
    right_start: u64,
    right_size: u64,
) -> Result<bool, AnalysisError> {
    if left_size == 0 || right_size == 0 {
        return Ok(false);
    }
    let left_end = left_start
        .checked_add(left_size)
        .ok_or(AnalysisError::ArithmeticOverflow("section range"))?;
    let right_end = right_start
        .checked_add(right_size)
        .ok_or(AnalysisError::ArithmeticOverflow("section range"))?;
    Ok(left_start < right_end && right_start < left_end)
}

fn display_section_name(raw_name_bytes: &[u8; 8]) -> String {
    let end = raw_name_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(raw_name_bytes.len());
    let mut name = String::new();
    for byte in &raw_name_bytes[..end] {
        if byte.is_ascii_graphic() || *byte == b' ' {
            name.push(char::from(*byte));
        } else {
            name.push('\\');
            name.push('x');
            push_hex_byte(&mut name, *byte);
        }
    }
    name
}

fn format_hex(bytes: &[u8]) -> String {
    let mut output = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            output.push(' ');
        }
        push_hex_byte(&mut output, *byte);
    }
    output
}

fn push_hex_byte(output: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
}

#[cfg(test)]
mod section_layout_tests {
    use super::*;

    fn section(
        virtual_address: u32,
        virtual_size: u32,
        raw_data_offset: u32,
        raw_data_size: u32,
    ) -> PeSection {
        PeSection {
            name: ".test".to_owned(),
            raw_name: *b".test\0\0\0",
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size,
            characteristics: IMAGE_SCN_MEM_EXECUTE,
        }
    }

    #[test]
    fn raw_alignment_padding_is_neither_loaded_nor_file_backed() {
        let sections = [section(0x1000, 0x801, 0x200, 0xa00)];
        assert_eq!(sections[0].loaded_size(), 0x801);
        assert_eq!(sections[0].file_backed_size(), 0x801);

        assert!(section_for_rva(0x1800, &sections).is_some());
        assert!(section_for_rva(0x1801, &sections).is_none());
        assert!(section_for_rva_range(0x1800, 1, &sections).is_some());
        assert!(section_for_rva_range(0x1801, 1, &sections).is_none());

        let bytes = vec![0_u8; 0xc00];
        let mapper = RvaMap::new(&bytes, 0x200, &sections);
        assert!(mapper.is_backed(0x1800, 1));
        assert!(!mapper.is_backed(0x1801, 1));
        assert_eq!(
            mapper
                .contiguous_bytes(0x1800, "last initialized byte")
                .expect("last loaded byte is initialized")
                .len(),
            1
        );
    }

    #[test]
    fn zero_virtual_size_falls_back_to_the_raw_size() {
        let sections = [section(0x1000, 0, 0x200, 0xa00)];
        assert_eq!(sections[0].loaded_size(), 0xa00);
        assert_eq!(sections[0].file_backed_size(), 0xa00);

        assert!(section_for_rva(0x19ff, &sections).is_some());
        assert!(section_for_rva(0x1a00, &sections).is_none());
        let bytes = vec![0_u8; 0xc00];
        let mapper = RvaMap::new(&bytes, 0x200, &sections);
        assert!(mapper.is_backed(0x19ff, 1));
        assert!(!mapper.is_backed(0x1a00, 1));
    }

    #[test]
    fn virtual_zero_fill_is_loaded_but_not_file_backed() {
        let sections = [section(0x1000, 0xa00, 0x200, 0x801)];
        assert_eq!(sections[0].loaded_size(), 0xa00);
        assert_eq!(sections[0].file_backed_size(), 0x801);

        assert!(section_for_rva(0x1900, &sections).is_some());
        let bytes = vec![0_u8; 0xa01];
        let mapper = RvaMap::new(&bytes, 0x200, &sections);
        assert!(!mapper.is_backed(0x1900, 1));
    }

    #[test]
    fn overlap_checks_use_loaded_spans_not_raw_padding() {
        let mut sections = [
            section(0x1000, 0x801, 0x200, 0x1200),
            section(0x2000, 0x100, 0x1400, 0x200),
        ];
        for (index, section) in sections.iter().enumerate() {
            validate_section_alignment(index, section, 0x1000, 0x200)
                .expect("standard section placement is aligned");
        }
        validate_section_overlaps(&sections)
            .expect("raw alignment padding does not overlap in virtual memory");

        sections[0].virtual_size = 0x1001;
        assert!(matches!(
            validate_section_overlaps(&sections),
            Err(AnalysisError::OverlappingSections {
                first: 0,
                second: 1,
                space: "virtual"
            })
        ));

        sections[0].virtual_size = 0;
        assert!(matches!(
            validate_section_overlaps(&sections),
            Err(AnalysisError::OverlappingSections {
                first: 0,
                second: 1,
                space: "virtual"
            })
        ));
    }

    #[test]
    fn accepts_standard_and_sub_page_section_placement() {
        validate_image_alignment(0x1000, 0x200, 0x3000, 0x200)
            .expect("standard PE image alignment");
        validate_section_alignment(0, &section(0x1000, 0x801, 0x200, 0xa00), 0x1000, 0x200)
            .expect("standard PE section alignment");

        validate_image_alignment(0x200, 0x200, 0x2000, 0x200)
            .expect("sub-page image uses identical alignments");
        validate_section_alignment(0, &section(0x400, 0x180, 0x400, 0x200), 0x200, 0x200)
            .expect("sub-page section has matching RVA and file offset");
    }

    #[test]
    fn rejects_invalid_image_alignment_contracts() {
        assert!(validate_image_alignment(0x1800, 0x200, 0x3000, 0x200).is_err());
        assert!(validate_image_alignment(0x1000, 0x180, 0x3000, 0x200).is_err());
        assert!(validate_image_alignment(0x200, 0x400, 0x2000, 0x400).is_err());
        assert!(validate_image_alignment(0x400, 0x200, 0x2000, 0x200).is_err());
        assert!(validate_image_alignment(0x1000, 0x200, 0x2800, 0x200).is_err());
        assert!(validate_image_alignment(0x1000, 0x200, 0x3000, 0x300).is_err());
    }

    #[test]
    fn rejects_misaligned_or_inconsistent_section_placement() {
        let misaligned_virtual = section(0x1800, 0x801, 0x200, 0xa00);
        assert!(matches!(
            validate_section_alignment(0, &misaligned_virtual, 0x1000, 0x200),
            Err(AnalysisError::InvalidField {
                field: "section virtual alignment",
                ..
            })
        ));

        let misaligned_raw_size = section(0x1000, 0x801, 0x200, 0xa01);
        assert!(matches!(
            validate_section_alignment(0, &misaligned_raw_size, 0x1000, 0x200),
            Err(AnalysisError::InvalidField {
                field: "section raw-data alignment",
                ..
            })
        ));

        let misaligned_raw_offset = section(0x1000, 0x801, 0x201, 0xa00);
        assert!(matches!(
            validate_section_alignment(0, &misaligned_raw_offset, 0x1000, 0x200),
            Err(AnalysisError::InvalidField {
                field: "section raw-data alignment",
                ..
            })
        ));

        let sub_page_offset_mismatch = section(0x400, 0x180, 0x600, 0x200);
        assert!(matches!(
            validate_section_alignment(0, &sub_page_offset_mismatch, 0x200, 0x200),
            Err(AnalysisError::InvalidField {
                field: "sub-page section layout",
                ..
            })
        ));
    }
}
