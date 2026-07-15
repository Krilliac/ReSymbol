use std::{
    cmp,
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
    PeControlFlowTarget, PeDataDirectories, PeDataReference, PeDirectCall, PeExport, PeExportName,
    PeImport, PeImportLibrary, PeRecoveredString, PeSection, PeThunk, RuntimeFunction,
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
const DATA_DIRECTORY_SIZE: usize = 8;
const DEBUG_DIRECTORY_ENTRY_SIZE: usize = 28;
const DEBUG_DIRECTORY_ENTRY_SIZE_U32: u32 = 28;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const IMPORT_DESCRIPTOR_SIZE_U32: u32 = 20;
const RUNTIME_FUNCTION_SIZE: usize = 12;
const RUNTIME_FUNCTION_SIZE_U32: u32 = 12;

const MACHINE_AMD64: u16 = 0x8664;
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x020b;
const IMPORT_BY_ORDINAL_64: u64 = 1_u64 << 63;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

const MAX_PE_HEADER_OFFSET: u32 = 16 * 1024 * 1024;
const MAX_SECTIONS: u64 = 96;
const MAX_DATA_DIRECTORIES: u64 = 16;
const MAX_DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPORT_LIBRARIES: u64 = 4_096;
const MAX_IMPORT_SYMBOLS: u64 = 65_536;
const MAX_IMPORT_NAME_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXPORT_FUNCTIONS: u64 = 65_536;
const MAX_EXPORT_NAMES: u64 = 65_536;
const MAX_EXPORT_NAME_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RUNTIME_FUNCTIONS: u64 = 262_144;
const MAX_DEBUG_DIRECTORY_ENTRIES: u64 = 4_096;
const MAX_CODEVIEW_RECORD_BYTES: u64 = 64 * 1_024;
const MAX_CODEVIEW_PATH_BYTES: u64 = 4_096;
const MAX_STRING_BYTES: usize = 4_096;
const MAX_STRING_CONTENT_BYTES: u64 = 4_095;
const MAX_PROVENANCE_VERSION_BYTES: usize = 128;

const EXPORT_DIRECTORY_INDEX: usize = 0;
const IMPORT_DIRECTORY_INDEX: usize = 1;
const EXCEPTION_DIRECTORY_INDEX: usize = 3;
const DEBUG_DIRECTORY_INDEX: usize = 6;

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
    },
    Thunk {
        source_rva: u32,
        instruction_size: u8,
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

pub(crate) struct SymbolGraphInput<'a> {
    pub identity: &'a BinaryIdentity,
    pub entry_point_rva: u32,
    pub sections: &'a [PeSection],
    pub exports: &'a [PeExport],
    pub runtime_functions: &'a [RuntimeFunction],
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

    let imports = parse_imports(&reader, &mapper, headers.directories.imports)?;
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
        exports: &exports,
        runtime_functions: &runtime_functions,
        msvc_rtti_vftables: &msvc_rtti_vftables,
    });

    let identity = pe_binary_identity(bytes, headers.image_base)?;
    let symbol_graph = build_symbol_graph(SymbolGraphInput {
        identity: &identity,
        entry_point_rva: headers.entry_point_rva,
        sections: &headers.sections,
        exports: &exports,
        runtime_functions: &runtime_functions,
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
        export_library_name,
        exports,
        runtime_functions,
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
    if analysis.section_alignment == 0 || analysis.file_alignment == 0 {
        return invalid_field(
            "PE alignment",
            "section and file alignment must be non-zero",
        );
    }
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
        let virtual_span = cmp::max(section.virtual_size, section.raw_data_size);
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
    ] {
        if let Some(directory) = directory {
            if !model_rva_is_backed(analysis, directory.rva, directory.size) {
                return invalid_field(name, "is not fully backed by file data");
            }
        }
    }

    let import_library_count = u64::try_from(analysis.imports.len())
        .map_err(|_| AnalysisError::IntegerConversion("import-library count"))?;
    enforce_limit("import library", import_library_count, MAX_IMPORT_LIBRARIES)?;
    let mut import_symbol_count = 0_u64;
    let mut import_name_bytes = 0_u64;
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
            MAX_IMPORT_LIBRARIES,
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
            expected.subject() == actual.subject()
                && expected.assertion() == actual.assertion()
                && expected.confidence() == actual.confidence()
                && expected.evidence() == actual.evidence()
                && expected.provenance().method == actual.provenance().method
                && expected.provenance().run_id == actual.provenance().run_id
                && producers_semantically_match(
                    &expected.provenance().producer,
                    &actual.provenance().producer,
                )
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
        let backed_end = start.saturating_add(u64::from(section.raw_data_size));
        u64::from(rva) >= start && end <= backed_end
    })
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
    if section_alignment == 0 || file_alignment == 0 {
        return invalid_field(
            "PE alignment",
            "section and file alignment must be non-zero",
        );
    }
    if size_of_headers > size_of_image {
        return invalid_field("size of headers", "must not exceed the declared image size");
    }
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

        let virtual_span = cmp::max(virtual_size, raw_data_size);
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

        sections.push(PeSection {
            name: display_section_name(&raw_name),
            raw_name,
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size,
            characteristics,
        });
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
        MAX_IMPORT_LIBRARIES,
    )?;
    let directory_size = usize::try_from(directory.size)
        .map_err(|_| AnalysisError::IntegerConversion("import-directory size"))?;
    let directory_offset = mapper.offset(directory.rva, directory_size, "import directory")?;

    let mut libraries = Vec::new();
    let mut total_symbols = 0_u64;
    let mut total_name_bytes = 0_u64;
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
        let name = mapper.c_string(name_rva, "import DLL name", MAX_STRING_BYTES)?;
        if name.is_empty() {
            return invalid_field(
                "import DLL name",
                format!("descriptor {index} has an empty name"),
            );
        }
        consume_string_budget(
            &mut total_name_bytes,
            &name,
            "import-name byte",
            MAX_IMPORT_NAME_BYTES,
        )?;
        let lookup_table_rva = if original_first_thunk == 0 {
            first_thunk
        } else {
            original_first_thunk
        };
        let entries = parse_import_thunks(
            reader,
            mapper,
            lookup_table_rva,
            first_thunk,
            &mut total_symbols,
            &mut total_name_bytes,
        )?;
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

fn parse_import_thunks(
    reader: &Reader<'_>,
    mapper: &RvaMap<'_>,
    lookup_table_rva: u32,
    first_thunk_rva: u32,
    total_symbols: &mut u64,
    total_name_bytes: &mut u64,
) -> Result<Vec<PeImport>, AnalysisError> {
    let mut entries = Vec::new();
    loop {
        enforce_limit("import symbol", *total_symbols, MAX_IMPORT_SYMBOLS)?;
        let index = u32::try_from(entries.len())
            .map_err(|_| AnalysisError::IntegerConversion("import thunk index"))?;
        let delta = checked_u32_mul(index, 8, "import thunk position")?;
        let lookup_rva = checked_u32_add(lookup_table_rva, delta, "import lookup RVA")?;
        let iat_rva = checked_u32_add(first_thunk_rva, delta, "import IAT RVA")?;
        let lookup_offset = mapper.offset(lookup_rva, 8, "import lookup thunk")?;
        let _ = mapper.offset(iat_rva, 8, "import address thunk")?;
        let value = reader.u64(lookup_offset, "import lookup thunk")?;
        if value == 0 {
            break;
        }
        if *total_symbols == MAX_IMPORT_SYMBOLS {
            return Err(AnalysisError::LimitExceeded {
                kind: "import symbol",
                count: (*total_symbols).saturating_add(1),
                limit: MAX_IMPORT_SYMBOLS,
            });
        }
        *total_symbols = (*total_symbols)
            .checked_add(1)
            .ok_or(AnalysisError::ArithmeticOverflow("import-symbol count"))?;

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
                total_name_bytes,
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
        let mut evidence = Evidence::new(
            control_flow_kind.clone(),
            "exact supported x64 call encoding observed during a bounded linear sweep of a file-backed runtime-function range",
        )?;
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
            provenance("pe-x64-direct-call"),
        )?)?;

        if let PeControlFlowTarget::Function { rva } = call.target {
            let source = RecoveredEntrySource::DirectCall {
                caller_rva: call.caller_rva,
                call_site_rva: call.call_site_rva,
                instruction_size: call.instruction_size,
            };
            recovered_entry_sources
                .entry(rva)
                .and_modify(|retained| *retained = (*retained).min(source))
                .or_insert(source);
        }
    }

    for thunk in thunks {
        let target = core_control_flow_target(&thunk.target);
        let mut evidence = Evidence::new(
            control_flow_kind.clone(),
            "exact unconditional x64 jump in the first instruction of a metadata-seeded executable candidate",
        )?;
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
        graph.submit_claim(SymbolClaim::new(
            SymbolSubject::Function {
                binary: identity.id.clone(),
                rva: u64::from(thunk.rva),
                size: None,
            },
            SymbolAssertion::ThunkTarget { target },
            thunk_confidence,
            vec![evidence],
            provenance("pe-x64-jump-thunk"),
        )?)?;

        if let PeControlFlowTarget::Function { rva } = thunk.target {
            let source = RecoveredEntrySource::Thunk {
                source_rva: thunk.rva,
                instruction_size: thunk.instruction_size,
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
            } => {
                let mut evidence = Evidence::new(
                    control_flow_kind.clone(),
                    "conservative internal function candidate inferred from the deterministic first retained direct-call edge",
                )?;
                evidence
                    .artifacts
                    .insert("edge_kind".to_owned(), "direct-call".to_owned());
                evidence
                    .artifacts
                    .insert("caller_rva".to_owned(), format!("{caller_rva:#x}"));
                evidence
                    .artifacts
                    .insert("call_site_rva".to_owned(), format!("{call_site_rva:#x}"));
                evidence
                    .artifacts
                    .insert("instruction_size".to_owned(), instruction_size.to_string());
                evidence
            }
            RecoveredEntrySource::Thunk {
                source_rva,
                instruction_size,
            } => {
                let mut evidence = Evidence::new(
                    control_flow_kind.clone(),
                    "conservative internal function candidate inferred from the deterministic first retained seeded-thunk edge",
                )?;
                evidence
                    .artifacts
                    .insert("edge_kind".to_owned(), "seeded-thunk".to_owned());
                evidence
                    .artifacts
                    .insert("source_rva".to_owned(), format!("{source_rva:#x}"));
                evidence
                    .artifacts
                    .insert("instruction_size".to_owned(), instruction_size.to_string());
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
    if delta >= section.raw_data_size {
        return None;
    }
    let file_offset = u64::from(section.raw_data_offset).checked_add(u64::from(delta))?;
    (file_offset < identity.size).then_some((section_index, section))
}

pub(crate) fn section_for_rva(rva: u32, sections: &[PeSection]) -> Option<(usize, &PeSection)> {
    sections.iter().enumerate().find(|(_, section)| {
        let start = u64::from(section.virtual_address);
        let size = u64::from(cmp::max(section.virtual_size, section.raw_data_size));
        let end = start.saturating_add(size);
        (start..end).contains(&u64::from(rva))
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
                .checked_add(u64::from(section.raw_data_size))
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
            let end = start.checked_add(u64::from(section.raw_data_size)).ok_or(
                AnalysisError::ArithmeticOverflow("section-backed RVA range"),
            )?;
            if u64::from(rva) >= start && u64::from(rva) < end {
                let delta = u64::from(rva) - start;
                let offset = u64::from(section.raw_data_offset)
                    .checked_add(delta)
                    .ok_or(AnalysisError::ArithmeticOverflow("string file offset"))?;
                let raw_end = u64::from(section.raw_data_offset)
                    .checked_add(u64::from(section.raw_data_size))
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

fn validate_section_overlaps(sections: &[PeSection]) -> Result<(), AnalysisError> {
    for first in 0..sections.len() {
        for second in first + 1..sections.len() {
            let left = &sections[first];
            let right = &sections[second];
            let left_virtual_size = cmp::max(left.virtual_size, left.raw_data_size);
            let right_virtual_size = cmp::max(right.virtual_size, right.raw_data_size);
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
