use resymbol_core::{
    BinaryFormat, BinaryId, BinaryIdentity, ClaimProducer, ClaimProvenance, Confidence, Evidence,
    EvidenceKind, SymbolAssertion, SymbolClaim, SymbolGraph, SymbolSubject,
};

use crate::{
    AnalysisError, ElfAnalysis, ElfClass, ElfEndian, ElfLoadSegment, ElfProgramHeader,
    ElfSectionHeader, ElfSymbol,
};

const ELF32_HEADER_SIZE: u16 = 52;
const ELF64_HEADER_SIZE: u16 = 64;
const ELF32_PROGRAM_HEADER_SIZE: u16 = 32;
const ELF64_PROGRAM_HEADER_SIZE: u16 = 56;
const ELF32_SECTION_HEADER_SIZE: u16 = 40;
const ELF64_SECTION_HEADER_SIZE: u16 = 64;
const ELF32_SYMBOL_SIZE: u16 = 16;
const ELF64_SYMBOL_SIZE: u16 = 24;
const ELF_CLASS_32: u8 = 1;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF_DATA_BIG_ENDIAN: u8 = 2;
const ELF_VERSION_CURRENT: u32 = 1;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_TYPE_DYNAMIC: u16 = 3;
const ELF_PROGRAM_TYPE_LOAD: u32 = 1;
const ELF_SECTION_TYPE_SYMTAB: u32 = 2;
const ELF_SECTION_TYPE_NOBITS: u32 = 8;
const ELF_SECTION_TYPE_DYNSYM: u32 = 11;
const ELF_SYMBOL_TYPE_OBJECT: u8 = 1;
const ELF_SYMBOL_TYPE_FUNC: u8 = 2;
const ELF_SECTION_FLAG_ALLOC: u32 = 0x2;
const ELF_SECTION_INDEX_EXTENDED: u16 = 0xffff;
const ELF32_ADDRESS_SPACE_END: u64 = 1_u64 << 32;
const MAX_PROGRAM_HEADERS: u64 = 1_024;
const MAX_SECTION_HEADERS: u64 = 4_096;
const MAX_ELF_SYMBOLS: usize = 262_144;

const EM_386: u16 = 3;
const EM_MIPS: u16 = 8;
const EM_PPC: u16 = 20;
const EM_PPC64: u16 = 21;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const EM_RISCV: u16 = 243;

impl ElfClass {
    const fn from_ident(value: u8) -> Option<Self> {
        match value {
            ELF_CLASS_32 => Some(Self::Elf32),
            ELF_CLASS_64 => Some(Self::Elf64),
            _ => None,
        }
    }

    const fn is_64(self) -> bool {
        matches!(self, Self::Elf64)
    }

    const fn header_size(self) -> u16 {
        match self {
            Self::Elf32 => ELF32_HEADER_SIZE,
            Self::Elf64 => ELF64_HEADER_SIZE,
        }
    }

    const fn program_header_size(self) -> u16 {
        match self {
            Self::Elf32 => ELF32_PROGRAM_HEADER_SIZE,
            Self::Elf64 => ELF64_PROGRAM_HEADER_SIZE,
        }
    }

    const fn section_header_size(self) -> u16 {
        match self {
            Self::Elf32 => ELF32_SECTION_HEADER_SIZE,
            Self::Elf64 => ELF64_SECTION_HEADER_SIZE,
        }
    }

    const fn symbol_size(self) -> u16 {
        match self {
            Self::Elf32 => ELF32_SYMBOL_SIZE,
            Self::Elf64 => ELF64_SYMBOL_SIZE,
        }
    }

    /// Exclusive virtual-address ceiling, or `None` for the full ELF64 space.
    const fn address_space_end(self) -> Option<u64> {
        match self {
            Self::Elf32 => Some(ELF32_ADDRESS_SPACE_END),
            Self::Elf64 => None,
        }
    }
}

impl ElfEndian {
    const fn from_ident(value: u8) -> Option<Self> {
        match value {
            ELF_DATA_LITTLE_ENDIAN => Some(Self::Little),
            ELF_DATA_BIG_ENDIAN => Some(Self::Big),
            _ => None,
        }
    }

    const fn suffix(self) -> &'static str {
        match self {
            Self::Little => "le",
            Self::Big => "be",
        }
    }
}

/// Decoded `e_machine` allow-list. Unknown values fall back to `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfMachine {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Mips,
    Mips64,
    Riscv,
    PowerPc,
    PowerPc64,
    Other(u16),
}

impl ElfMachine {
    /// Decode the raw `e_machine` value against the file class.
    #[must_use]
    pub const fn from_raw(machine: u16, class: ElfClass) -> Self {
        match machine {
            EM_386 => Self::X86,
            EM_MIPS => {
                if class.is_64() {
                    Self::Mips64
                } else {
                    Self::Mips
                }
            }
            EM_PPC => Self::PowerPc,
            EM_PPC64 => Self::PowerPc64,
            EM_ARM => Self::Arm,
            EM_X86_64 => Self::X86_64,
            EM_AARCH64 => Self::Aarch64,
            EM_RISCV => Self::Riscv,
            other => Self::Other(other),
        }
    }
}

/// Derive the canonical architecture string from class, machine, and byte order.
///
/// The ELF32 little-endian `EM_MIPS` case is kept byte-identical to preserve
/// existing fixtures and identities.
fn elf_architecture(class: ElfClass, machine: ElfMachine, endian: ElfEndian) -> String {
    let class_token = if class.is_64() { "elf64" } else { "elf32" };
    let (arch_token, with_endian) = match machine {
        ElfMachine::X86 => ("x86".to_owned(), true),
        ElfMachine::X86_64 => ("x86-64".to_owned(), false),
        ElfMachine::Arm => ("arm".to_owned(), true),
        ElfMachine::Aarch64 => ("aarch64".to_owned(), false),
        ElfMachine::Mips | ElfMachine::Mips64 => ("em-mips".to_owned(), true),
        ElfMachine::Riscv => ("riscv".to_owned(), true),
        ElfMachine::PowerPc => ("ppc".to_owned(), true),
        ElfMachine::PowerPc64 => ("ppc64".to_owned(), true),
        ElfMachine::Other(value) => (format!("em-{value:#06x}"), true),
    };
    if with_endian {
        format!("{class_token}-{arch_token}-{}", endian.suffix())
    } else {
        format!("{class_token}-{arch_token}")
    }
}

/// Parse a bounded ELF container without loading or executing it.
///
/// Both ELF32 and ELF64, either byte order, and any `e_machine` value are
/// accepted. This records only bounded container evidence, sparse `PT_LOAD`
/// mappings, and symbol-table name claims. It performs no instruction decoding.
pub fn analyze_elf(bytes: &[u8]) -> Result<ElfAnalysis, AnalysisError> {
    if bytes.len() < 16 {
        return Err(AnalysisError::Truncated {
            context: "ELF identity",
            offset: 0,
            needed: 16,
            available: bytes.len(),
        });
    }
    if &bytes[0..4] != b"\x7fELF" {
        return Err(AnalysisError::InvalidElfSignature);
    }
    let class = ElfClass::from_ident(bytes[4])
        .ok_or(AnalysisError::UnsupportedElfClass { class: bytes[4] })?;
    let endian = ElfEndian::from_ident(bytes[5])
        .ok_or(AnalysisError::UnsupportedElfDataEncoding { data: bytes[5] })?;
    let ident_version = bytes[6];
    if u32::from(ident_version) != ELF_VERSION_CURRENT {
        return Err(AnalysisError::UnsupportedElfVersion {
            version: u32::from(ident_version),
            context: "identity",
        });
    }

    let reader = ElfReader::new(bytes, class, endian);
    reader.require(0, usize::from(class.header_size()), "ELF header")?;
    if reader
        .bytes(9, 7, "ELF identity padding")?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(AnalysisError::InvalidField {
            field: "ELF identity padding",
            reason: "reserved bytes must be zero".to_owned(),
        });
    }

    let os_abi = reader.u8(7, "ELF OS ABI")?;
    let abi_version = reader.u8(8, "ELF ABI version")?;
    let elf_type = reader.u16(16, "ELF type")?;
    if elf_type != ELF_TYPE_EXECUTABLE && elf_type != ELF_TYPE_DYNAMIC {
        return Err(AnalysisError::UnsupportedElfType { elf_type });
    }
    let machine = reader.u16(18, "ELF machine")?;
    let elf_version = reader.u32(20, "ELF version")?;
    if elf_version != ELF_VERSION_CURRENT {
        return Err(AnalysisError::UnsupportedElfVersion {
            version: elf_version,
            context: "header",
        });
    }

    let entry_va = reader.addr(24, "ELF entry address")?;
    let program_header_offset;
    let section_header_offset;
    let flags;
    if class.is_64() {
        program_header_offset = reader.u64(32, "ELF program-header offset")?;
        section_header_offset = reader.u64(40, "ELF section-header offset")?;
        flags = reader.u32(48, "ELF flags")?;
    } else {
        program_header_offset = u64::from(reader.u32(28, "ELF program-header offset")?);
        section_header_offset = u64::from(reader.u32(32, "ELF section-header offset")?);
        flags = reader.u32(36, "ELF flags")?;
    }
    let ehsize_off = if class.is_64() { 52 } else { 40 };
    let header_size = reader.u16(ehsize_off, "ELF header size")?;
    if header_size != class.header_size() {
        return Err(AnalysisError::InvalidField {
            field: "ELF header size",
            reason: format!(
                "expected {} bytes for this class, found {header_size}",
                class.header_size()
            ),
        });
    }
    let program_header_entry_size = reader.u16(ehsize_off + 2, "ELF program-header entry size")?;
    let program_header_count = reader.u16(ehsize_off + 4, "ELF program-header count")?;
    let section_header_entry_size = reader.u16(ehsize_off + 6, "ELF section-header entry size")?;
    let section_header_count = reader.u16(ehsize_off + 8, "ELF section-header count")?;
    let section_name_table_index = reader.u16(ehsize_off + 10, "ELF section-name table index")?;

    if program_header_count == 0 {
        return Err(AnalysisError::InvalidField {
            field: "ELF program-header count",
            reason: "an executable image must contain at least one program header".to_owned(),
        });
    }
    enforce_count(
        "ELF program header",
        u64::from(program_header_count),
        MAX_PROGRAM_HEADERS,
    )?;
    if program_header_entry_size != class.program_header_size() {
        return Err(AnalysisError::InvalidField {
            field: "ELF program-header entry size",
            reason: format!(
                "expected {} bytes for this class, found {program_header_entry_size}",
                class.program_header_size()
            ),
        });
    }
    if program_header_offset < u64::from(header_size) {
        return Err(AnalysisError::InvalidField {
            field: "ELF program-header offset",
            reason: "the table overlaps the ELF header".to_owned(),
        });
    }
    reader.table(
        program_header_offset,
        program_header_count,
        program_header_entry_size,
        "ELF program-header table",
    )?;

    validate_section_table_header(
        &reader,
        section_header_offset,
        section_header_count,
        section_header_entry_size,
        section_name_table_index,
    )?;

    let program_headers = parse_program_headers(
        &reader,
        program_header_offset,
        program_header_count,
        program_header_entry_size,
    )?;
    let section_headers = parse_section_headers(
        &reader,
        section_header_offset,
        section_header_count,
        section_header_entry_size,
    )?;
    validate_section_header_zero(&section_headers)?;
    let input_size = u64::try_from(bytes.len())
        .map_err(|_| AnalysisError::IntegerConversion("ELF input size"))?;
    let load_segments = derive_load_segments(&program_headers, input_size, class)?;
    let (image_base, image_size) = image_extent(&load_segments)?;
    let entry_rva = entry_rva(elf_type, entry_va, image_base, &load_segments)?;
    let (symbols, symbol_scan_truncated) = parse_symbols(&reader, &section_headers)?;

    let machine_kind = ElfMachine::from_raw(machine, class);
    let identity = BinaryIdentity {
        id: BinaryId::digest(bytes),
        size: input_size,
        format: BinaryFormat::Elf,
        architecture: elf_architecture(class, machine_kind, endian),
        image_base,
    };
    let symbol_graph = build_symbol_graph(&identity, &symbols, &load_segments)?;
    let analysis = ElfAnalysis {
        identity,
        class,
        endian,
        os_abi,
        abi_version,
        elf_type,
        machine,
        elf_version,
        entry_va,
        entry_rva,
        flags,
        header_size,
        program_header_offset,
        program_header_entry_size,
        program_headers,
        section_header_offset,
        section_header_entry_size,
        section_name_table_index,
        section_headers,
        load_segments,
        image_size,
        symbols,
        symbol_scan_truncated,
        symbol_graph,
    };
    validate_elf_analysis(&analysis)?;
    Ok(analysis)
}

pub(crate) fn build_symbol_graph(
    identity: &BinaryIdentity,
    symbols: &[ElfSymbol],
    load_segments: &[ElfLoadSegment],
) -> Result<SymbolGraph, AnalysisError> {
    let mut graph = SymbolGraph::default();
    graph.insert_binary(identity.clone())?;

    let image_base = identity.image_base;
    let name_confidence = Confidence::new(0.95)?;
    let metadata_kind = EvidenceKind::new(EvidenceKind::METADATA)?;
    let provenance = ClaimProvenance {
        producer: ClaimProducer::Core {
            component: "resymbol-analysis".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        method: "elf-symbol-table".to_owned(),
        run_id: None,
    };

    for symbol in symbols {
        let symbol_type = symbol.info & 0x0f;
        let is_function = symbol_type == ELF_SYMBOL_TYPE_FUNC;
        let is_global = symbol_type == ELF_SYMBOL_TYPE_OBJECT;
        if (!is_function && !is_global) || symbol.name.is_empty() {
            continue;
        }
        let Some(rva) = symbol.value.checked_sub(image_base) else {
            continue;
        };
        if !rva_in_load_segment(rva, image_base, load_segments) {
            continue;
        }

        let mut evidence =
            Evidence::new(metadata_kind.clone(), "exact name from an ELF symbol table")?;
        evidence.confidence = Some(name_confidence);
        evidence
            .artifacts
            .insert("symbol_value".to_owned(), format!("{:#x}", symbol.value));
        evidence
            .artifacts
            .insert("symbol_rva".to_owned(), format!("{rva:#x}"));
        evidence
            .artifacts
            .insert("table_index".to_owned(), symbol.table_index.to_string());
        evidence.artifacts.insert(
            "symbol_kind".to_owned(),
            if is_function { "function" } else { "global" }.to_owned(),
        );
        let subject = if is_function {
            SymbolSubject::Function {
                binary: identity.id.clone(),
                rva,
                size: None,
            }
        } else {
            SymbolSubject::Global {
                binary: identity.id.clone(),
                rva,
                size: None,
            }
        };
        graph.submit_claim(SymbolClaim::new(
            subject,
            SymbolAssertion::Name {
                name: symbol.name.clone(),
            },
            name_confidence,
            vec![evidence],
            provenance.clone(),
        )?)?;
    }
    Ok(graph)
}

/// Whether `rva` lands inside any mapped `PT_LOAD` segment's memory extent.
fn rva_in_load_segment(rva: u64, image_base: u64, segments: &[ElfLoadSegment]) -> bool {
    segments.iter().any(|segment| {
        let Some(start) = segment.virtual_address.checked_sub(image_base) else {
            return false;
        };
        let Some(end) = start.checked_add(segment.memory_size) else {
            return false;
        };
        rva >= start && rva < end
    })
}

pub(crate) fn validate_elf_analysis(analysis: &ElfAnalysis) -> Result<(), AnalysisError> {
    analysis.identity.validate()?;
    if !matches!(analysis.identity.format, BinaryFormat::Elf) {
        return invalid("ELF identity format", "expected the ELF format marker");
    }
    let machine_kind = ElfMachine::from_raw(analysis.machine, analysis.class);
    let expected_architecture = elf_architecture(analysis.class, machine_kind, analysis.endian);
    if analysis.identity.architecture != expected_architecture {
        return invalid(
            "ELF identity architecture",
            &format!("expected `{expected_architecture}`"),
        );
    }
    if analysis.identity.size < u64::from(analysis.class.header_size()) {
        return invalid(
            "ELF identity size",
            "the file is smaller than one ELF header",
        );
    }
    if analysis.elf_type != ELF_TYPE_EXECUTABLE && analysis.elf_type != ELF_TYPE_DYNAMIC {
        return Err(AnalysisError::UnsupportedElfType {
            elf_type: analysis.elf_type,
        });
    }
    if analysis.elf_version != ELF_VERSION_CURRENT {
        return Err(AnalysisError::UnsupportedElfVersion {
            version: analysis.elf_version,
            context: "header",
        });
    }
    if analysis.header_size != analysis.class.header_size() {
        return invalid("ELF header size", "expected the canonical header size");
    }
    if analysis.program_header_entry_size != analysis.class.program_header_size() {
        return invalid(
            "ELF program-header entry size",
            "expected the canonical program-header size",
        );
    }
    if analysis.program_headers.is_empty() {
        return invalid("ELF program headers", "at least one record is required");
    }
    enforce_count(
        "ELF program header",
        usize_to_u64(analysis.program_headers.len(), "ELF program-header count")?,
        MAX_PROGRAM_HEADERS,
    )?;
    validate_table_model(
        analysis.program_header_offset,
        analysis.program_headers.len(),
        analysis.program_header_entry_size,
        analysis.identity.size,
        "ELF program-header table",
    )?;
    if analysis.program_header_offset < u64::from(analysis.header_size) {
        return invalid(
            "ELF program-header offset",
            "the table overlaps the ELF header",
        );
    }
    validate_section_table_model(analysis)?;
    for (index, header) in analysis.program_headers.iter().enumerate() {
        if usize::from(header.table_index) != index {
            return invalid(
                "ELF program-header index",
                "records must retain contiguous source-table order",
            );
        }
        validate_file_range(
            header.file_offset,
            header.file_size,
            analysis.identity.size,
            "ELF program segment",
        )?;
        validate_segment_alignment(header)?;
    }
    for (index, header) in analysis.section_headers.iter().enumerate() {
        if usize::from(header.table_index) != index {
            return invalid(
                "ELF section-header index",
                "records must retain contiguous source-table order",
            );
        }
        validate_section_header(header, analysis.identity.size, analysis.class)?;
    }

    let expected_load_segments = derive_load_segments(
        &analysis.program_headers,
        analysis.identity.size,
        analysis.class,
    )?;
    if analysis.load_segments != expected_load_segments {
        return invalid(
            "ELF load segments",
            "the sparse mapping does not match the ordered PT_LOAD records",
        );
    }
    let (image_base, image_size) = image_extent(&analysis.load_segments)?;
    if analysis.identity.image_base != image_base {
        return invalid(
            "ELF image base",
            "the identity base is not the lowest non-empty PT_LOAD address",
        );
    }
    if analysis.image_size != image_size {
        return invalid(
            "ELF image size",
            "the image extent does not match the sparse PT_LOAD mapping",
        );
    }
    let expected_entry_rva = entry_rva(
        analysis.elf_type,
        analysis.entry_va,
        image_base,
        &analysis.load_segments,
    )?;
    if analysis.entry_rva != expected_entry_rva {
        return invalid(
            "ELF entry RVA",
            "the RVA does not match the entry VA and image base",
        );
    }
    validate_symbols(&analysis.symbols)?;
    let expected_graph = build_symbol_graph(
        &analysis.identity,
        &analysis.symbols,
        &analysis.load_segments,
    )?;
    if analysis.symbol_graph != expected_graph {
        return invalid(
            "ELF symbol graph",
            "the graph must be reproducible from the exact identity and stored symbols",
        );
    }
    Ok(())
}

fn validate_symbols(symbols: &[ElfSymbol]) -> Result<(), AnalysisError> {
    if symbols.len() > MAX_ELF_SYMBOLS {
        return Err(AnalysisError::LimitExceeded {
            kind: "ELF symbol",
            count: usize_to_u64(symbols.len(), "ELF symbol count")?,
            limit: usize_to_u64(MAX_ELF_SYMBOLS, "ELF symbol cap")?,
        });
    }
    for symbol in symbols {
        if symbol.name.is_empty() {
            return invalid("ELF symbol name", "recovered symbols must be named");
        }
    }
    Ok(())
}

fn validate_section_table_header(
    reader: &ElfReader<'_>,
    offset: u64,
    count: u16,
    entry_size: u16,
    name_table_index: u16,
) -> Result<(), AnalysisError> {
    let class = reader.class;
    let canonical_entry_size = class.section_header_size();
    if count == 0 {
        if offset != 0 {
            return invalid(
                "ELF section-header count",
                "extended section numbering is not supported",
            );
        }
        if entry_size != 0 && entry_size != canonical_entry_size {
            return invalid(
                "ELF section-header entry size",
                "an absent table must use zero or the canonical entry size",
            );
        }
        if name_table_index != 0 {
            return invalid(
                "ELF section-name table index",
                "an absent section table cannot name a string table",
            );
        }
        return Ok(());
    }

    enforce_count("ELF section header", u64::from(count), MAX_SECTION_HEADERS)?;
    if entry_size != canonical_entry_size {
        return invalid(
            "ELF section-header entry size",
            &format!("expected {canonical_entry_size} bytes for this class, found {entry_size}"),
        );
    }
    if offset == 0 {
        return invalid(
            "ELF section-header offset",
            "a non-empty table must have a nonzero file offset",
        );
    }
    if offset < u64::from(class.header_size()) {
        return invalid(
            "ELF section-header offset",
            "the table overlaps the ELF header",
        );
    }
    if name_table_index == ELF_SECTION_INDEX_EXTENDED {
        return invalid(
            "ELF section-name table index",
            "extended section indexes are not supported",
        );
    }
    if name_table_index != 0 && name_table_index >= count {
        return invalid(
            "ELF section-name table index",
            "the index lies outside the section-header table",
        );
    }
    reader.table(offset, count, entry_size, "ELF section-header table")?;
    Ok(())
}

fn validate_section_table_model(analysis: &ElfAnalysis) -> Result<(), AnalysisError> {
    let canonical_entry_size = analysis.class.section_header_size();
    let count = analysis.section_headers.len();
    if count == 0 {
        if analysis.section_header_offset != 0
            || analysis.section_name_table_index != 0
            || (analysis.section_header_entry_size != 0
                && analysis.section_header_entry_size != canonical_entry_size)
        {
            return invalid(
                "ELF section-header table",
                "the absent table has inconsistent header metadata",
            );
        }
        return Ok(());
    }
    enforce_count(
        "ELF section header",
        usize_to_u64(count, "ELF section-header count")?,
        MAX_SECTION_HEADERS,
    )?;
    if analysis.section_header_entry_size != canonical_entry_size {
        return invalid(
            "ELF section-header entry size",
            "expected the canonical section-header size",
        );
    }
    if analysis.section_header_offset < u64::from(analysis.header_size) {
        return invalid(
            "ELF section-header offset",
            "the table overlaps the ELF header",
        );
    }
    if analysis.section_name_table_index == ELF_SECTION_INDEX_EXTENDED
        || (analysis.section_name_table_index != 0
            && usize::from(analysis.section_name_table_index) >= count)
    {
        return invalid(
            "ELF section-name table index",
            "the index lies outside the section-header table",
        );
    }
    validate_table_model(
        analysis.section_header_offset,
        count,
        analysis.section_header_entry_size,
        analysis.identity.size,
        "ELF section-header table",
    )?;
    validate_section_header_zero(&analysis.section_headers)
}

fn validate_section_header_zero(headers: &[ElfSectionHeader]) -> Result<(), AnalysisError> {
    let Some(header) = headers.first() else {
        return Ok(());
    };
    if header.name_offset != 0
        || header.section_type != 0
        || header.flags != 0
        || header.virtual_address != 0
        || header.file_offset != 0
        || header.size != 0
        || header.link != 0
        || header.info != 0
        || header.address_alignment != 0
        || header.entry_size != 0
    {
        return invalid(
            "ELF section header zero",
            "extended numbering is unsupported, so the reserved record must be all zero",
        );
    }
    Ok(())
}

fn parse_program_headers(
    reader: &ElfReader<'_>,
    offset: u64,
    count: u16,
    entry_size: u16,
) -> Result<Vec<ElfProgramHeader>, AnalysisError> {
    let mut headers = Vec::with_capacity(usize::from(count));
    for table_index in 0..count {
        let entry_offset = table_entry_offset(offset, table_index, entry_size)?;
        let header = if reader.class.is_64() {
            ElfProgramHeader {
                table_index,
                segment_type: reader.u32(entry_offset, "ELF program type")?,
                flags: reader.u32(entry_offset + 4, "ELF segment flags")?,
                file_offset: reader.u64(entry_offset + 8, "ELF segment file offset")?,
                virtual_address: reader.u64(entry_offset + 16, "ELF segment virtual address")?,
                physical_address: reader.u64(entry_offset + 24, "ELF segment physical address")?,
                file_size: reader.u64(entry_offset + 32, "ELF segment file size")?,
                memory_size: reader.u64(entry_offset + 40, "ELF segment memory size")?,
                alignment: narrow_alignment(
                    reader.u64(entry_offset + 48, "ELF segment alignment")?,
                    "ELF segment alignment",
                )?,
            }
        } else {
            ElfProgramHeader {
                table_index,
                segment_type: reader.u32(entry_offset, "ELF program type")?,
                file_offset: u64::from(reader.u32(entry_offset + 4, "ELF segment file offset")?),
                virtual_address: u64::from(
                    reader.u32(entry_offset + 8, "ELF segment virtual address")?,
                ),
                physical_address: u64::from(
                    reader.u32(entry_offset + 12, "ELF segment physical address")?,
                ),
                file_size: u64::from(reader.u32(entry_offset + 16, "ELF segment file size")?),
                memory_size: u64::from(reader.u32(entry_offset + 20, "ELF segment memory size")?),
                flags: reader.u32(entry_offset + 24, "ELF segment flags")?,
                alignment: reader.u32(entry_offset + 28, "ELF segment alignment")?,
            }
        };
        headers.push(header);
    }
    Ok(headers)
}

fn parse_section_headers(
    reader: &ElfReader<'_>,
    offset: u64,
    count: u16,
    entry_size: u16,
) -> Result<Vec<ElfSectionHeader>, AnalysisError> {
    let mut headers = Vec::with_capacity(usize::from(count));
    for table_index in 0..count {
        let entry_offset = table_entry_offset(offset, table_index, entry_size)?;
        let header = if reader.class.is_64() {
            ElfSectionHeader {
                table_index,
                name_offset: reader.u32(entry_offset, "ELF section-name offset")?,
                section_type: reader.u32(entry_offset + 4, "ELF section type")?,
                flags: narrow_section_flags(reader.u64(entry_offset + 8, "ELF section flags")?)?,
                virtual_address: reader.u64(entry_offset + 16, "ELF section virtual address")?,
                file_offset: reader.u64(entry_offset + 24, "ELF section file offset")?,
                size: reader.u64(entry_offset + 32, "ELF section size")?,
                link: reader.u32(entry_offset + 40, "ELF section link")?,
                info: reader.u32(entry_offset + 44, "ELF section info")?,
                address_alignment: reader.u64(entry_offset + 48, "ELF section alignment")?,
                entry_size: reader.u64(entry_offset + 56, "ELF section entry size")?,
            }
        } else {
            ElfSectionHeader {
                table_index,
                name_offset: reader.u32(entry_offset, "ELF section-name offset")?,
                section_type: reader.u32(entry_offset + 4, "ELF section type")?,
                flags: reader.u32(entry_offset + 8, "ELF section flags")?,
                virtual_address: u64::from(
                    reader.u32(entry_offset + 12, "ELF section virtual address")?,
                ),
                file_offset: u64::from(reader.u32(entry_offset + 16, "ELF section file offset")?),
                size: u64::from(reader.u32(entry_offset + 20, "ELF section size")?),
                link: reader.u32(entry_offset + 24, "ELF section link")?,
                info: reader.u32(entry_offset + 28, "ELF section info")?,
                address_alignment: u64::from(
                    reader.u32(entry_offset + 32, "ELF section alignment")?,
                ),
                entry_size: u64::from(reader.u32(entry_offset + 36, "ELF section entry size")?),
            }
        };
        validate_section_header(&header, reader.len_u64()?, reader.class)?;
        headers.push(header);
    }
    Ok(headers)
}

fn parse_symbols(
    reader: &ElfReader<'_>,
    section_headers: &[ElfSectionHeader],
) -> Result<(Vec<ElfSymbol>, bool), AnalysisError> {
    let record_size = reader.class.symbol_size();
    let mut symbols = Vec::new();
    let mut truncated = false;
    'sections: for section in section_headers {
        if section.section_type != ELF_SECTION_TYPE_SYMTAB
            && section.section_type != ELF_SECTION_TYPE_DYNSYM
        {
            continue;
        }
        if section.entry_size != u64::from(record_size) || section.entry_size == 0 {
            continue;
        }
        let Some(strtab) = section_headers.get(section.link as usize) else {
            continue;
        };
        if strtab.section_type == ELF_SECTION_TYPE_NOBITS {
            continue;
        }
        let strtab_offset = usize::try_from(strtab.file_offset)
            .map_err(|_| AnalysisError::IntegerConversion("ELF string-table offset"))?;
        let strtab_size = usize::try_from(strtab.size)
            .map_err(|_| AnalysisError::IntegerConversion("ELF string-table size"))?;
        let Ok(strtab_bytes) = reader.bytes(strtab_offset, strtab_size, "ELF string table") else {
            continue;
        };

        let count = section.size / section.entry_size;
        for index in 0..count {
            if symbols.len() >= MAX_ELF_SYMBOLS {
                truncated = true;
                break 'sections;
            }
            let table_index = u32::try_from(index)
                .map_err(|_| AnalysisError::IntegerConversion("ELF symbol index"))?;
            let record_relative =
                index
                    .checked_mul(section.entry_size)
                    .ok_or(AnalysisError::ArithmeticOverflow(
                        "ELF symbol record offset",
                    ))?;
            let record_offset = section.file_offset.checked_add(record_relative).ok_or(
                AnalysisError::ArithmeticOverflow("ELF symbol record offset"),
            )?;
            let record_offset = usize::try_from(record_offset)
                .map_err(|_| AnalysisError::IntegerConversion("ELF symbol record offset"))?;

            let (name_offset, value, size, info, other, section_index) = if reader.class.is_64() {
                (
                    reader.u32(record_offset, "ELF symbol name")?,
                    reader.u64(record_offset + 8, "ELF symbol value")?,
                    reader.u64(record_offset + 16, "ELF symbol size")?,
                    reader.u8(record_offset + 4, "ELF symbol info")?,
                    reader.u8(record_offset + 5, "ELF symbol other")?,
                    reader.u16(record_offset + 6, "ELF symbol section index")?,
                )
            } else {
                (
                    reader.u32(record_offset, "ELF symbol name")?,
                    u64::from(reader.u32(record_offset + 4, "ELF symbol value")?),
                    u64::from(reader.u32(record_offset + 8, "ELF symbol size")?),
                    reader.u8(record_offset + 12, "ELF symbol info")?,
                    reader.u8(record_offset + 13, "ELF symbol other")?,
                    reader.u16(record_offset + 14, "ELF symbol section index")?,
                )
            };
            let Some(name) = resolve_symbol_name(strtab_bytes, name_offset) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            symbols.push(ElfSymbol {
                table_index,
                name,
                value,
                size,
                info,
                other,
                section_index,
            });
        }
    }
    Ok((symbols, truncated))
}

/// Resolve a NUL-terminated UTF-8 name from a string-table slice.
///
/// Returns `None` when the offset is out of range, the string is unterminated,
/// or the bytes are not valid UTF-8.
fn resolve_symbol_name(strtab: &[u8], name_offset: u32) -> Option<String> {
    let start = usize::try_from(name_offset).ok()?;
    let tail = strtab.get(start..)?;
    let end = tail.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&tail[..end]).ok().map(str::to_owned)
}

fn derive_load_segments(
    headers: &[ElfProgramHeader],
    file_size: u64,
    class: ElfClass,
) -> Result<Vec<ElfLoadSegment>, AnalysisError> {
    let mut segments = Vec::new();
    for header in headers {
        validate_file_range(
            header.file_offset,
            header.file_size,
            file_size,
            "ELF program segment",
        )?;
        validate_segment_alignment(header)?;
        if header.segment_type != ELF_PROGRAM_TYPE_LOAD {
            continue;
        }
        if header.file_size > header.memory_size {
            return invalid(
                "ELF PT_LOAD sizes",
                &format!(
                    "program header {} has file size {:#x} larger than memory size {:#x}",
                    header.table_index, header.file_size, header.memory_size
                ),
            );
        }
        if header.memory_size == 0 {
            continue;
        }
        let virtual_end = header
            .virtual_address
            .checked_add(header.memory_size)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "ELF PT_LOAD virtual range",
            ))?;
        if let Some(ceiling) = class.address_space_end() {
            if virtual_end > ceiling {
                return invalid(
                    "ELF PT_LOAD virtual range",
                    &format!(
                        "program header {} extends past the ELF32 address space",
                        header.table_index
                    ),
                );
            }
        }
        segments.push(ElfLoadSegment {
            program_header_index: header.table_index,
            file_offset: header.file_offset,
            file_size: header.file_size,
            virtual_address: header.virtual_address,
            memory_size: header.memory_size,
            flags: header.flags,
            alignment: header.alignment,
        });
    }
    segments.sort_by_key(|segment| (segment.virtual_address, segment.program_header_index));
    if segments.is_empty() {
        return invalid(
            "ELF PT_LOAD segments",
            "at least one non-empty mapping is required",
        );
    }
    for pair in segments.windows(2) {
        let first = &pair[0];
        let second = &pair[1];
        let first_end = first.virtual_address.checked_add(first.memory_size).ok_or(
            AnalysisError::ArithmeticOverflow("ELF PT_LOAD virtual range"),
        )?;
        if first_end > second.virtual_address {
            return invalid(
                "ELF PT_LOAD segments",
                &format!(
                    "program headers {} and {} have overlapping virtual ranges",
                    first.program_header_index, second.program_header_index
                ),
            );
        }
    }
    Ok(segments)
}

fn image_extent(segments: &[ElfLoadSegment]) -> Result<(u64, u64), AnalysisError> {
    let first = segments
        .first()
        .ok_or_else(|| AnalysisError::InvalidField {
            field: "ELF PT_LOAD segments",
            reason: "at least one non-empty mapping is required".to_owned(),
        })?;
    let image_base = first.virtual_address;
    let image_end = segments.iter().try_fold(image_base, |current, segment| {
        let end = segment
            .virtual_address
            .checked_add(segment.memory_size)
            .ok_or(AnalysisError::ArithmeticOverflow("ELF image extent"))?;
        Ok::<u64, AnalysisError>(current.max(end))
    })?;
    let image_size = image_end
        .checked_sub(image_base)
        .ok_or(AnalysisError::ArithmeticOverflow("ELF image size"))?;
    if image_size == 0 {
        return invalid("ELF image size", "the mapped image must not be empty");
    }
    Ok((image_base, image_size))
}

fn entry_rva(
    elf_type: u16,
    entry_va: u64,
    image_base: u64,
    segments: &[ElfLoadSegment],
) -> Result<u64, AnalysisError> {
    let executable_segment = segments.iter().find(|segment| {
        let start = segment.virtual_address;
        let file_end = start.checked_add(segment.file_size);
        segment.executable() && entry_va >= start && file_end.is_some_and(|end| entry_va < end)
    });
    if executable_segment.is_none() {
        // Shared objects may declare no meaningful entry point; record a zero
        // RVA rather than rejecting the container. Executables must resolve.
        if elf_type == ELF_TYPE_DYNAMIC {
            return Ok(0);
        }
        return invalid(
            "ELF entry address",
            "the entry must lie in file-backed bytes of an executable PT_LOAD segment",
        );
    }
    entry_va
        .checked_sub(image_base)
        .ok_or_else(|| AnalysisError::InvalidField {
            field: "ELF entry address",
            reason: "the entry lies below the image base".to_owned(),
        })
}

fn validate_segment_alignment(header: &ElfProgramHeader) -> Result<(), AnalysisError> {
    let alignment = header.alignment;
    if alignment > 1 && !alignment.is_power_of_two() {
        return invalid(
            "ELF segment alignment",
            &format!(
                "program header {} uses non-power-of-two alignment {alignment:#x}",
                header.table_index
            ),
        );
    }
    if alignment > 1 {
        let alignment = u64::from(alignment);
        if header.virtual_address % alignment != header.file_offset % alignment {
            return invalid(
                "ELF segment alignment",
                &format!(
                    "program header {} has incongruent virtual and file offsets for alignment {alignment:#x}",
                    header.table_index
                ),
            );
        }
    }
    Ok(())
}

fn validate_section_header(
    header: &ElfSectionHeader,
    file_size: u64,
    class: ElfClass,
) -> Result<(), AnalysisError> {
    if header.address_alignment > 1 && !header.address_alignment.is_power_of_two() {
        return invalid(
            "ELF section alignment",
            &format!(
                "section header {} uses non-power-of-two alignment {:#x}",
                header.table_index, header.address_alignment
            ),
        );
    }
    if header.section_type != ELF_SECTION_TYPE_NOBITS {
        validate_file_range(
            header.file_offset,
            header.size,
            file_size,
            "ELF section data",
        )?;
    }
    if header.flags & ELF_SECTION_FLAG_ALLOC != 0 && header.size != 0 {
        let virtual_end = header.virtual_address.checked_add(header.size).ok_or(
            AnalysisError::ArithmeticOverflow("ELF allocated section virtual range"),
        )?;
        if let Some(ceiling) = class.address_space_end() {
            if virtual_end > ceiling {
                return invalid(
                    "ELF allocated section virtual range",
                    &format!(
                        "section header {} extends past the ELF32 address space",
                        header.table_index
                    ),
                );
            }
        }
    }
    Ok(())
}

fn validate_file_range(
    offset: u64,
    size: u64,
    file_size: u64,
    field: &'static str,
) -> Result<(), AnalysisError> {
    if offset > file_size {
        return invalid(
            field,
            &format!("offset {offset:#x} exceeds file size {file_size:#x}"),
        );
    }
    if size == 0 {
        return Ok(());
    }
    let end = offset
        .checked_add(size)
        .ok_or(AnalysisError::ArithmeticOverflow("ELF file range"))?;
    if end > file_size {
        return invalid(
            field,
            &format!("range {offset:#x}..{end:#x} exceeds file size {file_size:#x}"),
        );
    }
    Ok(())
}

fn validate_table_model(
    offset: u64,
    count: usize,
    entry_size: u16,
    file_size: u64,
    field: &'static str,
) -> Result<(), AnalysisError> {
    let bytes = usize_to_u64(count, "ELF table count")?
        .checked_mul(u64::from(entry_size))
        .ok_or(AnalysisError::ArithmeticOverflow("ELF table byte size"))?;
    validate_file_range(offset, bytes, file_size, field)
}

fn table_entry_offset(offset: u64, index: u16, entry_size: u16) -> Result<usize, AnalysisError> {
    let relative = u64::from(index)
        .checked_mul(u64::from(entry_size))
        .ok_or(AnalysisError::ArithmeticOverflow("ELF table entry offset"))?;
    let absolute = offset
        .checked_add(relative)
        .ok_or(AnalysisError::ArithmeticOverflow("ELF table entry offset"))?;
    usize::try_from(absolute).map_err(|_| AnalysisError::IntegerConversion("ELF table offset"))
}

fn narrow_alignment(value: u64, field: &'static str) -> Result<u32, AnalysisError> {
    u32::try_from(value).map_err(|_| AnalysisError::InvalidField {
        field,
        reason: "alignment beyond the 32-bit range is unsupported".to_owned(),
    })
}

fn narrow_section_flags(value: u64) -> Result<u32, AnalysisError> {
    u32::try_from(value).map_err(|_| AnalysisError::InvalidField {
        field: "ELF section flags",
        reason: "processor-specific flags beyond the 32-bit range are unsupported".to_owned(),
    })
}

fn enforce_count(kind: &'static str, count: u64, limit: u64) -> Result<(), AnalysisError> {
    if count > limit {
        Err(AnalysisError::LimitExceeded { kind, count, limit })
    } else {
        Ok(())
    }
}

fn usize_to_u64(value: usize, context: &'static str) -> Result<u64, AnalysisError> {
    u64::try_from(value).map_err(|_| AnalysisError::IntegerConversion(context))
}

fn invalid<T>(field: &'static str, reason: &str) -> Result<T, AnalysisError> {
    Err(AnalysisError::InvalidField {
        field,
        reason: reason.to_owned(),
    })
}

struct ElfReader<'bytes> {
    bytes: &'bytes [u8],
    class: ElfClass,
    endian: ElfEndian,
}

impl<'bytes> ElfReader<'bytes> {
    const fn new(bytes: &'bytes [u8], class: ElfClass, endian: ElfEndian) -> Self {
        Self {
            bytes,
            class,
            endian,
        }
    }

    fn len_u64(&self) -> Result<u64, AnalysisError> {
        usize_to_u64(self.bytes.len(), "ELF input size")
    }

    fn require(
        &self,
        offset: usize,
        needed: usize,
        context: &'static str,
    ) -> Result<(), AnalysisError> {
        let end = offset
            .checked_add(needed)
            .ok_or(AnalysisError::ArithmeticOverflow("ELF read range"))?;
        if end > self.bytes.len() {
            return Err(AnalysisError::Truncated {
                context,
                offset,
                needed,
                available: self.bytes.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    fn bytes(
        &self,
        offset: usize,
        size: usize,
        context: &'static str,
    ) -> Result<&'bytes [u8], AnalysisError> {
        self.require(offset, size, context)?;
        Ok(&self.bytes[offset..offset + size])
    }

    fn u8(&self, offset: usize, context: &'static str) -> Result<u8, AnalysisError> {
        self.require(offset, 1, context)?;
        Ok(self.bytes[offset])
    }

    fn u16(&self, offset: usize, context: &'static str) -> Result<u16, AnalysisError> {
        let bytes = self.bytes(offset, 2, context)?;
        let array = [bytes[0], bytes[1]];
        Ok(match self.endian {
            ElfEndian::Little => u16::from_le_bytes(array),
            ElfEndian::Big => u16::from_be_bytes(array),
        })
    }

    fn u32(&self, offset: usize, context: &'static str) -> Result<u32, AnalysisError> {
        let bytes = self.bytes(offset, 4, context)?;
        let array = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(match self.endian {
            ElfEndian::Little => u32::from_le_bytes(array),
            ElfEndian::Big => u32::from_be_bytes(array),
        })
    }

    fn u64(&self, offset: usize, context: &'static str) -> Result<u64, AnalysisError> {
        let bytes = self.bytes(offset, 8, context)?;
        let array = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];
        Ok(match self.endian {
            ElfEndian::Little => u64::from_le_bytes(array),
            ElfEndian::Big => u64::from_be_bytes(array),
        })
    }

    /// Read a class-sized address (4 bytes for ELF32, 8 bytes for ELF64).
    fn addr(&self, offset: usize, context: &'static str) -> Result<u64, AnalysisError> {
        if self.class.is_64() {
            self.u64(offset, context)
        } else {
            Ok(u64::from(self.u32(offset, context)?))
        }
    }

    fn table(
        &self,
        offset: u64,
        count: u16,
        entry_size: u16,
        context: &'static str,
    ) -> Result<(), AnalysisError> {
        let bytes = u64::from(count)
            .checked_mul(u64::from(entry_size))
            .ok_or(AnalysisError::ArithmeticOverflow("ELF table byte size"))?;
        let offset = usize::try_from(offset)
            .map_err(|_| AnalysisError::IntegerConversion("ELF table offset"))?;
        let bytes = usize::try_from(bytes)
            .map_err(|_| AnalysisError::IntegerConversion("ELF table byte size"))?;
        self.require(offset, bytes, context)
    }
}
