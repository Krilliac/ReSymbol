use resymbol_core::{BinaryFormat, BinaryId, BinaryIdentity, SymbolGraph};

use crate::{AnalysisError, ElfAnalysis, ElfLoadSegment, ElfProgramHeader, ElfSectionHeader};

const ELF32_HEADER_SIZE: u16 = 52;
const ELF32_PROGRAM_HEADER_SIZE: u16 = 32;
const ELF32_SECTION_HEADER_SIZE: u16 = 40;
const ELF_CLASS_32: u8 = 1;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF_VERSION_CURRENT: u32 = 1;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_MACHINE_MIPS: u16 = 8;
const ELF_PROGRAM_TYPE_LOAD: u32 = 1;
const ELF_SECTION_TYPE_NOBITS: u32 = 8;
const ELF_SECTION_FLAG_ALLOC: u32 = 0x2;
const ELF_SECTION_INDEX_EXTENDED: u16 = 0xffff;
const ELF_ARCHITECTURE: &str = "elf32-em-mips-le";
const ELF32_ADDRESS_SPACE_END: u64 = 1_u64 << 32;
const MAX_PROGRAM_HEADERS: u64 = 1_024;
const MAX_SECTION_HEADERS: u64 = 4_096;

/// Parse an ELF32 little-endian `EM_MIPS` executable without loading or executing it.
///
/// This first ELF slice records only bounded container evidence and sparse
/// `PT_LOAD` mappings. It performs no instruction decoding.
pub fn analyze_elf(bytes: &[u8]) -> Result<ElfAnalysis, AnalysisError> {
    let reader = ElfReader::new(bytes);
    reader.require(0, usize::from(ELF32_HEADER_SIZE), "ELF32 header")?;

    if reader.bytes(0, 4, "ELF magic")? != b"\x7fELF" {
        return Err(AnalysisError::InvalidElfSignature);
    }
    let class = reader.u8(4, "ELF class")?;
    if class != ELF_CLASS_32 {
        return Err(AnalysisError::UnsupportedElfClass {
            class,
            expected: ELF_CLASS_32,
        });
    }
    let data = reader.u8(5, "ELF data encoding")?;
    if data != ELF_DATA_LITTLE_ENDIAN {
        return Err(AnalysisError::UnsupportedElfDataEncoding {
            data,
            expected: ELF_DATA_LITTLE_ENDIAN,
        });
    }
    let ident_version = reader.u8(6, "ELF identity version")?;
    if u32::from(ident_version) != ELF_VERSION_CURRENT {
        return Err(AnalysisError::UnsupportedElfVersion {
            version: u32::from(ident_version),
            context: "identity",
        });
    }
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
    if elf_type != ELF_TYPE_EXECUTABLE {
        return Err(AnalysisError::UnsupportedElfType {
            elf_type,
            expected: ELF_TYPE_EXECUTABLE,
        });
    }
    let machine = reader.u16(18, "ELF machine")?;
    if machine != ELF_MACHINE_MIPS {
        return Err(AnalysisError::UnsupportedElfMachine {
            machine,
            expected: ELF_MACHINE_MIPS,
        });
    }
    let elf_version = reader.u32(20, "ELF version")?;
    if elf_version != ELF_VERSION_CURRENT {
        return Err(AnalysisError::UnsupportedElfVersion {
            version: elf_version,
            context: "header",
        });
    }

    let entry_va = reader.u32(24, "ELF entry address")?;
    let program_header_offset = reader.u32(28, "ELF program-header offset")?;
    let section_header_offset = reader.u32(32, "ELF section-header offset")?;
    let flags = reader.u32(36, "ELF flags")?;
    let header_size = reader.u16(40, "ELF header size")?;
    if header_size != ELF32_HEADER_SIZE {
        return Err(AnalysisError::InvalidField {
            field: "ELF header size",
            reason: format!("expected {ELF32_HEADER_SIZE} bytes for ELF32, found {header_size}"),
        });
    }
    let program_header_entry_size = reader.u16(42, "ELF program-header entry size")?;
    let program_header_count = reader.u16(44, "ELF program-header count")?;
    let section_header_entry_size = reader.u16(46, "ELF section-header entry size")?;
    let section_header_count = reader.u16(48, "ELF section-header count")?;
    let section_name_table_index = reader.u16(50, "ELF section-name table index")?;

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
    if program_header_entry_size != ELF32_PROGRAM_HEADER_SIZE {
        return Err(AnalysisError::InvalidField {
            field: "ELF program-header entry size",
            reason: format!(
                "expected {ELF32_PROGRAM_HEADER_SIZE} bytes for ELF32, found {program_header_entry_size}"
            ),
        });
    }
    if program_header_offset < u32::from(header_size) {
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
    let load_segments = derive_load_segments(&program_headers, input_size)?;
    let (image_base, image_size) = image_extent(&load_segments)?;
    let entry_rva = entry_rva(entry_va, image_base, &load_segments)?;

    let identity = BinaryIdentity {
        id: BinaryId::digest(bytes),
        size: input_size,
        format: BinaryFormat::Elf,
        architecture: ELF_ARCHITECTURE.to_owned(),
        image_base,
    };
    let symbol_graph = build_symbol_graph(&identity)?;
    let analysis = ElfAnalysis {
        identity,
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
        symbol_graph,
    };
    validate_elf_analysis(&analysis)?;
    Ok(analysis)
}

pub(crate) fn build_symbol_graph(identity: &BinaryIdentity) -> Result<SymbolGraph, AnalysisError> {
    let mut graph = SymbolGraph::default();
    graph.insert_binary(identity.clone())?;
    Ok(graph)
}

pub(crate) fn validate_elf_analysis(analysis: &ElfAnalysis) -> Result<(), AnalysisError> {
    analysis.identity.validate()?;
    if !matches!(analysis.identity.format, BinaryFormat::Elf) {
        return invalid("ELF identity format", "expected the ELF format marker");
    }
    if analysis.identity.architecture != ELF_ARCHITECTURE {
        return invalid(
            "ELF identity architecture",
            &format!("expected `{ELF_ARCHITECTURE}`"),
        );
    }
    if analysis.identity.size < u64::from(ELF32_HEADER_SIZE) {
        return invalid(
            "ELF identity size",
            "the file is smaller than one ELF32 header",
        );
    }
    if analysis.elf_type != ELF_TYPE_EXECUTABLE {
        return Err(AnalysisError::UnsupportedElfType {
            elf_type: analysis.elf_type,
            expected: ELF_TYPE_EXECUTABLE,
        });
    }
    if analysis.machine != ELF_MACHINE_MIPS {
        return Err(AnalysisError::UnsupportedElfMachine {
            machine: analysis.machine,
            expected: ELF_MACHINE_MIPS,
        });
    }
    if analysis.elf_version != ELF_VERSION_CURRENT {
        return Err(AnalysisError::UnsupportedElfVersion {
            version: analysis.elf_version,
            context: "header",
        });
    }
    if analysis.header_size != ELF32_HEADER_SIZE {
        return invalid(
            "ELF header size",
            "expected the canonical ELF32 header size",
        );
    }
    if analysis.program_header_entry_size != ELF32_PROGRAM_HEADER_SIZE {
        return invalid(
            "ELF program-header entry size",
            "expected the canonical ELF32 program-header size",
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
    if analysis.program_header_offset < u32::from(analysis.header_size) {
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
            u64::from(header.file_offset),
            u64::from(header.file_size),
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
        validate_section_header(header, analysis.identity.size)?;
    }

    let expected_load_segments =
        derive_load_segments(&analysis.program_headers, analysis.identity.size)?;
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
    let expected_entry_rva = entry_rva(analysis.entry_va, image_base, &analysis.load_segments)?;
    if analysis.entry_rva != expected_entry_rva {
        return invalid(
            "ELF entry RVA",
            "the RVA does not match the entry VA and image base",
        );
    }
    let expected_graph = build_symbol_graph(&analysis.identity)?;
    if analysis.symbol_graph != expected_graph {
        return invalid(
            "ELF symbol graph",
            "container-only intake requires the exact identity and zero base claims",
        );
    }
    Ok(())
}

fn validate_section_table_header(
    reader: &ElfReader<'_>,
    offset: u32,
    count: u16,
    entry_size: u16,
    name_table_index: u16,
) -> Result<(), AnalysisError> {
    if count == 0 {
        if offset != 0 {
            return invalid(
                "ELF section-header count",
                "extended section numbering is not supported",
            );
        }
        if !matches!(entry_size, 0 | ELF32_SECTION_HEADER_SIZE) {
            return invalid(
                "ELF section-header entry size",
                "an absent table must use zero or the canonical ELF32 entry size",
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
    if entry_size != ELF32_SECTION_HEADER_SIZE {
        return invalid(
            "ELF section-header entry size",
            &format!("expected {ELF32_SECTION_HEADER_SIZE} bytes for ELF32, found {entry_size}"),
        );
    }
    if offset == 0 {
        return invalid(
            "ELF section-header offset",
            "a non-empty table must have a nonzero file offset",
        );
    }
    if offset < u32::from(ELF32_HEADER_SIZE) {
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
    let count = analysis.section_headers.len();
    if count == 0 {
        if analysis.section_header_offset != 0
            || analysis.section_name_table_index != 0
            || !matches!(
                analysis.section_header_entry_size,
                0 | ELF32_SECTION_HEADER_SIZE
            )
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
    if analysis.section_header_entry_size != ELF32_SECTION_HEADER_SIZE {
        return invalid(
            "ELF section-header entry size",
            "expected the canonical ELF32 section-header size",
        );
    }
    if analysis.section_header_offset < u32::from(analysis.header_size) {
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
    offset: u32,
    count: u16,
    entry_size: u16,
) -> Result<Vec<ElfProgramHeader>, AnalysisError> {
    let mut headers = Vec::with_capacity(usize::from(count));
    for table_index in 0..count {
        let entry_offset = table_entry_offset(offset, table_index, entry_size)?;
        headers.push(ElfProgramHeader {
            table_index,
            segment_type: reader.u32(entry_offset, "ELF program type")?,
            file_offset: reader.u32(entry_offset + 4, "ELF segment file offset")?,
            virtual_address: reader.u32(entry_offset + 8, "ELF segment virtual address")?,
            physical_address: reader.u32(entry_offset + 12, "ELF segment physical address")?,
            file_size: reader.u32(entry_offset + 16, "ELF segment file size")?,
            memory_size: reader.u32(entry_offset + 20, "ELF segment memory size")?,
            flags: reader.u32(entry_offset + 24, "ELF segment flags")?,
            alignment: reader.u32(entry_offset + 28, "ELF segment alignment")?,
        });
    }
    Ok(headers)
}

fn parse_section_headers(
    reader: &ElfReader<'_>,
    offset: u32,
    count: u16,
    entry_size: u16,
) -> Result<Vec<ElfSectionHeader>, AnalysisError> {
    let mut headers = Vec::with_capacity(usize::from(count));
    for table_index in 0..count {
        let entry_offset = table_entry_offset(offset, table_index, entry_size)?;
        let header = ElfSectionHeader {
            table_index,
            name_offset: reader.u32(entry_offset, "ELF section-name offset")?,
            section_type: reader.u32(entry_offset + 4, "ELF section type")?,
            flags: reader.u32(entry_offset + 8, "ELF section flags")?,
            virtual_address: reader.u32(entry_offset + 12, "ELF section virtual address")?,
            file_offset: reader.u32(entry_offset + 16, "ELF section file offset")?,
            size: reader.u32(entry_offset + 20, "ELF section size")?,
            link: reader.u32(entry_offset + 24, "ELF section link")?,
            info: reader.u32(entry_offset + 28, "ELF section info")?,
            address_alignment: reader.u32(entry_offset + 32, "ELF section alignment")?,
            entry_size: reader.u32(entry_offset + 36, "ELF section entry size")?,
        };
        validate_section_header(&header, reader.len_u64()?)?;
        headers.push(header);
    }
    Ok(headers)
}

fn derive_load_segments(
    headers: &[ElfProgramHeader],
    file_size: u64,
) -> Result<Vec<ElfLoadSegment>, AnalysisError> {
    let mut segments = Vec::new();
    for header in headers {
        validate_file_range(
            u64::from(header.file_offset),
            u64::from(header.file_size),
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
        let virtual_end = u64::from(header.virtual_address)
            .checked_add(u64::from(header.memory_size))
            .ok_or(AnalysisError::ArithmeticOverflow(
                "ELF PT_LOAD virtual range",
            ))?;
        if virtual_end > ELF32_ADDRESS_SPACE_END {
            return invalid(
                "ELF PT_LOAD virtual range",
                &format!(
                    "program header {} extends past the ELF32 address space",
                    header.table_index
                ),
            );
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
        let first_end = u64::from(first.virtual_address) + u64::from(first.memory_size);
        if first_end > u64::from(second.virtual_address) {
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
    let image_base = u64::from(first.virtual_address);
    let image_end = segments.iter().try_fold(image_base, |current, segment| {
        let end = u64::from(segment.virtual_address)
            .checked_add(u64::from(segment.memory_size))
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
    entry_va: u32,
    image_base: u64,
    segments: &[ElfLoadSegment],
) -> Result<u32, AnalysisError> {
    let entry_va_u64 = u64::from(entry_va);
    let executable_segment = segments.iter().find(|segment| {
        let start = u64::from(segment.virtual_address);
        let file_end = start + u64::from(segment.file_size);
        segment.executable() && entry_va_u64 >= start && entry_va_u64 < file_end
    });
    if executable_segment.is_none() {
        return invalid(
            "ELF entry address",
            "the entry must lie in file-backed bytes of an executable PT_LOAD segment",
        );
    }
    let rva = entry_va_u64
        .checked_sub(image_base)
        .ok_or_else(|| AnalysisError::InvalidField {
            field: "ELF entry address",
            reason: "the entry lies below the image base".to_owned(),
        })?;
    u32::try_from(rva).map_err(|_| AnalysisError::IntegerConversion("ELF entry RVA"))
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
    if alignment > 1 && header.virtual_address % alignment != header.file_offset % alignment {
        return invalid(
            "ELF segment alignment",
            &format!(
                "program header {} has incongruent virtual and file offsets for alignment {alignment:#x}",
                header.table_index
            ),
        );
    }
    Ok(())
}

fn validate_section_header(header: &ElfSectionHeader, file_size: u64) -> Result<(), AnalysisError> {
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
            u64::from(header.file_offset),
            u64::from(header.size),
            file_size,
            "ELF section data",
        )?;
    }
    if header.flags & ELF_SECTION_FLAG_ALLOC != 0 && header.size != 0 {
        let virtual_end = u64::from(header.virtual_address)
            .checked_add(u64::from(header.size))
            .ok_or(AnalysisError::ArithmeticOverflow(
                "ELF allocated section virtual range",
            ))?;
        if virtual_end > ELF32_ADDRESS_SPACE_END {
            return invalid(
                "ELF allocated section virtual range",
                &format!(
                    "section header {} extends past the ELF32 address space",
                    header.table_index
                ),
            );
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
    offset: u32,
    count: usize,
    entry_size: u16,
    file_size: u64,
    field: &'static str,
) -> Result<(), AnalysisError> {
    let bytes = usize_to_u64(count, "ELF table count")?
        .checked_mul(u64::from(entry_size))
        .ok_or(AnalysisError::ArithmeticOverflow("ELF table byte size"))?;
    validate_file_range(u64::from(offset), bytes, file_size, field)
}

fn table_entry_offset(offset: u32, index: u16, entry_size: u16) -> Result<usize, AnalysisError> {
    let relative = u64::from(index)
        .checked_mul(u64::from(entry_size))
        .ok_or(AnalysisError::ArithmeticOverflow("ELF table entry offset"))?;
    let absolute = u64::from(offset)
        .checked_add(relative)
        .ok_or(AnalysisError::ArithmeticOverflow("ELF table entry offset"))?;
    usize::try_from(absolute).map_err(|_| AnalysisError::IntegerConversion("ELF table offset"))
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
}

impl<'bytes> ElfReader<'bytes> {
    const fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes }
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
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&self, offset: usize, context: &'static str) -> Result<u32, AnalysisError> {
        let bytes = self.bytes(offset, 4, context)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn table(
        &self,
        offset: u32,
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
