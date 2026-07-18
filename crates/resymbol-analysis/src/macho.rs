use resymbol_core::{
    BinaryFormat, BinaryId, BinaryIdentity, ClaimProducer, ClaimProvenance, Confidence, Evidence,
    EvidenceKind, SymbolAssertion, SymbolClaim, SymbolGraph, SymbolSubject,
};

use crate::{
    AnalysisError, MachOAnalysis, MachOArchSlice, MachOContainer, MachOEndian, MachOFat,
    MachOImage, MachOSection, MachOSegment, MachOSymbol,
};

const MH_MAGIC_32_LE: [u8; 4] = [0xce, 0xfa, 0xed, 0xfe];
const MH_MAGIC_64_LE: [u8; 4] = [0xcf, 0xfa, 0xed, 0xfe];
const MH_MAGIC_32_BE: [u8; 4] = [0xfe, 0xed, 0xfa, 0xce];
const MH_MAGIC_64_BE: [u8; 4] = [0xfe, 0xed, 0xfa, 0xcf];
const FAT_MAGIC: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];
const FAT_MAGIC_64: [u8; 4] = [0xca, 0xfe, 0xba, 0xbf];

const MACH_HEADER_32_SIZE: usize = 28;
const MACH_HEADER_64_SIZE: usize = 32;
const SEGMENT_COMMAND_32_SIZE: u64 = 56;
const SEGMENT_COMMAND_64_SIZE: u64 = 72;
const SECTION_32_SIZE: u64 = 68;
const SECTION_64_SIZE: u64 = 80;
const NLIST_32_SIZE: u64 = 12;
const NLIST_64_SIZE: u64 = 16;
const FAT_ARCH_32_SIZE: u64 = 20;
const FAT_ARCH_64_SIZE: u64 = 32;
const FAT_HEADER_SIZE: usize = 8;

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x8000_0028;

const N_STAB: u8 = 0xe0;
const NO_SECT: u8 = 0;

const SECTION_TYPE_MASK: u32 = 0xff;
const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x11;

const CPU_ARCH_ABI64: i32 = 0x0100_0000;
const CPU_TYPE_X86: i32 = 7;
const CPU_TYPE_X86_64: i32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
const CPU_TYPE_ARM: i32 = 12;
const CPU_TYPE_ARM64: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
const CPU_TYPE_POWERPC: i32 = 18;
const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;

const MAX_LOAD_COMMANDS: u64 = 4_096;
const MAX_SEGMENTS: u64 = 1_024;
const MAX_SECTIONS: u64 = 4_096;
const MAX_MACHO_SYMBOLS: usize = 262_144;
const MAX_FAT_ARCH: u64 = 64;

const FAT_ARCHITECTURE: &str = "macho-universal";

/// Container shape recognized from a Mach-O file's leading magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachOKind {
    /// Thin 32-bit image with the given byte order.
    Thin32(MachOEndian),
    /// Thin 64-bit image with the given byte order.
    Thin64(MachOEndian),
    /// Fat/universal container with 32-bit architecture records.
    Fat,
    /// Fat/universal container with 64-bit architecture records.
    Fat64,
}

/// Classify a byte slice by its leading Mach-O magic without parsing it.
///
/// Returns `None` for any other input. Fat detection is deliberately reached
/// only after PE and ELF dispatch, so the `0xCAFEBABE` collision with Java
/// class files is acceptable; a fat header that fails validation is later
/// reported as an explicit error rather than silently misclassified.
#[must_use]
pub fn detect_macho(bytes: &[u8]) -> Option<MachOKind> {
    let magic: [u8; 4] = bytes.get(0..4)?.try_into().ok()?;
    match magic {
        MH_MAGIC_32_LE => Some(MachOKind::Thin32(MachOEndian::Little)),
        MH_MAGIC_32_BE => Some(MachOKind::Thin32(MachOEndian::Big)),
        MH_MAGIC_64_LE => Some(MachOKind::Thin64(MachOEndian::Little)),
        MH_MAGIC_64_BE => Some(MachOKind::Thin64(MachOEndian::Big)),
        FAT_MAGIC => Some(MachOKind::Fat),
        FAT_MAGIC_64 => Some(MachOKind::Fat64),
        _ => None,
    }
}

/// Parse a bounded Mach-O container without loading or executing it.
///
/// Thin images contribute exact segment/section/symbol metadata and
/// deterministic name claims. Fat/universal images retain each slice's parsed
/// container metadata but keep an identity-only symbol graph.
pub fn analyze_macho(bytes: &[u8]) -> Result<MachOAnalysis, AnalysisError> {
    let kind = detect_macho(bytes).ok_or_else(|| AnalysisError::InvalidMachOMagic {
        magic: leading_magic(bytes),
    })?;
    let size = slice_len_u64(bytes)?;
    match kind {
        MachOKind::Thin32(endian) => analyze_thin(bytes, size, endian, false),
        MachOKind::Thin64(endian) => analyze_thin(bytes, size, endian, true),
        MachOKind::Fat => analyze_fat(bytes, size, false),
        MachOKind::Fat64 => analyze_fat(bytes, size, true),
    }
}

fn analyze_thin(
    bytes: &[u8],
    size: u64,
    endian: MachOEndian,
    is_64: bool,
) -> Result<MachOAnalysis, AnalysisError> {
    let image = parse_thin_image(bytes, endian, is_64)?;
    let identity = BinaryIdentity {
        id: BinaryId::digest(bytes),
        size,
        format: BinaryFormat::MachO,
        architecture: macho_architecture(image.cputype, image.is_64),
        image_base: image.image_base,
    };
    let image_size = image.image_size;
    let container = MachOContainer::Thin(image);
    let symbol_graph = build_symbol_graph(&identity, &container)?;
    let analysis = MachOAnalysis {
        identity,
        image_size,
        container,
        symbol_graph,
    };
    validate_macho_analysis(&analysis)?;
    Ok(analysis)
}

fn analyze_fat(bytes: &[u8], size: u64, is_64: bool) -> Result<MachOAnalysis, AnalysisError> {
    let slices = parse_fat(bytes, is_64)?;
    let image_size = slices
        .iter()
        .map(|slice| slice.image.image_size)
        .max()
        .unwrap_or(0);
    let identity = BinaryIdentity {
        id: BinaryId::digest(bytes),
        size,
        format: BinaryFormat::MachO,
        architecture: FAT_ARCHITECTURE.to_owned(),
        image_base: 0,
    };
    let container = MachOContainer::Fat(MachOFat { is_64, slices });
    let symbol_graph = build_symbol_graph(&identity, &container)?;
    let analysis = MachOAnalysis {
        identity,
        image_size,
        container,
        symbol_graph,
    };
    validate_macho_analysis(&analysis)?;
    Ok(analysis)
}

fn parse_fat(bytes: &[u8], is_64: bool) -> Result<Vec<MachOArchSlice>, AnalysisError> {
    // The fat header and architecture table are always big-endian.
    let reader = MachOReader::new(bytes, MachOEndian::Big);
    reader.require(0, FAT_HEADER_SIZE, "Mach-O fat header")?;
    let nfat_arch = reader.u32(4, "Mach-O fat arch count")?;
    if nfat_arch == 0 {
        return invalid("Mach-O fat arch count", "a fat container needs one slice");
    }
    enforce_count("Mach-O fat arch", u64::from(nfat_arch), MAX_FAT_ARCH)?;
    let record_size = if is_64 {
        FAT_ARCH_64_SIZE
    } else {
        FAT_ARCH_32_SIZE
    };
    let file_size = slice_len_u64(bytes)?;

    let mut slices = Vec::with_capacity(usize::try_from(nfat_arch).unwrap_or(0));
    for index in 0..nfat_arch {
        let record_relative = u64::from(index)
            .checked_mul(record_size)
            .ok_or(AnalysisError::ArithmeticOverflow("Mach-O fat arch offset"))?;
        let record_offset = usize_add(FAT_HEADER_SIZE, record_relative, "Mach-O fat arch offset")?;
        let cputype = reader.i32(record_offset, "Mach-O fat cputype")?;
        let cpusubtype = reader.i32(record_offset + 4, "Mach-O fat cpusubtype")?;
        let (offset, slice_size, align) = if is_64 {
            (
                reader.u64(record_offset + 8, "Mach-O fat offset")?,
                reader.u64(record_offset + 16, "Mach-O fat size")?,
                reader.u32(record_offset + 24, "Mach-O fat align")?,
            )
        } else {
            (
                u64::from(reader.u32(record_offset + 8, "Mach-O fat offset")?),
                u64::from(reader.u32(record_offset + 12, "Mach-O fat size")?),
                reader.u32(record_offset + 16, "Mach-O fat align")?,
            )
        };
        validate_file_range(offset, slice_size, file_size, "Mach-O fat slice")?;
        let start = usize::try_from(offset)
            .map_err(|_| AnalysisError::IntegerConversion("Mach-O fat slice offset"))?;
        let len = usize::try_from(slice_size)
            .map_err(|_| AnalysisError::IntegerConversion("Mach-O fat slice size"))?;
        let end = start
            .checked_add(len)
            .ok_or(AnalysisError::ArithmeticOverflow("Mach-O fat slice range"))?;
        let sub = &bytes[start..end];
        let (sub_endian, sub_is_64) = match detect_macho(sub) {
            Some(MachOKind::Thin32(endian)) => (endian, false),
            Some(MachOKind::Thin64(endian)) => (endian, true),
            _ => return Err(AnalysisError::InvalidMachOSlice { index }),
        };
        let image = parse_thin_image(sub, sub_endian, sub_is_64)?;
        let architecture = macho_architecture(image.cputype, image.is_64);
        slices.push(MachOArchSlice {
            index,
            cputype,
            cpusubtype,
            offset,
            size: slice_size,
            align,
            architecture,
            image,
        });
    }
    Ok(slices)
}

fn parse_thin_image(
    bytes: &[u8],
    endian: MachOEndian,
    is_64: bool,
) -> Result<MachOImage, AnalysisError> {
    let reader = MachOReader::new(bytes, endian);
    let header_size = if is_64 {
        MACH_HEADER_64_SIZE
    } else {
        MACH_HEADER_32_SIZE
    };
    reader.require(0, header_size, "Mach-O header")?;

    let cputype = reader.i32(4, "Mach-O cputype")?;
    let cpusubtype = reader.i32(8, "Mach-O cpusubtype")?;
    let filetype = reader.u32(12, "Mach-O filetype")?;
    let ncmds = reader.u32(16, "Mach-O ncmds")?;
    let sizeofcmds = reader.u32(20, "Mach-O sizeofcmds")?;
    let flags = reader.u32(24, "Mach-O flags")?;
    enforce_count("Mach-O load command", u64::from(ncmds), MAX_LOAD_COMMANDS)?;

    // Bound the load-command walk by both `sizeofcmds` and the file itself.
    let commands_end = usize_add(header_size, u64::from(sizeofcmds), "Mach-O load commands")?;
    reader.require(
        header_size,
        usize::try_from(sizeofcmds)
            .map_err(|_| AnalysisError::IntegerConversion("Mach-O sizeofcmds"))?,
        "Mach-O load commands",
    )?;

    let align = if is_64 { 8 } else { 4 };
    let mut segments: Vec<MachOSegment> = Vec::new();
    let mut sections: Vec<MachOSection> = Vec::new();
    let mut symtab: Option<SymtabCommand> = None;
    let mut entry_offset: Option<u64> = None;
    let mut has_unixthread = false;

    let mut cursor = header_size;
    let mut remaining = u64::from(sizeofcmds);
    for _ in 0..ncmds {
        if remaining < 8 {
            return invalid(
                "Mach-O load command",
                "the declared command table is exhausted",
            );
        }
        reader.require(cursor, 8, "Mach-O load command")?;
        let cmd = reader.u32(cursor, "Mach-O load command")?;
        let cmdsize = reader.u32(cursor + 4, "Mach-O load command size")?;
        let cmdsize_u64 = u64::from(cmdsize);
        if cmdsize < 8 {
            return invalid("Mach-O load command size", "each command needs eight bytes");
        }
        if cmdsize % align != 0 {
            return invalid("Mach-O load command size", "command size must stay aligned");
        }
        if cmdsize_u64 > remaining {
            return invalid(
                "Mach-O load command size",
                "the command overruns the declared table",
            );
        }
        let command_end = usize_add(cursor, cmdsize_u64, "Mach-O load command range")?;
        if command_end > commands_end {
            return invalid(
                "Mach-O load command size",
                "the command overruns the declared table",
            );
        }

        match cmd {
            LC_SEGMENT if !is_64 => {
                parse_segment(
                    &reader,
                    cursor,
                    cmdsize_u64,
                    false,
                    &mut segments,
                    &mut sections,
                )?;
            }
            LC_SEGMENT_64 if is_64 => {
                parse_segment(
                    &reader,
                    cursor,
                    cmdsize_u64,
                    true,
                    &mut segments,
                    &mut sections,
                )?;
            }
            LC_SYMTAB => {
                if cmdsize < 24 {
                    return invalid("Mach-O symtab command", "the record is too small");
                }
                symtab = Some(SymtabCommand {
                    symoff: reader.u32(cursor + 8, "Mach-O symoff")?,
                    nsyms: reader.u32(cursor + 12, "Mach-O nsyms")?,
                    stroff: reader.u32(cursor + 16, "Mach-O stroff")?,
                    strsize: reader.u32(cursor + 20, "Mach-O strsize")?,
                });
            }
            LC_MAIN => {
                if cmdsize < 24 {
                    return invalid("Mach-O main command", "the record is too small");
                }
                entry_offset = Some(reader.u64(cursor + 8, "Mach-O entry offset")?);
            }
            LC_UNIXTHREAD => {
                has_unixthread = true;
            }
            _ => {}
        }

        cursor = command_end;
        remaining -= cmdsize_u64;
    }

    let (symbols, symbol_scan_truncated) = match symtab {
        Some(command) => parse_symbols(&reader, &command, is_64)?,
        None => (Vec::new(), false),
    };
    let (image_base, image_size) = image_extent(&segments)?;

    Ok(MachOImage {
        endian,
        is_64,
        cputype,
        cpusubtype,
        filetype,
        ncmds,
        flags,
        image_base,
        image_size,
        entry_offset,
        has_unixthread,
        segments,
        sections,
        symbols,
        symbol_scan_truncated,
    })
}

fn parse_segment(
    reader: &MachOReader<'_>,
    cursor: usize,
    cmdsize: u64,
    is_64: bool,
    segments: &mut Vec<MachOSegment>,
    sections: &mut Vec<MachOSection>,
) -> Result<(), AnalysisError> {
    enforce_count(
        "Mach-O segment",
        usize_to_u64(segments.len(), "Mach-O segment count")?.saturating_add(1),
        MAX_SEGMENTS,
    )?;
    let header_size = if is_64 {
        SEGMENT_COMMAND_64_SIZE
    } else {
        SEGMENT_COMMAND_32_SIZE
    };
    let section_size = if is_64 {
        SECTION_64_SIZE
    } else {
        SECTION_32_SIZE
    };
    if cmdsize < header_size {
        return invalid("Mach-O segment command", "the record is too small");
    }

    let raw_name = read_fixed16(reader, cursor + 8, "Mach-O segment name")?;
    let name = display_fixed_name(&raw_name);
    let (vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags) = if is_64 {
        (
            reader.u64(cursor + 24, "Mach-O vmaddr")?,
            reader.u64(cursor + 32, "Mach-O vmsize")?,
            reader.u64(cursor + 40, "Mach-O fileoff")?,
            reader.u64(cursor + 48, "Mach-O filesize")?,
            reader.i32(cursor + 56, "Mach-O maxprot")?,
            reader.i32(cursor + 60, "Mach-O initprot")?,
            reader.u32(cursor + 64, "Mach-O nsects")?,
            reader.u32(cursor + 68, "Mach-O segment flags")?,
        )
    } else {
        (
            u64::from(reader.u32(cursor + 24, "Mach-O vmaddr")?),
            u64::from(reader.u32(cursor + 28, "Mach-O vmsize")?),
            u64::from(reader.u32(cursor + 32, "Mach-O fileoff")?),
            u64::from(reader.u32(cursor + 36, "Mach-O filesize")?),
            reader.i32(cursor + 40, "Mach-O maxprot")?,
            reader.i32(cursor + 44, "Mach-O initprot")?,
            reader.u32(cursor + 48, "Mach-O nsects")?,
            reader.u32(cursor + 52, "Mach-O segment flags")?,
        )
    };

    let sections_bytes = u64::from(nsects)
        .checked_mul(section_size)
        .ok_or(AnalysisError::ArithmeticOverflow("Mach-O section table"))?;
    let sections_span = header_size
        .checked_add(sections_bytes)
        .ok_or(AnalysisError::ArithmeticOverflow("Mach-O segment span"))?;
    if sections_span > cmdsize {
        return invalid(
            "Mach-O segment command",
            "declared sections exceed the command size",
        );
    }
    let file_size = reader.len_u64()?;
    validate_file_range(fileoff, filesize, file_size, "Mach-O segment")?;

    let segment_index = usize_to_u64(segments.len(), "Mach-O segment index")?;
    let segment_index = u32::try_from(segment_index)
        .map_err(|_| AnalysisError::IntegerConversion("Mach-O segment index"))?;
    let first_section = u32::try_from(sections.len())
        .map_err(|_| AnalysisError::IntegerConversion("Mach-O section index"))?;

    for section_index in 0..nsects {
        enforce_count(
            "Mach-O section",
            usize_to_u64(sections.len(), "Mach-O section count")?.saturating_add(1),
            MAX_SECTIONS,
        )?;
        let record_relative = u64::from(section_index)
            .checked_mul(section_size)
            .ok_or(AnalysisError::ArithmeticOverflow("Mach-O section offset"))?;
        let record = usize_add(
            usize_add(cursor, header_size, "Mach-O section offset")?,
            record_relative,
            "Mach-O section offset",
        )?;
        let raw_sect_name = read_fixed16(reader, record, "Mach-O section name")?;
        let raw_seg_name = read_fixed16(reader, record + 16, "Mach-O section segment name")?;
        let (addr, size, offset, align, reloff, nreloc, sect_flags) = if is_64 {
            (
                reader.u64(record + 32, "Mach-O section addr")?,
                reader.u64(record + 40, "Mach-O section size")?,
                reader.u32(record + 48, "Mach-O section offset")?,
                reader.u32(record + 52, "Mach-O section align")?,
                reader.u32(record + 56, "Mach-O section reloff")?,
                reader.u32(record + 60, "Mach-O section nreloc")?,
                reader.u32(record + 64, "Mach-O section flags")?,
            )
        } else {
            (
                u64::from(reader.u32(record + 32, "Mach-O section addr")?),
                u64::from(reader.u32(record + 36, "Mach-O section size")?),
                reader.u32(record + 40, "Mach-O section offset")?,
                reader.u32(record + 44, "Mach-O section align")?,
                reader.u32(record + 48, "Mach-O section reloff")?,
                reader.u32(record + 52, "Mach-O section nreloc")?,
                reader.u32(record + 56, "Mach-O section flags")?,
            )
        };
        if !is_zerofill(sect_flags) && offset != 0 {
            validate_file_range(u64::from(offset), size, file_size, "Mach-O section data")?;
        }
        let index = u32::try_from(sections.len())
            .map_err(|_| AnalysisError::IntegerConversion("Mach-O section index"))?;
        sections.push(MachOSection {
            index,
            segment_index,
            name: display_fixed_name(&raw_sect_name),
            raw_name: raw_sect_name,
            segment_name: display_fixed_name(&raw_seg_name),
            raw_segment_name: raw_seg_name,
            addr,
            size,
            offset,
            align,
            reloff,
            nreloc,
            flags: sect_flags,
        });
    }

    segments.push(MachOSegment {
        index: segment_index,
        name,
        raw_name,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot,
        initprot,
        nsects,
        flags,
        first_section,
    });
    Ok(())
}

struct SymtabCommand {
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}

fn parse_symbols(
    reader: &MachOReader<'_>,
    command: &SymtabCommand,
    is_64: bool,
) -> Result<(Vec<MachOSymbol>, bool), AnalysisError> {
    let record_size = if is_64 { NLIST_64_SIZE } else { NLIST_32_SIZE };
    let file_size = reader.len_u64()?;
    let symoff = u64::from(command.symoff);
    let table_bytes = u64::from(command.nsyms)
        .checked_mul(record_size)
        .ok_or(AnalysisError::ArithmeticOverflow("Mach-O symbol table"))?;
    validate_file_range(symoff, table_bytes, file_size, "Mach-O symbol table")?;
    let stroff = usize::try_from(command.stroff)
        .map_err(|_| AnalysisError::IntegerConversion("Mach-O string-table offset"))?;
    let strsize = usize::try_from(command.strsize)
        .map_err(|_| AnalysisError::IntegerConversion("Mach-O string-table size"))?;
    let strtab = reader.bytes(stroff, strsize, "Mach-O string table")?;

    let mut symbols = Vec::new();
    let mut truncated = false;
    for index in 0..command.nsyms {
        if symbols.len() >= MAX_MACHO_SYMBOLS {
            truncated = true;
            break;
        }
        let record_relative = u64::from(index)
            .checked_mul(record_size)
            .ok_or(AnalysisError::ArithmeticOverflow("Mach-O symbol offset"))?;
        let record = usize_add_u64(symoff, record_relative, "Mach-O symbol offset")?;
        let n_strx = reader.u32(record, "Mach-O symbol name")?;
        let n_type = reader.u8(record + 4, "Mach-O symbol type")?;
        let n_sect = reader.u8(record + 5, "Mach-O symbol section")?;
        let n_desc = reader.u16(record + 6, "Mach-O symbol desc")?;
        let n_value = if is_64 {
            reader.u64(record + 8, "Mach-O symbol value")?
        } else {
            u64::from(reader.u32(record + 8, "Mach-O symbol value")?)
        };
        // Skip debug (stab) records; they are not container name evidence.
        if n_type & N_STAB != 0 {
            continue;
        }
        let Some(name) = resolve_symbol_name(strtab, n_strx) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        symbols.push(MachOSymbol {
            table_index: index,
            name,
            n_type,
            n_sect,
            n_desc,
            n_value,
        });
    }
    Ok((symbols, truncated))
}

/// Build the deterministic base graph from the exact identity and container.
///
/// A thin image yields function claims for symbols whose section maps into an
/// executable segment and global claims for symbols in readable, non-executable
/// segments. A fat container yields an identity-only graph: one whole-file
/// binary id cannot host per-architecture RVA claims without cross-slice
/// collisions, so no per-symbol claim is emitted for universal binaries.
pub(crate) fn build_symbol_graph(
    identity: &BinaryIdentity,
    container: &MachOContainer,
) -> Result<SymbolGraph, AnalysisError> {
    let mut graph = SymbolGraph::default();
    graph.insert_binary(identity.clone())?;

    let MachOContainer::Thin(image) = container else {
        return Ok(graph);
    };

    let image_base = identity.image_base;
    let name_confidence = Confidence::new(0.9)?;
    let metadata_kind = EvidenceKind::new(EvidenceKind::METADATA)?;
    let provenance = ClaimProvenance {
        producer: ClaimProducer::Core {
            component: "resymbol-analysis".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        method: "macho-symbol-table".to_owned(),
        run_id: None,
    };

    for symbol in &image.symbols {
        if symbol.n_sect == NO_SECT {
            continue;
        }
        let section_index = usize::from(symbol.n_sect - 1);
        let Some(section) = image.sections.get(section_index) else {
            continue;
        };
        let Some(segment) = image.segments.get(section.segment_index as usize) else {
            continue;
        };
        // Only symbols whose value lands inside the owning segment map cleanly.
        let segment_end = match segment.vmaddr.checked_add(segment.vmsize) {
            Some(end) => end,
            None => continue,
        };
        if symbol.n_value < segment.vmaddr || symbol.n_value >= segment_end {
            continue;
        }
        let Some(rva) = symbol.n_value.checked_sub(image_base) else {
            continue;
        };
        let is_function = segment.executable();
        if !is_function && !segment.readable() {
            continue;
        }

        let mut evidence = Evidence::new(
            metadata_kind.clone(),
            "exact name from a Mach-O symbol table",
        )?;
        evidence.confidence = Some(name_confidence);
        evidence
            .artifacts
            .insert("symbol_value".to_owned(), format!("{:#x}", symbol.n_value));
        evidence
            .artifacts
            .insert("symbol_rva".to_owned(), format!("{rva:#x}"));
        evidence
            .artifacts
            .insert("table_index".to_owned(), symbol.table_index.to_string());
        evidence
            .artifacts
            .insert("section".to_owned(), section.name.clone());
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

pub(crate) fn validate_macho_analysis(analysis: &MachOAnalysis) -> Result<(), AnalysisError> {
    analysis.identity.validate()?;
    if !matches!(analysis.identity.format, BinaryFormat::MachO) {
        return invalid(
            "Mach-O identity format",
            "expected the Mach-O format marker",
        );
    }
    match &analysis.container {
        MachOContainer::Thin(image) => validate_thin(analysis, image)?,
        MachOContainer::Fat(fat) => validate_fat(analysis, fat)?,
    }
    let expected_graph = build_symbol_graph(&analysis.identity, &analysis.container)?;
    if analysis.symbol_graph != expected_graph {
        return invalid(
            "Mach-O symbol graph",
            "the graph must be reproducible from the exact identity and container",
        );
    }
    Ok(())
}

fn validate_thin(analysis: &MachOAnalysis, image: &MachOImage) -> Result<(), AnalysisError> {
    let expected_architecture = macho_architecture(image.cputype, image.is_64);
    if analysis.identity.architecture != expected_architecture {
        return invalid(
            "Mach-O identity architecture",
            &format!("expected `{expected_architecture}`"),
        );
    }
    enforce_count(
        "Mach-O segment",
        usize_to_u64(image.segments.len(), "Mach-O segment count")?,
        MAX_SEGMENTS,
    )?;
    enforce_count(
        "Mach-O section",
        usize_to_u64(image.sections.len(), "Mach-O section count")?,
        MAX_SECTIONS,
    )?;
    if image.symbols.len() > MAX_MACHO_SYMBOLS {
        return Err(AnalysisError::LimitExceeded {
            kind: "Mach-O symbol",
            count: usize_to_u64(image.symbols.len(), "Mach-O symbol count")?,
            limit: usize_to_u64(MAX_MACHO_SYMBOLS, "Mach-O symbol cap")?,
        });
    }
    for (index, segment) in image.segments.iter().enumerate() {
        if u64::from(segment.index) != usize_to_u64(index, "Mach-O segment index")? {
            return invalid(
                "Mach-O segment index",
                "records must retain contiguous source order",
            );
        }
        validate_file_range(
            segment.fileoff,
            segment.filesize,
            analysis.identity.size,
            "Mach-O segment",
        )?;
    }
    for (index, section) in image.sections.iter().enumerate() {
        if u64::from(section.index) != usize_to_u64(index, "Mach-O section index")? {
            return invalid(
                "Mach-O section index",
                "records must retain contiguous source order",
            );
        }
        if image.segments.get(section.segment_index as usize).is_none() {
            return invalid(
                "Mach-O section segment",
                "each section must reference a parsed segment",
            );
        }
        if !is_zerofill(section.flags) && section.offset != 0 {
            validate_file_range(
                u64::from(section.offset),
                section.size,
                analysis.identity.size,
                "Mach-O section data",
            )?;
        }
    }
    for symbol in &image.symbols {
        if symbol.name.is_empty() {
            return invalid("Mach-O symbol name", "recovered symbols must be named");
        }
        if symbol.n_type & N_STAB != 0 {
            return invalid("Mach-O symbol", "debug symbols must not be retained");
        }
    }
    let (image_base, image_size) = image_extent(&image.segments)?;
    if image.image_base != image_base {
        return invalid(
            "Mach-O image base",
            "the base is not the lowest non-__PAGEZERO segment address",
        );
    }
    if image.image_size != image_size || analysis.image_size != image_size {
        return invalid(
            "Mach-O image size",
            "the extent does not match the segment mapping",
        );
    }
    if analysis.identity.image_base != image_base {
        return invalid(
            "Mach-O identity base",
            "the identity base must match the segment mapping",
        );
    }
    Ok(())
}

fn validate_fat(analysis: &MachOAnalysis, fat: &MachOFat) -> Result<(), AnalysisError> {
    if fat.slices.is_empty() {
        return invalid("Mach-O fat slices", "a fat container needs one slice");
    }
    enforce_count(
        "Mach-O fat arch",
        usize_to_u64(fat.slices.len(), "Mach-O fat arch count")?,
        MAX_FAT_ARCH,
    )?;
    if analysis.identity.architecture != FAT_ARCHITECTURE {
        return invalid(
            "Mach-O identity architecture",
            "a fat container uses the universal marker",
        );
    }
    if analysis.identity.image_base != 0 {
        return invalid(
            "Mach-O identity base",
            "a fat container has no single image base",
        );
    }
    let mut max_image_size = 0_u64;
    for (index, slice) in fat.slices.iter().enumerate() {
        if u64::from(slice.index) != usize_to_u64(index, "Mach-O fat slice index")? {
            return invalid(
                "Mach-O fat slice index",
                "records must retain contiguous source order",
            );
        }
        validate_file_range(
            slice.offset,
            slice.size,
            analysis.identity.size,
            "Mach-O fat slice",
        )?;
        let expected_architecture = macho_architecture(slice.cputype, slice.image.is_64);
        if slice.architecture != expected_architecture {
            return invalid(
                "Mach-O fat slice architecture",
                &format!("expected `{expected_architecture}`"),
            );
        }
        let (image_base, image_size) = image_extent(&slice.image.segments)?;
        if slice.image.image_base != image_base || slice.image.image_size != image_size {
            return invalid(
                "Mach-O fat slice image",
                "the slice extent does not match its segment mapping",
            );
        }
        max_image_size = max_image_size.max(image_size);
    }
    if analysis.image_size != max_image_size {
        return invalid(
            "Mach-O fat image size",
            "the container size must be the maximum across slices",
        );
    }
    Ok(())
}

fn image_extent(segments: &[MachOSegment]) -> Result<(u64, u64), AnalysisError> {
    let mut base: Option<u64> = None;
    let mut end = 0_u64;
    for segment in segments {
        if is_pagezero(segment) {
            continue;
        }
        let segment_end = segment
            .vmaddr
            .checked_add(segment.vmsize)
            .ok_or(AnalysisError::ArithmeticOverflow("Mach-O segment extent"))?;
        base = Some(base.map_or(segment.vmaddr, |current| current.min(segment.vmaddr)));
        end = end.max(segment_end);
    }
    match base {
        Some(base) => {
            let size = end
                .checked_sub(base)
                .ok_or(AnalysisError::ArithmeticOverflow("Mach-O image size"))?;
            Ok((base, size))
        }
        None => Ok((0, 0)),
    }
}

fn is_pagezero(segment: &MachOSegment) -> bool {
    segment.name == "__PAGEZERO"
        || (segment.fileoff == 0 && segment.filesize == 0 && segment.vmaddr == 0)
}

fn is_zerofill(flags: u32) -> bool {
    matches!(
        flags & SECTION_TYPE_MASK,
        S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
    )
}

/// Derive the canonical architecture string from `cputype` and container width.
fn macho_architecture(cputype: i32, is_64: bool) -> String {
    let width = if is_64 { "macho64" } else { "macho32" };
    match cputype {
        CPU_TYPE_X86_64 => "macho64-x86-64".to_owned(),
        CPU_TYPE_ARM64 => "macho64-arm64".to_owned(),
        CPU_TYPE_X86 => "macho32-x86".to_owned(),
        CPU_TYPE_ARM => "macho32-arm".to_owned(),
        CPU_TYPE_POWERPC => "macho32-ppc".to_owned(),
        CPU_TYPE_POWERPC64 => "macho64-ppc64".to_owned(),
        other => {
            let unsigned = u32::from_ne_bytes(other.to_ne_bytes());
            format!("{width}-cputype-{unsigned}")
        }
    }
}

/// Resolve a NUL-terminated UTF-8 name from a string-table slice.
fn resolve_symbol_name(strtab: &[u8], name_offset: u32) -> Option<String> {
    let start = usize::try_from(name_offset).ok()?;
    let tail = strtab.get(start..)?;
    let end = tail.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&tail[..end]).ok().map(str::to_owned)
}

fn read_fixed16(
    reader: &MachOReader<'_>,
    offset: usize,
    context: &'static str,
) -> Result<[u8; 16], AnalysisError> {
    let bytes = reader.bytes(offset, 16, context)?;
    let mut fixed = [0_u8; 16];
    fixed.copy_from_slice(bytes);
    Ok(fixed)
}

/// Escape a fixed-width name field to printable text, dropping trailing NULs.
fn display_fixed_name(raw: &[u8; 16]) -> String {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    let mut name = String::new();
    for byte in &raw[..end] {
        if byte.is_ascii_graphic() || *byte == b' ' {
            name.push(char::from(*byte));
        } else {
            name.push('\\');
            name.push('x');
            const HEX: &[u8; 16] = b"0123456789abcdef";
            name.push(char::from(HEX[usize::from(*byte >> 4)]));
            name.push(char::from(HEX[usize::from(*byte & 0x0f)]));
        }
    }
    name
}

fn leading_magic(bytes: &[u8]) -> String {
    let take = bytes.len().min(4);
    let mut result = String::with_capacity(take.saturating_mul(3));
    for (index, byte) in bytes[..take].iter().enumerate() {
        if index != 0 {
            result.push(' ');
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        result.push(char::from(HEX[usize::from(*byte >> 4)]));
        result.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    result
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
        .ok_or(AnalysisError::ArithmeticOverflow("Mach-O file range"))?;
    if end > file_size {
        return invalid(
            field,
            &format!("range {offset:#x}..{end:#x} exceeds file size {file_size:#x}"),
        );
    }
    Ok(())
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

fn slice_len_u64(bytes: &[u8]) -> Result<u64, AnalysisError> {
    usize_to_u64(bytes.len(), "Mach-O input size")
}

fn usize_add(base: usize, add: u64, context: &'static str) -> Result<usize, AnalysisError> {
    let base = usize_to_u64(base, context)?;
    let sum = base
        .checked_add(add)
        .ok_or(AnalysisError::ArithmeticOverflow(context))?;
    usize::try_from(sum).map_err(|_| AnalysisError::IntegerConversion(context))
}

fn usize_add_u64(base: u64, add: u64, context: &'static str) -> Result<usize, AnalysisError> {
    let sum = base
        .checked_add(add)
        .ok_or(AnalysisError::ArithmeticOverflow(context))?;
    usize::try_from(sum).map_err(|_| AnalysisError::IntegerConversion(context))
}

fn invalid<T>(field: &'static str, reason: &str) -> Result<T, AnalysisError> {
    Err(AnalysisError::InvalidField {
        field,
        reason: reason.to_owned(),
    })
}

struct MachOReader<'bytes> {
    bytes: &'bytes [u8],
    endian: MachOEndian,
}

impl<'bytes> MachOReader<'bytes> {
    const fn new(bytes: &'bytes [u8], endian: MachOEndian) -> Self {
        Self { bytes, endian }
    }

    fn len_u64(&self) -> Result<u64, AnalysisError> {
        slice_len_u64(self.bytes)
    }

    fn require(
        &self,
        offset: usize,
        needed: usize,
        context: &'static str,
    ) -> Result<(), AnalysisError> {
        let end = offset
            .checked_add(needed)
            .ok_or(AnalysisError::ArithmeticOverflow("Mach-O read range"))?;
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
            MachOEndian::Little => u16::from_le_bytes(array),
            MachOEndian::Big => u16::from_be_bytes(array),
        })
    }

    fn u32(&self, offset: usize, context: &'static str) -> Result<u32, AnalysisError> {
        let bytes = self.bytes(offset, 4, context)?;
        let array = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(match self.endian {
            MachOEndian::Little => u32::from_le_bytes(array),
            MachOEndian::Big => u32::from_be_bytes(array),
        })
    }

    fn i32(&self, offset: usize, context: &'static str) -> Result<i32, AnalysisError> {
        Ok(i32::from_ne_bytes(self.u32(offset, context)?.to_ne_bytes()))
    }

    fn u64(&self, offset: usize, context: &'static str) -> Result<u64, AnalysisError> {
        let bytes = self.bytes(offset, 8, context)?;
        let array = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];
        Ok(match self.endian {
            MachOEndian::Little => u64::from_le_bytes(array),
            MachOEndian::Big => u64::from_be_bytes(array),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{MachOKind, detect_macho, macho_architecture};
    use crate::MachOEndian;

    #[test]
    fn detects_every_supported_magic() {
        assert_eq!(
            detect_macho(&[0xce, 0xfa, 0xed, 0xfe]),
            Some(MachOKind::Thin32(MachOEndian::Little))
        );
        assert_eq!(
            detect_macho(&[0xcf, 0xfa, 0xed, 0xfe]),
            Some(MachOKind::Thin64(MachOEndian::Little))
        );
        assert_eq!(
            detect_macho(&[0xfe, 0xed, 0xfa, 0xce]),
            Some(MachOKind::Thin32(MachOEndian::Big))
        );
        assert_eq!(
            detect_macho(&[0xfe, 0xed, 0xfa, 0xcf]),
            Some(MachOKind::Thin64(MachOEndian::Big))
        );
        assert_eq!(
            detect_macho(&[0xca, 0xfe, 0xba, 0xbe]),
            Some(MachOKind::Fat)
        );
        assert_eq!(
            detect_macho(&[0xca, 0xfe, 0xba, 0xbf]),
            Some(MachOKind::Fat64)
        );
        assert_eq!(detect_macho(&[0x7f, b'E', b'L', b'F']), None);
        assert_eq!(detect_macho(&[0xcf, 0xfa]), None);
    }

    #[test]
    fn architecture_strings_cover_known_and_unknown_cputypes() {
        assert_eq!(macho_architecture(0x0100_0007, true), "macho64-x86-64");
        assert_eq!(macho_architecture(0x0100_000c, true), "macho64-arm64");
        assert_eq!(macho_architecture(7, false), "macho32-x86");
        assert_eq!(macho_architecture(12, false), "macho32-arm");
        assert_eq!(macho_architecture(18, false), "macho32-ppc");
        assert_eq!(macho_architecture(0x0100_0012, true), "macho64-ppc64");
        assert_eq!(macho_architecture(0x1234, true), "macho64-cputype-4660");
        assert_eq!(macho_architecture(0x1234, false), "macho32-cputype-4660");
    }
}
