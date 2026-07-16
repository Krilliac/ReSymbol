//! Deterministic logical streams for a public-symbol-only PDB.
//!
//! The caller supplies the exact RSDS identity and exact PE section headers.
//! This module writes the fixed-index streams consumed by an MSF 7.00 writer;
//! it never edits the source executable and never invents a replacement GUID.
//!
//! The layouts follow LLVM's PDB documentation and native builders:
//! - <https://llvm.org/docs/PDB/PdbStream.html>
//! - <https://llvm.org/docs/PDB/TpiStream.html>
//! - <https://llvm.org/docs/PDB/DbiStream.html>
//! - <https://llvm.org/docs/PDB/CodeViewSymbols.html>
//! - `llvm/lib/DebugInfo/PDB/Native/GSIStreamBuilder.cpp`

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

/// Maximum number of public records accepted by one synthetic PDB.
pub(super) const MAX_PDB_PUBLIC_SYMBOLS: usize = 262_144;

const MAX_PDB_NAME_BYTES: usize = 511;
const MAX_PDB_LOGICAL_BYTES: usize = 128 * 1024 * 1024;
const MAX_SECTION_HEADERS: usize = (u16::MAX as usize) - 1;

const STREAM_COUNT: usize = 9;
const STREAM_PDB: usize = 1;
const STREAM_TPI: usize = 2;
const STREAM_DBI: usize = 3;
const STREAM_IPI: usize = 4;
const STREAM_GSI: usize = 5;
const STREAM_PSI: usize = 6;
const STREAM_SYMBOL_RECORDS: usize = 7;
const STREAM_SECTION_HEADERS: usize = 8;

const PDB_INFO_VERSION_VC70: u32 = 20_000_404;
const TPI_VERSION_V80: u32 = 20_040_203;
const DBI_VERSION_V70: u32 = 19_990_903;
const DBI_BUILD_NUMBER: u16 = 0x8e0b;
const TYPE_INDEX_BEGIN: u32 = 0x1000;
const INVALID_STREAM_INDEX: u16 = u16::MAX;

const S_PUB32: u16 = 0x110e;
const PUBLIC_FUNCTION_FLAG: u32 = 0x0000_0002;

const GSI_BUCKETS: usize = 4_096;
const GSI_BITMAP_WORDS: usize = (GSI_BUCKETS + 32) / 32;
const GSI_BITMAP_BYTES: usize = GSI_BITMAP_WORDS * 4;
const GSI_HEADER_SIGNATURE: u32 = u32::MAX;
const GSI_HEADER_VERSION: u32 = 0xeffe_0000 + 19_990_810;
const GSI_HEADER_BYTES: usize = 16;
const GSI_HASH_RECORD_BYTES: usize = 8;
const GSI_IN_MEMORY_HASH_RECORD_BYTES: usize = 12;

const PUBLICS_HEADER_BYTES: usize = 28;
const TPI_HEADER_BYTES: usize = 56;
const DBI_HEADER_BYTES: usize = 64;
const SECTION_MAP_HEADER_BYTES: usize = 4;
const SECTION_MAP_ENTRY_BYTES: usize = 20;
const FILE_INFO_EMPTY_BYTES: usize = 4;
const OPTIONAL_DEBUG_HEADER_BYTES: usize = 6 * 2;

const IMAGE_SCN_MEM_16BIT: u32 = 0x0002_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const SECTION_MAP_READ: u16 = 1 << 0;
const SECTION_MAP_WRITE: u16 = 1 << 1;
const SECTION_MAP_EXECUTE: u16 = 1 << 2;
const SECTION_MAP_32_BIT: u16 = 1 << 3;
const SECTION_MAP_SELECTOR: u16 = 1 << 8;
const SECTION_MAP_ABSOLUTE: u16 = 1 << 9;

/// One already-mapped public symbol in PE section:offset form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PdbPublicSymbol<'name> {
    pub(super) name: &'name str,
    /// One-based PE section number.
    pub(super) section: u16,
    pub(super) offset: u32,
    pub(super) is_function: bool,
}

/// A checked failure to represent the requested logical PDB streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PdbStreamError {
    MissingSections,
    TooManySections {
        actual: usize,
        maximum: usize,
    },
    TooManySymbols {
        actual: usize,
        maximum: usize,
    },
    EmptySymbolName {
        symbol: usize,
    },
    SymbolNameContainsNul {
        symbol: usize,
    },
    SymbolNameTooLong {
        symbol: usize,
        bytes: usize,
        maximum: usize,
    },
    InvalidSymbolSection {
        symbol: usize,
        section: u16,
        section_count: usize,
    },
    SymbolOutsideSection {
        symbol: usize,
        section: u16,
        offset: u32,
        section_size: u32,
    },
    OutputTooLarge {
        bytes: usize,
        maximum: usize,
    },
    IntegerOverflow {
        context: &'static str,
    },
    AllocationFailed {
        context: &'static str,
    },
    InvalidLayout {
        context: &'static str,
    },
}

impl fmt::Display for PdbStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSections => write!(formatter, "a PDB requires at least one PE section"),
            Self::TooManySections { actual, maximum } => write!(
                formatter,
                "PE section count {actual} exceeds the PDB section-map maximum {maximum}"
            ),
            Self::TooManySymbols { actual, maximum } => write!(
                formatter,
                "public symbol count {actual} exceeds the supported maximum {maximum}"
            ),
            Self::EmptySymbolName { symbol } => {
                write!(formatter, "public symbol {symbol} has an empty name")
            }
            Self::SymbolNameContainsNul { symbol } => write!(
                formatter,
                "public symbol {symbol} contains an embedded NUL byte"
            ),
            Self::SymbolNameTooLong {
                symbol,
                bytes,
                maximum,
            } => write!(
                formatter,
                "public symbol {symbol} has a {bytes}-byte name, exceeding the maximum {maximum}"
            ),
            Self::InvalidSymbolSection {
                symbol,
                section,
                section_count,
            } => write!(
                formatter,
                "public symbol {symbol} uses section {section}, outside 1..={section_count}"
            ),
            Self::SymbolOutsideSection {
                symbol,
                section,
                offset,
                section_size,
            } => write!(
                formatter,
                "public symbol {symbol} offset {offset:#x} is outside section {section} of size {section_size:#x}"
            ),
            Self::OutputTooLarge { bytes, maximum } => write!(
                formatter,
                "logical PDB streams need {bytes} bytes, exceeding the supported maximum {maximum}"
            ),
            Self::IntegerOverflow { context } => {
                write!(formatter, "integer overflow while computing {context}")
            }
            Self::AllocationFailed { context } => {
                write!(
                    formatter,
                    "memory allocation failed while building {context}"
                )
            }
            Self::InvalidLayout { context } => {
                write!(
                    formatter,
                    "internal PDB stream layout is invalid: {context}"
                )
            }
        }
    }
}

impl Error for PdbStreamError {}

#[derive(Debug, Clone, Copy)]
struct PreparedSymbol<'name> {
    name: &'name [u8],
    section: u16,
    offset: u32,
    is_function: bool,
    bucket: usize,
    record_offset: u32,
    record_size: usize,
}

#[derive(Debug, Clone, Copy)]
struct StreamLengths {
    record_stream: usize,
    public_hash: usize,
    psi: usize,
    dbi: usize,
    section_headers: usize,
}

/// Build fixed-index PDB streams for an exact RSDS identity.
///
/// The returned vector always has nine entries. Stream 0 is a present empty
/// old-MSF-directory stream; streams 1 through 8 are respectively PDB Info, TPI,
/// DBI, IPI, GSI, PSI, CodeView symbol records, and original section headers.
/// The public records are sorted canonically, so input order cannot affect the
/// output, including when names or addresses collide.
pub(super) fn build_logical_streams(
    guid: [u8; 16],
    age: u32,
    machine: u16,
    section_headers: &[[u8; 40]],
    symbols: &[PdbPublicSymbol<'_>],
) -> Result<Vec<Option<Vec<u8>>>, PdbStreamError> {
    let lengths = validate_and_measure(section_headers, symbols)?;
    let prepared = prepare_symbols(symbols, lengths.record_stream)?;

    let info = build_info_stream(guid, age)?;
    let tpi = build_empty_tpi_stream()?;
    let dbi = build_dbi_stream(age, machine, section_headers, lengths.dbi)?;
    let ipi = build_empty_tpi_stream()?;
    let gsi = build_hash_stream(&[], GSI_HEADER_BYTES + GSI_BITMAP_BYTES)?;
    let records = build_symbol_record_stream(&prepared, lengths.record_stream)?;
    let psi = build_publics_stream(&prepared, lengths.public_hash, lengths.psi)?;
    let raw_sections = build_section_header_stream(section_headers, lengths.section_headers)?;

    let mut streams = Vec::new();
    streams
        .try_reserve_exact(STREAM_COUNT)
        .map_err(|_| PdbStreamError::AllocationFailed {
            context: "logical PDB stream table",
        })?;
    streams.resize_with(STREAM_COUNT, || None);
    // LLVM's PDB builder creates every reserved stream with size zero before
    // filling streams 1..4. Consequently the unused old-directory stream is
    // present-empty (size 0), not nil (size 0xffffffff).
    streams[0] = Some(Vec::new());
    streams[STREAM_PDB] = Some(info);
    streams[STREAM_TPI] = Some(tpi);
    streams[STREAM_DBI] = Some(dbi);
    streams[STREAM_IPI] = Some(ipi);
    streams[STREAM_GSI] = Some(gsi);
    streams[STREAM_PSI] = Some(psi);
    streams[STREAM_SYMBOL_RECORDS] = Some(records);
    streams[STREAM_SECTION_HEADERS] = Some(raw_sections);

    Ok(streams)
}

fn validate_and_measure(
    section_headers: &[[u8; 40]],
    symbols: &[PdbPublicSymbol<'_>],
) -> Result<StreamLengths, PdbStreamError> {
    if section_headers.is_empty() {
        return Err(PdbStreamError::MissingSections);
    }
    if section_headers.len() > MAX_SECTION_HEADERS {
        return Err(PdbStreamError::TooManySections {
            actual: section_headers.len(),
            maximum: MAX_SECTION_HEADERS,
        });
    }
    if symbols.len() > MAX_PDB_PUBLIC_SYMBOLS {
        return Err(PdbStreamError::TooManySymbols {
            actual: symbols.len(),
            maximum: MAX_PDB_PUBLIC_SYMBOLS,
        });
    }

    let mut record_stream = 0_usize;
    let mut occupied_buckets = [false; GSI_BUCKETS];
    for (index, symbol) in symbols.iter().enumerate() {
        let name = symbol.name.as_bytes();
        if name.is_empty() {
            return Err(PdbStreamError::EmptySymbolName { symbol: index });
        }
        if name.contains(&0) {
            return Err(PdbStreamError::SymbolNameContainsNul { symbol: index });
        }
        if name.len() > MAX_PDB_NAME_BYTES {
            return Err(PdbStreamError::SymbolNameTooLong {
                symbol: index,
                bytes: name.len(),
                maximum: MAX_PDB_NAME_BYTES,
            });
        }

        let section_index = usize::from(symbol.section).checked_sub(1).ok_or(
            PdbStreamError::InvalidSymbolSection {
                symbol: index,
                section: symbol.section,
                section_count: section_headers.len(),
            },
        )?;
        let section =
            section_headers
                .get(section_index)
                .ok_or(PdbStreamError::InvalidSymbolSection {
                    symbol: index,
                    section: symbol.section,
                    section_count: section_headers.len(),
                })?;
        let section_size = loaded_section_size(section);
        if symbol.offset >= section_size {
            return Err(PdbStreamError::SymbolOutsideSection {
                symbol: index,
                section: symbol.section,
                offset: symbol.offset,
                section_size,
            });
        }

        record_stream = checked_add(
            record_stream,
            symbol_record_size(name.len())?,
            "CodeView symbol record stream size",
        )?;
        let bucket =
            usize::try_from(hash_string_v1(name) % (GSI_BUCKETS as u32)).map_err(|_| {
                PdbStreamError::IntegerOverflow {
                    context: "GSI bucket index",
                }
            })?;
        occupied_buckets[bucket] = true;
    }

    let public_hash = checked_add(
        checked_add(
            checked_add(
                GSI_HEADER_BYTES,
                checked_mul(symbols.len(), GSI_HASH_RECORD_BYTES, "GSI hash records")?,
                "GSI header and hash records",
            )?,
            GSI_BITMAP_BYTES,
            "GSI bucket bitmap",
        )?,
        checked_mul(
            occupied_buckets.iter().filter(|value| **value).count(),
            4,
            "GSI nonempty bucket offsets",
        )?,
        "GSI hash stream",
    )?;
    let psi = checked_add(
        checked_add(PUBLICS_HEADER_BYTES, public_hash, "PSI hash table")?,
        checked_mul(symbols.len(), 4, "PSI address map")?,
        "PSI stream",
    )?;

    let section_map_entries = checked_add(section_headers.len(), 1, "section-map entries")?;
    let section_map = checked_add(
        SECTION_MAP_HEADER_BYTES,
        checked_mul(
            section_map_entries,
            SECTION_MAP_ENTRY_BYTES,
            "section-map entries",
        )?,
        "section-map stream",
    )?;
    let dbi = checked_add(
        checked_add(
            checked_add(DBI_HEADER_BYTES, section_map, "DBI section map")?,
            FILE_INFO_EMPTY_BYTES,
            "DBI empty file-info substream",
        )?,
        OPTIONAL_DEBUG_HEADER_BYTES,
        "DBI optional debug header",
    )?;
    let raw_sections = checked_mul(
        section_headers.len(),
        40,
        "original PE section-header stream",
    )?;

    let mut logical_total = 52_usize;
    for (size, context) in [
        (TPI_HEADER_BYTES, "TPI stream"),
        (dbi, "DBI stream"),
        (TPI_HEADER_BYTES, "IPI stream"),
        (GSI_HEADER_BYTES + GSI_BITMAP_BYTES, "GSI stream"),
        (psi, "PSI stream"),
        (record_stream, "symbol record stream"),
        (raw_sections, "section-header stream"),
    ] {
        logical_total = checked_add(logical_total, size, context)?;
    }
    if logical_total > MAX_PDB_LOGICAL_BYTES {
        return Err(PdbStreamError::OutputTooLarge {
            bytes: logical_total,
            maximum: MAX_PDB_LOGICAL_BYTES,
        });
    }

    Ok(StreamLengths {
        record_stream,
        public_hash,
        psi,
        dbi,
        section_headers: raw_sections,
    })
}

fn prepare_symbols<'name>(
    symbols: &[PdbPublicSymbol<'name>],
    expected_bytes: usize,
) -> Result<Vec<PreparedSymbol<'name>>, PdbStreamError> {
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(symbols.len())
        .map_err(|_| PdbStreamError::AllocationFailed {
            context: "public symbol plan",
        })?;
    for symbol in symbols {
        prepared.push(PreparedSymbol {
            name: symbol.name.as_bytes(),
            section: symbol.section,
            offset: symbol.offset,
            is_function: symbol.is_function,
            // Cache this before the O(n log n) bucket sort. Re-hashing every
            // name in its comparator would make maximum-size inputs needlessly
            // expensive even though the output itself is bounded.
            bucket: (hash_string_v1(symbol.name.as_bytes()) % (GSI_BUCKETS as u32)) as usize,
            record_offset: 0,
            record_size: symbol_record_size(symbol.name.len())?,
        });
    }

    prepared.sort_unstable_by(canonical_symbol_cmp);
    let mut offset = 0_usize;
    for symbol in &mut prepared {
        symbol.record_offset =
            u32::try_from(offset).map_err(|_| PdbStreamError::IntegerOverflow {
                context: "CodeView symbol record offset",
            })?;
        offset = checked_add(offset, symbol.record_size, "CodeView symbol record offsets")?;
    }
    if offset != expected_bytes {
        return Err(PdbStreamError::InvalidLayout {
            context: "measured symbol record length changed during canonicalization",
        });
    }
    Ok(prepared)
}

fn canonical_symbol_cmp(left: &PreparedSymbol<'_>, right: &PreparedSymbol<'_>) -> Ordering {
    left.name
        .cmp(right.name)
        .then_with(|| left.section.cmp(&right.section))
        .then_with(|| left.offset.cmp(&right.offset))
        .then_with(|| right.is_function.cmp(&left.is_function))
}

fn build_info_stream(guid: [u8; 16], age: u32) -> Result<Vec<u8>, PdbStreamError> {
    // 28-byte VC70 header + empty string buffer + empty capacity-8 hash map
    // + zero feature-code terminator.
    let mut output = allocate_bytes(52, "PDB Info stream")?;
    push_u32(&mut output, PDB_INFO_VERSION_VC70);
    push_u32(&mut output, 0); // Deterministic signature, not a timestamp.
    push_u32(&mut output, age);
    output.extend_from_slice(&guid);
    push_u32(&mut output, 0); // Named-stream string buffer bytes.
    push_u32(&mut output, 0); // Hash table size.
    push_u32(&mut output, 8); // LLVM's minimum serialized-map capacity.
    push_u32(&mut output, 0); // Present bit-vector word count.
    push_u32(&mut output, 0); // Deleted bit-vector word count.
    push_u32(&mut output, 0); // Feature-code terminator.
    ensure_length(&output, 52, "PDB Info stream")?;
    Ok(output)
}

fn build_empty_tpi_stream() -> Result<Vec<u8>, PdbStreamError> {
    let mut output = allocate_bytes(TPI_HEADER_BYTES, "empty TPI/IPI stream")?;
    push_u32(&mut output, TPI_VERSION_V80);
    push_u32(&mut output, TPI_HEADER_BYTES as u32);
    push_u32(&mut output, TYPE_INDEX_BEGIN);
    push_u32(&mut output, TYPE_INDEX_BEGIN);
    push_u32(&mut output, 0); // Type record bytes.
    push_u16(&mut output, INVALID_STREAM_INDEX); // Hash stream.
    push_u16(&mut output, INVALID_STREAM_INDEX); // Auxiliary hash stream.
    push_u32(&mut output, 4); // Hash key bytes.
    push_u32(&mut output, 0x0003_ffff); // LLVM MaxTpiHashBuckets - 1.
    for _ in 0..3 {
        push_u32(&mut output, 0); // Buffer offset.
        push_u32(&mut output, 0); // Buffer length.
    }
    ensure_length(&output, TPI_HEADER_BYTES, "empty TPI/IPI stream")?;
    Ok(output)
}

fn build_dbi_stream(
    age: u32,
    machine: u16,
    section_headers: &[[u8; 40]],
    expected_bytes: usize,
) -> Result<Vec<u8>, PdbStreamError> {
    let section_map_size = checked_add(
        SECTION_MAP_HEADER_BYTES,
        checked_mul(
            section_headers.len() + 1,
            SECTION_MAP_ENTRY_BYTES,
            "DBI section map",
        )?,
        "DBI section-map header",
    )?;
    let mut output = allocate_bytes(expected_bytes, "DBI stream")?;

    push_u32(&mut output, u32::MAX); // Version signature -1.
    push_u32(&mut output, DBI_VERSION_V70);
    push_u32(&mut output, age);
    push_u16(&mut output, STREAM_GSI as u16);
    push_u16(&mut output, DBI_BUILD_NUMBER);
    push_u16(&mut output, STREAM_PSI as u16);
    push_u16(&mut output, 0); // PDB DLL version.
    push_u16(&mut output, STREAM_SYMBOL_RECORDS as u16);
    push_u16(&mut output, 0); // PDB DLL rebuild.
    push_u32(&mut output, 0); // Module info.
    push_u32(&mut output, 0); // Section contributions.
    push_u32(
        &mut output,
        u32::try_from(section_map_size).map_err(|_| PdbStreamError::IntegerOverflow {
            context: "DBI section-map size field",
        })?,
    );
    push_u32(&mut output, FILE_INFO_EMPTY_BYTES as u32);
    push_u32(&mut output, 0); // Type-server map.
    push_u32(&mut output, 0); // MFC type server index.
    push_u32(&mut output, OPTIONAL_DEBUG_HEADER_BYTES as u32);
    push_u32(&mut output, 0); // Edit-and-continue substream.
    push_u16(&mut output, 0); // DBI flags.
    push_u16(&mut output, machine);
    push_u32(&mut output, 0); // Reserved.

    let descriptor_count =
        u16::try_from(section_headers.len() + 1).map_err(|_| PdbStreamError::IntegerOverflow {
            context: "DBI section-map descriptor count",
        })?;
    push_u16(&mut output, descriptor_count);
    push_u16(&mut output, descriptor_count);
    for (index, header) in section_headers.iter().enumerate() {
        let characteristics = u32_at(header, 36);
        let mapped_size = loaded_section_size(header);
        push_section_map_entry(
            &mut output,
            section_map_flags(characteristics),
            u16::try_from(index + 1).map_err(|_| PdbStreamError::IntegerOverflow {
                context: "DBI section-map frame",
            })?,
            mapped_size,
        );
    }
    push_section_map_entry(
        &mut output,
        SECTION_MAP_32_BIT | SECTION_MAP_ABSOLUTE,
        descriptor_count,
        u32::MAX,
    );

    // The canonical empty file-info substream contains two zero counts.
    push_u16(&mut output, 0);
    push_u16(&mut output, 0);

    // Emit exactly through SectionHdr (slot 5). All earlier debug streams are
    // absent, and stream 8 is a verbatim IMAGE_SECTION_HEADER array.
    for _ in 0..5 {
        push_u16(&mut output, INVALID_STREAM_INDEX);
    }
    push_u16(&mut output, STREAM_SECTION_HEADERS as u16);

    ensure_length(&output, expected_bytes, "DBI stream")?;
    Ok(output)
}

fn push_section_map_entry(output: &mut Vec<u8>, flags: u16, frame: u16, size: u32) {
    push_u16(output, flags);
    push_u16(output, 0); // Overlay.
    push_u16(output, 0); // Group.
    push_u16(output, frame);
    push_u16(output, u16::MAX); // Section-name string-table offset.
    push_u16(output, u16::MAX); // Class-name string-table offset.
    push_u32(output, 0); // Offset within physical segment.
    push_u32(output, size);
}

fn section_map_flags(characteristics: u32) -> u16 {
    let mut flags = SECTION_MAP_SELECTOR;
    if characteristics & IMAGE_SCN_MEM_READ != 0 {
        flags |= SECTION_MAP_READ;
    }
    if characteristics & IMAGE_SCN_MEM_WRITE != 0 {
        flags |= SECTION_MAP_WRITE;
    }
    if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
        flags |= SECTION_MAP_EXECUTE;
    }
    if characteristics & IMAGE_SCN_MEM_16BIT == 0 {
        flags |= SECTION_MAP_32_BIT;
    }
    flags
}

fn build_symbol_record_stream(
    symbols: &[PreparedSymbol<'_>],
    expected_bytes: usize,
) -> Result<Vec<u8>, PdbStreamError> {
    let mut output = allocate_bytes(expected_bytes, "CodeView symbol record stream")?;
    for symbol in symbols {
        let record_start = output.len();
        let record_length =
            u16::try_from(symbol.record_size - 2).map_err(|_| PdbStreamError::IntegerOverflow {
                context: "S_PUB32 record length",
            })?;
        push_u16(&mut output, record_length);
        push_u16(&mut output, S_PUB32);
        push_u32(
            &mut output,
            if symbol.is_function {
                PUBLIC_FUNCTION_FLAG
            } else {
                0
            },
        );
        push_u32(&mut output, symbol.offset);
        push_u16(&mut output, symbol.section);
        output.extend_from_slice(symbol.name);
        output.push(0);
        while output.len() - record_start < symbol.record_size {
            output.push(0);
        }
    }
    ensure_length(&output, expected_bytes, "CodeView symbol record stream")?;
    Ok(output)
}

fn build_publics_stream(
    symbols: &[PreparedSymbol<'_>],
    hash_bytes: usize,
    expected_bytes: usize,
) -> Result<Vec<u8>, PdbStreamError> {
    let hash = build_hash_stream(symbols, hash_bytes)?;
    let mut output = allocate_bytes(expected_bytes, "PSI stream")?;
    push_u32(
        &mut output,
        u32::try_from(hash.len()).map_err(|_| PdbStreamError::IntegerOverflow {
            context: "PSI name-hash size",
        })?,
    );
    push_u32(
        &mut output,
        u32::try_from(
            symbols
                .len()
                .checked_mul(4)
                .ok_or(PdbStreamError::IntegerOverflow {
                    context: "PSI address-map size",
                })?,
        )
        .map_err(|_| PdbStreamError::IntegerOverflow {
            context: "PSI address-map size field",
        })?,
    );
    push_u32(&mut output, 0); // Thunk count.
    push_u32(&mut output, 0); // Thunk size.
    push_u16(&mut output, 0); // Thunk-table section.
    push_u16(&mut output, 0); // Padding.
    push_u32(&mut output, 0); // Thunk-table offset.
    push_u32(&mut output, 0); // Section-offset entry count.
    output.extend_from_slice(&hash);

    let mut address_order = Vec::new();
    address_order
        .try_reserve_exact(symbols.len())
        .map_err(|_| PdbStreamError::AllocationFailed {
            context: "PSI address map",
        })?;
    address_order.extend(0..symbols.len());
    address_order.sort_unstable_by(|left, right| {
        let left = &symbols[*left];
        let right = &symbols[*right];
        left.section
            .cmp(&right.section)
            .then_with(|| left.offset.cmp(&right.offset))
            .then_with(|| left.name.cmp(right.name))
            .then_with(|| right.is_function.cmp(&left.is_function))
            .then_with(|| left.record_offset.cmp(&right.record_offset))
    });
    for index in address_order {
        push_u32(&mut output, symbols[index].record_offset);
    }

    ensure_length(&output, expected_bytes, "PSI stream")?;
    Ok(output)
}

fn build_hash_stream(
    symbols: &[PreparedSymbol<'_>],
    expected_bytes: usize,
) -> Result<Vec<u8>, PdbStreamError> {
    let mut order = Vec::new();
    order
        .try_reserve_exact(symbols.len())
        .map_err(|_| PdbStreamError::AllocationFailed {
            context: "GSI hash records",
        })?;
    order.extend(0..symbols.len());
    order.sort_unstable_by(|left, right| {
        let left = &symbols[*left];
        let right = &symbols[*right];
        symbol_bucket(left)
            .cmp(&symbol_bucket(right))
            .then_with(|| gsi_name_cmp(left.name, right.name))
            .then_with(|| left.record_offset.cmp(&right.record_offset))
    });

    let mut bitmap = [0_u32; GSI_BITMAP_WORDS];
    let mut bucket_starts = Vec::new();
    bucket_starts
        .try_reserve_exact(GSI_BUCKETS.min(symbols.len()))
        .map_err(|_| PdbStreamError::AllocationFailed {
            context: "GSI bucket offsets",
        })?;
    let mut previous_bucket = None;
    for (hash_index, symbol_index) in order.iter().copied().enumerate() {
        let bucket = symbol_bucket(&symbols[symbol_index]);
        if previous_bucket != Some(bucket) {
            bitmap[bucket / 32] |= 1_u32 << (bucket % 32);
            let start = checked_mul(
                hash_index,
                GSI_IN_MEMORY_HASH_RECORD_BYTES,
                "GSI bucket start",
            )?;
            bucket_starts.push(u32::try_from(start).map_err(|_| {
                PdbStreamError::IntegerOverflow {
                    context: "GSI bucket start field",
                }
            })?);
            previous_bucket = Some(bucket);
        }
    }

    let mut output = allocate_bytes(expected_bytes, "GSI name hash")?;
    push_u32(&mut output, GSI_HEADER_SIGNATURE);
    push_u32(&mut output, GSI_HEADER_VERSION);
    push_u32(
        &mut output,
        u32::try_from(symbols.len().checked_mul(GSI_HASH_RECORD_BYTES).ok_or(
            PdbStreamError::IntegerOverflow {
                context: "GSI hash-record byte count",
            },
        )?)
        .map_err(|_| PdbStreamError::IntegerOverflow {
            context: "GSI hash-record byte field",
        })?,
    );
    let bucket_bytes = checked_add(
        GSI_BITMAP_BYTES,
        checked_mul(bucket_starts.len(), 4, "GSI bucket-offset bytes")?,
        "GSI bucket bytes",
    )?;
    push_u32(
        &mut output,
        u32::try_from(bucket_bytes).map_err(|_| PdbStreamError::IntegerOverflow {
            context: "GSI bucket-byte field",
        })?,
    );

    for symbol_index in order {
        let biased = symbols[symbol_index].record_offset.checked_add(1).ok_or(
            PdbStreamError::IntegerOverflow {
                context: "biased GSI symbol offset",
            },
        )?;
        push_u32(&mut output, biased);
        push_u32(&mut output, 1); // Reference count.
    }
    for word in bitmap {
        push_u32(&mut output, word);
    }
    for start in bucket_starts {
        push_u32(&mut output, start);
    }

    ensure_length(&output, expected_bytes, "GSI name hash")?;
    Ok(output)
}

fn symbol_bucket(symbol: &PreparedSymbol<'_>) -> usize {
    symbol.bucket
}

fn gsi_name_cmp(left: &[u8], right: &[u8]) -> Ordering {
    match left.len().cmp(&right.len()) {
        Ordering::Equal => {}
        ordering => return ordering,
    }
    if !left.is_ascii() || !right.is_ascii() {
        return left.cmp(right);
    }
    for (left, right) in left.iter().copied().zip(right.iter().copied()) {
        match left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase()) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

/// LLVM's `hashStringV1`, interpreted explicitly as little-endian words.
fn hash_string_v1(name: &[u8]) -> u32 {
    let mut result = 0_u32;
    let mut chunks = name.chunks_exact(4);
    for chunk in &mut chunks {
        result ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    let remainder = chunks.remainder();
    if remainder.len() >= 2 {
        result ^= u32::from(u16::from_le_bytes([remainder[0], remainder[1]]));
    }
    if remainder.len() & 1 != 0 {
        result ^= u32::from(remainder[remainder.len() - 1]);
    }
    result |= 0x2020_2020;
    result ^= result >> 11;
    result ^ (result >> 16)
}

fn build_section_header_stream(
    section_headers: &[[u8; 40]],
    expected_bytes: usize,
) -> Result<Vec<u8>, PdbStreamError> {
    let mut output = allocate_bytes(expected_bytes, "original PE section headers")?;
    for header in section_headers {
        output.extend_from_slice(header);
    }
    ensure_length(&output, expected_bytes, "original PE section-header stream")?;
    Ok(output)
}

fn symbol_record_size(name_bytes: usize) -> Result<usize, PdbStreamError> {
    let unaligned = checked_add(15, name_bytes, "S_PUB32 record size")?;
    let with_rounding = checked_add(unaligned, 3, "S_PUB32 record alignment")?;
    Ok(with_rounding & !3)
}

fn checked_add(left: usize, right: usize, context: &'static str) -> Result<usize, PdbStreamError> {
    left.checked_add(right)
        .ok_or(PdbStreamError::IntegerOverflow { context })
}

fn checked_mul(left: usize, right: usize, context: &'static str) -> Result<usize, PdbStreamError> {
    left.checked_mul(right)
        .ok_or(PdbStreamError::IntegerOverflow { context })
}

fn allocate_bytes(capacity: usize, context: &'static str) -> Result<Vec<u8>, PdbStreamError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| PdbStreamError::AllocationFailed { context })?;
    Ok(output)
}

fn ensure_length(
    output: &[u8],
    expected: usize,
    context: &'static str,
) -> Result<(), PdbStreamError> {
    if output.len() != expected {
        return Err(PdbStreamError::InvalidLayout { context });
    }
    Ok(())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn loaded_section_size(header: &[u8; 40]) -> u32 {
    let virtual_size = u32_at(header, 8);
    if virtual_size == 0 {
        u32_at(header, 16)
    } else {
        virtual_size
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: [u8; 16] = [
        0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn section(name: &[u8], virtual_size: u32, raw_size: u32, characteristics: u32) -> [u8; 40] {
        let mut header = [0_u8; 40];
        let copied = name.len().min(8);
        header[..copied].copy_from_slice(&name[..copied]);
        header[8..12].copy_from_slice(&virtual_size.to_le_bytes());
        header[12..16].copy_from_slice(&0x1000_u32.to_le_bytes());
        header[16..20].copy_from_slice(&raw_size.to_le_bytes());
        header[20..24].copy_from_slice(&0x400_u32.to_le_bytes());
        header[36..40].copy_from_slice(&characteristics.to_le_bytes());
        header
    }

    fn sample_sections() -> Vec<[u8; 40]> {
        vec![
            section(
                b".text",
                0x321,
                0x400,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            ),
            section(
                b".data",
                0x80,
                0x200,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            ),
        ]
    }

    fn stream(streams: &[Option<Vec<u8>>], index: usize) -> &[u8] {
        streams[index].as_deref().expect("present stream")
    }

    fn read_u16(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    fn record_offsets(records: &[u8]) -> Vec<u32> {
        let mut offsets = Vec::new();
        let mut offset = 0_usize;
        while offset < records.len() {
            offsets.push(offset as u32);
            offset += usize::from(read_u16(records, offset)) + 2;
        }
        assert_eq!(offset, records.len());
        offsets
    }

    fn record_name(records: &[u8], offset: usize) -> &[u8] {
        let record_end = offset + usize::from(read_u16(records, offset)) + 2;
        let name_start = offset + 14;
        let nul = records[name_start..record_end]
            .iter()
            .position(|byte| *byte == 0)
            .expect("record name terminator");
        &records[name_start..name_start + nul]
    }

    #[test]
    fn fixed_stream_indices_and_info_identity_are_exact() {
        let sections = sample_sections();
        let streams = build_logical_streams(GUID, 7, 0x8664, &sections, &[]).unwrap();
        assert_eq!(streams.len(), STREAM_COUNT);
        assert_eq!(streams[0].as_deref(), Some([].as_slice()));
        assert!(streams.iter().all(Option::is_some));

        let info = stream(&streams, STREAM_PDB);
        assert_eq!(info.len(), 52);
        assert_eq!(read_u32(info, 0), 20_000_404);
        assert_eq!(read_u32(info, 4), 0);
        assert_eq!(read_u32(info, 8), 7);
        assert_eq!(&info[12..28], &GUID);
        assert_eq!(
            &info[28..],
            &[
                0, 0, 0, 0, // Empty string buffer.
                0, 0, 0, 0, // Empty map size.
                8, 0, 0, 0, // Capacity eight.
                0, 0, 0, 0, // No present words.
                0, 0, 0, 0, // No deleted words.
                0, 0, 0, 0, // Feature terminator.
            ]
        );
    }

    #[test]
    fn empty_tpi_and_ipi_have_complete_v80_headers() {
        let sections = sample_sections();
        let streams = build_logical_streams(GUID, 1, 0x8664, &sections, &[]).unwrap();
        for index in [STREAM_TPI, STREAM_IPI] {
            let types = stream(&streams, index);
            assert_eq!(types.len(), 56);
            assert_eq!(read_u32(types, 0), 20_040_203);
            assert_eq!(read_u32(types, 4), 56);
            assert_eq!(read_u32(types, 8), 0x1000);
            assert_eq!(read_u32(types, 12), 0x1000);
            assert_eq!(read_u32(types, 16), 0);
            assert_eq!(read_u16(types, 20), u16::MAX);
            assert_eq!(read_u16(types, 22), u16::MAX);
            assert_eq!(read_u32(types, 24), 4);
            assert_eq!(read_u32(types, 28), 0x3ffff);
            assert!(types[32..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn dbi_references_fixed_streams_and_copies_section_semantics() {
        let sections = sample_sections();
        let streams = build_logical_streams(GUID, 9, 0x8664, &sections, &[]).unwrap();
        let dbi = stream(&streams, STREAM_DBI);

        assert_eq!(read_u32(dbi, 0), u32::MAX);
        assert_eq!(read_u32(dbi, 4), 19_990_903);
        assert_eq!(read_u32(dbi, 8), 9);
        assert_eq!(read_u16(dbi, 12), 5);
        assert_eq!(read_u16(dbi, 14), 0x8e0b);
        assert_eq!(read_u16(dbi, 16), 6);
        assert_eq!(read_u16(dbi, 20), 7);
        assert_eq!(read_u32(dbi, 24), 0);
        assert_eq!(read_u32(dbi, 28), 0);
        assert_eq!(read_u32(dbi, 32), 4 + 3 * 20);
        assert_eq!(read_u32(dbi, 36), 4);
        assert_eq!(read_u32(dbi, 48), 12);
        assert_eq!(read_u32(dbi, 52), 0);
        assert_eq!(read_u16(dbi, 58), 0x8664);

        let map = 64;
        assert_eq!(read_u16(dbi, map), 3);
        assert_eq!(read_u16(dbi, map + 2), 3);
        assert_eq!(read_u16(dbi, map + 4), 0x10d); // RX, 32-bit, selector.
        assert_eq!(read_u16(dbi, map + 10), 1);
        assert_eq!(read_u32(dbi, map + 20), 0x321);
        assert_eq!(read_u16(dbi, map + 24), 0x10b); // RW, 32-bit, selector.
        assert_eq!(read_u16(dbi, map + 30), 2);
        assert_eq!(read_u32(dbi, map + 40), 0x80);
        assert_eq!(read_u16(dbi, map + 44), 0x208); // Absolute descriptor.
        assert_eq!(read_u16(dbi, map + 50), 3);
        assert_eq!(read_u32(dbi, map + 60), u32::MAX);

        let file_info = map + 4 + 3 * 20;
        assert_eq!(&dbi[file_info..file_info + 4], &[0, 0, 0, 0]);
        let debug_header = file_info + 4;
        for slot in 0..5 {
            assert_eq!(read_u16(dbi, debug_header + slot * 2), u16::MAX);
        }
        assert_eq!(read_u16(dbi, debug_header + 10), 8);
        assert_eq!(dbi.len(), debug_header + 12);
    }

    #[test]
    fn original_section_header_stream_is_verbatim() {
        let sections = sample_sections();
        let streams = build_logical_streams(GUID, 1, 0x8664, &sections, &[]).unwrap();
        let mut expected = Vec::new();
        for section in &sections {
            expected.extend_from_slice(section);
        }
        assert_eq!(stream(&streams, STREAM_SECTION_HEADERS), expected);
    }

    #[test]
    fn section_extents_exclude_raw_padding_and_keep_zero_virtual_size_fallback() {
        let raw_padding = section(b".rawpad", 0x100, 0x200, IMAGE_SCN_MEM_READ);
        assert_eq!(loaded_section_size(&raw_padding), 0x100);

        let zero_virtual = section(b".legacy", 0, 0x200, IMAGE_SCN_MEM_READ);
        assert_eq!(loaded_section_size(&zero_virtual), 0x200);

        let last_fallback_byte = PdbPublicSymbol {
            name: "fallback_end",
            section: 1,
            offset: 0x1ff,
            is_function: false,
        };
        build_logical_streams(GUID, 1, 0x8664, &[zero_virtual], &[last_fallback_byte])
            .expect("zero VirtualSize uses the raw-size fallback");
    }

    #[test]
    fn pub32_records_are_name_sorted_flagged_and_four_byte_aligned() {
        let sections = sample_sections();
        let symbols = [
            PdbPublicSymbol {
                name: "zeta",
                section: 1,
                offset: 0x20,
                is_function: true,
            },
            PdbPublicSymbol {
                name: "alpha",
                section: 2,
                offset: 0x10,
                is_function: false,
            },
        ];
        let streams = build_logical_streams(GUID, 1, 0x8664, &sections, &symbols).unwrap();
        let records = stream(&streams, STREAM_SYMBOL_RECORDS);
        let offsets = record_offsets(records);
        assert_eq!(offsets.len(), 2);
        assert_eq!(record_name(records, offsets[0] as usize), b"alpha");
        assert_eq!(read_u16(records, offsets[0] as usize + 2), S_PUB32);
        assert_eq!(read_u32(records, offsets[0] as usize + 4), 0);
        assert_eq!(read_u32(records, offsets[0] as usize + 8), 0x10);
        assert_eq!(read_u16(records, offsets[0] as usize + 12), 2);
        assert_eq!(record_name(records, offsets[1] as usize), b"zeta");
        assert_eq!(read_u32(records, offsets[1] as usize + 4), 2);
        assert_eq!(read_u16(records, offsets[1] as usize + 12), 1);
        assert!(offsets.iter().all(|offset| offset % 4 == 0));
        assert_eq!(records.len() % 4, 0);
    }

    #[test]
    fn hash_v1_matches_known_values_and_uses_4096_buckets() {
        assert_eq!(hash_string_v1(b""), 0x2024_0400);
        assert_eq!(hash_string_v1(b"foo"), 0x2024_4b00);
        assert_eq!(hash_string_v1(b"FunctionName"), 0x6861_1892);
        assert_eq!(hash_string_v1(b"functionname"), 0x6861_1892);
        assert_eq!(GSI_BITMAP_WORDS, 129);
    }

    #[test]
    fn gsi_is_empty_and_psi_hash_and_address_maps_are_canonical() {
        let sections = sample_sections();
        let symbols = [
            PdbPublicSymbol {
                name: "zeta",
                section: 2,
                offset: 0x20,
                is_function: false,
            },
            PdbPublicSymbol {
                name: "Alpha",
                section: 1,
                offset: 0x30,
                is_function: true,
            },
            PdbPublicSymbol {
                name: "alpha",
                section: 1,
                offset: 0x10,
                is_function: true,
            },
        ];
        let streams = build_logical_streams(GUID, 1, 0x8664, &sections, &symbols).unwrap();

        let gsi = stream(&streams, STREAM_GSI);
        assert_eq!(gsi.len(), 16 + 516);
        assert_eq!(read_u32(gsi, 0), u32::MAX);
        assert_eq!(read_u32(gsi, 4), GSI_HEADER_VERSION);
        assert_eq!(read_u32(gsi, 8), 0);
        assert_eq!(read_u32(gsi, 12), 516);
        assert!(gsi[16..].iter().all(|byte| *byte == 0));

        let psi = stream(&streams, STREAM_PSI);
        let hash_size = read_u32(psi, 0) as usize;
        assert_eq!(read_u32(psi, 4), 12);
        assert_eq!(read_u32(psi, 8), 0);
        assert_eq!(read_u32(psi, 24), 0);
        let hash = &psi[28..28 + hash_size];
        assert_eq!(read_u32(hash, 8), 24);
        let bucket_region_size = read_u32(hash, 12) as usize;
        assert!(bucket_region_size >= 516 + 4);

        let records = stream(&streams, STREAM_SYMBOL_RECORDS);
        let offsets = record_offsets(records);
        let mut expected_address_order = offsets.clone();
        expected_address_order.sort_unstable_by_key(|offset| {
            let at = *offset as usize;
            (
                read_u16(records, at + 12),
                read_u32(records, at + 8),
                record_name(records, at).to_vec(),
            )
        });
        let address_map = &psi[28 + hash_size..];
        let actual_address_order: Vec<u32> = address_map
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect();
        assert_eq!(actual_address_order, expected_address_order);

        let bitmap_start = 16 + symbols.len() * 8;
        let bucket_starts = &hash[bitmap_start + 516..];
        assert_eq!(bucket_starts.len() % 4, 0);
        let starts: Vec<u32> = bucket_starts
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect();
        assert_eq!(starts.first(), Some(&0));
        assert!(starts.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(starts.iter().all(|start| start % 12 == 0));
    }

    #[test]
    fn duplicate_names_and_addresses_are_input_order_independent() {
        let sections = sample_sections();
        let forward = [
            PdbPublicSymbol {
                name: "same",
                section: 1,
                offset: 0x20,
                is_function: false,
            },
            PdbPublicSymbol {
                name: "same",
                section: 1,
                offset: 0x20,
                is_function: true,
            },
            PdbPublicSymbol {
                name: "same",
                section: 2,
                offset: 0x10,
                is_function: false,
            },
        ];
        let mut reverse = forward;
        reverse.reverse();
        let first = build_logical_streams(GUID, 3, 0x8664, &sections, &forward).unwrap();
        let second = build_logical_streams(GUID, 3, 0x8664, &sections, &reverse).unwrap();
        assert_eq!(first, second);

        let records = stream(&first, STREAM_SYMBOL_RECORDS);
        assert_eq!(read_u32(records, 4), PUBLIC_FUNCTION_FLAG);
    }

    #[test]
    fn rejects_malformed_names_sections_offsets_and_counts() {
        let sections = sample_sections();
        let missing = build_logical_streams(GUID, 1, 0x8664, &[], &[]).unwrap_err();
        assert_eq!(missing, PdbStreamError::MissingSections);

        for (symbol, expected) in [
            (
                PdbPublicSymbol {
                    name: "",
                    section: 1,
                    offset: 0,
                    is_function: true,
                },
                PdbStreamError::EmptySymbolName { symbol: 0 },
            ),
            (
                PdbPublicSymbol {
                    name: "bad\0name",
                    section: 1,
                    offset: 0,
                    is_function: true,
                },
                PdbStreamError::SymbolNameContainsNul { symbol: 0 },
            ),
            (
                PdbPublicSymbol {
                    name: "valid",
                    section: 0,
                    offset: 0,
                    is_function: true,
                },
                PdbStreamError::InvalidSymbolSection {
                    symbol: 0,
                    section: 0,
                    section_count: 2,
                },
            ),
            (
                PdbPublicSymbol {
                    name: "valid",
                    section: 3,
                    offset: 0,
                    is_function: true,
                },
                PdbStreamError::InvalidSymbolSection {
                    symbol: 0,
                    section: 3,
                    section_count: 2,
                },
            ),
            (
                PdbPublicSymbol {
                    name: "valid",
                    section: 1,
                    offset: 0x321,
                    is_function: true,
                },
                PdbStreamError::SymbolOutsideSection {
                    symbol: 0,
                    section: 1,
                    offset: 0x321,
                    section_size: 0x321,
                },
            ),
        ] {
            assert_eq!(
                build_logical_streams(GUID, 1, 0x8664, &sections, &[symbol]).unwrap_err(),
                expected
            );
        }

        let long = "x".repeat(MAX_PDB_NAME_BYTES + 1);
        let symbol = PdbPublicSymbol {
            name: &long,
            section: 1,
            offset: 0,
            is_function: true,
        };
        assert_eq!(
            build_logical_streams(GUID, 1, 0x8664, &sections, &[symbol]).unwrap_err(),
            PdbStreamError::SymbolNameTooLong {
                symbol: 0,
                bytes: MAX_PDB_NAME_BYTES + 1,
                maximum: MAX_PDB_NAME_BYTES,
            }
        );

        let repeated = PdbPublicSymbol {
            name: "x",
            section: 1,
            offset: 0,
            is_function: true,
        };
        let too_many = vec![repeated; MAX_PDB_PUBLIC_SYMBOLS + 1];
        assert_eq!(
            build_logical_streams(GUID, 1, 0x8664, &sections, &too_many).unwrap_err(),
            PdbStreamError::TooManySymbols {
                actual: MAX_PDB_PUBLIC_SYMBOLS + 1,
                maximum: MAX_PDB_PUBLIC_SYMBOLS,
            }
        );
    }

    #[test]
    fn repeated_build_is_byte_for_byte_deterministic() {
        let sections = sample_sections();
        let symbols = [PdbPublicSymbol {
            name: "deterministic",
            section: 1,
            offset: 0x44,
            is_function: true,
        }];
        let first = build_logical_streams(GUID, 11, 0x8664, &sections, &symbols).unwrap();
        let second = build_logical_streams(GUID, 11, 0x8664, &sections, &symbols).unwrap();
        assert_eq!(first, second);
    }
}
