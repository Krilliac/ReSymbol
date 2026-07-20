//! Explicit PlayStation 2 container views over ReSymbol's canonical ELF analysis.
//!
//! This crate deliberately does not parse a second copy of the ELF format and
//! never infers Emotion Engine/R5900 instruction semantics from `EM_MIPS`.
//! [`analyze_ps2_elf`] delegates structural ingestion to `resymbol-analysis`;
//! [`Ps2EeElfImage`] then binds the returned model to the exact bytes and checks
//! only the narrow ELF32, little-endian, executable, `EM_MIPS` container profile.
//! Callers must make a separate explicit decoder-profile selection before any
//! instruction analysis.

use resymbol_analysis::{
    AnalysisError, DecoderProfile, ElfAnalysis, ElfClass, ElfEndian, ElfLoadSegment,
    ElfProgramHeader, ElfSectionHeader, ElfSymbol, analyze_elf,
};
use resymbol_core::BinaryId;
use thiserror::Error;

/// Maximum byte length accepted for one resolved ELF section name.
pub const MAX_PS2_EE_ELF_NAME_BYTES: usize = 8 * 1024;

const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_MACHINE_MIPS: u16 = 8;
const ELF_SECTION_TYPE_STRING_TABLE: u32 = 3;

/// A canonical ELF analysis that has passed the explicit PS2 EE container gate.
///
/// The view borrows both inputs, owns no resources, performs no I/O, and is safe
/// to construct on any thread. Its source bytes must remain the exact bytes that
/// produced `analysis`; both size and SHA-256 identity are checked by [`Self::new`].
#[derive(Debug, Clone, Copy)]
pub struct Ps2EeElfImage<'a> {
    exact_elf: &'a [u8],
    analysis: &'a ElfAnalysis,
}

impl<'a> Ps2EeElfImage<'a> {
    /// Bind one canonical analysis to its exact source and require the explicit
    /// PS2 EE ELF container shape. This does not select an instruction decoder.
    pub fn new(exact_elf: &'a [u8], analysis: &'a ElfAnalysis) -> Result<Self, Ps2EeElfError> {
        analysis
            .validate()
            .map_err(|error| Ps2EeElfError::InvalidAnalysis {
                reason: error.to_string(),
            })?;

        let actual_size = u64::try_from(exact_elf.len())
            .map_err(|_| Ps2EeElfError::IntegerConversion("exact ELF byte length"))?;
        if actual_size != analysis.identity.size {
            return Err(Ps2EeElfError::SourceSizeMismatch {
                expected: analysis.identity.size,
                actual: actual_size,
            });
        }
        let actual_id = BinaryId::digest(exact_elf);
        if actual_id != analysis.identity.id {
            return Err(Ps2EeElfError::SourceIdentityMismatch);
        }

        let canonical = analyze_elf(exact_elf)?;
        if canonical != *analysis {
            return Err(Ps2EeElfError::AnalysisModelMismatch);
        }
        require_ps2_ee_container(analysis)?;

        Ok(Self {
            exact_elf,
            analysis,
        })
    }

    /// The exact canonical ELF analysis bound by this view.
    #[must_use]
    pub const fn analysis(&self) -> &'a ElfAnalysis {
        self.analysis
    }

    /// The exact source bytes bound by this view.
    #[must_use]
    pub const fn exact_elf(&self) -> &'a [u8] {
        self.exact_elf
    }

    /// Classify one validated program header without inventing loader semantics.
    pub fn program_header(&self, index: usize) -> Result<Ps2ProgramHeaderView<'a>, Ps2EeElfError> {
        let header = self.analysis.program_headers.get(index).ok_or(
            Ps2EeElfError::ProgramHeaderIndexOutOfRange {
                index,
                count: self.analysis.program_headers.len(),
            },
        )?;
        Ok(Ps2ProgramHeaderView {
            header,
            kind: Ps2ProgramHeaderKind::from_raw(header.segment_type),
        })
    }

    /// Classify one validated sparse load mapping.
    pub fn load_segment(&self, index: usize) -> Result<Ps2LoadSegmentView<'a>, Ps2EeElfError> {
        let segment = self.analysis.load_segments.get(index).ok_or(
            Ps2EeElfError::LoadSegmentIndexOutOfRange {
                index,
                count: self.analysis.load_segments.len(),
            },
        )?;
        Ok(Ps2LoadSegmentView { segment })
    }

    /// Resolve and classify one validated section header.
    ///
    /// Resolution is bounded by [`MAX_PS2_EE_ELF_NAME_BYTES`], validates that
    /// `e_shstrndx` actually names `SHT_STRTAB`, and returns a borrow into the
    /// already identity-checked source rather than allocating a second copy.
    pub fn section(&self, index: usize) -> Result<Ps2SectionView<'a>, Ps2EeElfError> {
        let header = self.analysis.section_headers.get(index).ok_or(
            Ps2EeElfError::SectionIndexOutOfRange {
                index,
                count: self.analysis.section_headers.len(),
            },
        )?;
        let name = self.resolve_section_name(header)?;
        Ok(Ps2SectionView {
            header,
            name,
            kind: Ps2SectionKind::from_raw(header.section_type),
        })
    }

    /// Classify one bounded symbol recovered by the canonical ELF parser.
    pub fn symbol(&self, index: usize) -> Result<Ps2SymbolView<'a>, Ps2EeElfError> {
        let symbol =
            self.analysis
                .symbols
                .get(index)
                .ok_or(Ps2EeElfError::SymbolIndexOutOfRange {
                    index,
                    count: self.analysis.symbols.len(),
                })?;
        Ok(Ps2SymbolView {
            symbol,
            binding: Ps2SymbolBinding::from_info(symbol.info),
            kind: Ps2SymbolKind::from_info(symbol.info),
        })
    }

    fn resolve_section_name(&self, header: &ElfSectionHeader) -> Result<&'a str, Ps2EeElfError> {
        if self.analysis.section_headers.is_empty() || self.analysis.section_name_table_index == 0 {
            return Ok("");
        }
        let name_table_index = usize::from(self.analysis.section_name_table_index);
        let name_table = self.analysis.section_headers.get(name_table_index).ok_or(
            Ps2EeElfError::SectionNameTableIndexOutOfRange {
                index: name_table_index,
                count: self.analysis.section_headers.len(),
            },
        )?;
        if name_table.section_type != ELF_SECTION_TYPE_STRING_TABLE {
            return Err(Ps2EeElfError::SectionNameTableWrongType {
                section_type: name_table.section_type,
            });
        }

        let table_start = usize::try_from(name_table.file_offset)
            .map_err(|_| Ps2EeElfError::IntegerConversion("section-name table file offset"))?;
        let table_size = usize::try_from(name_table.size)
            .map_err(|_| Ps2EeElfError::IntegerConversion("section-name table size"))?;
        let table_end =
            table_start
                .checked_add(table_size)
                .ok_or(Ps2EeElfError::ArithmeticOverflow(
                    "section-name table file range",
                ))?;
        let table = self.exact_elf.get(table_start..table_end).ok_or(
            Ps2EeElfError::SectionNameTableOutsideSource {
                offset: name_table.file_offset,
                size: name_table.size,
            },
        )?;

        let relative = usize::try_from(header.name_offset)
            .map_err(|_| Ps2EeElfError::IntegerConversion("section-name offset"))?;
        if relative >= table.len() {
            return Err(Ps2EeElfError::SectionNameOffsetOutOfRange {
                offset: header.name_offset,
                table_size: name_table.size,
            });
        }
        let tail = table
            .get(relative..)
            .ok_or(Ps2EeElfError::SectionNameOffsetOutOfRange {
                offset: header.name_offset,
                table_size: name_table.size,
            })?;
        let scan_len = tail.len().min(MAX_PS2_EE_ELF_NAME_BYTES.saturating_add(1));
        let Some(nul) = tail[..scan_len].iter().position(|byte| *byte == 0) else {
            if tail.len() > MAX_PS2_EE_ELF_NAME_BYTES {
                return Err(Ps2EeElfError::SectionNameTooLong {
                    maximum: MAX_PS2_EE_ELF_NAME_BYTES,
                });
            }
            return Err(Ps2EeElfError::UnterminatedSectionName {
                offset: header.name_offset,
                available: tail.len(),
            });
        };
        std::str::from_utf8(&tail[..nul]).map_err(|_| Ps2EeElfError::InvalidSectionNameUtf8 {
            offset: header.name_offset,
        })
    }
}

/// Parse with ReSymbol's canonical ELF reader and then apply the explicit PS2
/// EE container gate. The returned model remains architecture-neutral; callers
/// must still select an exact R5900 decoder profile separately.
pub fn analyze_ps2_elf(exact_elf: &[u8]) -> Result<ElfAnalysis, Ps2EeElfError> {
    let analysis = analyze_elf(exact_elf)?;
    require_ps2_ee_container(&analysis)?;
    Ok(analysis)
}

/// Return whether `profile` is one of the explicit bundled EE/R5900 profiles.
///
/// This helper never selects a profile and deliberately rejects every generic
/// MIPS profile even when the container is `EM_MIPS`.
#[must_use]
pub const fn is_explicit_ps2_ee_decoder_profile(profile: DecoderProfile) -> bool {
    matches!(
        profile,
        DecoderProfile::Ps2EeR5900LeCoreV1
            | DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1
            | DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1
            | DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1
            | DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1
            | DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1
    )
}

fn require_ps2_ee_container(analysis: &ElfAnalysis) -> Result<(), Ps2EeElfError> {
    if analysis.class != ElfClass::Elf32 {
        return Err(Ps2EeElfError::IneligibleContainer {
            requirement: "ELFCLASS32",
        });
    }
    if analysis.endian != ElfEndian::Little {
        return Err(Ps2EeElfError::IneligibleContainer {
            requirement: "little-endian ELF data",
        });
    }
    if analysis.elf_type != ELF_TYPE_EXECUTABLE {
        return Err(Ps2EeElfError::IneligibleContainer {
            requirement: "ET_EXEC",
        });
    }
    if analysis.machine != ELF_MACHINE_MIPS {
        return Err(Ps2EeElfError::IneligibleContainer {
            requirement: "EM_MIPS",
        });
    }
    Ok(())
}

/// Conservative classification of a raw ELF program-header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2ProgramHeaderKind {
    Null,
    Load,
    Dynamic,
    Interpreter,
    Note,
    ProgramHeaderTable,
    Other(u32),
}

impl Ps2ProgramHeaderKind {
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Null,
            1 => Self::Load,
            2 => Self::Dynamic,
            3 => Self::Interpreter,
            4 => Self::Note,
            6 => Self::ProgramHeaderTable,
            other => Self::Other(other),
        }
    }
}

/// Borrowed classified program-header view.
#[derive(Debug, Clone, Copy)]
pub struct Ps2ProgramHeaderView<'a> {
    pub header: &'a ElfProgramHeader,
    pub kind: Ps2ProgramHeaderKind,
}

/// Borrowed validated sparse `PT_LOAD` mapping.
#[derive(Debug, Clone, Copy)]
pub struct Ps2LoadSegmentView<'a> {
    pub segment: &'a ElfLoadSegment,
}

/// Conservative classification of a raw ELF section type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2SectionKind {
    Null,
    ProgramBits,
    SymbolTable,
    StringTable,
    RelocationAddend,
    Hash,
    Dynamic,
    Note,
    NoBits,
    Relocation,
    DynamicSymbols,
    Other(u32),
}

impl Ps2SectionKind {
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Null,
            1 => Self::ProgramBits,
            2 => Self::SymbolTable,
            3 => Self::StringTable,
            4 => Self::RelocationAddend,
            5 => Self::Hash,
            6 => Self::Dynamic,
            7 => Self::Note,
            8 => Self::NoBits,
            9 => Self::Relocation,
            11 => Self::DynamicSymbols,
            other => Self::Other(other),
        }
    }
}

/// Borrowed classified section view with a bounded resolved name.
#[derive(Debug, Clone, Copy)]
pub struct Ps2SectionView<'a> {
    pub header: &'a ElfSectionHeader,
    pub name: &'a str,
    pub kind: Ps2SectionKind,
}

/// Conservative classification of the binding nibble in `st_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2SymbolBinding {
    Local,
    Global,
    Weak,
    Other(u8),
}

impl Ps2SymbolBinding {
    #[must_use]
    pub const fn from_info(info: u8) -> Self {
        match info >> 4 {
            0 => Self::Local,
            1 => Self::Global,
            2 => Self::Weak,
            other => Self::Other(other),
        }
    }
}

/// Conservative classification of the type nibble in `st_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2SymbolKind {
    NoType,
    Object,
    Function,
    Section,
    File,
    Other(u8),
}

impl Ps2SymbolKind {
    #[must_use]
    pub const fn from_info(info: u8) -> Self {
        match info & 0x0f {
            0 => Self::NoType,
            1 => Self::Object,
            2 => Self::Function,
            3 => Self::Section,
            4 => Self::File,
            other => Self::Other(other),
        }
    }
}

/// Borrowed classified symbol view.
#[derive(Debug, Clone, Copy)]
pub struct Ps2SymbolView<'a> {
    pub symbol: &'a ElfSymbol,
    pub binding: Ps2SymbolBinding,
    pub kind: Ps2SymbolKind,
}

/// Typed, path-free failure from the explicit PS2 container facade.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Ps2EeElfError {
    #[error(transparent)]
    Analysis(#[from] AnalysisError),
    #[error("the supplied canonical ELF analysis is invalid: {reason}")]
    InvalidAnalysis { reason: String },
    #[error("exact source size mismatch: expected {expected} bytes, found {actual}")]
    SourceSizeMismatch { expected: u64, actual: u64 },
    #[error("exact source SHA-256 does not match the canonical ELF analysis")]
    SourceIdentityMismatch,
    #[error("the supplied ELF analysis does not exactly match a fresh canonical analysis")]
    AnalysisModelMismatch,
    #[error("ineligible PS2 EE container: requires {requirement}")]
    IneligibleContainer { requirement: &'static str },
    #[error("cannot represent {0} on this platform")]
    IntegerConversion(&'static str),
    #[error("integer arithmetic overflow while computing {0}")]
    ArithmeticOverflow(&'static str),
    #[error("program-header index {index} is outside the {count} validated records")]
    ProgramHeaderIndexOutOfRange { index: usize, count: usize },
    #[error("load-segment index {index} is outside the {count} validated mappings")]
    LoadSegmentIndexOutOfRange { index: usize, count: usize },
    #[error("section index {index} is outside the {count} validated records")]
    SectionIndexOutOfRange { index: usize, count: usize },
    #[error("symbol index {index} is outside the {count} recovered records")]
    SymbolIndexOutOfRange { index: usize, count: usize },
    #[error("section-name table index {index} is outside the {count} validated records")]
    SectionNameTableIndexOutOfRange { index: usize, count: usize },
    #[error("section-name table has type {section_type:#x}, expected SHT_STRTAB")]
    SectionNameTableWrongType { section_type: u32 },
    #[error("section-name table file range {offset:#x}+{size:#x} is outside the exact source")]
    SectionNameTableOutsideSource { offset: u64, size: u64 },
    #[error("section-name offset {offset:#x} is outside the table size {table_size:#x}")]
    SectionNameOffsetOutOfRange { offset: u32, table_size: u64 },
    #[error("section name exceeds the {maximum}-byte limit")]
    SectionNameTooLong { maximum: usize },
    #[error("section name at offset {offset:#x} is unterminated in {available} available bytes")]
    UnterminatedSectionName { offset: u32, available: usize },
    #[error("section name at offset {offset:#x} is not valid UTF-8")]
    InvalidSectionNameUtf8 { offset: u32 },
}
