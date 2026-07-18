use resymbol_core::{ClaimValidationError, GraphValidationError};
use thiserror::Error;

/// A deterministic parse or model-construction failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AnalysisError {
    #[error("unsupported binary format (first bytes: {magic})")]
    UnsupportedBinaryFormat { magic: String },
    #[error("invalid ELF signature: expected 7f 45 4c 46")]
    InvalidElfSignature,
    #[error("invalid ELF class {class}; expected 1 (ELF32) or 2 (ELF64)")]
    UnsupportedElfClass { class: u8 },
    #[error("invalid ELF data encoding {data}; expected 1 (little-endian) or 2 (big-endian)")]
    UnsupportedElfDataEncoding { data: u8 },
    #[error("unsupported ELF {context} version {version}; only version 1 is supported")]
    UnsupportedElfVersion { version: u32, context: &'static str },
    #[error(
        "unsupported ELF type {elf_type:#06x}; only ET_EXEC (0x0002) and ET_DYN (0x0003) are supported"
    )]
    UnsupportedElfType { elf_type: u16 },
    #[error("invalid DOS signature: expected MZ, found {found}")]
    InvalidDosSignature { found: String },
    #[error("invalid PE signature at file offset {offset:#x}")]
    InvalidPeSignature { offset: usize },
    #[error("PE header offset {offset:#x} exceeds the parser limit {limit:#x}")]
    PeHeaderOffsetLimit { offset: u32, limit: u32 },
    #[error("unsupported COFF machine {machine:#06x}; only x86-64 ({expected:#06x}) is supported")]
    UnsupportedMachine { machine: u16, expected: u16 },
    #[error(
        "unsupported optional-header magic {magic:#06x}; only PE32+ ({expected:#06x}) is supported"
    )]
    UnsupportedOptionalHeader { magic: u16, expected: u16 },
    #[error("optional header is {actual} bytes; at least {minimum} bytes are required")]
    OptionalHeaderTooSmall { actual: usize, minimum: usize },
    #[error("{kind} count {count} exceeds the parser limit {limit}")]
    LimitExceeded {
        kind: &'static str,
        count: u64,
        limit: u64,
    },
    #[error(
        "truncated {context} at file offset {offset:#x}: need {needed} bytes, only {available} remain"
    )]
    Truncated {
        context: &'static str,
        offset: usize,
        needed: usize,
        available: usize,
    },
    #[error("integer arithmetic overflow while computing {0}")]
    ArithmeticOverflow(&'static str),
    #[error("cannot represent {0} on this platform")]
    IntegerConversion(&'static str),
    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("{context} RVA range {rva:#x}..+{size:#x} is not backed by file data")]
    UnmappedRva {
        context: &'static str,
        rva: u32,
        size: usize,
    },
    #[error("unterminated {context} string at RVA {rva:#x} within {limit} bytes")]
    UnterminatedString {
        context: &'static str,
        rva: u32,
        limit: usize,
    },
    #[error("{context} string at RVA {rva:#x} is not valid UTF-8")]
    InvalidUtf8 { context: &'static str, rva: u32 },
    #[error("{context} is missing its all-zero terminator within the declared directory")]
    MissingTerminator { context: &'static str },
    #[error("ambiguous PE mapping: sections {first} and {second} have overlapping {space} ranges")]
    OverlappingSections {
        first: usize,
        second: usize,
        space: &'static str,
    },
    #[error("invalid Mach-O magic (first bytes: {magic})")]
    InvalidMachOMagic { magic: String },
    #[error("Mach-O fat slice {index} is not a supported thin Mach-O image")]
    InvalidMachOSlice { index: u32 },
    #[error("failed to construct a validated symbol claim: {0}")]
    Claim(#[from] ClaimValidationError),
    #[error("failed to construct the symbol graph: {0}")]
    Graph(#[from] GraphValidationError),
}
