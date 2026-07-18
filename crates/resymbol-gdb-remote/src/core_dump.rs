//! A read-only, post-mortem [`RemoteTarget`] backed by an ELF core dump.
//!
//! This module parses a minimal ELF core file (`ET_CORE`) entirely in safe,
//! bounded, checked-arithmetic code — no `unsafe`, no execution, no I/O beyond
//! the caller handing us the file bytes. It recovers two things a debugger
//! needs for inspection:
//!
//! * the captured **register state** of the faulting thread, from the first
//!   `NT_PRSTATUS` note (x86-64 only for register recovery — see below), and
//! * the captured **memory image**, from the file-backed bytes of the
//!   `PT_LOAD` program headers.
//!
//! [`CoreDumpTarget`] wraps a parsed [`CoreDump`] and presents it to the RSP
//! server as a target that answers register and memory reads but rejects every
//! mutating or execution operation, because a core dump is a frozen snapshot:
//! there is nothing to write to and nothing to resume.
//!
//! # Register layout
//!
//! On x86-64 the `NT_PRSTATUS` note descriptor is a `struct elf_prstatus`. Its
//! `pr_reg` member (a `user_regs_struct`, 27 `u64` = 216 bytes) begins at byte
//! offset [`PRSTATUS_PR_REG_OFFSET`] within the descriptor, after the fixed
//! prologue (`pr_info`, `pr_cursig`, the signal masks, the pid/ppid/pgrp/sid
//! quartet, and the four `timeval`s). The 27 registers are stored in
//! `user_regs_struct` order and mapped into an [`Amd64CoreRegisters`]. The
//! current signal (`pr_cursig`) sits at offset [`PRSTATUS_PR_CURSIG_OFFSET`].
//!
//! For any non-x86-64 machine we still parse the container and the memory
//! image, but register recovery is unsupported: [`CoreDump::registers`] returns
//! `None` and [`CoreDumpTarget::read_registers`] reports a clear error.
//!
//! # Unmapped memory
//!
//! [`CoreDump::read_memory`] gathers bytes strictly from the **file-backed**
//! extent of the covering `PT_LOAD` segments (the first `p_filesz` bytes of each
//! mapping). It fails closed for any byte that is not file-backed — a gap
//! between mappings, or the zero-fill (`.bss`) tail past `p_filesz`. The RSP
//! server turns that into an `Exx` reply, which GDB tolerates gracefully.

use crate::target::{Amd64CoreRegisters, RemoteTarget, StopReply, TargetError};
use thiserror::Error;

/// ELF class byte: 32-bit objects.
const ELF_CLASS_32: u8 = 1;
/// ELF class byte: 64-bit objects.
const ELF_CLASS_64: u8 = 2;
/// ELF data byte: two's-complement little-endian.
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
/// ELF data byte: two's-complement big-endian.
const ELF_DATA_BIG_ENDIAN: u8 = 2;
/// `e_version` / `EI_VERSION` current value.
const ELF_VERSION_CURRENT: u32 = 1;
/// `e_type` for a core dump.
const ELF_TYPE_CORE: u16 = 4;
/// `e_machine` for x86-64.
const EM_X86_64: u16 = 62;

/// ELF64 header size and the offset of the ELF64 program-header table fields.
const ELF64_HEADER_SIZE: usize = 64;
/// ELF32 header size.
const ELF32_HEADER_SIZE: usize = 52;
/// ELF64 program-header entry size.
const ELF64_PROGRAM_HEADER_SIZE: u16 = 56;
/// ELF32 program-header entry size.
const ELF32_PROGRAM_HEADER_SIZE: u16 = 32;

/// `p_type` for a loadable segment.
const PT_LOAD: u32 = 1;
/// `p_type` for a note segment.
const PT_NOTE: u32 = 4;
/// Note type carrying the general-purpose register set (`struct elf_prstatus`).
const NT_PRSTATUS: u32 = 1;

/// Byte offset of `pr_cursig` (a `short`) within `struct elf_prstatus`.
const PRSTATUS_PR_CURSIG_OFFSET: usize = 12;
/// Byte offset of `pr_reg` (the `user_regs_struct`) within `struct elf_prstatus`.
pub const PRSTATUS_PR_REG_OFFSET: usize = 112;
/// Number of `u64` general-purpose registers in the x86-64 `user_regs_struct`.
const USER_REGS_COUNT: usize = 27;
/// Byte length of the x86-64 `user_regs_struct` (`pr_reg`).
const USER_REGS_BYTES: usize = USER_REGS_COUNT * 8;

/// GDB's `SIGSEGV`, the default stop signal when a core records none.
const GDB_SIGSEGV: u8 = 11;

/// Upper bound on program headers parsed from a core.
const MAX_PROGRAM_HEADERS: u64 = 65_536;
/// Upper bound on the number of notes walked across all `PT_NOTE` segments.
const MAX_NOTES: u64 = 65_536;
/// Upper bound on a single note's name length, in bytes.
const MAX_NOTE_NAME_BYTES: u64 = 4_096;
/// Upper bound on a single note's descriptor length, in bytes (64 MiB).
const MAX_NOTE_DESC_BYTES: u64 = 64 * 1024 * 1024;

/// A fault raised while parsing an ELF core dump.
#[derive(Debug, Error)]
pub enum CoreDumpError {
    /// The buffer ended before a required field could be read.
    #[error(
        "core dump truncated reading {context}: need {needed} bytes at offset {offset}, {available} available"
    )]
    Truncated {
        /// What was being read.
        context: &'static str,
        /// Offset the read started at.
        offset: usize,
        /// Bytes required.
        needed: usize,
        /// Bytes actually available from `offset`.
        available: usize,
    },
    /// The first four bytes were not the ELF magic `\x7fELF`.
    #[error("not an ELF file: the magic `\\x7fELF` is missing")]
    BadMagic,
    /// The `EI_CLASS` byte was neither 32- nor 64-bit.
    #[error("unsupported ELF class byte {0:#x}")]
    UnsupportedClass(u8),
    /// The `EI_DATA` byte was neither little- nor big-endian.
    #[error("unsupported ELF data encoding byte {0:#x}")]
    UnsupportedEncoding(u8),
    /// The `EI_VERSION`/`e_version` value was not the current version.
    #[error("unsupported ELF version {version} in {context}")]
    UnsupportedVersion {
        /// The version value found.
        version: u32,
        /// Where it was found.
        context: &'static str,
    },
    /// `e_type` was not `ET_CORE`.
    #[error("expected an ELF core dump (ET_CORE = 4), found e_type {0}")]
    NotCore(u16),
    /// A structural field carried an unusable value.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// The field name.
        field: &'static str,
        /// Why it is invalid.
        reason: String,
    },
    /// A counted structure exceeded its parsing bound.
    #[error("core dump exceeds the {kind} limit: {count} > {limit}")]
    LimitExceeded {
        /// What kind of structure.
        kind: &'static str,
        /// The count found.
        count: u64,
        /// The enforced ceiling.
        limit: u64,
    },
    /// A checked add/multiply overflowed while computing a range.
    #[error("arithmetic overflow computing {0}")]
    ArithmeticOverflow(&'static str),
    /// A `u64` value would not fit in the platform `usize`.
    #[error("value out of range converting {0}")]
    IntegerConversion(&'static str),
    /// The core carried no `NT_PRSTATUS` note, so no registers were recovered.
    #[error("core dump has no NT_PRSTATUS register note")]
    NoRegisters,
    /// Register recovery was requested for a non-x86-64 core.
    #[error("register recovery is only supported for x86-64 cores (e_machine {0})")]
    UnsupportedMachine(u16),
    /// A requested memory range was not backed by any file-backed `PT_LOAD`.
    #[error("memory range {addr:#x}..+{len} is not backed by any core PT_LOAD segment")]
    UnmappedMemory {
        /// The requested start address.
        addr: u64,
        /// The requested length.
        len: usize,
    },
}

/// The ELF class (word width) of a core dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreClass {
    /// 32-bit ELF.
    Elf32,
    /// 64-bit ELF.
    Elf64,
}

impl CoreClass {
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

    const fn header_size(self) -> usize {
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
}

/// The byte order of a core dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreEndian {
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

impl CoreEndian {
    const fn from_ident(value: u8) -> Option<Self> {
        match value {
            ELF_DATA_LITTLE_ENDIAN => Some(Self::Little),
            ELF_DATA_BIG_ENDIAN => Some(Self::Big),
            _ => None,
        }
    }
}

/// A file-backed loadable region recovered from a `PT_LOAD` program header.
///
/// Only the first `file_size` bytes at `vaddr` are file-backed (found at
/// `file_offset` in the core); the remaining `mem_size - file_size` bytes are
/// zero-fill and are treated as unmapped by [`CoreDump::read_memory`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreRegion {
    /// Virtual address the segment was mapped at.
    pub vaddr: u64,
    /// Offset of the file-backed bytes within the core file.
    pub file_offset: u64,
    /// Number of file-backed bytes (`p_filesz`).
    pub file_size: u64,
    /// Total mapped size (`p_memsz`); the tail past `file_size` is zero-fill.
    pub mem_size: u64,
    /// Segment permission flags (`p_flags`).
    pub flags: u32,
}

/// A parsed, read-only ELF core dump.
#[derive(Debug, Clone)]
pub struct CoreDump {
    class: CoreClass,
    endian: CoreEndian,
    machine: u16,
    regions: Vec<CoreRegion>,
    registers: Option<Amd64CoreRegisters>,
    signal: u8,
    bytes: Vec<u8>,
}

impl CoreDump {
    /// Parse a minimal ELF core dump from `bytes`.
    ///
    /// Verifies the ELF magic, class, encoding, version, and `ET_CORE` type,
    /// then walks the program headers: `PT_LOAD` mappings become file-backed
    /// [`CoreRegion`]s and `PT_NOTE` segments are scanned for the first
    /// `NT_PRSTATUS` note, whose registers (x86-64 only) and current signal are
    /// captured. Everything is bounded and uses checked arithmetic.
    ///
    /// # Errors
    ///
    /// Returns a [`CoreDumpError`] if the buffer is truncated, is not an ELF
    /// core, carries an unsupported class/encoding/version, or exceeds a
    /// structural bound.
    pub fn parse(bytes: &[u8]) -> Result<Self, CoreDumpError> {
        if bytes.len() < 16 {
            return Err(CoreDumpError::Truncated {
                context: "ELF identity",
                offset: 0,
                needed: 16,
                available: bytes.len(),
            });
        }
        if bytes[0..4] != *b"\x7fELF" {
            return Err(CoreDumpError::BadMagic);
        }
        let class =
            CoreClass::from_ident(bytes[4]).ok_or(CoreDumpError::UnsupportedClass(bytes[4]))?;
        let endian =
            CoreEndian::from_ident(bytes[5]).ok_or(CoreDumpError::UnsupportedEncoding(bytes[5]))?;
        if u32::from(bytes[6]) != ELF_VERSION_CURRENT {
            return Err(CoreDumpError::UnsupportedVersion {
                version: u32::from(bytes[6]),
                context: "identity",
            });
        }

        let reader = CoreReader {
            bytes,
            class,
            endian,
        };
        reader.require(0, class.header_size(), "ELF header")?;

        let elf_type = reader.u16(16, "ELF type")?;
        if elf_type != ELF_TYPE_CORE {
            return Err(CoreDumpError::NotCore(elf_type));
        }
        let machine = reader.u16(18, "ELF machine")?;
        let elf_version = reader.u32(20, "ELF version")?;
        if elf_version != ELF_VERSION_CURRENT {
            return Err(CoreDumpError::UnsupportedVersion {
                version: elf_version,
                context: "header",
            });
        }

        let (program_header_offset, phentsize_offset) = if class.is_64() {
            (reader.u64(32, "ELF program-header offset")?, 54)
        } else {
            (u64::from(reader.u32(28, "ELF program-header offset")?), 42)
        };
        let program_header_entry_size =
            reader.u16(phentsize_offset, "ELF program-header entry size")?;
        let program_header_count = reader.u16(phentsize_offset + 2, "ELF program-header count")?;

        if program_header_entry_size != class.program_header_size() {
            return Err(CoreDumpError::InvalidField {
                field: "ELF program-header entry size",
                reason: format!(
                    "expected {} bytes for this class, found {program_header_entry_size}",
                    class.program_header_size()
                ),
            });
        }
        if program_header_count == 0 {
            return Err(CoreDumpError::InvalidField {
                field: "ELF program-header count",
                reason: "a core dump must contain at least one program header".to_owned(),
            });
        }
        enforce_count(
            "program header",
            u64::from(program_header_count),
            MAX_PROGRAM_HEADERS,
        )?;

        let mut regions = Vec::new();
        let mut prstatus_descriptor: Option<Vec<u8>> = None;
        let mut notes_walked: u64 = 0;

        for index in 0..program_header_count {
            let entry_offset =
                table_entry_offset(program_header_offset, index, program_header_entry_size)?;
            let header = reader.program_header(entry_offset)?;
            match header.segment_type {
                PT_LOAD => {
                    validate_file_range(
                        header.file_offset,
                        header.file_size,
                        reader.len_u64()?,
                        "PT_LOAD segment",
                    )?;
                    if header.file_size > header.memory_size {
                        return Err(CoreDumpError::InvalidField {
                            field: "PT_LOAD sizes",
                            reason: format!(
                                "program header {index} has file size {:#x} larger than memory size {:#x}",
                                header.file_size, header.memory_size
                            ),
                        });
                    }
                    if header.memory_size == 0 {
                        continue;
                    }
                    regions.push(CoreRegion {
                        vaddr: header.virtual_address,
                        file_offset: header.file_offset,
                        file_size: header.file_size,
                        mem_size: header.memory_size,
                        flags: header.flags,
                    });
                }
                PT_NOTE => {
                    walk_notes(
                        &reader,
                        header.file_offset,
                        header.file_size,
                        &mut notes_walked,
                        &mut prstatus_descriptor,
                    )?;
                }
                _ => {}
            }
        }

        regions.sort_by_key(|region| region.vaddr);

        let (registers, signal) = match prstatus_descriptor {
            Some(descriptor) if machine == EM_X86_64 => {
                let registers = parse_prstatus_registers(&descriptor, endian)?;
                let signal = parse_prstatus_signal(&descriptor, endian);
                (Some(registers), signal)
            }
            // A non-x86-64 core is parsed for its container and memory, but the
            // register layout is architecture-specific and unsupported here.
            _ => (None, GDB_SIGSEGV),
        };

        Ok(Self {
            class,
            endian,
            machine,
            regions,
            registers,
            signal,
            bytes: bytes.to_vec(),
        })
    }

    /// The ELF class (word width) of the core.
    #[must_use]
    pub const fn class(&self) -> CoreClass {
        self.class
    }

    /// The byte order of the core.
    #[must_use]
    pub const fn endian(&self) -> CoreEndian {
        self.endian
    }

    /// The raw `e_machine` value of the core.
    #[must_use]
    pub const fn machine(&self) -> u16 {
        self.machine
    }

    /// The file-backed loadable regions, sorted by virtual address.
    #[must_use]
    pub fn regions(&self) -> &[CoreRegion] {
        &self.regions
    }

    /// The recovered primary-thread registers, if this is an x86-64 core with an
    /// `NT_PRSTATUS` note.
    #[must_use]
    pub fn registers(&self) -> Option<Amd64CoreRegisters> {
        self.registers
    }

    /// The primary thread's registers serialised as an amd64 `g`-packet.
    ///
    /// # Errors
    ///
    /// Returns [`CoreDumpError::NoRegisters`] if no `NT_PRSTATUS` was found, or
    /// [`CoreDumpError::UnsupportedMachine`] for a non-x86-64 core.
    pub fn gpacket(&self) -> Result<Vec<u8>, CoreDumpError> {
        match self.registers {
            Some(registers) => Ok(registers.to_gpacket()),
            None => {
                if self.machine == EM_X86_64 {
                    Err(CoreDumpError::NoRegisters)
                } else {
                    Err(CoreDumpError::UnsupportedMachine(self.machine))
                }
            }
        }
    }

    /// The stop signal recorded for the core (`pr_cursig`, or `SIGSEGV`).
    #[must_use]
    pub const fn signal(&self) -> u8 {
        self.signal
    }

    /// Read `len` bytes starting at virtual address `addr`.
    ///
    /// Bytes are gathered from the file-backed extent of the covering `PT_LOAD`
    /// regions. Any byte in the requested range that is not file-backed (a gap
    /// between mappings, or the zero-fill tail past `p_filesz`) makes the whole
    /// read fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`CoreDumpError::UnmappedMemory`] if the range is not fully
    /// file-backed, or an arithmetic/conversion error on a pathological range.
    pub fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, CoreDumpError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let len_u64 = u64::try_from(len)
            .map_err(|_| CoreDumpError::IntegerConversion("memory read length"))?;
        let end = addr
            .checked_add(len_u64)
            .ok_or(CoreDumpError::ArithmeticOverflow("memory read range"))?;

        let mut out = Vec::with_capacity(len);
        let mut cursor = addr;
        while cursor < end {
            let region = self
                .regions
                .iter()
                .find(|region| region_file_contains(region, cursor))
                .ok_or(CoreDumpError::UnmappedMemory { addr, len })?;

            let file_backed_end = region
                .vaddr
                .checked_add(region.file_size)
                .ok_or(CoreDumpError::ArithmeticOverflow("PT_LOAD file extent"))?;
            let chunk_end = end.min(file_backed_end);

            let offset_in_region = cursor
                .checked_sub(region.vaddr)
                .ok_or(CoreDumpError::ArithmeticOverflow("region offset"))?;
            let file_position = region
                .file_offset
                .checked_add(offset_in_region)
                .ok_or(CoreDumpError::ArithmeticOverflow("region file position"))?;
            let chunk_len = chunk_end
                .checked_sub(cursor)
                .ok_or(CoreDumpError::ArithmeticOverflow("region chunk length"))?;

            let start = usize::try_from(file_position)
                .map_err(|_| CoreDumpError::IntegerConversion("region file position"))?;
            let count = usize::try_from(chunk_len)
                .map_err(|_| CoreDumpError::IntegerConversion("region chunk length"))?;
            let slice = self
                .bytes
                .get(
                    start
                        ..start
                            .checked_add(count)
                            .ok_or(CoreDumpError::ArithmeticOverflow("region slice end"))?,
                )
                .ok_or(CoreDumpError::UnmappedMemory { addr, len })?;
            out.extend_from_slice(slice);
            cursor = chunk_end;
        }
        Ok(out)
    }
}

/// Whether `addr` lands in the file-backed extent of `region`.
fn region_file_contains(region: &CoreRegion, addr: u64) -> bool {
    let Some(end) = region.vaddr.checked_add(region.file_size) else {
        return false;
    };
    addr >= region.vaddr && addr < end
}

/// A decoded program header (fields normalised to `u64`).
struct ProgramHeader {
    segment_type: u32,
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
}

/// Walk the notes in one `PT_NOTE` segment, capturing the first `NT_PRSTATUS`.
fn walk_notes(
    reader: &CoreReader<'_>,
    segment_offset: u64,
    segment_size: u64,
    notes_walked: &mut u64,
    prstatus_descriptor: &mut Option<Vec<u8>>,
) -> Result<(), CoreDumpError> {
    validate_file_range(
        segment_offset,
        segment_size,
        reader.len_u64()?,
        "PT_NOTE segment",
    )?;
    let segment_start = usize::try_from(segment_offset)
        .map_err(|_| CoreDumpError::IntegerConversion("PT_NOTE offset"))?;
    let segment_len = usize::try_from(segment_size)
        .map_err(|_| CoreDumpError::IntegerConversion("PT_NOTE size"))?;

    let mut cursor = 0usize;
    while cursor + 12 <= segment_len {
        *notes_walked += 1;
        if *notes_walked > MAX_NOTES {
            return Err(CoreDumpError::LimitExceeded {
                kind: "note",
                count: *notes_walked,
                limit: MAX_NOTES,
            });
        }

        let header_offset = segment_start
            .checked_add(cursor)
            .ok_or(CoreDumpError::ArithmeticOverflow("note header offset"))?;
        let namesz = reader.u32(header_offset, "note name size")?;
        let descsz = reader.u32(header_offset + 4, "note descriptor size")?;
        let note_type = reader.u32(header_offset + 8, "note type")?;

        if u64::from(namesz) > MAX_NOTE_NAME_BYTES {
            return Err(CoreDumpError::LimitExceeded {
                kind: "note name",
                count: u64::from(namesz),
                limit: MAX_NOTE_NAME_BYTES,
            });
        }
        if u64::from(descsz) > MAX_NOTE_DESC_BYTES {
            return Err(CoreDumpError::LimitExceeded {
                kind: "note descriptor",
                count: u64::from(descsz),
                limit: MAX_NOTE_DESC_BYTES,
            });
        }

        let name_padded = align4_u64(u64::from(namesz))?;
        let desc_padded = align4_u64(u64::from(descsz))?;
        // 12 (header) + padded name + padded descriptor, all as a usize advance.
        let name_padded = usize::try_from(name_padded)
            .map_err(|_| CoreDumpError::IntegerConversion("note name padding"))?;
        let desc_padded = usize::try_from(desc_padded)
            .map_err(|_| CoreDumpError::IntegerConversion("note descriptor padding"))?;

        let desc_start_rel = cursor
            .checked_add(12)
            .and_then(|value| value.checked_add(name_padded))
            .ok_or(CoreDumpError::ArithmeticOverflow("note descriptor offset"))?;
        let next_rel = desc_start_rel
            .checked_add(desc_padded)
            .ok_or(CoreDumpError::ArithmeticOverflow("note advance"))?;
        if next_rel > segment_len {
            // A trailing partial note; stop walking this segment.
            break;
        }

        if note_type == NT_PRSTATUS && prstatus_descriptor.is_none() {
            let desc_len = usize::try_from(descsz)
                .map_err(|_| CoreDumpError::IntegerConversion("note descriptor size"))?;
            let desc_abs = segment_start.checked_add(desc_start_rel).ok_or(
                CoreDumpError::ArithmeticOverflow("note descriptor absolute offset"),
            )?;
            let descriptor = reader.bytes(desc_abs, desc_len, "NT_PRSTATUS descriptor")?;
            *prstatus_descriptor = Some(descriptor.to_vec());
        }

        cursor = next_rel;
    }
    Ok(())
}

/// Extract the x86-64 register file from an `elf_prstatus` descriptor.
fn parse_prstatus_registers(
    descriptor: &[u8],
    endian: CoreEndian,
) -> Result<Amd64CoreRegisters, CoreDumpError> {
    let reg_end = PRSTATUS_PR_REG_OFFSET
        .checked_add(USER_REGS_BYTES)
        .ok_or(CoreDumpError::ArithmeticOverflow("pr_reg extent"))?;
    if descriptor.len() < reg_end {
        return Err(CoreDumpError::Truncated {
            context: "NT_PRSTATUS pr_reg",
            offset: PRSTATUS_PR_REG_OFFSET,
            needed: USER_REGS_BYTES,
            available: descriptor.len().saturating_sub(PRSTATUS_PR_REG_OFFSET),
        });
    }

    let mut regs = [0u64; USER_REGS_COUNT];
    for (index, slot) in regs.iter_mut().enumerate() {
        let offset = PRSTATUS_PR_REG_OFFSET
            .checked_add(
                index
                    .checked_mul(8)
                    .ok_or(CoreDumpError::ArithmeticOverflow("pr_reg index"))?,
            )
            .ok_or(CoreDumpError::ArithmeticOverflow("pr_reg offset"))?;
        let mut array = [0u8; 8];
        array.copy_from_slice(&descriptor[offset..offset + 8]);
        *slot = match endian {
            CoreEndian::Little => u64::from_le_bytes(array),
            CoreEndian::Big => u64::from_be_bytes(array),
        };
    }

    // user_regs_struct order:
    // r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi,
    // orig_rax, rip, cs, eflags, rsp, ss, fs_base, gs_base, ds, es, fs, gs.
    Ok(Amd64CoreRegisters {
        r15: regs[0],
        r14: regs[1],
        r13: regs[2],
        r12: regs[3],
        rbp: regs[4],
        rbx: regs[5],
        r11: regs[6],
        r10: regs[7],
        r9: regs[8],
        r8: regs[9],
        rax: regs[10],
        rcx: regs[11],
        rdx: regs[12],
        rsi: regs[13],
        rdi: regs[14],
        orig_rax: regs[15],
        rip: regs[16],
        cs: regs[17],
        eflags: regs[18],
        rsp: regs[19],
        ss: regs[20],
        fs_base: regs[21],
        gs_base: regs[22],
        ds: regs[23],
        es: regs[24],
        fs: regs[25],
        gs: regs[26],
    })
}

/// Read `pr_cursig` from an `elf_prstatus` descriptor, defaulting to `SIGSEGV`.
fn parse_prstatus_signal(descriptor: &[u8], endian: CoreEndian) -> u8 {
    let end = PRSTATUS_PR_CURSIG_OFFSET + 2;
    let Some(slice) = descriptor.get(PRSTATUS_PR_CURSIG_OFFSET..end) else {
        return GDB_SIGSEGV;
    };
    let array = [slice[0], slice[1]];
    let raw = match endian {
        CoreEndian::Little => i16::from_le_bytes(array),
        CoreEndian::Big => i16::from_be_bytes(array),
    };
    if raw <= 0 {
        GDB_SIGSEGV
    } else {
        u8::try_from(raw & 0xff).unwrap_or(GDB_SIGSEGV)
    }
}

/// A read-only [`RemoteTarget`] serving a parsed [`CoreDump`] to GDB.
///
/// Register and memory reads answer from the captured snapshot; every mutating
/// or execution operation (`write_registers`, `write_memory`, `cont`, `step`,
/// breakpoints) reports an error, because a core dump is a frozen post-mortem
/// image with nothing to write to and nothing to resume.
#[derive(Debug, Clone)]
pub struct CoreDumpTarget {
    core: CoreDump,
}

impl CoreDumpTarget {
    /// Wrap a parsed [`CoreDump`] as a read-only remote target.
    #[must_use]
    pub const fn new(core: CoreDump) -> Self {
        Self { core }
    }

    /// Borrow the underlying parsed core.
    #[must_use]
    pub const fn core(&self) -> &CoreDump {
        &self.core
    }

    /// The error returned by every mutating operation.
    fn read_only(operation: &str) -> TargetError {
        TargetError::Execution(format!(
            "cannot {operation}: the target is a read-only core dump (post-mortem snapshot)"
        ))
    }
}

impl RemoteTarget for CoreDumpTarget {
    fn read_registers(&mut self) -> Result<Vec<u8>, TargetError> {
        self.core
            .gpacket()
            .map_err(|error| TargetError::Register(error.to_string()))
    }

    fn write_registers(&mut self, _raw: &[u8]) -> Result<(), TargetError> {
        Err(TargetError::Register(
            "cannot write registers: the target is a read-only core dump".to_owned(),
        ))
    }

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, TargetError> {
        self.core
            .read_memory(addr, len)
            .map_err(|error| TargetError::Memory(error.to_string()))
    }

    fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<(), TargetError> {
        Err(TargetError::Memory(
            "cannot write memory: the target is a read-only core dump".to_owned(),
        ))
    }

    fn cont(&mut self) -> Result<StopReply, TargetError> {
        Err(Self::read_only("continue"))
    }

    fn step(&mut self) -> Result<StopReply, TargetError> {
        Err(Self::read_only("single-step"))
    }

    fn set_sw_breakpoint(&mut self, _addr: u64) -> Result<(), TargetError> {
        Err(TargetError::Breakpoint(
            "cannot set a breakpoint: the target is a read-only core dump".to_owned(),
        ))
    }

    fn remove_sw_breakpoint(&mut self, _addr: u64) -> Result<(), TargetError> {
        Err(TargetError::Breakpoint(
            "cannot remove a breakpoint: the target is a read-only core dump".to_owned(),
        ))
    }

    fn stop_reason(&mut self) -> StopReply {
        StopReply::Signal(self.core.signal())
    }
}

/// Round `value` up to the next multiple of four, with overflow checked.
fn align4_u64(value: u64) -> Result<u64, CoreDumpError> {
    let bumped = value
        .checked_add(3)
        .ok_or(CoreDumpError::ArithmeticOverflow("note alignment"))?;
    Ok(bumped & !3)
}

/// Compute the absolute file offset of program-header entry `index`.
fn table_entry_offset(offset: u64, index: u16, entry_size: u16) -> Result<usize, CoreDumpError> {
    let relative = u64::from(index).checked_mul(u64::from(entry_size)).ok_or(
        CoreDumpError::ArithmeticOverflow("program-header entry offset"),
    )?;
    let absolute = offset
        .checked_add(relative)
        .ok_or(CoreDumpError::ArithmeticOverflow(
            "program-header entry offset",
        ))?;
    usize::try_from(absolute).map_err(|_| CoreDumpError::IntegerConversion("program-header offset"))
}

/// Verify `[offset, offset + size)` lies within a `file_size`-byte file.
fn validate_file_range(
    offset: u64,
    size: u64,
    file_size: u64,
    field: &'static str,
) -> Result<(), CoreDumpError> {
    if offset > file_size {
        return Err(CoreDumpError::InvalidField {
            field,
            reason: format!("offset {offset:#x} exceeds file size {file_size:#x}"),
        });
    }
    if size == 0 {
        return Ok(());
    }
    let end = offset
        .checked_add(size)
        .ok_or(CoreDumpError::ArithmeticOverflow("file range"))?;
    if end > file_size {
        return Err(CoreDumpError::InvalidField {
            field,
            reason: format!("range {offset:#x}..{end:#x} exceeds file size {file_size:#x}"),
        });
    }
    Ok(())
}

/// Enforce a structural count ceiling.
fn enforce_count(kind: &'static str, count: u64, limit: u64) -> Result<(), CoreDumpError> {
    if count > limit {
        Err(CoreDumpError::LimitExceeded { kind, count, limit })
    } else {
        Ok(())
    }
}

/// An endian- and width-aware reader over a bounded core buffer.
struct CoreReader<'bytes> {
    bytes: &'bytes [u8],
    class: CoreClass,
    endian: CoreEndian,
}

impl<'bytes> CoreReader<'bytes> {
    fn len_u64(&self) -> Result<u64, CoreDumpError> {
        u64::try_from(self.bytes.len())
            .map_err(|_| CoreDumpError::IntegerConversion("core input size"))
    }

    fn require(
        &self,
        offset: usize,
        needed: usize,
        context: &'static str,
    ) -> Result<(), CoreDumpError> {
        let end = offset
            .checked_add(needed)
            .ok_or(CoreDumpError::ArithmeticOverflow("read range"))?;
        if end > self.bytes.len() {
            return Err(CoreDumpError::Truncated {
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
    ) -> Result<&'bytes [u8], CoreDumpError> {
        self.require(offset, size, context)?;
        Ok(&self.bytes[offset..offset + size])
    }

    fn u16(&self, offset: usize, context: &'static str) -> Result<u16, CoreDumpError> {
        let bytes = self.bytes(offset, 2, context)?;
        let array = [bytes[0], bytes[1]];
        Ok(match self.endian {
            CoreEndian::Little => u16::from_le_bytes(array),
            CoreEndian::Big => u16::from_be_bytes(array),
        })
    }

    fn u32(&self, offset: usize, context: &'static str) -> Result<u32, CoreDumpError> {
        let bytes = self.bytes(offset, 4, context)?;
        let array = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(match self.endian {
            CoreEndian::Little => u32::from_le_bytes(array),
            CoreEndian::Big => u32::from_be_bytes(array),
        })
    }

    fn u64(&self, offset: usize, context: &'static str) -> Result<u64, CoreDumpError> {
        let bytes = self.bytes(offset, 8, context)?;
        let array = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];
        Ok(match self.endian {
            CoreEndian::Little => u64::from_le_bytes(array),
            CoreEndian::Big => u64::from_be_bytes(array),
        })
    }

    /// Decode the program header at absolute file offset `entry_offset`.
    fn program_header(&self, entry_offset: usize) -> Result<ProgramHeader, CoreDumpError> {
        if self.class.is_64() {
            Ok(ProgramHeader {
                segment_type: self.u32(entry_offset, "PT segment type")?,
                flags: self.u32(entry_offset + 4, "PT segment flags")?,
                file_offset: self.u64(entry_offset + 8, "PT segment file offset")?,
                virtual_address: self.u64(entry_offset + 16, "PT segment virtual address")?,
                file_size: self.u64(entry_offset + 32, "PT segment file size")?,
                memory_size: self.u64(entry_offset + 40, "PT segment memory size")?,
            })
        } else {
            Ok(ProgramHeader {
                segment_type: self.u32(entry_offset, "PT segment type")?,
                file_offset: u64::from(self.u32(entry_offset + 4, "PT segment file offset")?),
                virtual_address: u64::from(
                    self.u32(entry_offset + 8, "PT segment virtual address")?,
                ),
                file_size: u64::from(self.u32(entry_offset + 16, "PT segment file size")?),
                memory_size: u64::from(self.u32(entry_offset + 20, "PT segment memory size")?),
                flags: self.u32(entry_offset + 24, "PT segment flags")?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known register values baked into the test core.
    const TEST_RIP: u64 = 0x0000_0000_0040_11a0;
    const TEST_RAX: u64 = 0x1122_3344_5566_7788;
    const TEST_RSP: u64 = 0x0000_7fff_ffff_e100;
    // The loadable region and its bytes.
    const TEST_LOAD_VADDR: u64 = 0x0040_0000;
    const TEST_LOAD_BYTES: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
    const TEST_SIGNAL: u8 = 11;

    /// Set the `user_regs_struct` register at zero-based `index` in a descriptor.
    fn set_reg(descriptor: &mut [u8], index: usize, value: u64) {
        let offset = PRSTATUS_PR_REG_OFFSET + index * 8;
        descriptor[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Build one `NT_PRSTATUS` note (header + name + descriptor).
    fn build_prstatus_note() -> Vec<u8> {
        let mut descriptor = vec![0u8; 336];
        descriptor[PRSTATUS_PR_CURSIG_OFFSET..PRSTATUS_PR_CURSIG_OFFSET + 2]
            .copy_from_slice(&i16::from(TEST_SIGNAL).to_le_bytes());
        // user_regs_struct indices: rax=10, rip=16, rsp=19.
        set_reg(&mut descriptor, 10, TEST_RAX);
        set_reg(&mut descriptor, 16, TEST_RIP);
        set_reg(&mut descriptor, 19, TEST_RSP);

        let name = b"CORE\0";
        let mut note = Vec::new();
        note.extend_from_slice(&(name.len() as u32).to_le_bytes());
        note.extend_from_slice(&(descriptor.len() as u32).to_le_bytes());
        note.extend_from_slice(&NT_PRSTATUS.to_le_bytes());
        note.extend_from_slice(name);
        // Pad the 5-byte name to a 4-byte boundary (to 8 bytes).
        note.extend_from_slice(&[0, 0, 0]);
        note.extend_from_slice(&descriptor);
        // The 336-byte descriptor is already 4-byte aligned.
        note
    }

    /// Assemble a minimal ELF64-LE core: one `PT_NOTE`, one `PT_LOAD`.
    fn build_core() -> Vec<u8> {
        let note_segment = build_prstatus_note();
        let phnum: u16 = 2;
        let phentsize = ELF64_PROGRAM_HEADER_SIZE;
        let phoff = ELF64_HEADER_SIZE as u64;
        let note_offset = phoff + u64::from(phnum) * u64::from(phentsize);
        let note_size = note_segment.len() as u64;
        let load_offset = note_offset + note_size;
        let load_size = TEST_LOAD_BYTES.len() as u64;

        let mut core = Vec::new();
        // --- ELF header (64 bytes) ---
        core.extend_from_slice(b"\x7fELF");
        core.push(ELF_CLASS_64);
        core.push(ELF_DATA_LITTLE_ENDIAN);
        core.push(1); // EI_VERSION
        core.extend_from_slice(&[0u8; 9]); // EI_OSABI..EI_PAD
        core.extend_from_slice(&ELF_TYPE_CORE.to_le_bytes()); // e_type
        core.extend_from_slice(&EM_X86_64.to_le_bytes()); // e_machine
        core.extend_from_slice(&1u32.to_le_bytes()); // e_version
        core.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        core.extend_from_slice(&phoff.to_le_bytes()); // e_phoff
        core.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        core.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        core.extend_from_slice(&(ELF64_HEADER_SIZE as u16).to_le_bytes()); // e_ehsize
        core.extend_from_slice(&phentsize.to_le_bytes()); // e_phentsize
        core.extend_from_slice(&phnum.to_le_bytes()); // e_phnum
        core.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        core.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        core.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(core.len(), ELF64_HEADER_SIZE);

        // --- PT_NOTE program header ---
        push_phdr64(&mut core, PT_NOTE, 0, note_offset, 0, note_size, note_size);
        // --- PT_LOAD program header ---
        push_phdr64(
            &mut core,
            PT_LOAD,
            0x5, // R + X
            load_offset,
            TEST_LOAD_VADDR,
            load_size,
            load_size,
        );
        assert_eq!(core.len() as u64, note_offset);

        core.extend_from_slice(&note_segment);
        assert_eq!(core.len() as u64, load_offset);
        core.extend_from_slice(&TEST_LOAD_BYTES);
        core
    }

    fn push_phdr64(
        core: &mut Vec<u8>,
        p_type: u32,
        p_flags: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
    ) {
        core.extend_from_slice(&p_type.to_le_bytes());
        core.extend_from_slice(&p_flags.to_le_bytes());
        core.extend_from_slice(&p_offset.to_le_bytes());
        core.extend_from_slice(&p_vaddr.to_le_bytes());
        core.extend_from_slice(&p_vaddr.to_le_bytes()); // p_paddr
        core.extend_from_slice(&p_filesz.to_le_bytes());
        core.extend_from_slice(&p_memsz.to_le_bytes());
        core.extend_from_slice(&0u64.to_le_bytes()); // p_align
    }

    #[test]
    fn parses_registers_from_prstatus() {
        let core = CoreDump::parse(&build_core()).expect("core parses");
        let registers = core.registers().expect("x86-64 registers recovered");
        assert_eq!(registers.rip, TEST_RIP);
        assert_eq!(registers.rax, TEST_RAX);
        assert_eq!(registers.rsp, TEST_RSP);
        assert_eq!(core.signal(), TEST_SIGNAL);
    }

    #[test]
    fn gpacket_places_registers_at_the_right_offsets() {
        let core = CoreDump::parse(&build_core()).expect("core parses");
        let packet = core.gpacket().expect("g-packet built");
        assert_eq!(packet.len(), crate::AMD64_GPACKET_BYTES);
        // rax is g-packet register 0 (bytes 0..8).
        assert_eq!(&packet[0..8], &TEST_RAX.to_le_bytes());
        // rsp is g-packet register 7 (bytes 56..64).
        assert_eq!(&packet[56..64], &TEST_RSP.to_le_bytes());
        // rip is g-packet register 16 (bytes 128..136).
        assert_eq!(&packet[128..136], &TEST_RIP.to_le_bytes());
    }

    #[test]
    fn reads_file_backed_memory() {
        let core = CoreDump::parse(&build_core()).expect("core parses");
        let bytes = core
            .read_memory(TEST_LOAD_VADDR, TEST_LOAD_BYTES.len())
            .expect("mapped memory reads");
        assert_eq!(bytes, TEST_LOAD_BYTES);
        // A sub-range from the middle also works.
        let middle = core.read_memory(TEST_LOAD_VADDR + 2, 3).expect("sub-range");
        assert_eq!(middle, &TEST_LOAD_BYTES[2..5]);
    }

    #[test]
    fn unmapped_reads_fail_closed() {
        let core = CoreDump::parse(&build_core()).expect("core parses");
        // Entirely outside any mapping.
        assert!(matches!(
            core.read_memory(0x1_0000_0000, 4),
            Err(CoreDumpError::UnmappedMemory { .. })
        ));
        // Straddling the end of the file-backed region.
        assert!(matches!(
            core.read_memory(TEST_LOAD_VADDR + 6, 8),
            Err(CoreDumpError::UnmappedMemory { .. })
        ));
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        assert!(matches!(
            CoreDump::parse(b"not an elf file at all"),
            Err(CoreDumpError::BadMagic)
        ));
        assert!(matches!(
            CoreDump::parse(&[0x7f, b'E', b'L']),
            Err(CoreDumpError::Truncated { .. })
        ));
        // A valid header truncated before the program-header table.
        let mut truncated = build_core();
        truncated.truncate(ELF64_HEADER_SIZE + 4);
        assert!(CoreDump::parse(&truncated).is_err());
    }

    #[test]
    fn rejects_non_core_type() {
        let mut bytes = build_core();
        // Overwrite e_type (offset 16) with ET_EXEC (2).
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            CoreDump::parse(&bytes),
            Err(CoreDumpError::NotCore(2))
        ));
    }

    #[test]
    fn target_serves_reads_and_rejects_writes() {
        let core = CoreDump::parse(&build_core()).expect("core parses");
        let mut target = CoreDumpTarget::new(core);

        let packet = target.read_registers().expect("registers read");
        assert_eq!(&packet[128..136], &TEST_RIP.to_le_bytes());

        let memory = target
            .read_memory(TEST_LOAD_VADDR, TEST_LOAD_BYTES.len())
            .expect("memory read");
        assert_eq!(memory, TEST_LOAD_BYTES);

        assert_eq!(target.stop_reason(), StopReply::Signal(TEST_SIGNAL));

        assert!(target.write_registers(&packet).is_err());
        assert!(target.write_memory(TEST_LOAD_VADDR, &[0u8]).is_err());
        assert!(target.cont().is_err());
        assert!(target.step().is_err());
        assert!(target.set_sw_breakpoint(TEST_LOAD_VADDR).is_err());
        assert!(target.remove_sw_breakpoint(TEST_LOAD_VADDR).is_err());
    }

    #[test]
    fn non_x86_64_core_parses_without_registers() {
        let mut bytes = build_core();
        // Overwrite e_machine (offset 18) with EM_AARCH64 (183).
        bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
        let core = CoreDump::parse(&bytes).expect("container still parses");
        assert!(core.registers().is_none());
        // Memory is still readable.
        let memory = core
            .read_memory(TEST_LOAD_VADDR, TEST_LOAD_BYTES.len())
            .expect("memory read");
        assert_eq!(memory, TEST_LOAD_BYTES);
        // g-packet reports the unsupported machine.
        assert!(matches!(
            core.gpacket(),
            Err(CoreDumpError::UnsupportedMachine(183))
        ));
    }

    #[test]
    fn loopback_serves_core_to_client() {
        use crate::client::GdbRemoteClient;
        use crate::server::GdbStubServer;
        use crate::transport::memory_pair;

        let core = CoreDump::parse(&build_core()).expect("core parses");
        let mut target = CoreDumpTarget::new(core);
        let (server_side, client_side) = memory_pair();

        let server = std::thread::spawn(move || {
            let mut server = GdbStubServer::new(server_side);
            let _ = server.serve(&mut target);
        });

        let mut client = GdbRemoteClient::new(client_side);
        let registers = client.read_registers().expect("client reads registers");
        assert_eq!(&registers[128..136], &TEST_RIP.to_le_bytes());
        let memory = client
            .read_memory(TEST_LOAD_VADDR, TEST_LOAD_BYTES.len())
            .expect("client reads memory");
        assert_eq!(memory, TEST_LOAD_BYTES);

        // Dropping the client closes its transport, which signals EOF to the
        // server loop so it returns cleanly.
        drop(client);
        server.join().expect("server thread joins");
    }
}
