//! The backend contract the RSP server drives, plus the amd64 `g`-packet
//! register layout.
//!
//! [`RemoteTarget`] is the narrow surface [`crate::server`] needs: register and
//! memory access, execution control, and software breakpoints. It is
//! deliberately free of any dependency on the ptrace host — the ptrace adapter
//! lives in [`crate::ptrace_target`] and maps its own register type onto the
//! dependency-free [`Amd64CoreRegisters`] defined here.

use thiserror::Error;

/// Why a [`RemoteTarget`] resumed the debugger.
///
/// Signal numbers follow the GDB convention (the target-independent values GDB
/// uses on the wire); `5` is `SIGTRAP`, reported for breakpoint and step stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReply {
    /// The target stopped in a signal-`u8` stop (e.g. `5` for a trap).
    Signal(u8),
    /// The target exited normally with this status code.
    Exited(u8),
    /// The target was terminated by this signal.
    Terminated(u8),
}

/// The access condition of a hardware watchpoint, as distinguished by the RSP
/// `Z2`/`Z3`/`Z4` packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchKind {
    /// A write watchpoint (`Z2`).
    Write,
    /// A read watchpoint (`Z3`). x86-64 has no read-only debug condition, so an
    /// adapter maps this to a read/write condition.
    Read,
    /// An access (read or write) watchpoint (`Z4`).
    Access,
}

/// A fault raised while driving a [`RemoteTarget`].
#[derive(Debug, Error)]
pub enum TargetError {
    /// A memory read or write failed.
    #[error("target memory access failed: {0}")]
    Memory(String),
    /// A register read or write failed.
    #[error("target register access failed: {0}")]
    Register(String),
    /// Resuming or single-stepping the target failed.
    #[error("target execution control failed: {0}")]
    Execution(String),
    /// A breakpoint could not be set or removed.
    #[error("target breakpoint operation failed: {0}")]
    Breakpoint(String),
    /// A supplied register buffer was not a valid amd64 `g`-packet.
    #[error("malformed g-packet: {0}")]
    Registers(String),
    /// The target is gone and can no longer be driven.
    #[error("the target is no longer available")]
    Unavailable,
    /// The target does not support the requested operation.
    #[error("operation not supported by this target: {0}")]
    Unsupported(String),
}

impl TargetError {
    /// Build an [`TargetError::Unsupported`] describing an unsupported `what`.
    #[must_use]
    pub fn unsupported(what: &str) -> Self {
        Self::Unsupported(format!("{what} is not supported by this target"))
    }
}

/// The backend the RSP server serves.
///
/// Register buffers are raw amd64 `g`-packet bytes (see
/// [`Amd64CoreRegisters::to_gpacket`]); the server hex-encodes them for the
/// wire. Addresses are absolute target virtual addresses.
pub trait RemoteTarget {
    /// Read the full register file as raw `g`-packet bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Register`] if the read fails.
    fn read_registers(&mut self) -> Result<Vec<u8>, TargetError>;

    /// Write the full register file from raw `g`-packet bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Register`] or [`TargetError::Registers`].
    fn write_registers(&mut self, raw: &[u8]) -> Result<(), TargetError>;

    /// Read `len` bytes starting at `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Memory`] if the read fails.
    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, TargetError>;

    /// Write `data` starting at `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Memory`] if the write fails.
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), TargetError>;

    /// Resume the target until it next stops.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Execution`] if resuming fails.
    fn cont(&mut self) -> Result<StopReply, TargetError>;

    /// Single-step one instruction.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Execution`] if stepping fails.
    fn step(&mut self) -> Result<StopReply, TargetError>;

    /// Arm a software breakpoint at `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Breakpoint`] if the breakpoint cannot be set.
    fn set_sw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError>;

    /// Remove the software breakpoint at `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Breakpoint`] if the breakpoint cannot be removed.
    fn remove_sw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError>;

    /// Arm a hardware execute breakpoint at `addr` (RSP `Z1`).
    ///
    /// The default implementation reports the operation as unsupported, so a
    /// read-only or mock target need not override it.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unsupported`] by default, or
    /// [`TargetError::Breakpoint`] from an implementor.
    fn set_hw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError> {
        let _ = addr;
        Err(TargetError::unsupported("hardware breakpoints"))
    }

    /// Remove the hardware execute breakpoint at `addr` (RSP `z1`).
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unsupported`] by default, or
    /// [`TargetError::Breakpoint`] from an implementor.
    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError> {
        let _ = addr;
        Err(TargetError::unsupported("hardware breakpoints"))
    }

    /// Arm a hardware watchpoint of `len` bytes at `addr` (RSP `Z2`/`Z3`/`Z4`).
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unsupported`] by default, or
    /// [`TargetError::Breakpoint`] from an implementor.
    fn set_watchpoint(&mut self, addr: u64, len: u64, kind: WatchKind) -> Result<(), TargetError> {
        let _ = (addr, len, kind);
        Err(TargetError::unsupported("hardware watchpoints"))
    }

    /// Remove the hardware watchpoint of `len` bytes at `addr` (RSP
    /// `z2`/`z3`/`z4`).
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unsupported`] by default, or
    /// [`TargetError::Breakpoint`] from an implementor.
    fn remove_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> Result<(), TargetError> {
        let _ = (addr, len, kind);
        Err(TargetError::unsupported("hardware watchpoints"))
    }

    /// The most recent stop reason, without resuming the target.
    fn stop_reason(&mut self) -> StopReply;
}

/// The total size of an amd64 `g`-packet: 17 eight-byte registers plus seven
/// four-byte registers (`eflags` and the six segment selectors).
pub const AMD64_GPACKET_BYTES: usize = 17 * 8 + 7 * 4;

/// A dependency-free amd64 register snapshot.
///
/// Field names and count mirror the ptrace host's register type so the adapter
/// can copy one-to-one, but this struct carries no dependency on it. Only the
/// fields present in the amd64 `g`-packet participate in the wire conversions;
/// the remainder (`orig_rax`, `fs_base`, `gs_base`) are preserved across a
/// read-modify-write so a `G` packet from GDB never clobbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Amd64CoreRegisters {
    /// `r15`.
    pub r15: u64,
    /// `r14`.
    pub r14: u64,
    /// `r13`.
    pub r13: u64,
    /// `r12`.
    pub r12: u64,
    /// `rbp`.
    pub rbp: u64,
    /// `rbx`.
    pub rbx: u64,
    /// `r11`.
    pub r11: u64,
    /// `r10`.
    pub r10: u64,
    /// `r9`.
    pub r9: u64,
    /// `r8`.
    pub r8: u64,
    /// `rax`.
    pub rax: u64,
    /// `rcx`.
    pub rcx: u64,
    /// `rdx`.
    pub rdx: u64,
    /// `rsi`.
    pub rsi: u64,
    /// `rdi`.
    pub rdi: u64,
    /// `orig_rax` (not part of the `g`-packet; preserved verbatim).
    pub orig_rax: u64,
    /// `rip`.
    pub rip: u64,
    /// `cs`.
    pub cs: u64,
    /// `eflags`.
    pub eflags: u64,
    /// `rsp`.
    pub rsp: u64,
    /// `ss`.
    pub ss: u64,
    /// `fs_base` (not part of the `g`-packet; preserved verbatim).
    pub fs_base: u64,
    /// `gs_base` (not part of the `g`-packet; preserved verbatim).
    pub gs_base: u64,
    /// `ds`.
    pub ds: u64,
    /// `es`.
    pub es: u64,
    /// `fs`.
    pub fs: u64,
    /// `gs`.
    pub gs: u64,
}

impl Amd64CoreRegisters {
    /// Serialise to the raw amd64 `g`-packet byte layout.
    ///
    /// Order (each little-endian): `rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp,
    /// r8..r15, rip` as 8 bytes each, then `eflags` as 4 bytes, then `cs, ss,
    /// ds, es, fs, gs` as 4 bytes each. Total [`AMD64_GPACKET_BYTES`] bytes.
    #[must_use]
    pub fn to_gpacket(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AMD64_GPACKET_BYTES);
        for reg in [
            self.rax, self.rbx, self.rcx, self.rdx, self.rsi, self.rdi, self.rbp, self.rsp,
            self.r8, self.r9, self.r10, self.r11, self.r12, self.r13, self.r14, self.r15, self.rip,
        ] {
            out.extend_from_slice(&reg.to_le_bytes());
        }
        for reg in [
            self.eflags,
            self.cs,
            self.ss,
            self.ds,
            self.es,
            self.fs,
            self.gs,
        ] {
            out.extend_from_slice(&low_u32_le(reg));
        }
        debug_assert_eq!(out.len(), AMD64_GPACKET_BYTES);
        out
    }

    /// Overlay the `g`-packet fields from `raw` onto `self`, leaving the fields
    /// absent from the packet (`orig_rax`, `fs_base`, `gs_base`) untouched.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Registers`] if `raw` is shorter than a full
    /// `g`-packet.
    pub fn apply_gpacket(&mut self, raw: &[u8]) -> Result<(), TargetError> {
        if raw.len() < AMD64_GPACKET_BYTES {
            return Err(TargetError::Registers(format!(
                "expected at least {AMD64_GPACKET_BYTES} bytes, got {}",
                raw.len()
            )));
        }
        let mut cursor = GpacketCursor::new(raw);
        self.rax = cursor.next_u64();
        self.rbx = cursor.next_u64();
        self.rcx = cursor.next_u64();
        self.rdx = cursor.next_u64();
        self.rsi = cursor.next_u64();
        self.rdi = cursor.next_u64();
        self.rbp = cursor.next_u64();
        self.rsp = cursor.next_u64();
        self.r8 = cursor.next_u64();
        self.r9 = cursor.next_u64();
        self.r10 = cursor.next_u64();
        self.r11 = cursor.next_u64();
        self.r12 = cursor.next_u64();
        self.r13 = cursor.next_u64();
        self.r14 = cursor.next_u64();
        self.r15 = cursor.next_u64();
        self.rip = cursor.next_u64();
        self.eflags = cursor.next_u32();
        self.cs = cursor.next_u32();
        self.ss = cursor.next_u32();
        self.ds = cursor.next_u32();
        self.es = cursor.next_u32();
        self.fs = cursor.next_u32();
        self.gs = cursor.next_u32();
        Ok(())
    }
}

/// Serialise `registers` to the amd64 `g`-packet layout.
#[must_use]
pub fn amd64_registers_to_gpacket(registers: &Amd64CoreRegisters) -> Vec<u8> {
    registers.to_gpacket()
}

/// Parse a full amd64 `g`-packet into a fresh register snapshot.
///
/// Fields absent from the packet (`orig_rax`, `fs_base`, `gs_base`) are left at
/// their `Default` (zero) value; callers that must preserve them should use
/// [`Amd64CoreRegisters::apply_gpacket`] on a previously read snapshot instead.
///
/// # Errors
///
/// Returns [`TargetError::Registers`] if `raw` is too short.
pub fn amd64_gpacket_to_registers(raw: &[u8]) -> Result<Amd64CoreRegisters, TargetError> {
    let mut registers = Amd64CoreRegisters::default();
    registers.apply_gpacket(raw)?;
    Ok(registers)
}

/// A little-endian reader over a `g`-packet buffer known to be long enough.
struct GpacketCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> GpacketCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[self.offset..self.offset + 8]);
        self.offset += 8;
        u64::from_le_bytes(bytes)
    }

    fn next_u32(&mut self) -> u64 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.data[self.offset..self.offset + 4]);
        self.offset += 4;
        u64::from(u32::from_le_bytes(bytes))
    }
}

/// The low 32 bits of `value` as little-endian bytes.
fn low_u32_le(value: u64) -> [u8; 4] {
    let truncated = (value & 0xffff_ffff) as u32;
    truncated.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Amd64CoreRegisters {
        Amd64CoreRegisters {
            rax: 0x1111_1111_1111_1111,
            rbx: 0x2222_2222_2222_2222,
            rip: 0x0000_0000_0040_1000,
            rsp: 0x0000_7fff_ffff_e000,
            eflags: 0x0000_0202,
            cs: 0x33,
            ss: 0x2b,
            orig_rax: 0xdead,
            fs_base: 0xbeef,
            gs_base: 0xcafe,
            ..Amd64CoreRegisters::default()
        }
    }

    #[test]
    fn gpacket_is_exactly_164_bytes() {
        assert_eq!(AMD64_GPACKET_BYTES, 164);
        assert_eq!(sample().to_gpacket().len(), 164);
    }

    #[test]
    fn gpacket_field_offsets_are_correct() {
        let packet = sample().to_gpacket();
        // rax is the first 8 bytes.
        assert_eq!(&packet[0..8], &0x1111_1111_1111_1111u64.to_le_bytes());
        // rbx is the second 8 bytes.
        assert_eq!(&packet[8..16], &0x2222_2222_2222_2222u64.to_le_bytes());
        // rip is register index 16 (bytes 128..136).
        assert_eq!(&packet[128..136], &0x0040_1000u64.to_le_bytes());
        // eflags is the first 4-byte field after the 17 u64s (bytes 136..140).
        assert_eq!(&packet[136..140], &0x0000_0202u32.to_le_bytes());
        // cs follows eflags (bytes 140..144).
        assert_eq!(&packet[140..144], &0x33u32.to_le_bytes());
    }

    #[test]
    fn round_trips_g_packet_fields() {
        let original = sample();
        let packet = amd64_registers_to_gpacket(&original);
        let parsed = amd64_gpacket_to_registers(&packet).unwrap();
        // The g-packet fields survive; the excluded fields default to zero.
        assert_eq!(parsed.rax, original.rax);
        assert_eq!(parsed.rip, original.rip);
        assert_eq!(parsed.eflags, original.eflags);
        assert_eq!(parsed.cs, original.cs);
        assert_eq!(parsed.orig_rax, 0);
    }

    #[test]
    fn apply_gpacket_preserves_excluded_fields() {
        let mut current = sample();
        let mut incoming = sample();
        incoming.rax = 0x9999;
        let packet = incoming.to_gpacket();
        current.apply_gpacket(&packet).unwrap();
        assert_eq!(current.rax, 0x9999);
        // orig_rax / fs_base / gs_base are not in the packet and are preserved.
        assert_eq!(current.orig_rax, 0xdead);
        assert_eq!(current.fs_base, 0xbeef);
        assert_eq!(current.gs_base, 0xcafe);
    }

    #[test]
    fn short_g_packet_is_rejected() {
        let mut registers = Amd64CoreRegisters::default();
        assert!(matches!(
            registers.apply_gpacket(&[0u8; 10]),
            Err(TargetError::Registers(_))
        ));
    }
}
