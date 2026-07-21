//! Architecture metadata and register-file layouts used by RSP targets.
//!
//! The wire-level server is intentionally architecture-neutral.  A backend
//! supplies one of these descriptions and raw `g`-packet bytes in the exact
//! order declared by its XML.  This module retains the historical amd64
//! layout while adding an explicit, lossless PlayStation 2 EE/R5900 layout.

use crate::target::TargetError;

/// Byte order used to encode multi-byte registers in a raw `g` packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetByteOrder {
    /// Least-significant byte first.
    Little,
    /// Most-significant byte first.
    Big,
}

/// Static metadata for one architecture-specific RSP register file.
///
/// The XML is the `target.xml` annex served through
/// `qXfer:features:read`. `register_packet_bytes` is the exact decoded size of
/// `g`/`G`, and `software_breakpoint_kind` is the architecture-specific third
/// field of `Z0`/`z0` (one byte on amd64, one four-byte instruction on EE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetDescription<'a> {
    /// Stable human-readable target name.
    pub name: &'a str,
    /// GDB architecture spelling used by `<architecture>`.
    pub architecture: &'a str,
    /// Target byte order.
    pub byte_order: TargetByteOrder,
    /// Complete `target.xml` document.
    pub xml: &'a str,
    /// Exact decoded byte length of the `g`/`G` register packet.
    pub register_packet_bytes: usize,
    /// Required RSP software-breakpoint kind.
    pub software_breakpoint_kind: u64,
}

/// The amd64 target description matching [`crate::Amd64CoreRegisters`].
pub const AMD64_TARGET_DESCRIPTION: TargetDescription<'static> = TargetDescription {
    name: "AMD64",
    architecture: "i386:x86-64",
    byte_order: TargetByteOrder::Little,
    xml: AMD64_TARGET_XML,
    register_packet_bytes: crate::target::AMD64_GPACKET_BYTES,
    software_breakpoint_kind: 1,
};

/// A compact amd64 target description in the same order as the legacy
/// ReSymbol `g`-packet helpers.
pub const AMD64_TARGET_XML: &str = r#"<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386:x86-64</architecture>
  <feature name="org.gnu.gdb.i386.core">
    <reg name="rax" bitsize="64" regnum="0" type="uint64" group="general"/>
    <reg name="rbx" bitsize="64" regnum="1" type="uint64" group="general"/>
    <reg name="rcx" bitsize="64" regnum="2" type="uint64" group="general"/>
    <reg name="rdx" bitsize="64" regnum="3" type="uint64" group="general"/>
    <reg name="rsi" bitsize="64" regnum="4" type="uint64" group="general"/>
    <reg name="rdi" bitsize="64" regnum="5" type="uint64" group="general"/>
    <reg name="rbp" bitsize="64" regnum="6" type="data_ptr" group="general"/>
    <reg name="rsp" bitsize="64" regnum="7" type="data_ptr" group="general"/>
    <reg name="r8" bitsize="64" regnum="8" type="uint64" group="general"/>
    <reg name="r9" bitsize="64" regnum="9" type="uint64" group="general"/>
    <reg name="r10" bitsize="64" regnum="10" type="uint64" group="general"/>
    <reg name="r11" bitsize="64" regnum="11" type="uint64" group="general"/>
    <reg name="r12" bitsize="64" regnum="12" type="uint64" group="general"/>
    <reg name="r13" bitsize="64" regnum="13" type="uint64" group="general"/>
    <reg name="r14" bitsize="64" regnum="14" type="uint64" group="general"/>
    <reg name="r15" bitsize="64" regnum="15" type="uint64" group="general"/>
    <reg name="rip" bitsize="64" regnum="16" type="code_ptr" group="general"/>
    <reg name="eflags" bitsize="32" regnum="17" type="uint32" group="general"/>
    <reg name="cs" bitsize="32" regnum="18" type="uint32" group="general"/>
    <reg name="ss" bitsize="32" regnum="19" type="uint32" group="general"/>
    <reg name="ds" bitsize="32" regnum="20" type="uint32" group="general"/>
    <reg name="es" bitsize="32" regnum="21" type="uint32" group="general"/>
    <reg name="fs" bitsize="32" regnum="22" type="uint32" group="general"/>
    <reg name="gs" bitsize="32" regnum="23" type="uint32" group="general"/>
  </feature>
</target>
"#;

/// Exact byte length of the lossless PS2 EE/R5900 `g` packet.
///
/// Standard GDB MIPS core registers expose the scalar low 64-bit view.  The
/// custom `org.openomega.ps2.ee` feature carries every corresponding upper
/// half, so no 128-bit GPR, HI, or LO state is silently discarded.
pub const PS2_EE_GPACKET_BYTES: usize = 708;

/// The PS2 EE/R5900 target description used by PCSX2/OpenOmega adapters.
pub const PS2_EE_TARGET_DESCRIPTION: TargetDescription<'static> = TargetDescription {
    name: "PlayStation 2 Emotion Engine R5900",
    architecture: "mips:5900",
    byte_order: TargetByteOrder::Little,
    xml: PS2_EE_TARGET_XML,
    register_packet_bytes: PS2_EE_GPACKET_BYTES,
    software_breakpoint_kind: 4,
};

/// Lossless EE/R5900 register description.
///
/// GDB's standard MIPS feature accepts 32- or 64-bit `r0..r31`, `lo`, and
/// `hi`, not the EE's physical 128-bit registers.  The standard feature below
/// therefore carries each low 64-bit scalar half and `org.openomega.ps2.ee`
/// carries the matching upper 64-bit half.  Concatenating each `_upper` value
/// above its standard register reconstructs the exact 128-bit PCSX2 state.
pub const PS2_EE_TARGET_XML: &str = include_str!("ps2_ee_target.xml");

/// A complete, lossless PS2 Emotion Engine register snapshot.
///
/// Multi-byte values are encoded little-endian.  The `gpr`, `lo`, and `hi`
/// fields retain all 128 bits used by PCSX2's `GPR_reg`; conversion never
/// narrows them to the standard MIPS scalar view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ps2EeCoreRegisters {
    /// General-purpose registers `r0..r31`.
    pub gpr: [u128; 32],
    /// 128-bit multiply/divide LO state.
    pub lo: u128,
    /// 128-bit multiply/divide HI state.
    pub hi: u128,
    /// Program counter.
    pub pc: u32,
    /// CP0 Status.
    pub status: u32,
    /// CP0 BadVAddr.
    pub badvaddr: u32,
    /// CP0 Cause.
    pub cause: u32,
    /// CP0 EPC.
    pub epc: u32,
    /// Floating-point registers `f0..f31`, preserved as raw bits.
    pub fpr: [u32; 32],
    /// Floating-point control/status register (`fprc[31]` in PCSX2).
    pub fcsr: u32,
    /// Floating-point implementation/revision register (`fprc[0]` in PCSX2).
    pub fir: u32,
    /// MMI shift amount register.
    pub sa: u32,
    /// Floating-point accumulator, preserved as raw bits.
    pub fpu_acc: u32,
}

impl Ps2EeCoreRegisters {
    /// Serialise this snapshot to the exact layout declared by
    /// [`PS2_EE_TARGET_XML`].
    #[must_use]
    pub fn to_gpacket(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PS2_EE_GPACKET_BYTES);

        // Standard MIPS scalar view: low halves first.
        for value in self.gpr {
            out.extend_from_slice(&(value as u64).to_le_bytes());
        }
        // Preserve the established GDB MIPS packet order by increasing
        // register number: status precedes LO/HI, followed by exception state
        // and PC.
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&(self.lo as u64).to_le_bytes());
        out.extend_from_slice(&(self.hi as u64).to_le_bytes());
        out.extend_from_slice(&self.badvaddr.to_le_bytes());
        out.extend_from_slice(&self.cause.to_le_bytes());
        out.extend_from_slice(&self.pc.to_le_bytes());
        for value in self.fpr {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&self.fcsr.to_le_bytes());
        out.extend_from_slice(&self.fir.to_le_bytes());
        out.extend_from_slice(&self.epc.to_le_bytes());

        // EE extension: matching upper halves make every 128-bit value exact.
        for value in self.gpr {
            out.extend_from_slice(&((value >> 64) as u64).to_le_bytes());
        }
        out.extend_from_slice(&((self.lo >> 64) as u64).to_le_bytes());
        out.extend_from_slice(&((self.hi >> 64) as u64).to_le_bytes());
        out.extend_from_slice(&self.sa.to_le_bytes());
        out.extend_from_slice(&self.fpu_acc.to_le_bytes());

        debug_assert_eq!(out.len(), PS2_EE_GPACKET_BYTES);
        out
    }

    /// Replace this snapshot from one exact EE `g` packet.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Registers`] unless `raw` is exactly
    /// [`PS2_EE_GPACKET_BYTES`] bytes.  Exact sizing prevents callers from
    /// accidentally accepting a standard MIPS packet that omitted upper state.
    pub fn apply_gpacket(&mut self, raw: &[u8]) -> Result<(), TargetError> {
        if raw.len() != PS2_EE_GPACKET_BYTES {
            return Err(TargetError::Registers(format!(
                "expected exactly {PS2_EE_GPACKET_BYTES} EE register bytes, got {}",
                raw.len()
            )));
        }

        let mut cursor = EePacketCursor::new(raw);
        let mut low_gpr = [0u64; 32];
        for value in &mut low_gpr {
            *value = cursor.next_u64();
        }
        self.status = cursor.next_u32();
        let low_lo = cursor.next_u64();
        let low_hi = cursor.next_u64();
        self.badvaddr = cursor.next_u32();
        self.cause = cursor.next_u32();
        self.pc = cursor.next_u32();
        for value in &mut self.fpr {
            *value = cursor.next_u32();
        }
        self.fcsr = cursor.next_u32();
        self.fir = cursor.next_u32();
        self.epc = cursor.next_u32();
        for (slot, low) in self.gpr.iter_mut().zip(low_gpr) {
            let upper = cursor.next_u64();
            *slot = u128::from(low) | (u128::from(upper) << 64);
        }
        let upper_lo = cursor.next_u64();
        let upper_hi = cursor.next_u64();
        self.lo = u128::from(low_lo) | (u128::from(upper_lo) << 64);
        self.hi = u128::from(low_hi) | (u128::from(upper_hi) << 64);
        self.sa = cursor.next_u32();
        self.fpu_acc = cursor.next_u32();
        debug_assert_eq!(cursor.offset, PS2_EE_GPACKET_BYTES);
        Ok(())
    }
}

/// Serialise `registers` to the lossless EE/R5900 `g`-packet layout.
#[must_use]
pub fn ps2_ee_registers_to_gpacket(registers: &Ps2EeCoreRegisters) -> Vec<u8> {
    registers.to_gpacket()
}

/// Parse an exact lossless EE/R5900 `g` packet.
///
/// # Errors
///
/// Returns [`TargetError::Registers`] when the packet length is not exact.
pub fn ps2_ee_gpacket_to_registers(raw: &[u8]) -> Result<Ps2EeCoreRegisters, TargetError> {
    let mut registers = Ps2EeCoreRegisters::default();
    registers.apply_gpacket(raw)?;
    Ok(registers)
}

struct EePacketCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> EePacketCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[self.offset..self.offset + 8]);
        self.offset += 8;
        u64::from_le_bytes(bytes)
    }

    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.data[self.offset..self.offset + 4]);
        self.offset += 4;
        u32::from_le_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ee() -> Ps2EeCoreRegisters {
        let mut registers = Ps2EeCoreRegisters {
            lo: 0xaaaa_bbbb_cccc_dddd_1111_2222_3333_4444,
            hi: 0xffff_eeee_dddd_cccc_9999_8888_7777_6666,
            pc: 0x0010_2000,
            status: 0x1000_0001,
            badvaddr: 0x2000_0002,
            cause: 0x3000_0003,
            epc: 0x4000_0004,
            fcsr: 0x0102_0304,
            fir: 0x0506_0708,
            sa: 0x0000_001f,
            fpu_acc: 0x3f80_0000,
            ..Ps2EeCoreRegisters::default()
        };
        registers.gpr[0] = 0;
        registers.gpr[1] = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
        registers.gpr[31] = 0x1111_2222_3333_4444_5555_6666_7777_8888;
        registers.fpr[0] = 0x3f00_0000;
        registers.fpr[31] = 0xbf80_0000;
        registers
    }

    #[test]
    fn ee_packet_has_exact_documented_size_and_offsets() {
        let packet = sample_ee().to_gpacket();
        assert_eq!(packet.len(), PS2_EE_GPACKET_BYTES);
        // Standard low halves.
        assert_eq!(&packet[8..16], &0xfedc_ba98_7654_3210u64.to_le_bytes());
        assert_eq!(&packet[248..256], &0x5555_6666_7777_8888u64.to_le_bytes());
        assert_eq!(&packet[256..260], &0x1000_0001u32.to_le_bytes());
        assert_eq!(&packet[260..268], &0x1111_2222_3333_4444u64.to_le_bytes());
        assert_eq!(&packet[268..276], &0x9999_8888_7777_6666u64.to_le_bytes());
        assert_eq!(&packet[276..280], &0x2000_0002u32.to_le_bytes());
        assert_eq!(&packet[280..284], &0x3000_0003u32.to_le_bytes());
        assert_eq!(&packet[284..288], &0x0010_2000u32.to_le_bytes());
        // FPU state is followed by the custom EPC register.
        assert_eq!(&packet[288..292], &0x3f00_0000u32.to_le_bytes());
        assert_eq!(&packet[412..416], &0xbf80_0000u32.to_le_bytes());
        assert_eq!(&packet[416..420], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&packet[420..424], &0x0506_0708u32.to_le_bytes());
        assert_eq!(&packet[424..428], &0x4000_0004u32.to_le_bytes());
        // Matching upper halves are never discarded.
        assert_eq!(&packet[436..444], &0x0123_4567_89ab_cdefu64.to_le_bytes());
        assert_eq!(&packet[676..684], &0x1111_2222_3333_4444u64.to_le_bytes());
        assert_eq!(&packet[684..692], &0xaaaa_bbbb_cccc_ddddu64.to_le_bytes());
        assert_eq!(&packet[692..700], &0xffff_eeee_dddd_ccccu64.to_le_bytes());
        assert_eq!(&packet[700..704], &0x0000_001fu32.to_le_bytes());
        assert_eq!(&packet[704..708], &0x3f80_0000u32.to_le_bytes());
    }

    #[test]
    fn ee_packet_round_trips_all_128_bit_state() {
        let original = sample_ee();
        let parsed = ps2_ee_gpacket_to_registers(&original.to_gpacket()).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn ee_packet_rejects_missing_or_trailing_state() {
        let packet = sample_ee().to_gpacket();
        assert!(ps2_ee_gpacket_to_registers(&packet[..packet.len() - 1]).is_err());
        let mut trailing = packet;
        trailing.push(0);
        assert!(ps2_ee_gpacket_to_registers(&trailing).is_err());
    }

    #[test]
    fn ee_description_declares_required_standard_and_upper_features() {
        assert!(PS2_EE_TARGET_XML.contains("org.gnu.gdb.mips.cpu"));
        assert!(PS2_EE_TARGET_XML.contains("org.gnu.gdb.mips.cp0"));
        assert!(PS2_EE_TARGET_XML.contains("org.gnu.gdb.mips.fpu"));
        assert!(PS2_EE_TARGET_XML.contains("org.openomega.ps2.ee"));
        assert!(PS2_EE_TARGET_XML.contains("name=\"r31_upper\" bitsize=\"64\""));
        assert!(!PS2_EE_TARGET_XML.contains("name=\"r0\" bitsize=\"128\""));
        assert_eq!(PS2_EE_TARGET_DESCRIPTION.software_breakpoint_kind, 4);
    }
}
