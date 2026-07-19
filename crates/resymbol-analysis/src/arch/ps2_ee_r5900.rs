//! Minimal, fail-closed PlayStation 2 Emotion Engine/R5900 core decoders.
//!
//! This decoder intentionally covers only the frozen scalar core-v1 whitelist.
//! It never delegates unknown words to a generic MIPS backend, and it reports
//! recognized-but-unsupported EE opcode spaces separately from invalid words.

use super::{
    DecodeOutcome, DecodedInstruction, DecoderProfile, FlowKind, InstructionDecoder, TargetArch,
    UnsupportedInstructionClass,
};

/// Always-available pure-Rust decoder for the little-endian EE/R5900 core-v1
/// profile.
#[derive(Debug, Default)]
pub(crate) struct Ps2EeR5900LeCoreV1Decoder;

impl Ps2EeR5900LeCoreV1Decoder {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl InstructionDecoder for Ps2EeR5900LeCoreV1Decoder {
    fn arch(&self) -> TargetArch {
        TargetArch::Mips64
    }

    fn profile(&self) -> DecoderProfile {
        DecoderProfile::Ps2EeR5900LeCoreV1
    }

    fn decode_one(&mut self, bytes: &[u8], address: u64) -> DecodeOutcome {
        if bytes.len() < 4 {
            return DecodeOutcome::Truncated {
                available: bytes.len(),
            };
        }
        if address > u64::from(u32::MAX) || address % 4 != 0 {
            return DecodeOutcome::Invalid;
        }

        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        decode_word(word, address as u32)
    }
}

/// Always-available pure-Rust decoder for the little-endian EE/R5900 core-v1
/// profile plus the frozen MMI word-immediate-shift-v1 extension.
#[derive(Debug, Default)]
pub(crate) struct Ps2EeR5900LeCoreV1MmiWordShiftV1Decoder;

impl Ps2EeR5900LeCoreV1MmiWordShiftV1Decoder {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl InstructionDecoder for Ps2EeR5900LeCoreV1MmiWordShiftV1Decoder {
    fn arch(&self) -> TargetArch {
        TargetArch::Mips64
    }

    fn profile(&self) -> DecoderProfile {
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1
    }

    fn decode_one(&mut self, bytes: &[u8], address: u64) -> DecodeOutcome {
        if bytes.len() < 4 {
            return DecodeOutcome::Truncated {
                available: bytes.len(),
            };
        }
        if address > u64::from(u32::MAX) || address % 4 != 0 {
            return DecodeOutcome::Invalid;
        }

        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if field(word, 26, 0x3f) == 0x1c {
            decode_mmi_word_shift(word, address as u32)
        } else {
            decode_word(word, address as u32)
        }
    }
}

/// Always-available pure-Rust decoder for the little-endian EE/R5900 core-v1
/// profile plus the frozen MMI word-shift-v1 and packed-logical-v1 extensions.
#[derive(Debug, Default)]
pub(crate) struct Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1Decoder;

impl Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1Decoder {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl InstructionDecoder for Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1Decoder {
    fn arch(&self) -> TargetArch {
        TargetArch::Mips64
    }

    fn profile(&self) -> DecoderProfile {
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1
    }

    fn decode_one(&mut self, bytes: &[u8], address: u64) -> DecodeOutcome {
        if bytes.len() < 4 {
            return DecodeOutcome::Truncated {
                available: bytes.len(),
            };
        }
        if address > u64::from(u32::MAX) || address % 4 != 0 {
            return DecodeOutcome::Invalid;
        }

        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if field(word, 26, 0x3f) == 0x1c {
            decode_mmi_word_shift_packed_logical(word, address as u32)
        } else {
            decode_word(word, address as u32)
        }
    }
}

/// Always-available pure-Rust decoder for the little-endian EE/R5900 core-v1
/// profile plus the frozen MMI word-shift-v1, packed-logical-v1, and
/// packed-add-v1 extensions.
#[derive(Debug, Default)]
pub(crate) struct Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1Decoder;

impl Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1Decoder {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl InstructionDecoder for Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1Decoder {
    fn arch(&self) -> TargetArch {
        TargetArch::Mips64
    }

    fn profile(&self) -> DecoderProfile {
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1
    }

    fn decode_one(&mut self, bytes: &[u8], address: u64) -> DecodeOutcome {
        if bytes.len() < 4 {
            return DecodeOutcome::Truncated {
                available: bytes.len(),
            };
        }
        if address > u64::from(u32::MAX) || address % 4 != 0 {
            return DecodeOutcome::Invalid;
        }

        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if field(word, 26, 0x3f) == 0x1c {
            decode_mmi_word_shift_packed_logical_packed_add(word, address as u32)
        } else {
            decode_word(word, address as u32)
        }
    }
}

/// Always-available pure-Rust decoder for the little-endian EE/R5900 core-v1
/// profile plus the frozen MMI word-shift-v1, packed-logical-v1, packed-add-v1,
/// and packed-sub-v1 extensions.
#[derive(Debug, Default)]
pub(crate) struct Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1Decoder;

impl Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1Decoder {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl InstructionDecoder
    for Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1Decoder
{
    fn arch(&self) -> TargetArch {
        TargetArch::Mips64
    }

    fn profile(&self) -> DecoderProfile {
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1
    }

    fn decode_one(&mut self, bytes: &[u8], address: u64) -> DecodeOutcome {
        if bytes.len() < 4 {
            return DecodeOutcome::Truncated {
                available: bytes.len(),
            };
        }
        if address > u64::from(u32::MAX) || address % 4 != 0 {
            return DecodeOutcome::Invalid;
        }

        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if field(word, 26, 0x3f) == 0x1c {
            decode_mmi_word_shift_packed_logical_packed_add_packed_sub(word, address as u32)
        } else {
            decode_word(word, address as u32)
        }
    }
}

/// Always-available pure-Rust decoder for the little-endian EE/R5900 core-v1
/// profile plus the frozen MMI word-shift-v1, packed-logical-v1, packed-add-v1,
/// packed-sub-v1, and packed-compare-gt-v1 extensions.
#[derive(Debug, Default)]
pub(crate) struct Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1Decoder;

impl Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1Decoder {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl InstructionDecoder
    for Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1Decoder
{
    fn arch(&self) -> TargetArch {
        TargetArch::Mips64
    }

    fn profile(&self) -> DecoderProfile {
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1
    }

    fn decode_one(&mut self, bytes: &[u8], address: u64) -> DecodeOutcome {
        if bytes.len() < 4 {
            return DecodeOutcome::Truncated {
                available: bytes.len(),
            };
        }
        if address > u64::from(u32::MAX) || address % 4 != 0 {
            return DecodeOutcome::Invalid;
        }

        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if field(word, 26, 0x3f) == 0x1c {
            decode_mmi_word_shift_packed_logical_packed_add_packed_sub_packed_compare_gt(
                word,
                address as u32,
            )
        } else {
            decode_word(word, address as u32)
        }
    }
}

fn decode_mmi_word_shift(word: u32, address: u32) -> DecodeOutcome {
    const MASK: u32 = 0xffe0_003f;
    const PSLLW: u32 = 0x7000_003c;
    const PSRLW: u32 = 0x7000_003e;
    const PSRAW: u32 = 0x7000_003f;

    match word & MASK {
        PSLLW => shift_immediate("psllw", word, address),
        PSRLW => shift_immediate("psrlw", word, address),
        PSRAW => shift_immediate("psraw", word, address),
        _ if matches!(field(word, 0, 0x3f), 0x3c | 0x3e | 0x3f) => DecodeOutcome::Invalid,
        _ => unsupported(UnsupportedInstructionClass::Ps2EeMmiEncoding),
    }
}

fn decode_mmi_word_shift_packed_logical(word: u32, address: u32) -> DecodeOutcome {
    const MASK: u32 = 0xfc00_07ff;
    const PAND: u32 = 0x7000_0489;
    const POR: u32 = 0x7000_04a9;
    const PXOR: u32 = 0x7000_04c9;
    const PNOR: u32 = 0x7000_04e9;

    match word & MASK {
        PAND => three_registers("pand", word, address),
        POR => three_registers("por", word, address),
        PXOR => three_registers("pxor", word, address),
        PNOR => three_registers("pnor", word, address),
        _ => decode_mmi_word_shift(word, address),
    }
}

fn decode_mmi_word_shift_packed_logical_packed_add(word: u32, address: u32) -> DecodeOutcome {
    const MASK: u32 = 0xfc00_07ff;
    const PADDW: u32 = 0x7000_0008;
    const PADDH: u32 = 0x7000_0108;
    const PADDB: u32 = 0x7000_0208;

    match word & MASK {
        PADDW => three_registers("paddw", word, address),
        PADDH => three_registers("paddh", word, address),
        PADDB => three_registers("paddb", word, address),
        _ => decode_mmi_word_shift_packed_logical(word, address),
    }
}

fn decode_mmi_word_shift_packed_logical_packed_add_packed_sub(
    word: u32,
    address: u32,
) -> DecodeOutcome {
    const MASK: u32 = 0xfc00_07ff;
    const PSUBW: u32 = 0x7000_0048;
    const PSUBH: u32 = 0x7000_0148;
    const PSUBB: u32 = 0x7000_0248;

    match word & MASK {
        PSUBW => three_registers("psubw", word, address),
        PSUBH => three_registers("psubh", word, address),
        PSUBB => three_registers("psubb", word, address),
        _ => decode_mmi_word_shift_packed_logical_packed_add(word, address),
    }
}

fn decode_mmi_word_shift_packed_logical_packed_add_packed_sub_packed_compare_gt(
    word: u32,
    address: u32,
) -> DecodeOutcome {
    const MASK: u32 = 0xfc00_07ff;
    const PCGTW: u32 = 0x7000_0088;
    const PCGTH: u32 = 0x7000_0188;
    const PCGTB: u32 = 0x7000_0288;

    match word & MASK {
        PCGTW => three_registers("pcgtw", word, address),
        PCGTH => three_registers("pcgth", word, address),
        PCGTB => three_registers("pcgtb", word, address),
        _ => decode_mmi_word_shift_packed_logical_packed_add_packed_sub(word, address),
    }
}

fn decode_word(word: u32, address: u32) -> DecodeOutcome {
    let opcode = field(word, 26, 0x3f);
    match opcode {
        0x00 => decode_special(word, address),
        0x01 => decode_regimm(word, address),
        0x02 => decoded(
            address,
            format!("j {}", target_text(jump_target(address, word))),
            FlowKind::UnconditionalBranch,
            Some(jump_target(address, word)),
        ),
        0x03 => decoded(
            address,
            format!("jal {}", target_text(jump_target(address, word))),
            FlowKind::Call,
            Some(jump_target(address, word)),
        ),
        0x04 => branch_two_registers("beq", word, address),
        0x05 => branch_two_registers("bne", word, address),
        0x06 if rt(word) == 0 => branch_one_register("blez", word, address),
        0x07 if rt(word) == 0 => branch_one_register("bgtz", word, address),
        0x08 => immediate_signed("addi", word, address),
        0x09 => immediate_signed("addiu", word, address),
        0x0a => immediate_signed("slti", word, address),
        0x0b => immediate_signed("sltiu", word, address),
        0x0c => immediate_logical("andi", word, address),
        0x0d => immediate_logical("ori", word, address),
        0x0e => immediate_logical("xori", word, address),
        0x0f if rs(word) == 0 => decoded_sequential(
            address,
            format!("lui {}, {}", register(rt(word)), logical_immediate(word)),
        ),
        0x10 => unsupported(UnsupportedInstructionClass::Ps2EeCop0Encoding),
        0x11 => unsupported(UnsupportedInstructionClass::Ps2EeCop1Encoding),
        0x12 if rs(word) < 0x10 => unsupported(UnsupportedInstructionClass::Ps2EeCop2Encoding),
        0x12 => unsupported(UnsupportedInstructionClass::Ps2EeVuMacroEncoding),
        0x14 => branch_two_registers("beql", word, address),
        0x15 => branch_two_registers("bnel", word, address),
        0x16 if rt(word) == 0 => branch_one_register("blezl", word, address),
        0x17 if rt(word) == 0 => branch_one_register("bgtzl", word, address),
        0x18 => immediate_signed("daddi", word, address),
        0x19 => immediate_signed("daddiu", word, address),
        0x1a => memory("ldl", word, address),
        0x1b => memory("ldr", word, address),
        0x1c => unsupported(UnsupportedInstructionClass::Ps2EeMmiEncoding),
        0x1e => memory("lq", word, address),
        0x1f => memory("sq", word, address),
        0x20 => memory("lb", word, address),
        0x21 => memory("lh", word, address),
        0x22 => memory("lwl", word, address),
        0x23 => memory("lw", word, address),
        0x24 => memory("lbu", word, address),
        0x25 => memory("lhu", word, address),
        0x26 => memory("lwr", word, address),
        0x27 => memory("lwu", word, address),
        0x28 => memory("sb", word, address),
        0x29 => memory("sh", word, address),
        0x2a => memory("swl", word, address),
        0x2b => memory("sw", word, address),
        0x2c => memory("sdl", word, address),
        0x2d => memory("sdr", word, address),
        0x2e => memory("swr", word, address),
        0x2f => selector_memory("cache", word, address),
        0x31 => unsupported(UnsupportedInstructionClass::Ps2EeCop1Encoding),
        0x33 => selector_memory("pref", word, address),
        0x36 => unsupported(UnsupportedInstructionClass::Ps2EeCop2Encoding),
        0x37 => memory("ld", word, address),
        0x39 => unsupported(UnsupportedInstructionClass::Ps2EeCop1Encoding),
        0x3e => unsupported(UnsupportedInstructionClass::Ps2EeCop2Encoding),
        0x3f => memory("sd", word, address),
        _ => DecodeOutcome::Invalid,
    }
}

fn decode_special(word: u32, address: u32) -> DecodeOutcome {
    let function = field(word, 0, 0x3f);
    match function {
        0x00 if rs(word) == 0 => shift_immediate("sll", word, address),
        0x02 if rs(word) == 0 => shift_immediate("srl", word, address),
        0x03 if rs(word) == 0 => shift_immediate("sra", word, address),
        0x04 if sa(word) == 0 => shift_variable("sllv", word, address),
        0x06 if sa(word) == 0 => shift_variable("srlv", word, address),
        0x07 if sa(word) == 0 => shift_variable("srav", word, address),
        0x08 if rt(word) == 0 && rd(word) == 0 && sa(word) == 0 => decoded(
            address,
            format!("jr {}", register(rs(word))),
            FlowKind::IndirectBranch,
            None,
        ),
        0x09 if rt(word) == 0 && sa(word) == 0 => decoded(
            address,
            format!("jalr {}, {}", register(rd(word)), register(rs(word))),
            if rd(word) == 0 {
                FlowKind::IndirectBranch
            } else {
                FlowKind::IndirectCall
            },
            None,
        ),
        0x0a if sa(word) == 0 => three_registers("movz", word, address),
        0x0b if sa(word) == 0 => three_registers("movn", word, address),
        0x0c => decoded(
            address,
            format!("syscall 0x{:05x}", field(word, 6, 0x000f_ffff)),
            FlowKind::Interrupt,
            None,
        ),
        0x0d => decoded(
            address,
            format!("break 0x{:05x}", field(word, 6, 0x000f_ffff)),
            FlowKind::Interrupt,
            None,
        ),
        0x0f if rs(word) == 0 && rt(word) == 0 && rd(word) == 0 => {
            decoded_sequential(address, format!("sync 0x{:02x}", sa(word)))
        }
        0x10 if rs(word) == 0 && rt(word) == 0 && sa(word) == 0 => {
            one_destination_register("mfhi", word, address)
        }
        0x11 if rt(word) == 0 && rd(word) == 0 && sa(word) == 0 => {
            one_source_register("mthi", word, address)
        }
        0x12 if rs(word) == 0 && rt(word) == 0 && sa(word) == 0 => {
            one_destination_register("mflo", word, address)
        }
        0x13 if rt(word) == 0 && rd(word) == 0 && sa(word) == 0 => {
            one_source_register("mtlo", word, address)
        }
        0x14 if sa(word) == 0 => shift_variable("dsllv", word, address),
        0x16 if sa(word) == 0 => shift_variable("dsrlv", word, address),
        0x17 if sa(word) == 0 => shift_variable("dsrav", word, address),
        0x18 if sa(word) == 0 => three_registers_rd_first("mult", word, address),
        0x19 if sa(word) == 0 => three_registers_rd_first("multu", word, address),
        0x1a if rd(word) == 0 && sa(word) == 0 => two_source_registers("div", word, address),
        0x1b if rd(word) == 0 && sa(word) == 0 => two_source_registers("divu", word, address),
        0x20 if sa(word) == 0 => three_registers("add", word, address),
        0x21 if sa(word) == 0 => three_registers("addu", word, address),
        0x22 if sa(word) == 0 => three_registers("sub", word, address),
        0x23 if sa(word) == 0 => three_registers("subu", word, address),
        0x24 if sa(word) == 0 => three_registers("and", word, address),
        0x25 if sa(word) == 0 => three_registers("or", word, address),
        0x26 if sa(word) == 0 => three_registers("xor", word, address),
        0x27 if sa(word) == 0 => three_registers("nor", word, address),
        0x28 if rs(word) == 0 && rt(word) == 0 && sa(word) == 0 => {
            one_destination_register("mfsa", word, address)
        }
        0x29 if rt(word) == 0 && rd(word) == 0 && sa(word) == 0 => {
            one_source_register("mtsa", word, address)
        }
        0x2a if sa(word) == 0 => three_registers("slt", word, address),
        0x2b if sa(word) == 0 => three_registers("sltu", word, address),
        0x2c if sa(word) == 0 => three_registers("dadd", word, address),
        0x2d if sa(word) == 0 => three_registers("daddu", word, address),
        0x2e if sa(word) == 0 => three_registers("dsub", word, address),
        0x2f if sa(word) == 0 => three_registers("dsubu", word, address),
        0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x36 => {
            unsupported(UnsupportedInstructionClass::Ps2EeConditionalTrapEncoding)
        }
        0x38 if rs(word) == 0 => shift_immediate("dsll", word, address),
        0x3a if rs(word) == 0 => shift_immediate("dsrl", word, address),
        0x3b if rs(word) == 0 => shift_immediate("dsra", word, address),
        0x3c if rs(word) == 0 => shift_immediate("dsll32", word, address),
        0x3e if rs(word) == 0 => shift_immediate("dsrl32", word, address),
        0x3f if rs(word) == 0 => shift_immediate("dsra32", word, address),
        _ => DecodeOutcome::Invalid,
    }
}

fn decode_regimm(word: u32, address: u32) -> DecodeOutcome {
    match rt(word) {
        0x00 => branch_one_register("bltz", word, address),
        0x01 => branch_one_register("bgez", word, address),
        0x02 => branch_one_register("bltzl", word, address),
        0x03 => branch_one_register("bgezl", word, address),
        0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0e => {
            unsupported(UnsupportedInstructionClass::Ps2EeConditionalTrapEncoding)
        }
        0x10 => branch_one_register("bltzal", word, address),
        0x11 => branch_one_register("bgezal", word, address),
        0x12 => branch_one_register("bltzall", word, address),
        0x13 => branch_one_register("bgezall", word, address),
        0x18 => decode_mtsab(word, address),
        0x19 => decode_mtsah(word, address),
        _ => DecodeOutcome::Invalid,
    }
}

fn decode_mtsab(word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(
        address,
        format!("mtsab {}, {}", register(rs(word)), logical_immediate(word)),
    )
}

fn decode_mtsah(word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(
        address,
        format!("mtsah {}, {}", register(rs(word)), logical_immediate(word)),
    )
}

fn shift_immediate(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(
        address,
        format!(
            "{mnemonic} {}, {}, {}",
            register(rd(word)),
            register(rt(word)),
            sa(word)
        ),
    )
}

fn shift_variable(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(
        address,
        format!(
            "{mnemonic} {}, {}, {}",
            register(rd(word)),
            register(rt(word)),
            register(rs(word))
        ),
    )
}

fn three_registers(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(
        address,
        format!(
            "{mnemonic} {}, {}, {}",
            register(rd(word)),
            register(rs(word)),
            register(rt(word))
        ),
    )
}

fn three_registers_rd_first(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    three_registers(mnemonic, word, address)
}

fn two_source_registers(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(
        address,
        format!("{mnemonic} {}, {}", register(rs(word)), register(rt(word))),
    )
}

fn one_destination_register(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(address, format!("{mnemonic} {}", register(rd(word))))
}

fn one_source_register(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(address, format!("{mnemonic} {}", register(rs(word))))
}

fn immediate_signed(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(
        address,
        format!(
            "{mnemonic} {}, {}, {}",
            register(rt(word)),
            register(rs(word)),
            signed_immediate(word)
        ),
    )
}

fn immediate_logical(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(
        address,
        format!(
            "{mnemonic} {}, {}, {}",
            register(rt(word)),
            register(rs(word)),
            logical_immediate(word)
        ),
    )
}

fn branch_two_registers(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    let target = branch_target(address, word);
    decoded(
        address,
        format!(
            "{mnemonic} {}, {}, {}",
            register(rs(word)),
            register(rt(word)),
            target_text(target)
        ),
        FlowKind::ConditionalBranch,
        Some(target),
    )
}

fn branch_one_register(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    let target = branch_target(address, word);
    decoded(
        address,
        format!("{mnemonic} {}, {}", register(rs(word)), target_text(target)),
        FlowKind::ConditionalBranch,
        Some(target),
    )
}

fn memory(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(
        address,
        format!(
            "{mnemonic} {}, {}({})",
            register(rt(word)),
            signed_immediate(word),
            register(rs(word))
        ),
    )
}

fn selector_memory(mnemonic: &str, word: u32, address: u32) -> DecodeOutcome {
    decoded_sequential(
        address,
        format!(
            "{mnemonic} 0x{:02x}, {}({})",
            rt(word),
            signed_immediate(word),
            register(rs(word))
        ),
    )
}

fn decoded_sequential(address: u32, text: String) -> DecodeOutcome {
    decoded(address, text, FlowKind::Sequential, None)
}

fn decoded(
    address: u32,
    text: String,
    flow: FlowKind,
    direct_target: Option<u64>,
) -> DecodeOutcome {
    DecodeOutcome::Decoded(DecodedInstruction {
        address: u64::from(address),
        length: 4,
        text,
        flow,
        direct_target,
    })
}

const fn unsupported(class: UnsupportedInstructionClass) -> DecodeOutcome {
    DecodeOutcome::Unsupported { class }
}

const fn field(word: u32, shift: u32, mask: u32) -> u32 {
    (word >> shift) & mask
}

const fn rs(word: u32) -> u32 {
    field(word, 21, 0x1f)
}

const fn rt(word: u32) -> u32 {
    field(word, 16, 0x1f)
}

const fn rd(word: u32) -> u32 {
    field(word, 11, 0x1f)
}

const fn sa(word: u32) -> u32 {
    field(word, 6, 0x1f)
}

const fn signed_immediate(word: u32) -> i16 {
    word as u16 as i16
}

fn logical_immediate(word: u32) -> String {
    format!("0x{:04x}", word as u16)
}

fn branch_target(address: u32, word: u32) -> u64 {
    let pc4 = address.wrapping_add(4);
    let displacement = i32::from(signed_immediate(word)).wrapping_mul(4) as u32;
    u64::from(pc4.wrapping_add(displacement))
}

fn jump_target(address: u32, word: u32) -> u64 {
    let pc4 = address.wrapping_add(4);
    u64::from((pc4 & 0xf000_0000) | ((word & 0x03ff_ffff) << 2))
}

fn target_text(target: u64) -> String {
    format!("0x{target:08x}")
}

const fn register(index: u32) -> &'static str {
    const REGISTERS: [&str; 32] = [
        "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", "$t0", "$t1", "$t2", "$t3",
        "$t4", "$t5", "$t6", "$t7", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$t8",
        "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
    ];
    REGISTERS[index as usize]
}
