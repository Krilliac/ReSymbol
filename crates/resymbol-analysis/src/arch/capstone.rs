//! The optional Capstone decoder backend.
//!
//! This backend is only compiled when the `capstone` feature is enabled. It
//! covers the non-x86 architectures the crate models by driving the Capstone
//! disassembler through the `capstone` (capstone-rs) crate, which bundles and
//! builds the Capstone C library.
//!
//! Classification is derived from Capstone's architecture-independent instruction
//! groups so a single mapping serves every architecture: `CS_GRP_CALL`,
//! `CS_GRP_RET`/`CS_GRP_IRET`, `CS_GRP_INT`, `CS_GRP_JUMP`, and `CS_GRP_PRIVILEGE`
//! map onto [`FlowKind`]. A direct target is the last immediate operand of a
//! branch or call (Capstone resolves relative branch displacements to absolute
//! addresses); register/indirect forms expose no immediate and are reported as
//! the indirect variants.
//!
//! Conditional-versus-unconditional jump distinction is intentionally a modest
//! per-architecture mnemonic heuristic (see [`is_conditional_branch`]): Capstone's
//! generic groups do not carry that bit, and — per design — correct target
//! extraction and the jump/call/return/interrupt/invalid classification are what
//! matter here. Unrecognized jump mnemonics default to `UnconditionalBranch`.

use capstone::arch::ArchOperand;
use capstone::arch::arm::ArmOperandType;
use capstone::arch::arm64::Arm64OperandType;
use capstone::arch::mips::MipsOperand;
use capstone::arch::ppc::PpcOperand;
use capstone::arch::riscv::RiscVOperand;
use capstone::{Arch, Capstone, Endian, InsnGroupType, Mode, NO_EXTRA_MODE};

use super::{
    DecodeOutcome, DecodedInstruction, FlowKind, InstructionDecoder, TargetArch,
    UnsupportedArchError,
};

/// A Capstone-backed single-instruction decoder for one non-x86 architecture.
pub(crate) struct CapstoneDecoder {
    capstone: Capstone,
    arch: TargetArch,
    minimum_instruction_bytes: usize,
}

impl CapstoneDecoder {
    /// Build a Capstone decoder for `arch` with instruction detail enabled.
    pub(crate) fn new(arch: TargetArch) -> Result<Self, UnsupportedArchError> {
        let (cs_arch, cs_mode, endian) = capstone_configuration(arch);
        let mut capstone = Capstone::new_raw(cs_arch, cs_mode, NO_EXTRA_MODE, Some(endian))
            .map_err(|error| UnsupportedArchError::BackendUnavailable {
                arch: arch.name(),
                reason: error.to_string(),
            })?;
        capstone
            .set_detail(true)
            .map_err(|error| UnsupportedArchError::BackendUnavailable {
                arch: arch.name(),
                reason: error.to_string(),
            })?;
        Ok(Self {
            capstone,
            arch,
            minimum_instruction_bytes: minimum_instruction_bytes(arch),
        })
    }
}

impl InstructionDecoder for CapstoneDecoder {
    fn arch(&self) -> TargetArch {
        self.arch
    }

    fn decode_one(&mut self, bytes: &[u8], address: u64) -> DecodeOutcome {
        let Ok(instructions) = self.capstone.disasm_count(bytes, address, 1) else {
            return self.empty_outcome(bytes);
        };
        let Some(instruction) = instructions.iter().next() else {
            return self.empty_outcome(bytes);
        };
        let Ok(length) = u8::try_from(instruction.len()) else {
            return DecodeOutcome::Invalid;
        };
        if length == 0 {
            return self.empty_outcome(bytes);
        }

        let mnemonic = instruction.mnemonic().unwrap_or_default();
        let text = match instruction.op_str() {
            Some(operands) if !operands.is_empty() => format!("{mnemonic} {operands}"),
            _ => mnemonic.to_owned(),
        };

        let (flow, direct_target) = match self.capstone.insn_detail(instruction) {
            Ok(detail) => {
                let target = last_immediate_target(&detail.arch_detail().operands());
                (
                    classify_flow(self.arch, mnemonic, detail.groups(), target),
                    branch_or_call_target(detail.groups(), target),
                )
            }
            // Without detail there is no reliable control-flow classification;
            // report a sequential instruction with no resolvable target.
            Err(_) => (FlowKind::Sequential, None),
        };

        DecodeOutcome::Decoded(DecodedInstruction {
            address,
            length,
            text,
            flow,
            direct_target,
        })
    }
}

impl CapstoneDecoder {
    /// Distinguish an encoding that is too short from one that is undecodable.
    fn empty_outcome(&self, bytes: &[u8]) -> DecodeOutcome {
        if bytes.len() < self.minimum_instruction_bytes {
            DecodeOutcome::Truncated {
                available: bytes.len(),
            }
        } else {
            DecodeOutcome::Invalid
        }
    }
}

/// The Capstone architecture, base mode, and byte order for a [`TargetArch`].
///
/// Endianness is not carried by [`TargetArch`], so the conventional byte order
/// for each family is chosen: big-endian for PowerPC, little-endian otherwise.
fn capstone_configuration(arch: TargetArch) -> (Arch, Mode, Endian) {
    match arch {
        TargetArch::Aarch64 => (Arch::ARM64, Mode::Arm, Endian::Little),
        TargetArch::Arm => (Arch::ARM, Mode::Arm, Endian::Little),
        TargetArch::ArmThumb => (Arch::ARM, Mode::Thumb, Endian::Little),
        TargetArch::Mips32 => (Arch::MIPS, Mode::Mips32, Endian::Little),
        TargetArch::Mips64 => (Arch::MIPS, Mode::Mips64, Endian::Little),
        TargetArch::Riscv32 => (Arch::RISCV, Mode::RiscV32, Endian::Little),
        TargetArch::Riscv64 => (Arch::RISCV, Mode::RiscV64, Endian::Little),
        TargetArch::PowerPc32 => (Arch::PPC, Mode::Mode32, Endian::Big),
        TargetArch::PowerPc64 => (Arch::PPC, Mode::Mode64, Endian::Big),
        // x86/x86-64 are served by the iced backend; map them for totality.
        TargetArch::X86 => (Arch::X86, Mode::Mode32, Endian::Little),
        TargetArch::X86_64 => (Arch::X86, Mode::Mode64, Endian::Little),
    }
}

/// Minimum byte width of one instruction, used to report truncation.
const fn minimum_instruction_bytes(arch: TargetArch) -> usize {
    match arch {
        // Thumb and the RISC-V C extension admit 2-byte instructions.
        TargetArch::ArmThumb | TargetArch::Riscv32 | TargetArch::Riscv64 => 2,
        _ => 4,
    }
}

/// Map Capstone instruction groups onto the architecture-neutral [`FlowKind`].
fn classify_flow(
    arch: TargetArch,
    mnemonic: &str,
    groups: &[capstone::InsnGroupId],
    direct_target: Option<u64>,
) -> FlowKind {
    let has_group =
        |wanted: InsnGroupType::Type| groups.iter().any(|group| u32::from(group.0) == wanted);

    if has_group(InsnGroupType::CS_GRP_CALL) {
        return if direct_target.is_some() {
            FlowKind::Call
        } else {
            FlowKind::IndirectCall
        };
    }
    if has_group(InsnGroupType::CS_GRP_RET) || has_group(InsnGroupType::CS_GRP_IRET) {
        return FlowKind::Return;
    }
    if has_group(InsnGroupType::CS_GRP_INT) {
        return FlowKind::Interrupt;
    }
    if has_group(InsnGroupType::CS_GRP_JUMP) {
        return match direct_target {
            None => FlowKind::IndirectBranch,
            Some(_) if is_conditional_branch(arch, mnemonic) => FlowKind::ConditionalBranch,
            Some(_) => FlowKind::UnconditionalBranch,
        };
    }
    if has_group(InsnGroupType::CS_GRP_PRIVILEGE) {
        return FlowKind::Privileged;
    }
    FlowKind::Sequential
}

/// A direct target is only meaningful for branch/call instructions.
fn branch_or_call_target(
    groups: &[capstone::InsnGroupId],
    direct_target: Option<u64>,
) -> Option<u64> {
    let is_branchish = groups.iter().any(|group| {
        let id = u32::from(group.0);
        id == InsnGroupType::CS_GRP_JUMP || id == InsnGroupType::CS_GRP_CALL
    });
    if is_branchish { direct_target } else { None }
}

/// The last immediate operand, interpreted as an absolute address.
///
/// Capstone resolves relative branch displacements to absolute addresses in the
/// immediate operand, and for the branch/call forms modeled here the target is
/// always the final immediate operand (any earlier immediates are bit indices or
/// register-relative offsets). Register-indirect forms have no immediate and
/// yield `None`.
fn last_immediate_target(operands: &[ArchOperand]) -> Option<u64> {
    let mut target = None;
    for operand in operands {
        match operand {
            ArchOperand::Arm64Operand(op) => {
                if let Arm64OperandType::Imm(value) = op.op_type {
                    target = Some(value as u64);
                }
            }
            ArchOperand::ArmOperand(op) => {
                if let ArmOperandType::Imm(value) = op.op_type {
                    target = Some(u64::from(value as u32));
                }
            }
            ArchOperand::MipsOperand(MipsOperand::Imm(value)) => {
                target = Some(*value as u64);
            }
            ArchOperand::RiscVOperand(RiscVOperand::Imm(value)) => {
                target = Some(*value as u64);
            }
            ArchOperand::PpcOperand(PpcOperand::Imm(value)) => {
                target = Some(*value as u64);
            }
            _ => {}
        }
    }
    target
}

/// A modest per-architecture conditional-branch mnemonic heuristic.
///
/// This deliberately does not attempt a complete conditional/unconditional
/// classification for every encoding; it recognizes the common conditional
/// branch forms and lets everything else fall back to `UnconditionalBranch`.
fn is_conditional_branch(arch: TargetArch, mnemonic: &str) -> bool {
    let mnemonic = mnemonic.trim();
    match arch {
        TargetArch::Aarch64 => {
            mnemonic.starts_with("b.") || mnemonic.starts_with("cb") || mnemonic.starts_with("tb")
        }
        TargetArch::Arm | TargetArch::ArmThumb => {
            mnemonic.starts_with("cb") || arm_conditional_branch(mnemonic)
        }
        TargetArch::Mips32 | TargetArch::Mips64 => {
            mnemonic.starts_with('b') && mnemonic != "b" && mnemonic != "bal"
        }
        TargetArch::Riscv32 | TargetArch::Riscv64 => matches!(
            mnemonic,
            "beq"
                | "bne"
                | "blt"
                | "bge"
                | "bltu"
                | "bgeu"
                | "beqz"
                | "bnez"
                | "blez"
                | "bgez"
                | "bltz"
                | "bgtz"
                | "bgt"
                | "ble"
                | "bgtu"
                | "bleu"
        ),
        TargetArch::PowerPc32 | TargetArch::PowerPc64 => {
            (mnemonic.starts_with("bc") || mnemonic.starts_with("bd"))
                || (mnemonic.starts_with('b')
                    && ["eq", "ne", "lt", "gt", "le", "ge", "so", "ns"]
                        .iter()
                        .any(|suffix| mnemonic.contains(suffix)))
        }
        TargetArch::X86 | TargetArch::X86_64 => false,
    }
}

/// Recognize a conditional `B<cond>` on 32-bit ARM by its condition suffix.
fn arm_conditional_branch(mnemonic: &str) -> bool {
    let Some(suffix) = mnemonic.strip_prefix('b') else {
        return false;
    };
    // Strip an optional width qualifier (`b.w`) before testing the condition.
    let suffix = suffix.strip_prefix('.').map_or(suffix, |rest| rest);
    matches!(
        suffix,
        "eq" | "ne"
            | "cs"
            | "hs"
            | "cc"
            | "lo"
            | "mi"
            | "pl"
            | "vs"
            | "vc"
            | "hi"
            | "ls"
            | "ge"
            | "lt"
            | "gt"
            | "le"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::DecodeOutcome;

    fn decode(arch: TargetArch, bytes: &[u8], address: u64) -> DecodedInstruction {
        let mut decoder = CapstoneDecoder::new(arch).expect("capstone decoder");
        match decoder.decode_one(bytes, address) {
            DecodeOutcome::Decoded(instruction) => instruction,
            other => panic!("expected decoded instruction, got {other:?}"),
        }
    }

    #[test]
    fn aarch64_control_flow_is_classified_with_targets() {
        // bl #0x10
        let bl = decode(TargetArch::Aarch64, &[0x04, 0x00, 0x00, 0x94], 0x1000);
        assert_eq!(bl.flow, FlowKind::Call);
        assert_eq!(bl.direct_target, Some(0x1010));

        // b #0x10
        let b = decode(TargetArch::Aarch64, &[0x04, 0x00, 0x00, 0x14], 0x1000);
        assert_eq!(b.flow, FlowKind::UnconditionalBranch);
        assert_eq!(b.direct_target, Some(0x1010));

        // b.eq #0x10
        let beq = decode(TargetArch::Aarch64, &[0x80, 0x00, 0x00, 0x54], 0x1000);
        assert_eq!(beq.flow, FlowKind::ConditionalBranch);
        assert_eq!(beq.direct_target, Some(0x1010));

        // ret
        let ret = decode(TargetArch::Aarch64, &[0xc0, 0x03, 0x5f, 0xd6], 0x1000);
        assert_eq!(ret.flow, FlowKind::Return);
        assert_eq!(ret.direct_target, None);

        // br x0
        let br = decode(TargetArch::Aarch64, &[0x00, 0x00, 0x1f, 0xd6], 0x1000);
        assert_eq!(br.flow, FlowKind::IndirectBranch);
        assert_eq!(br.direct_target, None);

        // blr x0
        let blr = decode(TargetArch::Aarch64, &[0x00, 0x00, 0x3f, 0xd6], 0x1000);
        assert_eq!(blr.flow, FlowKind::IndirectCall);
        assert_eq!(blr.direct_target, None);
    }

    #[test]
    fn riscv_conditional_branch_is_classified() {
        // `beqz zero, 0x10`. Capstone reports RISC-V branch displacements as the
        // relative offset (0x10) rather than an absolute address, so that is the
        // immediate operand this backend surfaces.
        let beq = decode(TargetArch::Riscv64, &[0x63, 0x08, 0x00, 0x00], 0x1000);
        assert_eq!(beq.flow, FlowKind::ConditionalBranch);
        assert_eq!(beq.direct_target, Some(0x10));
    }

    #[test]
    fn mips_jump_and_branch_are_classified() {
        // beq $at, $v0, 0x1014 (little-endian MIPS32); Capstone resolves the
        // absolute branch target.
        let beq = decode(TargetArch::Mips32, &[0x04, 0x00, 0x22, 0x10], 0x1000);
        assert_eq!(beq.flow, FlowKind::ConditionalBranch);
        assert_eq!(beq.direct_target, Some(0x1014));

        // jr $ra
        let jr = decode(TargetArch::Mips32, &[0x08, 0x00, 0xe0, 0x03], 0x1000);
        assert_eq!(jr.flow, FlowKind::IndirectBranch);
        assert_eq!(jr.direct_target, None);
    }

    #[test]
    fn decoding_is_deterministic() {
        let bytes = [0x04, 0x00, 0x00, 0x94];
        let first = decode(TargetArch::Aarch64, &bytes, 0x2000);
        let second = decode(TargetArch::Aarch64, &bytes, 0x2000);
        assert_eq!(first, second);
    }

    #[test]
    fn short_and_invalid_inputs_are_distinguished() {
        let mut decoder = CapstoneDecoder::new(TargetArch::Aarch64).expect("decoder");
        assert_eq!(
            decoder.decode_one(&[0x00, 0x00], 0x1000),
            DecodeOutcome::Truncated { available: 2 }
        );
        // 0x00000000 is `udf #0` on AArch64 and does not decode.
        assert_eq!(
            decoder.decode_one(&[0x00, 0x00, 0x00, 0x00], 0x1000),
            DecodeOutcome::Invalid
        );
    }
}
