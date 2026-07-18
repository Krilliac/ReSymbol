//! The always-available x86/x86-64 decoder backend, wrapping `iced-x86`.

use iced_x86::{
    Decoder, DecoderError, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter,
    OpKind,
};

use super::{DecodeOutcome, DecodedInstruction, FlowKind, InstructionDecoder, TargetArch};

/// A pure-Rust `iced-x86` decoder for either 32-bit x86 or 64-bit x86-64.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IcedX64Decoder {
    bitness: u32,
    arch: TargetArch,
}

impl IcedX64Decoder {
    /// A 64-bit x86-64 decoder.
    #[must_use]
    pub(crate) const fn new_x86_64() -> Self {
        Self {
            bitness: 64,
            arch: TargetArch::X86_64,
        }
    }

    /// A 32-bit x86 decoder.
    #[must_use]
    pub(crate) const fn new_x86() -> Self {
        Self {
            bitness: 32,
            arch: TargetArch::X86,
        }
    }
}

impl InstructionDecoder for IcedX64Decoder {
    fn arch(&self) -> TargetArch {
        self.arch
    }

    fn decode_one(&mut self, bytes: &[u8], address: u64) -> DecodeOutcome {
        // A fresh single-use decoder over the exact byte span reproduces the
        // streaming decoder's per-instruction result: instruction length, flow
        // control, and relative-branch targets depend only on the instruction
        // bytes and the supplied instruction pointer.
        let mut decoder = Decoder::with_ip(self.bitness, bytes, address, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return match decoder.last_error() {
                DecoderError::NoMoreBytes => DecodeOutcome::Truncated {
                    available: bytes.len(),
                },
                _ => DecodeOutcome::Invalid,
            };
        }
        let length = instruction.len();
        let Ok(length) = u8::try_from(length) else {
            // x86 instructions never exceed fifteen bytes; treat any decoder
            // that violates that invariant as an invalid encoding.
            return DecodeOutcome::Invalid;
        };
        let mut text = String::new();
        IntelFormatter::new().format(&instruction, &mut text);
        DecodeOutcome::Decoded(DecodedInstruction {
            address,
            length,
            text,
            flow: flow_kind(&instruction),
            direct_target: direct_target(&instruction),
        })
    }
}

/// Map `iced-x86`'s `FlowControl` onto the architecture-neutral [`FlowKind`].
///
/// The eight shared categories map one-to-one. `iced-x86`'s transactional group
/// reuses [`FlowKind::Privileged`] and its exception-generating group reuses
/// [`FlowKind::Invalid`]; `iced-x86` never reports those `FlowControl` values for
/// any other instruction, so the reuse is unambiguous and lets the x86 linear
/// preview reconstruct its original `transaction`/`exception` categories exactly.
pub(crate) fn flow_kind(instruction: &Instruction) -> FlowKind {
    match instruction.flow_control() {
        FlowControl::Next => FlowKind::Sequential,
        FlowControl::ConditionalBranch => FlowKind::ConditionalBranch,
        FlowControl::UnconditionalBranch => FlowKind::UnconditionalBranch,
        FlowControl::IndirectBranch => FlowKind::IndirectBranch,
        FlowControl::Call => FlowKind::Call,
        FlowControl::IndirectCall => FlowKind::IndirectCall,
        FlowControl::Return => FlowKind::Return,
        FlowControl::Interrupt => FlowKind::Interrupt,
        FlowControl::XbeginXabortXend => FlowKind::Privileged,
        FlowControl::Exception => FlowKind::Invalid,
    }
}

/// Resolve a direct near branch/call target, if any.
///
/// This reproduces the original linear-disassembly target resolution: only
/// conditional branches, unconditional branches, and calls whose first operand
/// is a near-branch immediate expose a direct target. Indirect and far control
/// flow return `None`.
pub(crate) fn direct_target(instruction: &Instruction) -> Option<u64> {
    if !matches!(
        instruction.flow_control(),
        FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Call
    ) {
        return None;
    }
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| instruction.near_branch_target())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::DecodeOutcome;

    fn decode(bytes: &[u8], address: u64) -> DecodedInstruction {
        let mut decoder = IcedX64Decoder::new_x86_64();
        match decoder.decode_one(bytes, address) {
            DecodeOutcome::Decoded(instruction) => instruction,
            other => panic!("expected a decoded instruction, got {other:?}"),
        }
    }

    #[test]
    fn known_encodings_match_the_iced_flow_and_target() {
        let call = decode(&[0xe8, 0x03, 0x00, 0x00, 0x00], 0x1000);
        assert_eq!(call.flow, FlowKind::Call);
        assert_eq!(call.length, 5);
        assert_eq!(call.direct_target, Some(0x1008));

        let conditional = decode(&[0x75, 0x02], 0x2000);
        assert_eq!(conditional.flow, FlowKind::ConditionalBranch);
        assert_eq!(conditional.direct_target, Some(0x2004));

        let jump = decode(&[0xeb, 0x02], 0x3000);
        assert_eq!(jump.flow, FlowKind::UnconditionalBranch);
        assert_eq!(jump.direct_target, Some(0x3004));

        let ret = decode(&[0xc3], 0x4000);
        assert_eq!(ret.flow, FlowKind::Return);
        assert_eq!(ret.direct_target, None);

        let indirect = decode(&[0xff, 0xe0], 0x5000);
        assert_eq!(indirect.flow, FlowKind::IndirectBranch);
        assert_eq!(indirect.direct_target, None);
    }

    #[test]
    fn truncated_and_invalid_outcomes_are_distinguished() {
        let mut decoder = IcedX64Decoder::new_x86_64();
        assert_eq!(
            decoder.decode_one(&[0x48, 0x8b], 0x1000),
            DecodeOutcome::Truncated { available: 2 }
        );
        assert_eq!(
            decoder.decode_one(&[0xff, 0xf8], 0x1000),
            DecodeOutcome::Invalid
        );
    }

    #[test]
    fn decoding_is_deterministic() {
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0x75, 0x02, 0xc3];
        let mut first = IcedX64Decoder::new_x86_64();
        let mut second = IcedX64Decoder::new_x86_64();
        assert_eq!(
            first.decode_one(&bytes, 0x1000),
            second.decode_one(&bytes, 0x1000)
        );
    }
}
