//! Bounded, deterministic x64 linear-disassembly previews.
//!
//! This module is deliberately a pure value transformer. It does not discover
//! control-flow graphs or function boundaries, read files, map images, or
//! execute target code. Callers must provide bytes already verified by their
//! own source-binding policy.

use iced_x86::{
    Decoder, DecoderError, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter,
    OpKind,
};
use thiserror::Error;

/// Hard ceiling for source bytes considered by one preview.
pub const MAX_LINEAR_DISASSEMBLY_BYTES: usize = 64 * 1024;
/// Hard ceiling for instruction rows retained by one preview.
pub const MAX_LINEAR_DISASSEMBLY_INSTRUCTIONS: usize = 4 * 1024;

/// Independent byte and instruction budgets for one linear preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinearDisassemblyLimits {
    maximum_bytes: usize,
    maximum_instructions: usize,
}

impl LinearDisassemblyLimits {
    /// Validate caller-selected limits against the crate-wide hard ceilings.
    pub fn new(
        maximum_bytes: usize,
        maximum_instructions: usize,
    ) -> Result<Self, LinearDisassemblyError> {
        if maximum_bytes == 0 {
            return Err(LinearDisassemblyError::EmptyByteLimit);
        }
        if maximum_instructions == 0 {
            return Err(LinearDisassemblyError::EmptyInstructionLimit);
        }
        if maximum_bytes > MAX_LINEAR_DISASSEMBLY_BYTES {
            return Err(LinearDisassemblyError::ByteLimitTooLarge {
                actual: maximum_bytes,
                maximum: MAX_LINEAR_DISASSEMBLY_BYTES,
            });
        }
        if maximum_instructions > MAX_LINEAR_DISASSEMBLY_INSTRUCTIONS {
            return Err(LinearDisassemblyError::InstructionLimitTooLarge {
                actual: maximum_instructions,
                maximum: MAX_LINEAR_DISASSEMBLY_INSTRUCTIONS,
            });
        }
        Ok(Self {
            maximum_bytes,
            maximum_instructions,
        })
    }

    #[must_use]
    pub const fn maximum_bytes(self) -> usize {
        self.maximum_bytes
    }

    #[must_use]
    pub const fn maximum_instructions(self) -> usize {
        self.maximum_instructions
    }
}

/// Owned display row for exactly one successfully decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearInstructionRow {
    rva: u64,
    bytes: Vec<u8>,
    text: String,
    flow_control: LinearFlowControlCategory,
    direct_target_rva: Option<u64>,
    length: u8,
}

impl LinearInstructionRow {
    #[must_use]
    pub const fn rva(&self) -> u64 {
        self.rva
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn flow_control(&self) -> LinearFlowControlCategory {
        self.flow_control
    }

    /// Typed direct near branch/call target. Indirect and non-control-flow
    /// instructions return `None`; this API never guesses a runtime target.
    #[must_use]
    pub const fn direct_target_rva(&self) -> Option<u64> {
        self.direct_target_rva
    }

    #[must_use]
    pub const fn length(&self) -> u8 {
        self.length
    }
}

/// Stable presentation category derived from iced-x86 control-flow metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearFlowControlCategory {
    Sequential,
    ConditionalBranch,
    UnconditionalBranch,
    IndirectBranch,
    Call,
    IndirectCall,
    Return,
    Interrupt,
    Transaction,
    Exception,
}

impl LinearFlowControlCategory {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::ConditionalBranch => "conditional branch",
            Self::UnconditionalBranch => "unconditional branch",
            Self::IndirectBranch => "indirect branch",
            Self::Call => "call",
            Self::IndirectCall => "indirect call",
            Self::Return => "return",
            Self::Interrupt => "interrupt",
            Self::Transaction => "transaction",
            Self::Exception => "exception",
        }
    }
}

impl From<FlowControl> for LinearFlowControlCategory {
    fn from(flow: FlowControl) -> Self {
        match flow {
            FlowControl::Next => Self::Sequential,
            FlowControl::ConditionalBranch => Self::ConditionalBranch,
            FlowControl::UnconditionalBranch => Self::UnconditionalBranch,
            FlowControl::IndirectBranch => Self::IndirectBranch,
            FlowControl::Call => Self::Call,
            FlowControl::IndirectCall => Self::IndirectCall,
            FlowControl::Return => Self::Return,
            FlowControl::Interrupt => Self::Interrupt,
            FlowControl::XbeginXabortXend => Self::Transaction,
            FlowControl::Exception => Self::Exception,
        }
    }
}

/// Boundary that denied the remaining bytes needed by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearTruncationBoundary {
    InputEnd,
    ByteLimit,
}

/// Exact, deterministic reason the linear sweep stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinearDisassemblyStopReason {
    EmptyInput,
    EndOfInput,
    ByteLimitReached {
        decoded_bytes: usize,
    },
    InstructionLimitReached {
        decoded_instructions: usize,
    },
    InvalidInstruction {
        rva: u64,
        offset: usize,
    },
    TruncatedInstruction {
        rva: u64,
        available_bytes: usize,
        boundary: LinearTruncationBoundary,
    },
    AddressOverflow {
        rva: u64,
        instruction_length: usize,
    },
}

impl LinearDisassemblyStopReason {
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::EmptyInput => "no verified bytes were supplied".to_owned(),
            Self::EndOfInput => "reached the end of the verified byte span".to_owned(),
            Self::ByteLimitReached { decoded_bytes } => {
                format!("reached the independent {decoded_bytes}-byte preview limit")
            }
            Self::InstructionLimitReached {
                decoded_instructions,
            } => {
                format!("reached the independent {decoded_instructions}-instruction preview limit")
            }
            Self::InvalidInstruction { rva, .. } => {
                format!("iced-x86 rejected the encoding at RVA 0x{rva:016X}")
            }
            Self::TruncatedInstruction {
                rva,
                available_bytes,
                boundary,
            } => {
                let boundary = match boundary {
                    LinearTruncationBoundary::InputEnd => "verified input ended",
                    LinearTruncationBoundary::ByteLimit => "the byte preview limit was reached",
                };
                format!(
                    "instruction at RVA 0x{rva:016X} is truncated after {available_bytes} byte(s): {boundary}"
                )
            }
            Self::AddressOverflow {
                rva,
                instruction_length,
            } => format!(
                "instruction at RVA 0x{rva:016X} with length {instruction_length} overflows the RVA address space"
            ),
        }
    }
}

/// Owned result of a bounded x64 linear sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearDisassemblyPreview {
    start_rva: u64,
    considered_bytes: usize,
    rows: Vec<LinearInstructionRow>,
    stop_reason: LinearDisassemblyStopReason,
}

impl LinearDisassemblyPreview {
    /// This text is intentionally explicit in every consumer surface.
    pub const DISCLAIMER: &'static str =
        "Linear preview only; this is not CFG or function-boundary truth.";

    #[must_use]
    pub const fn start_rva(&self) -> u64 {
        self.start_rva
    }

    #[must_use]
    pub const fn considered_bytes(&self) -> usize {
        self.considered_bytes
    }

    #[must_use]
    pub fn rows(&self) -> &[LinearInstructionRow] {
        &self.rows
    }

    #[must_use]
    pub const fn stop_reason(&self) -> &LinearDisassemblyStopReason {
        &self.stop_reason
    }
}

/// Decode a verified byte span as a deterministic x64 linear preview.
///
/// This function is thread-safe and has no side effects. The caller retains
/// ownership of source verification and RVA-to-file/live mapping policy.
pub fn disassemble_x64_linear(
    verified_bytes: &[u8],
    start_rva: u64,
    limits: LinearDisassemblyLimits,
) -> LinearDisassemblyPreview {
    if verified_bytes.is_empty() {
        return LinearDisassemblyPreview {
            start_rva,
            considered_bytes: 0,
            rows: Vec::new(),
            stop_reason: LinearDisassemblyStopReason::EmptyInput,
        };
    }

    let considered_bytes = verified_bytes.len().min(limits.maximum_bytes);
    let window = &verified_bytes[..considered_bytes];
    let byte_limited = considered_bytes < verified_bytes.len();
    let mut decoder = Decoder::with_ip(64, window, start_rva, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut rows = Vec::with_capacity(
        limits
            .maximum_instructions
            .min(considered_bytes)
            .min(MAX_LINEAR_DISASSEMBLY_INSTRUCTIONS),
    );

    let stop_reason = loop {
        let offset = decoder.position();
        if offset == window.len() {
            break if byte_limited {
                LinearDisassemblyStopReason::ByteLimitReached {
                    decoded_bytes: offset,
                }
            } else {
                LinearDisassemblyStopReason::EndOfInput
            };
        }
        if rows.len() == limits.maximum_instructions {
            break LinearDisassemblyStopReason::InstructionLimitReached {
                decoded_instructions: rows.len(),
            };
        }
        let Some(rva) = start_rva.checked_add(offset as u64) else {
            break LinearDisassemblyStopReason::AddressOverflow {
                rva: start_rva,
                instruction_length: offset,
            };
        };

        let instruction = decoder.decode();
        let length = instruction.len();
        if instruction.is_invalid() {
            break match decoder.last_error() {
                DecoderError::NoMoreBytes => LinearDisassemblyStopReason::TruncatedInstruction {
                    rva,
                    available_bytes: window.len() - offset,
                    boundary: if byte_limited {
                        LinearTruncationBoundary::ByteLimit
                    } else {
                        LinearTruncationBoundary::InputEnd
                    },
                },
                DecoderError::InvalidInstruction | DecoderError::None => {
                    LinearDisassemblyStopReason::InvalidInstruction { rva, offset }
                }
                _ => LinearDisassemblyStopReason::InvalidInstruction { rva, offset },
            };
        }
        if rva.checked_add(length as u64).is_none() {
            break LinearDisassemblyStopReason::AddressOverflow {
                rva,
                instruction_length: length,
            };
        }
        let end = offset + length;
        let exact_bytes = window[offset..end].to_vec();
        let length = u8::try_from(length).expect("x64 instructions are at most 15 bytes");
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        rows.push(LinearInstructionRow {
            rva,
            bytes: exact_bytes,
            text,
            flow_control: instruction.flow_control().into(),
            direct_target_rva: direct_target_rva(&instruction),
            length,
        });
    };

    LinearDisassemblyPreview {
        start_rva,
        considered_bytes,
        rows,
        stop_reason,
    }
}

fn direct_target_rva(instruction: &Instruction) -> Option<u64> {
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

/// Invalid caller-selected preview limits.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LinearDisassemblyError {
    #[error("linear-disassembly byte limit must be nonzero")]
    EmptyByteLimit,
    #[error("linear-disassembly instruction limit must be nonzero")]
    EmptyInstructionLimit,
    #[error("linear-disassembly byte limit {actual} exceeds hard maximum {maximum}")]
    ByteLimitTooLarge { actual: usize, maximum: usize },
    #[error("linear-disassembly instruction limit {actual} exceeds hard maximum {maximum}")]
    InstructionLimitTooLarge { actual: usize, maximum: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(bytes: usize, instructions: usize) -> LinearDisassemblyLimits {
        LinearDisassemblyLimits::new(bytes, instructions).expect("valid limits")
    }

    #[test]
    fn preview_is_deterministic_owned_and_flow_categorized() {
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x75, 0x02, 0xC3];
        let first = disassemble_x64_linear(&bytes, 0x1000, limits(bytes.len(), 16));
        let second = disassemble_x64_linear(&bytes, 0x1000, limits(bytes.len(), 16));

        assert_eq!(first, second);
        assert_eq!(first.rows().len(), 4);
        assert_eq!(first.rows()[0].rva(), 0x1000);
        assert_eq!(first.rows()[0].bytes(), &[0x55]);
        assert_eq!(first.rows()[0].text(), "push rbp");
        assert_eq!(first.rows()[1].text(), "mov rbp,rsp");
        assert_eq!(
            first.rows()[2].flow_control(),
            LinearFlowControlCategory::ConditionalBranch
        );
        assert_eq!(first.rows()[2].direct_target_rva(), Some(0x1008));
        assert_eq!(
            first.rows()[3].flow_control(),
            LinearFlowControlCategory::Return
        );
        assert_eq!(first.rows()[3].direct_target_rva(), None);
        assert_eq!(
            first.stop_reason(),
            &LinearDisassemblyStopReason::EndOfInput
        );
    }

    #[test]
    fn byte_and_instruction_limits_stop_independently() {
        let bytes = [0x90; 10];
        let byte_limited = disassemble_x64_linear(&bytes, 0, limits(3, 10));
        assert_eq!(byte_limited.rows().len(), 3);
        assert_eq!(
            byte_limited.stop_reason(),
            &LinearDisassemblyStopReason::ByteLimitReached { decoded_bytes: 3 }
        );

        let instruction_limited = disassemble_x64_linear(&bytes, 0, limits(10, 2));
        assert_eq!(instruction_limited.rows().len(), 2);
        assert_eq!(
            instruction_limited.stop_reason(),
            &LinearDisassemblyStopReason::InstructionLimitReached {
                decoded_instructions: 2
            }
        );
    }

    #[test]
    fn truncation_identifies_input_and_byte_limit_boundaries() {
        let bytes = [0x48, 0x8B, 0xC0];
        let input_end = disassemble_x64_linear(&bytes[..2], 0x2000, limits(2, 10));
        assert_eq!(
            input_end.stop_reason(),
            &LinearDisassemblyStopReason::TruncatedInstruction {
                rva: 0x2000,
                available_bytes: 2,
                boundary: LinearTruncationBoundary::InputEnd,
            }
        );

        let byte_limit = disassemble_x64_linear(&bytes, 0x2000, limits(2, 10));
        assert_eq!(
            byte_limit.stop_reason(),
            &LinearDisassemblyStopReason::TruncatedInstruction {
                rva: 0x2000,
                available_bytes: 2,
                boundary: LinearTruncationBoundary::ByteLimit,
            }
        );
    }

    #[test]
    fn invalid_encoding_and_address_overflow_are_explicit() {
        let invalid = disassemble_x64_linear(&[0xFF, 0xF8], 0x3000, limits(2, 10));
        assert!(matches!(
            invalid.stop_reason(),
            LinearDisassemblyStopReason::InvalidInstruction {
                rva: 0x3000,
                offset: 0
            }
        ));

        let overflow = disassemble_x64_linear(&[0x90], u64::MAX, limits(1, 1));
        assert_eq!(
            overflow.stop_reason(),
            &LinearDisassemblyStopReason::AddressOverflow {
                rva: u64::MAX,
                instruction_length: 1,
            }
        );
        assert!(overflow.rows().is_empty());
    }

    #[test]
    fn empty_input_and_invalid_limits_fail_closed() {
        let empty = disassemble_x64_linear(&[], 0x4000, limits(1, 1));
        assert_eq!(
            empty.stop_reason(),
            &LinearDisassemblyStopReason::EmptyInput
        );
        assert!(matches!(
            LinearDisassemblyLimits::new(0, 1),
            Err(LinearDisassemblyError::EmptyByteLimit)
        ));
        assert!(matches!(
            LinearDisassemblyLimits::new(1, 0),
            Err(LinearDisassemblyError::EmptyInstructionLimit)
        ));
        assert!(matches!(
            LinearDisassemblyLimits::new(MAX_LINEAR_DISASSEMBLY_BYTES + 1, 1),
            Err(LinearDisassemblyError::ByteLimitTooLarge { .. })
        ));
        assert!(matches!(
            LinearDisassemblyLimits::new(1, MAX_LINEAR_DISASSEMBLY_INSTRUCTIONS + 1),
            Err(LinearDisassemblyError::InstructionLimitTooLarge { .. })
        ));
    }
}
