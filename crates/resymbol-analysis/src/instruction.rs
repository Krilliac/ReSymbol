use iced_x86::{Decoder, DecoderOptions};
use thiserror::Error;

/// Architectural maximum length of one x86/x86-64 instruction.
pub const MAX_X64_INSTRUCTION_BYTES: usize = 15;

/// Why a byte span cannot represent exactly one complete x86-64 instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ExactX64InstructionError {
    #[error("an x86-64 instruction byte span cannot be empty")]
    Empty,
    #[error(
        "x86-64 instruction byte span has {actual} bytes; the architectural maximum is {maximum}"
    )]
    TooLong { actual: usize, maximum: usize },
    #[error("the {actual}-byte span is not one complete valid x86-64 instruction")]
    InvalidOrTruncated { actual: usize },
    #[error(
        "the first x86-64 instruction consumes {instruction} of {actual} bytes; trailing bytes are not part of that instruction"
    )]
    TrailingBytes { instruction: usize, actual: usize },
}

/// Validate that `bytes` decode as exactly one complete x86-64 instruction.
///
/// The supplied instruction pointer is used by the decoder for relative-address
/// semantics, but this function neither follows targets nor infers instruction
/// boundaries outside the exact caller-supplied span. Empty, oversized,
/// invalid, truncated, and multi-instruction spans are rejected.
pub fn validate_exact_x64_instruction(
    instruction_pointer: u64,
    bytes: &[u8],
) -> Result<(), ExactX64InstructionError> {
    if bytes.is_empty() {
        return Err(ExactX64InstructionError::Empty);
    }
    if bytes.len() > MAX_X64_INSTRUCTION_BYTES {
        return Err(ExactX64InstructionError::TooLong {
            actual: bytes.len(),
            maximum: MAX_X64_INSTRUCTION_BYTES,
        });
    }

    let mut decoder = Decoder::with_ip(64, bytes, instruction_pointer, DecoderOptions::NONE);
    let instruction = decoder.decode();
    let instruction_length = instruction.len();
    if instruction.is_invalid() || instruction_length == 0 || instruction_length > bytes.len() {
        return Err(ExactX64InstructionError::InvalidOrTruncated {
            actual: bytes.len(),
        });
    }
    if instruction_length != bytes.len() {
        return Err(ExactX64InstructionError::TrailingBytes {
            instruction: instruction_length,
            actual: bytes.len(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exactly_one_complete_instruction() {
        validate_exact_x64_instruction(0x1400_01000, &[0xe9, 3, 0, 0, 0])
            .expect("one complete relative jump");
        validate_exact_x64_instruction(0x1400_01000, &[0x74, 5])
            .expect("one complete conditional jump");
    }

    #[test]
    fn rejects_empty_oversized_invalid_truncated_and_trailing_spans() {
        assert_eq!(
            validate_exact_x64_instruction(0, &[]),
            Err(ExactX64InstructionError::Empty)
        );
        assert!(matches!(
            validate_exact_x64_instruction(0, &[0xcc; 16]),
            Err(ExactX64InstructionError::TooLong { .. })
        ));
        assert!(matches!(
            validate_exact_x64_instruction(0, &[0x0f]),
            Err(ExactX64InstructionError::InvalidOrTruncated { .. })
        ));
        assert!(matches!(
            validate_exact_x64_instruction(0, &[0xe9, 0, 0]),
            Err(ExactX64InstructionError::InvalidOrTruncated { .. })
        ));
        assert!(matches!(
            validate_exact_x64_instruction(0, &[0xcc, 0xcc]),
            Err(ExactX64InstructionError::TrailingBytes {
                instruction: 1,
                actual: 2,
            })
        ));
    }
}
