use resymbol_analysis::{
    DecodeOutcome, DecoderProfile, FlowKind, InstructionDecoder, LinearDisassemblyLimits,
    LinearDisassemblyStopReason, UnsupportedInstructionClass, decoder_for_profile,
    disassemble_linear,
};

const START: u64 = 0x1000;
const CORE_V1: DecoderProfile = DecoderProfile::Ps2EeR5900LeCoreV1;
const MMI_WORD_SHIFT_V1: DecoderProfile = DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1;

fn decoder(profile: DecoderProfile) -> Box<dyn InstructionDecoder> {
    decoder_for_profile(profile).expect("pure-Rust R5900 decoder is always available")
}

fn decode_word(profile: DecoderProfile, word: u32, address: u64) -> DecodeOutcome {
    decoder(profile).decode_one(&word.to_le_bytes(), address)
}

#[test]
fn six_exact_little_endian_vectors_decode_with_canonical_text() {
    let vectors: [(u32, [u8; 4], &str); 6] = [
        (0x7006_383c, [0x3c, 0x38, 0x06, 0x70], "psllw $a3, $a2, 0"),
        (0x7006_383e, [0x3e, 0x38, 0x06, 0x70], "psrlw $a3, $a2, 0"),
        (0x7006_383f, [0x3f, 0x38, 0x06, 0x70], "psraw $a3, $a2, 0"),
        (0x7006_3ffc, [0xfc, 0x3f, 0x06, 0x70], "psllw $a3, $a2, 31"),
        (0x7006_3ffe, [0xfe, 0x3f, 0x06, 0x70], "psrlw $a3, $a2, 31"),
        (0x7006_3fff, [0xff, 0x3f, 0x06, 0x70], "psraw $a3, $a2, 31"),
    ];

    for (word, exact_bytes, expected_text) in vectors {
        assert_eq!(word.to_le_bytes(), exact_bytes);
        let DecodeOutcome::Decoded(instruction) =
            decoder(MMI_WORD_SHIFT_V1).decode_one(&exact_bytes, START)
        else {
            panic!("expected 0x{word:08x} to decode");
        };

        assert_eq!(instruction.address, START);
        assert_eq!(instruction.length, 4);
        assert_eq!(instruction.text, expected_text);
        assert_eq!(instruction.flow, FlowKind::Sequential);
        assert_eq!(instruction.direct_target, None);
    }
}

#[test]
fn word_shift_function_codes_with_nonzero_rs_are_invalid() {
    for word in [0x7026_38fc, 0x7026_38fe, 0x7026_38ff] {
        assert_eq!(
            decode_word(MMI_WORD_SHIFT_V1, word, START),
            DecodeOutcome::Invalid,
            "0x{word:08x}"
        );
    }
}

#[test]
fn residual_canonical_mmi_word_remains_typed_unsupported() {
    assert_eq!(
        decode_word(MMI_WORD_SHIFT_V1, 0x70a6_3808, START),
        DecodeOutcome::Unsupported {
            class: UnsupportedInstructionClass::Ps2EeMmiEncoding,
        }
    );
}

#[test]
fn original_core_v1_still_rejects_every_new_word_as_typed_mmi() {
    for word in [
        0x7006_383c,
        0x7006_383e,
        0x7006_383f,
        0x7006_3ffc,
        0x7006_3ffe,
        0x7006_3fff,
    ] {
        assert_eq!(
            decode_word(CORE_V1, word, START),
            DecodeOutcome::Unsupported {
                class: UnsupportedInstructionClass::Ps2EeMmiEncoding,
            },
            "0x{word:08x}"
        );
    }
}

#[test]
fn extension_preserves_scalar_and_non_mmi_fail_closed_outcomes() {
    for opcode in 0..64_u32 {
        if opcode == 0x1c {
            continue;
        }
        let word = opcode << 26;
        assert_eq!(
            decode_word(MMI_WORD_SHIFT_V1, word, START),
            decode_word(CORE_V1, word, START),
            "primary opcode 0x{opcode:02x}"
        );
    }

    for word in [
        0x0006_38c0,
        0x00a6_3821,
        0x24a6_004c,
        0x10a6_0001,
        0x8ca6_fff0,
        0x0120_0048,
        0x4a00_0000,
    ] {
        assert_eq!(
            decode_word(MMI_WORD_SHIFT_V1, word, START),
            decode_word(CORE_V1, word, START),
            "0x{word:08x}"
        );
    }
}

#[test]
fn framing_little_endian_address_and_trailing_precedence_are_exact() {
    let word = 0x7006_383c_u32;
    let bytes = word.to_le_bytes();
    for available in 0..4 {
        assert_eq!(
            decoder(MMI_WORD_SHIFT_V1).decode_one(&bytes[..available], u64::MAX),
            DecodeOutcome::Truncated { available }
        );
    }

    assert_eq!(
        decode_word(MMI_WORD_SHIFT_V1, word, 2),
        DecodeOutcome::Invalid
    );
    assert_eq!(
        decode_word(MMI_WORD_SHIFT_V1, word, u64::from(u32::MAX) + 1),
        DecodeOutcome::Invalid
    );
    let DecodeOutcome::Decoded(last_aligned) =
        decode_word(MMI_WORD_SHIFT_V1, word, u64::from(u32::MAX) - 3)
    else {
        panic!("last aligned 32-bit address should decode");
    };
    assert_eq!(last_aligned.address, u64::from(u32::MAX) - 3);

    let mut with_trailing = bytes.to_vec();
    with_trailing.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(
        decoder(MMI_WORD_SHIFT_V1).decode_one(&with_trailing, START),
        decoder(MMI_WORD_SHIFT_V1).decode_one(&bytes, START)
    );
    assert_eq!(
        decoder(MMI_WORD_SHIFT_V1).decode_one(&word.to_be_bytes(), START),
        DecodeOutcome::Invalid
    );
}

#[test]
fn linear_sweep_preserves_the_extended_prefix_then_stops_on_residual_mmi() {
    let scalar = 0x24a6_0001_u32;
    let extended = 0x7006_383c_u32;
    let unsupported = 0x70a6_3808_u32;
    let bytes = [
        scalar.to_le_bytes(),
        extended.to_le_bytes(),
        unsupported.to_le_bytes(),
    ]
    .concat();
    let limits = LinearDisassemblyLimits::new(bytes.len(), 8).expect("valid focused limits");
    let mut decoder = decoder(MMI_WORD_SHIFT_V1);

    let preview = disassemble_linear(decoder.as_mut(), &bytes, 0x2000, limits);

    assert_eq!(preview.considered_bytes(), bytes.len());
    assert_eq!(preview.rows().len(), 2);
    assert_eq!(preview.rows()[0].rva(), 0x2000);
    assert_eq!(preview.rows()[0].bytes(), &scalar.to_le_bytes());
    assert_eq!(preview.rows()[0].text(), "addiu $a2, $a1, 1");
    assert_eq!(preview.rows()[1].rva(), 0x2004);
    assert_eq!(preview.rows()[1].bytes(), &extended.to_le_bytes());
    assert_eq!(preview.rows()[1].text(), "psllw $a3, $a2, 0");
    assert_eq!(
        preview.stop_reason(),
        &LinearDisassemblyStopReason::UnsupportedInstruction {
            rva: 0x2008,
            offset: 8,
            class: UnsupportedInstructionClass::Ps2EeMmiEncoding,
        }
    );
}
