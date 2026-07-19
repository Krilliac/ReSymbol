use resymbol_analysis::{
    DecodeOutcome, DecoderProfile, FlowKind, InstructionDecoder, LinearDisassemblyLimits,
    LinearDisassemblyStopReason, TargetArch, UnsupportedInstructionClass, decoder_for_profile,
    disassemble_linear,
};

const START: u64 = 0x1000;
const CORE_V1: DecoderProfile = DecoderProfile::Ps2EeR5900LeCoreV1;
const WORD_SHIFT_V1: DecoderProfile = DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1;
const PACKED_LOGICAL_V1: DecoderProfile =
    DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1;

fn decoder(profile: DecoderProfile) -> Box<dyn InstructionDecoder> {
    decoder_for_profile(profile).expect("pure-Rust R5900 decoder is always available")
}

fn decode_word(profile: DecoderProfile, word: u32, address: u64) -> DecodeOutcome {
    decoder(profile).decode_one(&word.to_le_bytes(), address)
}

#[test]
fn eight_exact_little_endian_vectors_match_the_frozen_mask_and_text() {
    const MASK: u32 = 0xfc00_07ff;
    let vectors: [(u32, [u8; 4], u32, &str); 8] = [
        (
            0x70a6_3c89,
            [0x89, 0x3c, 0xa6, 0x70],
            0x7000_0489,
            "pand $a3, $a1, $a2",
        ),
        (
            0x70a6_3ca9,
            [0xa9, 0x3c, 0xa6, 0x70],
            0x7000_04a9,
            "por $a3, $a1, $a2",
        ),
        (
            0x70a6_3cc9,
            [0xc9, 0x3c, 0xa6, 0x70],
            0x7000_04c9,
            "pxor $a3, $a1, $a2",
        ),
        (
            0x70a6_3ce9,
            [0xe9, 0x3c, 0xa6, 0x70],
            0x7000_04e9,
            "pnor $a3, $a1, $a2",
        ),
        (
            0x73e1_0489,
            [0x89, 0x04, 0xe1, 0x73],
            0x7000_0489,
            "pand $zero, $ra, $at",
        ),
        (
            0x73e1_04a9,
            [0xa9, 0x04, 0xe1, 0x73],
            0x7000_04a9,
            "por $zero, $ra, $at",
        ),
        (
            0x73e1_04c9,
            [0xc9, 0x04, 0xe1, 0x73],
            0x7000_04c9,
            "pxor $zero, $ra, $at",
        ),
        (
            0x73e1_04e9,
            [0xe9, 0x04, 0xe1, 0x73],
            0x7000_04e9,
            "pnor $zero, $ra, $at",
        ),
    ];

    for (word, exact_bytes, pattern, expected_text) in vectors {
        assert_eq!(word.to_le_bytes(), exact_bytes);
        assert_eq!(word & MASK, pattern);
        let DecodeOutcome::Decoded(instruction) =
            decoder(PACKED_LOGICAL_V1).decode_one(&exact_bytes, START)
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
fn selector_and_function_near_misses_remain_typed_mmi_unsupported() {
    for word in [0x70a6_3808, 0x70a6_3c49, 0x70a6_3d09, 0x70a6_3c88] {
        assert_eq!(
            decode_word(PACKED_LOGICAL_V1, word, START),
            DecodeOutcome::Unsupported {
                class: UnsupportedInstructionClass::Ps2EeMmiEncoding,
            },
            "0x{word:08x}"
        );
    }
}

#[test]
fn excluded_halfword_shift_alias_space_remains_typed_mmi_unsupported() {
    for word in [
        0x7006_3834,
        0x7006_3836,
        0x7006_3837,
        0x7006_3c34,
        0x7006_3c36,
        0x7006_3c37,
    ] {
        assert_eq!(
            decode_word(PACKED_LOGICAL_V1, word, START),
            DecodeOutcome::Unsupported {
                class: UnsupportedInstructionClass::Ps2EeMmiEncoding,
            },
            "0x{word:08x}"
        );
    }
}

#[test]
fn both_prior_profiles_remain_immutable_and_typed_unsupported() {
    for profile in [CORE_V1, WORD_SHIFT_V1] {
        for word in [0x70a6_3c89, 0x70a6_3ca9, 0x70a6_3cc9, 0x70a6_3ce9] {
            assert_eq!(
                decode_word(profile, word, START),
                DecodeOutcome::Unsupported {
                    class: UnsupportedInstructionClass::Ps2EeMmiEncoding,
                },
                "{profile}: 0x{word:08x}"
            );
        }
    }
}

#[test]
fn extension_preserves_every_frozen_word_shift_disposition() {
    for word in [
        0x7006_383c,
        0x7006_383e,
        0x7006_383f,
        0x7006_3ffc,
        0x7006_3ffe,
        0x7006_3fff,
        0x7026_38fc,
        0x7026_38fe,
        0x7026_38ff,
        0x70a6_3808,
    ] {
        assert_eq!(
            decode_word(PACKED_LOGICAL_V1, word, START),
            decode_word(WORD_SHIFT_V1, word, START),
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
            decode_word(PACKED_LOGICAL_V1, word, START),
            decode_word(WORD_SHIFT_V1, word, START),
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
            decode_word(PACKED_LOGICAL_V1, word, START),
            decode_word(WORD_SHIFT_V1, word, START),
            "0x{word:08x}"
        );
    }
}

#[test]
fn framing_little_endian_address_and_trailing_precedence_are_exact() {
    let word = 0x70a6_3cc9_u32;
    let bytes = word.to_le_bytes();
    for available in 0..4 {
        assert_eq!(
            decoder(PACKED_LOGICAL_V1).decode_one(&bytes[..available], u64::MAX),
            DecodeOutcome::Truncated { available }
        );
    }

    assert_eq!(
        decode_word(PACKED_LOGICAL_V1, word, 2),
        DecodeOutcome::Invalid
    );
    assert_eq!(
        decode_word(PACKED_LOGICAL_V1, word, u64::from(u32::MAX) + 1),
        DecodeOutcome::Invalid
    );
    let DecodeOutcome::Decoded(last_aligned) =
        decode_word(PACKED_LOGICAL_V1, word, u64::from(u32::MAX) - 3)
    else {
        panic!("last aligned 32-bit address should decode");
    };
    assert_eq!(last_aligned.address, u64::from(u32::MAX) - 3);

    let mut with_trailing = bytes.to_vec();
    with_trailing.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(
        decoder(PACKED_LOGICAL_V1).decode_one(&with_trailing, START),
        decoder(PACKED_LOGICAL_V1).decode_one(&bytes, START)
    );
    assert_eq!(
        decoder(PACKED_LOGICAL_V1).decode_one(&word.to_be_bytes(), START),
        DecodeOutcome::Invalid
    );
}

#[test]
fn linear_sweep_preserves_the_packed_logical_prefix_then_stops_on_residual_mmi() {
    let first = 0x70a6_3c89_u32;
    let unsupported = 0x70a6_3808_u32;
    let third = 0x24a6_0001_u32;
    let bytes = [
        first.to_le_bytes(),
        unsupported.to_le_bytes(),
        third.to_le_bytes(),
    ]
    .concat();
    let limits = LinearDisassemblyLimits::new(bytes.len(), 8).expect("valid focused limits");
    let mut decoder = decoder(PACKED_LOGICAL_V1);

    let preview = disassemble_linear(decoder.as_mut(), &bytes, 0x2000, limits);

    assert_eq!(preview.considered_bytes(), bytes.len());
    assert_eq!(preview.rows().len(), 1);
    assert_eq!(preview.rows()[0].rva(), 0x2000);
    assert_eq!(preview.rows()[0].bytes(), &first.to_le_bytes());
    assert_eq!(preview.rows()[0].text(), "pand $a3, $a1, $a2");
    assert_eq!(
        preview.stop_reason(),
        &LinearDisassemblyStopReason::UnsupportedInstruction {
            rva: 0x2004,
            offset: 4,
            class: UnsupportedInstructionClass::Ps2EeMmiEncoding,
        }
    );
}

#[test]
fn exact_profile_identity_is_authoritative_over_the_broad_family() {
    let decoder = decoder(PACKED_LOGICAL_V1);
    assert_eq!(decoder.profile(), PACKED_LOGICAL_V1);
    assert_eq!(decoder.arch(), TargetArch::Mips64);
}
