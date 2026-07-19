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
const PACKED_ADD_V1: DecoderProfile =
    DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1;

fn decoder(profile: DecoderProfile) -> Box<dyn InstructionDecoder> {
    decoder_for_profile(profile).expect("pure-Rust R5900 decoder is always available")
}

fn decode_word(profile: DecoderProfile, word: u32, address: u64) -> DecodeOutcome {
    decoder(profile).decode_one(&word.to_le_bytes(), address)
}

const fn nested_mmi_word(function: u32, secondary: u32, rs: u32, rt: u32, rd: u32) -> u32 {
    (0x1c << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (secondary << 6) | function
}

#[test]
fn six_exact_little_endian_vectors_match_the_frozen_mask_and_text() {
    const MASK: u32 = 0xfc00_07ff;
    let vectors: [(u32, [u8; 4], u32, &str); 6] = [
        (
            0x70a6_3808,
            [0x08, 0x38, 0xa6, 0x70],
            0x7000_0008,
            "paddw $a3, $a1, $a2",
        ),
        (
            0x70a6_3908,
            [0x08, 0x39, 0xa6, 0x70],
            0x7000_0108,
            "paddh $a3, $a1, $a2",
        ),
        (
            0x70a6_3a08,
            [0x08, 0x3a, 0xa6, 0x70],
            0x7000_0208,
            "paddb $a3, $a1, $a2",
        ),
        (
            0x73e1_0008,
            [0x08, 0x00, 0xe1, 0x73],
            0x7000_0008,
            "paddw $zero, $ra, $at",
        ),
        (
            0x73e1_0108,
            [0x08, 0x01, 0xe1, 0x73],
            0x7000_0108,
            "paddh $zero, $ra, $at",
        ),
        (
            0x73e1_0208,
            [0x08, 0x02, 0xe1, 0x73],
            0x7000_0208,
            "paddb $zero, $ra, $at",
        ),
    ];

    for (word, exact_bytes, pattern, expected_text) in vectors {
        assert_eq!(word.to_le_bytes(), exact_bytes);
        assert_eq!(word & MASK, pattern);
        let DecodeOutcome::Decoded(instruction) =
            decoder(PACKED_ADD_V1).decode_one(&exact_bytes, START)
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
fn selector_function_and_arithmetic_family_near_misses_remain_typed_mmi_unsupported() {
    for word in [
        0x70a6_3848,
        0x70a6_3888,
        0x70a6_38c8,
        0x70a6_3c08,
        0x70a6_3c28,
        0x70a6_3809,
    ] {
        assert_eq!(
            decode_word(PACKED_ADD_V1, word, START),
            DecodeOutcome::Unsupported {
                class: UnsupportedInstructionClass::Ps2EeMmiEncoding,
            },
            "0x{word:08x}"
        );
    }
}

#[test]
fn all_three_prior_profiles_remain_immutable_and_typed_unsupported() {
    for profile in [CORE_V1, WORD_SHIFT_V1, PACKED_LOGICAL_V1] {
        for word in [
            0x70a6_3808,
            0x70a6_3908,
            0x70a6_3a08,
            0x73e1_0008,
            0x73e1_0108,
            0x73e1_0208,
        ] {
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
fn extension_preserves_every_frozen_word_shift_and_packed_logical_disposition() {
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
        0x70a6_3c89,
        0x70a6_3ca9,
        0x70a6_3cc9,
        0x70a6_3ce9,
        0x73e1_0489,
        0x73e1_04a9,
        0x73e1_04c9,
        0x73e1_04e9,
        0x70a6_3c49,
        0x70a6_3d09,
        0x70a6_3c88,
        0x7006_3834,
        0x7006_3836,
        0x7006_3837,
        0x7006_3c34,
        0x7006_3c36,
        0x7006_3c37,
    ] {
        assert_eq!(
            decode_word(PACKED_ADD_V1, word, START),
            decode_word(PACKED_LOGICAL_V1, word, START),
            "0x{word:08x}"
        );
    }
}

#[test]
fn every_nested_mmi_selector_differs_from_the_parent_only_for_the_three_additions() {
    for function in [0x08_u32, 0x09, 0x28, 0x29] {
        for secondary in 0..32_u32 {
            let word = nested_mmi_word(function, secondary, 5, 6, 7);
            if function == 0x08 && matches!(secondary, 0x00 | 0x04 | 0x08) {
                let expected_text = match secondary {
                    0x00 => "paddw $a3, $a1, $a2",
                    0x04 => "paddh $a3, $a1, $a2",
                    0x08 => "paddb $a3, $a1, $a2",
                    _ => unreachable!(),
                };
                let DecodeOutcome::Decoded(instruction) = decode_word(PACKED_ADD_V1, word, START)
                else {
                    panic!("expected 0x{word:08x} to decode");
                };
                assert_eq!(instruction.text, expected_text);
                assert_eq!(
                    decode_word(PACKED_LOGICAL_V1, word, START),
                    DecodeOutcome::Unsupported {
                        class: UnsupportedInstructionClass::Ps2EeMmiEncoding,
                    }
                );
            } else {
                assert_eq!(
                    decode_word(PACKED_ADD_V1, word, START),
                    decode_word(PACKED_LOGICAL_V1, word, START),
                    "function 0x{function:02x}, secondary 0x{secondary:02x}"
                );
            }
        }
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
            decode_word(PACKED_ADD_V1, word, START),
            decode_word(PACKED_LOGICAL_V1, word, START),
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
            decode_word(PACKED_ADD_V1, word, START),
            decode_word(PACKED_LOGICAL_V1, word, START),
            "0x{word:08x}"
        );
    }
}

#[test]
fn framing_little_endian_address_trailing_and_swapped_word_inheritance_are_exact() {
    let word = 0x70a6_3808_u32;
    let bytes = word.to_le_bytes();
    for available in 0..4 {
        assert_eq!(
            decoder(PACKED_ADD_V1).decode_one(&bytes[..available], u64::MAX),
            DecodeOutcome::Truncated { available }
        );
    }

    assert_eq!(decode_word(PACKED_ADD_V1, word, 2), DecodeOutcome::Invalid);
    assert_eq!(
        decode_word(PACKED_ADD_V1, word, u64::from(u32::MAX) + 1),
        DecodeOutcome::Invalid
    );
    let DecodeOutcome::Decoded(last_aligned) =
        decode_word(PACKED_ADD_V1, word, u64::from(u32::MAX) - 3)
    else {
        panic!("last aligned 32-bit address should decode");
    };
    assert_eq!(last_aligned.address, u64::from(u32::MAX) - 3);

    let mut with_trailing = bytes.to_vec();
    with_trailing.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(
        decoder(PACKED_ADD_V1).decode_one(&with_trailing, START),
        decoder(PACKED_ADD_V1).decode_one(&bytes, START)
    );

    let swapped_outcome = decoder(PACKED_ADD_V1).decode_one(&word.to_be_bytes(), START);
    assert_eq!(
        swapped_outcome,
        decode_word(PACKED_ADD_V1, word.swap_bytes(), START)
    );
    let DecodeOutcome::Decoded(swapped) = swapped_outcome else {
        panic!("the byte-swapped word inherits a valid scalar jump disposition");
    };
    assert_eq!(swapped.text, "j 0x00e299c0");
    assert_eq!(swapped.flow, FlowKind::UnconditionalBranch);
    assert_eq!(swapped.direct_target, Some(0x00e2_99c0));
}

#[test]
fn linear_sweep_preserves_prior_and_packed_add_prefix_then_stops_on_residual_mmi() {
    let logical = 0x70a6_3c89_u32;
    let added = 0x70a6_3808_u32;
    let unsupported = 0x70a6_3848_u32;
    let fourth = 0x24a6_0001_u32;
    let bytes = [
        logical.to_le_bytes(),
        added.to_le_bytes(),
        unsupported.to_le_bytes(),
        fourth.to_le_bytes(),
    ]
    .concat();
    let limits = LinearDisassemblyLimits::new(bytes.len(), 8).expect("valid focused limits");
    let mut decoder = decoder(PACKED_ADD_V1);

    let preview = disassemble_linear(decoder.as_mut(), &bytes, 0x2000, limits);

    assert_eq!(preview.considered_bytes(), bytes.len());
    assert_eq!(preview.rows().len(), 2);
    assert_eq!(preview.rows()[0].rva(), 0x2000);
    assert_eq!(preview.rows()[0].bytes(), &logical.to_le_bytes());
    assert_eq!(preview.rows()[0].text(), "pand $a3, $a1, $a2");
    assert_eq!(preview.rows()[1].rva(), 0x2004);
    assert_eq!(preview.rows()[1].bytes(), &added.to_le_bytes());
    assert_eq!(preview.rows()[1].text(), "paddw $a3, $a1, $a2");
    assert_eq!(
        preview.stop_reason(),
        &LinearDisassemblyStopReason::UnsupportedInstruction {
            rva: 0x2008,
            offset: 8,
            class: UnsupportedInstructionClass::Ps2EeMmiEncoding,
        }
    );
}

#[test]
fn exact_profile_identity_is_authoritative_over_the_broad_family() {
    let decoder = decoder(PACKED_ADD_V1);
    assert_eq!(decoder.profile(), PACKED_ADD_V1);
    assert_eq!(decoder.arch(), TargetArch::Mips64);
}
