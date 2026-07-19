use resymbol_analysis::{
    DecodeOutcome, DecoderProfile, FlowKind, LinearDisassemblyLimits, LinearDisassemblyStopReason,
    TargetArch, UnsupportedInstructionClass, decoder_for_profile, disassemble_linear,
};

const START: u64 = 0x1000;

const fn special(rs: u32, rt: u32, rd: u32, sa: u32, function: u32) -> u32 {
    (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | function
}

const fn immediate(opcode: u32, rs: u32, rt: u32, value: u16) -> u32 {
    (opcode << 26) | (rs << 21) | (rt << 16) | value as u32
}

const fn jump(opcode: u32, index: u32) -> u32 {
    (opcode << 26) | (index & 0x03ff_ffff)
}

const fn special_code(code: u32, function: u32) -> u32 {
    ((code & 0x000f_ffff) << 6) | function
}

fn decoder() -> Box<dyn resymbol_analysis::InstructionDecoder> {
    decoder_for_profile(DecoderProfile::Ps2EeR5900LeCoreV1)
        .expect("pure-Rust R5900 decoder is always available")
}

fn decode_word(word: u32, address: u64) -> DecodeOutcome {
    decoder().decode_one(&word.to_le_bytes(), address)
}

fn assert_decoded(
    word: u32,
    expected_text: &str,
    expected_flow: FlowKind,
    expected_target: Option<u64>,
) {
    let DecodeOutcome::Decoded(instruction) = decode_word(word, START) else {
        panic!("expected 0x{word:08x} to decode");
    };
    assert_eq!(instruction.address, START);
    assert_eq!(instruction.length, 4);
    assert_eq!(instruction.text, expected_text);
    assert_eq!(instruction.flow, expected_flow);
    assert_eq!(instruction.direct_target, expected_target);
}

#[test]
fn golden_vector_covers_every_core_v1_whitelist_mnemonic() {
    let sequential = [
        (special(0, 6, 7, 3, 0x00), "sll $a3, $a2, 3"),
        (special(0, 6, 7, 3, 0x02), "srl $a3, $a2, 3"),
        (special(0, 6, 7, 3, 0x03), "sra $a3, $a2, 3"),
        (special(5, 6, 7, 0, 0x04), "sllv $a3, $a2, $a1"),
        (special(5, 6, 7, 0, 0x06), "srlv $a3, $a2, $a1"),
        (special(5, 6, 7, 0, 0x07), "srav $a3, $a2, $a1"),
        (special(5, 6, 7, 0, 0x0a), "movz $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x0b), "movn $a3, $a1, $a2"),
        (special(0, 0, 7, 0, 0x10), "mfhi $a3"),
        (special(5, 0, 0, 0, 0x11), "mthi $a1"),
        (special(0, 0, 7, 0, 0x12), "mflo $a3"),
        (special(5, 0, 0, 0, 0x13), "mtlo $a1"),
        (special(5, 6, 7, 0, 0x14), "dsllv $a3, $a2, $a1"),
        (special(5, 6, 7, 0, 0x16), "dsrlv $a3, $a2, $a1"),
        (special(5, 6, 7, 0, 0x17), "dsrav $a3, $a2, $a1"),
        (special(5, 6, 7, 0, 0x18), "mult $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x19), "multu $a3, $a1, $a2"),
        (special(5, 6, 0, 0, 0x1a), "div $a1, $a2"),
        (special(5, 6, 0, 0, 0x1b), "divu $a1, $a2"),
        (special(5, 6, 7, 0, 0x20), "add $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x21), "addu $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x22), "sub $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x23), "subu $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x24), "and $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x25), "or $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x26), "xor $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x27), "nor $a3, $a1, $a2"),
        (special(0, 0, 7, 0, 0x28), "mfsa $a3"),
        (special(5, 0, 0, 0, 0x29), "mtsa $a1"),
        (special(5, 6, 7, 0, 0x2a), "slt $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x2b), "sltu $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x2c), "dadd $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x2d), "daddu $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x2e), "dsub $a3, $a1, $a2"),
        (special(5, 6, 7, 0, 0x2f), "dsubu $a3, $a1, $a2"),
        (special(0, 6, 7, 3, 0x38), "dsll $a3, $a2, 3"),
        (special(0, 6, 7, 3, 0x3a), "dsrl $a3, $a2, 3"),
        (special(0, 6, 7, 3, 0x3b), "dsra $a3, $a2, 3"),
        (special(0, 6, 7, 3, 0x3c), "dsll32 $a3, $a2, 3"),
        (special(0, 6, 7, 3, 0x3e), "dsrl32 $a3, $a2, 3"),
        (special(0, 6, 7, 3, 0x3f), "dsra32 $a3, $a2, 3"),
        (immediate(0x08, 5, 6, 0xfffc), "addi $a2, $a1, -4"),
        (immediate(0x09, 5, 6, 0xfffc), "addiu $a2, $a1, -4"),
        (immediate(0x0a, 5, 6, 0xfffc), "slti $a2, $a1, -4"),
        (immediate(0x0b, 5, 6, 0xfffc), "sltiu $a2, $a1, -4"),
        (immediate(0x0c, 5, 6, 0xabcd), "andi $a2, $a1, 0xabcd"),
        (immediate(0x0d, 5, 6, 0xabcd), "ori $a2, $a1, 0xabcd"),
        (immediate(0x0e, 5, 6, 0xabcd), "xori $a2, $a1, 0xabcd"),
        (immediate(0x0f, 0, 6, 0xabcd), "lui $a2, 0xabcd"),
        (immediate(0x18, 5, 6, 0xfffc), "daddi $a2, $a1, -4"),
        (immediate(0x19, 5, 6, 0xfffc), "daddiu $a2, $a1, -4"),
        (immediate(0x1a, 5, 6, 0xfffc), "ldl $a2, -4($a1)"),
        (immediate(0x1b, 5, 6, 0xfffc), "ldr $a2, -4($a1)"),
        (immediate(0x1e, 5, 6, 0xfffc), "lq $a2, -4($a1)"),
        (immediate(0x1f, 5, 6, 0xfffc), "sq $a2, -4($a1)"),
        (immediate(0x20, 5, 6, 0xfffc), "lb $a2, -4($a1)"),
        (immediate(0x21, 5, 6, 0xfffc), "lh $a2, -4($a1)"),
        (immediate(0x22, 5, 6, 0xfffc), "lwl $a2, -4($a1)"),
        (immediate(0x23, 5, 6, 0xfffc), "lw $a2, -4($a1)"),
        (immediate(0x24, 5, 6, 0xfffc), "lbu $a2, -4($a1)"),
        (immediate(0x25, 5, 6, 0xfffc), "lhu $a2, -4($a1)"),
        (immediate(0x26, 5, 6, 0xfffc), "lwr $a2, -4($a1)"),
        (immediate(0x27, 5, 6, 0xfffc), "lwu $a2, -4($a1)"),
        (immediate(0x28, 5, 6, 0xfffc), "sb $a2, -4($a1)"),
        (immediate(0x29, 5, 6, 0xfffc), "sh $a2, -4($a1)"),
        (immediate(0x2a, 5, 6, 0xfffc), "swl $a2, -4($a1)"),
        (immediate(0x2b, 5, 6, 0xfffc), "sw $a2, -4($a1)"),
        (immediate(0x2c, 5, 6, 0xfffc), "sdl $a2, -4($a1)"),
        (immediate(0x2d, 5, 6, 0xfffc), "sdr $a2, -4($a1)"),
        (immediate(0x2e, 5, 6, 0xfffc), "swr $a2, -4($a1)"),
        (immediate(0x2f, 29, 31, 0xfff0), "cache 0x1f, -16($sp)"),
        (immediate(0x33, 29, 0, 0), "pref 0x00, 0($sp)"),
        (immediate(0x37, 5, 6, 0xfffc), "ld $a2, -4($a1)"),
        (immediate(0x3f, 5, 6, 0xfffc), "sd $a2, -4($a1)"),
        (immediate(0x01, 5, 0x18, 0xabcd), "mtsab $a1, 0xabcd"),
        (immediate(0x01, 29, 0x19, 0x8007), "mtsah $sp, 0x8007"),
    ];

    for (word, text) in sequential {
        assert_decoded(word, text, FlowKind::Sequential, None);
    }

    let conditional = [
        (immediate(0x04, 5, 6, 0xfffc), "beq $a1, $a2, 0x00000ff4"),
        (immediate(0x05, 5, 6, 0xfffc), "bne $a1, $a2, 0x00000ff4"),
        (immediate(0x06, 5, 0, 0xfffc), "blez $a1, 0x00000ff4"),
        (immediate(0x07, 5, 0, 0xfffc), "bgtz $a1, 0x00000ff4"),
        (immediate(0x14, 5, 6, 0xfffc), "beql $a1, $a2, 0x00000ff4"),
        (immediate(0x15, 5, 6, 0xfffc), "bnel $a1, $a2, 0x00000ff4"),
        (immediate(0x16, 5, 0, 0xfffc), "blezl $a1, 0x00000ff4"),
        (immediate(0x17, 5, 0, 0xfffc), "bgtzl $a1, 0x00000ff4"),
        (immediate(0x01, 5, 0x00, 0xfffc), "bltz $a1, 0x00000ff4"),
        (immediate(0x01, 5, 0x01, 0xfffc), "bgez $a1, 0x00000ff4"),
        (immediate(0x01, 5, 0x02, 0xfffc), "bltzl $a1, 0x00000ff4"),
        (immediate(0x01, 5, 0x03, 0xfffc), "bgezl $a1, 0x00000ff4"),
        (immediate(0x01, 5, 0x10, 0xfffc), "bltzal $a1, 0x00000ff4"),
        (immediate(0x01, 5, 0x11, 0xfffc), "bgezal $a1, 0x00000ff4"),
        (immediate(0x01, 5, 0x12, 0xfffc), "bltzall $a1, 0x00000ff4"),
        (immediate(0x01, 5, 0x13, 0xfffc), "bgezall $a1, 0x00000ff4"),
    ];
    for (word, text) in conditional {
        assert_decoded(word, text, FlowKind::ConditionalBranch, Some(0x0ff4));
    }

    assert_decoded(
        jump(0x02, 0x0001_2345),
        "j 0x00048d14",
        FlowKind::UnconditionalBranch,
        Some(0x0004_8d14),
    );
    assert_decoded(
        jump(0x03, 0x0001_2345),
        "jal 0x00048d14",
        FlowKind::Call,
        Some(0x0004_8d14),
    );
    assert_decoded(
        special(5, 0, 0, 0, 0x08),
        "jr $a1",
        FlowKind::IndirectBranch,
        None,
    );
    assert_decoded(
        special(5, 0, 7, 0, 0x09),
        "jalr $a3, $a1",
        FlowKind::IndirectCall,
        None,
    );
    assert_decoded(
        special_code(0x000f_ffff, 0x0c),
        "syscall 0xfffff",
        FlowKind::Interrupt,
        None,
    );
    assert_decoded(
        special_code(0x000f_ffff, 0x0d),
        "break 0xfffff",
        FlowKind::Interrupt,
        None,
    );
    assert_decoded(
        special(0, 0, 0, 0x1f, 0x0f),
        "sync 0x1f",
        FlowKind::Sequential,
        None,
    );

    assert_decoded(0, "sll $zero, $zero, 0", FlowKind::Sequential, None);
    assert_decoded(
        special_code(0, 0x0c),
        "syscall 0x00000",
        FlowKind::Interrupt,
        None,
    );
}

#[test]
fn all_abi_register_names_are_canonical_including_fp() {
    let names = [
        "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", "$t0", "$t1", "$t2", "$t3",
        "$t4", "$t5", "$t6", "$t7", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$t8",
        "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
    ];

    for (index, name) in names.iter().enumerate() {
        assert_decoded(
            special(0, 0, index as u32, 0, 0x10),
            &format!("mfhi {name}"),
            FlowKind::Sequential,
            None,
        );
    }
}

#[test]
fn reserved_fields_fail_closed() {
    let invalid_words = [
        special(1, 6, 7, 3, 0x00),
        special(5, 6, 7, 1, 0x04),
        special(5, 1, 0, 0, 0x08),
        special(5, 0, 1, 0, 0x08),
        special(5, 0, 0, 1, 0x08),
        special(5, 1, 7, 0, 0x09),
        special(5, 0, 7, 1, 0x09),
        special(5, 6, 7, 1, 0x0a),
        special(1, 0, 7, 0, 0x10),
        special(0, 1, 7, 0, 0x10),
        special(0, 0, 7, 1, 0x10),
        special(5, 1, 0, 0, 0x11),
        special(5, 0, 1, 0, 0x11),
        special(5, 0, 0, 1, 0x11),
        special(5, 6, 7, 1, 0x18),
        special(5, 6, 1, 0, 0x1a),
        special(5, 6, 0, 1, 0x1a),
        special(5, 6, 7, 1, 0x20),
        special(1, 0, 7, 0, 0x28),
        special(0, 1, 7, 0, 0x28),
        special(0, 0, 7, 1, 0x28),
        special(5, 1, 0, 0, 0x29),
        special(5, 0, 1, 0, 0x29),
        special(5, 0, 0, 1, 0x29),
        special(1, 6, 7, 3, 0x38),
        immediate(0x06, 5, 1, 0),
        immediate(0x07, 5, 1, 0),
        immediate(0x16, 5, 1, 0),
        immediate(0x17, 5, 1, 0),
        immediate(0x0f, 1, 6, 0),
        immediate(0x01, 5, 0x1a, 0),
    ];

    for word in invalid_words {
        assert_eq!(
            decode_word(word, START),
            DecodeOutcome::Invalid,
            "0x{word:08x}"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeKind {
    Decoded,
    Invalid,
    Unsupported(UnsupportedInstructionClass),
}

#[test]
fn every_primary_opcode_space_has_an_explicit_fail_closed_disposition() {
    let expected = [
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Unsupported(UnsupportedInstructionClass::Ps2EeCop0Encoding),
        OutcomeKind::Unsupported(UnsupportedInstructionClass::Ps2EeCop1Encoding),
        OutcomeKind::Unsupported(UnsupportedInstructionClass::Ps2EeCop2Encoding),
        OutcomeKind::Invalid,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Unsupported(UnsupportedInstructionClass::Ps2EeMmiEncoding),
        OutcomeKind::Invalid,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Decoded,
        OutcomeKind::Invalid,
        OutcomeKind::Unsupported(UnsupportedInstructionClass::Ps2EeCop1Encoding),
        OutcomeKind::Invalid,
        OutcomeKind::Decoded,
        OutcomeKind::Invalid,
        OutcomeKind::Invalid,
        OutcomeKind::Unsupported(UnsupportedInstructionClass::Ps2EeCop2Encoding),
        OutcomeKind::Decoded,
        OutcomeKind::Invalid,
        OutcomeKind::Unsupported(UnsupportedInstructionClass::Ps2EeCop1Encoding),
        OutcomeKind::Invalid,
        OutcomeKind::Invalid,
        OutcomeKind::Invalid,
        OutcomeKind::Invalid,
        OutcomeKind::Unsupported(UnsupportedInstructionClass::Ps2EeCop2Encoding),
        OutcomeKind::Decoded,
    ];

    assert_eq!(expected.len(), 64);
    for (opcode, expected) in expected.into_iter().enumerate() {
        let outcome = decode_word((opcode as u32) << 26, START);
        let actual = match outcome {
            DecodeOutcome::Decoded(_) => OutcomeKind::Decoded,
            DecodeOutcome::Invalid => OutcomeKind::Invalid,
            DecodeOutcome::Unsupported { class } => OutcomeKind::Unsupported(class),
            DecodeOutcome::Truncated { .. } => panic!("four bytes cannot truncate"),
            _ => panic!("unexpected future decode outcome"),
        };
        assert_eq!(actual, expected, "primary opcode 0x{opcode:02x}");
    }
}

#[test]
fn unsupported_ee_spaces_and_conditional_traps_are_typed() {
    let cases = [
        (
            0x1c_u32 << 26,
            UnsupportedInstructionClass::Ps2EeMmiEncoding,
        ),
        (
            0x10_u32 << 26,
            UnsupportedInstructionClass::Ps2EeCop0Encoding,
        ),
        (
            0x11_u32 << 26,
            UnsupportedInstructionClass::Ps2EeCop1Encoding,
        ),
        (
            0x31_u32 << 26,
            UnsupportedInstructionClass::Ps2EeCop1Encoding,
        ),
        (
            0x39_u32 << 26,
            UnsupportedInstructionClass::Ps2EeCop1Encoding,
        ),
        (
            immediate(0x12, 0x0f, 0, 0),
            UnsupportedInstructionClass::Ps2EeCop2Encoding,
        ),
        (
            0x36_u32 << 26,
            UnsupportedInstructionClass::Ps2EeCop2Encoding,
        ),
        (
            0x3e_u32 << 26,
            UnsupportedInstructionClass::Ps2EeCop2Encoding,
        ),
        (
            immediate(0x12, 0x10, 0, 0),
            UnsupportedInstructionClass::Ps2EeVuMacroEncoding,
        ),
    ];

    for (word, class) in cases {
        assert_eq!(
            decode_word(word, START),
            DecodeOutcome::Unsupported { class }
        );
    }

    for function in [0x30, 0x31, 0x32, 0x33, 0x34, 0x36] {
        assert_eq!(
            decode_word(special(31, 31, 31, 31, function), START),
            DecodeOutcome::Unsupported {
                class: UnsupportedInstructionClass::Ps2EeConditionalTrapEncoding
            }
        );
    }
    for selector in [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0e] {
        assert_eq!(
            decode_word(immediate(0x01, 31, selector, 0xffff), START),
            DecodeOutcome::Unsupported {
                class: UnsupportedInstructionClass::Ps2EeConditionalTrapEncoding
            }
        );
    }
}

#[test]
fn byte_order_length_address_and_trailing_byte_rules_are_exact() {
    let word = immediate(0x09, 5, 6, 0x004c);
    for available in 0..4 {
        let bytes = word.to_le_bytes();
        assert_eq!(
            decoder().decode_one(&bytes[..available], u64::MAX),
            DecodeOutcome::Truncated { available }
        );
    }

    assert_eq!(decode_word(word, 2), DecodeOutcome::Invalid);
    assert_eq!(
        decode_word(word, u64::from(u32::MAX) + 1),
        DecodeOutcome::Invalid
    );
    assert!(matches!(
        decode_word(word, u64::from(u32::MAX) - 3),
        DecodeOutcome::Decoded(_)
    ));

    let mut with_trailing = word.to_le_bytes().to_vec();
    with_trailing.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(
        decoder().decode_one(&with_trailing, START),
        decoder().decode_one(&word.to_le_bytes(), START)
    );
    assert_eq!(
        decoder().decode_one(&word.to_be_bytes(), START),
        DecodeOutcome::Invalid
    );
}

#[test]
fn branch_and_jump_targets_use_wrapping_32_bit_pc_rules() {
    let branch_back = decode_word(immediate(0x04, 1, 2, 0xffff), 0xffff_fffc);
    let DecodeOutcome::Decoded(branch_back) = branch_back else {
        panic!("branch should decode");
    };
    assert_eq!(branch_back.direct_target, Some(0xffff_fffc));
    assert_eq!(branch_back.text, "beq $at, $v0, 0xfffffffc");

    let branch_forward = decode_word(immediate(0x05, 1, 2, 1), 0xffff_fffc);
    let DecodeOutcome::Decoded(branch_forward) = branch_forward else {
        panic!("branch should decode");
    };
    assert_eq!(branch_forward.direct_target, Some(4));
    assert_eq!(branch_forward.text, "bne $at, $v0, 0x00000004");

    let region_carry = decode_word(jump(0x02, 0), 0x0fff_fffc);
    let DecodeOutcome::Decoded(region_carry) = region_carry else {
        panic!("jump should decode");
    };
    assert_eq!(region_carry.direct_target, Some(0x1000_0000));
    assert_eq!(region_carry.text, "j 0x10000000");

    let pc_wrap = decode_word(jump(0x03, 0), 0xffff_fffc);
    let DecodeOutcome::Decoded(pc_wrap) = pc_wrap else {
        panic!("jump should decode");
    };
    assert_eq!(pc_wrap.direct_target, Some(0));
    assert_eq!(pc_wrap.text, "jal 0x00000000");
}

#[test]
fn jalr_zero_destination_is_an_indirect_branch_not_a_call() {
    assert_decoded(
        special(5, 0, 0, 0, 0x09),
        "jalr $zero, $a1",
        FlowKind::IndirectBranch,
        None,
    );
    assert_decoded(
        special(5, 0, 31, 0, 0x09),
        "jalr $ra, $a1",
        FlowKind::IndirectCall,
        None,
    );
}

#[test]
fn linear_sweep_preserves_the_accepted_prefix_then_stops_on_typed_unsupported_word() {
    let first = immediate(0x09, 5, 6, 1);
    let unsupported = 0x1c_u32 << 26;
    let third = immediate(0x09, 6, 7, 2);
    let bytes = [
        first.to_le_bytes(),
        unsupported.to_le_bytes(),
        third.to_le_bytes(),
    ]
    .concat();
    let limits = LinearDisassemblyLimits::new(bytes.len(), 8).expect("valid focused limits");
    let mut decoder = decoder();

    let preview = disassemble_linear(decoder.as_mut(), &bytes, 0x2000, limits);

    assert_eq!(preview.considered_bytes(), bytes.len());
    assert_eq!(preview.rows().len(), 1);
    assert_eq!(preview.rows()[0].rva(), 0x2000);
    assert_eq!(preview.rows()[0].bytes(), &first.to_le_bytes());
    assert_eq!(preview.rows()[0].text(), "addiu $a2, $a1, 1");
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
fn exact_profile_identity_is_authoritative_over_broad_architecture_family() {
    let decoder = decoder();
    assert_eq!(decoder.profile(), DecoderProfile::Ps2EeR5900LeCoreV1);
    assert_eq!(decoder.arch(), TargetArch::Mips64);
}
