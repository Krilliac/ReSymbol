//! Source-built coverage for the bounded PS2 EE observer-site analysis.
//!
//! Every byte below is synthetic and redistributable. The fixture deliberately
//! uses sparse ELF mappings so tests cannot pass by treating an ELF as one flat
//! virtual byte array.

use resymbol_analysis::{
    BinaryAnalysis, DecoderProfile, ElfAnalysis, MAX_PS2_EE_OBSERVER_BLOCKS,
    MAX_PS2_EE_OBSERVER_EDGES, MAX_PS2_EE_OBSERVER_SCAN_BYTES, MAX_PS2_EE_OBSERVER_SEEDS,
    MAX_PS2_EE_OBSERVER_SITES, MAX_PS2_EE_OBSERVER_STRING_BYTES,
    MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES, MAX_PS2_EE_OBSERVER_WORDS, MAX_PS2_EE_OBSERVER_XREFS,
    PS2_EE_OBSERVER_REPORT_SCHEMA_VERSION, Ps2EeAccessDirection, Ps2EeAccessForm, Ps2EeAccessWidth,
    Ps2EeAddressMaterialization, Ps2EeBasicBlock, Ps2EeBlockTerminator, Ps2EeCfgEdge,
    Ps2EeCfgEdgeKind, Ps2EeDataTargetClass, Ps2EeDataXref, Ps2EeExecutableCoverage,
    Ps2EeFunctionSeed, Ps2EeFunctionSeedSource, Ps2EeObserverError, Ps2EeObserverLimits,
    Ps2EeObserverReport, Ps2EeObserverSelection, Ps2EeObserverSite, Ps2EeObserverSiteSelector,
    Ps2EeSegmentPermissions, Ps2EeStringAnchor, TargetArch, analyze_bytes,
    scan_ps2_ee_observer_sites, select_site,
};
use serde::Serialize;

const ELF32_HEADER_SIZE: usize = 52;
const ELF32_PROGRAM_HEADER_SIZE: usize = 32;
const PROGRAM_HEADER_OFFSET: usize = ELF32_HEADER_SIZE;

const CODE0_FILE: usize = 0x100;
const CODE0_VA: u32 = 0x0010_0000;
const CODE0_SIZE: usize = 0x300;
const DATA_FILE: usize = 0x500;
const DATA_VA: u32 = 0x0020_0000;
const DATA_SIZE: usize = 0x300;
const CODE1_FILE: usize = 0x900;
const CODE1_VA: u32 = 0x0090_0000;
const CODE1_SIZE: usize = 0x100;

#[derive(Clone, Copy)]
struct Segment {
    file_offset: usize,
    virtual_address: u32,
    file_size: usize,
    memory_size: usize,
    flags: u32,
}

const SEGMENTS: [Segment; 3] = [
    Segment {
        file_offset: CODE0_FILE,
        virtual_address: CODE0_VA,
        file_size: CODE0_SIZE,
        memory_size: CODE0_SIZE + 0x80,
        flags: 5,
    },
    Segment {
        file_offset: DATA_FILE,
        virtual_address: DATA_VA,
        file_size: DATA_SIZE,
        memory_size: DATA_SIZE + 0x80,
        flags: 6,
    },
    Segment {
        file_offset: CODE1_FILE,
        virtual_address: CODE1_VA,
        file_size: CODE1_SIZE,
        memory_size: CODE1_SIZE,
        flags: 5,
    },
];

fn synthetic_elf(entry_va: u32) -> Vec<u8> {
    let file_size = SEGMENTS
        .iter()
        .map(|segment| segment.file_offset + segment.file_size)
        .max()
        .expect("fixture has mappings");
    let mut bytes = vec![0_u8; file_size];

    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(&mut bytes, 16, 2); // ET_EXEC
    put_u16(&mut bytes, 18, 8); // EM_MIPS
    put_u32(&mut bytes, 20, 1); // EV_CURRENT
    put_u32(&mut bytes, 24, entry_va);
    put_u32(&mut bytes, 28, PROGRAM_HEADER_OFFSET as u32);
    put_u32(&mut bytes, 32, 0); // no section table
    put_u32(&mut bytes, 36, 0x2092_4001); // synthetic EE-style flags
    put_u16(&mut bytes, 40, ELF32_HEADER_SIZE as u16);
    put_u16(&mut bytes, 42, ELF32_PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut bytes, 44, SEGMENTS.len() as u16);
    put_u16(&mut bytes, 46, 40); // canonical ELF32 shdr size, table absent
    put_u16(&mut bytes, 48, 0);
    put_u16(&mut bytes, 50, 0);

    for (index, segment) in SEGMENTS.iter().enumerate() {
        let offset = PROGRAM_HEADER_OFFSET + index * ELF32_PROGRAM_HEADER_SIZE;
        put_u32(&mut bytes, offset, 1); // PT_LOAD
        put_u32(
            &mut bytes,
            offset + 4,
            u32::try_from(segment.file_offset).expect("small synthetic file offset"),
        );
        put_u32(&mut bytes, offset + 8, segment.virtual_address);
        put_u32(&mut bytes, offset + 12, segment.virtual_address);
        put_u32(
            &mut bytes,
            offset + 16,
            u32::try_from(segment.file_size).expect("small synthetic file size"),
        );
        put_u32(
            &mut bytes,
            offset + 20,
            u32::try_from(segment.memory_size).expect("small synthetic memory size"),
        );
        put_u32(&mut bytes, offset + 24, segment.flags);
        put_u32(&mut bytes, offset + 28, 0x100);
    }
    bytes
}

fn analyzed_elf(bytes: &[u8]) -> ElfAnalysis {
    let BinaryAnalysis::Elf(analysis) = analyze_bytes(bytes).expect("synthetic ELF is valid")
    else {
        panic!("fixture must analyze as ELF");
    };
    analysis
}

fn minimal_observer_elf() -> Vec<u8> {
    let mut bytes = synthetic_elf(CODE0_VA);
    put_word_at_va(&mut bytes, CODE0_VA, special(31, 0, 0, 0, 0x08)); // jr $ra
    put_word_at_va(&mut bytes, CODE0_VA + 4, 0); // delay-slot nop
    put_word_at_va(&mut bytes, CODE1_VA, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, CODE1_VA + 4, 0);
    bytes
}

fn terminal_exec_word_elf(guest_va: u32) -> Vec<u8> {
    let mut bytes = minimal_observer_elf();
    put_u32(&mut bytes, 24, guest_va);
    put_u32(&mut bytes, PROGRAM_HEADER_OFFSET + 8, guest_va);
    put_u32(&mut bytes, PROGRAM_HEADER_OFFSET + 12, guest_va);
    put_u32(&mut bytes, PROGRAM_HEADER_OFFSET + 16, 4);
    put_u32(&mut bytes, PROGRAM_HEADER_OFFSET + 20, 4);
    put_u32(&mut bytes, PROGRAM_HEADER_OFFSET + 28, 1);
    bytes
}

fn append_undefined_function_symbol(mut bytes: Vec<u8>) -> Vec<u8> {
    const SECTION_COUNT: usize = 3;
    const SECTION_HEADER_SIZE: usize = 40;
    const SYMBOL_SIZE: usize = 16;
    const STRING_TABLE: &[u8] = b"\0undefined_function\0";

    let section_table = (bytes.len() + 3) & !3;
    let symbol_table = section_table + SECTION_COUNT * SECTION_HEADER_SIZE;
    let string_table = symbol_table + 2 * SYMBOL_SIZE;
    bytes.resize(string_table + STRING_TABLE.len(), 0);
    put_u32(&mut bytes, 32, section_table as u32);
    put_u16(&mut bytes, 46, SECTION_HEADER_SIZE as u16);
    put_u16(&mut bytes, 48, SECTION_COUNT as u16);
    put_u16(&mut bytes, 50, 0);

    let symtab_header = section_table + SECTION_HEADER_SIZE;
    put_u32(&mut bytes, symtab_header + 4, 2); // SHT_SYMTAB
    put_u32(&mut bytes, symtab_header + 16, symbol_table as u32);
    put_u32(&mut bytes, symtab_header + 20, (2 * SYMBOL_SIZE) as u32);
    put_u32(&mut bytes, symtab_header + 24, 2); // linked string table
    put_u32(&mut bytes, symtab_header + 28, 1); // first non-local symbol
    put_u32(&mut bytes, symtab_header + 32, 4);
    put_u32(&mut bytes, symtab_header + 36, SYMBOL_SIZE as u32);

    let strtab_header = section_table + 2 * SECTION_HEADER_SIZE;
    put_u32(&mut bytes, strtab_header + 4, 3); // SHT_STRTAB
    put_u32(&mut bytes, strtab_header + 16, string_table as u32);
    put_u32(
        &mut bytes,
        strtab_header + 20,
        u32::try_from(STRING_TABLE.len()).expect("small string table"),
    );
    put_u32(&mut bytes, strtab_header + 32, 1);

    let undefined = symbol_table + SYMBOL_SIZE;
    put_u32(&mut bytes, undefined, 1); // name offset
    put_u32(&mut bytes, undefined + 4, 0); // value aliases executable VA zero
    bytes[undefined + 12] = 0x12; // STB_GLOBAL | STT_FUNC
    put_u16(&mut bytes, undefined + 14, 0); // SHN_UNDEF
    bytes[string_table..string_table + STRING_TABLE.len()].copy_from_slice(STRING_TABLE);
    bytes
}

fn append_function_symbol_with_section(
    mut bytes: Vec<u8>,
    symbol_section_index: u16,
    symbol_value: u32,
    symbol_size: u32,
    section_virtual_address: u32,
    section_size: u32,
    section_flags: u32,
) -> Vec<u8> {
    const SECTION_COUNT: usize = 4;
    const SECTION_HEADER_SIZE: usize = 40;
    const SYMBOL_SIZE: usize = 16;
    const STRING_TABLE: &[u8] = b"\0candidate_function\0";

    let section_table = (bytes.len() + 3) & !3;
    let symbol_table = section_table + SECTION_COUNT * SECTION_HEADER_SIZE;
    let string_table = symbol_table + 2 * SYMBOL_SIZE;
    bytes.resize(string_table + STRING_TABLE.len(), 0);
    put_u32(&mut bytes, 32, section_table as u32);
    put_u16(&mut bytes, 46, SECTION_HEADER_SIZE as u16);
    put_u16(&mut bytes, 48, SECTION_COUNT as u16);
    put_u16(&mut bytes, 50, 0);

    let symtab_header = section_table + SECTION_HEADER_SIZE;
    put_u32(&mut bytes, symtab_header + 4, 2);
    put_u32(&mut bytes, symtab_header + 16, symbol_table as u32);
    put_u32(&mut bytes, symtab_header + 20, (2 * SYMBOL_SIZE) as u32);
    put_u32(&mut bytes, symtab_header + 24, 2);
    put_u32(&mut bytes, symtab_header + 28, 1);
    put_u32(&mut bytes, symtab_header + 32, 4);
    put_u32(&mut bytes, symtab_header + 36, SYMBOL_SIZE as u32);

    let strtab_header = section_table + 2 * SECTION_HEADER_SIZE;
    put_u32(&mut bytes, strtab_header + 4, 3);
    put_u32(&mut bytes, strtab_header + 16, string_table as u32);
    put_u32(&mut bytes, strtab_header + 20, STRING_TABLE.len() as u32);
    put_u32(&mut bytes, strtab_header + 32, 1);

    let code_header = section_table + 3 * SECTION_HEADER_SIZE;
    put_u32(&mut bytes, code_header + 4, 1);
    put_u32(&mut bytes, code_header + 8, section_flags);
    put_u32(&mut bytes, code_header + 12, section_virtual_address);
    put_u32(
        &mut bytes,
        code_header + 16,
        u32::try_from(file_offset_for_va(section_virtual_address))
            .expect("synthetic section file offset fits u32"),
    );
    put_u32(&mut bytes, code_header + 20, section_size);
    put_u32(&mut bytes, code_header + 32, 4);

    let symbol = symbol_table + SYMBOL_SIZE;
    put_u32(&mut bytes, symbol, 1);
    put_u32(&mut bytes, symbol + 4, symbol_value);
    put_u32(&mut bytes, symbol + 8, symbol_size);
    bytes[symbol + 12] = 0x12;
    put_u16(&mut bytes, symbol + 14, symbol_section_index);
    bytes[string_table..string_table + STRING_TABLE.len()].copy_from_slice(STRING_TABLE);
    bytes
}

fn append_truncated_symbol_table(mut bytes: Vec<u8>) -> Vec<u8> {
    const SECTION_COUNT: usize = 3;
    const SECTION_HEADER_SIZE: usize = 40;
    const SYMBOL_SIZE: usize = 16;
    const SYMBOL_COUNT: usize = 300_000;
    const STRING_TABLE: &[u8] = b"\0x\0";

    let section_table = (bytes.len() + 3) & !3;
    let symbol_table = section_table + SECTION_COUNT * SECTION_HEADER_SIZE;
    let symbol_bytes = SYMBOL_COUNT
        .checked_mul(SYMBOL_SIZE)
        .expect("bounded synthetic symbol table");
    let string_table = symbol_table + symbol_bytes;
    bytes.resize(string_table + STRING_TABLE.len(), 0);
    put_u32(&mut bytes, 32, section_table as u32);
    put_u16(&mut bytes, 46, SECTION_HEADER_SIZE as u16);
    put_u16(&mut bytes, 48, SECTION_COUNT as u16);
    put_u16(&mut bytes, 50, 0);

    let symtab_header = section_table + SECTION_HEADER_SIZE;
    put_u32(&mut bytes, symtab_header + 4, 2);
    put_u32(&mut bytes, symtab_header + 16, symbol_table as u32);
    put_u32(&mut bytes, symtab_header + 20, symbol_bytes as u32);
    put_u32(&mut bytes, symtab_header + 24, 2);
    put_u32(&mut bytes, symtab_header + 28, SYMBOL_COUNT as u32);
    put_u32(&mut bytes, symtab_header + 32, 4);
    put_u32(&mut bytes, symtab_header + 36, SYMBOL_SIZE as u32);

    let strtab_header = section_table + 2 * SECTION_HEADER_SIZE;
    put_u32(&mut bytes, strtab_header + 4, 3);
    put_u32(&mut bytes, strtab_header + 16, string_table as u32);
    put_u32(&mut bytes, strtab_header + 20, STRING_TABLE.len() as u32);
    put_u32(&mut bytes, strtab_header + 32, 1);

    for index in 0..SYMBOL_COUNT {
        put_u32(&mut bytes, symbol_table + index * SYMBOL_SIZE, 1);
    }
    bytes[string_table..string_table + STRING_TABLE.len()].copy_from_slice(STRING_TABLE);
    bytes
}

const LARGE_CODE_FILE: usize = 0x100;
const LARGE_CODE_VA: u32 = 0x0100_0000;
const LARGE_DATA_VA: u32 = 0x0200_0000;

fn synthetic_two_segment_elf(code_size: usize, data_size: usize) -> (Vec<u8>, usize) {
    assert!(code_size >= 8 && code_size % 4 == 0);
    let data_file = (LARGE_CODE_FILE + code_size + 0xff) & !0xff;
    let mut bytes = vec![0_u8; data_file + data_size];
    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 8);
    put_u32(&mut bytes, 20, 1);
    put_u32(&mut bytes, 24, LARGE_CODE_VA);
    put_u32(&mut bytes, 28, PROGRAM_HEADER_OFFSET as u32);
    put_u32(&mut bytes, 36, 0x2092_4001);
    put_u16(&mut bytes, 40, ELF32_HEADER_SIZE as u16);
    put_u16(&mut bytes, 42, ELF32_PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut bytes, 44, 2);
    put_u16(&mut bytes, 46, 40);

    let segments = [
        Segment {
            file_offset: LARGE_CODE_FILE,
            virtual_address: LARGE_CODE_VA,
            file_size: code_size,
            memory_size: code_size,
            flags: 5,
        },
        Segment {
            file_offset: data_file,
            virtual_address: LARGE_DATA_VA,
            file_size: data_size,
            memory_size: data_size,
            flags: 6,
        },
    ];
    for (index, segment) in segments.iter().enumerate() {
        let offset = PROGRAM_HEADER_OFFSET + index * ELF32_PROGRAM_HEADER_SIZE;
        put_u32(&mut bytes, offset, 1);
        put_u32(&mut bytes, offset + 4, segment.file_offset as u32);
        put_u32(&mut bytes, offset + 8, segment.virtual_address);
        put_u32(&mut bytes, offset + 12, segment.virtual_address);
        put_u32(&mut bytes, offset + 16, segment.file_size as u32);
        put_u32(&mut bytes, offset + 20, segment.memory_size as u32);
        put_u32(&mut bytes, offset + 24, segment.flags);
        put_u32(&mut bytes, offset + 28, 0x100);
    }
    (bytes, data_file)
}

fn synthetic_many_exec_segments(count: usize) -> Vec<u8> {
    assert!((1..=u16::MAX as usize).contains(&count));
    let table_end = PROGRAM_HEADER_OFFSET + count * ELF32_PROGRAM_HEADER_SIZE;
    let first_file = (table_end + 0xff) & !0xff;
    let file_size = first_file + count * 0x100;
    let mut bytes = vec![0_u8; file_size];
    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 8);
    put_u32(&mut bytes, 20, 1);
    put_u32(&mut bytes, 24, LARGE_CODE_VA);
    put_u32(&mut bytes, 28, PROGRAM_HEADER_OFFSET as u32);
    put_u32(&mut bytes, 36, 0x2092_4001);
    put_u16(&mut bytes, 40, ELF32_HEADER_SIZE as u16);
    put_u16(&mut bytes, 42, ELF32_PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut bytes, 44, count as u16);
    put_u16(&mut bytes, 46, 40);
    for index in 0..count {
        let header = PROGRAM_HEADER_OFFSET + index * ELF32_PROGRAM_HEADER_SIZE;
        let segment_file = first_file + index * 0x100;
        let segment_va = LARGE_CODE_VA + u32::try_from(index * 0x1000).expect("small guest gap");
        put_u32(&mut bytes, header, 1);
        put_u32(
            &mut bytes,
            header + 4,
            u32::try_from(segment_file).expect("small synthetic file"),
        );
        put_u32(&mut bytes, header + 8, segment_va);
        put_u32(&mut bytes, header + 12, segment_va);
        put_u32(&mut bytes, header + 16, 8);
        put_u32(&mut bytes, header + 20, 8);
        put_u32(&mut bytes, header + 24, 5);
        put_u32(&mut bytes, header + 28, 0x100);
        put_u32(&mut bytes, segment_file, special(31, 0, 0, 0, 0x08));
    }
    bytes
}

fn put_large_code_word(bytes: &mut [u8], word_index: usize, word: u32) {
    put_u32(bytes, LARGE_CODE_FILE + word_index * 4, word);
}

fn scan(bytes: &[u8]) -> Ps2EeObserverReport {
    scan_ps2_ee_observer_sites(bytes, latest_selection(), Ps2EeObserverLimits::default())
        .expect("synthetic observer analysis succeeds")
}

fn assert_output_limit_kind(bytes: &[u8], limits: Ps2EeObserverLimits, expected: &'static str) {
    let error = scan_ps2_ee_observer_sites(bytes, latest_selection(), limits)
        .expect_err("the tightened output limit must fail closed");
    assert!(
        matches!(
            &error,
            Ps2EeObserverError::OutputLimitExceeded { kind, .. } if *kind == expected
        ),
        "unexpected limit error: {error}"
    );
}

fn limits_with(
    maximum_words: usize,
    maximum_sites: usize,
    maximum_string_bytes: usize,
    maximum_total_string_bytes: usize,
) -> Ps2EeObserverLimits {
    observer_limits(
        MAX_PS2_EE_OBSERVER_SCAN_BYTES,
        maximum_words,
        MAX_PS2_EE_OBSERVER_SEEDS,
        MAX_PS2_EE_OBSERVER_BLOCKS,
        MAX_PS2_EE_OBSERVER_EDGES,
        maximum_sites,
        MAX_PS2_EE_OBSERVER_XREFS,
        maximum_string_bytes,
        maximum_total_string_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn observer_limits(
    maximum_scan_bytes: u64,
    maximum_words: usize,
    maximum_seeds: usize,
    maximum_blocks: usize,
    maximum_edges: usize,
    maximum_sites: usize,
    maximum_xrefs: usize,
    maximum_string_bytes: usize,
    maximum_total_string_bytes: usize,
) -> Ps2EeObserverLimits {
    Ps2EeObserverLimits::new(
        maximum_scan_bytes,
        maximum_words,
        maximum_seeds,
        maximum_blocks,
        maximum_edges,
        maximum_sites,
        maximum_xrefs,
        maximum_string_bytes,
        maximum_total_string_bytes,
    )
    .expect("caller limits stay inside hard ceilings")
}

fn latest_selection() -> Ps2EeObserverSelection {
    Ps2EeObserverSelection::new(DecoderProfile::PS2_EE_R5900_LATEST)
        .expect("the exact latest R5900 profile is eligible")
}

fn assert_object_keys<T: Serialize>(value: &T, expected: &[&str]) {
    let value = serde_json::to_value(value).expect("schema value serializes");
    let object = value.as_object().expect("schema value is an object");
    let mut actual: Vec<_> = object.keys().map(String::as_str).collect();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

fn assert_serialized_spellings<T: Serialize>(cases: &[(T, &str)]) {
    for (value, expected) in cases {
        assert_eq!(
            serde_json::to_value(value).expect("enum value serializes"),
            serde_json::Value::String((*expected).to_owned())
        );
    }
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn file_offset_for_va(va: u32) -> usize {
    SEGMENTS
        .iter()
        .find_map(|segment| {
            let relative = va.checked_sub(segment.virtual_address)?;
            let relative = usize::try_from(relative).ok()?;
            (relative < segment.file_size).then_some(segment.file_offset + relative)
        })
        .unwrap_or_else(|| panic!("VA 0x{va:08x} is not file-backed in the synthetic ELF"))
}

fn put_word_at_va(bytes: &mut [u8], va: u32, word: u32) {
    let offset = file_offset_for_va(va);
    put_u32(bytes, offset, word);
}

fn put_bytes_at_va(bytes: &mut [u8], va: u32, value: &[u8]) {
    let offset = file_offset_for_va(va);
    bytes[offset..offset + value.len()].copy_from_slice(value);
}

const fn immediate(opcode: u32, rs: u32, rt: u32, value: u16) -> u32 {
    (opcode << 26) | (rs << 21) | (rt << 16) | value as u32
}

const fn special(rs: u32, rt: u32, rd: u32, sa: u32, function: u32) -> u32 {
    (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | function
}

const fn jump(opcode: u32, target_va: u32) -> u32 {
    (opcode << 26) | ((target_va >> 2) & 0x03ff_ffff)
}

fn branch(opcode: u32, rs: u32, rt: u32, pc: u32, target: u32) -> u32 {
    let displacement = i64::from(target) - i64::from(pc) - 4;
    assert_eq!(displacement % 4, 0, "branch target must be word aligned");
    let words = displacement / 4;
    let value = i16::try_from(words).expect("synthetic branch is in range");
    immediate(opcode, rs, rt, u16::from_ne_bytes(value.to_ne_bytes()))
}

#[test]
fn source_built_fixture_has_sparse_file_backed_mappings() {
    let bytes = synthetic_elf(CODE0_VA);
    let elf = analyzed_elf(&bytes);

    assert_eq!(elf.entry_va, u64::from(CODE0_VA));
    assert_eq!(elf.load_segments.len(), 3);
    assert_eq!(elf.load_segments[0].virtual_address, u64::from(CODE0_VA));
    assert_eq!(elf.load_segments[1].virtual_address, u64::from(DATA_VA));
    assert_eq!(elf.load_segments[2].virtual_address, u64::from(CODE1_VA));
    assert!(elf.load_segments[0].executable());
    assert!(!elf.load_segments[1].executable());
    assert!(elf.load_segments[2].executable());
    assert!(elf.image_size > u64::from(CODE1_VA - CODE0_VA));

    let mut bytes = bytes;
    put_word_at_va(&mut bytes, CODE0_VA, special(31, 0, 0, 0, 0x08));
    const ANCHOR: &[u8] = b"synthetic-observer-anchor\0";
    put_bytes_at_va(&mut bytes, DATA_VA, ANCHOR);
    let anchor_offset = file_offset_for_va(DATA_VA);
    assert_eq!(&bytes[anchor_offset..anchor_offset + ANCHOR.len()], ANCHOR);
    assert_eq!(jump(0x03, CODE1_VA), 0x0c24_0000);
    assert_eq!(
        branch(0x04, 2, 0, CODE0_VA, CODE0_VA + 8),
        immediate(0x04, 2, 0, 1)
    );
}

#[test]
fn undefined_function_symbols_never_become_function_seeds() {
    let mut bytes = minimal_observer_elf();
    put_u32(&mut bytes, 24, 0);
    put_u32(&mut bytes, PROGRAM_HEADER_OFFSET + 8, 0);
    put_u32(&mut bytes, PROGRAM_HEADER_OFFSET + 12, 0);
    let bytes = append_undefined_function_symbol(bytes);
    let analysis = analyzed_elf(&bytes);
    assert!(analysis.symbols.iter().any(|symbol| {
        symbol.value == 0 && symbol.info & 0x0f == 2 && symbol.section_index == 0
    }));

    let report = scan(&bytes);
    let zero_seed = report
        .function_seeds
        .iter()
        .find(|seed| seed.guest_va == 0)
        .expect("entry and executable-segment start seed address zero");
    assert!(
        zero_seed
            .sources
            .contains(&Ps2EeFunctionSeedSource::EntryPoint)
    );
    assert!(
        zero_seed
            .sources
            .contains(&Ps2EeFunctionSeedSource::ExecutableSegmentStart)
    );
    assert!(
        !zero_seed
            .sources
            .contains(&Ps2EeFunctionSeedSource::ElfFunctionSymbol)
    );
}

#[test]
fn truncated_elf_symbol_scans_fail_without_a_partial_report() {
    let bytes = append_truncated_symbol_table(minimal_observer_elf());
    let error =
        scan_ps2_ee_observer_sites(&bytes, latest_selection(), Ps2EeObserverLimits::default())
            .expect_err("a truncated upstream symbol scan must fail all-or-nothing");
    assert!(matches!(
        error,
        Ps2EeObserverError::IneligibleContainer {
            requirement: "a complete bounded ELF symbol scan"
        }
    ));
}

#[test]
fn only_section_consistent_ordinary_function_symbols_become_seeds() {
    const SHN_ABS: u16 = 0xfff1;
    const SHN_COMMON: u16 = 0xfff2;
    const SHN_XINDEX: u16 = 0xffff;
    let target = CODE0_VA + 0x40;
    let cases = [
        (
            "ordinary executable section",
            3,
            CODE0_VA,
            CODE0_SIZE as u32,
            6,
            true,
        ),
        (
            "conservatively rejected SHN_ABS",
            SHN_ABS,
            CODE0_VA,
            CODE0_SIZE as u32,
            6,
            false,
        ),
        (
            "SHN_COMMON",
            SHN_COMMON,
            CODE0_VA,
            CODE0_SIZE as u32,
            6,
            false,
        ),
        (
            "SHN_XINDEX",
            SHN_XINDEX,
            CODE0_VA,
            CODE0_SIZE as u32,
            6,
            false,
        ),
        (
            "reserved section index",
            0xff00,
            CODE0_VA,
            CODE0_SIZE as u32,
            6,
            false,
        ),
        (
            "out-of-range ordinary section index",
            4,
            CODE0_VA,
            CODE0_SIZE as u32,
            6,
            false,
        ),
        (
            "value outside its declared section",
            3,
            CODE0_VA,
            0x20,
            6,
            false,
        ),
        (
            "non-executable declared section",
            3,
            CODE0_VA,
            CODE0_SIZE as u32,
            2,
            false,
        ),
        (
            "non-allocated executable section",
            3,
            CODE0_VA,
            CODE0_SIZE as u32,
            4,
            false,
        ),
    ];

    for (label, section_index, section_va, section_size, section_flags, expected) in cases {
        let bytes = append_function_symbol_with_section(
            minimal_observer_elf(),
            section_index,
            target,
            0,
            section_va,
            section_size,
            section_flags,
        );
        let report = scan(&bytes);
        let retained = report.function_seeds.iter().any(|seed| {
            seed.guest_va == u64::from(target)
                && seed
                    .sources
                    .contains(&Ps2EeFunctionSeedSource::ElfFunctionSymbol)
        });
        assert_eq!(retained, expected, "unexpected symbol policy for {label}");
    }

    let crossing_extent = append_function_symbol_with_section(
        minimal_observer_elf(),
        3,
        target,
        CODE0_SIZE as u32,
        CODE0_VA,
        CODE0_SIZE as u32,
        6,
    );
    assert!(scan(&crossing_extent).function_seeds.iter().all(|seed| {
        seed.guest_va != u64::from(target)
            || !seed
                .sources
                .contains(&Ps2EeFunctionSeedSource::ElfFunctionSymbol)
    }));

    let misaligned_target = CODE0_VA + 1;
    let misaligned = append_function_symbol_with_section(
        minimal_observer_elf(),
        3,
        misaligned_target,
        0,
        CODE0_VA,
        CODE0_SIZE as u32,
        6,
    );
    assert!(scan(&misaligned).function_seeds.iter().all(|seed| {
        seed.guest_va != u64::from(misaligned_target)
            || !seed
                .sources
                .contains(&Ps2EeFunctionSeedSource::ElfFunctionSymbol)
    }));
}

#[test]
fn observer_selection_requires_an_exact_r5900_profile() {
    let exact_profiles = [
        DecoderProfile::Ps2EeR5900LeCoreV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1,
    ];

    for profile in exact_profiles {
        let selection = Ps2EeObserverSelection::new(profile)
            .unwrap_or_else(|error| panic!("{profile} must be eligible: {error}"));
        assert_eq!(selection.exact_profile(), profile);
    }

    for generic in [TargetArch::Mips32, TargetArch::Mips64, TargetArch::X86_64] {
        assert!(
            Ps2EeObserverSelection::new(DecoderProfile::Generic(generic)).is_err(),
            "generic {generic:?} must never stand in for explicit EE semantics"
        );
    }
}

#[test]
fn observer_scan_reparses_and_rejects_ineligible_elf_containers() {
    let valid = minimal_observer_elf();
    scan_ps2_ee_observer_sites(&valid, latest_selection(), Ps2EeObserverLimits::default())
        .expect("ELF32 little-endian ET_EXEC EM_MIPS is eligible");

    let mut cases = Vec::new();
    let mut wrong_class = valid.clone();
    wrong_class[4] = 2;
    cases.push(("ELF64", wrong_class));
    let mut wrong_endian = valid.clone();
    wrong_endian[5] = 2;
    cases.push(("big-endian", wrong_endian));
    let mut wrong_type = valid.clone();
    put_u16(&mut wrong_type, 16, 3); // ET_DYN
    cases.push(("non-ET_EXEC", wrong_type));
    let mut wrong_machine = valid.clone();
    put_u16(&mut wrong_machine, 18, 3); // EM_386
    cases.push(("non-EM_MIPS", wrong_machine));
    let mut truncated = valid;
    truncated.truncate(32);
    cases.push(("truncated", truncated));

    for (label, bytes) in cases {
        assert!(
            scan_ps2_ee_observer_sites(&bytes, latest_selection(), Ps2EeObserverLimits::default(),)
                .is_err(),
            "{label} input must fail closed"
        );
    }
}

#[test]
fn complete_reports_and_json_are_deterministic() {
    let bytes = minimal_observer_elf();
    let first =
        scan_ps2_ee_observer_sites(&bytes, latest_selection(), Ps2EeObserverLimits::default())
            .expect("first scan succeeds");
    let second =
        scan_ps2_ee_observer_sites(&bytes, latest_selection(), Ps2EeObserverLimits::default())
            .expect("second scan succeeds");

    assert_eq!(first, second);
    assert_eq!(first.schema_version, PS2_EE_OBSERVER_REPORT_SCHEMA_VERSION);
    assert_eq!(
        serde_json::to_value(&first).expect("report value serializes")["schema_version"],
        PS2_EE_OBSERVER_REPORT_SCHEMA_VERSION
    );
    assert_eq!(
        serde_json::to_vec(&first).expect("report serializes"),
        serde_json::to_vec(&second).expect("report serializes identically")
    );
}

#[test]
fn schema_v1_keys_and_enum_spellings_are_exact() {
    let report = scan(&minimal_observer_elf());
    assert_eq!(report.schema_version, 1);
    let report_json = serde_json::to_value(&report).expect("schema report serializes");
    assert_eq!(
        report_json["exact_profile"],
        DecoderProfile::PS2_EE_R5900_LATEST.name()
    );
    assert_eq!(
        report_json["exact_profile_name"],
        DecoderProfile::PS2_EE_R5900_LATEST.name()
    );
    assert_object_keys(
        &report,
        &[
            "schema_version",
            "identity",
            "exact_profile",
            "exact_profile_name",
            "limits",
            "executable_coverage",
            "scanned_word_count",
            "function_seeds",
            "basic_blocks",
            "cfg_edges",
            "address_materializations",
            "data_xrefs",
            "observer_sites",
        ],
    );
    assert_object_keys(
        &report.identity,
        &["id", "size", "format", "architecture", "image_base"],
    );
    assert_object_keys(
        &Ps2EeObserverLimits::default(),
        &[
            "maximum_scan_bytes",
            "maximum_words",
            "maximum_seeds",
            "maximum_blocks",
            "maximum_edges",
            "maximum_sites",
            "maximum_xrefs",
            "maximum_string_bytes",
            "maximum_total_string_bytes",
        ],
    );

    let permissions = Ps2EeSegmentPermissions {
        raw_flags: 5,
        readable: true,
        writable: false,
        executable: true,
    };
    assert_object_keys(
        &permissions,
        &["raw_flags", "readable", "writable", "executable"],
    );
    assert_object_keys(
        &Ps2EeExecutableCoverage {
            program_header_index: 1,
            start_guest_va: 0x1000,
            start_rva: 0,
            end_guest_va: 0x1004,
            end_rva: 4,
            start_file_offset: 0x100,
            byte_size: 4,
            word_count: 1,
            permissions,
        },
        &[
            "program_header_index",
            "start_guest_va",
            "start_rva",
            "end_guest_va",
            "end_rva",
            "start_file_offset",
            "byte_size",
            "word_count",
            "permissions",
        ],
    );
    assert_object_keys(
        &Ps2EeFunctionSeed {
            guest_va: 0x1000,
            rva: 0,
            sources: vec![Ps2EeFunctionSeedSource::EntryPoint],
        },
        &["guest_va", "rva", "sources"],
    );
    assert_object_keys(
        &Ps2EeBasicBlock {
            start_guest_va: 0x1000,
            start_rva: 0,
            end_guest_va: 0x1004,
            end_rva: Some(4),
            decoded_word_count: 1,
            terminator_guest_pc: Some(0x1000),
            terminator_rva: Some(0),
            terminator: Ps2EeBlockTerminator::Return,
        },
        &[
            "start_guest_va",
            "start_rva",
            "end_guest_va",
            "end_rva",
            "decoded_word_count",
            "terminator_guest_pc",
            "terminator_rva",
            "terminator",
        ],
    );
    assert_object_keys(
        &Ps2EeCfgEdge {
            source_block_guest_va: 0x1000,
            source_block_rva: 0,
            instruction_guest_pc: 0x1000,
            instruction_rva: 0,
            target_guest_va: 0x1004,
            target_rva: Some(4),
            kind: Ps2EeCfgEdgeKind::FallThrough,
        },
        &[
            "source_block_guest_va",
            "source_block_rva",
            "instruction_guest_pc",
            "instruction_rva",
            "target_guest_va",
            "target_rva",
            "kind",
        ],
    );
    assert_object_keys(
        &Ps2EeAddressMaterialization {
            instruction_guest_pc: 0x1000,
            instruction_rva: 0,
            destination_register: 8,
            target_guest_va: 0x2000,
            target_rva: 0x1000,
            target_class: Ps2EeDataTargetClass::FullyFileBacked,
        },
        &[
            "instruction_guest_pc",
            "instruction_rva",
            "destination_register",
            "target_guest_va",
            "target_rva",
            "target_class",
        ],
    );
    assert_object_keys(
        &Ps2EeDataXref {
            instruction_guest_pc: 0x1000,
            instruction_rva: 0,
            target_guest_va: 0x2000,
            target_rva: Some(0x1000),
            access_span_guest_va: 0x2000,
            access_span_rva: Some(0x1000),
            direction: Ps2EeAccessDirection::Read,
            form: Ps2EeAccessForm::ScalarLoad,
            width: Ps2EeAccessWidth::Word,
            target_class: Ps2EeDataTargetClass::FullyFileBacked,
            program_header_index: Some(2),
            file_offset: Some(0x200),
            permissions: Some(permissions),
        },
        &[
            "instruction_guest_pc",
            "instruction_rva",
            "target_guest_va",
            "target_rva",
            "access_span_guest_va",
            "access_span_rva",
            "direction",
            "form",
            "width",
            "target_class",
            "program_header_index",
            "file_offset",
            "permissions",
        ],
    );
    let string_anchor = Ps2EeStringAnchor {
        guest_va: 0x2000,
        rva: 0x1000,
        byte_size: 5,
        value: "test".to_owned(),
    };
    assert_object_keys(&string_anchor, &["guest_va", "rva", "byte_size", "value"]);
    assert_object_keys(
        &Ps2EeObserverSite {
            instruction_guest_pc: 0x1000,
            instruction_rva: 0,
            target_guest_va: 0x2000,
            target_rva: 0x1000,
            access_span_guest_va: 0x2000,
            access_span_rva: 0x1000,
            direction: Ps2EeAccessDirection::Read,
            form: Ps2EeAccessForm::ScalarLoad,
            width: Ps2EeAccessWidth::Word,
            program_header_index: 2,
            file_offset: 0x200,
            permissions,
            string_anchor: Some(string_anchor),
        },
        &[
            "instruction_guest_pc",
            "instruction_rva",
            "target_guest_va",
            "target_rva",
            "access_span_guest_va",
            "access_span_rva",
            "direction",
            "form",
            "width",
            "program_header_index",
            "file_offset",
            "permissions",
            "string_anchor",
        ],
    );

    assert_serialized_spellings(&[
        (Ps2EeFunctionSeedSource::EntryPoint, "entry-point"),
        (
            Ps2EeFunctionSeedSource::ExecutableSegmentStart,
            "executable-segment-start",
        ),
        (
            Ps2EeFunctionSeedSource::ElfFunctionSymbol,
            "elf-function-symbol",
        ),
        (
            Ps2EeFunctionSeedSource::DirectCallTarget,
            "direct-call-target",
        ),
    ]);
    assert_serialized_spellings(&[
        (Ps2EeBlockTerminator::FallThrough, "fall-through"),
        (
            Ps2EeBlockTerminator::ConditionalBranch,
            "conditional-branch",
        ),
        (
            Ps2EeBlockTerminator::UnconditionalBranch,
            "unconditional-branch",
        ),
        (Ps2EeBlockTerminator::IndirectBranch, "indirect-branch"),
        (Ps2EeBlockTerminator::DirectCall, "direct-call"),
        (Ps2EeBlockTerminator::IndirectCall, "indirect-call"),
        (Ps2EeBlockTerminator::Return, "return"),
        (Ps2EeBlockTerminator::Interrupt, "interrupt"),
        (Ps2EeBlockTerminator::ArithmeticTrap, "arithmetic-trap"),
        (Ps2EeBlockTerminator::Unsupported, "unsupported"),
        (Ps2EeBlockTerminator::Invalid, "invalid"),
        (Ps2EeBlockTerminator::MissingDelaySlot, "missing-delay-slot"),
        (Ps2EeBlockTerminator::EndOfCoverage, "end-of-coverage"),
    ]);
    assert_serialized_spellings(&[
        (Ps2EeCfgEdgeKind::FallThrough, "fall-through"),
        (Ps2EeCfgEdgeKind::Branch, "branch"),
        (Ps2EeCfgEdgeKind::BranchTaken, "branch-taken"),
        (Ps2EeCfgEdgeKind::BranchNotTaken, "branch-not-taken"),
        (Ps2EeCfgEdgeKind::DirectCall, "direct-call"),
        (Ps2EeCfgEdgeKind::CallContinuation, "call-continuation"),
    ]);
    assert_serialized_spellings(&[
        (Ps2EeDataTargetClass::FullyFileBacked, "fully-file-backed"),
        (Ps2EeDataTargetClass::MappedZeroFill, "mapped-zero-fill"),
        (
            Ps2EeDataTargetClass::MappedCrossBoundary,
            "mapped-cross-boundary",
        ),
        (Ps2EeDataTargetClass::Unmapped, "unmapped"),
    ]);
    assert_serialized_spellings(&[
        (Ps2EeAccessDirection::Read, "read"),
        (Ps2EeAccessDirection::Write, "write"),
    ]);
    assert_serialized_spellings(&[
        (Ps2EeAccessForm::ScalarLoad, "scalar-load"),
        (Ps2EeAccessForm::ScalarStore, "scalar-store"),
        (Ps2EeAccessForm::MergeLoadLeft, "merge-load-left"),
        (Ps2EeAccessForm::MergeLoadRight, "merge-load-right"),
        (Ps2EeAccessForm::MergeStoreLeft, "merge-store-left"),
        (Ps2EeAccessForm::MergeStoreRight, "merge-store-right"),
    ]);
    assert_serialized_spellings(&[
        (Ps2EeAccessWidth::Byte, "byte"),
        (Ps2EeAccessWidth::Halfword, "halfword"),
        (Ps2EeAccessWidth::Word, "word"),
        (Ps2EeAccessWidth::Doubleword, "doubleword"),
        (Ps2EeAccessWidth::Quadword, "quadword"),
    ]);
}

#[test]
fn branch_likely_annuls_only_the_not_taken_delay_slot() {
    let mut bytes = synthetic_elf(CODE0_VA);
    let branch_pc = CODE0_VA + 4;
    let taken_pc = CODE0_VA + 0x20;
    let end_pc = CODE0_VA + 0x30;
    put_word_at_va(&mut bytes, CODE0_VA, immediate(0x0f, 0, 8, 0x20));
    put_word_at_va(
        &mut bytes,
        branch_pc,
        branch(0x14, 9, 10, branch_pc, taken_pc),
    );
    put_word_at_va(&mut bytes, CODE0_VA + 8, immediate(0x09, 8, 8, 0x20));
    put_word_at_va(&mut bytes, CODE0_VA + 0x0c, immediate(0x23, 8, 2, 0));
    put_word_at_va(&mut bytes, CODE0_VA + 0x10, jump(0x02, end_pc));
    put_word_at_va(&mut bytes, CODE0_VA + 0x14, 0);
    put_word_at_va(&mut bytes, taken_pc, immediate(0x23, 8, 3, 0));
    put_word_at_va(&mut bytes, taken_pc + 4, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, taken_pc + 8, 0);
    put_word_at_va(&mut bytes, end_pc, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, end_pc + 4, 0);

    let report = scan(&bytes);
    let not_taken = report
        .data_xrefs
        .iter()
        .find(|xref| xref.instruction_guest_pc == u64::from(CODE0_VA + 0x0c))
        .expect("not-taken continuation retains the pre-slot base");
    assert_eq!(not_taken.target_guest_va, u64::from(DATA_VA));
    let taken = report
        .data_xrefs
        .iter()
        .find(|xref| xref.instruction_guest_pc == u64::from(taken_pc))
        .expect("taken path executes the delay-slot increment");
    assert_eq!(taken.target_guest_va, u64::from(DATA_VA + 0x20));
}

#[test]
fn regimm_link_models_link_delay_target_and_unknown_call_return() {
    let mut bytes = synthetic_elf(CODE0_VA);
    let branch_pc = CODE0_VA;
    let taken_pc = CODE0_VA + 0x20;
    let end_pc = CODE0_VA + 0x30;
    put_word_at_va(
        &mut bytes,
        branch_pc,
        branch(0x01, 2, 0x10, branch_pc, taken_pc),
    );
    put_word_at_va(&mut bytes, branch_pc + 4, immediate(0x24, 31, 2, 0));
    put_word_at_va(&mut bytes, branch_pc + 8, immediate(0x24, 31, 3, 0));
    put_word_at_va(&mut bytes, branch_pc + 0x0c, jump(0x02, end_pc));
    put_word_at_va(&mut bytes, branch_pc + 0x10, 0);
    put_word_at_va(&mut bytes, taken_pc, immediate(0x24, 31, 4, 0));
    put_word_at_va(&mut bytes, taken_pc + 4, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, taken_pc + 8, 0);
    put_word_at_va(&mut bytes, end_pc, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, end_pc + 4, 0);

    let report = scan(&bytes);
    let expected_target = u64::from(branch_pc + 8);
    let delay_xref = report
        .data_xrefs
        .iter()
        .find(|xref| xref.instruction_guest_pc == u64::from(branch_pc + 4))
        .expect("REGIMM link writes RA before its executed delay slot");
    assert_eq!(delay_xref.target_guest_va, expected_target);
    assert_eq!(
        delay_xref.target_class,
        Ps2EeDataTargetClass::FullyFileBacked
    );
    for instruction_guest_pc in [branch_pc + 8, taken_pc] {
        assert!(
            report
                .data_xrefs
                .iter()
                .all(|xref| xref.instruction_guest_pc != u64::from(instruction_guest_pc)),
            "callee or post-call state at {instruction_guest_pc:#x} must not inherit exact RA"
        );
    }
    let target_seed = report
        .function_seeds
        .iter()
        .find(|seed| seed.guest_va == u64::from(taken_pc))
        .expect("REGIMM link target is retained as a direct-call seed");
    assert!(
        target_seed
            .sources
            .contains(&Ps2EeFunctionSeedSource::DirectCallTarget)
    );
    let edge_kinds: Vec<_> = report
        .cfg_edges
        .iter()
        .filter(|edge| edge.instruction_guest_pc == u64::from(branch_pc))
        .map(|edge| (edge.kind, edge.target_guest_va))
        .collect();
    assert!(edge_kinds.contains(&(Ps2EeCfgEdgeKind::BranchTaken, u64::from(taken_pc))));
    assert!(edge_kinds.contains(&(Ps2EeCfgEdgeKind::BranchNotTaken, u64::from(branch_pc + 8))));
    assert!(edge_kinds.contains(&(Ps2EeCfgEdgeKind::CallContinuation, u64::from(branch_pc + 8))));
}

#[test]
fn jal_and_jalr_continuations_forget_pre_call_constants() {
    let mut direct = synthetic_elf(CODE0_VA);
    let call_pc = CODE0_VA + 4;
    let continuation = call_pc + 8;
    let callee = CODE0_VA + 0x40;
    put_word_at_va(&mut direct, CODE0_VA, immediate(0x0f, 0, 8, 0x20));
    put_word_at_va(&mut direct, call_pc, jump(0x03, callee));
    put_word_at_va(&mut direct, call_pc + 4, immediate(0x24, 31, 2, 0));
    put_word_at_va(&mut direct, continuation, immediate(0x23, 8, 3, 0));
    put_word_at_va(&mut direct, continuation + 4, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut direct, continuation + 8, 0);
    put_word_at_va(&mut direct, callee, immediate(0x24, 31, 4, 0));
    put_word_at_va(&mut direct, callee + 4, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut direct, callee + 8, 0);

    let direct_report = scan(&direct);
    let delay_xref = direct_report
        .data_xrefs
        .iter()
        .find(|xref| xref.instruction_guest_pc == u64::from(call_pc + 4))
        .expect("JAL writes RA before its delay slot");
    assert_eq!(delay_xref.target_guest_va, u64::from(continuation));
    for guest_pc in [continuation, callee] {
        assert!(
            direct_report
                .data_xrefs
                .iter()
                .all(|xref| xref.instruction_guest_pc != u64::from(guest_pc)),
            "post-call or callee entry at {guest_pc:#x} inherited an exact register"
        );
    }
    assert!(direct_report.cfg_edges.iter().any(|edge| {
        edge.instruction_guest_pc == u64::from(call_pc)
            && edge.target_guest_va == u64::from(continuation)
            && edge.kind == Ps2EeCfgEdgeKind::CallContinuation
    }));

    let mut indirect = synthetic_elf(CODE0_VA);
    let jalr_pc = CODE0_VA + 0x0c;
    let jalr_continuation = jalr_pc + 8;
    put_word_at_va(&mut indirect, CODE0_VA, immediate(0x0f, 0, 8, 0x20));
    put_word_at_va(&mut indirect, CODE0_VA + 4, immediate(0x0f, 0, 25, 0x0010));
    put_word_at_va(&mut indirect, CODE0_VA + 8, immediate(0x0d, 25, 25, 0x0080));
    put_word_at_va(&mut indirect, jalr_pc, special(25, 0, 31, 0, 0x09));
    put_word_at_va(&mut indirect, jalr_pc + 4, 0);
    put_word_at_va(&mut indirect, jalr_continuation, immediate(0x23, 8, 3, 0));
    put_word_at_va(
        &mut indirect,
        jalr_continuation + 4,
        special(31, 0, 0, 0, 0x08),
    );
    put_word_at_va(&mut indirect, jalr_continuation + 8, 0);

    let indirect_report = scan(&indirect);
    assert!(
        indirect_report
            .data_xrefs
            .iter()
            .all(|xref| { xref.instruction_guest_pc != u64::from(jalr_continuation) })
    );
    assert!(indirect_report.cfg_edges.iter().any(|edge| {
        edge.instruction_guest_pc == u64::from(jalr_pc)
            && edge.target_guest_va == u64::from(jalr_continuation)
            && edge.kind == Ps2EeCfgEdgeKind::CallContinuation
    }));
}

#[test]
fn cache_pref_and_coprocessor_words_never_become_data_xrefs() {
    let mut bytes = synthetic_elf(CODE0_VA);
    put_word_at_va(&mut bytes, CODE0_VA, immediate(0x0f, 0, 8, 0x20));
    put_word_at_va(&mut bytes, CODE0_VA + 4, immediate(0x2f, 8, 7, 0));
    put_word_at_va(&mut bytes, CODE0_VA + 8, immediate(0x33, 8, 3, 0));
    put_word_at_va(&mut bytes, CODE0_VA + 0x0c, immediate(0x31, 8, 2, 0));
    put_word_at_va(&mut bytes, CODE0_VA + 0x10, immediate(0x23, 8, 2, 0));

    let report = scan(&bytes);
    for guest_pc in [CODE0_VA + 4, CODE0_VA + 8, CODE0_VA + 0x0c, CODE0_VA + 0x10] {
        assert!(
            report
                .data_xrefs
                .iter()
                .all(|xref| xref.instruction_guest_pc != u64::from(guest_pc)),
            "excluded word at {guest_pc:#x} produced an xref"
        );
    }
    assert!(report.basic_blocks.iter().any(|block| {
        block.terminator_guest_pc == Some(u64::from(CODE0_VA + 0x0c))
            && block.terminator == Ps2EeBlockTerminator::Unsupported
    }));
}

#[test]
fn scalar_and_merge_xrefs_preserve_exact_width_alignment_and_target_class() {
    let mut bytes = synthetic_elf(CODE0_VA);
    put_word_at_va(&mut bytes, CODE0_VA, immediate(0x0f, 0, 8, 0x20));
    let accesses = [
        (0x04, immediate(0x20, 8, 2, 0)),
        (0x08, immediate(0x29, 8, 3, 2)),
        (0x0c, immediate(0x23, 8, 4, 1)),
        (0x10, immediate(0x22, 8, 5, 3)),
        (0x14, immediate(0x1b, 8, 6, 7)),
        (0x18, immediate(0x1e, 8, 7, 0x10)),
        (0x1c, immediate(0x23, 8, 9, 0x02ff)),
        (0x20, immediate(0x24, 8, 10, DATA_SIZE as u16)),
        (0x24, immediate(0x24, 8, 11, (DATA_SIZE + 0x80) as u16)),
        (0x28, immediate(0x2e, 8, 12, 3)),
    ];
    for (offset, word) in accesses {
        put_word_at_va(&mut bytes, CODE0_VA + offset, word);
    }
    put_word_at_va(&mut bytes, CODE0_VA + 0x30, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, CODE0_VA + 0x34, 0);

    let report = scan(&bytes);
    let xref_at = |offset: u32| {
        report
            .data_xrefs
            .iter()
            .find(|xref| xref.instruction_guest_pc == u64::from(CODE0_VA + offset))
            .unwrap_or_else(|| panic!("missing xref at +{offset:#x}"))
    };
    assert_eq!(xref_at(0x04).width, Ps2EeAccessWidth::Byte);
    assert_eq!(xref_at(0x04).direction, Ps2EeAccessDirection::Read);
    assert_eq!(xref_at(0x04).program_header_index, Some(1));
    assert_eq!(xref_at(0x04).file_offset, Some(DATA_FILE as u64));
    assert_eq!(
        xref_at(0x04).permissions,
        Some(Ps2EeSegmentPermissions {
            raw_flags: 6,
            readable: true,
            writable: true,
            executable: false,
        })
    );
    assert_eq!(xref_at(0x08).width, Ps2EeAccessWidth::Halfword);
    assert_eq!(xref_at(0x0c).form, Ps2EeAccessForm::ScalarLoad);
    assert_eq!(xref_at(0x0c).target_guest_va, u64::from(DATA_VA + 1));
    assert_eq!(xref_at(0x0c).access_span_guest_va, u64::from(DATA_VA + 1));
    assert_eq!(xref_at(0x10).form, Ps2EeAccessForm::MergeLoadLeft);
    assert_eq!(xref_at(0x10).width, Ps2EeAccessWidth::Word);
    assert_eq!(xref_at(0x10).target_guest_va, u64::from(DATA_VA + 3));
    assert_eq!(xref_at(0x10).access_span_guest_va, u64::from(DATA_VA));
    assert_eq!(xref_at(0x14).form, Ps2EeAccessForm::MergeLoadRight);
    assert_eq!(xref_at(0x14).width, Ps2EeAccessWidth::Doubleword);
    assert_eq!(xref_at(0x14).access_span_guest_va, u64::from(DATA_VA));
    assert_eq!(xref_at(0x18).width, Ps2EeAccessWidth::Quadword);
    assert_eq!(
        xref_at(0x1c).target_class,
        Ps2EeDataTargetClass::MappedCrossBoundary
    );
    assert!(
        report
            .observer_sites
            .iter()
            .all(|site| { site.instruction_guest_pc != u64::from(CODE0_VA + 0x1c) })
    );
    assert_eq!(
        xref_at(0x20).target_class,
        Ps2EeDataTargetClass::MappedZeroFill
    );
    assert_eq!(xref_at(0x20).program_header_index, Some(1));
    assert_eq!(xref_at(0x20).file_offset, None);
    assert_eq!(xref_at(0x24).target_class, Ps2EeDataTargetClass::Unmapped);
    assert_eq!(xref_at(0x24).program_header_index, None);
    assert_eq!(xref_at(0x24).permissions, None);
    assert_eq!(xref_at(0x28).form, Ps2EeAccessForm::MergeStoreRight);
    assert_eq!(xref_at(0x28).direction, Ps2EeAccessDirection::Write);
    for offset in [0x20, 0x24] {
        assert!(
            report
                .observer_sites
                .iter()
                .all(|site| site.instruction_guest_pc != u64::from(CODE0_VA + offset))
        );
    }
}

#[test]
fn site_selection_rejects_duplicate_guest_pc_ambiguity() {
    let mut bytes = synthetic_elf(CODE0_VA);
    put_word_at_va(&mut bytes, CODE0_VA, immediate(0x0f, 0, 8, 0x20));
    put_word_at_va(&mut bytes, CODE0_VA + 4, immediate(0x24, 8, 2, 0));
    put_word_at_va(&mut bytes, CODE0_VA + 8, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, CODE0_VA + 0x0c, 0);
    let mut report = scan(&bytes);
    let first = report.observer_sites[0].clone();
    assert_eq!(
        select_site(
            &report,
            Ps2EeObserverSiteSelector::GuestPc(first.instruction_guest_pc)
        )
        .expect("a unique generated guest PC is selectable"),
        (first.instruction_guest_pc, first.form, first.width)
    );
    assert!(matches!(
        select_site(
            &report,
            Ps2EeObserverSiteSelector::Index(report.observer_sites.len())
        ),
        Err(Ps2EeObserverError::SiteIndexOutOfRange { .. })
    ));
    assert!(matches!(
        select_site(&report, Ps2EeObserverSiteSelector::GuestPc(u64::MAX)),
        Err(Ps2EeObserverError::SiteGuestPcNotFound { .. })
    ));
    let mut duplicate_pc = first.clone();
    duplicate_pc.target_guest_va += 4;
    duplicate_pc.target_rva += 4;
    duplicate_pc.access_span_guest_va += 4;
    duplicate_pc.access_span_rva += 4;
    duplicate_pc.file_offset += 4;
    report.observer_sites.push(duplicate_pc);
    report.observer_sites.sort();

    assert_eq!(
        select_site(&report, Ps2EeObserverSiteSelector::Index(0))
            .expect("an exact sorted index is unambiguous"),
        (first.instruction_guest_pc, first.form, first.width)
    );
    assert!(matches!(
        select_site(
            &report,
            Ps2EeObserverSiteSelector::GuestPc(first.instruction_guest_pc)
        ),
        Err(Ps2EeObserverError::AmbiguousSiteGuestPc { .. })
    ));
}

#[test]
fn differing_constants_at_a_diamond_join_emit_no_stale_site() {
    let mut bytes = synthetic_elf(CODE0_VA);
    let branch_pc = CODE0_VA;
    let taken_pc = CODE0_VA + 0x20;
    let join_pc = CODE0_VA + 0x40;
    put_word_at_va(
        &mut bytes,
        branch_pc,
        branch(0x04, 2, 3, branch_pc, taken_pc),
    );
    put_word_at_va(&mut bytes, branch_pc + 4, 0);
    put_word_at_va(&mut bytes, branch_pc + 8, immediate(0x0f, 0, 8, 0x20));
    put_word_at_va(&mut bytes, branch_pc + 0x0c, jump(0x02, join_pc));
    put_word_at_va(&mut bytes, branch_pc + 0x10, 0);
    put_word_at_va(&mut bytes, taken_pc, immediate(0x0f, 0, 8, 0x20));
    put_word_at_va(&mut bytes, taken_pc + 4, immediate(0x09, 8, 8, 0x20));
    put_word_at_va(&mut bytes, taken_pc + 8, jump(0x02, join_pc));
    put_word_at_va(&mut bytes, taken_pc + 0x0c, 0);
    put_word_at_va(&mut bytes, join_pc, immediate(0x23, 8, 2, 0));
    put_word_at_va(&mut bytes, join_pc + 4, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, join_pc + 8, 0);

    let report = scan(&bytes);
    assert!(
        report
            .data_xrefs
            .iter()
            .all(|xref| { xref.instruction_guest_pc != u64::from(join_pc) })
    );
    assert!(
        report
            .observer_sites
            .iter()
            .all(|site| { site.instruction_guest_pc != u64::from(join_pc) })
    );
}

#[test]
fn definite_trapping_integer_overflow_terminates_the_path() {
    let mut bytes = synthetic_elf(CODE0_VA);
    put_word_at_va(&mut bytes, CODE0_VA, immediate(0x0f, 0, 9, 0x20));
    put_word_at_va(&mut bytes, CODE0_VA + 4, immediate(0x0f, 0, 8, 0x7fff));
    put_word_at_va(&mut bytes, CODE0_VA + 8, immediate(0x0d, 8, 8, 0xffff));
    put_word_at_va(&mut bytes, CODE0_VA + 0x0c, immediate(0x08, 8, 8, 1));
    put_word_at_va(&mut bytes, CODE0_VA + 0x10, immediate(0x23, 9, 2, 0));

    let report = scan(&bytes);
    assert!(report.basic_blocks.iter().any(|block| {
        block.terminator_guest_pc == Some(u64::from(CODE0_VA + 0x0c))
            && block.terminator == Ps2EeBlockTerminator::ArithmeticTrap
    }));
    assert!(
        report
            .data_xrefs
            .iter()
            .all(|xref| { xref.instruction_guest_pc != u64::from(CODE0_VA + 0x10) })
    );
}

#[test]
fn definite_overflow_in_a_required_delay_slot_is_an_arithmetic_trap() {
    let mut bytes = synthetic_elf(CODE0_VA);
    let branch_pc = CODE0_VA + 8;
    let target = CODE0_VA + 0x20;
    put_word_at_va(&mut bytes, CODE0_VA, immediate(0x0f, 0, 8, 0x7fff));
    put_word_at_va(&mut bytes, CODE0_VA + 4, immediate(0x0d, 8, 8, 0xffff));
    put_word_at_va(&mut bytes, branch_pc, branch(0x04, 2, 3, branch_pc, target));
    put_word_at_va(&mut bytes, branch_pc + 4, immediate(0x08, 8, 8, 1));
    put_word_at_va(&mut bytes, branch_pc + 8, immediate(0x23, 9, 2, 0));
    put_word_at_va(&mut bytes, target, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, target + 4, 0);

    let report = scan(&bytes);
    let block = report
        .basic_blocks
        .iter()
        .find(|block| {
            block.start_guest_va == u64::from(CODE0_VA)
                && block.terminator == Ps2EeBlockTerminator::ArithmeticTrap
        })
        .expect("the trapping branch block is retained");
    assert_eq!(block.terminator, Ps2EeBlockTerminator::ArithmeticTrap);
    assert_eq!(block.terminator_guest_pc, Some(u64::from(branch_pc + 4)));
    assert_eq!(block.decoded_word_count, 4);
    assert!(
        report
            .cfg_edges
            .iter()
            .all(|edge| edge.instruction_guest_pc != u64::from(branch_pc))
    );
}

#[test]
fn branch_likely_delay_trap_preserves_only_the_annulled_not_taken_path() {
    let mut bytes = synthetic_elf(CODE0_VA);
    let branch_pc = CODE0_VA + 0x0c;
    let continuation = branch_pc + 8;
    let target = CODE0_VA + 0x30;
    put_word_at_va(&mut bytes, CODE0_VA, immediate(0x0f, 0, 9, 0x20));
    put_word_at_va(&mut bytes, CODE0_VA + 4, immediate(0x0f, 0, 8, 0x7fff));
    put_word_at_va(&mut bytes, CODE0_VA + 8, immediate(0x0d, 8, 8, 0xffff));
    put_word_at_va(&mut bytes, branch_pc, branch(0x14, 2, 3, branch_pc, target));
    put_word_at_va(&mut bytes, branch_pc + 4, immediate(0x08, 8, 8, 1));
    put_word_at_va(&mut bytes, continuation, immediate(0x23, 9, 2, 0));
    put_word_at_va(&mut bytes, continuation + 4, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, continuation + 8, 0);
    put_word_at_va(&mut bytes, target, immediate(0x23, 9, 3, 0));
    put_word_at_va(&mut bytes, target + 4, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut bytes, target + 8, 0);

    let report = scan(&bytes);
    let block = report
        .basic_blocks
        .iter()
        .find(|block| block.terminator_guest_pc == Some(u64::from(branch_pc)))
        .expect("the likely branch block is retained");
    assert_eq!(block.terminator, Ps2EeBlockTerminator::ConditionalBranch);
    assert_eq!(block.terminator_guest_pc, Some(u64::from(branch_pc)));
    assert_eq!(block.decoded_word_count, 5);
    let branch_edges: Vec<_> = report
        .cfg_edges
        .iter()
        .filter(|edge| edge.instruction_guest_pc == u64::from(branch_pc))
        .collect();
    assert_eq!(branch_edges.len(), 1);
    assert_eq!(branch_edges[0].kind, Ps2EeCfgEdgeKind::BranchNotTaken);
    assert_eq!(branch_edges[0].target_guest_va, u64::from(continuation));
    assert!(report.data_xrefs.iter().any(|xref| {
        xref.instruction_guest_pc == u64::from(continuation)
            && xref.target_guest_va == u64::from(DATA_VA)
    }));
    assert!(
        report
            .data_xrefs
            .iter()
            .all(|xref| xref.instruction_guest_pc != u64::from(target))
    );
}

#[test]
fn direct_and_indirect_call_delay_traps_report_the_delay_instruction_pc() {
    let direct_call_pc = CODE0_VA + 8;
    let direct_target = CODE0_VA + 0x40;
    let mut direct = synthetic_elf(CODE0_VA);
    put_word_at_va(&mut direct, CODE0_VA, immediate(0x0f, 0, 8, 0x7fff));
    put_word_at_va(&mut direct, CODE0_VA + 4, immediate(0x0d, 8, 8, 0xffff));
    put_word_at_va(&mut direct, direct_call_pc, jump(0x03, direct_target));
    put_word_at_va(&mut direct, direct_call_pc + 4, immediate(0x08, 8, 8, 1));
    put_word_at_va(&mut direct, direct_target, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut direct, direct_target + 4, 0);

    let direct_report = scan(&direct);
    let direct_block = direct_report
        .basic_blocks
        .iter()
        .find(|block| block.start_guest_va == u64::from(CODE0_VA))
        .expect("direct-call block is retained");
    assert_eq!(
        direct_block.terminator,
        Ps2EeBlockTerminator::ArithmeticTrap
    );
    assert_eq!(
        direct_block.terminator_guest_pc,
        Some(u64::from(direct_call_pc + 4))
    );
    assert_eq!(direct_block.decoded_word_count, 4);
    assert!(
        direct_report
            .cfg_edges
            .iter()
            .all(|edge| edge.instruction_guest_pc != u64::from(direct_call_pc))
    );

    let indirect_call_pc = CODE0_VA + 8;
    let mut indirect = synthetic_elf(CODE0_VA);
    put_word_at_va(&mut indirect, CODE0_VA, immediate(0x0f, 0, 8, 0x7fff));
    put_word_at_va(&mut indirect, CODE0_VA + 4, immediate(0x0d, 8, 8, 0xffff));
    put_word_at_va(&mut indirect, indirect_call_pc, special(25, 0, 31, 0, 0x09));
    put_word_at_va(
        &mut indirect,
        indirect_call_pc + 4,
        immediate(0x08, 8, 8, 1),
    );

    let indirect_report = scan(&indirect);
    let indirect_block = indirect_report
        .basic_blocks
        .iter()
        .find(|block| block.start_guest_va == u64::from(CODE0_VA))
        .expect("indirect-call block is retained");
    assert_eq!(
        indirect_block.terminator,
        Ps2EeBlockTerminator::ArithmeticTrap
    );
    assert_eq!(
        indirect_block.terminator_guest_pc,
        Some(u64::from(indirect_call_pc + 4))
    );
    assert_eq!(indirect_block.decoded_word_count, 4);
    assert!(
        indirect_report
            .cfg_edges
            .iter()
            .all(|edge| edge.instruction_guest_pc != u64::from(indirect_call_pc))
    );
}

#[test]
fn sparse_many_segment_coverage_remains_exact_and_sorted() {
    const SEGMENT_COUNT: usize = 128;
    let bytes = synthetic_many_exec_segments(SEGMENT_COUNT);
    let report = scan(&bytes);
    assert_eq!(report.executable_coverage.len(), SEGMENT_COUNT);
    assert_eq!(report.scanned_word_count, (SEGMENT_COUNT * 2) as u64);
    assert!(
        report
            .executable_coverage
            .windows(2)
            .all(|pair| { pair[0].end_guest_va < pair[1].start_guest_va })
    );
    assert_eq!(
        report
            .function_seeds
            .iter()
            .filter(|seed| {
                seed.sources
                    .contains(&Ps2EeFunctionSeedSource::ExecutableSegmentStart)
            })
            .count(),
        SEGMENT_COUNT
    );
}

#[test]
fn eligible_elf_without_one_aligned_executable_word_is_rejected() {
    let mut bytes = synthetic_elf(CODE0_VA);
    put_u32(&mut bytes, PROGRAM_HEADER_OFFSET + 16, 1);
    put_u32(&mut bytes, PROGRAM_HEADER_OFFSET + 20, 1);
    let code1_header = PROGRAM_HEADER_OFFSET + 2 * ELF32_PROGRAM_HEADER_SIZE;
    put_u32(&mut bytes, code1_header + 24, 4);
    let error =
        scan_ps2_ee_observer_sites(&bytes, latest_selection(), Ps2EeObserverLimits::default())
            .expect_err("a byte-sized executable entry mapping has no complete word");
    assert!(
        error
            .to_string()
            .contains("aligned fully file-backed executable word")
    );
}

#[test]
fn entry_point_must_be_an_aligned_complete_executable_word() {
    for entry_va in [CODE0_VA + 1, CODE0_VA + CODE0_SIZE as u32 - 1] {
        let mut bytes = minimal_observer_elf();
        put_u32(&mut bytes, 24, entry_va);
        assert_eq!(analyzed_elf(&bytes).entry_va, u64::from(entry_va));
        let error =
            scan_ps2_ee_observer_sites(&bytes, latest_selection(), Ps2EeObserverLimits::default())
                .expect_err("an incomplete or misaligned entry word must fail closed");
        assert!(matches!(
            error,
            Ps2EeObserverError::IneligibleContainer {
                requirement: "an aligned, complete, file-backed executable entry-point word"
            }
        ));
    }
}

#[test]
fn executable_coverage_fails_before_r5900_pc_arithmetic_can_wrap() {
    let safe = terminal_exec_word_elf(0xffff_fff4);
    let safe_report = scan(&safe);
    assert!(safe_report.executable_coverage.iter().any(|coverage| {
        coverage.start_guest_va == 0xffff_fff4 && coverage.end_guest_va == 0xffff_fff8
    }));
    assert!(
        safe_report
            .basic_blocks
            .iter()
            .all(|block| block.end_guest_va >= block.start_guest_va)
    );

    let wrapping = terminal_exec_word_elf(0xffff_fff8);
    assert_eq!(analyzed_elf(&wrapping).entry_va, 0xffff_fff8);
    let error = scan_ps2_ee_observer_sites(
        &wrapping,
        latest_selection(),
        Ps2EeObserverLimits::default(),
    )
    .expect_err("a decoded PC whose PC+8 wraps cannot enter the linear report");
    assert!(matches!(
        error,
        Ps2EeObserverError::IneligibleContainer {
            requirement: "executable coverage below the R5900 PC wrap boundary"
        }
    ));
}

#[test]
fn limits_only_tighten_hard_caps_and_fail_all_or_nothing() {
    Ps2EeObserverLimits::new(
        MAX_PS2_EE_OBSERVER_SCAN_BYTES,
        MAX_PS2_EE_OBSERVER_WORDS,
        MAX_PS2_EE_OBSERVER_SEEDS,
        MAX_PS2_EE_OBSERVER_BLOCKS,
        MAX_PS2_EE_OBSERVER_EDGES,
        MAX_PS2_EE_OBSERVER_SITES,
        MAX_PS2_EE_OBSERVER_XREFS,
        MAX_PS2_EE_OBSERVER_STRING_BYTES,
        MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
    )
    .expect("every exact hard ceiling is valid");
    let hard = [
        MAX_PS2_EE_OBSERVER_SCAN_BYTES,
        MAX_PS2_EE_OBSERVER_WORDS as u64,
        MAX_PS2_EE_OBSERVER_SEEDS as u64,
        MAX_PS2_EE_OBSERVER_BLOCKS as u64,
        MAX_PS2_EE_OBSERVER_EDGES as u64,
        MAX_PS2_EE_OBSERVER_SITES as u64,
        MAX_PS2_EE_OBSERVER_XREFS as u64,
        MAX_PS2_EE_OBSERVER_STRING_BYTES as u64,
        MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES as u64,
    ];
    let construct = |values: [u64; 9]| {
        Ps2EeObserverLimits::new(
            values[0],
            usize::try_from(values[1]).expect("word limit fits usize"),
            usize::try_from(values[2]).expect("seed limit fits usize"),
            usize::try_from(values[3]).expect("block limit fits usize"),
            usize::try_from(values[4]).expect("edge limit fits usize"),
            usize::try_from(values[5]).expect("site limit fits usize"),
            usize::try_from(values[6]).expect("xref limit fits usize"),
            usize::try_from(values[7]).expect("string limit fits usize"),
            usize::try_from(values[8]).expect("aggregate string limit fits usize"),
        )
    };
    for index in 0..hard.len() {
        let mut empty = hard;
        empty[index] = 0;
        assert!(
            matches!(construct(empty), Err(Ps2EeObserverError::EmptyLimit { .. })),
            "limit field {index} accepted zero"
        );
        let mut oversized = hard;
        oversized[index] += 1;
        assert!(
            matches!(
                construct(oversized),
                Err(Ps2EeObserverError::LimitTooLarge { .. })
            ),
            "limit field {index} widened its hard ceiling"
        );
    }

    let bytes = minimal_observer_elf();
    let tight = limits_with(
        1,
        MAX_PS2_EE_OBSERVER_SITES,
        MAX_PS2_EE_OBSERVER_STRING_BYTES,
        MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
    );
    let first = scan_ps2_ee_observer_sites(&bytes, latest_selection(), tight)
        .expect_err("one word cannot cover the synthetic executable segments");
    let second = scan_ps2_ee_observer_sites(&bytes, latest_selection(), tight)
        .expect_err("the same complete scan fails identically");
    assert_eq!(first.to_string(), second.to_string());
    assert!(matches!(
        first,
        Ps2EeObserverError::OutputLimitExceeded {
            kind: "executable words",
            ..
        }
    ));
}

#[test]
fn every_bounded_output_collection_honors_exact_and_one_below_limits() {
    let minimal = minimal_observer_elf();
    let exact_minimal = observer_limits(
        0x400,
        0x100,
        2,
        2,
        MAX_PS2_EE_OBSERVER_EDGES,
        MAX_PS2_EE_OBSERVER_SITES,
        MAX_PS2_EE_OBSERVER_XREFS,
        MAX_PS2_EE_OBSERVER_STRING_BYTES,
        MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
    );
    let minimal_report = scan_ps2_ee_observer_sites(&minimal, latest_selection(), exact_minimal)
        .expect("exact scan, word, seed, and block bounds are accepted");
    assert_eq!(minimal_report.scanned_word_count, 0x100);
    assert_eq!(minimal_report.function_seeds.len(), 2);
    assert_eq!(minimal_report.basic_blocks.len(), 2);
    assert_output_limit_kind(
        &minimal,
        observer_limits(
            0x3ff,
            MAX_PS2_EE_OBSERVER_WORDS,
            MAX_PS2_EE_OBSERVER_SEEDS,
            MAX_PS2_EE_OBSERVER_BLOCKS,
            MAX_PS2_EE_OBSERVER_EDGES,
            MAX_PS2_EE_OBSERVER_SITES,
            MAX_PS2_EE_OBSERVER_XREFS,
            MAX_PS2_EE_OBSERVER_STRING_BYTES,
            MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
        ),
        "executable scan bytes",
    );
    assert_output_limit_kind(
        &minimal,
        observer_limits(
            MAX_PS2_EE_OBSERVER_SCAN_BYTES,
            0xff,
            MAX_PS2_EE_OBSERVER_SEEDS,
            MAX_PS2_EE_OBSERVER_BLOCKS,
            MAX_PS2_EE_OBSERVER_EDGES,
            MAX_PS2_EE_OBSERVER_SITES,
            MAX_PS2_EE_OBSERVER_XREFS,
            MAX_PS2_EE_OBSERVER_STRING_BYTES,
            MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
        ),
        "executable words",
    );
    assert_output_limit_kind(
        &minimal,
        observer_limits(
            MAX_PS2_EE_OBSERVER_SCAN_BYTES,
            MAX_PS2_EE_OBSERVER_WORDS,
            1,
            MAX_PS2_EE_OBSERVER_BLOCKS,
            MAX_PS2_EE_OBSERVER_EDGES,
            MAX_PS2_EE_OBSERVER_SITES,
            MAX_PS2_EE_OBSERVER_XREFS,
            MAX_PS2_EE_OBSERVER_STRING_BYTES,
            MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
        ),
        "function seeds",
    );
    assert_output_limit_kind(
        &minimal,
        observer_limits(
            MAX_PS2_EE_OBSERVER_SCAN_BYTES,
            MAX_PS2_EE_OBSERVER_WORDS,
            MAX_PS2_EE_OBSERVER_SEEDS,
            1,
            MAX_PS2_EE_OBSERVER_EDGES,
            MAX_PS2_EE_OBSERVER_SITES,
            MAX_PS2_EE_OBSERVER_XREFS,
            MAX_PS2_EE_OBSERVER_STRING_BYTES,
            MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
        ),
        "basic-block boundaries",
    );

    let mut branching = minimal_observer_elf();
    let target = CODE0_VA + 0x20;
    put_word_at_va(
        &mut branching,
        CODE0_VA,
        branch(0x04, 2, 3, CODE0_VA, target),
    );
    put_word_at_va(&mut branching, CODE0_VA + 4, 0);
    put_word_at_va(&mut branching, CODE0_VA + 8, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut branching, CODE0_VA + 0x0c, 0);
    put_word_at_va(&mut branching, target, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut branching, target + 4, 0);
    let exact_edges = observer_limits(
        MAX_PS2_EE_OBSERVER_SCAN_BYTES,
        MAX_PS2_EE_OBSERVER_WORDS,
        MAX_PS2_EE_OBSERVER_SEEDS,
        MAX_PS2_EE_OBSERVER_BLOCKS,
        2,
        MAX_PS2_EE_OBSERVER_SITES,
        MAX_PS2_EE_OBSERVER_XREFS,
        MAX_PS2_EE_OBSERVER_STRING_BYTES,
        MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
    );
    assert_eq!(
        scan_ps2_ee_observer_sites(&branching, latest_selection(), exact_edges)
            .expect("two exact branch edges fit")
            .cfg_edges
            .len(),
        2
    );
    assert_output_limit_kind(
        &branching,
        observer_limits(
            MAX_PS2_EE_OBSERVER_SCAN_BYTES,
            MAX_PS2_EE_OBSERVER_WORDS,
            MAX_PS2_EE_OBSERVER_SEEDS,
            MAX_PS2_EE_OBSERVER_BLOCKS,
            1,
            MAX_PS2_EE_OBSERVER_SITES,
            MAX_PS2_EE_OBSERVER_XREFS,
            MAX_PS2_EE_OBSERVER_STRING_BYTES,
            MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
        ),
        "CFG edges",
    );

    let mut accesses = minimal_observer_elf();
    put_word_at_va(&mut accesses, CODE0_VA, immediate(0x0f, 0, 8, 0x20));
    put_word_at_va(&mut accesses, CODE0_VA + 4, immediate(0x24, 8, 2, 0));
    put_word_at_va(&mut accesses, CODE0_VA + 8, immediate(0x24, 8, 3, 1));
    put_word_at_va(&mut accesses, CODE0_VA + 0x0c, special(31, 0, 0, 0, 0x08));
    put_word_at_va(&mut accesses, CODE0_VA + 0x10, 0);
    let exact_accesses = observer_limits(
        MAX_PS2_EE_OBSERVER_SCAN_BYTES,
        MAX_PS2_EE_OBSERVER_WORDS,
        MAX_PS2_EE_OBSERVER_SEEDS,
        MAX_PS2_EE_OBSERVER_BLOCKS,
        MAX_PS2_EE_OBSERVER_EDGES,
        2,
        2,
        MAX_PS2_EE_OBSERVER_STRING_BYTES,
        MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
    );
    let access_report = scan_ps2_ee_observer_sites(&accesses, latest_selection(), exact_accesses)
        .expect("two exact xrefs and sites fit");
    assert_eq!(access_report.data_xrefs.len(), 2);
    assert_eq!(access_report.observer_sites.len(), 2);
    assert_output_limit_kind(
        &accesses,
        observer_limits(
            MAX_PS2_EE_OBSERVER_SCAN_BYTES,
            MAX_PS2_EE_OBSERVER_WORDS,
            MAX_PS2_EE_OBSERVER_SEEDS,
            MAX_PS2_EE_OBSERVER_BLOCKS,
            MAX_PS2_EE_OBSERVER_EDGES,
            MAX_PS2_EE_OBSERVER_SITES,
            1,
            MAX_PS2_EE_OBSERVER_STRING_BYTES,
            MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
        ),
        "data xrefs",
    );
    assert_output_limit_kind(
        &accesses,
        observer_limits(
            MAX_PS2_EE_OBSERVER_SCAN_BYTES,
            MAX_PS2_EE_OBSERVER_WORDS,
            MAX_PS2_EE_OBSERVER_SEEDS,
            MAX_PS2_EE_OBSERVER_BLOCKS,
            MAX_PS2_EE_OBSERVER_EDGES,
            1,
            2,
            MAX_PS2_EE_OBSERVER_STRING_BYTES,
            MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
        ),
        "observer sites",
    );

    let mut materializations = minimal_observer_elf();
    put_word_at_va(&mut materializations, CODE0_VA, immediate(0x0f, 0, 8, 0x20));
    put_word_at_va(
        &mut materializations,
        CODE0_VA + 4,
        immediate(0x0f, 0, 9, 0x20),
    );
    put_word_at_va(
        &mut materializations,
        CODE0_VA + 8,
        special(31, 0, 0, 0, 0x08),
    );
    put_word_at_va(&mut materializations, CODE0_VA + 0x0c, 0);
    let exact_materializations = observer_limits(
        MAX_PS2_EE_OBSERVER_SCAN_BYTES,
        MAX_PS2_EE_OBSERVER_WORDS,
        MAX_PS2_EE_OBSERVER_SEEDS,
        MAX_PS2_EE_OBSERVER_BLOCKS,
        MAX_PS2_EE_OBSERVER_EDGES,
        MAX_PS2_EE_OBSERVER_SITES,
        2,
        MAX_PS2_EE_OBSERVER_STRING_BYTES,
        MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
    );
    assert_eq!(
        scan_ps2_ee_observer_sites(
            &materializations,
            latest_selection(),
            exact_materializations,
        )
        .expect("two exact materializations fit")
        .address_materializations
        .len(),
        2
    );
    assert_output_limit_kind(
        &materializations,
        observer_limits(
            MAX_PS2_EE_OBSERVER_SCAN_BYTES,
            MAX_PS2_EE_OBSERVER_WORDS,
            MAX_PS2_EE_OBSERVER_SEEDS,
            MAX_PS2_EE_OBSERVER_BLOCKS,
            MAX_PS2_EE_OBSERVER_EDGES,
            MAX_PS2_EE_OBSERVER_SITES,
            1,
            MAX_PS2_EE_OBSERVER_STRING_BYTES,
            MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
        ),
        "address materializations",
    );
}

fn single_string_fixture(content_bytes: usize) -> Vec<u8> {
    let (mut bytes, data_file) = synthetic_two_segment_elf(0x10, content_bytes + 1);
    put_large_code_word(&mut bytes, 0, immediate(0x0f, 0, 8, 0x0200));
    put_large_code_word(&mut bytes, 1, immediate(0x24, 8, 2, 0));
    put_large_code_word(&mut bytes, 2, special(31, 0, 0, 0, 0x08));
    put_large_code_word(&mut bytes, 3, 0);
    bytes[data_file..data_file + content_bytes].fill(b'A');
    bytes
}

#[test]
fn string_anchor_accepts_the_exact_bound_and_omits_an_oversized_value() {
    let exact = single_string_fixture(MAX_PS2_EE_OBSERVER_STRING_BYTES - 1);
    let exact_report = scan(&exact);
    let anchor = exact_report.observer_sites[0]
        .string_anchor
        .as_ref()
        .expect("4095 printable bytes plus NUL fit the 4096-byte scan bound");
    assert_eq!(anchor.value.len(), MAX_PS2_EE_OBSERVER_STRING_BYTES - 1);
    assert_eq!(
        usize::try_from(anchor.byte_size).expect("small anchor"),
        MAX_PS2_EE_OBSERVER_STRING_BYTES
    );

    let oversized = single_string_fixture(MAX_PS2_EE_OBSERVER_STRING_BYTES);
    let oversized_report = scan(&oversized);
    assert!(oversized_report.observer_sites[0].string_anchor.is_none());
}

fn aggregate_string_fixture(count: usize, content_bytes: usize) -> Vec<u8> {
    let code_words = count
        .checked_mul(3)
        .and_then(|value| value.checked_add(2))
        .expect("bounded synthetic code words");
    let stride = content_bytes + 1;
    let data_size = count
        .checked_mul(stride)
        .expect("bounded synthetic string data");
    let (mut bytes, data_file) = synthetic_two_segment_elf(code_words * 4, data_size);
    for index in 0..count {
        let guest_va = LARGE_DATA_VA
            .checked_add(u32::try_from(index * stride).expect("bounded data offset"))
            .expect("bounded guest string address");
        let word_index = index * 3;
        put_large_code_word(
            &mut bytes,
            word_index,
            immediate(0x0f, 0, 8, (guest_va >> 16) as u16),
        );
        put_large_code_word(
            &mut bytes,
            word_index + 1,
            immediate(0x0d, 8, 8, guest_va as u16),
        );
        put_large_code_word(&mut bytes, word_index + 2, immediate(0x24, 8, 2, 0));
        let start = data_file + index * stride;
        bytes[start..start + content_bytes].fill(b'A');
    }
    put_large_code_word(&mut bytes, count * 3, special(31, 0, 0, 0, 0x08));
    put_large_code_word(&mut bytes, count * 3 + 1, 0);
    bytes
}

#[test]
fn aggregate_owned_string_cap_is_exact_and_overflow_is_all_or_nothing() {
    const STRING_COUNT: usize = 4_097;
    const CONTENT_BYTES: usize = MAX_PS2_EE_OBSERVER_STRING_BYTES - 1;
    const EXACT_TOTAL: usize = STRING_COUNT * CONTENT_BYTES;
    assert_eq!(EXACT_TOTAL, MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES - 1);
    let bytes = aggregate_string_fixture(STRING_COUNT, CONTENT_BYTES);

    let exact_limits = limits_with(
        MAX_PS2_EE_OBSERVER_WORDS,
        STRING_COUNT,
        MAX_PS2_EE_OBSERVER_STRING_BYTES,
        EXACT_TOTAL,
    );
    let exact_report = scan_ps2_ee_observer_sites(&bytes, latest_selection(), exact_limits)
        .expect("the exact aggregate owned-string total is accepted");
    assert_eq!(
        exact_report
            .observer_sites
            .iter()
            .filter(|site| site.string_anchor.is_some())
            .count(),
        STRING_COUNT
    );
    drop(exact_report);

    let over_limits = limits_with(
        MAX_PS2_EE_OBSERVER_WORDS,
        STRING_COUNT,
        MAX_PS2_EE_OBSERVER_STRING_BYTES,
        EXACT_TOTAL - 1,
    );
    assert!(matches!(
        scan_ps2_ee_observer_sites(&bytes, latest_selection(), over_limits),
        Err(Ps2EeObserverError::OutputLimitExceeded {
            kind: "aggregate string-anchor bytes",
            ..
        })
    ));
}
