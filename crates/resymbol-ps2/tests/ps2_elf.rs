//! Source-built coverage for the explicit PS2 EE ELF facade.
//!
//! Every byte in these fixtures is synthetic and redistributable. No test
//! reads a path, owner binary, disc image, or emulator artifact.

use resymbol_analysis::{DecoderProfile, ElfClass, ElfEndian, TargetArch, analyze_elf};
use resymbol_core::BinaryId;
use resymbol_ps2::{
    MAX_PS2_EE_ELF_NAME_BYTES, Ps2EeElfError, Ps2EeElfImage, Ps2ProgramHeaderKind, Ps2SectionKind,
    Ps2SymbolBinding, Ps2SymbolKind, analyze_ps2_elf, is_explicit_ps2_ee_decoder_profile,
};

const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_TYPE_DYNAMIC: u16 = 3;
const ELF_MACHINE_386: u16 = 3;
const ELF_MACHINE_MIPS: u16 = 8;
const ENTRY_VA: u32 = 0x0010_0010;
const IMAGE_BASE: u32 = 0x0010_0000;
const OTHER_PROGRAM_TYPE: u32 = 0x7000_0001;
const OTHER_SECTION_TYPE: u32 = 0x7000_0042;

mod layout {
    pub const ELF_HEADER: usize = 52;
    pub const PROGRAM_HEADER_SIZE: usize = 32;
    pub const PROGRAM_HEADER_COUNT: usize = 2;
    pub const TEXT: usize = 0x100;
    pub const TEXT_FILE_SIZE: usize = 0x80;
    pub const SYMTAB: usize = 0x200;
    pub const SYMBOL_SIZE: usize = 16;
    pub const SYMBOL_COUNT: usize = 4;
    pub const STRTAB: usize = 0x240;
    pub const SHSTRTAB: usize = 0x280;
    pub const CUSTOM: usize = 0x2c0;
    pub const SECTION_HEADERS: usize = 0x300;
    pub const SECTION_HEADER_SIZE: usize = 40;
    pub const SECTION_COUNT: usize = 7;
    pub const SHSTRTAB_INDEX: usize = 5;
    pub const TOTAL: usize = 0x420;
}

const SECTION_NAMES: &[u8] = b"\0.text\0.bss\0.symtab\0.strtab\0.shstrtab\0.custom\0";
const SYMBOL_NAMES: &[u8] = b"\0entry_fn\0global_obj\0odd_symbol\0";

#[derive(Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    const fn ident(self) -> u8 {
        match self {
            Self::Little => 1,
            Self::Big => 2,
        }
    }
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16, order: ByteOrder) {
    let encoded = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + encoded.len()].copy_from_slice(&encoded);
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32, order: ByteOrder) {
    let encoded = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + encoded.len()].copy_from_slice(&encoded);
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64, order: ByteOrder) {
    let encoded = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + encoded.len()].copy_from_slice(&encoded);
}

struct ProgramHeaderSpec {
    segment_type: u32,
    file_offset: u32,
    virtual_address: u32,
    physical_address: u32,
    file_size: u32,
    memory_size: u32,
    flags: u32,
    alignment: u32,
}

fn write_program_header(
    bytes: &mut [u8],
    index: usize,
    spec: &ProgramHeaderSpec,
    order: ByteOrder,
) {
    let base = layout::ELF_HEADER + index * layout::PROGRAM_HEADER_SIZE;
    put_u32(bytes, base, spec.segment_type, order);
    put_u32(bytes, base + 4, spec.file_offset, order);
    put_u32(bytes, base + 8, spec.virtual_address, order);
    put_u32(bytes, base + 12, spec.physical_address, order);
    put_u32(bytes, base + 16, spec.file_size, order);
    put_u32(bytes, base + 20, spec.memory_size, order);
    put_u32(bytes, base + 24, spec.flags, order);
    put_u32(bytes, base + 28, spec.alignment, order);
}

struct SectionSpec {
    name: u32,
    section_type: u32,
    flags: u32,
    virtual_address: u32,
    file_offset: u32,
    size: u32,
    link: u32,
    info: u32,
    alignment: u32,
    entry_size: u32,
}

impl SectionSpec {
    const fn null() -> Self {
        Self {
            name: 0,
            section_type: 0,
            flags: 0,
            virtual_address: 0,
            file_offset: 0,
            size: 0,
            link: 0,
            info: 0,
            alignment: 0,
            entry_size: 0,
        }
    }
}

fn section_header_offset(index: usize) -> usize {
    layout::SECTION_HEADERS + index * layout::SECTION_HEADER_SIZE
}

fn write_section(bytes: &mut [u8], index: usize, spec: &SectionSpec, order: ByteOrder) {
    let base = section_header_offset(index);
    put_u32(bytes, base, spec.name, order);
    put_u32(bytes, base + 4, spec.section_type, order);
    put_u32(bytes, base + 8, spec.flags, order);
    put_u32(bytes, base + 12, spec.virtual_address, order);
    put_u32(bytes, base + 16, spec.file_offset, order);
    put_u32(bytes, base + 20, spec.size, order);
    put_u32(bytes, base + 24, spec.link, order);
    put_u32(bytes, base + 28, spec.info, order);
    put_u32(bytes, base + 32, spec.alignment, order);
    put_u32(bytes, base + 36, spec.entry_size, order);
}

struct SymbolSpec {
    name: u32,
    value: u32,
    size: u32,
    info: u8,
    other: u8,
    section_index: u16,
}

fn write_symbol(bytes: &mut [u8], index: usize, spec: &SymbolSpec, order: ByteOrder) {
    let base = layout::SYMTAB + index * layout::SYMBOL_SIZE;
    put_u32(bytes, base, spec.name, order);
    put_u32(bytes, base + 4, spec.value, order);
    put_u32(bytes, base + 8, spec.size, order);
    bytes[base + 12] = spec.info;
    bytes[base + 13] = spec.other;
    put_u16(bytes, base + 14, spec.section_index, order);
}

/// Fully valid ELF32 image with one aligned executable `PT_LOAD`, an entry in
/// its file-backed range, valid section-name and symbol string tables, and one
/// deliberately unknown program/section type for raw-preservation checks.
fn synthetic_elf32(order: ByteOrder, elf_type: u16, machine: u16) -> Vec<u8> {
    let mut bytes = vec![0_u8; layout::TOTAL];
    bytes[..16].copy_from_slice(&[
        0x7f,
        b'E',
        b'L',
        b'F',
        1,
        order.ident(),
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    put_u16(&mut bytes, 16, elf_type, order);
    put_u16(&mut bytes, 18, machine, order);
    put_u32(&mut bytes, 20, 1, order);
    put_u32(&mut bytes, 24, ENTRY_VA, order);
    put_u32(&mut bytes, 28, layout::ELF_HEADER as u32, order);
    put_u32(&mut bytes, 32, layout::SECTION_HEADERS as u32, order);
    put_u32(&mut bytes, 36, 0x2092_4001, order);
    put_u16(&mut bytes, 40, layout::ELF_HEADER as u16, order);
    put_u16(&mut bytes, 42, layout::PROGRAM_HEADER_SIZE as u16, order);
    put_u16(&mut bytes, 44, layout::PROGRAM_HEADER_COUNT as u16, order);
    put_u16(&mut bytes, 46, layout::SECTION_HEADER_SIZE as u16, order);
    put_u16(&mut bytes, 48, layout::SECTION_COUNT as u16, order);
    put_u16(&mut bytes, 50, layout::SHSTRTAB_INDEX as u16, order);

    write_program_header(
        &mut bytes,
        0,
        &ProgramHeaderSpec {
            segment_type: 1,
            file_offset: layout::TEXT as u32,
            virtual_address: IMAGE_BASE,
            physical_address: IMAGE_BASE,
            file_size: layout::TEXT_FILE_SIZE as u32,
            memory_size: 0xa0,
            flags: 5,
            alignment: 0x100,
        },
        order,
    );
    write_program_header(
        &mut bytes,
        1,
        &ProgramHeaderSpec {
            segment_type: OTHER_PROGRAM_TYPE,
            file_offset: layout::CUSTOM as u32,
            virtual_address: 0,
            physical_address: 0,
            file_size: 4,
            memory_size: 4,
            flags: 4,
            alignment: 4,
        },
        order,
    );

    bytes[layout::TEXT..layout::TEXT + 8]
        .copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0xe0, 0x03]);
    bytes[layout::STRTAB..layout::STRTAB + SYMBOL_NAMES.len()].copy_from_slice(SYMBOL_NAMES);
    bytes[layout::SHSTRTAB..layout::SHSTRTAB + SECTION_NAMES.len()].copy_from_slice(SECTION_NAMES);
    bytes[layout::CUSTOM..layout::CUSTOM + 4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    write_symbol(
        &mut bytes,
        0,
        &SymbolSpec {
            name: 0,
            value: 0,
            size: 0,
            info: 0,
            other: 0,
            section_index: 0,
        },
        order,
    );
    write_symbol(
        &mut bytes,
        1,
        &SymbolSpec {
            name: 1,
            value: ENTRY_VA,
            size: 0x20,
            info: 0x12,
            other: 0,
            section_index: 1,
        },
        order,
    );
    write_symbol(
        &mut bytes,
        2,
        &SymbolSpec {
            name: 10,
            value: IMAGE_BASE + 0x80,
            size: 4,
            info: 0x21,
            other: 0,
            section_index: 2,
        },
        order,
    );
    write_symbol(
        &mut bytes,
        3,
        &SymbolSpec {
            name: 21,
            value: 0,
            size: 0,
            info: 0xaf,
            other: 0x7f,
            section_index: 0,
        },
        order,
    );

    write_section(&mut bytes, 0, &SectionSpec::null(), order);
    write_section(
        &mut bytes,
        1,
        &SectionSpec {
            name: 1,
            section_type: 1,
            flags: 6,
            virtual_address: IMAGE_BASE,
            file_offset: layout::TEXT as u32,
            size: 0x40,
            link: 0,
            info: 0,
            alignment: 16,
            entry_size: 0,
        },
        order,
    );
    write_section(
        &mut bytes,
        2,
        &SectionSpec {
            name: 7,
            section_type: 8,
            flags: 3,
            virtual_address: IMAGE_BASE + 0x80,
            file_offset: (layout::TEXT + layout::TEXT_FILE_SIZE) as u32,
            size: 0x20,
            link: 0,
            info: 0,
            alignment: 16,
            entry_size: 0,
        },
        order,
    );
    write_section(
        &mut bytes,
        3,
        &SectionSpec {
            name: 12,
            section_type: 2,
            flags: 0,
            virtual_address: 0,
            file_offset: layout::SYMTAB as u32,
            size: (layout::SYMBOL_COUNT * layout::SYMBOL_SIZE) as u32,
            link: 4,
            info: 1,
            alignment: 4,
            entry_size: layout::SYMBOL_SIZE as u32,
        },
        order,
    );
    write_section(
        &mut bytes,
        4,
        &SectionSpec {
            name: 20,
            section_type: 3,
            flags: 0,
            virtual_address: 0,
            file_offset: layout::STRTAB as u32,
            size: SYMBOL_NAMES.len() as u32,
            link: 0,
            info: 0,
            alignment: 1,
            entry_size: 0,
        },
        order,
    );
    write_section(
        &mut bytes,
        5,
        &SectionSpec {
            name: 28,
            section_type: 3,
            flags: 0,
            virtual_address: 0,
            file_offset: layout::SHSTRTAB as u32,
            size: SECTION_NAMES.len() as u32,
            link: 0,
            info: 0,
            alignment: 1,
            entry_size: 0,
        },
        order,
    );
    write_section(
        &mut bytes,
        6,
        &SectionSpec {
            name: 38,
            section_type: OTHER_SECTION_TYPE,
            flags: 0,
            virtual_address: 0,
            file_offset: layout::CUSTOM as u32,
            size: 4,
            link: 0,
            info: 0,
            alignment: 4,
            entry_size: 0,
        },
        order,
    );
    bytes
}

fn synthetic_elf64() -> Vec<u8> {
    const ELF64_HEADER: usize = 64;
    const PROGRAM_HEADER_SIZE: usize = 56;
    const TEXT: usize = 0x100;
    const TOTAL: usize = 0x110;
    let order = ByteOrder::Little;
    let mut bytes = vec![0_u8; TOTAL];
    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(&mut bytes, 16, ELF_TYPE_EXECUTABLE, order);
    put_u16(&mut bytes, 18, ELF_MACHINE_MIPS, order);
    put_u32(&mut bytes, 20, 1, order);
    put_u64(&mut bytes, 24, 0x0040_0000, order);
    put_u64(&mut bytes, 32, ELF64_HEADER as u64, order);
    put_u64(&mut bytes, 40, 0, order);
    put_u32(&mut bytes, 48, 0x2092_4001, order);
    put_u16(&mut bytes, 52, ELF64_HEADER as u16, order);
    put_u16(&mut bytes, 54, PROGRAM_HEADER_SIZE as u16, order);
    put_u16(&mut bytes, 56, 1, order);
    put_u16(&mut bytes, 58, 64, order);
    put_u16(&mut bytes, 60, 0, order);
    put_u16(&mut bytes, 62, 0, order);

    let ph = ELF64_HEADER;
    put_u32(&mut bytes, ph, 1, order);
    put_u32(&mut bytes, ph + 4, 5, order);
    put_u64(&mut bytes, ph + 8, TEXT as u64, order);
    put_u64(&mut bytes, ph + 16, 0x0040_0000, order);
    put_u64(&mut bytes, ph + 24, 0x0040_0000, order);
    put_u64(&mut bytes, ph + 32, 0x10, order);
    put_u64(&mut bytes, ph + 40, 0x10, order);
    put_u64(&mut bytes, ph + 48, 0x100, order);
    bytes
}

fn valid_elf() -> Vec<u8> {
    synthetic_elf32(ByteOrder::Little, ELF_TYPE_EXECUTABLE, ELF_MACHINE_MIPS)
}

fn replace_section_name_table(mut bytes: Vec<u8>, table: &[u8], name_offset: u32) -> Vec<u8> {
    let table_offset = bytes.len();
    bytes.extend_from_slice(table);
    let shstrtab = section_header_offset(layout::SHSTRTAB_INDEX);
    put_u32(
        &mut bytes,
        shstrtab + 16,
        table_offset as u32,
        ByteOrder::Little,
    );
    put_u32(
        &mut bytes,
        shstrtab + 20,
        table.len() as u32,
        ByteOrder::Little,
    );
    put_u32(
        &mut bytes,
        section_header_offset(1),
        name_offset,
        ByteOrder::Little,
    );
    bytes
}

fn assert_ineligible(bytes: &[u8], requirement: &'static str) {
    let generic = analyze_elf(bytes).expect("generic ELF analysis remains container-only");
    let direct = Ps2EeElfImage::new(bytes, &generic).expect_err("facade view must reject shape");
    match direct {
        Ps2EeElfError::IneligibleContainer {
            requirement: actual,
        } => assert_eq!(actual, requirement),
        other => panic!("unexpected facade error: {other:?}"),
    }

    let wrapped = analyze_ps2_elf(bytes).expect_err("facade parser must reject shape");
    match wrapped {
        Ps2EeElfError::IneligibleContainer {
            requirement: actual,
        } => assert_eq!(actual, requirement),
        other => panic!("unexpected facade parser error: {other:?}"),
    }
}

#[test]
fn canonical_analysis_and_view_are_bound_to_the_exact_source() {
    let bytes = valid_elf();
    let canonical = analyze_elf(&bytes).expect("canonical parser accepts fixture");
    let analysis = analyze_ps2_elf(&bytes).expect("explicit PS2 facade accepts fixture");

    assert_eq!(analysis, canonical);
    assert_eq!(analysis.class, ElfClass::Elf32);
    assert_eq!(analysis.endian, ElfEndian::Little);
    assert_eq!(analysis.elf_type, ELF_TYPE_EXECUTABLE);
    assert_eq!(analysis.machine, ELF_MACHINE_MIPS);
    assert_eq!(analysis.flags, 0x2092_4001);
    assert_eq!(analysis.identity.id, BinaryId::digest(&bytes));
    assert_eq!(analysis.identity.size, bytes.len() as u64);
    assert_eq!(analysis.identity.architecture, "elf32-em-mips-le");
    assert_eq!(analysis.identity.image_base, u64::from(IMAGE_BASE));
    assert_eq!(analysis.entry_va, u64::from(ENTRY_VA));
    assert_eq!(analysis.entry_rva, u64::from(ENTRY_VA - IMAGE_BASE));
    assert_eq!(analysis.program_headers.len(), layout::PROGRAM_HEADER_COUNT);
    assert_eq!(analysis.load_segments.len(), 1);
    assert_eq!(analysis.section_headers.len(), layout::SECTION_COUNT);
    assert_eq!(analysis.symbols.len(), 3);

    let view = Ps2EeElfImage::new(&bytes, &analysis).expect("exact view binds");
    assert!(std::ptr::eq(view.analysis(), &analysis));
    assert!(std::ptr::eq(view.exact_elf().as_ptr(), bytes.as_ptr()));
    assert_eq!(view.exact_elf().len(), bytes.len());
}

#[test]
fn resolved_names_and_classifiers_preserve_raw_records() {
    let bytes = valid_elf();
    let analysis = analyze_ps2_elf(&bytes).expect("fixture analyzes");
    let view = Ps2EeElfImage::new(&bytes, &analysis).expect("fixture binds");

    let load_header = view.program_header(0).expect("load program header");
    assert!(std::ptr::eq(
        load_header.header,
        &analysis.program_headers[0]
    ));
    assert_eq!(load_header.header.segment_type, 1);
    assert_eq!(load_header.kind, Ps2ProgramHeaderKind::Load);
    let other_header = view.program_header(1).expect("vendor program header");
    assert_eq!(other_header.header.segment_type, OTHER_PROGRAM_TYPE);
    assert_eq!(
        other_header.kind,
        Ps2ProgramHeaderKind::Other(OTHER_PROGRAM_TYPE)
    );

    let load = view.load_segment(0).expect("sparse load mapping");
    assert!(std::ptr::eq(load.segment, &analysis.load_segments[0]));
    assert_eq!(load.segment.program_header_index, 0);
    assert_eq!(load.segment.file_offset, layout::TEXT as u64);
    assert_eq!(load.segment.file_size, layout::TEXT_FILE_SIZE as u64);
    assert_eq!(load.segment.virtual_address, u64::from(IMAGE_BASE));
    assert_eq!(load.segment.memory_size, 0xa0);
    assert!(load.segment.readable());
    assert!(load.segment.executable());
    assert!(!load.segment.writable());

    let expected_names = [
        "",
        ".text",
        ".bss",
        ".symtab",
        ".strtab",
        ".shstrtab",
        ".custom",
    ];
    for (index, expected_name) in expected_names.into_iter().enumerate() {
        let section = view.section(index).expect("section name resolves");
        assert!(std::ptr::eq(
            section.header,
            &analysis.section_headers[index]
        ));
        assert_eq!(section.name, expected_name);
    }
    assert_eq!(view.section(0).unwrap().kind, Ps2SectionKind::Null);
    assert_eq!(view.section(1).unwrap().kind, Ps2SectionKind::ProgramBits);
    assert_eq!(view.section(2).unwrap().kind, Ps2SectionKind::NoBits);
    assert_eq!(view.section(3).unwrap().kind, Ps2SectionKind::SymbolTable);
    assert_eq!(view.section(4).unwrap().kind, Ps2SectionKind::StringTable);
    let custom = view.section(6).expect("custom section resolves");
    assert_eq!(custom.header.section_type, OTHER_SECTION_TYPE);
    assert_eq!(custom.kind, Ps2SectionKind::Other(OTHER_SECTION_TYPE));

    let function = view.symbol(0).expect("function symbol");
    assert!(std::ptr::eq(function.symbol, &analysis.symbols[0]));
    assert_eq!(function.symbol.table_index, 1);
    assert_eq!(function.symbol.name, "entry_fn");
    assert_eq!(function.symbol.info, 0x12);
    assert_eq!(function.binding, Ps2SymbolBinding::Global);
    assert_eq!(function.kind, Ps2SymbolKind::Function);

    let object = view.symbol(1).expect("object symbol");
    assert_eq!(object.symbol.table_index, 2);
    assert_eq!(object.symbol.name, "global_obj");
    assert_eq!(object.binding, Ps2SymbolBinding::Weak);
    assert_eq!(object.kind, Ps2SymbolKind::Object);

    let other = view.symbol(2).expect("unknown symbol class");
    assert_eq!(other.symbol.table_index, 3);
    assert_eq!(other.symbol.name, "odd_symbol");
    assert_eq!(other.symbol.info, 0xaf);
    assert_eq!(other.symbol.other, 0x7f);
    assert_eq!(other.binding, Ps2SymbolBinding::Other(0x0a));
    assert_eq!(other.kind, Ps2SymbolKind::Other(0x0f));
}

#[test]
fn generic_parser_accepts_shapes_that_the_explicit_facade_rejects() {
    let elf64 = synthetic_elf64();
    assert_eq!(
        analyze_elf(&elf64)
            .expect("ELF64 is generically valid")
            .class,
        ElfClass::Elf64
    );
    assert_ineligible(&elf64, "ELFCLASS32");

    let big_endian = synthetic_elf32(ByteOrder::Big, ELF_TYPE_EXECUTABLE, ELF_MACHINE_MIPS);
    assert_eq!(
        analyze_elf(&big_endian)
            .expect("big-endian ELF32 is generically valid")
            .endian,
        ElfEndian::Big
    );
    assert_ineligible(&big_endian, "little-endian ELF data");

    let dynamic = synthetic_elf32(ByteOrder::Little, ELF_TYPE_DYNAMIC, ELF_MACHINE_MIPS);
    assert_eq!(
        analyze_elf(&dynamic)
            .expect("ET_DYN is generically valid")
            .elf_type,
        ELF_TYPE_DYNAMIC
    );
    assert_ineligible(&dynamic, "ET_EXEC");

    let other_machine = synthetic_elf32(ByteOrder::Little, ELF_TYPE_EXECUTABLE, ELF_MACHINE_386);
    assert_eq!(
        analyze_elf(&other_machine)
            .expect("other machines remain generic container input")
            .machine,
        ELF_MACHINE_386
    );
    assert_ineligible(&other_machine, "EM_MIPS");
}

#[test]
fn stale_or_mutated_source_bytes_cannot_bind_to_an_old_analysis() {
    let bytes = valid_elf();
    let analysis = analyze_ps2_elf(&bytes).expect("fixture analyzes");

    let shortened = &bytes[..bytes.len() - 1];
    match Ps2EeElfImage::new(shortened, &analysis).expect_err("size mismatch fails") {
        Ps2EeElfError::SourceSizeMismatch { expected, actual } => {
            assert_eq!(expected, bytes.len() as u64);
            assert_eq!(actual, shortened.len() as u64);
        }
        other => panic!("unexpected shortened-source error: {other:?}"),
    }

    let mut mutated = bytes.clone();
    mutated[layout::CUSTOM] ^= 0xff;
    assert_eq!(mutated.len(), bytes.len());
    assert!(matches!(
        Ps2EeElfImage::new(&mutated, &analysis),
        Err(Ps2EeElfError::SourceIdentityMismatch)
    ));

    let fresh = analyze_ps2_elf(&mutated).expect("fresh analysis owns the new identity");
    assert_ne!(fresh.identity.id, analysis.identity.id);
    Ps2EeElfImage::new(&mutated, &fresh).expect("fresh exact pair binds");
}

#[test]
fn internally_valid_but_forged_analysis_cannot_bind_to_exact_source() {
    let bytes = valid_elf();
    let canonical = analyze_ps2_elf(&bytes).expect("fixture analyzes");
    let mut forged = canonical.clone();
    forged.flags ^= 1;

    forged
        .validate()
        .expect("ELF flags are raw metadata and the forged model remains internally valid");
    assert!(matches!(
        Ps2EeElfImage::new(&bytes, &forged),
        Err(Ps2EeElfError::AnalysisModelMismatch)
    ));
    assert_eq!(
        Ps2EeElfImage::new(&bytes, &forged)
            .expect_err("a noncanonical public model must not bind")
            .to_string(),
        "the supplied ELF analysis does not exactly match a fresh canonical analysis"
    );
}

#[test]
fn section_name_table_must_really_be_a_string_table() {
    let mut bytes = valid_elf();
    put_u32(
        &mut bytes,
        section_header_offset(layout::SHSTRTAB_INDEX) + 4,
        1,
        ByteOrder::Little,
    );
    let analysis = analyze_ps2_elf(&bytes).expect("container parser preserves raw section type");
    let view = Ps2EeElfImage::new(&bytes, &analysis).expect("exact pair binds");
    match view.section(1).expect_err("wrong shstrndx type fails") {
        Ps2EeElfError::SectionNameTableWrongType { section_type } => {
            assert_eq!(section_type, 1)
        }
        other => panic!("unexpected section-name table error: {other:?}"),
    }
}

#[test]
fn section_name_resolution_enforces_offsets_utf8_termination_and_bounds() {
    let mut outside_offset = valid_elf();
    put_u32(
        &mut outside_offset,
        section_header_offset(1),
        SECTION_NAMES.len() as u32,
        ByteOrder::Little,
    );
    let analysis = analyze_ps2_elf(&outside_offset).expect("raw name offset is retained");
    let view = Ps2EeElfImage::new(&outside_offset, &analysis).expect("exact pair binds");
    match view.section(1).expect_err("offset at table end fails") {
        Ps2EeElfError::SectionNameOffsetOutOfRange { offset, table_size } => {
            assert_eq!(offset, SECTION_NAMES.len() as u32);
            assert_eq!(table_size, SECTION_NAMES.len() as u64);
        }
        other => panic!("unexpected name-offset error: {other:?}"),
    }

    let exact_limit_table = {
        let mut table = vec![b'X'; MAX_PS2_EE_ELF_NAME_BYTES + 2];
        table[0] = 0;
        let last = table.len() - 1;
        table[last] = 0;
        table
    };
    let exact_limit = replace_section_name_table(valid_elf(), &exact_limit_table, 1);
    let analysis = analyze_ps2_elf(&exact_limit).expect("maximum-length name container parses");
    let view = Ps2EeElfImage::new(&exact_limit, &analysis).expect("exact pair binds");
    assert_eq!(
        view.section(1)
            .expect("maximum-length name is accepted")
            .name
            .len(),
        MAX_PS2_EE_ELF_NAME_BYTES
    );

    let oversized_table = {
        let mut table = vec![b'X'; MAX_PS2_EE_ELF_NAME_BYTES + 3];
        table[0] = 0;
        let last = table.len() - 1;
        table[last] = 0;
        table
    };
    let oversized = replace_section_name_table(valid_elf(), &oversized_table, 1);
    let analysis = analyze_ps2_elf(&oversized).expect("raw oversized name container parses");
    let view = Ps2EeElfImage::new(&oversized, &analysis).expect("exact pair binds");
    match view.section(1).expect_err("oversized name fails") {
        Ps2EeElfError::SectionNameTooLong { maximum } => {
            assert_eq!(maximum, MAX_PS2_EE_ELF_NAME_BYTES)
        }
        other => panic!("unexpected oversized-name error: {other:?}"),
    }

    let unterminated = replace_section_name_table(valid_elf(), &[0, b'A', b'B'], 1);
    let analysis = analyze_ps2_elf(&unterminated).expect("raw unterminated name container parses");
    let view = Ps2EeElfImage::new(&unterminated, &analysis).expect("exact pair binds");
    match view.section(1).expect_err("unterminated name fails") {
        Ps2EeElfError::UnterminatedSectionName { offset, available } => {
            assert_eq!(offset, 1);
            assert_eq!(available, 2);
        }
        other => panic!("unexpected unterminated-name error: {other:?}"),
    }

    let invalid_utf8 = replace_section_name_table(valid_elf(), &[0, 0xc3, 0x28, 0], 1);
    let analysis = analyze_ps2_elf(&invalid_utf8).expect("raw invalid UTF-8 container parses");
    let view = Ps2EeElfImage::new(&invalid_utf8, &analysis).expect("exact pair binds");
    match view.section(1).expect_err("invalid UTF-8 name fails") {
        Ps2EeElfError::InvalidSectionNameUtf8 { offset } => assert_eq!(offset, 1),
        other => panic!("unexpected invalid-UTF-8 error: {other:?}"),
    }
}

#[test]
fn decoder_profile_helper_never_treats_generic_mips_as_ee() {
    let explicit = [
        DecoderProfile::Ps2EeR5900LeCoreV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1,
    ];
    for profile in explicit {
        assert!(is_explicit_ps2_ee_decoder_profile(profile));
    }

    for profile in [
        DecoderProfile::Generic(TargetArch::Mips32),
        DecoderProfile::Generic(TargetArch::Mips64),
        DecoderProfile::Generic(TargetArch::X86_64),
    ] {
        assert!(!is_explicit_ps2_ee_decoder_profile(profile));
    }
}

#[test]
fn index_errors_are_exact_and_diagnostics_remain_path_free() {
    let bytes = valid_elf();
    let analysis = analyze_ps2_elf(&bytes).expect("fixture analyzes");
    let view = Ps2EeElfImage::new(&bytes, &analysis).expect("fixture binds");

    assert!(matches!(
        view.program_header(layout::PROGRAM_HEADER_COUNT),
        Err(Ps2EeElfError::ProgramHeaderIndexOutOfRange {
            index: layout::PROGRAM_HEADER_COUNT,
            count: layout::PROGRAM_HEADER_COUNT,
        })
    ));
    assert!(matches!(
        view.load_segment(1),
        Err(Ps2EeElfError::LoadSegmentIndexOutOfRange { index: 1, count: 1 })
    ));
    assert!(matches!(
        view.section(layout::SECTION_COUNT),
        Err(Ps2EeElfError::SectionIndexOutOfRange {
            index: layout::SECTION_COUNT,
            count: layout::SECTION_COUNT,
        })
    ));
    assert!(matches!(
        view.symbol(3),
        Err(Ps2EeElfError::SymbolIndexOutOfRange { index: 3, count: 3 })
    ));

    let path_shaped = b"C:\\private\\disc\\SCUS_972.64";
    let rendered = analyze_ps2_elf(path_shaped)
        .expect_err("non-ELF path-shaped bytes fail")
        .to_string();
    for forbidden in ["private", "SCUS", "972", "\\", "C:"] {
        assert!(
            !rendered.contains(forbidden),
            "diagnostic leaked path-shaped input through {forbidden:?}: {rendered}"
        );
    }

    let mut mutated = bytes.clone();
    mutated[layout::CUSTOM] ^= 1;
    let rendered = Ps2EeElfImage::new(&mutated, &analysis)
        .expect_err("identity mismatch fails")
        .to_string();
    assert_eq!(
        rendered,
        "exact source SHA-256 does not match the canonical ELF analysis"
    );
    assert!(!rendered.contains("private"));
}
