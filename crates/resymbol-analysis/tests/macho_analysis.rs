use resymbol_analysis::{
    AnalysisError, AnalysisSession, BinaryAnalysis, MachOContainer, MachOEndian, analyze_bytes,
    analyze_macho, detect_macho,
};
use resymbol_core::{BinaryFormat, SymbolAssertion, SymbolSubject};
use resymbol_package::{CURRENT_SCHEMA_VERSION, ResymPackage, from_slice, to_vec};

const IMAGE_BASE: u64 = 0x1_0000_0000;

fn put_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_name(bytes: &mut [u8], offset: usize, name: &[u8]) {
    bytes[offset..offset + name.len()].copy_from_slice(name);
}

/// Build a redistributable, fully synthetic thin 64-bit little-endian Mach-O
/// with `__PAGEZERO`, an executable `__TEXT`, a writable `__DATA`, and a two
/// symbol `LC_SYMTAB` (one function, one global). Every byte is test data.
fn synthetic_thin64(cputype: i32, cpusubtype: i32) -> Vec<u8> {
    const HDR: usize = 32;
    const PAGEZERO_OFF: usize = HDR; // 32
    const TEXT_SEG_OFF: usize = 104;
    const DATA_SEG_OFF: usize = 256;
    const SYMTAB_OFF: usize = 408;
    const CODE_OFF: usize = 432;
    const DATA_OFF: usize = 464;
    const SYM_OFF: usize = 480;
    const STR_OFF: usize = 512;
    const FILE_SIZE: usize = 528;
    const SIZEOFCMDS: u32 = 400;

    let mut bytes = vec![0_u8; FILE_SIZE];
    // mach_header_64 (magic CF FA ED FE little-endian).
    bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    put_u32_le(&mut bytes, 4, u32::from_ne_bytes(cputype.to_ne_bytes()));
    put_u32_le(&mut bytes, 8, u32::from_ne_bytes(cpusubtype.to_ne_bytes()));
    put_u32_le(&mut bytes, 12, 2); // MH_EXECUTE
    put_u32_le(&mut bytes, 16, 4); // ncmds
    put_u32_le(&mut bytes, 20, SIZEOFCMDS);
    put_u32_le(&mut bytes, 24, 0); // flags
    put_u32_le(&mut bytes, 28, 0); // reserved

    // LC_SEGMENT_64 __PAGEZERO
    put_u32_le(&mut bytes, PAGEZERO_OFF, 0x19);
    put_u32_le(&mut bytes, PAGEZERO_OFF + 4, 72);
    put_name(&mut bytes, PAGEZERO_OFF + 8, b"__PAGEZERO");
    put_u64_le(&mut bytes, PAGEZERO_OFF + 24, 0); // vmaddr
    put_u64_le(&mut bytes, PAGEZERO_OFF + 32, IMAGE_BASE); // vmsize
    put_u64_le(&mut bytes, PAGEZERO_OFF + 40, 0); // fileoff
    put_u64_le(&mut bytes, PAGEZERO_OFF + 48, 0); // filesize
    put_u32_le(&mut bytes, PAGEZERO_OFF + 56, 0); // maxprot
    put_u32_le(&mut bytes, PAGEZERO_OFF + 60, 0); // initprot
    put_u32_le(&mut bytes, PAGEZERO_OFF + 64, 0); // nsects
    put_u32_le(&mut bytes, PAGEZERO_OFF + 68, 0); // flags

    // LC_SEGMENT_64 __TEXT with one __text section (RX).
    put_u32_le(&mut bytes, TEXT_SEG_OFF, 0x19);
    put_u32_le(&mut bytes, TEXT_SEG_OFF + 4, 152);
    put_name(&mut bytes, TEXT_SEG_OFF + 8, b"__TEXT");
    put_u64_le(&mut bytes, TEXT_SEG_OFF + 24, IMAGE_BASE);
    put_u64_le(&mut bytes, TEXT_SEG_OFF + 32, 0x1000);
    put_u64_le(&mut bytes, TEXT_SEG_OFF + 40, 0);
    put_u64_le(&mut bytes, TEXT_SEG_OFF + 48, 0x200);
    put_u32_le(&mut bytes, TEXT_SEG_OFF + 56, 5); // maxprot RX
    put_u32_le(&mut bytes, TEXT_SEG_OFF + 60, 5); // initprot RX
    put_u32_le(&mut bytes, TEXT_SEG_OFF + 64, 1); // nsects
    put_u32_le(&mut bytes, TEXT_SEG_OFF + 68, 0);
    let text_sect = TEXT_SEG_OFF + 72;
    put_name(&mut bytes, text_sect, b"__text");
    put_name(&mut bytes, text_sect + 16, b"__TEXT");
    put_u64_le(&mut bytes, text_sect + 32, IMAGE_BASE + 0xf00); // addr
    put_u64_le(&mut bytes, text_sect + 40, 0x20); // size
    put_u32_le(&mut bytes, text_sect + 48, CODE_OFF as u32); // offset
    put_u32_le(&mut bytes, text_sect + 52, 4); // align
    put_u32_le(&mut bytes, text_sect + 64, 0x8000_0400); // S_REGULAR + pure instructions

    // LC_SEGMENT_64 __DATA with one __data section (RW).
    put_u32_le(&mut bytes, DATA_SEG_OFF, 0x19);
    put_u32_le(&mut bytes, DATA_SEG_OFF + 4, 152);
    put_name(&mut bytes, DATA_SEG_OFF + 8, b"__DATA");
    put_u64_le(&mut bytes, DATA_SEG_OFF + 24, IMAGE_BASE + 0x1000);
    put_u64_le(&mut bytes, DATA_SEG_OFF + 32, 0x1000);
    put_u64_le(&mut bytes, DATA_SEG_OFF + 40, DATA_OFF as u64);
    put_u64_le(&mut bytes, DATA_SEG_OFF + 48, 0x10);
    put_u32_le(&mut bytes, DATA_SEG_OFF + 56, 3); // maxprot RW
    put_u32_le(&mut bytes, DATA_SEG_OFF + 60, 3); // initprot RW
    put_u32_le(&mut bytes, DATA_SEG_OFF + 64, 1);
    put_u32_le(&mut bytes, DATA_SEG_OFF + 68, 0);
    let data_sect = DATA_SEG_OFF + 72;
    put_name(&mut bytes, data_sect, b"__data");
    put_name(&mut bytes, data_sect + 16, b"__DATA");
    put_u64_le(&mut bytes, data_sect + 32, IMAGE_BASE + 0x1000);
    put_u64_le(&mut bytes, data_sect + 40, 0x10);
    put_u32_le(&mut bytes, data_sect + 48, DATA_OFF as u32);
    put_u32_le(&mut bytes, data_sect + 52, 3);
    put_u32_le(&mut bytes, data_sect + 64, 0);

    // LC_SYMTAB
    put_u32_le(&mut bytes, SYMTAB_OFF, 0x2);
    put_u32_le(&mut bytes, SYMTAB_OFF + 4, 24);
    put_u32_le(&mut bytes, SYMTAB_OFF + 8, SYM_OFF as u32);
    put_u32_le(&mut bytes, SYMTAB_OFF + 12, 2); // nsyms
    put_u32_le(&mut bytes, SYMTAB_OFF + 16, STR_OFF as u32);
    put_u32_le(&mut bytes, SYMTAB_OFF + 20, 16); // strsize

    // nlist_64 records: _main (function) and _counter (global).
    put_u32_le(&mut bytes, SYM_OFF, 1); // n_strx -> "_main"
    bytes[SYM_OFF + 4] = 0x0f; // N_SECT | N_EXT
    bytes[SYM_OFF + 5] = 1; // n_sect (1-based -> __text)
    put_u16_le(&mut bytes, SYM_OFF + 6, 0);
    put_u64_le(&mut bytes, SYM_OFF + 8, IMAGE_BASE + 0xf00);
    put_u32_le(&mut bytes, SYM_OFF + 16, 7); // n_strx -> "_counter"
    bytes[SYM_OFF + 20] = 0x0f;
    bytes[SYM_OFF + 21] = 2; // n_sect (1-based -> __data)
    put_u16_le(&mut bytes, SYM_OFF + 22, 0);
    put_u64_le(&mut bytes, SYM_OFF + 24, IMAGE_BASE + 0x1000);

    // String table: leading NUL, then "_main\0" at 1, "_counter\0" at 7.
    put_name(&mut bytes, STR_OFF + 1, b"_main\0");
    put_name(&mut bytes, STR_OFF + 7, b"_counter\0");
    bytes
}

/// Build a minimal thin 32-bit big-endian PowerPC Mach-O with a single
/// executable segment and no symbol table.
fn synthetic_thin32_be_ppc() -> Vec<u8> {
    const HDR: usize = 28;
    const SEG_OFF: usize = HDR; // 28
    const SIZEOFCMDS: u32 = 56; // one bare segment command, no sections
    const FILE_SIZE: usize = HDR + SIZEOFCMDS as usize;

    let mut bytes = vec![0_u8; FILE_SIZE];
    // mach_header (magic FE ED FA CE big-endian).
    bytes[0..4].copy_from_slice(&[0xfe, 0xed, 0xfa, 0xce]);
    bytes[4..8].copy_from_slice(&18_i32.to_be_bytes()); // CPU_TYPE_POWERPC
    bytes[8..12].copy_from_slice(&0_i32.to_be_bytes()); // cpusubtype
    bytes[12..16].copy_from_slice(&2_u32.to_be_bytes()); // MH_EXECUTE
    bytes[16..20].copy_from_slice(&1_u32.to_be_bytes()); // ncmds
    bytes[20..24].copy_from_slice(&SIZEOFCMDS.to_be_bytes());
    bytes[24..28].copy_from_slice(&0_u32.to_be_bytes()); // flags

    // LC_SEGMENT __TEXT (32-bit, no sections).
    bytes[SEG_OFF..SEG_OFF + 4].copy_from_slice(&0x1_u32.to_be_bytes());
    bytes[SEG_OFF + 4..SEG_OFF + 8].copy_from_slice(&56_u32.to_be_bytes());
    put_name(&mut bytes, SEG_OFF + 8, b"__TEXT");
    bytes[SEG_OFF + 24..SEG_OFF + 28].copy_from_slice(&0x2000_u32.to_be_bytes()); // vmaddr
    bytes[SEG_OFF + 28..SEG_OFF + 32].copy_from_slice(&0x1000_u32.to_be_bytes()); // vmsize
    bytes[SEG_OFF + 32..SEG_OFF + 36].copy_from_slice(&0_u32.to_be_bytes()); // fileoff
    bytes[SEG_OFF + 36..SEG_OFF + 40].copy_from_slice(&(FILE_SIZE as u32).to_be_bytes()); // filesize
    bytes[SEG_OFF + 40..SEG_OFF + 44].copy_from_slice(&5_i32.to_be_bytes()); // maxprot RX
    bytes[SEG_OFF + 44..SEG_OFF + 48].copy_from_slice(&5_i32.to_be_bytes()); // initprot RX
    bytes[SEG_OFF + 48..SEG_OFF + 52].copy_from_slice(&0_u32.to_be_bytes()); // nsects
    bytes[SEG_OFF + 52..SEG_OFF + 56].copy_from_slice(&0_u32.to_be_bytes()); // flags
    bytes
}

/// Build a fat/universal container from two thin slices, big-endian header.
fn synthetic_fat(slice_a: &[u8], slice_b: &[u8]) -> Vec<u8> {
    let table_end = 8 + 2 * 20;
    let offset_a = table_end;
    let offset_b = offset_a + slice_a.len();
    let total = offset_b + slice_b.len();

    let mut bytes = vec![0_u8; total];
    bytes[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]); // FAT_MAGIC
    bytes[4..8].copy_from_slice(&2_u32.to_be_bytes()); // nfat_arch

    // fat_arch[0]
    bytes[8..12].copy_from_slice(&0x0100_0007_u32.to_be_bytes()); // cputype x86-64
    bytes[12..16].copy_from_slice(&3_u32.to_be_bytes()); // cpusubtype
    bytes[16..20].copy_from_slice(&(offset_a as u32).to_be_bytes());
    bytes[20..24].copy_from_slice(&(slice_a.len() as u32).to_be_bytes());
    bytes[24..28].copy_from_slice(&12_u32.to_be_bytes()); // align

    // fat_arch[1]
    bytes[28..32].copy_from_slice(&0x0100_000c_u32.to_be_bytes()); // cputype arm64
    bytes[32..36].copy_from_slice(&0_u32.to_be_bytes());
    bytes[36..40].copy_from_slice(&(offset_b as u32).to_be_bytes());
    bytes[40..44].copy_from_slice(&(slice_b.len() as u32).to_be_bytes());
    bytes[44..48].copy_from_slice(&14_u32.to_be_bytes());

    bytes[offset_a..offset_a + slice_a.len()].copy_from_slice(slice_a);
    bytes[offset_b..offset_b + slice_b.len()].copy_from_slice(slice_b);
    bytes
}

#[test]
fn thin64_x86_64_yields_function_and_global_claims() {
    let fixture = synthetic_thin64(0x0100_0007, 3);
    let analysis = analyze_bytes(&fixture).expect("synthetic thin Mach-O is accepted");
    let BinaryAnalysis::MachO(macho) = &analysis else {
        panic!("Mach-O input must produce a Mach-O analysis");
    };

    assert!(matches!(macho.identity.format, BinaryFormat::MachO));
    assert_eq!(macho.identity.architecture, "macho64-x86-64");
    assert_eq!(macho.identity.image_base, IMAGE_BASE);
    assert_eq!(macho.image_size, 0x2000);

    let MachOContainer::Thin(image) = &macho.container else {
        panic!("thin input must produce a thin container");
    };
    assert_eq!(image.endian, MachOEndian::Little);
    assert!(image.is_64);
    assert_eq!(image.segments.len(), 3);
    assert_eq!(image.sections.len(), 2);
    assert_eq!(image.symbols.len(), 2);
    assert!(!image.symbol_scan_truncated);

    assert_eq!(macho.symbol_graph.binaries().len(), 1);
    let claims = macho.symbol_graph.claims();
    assert_eq!(claims.len(), 2);

    let function = claims
        .iter()
        .find(|claim| matches!(claim.subject(), SymbolSubject::Function { .. }))
        .expect("one function claim");
    let SymbolSubject::Function { rva, .. } = function.subject() else {
        unreachable!();
    };
    assert_eq!(*rva, 0xf00);
    assert!(matches!(function.assertion(), SymbolAssertion::Name { name } if name == "_main"));

    let global = claims
        .iter()
        .find(|claim| matches!(claim.subject(), SymbolSubject::Global { .. }))
        .expect("one global claim");
    let SymbolSubject::Global { rva, .. } = global.subject() else {
        unreachable!();
    };
    assert_eq!(*rva, 0x1000);
    assert!(matches!(global.assertion(), SymbolAssertion::Name { name } if name == "_counter"));

    macho.validate().expect("thin analysis revalidates");
    assert_eq!(
        macho.rebuild_symbol_graph().expect("rebuild"),
        macho.symbol_graph
    );
}

#[test]
fn thin64_arm64_architecture_is_recognized() {
    let fixture = synthetic_thin64(0x0100_000c, 0);
    let analysis = analyze_macho(&fixture).expect("arm64 thin Mach-O is accepted");
    assert_eq!(analysis.identity.architecture, "macho64-arm64");
}

#[test]
fn thin32_big_endian_ppc_is_recognized() {
    let fixture = synthetic_thin32_be_ppc();
    assert_eq!(
        detect_macho(&fixture),
        Some(resymbol_analysis::MachOKind::Thin32(MachOEndian::Big))
    );
    let analysis = analyze_macho(&fixture).expect("big-endian PPC Mach-O is accepted");
    assert_eq!(analysis.identity.architecture, "macho32-ppc");
    let MachOContainer::Thin(image) = &analysis.container else {
        panic!("thin container expected");
    };
    assert_eq!(image.endian, MachOEndian::Big);
    assert!(!image.is_64);
    assert_eq!(image.segments.len(), 1);
    assert_eq!(image.image_base, 0x2000);
    assert!(analysis.symbol_graph.claims().is_empty());
}

#[test]
fn fat_universal_has_identity_only_graph() {
    let x86 = synthetic_thin64(0x0100_0007, 3);
    let arm = synthetic_thin64(0x0100_000c, 0);
    let fixture = synthetic_fat(&x86, &arm);

    let analysis = analyze_bytes(&fixture).expect("fat Mach-O is accepted");
    let BinaryAnalysis::MachO(macho) = &analysis else {
        panic!("fat input must produce a Mach-O analysis");
    };
    assert_eq!(macho.identity.architecture, "macho-universal");
    assert_eq!(macho.identity.image_base, 0);
    assert_eq!(macho.image_size, 0x2000);

    let MachOContainer::Fat(fat) = &macho.container else {
        panic!("fat input must produce a fat container");
    };
    assert_eq!(fat.slices.len(), 2);
    assert_eq!(fat.slices[0].architecture, "macho64-x86-64");
    assert_eq!(fat.slices[1].architecture, "macho64-arm64");
    // Each slice keeps its own parsed symbols, but the whole-file graph stays
    // identity-only to avoid cross-architecture RVA collisions.
    assert_eq!(fat.slices[0].image.symbols.len(), 2);
    assert_eq!(macho.symbol_graph.binaries().len(), 1);
    assert!(macho.symbol_graph.claims().is_empty());

    macho.validate().expect("fat analysis revalidates");
}

#[test]
fn dispatch_prefers_pe_and_elf_over_macho() {
    // A PE stub keeps winning on the MZ magic.
    let mut pe = vec![0_u8; 4];
    pe[0..2].copy_from_slice(b"MZ");
    assert!(!matches!(analyze_bytes(&pe), Ok(BinaryAnalysis::MachO(_))));

    // An ELF stub keeps winning on its magic.
    let mut elf = vec![0_u8; 8];
    elf[0..4].copy_from_slice(b"\x7fELF");
    assert!(!matches!(analyze_bytes(&elf), Ok(BinaryAnalysis::MachO(_))));

    // Mach-O magic without a body fails closed inside the Mach-O parser.
    assert!(detect_macho(b"\xcf\xfa\xed\xfe").is_some());
}

#[test]
fn truncated_and_malformed_inputs_fail_closed() {
    // Too short for any magic.
    assert!(detect_macho(b"\xcf\xfa").is_none());
    assert!(matches!(
        analyze_macho(b"\xcf\xfa"),
        Err(AnalysisError::InvalidMachOMagic { .. })
    ));

    // Valid 64-bit magic but a truncated header.
    let mut short = vec![0xcf, 0xfa, 0xed, 0xfe];
    short.extend_from_slice(&[0_u8; 8]);
    assert!(matches!(
        analyze_macho(&short),
        Err(AnalysisError::Truncated { .. })
    ));

    // A load command that overruns the declared table.
    let mut overrun = synthetic_thin64(0x0100_0007, 3);
    // Corrupt the first segment command's size to exceed sizeofcmds.
    put_u32_le(&mut overrun, 104 + 4, 0xffff);
    assert!(analyze_macho(&overrun).is_err());

    // A fat header claiming a slice beyond the file.
    let mut fat = vec![0_u8; 8 + 20];
    fat[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    fat[4..8].copy_from_slice(&1_u32.to_be_bytes());
    fat[16..20].copy_from_slice(&0x1000_u32.to_be_bytes()); // offset past EOF
    fat[20..24].copy_from_slice(&0x1000_u32.to_be_bytes()); // size past EOF
    assert!(analyze_macho(&fat).is_err());

    // A fat slice that is not itself a Mach-O.
    let junk = vec![0_u8; 64];
    let bad = synthetic_fat(&junk, &junk);
    assert!(matches!(
        analyze_macho(&bad),
        Err(AnalysisError::InvalidMachOSlice { .. })
    ));
}

#[test]
fn macho_analysis_round_trips_through_serde_and_a_package() {
    let fixture = synthetic_thin64(0x0100_0007, 3);
    let analysis = analyze_bytes(&fixture).expect("thin Mach-O is accepted");

    let BinaryAnalysis::MachO(macho) = &analysis else {
        panic!("expected Mach-O analysis");
    };
    let json = serde_json::to_string(macho).expect("serialize");
    let decoded: resymbol_analysis::MachOAnalysis =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(&decoded, macho);

    let session =
        AnalysisSession::new(analysis, Vec::new(), Vec::new()).expect("Mach-O session is valid");
    let package = ResymPackage::from_bound_payload("0.1.0-test", session)
        .expect("Mach-O session binds to a package");
    assert_eq!(CURRENT_SCHEMA_VERSION, 15);
    let encoded = to_vec(&package).expect("package serializes");
    assert!(
        std::str::from_utf8(&encoded)
            .expect("package is UTF-8")
            .contains("\"format\":\"mach-o\"")
    );
    let round: ResymPackage<AnalysisSession> = from_slice(&encoded).expect("package round trips");
    assert_eq!(round, package);
}
