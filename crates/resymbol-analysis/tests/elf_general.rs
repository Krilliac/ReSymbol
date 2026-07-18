//! Golden-header coverage for the generalized ELF container parser: ELF64,
//! both byte orders, AArch64, symbol-table name claims, and fail-closed inputs.

use resymbol_analysis::{
    AnalysisError, BinaryAnalysis, ElfAnalysis, ElfClass, ElfEndian, analyze_bytes,
};
use resymbol_core::{BinaryFormat, SymbolAssertion, SymbolSubject};

const EH64: usize = 64;
const PH64: usize = 56;
const SH64: usize = 64;
const SYM64: usize = 24;
const EH32: usize = 52;
const PH32: usize = 32;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16, big: bool) {
    let raw = if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    bytes[offset..offset + 2].copy_from_slice(&raw);
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32, big: bool) {
    let raw = if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    bytes[offset..offset + 4].copy_from_slice(&raw);
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64, big: bool) {
    let raw = if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    bytes[offset..offset + 8].copy_from_slice(&raw);
}

/// Minimal ELF64 executable with one file-covering R+X `PT_LOAD` and no sections.
fn elf64_exec(machine: u16, big: bool) -> Vec<u8> {
    let file_size = EH64 + PH64;
    let mut bytes = vec![0_u8; file_size];
    bytes[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, if big { 2 } else { 1 }, 1, 0]);
    put_u16(&mut bytes, 16, 2, big); // ET_EXEC
    put_u16(&mut bytes, 18, machine, big);
    put_u32(&mut bytes, 20, 1, big); // EV_CURRENT
    put_u64(&mut bytes, 24, 0x40_0000, big); // e_entry
    put_u64(&mut bytes, 32, EH64 as u64, big); // e_phoff
    put_u64(&mut bytes, 40, 0, big); // e_shoff
    put_u32(&mut bytes, 48, 0, big); // e_flags
    put_u16(&mut bytes, 52, EH64 as u16, big);
    put_u16(&mut bytes, 54, PH64 as u16, big);
    put_u16(&mut bytes, 56, 1, big); // e_phnum
    put_u16(&mut bytes, 58, SH64 as u16, big); // e_shentsize (harmless when absent)
    put_u16(&mut bytes, 60, 0, big); // e_shnum
    put_u16(&mut bytes, 62, 0, big); // e_shstrndx

    // Program header: PT_LOAD, R+X, covering the whole file.
    let ph = EH64;
    put_u32(&mut bytes, ph, 1, big); // p_type = PT_LOAD
    put_u32(&mut bytes, ph + 4, 5, big); // p_flags = R+X
    put_u64(&mut bytes, ph + 8, 0, big); // p_offset
    put_u64(&mut bytes, ph + 16, 0x40_0000, big); // p_vaddr
    put_u64(&mut bytes, ph + 24, 0x40_0000, big); // p_paddr
    put_u64(&mut bytes, ph + 32, file_size as u64, big); // p_filesz
    put_u64(&mut bytes, ph + 40, file_size as u64, big); // p_memsz
    put_u64(&mut bytes, ph + 48, 0x1000, big); // p_align
    bytes
}

/// Minimal ELF32 big-endian executable with one file-covering R+X `PT_LOAD`.
fn elf32_be_exec(machine: u16) -> Vec<u8> {
    let big = true;
    let file_size = EH32 + PH32;
    let mut bytes = vec![0_u8; file_size];
    bytes[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 2, 1, 0]);
    put_u16(&mut bytes, 16, 2, big);
    put_u16(&mut bytes, 18, machine, big);
    put_u32(&mut bytes, 20, 1, big);
    put_u32(&mut bytes, 24, 0x40_0000, big); // e_entry
    put_u32(&mut bytes, 28, EH32 as u32, big); // e_phoff
    put_u32(&mut bytes, 32, 0, big); // e_shoff
    put_u32(&mut bytes, 36, 0, big); // e_flags
    put_u16(&mut bytes, 40, EH32 as u16, big);
    put_u16(&mut bytes, 42, PH32 as u16, big);
    put_u16(&mut bytes, 44, 1, big); // e_phnum
    put_u16(&mut bytes, 46, 40, big); // e_shentsize
    put_u16(&mut bytes, 48, 0, big); // e_shnum
    put_u16(&mut bytes, 50, 0, big); // e_shstrndx

    let ph = EH32;
    put_u32(&mut bytes, ph, 1, big); // PT_LOAD
    put_u32(&mut bytes, ph + 4, 0, big); // p_offset
    put_u32(&mut bytes, ph + 8, 0x40_0000, big); // p_vaddr
    put_u32(&mut bytes, ph + 12, 0x40_0000, big); // p_paddr
    put_u32(&mut bytes, ph + 16, file_size as u32, big); // p_filesz
    put_u32(&mut bytes, ph + 20, file_size as u32, big); // p_memsz
    put_u32(&mut bytes, ph + 24, 5, big); // p_flags = R+X
    put_u32(&mut bytes, ph + 28, 0x1000, big); // p_align
    bytes
}

/// ELF64 image with one `PT_LOAD` plus a `SHT_SYMTAB` and its `.strtab`.
fn elf64_with_symtab() -> Vec<u8> {
    let big = false;
    let sym_off = EH64 + PH64; // 120
    let sym_size = 3 * SYM64; // 72
    let str_off = sym_off + sym_size; // 192
    let strtab: &[u8] = b"\0func_a\0glob_b\0"; // len 15
    let sh_off = str_off + strtab.len(); // 207
    let sh_off = sh_off.div_ceil(8) * 8; // align to 8 -> 208
    let file_size = sh_off + 3 * SH64;
    let mut bytes = vec![0_u8; file_size];

    bytes[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    put_u16(&mut bytes, 16, 2, big); // ET_EXEC
    put_u16(&mut bytes, 18, 62, big); // EM_X86_64
    put_u32(&mut bytes, 20, 1, big);
    put_u64(&mut bytes, 24, 0x40_0000, big); // e_entry
    put_u64(&mut bytes, 32, EH64 as u64, big); // e_phoff
    put_u64(&mut bytes, 40, sh_off as u64, big); // e_shoff
    put_u32(&mut bytes, 48, 0, big);
    put_u16(&mut bytes, 52, EH64 as u16, big);
    put_u16(&mut bytes, 54, PH64 as u16, big);
    put_u16(&mut bytes, 56, 1, big); // e_phnum
    put_u16(&mut bytes, 58, SH64 as u16, big);
    put_u16(&mut bytes, 60, 3, big); // e_shnum
    put_u16(&mut bytes, 62, 0, big); // e_shstrndx

    let ph = EH64;
    put_u32(&mut bytes, ph, 1, big);
    put_u32(&mut bytes, ph + 4, 5, big); // R+X
    put_u64(&mut bytes, ph + 8, 0, big);
    put_u64(&mut bytes, ph + 16, 0x40_0000, big);
    put_u64(&mut bytes, ph + 24, 0x40_0000, big);
    put_u64(&mut bytes, ph + 32, file_size as u64, big);
    put_u64(&mut bytes, ph + 40, file_size as u64, big);
    put_u64(&mut bytes, ph + 48, 0x1000, big);

    // Symbols: [0]=null, [1]=func_a (STT_FUNC), [2]=glob_b (STT_OBJECT).
    let sym = |bytes: &mut [u8], index: usize, name: u32, value: u64, info: u8| {
        let base = sym_off + index * SYM64;
        put_u32(bytes, base, name, big);
        bytes[base + 4] = info;
        bytes[base + 5] = 0; // st_other
        put_u16(bytes, base + 6, 1, big); // st_shndx
        put_u64(bytes, base + 8, value, big);
        put_u64(bytes, base + 16, 0, big); // st_size
    };
    sym(&mut bytes, 0, 0, 0, 0);
    sym(&mut bytes, 1, 1, 0x40_0010, 0x12); // GLOBAL | STT_FUNC
    sym(&mut bytes, 2, 8, 0x40_0020, 0x11); // GLOBAL | STT_OBJECT

    bytes[str_off..str_off + strtab.len()].copy_from_slice(strtab);

    // Section 0 is the all-zero reserved record. Section 1 = symtab, 2 = strtab.
    let sh1 = sh_off + SH64;
    put_u32(&mut bytes, sh1 + 4, 2, big); // sh_type = SHT_SYMTAB
    put_u64(&mut bytes, sh1 + 24, sym_off as u64, big); // sh_offset
    put_u64(&mut bytes, sh1 + 32, sym_size as u64, big); // sh_size
    put_u32(&mut bytes, sh1 + 40, 2, big); // sh_link = strtab index
    put_u64(&mut bytes, sh1 + 48, 8, big); // sh_addralign
    put_u64(&mut bytes, sh1 + 56, SYM64 as u64, big); // sh_entsize

    let sh2 = sh_off + 2 * SH64;
    put_u32(&mut bytes, sh2 + 4, 3, big); // sh_type = SHT_STRTAB
    put_u64(&mut bytes, sh2 + 24, str_off as u64, big); // sh_offset
    put_u64(&mut bytes, sh2 + 32, strtab.len() as u64, big); // sh_size
    put_u64(&mut bytes, sh2 + 48, 1, big); // sh_addralign
    bytes
}

fn expect_elf(bytes: &[u8]) -> ElfAnalysis {
    match analyze_bytes(bytes).expect("golden ELF is accepted") {
        BinaryAnalysis::Elf(elf) => elf,
        other => panic!("expected an ELF analysis, found {other:?}"),
    }
}

#[test]
fn elf64_x86_64_executable_is_accepted() {
    let elf = expect_elf(&elf64_exec(62, false));
    assert_eq!(elf.class, ElfClass::Elf64);
    assert_eq!(elf.endian, ElfEndian::Little);
    assert!(matches!(elf.identity.format, BinaryFormat::Elf));
    assert_eq!(elf.identity.architecture, "elf64-x86-64");
    assert_eq!(elf.identity.image_base, 0x40_0000);
    assert_eq!(elf.entry_va, 0x40_0000);
    assert_eq!(elf.entry_rva, 0);
    assert_eq!(elf.header_size, 64);
    assert_eq!(elf.program_header_entry_size, 56);
    assert_eq!(elf.load_segments.len(), 1);
    assert!(elf.symbols.is_empty());
    assert!(elf.symbol_graph.claims().is_empty());
}

#[test]
fn elf64_aarch64_architecture_is_derived() {
    let elf = expect_elf(&elf64_exec(183, false));
    assert_eq!(elf.identity.architecture, "elf64-aarch64");
}

#[test]
fn elf32_big_endian_is_parsed_with_the_correct_byte_order() {
    let elf = expect_elf(&elf32_be_exec(8)); // EM_MIPS, big-endian
    assert_eq!(elf.class, ElfClass::Elf32);
    assert_eq!(elf.endian, ElfEndian::Big);
    assert_eq!(elf.identity.architecture, "elf32-em-mips-be");
    assert_eq!(elf.entry_va, 0x40_0000);
    assert_eq!(elf.machine, 8);
}

#[test]
fn elf64_symtab_produces_function_and_global_name_claims() {
    let elf = expect_elf(&elf64_with_symtab());
    // The null symbol is skipped; only the two named symbols are retained.
    assert_eq!(elf.symbols.len(), 2);
    assert!(!elf.symbol_scan_truncated);
    assert_eq!(elf.symbols[0].name, "func_a");
    assert_eq!(elf.symbols[0].value, 0x40_0010);
    assert_eq!(elf.symbols[1].name, "glob_b");

    let claims = elf.symbol_graph.claims();
    assert_eq!(claims.len(), 2);
    let function = claims
        .iter()
        .find(|claim| matches!(claim.subject(), SymbolSubject::Function { .. }))
        .expect("STT_FUNC symbol becomes a Function claim");
    assert!(matches!(
        function.assertion(),
        SymbolAssertion::Name { name } if name == "func_a"
    ));
    let SymbolSubject::Function { rva, .. } = function.subject() else {
        panic!("function subject");
    };
    assert_eq!(*rva, 0x10);
    let global = claims
        .iter()
        .find(|claim| matches!(claim.subject(), SymbolSubject::Global { .. }))
        .expect("STT_OBJECT symbol becomes a Global claim");
    assert!(matches!(
        global.assertion(),
        SymbolAssertion::Name { name } if name == "glob_b"
    ));
}

#[test]
fn schema15_elf_analysis_round_trips_through_serde_json() {
    let elf = expect_elf(&elf64_with_symtab());
    let json = serde_json::to_string(&elf).expect("analysis serializes");
    assert!(json.contains("\"symbols\""));
    assert!(json.contains("func_a"));
    let decoded: ElfAnalysis = serde_json::from_str(&json).expect("analysis round trips");
    assert_eq!(decoded, elf);
}

#[test]
fn schema14_style_payload_without_symbol_fields_still_loads() {
    let elf = expect_elf(&elf64_exec(62, false));
    let mut value = serde_json::to_value(&elf).expect("analysis serializes");
    // Emulate a schema<=14 package that predates the symbol fields.
    let object = value.as_object_mut().expect("analysis object");
    object.remove("symbols");
    object.remove("symbol_scan_truncated");
    let decoded: ElfAnalysis =
        serde_json::from_value(value).expect("defaulted symbol fields keep old payloads loadable");
    assert!(decoded.symbols.is_empty());
    assert!(!decoded.symbol_scan_truncated);
}

#[test]
fn truncated_and_malformed_inputs_fail_closed() {
    assert!(matches!(
        analyze_bytes(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0]),
        Err(AnalysisError::Truncated { .. })
    ));

    let mut bad_class = elf64_exec(62, false);
    bad_class[4] = 0;
    assert!(matches!(
        analyze_bytes(&bad_class),
        Err(AnalysisError::UnsupportedElfClass { class: 0 })
    ));

    // A valid 64-bit identity but a body cut short of one full ELF64 header.
    let short = elf64_exec(62, false)[..40].to_vec();
    assert!(matches!(
        analyze_bytes(&short),
        Err(AnalysisError::Truncated { .. })
    ));

    // A program-header count that overruns the file must be rejected, not read.
    let mut overrun = elf64_exec(62, false);
    put_u16(&mut overrun, 56, 4096, false);
    assert!(analyze_bytes(&overrun).is_err());
}
