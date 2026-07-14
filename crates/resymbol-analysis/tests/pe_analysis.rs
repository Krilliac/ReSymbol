use resymbol_analysis::{
    AnalysisError, BinaryAnalysis, ImportTarget, analyze_bytes, analyze_pe,
};
use resymbol_core::{BinaryId, SymbolAssertion, SymbolSubject};
use resymbol_package::BinaryBoundPayload;

const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 0xf0;
const RAW_OFFSET: usize = 0x200;
const SECTION_RVA: u32 = 0x1000;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_c_string(bytes: &mut [u8], offset: usize, value: &str) {
    let encoded = value.as_bytes();
    bytes[offset..offset + encoded.len()].copy_from_slice(encoded);
    bytes[offset + encoded.len()] = 0;
}

fn file_offset(rva: u32) -> usize {
    RAW_OFFSET + usize::try_from(rva - SECTION_RVA).expect("fixture RVA fits usize")
}

fn set_directory(bytes: &mut [u8], index: usize, rva: u32, size: u32) {
    let offset = OPTIONAL_OFFSET + 112 + index * 8;
    put_u32(bytes, offset, rva);
    put_u32(bytes, offset + 4, size);
}

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x800];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, u32::try_from(PE_OFFSET).expect("fixture offset"));
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 1);
    put_u32(&mut bytes, COFF_OFFSET + 4, 0x1234_5678);
    put_u16(&mut bytes, COFF_OFFSET + 16, 0xf0);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x2022);

    put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1000);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 24, 0x0000_0001_4000_0000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x2000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 70, 0x8160);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 108, 16);
    set_directory(&mut bytes, 0, 0x1100, 0x90);
    set_directory(&mut bytes, 1, 0x1200, 40);
    set_directory(&mut bytes, 3, 0x1300, 12);

    bytes[SECTION_OFFSET..SECTION_OFFSET + 5].copy_from_slice(b".all\0");
    put_u32(&mut bytes, SECTION_OFFSET + 8, 0x600);
    put_u32(&mut bytes, SECTION_OFFSET + 12, SECTION_RVA);
    put_u32(&mut bytes, SECTION_OFFSET + 16, 0x600);
    put_u32(
        &mut bytes,
        SECTION_OFFSET + 20,
        u32::try_from(RAW_OFFSET).expect("fixture raw offset"),
    );
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x6000_0020);

    let export = file_offset(0x1100);
    put_u32(&mut bytes, export + 12, 0x1180);
    put_u32(&mut bytes, export + 16, 1);
    put_u32(&mut bytes, export + 20, 2);
    put_u32(&mut bytes, export + 24, 2);
    put_u32(&mut bytes, export + 28, 0x1140);
    put_u32(&mut bytes, export + 32, 0x1148);
    put_u32(&mut bytes, export + 36, 0x1150);
    put_u32(&mut bytes, file_offset(0x1140), 0x1000);
    put_u32(&mut bytes, file_offset(0x1144), 0);
    put_u32(&mut bytes, file_offset(0x1148), 0x1160);
    put_u32(&mut bytes, file_offset(0x114c), 0x1168);
    put_u16(&mut bytes, file_offset(0x1150), 0);
    put_u16(&mut bytes, file_offset(0x1152), 0);
    put_c_string(&mut bytes, file_offset(0x1160), "ExportA");
    put_c_string(&mut bytes, file_offset(0x1168), "Alias");
    put_c_string(&mut bytes, file_offset(0x1180), "fixture.dll");

    let import = file_offset(0x1200);
    put_u32(&mut bytes, import, 0x1240);
    put_u32(&mut bytes, import + 4, 0x1111_1111);
    put_u32(&mut bytes, import + 8, 0xffff_ffff);
    put_u32(&mut bytes, import + 12, 0x1280);
    put_u32(&mut bytes, import + 16, 0x1260);
    put_u64(&mut bytes, file_offset(0x1240), 0x1290);
    put_u64(&mut bytes, file_offset(0x1248), (1_u64 << 63) | 42);
    put_u64(&mut bytes, file_offset(0x1250), 0);
    put_c_string(&mut bytes, file_offset(0x1280), "KERNEL32.dll");
    put_u16(&mut bytes, file_offset(0x1290), 7);
    put_c_string(&mut bytes, file_offset(0x1292), "Imported");

    let exception = file_offset(0x1300);
    put_u32(&mut bytes, exception, 0x1000);
    put_u32(&mut bytes, exception + 4, 0x1020);
    put_u32(&mut bytes, exception + 8, 0x1350);
    bytes
}

#[test]
fn analyzes_minimal_pe_with_imports_exports_and_runtime_functions() {
    let bytes = fixture();
    let analysis = analyze_pe(&bytes).expect("valid synthetic PE");

    assert_eq!(analysis.identity.id, BinaryId::digest(&bytes));
    assert_eq!(analysis.identity.image_base, 0x0000_0001_4000_0000);
    assert_eq!(analysis.pe_header_offset, 0x80);
    assert_eq!(analysis.entry_point_rva, 0x1000);
    assert_eq!(analysis.sections.len(), 1);
    assert_eq!(analysis.sections[0].name, ".all");
    assert_eq!(analysis.export_library_name.as_deref(), Some("fixture.dll"));

    assert_eq!(analysis.imports.len(), 1);
    assert_eq!(analysis.imports[0].name, "KERNEL32.dll");
    assert_eq!(analysis.imports[0].entries.len(), 2);
    assert_eq!(
        analysis.imports[0].entries[0].target,
        ImportTarget::Name {
            hint: 7,
            name: "Imported".to_owned(),
        }
    );
    assert_eq!(
        analysis.imports[0].entries[1].target,
        ImportTarget::Ordinal { ordinal: 42 }
    );

    assert_eq!(analysis.exports.len(), 2);
    assert_eq!(analysis.exports[0].ordinal, 1);
    assert_eq!(analysis.exports[0].address_rva, Some(0x1000));
    assert_eq!(analysis.exports[0].names.len(), 2);
    assert_eq!(analysis.exports[0].names[0].name, "ExportA");
    assert_eq!(analysis.exports[0].names[1].name, "Alias");
    assert_eq!(analysis.exports[1].address_rva, None);

    assert_eq!(analysis.runtime_functions.len(), 1);
    assert_eq!(analysis.runtime_functions[0].begin_rva, 0x1000);
    assert_eq!(analysis.runtime_functions[0].end_rva, 0x1020);
    assert_eq!(analysis.symbol_graph.binaries().len(), 1);
    assert_eq!(analysis.symbol_graph.claims().len(), 3);
    assert!(matches!(
        analysis.symbol_graph.claims()[0].assertion(),
        SymbolAssertion::Name { name } if name == "ExportA"
    ));
    assert_eq!(analysis.symbol_graph.claims()[0].confidence().get(), 0.99);
    assert_eq!(
        analysis.symbol_graph.claims()[0].evidence()[0]
            .confidence
            .expect("exact export evidence")
            .get(),
        1.0
    );
}

#[test]
fn analyze_bytes_exposes_format_independent_accessors() {
    let bytes = fixture();
    let analysis = analyze_bytes(&bytes).expect("recognized PE");
    assert_eq!(analysis.identity().id, BinaryId::digest(&bytes));
    assert_eq!(analysis.binary_id(), &BinaryId::digest(&bytes));
    assert_eq!(analysis.symbol_graph().claims().len(), 3);
    assert!(matches!(analysis, BinaryAnalysis::Pe(_)));
}

#[test]
fn analysis_round_trips_through_serde() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");
    let json = serde_json::to_string(&analysis).expect("serialize analysis");
    let decoded = serde_json::from_str(&json).expect("deserialize analysis");
    assert_eq!(analysis, decoded);
    assert_eq!(analysis.rebuild_symbol_graph().expect("rebuild"), analysis.symbol_graph);
}

#[test]
fn rejects_bad_dos_and_pe_signatures() {
    let mut bad_dos = fixture();
    bad_dos[0..2].copy_from_slice(b"ZZ");
    assert!(matches!(
        analyze_pe(&bad_dos),
        Err(AnalysisError::InvalidDosSignature { .. })
    ));

    let mut bad_pe = fixture();
    bad_pe[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PX\0\0");
    assert!(matches!(
        analyze_pe(&bad_pe),
        Err(AnalysisError::InvalidPeSignature { .. })
    ));
}

#[test]
fn every_truncated_prefix_is_rejected_without_panicking() {
    let bytes = fixture();
    for length in 0..bytes.len() {
        assert!(
            analyze_pe(&bytes[..length]).is_err(),
            "prefix of length {length} unexpectedly parsed"
        );
    }
}

#[test]
fn rejects_unmapped_rvas_with_context() {
    let mut bytes = fixture();
    put_u32(&mut bytes, file_offset(0x1200) + 12, 0x3000);
    let error = analyze_pe(&bytes).expect_err("DLL name RVA is outside the image");
    assert!(matches!(
        error,
        AnalysisError::UnmappedRva {
            context: "import DLL name",
            rva: 0x3000,
            ..
        }
    ));
}

#[test]
fn rejects_unmapped_iat_slots_and_unwind_info() {
    let mut bad_iat = fixture();
    put_u32(&mut bad_iat, file_offset(0x1200) + 16, 0x3000);
    assert!(matches!(
        analyze_pe(&bad_iat),
        Err(AnalysisError::UnmappedRva {
            context: "import address thunk",
            rva: 0x3000,
            ..
        })
    ));

    let mut bad_unwind = fixture();
    put_u32(&mut bad_unwind, file_offset(0x1300) + 8, 0x1700);
    assert!(matches!(
        analyze_pe(&bad_unwind),
        Err(AnalysisError::UnmappedRva {
            context: "runtime-function unwind info",
            rva: 0x1700,
            ..
        })
    ));
}

#[test]
fn validated_deserialization_rejects_reversed_runtime_ranges() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    value["runtime_functions"][0]["end_rva"] = serde_json::json!(0x0fff);

    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect_err("reversed range must not enter the trusted model");
    assert!(error.to_string().contains("runtime-function range"));
}

#[test]
fn validated_deserialization_accepts_prior_generator_provenance_versions() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");
    let mut value = serde_json::to_value(&analysis).expect("serialize analysis");
    for claim in value["symbol_graph"]["claims"]
        .as_array_mut()
        .expect("serialized claims")
    {
        claim["provenance"]["producer"]["version"] = serde_json::json!("0.0.9-alpha.1");
    }

    let decoded = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect("older producer version remains semantically compatible");
    assert_eq!(decoded.identity, analysis.identity);
    assert_eq!(decoded.symbol_graph.claims().len(), 3);
}

#[test]
fn validated_deserialization_rejects_noncanonical_provenance_versions() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");
    let mut value = serde_json::to_value(analysis).expect("serialize analysis");
    value["symbol_graph"]["claims"][0]["provenance"]["producer"]["version"] =
        serde_json::json!("0.1.0\n");

    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(value)
        .expect_err("control characters must not enter trusted provenance");
    assert!(error.to_string().contains("symbol graph"));
}

#[test]
fn validated_deserialization_rejects_noncontiguous_import_metadata() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");

    let mut descriptor = serde_json::to_value(&analysis).expect("serialize analysis");
    descriptor["imports"][0]["descriptor_rva"] = serde_json::json!(0x1214);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(descriptor)
        .expect_err("descriptor source order must be preserved");
    assert!(error.to_string().contains("import descriptor"));

    let mut thunk = serde_json::to_value(analysis).expect("serialize analysis");
    thunk["imports"][0]["entries"][1]["lookup_rva"] = serde_json::json!(0x1250);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(thunk)
        .expect_err("thunk source order must be preserved");
    assert!(error.to_string().contains("import thunk"));
}

#[test]
fn validated_deserialization_rejects_inconsistent_export_metadata() {
    let analysis = analyze_pe(&fixture()).expect("valid PE");

    let mut ordinal = serde_json::to_value(&analysis).expect("serialize analysis");
    ordinal["exports"][1]["ordinal"] = serde_json::json!(4);
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(ordinal)
        .expect_err("EAT ordinals must stay contiguous");
    assert!(error.to_string().contains("export ordinal"));

    let mut forwarder = serde_json::to_value(analysis).expect("serialize analysis");
    forwarder["exports"][0]["forwarded_to"] = serde_json::json!("OTHER.Forwarded");
    let error = serde_json::from_value::<resymbol_analysis::PeAnalysis>(forwarder)
        .expect_err("forwarder text requires an in-directory address");
    assert!(error.to_string().contains("export forwarder"));
}

#[test]
fn preserves_duplicate_and_overlapping_runtime_metadata() {
    let mut bytes = fixture();
    set_directory(&mut bytes, 3, 0x1300, 36);
    let table = file_offset(0x1300);
    put_u32(&mut bytes, table + 12, 0x1000);
    put_u32(&mut bytes, table + 16, 0x1020);
    put_u32(&mut bytes, table + 20, 0x1350);
    put_u32(&mut bytes, table + 24, 0x1010);
    put_u32(&mut bytes, table + 28, 0x1030);
    put_u32(&mut bytes, table + 32, 0x1360);

    let analysis = analyze_pe(&bytes).expect("overlap is evidence, not parser ambiguity");
    assert_eq!(analysis.runtime_functions.len(), 3);
    assert_eq!(
        analysis.runtime_functions[0].begin_rva,
        analysis.runtime_functions[1].begin_rva
    );
    assert_eq!(
        analysis.runtime_functions[0].end_rva,
        analysis.runtime_functions[1].end_rva
    );
    assert_eq!(
        analysis.runtime_functions[0].unwind_info_rva,
        analysis.runtime_functions[1].unwind_info_rva
    );
    assert_eq!(analysis.runtime_functions[0].table_index, 0);
    assert_eq!(analysis.runtime_functions[1].table_index, 1);
    assert_eq!(analysis.symbol_graph.claims().len(), 5);
}

#[test]
fn preserves_duplicate_export_name_claims_in_source_order() {
    let mut bytes = fixture();
    put_u32(&mut bytes, file_offset(0x114c), 0x1160);
    let analysis = analyze_pe(&bytes).expect("duplicate export metadata is valid");
    assert_eq!(analysis.exports[0].names[0].name, "ExportA");
    assert_eq!(analysis.exports[0].names[1].name, "ExportA");
    let claims = analysis.symbol_graph.claims();
    assert!(matches!(
        claims[0].assertion(),
        SymbolAssertion::Name { name } if name == "ExportA"
    ));
    assert!(matches!(
        claims[1].assertion(),
        SymbolAssertion::Name { name } if name == "ExportA"
    ));
    assert_ne!(
        claims[0].evidence()[0].artifacts["name_table_index"],
        claims[1].evidence()[0].artifacts["name_table_index"]
    );
}

#[test]
fn classifies_non_executable_exports_as_globals() {
    let mut bytes = fixture();
    set_directory(&mut bytes, 3, 0, 0);
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x4000_0040);

    let analysis = analyze_pe(&bytes).expect("valid data export");
    assert_eq!(analysis.symbol_graph.claims().len(), 2);
    assert!(analysis.symbol_graph.claims().iter().all(|claim| matches!(
        claim.subject(),
        SymbolSubject::Global { rva: 0x1000, .. }
    )));
}

#[test]
fn rejects_zero_export_name_rvas() {
    let mut bytes = fixture();
    put_u32(&mut bytes, file_offset(0x1148), 0);
    assert!(matches!(
        analyze_pe(&bytes),
        Err(AnalysisError::InvalidField {
            field: "export name RVA",
            ..
        })
    ));
}

#[test]
fn retains_forwarded_exports_without_creating_local_function_claims() {
    let mut bytes = fixture();
    put_u32(&mut bytes, file_offset(0x1140), 0x1170);
    put_c_string(&mut bytes, file_offset(0x1170), "OTHER.Forwarded");

    let analysis = analyze_pe(&bytes).expect("valid forwarded export");
    assert_eq!(
        analysis.exports[0].forwarded_to.as_deref(),
        Some("OTHER.Forwarded")
    );
    assert_eq!(analysis.symbol_graph.claims().len(), 1);
    assert!(matches!(
        analysis.symbol_graph.claims()[0].assertion(),
        SymbolAssertion::FunctionBoundary { .. }
    ));
}

#[test]
fn rejects_an_import_directory_without_a_zero_descriptor() {
    let mut bytes = fixture();
    set_directory(&mut bytes, 1, 0x1200, 20);
    assert!(matches!(
        analyze_pe(&bytes),
        Err(AnalysisError::MissingTerminator {
            context: "import directory"
        })
    ));
}

#[test]
fn rejects_pe32_and_non_amd64_images_explicitly() {
    let mut pe32 = fixture();
    put_u16(&mut pe32, OPTIONAL_OFFSET, 0x010b);
    assert!(matches!(
        analyze_pe(&pe32),
        Err(AnalysisError::UnsupportedOptionalHeader {
            magic: 0x010b,
            expected: 0x020b,
        })
    ));

    let mut x86 = fixture();
    put_u16(&mut x86, COFF_OFFSET, 0x014c);
    assert!(matches!(
        analyze_pe(&x86),
        Err(AnalysisError::UnsupportedMachine {
            machine: 0x014c,
            expected: 0x8664,
        })
    ));
}

#[test]
fn enforces_section_count_limit_before_allocating() {
    let mut bytes = fixture();
    put_u16(&mut bytes, COFF_OFFSET + 2, 97);
    assert!(matches!(
        analyze_pe(&bytes),
        Err(AnalysisError::LimitExceeded {
            kind: "section",
            count: 97,
            limit: 96,
        })
    ));
}

#[test]
fn rejects_unknown_formats_without_guessing() {
    assert!(matches!(
        analyze_bytes(b"\x7fELFtest"),
        Err(AnalysisError::UnsupportedBinaryFormat { .. })
    ));
}
