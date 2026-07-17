use resymbol_analysis::{
    AnalysisError, AnalysisSession, BinaryAnalysis, PluginRunRecord, PluginRunStatus,
    SessionValidationError, analyze_bytes,
};
use resymbol_core::{
    BinaryFormat, BinaryId, ClaimProducer, ClaimProvenance, Confidence, Evidence, EvidenceKind,
    SymbolAssertion, SymbolClaim, SymbolSubject, plugin_api::PluginId,
};
use resymbol_package::{CURRENT_SCHEMA_VERSION, ResymPackage, from_slice, to_vec};

const ELF_HEADER_SIZE: usize = 52;
const PROGRAM_HEADER_OFFSET: usize = ELF_HEADER_SIZE;
const PROGRAM_HEADER_SIZE: usize = 32;
const PROGRAM_HEADER_COUNT: usize = 3;
const SECTION_HEADER_OFFSET: usize = 0x1c0;
const SECTION_HEADER_SIZE: usize = 40;
const SECTION_HEADER_COUNT: usize = 3;
const FIXTURE_SIZE: usize = SECTION_HEADER_OFFSET + SECTION_HEADER_SIZE * SECTION_HEADER_COUNT;

/// Source-built, redistributable fixture. Every byte is synthetic test data.
fn synthetic_elf32_mips() -> Vec<u8> {
    let mut bytes = vec![0_u8; FIXTURE_SIZE];
    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(&mut bytes, 16, 2); // ET_EXEC
    put_u16(&mut bytes, 18, 8); // EM_MIPS
    put_u32(&mut bytes, 20, 1); // EV_CURRENT
    put_u32(&mut bytes, 24, 0x1200_0040);
    put_u32(&mut bytes, 28, PROGRAM_HEADER_OFFSET as u32);
    put_u32(&mut bytes, 32, SECTION_HEADER_OFFSET as u32);
    put_u32(&mut bytes, 36, 0);
    put_u16(&mut bytes, 40, ELF_HEADER_SIZE as u16);
    put_u16(&mut bytes, 42, PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut bytes, 44, PROGRAM_HEADER_COUNT as u16);
    put_u16(&mut bytes, 46, SECTION_HEADER_SIZE as u16);
    put_u16(&mut bytes, 48, SECTION_HEADER_COUNT as u16);
    put_u16(&mut bytes, 50, 0); // no section-name string table

    program_header(
        &mut bytes,
        0,
        ProgramHeader {
            segment_type: 1,
            file_offset: 0,
            virtual_address: 0x1200_0000,
            physical_address: 0x1200_0000,
            file_size: 0x180,
            memory_size: 0x200,
            flags: 7,
            alignment: 0x1000,
        },
    );
    // A zero-sized PT_LOAD exercises the rule that it does not expand the image.
    program_header(
        &mut bytes,
        1,
        ProgramHeader {
            segment_type: 1,
            file_offset: 0,
            virtual_address: 0xf000_0000,
            physical_address: 0xf000_0000,
            file_size: 0,
            memory_size: 0,
            flags: 0,
            alignment: 0,
        },
    );
    program_header(
        &mut bytes,
        2,
        ProgramHeader {
            segment_type: 1,
            file_offset: 0x180,
            virtual_address: 0x1270_0180,
            physical_address: 0x1270_0180,
            file_size: 4,
            memory_size: 0x80,
            flags: 6,
            alignment: 0x10,
        },
    );

    section_header(
        &mut bytes,
        1,
        SectionHeader {
            section_type: 1,
            flags: 6,
            virtual_address: 0x1200_0000,
            file_offset: 0,
            size: 0x180,
            address_alignment: 0x1000,
        },
    );
    section_header(
        &mut bytes,
        2,
        SectionHeader {
            section_type: 1,
            flags: 3,
            virtual_address: 0x1270_0180,
            file_offset: 0x180,
            size: 4,
            address_alignment: 0x10,
        },
    );
    bytes[0x180..0x184].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    bytes
}

#[test]
fn elf32_mips_container_intake_is_sparse_and_claim_free() {
    let fixture = synthetic_elf32_mips();
    let analysis = analyze_bytes(&fixture).expect("synthetic ELF is accepted");
    let BinaryAnalysis::Elf(elf) = &analysis else {
        panic!("ELF input must produce an ELF analysis");
    };

    assert!(matches!(elf.identity.format, BinaryFormat::Elf));
    assert_eq!(elf.identity.architecture, "elf32-em-mips-le");
    assert_eq!(elf.identity.image_base, 0x1200_0000);
    assert_eq!(elf.entry_va, 0x1200_0040);
    assert_eq!(elf.entry_rva, 0x40);
    assert_eq!(elf.flags, 0);
    assert_eq!(elf.program_headers.len(), 3);
    assert_eq!(elf.load_segments.len(), 2);
    assert_eq!(elf.load_segments[0].program_header_index, 0);
    assert_eq!(elf.load_segments[1].program_header_index, 2);
    assert_eq!(elf.image_size, 0x0070_0200);
    assert_eq!(elf.section_headers.len(), 3);
    assert_eq!(elf.symbol_graph.binaries().len(), 1);
    assert!(elf.symbol_graph.claims().is_empty());

    let session = AnalysisSession::new(analysis, Vec::new(), Vec::new())
        .expect("container-only session is valid");
    let package = ResymPackage::from_bound_payload("0.1.0-test", session)
        .expect("ELF session binds to a package");
    assert_eq!(CURRENT_SCHEMA_VERSION, 14);
    let first = to_vec(&package).expect("package serializes");
    let second = to_vec(&package).expect("package serializes deterministically");
    assert_eq!(first, second);
    assert!(
        std::str::from_utf8(&first)
            .expect("package is UTF-8")
            .contains("\"format\":\"elf\"")
    );
    let decoded: ResymPackage<AnalysisSession> = from_slice(&first).expect("package round trips");
    assert_eq!(decoded, package);
}

#[test]
fn sparse_mapping_does_not_materialize_large_virtual_gaps() {
    let mut fixture = synthetic_elf32_mips();
    let third = PROGRAM_HEADER_OFFSET + 2 * PROGRAM_HEADER_SIZE;
    put_u32(&mut fixture, third + 8, 0xffff_f180);
    put_u32(&mut fixture, third + 12, 0xffff_f180);
    let analysis = analyze_bytes(&fixture).expect("large sparse gap remains bounded metadata");
    let BinaryAnalysis::Elf(elf) = analysis else {
        panic!("expected ELF analysis");
    };
    assert_eq!(elf.load_segments.len(), 2);
    assert_eq!(elf.load_segments[1].virtual_address, 0xffff_f180);
    assert_eq!(elf.image_size, 0xedff_f200);
}

#[test]
fn elf_identity_and_load_invariants_are_rejected_explicitly() {
    let mut wrong_class = synthetic_elf32_mips();
    wrong_class[4] = 2;
    assert!(matches!(
        analyze_bytes(&wrong_class),
        Err(AnalysisError::UnsupportedElfClass { class: 2, .. })
    ));

    let mut wrong_endian = synthetic_elf32_mips();
    wrong_endian[5] = 2;
    assert!(matches!(
        analyze_bytes(&wrong_endian),
        Err(AnalysisError::UnsupportedElfDataEncoding { data: 2, .. })
    ));

    let mut wrong_machine = synthetic_elf32_mips();
    put_u16(&mut wrong_machine, 18, 62);
    assert!(matches!(
        analyze_bytes(&wrong_machine),
        Err(AnalysisError::UnsupportedElfMachine { machine: 62, .. })
    ));

    let mut oversized_file_span = synthetic_elf32_mips();
    let third = PROGRAM_HEADER_OFFSET + 2 * PROGRAM_HEADER_SIZE;
    put_u32(&mut oversized_file_span, third + 16, 0x81);
    assert!(matches!(
        analyze_bytes(&oversized_file_span),
        Err(AnalysisError::InvalidField {
            field: "ELF PT_LOAD sizes",
            ..
        })
    ));

    let mut overflowing_load = synthetic_elf32_mips();
    let third = PROGRAM_HEADER_OFFSET + 2 * PROGRAM_HEADER_SIZE;
    put_u32(&mut overflowing_load, third + 8, 0xffff_ffc0);
    put_u32(&mut overflowing_load, third + 12, 0xffff_ffc0);
    put_u32(&mut overflowing_load, third + 20, 0x80);
    assert!(matches!(
        analyze_bytes(&overflowing_load),
        Err(AnalysisError::InvalidField {
            field: "ELF PT_LOAD virtual range",
            ..
        })
    ));

    let mut overflowing_allocated_section = synthetic_elf32_mips();
    let third_section = SECTION_HEADER_OFFSET + 2 * SECTION_HEADER_SIZE;
    put_u32(
        &mut overflowing_allocated_section,
        third_section + 12,
        0xffff_fffc,
    );
    put_u32(&mut overflowing_allocated_section, third_section + 20, 8);
    assert!(matches!(
        analyze_bytes(&overflowing_allocated_section),
        Err(AnalysisError::InvalidField {
            field: "ELF allocated section virtual range",
            ..
        })
    ));

    let mut out_of_file_zero_span = synthetic_elf32_mips();
    let zero_sized = PROGRAM_HEADER_OFFSET + PROGRAM_HEADER_SIZE;
    put_u32(&mut out_of_file_zero_span, zero_sized + 4, u32::MAX);
    assert!(matches!(
        analyze_bytes(&out_of_file_zero_span),
        Err(AnalysisError::InvalidField {
            field: "ELF program segment",
            ..
        })
    ));

    let mut section_table_over_header = synthetic_elf32_mips();
    put_u32(&mut section_table_over_header, 32, 4);
    assert!(matches!(
        analyze_bytes(&section_table_over_header),
        Err(AnalysisError::InvalidField {
            field: "ELF section-header offset",
            ..
        })
    ));

    let mut noncanonical_section_zero = synthetic_elf32_mips();
    put_u32(&mut noncanonical_section_zero, SECTION_HEADER_OFFSET + 4, 1);
    assert!(matches!(
        analyze_bytes(&noncanonical_section_zero),
        Err(AnalysisError::InvalidField {
            field: "ELF section header zero",
            ..
        })
    ));
}

#[test]
fn serialized_elf_analysis_cannot_forge_derived_metadata() {
    let fixture = synthetic_elf32_mips();
    let analysis = analyze_bytes(&fixture).expect("fixture analysis");
    let mut value = serde_json::to_value(analysis).expect("analysis serializes");
    value["analysis"]["entry_rva"] = serde_json::json!(9);
    let error = serde_json::from_value::<BinaryAnalysis>(value)
        .expect_err("forged derived entry RVA is rejected");
    assert!(error.to_string().contains("ELF entry RVA"));

    let analysis = analyze_bytes(&fixture).expect("fixture analysis");
    let mut overflowing_load = serde_json::to_value(&analysis).expect("analysis serializes");
    overflowing_load["analysis"]["program_headers"][2]["virtual_address"] =
        serde_json::json!(0xffff_ffc0_u32);
    overflowing_load["analysis"]["program_headers"][2]["physical_address"] =
        serde_json::json!(0xffff_ffc0_u32);
    overflowing_load["analysis"]["program_headers"][2]["memory_size"] = serde_json::json!(0x80_u32);
    let error = serde_json::from_value::<BinaryAnalysis>(overflowing_load)
        .expect_err("forged overflowing PT_LOAD is rejected");
    assert!(error.to_string().contains("ELF PT_LOAD virtual range"));

    let analysis = analyze_bytes(&fixture).expect("fixture analysis");
    let mut overflowing_section = serde_json::to_value(analysis).expect("analysis serializes");
    overflowing_section["analysis"]["section_headers"][2]["virtual_address"] =
        serde_json::json!(0xffff_fffc_u32);
    overflowing_section["analysis"]["section_headers"][2]["size"] = serde_json::json!(8_u32);
    let error = serde_json::from_value::<BinaryAnalysis>(overflowing_section)
        .expect_err("forged overflowing allocated section is rejected");
    assert!(
        error
            .to_string()
            .contains("ELF allocated section virtual range")
    );

    let analysis = analyze_bytes(&fixture).expect("fixture analysis");
    let mut overlapping_section_table =
        serde_json::to_value(analysis).expect("analysis serializes");
    overlapping_section_table["analysis"]["section_header_offset"] = serde_json::json!(0_u32);
    let error = serde_json::from_value::<BinaryAnalysis>(overlapping_section_table)
        .expect_err("forged section table overlapping the ELF header is rejected");
    assert!(error.to_string().contains("ELF section-header offset"));

    let analysis = analyze_bytes(&fixture).expect("fixture analysis");
    let mut out_of_file_zero_span = serde_json::to_value(analysis).expect("analysis serializes");
    out_of_file_zero_span["analysis"]["program_headers"][1]["file_offset"] =
        serde_json::json!(u32::MAX);
    let error = serde_json::from_value::<BinaryAnalysis>(out_of_file_zero_span)
        .expect_err("forged zero-length file span beyond EOF is rejected");
    assert!(error.to_string().contains("ELF program segment"));

    let analysis = analyze_bytes(&fixture).expect("fixture analysis");
    let mut noncanonical_section_zero =
        serde_json::to_value(analysis).expect("analysis serializes");
    noncanonical_section_zero["analysis"]["section_headers"][0]["section_type"] =
        serde_json::json!(1_u32);
    let error = serde_json::from_value::<BinaryAnalysis>(noncanonical_section_zero)
        .expect_err("forged noncanonical reserved section record is rejected");
    assert!(error.to_string().contains("ELF section header zero"));
}

#[test]
fn elf_function_boundary_must_fit_one_executable_load_mapping() {
    let analysis = analyze_bytes(&synthetic_elf32_mips()).expect("fixture analysis");
    let gap_crossing = function_boundary_claim(analysis.identity().id.clone(), 0x1f0, 0x20);
    let error = AnalysisSession::new(analysis, vec![plugin_run(1)], vec![gap_crossing])
        .expect_err("a boundary spanning a sparse gap must fail");
    assert!(matches!(
        error,
        SessionValidationError::ElfSubjectOutsideLoadSegment { .. }
    ));

    let analysis = analyze_bytes(&synthetic_elf32_mips()).expect("fixture analysis");
    let non_executable = function_boundary_claim(analysis.identity().id.clone(), 0x0070_0180, 0x20);
    let error = AnalysisSession::new(analysis, vec![plugin_run(1)], vec![non_executable])
        .expect_err("a function boundary in a non-executable mapping must fail");
    assert!(matches!(
        error,
        SessionValidationError::ElfFunctionNotExecutable { .. }
    ));

    let analysis = analyze_bytes(&synthetic_elf32_mips()).expect("fixture analysis");
    let valid = function_boundary_claim(analysis.identity().id.clone(), 0x40, 0x20);
    AnalysisSession::new(analysis, vec![plugin_run(1)], vec![valid])
        .expect("a boundary wholly inside an executable mapping is accepted");
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    file_offset: u32,
    virtual_address: u32,
    physical_address: u32,
    file_size: u32,
    memory_size: u32,
    flags: u32,
    alignment: u32,
}

fn program_header(bytes: &mut [u8], index: usize, header: ProgramHeader) {
    let offset = PROGRAM_HEADER_OFFSET + index * PROGRAM_HEADER_SIZE;
    for (field_offset, value) in [
        (0, header.segment_type),
        (4, header.file_offset),
        (8, header.virtual_address),
        (12, header.physical_address),
        (16, header.file_size),
        (20, header.memory_size),
        (24, header.flags),
        (28, header.alignment),
    ] {
        put_u32(bytes, offset + field_offset, value);
    }
}

#[derive(Clone, Copy)]
struct SectionHeader {
    section_type: u32,
    flags: u32,
    virtual_address: u32,
    file_offset: u32,
    size: u32,
    address_alignment: u32,
}

fn section_header(bytes: &mut [u8], index: usize, header: SectionHeader) {
    let offset = SECTION_HEADER_OFFSET + index * SECTION_HEADER_SIZE;
    for (field_offset, value) in [
        (4, header.section_type),
        (8, header.flags),
        (12, header.virtual_address),
        (16, header.file_offset),
        (20, header.size),
        (32, header.address_alignment),
    ] {
        put_u32(bytes, offset + field_offset, value);
    }
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn plugin_id() -> PluginId {
    PluginId::new("dev.resymbol.elf-container-test").expect("valid plugin id")
}

fn plugin_run(accepted_claim_count: u64) -> PluginRunRecord {
    PluginRunRecord::new(
        plugin_id(),
        "1.0.0",
        "elf-run-001",
        BinaryId::digest(b"synthetic ELF plugin artifact").to_string(),
        PluginRunStatus::Succeeded,
        accepted_claim_count,
    )
    .expect("valid plugin run")
}

fn function_boundary_claim(binary: BinaryId, rva: u64, size: u64) -> SymbolClaim {
    SymbolClaim::new(
        SymbolSubject::Function {
            binary,
            rva,
            size: None,
        },
        SymbolAssertion::FunctionBoundary { size },
        Confidence::new(0.75).expect("valid confidence"),
        vec![
            Evidence::new(
                EvidenceKind::new(EvidenceKind::SIGNATURE_MATCH).expect("valid evidence kind"),
                "matched an independently generated synthetic signature",
            )
            .expect("valid evidence"),
        ],
        ClaimProvenance {
            producer: ClaimProducer::Plugin {
                id: plugin_id(),
                version: "1.0.0".to_owned(),
            },
            method: "elf-container-test".to_owned(),
            run_id: Some("elf-run-001".to_owned()),
        },
    )
    .expect("valid core claim")
}
