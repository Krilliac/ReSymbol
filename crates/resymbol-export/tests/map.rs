use resymbol_analysis::{AnalysisSession, analyze_bytes};
use resymbol_export::{
    AttributedText, ExportGlobal, ExportName, ExportProjection, MAX_MAP_MODULE_NAME_BYTES,
    MapError, ProjectionValidationError, render_map,
};

const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 0xf0;
const IMAGE_BASE: u64 = 0x0000_0001_8000_0000;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn two_section_pe() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x600];
    bytes[..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 2);
    put_u32(&mut bytes, COFF_OFFSET + 4, 0x1234_abcd);
    put_u16(&mut bytes, COFF_OFFSET + 16, 0xf0);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x2022);

    put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1010);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 24, IMAGE_BASE);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x3000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 70, 0x8160);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 108, 16);

    bytes[SECTION_OFFSET..SECTION_OFFSET + 8].copy_from_slice(b".text\0\0\0");
    put_u32(&mut bytes, SECTION_OFFSET + 8, 0x180);
    put_u32(&mut bytes, SECTION_OFFSET + 12, 0x1000);
    put_u32(&mut bytes, SECTION_OFFSET + 16, 0x200);
    put_u32(&mut bytes, SECTION_OFFSET + 20, 0x200);
    put_u32(&mut bytes, SECTION_OFFSET + 36, 0x6000_0020);

    let data = SECTION_OFFSET + 40;
    bytes[data..data + 8].copy_from_slice(b".r data\0");
    put_u32(&mut bytes, data + 8, 0x180);
    put_u32(&mut bytes, data + 12, 0x2000);
    put_u32(&mut bytes, data + 16, 0x200);
    put_u32(&mut bytes, data + 20, 0x400);
    put_u32(&mut bytes, data + 36, 0x4000_0040);

    bytes[0x210] = 0xc3;
    bytes
}

fn session_and_projection() -> (AnalysisSession, ExportProjection) {
    let analysis = analyze_bytes(&two_section_pe()).expect("valid synthetic PE");
    let session = AnalysisSession::new(analysis, Vec::new(), Vec::new()).expect("valid session");
    let mut projection = ExportProjection::from_session(&session).expect("session projection");
    let attribution = projection.functions[0]
        .entry_attribution
        .clone()
        .expect("entry point attribution");
    projection.functions[0].selected_name = Some(ExportName {
        source: AttributedText {
            text: "evil name;?".to_owned(),
            attribution: attribution.clone(),
        },
        output_name: "evil_x20_name_x3b__x3f_".to_owned(),
    });
    projection.globals.push(ExportGlobal {
        rva: 0x2020,
        size: None,
        size_attribution: None,
        selected_name: Some(ExportName {
            source: AttributedText {
                text: "global value".to_owned(),
                attribution,
            },
            output_name: "global_x20_value".to_owned(),
        }),
        alternate_names: Vec::new(),
    });
    projection.validate().expect("test projection");
    (session, projection)
}

#[test]
fn emits_documented_sections_rebased_addresses_and_exact_identity() {
    let bytes = two_section_pe();
    let (session, projection) = session_and_projection();
    let output = render_map(&session, &projection, "sample.exe").expect("MAP export");

    assert!(output.starts_with(" sample.exe\n\n Timestamp is 1234abcd\n\n"));
    assert!(output.contains(" Preferred load address is 0000000180000000\n"));
    assert!(output.contains(&format!(
        "; ReSymbol exact binary SHA-256: {}\n",
        resymbol_core::BinaryId::digest(&bytes)
    )));
    assert!(output.contains("; ReSymbol exact binary file size: 1536 bytes\n"));
    assert!(output.contains(" Start         Length     Name                   Class\n"));
    assert!(output.contains(" 0001:00000000 00000200H .text"));
    assert!(output.contains(".text                   CODE\n"));
    assert!(output.contains(" 0002:00000000 00000200H .r_x20_data"));
    assert!(output.contains(".r_x20_data             DATA\n"));
    assert!(output.contains(&format!(
        " 0001:00000010       {:<26} 0000000180001010     <resymbol>\n",
        "evil_x20_name_x3b__x3f_"
    )));
    assert!(output.contains(&format!(
        " 0002:00000020       {:<26} 0000000180002020     <resymbol>\n",
        "global_x20_value"
    )));
    assert!(output.contains(
        "  Address         Publics by Value              Rva+Base               Lib:Object\n"
    ));
    assert!(output.ends_with("\n entry point at         0001:00000010\n"));
}

#[test]
fn hostile_source_names_never_enter_the_whitespace_delimited_symbol_column() {
    let (session, projection) = session_and_projection();
    let output = render_map(&session, &projection, "safe-module").expect("MAP export");

    assert!(output.contains("evil_x20_name_x3b__x3f_"));
    assert!(!output.contains("evil name;?"));

    let mut invalid = projection;
    invalid.functions[0]
        .selected_name
        .as_mut()
        .expect("selected name")
        .output_name = "column break".to_owned();
    assert!(matches!(
        render_map(&session, &invalid, "safe-module"),
        Err(MapError::InvalidProjection(
            ProjectionValidationError::InvalidText {
                field: "symbol.output_name"
            }
        ))
    ));
}

#[test]
fn module_and_section_bounds_are_rejected_instead_of_guessed() {
    let (session, projection) = session_and_projection();
    let oversized = "a".repeat(MAX_MAP_MODULE_NAME_BYTES + 1);
    for invalid in ["", ".", "../sample", "line\nbreak", oversized.as_str()] {
        assert!(matches!(
            render_map(&session, &projection, invalid),
            Err(MapError::InvalidModuleName)
        ));
    }

    let mut outside = projection;
    outside.globals[0].rva = 0x0500;
    outside.validate().expect("header RVA remains in the image");
    assert!(matches!(
        render_map(&session, &outside, "sample"),
        Err(MapError::SymbolOutsideSections {
            kind: "global",
            rva: 0x0500,
            ..
        })
    ));
}

#[test]
fn function_wins_an_address_kind_collision_deterministically() {
    let (session, mut projection) = session_and_projection();
    let attribution = projection.functions[0]
        .entry_attribution
        .clone()
        .expect("entry attribution");
    projection.globals.insert(
        0,
        ExportGlobal {
            rva: 0x1010,
            size: None,
            size_attribution: None,
            selected_name: Some(ExportName {
                source: AttributedText {
                    text: "colliding global".to_owned(),
                    attribution,
                },
                output_name: "colliding_global".to_owned(),
            }),
            alternate_names: Vec::new(),
        },
    );
    projection
        .validate()
        .expect("address-kind collision is valid");

    let first = render_map(&session, &projection, "sample").expect("MAP export");
    let second = render_map(&session, &projection, "sample").expect("repeat MAP export");
    assert_eq!(first, second);
    assert!(first.contains("evil_x20_name_x3b__x3f_"));
    assert!(!first.contains("colliding_global"));
}

#[test]
fn unnamed_function_does_not_suppress_a_same_rva_named_global() {
    let (session, mut projection) = session_and_projection();
    let attribution = projection.functions[0]
        .entry_attribution
        .clone()
        .expect("entry attribution");
    projection.functions[0].selected_name = None;
    projection.globals.insert(
        0,
        ExportGlobal {
            rva: 0x1010,
            size: None,
            size_attribution: None,
            selected_name: Some(ExportName {
                source: AttributedText {
                    text: "entry global".to_owned(),
                    attribution,
                },
                output_name: "entry_global".to_owned(),
            }),
            alternate_names: Vec::new(),
        },
    );
    projection
        .validate()
        .expect("entry/global collision is valid");

    let output = render_map(&session, &projection, "sample").expect("MAP export");
    assert!(output.contains("entry_global"));
    assert!(!output.contains("evil_x20_name_x3b__x3f_"));
}

#[test]
fn duplicate_output_name_and_wrong_binary_binding_fail_closed() {
    let (session, projection) = session_and_projection();

    let mut duplicate = projection.clone();
    duplicate.globals[0]
        .selected_name
        .as_mut()
        .expect("global name")
        .output_name = duplicate.functions[0]
        .selected_name
        .as_ref()
        .expect("function name")
        .output_name
        .clone();
    assert!(matches!(
        render_map(&session, &duplicate, "sample"),
        Err(MapError::InvalidProjection(
            ProjectionValidationError::DuplicateOutputName { .. }
        ))
    ));

    let mut wrong_base = projection;
    wrong_base.binary.image_base += 0x1000;
    wrong_base
        .validate()
        .expect("projection remains internally valid");
    assert!(matches!(
        render_map(&session, &wrong_base, "sample"),
        Err(MapError::ProjectionSessionMismatch {
            field: "binary.image_base"
        })
    ));
}
