#![forbid(unsafe_code)]

use std::{fs, sync::Arc};

use resymbol_app::{AppError, AppServices, ExportFormat, ReviewLedger};
use resymbol_package::{CURRENT_SCHEMA_VERSION, PackageError};
use tempfile::TempDir;

const EXACT_RSDS_PE: &[u8] =
    include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-symbolized.exe");

fn write_source(temp: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = temp.path().join(name);
    fs::write(&path, bytes).expect("write source fixture");
    path
}

#[test]
fn analyze_save_open_and_exact_identity_verification_are_immutable() {
    let temp = TempDir::new().expect("create temp directory");
    let binary = write_source(&temp, "fixture.exe", EXACT_RSDS_PE);
    let services = AppServices::new("0.1.0-service-test");

    let analyzed = services
        .analyze_binary(&binary)
        .expect("analyze exact PE fixture");
    assert!(analyzed.has_verified_source());
    assert_eq!(analyzed.binary_path(), Some(binary.as_path()));
    assert!(analyzed.package_path().is_none());
    assert_eq!(Arc::strong_count(&analyzed), 1);

    let package_path = temp.path().join("fixture.resym");
    services
        .save_package_new(&analyzed, &package_path)
        .expect("save package with create-new semantics");
    assert!(matches!(
        services.save_package_new(&analyzed, &package_path),
        Err(AppError::Package(PackageError::TargetAlreadyExists { .. }))
    ));

    let opened = services
        .open_package(&package_path)
        .expect("open current-schema package");
    assert!(!opened.has_verified_source());
    assert!(opened.binary_path().is_none());
    assert_eq!(opened.package_path(), Some(package_path.as_path()));
    assert_eq!(
        opened.package().binary_sha256(),
        analyzed.package().binary_sha256()
    );

    let reviews = ReviewLedger::for_session(opened.session()).expect("create review ledger");
    assert!(matches!(
        services.prepare_export(&opened, &reviews, ExportFormat::Pdb),
        Err(AppError::ExactSourceRequired)
    ));

    let mut wrong_bytes = EXACT_RSDS_PE.to_vec();
    let last = wrong_bytes.last_mut().expect("fixture is not empty");
    *last ^= 0x5a;
    let wrong_binary = write_source(&temp, "wrong.exe", &wrong_bytes);
    assert!(matches!(
        services.verify_source_binary(&opened, &wrong_binary),
        Err(AppError::SourceIdentityMismatch { .. })
    ));
    assert!(!opened.has_verified_source(), "the old Arc stays immutable");

    let verified = services
        .verify_source_binary(&opened, &binary)
        .expect("bind exact original PE");
    assert!(verified.has_verified_source());
    assert!(
        !opened.has_verified_source(),
        "verification returns a new snapshot"
    );
}

#[test]
fn all_six_exports_prepare_and_publish_without_clobbering() {
    let temp = TempDir::new().expect("create temp directory");
    let binary = write_source(&temp, "first glance.exe", EXACT_RSDS_PE);
    let services = AppServices::default();
    let project = services
        .analyze_binary(&binary)
        .expect("analyze exact PE fixture");
    let reviews = ReviewLedger::for_session(project.session()).expect("create review ledger");

    for format in ExportFormat::ALL {
        let prepared = services
            .prepare_export(&project, &reviews, format)
            .unwrap_or_else(|error| panic!("prepare {} export: {error}", format.label()));
        assert!(!prepared.bytes().is_empty(), "{} bytes", format.label());
        assert_eq!(prepared.format(), format);
        assert_eq!(
            prepared.projection().binary.id,
            project.session().base_analysis().identity().id
        );

        match format {
            ExportFormat::Json => {
                let json: serde_json::Value =
                    serde_json::from_slice(prepared.bytes()).expect("valid JSON export");
                assert!(json.get("binary").is_some());
            }
            ExportFormat::Markdown => {
                assert!(prepared.bytes().starts_with(b"# ReSymbol"));
            }
            ExportFormat::Map => {
                assert!(prepared.bytes().windows(7).any(|value| value == b"Address"));
            }
            ExportFormat::Pdb => {
                assert!(prepared.bytes().starts_with(b"Microsoft C/C++ MSF 7.00"));
            }
            ExportFormat::IdaPython => {
                assert!(prepared.bytes().windows(6).any(|value| value == b"idaapi"));
            }
            ExportFormat::GhidraJava => {
                let marker = b"extends GhidraScript";
                assert!(
                    prepared
                        .bytes()
                        .windows(marker.len())
                        .any(|value| value == marker)
                );
            }
        }

        let output = temp.path().join(prepared.suggested_file_name());
        services
            .publish_export_new(&prepared, &output)
            .unwrap_or_else(|error| panic!("publish {} export: {error}", format.label()));
        assert_eq!(
            fs::read(&output).expect("read published export"),
            prepared.bytes()
        );
        assert!(matches!(
            services.publish_export_new(&prepared, &output),
            Err(AppError::TargetAlreadyExists { .. })
        ));
    }
}

#[test]
fn plugin_catalog_is_deterministic_and_safe_mode_never_loads() {
    let temp = TempDir::new().expect("create temp directory");
    let plugin = temp.path().join("sample-plugin");
    fs::create_dir(&plugin).expect("create plugin directory");
    fs::write(plugin.join("plugin.wasm"), b"not executed").expect("write plugin placeholder");
    fs::write(
        plugin.join("plugin.toml"),
        r#"manifest_version = 1
id = "community.resymbol.sample"
name = "Sample resolver"
version = "1.2.3"
api = "^0.1"
description = "A discovery-only test plugin"
capabilities = ["resolver.symbols"]
permissions = ["binary.read", "claims.submit"]

[runtime]
kind = "wasm"
entrypoint = "plugin.wasm"
"#,
    )
    .expect("write plugin manifest");

    let services = AppServices::default();
    let normal = services
        .discover_plugins(temp.path(), false)
        .expect("discover normal plugin catalog");
    assert_eq!(normal.loadable_count(), 1);
    assert_eq!(normal.entries().len(), 1);
    let entry = &normal.entries()[0];
    assert_eq!(entry.id.as_deref(), Some("community.resymbol.sample"));
    assert_eq!(entry.version.as_deref(), Some("1.2.3"));
    assert_eq!(entry.runtime.as_deref(), Some("wasm"));
    assert_eq!(entry.health, "enabled");
    assert!(entry.loadable);

    let safe = services
        .discover_plugins(temp.path(), true)
        .expect("discover safe-mode plugin catalog");
    assert!(safe.safe_mode());
    assert_eq!(safe.loadable_count(), 0);
    assert_eq!(safe.entries()[0].health, "disabled");
    assert!(
        safe.entries()[0]
            .diagnostics
            .iter()
            .any(|message| message.contains("safe-mode"))
    );
}

#[test]
fn package_schema_and_binary_size_policies_are_explicit() {
    let temp = TempDir::new().expect("create temp directory");
    let binary = write_source(&temp, "fixture.exe", EXACT_RSDS_PE);
    let too_small = AppServices::default()
        .with_binary_size_limit(EXACT_RSDS_PE.len() as u64 - 1)
        .expect("valid non-zero limit");
    assert!(matches!(
        too_small.analyze_binary(&binary),
        Err(AppError::BinaryTooLarge { .. })
    ));
    assert!(matches!(
        AppServices::default().with_binary_size_limit(0),
        Err(AppError::InvalidBinarySizeLimit)
    ));

    let services = AppServices::default();
    let project = services.analyze_binary(&binary).expect("analyze fixture");
    let current = temp.path().join("current.resym");
    services
        .save_package_new(&project, &current)
        .expect("save current package");
    let encoded = fs::read_to_string(&current).expect("read package JSON");
    let current_marker = format!("\"schema_version\":{CURRENT_SCHEMA_VERSION}");
    let old_marker = format!(
        "\"schema_version\":{}",
        CURRENT_SCHEMA_VERSION.saturating_sub(1)
    );
    let old_encoded = encoded.replacen(&current_marker, &old_marker, 1);
    assert_ne!(old_encoded, encoded, "schema marker was present");
    let old = temp.path().join("old.resym");
    fs::write(&old, old_encoded).expect("write old-schema package");
    assert!(matches!(
        services.open_package(&old),
        Err(AppError::Package(PackageError::UnsupportedSchema { .. }))
    ));
}

#[test]
fn ghidra_publication_enforces_the_java_class_filename() {
    let temp = TempDir::new().expect("create temp directory");
    let binary = write_source(&temp, "fixture.exe", EXACT_RSDS_PE);
    let services = AppServices::default();
    let project = services.analyze_binary(&binary).expect("analyze fixture");
    let reviews = ReviewLedger::for_session(project.session()).expect("create review ledger");
    let prepared = services
        .prepare_export(&project, &reviews, ExportFormat::GhidraJava)
        .expect("prepare Ghidra export");
    let wrong = temp.path().join("Renamed.java");
    assert!(matches!(
        services.publish_export_new(&prepared, &wrong),
        Err(AppError::GhidraFileNameMismatch { .. })
    ));
    assert!(!wrong.exists());
}
