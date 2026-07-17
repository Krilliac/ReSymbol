#![forbid(unsafe_code)]

use std::{
    fs::{self, File},
    sync::Arc,
};

use resymbol_app::{
    AppError, AppServices, DEFAULT_MAX_BINARY_BYTES, ExportFormat, PluginArtifactPolicyStatus,
    ReviewLedger,
};
use resymbol_core::plugin_api::PluginId;
use resymbol_package::{CURRENT_SCHEMA_VERSION, PackageError};
use resymbol_plugin_state::{
    ArtifactStateKey, FingerprintLimits, PluginStateStore, fingerprint_plugin_directory,
};
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
    let canonical_binary = fs::canonicalize(&binary).expect("canonicalize source fixture");
    assert!(analyzed.has_verified_source());
    assert_eq!(analyzed.binary_path(), Some(canonical_binary.as_path()));
    assert!(analyzed.package_path().is_none());
    assert_eq!(Arc::strong_count(&analyzed), 1);
    let first_source = analyzed
        .verified_source_bytes_arc()
        .expect("analyzed source snapshot");
    let second_source = analyzed
        .verified_source_bytes_arc()
        .expect("shared source snapshot");
    assert!(Arc::ptr_eq(&first_source, &second_source));
    assert_eq!(first_source.as_ref(), EXACT_RSDS_PE);

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
    let canonical_package = fs::canonicalize(&package_path).expect("canonicalize saved package");
    assert!(!opened.has_verified_source());
    assert!(opened.verified_source_bytes_arc().is_none());
    assert!(opened.binary_path().is_none());
    assert_eq!(opened.package_path(), Some(canonical_package.as_path()));
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
fn plugin_catalog_is_deterministic_and_safe_mode_never_passes_artifact_policy() {
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
    assert_eq!(normal.artifact_policy_allowed_count(), 1);
    assert_eq!(normal.entries().len(), 1);
    let entry = &normal.entries()[0];
    assert_eq!(entry.id.as_deref(), Some("community.resymbol.sample"));
    assert_eq!(entry.version.as_deref(), Some("1.2.3"));
    assert_eq!(entry.runtime.as_deref(), Some("wasm"));
    assert_eq!(entry.health, "enabled");
    assert!(entry.loadable);
    assert_eq!(entry.artifact_policy, PluginArtifactPolicyStatus::Sandboxed);
    assert_eq!(
        entry.artifact_fingerprint.as_ref().map(String::len),
        Some(64)
    );
    assert!(entry.artifact_policy.allows_by_artifact_policy());

    let safe = services
        .discover_plugins(temp.path(), true)
        .expect("discover safe-mode plugin catalog");
    assert!(safe.safe_mode());
    assert_eq!(safe.loadable_count(), 0);
    assert_eq!(safe.artifact_policy_allowed_count(), 0);
    assert_eq!(safe.entries()[0].health, "disabled");
    assert_eq!(
        safe.entries()[0].artifact_policy,
        PluginArtifactPolicyStatus::Disabled
    );
    assert!(
        safe.entries()[0]
            .diagnostics
            .iter()
            .any(|message| message.contains("safe-mode"))
    );
}

#[test]
fn process_catalog_policy_is_bound_to_the_exact_artifact() {
    let temp = TempDir::new().expect("create temp directory");
    let plugin = temp.path().join("process-plugin");
    fs::create_dir(&plugin).expect("create process plugin directory");
    let executable = plugin.join("plugin.exe");
    fs::write(&executable, b"first exact process artifact").expect("write process entrypoint");
    fs::write(
        plugin.join("plugin.toml"),
        r#"manifest_version = 1
id = "community.resymbol.process-policy"
name = "Process policy fixture"
version = "1.0.0"
api = "^0.1"
capabilities = ["analyzer.binary"]
permissions = ["binary.read", "claims.submit"]

[runtime]
kind = "external-process"
entrypoint = "plugin.exe"
args = ["--stdio"]
"#,
    )
    .expect("write process manifest");

    let services = AppServices::default();
    let initial = services
        .inspect_plugin_catalog(temp.path())
        .expect("inspect initial process policy");
    let initial_entry = &initial.entries()[0];
    assert_eq!(initial.loadable_count(), 1);
    assert_eq!(initial.artifact_policy_allowed_count(), 0);
    assert_eq!(
        initial_entry.artifact_policy,
        PluginArtifactPolicyStatus::ApprovalRequired
    );
    assert!(initial_entry.loadable);
    assert!(!initial_entry.artifact_policy.allows_by_artifact_policy());
    let initial_fingerprint = fingerprint_plugin_directory(&plugin, FingerprintLimits::default())
        .expect("fingerprint initial process artifact")
        .fingerprint;
    let initial_fingerprint_hex = initial_fingerprint.to_hex();
    assert_eq!(
        initial_entry.artifact_fingerprint.as_deref(),
        Some(initial_fingerprint_hex.as_str())
    );

    let plugin_id = PluginId::new("community.resymbol.process-policy").expect("plugin id");
    let store = PluginStateStore::new(temp.path());
    store
        .trust(&ArtifactStateKey::new(
            plugin_id.clone(),
            initial_fingerprint,
        ))
        .expect("trust exact initial artifact");
    let trusted = services
        .inspect_plugin_catalog(temp.path())
        .expect("inspect trusted process policy");
    assert_eq!(
        trusted.entries()[0].artifact_policy,
        PluginArtifactPolicyStatus::Trusted
    );
    assert_eq!(trusted.loadable_count(), 1);
    assert_eq!(trusted.artifact_policy_allowed_count(), 1);
    assert!(
        trusted.entries()[0]
            .artifact_policy
            .allows_by_artifact_policy()
    );

    fs::write(&executable, b"mutated process artifact").expect("mutate process entrypoint");
    let changed = services
        .inspect_plugin_catalog(temp.path())
        .expect("inspect changed process policy");
    assert_eq!(
        changed.entries()[0].artifact_policy,
        PluginArtifactPolicyStatus::ApprovalRequired
    );
    assert_eq!(changed.artifact_policy_allowed_count(), 0);
    assert!(
        !changed.entries()[0]
            .artifact_policy
            .allows_by_artifact_policy()
    );
    assert_ne!(
        changed.entries()[0].artifact_fingerprint,
        initial.entries()[0].artifact_fingerprint
    );

    let changed_fingerprint = fingerprint_plugin_directory(&plugin, FingerprintLimits::default())
        .expect("fingerprint changed process artifact")
        .fingerprint;
    let changed_key = ArtifactStateKey::new(plugin_id, changed_fingerprint);
    store
        .quarantine(&changed_key, "deterministic policy test quarantine")
        .expect("quarantine exact changed artifact");
    let quarantined = services
        .inspect_plugin_catalog(temp.path())
        .expect("inspect quarantined process policy");
    assert_eq!(
        quarantined.entries()[0].artifact_policy,
        PluginArtifactPolicyStatus::Quarantined
    );
    assert_eq!(quarantined.artifact_policy_allowed_count(), 0);
    assert!(
        !quarantined.entries()[0]
            .artifact_policy
            .allows_by_artifact_policy()
    );
}

#[test]
fn corrupt_exact_process_state_fails_catalog_policy_closed() {
    let temp = TempDir::new().expect("create temp directory");
    let plugin = temp.path().join("corrupt-state-plugin");
    fs::create_dir(&plugin).expect("create process plugin directory");
    fs::write(plugin.join("plugin.exe"), b"process artifact").expect("write entrypoint");
    fs::write(
        plugin.join("plugin.toml"),
        r#"manifest_version = 1
id = "community.resymbol.corrupt-state"
name = "Corrupt state fixture"
version = "1.0.0"
api = "^0.1"
capabilities = ["analyzer.binary"]
permissions = ["binary.read", "claims.submit"]

[runtime]
kind = "external-process"
entrypoint = "plugin.exe"
"#,
    )
    .expect("write process manifest");

    let fingerprint = fingerprint_plugin_directory(&plugin, FingerprintLimits::default())
        .expect("fingerprint process artifact")
        .fingerprint;
    let key = ArtifactStateKey::new(
        PluginId::new("community.resymbol.corrupt-state").expect("plugin id"),
        fingerprint,
    );
    let store = PluginStateStore::new(temp.path());
    store.trust(&key).expect("create exact trust record");
    let record = fs::read_dir(store.state_root().join("v1").join("trust"))
        .expect("read trust directory")
        .map(|entry| entry.expect("read trust entry").path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(&format!("-{fingerprint}.json")))
        })
        .expect("exact trust record");
    fs::write(record, b"{").expect("corrupt exact trust record");

    let catalog = AppServices::default()
        .inspect_plugin_catalog(temp.path())
        .expect("catalog scan survives corrupt plugin state");
    let entry = &catalog.entries()[0];
    assert_eq!(
        entry.artifact_policy,
        PluginArtifactPolicyStatus::CorruptState
    );
    assert!(!entry.artifact_policy.allows_by_artifact_policy());
    assert!(
        entry
            .diagnostics
            .iter()
            .any(|message| message.contains("failed closed"))
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
fn exact_binary_reader_enforces_limits_lengths_and_optional_identity() {
    let temp = TempDir::new().expect("create temp directory");
    let binary = write_source(&temp, "fixture.exe", EXACT_RSDS_PE);
    assert_eq!(DEFAULT_MAX_BINARY_BYTES, 1024 * 1024 * 1024);

    let exact_limit = AppServices::default()
        .with_binary_size_limit(EXACT_RSDS_PE.len() as u64)
        .expect("fixture-sized limit is valid");
    let exact = exact_limit
        .read_binary_exact(&binary, None)
        .expect("a file exactly at the configured limit is accepted");
    assert_eq!(exact.bytes(), EXACT_RSDS_PE);
    assert_eq!(
        exact.path(),
        fs::canonicalize(&binary)
            .expect("canonicalize exact source")
            .as_path()
    );

    let project = exact_limit
        .analyze_binary(&binary)
        .expect("analyze identity fixture");
    let identity = project.session().base_analysis().identity().clone();
    exact_limit
        .read_binary_exact(&binary, Some(&identity))
        .expect("size and SHA-256 identity match");

    let mut mutated = EXACT_RSDS_PE.to_vec();
    *mutated.last_mut().expect("fixture is not empty") ^= 0x5a;
    let mutated_path = write_source(&temp, "mutated.exe", &mutated);
    assert!(matches!(
        exact_limit.read_binary_exact(&mutated_path, Some(&identity)),
        Err(AppError::SourceIdentityMismatch { .. })
    ));

    let short_path = write_source(
        &temp,
        "short.exe",
        &EXACT_RSDS_PE[..EXACT_RSDS_PE.len() - 1],
    );
    assert!(matches!(
        exact_limit.read_binary_exact(&short_path, Some(&identity)),
        Err(AppError::SourceSizeMismatch { .. })
    ));

    let sparse_path = temp.path().join("oversized-sparse.exe");
    let sparse = File::create(&sparse_path).expect("create sparse-size fixture");
    sparse
        .set_len(4_097)
        .expect("set sparse-size fixture length");
    drop(sparse);
    let small_limit = AppServices::default()
        .with_binary_size_limit(4_096)
        .expect("small nonzero limit is valid");
    assert!(matches!(
        small_limit.read_binary_exact(&sparse_path, None),
        Err(AppError::BinaryTooLarge {
            actual: 4_097,
            maximum: 4_096,
            ..
        })
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
