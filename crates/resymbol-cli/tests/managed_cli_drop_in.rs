#![forbid(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use resymbol_core::BinaryId;
use resymbol_package::CURRENT_SCHEMA_VERSION;
use resymbol_plugin_state::{FingerprintLimits, fingerprint_plugin_directory};
use serde_json::Value;
use tempfile::{Builder, TempDir};

const HOST_ENV: &str = "RESYMBOL_MANAGED_E2E_HOST";
const PLUGIN_ENV: &str = "RESYMBOL_MANAGED_E2E_PLUGIN_DIR";
const CLI_ENV: &str = "RESYMBOL_MANAGED_E2E_CLI";
const PLUGIN_ID: &str = "dev.resymbol.example.managed-matcher";
const PLUGIN_VERSION: &str = "0.1.0";
const ENTRY_ASSEMBLY: &str = "Example.ManagedMatcher.dll";

/// Full application-level coverage is opt-in because it needs a published,
/// RID-specific managed helper and the separately built example assembly. The
/// managed SDK workflow supplies both. Invoking this ignored test without its
/// required inputs is intentionally a hard failure rather than a silent skip.
#[test]
#[ignore = "requires a published managed host and managed example plugin"]
fn real_managed_cli_drop_in_round_trip() {
    let source_helper = required_absolute_path(HOST_ENV, false);
    let source_plugin = required_absolute_path(PLUGIN_ENV, true);
    assert_real_example_plugin(&source_plugin);

    // Normal integration CI exercises Cargo's current test binary. Release CI
    // supplies the exact platform archive candidate so the shipped CLI/helper
    // pairing traverses this same drop-in path (including the musl CLI on Linux).
    let source_cli = match env::var_os(CLI_ENV) {
        Some(path) => required_absolute_file(CLI_ENV, path),
        None => fs::canonicalize(env!("CARGO_BIN_EXE_resymbol"))
            .expect("resolve the Cargo-built resymbol CLI"),
    };
    assert!(
        source_cli.is_file(),
        "Cargo did not build a real resymbol CLI"
    );

    let fixture = PrivateApplication::stage(&source_cli, &source_helper, &source_plugin);
    let plugin_path = fixture.plugin_root.join("managed-matcher");
    let expected_artifact =
        fingerprint_plugin_directory(&plugin_path, FingerprintLimits::default())
            .expect("fingerprint the private drop-in plugin")
            .fingerprint;
    let expected_artifact_hex = expected_artifact.to_hex();

    let listed = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "list"]),
    );
    assert_contains(&listed.stdout, PLUGIN_ID, "initial plugin list");
    assert_contains(&listed.stdout, "managed", "initial plugin list");
    assert_contains(
        &listed.stdout,
        &expected_artifact_hex,
        "initial plugin list fingerprint",
    );
    assert_contains(
        &listed.stdout,
        "policy: approval-required",
        "initial plugin list policy",
    );

    let trusted = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "trust", PLUGIN_ID, "--fingerprint"])
            .arg(&expected_artifact_hex),
    );
    assert_contains(
        &trusted.stdout,
        &format!("trusted exact plugin artifact {PLUGIN_ID}@{expected_artifact_hex}"),
        "exact-artifact trust result",
    );

    let binary_bytes = deterministic_pe_x86_64();
    let expected_binary = BinaryId::digest(&binary_bytes).to_string();
    let binary_path = fixture.app_root.join("deterministic-x86_64.exe");
    let package_path = fixture.app_root.join("managed-success.resym");
    fs::write(&binary_path, &binary_bytes).expect("write deterministic PE fixture");

    let analyzed = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .arg("analyze")
            .arg(&binary_path)
            .arg("--output")
            .arg(&package_path)
            .args(["--plugin", PLUGIN_ID, "--strict-plugins"]),
    );
    assert_contains(
        &analyzed.stdout,
        &format!("plugin {PLUGIN_ID}: succeeded"),
        "managed CLI analysis",
    );
    assert!(
        package_path.is_file(),
        "analysis did not create a .resym package"
    );

    let inspected = inspect_json(&fixture.cli, &fixture.app_root, &package_path);
    assert_logically_valid_success_package(&inspected, &expected_binary, &expected_artifact_hex);
    assert_eq!(
        fingerprint_plugin_directory(&plugin_path, FingerprintLimits::default())
            .expect("fingerprint the plugin after successful execution")
            .fingerprint,
        expected_artifact,
        "the exact trusted plugin changed during CLI execution"
    );
    assert_eq!(
        fs::read(&binary_path).expect("read PE fixture after execution"),
        binary_bytes,
        "managed execution changed the exact source binary"
    );

    let disabled = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "disable", PLUGIN_ID]),
    );
    assert_contains(&disabled.stdout, "disabled plugin", "disable result");
    let disabled_sentinel = plugin_path.join("plugin.disabled");
    assert!(
        disabled_sentinel.is_file(),
        "plugin disable did not create the drop-in sentinel"
    );
    assert_eq!(
        fingerprint_plugin_directory(&plugin_path, FingerprintLimits::default())
            .expect("fingerprint the disabled plugin")
            .fingerprint,
        expected_artifact,
        "the root disable sentinel must not change exact artifact identity"
    );

    let disabled_list = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "list"]),
    );
    assert_contains(
        &disabled_list.stdout,
        "disabled  managed",
        "disabled list state",
    );
    assert_contains(&disabled_list.stdout, PLUGIN_ID, "disabled list identity");

    let disabled_package = fixture.app_root.join("disabled-policy.resym");
    let disabled_analysis = run_failure(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .arg("analyze")
            .arg(&binary_path)
            .arg("--output")
            .arg(&disabled_package)
            .args(["--plugin", PLUGIN_ID, "--strict-plugins"]),
    );
    assert_contains(
        &disabled_analysis.stdout,
        &format!("plugin {PLUGIN_ID}: skipped"),
        "disabled strict analysis",
    );
    assert_contains(
        &disabled_analysis.stderr,
        "strict plugin policy rejected 1 plugin outcome(s)",
        "disabled strict analysis",
    );
    assert_empty_plugin_ledger(inspect_json(
        &fixture.cli,
        &fixture.app_root,
        &disabled_package,
    ));

    run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "enable", PLUGIN_ID]),
    );
    assert!(
        !disabled_sentinel.exists(),
        "plugin enable did not remove the disable sentinel"
    );

    let safe_mode_package = fixture.app_root.join("safe-mode-policy.resym");
    let safe_mode_analysis = run_failure(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .arg("--safe-mode")
            .arg("analyze")
            .arg(&binary_path)
            .arg("--output")
            .arg(&safe_mode_package)
            .args(["--plugin", PLUGIN_ID, "--strict-plugins"]),
    );
    assert_contains(
        &safe_mode_analysis.stdout,
        &format!("plugin {PLUGIN_ID}: skipped"),
        "safe-mode strict analysis",
    );
    assert_contains(
        &safe_mode_analysis.stderr,
        "strict plugin policy rejected 1 plugin outcome(s)",
        "safe-mode strict analysis",
    );
    assert_empty_plugin_ledger(inspect_json(
        &fixture.cli,
        &fixture.app_root,
        &safe_mode_package,
    ));
}

struct PrivateApplication {
    _temporary: TempDir,
    app_root: PathBuf,
    plugin_root: PathBuf,
    cli: PathBuf,
}

impl PrivateApplication {
    fn stage(source_cli: &Path, source_helper: &Path, source_plugin: &Path) -> Self {
        let temporary = Builder::new()
            .prefix("resymbol-managed-cli-e2e-")
            .tempdir()
            .expect("create private managed CLI E2E directory");
        let app_root = temporary.path().join("private app");
        create_private_directory(&app_root);

        let cli = app_root.join(format!("resymbol{}", env::consts::EXE_SUFFIX));
        fs::copy(source_cli, &cli).expect("copy the real resymbol CLI into the private app");
        make_private_executable(&cli);

        let helper = app_root.join(format!("resymbol-managed-host{}", env::consts::EXE_SUFFIX));
        fs::copy(source_helper, &helper)
            .expect("copy the published managed helper beside the private CLI");
        make_private_executable(&helper);

        let plugin_root = app_root.join("plugins");
        create_private_directory(&plugin_root);
        copy_directory(source_plugin, &plugin_root.join("managed-matcher"));

        Self {
            _temporary: temporary,
            app_root,
            plugin_root,
            cli,
        }
    }
}

fn required_absolute_path(variable: &str, directory: bool) -> PathBuf {
    let value = env::var_os(variable).unwrap_or_else(|| {
        panic!("required managed CLI E2E environment variable {variable} is absent")
    });
    let path = PathBuf::from(value);
    assert!(
        path.is_absolute(),
        "{variable} must be an absolute path: {}",
        path.display()
    );
    let canonical = fs::canonicalize(&path)
        .unwrap_or_else(|error| panic!("cannot resolve {variable} {}: {error}", path.display()));
    if directory {
        assert!(
            canonical.is_dir(),
            "{variable} must identify a directory: {}",
            canonical.display()
        );
    } else {
        assert!(
            canonical.is_file(),
            "{variable} must identify a file: {}",
            canonical.display()
        );
    }
    canonical
}

fn required_absolute_file(variable: &str, value: std::ffi::OsString) -> PathBuf {
    let path = PathBuf::from(value);
    assert!(
        path.is_absolute(),
        "{variable} must be an absolute path: {}",
        path.display()
    );
    let canonical = fs::canonicalize(&path)
        .unwrap_or_else(|error| panic!("cannot resolve {variable} {}: {error}", path.display()));
    assert!(
        canonical.is_file(),
        "{variable} must identify a file: {}",
        canonical.display()
    );
    canonical
}

fn assert_real_example_plugin(path: &Path) {
    assert!(
        path.join("plugin.toml").is_file(),
        "{PLUGIN_ENV} does not contain plugin.toml"
    );
    assert!(
        path.join(ENTRY_ASSEMBLY).is_file(),
        "{PLUGIN_ENV} does not contain {ENTRY_ASSEMBLY}"
    );
    assert!(
        !path.join("ReSymbol.PluginSdk.dll").exists(),
        "the managed example must bind the helper-owned SDK"
    );
    assert!(
        !path.join("plugin.disabled").exists(),
        "the workflow-provided managed example must begin enabled"
    );
}

fn copy_directory(source: &Path, destination: &Path) {
    let metadata = fs::symlink_metadata(source)
        .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", source.display()));
    assert!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "copy source must be an unlinked directory: {}",
        source.display()
    );
    create_private_directory(destination);

    let mut entries = fs::read_dir(source)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", source.display()))
        .map(|entry| entry.expect("read managed plugin directory entry"))
        .collect::<Vec<_>>();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", source_path.display()));
        assert!(
            !file_type.is_symlink(),
            "managed plugin staging refuses links: {}",
            source_path.display()
        );
        if file_type.is_dir() {
            copy_directory(&source_path, &destination_path);
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).unwrap_or_else(|error| {
                panic!(
                    "cannot copy {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            });
        } else {
            panic!(
                "managed plugin staging refuses special files: {}",
                source_path.display()
            );
        }
    }
}

fn run_success(command: &mut Command) -> CapturedOutput {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("cannot launch {rendered}: {error}"));
    let captured = CapturedOutput::decode(output);
    assert!(
        captured.success,
        "command failed: {rendered}\nstdout:\n{}\nstderr:\n{}",
        captured.stdout, captured.stderr
    );
    captured
}

fn run_failure(command: &mut Command) -> CapturedOutput {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("cannot launch {rendered}: {error}"));
    let captured = CapturedOutput::decode(output);
    assert!(
        !captured.success,
        "command unexpectedly succeeded: {rendered}\nstdout:\n{}\nstderr:\n{}",
        captured.stdout, captured.stderr
    );
    captured
}

struct CapturedOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

impl CapturedOutput {
    fn decode(output: Output) -> Self {
        Self {
            success: output.status.success(),
            stdout: String::from_utf8(output.stdout).expect("resymbol stdout must be UTF-8"),
            stderr: String::from_utf8(output.stderr).expect("resymbol stderr must be UTF-8"),
        }
    }
}

fn inspect_json(cli: &Path, app_root: &Path, package: &Path) -> Value {
    assert!(
        package.is_file(),
        "strict policy must still write a logically valid package: {}",
        package.display()
    );
    let inspected = run_success(
        Command::new(cli)
            .current_dir(app_root)
            .arg("inspect")
            .arg(package)
            .arg("--json"),
    );
    assert!(
        inspected.stderr.is_empty(),
        "validated package inspection wrote diagnostics: {}",
        inspected.stderr
    );
    serde_json::from_str(&inspected.stdout).expect("inspect --json must emit one JSON package")
}

fn assert_logically_valid_success_package(
    package: &Value,
    expected_binary: &str,
    expected_artifact: &str,
) {
    assert_eq!(
        package.pointer("/schema_version").and_then(Value::as_u64),
        Some(u64::from(CURRENT_SCHEMA_VERSION))
    );
    assert_eq!(
        package
            .pointer("/generator_version")
            .and_then(Value::as_str),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        package.pointer("/binary_sha256").and_then(Value::as_str),
        Some(expected_binary)
    );
    assert_eq!(
        package
            .pointer("/payload/base_analysis/format")
            .and_then(Value::as_str),
        Some("pe")
    );
    assert_eq!(
        package
            .pointer("/payload/base_analysis/analysis/identity/id")
            .and_then(Value::as_str),
        Some(expected_binary),
        "the validated payload and package envelope must bind the same binary"
    );

    let runs = package
        .pointer("/payload/plugin_runs")
        .and_then(Value::as_array)
        .expect("validated package must contain a plugin run ledger");
    assert_eq!(runs.len(), 1, "exactly one selected plugin must run");
    let run = &runs[0];
    assert_eq!(
        run.pointer("/plugin_id").and_then(Value::as_str),
        Some(PLUGIN_ID)
    );
    assert_eq!(
        run.pointer("/plugin_version").and_then(Value::as_str),
        Some(PLUGIN_VERSION)
    );
    assert_eq!(
        run.pointer("/artifact_sha256").and_then(Value::as_str),
        Some(expected_artifact),
        "PluginRunRecord must retain the exact trusted artifact fingerprint"
    );
    assert_eq!(
        run.pointer("/status").and_then(Value::as_str),
        Some("succeeded")
    );
    assert_eq!(
        run.pointer("/accepted_claim_count").and_then(Value::as_u64),
        Some(1)
    );
    let run_id = run
        .pointer("/run_id")
        .and_then(Value::as_str)
        .expect("validated PluginRunRecord must contain a run ID");
    assert!(
        !run_id.is_empty() && run_id.len() <= 128 && !run_id.chars().any(char::is_control),
        "PluginRunRecord contains a non-canonical run ID: {run_id:?}"
    );
    let claims = package
        .pointer("/payload/plugin_claims")
        .and_then(Value::as_array)
        .expect("successful managed execution must retain its accepted claim");
    assert_eq!(claims.len(), 1, "the example must emit exactly one claim");
    let claim = &claims[0];
    assert_eq!(
        claim.pointer("/subject/kind").and_then(Value::as_str),
        Some("global")
    );
    assert_eq!(
        claim.pointer("/subject/binary").and_then(Value::as_str),
        Some(expected_binary)
    );
    assert_eq!(
        claim.pointer("/subject/rva").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        claim.pointer("/subject/size").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        claim.pointer("/assertion/kind").and_then(Value::as_str),
        Some("comment")
    );
    assert_eq!(
        claim.pointer("/assertion/text").and_then(Value::as_str),
        Some("Managed example verified the DOS MZ signature via binary.read.")
    );
    assert_eq!(
        claim
            .pointer("/provenance/producer/kind")
            .and_then(Value::as_str),
        Some("plugin")
    );
    assert_eq!(
        claim
            .pointer("/provenance/producer/id")
            .and_then(Value::as_str),
        Some(PLUGIN_ID)
    );
}

fn assert_empty_plugin_ledger(package: Value) {
    assert!(
        package
            .pointer("/payload/plugin_runs")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        "policy-blocked execution must not create a PluginRunRecord"
    );
    assert!(
        package
            .pointer("/payload/plugin_claims")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        "policy-blocked execution must not accept plugin claims"
    );
}

fn assert_contains(output: &str, expected: &str, context: &str) {
    assert!(
        output.contains(expected),
        "{context} did not contain {expected:?}:\n{output}"
    );
}

#[cfg(unix)]
fn create_private_directory(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::create_dir(path)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", path.display()));
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("cannot protect {}: {error}", path.display()));
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) {
    fs::create_dir(path)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", path.display()));
}

#[cfg(unix)]
fn make_private_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("cannot protect {}: {error}", path.display()));
}

#[cfg(not(unix))]
fn make_private_executable(_path: &Path) {}

/// Minimal deterministic PE32+ AMD64 image accepted by the CLI's bounded PE
/// parser and by the managed helper's independent PE validation.
fn deterministic_pe_x86_64() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

    let coff = 0x84;
    put_u16(&mut bytes, coff, 0x8664);
    put_u16(&mut bytes, coff + 2, 1);
    put_u16(&mut bytes, coff + 16, 0x00f0);
    put_u16(&mut bytes, coff + 18, 0x0022);

    let optional = coff + 20;
    put_u16(&mut bytes, optional, 0x020b);
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u32(&mut bytes, optional + 20, 0x1000);
    put_u64(&mut bytes, optional + 24, 0x0000_0001_4000_0000);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x0200);
    put_u16(&mut bytes, optional + 40, 6);
    put_u16(&mut bytes, optional + 48, 6);
    put_u32(&mut bytes, optional + 56, 0x2000);
    put_u32(&mut bytes, optional + 60, 0x0200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u16(&mut bytes, optional + 70, 0x8160);
    put_u64(&mut bytes, optional + 72, 0x10_0000);
    put_u64(&mut bytes, optional + 80, 0x1000);
    put_u64(&mut bytes, optional + 88, 0x10_0000);
    put_u64(&mut bytes, optional + 96, 0x1000);
    put_u32(&mut bytes, optional + 108, 16);

    let section = optional + 0x00f0;
    bytes[section..section + 5].copy_from_slice(b".text");
    put_u32(&mut bytes, section + 8, 0x0100);
    put_u32(&mut bytes, section + 12, 0x1000);
    put_u32(&mut bytes, section + 16, 0x0200);
    put_u32(&mut bytes, section + 20, 0x0200);
    put_u32(&mut bytes, section + 36, 0x6000_0020);
    bytes[0x200] = 0xc3;
    bytes
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
