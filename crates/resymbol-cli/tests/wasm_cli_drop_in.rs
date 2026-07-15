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

const PLUGIN_ENV: &str = "RESYMBOL_WASM_E2E_PLUGIN_DIR";
const CLI_ENV: &str = "RESYMBOL_WASM_E2E_CLI";
const PLUGIN_ID: &str = "dev.resymbol.example.wasm-resolver";
const PLUGIN_VERSION: &str = "0.1.0";
const ENTRY_COMPONENT: &str = "example-resolver.wasm";

/// Full application-level coverage is opt-in until the example Component Model
/// plugin is built by CI. The supplied example must read the deterministic PE
/// through `binary.read` and submit at least one valid claim. This test stages
/// the real CLI and component in a private drop-in layout and never relies on a
/// developer checkout as the runtime working directory.
#[test]
#[ignore = "requires the built WASM example component"]
fn real_wasm_cli_drop_in_round_trip() {
    let source_plugin = required_absolute_directory(PLUGIN_ENV);
    assert_real_example_plugin(&source_plugin);
    let source_cli = match env::var_os(CLI_ENV) {
        Some(path) => required_absolute_file(CLI_ENV, path),
        None => fs::canonicalize(env!("CARGO_BIN_EXE_resymbol"))
            .expect("resolve the Cargo-built resymbol CLI"),
    };

    let fixture = PrivateApplication::stage(&source_cli, &source_plugin);
    let plugin_path = fixture.plugin_root.join("wasm-resolver");
    let component_path = plugin_path.join(ENTRY_COMPONENT);
    let original_component = fs::read(&component_path).expect("read staged WASM component");
    let expected_artifact =
        fingerprint_plugin_directory(&plugin_path, FingerprintLimits::default())
            .expect("fingerprint the private WASM drop-in")
            .fingerprint;
    let expected_artifact_hex = expected_artifact.to_hex();

    let listed = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "list"]),
    );
    assert_contains(&listed.stdout, "enabled  wasm", "initial plugin state");
    assert_contains(&listed.stdout, PLUGIN_ID, "initial plugin identity");
    assert_contains(
        &listed.stdout,
        &expected_artifact_hex,
        "initial plugin fingerprint",
    );
    assert_contains(
        &listed.stdout,
        "policy: sandboxed-autoload",
        "initial WASM policy",
    );
    assert!(
        !listed.stdout.contains("policy: approval-required"),
        "sandboxed WASM must not ask for ambient-authority approval:\n{}",
        listed.stdout
    );

    let trust = run_failure(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "trust", PLUGIN_ID]),
    );
    assert_contains(
        &trust.stderr,
        "plugin trust does not apply to sandboxed WASM plugins",
        "unnecessary WASM trust",
    );

    let binary_bytes = deterministic_pe_x86_64();
    let expected_binary = BinaryId::digest(&binary_bytes).to_string();
    let binary_path = fixture.app_root.join("deterministic-x86_64.exe");
    fs::write(&binary_path, &binary_bytes).expect("write deterministic PE fixture");

    let success_package = fixture.app_root.join("wasm-success.resym");
    let analyzed = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .arg("analyze")
            .arg(&binary_path)
            .arg("--output")
            .arg(&success_package)
            .arg("--strict-plugins"),
    );
    assert_contains(
        &analyzed.stdout,
        &format!("plugin {PLUGIN_ID}: succeeded"),
        "WASM CLI analysis",
    );
    assert_success_package(
        &inspect_json(&fixture.cli, &fixture.app_root, &success_package),
        &expected_binary,
        &expected_artifact_hex,
    );
    let trust_directory = fixture
        .plugin_root
        .join(".resymbol")
        .join("v1")
        .join("trust");
    assert!(
        !trust_directory.exists()
            || fs::read_dir(&trust_directory)
                .expect("read WASM trust directory")
                .next()
                .is_none(),
        "sandboxed WASM autoload unexpectedly created a trust record"
    );
    assert_eq!(
        fingerprint_plugin_directory(&plugin_path, FingerprintLimits::default())
            .expect("fingerprint the component after execution")
            .fingerprint,
        expected_artifact,
        "sandboxed execution changed the drop-in artifact"
    );
    assert_eq!(
        fs::read(&binary_path).expect("read PE after WASM execution"),
        binary_bytes,
        "sandboxed execution changed the exact PE snapshot"
    );

    run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "disable", PLUGIN_ID]),
    );
    let disabled_list = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "list"]),
    );
    assert_contains(
        &disabled_list.stdout,
        "disabled  wasm",
        "manual WASM disable",
    );
    let disabled_package = fixture.app_root.join("wasm-disabled.resym");
    let disabled = run_failure(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .arg("analyze")
            .arg(&binary_path)
            .arg("--output")
            .arg(&disabled_package)
            .args(["--plugin", PLUGIN_ID, "--strict-plugins"]),
    );
    assert_contains(
        &disabled.stdout,
        &format!("plugin {PLUGIN_ID}: skipped"),
        "disabled strict analysis",
    );
    assert_strict_failure(&disabled);
    assert_empty_plugin_ledger(&inspect_json(
        &fixture.cli,
        &fixture.app_root,
        &disabled_package,
    ));

    run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "enable", PLUGIN_ID]),
    );
    let safe_package = fixture.app_root.join("wasm-safe-mode.resym");
    let safe = run_failure(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .arg("--safe-mode")
            .arg("analyze")
            .arg(&binary_path)
            .arg("--output")
            .arg(&safe_package)
            .args(["--plugin", PLUGIN_ID, "--strict-plugins"]),
    );
    assert_contains(
        &safe.stdout,
        &format!("plugin {PLUGIN_ID}: skipped"),
        "safe-mode strict analysis",
    );
    assert_strict_failure(&safe);
    assert_empty_plugin_ledger(&inspect_json(
        &fixture.cli,
        &fixture.app_root,
        &safe_package,
    ));

    // A malformed component is attributable plugin content: the first strict
    // run records failure and quarantines its exact fingerprint; the second is
    // blocked before execution. Reset makes that exact artifact eligible for
    // sandboxed autoload again without creating a trust record.
    fs::write(&component_path, b"not a WebAssembly component")
        .expect("replace component with an invalid exact artifact");
    let broken_artifact = fingerprint_plugin_directory(&plugin_path, FingerprintLimits::default())
        .expect("fingerprint invalid component")
        .fingerprint;
    assert_ne!(broken_artifact, expected_artifact);

    let broken_package = fixture.app_root.join("wasm-attributable-failure.resym");
    let broken = run_failure(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .arg("analyze")
            .arg(&binary_path)
            .arg("--output")
            .arg(&broken_package)
            .args(["--plugin", PLUGIN_ID, "--strict-plugins"]),
    );
    assert_contains(
        &broken.stdout,
        &format!("plugin {PLUGIN_ID}: failed"),
        "attributable invalid component",
    );
    assert_strict_failure(&broken);
    assert_failed_plugin_ledger(&inspect_json(
        &fixture.cli,
        &fixture.app_root,
        &broken_package,
    ));
    let quarantined_list = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "list"]),
    );
    assert_contains(
        &quarantined_list.stdout,
        "policy: quarantined",
        "attributable WASM quarantine",
    );

    let blocked_package = fixture.app_root.join("wasm-quarantine-block.resym");
    let blocked = run_failure(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .arg("analyze")
            .arg(&binary_path)
            .arg("--output")
            .arg(&blocked_package)
            .args(["--plugin", PLUGIN_ID, "--strict-plugins"]),
    );
    assert_contains(
        &blocked.stdout,
        &format!("plugin {PLUGIN_ID}: skipped"),
        "quarantined WASM analysis",
    );
    assert_empty_plugin_ledger(&inspect_json(
        &fixture.cli,
        &fixture.app_root,
        &blocked_package,
    ));

    run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "reset", PLUGIN_ID]),
    );
    let reset_list = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .args(["plugin", "list"]),
    );
    assert_contains(
        &reset_list.stdout,
        "policy: sandboxed-autoload",
        "WASM quarantine reset",
    );

    fs::write(&component_path, original_component).expect("restore valid WASM component");
    let recovered_package = fixture.app_root.join("wasm-recovered.resym");
    let recovered = run_success(
        Command::new(&fixture.cli)
            .current_dir(&fixture.app_root)
            .arg("analyze")
            .arg(&binary_path)
            .arg("--output")
            .arg(&recovered_package)
            .args(["--plugin", PLUGIN_ID, "--strict-plugins"]),
    );
    assert_contains(
        &recovered.stdout,
        &format!("plugin {PLUGIN_ID}: succeeded"),
        "restored WASM analysis",
    );
}

struct PrivateApplication {
    _temporary: TempDir,
    app_root: PathBuf,
    plugin_root: PathBuf,
    cli: PathBuf,
}

impl PrivateApplication {
    fn stage(source_cli: &Path, source_plugin: &Path) -> Self {
        let temporary = Builder::new()
            .prefix("resymbol-wasm-cli-e2e-")
            .tempdir()
            .expect("create private WASM CLI E2E directory");
        let app_root = temporary.path().join("private app");
        create_private_directory(&app_root);
        let cli = app_root.join(format!("resymbol{}", env::consts::EXE_SUFFIX));
        fs::copy(source_cli, &cli).expect("copy the real CLI into the private app");
        make_private_executable(&cli);
        let plugin_root = app_root.join("plugins");
        create_private_directory(&plugin_root);
        copy_directory(source_plugin, &plugin_root.join("wasm-resolver"));
        Self {
            _temporary: temporary,
            app_root,
            plugin_root,
            cli,
        }
    }
}

fn required_absolute_directory(variable: &str) -> PathBuf {
    let value = env::var_os(variable)
        .unwrap_or_else(|| panic!("required WASM E2E variable {variable} is absent"));
    let path = PathBuf::from(value);
    assert!(path.is_absolute(), "{variable} must be absolute");
    let canonical = fs::canonicalize(&path)
        .unwrap_or_else(|error| panic!("cannot resolve {}: {error}", path.display()));
    assert!(canonical.is_dir(), "{variable} must identify a directory");
    canonical
}

fn required_absolute_file(variable: &str, value: std::ffi::OsString) -> PathBuf {
    let path = PathBuf::from(value);
    assert!(path.is_absolute(), "{variable} must be absolute");
    let canonical = fs::canonicalize(&path)
        .unwrap_or_else(|error| panic!("cannot resolve {}: {error}", path.display()));
    assert!(canonical.is_file(), "{variable} must identify a file");
    canonical
}

fn assert_real_example_plugin(path: &Path) {
    assert!(path.join("plugin.toml").is_file());
    assert!(path.join(ENTRY_COMPONENT).is_file());
    assert!(!path.join("plugin.disabled").exists());
}

fn copy_directory(source: &Path, destination: &Path) {
    let metadata = fs::symlink_metadata(source)
        .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", source.display()));
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    create_private_directory(destination);
    let mut entries = fs::read_dir(source)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", source.display()))
        .map(|entry| entry.expect("read WASM plugin directory entry"))
        .collect::<Vec<_>>();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", source_path.display()));
        assert!(!file_type.is_symlink(), "WASM staging refuses links");
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
            panic!("WASM staging refuses special files");
        }
    }
}

fn run_success(command: &mut Command) -> CapturedOutput {
    run_with_expected_status(command, true)
}

fn run_failure(command: &mut Command) -> CapturedOutput {
    run_with_expected_status(command, false)
}

fn run_with_expected_status(command: &mut Command, success: bool) -> CapturedOutput {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("cannot launch {rendered}: {error}"));
    let captured = CapturedOutput::decode(output);
    assert_eq!(
        captured.success, success,
        "unexpected command status: {rendered}\nstdout:\n{}\nstderr:\n{}",
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
            stdout: String::from_utf8(output.stdout).expect("CLI stdout must be UTF-8"),
            stderr: String::from_utf8(output.stderr).expect("CLI stderr must be UTF-8"),
        }
    }
}

fn inspect_json(cli: &Path, app_root: &Path, package: &Path) -> Value {
    assert!(
        package.is_file(),
        "package was not written: {}",
        package.display()
    );
    let inspected = run_success(
        Command::new(cli)
            .current_dir(app_root)
            .arg("inspect")
            .arg(package)
            .arg("--json"),
    );
    serde_json::from_str(&inspected.stdout).expect("inspect --json must emit one JSON package")
}

fn assert_success_package(package: &Value, expected_binary: &str, expected_artifact: &str) {
    assert_eq!(
        package.pointer("/schema_version").and_then(Value::as_u64),
        Some(u64::from(CURRENT_SCHEMA_VERSION))
    );
    assert_eq!(
        package.pointer("/binary_sha256").and_then(Value::as_str),
        Some(expected_binary)
    );
    let runs = package
        .pointer("/payload/plugin_runs")
        .and_then(Value::as_array)
        .expect("plugin run ledger");
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].pointer("/plugin_id").and_then(Value::as_str),
        Some(PLUGIN_ID)
    );
    assert_eq!(
        runs[0].pointer("/plugin_version").and_then(Value::as_str),
        Some(PLUGIN_VERSION)
    );
    assert_eq!(
        runs[0].pointer("/artifact_sha256").and_then(Value::as_str),
        Some(expected_artifact)
    );
    assert_eq!(
        runs[0].pointer("/status").and_then(Value::as_str),
        Some("succeeded")
    );
    let claims = package
        .pointer("/payload/plugin_claims")
        .and_then(Value::as_array)
        .expect("plugin claim list");
    assert_eq!(
        claims.len(),
        1,
        "WASM example must submit its one exact binary-read claim"
    );
    assert_eq!(
        runs[0]
            .pointer("/accepted_claim_count")
            .and_then(Value::as_u64),
        u64::try_from(claims.len()).ok()
    );
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
        Some("WASM example verified the DOS MZ signature via binary.read.")
    );
    assert_eq!(
        claim.pointer("/evidence/0/summary").and_then(Value::as_str),
        Some("exact image bytes at RVA 0 were 4d 5a")
    );
    assert_eq!(
        claim
            .pointer("/provenance/producer/id")
            .and_then(Value::as_str),
        Some(PLUGIN_ID)
    );
}

fn assert_empty_plugin_ledger(package: &Value) {
    assert!(
        package
            .pointer("/payload/plugin_runs")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    );
    assert!(
        package
            .pointer("/payload/plugin_claims")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    );
}

fn assert_failed_plugin_ledger(package: &Value) {
    let runs = package
        .pointer("/payload/plugin_runs")
        .and_then(Value::as_array)
        .expect("failed plugin run ledger");
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].pointer("/status").and_then(Value::as_str),
        Some("failed")
    );
    assert!(
        package
            .pointer("/payload/plugin_claims")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    );
}

fn assert_strict_failure(output: &CapturedOutput) {
    assert_contains(
        &output.stderr,
        "strict plugin policy rejected 1 plugin outcome(s)",
        "strict plugin policy",
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
