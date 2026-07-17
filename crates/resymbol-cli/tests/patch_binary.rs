#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use resymbol_app::{AppServices, StaticPatchEditRequest};
use resymbol_core::BinaryId;
use serde_json::Value;
use tempfile::TempDir;

const EXACT_PE: &[u8] =
    include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-symbolized.exe");
const WRONG_PE: &[u8] =
    include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");
const THUNK_RVA: u32 = 0x1184;
const THUNK_FILE_OFFSET: usize = 0x584;
const THUNK_BYTES: [u8; 5] = [0xe9, 0x03, 0x00, 0x00, 0x00];

fn cli() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_resymbol"))
}

fn run(command: &mut Command) -> Output {
    command.output().expect("launch ReSymbol CLI")
}

fn write_source(temp: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = temp.path().join(name);
    fs::write(&path, bytes).expect("write PE fixture");
    path
}

fn write_patch_set(temp: &TempDir, source: &Path) -> PathBuf {
    let services = AppServices::default();
    let project = services
        .analyze_binary(source)
        .expect("analyze exact PE fixture");
    let request = StaticPatchEditRequest::nop_instruction(
        THUNK_RVA,
        THUNK_BYTES,
        "Disable internal jump thunk",
    )
    .expect("construct exact NOP request");
    let path = temp.path().join("disable-thunk.respatch.json");
    services
        .save_static_patch_set_new(&project, vec![request], &path)
        .expect("save strict patch set");
    path
}

fn patch_command(source: &Path, patch_set: &Path, output: &Path) -> Command {
    let mut command = Command::new(cli());
    command
        .arg("patch")
        .arg(source)
        .arg(patch_set)
        .arg("--output")
        .arg(output);
    command
}

fn assert_no_patch_staging_files(root: &Path) {
    assert!(
        fs::read_dir(root)
            .expect("read patch directory")
            .all(|entry| !entry
                .expect("read patch directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".resymbol-patch-")),
        "patch command left a staging file behind"
    );
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).expect("create patch-set symlink");
    true
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> bool {
    match std::os::windows::fs::symlink_file(target, link) {
        Ok(()) => true,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
            ) || error.raw_os_error() == Some(1_314) =>
        {
            false
        }
        Err(error) => panic!("create patch-set symlink: {error}"),
    }
}

#[test]
fn patch_command_publishes_a_checked_create_new_binary_and_receipt() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let source = write_source(&temp, "source.exe", EXACT_PE);
    let patch_set = write_patch_set(&temp, &source);
    let output = temp.path().join("source-patched.exe");

    let result = run(&mut patch_command(&source, &patch_set, &output));
    assert!(
        result.status.success(),
        "patch failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());

    let patched = fs::read(&output).expect("read patched output");
    assert_eq!(
        &patched[THUNK_FILE_OFFSET..THUNK_FILE_OFFSET + THUNK_BYTES.len()],
        &[0x90; THUNK_BYTES.len()]
    );
    assert_eq!(fs::read(&source).expect("read unchanged source"), EXACT_PE);

    let stdout = String::from_utf8(result.stdout).expect("receipt is UTF-8");
    assert!(stdout.contains(&format!(
        "source binary: {}",
        source.canonicalize().expect("canonical source").display()
    )));
    assert!(stdout.contains(&format!(
        "patch set: {}",
        patch_set.canonicalize().expect("canonical patch set").display()
    )));
    assert!(stdout.contains("edits: 1\n"));
    assert!(stdout.contains(&format!("patched binary: {}", output.display())));
    assert!(stdout.contains(&format!("output SHA-256: {}", BinaryId::digest(&patched))));
    let reported_warning_count = stdout
        .lines()
        .find_map(|line| line.strip_prefix("warnings: "))
        .expect("receipt reports a warning count")
        .parse::<usize>()
        .expect("warning count is numeric");
    let printed_warning_count = stdout
        .lines()
        .filter(|line| line.starts_with("  - "))
        .count();
    assert_eq!(reported_warning_count, printed_warning_count);
    assert!(reported_warning_count >= 2);
    assert!(stdout.contains("Authenticode signature"));
    assert!(stdout.contains("PE checksum"));
    assert!(stdout.contains("durability: "));
    assert!(stdout.contains("execution: not performed\n"));
    assert_no_patch_staging_files(temp.path());
}

#[test]
fn patch_command_rejects_a_patch_set_for_a_different_exact_source() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let source = write_source(&temp, "source.exe", EXACT_PE);
    let patch_set = write_patch_set(&temp, &source);
    let wrong_source = write_source(&temp, "wrong-source.exe", WRONG_PE);
    let output = temp.path().join("wrong-source-patched.exe");

    let result = run(&mut patch_command(&wrong_source, &patch_set, &output));
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).expect("error is UTF-8");
    assert!(stderr.contains("patch set belongs to source"));
    assert!(stderr.contains(BinaryId::digest(EXACT_PE).as_str()));
    assert!(stderr.contains(BinaryId::digest(WRONG_PE).as_str()));
    assert!(!output.exists());
    assert_eq!(
        fs::read(&wrong_source).expect("read unchanged wrong source"),
        WRONG_PE
    );
    assert_no_patch_staging_files(temp.path());
}

#[test]
fn patch_command_rejects_tampered_expected_bytes_before_publication() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let source = write_source(&temp, "source.exe", EXACT_PE);
    let patch_set = write_patch_set(&temp, &source);
    let mut document: Value =
        serde_json::from_slice(&fs::read(&patch_set).expect("read patch set"))
            .expect("decode patch set");
    document["edits"][0]["expected"][1] = Value::from(4_u64);
    fs::write(
        &patch_set,
        serde_json::to_vec(&document).expect("encode tampered patch set"),
    )
    .expect("write tampered patch set");
    let output = temp.path().join("tampered-patched.exe");

    let result = run(&mut patch_command(&source, &patch_set, &output));
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).expect("error is UTF-8");
    assert!(stderr.contains("source bytes are stale at RVA 0x1184"));
    assert!(stderr.contains("expected [e9, 04, 00, 00, 00]"));
    assert!(!output.exists());
    assert_eq!(fs::read(&source).expect("read unchanged source"), EXACT_PE);
    assert_no_patch_staging_files(temp.path());
}

#[test]
fn patch_command_preserves_an_existing_destination() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let source = write_source(&temp, "source.exe", EXACT_PE);
    let patch_set = write_patch_set(&temp, &source);
    let output = temp.path().join("existing.exe");
    let sentinel = b"existing destination must survive";
    fs::write(&output, sentinel).expect("write existing destination");

    let result = run(&mut patch_command(&source, &patch_set, &output));
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).expect("error is UTF-8");
    assert!(stderr.contains("refusing to overwrite existing patched binary"));
    assert_eq!(
        fs::read(&output).expect("read preserved destination"),
        sentinel
    );
    assert_eq!(fs::read(&source).expect("read unchanged source"), EXACT_PE);
    assert_no_patch_staging_files(temp.path());
}

#[test]
fn patch_command_checks_the_requested_relative_symlink_suffix() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let source = write_source(&temp, "source.exe", EXACT_PE);
    let patch_set = write_patch_set(&temp, &source);
    let alias = temp.path().join("patch-set-alias.json");
    if !create_file_symlink(&patch_set, &alias) {
        // Creating symlinks may require an unavailable Windows developer-mode
        // privilege. The same assertion runs on hosts where links are allowed.
        return;
    }
    let output = temp.path().join("alias-patched.exe");
    let mut command = Command::new(cli());
    command
        .current_dir(temp.path())
        .arg("patch")
        .arg("source.exe")
        .arg("patch-set-alias.json")
        .arg("--output")
        .arg("alias-patched.exe");

    let result = run(&mut command);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).expect("error is UTF-8");
    assert!(stderr.contains("must end with `.respatch.json`"));
    assert!(!output.exists());
    assert_eq!(fs::read(&source).expect("read unchanged source"), EXACT_PE);
}

#[test]
fn patch_help_documents_exact_inputs_and_create_new_output() {
    let result = run(Command::new(cli()).arg("patch").arg("--help"));
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let stdout = String::from_utf8(result.stdout).expect("help is UTF-8");
    assert!(stdout.contains("Apply a strict portable patch set"));
    assert!(stdout.contains("Exact source PE"));
    assert!(stdout.contains("never executed"));
    assert!(stdout.contains("<EXACT_SOURCE_PE>"));
    assert!(stdout.contains("<PATCH_SET>"));
    assert!(stdout.contains("--output <NEW_BINARY>"));
    assert!(stdout.contains("an existing path is never replaced"));
}
