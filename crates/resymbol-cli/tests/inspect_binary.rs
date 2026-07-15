use std::{fs, path::PathBuf, process::Command};

use resymbol_core::BinaryId;
use serde_json::Value;

fn cli() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_resymbol"))
}

fn fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe")
        .canonicalize()
        .expect("canonical MSVC fixture")
}

fn run(command: &mut Command) -> std::process::Output {
    command.output().expect("launch ReSymbol CLI")
}

#[test]
fn inspect_binary_gate_keeps_stdout_pure_and_inputs_unchanged() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let binary = fixture_binary();
    let package = temp.path().join("inspection.resym");
    let plugins = temp.path().join("plugins");

    let analyzed = run(Command::new(cli())
        .arg("--safe-mode")
        .arg("--plugin-dir")
        .arg(&plugins)
        .arg("analyze")
        .arg(&binary)
        .arg("--output")
        .arg(&package));
    assert!(
        analyzed.status.success(),
        "analysis failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&analyzed.stdout),
        String::from_utf8_lossy(&analyzed.stderr)
    );
    let original_package = fs::read(&package).expect("read generated package");
    let original_binary = fs::read(&binary).expect("read fixture binary");

    let human = run(Command::new(cli())
        .arg("inspect")
        .arg(&package)
        .arg("--binary")
        .arg(&binary));
    assert!(
        human.status.success(),
        "human inspection failed: {}",
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(human.stderr.is_empty());
    let human_stdout = String::from_utf8(human.stdout).expect("human stdout is UTF-8");
    assert!(human_stdout.contains(&format!("source binary: {}\n", binary.display())));
    assert!(human_stdout.contains("identity gate: matched\n"));

    let json = run(Command::new(cli())
        .arg("inspect")
        .arg(&package)
        .arg("--binary")
        .arg(&binary)
        .arg("--json"));
    assert!(
        json.status.success(),
        "JSON inspection failed: {}",
        String::from_utf8_lossy(&json.stderr)
    );
    assert!(json.stderr.is_empty());
    let document: Value =
        serde_json::from_slice(&json.stdout).expect("stdout is exactly one JSON document");
    assert_eq!(document["schema_version"], 6);
    let json_stdout = String::from_utf8(json.stdout).expect("JSON stdout is UTF-8");
    assert!(!json_stdout.contains("identity gate"));
    assert!(!json_stdout.contains("source binary"));

    let mutated = temp.path().join("mutated.exe");
    let mut mutated_bytes = original_binary.clone();
    mutated_bytes[0] ^= 0xff;
    fs::write(&mutated, &mutated_bytes).expect("write same-size mutation");
    let mutation = run(Command::new(cli())
        .arg("inspect")
        .arg(&package)
        .arg("--binary")
        .arg(&mutated));
    assert!(!mutation.status.success());
    assert!(mutation.stdout.is_empty());
    let mutation_error = String::from_utf8(mutation.stderr).expect("mutation error is UTF-8");
    assert!(mutation_error.contains("does not match the validated package identity"));
    assert!(mutation_error.contains(BinaryId::digest(&original_binary).as_str()));
    assert!(mutation_error.contains(BinaryId::digest(&mutated_bytes).as_str()));

    let shorter = temp.path().join("shorter.exe");
    fs::write(&shorter, &original_binary[..original_binary.len() - 1])
        .expect("write shorter binary");
    let size_mismatch = run(Command::new(cli())
        .arg("inspect")
        .arg(&package)
        .arg("--binary")
        .arg(&shorter));
    assert!(!size_mismatch.status.success());
    assert!(size_mismatch.stdout.is_empty());
    let size_error = String::from_utf8(size_mismatch.stderr).expect("size error is UTF-8");
    assert!(size_error.contains(&format!("has {} byte(s)", original_binary.len() - 1)));
    assert!(size_error.contains(&format!("describes {} byte(s)", original_binary.len())));

    assert_eq!(
        fs::read(&package).expect("read preserved package"),
        original_package
    );
    assert_eq!(
        fs::read(&binary).expect("read preserved binary"),
        original_binary
    );
}

#[test]
fn invalid_package_fails_before_a_missing_binary_is_opened() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let package = temp.path().join("invalid.resym");
    let missing_binary = temp.path().join("missing.exe");
    fs::write(&package, b"not a package").expect("write invalid package");

    let output = run(Command::new(cli())
        .arg("inspect")
        .arg(&package)
        .arg("--binary")
        .arg(&missing_binary));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).expect("error output is UTF-8");
    assert!(error.contains("cannot read package"));
    assert!(!error.contains("cannot open source binary"));
}
