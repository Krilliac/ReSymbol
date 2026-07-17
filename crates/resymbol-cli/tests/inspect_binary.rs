use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use resymbol_core::BinaryId;
use resymbol_package::CURRENT_SCHEMA_VERSION;
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

fn pdb_fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pe-x64-msvc/artifacts/milestone2-symbolized.exe")
        .canonicalize()
        .expect("canonical symbolized MSVC fixture")
}

fn run(command: &mut Command) -> std::process::Output {
    command.output().expect("launch ReSymbol CLI")
}

fn assert_no_export_staging_files(root: &Path) {
    assert!(
        fs::read_dir(root)
            .expect("read export directory")
            .all(|entry| !entry
                .expect("read export directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".resymbol-export-")),
        "dry-run export must not create staging files"
    );
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
    assert_eq!(
        document["schema_version"],
        u64::from(CURRENT_SCHEMA_VERSION)
    );
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
fn export_summarizes_both_loss_domains_and_strict_mode_creates_no_output() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let binary = fixture_binary();
    let package = temp.path().join("loss-policy.resym");
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
        "analysis failed: {}",
        String::from_utf8_lossy(&analyzed.stderr)
    );

    let json_output = temp.path().join("symbols.json");
    let exported = run(Command::new(cli())
        .arg("export")
        .arg(&package)
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&json_output));
    assert!(
        exported.status.success(),
        "JSON export failed: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let stdout = String::from_utf8(exported.stdout).expect("export stdout is UTF-8");
    assert!(stdout.contains("neutral warnings:"));
    assert!(stdout.contains("target loss: 0 item(s), 0 occurrence(s)"));
    assert!(json_output.is_file());

    let strict_output = temp.path().join("strict.map");
    let rejected = run(Command::new(cli())
        .arg("export")
        .arg(&package)
        .arg("--format")
        .arg("map")
        .arg("--output")
        .arg(&strict_output)
        .arg("--dry-run")
        .arg("--fail-on-loss"));
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let stderr = String::from_utf8(rejected.stderr).expect("export stderr is UTF-8");
    assert!(stderr.contains("--fail-on-loss rejected export"));
    assert!(stderr.contains("neutral warnings:"));
    assert!(stderr.contains("target loss:"));
    assert!(!strict_output.exists());
    assert!(
        fs::read_dir(temp.path())
            .expect("read export directory")
            .all(|entry| !entry
                .expect("read export directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".resymbol-export-"))
    );
}

#[test]
fn export_dry_run_validates_every_format_without_publishing() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let binary = pdb_fixture_binary();
    let package = temp.path().join("dry-run.resym");
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

    for (format, filename, needs_binary) in [
        ("json", "Preview.symbols.json", false),
        ("markdown", "Preview.symbols.md", false),
        ("map", "Preview.map", false),
        ("pdb", "Preview.pdb", true),
        ("ida-python", "Preview.ida.py", false),
        ("ghidra-java", "PreviewSymbols.java", false),
    ] {
        let destination = temp.path().join(filename);
        let mut command = Command::new(cli());
        command
            .arg("export")
            .arg(&package)
            .arg("--format")
            .arg(format)
            .arg("--output")
            .arg(&destination)
            .arg("--dry-run");
        if needs_binary {
            command.arg("--binary").arg(&binary);
        }

        let result = run(&mut command);
        assert!(
            result.status.success(),
            "{format} dry run failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stderr.is_empty(), "{format} dry run wrote stderr");
        let stdout = String::from_utf8(result.stdout).expect("dry-run stdout is UTF-8");
        assert!(stdout.contains("mode: dry run (rendered and validated; destination not written)"));
        assert!(stdout.contains(&format!("output: {} (not written)", destination.display())));
        assert!(stdout.contains("neutral warnings:"));
        assert!(stdout.contains("target loss:"));
        assert!(
            !destination.exists(),
            "{format} dry run created {}",
            destination.display()
        );
        assert_no_export_staging_files(temp.path());
    }

    let missing_source = temp.path().join("missing-source.pdb");
    let missing = run(Command::new(cli())
        .arg("export")
        .arg(&package)
        .arg("--format")
        .arg("pdb")
        .arg("--output")
        .arg(&missing_source)
        .arg("--dry-run"));
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert!(
        String::from_utf8(missing.stderr)
            .expect("missing-source error is UTF-8")
            .contains("--binary <EXACT_ORIGINAL_PE>")
    );
    assert!(!missing_source.exists());

    let wrong_binary = temp.path().join("wrong.exe");
    let mut wrong_bytes = fs::read(&binary).expect("read symbolized fixture");
    *wrong_bytes.last_mut().expect("fixture is non-empty") ^= 1;
    fs::write(&wrong_binary, wrong_bytes).expect("write mismatched binary");
    let mismatched_output = temp.path().join("mismatched.pdb");
    let mismatched = run(Command::new(cli())
        .arg("export")
        .arg(&package)
        .arg("--format")
        .arg("pdb")
        .arg("--binary")
        .arg(&wrong_binary)
        .arg("--output")
        .arg(&mismatched_output)
        .arg("--dry-run"));
    assert!(!mismatched.status.success());
    assert!(mismatched.stdout.is_empty());
    let mismatch_error = String::from_utf8(mismatched.stderr).expect("identity error is UTF-8");
    assert!(mismatch_error.contains("SHA-256"));
    assert!(!mismatched_output.exists());

    let invalid_java = temp.path().join("123-invalid.java");
    let invalid_renderer = run(Command::new(cli())
        .arg("export")
        .arg(&package)
        .arg("--format")
        .arg("ghidra-java")
        .arg("--output")
        .arg(&invalid_java)
        .arg("--dry-run"));
    assert!(!invalid_renderer.status.success());
    assert!(invalid_renderer.stdout.is_empty());
    let renderer_error =
        String::from_utf8(invalid_renderer.stderr).expect("renderer error is UTF-8");
    assert!(renderer_error.contains("conservative Java identifier"));
    assert!(!invalid_java.exists());
    assert_no_export_staging_files(temp.path());
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

    let export_path = temp.path().join("invalid.symbols.json");
    let dry_run = run(Command::new(cli())
        .arg("export")
        .arg(&package)
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&export_path)
        .arg("--dry-run"));
    assert!(!dry_run.status.success());
    assert!(dry_run.stdout.is_empty());
    let dry_run_error = String::from_utf8(dry_run.stderr).expect("dry-run package error is UTF-8");
    assert!(dry_run_error.contains("cannot read package"));
    assert!(!export_path.exists());
    assert_no_export_staging_files(temp.path());
}
