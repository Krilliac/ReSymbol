#![cfg(all(windows, feature = "containment-test-fixture"))]
#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    env,
    io::{Read as _, Write as _},
    mem::size_of,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    thread,
    time::Duration,
};

use resymbol_windows_process::{ContainedCommand, Stdio};
use tempfile::TempDir;
use windows_sys::Win32::{
    Foundation::{FALSE, TRUE, WAIT_TIMEOUT},
    Security::SECURITY_ATTRIBUTES,
    System::Threading::{CreateEventW, WaitForSingleObject},
};

const FIXTURE: &str = env!("CARGO_BIN_EXE_resymbol-windows-process-fixture");

#[test]
fn preserves_unicode_command_environment_cwd_and_pipes() {
    let temporary = TempDir::new().expect("create temporary directory");
    let current_directory = temporary.path().join("resymbol-雪");
    std::fs::create_dir(&current_directory).expect("create Unicode current directory");

    let mut command = ContainedCommand::new(FIXTURE);
    command
        .arg("semantics")
        .args([
            "",
            "with space",
            "quote\"inside",
            r"trailing\\",
            "space trailing\\",
            r#"space trailing\\\\"#,
            r#"slashes\\\"quote"#,
            r#"left""right"#,
            "Unicode-雪-λ",
        ])
        .current_dir(&current_directory)
        .env_clear()
        .env("RESYMBOL_UNICODE_VALUE", "value-雪-λ")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(system_root) = env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }

    let mut child = command.spawn().expect("spawn semantics fixture");
    let mut stdin = child.take_stdin().expect("take piped stdin");
    stdin
        .write_all(b"protocol-input")
        .expect("write protocol input");
    drop(stdin);
    let status = child.wait().expect("wait for semantics fixture");
    assert!(status.success(), "semantics fixture exited {status}");

    let mut stdout = String::new();
    child
        .take_stdout()
        .expect("take piped stdout")
        .read_to_string(&mut stdout)
        .expect("read fixture stdout");
    let mut stderr = String::new();
    child
        .take_stderr()
        .expect("take piped stderr")
        .read_to_string(&mut stderr)
        .expect("read fixture stderr");
    assert_eq!(stdout, "stdout-雪");
    assert_eq!(stderr, "stderr-λ");
}

#[test]
fn immediate_grandchild_cannot_escape_kill_on_close_job() {
    let temporary = TempDir::new().expect("create temporary directory");
    let mut markers = Vec::new();
    for attempt in 0..24 {
        let marker = temporary.path().join(format!("survived-{attempt}.marker"));
        let mut command = ContainedCommand::new(FIXTURE);
        command
            .arg("leader")
            .arg(&marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().expect("spawn immediate-descendant leader");
        assert!(
            child.wait().expect("wait for leader").success(),
            "leader could not create its immediate descendant on attempt {attempt}"
        );
        child
            .terminate_tree()
            .expect("explicitly terminate contained Job");
        markers.push(marker);
    }
    thread::sleep(Duration::from_millis(600));
    for (attempt, marker) in markers.iter().enumerate() {
        assert!(
            !marker.exists(),
            "immediate grandchild escaped atomic Job containment on attempt {attempt}"
        );
    }
}

#[test]
fn exact_handle_list_excludes_other_inheritable_handles() {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES size fits u32"),
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: TRUE,
    };
    // SAFETY: `attributes` is initialized and lives for the call. CreateEventW
    // returns one caller-owned real handle on success.
    let sentinel = unsafe { CreateEventW(&raw const attributes, FALSE, FALSE, std::ptr::null()) };
    assert!(!sentinel.is_null(), "create inheritable sentinel event");
    // SAFETY: successful CreateEventW transferred sole ownership of this real handle.
    let sentinel = unsafe { OwnedHandle::from_raw_handle(sentinel) };

    let raw_value = sentinel.as_raw_handle() as usize;
    let mut command = ContainedCommand::new(FIXTURE);
    command
        .arg("signal-handle")
        .arg(raw_value.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn handle probe");
    let status = child.wait().expect("wait for handle probe");
    let mut diagnostics = String::new();
    child
        .take_stderr()
        .expect("take handle-probe stderr")
        .read_to_string(&mut diagnostics)
        .expect("read handle-probe stderr");
    assert!(
        status.success(),
        "child handle-signal fixture failed: {status}: {diagnostics}"
    );
    // SAFETY: `sentinel` remains a live parent-owned event handle. A zero-time
    // wait only observes its signaled state and does not transfer ownership.
    let sentinel_state = unsafe { WaitForSingleObject(sentinel.as_raw_handle(), 0) };
    assert_eq!(
        sentinel_state, WAIT_TIMEOUT,
        "child signaled an inheritable event omitted from HANDLE_LIST"
    );
}

#[test]
fn contained_child_cannot_request_job_breakaway() {
    let mut command = ContainedCommand::new(FIXTURE);
    command
        .arg("attempt-breakaway")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().expect("spawn breakaway probe");
    let status = child.wait().expect("wait for breakaway probe");
    assert!(
        status.success(),
        "contained process could escape with CREATE_BREAKAWAY_FROM_JOB: {status}"
    );
}
