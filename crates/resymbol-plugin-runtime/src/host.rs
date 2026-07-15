use std::{
    env, fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use resymbol_core::{
    DiscoveredPlugin, PluginSource,
    plugin_api::{PluginManifest, PluginRuntime},
};

use crate::{
    ExternalProcessRequest, PluginExecution, PluginRuntimeError, ProcessDiagnostics, RuntimeLimits,
    StreamKind,
    wire::{encode_input, parse_output},
};

/// Direct, bounded host for one-process-per-request plugins.
#[derive(Debug, Clone, Default)]
pub struct ExternalProcessHost {
    limits: RuntimeLimits,
}

impl ExternalProcessHost {
    pub fn new(limits: RuntimeLimits) -> Result<Self, PluginRuntimeError> {
        limits.validate()?;
        Ok(Self { limits })
    }

    #[must_use]
    pub const fn limits(&self) -> &RuntimeLimits {
        &self.limits
    }

    /// Validate and execute a discovered, explicitly trusted external-process plugin.
    ///
    /// The caller **MUST** verify the plugin ID and exact artifact fingerprint against host-owned
    /// trust state immediately before calling this method. This runtime deliberately cannot infer
    /// that user authorization from discovery health. The entrypoint is passed directly to the
    /// operating system; manifest arguments are never concatenated, interpreted by a shell, or
    /// reparsed.
    pub fn execute_trusted(
        &self,
        plugin: &DiscoveredPlugin,
        request: &ExternalProcessRequest,
    ) -> Result<PluginExecution, PluginRuntimeError> {
        self.limits.validate()?;
        request.validate()?;
        let manifest = validate_plugin(plugin, request)?;
        let (entrypoint, plugin_root) = resolve_entrypoint(&plugin.path, manifest)?;
        let args = match &manifest.runtime {
            PluginRuntime::ExternalProcess { args, .. } => args,
            runtime => {
                return Err(PluginRuntimeError::UnsupportedRuntime(runtime.kind()));
            }
        };
        let input = encode_input(manifest, request, &self.limits)?;
        let deadline = Instant::now()
            .checked_add(self.limits.request_timeout)
            .ok_or(PluginRuntimeError::InvalidLimits(
                "request_timeout is too large for the platform clock",
            ))?;

        let mut command = Command::new(entrypoint);
        command
            .args(args)
            .current_dir(plugin_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        preserve_operating_system_environment(&mut command);

        let child = command.spawn().map_err(|source| PluginRuntimeError::Io {
            operation: "launch plugin entrypoint",
            source,
        })?;
        run_child(child, input, manifest, request, &self.limits, deadline)
    }
}

fn validate_plugin<'a>(
    plugin: &'a DiscoveredPlugin,
    request: &ExternalProcessRequest,
) -> Result<&'a PluginManifest, PluginRuntimeError> {
    if plugin.source != PluginSource::Directory {
        return Err(PluginRuntimeError::UnsupportedPluginSource);
    }
    let manifest = plugin
        .manifest
        .as_ref()
        .ok_or(PluginRuntimeError::MissingManifest)?;
    if !plugin.is_loadable() {
        return Err(PluginRuntimeError::PluginNotLoadable(format!(
            "{:?}",
            plugin.health.state
        )));
    }
    manifest
        .validate()
        .map_err(|error| PluginRuntimeError::InvalidManifest(error.to_string()))?;
    if !matches!(&manifest.runtime, PluginRuntime::ExternalProcess { .. }) {
        return Err(PluginRuntimeError::UnsupportedRuntime(
            manifest.runtime.kind(),
        ));
    }
    for permission in request.granted_permissions() {
        if !manifest.permissions.contains(permission) {
            return Err(PluginRuntimeError::PermissionNotRequested(
                permission.to_string(),
            ));
        }
    }
    Ok(manifest)
}

fn resolve_entrypoint(
    plugin_path: &Path,
    manifest: &PluginManifest,
) -> Result<(PathBuf, PathBuf), PluginRuntimeError> {
    let root_metadata =
        fs::symlink_metadata(plugin_path).map_err(|source| PluginRuntimeError::Io {
            operation: "inspect plugin directory",
            source,
        })?;
    if root_metadata.file_type().is_symlink() {
        return Err(PluginRuntimeError::LinkedEntrypoint);
    }
    if !root_metadata.is_dir() {
        return Err(PluginRuntimeError::EntrypointOutsidePlugin);
    }
    let canonical_root =
        fs::canonicalize(plugin_path).map_err(|source| PluginRuntimeError::Io {
            operation: "resolve plugin directory",
            source,
        })?;

    let mut candidate = plugin_path.to_path_buf();
    for component in manifest.runtime.entrypoint().components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(component) => candidate.push(component),
            _ => return Err(PluginRuntimeError::EntrypointOutsidePlugin),
        }
        let metadata =
            fs::symlink_metadata(&candidate).map_err(|source| PluginRuntimeError::Io {
                operation: "inspect plugin entrypoint",
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(PluginRuntimeError::LinkedEntrypoint);
        }
    }

    let metadata = fs::metadata(&candidate).map_err(|source| PluginRuntimeError::Io {
        operation: "inspect plugin entrypoint",
        source,
    })?;
    if !metadata.is_file() {
        return Err(PluginRuntimeError::EntrypointNotFile);
    }
    let canonical_entrypoint =
        fs::canonicalize(candidate).map_err(|source| PluginRuntimeError::Io {
            operation: "resolve plugin entrypoint",
            source,
        })?;
    if !canonical_entrypoint.starts_with(&canonical_root) {
        return Err(PluginRuntimeError::EntrypointOutsidePlugin);
    }
    Ok((canonical_entrypoint, canonical_root))
}

pub(crate) fn preserve_operating_system_environment(command: &mut Command) {
    // These variables can be required by Windows process initialization and
    // temporary-directory APIs. User credentials and arbitrary host variables
    // are deliberately not inherited.
    for name in ["SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _kill_result = self.child.kill();
        let _wait_result = self.child.wait();
    }
}

enum CaptureFailure {
    Limit(Vec<u8>),
    Io(io::Error),
}

enum WorkerMessage {
    Stdin(io::Result<()>),
    Stdout(Result<Vec<u8>, CaptureFailure>),
    Stderr(Result<Vec<u8>, CaptureFailure>),
}

#[derive(Clone, Copy)]
enum CaptureStream {
    Stdout,
    Stderr,
}

/// Raw stderr observed so far, independent of pipe EOF.
///
/// A timed-out plugin can leave a descendant holding the pipe open. Keeping a
/// bounded live prefix lets native-host framing remain observable even when
/// the final stderr worker result cannot arrive during cleanup.
#[derive(Clone, Default)]
struct ObservedStderr {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl ObservedStderr {
    fn append(&self, bytes: &[u8]) {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
    }

    fn snapshot(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[derive(Default)]
struct WorkerResults {
    stdin: Option<io::Result<()>>,
    stdout: Option<Result<Vec<u8>, CaptureFailure>>,
    stderr: Option<Result<Vec<u8>, CaptureFailure>>,
}

impl WorkerResults {
    fn record(&mut self, message: WorkerMessage) {
        match message {
            WorkerMessage::Stdin(result) => self.stdin = Some(result),
            WorkerMessage::Stdout(result) => self.stdout = Some(result),
            WorkerMessage::Stderr(result) => self.stderr = Some(result),
        }
    }

    fn is_complete(&self) -> bool {
        self.stdin.is_some() && self.stdout.is_some() && self.stderr.is_some()
    }

    fn has_capture_failure(&self) -> bool {
        self.stdout.as_ref().is_some_and(Result::is_err)
            || self.stderr.as_ref().is_some_and(Result::is_err)
    }
}

enum AwaitOutcome {
    Complete {
        status: ExitStatus,
        workers: WorkerResults,
    },
    Deadline {
        workers: WorkerResults,
    },
}

pub(crate) fn run_child(
    child: Child,
    input: Vec<u8>,
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    limits: &RuntimeLimits,
    deadline: Instant,
) -> Result<PluginExecution, PluginRuntimeError> {
    run_child_observing_stderr(child, input, manifest, request, limits, deadline).0
}

/// Run one child while retaining the bounded raw stderr prefix independently
/// from the structured result. Native-host stage framing must survive result
/// variants that do not themselves carry [`ProcessDiagnostics`].
pub(crate) fn run_child_observing_stderr(
    child: Child,
    input: Vec<u8>,
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    limits: &RuntimeLimits,
    deadline: Instant,
) -> (Result<PluginExecution, PluginRuntimeError>, Vec<u8>) {
    let observed_stderr = ObservedStderr::default();
    let result = run_child_inner(
        child,
        input,
        manifest,
        request,
        limits,
        deadline,
        &observed_stderr,
    );
    (result, observed_stderr.snapshot())
}

fn run_child_inner(
    child: Child,
    input: Vec<u8>,
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    limits: &RuntimeLimits,
    deadline: Instant,
    observed_stderr: &ObservedStderr,
) -> Result<PluginExecution, PluginRuntimeError> {
    let mut guard = ChildGuard { child };
    let stdin = guard
        .child
        .stdin
        .take()
        .expect("stdin was configured as piped");
    let stdout = guard
        .child
        .stdout
        .take()
        .expect("stdout was configured as piped");
    let stderr = guard
        .child
        .stderr
        .take()
        .expect("stderr was configured as piped");

    let (result_sender, result_receiver) = mpsc::channel();
    spawn_stdin_worker(stdin, input, result_sender.clone());
    spawn_capture_worker(
        stdout,
        limits.max_stdout_bytes,
        CaptureStream::Stdout,
        None,
        result_sender.clone(),
    );
    spawn_capture_worker(
        stderr,
        limits.max_stderr_bytes,
        CaptureStream::Stderr,
        Some(observed_stderr.clone()),
        result_sender,
    );

    let (status, mut workers) =
        match await_child_and_workers(&mut guard.child, deadline, &result_receiver)? {
            AwaitOutcome::Complete { status, workers } => (status, workers),
            AwaitOutcome::Deadline { workers } => {
                return Err(PluginRuntimeError::Timeout {
                    timeout: limits.request_timeout,
                    diagnostics: diagnostics_from_results(&workers, observed_stderr),
                });
            }
        };
    let stdin_result = workers.stdin.take().expect("complete worker results");
    let stdout_result = workers.stdout.take().expect("complete worker results");
    let stderr_result = workers.stderr.take().expect("complete worker results");
    let diagnostics = diagnostics_from_capture(&stderr_result, observed_stderr);
    match stderr_result {
        Ok(_) => {}
        Err(CaptureFailure::Limit(_)) => {
            return Err(PluginRuntimeError::StreamLimit {
                stream: StreamKind::Stderr,
                limit: limits.max_stderr_bytes,
                diagnostics,
            });
        }
        Err(CaptureFailure::Io(source)) => {
            return Err(PluginRuntimeError::Io {
                operation: "read plugin stderr",
                source,
            });
        }
    }
    let stdout = match stdout_result {
        Ok(stdout) => stdout,
        Err(CaptureFailure::Io(source)) => {
            return Err(PluginRuntimeError::Io {
                operation: "read plugin stdout",
                source,
            });
        }
        Err(CaptureFailure::Limit(_)) => {
            return Err(PluginRuntimeError::StreamLimit {
                stream: StreamKind::Stdout,
                limit: limits.max_stdout_bytes,
                diagnostics,
            });
        }
    };
    validate_child_completion(status, stdin_result, diagnostics.clone())?;

    parse_output(
        &stdout,
        manifest,
        request,
        limits,
        diagnostics,
        status.code(),
    )
}

fn validate_child_completion(
    status: ExitStatus,
    stdin_result: io::Result<()>,
    diagnostics: ProcessDiagnostics,
) -> Result<(), PluginRuntimeError> {
    // A helper can reject bounded input and exit before the writer finishes.
    // Preserve its stage-aware exit code instead of replacing it with the
    // resulting BrokenPipe. A stdin failure remains host-side when the child
    // itself reported success.
    if !status.success() {
        return Err(PluginRuntimeError::ProcessFailed {
            code: status.code(),
            diagnostics,
        });
    }
    stdin_result.map_err(|source| PluginRuntimeError::Io {
        operation: "write plugin stdin",
        source,
    })
}

fn spawn_stdin_worker(
    mut stdin: impl Write + Send + 'static,
    input: Vec<u8>,
    result_sender: mpsc::Sender<WorkerMessage>,
) {
    let _worker = thread::spawn(move || {
        let result = stdin.write_all(&input).and_then(|()| stdin.flush());
        drop(stdin);
        let _send_result = result_sender.send(WorkerMessage::Stdin(result));
    });
}

fn spawn_capture_worker(
    reader: impl Read + Send + 'static,
    limit: usize,
    stream: CaptureStream,
    observed_stderr: Option<ObservedStderr>,
    result_sender: mpsc::Sender<WorkerMessage>,
) {
    let _worker = thread::spawn(move || {
        let result = match observed_stderr.as_ref() {
            Some(observed) => read_bounded_observed(reader, limit, Some(observed)),
            None => read_bounded(reader, limit),
        };
        let message = match stream {
            CaptureStream::Stdout => WorkerMessage::Stdout(result),
            CaptureStream::Stderr => WorkerMessage::Stderr(result),
        };
        let _send_result = result_sender.send(message);
    });
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, CaptureFailure> {
    read_bounded_observed(&mut reader, limit, None)
}

fn read_bounded_observed(
    mut reader: impl Read,
    limit: usize,
    observed: Option<&ObservedStderr>,
) -> Result<Vec<u8>, CaptureFailure> {
    let mut captured = Vec::with_capacity(limit.min(8_192));
    let mut buffer = [0_u8; 8_192];
    loop {
        let count = reader.read(&mut buffer).map_err(CaptureFailure::Io)?;
        if count == 0 {
            return Ok(captured);
        }
        if count > limit.saturating_sub(captured.len()) {
            let remaining = limit.saturating_sub(captured.len());
            captured.extend_from_slice(&buffer[..remaining]);
            if let Some(observed) = observed {
                observed.append(&buffer[..remaining]);
            }
            return Err(CaptureFailure::Limit(captured));
        }
        captured.extend_from_slice(&buffer[..count]);
        if let Some(observed) = observed {
            observed.append(&buffer[..count]);
        }
    }
}

fn await_child_and_workers(
    child: &mut Child,
    deadline: Instant,
    result_receiver: &mpsc::Receiver<WorkerMessage>,
) -> Result<AwaitOutcome, PluginRuntimeError> {
    let mut status = None;
    let mut workers = WorkerResults::default();

    loop {
        while let Ok(message) = result_receiver.try_recv() {
            workers.record(message);
        }
        if status.is_none() {
            status = child.try_wait().map_err(|source| PluginRuntimeError::Io {
                operation: "poll plugin process",
                source,
            })?;
        }
        // Stop immediately for failed/over-limit capture workers, but allow a
        // stdin BrokenPipe to race naturally with the child's bounded exit.
        // Otherwise an early native-host rejection could be killed before its
        // stable 70/71 stage code becomes observable.
        if workers.has_capture_failure() && status.is_none() {
            terminate(child)?;
            status = Some(child.wait().map_err(|source| PluginRuntimeError::Io {
                operation: "reap plugin after I/O failure",
                source,
            })?);
        }
        if workers.is_complete() {
            if let Some(status) = status {
                return Ok(AwaitOutcome::Complete { status, workers });
            }
        }

        let now = Instant::now();
        if now >= deadline {
            if status.is_none() {
                terminate(child)?;
                let _status = child.wait().map_err(|source| PluginRuntimeError::Io {
                    operation: "reap timed-out plugin",
                    source,
                })?;
            }
            drain_worker_results_bounded(&mut workers, result_receiver);
            return Ok(AwaitOutcome::Deadline { workers });
        }

        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(2));
        match result_receiver.recv_timeout(wait) {
            Ok(message) => workers.record(message),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) if workers.is_complete() => {
                thread::sleep(wait);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(PluginRuntimeError::WorkerPanicked("plugin pipe worker"));
            }
        }
    }
}

fn drain_worker_results_bounded(
    workers: &mut WorkerResults,
    result_receiver: &mpsc::Receiver<WorkerMessage>,
) {
    const CLEANUP_GRACE: Duration = Duration::from_millis(50);
    let cleanup_deadline = Instant::now() + CLEANUP_GRACE;
    while !workers.is_complete() {
        while let Ok(message) = result_receiver.try_recv() {
            workers.record(message);
        }
        if workers.is_complete() {
            return;
        }
        let remaining = cleanup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        match result_receiver.recv_timeout(remaining) {
            Ok(message) => workers.record(message),
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn terminate(child: &mut Child) -> Result<(), PluginRuntimeError> {
    match child.kill() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ok(()),
        Err(source) => Err(PluginRuntimeError::Io {
            operation: "terminate plugin process",
            source,
        }),
    }
}

fn diagnostics_from_capture(
    capture: &Result<Vec<u8>, CaptureFailure>,
    observed_stderr: &ObservedStderr,
) -> ProcessDiagnostics {
    match capture {
        Ok(bytes) | Err(CaptureFailure::Limit(bytes)) => ProcessDiagnostics::from_bytes(bytes),
        Err(CaptureFailure::Io(_)) => ProcessDiagnostics::from_bytes(&observed_stderr.snapshot()),
    }
}

fn diagnostics_from_results(
    results: &WorkerResults,
    observed_stderr: &ObservedStderr,
) -> ProcessDiagnostics {
    results.stderr.as_ref().map_or_else(
        || ProcessDiagnostics::from_bytes(&observed_stderr.snapshot()),
        |capture| diagnostics_from_capture(capture, observed_stderr),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn failed_status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;

        ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn failed_status(code: i32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt as _;

        ExitStatus::from_raw(code as u32)
    }

    #[test]
    fn bounded_reader_keeps_only_the_configured_prefix() {
        let error = read_bounded(&b"abcdefgh"[..], 4).expect_err("must exceed limit");
        match error {
            CaptureFailure::Limit(bytes) => assert_eq!(bytes, b"abcd"),
            CaptureFailure::Io(error) => panic!("unexpected I/O error: {error}"),
        }
    }

    #[test]
    fn failed_child_status_takes_precedence_over_stdin_broken_pipe() {
        let diagnostics = ProcessDiagnostics {
            stderr: "stage-aware failure".to_owned(),
            stderr_was_lossy: false,
        };
        let stdin = Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed early"));
        let error = validate_child_completion(failed_status(70), stdin, diagnostics.clone())
            .expect_err("the nonzero child status must be retained");
        assert!(matches!(
            error,
            PluginRuntimeError::ProcessFailed { code: Some(70), .. }
        ));
        assert_eq!(error.diagnostics(), Some(&diagnostics));
    }

    #[test]
    fn timeout_diagnostics_use_raw_stderr_observed_before_pipe_eof() {
        let observed = ObservedStderr::default();
        observed.append(b"flushed marker\npartial plugin detail");
        let diagnostics = diagnostics_from_results(&WorkerResults::default(), &observed);
        assert_eq!(diagnostics.stderr, "flushed marker\npartial plugin detail");
        assert!(!diagnostics.stderr_was_lossy);
    }

    #[test]
    fn deadline_cleanup_records_results_delivered_after_the_worker_snapshot() {
        let (sender, receiver) = mpsc::channel();
        let mut workers = WorkerResults {
            stdin: Some(Ok(())),
            stdout: Some(Ok(Vec::new())),
            stderr: None,
        };
        sender
            .send(WorkerMessage::Stderr(Ok(b"late stderr".to_vec())))
            .unwrap();
        drain_worker_results_bounded(&mut workers, &receiver);
        let diagnostics = diagnostics_from_results(&workers, &ObservedStderr::default());
        assert_eq!(diagnostics.stderr, "late stderr");
    }
}
