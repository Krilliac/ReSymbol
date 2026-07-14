use std::{
    env, fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
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

fn preserve_operating_system_environment(command: &mut Command) {
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

    fn has_failure(&self) -> bool {
        self.stdin.as_ref().is_some_and(Result::is_err)
            || self.stdout.as_ref().is_some_and(Result::is_err)
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

fn run_child(
    child: Child,
    input: Vec<u8>,
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    limits: &RuntimeLimits,
    deadline: Instant,
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
        result_sender.clone(),
    );
    spawn_capture_worker(
        stderr,
        limits.max_stderr_bytes,
        CaptureStream::Stderr,
        result_sender,
    );

    let (status, mut workers) =
        match await_child_and_workers(&mut guard.child, deadline, &result_receiver)? {
            AwaitOutcome::Complete { status, workers } => (status, workers),
            AwaitOutcome::Deadline { workers } => {
                return Err(PluginRuntimeError::Timeout {
                    timeout: limits.request_timeout,
                    diagnostics: diagnostics_from_results(&workers),
                });
            }
        };
    let stdin_result = workers.stdin.take().expect("complete worker results");
    let stdout_result = workers.stdout.take().expect("complete worker results");
    let stderr_result = workers.stderr.take().expect("complete worker results");
    let diagnostics = diagnostics_from_capture(&stderr_result);
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
    if let Err(source) = stdin_result {
        return Err(PluginRuntimeError::Io {
            operation: "write plugin stdin",
            source,
        });
    }
    if !status.success() {
        return Err(PluginRuntimeError::ProcessFailed {
            code: status.code(),
            diagnostics,
        });
    }

    parse_output(
        &stdout,
        manifest,
        request,
        limits,
        diagnostics,
        status.code(),
    )
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
    result_sender: mpsc::Sender<WorkerMessage>,
) {
    let _worker = thread::spawn(move || {
        let result = read_bounded(reader, limit);
        let message = match stream {
            CaptureStream::Stdout => WorkerMessage::Stdout(result),
            CaptureStream::Stderr => WorkerMessage::Stderr(result),
        };
        let _send_result = result_sender.send(message);
    });
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, CaptureFailure> {
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
            return Err(CaptureFailure::Limit(captured));
        }
        captured.extend_from_slice(&buffer[..count]);
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
        if workers.has_failure() && status.is_none() {
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

fn diagnostics_from_capture(capture: &Result<Vec<u8>, CaptureFailure>) -> ProcessDiagnostics {
    match capture {
        Ok(bytes) | Err(CaptureFailure::Limit(bytes)) => ProcessDiagnostics::from_bytes(bytes),
        Err(CaptureFailure::Io(_)) => ProcessDiagnostics::default(),
    }
}

fn diagnostics_from_results(results: &WorkerResults) -> ProcessDiagnostics {
    results
        .stderr
        .as_ref()
        .map_or_else(ProcessDiagnostics::default, diagnostics_from_capture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_keeps_only_the_configured_prefix() {
        let error = read_bounded(&b"abcdefgh"[..], 4).expect_err("must exceed limit");
        match error {
            CaptureFailure::Limit(bytes) => assert_eq!(bytes, b"abcd"),
            CaptureFailure::Io(error) => panic!("unexpected I/O error: {error}"),
        }
    }
}
