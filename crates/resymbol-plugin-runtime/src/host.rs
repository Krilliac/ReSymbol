use std::{
    env, fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::ExitStatus,
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
    process_tree::{ContainedChild, ContainedCommand},
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

        let mut command = ContainedCommand::new(entrypoint);
        command
            .args(args)
            .current_dir(plugin_root)
            .piped_standard_io()
            .env_clear();
        preserve_operating_system_environment(&mut command);

        let child =
            ContainedChild::spawn(&mut command).map_err(|source| PluginRuntimeError::Io {
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

pub(crate) fn resolve_entrypoint(
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

pub(crate) fn preserve_operating_system_environment(command: &mut ContainedCommand) {
    // These variables can be required by Windows process initialization and
    // temporary-directory APIs. User credentials and arbitrary host variables
    // are deliberately not inherited.
    for name in ["SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
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
/// Tree termination and pipe EOF are asynchronous, and a deliberately escaped
/// descendant can still retain an inherited handle. Keeping a bounded live
/// prefix lets native-host framing remain observable even when the final stderr
/// worker result cannot arrive during the cleanup grace period.
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

trait ChildLifecycle {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;
    fn wait(&mut self) -> io::Result<ExitStatus>;
    fn terminate(&mut self) -> io::Result<()>;
}

impl ChildLifecycle for ContainedChild {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        ContainedChild::try_wait(self)
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        ContainedChild::wait(self)
    }

    fn terminate(&mut self) -> io::Result<()> {
        ContainedChild::terminate(self)
    }
}

pub(crate) fn run_child(
    child: ContainedChild,
    input: Vec<u8>,
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    limits: &RuntimeLimits,
    deadline: Instant,
) -> Result<PluginExecution, PluginRuntimeError> {
    run_child_observing_stderr(child, input, manifest, request, limits, deadline).0
}

/// Run one child while retaining the bounded raw stderr prefix independently
/// from the structured result. Native and managed marker attribution needs the
/// raw prefix before runtime-specific cleanup mutates [`ProcessDiagnostics`].
pub(crate) fn run_child_observing_stderr(
    child: ContainedChild,
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
    mut child: ContainedChild,
    input: Vec<u8>,
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    limits: &RuntimeLimits,
    deadline: Instant,
    observed_stderr: &ObservedStderr,
) -> Result<PluginExecution, PluginRuntimeError> {
    let stdin = child.take_stdin().expect("stdin was configured as piped");
    let stdout = child.take_stdout().expect("stdout was configured as piped");
    let stderr = child.take_stderr().expect("stderr was configured as piped");

    let (result_sender, result_receiver) = mpsc::channel();
    // Install both bounded readers before delivering stdin. Native and managed
    // helpers treat stdin as their execution gate, so a reader-start failure
    // cannot occur after the helper has emitted its load-attempted marker.
    spawn_capture_worker(
        stderr,
        limits.max_stderr_bytes,
        CaptureStream::Stderr,
        Some(observed_stderr.clone()),
        result_sender.clone(),
    )
    .map_err(|source| {
        process_io_from_observed("start plugin stderr worker", source, observed_stderr)
    })?;
    spawn_capture_worker(
        stdout,
        limits.max_stdout_bytes,
        CaptureStream::Stdout,
        None,
        result_sender.clone(),
    )
    .map_err(|source| {
        process_io_from_observed("start plugin stdout worker", source, observed_stderr)
    })?;
    spawn_stdin_worker(stdin, input, result_sender).map_err(|source| {
        process_io_from_observed("start plugin stdin worker", source, observed_stderr)
    })?;

    let (status, mut workers) =
        match await_child_and_workers(&mut child, deadline, &result_receiver, observed_stderr)? {
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
            return Err(process_io_error("read plugin stderr", source, diagnostics));
        }
    }
    let stdout = match stdout_result {
        Ok(stdout) => stdout,
        Err(CaptureFailure::Io(source)) => {
            return Err(process_io_error("read plugin stdout", source, diagnostics));
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
    stdin_result.map_err(|source| process_io_error("write plugin stdin", source, diagnostics))
}

fn spawn_stdin_worker(
    mut stdin: impl Write + Send + 'static,
    input: Vec<u8>,
    result_sender: mpsc::Sender<WorkerMessage>,
) -> io::Result<()> {
    let worker = thread::Builder::new()
        .name("resymbol-stdin".to_owned())
        .spawn(move || {
            let result = stdin.write_all(&input).and_then(|()| stdin.flush());
            drop(stdin);
            let _send_result = result_sender.send(WorkerMessage::Stdin(result));
        })?;
    drop(worker);
    Ok(())
}

fn spawn_capture_worker(
    reader: impl Read + Send + 'static,
    limit: usize,
    stream: CaptureStream,
    observed_stderr: Option<ObservedStderr>,
    result_sender: mpsc::Sender<WorkerMessage>,
) -> io::Result<()> {
    let worker_name = match stream {
        CaptureStream::Stdout => "resymbol-stdout",
        CaptureStream::Stderr => "resymbol-stderr",
    };
    let worker = thread::Builder::new()
        .name(worker_name.to_owned())
        .spawn(move || {
            let result = match observed_stderr.as_ref() {
                Some(observed) => read_bounded_observed(reader, limit, Some(observed)),
                None => read_bounded(reader, limit),
            };
            let message = match stream {
                CaptureStream::Stdout => WorkerMessage::Stdout(result),
                CaptureStream::Stderr => WorkerMessage::Stderr(result),
            };
            let _send_result = result_sender.send(message);
        })?;
    drop(worker);
    Ok(())
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
    child: &mut impl ChildLifecycle,
    deadline: Instant,
    result_receiver: &mpsc::Receiver<WorkerMessage>,
    observed_stderr: &ObservedStderr,
) -> Result<AwaitOutcome, PluginRuntimeError> {
    let mut status = None;
    let mut workers = WorkerResults::default();

    loop {
        let workers_disconnected = drain_available_worker_results(&mut workers, result_receiver);
        if workers_disconnected && !workers.is_complete() {
            return Err(process_worker_panicked(
                "plugin pipe worker",
                &workers,
                observed_stderr,
            ));
        }
        if status.is_none() {
            status = child.try_wait().map_err(|source| {
                process_io_from_results("poll plugin process", source, &workers, observed_stderr)
            })?;
            if status.is_some() {
                // Pipe EOF is not a reliable direct-child completion signal:
                // descendants may inherit the handles. Tear down the owned
                // tree as soon as the direct leader exits so workers can
                // finish without consuming the invocation deadline.
                terminate(child).map_err(|source| {
                    process_io_from_results(
                        "terminate plugin process tree",
                        source,
                        &workers,
                        observed_stderr,
                    )
                })?;
            }
        }
        // Stop immediately for failed/over-limit capture workers, but allow a
        // stdin BrokenPipe to race naturally with the child's bounded exit.
        // Otherwise an early native-host rejection could be killed before its
        // stable 70/71 stage code becomes observable.
        if workers.has_capture_failure() && status.is_none() {
            terminate(child).map_err(|source| {
                process_io_from_results(
                    "terminate plugin process tree",
                    source,
                    &workers,
                    observed_stderr,
                )
            })?;
            status = Some(child.wait().map_err(|source| {
                process_io_from_results(
                    "reap plugin after I/O failure",
                    source,
                    &workers,
                    observed_stderr,
                )
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
                terminate(child).map_err(|source| {
                    process_io_from_results(
                        "terminate plugin process tree",
                        source,
                        &workers,
                        observed_stderr,
                    )
                })?;
                let _status = child.wait().map_err(|source| {
                    process_io_from_results(
                        "reap timed-out plugin",
                        source,
                        &workers,
                        observed_stderr,
                    )
                })?;
            }
            let workers_disconnected = drain_worker_results_bounded(&mut workers, result_receiver);
            if workers_disconnected && !workers.is_complete() {
                return Err(process_worker_panicked(
                    "plugin pipe worker",
                    &workers,
                    observed_stderr,
                ));
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
                return Err(process_worker_panicked(
                    "plugin pipe worker",
                    &workers,
                    observed_stderr,
                ));
            }
        }
    }
}

fn drain_available_worker_results(
    workers: &mut WorkerResults,
    result_receiver: &mpsc::Receiver<WorkerMessage>,
) -> bool {
    loop {
        match result_receiver.try_recv() {
            Ok(message) => workers.record(message),
            Err(mpsc::TryRecvError::Empty) => return false,
            Err(mpsc::TryRecvError::Disconnected) => return true,
        }
    }
}

fn drain_worker_results_bounded(
    workers: &mut WorkerResults,
    result_receiver: &mpsc::Receiver<WorkerMessage>,
) -> bool {
    const CLEANUP_GRACE: Duration = Duration::from_millis(50);
    let cleanup_deadline = Instant::now() + CLEANUP_GRACE;
    while !workers.is_complete() {
        if drain_available_worker_results(workers, result_receiver) {
            return true;
        }
        if workers.is_complete() {
            return false;
        }
        let remaining = cleanup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match result_receiver.recv_timeout(remaining) {
            Ok(message) => workers.record(message),
            Err(mpsc::RecvTimeoutError::Timeout) => return false,
            Err(mpsc::RecvTimeoutError::Disconnected) => return true,
        }
    }
    false
}

fn terminate(child: &mut impl ChildLifecycle) -> io::Result<()> {
    match child.terminate() {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
            ) =>
        {
            Ok(())
        }
        Err(source) => Err(source),
    }
}

fn process_io_error(
    operation: &'static str,
    source: io::Error,
    diagnostics: ProcessDiagnostics,
) -> PluginRuntimeError {
    PluginRuntimeError::ProcessIo {
        operation,
        source,
        diagnostics,
    }
}

fn process_io_from_results(
    operation: &'static str,
    source: io::Error,
    results: &WorkerResults,
    observed_stderr: &ObservedStderr,
) -> PluginRuntimeError {
    process_io_error(
        operation,
        source,
        diagnostics_from_results(results, observed_stderr),
    )
}

fn process_io_from_observed(
    operation: &'static str,
    source: io::Error,
    observed_stderr: &ObservedStderr,
) -> PluginRuntimeError {
    process_io_error(
        operation,
        source,
        ProcessDiagnostics::from_bytes(&observed_stderr.snapshot()),
    )
}

fn process_worker_panicked(
    worker: &'static str,
    results: &WorkerResults,
    observed_stderr: &ObservedStderr,
) -> PluginRuntimeError {
    PluginRuntimeError::ProcessWorkerPanicked {
        worker,
        diagnostics: diagnostics_from_results(results, observed_stderr),
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
    use std::collections::VecDeque;

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

    #[cfg(unix)]
    fn successful_status() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;

        ExitStatus::from_raw(0)
    }

    #[cfg(windows)]
    fn successful_status() -> ExitStatus {
        use std::os::windows::process::ExitStatusExt as _;

        ExitStatus::from_raw(0)
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected read failure"))
        }
    }

    #[derive(Default)]
    struct ScriptedChild {
        polls: VecDeque<io::Result<Option<ExitStatus>>>,
        terminations: VecDeque<io::Result<()>>,
        waits: VecDeque<io::Result<ExitStatus>>,
    }

    impl ChildLifecycle for ScriptedChild {
        fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            self.polls.pop_front().expect("unexpected child poll")
        }

        fn wait(&mut self) -> io::Result<ExitStatus> {
            self.waits.pop_front().expect("unexpected child wait")
        }

        fn terminate(&mut self) -> io::Result<()> {
            self.terminations
                .pop_front()
                .expect("unexpected child termination")
        }
    }

    fn assert_process_io(error: PluginRuntimeError, operation: &'static str, stderr: &str) {
        assert!(matches!(
            error,
            PluginRuntimeError::ProcessIo {
                operation: actual,
                ..
            } if actual == operation
        ));
        assert_eq!(error.diagnostics().unwrap().stderr, stderr);
    }

    fn expect_await_error(
        result: Result<AwaitOutcome, PluginRuntimeError>,
        message: &str,
    ) -> PluginRuntimeError {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
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
    fn successful_child_stdin_failure_retains_diagnostics() {
        let diagnostics = ProcessDiagnostics {
            stderr: "plugin completed before reading input".to_owned(),
            stderr_was_lossy: false,
        };
        let stdin = Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed early"));
        let error = validate_child_completion(successful_status(), stdin, diagnostics.clone())
            .expect_err("a successful child does not hide its stdin transport failure");
        assert!(matches!(
            error,
            PluginRuntimeError::ProcessIo {
                operation: "write plugin stdin",
                ..
            }
        ));
        assert_eq!(error.diagnostics(), Some(&diagnostics));
    }

    #[test]
    fn stderr_read_failure_retains_the_observed_bounded_prefix() {
        let observed = ObservedStderr::default();
        let reader = io::Cursor::new(b"partial diagnostic".to_vec()).chain(FailingReader);
        let capture = read_bounded_observed(reader, 64, Some(&observed));
        let diagnostics = diagnostics_from_capture(&capture, &observed);
        let CaptureFailure::Io(source) =
            capture.expect_err("the injected reader must fail after its prefix")
        else {
            panic!("unexpected stream limit")
        };
        let error = process_io_error("read plugin stderr", source, diagnostics.clone());
        assert!(matches!(
            error,
            PluginRuntimeError::ProcessIo {
                operation: "read plugin stderr",
                ..
            }
        ));
        assert_eq!(error.diagnostics(), Some(&diagnostics));
        assert_eq!(diagnostics.stderr, "partial diagnostic");
    }

    #[test]
    fn process_poll_and_worker_failures_retain_live_stderr() {
        let observed = ObservedStderr::default();
        observed.append(b"live diagnostic");

        let poll = process_io_from_results(
            "poll plugin process",
            io::Error::other("injected poll failure"),
            &WorkerResults::default(),
            &observed,
        );
        assert!(matches!(poll, PluginRuntimeError::ProcessIo { .. }));
        assert_eq!(poll.diagnostics().unwrap().stderr, "live diagnostic");

        let worker =
            process_worker_panicked("plugin pipe worker", &WorkerResults::default(), &observed);
        assert!(matches!(
            worker,
            PluginRuntimeError::ProcessWorkerPanicked { .. }
        ));
        assert_eq!(worker.diagnostics().unwrap().stderr, "live diagnostic");
    }

    #[test]
    fn await_poll_failure_retains_observed_stderr() {
        let mut child = ScriptedChild::default();
        child
            .polls
            .push_back(Err(io::Error::other("injected poll failure")));
        let (_sender, receiver) = mpsc::channel();
        let observed = ObservedStderr::default();
        observed.append(b"poll diagnostic");

        let error = expect_await_error(
            await_child_and_workers(
                &mut child,
                Instant::now() + Duration::from_secs(1),
                &receiver,
                &observed,
            ),
            "poll failure must escape",
        );
        assert_process_io(error, "poll plugin process", "poll diagnostic");
    }

    #[test]
    fn await_termination_failure_after_direct_exit_retains_observed_stderr() {
        let mut child = ScriptedChild::default();
        child.polls.push_back(Ok(Some(successful_status())));
        child.terminations.push_back(Err(io::Error::other(
            "injected process-tree termination failure",
        )));
        let (_sender, receiver) = mpsc::channel();
        let observed = ObservedStderr::default();
        observed.append(b"termination diagnostic");

        let error = expect_await_error(
            await_child_and_workers(
                &mut child,
                Instant::now() + Duration::from_secs(1),
                &receiver,
                &observed,
            ),
            "termination failure must escape",
        );
        assert_process_io(
            error,
            "terminate plugin process tree",
            "termination diagnostic",
        );
    }

    #[test]
    fn await_reap_failure_after_capture_failure_retains_observed_stderr() {
        let mut child = ScriptedChild::default();
        child.polls.push_back(Ok(None));
        child.terminations.push_back(Ok(()));
        child
            .waits
            .push_back(Err(io::Error::other("injected reap failure")));
        let (sender, receiver) = mpsc::channel();
        sender
            .send(WorkerMessage::Stdout(Err(CaptureFailure::Io(
                io::Error::other("injected stdout read failure"),
            ))))
            .unwrap();
        let observed = ObservedStderr::default();
        observed.append(b"capture diagnostic");

        let error = expect_await_error(
            await_child_and_workers(
                &mut child,
                Instant::now() + Duration::from_secs(1),
                &receiver,
                &observed,
            ),
            "reap failure must escape",
        );
        assert_process_io(error, "reap plugin after I/O failure", "capture diagnostic");
    }

    #[test]
    fn await_reap_failure_after_deadline_retains_observed_stderr() {
        let mut child = ScriptedChild::default();
        child.polls.push_back(Ok(None));
        child.terminations.push_back(Ok(()));
        child
            .waits
            .push_back(Err(io::Error::other("injected timeout reap failure")));
        let (_sender, receiver) = mpsc::channel();
        let observed = ObservedStderr::default();
        observed.append(b"deadline diagnostic");

        let error = expect_await_error(
            await_child_and_workers(&mut child, Instant::now(), &receiver, &observed),
            "deadline reap failure must escape",
        );
        assert_process_io(error, "reap timed-out plugin", "deadline diagnostic");
    }

    #[test]
    fn await_deadline_prefers_disconnected_worker_and_retains_observed_stderr() {
        let mut child = ScriptedChild::default();
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        let observed = ObservedStderr::default();
        observed.append(b"worker diagnostic");

        let error = expect_await_error(
            await_child_and_workers(&mut child, Instant::now(), &receiver, &observed),
            "known worker disconnect must take precedence over the deadline",
        );
        assert!(matches!(
            error,
            PluginRuntimeError::ProcessWorkerPanicked {
                worker: "plugin pipe worker",
                ..
            }
        ));
        assert_eq!(error.diagnostics().unwrap().stderr, "worker diagnostic");
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
        assert!(!drain_worker_results_bounded(&mut workers, &receiver));
        let diagnostics = diagnostics_from_results(&workers, &ObservedStderr::default());
        assert_eq!(diagnostics.stderr, "late stderr");
    }

    #[test]
    fn deadline_cleanup_reports_an_incomplete_worker_disconnect() {
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        let mut workers = WorkerResults::default();

        assert!(drain_worker_results_bounded(&mut workers, &receiver));
        assert!(!workers.is_complete());
    }
}
