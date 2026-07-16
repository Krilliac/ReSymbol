//! Cross-platform child-process tree containment.
//!
//! Unix children become leaders of a fresh process group before `exec`, so a
//! single signal can terminate the leader and all descendants that remain in
//! that group. Linux and macOS observe natural leader exit without reaping,
//! keeping its process-group identifier reserved while group termination is
//! attempted. XNU's zombie-only `EPERM` exception is resolved by relinquishing
//! destructive authority, reaping the leader, and accepting only an `ESRCH`
//! signal-zero proof that the group is absent.
//! Windows children are created atomically inside a preconfigured kill-on-close
//! Job Object. A `STARTUPINFOEX` handle allow-list restricts inheritance to the
//! three configured standard streams; there is no spawn-then-assign fallback.

use std::{ffi::OsStr, io, path::Path, process::ExitStatus};

#[cfg(not(windows))]
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

#[cfg(target_os = "macos")]
use kqueue::{Event, EventData, EventFilter, FilterFlag, Ident, Proc, Watcher};
#[cfg(windows)]
use resymbol_windows_process::{
    ContainedChild as PlatformChild, ContainedCommand as PlatformCommand, Stdio as PlatformStdio,
};
#[cfg(target_os = "macos")]
use rustix::process::test_kill_process_group;
#[cfg(target_os = "linux")]
use rustix::process::{WaitId, WaitIdOptions, waitid};
#[cfg(unix)]
use rustix::{
    io::Errno,
    process::{Pid, Signal, kill_process_group},
};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(not(windows))]
type PlatformChild = Child;
#[cfg(not(windows))]
type PlatformCommand = Command;
#[cfg(windows)]
type PlatformStdin = std::fs::File;
#[cfg(not(windows))]
type PlatformStdin = ChildStdin;
#[cfg(windows)]
type PlatformStdout = std::fs::File;
#[cfg(not(windows))]
type PlatformStdout = ChildStdout;
#[cfg(windows)]
type PlatformStderr = std::fs::File;
#[cfg(not(windows))]
type PlatformStderr = ChildStderr;

#[cfg(target_os = "macos")]
const MACOS_EXIT_CONFIRMATION_TIMEOUT: Duration = Duration::from_millis(250);

/// Small cross-platform command surface used by contained plugin launches.
///
/// On Unix this delegates to `std::process::Command`. On Windows it records the
/// exact launch inputs needed by the native atomic Job-at-creation boundary.
/// Arbitrary inherited handles and raw command-line fragments are intentionally
/// outside this internal API.
#[derive(Debug)]
pub(crate) struct ContainedCommand {
    inner: PlatformCommand,
}

impl ContainedCommand {
    pub(crate) fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            inner: PlatformCommand::new(program),
        }
    }

    pub(crate) fn arg(&mut self, argument: impl AsRef<OsStr>) -> &mut Self {
        self.inner.arg(argument);
        self
    }

    pub(crate) fn args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(arguments);
        self
    }

    pub(crate) fn current_dir(&mut self, directory: impl AsRef<Path>) -> &mut Self {
        self.inner.current_dir(directory);
        self
    }

    pub(crate) fn env_clear(&mut self) -> &mut Self {
        self.inner.env_clear();
        self
    }

    pub(crate) fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.inner.env(key, value);
        self
    }

    pub(crate) fn piped_standard_io(&mut self) -> &mut Self {
        #[cfg(windows)]
        self.inner
            .stdin(PlatformStdio::piped())
            .stdout(PlatformStdio::piped())
            .stderr(PlatformStdio::piped());
        #[cfg(not(windows))]
        self.inner
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn null_standard_io(&mut self) -> &mut Self {
        self.inner
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        self
    }
}

/// A direct child process whose descendants share an OS containment boundary.
///
/// Waiting and polling report the exit status of the direct child (the process
/// group leader on Unix), not an aggregate status for its descendants.
#[derive(Debug)]
pub(crate) struct ContainedChild {
    child: PlatformChild,
    direct_child_status: Option<ExitStatus>,
    #[cfg(unix)]
    process_group: Option<Pid>,
    #[cfg(target_os = "macos")]
    exit_observation: MacOsExitObservation,
    #[cfg(target_os = "macos")]
    terminal_containment_error: Option<MacOsContainmentError>,
}

impl ContainedChild {
    /// Spawns `command` inside a new process-tree containment boundary.
    pub(crate) fn spawn(command: &mut ContainedCommand) -> io::Result<Self> {
        #[cfg(unix)]
        {
            command.inner.process_group(0);
            let child = command.inner.spawn()?;
            let process_group = Pid::from_child(&child);
            #[cfg(target_os = "macos")]
            let (child, exit_observation) = {
                let mut child = child;
                let exit_observation = match MacOsExitObservation::register(&child) {
                    Ok(observation) => observation,
                    Err(error) => {
                        // The leader is still unreaped here, so its PID continues
                        // to reserve the process-group identifier during cleanup.
                        let termination_error = combine_termination_results(
                            terminate_process_group(process_group),
                            terminate_direct_child(&mut child),
                        )
                        .err();
                        let wait_error = child.wait().err();
                        return Err(macos_exit_watcher_setup_error(
                            error,
                            termination_error,
                            wait_error,
                        ));
                    }
                };
                (child, exit_observation)
            };

            Ok(Self {
                child,
                direct_child_status: None,
                process_group: Some(process_group),
                #[cfg(target_os = "macos")]
                exit_observation,
                #[cfg(target_os = "macos")]
                terminal_containment_error: None,
            })
        }

        #[cfg(windows)]
        {
            let child = command.inner.spawn()?;

            Ok(Self {
                child,
                direct_child_status: None,
            })
        }
    }

    /// Returns the operating-system identifier of the direct child.
    #[cfg(test)]
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    /// Takes ownership of the direct child's piped standard input, if present.
    pub(crate) fn take_stdin(&mut self) -> Option<PlatformStdin> {
        #[cfg(windows)]
        {
            self.child.take_stdin()
        }
        #[cfg(not(windows))]
        {
            self.child.stdin.take()
        }
    }

    /// Takes ownership of the direct child's piped standard output, if present.
    pub(crate) fn take_stdout(&mut self) -> Option<PlatformStdout> {
        #[cfg(windows)]
        {
            self.child.take_stdout()
        }
        #[cfg(not(windows))]
        {
            self.child.stdout.take()
        }
    }

    /// Takes ownership of the direct child's piped standard error, if present.
    pub(crate) fn take_stderr(&mut self) -> Option<PlatformStderr> {
        #[cfg(windows)]
        {
            self.child.take_stderr()
        }
        #[cfg(not(windows))]
        {
            self.child.stderr.take()
        }
    }

    /// Polls the direct child without waiting for descendants.
    ///
    /// Linux uses `waitid(WNOWAIT)` and macOS uses a pre-registered kqueue
    /// `NOTE_EXIT` filter to observe exit without reaping. Both platforms
    /// normally terminate the still-stable containment boundary before collecting
    /// the direct child's status. macOS handles XNU's zombie-only `EPERM` by first
    /// relinquishing destructive authority, reaping, and then requiring an `ESRCH`
    /// absence proof, so a recycled identifier is never signaled destructively.
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        #[cfg(target_os = "macos")]
        self.check_terminal_containment_error()?;

        if let Some(status) = self.direct_child_status {
            return Ok(Some(status));
        }

        #[cfg(target_os = "linux")]
        {
            if !self.observe_direct_child_exit(true)? {
                return Ok(None);
            }
            self.reap_observed_direct_child().map(Some)
        }

        #[cfg(target_os = "macos")]
        {
            if !self.exit_observation.try_observe_exit()? {
                return Ok(None);
            }
            self.reap_observed_direct_child().map(Some)
        }

        #[cfg(any(windows, all(unix, not(any(target_os = "linux", target_os = "macos")))))]
        {
            let status = self.child.try_wait()?;
            self.direct_child_status = status;
            Ok(status)
        }
    }

    /// Waits for and returns the direct child's exit status.
    ///
    /// Linux and macOS retain the exited leader while terminating the containment
    /// boundary. macOS' `EPERM` fallback clears destructive group authority before
    /// reaping and reports an error unless the now-non-destructive probe proves
    /// the group absent.
    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        #[cfg(target_os = "macos")]
        self.check_terminal_containment_error()?;

        if let Some(status) = self.direct_child_status {
            return Ok(status);
        }

        #[cfg(target_os = "linux")]
        {
            self.observe_direct_child_exit(false)?;
            self.reap_observed_direct_child()
        }

        #[cfg(target_os = "macos")]
        {
            self.exit_observation.observe_exit()?;
            self.reap_observed_direct_child()
        }

        #[cfg(any(windows, all(unix, not(any(target_os = "linux", target_os = "macos")))))]
        {
            let status = self.child.wait()?;
            self.direct_child_status = Some(status);
            Ok(status)
        }
    }

    /// Observes direct-child exit without releasing its PID or process-group ID.
    #[cfg(target_os = "linux")]
    fn observe_direct_child_exit(&self, nohang: bool) -> io::Result<bool> {
        let mut options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT;
        if nohang {
            options |= WaitIdOptions::NOHANG;
        }
        loop {
            match waitid(WaitId::Pid(Pid::from_child(&self.child)), options) {
                Ok(status) => return Ok(status.is_some()),
                Err(Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Terminates the still-stable containment boundary, then reaps its leader.
    #[cfg(target_os = "linux")]
    fn reap_observed_direct_child(&mut self) -> io::Result<ExitStatus> {
        self.terminate()?;
        let status = self.child.wait()?;
        self.direct_child_status = Some(status);
        Ok(status)
    }

    /// Resolves XNU's zombie-only process-group `EPERM` without accepting a live descendant.
    #[cfg(target_os = "macos")]
    fn reap_observed_direct_child(&mut self) -> io::Result<ExitStatus> {
        let Some(process_group) = self.process_group else {
            let status = self.child.wait()?;
            self.direct_child_status = Some(status);
            return Ok(status);
        };

        match kill_process_group(process_group, Signal::KILL) {
            Ok(()) | Err(Errno::SRCH) => {
                // Signal delivery succeeded or the group was already absent. Forget the identifier
                // before reaping so no later call can target a recycled process group.
                let _ = self.process_group.take();
                let status = self.child.wait()?;
                self.direct_child_status = Some(status);
                Ok(status)
            }
            Err(Errno::PERM) => {
                // XNU excludes zombie members from process-group signal delivery. A group whose
                // only member is the observed-but-unreaped leader therefore reports EPERM. Clear
                // destructive authority before reaping, then use signal 0 solely to prove absence;
                // a recycled identifier can only produce a safe false failure at that point.
                let _ = self.process_group.take();
                let status = match self.child.wait() {
                    Ok(status) => {
                        self.direct_child_status = Some(status);
                        status
                    }
                    Err(error) => {
                        let error = io::Error::new(
                            error.kind(),
                            format!(
                                "failed to reap the observed macOS process-group leader after kill returned EPERM: {error}"
                            ),
                        );
                        return Err(self.remember_terminal_containment_error(error));
                    }
                };

                if let Err(error) =
                    require_macos_process_group_absent(test_kill_process_group(process_group))
                {
                    let error = io::Error::new(
                        error.kind(),
                        format!(
                            "macOS process-group kill returned EPERM and absence could not be proven for {process_group:?}: {error}"
                        ),
                    );
                    return Err(self.remember_terminal_containment_error(error));
                }
                Ok(status)
            }
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(target_os = "macos")]
    fn check_terminal_containment_error(&self) -> io::Result<()> {
        match &self.terminal_containment_error {
            Some(error) => Err(error.to_io_error()),
            None => Ok(()),
        }
    }

    #[cfg(target_os = "macos")]
    fn remember_terminal_containment_error(&mut self, error: io::Error) -> io::Error {
        let error = MacOsContainmentError::from_io_error(error);
        let returned = error.to_io_error();
        self.terminal_containment_error = Some(error);
        returned
    }

    #[cfg(target_os = "macos")]
    fn terminate_macos_containment_group(&mut self) -> io::Result<()> {
        match self.terminate_containment_group() {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(Errno::PERM.raw_os_error()) => {
                // XNU can expose the zombie-only group result just before the registered kqueue
                // event becomes readable. Wait only at this evidence boundary; a live or
                // inaccessible process still returns the original EPERM after the fixed deadline.
                match self
                    .exit_observation
                    .try_observe_exit_for(MACOS_EXIT_CONFIRMATION_TIMEOUT)
                {
                    Ok(true) => self.reap_observed_direct_child().map(|_| ()),
                    Ok(false) => Err(error),
                    Err(observation_error) => Err(io::Error::new(
                        error.kind(),
                        format!(
                            "{error}; macOS child-exit observation also failed: {observation_error}"
                        ),
                    )),
                }
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(unix)]
    fn terminate_containment_group(&mut self) -> io::Result<()> {
        match self.process_group {
            None => Ok(()),
            Some(process_group) => match terminate_process_group(process_group) {
                Ok(()) => {
                    // Process-group identifiers can eventually be recycled. Forget the group after
                    // a conclusive result so a repeated caller cannot signal an unrelated group.
                    self.process_group = None;
                    Ok(())
                }
                Err(error) => Err(error),
            },
        }
    }

    /// Requests immediate termination of the entire contained process tree.
    ///
    /// Calling this method repeatedly is harmless. It initiates termination but
    /// normally leaves direct-child reaping to [`Self::wait`] or `Drop`. On macOS,
    /// an authoritative `NOTE_EXIT` plus XNU's zombie-only `EPERM` requires reaping
    /// immediately so a signal-zero probe can prove that the group is absent.
    pub(crate) fn terminate(&mut self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        self.check_terminal_containment_error()?;

        #[cfg(all(unix, not(target_os = "macos")))]
        let containment_result = self.terminate_containment_group();

        #[cfg(target_os = "macos")]
        let containment_result = self.terminate_macos_containment_group();

        #[cfg(windows)]
        let containment_result = {
            // Closing the final job handle applies JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
            self.child.terminate_tree()
        };

        // A hostile POSIX leader can join another process group before the
        // deadline. Always target the direct child too, so a successful or
        // already-empty containment-boundary kill cannot make the later wait
        // block indefinitely. This is also a defensive fallback on Windows.
        let child_result = if self.direct_child_status.is_some() {
            Ok(())
        } else {
            terminate_direct_child(&mut self.child)
        };
        combine_termination_results(containment_result, child_result)
    }
}

impl Drop for ContainedChild {
    fn drop(&mut self) {
        let _ = self.terminate();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MacOsContainmentError {
    kind: io::ErrorKind,
    message: String,
}

#[cfg(target_os = "macos")]
impl MacOsContainmentError {
    fn from_io_error(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
enum MacOsExitObservation {
    Watching(MacOsExitWatcher),
    Observed,
}

#[cfg(target_os = "macos")]
impl MacOsExitObservation {
    fn register(child: &Child) -> io::Result<Self> {
        let pid = i32::try_from(child.id()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("child process ID does not fit macOS pid_t: {error}"),
            )
        })?;
        let mut watcher = Watcher::new()
            .map_err(|error| macos_exit_watch_error("create child-exit kqueue", error))?;
        watcher
            .add_pid(pid, EventFilter::EVFILT_PROC, FilterFlag::NOTE_EXIT)
            .map_err(|error| macos_exit_watch_error("configure child-exit filter", error))?;
        match watcher.watch() {
            Ok(()) => Ok(Self::Watching(MacOsExitWatcher { watcher, pid })),
            Err(error) if error.raw_os_error() == Some(Errno::SRCH.raw_os_error()) => {
                // XNU process filters are edge-triggered and cannot attach once
                // exit teardown has removed the child from proc_find(). The
                // unreaped Child still reserves its PID/PGID, so this is a
                // conclusive exit observation rather than an unsafe lookup.
                Ok(Self::Observed)
            }
            Err(error) => Err(macos_exit_watch_error("register child-exit filter", error)),
        }
    }

    fn try_observe_exit(&mut self) -> io::Result<bool> {
        self.try_observe_exit_for(Duration::ZERO)
    }

    fn try_observe_exit_for(&mut self, timeout: Duration) -> io::Result<bool> {
        match self {
            Self::Observed => Ok(true),
            Self::Watching(watcher) => {
                let observed = watcher.try_observe_exit_for(timeout)?;
                if observed {
                    *self = Self::Observed;
                }
                Ok(observed)
            }
        }
    }

    fn observe_exit(&mut self) -> io::Result<()> {
        match self {
            Self::Observed => Ok(()),
            Self::Watching(watcher) => {
                watcher.observe_exit()?;
                *self = Self::Observed;
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MacOsExitWatcher {
    watcher: Watcher,
    pid: i32,
}

#[cfg(target_os = "macos")]
impl MacOsExitWatcher {
    fn try_observe_exit_for(&self, timeout: Duration) -> io::Result<bool> {
        match self.watcher.poll(Some(timeout)) {
            None => Ok(false),
            Some(event) => classify_macos_exit_event(self.pid, event),
        }
    }

    fn observe_exit(&self) -> io::Result<()> {
        loop {
            let event = self.watcher.poll_forever(None).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "macOS child-exit watcher stopped before reporting exit",
                )
            })?;
            if classify_macos_exit_event(self.pid, event)? {
                return Ok(());
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn classify_macos_exit_event(pid: i32, event: Event) -> io::Result<bool> {
    match (event.ident, event.data) {
        (_, EventData::Error(error)) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        (_, EventData::Error(error)) => {
            Err(macos_exit_watch_error("observe child-exit event", error))
        }
        (Ident::Pid(event_pid), EventData::Proc(Proc::Exit(_))) if event_pid == pid => Ok(true),
        (ident, data) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected macOS child-exit event for PID {pid}: {ident:?} {data:?}"),
        )),
    }
}

#[cfg(target_os = "macos")]
fn macos_exit_watch_error(context: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(unix)]
fn terminate_process_group(process_group: Pid) -> io::Result<()> {
    match kill_process_group(process_group, Signal::KILL) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "macos")]
fn require_macos_process_group_absent(result: rustix::io::Result<()>) -> io::Result<()> {
    match result {
        Err(Errno::SRCH) => Ok(()),
        Ok(()) => Err(io::Error::other(
            "process group still exists after its observed leader was reaped",
        )),
        Err(error) => {
            let error: io::Error = error.into();
            Err(io::Error::new(
                error.kind(),
                format!("process-group absence probe failed: {error}"),
            ))
        }
    }
}

fn terminate_direct_child(child: &mut PlatformChild) -> io::Result<()> {
    match child.kill() {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
            ) || cfg!(windows) && error.kind() == io::ErrorKind::PermissionDenied =>
        {
            // Windows TerminateProcess reports access denied when the process
            // has already finished; a child spawned through Command retains a
            // terminate-capable handle for its lifetime.
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn combine_termination_results(
    containment_result: io::Result<()>,
    child_result: io::Result<()>,
) -> io::Result<()> {
    match (containment_result, child_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(containment_error), Err(child_error)) => Err(io::Error::new(
            containment_error.kind(),
            format!("{containment_error}; direct-child termination also failed: {child_error}"),
        )),
    }
}

#[cfg(target_os = "macos")]
fn macos_exit_watcher_setup_error(
    error: io::Error,
    termination_error: Option<io::Error>,
    wait_error: Option<io::Error>,
) -> io::Error {
    let mut message = format!("failed to establish non-reaping child-exit observation: {error}");
    if let Some(error) = termination_error {
        message.push_str(&format!(
            "; child process-tree termination also failed: {error}"
        ));
    }
    if let Some(error) = wait_error {
        message.push_str(&format!("; direct-child reap also failed: {error}"));
    }
    io::Error::new(error.kind(), message)
}

#[cfg(test)]
mod tests {
    use super::{ContainedChild, ContainedCommand};
    #[cfg(target_os = "macos")]
    use super::{classify_macos_exit_event, require_macos_process_group_absent};
    #[cfg(target_os = "macos")]
    use kqueue::{Event, EventData, Ident, Proc};
    #[cfg(target_os = "macos")]
    use rustix::io::Errno;
    use std::io;
    #[cfg(target_os = "macos")]
    use std::thread;
    #[cfg(target_os = "macos")]
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[test]
    fn preserves_direct_leader_status_and_termination_is_idempotent() -> io::Result<()> {
        let mut command = exit_command(23);
        let mut child = ContainedChild::spawn(&mut command)?;
        assert!(child.id() > 0);

        let status = child.wait()?;
        assert_eq!(status.code(), Some(23));
        assert_eq!(child.try_wait()?.and_then(|status| status.code()), Some(23));
        child.terminate()?;
        child.terminate()?;

        Ok(())
    }

    #[test]
    fn takes_each_configured_pipe_once() -> io::Result<()> {
        let mut command = exit_command(0);
        command.piped_standard_io();
        let mut child = ContainedChild::spawn(&mut command)?;

        assert!(child.take_stdin().is_some());
        assert!(child.take_stdin().is_none());
        assert!(child.take_stdout().is_some());
        assert!(child.take_stdout().is_none());
        assert!(child.take_stderr().is_some());
        assert!(child.take_stderr().is_none());
        assert!(child.wait()?.success());

        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_immediate_exit_registration_and_polling_preserve_status() -> io::Result<()> {
        for _ in 0..64 {
            let mut command = exit_command(37);
            let mut child = ContainedChild::spawn(&mut command)?;
            let deadline = Instant::now() + Duration::from_secs(2);

            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "macOS kqueue did not report direct-child exit",
                    ));
                }
                thread::sleep(Duration::from_millis(1));
            };

            assert_eq!(status.code(), Some(37));
            assert_eq!(child.wait()?.code(), Some(37));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_group_absence_requires_esrch() {
        assert!(require_macos_process_group_absent(Err(Errno::SRCH)).is_ok());
        assert!(require_macos_process_group_absent(Ok(())).is_err());
        assert!(require_macos_process_group_absent(Err(Errno::PERM)).is_err());
        assert!(require_macos_process_group_absent(Err(Errno::INVAL)).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_terminal_containment_error_stays_sticky_after_status_is_cached() -> io::Result<()> {
        let mut command = exit_command(0);
        let mut child = ContainedChild::spawn(&mut command)?;
        let _ = child.process_group.take();
        let status = child.child.wait()?;
        child.direct_child_status = Some(status);

        let expected = "synthetic terminal containment failure";
        let first = child.remember_terminal_containment_error(io::Error::new(
            io::ErrorKind::PermissionDenied,
            expected,
        ));
        assert_eq!(first.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(first.to_string(), expected);

        let wait_error = child
            .wait()
            .expect_err("cached status must not mask the error");
        assert_eq!(wait_error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(wait_error.to_string(), expected);
        let poll_error = child
            .try_wait()
            .expect_err("polling must preserve the terminal containment error");
        assert_eq!(poll_error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(poll_error.to_string(), expected);
        let terminate_error = child
            .terminate()
            .expect_err("termination must preserve the terminal containment error");
        assert_eq!(terminate_error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(terminate_error.to_string(), expected);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_terminate_reaps_an_authoritatively_observed_immediate_exit() -> io::Result<()> {
        for _ in 0..64 {
            let mut command = exit_command(41);
            let mut child = ContainedChild::spawn(&mut command)?;
            child.exit_observation.observe_exit()?;

            child.terminate()?;
            assert_eq!(child.wait()?.code(), Some(41));
            child.terminate()?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bounded_exit_confirmation_rejects_a_live_child() -> io::Result<()> {
        let mut command = ContainedCommand::new("sh");
        command.args(["-c", "sleep 1"]);
        let mut child = ContainedChild::spawn(&mut command)?;

        assert!(
            !child
                .exit_observation
                .try_observe_exit_for(Duration::from_millis(25))?
        );
        child.terminate()?;
        let _ = child.wait()?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_observed_leader_exit_kills_live_same_group_descendant() -> io::Result<()> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let marker = std::env::temp_dir().join(format!(
            "resymbol-process-tree-{}-{nonce}.marker",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&marker);

        let mut command = ContainedCommand::new("sh");
        command
            .args([
                "-c",
                "trap '' HUP TERM; (sleep 0.25; printf leaked > \"$1\") & exit 0",
                "resymbol-process-tree",
            ])
            .arg(&marker)
            .null_standard_io();
        let mut child = ContainedChild::spawn(&mut command)?;
        assert!(child.wait()?.success());

        thread::sleep(Duration::from_millis(500));
        let descendant_survived = marker.exists();
        let _ = std::fs::remove_file(&marker);
        assert!(
            !descendant_survived,
            "same-group descendant survived observed-leader cleanup"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_exit_event_classifier_rejects_pid_aliases() -> io::Result<()> {
        let pid = 41;
        assert!(classify_macos_exit_event(
            pid,
            Event {
                ident: Ident::Pid(pid),
                data: EventData::Proc(Proc::Exit(0)),
            },
        )?);

        let interrupted = classify_macos_exit_event(
            pid,
            Event {
                ident: Ident::Fd(-1),
                data: EventData::Error(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "signal interrupted kevent",
                )),
            },
        )?;
        assert!(!interrupted);

        let error = classify_macos_exit_event(
            pid,
            Event {
                ident: Ident::Pid(pid + 1),
                data: EventData::Proc(Proc::Exit(0)),
            },
        )
        .expect_err("a recycled or unrelated PID must not satisfy the watcher");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        Ok(())
    }

    #[cfg(unix)]
    fn exit_command(code: u8) -> ContainedCommand {
        let mut command = ContainedCommand::new("sh");
        command.arg("-c").arg(format!("exit {code}"));
        command
    }

    #[cfg(windows)]
    fn exit_command(code: u8) -> ContainedCommand {
        let command_interpreter = std::env::var_os("COMSPEC")
            .map(std::path::PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| {
                std::env::var_os("SystemRoot")
                    .map(std::path::PathBuf::from)
                    .map(|root| root.join("System32").join("cmd.exe"))
            })
            .expect("Windows tests require an exact command-interpreter path");
        let mut command = ContainedCommand::new(command_interpreter);
        command.args(["/D", "/S", "/C"]).arg(format!("exit {code}"));
        command
    }
}
