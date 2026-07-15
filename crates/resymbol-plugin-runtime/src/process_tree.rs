//! Cross-platform child-process tree containment.
//!
//! Unix children become leaders of a fresh process group before `exec`, so a
//! single signal can terminate the leader and all descendants that remain in
//! that group. Windows children are assigned to a kill-on-close Job Object.
//! Windows' ordinary [`Command::spawn`] API cannot create a process already
//! suspended inside a job, so there is an unavoidable spawn-to-assignment race
//! in which a very short-lived child could create an uncontained descendant.

use std::io;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustix::process::{WaitId, WaitIdOptions, waitid};
#[cfg(unix)]
use rustix::{
    io::Errno,
    process::{Pid, Signal, kill_process_group},
};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use win32job::{ExtendedLimitInfo, Job};

/// A direct child process whose descendants share an OS containment boundary.
///
/// Waiting and polling report the exit status of the direct child (the process
/// group leader on Unix), not an aggregate status for its descendants.
#[derive(Debug)]
pub(crate) struct ContainedChild {
    child: Child,
    direct_child_status: Option<ExitStatus>,
    #[cfg(unix)]
    process_group: Option<Pid>,
    #[cfg(windows)]
    job: Option<Job>,
}

impl ContainedChild {
    /// Spawns `command` inside a new process-tree containment boundary.
    pub(crate) fn spawn(command: &mut Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            command.process_group(0);
            let child = command.spawn()?;
            let process_group = Pid::from_child(&child);

            Ok(Self {
                child,
                direct_child_status: None,
                process_group: Some(process_group),
            })
        }

        #[cfg(windows)]
        {
            let mut limits = ExtendedLimitInfo::new();
            limits.limit_kill_on_job_close();
            let job = Job::create_with_limit_info(&limits)
                .map_err(|error| job_error("failed to create process Job Object", error))?;

            // `Command::spawn` cannot start the child suspended and atomically
            // assign it to the job through safe std APIs. Keep this interval as
            // short as possible; see the module-level race documentation.
            let mut child = command.spawn()?;
            if let Err(error) = job.assign_process(child.as_raw_handle() as isize) {
                let kill_error = child.kill().err();
                let wait_error = child.wait().err();
                return Err(job_assignment_error(error, kill_error, wait_error));
            }

            Ok(Self {
                child,
                direct_child_status: None,
                job: Some(job),
            })
        }
    }

    /// Returns the operating-system identifier of the direct child.
    #[cfg(test)]
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    /// Takes ownership of the direct child's piped standard input, if present.
    pub(crate) fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    /// Takes ownership of the direct child's piped standard output, if present.
    pub(crate) fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    /// Takes ownership of the direct child's piped standard error, if present.
    pub(crate) fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    /// Polls the direct child without waiting for descendants.
    ///
    /// Linux and macOS observe exit without reaping, terminate the still-stable
    /// containment boundary, and only then collect the direct child's status.
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.direct_child_status {
            return Ok(Some(status));
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if !self.observe_direct_child_exit(true)? {
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
    /// Linux and macOS retain the exited child until the containment boundary
    /// has been terminated, preventing process-group identifier reuse.
    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.direct_child_status {
            return Ok(status);
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.observe_direct_child_exit(false)?;
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn reap_observed_direct_child(&mut self) -> io::Result<ExitStatus> {
        self.terminate()?;
        let status = self.child.wait()?;
        self.direct_child_status = Some(status);
        Ok(status)
    }

    /// Requests immediate termination of the entire contained process tree.
    ///
    /// Calling this method repeatedly is harmless. It initiates termination but
    /// deliberately leaves direct-child reaping to [`Self::wait`] or `Drop`.
    pub(crate) fn terminate(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        let containment_result = match self.process_group {
            None => Ok(()),
            Some(process_group) => match kill_process_group(process_group, Signal::KILL) {
                Ok(()) | Err(Errno::SRCH) => {
                    // Process-group identifiers can eventually be recycled.
                    // Forget the group after a conclusive result so Drop or a
                    // repeated caller cannot signal an unrelated future group.
                    self.process_group = None;
                    Ok(())
                }
                Err(error) => Err(error.into()),
            },
        };

        #[cfg(windows)]
        let containment_result = {
            // Closing the final job handle applies JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
            drop(self.job.take());
            Ok(())
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

fn terminate_direct_child(child: &mut Child) -> io::Result<()> {
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

#[cfg(windows)]
fn job_error(context: &str, error: win32job::JobError) -> io::Error {
    let error: io::Error = error.into();
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(windows)]
fn job_assignment_error(
    error: win32job::JobError,
    kill_error: Option<io::Error>,
    wait_error: Option<io::Error>,
) -> io::Error {
    let error: io::Error = error.into();
    let mut message = format!("failed to assign child process to Job Object: {error}");
    append_cleanup_errors(&mut message, kill_error, wait_error);
    io::Error::new(error.kind(), message)
}

#[cfg(windows)]
fn append_cleanup_errors(
    message: &mut String,
    kill_error: Option<io::Error>,
    wait_error: Option<io::Error>,
) {
    if let Some(error) = kill_error {
        message.push_str(&format!("; direct-child kill also failed: {error}"));
    }
    if let Some(error) = wait_error {
        message.push_str(&format!("; direct-child reap also failed: {error}"));
    }
}

#[cfg(test)]
mod tests {
    use super::ContainedChild;
    use std::io;
    use std::process::{Command, Stdio};

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
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
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

    #[cfg(unix)]
    fn exit_command(code: u8) -> Command {
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!("exit {code}"));
        command
    }

    #[cfg(windows)]
    fn exit_command(code: u8) -> Command {
        let mut command = Command::new("cmd.exe");
        command.args(["/D", "/S", "/C"]).arg(format!("exit {code}"));
        command
    }
}
