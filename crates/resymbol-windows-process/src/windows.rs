use std::{
    cmp::Ordering,
    env,
    ffi::{OsStr, OsString, c_void},
    fs::File,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt as _,
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle},
        process::ExitStatusExt as _,
    },
    path::{Path, PathBuf},
    process::ExitStatus,
    ptr::{null, null_mut},
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INSUFFICIENT_BUFFER, FALSE, HANDLE,
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, TRUE, WAIT_FAILED,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Globalization::{CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    },
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        JobObjects::{
            CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject,
        },
        Pipes::CreatePipe,
        Threading::{
            CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
            EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, INFINITE,
            InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
            WaitForSingleObject,
        },
    },
};

const WINDOWS_MAX_COMMAND_LINE_UNITS: usize = 32_767;
const FAIL_CLOSED_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const FAIL_CLOSED_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Standard-stream behavior supported by the atomic contained launcher.
///
/// ReSymbol production launches use [`Self::piped`] for all three streams.
/// `Inherit` duplicates the current standard handle into an inheritable handle,
/// while `Null` opens a dedicated `NUL` handle. Arbitrary caller-owned handles
/// are deliberately unsupported: accepting them would broaden the inherited
/// handle surface beyond this crate's fixed three-handle allow-list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stdio {
    Inherit,
    Null,
    Piped,
}

impl Stdio {
    #[must_use]
    pub const fn inherit() -> Self {
        Self::Inherit
    }

    #[must_use]
    pub const fn null() -> Self {
        Self::Null
    }

    #[must_use]
    pub const fn piped() -> Self {
        Self::Piped
    }
}

/// A deliberately small command builder for an atomically contained process.
///
/// It preserves the `Command` behavior ReSymbol relies on: Windows-native
/// Unicode arguments, inherited-or-cleared environment construction, exact
/// environment overrides, a Unicode current directory, and inherited, null,
/// or piped standard streams. The program must be an exact executable path;
/// ReSymbol resolves and validates it before constructing this command. Shell
/// strings, executable search, raw command-line fragments, arbitrary inherited
/// handles, and process-breakaway flags are intentionally absent from the API.
#[derive(Debug)]
pub struct ContainedCommand {
    program: OsString,
    arguments: Vec<OsString>,
    current_directory: Option<PathBuf>,
    environment: CommandEnvironment,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
}

impl ContainedCommand {
    #[must_use]
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            program: program.as_ref().to_os_string(),
            arguments: Vec::new(),
            current_directory: None,
            environment: CommandEnvironment::default(),
            stdin: Stdio::Inherit,
            stdout: Stdio::Inherit,
            stderr: Stdio::Inherit,
        }
    }

    pub fn arg(&mut self, argument: impl AsRef<OsStr>) -> &mut Self {
        self.arguments.push(argument.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.arguments.extend(
            arguments
                .into_iter()
                .map(|argument| argument.as_ref().to_os_string()),
        );
        self
    }

    pub fn current_dir(&mut self, directory: impl AsRef<Path>) -> &mut Self {
        self.current_directory = Some(directory.as_ref().to_path_buf());
        self
    }

    pub fn env_clear(&mut self) -> &mut Self {
        self.environment.clear();
        self
    }

    pub fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.environment.set(key.as_ref(), value.as_ref());
        self
    }

    pub fn stdin(&mut self, stdio: Stdio) -> &mut Self {
        self.stdin = stdio;
        self
    }

    pub fn stdout(&mut self, stdio: Stdio) -> &mut Self {
        self.stdout = stdio;
        self
    }

    pub fn stderr(&mut self, stdio: Stdio) -> &mut Self {
        self.stderr = stdio;
        self
    }

    /// Creates the process with Job and handle-list attributes already applied.
    ///
    /// The returned child owns ReSymbol's anonymous Job handle. There
    /// is no suspended or post-spawn assignment path: unsupported systems and
    /// any attribute-list failure fail closed before `CreateProcessW` succeeds.
    pub fn spawn(&mut self) -> io::Result<ContainedChild> {
        spawn_contained(self)
    }
}

/// Direct child plus the Job Object that contains its complete descendant tree.
#[derive(Debug)]
pub struct ContainedChild {
    process: OwnedHandle,
    job: Option<OwnedHandle>,
    process_id: u32,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
}

impl ContainedChild {
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.process_id
    }

    pub fn take_stdin(&mut self) -> Option<File> {
        self.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<File> {
        self.stderr.take()
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        // SAFETY: `self.process` is a live owned process handle for the entire call.
        match unsafe { WaitForSingleObject(raw_handle(&self.process), 0) } {
            WAIT_OBJECT_0 => process_exit_status(&self.process).map(Some),
            WAIT_TIMEOUT => Ok(None),
            WAIT_FAILED => Err(last_error("poll contained child process")),
            result => Err(io::Error::other(format!(
                "poll contained child process returned unexpected wait result {result}"
            ))),
        }
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        // Match std::process::Child::wait: a child waiting for stdin EOF must
        // not deadlock merely because the caller left its piped writer attached.
        drop(self.stdin.take());
        // SAFETY: `self.process` is a live owned process handle for the entire call.
        match unsafe { WaitForSingleObject(raw_handle(&self.process), INFINITE) } {
            WAIT_OBJECT_0 => process_exit_status(&self.process),
            WAIT_FAILED => Err(last_error("wait for contained child process")),
            result => Err(io::Error::other(format!(
                "wait for contained child process returned unexpected wait result {result}"
            ))),
        }
    }

    pub fn kill(&mut self) -> io::Result<()> {
        // SAFETY: `self.process` is a live owned process handle with terminate access,
        // obtained directly from CreateProcessW.
        if unsafe { TerminateProcess(raw_handle(&self.process), 1) } == FALSE {
            Err(last_error("terminate contained direct child"))
        } else {
            Ok(())
        }
    }

    /// Explicitly terminates the Job and then closes ReSymbol's Job handle.
    ///
    /// Explicit termination keeps ordinary cleanup authoritative even if
    /// hostile same-account code duplicated the handle. `KILL_ON_JOB_CLOSE`
    /// remains the abrupt-parent fallback when no out-of-scope process retains
    /// a duplicate. A failed termination retains the handle so callers and
    /// [`Drop`] can retry instead of silently discarding the cleanup authority.
    pub fn terminate_tree(&mut self) -> io::Result<()> {
        let Some(job) = self.job.take() else {
            return Ok(());
        };
        // SAFETY: `job` is ReSymbol's live Job handle. All processes currently
        // assigned to the Job receive the fixed non-success termination code.
        if unsafe { TerminateJobObject(raw_handle(&job), 1) } == FALSE {
            let error = last_error("terminate contained process Job");
            self.job = Some(job);
            Err(error)
        } else {
            drop(job);
            Ok(())
        }
    }
}

impl Drop for ContainedChild {
    fn drop(&mut self) {
        // Make normal unwinding authoritative even if another process duplicated
        // the Job handle. The configured close limit remains the crash fallback
        // when no out-of-scope process retains a duplicate.
        let _ = self.terminate_tree();
    }
}

#[derive(Debug)]
struct CommandEnvironment {
    inherit: bool,
    overrides: Vec<(OsString, OsString)>,
}

impl Default for CommandEnvironment {
    fn default() -> Self {
        Self {
            inherit: true,
            overrides: Vec::new(),
        }
    }
}

impl CommandEnvironment {
    fn clear(&mut self) {
        self.inherit = false;
        self.overrides.clear();
    }

    fn set(&mut self, key: &OsStr, value: &OsStr) {
        let key_wide = encode_wide(key);
        self.overrides
            .retain(|(existing, _)| !environment_keys_equal(&encode_wide(existing), &key_wide));
        self.overrides
            .push((key.to_os_string(), value.to_os_string()));
    }

    fn block(&self) -> io::Result<Vec<u16>> {
        let mut entries = if self.inherit {
            env::vars_os().collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        for (key, value) in &self.overrides {
            let key_wide = encode_wide(key);
            entries
                .retain(|(existing, _)| !environment_keys_equal(&encode_wide(existing), &key_wide));
            entries.push((key.clone(), value.clone()));
        }

        let mut entries = entries
            .into_iter()
            .map(|(key, value)| {
                let key = encode_wide(&key);
                let value = encode_wide(&value);
                validate_environment_entry(&key, &value)?;
                Ok((key, value))
            })
            .collect::<io::Result<Vec<_>>>()?;
        entries.sort_by(|(left, _), (right, _)| compare_environment_keys(left, right));

        let mut block = Vec::new();
        for (key, value) in entries {
            block.extend_from_slice(&key);
            block.push(u16::from(b'='));
            block.extend_from_slice(&value);
            block.push(0);
        }
        // CreateProcessW requires an empty environment to contain two NULs.
        block.push(0);
        if block.len() == 1 {
            block.push(0);
        }
        Ok(block)
    }
}

fn spawn_contained(command: &ContainedCommand) -> io::Result<ContainedChild> {
    if !Path::new(&command.program).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "contained Windows program must be an exact absolute executable path",
        ));
    }
    let application = nul_terminated_wide(&command.program, "program")?;
    if application.len() == 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "program must not be empty",
        ));
    }
    let mut command_line = command_line(command)?;
    let environment = command.environment.block()?;
    let current_directory = command
        .current_directory
        .as_deref()
        .map(|directory| nul_terminated_wide(directory.as_os_str(), "current directory"))
        .transpose()?;

    let job = create_kill_on_close_job()?;
    let mut stdin = prepare_stdio(command.stdin, StreamDirection::Input, STD_INPUT_HANDLE)?;
    let mut stdout = prepare_stdio(command.stdout, StreamDirection::Output, STD_OUTPUT_HANDLE)?;
    let mut stderr = prepare_stdio(command.stderr, StreamDirection::Output, STD_ERROR_HANDLE)?;
    let inherited_handles = [
        raw_handle(&stdin.child),
        raw_handle(&stdout.child),
        raw_handle(&stderr.child),
    ];
    let job_handle = [raw_handle(&job)];

    // These arrays are declared before the attribute-list owner so Rust's
    // reverse drop order keeps their backing storage alive until after
    // DeleteProcThreadAttributeList runs on every success and error path.
    let mut attributes = ProcThreadAttributeList::new(2)?;
    attributes.update_handles(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
        &inherited_handles,
    )?;
    attributes.update_handles(PROC_THREAD_ATTRIBUTE_JOB_LIST as usize, &job_handle)?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "STARTUPINFOEXW size exceeds u32",
        )
    })?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited_handles[0];
    startup.StartupInfo.hStdOutput = inherited_handles[1];
    startup.StartupInfo.hStdError = inherited_handles[2];
    startup.lpAttributeList = attributes.as_ptr();

    let mut process_information = PROCESS_INFORMATION::default();
    let current_directory_pointer = current_directory
        .as_ref()
        .map_or(null(), |directory| directory.as_ptr());
    // SAFETY: every pointer refers to initialized storage that remains alive and
    // immobile for the call. `command_line` is writable and NUL-terminated;
    // application, environment, and cwd are NUL-terminated. STARTUPINFOEX owns
    // an initialized two-entry attribute list whose referenced HANDLE arrays
    // also remain live. Only those three inheritable stdio handles are listed.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast::<c_void>(),
            current_directory_pointer,
            &startup.StartupInfo,
            &mut process_information,
        )
    };
    if created == FALSE {
        return Err(last_error("create atomically contained child process"));
    }

    // SAFETY: successful CreateProcessW returns two distinct non-null handles
    // owned by the caller in PROCESS_INFORMATION.
    let process = unsafe { owned_handle_from_created(process_information.hProcess) };
    // SAFETY: same CreateProcessW ownership invariant as for `process` above.
    let primary_thread = unsafe { owned_handle_from_created(process_information.hThread) };
    let (process, primary_thread) = match (process, primary_thread) {
        (Ok(process), Ok(primary_thread)) => (process, primary_thread),
        (process, thread) => {
            // A successful CreateProcessW must return valid handles. If the ABI
            // contract is violated, close any handle we did receive and close
            // the Job immediately; the child cannot escape that preassigned Job.
            drop(process.ok());
            drop(thread.ok());
            drop(job);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CreateProcessW returned an invalid process or primary-thread handle",
            ));
        }
    };
    drop(primary_thread);

    let child = ContainedChild {
        process,
        job: Some(job),
        process_id: process_information.dwProcessId,
        stdin: stdin.parent.take(),
        stdout: stdout.parent.take(),
        stderr: stderr.parent.take(),
    };
    match process_is_in_job(&child.process, child.job.as_ref().expect("job is present")) {
        Ok(true) => Ok(child),
        Ok(false) => Err(fail_closed_child(
            child,
            io::Error::other(
                "CreateProcessW succeeded but the child is not in its requested Job Object",
            ),
        )),
        Err(error) => Err(fail_closed_child(child, error)),
    }
}

fn fail_closed_child(mut child: ContainedChild, error: io::Error) -> io::Error {
    // The protocol writer is still private to this stack frame, so the process
    // cannot receive ReSymbol input. Close our writer, terminate the Job first,
    // target the direct child defensively, and make only a bounded reap attempt.
    drop(child.stdin.take());
    let tree_error = child.terminate_tree().err();
    let direct_error = child.kill().err();
    let reap_error = wait_for_exit_bounded(&mut child, FAIL_CLOSED_REAP_TIMEOUT).err();
    let mut message = error.to_string();
    for (label, cleanup_error) in [
        ("Job termination", tree_error),
        // A failed TerminateProcess is harmless if the bounded poll proves the
        // child exited. Otherwise retain both failures in the diagnostic.
        (
            "direct-child termination",
            reap_error.as_ref().and(direct_error),
        ),
        ("bounded direct-child reap", reap_error),
    ] {
        if let Some(cleanup_error) = cleanup_error {
            message.push_str(&format!("; {label} also failed: {cleanup_error}"));
        }
    }
    io::Error::new(error.kind(), message)
}

fn wait_for_exit_bounded(child: &mut ContainedChild, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "bounded child-reap timeout exceeds the platform clock",
        )
    })?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "contained direct child did not exit within {} ms after fail-closed termination",
                    timeout.as_millis()
                ),
            ));
        }
        thread::sleep(FAIL_CLOSED_POLL_INTERVAL.min(deadline.duration_since(now)));
    }
}

fn create_kill_on_close_job() -> io::Result<OwnedHandle> {
    // SAFETY: null security attributes and name request an unnamed, non-inheritable Job.
    let raw_job = unsafe { CreateJobObjectW(null(), null()) };
    let job = owned_handle(raw_job, "create process Job Object")?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Job extended-limit structure size exceeds u32",
        )
    })?;
    // SAFETY: `job` is a live Job handle and `limits` is a correctly sized,
    // initialized JOBOBJECT_EXTENDED_LIMIT_INFORMATION value for the call.
    if unsafe {
        SetInformationJobObject(
            raw_handle(&job),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast::<c_void>(),
            size,
        )
    } == FALSE
    {
        return Err(last_error("configure kill-on-close process Job Object"));
    }
    Ok(job)
}

fn process_is_in_job(process: &OwnedHandle, job: &OwnedHandle) -> io::Result<bool> {
    let mut contained = FALSE;
    // SAFETY: both handles are live for the call and `contained` is writable BOOL storage.
    if unsafe { IsProcessInJob(raw_handle(process), raw_handle(job), &mut contained) } == FALSE {
        Err(last_error("verify child process Job membership"))
    } else {
        Ok(contained != FALSE)
    }
}

#[derive(Debug, Clone, Copy)]
enum StreamDirection {
    Input,
    Output,
}

#[derive(Debug)]
struct PreparedStdio {
    child: OwnedHandle,
    parent: Option<File>,
}

fn prepare_stdio(
    behavior: Stdio,
    direction: StreamDirection,
    standard_handle: u32,
) -> io::Result<PreparedStdio> {
    match behavior {
        Stdio::Piped => prepare_pipe(direction),
        Stdio::Null => Ok(PreparedStdio {
            child: open_inheritable_null(direction)?,
            parent: None,
        }),
        Stdio::Inherit => Ok(PreparedStdio {
            child: duplicate_standard_handle(standard_handle, direction)?,
            parent: None,
        }),
    }
}

fn prepare_pipe(direction: StreamDirection) -> io::Result<PreparedStdio> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SECURITY_ATTRIBUTES size exceeds u32",
            )
        })?,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };
    let mut read = null_mut();
    let mut write = null_mut();
    // SAFETY: `read` and `write` are writable HANDLE slots and `attributes`
    // remains live. CreatePipe initializes both handles on success.
    if unsafe { CreatePipe(&mut read, &mut write, &raw const attributes, 0) } == FALSE {
        return Err(last_error("create contained child standard-I/O pipe"));
    }
    // SAFETY: successful CreatePipe transfers ownership of each returned handle.
    let read = unsafe { owned_handle_from_created(read) }?;
    // SAFETY: successful CreatePipe transfers ownership of each returned handle.
    let write = unsafe { owned_handle_from_created(write) }?;
    let (child, parent) = match direction {
        StreamDirection::Input => (read, write),
        StreamDirection::Output => (write, read),
    };
    clear_inherit_flag(&parent)?;
    Ok(PreparedStdio {
        child,
        parent: Some(File::from(parent)),
    })
}

fn open_inheritable_null(direction: StreamDirection) -> io::Result<OwnedHandle> {
    const NUL: &[u16] = &[b'N' as u16, b'U' as u16, b'L' as u16, 0];
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SECURITY_ATTRIBUTES size exceeds u32",
            )
        })?,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };
    let access = match direction {
        StreamDirection::Input => FILE_GENERIC_READ,
        StreamDirection::Output => FILE_GENERIC_WRITE,
    };
    // SAFETY: NUL is a static NUL-terminated UTF-16 path and `attributes`
    // remains valid for the call. The returned handle is owned on success.
    let handle = unsafe {
        CreateFileW(
            NUL.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &raw const attributes,
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    owned_handle(handle, "open inheritable NUL standard handle")
}

fn duplicate_standard_handle(
    standard_handle: u32,
    direction: StreamDirection,
) -> io::Result<OwnedHandle> {
    // SAFETY: GetStdHandle accepts one of the three fixed STD_* constants.
    let source = unsafe { GetStdHandle(standard_handle) };
    if source.is_null() || source == INVALID_HANDLE_VALUE {
        return open_inheritable_null(direction);
    }
    let mut duplicate = null_mut();
    // SAFETY: the pseudo process handles identify the current process; `source`
    // is the current standard handle. `duplicate` is writable and ownership of
    // the real duplicated handle transfers to us on success.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            TRUE,
            DUPLICATE_SAME_ACCESS,
        )
    } == FALSE
    {
        return Err(last_error("duplicate inheritable standard handle"));
    }
    // SAFETY: successful DuplicateHandle returned one newly owned real handle.
    unsafe { owned_handle_from_created(duplicate) }
}

fn clear_inherit_flag(handle: &OwnedHandle) -> io::Result<()> {
    // SAFETY: `handle` is live; mask=INHERIT and flags=0 only clear its inherit bit.
    if unsafe { SetHandleInformation(raw_handle(handle), HANDLE_FLAG_INHERIT, 0) } == FALSE {
        Err(last_error("make parent pipe endpoint non-inheritable"))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct ProcThreadAttributeList {
    storage: Vec<usize>,
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl ProcThreadAttributeList {
    fn new(attribute_count: u32) -> io::Result<Self> {
        let mut bytes = 0_usize;
        // SAFETY: a null first call is the documented size query; `bytes` is writable.
        let size_query = unsafe {
            InitializeProcThreadAttributeList(null_mut(), attribute_count, 0, &mut bytes)
        };
        let size_error = io::Error::last_os_error();
        if size_query != FALSE
            || size_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || bytes == 0
        {
            return Err(io::Error::new(
                size_error.kind(),
                format!("size process-thread attribute list: {size_error}"),
            ));
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let pointer = storage.as_mut_ptr().cast::<c_void>();
        // SAFETY: `storage` is pointer-aligned and at least the byte size returned
        // by the query. It remains fixed and owned by Self until Delete is called.
        if unsafe { InitializeProcThreadAttributeList(pointer, attribute_count, 0, &mut bytes) }
            == FALSE
        {
            return Err(last_error("initialize process-thread attribute list"));
        }
        Ok(Self { storage, pointer })
    }

    const fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.pointer
    }

    fn update_handles(&mut self, attribute: usize, handles: &[HANDLE]) -> io::Result<()> {
        let byte_count = handles
            .len()
            .checked_mul(size_of::<HANDLE>())
            .ok_or_else(|| io::Error::other("process attribute handle-list size overflow"))?;
        // SAFETY: `self.pointer` references an initialized list with remaining
        // capacity. `handles` is a live contiguous HANDLE array through
        // CreateProcessW; no previous-value output was requested.
        if unsafe {
            UpdateProcThreadAttribute(
                self.pointer,
                0,
                attribute,
                handles.as_ptr().cast::<c_void>(),
                byte_count,
                null_mut(),
                null(),
            )
        } == FALSE
        {
            Err(last_error("add process-thread handle attribute"))
        } else {
            Ok(())
        }
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        debug_assert!(!self.storage.is_empty());
        // SAFETY: `pointer` was successfully initialized exactly once and its
        // backing storage remains alive until this destructor returns.
        unsafe { DeleteProcThreadAttributeList(self.pointer) };
    }
}

fn command_line(command: &ContainedCommand) -> io::Result<Vec<u16>> {
    let mut line = Vec::new();
    let program = encode_wide(&command.program);
    if program.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "program contains an embedded NUL",
        ));
    }
    append_quoted_argument(&mut line, &program);
    for argument in &command.arguments {
        let argument = encode_wide(argument);
        if argument.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "argument contains an embedded NUL",
            ));
        }
        line.push(u16::from(b' '));
        append_quoted_argument(&mut line, &argument);
    }
    line.push(0);
    if line.len() > WINDOWS_MAX_COMMAND_LINE_UNITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Windows command line exceeds {WINDOWS_MAX_COMMAND_LINE_UNITS} UTF-16 code units"
            ),
        ));
    }
    Ok(line)
}

fn append_quoted_argument(line: &mut Vec<u16>, argument: &[u16]) {
    const BACKSLASH: u16 = b'\\' as u16;
    const QUOTE: u16 = b'"' as u16;
    let quote = argument.is_empty()
        || argument
            .iter()
            .any(|unit| *unit == b' ' as u16 || *unit == b'\t' as u16 || *unit == QUOTE);
    if !quote {
        line.extend_from_slice(argument);
        return;
    }

    line.push(QUOTE);
    let mut backslashes = 0_usize;
    for &unit in argument {
        if unit == BACKSLASH {
            backslashes += 1;
            continue;
        }
        if unit == QUOTE {
            line.extend(std::iter::repeat_n(BACKSLASH, backslashes * 2 + 1));
        } else {
            line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
        }
        backslashes = 0;
        line.push(unit);
    }
    line.extend(std::iter::repeat_n(BACKSLASH, backslashes * 2));
    line.push(QUOTE);
}

fn validate_environment_entry(key: &[u16], value: &[u16]) -> io::Result<()> {
    if key.is_empty() || key.contains(&0) || value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "environment names must be non-empty and names/values cannot contain NUL",
        ));
    }
    let equals = u16::from(b'=');
    let invalid_equals = if key.first() == Some(&equals) {
        key[1..].contains(&equals)
    } else {
        key.contains(&equals)
    };
    if invalid_equals {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "environment names cannot contain '=' except as a leading drive-current-directory marker",
        ));
    }
    Ok(())
}

fn environment_keys_equal(left: &[u16], right: &[u16]) -> bool {
    compare_environment_keys(left, right) == Ordering::Equal
}

fn compare_environment_keys(left: &[u16], right: &[u16]) -> Ordering {
    let Ok(left_len) = i32::try_from(left.len()) else {
        return left.cmp(right);
    };
    let Ok(right_len) = i32::try_from(right.len()) else {
        return left.cmp(right);
    };
    // SAFETY: both slices are live UTF-16 buffers for the supplied lengths.
    // CompareStringOrdinal does not require NUL termination when lengths are explicit.
    match unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, TRUE) }
    {
        CSTR_LESS_THAN => Ordering::Less,
        CSTR_EQUAL => Ordering::Equal,
        CSTR_GREATER_THAN => Ordering::Greater,
        _ => left.cmp(right),
    }
}

fn encode_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().collect()
}

fn nul_terminated_wide(value: &OsStr, label: &str) -> io::Result<Vec<u16>> {
    let mut value = encode_wide(value);
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} contains an embedded NUL"),
        ));
    }
    value.push(0);
    Ok(value)
}

fn process_exit_status(process: &OwnedHandle) -> io::Result<ExitStatus> {
    let mut exit_code = 0_u32;
    // SAFETY: `process` is a live process handle and `exit_code` is writable.
    if unsafe { GetExitCodeProcess(raw_handle(process), &mut exit_code) } == FALSE {
        Err(last_error("read contained child exit code"))
    } else {
        Ok(ExitStatus::from_raw(exit_code))
    }
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle()
}

fn owned_handle(handle: HANDLE, context: &str) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(last_error(context))
    } else {
        // SAFETY: the checked non-null, non-pseudo handle is newly returned by a
        // Win32 ownership-transferring API and has no other Rust owner.
        unsafe { owned_handle_from_created(handle) }
    }
}

/// Converts a newly created Win32 handle into its sole Rust owner.
///
/// # Safety
///
/// `handle` must be a valid, real, caller-owned handle returned by an API that
/// transfers ownership. It must not be a pseudo handle or already owned elsewhere.
unsafe fn owned_handle_from_created(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Win32 API returned an invalid owned handle",
        ));
    }
    // SAFETY: upheld by this function's caller contract and validated against
    // the two invalid sentinel values above.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

fn last_error(context: &str) -> io::Error {
    let error = io::Error::last_os_error();
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        ContainedChild, ContainedCommand, Stdio, command_line, owned_handle_from_created,
        raw_handle, wait_for_exit_bounded,
    };
    use std::{
        ffi::OsString,
        io::{self, Read as _},
        os::windows::{ffi::OsStringExt as _, io::OwnedHandle},
        process,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, FALSE};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    const FIXTURE_MODE: &str = "RESYMBOL_WINDOWS_PROCESS_UNIT_FIXTURE";
    const LONG_RUNNING_FIXTURE: &str = "windows::tests::long_running_fixture";
    const NORMAL_EXIT_FIXTURE: &str = "windows::tests::normal_exit_fixture";
    const STDIN_EOF_FIXTURE: &str = "windows::tests::stdin_eof_fixture";

    #[test]
    fn embedded_argument_nul_is_rejected_before_process_creation() {
        let mut command = ContainedCommand::new("does-not-exist.exe");
        command.arg(OsString::from_wide(&[u16::from(b'a'), 0, u16::from(b'b')]));

        let error = command_line(&command).expect_err("embedded NUL must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("argument"));
    }

    #[test]
    fn relative_application_path_is_rejected_before_process_creation() {
        let mut command = ContainedCommand::new("relative.exe");
        let error = command
            .spawn()
            .expect_err("relative application path must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("absolute"));
    }

    #[test]
    fn duplicated_job_handle_does_not_defeat_explicit_tree_termination() {
        let mut child = spawn_fixture(LONG_RUNNING_FIXTURE, "long-running", Stdio::null());
        let duplicate = duplicate_job_handle(&child);

        child
            .terminate_tree()
            .expect("explicitly terminate Job while a duplicate handle survives");
        let status = wait_for_exit_bounded(&mut child, Duration::from_secs(2))
            .expect("explicit Job termination must stop the long-running child");
        assert_eq!(status.code(), Some(1));
        drop(duplicate);
    }

    #[test]
    fn terminate_after_normal_exit_preserves_status() {
        let mut child = spawn_fixture(NORMAL_EXIT_FIXTURE, "normal-exit", Stdio::null());
        let status = child.wait().expect("wait for normal fixture exit");
        assert!(status.success());

        child
            .terminate_tree()
            .expect("terminate empty Job after direct-child exit");
        assert_eq!(child.wait().expect("re-read direct-child status"), status);
    }

    #[test]
    fn explicit_tree_termination_is_idempotent() {
        let mut child = spawn_fixture(LONG_RUNNING_FIXTURE, "long-running", Stdio::null());
        child.terminate_tree().expect("first Job termination");
        child.terminate_tree().expect("second Job termination");
        let status = wait_for_exit_bounded(&mut child, Duration::from_secs(2))
            .expect("terminated child must become signaled");
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn failed_tree_termination_retains_job_handle_for_retry() {
        const JOB_OBJECT_QUERY_ACCESS: u32 = 0x0004;

        let mut child = spawn_fixture(LONG_RUNNING_FIXTURE, "long-running", Stdio::null());
        let full_access_job = child
            .job
            .take()
            .expect("contained child owns a full-access Job handle");
        let restricted_job =
            duplicate_job_handle_with_access(&full_access_job, JOB_OBJECT_QUERY_ACCESS);
        let restricted_raw = raw_handle(&restricted_job);
        child.job = Some(restricted_job);

        for attempt in 1..=2 {
            let error = child
                .terminate_tree()
                .expect_err("query-only Job handle must not terminate the Job");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                child.job.as_ref().map(raw_handle),
                Some(restricted_raw),
                "attempt {attempt} discarded or replaced the retryable Job handle"
            );
            assert!(
                child.try_wait().expect("poll live fixture").is_none(),
                "failed termination attempt {attempt} unexpectedly stopped the fixture"
            );
        }

        let restricted_job = child
            .job
            .replace(full_access_job)
            .expect("replace retained query-only Job handle");
        drop(restricted_job);
        child
            .terminate_tree()
            .expect("restored full-access Job handle must terminate the Job");
        let status = wait_for_exit_bounded(&mut child, Duration::from_secs(2))
            .expect("fixture must exit after successful retry");
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn wait_closes_attached_piped_stdin_to_deliver_eof() {
        let mut child = spawn_fixture(STDIN_EOF_FIXTURE, "stdin-eof", Stdio::piped());
        let started = Instant::now();
        let status = child.wait().expect("wait should deliver stdin EOF");

        assert!(status.success(), "EOF fixture exited {status}");
        assert!(child.take_stdin().is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "wait did not promptly close the attached stdin writer"
        );
    }

    #[test]
    fn bounded_reap_reports_timeout_without_hanging() {
        let mut child = spawn_fixture(LONG_RUNNING_FIXTURE, "long-running", Stdio::null());
        let started = Instant::now();
        let error = wait_for_exit_bounded(&mut child, Duration::from_millis(25))
            .expect_err("live child must exceed the synthetic reap deadline");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        child
            .terminate_tree()
            .expect("clean up timeout fixture Job");
        wait_for_exit_bounded(&mut child, Duration::from_secs(2))
            .expect("cleanup fixture must exit after Job termination");
    }

    #[test]
    fn long_running_fixture() {
        if fixture_mode() == Some("long-running") {
            thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn normal_exit_fixture() {}

    #[test]
    fn stdin_eof_fixture() {
        if fixture_mode() != Some("stdin-eof") {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = io::stdin().read_to_end(&mut bytes).map(|_| bytes);
            let _ = sender.send(result);
        });
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(Ok(bytes)) => assert!(bytes.is_empty()),
            Ok(Err(error)) => panic!("read piped stdin: {error}"),
            Err(_) => process::exit(88),
        }
        reader.join().expect("stdin reader thread");
    }

    fn fixture_mode() -> Option<&'static str> {
        match std::env::var(FIXTURE_MODE).as_deref() {
            Ok("long-running") => Some("long-running"),
            Ok("normal-exit") => Some("normal-exit"),
            Ok("stdin-eof") => Some("stdin-eof"),
            _ => None,
        }
    }

    fn spawn_fixture(test_name: &str, mode: &str, stdin: Stdio) -> ContainedChild {
        let mut command = ContainedCommand::new(
            std::env::current_exe().expect("resolve exact unit-test executable"),
        );
        command
            .args(["--exact", test_name, "--nocapture"])
            .env(FIXTURE_MODE, mode)
            .stdin(stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.spawn().expect("spawn contained unit-test fixture")
    }

    fn duplicate_job_handle(child: &ContainedChild) -> OwnedHandle {
        let source = child
            .job
            .as_ref()
            .expect("contained child owns a Job handle");
        duplicate_job_handle_with_options(source, 0, DUPLICATE_SAME_ACCESS)
    }

    fn duplicate_job_handle_with_access(source: &OwnedHandle, desired_access: u32) -> OwnedHandle {
        duplicate_job_handle_with_options(source, desired_access, 0)
    }

    fn duplicate_job_handle_with_options(
        source: &OwnedHandle,
        desired_access: u32,
        options: u32,
    ) -> OwnedHandle {
        let mut duplicate = std::ptr::null_mut();
        // SAFETY: both pseudo process handles denote this process, `source` is a
        // live Job handle, and `duplicate` is writable storage. Success transfers
        // one independent real-handle ownership reference to this test.
        let result = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                raw_handle(source),
                GetCurrentProcess(),
                &mut duplicate,
                desired_access,
                FALSE,
                options,
            )
        };
        assert_ne!(result, FALSE, "duplicate contained Job handle");
        // SAFETY: successful DuplicateHandle returned one newly owned real handle.
        unsafe { owned_handle_from_created(duplicate) }.expect("own duplicate Job handle")
    }
}
