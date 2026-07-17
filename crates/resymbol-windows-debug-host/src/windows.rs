//! Narrow Win32 debug-loop boundary.

use std::{
    io,
    os::windows::io::{FromRawHandle as _, OwnedHandle, RawHandle},
    time::{Duration, Instant},
};

use resymbol_debugger::{LiveTargetBinding, MemoryAddress, ProcessId};
use resymbol_windows_live_access::{OpenLiveProcessRequest, ReadOnlyLiveProcessAccess};
use windows_sys::Win32::{
    Foundation::{DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_SEM_TIMEOUT, FALSE, HANDLE},
    System::Diagnostics::Debug::{
        CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT,
        DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
        EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
        LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, UNLOAD_DLL_DEBUG_EVENT,
        WaitForDebugEventEx,
    },
};

use crate::{
    BackendFailure, ContinueDisposition, DebugAttachLimits, DebugBackend, DebugEventKind,
    DebugEventRecord, DebugFileToken, DebugHostError, DebugHostWorker, DebugHostWorkerState,
    PendingStopEvidence, phase_one_capability_report,
};

/// Single-thread owner of one phase-one Windows debug attachment.
///
/// The value is intentionally neither `Send` nor `Sync`. Construct, attach,
/// read, and detach it on the same dedicated session-worker thread.
#[derive(Debug)]
pub struct WindowsDebugHostWorker {
    inner: DebugHostWorker<WindowsDebugBackend>,
}

impl WindowsDebugHostWorker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: DebugHostWorker::new(WindowsDebugBackend::new()),
        }
    }

    /// Returns the static provider surface. The future authenticated helper
    /// transport remains responsible for deciding whether it may publish it.
    #[must_use]
    pub fn capabilities() -> resymbol_debugger::CapabilityReport {
        phase_one_capability_report()
    }

    #[must_use]
    pub fn state(&self) -> DebugHostWorkerState {
        self.inner.state()
    }

    #[must_use]
    pub fn binding(&self) -> Option<&LiveTargetBinding> {
        self.inner.binding()
    }

    #[must_use]
    pub fn pending_stop(&self) -> Option<&PendingStopEvidence> {
        self.inner.pending_stop()
    }

    /// Attaches only after the owning authenticated session worker has
    /// consumed authority for this exact process and attach mode.
    ///
    /// This low-level method does not authenticate its caller, a helper
    /// process, a transport, or a serialized lease identifier. Passing a
    /// `LiveTargetBinding` proves identity and mapping equality only. Do not
    /// call it directly from UI or untrusted command-dispatch code.
    pub fn attach_after_authorization(
        &mut self,
        expected: &LiveTargetBinding,
        limits: DebugAttachLimits,
    ) -> Result<PendingStopEvidence, DebugHostError> {
        self.inner.attach_after_authorization(expected, limits)
    }

    /// Reads a bounded span from the exact preflight main image while the
    /// initial attach breakpoint remains pending.
    pub fn read_stopped_main_image(
        &mut self,
        address: MemoryAddress,
        size: usize,
    ) -> Result<Vec<u8>, DebugHostError> {
        self.inner.read_stopped_main_image(address, size)
    }

    /// Continues any retained event with its conservative disposition, then
    /// attempts `DebugActiveProcessStop` even if continuation fails. The error
    /// reports kill-policy, event-continuation, and detach outcomes
    /// independently. Invoke this explicitly: the worker's `Drop` cleanup is
    /// best effort and discards evidence, so it is never proof of detachment.
    pub fn detach(&mut self) -> Result<(), DebugHostError> {
        self.inner.detach()
    }
}

impl Default for WindowsDebugHostWorker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct WindowsDebugBackend {
    clock_origin: Instant,
    live_access: Option<ReadOnlyLiveProcessAccess>,
}

impl WindowsDebugBackend {
    fn new() -> Self {
        Self {
            clock_origin: Instant::now(),
            live_access: None,
        }
    }
}

impl DebugBackend for WindowsDebugBackend {
    fn monotonic_now(&self) -> Duration {
        self.clock_origin.elapsed()
    }

    fn preflight(
        &mut self,
        expected: &LiveTargetBinding,
    ) -> Result<LiveTargetBinding, BackendFailure> {
        debug_assert!(self.live_access.is_none());
        let process = expected.process();
        let request = OpenLiveProcessRequest::new(
            process.process_id,
            process.start_key,
            expected.actual_image_base(),
            expected.main_module_binary_id().clone(),
        );
        let access = ReadOnlyLiveProcessAccess::open_read_only(request).map_err(|error| {
            BackendFailure::new("preflight exact live target", error.to_string())
        })?;
        let observed = access
            .refresh_binding(expected)
            .map_err(|error| BackendFailure::new("refresh preflight binding", error.to_string()))?;
        self.live_access = Some(access);
        Ok(observed)
    }

    fn clear_preflight(&mut self) {
        self.live_access = None;
    }

    fn attach(&mut self, process_id: ProcessId) -> Result<(), BackendFailure> {
        // SAFETY: the PID is a validated nonzero scalar. This call establishes
        // the debug connection owned by this same non-Send worker thread.
        if unsafe { DebugActiveProcess(process_id.get()) } == FALSE {
            Err(last_win32("attach to exact process"))
        } else {
            Ok(())
        }
    }

    fn disable_kill_on_exit(&mut self) -> Result<(), BackendFailure> {
        // SAFETY: this runs immediately after this thread's successful attach.
        // FALSE changes only this debug thread's current/future debuggees to
        // detach-on-thread-exit behavior.
        if unsafe { DebugSetProcessKillOnExit(FALSE) } == FALSE {
            Err(last_win32("disable process kill on debug-thread exit"))
        } else {
            Ok(())
        }
    }

    fn wait_for_debug_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<DebugEventRecord>, BackendFailure> {
        let mut event = DEBUG_EVENT::default();
        // SAFETY: `event` is initialized writable storage for the exact Win32
        // structure. The same thread that attached waits synchronously. Using
        // the Ex form opts this debugger into Unicode OutputDebugString data.
        if unsafe { WaitForDebugEventEx(&mut event, wait_timeout_millis(timeout)) } == FALSE {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32) {
                return Ok(None);
            }
            return Err(BackendFailure::new(
                "wait for initial debug event",
                source.to_string(),
            ));
        }
        Ok(Some(debug_event_record(event)))
    }

    fn close_debug_file(&mut self, file: DebugFileToken) {
        let handle = file.0 as RawHandle;
        debug_assert!(!handle.is_null());
        // SAFETY: tokens are created only from a non-null hFile in either a
        // CREATE_PROCESS or LOAD_DLL event and are removed from the event
        // before this one adoption. Process and thread handles are never
        // tokenized. OwnedHandle performs exactly one CloseHandle on drop.
        let file = unsafe { OwnedHandle::from_raw_handle(handle) };
        drop(file);
    }

    fn continue_debug_event(
        &mut self,
        process_id: u32,
        thread_id: u32,
        disposition: ContinueDisposition,
    ) -> Result<(), BackendFailure> {
        let status = match disposition {
            ContinueDisposition::Handled => DBG_CONTINUE,
            ContinueDisposition::ExceptionNotHandled => DBG_EXCEPTION_NOT_HANDLED,
        };
        // SAFETY: process/thread IDs come from the one currently retained
        // DEBUG_EVENT, and this is the same thread that received that event.
        if unsafe { ContinueDebugEvent(process_id, thread_id, status) } == FALSE {
            Err(last_win32("continue retained debug event"))
        } else {
            Ok(())
        }
    }

    fn read_exact_main_image_rva(
        &mut self,
        expected: &LiveTargetBinding,
        rva: u64,
        size: usize,
    ) -> Result<Vec<u8>, BackendFailure> {
        self.live_access
            .as_ref()
            .ok_or_else(|| {
                BackendFailure::new(
                    "read stopped main image",
                    "exact live-access preflight handle is absent",
                )
            })?
            .read_exact_rva(expected, rva, size)
            .map_err(|error| BackendFailure::new("read stopped main image", error.to_string()))
    }

    fn detach(&mut self, process_id: ProcessId) -> Result<(), BackendFailure> {
        // SAFETY: the PID is the exact retained binding for the debug
        // connection established by this same worker thread.
        if unsafe { DebugActiveProcessStop(process_id.get()) } == FALSE {
            Err(last_win32("stop debugging exact process"))
        } else {
            Ok(())
        }
    }
}

fn debug_event_record(event: DEBUG_EVENT) -> DebugEventRecord {
    let kind = match event.dwDebugEventCode {
        EXCEPTION_DEBUG_EVENT => {
            // SAFETY: dwDebugEventCode selects the Exception union member.
            let info = unsafe { event.u.Exception };
            DebugEventKind::Exception {
                code: info.ExceptionRecord.ExceptionCode as u32,
                first_chance: info.dwFirstChance != 0,
                address: info.ExceptionRecord.ExceptionAddress as usize as u64,
            }
        }
        CREATE_THREAD_DEBUG_EVENT => DebugEventKind::CreateThread,
        CREATE_PROCESS_DEBUG_EVENT => {
            // SAFETY: dwDebugEventCode selects CreateProcessInfo. Only hFile
            // and the value-only image base are consumed; hProcess/hThread
            // remain owned by the operating-system debugging lifecycle.
            let info = unsafe { event.u.CreateProcessInfo };
            DebugEventKind::CreateProcess {
                image_base: info.lpBaseOfImage as usize as u64,
                image_file: debug_file_token(info.hFile),
            }
        }
        EXIT_THREAD_DEBUG_EVENT => DebugEventKind::ExitThread,
        EXIT_PROCESS_DEBUG_EVENT => {
            // SAFETY: dwDebugEventCode selects ExitProcess.
            let info = unsafe { event.u.ExitProcess };
            DebugEventKind::ExitProcess {
                exit_code: info.dwExitCode,
            }
        }
        LOAD_DLL_DEBUG_EVENT => {
            // SAFETY: dwDebugEventCode selects LoadDll. Only its hFile is
            // copied into the worker's one-shot debug-file ledger.
            let info = unsafe { event.u.LoadDll };
            DebugEventKind::LoadDll {
                image_file: debug_file_token(info.hFile),
            }
        }
        UNLOAD_DLL_DEBUG_EVENT => DebugEventKind::UnloadDll,
        OUTPUT_DEBUG_STRING_EVENT => DebugEventKind::OutputDebugString,
        RIP_EVENT => DebugEventKind::Rip,
        code => DebugEventKind::Unknown { code },
    };
    DebugEventRecord {
        process_id: event.dwProcessId,
        thread_id: event.dwThreadId,
        kind,
    }
}

fn debug_file_token(handle: HANDLE) -> Option<DebugFileToken> {
    (!handle.is_null()).then_some(DebugFileToken(handle as usize))
}

fn wait_timeout_millis(timeout: Duration) -> u32 {
    let mut milliseconds = timeout.as_millis();
    if timeout.subsec_nanos() % 1_000_000 != 0 {
        milliseconds = milliseconds.saturating_add(1);
    }
    u32::try_from(milliseconds).unwrap_or(u32::MAX).max(1)
}

fn last_win32(operation: &'static str) -> BackendFailure {
    BackendFailure::new(operation, io::Error::last_os_error().to_string())
}
