//! Narrow Win32 debug-loop boundary.

use std::{
    io,
    os::windows::io::{FromRawHandle as _, OwnedHandle, RawHandle},
    time::{Duration, Instant},
};

use resymbol_debugger::{
    CommandEnvelope, HelperBuildId, HostRiskLease, LiveTargetBinding, MemoryAddress, ProcessId,
    ProvisioningEpoch, RemoteCommandCheckpoint, SessionId, SessionMachine, SessionState, StopToken,
    ValidatedLiveMemoryWrite,
};
use resymbol_windows_live_access::{
    LiveAccessError, MutatingLiveProcessAccess, OpenLiveProcessRequest, ReadOnlyLiveProcessAccess,
};
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
    BackendFailure, BackendWriteFailure, BackendWriteReceipt, ContinueDisposition,
    DebugAttachLimits, DebugAttachReceipt, DebugBackend, DebugEventKind, DebugEventRecord,
    DebugFileToken, DebugHostError, DebugHostMemoryWriteError, DebugHostMemoryWriteReceipt,
    DebugHostWorker, DebugHostWorkerState, PendingStopEvidence, SessionWorkerCleanupReceipt,
    SessionWorkerError, SessionWorkerHealth, SessionWorkerMemoryReadReceipt,
    SessionWorkerMemoryWriteReceipt, phase_one_capability_report,
    session_worker::SessionWorkerCore,
};

/// Single-thread owner of one phase-one Windows debug attachment.
///
/// The value is intentionally neither `Send` nor `Sync`. Construct, attach,
/// read, and detach it on the same dedicated session-worker thread.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct WindowsDebugHostWorker {
    inner: DebugHostWorker<WindowsDebugBackend>,
}

#[allow(dead_code)]
impl WindowsDebugHostWorker {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            inner: DebugHostWorker::new(WindowsDebugBackend::new()),
        }
    }

    /// Returns the static provider surface. The future authenticated helper
    /// transport remains responsible for deciding whether it may publish it.
    #[must_use]
    pub(crate) fn capabilities() -> resymbol_debugger::CapabilityReport {
        phase_one_capability_report()
    }

    #[must_use]
    pub(crate) fn state(&self) -> DebugHostWorkerState {
        self.inner.state()
    }

    #[must_use]
    pub(crate) fn binding(&self) -> Option<&LiveTargetBinding> {
        self.inner.binding()
    }

    #[must_use]
    pub(crate) fn pending_stop(&self) -> Option<&PendingStopEvidence> {
        self.inner.pending_stop()
    }

    /// Attaches only after the owning authenticated session worker has
    /// consumed authority for this exact process and attach mode.
    ///
    /// This low-level method does not authenticate its caller, a helper
    /// process, a transport, or a serialized lease identifier. Passing a
    /// `LiveTargetBinding` proves identity and mapping equality only. Do not
    /// call it directly from UI or untrusted command-dispatch code.
    pub(crate) fn attach_after_authorization(
        &mut self,
        expected: &LiveTargetBinding,
        limits: DebugAttachLimits,
    ) -> Result<PendingStopEvidence, DebugHostError> {
        self.inner.attach_after_authorization(expected, limits)
    }

    /// Reads a bounded span from the exact preflight main image while the
    /// initial attach breakpoint remains pending.
    pub(crate) fn read_stopped_main_image(
        &mut self,
        address: MemoryAddress,
        size: usize,
    ) -> Result<Vec<u8>, DebugHostError> {
        self.inner.read_stopped_main_image(address, size)
    }

    /// Performs one exact compare-before-write while the retained OS debug
    /// event remains pending. The ticket is minted only after host-local
    /// reducer acceptance and is consumed here exactly once. The separately
    /// retained checkpoint must match the ticket's reducer allocation and
    /// command ID. This worker also checks the ticket's exact target binding
    /// and the caller's retained operating-system stop before opening mutation
    /// rights.
    pub(crate) fn write_stopped_main_image_after_protocol_validation(
        &mut self,
        expected_pending_stop: &PendingStopEvidence,
        checkpoint: &RemoteCommandCheckpoint,
        write: ValidatedLiveMemoryWrite,
    ) -> Result<DebugHostMemoryWriteReceipt, DebugHostMemoryWriteError> {
        self.inner
            .write_stopped_main_image_after_protocol_validation(
                expected_pending_stop,
                checkpoint,
                write,
            )
    }

    /// Continues any retained event with its conservative disposition, then
    /// attempts `DebugActiveProcessStop` even if continuation fails. The error
    /// reports kill-policy, event-continuation, and detach outcomes
    /// independently. Invoke this explicitly: the worker's `Drop` cleanup is
    /// best effort and discards evidence, so it is never proof of detachment.
    pub(crate) fn detach(&mut self) -> Result<(), DebugHostError> {
        self.inner.detach()
    }
}

impl Default for WindowsDebugHostWorker {
    fn default() -> Self {
        Self::new()
    }
}

/// Authenticated same-thread owner of a Windows debug session.
///
/// Unlike [WindowsDebugHostWorker], this facade never accepts a pre-minted
/// write ticket or reducer checkpoint. It owns the session reducer, consumes
/// exact host-risk leases, and correlates every provider outcome before making
/// the resulting state visible.
///
/// Its observable axes have separate meanings: `state()` is the logical
/// reducer snapshot, `health()` gates further orchestration, and
/// `provider_state()` reports low-level OS attachment cleanup. Callers must not
/// infer one axis from another. In particular, `Closed` health means explicit
/// provider/core cleanup completed while `state()` remains the last reducer
/// snapshot; `CleanupRequired` and `Poisoned` accept only `cleanup()`.
///
/// ```compile_fail
/// use resymbol_windows_debug_host::WindowsSessionWorker;
///
/// fn require_send<T: Send>() {}
/// require_send::<WindowsSessionWorker>();
/// ```
///
/// ```compile_fail
/// use resymbol_windows_debug_host::WindowsSessionWorker;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<WindowsSessionWorker>();
/// ```
///
/// The unauthenticated low-level provider is intentionally not public:
///
/// ```compile_fail
/// use resymbol_windows_debug_host::WindowsDebugHostWorker;
/// ```
#[derive(Debug)]
pub struct WindowsSessionWorker {
    inner: SessionWorkerCore<WindowsDebugBackend>,
    attach_limits: DebugAttachLimits,
}

impl WindowsSessionWorker {
    #[must_use]
    pub fn new(
        session_id: SessionId,
        provisioning_epoch: ProvisioningEpoch,
        helper_build: HelperBuildId,
        attach_limits: DebugAttachLimits,
    ) -> Self {
        Self {
            inner: SessionWorkerCore::new(
                SessionMachine::new(session_id, provisioning_epoch, helper_build),
                WindowsDebugBackend::new(),
            ),
            attach_limits,
        }
    }

    #[must_use]
    pub fn capabilities() -> resymbol_debugger::CapabilityReport {
        phase_one_capability_report()
    }

    #[must_use]
    pub const fn state(&self) -> &SessionState {
        self.inner.state()
    }

    #[must_use]
    pub const fn health(&self) -> SessionWorkerHealth {
        self.inner.health()
    }

    #[must_use]
    pub fn provider_state(&self) -> DebugHostWorkerState {
        self.inner.provider_state()
    }

    #[must_use]
    pub fn binding(&self) -> Option<&LiveTargetBinding> {
        self.inner.binding()
    }

    #[must_use]
    pub fn pending_stop(&self) -> Option<&PendingStopEvidence> {
        self.inner.pending_stop()
    }

    /// Registers one move-only host approval directly in the owned reducer.
    pub fn register_host_risk_lease(
        &mut self,
        lease: HostRiskLease,
    ) -> Result<(), SessionWorkerError> {
        self.inner.register_host_risk_lease(lease)
    }

    /// Accepts, authorizes, and executes one exact host debug-attach command.
    pub fn open_debug_attach(
        &mut self,
        envelope: CommandEnvelope,
        binding: LiveTargetBinding,
    ) -> Result<DebugAttachReceipt, SessionWorkerError> {
        self.inner
            .open_debug_attach(envelope, binding, self.attach_limits)
    }

    /// Validates and executes one stopped-memory read from its envelope.
    pub fn read_memory(
        &mut self,
        envelope: CommandEnvelope,
    ) -> Result<SessionWorkerMemoryReadReceipt, SessionWorkerError> {
        self.inner.read_memory(envelope)
    }

    /// Validates and executes one stopped-memory command from its envelope.
    pub fn write_memory(
        &mut self,
        envelope: CommandEnvelope,
    ) -> Result<SessionWorkerMemoryWriteReceipt, SessionWorkerError> {
        self.inner.write_memory(envelope)
    }

    /// Attempts explicit provider cleanup.
    ///
    /// This owner becomes terminally `Closed` only when the returned receipt's
    /// `complete()` is true. Incomplete cleanup remains retryable when the
    /// provider is still attached, or sticky and `Poisoned` when detach already
    /// made missing cleanup evidence unrecoverable. Completion does not
    /// synthesize a logical `SessionState::Closed` or a controller close
    /// receipt; the receipt exposes the last reducer snapshot.
    pub fn cleanup(&mut self) -> SessionWorkerCleanupReceipt {
        self.inner.cleanup()
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

    fn write_exact_main_image_rva(
        &mut self,
        expected: &LiveTargetBinding,
        validated_protocol_stop: StopToken,
        address: MemoryAddress,
        rva: u64,
        expected_bytes: &[u8],
        replacement: &[u8],
    ) -> Result<BackendWriteReceipt, BackendWriteFailure> {
        let process = expected.process();
        let request = OpenLiveProcessRequest::new(
            process.process_id,
            process.start_key,
            expected.actual_image_base(),
            expected.main_module_binary_id().clone(),
        );
        // Mutation rights exist only for this one stopped write boundary. The
        // long-lived preflight handle remains read-only.
        let mut access = MutatingLiveProcessAccess::open_mutating(request).map_err(|error| {
            adapt_write_failure(
                &error,
                validated_protocol_stop,
                address,
                expected_bytes.len(),
            )
        })?;
        let receipt = access
            .compare_before_write_rva(expected, rva, expected_bytes, replacement)
            .map_err(|error| {
                adapt_write_failure(
                    &error,
                    validated_protocol_stop,
                    address,
                    expected_bytes.len(),
                )
            })?;
        Ok(BackendWriteReceipt {
            binding: receipt.binding().clone(),
            rva: receipt.rva(),
            bytes_written: receipt.bytes_written(),
        })
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

fn adapt_write_failure(
    error: &LiveAccessError,
    validated_protocol_stop: StopToken,
    address: MemoryAddress,
    size: usize,
) -> BackendWriteFailure {
    let detail = error.to_string();
    match error.to_memory_write_failure(validated_protocol_stop, address, size) {
        Ok(Some(failure)) => BackendWriteFailure::MemoryWriteFailed(failure),
        Ok(None) if target_invalidated(error) => BackendWriteFailure::TargetInvalidated { detail },
        Ok(None) if safe_no_effect_rejection(error) => BackendWriteFailure::SafeNoEffect { detail },
        Ok(None) => BackendWriteFailure::InvalidEvidence {
            detail: format!("unexpected non-transaction write failure: {detail}"),
        },
        Err(evidence_error) => BackendWriteFailure::InvalidEvidence {
            detail: format!("{detail}; invalid protocol evidence: {evidence_error}"),
        },
    }
}

fn safe_no_effect_rejection(error: &LiveAccessError) -> bool {
    matches!(
        error,
        LiveAccessError::InvalidRequest(_)
            | LiveAccessError::Win32 { .. }
            | LiveAccessError::ExecutableIo { .. }
            | LiveAccessError::RvaRange(_)
            | LiveAccessError::AddressDoesNotFitPointer
            | LiveAccessError::PartialRead { .. }
            | LiveAccessError::PartialMemoryRegionQuery { .. }
            | LiveAccessError::CompareMismatch { .. }
            | LiveAccessError::UnsafeWriteRegion
            | LiveAccessError::InvalidSystemPageSize
    )
}

fn target_invalidated(error: &LiveAccessError) -> bool {
    matches!(
        error,
        LiveAccessError::ProcessExited
            | LiveAccessError::ProcessIdChanged
            | LiveAccessError::ProcessStartIdentityChanged
            | LiveAccessError::ProcessStartIdentityMismatch { .. }
            | LiveAccessError::ZeroProcessStartKey
            | LiveAccessError::InvalidExecutablePath
            | LiveAccessError::ExecutableNotRegular { .. }
            | LiveAccessError::ExecutableChangedDuringIdentity
            | LiveAccessError::ExecutablePathChanged
            | LiveAccessError::ExecutableEvidenceChanged
            | LiveAccessError::BinaryIdentityMismatch { .. }
            | LiveAccessError::InvalidPeImage { .. }
            | LiveAccessError::PeHeaderOutOfRange
            | LiveAccessError::ModuleProcessMismatch
            | LiveAccessError::EmptyMainModule
            | LiveAccessError::InvalidMainModulePath
            | LiveAccessError::MainModulePathMismatch
            | LiveAccessError::MainModuleBaseMismatch { .. }
            | LiveAccessError::MainModuleRangeOverflow
            | LiveAccessError::FileModuleSizeMismatch { .. }
            | LiveAccessError::RemoteModuleSizeMismatch { .. }
            | LiveAccessError::InvalidMainModuleMapping
            | LiveAccessError::MainModuleRegionLimitExceeded { .. }
            | LiveAccessError::BindingConstruction(_)
            | LiveAccessError::BindingMismatch
    )
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
