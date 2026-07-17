//! Same-thread, read-only Windows debug-attach foundation.
//!
//! This crate is a low-level provider boundary, not ReSymbol's authenticated
//! live-helper transport and not a UI bridge. `WindowsDebugHostWorker` makes
//! prior authorization explicit in its attach method name, but cannot prove
//! that a caller consumed a move-only host-risk lease. The future authenticated
//! `SessionWorker` must own this value, its `SessionMachine`, and the exact
//! accepted command transaction on the same thread.
//!
//! Phase one deliberately exposes only host attach and stopped main-image
//! reads. It has no continue, pause, step, register, breakpoint, write, launch,
//! or sandbox-provisioning API.

#![deny(unsafe_op_in_unsafe_fn)]

use std::{fmt, time::Duration};

#[cfg(any(windows, test))]
use std::{marker::PhantomData, rc::Rc};

use resymbol_debugger::{
    CapabilityAvailability, CapabilityReport, CapabilityStatus, CapabilityUnavailableCode,
    DebugCapability, LiveTargetBindingError, MemoryAddress, ProcessId, ThreadId,
};
use thiserror::Error;

#[cfg(any(windows, test))]
use resymbol_debugger::LiveTargetBinding;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::WindowsDebugHostWorker;

/// Hard ceiling on the finite current-state event drain before attach fails
/// closed and attempts to detach.
pub const MAX_INITIAL_DRAIN_EVENTS: usize = 65_536;
pub const DEFAULT_INITIAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_INITIAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Bounded resources for one current-state attach drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugAttachLimits {
    initial_drain_timeout: Duration,
}

impl DebugAttachLimits {
    pub fn new(initial_drain_timeout: Duration) -> Result<Self, DebugAttachLimitsError> {
        if initial_drain_timeout.is_zero() {
            return Err(DebugAttachLimitsError::ZeroInitialDrainTimeout);
        }
        if initial_drain_timeout > MAX_INITIAL_DRAIN_TIMEOUT {
            return Err(DebugAttachLimitsError::InitialDrainTimeoutTooLarge {
                actual: initial_drain_timeout,
                maximum: MAX_INITIAL_DRAIN_TIMEOUT,
            });
        }
        Ok(Self {
            initial_drain_timeout,
        })
    }

    #[must_use]
    pub const fn initial_drain_timeout(self) -> Duration {
        self.initial_drain_timeout
    }
}

impl Default for DebugAttachLimits {
    fn default() -> Self {
        Self {
            initial_drain_timeout: DEFAULT_INITIAL_DRAIN_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum DebugAttachLimitsError {
    #[error("initial debug-event drain timeout must be nonzero")]
    ZeroInitialDrainTimeout,
    #[error("initial debug-event drain timeout {actual:?} exceeds {maximum:?}")]
    InitialDrainTimeoutTooLarge { actual: Duration, maximum: Duration },
}

/// Static phase-one provider capability contract.
///
/// A transport must not publish this report until it has independently
/// authenticated its helper channel and installed the host-local authorization
/// control plane. This value describes only the implemented provider surface.
#[must_use]
pub fn phase_one_capability_report() -> CapabilityReport {
    phase_one_capability_report_for_platform(cfg!(windows))
}

fn phase_one_capability_report_for_platform(windows_supported: bool) -> CapabilityReport {
    CapabilityReport {
        statuses: DebugCapability::ALL
            .into_iter()
            .map(|capability| phase_one_capability_status(capability, windows_supported))
            .collect(),
    }
}

fn phase_one_capability_status(
    capability: DebugCapability,
    windows_supported: bool,
) -> CapabilityStatus {
    let availability = match capability {
        DebugCapability::LiveMemoryRead | DebugCapability::HostAttach if windows_supported => {
            CapabilityAvailability::Available
        }
        DebugCapability::LiveMemoryRead | DebugCapability::HostAttach => {
            CapabilityAvailability::Unavailable {
                code: CapabilityUnavailableCode::UnsupportedPlatform,
                reason: "phase-one debug attach is available only on Windows".to_owned(),
            }
        }
        DebugCapability::LiveMemoryWrite
        | DebugCapability::ExecutionControl
        | DebugCapability::StepInto
        | DebugCapability::StepOver
        | DebugCapability::StepOut
        | DebugCapability::RegisterRead
        | DebugCapability::RegisterWrite
        | DebugCapability::SoftwareBreakpoints
        | DebugCapability::HardwareBreakpoints => CapabilityAvailability::Unavailable {
            code: CapabilityUnavailableCode::TargetModeReadOnly,
            reason: "phase-one Windows debug attach is stopped and read-only".to_owned(),
        },
        DebugCapability::OfflineAnalysis
        | DebugCapability::DumpRead
        | DebugCapability::SnapshotRead
        | DebugCapability::ObserveProcess
        | DebugCapability::SandboxedLaunch
        | DebugCapability::HostLaunch => CapabilityAvailability::Unavailable {
            code: CapabilityUnavailableCode::BackendUnavailable,
            reason: "phase-one Windows debug host implements only attach and live reads".to_owned(),
        },
    };
    CapabilityStatus {
        capability,
        availability,
    }
}

/// Externally observable lifecycle of the single-owner worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugHostWorkerState {
    Detached,
    DrainingInitialEvents,
    Stopped,
    CleanupRequired,
}

impl fmt::Display for DebugHostWorkerState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Detached => formatter.write_str("detached"),
            Self::DrainingInitialEvents => formatter.write_str("draining initial events"),
            Self::Stopped => formatter.write_str("stopped"),
            Self::CleanupRequired => formatter.write_str("cleanup required"),
        }
    }
}

/// Value-only correlation for the retained initial breakpoint.
///
/// This cloneable evidence is not authority. The worker privately retains the
/// actual pending operating-system debug event until explicit or failure-path
/// cleanup continues it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "the pending-stop evidence correlates reads and later cleanup"]
pub struct PendingStopEvidence {
    process_id: ProcessId,
    thread_id: ThreadId,
    exception_address: MemoryAddress,
}

impl PendingStopEvidence {
    #[must_use]
    pub const fn process_id(&self) -> ProcessId {
        self.process_id
    }

    #[must_use]
    pub const fn thread_id(&self) -> ThreadId {
        self.thread_id
    }

    #[must_use]
    pub const fn exception_address(&self) -> MemoryAddress {
        self.exception_address
    }
}

/// Independently reported result of one cleanup step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupStepOutcome {
    NotRequired,
    Succeeded,
    Failed {
        operation: &'static str,
        detail: String,
    },
}

impl CleanupStepOutcome {
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self, Self::Succeeded)
    }

    fn complete_or_not_required(&self) -> bool {
        matches!(self, Self::NotRequired | Self::Succeeded)
    }
}

impl fmt::Display for CleanupStepOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRequired => formatter.write_str("not required"),
            Self::Succeeded => formatter.write_str("succeeded"),
            Self::Failed { operation, detail } => {
                write!(formatter, "{operation} failed: {detail}")
            }
        }
    }
}

/// Separate evidence for clearing a pending event and stopping debug attach.
///
/// `DebugActiveProcessStop` is attempted even when `ContinueDebugEvent` fails.
/// Therefore the caller can distinguish incomplete event cleanup from an
/// unconfirmed attachment release without inferring one outcome from the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugHostCleanupEvidence {
    pub detach_on_thread_exit: CleanupStepOutcome,
    pub continue_event: CleanupStepOutcome,
    pub detach: CleanupStepOutcome,
}

impl DebugHostCleanupEvidence {
    #[must_use]
    pub fn complete(&self) -> bool {
        self.detach_on_thread_exit.complete_or_not_required()
            && self.continue_event.complete_or_not_required()
            && self.detach.succeeded()
    }

    /// True when `DebugActiveProcessStop` did not confirm release. This makes
    /// no stronger claim that the target is definitely still attached.
    #[must_use]
    pub fn attachment_release_unconfirmed(&self) -> bool {
        !self.detach.succeeded()
    }
}

impl fmt::Display for DebugHostCleanupEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "detach_on_thread_exit=({}), continue_event=({}), detach=({})",
            self.detach_on_thread_exit, self.continue_event, self.detach
        )
    }
}

#[derive(Debug, Error)]
pub enum DebugHostError {
    #[error("debug-host worker is {state}; attach requires the detached state")]
    AttachWhileBusy { state: DebugHostWorkerState },
    #[error("debug-host worker is already detached")]
    AlreadyDetached,
    #[error("live memory is readable only while an operating-system debug event is pending")]
    NotStopped,
    #[error("preflight returned a different live-target binding")]
    PreflightBindingMismatch,
    #[error("first attach event must be CREATE_PROCESS_DEBUG_EVENT, received code {actual_code}")]
    CreateProcessNotFirst { actual_code: u32 },
    #[error("CREATE_PROCESS_DEBUG_EVENT appeared more than once during initial attach")]
    DuplicateCreateProcess,
    #[error("debug event PID {actual} differs from the exact attached process PID {expected}")]
    EventProcessMismatch { expected: u32, actual: u32 },
    #[error("debug event for PID {process_id} carried an invalid zero thread identifier")]
    ZeroEventThreadId { process_id: u32 },
    #[error("CREATE_PROCESS image base {actual:#x} differs from preflight evidence {expected:#x}")]
    CreateProcessBaseMismatch { expected: u64, actual: u64 },
    #[error("initial breakpoint arrived before exact CREATE_PROCESS evidence")]
    InitialBreakpointBeforeCreateProcess,
    #[error("unexpected exception {code:#010x} (first_chance={first_chance}) during attach drain")]
    UnexpectedInitialException { code: u32, first_chance: bool },
    #[error("target exited with code {exit_code:#010x} before the initial breakpoint")]
    TargetExitedDuringAttach { exit_code: u32 },
    #[error("RIP or unknown debug event code {code} interrupted the initial attach drain")]
    UnexpectedInitialEvent { code: u32 },
    #[error("initial attach exceeded the {maximum}-event drain ceiling")]
    InitialDrainLimitExceeded { maximum: usize },
    #[error("initial debug-event drain exceeded its total {timeout:?} deadline")]
    InitialDrainDeadlineExceeded { timeout: Duration },
    #[error("{operation} failed: {detail}")]
    Provider {
        operation: &'static str,
        detail: String,
    },
    #[error("{cause}; cleanup outcome: {evidence}")]
    CleanupAfterFailure {
        #[source]
        cause: Box<DebugHostError>,
        evidence: DebugHostCleanupEvidence,
    },
    #[error("detach cleanup was incomplete: {evidence}")]
    DetachCleanupIncomplete { evidence: DebugHostCleanupEvidence },
    #[error("main-image address validation failed: {0}")]
    AddressRange(#[from] LiveTargetBindingError),
}

#[derive(Debug)]
#[cfg(any(windows, test))]
struct BackendFailure {
    operation: &'static str,
    detail: String,
}

#[cfg(any(windows, test))]
impl BackendFailure {
    fn new(operation: &'static str, detail: impl Into<String>) -> Self {
        Self {
            operation,
            detail: detail.into(),
        }
    }

    fn into_public(self) -> DebugHostError {
        DebugHostError::Provider {
            operation: self.operation,
            detail: self.detail,
        }
    }
}

#[cfg(any(windows, test))]
impl fmt::Display for BackendFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} failed: {}", self.operation, self.detail)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(windows, test))]
struct DebugFileToken(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(windows, test))]
enum ContinueDisposition {
    Handled,
    ExceptionNotHandled,
}

#[derive(Debug)]
#[cfg(any(windows, test))]
struct DebugEventRecord {
    process_id: u32,
    thread_id: u32,
    kind: DebugEventKind,
}

#[cfg(any(windows, test))]
impl DebugEventRecord {
    fn code(&self) -> u32 {
        self.kind.code()
    }

    fn take_debug_file(&mut self) -> Option<DebugFileToken> {
        match &mut self.kind {
            DebugEventKind::CreateProcess { image_file, .. }
            | DebugEventKind::LoadDll { image_file } => image_file.take(),
            DebugEventKind::Exception { .. }
            | DebugEventKind::CreateThread
            | DebugEventKind::ExitThread
            | DebugEventKind::ExitProcess { .. }
            | DebugEventKind::UnloadDll
            | DebugEventKind::OutputDebugString
            | DebugEventKind::Rip
            | DebugEventKind::Unknown { .. } => None,
        }
    }
}

#[derive(Debug)]
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
enum DebugEventKind {
    Exception {
        code: u32,
        first_chance: bool,
        address: u64,
    },
    CreateThread,
    CreateProcess {
        image_base: u64,
        image_file: Option<DebugFileToken>,
    },
    ExitThread,
    ExitProcess {
        exit_code: u32,
    },
    LoadDll {
        image_file: Option<DebugFileToken>,
    },
    UnloadDll,
    OutputDebugString,
    Rip,
    Unknown {
        code: u32,
    },
}

#[cfg(any(windows, test))]
impl DebugEventKind {
    const fn code(&self) -> u32 {
        match self {
            Self::Exception { .. } => 1,
            Self::CreateThread => 2,
            Self::CreateProcess { .. } => 3,
            Self::ExitThread => 4,
            Self::ExitProcess { .. } => 5,
            Self::LoadDll { .. } => 6,
            Self::UnloadDll => 7,
            Self::OutputDebugString => 8,
            Self::Rip => 9,
            Self::Unknown { code } => *code,
        }
    }
}

#[cfg(any(windows, test))]
trait DebugBackend {
    fn monotonic_now(&self) -> Duration;

    fn preflight(
        &mut self,
        expected: &LiveTargetBinding,
    ) -> Result<LiveTargetBinding, BackendFailure>;

    fn clear_preflight(&mut self);

    fn attach(&mut self, process_id: ProcessId) -> Result<(), BackendFailure>;

    fn disable_kill_on_exit(&mut self) -> Result<(), BackendFailure>;

    fn wait_for_debug_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<DebugEventRecord>, BackendFailure>;

    fn close_debug_file(&mut self, file: DebugFileToken);

    fn continue_debug_event(
        &mut self,
        process_id: u32,
        thread_id: u32,
        disposition: ContinueDisposition,
    ) -> Result<(), BackendFailure>;

    fn read_exact_main_image_rva(
        &mut self,
        expected: &LiveTargetBinding,
        rva: u64,
        size: usize,
    ) -> Result<Vec<u8>, BackendFailure>;

    fn detach(&mut self, process_id: ProcessId) -> Result<(), BackendFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(windows, test))]
enum AttachedPhase {
    Draining,
    Stopped,
    CleanupRequired,
}

#[derive(Debug)]
#[cfg(any(windows, test))]
struct AttachedState {
    binding: LiveTargetBinding,
    phase: AttachedPhase,
    detach_on_thread_exit: bool,
    pending: Option<DebugEventRecord>,
    pending_disposition: Option<ContinueDisposition>,
    stop: Option<PendingStopEvidence>,
}

#[derive(Debug)]
#[cfg(any(windows, test))]
enum WorkerState {
    Detached,
    Attached(AttachedState),
}

/// Platform-independent worker core. The real Windows wrapper and deterministic
/// fake tests both drive this exact ordering reducer.
#[derive(Debug)]
#[cfg(any(windows, test))]
struct DebugHostWorker<B: DebugBackend> {
    backend: B,
    state: WorkerState,
    // DebugActiveProcess, WaitForDebugEventEx, ContinueDebugEvent, and detach
    // must remain on one owning OS thread. This marker prevents transfer or
    // sharing even when a backend's fields would otherwise permit it.
    _thread_affinity: PhantomData<Rc<()>>,
}

#[cfg(any(windows, test))]
impl<B: DebugBackend> DebugHostWorker<B> {
    fn new(backend: B) -> Self {
        Self {
            backend,
            state: WorkerState::Detached,
            _thread_affinity: PhantomData,
        }
    }

    fn state(&self) -> DebugHostWorkerState {
        match &self.state {
            WorkerState::Detached => DebugHostWorkerState::Detached,
            WorkerState::Attached(attached) => match attached.phase {
                AttachedPhase::Draining => DebugHostWorkerState::DrainingInitialEvents,
                AttachedPhase::Stopped => DebugHostWorkerState::Stopped,
                AttachedPhase::CleanupRequired => DebugHostWorkerState::CleanupRequired,
            },
        }
    }

    fn binding(&self) -> Option<&LiveTargetBinding> {
        match &self.state {
            WorkerState::Detached => None,
            WorkerState::Attached(attached) => Some(&attached.binding),
        }
    }

    fn pending_stop(&self) -> Option<&PendingStopEvidence> {
        match &self.state {
            WorkerState::Attached(AttachedState {
                phase: AttachedPhase::Stopped,
                stop: Some(stop),
                ..
            }) => Some(stop),
            WorkerState::Detached | WorkerState::Attached(_) => None,
        }
    }

    /// Low-level provider entry point. Its name records a prerequisite; it
    /// does not create or verify authorization.
    fn attach_after_authorization(
        &mut self,
        expected: &LiveTargetBinding,
        limits: DebugAttachLimits,
    ) -> Result<PendingStopEvidence, DebugHostError> {
        if !matches!(&self.state, WorkerState::Detached) {
            return Err(DebugHostError::AttachWhileBusy {
                state: self.state(),
            });
        }

        let observed = match self.backend.preflight(expected) {
            Ok(observed) => observed,
            Err(error) => {
                self.backend.clear_preflight();
                return Err(error.into_public());
            }
        };
        if &observed != expected {
            self.backend.clear_preflight();
            return Err(DebugHostError::PreflightBindingMismatch);
        }

        let process_id = expected.process().process_id;
        if let Err(error) = self.backend.attach(process_id) {
            self.backend.clear_preflight();
            return Err(error.into_public());
        }
        self.state = WorkerState::Attached(AttachedState {
            binding: observed,
            phase: AttachedPhase::Draining,
            detach_on_thread_exit: false,
            pending: None,
            pending_disposition: None,
            stop: None,
        });

        // This must be the first operation after a successful attach. The
        // setting is thread-wide and makes worker loss detach rather than kill.
        if let Err(error) = self.backend.disable_kill_on_exit() {
            return Err(self.abort_attached(error.into_public()));
        }
        self.attached_mut().detach_on_thread_exit = true;

        let drain_timeout = limits.initial_drain_timeout();
        let drain_deadline = self.backend.monotonic_now().saturating_add(drain_timeout);
        let mut saw_create_process = false;
        for event_index in 0..MAX_INITIAL_DRAIN_EVENTS {
            let Some(remaining) = drain_deadline
                .checked_sub(self.backend.monotonic_now())
                .filter(|remaining| !remaining.is_zero())
            else {
                return Err(
                    self.abort_attached(DebugHostError::InitialDrainDeadlineExceeded {
                        timeout: drain_timeout,
                    }),
                );
            };
            let event = match self.backend.wait_for_debug_event(remaining) {
                Ok(Some(event)) => event,
                Ok(None) => {
                    return Err(self.abort_attached(
                        DebugHostError::InitialDrainDeadlineExceeded {
                            timeout: drain_timeout,
                        },
                    ));
                }
                Err(error) => return Err(self.abort_attached(error.into_public())),
            };
            self.set_pending(event);
            self.close_pending_debug_file();
            // A backend can report an event at its timeout boundary and this
            // worker can be rescheduled only after the total deadline. Retain
            // it first so cleanup can conservatively continue it, but never
            // classify or accept a stop once the monotonic budget has expired.
            if self.backend.monotonic_now() >= drain_deadline {
                return Err(
                    self.abort_attached(DebugHostError::InitialDrainDeadlineExceeded {
                        timeout: drain_timeout,
                    }),
                );
            }

            let action = match self.classify_pending_initial_event(
                expected,
                event_index,
                saw_create_process,
            ) {
                Ok(action) => action,
                Err(error) => return Err(self.abort_attached(error)),
            };

            match action {
                InitialDrainAction::Continue { saw_create } => {
                    saw_create_process |= saw_create;
                    if let Err(error) = self.continue_pending() {
                        return Err(self.abort_attached(error.into_public()));
                    }
                }
                InitialDrainAction::Stop(stop) => {
                    let attached = self.attached_mut();
                    attached.phase = AttachedPhase::Stopped;
                    attached.pending_disposition = Some(ContinueDisposition::Handled);
                    attached.stop = Some(stop.clone());
                    debug_assert!(attached.pending.is_some());
                    return Ok(stop);
                }
                InitialDrainAction::Exit { exit_code } => {
                    if let Err(error) = self.continue_pending() {
                        return Err(self.abort_attached(error.into_public()));
                    }
                    self.backend.clear_preflight();
                    self.state = WorkerState::Detached;
                    return Err(DebugHostError::TargetExitedDuringAttach { exit_code });
                }
            }
        }

        Err(
            self.abort_attached(DebugHostError::InitialDrainLimitExceeded {
                maximum: MAX_INITIAL_DRAIN_EVENTS,
            }),
        )
    }

    fn read_stopped_main_image(
        &mut self,
        address: MemoryAddress,
        size: usize,
    ) -> Result<Vec<u8>, DebugHostError> {
        let binding = match &self.state {
            WorkerState::Attached(AttachedState {
                binding,
                phase: AttachedPhase::Stopped,
                pending: Some(_),
                ..
            }) => binding.clone(),
            WorkerState::Detached | WorkerState::Attached(_) => {
                return Err(DebugHostError::NotStopped);
            }
        };
        let size_u64 = u64::try_from(size).unwrap_or(u64::MAX);
        let rva = binding.rva_for_address_span(address, size_u64)?;
        self.backend
            .read_exact_main_image_rva(&binding, rva, size)
            .map_err(BackendFailure::into_public)
    }

    fn detach(&mut self) -> Result<(), DebugHostError> {
        if matches!(&self.state, WorkerState::Detached) {
            return Err(DebugHostError::AlreadyDetached);
        }
        let evidence = self.attempt_cleanup();
        if evidence.complete() {
            Ok(())
        } else {
            Err(DebugHostError::DetachCleanupIncomplete { evidence })
        }
    }

    fn set_pending(&mut self, event: DebugEventRecord) {
        let attached = self.attached_mut();
        debug_assert!(attached.pending.is_none());
        debug_assert!(attached.pending_disposition.is_none());
        attached.pending_disposition = Some(match &event.kind {
            DebugEventKind::Exception { .. } => ContinueDisposition::ExceptionNotHandled,
            DebugEventKind::CreateThread
            | DebugEventKind::CreateProcess { .. }
            | DebugEventKind::ExitThread
            | DebugEventKind::ExitProcess { .. }
            | DebugEventKind::LoadDll { .. }
            | DebugEventKind::UnloadDll
            | DebugEventKind::OutputDebugString
            | DebugEventKind::Rip
            | DebugEventKind::Unknown { .. } => ContinueDisposition::Handled,
        });
        attached.pending = Some(event);
    }

    fn close_pending_debug_file(&mut self) {
        let file = self
            .attached_mut()
            .pending
            .as_mut()
            .and_then(DebugEventRecord::take_debug_file);
        if let Some(file) = file {
            self.backend.close_debug_file(file);
        }
    }

    fn classify_pending_initial_event(
        &self,
        expected: &LiveTargetBinding,
        event_index: usize,
        saw_create_process: bool,
    ) -> Result<InitialDrainAction, DebugHostError> {
        let event = self
            .attached()
            .pending
            .as_ref()
            .expect("classification requires one retained pending event");
        let expected_pid = expected.process().process_id.get();
        if event.process_id != expected_pid {
            return Err(DebugHostError::EventProcessMismatch {
                expected: expected_pid,
                actual: event.process_id,
            });
        }
        let thread_id =
            ThreadId::new(event.thread_id).map_err(|_| DebugHostError::ZeroEventThreadId {
                process_id: event.process_id,
            })?;

        if event_index == 0 && !matches!(&event.kind, DebugEventKind::CreateProcess { .. }) {
            return Err(DebugHostError::CreateProcessNotFirst {
                actual_code: event.code(),
            });
        }

        match &event.kind {
            DebugEventKind::CreateProcess { image_base, .. } => {
                if saw_create_process {
                    return Err(DebugHostError::DuplicateCreateProcess);
                }
                let expected_base = expected.actual_image_base().get();
                if *image_base != expected_base {
                    return Err(DebugHostError::CreateProcessBaseMismatch {
                        expected: expected_base,
                        actual: *image_base,
                    });
                }
                Ok(InitialDrainAction::Continue { saw_create: true })
            }
            DebugEventKind::Exception {
                code,
                first_chance,
                address,
            } => {
                if !saw_create_process {
                    return Err(DebugHostError::InitialBreakpointBeforeCreateProcess);
                }
                if *code != EXCEPTION_BREAKPOINT_CODE || !*first_chance {
                    return Err(DebugHostError::UnexpectedInitialException {
                        code: *code,
                        first_chance: *first_chance,
                    });
                }
                Ok(InitialDrainAction::Stop(PendingStopEvidence {
                    process_id: expected.process().process_id,
                    thread_id,
                    exception_address: MemoryAddress::new(*address),
                }))
            }
            DebugEventKind::ExitProcess { exit_code } => Ok(InitialDrainAction::Exit {
                exit_code: *exit_code,
            }),
            DebugEventKind::Rip | DebugEventKind::Unknown { .. } => {
                Err(DebugHostError::UnexpectedInitialEvent { code: event.code() })
            }
            DebugEventKind::CreateThread
            | DebugEventKind::ExitThread
            | DebugEventKind::LoadDll { .. }
            | DebugEventKind::UnloadDll
            | DebugEventKind::OutputDebugString => {
                if !saw_create_process {
                    return Err(DebugHostError::CreateProcessNotFirst {
                        actual_code: event.code(),
                    });
                }
                Ok(InitialDrainAction::Continue { saw_create: false })
            }
        }
    }

    fn continue_pending(&mut self) -> Result<(), BackendFailure> {
        let (process_id, thread_id, disposition) = {
            let attached = self.attached();
            let event = attached
                .pending
                .as_ref()
                .expect("continue requires one retained pending event");
            let disposition = attached
                .pending_disposition
                .expect("pending event requires one retained disposition");
            (event.process_id, event.thread_id, disposition)
        };
        self.backend
            .continue_debug_event(process_id, thread_id, disposition)?;
        let attached = self.attached_mut();
        attached.pending = None;
        attached.pending_disposition = None;
        Ok(())
    }

    fn abort_attached(&mut self, cause: DebugHostError) -> DebugHostError {
        let evidence = self.attempt_cleanup();
        if evidence.complete() {
            cause
        } else {
            DebugHostError::CleanupAfterFailure {
                cause: Box::new(cause),
                evidence,
            }
        }
    }

    fn attempt_cleanup(&mut self) -> DebugHostCleanupEvidence {
        let process_id = self.attached().binding.process().process_id;
        let detach_on_thread_exit = if self.attached().detach_on_thread_exit {
            CleanupStepOutcome::NotRequired
        } else {
            match self.backend.disable_kill_on_exit() {
                Ok(()) => {
                    self.attached_mut().detach_on_thread_exit = true;
                    CleanupStepOutcome::Succeeded
                }
                Err(error) => CleanupStepOutcome::Failed {
                    operation: error.operation,
                    detail: error.detail,
                },
            }
        };
        let continue_event = if self.attached().pending.is_some() {
            match self.continue_pending() {
                Ok(()) => CleanupStepOutcome::Succeeded,
                Err(error) => CleanupStepOutcome::Failed {
                    operation: error.operation,
                    detail: error.detail,
                },
            }
        } else {
            CleanupStepOutcome::NotRequired
        };

        let detach = match self.backend.detach(process_id) {
            Ok(()) => CleanupStepOutcome::Succeeded,
            Err(error) => CleanupStepOutcome::Failed {
                operation: error.operation,
                detail: error.detail,
            },
        };
        if detach.succeeded() {
            self.backend.clear_preflight();
            self.state = WorkerState::Detached;
        } else {
            self.attached_mut().phase = AttachedPhase::CleanupRequired;
        }
        DebugHostCleanupEvidence {
            detach_on_thread_exit,
            continue_event,
            detach,
        }
    }

    fn attached(&self) -> &AttachedState {
        match &self.state {
            WorkerState::Attached(attached) => attached,
            WorkerState::Detached => unreachable!("attached operation requires attached state"),
        }
    }

    fn attached_mut(&mut self) -> &mut AttachedState {
        match &mut self.state {
            WorkerState::Attached(attached) => attached,
            WorkerState::Detached => unreachable!("attached operation requires attached state"),
        }
    }
}

#[cfg(any(windows, test))]
impl<B: DebugBackend> Drop for DebugHostWorker<B> {
    fn drop(&mut self) {
        if matches!(&self.state, WorkerState::Detached) {
            return;
        }
        // Last-resort safety only: Drop cannot surface cleanup evidence. Only
        // the result of an explicit `detach` call can prove cleanup outcomes.
        let _discarded_cleanup_evidence = self.attempt_cleanup();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(windows, test))]
enum InitialDrainAction {
    Continue { saw_create: bool },
    Stop(PendingStopEvidence),
    Exit { exit_code: u32 },
}

#[cfg(any(windows, test))]
const EXCEPTION_BREAKPOINT_CODE: u32 = 0x8000_0003;

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        time::Duration,
    };

    use resymbol_core::BinaryId;
    use resymbol_debugger::{
        CapabilityAvailability, DebugCapability, LiveTargetBinding, MemoryAddress, ProcessId,
        ProcessIdentity, ProcessStartKey,
    };

    use super::{
        BackendFailure, CleanupStepOutcome, ContinueDisposition, DebugAttachLimits,
        DebugAttachLimitsError, DebugBackend, DebugEventKind, DebugEventRecord, DebugFileToken,
        DebugHostError, DebugHostWorker, DebugHostWorkerState, EXCEPTION_BREAKPOINT_CODE,
        MAX_INITIAL_DRAIN_TIMEOUT, phase_one_capability_report_for_platform,
    };

    const PID: u32 = 41;
    const CREATE_THREAD_ID: u32 = 101;
    const STOP_THREAD_ID: u32 = 102;
    const IMAGE_BASE: u64 = 0x1_4000_0000;
    const IMAGE_SIZE: u32 = 0x5_000;
    const CREATE_FILE: usize = 0x1010;
    const DLL_FILE: usize = 0x2020;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Operation {
        Preflight,
        Attach(u32),
        DisableKillOnExit,
        Wait,
        CloseFile(usize),
        Continue {
            process_id: u32,
            thread_id: u32,
            disposition: ContinueDisposition,
        },
        Read {
            rva: u64,
            size: usize,
        },
        Detach(u32),
        ClearPreflight,
    }

    #[derive(Debug)]
    struct FakeBackend {
        binding: LiveTargetBinding,
        events: VecDeque<DebugEventRecord>,
        operations: Vec<Operation>,
        handle_closes: BTreeMap<usize, usize>,
        now: Duration,
        event_delays: VecDeque<Duration>,
        wait_timeouts: Vec<Duration>,
        return_late_events: bool,
        fail_operation: Option<&'static str>,
        fail_detach: bool,
        bytes: Vec<u8>,
    }

    impl FakeBackend {
        fn new(events: impl IntoIterator<Item = DebugEventRecord>) -> Self {
            Self {
                binding: test_binding(),
                events: events.into_iter().collect(),
                operations: Vec::new(),
                handle_closes: BTreeMap::new(),
                now: Duration::ZERO,
                event_delays: VecDeque::new(),
                wait_timeouts: Vec::new(),
                return_late_events: false,
                fail_operation: None,
                fail_detach: false,
                bytes: b"phase-one-read".to_vec(),
            }
        }

        fn fail(&self, operation: &'static str) -> Result<(), BackendFailure> {
            if self.fail_operation == Some(operation) {
                Err(BackendFailure::new(operation, "injected failure"))
            } else {
                Ok(())
            }
        }
    }

    impl DebugBackend for FakeBackend {
        fn monotonic_now(&self) -> Duration {
            self.now
        }

        fn preflight(
            &mut self,
            _expected: &LiveTargetBinding,
        ) -> Result<LiveTargetBinding, BackendFailure> {
            self.operations.push(Operation::Preflight);
            self.fail("preflight")?;
            Ok(self.binding.clone())
        }

        fn clear_preflight(&mut self) {
            self.operations.push(Operation::ClearPreflight);
        }

        fn attach(&mut self, process_id: ProcessId) -> Result<(), BackendFailure> {
            self.operations.push(Operation::Attach(process_id.get()));
            self.fail("attach")
        }

        fn disable_kill_on_exit(&mut self) -> Result<(), BackendFailure> {
            self.operations.push(Operation::DisableKillOnExit);
            self.fail("disable kill on exit")
        }

        fn wait_for_debug_event(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<DebugEventRecord>, BackendFailure> {
            self.operations.push(Operation::Wait);
            self.wait_timeouts.push(timeout);
            self.fail("wait for debug event")?;
            let delay = self.event_delays.pop_front().unwrap_or({
                if self.events.is_empty() {
                    timeout
                } else {
                    Duration::ZERO
                }
            });
            if delay >= timeout && (!self.return_late_events || self.events.is_empty()) {
                self.now = self.now.saturating_add(timeout);
                return Ok(None);
            }
            self.now = self.now.saturating_add(delay);
            Ok(self.events.pop_front())
        }

        fn close_debug_file(&mut self, file: DebugFileToken) {
            self.operations.push(Operation::CloseFile(file.0));
            *self.handle_closes.entry(file.0).or_default() += 1;
        }

        fn continue_debug_event(
            &mut self,
            process_id: u32,
            thread_id: u32,
            disposition: ContinueDisposition,
        ) -> Result<(), BackendFailure> {
            self.operations.push(Operation::Continue {
                process_id,
                thread_id,
                disposition,
            });
            self.fail("continue debug event")
        }

        fn read_exact_main_image_rva(
            &mut self,
            _expected: &LiveTargetBinding,
            rva: u64,
            size: usize,
        ) -> Result<Vec<u8>, BackendFailure> {
            self.operations.push(Operation::Read { rva, size });
            self.fail("read stopped main image")?;
            Ok(self.bytes[..size].to_vec())
        }

        fn detach(&mut self, process_id: ProcessId) -> Result<(), BackendFailure> {
            self.operations.push(Operation::Detach(process_id.get()));
            if self.fail_detach {
                Err(BackendFailure::new("detach", "injected detach failure"))
            } else {
                Ok(())
            }
        }
    }

    fn test_binding() -> LiveTargetBinding {
        let binary_id = BinaryId::digest(b"windows-debug-host-test-target");
        LiveTargetBinding::new(
            ProcessIdentity {
                process_id: ProcessId::new(PID).expect("nonzero test PID"),
                start_key: ProcessStartKey::new(77).expect("nonzero test start key"),
                binary_id: binary_id.clone(),
            },
            binary_id,
            MemoryAddress::new(IMAGE_BASE),
            IMAGE_SIZE,
        )
        .expect("valid deterministic binding")
    }

    fn create_process(image_base: u64, image_file: Option<usize>) -> DebugEventRecord {
        DebugEventRecord {
            process_id: PID,
            thread_id: CREATE_THREAD_ID,
            kind: DebugEventKind::CreateProcess {
                image_base,
                image_file: image_file.map(DebugFileToken),
            },
        }
    }

    fn load_dll(image_file: Option<usize>) -> DebugEventRecord {
        DebugEventRecord {
            process_id: PID,
            thread_id: CREATE_THREAD_ID,
            kind: DebugEventKind::LoadDll {
                image_file: image_file.map(DebugFileToken),
            },
        }
    }

    fn initial_breakpoint() -> DebugEventRecord {
        DebugEventRecord {
            process_id: PID,
            thread_id: STOP_THREAD_ID,
            kind: DebugEventKind::Exception {
                code: EXCEPTION_BREAKPOINT_CODE,
                first_chance: true,
                address: IMAGE_BASE + 0x123,
            },
        }
    }

    fn attached_worker() -> DebugHostWorker<FakeBackend> {
        DebugHostWorker::new(FakeBackend::new([
            create_process(IMAGE_BASE, Some(CREATE_FILE)),
            DebugEventRecord {
                process_id: PID,
                thread_id: CREATE_THREAD_ID,
                kind: DebugEventKind::CreateThread,
            },
            load_dll(Some(DLL_FILE)),
            initial_breakpoint(),
        ]))
    }

    #[test]
    fn capability_report_advertises_only_attach_and_live_read() {
        let report = phase_one_capability_report_for_platform(true);
        report.validate().expect("complete capability report");
        let available = report
            .statuses
            .iter()
            .filter_map(|status| {
                matches!(&status.availability, CapabilityAvailability::Available)
                    .then_some(status.capability)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            available,
            [DebugCapability::LiveMemoryRead, DebugCapability::HostAttach]
        );
    }

    #[test]
    fn capability_report_marks_windows_provider_surface_unsupported_off_windows() {
        let report = phase_one_capability_report_for_platform(false);
        report.validate().expect("complete capability report");
        assert!(report.statuses.iter().all(|status| {
            matches!(
                &status.availability,
                CapabilityAvailability::Unavailable { .. }
            )
        }));
        for capability in [DebugCapability::LiveMemoryRead, DebugCapability::HostAttach] {
            let status = report
                .statuses
                .iter()
                .find(|status| status.capability == capability)
                .expect("capability report is complete");
            assert!(matches!(
                &status.availability,
                CapabilityAvailability::Unavailable {
                    code: resymbol_debugger::CapabilityUnavailableCode::UnsupportedPlatform,
                    ..
                }
            ));
        }
    }

    #[test]
    fn attach_limits_reject_zero_and_overlarge_deadlines() {
        assert_eq!(
            DebugAttachLimits::new(Duration::ZERO),
            Err(DebugAttachLimitsError::ZeroInitialDrainTimeout)
        );
        let actual = MAX_INITIAL_DRAIN_TIMEOUT + Duration::from_nanos(1);
        assert_eq!(
            DebugAttachLimits::new(actual),
            Err(DebugAttachLimitsError::InitialDrainTimeoutTooLarge {
                actual,
                maximum: MAX_INITIAL_DRAIN_TIMEOUT,
            })
        );
    }

    #[test]
    fn exhausted_event_source_expires_with_typed_deadline_and_detaches() {
        let binding = test_binding();
        let mut worker = DebugHostWorker::new(FakeBackend::new([]));
        let timeout = Duration::from_millis(5);

        let error = worker
            .attach_after_authorization(
                &binding,
                DebugAttachLimits::new(timeout).expect("valid test deadline"),
            )
            .expect_err("event exhaustion expires the finite drain");

        assert!(matches!(
            error,
            DebugHostError::InitialDrainDeadlineExceeded { timeout: actual }
                if actual == timeout
        ));
        assert_eq!(worker.backend.wait_timeouts, [timeout]);
        assert_eq!(worker.state(), DebugHostWorkerState::Detached);
        assert_eq!(
            worker.backend.operations,
            [
                Operation::Preflight,
                Operation::Attach(PID),
                Operation::DisableKillOnExit,
                Operation::Wait,
                Operation::Detach(PID),
                Operation::ClearPreflight,
            ]
        );
    }

    #[test]
    fn quick_events_consume_one_total_deadline_instead_of_resetting_it() {
        let binding = test_binding();
        let mut events = vec![create_process(IMAGE_BASE, None)];
        events.extend((0..6).map(|_| DebugEventRecord {
            process_id: PID,
            thread_id: CREATE_THREAD_ID,
            kind: DebugEventKind::CreateThread,
        }));
        let mut backend = FakeBackend::new(events);
        backend.event_delays = VecDeque::from([Duration::from_millis(1); 8]);
        let mut worker = DebugHostWorker::new(backend);
        let timeout = Duration::from_millis(8);

        let error = worker
            .attach_after_authorization(
                &binding,
                DebugAttachLimits::new(timeout).expect("valid test deadline"),
            )
            .expect_err("second event cannot receive a fresh timeout budget");

        assert!(matches!(
            error,
            DebugHostError::InitialDrainDeadlineExceeded { timeout: actual }
                if actual == timeout
        ));
        assert_eq!(
            worker.backend.wait_timeouts,
            [
                Duration::from_millis(8),
                Duration::from_millis(7),
                Duration::from_millis(6),
                Duration::from_millis(5),
                Duration::from_millis(4),
                Duration::from_millis(3),
                Duration::from_millis(2),
                Duration::from_millis(1),
            ]
        );
        assert_eq!(worker.state(), DebugHostWorkerState::Detached);
    }

    #[test]
    fn late_returned_event_is_retained_then_cleaned_without_classification() {
        let binding = test_binding();
        let mut backend =
            FakeBackend::new([create_process(IMAGE_BASE + 0x1_000, Some(CREATE_FILE))]);
        backend.event_delays = VecDeque::from([Duration::from_millis(6)]);
        backend.return_late_events = true;
        let mut worker = DebugHostWorker::new(backend);
        let timeout = Duration::from_millis(5);

        let error = worker
            .attach_after_authorization(
                &binding,
                DebugAttachLimits::new(timeout).expect("valid test deadline"),
            )
            .expect_err("late event cannot be classified or accepted");

        assert!(matches!(
            error,
            DebugHostError::InitialDrainDeadlineExceeded { timeout: actual }
                if actual == timeout
        ));
        assert_eq!(worker.backend.handle_closes.get(&CREATE_FILE), Some(&1));
        assert_eq!(
            worker.backend.operations,
            [
                Operation::Preflight,
                Operation::Attach(PID),
                Operation::DisableKillOnExit,
                Operation::Wait,
                Operation::CloseFile(CREATE_FILE),
                Operation::Continue {
                    process_id: PID,
                    thread_id: CREATE_THREAD_ID,
                    disposition: ContinueDisposition::Handled,
                },
                Operation::Detach(PID),
                Operation::ClearPreflight,
            ]
        );
        assert_eq!(worker.state(), DebugHostWorkerState::Detached);
    }

    #[test]
    fn preflight_must_return_the_exact_requested_binding_before_attach() {
        let binding = test_binding();
        let mut backend = FakeBackend::new([]);
        backend.binding = LiveTargetBinding::new(
            binding.process().clone(),
            binding.main_module_binary_id().clone(),
            MemoryAddress::new(IMAGE_BASE + 0x1_000),
            IMAGE_SIZE,
        )
        .expect("alternate binding remains structurally valid");
        let mut worker = DebugHostWorker::new(backend);

        let error = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect_err("provider cannot replace exact preflight evidence");

        assert!(matches!(error, DebugHostError::PreflightBindingMismatch));
        assert_eq!(
            worker.backend.operations,
            [Operation::Preflight, Operation::ClearPreflight]
        );
        assert_eq!(worker.state(), DebugHostWorkerState::Detached);
    }

    #[test]
    fn exact_order_closes_only_debug_file_handles_and_retains_breakpoint() {
        let binding = test_binding();
        let mut worker = attached_worker();

        let stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("deterministic attach reaches initial breakpoint");

        assert_eq!(worker.state(), DebugHostWorkerState::Stopped);
        assert_eq!(stop.process_id().get(), PID);
        assert_eq!(stop.thread_id().get(), STOP_THREAD_ID);
        assert_eq!(worker.pending_stop(), Some(&stop));
        assert_eq!(worker.backend.handle_closes.get(&CREATE_FILE), Some(&1));
        assert_eq!(worker.backend.handle_closes.get(&DLL_FILE), Some(&1));
        assert_eq!(
            worker.backend.operations,
            [
                Operation::Preflight,
                Operation::Attach(PID),
                Operation::DisableKillOnExit,
                Operation::Wait,
                Operation::CloseFile(CREATE_FILE),
                Operation::Continue {
                    process_id: PID,
                    thread_id: CREATE_THREAD_ID,
                    disposition: ContinueDisposition::Handled,
                },
                Operation::Wait,
                Operation::Continue {
                    process_id: PID,
                    thread_id: CREATE_THREAD_ID,
                    disposition: ContinueDisposition::Handled,
                },
                Operation::Wait,
                Operation::CloseFile(DLL_FILE),
                Operation::Continue {
                    process_id: PID,
                    thread_id: CREATE_THREAD_ID,
                    disposition: ContinueDisposition::Handled,
                },
                Operation::Wait,
            ]
        );
    }

    #[test]
    fn stopped_main_image_read_uses_checked_inverse_rva_without_continuing_stop() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let _stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        let operations_before_read = worker.backend.operations.len();

        let bytes = worker
            .read_stopped_main_image(MemoryAddress::new(IMAGE_BASE + 0x40), 4)
            .expect("stopped exact main-image read");

        assert_eq!(bytes, b"phas");
        assert_eq!(
            worker.backend.operations[operations_before_read..],
            [Operation::Read { rva: 0x40, size: 4 }]
        );
        assert_eq!(worker.state(), DebugHostWorkerState::Stopped);
        assert!(worker.pending_stop().is_some());
    }

    #[test]
    fn detach_continues_retained_initial_breakpoint_then_stops_debugging() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let _stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        worker.detach().expect("explicit detach succeeds");

        assert_eq!(worker.state(), DebugHostWorkerState::Detached);
        assert_eq!(
            worker.backend.operations[worker.backend.operations.len() - 3..],
            [
                Operation::Continue {
                    process_id: PID,
                    thread_id: STOP_THREAD_ID,
                    disposition: ContinueDisposition::Handled,
                },
                Operation::Detach(PID),
                Operation::ClearPreflight,
            ]
        );
    }

    #[test]
    fn kill_on_exit_failure_immediately_detaches_without_waiting() {
        let binding = test_binding();
        let mut backend = FakeBackend::new([]);
        backend.fail_operation = Some("disable kill on exit");
        let mut worker = DebugHostWorker::new(backend);

        let error = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect_err("kill-on-exit failure must abort attach");

        let DebugHostError::CleanupAfterFailure { cause, evidence } = error else {
            panic!("kill-policy failure must retain separate cleanup evidence");
        };
        assert!(matches!(*cause, DebugHostError::Provider { .. }));
        assert!(matches!(
            &evidence.detach_on_thread_exit,
            CleanupStepOutcome::Failed { .. }
        ));
        assert!(matches!(
            &evidence.continue_event,
            CleanupStepOutcome::NotRequired
        ));
        assert!(matches!(&evidence.detach, CleanupStepOutcome::Succeeded));
        assert!(!evidence.complete());
        assert!(!evidence.attachment_release_unconfirmed());
        assert_eq!(worker.state(), DebugHostWorkerState::Detached);
        assert_eq!(
            worker.backend.operations,
            [
                Operation::Preflight,
                Operation::Attach(PID),
                Operation::DisableKillOnExit,
                Operation::DisableKillOnExit,
                Operation::Detach(PID),
                Operation::ClearPreflight,
            ]
        );
    }

    #[test]
    fn mismatched_create_process_base_closes_hfile_then_continues_and_detaches() {
        let binding = test_binding();
        let mut worker = DebugHostWorker::new(FakeBackend::new([create_process(
            IMAGE_BASE + 0x1_000,
            Some(CREATE_FILE),
        )]));

        let error = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect_err("mismatched CREATE_PROCESS evidence fails closed");

        assert!(matches!(
            error,
            DebugHostError::CreateProcessBaseMismatch { .. }
        ));
        assert_eq!(worker.backend.handle_closes.get(&CREATE_FILE), Some(&1));
        assert!(worker.backend.operations.contains(&Operation::Continue {
            process_id: PID,
            thread_id: CREATE_THREAD_ID,
            disposition: ContinueDisposition::Handled,
        }));
        assert_eq!(worker.state(), DebugHostWorkerState::Detached);
    }

    #[test]
    fn unexpected_exception_is_passed_on_before_stop() {
        let binding = test_binding();
        let mut worker = DebugHostWorker::new(FakeBackend::new([
            create_process(IMAGE_BASE, None),
            DebugEventRecord {
                process_id: PID,
                thread_id: STOP_THREAD_ID,
                kind: DebugEventKind::Exception {
                    code: 0xc000_0005,
                    first_chance: true,
                    address: IMAGE_BASE + 0x88,
                },
            },
        ]));

        let error = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect_err("non-attach exception fails initial drain");

        assert!(matches!(
            error,
            DebugHostError::UnexpectedInitialException {
                code: 0xc000_0005,
                first_chance: true,
            }
        ));
        assert_eq!(
            worker.backend.operations[worker.backend.operations.len() - 3..],
            [
                Operation::Continue {
                    process_id: PID,
                    thread_id: STOP_THREAD_ID,
                    disposition: ContinueDisposition::ExceptionNotHandled,
                },
                Operation::Detach(PID),
                Operation::ClearPreflight,
            ]
        );
    }

    #[test]
    fn detach_failure_preserves_explicit_cleanup_required_state() {
        let binding = test_binding();
        let mut backend = FakeBackend::new([]);
        backend.fail_operation = Some("disable kill on exit");
        backend.fail_detach = true;
        let mut worker = DebugHostWorker::new(backend);

        let error = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect_err("failed detach must remain visible");

        assert!(matches!(error, DebugHostError::CleanupAfterFailure { .. }));
        assert_eq!(worker.state(), DebugHostWorkerState::CleanupRequired);
        assert_eq!(worker.binding(), Some(&binding));
    }

    #[test]
    fn continue_failure_still_attempts_stop_and_reports_attachment_gone() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let _stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        worker.backend.fail_operation = Some("continue debug event");

        let error = worker
            .detach()
            .expect_err("failed event continuation prevents clean detach evidence");

        let DebugHostError::DetachCleanupIncomplete { evidence } = error else {
            panic!("expected separate cleanup evidence");
        };
        assert!(matches!(
            &evidence.continue_event,
            CleanupStepOutcome::Failed { .. }
        ));
        assert!(matches!(&evidence.detach, CleanupStepOutcome::Succeeded));
        assert!(!evidence.attachment_release_unconfirmed());
        assert_eq!(worker.state(), DebugHostWorkerState::Detached);
        assert!(matches!(
            worker.backend.operations[worker.backend.operations.len() - 3..],
            [
                Operation::Continue { .. },
                Operation::Detach(PID),
                Operation::ClearPreflight
            ]
        ));
    }

    #[test]
    fn continue_and_stop_failures_remain_separate_and_retryable() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let _stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        worker.backend.fail_operation = Some("continue debug event");
        worker.backend.fail_detach = true;

        let error = worker
            .detach()
            .expect_err("both cleanup failures must remain visible");

        let DebugHostError::DetachCleanupIncomplete { evidence } = error else {
            panic!("expected separate cleanup evidence");
        };
        assert!(matches!(
            &evidence.continue_event,
            CleanupStepOutcome::Failed { .. }
        ));
        assert!(matches!(
            &evidence.detach,
            CleanupStepOutcome::Failed { .. }
        ));
        assert!(evidence.attachment_release_unconfirmed());
        assert_eq!(worker.state(), DebugHostWorkerState::CleanupRequired);
        assert!(worker.pending_stop().is_none());
        assert!(worker.attached().pending.is_some());

        worker.backend.fail_operation = None;
        worker.backend.fail_detach = false;
        worker
            .detach()
            .expect("retry preserves the retained attach-breakpoint disposition");
        assert_eq!(
            worker.backend.operations[worker.backend.operations.len() - 3..],
            [
                Operation::Continue {
                    process_id: PID,
                    thread_id: STOP_THREAD_ID,
                    disposition: ContinueDisposition::Handled,
                },
                Operation::Detach(PID),
                Operation::ClearPreflight,
            ]
        );
        assert_eq!(worker.state(), DebugHostWorkerState::Detached);
    }

    #[test]
    fn null_debug_file_tokens_are_ignored() {
        let binding = test_binding();
        let mut worker = DebugHostWorker::new(FakeBackend::new([
            create_process(IMAGE_BASE, None),
            load_dll(None),
            initial_breakpoint(),
        ]));

        let _stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("null debug files are valid");

        assert!(worker.backend.handle_closes.is_empty());
        assert!(
            !worker
                .backend
                .operations
                .iter()
                .any(|operation| matches!(operation, Operation::CloseFile(_)))
        );
    }
}
