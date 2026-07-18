//! Same-thread Windows debug-attach and stopped-memory foundation.
//!
//! This crate is a provider boundary, not ReSymbol's authenticated live-helper
//! transport and not a UI bridge. Its low-level `WindowsDebugHostWorker` is
//! crate-private because an attach method name cannot prove that a caller
//! consumed a move-only host-risk lease. Public `WindowsSessionWorker` supplies
//! the authority boundary: it owns the provider, its `SessionMachine`, and each
//! exact accepted command transaction on the same thread.
//!
//! Phase one deliberately exposes only host attach plus stopped main-image
//! reads and exact compare-before-write mutations. It has no continue, pause,
//! step, register, breakpoint, launch, or sandbox-provisioning API.

#![deny(unsafe_op_in_unsafe_fn)]

use std::{fmt, time::Duration};

#[cfg(any(windows, test))]
use std::{marker::PhantomData, rc::Rc};

use resymbol_debugger::{
    CapabilityAvailability, CapabilityReport, CapabilityStatus, CapabilityUnavailableCode,
    CommandId, DebugCapability, LiveTargetBinding, LiveTargetBindingError, MemoryAddress,
    MemoryWriteFailure, ProcessId, RemoteCommandCheckpoint, StopToken, ThreadId,
};
use thiserror::Error;

#[cfg(any(windows, test))]
use resymbol_debugger::{MAX_MEMORY_WRITE_BYTES, ValidatedLiveMemoryWrite};

#[cfg(windows)]
mod windows;

mod session_worker;

#[cfg(windows)]
pub use windows::WindowsSessionWorker;

pub use session_worker::{
    DebugAttachReceipt, SessionWorkerCleanupReceipt, SessionWorkerError, SessionWorkerHealth,
    SessionWorkerMemoryReadReceipt, SessionWorkerMemoryWriteNoEffectReceipt,
    SessionWorkerMemoryWriteOutcome, SessionWorkerMemoryWriteReceipt,
};

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
        DebugCapability::LiveMemoryRead
        | DebugCapability::LiveMemoryWrite
        | DebugCapability::HostAttach
            if windows_supported =>
        {
            CapabilityAvailability::Available
        }
        DebugCapability::LiveMemoryRead
        | DebugCapability::LiveMemoryWrite
        | DebugCapability::HostAttach => CapabilityAvailability::Unavailable {
            code: CapabilityUnavailableCode::UnsupportedPlatform,
            reason: "phase-one debug attach is available only on Windows".to_owned(),
        },
        DebugCapability::ExecutionControl
        | DebugCapability::StepInto
        | DebugCapability::StepOver
        | DebugCapability::StepOut
        | DebugCapability::RegisterRead
        | DebugCapability::RegisterWrite
        | DebugCapability::SoftwareBreakpoints
        | DebugCapability::HardwareBreakpoints => CapabilityAvailability::Unavailable {
            code: CapabilityUnavailableCode::TargetModeReadOnly,
            reason: "phase-one Windows debug attach retains one stop without execution control"
                .to_owned(),
        },
        DebugCapability::OfflineAnalysis
        | DebugCapability::DumpRead
        | DebugCapability::SnapshotRead
        | DebugCapability::ObserveProcess
        | DebugCapability::SandboxedLaunch
        | DebugCapability::HostLaunch => CapabilityAvailability::Unavailable {
            code: CapabilityUnavailableCode::BackendUnavailable,
            reason: "phase-one Windows debug host implements only attach and stopped live memory"
                .to_owned(),
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

/// Exact low-level receipt for one stopped main-image mutation.
///
/// This is correlated to the retained operating-system event and echoes the
/// command ID and old logical stop from the consumed reducer-validated ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a successful stopped-memory mutation must be correlated and published"]
pub struct DebugHostMemoryWriteReceipt {
    command_id: CommandId,
    stop: StopToken,
    pending_stop: PendingStopEvidence,
    binding: LiveTargetBinding,
    address: MemoryAddress,
    before: Vec<u8>,
    after: Vec<u8>,
}

impl DebugHostMemoryWriteReceipt {
    #[must_use]
    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }

    #[must_use]
    pub const fn stop(&self) -> StopToken {
        self.stop
    }

    pub const fn pending_stop(&self) -> &PendingStopEvidence {
        &self.pending_stop
    }

    #[must_use]
    pub const fn binding(&self) -> &LiveTargetBinding {
        &self.binding
    }

    #[must_use]
    pub const fn address(&self) -> MemoryAddress {
        self.address
    }

    #[must_use]
    pub fn before(&self) -> &[u8] {
        &self.before
    }

    #[must_use]
    pub fn after(&self) -> &[u8] {
        &self.after
    }
}

/// Typed failure for a stopped exact-memory write.
#[derive(Debug, Error)]
pub enum DebugHostMemoryWriteError {
    #[error("live memory is writable only while an operating-system debug event is pending")]
    NotStopped,
    #[error("the caller's operating-system stop evidence is not the worker's retained stop")]
    PendingStopMismatch,
    #[error("the validated write ticket does not match the presented reducer checkpoint")]
    CheckpointMismatch,
    #[error("the validated write binding is not the worker's retained live target")]
    TargetBindingMismatch,
    #[error("live memory write was safely rejected without a target-side effect: {detail}")]
    SafeNoEffectRejected { detail: String },
    #[error("live memory mutation failed with protocol evidence: {failure:?}")]
    MemoryWriteFailed {
        pending_stop: PendingStopEvidence,
        failure: MemoryWriteFailure,
    },
    #[error("live memory mutation returned invalid or uncorrelated evidence: {detail}")]
    InvalidEvidence {
        pending_stop: PendingStopEvidence,
        detail: String,
    },
    #[error("live target identity or mapping became invalid during the write boundary: {detail}")]
    TargetInvalidated {
        pending_stop: PendingStopEvidence,
        detail: String,
    },
}

impl DebugHostMemoryWriteError {
    /// Whether an authenticated session worker may reject the exact remote
    /// checkpoint and restore its pre-command visible state without hiding a
    /// possible target-side effect.
    #[must_use]
    pub const fn permits_effect_free_checkpoint_rejection(&self) -> bool {
        match self {
            Self::NotStopped
            | Self::PendingStopMismatch
            | Self::CheckpointMismatch
            | Self::TargetBindingMismatch
            | Self::SafeNoEffectRejected { .. } => true,
            Self::MemoryWriteFailed { failure, .. } => failure.recovery.is_rollback_safe(),
            Self::InvalidEvidence { .. } | Self::TargetInvalidated { .. } => false,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(windows, test))]
struct BackendWriteReceipt {
    binding: LiveTargetBinding,
    rva: u64,
    bytes_written: usize,
}

#[derive(Debug)]
#[cfg(any(windows, test))]
enum BackendWriteFailure {
    SafeNoEffect { detail: String },
    MemoryWriteFailed(MemoryWriteFailure),
    InvalidEvidence { detail: String },
    TargetInvalidated { detail: String },
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

    fn write_exact_main_image_rva(
        &mut self,
        expected: &LiveTargetBinding,
        validated_protocol_stop: StopToken,
        address: MemoryAddress,
        rva: u64,
        expected_bytes: &[u8],
        replacement: &[u8],
    ) -> Result<BackendWriteReceipt, BackendWriteFailure>;

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

    /// Writes only while the exact operating-system stop remains retained.
    ///
    /// The move-only ticket proves host-local reducer acceptance. Its reducer
    /// allocation and command ID must match the separately retained checkpoint.
    /// This worker still revalidates its exact target binding and retained
    /// operating-system stop before any provider write is attempted.
    fn write_stopped_main_image_after_protocol_validation(
        &mut self,
        expected_pending_stop: &PendingStopEvidence,
        checkpoint: &RemoteCommandCheckpoint,
        write: ValidatedLiveMemoryWrite,
    ) -> Result<DebugHostMemoryWriteReceipt, DebugHostMemoryWriteError> {
        if !write.matches_checkpoint(checkpoint) {
            return Err(DebugHostMemoryWriteError::CheckpointMismatch);
        }
        let (binding, pending_stop) = match &self.state {
            WorkerState::Attached(AttachedState {
                binding,
                phase: AttachedPhase::Stopped,
                pending: Some(_),
                stop: Some(stop),
                ..
            }) => (binding.clone(), stop.clone()),
            WorkerState::Detached | WorkerState::Attached(_) => {
                return Err(DebugHostMemoryWriteError::NotStopped);
            }
        };
        if &pending_stop != expected_pending_stop {
            return Err(DebugHostMemoryWriteError::PendingStopMismatch);
        }
        if write.binding() != &binding {
            return Err(DebugHostMemoryWriteError::TargetBindingMismatch);
        }
        let command_id = write.command_id();
        let validated_protocol_stop = write.stop();
        let address = write.address();
        let expected_bytes = write.expected();
        let replacement = write.replacement();
        let rejection = if expected_bytes.is_empty() {
            Some("live memory writes must replace at least one byte".to_owned())
        } else if expected_bytes.len() > MAX_MEMORY_WRITE_BYTES {
            Some(format!(
                "live memory write size {} exceeds the {}-byte limit",
                expected_bytes.len(),
                MAX_MEMORY_WRITE_BYTES
            ))
        } else if expected_bytes.len() != replacement.len() {
            Some("compare-before-write lengths differ".to_owned())
        } else if expected_bytes == replacement {
            Some("compare-before-write replacement is identical".to_owned())
        } else {
            None
        };
        if let Some(detail) = rejection {
            return Err(DebugHostMemoryWriteError::SafeNoEffectRejected { detail });
        }
        let size = u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX);
        let rva = binding
            .rva_for_address_span(address, size)
            .map_err(|error| DebugHostMemoryWriteError::SafeNoEffectRejected {
                detail: error.to_string(),
            })?;

        let result = self.backend.write_exact_main_image_rva(
            &binding,
            validated_protocol_stop,
            address,
            rva,
            expected_bytes,
            replacement,
        );
        match result {
            Ok(receipt)
                if receipt.binding == binding
                    && receipt.rva == rva
                    && receipt.bytes_written == replacement.len() =>
            {
                Ok(DebugHostMemoryWriteReceipt {
                    command_id,
                    stop: validated_protocol_stop,
                    pending_stop,
                    binding,
                    address,
                    before: expected_bytes.to_vec(),
                    after: replacement.to_vec(),
                })
            }
            Ok(_) => Err(self.invalid_write_evidence(
                pending_stop,
                "backend success receipt did not exactly match the request".to_owned(),
            )),
            Err(BackendWriteFailure::SafeNoEffect { detail }) => {
                Err(DebugHostMemoryWriteError::SafeNoEffectRejected { detail })
            }
            Err(BackendWriteFailure::MemoryWriteFailed(failure)) => {
                let evidence_valid = failure.validate().is_ok()
                    && failure.stop == validated_protocol_stop
                    && failure.address == address
                    && usize::try_from(failure.size) == Ok(expected_bytes.len());
                if !evidence_valid {
                    return Err(self.invalid_write_evidence(
                        pending_stop,
                        "backend failure evidence did not exactly match the request".to_owned(),
                    ));
                }
                if !failure.recovery.is_rollback_safe() {
                    self.attached_mut().phase = AttachedPhase::CleanupRequired;
                }
                Err(DebugHostMemoryWriteError::MemoryWriteFailed {
                    pending_stop,
                    failure,
                })
            }
            Err(BackendWriteFailure::InvalidEvidence { detail }) => {
                Err(self.invalid_write_evidence(pending_stop, detail))
            }
            Err(BackendWriteFailure::TargetInvalidated { detail }) => {
                self.attached_mut().phase = AttachedPhase::CleanupRequired;
                Err(DebugHostMemoryWriteError::TargetInvalidated {
                    pending_stop,
                    detail,
                })
            }
        }
    }

    fn invalid_write_evidence(
        &mut self,
        pending_stop: PendingStopEvidence,
        detail: String,
    ) -> DebugHostMemoryWriteError {
        self.attached_mut().phase = AttachedPhase::CleanupRequired;
        DebugHostMemoryWriteError::InvalidEvidence {
            pending_stop,
            detail,
        }
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
        AttachMode, AttachScope, AttachTarget, CapabilityAvailability, CommandEnvelope, CommandId,
        DebugCapability, DebugCommand, DebugTargetRequest, HelperBuildId, HostRiskLeaseIssuer,
        HostRiskOperation, LivePatchHistory, LivePatchResolution, LiveTargetBinding,
        LocalLiveMemoryWriteReceiptIdentity, MemoryAddress, MemoryWriteFailure,
        MemoryWriteRecovery, MemoryWriteStage, ProcessId, ProcessIdentity, ProcessStartKey,
        ProtocolVersion, ProvisioningEpoch, RemoteCommandCheckpoint, SessionId, SessionMachine,
        SessionState, StopId, StopReason, StopToken, ThreadId, ValidatedLiveMemoryWrite,
    };

    use super::{
        BackendFailure, BackendWriteFailure, BackendWriteReceipt, CleanupStepOutcome,
        ContinueDisposition, DebugAttachLimits, DebugAttachLimitsError, DebugBackend,
        DebugEventKind, DebugEventRecord, DebugFileToken, DebugHostError,
        DebugHostMemoryWriteError, DebugHostMemoryWriteReceipt, DebugHostWorker,
        DebugHostWorkerState, EXCEPTION_BREAKPOINT_CODE, MAX_INITIAL_DRAIN_TIMEOUT,
        PendingStopEvidence, SessionWorkerError, SessionWorkerHealth,
        SessionWorkerMemoryWriteOutcome, phase_one_capability_report_for_platform,
        session_worker::SessionWorkerCore,
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
        Write {
            address: u64,
            rva: u64,
            expected: Vec<u8>,
            replacement: Vec<u8>,
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
        write_failure: Option<BackendWriteFailure>,
        corrupt_write_receipt: bool,
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
                write_failure: None,
                corrupt_write_receipt: false,
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

        fn write_exact_main_image_rva(
            &mut self,
            _expected: &LiveTargetBinding,
            _validated_protocol_stop: StopToken,
            address: MemoryAddress,
            rva: u64,
            expected_bytes: &[u8],
            replacement: &[u8],
        ) -> Result<BackendWriteReceipt, BackendWriteFailure> {
            self.operations.push(Operation::Write {
                address: address.get(),
                rva,
                expected: expected_bytes.to_vec(),
                replacement: replacement.to_vec(),
            });
            if let Some(failure) = self.write_failure.take() {
                return Err(failure);
            }
            if self.bytes.get(..expected_bytes.len()) != Some(expected_bytes) {
                return Err(BackendWriteFailure::SafeNoEffect {
                    detail: "injected compare mismatch".to_owned(),
                });
            }
            self.bytes[..replacement.len()].copy_from_slice(replacement);
            Ok(BackendWriteReceipt {
                binding: self.binding.clone(),
                rva: if self.corrupt_write_receipt {
                    rva.saturating_add(1)
                } else {
                    rva
                },
                bytes_written: replacement.len(),
            })
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

    struct ValidatedWriteTransaction {
        machine: SessionMachine,
        checkpoint: Option<RemoteCommandCheckpoint>,
        ticket: Option<ValidatedLiveMemoryWrite>,
        receipt_identity: Option<LocalLiveMemoryWriteReceiptIdentity>,
    }

    impl ValidatedWriteTransaction {
        fn stop(&self) -> StopToken {
            self.ticket.as_ref().expect("ticket available").stop()
        }

        fn command_id(&self) -> CommandId {
            self.ticket.as_ref().expect("ticket available").command_id()
        }

        fn checkpoint(&self) -> &RemoteCommandCheckpoint {
            self.checkpoint.as_ref().expect("checkpoint available")
        }

        fn take(&mut self) -> ValidatedLiveMemoryWrite {
            self.ticket.take().expect("ticket is consumed once")
        }

        fn dispatch(
            &mut self,
            worker: &mut DebugHostWorker<FakeBackend>,
            pending_stop: &PendingStopEvidence,
        ) -> Result<DebugHostMemoryWriteReceipt, DebugHostMemoryWriteError> {
            let write = self.take();
            worker.write_stopped_main_image_after_protocol_validation(
                pending_stop,
                self.checkpoint(),
                write,
            )
        }

        fn reject(&mut self, command_id: CommandId) -> SessionState {
            let checkpoint = self.checkpoint.take().expect("checkpoint is resolved once");
            let receipt_identity = self
                .receipt_identity
                .take()
                .expect("receipt identity is resolved once");
            let receipt = self
                .machine
                .resolve_live_memory_write_no_effect(checkpoint, receipt_identity)
                .expect("effect-free error resolves the exact local write");
            assert_eq!(receipt.command_id(), command_id);
            self.machine.state().clone()
        }

        fn state(&self) -> &SessionState {
            self.machine.state()
        }
    }

    fn validated_write(
        binding: &LiveTargetBinding,
        address: MemoryAddress,
        expected: &[u8],
        replacement: &[u8],
    ) -> ValidatedWriteTransaction {
        let session_id = SessionId::new(1).expect("nonzero test session");
        let provisioning_epoch =
            ProvisioningEpoch::new("a".repeat(64)).expect("test provisioning epoch");
        let helper_build =
            HelperBuildId::new("windows-debug-host-test").expect("test helper build");
        let process = binding.process().clone();
        let mut issuer = HostRiskLeaseIssuer::new().expect("host-risk issuer");
        let (lease, _verifier) = issuer
            .issue(
                session_id,
                provisioning_epoch.clone(),
                HostRiskOperation::Attach {
                    process: process.clone(),
                    mode: AttachMode::Debug,
                },
            )
            .expect("issue exact attach authority");
        let risk_lease = lease.id().clone();
        let mut machine = SessionMachine::new(session_id, provisioning_epoch, helper_build);
        machine
            .register_host_risk_lease(lease)
            .expect("register exact attach authority");
        let initial = machine.state().state_token();
        machine
            .accept_command(&CommandEnvelope {
                version: ProtocolVersion::current(),
                command_id: CommandId::new(1).expect("open command id"),
                session_id: Some(session_id),
                expected_state: Some(initial),
                command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                    scope: AttachScope::Host {
                        process,
                        risk_lease,
                    },
                    mode: AttachMode::Debug,
                })),
            })
            .expect("accept exact debug attach");
        machine
            .mark_stopped(
                StopReason::Initial,
                ThreadId::new(STOP_THREAD_ID).expect("stopped thread id"),
            )
            .expect("debug attach reaches stopped state");
        let SessionState::Stopped { token: stop, .. } = machine.state() else {
            panic!("debug attach is stopped")
        };
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(2).expect("write command id"),
            session_id: Some(session_id),
            expected_state: Some(stop.state),
            command: DebugCommand::WriteMemory {
                stop: *stop,
                address,
                expected: expected.to_vec(),
                replacement: replacement.to_vec(),
            },
        };
        let (checkpoint, ticket, receipt_identity) = machine
            .begin_live_memory_write(envelope, binding.clone())
            .expect("mint exact validated write ticket");
        ValidatedWriteTransaction {
            machine,
            checkpoint: Some(checkpoint),
            ticket: Some(ticket),
            receipt_identity: Some(receipt_identity),
        }
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

    fn attach_backend() -> FakeBackend {
        FakeBackend::new([
            create_process(IMAGE_BASE, Some(CREATE_FILE)),
            DebugEventRecord {
                process_id: PID,
                thread_id: CREATE_THREAD_ID,
                kind: DebugEventKind::CreateThread,
            },
            load_dll(Some(DLL_FILE)),
            initial_breakpoint(),
        ])
    }

    fn attached_worker() -> DebugHostWorker<FakeBackend> {
        DebugHostWorker::new(attach_backend())
    }

    fn session_worker_fixture() -> (
        SessionWorkerCore<FakeBackend>,
        CommandEnvelope,
        LiveTargetBinding,
        SessionId,
    ) {
        let binding = test_binding();
        let session_id = SessionId::new(91).expect("nonzero session id");
        let provisioning_epoch =
            ProvisioningEpoch::new("b".repeat(64)).expect("test provisioning epoch");
        let helper_build =
            HelperBuildId::new("windows-session-worker-test").expect("test helper build");
        let mut issuer = HostRiskLeaseIssuer::new().expect("host-risk issuer");
        let (lease, _verifier) = issuer
            .issue(
                session_id,
                provisioning_epoch.clone(),
                HostRiskOperation::Attach {
                    process: binding.process().clone(),
                    mode: AttachMode::Debug,
                },
            )
            .expect("issue exact attach authority");
        let risk_lease = lease.id().clone();
        let machine = SessionMachine::new(session_id, provisioning_epoch, helper_build);
        let mut worker = SessionWorkerCore::new(machine, attach_backend());
        worker
            .register_host_risk_lease(lease)
            .expect("register exact attach authority");
        let open = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(1).expect("open command id"),
            session_id: Some(session_id),
            expected_state: Some(worker.state().state_token()),
            command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                scope: AttachScope::Host {
                    process: binding.process().clone(),
                    risk_lease,
                },
                mode: AttachMode::Debug,
            })),
        };
        (worker, open, binding, session_id)
    }

    fn session_write_envelope(
        worker: &SessionWorkerCore<FakeBackend>,
        session_id: SessionId,
        address: MemoryAddress,
        expected: &[u8],
        replacement: &[u8],
    ) -> CommandEnvelope {
        let SessionState::Stopped { token, .. } = worker.state() else {
            panic!("session worker must retain a stopped reducer");
        };
        CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(2).expect("write command id"),
            session_id: Some(session_id),
            expected_state: Some(token.state),
            command: DebugCommand::WriteMemory {
                stop: *token,
                address,
                expected: expected.to_vec(),
                replacement: replacement.to_vec(),
            },
        }
    }

    fn session_read_envelope(
        worker: &SessionWorkerCore<FakeBackend>,
        session_id: SessionId,
        command_id: u64,
        address: MemoryAddress,
        size: u32,
    ) -> CommandEnvelope {
        let SessionState::Stopped { token, .. } = worker.state() else {
            panic!("session worker must retain a stopped reducer");
        };
        CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(command_id).expect("read command id"),
            session_id: Some(session_id),
            expected_state: Some(token.state),
            command: DebugCommand::ReadMemory {
                view: resymbol_debugger::ReadViewToken::Stopped { stop: *token },
                address,
                size,
            },
        }
    }

    #[test]
    fn session_worker_pre_attach_failure_safely_rejects_without_attach_effect() {
        let (mut worker, open, binding, _session_id) = session_worker_fixture();
        let state_before = worker.state().clone();
        worker.backend_for_test_mut().fail_operation = Some("preflight");

        let error = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect_err("pre-attach provider failure is effect free");

        assert!(matches!(
            error,
            SessionWorkerError::DebugHost(DebugHostError::Provider {
                operation: "preflight",
                ..
            })
        ));
        assert_eq!(worker.state(), &state_before);
        assert_eq!(worker.health(), SessionWorkerHealth::Ready);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Detached);
        assert!(
            !worker
                .backend_for_test()
                .operations
                .iter()
                .any(|operation| matches!(operation, Operation::Attach(_)))
        );
    }

    #[test]
    fn session_worker_incomplete_attach_cleanup_detached_is_sticky_and_poisoned() {
        let (mut worker, open, binding, _session_id) = session_worker_fixture();
        worker.backend_for_test_mut().fail_operation = Some("continue debug event");

        let error = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect_err("incomplete post-attach cleanup cannot be rejected");
        let expected_evidence = match &error {
            SessionWorkerError::DebugHost(DebugHostError::CleanupAfterFailure {
                evidence, ..
            }) => evidence.clone(),
            other => panic!("expected incomplete attach cleanup, received {other:?}"),
        };

        assert!(!expected_evidence.complete());
        assert!(matches!(worker.state(), SessionState::Failed { .. }));
        assert_eq!(worker.health(), SessionWorkerHealth::Poisoned);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Detached);

        let first = worker.cleanup();
        let second = worker.cleanup();
        assert!(!first.complete());
        assert!(!second.complete());
        assert_eq!(first.evidence(), Some(&expected_evidence));
        assert_eq!(second.evidence(), Some(&expected_evidence));
        assert_eq!(first.health(), SessionWorkerHealth::Poisoned);
        assert_eq!(second.health(), SessionWorkerHealth::Poisoned);
        assert_eq!(worker.health(), SessionWorkerHealth::Poisoned);
    }

    #[test]
    fn session_worker_cleanup_required_can_retry_to_closed() {
        let (mut worker, open, binding, _session_id) = session_worker_fixture();
        let attach = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach.state(), worker.state());
        worker.backend_for_test_mut().fail_detach = true;

        let first = worker.cleanup();

        assert!(!first.complete());
        assert_eq!(first.health(), SessionWorkerHealth::CleanupRequired);
        assert_eq!(
            worker.provider_state(),
            DebugHostWorkerState::CleanupRequired
        );

        worker.backend_for_test_mut().fail_detach = false;
        let second = worker.cleanup();
        assert!(second.complete());
        assert_eq!(second.health(), SessionWorkerHealth::Closed);
        assert_eq!(worker.health(), SessionWorkerHealth::Closed);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Detached);
    }

    #[test]
    fn session_worker_commits_correlated_attach_success() {
        let (mut worker, open, binding, _session_id) = session_worker_fixture();

        let receipt = worker
            .open_debug_attach(open, binding.clone(), DebugAttachLimits::default())
            .expect("authenticated attach succeeds");

        assert_eq!(worker.health(), SessionWorkerHealth::Ready);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Stopped);
        assert_eq!(worker.binding(), Some(&binding));
        assert_eq!(worker.pending_stop(), Some(receipt.pending_stop()));
        assert!(matches!(receipt.state(), SessionState::Stopped { .. }));
        assert_eq!(worker.state(), receipt.state());
    }

    #[test]
    fn session_worker_commits_correlated_stopped_memory_read() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach = worker
            .open_debug_attach(open, binding.clone(), DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        let pending_stop = attach.pending_stop().clone();
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let envelope = session_read_envelope(&worker, session_id, 2, address, 4);

        let receipt = worker
            .read_memory(envelope)
            .expect("exact stopped read succeeds");

        assert_eq!(receipt.command_id(), CommandId::new(2).expect("command id"));
        assert_eq!(receipt.binding(), &binding);
        assert_eq!(receipt.pending_stop(), &pending_stop);
        assert_eq!(receipt.address(), address);
        assert_eq!(receipt.bytes(), b"phas");
        assert_eq!(receipt.state(), worker.state());
        assert_eq!(worker.health(), SessionWorkerHealth::Ready);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Stopped);
    }

    #[test]
    fn session_worker_reducer_rejected_read_never_calls_provider() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach.state(), worker.state());
        let operations_before = worker.backend_for_test().operations.len();
        let envelope = session_read_envelope(
            &worker,
            session_id,
            1,
            MemoryAddress::new(IMAGE_BASE + 0x40),
            4,
        );

        let error = worker
            .read_memory(envelope)
            .expect_err("non-monotonic read is reducer rejected");

        assert!(matches!(error, SessionWorkerError::Reducer(_)));
        assert_eq!(
            worker.backend_for_test().operations.len(),
            operations_before
        );
        assert_eq!(worker.health(), SessionWorkerHealth::Ready);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Stopped);
    }

    #[test]
    fn session_worker_read_contradiction_commits_failed_and_poisons() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach.state(), worker.state());
        worker.set_post_dispatch_provider_state_for_test(DebugHostWorkerState::CleanupRequired);
        let envelope = session_read_envelope(
            &worker,
            session_id,
            2,
            MemoryAddress::new(IMAGE_BASE + 0x40),
            4,
        );

        let error = worker
            .read_memory(envelope)
            .expect_err("read without retained provider stop is contradictory");

        assert!(matches!(
            error,
            SessionWorkerError::ContradictoryEvidence { .. }
        ));
        assert!(matches!(worker.state(), SessionState::Failed { .. }));
        assert_eq!(worker.health(), SessionWorkerHealth::Poisoned);
        assert_eq!(
            worker.provider_state(),
            DebugHostWorkerState::CleanupRequired
        );
    }

    #[test]
    fn session_worker_commits_fully_correlated_memory_write() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach_receipt = worker
            .open_debug_attach(open, binding.clone(), DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach_receipt.state(), worker.state());
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let SessionState::Stopped { token: stop, .. } = worker.state() else {
            panic!("attach reaches stopped state")
        };
        let stop = *stop;
        let mut history = LivePatchHistory::new(session_id, binding.clone());
        history
            .begin_forward_write(
                session_id,
                &binding,
                stop,
                address,
                b"phas".to_vec(),
                b"PHAS".to_vec(),
            )
            .expect("reserve exact local write");
        let dispatched = history.mark_for_dispatch().expect("mark exact dispatch");
        let envelope = session_write_envelope(&worker, session_id, address, b"phas", b"PHAS");
        assert_eq!(envelope.command, dispatched);

        let outcome = worker
            .write_memory(envelope)
            .expect("exact stopped write succeeds");
        let SessionWorkerMemoryWriteOutcome::Committed(receipt) = outcome else {
            panic!("exact stopped write must return committed evidence")
        };

        let (provider, state, history_receipt) = receipt.into_parts();
        assert_eq!(worker.health(), SessionWorkerHealth::Ready);
        assert_eq!(provider.address(), address);
        assert_eq!(provider.before(), b"phas");
        assert_eq!(provider.after(), b"PHAS");
        assert_eq!(worker.state(), &state);
        assert!(matches!(
            history
                .resolve_local_receipt(history_receipt)
                .expect("worker success proof resolves exact history"),
            LivePatchResolution::ForwardCommitted(_)
        ));
    }

    #[test]
    fn session_worker_safe_write_rejection_restores_old_stop() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach_receipt = worker
            .open_debug_attach(open, binding.clone(), DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach_receipt.binding(), &binding);
        let stopped_before = worker.state().clone();
        let pending_before = worker.pending_stop().expect("retained OS stop").clone();
        let SessionState::Stopped { token: stop, .. } = worker.state() else {
            panic!("attach reaches stopped state")
        };
        let stop = *stop;
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut history = LivePatchHistory::new(session_id, binding.clone());
        history
            .begin_forward_write(
                session_id,
                &binding,
                stop,
                address,
                b"nope".to_vec(),
                b"NOPE".to_vec(),
            )
            .expect("reserve exact local write");
        let dispatched = history.mark_for_dispatch().expect("mark exact dispatch");
        let envelope = session_write_envelope(&worker, session_id, address, b"nope", b"NOPE");
        assert_eq!(envelope.command, dispatched);

        let outcome = worker
            .write_memory(envelope)
            .expect("compare mismatch is a proved no-effect resolution");
        let SessionWorkerMemoryWriteOutcome::RejectedNoEffect(receipt) = outcome else {
            panic!("compare mismatch must return no-effect evidence")
        };

        let (error, state, history_receipt) = receipt.into_parts();
        assert!(matches!(
            error,
            DebugHostMemoryWriteError::SafeNoEffectRejected { .. }
        ));
        assert_eq!(state, stopped_before);
        assert_eq!(
            history
                .resolve_local_receipt(history_receipt)
                .expect("worker no-effect proof clears exact dispatch"),
            LivePatchResolution::RejectedNoEffect
        );
        assert!(history.entries().is_empty());
        assert!(history.pending().is_none());
        assert_eq!(worker.state(), &stopped_before);
        assert_eq!(worker.health(), SessionWorkerHealth::Ready);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Stopped);
        assert_eq!(worker.binding(), Some(&binding));
        assert_eq!(worker.pending_stop(), Some(&pending_before));
    }

    #[test]
    fn session_worker_rollback_safe_write_failure_restores_old_stop() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach.state(), worker.state());
        let state_before = worker.state().clone();
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let SessionState::Stopped { token: stop, .. } = worker.state() else {
            panic!("attach reaches stopped state");
        };
        let stop = *stop;
        worker.backend_for_test_mut().write_failure =
            Some(BackendWriteFailure::MemoryWriteFailed(MemoryWriteFailure {
                stop,
                address,
                size: 4,
                stage: MemoryWriteStage::VerifyReplacement,
                recovery: MemoryWriteRecovery::Restored,
                detail: "injected rollback-safe mutation".to_owned(),
            }));
        let envelope = session_write_envelope(&worker, session_id, address, b"phas", b"PHAS");

        let outcome = worker
            .write_memory(envelope)
            .expect("rollback-safe provider failure is a proved no-effect resolution");
        let SessionWorkerMemoryWriteOutcome::RejectedNoEffect(receipt) = outcome else {
            panic!("rollback-safe provider failure must return no-effect evidence")
        };

        assert!(matches!(
            receipt.error(),
            DebugHostMemoryWriteError::MemoryWriteFailed { .. }
        ));
        assert_eq!(receipt.state(), &state_before);
        assert_eq!(worker.state(), &state_before);
        assert_eq!(worker.health(), SessionWorkerHealth::Ready);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Stopped);
    }

    #[test]
    fn session_worker_success_with_lost_provider_stop_commits_failed_and_poisons() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach_receipt = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach_receipt.state(), worker.state());
        worker.set_post_dispatch_provider_state_for_test(DebugHostWorkerState::CleanupRequired);
        let envelope = session_write_envelope(
            &worker,
            session_id,
            MemoryAddress::new(IMAGE_BASE + 0x40),
            b"phas",
            b"PHAS",
        );

        let error = worker
            .write_memory(envelope)
            .expect_err("success without the exact retained provider stop is contradictory");

        assert!(matches!(
            error,
            SessionWorkerError::ContradictoryEvidence { .. }
        ));
        assert!(matches!(worker.state(), SessionState::Failed { .. }));
        assert_eq!(worker.health(), SessionWorkerHealth::Poisoned);
        assert_eq!(
            worker.provider_state(),
            DebugHostWorkerState::CleanupRequired
        );
    }

    #[test]
    fn session_worker_safe_error_with_contradictory_provider_state_commits_failed() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach_receipt = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach_receipt.state(), worker.state());
        worker.set_post_dispatch_provider_state_for_test(DebugHostWorkerState::CleanupRequired);
        let envelope = session_write_envelope(
            &worker,
            session_id,
            MemoryAddress::new(IMAGE_BASE + 0x40),
            b"nope",
            b"NOPE",
        );

        let error = worker
            .write_memory(envelope)
            .expect_err("safe classification cannot override contradictory provider state");

        assert!(matches!(
            error,
            SessionWorkerError::MemoryWrite(DebugHostMemoryWriteError::SafeNoEffectRejected { .. })
        ));
        assert!(matches!(worker.state(), SessionState::Failed { .. }));
        assert_eq!(worker.health(), SessionWorkerHealth::Poisoned);
        assert_eq!(
            worker.provider_state(),
            DebugHostWorkerState::CleanupRequired
        );
    }

    #[test]
    fn session_worker_unsafe_write_commits_failure_and_freezes() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach_receipt = worker
            .open_debug_attach(open, binding.clone(), DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach_receipt.state(), worker.state());
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let SessionState::Stopped { token: stop, .. } = worker.state() else {
            panic!("attach reaches stopped state");
        };
        let stop = *stop;
        let mut history = LivePatchHistory::new(session_id, binding.clone());
        history
            .begin_forward_write(
                session_id,
                &binding,
                stop,
                address,
                b"phas".to_vec(),
                b"PHAS".to_vec(),
            )
            .expect("reserve exact local write");
        let dispatched = history.mark_for_dispatch().expect("mark exact dispatch");
        worker.backend_for_test_mut().write_failure =
            Some(BackendWriteFailure::MemoryWriteFailed(MemoryWriteFailure {
                stop,
                address,
                size: 4,
                stage: MemoryWriteStage::FlushReplacement,
                recovery: MemoryWriteRecovery::Indeterminate {
                    bytes_restored: false,
                    instruction_cache_flushed: false,
                    protection_restored: false,
                },
                detail: "injected indeterminate mutation".to_owned(),
            }));
        let envelope = session_write_envelope(&worker, session_id, address, b"phas", b"PHAS");
        assert_eq!(envelope.command, dispatched);

        let error = worker
            .write_memory(envelope)
            .expect_err("indeterminate mutation freezes the session");

        assert!(matches!(
            error,
            SessionWorkerError::MemoryWrite(DebugHostMemoryWriteError::MemoryWriteFailed { .. })
        ));
        assert_eq!(worker.health(), SessionWorkerHealth::CleanupRequired);
        assert_eq!(
            worker.provider_state(),
            DebugHostWorkerState::CleanupRequired
        );
        assert!(matches!(worker.state(), SessionState::Failed { .. }));
        assert!(history.pending().is_some());
        assert!(!history.is_inspection_only());
        assert_eq!(
            history.mark_transport_outcome_unknown(),
            Ok(LivePatchResolution::Frozen)
        );
        assert!(history.is_inspection_only());
    }

    #[test]
    fn session_worker_target_invalidation_commits_failed_cleanup_required() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach.state(), worker.state());
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        worker.backend_for_test_mut().write_failure =
            Some(BackendWriteFailure::TargetInvalidated {
                detail: "injected target invalidation".to_owned(),
            });
        let envelope = session_write_envelope(&worker, session_id, address, b"phas", b"PHAS");

        let error = worker
            .write_memory(envelope)
            .expect_err("target invalidation freezes for cleanup");

        assert!(matches!(
            error,
            SessionWorkerError::MemoryWrite(DebugHostMemoryWriteError::TargetInvalidated { .. })
        ));
        assert!(matches!(worker.state(), SessionState::Failed { .. }));
        assert_eq!(worker.health(), SessionWorkerHealth::CleanupRequired);
        assert_eq!(
            worker.provider_state(),
            DebugHostWorkerState::CleanupRequired
        );
    }

    #[test]
    fn session_worker_invalid_write_evidence_commits_failed_and_poisons() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach.state(), worker.state());
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        worker.backend_for_test_mut().write_failure = Some(BackendWriteFailure::InvalidEvidence {
            detail: "injected invalid provider evidence".to_owned(),
        });
        let envelope = session_write_envelope(&worker, session_id, address, b"phas", b"PHAS");

        let error = worker
            .write_memory(envelope)
            .expect_err("invalid provider evidence poisons orchestration");

        assert!(matches!(
            error,
            SessionWorkerError::MemoryWrite(DebugHostMemoryWriteError::InvalidEvidence { .. })
        ));
        assert!(matches!(worker.state(), SessionState::Failed { .. }));
        assert_eq!(worker.health(), SessionWorkerHealth::Poisoned);
        assert_eq!(
            worker.provider_state(),
            DebugHostWorkerState::CleanupRequired
        );
    }

    #[test]
    fn session_worker_unsafe_error_without_cleanup_state_commits_failed_and_poisons() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach_receipt = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach_receipt.state(), worker.state());
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let SessionState::Stopped { token: stop, .. } = worker.state() else {
            panic!("attach reaches stopped state");
        };
        let stop = *stop;
        worker.backend_for_test_mut().write_failure =
            Some(BackendWriteFailure::MemoryWriteFailed(MemoryWriteFailure {
                stop,
                address,
                size: 4,
                stage: MemoryWriteStage::FlushReplacement,
                recovery: MemoryWriteRecovery::Indeterminate {
                    bytes_restored: false,
                    instruction_cache_flushed: false,
                    protection_restored: false,
                },
                detail: "injected indeterminate mutation".to_owned(),
            }));
        worker.set_post_dispatch_provider_state_for_test(DebugHostWorkerState::Stopped);
        let envelope = session_write_envelope(&worker, session_id, address, b"phas", b"PHAS");

        let error = worker
            .write_memory(envelope)
            .expect_err("unsafe failure without cleanup-required state is contradictory");

        assert!(matches!(
            error,
            SessionWorkerError::MemoryWrite(DebugHostMemoryWriteError::MemoryWriteFailed { .. })
        ));
        assert!(matches!(worker.state(), SessionState::Failed { .. }));
        assert_eq!(worker.health(), SessionWorkerHealth::Poisoned);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Stopped);
    }

    #[test]
    fn session_worker_reducer_rejection_never_calls_provider_write() {
        let (mut worker, open, binding, session_id) = session_worker_fixture();
        let attach_receipt = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach_receipt.state(), worker.state());
        let operations_before = worker.backend_for_test().operations.len();
        let outside_image = MemoryAddress::new(IMAGE_BASE + u64::from(IMAGE_SIZE));
        let envelope = session_write_envelope(&worker, session_id, outside_image, b"phas", b"PHAS");

        let error = worker
            .write_memory(envelope)
            .expect_err("reducer rejects an out-of-image write");

        assert!(matches!(error, SessionWorkerError::Reducer(_)));
        assert_eq!(
            worker.backend_for_test().operations.len(),
            operations_before
        );
        assert_eq!(worker.health(), SessionWorkerHealth::Ready);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Stopped);
    }

    #[test]
    fn session_worker_cleanup_is_terminal_closed() {
        let (mut worker, open, binding, _session_id) = session_worker_fixture();
        let attach_receipt = worker
            .open_debug_attach(open, binding, DebugAttachLimits::default())
            .expect("authenticated attach succeeds");
        assert_eq!(attach_receipt.state(), worker.state());

        let receipt = worker.cleanup();

        assert!(receipt.complete());
        assert_eq!(receipt.health(), SessionWorkerHealth::Closed);
        assert_eq!(worker.health(), SessionWorkerHealth::Closed);
        assert_eq!(worker.provider_state(), DebugHostWorkerState::Detached);
        assert_eq!(worker.binding(), None);
        assert_eq!(worker.pending_stop(), None);
    }

    #[test]
    fn capability_report_advertises_attach_and_stopped_live_memory() {
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
            [
                DebugCapability::LiveMemoryRead,
                DebugCapability::LiveMemoryWrite,
                DebugCapability::HostAttach,
            ]
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
    fn stopped_exact_write_returns_correlated_receipt_without_continuing_stop() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let pending_stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        let operations_before = worker.backend.operations.len();
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut transaction = validated_write(&binding, address, b"phas", b"PHAS");
        let command_id = transaction.ticket.as_ref().expect("ticket").command_id();
        let protocol_stop = transaction.stop();
        let receipt = transaction
            .dispatch(&mut worker, &pending_stop)
            .expect("exact stopped write succeeds");

        assert_eq!(receipt.command_id(), command_id);
        assert_eq!(receipt.stop(), protocol_stop);
        assert_eq!(receipt.pending_stop(), &pending_stop);
        assert_eq!(receipt.binding(), &binding);
        assert_eq!(receipt.address(), address);
        assert_eq!(receipt.before(), b"phas");
        assert_eq!(receipt.after(), b"PHAS");
        assert_eq!(worker.state(), DebugHostWorkerState::Stopped);
        assert_eq!(worker.pending_stop(), Some(&pending_stop));
        assert_eq!(
            worker.backend.operations[operations_before..],
            [Operation::Write {
                address: address.get(),
                rva: 0x40,
                expected: b"phas".to_vec(),
                replacement: b"PHAS".to_vec(),
            }]
        );
    }

    #[test]
    fn compare_mismatch_is_safe_no_effect_and_preserves_stop() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let pending_stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut transaction = validated_write(&binding, address, b"nope", b"NOPE");
        let command_id = transaction.command_id();
        let old_stop = transaction.stop();
        let error = transaction
            .dispatch(&mut worker, &pending_stop)
            .expect_err("compare mismatch rejects without mutation");

        assert!(matches!(
            &error,
            DebugHostMemoryWriteError::SafeNoEffectRejected { .. }
        ));
        assert!(error.permits_effect_free_checkpoint_rejection());
        assert!(matches!(
            transaction.reject(command_id),
            SessionState::Stopped { token, .. } if token == old_stop
        ));
        assert_eq!(worker.state(), DebugHostWorkerState::Stopped);
        assert_eq!(worker.pending_stop(), Some(&pending_stop));
    }

    #[test]
    fn mismatched_pending_stop_is_rejected_before_backend_write() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let pending_stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        let operations_before = worker.backend.operations.len();
        let mismatched = PendingStopEvidence {
            process_id: pending_stop.process_id(),
            thread_id: pending_stop.thread_id(),
            exception_address: MemoryAddress::new(pending_stop.exception_address().get() + 1),
        };
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut transaction = validated_write(&binding, address, b"phas", b"PHAS");

        let error = transaction
            .dispatch(&mut worker, &mismatched)
            .expect_err("stale OS-stop evidence cannot authorize a write");

        assert!(matches!(
            error,
            DebugHostMemoryWriteError::PendingStopMismatch
        ));
        assert_eq!(worker.backend.operations.len(), operations_before);
        assert_eq!(worker.state(), DebugHostWorkerState::Stopped);
    }

    #[test]
    fn mismatched_validated_target_binding_is_rejected_before_backend_write() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let pending_stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        let operations_before = worker.backend.operations.len();
        let other_binary = BinaryId::digest(b"different validated target");
        let other_binding = LiveTargetBinding::new(
            ProcessIdentity {
                process_id: ProcessId::new(PID + 1).expect("other PID"),
                start_key: ProcessStartKey::new(78).expect("other start key"),
                binary_id: other_binary.clone(),
            },
            other_binary,
            MemoryAddress::new(IMAGE_BASE),
            IMAGE_SIZE,
        )
        .expect("other exact binding");
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut transaction = validated_write(&other_binding, address, b"phas", b"PHAS");

        let error = transaction
            .dispatch(&mut worker, &pending_stop)
            .expect_err("ticket for another target cannot authorize this worker");

        assert!(matches!(
            error,
            DebugHostMemoryWriteError::TargetBindingMismatch
        ));
        assert_eq!(worker.backend.operations.len(), operations_before);
        assert_eq!(worker.state(), DebugHostWorkerState::Stopped);
        assert_eq!(worker.pending_stop(), Some(&pending_stop));
    }

    #[test]
    fn checkpoint_from_identical_distinct_reducer_is_rejected_before_backend_write() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let pending_stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        let operations_before = worker.backend.operations.len();
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut ticket_transaction = validated_write(&binding, address, b"phas", b"PHAS");
        let checkpoint_transaction = validated_write(&binding, address, b"phas", b"PHAS");
        let write = ticket_transaction.take();

        let error = worker
            .write_stopped_main_image_after_protocol_validation(
                &pending_stop,
                checkpoint_transaction.checkpoint(),
                write,
            )
            .expect_err("an identical command from another reducer allocation is not authority");

        assert!(matches!(
            error,
            DebugHostMemoryWriteError::CheckpointMismatch
        ));
        assert_eq!(worker.backend.operations.len(), operations_before);
        assert_eq!(worker.state(), DebugHostWorkerState::Stopped);
        assert_eq!(worker.pending_stop(), Some(&pending_stop));
    }

    #[test]
    fn write_rejects_when_no_operating_system_stop_is_retained() {
        let mut worker = DebugHostWorker::new(FakeBackend::new([]));
        let pending_stop = PendingStopEvidence {
            process_id: ProcessId::new(PID).expect("nonzero PID"),
            thread_id: resymbol_debugger::ThreadId::new(STOP_THREAD_ID).expect("nonzero thread"),
            exception_address: MemoryAddress::new(IMAGE_BASE + 1),
        };
        let binding = test_binding();
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut transaction = validated_write(&binding, address, b"phas", b"PHAS");
        let error = transaction
            .dispatch(&mut worker, &pending_stop)
            .expect_err("detached worker cannot write");

        assert!(matches!(error, DebugHostMemoryWriteError::NotStopped));
        assert!(worker.backend.operations.is_empty());
    }

    #[test]
    fn indeterminate_write_failure_enters_cleanup_required_with_event_retained() {
        let binding = test_binding();
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut worker = attached_worker();
        let pending_stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        let mut transaction = validated_write(&binding, address, b"phas", b"PHAS");
        let protocol_stop = transaction.stop();
        let accepted_state = transaction.state().clone();
        worker.backend.write_failure =
            Some(BackendWriteFailure::MemoryWriteFailed(MemoryWriteFailure {
                stop: protocol_stop,
                address,
                size: 4,
                stage: MemoryWriteStage::FlushReplacement,
                recovery: MemoryWriteRecovery::Indeterminate {
                    bytes_restored: false,
                    instruction_cache_flushed: false,
                    protection_restored: false,
                },
                detail: "injected indeterminate mutation".to_owned(),
            }));

        let error = transaction
            .dispatch(&mut worker, &pending_stop)
            .expect_err("indeterminate write cannot publish success");

        assert!(matches!(
            &error,
            DebugHostMemoryWriteError::MemoryWriteFailed { .. }
        ));
        assert!(!error.permits_effect_free_checkpoint_rejection());
        assert_eq!(transaction.state(), &accepted_state);
        assert_eq!(worker.state(), DebugHostWorkerState::CleanupRequired);
        assert!(worker.attached().pending.is_some());
        worker.detach().expect("cleanup ability remains retained");
        assert_eq!(worker.state(), DebugHostWorkerState::Detached);
    }

    #[test]
    fn mismatched_success_receipt_enters_cleanup_required() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let pending_stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        worker.backend.corrupt_write_receipt = true;
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut transaction = validated_write(&binding, address, b"phas", b"PHAS");

        let error = transaction
            .dispatch(&mut worker, &pending_stop)
            .expect_err("uncorrelated success evidence cannot be published");

        assert!(matches!(
            error,
            DebugHostMemoryWriteError::InvalidEvidence { .. }
        ));
        assert_eq!(worker.state(), DebugHostWorkerState::CleanupRequired);
        assert!(worker.attached().pending.is_some());
    }

    #[test]
    fn invalid_failure_evidence_enters_cleanup_required() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let pending_stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        worker.backend.write_failure = Some(BackendWriteFailure::InvalidEvidence {
            detail: "injected malformed protocol evidence".to_owned(),
        });
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut transaction = validated_write(&binding, address, b"phas", b"PHAS");
        let accepted_state = transaction.state().clone();

        let error = transaction
            .dispatch(&mut worker, &pending_stop)
            .expect_err("invalid failure evidence cannot be published");

        assert!(matches!(
            &error,
            DebugHostMemoryWriteError::InvalidEvidence { .. }
        ));
        assert!(!error.permits_effect_free_checkpoint_rejection());
        assert_eq!(transaction.state(), &accepted_state);
        assert_eq!(worker.state(), DebugHostWorkerState::CleanupRequired);
        assert!(worker.attached().pending.is_some());
    }

    #[test]
    fn mismatched_memory_write_failure_evidence_fails_closed() {
        let binding = test_binding();
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let seed_transaction = validated_write(&binding, address, b"phas", b"PHAS");
        let protocol_stop = seed_transaction.stop();
        let mismatched_stop = StopToken {
            stop_id: StopId::new(protocol_stop.stop_id.get() + 1).expect("nonzero stop"),
            ..protocol_stop
        };
        let cases = [
            (
                "stop token",
                MemoryWriteFailure {
                    stop: mismatched_stop,
                    address,
                    size: 4,
                    stage: MemoryWriteStage::WriteReplacement,
                    recovery: MemoryWriteRecovery::Restored,
                    detail: "injected stop mismatch".to_owned(),
                },
            ),
            (
                "address",
                MemoryWriteFailure {
                    stop: protocol_stop,
                    address: MemoryAddress::new(address.get() + 1),
                    size: 4,
                    stage: MemoryWriteStage::WriteReplacement,
                    recovery: MemoryWriteRecovery::Restored,
                    detail: "injected address mismatch".to_owned(),
                },
            ),
            (
                "size",
                MemoryWriteFailure {
                    stop: protocol_stop,
                    address,
                    size: 3,
                    stage: MemoryWriteStage::WriteReplacement,
                    recovery: MemoryWriteRecovery::Restored,
                    detail: "injected size mismatch".to_owned(),
                },
            ),
        ];

        for (field, failure) in cases {
            failure
                .validate()
                .unwrap_or_else(|error| panic!("{field} fixture must be valid: {error}"));
            let mut worker = attached_worker();
            let pending_stop = worker
                .attach_after_authorization(&binding, DebugAttachLimits::default())
                .expect("attach reaches initial breakpoint");
            worker.backend.write_failure = Some(BackendWriteFailure::MemoryWriteFailed(failure));
            let mut transaction = validated_write(&binding, address, b"phas", b"PHAS");

            let error = transaction
                .dispatch(&mut worker, &pending_stop)
                .unwrap_err();

            assert!(
                matches!(&error, DebugHostMemoryWriteError::InvalidEvidence { .. }),
                "{field} mismatch must fail closed: {error:?}"
            );
            assert_eq!(worker.state(), DebugHostWorkerState::CleanupRequired);
            assert_eq!(worker.attached().stop.as_ref(), Some(&pending_stop));
            assert!(worker.attached().pending.is_some());
            worker
                .detach()
                .unwrap_or_else(|error| panic!("{field} mismatch must retain cleanup: {error}"));
            assert_eq!(worker.state(), DebugHostWorkerState::Detached);
        }
    }

    #[test]
    fn target_invalidation_enters_cleanup_required() {
        let binding = test_binding();
        let mut worker = attached_worker();
        let pending_stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        worker.backend.write_failure = Some(BackendWriteFailure::TargetInvalidated {
            detail: "injected process identity drift".to_owned(),
        });
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut transaction = validated_write(&binding, address, b"phas", b"PHAS");

        let error = transaction
            .dispatch(&mut worker, &pending_stop)
            .expect_err("identity drift cannot preserve stopped authority");

        assert!(matches!(
            error,
            DebugHostMemoryWriteError::TargetInvalidated { .. }
        ));
        assert_eq!(worker.state(), DebugHostWorkerState::CleanupRequired);
        assert!(worker.attached().pending.is_some());
    }

    #[test]
    fn unrestored_protection_enters_cleanup_required_even_before_write() {
        let binding = test_binding();
        let address = MemoryAddress::new(IMAGE_BASE + 0x40);
        let mut worker = attached_worker();
        let pending_stop = worker
            .attach_after_authorization(&binding, DebugAttachLimits::default())
            .expect("attach reaches initial breakpoint");
        let mut transaction = validated_write(&binding, address, b"phas", b"PHAS");
        let protocol_stop = transaction.stop();
        worker.backend.write_failure =
            Some(BackendWriteFailure::MemoryWriteFailed(MemoryWriteFailure {
                stop: protocol_stop,
                address,
                size: 4,
                stage: MemoryWriteStage::ChangeProtection,
                recovery: MemoryWriteRecovery::NoWriteAttempted {
                    protection_restored: false,
                },
                detail: "injected unrestored protection".to_owned(),
            }));

        let error = transaction
            .dispatch(&mut worker, &pending_stop)
            .expect_err("unrestored protection is not rollback-safe");

        assert!(matches!(
            error,
            DebugHostMemoryWriteError::MemoryWriteFailed { .. }
        ));
        assert_eq!(worker.state(), DebugHostWorkerState::CleanupRequired);
        assert!(worker.attached().pending.is_some());
    }

    #[test]
    fn rollback_safe_failure_evidence_preserves_stopped_state() {
        let cases = [
            (
                MemoryWriteStage::ChangeProtection,
                MemoryWriteRecovery::NoWriteAttempted {
                    protection_restored: true,
                },
            ),
            (
                MemoryWriteStage::VerifyReplacement,
                MemoryWriteRecovery::Restored,
            ),
        ];
        for (stage, recovery) in cases {
            let binding = test_binding();
            let address = MemoryAddress::new(IMAGE_BASE + 0x40);
            let mut worker = attached_worker();
            let pending_stop = worker
                .attach_after_authorization(&binding, DebugAttachLimits::default())
                .expect("attach reaches initial breakpoint");
            let mut transaction = validated_write(&binding, address, b"phas", b"PHAS");
            let protocol_stop = transaction.stop();
            let command_id = transaction.command_id();
            worker.backend.write_failure =
                Some(BackendWriteFailure::MemoryWriteFailed(MemoryWriteFailure {
                    stop: protocol_stop,
                    address,
                    size: 4,
                    stage,
                    recovery,
                    detail: "injected rollback-safe mutation failure".to_owned(),
                }));

            let error = transaction
                .dispatch(&mut worker, &pending_stop)
                .expect_err("failure evidence remains a failure");

            assert!(matches!(
                &error,
                DebugHostMemoryWriteError::MemoryWriteFailed { .. }
            ));
            assert!(error.permits_effect_free_checkpoint_rejection());
            assert!(matches!(
                transaction.reject(command_id),
                SessionState::Stopped { token, .. } if token == protocol_stop
            ));
            assert_eq!(worker.state(), DebugHostWorkerState::Stopped);
            assert_eq!(worker.pending_stop(), Some(&pending_stop));
        }
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
