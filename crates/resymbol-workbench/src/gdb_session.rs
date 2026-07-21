//! Capacity-one, non-blocking ownership for an outbound GDB RSP session.
//!
//! Ownership is deliberately one-way:
//!
//! ```text
//! WorkbenchApp -> RemoteSessionController -> remote I/O thread -> GdbRemoteClient
//! ```
//!
//! The egui thread owns only bounded request/result queues and presentation
//! state. The named I/O thread exclusively owns the socket and RSP client. No
//! socket operation, including connect, runs on the egui thread.

use std::{
    io,
    net::{Shutdown, SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use resymbol_gdb_remote::{
    GdbRemoteClient, PS2_EE_GPACKET_BYTES, PS2_EE_TARGET_DESCRIPTION, PS2_EE_TARGET_XML,
    RemoteTargetDescription, TargetByteOrder, TcpTransport, ps2_ee_gpacket_to_registers,
};
use thiserror::Error;

pub(crate) const DEFAULT_REMOTE_ENDPOINT: &str = "127.0.0.1:1234";
pub(crate) const MAX_REMOTE_MEMORY_READ_BYTES: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_FEATURE_TEXT_BYTES: usize = 1_024;
const MAX_REGISTER_PREVIEW_BYTES: usize = 512;
const COMMAND_QUEUE_CAPACITY: usize = 1;
const EVENT_QUEUE_CAPACITY: usize = 2;
/// Register count of ReSymbol's canonical PS2 EE target description.
///
/// Asserted against the parsed canonical XML by
/// `canonical_ps2_ee_constants_match_the_shared_schema`.
const PS2_EE_REGISTER_COUNT: usize = 109;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteSessionCapabilities {
    pub(crate) read_registers: bool,
    pub(crate) read_memory: bool,
    pub(crate) write_target: bool,
    pub(crate) control_execution: bool,
}

impl RemoteSessionCapabilities {
    /// The first Workbench surface is intentionally inspection-only. Mutating
    /// and execution-control commands require separate explicit policy and
    /// asynchronous target-interrupt support before they can be advertised.
    const READ_ONLY: Self = Self {
        read_registers: true,
        read_memory: true,
        write_target: false,
        control_execution: false,
    };
}

/// Bounded target metadata copied into ephemeral egui presentation state.
///
/// The complete XML and parsed register schema stay with the remote-I/O
/// worker. Workbench never serializes either representation into a project or
/// preference artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteTargetView {
    architecture: String,
    byte_order: Option<TargetByteOrder>,
    register_count: usize,
    expected_gpacket_bytes: usize,
    software_breakpoint_kind: Option<u64>,
    exact_ps2_ee_schema: bool,
}

impl RemoteTargetView {
    pub(crate) fn architecture(&self) -> &str {
        &self.architecture
    }

    pub(crate) const fn byte_order(&self) -> Option<TargetByteOrder> {
        self.byte_order
    }

    pub(crate) const fn register_count(&self) -> usize {
        self.register_count
    }

    pub(crate) const fn expected_gpacket_bytes(&self) -> usize {
        self.expected_gpacket_bytes
    }

    pub(crate) const fn software_breakpoint_kind(&self) -> Option<u64> {
        self.software_breakpoint_kind
    }

    pub(crate) const fn is_exact_ps2_ee_schema(&self) -> bool {
        self.exact_ps2_ee_schema
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteAttachRequest {
    endpoint: SocketAddr,
}

impl RemoteAttachRequest {
    pub(crate) fn parse(
        endpoint: &str,
        allow_non_loopback: bool,
    ) -> Result<Self, RemoteSessionError> {
        let endpoint = endpoint
            .trim()
            .parse::<SocketAddr>()
            .map_err(|_| RemoteSessionError::InvalidEndpoint)?;
        if endpoint.port() == 0 {
            return Err(RemoteSessionError::ZeroPort);
        }
        if !endpoint.ip().is_loopback() && !allow_non_loopback {
            return Err(RemoteSessionError::NonLoopbackRequiresOptIn);
        }
        Ok(Self { endpoint })
    }

    pub(crate) const fn endpoint(self) -> SocketAddr {
        self.endpoint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteMemoryRead {
    address: u64,
    size: usize,
}

impl RemoteMemoryRead {
    pub(crate) fn new(address: u64, size: usize) -> Result<Self, RemoteSessionError> {
        if !(1..=MAX_REMOTE_MEMORY_READ_BYTES).contains(&size) {
            return Err(RemoteSessionError::InvalidReadSize);
        }
        let size_u64 = u64::try_from(size).map_err(|_| RemoteSessionError::InvalidReadSize)?;
        address
            .checked_add(size_u64.saturating_sub(1))
            .ok_or(RemoteSessionError::AddressOverflow)?;
        Ok(Self { address, size })
    }

    pub(crate) const fn address(self) -> u64 {
        self.address
    }

    pub(crate) const fn size(self) -> usize {
        self.size
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum RemoteSessionError {
    #[error("enter a numeric TCP endpoint such as {DEFAULT_REMOTE_ENDPOINT}")]
    InvalidEndpoint,
    #[error("the remote GDB endpoint must use a non-zero port")]
    ZeroPort,
    #[error("non-loopback GDB endpoints require explicit remote-network opt-in")]
    NonLoopbackRequiresOptIn,
    #[error("remote memory reads must contain between 1 and {MAX_REMOTE_MEMORY_READ_BYTES} bytes")]
    InvalidReadSize,
    #[error("the remote memory range overflows the 64-bit target address space")]
    AddressOverflow,
    #[error("wait for the current remote operation to finish")]
    Busy,
    #[error("connect to a remote GDB target first")]
    NotConnected,
    #[error("disconnect the current remote GDB target before connecting another")]
    AlreadyConnected,
    #[error("the remote GDB session worker stopped unexpectedly")]
    WorkerDisconnected,
    #[error("there is no pending remote operation to cancel")]
    NoPendingOperation,
    #[error(
        "reading the current EE program counter requires the exact canonical {PS2_EE_REGISTER_COUNT}-register, {PS2_EE_GPACKET_BYTES}-byte PS2 EE schema"
    )]
    RequiresExactPs2EeSchema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Connect,
    Disconnect,
    Registers,
    Memory,
    ProgramCounter,
}

impl RequestKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Disconnect => "disconnect",
            Self::Registers => "register read",
            Self::Memory => "memory read",
            Self::ProgramCounter => "EE program counter read",
        }
    }
}

#[derive(Debug)]
enum RemoteCommand {
    Connect {
        request: u64,
        attach: RemoteAttachRequest,
    },
    Disconnect {
        request: u64,
    },
    ReadRegisters {
        request: u64,
    },
    ReadMemory {
        request: u64,
        read: RemoteMemoryRead,
    },
    ReadProgramCounter {
        request: u64,
    },
}

impl RemoteCommand {
    const fn request(&self) -> u64 {
        match self {
            Self::Connect { request, .. }
            | Self::Disconnect { request }
            | Self::ReadRegisters { request }
            | Self::ReadMemory { request, .. }
            | Self::ReadProgramCounter { request } => *request,
        }
    }

    const fn kind(&self) -> RequestKind {
        match self {
            Self::Connect { .. } => RequestKind::Connect,
            Self::Disconnect { .. } => RequestKind::Disconnect,
            Self::ReadRegisters { .. } => RequestKind::Registers,
            Self::ReadMemory { .. } => RequestKind::Memory,
            Self::ReadProgramCounter { .. } => RequestKind::ProgramCounter,
        }
    }
}

#[derive(Debug)]
enum RemoteOutcome {
    Connected {
        endpoint: SocketAddr,
        advertised_features: String,
        target: RemoteTargetView,
    },
    Disconnected,
    Registers {
        byte_count: usize,
        preview: Vec<u8>,
    },
    Memory {
        address: u64,
        bytes: Vec<u8>,
    },
    /// Only the typed program counter crosses the worker/UI channel. The raw
    /// `g` packet and every other decoded EE register stay worker-local.
    ProgramCounter {
        pc: u32,
    },
    Failed {
        detail: String,
        connection_lost: bool,
    },
}

#[derive(Debug)]
struct RemoteEvent {
    request: u64,
    kind: RequestKind,
    outcome: RemoteOutcome,
}

/// What presentation state should do with one worker result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventDisposition {
    /// The result belongs to no tracked request; drop it without touching
    /// presentation state so a superseded observation can never be displayed.
    Stale,
    /// The result completes a request the UI already cancelled; scrub instead
    /// of displaying it.
    Cancelled,
    /// The result completes the sole tracked request.
    Apply,
}

/// `[egui thread, non-blocking]` Decide one worker result's disposition.
///
/// Because the session is capacity-one, any result whose identifier is not the
/// tracked pending request is stale by construction — including results that
/// won a race against socket shutdown.
fn classify_event(
    pending_request: Option<u64>,
    cancelled_request: Option<u64>,
    request: u64,
) -> EventDisposition {
    if pending_request != Some(request) {
        EventDisposition::Stale
    } else if cancelled_request == Some(request) {
        EventDisposition::Cancelled
    } else {
        EventDisposition::Apply
    }
}

/// Presentation snapshot owned exclusively by the egui thread.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RemoteSessionView {
    endpoint: Option<SocketAddr>,
    pending: Option<&'static str>,
    cancelling: bool,
    advertised_features: Option<String>,
    target: Option<RemoteTargetView>,
    register_summary: Option<String>,
    memory_summary: Option<String>,
    program_counter: Option<u32>,
    last_error: Option<String>,
}

impl RemoteSessionView {
    pub(crate) const fn is_connected(&self) -> bool {
        self.endpoint.is_some()
    }

    pub(crate) const fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub(crate) const fn is_cancelling(&self) -> bool {
        self.cancelling
    }

    pub(crate) fn status(&self) -> String {
        if let Some(operation) = self.pending {
            if self.cancelling {
                format!("[CANCELLING] {operation}")
            } else {
                format!("[BUSY] {operation}")
            }
        } else if let Some(endpoint) = self.endpoint {
            format!("[CONNECTED] {endpoint}")
        } else {
            "[DISCONNECTED]".to_owned()
        }
    }

    pub(crate) fn advertised_features(&self) -> Option<&str> {
        self.advertised_features.as_deref()
    }

    pub(crate) const fn target(&self) -> Option<&RemoteTargetView> {
        self.target.as_ref()
    }

    pub(crate) fn register_summary(&self) -> Option<&str> {
        self.register_summary.as_deref()
    }

    pub(crate) fn memory_summary(&self) -> Option<&str> {
        self.memory_summary.as_deref()
    }

    /// Last observed EE program counter, retained as a typed scalar only.
    pub(crate) const fn program_counter(&self) -> Option<u32> {
        self.program_counter
    }

    /// Whether the typed EE program-counter route is currently offered.
    pub(crate) fn can_read_program_counter(&self) -> bool {
        require_program_counter_route(self).is_ok()
    }

    pub(crate) fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    fn clear_observations(&mut self) {
        self.register_summary = None;
        self.memory_summary = None;
        self.program_counter = None;
    }

    /// Drop only the observation `kind` produces, so a failed read never leaves
    /// a stale preview attributable to it.
    fn clear_observation_for(&mut self, kind: RequestKind) {
        match kind {
            RequestKind::Registers => self.register_summary = None,
            RequestKind::Memory => self.memory_summary = None,
            RequestKind::ProgramCounter => self.program_counter = None,
            RequestKind::Connect | RequestKind::Disconnect => {}
        }
    }

    fn clear_session(&mut self) {
        self.endpoint = None;
        self.advertised_features = None;
        self.target = None;
        self.clear_observations();
    }
}

/// `[egui thread, non-blocking]` Submission gate for the typed EE
/// program-counter route.
///
/// This route is a strict narrowing of the existing read-register route: it
/// issues the same `g` read and adds no capability. It is offered only for a
/// live connection whose target description matched the exact canonical PS2 EE
/// schema at connect time. The remote-I/O worker re-derives the same decision
/// from its own retained description before touching the socket, so this check
/// is a UI gate and never the sole enforcement point.
fn require_program_counter_route(view: &RemoteSessionView) -> Result<(), RemoteSessionError> {
    if !view.is_connected() {
        return Err(RemoteSessionError::NotConnected);
    }
    if !view
        .target
        .as_ref()
        .is_some_and(RemoteTargetView::is_exact_ps2_ee_schema)
    {
        return Err(RemoteSessionError::RequiresExactPs2EeSchema);
    }
    Ok(())
}

/// Render an EE program counter as a fixed-width `0xXXXXXXXX` literal.
///
/// The EE program counter is exactly 32 bits, so the width is constant and
/// never truncates or elides a digit.
pub(crate) fn format_ee_program_counter(pc: u32) -> String {
    format!("{pc:#010x}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteNoticeLevel {
    Info,
    Success,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteSessionNotice {
    pub(crate) level: RemoteNoticeLevel,
    pub(crate) message: String,
}

/// `[egui thread, non-blocking]` Apply one successful EE program-counter read.
///
/// The observed value is retained in exactly one place: the [`RemoteSessionView`]
/// scalar, which `clear_observations` and `clear_session` own and which only the
/// session panel's explicit current-PC row renders.
///
/// The returned notice is deliberately value-free. Notices are forwarded to the
/// Workbench activity log — a bounded ring that outlives the session — and to
/// the companion console process, and no session scrub can reach either. A
/// notice carrying the formatted program counter would therefore survive every
/// scrub this route promises, and would leave the observation attributable after
/// the connection it came from is gone. The message is a constant, identical for
/// every observed value, so the log-facing payload encodes nothing about it.
fn apply_program_counter(view: &mut RemoteSessionView, pc: u32) -> RemoteSessionNotice {
    view.program_counter = Some(pc);
    view.last_error = None;
    RemoteSessionNotice {
        level: RemoteNoticeLevel::Success,
        message: "Read the current EE program counter from the remote target; \
                  the value is shown only in the remote session panel"
            .to_owned(),
    }
}

/// UI-facing controller for exactly one outbound RSP session.
///
/// All methods are `[egui thread, non-blocking]`. The controller is
/// non-hot-reloadable because it owns a named native thread and socket
/// lifecycle; dropping it cancels socket I/O, closes the channels, and detaches
/// that thread without blocking UI teardown.
pub(crate) struct RemoteSessionController {
    commands: Option<SyncSender<RemoteCommand>>,
    events: Option<Receiver<RemoteEvent>>,
    join: Option<JoinHandle<()>>,
    cancel_stream: Arc<Mutex<Option<TcpStream>>>,
    cancel_requested: Arc<AtomicBool>,
    next_request: u64,
    pending_request: Option<u64>,
    cancelled_request: Option<u64>,
    worker_disconnected: bool,
    view: RemoteSessionView,
}

impl RemoteSessionController {
    /// `[egui thread, non-blocking]` Spawn the sole remote I/O owner.
    pub(crate) fn start(repaint: eframe::egui::Context) -> Self {
        let (commands, command_rx) = sync_channel(COMMAND_QUEUE_CAPACITY);
        let (event_tx, events) = sync_channel(EVENT_QUEUE_CAPACITY);
        let cancel_stream = Arc::new(Mutex::new(None));
        let worker_cancel_stream = Arc::clone(&cancel_stream);
        let cancel_requested = Arc::new(AtomicBool::new(false));
        let worker_cancel_requested = Arc::clone(&cancel_requested);
        let join = thread::Builder::new()
            .name("resymbol-gdb-remote-client".to_owned())
            .spawn(move || {
                remote_worker_loop(
                    command_rx,
                    event_tx,
                    repaint,
                    worker_cancel_stream,
                    worker_cancel_requested,
                );
            })
            .expect("the remote GDB client worker thread must start");
        Self {
            commands: Some(commands),
            events: Some(events),
            join: Some(join),
            cancel_stream,
            cancel_requested,
            next_request: 1,
            pending_request: None,
            cancelled_request: None,
            worker_disconnected: false,
            view: RemoteSessionView::default(),
        }
    }

    pub(crate) const fn capabilities(&self) -> RemoteSessionCapabilities {
        RemoteSessionCapabilities::READ_ONLY
    }

    pub(crate) const fn view(&self) -> &RemoteSessionView {
        &self.view
    }

    /// `[egui thread, non-blocking]` Retain a bounded local validation error;
    /// this never crosses the network or persists in Workbench preferences.
    pub(crate) fn note_local_error(&mut self, detail: impl Into<String>) {
        self.view.last_error = Some(bounded_printable(
            detail.into().as_bytes(),
            MAX_FEATURE_TEXT_BYTES,
        ));
    }

    /// `[egui thread, non-blocking]`
    pub(crate) fn connect(
        &mut self,
        attach: RemoteAttachRequest,
    ) -> Result<(), RemoteSessionError> {
        if self.view.is_connected() {
            return Err(RemoteSessionError::AlreadyConnected);
        }
        self.view.clear_session();
        self.submit(RequestKind::Connect, |request| RemoteCommand::Connect {
            request,
            attach,
        })
    }

    /// `[egui thread, non-blocking]`
    pub(crate) fn disconnect(&mut self) -> Result<(), RemoteSessionError> {
        if !self.view.is_connected() {
            return Err(RemoteSessionError::NotConnected);
        }
        self.view.clear_observations();
        self.submit(RequestKind::Disconnect, |request| {
            RemoteCommand::Disconnect { request }
        })
    }

    /// `[egui thread, non-blocking]` Request cancellation of the sole pending
    /// operation and interrupt any socket I/O already in progress.
    pub(crate) fn cancel_pending(&mut self) -> Result<(), RemoteSessionError> {
        let Some(request) = self.pending_request else {
            return Err(RemoteSessionError::NoPendingOperation);
        };
        if self.cancelled_request == Some(request) {
            return Ok(());
        }

        self.cancelled_request = Some(request);
        self.cancel_requested.store(true, Ordering::Release);
        self.view.cancelling = true;
        self.view.clear_session();
        if let Some(commands) = &self.commands {
            // Usually socket shutdown wakes the in-flight command and its
            // worker-side cancellation check drops the typed session. If the
            // result already won that race, this queued disconnect wakes the
            // idle worker and still scrubs its client/description. Both events
            // carry the cancelled request ID and are ignored by presentation
            // state after the first stale completion is consumed.
            let _ = commands.try_send(RemoteCommand::Disconnect { request });
        }
        shutdown_cancel_stream(&self.cancel_stream);
        Ok(())
    }

    /// `[egui thread, non-blocking]`
    pub(crate) fn read_registers(&mut self) -> Result<(), RemoteSessionError> {
        if !self.view.is_connected() {
            return Err(RemoteSessionError::NotConnected);
        }
        self.submit(RequestKind::Registers, |request| {
            RemoteCommand::ReadRegisters { request }
        })
    }

    /// `[egui thread, non-blocking]`
    pub(crate) fn read_memory(&mut self, read: RemoteMemoryRead) -> Result<(), RemoteSessionError> {
        if !self.view.is_connected() {
            return Err(RemoteSessionError::NotConnected);
        }
        self.submit(RequestKind::Memory, |request| RemoteCommand::ReadMemory {
            request,
            read,
        })
    }

    /// `[egui thread, non-blocking]` Request one typed read of the current EE
    /// program counter.
    ///
    /// This is a single explicit observation, never a poll. It fails closed
    /// unless the connected target matched the exact canonical PS2 EE schema.
    pub(crate) fn read_program_counter(&mut self) -> Result<(), RemoteSessionError> {
        require_program_counter_route(&self.view)?;
        self.submit(RequestKind::ProgramCounter, |request| {
            RemoteCommand::ReadProgramCounter { request }
        })
    }

    /// `[egui thread, non-blocking]` Apply every ready worker result.
    pub(crate) fn poll(&mut self) -> Vec<RemoteSessionNotice> {
        let mut notices = Vec::new();
        loop {
            let event = match self.events.as_ref().map(Receiver::try_recv) {
                Some(Ok(event)) => event,
                Some(Err(TryRecvError::Empty)) | None => break,
                Some(Err(TryRecvError::Disconnected)) => {
                    if !self.worker_disconnected {
                        self.worker_disconnected = true;
                        self.pending_request = None;
                        self.cancelled_request = None;
                        self.view.pending = None;
                        self.view.cancelling = false;
                        self.view.clear_session();
                        clear_cancel_stream(&self.cancel_stream);
                        let message = RemoteSessionError::WorkerDisconnected.to_string();
                        self.view.last_error = Some(message.clone());
                        notices.push(RemoteSessionNotice {
                            level: RemoteNoticeLevel::Error,
                            message,
                        });
                    }
                    break;
                }
            };
            match classify_event(self.pending_request, self.cancelled_request, event.request) {
                EventDisposition::Stale => continue,
                EventDisposition::Cancelled => {
                    self.pending_request = None;
                    self.view.pending = None;
                    self.view.cancelling = false;
                    self.cancelled_request = None;
                    self.cancel_requested.store(false, Ordering::Release);
                    self.view.clear_session();
                    clear_cancel_stream(&self.cancel_stream);
                    notices.push(RemoteSessionNotice {
                        level: RemoteNoticeLevel::Info,
                        message: format!("Cancelled remote {}", event.kind.label()),
                    });
                    continue;
                }
                EventDisposition::Apply => {
                    self.pending_request = None;
                    self.view.pending = None;
                    self.view.cancelling = false;
                    self.apply_event(event, &mut notices);
                }
            }
        }
        notices
    }

    fn submit(
        &mut self,
        kind: RequestKind,
        make: impl FnOnce(u64) -> RemoteCommand,
    ) -> Result<(), RemoteSessionError> {
        if self.pending_request.is_some() {
            return Err(RemoteSessionError::Busy);
        }
        let Some(commands) = &self.commands else {
            return Err(RemoteSessionError::WorkerDisconnected);
        };
        let request = self.next_request;
        let command = make(request);
        debug_assert_eq!(command.request(), request);
        debug_assert_eq!(command.kind(), kind);
        self.cancel_requested.store(false, Ordering::Release);
        self.cancelled_request = None;
        commands.try_send(command).map_err(|error| match error {
            TrySendError::Full(_) => RemoteSessionError::Busy,
            TrySendError::Disconnected(_) => RemoteSessionError::WorkerDisconnected,
        })?;
        self.next_request = self
            .next_request
            .checked_add(1)
            .expect("remote request identifier space exhausted");
        self.pending_request = Some(request);
        self.view.pending = Some(kind.label());
        self.view.last_error = None;
        Ok(())
    }

    fn apply_event(&mut self, event: RemoteEvent, notices: &mut Vec<RemoteSessionNotice>) {
        match event.outcome {
            RemoteOutcome::Connected {
                endpoint,
                advertised_features,
                target,
            } => {
                self.view.endpoint = Some(endpoint);
                self.view.advertised_features = Some(advertised_features);
                self.view.target = Some(target);
                self.view.register_summary = None;
                self.view.memory_summary = None;
                self.view.last_error = None;
                notices.push(RemoteSessionNotice {
                    level: RemoteNoticeLevel::Success,
                    message: format!("Connected read-only GDB RSP session to {endpoint}"),
                });
            }
            RemoteOutcome::Disconnected => {
                let endpoint = self.view.endpoint.take();
                self.view.clear_session();
                clear_cancel_stream(&self.cancel_stream);
                self.view.last_error = None;
                notices.push(RemoteSessionNotice {
                    level: RemoteNoticeLevel::Info,
                    message: endpoint.map_or_else(
                        || "Remote GDB RSP session disconnected".to_owned(),
                        |endpoint| format!("Disconnected remote GDB RSP session from {endpoint}"),
                    ),
                });
            }
            RemoteOutcome::Registers {
                byte_count,
                preview,
            } => {
                self.view.register_summary = Some(format!(
                    "{byte_count} byte register packet: {}{}",
                    hex_bytes(&preview),
                    if preview.len() < byte_count {
                        " ..."
                    } else {
                        ""
                    }
                ));
                self.view.last_error = None;
                notices.push(RemoteSessionNotice {
                    level: RemoteNoticeLevel::Success,
                    message: format!("Read {byte_count} raw register bytes from the remote target"),
                });
            }
            RemoteOutcome::Memory { address, bytes } => {
                self.view.memory_summary = Some(format!(
                    "{address:#018x} ({} byte{}): {}",
                    bytes.len(),
                    if bytes.len() == 1 { "" } else { "s" },
                    hex_bytes(&bytes)
                ));
                self.view.last_error = None;
                notices.push(RemoteSessionNotice {
                    level: RemoteNoticeLevel::Success,
                    message: format!("Read {} remote byte(s) at {address:#x}", bytes.len()),
                });
            }
            RemoteOutcome::ProgramCounter { pc } => {
                notices.push(apply_program_counter(&mut self.view, pc));
            }
            RemoteOutcome::Failed {
                detail,
                connection_lost,
            } => {
                self.view.clear_observation_for(event.kind);
                if connection_lost {
                    self.view.clear_session();
                    clear_cancel_stream(&self.cancel_stream);
                }
                let message = format!("Remote {} failed: {detail}", event.kind.label());
                self.view.last_error = Some(message.clone());
                notices.push(RemoteSessionNotice {
                    level: RemoteNoticeLevel::Error,
                    message,
                });
            }
        }
    }
}

impl Drop for RemoteSessionController {
    fn drop(&mut self) {
        // UI teardown must never join a network owner. Signal cancellation,
        // interrupt any socket operation, close the channels, and detach the
        // named worker. Its bounded connect path or interrupted I/O will unwind.
        self.cancel_requested.store(true, Ordering::Release);
        shutdown_cancel_stream(&self.cancel_stream);
        self.commands.take();
        self.events.take();
        drop(self.join.take());
    }
}

/// `[remote I/O thread]` Sole owner of the socket and protocol client.
fn remote_worker_loop(
    commands: Receiver<RemoteCommand>,
    events: SyncSender<RemoteEvent>,
    repaint: eframe::egui::Context,
    cancel_stream: Arc<Mutex<Option<TcpStream>>>,
    cancel_requested: Arc<AtomicBool>,
) {
    let mut client: Option<RemoteClientSession> = None;
    while let Ok(command) = commands.recv() {
        let request = command.request();
        let kind = command.kind();
        let outcome =
            process_remote_command(command, &mut client, &cancel_stream, &cancel_requested);
        if cancel_requested.load(Ordering::Acquire) {
            // Cancellation is a lifecycle boundary even if an operation won a
            // race with socket shutdown. Drop the worker-owned XML/schema and
            // client before reporting the stale result that the UI will ignore.
            client = None;
            clear_cancel_stream(&cancel_stream);
        }
        if events
            .send(RemoteEvent {
                request,
                kind,
                outcome,
            })
            .is_err()
        {
            break;
        }
        repaint.request_repaint();
    }
    clear_cancel_stream(&cancel_stream);
}

/// `[remote I/O thread]`
fn process_remote_command(
    command: RemoteCommand,
    client: &mut Option<RemoteClientSession>,
    cancel_stream: &Arc<Mutex<Option<TcpStream>>>,
    cancel_requested: &Arc<AtomicBool>,
) -> RemoteOutcome {
    match command {
        RemoteCommand::Connect { attach, .. } => {
            *client = None;
            clear_cancel_stream(cancel_stream);
            match connect_client(attach.endpoint(), cancel_stream, cancel_requested) {
                Ok((connected, advertised_features, target)) => {
                    *client = Some(connected);
                    RemoteOutcome::Connected {
                        endpoint: attach.endpoint(),
                        advertised_features,
                        target,
                    }
                }
                Err(error) => {
                    clear_cancel_stream(cancel_stream);
                    RemoteOutcome::Failed {
                        detail: bounded_io_error(error),
                        connection_lost: true,
                    }
                }
            }
        }
        RemoteCommand::Disconnect { .. } => {
            *client = None;
            clear_cancel_stream(cancel_stream);
            RemoteOutcome::Disconnected
        }
        RemoteCommand::ReadRegisters { .. } => {
            let Some(connected) = client.as_mut() else {
                return RemoteOutcome::Failed {
                    detail: RemoteSessionError::NotConnected.to_string(),
                    connection_lost: true,
                };
            };
            let result = connected.client.read_registers().and_then(|registers| {
                connected.description.validate_gpacket(&registers)?;
                Ok(registers)
            });
            match result {
                Ok(registers) => RemoteOutcome::Registers {
                    byte_count: registers.len(),
                    preview: registers
                        .into_iter()
                        .take(MAX_REGISTER_PREVIEW_BYTES)
                        .collect(),
                },
                Err(error) => {
                    *client = None;
                    clear_cancel_stream(cancel_stream);
                    RemoteOutcome::Failed {
                        detail: bounded_io_error(error),
                        connection_lost: true,
                    }
                }
            }
        }
        RemoteCommand::ReadProgramCounter { .. } => {
            let Some(connected) = client.as_mut() else {
                return RemoteOutcome::Failed {
                    detail: RemoteSessionError::NotConnected.to_string(),
                    connection_lost: true,
                };
            };
            // Re-enforce the schema here, against this worker's own retained
            // description, rather than trusting the egui-side route gate.
            if let Err(error) = require_exact_ps2_ee_schema(&connected.description) {
                // The packet stream is still synchronized and nothing was
                // read, so the session survives an unroutable request.
                return RemoteOutcome::Failed {
                    detail: bounded_io_error(error),
                    connection_lost: false,
                };
            }
            let result = connected.client.read_registers().and_then(|registers| {
                connected.description.validate_gpacket(&registers)?;
                extract_ee_program_counter(&registers)
                // `registers` is dropped here: the raw packet is worker-local
                // and only the typed program counter leaves this scope.
            });
            match result {
                Ok(pc) => RemoteOutcome::ProgramCounter { pc },
                Err(error) => {
                    *client = None;
                    clear_cancel_stream(cancel_stream);
                    RemoteOutcome::Failed {
                        detail: bounded_io_error(error),
                        connection_lost: true,
                    }
                }
            }
        }
        RemoteCommand::ReadMemory { read, .. } => {
            let Some(connected) = client.as_mut() else {
                return RemoteOutcome::Failed {
                    detail: RemoteSessionError::NotConnected.to_string(),
                    connection_lost: true,
                };
            };
            match connected.client.read_memory(read.address(), read.size()) {
                Ok(bytes) if bytes.len() == read.size() => RemoteOutcome::Memory {
                    address: read.address(),
                    bytes,
                },
                Ok(bytes) => {
                    *client = None;
                    clear_cancel_stream(cancel_stream);
                    RemoteOutcome::Failed {
                        detail: format!(
                            "target returned {} bytes for a {} byte request",
                            bytes.len(),
                            read.size()
                        ),
                        connection_lost: true,
                    }
                }
                Err(error) => {
                    *client = None;
                    clear_cancel_stream(cancel_stream);
                    RemoteOutcome::Failed {
                        detail: bounded_io_error(error),
                        connection_lost: true,
                    }
                }
            }
        }
    }
}

/// Complete typed session retained only by the remote-I/O worker.
#[derive(Debug)]
struct RemoteClientSession {
    client: GdbRemoteClient<TcpTransport>,
    description: RemoteTargetDescription,
}

/// `[remote I/O thread]`
fn connect_client(
    endpoint: SocketAddr,
    cancel_stream: &Arc<Mutex<Option<TcpStream>>>,
    cancel_requested: &Arc<AtomicBool>,
) -> io::Result<(RemoteClientSession, String, RemoteTargetView)> {
    let stream = TcpStream::connect_timeout(&endpoint, CONNECT_TIMEOUT)?;
    let interrupt = stream.try_clone()?;
    *cancel_stream
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(interrupt);
    if cancel_requested.load(Ordering::Acquire) {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "remote operation cancelled",
        ));
    }
    let transport = TcpTransport::from_connected_stream(stream)?;
    let mut client = GdbRemoteClient::new(transport).with_operation_timeout(IO_TIMEOUT);
    let advertised_features = client.query_supported()?;
    let description = require_target_description(client.read_target_description()?)?;
    let target = validate_target_description(&description)?;
    Ok((
        RemoteClientSession {
            client,
            description,
        },
        bounded_printable(&advertised_features, MAX_FEATURE_TEXT_BYTES),
        target,
    ))
}

fn require_target_description(
    description: Option<RemoteTargetDescription>,
) -> io::Result<RemoteTargetDescription> {
    description.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "remote stub does not provide qXfer:features:read:target.xml; typed inspection requires a target description",
        )
    })
}

fn validate_target_description(
    description: &RemoteTargetDescription,
) -> io::Result<RemoteTargetView> {
    let architecture = description.architecture().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "target description does not declare an architecture",
        )
    })?;
    let expected_gpacket_bytes = description.expected_gpacket_bytes().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "target description does not declare a register layout",
        )
    })?;

    let exact_ps2_ee_schema = if architecture == PS2_EE_TARGET_DESCRIPTION.architecture {
        let canonical = canonical_ps2_ee_description()?;
        if !matches_canonical_ps2_ee_schema(description, &canonical) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "mips:5900 target does not match the canonical {}-register, {PS2_EE_GPACKET_BYTES}-byte PS2 EE schema",
                    canonical.registers().len()
                ),
            ));
        }
        true
    } else {
        false
    };

    Ok(RemoteTargetView {
        architecture: architecture.to_owned(),
        byte_order: description.byte_order(),
        register_count: description.registers().len(),
        expected_gpacket_bytes,
        software_breakpoint_kind: description.software_breakpoint_kind(),
        exact_ps2_ee_schema,
    })
}

/// Parse ReSymbol's own canonical PS2 EE target description.
fn canonical_ps2_ee_description() -> io::Result<RemoteTargetDescription> {
    RemoteTargetDescription::parse(PS2_EE_TARGET_XML.to_owned())
}

/// Whether `description` is structurally identical to the canonical EE schema.
///
/// Both the connect-time validation and the worker's per-operation
/// re-enforcement resolve "exact PS2 EE schema" through this one definition, so
/// the two enforcement points cannot drift apart.
fn matches_canonical_ps2_ee_schema(
    description: &RemoteTargetDescription,
    canonical: &RemoteTargetDescription,
) -> bool {
    description.architecture() == Some(PS2_EE_TARGET_DESCRIPTION.architecture)
        && description.expected_gpacket_bytes()
            == Some(PS2_EE_TARGET_DESCRIPTION.register_packet_bytes)
        && description.registers() == canonical.registers()
        && description.byte_order() == Some(PS2_EE_TARGET_DESCRIPTION.byte_order)
        && description.software_breakpoint_kind()
            == Some(PS2_EE_TARGET_DESCRIPTION.software_breakpoint_kind)
}

/// `[remote I/O thread]` Fail closed unless the worker's retained description
/// is still the exact canonical PS2 EE schema.
fn require_exact_ps2_ee_schema(description: &RemoteTargetDescription) -> io::Result<()> {
    let canonical = canonical_ps2_ee_description()?;
    if matches_canonical_ps2_ee_schema(description, &canonical) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            RemoteSessionError::RequiresExactPs2EeSchema.to_string(),
        ))
    }
}

/// `[remote I/O thread]` Reduce one exact canonical EE `g` packet to its typed
/// program counter.
///
/// The length is re-checked here so parsing never depends on an earlier
/// validation having run. Every other decoded register — including the EE's
/// 128-bit GPR, HI, and LO state — is dropped when this function returns; only
/// the `u32` escapes.
fn extract_ee_program_counter(raw: &[u8]) -> io::Result<u32> {
    if raw.len() != PS2_EE_GPACKET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "expected exactly {PS2_EE_GPACKET_BYTES} canonical PS2 EE register bytes, got {}",
                raw.len()
            ),
        ));
    }
    ps2_ee_gpacket_to_registers(raw)
        .map(|registers| registers.pc)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn shutdown_cancel_stream(cancel_stream: &Arc<Mutex<Option<TcpStream>>>) {
    if let Some(stream) = cancel_stream
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
    {
        let _ = stream.shutdown(Shutdown::Both);
    }
}

fn clear_cancel_stream(cancel_stream: &Arc<Mutex<Option<TcpStream>>>) {
    cancel_stream
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
}

fn bounded_printable(bytes: &[u8], maximum: usize) -> String {
    let mut text = String::with_capacity(bytes.len().min(maximum));
    for byte in bytes.iter().copied().take(maximum) {
        text.push(if byte.is_ascii_graphic() || byte == b' ' {
            char::from(byte)
        } else {
            '\u{fffd}'
        });
    }
    if bytes.len() > maximum {
        text.push_str("...");
    }
    if text.is_empty() {
        "(no advertised qSupported features)".to_owned()
    } else {
        text
    }
}

fn bounded_io_error(error: io::Error) -> String {
    bounded_printable(error.to_string().as_bytes(), MAX_FEATURE_TEXT_BYTES)
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            text.push(' ');
        }
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    use resymbol_gdb_remote::{AMD64_TARGET_XML, Ps2EeCoreRegisters};

    /// Byte offset of the 32-bit `pc` register inside the canonical EE `g`
    /// packet, restated here so the extraction path is checked against a
    /// literal offset rather than against the serializer that produced it.
    const PS2_EE_PC_OFFSET: usize = 284;

    fn ee_target_view(exact_ps2_ee_schema: bool) -> RemoteTargetView {
        RemoteTargetView {
            architecture: PS2_EE_TARGET_DESCRIPTION.architecture.to_owned(),
            byte_order: Some(TargetByteOrder::Little),
            register_count: PS2_EE_REGISTER_COUNT,
            expected_gpacket_bytes: PS2_EE_GPACKET_BYTES,
            software_breakpoint_kind: Some(PS2_EE_TARGET_DESCRIPTION.software_breakpoint_kind),
            exact_ps2_ee_schema,
        }
    }

    fn connected_view(target: Option<RemoteTargetView>) -> RemoteSessionView {
        RemoteSessionView {
            endpoint: Some("127.0.0.1:1234".parse().expect("numeric endpoint")),
            target,
            ..RemoteSessionView::default()
        }
    }

    #[test]
    fn attach_defaults_fail_closed_for_non_loopback_networks() {
        assert!(RemoteAttachRequest::parse(DEFAULT_REMOTE_ENDPOINT, false).is_ok());
        assert_eq!(
            RemoteAttachRequest::parse("192.0.2.1:1234", false),
            Err(RemoteSessionError::NonLoopbackRequiresOptIn)
        );
        assert!(RemoteAttachRequest::parse("192.0.2.1:1234", true).is_ok());
    }

    #[test]
    fn attach_requires_numeric_nonzero_endpoint() {
        assert_eq!(
            RemoteAttachRequest::parse("localhost:1234", false),
            Err(RemoteSessionError::InvalidEndpoint)
        );
        assert_eq!(
            RemoteAttachRequest::parse("127.0.0.1:0", false),
            Err(RemoteSessionError::ZeroPort)
        );
    }

    #[test]
    fn memory_read_is_bounded_and_cannot_wrap() {
        assert_eq!(
            RemoteMemoryRead::new(0, 0),
            Err(RemoteSessionError::InvalidReadSize)
        );
        assert_eq!(
            RemoteMemoryRead::new(0, MAX_REMOTE_MEMORY_READ_BYTES + 1),
            Err(RemoteSessionError::InvalidReadSize)
        );
        assert_eq!(
            RemoteMemoryRead::new(u64::MAX, 2),
            Err(RemoteSessionError::AddressOverflow)
        );
        assert_eq!(
            RemoteMemoryRead::new(u64::MAX, 1),
            Ok(RemoteMemoryRead {
                address: u64::MAX,
                size: 1,
            })
        );
    }

    #[test]
    fn remote_policy_does_not_imply_mutation_or_execution_control() {
        let policy = RemoteSessionCapabilities::READ_ONLY;
        assert!(policy.read_registers);
        assert!(policy.read_memory);
        assert!(!policy.write_target);
        assert!(!policy.control_execution);
    }

    #[test]
    fn printable_diagnostics_are_bounded_and_sanitized() {
        assert_eq!(bounded_printable(b"abc\nxyz", 64), "abc\u{fffd}xyz");
        assert_eq!(bounded_printable(b"abcdef", 3), "abc...");
        assert_eq!(
            bounded_printable(b"", 3),
            "(no advertised qSupported features)"
        );
    }

    #[test]
    fn typed_surface_requires_a_target_description() {
        let error = require_target_description(None).expect_err("missing XML must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn canonical_ps2_description_is_typed_as_exact_708_byte_state() {
        let description = RemoteTargetDescription::parse(PS2_EE_TARGET_XML.to_owned())
            .expect("canonical PS2 XML");
        let target = validate_target_description(&description).expect("canonical PS2 schema");

        assert_eq!(
            target.architecture(),
            PS2_EE_TARGET_DESCRIPTION.architecture
        );
        assert_eq!(target.byte_order(), Some(TargetByteOrder::Little));
        assert_eq!(target.register_count(), 109);
        assert_eq!(target.expected_gpacket_bytes(), PS2_EE_GPACKET_BYTES);
        assert_eq!(
            target.software_breakpoint_kind(),
            Some(PS2_EE_TARGET_DESCRIPTION.software_breakpoint_kind)
        );
        assert!(target.is_exact_ps2_ee_schema());
    }

    #[test]
    fn ps2_description_rejects_structural_metadata_drift() {
        let drifted = PS2_EE_TARGET_XML.replacen(
            "name=\"fpu_acc\" bitsize=\"32\" regnum=\"108\" type=\"ieee_single\"",
            "name=\"fpu_acc\" bitsize=\"32\" regnum=\"108\" type=\"uint32\"",
            1,
        );
        assert_ne!(drifted, PS2_EE_TARGET_XML);
        let description =
            RemoteTargetDescription::parse(drifted).expect("drift remains valid target XML");

        let error = validate_target_description(&description)
            .expect_err("a near-match must not be treated as canonical EE state");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn session_scrub_removes_target_identity_and_observations() {
        let mut view = RemoteSessionView {
            endpoint: Some("127.0.0.1:1234".parse().expect("numeric endpoint")),
            pending: Some("memory read"),
            cancelling: true,
            advertised_features: Some("PacketSize=1000".to_owned()),
            target: Some(RemoteTargetView {
                architecture: "mips:5900".to_owned(),
                byte_order: Some(TargetByteOrder::Little),
                register_count: 109,
                expected_gpacket_bytes: PS2_EE_GPACKET_BYTES,
                software_breakpoint_kind: Some(4),
                exact_ps2_ee_schema: true,
            }),
            register_summary: Some("register bytes".to_owned()),
            memory_summary: Some("memory bytes".to_owned()),
            program_counter: Some(0x0010_2000),
            last_error: Some("diagnostic".to_owned()),
        };

        view.clear_session();

        assert!(!view.is_connected());
        assert!(view.advertised_features().is_none());
        assert!(view.target().is_none());
        assert!(view.register_summary().is_none());
        assert!(view.memory_summary().is_none());
        assert!(view.program_counter().is_none());
        assert!(view.is_pending());
        assert!(view.is_cancelling());
        assert_eq!(view.last_error(), Some("diagnostic"));
    }

    #[test]
    fn cancelling_status_is_distinct_from_ordinary_busy_state() {
        let mut view = RemoteSessionView {
            pending: Some("register read"),
            ..RemoteSessionView::default()
        };
        assert_eq!(view.status(), "[BUSY] register read");

        view.cancelling = true;
        assert_eq!(view.status(), "[CANCELLING] register read");
    }

    #[test]
    fn canonical_ps2_ee_constants_match_the_shared_schema() {
        let canonical = canonical_ps2_ee_description().expect("canonical PS2 XML");

        assert_eq!(canonical.registers().len(), PS2_EE_REGISTER_COUNT);
        assert_eq!(
            canonical.expected_gpacket_bytes(),
            Some(PS2_EE_GPACKET_BYTES)
        );
        assert_eq!(
            PS2_EE_TARGET_DESCRIPTION.register_packet_bytes,
            PS2_EE_GPACKET_BYTES
        );
    }

    #[test]
    fn ee_program_counter_is_read_from_the_canonical_packet_offset() {
        let mut packet = vec![0u8; PS2_EE_GPACKET_BYTES];
        packet[PS2_EE_PC_OFFSET..PS2_EE_PC_OFFSET + 4]
            .copy_from_slice(&0x0010_2000u32.to_le_bytes());
        assert_eq!(
            extract_ee_program_counter(&packet).expect("canonical packet"),
            0x0010_2000
        );

        // Cross-check the hand-built offset against the protocol crate's own
        // serializer so this constant cannot drift from the shared schema.
        let registers = Ps2EeCoreRegisters {
            pc: 0x2000_1234,
            ..Ps2EeCoreRegisters::default()
        };
        let serialized = registers.to_gpacket();
        assert_eq!(serialized.len(), PS2_EE_GPACKET_BYTES);
        assert_eq!(
            &serialized[PS2_EE_PC_OFFSET..PS2_EE_PC_OFFSET + 4],
            &0x2000_1234u32.to_le_bytes()
        );
        assert_eq!(
            extract_ee_program_counter(&serialized).expect("canonical packet"),
            0x2000_1234
        );
    }

    #[test]
    fn ee_program_counter_rejects_near_canonical_packet_lengths() {
        let packet = vec![0u8; PS2_EE_GPACKET_BYTES];

        assert_eq!(
            extract_ee_program_counter(&packet[..PS2_EE_GPACKET_BYTES - 1])
                .expect_err("a short packet must never be decoded")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut trailing = packet;
        trailing.push(0);
        assert_eq!(
            extract_ee_program_counter(&trailing)
                .expect_err("a long packet must never be decoded")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn worker_reenforcement_rejects_near_schema_and_foreign_targets() {
        let canonical = canonical_ps2_ee_description().expect("canonical PS2 XML");
        require_exact_ps2_ee_schema(&canonical).expect("canonical EE schema is routable");

        let drifted = PS2_EE_TARGET_XML.replacen(
            "name=\"fpu_acc\" bitsize=\"32\" regnum=\"108\" type=\"ieee_single\"",
            "name=\"fpu_acc\" bitsize=\"32\" regnum=\"108\" type=\"uint32\"",
            1,
        );
        assert_ne!(drifted, PS2_EE_TARGET_XML);
        let near_match =
            RemoteTargetDescription::parse(drifted).expect("drift remains valid target XML");
        assert_eq!(
            require_exact_ps2_ee_schema(&near_match)
                .expect_err("a near-match must never reach the EE program-counter route")
                .kind(),
            io::ErrorKind::Unsupported
        );

        let foreign = RemoteTargetDescription::parse(AMD64_TARGET_XML.to_owned())
            .expect("canonical amd64 XML");
        assert!(require_exact_ps2_ee_schema(&foreign).is_err());
    }

    #[test]
    fn program_counter_route_is_gated_on_connection_and_exact_schema() {
        assert_eq!(
            require_program_counter_route(&RemoteSessionView::default()),
            Err(RemoteSessionError::NotConnected)
        );
        assert!(!RemoteSessionView::default().can_read_program_counter());

        assert_eq!(
            require_program_counter_route(&connected_view(None)),
            Err(RemoteSessionError::RequiresExactPs2EeSchema)
        );
        assert_eq!(
            require_program_counter_route(&connected_view(Some(ee_target_view(false)))),
            Err(RemoteSessionError::RequiresExactPs2EeSchema)
        );

        let exact = connected_view(Some(ee_target_view(true)));
        assert_eq!(require_program_counter_route(&exact), Ok(()));
        assert!(exact.can_read_program_counter());
    }

    #[test]
    fn ee_program_counter_is_formatted_as_fixed_width_hexadecimal() {
        assert_eq!(format_ee_program_counter(0), "0x00000000");
        assert_eq!(format_ee_program_counter(0x0010_2000), "0x00102000");
        assert_eq!(format_ee_program_counter(u32::MAX), "0xffffffff");
        for pc in [0, 1, 0x0010_2000, 0x8000_0000, u32::MAX] {
            assert_eq!(format_ee_program_counter(pc).len(), 10);
        }
    }

    #[test]
    fn lifecycle_scrub_clears_the_ee_program_counter_preview() {
        let mut view = connected_view(Some(ee_target_view(true)));
        view.program_counter = Some(0x0010_2000);

        // Disconnect scrubs observations while the session is torn down.
        view.clear_observations();
        assert!(view.program_counter().is_none());

        // Connection attempt, cancellation, worker loss, and connection loss
        // all scrub the whole session, which must take the PC with it.
        view.program_counter = Some(0x0010_2000);
        view.clear_session();
        assert!(view.program_counter().is_none());
        assert!(!view.can_read_program_counter());
    }

    #[test]
    fn a_failed_program_counter_read_scrubs_only_its_own_preview() {
        let mut view = connected_view(Some(ee_target_view(true)));
        view.program_counter = Some(0x0010_2000);
        view.register_summary = Some("register bytes".to_owned());
        view.memory_summary = Some("memory bytes".to_owned());

        view.clear_observation_for(RequestKind::ProgramCounter);

        assert!(view.program_counter().is_none());
        assert_eq!(view.register_summary(), Some("register bytes"));
        assert_eq!(view.memory_summary(), Some("memory bytes"));
    }

    #[test]
    fn an_applied_program_counter_never_reaches_the_activity_log() {
        let mut view = connected_view(Some(ee_target_view(true)));
        let mut notices = Vec::new();

        for pc in [0, 1, 0x0010_2000, 0x8000_0000, u32::MAX] {
            let notice = apply_program_counter(&mut view, pc);

            // The typed scalar still reaches presentation state, where the
            // session scrub owns it and the explicit current-PC row renders it.
            assert_eq!(view.program_counter(), Some(pc));

            // Notices are forwarded to the bounded activity log and to the
            // companion console, neither of which any scrub can reach, so the
            // log-facing payload must carry no rendering of the value: not the
            // displayed literal, not a bare hexadecimal or decimal rendering,
            // and not a hexadecimal literal of any other observation.
            assert!(!notice.message.contains(&format_ee_program_counter(pc)));
            assert!(!notice.message.contains(&format!("{pc:x}")));
            assert!(!notice.message.contains(&format!("{pc:X}")));
            assert!(!notice.message.contains("0x"));
            assert!(!notice.message.contains("0X"));
            assert!(!notice.message.chars().any(|c| c.is_ascii_digit()));

            notices.push(notice);
        }

        // The invariant in its strongest form: the whole log-facing payload --
        // level and message -- is identical across the full 32-bit range, so it
        // cannot encode the program counter by any rendering at all.
        let (first, rest) = notices.split_first().expect("one applied result");
        for notice in rest {
            assert_eq!(notice, first);
        }
        assert_eq!(first.level, RemoteNoticeLevel::Success);

        // The sole retained copy still answers to the scrub.
        view.clear_session();
        assert!(view.program_counter().is_none());
    }

    #[test]
    fn cancelled_and_stale_program_counter_results_are_never_displayed() {
        // The sole tracked request completes normally.
        assert_eq!(classify_event(Some(7), None, 7), EventDisposition::Apply);
        // The same request once the UI cancelled it scrubs instead of showing
        // a PC the operator already withdrew.
        assert_eq!(
            classify_event(Some(7), Some(7), 7),
            EventDisposition::Cancelled
        );
        // A completion that lost its race with socket shutdown, or that landed
        // with nothing pending, never touches presentation state.
        assert_eq!(classify_event(Some(8), Some(7), 7), EventDisposition::Stale);
        assert_eq!(classify_event(None, Some(7), 7), EventDisposition::Stale);
        assert_eq!(classify_event(None, None, 7), EventDisposition::Stale);
    }
}
