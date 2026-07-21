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
    RemoteTargetDescription, TargetByteOrder, TcpTransport,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Connect,
    Disconnect,
    Registers,
    Memory,
}

impl RequestKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Disconnect => "disconnect",
            Self::Registers => "register read",
            Self::Memory => "memory read",
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
}

impl RemoteCommand {
    const fn request(&self) -> u64 {
        match self {
            Self::Connect { request, .. }
            | Self::Disconnect { request }
            | Self::ReadRegisters { request }
            | Self::ReadMemory { request, .. } => *request,
        }
    }

    const fn kind(&self) -> RequestKind {
        match self {
            Self::Connect { .. } => RequestKind::Connect,
            Self::Disconnect { .. } => RequestKind::Disconnect,
            Self::ReadRegisters { .. } => RequestKind::Registers,
            Self::ReadMemory { .. } => RequestKind::Memory,
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

    pub(crate) fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    fn clear_observations(&mut self) {
        self.register_summary = None;
        self.memory_summary = None;
    }

    fn clear_session(&mut self) {
        self.endpoint = None;
        self.advertised_features = None;
        self.target = None;
        self.clear_observations();
    }
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
            if self.pending_request != Some(event.request) {
                continue;
            }
            self.pending_request = None;
            self.view.pending = None;
            self.view.cancelling = false;
            if self.cancelled_request == Some(event.request) {
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
            self.apply_event(event, &mut notices);
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
            RemoteOutcome::Failed {
                detail,
                connection_lost,
            } => {
                match event.kind {
                    RequestKind::Registers => self.view.register_summary = None,
                    RequestKind::Memory => self.view.memory_summary = None,
                    RequestKind::Connect | RequestKind::Disconnect => {}
                }
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
        let canonical = RemoteTargetDescription::parse(PS2_EE_TARGET_XML.to_owned())?;
        if expected_gpacket_bytes != PS2_EE_TARGET_DESCRIPTION.register_packet_bytes
            || description.registers() != canonical.registers()
            || description.byte_order() != Some(PS2_EE_TARGET_DESCRIPTION.byte_order)
            || description.software_breakpoint_kind()
                != Some(PS2_EE_TARGET_DESCRIPTION.software_breakpoint_kind)
        {
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
            last_error: Some("diagnostic".to_owned()),
        };

        view.clear_session();

        assert!(!view.is_connected());
        assert!(view.advertised_features().is_none());
        assert!(view.target().is_none());
        assert!(view.register_summary().is_none());
        assert!(view.memory_summary().is_none());
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
}
