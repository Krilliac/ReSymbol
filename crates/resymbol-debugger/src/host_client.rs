//! Single-owner debugger-host client seam and deterministic reducer-backed fake.
//!
//! This module performs no process operations. The fake host exists to exercise
//! protocol and lifecycle invariants before a platform provider is permitted.

use std::{marker::PhantomData, rc::Rc};

use thiserror::Error;

use crate::host_codec::{
    HostCodecError, HostFrame, decode_command_frame, decode_event_frame, encode_command_frame,
    encode_event_frame,
};
use crate::host_wire::{
    EndpointRole, FrameSequence, HandshakeError, HandshakeMachine, HandshakeState,
    ProtocolVersion as WireProtocolVersion, SequenceTracker, WireError,
};
use crate::protocol::{
    BreakpointChange, CommandEnvelope, CommandId, CommandOutcome, DebugCommand, DebugEvent,
    DebugTargetRequest, EventEnvelope, EventSequenceCursor, ProtocolValidationError,
    ProtocolVersion, SessionId, SessionState, SessionStateKind,
};
use crate::sandbox::{
    AttestationMismatch, CleanupReceiptError, DiagnosticText, HelperBuildId,
    SandboxCleanupReceipt, SandboxLifecycleEvent, SandboxLifecycleState,
};
use crate::{SessionMachine, SessionMachineError};

pub const MAX_RESPONSE_FRAMES: usize = 256;
pub const MAX_PENDING_COMMANDS: usize = 1;
pub const MAX_RESPONSE_BATCH_BYTES: usize = 16 * 1024 * 1024;

/// A transport response whose frame count and aggregate encoded size were
/// bounded while frames were admitted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostResponseBatch {
    frames: Vec<HostFrame>,
    encoded_bytes: usize,
}

impl HostResponseBatch {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            frames: Vec::new(),
            encoded_bytes: 0,
        }
    }

    pub fn single(frame: HostFrame) -> Result<Self, ResponseBatchError> {
        let mut batch = Self::new();
        batch.push(frame)?;
        Ok(batch)
    }

    /// Admits one frame after checking both count and aggregate bytes. Pipe
    /// transports should call this immediately after decoding each frame.
    pub fn push(&mut self, frame: HostFrame) -> Result<(), ResponseBatchError> {
        if self.frames.len() >= MAX_RESPONSE_FRAMES {
            return Err(ResponseBatchError::TooManyFrames {
                maximum: MAX_RESPONSE_FRAMES,
            });
        }
        let frame_bytes = frame.header().frame_len()?;
        let encoded_bytes = self
            .encoded_bytes
            .checked_add(frame_bytes)
            .ok_or(ResponseBatchError::ByteCountOverflow)?;
        if encoded_bytes > MAX_RESPONSE_BATCH_BYTES {
            return Err(ResponseBatchError::TooManyBytes {
                actual: encoded_bytes,
                maximum: MAX_RESPONSE_BATCH_BYTES,
            });
        }
        self.encoded_bytes = encoded_bytes;
        self.frames.push(frame);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }

    #[must_use]
    pub fn first(&self) -> Option<&HostFrame> {
        self.frames.first()
    }

    #[must_use]
    pub fn into_frames(self) -> Vec<HostFrame> {
        self.frames
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResponseBatchError {
    #[error("response exceeds the frame limit of {maximum}")]
    TooManyFrames { maximum: usize },
    #[error("response has {actual} encoded bytes; maximum is {maximum}")]
    TooManyBytes { actual: usize, maximum: usize },
    #[error("response byte count overflow")]
    ByteCountOverflow,
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlShutdownReason {
    Graceful,
    ExplicitAbandon,
    ClientDropped,
    HandshakeFailed,
    ProtocolFailure,
    TransportFailure,
}

/// A synchronous frame exchange owned by one connection worker.
///
/// Implementations may own a helper process or an I/O thread, but must not
/// expose either handle. `exchange` runs on the connection owner thread and
/// returns only complete, bounded frames. It must fail instead of silently
/// reconnecting or changing the requested provider boundary.
pub trait HostFrameExchange {
    fn exchange(&mut self, request: HostFrame) -> Result<HostResponseBatch, HostTransportError>;

    /// Releases host-side reducer state only after the client has independently
    /// verified a terminal `Closed` state.
    fn release_session(&mut self, session_id: SessionId) -> Result<(), HostTransportError>;

    /// Tears down only the control transport. Success is not evidence that a
    /// target exited or that sandbox cleanup completed.
    fn shutdown_control(
        &mut self,
        reason: ControlShutdownReason,
    ) -> Result<(), HostTransportError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConnectionState {
    Connected,
    SessionOpen,
    Disconnected,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReceipt {
    pub command_id: CommandId,
    pub outcome: CommandOutcome,
    pub events: Vec<EventEnvelope>,
}

/// One connection and at most one active session.
///
/// The `Rc` marker intentionally makes this type `!Send` and `!Sync`; construct
/// and use it on its long-lived connection worker. UI code should communicate
/// with that worker through bounded queues rather than calling this API.
pub struct DebugHostClient<T: HostFrameExchange> {
    transport: T,
    connection_state: ClientConnectionState,
    negotiated_version: WireProtocolVersion,
    typed_version: ProtocolVersion,
    session: Option<ClientSession>,
    next_command_id: u64,
    next_outbound_frame_sequence: u64,
    next_inbound_frame_sequence: u64,
    event_cursor: EventSequenceCursor,
    transport_shutdown: bool,
    _owner_thread: PhantomData<Rc<()>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientSession {
    reducer: SessionMachine,
    sandbox_cleanup_verified: bool,
}

impl<T: HostFrameExchange> DebugHostClient<T> {
    /// Establishes the identity-pinned controller/host handshake.
    ///
    /// `[connection owner thread; potentially blocking]`
    pub fn connect(
        mut transport: T,
        nonce: [u8; 16],
        controller_build: impl Into<String>,
        expected_host_build: impl Into<String>,
    ) -> Result<Self, DebugHostClientError> {
        let mut handshake = HandshakeMachine::initiator(
            EndpointRole::Controller,
            nonce,
            controller_build,
            expected_host_build,
        )?;
        let hello = handshake.begin(FrameSequence::new(1)?)?;
        let responses = match transport.exchange(HostFrame::new(hello, Vec::new())?) {
            Ok(responses) => responses,
            Err(error) => {
                let _ = transport.shutdown_control(ControlShutdownReason::TransportFailure);
                return Err(error.into());
            }
        };
        if responses.len() != 1 {
            let _ = transport.shutdown_control(ControlShutdownReason::HandshakeFailed);
            return Err(DebugHostClientError::UnexpectedHandshakeResponseCount {
                actual: responses.len(),
            });
        }
        let acknowledgement = responses
            .first()
            .ok_or(DebugHostClientError::HandshakeIncomplete)?;
        if !acknowledgement.raw().is_empty() {
            let _ = transport.shutdown_control(ControlShutdownReason::HandshakeFailed);
            return Err(DebugHostClientError::HandshakeCarriedRawPayload);
        }
        if let Err(error) = handshake.accept(acknowledgement.header()) {
            let _ = transport.shutdown_control(ControlShutdownReason::HandshakeFailed);
            return Err(error.into());
        }
        if handshake.state() != HandshakeState::Established {
            let _ = transport.shutdown_control(ControlShutdownReason::HandshakeFailed);
            return Err(DebugHostClientError::HandshakeIncomplete);
        }
        let Some(negotiated_version) = handshake.negotiated_version() else {
            let _ = transport.shutdown_control(ControlShutdownReason::HandshakeFailed);
            return Err(DebugHostClientError::HandshakeIncomplete);
        };
        let typed_version = bind_typed_protocol_version(negotiated_version).map_err(|error| {
            let _ = transport.shutdown_control(ControlShutdownReason::HandshakeFailed);
            error
        })?;
        Ok(Self {
            transport,
            connection_state: ClientConnectionState::Connected,
            negotiated_version,
            typed_version,
            session: None,
            next_command_id: 1,
            next_outbound_frame_sequence: 2,
            next_inbound_frame_sequence: 2,
            event_cursor: EventSequenceCursor::default(),
            transport_shutdown: false,
            _owner_thread: PhantomData,
        })
    }

    #[must_use]
    pub const fn connection_state(&self) -> ClientConnectionState {
        self.connection_state
    }

    #[must_use]
    pub const fn negotiated_version(&self) -> WireProtocolVersion {
        self.negotiated_version
    }

    #[must_use]
    pub fn session_id(&self) -> Option<SessionId> {
        self.session
            .as_ref()
            .map(|session| session.reducer.session_id())
    }

    #[must_use]
    pub fn session_state(&self) -> Option<&SessionState> {
        self.session
            .as_ref()
            .map(|session| session.reducer.state())
    }

    /// Claims one logical session on this connection. The host independently
    /// creates its reducer when it receives the first `Open` command, so merely
    /// calling this method never claims a target has been opened.
    ///
    /// `[connection owner thread]`
    pub fn begin_session(
        &mut self,
        session_id: SessionId,
        helper_build: HelperBuildId,
    ) -> Result<(), DebugHostClientError> {
        self.require_connected()?;
        if self.session.is_some() {
            return Err(DebugHostClientError::SessionAlreadyOwned);
        }
        self.session = Some(ClientSession {
            reducer: SessionMachine::new(session_id, helper_build),
            sandbox_cleanup_verified: false,
        });
        self.connection_state = ClientConnectionState::SessionOpen;
        Ok(())
    }

    /// Submits exactly one command and validates its complete correlated event
    /// batch before returning it to the caller.
    ///
    /// `[connection owner thread; potentially blocking]`
    pub fn submit(
        &mut self,
        command: DebugCommand,
    ) -> Result<CommandReceipt, DebugHostClientError> {
        self.require_session_open()?;
        if matches!(&command, DebugCommand::ProbeCapabilities) {
            return Err(DebugHostClientError::GlobalCommandRequiresConnectionApi);
        }
        let session = self
            .session
            .as_ref()
            .ok_or(DebugHostClientError::SessionNotOwned)?;
        let command_id =
            CommandId::new(self.next_command_id).map_err(DebugHostClientError::Protocol)?;
        let state = session.reducer.state().state_token();
        let envelope = CommandEnvelope {
            version: self.typed_version,
            command_id,
            session_id: Some(session.reducer.session_id()),
            expected_state: Some(state),
            command,
        };
        envelope.validate_against(session.reducer.state())?;
        let original_reducer = session.reducer.clone();
        let mut candidate_reducer = original_reducer.clone();
        candidate_reducer.accept_command(&envelope)?;
        let required_command_state = (candidate_reducer.state() != original_reducer.state())
            .then(|| candidate_reducer.state().clone());

        let frame_sequence = FrameSequence::new(self.next_outbound_frame_sequence)?;
        let request = encode_command_frame(frame_sequence, &envelope)?;
        self.next_outbound_frame_sequence = self
            .next_outbound_frame_sequence
            .checked_add(1)
            .ok_or(DebugHostClientError::FrameSequenceOverflow)?;
        self.next_command_id = self
            .next_command_id
            .checked_add(1)
            .ok_or(DebugHostClientError::CommandIdOverflow)?;
        let responses = match self.transport.exchange(request) {
            Ok(responses) => responses,
            Err(error) => {
                self.connection_state = if error.is_disconnected() {
                    ClientConnectionState::Disconnected
                } else {
                    ClientConnectionState::Failed
                };
                self.shutdown_transport(ControlShutdownReason::TransportFailure);
                return Err(error.into());
            }
        };
        self.accept_response_batch(
            command_id,
            &envelope,
            original_reducer,
            candidate_reducer,
            required_command_state,
            responses,
        )
    }

    /// Releases only a terminal, reducer-confirmed session. This does not send
    /// a target operation and cannot turn an unclean session into a clean one.
    ///
    /// `[connection owner thread]`
    pub fn release_closed_session(&mut self) -> Result<(), DebugHostClientError> {
        self.require_session_open()?;
        let session = self
            .session
            .as_ref()
            .ok_or(DebugHostClientError::SessionNotOwned)?;
        if session.reducer.state().kind() != SessionStateKind::Closed {
            return Err(DebugHostClientError::SessionNotClosed {
                state: session.reducer.state().kind(),
            });
        }
        if session.reducer.expected_attestation().is_some() && !session.sandbox_cleanup_verified {
            return Err(DebugHostClientError::SandboxCleanupNotVerified);
        }
        let session_id = session.reducer.session_id();
        self.transport.release_session(session_id)?;
        self.session = None;
        self.connection_state = ClientConnectionState::Connected;
        Ok(())
    }

    /// Closes the control connection. An active target session must first
    /// reach `Closed`, including exact sandbox cleanup when applicable.
    ///
    /// `[connection owner thread; potentially blocking]`
    pub fn disconnect(&mut self) -> Result<(), DebugHostClientError> {
        if self.connection_state == ClientConnectionState::Disconnected {
            return Ok(());
        }
        if self.session.is_some() {
            return Err(DebugHostClientError::SessionStillOwned);
        }
        self.transport
            .shutdown_control(ControlShutdownReason::Graceful)?;
        self.transport_shutdown = true;
        self.connection_state = ClientConnectionState::Disconnected;
        Ok(())
    }

    /// Abandons an active logical session by tearing down the control channel.
    /// This deliberately returns no cleanup receipt and makes no claim that a
    /// target exited, containment held, or provider cleanup completed.
    pub fn abandon_session(&mut self) -> Result<(), DebugHostClientError> {
        self.require_session_open()?;
        let result = self
            .transport
            .shutdown_control(ControlShutdownReason::ExplicitAbandon);
        self.transport_shutdown = true;
        self.connection_state = ClientConnectionState::Disconnected;
        self.session = None;
        result.map_err(Into::into)
    }

    fn accept_response_batch(
        &mut self,
        command_id: CommandId,
        envelope: &CommandEnvelope,
        original_reducer: SessionMachine,
        candidate_reducer: SessionMachine,
        required_command_state: Option<SessionState>,
        responses: HostResponseBatch,
    ) -> Result<CommandReceipt, DebugHostClientError> {
        let result = self.accept_response_batch_inner(
            command_id,
            envelope,
            original_reducer,
            candidate_reducer,
            required_command_state,
            responses,
        );
        if result.is_err() {
            self.connection_state = ClientConnectionState::Failed;
            self.shutdown_transport(ControlShutdownReason::ProtocolFailure);
        }
        result
    }

    fn accept_response_batch_inner(
        &mut self,
        command_id: CommandId,
        envelope: &CommandEnvelope,
        original_reducer: SessionMachine,
        mut candidate_reducer: SessionMachine,
        required_command_state: Option<SessionState>,
        responses: HostResponseBatch,
    ) -> Result<CommandReceipt, DebugHostClientError> {
        if responses.is_empty() {
            return Err(DebugHostClientError::MissingCommandResult { command_id });
        }
        let mut events = Vec::with_capacity(responses.len());
        let mut outcome = None;
        let mut evidence = ResponseEvidence::default();

        for frame in responses.into_frames() {
            if frame.header().sequence.get() != self.next_inbound_frame_sequence {
                return self.fail(DebugHostClientError::UnexpectedFrameSequence {
                    expected: self.next_inbound_frame_sequence,
                    actual: frame.header().sequence.get(),
                });
            }
            self.next_inbound_frame_sequence = self
                .next_inbound_frame_sequence
                .checked_add(1)
                .ok_or(DebugHostClientError::FrameSequenceOverflow)?;
            let event = decode_event_frame(&frame)?;
            if event.version != self.typed_version {
                return Err(DebugHostClientError::TypedProtocolVersionMismatch {
                    negotiated_major: self.typed_version.major,
                    negotiated_minor: self.typed_version.minor,
                    received_major: event.version.major,
                    received_minor: event.version.minor,
                });
            }
            self.event_cursor.observe(event.sequence)?;
            if event.caused_by != Some(command_id) {
                return self.fail(DebugHostClientError::UnexpectedCommandCorrelation {
                    expected: command_id,
                    actual: event.caused_by,
                });
            }
            let session_id = self
                .session
                .as_ref()
                .ok_or(DebugHostClientError::SessionNotOwned)?
                .reducer
                .session_id();
            if event.session_id != Some(session_id) {
                return self.fail(DebugHostClientError::UnexpectedEventSession {
                    expected: session_id,
                    actual: event.session_id,
                });
            }
            if !matches!(&event.event, DebugEvent::StateChanged(_))
                && event.state != Some(candidate_reducer.state().state_token())
            {
                return Err(DebugHostClientError::UnexpectedEventState {
                    expected: candidate_reducer.state().state_token(),
                    actual: event.state,
                });
            }
            match &event.event {
                DebugEvent::StateChanged(state) => {
                    apply_state_event(
                        &mut candidate_reducer,
                        state,
                        evidence.cleanup_receipt.as_ref(),
                    )?;
                    evidence.state_changed = true;
                    if required_command_state.as_ref() == Some(state) {
                        evidence.command_state_observed = true;
                    }
                }
                DebugEvent::SandboxAttested(attestation) => accept_attestation_event(
                    &mut candidate_reducer,
                    attestation,
                    &mut evidence,
                )?,
                DebugEvent::SandboxLifecycle(lifecycle) => validate_sandbox_lifecycle(
                    &candidate_reducer,
                    lifecycle,
                    &mut evidence,
                )?,
                DebugEvent::MemoryRead {
                    view,
                    address,
                    bytes,
                } => match &envelope.command {
                    DebugCommand::ReadMemory {
                        view: expected_view,
                        address: expected_address,
                        size,
                    } if view == expected_view
                        && address == expected_address
                        && bytes.len() == *size as usize =>
                    {
                        require_unique_evidence(&mut evidence.memory_read, "memory read")?;
                    }
                    _ => return Err(DebugHostClientError::UnexpectedCommandEvidence),
                },
                DebugEvent::MemoryWritten {
                    stop,
                    address,
                    before,
                    after,
                } => match &envelope.command {
                    DebugCommand::WriteMemory {
                        address: expected_address,
                        expected,
                        replacement,
                        ..
                    } if address == expected_address
                        && before == expected
                        && after == replacement
                        && matches!(
                            candidate_reducer.state(),
                            SessionState::Stopped { token, .. } if token == stop
                        ) =>
                    {
                        require_unique_evidence(&mut evidence.memory_written, "memory write")?;
                    }
                    _ => return Err(DebugHostClientError::UnexpectedCommandEvidence),
                },
                DebugEvent::BreakpointChanged {
                    stop,
                    breakpoint,
                    change,
                } => {
                    let current_stop = match candidate_reducer.state() {
                        SessionState::Stopped { token, .. } => token,
                        _ => return Err(DebugHostClientError::UnexpectedCommandEvidence),
                    };
                    if stop != current_stop {
                        return Err(DebugHostClientError::UnexpectedCommandEvidence);
                    }
                    let matches_command = match (&envelope.command, change) {
                        (
                            DebugCommand::SetBreakpoint {
                                breakpoint: expected,
                                ..
                            },
                            BreakpointChange::Set,
                        ) => breakpoint == expected,
                        (
                            DebugCommand::RemoveBreakpoint {
                                breakpoint_id, ..
                            },
                            BreakpointChange::Removed,
                        ) => breakpoint.id == *breakpoint_id,
                        _ => false,
                    };
                    if !matches_command {
                        return Err(DebugHostClientError::UnexpectedCommandEvidence);
                    }
                    require_unique_evidence(&mut evidence.breakpoint_changed, "breakpoint change")?;
                }
                DebugEvent::CommandResult {
                    command_id: result_id,
                    outcome: result,
                } => {
                    if *result_id != command_id {
                        return self.fail(DebugHostClientError::UnexpectedCommandCorrelation {
                            expected: command_id,
                            actual: Some(*result_id),
                        });
                    }
                    if outcome.replace(result.clone()).is_some() {
                        return self
                            .fail(DebugHostClientError::DuplicateCommandResult { command_id });
                    }
                }
                DebugEvent::Warning { .. } => {}
                DebugEvent::Capabilities(_) => {
                    return Err(DebugHostClientError::UnexpectedCommandEvidence);
                }
            }
            events.push(event);
        }
        let outcome = outcome.ok_or_else(|| {
            self.connection_state = ClientConnectionState::Failed;
            DebugHostClientError::MissingCommandResult { command_id }
        })?;
        match &outcome {
            CommandOutcome::Rejected { .. } => {
                if evidence.has_effect() {
                    return Err(DebugHostClientError::RejectedCommandChangedState { command_id });
                }
            }
            CommandOutcome::Succeeded => {
                if required_command_state.is_some() && !evidence.command_state_observed {
                    return Err(DebugHostClientError::MissingCommandState { command_id });
                }
                validate_success_evidence(
                    &envelope.command,
                    &candidate_reducer,
                    &evidence,
                    command_id,
                )?;
                let session = self
                    .session
                    .as_mut()
                    .ok_or(DebugHostClientError::SessionNotOwned)?;
                session.sandbox_cleanup_verified = candidate_reducer.state().kind()
                    == SessionStateKind::Closed
                    && candidate_reducer.expected_attestation().is_some()
                    && evidence.cleanup_receipt.is_some();
                session.reducer = candidate_reducer;
            }
        }
        debug_assert_eq!(
            self.session
                .as_ref()
                .map(|session| session.reducer.state()),
            if matches!(&outcome, CommandOutcome::Succeeded) {
                self.session
                    .as_ref()
                    .map(|session| session.reducer.state())
            } else {
                Some(original_reducer.state())
            }
        );
        Ok(CommandReceipt {
            command_id,
            outcome,
            events,
        })
    }

    fn require_connected(&self) -> Result<(), DebugHostClientError> {
        match self.connection_state {
            ClientConnectionState::Connected | ClientConnectionState::SessionOpen => Ok(()),
            ClientConnectionState::Disconnected => Err(DebugHostClientError::Disconnected),
            ClientConnectionState::Failed => Err(DebugHostClientError::ConnectionFailed),
        }
    }

    fn require_session_open(&self) -> Result<(), DebugHostClientError> {
        self.require_connected()?;
        if self.connection_state != ClientConnectionState::SessionOpen || self.session.is_none() {
            Err(DebugHostClientError::SessionNotOwned)
        } else {
            Ok(())
        }
    }

    fn fail<U>(&mut self, error: DebugHostClientError) -> Result<U, DebugHostClientError> {
        self.connection_state = ClientConnectionState::Failed;
        let _ = self.transport.disconnect();
        Err(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HostTransportError {
    #[error("debugger host disconnected")]
    Disconnected,
    #[error("debugger host protocol failure: {detail:?}")]
    Protocol { detail: DiagnosticText },
    #[error("debugger host backend failure: {detail:?}")]
    Backend { detail: DiagnosticText },
}

impl HostTransportError {
    pub fn protocol(detail: impl Into<String>) -> Self {
        Self::Protocol {
            detail: bounded_transport_detail(detail),
        }
    }

    pub fn backend(detail: impl Into<String>) -> Self {
        Self::Backend {
            detail: bounded_transport_detail(detail),
        }
    }

    #[must_use]
    pub const fn is_disconnected(&self) -> bool {
        matches!(self, Self::Disconnected)
    }
}

fn bounded_transport_detail(detail: impl Into<String>) -> DiagnosticText {
    let detail = detail.into();
    DiagnosticText::new(detail).unwrap_or_else(|_| {
        DiagnosticText::new("invalid or overlong transport diagnostic")
            .expect("static transport diagnostic is valid")
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DebugHostClientError {
    #[error(transparent)]
    Transport(#[from] HostTransportError),
    #[error(transparent)]
    Codec(#[from] HostCodecError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    #[error("handshake returned {actual} frames; exactly one is required")]
    UnexpectedHandshakeResponseCount { actual: usize },
    #[error("handshake acknowledgement carried a raw payload")]
    HandshakeCarriedRawPayload,
    #[error("handshake did not reach established state")]
    HandshakeIncomplete,
    #[error("debugger host connection is disconnected")]
    Disconnected,
    #[error("debugger host connection is terminal after protocol failure")]
    ConnectionFailed,
    #[error("this connection already owns a session")]
    SessionAlreadyOwned,
    #[error("this connection does not own a session")]
    SessionNotOwned,
    #[error("session must be closed before release; current state is {state:?}")]
    SessionNotClosed { state: SessionStateKind },
    #[error("session must be released before disconnect")]
    SessionStillOwned,
    #[error("global capability probing is not a session command")]
    GlobalCommandRequiresConnectionApi,
    #[error("command identifier exhausted its u64 space")]
    CommandIdOverflow,
    #[error("host returned no correlated result for command {command_id:?}")]
    MissingCommandResult { command_id: CommandId },
    #[error("host returned more than {maximum} response frames ({actual})")]
    TooManyResponseFrames { actual: usize, maximum: usize },
    #[error("expected frame sequence {expected}, received {actual}")]
    UnexpectedFrameSequence { expected: u64, actual: u64 },
    #[error("frame sequence exhausted its u64 space")]
    FrameSequenceOverflow,
    #[error("expected correlation {expected:?}, received {actual:?}")]
    UnexpectedCommandCorrelation {
        expected: CommandId,
        actual: Option<CommandId>,
    },
    #[error("expected event session {expected:?}, received {actual:?}")]
    UnexpectedEventSession {
        expected: SessionId,
        actual: Option<SessionId>,
    },
    #[error("host returned more than one result for command {command_id:?}")]
    DuplicateCommandResult { command_id: CommandId },
    #[error("rejected command {command_id:?} changed session state")]
    RejectedCommandChangedState { command_id: CommandId },
    #[error("expected state generation {expected}, received {actual}")]
    UnexpectedStateGeneration { expected: u64, actual: u64 },
    #[error("state generation exhausted its u64 space")]
    StateGenerationOverflow,
}

/// A deterministic, non-executing host used for integration and UI tests.
///
/// It owns only pure reducers and bounded frames. It does not inspect files,
/// attach processes, launch targets, or claim platform capabilities.
pub struct InMemoryDebugHost {
    handshake: HandshakeMachine,
    helper_build: HelperBuildId,
    machine: Option<SessionMachine>,
    command_frames: SequenceTracker,
    next_frame_sequence: u64,
    next_event_sequence: u64,
    successful_exchanges: usize,
    disconnect_after: Option<usize>,
    backend_error_after: Option<usize>,
    disconnected: bool,
}

impl InMemoryDebugHost {
    pub fn new(
        host_build: impl Into<String>,
        expected_controller_build: impl Into<String>,
        helper_build: HelperBuildId,
    ) -> Result<Self, HandshakeError> {
        Ok(Self {
            handshake: HandshakeMachine::responder(
                EndpointRole::Host,
                host_build,
                expected_controller_build,
            )?,
            helper_build,
            machine: None,
            command_frames: SequenceTracker::default(),
            next_frame_sequence: 2,
            next_event_sequence: 1,
            successful_exchanges: 0,
            disconnect_after: None,
            backend_error_after: None,
            disconnected: false,
        })
    }

    /// Disconnect before the first exchange after `count` successful exchanges.
    #[must_use]
    pub fn with_disconnect_after(mut self, count: usize) -> Self {
        self.disconnect_after = Some(count);
        self
    }

    /// Return a deterministic bounded backend error after `count` successes.
    #[must_use]
    pub fn with_backend_error_after(mut self, count: usize) -> Self {
        self.backend_error_after = Some(count);
        self
    }

    fn exchange_inner(&mut self, request: HostFrame) -> Result<Vec<HostFrame>, HostTransportError> {
        if self.disconnected {
            return Err(HostTransportError::Disconnected);
        }
        if self.disconnect_after == Some(self.successful_exchanges) {
            self.disconnected = true;
            return Err(HostTransportError::Disconnected);
        }
        if self.backend_error_after == Some(self.successful_exchanges) {
            return Err(HostTransportError::backend(
                "injected in-memory backend failure",
            ));
        }

        let responses = if self.handshake.state() != HandshakeState::Established {
            if !request.raw().is_empty() {
                return Err(HostTransportError::protocol(
                    "handshake request carried raw payload",
                ));
            }
            self.command_frames
                .observe(request.header().sequence)
                .map_err(|error| HostTransportError::protocol(error.to_string()))?;
            let acknowledgement = self
                .handshake
                .accept(request.header())
                .map_err(|error| HostTransportError::protocol(error.to_string()))?
                .ok_or_else(|| HostTransportError::protocol("unexpected handshake direction"))?;
            vec![
                HostFrame::new(acknowledgement, Vec::new())
                    .map_err(|error| HostTransportError::protocol(error.to_string()))?,
            ]
        } else {
            self.command_frames
                .observe(request.header().sequence)
                .map_err(|error| HostTransportError::protocol(error.to_string()))?;
            let command = decode_command_frame(&request)
                .map_err(|error| HostTransportError::protocol(error.to_string()))?;
            self.handle_command(command)?
        };
        self.successful_exchanges = self
            .successful_exchanges
            .checked_add(1)
            .ok_or_else(|| HostTransportError::backend("exchange counter overflow"))?;
        Ok(responses)
    }

    fn handle_command(
        &mut self,
        envelope: CommandEnvelope,
    ) -> Result<Vec<HostFrame>, HostTransportError> {
        if matches!(&envelope.command, DebugCommand::ProbeCapabilities) {
            return Err(HostTransportError::protocol(
                "the in-memory session seam does not claim global capabilities",
            ));
        }
        let session_id = envelope
            .session_id
            .ok_or_else(|| HostTransportError::protocol("session command omitted session id"))?;
        if self.machine.is_none()
            || self.machine.as_ref().is_some_and(|machine| {
                machine.state().kind() == SessionStateKind::Closed
                    && machine.session_id() != session_id
            })
        {
            if !matches!(&envelope.command, DebugCommand::Open(_)) {
                return Err(HostTransportError::protocol(
                    "first command for a session must be open",
                ));
            }
            self.machine = Some(SessionMachine::new(session_id, self.helper_build.clone()));
        }
        if self
            .machine
            .as_ref()
            .is_some_and(|machine| machine.session_id() != session_id)
        {
            return Err(HostTransportError::protocol(
                "connection already owns a different session",
            ));
        }

        let command_id = envelope.command_id;
        let command = envelope.command.clone();
        let before = self.machine_ref()?.state().clone();
        let accepted = self.machine_mut()?.accept_command(&envelope).cloned();
        let mut events = Vec::new();
        match accepted {
            Ok(after) => {
                if after != before {
                    self.push_event(&mut events, command_id, DebugEvent::StateChanged(after))?;
                }
                self.drive_accepted_command(command_id, command, &mut events)?;
                self.push_event(
                    &mut events,
                    command_id,
                    DebugEvent::CommandResult {
                        command_id,
                        outcome: CommandOutcome::Succeeded,
                    },
                )?;
            }
            Err(error) => {
                self.push_event(
                    &mut events,
                    command_id,
                    DebugEvent::CommandResult {
                        command_id,
                        outcome: CommandOutcome::Rejected {
                            code: "command-rejected".to_owned(),
                            message: bounded_rejection_message(&error),
                        },
                    },
                )?;
            }
        }
        Ok(events)
    }

    fn drive_accepted_command(
        &mut self,
        command_id: CommandId,
        command: DebugCommand,
        events: &mut Vec<HostFrame>,
    ) -> Result<(), HostTransportError> {
        match command {
            DebugCommand::Open(target) => self.drive_open(command_id, target, events)?,
            DebugCommand::Pause { .. } => {
                let state = self
                    .machine_mut()?
                    .mark_stopped(
                        StopReason::UserPause,
                        ThreadId::new(1).expect("fake thread id is nonzero"),
                    )
                    .map_err(machine_error)?
                    .clone();
                self.push_event(events, command_id, DebugEvent::StateChanged(state))?;
            }
            DebugCommand::Step { .. } => {
                let state = self
                    .machine_mut()?
                    .mark_stopped(
                        StopReason::SingleStep,
                        ThreadId::new(1).expect("fake thread id is nonzero"),
                    )
                    .map_err(machine_error)?
                    .clone();
                self.push_event(events, command_id, DebugEvent::StateChanged(state))?;
            }
            DebugCommand::Close { .. } | DebugCommand::Terminate { .. } => {
                self.drive_close(command_id, events)?;
            }
            DebugCommand::Continue { .. }
            | DebugCommand::ReadMemory { .. }
            | DebugCommand::WriteMemory { .. }
            | DebugCommand::SetBreakpoint { .. }
            | DebugCommand::RemoveBreakpoint { .. }
            | DebugCommand::CaptureSnapshot { .. }
            | DebugCommand::Detach { .. } => {}
            DebugCommand::ProbeCapabilities => unreachable!("handled before session dispatch"),
        }
        Ok(())
    }

    fn drive_open(
        &mut self,
        command_id: CommandId,
        target: DebugTargetRequest,
        events: &mut Vec<HostFrame>,
    ) -> Result<(), HostTransportError> {
        match target {
            DebugTargetRequest::Offline(_) => {
                let state = self
                    .machine_mut()?
                    .complete_open_offline()
                    .map_err(machine_error)?
                    .clone();
                self.push_event(events, command_id, DebugEvent::StateChanged(state))?;
            }
            DebugTargetRequest::Dump(_) => {
                let state = self
                    .machine_mut()?
                    .complete_open_dump()
                    .map_err(machine_error)?
                    .clone();
                self.push_event(events, command_id, DebugEvent::StateChanged(state))?;
            }
            DebugTargetRequest::Attach(target)
                if target.mode == crate::protocol::AttachMode::ObserveReadOnly =>
            {
                let process_id = match target.scope {
                    crate::protocol::AttachScope::Host { process_id, .. }
                    | crate::protocol::AttachScope::OwnedSandbox { process_id, .. } => process_id,
                };
                let state = self
                    .machine_mut()?
                    .complete_open_observing(process_id)
                    .map_err(machine_error)?
                    .clone();
                self.push_event(events, command_id, DebugEvent::StateChanged(state))?;
            }
            DebugTargetRequest::Launch(crate::protocol::LaunchTarget {
                environment: crate::protocol::LaunchEnvironment::Sandboxed { .. },
                ..
            }) => {
                self.push_sandbox_state(events, command_id, SandboxLifecycleState::Provisioning)?;
                let state = self
                    .machine_mut()?
                    .target_created_suspended()
                    .map_err(machine_error)?
                    .clone();
                self.push_event(events, command_id, DebugEvent::StateChanged(state))?;
                self.push_sandbox_state(
                    events,
                    command_id,
                    SandboxLifecycleState::TargetCreatedSuspended,
                )?;
                let actual =
                    exact_attestation(self.machine_ref()?.expected_attestation().ok_or_else(
                        || HostTransportError::protocol("missing expected attestation"),
                    )?);
                self.push_event(
                    events,
                    command_id,
                    DebugEvent::SandboxAttested(actual.clone()),
                )?;
                let state = self
                    .machine_mut()?
                    .accept_sandbox_attestation(&actual)
                    .map_err(machine_error)?
                    .clone();
                self.push_event(events, command_id, DebugEvent::StateChanged(state))?;
                self.push_sandbox_state(
                    events,
                    command_id,
                    SandboxLifecycleState::AttestationAccepted,
                )?;
                self.mark_initial_stop(command_id, events)?;
            }
            DebugTargetRequest::Launch(_) | DebugTargetRequest::Attach(_) => {
                self.mark_initial_stop(command_id, events)?;
            }
        }
        Ok(())
    }

    fn mark_initial_stop(
        &mut self,
        command_id: CommandId,
        events: &mut Vec<HostFrame>,
    ) -> Result<(), HostTransportError> {
        let state = self
            .machine_mut()?
            .mark_stopped(
                StopReason::Initial,
                ThreadId::new(1).expect("fake thread id is nonzero"),
            )
            .map_err(machine_error)?
            .clone();
        self.push_event(events, command_id, DebugEvent::StateChanged(state))
    }

    fn drive_close(
        &mut self,
        command_id: CommandId,
        events: &mut Vec<HostFrame>,
    ) -> Result<(), HostTransportError> {
        let receipt = self
            .machine_ref()?
            .expected_attestation()
            .map(complete_cleanup_receipt);
        if receipt.is_some() {
            self.push_sandbox_state(events, command_id, SandboxLifecycleState::Cleanup)?;
        }
        let state = self
            .machine_mut()?
            .complete_close(receipt.as_ref())
            .map_err(machine_error)?
            .clone();
        self.push_event(events, command_id, DebugEvent::StateChanged(state))?;
        if let Some(receipt) = receipt {
            self.push_event(
                events,
                command_id,
                DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::Closed(receipt)),
            )?;
        }
        Ok(())
    }

    fn push_sandbox_state(
        &mut self,
        events: &mut Vec<HostFrame>,
        command_id: CommandId,
        state: SandboxLifecycleState,
    ) -> Result<(), HostTransportError> {
        let session_id = self.machine_ref()?.session_id();
        self.push_event(
            events,
            command_id,
            DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::State { session_id, state }),
        )
    }

    fn push_event(
        &mut self,
        frames: &mut Vec<HostFrame>,
        command_id: CommandId,
        event: DebugEvent,
    ) -> Result<(), HostTransportError> {
        if frames.len() >= MAX_RESPONSE_FRAMES {
            return Err(HostTransportError::backend(
                "fake response frame limit exceeded",
            ));
        }
        let machine = self.machine_ref()?;
        let sequence = EventSequence::new(self.next_event_sequence)
            .map_err(|error| HostTransportError::protocol(error.to_string()))?;
        let envelope = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence,
            session_id: Some(machine.session_id()),
            state: Some(machine.state().state_token()),
            caused_by: Some(command_id),
            event,
        };
        let frame = encode_event_frame(
            FrameSequence::new(self.next_frame_sequence)
                .map_err(|error| HostTransportError::protocol(error.to_string()))?,
            &envelope,
        )
        .map_err(|error| HostTransportError::protocol(error.to_string()))?;
        self.next_event_sequence = self
            .next_event_sequence
            .checked_add(1)
            .ok_or_else(|| HostTransportError::protocol("event sequence overflow"))?;
        self.next_frame_sequence = self
            .next_frame_sequence
            .checked_add(1)
            .ok_or_else(|| HostTransportError::protocol("frame sequence overflow"))?;
        frames.push(frame);
        Ok(())
    }

    fn machine_ref(&self) -> Result<&SessionMachine, HostTransportError> {
        self.machine
            .as_ref()
            .ok_or_else(|| HostTransportError::protocol("no active session reducer"))
    }

    fn machine_mut(&mut self) -> Result<&mut SessionMachine, HostTransportError> {
        self.machine
            .as_mut()
            .ok_or_else(|| HostTransportError::protocol("no active session reducer"))
    }
}

impl HostFrameExchange for InMemoryDebugHost {
    fn exchange(&mut self, request: HostFrame) -> Result<Vec<HostFrame>, HostTransportError> {
        self.exchange_inner(request)
    }

    fn disconnect(&mut self) -> Result<(), HostTransportError> {
        self.disconnected = true;
        Ok(())
    }
}

fn machine_error(error: SessionMachineError) -> HostTransportError {
    HostTransportError::protocol(error.to_string())
}

fn bounded_rejection_message(error: &SessionMachineError) -> String {
    let message = error.to_string();
    if message.is_empty()
        || message.len() > crate::protocol::MAX_REASON_BYTES
        || message.chars().any(char::is_control)
    {
        "command rejected by session reducer".to_owned()
    } else {
        message
    }
}

fn exact_attestation(expected: &ExpectedSandboxAttestation) -> SandboxAttestation {
    SandboxAttestation {
        binary_id: expected.binary_id.clone(),
        session_id: expected.session_id,
        policy_digest: expected.policy_digest.clone(),
        provider: expected.provider.clone(),
        boundary: expected.boundary,
        guarantees: expected.guarantees.clone(),
        job_assigned_at_creation: expected.job_assigned_at_creation,
        helper_build: expected.helper_build.clone(),
        vm_identity: expected.vm_identity.clone(),
    }
}

fn complete_cleanup_receipt(expected: &ExpectedSandboxAttestation) -> SandboxCleanupReceipt {
    let (appcontainer_profile_deleted, differencing_disk_discarded, control_channel_closed) =
        match expected.boundary {
            IsolationBoundary::UserMode => (Some(true), None, None),
            IsolationBoundary::Hypervisor => (None, Some(true), Some(true)),
        };
    SandboxCleanupReceipt {
        receipt_id: CleanupReceiptId::new(format!("fake-cleanup-{}", expected.session_id.get()))
            .expect("bounded fake cleanup receipt id"),
        session_id: expected.session_id,
        provider: expected.provider.clone(),
        policy_digest: expected.policy_digest.clone(),
        outcome: CleanupOutcome::Complete,
        process_tree_terminated_and_reaped: true,
        handles_closed: true,
        file_system_rolled_back: true,
        registry_rolled_back: true,
        network_torn_down: true,
        owned_paths_deleted: true,
        appcontainer_profile_deleted,
        differencing_disk_discarded,
        control_channel_closed,
        terminated_processes: 1,
        residuals: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use resymbol_core::BinaryId;

    use super::*;
    use crate::protocol::{LaunchEnvironment, LaunchTarget, OfflineTarget};
    use crate::sandbox::{
        ChildProcessProfile, DynamicCodeProfile, ProcessMitigationProfile, RiskAcknowledgementId,
        SandboxGuarantee, SandboxNetworkMode, SandboxPolicy, SandboxProviderSelection,
        SandboxResourceLimits, Win32kProfile,
    };

    fn session_id() -> SessionId {
        SessionId::new(17).expect("session id")
    }

    fn helper_build() -> HelperBuildId {
        HelperBuildId::new("fake-helper-1.0.0+test").expect("helper build")
    }

    fn host() -> InMemoryDebugHost {
        InMemoryDebugHost::new("host/build-4", "controller/build-7", helper_build()).unwrap()
    }

    fn client(host: InMemoryDebugHost) -> DebugHostClient<InMemoryDebugHost> {
        DebugHostClient::connect(host, [0x6d; 16], "controller/build-7", "host/build-4").unwrap()
    }

    #[derive(Debug, Clone, Copy)]
    enum ResponseMutation {
        FrameGap,
        WrongCorrelation,
        MissingResult,
        DuplicateResult,
    }

    struct MutatingHost {
        inner: InMemoryDebugHost,
        mutation: ResponseMutation,
        exchanges: usize,
    }

    impl MutatingHost {
        fn new(mutation: ResponseMutation) -> Self {
            Self {
                inner: host(),
                mutation,
                exchanges: 0,
            }
        }

        fn mutate(&self, mut responses: Vec<HostFrame>) -> Vec<HostFrame> {
            match self.mutation {
                ResponseMutation::FrameGap => {
                    let (mut header, raw) = responses[0].clone().into_parts();
                    header.sequence = FrameSequence::new(header.sequence.get() + 1).unwrap();
                    responses[0] = HostFrame::new(header, raw).unwrap();
                }
                ResponseMutation::WrongCorrelation => {
                    for frame in &mut responses {
                        let mut event = decode_event_frame(frame).unwrap();
                        let DebugEvent::CommandResult {
                            command_id,
                            outcome: _,
                        } = &mut event.event
                        else {
                            continue;
                        };
                        let wrong = CommandId::new(command_id.get() + 100).unwrap();
                        *command_id = wrong;
                        event.caused_by = Some(wrong);
                        *frame = encode_event_frame(frame.header().sequence, &event).unwrap();
                        break;
                    }
                }
                ResponseMutation::MissingResult => responses.retain(|frame| {
                    !matches!(
                        decode_event_frame(frame).unwrap().event,
                        DebugEvent::CommandResult { .. }
                    )
                }),
                ResponseMutation::DuplicateResult => {
                    let result = responses
                        .iter()
                        .rev()
                        .find(|frame| {
                            matches!(
                                decode_event_frame(frame).unwrap().event,
                                DebugEvent::CommandResult { .. }
                            )
                        })
                        .cloned()
                        .unwrap();
                    let mut event = decode_event_frame(&result).unwrap();
                    event.sequence = EventSequence::new(event.sequence.get() + 1).unwrap();
                    responses.push(
                        encode_event_frame(
                            FrameSequence::new(result.header().sequence.get() + 1).unwrap(),
                            &event,
                        )
                        .unwrap(),
                    );
                }
            }
            responses
        }
    }

    impl HostFrameExchange for MutatingHost {
        fn exchange(&mut self, request: HostFrame) -> Result<Vec<HostFrame>, HostTransportError> {
            let responses = self.inner.exchange(request)?;
            let handshake = self.exchanges == 0;
            self.exchanges += 1;
            if handshake {
                Ok(responses)
            } else {
                Ok(self.mutate(responses))
            }
        }

        fn disconnect(&mut self) -> Result<(), HostTransportError> {
            self.inner.disconnect()
        }
    }

    fn mutating_client(mutation: ResponseMutation) -> DebugHostClient<MutatingHost> {
        DebugHostClient::connect(
            MutatingHost::new(mutation),
            [0x6d; 16],
            "controller/build-7",
            "host/build-4",
        )
        .unwrap()
    }

    fn sandbox_policy() -> SandboxPolicy {
        let session_id = session_id();
        let required_guarantees: BTreeSet<_> = [
            SandboxGuarantee::FileSystemRedirection,
            SandboxGuarantee::RegistryRedirection,
            SandboxGuarantee::RollbackOnClose,
            SandboxGuarantee::NetworkDisabled,
            SandboxGuarantee::ResourceLimits,
            SandboxGuarantee::ChildProcessControl,
            SandboxGuarantee::ProcessMitigations,
            SandboxGuarantee::JobAssignmentAtCreation,
        ]
        .into_iter()
        .collect();
        SandboxPolicy {
            session_id,
            risk_acknowledgement: RiskAcknowledgementId::new(session_id, "fake-sandbox-ack")
                .expect("acknowledgement"),
            provider: SandboxProviderSelection::LocalAppContainer,
            required_boundary: IsolationBoundary::UserMode,
            required_guarantees,
            network: SandboxNetworkMode::Disabled,
            resources: SandboxResourceLimits {
                memory_bytes: 256 * 1024 * 1024,
                disk_bytes: 1024 * 1024 * 1024,
                active_process_limit: 4,
                cpu_rate_basis_points: 5_000,
                wall_clock_millis: 60_000,
            },
            process_mitigations: ProcessMitigationProfile::StrictV1,
            child_processes: ChildProcessProfile::Deny,
            dynamic_code: DynamicCodeProfile::Prohibit,
            win32k: Win32kProfile::Disable,
            rollback_on_close: true,
            vm_identity: None,
        }
    }

    #[test]
    fn fake_host_drives_exact_attestation_and_complete_cleanup() {
        let binary_id = BinaryId::digest(b"exact fake sample");
        let policy = sandbox_policy();
        let expected_policy_digest = policy.digest(&binary_id).expect("canonical policy digest");
        let expected_helper_build = helper_build();
        let mut client = client(host());
        assert_eq!(client.negotiated_version(), WireProtocolVersion::CURRENT);
        client.begin_session(session_id()).unwrap();
        let opened = client
            .submit(DebugCommand::Open(DebugTargetRequest::Launch(
                LaunchTarget {
                    binary_id: binary_id.clone(),
                    executable: PathBuf::from("sample.exe"),
                    arguments: Vec::new(),
                    working_directory: None,
                    environment: LaunchEnvironment::Sandboxed { policy },
                    stop_before_entry: true,
                },
            )))
            .unwrap();
        assert_eq!(opened.outcome, CommandOutcome::Succeeded);
        let attestation = opened.events.iter().find_map(|event| match &event.event {
            DebugEvent::SandboxAttested(attestation) => Some(attestation),
            _ => None,
        });
        assert_eq!(attestation.map(|value| &value.binary_id), Some(&binary_id));
        assert_eq!(
            attestation.map(|value| &value.policy_digest),
            Some(&expected_policy_digest)
        );
        assert_eq!(
            attestation.map(|value| &value.helper_build),
            Some(&expected_helper_build)
        );
        assert_eq!(
            attestation.map(|value| value.session_id),
            Some(session_id())
        );
        assert_eq!(
            client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Stopped)
        );

        let state = client.session_state().unwrap().state_token();
        let closed = client.submit(DebugCommand::Close { state }).unwrap();
        assert_eq!(closed.outcome, CommandOutcome::Succeeded);
        let cleanup = closed.events.iter().find_map(|event| match &event.event {
            DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::Closed(receipt)) => Some(receipt),
            _ => None,
        });
        assert_eq!(
            cleanup.map(|receipt| receipt.outcome),
            Some(CleanupOutcome::Complete)
        );
        assert_eq!(
            cleanup.map(|receipt| &receipt.policy_digest),
            Some(&expected_policy_digest)
        );
        assert_eq!(
            client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Closed)
        );
        client.release_closed_session().unwrap();
        client.disconnect().unwrap();
    }

    #[test]
    fn client_rejects_stale_tokens_before_transport_and_fake_rejects_replay() {
        let mut client = client(host());
        client.begin_session(session_id()).unwrap();
        let initial = client.session_state().unwrap().state_token();
        client
            .submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe"),
                },
            )))
            .unwrap();
        assert!(matches!(
            client.submit(DebugCommand::Close { state: initial }),
            Err(DebugHostClientError::Protocol(
                ProtocolValidationError::StaleStateToken
            ))
        ));

        let stale_id = CommandId::new(2).unwrap();
        let stale = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: stale_id,
            session_id: Some(session_id()),
            expected_state: Some(initial),
            command: DebugCommand::Close { state: initial },
        };
        let frame = encode_command_frame(FrameSequence::new(3).unwrap(), &stale).unwrap();
        let rejected = client.transport.exchange(frame.clone()).unwrap();
        assert_eq!(rejected.len(), 1);
        assert!(matches!(
            decode_event_frame(&rejected[0]).unwrap().event,
            DebugEvent::CommandResult {
                command_id,
                outcome: CommandOutcome::Rejected { .. },
            } if command_id == stale_id
        ));
        assert!(rejected.iter().all(|frame| !matches!(
            decode_event_frame(frame).unwrap().event,
            DebugEvent::StateChanged(_)
        )));

        assert!(matches!(
            client.transport.exchange(frame),
            Err(HostTransportError::Protocol { .. })
        ));
    }

    #[test]
    fn disconnect_and_backend_failures_are_terminal_and_explicit() {
        let disconnecting = host().with_disconnect_after(1);
        let mut disconnected = client(disconnecting);
        disconnected.begin_session(session_id()).unwrap();
        assert!(matches!(
            disconnected.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe")
                }
            ))),
            Err(DebugHostClientError::Transport(
                HostTransportError::Disconnected
            ))
        ));
        assert_eq!(
            disconnected.connection_state(),
            ClientConnectionState::Disconnected
        );

        let failing = host().with_backend_error_after(1);
        let mut failed = client(failing);
        failed.begin_session(session_id()).unwrap();
        assert!(matches!(
            failed.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe")
                }
            ))),
            Err(DebugHostClientError::Transport(
                HostTransportError::Backend { .. }
            ))
        ));
        assert_eq!(failed.connection_state(), ClientConnectionState::Failed);
    }

    #[test]
    fn disconnect_during_an_active_sandbox_never_claims_cleanup() {
        let binary_id = BinaryId::digest(b"disconnect sample");
        let mut client = client(host().with_disconnect_after(2));
        client.begin_session(session_id()).unwrap();
        client
            .submit(DebugCommand::Open(DebugTargetRequest::Launch(
                LaunchTarget {
                    binary_id,
                    executable: PathBuf::from("sample.exe"),
                    arguments: Vec::new(),
                    working_directory: None,
                    environment: LaunchEnvironment::Sandboxed {
                        policy: sandbox_policy(),
                    },
                    stop_before_entry: true,
                },
            )))
            .unwrap();
        let stopped = client.session_state().unwrap().clone();
        let state = stopped.state_token();
        assert!(matches!(
            client.submit(DebugCommand::Close { state }),
            Err(DebugHostClientError::Transport(
                HostTransportError::Disconnected
            ))
        ));
        assert_eq!(
            client.connection_state(),
            ClientConnectionState::Disconnected
        );
        assert_eq!(client.session_state(), Some(&stopped));
        assert_eq!(
            client.release_closed_session(),
            Err(DebugHostClientError::Disconnected)
        );
    }

    #[test]
    fn handshake_pins_the_expected_host_build() {
        let result =
            DebugHostClient::connect(host(), [0x7f; 16], "controller/build-7", "host/wrong-build");
        assert!(matches!(
            result,
            Err(DebugHostClientError::Handshake(
                HandshakeError::PeerBuildIdentityMismatch
            ))
        ));
    }

    #[test]
    fn client_rejects_frame_gaps_and_wrong_command_correlation() {
        let mut gap = mutating_client(ResponseMutation::FrameGap);
        gap.begin_session(session_id()).unwrap();
        assert_eq!(
            gap.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe"),
                },
            ))),
            Err(DebugHostClientError::UnexpectedFrameSequence {
                expected: 2,
                actual: 3,
            })
        );
        assert_eq!(gap.connection_state(), ClientConnectionState::Failed);

        let mut wrong = mutating_client(ResponseMutation::WrongCorrelation);
        wrong.begin_session(session_id()).unwrap();
        assert!(matches!(
            wrong.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe")
                }
            ))),
            Err(DebugHostClientError::UnexpectedCommandCorrelation {
                expected,
                actual: Some(actual),
            }) if expected.get() == 1 && actual.get() == 101
        ));
        assert_eq!(wrong.connection_state(), ClientConnectionState::Failed);
    }

    #[test]
    fn client_rejects_missing_and_duplicate_command_results() {
        let mut missing = mutating_client(ResponseMutation::MissingResult);
        missing.begin_session(session_id()).unwrap();
        assert!(matches!(
            missing.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe")
                }
            ))),
            Err(DebugHostClientError::MissingCommandResult { command_id })
                if command_id.get() == 1
        ));

        let mut duplicate = mutating_client(ResponseMutation::DuplicateResult);
        duplicate.begin_session(session_id()).unwrap();
        assert!(matches!(
            duplicate.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe")
                }
            ))),
            Err(DebugHostClientError::DuplicateCommandResult { command_id })
                if command_id.get() == 1
        ));
    }
}
