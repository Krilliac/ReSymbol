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
use crate::host_response::{
    DEFAULT_HOST_RESPONSE_LIMITS, HostResponseBatch, HostResponseBudgetError, HostResponseLimits,
    MAX_RESPONSE_FRAMES,
};
use crate::host_wire::{
    EndpointRole, FrameSequence, HandshakeError, HandshakeMachine, HandshakeState,
    ProtocolVersion as WireProtocolVersion, WireError,
};
use crate::protocol::{
    CapabilityAvailability, CapabilityReport, CapabilityStatus, CapabilityUnavailableCode,
    CommandEnvelope, CommandId, CommandOutcome, DebugCapability, DebugCommand, DebugEvent,
    DebugTargetRequest, EventEnvelope, EventSequence, EventSequenceCursor, ProtocolValidationError,
    ProtocolVersion, SessionId, SessionState, SessionStateKind, StateGeneration, StateToken,
    StopReason, ThreadId,
};
use crate::sandbox::{
    CleanupOutcome, CleanupReceiptId, DiagnosticText, ExpectedSandboxAttestation, HelperBuildId,
    IsolationBoundary, SandboxAttestation, SandboxCleanupReceipt, SandboxLifecycleEvent,
    SandboxLifecycleState,
};
use crate::{SessionMachine, SessionMachineError};

pub const MAX_PENDING_COMMANDS: usize = 1;

/// A synchronous frame exchange owned by one connection worker.
///
/// Implementations may own a helper process or an I/O thread, but must not
/// expose either handle. `exchange` runs on the connection owner thread and
/// returns only complete, bounded frames. The transport must apply `limits` to
/// the peer-declared frame count before batch allocation and to every decoded
/// header before allocating its raw payload. It must fail instead of silently
/// reconnecting or changing the requested provider boundary.
pub trait HostFrameExchange {
    fn exchange(
        &mut self,
        request: HostFrame,
        limits: HostResponseLimits,
    ) -> Result<HostResponseBatch, HostTransportError>;

    fn disconnect(&mut self) -> Result<(), HostTransportError>;
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
    session: Option<ClientSession>,
    next_command_id: u64,
    next_outbound_frame_sequence: u64,
    next_inbound_frame_sequence: u64,
    event_cursor: EventSequenceCursor,
    _owner_thread: PhantomData<Rc<()>>,
}

#[derive(Debug, Clone)]
struct ClientSession {
    session_id: SessionId,
    state: SessionState,
    last_stop_id: u64,
    last_run_id: u64,
}

impl<T: HostFrameExchange> DebugHostClient<T> {
    /// Establishes the direction- and identity-checked controller/host handshake.
    /// The injected transport remains responsible for cryptographic peer
    /// authentication; the wire handshake itself is not an authenticator.
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
        let responses = match transport.exchange(
            HostFrame::new(hello, Vec::new())?,
            DEFAULT_HOST_RESPONSE_LIMITS,
        ) {
            Ok(responses) => responses,
            Err(error) => {
                let _ = transport.disconnect();
                return Err(error.into());
            }
        };
        if let Err(error) = responses.validate(DEFAULT_HOST_RESPONSE_LIMITS) {
            let _ = transport.disconnect();
            return Err(error.into());
        }
        if responses.len() != 1 {
            let _ = transport.disconnect();
            return Err(DebugHostClientError::UnexpectedHandshakeResponseCount {
                actual: responses.len(),
            });
        }
        let acknowledgement = &responses.as_slice()[0];
        if !acknowledgement.raw().is_empty() {
            let _ = transport.disconnect();
            return Err(DebugHostClientError::HandshakeCarriedRawPayload);
        }
        if let Err(error) = handshake.accept(acknowledgement.header()) {
            let _ = transport.disconnect();
            return Err(error.into());
        }
        if handshake.state() != HandshakeState::Established {
            let _ = transport.disconnect();
            return Err(DebugHostClientError::HandshakeIncomplete);
        }
        let Some(negotiated_version) = handshake.negotiated_version() else {
            let _ = transport.disconnect();
            return Err(DebugHostClientError::HandshakeIncomplete);
        };
        Ok(Self {
            transport,
            connection_state: ClientConnectionState::Connected,
            negotiated_version,
            session: None,
            next_command_id: 1,
            next_outbound_frame_sequence: 2,
            next_inbound_frame_sequence: 2,
            event_cursor: EventSequenceCursor::default(),
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
        self.session.as_ref().map(|session| session.session_id)
    }

    #[must_use]
    pub fn session_state(&self) -> Option<&SessionState> {
        self.session.as_ref().map(|session| &session.state)
    }

    /// Queries connection-level capabilities without opening a target session.
    /// The in-memory host returns every platform capability as unavailable;
    /// real transports must report their provider's exact bounded status set.
    ///
    /// `[connection owner thread; potentially blocking]`
    pub fn probe_capabilities(&mut self) -> Result<CapabilityReport, DebugHostClientError> {
        self.require_connected()?;
        if self.session.is_some() {
            return Err(DebugHostClientError::CapabilityProbeRequiresNoSession);
        }
        let command_id =
            CommandId::new(self.next_command_id).map_err(DebugHostClientError::Protocol)?;
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id,
            session_id: None,
            expected_state: None,
            command: DebugCommand::ProbeCapabilities,
        };
        envelope.validate()?;
        let frame_sequence = FrameSequence::new(self.next_outbound_frame_sequence)?;
        let request = encode_command_frame(frame_sequence, &envelope)?;
        self.require_negotiated_frame_version(&request)?;
        self.next_outbound_frame_sequence = self
            .next_outbound_frame_sequence
            .checked_add(1)
            .ok_or(DebugHostClientError::FrameSequenceOverflow)?;
        self.next_command_id = self
            .next_command_id
            .checked_add(1)
            .ok_or(DebugHostClientError::CommandIdOverflow)?;
        let responses = match self
            .transport
            .exchange(request, DEFAULT_HOST_RESPONSE_LIMITS)
        {
            Ok(responses) => responses,
            Err(error) => {
                self.connection_state = if error.is_disconnected() {
                    ClientConnectionState::Disconnected
                } else {
                    ClientConnectionState::Failed
                };
                let _ = self.transport.disconnect();
                return Err(error.into());
            }
        };
        let result = self.accept_capability_batch(command_id, responses);
        if result.is_err() {
            self.connection_state = ClientConnectionState::Failed;
            let _ = self.transport.disconnect();
        }
        result
    }

    /// Claims one logical session on this connection. The host independently
    /// creates its reducer when it receives the first `Open` command, so merely
    /// calling this method never claims a target has been opened.
    ///
    /// `[connection owner thread]`
    pub fn begin_session(&mut self, session_id: SessionId) -> Result<(), DebugHostClientError> {
        self.require_connected()?;
        if self.session.is_some() {
            return Err(DebugHostClientError::SessionAlreadyOwned);
        }
        self.session = Some(ClientSession {
            session_id,
            state: SessionState::Idle {
                token: StateToken {
                    session_id,
                    generation: StateGeneration::new(1)
                        .expect("initial state generation is nonzero"),
                },
            },
            last_stop_id: 0,
            last_run_id: 0,
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
        let state = session.state.state_token();
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id,
            session_id: Some(session.session_id),
            expected_state: Some(state),
            command,
        };
        envelope.validate_against(&session.state)?;

        let frame_sequence = FrameSequence::new(self.next_outbound_frame_sequence)?;
        let request = encode_command_frame(frame_sequence, &envelope)?;
        self.require_negotiated_frame_version(&request)?;
        self.next_outbound_frame_sequence = self
            .next_outbound_frame_sequence
            .checked_add(1)
            .ok_or(DebugHostClientError::FrameSequenceOverflow)?;
        self.next_command_id = self
            .next_command_id
            .checked_add(1)
            .ok_or(DebugHostClientError::CommandIdOverflow)?;
        let responses = match self
            .transport
            .exchange(request, DEFAULT_HOST_RESPONSE_LIMITS)
        {
            Ok(responses) => responses,
            Err(error) => {
                self.connection_state = if error.is_disconnected() {
                    ClientConnectionState::Disconnected
                } else {
                    ClientConnectionState::Failed
                };
                let _ = self.transport.disconnect();
                return Err(error.into());
            }
        };
        self.accept_response_batch(command_id, responses)
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
        if session.state.kind() != SessionStateKind::Closed {
            return Err(DebugHostClientError::SessionNotClosed {
                state: session.state.kind(),
            });
        }
        self.session = None;
        self.connection_state = ClientConnectionState::Connected;
        Ok(())
    }

    /// Drops client-side ownership after an unrecoverable connection failure.
    ///
    /// This is an evidence-preserving abandon operation, not cleanup: it
    /// returns the last observed state and leaves the connection terminal. It
    /// never converts an unclean sandbox or target session into `Closed`.
    pub fn abandon_failed_session(&mut self) -> Result<SessionState, DebugHostClientError> {
        if !matches!(
            self.connection_state,
            ClientConnectionState::Failed | ClientConnectionState::Disconnected
        ) {
            return Err(DebugHostClientError::SessionAbandonRequiresFailedConnection);
        }
        self.session
            .take()
            .map(|session| session.state)
            .ok_or(DebugHostClientError::SessionNotOwned)
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
        if self.connection_state == ClientConnectionState::Failed {
            return Err(DebugHostClientError::ConnectionFailed);
        }
        self.transport.disconnect()?;
        self.connection_state = ClientConnectionState::Disconnected;
        Ok(())
    }

    fn accept_response_batch(
        &mut self,
        command_id: CommandId,
        responses: HostResponseBatch,
    ) -> Result<CommandReceipt, DebugHostClientError> {
        let result = self.accept_response_batch_inner(command_id, responses);
        if result.is_err() {
            self.connection_state = ClientConnectionState::Failed;
            let _ = self.transport.disconnect();
        }
        result
    }

    fn accept_capability_batch(
        &mut self,
        command_id: CommandId,
        responses: HostResponseBatch,
    ) -> Result<CapabilityReport, DebugHostClientError> {
        responses.validate(DEFAULT_HOST_RESPONSE_LIMITS)?;
        if responses.is_empty() {
            return Err(DebugHostClientError::MissingCommandResult { command_id });
        }
        if responses.len() > MAX_RESPONSE_FRAMES {
            return Err(DebugHostClientError::TooManyResponseFrames {
                actual: responses.len(),
                maximum: MAX_RESPONSE_FRAMES,
            });
        }
        let mut report = None;
        let mut outcome = None;
        for frame in responses.into_frames() {
            self.require_negotiated_frame_version(&frame)?;
            if frame.header().sequence.get() != self.next_inbound_frame_sequence {
                return Err(DebugHostClientError::UnexpectedFrameSequence {
                    expected: self.next_inbound_frame_sequence,
                    actual: frame.header().sequence.get(),
                });
            }
            self.next_inbound_frame_sequence = self
                .next_inbound_frame_sequence
                .checked_add(1)
                .ok_or(DebugHostClientError::FrameSequenceOverflow)?;
            let event = decode_event_frame(&frame)?;
            self.event_cursor.observe(event.sequence)?;
            if event.caused_by != Some(command_id) {
                return Err(DebugHostClientError::UnexpectedCommandCorrelation {
                    expected: command_id,
                    actual: event.caused_by,
                });
            }
            if event.session_id.is_some() || event.state.is_some() {
                return Err(DebugHostClientError::UnexpectedGlobalSessionContext);
            }
            match event.event {
                DebugEvent::Capabilities(value) => {
                    if report.replace(value).is_some() {
                        return Err(DebugHostClientError::DuplicateCapabilityReport);
                    }
                }
                DebugEvent::CommandResult {
                    command_id: result_id,
                    outcome: result,
                } => {
                    if result_id != command_id {
                        return Err(DebugHostClientError::UnexpectedCommandCorrelation {
                            expected: command_id,
                            actual: Some(result_id),
                        });
                    }
                    if outcome.replace(result).is_some() {
                        return Err(DebugHostClientError::DuplicateCommandResult { command_id });
                    }
                }
                DebugEvent::Warning { .. } => {}
                _ => return Err(DebugHostClientError::UnexpectedGlobalEvent),
            }
        }
        let outcome = outcome.ok_or(DebugHostClientError::MissingCommandResult { command_id })?;
        if let CommandOutcome::Rejected { code, message } = outcome {
            return Err(DebugHostClientError::CapabilityProbeRejected { code, message });
        }
        report.ok_or(DebugHostClientError::MissingCapabilityReport)
    }

    fn accept_response_batch_inner(
        &mut self,
        command_id: CommandId,
        responses: HostResponseBatch,
    ) -> Result<CommandReceipt, DebugHostClientError> {
        responses.validate(DEFAULT_HOST_RESPONSE_LIMITS)?;
        if responses.is_empty() {
            self.connection_state = ClientConnectionState::Failed;
            return Err(DebugHostClientError::MissingCommandResult { command_id });
        }
        if responses.len() > MAX_RESPONSE_FRAMES {
            self.connection_state = ClientConnectionState::Failed;
            return Err(DebugHostClientError::TooManyResponseFrames {
                actual: responses.len(),
                maximum: MAX_RESPONSE_FRAMES,
            });
        }
        let original_state = self
            .session
            .as_ref()
            .ok_or(DebugHostClientError::SessionNotOwned)?
            .state
            .clone();
        let mut events = Vec::with_capacity(responses.len());
        let mut outcome = None;

        for frame in responses.into_frames() {
            self.require_negotiated_frame_version(&frame)?;
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
                .session_id;
            if event.session_id != Some(session_id) {
                return self.fail(DebugHostClientError::UnexpectedEventSession {
                    expected: session_id,
                    actual: event.session_id,
                });
            }
            if !matches!(&event.event, DebugEvent::StateChanged(_)) {
                let expected = self
                    .session
                    .as_ref()
                    .ok_or(DebugHostClientError::SessionNotOwned)?
                    .state
                    .state_token();
                if event.state != Some(expected) {
                    return self.fail(DebugHostClientError::UnexpectedEventState {
                        expected,
                        actual: event.state,
                    });
                }
            }
            match &event.event {
                DebugEvent::StateChanged(state) => self.accept_state_change(state.clone())?,
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
                _ => {}
            }
            events.push(event);
        }
        let outcome = outcome.ok_or_else(|| {
            self.connection_state = ClientConnectionState::Failed;
            DebugHostClientError::MissingCommandResult { command_id }
        })?;
        if matches!(&outcome, CommandOutcome::Rejected { .. })
            && self.session.as_ref().map(|session| &session.state) != Some(&original_state)
        {
            return self.fail(DebugHostClientError::RejectedCommandChangedState { command_id });
        }
        Ok(CommandReceipt {
            command_id,
            outcome,
            events,
        })
    }

    fn accept_state_change(&mut self, next: SessionState) -> Result<(), DebugHostClientError> {
        let session = self
            .session
            .as_ref()
            .ok_or(DebugHostClientError::SessionNotOwned)?;
        session.state.validate_successor(&next)?;
        let (next_stop_id, next_run_id) = match &next {
            SessionState::Stopped { token, .. } => {
                let expected = session
                    .last_stop_id
                    .checked_add(1)
                    .ok_or(DebugHostClientError::ExecutionTokenOverflow)?;
                if token.stop_id.get() != expected {
                    return Err(DebugHostClientError::UnexpectedStopId {
                        expected,
                        actual: token.stop_id.get(),
                    });
                }
                (Some(expected), None)
            }
            SessionState::Running { token } => {
                let expected = session
                    .last_run_id
                    .checked_add(1)
                    .ok_or(DebugHostClientError::ExecutionTokenOverflow)?;
                if token.run_id.get() != expected {
                    return Err(DebugHostClientError::UnexpectedRunId {
                        expected,
                        actual: token.run_id.get(),
                    });
                }
                (None, Some(expected))
            }
            _ => (None, None),
        };
        let session = self
            .session
            .as_mut()
            .ok_or(DebugHostClientError::SessionNotOwned)?;
        if let Some(stop_id) = next_stop_id {
            session.last_stop_id = stop_id;
        }
        if let Some(run_id) = next_run_id {
            session.last_run_id = run_id;
        }
        session.state = next;
        Ok(())
    }

    fn require_negotiated_frame_version(
        &self,
        frame: &HostFrame,
    ) -> Result<(), DebugHostClientError> {
        if frame.header().version == self.negotiated_version {
            Ok(())
        } else {
            Err(DebugHostClientError::UnexpectedWireProtocolVersion {
                expected_major: self.negotiated_version.major,
                expected_minor: self.negotiated_version.minor,
                actual_major: frame.header().version.major,
                actual_minor: frame.header().version.minor,
            })
        }
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
    #[error(transparent)]
    ResponseBudget(#[from] HostResponseBudgetError),
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
    ResponseBudget(#[from] HostResponseBudgetError),
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
    #[error("session abandonment is allowed only after connection failure")]
    SessionAbandonRequiresFailedConnection,
    #[error("global capability probing is not a session command")]
    GlobalCommandRequiresConnectionApi,
    #[error("capability probing requires a connection with no owned session")]
    CapabilityProbeRequiresNoSession,
    #[error("connection-level capability event unexpectedly carried session state")]
    UnexpectedGlobalSessionContext,
    #[error("connection-level capability response contained a session-only event")]
    UnexpectedGlobalEvent,
    #[error("capability response did not contain a capability report")]
    MissingCapabilityReport,
    #[error("capability response contained more than one capability report")]
    DuplicateCapabilityReport,
    #[error("capability probe was rejected with {code}: {message}")]
    CapabilityProbeRejected { code: String, message: String },
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
    #[error(
        "expected wire protocol {expected_major}.{expected_minor}, received {actual_major}.{actual_minor}"
    )]
    UnexpectedWireProtocolVersion {
        expected_major: u16,
        expected_minor: u16,
        actual_major: u16,
        actual_minor: u16,
    },
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
    #[error("expected event state {expected:?}, received {actual:?}")]
    UnexpectedEventState {
        expected: StateToken,
        actual: Option<StateToken>,
    },
    #[error("expected stop identifier {expected}, received {actual}")]
    UnexpectedStopId { expected: u64, actual: u64 },
    #[error("expected run identifier {expected}, received {actual}")]
    UnexpectedRunId { expected: u64, actual: u64 },
    #[error("execution token identifier space is exhausted")]
    ExecutionTokenOverflow,
    #[error("host returned more than one result for command {command_id:?}")]
    DuplicateCommandResult { command_id: CommandId },
    #[error("rejected command {command_id:?} changed session state")]
    RejectedCommandChangedState { command_id: CommandId },
}

/// A deterministic, non-executing host used for integration and UI tests.
///
/// It owns only pure reducers and bounded frames. It does not inspect files,
/// attach processes, launch targets, or claim platform capabilities.
pub struct InMemoryDebugHost {
    handshake: HandshakeMachine,
    helper_build: HelperBuildId,
    machine: Option<SessionMachine>,
    last_command_id: Option<CommandId>,
    next_command_frame_sequence: u64,
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
            last_command_id: None,
            next_command_frame_sequence: 1,
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
        if request.header().sequence.get() != self.next_command_frame_sequence {
            return Err(HostTransportError::protocol(format!(
                "expected frame sequence {}, received {}",
                self.next_command_frame_sequence,
                request.header().sequence.get()
            )));
        }
        self.next_command_frame_sequence = self
            .next_command_frame_sequence
            .checked_add(1)
            .ok_or_else(|| HostTransportError::protocol("frame sequence overflow"))?;

        let responses = if self.handshake.state() != HandshakeState::Established {
            if !request.raw().is_empty() {
                return Err(HostTransportError::protocol(
                    "handshake request carried raw payload",
                ));
            }
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
            if self.handshake.negotiated_version() != Some(request.header().version) {
                return Err(HostTransportError::protocol(
                    "command frame version differs from negotiated handshake version",
                ));
            }
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
        self.observe_command_id(envelope.command_id)?;
        if matches!(&envelope.command, DebugCommand::ProbeCapabilities) {
            envelope
                .validate()
                .map_err(|error| HostTransportError::protocol(error.to_string()))?;
            return self.handle_capability_probe(envelope.command_id);
        }
        if matches!(
            &envelope.command,
            DebugCommand::ReadMemory { .. }
                | DebugCommand::WriteMemory { .. }
                | DebugCommand::SetBreakpoint { .. }
                | DebugCommand::RemoveBreakpoint { .. }
                | DebugCommand::CaptureSnapshot { .. }
        ) {
            return Err(HostTransportError::protocol(
                "the execution-neutral in-memory host does not implement target data operations",
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

    fn observe_command_id(&mut self, command_id: CommandId) -> Result<(), HostTransportError> {
        if self.last_command_id.is_some_and(|last| command_id <= last) {
            return Err(HostTransportError::protocol(
                "command identifier is not newer than the previous command",
            ));
        }
        self.last_command_id = Some(command_id);
        Ok(())
    }

    fn handle_capability_probe(
        &mut self,
        command_id: CommandId,
    ) -> Result<Vec<HostFrame>, HostTransportError> {
        let unavailable = |capability| CapabilityStatus {
            capability,
            availability: CapabilityAvailability::Unavailable {
                code: CapabilityUnavailableCode::BackendUnavailable,
                reason: "execution-neutral in-memory host has no platform provider".to_owned(),
            },
        };
        let report = CapabilityReport {
            statuses: [
                DebugCapability::OfflineAnalysis,
                DebugCapability::DumpRead,
                DebugCapability::SnapshotRead,
                DebugCapability::ObserveProcess,
                DebugCapability::LiveMemoryRead,
                DebugCapability::LiveMemoryWrite,
                DebugCapability::ExecutionControl,
                DebugCapability::RegisterRead,
                DebugCapability::RegisterWrite,
                DebugCapability::SoftwareBreakpoints,
                DebugCapability::HardwareBreakpoints,
                DebugCapability::SandboxedLaunch,
                DebugCapability::HostLaunch,
                DebugCapability::HostAttach,
            ]
            .into_iter()
            .map(unavailable)
            .collect(),
        };
        let mut events = Vec::with_capacity(2);
        self.push_global_event(&mut events, command_id, DebugEvent::Capabilities(report))?;
        self.push_global_event(
            &mut events,
            command_id,
            DebugEvent::CommandResult {
                command_id,
                outcome: CommandOutcome::Succeeded,
            },
        )?;
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
            DebugCommand::Continue { .. } | DebugCommand::Detach { .. } => {}
            DebugCommand::ReadMemory { .. }
            | DebugCommand::WriteMemory { .. }
            | DebugCommand::SetBreakpoint { .. }
            | DebugCommand::RemoveBreakpoint { .. }
            | DebugCommand::CaptureSnapshot { .. } => {
                unreachable!("unsupported target data operations are rejected before reduction")
            }
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

    fn push_global_event(
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
        let sequence = EventSequence::new(self.next_event_sequence)
            .map_err(|error| HostTransportError::protocol(error.to_string()))?;
        let envelope = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence,
            session_id: None,
            state: None,
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
    fn exchange(
        &mut self,
        request: HostFrame,
        limits: HostResponseLimits,
    ) -> Result<HostResponseBatch, HostTransportError> {
        let frames = self.exchange_inner(request)?;
        match HostResponseBatch::try_from_frames(frames, limits) {
            Ok(batch) => Ok(batch),
            Err(error) => {
                self.disconnected = true;
                Err(error.into())
            }
        }
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
    use crate::host_response::{MAX_RESPONSE_BYTES, MAX_RESPONSE_FRAME_BYTES};
    use crate::host_wire::{ControlBody, FrameHeader, MessageKind};
    use crate::protocol::{
        LaunchEnvironment, LaunchTarget, MAX_MEMORY_READ_BYTES, MemoryAddress, OfflineTarget,
        ReadViewToken,
    };
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
        ImpossibleTransition,
        StaleEventState,
    }

    struct MutatingHost {
        inner: InMemoryDebugHost,
        mutation: ResponseMutation,
        exchanges: usize,
    }

    struct OverBudgetHost {
        inner: InMemoryDebugHost,
        exchanges: usize,
    }

    impl OverBudgetHost {
        fn new() -> Self {
            Self {
                inner: host(),
                exchanges: 0,
            }
        }
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
                ResponseMutation::ImpossibleTransition => {
                    for frame in &mut responses {
                        let mut event = decode_event_frame(frame).unwrap();
                        let DebugEvent::StateChanged(state) = &event.event else {
                            continue;
                        };
                        let token = state.state_token();
                        event.event = DebugEvent::StateChanged(SessionState::Closed { token });
                        event.state = Some(token);
                        *frame = encode_event_frame(frame.header().sequence, &event).unwrap();
                        break;
                    }
                }
                ResponseMutation::StaleEventState => {
                    for frame in &mut responses {
                        let mut event = decode_event_frame(frame).unwrap();
                        if !matches!(event.event, DebugEvent::CommandResult { .. }) {
                            continue;
                        }
                        event.state = Some(StateToken {
                            session_id: session_id(),
                            generation: StateGeneration::new(1).unwrap(),
                        });
                        *frame = encode_event_frame(frame.header().sequence, &event).unwrap();
                        break;
                    }
                }
            }
            responses
        }
    }

    impl HostFrameExchange for MutatingHost {
        fn exchange(
            &mut self,
            request: HostFrame,
            limits: HostResponseLimits,
        ) -> Result<HostResponseBatch, HostTransportError> {
            let responses = self.inner.exchange(request, limits)?;
            let handshake = self.exchanges == 0;
            self.exchanges += 1;
            if handshake {
                Ok(responses)
            } else {
                HostResponseBatch::try_from_frames(self.mutate(responses.into_frames()), limits)
                    .map_err(HostTransportError::from)
            }
        }

        fn disconnect(&mut self) -> Result<(), HostTransportError> {
            self.inner.disconnect()
        }
    }

    impl HostFrameExchange for OverBudgetHost {
        fn exchange(
            &mut self,
            request: HostFrame,
            limits: HostResponseLimits,
        ) -> Result<HostResponseBatch, HostTransportError> {
            let responses = self.inner.exchange(request, limits)?;
            let handshake = self.exchanges == 0;
            self.exchanges += 1;
            if handshake {
                return Ok(responses);
            }

            // Model a hostile transport that ignores the caller's cumulative
            // limit and constructs a batch under a private, larger limit. Each
            // individual frame remains below the caller's per-frame ceiling.
            let mut total_bytes = responses.total_bytes();
            let mut frames = responses.into_frames();
            let mut sequence = frames
                .last()
                .map(|frame| frame.header().sequence.get() + 1)
                .unwrap_or(2);
            while total_bytes <= MAX_RESPONSE_BYTES {
                let raw = vec![0u8; MAX_MEMORY_READ_BYTES as usize];
                let header = FrameHeader::new(
                    FrameSequence::new(sequence).unwrap(),
                    MessageKind::Event,
                    MAX_MEMORY_READ_BYTES,
                    None,
                    ControlBody::Bytes(vec![0]),
                )
                .unwrap();
                let frame = HostFrame::new(header, raw).unwrap();
                total_bytes += frame.header().frame_len().unwrap();
                frames.push(frame);
                sequence += 1;
            }
            let permissive = HostResponseLimits::new(
                MAX_RESPONSE_FRAMES,
                MAX_RESPONSE_FRAME_BYTES,
                MAX_RESPONSE_BYTES * 2,
            )
            .unwrap();
            HostResponseBatch::try_from_frames(frames, permissive).map_err(HostTransportError::from)
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
    fn response_builder_rejects_cumulative_bytes() {
        let frame = HostFrame::new(
            FrameHeader::new(
                FrameSequence::new(2).unwrap(),
                MessageKind::Event,
                32,
                None,
                ControlBody::Bytes(vec![0; 32]),
            )
            .unwrap(),
            vec![0; 32],
        )
        .unwrap();
        let frame_bytes = frame.header().frame_len().unwrap();
        let limits = HostResponseLimits::new(2, frame_bytes, frame_bytes * 2 - 1).unwrap();
        assert_eq!(
            HostResponseBatch::try_from_frames(vec![frame.clone(), frame], limits),
            Err(HostResponseBudgetError::TotalBytesExceeded {
                actual: frame_bytes * 2,
                maximum: frame_bytes * 2 - 1,
            })
        );
    }

    #[test]
    fn in_memory_transport_enforces_supplied_limits_and_disconnects() {
        let mut initiator = HandshakeMachine::initiator(
            EndpointRole::Controller,
            [0x6d; 16],
            "controller/build-7",
            "host/build-4",
        )
        .unwrap();
        let hello = initiator.begin(FrameSequence::new(1).unwrap()).unwrap();
        let request = HostFrame::new(hello, Vec::new()).unwrap();
        let limits = HostResponseLimits::new(1, 1, 1).unwrap();
        let mut transport = host();
        assert!(matches!(
            transport.exchange(request.clone(), limits),
            Err(HostTransportError::ResponseBudget(
                HostResponseBudgetError::FrameTooLarge { .. }
            ))
        ));
        assert_eq!(
            transport.exchange(request, DEFAULT_HOST_RESPONSE_LIMITS),
            Err(HostTransportError::Disconnected)
        );
    }

    #[test]
    fn client_revalidates_cumulative_bytes_and_poisons_connection() {
        let mut client = DebugHostClient::connect(
            OverBudgetHost::new(),
            [0x6d; 16],
            "controller/build-7",
            "host/build-4",
        )
        .unwrap();
        client.begin_session(session_id()).unwrap();
        assert!(matches!(
            client.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe"),
                },
            ))),
            Err(DebugHostClientError::ResponseBudget(
                HostResponseBudgetError::TotalBytesExceeded { .. }
            ))
        ));
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
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
    fn connection_probe_reports_every_fake_capability_as_unavailable() {
        let mut client = client(host());
        let report = client.probe_capabilities().unwrap();
        assert_eq!(report.statuses.len(), 14);
        assert!(report.statuses.iter().all(|status| matches!(
            &status.availability,
            CapabilityAvailability::Unavailable {
                code: CapabilityUnavailableCode::BackendUnavailable,
                ..
            }
        )));

        client.begin_session(session_id()).unwrap();
        let opened = client
            .submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe"),
                },
            )))
            .unwrap();
        assert_eq!(opened.command_id.get(), 2);
    }

    #[test]
    fn fake_host_rejects_unimplemented_data_operations_and_client_can_abandon_failure() {
        let mut client = client(host());
        client.begin_session(session_id()).unwrap();
        client
            .submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe"),
                },
            )))
            .unwrap();
        let state = client.session_state().unwrap().state_token();
        assert!(matches!(
            client.submit(DebugCommand::ReadMemory {
                view: ReadViewToken::Offline { state },
                address: MemoryAddress::new(0),
                size: 16,
            }),
            Err(DebugHostClientError::Transport(
                HostTransportError::Protocol { .. }
            ))
        ));
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
        let abandoned = client.abandon_failed_session().unwrap();
        assert_eq!(abandoned.kind(), SessionStateKind::Offline);
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
        assert_eq!(
            client.disconnect(),
            Err(DebugHostClientError::ConnectionFailed)
        );
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
        let rejected = client
            .transport
            .exchange(frame.clone(), DEFAULT_HOST_RESPONSE_LIMITS)
            .unwrap();
        assert_eq!(rejected.len(), 1);
        assert!(matches!(
            decode_event_frame(&rejected.as_slice()[0]).unwrap().event,
            DebugEvent::CommandResult {
                command_id,
                outcome: CommandOutcome::Rejected { .. },
            } if command_id == stale_id
        ));
        assert!(rejected.as_slice().iter().all(|frame| !matches!(
            decode_event_frame(frame).unwrap().event,
            DebugEvent::StateChanged(_)
        )));

        assert!(matches!(
            client
                .transport
                .exchange(frame, DEFAULT_HOST_RESPONSE_LIMITS),
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

    #[test]
    fn client_rejects_impossible_transitions_and_stale_event_state() {
        let mut impossible = mutating_client(ResponseMutation::ImpossibleTransition);
        impossible.begin_session(session_id()).unwrap();
        assert!(matches!(
            impossible.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe")
                }
            ))),
            Err(DebugHostClientError::Protocol(
                ProtocolValidationError::InvalidSessionStateTransition {
                    from: SessionStateKind::Idle,
                    to: SessionStateKind::Closed,
                }
            ))
        ));
        assert_eq!(impossible.connection_state(), ClientConnectionState::Failed);

        let mut stale = mutating_client(ResponseMutation::StaleEventState);
        stale.begin_session(session_id()).unwrap();
        assert!(matches!(
            stale.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe")
                }
            ))),
            Err(DebugHostClientError::UnexpectedEventState { .. })
        ));
        assert_eq!(stale.connection_state(), ClientConnectionState::Failed);
    }
}
