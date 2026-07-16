//! Single-owner debugger-host client seam and synthetic test transport.
//!
//! This module performs no process operations. The feature-gated synthetic host
//! exercises protocol mechanics but never claims target or sandbox work occurred.

use std::{marker::PhantomData, rc::Rc};

use thiserror::Error;

use crate::authorization::{HostRiskLease, SandboxOwnershipLease};
use crate::host_codec::{
    HostCodecError, HostFrame, decode_command_frame, decode_event_frame, encode_command_frame,
    encode_event_frame,
};
use crate::host_response::{
    DEFAULT_HOST_RESPONSE_LIMITS, HostResponseBatch, HostResponseBudgetError, HostResponseLimits,
    MAX_RESPONSE_FRAMES,
};
use crate::host_wire::{
    BuildClaimHandshake, EndpointRole, FrameSequence, HandshakeError, HandshakeState,
    ProtocolVersion as WireProtocolVersion, WireError,
};
use crate::identity::ProvisioningEpoch;
use crate::protocol::{
    BreakpointChange, CapabilityReport, CommandEnvelope, CommandId, CommandOutcome, DebugCommand,
    DebugEvent, DebugTargetRequest, EventEnvelope, EventSequenceCursor, ProtocolValidationError,
    ProtocolVersion, SessionId, SessionState, SessionStateKind, StateToken,
};
use crate::sandbox::{
    AttestationMismatch, CleanupReceiptError, DiagnosticText, HelperBuildId, SandboxAttestation,
    SandboxCleanupReceipt, SandboxLifecycleEvent, SandboxLifecycleState,
};
use crate::session_machine::RemoteCommandCheckpoint;
use crate::{SessionMachine, SessionMachineError};

#[cfg(any(test, feature = "test-support"))]
use crate::protocol::{
    CapabilityAvailability, CapabilityStatus, CapabilityUnavailableCode, DebugCapability,
    EventSequence,
};
pub const MAX_PENDING_COMMANDS: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlShutdownReason {
    Graceful,
    ExplicitAbandon,
    ClientDropped,
    BuildClaimFailed,
    ProtocolFailure,
    TransportFailure,
}

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

    /// Releases host-side bookkeeping only after the client independently
    /// verified a terminal session and, when required, exact cleanup evidence.
    fn release_session(&mut self, session_id: SessionId) -> Result<(), HostTransportError>;

    /// Best-effort control-channel shutdown. This is never cleanup evidence.
    fn shutdown_control(&mut self, reason: ControlShutdownReason)
    -> Result<(), HostTransportError>;
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

#[derive(Debug, PartialEq, Eq)]
struct ClientSession {
    reducer: SessionMachine,
    verified_state: SessionState,
    sandbox_cleanup_verified: bool,
}

#[derive(Debug, Default)]
struct ResponseEvidence {
    state_changed: bool,
    command_state_observed: bool,
    attestation_accepted: bool,
    cleanup_receipt: Option<SandboxCleanupReceipt>,
    memory_read: bool,
    memory_written: bool,
    breakpoint_changed: bool,
    sandbox_event: bool,
}

impl ResponseEvidence {
    fn has_effect(&self) -> bool {
        self.state_changed
            || self.attestation_accepted
            || self.cleanup_receipt.is_some()
            || self.memory_read
            || self.memory_written
            || self.breakpoint_changed
            || self.sandbox_event
    }
}

impl<T: HostFrameExchange> DebugHostClient<T> {
    /// Correlates a caller nonce with expected, plaintext build claims.
    ///
    /// This rejects accidental peer/version mismatches; it does not authenticate
    /// either endpoint. The transport must authenticate the helper separately.
    ///
    /// `[connection owner thread; potentially blocking]`
    pub fn connect(
        mut transport: T,
        nonce: [u8; 16],
        controller_build: impl Into<String>,
        expected_host_build: impl Into<String>,
    ) -> Result<Self, DebugHostClientError> {
        let mut handshake = BuildClaimHandshake::initiator(
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
                let _ = transport.shutdown_control(ControlShutdownReason::TransportFailure);
                return Err(error.into());
            }
        };
        if let Err(error) = responses.validate(DEFAULT_HOST_RESPONSE_LIMITS) {
            let _ = transport.shutdown_control(ControlShutdownReason::BuildClaimFailed);
            return Err(error.into());
        }
        if responses.len() != 1 {
            let _ = transport.shutdown_control(ControlShutdownReason::BuildClaimFailed);
            return Err(DebugHostClientError::UnexpectedHandshakeResponseCount {
                actual: responses.len(),
            });
        }
        let acknowledgement = &responses.as_slice()[0];
        if !acknowledgement.raw().is_empty() {
            let _ = transport.shutdown_control(ControlShutdownReason::BuildClaimFailed);
            return Err(DebugHostClientError::HandshakeCarriedRawPayload);
        }
        if let Err(error) = handshake.accept(acknowledgement.header()) {
            let _ = transport.shutdown_control(ControlShutdownReason::BuildClaimFailed);
            return Err(error.into());
        }
        if handshake.state() != HandshakeState::Established {
            let _ = transport.shutdown_control(ControlShutdownReason::BuildClaimFailed);
            return Err(DebugHostClientError::HandshakeIncomplete);
        }
        let Some(negotiated_version) = handshake.negotiated_version() else {
            let _ = transport.shutdown_control(ControlShutdownReason::BuildClaimFailed);
            return Err(DebugHostClientError::HandshakeIncomplete);
        };
        let typed_version = match bind_typed_protocol_version(negotiated_version) {
            Ok(version) => version,
            Err(error) => {
                let _ = transport.shutdown_control(ControlShutdownReason::BuildClaimFailed);
                return Err(error);
            }
        };
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
        self.session.as_ref().map(|session| &session.verified_state)
    }

    /// Queries connection-level capabilities without opening a target session.
    /// The synthetic test host returns every platform capability as unavailable;
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
            version: self.typed_version,
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
                self.shutdown_transport(ControlShutdownReason::TransportFailure);
                return Err(error.into());
            }
        };
        let result = self.accept_capability_batch(command_id, responses);
        if result.is_err() {
            self.connection_state = ClientConnectionState::Failed;
            self.shutdown_transport(ControlShutdownReason::ProtocolFailure);
        }
        result
    }

    /// Claims one logical session on this connection. The host independently
    /// creates its reducer when it receives the first `Open` command, so merely
    /// calling this method never claims a target has been opened.
    ///
    /// `[connection owner thread]`
    pub fn begin_session(
        &mut self,
        session_id: SessionId,
        provisioning_epoch: ProvisioningEpoch,
        helper_build: HelperBuildId,
    ) -> Result<(), DebugHostClientError> {
        self.require_connected()?;
        if self.session.is_some() {
            return Err(DebugHostClientError::SessionAlreadyOwned);
        }
        let reducer = SessionMachine::new(session_id, provisioning_epoch, helper_build);
        let verified_state = reducer.state().clone();
        self.session = Some(ClientSession {
            reducer,
            verified_state,
            sandbox_cleanup_verified: false,
        });
        self.connection_state = ClientConnectionState::SessionOpen;
        Ok(())
    }

    /// Registers one controller-side host-risk grant in the validating reducer.
    ///
    /// The trusted transport/session worker must independently register the
    /// same grant with the host; command payloads carry only its one-use ID.
    pub fn register_host_risk_lease(
        &mut self,
        lease: HostRiskLease,
    ) -> Result<(), DebugHostClientError> {
        self.require_session_open()?;
        self.session
            .as_mut()
            .ok_or(DebugHostClientError::SessionNotOwned)?
            .reducer
            .register_host_risk_lease(lease)?;
        Ok(())
    }

    /// Registers one controller-side sandbox-ownership grant in the validating
    /// reducer. The host must receive its own out-of-band copy from the trusted
    /// provider; no serialized command can create this authority.
    pub fn register_sandbox_ownership_lease(
        &mut self,
        lease: SandboxOwnershipLease,
    ) -> Result<(), DebugHostClientError> {
        self.require_session_open()?;
        self.session
            .as_mut()
            .ok_or(DebugHostClientError::SessionNotOwned)?
            .reducer
            .register_sandbox_ownership_lease(lease)?;
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
        let command_id =
            CommandId::new(self.next_command_id).map_err(DebugHostClientError::Protocol)?;
        let session = self
            .session
            .as_ref()
            .ok_or(DebugHostClientError::SessionNotOwned)?;
        let prior_state = session.verified_state.clone();
        let envelope = CommandEnvelope {
            version: self.typed_version,
            command_id,
            session_id: Some(session.reducer.session_id()),
            expected_state: Some(prior_state.state_token()),
            command,
        };
        envelope.validate()?;
        let frame_sequence = FrameSequence::new(self.next_outbound_frame_sequence)?;
        let request = encode_command_frame(frame_sequence, &envelope)?;
        self.require_negotiated_frame_version(&request)?;
        let next_outbound_frame_sequence = self
            .next_outbound_frame_sequence
            .checked_add(1)
            .ok_or(DebugHostClientError::FrameSequenceOverflow)?;
        let next_command_id = self
            .next_command_id
            .checked_add(1)
            .ok_or(DebugHostClientError::CommandIdOverflow)?;

        let (accept_result, command_id_consumed, accepted_state) = {
            let session = self
                .session
                .as_mut()
                .ok_or(DebugHostClientError::SessionNotOwned)?;
            let accept_result = session.reducer.begin_remote_command(&envelope);
            (
                accept_result,
                session.reducer.last_command_id() == Some(command_id),
                session.reducer.state().clone(),
            )
        };
        if command_id_consumed {
            self.next_command_id = next_command_id;
        }
        let checkpoint = accept_result.map_err(|error| match error {
            SessionMachineError::Protocol(error) => DebugHostClientError::Protocol(error),
            error => DebugHostClientError::SessionMachine(error),
        })?;
        let required_command_state = (accepted_state != prior_state).then_some(accepted_state);

        self.next_outbound_frame_sequence = next_outbound_frame_sequence;
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
                self.shutdown_transport(ControlShutdownReason::TransportFailure);
                return Err(error.into());
            }
        };
        self.accept_response_batch(&envelope, checkpoint, required_command_state, responses)
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
        if session.verified_state.kind() != SessionStateKind::Closed {
            return Err(DebugHostClientError::SessionNotClosed {
                state: session.verified_state.kind(),
            });
        }
        if session.reducer.expected_attestation().is_some() && !session.sandbox_cleanup_verified {
            return Err(DebugHostClientError::SandboxCleanupNotVerified);
        }
        self.transport
            .release_session(session.reducer.session_id())?;
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
        self.shutdown_transport(ControlShutdownReason::ExplicitAbandon);
        self.session
            .take()
            .map(|session| session.verified_state)
            .ok_or(DebugHostClientError::SessionNotOwned)
    }

    /// Abandons an active session and closes only the control channel.
    ///
    /// The returned state is the last verified state. No state transition,
    /// sandbox cleanup receipt, or release is inferred from channel shutdown.
    pub fn abandon_session(&mut self) -> Result<SessionState, DebugHostClientError> {
        let state = self
            .session
            .as_ref()
            .map(|session| session.verified_state.clone())
            .ok_or(DebugHostClientError::SessionNotOwned)?;
        self.shutdown_transport(ControlShutdownReason::ExplicitAbandon);
        self.connection_state = ClientConnectionState::Disconnected;
        self.session = None;
        Ok(state)
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
        self.transport
            .shutdown_control(ControlShutdownReason::Graceful)?;
        self.transport_shutdown = true;
        self.connection_state = ClientConnectionState::Disconnected;
        Ok(())
    }

    fn accept_response_batch(
        &mut self,
        envelope: &CommandEnvelope,
        checkpoint: RemoteCommandCheckpoint,
        required_command_state: Option<SessionState>,
        responses: HostResponseBatch,
    ) -> Result<CommandReceipt, DebugHostClientError> {
        let mut session = self
            .session
            .take()
            .ok_or(DebugHostClientError::SessionNotOwned)?;
        let result = self.accept_response_batch_inner(
            &mut session,
            envelope,
            checkpoint,
            required_command_state,
            responses,
        );
        self.session = Some(session);
        if result.is_err() {
            self.connection_state = ClientConnectionState::Failed;
            self.shutdown_transport(ControlShutdownReason::ProtocolFailure);
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
        session: &mut ClientSession,
        envelope: &CommandEnvelope,
        checkpoint: RemoteCommandCheckpoint,
        required_command_state: Option<SessionState>,
        responses: HostResponseBatch,
    ) -> Result<CommandReceipt, DebugHostClientError> {
        responses.validate(DEFAULT_HOST_RESPONSE_LIMITS)?;
        let command_id = envelope.command_id;
        if responses.is_empty() {
            return Err(DebugHostClientError::MissingCommandResult { command_id });
        }
        let mut events = Vec::with_capacity(responses.len());
        let mut outcome = None;
        let mut evidence = ResponseEvidence::default();

        for frame in responses.into_frames() {
            if outcome.is_some() {
                return Err(DebugHostClientError::EventAfterCommandResult { command_id });
            }
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
            if event.version != self.typed_version {
                return Err(DebugHostClientError::UnexpectedTypedProtocolVersion {
                    expected: self.typed_version,
                    actual: event.version,
                });
            }
            self.event_cursor.observe(event.sequence)?;
            if event.caused_by != Some(command_id) {
                return Err(DebugHostClientError::UnexpectedCommandCorrelation {
                    expected: command_id,
                    actual: event.caused_by,
                });
            }
            let session_id = session.reducer.session_id();
            if event.session_id != Some(session_id) {
                return Err(DebugHostClientError::UnexpectedEventSession {
                    expected: session_id,
                    actual: event.session_id,
                });
            }
            if !matches!(&event.event, DebugEvent::StateChanged(_)) {
                let expected =
                    if required_command_state.is_some() && !evidence.command_state_observed {
                        session.verified_state.state_token()
                    } else {
                        session.reducer.state().state_token()
                    };
                if event.state != Some(expected) {
                    return Err(DebugHostClientError::UnexpectedEventState {
                        expected,
                        actual: event.state,
                    });
                }
            }
            match &event.event {
                DebugEvent::StateChanged(state) => {
                    if required_command_state.as_ref() == Some(state)
                        && !evidence.command_state_observed
                    {
                        evidence.command_state_observed = true;
                    } else if let Some(expected) = required_command_state
                        .as_ref()
                        .filter(|_| !evidence.command_state_observed)
                    {
                        return Err(DebugHostClientError::ReducerStateMismatch {
                            expected: expected.clone(),
                            actual: state.clone(),
                        });
                    } else {
                        apply_state_event(
                            &mut session.reducer,
                            state,
                            evidence.cleanup_receipt.as_ref(),
                        )?;
                    }
                    evidence.state_changed = true;
                }
                DebugEvent::SandboxAttested(actual) => {
                    if !is_sandboxed_open(&envelope.command) {
                        return Err(DebugHostClientError::UnexpectedCommandEvidence {
                            command_id,
                            evidence: "sandbox-attestation",
                        });
                    }
                    accept_attestation_event(&mut session.reducer, actual, &mut evidence)?;
                }
                DebugEvent::SandboxLifecycle(lifecycle) => {
                    validate_sandbox_lifecycle(
                        envelope,
                        &mut session.reducer,
                        lifecycle,
                        &mut evidence,
                    )?;
                }
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
                        require_unique_evidence(&mut evidence.memory_read, "memory-read")?;
                    }
                    _ => {
                        return Err(DebugHostClientError::UnexpectedCommandEvidence {
                            command_id,
                            evidence: "memory-read",
                        });
                    }
                },
                DebugEvent::MemoryWritten {
                    stop,
                    address,
                    before,
                    after,
                } => match &envelope.command {
                    DebugCommand::WriteMemory {
                        stop: expected_stop,
                        address: expected_address,
                        expected,
                        replacement,
                    } if stop == expected_stop
                        && address == expected_address
                        && before == expected
                        && after == replacement =>
                    {
                        require_unique_evidence(&mut evidence.memory_written, "memory-written")?;
                    }
                    _ => {
                        return Err(DebugHostClientError::UnexpectedCommandEvidence {
                            command_id,
                            evidence: "memory-written",
                        });
                    }
                },
                DebugEvent::BreakpointChanged {
                    stop,
                    breakpoint,
                    change,
                } => {
                    let exact = match &envelope.command {
                        DebugCommand::SetBreakpoint {
                            stop: expected_stop,
                            breakpoint: expected_breakpoint,
                        } => {
                            stop == expected_stop
                                && breakpoint == expected_breakpoint
                                && *change == BreakpointChange::Set
                        }
                        DebugCommand::RemoveBreakpoint {
                            stop: expected_stop,
                            breakpoint_id,
                        } => {
                            stop == expected_stop
                                && breakpoint.id == *breakpoint_id
                                && *change == BreakpointChange::Removed
                        }
                        _ => false,
                    };
                    if !exact {
                        return Err(DebugHostClientError::UnexpectedCommandEvidence {
                            command_id,
                            evidence: "breakpoint-change",
                        });
                    }
                    require_unique_evidence(&mut evidence.breakpoint_changed, "breakpoint-change")?;
                }
                DebugEvent::CommandResult {
                    command_id: result_id,
                    outcome: result,
                } => {
                    if *result_id != command_id {
                        return Err(DebugHostClientError::UnexpectedCommandCorrelation {
                            expected: command_id,
                            actual: Some(*result_id),
                        });
                    }
                    if outcome.replace(result.clone()).is_some() {
                        return Err(DebugHostClientError::DuplicateCommandResult { command_id });
                    }
                }
                DebugEvent::Warning { .. } => {}
                DebugEvent::Capabilities(_) => {
                    return Err(DebugHostClientError::UnexpectedCommandEvidence {
                        command_id,
                        evidence: "capabilities",
                    });
                }
            }
            events.push(event);
        }
        let outcome = outcome.ok_or(DebugHostClientError::MissingCommandResult { command_id })?;
        match &outcome {
            CommandOutcome::Rejected { .. } => {
                if evidence.has_effect() {
                    return Err(DebugHostClientError::RejectedCommandProducedEvidence {
                        command_id,
                    });
                }
                session.reducer.reject_remote_command(checkpoint)?;
                if session.reducer.state() != &session.verified_state {
                    return Err(DebugHostClientError::ReducerStateMismatch {
                        expected: session.verified_state.clone(),
                        actual: session.reducer.state().clone(),
                    });
                }
            }
            CommandOutcome::Succeeded => {
                if required_command_state.is_some() && !evidence.command_state_observed {
                    return Err(DebugHostClientError::MissingCommandState { command_id });
                }
                validate_success_evidence(envelope, &session.reducer, &evidence)?;
                let cleanup_verified = session.reducer.expected_attestation().is_some()
                    && session.reducer.state().kind() == SessionStateKind::Closed
                    && evidence.cleanup_receipt.is_some();
                session.verified_state = session.reducer.state().clone();
                session.sandbox_cleanup_verified |= cleanup_verified;
            }
        }
        Ok(CommandReceipt {
            command_id,
            outcome,
            events,
        })
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

    fn shutdown_transport(&mut self, reason: ControlShutdownReason) {
        if !self.transport_shutdown {
            let _ = self.transport.shutdown_control(reason);
            self.transport_shutdown = true;
        }
    }
}

impl<T: HostFrameExchange> Drop for DebugHostClient<T> {
    fn drop(&mut self) {
        if !self.transport_shutdown {
            let reason = if self.session.is_some() {
                ControlShutdownReason::ClientDropped
            } else {
                ControlShutdownReason::Graceful
            };
            let _ = self.transport.shutdown_control(reason);
            self.transport_shutdown = true;
        }
    }
}

fn bind_typed_protocol_version(
    wire: WireProtocolVersion,
) -> Result<ProtocolVersion, DebugHostClientError> {
    let typed = ProtocolVersion {
        major: wire.major,
        minor: wire.minor,
    };
    typed.validate()?;
    Ok(typed)
}

fn apply_state_event(
    reducer: &mut SessionMachine,
    next: &SessionState,
    cleanup_receipt: Option<&SandboxCleanupReceipt>,
) -> Result<(), DebugHostClientError> {
    if reducer.state() == next {
        return Err(DebugHostClientError::DuplicateCommandEvidence {
            evidence: "state-change",
        });
    }
    match next {
        SessionState::AwaitingAttestation { .. } => {
            reducer.target_created_suspended()?;
        }
        SessionState::Offline { .. } => {
            reducer.complete_open_offline()?;
        }
        SessionState::Dump { .. } => {
            reducer.complete_open_dump()?;
        }
        SessionState::Observing { process_id, .. } => {
            reducer.complete_open_observing(*process_id)?;
        }
        SessionState::Stopped {
            reason, thread_id, ..
        } => {
            reducer.mark_stopped(reason.clone(), *thread_id)?;
        }
        SessionState::Exited { exit_code, .. } => {
            reducer.mark_exited(*exit_code)?;
        }
        SessionState::Failed { message, .. } => {
            reducer.mark_failed(message.clone())?;
        }
        SessionState::Closed { .. } => {
            reducer.complete_close(cleanup_receipt)?;
        }
        SessionState::Idle { .. }
        | SessionState::Opening { .. }
        | SessionState::AttestationAccepted { .. }
        | SessionState::Snapshot { .. }
        | SessionState::Running { .. }
        | SessionState::Pausing { .. }
        | SessionState::Closing { .. }
        | SessionState::Detached { .. } => {
            return Err(DebugHostClientError::IllegalHostStateTransition {
                from: reducer.state().kind(),
                to: next.kind(),
            });
        }
    }
    if reducer.state() != next {
        return Err(DebugHostClientError::ReducerStateMismatch {
            expected: reducer.state().clone(),
            actual: next.clone(),
        });
    }
    Ok(())
}

fn accept_attestation_event(
    reducer: &mut SessionMachine,
    actual: &SandboxAttestation,
    evidence: &mut ResponseEvidence,
) -> Result<(), DebugHostClientError> {
    require_unique_evidence(&mut evidence.attestation_accepted, "sandbox-attestation")?;
    if actual.session_id != reducer.session_id() {
        return Err(DebugHostClientError::SandboxEvidenceSessionMismatch {
            expected: reducer.session_id(),
            actual: actual.session_id,
        });
    }
    let expected = reducer
        .expected_attestation()
        .ok_or(DebugHostClientError::UnexpectedSandboxEvidence)?;
    expected.validate_exact(actual)?;
    reducer.accept_sandbox_attestation(actual)?;
    evidence.sandbox_event = true;
    Ok(())
}

fn validate_sandbox_lifecycle(
    envelope: &CommandEnvelope,
    reducer: &mut SessionMachine,
    lifecycle: &SandboxLifecycleEvent,
    evidence: &mut ResponseEvidence,
) -> Result<(), DebugHostClientError> {
    if !command_allows_sandbox_lifecycle(&envelope.command, lifecycle) {
        return Err(DebugHostClientError::UnexpectedCommandEvidence {
            command_id: envelope.command_id,
            evidence: "sandbox-lifecycle",
        });
    }
    evidence.sandbox_event = true;
    match lifecycle {
        SandboxLifecycleEvent::State { session_id, state } => {
            require_sandbox_session(reducer, *session_id)?;
            if reducer.sandbox_state() != Some(*state) {
                return Err(DebugHostClientError::UnexpectedSandboxLifecycleState {
                    expected: reducer.sandbox_state(),
                    actual: *state,
                });
            }
        }
        SandboxLifecycleEvent::Attested(actual) => {
            accept_attestation_event(reducer, actual, evidence)?;
        }
        SandboxLifecycleEvent::ProviderUnavailable(unavailable) => {
            require_sandbox_session(reducer, unavailable.session_id)?;
            let expected = reducer
                .expected_attestation()
                .ok_or(DebugHostClientError::UnexpectedSandboxEvidence)?;
            if unavailable.provider != expected.provider {
                return Err(DebugHostClientError::UnexpectedSandboxProvider);
            }
        }
        SandboxLifecycleEvent::Failed(failure) => {
            require_sandbox_session(reducer, failure.session_id)?;
            let expected = reducer
                .expected_attestation()
                .ok_or(DebugHostClientError::UnexpectedSandboxEvidence)?;
            if failure.provider != expected.provider {
                return Err(DebugHostClientError::UnexpectedSandboxProvider);
            }
        }
        SandboxLifecycleEvent::Closed(receipt) => {
            require_sandbox_session(reducer, receipt.session_id)?;
            if reducer.state().kind() != SessionStateKind::Closing {
                return Err(DebugHostClientError::CleanupReceiptOutsideClose);
            }
            if evidence.cleanup_receipt.is_some() {
                return Err(DebugHostClientError::DuplicateCommandEvidence {
                    evidence: "sandbox-cleanup-receipt",
                });
            }
            let expected = reducer
                .expected_attestation()
                .ok_or(DebugHostClientError::UnexpectedSandboxEvidence)?;
            receipt.validate_against(expected)?;
            evidence.cleanup_receipt = Some(receipt.clone());
        }
    }
    Ok(())
}

fn is_sandboxed_open(command: &DebugCommand) -> bool {
    matches!(
        command,
        DebugCommand::Open(DebugTargetRequest::Launch(crate::protocol::LaunchTarget {
            environment: crate::protocol::LaunchEnvironment::Sandboxed { .. },
            ..
        }))
    )
}

fn command_allows_sandbox_lifecycle(
    command: &DebugCommand,
    lifecycle: &SandboxLifecycleEvent,
) -> bool {
    match lifecycle {
        SandboxLifecycleEvent::Attested(_) | SandboxLifecycleEvent::ProviderUnavailable(_) => {
            is_sandboxed_open(command)
        }
        SandboxLifecycleEvent::Closed(_) => matches!(
            command,
            DebugCommand::Terminate { .. } | DebugCommand::Close { .. }
        ),
        SandboxLifecycleEvent::State { .. } | SandboxLifecycleEvent::Failed(_) => matches!(
            command,
            DebugCommand::Open(DebugTargetRequest::Launch(crate::protocol::LaunchTarget {
                environment: crate::protocol::LaunchEnvironment::Sandboxed { .. },
                ..
            })) | DebugCommand::Continue { .. }
                | DebugCommand::Pause { .. }
                | DebugCommand::Step { .. }
                | DebugCommand::Terminate { .. }
                | DebugCommand::Close { .. }
        ),
    }
}

fn require_sandbox_session(
    reducer: &SessionMachine,
    actual: SessionId,
) -> Result<(), DebugHostClientError> {
    if actual == reducer.session_id() {
        Ok(())
    } else {
        Err(DebugHostClientError::SandboxEvidenceSessionMismatch {
            expected: reducer.session_id(),
            actual,
        })
    }
}

fn require_unique_evidence(
    observed: &mut bool,
    evidence: &'static str,
) -> Result<(), DebugHostClientError> {
    if *observed {
        Err(DebugHostClientError::DuplicateCommandEvidence { evidence })
    } else {
        *observed = true;
        Ok(())
    }
}

fn validate_success_evidence(
    envelope: &CommandEnvelope,
    reducer: &SessionMachine,
    evidence: &ResponseEvidence,
) -> Result<(), DebugHostClientError> {
    let command_id = envelope.command_id;
    let final_state = reducer.state().kind();
    let valid_state = match &envelope.command {
        DebugCommand::Open(DebugTargetRequest::Offline(_)) => {
            final_state == SessionStateKind::Offline
        }
        DebugCommand::Open(DebugTargetRequest::Dump(_)) => final_state == SessionStateKind::Dump,
        DebugCommand::Open(DebugTargetRequest::Attach(target))
            if target.mode == crate::protocol::AttachMode::ObserveReadOnly =>
        {
            final_state == SessionStateKind::Observing
        }
        DebugCommand::Open(DebugTargetRequest::Attach(_))
        | DebugCommand::Open(DebugTargetRequest::Launch(_)) => {
            final_state == SessionStateKind::Stopped
        }
        DebugCommand::Continue { .. } | DebugCommand::Step { .. } => matches!(
            final_state,
            SessionStateKind::Running | SessionStateKind::Stopped | SessionStateKind::Exited
        ),
        DebugCommand::Pause { .. } => {
            matches!(
                final_state,
                SessionStateKind::Stopped | SessionStateKind::Exited
            )
        }
        DebugCommand::ReadMemory { .. } => evidence.memory_read,
        DebugCommand::WriteMemory { .. } => {
            evidence.memory_written && final_state == SessionStateKind::Stopped
        }
        DebugCommand::SetBreakpoint { .. } | DebugCommand::RemoveBreakpoint { .. } => {
            evidence.breakpoint_changed && final_state == SessionStateKind::Stopped
        }
        DebugCommand::CaptureSnapshot { .. } => false,
        DebugCommand::Detach { .. } => final_state == SessionStateKind::Detached,
        DebugCommand::Terminate { .. } | DebugCommand::Close { .. } => {
            final_state == SessionStateKind::Closed
                && (reducer.expected_attestation().is_none() || evidence.cleanup_receipt.is_some())
        }
        DebugCommand::ProbeCapabilities => false,
    };
    if !valid_state {
        return Err(DebugHostClientError::MissingCommandEvidence {
            command_id,
            command: command_name(&envelope.command),
            final_state,
        });
    }
    if matches!(
        &envelope.command,
        DebugCommand::Open(DebugTargetRequest::Launch(crate::protocol::LaunchTarget {
            environment: crate::protocol::LaunchEnvironment::Sandboxed { .. },
            ..
        }))
    ) && !evidence.attestation_accepted
    {
        return Err(DebugHostClientError::MissingCommandEvidence {
            command_id,
            command: "sandboxed-open",
            final_state,
        });
    }
    Ok(())
}

fn command_name(command: &DebugCommand) -> &'static str {
    match command {
        DebugCommand::ProbeCapabilities => "probe-capabilities",
        DebugCommand::Open(_) => "open",
        DebugCommand::Continue { .. } => "continue",
        DebugCommand::Pause { .. } => "pause",
        DebugCommand::Step { .. } => "step",
        DebugCommand::ReadMemory { .. } => "read-memory",
        DebugCommand::WriteMemory { .. } => "write-memory",
        DebugCommand::SetBreakpoint { .. } => "set-breakpoint",
        DebugCommand::RemoveBreakpoint { .. } => "remove-breakpoint",
        DebugCommand::CaptureSnapshot { .. } => "capture-snapshot",
        DebugCommand::Detach { .. } => "detach",
        DebugCommand::Terminate { .. } => "terminate",
        DebugCommand::Close { .. } => "close",
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
    #[error(transparent)]
    SessionMachine(#[from] SessionMachineError),
    #[error(transparent)]
    Attestation(#[from] AttestationMismatch),
    #[error(transparent)]
    CleanupReceipt(#[from] CleanupReceiptError),
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
    #[error("expected typed protocol {expected:?}, received {actual:?}")]
    UnexpectedTypedProtocolVersion {
        expected: ProtocolVersion,
        actual: ProtocolVersion,
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
    #[error("host returned more than one result for command {command_id:?}")]
    DuplicateCommandResult { command_id: CommandId },
    #[error("host returned an event after the result for command {command_id:?}")]
    EventAfterCommandResult { command_id: CommandId },
    #[error("host returned duplicate {evidence} evidence")]
    DuplicateCommandEvidence { evidence: &'static str },
    #[error("host returned {evidence} evidence for the wrong command")]
    UnexpectedCommandEvidence {
        command_id: CommandId,
        evidence: &'static str,
    },
    #[error("rejected command {command_id:?} produced state or operation evidence")]
    RejectedCommandProducedEvidence { command_id: CommandId },
    #[error("successful command {command_id:?} omitted its reducer-produced state")]
    MissingCommandState { command_id: CommandId },
    #[error(
        "successful {command} command {command_id:?} lacks exact evidence; final state is {final_state:?}"
    )]
    MissingCommandEvidence {
        command_id: CommandId,
        command: &'static str,
        final_state: SessionStateKind,
    },
    #[error("host attempted illegal reducer transition {from:?} -> {to:?}")]
    IllegalHostStateTransition {
        from: SessionStateKind,
        to: SessionStateKind,
    },
    #[error("host state differs from reducer output: expected {expected:?}, actual {actual:?}")]
    ReducerStateMismatch {
        expected: SessionState,
        actual: SessionState,
    },
    #[error("sandbox evidence is not valid for this command/session")]
    UnexpectedSandboxEvidence,
    #[error("sandbox evidence session mismatch: expected {expected:?}, actual {actual:?}")]
    SandboxEvidenceSessionMismatch {
        expected: SessionId,
        actual: SessionId,
    },
    #[error("sandbox lifecycle provider differs from the requested provider")]
    UnexpectedSandboxProvider,
    #[error("sandbox lifecycle state mismatch: expected {expected:?}, actual {actual:?}")]
    UnexpectedSandboxLifecycleState {
        expected: Option<SandboxLifecycleState>,
        actual: SandboxLifecycleState,
    },
    #[error("sandbox cleanup receipt arrived outside a close operation")]
    CleanupReceiptOutsideClose,
    #[error("sandbox cleanup was not independently verified before release")]
    SandboxCleanupNotVerified,
}

/// A deterministic, non-executing transport used only for tests.
///
/// It is deliberately named synthetic, feature-gated, and limited to offline
/// reducer mechanics. It never emits sandbox attestation or cleanup receipts.
#[cfg(any(test, feature = "test-support"))]
pub struct SyntheticDebugHost {
    handshake: BuildClaimHandshake,
    provisioning_epoch: ProvisioningEpoch,
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

#[cfg(any(test, feature = "test-support"))]
impl SyntheticDebugHost {
    pub fn new(
        host_build: impl Into<String>,
        expected_controller_build: impl Into<String>,
        provisioning_epoch: ProvisioningEpoch,
        helper_build: HelperBuildId,
    ) -> Result<Self, HandshakeError> {
        Ok(Self {
            handshake: BuildClaimHandshake::responder(
                EndpointRole::Host,
                host_build,
                expected_controller_build,
            )?,
            provisioning_epoch,
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
                "injected synthetic backend failure",
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
        let session_id = envelope
            .session_id
            .ok_or_else(|| HostTransportError::protocol("session command omitted session id"))?;
        if self.machine.is_none() {
            self.machine = Some(SessionMachine::new(
                session_id,
                self.provisioning_epoch.clone(),
                self.helper_build.clone(),
            ));
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
        if !synthetic_command_supported(&command) {
            envelope
                .validate_against(&before)
                .map_err(|error| HostTransportError::protocol(error.to_string()))?;
            let mut events = Vec::new();
            self.push_event(
                &mut events,
                command_id,
                DebugEvent::CommandResult {
                    command_id,
                    outcome: CommandOutcome::Rejected {
                        code: "synthetic-unsupported".to_owned(),
                        message: "synthetic host did not perform this target operation".to_owned(),
                    },
                },
            )?;
            return Ok(events);
        }
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
                reason: "synthetic test host has no platform provider".to_owned(),
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
            DebugCommand::Open(DebugTargetRequest::Offline(_)) => {
                let state = self
                    .machine_mut()?
                    .complete_open_offline()
                    .map_err(machine_error)?
                    .clone();
                self.push_event(events, command_id, DebugEvent::StateChanged(state))?;
            }
            DebugCommand::Close { .. } => {
                let state = self
                    .machine_mut()?
                    .complete_close(None)
                    .map_err(machine_error)?
                    .clone();
                self.push_event(events, command_id, DebugEvent::StateChanged(state))?;
            }
            _ => unreachable!("unsupported synthetic command passed the support gate"),
        }
        Ok(())
    }

    fn push_global_event(
        &mut self,
        frames: &mut Vec<HostFrame>,
        command_id: CommandId,
        event: DebugEvent,
    ) -> Result<(), HostTransportError> {
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

#[cfg(any(test, feature = "test-support"))]
impl HostFrameExchange for SyntheticDebugHost {
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

    fn release_session(&mut self, session_id: SessionId) -> Result<(), HostTransportError> {
        let machine = self.machine_ref()?;
        if machine.session_id() != session_id || machine.state().kind() != SessionStateKind::Closed
        {
            return Err(HostTransportError::protocol(
                "synthetic session release was not reducer-confirmed",
            ));
        }
        self.machine = None;
        Ok(())
    }

    fn shutdown_control(
        &mut self,
        _reason: ControlShutdownReason,
    ) -> Result<(), HostTransportError> {
        self.disconnected = true;
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
fn machine_error(error: SessionMachineError) -> HostTransportError {
    HostTransportError::protocol(error.to_string())
}

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
fn synthetic_command_supported(command: &DebugCommand) -> bool {
    matches!(
        command,
        DebugCommand::Open(DebugTargetRequest::Offline(_)) | DebugCommand::Close { .. }
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::rc::Rc;

    use resymbol_core::BinaryId;

    use super::*;
    use crate::authorization::HostRiskOperation;
    use crate::host_response::{MAX_RESPONSE_BYTES, MAX_RESPONSE_FRAME_BYTES};
    use crate::host_wire::{ControlBody, FrameHeader, MessageKind};
    use crate::identity::HostRiskLeaseId;
    use crate::protocol::{
        LaunchEnvironment, LaunchTarget, MAX_MEMORY_READ_BYTES, MemoryAddress, OfflineTarget,
        ReadViewToken, StateGeneration, StopReason, ThreadId,
    };
    use crate::sandbox::{
        ChildProcessProfile, CleanupOutcome, CleanupReceiptId, DynamicCodeProfile,
        ExpectedSandboxAttestation, IsolationBoundary, ProcessMitigationProfile, SandboxGuarantee,
        SandboxNetworkMode, SandboxPolicy, SandboxPolicyApprovalId, SandboxProviderSelection,
        SandboxResourceLimits, Win32kProfile,
    };

    fn session_id() -> SessionId {
        SessionId::new(17).expect("session id")
    }

    fn helper_build() -> HelperBuildId {
        HelperBuildId::new("fake-helper-1.0.0+test").expect("helper build")
    }

    fn provisioning_epoch() -> ProvisioningEpoch {
        ProvisioningEpoch::new("9".repeat(64)).expect("provisioning epoch")
    }

    fn host() -> SyntheticDebugHost {
        SyntheticDebugHost::new(
            "host/build-4",
            "controller/build-7",
            provisioning_epoch(),
            helper_build(),
        )
        .unwrap()
    }

    fn client(host: SyntheticDebugHost) -> DebugHostClient<SyntheticDebugHost> {
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
        inner: SyntheticDebugHost,
        mutation: ResponseMutation,
        exchanges: usize,
    }

    struct OverBudgetHost {
        inner: SyntheticDebugHost,
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

        fn release_session(&mut self, session_id: SessionId) -> Result<(), HostTransportError> {
            self.inner.release_session(session_id)
        }

        fn shutdown_control(
            &mut self,
            reason: ControlShutdownReason,
        ) -> Result<(), HostTransportError> {
            self.inner.shutdown_control(reason)
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

        fn release_session(&mut self, session_id: SessionId) -> Result<(), HostTransportError> {
            self.inner.release_session(session_id)
        }

        fn shutdown_control(
            &mut self,
            reason: ControlShutdownReason,
        ) -> Result<(), HostTransportError> {
            self.inner.shutdown_control(reason)
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

    #[derive(Debug, Clone, Copy)]
    enum ScriptedAttack {
        ForgedAttestation,
        MissingCleanup,
        WrongCleanup,
    }

    struct ScriptedHost {
        build_claim: BuildClaimHandshake,
        attack: ScriptedAttack,
        next_frame_sequence: u64,
        next_event_sequence: u64,
        shutdown: bool,
    }

    impl ScriptedHost {
        fn new(attack: ScriptedAttack) -> Self {
            Self {
                build_claim: BuildClaimHandshake::responder(
                    EndpointRole::Host,
                    "host/build-4",
                    "controller/build-7",
                )
                .unwrap(),
                attack,
                next_frame_sequence: 2,
                next_event_sequence: 1,
                shutdown: false,
            }
        }

        fn scripted_response(
            &mut self,
            envelope: &CommandEnvelope,
        ) -> Result<Vec<HostFrame>, HostTransportError> {
            let session_id = envelope
                .session_id
                .ok_or_else(|| HostTransportError::protocol("script omitted session"))?;
            let mut batch = Vec::new();
            match self.attack {
                ScriptedAttack::ForgedAttestation => {
                    let mut reducer =
                        SessionMachine::new(session_id, provisioning_epoch(), helper_build());
                    reducer.accept_command(envelope).map_err(machine_error)?;
                    self.push_scripted_event(
                        &mut batch,
                        envelope.command_id,
                        session_id,
                        reducer.state().state_token(),
                        DebugEvent::StateChanged(reducer.state().clone()),
                    )?;
                    reducer.target_created_suspended().map_err(machine_error)?;
                    self.push_scripted_event(
                        &mut batch,
                        envelope.command_id,
                        session_id,
                        reducer.state().state_token(),
                        DebugEvent::StateChanged(reducer.state().clone()),
                    )?;
                    let mut forged = test_attestation(
                        reducer
                            .expected_attestation()
                            .expect("sandbox command creates expectation"),
                    );
                    forged.helper_build =
                        HelperBuildId::new("forged-helper-build").expect("forged build id");
                    self.push_scripted_event(
                        &mut batch,
                        envelope.command_id,
                        session_id,
                        reducer.state().state_token(),
                        DebugEvent::SandboxAttested(forged),
                    )?;
                }
                ScriptedAttack::MissingCleanup | ScriptedAttack::WrongCleanup => {
                    let prior = envelope
                        .expected_state
                        .ok_or_else(|| HostTransportError::protocol("close omitted state"))?;
                    let closing_token = next_state_token(prior, 1);
                    let closing = SessionState::Closing {
                        token: closing_token,
                    };
                    self.push_scripted_event(
                        &mut batch,
                        envelope.command_id,
                        session_id,
                        closing_token,
                        DebugEvent::StateChanged(closing),
                    )?;
                    if matches!(self.attack, ScriptedAttack::WrongCleanup) {
                        let mut wrong = test_cleanup_receipt(&expected_sandbox_attestation());
                        wrong.handles_closed = false;
                        self.push_scripted_event(
                            &mut batch,
                            envelope.command_id,
                            session_id,
                            closing_token,
                            DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::Closed(wrong)),
                        )?;
                    } else {
                        let closed = SessionState::Closed {
                            token: next_state_token(prior, 2),
                        };
                        self.push_scripted_event(
                            &mut batch,
                            envelope.command_id,
                            session_id,
                            closed.state_token(),
                            DebugEvent::StateChanged(closed),
                        )?;
                    }
                }
            }
            Ok(batch)
        }

        fn push_scripted_event(
            &mut self,
            batch: &mut Vec<HostFrame>,
            command_id: CommandId,
            session_id: SessionId,
            state: StateToken,
            event: DebugEvent,
        ) -> Result<(), HostTransportError> {
            let event = EventEnvelope {
                version: ProtocolVersion::current(),
                sequence: EventSequence::new(self.next_event_sequence)
                    .map_err(|error| HostTransportError::protocol(error.to_string()))?,
                session_id: Some(session_id),
                state: Some(state),
                caused_by: Some(command_id),
                event,
            };
            let frame = encode_event_frame(
                FrameSequence::new(self.next_frame_sequence)
                    .map_err(|error| HostTransportError::protocol(error.to_string()))?,
                &event,
            )
            .map_err(|error| HostTransportError::protocol(error.to_string()))?;
            self.next_frame_sequence += 1;
            self.next_event_sequence += 1;
            batch.push(frame);
            Ok(())
        }
    }

    impl HostFrameExchange for ScriptedHost {
        fn exchange(
            &mut self,
            request: HostFrame,
            limits: HostResponseLimits,
        ) -> Result<HostResponseBatch, HostTransportError> {
            if self.shutdown {
                return Err(HostTransportError::Disconnected);
            }
            if self.build_claim.state() != HandshakeState::Established {
                let acknowledgement = self
                    .build_claim
                    .accept(request.header())
                    .map_err(|error| HostTransportError::protocol(error.to_string()))?
                    .ok_or_else(|| HostTransportError::protocol("missing build-claim response"))?;
                let frame = HostFrame::new(acknowledgement, Vec::new())
                    .map_err(|error| HostTransportError::protocol(error.to_string()))?;
                return HostResponseBatch::try_from_frames(vec![frame], limits)
                    .map_err(HostTransportError::from);
            }
            let envelope = decode_command_frame(&request)
                .map_err(|error| HostTransportError::protocol(error.to_string()))?;
            HostResponseBatch::try_from_frames(self.scripted_response(&envelope)?, limits)
                .map_err(HostTransportError::from)
        }

        fn release_session(&mut self, _session_id: SessionId) -> Result<(), HostTransportError> {
            Err(HostTransportError::protocol(
                "adversarial host cannot release a session",
            ))
        }

        fn shutdown_control(
            &mut self,
            _reason: ControlShutdownReason,
        ) -> Result<(), HostTransportError> {
            self.shutdown = true;
            Ok(())
        }
    }

    fn next_state_token(prior: StateToken, offset: u64) -> StateToken {
        StateToken {
            session_id: prior.session_id,
            generation: StateGeneration::new(prior.generation.get() + offset)
                .expect("test generation is nonzero"),
        }
    }

    struct TrackingHost {
        inner: SyntheticDebugHost,
        shutdowns: Rc<RefCell<Vec<ControlShutdownReason>>>,
    }

    impl TrackingHost {
        fn new(shutdowns: Rc<RefCell<Vec<ControlShutdownReason>>>) -> Self {
            Self {
                inner: host(),
                shutdowns,
            }
        }
    }

    impl HostFrameExchange for TrackingHost {
        fn exchange(
            &mut self,
            request: HostFrame,
            limits: HostResponseLimits,
        ) -> Result<HostResponseBatch, HostTransportError> {
            self.inner.exchange(request, limits)
        }

        fn release_session(&mut self, session_id: SessionId) -> Result<(), HostTransportError> {
            self.inner.release_session(session_id)
        }

        fn shutdown_control(
            &mut self,
            reason: ControlShutdownReason,
        ) -> Result<(), HostTransportError> {
            self.shutdowns.borrow_mut().push(reason);
            self.inner.shutdown_control(reason)
        }
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
            policy_approval: SandboxPolicyApprovalId::new(session_id, "fake-sandbox-ack")
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

    fn sandbox_target() -> DebugTargetRequest {
        DebugTargetRequest::Launch(LaunchTarget {
            binary_id: BinaryId::digest(b"adversarial sandbox sample"),
            executable: PathBuf::from("sample.exe"),
            arguments: Vec::new(),
            working_directory: None,
            environment: LaunchEnvironment::Sandboxed {
                policy: sandbox_policy(),
            },
            stop_before_entry: true,
        })
    }

    fn expected_sandbox_attestation() -> ExpectedSandboxAttestation {
        let DebugTargetRequest::Launch(target) = sandbox_target() else {
            unreachable!("test target is a launch")
        };
        let LaunchEnvironment::Sandboxed { policy } = target.environment else {
            unreachable!("test launch is sandboxed")
        };
        ExpectedSandboxAttestation::from_policy(
            target.binary_id,
            &policy,
            helper_build(),
            provisioning_epoch(),
        )
        .expect("test policy produces an expectation")
    }

    fn test_attestation(expected: &ExpectedSandboxAttestation) -> SandboxAttestation {
        SandboxAttestation {
            binary_id: expected.binary_id.clone(),
            session_id: expected.session_id,
            provisioning_epoch: expected.provisioning_epoch.clone(),
            policy_digest: expected.policy_digest.clone(),
            provider: expected.provider.clone(),
            boundary: expected.boundary,
            guarantees: expected.guarantees.clone(),
            job_assigned_at_creation: expected.job_assigned_at_creation,
            helper_build: expected.helper_build.clone(),
            vm_identity: expected.vm_identity.clone(),
        }
    }

    fn test_cleanup_receipt(expected: &ExpectedSandboxAttestation) -> SandboxCleanupReceipt {
        SandboxCleanupReceipt {
            receipt_id: CleanupReceiptId::new("adversarial-cleanup-receipt")
                .expect("test receipt id"),
            session_id: expected.session_id,
            provisioning_epoch: expected.provisioning_epoch.clone(),
            provider: expected.provider.clone(),
            policy_digest: expected.policy_digest.clone(),
            process: None,
            outcome: CleanupOutcome::Complete,
            process_tree_terminated_and_reaped: true,
            handles_closed: true,
            file_system_rolled_back: true,
            registry_rolled_back: true,
            network_torn_down: true,
            owned_paths_deleted: true,
            appcontainer_profile_deleted: Some(true),
            differencing_disk_discarded: None,
            control_channel_closed: None,
            terminated_processes: 1,
            residuals: Vec::new(),
        }
    }

    fn scripted_client(attack: ScriptedAttack) -> DebugHostClient<ScriptedHost> {
        DebugHostClient::connect(
            ScriptedHost::new(attack),
            [0x6d; 16],
            "controller/build-7",
            "host/build-4",
        )
        .unwrap()
    }

    fn prime_sandbox_stopped(client: &mut DebugHostClient<ScriptedHost>) {
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        let verified_state = {
            let reducer = &mut client
                .session
                .as_mut()
                .expect("test session exists")
                .reducer;
            let state = reducer.state().state_token();
            let open = CommandEnvelope {
                version: ProtocolVersion::current(),
                command_id: CommandId::new(1).unwrap(),
                session_id: Some(session_id()),
                expected_state: Some(state),
                command: DebugCommand::Open(sandbox_target()),
            };
            reducer.accept_command(&open).unwrap();
            reducer.target_created_suspended().unwrap();
            let attestation = test_attestation(
                reducer
                    .expected_attestation()
                    .expect("sandbox expectation exists"),
            );
            reducer.accept_sandbox_attestation(&attestation).unwrap();
            reducer
                .mark_stopped(
                    StopReason::Initial,
                    ThreadId::new(1).expect("test thread id"),
                )
                .unwrap();
            reducer.state().clone()
        };
        client
            .session
            .as_mut()
            .expect("test session exists")
            .verified_state = verified_state;
        client.next_command_id = 2;
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
    fn synthetic_transport_enforces_supplied_limits_and_disconnects() {
        let mut initiator = BuildClaimHandshake::initiator(
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
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
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
    fn synthetic_host_rejects_sandbox_and_emits_no_security_evidence() {
        let mut client = client(host());
        assert_eq!(client.negotiated_version(), WireProtocolVersion::CURRENT);
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        let rejected = client
            .submit(DebugCommand::Open(DebugTargetRequest::Launch(
                LaunchTarget {
                    binary_id: BinaryId::digest(b"synthetic sandbox sample"),
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
        assert!(matches!(rejected.outcome, CommandOutcome::Rejected { .. }));
        assert!(rejected.events.iter().all(|event| !matches!(
            event.event,
            DebugEvent::SandboxAttested(_) | DebugEvent::SandboxLifecycle(_)
        )));
        assert_eq!(
            client.session_state().unwrap().kind(),
            SessionStateKind::Idle
        );
        assert_eq!(
            client.abandon_session().unwrap().kind(),
            SessionStateKind::Idle
        );
    }

    #[test]
    fn client_rejects_forged_sandbox_attestation() {
        let mut client = scripted_client(ScriptedAttack::ForgedAttestation);
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        assert_eq!(
            client.submit(DebugCommand::Open(sandbox_target())),
            Err(DebugHostClientError::Attestation(
                AttestationMismatch::HelperBuild
            ))
        );
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
    }

    #[test]
    fn client_rejects_closed_without_cleanup_receipt() {
        let mut client = scripted_client(ScriptedAttack::MissingCleanup);
        prime_sandbox_stopped(&mut client);
        let state = client.session_state().unwrap().state_token();
        assert_eq!(
            client.submit(DebugCommand::Close { state }),
            Err(DebugHostClientError::SessionMachine(
                SessionMachineError::MissingCleanupReceipt
            ))
        );
        assert_eq!(
            client.session_state().unwrap().kind(),
            SessionStateKind::Stopped
        );
    }

    #[test]
    fn client_rejects_false_complete_cleanup_receipt() {
        let mut client = scripted_client(ScriptedAttack::WrongCleanup);
        prime_sandbox_stopped(&mut client);
        let state = client.session_state().unwrap().state_token();
        assert_eq!(
            client.submit(DebugCommand::Close { state }),
            Err(DebugHostClientError::CleanupReceipt(
                CleanupReceiptError::FalseComplete
            ))
        );
        assert_eq!(
            client.session_state().unwrap().kind(),
            SessionStateKind::Stopped
        );
    }

    #[test]
    fn active_session_drop_and_abandon_only_shutdown_control() {
        let dropped = Rc::new(RefCell::new(Vec::new()));
        {
            let mut client = DebugHostClient::connect(
                TrackingHost::new(Rc::clone(&dropped)),
                [0x6d; 16],
                "controller/build-7",
                "host/build-4",
            )
            .unwrap();
            client
                .begin_session(session_id(), provisioning_epoch(), helper_build())
                .unwrap();
            client
                .submit(DebugCommand::Open(DebugTargetRequest::Offline(
                    OfflineTarget {
                        path: PathBuf::from("sample.exe"),
                    },
                )))
                .unwrap();
        }
        assert_eq!(
            dropped.borrow().as_slice(),
            &[ControlShutdownReason::ClientDropped]
        );

        let abandoned = Rc::new(RefCell::new(Vec::new()));
        {
            let mut client = DebugHostClient::connect(
                TrackingHost::new(Rc::clone(&abandoned)),
                [0x6d; 16],
                "controller/build-7",
                "host/build-4",
            )
            .unwrap();
            client
                .begin_session(session_id(), provisioning_epoch(), helper_build())
                .unwrap();
            client
                .submit(DebugCommand::Open(DebugTargetRequest::Offline(
                    OfflineTarget {
                        path: PathBuf::from("sample.exe"),
                    },
                )))
                .unwrap();
            assert_eq!(
                client.abandon_session().unwrap().kind(),
                SessionStateKind::Offline
            );
        }
        assert_eq!(
            abandoned.borrow().as_slice(),
            &[ControlShutdownReason::ExplicitAbandon]
        );
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

        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
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
    fn synthetic_host_rejects_unsupported_operations_without_claiming_effects() {
        let mut client = client(host());
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        client
            .submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe"),
                },
            )))
            .unwrap();
        let state = client.session_state().unwrap().state_token();
        let rejected = client
            .submit(DebugCommand::ReadMemory {
                view: ReadViewToken::Offline { state },
                address: MemoryAddress::new(0),
                size: 16,
            })
            .unwrap();
        assert!(matches!(rejected.outcome, CommandOutcome::Rejected { .. }));
        assert_eq!(
            client.session_state().unwrap().kind(),
            SessionStateKind::Offline
        );
        let state = client.session_state().unwrap().state_token();
        client.submit(DebugCommand::Close { state }).unwrap();
        client.release_closed_session().unwrap();
        client.disconnect().unwrap();
    }

    #[test]
    fn rejected_host_operation_consumes_its_controller_authority() {
        let binary_id = BinaryId::digest(b"synthetic host-risk sample");
        let risk_lease = HostRiskLeaseId::new("a".repeat(64)).expect("host-risk lease id");
        let command = DebugCommand::Open(DebugTargetRequest::Launch(LaunchTarget {
            binary_id: binary_id.clone(),
            executable: PathBuf::from("sample.exe"),
            arguments: Vec::new(),
            working_directory: None,
            environment: LaunchEnvironment::Host {
                risk_lease: risk_lease.clone(),
            },
            stop_before_entry: true,
        }));
        let mut client = client(host());
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        client
            .register_host_risk_lease(HostRiskLease::new(
                risk_lease,
                session_id(),
                HostRiskOperation::Launch { binary_id },
            ))
            .unwrap();

        let rejected = client.submit(command.clone()).unwrap();
        assert!(matches!(rejected.outcome, CommandOutcome::Rejected { .. }));
        assert_eq!(
            client.session_state().unwrap().kind(),
            SessionStateKind::Idle
        );
        assert_eq!(
            client.submit(command),
            Err(DebugHostClientError::SessionMachine(
                SessionMachineError::HostRiskLeaseUnavailable
            ))
        );
    }

    #[test]
    fn client_rejects_stale_tokens_before_transport_and_fake_rejects_replay() {
        let mut client = client(host());
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
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
        let rejected_frames = rejected.into_frames();
        assert!(matches!(
            decode_event_frame(&rejected_frames[0]).unwrap().event,
            DebugEvent::CommandResult {
                command_id,
                outcome: CommandOutcome::Rejected { .. },
            } if command_id == stale_id
        ));
        assert!(rejected_frames.iter().all(|frame| !matches!(
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
        disconnected
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
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
        failed
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
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
    fn disconnect_during_an_active_session_preserves_last_verified_state() {
        let mut client = client(host().with_disconnect_after(2));
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        client
            .submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe"),
                },
            )))
            .unwrap();
        let opened = client.session_state().unwrap().clone();
        let state = opened.state_token();
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
        assert_eq!(client.session_state(), Some(&opened));
        assert_eq!(
            client.release_closed_session(),
            Err(DebugHostClientError::Disconnected)
        );
    }

    #[test]
    fn build_claim_correlation_pins_the_expected_host_build_claim() {
        let result =
            DebugHostClient::connect(host(), [0x7f; 16], "controller/build-7", "host/wrong-build");
        assert!(matches!(
            result,
            Err(DebugHostClientError::Handshake(
                HandshakeError::PeerBuildClaimMismatch
            ))
        ));
    }

    #[test]
    fn client_rejects_frame_gaps_and_wrong_command_correlation() {
        let mut gap = mutating_client(ResponseMutation::FrameGap);
        gap.begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
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
        wrong
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
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
        missing
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
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
        duplicate
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        assert!(matches!(
            duplicate.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe")
                }
            ))),
            Err(DebugHostClientError::EventAfterCommandResult { command_id })
                if command_id.get() == 1
        ));
    }

    #[test]
    fn client_rejects_impossible_transitions_and_stale_event_state() {
        let mut impossible = mutating_client(ResponseMutation::ImpossibleTransition);
        impossible
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        assert!(matches!(
            impossible.submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe")
                }
            ))),
            Err(DebugHostClientError::ReducerStateMismatch { expected, actual })
                if expected.kind() == SessionStateKind::Opening
                    && actual.kind() == SessionStateKind::Closed
        ));
        assert_eq!(impossible.connection_state(), ClientConnectionState::Failed);
        assert_eq!(
            impossible.session_state().map(SessionState::kind),
            Some(SessionStateKind::Idle)
        );

        let mut stale = mutating_client(ResponseMutation::StaleEventState);
        stale
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
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
