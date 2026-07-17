//! Single-owner debugger-host client seam and synthetic test transport.
//!
//! This module performs no process operations. The feature-gated synthetic host
//! exercises protocol mechanics but never claims target or sandbox work occurred.

use std::{collections::VecDeque, marker::PhantomData, rc::Rc};

use resymbol_core::BinaryId;
use thiserror::Error;

use crate::authorization::{HostRiskVerifier, SandboxOwnershipVerifier};
use crate::host_codec::{HostCodecError, HostFrame, decode_event_frame, encode_command_frame};
#[cfg(any(test, feature = "test-support"))]
use crate::host_codec::{decode_command_frame, encode_event_frame};
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
    DebugEvent, DebugTargetRequest, EventEnvelope, EventSequenceCursor, LiveTargetBinding,
    ProcessIdentity, ProtocolValidationError, ProtocolVersion, SessionId, SessionState,
    SessionStateKind, StateToken,
};
use crate::sandbox::{
    AttestationMismatch, CleanupAttemptFailureError, CleanupReceiptError, DiagnosticText,
    HelperBuildId, SandboxAttestation, SandboxCleanupReceipt, SandboxFailure, SandboxFailureStage,
    SandboxLifecycleEvent, SandboxLifecycleState, SandboxMachineError, SandboxProviderSelection,
};
use crate::session_machine::{RemoteCommandCheckpoint, UnsolicitedObservationError};
use crate::{SessionMachine, SessionMachineError};

#[cfg(any(test, feature = "test-support"))]
use crate::protocol::{
    CapabilityAvailability, CapabilityStatus, CapabilityUnavailableCode, DebugCapability,
    EventSequence,
};
pub const MAX_PENDING_COMMANDS: usize = 1;
/// Maximum accepted unsolicited observations retained until the connection
/// owner drains them through [`DebugHostClient::pump_inbound`].
pub const MAX_PENDING_UNSOLICITED_EVENTS: usize = MAX_RESPONSE_FRAMES;
/// Longest single wait a transport may perform for unsolicited host events.
///
/// Callers can pump repeatedly, but one poll remains bounded so a connection
/// owner can service shutdown and outbound command queues between waits.
pub const MAX_HOST_POLL_WAIT_MILLIS: u32 = 1_000;

/// Validated wait supplied to [`HostFrameExchange::poll_inbound`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostPollWait(u32);

impl HostPollWait {
    pub fn from_millis(milliseconds: u32) -> Result<Self, HostPollWaitError> {
        if milliseconds > MAX_HOST_POLL_WAIT_MILLIS {
            Err(HostPollWaitError::TooLong {
                actual: milliseconds,
                maximum: MAX_HOST_POLL_WAIT_MILLIS,
            })
        } else {
            Ok(Self(milliseconds))
        }
    }

    #[must_use]
    pub const fn immediate() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn as_millis(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum HostPollWaitError {
    #[error("host event poll wait {actual} ms exceeds the {maximum} ms maximum")]
    TooLong { actual: u32, maximum: u32 },
}

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

    /// Receives one nonempty, peer-declared batch of unsolicited event frames.
    ///
    /// The default preserves compatibility for request/response-only hosts by
    /// reporting that no batch arrived. A live transport must apply `limits`
    /// before allocating exactly as [`Self::exchange`] does. `Ok(None)` means
    /// the bounded wait elapsed; it is not a disconnect or an empty batch.
    /// Poll batches and exchange responses share one inbound frame/event
    /// sequence and must be surfaced in the exact order assigned by the host.
    fn poll_inbound(
        &mut self,
        _wait: HostPollWait,
        _limits: HostResponseLimits,
    ) -> Result<Option<HostResponseBatch>, HostTransportError> {
        Ok(None)
    }

    /// Releases host-side bookkeeping only after the client independently
    /// verified a terminal session and, when required, exact cleanup evidence.
    fn release_session(&mut self, session_id: SessionId) -> Result<(), HostTransportError>;

    /// Best-effort control-channel shutdown. This is never cleanup evidence.
    fn shutdown_control(&mut self, reason: ControlShutdownReason)
    -> Result<(), HostTransportError>;

    /// Mandatory non-panicking emergency teardown for owned control/process
    /// resources. Implementations must synchronously sever the channel and
    /// trigger kill-on-close ownership where applicable. This is never target
    /// or sandbox cleanup evidence.
    fn abort_control(&mut self, reason: ControlShutdownReason);
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
    pending_unsolicited_events: VecDeque<EventEnvelope>,
    transport_shutdown: bool,
    _owner_thread: PhantomData<Rc<()>>,
}

#[derive(Debug, PartialEq, Eq)]
struct ClientSession {
    reducer: SessionMachine,
    verified_state: SessionState,
    sandbox_cleanup_verified: bool,
    live_target_binding: Option<LiveTargetBinding>,
}

#[derive(Debug, Default)]
struct ResponseEvidence {
    state_changed: bool,
    command_state_observed: bool,
    failure_state_observed: bool,
    attestation_accepted: bool,
    cleanup_receipt: Option<SandboxCleanupReceipt>,
    incomplete_cleanup_receipt: Option<SandboxCleanupReceipt>,
    memory_read: bool,
    memory_written: bool,
    breakpoint_changed: bool,
    live_target_bound: bool,
    sandbox_event: bool,
    sandbox_states: Vec<SandboxLifecycleState>,
    sandbox_rejection_diagnostic: Option<SandboxRejectionDiagnostic>,
}

impl ResponseEvidence {
    fn has_effect(&self) -> bool {
        self.state_changed
            || self.attestation_accepted
            || self.cleanup_receipt.is_some()
            || self.incomplete_cleanup_receipt.is_some()
            || self.memory_read
            || self.memory_written
            || self.breakpoint_changed
            || self.live_target_bound
            || self.sandbox_event
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SandboxRejectionDiagnostic {
    ProviderUnavailable,
    Failed {
        failure: SandboxFailure,
        cleanup_attempt: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectedResponseDisposition {
    RollBack,
    RetainCleanupRequiredFailure,
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
                transport.abort_control(ControlShutdownReason::TransportFailure);
                return Err(error.into());
            }
        };
        if let Err(error) = responses.validate(DEFAULT_HOST_RESPONSE_LIMITS) {
            transport.abort_control(ControlShutdownReason::BuildClaimFailed);
            return Err(error.into());
        }
        if responses.len() != 1 {
            transport.abort_control(ControlShutdownReason::BuildClaimFailed);
            return Err(DebugHostClientError::UnexpectedHandshakeResponseCount {
                actual: responses.len(),
            });
        }
        let acknowledgement = &responses.as_slice()[0];
        if !acknowledgement.raw().is_empty() {
            transport.abort_control(ControlShutdownReason::BuildClaimFailed);
            return Err(DebugHostClientError::HandshakeCarriedRawPayload);
        }
        if let Err(error) = handshake.accept(acknowledgement.header()) {
            transport.abort_control(ControlShutdownReason::BuildClaimFailed);
            return Err(error.into());
        }
        if handshake.state() != HandshakeState::Established {
            transport.abort_control(ControlShutdownReason::BuildClaimFailed);
            return Err(DebugHostClientError::HandshakeIncomplete);
        }
        let Some(negotiated_version) = handshake.negotiated_version() else {
            transport.abort_control(ControlShutdownReason::BuildClaimFailed);
            return Err(DebugHostClientError::HandshakeIncomplete);
        };
        let typed_version = match bind_typed_protocol_version(negotiated_version) {
            Ok(version) => version,
            Err(error) => {
                transport.abort_control(ControlShutdownReason::BuildClaimFailed);
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
            pending_unsolicited_events: VecDeque::new(),
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

    /// Returns the exact validated main-module mapping for the active live
    /// launch or debug attach, if the host supplied it and the session remains
    /// live.
    ///
    /// The binding is invalidated on terminal state, connection failure, or
    /// replacement evidence. Callers receive no mutable access to it.
    #[must_use]
    pub fn live_target_binding(&self) -> Option<&LiveTargetBinding> {
        (self.connection_state == ClientConnectionState::SessionOpen)
            .then(|| {
                self.session
                    .as_ref()
                    .and_then(|session| session.live_target_binding.as_ref())
            })
            .flatten()
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
                self.abort_transport(ControlShutdownReason::TransportFailure);
                return Err(error.into());
            }
        };
        let result = self.accept_capability_batch(command_id, responses);
        if result.is_err() {
            self.connection_state = ClientConnectionState::Failed;
            self.abort_transport(ControlShutdownReason::ProtocolFailure);
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
            live_target_binding: None,
        });
        self.connection_state = ClientConnectionState::SessionOpen;
        Ok(())
    }

    /// Registers controller-side comparison data in the validating reducer.
    ///
    /// This cloneable value is not authority. The sole move-only lease must be
    /// registered independently with the trusted host session worker.
    pub fn register_host_risk_verifier(
        &mut self,
        verifier: HostRiskVerifier,
    ) -> Result<(), DebugHostClientError> {
        self.require_session_open()?;
        self.session
            .as_mut()
            .ok_or(DebugHostClientError::SessionNotOwned)?
            .reducer
            .register_host_risk_verifier(verifier)?;
        Ok(())
    }

    /// Registers non-authority sandbox-ownership comparison data in the
    /// validating reducer. The provider-issued move-only lease must be moved
    /// independently into the trusted host worker.
    pub fn register_sandbox_ownership_verifier(
        &mut self,
        verifier: SandboxOwnershipVerifier,
    ) -> Result<(), DebugHostClientError> {
        self.require_session_open()?;
        self.session
            .as_mut()
            .ok_or(DebugHostClientError::SessionNotOwned)?
            .reducer
            .register_sandbox_ownership_verifier(verifier)?;
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
                self.invalidate_live_target_binding();
                self.connection_state = if error.is_disconnected() {
                    ClientConnectionState::Disconnected
                } else {
                    ClientConnectionState::Failed
                };
                self.abort_transport(ControlShutdownReason::TransportFailure);
                return Err(error.into());
            }
        };
        self.accept_response_batch(&envelope, checkpoint, required_command_state, responses)
    }

    /// Pumps one bounded batch of unsolicited state observations.
    ///
    /// This path never completes or implies success for an outbound command.
    /// Only `caused_by = None` stopped and exited observations for the exact
    /// active session are accepted, and each observation is independently
    /// replayed through the controller's reducer before it becomes verified
    /// state. `Ok(Vec::new())` means the bounded transport wait elapsed.
    ///
    /// `[connection owner thread; potentially blocking for at most wait]`
    pub fn pump_inbound(
        &mut self,
        wait: HostPollWait,
    ) -> Result<Vec<EventEnvelope>, DebugHostClientError> {
        self.require_session_open()?;
        if !self.pending_unsolicited_events.is_empty() {
            return Ok(self.pending_unsolicited_events.drain(..).collect());
        }
        let responses = match self
            .transport
            .poll_inbound(wait, DEFAULT_HOST_RESPONSE_LIMITS)
        {
            Ok(Some(responses)) => responses,
            Ok(None) => return Ok(Vec::new()),
            Err(error) => {
                self.invalidate_live_target_binding();
                self.connection_state = if error.is_disconnected() {
                    ClientConnectionState::Disconnected
                } else {
                    ClientConnectionState::Failed
                };
                self.abort_transport(ControlShutdownReason::TransportFailure);
                return Err(error.into());
            }
        };

        let mut session = self
            .session
            .take()
            .ok_or(DebugHostClientError::SessionNotOwned)?;
        let result = self.accept_unsolicited_batch(&mut session, responses);
        self.session = Some(session);
        if result.is_err() {
            self.invalidate_live_target_binding();
            self.connection_state = ClientConnectionState::Failed;
            self.abort_transport(ControlShutdownReason::ProtocolFailure);
        }
        result
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
        if session.reducer.requires_cleanup_receipt() && !session.sandbox_cleanup_verified {
            return Err(DebugHostClientError::SandboxCleanupNotVerified);
        }
        self.transport
            .release_session(session.reducer.session_id())?;
        self.session = None;
        self.pending_unsolicited_events.clear();
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
        self.abort_transport(ControlShutdownReason::ExplicitAbandon);
        let state = self
            .session
            .take()
            .map(|session| session.verified_state)
            .ok_or(DebugHostClientError::SessionNotOwned)?;
        self.pending_unsolicited_events.clear();
        Ok(state)
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
        self.abort_transport(ControlShutdownReason::ExplicitAbandon);
        self.connection_state = ClientConnectionState::Disconnected;
        self.session = None;
        self.pending_unsolicited_events.clear();
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
        let result = self.accept_dispatched_response_batch(
            &mut session,
            envelope,
            checkpoint,
            required_command_state,
            responses,
        );
        self.session = Some(session);
        if result.is_err() {
            self.invalidate_live_target_binding();
            self.connection_state = ClientConnectionState::Failed;
            self.abort_transport(ControlShutdownReason::ProtocolFailure);
        }
        result
    }

    fn accept_dispatched_response_batch(
        &mut self,
        session: &mut ClientSession,
        envelope: &CommandEnvelope,
        checkpoint: RemoteCommandCheckpoint,
        required_command_state: Option<SessionState>,
        responses: HostResponseBatch,
    ) -> Result<CommandReceipt, DebugHostClientError> {
        let correlations = self.prevalidate_inbound_correlations(&responses)?;
        let command_id = envelope.command_id;
        let unsolicited_prefix = correlations
            .iter()
            .take_while(|correlation| correlation.is_none())
            .count();

        if unsolicited_prefix == 0 {
            if let Some(actual) = correlations
                .iter()
                .copied()
                .find(|correlation| *correlation != Some(command_id))
            {
                return Err(match actual {
                    Some(actual) => DebugHostClientError::UnexpectedCommandCorrelation {
                        expected: command_id,
                        actual: Some(actual),
                    },
                    None => {
                        DebugHostClientError::UnsolicitedEventAfterCorrelatedResponse { command_id }
                    }
                });
            }
            return self.accept_response_batch_inner(
                session,
                envelope,
                checkpoint,
                required_command_state,
                responses,
            );
        }

        if unsolicited_prefix == correlations.len() {
            return Err(DebugHostClientError::MissingCommandResult { command_id });
        }
        for correlation in &correlations[unsolicited_prefix..] {
            match correlation {
                Some(actual) if *actual == command_id => {}
                Some(actual) => {
                    return Err(DebugHostClientError::UnexpectedCommandCorrelation {
                        expected: command_id,
                        actual: Some(*actual),
                    });
                }
                None => {
                    return Err(
                        DebugHostClientError::UnsolicitedEventAfterCorrelatedResponse {
                            command_id,
                        },
                    );
                }
            }
        }

        let pending_after = self
            .pending_unsolicited_events
            .len()
            .checked_add(unsolicited_prefix)
            .ok_or(DebugHostClientError::PendingUnsolicitedEventQueueOverflow)?;
        if pending_after > MAX_PENDING_UNSOLICITED_EVENTS {
            return Err(DebugHostClientError::PendingUnsolicitedEventQueueFull {
                actual: pending_after,
                maximum: MAX_PENDING_UNSOLICITED_EVENTS,
            });
        }

        let mut frames = responses.into_frames();
        let correlated_frames = frames.split_off(unsolicited_prefix);
        let unsolicited = HostResponseBatch::try_from_frames(frames, DEFAULT_HOST_RESPONSE_LIMITS)?;
        let correlated =
            HostResponseBatch::try_from_frames(correlated_frames, DEFAULT_HOST_RESPONSE_LIMITS)?;
        let accepted = self.accept_unsolicited_batch(session, unsolicited)?;
        self.pending_unsolicited_events.extend(accepted);
        self.accept_response_batch_inner(
            session,
            envelope,
            checkpoint,
            required_command_state,
            correlated,
        )
    }

    /// Decodes a bounded response once without committing stream cursors so a
    /// complete mixed exchange is known structurally valid before any
    /// unsolicited prefix is routed into the reducer.
    fn prevalidate_inbound_correlations(
        &self,
        responses: &HostResponseBatch,
    ) -> Result<Vec<Option<CommandId>>, DebugHostClientError> {
        responses.validate(DEFAULT_HOST_RESPONSE_LIMITS)?;
        let mut correlations = Vec::with_capacity(responses.len());
        let mut next_inbound_frame_sequence = self.next_inbound_frame_sequence;
        let mut event_cursor = self.event_cursor;
        for frame in responses.as_slice() {
            self.require_negotiated_frame_version(frame)?;
            if frame.header().sequence.get() != next_inbound_frame_sequence {
                return Err(DebugHostClientError::UnexpectedFrameSequence {
                    expected: next_inbound_frame_sequence,
                    actual: frame.header().sequence.get(),
                });
            }
            next_inbound_frame_sequence = next_inbound_frame_sequence
                .checked_add(1)
                .ok_or(DebugHostClientError::FrameSequenceOverflow)?;
            let event = decode_event_frame(frame)?;
            if event.version != self.typed_version {
                return Err(DebugHostClientError::UnexpectedTypedProtocolVersion {
                    expected: self.typed_version,
                    actual: event.version,
                });
            }
            event_cursor.observe(event.sequence)?;
            correlations.push(event.caused_by);
        }
        Ok(correlations)
    }

    fn accept_unsolicited_batch(
        &mut self,
        session: &mut ClientSession,
        responses: HostResponseBatch,
    ) -> Result<Vec<EventEnvelope>, DebugHostClientError> {
        responses.validate(DEFAULT_HOST_RESPONSE_LIMITS)?;
        if responses.is_empty() {
            return Err(DebugHostClientError::EmptyUnsolicitedEventBatch);
        }
        let mut events = Vec::with_capacity(responses.len());
        let mut next_inbound_frame_sequence = self.next_inbound_frame_sequence;
        let mut event_cursor = self.event_cursor;
        for frame in responses.into_frames() {
            self.require_negotiated_frame_version(&frame)?;
            if frame.header().sequence.get() != next_inbound_frame_sequence {
                return Err(DebugHostClientError::UnexpectedFrameSequence {
                    expected: next_inbound_frame_sequence,
                    actual: frame.header().sequence.get(),
                });
            }
            next_inbound_frame_sequence = next_inbound_frame_sequence
                .checked_add(1)
                .ok_or(DebugHostClientError::FrameSequenceOverflow)?;
            let event = decode_event_frame(&frame)?;
            if event.version != self.typed_version {
                return Err(DebugHostClientError::UnexpectedTypedProtocolVersion {
                    expected: self.typed_version,
                    actual: event.version,
                });
            }
            event_cursor.observe(event.sequence)?;
            if let Some(command_id) = event.caused_by {
                return Err(DebugHostClientError::UnsolicitedEventCarriedCorrelation {
                    command_id,
                });
            }
            let session_id = session.reducer.session_id();
            if event.session_id != Some(session_id) {
                return Err(DebugHostClientError::UnexpectedEventSession {
                    expected: session_id,
                    actual: event.session_id,
                });
            }
            let next = match &event.event {
                DebugEvent::StateChanged(
                    next @ (SessionState::Stopped { .. } | SessionState::Exited { .. }),
                ) => next,
                DebugEvent::StateChanged(next) => {
                    return Err(DebugHostClientError::UnexpectedUnsolicitedState {
                        state: next.kind(),
                    });
                }
                _ => return Err(DebugHostClientError::UnexpectedUnsolicitedEvent),
            };
            if event.state != Some(next.state_token()) {
                return Err(DebugHostClientError::UnexpectedEventState {
                    expected: next.state_token(),
                    actual: event.state,
                });
            }
            events.push(event);
        }

        // Replay the complete decoded batch through the exact reducer contract
        // in one transaction. Protocol successor validation alone is too broad:
        // it also admits correlated stopped-token refreshes that are not valid
        // unsolicited observations.
        session
            .reducer
            .apply_unsolicited_observations(events.iter().map(|event| {
                let DebugEvent::StateChanged(next) = &event.event else {
                    unreachable!("unsolicited events were restricted above")
                };
                next
            }))
            .map_err(|error| match error {
                UnsolicitedObservationError::Reducer(error) => {
                    DebugHostClientError::SessionMachine(error)
                }
                UnsolicitedObservationError::StateMismatch { expected, actual } => {
                    DebugHostClientError::ReducerStateMismatch { expected, actual }
                }
            })?;
        session.verified_state = session.reducer.state().clone();
        self.next_inbound_frame_sequence = next_inbound_frame_sequence;
        self.event_cursor = event_cursor;
        invalidate_binding_for_state(session);
        Ok(events)
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
            validate_post_rejection_event(
                command_id,
                &event.event,
                evidence.sandbox_rejection_diagnostic.as_ref(),
            )?;
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
                    if matches!(state, SessionState::Failed { .. }) {
                        require_unique_evidence(
                            &mut evidence.failure_state_observed,
                            "sandbox-failure-state",
                        )?;
                    }
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
                DebugEvent::LiveTargetBound { binding, .. } => {
                    accept_live_target_binding(
                        envelope,
                        &session.reducer,
                        &mut session.live_target_binding,
                        binding,
                        &mut evidence,
                    )?;
                }
                DebugEvent::SandboxAttested(actual) => {
                    if !is_sandboxed_open(&envelope.command) {
                        return Err(DebugHostClientError::UnexpectedCommandEvidence {
                            command_id,
                            evidence: "sandbox-attestation",
                        });
                    }
                    require_command_state_before_sandbox_evidence(envelope, &evidence)?;
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
                            persistence: expected_persistence,
                        } => {
                            stop == expected_stop
                                && breakpoint == expected_breakpoint
                                && *change
                                    == (BreakpointChange::Set {
                                        persistence: *expected_persistence,
                                    })
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
                match classify_rejected_response(envelope, &session.reducer, &evidence)? {
                    RejectedResponseDisposition::RollBack => {
                        session
                            .reducer
                            .reject_remote_command(checkpoint, command_id)?;
                        if session.reducer.state() != &session.verified_state {
                            return Err(DebugHostClientError::ReducerStateMismatch {
                                expected: session.verified_state.clone(),
                                actual: session.reducer.state().clone(),
                            });
                        }
                    }
                    RejectedResponseDisposition::RetainCleanupRequiredFailure => {
                        session
                            .reducer
                            .commit_remote_command(checkpoint, command_id)?;
                        session.verified_state = session.reducer.state().clone();
                        session.sandbox_cleanup_verified = false;
                        invalidate_binding_for_state(session);
                    }
                }
            }
            CommandOutcome::Succeeded => {
                if evidence.sandbox_rejection_diagnostic.is_some() {
                    return Err(DebugHostClientError::UnexpectedCommandEvidence {
                        command_id,
                        evidence: "sandbox-rejection-diagnostic",
                    });
                }
                if required_command_state.is_some() && !evidence.command_state_observed {
                    return Err(DebugHostClientError::MissingCommandState { command_id });
                }
                validate_success_evidence(envelope, &session.reducer, &evidence)?;
                let cleanup_verified = session.reducer.requires_cleanup_receipt()
                    && session.reducer.state().kind() == SessionStateKind::Closed
                    && evidence.cleanup_receipt.is_some();
                session
                    .reducer
                    .commit_remote_command(checkpoint, command_id)?;
                session.verified_state = session.reducer.state().clone();
                session.sandbox_cleanup_verified |= cleanup_verified;
                invalidate_binding_for_state(session);
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

    fn abort_transport(&mut self, reason: ControlShutdownReason) {
        if !self.transport_shutdown {
            self.transport.abort_control(reason);
            self.transport_shutdown = true;
        }
    }

    fn invalidate_live_target_binding(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.live_target_binding = None;
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
            self.transport.abort_control(reason);
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

fn accept_live_target_binding(
    envelope: &CommandEnvelope,
    reducer: &SessionMachine,
    current: &mut Option<LiveTargetBinding>,
    binding: &LiveTargetBinding,
    evidence: &mut ResponseEvidence,
) -> Result<(), DebugHostClientError> {
    let DebugCommand::Open(request) = &envelope.command else {
        return Err(DebugHostClientError::UnexpectedCommandEvidence {
            command_id: envelope.command_id,
            evidence: "live-target-binding",
        });
    };
    if reducer.target() != Some(request) {
        return Err(DebugHostClientError::UnexpectedCommandEvidence {
            command_id: envelope.command_id,
            evidence: "live-target-binding",
        });
    }
    if !evidence.command_state_observed {
        return Err(DebugHostClientError::LiveTargetBindingBeforeOpenState {
            command_id: envelope.command_id,
        });
    }
    match request {
        DebugTargetRequest::Attach(target) if target.mode == crate::protocol::AttachMode::Debug => {
            let expected = match &target.scope {
                crate::protocol::AttachScope::Host { process, .. }
                | crate::protocol::AttachScope::OwnedSandbox { process, .. } => process,
            };
            require_live_target_process(binding, expected)?;
        }
        DebugTargetRequest::Launch(target) => {
            if binding.main_module_binary_id() != &target.binary_id {
                return Err(DebugHostClientError::LiveTargetBinaryMismatch {
                    expected: target.binary_id.clone(),
                    actual: binding.main_module_binary_id().clone(),
                });
            }
            if matches!(
                &target.environment,
                crate::protocol::LaunchEnvironment::Sandboxed { .. }
            ) {
                if !evidence.attestation_accepted {
                    return Err(
                        DebugHostClientError::LiveTargetBindingBeforeSandboxAttestation {
                            command_id: envelope.command_id,
                        },
                    );
                }
                let attested = reducer.accepted_sandbox_attestation().ok_or(
                    DebugHostClientError::LiveTargetBindingBeforeSandboxAttestation {
                        command_id: envelope.command_id,
                    },
                )?;
                require_live_target_process(binding, &attested.process)?;
            }
        }
        DebugTargetRequest::Attach(_)
        | DebugTargetRequest::Dump(_)
        | DebugTargetRequest::Offline(_) => {
            return Err(DebugHostClientError::UnexpectedCommandEvidence {
                command_id: envelope.command_id,
                evidence: "live-target-binding",
            });
        }
    }
    if let Some(existing) = current.as_ref() {
        if existing == binding {
            return Err(DebugHostClientError::DuplicateLiveTargetBinding);
        }
        *current = None;
        return Err(DebugHostClientError::ReplacedLiveTargetBinding);
    }
    require_unique_evidence(&mut evidence.live_target_bound, "live-target-binding")?;
    *current = Some(binding.clone());
    Ok(())
}

fn require_live_target_process(
    binding: &LiveTargetBinding,
    expected: &ProcessIdentity,
) -> Result<(), DebugHostClientError> {
    if binding.process() == expected {
        Ok(())
    } else {
        Err(DebugHostClientError::LiveTargetProcessMismatch {
            expected: expected.clone(),
            actual: binding.process().clone(),
        })
    }
}

fn invalidate_binding_for_state(session: &mut ClientSession) {
    if !matches!(
        session.verified_state.kind(),
        SessionStateKind::Stopped | SessionStateKind::Running | SessionStateKind::Pausing
    ) {
        session.live_target_binding = None;
    }
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
        SessionState::AwaitingAttestation { process, .. } => {
            reducer.target_created_suspended(process.clone())?;
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
    match reducer.accept_sandbox_attestation(actual) {
        Ok(_) => {}
        Err(SessionMachineError::Sandbox(SandboxMachineError::Attestation(error))) => {
            return Err(DebugHostClientError::Attestation(error));
        }
        Err(error) => return Err(DebugHostClientError::SessionMachine(error)),
    }
    evidence.sandbox_event = true;
    Ok(())
}

fn validate_post_rejection_event(
    command_id: CommandId,
    event: &DebugEvent,
    diagnostic: Option<&SandboxRejectionDiagnostic>,
) -> Result<(), DebugHostClientError> {
    let Some(diagnostic) = diagnostic else {
        return Ok(());
    };
    let allowed = match event {
        DebugEvent::CommandResult { .. } | DebugEvent::Warning { .. } => true,
        DebugEvent::StateChanged(SessionState::Failed { message, .. }) => match diagnostic {
            SandboxRejectionDiagnostic::Failed { failure, .. }
                if !is_rollback_safe_failure_stage(failure.stage) =>
            {
                message.as_str() == failure.detail.as_str()
            }
            SandboxRejectionDiagnostic::ProviderUnavailable
            | SandboxRejectionDiagnostic::Failed { .. } => false,
        },
        // Let duplicate rejection diagnostics reach their specific uniqueness
        // checks. No other lifecycle or operation evidence is valid after a
        // rejection diagnostic.
        DebugEvent::SandboxLifecycle(
            SandboxLifecycleEvent::ProviderUnavailable(_)
            | SandboxLifecycleEvent::Failed(_)
            | SandboxLifecycleEvent::CleanupAttemptFailed(_),
        ) => true,
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(DebugHostClientError::UnexpectedCommandEvidence {
            command_id,
            evidence: "evidence-after-sandbox-rejection",
        })
    }
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
    match lifecycle {
        SandboxLifecycleEvent::State { session_id, state } => {
            require_command_state_before_sandbox_evidence(envelope, evidence)?;
            require_sandbox_session(reducer, *session_id)?;
            if evidence.sandbox_states.contains(state) {
                return Err(DebugHostClientError::DuplicateCommandEvidence {
                    evidence: "sandbox-lifecycle-state",
                });
            }
            if reducer.sandbox_state() != Some(*state) {
                return Err(DebugHostClientError::UnexpectedSandboxLifecycleState {
                    expected: reducer.sandbox_state(),
                    actual: *state,
                });
            }
            evidence.sandbox_states.push(*state);
            evidence.sandbox_event = true;
        }
        SandboxLifecycleEvent::Attested(actual) => {
            require_command_state_before_sandbox_evidence(envelope, evidence)?;
            accept_attestation_event(reducer, actual, evidence)?;
        }
        SandboxLifecycleEvent::ProviderUnavailable(unavailable) => {
            require_sandbox_session(reducer, unavailable.session_id)?;
            let expected_provider = expected_sandbox_provider(reducer)
                .ok_or(DebugHostClientError::UnexpectedSandboxEvidence)?;
            if &unavailable.provider != expected_provider {
                return Err(DebugHostClientError::UnexpectedSandboxProvider);
            }
            if evidence.command_state_observed || evidence.has_effect() {
                return Err(DebugHostClientError::UnexpectedCommandEvidence {
                    command_id: envelope.command_id,
                    evidence: "sandbox-failure-phase",
                });
            }
            observe_sandbox_rejection_diagnostic(
                evidence,
                SandboxRejectionDiagnostic::ProviderUnavailable,
            )?;
        }
        SandboxLifecycleEvent::Failed(failure) => {
            reducer.validate_sandbox_failure(failure)?;
            validate_sandbox_failure_phase(envelope, reducer, failure, evidence, false)?;
            reducer.retain_sandbox_failure_target_creation(failure)?;
            observe_sandbox_rejection_diagnostic(
                evidence,
                SandboxRejectionDiagnostic::Failed {
                    failure: failure.clone(),
                    cleanup_attempt: false,
                },
            )?;
        }
        SandboxLifecycleEvent::CleanupAttemptFailed(attempt) => {
            attempt.validate()?;
            if evidence.cleanup_receipt.is_some() || evidence.incomplete_cleanup_receipt.is_some() {
                return Err(DebugHostClientError::DuplicateCommandEvidence {
                    evidence: "sandbox-cleanup-evidence",
                });
            }
            preserve_cleanup_error(reducer.validate_cleanup_attempt_receipt(&attempt.receipt))?;
            reducer.validate_sandbox_failure(&attempt.failure)?;
            validate_sandbox_failure_phase(envelope, reducer, &attempt.failure, evidence, true)?;
            reducer.retain_sandbox_failure_target_creation(&attempt.failure)?;
            observe_sandbox_rejection_diagnostic(
                evidence,
                SandboxRejectionDiagnostic::Failed {
                    failure: attempt.failure.clone(),
                    cleanup_attempt: true,
                },
            )?;
            evidence.incomplete_cleanup_receipt = Some(attempt.receipt.clone());
            evidence.sandbox_event = true;
        }
        SandboxLifecycleEvent::Closed(receipt) => {
            require_command_state_before_sandbox_evidence(envelope, evidence)?;
            require_sandbox_session(reducer, receipt.session_id)?;
            if reducer.state().kind() != SessionStateKind::Closing {
                return Err(DebugHostClientError::CleanupReceiptOutsideClose);
            }
            if evidence.cleanup_receipt.is_some() || evidence.incomplete_cleanup_receipt.is_some() {
                return Err(DebugHostClientError::DuplicateCommandEvidence {
                    evidence: "sandbox-cleanup-evidence",
                });
            }
            preserve_cleanup_error(reducer.validate_cleanup_receipt(receipt))?;
            evidence.cleanup_receipt = Some(receipt.clone());
            evidence.sandbox_event = true;
        }
    }
    Ok(())
}

fn preserve_cleanup_error(
    result: Result<(), SessionMachineError>,
) -> Result<(), DebugHostClientError> {
    match result {
        Ok(()) => Ok(()),
        Err(SessionMachineError::Sandbox(SandboxMachineError::Cleanup(error))) => {
            Err(DebugHostClientError::CleanupReceipt(error))
        }
        Err(error) => Err(DebugHostClientError::SessionMachine(error)),
    }
}

fn require_command_state_before_sandbox_evidence(
    envelope: &CommandEnvelope,
    evidence: &ResponseEvidence,
) -> Result<(), DebugHostClientError> {
    if evidence.command_state_observed {
        Ok(())
    } else {
        Err(DebugHostClientError::UnexpectedCommandEvidence {
            command_id: envelope.command_id,
            evidence: "sandbox-evidence-before-command-state",
        })
    }
}

fn observe_sandbox_rejection_diagnostic(
    evidence: &mut ResponseEvidence,
    diagnostic: SandboxRejectionDiagnostic,
) -> Result<(), DebugHostClientError> {
    if evidence.sandbox_rejection_diagnostic.is_some() {
        Err(DebugHostClientError::DuplicateCommandEvidence {
            evidence: "sandbox-rejection-diagnostic",
        })
    } else {
        evidence.sandbox_rejection_diagnostic = Some(diagnostic);
        Ok(())
    }
}

fn expected_sandbox_provider(reducer: &SessionMachine) -> Option<&SandboxProviderSelection> {
    reducer
        .expected_attestation()
        .map(|expected| &expected.provider)
        .or_else(|| {
            reducer
                .inherited_sandbox()
                .map(|binding| binding.provider())
        })
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

fn is_inherited_sandbox_open(command: &DebugCommand) -> bool {
    matches!(
        command,
        DebugCommand::Open(DebugTargetRequest::Attach(crate::protocol::AttachTarget {
            scope: crate::protocol::AttachScope::OwnedSandbox { .. },
            ..
        }))
    )
}

fn is_rollback_safe_failure_stage(stage: SandboxFailureStage) -> bool {
    matches!(
        stage,
        SandboxFailureStage::Policy | SandboxFailureStage::Discovery
    )
}

fn command_allows_failure_stage(command: &DebugCommand, stage: SandboxFailureStage) -> bool {
    match command {
        DebugCommand::Open(_) if is_sandboxed_open(command) => {
            !matches!(stage, SandboxFailureStage::Cleanup)
        }
        DebugCommand::Open(_) if is_inherited_sandbox_open(command) => {
            matches!(stage, SandboxFailureStage::Runtime)
        }
        DebugCommand::Continue { .. }
        | DebugCommand::Pause { .. }
        | DebugCommand::Step { .. }
        | DebugCommand::Terminate { .. } => matches!(stage, SandboxFailureStage::Runtime),
        DebugCommand::ProbeCapabilities
        | DebugCommand::Open(_)
        | DebugCommand::ReadMemory { .. }
        | DebugCommand::WriteMemory { .. }
        | DebugCommand::SetBreakpoint { .. }
        | DebugCommand::RemoveBreakpoint { .. }
        | DebugCommand::CaptureSnapshot { .. }
        | DebugCommand::Detach { .. }
        | DebugCommand::Close { .. } => false,
    }
}

fn validate_sandbox_failure_phase(
    envelope: &CommandEnvelope,
    reducer: &SessionMachine,
    failure: &SandboxFailure,
    evidence: &ResponseEvidence,
    cleanup_attempt: bool,
) -> Result<(), DebugHostClientError> {
    let rollback_safe = is_rollback_safe_failure_stage(failure.stage);
    let ordering_valid = if rollback_safe {
        !cleanup_attempt && !evidence.command_state_observed && !evidence.has_effect()
    } else {
        evidence.command_state_observed
    };
    let state = reducer.state().kind();
    let sandbox_state = reducer.sandbox_state();
    let inherited = reducer.inherited_sandbox().is_some();
    let provisioned_or_inherited = |provisioned| provisioned || inherited;
    let phase_valid = match failure.stage {
        SandboxFailureStage::Policy | SandboxFailureStage::Discovery => {
            is_sandboxed_open(&envelope.command)
                && state == SessionStateKind::Opening
                && sandbox_state == Some(SandboxLifecycleState::Provisioning)
                && !evidence.attestation_accepted
        }
        SandboxFailureStage::Provisioning => {
            !cleanup_attempt
                && is_sandboxed_open(&envelope.command)
                && state == SessionStateKind::Opening
                && sandbox_state == Some(SandboxLifecycleState::Provisioning)
                && !evidence.attestation_accepted
        }
        SandboxFailureStage::Attestation => {
            !cleanup_attempt
                && is_sandboxed_open(&envelope.command)
                && state == SessionStateKind::AwaitingAttestation
                && sandbox_state == Some(SandboxLifecycleState::TargetCreatedSuspended)
                && !evidence.attestation_accepted
        }
        SandboxFailureStage::Launch => {
            let launch_phase = matches!(
                (state, sandbox_state),
                (
                    SessionStateKind::Opening,
                    Some(SandboxLifecycleState::Provisioning)
                ) | (
                    SessionStateKind::AttestationAccepted,
                    Some(SandboxLifecycleState::AttestationAccepted)
                )
            );
            let attestation_coherent =
                evidence.attestation_accepted == (state == SessionStateKind::AttestationAccepted);
            !cleanup_attempt
                && is_sandboxed_open(&envelope.command)
                && launch_phase
                && attestation_coherent
        }
        SandboxFailureStage::Runtime => {
            let operation_phase = match &envelope.command {
                DebugCommand::Open(_) if is_sandboxed_open(&envelope.command) => {
                    state == SessionStateKind::AttestationAccepted
                        && sandbox_state == Some(SandboxLifecycleState::AttestationAccepted)
                        && evidence.attestation_accepted
                }
                DebugCommand::Open(_) if is_inherited_sandbox_open(&envelope.command) => {
                    state == SessionStateKind::Opening
                        && inherited
                        && sandbox_state.is_none()
                        && !evidence.attestation_accepted
                }
                DebugCommand::Continue { .. } | DebugCommand::Step { .. } => {
                    state == SessionStateKind::Running
                        && provisioned_or_inherited(
                            sandbox_state == Some(SandboxLifecycleState::Running),
                        )
                        && !evidence.attestation_accepted
                }
                DebugCommand::Pause { .. } => {
                    state == SessionStateKind::Pausing
                        && provisioned_or_inherited(
                            sandbox_state == Some(SandboxLifecycleState::Running),
                        )
                        && !evidence.attestation_accepted
                }
                DebugCommand::Terminate { .. } => {
                    state == SessionStateKind::Closing
                        && provisioned_or_inherited(
                            sandbox_state == Some(SandboxLifecycleState::Cleanup),
                        )
                        && !evidence.attestation_accepted
                }
                _ => false,
            };
            !cleanup_attempt && operation_phase
        }
        SandboxFailureStage::Cleanup => {
            cleanup_attempt
                && matches!(
                    &envelope.command,
                    DebugCommand::Terminate { .. } | DebugCommand::Close { .. }
                )
                && state == SessionStateKind::Closing
                && provisioned_or_inherited(sandbox_state == Some(SandboxLifecycleState::Cleanup))
                && !evidence.attestation_accepted
        }
    };
    let command_valid = if cleanup_attempt {
        failure.stage == SandboxFailureStage::Cleanup
            && matches!(
                &envelope.command,
                DebugCommand::Terminate { .. } | DebugCommand::Close { .. }
            )
    } else {
        command_allows_failure_stage(&envelope.command, failure.stage)
    };
    if ordering_valid && phase_valid && command_valid {
        Ok(())
    } else {
        Err(DebugHostClientError::UnexpectedCommandEvidence {
            command_id: envelope.command_id,
            evidence: "sandbox-failure-phase",
        })
    }
}

fn command_allows_sandbox_lifecycle(
    command: &DebugCommand,
    lifecycle: &SandboxLifecycleEvent,
) -> bool {
    match lifecycle {
        SandboxLifecycleEvent::Attested(_) | SandboxLifecycleEvent::ProviderUnavailable(_) => {
            is_sandboxed_open(command)
        }
        SandboxLifecycleEvent::CleanupAttemptFailed(_) | SandboxLifecycleEvent::Closed(_) => {
            matches!(
                command,
                DebugCommand::Terminate { .. } | DebugCommand::Close { .. }
            )
        }
        SandboxLifecycleEvent::Failed(failure) => {
            command_allows_failure_stage(command, failure.stage)
        }
        SandboxLifecycleEvent::State { .. } => matches!(
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

fn classify_rejected_response(
    envelope: &CommandEnvelope,
    reducer: &SessionMachine,
    evidence: &ResponseEvidence,
) -> Result<RejectedResponseDisposition, DebugHostClientError> {
    let invalid = || DebugHostClientError::RejectedCommandProducedEvidence {
        command_id: envelope.command_id,
    };
    match &evidence.sandbox_rejection_diagnostic {
        None => {
            if evidence.has_effect() {
                Err(invalid())
            } else {
                Ok(RejectedResponseDisposition::RollBack)
            }
        }
        Some(SandboxRejectionDiagnostic::ProviderUnavailable) => {
            if is_sandboxed_open(&envelope.command)
                && !evidence.command_state_observed
                && !evidence.has_effect()
            {
                Ok(RejectedResponseDisposition::RollBack)
            } else {
                Err(invalid())
            }
        }
        Some(SandboxRejectionDiagnostic::Failed {
            failure,
            cleanup_attempt,
        }) if is_rollback_safe_failure_stage(failure.stage) => {
            if !cleanup_attempt
                && is_sandboxed_open(&envelope.command)
                && !evidence.command_state_observed
                && !evidence.has_effect()
            {
                Ok(RejectedResponseDisposition::RollBack)
            } else {
                Err(invalid())
            }
        }
        Some(SandboxRejectionDiagnostic::Failed {
            failure,
            cleanup_attempt,
        }) => {
            let exact_failed_state = matches!(
                reducer.state(),
                SessionState::Failed { message, .. }
                    if message.as_str() == failure.detail.as_str()
            );
            let cleanup_state_preserved = reducer.sandbox_state()
                == Some(SandboxLifecycleState::Cleanup)
                || reducer.inherited_sandbox().is_some();
            let cleanup_required = reducer.requires_cleanup_receipt() && cleanup_state_preserved;
            let incomplete_receipt_exact = if *cleanup_attempt {
                failure.stage == SandboxFailureStage::Cleanup
                    && evidence.incomplete_cleanup_receipt.is_some()
            } else {
                failure.stage != SandboxFailureStage::Cleanup
                    && evidence.incomplete_cleanup_receipt.is_none()
            };
            if evidence.state_changed
                && evidence.command_state_observed
                && evidence.failure_state_observed
                && exact_failed_state
                && cleanup_required
                && evidence.cleanup_receipt.is_none()
                && incomplete_receipt_exact
                && !evidence.memory_read
                && !evidence.memory_written
                && !evidence.breakpoint_changed
                && !evidence.live_target_bound
            {
                Ok(RejectedResponseDisposition::RetainCleanupRequiredFailure)
            } else {
                Err(invalid())
            }
        }
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
                && (!reducer.requires_cleanup_receipt() || evidence.cleanup_receipt.is_some())
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
    if !evidence.live_target_bound {
        let binding_command = match &envelope.command {
            DebugCommand::Open(DebugTargetRequest::Attach(crate::protocol::AttachTarget {
                mode: crate::protocol::AttachMode::Debug,
                ..
            })) => Some("debug-attach-binding"),
            DebugCommand::Open(DebugTargetRequest::Launch(crate::protocol::LaunchTarget {
                environment: crate::protocol::LaunchEnvironment::Host { .. },
                ..
            })) => Some("host-launch-binding"),
            DebugCommand::Open(DebugTargetRequest::Launch(crate::protocol::LaunchTarget {
                environment: crate::protocol::LaunchEnvironment::Sandboxed { .. },
                ..
            })) => Some("sandboxed-launch-binding"),
            _ => None,
        };
        if let Some(command) = binding_command {
            return Err(DebugHostClientError::MissingCommandEvidence {
                command_id,
                command,
                final_state,
            });
        }
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
    #[error(transparent)]
    CleanupAttemptFailure(#[from] CleanupAttemptFailureError),
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
    #[error("unsolicited host event carried command correlation {command_id:?}")]
    UnsolicitedEventCarriedCorrelation { command_id: CommandId },
    #[error("transport returned an empty unsolicited event batch instead of a poll timeout")]
    EmptyUnsolicitedEventBatch,
    #[error("unsolicited host event carried unsupported session state {state:?}")]
    UnexpectedUnsolicitedState { state: SessionStateKind },
    #[error("unsolicited host batch carried a non-state event")]
    UnexpectedUnsolicitedEvent,
    #[error("unsolicited host event followed correlated response frames for {command_id:?}")]
    UnsolicitedEventAfterCorrelatedResponse { command_id: CommandId },
    #[error("pending unsolicited event queue length overflow")]
    PendingUnsolicitedEventQueueOverflow,
    #[error("pending unsolicited event queue would contain {actual} events; maximum is {maximum}")]
    PendingUnsolicitedEventQueueFull { actual: usize, maximum: usize },
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
    #[error("live target binding arrived before the target opening state for {command_id:?}")]
    LiveTargetBindingBeforeOpenState { command_id: CommandId },
    #[error(
        "sandbox live target binding arrived before exact process attestation for {command_id:?}"
    )]
    LiveTargetBindingBeforeSandboxAttestation { command_id: CommandId },
    #[error("live target binding main-module identity differs from the exact launch binary")]
    LiveTargetBinaryMismatch {
        expected: BinaryId,
        actual: BinaryId,
    },
    #[error("live target binding process differs from the exact target process")]
    LiveTargetProcessMismatch {
        expected: ProcessIdentity,
        actual: ProcessIdentity,
    },
    #[error("host returned the same live target binding more than once")]
    DuplicateLiveTargetBinding,
    #[error("host attempted to replace an accepted live target binding")]
    ReplacedLiveTargetBinding,
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
    #[error("incomplete sandbox cleanup-attempt receipt arrived outside a close operation")]
    CleanupAttemptReceiptOutsideClose,
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
            statuses: DebugCapability::ALL.into_iter().map(unavailable).collect(),
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

    fn abort_control(&mut self, _reason: ControlShutdownReason) {
        self.disconnected = true;
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
    use std::collections::{BTreeSet, VecDeque};
    use std::path::PathBuf;
    use std::rc::Rc;

    use resymbol_core::BinaryId;

    use super::*;
    use crate::authorization::{
        HostLaunchIntent, HostRiskLease, HostRiskOperation, SandboxOwnershipBinding,
        SandboxOwnershipVerifier,
    };
    use crate::host_response::{MAX_RESPONSE_BYTES, MAX_RESPONSE_FRAME_BYTES};
    use crate::host_wire::{ControlBody, FrameHeader, MessageKind};
    use crate::identity::{HostRiskLeaseId, SandboxOwnershipLeaseId};
    use crate::protocol::{
        AttachMode, AttachScope, AttachTarget, BreakpointId, BreakpointKind, BreakpointPersistence,
        BreakpointScope, BreakpointSpec, ExecutionToken, LaunchEnvironment, LaunchTarget,
        MAX_MEMORY_READ_BYTES, MemoryAddress, OfflineTarget, ProcessId, ProcessIdentity,
        ProcessStartKey, ReadViewToken, RunId, RunToken, StateGeneration, StepKind, StopId,
        StopReason, StopToken, ThreadId,
    };
    use crate::sandbox::{
        ChildProcessProfile, CleanupOutcome, CleanupReceiptId, CleanupResidual,
        CleanupResidualKind, DynamicCodeProfile, ExpectedSandboxAttestation, IsolationBoundary,
        PolicyDigest, ProcessMitigationProfile, ProviderUnavailable, ProviderUnavailableReason,
        SandboxCleanupAttemptFailure, SandboxFailure, SandboxFailureContext, SandboxFailureKind,
        SandboxFailureValidationError, SandboxGuarantee, SandboxNetworkMode, SandboxPolicy,
        SandboxPolicyApprovalId, SandboxProviderSelection, SandboxResourceLimits,
        SandboxTargetCreationOutcome, Win32kProfile,
    };

    const TEST_SANDBOX_FAILURE_DETAIL: &str = "sandbox helper failed with cleanup still required";

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

    fn async_process() -> ProcessIdentity {
        ProcessIdentity {
            process_id: ProcessId::new(4_242).expect("process id"),
            start_key: ProcessStartKey::new(7_777).expect("process start key"),
            binary_id: BinaryId::digest(b"async host-client fixture"),
        }
    }

    fn async_state_frame(
        frame_sequence: u64,
        event_sequence: u64,
        state: SessionState,
        caused_by: Option<CommandId>,
    ) -> HostFrame {
        let envelope = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(event_sequence).expect("event sequence"),
            session_id: Some(state.state_token().session_id),
            state: Some(state.state_token()),
            caused_by,
            event: DebugEvent::StateChanged(state),
        };
        encode_event_frame(
            FrameSequence::new(frame_sequence).expect("frame sequence"),
            &envelope,
        )
        .expect("async event frame")
    }

    fn async_event_frame(
        frame_sequence: u64,
        event_sequence: u64,
        state: StateToken,
        event: DebugEvent,
    ) -> HostFrame {
        let envelope = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(event_sequence).expect("event sequence"),
            session_id: Some(state.session_id),
            state: Some(state),
            caused_by: None,
            event,
        };
        encode_event_frame(
            FrameSequence::new(frame_sequence).expect("frame sequence"),
            &envelope,
        )
        .expect("async event frame")
    }

    fn correlated_event_frame(
        frame_sequence: u64,
        event_sequence: u64,
        command_id: CommandId,
        state: StateToken,
        event: DebugEvent,
    ) -> HostFrame {
        let envelope = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(event_sequence).expect("event sequence"),
            session_id: Some(state.session_id),
            state: Some(state),
            caused_by: Some(command_id),
            event,
        };
        encode_event_frame(
            FrameSequence::new(frame_sequence).expect("frame sequence"),
            &envelope,
        )
        .expect("correlated event frame")
    }

    fn with_legacy_typed_minor(frame: HostFrame) -> HostFrame {
        let (mut header, raw) = frame.into_parts();
        let ControlBody::Bytes(control) = &mut header.body else {
            panic!("typed event control must be opaque bytes")
        };
        let current = format!("\"minor\":{}", crate::protocol::PROTOCOL_MINOR);
        let legacy = format!("\"minor\":{}", crate::protocol::PROTOCOL_MINOR - 1);
        let json = String::from_utf8(std::mem::take(control)).expect("JSON control bytes");
        assert!(json.contains(&current));
        *control = json.replacen(&current, &legacy, 1).into_bytes();
        HostFrame::new(header, raw).expect("same-length typed-version mutation")
    }

    fn async_live_binding() -> LiveTargetBinding {
        let process = async_process();
        LiveTargetBinding::new(
            process.clone(),
            process.binary_id.clone(),
            MemoryAddress::new(0x0000_7ff6_8000_0000),
            0x4_0000,
        )
        .expect("async live binding")
    }

    fn running_async_client(inbound: Vec<Vec<HostFrame>>) -> DebugHostClient<AsyncQueueHost> {
        let client = DebugHostClient::connect(
            AsyncQueueHost::new(inbound),
            [0x6d; 16],
            "controller/build-7",
            "host/build-4",
        )
        .expect("connect async test host");
        prime_running_client(client)
    }

    fn prime_running_client<T: HostFrameExchange>(
        mut client: DebugHostClient<T>,
    ) -> DebugHostClient<T> {
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .expect("begin async test session");

        let process = async_process();
        let risk_id = HostRiskLeaseId::new("a".repeat(64)).expect("host-risk id");
        let operation = HostRiskOperation::Attach {
            process: process.clone(),
            mode: AttachMode::Debug,
        };
        client
            .register_host_risk_verifier(HostRiskVerifier::new(
                risk_id.clone(),
                session_id(),
                provisioning_epoch(),
                operation,
            ))
            .expect("register controller verifier");

        // Prime only the controller's pure reducer. The synthetic transport
        // still performs no process operation and makes no live-host claim.
        let idle = client
            .session_state()
            .expect("idle session state")
            .state_token();
        let open = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(1).expect("open command id"),
            session_id: Some(session_id()),
            expected_state: Some(idle),
            command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                scope: AttachScope::Host {
                    process,
                    risk_lease: risk_id,
                },
                mode: AttachMode::Debug,
            })),
        };
        let session = client.session.as_mut().expect("client session");
        session
            .reducer
            .accept_command(&open)
            .expect("accept synthetic attach");
        let stopped = session
            .reducer
            .mark_stopped(
                StopReason::Initial,
                ThreadId::new(9).expect("initial thread id"),
            )
            .expect("mark initial stop")
            .clone();
        let SessionState::Stopped { token, .. } = stopped else {
            panic!("attach did not produce a stopped state");
        };
        let continue_command = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(2).expect("continue command id"),
            session_id: Some(session_id()),
            expected_state: Some(token.state),
            command: DebugCommand::Continue { stop: token },
        };
        let running = session
            .reducer
            .accept_command(&continue_command)
            .expect("accept synthetic continue")
            .clone();
        assert_eq!(running.kind(), SessionStateKind::Running);
        session.verified_state = running;
        client
    }

    fn next_async_state_token() -> StateToken {
        StateToken {
            session_id: session_id(),
            generation: StateGeneration::new(5).expect("next state generation"),
        }
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

    struct AsyncQueueHost {
        inner: SyntheticDebugHost,
        inbound: VecDeque<Vec<HostFrame>>,
        poll_error: Option<HostTransportError>,
    }

    struct ScriptedExchangeHost {
        inner: SyntheticDebugHost,
        scripted: VecDeque<Vec<HostFrame>>,
        exchanges: usize,
    }

    impl AsyncQueueHost {
        fn new(inbound: Vec<Vec<HostFrame>>) -> Self {
            Self {
                inner: host(),
                inbound: inbound.into(),
                poll_error: None,
            }
        }
    }

    impl ScriptedExchangeHost {
        fn new(scripted: Vec<Vec<HostFrame>>) -> Self {
            Self {
                inner: host(),
                scripted: scripted.into(),
                exchanges: 0,
            }
        }
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

        fn abort_control(&mut self, reason: ControlShutdownReason) {
            self.inner.abort_control(reason);
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

        fn abort_control(&mut self, reason: ControlShutdownReason) {
            self.inner.abort_control(reason);
        }
    }

    impl HostFrameExchange for AsyncQueueHost {
        fn exchange(
            &mut self,
            request: HostFrame,
            limits: HostResponseLimits,
        ) -> Result<HostResponseBatch, HostTransportError> {
            self.inner.exchange(request, limits)
        }

        fn poll_inbound(
            &mut self,
            _wait: HostPollWait,
            limits: HostResponseLimits,
        ) -> Result<Option<HostResponseBatch>, HostTransportError> {
            if let Some(error) = self.poll_error.take() {
                return Err(error);
            }
            let frames = self.inbound.pop_front();
            frames
                .map(|frames| {
                    HostResponseBatch::try_from_frames(frames, limits)
                        .map_err(HostTransportError::from)
                })
                .transpose()
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

        fn abort_control(&mut self, reason: ControlShutdownReason) {
            self.inner.abort_control(reason);
        }
    }

    impl HostFrameExchange for ScriptedExchangeHost {
        fn exchange(
            &mut self,
            request: HostFrame,
            limits: HostResponseLimits,
        ) -> Result<HostResponseBatch, HostTransportError> {
            if self.exchanges == 0 {
                self.exchanges += 1;
                return self.inner.exchange(request, limits);
            }
            self.exchanges += 1;
            let frames = self
                .scripted
                .pop_front()
                .ok_or_else(|| HostTransportError::backend("scripted response exhausted"))?;
            HostResponseBatch::try_from_frames(frames, limits).map_err(HostTransportError::from)
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

        fn abort_control(&mut self, reason: ControlShutdownReason) {
            self.inner.abort_control(reason);
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
        WrongAttestationProcess,
        MissingAttestation,
        MissingCleanup,
        WrongCleanup,
        MissingCleanupProcess,
        WrongCleanupProcess,
        InheritedCleanup,
        WrongInheritedCleanup,
        ProviderUnavailableRejection,
        FailedRejection,
        WrongFailureProvider,
        FailureWithStateEffect,
        ProvisioningFailureThenCleanup,
        RuntimeFailureThenCleanup,
        CleanupFailureWithoutReceipt,
        CleanupFailureThenCleanup,
        WrongCleanupFailureReceipt,
        DuplicateCleanupFailureReceipt,
        CleanupFailureReportedAsSuccess,
        InheritedCleanupFailure,
        WrongInheritedCleanupFailure,
        FailureReportedAsSuccess,
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
                ScriptedAttack::ForgedAttestation
                | ScriptedAttack::WrongAttestationProcess
                | ScriptedAttack::MissingAttestation => {
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
                    let process = test_process_identity(
                        reducer
                            .expected_attestation()
                            .expect("sandbox command creates expectation"),
                    );
                    reducer
                        .target_created_suspended(process)
                        .map_err(machine_error)?;
                    self.push_scripted_event(
                        &mut batch,
                        envelope.command_id,
                        session_id,
                        reducer.state().state_token(),
                        DebugEvent::StateChanged(reducer.state().clone()),
                    )?;
                    let mut attestation = test_attestation(
                        reducer
                            .expected_attestation()
                            .expect("sandbox command creates expectation"),
                    );
                    match self.attack {
                        ScriptedAttack::ForgedAttestation => {
                            attestation.helper_build =
                                HelperBuildId::new("forged-helper-build").expect("forged build id");
                            self.push_scripted_event(
                                &mut batch,
                                envelope.command_id,
                                session_id,
                                reducer.state().state_token(),
                                DebugEvent::SandboxAttested(attestation),
                            )?;
                        }
                        ScriptedAttack::WrongAttestationProcess => {
                            attestation.process.start_key =
                                ProcessStartKey::new(8).expect("wrong process start key");
                            self.push_scripted_event(
                                &mut batch,
                                envelope.command_id,
                                session_id,
                                reducer.state().state_token(),
                                DebugEvent::SandboxAttested(attestation),
                            )?;
                        }
                        ScriptedAttack::MissingAttestation => {
                            self.push_scripted_event(
                                &mut batch,
                                envelope.command_id,
                                session_id,
                                reducer.state().state_token(),
                                DebugEvent::CommandResult {
                                    command_id: envelope.command_id,
                                    outcome: CommandOutcome::Succeeded,
                                },
                            )?;
                        }
                        _ => unreachable!("matched attestation attack"),
                    }
                }
                ScriptedAttack::MissingCleanup
                | ScriptedAttack::WrongCleanup
                | ScriptedAttack::MissingCleanupProcess
                | ScriptedAttack::WrongCleanupProcess
                | ScriptedAttack::InheritedCleanup
                | ScriptedAttack::WrongInheritedCleanup => {
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
                    if matches!(
                        self.attack,
                        ScriptedAttack::WrongCleanup
                            | ScriptedAttack::MissingCleanupProcess
                            | ScriptedAttack::WrongCleanupProcess
                    ) {
                        let mut wrong = test_cleanup_receipt(&expected_sandbox_attestation());
                        match self.attack {
                            ScriptedAttack::WrongCleanup => wrong.handles_closed = false,
                            ScriptedAttack::MissingCleanupProcess => wrong.process = None,
                            ScriptedAttack::WrongCleanupProcess => {
                                wrong.process.as_mut().expect("created process").start_key =
                                    ProcessStartKey::new(8).expect("wrong process start key");
                            }
                            _ => unreachable!("matched cleanup attack"),
                        }
                        self.push_scripted_event(
                            &mut batch,
                            envelope.command_id,
                            session_id,
                            closing_token,
                            DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::Closed(wrong)),
                        )?;
                    } else if matches!(
                        self.attack,
                        ScriptedAttack::InheritedCleanup | ScriptedAttack::WrongInheritedCleanup
                    ) {
                        let mut receipt = inherited_cleanup_receipt(&inherited_binding());
                        if matches!(self.attack, ScriptedAttack::WrongInheritedCleanup) {
                            receipt.process = Some(ProcessIdentity {
                                process_id: ProcessId::new(41).expect("wrong process id"),
                                start_key: ProcessStartKey::new(8).expect("wrong process start"),
                                binary_id: BinaryId::digest(b"different inherited image"),
                            });
                        }
                        self.push_scripted_event(
                            &mut batch,
                            envelope.command_id,
                            session_id,
                            closing_token,
                            DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::Closed(receipt)),
                        )?;
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
                        self.push_scripted_event(
                            &mut batch,
                            envelope.command_id,
                            session_id,
                            next_state_token(prior, 2),
                            DebugEvent::CommandResult {
                                command_id: envelope.command_id,
                                outcome: CommandOutcome::Succeeded,
                            },
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
                ScriptedAttack::ProviderUnavailableRejection
                | ScriptedAttack::FailedRejection
                | ScriptedAttack::WrongFailureProvider
                | ScriptedAttack::FailureWithStateEffect
                | ScriptedAttack::FailureReportedAsSuccess => {
                    let prior = envelope.expected_state.ok_or_else(|| {
                        HostTransportError::protocol("sandbox open omitted prior state")
                    })?;
                    let mut event_state = prior;
                    if matches!(self.attack, ScriptedAttack::FailureWithStateEffect) {
                        let DebugCommand::Open(target) = &envelope.command else {
                            return Err(HostTransportError::protocol(
                                "state-effect script requires sandbox open",
                            ));
                        };
                        event_state = next_state_token(prior, 1);
                        self.push_scripted_event(
                            &mut batch,
                            envelope.command_id,
                            session_id,
                            event_state,
                            DebugEvent::StateChanged(SessionState::Opening {
                                token: event_state,
                                target: target.clone(),
                            }),
                        )?;
                    }
                    let lifecycle = match self.attack {
                        ScriptedAttack::ProviderUnavailableRejection => {
                            SandboxLifecycleEvent::ProviderUnavailable(ProviderUnavailable {
                                session_id,
                                provider: SandboxProviderSelection::LocalAppContainer,
                                reason: ProviderUnavailableReason::FeatureDisabled,
                                retryable: false,
                                detail: DiagnosticText::new(
                                    "Local AppContainer support is disabled",
                                )
                                .expect("bounded provider diagnostic"),
                            })
                        }
                        ScriptedAttack::FailedRejection
                        | ScriptedAttack::FailureWithStateEffect
                        | ScriptedAttack::FailureReportedAsSuccess => test_sandbox_failure(
                            session_id,
                            SandboxProviderSelection::LocalAppContainer,
                            SandboxFailureStage::Discovery,
                        ),
                        ScriptedAttack::WrongFailureProvider => test_sandbox_failure(
                            session_id,
                            SandboxProviderSelection::HyperV,
                            SandboxFailureStage::Discovery,
                        ),
                        ScriptedAttack::ForgedAttestation
                        | ScriptedAttack::WrongAttestationProcess
                        | ScriptedAttack::MissingAttestation
                        | ScriptedAttack::MissingCleanup
                        | ScriptedAttack::WrongCleanup
                        | ScriptedAttack::MissingCleanupProcess
                        | ScriptedAttack::WrongCleanupProcess
                        | ScriptedAttack::InheritedCleanup
                        | ScriptedAttack::WrongInheritedCleanup
                        | ScriptedAttack::ProvisioningFailureThenCleanup
                        | ScriptedAttack::RuntimeFailureThenCleanup
                        | ScriptedAttack::CleanupFailureWithoutReceipt
                        | ScriptedAttack::CleanupFailureThenCleanup
                        | ScriptedAttack::WrongCleanupFailureReceipt
                        | ScriptedAttack::DuplicateCleanupFailureReceipt
                        | ScriptedAttack::CleanupFailureReportedAsSuccess
                        | ScriptedAttack::InheritedCleanupFailure
                        | ScriptedAttack::WrongInheritedCleanupFailure => {
                            unreachable!("handled elsewhere")
                        }
                    };
                    self.push_scripted_event(
                        &mut batch,
                        envelope.command_id,
                        session_id,
                        event_state,
                        DebugEvent::SandboxLifecycle(lifecycle),
                    )?;
                    let outcome = if matches!(self.attack, ScriptedAttack::FailureReportedAsSuccess)
                    {
                        CommandOutcome::Succeeded
                    } else {
                        CommandOutcome::Rejected {
                            code: "sandbox-open-failed".into(),
                            message: "sandbox provider did not open a target".into(),
                        }
                    };
                    self.push_scripted_event(
                        &mut batch,
                        envelope.command_id,
                        session_id,
                        event_state,
                        DebugEvent::CommandResult {
                            command_id: envelope.command_id,
                            outcome,
                        },
                    )?;
                }
                ScriptedAttack::ProvisioningFailureThenCleanup
                | ScriptedAttack::RuntimeFailureThenCleanup
                | ScriptedAttack::CleanupFailureWithoutReceipt
                | ScriptedAttack::CleanupFailureThenCleanup
                | ScriptedAttack::WrongCleanupFailureReceipt
                | ScriptedAttack::DuplicateCleanupFailureReceipt
                | ScriptedAttack::CleanupFailureReportedAsSuccess
                | ScriptedAttack::InheritedCleanupFailure
                | ScriptedAttack::WrongInheritedCleanupFailure => {
                    if matches!(self.attack, ScriptedAttack::CleanupFailureWithoutReceipt) {
                        self.scripted_cleanup_required_failure(
                            &mut batch,
                            envelope,
                            session_id,
                            SandboxFailureStage::Cleanup,
                        )?;
                    } else if matches!(
                        self.attack,
                        ScriptedAttack::CleanupFailureThenCleanup
                            | ScriptedAttack::WrongCleanupFailureReceipt
                            | ScriptedAttack::DuplicateCleanupFailureReceipt
                            | ScriptedAttack::CleanupFailureReportedAsSuccess
                            | ScriptedAttack::InheritedCleanupFailure
                            | ScriptedAttack::WrongInheritedCleanupFailure
                    ) {
                        self.scripted_incomplete_cleanup_attempt(&mut batch, envelope, session_id)?;
                    } else if matches!(&envelope.command, DebugCommand::Close { .. }) {
                        self.scripted_exact_close(&mut batch, envelope, session_id)?;
                    } else {
                        let stage = match self.attack {
                            ScriptedAttack::ProvisioningFailureThenCleanup => {
                                SandboxFailureStage::Provisioning
                            }
                            ScriptedAttack::RuntimeFailureThenCleanup => {
                                SandboxFailureStage::Runtime
                            }
                            ScriptedAttack::CleanupFailureWithoutReceipt => {
                                unreachable!("receipt-free cleanup failure is handled above")
                            }
                            ScriptedAttack::CleanupFailureThenCleanup
                            | ScriptedAttack::WrongCleanupFailureReceipt
                            | ScriptedAttack::DuplicateCleanupFailureReceipt
                            | ScriptedAttack::CleanupFailureReportedAsSuccess => {
                                unreachable!("cleanup attempts are handled above")
                            }
                            ScriptedAttack::InheritedCleanupFailure => {
                                unreachable!("handled as cleanup failure")
                            }
                            ScriptedAttack::WrongInheritedCleanupFailure => {
                                unreachable!("handled as forged cleanup failure")
                            }
                            _ => unreachable!("matched resource-owning failure"),
                        };
                        self.scripted_cleanup_required_failure(
                            &mut batch, envelope, session_id, stage,
                        )?;
                    }
                }
            }
            Ok(batch)
        }

        fn scripted_cleanup_required_failure(
            &mut self,
            batch: &mut Vec<HostFrame>,
            envelope: &CommandEnvelope,
            session_id: SessionId,
            stage: SandboxFailureStage,
        ) -> Result<(), HostTransportError> {
            let mut reducer = reducer_for_scripted_operation(envelope, false)?;
            let operation_state = reducer.state().clone();
            let operation_token = operation_state.state_token();
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                operation_token,
                DebugEvent::StateChanged(operation_state),
            )?;
            if reducer.sandbox_target_creation_outcome().is_none() {
                reducer
                    .record_sandbox_target_not_created()
                    .map_err(machine_error)?;
            }
            let kind = failure_kind_for_stage(stage);
            let failure = reducer
                .bind_sandbox_failure(
                    stage,
                    kind,
                    true,
                    DiagnosticText::new(TEST_SANDBOX_FAILURE_DETAIL)
                        .expect("bounded sandbox failure"),
                )
                .map_err(machine_error)?;
            reducer
                .retain_sandbox_failure_target_creation(&failure)
                .map_err(machine_error)?;
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                operation_token,
                DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::Failed(failure)),
            )?;
            reducer
                .mark_failed(TEST_SANDBOX_FAILURE_DETAIL)
                .map_err(machine_error)?;
            let failed_state = reducer.state().clone();
            let failed_token = failed_state.state_token();
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                failed_token,
                DebugEvent::StateChanged(failed_state),
            )?;
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                failed_token,
                DebugEvent::CommandResult {
                    command_id: envelope.command_id,
                    outcome: CommandOutcome::Rejected {
                        code: "sandbox-cleanup-required".into(),
                        message: "sandbox operation failed and requires cleanup".into(),
                    },
                },
            )
        }

        fn scripted_incomplete_cleanup_attempt(
            &mut self,
            batch: &mut Vec<HostFrame>,
            envelope: &CommandEnvelope,
            session_id: SessionId,
        ) -> Result<(), HostTransportError> {
            if !matches!(
                &envelope.command,
                DebugCommand::Terminate { .. } | DebugCommand::Close { .. }
            ) {
                return Err(HostTransportError::protocol(
                    "cleanup-attempt script requires terminate or close",
                ));
            }
            let inherited = matches!(
                self.attack,
                ScriptedAttack::InheritedCleanupFailure
                    | ScriptedAttack::WrongInheritedCleanupFailure
            );
            let mut reducer = reducer_for_scripted_operation(envelope, inherited)?;
            let closing_state = reducer.state().clone();
            let closing_token = closing_state.state_token();
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                closing_token,
                DebugEvent::StateChanged(closing_state),
            )?;

            let mut cleanup_receipt = if inherited {
                inherited_cleanup_receipt(&inherited_binding())
            } else {
                test_cleanup_receipt(&expected_sandbox_attestation())
            };
            cleanup_receipt = incomplete_cleanup_receipt(cleanup_receipt);
            match self.attack {
                ScriptedAttack::WrongCleanupFailureReceipt => {
                    cleanup_receipt.policy_digest =
                        PolicyDigest::new("4".repeat(64)).expect("forged policy digest");
                }
                ScriptedAttack::WrongInheritedCleanupFailure => {
                    cleanup_receipt.process = Some(ProcessIdentity {
                        process_id: ProcessId::new(40).expect("process id"),
                        start_key: ProcessStartKey::new(8).expect("wrong process start"),
                        binary_id: BinaryId::digest(b"inherited sandbox image"),
                    });
                }
                _ => {}
            }
            let attempt = cleanup_attempt_failure(cleanup_receipt, inherited);
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                closing_token,
                DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::CleanupAttemptFailed(
                    attempt.clone(),
                )),
            )?;
            if matches!(self.attack, ScriptedAttack::DuplicateCleanupFailureReceipt) {
                self.push_scripted_event(
                    batch,
                    envelope.command_id,
                    session_id,
                    closing_token,
                    DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::CleanupAttemptFailed(
                        attempt,
                    )),
                )?;
            }

            reducer
                .mark_failed(TEST_SANDBOX_FAILURE_DETAIL)
                .map_err(machine_error)?;
            let failed_state = reducer.state().clone();
            let failed_token = failed_state.state_token();
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                failed_token,
                DebugEvent::StateChanged(failed_state),
            )?;
            let outcome = if matches!(self.attack, ScriptedAttack::CleanupFailureReportedAsSuccess)
            {
                CommandOutcome::Succeeded
            } else {
                CommandOutcome::Rejected {
                    code: "sandbox-cleanup-incomplete".into(),
                    message: "sandbox cleanup remains incomplete and requires retry".into(),
                }
            };
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                failed_token,
                DebugEvent::CommandResult {
                    command_id: envelope.command_id,
                    outcome,
                },
            )
        }

        fn scripted_exact_close(
            &mut self,
            batch: &mut Vec<HostFrame>,
            envelope: &CommandEnvelope,
            session_id: SessionId,
        ) -> Result<(), HostTransportError> {
            let prior = envelope
                .expected_state
                .ok_or_else(|| HostTransportError::protocol("close omitted prior state"))?;
            let closing_token = next_state_token(prior, 1);
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                closing_token,
                DebugEvent::StateChanged(SessionState::Closing {
                    token: closing_token,
                }),
            )?;
            let mut cleanup = test_cleanup_receipt(&expected_sandbox_attestation());
            if matches!(self.attack, ScriptedAttack::ProvisioningFailureThenCleanup) {
                cleanup.process = None;
            }
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                closing_token,
                DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::Closed(cleanup)),
            )?;
            let closed_token = next_state_token(prior, 2);
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                closed_token,
                DebugEvent::StateChanged(SessionState::Closed {
                    token: closed_token,
                }),
            )?;
            self.push_scripted_event(
                batch,
                envelope.command_id,
                session_id,
                closed_token,
                DebugEvent::CommandResult {
                    command_id: envelope.command_id,
                    outcome: CommandOutcome::Succeeded,
                },
            )
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

    fn failure_kind_for_stage(stage: SandboxFailureStage) -> SandboxFailureKind {
        match stage {
            SandboxFailureStage::Policy => SandboxFailureKind::InvalidPolicy,
            SandboxFailureStage::Discovery => SandboxFailureKind::HelperFailure,
            SandboxFailureStage::Provisioning => SandboxFailureKind::HelperFailure,
            SandboxFailureStage::Attestation => SandboxFailureKind::AttestationRejected,
            SandboxFailureStage::Launch => SandboxFailureKind::LaunchDenied,
            SandboxFailureStage::Runtime => SandboxFailureKind::HelperFailure,
            SandboxFailureStage::Cleanup => SandboxFailureKind::CleanupIncomplete,
        }
    }

    /// Replays the host side of an adversarial operation through the same
    /// reducer API used by the client shadow. Only the emitted evidence is
    /// hostile; operation and failure state tokens are never fabricated.
    fn reducer_for_scripted_operation(
        envelope: &CommandEnvelope,
        inherited: bool,
    ) -> Result<SessionMachine, HostTransportError> {
        let mut reducer = SessionMachine::new(session_id(), provisioning_epoch(), helper_build());
        if inherited {
            let binding = inherited_binding();
            let lease_id = match &envelope.command {
                DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                    scope:
                        AttachScope::OwnedSandbox {
                            ownership_lease, ..
                        },
                    ..
                })) => ownership_lease.clone(),
                _ => SandboxOwnershipLeaseId::new("8".repeat(64)).expect("ownership lease id"),
            };
            reducer
                .register_sandbox_ownership_verifier(SandboxOwnershipVerifier::new(
                    lease_id.clone(),
                    binding.clone(),
                ))
                .map_err(machine_error)?;
            if !is_inherited_sandbox_open(&envelope.command) {
                let initial = reducer.state().state_token();
                reducer
                    .accept_command(&CommandEnvelope {
                        version: ProtocolVersion::current(),
                        command_id: CommandId::new(1).expect("command id"),
                        session_id: Some(session_id()),
                        expected_state: Some(initial),
                        command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                            scope: AttachScope::OwnedSandbox {
                                process: binding.process().clone(),
                                ownership_lease: lease_id,
                            },
                            mode: binding.mode(),
                        })),
                    })
                    .map_err(machine_error)?;
                reducer
                    .complete_open_observing(binding.process().process_id)
                    .map_err(machine_error)?;
            }
        } else if !is_sandboxed_open(&envelope.command) {
            let initial = reducer.state().state_token();
            reducer
                .accept_command(&CommandEnvelope {
                    version: ProtocolVersion::current(),
                    command_id: CommandId::new(1).expect("command id"),
                    session_id: Some(session_id()),
                    expected_state: Some(initial),
                    command: DebugCommand::Open(sandbox_target()),
                })
                .map_err(machine_error)?;
            let process = test_process_identity(
                reducer
                    .expected_attestation()
                    .expect("sandbox expectation exists"),
            );
            reducer
                .target_created_suspended(process)
                .map_err(machine_error)?;
            let attestation = test_attestation(
                reducer
                    .expected_attestation()
                    .expect("sandbox expectation exists"),
            );
            reducer
                .accept_sandbox_attestation(&attestation)
                .map_err(machine_error)?;
            reducer
                .mark_stopped(
                    StopReason::Initial,
                    ThreadId::new(1).expect("test thread id"),
                )
                .map_err(machine_error)?;
        }
        let expected = envelope
            .expected_state
            .ok_or_else(|| HostTransportError::protocol("scripted operation omitted state"))?;
        if reducer.state().state_token() != expected {
            return Err(HostTransportError::protocol(
                "host reducer did not reproduce the operation's prior state",
            ));
        }
        let _checkpoint = reducer
            .begin_remote_command(envelope)
            .map_err(machine_error)?;
        Ok(reducer)
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

        fn release_session(&mut self, actual_session: SessionId) -> Result<(), HostTransportError> {
            if matches!(
                self.attack,
                ScriptedAttack::ProvisioningFailureThenCleanup
                    | ScriptedAttack::RuntimeFailureThenCleanup
                    | ScriptedAttack::InheritedCleanup
            ) && actual_session == session_id()
            {
                Ok(())
            } else {
                Err(HostTransportError::protocol(
                    "adversarial host cannot release a session",
                ))
            }
        }

        fn shutdown_control(
            &mut self,
            _reason: ControlShutdownReason,
        ) -> Result<(), HostTransportError> {
            self.shutdown = true;
            Ok(())
        }

        fn abort_control(&mut self, _reason: ControlShutdownReason) {
            self.shutdown = true;
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

        fn abort_control(&mut self, reason: ControlShutdownReason) {
            self.shutdowns.borrow_mut().push(reason);
            self.inner.abort_control(reason);
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
            process: test_process_identity(expected),
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

    fn test_process_identity(expected: &ExpectedSandboxAttestation) -> ProcessIdentity {
        ProcessIdentity {
            process_id: ProcessId::new(41).expect("sandbox process id"),
            start_key: ProcessStartKey::new(7).expect("sandbox process start key"),
            binary_id: expected.binary_id.clone(),
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
            process: Some(test_process_identity(expected)),
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

    fn incomplete_cleanup_receipt(mut receipt: SandboxCleanupReceipt) -> SandboxCleanupReceipt {
        receipt.outcome = CleanupOutcome::Incomplete;
        receipt.handles_closed = false;
        receipt.residuals.push(CleanupResidual {
            kind: CleanupResidualKind::Handles,
            detail: DiagnosticText::new("one provider handle remains open")
                .expect("bounded cleanup residual"),
        });
        receipt
    }

    fn cleanup_attempt_failure(
        receipt: SandboxCleanupReceipt,
        inherited: bool,
    ) -> SandboxCleanupAttemptFailure {
        let expected = expected_sandbox_attestation();
        let context = if inherited {
            SandboxFailureContext::InheritedAttach {
                process: receipt
                    .process
                    .clone()
                    .expect("inherited cleanup carries a process identity"),
                mode: inherited_binding().mode(),
            }
        } else {
            let target_creation = match receipt.process.clone() {
                Some(process) => SandboxTargetCreationOutcome::Created { process },
                None => SandboxTargetCreationOutcome::NotCreated,
            };
            SandboxFailureContext::Launch {
                binary_id: expected.binary_id,
                helper_build: expected.helper_build,
                target_creation,
            }
        };
        SandboxCleanupAttemptFailure {
            failure: SandboxFailure {
                session_id: receipt.session_id,
                provisioning_epoch: receipt.provisioning_epoch.clone(),
                policy_digest: receipt.policy_digest.clone(),
                provider: receipt.provider.clone(),
                context,
                stage: SandboxFailureStage::Cleanup,
                kind: SandboxFailureKind::CleanupIncomplete,
                retryable: true,
                detail: DiagnosticText::new(TEST_SANDBOX_FAILURE_DETAIL)
                    .expect("bounded sandbox failure"),
            },
            receipt,
        }
    }

    fn inherited_binding() -> SandboxOwnershipBinding {
        SandboxOwnershipBinding::new(
            session_id(),
            ProcessIdentity {
                process_id: ProcessId::new(40).expect("process id"),
                start_key: ProcessStartKey::new(7).expect("process start key"),
                binary_id: BinaryId::digest(b"inherited sandbox image"),
            },
            AttachMode::ObserveReadOnly,
            SandboxProviderSelection::LocalAppContainer,
            PolicyDigest::new("7".repeat(64)).expect("policy digest"),
            provisioning_epoch(),
        )
    }

    fn inherited_cleanup_receipt(binding: &SandboxOwnershipBinding) -> SandboxCleanupReceipt {
        SandboxCleanupReceipt {
            receipt_id: CleanupReceiptId::new("inherited-cleanup-receipt")
                .expect("test receipt id"),
            session_id: binding.session_id(),
            provisioning_epoch: binding.provisioning_epoch().clone(),
            provider: binding.provider().clone(),
            policy_digest: binding.policy_digest().clone(),
            process: Some(binding.process().clone()),
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

    fn test_sandbox_failure(
        session_id: SessionId,
        provider: SandboxProviderSelection,
        stage: SandboxFailureStage,
    ) -> SandboxLifecycleEvent {
        let expected = expected_sandbox_attestation();
        SandboxLifecycleEvent::Failed(SandboxFailure {
            session_id,
            provisioning_epoch: expected.provisioning_epoch,
            policy_digest: expected.policy_digest,
            provider,
            context: SandboxFailureContext::Launch {
                binary_id: expected.binary_id,
                helper_build: expected.helper_build,
                target_creation: SandboxTargetCreationOutcome::NotCreated,
            },
            stage,
            kind: failure_kind_for_stage(stage),
            retryable: true,
            detail: DiagnosticText::new(TEST_SANDBOX_FAILURE_DETAIL)
                .expect("bounded sandbox failure"),
        })
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
            let process = test_process_identity(
                reducer
                    .expected_attestation()
                    .expect("sandbox expectation exists"),
            );
            reducer.target_created_suspended(process).unwrap();
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

    fn prime_inherited_observing(client: &mut DebugHostClient<ScriptedHost>) {
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        let binding = inherited_binding();
        let lease_id = SandboxOwnershipLeaseId::new("8".repeat(64)).expect("ownership lease id");
        let verified_state = {
            let reducer = &mut client
                .session
                .as_mut()
                .expect("test session exists")
                .reducer;
            reducer
                .register_sandbox_ownership_verifier(SandboxOwnershipVerifier::new(
                    lease_id.clone(),
                    binding.clone(),
                ))
                .unwrap();
            let state = reducer.state().state_token();
            let open = CommandEnvelope {
                version: ProtocolVersion::current(),
                command_id: CommandId::new(1).unwrap(),
                session_id: Some(session_id()),
                expected_state: Some(state),
                command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                    scope: AttachScope::OwnedSandbox {
                        process: binding.process().clone(),
                        ownership_lease: lease_id,
                    },
                    mode: binding.mode(),
                })),
            };
            reducer.accept_command(&open).unwrap();
            reducer
                .complete_open_observing(binding.process().process_id)
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

    fn prime_stopped_scripted_exchange_client() -> (DebugHostClient<ScriptedExchangeHost>, StopToken)
    {
        let mut client = DebugHostClient::connect(
            ScriptedExchangeHost::new(Vec::new()),
            [0x6d; 16],
            "controller/build-7",
            "host/build-4",
        )
        .expect("connect scripted exchange host");
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .expect("begin breakpoint test session");

        let process = async_process();
        let risk_id = HostRiskLeaseId::new("b".repeat(64)).expect("host-risk id");
        client
            .register_host_risk_verifier(HostRiskVerifier::new(
                risk_id.clone(),
                session_id(),
                provisioning_epoch(),
                HostRiskOperation::Attach {
                    process: process.clone(),
                    mode: AttachMode::Debug,
                },
            ))
            .expect("register breakpoint test verifier");

        let verified_state = {
            let reducer = &mut client.session.as_mut().expect("test session").reducer;
            let idle = reducer.state().state_token();
            reducer
                .accept_command(&CommandEnvelope {
                    version: ProtocolVersion::current(),
                    command_id: CommandId::new(1).expect("open command id"),
                    session_id: Some(session_id()),
                    expected_state: Some(idle),
                    command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                        scope: AttachScope::Host {
                            process,
                            risk_lease: risk_id,
                        },
                        mode: AttachMode::Debug,
                    })),
                })
                .expect("accept synthetic attach");
            reducer
                .mark_stopped(
                    StopReason::Initial,
                    ThreadId::new(9).expect("initial thread"),
                )
                .expect("mark synthetic stop")
                .clone()
        };
        let token = match &verified_state {
            SessionState::Stopped { token, .. } => *token,
            _ => panic!("synthetic attach must be stopped"),
        };
        client
            .session
            .as_mut()
            .expect("test session")
            .verified_state = verified_state;
        client.next_command_id = 2;
        (client, token)
    }

    #[test]
    fn breakpoint_policy_substitution_is_rejected_and_poisons_connection() {
        let (mut client, stop) = prime_stopped_scripted_exchange_client();
        let command_id = CommandId::new(2).expect("set command id");
        let breakpoint = BreakpointSpec {
            id: BreakpointId::new(7).expect("breakpoint id"),
            address: MemoryAddress::new(0x0000_7ff6_8000_1234),
            kind: BreakpointKind::Software,
            scope: BreakpointScope::Process,
        };
        let refreshed_stop = StopToken {
            state: StateToken {
                session_id: session_id(),
                generation: stop
                    .state
                    .generation
                    .checked_next()
                    .expect("refreshed state generation"),
            },
            stop_id: StopId::new(stop.stop_id.get() + 1).expect("refreshed stop id"),
        };
        let refreshed_state = SessionState::Stopped {
            token: refreshed_stop,
            reason: StopReason::Initial,
            thread_id: ThreadId::new(9).expect("initial thread"),
        };
        client.transport.scripted.push_back(vec![
            correlated_event_frame(
                2,
                1,
                command_id,
                stop.state,
                DebugEvent::BreakpointChanged {
                    stop,
                    breakpoint: breakpoint.clone(),
                    change: BreakpointChange::Set {
                        persistence: BreakpointPersistence::Persistent,
                    },
                },
            ),
            correlated_event_frame(
                3,
                2,
                command_id,
                refreshed_stop.state,
                DebugEvent::StateChanged(refreshed_state),
            ),
            correlated_event_frame(
                4,
                3,
                command_id,
                refreshed_stop.state,
                DebugEvent::CommandResult {
                    command_id,
                    outcome: CommandOutcome::Succeeded,
                },
            ),
        ]);

        assert_eq!(
            client.submit(DebugCommand::SetBreakpoint {
                stop,
                breakpoint: breakpoint.clone(),
                persistence: BreakpointPersistence::Temporary,
            }),
            Err(DebugHostClientError::UnexpectedCommandEvidence {
                command_id,
                evidence: "breakpoint-change",
            })
        );
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
        assert_eq!(
            client.submit(DebugCommand::RemoveBreakpoint {
                stop,
                breakpoint_id: breakpoint.id,
            }),
            Err(DebugHostClientError::ConnectionFailed)
        );
    }

    #[test]
    fn exact_breakpoint_policy_succeeds_and_consumes_the_old_stop_token() {
        for persistence in [
            BreakpointPersistence::Persistent,
            BreakpointPersistence::Temporary,
        ] {
            let (mut client, stop) = prime_stopped_scripted_exchange_client();
            let command_id = CommandId::new(2).expect("set command id");
            let breakpoint = BreakpointSpec {
                id: BreakpointId::new(7).expect("breakpoint id"),
                address: MemoryAddress::new(0x0000_7ff6_8000_1234),
                kind: BreakpointKind::Software,
                scope: BreakpointScope::Process,
            };
            let refreshed_stop = StopToken {
                state: StateToken {
                    session_id: session_id(),
                    generation: stop
                        .state
                        .generation
                        .checked_next()
                        .expect("refreshed state generation"),
                },
                stop_id: StopId::new(stop.stop_id.get() + 1).expect("refreshed stop id"),
            };
            let refreshed_state = SessionState::Stopped {
                token: refreshed_stop,
                reason: StopReason::Initial,
                thread_id: ThreadId::new(9).expect("initial thread"),
            };
            client.transport.scripted.push_back(vec![
                correlated_event_frame(
                    2,
                    1,
                    command_id,
                    stop.state,
                    DebugEvent::BreakpointChanged {
                        stop,
                        breakpoint: breakpoint.clone(),
                        change: BreakpointChange::Set { persistence },
                    },
                ),
                correlated_event_frame(
                    3,
                    2,
                    command_id,
                    refreshed_stop.state,
                    DebugEvent::StateChanged(refreshed_state.clone()),
                ),
                correlated_event_frame(
                    4,
                    3,
                    command_id,
                    refreshed_stop.state,
                    DebugEvent::CommandResult {
                        command_id,
                        outcome: CommandOutcome::Succeeded,
                    },
                ),
            ]);
            let command = DebugCommand::SetBreakpoint {
                stop,
                breakpoint: breakpoint.clone(),
                persistence,
            };

            let receipt = client
                .submit(command.clone())
                .expect("exact breakpoint policy evidence");
            assert_eq!(receipt.outcome, CommandOutcome::Succeeded);
            assert!(matches!(
                &receipt.events[0].event,
                DebugEvent::BreakpointChanged {
                    stop: actual_stop,
                    breakpoint: actual_breakpoint,
                    change: BreakpointChange::Set {
                        persistence: actual_persistence,
                    },
                } if *actual_stop == stop
                    && actual_breakpoint == &breakpoint
                    && *actual_persistence == persistence
            ));
            assert_eq!(client.session_state(), Some(&refreshed_state));
            assert_eq!(
                client.submit(command),
                Err(DebugHostClientError::Protocol(
                    ProtocolValidationError::StaleStateToken
                ))
            );
            assert_eq!(
                client.connection_state(),
                ClientConnectionState::SessionOpen
            );
        }
    }

    #[test]
    fn breakpoint_evidence_replay_and_post_result_order_are_terminal() {
        let breakpoint = BreakpointSpec {
            id: BreakpointId::new(7).expect("breakpoint id"),
            address: MemoryAddress::new(0x0000_7ff6_8000_1234),
            kind: BreakpointKind::Software,
            scope: BreakpointScope::Process,
        };

        let (mut replayed, stop) = prime_stopped_scripted_exchange_client();
        let command_id = CommandId::new(2).expect("set command id");
        let refreshed_stop = StopToken {
            state: StateToken {
                session_id: session_id(),
                generation: stop
                    .state
                    .generation
                    .checked_next()
                    .expect("refreshed state generation"),
            },
            stop_id: StopId::new(stop.stop_id.get() + 1).expect("refreshed stop id"),
        };
        let refreshed_state = SessionState::Stopped {
            token: refreshed_stop,
            reason: StopReason::Initial,
            thread_id: ThreadId::new(9).expect("initial thread"),
        };
        let breakpoint_event = DebugEvent::BreakpointChanged {
            stop,
            breakpoint: breakpoint.clone(),
            change: BreakpointChange::Set {
                persistence: BreakpointPersistence::Temporary,
            },
        };
        replayed.transport.scripted.push_back(vec![
            correlated_event_frame(2, 1, command_id, stop.state, breakpoint_event.clone()),
            correlated_event_frame(3, 2, command_id, stop.state, breakpoint_event),
            correlated_event_frame(
                4,
                3,
                command_id,
                refreshed_stop.state,
                DebugEvent::StateChanged(refreshed_state.clone()),
            ),
            correlated_event_frame(
                5,
                4,
                command_id,
                refreshed_stop.state,
                DebugEvent::CommandResult {
                    command_id,
                    outcome: CommandOutcome::Succeeded,
                },
            ),
        ]);
        assert_eq!(
            replayed.submit(DebugCommand::SetBreakpoint {
                stop,
                breakpoint: breakpoint.clone(),
                persistence: BreakpointPersistence::Temporary,
            }),
            Err(DebugHostClientError::DuplicateCommandEvidence {
                evidence: "breakpoint-change",
            })
        );
        assert_eq!(replayed.connection_state(), ClientConnectionState::Failed);

        let (mut reordered, stop) = prime_stopped_scripted_exchange_client();
        let refreshed_stop = StopToken {
            state: StateToken {
                session_id: session_id(),
                generation: stop
                    .state
                    .generation
                    .checked_next()
                    .expect("refreshed state generation"),
            },
            stop_id: StopId::new(stop.stop_id.get() + 1).expect("refreshed stop id"),
        };
        let refreshed_state = SessionState::Stopped {
            token: refreshed_stop,
            reason: StopReason::Initial,
            thread_id: ThreadId::new(9).expect("initial thread"),
        };
        reordered.transport.scripted.push_back(vec![
            correlated_event_frame(
                2,
                1,
                command_id,
                refreshed_stop.state,
                DebugEvent::StateChanged(refreshed_state),
            ),
            correlated_event_frame(
                3,
                2,
                command_id,
                refreshed_stop.state,
                DebugEvent::CommandResult {
                    command_id,
                    outcome: CommandOutcome::Succeeded,
                },
            ),
            correlated_event_frame(
                4,
                3,
                command_id,
                stop.state,
                DebugEvent::BreakpointChanged {
                    stop,
                    breakpoint: breakpoint.clone(),
                    change: BreakpointChange::Set {
                        persistence: BreakpointPersistence::Temporary,
                    },
                },
            ),
        ]);
        assert_eq!(
            reordered.submit(DebugCommand::SetBreakpoint {
                stop,
                breakpoint,
                persistence: BreakpointPersistence::Temporary,
            }),
            Err(DebugHostClientError::EventAfterCommandResult { command_id })
        );
        assert_eq!(reordered.connection_state(), ClientConnectionState::Failed);
    }

    #[test]
    fn sandbox_failure_stage_command_matrix_is_exact() {
        let state = StateToken {
            session_id: session_id(),
            generation: StateGeneration::new(1).expect("generation"),
        };
        let stop = StopToken {
            state,
            stop_id: StopId::new(1).expect("stop id"),
        };
        let run = RunToken {
            state,
            run_id: RunId::new(1).expect("run id"),
        };
        let binding = inherited_binding();
        let commands = [
            ("sandbox-open", DebugCommand::Open(sandbox_target())),
            (
                "inherited-open",
                DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                    scope: AttachScope::OwnedSandbox {
                        process: binding.process().clone(),
                        ownership_lease: SandboxOwnershipLeaseId::new("5".repeat(64))
                            .expect("lease id"),
                    },
                    mode: binding.mode(),
                })),
            ),
            ("continue", DebugCommand::Continue { stop }),
            ("pause", DebugCommand::Pause { run }),
            (
                "step",
                DebugCommand::Step {
                    stop,
                    thread_id: ThreadId::new(1).expect("thread id"),
                    kind: StepKind::Into,
                },
            ),
            (
                "terminate",
                DebugCommand::Terminate {
                    execution: ExecutionToken::Stopped { stop },
                },
            ),
            ("close", DebugCommand::Close { state }),
            (
                "offline-open",
                DebugCommand::Open(DebugTargetRequest::Offline(OfflineTarget {
                    path: PathBuf::from("sample.exe"),
                })),
            ),
        ];
        let stages = [
            SandboxFailureStage::Policy,
            SandboxFailureStage::Discovery,
            SandboxFailureStage::Provisioning,
            SandboxFailureStage::Attestation,
            SandboxFailureStage::Launch,
            SandboxFailureStage::Runtime,
            SandboxFailureStage::Cleanup,
        ];
        for (name, command) in commands {
            for stage in stages {
                let expected = match name {
                    "sandbox-open" => stage != SandboxFailureStage::Cleanup,
                    "inherited-open" | "continue" | "pause" | "step" | "terminate" => {
                        stage == SandboxFailureStage::Runtime
                    }
                    "close" | "offline-open" => false,
                    _ => unreachable!("complete command matrix"),
                };
                assert_eq!(
                    command_allows_failure_stage(&command, stage),
                    expected,
                    "unexpected {name}/{stage:?} mapping"
                );
            }
        }
    }

    #[test]
    fn sandbox_failure_phase_enforces_ordering_and_attestation_coherence() {
        let mut reducer = SessionMachine::new(session_id(), provisioning_epoch(), helper_build());
        let initial = reducer.state().state_token();
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(1).expect("command id"),
            session_id: Some(session_id()),
            expected_state: Some(initial),
            command: DebugCommand::Open(sandbox_target()),
        };
        let _checkpoint = reducer
            .begin_remote_command(&envelope)
            .expect("begin sandbox open");
        reducer
            .record_sandbox_target_not_created()
            .expect("record trusted pre-target outcome");

        let policy = reducer
            .bind_sandbox_failure(
                SandboxFailureStage::Policy,
                SandboxFailureKind::InvalidPolicy,
                false,
                DiagnosticText::new("policy rejected").expect("detail"),
            )
            .expect("policy failure");
        let mut evidence = ResponseEvidence::default();
        validate_sandbox_failure_phase(&envelope, &reducer, &policy, &evidence, false)
            .expect("pre-state policy failure is rollback-safe");
        evidence.command_state_observed = true;
        assert!(
            validate_sandbox_failure_phase(&envelope, &reducer, &policy, &evidence, false).is_err()
        );

        let provisioning = reducer
            .bind_sandbox_failure(
                SandboxFailureStage::Provisioning,
                SandboxFailureKind::HelperFailure,
                true,
                DiagnosticText::new("provisioning failed").expect("detail"),
            )
            .expect("provisioning failure");
        validate_sandbox_failure_phase(&envelope, &reducer, &provisioning, &evidence, false)
            .expect("post-state provisioning failure");
        let early_launch = reducer
            .bind_sandbox_failure(
                SandboxFailureStage::Launch,
                SandboxFailureKind::LaunchDenied,
                false,
                DiagnosticText::new("target creation denied").expect("detail"),
            )
            .expect("early launch failure");
        validate_sandbox_failure_phase(&envelope, &reducer, &early_launch, &evidence, false)
            .expect("launch may fail while target creation is pending");
        evidence.attestation_accepted = true;
        assert!(
            validate_sandbox_failure_phase(&envelope, &reducer, &provisioning, &evidence, false,)
                .is_err()
        );
        evidence.attestation_accepted = false;

        let mut reducer = SessionMachine::new(session_id(), provisioning_epoch(), helper_build());
        let _created_checkpoint = reducer
            .begin_remote_command(&envelope)
            .expect("begin created-target sandbox open");
        let process = test_process_identity(
            reducer
                .expected_attestation()
                .expect("sandbox expectation exists"),
        );
        reducer
            .target_created_suspended(process)
            .expect("target created suspended");
        let attestation_failure = reducer
            .bind_sandbox_failure(
                SandboxFailureStage::Attestation,
                SandboxFailureKind::AttestationRejected,
                false,
                DiagnosticText::new("attestation rejected").expect("detail"),
            )
            .expect("attestation failure");
        validate_sandbox_failure_phase(&envelope, &reducer, &attestation_failure, &evidence, false)
            .expect("exact attestation phase");
        let premature_launch = reducer
            .bind_sandbox_failure(
                SandboxFailureStage::Launch,
                SandboxFailureKind::LaunchDenied,
                false,
                DiagnosticText::new("launch denied").expect("detail"),
            )
            .expect("launch failure");
        assert!(
            validate_sandbox_failure_phase(
                &envelope,
                &reducer,
                &premature_launch,
                &evidence,
                false,
            )
            .is_err()
        );

        let actual = test_attestation(reducer.expected_attestation().expect("sandbox expectation"));
        reducer
            .accept_sandbox_attestation(&actual)
            .expect("attestation accepted");
        evidence.attestation_accepted = true;
        validate_sandbox_failure_phase(&envelope, &reducer, &premature_launch, &evidence, false)
            .expect("post-attestation launch failure");
        let runtime = reducer
            .bind_sandbox_failure(
                SandboxFailureStage::Runtime,
                SandboxFailureKind::HelperFailure,
                false,
                DiagnosticText::new("initial runtime failed").expect("detail"),
            )
            .expect("runtime failure");
        validate_sandbox_failure_phase(&envelope, &reducer, &runtime, &evidence, false)
            .expect("post-attestation runtime failure");
        evidence.attestation_accepted = false;
        assert!(
            validate_sandbox_failure_phase(&envelope, &reducer, &runtime, &evidence, false)
                .is_err()
        );
    }

    #[test]
    fn lifecycle_and_final_failure_states_are_ordered_and_unique() {
        let mut reducer = SessionMachine::new(session_id(), provisioning_epoch(), helper_build());
        let initial = reducer.state().state_token();
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(1).expect("command id"),
            session_id: Some(session_id()),
            expected_state: Some(initial),
            command: DebugCommand::Open(sandbox_target()),
        };
        let _checkpoint = reducer
            .begin_remote_command(&envelope)
            .expect("begin sandbox open");
        let lifecycle = SandboxLifecycleEvent::State {
            session_id: session_id(),
            state: SandboxLifecycleState::Provisioning,
        };
        let mut evidence = ResponseEvidence::default();
        assert!(matches!(
            validate_sandbox_lifecycle(&envelope, &mut reducer, &lifecycle, &mut evidence),
            Err(DebugHostClientError::UnexpectedCommandEvidence {
                evidence: "sandbox-evidence-before-command-state",
                ..
            })
        ));
        evidence.command_state_observed = true;
        validate_sandbox_lifecycle(&envelope, &mut reducer, &lifecycle, &mut evidence)
            .expect("first exact lifecycle state");
        assert_eq!(
            validate_sandbox_lifecycle(&envelope, &mut reducer, &lifecycle, &mut evidence),
            Err(DebugHostClientError::DuplicateCommandEvidence {
                evidence: "sandbox-lifecycle-state",
            })
        );
        let process = test_process_identity(
            reducer
                .expected_attestation()
                .expect("sandbox expectation exists"),
        );
        reducer
            .target_created_suspended(process)
            .expect("advance sandbox lifecycle");
        validate_sandbox_lifecycle(
            &envelope,
            &mut reducer,
            &SandboxLifecycleEvent::State {
                session_id: session_id(),
                state: SandboxLifecycleState::TargetCreatedSuspended,
            },
            &mut evidence,
        )
        .expect("a distinct reducer-backed lifecycle state remains valid");

        let failure = reducer
            .bind_sandbox_failure(
                SandboxFailureStage::Attestation,
                SandboxFailureKind::AttestationRejected,
                false,
                DiagnosticText::new("exact failure detail").expect("detail"),
            )
            .expect("failure");
        let diagnostic = SandboxRejectionDiagnostic::Failed {
            failure,
            cleanup_attempt: false,
        };
        let wrong = SessionState::Failed {
            token: next_state_token(reducer.state().state_token(), 1),
            message: "wrong detail".into(),
        };
        assert!(
            validate_post_rejection_event(
                envelope.command_id,
                &DebugEvent::StateChanged(wrong),
                Some(&diagnostic),
            )
            .is_err()
        );
        let exact = SessionState::Failed {
            token: next_state_token(reducer.state().state_token(), 1),
            message: "exact failure detail".into(),
        };
        validate_post_rejection_event(
            envelope.command_id,
            &DebugEvent::StateChanged(exact),
            Some(&diagnostic),
        )
        .expect("one exact final failure state");
        require_unique_evidence(
            &mut evidence.failure_state_observed,
            "sandbox-failure-state",
        )
        .expect("first final failure state");
        assert_eq!(
            require_unique_evidence(
                &mut evidence.failure_state_observed,
                "sandbox-failure-state",
            ),
            Err(DebugHostClientError::DuplicateCommandEvidence {
                evidence: "sandbox-failure-state",
            })
        );
    }

    #[test]
    fn inherited_open_runtime_failure_uses_exact_reducer_phase() {
        let binding = inherited_binding();
        let lease_id = SandboxOwnershipLeaseId::new("8".repeat(64)).expect("lease id");
        let mut reducer = SessionMachine::new(session_id(), provisioning_epoch(), helper_build());
        reducer
            .register_sandbox_ownership_verifier(SandboxOwnershipVerifier::new(
                lease_id.clone(),
                binding.clone(),
            ))
            .expect("register verifier");
        let initial = reducer.state().state_token();
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(1).expect("command id"),
            session_id: Some(session_id()),
            expected_state: Some(initial),
            command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                scope: AttachScope::OwnedSandbox {
                    process: binding.process().clone(),
                    ownership_lease: lease_id,
                },
                mode: binding.mode(),
            })),
        };
        let _checkpoint = reducer
            .begin_remote_command(&envelope)
            .expect("begin inherited open");
        let failure = reducer
            .bind_sandbox_failure(
                SandboxFailureStage::Runtime,
                SandboxFailureKind::HelperFailure,
                false,
                DiagnosticText::new("inherited open failed").expect("detail"),
            )
            .expect("inherited failure");
        let evidence = ResponseEvidence {
            command_state_observed: true,
            ..ResponseEvidence::default()
        };
        validate_sandbox_failure_phase(&envelope, &reducer, &failure, &evidence, false)
            .expect("exact inherited open runtime phase");
        assert!(matches!(
            failure.context,
            SandboxFailureContext::InheritedAttach { .. }
        ));
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
    fn exact_provider_unavailable_rejection_rolls_back_without_cleanup_claim() {
        let mut client = scripted_client(ScriptedAttack::ProviderUnavailableRejection);
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();

        let receipt = client
            .submit(DebugCommand::Open(sandbox_target()))
            .expect("exact provider diagnostic is a valid rejection");
        assert!(matches!(receipt.outcome, CommandOutcome::Rejected { .. }));
        assert!(receipt.events.iter().any(|event| matches!(
            &event.event,
            DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::ProviderUnavailable(
                unavailable
            )) if unavailable.session_id == session_id()
                && unavailable.provider == SandboxProviderSelection::LocalAppContainer
                && unavailable.reason == ProviderUnavailableReason::FeatureDisabled
        )));
        assert_eq!(
            client.connection_state(),
            ClientConnectionState::SessionOpen
        );
        assert_eq!(
            client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Idle)
        );
        let session = client.session.as_ref().expect("session remains owned");
        assert!(session.reducer.expected_attestation().is_none());
        assert!(!session.sandbox_cleanup_verified);
        assert_eq!(
            client.release_closed_session(),
            Err(DebugHostClientError::SessionNotClosed {
                state: SessionStateKind::Idle,
            })
        );

        let second = client
            .submit(DebugCommand::Open(sandbox_target()))
            .expect("connection remains usable after exact rejection");
        assert!(matches!(second.outcome, CommandOutcome::Rejected { .. }));
    }

    #[test]
    fn inbound_discovery_failure_cannot_mint_not_created_state() {
        let mut client = scripted_client(ScriptedAttack::FailedRejection);
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();

        assert_eq!(
            client.submit(DebugCommand::Open(sandbox_target())),
            Err(DebugHostClientError::SessionMachine(
                SessionMachineError::SandboxFailure(
                    SandboxFailureValidationError::TargetCreationOutcome
                )
            ))
        );
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
        let session = client
            .session
            .as_ref()
            .expect("session remains fail-closed");
        assert_eq!(session.reducer.state().kind(), SessionStateKind::Opening);
        assert_eq!(session.reducer.sandbox_target_creation_outcome(), None);
        assert_eq!(
            client.submit(DebugCommand::Open(sandbox_target())),
            Err(DebugHostClientError::ConnectionFailed)
        );
    }

    #[test]
    fn mismatched_or_effectful_rollback_diagnostics_poison_the_connection() {
        let mut wrong_provider = scripted_client(ScriptedAttack::WrongFailureProvider);
        wrong_provider
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        assert_eq!(
            wrong_provider.submit(DebugCommand::Open(sandbox_target())),
            Err(DebugHostClientError::SessionMachine(
                SessionMachineError::SandboxFailure(SandboxFailureValidationError::Provider)
            ))
        );
        assert_eq!(
            wrong_provider.connection_state(),
            ClientConnectionState::Failed
        );

        let mut extra_effect = scripted_client(ScriptedAttack::FailureWithStateEffect);
        extra_effect
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        assert_eq!(
            extra_effect.submit(DebugCommand::Open(sandbox_target())),
            Err(DebugHostClientError::SessionMachine(
                SessionMachineError::SandboxFailure(
                    SandboxFailureValidationError::TargetCreationOutcome
                )
            ))
        );
        assert_eq!(
            extra_effect.connection_state(),
            ClientConnectionState::Failed
        );
        assert_eq!(
            extra_effect.session_state().map(SessionState::kind),
            Some(SessionStateKind::Idle)
        );
        let failed_session = extra_effect
            .session
            .as_ref()
            .expect("failed connection retains speculative reducer evidence");
        assert_eq!(
            failed_session.reducer.state().kind(),
            SessionStateKind::Opening
        );
        assert_eq!(
            failed_session.reducer.sandbox_target_creation_outcome(),
            None
        );
    }

    #[test]
    fn remote_provisioning_failure_cannot_mint_processless_cleanup_ownership() {
        let mut client = scripted_client(ScriptedAttack::ProvisioningFailureThenCleanup);
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();

        assert_eq!(
            client.submit(DebugCommand::Open(sandbox_target())),
            Err(DebugHostClientError::SessionMachine(
                SessionMachineError::SandboxFailure(
                    SandboxFailureValidationError::TargetCreationOutcome
                )
            ))
        );
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
        let session = client
            .session
            .as_ref()
            .expect("failed connection retains its reducer evidence");
        assert!(session.reducer.expected_attestation().is_some());
        assert_eq!(session.reducer.sandbox_target_creation_outcome(), None);
        assert!(!session.sandbox_cleanup_verified);
        let opening = client.session_state().expect("opening state").state_token();
        assert_eq!(
            client.submit(DebugCommand::Close { state: opening }),
            Err(DebugHostClientError::ConnectionFailed)
        );
    }

    #[test]
    fn runtime_failure_retains_cleanup_ownership_and_rejects_success_claim() {
        let mut client = scripted_client(ScriptedAttack::RuntimeFailureThenCleanup);
        prime_sandbox_stopped(&mut client);
        let SessionState::Stopped { token: stop, .. } = client
            .session_state()
            .expect("primed stopped state")
            .clone()
        else {
            panic!("primed session must be stopped");
        };
        let receipt = client
            .submit(DebugCommand::Continue { stop })
            .expect("runtime failure remains cleanup-capable");
        assert!(matches!(receipt.outcome, CommandOutcome::Rejected { .. }));
        assert_eq!(
            client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Failed)
        );
        let failed = client.session_state().expect("failed state").state_token();
        client
            .submit(DebugCommand::Close { state: failed })
            .expect("runtime failure can close with exact cleanup");
        client.release_closed_session().expect("verified release");

        let mut contradictory = scripted_client(ScriptedAttack::FailureReportedAsSuccess);
        contradictory
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        assert_eq!(
            contradictory.submit(DebugCommand::Open(sandbox_target())),
            Err(DebugHostClientError::SessionMachine(
                SessionMachineError::SandboxFailure(
                    SandboxFailureValidationError::TargetCreationOutcome
                )
            ))
        );
        assert_eq!(
            contradictory.connection_state(),
            ClientConnectionState::Failed
        );
    }

    #[test]
    fn incomplete_cleanup_attempt_retains_residual_evidence_and_allows_exact_retry() {
        let mut client = scripted_client(ScriptedAttack::CleanupFailureThenCleanup);
        prime_sandbox_stopped(&mut client);
        let stopped = client
            .session_state()
            .expect("primed stopped state")
            .state_token();

        let failure = client
            .submit(DebugCommand::Close { state: stopped })
            .expect("exact incomplete cleanup evidence is a valid retained rejection");
        assert!(matches!(failure.outcome, CommandOutcome::Rejected { .. }));
        assert!(failure.events.iter().any(|event| matches!(
            &event.event,
            DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::CleanupAttemptFailed(attempt))
                if attempt.failure.stage == SandboxFailureStage::Cleanup
                    && attempt.failure.kind == SandboxFailureKind::CleanupIncomplete
                    && attempt.receipt.outcome == CleanupOutcome::Incomplete
                    && !attempt.receipt.residuals.is_empty()
        )));
        assert_eq!(
            client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Failed)
        );
        let session = client
            .session
            .as_ref()
            .expect("cleanup-required session remains owned");
        assert!(session.reducer.requires_cleanup_receipt());
        assert_eq!(
            session.reducer.sandbox_state(),
            Some(SandboxLifecycleState::Cleanup)
        );
        assert!(!session.sandbox_cleanup_verified);
        assert_eq!(
            client.release_closed_session(),
            Err(DebugHostClientError::SessionNotClosed {
                state: SessionStateKind::Failed,
            })
        );

        // This session already created and attested a target before cleanup
        // failed, so the retry must carry that exact process identity. The
        // provisioning-failure script intentionally omits one because it
        // models failure before process creation.
        client.transport.attack = ScriptedAttack::RuntimeFailureThenCleanup;
        let failed = client.session_state().expect("failed state").state_token();
        client
            .submit(DebugCommand::Close { state: failed })
            .expect("later exact complete cleanup closes the session");
        assert_eq!(
            client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Closed)
        );
        client.release_closed_session().expect("verified release");
    }

    #[test]
    fn incomplete_cleanup_attempt_rejects_forgery_duplication_and_success_claims() {
        let mut missing = scripted_client(ScriptedAttack::CleanupFailureWithoutReceipt);
        prime_sandbox_stopped(&mut missing);
        let stopped = missing.session_state().unwrap().state_token();
        assert!(matches!(
            missing.submit(DebugCommand::Close { state: stopped }),
            Err(DebugHostClientError::UnexpectedCommandEvidence {
                command_id,
                evidence: "sandbox-lifecycle",
            }) if command_id.get() == 2
        ));
        assert_eq!(missing.connection_state(), ClientConnectionState::Failed);

        let mut forged = scripted_client(ScriptedAttack::WrongCleanupFailureReceipt);
        prime_sandbox_stopped(&mut forged);
        let stopped = forged.session_state().unwrap().state_token();
        assert_eq!(
            forged.submit(DebugCommand::Close { state: stopped }),
            Err(DebugHostClientError::CleanupReceipt(
                CleanupReceiptError::BindingMismatch
            ))
        );
        assert_eq!(forged.connection_state(), ClientConnectionState::Failed);

        let mut duplicate = scripted_client(ScriptedAttack::DuplicateCleanupFailureReceipt);
        prime_sandbox_stopped(&mut duplicate);
        let stopped = duplicate.session_state().unwrap().state_token();
        assert_eq!(
            duplicate.submit(DebugCommand::Close { state: stopped }),
            Err(DebugHostClientError::DuplicateCommandEvidence {
                evidence: "sandbox-cleanup-evidence",
            })
        );
        assert_eq!(duplicate.connection_state(), ClientConnectionState::Failed);

        let mut contradictory = scripted_client(ScriptedAttack::CleanupFailureReportedAsSuccess);
        prime_sandbox_stopped(&mut contradictory);
        let stopped = contradictory.session_state().unwrap().state_token();
        assert!(matches!(
            contradictory.submit(DebugCommand::Close { state: stopped }),
            Err(DebugHostClientError::UnexpectedCommandEvidence {
                evidence: "sandbox-rejection-diagnostic",
                ..
            })
        ));
        assert_eq!(
            contradictory.connection_state(),
            ClientConnectionState::Failed
        );
    }

    #[test]
    fn inherited_cleanup_failure_retains_exact_ownership_for_retry() {
        let mut client = scripted_client(ScriptedAttack::InheritedCleanupFailure);
        prime_inherited_observing(&mut client);
        let observing = client
            .session_state()
            .expect("inherited observing state")
            .state_token();
        let failure = client
            .submit(DebugCommand::Close { state: observing })
            .expect("exact inherited cleanup failure remains representable");
        assert!(matches!(failure.outcome, CommandOutcome::Rejected { .. }));
        let expected_process = inherited_binding().process().clone();
        assert!(failure.events.iter().any(|event| matches!(
            &event.event,
            DebugEvent::SandboxLifecycle(SandboxLifecycleEvent::CleanupAttemptFailed(attempt))
                if attempt.receipt.process.as_ref()
                    == Some(&expected_process)
                    && attempt.receipt.outcome == CleanupOutcome::Incomplete
                    && !attempt.receipt.residuals.is_empty()
        )));
        assert_eq!(
            client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Failed)
        );
        let session = client
            .session
            .as_ref()
            .expect("inherited session remains owned");
        assert!(session.reducer.inherited_sandbox().is_some());
        assert!(session.reducer.requires_cleanup_receipt());
        assert!(!session.sandbox_cleanup_verified);
        assert_eq!(
            client.connection_state(),
            ClientConnectionState::SessionOpen
        );

        client.transport.attack = ScriptedAttack::InheritedCleanup;
        let failed = client.session_state().expect("failed state").state_token();
        client
            .submit(DebugCommand::Close { state: failed })
            .expect("exact inherited receipt closes after failure");
        assert_eq!(
            client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Closed)
        );
        client.release_closed_session().expect("verified release");
        assert_eq!(client.connection_state(), ClientConnectionState::Connected);

        let mut forged = scripted_client(ScriptedAttack::WrongInheritedCleanupFailure);
        prime_inherited_observing(&mut forged);
        let observing = forged
            .session_state()
            .expect("inherited observing state")
            .state_token();
        assert_eq!(
            forged.submit(DebugCommand::Close { state: observing }),
            Err(DebugHostClientError::SessionMachine(
                SessionMachineError::InheritedCleanupReceiptMismatch
            ))
        );
        assert_eq!(forged.connection_state(), ClientConnectionState::Failed);
        assert_eq!(
            forged.session_state().map(SessionState::kind),
            Some(SessionStateKind::Observing)
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
    fn client_rejects_wrong_or_missing_sandbox_attestation_process_evidence() {
        let mut wrong = scripted_client(ScriptedAttack::WrongAttestationProcess);
        wrong
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        assert_eq!(
            wrong.submit(DebugCommand::Open(sandbox_target())),
            Err(DebugHostClientError::Attestation(
                AttestationMismatch::ProcessIdentity
            ))
        );
        assert_eq!(wrong.connection_state(), ClientConnectionState::Failed);

        let mut missing = scripted_client(ScriptedAttack::MissingAttestation);
        missing
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        assert!(matches!(
            missing.submit(DebugCommand::Open(sandbox_target())),
            Err(DebugHostClientError::MissingCommandEvidence {
                command: "open",
                final_state: SessionStateKind::AwaitingAttestation,
                ..
            })
        ));
        assert_eq!(missing.connection_state(), ClientConnectionState::Failed);
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
    fn client_rejects_missing_or_mismatched_created_process_cleanup_binding() {
        for attack in [
            ScriptedAttack::MissingCleanupProcess,
            ScriptedAttack::WrongCleanupProcess,
        ] {
            let mut client = scripted_client(attack);
            prime_sandbox_stopped(&mut client);
            let state = client.session_state().unwrap().state_token();
            assert_eq!(
                client.submit(DebugCommand::Close { state }),
                Err(DebugHostClientError::CleanupReceipt(
                    CleanupReceiptError::BindingMismatch
                ))
            );
            assert_eq!(client.connection_state(), ClientConnectionState::Failed);
            assert_eq!(
                client.session_state().map(SessionState::kind),
                Some(SessionStateKind::Stopped)
            );
        }
    }

    #[test]
    fn client_accepts_only_exact_inherited_sandbox_cleanup() {
        let mut client = scripted_client(ScriptedAttack::InheritedCleanup);
        prime_inherited_observing(&mut client);
        let state = client.session_state().unwrap().state_token();
        let receipt = client.submit(DebugCommand::Close { state }).unwrap();
        assert_eq!(receipt.outcome, CommandOutcome::Succeeded);
        assert_eq!(
            client.session_state().unwrap().kind(),
            SessionStateKind::Closed
        );
        assert!(
            client
                .session
                .as_ref()
                .expect("session retained until release")
                .sandbox_cleanup_verified
        );

        let mut forged = scripted_client(ScriptedAttack::WrongInheritedCleanup);
        prime_inherited_observing(&mut forged);
        let state = forged.session_state().unwrap().state_token();
        assert_eq!(
            forged.submit(DebugCommand::Close { state }),
            Err(DebugHostClientError::SessionMachine(
                SessionMachineError::InheritedCleanupReceiptMismatch
            ))
        );
        assert_eq!(
            forged.session_state().unwrap().kind(),
            SessionStateKind::Observing
        );
        assert_eq!(forged.connection_state(), ClientConnectionState::Failed);
    }

    #[test]
    fn active_session_drop_and_abandon_force_control_abort() {
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
        assert_eq!(report.statuses.len(), DebugCapability::ALL.len());
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
    fn rejected_host_operation_consumes_its_controller_verifier() {
        let risk_lease = HostRiskLeaseId::new("a".repeat(64)).expect("host-risk lease id");
        let target = LaunchTarget {
            binary_id: BinaryId::digest(b"synthetic host-risk sample"),
            executable: PathBuf::from("sample.exe"),
            arguments: Vec::new(),
            working_directory: None,
            environment: LaunchEnvironment::Host {
                risk_lease: risk_lease.clone(),
            },
            stop_before_entry: true,
        };
        let command = DebugCommand::Open(DebugTargetRequest::Launch(target.clone()));
        let host_authority = HostRiskLease::new_for_test(
            risk_lease,
            session_id(),
            provisioning_epoch(),
            HostRiskOperation::Launch {
                intent: HostLaunchIntent::from_target(&target).expect("host launch target"),
            },
        );
        let verifier = host_authority.verifier();
        let mut client = client(host());
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();
        client.register_host_risk_verifier(verifier).unwrap();
        let _sole_host_authority = host_authority;

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

    #[test]
    fn live_binding_acceptance_is_exact_unique_and_nonreplaceable() {
        let process = async_process();
        let risk_id = HostRiskLeaseId::new("c".repeat(64)).expect("host-risk id");
        let mut reducer = SessionMachine::new(session_id(), provisioning_epoch(), helper_build());
        reducer
            .register_host_risk_verifier(HostRiskVerifier::new(
                risk_id.clone(),
                session_id(),
                provisioning_epoch(),
                HostRiskOperation::Attach {
                    process: process.clone(),
                    mode: AttachMode::Debug,
                },
            ))
            .expect("register verifier");
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(1).expect("command id"),
            session_id: Some(session_id()),
            expected_state: Some(reducer.state().state_token()),
            command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                scope: AttachScope::Host {
                    process: process.clone(),
                    risk_lease: risk_id,
                },
                mode: AttachMode::Debug,
            })),
        };
        let _checkpoint = reducer
            .begin_remote_command(&envelope)
            .expect("begin exact attach");
        let binding = LiveTargetBinding::new(
            process.clone(),
            process.binary_id.clone(),
            MemoryAddress::new(0x0000_7ff6_8000_0000),
            0x4_0000,
        )
        .expect("binding");
        let mut current = None;
        let mut before_open_state = ResponseEvidence::default();
        assert_eq!(
            accept_live_target_binding(
                &envelope,
                &reducer,
                &mut current,
                &binding,
                &mut before_open_state,
            ),
            Err(DebugHostClientError::LiveTargetBindingBeforeOpenState {
                command_id: envelope.command_id,
            })
        );

        let mut evidence = ResponseEvidence {
            command_state_observed: true,
            ..ResponseEvidence::default()
        };
        let wrong_process = ProcessIdentity {
            process_id: process.process_id,
            start_key: ProcessStartKey::new(process.start_key.get() + 1).expect("freshness key"),
            binary_id: process.binary_id.clone(),
        };
        let wrong_binding = LiveTargetBinding::new(
            wrong_process.clone(),
            wrong_process.binary_id.clone(),
            MemoryAddress::new(0x0000_7ff6_8000_0000),
            0x4_0000,
        )
        .expect("structurally valid wrong binding");
        assert_eq!(
            accept_live_target_binding(
                &envelope,
                &reducer,
                &mut current,
                &wrong_binding,
                &mut evidence,
            ),
            Err(DebugHostClientError::LiveTargetProcessMismatch {
                expected: process.clone(),
                actual: wrong_process,
            })
        );

        accept_live_target_binding(&envelope, &reducer, &mut current, &binding, &mut evidence)
            .expect("accept exact binding");
        assert_eq!(current.as_ref(), Some(&binding));
        assert_eq!(
            accept_live_target_binding(&envelope, &reducer, &mut current, &binding, &mut evidence,),
            Err(DebugHostClientError::DuplicateLiveTargetBinding)
        );

        let replacement = LiveTargetBinding::new(
            process.clone(),
            process.binary_id.clone(),
            MemoryAddress::new(0x0000_7ff6_9000_0000),
            0x4_0000,
        )
        .expect("structurally valid replacement");
        assert_eq!(
            accept_live_target_binding(
                &envelope,
                &reducer,
                &mut current,
                &replacement,
                &mut evidence,
            ),
            Err(DebugHostClientError::ReplacedLiveTargetBinding)
        );
        assert!(current.is_none());
    }

    #[test]
    fn correlated_debug_attach_stores_read_only_live_binding() {
        let process = async_process();
        let risk_id = HostRiskLeaseId::new("d".repeat(64)).expect("host-risk id");
        let mut client = DebugHostClient::connect(
            AsyncQueueHost::new(Vec::new()),
            [0x6d; 16],
            "controller/build-7",
            "host/build-4",
        )
        .expect("connect test client");
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .expect("begin session");
        client
            .register_host_risk_verifier(HostRiskVerifier::new(
                risk_id.clone(),
                session_id(),
                provisioning_epoch(),
                HostRiskOperation::Attach {
                    process: process.clone(),
                    mode: AttachMode::Debug,
                },
            ))
            .expect("register verifier");

        let command_id = CommandId::new(1).expect("command id");
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id,
            session_id: Some(session_id()),
            expected_state: Some(client.session_state().expect("idle state").state_token()),
            command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                scope: AttachScope::Host {
                    process: process.clone(),
                    risk_lease: risk_id,
                },
                mode: AttachMode::Debug,
            })),
        };
        let (checkpoint, opening) = {
            let session = client.session.as_mut().expect("client session");
            let checkpoint = session
                .reducer
                .begin_remote_command(&envelope)
                .expect("begin remote attach");
            (checkpoint, session.reducer.state().clone())
        };
        let opening_token = opening.state_token();
        let stopped = SessionState::Stopped {
            token: StopToken {
                state: StateToken {
                    session_id: session_id(),
                    generation: opening_token
                        .generation
                        .checked_next()
                        .expect("next generation"),
                },
                stop_id: StopId::new(1).expect("initial stop id"),
            },
            reason: StopReason::Initial,
            thread_id: ThreadId::new(9).expect("initial thread"),
        };
        let stopped_token = stopped.state_token();
        let binding = async_live_binding();
        let frames = vec![
            correlated_event_frame(
                2,
                1,
                command_id,
                opening_token,
                DebugEvent::StateChanged(opening.clone()),
            ),
            correlated_event_frame(
                3,
                2,
                command_id,
                opening_token,
                DebugEvent::LiveTargetBound {
                    state: opening_token,
                    binding: binding.clone(),
                },
            ),
            correlated_event_frame(
                4,
                3,
                command_id,
                stopped_token,
                DebugEvent::StateChanged(stopped.clone()),
            ),
            correlated_event_frame(
                5,
                4,
                command_id,
                stopped_token,
                DebugEvent::CommandResult {
                    command_id,
                    outcome: CommandOutcome::Succeeded,
                },
            ),
        ];
        let batch = HostResponseBatch::try_from_frames(frames, DEFAULT_HOST_RESPONSE_LIMITS)
            .expect("bounded attach response");

        let receipt = client
            .accept_response_batch(&envelope, checkpoint, Some(opening), batch)
            .expect("accept exact attach response");
        assert_eq!(receipt.outcome, CommandOutcome::Succeeded);
        assert_eq!(client.session_state(), Some(&stopped));
        assert_eq!(client.live_target_binding(), Some(&binding));
        assert_eq!(
            client
                .live_target_binding()
                .expect("stored binding")
                .address_for_rva(0x1200)
                .expect("translate RVA"),
            MemoryAddress::new(0x0000_7ff6_8000_1200)
        );
    }

    #[test]
    fn correlated_host_launch_requires_and_stores_exact_aslr_binding() {
        let binary_id = BinaryId::digest(b"correlated host launch image");
        let risk_id = HostRiskLeaseId::new("e".repeat(64)).expect("host-risk id");
        let target = LaunchTarget {
            binary_id: binary_id.clone(),
            executable: PathBuf::from("host-launch.exe"),
            arguments: vec!["--stopped".to_owned()],
            working_directory: None,
            environment: LaunchEnvironment::Host {
                risk_lease: risk_id.clone(),
            },
            stop_before_entry: true,
        };
        let mut client = DebugHostClient::connect(
            AsyncQueueHost::new(Vec::new()),
            [0x6d; 16],
            "controller/build-7",
            "host/build-4",
        )
        .expect("connect test client");
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .expect("begin session");
        client
            .register_host_risk_verifier(HostRiskVerifier::new(
                risk_id,
                session_id(),
                provisioning_epoch(),
                HostRiskOperation::Launch {
                    intent: HostLaunchIntent::from_target(&target).expect("host launch intent"),
                },
            ))
            .expect("register verifier");

        let command_id = CommandId::new(1).expect("command id");
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id,
            session_id: Some(session_id()),
            expected_state: Some(client.session_state().expect("idle state").state_token()),
            command: DebugCommand::Open(DebugTargetRequest::Launch(target)),
        };
        let (checkpoint, opening) = {
            let session = client.session.as_mut().expect("client session");
            let checkpoint = session
                .reducer
                .begin_remote_command(&envelope)
                .expect("begin remote host launch");
            (checkpoint, session.reducer.state().clone())
        };
        let opening_token = opening.state_token();
        let stopped = SessionState::Stopped {
            token: StopToken {
                state: StateToken {
                    session_id: session_id(),
                    generation: opening_token
                        .generation
                        .checked_next()
                        .expect("next generation"),
                },
                stop_id: StopId::new(1).expect("initial stop id"),
            },
            reason: StopReason::Initial,
            thread_id: ThreadId::new(9).expect("initial thread"),
        };
        let stopped_token = stopped.state_token();
        let process = ProcessIdentity {
            process_id: ProcessId::new(8_001).expect("launched process id"),
            start_key: ProcessStartKey::new(55_001).expect("launched process start key"),
            binary_id: binary_id.clone(),
        };
        let binding = LiveTargetBinding::new(
            process,
            binary_id,
            MemoryAddress::new(0x0000_7ff7_2000_0000),
            0x7_0000,
        )
        .expect("host launch binding");
        let frames = vec![
            correlated_event_frame(
                2,
                1,
                command_id,
                opening_token,
                DebugEvent::StateChanged(opening.clone()),
            ),
            correlated_event_frame(
                3,
                2,
                command_id,
                opening_token,
                DebugEvent::LiveTargetBound {
                    state: opening_token,
                    binding: binding.clone(),
                },
            ),
            correlated_event_frame(
                4,
                3,
                command_id,
                stopped_token,
                DebugEvent::StateChanged(stopped.clone()),
            ),
            correlated_event_frame(
                5,
                4,
                command_id,
                stopped_token,
                DebugEvent::CommandResult {
                    command_id,
                    outcome: CommandOutcome::Succeeded,
                },
            ),
        ];
        let batch = HostResponseBatch::try_from_frames(frames, DEFAULT_HOST_RESPONSE_LIMITS)
            .expect("bounded host launch response");

        let receipt = client
            .accept_response_batch(&envelope, checkpoint, Some(opening), batch)
            .expect("accept exact host launch response");
        assert_eq!(receipt.outcome, CommandOutcome::Succeeded);
        assert_eq!(client.session_state(), Some(&stopped));
        assert_eq!(client.live_target_binding(), Some(&binding));
        assert_eq!(
            client
                .live_target_binding()
                .expect("stored launch binding")
                .address_for_rva(0x2_4000)
                .expect("translate ASLR-adjusted RVA"),
            MemoryAddress::new(0x0000_7ff7_2002_4000)
        );
    }

    #[test]
    fn correlated_sandbox_launch_binds_mapping_to_attested_process_identity() {
        let target = sandbox_target();
        let mut client = DebugHostClient::connect(
            AsyncQueueHost::new(Vec::new()),
            [0x6d; 16],
            "controller/build-7",
            "host/build-4",
        )
        .expect("connect test client");
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .expect("begin session");

        let command_id = CommandId::new(1).expect("command id");
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id,
            session_id: Some(session_id()),
            expected_state: Some(client.session_state().expect("idle state").state_token()),
            command: DebugCommand::Open(target),
        };
        let (checkpoint, opening, expected) = {
            let session = client.session.as_mut().expect("client session");
            let checkpoint = session
                .reducer
                .begin_remote_command(&envelope)
                .expect("begin remote sandbox launch");
            (
                checkpoint,
                session.reducer.state().clone(),
                session
                    .reducer
                    .expected_attestation()
                    .expect("sandbox attestation expectation")
                    .clone(),
            )
        };
        let opening_token = opening.state_token();
        let process = test_process_identity(&expected);
        let awaiting_token = StateToken {
            session_id: session_id(),
            generation: opening_token
                .generation
                .checked_next()
                .expect("awaiting-attestation generation"),
        };
        let awaiting = SessionState::AwaitingAttestation {
            token: awaiting_token,
            process: process.clone(),
        };
        let attestation = test_attestation(&expected);
        assert_eq!(attestation.process, process);
        let attested_token = StateToken {
            session_id: session_id(),
            generation: awaiting_token
                .generation
                .checked_next()
                .expect("attestation-accepted generation"),
        };
        let stopped = SessionState::Stopped {
            token: StopToken {
                state: StateToken {
                    session_id: session_id(),
                    generation: attested_token
                        .generation
                        .checked_next()
                        .expect("stopped generation"),
                },
                stop_id: StopId::new(1).expect("initial stop id"),
            },
            reason: StopReason::Initial,
            thread_id: ThreadId::new(9).expect("initial thread"),
        };
        let stopped_token = stopped.state_token();
        let binding = LiveTargetBinding::new(
            process.clone(),
            process.binary_id.clone(),
            MemoryAddress::new(0x0000_7ff8_6000_0000),
            0x9_0000,
        )
        .expect("sandbox launch binding");
        let frames = vec![
            correlated_event_frame(
                2,
                1,
                command_id,
                opening_token,
                DebugEvent::StateChanged(opening.clone()),
            ),
            correlated_event_frame(
                3,
                2,
                command_id,
                awaiting_token,
                DebugEvent::StateChanged(awaiting),
            ),
            correlated_event_frame(
                4,
                3,
                command_id,
                awaiting_token,
                DebugEvent::SandboxAttested(attestation),
            ),
            correlated_event_frame(
                5,
                4,
                command_id,
                attested_token,
                DebugEvent::LiveTargetBound {
                    state: attested_token,
                    binding: binding.clone(),
                },
            ),
            correlated_event_frame(
                6,
                5,
                command_id,
                stopped_token,
                DebugEvent::StateChanged(stopped.clone()),
            ),
            correlated_event_frame(
                7,
                6,
                command_id,
                stopped_token,
                DebugEvent::CommandResult {
                    command_id,
                    outcome: CommandOutcome::Succeeded,
                },
            ),
        ];
        let batch = HostResponseBatch::try_from_frames(frames, DEFAULT_HOST_RESPONSE_LIMITS)
            .expect("bounded sandbox launch response");

        let receipt = client
            .accept_response_batch(&envelope, checkpoint, Some(opening), batch)
            .expect("accept exact sandbox launch response");
        assert_eq!(receipt.outcome, CommandOutcome::Succeeded);
        assert_eq!(client.session_state(), Some(&stopped));
        assert_eq!(client.live_target_binding(), Some(&binding));
        assert_eq!(binding.process(), &process);
        assert_eq!(
            binding
                .address_for_rva(0x1_1000)
                .expect("translate sandbox RVA"),
            MemoryAddress::new(0x0000_7ff8_6001_1000)
        );
    }

    #[test]
    fn launch_binding_rejects_missing_forged_and_replayed_evidence() {
        let host_binary = BinaryId::digest(b"host launch binding requirement");
        let risk_id = HostRiskLeaseId::new("f".repeat(64)).expect("host-risk id");
        let host_target = LaunchTarget {
            binary_id: host_binary.clone(),
            executable: PathBuf::from("host-launch.exe"),
            arguments: Vec::new(),
            working_directory: None,
            environment: LaunchEnvironment::Host {
                risk_lease: risk_id.clone(),
            },
            stop_before_entry: true,
        };
        let mut host_reducer =
            SessionMachine::new(session_id(), provisioning_epoch(), helper_build());
        host_reducer
            .register_host_risk_verifier(HostRiskVerifier::new(
                risk_id,
                session_id(),
                provisioning_epoch(),
                HostRiskOperation::Launch {
                    intent: HostLaunchIntent::from_target(&host_target)
                        .expect("host launch intent"),
                },
            ))
            .expect("register verifier");
        let host_envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(1).expect("command id"),
            session_id: Some(session_id()),
            expected_state: Some(host_reducer.state().state_token()),
            command: DebugCommand::Open(DebugTargetRequest::Launch(host_target)),
        };
        let _host_checkpoint = host_reducer
            .begin_remote_command(&host_envelope)
            .expect("begin host launch");
        host_reducer
            .mark_stopped(
                StopReason::Initial,
                ThreadId::new(3).expect("host launch thread"),
            )
            .expect("host launch stopped");
        let mut host_evidence = ResponseEvidence {
            state_changed: true,
            command_state_observed: true,
            ..ResponseEvidence::default()
        };
        assert_eq!(
            validate_success_evidence(&host_envelope, &host_reducer, &host_evidence),
            Err(DebugHostClientError::MissingCommandEvidence {
                command_id: host_envelope.command_id,
                command: "host-launch-binding",
                final_state: SessionStateKind::Stopped,
            })
        );
        let forged_binary = BinaryId::digest(b"forged host launch mapping");
        let forged_process = ProcessIdentity {
            process_id: ProcessId::new(8_002).expect("forged process id"),
            start_key: ProcessStartKey::new(55_002).expect("forged process start key"),
            binary_id: forged_binary.clone(),
        };
        let forged = LiveTargetBinding::new(
            forged_process,
            forged_binary.clone(),
            MemoryAddress::new(0x0000_7ff7_3000_0000),
            0x5_0000,
        )
        .expect("structurally valid forged binding");
        let mut current = None;
        assert_eq!(
            accept_live_target_binding(
                &host_envelope,
                &host_reducer,
                &mut current,
                &forged,
                &mut host_evidence,
            ),
            Err(DebugHostClientError::LiveTargetBinaryMismatch {
                expected: host_binary,
                actual: forged_binary,
            })
        );
        assert!(current.is_none());

        let mut sandbox_reducer =
            SessionMachine::new(session_id(), provisioning_epoch(), helper_build());
        let sandbox_envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(1).expect("command id"),
            session_id: Some(session_id()),
            expected_state: Some(sandbox_reducer.state().state_token()),
            command: DebugCommand::Open(sandbox_target()),
        };
        let _sandbox_checkpoint = sandbox_reducer
            .begin_remote_command(&sandbox_envelope)
            .expect("begin sandbox launch");
        let expected = sandbox_reducer
            .expected_attestation()
            .expect("sandbox expectation")
            .clone();
        let process = test_process_identity(&expected);
        let exact = LiveTargetBinding::new(
            process.clone(),
            process.binary_id.clone(),
            MemoryAddress::new(0x0000_7ff8_7000_0000),
            0x8_0000,
        )
        .expect("exact sandbox mapping");
        let mut sandbox_evidence = ResponseEvidence {
            command_state_observed: true,
            ..ResponseEvidence::default()
        };
        assert_eq!(
            accept_live_target_binding(
                &sandbox_envelope,
                &sandbox_reducer,
                &mut current,
                &exact,
                &mut sandbox_evidence,
            ),
            Err(
                DebugHostClientError::LiveTargetBindingBeforeSandboxAttestation {
                    command_id: sandbox_envelope.command_id,
                }
            )
        );
        sandbox_reducer
            .target_created_suspended(process.clone())
            .expect("record suspended sandbox target");
        let attestation = test_attestation(&expected);
        sandbox_reducer
            .accept_sandbox_attestation(&attestation)
            .expect("accept exact sandbox attestation");
        sandbox_evidence.attestation_accepted = true;
        sandbox_reducer
            .mark_stopped(
                StopReason::Initial,
                ThreadId::new(4).expect("sandbox launch thread"),
            )
            .expect("sandbox launch stopped");
        let missing_sandbox_evidence = ResponseEvidence {
            state_changed: true,
            command_state_observed: true,
            attestation_accepted: true,
            ..ResponseEvidence::default()
        };
        assert_eq!(
            validate_success_evidence(
                &sandbox_envelope,
                &sandbox_reducer,
                &missing_sandbox_evidence,
            ),
            Err(DebugHostClientError::MissingCommandEvidence {
                command_id: sandbox_envelope.command_id,
                command: "sandboxed-launch-binding",
                final_state: SessionStateKind::Stopped,
            })
        );

        let replayed_process = ProcessIdentity {
            process_id: process.process_id,
            start_key: ProcessStartKey::new(process.start_key.get() + 1)
                .expect("replayed process start key"),
            binary_id: process.binary_id.clone(),
        };
        let replayed = LiveTargetBinding::new(
            replayed_process.clone(),
            replayed_process.binary_id.clone(),
            MemoryAddress::new(0x0000_7ff8_7000_0000),
            0x8_0000,
        )
        .expect("structurally valid replayed mapping");
        assert_eq!(
            accept_live_target_binding(
                &sandbox_envelope,
                &sandbox_reducer,
                &mut current,
                &replayed,
                &mut sandbox_evidence,
            ),
            Err(DebugHostClientError::LiveTargetProcessMismatch {
                expected: process,
                actual: replayed_process,
            })
        );
        accept_live_target_binding(
            &sandbox_envelope,
            &sandbox_reducer,
            &mut current,
            &exact,
            &mut sandbox_evidence,
        )
        .expect("accept exact sandbox mapping once");
        assert_eq!(
            accept_live_target_binding(
                &sandbox_envelope,
                &sandbox_reducer,
                &mut current,
                &exact,
                &mut sandbox_evidence,
            ),
            Err(DebugHostClientError::DuplicateLiveTargetBinding)
        );

        let mut offline_reducer =
            SessionMachine::new(session_id(), provisioning_epoch(), helper_build());
        let offline_envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(1).expect("command id"),
            session_id: Some(session_id()),
            expected_state: Some(offline_reducer.state().state_token()),
            command: DebugCommand::Open(DebugTargetRequest::Offline(OfflineTarget {
                path: PathBuf::from("offline.exe"),
            })),
        };
        let _offline_checkpoint = offline_reducer
            .begin_remote_command(&offline_envelope)
            .expect("begin offline open");
        let mut offline_binding = None;
        let mut offline_evidence = ResponseEvidence {
            command_state_observed: true,
            ..ResponseEvidence::default()
        };
        assert_eq!(
            accept_live_target_binding(
                &offline_envelope,
                &offline_reducer,
                &mut offline_binding,
                &exact,
                &mut offline_evidence,
            ),
            Err(DebugHostClientError::UnexpectedCommandEvidence {
                command_id: offline_envelope.command_id,
                evidence: "live-target-binding",
            })
        );
        assert!(offline_binding.is_none());
    }

    #[test]
    fn async_pump_accepts_exact_uncorrelated_stop_observation() {
        let stopped = SessionState::Stopped {
            token: StopToken {
                state: next_async_state_token(),
                stop_id: StopId::new(2).expect("second stop id"),
            },
            reason: StopReason::UserPause,
            thread_id: ThreadId::new(10).expect("stopped thread id"),
        };
        let frame = async_state_frame(2, 1, stopped.clone(), None);
        let mut client = running_async_client(vec![vec![frame]]);

        let events = client
            .pump_inbound(HostPollWait::immediate())
            .expect("accept async stop");

        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0].event,
            DebugEvent::StateChanged(state) if state == &stopped
        ));
        assert_eq!(client.session_state(), Some(&stopped));
        assert_eq!(
            client.connection_state(),
            ClientConnectionState::SessionOpen
        );
        assert!(
            events
                .iter()
                .all(|event| !matches!(&event.event, DebugEvent::CommandResult { .. }))
        );
    }

    #[test]
    fn async_pump_rejects_wrong_stop_id_without_mutating_reducer() {
        let forged = SessionState::Stopped {
            token: StopToken {
                state: next_async_state_token(),
                stop_id: StopId::new(99).expect("forged stop id"),
            },
            reason: StopReason::UserPause,
            thread_id: ThreadId::new(10).expect("stopped thread id"),
        };
        let frame = async_state_frame(2, 1, forged.clone(), None);
        let mut client = running_async_client(vec![vec![frame]]);
        let before = client.session_state().expect("running state").clone();

        assert!(matches!(
            client.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::ReducerStateMismatch {
                expected: SessionState::Stopped {
                    token: StopToken { stop_id, .. },
                    ..
                },
                actual,
            }) if stop_id == StopId::new(2).expect("canonical stop id") && actual == forged
        ));
        let session = client
            .session
            .as_ref()
            .expect("diagnostic session retained");
        assert_eq!(session.reducer.state(), &before);
        assert_eq!(session.verified_state, before);
        assert_eq!(client.next_inbound_frame_sequence, 2);
        assert_eq!(client.event_cursor, EventSequenceCursor::default());
        let replayed = client
            .session
            .as_mut()
            .expect("diagnostic session retained")
            .reducer
            .mark_stopped(
                StopReason::UserPause,
                ThreadId::new(10).expect("stopped thread id"),
            )
            .expect("rollback restored running reducer and stop watermark");
        assert!(matches!(
            replayed,
            SessionState::Stopped {
                token: StopToken { stop_id, .. },
                ..
            } if *stop_id == StopId::new(2).expect("canonical stop id")
        ));
    }

    #[test]
    fn async_pump_stopped_to_stopped_matches_reducer_contract() {
        let first = SessionState::Stopped {
            token: StopToken {
                state: next_async_state_token(),
                stop_id: StopId::new(2).expect("second stop id"),
            },
            reason: StopReason::UserPause,
            thread_id: ThreadId::new(10).expect("first stopped thread"),
        };
        let second = SessionState::Stopped {
            token: StopToken {
                state: StateToken {
                    session_id: session_id(),
                    generation: StateGeneration::new(6).expect("following generation"),
                },
                stop_id: StopId::new(3).expect("third stop id"),
            },
            reason: StopReason::SingleStep,
            thread_id: ThreadId::new(11).expect("second stopped thread"),
        };
        let frames = vec![
            async_state_frame(2, 1, first, None),
            async_state_frame(3, 2, second, None),
        ];
        let mut client = running_async_client(vec![frames]);
        let before = client.session_state().expect("running state").clone();

        assert!(matches!(
            client.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::SessionMachine(
                SessionMachineError::InvalidTransition {
                    from: SessionStateKind::Stopped,
                    action: "mark stopped",
                }
            ))
        ));
        let session = client
            .session
            .as_ref()
            .expect("diagnostic session retained");
        assert_eq!(session.reducer.state(), &before);
        assert_eq!(session.verified_state, before);
        assert_eq!(client.next_inbound_frame_sequence, 2);
        assert_eq!(client.event_cursor, EventSequenceCursor::default());
        let replayed = client
            .session
            .as_mut()
            .expect("diagnostic session retained")
            .reducer
            .mark_stopped(
                StopReason::UserPause,
                ThreadId::new(10).expect("stopped thread id"),
            )
            .expect("whole-batch rollback restored reducer");
        assert!(matches!(
            replayed,
            SessionState::Stopped {
                token: StopToken { stop_id, .. },
                ..
            } if *stop_id == StopId::new(2).expect("canonical stop id")
        ));
    }

    #[test]
    fn async_pump_accepts_exact_uncorrelated_exit_observation() {
        let exited = SessionState::Exited {
            token: next_async_state_token(),
            exit_code: 0x55,
        };
        let frame = async_state_frame(2, 1, exited.clone(), None);
        let mut client = running_async_client(vec![vec![frame]]);
        client
            .session
            .as_mut()
            .expect("active session")
            .live_target_binding = Some(async_live_binding());
        assert!(client.live_target_binding().is_some());

        let events = client
            .pump_inbound(HostPollWait::from_millis(25).expect("bounded poll wait"))
            .expect("accept async exit");

        assert_eq!(events.len(), 1);
        assert_eq!(client.session_state(), Some(&exited));
        assert!(matches!(
            &events[0].event,
            DebugEvent::StateChanged(SessionState::Exited {
                exit_code: 0x55,
                ..
            })
        ));
        assert!(client.live_target_binding().is_none());
    }

    #[test]
    fn submit_routes_unsolicited_event_preceding_correlated_response_in_sequence() {
        let command_id = CommandId::new(3).expect("next command id");
        let pausing_token = StateToken {
            session_id: session_id(),
            generation: StateGeneration::new(5).expect("pausing generation"),
        };
        let pausing = SessionState::Pausing {
            token: pausing_token,
        };
        let stopped = SessionState::Stopped {
            token: StopToken {
                state: StateToken {
                    session_id: session_id(),
                    generation: StateGeneration::new(6).expect("stopped generation"),
                },
                stop_id: StopId::new(2).expect("second stop id"),
            },
            reason: StopReason::UserPause,
            thread_id: ThreadId::new(10).expect("stopped thread"),
        };
        let frames = vec![
            async_state_frame(2, 1, stopped.clone(), None),
            correlated_event_frame(
                3,
                2,
                command_id,
                pausing_token,
                DebugEvent::StateChanged(pausing),
            ),
            correlated_event_frame(
                4,
                3,
                command_id,
                stopped.state_token(),
                DebugEvent::CommandResult {
                    command_id,
                    outcome: CommandOutcome::Succeeded,
                },
            ),
        ];
        let transport = ScriptedExchangeHost::new(vec![frames]);
        let connected =
            DebugHostClient::connect(transport, [0x6d; 16], "controller/build-7", "host/build-4")
                .expect("connect scripted test host");
        let mut client = prime_running_client(connected);
        client.next_command_id = command_id.get();
        let SessionState::Running { token: run } = client
            .session_state()
            .expect("running state before pause")
            .clone()
        else {
            panic!("synthetic client is not running")
        };

        let receipt = client
            .submit(DebugCommand::Pause { run })
            .expect("route async stop before correlated pause response");

        assert_eq!(receipt.command_id, command_id);
        assert_eq!(receipt.outcome, CommandOutcome::Succeeded);
        assert_eq!(receipt.events.len(), 2);
        assert!(
            receipt
                .events
                .iter()
                .all(|event| event.caused_by == Some(command_id))
        );
        assert_eq!(client.session_state(), Some(&stopped));
        assert_eq!(client.next_inbound_frame_sequence, 5);
        let mut expected_cursor = EventSequenceCursor::default();
        for sequence in 1..=3 {
            expected_cursor
                .observe(EventSequence::new(sequence).expect("event sequence"))
                .expect("contiguous event sequence");
        }
        assert_eq!(client.event_cursor, expected_cursor);
        assert_eq!(client.pending_unsolicited_events.len(), 1);

        let routed = client
            .pump_inbound(HostPollWait::immediate())
            .expect("drain routed async event without another transport read");
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].caused_by, None);
        assert!(matches!(
            &routed[0].event,
            DebugEvent::StateChanged(state) if state == &stopped
        ));
        assert!(client.pending_unsolicited_events.is_empty());
    }

    #[test]
    fn submit_rejects_unsolicited_event_after_correlated_response_without_cursor_advance() {
        let command_id = CommandId::new(3).expect("next command id");
        let pausing_token = StateToken {
            session_id: session_id(),
            generation: StateGeneration::new(5).expect("pausing generation"),
        };
        let stopped = SessionState::Stopped {
            token: StopToken {
                state: StateToken {
                    session_id: session_id(),
                    generation: StateGeneration::new(6).expect("stopped generation"),
                },
                stop_id: StopId::new(2).expect("second stop id"),
            },
            reason: StopReason::UserPause,
            thread_id: ThreadId::new(10).expect("stopped thread"),
        };
        let frames = vec![
            correlated_event_frame(
                2,
                1,
                command_id,
                pausing_token,
                DebugEvent::StateChanged(SessionState::Pausing {
                    token: pausing_token,
                }),
            ),
            async_state_frame(3, 2, stopped.clone(), None),
            correlated_event_frame(
                4,
                3,
                command_id,
                stopped.state_token(),
                DebugEvent::CommandResult {
                    command_id,
                    outcome: CommandOutcome::Succeeded,
                },
            ),
        ];
        let transport = ScriptedExchangeHost::new(vec![frames]);
        let connected =
            DebugHostClient::connect(transport, [0x6d; 16], "controller/build-7", "host/build-4")
                .expect("connect scripted test host");
        let mut client = prime_running_client(connected);
        client.next_command_id = command_id.get();
        let verified_before = client.session_state().expect("running state").clone();
        let SessionState::Running { token: run } = verified_before.clone() else {
            panic!("synthetic client is not running")
        };

        assert_eq!(
            client.submit(DebugCommand::Pause { run }),
            Err(DebugHostClientError::UnsolicitedEventAfterCorrelatedResponse { command_id })
        );
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
        assert_eq!(client.session_state(), Some(&verified_before));
        assert_eq!(
            client
                .session
                .as_ref()
                .expect("diagnostic session")
                .reducer
                .state()
                .kind(),
            SessionStateKind::Pausing
        );
        assert_eq!(client.next_inbound_frame_sequence, 2);
        assert_eq!(client.event_cursor, EventSequenceCursor::default());
        assert!(client.pending_unsolicited_events.is_empty());
    }

    #[test]
    fn submit_poisons_before_applying_prefix_when_unsolicited_queue_is_full() {
        let command_id = CommandId::new(3).expect("next command id");
        let pausing_token = StateToken {
            session_id: session_id(),
            generation: StateGeneration::new(5).expect("pausing generation"),
        };
        let stopped = SessionState::Stopped {
            token: StopToken {
                state: StateToken {
                    session_id: session_id(),
                    generation: StateGeneration::new(6).expect("stopped generation"),
                },
                stop_id: StopId::new(2).expect("second stop id"),
            },
            reason: StopReason::UserPause,
            thread_id: ThreadId::new(10).expect("stopped thread"),
        };
        let prefix = async_state_frame(2, 1, stopped.clone(), None);
        let queued = decode_event_frame(&prefix).expect("decode queue fixture");
        let frames = vec![
            prefix,
            correlated_event_frame(
                3,
                2,
                command_id,
                pausing_token,
                DebugEvent::StateChanged(SessionState::Pausing {
                    token: pausing_token,
                }),
            ),
            correlated_event_frame(
                4,
                3,
                command_id,
                stopped.state_token(),
                DebugEvent::CommandResult {
                    command_id,
                    outcome: CommandOutcome::Succeeded,
                },
            ),
        ];
        let transport = ScriptedExchangeHost::new(vec![frames]);
        let connected =
            DebugHostClient::connect(transport, [0x6d; 16], "controller/build-7", "host/build-4")
                .expect("connect scripted test host");
        let mut client = prime_running_client(connected);
        client.next_command_id = command_id.get();
        client.pending_unsolicited_events =
            std::iter::repeat_n(queued, MAX_PENDING_UNSOLICITED_EVENTS).collect();
        let verified_before = client.session_state().expect("running state").clone();
        let SessionState::Running { token: run } = verified_before.clone() else {
            panic!("synthetic client is not running")
        };

        assert_eq!(
            client.submit(DebugCommand::Pause { run }),
            Err(DebugHostClientError::PendingUnsolicitedEventQueueFull {
                actual: MAX_PENDING_UNSOLICITED_EVENTS + 1,
                maximum: MAX_PENDING_UNSOLICITED_EVENTS,
            })
        );
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
        assert_eq!(client.session_state(), Some(&verified_before));
        assert_eq!(
            client
                .session
                .as_ref()
                .expect("diagnostic session")
                .reducer
                .state()
                .kind(),
            SessionStateKind::Pausing
        );
        assert_eq!(client.next_inbound_frame_sequence, 2);
        assert_eq!(client.event_cursor, EventSequenceCursor::default());
        assert_eq!(
            client.pending_unsolicited_events.len(),
            MAX_PENDING_UNSOLICITED_EVENTS
        );
    }

    #[test]
    fn async_pump_validates_a_whole_batch_before_applying_any_prefix() {
        let stopped = SessionState::Stopped {
            token: StopToken {
                state: next_async_state_token(),
                stop_id: StopId::new(2).expect("second stop id"),
            },
            reason: StopReason::UserPause,
            thread_id: ThreadId::new(10).expect("stopped thread id"),
        };
        let first = async_state_frame(2, 1, stopped.clone(), None);
        let second = async_event_frame(
            3,
            2,
            stopped.state_token(),
            DebugEvent::Warning {
                code: "host-warning".to_owned(),
                message: "unsupported in unsolicited batches".to_owned(),
            },
        );
        let mut client = running_async_client(vec![vec![first, second]]);
        client
            .session
            .as_mut()
            .expect("active session")
            .live_target_binding = Some(async_live_binding());

        assert_eq!(
            client.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::UnexpectedUnsolicitedEvent)
        );
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
        assert_eq!(
            client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Running)
        );
        assert!(client.live_target_binding().is_none());
        assert!(
            client
                .session
                .as_ref()
                .expect("retained diagnostic session")
                .live_target_binding
                .is_none()
        );
        assert_eq!(client.next_inbound_frame_sequence, 2);
        assert_eq!(client.event_cursor, EventSequenceCursor::default());
    }

    #[test]
    fn async_pump_rejects_empty_typed_version_and_unsupported_payloads() {
        let mut empty = running_async_client(vec![Vec::new()]);
        assert_eq!(
            empty.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::EmptyUnsolicitedEventBatch)
        );
        assert_eq!(empty.connection_state(), ClientConnectionState::Failed);

        let exited = SessionState::Exited {
            token: next_async_state_token(),
            exit_code: 1,
        };
        let legacy = with_legacy_typed_minor(async_state_frame(2, 1, exited, None));
        let mut wrong_version = running_async_client(vec![vec![legacy]]);
        assert!(matches!(
            wrong_version.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::Codec(
                HostCodecError::ProtocolVersionMismatch {
                    wire_major,
                    wire_minor,
                    envelope_major,
                    envelope_minor,
                }
            )) if wire_major == crate::host_wire::PROTOCOL_MAJOR
                && wire_minor == crate::host_wire::PROTOCOL_MINOR
                && envelope_major == crate::protocol::PROTOCOL_MAJOR
                && envelope_minor == crate::protocol::PROTOCOL_MINOR - 1
        ));
        assert_eq!(
            wrong_version.connection_state(),
            ClientConnectionState::Failed
        );

        let pausing = SessionState::Pausing {
            token: next_async_state_token(),
        };
        let mut unsupported_state =
            running_async_client(vec![vec![async_state_frame(2, 1, pausing, None)]]);
        assert_eq!(
            unsupported_state.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::UnexpectedUnsolicitedState {
                state: SessionStateKind::Pausing,
            })
        );

        let running_state = StateToken {
            session_id: session_id(),
            generation: StateGeneration::new(4).expect("running generation"),
        };
        let warning = async_event_frame(
            2,
            1,
            running_state,
            DebugEvent::Warning {
                code: "unexpected".to_owned(),
                message: "not an unsolicited state event".to_owned(),
            },
        );
        let mut unsupported_event = running_async_client(vec![vec![warning]]);
        assert_eq!(
            unsupported_event.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::UnexpectedUnsolicitedEvent)
        );
    }

    #[test]
    fn async_poll_transport_failure_is_terminal_and_invalidates_binding() {
        let mut client = running_async_client(Vec::new());
        client.transport.poll_error = Some(HostTransportError::backend("poll backend failed"));
        client
            .session
            .as_mut()
            .expect("active session")
            .live_target_binding = Some(async_live_binding());
        assert!(matches!(
            client.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::Transport(
                HostTransportError::Backend { .. }
            ))
        ));
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
        assert!(client.live_target_binding().is_none());
        assert!(
            client
                .session
                .as_ref()
                .expect("retained diagnostic session")
                .live_target_binding
                .is_none()
        );
    }

    #[test]
    fn async_pump_rejects_frame_and_event_sequence_gaps_and_poisons_connection() {
        let exited = SessionState::Exited {
            token: next_async_state_token(),
            exit_code: 1,
        };
        let frame_gap = async_state_frame(3, 1, exited.clone(), None);
        let mut frame_gap_client = running_async_client(vec![vec![frame_gap]]);
        assert_eq!(
            frame_gap_client.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::UnexpectedFrameSequence {
                expected: 2,
                actual: 3,
            })
        );
        assert_eq!(
            frame_gap_client.connection_state(),
            ClientConnectionState::Failed
        );
        assert_eq!(
            frame_gap_client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Running)
        );

        let event_gap = async_state_frame(2, 2, exited, None);
        let mut event_gap_client = running_async_client(vec![vec![event_gap]]);

        assert!(matches!(
            event_gap_client.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::Protocol(
                ProtocolValidationError::UnexpectedEventSequence {
                    expected: 1,
                    actual: 2
                }
            ))
        ));
        assert_eq!(
            event_gap_client.connection_state(),
            ClientConnectionState::Failed
        );
        assert_eq!(
            event_gap_client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Running)
        );
    }

    #[test]
    fn async_pump_rejects_wrong_session_without_advancing_verified_state() {
        let wrong_session = SessionId::new(99).expect("wrong session id");
        let exited = SessionState::Exited {
            token: StateToken {
                session_id: wrong_session,
                generation: StateGeneration::new(5).expect("next state generation"),
            },
            exit_code: 1,
        };
        let frame = async_state_frame(2, 1, exited, None);
        let mut client = running_async_client(vec![vec![frame]]);

        assert!(matches!(
            client.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::UnexpectedEventSession {
                expected,
                actual: Some(actual)
            }) if expected == session_id() && actual == wrong_session
        ));
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
        assert_eq!(
            client.session_state().map(SessionState::kind),
            Some(SessionStateKind::Running)
        );
    }

    #[test]
    fn async_pump_rejects_command_correlated_frame() {
        let stopped = SessionState::Stopped {
            token: StopToken {
                state: next_async_state_token(),
                stop_id: StopId::new(2).expect("second stop id"),
            },
            reason: StopReason::UserPause,
            thread_id: ThreadId::new(10).expect("stopped thread id"),
        };
        let correlation = CommandId::new(77).expect("command correlation");
        let frame = async_state_frame(2, 1, stopped, Some(correlation));
        let mut client = running_async_client(vec![vec![frame]]);

        assert_eq!(
            client.pump_inbound(HostPollWait::immediate()),
            Err(DebugHostClientError::UnsolicitedEventCarriedCorrelation {
                command_id: correlation
            })
        );
        assert_eq!(client.connection_state(), ClientConnectionState::Failed);
    }

    #[test]
    fn request_response_hosts_default_to_bounded_empty_poll_without_affecting_submit() {
        assert_eq!(
            HostPollWait::from_millis(MAX_HOST_POLL_WAIT_MILLIS + 1),
            Err(HostPollWaitError::TooLong {
                actual: MAX_HOST_POLL_WAIT_MILLIS + 1,
                maximum: MAX_HOST_POLL_WAIT_MILLIS,
            })
        );
        let mut client = client(host());
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .expect("begin offline session");
        let open = client
            .submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("sample.exe"),
                },
            )))
            .expect("open through compatibility exchange path");
        assert_eq!(open.outcome, CommandOutcome::Succeeded);
        assert!(
            client
                .pump_inbound(HostPollWait::immediate())
                .expect("default poll timeout")
                .is_empty()
        );
        let state = client.session_state().expect("offline state").state_token();
        let close = client
            .submit(DebugCommand::Close { state })
            .expect("close after empty poll");
        assert_eq!(close.outcome, CommandOutcome::Succeeded);
    }
}
