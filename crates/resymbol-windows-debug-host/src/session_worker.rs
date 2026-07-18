//! Authenticated session-reducer orchestration over the same-thread provider.
//!
//! The generic core stays crate-private: public transport construction must
//! choose the concrete backend and keep this value on its owning OS thread.

use std::fmt;

use resymbol_debugger::{
    CommandId, LiveTargetBinding, MemoryAddress, ReadViewToken, SessionMachineError, SessionState,
    ValidatedLocalLivePatchReceipt,
};
use thiserror::Error;

use super::{
    DebugHostCleanupEvidence, DebugHostError, DebugHostMemoryWriteError,
    DebugHostMemoryWriteReceipt, PendingStopEvidence,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionWorkerHealth {
    /// Reducer and provider evidence agree and commands may be accepted.
    Ready,
    /// A target-side effect requires explicit provider cleanup.
    CleanupRequired,
    /// Reducer/provider correlation failed and ordinary commands are frozen.
    Poisoned,
    /// Explicit provider cleanup completed and this core is terminal.
    ///
    /// This does not synthesize `SessionState::Closed` or a controller close
    /// receipt. Cleanup receipts retain the last reducer snapshot unchanged.
    Closed,
}

impl fmt::Display for SessionWorkerHealth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => formatter.write_str("ready"),
            Self::CleanupRequired => formatter.write_str("cleanup required"),
            Self::Poisoned => formatter.write_str("poisoned"),
            Self::Closed => formatter.write_str("closed"),
        }
    }
}

/// Correlated result of accepting a debug-attach open command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a successful attach receipt must be published"]
pub struct DebugAttachReceipt {
    command_id: resymbol_debugger::CommandId,
    binding: resymbol_debugger::LiveTargetBinding,
    pending_stop: PendingStopEvidence,
    state: SessionState,
}

impl DebugAttachReceipt {
    #[must_use]
    pub const fn command_id(&self) -> resymbol_debugger::CommandId {
        self.command_id
    }

    #[must_use]
    pub const fn binding(&self) -> &resymbol_debugger::LiveTargetBinding {
        &self.binding
    }

    pub const fn pending_stop(&self) -> &PendingStopEvidence {
        &self.pending_stop
    }

    #[must_use]
    pub const fn state(&self) -> &SessionState {
        &self.state
    }
}

/// Provider mutation evidence paired with reducer and history proof.
#[derive(Debug)]
#[must_use = "a successful memory-write receipt must be published"]
pub struct SessionWorkerMemoryWriteReceipt {
    provider: DebugHostMemoryWriteReceipt,
    state: SessionState,
    history_receipt: ValidatedLocalLivePatchReceipt,
}

impl SessionWorkerMemoryWriteReceipt {
    pub const fn provider(&self) -> &DebugHostMemoryWriteReceipt {
        &self.provider
    }

    #[must_use]
    pub const fn state(&self) -> &SessionState {
        &self.state
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        DebugHostMemoryWriteReceipt,
        SessionState,
        ValidatedLocalLivePatchReceipt,
    ) {
        (self.provider, self.state, self.history_receipt)
    }
}

/// Proved no-effect provider rejection paired with restored reducer state and
/// the one-use history proof that clears the dispatched reservation.
#[derive(Debug)]
#[must_use = "a safe memory-write rejection must resolve live-patch history"]
pub struct SessionWorkerMemoryWriteNoEffectReceipt {
    error: DebugHostMemoryWriteError,
    state: SessionState,
    history_receipt: ValidatedLocalLivePatchReceipt,
}

impl SessionWorkerMemoryWriteNoEffectReceipt {
    #[must_use]
    pub const fn error(&self) -> &DebugHostMemoryWriteError {
        &self.error
    }

    #[must_use]
    pub const fn state(&self) -> &SessionState {
        &self.state
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        DebugHostMemoryWriteError,
        SessionState,
        ValidatedLocalLivePatchReceipt,
    ) {
        (self.error, self.state, self.history_receipt)
    }
}

/// Safe reducer/provider resolution of one local live-memory write.
#[derive(Debug)]
#[must_use = "memory-write outcomes carry one-use live-patch history evidence"]
pub enum SessionWorkerMemoryWriteOutcome {
    Committed(SessionWorkerMemoryWriteReceipt),
    RejectedNoEffect(SessionWorkerMemoryWriteNoEffectReceipt),
}

/// Exact stopped-memory read evidence paired with committed reducer state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a successful memory-read receipt must be published"]
pub struct SessionWorkerMemoryReadReceipt {
    command_id: CommandId,
    view: ReadViewToken,
    binding: LiveTargetBinding,
    pending_stop: PendingStopEvidence,
    address: MemoryAddress,
    bytes: Vec<u8>,
    state: SessionState,
}

impl SessionWorkerMemoryReadReceipt {
    #[must_use]
    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }

    #[must_use]
    pub const fn view(&self) -> ReadViewToken {
        self.view
    }

    #[must_use]
    pub const fn binding(&self) -> &LiveTargetBinding {
        &self.binding
    }

    pub const fn pending_stop(&self) -> &PendingStopEvidence {
        &self.pending_stop
    }

    #[must_use]
    pub const fn address(&self) -> MemoryAddress {
        self.address
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn state(&self) -> &SessionState {
        &self.state
    }
}

/// Explicit provider cleanup evidence and the worker health after cleanup.
///
/// A complete receipt closes only this provider/core owner. Its `state` remains
/// the reducer snapshot observed at cleanup and is not a synthetic logical
/// close acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "cleanup evidence must be inspected before releasing the worker"]
pub struct SessionWorkerCleanupReceipt {
    evidence: Option<DebugHostCleanupEvidence>,
    health: SessionWorkerHealth,
    state: SessionState,
}

impl SessionWorkerCleanupReceipt {
    /// None means the provider was already detached, so no OS cleanup steps
    /// were required by this call.
    #[must_use]
    pub const fn evidence(&self) -> Option<&DebugHostCleanupEvidence> {
        self.evidence.as_ref()
    }

    #[must_use]
    pub const fn health(&self) -> SessionWorkerHealth {
        self.health
    }

    #[must_use]
    pub const fn state(&self) -> &SessionState {
        &self.state
    }

    #[must_use]
    pub fn complete(&self) -> bool {
        self.evidence
            .as_ref()
            .is_none_or(DebugHostCleanupEvidence::complete)
    }
}

/// Typed failure at the reducer/provider orchestration boundary.
#[derive(Debug, Error)]
pub enum SessionWorkerError {
    #[error("session worker is {health} and cannot accept this operation")]
    Unavailable { health: SessionWorkerHealth },
    #[error("session-worker debug attach accepts only an Open host Debug attach command")]
    NotDebugAttachCommand,
    #[error("the open command process identity is not the supplied live-target binding")]
    AttachTargetBindingMismatch,
    #[error("live memory write requires one worker-owned debug attach and retained stop")]
    NotDebugAttached,
    #[error("session-worker live reads accept only a stopped ReadMemory command")]
    NotStoppedReadCommand,
    #[error("session worker observed contradictory owned evidence: {detail}")]
    ContradictoryEvidence { detail: &'static str },
    #[error("session reducer failed while {operation}: {source}")]
    Resolution {
        operation: &'static str,
        #[source]
        source: SessionMachineError,
    },
    #[error(transparent)]
    Reducer(#[from] SessionMachineError),
    #[error(transparent)]
    DebugHost(#[from] DebugHostError),
    #[error(transparent)]
    MemoryWrite(#[from] DebugHostMemoryWriteError),
}

#[cfg(any(windows, test))]
use resymbol_debugger::{
    AttachMode, AttachScope, CommandEnvelope, DebugCommand, DebugTargetRequest, HostRiskLease,
    LocalLiveMemoryWriteReceiptIdentity, RemoteCommandCheckpoint, SessionMachine, StopReason,
};

#[cfg(any(windows, test))]
use super::{DebugAttachLimits, DebugBackend, DebugHostWorker, DebugHostWorkerState};

#[cfg(test)]
use super::AttachedPhase;

#[cfg(any(windows, test))]
#[derive(Debug)]
struct PendingTransaction {
    command_id: CommandId,
    checkpoint: RemoteCommandCheckpoint,
    local_write_receipt_identity: Option<LocalLiveMemoryWriteReceiptIdentity>,
}

/// Single-owner reducer/provider core used by the concrete session worker.
#[cfg(any(windows, test))]
#[derive(Debug)]
pub(crate) struct SessionWorkerCore<B: DebugBackend> {
    machine: SessionMachine,
    provider: DebugHostWorker<B>,
    binding: Option<LiveTargetBinding>,
    pending_stop: Option<PendingStopEvidence>,
    pending_transaction: Option<PendingTransaction>,
    terminal_incomplete_cleanup: Option<DebugHostCleanupEvidence>,
    health: SessionWorkerHealth,
    #[cfg(test)]
    post_dispatch_provider_state_for_test: Option<DebugHostWorkerState>,
}

#[cfg(any(windows, test))]
impl<B: DebugBackend> SessionWorkerCore<B> {
    pub(crate) fn new(machine: SessionMachine, backend: B) -> Self {
        Self {
            machine,
            provider: DebugHostWorker::new(backend),
            binding: None,
            pending_stop: None,
            pending_transaction: None,
            terminal_incomplete_cleanup: None,
            health: SessionWorkerHealth::Ready,
            #[cfg(test)]
            post_dispatch_provider_state_for_test: None,
        }
    }

    pub(crate) const fn health(&self) -> SessionWorkerHealth {
        self.health
    }

    pub(crate) const fn state(&self) -> &SessionState {
        self.machine.state()
    }

    pub(crate) fn provider_state(&self) -> DebugHostWorkerState {
        self.provider.state()
    }

    pub(crate) fn binding(&self) -> Option<&LiveTargetBinding> {
        self.binding.as_ref()
    }

    pub(crate) fn pending_stop(&self) -> Option<&PendingStopEvidence> {
        self.pending_stop.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn backend_for_test(&self) -> &B {
        &self.provider.backend
    }

    #[cfg(test)]
    pub(crate) fn backend_for_test_mut(&mut self) -> &mut B {
        &mut self.provider.backend
    }

    #[cfg(test)]
    pub(crate) fn set_post_dispatch_provider_state_for_test(
        &mut self,
        state: DebugHostWorkerState,
    ) {
        self.post_dispatch_provider_state_for_test = Some(state);
    }

    pub(crate) fn register_host_risk_lease(
        &mut self,
        lease: HostRiskLease,
    ) -> Result<(), SessionWorkerError> {
        self.ensure_can_begin()?;
        self.machine.register_host_risk_lease(lease)?;
        Ok(())
    }

    pub(crate) fn open_debug_attach(
        &mut self,
        envelope: CommandEnvelope,
        binding: LiveTargetBinding,
        limits: DebugAttachLimits,
    ) -> Result<DebugAttachReceipt, SessionWorkerError> {
        self.ensure_can_begin()?;
        let command_id = envelope.command_id;
        match &envelope.command {
            DebugCommand::Open(DebugTargetRequest::Attach(target))
                if target.mode == AttachMode::Debug
                    && matches!(
                        &target.scope,
                        AttachScope::Host { process, .. } if process == binding.process()
                    ) => {}
            DebugCommand::Open(DebugTargetRequest::Attach(target))
                if target.mode == AttachMode::Debug
                    && matches!(&target.scope, AttachScope::Host { .. }) =>
            {
                return Err(SessionWorkerError::AttachTargetBindingMismatch);
            }
            _ => return Err(SessionWorkerError::NotDebugAttachCommand),
        }

        let checkpoint = self.machine.begin_remote_command(&envelope)?;
        self.pending_transaction = Some(PendingTransaction {
            command_id,
            checkpoint,
            local_write_receipt_identity: None,
        });

        let pending_stop = match self.provider.attach_after_authorization(&binding, limits) {
            Ok(pending_stop) => pending_stop,
            Err(error) => {
                let incomplete_cleanup = match &error {
                    DebugHostError::CleanupAfterFailure { evidence, .. } => Some(evidence.clone()),
                    _ => None,
                };
                let provider_state = self.provider.state();
                if provider_state == DebugHostWorkerState::Detached && incomplete_cleanup.is_none()
                {
                    self.reject_pending("rejecting effect-free debug attach")?;
                } else {
                    let health = if provider_state == DebugHostWorkerState::CleanupRequired {
                        SessionWorkerHealth::CleanupRequired
                    } else {
                        SessionWorkerHealth::Poisoned
                    };
                    if provider_state == DebugHostWorkerState::Detached {
                        self.terminal_incomplete_cleanup = incomplete_cleanup;
                    }
                    self.fail_and_commit_pending(
                        health,
                        "debug attach failed without confirmed provider cleanup",
                    )?;
                }
                return Err(SessionWorkerError::DebugHost(error));
            }
        };

        self.binding = Some(binding.clone());
        self.pending_stop = Some(pending_stop.clone());
        if self.provider.binding() != Some(&binding)
            || self.provider.pending_stop() != Some(&pending_stop)
        {
            self.fail_and_commit_pending(
                SessionWorkerHealth::Poisoned,
                "debug attach returned contradictory retained evidence",
            )?;
            return Err(SessionWorkerError::ContradictoryEvidence {
                detail: "debug attach success did not match provider-owned binding and stop",
            });
        }

        if let Err(source) = self
            .machine
            .mark_stopped(StopReason::Initial, pending_stop.thread_id())
        {
            self.fail_and_commit_pending(
                SessionWorkerHealth::Poisoned,
                "debug attach stop could not be resolved by the session reducer",
            )?;
            return Err(SessionWorkerError::Resolution {
                operation: "recording the debug-attach stop",
                source,
            });
        }
        self.commit_pending("committing the debug-attach checkpoint")?;

        Ok(DebugAttachReceipt {
            command_id,
            binding,
            pending_stop,
            state: self.machine.state().clone(),
        })
    }

    /// Validates and resolves one exact stopped-memory read transaction.
    pub(crate) fn read_memory(
        &mut self,
        envelope: CommandEnvelope,
    ) -> Result<SessionWorkerMemoryReadReceipt, SessionWorkerError> {
        self.ensure_can_begin()?;
        let (view, address, size) = match &envelope.command {
            DebugCommand::ReadMemory {
                view: ReadViewToken::Stopped { .. },
                address,
                size,
            } => {
                let DebugCommand::ReadMemory { view, .. } = &envelope.command else {
                    unreachable!("read-memory variant matched")
                };
                (*view, *address, *size)
            }
            _ => return Err(SessionWorkerError::NotStoppedReadCommand),
        };
        let binding = self
            .binding
            .clone()
            .ok_or(SessionWorkerError::NotDebugAttached)?;
        let pending_stop = self
            .pending_stop
            .clone()
            .ok_or(SessionWorkerError::NotDebugAttached)?;
        binding
            .rva_for_address_span(address, u64::from(size))
            .map_err(DebugHostError::from)?;
        let expected_len = usize::try_from(size).expect("u32 read size fits usize");
        let command_id = envelope.command_id;
        let checkpoint = self.machine.begin_remote_command(&envelope)?;
        self.pending_transaction = Some(PendingTransaction {
            command_id,
            checkpoint,
            local_write_receipt_identity: None,
        });

        let result = self.provider.read_stopped_main_image(address, expected_len);
        #[cfg(test)]
        self.apply_post_dispatch_provider_state_for_test();

        match result {
            Ok(bytes) => {
                if self.provider.state() != DebugHostWorkerState::Stopped
                    || self.provider.binding() != Some(&binding)
                    || self.provider.pending_stop() != Some(&pending_stop)
                    || bytes.len() != expected_len
                {
                    self.fail_and_commit_pending(
                        SessionWorkerHealth::Poisoned,
                        "memory read returned contradictory provider evidence",
                    )?;
                    return Err(SessionWorkerError::ContradictoryEvidence {
                        detail: "memory-read success did not match retained provider state",
                    });
                }
                self.commit_pending("committing the memory-read checkpoint")?;
                Ok(SessionWorkerMemoryReadReceipt {
                    command_id,
                    view,
                    binding,
                    pending_stop,
                    address,
                    bytes,
                    state: self.machine.state().clone(),
                })
            }
            Err(error) => {
                let provider_retains_exact_stop = self.provider.state()
                    == DebugHostWorkerState::Stopped
                    && self.provider.binding() == Some(&binding)
                    && self.provider.pending_stop() == Some(&pending_stop);
                if provider_retains_exact_stop {
                    self.reject_pending("rejecting the effect-free memory-read checkpoint")?;
                } else {
                    self.fail_and_commit_pending(
                        SessionWorkerHealth::Poisoned,
                        "memory read failure contradicted retained provider state",
                    )?;
                }
                Err(SessionWorkerError::DebugHost(error))
            }
        }
    }

    /// Accepts only the wire envelope. Binding, OS-stop evidence, checkpoint,
    /// and provider ticket never cross this owner boundary.
    pub(crate) fn write_memory(
        &mut self,
        envelope: CommandEnvelope,
    ) -> Result<SessionWorkerMemoryWriteOutcome, SessionWorkerError> {
        self.ensure_can_begin()?;
        let binding = self
            .binding
            .clone()
            .ok_or(SessionWorkerError::NotDebugAttached)?;
        let pending_stop = self
            .pending_stop
            .clone()
            .ok_or(SessionWorkerError::NotDebugAttached)?;
        let command_id = envelope.command_id;
        let (checkpoint, ticket, receipt_identity) = self
            .machine
            .begin_live_memory_write(envelope, binding.clone())?;
        let ticket_stop = ticket.stop();
        let ticket_address = ticket.address();
        let ticket_before = ticket.expected().to_vec();
        let ticket_after = ticket.replacement().to_vec();
        self.pending_transaction = Some(PendingTransaction {
            command_id,
            checkpoint,
            local_write_receipt_identity: Some(receipt_identity),
        });

        let result = {
            let checkpoint = &self
                .pending_transaction
                .as_ref()
                .expect("transaction was retained before provider dispatch")
                .checkpoint;
            self.provider
                .write_stopped_main_image_after_protocol_validation(
                    &pending_stop,
                    checkpoint,
                    ticket,
                )
        };
        #[cfg(test)]
        self.apply_post_dispatch_provider_state_for_test();

        match result {
            Ok(provider) => {
                if self.provider.state() != DebugHostWorkerState::Stopped
                    || self.provider.binding() != Some(&binding)
                    || self.provider.pending_stop() != Some(&pending_stop)
                    || provider.command_id() != command_id
                    || provider.binding() != &binding
                    || provider.pending_stop() != &pending_stop
                    || provider.stop() != ticket_stop
                    || provider.address() != ticket_address
                    || provider.before() != ticket_before.as_slice()
                    || provider.after() != ticket_after.as_slice()
                {
                    self.fail_and_commit_pending(
                        SessionWorkerHealth::Poisoned,
                        "memory write returned contradictory success evidence",
                    )?;
                    return Err(SessionWorkerError::ContradictoryEvidence {
                        detail: "memory-write success did not match worker-owned transaction",
                    });
                }
                let history_receipt = self.resolve_pending_live_write_success(
                    "committing the correlated local memory write",
                )?;
                Ok(SessionWorkerMemoryWriteOutcome::Committed(
                    SessionWorkerMemoryWriteReceipt {
                        provider,
                        state: self.machine.state().clone(),
                        history_receipt,
                    },
                ))
            }
            Err(error) if error.permits_effect_free_checkpoint_rejection() => {
                let provider_retains_exact_stop = self.provider.state()
                    == DebugHostWorkerState::Stopped
                    && self.provider.binding() == Some(&binding)
                    && self.provider.pending_stop() == Some(&pending_stop);
                if provider_retains_exact_stop {
                    if matches!(
                        &error,
                        DebugHostMemoryWriteError::NotStopped
                            | DebugHostMemoryWriteError::PendingStopMismatch
                            | DebugHostMemoryWriteError::CheckpointMismatch
                            | DebugHostMemoryWriteError::TargetBindingMismatch
                    ) {
                        self.reject_pending(
                            "rejecting a contradictory but effect-free memory-write checkpoint",
                        )?;
                        self.health = SessionWorkerHealth::Poisoned;
                        return Err(SessionWorkerError::MemoryWrite(error));
                    }
                    let history_receipt = self.resolve_pending_live_write_no_effect(
                        "resolving the proved no-effect local memory write",
                    )?;
                    Ok(SessionWorkerMemoryWriteOutcome::RejectedNoEffect(
                        SessionWorkerMemoryWriteNoEffectReceipt {
                            error,
                            state: self.machine.state().clone(),
                            history_receipt,
                        },
                    ))
                } else {
                    self.fail_and_commit_pending(
                        SessionWorkerHealth::Poisoned,
                        "effect-free write rejection contradicted retained provider state",
                    )?;
                    Err(SessionWorkerError::MemoryWrite(error))
                }
            }
            Err(error) => {
                let health = if self.provider.state() == DebugHostWorkerState::CleanupRequired
                    && !matches!(&error, DebugHostMemoryWriteError::InvalidEvidence { .. })
                {
                    SessionWorkerHealth::CleanupRequired
                } else {
                    SessionWorkerHealth::Poisoned
                };
                self.fail_and_commit_pending(
                    health,
                    "memory write may have changed the target and requires cleanup",
                )?;
                Err(SessionWorkerError::MemoryWrite(error))
            }
        }
    }

    /// Attempts every provider cleanup step and closes the core only when the
    /// attachment release is confirmed. Cleanup remains callable while frozen.
    pub(crate) fn cleanup(&mut self) -> SessionWorkerCleanupReceipt {
        if let Some(evidence) = self.terminal_incomplete_cleanup.clone() {
            return SessionWorkerCleanupReceipt {
                evidence: Some(evidence),
                health: self.health,
                state: self.machine.state().clone(),
            };
        }
        let evidence = if self.provider.state() == DebugHostWorkerState::Detached {
            None
        } else {
            Some(self.provider.attempt_cleanup())
        };
        let complete = evidence
            .as_ref()
            .is_none_or(DebugHostCleanupEvidence::complete);
        if complete {
            self.binding = None;
            self.pending_stop = None;
            self.pending_transaction = None;
            self.health = SessionWorkerHealth::Closed;
        } else if self.provider.state() == DebugHostWorkerState::Detached {
            self.terminal_incomplete_cleanup = evidence.clone();
            self.health = SessionWorkerHealth::Poisoned;
        } else if self.health != SessionWorkerHealth::Poisoned {
            self.health = SessionWorkerHealth::CleanupRequired;
        }
        SessionWorkerCleanupReceipt {
            evidence,
            health: self.health,
            state: self.machine.state().clone(),
        }
    }

    fn ensure_can_begin(&mut self) -> Result<(), SessionWorkerError> {
        if self.health != SessionWorkerHealth::Ready {
            return Err(SessionWorkerError::Unavailable {
                health: self.health,
            });
        }
        if self.pending_transaction.is_some() {
            self.health = SessionWorkerHealth::Poisoned;
            return Err(SessionWorkerError::ContradictoryEvidence {
                detail: "a prior reducer checkpoint was still pending",
            });
        }
        Ok(())
    }

    fn commit_pending(&mut self, operation: &'static str) -> Result<(), SessionWorkerError> {
        let transaction = self.take_pending()?;
        self.machine
            .commit_remote_command(transaction.checkpoint, transaction.command_id)
            .map(|_| ())
            .map_err(|source| {
                self.health = SessionWorkerHealth::Poisoned;
                SessionWorkerError::Resolution { operation, source }
            })
    }

    fn reject_pending(&mut self, operation: &'static str) -> Result<(), SessionWorkerError> {
        let transaction = self.take_pending()?;
        self.machine
            .reject_remote_command(transaction.checkpoint, transaction.command_id)
            .map(|_| ())
            .map_err(|source| {
                self.health = SessionWorkerHealth::Poisoned;
                SessionWorkerError::Resolution { operation, source }
            })
    }

    fn resolve_pending_live_write_success(
        &mut self,
        operation: &'static str,
    ) -> Result<ValidatedLocalLivePatchReceipt, SessionWorkerError> {
        let transaction = self.take_pending()?;
        let Some(receipt_identity) = transaction.local_write_receipt_identity else {
            self.health = SessionWorkerHealth::Poisoned;
            return Err(SessionWorkerError::ContradictoryEvidence {
                detail: "the local memory-write receipt identity disappeared before commit",
            });
        };
        self.machine
            .resolve_live_memory_write_success(transaction.checkpoint, receipt_identity)
            .map_err(|source| {
                self.health = SessionWorkerHealth::Poisoned;
                SessionWorkerError::Resolution { operation, source }
            })
    }

    fn resolve_pending_live_write_no_effect(
        &mut self,
        operation: &'static str,
    ) -> Result<ValidatedLocalLivePatchReceipt, SessionWorkerError> {
        let transaction = self.take_pending()?;
        let Some(receipt_identity) = transaction.local_write_receipt_identity else {
            self.health = SessionWorkerHealth::Poisoned;
            return Err(SessionWorkerError::ContradictoryEvidence {
                detail: "the local memory-write receipt identity disappeared before rejection",
            });
        };
        self.machine
            .resolve_live_memory_write_no_effect(transaction.checkpoint, receipt_identity)
            .map_err(|source| {
                self.health = SessionWorkerHealth::Poisoned;
                SessionWorkerError::Resolution { operation, source }
            })
    }

    fn fail_and_commit_pending(
        &mut self,
        resolved_health: SessionWorkerHealth,
        message: &'static str,
    ) -> Result<(), SessionWorkerError> {
        if let Err(source) = self.machine.mark_failed(message) {
            self.health = SessionWorkerHealth::Poisoned;
            return Err(SessionWorkerError::Resolution {
                operation: "freezing a session after an unsafe provider outcome",
                source,
            });
        }
        self.commit_pending("committing the frozen unsafe checkpoint")?;
        self.health = resolved_health;
        Ok(())
    }

    fn take_pending(&mut self) -> Result<PendingTransaction, SessionWorkerError> {
        self.pending_transaction.take().ok_or_else(|| {
            self.health = SessionWorkerHealth::Poisoned;
            SessionWorkerError::ContradictoryEvidence {
                detail: "the reducer transaction disappeared before resolution",
            }
        })
    }

    #[cfg(test)]
    fn apply_post_dispatch_provider_state_for_test(&mut self) {
        let Some(state) = self.post_dispatch_provider_state_for_test.take() else {
            return;
        };
        self.provider.attached_mut().phase = match state {
            DebugHostWorkerState::Stopped => AttachedPhase::Stopped,
            DebugHostWorkerState::CleanupRequired => AttachedPhase::CleanupRequired,
            DebugHostWorkerState::Detached | DebugHostWorkerState::DrainingInitialEvents => {
                panic!("test hook supports only attached terminal phases")
            }
        };
    }
}
