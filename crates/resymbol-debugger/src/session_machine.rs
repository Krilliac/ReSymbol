//! Pure debugger-session state reduction.

use std::collections::BTreeMap;

use resymbol_core::BinaryId;
use thiserror::Error;

use crate::authorization::{
    HostLaunchIntent, HostRiskLease, HostRiskOperation, HostRiskVerifier, SandboxOwnershipBinding,
    SandboxOwnershipLease, SandboxOwnershipVerifier,
};
use crate::identity::{HostRiskLeaseId, ProvisioningEpoch, SandboxOwnershipLeaseId};
use crate::protocol::{
    AttachMode, AttachScope, CommandEnvelope, CommandId, DebugCommand, DebugTargetRequest,
    ProcessId, ProtocolValidationError, RunId, RunToken, SessionId, SessionState, SessionStateKind,
    StateGeneration, StateToken, StopId, StopReason, StopToken, ThreadId,
};
use crate::sandbox::{
    CleanupOutcome, DiagnosticText, ExpectedSandboxAttestation, HelperBuildId,
    PolicyValidationError, SandboxAttestation, SandboxCleanupReceipt, SandboxFailure,
    SandboxFailureContext, SandboxFailureKind, SandboxFailureStage, SandboxFailureValidationError,
    SandboxLifecycleState, SandboxMachine, SandboxMachineError, provider_boundary,
};

pub const MAX_REGISTERED_AUTHORIZATION_LEASES: usize = 64;

/// Single-owner, value-only reducer for one debugger session.
///
/// All methods are free of platform I/O and handles. The value may move across
/// threads, but mutation must be serialized by its owner (later, one host
/// `SessionWorker`). An active session is non-hot-reloadable and must reach
/// `Closed` before provider code is replaced.
///
/// The reducer intentionally does not implement [`Clone`] because it owns the
/// consumption registry for one-use authorization leases. Move the reducer
/// when transferring its single owner.
///
/// ```compile_fail
/// use resymbol_debugger::SessionMachine;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<SessionMachine>();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct SessionMachine {
    session_id: SessionId,
    provisioning_epoch: ProvisioningEpoch,
    helper_build: HelperBuildId,
    state: SessionState,
    target: Option<DebugTargetRequest>,
    last_command_id: Option<CommandId>,
    last_stop_id: u64,
    last_run_id: u64,
    execution_gate: ExecutionGate,
    sandbox: Option<SandboxMachine>,
    inherited_sandbox: Option<SandboxOwnershipBinding>,
    host_risk_leases: BTreeMap<HostRiskLeaseId, Option<HostRiskVerifier>>,
    sandbox_ownership_leases: BTreeMap<SandboxOwnershipLeaseId, Option<SandboxOwnershipVerifier>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionGate {
    NotApplicable,
    HostRiskAccepted,
    InheritedSandbox,
    SandboxPending,
    SandboxAccepted,
}

/// Ordinary-state checkpoint for one remote command, deliberately excluding
/// command watermarks and one-use authority registries.
#[derive(Debug)]
pub struct RemoteCommandCheckpoint {
    session_id: SessionId,
    provisioning_epoch: ProvisioningEpoch,
    state: SessionState,
    target: Option<DebugTargetRequest>,
    execution_gate: ExecutionGate,
    sandbox: Option<SandboxMachine>,
    inherited_sandbox: Option<SandboxOwnershipBinding>,
}

impl SessionMachine {
    #[must_use]
    pub fn new(
        session_id: SessionId,
        provisioning_epoch: ProvisioningEpoch,
        helper_build: HelperBuildId,
    ) -> Self {
        let token = StateToken {
            session_id,
            generation: StateGeneration::new(1).expect("initial generation is nonzero"),
        };
        Self {
            session_id,
            provisioning_epoch,
            helper_build,
            state: SessionState::Idle { token },
            target: None,
            last_command_id: None,
            last_stop_id: 0,
            last_run_id: 0,
            execution_gate: ExecutionGate::NotApplicable,
            sandbox: None,
            inherited_sandbox: None,
            host_risk_leases: BTreeMap::new(),
            sandbox_ownership_leases: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn provisioning_epoch(&self) -> &ProvisioningEpoch {
        &self.provisioning_epoch
    }

    #[must_use]
    pub const fn state(&self) -> &SessionState {
        &self.state
    }

    #[must_use]
    pub const fn target(&self) -> Option<&DebugTargetRequest> {
        self.target.as_ref()
    }

    #[must_use]
    pub fn target_binary_id(&self) -> Option<&BinaryId> {
        match self.target.as_ref() {
            Some(DebugTargetRequest::Launch(target)) => Some(&target.binary_id),
            _ => None,
        }
    }

    #[must_use]
    pub const fn last_command_id(&self) -> Option<CommandId> {
        self.last_command_id
    }

    #[must_use]
    pub fn expected_attestation(&self) -> Option<&ExpectedSandboxAttestation> {
        self.sandbox
            .as_ref()
            .map(SandboxMachine::expected_attestation)
    }

    #[must_use]
    pub fn sandbox_state(&self) -> Option<SandboxLifecycleState> {
        self.sandbox.as_ref().map(SandboxMachine::state)
    }

    #[must_use]
    pub const fn inherited_sandbox(&self) -> Option<&SandboxOwnershipBinding> {
        self.inherited_sandbox.as_ref()
    }

    /// Registers one host-local approval. This method is called only by the
    /// trusted session worker; command payloads cannot register authority.
    pub fn register_host_risk_lease(
        &mut self,
        lease: HostRiskLease,
    ) -> Result<(), SessionMachineError> {
        self.register_host_risk_verifier(lease.into_verifier())
    }

    /// Registers non-authority comparison data in a controller-side shadow
    /// reducer. The sole move-only lease must be registered independently on
    /// the host worker; this verifier cannot authorize that worker.
    pub(crate) fn register_host_risk_verifier(
        &mut self,
        verifier: HostRiskVerifier,
    ) -> Result<(), SessionMachineError> {
        self.require_state("register host-risk lease", &[SessionStateKind::Idle])?;
        self.require_session(verifier.session_id())?;
        if verifier.provisioning_epoch() != &self.provisioning_epoch {
            return Err(SessionMachineError::ProvisioningEpochMismatch);
        }
        if self.host_risk_leases.contains_key(verifier.id()) {
            return Err(SessionMachineError::DuplicateAuthorizationLease);
        }
        if self.host_risk_leases.len() >= MAX_REGISTERED_AUTHORIZATION_LEASES {
            return Err(SessionMachineError::TooManyAuthorizationLeases);
        }
        self.host_risk_leases
            .insert(verifier.id().clone(), Some(verifier));
        Ok(())
    }

    /// Registers one provider-authenticated process-ownership grant. The
    /// binding is local-only and cannot be supplied by a command envelope.
    pub fn register_sandbox_ownership_lease(
        &mut self,
        lease: SandboxOwnershipLease,
    ) -> Result<(), SessionMachineError> {
        self.register_sandbox_ownership_verifier(lease.into_verifier())
    }

    /// Registers non-authority ownership comparison data in a controller-side
    /// shadow reducer. Provider authority remains solely in the host lease.
    pub(crate) fn register_sandbox_ownership_verifier(
        &mut self,
        verifier: SandboxOwnershipVerifier,
    ) -> Result<(), SessionMachineError> {
        self.require_state(
            "register sandbox-ownership lease",
            &[SessionStateKind::Idle],
        )?;
        self.require_session(verifier.binding().session_id())?;
        if verifier.binding().provisioning_epoch() != &self.provisioning_epoch {
            return Err(SessionMachineError::ProvisioningEpochMismatch);
        }
        if self.sandbox_ownership_leases.contains_key(verifier.id()) {
            return Err(SessionMachineError::DuplicateAuthorizationLease);
        }
        if self.sandbox_ownership_leases.len() >= MAX_REGISTERED_AUTHORIZATION_LEASES {
            return Err(SessionMachineError::TooManyAuthorizationLeases);
        }
        self.sandbox_ownership_leases
            .insert(verifier.id().clone(), Some(verifier));
        Ok(())
    }

    /// Accepts one externally correlated command and advances state when the
    /// command changes execution. Structurally valid command IDs are consumed
    /// even when their state token is stale, so a rejected command cannot be
    /// replayed under the same correlation ID.
    pub fn accept_command(
        &mut self,
        envelope: &CommandEnvelope,
    ) -> Result<&SessionState, SessionMachineError> {
        envelope.validate()?;
        self.observe_command_id(envelope.command_id)?;
        if matches!(envelope.command, DebugCommand::ProbeCapabilities) {
            return Err(SessionMachineError::GlobalCommand);
        }
        envelope.validate_against(&self.state)?;

        match envelope.command.clone() {
            DebugCommand::ProbeCapabilities => unreachable!("handled above"),
            DebugCommand::Open(target) => self.accept_open(target)?,
            DebugCommand::Continue { .. } | DebugCommand::Step { .. } => {
                self.ensure_execution_allowed()?;
                let next = self.next_state_token()?;
                let run = self.allocate_run_token(next)?;
                if let Some(sandbox) = self.sandbox.as_mut() {
                    sandbox.mark_running()?;
                }
                self.transition_to(SessionState::Running { token: run })?;
            }
            DebugCommand::Pause { .. } => {
                let next = self.next_state_token()?;
                self.transition_to(SessionState::Pausing { token: next })?;
            }
            DebugCommand::WriteMemory { .. }
            | DebugCommand::SetBreakpoint { .. }
            | DebugCommand::RemoveBreakpoint { .. } => self.refresh_stopped_token()?,
            DebugCommand::ReadMemory { .. } | DebugCommand::CaptureSnapshot { .. } => {}
            DebugCommand::Detach { .. } => {
                if matches!(
                    self.execution_gate,
                    ExecutionGate::InheritedSandbox
                        | ExecutionGate::SandboxPending
                        | ExecutionGate::SandboxAccepted
                ) {
                    return Err(SessionMachineError::SandboxDetachForbidden);
                }
                let next = self.next_state_token()?;
                self.transition_to(SessionState::Detached { token: next })?;
            }
            DebugCommand::Terminate { .. } | DebugCommand::Close { .. } => {
                let next = self.next_state_token()?;
                if let Some(sandbox) = self.sandbox.as_mut() {
                    sandbox.begin_cleanup()?;
                }
                self.transition_to(SessionState::Closing { token: next })?;
            }
        }
        Ok(&self.state)
    }

    /// Begins a command whose outcome is reported by an untrusted remote host.
    ///
    /// The returned checkpoint can restore only visible reducer state after an
    /// explicit rejection. Command IDs and consumed/cleared authority remain
    /// one-use even when the remote operation reports no effect.
    pub fn begin_remote_command(
        &mut self,
        envelope: &CommandEnvelope,
    ) -> Result<RemoteCommandCheckpoint, SessionMachineError> {
        let checkpoint = RemoteCommandCheckpoint {
            session_id: self.session_id,
            provisioning_epoch: self.provisioning_epoch.clone(),
            state: self.state.clone(),
            target: self.target.clone(),
            execution_gate: self.execution_gate,
            sandbox: self.sandbox.clone(),
            inherited_sandbox: self.inherited_sandbox.clone(),
        };
        self.accept_command(envelope)?;
        Ok(checkpoint)
    }

    /// Restores visible state after an exact remote rejection without
    /// restoring command IDs, token allocation, or one-use authority.
    pub fn reject_remote_command(
        &mut self,
        checkpoint: RemoteCommandCheckpoint,
    ) -> Result<&SessionState, SessionMachineError> {
        if self.session_id != checkpoint.session_id {
            return Err(SessionMachineError::SessionBindingMismatch);
        }
        if self.provisioning_epoch != checkpoint.provisioning_epoch {
            return Err(SessionMachineError::ProvisioningEpochMismatch);
        }
        self.state = checkpoint.state;
        self.target = checkpoint.target;
        self.execution_gate = checkpoint.execution_gate;
        self.sandbox = checkpoint.sandbox;
        self.inherited_sandbox = checkpoint.inherited_sandbox;
        Ok(&self.state)
    }

    /// Records the creation-time suspended target before accepting any
    /// sandbox attestation.
    pub fn target_created_suspended(&mut self) -> Result<&SessionState, SessionMachineError> {
        self.require_state("record suspended target", &[SessionStateKind::Opening])?;
        if self.execution_gate != ExecutionGate::SandboxPending {
            return Err(SessionMachineError::SandboxNotPending);
        }
        let next = self.next_state_token()?;
        self.sandbox
            .as_mut()
            .ok_or(SessionMachineError::SandboxNotPending)?
            .target_created_suspended()?;
        self.transition_to(SessionState::AwaitingAttestation { token: next })?;
        Ok(&self.state)
    }

    /// Validates every attested field exactly. A mismatch leaves the target in
    /// `AwaitingAttestation` and therefore unable to continue.
    pub fn accept_sandbox_attestation(
        &mut self,
        actual: &SandboxAttestation,
    ) -> Result<&SessionState, SessionMachineError> {
        self.require_state(
            "accept sandbox attestation",
            &[SessionStateKind::AwaitingAttestation],
        )?;
        let next = self.next_state_token()?;
        self.sandbox
            .as_mut()
            .ok_or(SessionMachineError::SandboxNotPending)?
            .accept_attestation(actual)?;
        self.execution_gate = ExecutionGate::SandboxAccepted;
        self.transition_to(SessionState::AttestationAccepted { token: next })?;
        Ok(&self.state)
    }

    pub fn complete_open_offline(&mut self) -> Result<&SessionState, SessionMachineError> {
        self.require_open_target("complete offline open", |target| {
            matches!(target, DebugTargetRequest::Offline(_))
        })?;
        let next = self.next_state_token()?;
        self.transition_to(SessionState::Offline { token: next })?;
        Ok(&self.state)
    }

    pub fn complete_open_dump(&mut self) -> Result<&SessionState, SessionMachineError> {
        self.require_open_target("complete dump open", |target| {
            matches!(target, DebugTargetRequest::Dump(_))
        })?;
        let next = self.next_state_token()?;
        self.transition_to(SessionState::Dump { token: next })?;
        Ok(&self.state)
    }

    pub fn complete_open_observing(
        &mut self,
        process_id: ProcessId,
    ) -> Result<&SessionState, SessionMachineError> {
        self.require_open_target("complete observing attach", |target| {
            matches!(
                target,
                DebugTargetRequest::Attach(target) if target.mode == AttachMode::ObserveReadOnly
            )
        })?;
        let next = self.next_state_token()?;
        self.transition_to(SessionState::Observing {
            token: next,
            process_id,
        })?;
        Ok(&self.state)
    }

    pub fn mark_stopped(
        &mut self,
        reason: StopReason,
        thread_id: ThreadId,
    ) -> Result<&SessionState, SessionMachineError> {
        self.require_state(
            "mark stopped",
            &[
                SessionStateKind::Opening,
                SessionStateKind::AttestationAccepted,
                SessionStateKind::Running,
                SessionStateKind::Pausing,
            ],
        )?;
        if self.execution_gate == ExecutionGate::SandboxPending {
            return Err(SessionMachineError::AttestationNotAccepted);
        }
        if self.state.kind() == SessionStateKind::Opening {
            self.require_open_target("mark stopped", |target| {
                matches!(
                    target,
                    DebugTargetRequest::Launch(_)
                        | DebugTargetRequest::Attach(crate::protocol::AttachTarget {
                            mode: AttachMode::Debug,
                            ..
                        })
                )
            })?;
        }
        let next = self.next_state_token()?;
        let stop = self.allocate_stop_token(next)?;
        self.transition_to(SessionState::Stopped {
            token: stop,
            reason,
            thread_id,
        })?;
        Ok(&self.state)
    }

    pub fn mark_exited(&mut self, exit_code: u32) -> Result<&SessionState, SessionMachineError> {
        self.require_state(
            "mark exited",
            &[
                SessionStateKind::AttestationAccepted,
                SessionStateKind::Stopped,
                SessionStateKind::Running,
                SessionStateKind::Pausing,
            ],
        )?;
        let next = self.next_state_token()?;
        if let Some(sandbox) = self.sandbox.as_mut() {
            sandbox.begin_cleanup()?;
        }
        self.transition_to(SessionState::Exited {
            token: next,
            exit_code,
        })?;
        Ok(&self.state)
    }

    pub fn mark_failed(
        &mut self,
        message: impl Into<String>,
    ) -> Result<&SessionState, SessionMachineError> {
        if self.state.kind() == SessionStateKind::Closed {
            return Err(SessionMachineError::InvalidTransition {
                from: SessionStateKind::Closed,
                action: "mark failed",
            });
        }
        let message = message.into();
        if message.trim().is_empty()
            || message.len() > crate::protocol::MAX_REASON_BYTES
            || message.chars().any(char::is_control)
        {
            return Err(SessionMachineError::InvalidFailureMessage);
        }
        let next = self.next_state_token()?;
        if let Some(sandbox) = self.sandbox.as_mut() {
            sandbox.mark_failed()?;
            sandbox.begin_cleanup()?;
        }
        self.transition_to(SessionState::Failed {
            token: next,
            message,
        })?;
        Ok(&self.state)
    }

    /// Completes the non-hot-reloadable session boundary. Sandboxed sessions
    /// cannot become terminal without an exact, complete cleanup receipt.
    pub fn complete_close(
        &mut self,
        receipt: Option<&SandboxCleanupReceipt>,
    ) -> Result<&SessionState, SessionMachineError> {
        self.require_state("complete close", &[SessionStateKind::Closing])?;
        let next = self.next_state_token()?;
        match (&mut self.sandbox, &self.inherited_sandbox, receipt) {
            (Some(sandbox), None, Some(receipt)) => {
                sandbox.close(receipt)?;
            }
            (None, Some(binding), Some(receipt)) => {
                Self::validate_inherited_cleanup(binding, receipt)?;
            }
            (Some(_), None, None) | (None, Some(_), None) => {
                return Err(SessionMachineError::MissingCleanupReceipt);
            }
            (None, None, Some(_)) => {
                return Err(SessionMachineError::UnexpectedCleanupReceipt);
            }
            (None, None, None) => {}
            (Some(_), Some(_), _) => {
                return Err(SessionMachineError::ConflictingSandboxOwnership);
            }
        }
        self.transition_to(SessionState::Closed { token: next })?;
        Ok(&self.state)
    }

    /// Reports whether this session owns either a newly provisioned or an
    /// inherited sandbox whose closure requires exact cleanup evidence.
    #[must_use]
    pub const fn requires_cleanup_receipt(&self) -> bool {
        self.sandbox.is_some() || self.inherited_sandbox.is_some()
    }

    /// Produces exact, non-authority failure evidence from the reducer's
    /// sandbox operation context. Host implementations should use this instead
    /// of rebuilding evidence from command payloads.
    pub fn bind_sandbox_failure(
        &self,
        stage: SandboxFailureStage,
        kind: SandboxFailureKind,
        retryable: bool,
        detail: DiagnosticText,
    ) -> Result<SandboxFailure, SessionMachineError> {
        let failure = match (&self.sandbox, &self.inherited_sandbox) {
            (Some(sandbox), None) => {
                let expected = sandbox.expected_attestation();
                SandboxFailure {
                    session_id: expected.session_id,
                    provisioning_epoch: expected.provisioning_epoch.clone(),
                    policy_digest: expected.policy_digest.clone(),
                    provider: expected.provider.clone(),
                    context: SandboxFailureContext::Launch {
                        binary_id: expected.binary_id.clone(),
                        helper_build: expected.helper_build.clone(),
                    },
                    stage,
                    kind,
                    retryable,
                    detail,
                }
            }
            (None, Some(binding)) => SandboxFailure {
                session_id: binding.session_id(),
                provisioning_epoch: binding.provisioning_epoch().clone(),
                policy_digest: binding.policy_digest().clone(),
                provider: binding.provider().clone(),
                context: SandboxFailureContext::InheritedAttach {
                    process: binding.process().clone(),
                    mode: binding.mode(),
                },
                stage,
                kind,
                retryable,
                detail,
            },
            (None, None) => return Err(SessionMachineError::UnexpectedSandboxFailure),
            (Some(_), Some(_)) => return Err(SessionMachineError::ConflictingSandboxOwnership),
        };
        failure.validate_stage_kind()?;
        Ok(failure)
    }

    /// Validates a failure against controller-held sandbox ownership without
    /// consuming or changing that ownership.
    pub fn validate_sandbox_failure(
        &self,
        failure: &SandboxFailure,
    ) -> Result<(), SessionMachineError> {
        match (&self.sandbox, &self.inherited_sandbox) {
            (Some(sandbox), None) => {
                failure.validate_against_expected(sandbox.expected_attestation())?;
                Ok(())
            }
            (None, Some(binding)) => {
                failure.validate_against_inherited(
                    binding.session_id(),
                    binding.provisioning_epoch(),
                    binding.policy_digest(),
                    binding.provider(),
                    binding.process(),
                    binding.mode(),
                )?;
                Ok(())
            }
            (None, None) => Err(SessionMachineError::UnexpectedSandboxFailure),
            (Some(_), Some(_)) => Err(SessionMachineError::ConflictingSandboxOwnership),
        }
    }

    /// Validates cleanup evidence without advancing the reducer. This lets a
    /// controller or host validate a lifecycle event before the correlated
    /// `Closed` state transition is committed.
    pub fn validate_cleanup_receipt(
        &self,
        receipt: &SandboxCleanupReceipt,
    ) -> Result<(), SessionMachineError> {
        self.validate_cleanup_receipt_binding(receipt)?;
        if receipt.outcome != CleanupOutcome::Complete {
            return Err(SandboxMachineError::CleanupIncomplete.into());
        }
        Ok(())
    }

    /// Validates exact, incomplete cleanup-attempt evidence without advancing
    /// the reducer or releasing sandbox ownership.
    pub fn validate_cleanup_attempt_receipt(
        &self,
        receipt: &SandboxCleanupReceipt,
    ) -> Result<(), SessionMachineError> {
        self.validate_cleanup_receipt_binding(receipt)?;
        if receipt.outcome != CleanupOutcome::Incomplete {
            return Err(SessionMachineError::ExpectedIncompleteCleanupReceipt);
        }
        Ok(())
    }

    fn validate_cleanup_receipt_binding(
        &self,
        receipt: &SandboxCleanupReceipt,
    ) -> Result<(), SessionMachineError> {
        match (&self.sandbox, &self.inherited_sandbox) {
            (Some(sandbox), None) => {
                receipt
                    .validate_against(sandbox.expected_attestation())
                    .map_err(SandboxMachineError::Cleanup)?;
                Ok(())
            }
            (None, Some(binding)) => Self::validate_inherited_cleanup_binding(binding, receipt),
            (None, None) => Err(SessionMachineError::UnexpectedCleanupReceipt),
            (Some(_), Some(_)) => Err(SessionMachineError::ConflictingSandboxOwnership),
        }
    }

    fn validate_inherited_cleanup(
        binding: &SandboxOwnershipBinding,
        receipt: &SandboxCleanupReceipt,
    ) -> Result<(), SessionMachineError> {
        Self::validate_inherited_cleanup_binding(binding, receipt)?;
        if receipt.outcome != CleanupOutcome::Complete {
            return Err(SandboxMachineError::CleanupIncomplete.into());
        }
        Ok(())
    }

    fn validate_inherited_cleanup_binding(
        binding: &SandboxOwnershipBinding,
        receipt: &SandboxCleanupReceipt,
    ) -> Result<(), SessionMachineError> {
        if receipt.session_id != binding.session_id()
            || &receipt.provisioning_epoch != binding.provisioning_epoch()
            || &receipt.provider != binding.provider()
            || &receipt.policy_digest != binding.policy_digest()
            || receipt.process.as_ref() != Some(binding.process())
        {
            return Err(SessionMachineError::InheritedCleanupReceiptMismatch);
        }
        receipt
            .validate_for_boundary(provider_boundary(binding.provider()))
            .map_err(SandboxMachineError::Cleanup)?;
        Ok(())
    }

    fn accept_open(&mut self, target: DebugTargetRequest) -> Result<(), SessionMachineError> {
        let (mut sandbox, gate, inherited_sandbox) = match &target {
            DebugTargetRequest::Launch(target) => match &target.environment {
                crate::protocol::LaunchEnvironment::Sandboxed { policy } => {
                    self.require_session(policy.session_id)?;
                    let expected = ExpectedSandboxAttestation::from_policy(
                        target.binary_id.clone(),
                        policy,
                        self.helper_build.clone(),
                        self.provisioning_epoch.clone(),
                    )?;
                    let mut sandbox = SandboxMachine::new(expected)?;
                    sandbox.begin_provisioning()?;
                    (Some(sandbox), ExecutionGate::SandboxPending, None)
                }
                crate::protocol::LaunchEnvironment::Host { risk_lease } => {
                    self.consume_host_risk_lease(
                        risk_lease,
                        &HostRiskOperation::Launch {
                            intent: HostLaunchIntent::from_target(target),
                        },
                    )?;
                    (None, ExecutionGate::HostRiskAccepted, None)
                }
            },
            DebugTargetRequest::Attach(target) => match &target.scope {
                AttachScope::Host {
                    process,
                    risk_lease,
                } => {
                    self.consume_host_risk_lease(
                        risk_lease,
                        &HostRiskOperation::Attach {
                            process: process.clone(),
                            mode: target.mode,
                        },
                    )?;
                    (None, ExecutionGate::HostRiskAccepted, None)
                }
                AttachScope::OwnedSandbox {
                    process,
                    ownership_lease,
                } => {
                    let binding = self.consume_sandbox_ownership_lease(
                        ownership_lease,
                        process,
                        target.mode,
                    )?;
                    (None, ExecutionGate::InheritedSandbox, Some(binding))
                }
            },
            DebugTargetRequest::Dump(_) | DebugTargetRequest::Offline(_) => {
                (None, ExecutionGate::NotApplicable, None)
            }
        };
        let next = self.next_state_token()?;
        self.execution_gate = gate;
        self.sandbox = sandbox.take();
        self.inherited_sandbox = inherited_sandbox;
        self.target = Some(target.clone());
        // One target consumes the session. Drop every unused authority so no
        // later transition or accidental API reuse can resurrect it.
        self.host_risk_leases.clear();
        self.sandbox_ownership_leases.clear();
        self.transition_to(SessionState::Opening {
            token: next,
            target,
        })?;
        Ok(())
    }

    fn refresh_stopped_token(&mut self) -> Result<(), SessionMachineError> {
        let SessionState::Stopped {
            reason, thread_id, ..
        } = self.state.clone()
        else {
            return Err(SessionMachineError::InvalidTransition {
                from: self.state.kind(),
                action: "refresh stopped token",
            });
        };
        let next = self.next_state_token()?;
        let stop = self.allocate_stop_token(next)?;
        self.transition_to(SessionState::Stopped {
            token: stop,
            reason,
            thread_id,
        })?;
        Ok(())
    }

    fn transition_to(&mut self, next: SessionState) -> Result<(), SessionMachineError> {
        self.state.validate_successor(&next)?;
        self.state = next;
        Ok(())
    }

    fn observe_command_id(&mut self, command_id: CommandId) -> Result<(), SessionMachineError> {
        if let Some(last) = self.last_command_id {
            if command_id <= last {
                return Err(SessionMachineError::NonMonotonicCommandId {
                    last,
                    received: command_id,
                });
            }
        }
        self.last_command_id = Some(command_id);
        Ok(())
    }

    fn ensure_execution_allowed(&self) -> Result<(), SessionMachineError> {
        match self.execution_gate {
            ExecutionGate::SandboxPending => Err(SessionMachineError::AttestationNotAccepted),
            ExecutionGate::NotApplicable => Err(SessionMachineError::ExecutionUnavailable),
            ExecutionGate::HostRiskAccepted
            | ExecutionGate::InheritedSandbox
            | ExecutionGate::SandboxAccepted => Ok(()),
        }
    }

    fn require_session(&self, actual: SessionId) -> Result<(), SessionMachineError> {
        if actual == self.session_id {
            Ok(())
        } else {
            Err(SessionMachineError::SessionBindingMismatch)
        }
    }

    fn consume_host_risk_lease(
        &mut self,
        id: &HostRiskLeaseId,
        expected: &HostRiskOperation,
    ) -> Result<(), SessionMachineError> {
        let verifier = self
            .host_risk_leases
            .get_mut(id)
            .and_then(Option::take)
            .ok_or(SessionMachineError::HostRiskLeaseUnavailable)?;
        if verifier.session_id() != self.session_id
            || verifier.provisioning_epoch() != &self.provisioning_epoch
            || verifier.operation() != expected
        {
            return Err(SessionMachineError::HostRiskLeaseMismatch);
        }
        Ok(())
    }

    fn consume_sandbox_ownership_lease(
        &mut self,
        id: &SandboxOwnershipLeaseId,
        process: &crate::protocol::ProcessIdentity,
        mode: AttachMode,
    ) -> Result<SandboxOwnershipBinding, SessionMachineError> {
        let verifier = self
            .sandbox_ownership_leases
            .get_mut(id)
            .and_then(Option::take)
            .ok_or(SessionMachineError::SandboxOwnershipLeaseUnavailable)?;
        let binding = verifier.binding();
        if binding.session_id() != self.session_id
            || binding.provisioning_epoch() != &self.provisioning_epoch
            || binding.process() != process
            || binding.mode() != mode
        {
            return Err(SessionMachineError::SandboxOwnershipLeaseMismatch);
        }
        Ok(binding.clone())
    }

    fn require_open_target(
        &self,
        action: &'static str,
        predicate: impl FnOnce(&DebugTargetRequest) -> bool,
    ) -> Result<(), SessionMachineError> {
        self.require_state(action, &[SessionStateKind::Opening])?;
        let target = self
            .target
            .as_ref()
            .ok_or(SessionMachineError::InvalidTransition {
                from: self.state.kind(),
                action,
            })?;
        if predicate(target) {
            Ok(())
        } else {
            Err(SessionMachineError::InvalidTransition {
                from: self.state.kind(),
                action,
            })
        }
    }

    fn require_state(
        &self,
        action: &'static str,
        allowed: &[SessionStateKind],
    ) -> Result<(), SessionMachineError> {
        let from = self.state.kind();
        if allowed.contains(&from) {
            Ok(())
        } else {
            Err(SessionMachineError::InvalidTransition { from, action })
        }
    }

    fn next_state_token(&self) -> Result<StateToken, SessionMachineError> {
        Ok(StateToken {
            session_id: self.session_id,
            generation: self.state.state_token().generation.checked_next()?,
        })
    }

    fn allocate_stop_token(&mut self, state: StateToken) -> Result<StopToken, SessionMachineError> {
        self.last_stop_id = self
            .last_stop_id
            .checked_add(1)
            .ok_or(SessionMachineError::StopIdOverflow)?;
        Ok(StopToken {
            state,
            stop_id: StopId::new(self.last_stop_id)
                .expect("checked positive stop identifier is nonzero"),
        })
    }

    fn allocate_run_token(&mut self, state: StateToken) -> Result<RunToken, SessionMachineError> {
        self.last_run_id = self
            .last_run_id
            .checked_add(1)
            .ok_or(SessionMachineError::RunIdOverflow)?;
        Ok(RunToken {
            state,
            run_id: RunId::new(self.last_run_id)
                .expect("checked positive run identifier is nonzero"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SessionMachineError {
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    #[error(transparent)]
    Policy(#[from] PolicyValidationError),
    #[error(transparent)]
    Sandbox(#[from] SandboxMachineError),
    #[error("global capability commands are handled outside a session reducer")]
    GlobalCommand,
    #[error("command id {received:?} is not newer than {last:?}")]
    NonMonotonicCommandId {
        last: CommandId,
        received: CommandId,
    },
    #[error("cannot {action} from session state {from:?}")]
    InvalidTransition {
        from: SessionStateKind,
        action: &'static str,
    },
    #[error("sandbox policy or trusted authorization lease uses another session")]
    SessionBindingMismatch,
    #[error("authorization lease id is already registered")]
    DuplicateAuthorizationLease,
    #[error("session has reached its registered authorization lease limit")]
    TooManyAuthorizationLeases,
    #[error("authorization lease belongs to another provisioning epoch")]
    ProvisioningEpochMismatch,
    #[error("host-risk lease is unknown, unregistered, or already consumed")]
    HostRiskLeaseUnavailable,
    #[error("host-risk lease does not authorize this exact operation and target")]
    HostRiskLeaseMismatch,
    #[error("sandbox-ownership lease is unknown, unregistered, or already consumed")]
    SandboxOwnershipLeaseUnavailable,
    #[error("sandbox-ownership lease does not bind this exact process and provisioning instance")]
    SandboxOwnershipLeaseMismatch,
    #[error("sandbox target is not awaiting creation-time attestation")]
    SandboxNotPending,
    #[error("sandbox attestation has not been accepted")]
    AttestationNotAccepted,
    #[error("execution is unavailable for this target mode")]
    ExecutionUnavailable,
    #[error("sandbox-owned execution cannot detach without cleanup")]
    SandboxDetachForbidden,
    #[error("sandbox close requires an exact cleanup receipt")]
    MissingCleanupReceipt,
    #[error("non-sandbox close unexpectedly carried a cleanup receipt")]
    UnexpectedCleanupReceipt,
    #[error("inherited sandbox cleanup receipt does not match the exact ownership binding")]
    InheritedCleanupReceiptMismatch,
    #[error("cleanup-attempt evidence must carry an incomplete receipt")]
    ExpectedIncompleteCleanupReceipt,
    #[error("sandbox failure evidence arrived without retained sandbox ownership")]
    UnexpectedSandboxFailure,
    #[error(transparent)]
    SandboxFailure(#[from] SandboxFailureValidationError),
    #[error("session contains conflicting sandbox ownership records")]
    ConflictingSandboxOwnership,
    #[error("failure message must be nonempty, single-line, and bounded")]
    InvalidFailureMessage,
    #[error("stop identifier exhausted its u64 space")]
    StopIdOverflow,
    #[error("run identifier exhausted its u64 space")]
    RunIdOverflow,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use super::*;
    use crate::protocol::{
        AttachTarget, DebugTargetRequest, LaunchEnvironment, LaunchTarget, MemoryAddress,
        ProcessIdentity, ProcessStartKey, ProtocolVersion,
    };
    use crate::sandbox::{
        ChildProcessProfile, CleanupOutcome, CleanupReceiptId, DynamicCodeProfile,
        IsolationBoundary, PolicyDigest, ProcessMitigationProfile, SandboxGuarantee,
        SandboxNetworkMode, SandboxPolicy, SandboxPolicyApprovalId, SandboxProviderSelection,
        SandboxResourceLimits, Win32kProfile,
    };

    fn session_id() -> SessionId {
        SessionId::new(11).expect("session id")
    }

    fn helper_build() -> HelperBuildId {
        HelperBuildId::new("debugger-host-1.0.0+test").expect("helper build")
    }

    fn provisioning_epoch() -> ProvisioningEpoch {
        ProvisioningEpoch::new("a".repeat(64)).expect("provisioning epoch")
    }

    fn machine() -> SessionMachine {
        SessionMachine::new(session_id(), provisioning_epoch(), helper_build())
    }

    fn local_guarantees() -> BTreeSet<SandboxGuarantee> {
        [
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
        .collect()
    }

    fn local_policy() -> SandboxPolicy {
        let session_id = session_id();
        SandboxPolicy {
            session_id,
            policy_approval: SandboxPolicyApprovalId::new(session_id, "sandbox-ack")
                .expect("acknowledgement"),
            provider: SandboxProviderSelection::LocalAppContainer,
            required_boundary: IsolationBoundary::UserMode,
            required_guarantees: local_guarantees(),
            network: SandboxNetworkMode::Disabled,
            resources: SandboxResourceLimits {
                memory_bytes: 512 * 1024 * 1024,
                disk_bytes: 2 * 1024 * 1024 * 1024,
                active_process_limit: 8,
                cpu_rate_basis_points: 5_000,
                wall_clock_millis: 300_000,
            },
            process_mitigations: ProcessMitigationProfile::StrictV1,
            child_processes: ChildProcessProfile::Deny,
            dynamic_code: DynamicCodeProfile::Prohibit,
            win32k: Win32kProfile::Disable,
            rollback_on_close: true,
            vm_identity: None,
        }
    }

    fn sandbox_target(binary_id: BinaryId) -> DebugTargetRequest {
        DebugTargetRequest::Launch(LaunchTarget {
            binary_id,
            executable: PathBuf::from("sample.exe"),
            arguments: Vec::new(),
            working_directory: None,
            environment: LaunchEnvironment::Sandboxed {
                policy: local_policy(),
            },
            stop_before_entry: true,
        })
    }

    fn host_risk_lease_id(fill: char) -> HostRiskLeaseId {
        HostRiskLeaseId::new(fill.to_string().repeat(64)).expect("host-risk lease id")
    }

    fn ownership_lease_id(fill: char) -> SandboxOwnershipLeaseId {
        SandboxOwnershipLeaseId::new(fill.to_string().repeat(64))
            .expect("sandbox-ownership lease id")
    }

    fn process_identity(process_id: u32, start_key: u64, image: &[u8]) -> ProcessIdentity {
        ProcessIdentity {
            process_id: ProcessId::new(process_id).expect("process id"),
            start_key: ProcessStartKey::new(start_key).expect("process start key"),
            binary_id: BinaryId::digest(image),
        }
    }

    fn host_target(binary_id: BinaryId, risk_lease: HostRiskLeaseId) -> DebugTargetRequest {
        DebugTargetRequest::Launch(LaunchTarget {
            binary_id,
            executable: PathBuf::from("sample.exe"),
            arguments: Vec::new(),
            working_directory: None,
            environment: LaunchEnvironment::Host { risk_lease },
            stop_before_entry: true,
        })
    }

    fn host_launch_operation(
        binary_id: BinaryId,
        risk_lease: HostRiskLeaseId,
    ) -> HostRiskOperation {
        let DebugTargetRequest::Launch(target) = host_target(binary_id, risk_lease) else {
            unreachable!("host target is a launch")
        };
        HostRiskOperation::Launch {
            intent: HostLaunchIntent::from_target(&target),
        }
    }

    fn attach_target(scope: AttachScope) -> DebugTargetRequest {
        DebugTargetRequest::Attach(AttachTarget {
            scope,
            mode: AttachMode::Debug,
        })
    }

    fn command(id: u64, expected_state: StateToken, command: DebugCommand) -> CommandEnvelope {
        CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(id).expect("command id"),
            session_id: Some(expected_state.session_id),
            expected_state: Some(expected_state),
            command,
        }
    }

    fn actual_attestation(expected: &ExpectedSandboxAttestation) -> SandboxAttestation {
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

    fn cleanup_receipt(expected: &ExpectedSandboxAttestation) -> SandboxCleanupReceipt {
        SandboxCleanupReceipt {
            receipt_id: CleanupReceiptId::new("cleanup-11").expect("receipt id"),
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

    fn inherited_cleanup_receipt(binding: &SandboxOwnershipBinding) -> SandboxCleanupReceipt {
        let (appcontainer_profile_deleted, differencing_disk_discarded, control_channel_closed) =
            match provider_boundary(binding.provider()) {
                IsolationBoundary::UserMode => (Some(true), None, None),
                IsolationBoundary::Hypervisor => (None, Some(true), Some(true)),
            };
        SandboxCleanupReceipt {
            receipt_id: CleanupReceiptId::new("inherited-cleanup-11").expect("receipt id"),
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
            appcontainer_profile_deleted,
            differencing_disk_discarded,
            control_channel_closed,
            terminated_processes: 1,
            residuals: Vec::new(),
        }
    }

    fn open_attested_and_stopped(machine: &mut SessionMachine) -> u64 {
        let binary = BinaryId::digest(b"exact sample");
        let initial = machine.state().state_token();
        machine
            .accept_command(&command(
                1,
                initial,
                DebugCommand::Open(sandbox_target(binary)),
            ))
            .expect("open command");
        machine
            .target_created_suspended()
            .expect("suspended target");
        let actual = actual_attestation(
            machine
                .expected_attestation()
                .expect("expected attestation"),
        );
        machine
            .accept_sandbox_attestation(&actual)
            .expect("attestation");
        machine
            .mark_stopped(StopReason::Initial, ThreadId::new(3).expect("thread id"))
            .expect("initial stop");
        2
    }

    #[test]
    fn sandbox_launch_cannot_stop_or_continue_before_exact_attestation() {
        let binary = BinaryId::digest(b"exact sample");
        let mut machine = machine();
        let initial = machine.state().state_token();
        machine
            .accept_command(&command(
                1,
                initial,
                DebugCommand::Open(sandbox_target(binary.clone())),
            ))
            .expect("open command");
        assert_eq!(machine.target_binary_id(), Some(&binary));
        assert_eq!(machine.state().kind(), SessionStateKind::Opening);
        assert_eq!(machine.state().state_token().generation.get(), 2);

        machine
            .target_created_suspended()
            .expect("suspended target");
        assert_eq!(
            machine.state().kind(),
            SessionStateKind::AwaitingAttestation
        );
        assert_eq!(machine.state().state_token().generation.get(), 3);
        assert_eq!(
            machine.mark_stopped(StopReason::Initial, ThreadId::new(3).expect("thread id")),
            Err(SessionMachineError::InvalidTransition {
                from: SessionStateKind::AwaitingAttestation,
                action: "mark stopped",
            })
        );

        let waiting = machine.state().state_token();
        let fabricated_stop = StopToken {
            state: waiting,
            stop_id: StopId::new(99).expect("stop id"),
        };
        assert!(matches!(
            machine.accept_command(&command(
                2,
                waiting,
                DebugCommand::Continue {
                    stop: fabricated_stop
                }
            )),
            Err(SessionMachineError::Protocol(
                ProtocolValidationError::StaleExecutionToken
            ))
        ));

        let mut wrong = actual_attestation(
            machine
                .expected_attestation()
                .expect("expected attestation"),
        );
        wrong.binary_id = BinaryId::digest(b"wrong sample");
        assert!(matches!(
            machine.accept_sandbox_attestation(&wrong),
            Err(SessionMachineError::Sandbox(
                SandboxMachineError::Attestation(_)
            ))
        ));
        assert_eq!(
            machine.state().kind(),
            SessionStateKind::AwaitingAttestation
        );

        let actual = actual_attestation(
            machine
                .expected_attestation()
                .expect("expected attestation"),
        );
        machine
            .accept_sandbox_attestation(&actual)
            .expect("exact attestation");
        assert_eq!(
            machine.state().kind(),
            SessionStateKind::AttestationAccepted
        );
        machine
            .mark_stopped(StopReason::Initial, ThreadId::new(3).expect("thread id"))
            .expect("initial stop");
        let SessionState::Stopped { token, .. } = machine.state().clone() else {
            panic!("stopped state")
        };
        machine
            .accept_command(&command(
                3,
                token.state,
                DebugCommand::Continue { stop: token },
            ))
            .expect("continue after attestation");
        assert_eq!(machine.state().kind(), SessionStateKind::Running);
        assert_eq!(
            machine.sandbox_state(),
            Some(SandboxLifecycleState::Running)
        );
    }

    #[test]
    fn accepted_mutation_issues_fresh_stop_and_rejects_queued_stale_action() {
        let mut machine = machine();
        let next_id = open_attested_and_stopped(&mut machine);
        let SessionState::Stopped { token: first, .. } = machine.state().clone() else {
            panic!("stopped state")
        };
        machine
            .accept_command(&command(
                next_id,
                first.state,
                DebugCommand::WriteMemory {
                    stop: first,
                    address: MemoryAddress::new(0x1000),
                    expected: vec![0x90],
                    replacement: vec![0xcc],
                },
            ))
            .expect("first mutation");
        let SessionState::Stopped { token: second, .. } = machine.state().clone() else {
            panic!("stopped state")
        };
        assert_eq!(
            second.state.generation.get(),
            first.state.generation.get() + 1
        );
        assert_ne!(second.stop_id, first.stop_id);

        let queued = command(
            next_id + 1,
            first.state,
            DebugCommand::RemoveBreakpoint {
                stop: first,
                breakpoint_id: crate::protocol::BreakpointId::new(1).expect("breakpoint id"),
            },
        );
        assert!(matches!(
            machine.accept_command(&queued),
            Err(SessionMachineError::Protocol(
                ProtocolValidationError::StaleStateToken
            ))
        ));
        assert!(matches!(
            machine.accept_command(&command(
                next_id + 1,
                second.state,
                DebugCommand::RemoveBreakpoint {
                    stop: second,
                    breakpoint_id: crate::protocol::BreakpointId::new(1).expect("breakpoint id"),
                },
            )),
            Err(SessionMachineError::NonMonotonicCommandId { .. })
        ));
    }

    #[test]
    fn command_ids_are_strictly_monotonic_even_across_rejection() {
        let mut machine = machine();
        let initial = machine.state().state_token();
        let open = command(
            10,
            initial,
            DebugCommand::Open(DebugTargetRequest::Offline(
                crate::protocol::OfflineTarget {
                    path: PathBuf::from("sample.exe"),
                },
            )),
        );
        machine.accept_command(&open).expect("open");
        assert_eq!(machine.last_command_id(), Some(CommandId::new(10).unwrap()));
        assert!(matches!(
            machine.accept_command(&open),
            Err(SessionMachineError::NonMonotonicCommandId { .. })
        ));
    }

    #[test]
    fn sandbox_terminal_state_requires_bound_complete_cleanup_receipt() {
        let mut machine = machine();
        let next_id = open_attested_and_stopped(&mut machine);
        let expected = machine
            .expected_attestation()
            .expect("expected attestation")
            .clone();
        let state = machine.state().state_token();
        machine
            .accept_command(&command(next_id, state, DebugCommand::Close { state }))
            .expect("begin close");
        assert_eq!(machine.state().kind(), SessionStateKind::Closing);
        assert_eq!(
            machine.sandbox_state(),
            Some(SandboxLifecycleState::Cleanup)
        );
        assert_eq!(
            machine.complete_close(None),
            Err(SessionMachineError::MissingCleanupReceipt)
        );

        let mut wrong = cleanup_receipt(&expected);
        wrong.policy_digest = PolicyDigest::new("e".repeat(64)).expect("digest");
        assert!(matches!(
            machine.complete_close(Some(&wrong)),
            Err(SessionMachineError::Sandbox(SandboxMachineError::Cleanup(
                _
            )))
        ));
        let receipt = cleanup_receipt(&expected);
        machine
            .complete_close(Some(&receipt))
            .expect("complete close");
        assert_eq!(machine.state().kind(), SessionStateKind::Closed);

        let closed = machine.state().state_token();
        assert!(matches!(
            machine.accept_command(&command(
                next_id + 1,
                closed,
                DebugCommand::Close { state: closed }
            )),
            Err(SessionMachineError::Protocol(
                ProtocolValidationError::CommandNotAllowedInState
            ))
        ));
    }

    #[test]
    fn exact_registered_host_risk_lease_allows_only_its_launch_target() {
        let binary = BinaryId::digest(b"host target");
        let mut machine = machine();
        let risk_lease = host_risk_lease_id('b');
        machine
            .register_host_risk_lease(HostRiskLease::new(
                risk_lease.clone(),
                session_id(),
                provisioning_epoch(),
                host_launch_operation(binary.clone(), risk_lease.clone()),
            ))
            .expect("register host-risk lease");
        let initial = machine.state().state_token();
        machine
            .accept_command(&command(
                1,
                initial,
                DebugCommand::Open(host_target(binary.clone(), risk_lease)),
            ))
            .expect("host open");
        assert_eq!(machine.target_binary_id(), Some(&binary));
        assert!(machine.expected_attestation().is_none());
        machine
            .mark_stopped(StopReason::Initial, ThreadId::new(7).expect("thread id"))
            .expect("host initial stop");
    }

    #[test]
    fn cross_target_host_risk_attempt_consumes_the_one_use_lease() {
        let approved = BinaryId::digest(b"approved host target");
        let different = BinaryId::digest(b"different host target");
        let lease_id = host_risk_lease_id('c');
        let mut machine = machine();
        machine
            .register_host_risk_lease(HostRiskLease::new(
                lease_id.clone(),
                session_id(),
                provisioning_epoch(),
                host_launch_operation(approved.clone(), lease_id.clone()),
            ))
            .expect("register host-risk lease");

        let initial = machine.state().state_token();
        assert_eq!(
            machine.accept_command(&command(
                1,
                initial,
                DebugCommand::Open(host_target(different, lease_id.clone())),
            )),
            Err(SessionMachineError::HostRiskLeaseMismatch)
        );
        assert_eq!(machine.state().kind(), SessionStateKind::Idle);
        assert_eq!(
            machine.accept_command(&command(
                2,
                initial,
                DebugCommand::Open(host_target(approved, lease_id)),
            )),
            Err(SessionMachineError::HostRiskLeaseUnavailable)
        );
        assert_eq!(
            machine.register_host_risk_lease(HostRiskLease::new(
                host_risk_lease_id('c'),
                session_id(),
                provisioning_epoch(),
                host_launch_operation(
                    BinaryId::digest(b"approved host target"),
                    host_risk_lease_id('c'),
                ),
            )),
            Err(SessionMachineError::DuplicateAuthorizationLease)
        );
    }

    #[test]
    fn host_launch_lease_binds_arguments_working_directory_and_epoch() {
        let binary = BinaryId::digest(b"approved host launch");
        let lease_id = host_risk_lease_id('6');
        let DebugTargetRequest::Launch(mut approved) = host_target(binary, lease_id.clone()) else {
            unreachable!("host target is a launch")
        };
        approved.arguments = vec!["--approved".to_owned()];
        approved.working_directory = Some(PathBuf::from("approved-workdir"));

        let mut machine = machine();
        machine
            .register_host_risk_lease(HostRiskLease::new(
                lease_id.clone(),
                session_id(),
                provisioning_epoch(),
                HostRiskOperation::Launch {
                    intent: HostLaunchIntent::from_target(&approved),
                },
            ))
            .expect("register exact launch intent");

        let mut changed = approved.clone();
        changed.arguments = vec!["--different".to_owned()];
        let initial = machine.state().state_token();
        assert_eq!(
            machine.accept_command(&command(
                1,
                initial,
                DebugCommand::Open(DebugTargetRequest::Launch(changed)),
            )),
            Err(SessionMachineError::HostRiskLeaseMismatch)
        );

        let stale_id = host_risk_lease_id('9');
        assert_eq!(
            machine.register_host_risk_lease(HostRiskLease::new(
                stale_id,
                session_id(),
                ProvisioningEpoch::new("f".repeat(64)).expect("stale epoch"),
                HostRiskOperation::Launch {
                    intent: HostLaunchIntent::from_target(&approved),
                },
            )),
            Err(SessionMachineError::ProvisioningEpochMismatch)
        );
    }

    #[test]
    fn attach_risk_lease_binds_pid_start_key_image_identity_and_mode() {
        let approved = process_identity(4242, 10, b"approved attach image");
        let reused_pid = process_identity(4242, 11, b"approved attach image");
        let lease_id = host_risk_lease_id('d');
        let mut machine = machine();
        machine
            .register_host_risk_lease(HostRiskLease::new(
                lease_id.clone(),
                session_id(),
                provisioning_epoch(),
                HostRiskOperation::Attach {
                    process: approved.clone(),
                    mode: AttachMode::Debug,
                },
            ))
            .expect("register attach lease");
        let initial = machine.state().state_token();
        assert_eq!(
            machine.accept_command(&command(
                1,
                initial,
                DebugCommand::Open(attach_target(AttachScope::Host {
                    process: reused_pid,
                    risk_lease: lease_id.clone(),
                })),
            )),
            Err(SessionMachineError::HostRiskLeaseMismatch)
        );
        assert_eq!(
            machine.accept_command(&command(
                2,
                initial,
                DebugCommand::Open(attach_target(AttachScope::Host {
                    process: approved.clone(),
                    risk_lease: lease_id,
                })),
            )),
            Err(SessionMachineError::HostRiskLeaseUnavailable)
        );

        let mode_lease = host_risk_lease_id('4');
        let mut mode_machine =
            SessionMachine::new(session_id(), provisioning_epoch(), helper_build());
        mode_machine
            .register_host_risk_lease(HostRiskLease::new(
                mode_lease.clone(),
                session_id(),
                provisioning_epoch(),
                HostRiskOperation::Attach {
                    process: approved.clone(),
                    mode: AttachMode::Debug,
                },
            ))
            .expect("register mode-bound attach lease");
        let initial = mode_machine.state().state_token();
        assert_eq!(
            mode_machine.accept_command(&command(
                1,
                initial,
                DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                    scope: AttachScope::Host {
                        process: approved.clone(),
                        risk_lease: mode_lease.clone(),
                    },
                    mode: AttachMode::ObserveReadOnly,
                })),
            )),
            Err(SessionMachineError::HostRiskLeaseMismatch)
        );
        assert_eq!(
            mode_machine.accept_command(&command(
                2,
                initial,
                DebugCommand::Open(attach_target(AttachScope::Host {
                    process: approved,
                    risk_lease: mode_lease,
                })),
            )),
            Err(SessionMachineError::HostRiskLeaseUnavailable)
        );
    }

    #[test]
    fn sandbox_ownership_requires_registered_exact_one_use_binding() {
        let process = process_identity(5150, 22, b"owned sandbox image");
        let reused_pid = process_identity(5150, 23, b"owned sandbox image");
        let binding = SandboxOwnershipBinding::new(
            session_id(),
            process.clone(),
            AttachMode::Debug,
            SandboxProviderSelection::LocalAppContainer,
            PolicyDigest::new("b".repeat(64)).expect("policy digest"),
            provisioning_epoch(),
        );
        let first_id = ownership_lease_id('e');
        let mut machine = machine();

        let initial = machine.state().state_token();
        assert_eq!(
            machine.accept_command(&command(
                1,
                initial,
                DebugCommand::Open(attach_target(AttachScope::OwnedSandbox {
                    process: process.clone(),
                    ownership_lease: ownership_lease_id('f'),
                })),
            )),
            Err(SessionMachineError::SandboxOwnershipLeaseUnavailable)
        );

        machine
            .register_sandbox_ownership_lease(SandboxOwnershipLease::new(
                first_id.clone(),
                binding.clone(),
            ))
            .expect("register ownership lease");
        assert_eq!(
            machine.accept_command(&command(
                2,
                initial,
                DebugCommand::Open(attach_target(AttachScope::OwnedSandbox {
                    process: reused_pid,
                    ownership_lease: first_id.clone(),
                })),
            )),
            Err(SessionMachineError::SandboxOwnershipLeaseMismatch)
        );
        assert_eq!(
            machine.accept_command(&command(
                3,
                initial,
                DebugCommand::Open(attach_target(AttachScope::OwnedSandbox {
                    process: process.clone(),
                    ownership_lease: first_id,
                })),
            )),
            Err(SessionMachineError::SandboxOwnershipLeaseUnavailable)
        );
        assert_eq!(
            machine.register_sandbox_ownership_lease(SandboxOwnershipLease::new(
                ownership_lease_id('e'),
                binding.clone(),
            )),
            Err(SessionMachineError::DuplicateAuthorizationLease)
        );

        let mode_id = ownership_lease_id('5');
        machine
            .register_sandbox_ownership_lease(SandboxOwnershipLease::new(
                mode_id.clone(),
                binding.clone(),
            ))
            .expect("register mode-bound ownership lease");
        assert_eq!(
            machine.accept_command(&command(
                4,
                initial,
                DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                    scope: AttachScope::OwnedSandbox {
                        process: process.clone(),
                        ownership_lease: mode_id.clone(),
                    },
                    mode: AttachMode::ObserveReadOnly,
                })),
            )),
            Err(SessionMachineError::SandboxOwnershipLeaseMismatch)
        );
        assert_eq!(
            machine.accept_command(&command(
                5,
                initial,
                DebugCommand::Open(attach_target(AttachScope::OwnedSandbox {
                    process: process.clone(),
                    ownership_lease: mode_id,
                })),
            )),
            Err(SessionMachineError::SandboxOwnershipLeaseUnavailable)
        );

        let exact_id = ownership_lease_id('1');
        machine
            .register_sandbox_ownership_lease(SandboxOwnershipLease::new(
                exact_id.clone(),
                binding.clone(),
            ))
            .expect("register replacement ownership lease");
        machine
            .accept_command(&command(
                6,
                initial,
                DebugCommand::Open(attach_target(AttachScope::OwnedSandbox {
                    process,
                    ownership_lease: exact_id,
                })),
            ))
            .expect("exact owned-sandbox attach");
        assert_eq!(machine.inherited_sandbox(), Some(&binding));
    }

    #[test]
    fn ownership_registration_rejects_wrong_session_or_provisioning_epoch() {
        let process = process_identity(6000, 30, b"owned image");
        let mut machine = machine();
        let wrong_session = SandboxOwnershipBinding::new(
            SessionId::new(99).expect("other session"),
            process.clone(),
            AttachMode::Debug,
            SandboxProviderSelection::LocalAppContainer,
            PolicyDigest::new("c".repeat(64)).expect("policy digest"),
            provisioning_epoch(),
        );
        assert_eq!(
            machine.register_sandbox_ownership_lease(SandboxOwnershipLease::new(
                ownership_lease_id('2'),
                wrong_session,
            )),
            Err(SessionMachineError::SessionBindingMismatch)
        );

        let wrong_epoch = SandboxOwnershipBinding::new(
            session_id(),
            process,
            AttachMode::Debug,
            SandboxProviderSelection::LocalAppContainer,
            PolicyDigest::new("d".repeat(64)).expect("policy digest"),
            ProvisioningEpoch::new("f".repeat(64)).expect("different epoch"),
        );
        assert_eq!(
            machine.register_sandbox_ownership_lease(SandboxOwnershipLease::new(
                ownership_lease_id('3'),
                wrong_epoch,
            )),
            Err(SessionMachineError::ProvisioningEpochMismatch)
        );
    }

    #[test]
    fn host_reducer_binds_rollback_failure_without_restoring_command_authority() {
        let mut machine = machine();
        let initial = machine.state().state_token();
        let open = command(
            1,
            initial,
            DebugCommand::Open(sandbox_target(BinaryId::digest(b"rollback sample"))),
        );
        let checkpoint = machine
            .begin_remote_command(&open)
            .expect("begin host-side open");
        let failure = machine
            .bind_sandbox_failure(
                SandboxFailureStage::Discovery,
                SandboxFailureKind::HelperFailure,
                true,
                DiagnosticText::new("provider discovery failed").expect("detail"),
            )
            .expect("bind exact launch context");
        machine
            .validate_sandbox_failure(&failure)
            .expect("host and validating reducer share the binding");
        assert!(matches!(
            failure.context,
            SandboxFailureContext::Launch { .. }
        ));

        machine
            .reject_remote_command(checkpoint)
            .expect("rollback visible state");
        assert_eq!(machine.state().kind(), SessionStateKind::Idle);
        assert!(machine.expected_attestation().is_none());
        assert_eq!(machine.last_command_id(), Some(open.command_id));
        assert!(matches!(
            machine.begin_remote_command(&open),
            Err(SessionMachineError::NonMonotonicCommandId { .. })
        ));
        let replacement = command(
            2,
            initial,
            DebugCommand::Open(sandbox_target(BinaryId::digest(b"rollback sample"))),
        );
        let _replacement_checkpoint = machine
            .begin_remote_command(&replacement)
            .expect("new command id remains usable");
        assert_eq!(machine.state().state_token().generation.get(), 3);
    }

    #[test]
    fn host_reducer_binds_and_retains_exact_inherited_failure_context() {
        let process = process_identity(7100, 50, b"inherited failure image");
        let binding = SandboxOwnershipBinding::new(
            session_id(),
            process.clone(),
            AttachMode::Debug,
            SandboxProviderSelection::LocalAppContainer,
            PolicyDigest::new("6".repeat(64)).expect("policy digest"),
            provisioning_epoch(),
        );
        let lease_id = ownership_lease_id('6');
        let mut machine = machine();
        machine
            .register_sandbox_ownership_lease(SandboxOwnershipLease::new(
                lease_id.clone(),
                binding.clone(),
            ))
            .expect("register ownership lease");
        let initial = machine.state().state_token();
        let open = command(
            1,
            initial,
            DebugCommand::Open(attach_target(AttachScope::OwnedSandbox {
                process,
                ownership_lease: lease_id,
            })),
        );
        let _checkpoint = machine
            .begin_remote_command(&open)
            .expect("begin inherited open");
        let failure = machine
            .bind_sandbox_failure(
                SandboxFailureStage::Runtime,
                SandboxFailureKind::HelperFailure,
                false,
                DiagnosticText::new("inherited attach failed").expect("detail"),
            )
            .expect("bind inherited failure");
        machine
            .validate_sandbox_failure(&failure)
            .expect("exact inherited failure");
        assert!(matches!(
            &failure.context,
            SandboxFailureContext::InheritedAttach { process, mode }
                if process == binding.process() && *mode == binding.mode()
        ));

        let mut wrong_process = failure.clone();
        let SandboxFailureContext::InheritedAttach { process, .. } = &mut wrong_process.context
        else {
            unreachable!("inherited context")
        };
        *process = process_identity(7100, 51, b"inherited failure image");
        assert_eq!(
            machine.validate_sandbox_failure(&wrong_process),
            Err(SessionMachineError::SandboxFailure(
                SandboxFailureValidationError::ProcessIdentity
            ))
        );
        let mut wrong_mode = failure.clone();
        let SandboxFailureContext::InheritedAttach { mode, .. } = &mut wrong_mode.context else {
            unreachable!("inherited context")
        };
        *mode = AttachMode::Snapshot;
        assert_eq!(
            machine.validate_sandbox_failure(&wrong_mode),
            Err(SessionMachineError::SandboxFailure(
                SandboxFailureValidationError::AttachMode
            ))
        );

        machine
            .mark_failed(failure.detail.as_str())
            .expect("retain inherited failure");
        assert_eq!(machine.state().kind(), SessionStateKind::Failed);
        assert_eq!(machine.inherited_sandbox(), Some(&binding));
        assert!(machine.requires_cleanup_receipt());
    }

    #[test]
    fn inherited_sandbox_close_requires_exact_fresh_cleanup_and_rejects_replay() {
        let process = process_identity(7000, 40, b"inherited cleanup image");
        let binding = SandboxOwnershipBinding::new(
            session_id(),
            process.clone(),
            AttachMode::Debug,
            SandboxProviderSelection::LocalAppContainer,
            PolicyDigest::new("7".repeat(64)).expect("policy digest"),
            provisioning_epoch(),
        );
        let lease_id = ownership_lease_id('7');
        let mut machine = machine();
        machine
            .register_sandbox_ownership_lease(SandboxOwnershipLease::new(
                lease_id.clone(),
                binding.clone(),
            ))
            .expect("register ownership lease");
        let initial = machine.state().state_token();
        machine
            .accept_command(&command(
                1,
                initial,
                DebugCommand::Open(attach_target(AttachScope::OwnedSandbox {
                    process,
                    ownership_lease: lease_id,
                })),
            ))
            .expect("open inherited sandbox");
        machine
            .mark_stopped(StopReason::Initial, ThreadId::new(9).expect("thread id"))
            .expect("initial stop");
        let stopped = machine.state().state_token();
        machine
            .accept_command(&command(2, stopped, DebugCommand::Close { state: stopped }))
            .expect("begin inherited close");

        assert_eq!(
            machine.complete_close(None),
            Err(SessionMachineError::MissingCleanupReceipt)
        );

        let exact = inherited_cleanup_receipt(&binding);
        let mut mismatches = Vec::new();

        let mut wrong_session = exact.clone();
        wrong_session.session_id = SessionId::new(12).expect("other session");
        mismatches.push(wrong_session);

        let mut stale_epoch = exact.clone();
        stale_epoch.provisioning_epoch =
            ProvisioningEpoch::new("8".repeat(64)).expect("stale epoch");
        mismatches.push(stale_epoch);

        let mut wrong_provider = exact.clone();
        wrong_provider.provider = SandboxProviderSelection::HyperV;
        mismatches.push(wrong_provider);

        let mut wrong_policy = exact.clone();
        wrong_policy.policy_digest = PolicyDigest::new("9".repeat(64)).expect("other policy");
        mismatches.push(wrong_policy);

        let mut wrong_process = exact.clone();
        wrong_process.process = Some(process_identity(7000, 41, b"inherited cleanup image"));
        mismatches.push(wrong_process);

        for mismatch in mismatches {
            assert_eq!(
                machine.complete_close(Some(&mismatch)),
                Err(SessionMachineError::InheritedCleanupReceiptMismatch)
            );
            assert_eq!(machine.state().kind(), SessionStateKind::Closing);
        }

        machine
            .complete_close(Some(&exact))
            .expect("exact cleanup closes inherited sandbox");
        assert_eq!(machine.state().kind(), SessionStateKind::Closed);
        assert!(matches!(
            machine.complete_close(Some(&exact)),
            Err(SessionMachineError::InvalidTransition {
                from: SessionStateKind::Closed,
                action: "complete close",
            })
        ));
    }

    #[test]
    fn policy_session_mismatch_fails_without_changing_session_state() {
        let mut target = sandbox_target(BinaryId::digest(b"sample"));
        let DebugTargetRequest::Launch(LaunchTarget {
            environment: LaunchEnvironment::Sandboxed { policy },
            ..
        }) = &mut target
        else {
            unreachable!("sandbox launch")
        };
        policy.session_id = SessionId::new(99).expect("other session");
        policy.policy_approval =
            SandboxPolicyApprovalId::new(policy.session_id, "other-ack").expect("acknowledgement");

        let mut machine = machine();
        let initial = machine.state().state_token();
        assert_eq!(
            machine.accept_command(&command(1, initial, DebugCommand::Open(target))),
            Err(SessionMachineError::SessionBindingMismatch)
        );
        assert_eq!(machine.state().kind(), SessionStateKind::Idle);
        assert_eq!(machine.last_command_id(), Some(CommandId::new(1).unwrap()));
    }
}
