//! Pure debugger-session state reduction.

use resymbol_core::BinaryId;
use thiserror::Error;

use crate::protocol::{
    AttachMode, AttachScope, CommandEnvelope, CommandId, DebugCommand, DebugTargetRequest,
    ProcessId, ProtocolValidationError, RunId, RunToken, SessionId, SessionState, SessionStateKind,
    StateGeneration, StateToken, StopId, StopReason, StopToken, ThreadId,
};
use crate::sandbox::{
    ExpectedSandboxAttestation, HelperBuildId, PolicyValidationError, RiskAcknowledgementId,
    SandboxAttestation, SandboxCleanupReceipt, SandboxLifecycleState, SandboxMachine,
    SandboxMachineError,
};

/// Single-owner, value-only reducer for one debugger session.
///
/// All methods are free of platform I/O and handles. The value may move across
/// threads, but mutation must be serialized by its owner (later, one host
/// `SessionWorker`). An active session is non-hot-reloadable and must reach
/// `Closed` before provider code is replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMachine {
    session_id: SessionId,
    helper_build: HelperBuildId,
    state: SessionState,
    target: Option<DebugTargetRequest>,
    last_command_id: Option<CommandId>,
    last_stop_id: u64,
    last_run_id: u64,
    execution_gate: ExecutionGate,
    sandbox: Option<SandboxMachine>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionGate {
    NotApplicable,
    HostRiskAccepted,
    InheritedSandbox,
    SandboxPending,
    SandboxAccepted,
}

impl SessionMachine {
    #[must_use]
    pub fn new(session_id: SessionId, helper_build: HelperBuildId) -> Self {
        let token = StateToken {
            session_id,
            generation: StateGeneration::new(1).expect("initial generation is nonzero"),
        };
        Self {
            session_id,
            helper_build,
            state: SessionState::Idle { token },
            target: None,
            last_command_id: None,
            last_stop_id: 0,
            last_run_id: 0,
            execution_gate: ExecutionGate::NotApplicable,
            sandbox: None,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
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
        match (&mut self.sandbox, receipt) {
            (Some(sandbox), Some(receipt)) => {
                sandbox.close(receipt)?;
            }
            (Some(_), None) => return Err(SessionMachineError::MissingCleanupReceipt),
            (None, Some(_)) => return Err(SessionMachineError::UnexpectedCleanupReceipt),
            (None, None) => {}
        }
        self.transition_to(SessionState::Closed { token: next })?;
        Ok(&self.state)
    }

    fn accept_open(&mut self, target: DebugTargetRequest) -> Result<(), SessionMachineError> {
        let (mut sandbox, gate) = match &target {
            DebugTargetRequest::Launch(target) => match &target.environment {
                crate::protocol::LaunchEnvironment::Sandboxed { policy } => {
                    self.require_session(policy.session_id)?;
                    let expected = ExpectedSandboxAttestation::from_policy(
                        target.binary_id.clone(),
                        policy,
                        self.helper_build.clone(),
                    )?;
                    let mut sandbox = SandboxMachine::new(expected)?;
                    sandbox.begin_provisioning()?;
                    (Some(sandbox), ExecutionGate::SandboxPending)
                }
                crate::protocol::LaunchEnvironment::Host {
                    risk_acknowledgement,
                } => {
                    self.require_acknowledgement(risk_acknowledgement)?;
                    (None, ExecutionGate::HostRiskAccepted)
                }
            },
            DebugTargetRequest::Attach(target) => match &target.scope {
                AttachScope::Host {
                    risk_acknowledgement,
                    ..
                } => {
                    self.require_acknowledgement(risk_acknowledgement)?;
                    (None, ExecutionGate::HostRiskAccepted)
                }
                AttachScope::OwnedSandbox {
                    owner_session_id, ..
                } => {
                    self.require_session(*owner_session_id)?;
                    (None, ExecutionGate::InheritedSandbox)
                }
            },
            DebugTargetRequest::Dump(_) | DebugTargetRequest::Offline(_) => {
                (None, ExecutionGate::NotApplicable)
            }
        };
        let next = self.next_state_token()?;
        self.execution_gate = gate;
        self.sandbox = sandbox.take();
        self.target = Some(target.clone());
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

    fn require_acknowledgement(
        &self,
        acknowledgement: &RiskAcknowledgementId,
    ) -> Result<(), SessionMachineError> {
        self.require_session(acknowledgement.session_id())
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
    #[error("sandbox policy, acknowledgement, or inherited owner uses another session")]
    SessionBindingMismatch,
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
        DebugTargetRequest, LaunchEnvironment, LaunchTarget, MemoryAddress, ProtocolVersion,
    };
    use crate::sandbox::{
        ChildProcessProfile, CleanupOutcome, CleanupReceiptId, DynamicCodeProfile,
        IsolationBoundary, PolicyDigest, ProcessMitigationProfile, RiskAcknowledgementId,
        SandboxGuarantee, SandboxNetworkMode, SandboxPolicy, SandboxProviderSelection,
        SandboxResourceLimits, Win32kProfile,
    };

    fn session_id() -> SessionId {
        SessionId::new(11).expect("session id")
    }

    fn helper_build() -> HelperBuildId {
        HelperBuildId::new("debugger-host-1.0.0+test").expect("helper build")
    }

    fn machine() -> SessionMachine {
        SessionMachine::new(session_id(), helper_build())
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
            risk_acknowledgement: RiskAcknowledgementId::new(session_id, "sandbox-ack")
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

    fn host_target(binary_id: BinaryId) -> DebugTargetRequest {
        DebugTargetRequest::Launch(LaunchTarget {
            binary_id,
            executable: PathBuf::from("sample.exe"),
            arguments: Vec::new(),
            working_directory: None,
            environment: LaunchEnvironment::Host {
                risk_acknowledgement: RiskAcknowledgementId::new(session_id(), "host-ack")
                    .expect("acknowledgement"),
            },
            stop_before_entry: true,
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
            provider: expected.provider.clone(),
            policy_digest: expected.policy_digest.clone(),
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
    fn host_risk_override_is_session_bound_but_needs_no_sandbox_attestation() {
        let binary = BinaryId::digest(b"host target");
        let mut machine = machine();
        let initial = machine.state().state_token();
        machine
            .accept_command(&command(
                1,
                initial,
                DebugCommand::Open(host_target(binary.clone())),
            ))
            .expect("host open");
        assert_eq!(machine.target_binary_id(), Some(&binary));
        assert!(machine.expected_attestation().is_none());
        machine
            .mark_stopped(StopReason::Initial, ThreadId::new(7).expect("thread id"))
            .expect("host initial stop");
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
        policy.risk_acknowledgement =
            RiskAcknowledgementId::new(policy.session_id, "other-ack").expect("acknowledgement");

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
