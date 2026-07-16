//! Host-local, one-use authorization leases for live debugger operations.
//!
//! Lease grants are deliberately not serializable. A trusted session worker
//! registers them out of band, while untrusted command envelopes carry only a
//! 256-bit lease identifier. Possessing a syntactically valid identifier does
//! not create authority unless the exact grant is registered and unconsumed.

use std::path::{Path, PathBuf};

use resymbol_core::BinaryId;

use crate::identity::{HostRiskLeaseId, ProvisioningEpoch, SandboxOwnershipLeaseId, SessionId};
use crate::protocol::{AttachMode, LaunchTarget, ProcessIdentity};
use crate::sandbox::{PolicyDigest, SandboxProviderSelection};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRiskOperation {
    Launch {
        intent: HostLaunchIntent,
    },
    Attach {
        process: ProcessIdentity,
        mode: AttachMode,
    },
}

/// Exact, non-authority description of one approved host launch.
///
/// The environment is implicitly `Host`: sandboxed launches use provider
/// attestation instead of a host-risk lease. Lexical executable and working
/// directory paths are retained together so relative resolution cannot be
/// changed after approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLaunchIntent {
    binary_id: BinaryId,
    executable: PathBuf,
    arguments: Vec<String>,
    working_directory: Option<PathBuf>,
    stop_before_entry: bool,
}

impl HostLaunchIntent {
    #[must_use]
    pub fn from_target(target: &LaunchTarget) -> Self {
        Self {
            binary_id: target.binary_id.clone(),
            executable: target.executable.clone(),
            arguments: target.arguments.clone(),
            working_directory: target.working_directory.clone(),
            stop_before_entry: target.stop_before_entry,
        }
    }

    #[must_use]
    pub const fn binary_id(&self) -> &BinaryId {
        &self.binary_id
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    #[must_use]
    pub fn working_directory(&self) -> Option<&Path> {
        self.working_directory.as_deref()
    }

    #[must_use]
    pub const fn stop_before_entry(&self) -> bool {
        self.stop_before_entry
    }
}

/// Cloneable comparison record for the controller-side transcript verifier.
///
/// This value is not authority. The sole move-only [`HostRiskLease`] must be
/// registered independently on the host session worker before the command can
/// succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRiskVerifier {
    id: HostRiskLeaseId,
    session_id: SessionId,
    provisioning_epoch: ProvisioningEpoch,
    operation: HostRiskOperation,
}

impl HostRiskVerifier {
    #[must_use]
    pub const fn new(
        id: HostRiskLeaseId,
        session_id: SessionId,
        provisioning_epoch: ProvisioningEpoch,
        operation: HostRiskOperation,
    ) -> Self {
        Self {
            id,
            session_id,
            provisioning_epoch,
            operation,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &HostRiskLeaseId {
        &self.id
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
    pub const fn operation(&self) -> &HostRiskOperation {
        &self.operation
    }
}

/// Host-local approval grant. Register this on the owning session worker only
/// after the UI has approved the exact operation and target.
///
/// The lease intentionally does not implement [`Clone`]. Moving it into the
/// session worker transfers its one-use authority; duplicating it would create
/// two independently consumable grants with the same identifier.
///
/// ```compile_fail
/// use resymbol_debugger::HostRiskLease;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<HostRiskLease>();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct HostRiskLease {
    verifier: HostRiskVerifier,
}

impl HostRiskLease {
    #[must_use]
    pub const fn new(
        id: HostRiskLeaseId,
        session_id: SessionId,
        provisioning_epoch: ProvisioningEpoch,
        operation: HostRiskOperation,
    ) -> Self {
        Self {
            verifier: HostRiskVerifier::new(id, session_id, provisioning_epoch, operation),
        }
    }

    #[must_use]
    pub const fn id(&self) -> &HostRiskLeaseId {
        self.verifier.id()
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.verifier.session_id()
    }

    #[must_use]
    pub const fn provisioning_epoch(&self) -> &ProvisioningEpoch {
        self.verifier.provisioning_epoch()
    }

    #[must_use]
    pub const fn operation(&self) -> &HostRiskOperation {
        self.verifier.operation()
    }

    #[must_use]
    pub fn verifier(&self) -> HostRiskVerifier {
        self.verifier.clone()
    }

    #[must_use]
    pub(crate) fn into_verifier(self) -> HostRiskVerifier {
        self.verifier
    }
}

/// Provider-owned proof that one exact process belongs to one exact sandbox
/// provisioning instance. The binding remains available after its one-use
/// lease identifier is consumed so a future platform host can retain cleanup
/// and provider ownership context without trusting command payload fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxOwnershipBinding {
    session_id: SessionId,
    process: ProcessIdentity,
    mode: AttachMode,
    provider: SandboxProviderSelection,
    policy_digest: PolicyDigest,
    provisioning_epoch: ProvisioningEpoch,
}

impl SandboxOwnershipBinding {
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        process: ProcessIdentity,
        mode: AttachMode,
        provider: SandboxProviderSelection,
        policy_digest: PolicyDigest,
        provisioning_epoch: ProvisioningEpoch,
    ) -> Self {
        Self {
            session_id,
            process,
            mode,
            provider,
            policy_digest,
            provisioning_epoch,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    #[must_use]
    pub const fn mode(&self) -> AttachMode {
        self.mode
    }

    #[must_use]
    pub const fn provider(&self) -> &SandboxProviderSelection {
        &self.provider
    }

    #[must_use]
    pub const fn policy_digest(&self) -> &PolicyDigest {
        &self.policy_digest
    }

    #[must_use]
    pub const fn provisioning_epoch(&self) -> &ProvisioningEpoch {
        &self.provisioning_epoch
    }
}

/// Host-local, provider-issued one-use grant. It is intentionally not Serde;
/// only its unpredictable identifier crosses the command protocol.
///
/// The lease intentionally does not implement [`Clone`]. Moving it into the
/// session worker transfers its one-use authority while the cloneable binding
/// remains ordinary evidence after successful consumption.
///
/// ```compile_fail
/// use resymbol_debugger::SandboxOwnershipLease;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<SandboxOwnershipLease>();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct SandboxOwnershipLease {
    id: SandboxOwnershipLeaseId,
    binding: SandboxOwnershipBinding,
}

/// Cloneable comparison record for the controller-side transcript verifier.
/// The provider-issued [`SandboxOwnershipLease`] remains the sole authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxOwnershipVerifier {
    id: SandboxOwnershipLeaseId,
    binding: SandboxOwnershipBinding,
}

impl SandboxOwnershipVerifier {
    #[must_use]
    pub const fn new(id: SandboxOwnershipLeaseId, binding: SandboxOwnershipBinding) -> Self {
        Self { id, binding }
    }

    #[must_use]
    pub const fn id(&self) -> &SandboxOwnershipLeaseId {
        &self.id
    }

    #[must_use]
    pub const fn binding(&self) -> &SandboxOwnershipBinding {
        &self.binding
    }
}

impl SandboxOwnershipLease {
    #[must_use]
    pub const fn new(id: SandboxOwnershipLeaseId, binding: SandboxOwnershipBinding) -> Self {
        Self { id, binding }
    }

    #[must_use]
    pub const fn id(&self) -> &SandboxOwnershipLeaseId {
        &self.id
    }

    #[must_use]
    pub const fn binding(&self) -> &SandboxOwnershipBinding {
        &self.binding
    }

    #[must_use]
    pub fn verifier(&self) -> SandboxOwnershipVerifier {
        SandboxOwnershipVerifier::new(self.id.clone(), self.binding.clone())
    }

    #[must_use]
    pub(crate) fn into_verifier(self) -> SandboxOwnershipVerifier {
        SandboxOwnershipVerifier::new(self.id, self.binding)
    }

    #[must_use]
    pub fn into_binding(self) -> SandboxOwnershipBinding {
        self.binding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::identity::{HostRiskLeaseId, SandboxOwnershipLeaseId};
    use crate::protocol::{LaunchEnvironment, ProcessId, ProcessStartKey};

    fn assert_clone<T: Clone>() {}

    #[test]
    fn lease_inputs_remain_cloneable_without_cloning_authority() {
        assert_clone::<HostRiskLeaseId>();
        assert_clone::<SandboxOwnershipLeaseId>();
        assert_clone::<HostRiskOperation>();
        assert_clone::<HostRiskVerifier>();
        assert_clone::<SandboxOwnershipBinding>();
        assert_clone::<SandboxOwnershipVerifier>();
    }

    #[test]
    fn one_use_lease_apis_preserve_move_based_registration_inputs() {
        let session_id = SessionId::new(7).expect("session id");
        let risk_id = HostRiskLeaseId::new("a".repeat(64)).expect("host-risk lease id");
        let binary_id = BinaryId::digest(b"approved target");
        let epoch = ProvisioningEpoch::new("9".repeat(64)).expect("provisioning epoch");
        let target = LaunchTarget {
            binary_id,
            executable: PathBuf::from("sample.exe"),
            arguments: vec!["--safe".to_owned()],
            working_directory: Some(PathBuf::from("workspace")),
            environment: LaunchEnvironment::Host {
                risk_lease: risk_id.clone(),
            },
            stop_before_entry: true,
        };
        let operation = HostRiskOperation::Launch {
            intent: HostLaunchIntent::from_target(&target),
        };
        let risk = HostRiskLease::new(
            risk_id.clone(),
            session_id,
            epoch.clone(),
            operation.clone(),
        );
        assert_eq!(risk.id(), &risk_id);
        assert_eq!(risk.session_id(), session_id);
        assert_eq!(risk.provisioning_epoch(), &epoch);
        assert_eq!(risk.operation(), &operation);
        assert_eq!(risk.verifier().operation(), &operation);

        let binding = SandboxOwnershipBinding::new(
            session_id,
            ProcessIdentity {
                process_id: ProcessId::new(42).expect("process id"),
                start_key: ProcessStartKey::new(11).expect("process start key"),
                binary_id: BinaryId::digest(b"owned target"),
            },
            AttachMode::Debug,
            SandboxProviderSelection::LocalAppContainer,
            PolicyDigest::new("b".repeat(64)).expect("policy digest"),
            ProvisioningEpoch::new("c".repeat(64)).expect("provisioning epoch"),
        );
        let ownership_id =
            SandboxOwnershipLeaseId::new("d".repeat(64)).expect("ownership lease id");
        let ownership = SandboxOwnershipLease::new(ownership_id.clone(), binding.clone());
        assert_eq!(ownership.id(), &ownership_id);
        assert_eq!(ownership.binding(), &binding);
        assert_eq!(ownership.into_binding(), binding);
    }
}
