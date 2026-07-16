//! Host-local, one-use authorization leases for live debugger operations.
//!
//! Lease grants are deliberately not serializable. A trusted session worker
//! registers them out of band, while untrusted command envelopes carry only a
//! 256-bit lease identifier. Possessing a syntactically valid identifier does
//! not create authority unless the exact grant is registered and unconsumed.

use resymbol_core::BinaryId;

use crate::identity::{HostRiskLeaseId, ProvisioningEpoch, SandboxOwnershipLeaseId, SessionId};
use crate::protocol::{AttachMode, ProcessIdentity};
use crate::sandbox::{PolicyDigest, SandboxProviderSelection};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRiskOperation {
    Launch {
        binary_id: BinaryId,
    },
    Attach {
        process: ProcessIdentity,
        mode: AttachMode,
    },
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
    id: HostRiskLeaseId,
    session_id: SessionId,
    operation: HostRiskOperation,
}

impl HostRiskLease {
    #[must_use]
    pub const fn new(
        id: HostRiskLeaseId,
        session_id: SessionId,
        operation: HostRiskOperation,
    ) -> Self {
        Self {
            id,
            session_id,
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
    pub const fn operation(&self) -> &HostRiskOperation {
        &self.operation
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
    pub fn into_binding(self) -> SandboxOwnershipBinding {
        self.binding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::identity::{HostRiskLeaseId, SandboxOwnershipLeaseId};
    use crate::protocol::{ProcessId, ProcessStartKey};

    fn assert_clone<T: Clone>() {}

    #[test]
    fn lease_inputs_remain_cloneable_without_cloning_authority() {
        assert_clone::<HostRiskLeaseId>();
        assert_clone::<SandboxOwnershipLeaseId>();
        assert_clone::<HostRiskOperation>();
        assert_clone::<SandboxOwnershipBinding>();
    }

    #[test]
    fn one_use_lease_apis_preserve_move_based_registration_inputs() {
        let session_id = SessionId::new(7).expect("session id");
        let risk_id = HostRiskLeaseId::new("a".repeat(64)).expect("host-risk lease id");
        let binary_id = BinaryId::digest(b"approved target");
        let risk = HostRiskLease::new(
            risk_id.clone(),
            session_id,
            HostRiskOperation::Launch {
                binary_id: binary_id.clone(),
            },
        );
        assert_eq!(risk.id(), &risk_id);
        assert_eq!(risk.session_id(), session_id);
        assert_eq!(risk.operation(), &HostRiskOperation::Launch { binary_id });

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
