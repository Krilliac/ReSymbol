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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
