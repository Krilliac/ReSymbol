//! Host-local, one-use authorization leases for live debugger operations.
//!
//! Lease grants are deliberately not serializable. A trusted session worker
//! registers them out of band, while untrusted command envelopes carry only a
//! 256-bit lease identifier. Possessing a syntactically valid identifier does
//! not create authority unless the exact grant is registered and unconsumed.

use std::fmt;
use std::path::{Path, PathBuf};

use resymbol_core::BinaryId;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identity::{HostRiskLeaseId, ProvisioningEpoch, SandboxOwnershipLeaseId, SessionId};
use crate::protocol::{AttachMode, LaunchEnvironment, LaunchTarget, ProcessIdentity};
use crate::sandbox::{PolicyDigest, SandboxProviderSelection};

const AUTHORIZATION_ISSUER_SECRET_BYTES: usize = 32;
const HOST_RISK_LEASE_DOMAIN: &[u8] = b"resymbol-host-risk-lease-v1";
const SANDBOX_OWNERSHIP_LEASE_DOMAIN: &[u8] = b"resymbol-sandbox-ownership-lease-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthorizationIssuanceError {
    #[error("operating-system entropy is unavailable for authorization lease issuance")]
    EntropyUnavailable,
    #[error("authorization lease issuer exhausted its identifier sequence")]
    IdentifierSequenceExhausted,
}

#[derive(PartialEq, Eq)]
struct LeaseIdSequence {
    secret: [u8; AUTHORIZATION_ISSUER_SECRET_BYTES],
    next_counter: u128,
}

impl LeaseIdSequence {
    fn new() -> Result<Self, AuthorizationIssuanceError> {
        let mut secret = [0_u8; AUTHORIZATION_ISSUER_SECRET_BYTES];
        getrandom::fill(&mut secret).map_err(|_| AuthorizationIssuanceError::EntropyUnavailable)?;
        Ok(Self {
            secret,
            next_counter: 0,
        })
    }

    fn issue(&mut self, domain: &[u8]) -> Result<String, AuthorizationIssuanceError> {
        let counter = self.next_counter;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(AuthorizationIssuanceError::IdentifierSequenceExhausted)?;
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(self.secret);
        digest.update(counter.to_be_bytes());
        let digest = digest.finalize();
        let mut encoded = String::with_capacity(digest.len() * 2);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            encoded.push(HEX[usize::from(byte >> 4)] as char);
            encoded.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        Ok(encoded)
    }
}

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
/// Create an intent before issuing its lease with [`HostLaunchIntent::new`].
/// Sandboxed launches use provider attestation instead of a host-risk lease and
/// are rejected by [`HostLaunchIntent::from_target`]. Executable and working
/// directory paths are bound exactly as lexical values. This does not
/// canonicalize them or guarantee how a relative executable will be resolved;
/// callers that require filesystem identity must approve an absolute or
/// independently canonicalized path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLaunchIntent {
    binary_id: BinaryId,
    executable: PathBuf,
    arguments: Vec<String>,
    working_directory: Option<PathBuf>,
    stop_before_entry: bool,
}

impl HostLaunchIntent {
    /// Describes an approved host launch before its unpredictable lease ID is
    /// issued. This value carries no authority by itself.
    #[must_use]
    pub fn new(
        binary_id: BinaryId,
        executable: impl Into<PathBuf>,
        arguments: Vec<String>,
        working_directory: Option<PathBuf>,
        stop_before_entry: bool,
    ) -> Self {
        Self {
            binary_id,
            executable: executable.into(),
            arguments,
            working_directory,
            stop_before_entry,
        }
    }

    pub fn from_target(target: &LaunchTarget) -> Result<Self, HostLaunchIntentError> {
        if !matches!(&target.environment, LaunchEnvironment::Host { .. }) {
            return Err(HostLaunchIntentError::SandboxedTarget);
        }
        Ok(Self {
            binary_id: target.binary_id.clone(),
            executable: target.executable.clone(),
            arguments: target.arguments.clone(),
            working_directory: target.working_directory.clone(),
            stop_before_entry: target.stop_before_entry,
        })
    }

    /// Binds this exact approved intent to a freshly issued lease ID.
    #[must_use]
    pub fn into_target(self, risk_lease: HostRiskLeaseId) -> LaunchTarget {
        LaunchTarget {
            binary_id: self.binary_id,
            executable: self.executable,
            arguments: self.arguments,
            working_directory: self.working_directory,
            environment: LaunchEnvironment::Host { risk_lease },
            stop_before_entry: self.stop_before_entry,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HostLaunchIntentError {
    #[error("sandboxed launch targets cannot be authorized by a host-risk lease")]
    SandboxedTarget,
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

/// Trusted mint for unpredictable host-risk grants.
///
/// One issuer owns one secret-backed monotonic sequence. It is deliberately
/// non-cloneable, and each call returns the sole move-only lease together with
/// a cloneable, non-authority verifier for the controller-side reducer.
///
/// ```compile_fail
/// use resymbol_debugger::HostRiskLeaseIssuer;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<HostRiskLeaseIssuer>();
/// ```
pub struct HostRiskLeaseIssuer {
    sequence: LeaseIdSequence,
}

impl HostRiskLeaseIssuer {
    pub fn new() -> Result<Self, AuthorizationIssuanceError> {
        Ok(Self {
            sequence: LeaseIdSequence::new()?,
        })
    }

    pub fn issue(
        &mut self,
        session_id: SessionId,
        provisioning_epoch: ProvisioningEpoch,
        operation: HostRiskOperation,
    ) -> Result<(HostRiskLease, HostRiskVerifier), AuthorizationIssuanceError> {
        let id = HostRiskLeaseId::new(self.sequence.issue(HOST_RISK_LEASE_DOMAIN)?)
            .expect("SHA-256 authorization ids are valid lowercase hexadecimal");
        let verifier = HostRiskVerifier::new(id, session_id, provisioning_epoch, operation);
        let lease = HostRiskLease {
            verifier: verifier.clone(),
        };
        Ok((lease, verifier))
    }

    /// Atomically mints the authority pair and binds its unpredictable ID to
    /// the exact approved launch fields.
    pub fn issue_launch(
        &mut self,
        session_id: SessionId,
        provisioning_epoch: ProvisioningEpoch,
        intent: HostLaunchIntent,
    ) -> Result<(LaunchTarget, HostRiskLease, HostRiskVerifier), AuthorizationIssuanceError> {
        let operation = HostRiskOperation::Launch {
            intent: intent.clone(),
        };
        let (lease, verifier) = self.issue(session_id, provisioning_epoch, operation)?;
        let target = intent.into_target(lease.id().clone());
        Ok((target, lease, verifier))
    }
}

impl fmt::Debug for HostRiskLeaseIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRiskLeaseIssuer")
            .field("issued", &self.sequence.next_counter)
            .finish_non_exhaustive()
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
///
/// ```compile_fail
/// use resymbol_debugger::HostRiskLease;
///
/// // Grants must come from HostRiskLeaseIssuer; caller-chosen IDs cannot mint authority.
/// let _forged = HostRiskLease::new(todo!(), todo!(), todo!(), todo!());
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct HostRiskLease {
    verifier: HostRiskVerifier,
}

impl HostRiskLease {
    #[cfg(test)]
    pub(crate) const fn new_for_test(
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
///
/// ```compile_fail
/// use resymbol_debugger::SandboxOwnershipLease;
///
/// // Grants must come from SandboxOwnershipLeaseIssuer.
/// let _forged = SandboxOwnershipLease::new(todo!(), todo!());
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

/// Trusted sandbox-provider mint for unpredictable ownership grants.
///
/// The issuer is non-cloneable and returns the sole provider authority beside
/// its cloneable, non-authority verifier record.
///
/// ```compile_fail
/// use resymbol_debugger::SandboxOwnershipLeaseIssuer;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<SandboxOwnershipLeaseIssuer>();
/// ```
pub struct SandboxOwnershipLeaseIssuer {
    sequence: LeaseIdSequence,
}

impl SandboxOwnershipLeaseIssuer {
    pub fn new() -> Result<Self, AuthorizationIssuanceError> {
        Ok(Self {
            sequence: LeaseIdSequence::new()?,
        })
    }

    pub fn issue(
        &mut self,
        binding: SandboxOwnershipBinding,
    ) -> Result<(SandboxOwnershipLease, SandboxOwnershipVerifier), AuthorizationIssuanceError> {
        let id = SandboxOwnershipLeaseId::new(self.sequence.issue(SANDBOX_OWNERSHIP_LEASE_DOMAIN)?)
            .expect("SHA-256 authorization ids are valid lowercase hexadecimal");
        let verifier = SandboxOwnershipVerifier::new(id.clone(), binding.clone());
        let lease = SandboxOwnershipLease { id, binding };
        Ok((lease, verifier))
    }
}

impl fmt::Debug for SandboxOwnershipLeaseIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxOwnershipLeaseIssuer")
            .field("issued", &self.sequence.next_counter)
            .finish_non_exhaustive()
    }
}

impl SandboxOwnershipLease {
    #[cfg(test)]
    pub(crate) const fn new_for_test(
        id: SandboxOwnershipLeaseId,
        binding: SandboxOwnershipBinding,
    ) -> Self {
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
            intent: HostLaunchIntent::from_target(&target).expect("host launch target"),
        };
        let risk = HostRiskLease::new_for_test(
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
        let ownership = SandboxOwnershipLease::new_for_test(ownership_id.clone(), binding.clone());
        assert_eq!(ownership.id(), &ownership_id);
        assert_eq!(ownership.binding(), &binding);
        assert_eq!(ownership.into_binding(), binding);
    }

    #[test]
    fn trusted_issuers_return_unique_lease_and_verifier_pairs() {
        let session_id = SessionId::new(7).expect("session id");
        let epoch = ProvisioningEpoch::new("9".repeat(64)).expect("provisioning epoch");
        let intent = HostLaunchIntent::new(
            BinaryId::digest(b"issuer target"),
            PathBuf::from("sample.exe"),
            Vec::new(),
            None,
            true,
        );
        let mut host_issuer = HostRiskLeaseIssuer::new().expect("host-risk issuer");
        let (first_target, first, first_verifier) = host_issuer
            .issue_launch(session_id, epoch.clone(), intent.clone())
            .expect("first host-risk grant");
        let (second_target, second, second_verifier) = host_issuer
            .issue_launch(session_id, epoch, intent.clone())
            .expect("second host-risk grant");
        assert_eq!(first.id(), first_verifier.id());
        assert_eq!(second.id(), second_verifier.id());
        assert_ne!(first.id(), second.id());
        assert_eq!(
            HostLaunchIntent::from_target(&first_target).expect("issued host target"),
            intent
        );
        assert!(matches!(
            &first_target.environment,
            LaunchEnvironment::Host { risk_lease } if risk_lease == first.id()
        ));
        assert!(matches!(
            &second_target.environment,
            LaunchEnvironment::Host { risk_lease } if risk_lease == second.id()
        ));

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
        let mut ownership_issuer = SandboxOwnershipLeaseIssuer::new().expect("ownership issuer");
        let (ownership, ownership_verifier) = ownership_issuer
            .issue(binding)
            .expect("sandbox ownership grant");
        assert_eq!(ownership.id(), ownership_verifier.id());
        assert_eq!(ownership.binding(), ownership_verifier.binding());
    }
}
