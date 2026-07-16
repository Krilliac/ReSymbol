use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const SECURITY_NONCE_HEX_BYTES: usize = 64;

/// Stable identity for one debugger session across the protocol, sandbox,
/// attestation, and cleanup contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl SessionId {
    pub fn new(value: u64) -> Result<Self, SessionIdError> {
        if value == 0 {
            Err(SessionIdError)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Serialize for SessionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("session identifier must be nonzero")]
pub struct SessionIdError;

macro_rules! security_nonce {
    ($name:ident, $error:ident, $message:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Constructs a wire-safe identifier. Production callers must use
            /// 256 bits from a cryptographically secure random source; the
            /// constructor validates representation, not entropy provenance.
            pub fn new(value: impl Into<String>) -> Result<Self, $error> {
                let value = value.into();
                if value.len() != SECURITY_NONCE_HEX_BYTES
                    || !value
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                {
                    return Err($error);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
        #[error($message)]
        pub struct $error;
    };
}

security_nonce!(
    HostRiskLeaseId,
    HostRiskLeaseIdError,
    "host-risk lease id must be 64 lowercase hexadecimal characters"
);
security_nonce!(
    SandboxOwnershipLeaseId,
    SandboxOwnershipLeaseIdError,
    "sandbox-ownership lease id must be 64 lowercase hexadecimal characters"
);
security_nonce!(
    ProvisioningEpoch,
    ProvisioningEpochError,
    "provisioning epoch must be 64 lowercase hexadecimal characters"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_nonce_types_are_strict_and_round_trip_as_strings() {
        let id = HostRiskLeaseId::new("a".repeat(64)).expect("valid lease id");
        assert_eq!(
            serde_json::to_string(&id).expect("serialize"),
            format!("\"{}\"", "a".repeat(64))
        );
        assert_eq!(
            serde_json::from_str::<HostRiskLeaseId>(&format!("\"{}\"", "a".repeat(64)))
                .expect("deserialize"),
            id
        );
        assert!(HostRiskLeaseId::new("A".repeat(64)).is_err());
        assert!(SandboxOwnershipLeaseId::new("b".repeat(63)).is_err());
        assert!(ProvisioningEpoch::new("g".repeat(64)).is_err());
    }
}
