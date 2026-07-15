use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use thiserror::Error;

use resymbol_plugin_api::PluginId;

/// A finite confidence value in the inclusive range `0.0..=1.0`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Confidence(f64);

impl Confidence {
    pub fn new(value: f64) -> Result<Self, ClaimValidationError> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ClaimValidationError::InvalidConfidence(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for Confidence {
    type Error = ClaimValidationError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Confidence> for f64 {
    fn from(value: Confidence) -> Self {
        value.get()
    }
}

impl Serialize for Confidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(f64::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// SHA-256 identity for an exact binary build.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BinaryId(String);

impl BinaryId {
    pub fn from_sha256(value: impl Into<String>) -> Result<Self, ClaimValidationError> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ClaimValidationError::InvalidBinaryId(value));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self(encoded)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BinaryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for BinaryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BinaryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_sha256(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Binary container format, kept extensible for plugin-provided loaders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    Wasm,
    Other(String),
}

/// Build identity and address-space metadata used by claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIdentity {
    pub id: BinaryId,
    pub size: u64,
    pub format: BinaryFormat,
    pub architecture: String,
    #[serde(default)]
    pub image_base: u64,
}

impl BinaryIdentity {
    pub fn validate(&self) -> Result<(), ClaimValidationError> {
        if self.architecture.trim().is_empty() {
            return Err(ClaimValidationError::EmptyField("binary.architecture"));
        }
        Ok(())
    }
}

/// Canonical object to which a plugin attaches a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SymbolSubject {
    Function {
        binary: BinaryId,
        rva: u64,
        #[serde(default)]
        size: Option<u64>,
    },
    Global {
        binary: BinaryId,
        rva: u64,
        #[serde(default)]
        size: Option<u64>,
    },
    Type {
        binary: BinaryId,
        key: String,
    },
}

impl SymbolSubject {
    #[must_use]
    pub const fn binary(&self) -> &BinaryId {
        match self {
            Self::Function { binary, .. }
            | Self::Global { binary, .. }
            | Self::Type { binary, .. } => binary,
        }
    }

    fn validate(&self) -> Result<(), ClaimValidationError> {
        match self {
            Self::Function { rva, size, .. } | Self::Global { rva, size, .. } => {
                if let Some(size) = size {
                    if *size == 0 {
                        return Err(ClaimValidationError::ZeroSize);
                    }
                    if rva.checked_add(*size).is_none() {
                        return Err(ClaimValidationError::AddressOverflow);
                    }
                }
            }
            Self::Type { key, .. } if key.trim().is_empty() => {
                return Err(ClaimValidationError::EmptyField("subject.key"));
            }
            Self::Type { .. } => {}
        }
        Ok(())
    }
}

/// One resolved control-flow destination retained by a symbol claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ControlFlowTarget {
    /// An internal function entry in the analyzed image.
    Function { rva: u64 },
    /// An import address table slot in the analyzed image.
    ImportIat { iat_rva: u64 },
}

impl ControlFlowTarget {
    /// Return the target's canonical image-relative address.
    #[must_use]
    pub const fn rva(&self) -> u64 {
        match self {
            Self::Function { rva } => *rva,
            Self::ImportIat { iat_rva } => *iat_rva,
        }
    }

    /// Whether this target identifies an internal function rather than an IAT slot.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self, Self::Function { .. })
    }

    /// Whether this target identifies the internal function at `rva`.
    #[must_use]
    pub const fn is_function_at(&self, rva: u64) -> bool {
        matches!(self, Self::Function { rva: target_rva } if *target_rva == rva)
    }

    fn validate(&self) -> Result<(), ClaimValidationError> {
        match self {
            Self::Function { .. } | Self::ImportIat { .. } => Ok(()),
        }
    }
}

/// Information proposed for a subject. The core preserves competing claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SymbolAssertion {
    Name {
        name: String,
    },
    FunctionPrototype {
        declaration: String,
    },
    FunctionBoundary {
        size: u64,
    },
    FunctionEntry,
    DirectCall {
        call_site_rva: u64,
        target: ControlFlowTarget,
    },
    ThunkTarget {
        target: ControlFlowTarget,
    },
    TypeDefinition {
        declaration: String,
    },
    ClassMembership {
        class_name: String,
    },
    Comment {
        text: String,
    },
}

impl SymbolAssertion {
    fn validate(&self) -> Result<(), ClaimValidationError> {
        let (field, value) = match self {
            Self::Name { name } => ("assertion.name", name.as_str()),
            Self::FunctionPrototype { declaration } => {
                ("assertion.declaration", declaration.as_str())
            }
            Self::TypeDefinition { declaration } => ("assertion.declaration", declaration.as_str()),
            Self::ClassMembership { class_name } => ("assertion.class_name", class_name.as_str()),
            Self::Comment { text } => ("assertion.text", text.as_str()),
            Self::FunctionBoundary { size } => {
                if *size == 0 {
                    return Err(ClaimValidationError::ZeroSize);
                }
                return Ok(());
            }
            Self::FunctionEntry => return Ok(()),
            Self::DirectCall { target, .. } | Self::ThunkTarget { target } => {
                return target.validate();
            }
        };

        if value.trim().is_empty() {
            Err(ClaimValidationError::EmptyField(field))
        } else {
            Ok(())
        }
    }
}

/// Extensible evidence classification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceKind(String);

impl EvidenceKind {
    pub const METADATA: &'static str = "metadata";
    pub const SIGNATURE_MATCH: &'static str = "signature-match";
    pub const CROSS_BUILD_MATCH: &'static str = "cross-build-match";
    pub const CONTROL_FLOW: &'static str = "control-flow";
    pub const DATA_FLOW: &'static str = "data-flow";
    pub const STRING_REFERENCE: &'static str = "string-reference";
    pub const API_USAGE: &'static str = "api-usage";
    pub const MODEL_INFERENCE: &'static str = "model-inference";
    pub const USER_CONFIRMED: &'static str = "user-confirmed";

    pub fn new(value: impl Into<String>) -> Result<Self, ClaimValidationError> {
        let value = value.into();
        let valid = (2..=128).contains(&value.len())
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(ClaimValidationError::InvalidEvidenceKind(value))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for EvidenceKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EvidenceKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// One auditable reason supporting a claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub summary: String,
    #[serde(default)]
    pub confidence: Option<Confidence>,
    /// Stable key/value references such as `source_rva`, `signature`, or `uri`.
    #[serde(default)]
    pub artifacts: BTreeMap<String, String>,
}

impl Evidence {
    pub fn new(
        kind: EvidenceKind,
        summary: impl Into<String>,
    ) -> Result<Self, ClaimValidationError> {
        let evidence = Self {
            kind,
            summary: summary.into(),
            confidence: None,
            artifacts: BTreeMap::new(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), ClaimValidationError> {
        if self.summary.trim().is_empty() {
            return Err(ClaimValidationError::EmptyField("evidence.summary"));
        }
        if self
            .artifacts
            .iter()
            .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
        {
            return Err(ClaimValidationError::InvalidEvidenceArtifact);
        }
        Ok(())
    }
}

/// Entity that produced a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ClaimProducer {
    Core { component: String, version: String },
    Plugin { id: PluginId, version: String },
    User { reviewer: Option<String> },
}

/// Reproducibility details owned by the claim producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimProvenance {
    pub producer: ClaimProducer,
    pub method: String,
    #[serde(default)]
    pub run_id: Option<String>,
}

impl ClaimProvenance {
    fn validate(&self) -> Result<(), ClaimValidationError> {
        if self.method.trim().is_empty() {
            return Err(ClaimValidationError::EmptyField("provenance.method"));
        }
        match &self.producer {
            ClaimProducer::Core { component, version } => {
                require_nonempty("provenance.producer.component", component)?;
                require_nonempty("provenance.producer.version", version)?;
            }
            ClaimProducer::Plugin { version, .. } => {
                require_nonempty("provenance.producer.version", version)?;
            }
            ClaimProducer::User { .. } => {}
        }
        if self
            .run_id
            .as_ref()
            .is_some_and(|run_id| run_id.trim().is_empty())
        {
            return Err(ClaimValidationError::EmptyField("provenance.run_id"));
        }
        Ok(())
    }
}

/// Validated, evidence-backed proposal. Plugins submit claims to the host; only
/// the host decides which claims become accepted graph state.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SymbolClaim {
    subject: SymbolSubject,
    assertion: SymbolAssertion,
    confidence: Confidence,
    evidence: Vec<Evidence>,
    provenance: ClaimProvenance,
}

impl SymbolClaim {
    pub fn new(
        subject: SymbolSubject,
        assertion: SymbolAssertion,
        confidence: Confidence,
        evidence: Vec<Evidence>,
        provenance: ClaimProvenance,
    ) -> Result<Self, ClaimValidationError> {
        let claim = Self {
            subject,
            assertion,
            confidence,
            evidence,
            provenance,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn validate(&self) -> Result<(), ClaimValidationError> {
        self.subject.validate()?;
        self.assertion.validate()?;
        self.provenance.validate()?;
        if self.evidence.is_empty() {
            return Err(ClaimValidationError::MissingEvidence);
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub const fn subject(&self) -> &SymbolSubject {
        &self.subject
    }

    #[must_use]
    pub const fn assertion(&self) -> &SymbolAssertion {
        &self.assertion
    }

    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    #[must_use]
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    #[must_use]
    pub const fn provenance(&self) -> &ClaimProvenance {
        &self.provenance
    }
}

#[derive(Deserialize)]
struct UncheckedSymbolClaim {
    subject: SymbolSubject,
    assertion: SymbolAssertion,
    confidence: Confidence,
    evidence: Vec<Evidence>,
    provenance: ClaimProvenance,
}

impl<'de> Deserialize<'de> for SymbolClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let claim = UncheckedSymbolClaim::deserialize(deserializer)?;
        Self::new(
            claim.subject,
            claim.assertion,
            claim.confidence,
            claim.evidence,
            claim.provenance,
        )
        .map_err(D::Error::custom)
    }
}

/// Canonical collection of exact binary identities and uncollapsed claims.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SymbolGraph {
    binaries: BTreeMap<BinaryId, BinaryIdentity>,
    claims: Vec<SymbolClaim>,
}

impl SymbolGraph {
    #[must_use]
    pub fn binaries(&self) -> &BTreeMap<BinaryId, BinaryIdentity> {
        &self.binaries
    }

    #[must_use]
    pub fn claims(&self) -> &[SymbolClaim] {
        &self.claims
    }

    pub fn insert_binary(
        &mut self,
        binary: BinaryIdentity,
    ) -> Result<Option<BinaryIdentity>, ClaimValidationError> {
        binary.validate()?;
        Ok(self.binaries.insert(binary.id.clone(), binary))
    }

    pub fn submit_claim(&mut self, claim: SymbolClaim) -> Result<(), GraphValidationError> {
        claim.validate()?;
        if !self.binaries.contains_key(claim.subject().binary()) {
            return Err(GraphValidationError::UnknownBinary(
                claim.subject().binary().clone(),
            ));
        }
        self.claims.push(claim);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), GraphValidationError> {
        for (key, binary) in &self.binaries {
            binary.validate()?;
            if key != &binary.id {
                return Err(GraphValidationError::MismatchedBinaryKey {
                    key: key.clone(),
                    identity: binary.id.clone(),
                });
            }
        }
        for claim in &self.claims {
            claim.validate()?;
            if !self.binaries.contains_key(claim.subject().binary()) {
                return Err(GraphValidationError::UnknownBinary(
                    claim.subject().binary().clone(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct UncheckedSymbolGraph {
    binaries: BTreeMap<BinaryId, BinaryIdentity>,
    claims: Vec<SymbolClaim>,
}

impl<'de> Deserialize<'de> for SymbolGraph {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let graph = UncheckedSymbolGraph::deserialize(deserializer)?;
        let graph = Self {
            binaries: graph.binaries,
            claims: graph.claims,
        };
        graph.validate().map_err(D::Error::custom)?;
        Ok(graph)
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum ClaimValidationError {
    #[error("confidence must be finite and in 0.0..=1.0, got {0}")]
    InvalidConfidence(f64),
    #[error("invalid SHA-256 binary identity `{0}`")]
    InvalidBinaryId(String),
    #[error("invalid evidence kind `{0}`")]
    InvalidEvidenceKind(String),
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("symbol size must be greater than zero")]
    ZeroSize,
    #[error("symbol address range overflows")]
    AddressOverflow,
    #[error("a symbol claim must contain at least one evidence item")]
    MissingEvidence,
    #[error("evidence artifact keys and values must not be empty")]
    InvalidEvidenceArtifact,
}

#[derive(Debug, Error, PartialEq)]
pub enum GraphValidationError {
    #[error(transparent)]
    InvalidClaim(#[from] ClaimValidationError),
    #[error("claim references unknown binary {0}")]
    UnknownBinary(BinaryId),
    #[error("binary map key {key} does not match embedded identity {identity}")]
    MismatchedBinaryKey { key: BinaryId, identity: BinaryId },
}

fn require_nonempty(field: &'static str, value: &str) -> Result<(), ClaimValidationError> {
    if value.trim().is_empty() {
        Err(ClaimValidationError::EmptyField(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary_id() -> BinaryId {
        BinaryId::digest(b"test binary")
    }

    fn provenance() -> ClaimProvenance {
        ClaimProvenance {
            producer: ClaimProducer::Core {
                component: "test".to_owned(),
                version: "0.1.0".to_owned(),
            },
            method: "unit-test".to_owned(),
            run_id: None,
        }
    }

    fn evidence() -> Evidence {
        Evidence::new(
            EvidenceKind::new(EvidenceKind::SIGNATURE_MATCH).expect("valid kind"),
            "matched an exact normalized instruction signature",
        )
        .expect("valid evidence")
    }

    #[test]
    fn confidence_rejects_out_of_range_and_non_finite_values() {
        assert!(Confidence::new(-0.01).is_err());
        assert!(Confidence::new(1.01).is_err());
        assert!(Confidence::new(f64::NAN).is_err());
        assert!(Confidence::new(f64::INFINITY).is_err());
        assert_eq!(Confidence::new(0.91).expect("valid").get(), 0.91);
    }

    #[test]
    fn claims_require_evidence() {
        let result = SymbolClaim::new(
            SymbolSubject::Function {
                binary: binary_id(),
                rva: 0x1000,
                size: Some(32),
            },
            SymbolAssertion::Name {
                name: "PacketReader::ReadGuid".to_owned(),
            },
            Confidence::new(0.9).expect("valid confidence"),
            Vec::new(),
            provenance(),
        );

        assert_eq!(result, Err(ClaimValidationError::MissingEvidence));
    }

    #[test]
    fn deserialization_cannot_bypass_claim_validation() {
        let binary = binary_id();
        let json = format!(
            r#"{{
                "subject": {{"kind":"function","binary":"{binary}","rva":4096}},
                "assertion": {{"kind":"name","name":"RecoveredName"}},
                "confidence": 0.8,
                "evidence": [],
                "provenance": {{
                    "producer": {{"kind":"core","component":"test","version":"0.1"}},
                    "method":"test"
                }}
            }}"#
        );
        let error = serde_json::from_str::<SymbolClaim>(&json)
            .expect_err("empty evidence must be rejected");
        assert!(error.to_string().contains("at least one evidence"));
    }

    #[test]
    fn nested_symbol_fields_reject_unknown_properties() {
        let binary = binary_id();
        let subject =
            format!(r#"{{"kind":"function","binary":"{binary}","rva":4096,"unexpected":true}}"#);
        let error = serde_json::from_str::<SymbolSubject>(&subject)
            .expect_err("unknown subject fields must fail");
        assert!(error.to_string().contains("unknown field `unexpected`"));

        let error = serde_json::from_str::<SymbolAssertion>(
            r#"{"kind":"name","name":"RecoveredName","unexpected":true}"#,
        )
        .expect_err("unknown assertion fields must fail");
        assert!(error.to_string().contains("unknown field `unexpected`"));

        let error = serde_json::from_str::<ControlFlowTarget>(
            r#"{"kind":"function","rva":8192,"unexpected":true}"#,
        )
        .expect_err("unknown control-flow target fields must fail");
        assert!(error.to_string().contains("unknown field `unexpected`"));

        let error = serde_json::from_str::<SymbolAssertion>(
            r#"{
                "kind":"direct-call",
                "call_site_rva":4096,
                "target":{"kind":"import-iat","iat_rva":8192,"unexpected":true}
            }"#,
        )
        .expect_err("unknown nested target fields must fail");
        assert!(error.to_string().contains("unknown field `unexpected`"));
    }

    #[test]
    fn control_flow_assertions_have_canonical_tagged_shapes() {
        let function_target = ControlFlowTarget::Function { rva: 0x2000 };
        assert_eq!(function_target.rva(), 0x2000);
        assert!(function_target.is_function());
        assert!(function_target.is_function_at(0x2000));
        assert!(!function_target.is_function_at(0x2001));
        assert_eq!(
            serde_json::to_value(function_target).expect("serialize function target"),
            serde_json::json!({"kind": "function", "rva": 0x2000})
        );

        let iat_target = ControlFlowTarget::ImportIat { iat_rva: 0x3000 };
        assert_eq!(iat_target.rva(), 0x3000);
        assert!(!iat_target.is_function());
        assert!(!iat_target.is_function_at(0x3000));
        assert_eq!(
            serde_json::to_value(iat_target).expect("serialize IAT target"),
            serde_json::json!({"kind": "import-iat", "iat_rva": 0x3000})
        );

        let assertions = [
            SymbolAssertion::FunctionEntry,
            SymbolAssertion::DirectCall {
                call_site_rva: 0x1010,
                target: function_target,
            },
            SymbolAssertion::ThunkTarget { target: iat_target },
        ];
        for assertion in assertions {
            let encoded = serde_json::to_string(&assertion).expect("serialize assertion");
            let decoded =
                serde_json::from_str::<SymbolAssertion>(&encoded).expect("deserialize assertion");
            assert_eq!(decoded, assertion);
        }
    }

    #[test]
    fn graph_rejects_claims_for_unknown_binaries() {
        let claim = SymbolClaim::new(
            SymbolSubject::Function {
                binary: binary_id(),
                rva: 0x1000,
                size: Some(32),
            },
            SymbolAssertion::Name {
                name: "RecoveredName".to_owned(),
            },
            Confidence::new(0.8).expect("valid confidence"),
            vec![evidence()],
            provenance(),
        )
        .expect("valid claim");

        let error = SymbolGraph::default()
            .submit_claim(claim)
            .expect_err("binary is not registered");
        assert!(matches!(error, GraphValidationError::UnknownBinary(_)));
    }

    #[test]
    fn binary_hash_is_canonical_sha256() {
        assert_eq!(
            BinaryId::digest(b"abc").as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
