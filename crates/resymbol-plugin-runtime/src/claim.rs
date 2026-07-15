use resymbol_core::{
    ClaimProducer, ClaimProvenance, Confidence, Evidence, EvidenceKind, SymbolAssertion,
    SymbolClaim, SymbolSubject, plugin_api::PluginManifest,
};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use thiserror::Error;

use crate::ExternalProcessRequest;

#[derive(Debug, Error)]
pub(crate) enum ClaimDecodeError {
    #[error("invalid claim JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid claim: {0}")]
    Validation(#[from] resymbol_core::ClaimValidationError),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireClaim {
    subject: SymbolSubject,
    pub(crate) claim: SymbolAssertion,
    confidence: Confidence,
    evidence: Vec<WireEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvidence {
    kind: String,
    description: String,
    #[serde(default)]
    data: Present<Value>,
}

#[derive(Debug, Default)]
enum Present<T> {
    #[default]
    Missing,
    Value(T),
}

impl<'de, T> Deserialize<'de> for Present<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Value)
    }
}

pub(crate) fn decode_claim(
    payload: Value,
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
) -> Result<SymbolClaim, ClaimDecodeError> {
    let wire = serde_json::from_value::<WireClaim>(payload)?;
    let evidence = wire
        .evidence
        .into_iter()
        .map(|item| {
            let kind = EvidenceKind::new(item.kind)?;
            let mut evidence = Evidence::new(kind, item.description)?;
            if let Present::Value(data) = item.data {
                evidence
                    .artifacts
                    .insert("wire.data".to_owned(), data.to_string());
            }
            Ok(evidence)
        })
        .collect::<Result<Vec<_>, resymbol_core::ClaimValidationError>>()?;
    let provenance = ClaimProvenance {
        producer: ClaimProducer::Plugin {
            id: manifest.id.clone(),
            version: manifest.version.to_string(),
        },
        method: request.method().as_str().to_owned(),
        run_id: Some(request.session_id().to_owned()),
    };
    SymbolClaim::new(
        wire.subject,
        wire.claim,
        wire.confidence,
        evidence,
        provenance,
    )
    .map_err(ClaimDecodeError::from)
}
