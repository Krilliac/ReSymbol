use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum HostError {
    #[error("invalid native-host arguments: {0}")]
    Arguments(&'static str),
    #[error("failed to {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{kind} exceeds its {limit}-byte limit")]
    InputLimit { kind: &'static str, limit: usize },
    #[error("invalid {kind} JSON: {source}")]
    Json {
        kind: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid native-host bootstrap: {0}")]
    Bootstrap(String),
    #[error("invalid plugin-wire input: {0}")]
    Wire(String),
    #[error("invalid plugin manifest: {0}")]
    Manifest(String),
    #[error(
        "plugin manifest is missing, linked, or not a regular file: {path}",
        path = .0.display()
    )]
    UnsafeManifest(PathBuf),
    #[error(
        "plugin entrypoint is missing, linked, or outside its directory: {path}",
        path = .0.display()
    )]
    UnsafeEntrypoint(PathBuf),
    #[error("plugin artifact fingerprint failed: {0}")]
    Fingerprint(String),
    #[error("plugin artifact fingerprint does not match the approved bytes")]
    FingerprintMismatch,
    #[error("exact source binary is invalid: {0}")]
    Binary(String),
    #[error("failed to load native library: {0}")]
    Load(String),
    #[error("native plugin ABI violation: {0}")]
    Abi(String),
    #[error("native plugin returned status {status} from {operation}")]
    PluginStatus {
        operation: &'static str,
        status: i32,
    },
    #[error("native plugin callback failed: {0}")]
    Callback(String),
    #[error("failed to encode native-host protocol output: {0}")]
    Output(#[source] serde_json::Error),
}

impl HostError {
    pub(crate) fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}
