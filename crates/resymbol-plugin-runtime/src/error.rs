use std::{io, time::Duration};

use resymbol_core::{ClaimValidationError, plugin_api::PluginRuntimeKind};
use serde_json::Value;
use thiserror::Error;

use crate::ProcessDiagnostics;

/// Bounded stream associated with a resource-limit failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamKind {
    Stdin,
    Stdout,
    Stderr,
}

impl std::fmt::Display for StreamKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdin => formatter.write_str("stdin"),
            Self::Stdout => formatter.write_str("stdout"),
            Self::Stderr => formatter.write_str("stderr"),
        }
    }
}

/// A host-side launch, resource, transport, protocol, or claim-validation
/// failure. Variants retain stderr whenever the child produced diagnostics.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PluginRuntimeError {
    #[error("invalid runtime limit: {0}")]
    InvalidLimits(&'static str),
    #[error("the discovered plugin has no validated manifest")]
    MissingManifest,
    #[error("plugin source must be an installed directory")]
    UnsupportedPluginSource,
    #[error("plugin is not loadable: {0}")]
    PluginNotLoadable(String),
    #[error("runtime kind {0:?} is unsupported; only external-process plugins may execute")]
    UnsupportedRuntime(PluginRuntimeKind),
    #[error("invalid plugin manifest: {0}")]
    InvalidManifest(String),
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("failed to encode bounded plugin input: {0}")]
    EncodeInput(#[source] serde_json::Error),
    #[error("permission `{0}` was granted but is not requested by the plugin manifest")]
    PermissionNotRequested(String),
    #[error("plugin used ungranted permission `{permission}`")]
    PermissionDenied {
        permission: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error("plugin emitted a claim event during `{method}`; claims are accepted only during `analyze`")]
    ClaimEventNotAllowed {
        method: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error("plugin entrypoint is outside its installed directory")]
    EntrypointOutsidePlugin,
    #[error("plugin entrypoint is linked or traverses a linked path component")]
    LinkedEntrypoint,
    #[error("plugin entrypoint is not a regular file")]
    EntrypointNotFile,
    #[error("failed to {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{stream} exceeded its {limit}-byte limit")]
    StreamLimit {
        stream: StreamKind,
        limit: usize,
        diagnostics: ProcessDiagnostics,
    },
    #[error("plugin stdout exceeded its {limit}-message limit")]
    MessageLimit {
        limit: usize,
        diagnostics: ProcessDiagnostics,
    },
    #[error("plugin exceeded its {} ms deadline", .timeout.as_millis())]
    Timeout {
        timeout: Duration,
        diagnostics: ProcessDiagnostics,
    },
    #[error("plugin exited unsuccessfully (code {code:?})")]
    ProcessFailed {
        code: Option<i32>,
        diagnostics: ProcessDiagnostics,
    },
    #[error("plugin I/O worker `{0}` panicked")]
    WorkerPanicked(&'static str),
    #[error("invalid plugin JSON on output line {line}: {source}")]
    InvalidJson {
        line: usize,
        #[source]
        source: serde_json::Error,
        diagnostics: ProcessDiagnostics,
    },
    #[error("plugin protocol violation on output line {line}: {message}")]
    Protocol {
        line: usize,
        message: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error("plugin submitted an invalid claim on output line {line}: {source}")]
    InvalidClaim {
        line: usize,
        #[source]
        source: ClaimValidationError,
        diagnostics: ProcessDiagnostics,
    },
    #[error("plugin rejected request with `{code}`: {message}")]
    PluginRejected {
        code: String,
        message: String,
        data: Option<Value>,
        diagnostics: ProcessDiagnostics,
    },
}

impl PluginRuntimeError {
    /// Captured stderr, when process execution had already begun.
    #[must_use]
    pub const fn diagnostics(&self) -> Option<&ProcessDiagnostics> {
        match self {
            Self::StreamLimit { diagnostics, .. }
            | Self::MessageLimit { diagnostics, .. }
            | Self::PermissionDenied { diagnostics, .. }
            | Self::ClaimEventNotAllowed { diagnostics, .. }
            | Self::Timeout { diagnostics, .. }
            | Self::ProcessFailed { diagnostics, .. }
            | Self::InvalidJson { diagnostics, .. }
            | Self::Protocol { diagnostics, .. }
            | Self::InvalidClaim { diagnostics, .. }
            | Self::PluginRejected { diagnostics, .. } => Some(diagnostics),
            _ => None,
        }
    }
}
