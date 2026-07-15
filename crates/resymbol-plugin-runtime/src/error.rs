use std::{io, path::PathBuf, time::Duration};

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
    #[error("runtime kind {0:?} is unsupported by this process host")]
    UnsupportedRuntime(PluginRuntimeKind),
    #[error("invalid plugin manifest: {0}")]
    InvalidManifest(String),
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid native-plugin execution context: {0}")]
    InvalidNativeContext(String),
    #[error("invalid managed-plugin execution context: {0}")]
    InvalidManagedContext(String),
    #[error(
        "native-plugin helper is unavailable at {path}: {reason}",
        path = .path.display()
    )]
    NativeHostUnavailable { path: PathBuf, reason: String },
    #[error(
        "native-plugin helper failed before attributable plugin execution (code {code:?}): {reason}"
    )]
    NativeHostFailed {
        code: Option<i32>,
        reason: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error(
        "exact native-plugin source binary is unavailable or changed at {path}: {reason}",
        path = .path.display()
    )]
    NativeSourceBinary { path: PathBuf, reason: String },
    #[error(
        "exact native analysis input changed after helper launch at {path}: {reason}",
        path = .path.display()
    )]
    NativeHostInputChanged {
        path: PathBuf,
        reason: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error(
        "native-plugin artifact changed after helper launch but before platform load: {reason}"
    )]
    NativeHostArtifactChanged {
        reason: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error(
        "exact native analysis input changed during attributable plugin execution at {path}: {reason}",
        path = .path.display()
    )]
    NativeExecutionInputChanged {
        path: PathBuf,
        reason: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error(
        "managed-plugin helper is unavailable at {path}: {reason}",
        path = .path.display()
    )]
    ManagedHostUnavailable { path: PathBuf, reason: String },
    #[error(
        "managed-plugin helper failed before attributable plugin execution (code {code:?}): {reason}"
    )]
    ManagedHostFailed {
        code: Option<i32>,
        reason: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error("managed plugin artifact is unavailable or does not match trust state: {reason}")]
    ManagedArtifactMismatch { reason: String },
    #[error("managed assembly closure is invalid at {path}: {reason}", path = .path.display())]
    ManagedAssemblyClosure { path: PathBuf, reason: String },
    #[error(
        "exact managed analysis source binary is unavailable or changed at {path}: {reason}",
        path = .path.display()
    )]
    ManagedSourceBinary { path: PathBuf, reason: String },
    #[error(
        "exact managed analysis input changed after helper launch at {path}: {reason}",
        path = .path.display()
    )]
    ManagedHostInputChanged {
        path: PathBuf,
        reason: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error(
        "managed plugin artifact changed after helper launch but before attributable plugin execution: {reason}"
    )]
    ManagedHostArtifactChanged {
        reason: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error(
        "exact managed analysis input changed during attributable plugin execution at {path}: {reason}",
        path = .path.display()
    )]
    ManagedExecutionInputChanged {
        path: PathBuf,
        reason: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error("managed plugin artifact changed during attributable plugin execution: {reason}")]
    ManagedExecutionArtifactChanged {
        reason: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error("failed to encode bounded plugin input: {0}")]
    EncodeInput(#[source] serde_json::Error),
    #[error("failed to encode bounded native-host bootstrap: {0}")]
    EncodeNativeBootstrap(#[source] serde_json::Error),
    #[error("failed to encode bounded managed-host bootstrap: {0}")]
    EncodeManagedBootstrap(#[source] serde_json::Error),
    #[error("permission `{0}` was granted but is not requested by the plugin manifest")]
    PermissionNotRequested(String),
    #[error("plugin used ungranted permission `{permission}`")]
    PermissionDenied {
        permission: String,
        diagnostics: ProcessDiagnostics,
    },
    #[error(
        "plugin emitted a claim event during `{method}`; claims are accepted only during `analyze`"
    )]
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
    #[error("plugin artifact changed during native execution: {reason}")]
    PluginArtifactChanged {
        reason: String,
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
            | Self::NativeHostFailed { diagnostics, .. }
            | Self::NativeHostInputChanged { diagnostics, .. }
            | Self::NativeHostArtifactChanged { diagnostics, .. }
            | Self::NativeExecutionInputChanged { diagnostics, .. }
            | Self::ManagedHostFailed { diagnostics, .. }
            | Self::ManagedHostInputChanged { diagnostics, .. }
            | Self::ManagedHostArtifactChanged { diagnostics, .. }
            | Self::ManagedExecutionInputChanged { diagnostics, .. }
            | Self::ManagedExecutionArtifactChanged { diagnostics, .. }
            | Self::ProcessFailed { diagnostics, .. }
            | Self::InvalidJson { diagnostics, .. }
            | Self::Protocol { diagnostics, .. }
            | Self::InvalidClaim { diagnostics, .. }
            | Self::PluginRejected { diagnostics, .. }
            | Self::PluginArtifactChanged { diagnostics, .. } => Some(diagnostics),
            _ => None,
        }
    }

    /// Mutably access captured child stderr for runtime-specific protocol
    /// framing that must be removed before diagnostics leave this crate.
    pub(crate) const fn diagnostics_mut(&mut self) -> Option<&mut ProcessDiagnostics> {
        match self {
            Self::StreamLimit { diagnostics, .. }
            | Self::MessageLimit { diagnostics, .. }
            | Self::PermissionDenied { diagnostics, .. }
            | Self::ClaimEventNotAllowed { diagnostics, .. }
            | Self::Timeout { diagnostics, .. }
            | Self::NativeHostFailed { diagnostics, .. }
            | Self::NativeHostInputChanged { diagnostics, .. }
            | Self::NativeHostArtifactChanged { diagnostics, .. }
            | Self::NativeExecutionInputChanged { diagnostics, .. }
            | Self::ManagedHostFailed { diagnostics, .. }
            | Self::ManagedHostInputChanged { diagnostics, .. }
            | Self::ManagedHostArtifactChanged { diagnostics, .. }
            | Self::ManagedExecutionInputChanged { diagnostics, .. }
            | Self::ManagedExecutionArtifactChanged { diagnostics, .. }
            | Self::ProcessFailed { diagnostics, .. }
            | Self::InvalidJson { diagnostics, .. }
            | Self::Protocol { diagnostics, .. }
            | Self::InvalidClaim { diagnostics, .. }
            | Self::PluginRejected { diagnostics, .. }
            | Self::PluginArtifactChanged { diagnostics, .. } => Some(diagnostics),
            _ => None,
        }
    }
}
