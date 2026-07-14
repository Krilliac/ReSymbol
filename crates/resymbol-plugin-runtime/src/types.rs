use std::{collections::BTreeSet, time::Duration};

use resymbol_core::{SymbolClaim, plugin_api::PluginPermission};
use serde_json::{Map, Value};

use crate::PluginRuntimeError;

const MIN_MESSAGE_BYTES: usize = 1_024;
const MIN_ADVERTISED_MEMORY_BYTES: u64 = 1_048_576;

/// Resource ceilings applied to one child-process invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RuntimeLimits {
    /// Maximum encoded size of one stdin or stdout NDJSON message.
    pub max_message_bytes: usize,
    /// Maximum aggregate stdout retained from the process.
    pub max_stdout_bytes: usize,
    /// Maximum aggregate stderr retained from the process.
    pub max_stderr_bytes: usize,
    /// Maximum number of stdout protocol messages.
    pub max_messages: usize,
    /// Wall-clock deadline covering process startup, I/O, and exit.
    pub request_timeout: Duration,
    /// Memory ceiling advertised to the plugin wire protocol. This crate does
    /// not claim to enforce it without a platform-specific sandbox.
    pub advertised_max_memory_bytes: u64,
}

impl RuntimeLimits {
    /// Return these limits with a different wall-clock request deadline.
    #[must_use]
    pub const fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    /// Return these limits with different per-message and captured-output byte ceilings.
    #[must_use]
    pub const fn with_output_limits(
        mut self,
        max_message_bytes: usize,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Self {
        self.max_message_bytes = max_message_bytes;
        self.max_stdout_bytes = max_stdout_bytes;
        self.max_stderr_bytes = max_stderr_bytes;
        self
    }

    /// Return these limits with a different stdout protocol-message ceiling.
    #[must_use]
    pub const fn with_max_messages(mut self, max_messages: usize) -> Self {
        self.max_messages = max_messages;
        self
    }

    /// Validate limits before they are used to allocate or launch a process.
    pub fn validate(&self) -> Result<(), PluginRuntimeError> {
        if self.max_message_bytes < MIN_MESSAGE_BYTES {
            return Err(PluginRuntimeError::InvalidLimits(
                "max_message_bytes must be at least 1024",
            ));
        }
        if self.max_stdout_bytes < self.max_message_bytes {
            return Err(PluginRuntimeError::InvalidLimits(
                "max_stdout_bytes must be at least max_message_bytes",
            ));
        }
        if self.max_stderr_bytes == 0 {
            return Err(PluginRuntimeError::InvalidLimits(
                "max_stderr_bytes must be greater than zero",
            ));
        }
        if self.max_messages == 0 {
            return Err(PluginRuntimeError::InvalidLimits(
                "max_messages must be greater than zero",
            ));
        }
        if self.request_timeout < Duration::from_millis(1) {
            return Err(PluginRuntimeError::InvalidLimits(
                "request_timeout must be at least one millisecond",
            ));
        }
        if self.request_timeout.as_millis() > u128::from(u64::MAX) {
            return Err(PluginRuntimeError::InvalidLimits(
                "request_timeout cannot be represented in protocol milliseconds",
            ));
        }
        if self.advertised_max_memory_bytes < MIN_ADVERTISED_MEMORY_BYTES {
            return Err(PluginRuntimeError::InvalidLimits(
                "advertised_max_memory_bytes must be at least 1048576",
            ));
        }
        Ok(())
    }
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 1024 * 1024,
            max_stdout_bytes: 8 * 1024 * 1024,
            max_stderr_bytes: 256 * 1024,
            max_messages: 4_096,
            request_timeout: Duration::from_secs(30),
            advertised_max_memory_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Host-to-plugin method supported by a single invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PluginMethod {
    Initialize,
    Analyze,
    Health,
    Shutdown,
}

impl PluginMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Analyze => "analyze",
            Self::Health => "health",
            Self::Shutdown => "shutdown",
        }
    }
}

/// One host request. IDs are caller-provided so higher layers can make runs
/// reproducible and correlate them with package provenance.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ExternalProcessRequest {
    id: String,
    session_id: String,
    method: PluginMethod,
    payload: Map<String, Value>,
    granted_permissions: BTreeSet<PluginPermission>,
}

impl ExternalProcessRequest {
    pub fn new(
        id: impl Into<String>,
        session_id: impl Into<String>,
        method: PluginMethod,
        payload: Map<String, Value>,
    ) -> Result<Self, PluginRuntimeError> {
        let request = Self {
            id: id.into(),
            session_id: session_id.into(),
            method,
            payload,
            granted_permissions: BTreeSet::new(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn set_granted_permissions(
        &mut self,
        permissions: impl IntoIterator<Item = PluginPermission>,
    ) {
        self.granted_permissions = permissions.into_iter().collect();
    }

    #[must_use]
    pub fn with_granted_permissions(
        mut self,
        permissions: impl IntoIterator<Item = PluginPermission>,
    ) -> Self {
        self.set_granted_permissions(permissions);
        self
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn method(&self) -> PluginMethod {
        self.method
    }

    #[must_use]
    pub fn payload(&self) -> &Map<String, Value> {
        &self.payload
    }

    #[must_use]
    pub fn granted_permissions(&self) -> &BTreeSet<PluginPermission> {
        &self.granted_permissions
    }

    pub(crate) fn validate(&self) -> Result<(), PluginRuntimeError> {
        if self.id.trim().is_empty() {
            return Err(PluginRuntimeError::InvalidRequest(
                "request id must not be empty",
            ));
        }
        if self.session_id.trim().is_empty() {
            return Err(PluginRuntimeError::InvalidRequest(
                "session id must not be empty",
            ));
        }
        Ok(())
    }
}

/// Descriptor authenticated against the installed manifest during handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginDescriptor {
    pub id: String,
    pub name: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub requested_permissions: Vec<String>,
}

/// Structured log event emitted on protocol stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginLog {
    pub level: String,
    pub message: String,
}

/// Successful response to the caller's request.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PluginResponse {
    pub id: String,
    pub result: Value,
}

/// Bounded child stderr retained for operator diagnostics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessDiagnostics {
    pub stderr: String,
    /// True when invalid UTF-8 was replaced while decoding stderr.
    pub stderr_was_lossy: bool,
}

impl ProcessDiagnostics {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let decoded = String::from_utf8_lossy(bytes);
        Self {
            stderr_was_lossy: std::str::from_utf8(bytes).is_err(),
            stderr: decoded.into_owned(),
        }
    }
}

/// Complete, validated output from a successful plugin process.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PluginExecution {
    pub descriptor: PluginDescriptor,
    pub response: PluginResponse,
    pub claims: Vec<SymbolClaim>,
    pub logs: Vec<PluginLog>,
    pub diagnostics: ProcessDiagnostics,
    pub exit_code: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reject_unbounded_shapes() {
        let defaults = RuntimeLimits::default();
        let limits = RuntimeLimits {
            max_stdout_bytes: defaults.max_message_bytes - 1,
            ..defaults
        };
        assert!(matches!(
            limits.validate(),
            Err(PluginRuntimeError::InvalidLimits(_))
        ));
    }

    #[test]
    fn request_rejects_blank_identifiers() {
        assert!(matches!(
            ExternalProcessRequest::new(" ", "session", PluginMethod::Analyze, Map::new()),
            Err(PluginRuntimeError::InvalidRequest(_))
        ));
    }
}
