use serde::{Deserialize, Serialize};

/// A plugin's current lifecycle state as determined by the trusted host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PluginHealthState {
    /// Found on disk but not yet validated or selected for loading.
    Discovered,
    /// Eligible for automatic loading.
    Enabled,
    /// Explicitly disabled, disabled by safe mode, or blocked by a dependency.
    Disabled,
    /// Valid plugin metadata that targets an unsupported API or platform.
    Incompatible,
    /// Isolated after invalid input, a crash, a timeout, or another safety fault.
    Quarantined,
    /// A source plugin failed to build in optional developer mode.
    DevelopmentError,
}

impl PluginHealthState {
    /// Whether the host may attempt to load the plugin.
    #[must_use]
    pub const fn is_loadable(self) -> bool {
        matches!(self, Self::Discovered | Self::Enabled)
    }
}

/// Machine-readable classes used by CLI, GUI, and SDK diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PluginDiagnosticCode {
    InvalidManifest,
    UnsupportedManifestVersion,
    IncompatibleApi,
    UnsupportedPlatform,
    MissingEntrypoint,
    MissingDependency,
    IncompatibleDependency,
    DisabledSentinel,
    DisabledByUser,
    SafeMode,
    DuplicateId,
    PackagePendingInstallation,
    CompilationFailed,
    ValidationFailed,
    StartupFailed,
    RuntimeFailure,
    Timeout,
    ResourceLimit,
    PermissionDenied,
}

/// Diagnostic severity independent from the plugin's aggregate health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// One actionable reason associated with a plugin's health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginDiagnostic {
    pub code: PluginDiagnosticCode,
    pub severity: DiagnosticSeverity,
    pub message: String,
}

impl PluginDiagnostic {
    #[must_use]
    pub fn error(code: PluginDiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: DiagnosticSeverity::Error,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn warning(code: PluginDiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: DiagnosticSeverity::Warning,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn info(code: PluginDiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: DiagnosticSeverity::Info,
            message: message.into(),
        }
    }
}

/// Host-owned health information. Plugins may report failures, but may not set
/// their own final health state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginHealth {
    pub state: PluginHealthState,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub diagnostics: Vec<PluginDiagnostic>,
}

impl PluginHealth {
    #[must_use]
    pub const fn new(state: PluginHealthState) -> Self {
        Self {
            state,
            consecutive_failures: 0,
            diagnostics: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_diagnostic(state: PluginHealthState, diagnostic: PluginDiagnostic) -> Self {
        Self {
            state,
            consecutive_failures: 0,
            diagnostics: vec![diagnostic],
        }
    }

    pub fn add_diagnostic(&mut self, diagnostic: PluginDiagnostic) {
        self.diagnostics.push(diagnostic);
    }

    /// Record a recoverable runtime failure and quarantine after the configured
    /// number of consecutive failures. A threshold of zero quarantines on the
    /// first failure.
    pub fn record_failure(&mut self, diagnostic: PluginDiagnostic, quarantine_after: u32) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.diagnostics.push(diagnostic);

        if quarantine_after == 0 || self.consecutive_failures >= quarantine_after {
            self.state = PluginHealthState::Quarantined;
        }
    }

    /// Clear transient failures after a successful validation or execution.
    pub fn mark_healthy(&mut self) {
        self.state = PluginHealthState::Enabled;
        self.consecutive_failures = 0;
        self.diagnostics.clear();
    }
}

impl Default for PluginHealth {
    fn default() -> Self {
        Self::new(PluginHealthState::Discovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_failures_quarantine_without_overflowing() {
        let mut health = PluginHealth::new(PluginHealthState::Enabled);
        let diagnostic =
            PluginDiagnostic::error(PluginDiagnosticCode::RuntimeFailure, "plugin trapped");

        health.record_failure(diagnostic.clone(), 2);
        assert_eq!(health.state, PluginHealthState::Enabled);
        health.record_failure(diagnostic, 2);
        assert_eq!(health.state, PluginHealthState::Quarantined);
        assert_eq!(health.consecutive_failures, 2);
    }
}
