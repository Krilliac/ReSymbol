#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use resymbol_core::{
    DiscoveredPlugin, PluginDiscoveryOptions, PluginSource, discover_plugins,
    plugin_api::{PluginHealthState, PluginRuntimeKind},
};
use resymbol_plugin_state::{
    ArtifactStateKey, ArtifactTrustPolicy, FingerprintLimits, PluginExecutionPolicy,
    PluginStateStore, fingerprint_plugin_directory,
};

use crate::{AppError, AppServices};

/// A deterministic, presentation-ready plugin discovery result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginCatalog {
    root: PathBuf,
    safe_mode: bool,
    entries: Vec<PluginCatalogEntry>,
}

impl PluginCatalog {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn safe_mode(&self) -> bool {
        self.safe_mode
    }

    #[must_use]
    pub fn entries(&self) -> &[PluginCatalogEntry] {
        &self.entries
    }

    /// Count candidates that pass discovery and manifest-level loadability checks.
    ///
    /// This does not include exact-artifact trust policy. A loadable non-WASM plugin may still
    /// require approval for its current fingerprint.
    #[must_use]
    pub fn loadable_count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.loadable).count()
    }

    /// Count candidates that pass both discovery and exact-artifact policy.
    #[must_use]
    pub fn artifact_policy_allowed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.artifact_policy.allows_by_artifact_policy())
            .count()
    }
}

/// Effective discovery and exact-artifact policy status for one plugin candidate.
///
/// Passing this policy is necessary but not sufficient for command-line execution. Discovery
/// already evaluates manifest validity, API compatibility, entrypoint safety, duplicate IDs, and
/// declared plugin dependencies. Runtime support, capability selection, host/helper availability,
/// granted permissions, target compatibility, and launch-time revalidation are separate gates. The
/// desktop workbench only presents this status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginArtifactPolicyStatus {
    /// A WASM artifact does not require an approval record under the sandboxed policy.
    Sandboxed,
    /// A non-WASM artifact's exact ID and artifact fingerprint are trusted.
    Trusted,
    /// A non-WASM artifact needs approval for this exact fingerprint.
    ApprovalRequired,
    /// Discovery, safe mode, host configuration, or a manual sentinel disables the candidate.
    Disabled,
    /// Discovery or exact-artifact state quarantined the artifact.
    Quarantined,
    /// Host-owned policy state could not be validated and the policy fails closed.
    CorruptState,
    /// Compatibility, packaging, or fingerprinting blocks exact-artifact policy evaluation.
    Unavailable,
}

impl PluginArtifactPolicyStatus {
    #[must_use]
    pub const fn allows_by_artifact_policy(self) -> bool {
        matches!(self, Self::Sandboxed | Self::Trusted)
    }

    #[must_use]
    pub const fn badge_label(self) -> &'static str {
        match self {
            Self::Sandboxed => "SANDBOXED",
            Self::Trusted => "TRUSTED",
            Self::ApprovalRequired => "APPROVAL REQUIRED",
            Self::Disabled => "DISABLED",
            Self::Quarantined => "QUARANTINED",
            Self::CorruptState => "CORRUPT STATE",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

/// UI-facing summary of one discovered plugin candidate.
///
/// Strings are deliberately used for extensible manifest and health values so
/// frontends do not need to duplicate the plugin API's non-exhaustive enums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginCatalogEntry {
    pub path: PathBuf,
    pub source: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub runtime: Option<String>,
    pub health: String,
    /// Whether discovery and manifest-level checks consider the candidate loadable.
    ///
    /// This is intentionally distinct from [`Self::artifact_policy`].
    pub loadable: bool,
    /// Canonical lowercase SHA-256 fingerprint of this exact unpacked artifact.
    pub artifact_fingerprint: Option<String>,
    /// Effective discovery and exact-artifact policy status.
    pub artifact_policy: PluginArtifactPolicyStatus,
    pub diagnostics: Vec<String>,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
}

impl AppServices {
    /// Inspect normal exact-artifact plugin policy without loading or executing a plugin.
    ///
    /// Desktop callers should use this workflow instead of safe-mode discovery when they need an
    /// accurate health report. Passing artifact policy is not a complete CLI execution decision.
    pub fn inspect_plugin_catalog(
        &self,
        root: impl AsRef<Path>,
    ) -> Result<PluginCatalog, AppError> {
        self.discover_plugins(root, false)
    }

    /// Discover plugin metadata without loading or executing any plugin.
    pub fn discover_plugins(
        &self,
        root: impl AsRef<Path>,
        safe_mode: bool,
    ) -> Result<PluginCatalog, AppError> {
        let root = root.as_ref();
        let options = PluginDiscoveryOptions {
            safe_mode,
            ..PluginDiscoveryOptions::default()
        };
        let report = discover_plugins(root, &options)
            .map_err(|source| AppError::io("scan plugin directory", root, source))?;
        let state = PluginStateStore::new(&report.root);
        let entries = report
            .plugins
            .iter()
            .map(|plugin| PluginCatalogEntry::from_discovered(plugin, &state))
            .collect();
        Ok(PluginCatalog {
            root: report.root,
            safe_mode,
            entries,
        })
    }
}

impl PluginCatalogEntry {
    fn from_discovered(plugin: &DiscoveredPlugin, state: &PluginStateStore) -> Self {
        let manifest = plugin.manifest.as_ref();
        let diagnostics = plugin
            .health
            .diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "{} [{}]: {}",
                    diagnostic_severity_label(diagnostic.severity),
                    diagnostic_code_label(diagnostic.code),
                    diagnostic.message
                )
            })
            .collect();
        let capabilities = manifest
            .map(|value| {
                value
                    .capabilities
                    .iter()
                    .map(|capability| capability.as_str().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        let permissions = manifest
            .map(|value| {
                value
                    .permissions
                    .iter()
                    .map(|permission| permission.as_str().to_owned())
                    .collect()
            })
            .unwrap_or_default();

        let mut entry = Self {
            path: plugin.path.clone(),
            source: plugin_source_label(plugin.source).to_owned(),
            id: manifest.map(|value| value.id.as_str().to_owned()),
            name: manifest.map(|value| value.name.clone()),
            version: manifest.map(|value| value.version.to_string()),
            description: manifest.and_then(|value| value.description.clone()),
            runtime: manifest.map(|value| runtime_kind_label(value.runtime.kind()).to_owned()),
            health: health_label(plugin.health.state).to_owned(),
            loadable: plugin.is_loadable(),
            artifact_fingerprint: None,
            artifact_policy: discovery_policy(plugin.health.state),
            diagnostics,
            capabilities,
            permissions,
        };

        if plugin.source != PluginSource::Directory {
            return entry;
        }
        let Some(manifest) = manifest else {
            return entry;
        };

        let fingerprint = match fingerprint_plugin_directory(
            &plugin.path,
            FingerprintLimits::default(),
        ) {
            Ok(report) => report.fingerprint,
            Err(error) => {
                entry.artifact_policy = PluginArtifactPolicyStatus::Unavailable;
                let diagnostic = format!(
                    "error [artifact-fingerprint]: exact artifact fingerprint unavailable: {error}"
                );
                entry.diagnostics.push(diagnostic);
                return entry;
            }
        };
        entry.artifact_fingerprint = Some(fingerprint.to_hex());

        if !plugin.is_loadable() {
            return entry;
        }

        let key = ArtifactStateKey::new(manifest.id.clone(), fingerprint);
        let trust_policy = if manifest.runtime.kind() == PluginRuntimeKind::Wasm {
            ArtifactTrustPolicy::Sandboxed
        } else {
            ArtifactTrustPolicy::RequireApproval
        };
        entry.artifact_policy = match state.execution_policy(&plugin.path, &key, trust_policy) {
            Ok(PluginExecutionPolicy::Allowed)
                if trust_policy == ArtifactTrustPolicy::Sandboxed =>
            {
                PluginArtifactPolicyStatus::Sandboxed
            }
            Ok(PluginExecutionPolicy::Allowed) => PluginArtifactPolicyStatus::Trusted,
            Ok(PluginExecutionPolicy::Disabled) => PluginArtifactPolicyStatus::Disabled,
            Ok(PluginExecutionPolicy::ApprovalRequired) => {
                PluginArtifactPolicyStatus::ApprovalRequired
            }
            Ok(PluginExecutionPolicy::Quarantined { reason }) => {
                entry
                    .diagnostics
                    .push(format!("error [artifact-quarantine]: {reason}"));
                PluginArtifactPolicyStatus::Quarantined
            }
            Err(error) => {
                entry.diagnostics.push(format!(
                    "error [plugin-state]: execution policy unavailable; failed closed: {error}"
                ));
                PluginArtifactPolicyStatus::CorruptState
            }
        };
        entry
    }
}

const fn discovery_policy(state: PluginHealthState) -> PluginArtifactPolicyStatus {
    match state {
        PluginHealthState::Disabled => PluginArtifactPolicyStatus::Disabled,
        PluginHealthState::Quarantined | PluginHealthState::DevelopmentError => {
            PluginArtifactPolicyStatus::Quarantined
        }
        _ => PluginArtifactPolicyStatus::Unavailable,
    }
}

const fn plugin_source_label(source: PluginSource) -> &'static str {
    match source {
        PluginSource::Directory => "directory",
        PluginSource::Package => "package",
    }
}

const fn health_label(state: PluginHealthState) -> &'static str {
    match state {
        PluginHealthState::Discovered => "discovered",
        PluginHealthState::Enabled => "enabled",
        PluginHealthState::Disabled => "disabled",
        PluginHealthState::Incompatible => "incompatible",
        PluginHealthState::Quarantined => "quarantined",
        PluginHealthState::DevelopmentError => "development-error",
        _ => "unknown",
    }
}

const fn runtime_kind_label(kind: PluginRuntimeKind) -> &'static str {
    match kind {
        PluginRuntimeKind::Wasm => "wasm",
        PluginRuntimeKind::Native => "native",
        PluginRuntimeKind::Managed => "managed",
        PluginRuntimeKind::ExternalProcess => "external-process",
        PluginRuntimeKind::ToolAdapter => "tool-adapter",
    }
}

fn diagnostic_severity_label(
    severity: resymbol_core::plugin_api::DiagnosticSeverity,
) -> &'static str {
    use resymbol_core::plugin_api::DiagnosticSeverity;
    match severity {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
    }
}

fn diagnostic_code_label(code: resymbol_core::plugin_api::PluginDiagnosticCode) -> &'static str {
    use resymbol_core::plugin_api::PluginDiagnosticCode;
    match code {
        PluginDiagnosticCode::InvalidManifest => "invalid-manifest",
        PluginDiagnosticCode::UnsupportedManifestVersion => "unsupported-manifest-version",
        PluginDiagnosticCode::IncompatibleApi => "incompatible-api",
        PluginDiagnosticCode::UnsupportedPlatform => "unsupported-platform",
        PluginDiagnosticCode::MissingEntrypoint => "missing-entrypoint",
        PluginDiagnosticCode::MissingDependency => "missing-dependency",
        PluginDiagnosticCode::IncompatibleDependency => "incompatible-dependency",
        PluginDiagnosticCode::DisabledSentinel => "disabled-sentinel",
        PluginDiagnosticCode::DisabledByUser => "disabled-by-user",
        PluginDiagnosticCode::SafeMode => "safe-mode",
        PluginDiagnosticCode::DuplicateId => "duplicate-id",
        PluginDiagnosticCode::PackagePendingInstallation => "package-pending-installation",
        PluginDiagnosticCode::CompilationFailed => "compilation-failed",
        PluginDiagnosticCode::ValidationFailed => "validation-failed",
        PluginDiagnosticCode::StartupFailed => "startup-failed",
        PluginDiagnosticCode::RuntimeFailure => "runtime-failure",
        PluginDiagnosticCode::Timeout => "timeout",
        PluginDiagnosticCode::ResourceLimit => "resource-limit",
        PluginDiagnosticCode::PermissionDenied => "permission-denied",
        _ => "unknown",
    }
}
