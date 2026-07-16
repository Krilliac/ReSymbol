#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use resymbol_core::{
    DiscoveredPlugin, PluginDiscoveryOptions, PluginSource, discover_plugins,
    plugin_api::{PluginHealthState, PluginRuntimeKind},
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

    #[must_use]
    pub fn loadable_count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.loadable).count()
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
    pub loadable: bool,
    pub diagnostics: Vec<String>,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
}

impl AppServices {
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
        let entries = report
            .plugins
            .iter()
            .map(PluginCatalogEntry::from_discovered)
            .collect();
        Ok(PluginCatalog {
            root: report.root,
            safe_mode,
            entries,
        })
    }
}

impl PluginCatalogEntry {
    fn from_discovered(plugin: &DiscoveredPlugin) -> Self {
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

        Self {
            path: plugin.path.clone(),
            source: plugin_source_label(plugin.source).to_owned(),
            id: manifest.map(|value| value.id.as_str().to_owned()),
            name: manifest.map(|value| value.name.clone()),
            version: manifest.map(|value| value.version.to_string()),
            description: manifest.and_then(|value| value.description.clone()),
            runtime: manifest.map(|value| runtime_kind_label(value.runtime.kind()).to_owned()),
            health: health_label(plugin.health.state).to_owned(),
            loadable: plugin.is_loadable(),
            diagnostics,
            capabilities,
            permissions,
        }
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
