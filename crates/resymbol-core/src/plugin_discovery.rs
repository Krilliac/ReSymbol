use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Component, Path, PathBuf},
};

use resymbol_plugin_api::{
    ManifestValidationError, PLUGIN_API_VERSION, PluginDiagnostic, PluginDiagnosticCode,
    PluginHealth, PluginHealthState, PluginId, PluginManifest,
};
use semver::Version;
use serde::{Deserialize, Serialize};

pub const PLUGIN_MANIFEST_FILE: &str = "plugin.toml";
pub const PLUGIN_DISABLED_SENTINEL: &str = "plugin.disabled";
pub const PLUGIN_PACKAGE_EXTENSION: &str = "resymbol-plugin";

/// Source representation found directly beneath the plugin directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginSource {
    Directory,
    Package,
}

/// One deterministic discovery result. Package files are intentionally kept as
/// placeholders until the package verification/extraction layer is connected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredPlugin {
    pub source: PluginSource,
    pub path: PathBuf,
    pub manifest: Option<PluginManifest>,
    pub health: PluginHealth,
}

impl DiscoveredPlugin {
    #[must_use]
    pub fn id(&self) -> Option<&PluginId> {
        self.manifest.as_ref().map(|manifest| &manifest.id)
    }

    #[must_use]
    pub fn is_loadable(&self) -> bool {
        self.manifest.is_some() && self.health.state.is_loadable()
    }
}

/// Host policy affecting a scan without changing anything on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDiscoveryOptions {
    pub host_api: Version,
    pub safe_mode: bool,
    pub disabled_ids: BTreeSet<PluginId>,
}

impl Default for PluginDiscoveryOptions {
    fn default() -> Self {
        let host_api = Version::new(0, 1, 0);
        debug_assert_eq!(host_api.to_string(), PLUGIN_API_VERSION);
        Self {
            host_api,
            safe_mode: false,
            disabled_ids: BTreeSet::new(),
        }
    }
}

/// Complete scan result in stable plugin-id/path order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginDiscoveryReport {
    pub root: PathBuf,
    pub plugins: Vec<DiscoveredPlugin>,
}

impl PluginDiscoveryReport {
    pub fn loadable(&self) -> impl Iterator<Item = &DiscoveredPlugin> {
        self.plugins.iter().filter(|plugin| plugin.is_loadable())
    }
}

/// Scan immediate child directories and `*.resymbol-plugin` package files.
///
/// A missing root is equivalent to an empty plugin directory. Discovery never
/// modifies, deletes, compiles, or executes plugin content.
pub fn discover_plugins(
    root: impl AsRef<Path>,
    options: &PluginDiscoveryOptions,
) -> io::Result<PluginDiscoveryReport> {
    let root = root.as_ref().to_path_buf();
    let mut paths = match fs::read_dir(&root) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| is_candidate(path))
            .collect::<Vec<_>>(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    paths.sort_by_key(|path| deterministic_path_key(path));

    let mut plugins = paths
        .into_iter()
        .map(|path| discover_one(path, options))
        .collect::<Vec<_>>();

    quarantine_duplicate_ids(&mut plugins);
    disable_unresolved_dependencies(&mut plugins);
    plugins.sort_by_key(discovery_sort_key);

    Ok(PluginDiscoveryReport { root, plugins })
}

fn is_candidate(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    metadata.file_type().is_dir()
        || (metadata.file_type().is_file()
            && path.extension().is_some_and(|extension| {
                extension
                    .to_string_lossy()
                    .eq_ignore_ascii_case(PLUGIN_PACKAGE_EXTENSION)
            }))
}

fn discover_one(path: PathBuf, options: &PluginDiscoveryOptions) -> DiscoveredPlugin {
    if path.is_file() {
        discover_package(path, options)
    } else {
        discover_directory(path, options)
    }
}

fn discover_package(path: PathBuf, options: &PluginDiscoveryOptions) -> DiscoveredPlugin {
    let has_disabled_sentinel = package_disabled_sentinel(&path).exists();
    let (state, diagnostic) = if options.safe_mode {
        (
            PluginHealthState::Disabled,
            PluginDiagnostic::info(
                PluginDiagnosticCode::SafeMode,
                "package loading is disabled in safe mode",
            ),
        )
    } else if has_disabled_sentinel {
        (
            PluginHealthState::Disabled,
            PluginDiagnostic::info(
                PluginDiagnosticCode::DisabledSentinel,
                "package is disabled by its adjacent .disabled sentinel",
            ),
        )
    } else {
        (
            PluginHealthState::Discovered,
            PluginDiagnostic::info(
                PluginDiagnosticCode::PackagePendingInstallation,
                "package discovered; verification and extraction are pending",
            ),
        )
    };

    DiscoveredPlugin {
        source: PluginSource::Package,
        path,
        manifest: None,
        health: PluginHealth::with_diagnostic(state, diagnostic),
    }
}

fn discover_directory(path: PathBuf, options: &PluginDiscoveryOptions) -> DiscoveredPlugin {
    let manifest_path = path.join(PLUGIN_MANIFEST_FILE);
    let manifest_text = match fs::read_to_string(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            return invalid_directory(
                path,
                format!("failed to read {}: {error}", manifest_path.display()),
            );
        }
    };

    let manifest = match toml::from_str::<PluginManifest>(&manifest_text) {
        Ok(manifest) => manifest,
        Err(error) => {
            return invalid_directory(path, format!("invalid plugin manifest: {error}"));
        }
    };

    let mut plugin = DiscoveredPlugin {
        source: PluginSource::Directory,
        path,
        manifest: Some(manifest),
        health: PluginHealth::new(PluginHealthState::Enabled),
    };
    let manifest = plugin
        .manifest
        .as_ref()
        .expect("manifest was just assigned");

    if let Err(error) = manifest.validate() {
        let (state, diagnostic) = manifest_validation_diagnostic(&error);
        plugin.health = PluginHealth::with_diagnostic(state, diagnostic);
        return plugin;
    }

    if !manifest.api.matches(&options.host_api) {
        plugin.health = PluginHealth::with_diagnostic(
            PluginHealthState::Incompatible,
            PluginDiagnostic::error(
                PluginDiagnosticCode::IncompatibleApi,
                format!(
                    "plugin requires API {}, but the host provides {}",
                    manifest.api, options.host_api
                ),
            ),
        );
        return plugin;
    }

    if !has_safe_entrypoint(&plugin.path, manifest.runtime.entrypoint()) {
        plugin.health = PluginHealth::with_diagnostic(
            PluginHealthState::Quarantined,
            PluginDiagnostic::error(
                PluginDiagnosticCode::MissingEntrypoint,
                format!(
                    "runtime entrypoint {} is missing, linked, or not a regular file",
                    manifest.runtime.entrypoint().display()
                ),
            ),
        );
        return plugin;
    }

    if options.safe_mode {
        plugin.health = PluginHealth::with_diagnostic(
            PluginHealthState::Disabled,
            PluginDiagnostic::info(
                PluginDiagnosticCode::SafeMode,
                "third-party plugins are disabled in safe mode",
            ),
        );
    } else if plugin.path.join(PLUGIN_DISABLED_SENTINEL).exists() {
        plugin.health = PluginHealth::with_diagnostic(
            PluginHealthState::Disabled,
            PluginDiagnostic::info(
                PluginDiagnosticCode::DisabledSentinel,
                format!("disabled by {PLUGIN_DISABLED_SENTINEL}"),
            ),
        );
    } else if options.disabled_ids.contains(&manifest.id) {
        plugin.health = PluginHealth::with_diagnostic(
            PluginHealthState::Disabled,
            PluginDiagnostic::info(
                PluginDiagnosticCode::DisabledByUser,
                "disabled by host configuration",
            ),
        );
    }

    plugin
}

fn has_safe_entrypoint(plugin_path: &Path, entrypoint: &Path) -> bool {
    let mut candidate = plugin_path.to_path_buf();
    let mut components = entrypoint.components().peekable();

    while let Some(component) = components.next() {
        match component {
            Component::CurDir => continue,
            Component::Normal(segment) => candidate.push(segment),
            _ => return false,
        }

        let Ok(metadata) = fs::symlink_metadata(&candidate) else {
            return false;
        };
        if metadata.file_type().is_symlink() {
            return false;
        }
        if components.peek().is_some() && !metadata.is_dir() {
            return false;
        }
        if components.peek().is_none() && !metadata.is_file() {
            return false;
        }
    }

    candidate != plugin_path
}

fn invalid_directory(path: PathBuf, message: String) -> DiscoveredPlugin {
    DiscoveredPlugin {
        source: PluginSource::Directory,
        path,
        manifest: None,
        health: PluginHealth::with_diagnostic(
            PluginHealthState::Quarantined,
            PluginDiagnostic::error(PluginDiagnosticCode::InvalidManifest, message),
        ),
    }
}

fn manifest_validation_diagnostic(
    error: &ManifestValidationError,
) -> (PluginHealthState, PluginDiagnostic) {
    match error {
        ManifestValidationError::UnsupportedManifestVersion { .. } => (
            PluginHealthState::Incompatible,
            PluginDiagnostic::error(
                PluginDiagnosticCode::UnsupportedManifestVersion,
                error.to_string(),
            ),
        ),
        ManifestValidationError::IncompatibleApi { .. } => (
            PluginHealthState::Incompatible,
            PluginDiagnostic::error(PluginDiagnosticCode::IncompatibleApi, error.to_string()),
        ),
        _ => (
            PluginHealthState::Quarantined,
            PluginDiagnostic::error(PluginDiagnosticCode::InvalidManifest, error.to_string()),
        ),
    }
}

fn quarantine_duplicate_ids(plugins: &mut [DiscoveredPlugin]) {
    let mut indices = BTreeMap::<PluginId, Vec<usize>>::new();
    for (index, plugin) in plugins.iter().enumerate() {
        if let Some(id) = plugin.id() {
            indices.entry(id.clone()).or_default().push(index);
        }
    }

    for (id, duplicates) in indices {
        if duplicates.len() < 2 {
            continue;
        }
        for index in duplicates {
            let plugin = &mut plugins[index];
            plugin.health.state = PluginHealthState::Quarantined;
            plugin.health.add_diagnostic(PluginDiagnostic::error(
                PluginDiagnosticCode::DuplicateId,
                format!("multiple plugins declare id `{id}`"),
            ));
        }
    }
}

fn disable_unresolved_dependencies(plugins: &mut [DiscoveredPlugin]) {
    loop {
        let catalog = plugins
            .iter()
            .filter_map(|plugin| {
                plugin.manifest.as_ref().map(|manifest| {
                    (
                        manifest.id.clone(),
                        (manifest.version.clone(), plugin.health.state),
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        let mut changed = false;

        for plugin in plugins.iter_mut().filter(|plugin| {
            plugin.manifest.is_some() && plugin.health.state == PluginHealthState::Enabled
        }) {
            let manifest = plugin.manifest.as_ref().expect("filtered above");
            let failure = manifest
                .dependencies
                .iter()
                .find_map(|(dependency, requirement)| match catalog.get(dependency) {
                    None => Some((
                        PluginDiagnosticCode::MissingDependency,
                        format!("missing dependency `{dependency}` ({requirement})"),
                    )),
                    Some((version, _state)) if !requirement.matches(version) => Some((
                        PluginDiagnosticCode::IncompatibleDependency,
                        format!(
                            "dependency `{dependency}` is {version}, but {requirement} is required"
                        ),
                    )),
                    Some((_version, state)) if !state.is_loadable() => Some((
                        PluginDiagnosticCode::MissingDependency,
                        format!("dependency `{dependency}` is not loadable ({state:?})"),
                    )),
                    Some(_) => None,
                });

            if let Some((code, message)) = failure {
                plugin.health = PluginHealth::with_diagnostic(
                    PluginHealthState::Disabled,
                    PluginDiagnostic::error(code, message),
                );
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }
}

fn package_disabled_sentinel(package: &Path) -> PathBuf {
    let mut filename = package.as_os_str().to_os_string();
    filename.push(".disabled");
    PathBuf::from(filename)
}

fn discovery_sort_key(plugin: &DiscoveredPlugin) -> (String, String, String) {
    let path_name = path_name(&plugin.path);
    let identity = plugin
        .id()
        .map_or_else(|| path_name.clone(), ToString::to_string);
    (
        identity.to_ascii_lowercase(),
        path_name.to_ascii_lowercase(),
        path_name,
    )
}

fn deterministic_path_key(path: &Path) -> (String, String) {
    let name = path_name(path);
    (name.to_ascii_lowercase(), name)
}

fn path_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn create_plugin(root: &Path, directory: &str, id: &str) -> PathBuf {
        let plugin = root.join(directory);
        fs::create_dir_all(&plugin).expect("create plugin directory");
        fs::write(plugin.join("plugin.wasm"), b"placeholder").expect("write entrypoint");
        fs::write(
            plugin.join(PLUGIN_MANIFEST_FILE),
            format!(
                r#"manifest_version = 1
id = "{id}"
name = "Test plugin"
version = "1.0.0"
api = "^0.1"
capabilities = ["resolver.symbols"]
permissions = ["binary.read", "claims.submit"]

[runtime]
kind = "wasm"
entrypoint = "plugin.wasm"
"#
            ),
        )
        .expect("write manifest");
        plugin
    }

    #[test]
    fn missing_root_is_an_empty_report() {
        let temp = TempDir::new().expect("temp directory");
        let root = temp.path().join("not-created");
        let report = discover_plugins(&root, &PluginDiscoveryOptions::default())
            .expect("missing root is allowed");
        assert!(report.plugins.is_empty());
    }

    #[test]
    fn directory_plugins_autoload_and_sort_by_id() {
        let temp = TempDir::new().expect("temp directory");
        create_plugin(temp.path(), "z-directory", "community.alpha");
        create_plugin(temp.path(), "a-directory", "community.zulu");

        let report = discover_plugins(temp.path(), &PluginDiscoveryOptions::default())
            .expect("discover plugins");
        let ids = report
            .plugins
            .iter()
            .map(|plugin| plugin.id().expect("manifest").as_str())
            .collect::<Vec<_>>();

        assert_eq!(ids, ["community.alpha", "community.zulu"]);
        assert!(report.plugins.iter().all(DiscoveredPlugin::is_loadable));
    }

    #[test]
    fn sentinel_disables_only_its_plugin() {
        let temp = TempDir::new().expect("temp directory");
        let disabled = create_plugin(temp.path(), "disabled", "community.disabled");
        create_plugin(temp.path(), "enabled", "community.enabled");
        fs::write(disabled.join(PLUGIN_DISABLED_SENTINEL), b"").expect("write sentinel");

        let report = discover_plugins(temp.path(), &PluginDiscoveryOptions::default())
            .expect("discover plugins");
        let states = report
            .plugins
            .iter()
            .map(|plugin| (plugin.id().expect("manifest").as_str(), plugin.health.state))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(states["community.disabled"], PluginHealthState::Disabled);
        assert_eq!(states["community.enabled"], PluginHealthState::Enabled);
    }

    #[test]
    fn package_files_are_discovered_without_executing_them() {
        let temp = TempDir::new().expect("temp directory");
        fs::write(temp.path().join("example.resymbol-plugin"), b"package").expect("write package");

        let report = discover_plugins(temp.path(), &PluginDiscoveryOptions::default())
            .expect("discover plugins");
        assert_eq!(report.plugins.len(), 1);
        assert_eq!(report.plugins[0].source, PluginSource::Package);
        assert_eq!(
            report.plugins[0].health.state,
            PluginHealthState::Discovered
        );
        assert!(report.plugins[0].manifest.is_none());
    }

    #[test]
    fn duplicate_ids_are_all_quarantined() {
        let temp = TempDir::new().expect("temp directory");
        create_plugin(temp.path(), "one", "community.same");
        create_plugin(temp.path(), "two", "community.same");

        let report = discover_plugins(temp.path(), &PluginDiscoveryOptions::default())
            .expect("discover plugins");
        assert!(report.plugins.iter().all(|plugin| {
            plugin.health.state == PluginHealthState::Quarantined
                && plugin
                    .health
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == PluginDiagnosticCode::DuplicateId)
        }));
    }

    #[test]
    fn invalid_manifest_is_quarantined_instead_of_stopping_scan() {
        let temp = TempDir::new().expect("temp directory");
        let invalid = temp.path().join("invalid");
        fs::create_dir(&invalid).expect("create invalid plugin");
        fs::write(invalid.join(PLUGIN_MANIFEST_FILE), "not = [valid")
            .expect("write invalid manifest");
        create_plugin(temp.path(), "valid", "community.valid");

        let report = discover_plugins(temp.path(), &PluginDiscoveryOptions::default())
            .expect("scan continues");
        assert_eq!(report.plugins.len(), 2);
        assert!(report.plugins.iter().any(|plugin| {
            plugin.health.state == PluginHealthState::Quarantined && plugin.manifest.is_none()
        }));
        assert_eq!(report.loadable().count(), 1);
    }

    #[test]
    fn bundled_example_manifests_match_the_core_contract() {
        let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/plugins");
        let mut parsed = 0usize;

        for entry in fs::read_dir(examples).expect("read bundled examples") {
            let manifest_path = entry
                .expect("read example directory")
                .path()
                .join(PLUGIN_MANIFEST_FILE);
            let manifest_text = fs::read_to_string(&manifest_path).expect("read example manifest");
            let manifest = toml::from_str::<PluginManifest>(&manifest_text)
                .unwrap_or_else(|error| panic!("{}: {error}", manifest_path.display()));
            manifest
                .validate()
                .unwrap_or_else(|error| panic!("{}: {error}", manifest_path.display()));
            parsed += 1;
        }

        assert_eq!(parsed, 4);
    }

    #[cfg(unix)]
    #[test]
    fn linked_entrypoints_are_quarantined() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("temp directory");
        let plugin = create_plugin(temp.path(), "linked", "community.linked");
        fs::remove_file(plugin.join("plugin.wasm")).expect("remove regular entrypoint");
        symlink("outside.wasm", plugin.join("plugin.wasm")).expect("create linked entrypoint");

        let report = discover_plugins(temp.path(), &PluginDiscoveryOptions::default())
            .expect("discover plugins");
        assert_eq!(
            report.plugins[0].health.state,
            PluginHealthState::Quarantined
        );
        assert!(
            report.plugins[0]
                .health
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == PluginDiagnosticCode::MissingEntrypoint })
        );
    }
}
