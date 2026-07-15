use std::{
    collections::HashSet,
    fs::{self, File},
    io::Read as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use resymbol_core::{
    BinaryFormat, BinaryIdentity, DiscoveredPlugin, PluginSource,
    plugin_api::{PluginManifest, PluginPermission, PluginRuntime},
};
use resymbol_plugin_state::{ArtifactFingerprint, FingerprintLimits, fingerprint_plugin_directory};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    ExternalProcessRequest, PluginExecution, PluginMethod, PluginRuntimeError, ProcessDiagnostics,
    RuntimeLimits,
    host::{preserve_operating_system_environment, run_child_observing_stderr},
    process_tree::ContainedChild,
    wire::encode_input,
};

const MANAGED_HOST_PROTOCOL: &str = "resymbol.managed-host";
const MANAGED_HOST_PROTOCOL_MAJOR: u32 = 1;
const MANAGED_HOST_PROTOCOL_MINOR: u32 = 0;
const MANAGED_HOST_LOAD_ATTEMPTED_MARKER: &str = "@resymbol-managed-host/load-attempted/v1@\n";
const MAX_MANAGED_BOOTSTRAP_BYTES: usize = 256 * 1024;
const MAX_MANAGED_ASSEMBLIES: usize = 512;
const MAX_MANAGED_TRAVERSAL_ENTRIES: usize = 20_000;
const MAX_MANAGED_TRAVERSAL_DEPTH: usize = 32;
const MAX_MANAGED_PE_SECTIONS: usize = 96;
const MAX_MANAGED_CLOSURE_BYTES: u64 = 512 * 1024 * 1024;
const HARD_MAX_MANAGED_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
const HARD_MAX_MANAGED_SNAPSHOT_BYTES: u64 =
    MAX_MANAGED_CLOSURE_BYTES + HARD_MAX_MANAGED_BINARY_BYTES;
const MAX_MANAGED_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_MANAGED_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_MANAGED_ADVERTISED_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_MANAGED_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_MANAGED_MESSAGES: usize = 1_000_000;
const MAX_MANAGED_IDENTIFIER_BYTES: usize = 128;
const MAX_MANAGED_GRANTED_PERMISSIONS: usize = 256;
const MAX_MANAGED_DESCRIPTOR_NAME_BYTES: usize = 4_096;
const MAX_MANAGED_DESCRIPTOR_VERSION_BYTES: usize = 128;
const MAX_MANAGED_DESCRIPTOR_IDENTIFIERS: usize = 4_096;
const HOST_SDK_ASSEMBLY: &str = "ReSymbol.PluginSdk.dll";

/// One PE section mapping supplied to the disposable managed helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedPeImageSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_offset: u32,
    pub raw_data_size: u32,
}

/// Exact binary identity and PE file-to-image mapping required by managed `binary.read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPeImage {
    pub identity: BinaryIdentity,
    pub size_of_headers: u32,
    pub size_of_image: u32,
    pub sections: Vec<ManagedPeImageSection>,
}

impl ManagedPeImage {
    pub fn new(
        identity: BinaryIdentity,
        size_of_headers: u32,
        size_of_image: u32,
        sections: Vec<ManagedPeImageSection>,
    ) -> Result<Self, PluginRuntimeError> {
        let image = Self {
            identity,
            size_of_headers,
            size_of_image,
            sections,
        };
        image.validate()?;
        Ok(image)
    }

    /// Revalidate the exact identity and every PE file/image range.
    pub fn validate(&self) -> Result<(), PluginRuntimeError> {
        self.identity
            .validate()
            .map_err(|error| invalid_context(error.to_string()))?;
        if !matches!(self.identity.format, BinaryFormat::Pe) {
            return Err(invalid_context(
                "the first managed host accepts only PE binary maps",
            ));
        }
        if self.identity.architecture != "x86_64" {
            return Err(invalid_context(
                "the first managed host accepts only x86_64 binary maps",
            ));
        }
        if self.identity.size > HARD_MAX_MANAGED_BINARY_BYTES {
            return Err(invalid_context(format!(
                "managed source binary exceeds {HARD_MAX_MANAGED_BINARY_BYTES} bytes"
            )));
        }
        if self.size_of_headers == 0 || self.size_of_image == 0 {
            return Err(invalid_context("PE image and header sizes must be nonzero"));
        }
        if self.size_of_headers > self.size_of_image
            || u64::from(self.size_of_headers) > self.identity.size
        {
            return Err(invalid_context(
                "PE header size is inconsistent with the exact binary",
            ));
        }
        if self.sections.len() > MAX_MANAGED_PE_SECTIONS {
            return Err(invalid_context(format!(
                "PE image map exceeds the {MAX_MANAGED_PE_SECTIONS}-section limit"
            )));
        }

        let mut virtual_ranges = Vec::with_capacity(self.sections.len());
        let mut raw_ranges = Vec::with_capacity(self.sections.len());
        for (index, section) in self.sections.iter().enumerate() {
            let virtual_start = u64::from(section.virtual_address);
            let virtual_size = u64::from(section.virtual_size.max(section.raw_data_size));
            let virtual_end = virtual_start.checked_add(virtual_size).ok_or_else(|| {
                invalid_context(format!("PE section {index} virtual range overflows"))
            })?;
            if virtual_end > u64::from(self.size_of_image) {
                return Err(invalid_context(format!(
                    "PE section {index} extends beyond the declared image"
                )));
            }
            if virtual_size != 0 {
                if section.virtual_address < self.size_of_headers {
                    return Err(invalid_context(format!(
                        "PE section {index} overlaps the image headers"
                    )));
                }
                virtual_ranges.push((virtual_start, virtual_end));
            }

            let raw_start = u64::from(section.raw_data_offset);
            let raw_end = raw_start
                .checked_add(u64::from(section.raw_data_size))
                .ok_or_else(|| {
                    invalid_context(format!("PE section {index} file range overflows"))
                })?;
            if raw_end > self.identity.size {
                return Err(invalid_context(format!(
                    "PE section {index} extends beyond the exact binary"
                )));
            }
            if section.raw_data_size != 0 {
                if section.raw_data_offset < self.size_of_headers {
                    return Err(invalid_context(format!(
                        "PE section {index} raw data overlaps the PE headers"
                    )));
                }
                raw_ranges.push((raw_start, raw_end));
            }
        }
        require_non_overlapping(&mut virtual_ranges, "virtual")?;
        require_non_overlapping(&mut raw_ranges, "file")
    }
}

/// Bounded launcher for one managed plugin in the disposable app-local helper.
#[derive(Debug, Clone)]
pub struct ManagedProcessHost {
    helper_path: PathBuf,
    limits: RuntimeLimits,
}

impl ManagedProcessHost {
    pub fn new(
        helper_path: impl Into<PathBuf>,
        limits: RuntimeLimits,
    ) -> Result<Self, PluginRuntimeError> {
        validate_managed_limits(&limits)?;
        let helper_path = helper_path.into();
        if helper_path.as_os_str().is_empty() {
            return Err(PluginRuntimeError::ManagedHostUnavailable {
                path: helper_path,
                reason: "helper path must not be empty".to_owned(),
            });
        }
        Ok(Self {
            helper_path,
            limits,
        })
    }

    #[must_use]
    pub fn helper_path(&self) -> &Path {
        &self.helper_path
    }

    #[must_use]
    pub const fn limits(&self) -> &RuntimeLimits {
        &self.limits
    }

    /// Execute a discovered, explicitly trusted out-of-process managed plugin.
    ///
    /// `helper_path` must be an explicit absolute app-local path; it is never
    /// looked up through `PATH` or launched through a shell. The caller must
    /// bind `expected_artifact` to host-owned trust state immediately before
    /// calling. This method independently verifies that fingerprint before
    /// launch and after every child outcome.
    pub fn execute_trusted(
        &self,
        plugin: &DiscoveredPlugin,
        request: &ExternalProcessRequest,
        expected_artifact: ArtifactFingerprint,
        exact_binary: &Path,
        image: &ManagedPeImage,
    ) -> Result<PluginExecution, PluginRuntimeError> {
        validate_managed_limits(&self.limits)?;
        request.validate()?;
        validate_managed_request(request)?;
        image.validate()?;
        let manifest = validate_managed_plugin(plugin, request)?;
        validate_request_binary(request, &image.identity)?;

        let helper = resolve_helper(&self.helper_path)?;
        let plugin_root = resolve_plugin_root(plugin)?;
        verify_artifact_before_launch(&plugin_root, expected_artifact)?;
        let entry_assembly = normalize_package_path(manifest.runtime.entrypoint())?;
        let closure = discover_managed_assemblies(
            &plugin_root,
            &entry_assembly,
            self.limits.advertised_max_memory_bytes,
        )?;
        validate_snapshot_budget(
            closure.total_bytes,
            image.identity.size,
            self.limits.advertised_max_memory_bytes,
        )?;
        let exact_binary = verify_exact_binary(exact_binary, &image.identity)?;

        let (deadline, deadline_unix_ms) = managed_deadline(self.limits.request_timeout)?;
        let input = encode_managed_input(
            manifest,
            request,
            image,
            &entry_assembly,
            &closure.assemblies,
            expected_artifact,
            deadline_unix_ms,
            &self.limits,
        )?;

        // Close the largest preparation race before handing the exact closure
        // hashes to the helper. The helper independently re-hashes each DLL.
        verify_artifact_before_launch(&plugin_root, expected_artifact)?;
        let extraction_base = tempfile::Builder::new()
            .prefix("resymbol-managed-host-")
            .tempdir()
            .map_err(|error| PluginRuntimeError::ManagedHostUnavailable {
                path: helper.clone(),
                reason: format!("cannot create private bundle extraction directory: {error}"),
            })?;
        if Instant::now() >= deadline {
            return Err(PluginRuntimeError::ManagedHostFailed {
                code: None,
                reason: "request deadline elapsed before managed helper launch".to_owned(),
                diagnostics: ProcessDiagnostics::default(),
            });
        }

        let mut command = Command::new(&helper);
        command
            .arg("--plugin-root")
            .arg(&plugin_root)
            .arg("--binary")
            .arg(&exact_binary)
            .current_dir(&plugin_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            .env("DOTNET_BUNDLE_EXTRACT_BASE_DIR", extraction_base.path());
        preserve_operating_system_environment(&mut command);
        let child = ContainedChild::spawn(&mut command).map_err(|error| {
            PluginRuntimeError::ManagedHostUnavailable {
                path: helper.clone(),
                reason: error.to_string(),
            }
        })?;
        let (child_result, observed_stderr) =
            run_child_observing_stderr(child, input, manifest, request, &self.limits, deadline);
        let result = finish_managed_child_result(
            child_result,
            &observed_stderr,
            &plugin_root,
            expected_artifact,
            &exact_binary,
            &image.identity,
        );
        drop(extraction_base);
        result
    }
}

fn validate_managed_plugin<'a>(
    plugin: &'a DiscoveredPlugin,
    request: &ExternalProcessRequest,
) -> Result<&'a PluginManifest, PluginRuntimeError> {
    if plugin.source != PluginSource::Directory {
        return Err(PluginRuntimeError::UnsupportedPluginSource);
    }
    let manifest = plugin
        .manifest
        .as_ref()
        .ok_or(PluginRuntimeError::MissingManifest)?;
    if !plugin.is_loadable() {
        return Err(PluginRuntimeError::PluginNotLoadable(format!(
            "{:?}",
            plugin.health.state
        )));
    }
    manifest
        .validate()
        .map_err(|error| PluginRuntimeError::InvalidManifest(error.to_string()))?;
    if !matches!(&manifest.runtime, PluginRuntime::Managed { .. }) {
        return Err(PluginRuntimeError::UnsupportedRuntime(
            manifest.runtime.kind(),
        ));
    }
    validate_descriptor_shape(manifest)?;
    for permission in request.granted_permissions() {
        if !manifest.permissions.contains(permission) {
            return Err(PluginRuntimeError::PermissionNotRequested(
                permission.to_string(),
            ));
        }
    }
    Ok(manifest)
}

fn validate_descriptor_shape(manifest: &PluginManifest) -> Result<(), PluginRuntimeError> {
    if manifest.name.len() > MAX_MANAGED_DESCRIPTOR_NAME_BYTES {
        return Err(invalid_context(format!(
            "managed plugin name exceeds {MAX_MANAGED_DESCRIPTOR_NAME_BYTES} bytes"
        )));
    }
    if manifest.version.to_string().len() > MAX_MANAGED_DESCRIPTOR_VERSION_BYTES {
        return Err(invalid_context(format!(
            "managed plugin version exceeds {MAX_MANAGED_DESCRIPTOR_VERSION_BYTES} bytes"
        )));
    }
    if manifest.capabilities.len() > MAX_MANAGED_DESCRIPTOR_IDENTIFIERS
        || manifest.permissions.len() > MAX_MANAGED_DESCRIPTOR_IDENTIFIERS
    {
        return Err(invalid_context(
            "managed plugin descriptor exceeds the 4096-identifier limit",
        ));
    }
    Ok(())
}

fn validate_managed_request(request: &ExternalProcessRequest) -> Result<(), PluginRuntimeError> {
    if request.method() != PluginMethod::Analyze {
        return Err(invalid_context(
            "the first managed host accepts only analyze requests",
        ));
    }
    if request.id().len() > MAX_MANAGED_IDENTIFIER_BYTES
        || request.session_id().len() > MAX_MANAGED_IDENTIFIER_BYTES
    {
        return Err(invalid_context(
            "managed request and session identifiers must be at most 128 UTF-8 bytes",
        ));
    }
    if request.granted_permissions().len() > MAX_MANAGED_GRANTED_PERMISSIONS {
        return Err(invalid_context(
            "managed request exceeds the 256-permission grant limit",
        ));
    }
    Ok(())
}

fn validate_request_binary(
    request: &ExternalProcessRequest,
    expected: &BinaryIdentity,
) -> Result<(), PluginRuntimeError> {
    let value = request
        .payload()
        .get("binary")
        .ok_or_else(|| invalid_context("managed analyze request is missing its binary identity"))?;
    let found = serde_json::from_value::<BinaryIdentity>(value.clone()).map_err(|error| {
        invalid_context(format!(
            "managed analyze request has an invalid binary identity: {error}"
        ))
    })?;
    if &found != expected {
        return Err(invalid_context(
            "managed analyze request binary identity does not match the PE image map",
        ));
    }
    Ok(())
}

fn resolve_helper(path: &Path) -> Result<PathBuf, PluginRuntimeError> {
    let fail = |reason: String| PluginRuntimeError::ManagedHostUnavailable {
        path: path.to_path_buf(),
        reason,
    };
    if !path.is_absolute() {
        return Err(fail(
            "helper path must be an explicit absolute app-local path".to_owned(),
        ));
    }
    let expected_name = if cfg!(windows) {
        "resymbol-managed-host.exe"
    } else {
        "resymbol-managed-host"
    };
    if !path
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(expected_name))
    {
        return Err(fail(format!(
            "app-local helper must be named {expected_name}"
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| fail(error.to_string()))?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(fail("helper must be a regular, unlinked file".to_owned()));
    }
    fs::canonicalize(path).map_err(|error| fail(error.to_string()))
}

fn resolve_plugin_root(plugin: &DiscoveredPlugin) -> Result<PathBuf, PluginRuntimeError> {
    let metadata = fs::symlink_metadata(&plugin.path).map_err(|source| PluginRuntimeError::Io {
        operation: "inspect managed plugin directory",
        source,
    })?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(PluginRuntimeError::PluginNotLoadable(
            "managed plugin root must be a regular, unlinked directory".to_owned(),
        ));
    }
    fs::canonicalize(&plugin.path).map_err(|source| PluginRuntimeError::Io {
        operation: "resolve managed plugin directory",
        source,
    })
}

fn normalize_package_path(path: &Path) -> Result<String, PluginRuntimeError> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid_context("managed entry assembly path is not UTF-8"))?;
    if value.trim().is_empty() || value.starts_with(['/', '\\']) || value.contains(['\0', ':']) {
        return Err(invalid_context(
            "managed entry assembly must be a portable relative path",
        ));
    }
    let components = value.split(['/', '\\']).collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| !is_portable_component(component))
    {
        return Err(invalid_context(
            "managed entry assembly contains an unsafe path component",
        ));
    }
    let normalized = components.join("/");
    if !normalized
        .rsplit_once('.')
        .is_some_and(|(stem, extension)| {
            !stem.rsplit('/').next().unwrap_or_default().is_empty()
                && extension.eq_ignore_ascii_case("dll")
        })
    {
        return Err(invalid_context("managed entry assembly must end in .dll"));
    }
    if normalized
        .rsplit('/')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case(HOST_SDK_ASSEMBLY))
    {
        return Err(invalid_context(
            "the host-supplied ReSymbol.PluginSdk cannot be the plugin entry assembly",
        ));
    }
    Ok(normalized)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ExpectedManagedAssembly {
    path: String,
    sha256: String,
}

struct ManagedAssemblyClosure {
    assemblies: Vec<ExpectedManagedAssembly>,
    total_bytes: u64,
}

struct ClosureTraversal {
    entries: usize,
    total_bytes: u64,
    maximum_bytes: u64,
    portable_paths: HashSet<String>,
    assemblies: Vec<ExpectedManagedAssembly>,
}

fn discover_managed_assemblies(
    plugin_root: &Path,
    entry_assembly: &str,
    advertised_memory_bytes: u64,
) -> Result<ManagedAssemblyClosure, PluginRuntimeError> {
    let mut traversal = ClosureTraversal {
        entries: 0,
        total_bytes: 0,
        maximum_bytes: advertised_memory_bytes.min(MAX_MANAGED_CLOSURE_BYTES),
        portable_paths: HashSet::new(),
        assemblies: Vec::new(),
    };
    collect_managed_assemblies(plugin_root, "", 0, &mut traversal)?;
    traversal
        .assemblies
        .sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    if !traversal
        .assemblies
        .iter()
        .any(|assembly| assembly.path == entry_assembly)
    {
        return Err(invalid_context(
            "managed entry assembly is absent from the private DLL closure or has different casing",
        ));
    }
    Ok(ManagedAssemblyClosure {
        assemblies: traversal.assemblies,
        total_bytes: traversal.total_bytes,
    })
}

fn validate_snapshot_budget(
    closure_bytes: u64,
    binary_bytes: u64,
    advertised_memory_bytes: u64,
) -> Result<(), PluginRuntimeError> {
    let total = closure_bytes.checked_add(binary_bytes).ok_or_else(|| {
        invalid_context("managed DLL closure and exact binary byte count overflows")
    })?;
    let budget = advertised_memory_bytes.min(HARD_MAX_MANAGED_SNAPSHOT_BYTES);
    if total > budget {
        return Err(invalid_context(format!(
            "managed DLL closure plus exact binary require {total} snapshot bytes, exceeding the {budget}-byte advertised snapshot budget"
        )));
    }
    Ok(())
}

fn collect_managed_assemblies(
    directory: &Path,
    relative_parent: &str,
    depth: usize,
    traversal: &mut ClosureTraversal,
) -> Result<(), PluginRuntimeError> {
    if depth > MAX_MANAGED_TRAVERSAL_DEPTH {
        return Err(closure_error(
            directory,
            format!("directory depth exceeds {MAX_MANAGED_TRAVERSAL_DEPTH}"),
        ));
    }
    let reader = fs::read_dir(directory)
        .map_err(|error| closure_error(directory, format!("cannot read directory: {error}")))?;
    let mut children = Vec::new();
    for child in reader {
        let child = child.map_err(|error| {
            closure_error(directory, format!("cannot read directory entry: {error}"))
        })?;
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| closure_error(&child.path(), "package path is not UTF-8".to_owned()))?;
        validate_portable_component(&name, &child.path())?;
        children.push((name, child.path()));
    }
    children.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    for (name, path) in children {
        traversal.entries = traversal.entries.checked_add(1).ok_or_else(|| {
            closure_error(&path, "package traversal entry count overflowed".to_owned())
        })?;
        if traversal.entries > MAX_MANAGED_TRAVERSAL_ENTRIES {
            return Err(closure_error(
                &path,
                format!("package traversal exceeds {MAX_MANAGED_TRAVERSAL_ENTRIES} entries"),
            ));
        }
        let relative = if relative_parent.is_empty() {
            name.clone()
        } else {
            format!("{relative_parent}/{name}")
        };
        record_portable_path(traversal, &relative, &path)?;

        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| closure_error(&path, format!("cannot inspect entry: {error}")))?;
        if is_link_or_reparse(&metadata) {
            return Err(closure_error(
                &path,
                "managed package must not contain symbolic links or reparse points".to_owned(),
            ));
        }
        if metadata.is_dir() {
            collect_managed_assemblies(&path, &relative, depth + 1, traversal)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(closure_error(
                &path,
                "managed package contains a non-file, non-directory entry".to_owned(),
            ));
        }
        if !name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("dll"))
        {
            continue;
        }
        // Plugins compile against the SDK but never privately load it. A
        // bundled copy remains part of the artifact fingerprint; omitting its
        // exact basename from the closure forces the helper to bind references
        // to its own version-checked SDK assembly.
        if name.eq_ignore_ascii_case(HOST_SDK_ASSEMBLY) {
            continue;
        }
        if traversal.assemblies.len() == MAX_MANAGED_ASSEMBLIES {
            return Err(closure_error(
                &path,
                format!("managed DLL closure exceeds {MAX_MANAGED_ASSEMBLIES} assemblies"),
            ));
        }
        traversal.total_bytes = traversal
            .total_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| {
                closure_error(&path, "managed closure byte count overflowed".to_owned())
            })?;
        if traversal.total_bytes > traversal.maximum_bytes {
            return Err(closure_error(
                &path,
                format!(
                    "managed DLL closure exceeds its {}-byte memory budget",
                    traversal.maximum_bytes
                ),
            ));
        }
        let sha256 = hash_exact_file(&path, metadata.len())?;
        traversal.assemblies.push(ExpectedManagedAssembly {
            path: relative,
            sha256,
        });
    }
    Ok(())
}

fn record_portable_path(
    traversal: &mut ClosureTraversal,
    relative: &str,
    path: &Path,
) -> Result<(), PluginRuntimeError> {
    if !traversal.portable_paths.insert(relative.to_lowercase()) {
        return Err(closure_error(
            path,
            "package contains a portable path alias or case collision".to_owned(),
        ));
    }
    Ok(())
}

fn validate_portable_component(name: &str, path: &Path) -> Result<(), PluginRuntimeError> {
    if !is_portable_component(name) {
        return Err(closure_error(
            path,
            "package path contains a non-portable component".to_owned(),
        ));
    }
    Ok(())
}

fn is_portable_component(name: &str) -> bool {
    if name.trim().is_empty()
        || matches!(name, "." | "..")
        || name.contains(['/', '\\', ':', '\0', '<', '>', '"', '|', '?', '*'])
        || name.chars().any(char::is_control)
        || name.ends_with([' ', '.'])
    {
        return false;
    }
    let base = name.split('.').next().unwrap_or_default();
    !matches!(
        base.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn hash_exact_file(path: &Path, expected_size: u64) -> Result<String, PluginRuntimeError> {
    let mut file = File::open(path)
        .map_err(|error| closure_error(path, format!("cannot open DLL: {error}")))?;
    let opened = file
        .metadata()
        .map_err(|error| closure_error(path, format!("cannot inspect opened DLL: {error}")))?;
    if !opened.is_file() || opened.len() != expected_size {
        return Err(closure_error(
            path,
            "DLL changed before it could be read".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| closure_error(path, format!("cannot read DLL: {error}")))?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or_else(|| closure_error(path, "DLL byte count overflowed".to_owned()))?;
        if observed > expected_size {
            return Err(closure_error(path, "DLL grew while it was read".to_owned()));
        }
        hasher.update(&buffer[..count]);
    }
    if observed != expected_size {
        return Err(closure_error(
            path,
            "DLL changed while it was read".to_owned(),
        ));
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| closure_error(path, format!("cannot re-inspect DLL: {error}")))?;
    if is_link_or_reparse(&after) || !after.is_file() || after.len() != expected_size {
        return Err(closure_error(
            path,
            "DLL changed while it was verified".to_owned(),
        ));
    }
    Ok(encode_hex(&hasher.finalize()))
}

fn closure_error(path: &Path, reason: String) -> PluginRuntimeError {
    PluginRuntimeError::ManagedAssemblyClosure {
        path: path.to_path_buf(),
        reason,
    }
}

fn verify_artifact_before_launch(
    plugin_root: &Path,
    expected: ArtifactFingerprint,
) -> Result<(), PluginRuntimeError> {
    let observed = fingerprint_plugin_directory(plugin_root, FingerprintLimits::default())
        .map_err(|error| PluginRuntimeError::ManagedArtifactMismatch {
            reason: format!("fingerprint failed: {error}"),
        })?
        .fingerprint;
    if observed != expected {
        return Err(PluginRuntimeError::ManagedArtifactMismatch {
            reason: format!("expected {expected}, found {observed}"),
        });
    }
    Ok(())
}

fn verify_exact_binary(
    path: &Path,
    expected: &BinaryIdentity,
) -> Result<PathBuf, PluginRuntimeError> {
    let fail = |reason: String| PluginRuntimeError::ManagedSourceBinary {
        path: path.to_path_buf(),
        reason,
    };
    let metadata = fs::symlink_metadata(path).map_err(|error| fail(error.to_string()))?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(fail(
            "source binary must be a regular, unlinked file".to_owned(),
        ));
    }
    if metadata.len() != expected.size {
        return Err(fail(format!(
            "source size {} does not match expected {}",
            metadata.len(),
            expected.size
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|error| fail(error.to_string()))?;
    let mut file = File::open(&canonical).map_err(|error| fail(error.to_string()))?;
    let opened = file.metadata().map_err(|error| fail(error.to_string()))?;
    if !opened.is_file() || opened.len() != expected.size {
        return Err(fail(
            "source binary changed before it could be read".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut observed_size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| fail(error.to_string()))?;
        if count == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or_else(|| fail("source byte count overflowed".to_owned()))?;
        if observed_size > expected.size {
            return Err(fail("source binary grew while it was read".to_owned()));
        }
        hasher.update(&buffer[..count]);
    }
    if observed_size != expected.size {
        return Err(fail("source binary changed while it was read".to_owned()));
    }
    if encode_hex(&hasher.finalize()) != expected.id.as_str() {
        return Err(fail(
            "source SHA-256 does not match the analysis identity".to_owned(),
        ));
    }
    let after = fs::symlink_metadata(&canonical).map_err(|error| fail(error.to_string()))?;
    if is_link_or_reparse(&after) || !after.is_file() || after.len() != expected.size {
        return Err(fail(
            "source binary changed while it was verified".to_owned(),
        ));
    }
    Ok(canonical)
}

#[derive(Serialize)]
struct ManagedBootstrap<'a> {
    protocol: &'static str,
    version: ManagedProtocolVersion,
    entry_assembly: &'a str,
    expected_plugin: ManagedExpectedPlugin<'a>,
    assemblies: &'a [ExpectedManagedAssembly],
    expected_artifact_sha256: String,
    output_limits: ManagedOutputLimits,
    service_limits: ManagedServiceLimits,
    binary: &'a BinaryIdentity,
    image: ManagedBootstrapImage<'a>,
    deadline_unix_ms: i64,
}

#[derive(Serialize)]
struct ManagedProtocolVersion {
    major: u32,
    minor: u32,
}

#[derive(Serialize)]
struct ManagedExpectedPlugin<'a> {
    id: &'a str,
    name: &'a str,
    version: String,
    capabilities: Vec<&'a str>,
    requested_permissions: Vec<&'a str>,
}

#[derive(Serialize)]
struct ManagedOutputLimits {
    max_messages: usize,
    max_stdout_bytes: usize,
}

#[derive(Serialize)]
struct ManagedServiceLimits {
    max_binary_read_bytes: u64,
}

#[derive(Serialize)]
struct ManagedBootstrapImage<'a> {
    size_of_headers: u32,
    size_of_image: u32,
    sections: &'a [ManagedPeImageSection],
}

#[allow(clippy::too_many_arguments)]
fn encode_managed_input(
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    image: &ManagedPeImage,
    entry_assembly: &str,
    assemblies: &[ExpectedManagedAssembly],
    expected_artifact: ArtifactFingerprint,
    deadline_unix_ms: i64,
    limits: &RuntimeLimits,
) -> Result<Vec<u8>, PluginRuntimeError> {
    let capabilities = manifest
        .capabilities
        .iter()
        .map(|value| value.as_str())
        .collect();
    let requested_permissions = manifest
        .permissions
        .iter()
        .map(|value| value.as_str())
        .collect();
    let binary_read_granted = request
        .granted_permissions()
        .iter()
        .any(|permission| permission.as_str() == PluginPermission::BINARY_READ);
    let bootstrap = ManagedBootstrap {
        protocol: MANAGED_HOST_PROTOCOL,
        version: ManagedProtocolVersion {
            major: MANAGED_HOST_PROTOCOL_MAJOR,
            minor: MANAGED_HOST_PROTOCOL_MINOR,
        },
        entry_assembly,
        expected_plugin: ManagedExpectedPlugin {
            id: manifest.id.as_str(),
            name: &manifest.name,
            version: manifest.version.to_string(),
            capabilities,
            requested_permissions,
        },
        assemblies,
        expected_artifact_sha256: expected_artifact.to_hex(),
        output_limits: ManagedOutputLimits {
            max_messages: limits.max_messages,
            max_stdout_bytes: limits.max_stdout_bytes,
        },
        service_limits: ManagedServiceLimits {
            max_binary_read_bytes: if binary_read_granted {
                image.identity.size
            } else {
                0
            },
        },
        binary: &image.identity,
        image: ManagedBootstrapImage {
            size_of_headers: image.size_of_headers,
            size_of_image: image.size_of_image,
            sections: &image.sections,
        },
        deadline_unix_ms,
    };
    let bootstrap =
        serde_json::to_vec(&bootstrap).map_err(PluginRuntimeError::EncodeManagedBootstrap)?;
    if bootstrap.len() > MAX_MANAGED_BOOTSTRAP_BYTES {
        return Err(invalid_context(format!(
            "managed-host bootstrap exceeds {MAX_MANAGED_BOOTSTRAP_BYTES} bytes"
        )));
    }
    let wire = encode_input(manifest, request, limits)?;
    let total = bootstrap
        .len()
        .checked_add(1)
        .and_then(|size| size.checked_add(wire.len()))
        .ok_or_else(|| invalid_context("managed-host input size overflows this platform"))?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(total)
        .map_err(|_| invalid_context("cannot reserve managed-host input buffer"))?;
    input.extend_from_slice(&bootstrap);
    input.push(b'\n');
    input.extend_from_slice(&wire);
    Ok(input)
}

fn managed_deadline(timeout: Duration) -> Result<(Instant, i64), PluginRuntimeError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(PluginRuntimeError::InvalidLimits(
            "request_timeout is too large for the platform clock",
        ))?;
    let wall_deadline =
        SystemTime::now()
            .checked_add(timeout)
            .ok_or(PluginRuntimeError::InvalidLimits(
                "request_timeout is too large for the wall clock",
            ))?;
    let milliseconds = wall_deadline
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PluginRuntimeError::InvalidLimits("system clock predates the Unix epoch"))?
        .as_millis();
    let deadline_unix_ms = i64::try_from(milliseconds).map_err(|_| {
        PluginRuntimeError::InvalidLimits("absolute managed deadline exceeds signed 64-bit time")
    })?;
    Ok((deadline, deadline_unix_ms))
}

fn finish_managed_child_result(
    mut result: Result<PluginExecution, PluginRuntimeError>,
    observed_stderr: &[u8],
    plugin_root: &Path,
    expected_artifact: ArtifactFingerprint,
    exact_binary: &Path,
    expected_binary: &BinaryIdentity,
) -> Result<PluginExecution, PluginRuntimeError> {
    let load_attempted = observed_stderr.starts_with(MANAGED_HOST_LOAD_ATTEMPTED_MARKER.as_bytes());
    strip_managed_marker(&mut result);
    let diagnostics = child_result_diagnostics(&result, observed_stderr);
    verify_post_run_artifact(plugin_root, expected_artifact, &diagnostics, load_attempted)?;
    verify_post_child_binary(exact_binary, expected_binary, &diagnostics, load_attempted)?;
    classify_managed_child_result(result, observed_stderr, load_attempted)
}

fn strip_managed_marker(result: &mut Result<PluginExecution, PluginRuntimeError>) {
    let diagnostics = match result {
        Ok(execution) => &mut execution.diagnostics,
        Err(error) => {
            let Some(diagnostics) = error.diagnostics_mut() else {
                return;
            };
            diagnostics
        }
    };
    if diagnostics
        .stderr
        .starts_with(MANAGED_HOST_LOAD_ATTEMPTED_MARKER)
    {
        diagnostics
            .stderr
            .drain(..MANAGED_HOST_LOAD_ATTEMPTED_MARKER.len());
    }
}

fn child_result_diagnostics(
    result: &Result<PluginExecution, PluginRuntimeError>,
    observed_stderr: &[u8],
) -> ProcessDiagnostics {
    match result {
        Ok(execution) => execution.diagnostics.clone(),
        Err(error) => error.diagnostics().cloned().unwrap_or_else(|| {
            let bytes = observed_stderr
                .strip_prefix(MANAGED_HOST_LOAD_ATTEMPTED_MARKER.as_bytes())
                .unwrap_or(observed_stderr);
            ProcessDiagnostics::from_bytes(bytes)
        }),
    }
}

fn verify_post_run_artifact(
    plugin_root: &Path,
    expected: ArtifactFingerprint,
    diagnostics: &ProcessDiagnostics,
    load_attempted: bool,
) -> Result<(), PluginRuntimeError> {
    let observed = fingerprint_plugin_directory(plugin_root, FingerprintLimits::default())
        .map_err(|error| {
            post_child_artifact_error(
                format!("post-run fingerprint failed: {error}"),
                diagnostics,
                load_attempted,
            )
        })?
        .fingerprint;
    if observed != expected {
        return Err(post_child_artifact_error(
            format!("expected {expected}, found {observed}"),
            diagnostics,
            load_attempted,
        ));
    }
    Ok(())
}

fn post_child_artifact_error(
    reason: String,
    diagnostics: &ProcessDiagnostics,
    load_attempted: bool,
) -> PluginRuntimeError {
    if load_attempted {
        PluginRuntimeError::ManagedExecutionArtifactChanged {
            reason,
            diagnostics: diagnostics.clone(),
        }
    } else {
        PluginRuntimeError::ManagedHostArtifactChanged {
            reason,
            diagnostics: diagnostics.clone(),
        }
    }
}

fn verify_post_child_binary(
    exact_binary: &Path,
    expected_binary: &BinaryIdentity,
    diagnostics: &ProcessDiagnostics,
    load_attempted: bool,
) -> Result<(), PluginRuntimeError> {
    match verify_exact_binary(exact_binary, expected_binary) {
        Ok(_) => Ok(()),
        Err(PluginRuntimeError::ManagedSourceBinary { path, reason }) if load_attempted => {
            Err(PluginRuntimeError::ManagedExecutionInputChanged {
                path,
                reason,
                diagnostics: diagnostics.clone(),
            })
        }
        Err(PluginRuntimeError::ManagedSourceBinary { path, reason }) => {
            Err(PluginRuntimeError::ManagedHostInputChanged {
                path,
                reason,
                diagnostics: diagnostics.clone(),
            })
        }
        Err(error) => Err(error),
    }
}

fn classify_managed_child_result(
    result: Result<PluginExecution, PluginRuntimeError>,
    observed_stderr: &[u8],
    load_attempted: bool,
) -> Result<PluginExecution, PluginRuntimeError> {
    if load_attempted {
        return result;
    }
    let code = match &result {
        Ok(execution) => execution.exit_code,
        Err(PluginRuntimeError::ProcessFailed { code, .. })
        | Err(PluginRuntimeError::ManagedHostFailed { code, .. }) => *code,
        Err(_) => None,
    };
    let reason = match &result {
        Ok(_) => "helper returned protocol success without the current load-attempted marker"
            .to_owned(),
        Err(PluginRuntimeError::ManagedHostFailed { reason, .. }) => reason.clone(),
        Err(PluginRuntimeError::ProcessFailed { .. }) => match code {
            Some(code) => format!(
                "helper exited with code {code} before emitting the current load-attempted marker"
            ),
            None => "helper terminated without an exit code before emitting the current load-attempted marker"
                .to_owned(),
        },
        Err(error) => error.to_string(),
    };
    Err(PluginRuntimeError::ManagedHostFailed {
        code,
        reason: bounded_reason(&reason),
        diagnostics: child_result_diagnostics(&result, observed_stderr),
    })
}

fn require_non_overlapping(
    ranges: &mut [(u64, u64)],
    kind: &str,
) -> Result<(), PluginRuntimeError> {
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(invalid_context(format!(
            "PE image map contains overlapping {kind} sections"
        )));
    }
    Ok(())
}

fn invalid_context(message: impl Into<String>) -> PluginRuntimeError {
    PluginRuntimeError::InvalidManagedContext(message.into())
}

fn validate_managed_limits(limits: &RuntimeLimits) -> Result<(), PluginRuntimeError> {
    limits.validate()?;
    if !(2..=MAX_MANAGED_MESSAGES).contains(&limits.max_messages) {
        return Err(PluginRuntimeError::InvalidLimits(
            "managed-host max_messages must be in 2..=1000000",
        ));
    }
    if limits.max_stderr_bytes < MANAGED_HOST_LOAD_ATTEMPTED_MARKER.len() {
        return Err(PluginRuntimeError::InvalidLimits(
            "managed-host max_stderr_bytes must fit the load-attempted marker",
        ));
    }
    if limits.max_message_bytes > MAX_MANAGED_MESSAGE_BYTES {
        return Err(PluginRuntimeError::InvalidLimits(
            "managed-host max_message_bytes must not exceed 67108864",
        ));
    }
    if limits.max_stdout_bytes > MAX_MANAGED_STDOUT_BYTES {
        return Err(PluginRuntimeError::InvalidLimits(
            "managed-host max_stdout_bytes must not exceed 8388608",
        ));
    }
    if limits.advertised_max_memory_bytes > MAX_MANAGED_ADVERTISED_MEMORY_BYTES {
        return Err(PluginRuntimeError::InvalidLimits(
            "managed-host advertised_max_memory_bytes must not exceed 68719476736",
        ));
    }
    if limits.request_timeout > MAX_MANAGED_TIMEOUT {
        return Err(PluginRuntimeError::InvalidLimits(
            "managed-host request_timeout must not exceed 24 hours",
        ));
    }
    Ok(())
}

fn bounded_reason(reason: &str) -> String {
    const LIMIT: usize = 4_096;
    const SUFFIX: &str = "...";
    if reason.len() <= LIMIT {
        return reason.to_owned();
    }
    let boundary = LIMIT - SUFFIX.len();
    let end = reason
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= boundary)
        .last()
        .unwrap_or(0);
    format!("{}{SUFFIX}", &reason[..end])
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        str::FromStr as _,
    };

    use resymbol_core::{
        BinaryId,
        plugin_api::{MANIFEST_VERSION, PluginCapability, PluginId, PluginPermission},
    };
    use semver::{Version, VersionReq};
    use serde_json::{Map, Value};
    use tempfile::TempDir;

    use super::*;
    use crate::{PluginDescriptor, PluginResponse};

    fn image(bytes: &[u8]) -> ManagedPeImage {
        ManagedPeImage::new(
            BinaryIdentity {
                id: BinaryId::digest(bytes),
                size: bytes.len() as u64,
                format: BinaryFormat::Pe,
                architecture: "x86_64".to_owned(),
                image_base: 0x0001_4000_0000,
            },
            1,
            1,
            Vec::new(),
        )
        .unwrap()
    }

    fn manifest(entrypoint: &str) -> PluginManifest {
        PluginManifest {
            manifest_version: MANIFEST_VERSION,
            id: PluginId::new("dev.resymbol.managed-test").unwrap(),
            name: "Managed test".to_owned(),
            version: Version::new(0, 1, 0),
            api: VersionReq::parse("^0.1").unwrap(),
            runtime: PluginRuntime::Managed {
                entrypoint: PathBuf::from(entrypoint),
            },
            capabilities: BTreeSet::from([PluginCapability::new(
                PluginCapability::ANALYZER_BINARY,
            )
            .unwrap()]),
            permissions: BTreeSet::from([
                PluginPermission::new(PluginPermission::BINARY_READ).unwrap(),
                PluginPermission::new(PluginPermission::CLAIMS_SUBMIT).unwrap(),
            ]),
            dependencies: BTreeMap::new(),
            description: None,
            authors: Vec::new(),
            license: None,
            homepage: None,
        }
    }

    fn request(identity: &BinaryIdentity) -> ExternalProcessRequest {
        ExternalProcessRequest::new(
            "request-1",
            "session-1",
            PluginMethod::Analyze,
            Map::from_iter([("binary".to_owned(), serde_json::to_value(identity).unwrap())]),
        )
        .unwrap()
        .with_granted_permissions([
            PluginPermission::new(PluginPermission::BINARY_READ).unwrap(),
            PluginPermission::new(PluginPermission::CLAIMS_SUBMIT).unwrap(),
        ])
    }

    fn successful_result(marked: bool) -> Result<PluginExecution, PluginRuntimeError> {
        Ok(PluginExecution {
            descriptor: PluginDescriptor {
                id: "dev.resymbol.managed-test".to_owned(),
                name: "Managed test".to_owned(),
                version: "0.1.0".to_owned(),
                capabilities: vec![PluginCapability::ANALYZER_BINARY.to_owned()],
                requested_permissions: vec![
                    PluginPermission::BINARY_READ.to_owned(),
                    PluginPermission::CLAIMS_SUBMIT.to_owned(),
                ],
            },
            response: PluginResponse {
                id: "request-1".to_owned(),
                result: Value::Null,
            },
            claims: Vec::new(),
            logs: Vec::new(),
            diagnostics: ProcessDiagnostics {
                stderr: format!(
                    "{}helper detail",
                    if marked {
                        MANAGED_HOST_LOAD_ATTEMPTED_MARKER
                    } else {
                        ""
                    }
                ),
                stderr_was_lossy: false,
            },
            exit_code: Some(0),
        })
    }

    #[test]
    fn managed_input_has_exactly_three_strict_lines() {
        let image = image(b"M");
        let manifest = manifest("lib/Plugin.dll");
        let request = request(&image.identity);
        let fingerprint = ArtifactFingerprint::from_str(&"11".repeat(32)).unwrap();
        let assemblies = vec![ExpectedManagedAssembly {
            path: "lib/Plugin.dll".to_owned(),
            sha256: "22".repeat(32),
        }];
        let input = encode_managed_input(
            &manifest,
            &request,
            &image,
            "lib/Plugin.dll",
            &assemblies,
            fingerprint,
            1_900_000_000_000,
            &RuntimeLimits::default(),
        )
        .unwrap();
        let lines = input
            .strip_suffix(b"\n")
            .unwrap()
            .split(|byte| *byte == b'\n')
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        let bootstrap = serde_json::from_slice::<Value>(lines[0]).unwrap();
        assert_eq!(bootstrap["protocol"], MANAGED_HOST_PROTOCOL);
        assert_eq!(bootstrap["entry_assembly"], "lib/Plugin.dll");
        assert_eq!(bootstrap["expected_artifact_sha256"], "11".repeat(32));
        assert_eq!(bootstrap["binary"]["format"], "pe");
        assert_eq!(bootstrap["deadline_unix_ms"], 1_900_000_000_000_i64);
        assert_eq!(bootstrap["assemblies"][0]["sha256"], "22".repeat(32));
    }

    #[test]
    fn recursive_closure_is_sorted_and_excludes_host_sdk() {
        let temporary = TempDir::new().unwrap();
        fs::create_dir(temporary.path().join("z")).unwrap();
        fs::create_dir(temporary.path().join("a")).unwrap();
        fs::write(temporary.path().join("z/Plugin.dll"), b"entry").unwrap();
        fs::write(temporary.path().join("a/Dependency.DLL"), b"dependency").unwrap();
        fs::write(
            temporary.path().join(HOST_SDK_ASSEMBLY),
            b"ignored SDK copy",
        )
        .unwrap();
        fs::write(temporary.path().join("readme.txt"), b"ignored").unwrap();

        let closure = discover_managed_assemblies(
            temporary.path(),
            "z/Plugin.dll",
            MAX_MANAGED_CLOSURE_BYTES,
        )
        .unwrap();
        assert_eq!(
            closure
                .assemblies
                .iter()
                .map(|item| item.path.as_str())
                .collect::<Vec<_>>(),
            ["a/Dependency.DLL", "z/Plugin.dll"]
        );
        assert_eq!(closure.assemblies[0].sha256.len(), 64);
        assert_eq!(closure.total_bytes, 15);
    }

    #[test]
    fn entry_and_portable_paths_are_strict() {
        for invalid in [
            "/Plugin.dll",
            "../Plugin.dll",
            "a//Plugin.dll",
            "a/./Plugin.dll",
            "C:\\Plugin.dll",
            "Plugin.exe",
            HOST_SDK_ASSEMBLY,
        ] {
            assert!(
                normalize_package_path(Path::new(invalid)).is_err(),
                "{invalid}"
            );
        }
        assert_eq!(
            normalize_package_path(Path::new("a\\Plugin.dll")).unwrap(),
            "a/Plugin.dll"
        );
    }

    #[cfg(unix)]
    #[test]
    fn closure_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let linked = TempDir::new().unwrap();
        fs::write(linked.path().join("Plugin.dll"), b"entry").unwrap();
        symlink("Plugin.dll", linked.path().join("Alias.dll")).unwrap();
        assert!(
            discover_managed_assemblies(linked.path(), "Plugin.dll", MAX_MANAGED_CLOSURE_BYTES)
                .is_err()
        );
    }

    #[test]
    fn portable_path_aliases_are_rejected_without_filesystem_case_assumptions() {
        let temporary = TempDir::new().unwrap();
        let mut traversal = ClosureTraversal {
            entries: 0,
            total_bytes: 0,
            maximum_bytes: MAX_MANAGED_CLOSURE_BYTES,
            portable_paths: HashSet::new(),
            assemblies: Vec::new(),
        };
        record_portable_path(
            &mut traversal,
            "lib/Plugin.dll",
            &temporary.path().join("lib/Plugin.dll"),
        )
        .unwrap();
        assert!(
            record_portable_path(
                &mut traversal,
                "LIB/plugin.DLL",
                &temporary.path().join("LIB/plugin.DLL"),
            )
            .is_err()
        );
    }

    #[test]
    fn missing_marker_is_always_host_side_and_marker_is_stripped() {
        let missing =
            classify_managed_child_result(successful_result(false), b"helper detail", false)
                .unwrap_err();
        assert!(matches!(
            missing,
            PluginRuntimeError::ManagedHostFailed { .. }
        ));
        assert_eq!(missing.diagnostics().unwrap().stderr, "helper detail");

        let mut marked = successful_result(true);
        strip_managed_marker(&mut marked);
        let execution = classify_managed_child_result(
            marked,
            MANAGED_HOST_LOAD_ATTEMPTED_MARKER.as_bytes(),
            true,
        )
        .unwrap();
        assert_eq!(execution.diagnostics.stderr, "helper detail");
    }

    #[test]
    fn limits_reserve_marker_and_helper_is_explicit() {
        let too_small = RuntimeLimits {
            max_stderr_bytes: MANAGED_HOST_LOAD_ATTEMPTED_MARKER.len() - 1,
            ..RuntimeLimits::default()
        };
        assert!(ManagedProcessHost::new("host", too_small).is_err());
        let host = ManagedProcessHost::new("host", RuntimeLimits::default()).unwrap();
        assert!(matches!(
            resolve_helper(host.helper_path()),
            Err(PluginRuntimeError::ManagedHostUnavailable { .. })
        ));
    }

    #[test]
    fn closure_and_binary_share_one_snapshot_budget() {
        let advertised = 1_048_576;
        validate_snapshot_budget(400_000, 600_000, advertised).unwrap();
        assert!(matches!(
            validate_snapshot_budget(600_000, 600_000, advertised),
            Err(PluginRuntimeError::InvalidManagedContext(_))
        ));
        assert!(
            validate_snapshot_budget(16, 1, RuntimeLimits::default().advertised_max_memory_bytes)
                .is_ok()
        );
        assert!(matches!(
            validate_snapshot_budget(u64::MAX, 1, u64::MAX),
            Err(PluginRuntimeError::InvalidManagedContext(_))
        ));
    }

    #[test]
    fn post_child_drift_is_stage_attributed() {
        let temporary = TempDir::new().unwrap();
        let plugin_root = temporary.path().join("plugin");
        fs::create_dir(&plugin_root).unwrap();
        let assembly = plugin_root.join("Plugin.dll");
        fs::write(&assembly, b"approved").unwrap();
        let expected = fingerprint_plugin_directory(&plugin_root, FingerprintLimits::default())
            .unwrap()
            .fingerprint;
        let binary = temporary.path().join("input.exe");
        fs::write(&binary, b"M").unwrap();
        let image = image(b"M");

        fs::write(&assembly, b"changed").unwrap();
        let diagnostics = ProcessDiagnostics::default();
        assert!(matches!(
            verify_post_run_artifact(&plugin_root, expected, &diagnostics, false),
            Err(PluginRuntimeError::ManagedHostArtifactChanged { .. })
        ));
        assert!(matches!(
            verify_post_run_artifact(&plugin_root, expected, &diagnostics, true),
            Err(PluginRuntimeError::ManagedExecutionArtifactChanged { .. })
        ));

        fs::write(&assembly, b"approved").unwrap();
        fs::write(&binary, b"Z").unwrap();
        assert!(matches!(
            verify_post_child_binary(&binary, &image.identity, &diagnostics, false),
            Err(PluginRuntimeError::ManagedHostInputChanged { .. })
        ));
        assert!(matches!(
            verify_post_child_binary(&binary, &image.identity, &diagnostics, true),
            Err(PluginRuntimeError::ManagedExecutionInputChanged { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn fake_helper_receives_strict_input_and_cleans_up_descendants() {
        use resymbol_core::plugin_api::{PluginHealth, PluginHealthState};
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TempDir::new().unwrap();
        let helper = temporary.path().join("resymbol-managed-host");
        fs::write(
            &helper,
            concat!(
                "#!/bin/sh\n",
                "test \"$1\" = \"--plugin-root\" || exit 40\n",
                "root=$2\n",
                "test \"$3\" = \"--binary\" || exit 41\n",
                "test \"$PWD\" = \"$root\" || exit 42\n",
                "test -d \"$DOTNET_BUNDLE_EXTRACT_BASE_DIR\" || exit 43\n",
                "IFS= read -r bootstrap || exit 44\n",
                "IFS= read -r hello || exit 45\n",
                "IFS= read -r request || exit 46\n",
                "case \"$bootstrap\" in *'\"entry_assembly\":\"Plugin.dll\"'*'\"expected_artifact_sha256\"'*) ;; *) exit 47 ;; esac\n",
                "case \"$hello\" in *'\"kind\":\"hello\"'*) ;; *) exit 48 ;; esac\n",
                "case \"$request\" in *'\"method\":\"analyze\"'*) ;; *) exit 49 ;; esac\n",
                "printf '@resymbol-managed-host/load-attempted/v1@\\n' >&2\n",
                "( printf spawned > \"${0%/*}/managed-descendant-ready.marker\"; ",
                "/bin/sleep 2; printf survived > ",
                "\"${0%/*}/managed-descendant-survived.marker\" ) &\n",
                "while [ ! -f \"${0%/*}/managed-descendant-ready.marker\" ]; do :; done\n",
                "printf '%s\\n' '{\"protocol\":\"resymbol.plugin-wire\",\"version\":{\"major\":1,\"minor\":0},\"kind\":\"hello-result\",\"descriptor\":{\"id\":\"dev.resymbol.managed-test\",\"name\":\"Managed test\",\"version\":\"0.1.0\",\"capabilities\":[\"analyzer.binary\"],\"requested_permissions\":[\"binary.read\",\"claims.submit\"],\"isolation\":{\"mode\":\"process\",\"required\":true}}}'\n",
                "printf '%s\\n' '{\"protocol\":\"resymbol.plugin-wire\",\"version\":{\"major\":1,\"minor\":0},\"kind\":\"response\",\"direction\":\"plugin-to-host\",\"id\":\"request-1\",\"ok\":true,\"result\":null}'\n",
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&helper).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&helper, permissions).unwrap();

        let plugin_root = temporary.path().join("plugin");
        fs::create_dir(&plugin_root).unwrap();
        fs::write(plugin_root.join("Plugin.dll"), b"managed fixture").unwrap();
        let expected = fingerprint_plugin_directory(&plugin_root, FingerprintLimits::default())
            .unwrap()
            .fingerprint;
        let plugin = DiscoveredPlugin {
            source: PluginSource::Directory,
            path: plugin_root,
            manifest: Some(manifest("Plugin.dll")),
            health: PluginHealth::new(PluginHealthState::Enabled),
        };
        let binary = temporary.path().join("input.exe");
        fs::write(&binary, b"M").unwrap();
        let image = image(b"M");
        let host = ManagedProcessHost::new(
            &helper,
            RuntimeLimits::default().with_request_timeout(std::time::Duration::from_secs(1)),
        )
        .unwrap();

        let execution = host
            .execute_trusted(
                &plugin,
                &request(&image.identity),
                expected,
                &binary,
                &image,
            )
            .unwrap();
        assert_eq!(execution.response.id, "request-1");
        assert_eq!(execution.diagnostics.stderr, "");
        assert!(
            temporary
                .path()
                .join("managed-descendant-ready.marker")
                .is_file(),
            "managed helper did not spawn its descendant"
        );
        std::thread::sleep(std::time::Duration::from_secs(4));
        assert!(
            !temporary
                .path()
                .join("managed-descendant-survived.marker")
                .exists(),
            "managed completion cleanup left its descendant alive"
        );
    }
}
