use std::{
    fs::{self, File},
    io::Read as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

use resymbol_core::{
    BinaryFormat, BinaryIdentity, DiscoveredPlugin, PluginSource,
    plugin_api::{NativeIsolation, PluginManifest, PluginRuntime},
};
use resymbol_plugin_state::{ArtifactFingerprint, FingerprintLimits, fingerprint_plugin_directory};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    ExternalProcessRequest, PluginExecution, PluginRuntimeError, RuntimeLimits,
    host::{preserve_operating_system_environment, run_child_observing_stderr},
    wire::encode_input,
};

const NATIVE_HOST_PROTOCOL: &str = "resymbol.native-host";
const NATIVE_HOST_PROTOCOL_MAJOR: u32 = 1;
const NATIVE_HOST_PROTOCOL_MINOR: u32 = 0;
const MAX_NATIVE_BOOTSTRAP_BYTES: usize = 256 * 1024;
const MAX_NATIVE_PE_SECTIONS: usize = 96;
const HARD_MAX_NATIVE_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_NATIVE_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_NATIVE_ADVERTISED_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_NATIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
const MAX_NATIVE_IDENTIFIER_BYTES: usize = 128;
const MAX_NATIVE_GRANTED_PERMISSIONS: usize = 256;
const MAX_NATIVE_DESCRIPTOR_NAME_BYTES: usize = 4_096;
const MAX_NATIVE_DESCRIPTOR_VERSION_BYTES: usize = 128;
const MAX_NATIVE_DESCRIPTOR_IDENTIFIERS: usize = 4_096;
// Fixed contract with the trusted sibling helper. The marker is written and
// flushed immediately before its first platform loader call, then removed
// from captured diagnostics here before any result reaches a caller.
const NATIVE_HOST_LOAD_ATTEMPTED_MARKER: &str = "@resymbol-native-host/load-attempted/v1@\n";
// Stable contract with `resymbol-native-host`: 70 means the platform library
// loader was never called; 71 means it was called and plugin code may have run.
const NATIVE_HOST_PRE_LOAD_FAILURE_EXIT_CODE: i32 = 70;
const NATIVE_HOST_LOAD_ATTEMPTED_FAILURE_EXIT_CODE: i32 = 71;

/// One PE section mapping supplied to the disposable native helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativePeImageSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_offset: u32,
    pub raw_data_size: u32,
}

/// Exact binary identity and PE file-to-image mapping required by `binary.read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePeImage {
    pub identity: BinaryIdentity,
    pub size_of_headers: u32,
    pub size_of_image: u32,
    pub sections: Vec<NativePeImageSection>,
}

impl NativePeImage {
    pub fn new(
        identity: BinaryIdentity,
        size_of_headers: u32,
        size_of_image: u32,
        sections: Vec<NativePeImageSection>,
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

    /// Revalidate the identity and every file/image range before launching native code.
    pub fn validate(&self) -> Result<(), PluginRuntimeError> {
        self.identity
            .validate()
            .map_err(|error| invalid_context(error.to_string()))?;
        if !matches!(self.identity.format, BinaryFormat::Pe) {
            return Err(invalid_context(
                "the first native host accepts only PE binary maps",
            ));
        }
        if self.identity.architecture != "x86_64" {
            return Err(invalid_context(
                "the first native host accepts only x86_64 binary maps",
            ));
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
        if self.sections.len() > MAX_NATIVE_PE_SECTIONS {
            return Err(invalid_context(format!(
                "PE image map exceeds the {MAX_NATIVE_PE_SECTIONS}-section limit"
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

/// Bounded launcher for one native library in a disposable sibling helper process.
#[derive(Debug, Clone)]
pub struct NativeProcessHost {
    helper_path: PathBuf,
    limits: RuntimeLimits,
}

impl NativeProcessHost {
    pub fn new(
        helper_path: impl Into<PathBuf>,
        limits: RuntimeLimits,
    ) -> Result<Self, PluginRuntimeError> {
        validate_native_limits(&limits)?;
        let helper_path = helper_path.into();
        if helper_path.as_os_str().is_empty() {
            return Err(PluginRuntimeError::NativeHostUnavailable {
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

    /// Execute a discovered, explicitly trusted out-of-process native plugin.
    ///
    /// The caller must bind `expected_artifact` to host-owned trust state. This
    /// method independently verifies the exact source binary before launch,
    /// passes the expected plugin fingerprint to the helper, and fingerprints
    /// the plugin directory again after validated protocol output is received.
    pub fn execute_trusted(
        &self,
        plugin: &DiscoveredPlugin,
        request: &ExternalProcessRequest,
        expected_artifact: ArtifactFingerprint,
        exact_binary: &Path,
        image: &NativePeImage,
    ) -> Result<PluginExecution, PluginRuntimeError> {
        validate_native_limits(&self.limits)?;
        request.validate()?;
        validate_native_request(request)?;
        image.validate()?;
        let manifest = validate_native_plugin(plugin, request)?;
        validate_request_binary(request, &image.identity)?;

        let helper = resolve_helper(&self.helper_path)?;
        let plugin_root = resolve_plugin_root(plugin)?;
        let exact_binary = verify_exact_binary(exact_binary, &image.identity)?;
        let input = encode_native_input(manifest, request, image, expected_artifact, &self.limits)?;
        let deadline = Instant::now()
            .checked_add(self.limits.request_timeout)
            .ok_or(PluginRuntimeError::InvalidLimits(
                "request_timeout is too large for the platform clock",
            ))?;

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
            .env_clear();
        preserve_operating_system_environment(&mut command);
        let child = command
            .spawn()
            .map_err(|error| PluginRuntimeError::NativeHostUnavailable {
                path: helper.clone(),
                reason: error.to_string(),
            })?;
        let (child_result, observed_stderr) =
            run_child_observing_stderr(child, input, manifest, request, &self.limits, deadline);
        finish_native_child_result(
            child_result,
            &observed_stderr,
            &plugin_root,
            expected_artifact,
            &exact_binary,
            &image.identity,
        )
    }
}

fn validate_native_plugin<'a>(
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
    validate_native_descriptor_manifest_shape(manifest)?;
    match &manifest.runtime {
        PluginRuntime::Native {
            isolation: NativeIsolation::OutOfProcess,
            ..
        } => {}
        PluginRuntime::Native {
            isolation: NativeIsolation::InProcess,
            ..
        } => {
            return Err(invalid_context(
                "in-process native plugins are not supported by the disposable helper",
            ));
        }
        runtime => return Err(PluginRuntimeError::UnsupportedRuntime(runtime.kind())),
    }
    for permission in request.granted_permissions() {
        if !manifest.permissions.contains(permission) {
            return Err(PluginRuntimeError::PermissionNotRequested(
                permission.to_string(),
            ));
        }
    }
    Ok(manifest)
}

fn validate_native_descriptor_manifest_shape(
    manifest: &PluginManifest,
) -> Result<(), PluginRuntimeError> {
    if manifest.name.len() > MAX_NATIVE_DESCRIPTOR_NAME_BYTES {
        return Err(invalid_context(format!(
            "native plugin name exceeds the {MAX_NATIVE_DESCRIPTOR_NAME_BYTES}-byte descriptor limit"
        )));
    }
    if manifest.version.to_string().len() > MAX_NATIVE_DESCRIPTOR_VERSION_BYTES {
        return Err(invalid_context(format!(
            "native plugin version exceeds the {MAX_NATIVE_DESCRIPTOR_VERSION_BYTES}-byte descriptor limit"
        )));
    }
    if manifest.capabilities.len() > MAX_NATIVE_DESCRIPTOR_IDENTIFIERS {
        return Err(invalid_context(format!(
            "native plugin capabilities exceed the {MAX_NATIVE_DESCRIPTOR_IDENTIFIERS}-item descriptor limit"
        )));
    }
    if manifest.permissions.len() > MAX_NATIVE_DESCRIPTOR_IDENTIFIERS {
        return Err(invalid_context(format!(
            "native plugin permissions exceed the {MAX_NATIVE_DESCRIPTOR_IDENTIFIERS}-item descriptor limit"
        )));
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
        .ok_or_else(|| invalid_context("native analyze request is missing its binary identity"))?;
    let found = serde_json::from_value::<BinaryIdentity>(value.clone()).map_err(|error| {
        invalid_context(format!(
            "native analyze request has an invalid binary identity: {error}"
        ))
    })?;
    if &found != expected {
        return Err(invalid_context(
            "native analyze request binary identity does not match the PE image map",
        ));
    }
    Ok(())
}

fn validate_native_request(request: &ExternalProcessRequest) -> Result<(), PluginRuntimeError> {
    if request.method() != crate::PluginMethod::Analyze {
        return Err(invalid_context(
            "the first native host accepts only analyze requests",
        ));
    }
    if request.id().len() > MAX_NATIVE_IDENTIFIER_BYTES
        || request.session_id().len() > MAX_NATIVE_IDENTIFIER_BYTES
    {
        return Err(invalid_context(
            "native request and session identifiers must be at most 128 UTF-8 bytes",
        ));
    }
    if request.granted_permissions().len() > MAX_NATIVE_GRANTED_PERMISSIONS {
        return Err(invalid_context(
            "native request exceeds the 256-permission grant limit",
        ));
    }
    Ok(())
}

fn resolve_helper(path: &Path) -> Result<PathBuf, PluginRuntimeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| PluginRuntimeError::NativeHostUnavailable {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PluginRuntimeError::NativeHostUnavailable {
            path: path.to_path_buf(),
            reason: "helper must be a regular, unlinked file".to_owned(),
        });
    }
    fs::canonicalize(path).map_err(|error| PluginRuntimeError::NativeHostUnavailable {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

fn resolve_plugin_root(plugin: &DiscoveredPlugin) -> Result<PathBuf, PluginRuntimeError> {
    let metadata = fs::symlink_metadata(&plugin.path).map_err(|source| PluginRuntimeError::Io {
        operation: "inspect native plugin directory",
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PluginRuntimeError::PluginNotLoadable(
            "native plugin root must be a regular, unlinked directory".to_owned(),
        ));
    }
    fs::canonicalize(&plugin.path).map_err(|source| PluginRuntimeError::Io {
        operation: "resolve native plugin directory",
        source,
    })
}

fn verify_exact_binary(
    path: &Path,
    expected: &BinaryIdentity,
) -> Result<PathBuf, PluginRuntimeError> {
    let fail = |reason: String| PluginRuntimeError::NativeSourceBinary {
        path: path.to_path_buf(),
        reason,
    };
    if expected.size > HARD_MAX_NATIVE_BINARY_BYTES {
        return Err(fail(format!(
            "{} bytes exceed the native host's {HARD_MAX_NATIVE_BINARY_BYTES}-byte binary limit",
            expected.size
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| fail(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
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
    let observed_digest = encode_hex(&hasher.finalize());
    if observed_digest != expected.id.as_str() {
        return Err(fail(
            "source SHA-256 does not match the analysis identity".to_owned(),
        ));
    }
    let after = fs::symlink_metadata(&canonical).map_err(|error| fail(error.to_string()))?;
    if after.file_type().is_symlink() || !after.is_file() || after.len() != expected.size {
        return Err(fail(
            "source binary changed while it was verified".to_owned(),
        ));
    }
    Ok(canonical)
}

#[derive(Serialize)]
struct NativeBootstrap<'a> {
    protocol: &'static str,
    version: NativeProtocolVersion,
    expected_artifact_sha256: String,
    binary: &'a BinaryIdentity,
    image: NativeBootstrapImage<'a>,
    output_limits: NativeOutputLimits,
}

#[derive(Serialize)]
struct NativeProtocolVersion {
    major: u32,
    minor: u32,
}

#[derive(Serialize)]
struct NativeBootstrapImage<'a> {
    size_of_headers: u32,
    size_of_image: u32,
    sections: &'a [NativePeImageSection],
}

#[derive(Serialize)]
struct NativeOutputLimits {
    max_messages: usize,
    max_stdout_bytes: usize,
}

fn encode_native_input(
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    image: &NativePeImage,
    expected_artifact: ArtifactFingerprint,
    limits: &RuntimeLimits,
) -> Result<Vec<u8>, PluginRuntimeError> {
    let bootstrap = NativeBootstrap {
        protocol: NATIVE_HOST_PROTOCOL,
        version: NativeProtocolVersion {
            major: NATIVE_HOST_PROTOCOL_MAJOR,
            minor: NATIVE_HOST_PROTOCOL_MINOR,
        },
        expected_artifact_sha256: expected_artifact.to_hex(),
        binary: &image.identity,
        image: NativeBootstrapImage {
            size_of_headers: image.size_of_headers,
            size_of_image: image.size_of_image,
            sections: &image.sections,
        },
        output_limits: NativeOutputLimits {
            max_messages: limits.max_messages,
            max_stdout_bytes: limits.max_stdout_bytes,
        },
    };
    let bootstrap =
        serde_json::to_vec(&bootstrap).map_err(PluginRuntimeError::EncodeNativeBootstrap)?;
    if bootstrap.len() > MAX_NATIVE_BOOTSTRAP_BYTES {
        return Err(invalid_context(format!(
            "native-host bootstrap exceeds its {MAX_NATIVE_BOOTSTRAP_BYTES}-byte limit"
        )));
    }
    let wire = encode_input(manifest, request, limits)?;
    let total = bootstrap
        .len()
        .checked_add(1)
        .and_then(|size| size.checked_add(wire.len()))
        .ok_or_else(|| invalid_context("native-host input size overflows this platform"))?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(total)
        .map_err(|_| invalid_context("cannot reserve native-host input buffer"))?;
    input.extend_from_slice(&bootstrap);
    input.push(b'\n');
    input.extend_from_slice(&wire);
    Ok(input)
}

fn verify_post_run_artifact(
    plugin_root: &Path,
    expected: ArtifactFingerprint,
    diagnostics: &crate::ProcessDiagnostics,
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
    diagnostics: &crate::ProcessDiagnostics,
    load_attempted: bool,
) -> PluginRuntimeError {
    if load_attempted {
        PluginRuntimeError::PluginArtifactChanged {
            reason,
            diagnostics: diagnostics.clone(),
        }
    } else {
        PluginRuntimeError::NativeHostArtifactChanged {
            reason,
            diagnostics: diagnostics.clone(),
        }
    }
}

fn child_result_diagnostics(
    result: &Result<PluginExecution, PluginRuntimeError>,
) -> crate::ProcessDiagnostics {
    match result {
        Ok(execution) => execution.diagnostics.clone(),
        Err(error) => error.diagnostics().cloned().unwrap_or_default(),
    }
}

fn finish_native_child_result(
    mut result: Result<PluginExecution, PluginRuntimeError>,
    observed_stderr: &[u8],
    plugin_root: &Path,
    expected_artifact: ArtifactFingerprint,
    exact_binary: &Path,
    expected_binary: &BinaryIdentity,
) -> Result<PluginExecution, PluginRuntimeError> {
    let load_attempted = observed_stderr.starts_with(NATIVE_HOST_LOAD_ATTEMPTED_MARKER.as_bytes());
    let _diagnostic_marker_was_stripped = strip_native_load_attempted_marker(&mut result);
    let diagnostics = child_result_diagnostics(&result);

    // Integrity failures take precedence over child attribution. These checks
    // run after every completed, failed, timed-out, or crashed child result,
    // before any claims or plugin-fault decision can escape.
    verify_post_run_artifact(plugin_root, expected_artifact, &diagnostics, load_attempted)?;
    verify_post_child_binary(exact_binary, expected_binary, &diagnostics, load_attempted)?;
    classify_native_child_result(result, load_attempted)
}

fn strip_native_load_attempted_marker(
    result: &mut Result<PluginExecution, PluginRuntimeError>,
) -> bool {
    let diagnostics = match result {
        Ok(execution) => &mut execution.diagnostics,
        Err(error) => {
            let Some(diagnostics) = error.diagnostics_mut() else {
                return false;
            };
            diagnostics
        }
    };
    if !diagnostics
        .stderr
        .starts_with(NATIVE_HOST_LOAD_ATTEMPTED_MARKER)
    {
        return false;
    }
    diagnostics
        .stderr
        .drain(..NATIVE_HOST_LOAD_ATTEMPTED_MARKER.len());
    true
}

fn verify_post_child_binary(
    exact_binary: &Path,
    expected_binary: &BinaryIdentity,
    diagnostics: &crate::ProcessDiagnostics,
    load_attempted: bool,
) -> Result<(), PluginRuntimeError> {
    match verify_exact_binary(exact_binary, expected_binary) {
        Ok(_canonical) => Ok(()),
        Err(PluginRuntimeError::NativeSourceBinary { path, reason }) if load_attempted => {
            Err(PluginRuntimeError::NativeExecutionInputChanged {
                path,
                reason,
                diagnostics: diagnostics.clone(),
            })
        }
        Err(PluginRuntimeError::NativeSourceBinary { path, reason }) => {
            Err(PluginRuntimeError::NativeHostInputChanged {
                path,
                reason,
                diagnostics: diagnostics.clone(),
            })
        }
        Err(error) => Err(error),
    }
}

fn classify_native_child_result(
    result: Result<PluginExecution, PluginRuntimeError>,
    load_attempted: bool,
) -> Result<PluginExecution, PluginRuntimeError> {
    if load_attempted {
        return result;
    }

    // Missing the current, trusted marker is authoritative for every outcome,
    // including a stale helper that exits successfully, a signal/exception,
    // timeout, worker failure, or an unknown graceful code. Codes 70 and 71
    // remain useful compatibility/sanity signals, but never override marker
    // presence or absence.
    let code = match &result {
        Ok(execution) => execution.exit_code,
        Err(PluginRuntimeError::ProcessFailed { code, .. })
        | Err(PluginRuntimeError::NativeHostFailed { code, .. }) => *code,
        Err(_) => None,
    };
    let reason = native_host_failure_reason(&result, code);
    let diagnostics = child_result_diagnostics(&result);
    Err(PluginRuntimeError::NativeHostFailed {
        code,
        reason,
        diagnostics,
    })
}

fn native_host_failure_reason(
    result: &Result<PluginExecution, PluginRuntimeError>,
    code: Option<i32>,
) -> String {
    let reason = match result {
        Ok(_) => {
            "helper returned protocol success without the current load-attempted marker"
                .to_owned()
        }
        Err(PluginRuntimeError::NativeHostFailed { reason, .. }) => reason.clone(),
        Err(PluginRuntimeError::ProcessFailed { .. }) => match code {
            Some(NATIVE_HOST_PRE_LOAD_FAILURE_EXIT_CODE) => {
                "helper reported its compatible pre-load failure code without the current marker"
                    .to_owned()
            }
            Some(NATIVE_HOST_LOAD_ATTEMPTED_FAILURE_EXIT_CODE) => {
                "helper reported its load-attempted failure code without the required current marker"
                    .to_owned()
            }
            Some(code) => format!(
                "helper exited with code {code} before emitting the current load-attempted marker"
            ),
            None => {
                "helper terminated without an exit code before emitting the current load-attempted marker"
                    .to_owned()
            }
        },
        Err(error) => error.to_string(),
    };
    bounded_native_host_reason(&reason)
}

fn bounded_native_host_reason(reason: &str) -> String {
    const LIMIT: usize = 4_096;
    const SUFFIX: &str = "...";
    if reason.len() <= LIMIT {
        return reason.to_owned();
    }
    let boundary = LIMIT - SUFFIX.len();
    let end = reason
        .char_indices()
        .map(|(index, _character)| index)
        .take_while(|index| *index <= boundary)
        .last()
        .unwrap_or(0);
    format!("{}{SUFFIX}", &reason[..end])
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
    PluginRuntimeError::InvalidNativeContext(message.into())
}

fn validate_native_limits(limits: &RuntimeLimits) -> Result<(), PluginRuntimeError> {
    limits.validate()?;
    if limits.max_messages < 2 {
        return Err(PluginRuntimeError::InvalidLimits(
            "native-host max_messages must reserve hello-result and response",
        ));
    }
    if limits.max_stderr_bytes < NATIVE_HOST_LOAD_ATTEMPTED_MARKER.len() {
        return Err(PluginRuntimeError::InvalidLimits(
            "native-host max_stderr_bytes must fit the load-attempted marker",
        ));
    }
    if limits.max_message_bytes > MAX_NATIVE_MESSAGE_BYTES {
        return Err(PluginRuntimeError::InvalidLimits(
            "native-host max_message_bytes must not exceed 67108864",
        ));
    }
    if limits.advertised_max_memory_bytes > MAX_NATIVE_ADVERTISED_MEMORY_BYTES {
        return Err(PluginRuntimeError::InvalidLimits(
            "native-host advertised_max_memory_bytes must not exceed 68719476736",
        ));
    }
    if limits.request_timeout > MAX_NATIVE_TIMEOUT {
        return Err(PluginRuntimeError::InvalidLimits(
            "native-host request_timeout must not exceed 24 hours",
        ));
    }
    Ok(())
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
        plugin_api::{
            MANIFEST_VERSION, PluginCapability, PluginHealth, PluginHealthState, PluginId,
            PluginPermission,
        },
    };
    use semver::{Version, VersionReq};
    use serde_json::{Map, Value};
    use tempfile::TempDir;

    use super::*;
    use crate::{PluginDescriptor, PluginMethod, PluginResponse, ProcessDiagnostics};

    fn image(bytes: &[u8]) -> NativePeImage {
        NativePeImage::new(
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

    fn manifest(runtime: PluginRuntime) -> PluginManifest {
        PluginManifest {
            manifest_version: MANIFEST_VERSION,
            id: PluginId::new("dev.resymbol.native-test").unwrap(),
            name: "Native test".to_owned(),
            version: Version::new(0, 1, 0),
            api: VersionReq::parse("^0.1").unwrap(),
            runtime,
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

    fn test_diagnostics(marked: bool, detail: &str) -> ProcessDiagnostics {
        ProcessDiagnostics {
            stderr: format!(
                "{}{detail}",
                if marked {
                    NATIVE_HOST_LOAD_ATTEMPTED_MARKER
                } else {
                    ""
                }
            ),
            stderr_was_lossy: false,
        }
    }

    fn failed_result(
        code: Option<i32>,
        marked: bool,
    ) -> Result<PluginExecution, PluginRuntimeError> {
        Err(PluginRuntimeError::ProcessFailed {
            code,
            diagnostics: test_diagnostics(marked, "bounded helper detail"),
        })
    }

    fn successful_result(marked: bool) -> Result<PluginExecution, PluginRuntimeError> {
        Ok(PluginExecution {
            descriptor: PluginDescriptor {
                id: "dev.resymbol.native-test".to_owned(),
                name: "Native test".to_owned(),
                version: "0.1.0".to_owned(),
                capabilities: vec![PluginCapability::ANALYZER_BINARY.to_owned()],
                requested_permissions: Vec::new(),
            },
            response: PluginResponse {
                id: "request-1".to_owned(),
                result: Value::Null,
            },
            claims: Vec::new(),
            logs: Vec::new(),
            diagnostics: test_diagnostics(marked, "bounded helper detail"),
            exit_code: Some(0),
        })
    }

    fn classify_test_result(
        mut result: Result<PluginExecution, PluginRuntimeError>,
    ) -> Result<PluginExecution, PluginRuntimeError> {
        let load_attempted = strip_native_load_attempted_marker(&mut result);
        classify_native_child_result(result, load_attempted)
    }

    #[test]
    fn image_map_rejects_overlapping_sections() {
        let bytes = vec![0_u8; 0x500];
        let identity = BinaryIdentity {
            id: BinaryId::digest(&bytes),
            size: bytes.len() as u64,
            format: BinaryFormat::Pe,
            architecture: "x86_64".to_owned(),
            image_base: 0x0001_4000_0000,
        };
        let section = |virtual_address, raw_data_offset| NativePeImageSection {
            virtual_address,
            virtual_size: 0x200,
            raw_data_offset,
            raw_data_size: 0x200,
        };
        let error = NativePeImage::new(
            identity,
            0x100,
            0x3000,
            vec![section(0x1000, 0x100), section(0x1100, 0x300)],
        )
        .unwrap_err();
        assert!(error.to_string().contains("overlapping virtual"));
    }

    #[test]
    fn native_input_prefixes_strict_bootstrap_and_preserves_wire_messages() {
        let bytes = b"M";
        let image = image(bytes);
        let manifest = manifest(PluginRuntime::Native {
            entrypoint: PathBuf::from("plugin.dll"),
            isolation: NativeIsolation::OutOfProcess,
        });
        let request = request(&image.identity);
        let limits = RuntimeLimits::default().with_max_messages(123);
        let fingerprint = ArtifactFingerprint::from_str(&"11".repeat(32)).unwrap();
        let input = encode_native_input(&manifest, &request, &image, fingerprint, &limits).unwrap();
        let lines = input
            .strip_suffix(b"\n")
            .unwrap()
            .split(|byte| *byte == b'\n')
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        let bootstrap = serde_json::from_slice::<Value>(lines[0]).unwrap();
        assert_eq!(bootstrap["protocol"], NATIVE_HOST_PROTOCOL);
        assert_eq!(bootstrap["output_limits"]["max_messages"], 123);
        assert_eq!(
            bootstrap["output_limits"]["max_stdout_bytes"],
            limits.max_stdout_bytes
        );
        let hello = serde_json::from_slice::<Value>(lines[1]).unwrap();
        let wire_request = serde_json::from_slice::<Value>(lines[2]).unwrap();
        assert_eq!(hello["kind"], "hello");
        assert_eq!(wire_request["kind"], "request");
    }

    #[test]
    fn native_limits_reserve_handshake_and_response_messages() {
        let error = NativeProcessHost::new(
            "resymbol-native-host",
            RuntimeLimits::default().with_max_messages(1),
        )
        .unwrap_err();
        assert!(matches!(error, PluginRuntimeError::InvalidLimits(_)));
        assert!(error.to_string().contains("hello-result and response"));
    }

    #[test]
    fn native_limits_match_the_helpers_bounded_wire_contract() {
        let oversized_message = RuntimeLimits {
            max_message_bytes: MAX_NATIVE_MESSAGE_BYTES + 1,
            max_stdout_bytes: MAX_NATIVE_MESSAGE_BYTES + 1,
            ..RuntimeLimits::default()
        };
        assert!(NativeProcessHost::new("host", oversized_message).is_err());

        let oversized_memory = RuntimeLimits {
            advertised_max_memory_bytes: MAX_NATIVE_ADVERTISED_MEMORY_BYTES + 1,
            ..RuntimeLimits::default()
        };
        assert!(NativeProcessHost::new("host", oversized_memory).is_err());

        let marker_too_large_for_stderr = RuntimeLimits {
            max_stderr_bytes: NATIVE_HOST_LOAD_ATTEMPTED_MARKER.len() - 1,
            ..RuntimeLimits::default()
        };
        assert!(NativeProcessHost::new("host", marker_too_large_for_stderr).is_err());

        let exact_marker_stderr = RuntimeLimits {
            max_stderr_bytes: NATIVE_HOST_LOAD_ATTEMPTED_MARKER.len(),
            ..RuntimeLimits::default()
        };
        assert!(NativeProcessHost::new("host", exact_marker_stderr).is_ok());

        let oversized_timeout = RuntimeLimits::default()
            .with_request_timeout(MAX_NATIVE_TIMEOUT + std::time::Duration::from_millis(1));
        assert!(NativeProcessHost::new("host", oversized_timeout).is_err());
    }

    #[test]
    fn native_request_shape_is_rejected_before_helper_launch() {
        let image = image(b"M");
        let long = "x".repeat(MAX_NATIVE_IDENTIFIER_BYTES + 1);
        let long_request = ExternalProcessRequest::new(
            long,
            "session",
            PluginMethod::Analyze,
            Map::from_iter([(
                "binary".to_owned(),
                serde_json::to_value(&image.identity).unwrap(),
            )]),
        )
        .unwrap();
        assert!(validate_native_request(&long_request).is_err());

        let health =
            ExternalProcessRequest::new("request", "session", PluginMethod::Health, Map::new())
                .unwrap();
        assert!(validate_native_request(&health).is_err());
    }

    #[test]
    fn exact_binary_preflight_rejects_changed_bytes() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("input.exe");
        fs::write(&path, b"M").unwrap();
        let image = image(b"M");
        assert!(verify_exact_binary(&path, &image.identity).is_ok());

        fs::write(&path, b"Z").unwrap();
        let error = verify_exact_binary(&path, &image.identity).unwrap_err();
        assert!(matches!(
            error,
            PluginRuntimeError::NativeSourceBinary { .. }
        ));
        assert!(error.to_string().contains("SHA-256"));
    }

    #[test]
    fn exact_binary_preflight_uses_the_explicit_hard_source_limit() {
        let temporary = TempDir::new().unwrap();
        let missing = temporary.path().join("oversized.exe");
        let identity = BinaryIdentity {
            id: BinaryId::digest(b"not materialized"),
            size: HARD_MAX_NATIVE_BINARY_BYTES + 1,
            format: BinaryFormat::Pe,
            architecture: "x86_64".to_owned(),
            image_base: 0x0001_4000_0000,
        };
        let error = verify_exact_binary(&missing, &identity).unwrap_err();
        assert!(matches!(
            error,
            PluginRuntimeError::NativeSourceBinary { .. }
        ));
        assert!(
            error
                .to_string()
                .contains(&HARD_MAX_NATIVE_BINARY_BYTES.to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn helper_and_binary_symlinks_are_rejected_before_spawn() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let target = temporary.path().join("target");
        let linked = temporary.path().join("linked");
        fs::write(&target, b"M").unwrap();
        symlink(&target, &linked).unwrap();
        assert!(matches!(
            resolve_helper(&linked),
            Err(PluginRuntimeError::NativeHostUnavailable { .. })
        ));
        let image = image(b"M");
        assert!(matches!(
            verify_exact_binary(&linked, &image.identity),
            Err(PluginRuntimeError::NativeSourceBinary { .. })
        ));
    }

    #[test]
    fn native_validator_rejects_in_process_manifests() {
        let temporary = TempDir::new().unwrap();
        let mut manifest = manifest(PluginRuntime::Native {
            entrypoint: PathBuf::from("plugin.dll"),
            isolation: NativeIsolation::InProcess,
        });
        manifest
            .permissions
            .insert(PluginPermission::new(PluginPermission::UNSAFE_IN_PROCESS).unwrap());
        let image = image(b"M");
        let plugin = DiscoveredPlugin {
            source: PluginSource::Directory,
            path: temporary.path().to_path_buf(),
            manifest: Some(manifest),
            health: PluginHealth::new(PluginHealthState::Enabled),
        };
        let error = validate_native_plugin(&plugin, &request(&image.identity)).unwrap_err();
        assert!(matches!(error, PluginRuntimeError::InvalidNativeContext(_)));
        assert!(error.to_string().contains("in-process"));
    }

    #[test]
    fn native_descriptor_manifest_bounds_match_the_helper_contract() {
        let runtime = || PluginRuntime::Native {
            entrypoint: PathBuf::from("plugin.dll"),
            isolation: NativeIsolation::OutOfProcess,
        };

        let mut named = manifest(runtime());
        named.name = "x".repeat(MAX_NATIVE_DESCRIPTOR_NAME_BYTES);
        assert!(validate_native_descriptor_manifest_shape(&named).is_ok());
        named.name.push('x');
        assert!(validate_native_descriptor_manifest_shape(&named).is_err());

        let mut versioned = manifest(runtime());
        let boundary_version = format!("1.0.0-{}", "a".repeat(122));
        assert_eq!(boundary_version.len(), MAX_NATIVE_DESCRIPTOR_VERSION_BYTES);
        versioned.version = Version::parse(&boundary_version).unwrap();
        assert!(validate_native_descriptor_manifest_shape(&versioned).is_ok());
        versioned.version = Version::parse(&format!("{boundary_version}a")).unwrap();
        assert!(validate_native_descriptor_manifest_shape(&versioned).is_err());

        let mut capabilities = manifest(runtime());
        capabilities.capabilities = (0..MAX_NATIVE_DESCRIPTOR_IDENTIFIERS)
            .map(|index| PluginCapability::new(format!("test.capability{index}")).unwrap())
            .collect();
        assert!(validate_native_descriptor_manifest_shape(&capabilities).is_ok());
        capabilities.capabilities.insert(
            PluginCapability::new(format!(
                "test.capability{MAX_NATIVE_DESCRIPTOR_IDENTIFIERS}"
            ))
            .unwrap(),
        );
        assert!(validate_native_descriptor_manifest_shape(&capabilities).is_err());

        let mut permissions = manifest(runtime());
        permissions.permissions = (0..MAX_NATIVE_DESCRIPTOR_IDENTIFIERS)
            .map(|index| PluginPermission::new(format!("test.permission{index}")).unwrap())
            .collect();
        assert!(validate_native_descriptor_manifest_shape(&permissions).is_ok());
        permissions.permissions.insert(
            PluginPermission::new(format!(
                "test.permission{MAX_NATIVE_DESCRIPTOR_IDENTIFIERS}"
            ))
            .unwrap(),
        );
        assert!(validate_native_descriptor_manifest_shape(&permissions).is_err());

        let temporary = TempDir::new().unwrap();
        let plugin = DiscoveredPlugin {
            source: PluginSource::Directory,
            path: temporary.path().to_path_buf(),
            manifest: Some(named),
            health: PluginHealth::new(PluginHealthState::Enabled),
        };
        let image = image(b"M");
        assert!(matches!(
            validate_native_plugin(&plugin, &request(&image.identity)),
            Err(PluginRuntimeError::InvalidNativeContext(_))
        ));
    }

    #[test]
    fn post_run_fingerprint_drift_discards_the_execution_and_keeps_diagnostics() {
        let temporary = TempDir::new().unwrap();
        let plugin_root = temporary.path().join("plugin");
        fs::create_dir(&plugin_root).unwrap();
        let artifact = plugin_root.join("plugin.bin");
        fs::write(&artifact, b"approved").unwrap();
        let expected = fingerprint_plugin_directory(&plugin_root, FingerprintLimits::default())
            .unwrap()
            .fingerprint;
        fs::write(&artifact, b"changed").unwrap();

        let execution = PluginExecution {
            descriptor: PluginDescriptor {
                id: "dev.resymbol.native-test".to_owned(),
                name: "Native test".to_owned(),
                version: "0.1.0".to_owned(),
                capabilities: vec![PluginCapability::ANALYZER_BINARY.to_owned()],
                requested_permissions: Vec::new(),
            },
            response: PluginResponse {
                id: "request-1".to_owned(),
                result: Value::Null,
            },
            claims: Vec::new(),
            logs: Vec::new(),
            diagnostics: ProcessDiagnostics {
                stderr: "bounded helper detail".to_owned(),
                stderr_was_lossy: false,
            },
            exit_code: Some(0),
        };
        let error = verify_post_run_artifact(&plugin_root, expected, &execution.diagnostics, true)
            .unwrap_err();
        assert!(matches!(
            error,
            PluginRuntimeError::PluginArtifactChanged { .. }
        ));
        assert_eq!(error.diagnostics().unwrap(), &execution.diagnostics);
    }

    #[test]
    fn native_helper_marker_is_authoritative_across_exit_statuses() {
        let pre_load = classify_test_result(failed_result(
            Some(NATIVE_HOST_PRE_LOAD_FAILURE_EXIT_CODE),
            false,
        ))
        .unwrap_err();
        assert!(matches!(
            pre_load,
            PluginRuntimeError::NativeHostFailed {
                code: Some(NATIVE_HOST_PRE_LOAD_FAILURE_EXIT_CODE),
                ..
            }
        ));
        assert_eq!(
            pre_load.diagnostics().unwrap().stderr,
            "bounded helper detail"
        );
        assert!(pre_load.to_string().contains("pre-load failure code"));

        let unknown = classify_test_result(failed_result(Some(1), false)).unwrap_err();
        assert!(matches!(
            unknown,
            PluginRuntimeError::NativeHostFailed { code: Some(1), .. }
        ));
        assert!(unknown.to_string().contains("code 1 before emitting"));

        const WINDOWS_ACCESS_VIOLATION: i32 = 0xC000_0005_u32 as i32;
        assert!(matches!(
            classify_test_result(failed_result(Some(WINDOWS_ACCESS_VIOLATION), false)).unwrap_err(),
            PluginRuntimeError::NativeHostFailed {
                code: Some(WINDOWS_ACCESS_VIOLATION),
                ..
            }
        ));

        assert!(matches!(
            classify_test_result(failed_result(
                Some(NATIVE_HOST_LOAD_ATTEMPTED_FAILURE_EXIT_CODE),
                true,
            ))
            .unwrap_err(),
            PluginRuntimeError::ProcessFailed {
                code: Some(NATIVE_HOST_LOAD_ATTEMPTED_FAILURE_EXIT_CODE),
                ..
            }
        ));
        assert!(matches!(
            classify_test_result(failed_result(Some(WINDOWS_ACCESS_VIOLATION), true)).unwrap_err(),
            PluginRuntimeError::ProcessFailed {
                code: Some(WINDOWS_ACCESS_VIOLATION),
                ..
            }
        ));
        assert!(matches!(
            classify_test_result(failed_result(
                Some(NATIVE_HOST_PRE_LOAD_FAILURE_EXIT_CODE),
                true,
            ))
            .unwrap_err(),
            PluginRuntimeError::ProcessFailed {
                code: Some(NATIVE_HOST_PRE_LOAD_FAILURE_EXIT_CODE),
                ..
            }
        ));
        assert!(matches!(
            classify_test_result(failed_result(None, true)).unwrap_err(),
            PluginRuntimeError::ProcessFailed { code: None, .. }
        ));
    }

    #[test]
    fn marker_is_stripped_once_and_success_requires_it() {
        let success = classify_test_result(successful_result(true)).unwrap();
        assert_eq!(success.diagnostics.stderr, "bounded helper detail");

        let stale_success = classify_test_result(successful_result(false)).unwrap_err();
        assert!(matches!(
            stale_success,
            PluginRuntimeError::NativeHostFailed { code: Some(0), .. }
        ));
        assert!(stale_success.to_string().contains("protocol success"));

        let mut repeated = failed_result(Some(71), true).unwrap_err();
        repeated.diagnostics_mut().unwrap().stderr.insert_str(
            NATIVE_HOST_LOAD_ATTEMPTED_MARKER.len(),
            NATIVE_HOST_LOAD_ATTEMPTED_MARKER,
        );
        let mut repeated = Err(repeated);
        assert!(strip_native_load_attempted_marker(&mut repeated));
        assert_eq!(
            repeated.unwrap_err().diagnostics().unwrap().stderr,
            format!("{NATIVE_HOST_LOAD_ATTEMPTED_MARKER}bounded helper detail")
        );
    }

    #[test]
    fn timeout_and_protocol_errors_follow_marker_and_keep_clean_diagnostics() {
        let timeout = |marked| {
            classify_test_result(Err(PluginRuntimeError::Timeout {
                timeout: std::time::Duration::from_millis(17),
                diagnostics: test_diagnostics(marked, "timeout detail"),
            }))
            .unwrap_err()
        };
        let host_timeout = timeout(false);
        assert!(matches!(
            host_timeout,
            PluginRuntimeError::NativeHostFailed { code: None, .. }
        ));
        assert!(host_timeout.to_string().contains("17 ms deadline"));
        assert_eq!(host_timeout.diagnostics().unwrap().stderr, "timeout detail");

        let plugin_timeout = timeout(true);
        assert!(matches!(plugin_timeout, PluginRuntimeError::Timeout { .. }));
        assert_eq!(
            plugin_timeout.diagnostics().unwrap().stderr,
            "timeout detail"
        );

        let protocol = classify_test_result(Err(PluginRuntimeError::Protocol {
            line: 1,
            message: "bad response".to_owned(),
            diagnostics: test_diagnostics(true, "protocol detail"),
        }))
        .unwrap_err();
        assert!(matches!(protocol, PluginRuntimeError::Protocol { .. }));
        assert_eq!(protocol.diagnostics().unwrap().stderr, "protocol detail");
    }

    #[test]
    fn out_of_band_stage_keeps_diagnosticless_errors_attributable() {
        let marked = classify_native_child_result(
            Err(PluginRuntimeError::WorkerPanicked("native stderr worker")),
            true,
        )
        .unwrap_err();
        assert!(matches!(marked, PluginRuntimeError::WorkerPanicked(_)));

        let unmarked = classify_native_child_result(
            Err(PluginRuntimeError::WorkerPanicked("native stderr worker")),
            false,
        )
        .unwrap_err();
        assert!(matches!(
            unmarked,
            PluginRuntimeError::NativeHostFailed {
                code: None,
                ref reason,
                ..
            } if reason.contains("native stderr worker")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn hanging_marked_helper_retains_marker_before_descendant_pipe_eof() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TempDir::new().unwrap();
        let helper = temporary.path().join("fake-native-host");
        fs::write(
            &helper,
            "#!/bin/sh\nprintf '@resymbol-native-host/load-attempted/v1@\\n' >&2\n/bin/sleep 1 &\nwait\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&helper).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&helper, permissions).unwrap();

        let plugin_root = temporary.path().join("plugin");
        fs::create_dir(&plugin_root).unwrap();
        fs::write(plugin_root.join("plugin.bin"), b"fixture").unwrap();
        let expected_artifact =
            fingerprint_plugin_directory(&plugin_root, FingerprintLimits::default())
                .unwrap()
                .fingerprint;
        let plugin = DiscoveredPlugin {
            source: PluginSource::Directory,
            path: plugin_root,
            manifest: Some(manifest(PluginRuntime::Native {
                entrypoint: PathBuf::from("plugin.bin"),
                isolation: NativeIsolation::OutOfProcess,
            })),
            health: PluginHealth::new(PluginHealthState::Enabled),
        };
        let binary = temporary.path().join("input.exe");
        fs::write(&binary, b"M").unwrap();
        let image = image(b"M");
        let host = NativeProcessHost::new(
            &helper,
            RuntimeLimits::default().with_request_timeout(std::time::Duration::from_millis(100)),
        )
        .unwrap();

        let error = host
            .execute_trusted(
                &plugin,
                &request(&image.identity),
                expected_artifact,
                &binary,
                &image,
            )
            .unwrap_err();
        assert!(matches!(error, PluginRuntimeError::Timeout { .. }));
        assert_eq!(error.diagnostics().unwrap().stderr, "");
    }

    #[test]
    fn post_child_integrity_drift_takes_precedence_over_plugin_attribution() {
        let temporary = TempDir::new().unwrap();
        let plugin_root = temporary.path().join("plugin");
        fs::create_dir(&plugin_root).unwrap();
        let artifact = plugin_root.join("plugin.bin");
        fs::write(&artifact, b"approved").unwrap();
        let expected_artifact =
            fingerprint_plugin_directory(&plugin_root, FingerprintLimits::default())
                .unwrap()
                .fingerprint;
        let binary = temporary.path().join("input.exe");
        fs::write(&binary, b"M").unwrap();
        let image = image(b"M");
        let drift_failure = |code, marked| {
            Err(PluginRuntimeError::ProcessFailed {
                code: Some(code),
                diagnostics: test_diagnostics(marked, "plugin may have run"),
            })
        };

        fs::write(&artifact, b"changed").unwrap();
        let artifact_error = finish_native_child_result(
            drift_failure(NATIVE_HOST_LOAD_ATTEMPTED_FAILURE_EXIT_CODE, true),
            NATIVE_HOST_LOAD_ATTEMPTED_MARKER.as_bytes(),
            &plugin_root,
            expected_artifact,
            &binary,
            &image.identity,
        )
        .unwrap_err();
        assert!(matches!(
            artifact_error,
            PluginRuntimeError::PluginArtifactChanged { .. }
        ));

        let pre_load_artifact_error = finish_native_child_result(
            drift_failure(NATIVE_HOST_PRE_LOAD_FAILURE_EXIT_CODE, false),
            b"",
            &plugin_root,
            expected_artifact,
            &binary,
            &image.identity,
        )
        .unwrap_err();
        assert!(matches!(
            pre_load_artifact_error,
            PluginRuntimeError::NativeHostArtifactChanged { .. }
        ));
        assert!(pre_load_artifact_error.diagnostics().is_some());

        fs::write(&artifact, b"approved").unwrap();
        fs::write(&binary, b"Z").unwrap();
        let load_attempted_error = finish_native_child_result(
            drift_failure(NATIVE_HOST_LOAD_ATTEMPTED_FAILURE_EXIT_CODE, true),
            NATIVE_HOST_LOAD_ATTEMPTED_MARKER.as_bytes(),
            &plugin_root,
            expected_artifact,
            &binary,
            &image.identity,
        )
        .unwrap_err();
        assert!(matches!(
            load_attempted_error,
            PluginRuntimeError::NativeExecutionInputChanged { .. }
        ));
        assert!(load_attempted_error.diagnostics().is_some());

        let successful_execution = PluginExecution {
            descriptor: PluginDescriptor {
                id: "dev.resymbol.native-test".to_owned(),
                name: "Native test".to_owned(),
                version: "0.1.0".to_owned(),
                capabilities: vec![PluginCapability::ANALYZER_BINARY.to_owned()],
                requested_permissions: Vec::new(),
            },
            response: PluginResponse {
                id: "request-1".to_owned(),
                result: Value::Null,
            },
            claims: Vec::new(),
            logs: Vec::new(),
            diagnostics: test_diagnostics(true, "success diagnostics"),
            exit_code: Some(0),
        };
        let success_error = finish_native_child_result(
            Ok(successful_execution),
            NATIVE_HOST_LOAD_ATTEMPTED_MARKER.as_bytes(),
            &plugin_root,
            expected_artifact,
            &binary,
            &image.identity,
        )
        .unwrap_err();
        assert!(matches!(
            success_error,
            PluginRuntimeError::NativeExecutionInputChanged { .. }
        ));

        let pre_load_error = finish_native_child_result(
            drift_failure(NATIVE_HOST_PRE_LOAD_FAILURE_EXIT_CODE, false),
            b"",
            &plugin_root,
            expected_artifact,
            &binary,
            &image.identity,
        )
        .unwrap_err();
        assert!(matches!(
            pre_load_error,
            PluginRuntimeError::NativeHostInputChanged { .. }
        ));
        assert!(pre_load_error.diagnostics().is_some());
    }
}
