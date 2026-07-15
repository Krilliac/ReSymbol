use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    mem::ManuallyDrop,
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::ffi::OsStr;

use libloading::Library;
use resymbol_plugin_api::{
    NativeIsolation, PLUGIN_API_VERSION, PluginCapability, PluginManifest, PluginPermission,
    PluginRuntime,
};
use resymbol_plugin_state::{ArtifactFingerprint, FingerprintLimits, fingerprint_plugin_directory};
use semver::Version;

use crate::{
    abi::{
        self, ByteView, ISOLATION_OUT_OF_PROCESS, ISOLATION_TRUSTED_IN_PROCESS_ALLOWED,
        PluginApiV1, PluginDescriptorV1, PluginGetApiFn, STATUS_CANCELLED, STATUS_INCOMPATIBLE_ABI,
        STATUS_INVALID_ARGUMENT, STATUS_OK, STATUS_PERMISSION_DENIED, STATUS_RESOURCE_LIMIT,
        STATUS_UNAVAILABLE,
    },
    bootstrap::HostInput,
    callbacks::{CallbackContext, CallbackPhase, validate_grants},
    error::HostError,
    image::ExactBinaryImage,
    output::{NativeExecution, PluginRejection, ValidatedDescriptor},
};

const MANIFEST_FILE: &str = "plugin.toml";
const DISABLED_SENTINEL: &str = "plugin.disabled";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_DESCRIPTOR_ID_BYTES: usize = 128;
const MAX_DESCRIPTOR_NAME_BYTES: usize = 4_096;
const MAX_DESCRIPTOR_VERSION_BYTES: usize = 128;
const MAX_DESCRIPTOR_IDENTIFIERS: usize = 4_096;

/// Whether the helper has crossed the boundary where a failure can reasonably
/// be attributed to native plugin code. Keep this boundary immediately before
/// the first platform loader call: even a loader failure can run constructors
/// from the target or one of its dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionStage {
    BeforeLoad,
    LoadAttempted,
}

pub(crate) fn execute(
    plugin_root: &Path,
    binary_path: &Path,
    input: &HostInput,
    stage: &mut ExecutionStage,
) -> Result<NativeExecution, HostError> {
    reject_loader_environment()?;
    let (plugin_root, manifest) = load_manifest(plugin_root)?;
    validate_manifest_runtime(&manifest, input)?;
    let expected_fingerprint = input.bootstrap.artifact_fingerprint()?;
    verify_fingerprint(&plugin_root, expected_fingerprint)?;
    let entrypoint = resolve_entrypoint(&plugin_root, &manifest)?;

    let granted_permissions = input.hello.granted_permissions()?;
    validate_grants(&manifest, &granted_permissions)?;
    let image = ExactBinaryImage::open_verified(binary_path, &input.bootstrap)?;
    // Narrow the mutable-artifact window before invoking the platform loader.
    verify_fingerprint(&plugin_root, expected_fingerprint)?;

    // The context is deliberately process-lifetime storage. If a malformed
    // plugin starts a late callback thread, error paths must not free the
    // callback target while diagnostics are still being flushed.
    let callback_context = Box::leak(Box::new(CallbackContext::new(
        image,
        granted_permissions,
        input.hello.limits(),
        input.bootstrap.output_limits.max_messages,
        input.bootstrap.output_limits.max_stdout_bytes,
    )));
    // The table itself, not only its context pointer, is plugin-visible storage.
    // Retain both until process teardown so a malformed late callback cannot
    // dereference a returned stack frame while output is being flushed.
    let host_api = Box::leak(Box::new(callback_context.host_api()));

    // This last sentinel check closes the ordinary disable-during-preflight
    // window. It cannot make a mutable same-account directory immutable between
    // this check and the platform loader; parent-side post-run verification and
    // a future platform-specific immutable snapshot remain required defenses.
    ensure_not_disabled(&plugin_root)?;
    crate::mark_load_attempted(stage)?;
    let library = load_library(&entrypoint)?;
    // Never unload a native plugin. A plugin may have violated its thread-join
    // contract, and process teardown is the only generally safe retirement.
    let library = ManuallyDrop::new(library);
    // SAFETY: Protocol-1 plugins export this exact C symbol and the function
    // type mirrors sdk/native/include/resymbol_plugin.h.
    let get_api = unsafe { library.get::<PluginGetApiFn>(abi::ENTRYPOINT_NAME) }
        .map_err(|error| HostError::Load(error.to_string()))?;
    let get_api = *get_api;

    let mut plugin_api = PluginApiV1::empty_for_host();
    // SAFETY: All pointers address live, correctly aligned protocol-1
    // structures. A plugin ABI violation can terminate only this helper.
    let status = unsafe {
        get_api(
            abi::ABI_VERSION,
            std::ptr::from_ref(&*host_api),
            std::ptr::from_mut(&mut plugin_api),
        )
    };
    require_status("resymbol_plugin_get_api", status)?;
    plugin_api.validate()?;

    let descriptor = read_descriptor(
        &plugin_api,
        &manifest,
        input.hello.limits().max_message_bytes,
    )?;
    let rejection = run_lifecycle(&plugin_api, callback_context, input);
    let events = callback_context.finish()?;

    // A plugin that rewrites its own package cannot return claims attributed to
    // the bytes that were approved. This post-run gate discards the full batch.
    verify_fingerprint(&plugin_root, expected_fingerprint)?;
    callback_context.set_phase(CallbackPhase::Destroyed);
    // Keep host callback memory valid even for a plugin thread that calls back
    // after destroy. The process exits immediately after output is flushed.
    Ok(NativeExecution {
        descriptor,
        events,
        rejection,
    })
}

#[cfg(unix)]
fn load_library(entrypoint: &Path) -> Result<Library, HostError> {
    use libloading::os::unix::{Library as UnixLibrary, RTLD_LOCAL, RTLD_NOW};

    // SAFETY: The entrypoint is a canonical regular file beneath the exact
    // fingerprinted directory. Loading arbitrary native code is why this
    // executable is a disposable process rather than part of the core.
    let library = unsafe { UnixLibrary::open(Some(entrypoint), RTLD_NOW | RTLD_LOCAL) }
        .map_err(|error| HostError::Load(error.to_string()))?;
    Ok(library.into())
}

#[cfg(windows)]
fn load_library(entrypoint: &Path) -> Result<Library, HostError> {
    use libloading::os::windows::{
        LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
        Library as WindowsLibrary,
    };

    // SAFETY: The path is fully qualified and fingerprinted. These flags add
    // only the plugin DLL's directory for its private dependencies plus the
    // safe default application/system directories; they exclude the ambient
    // current-directory search order.
    let library = unsafe {
        WindowsLibrary::load_with_flags(
            entrypoint,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    }
    .map_err(|error| HostError::Load(error.to_string()))?;
    Ok(library.into())
}

fn load_manifest(plugin_root: &Path) -> Result<(PathBuf, PluginManifest), HostError> {
    let root_metadata = fs::symlink_metadata(plugin_root)
        .map_err(|error| HostError::io("inspect native plugin root", error))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(HostError::Manifest(
            "plugin root must be a real directory".to_owned(),
        ));
    }
    let root = fs::canonicalize(plugin_root)
        .map_err(|error| HostError::io("canonicalize native plugin root", error))?;
    ensure_not_disabled(&root)?;

    let path = root.join(MANIFEST_FILE);
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| HostError::UnsafeManifest(path.clone()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(HostError::UnsafeManifest(path));
    }
    let mut bytes = Vec::new();
    File::open(&path)
        .map_err(|error| HostError::io("open native plugin manifest", error))?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| HostError::io("read native plugin manifest", error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES {
        return Err(HostError::UnsafeManifest(path));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| HostError::Manifest("manifest is not valid UTF-8".to_owned()))?;
    let manifest = toml::from_str::<PluginManifest>(text)
        .map_err(|error| HostError::Manifest(error.to_string()))?;
    let host_api = Version::parse(PLUGIN_API_VERSION)
        .expect("the native host's compile-time plugin API version is valid SemVer");
    manifest
        .validate_for_host(&host_api)
        .map_err(|error| HostError::Manifest(error.to_string()))?;
    Ok((root, manifest))
}

fn validate_manifest_runtime(
    manifest: &PluginManifest,
    input: &HostInput,
) -> Result<(), HostError> {
    if manifest.id.as_str() != input.hello.plugin_id() {
        return Err(HostError::Wire(
            "hello plugin id does not match the installed manifest".to_owned(),
        ));
    }
    if !matches!(
        manifest.runtime,
        PluginRuntime::Native {
            isolation: NativeIsolation::OutOfProcess,
            ..
        }
    ) {
        return Err(HostError::Manifest(
            "native helper accepts only out-of-process native manifests".to_owned(),
        ));
    }
    Ok(())
}

fn verify_fingerprint(plugin_root: &Path, expected: ArtifactFingerprint) -> Result<(), HostError> {
    ensure_not_disabled(plugin_root)?;
    let report = fingerprint_plugin_directory(plugin_root, FingerprintLimits::default())
        .map_err(|error| HostError::Fingerprint(error.to_string()))?;
    verify_fingerprint_result(plugin_root, expected, report.fingerprint)
}

fn verify_fingerprint_result(
    plugin_root: &Path,
    expected: ArtifactFingerprint,
    actual: ArtifactFingerprint,
) -> Result<(), HostError> {
    if actual != expected {
        return Err(HostError::FingerprintMismatch);
    }
    // The sentinel is deliberately excluded from the artifact fingerprint, so
    // it must be checked on both sides of the potentially long directory hash.
    ensure_not_disabled(plugin_root)?;
    Ok(())
}

fn ensure_not_disabled(plugin_root: &Path) -> Result<(), HostError> {
    match fs::symlink_metadata(plugin_root.join(DISABLED_SENTINEL)) {
        Ok(_) => Err(HostError::Manifest(
            "plugin was disabled before native execution completed".to_owned(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(HostError::io("inspect native disable sentinel", error)),
    }
}

fn resolve_entrypoint(root: &Path, manifest: &PluginManifest) -> Result<PathBuf, HostError> {
    let mut candidate = root.to_path_buf();
    for component in manifest.runtime.entrypoint().components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(component) => candidate.push(component),
            _ => return Err(HostError::UnsafeEntrypoint(candidate)),
        }
        let metadata = fs::symlink_metadata(&candidate)
            .map_err(|_| HostError::UnsafeEntrypoint(candidate.clone()))?;
        if metadata.file_type().is_symlink() {
            return Err(HostError::UnsafeEntrypoint(candidate));
        }
    }
    let metadata =
        fs::metadata(&candidate).map_err(|_| HostError::UnsafeEntrypoint(candidate.clone()))?;
    if !metadata.is_file() {
        return Err(HostError::UnsafeEntrypoint(candidate));
    }
    let canonical =
        fs::canonicalize(&candidate).map_err(|_| HostError::UnsafeEntrypoint(candidate.clone()))?;
    if !canonical.starts_with(root) {
        return Err(HostError::UnsafeEntrypoint(candidate));
    }
    Ok(canonical)
}

fn read_descriptor(
    api: &PluginApiV1,
    manifest: &PluginManifest,
    max_message_bytes: usize,
) -> Result<ValidatedDescriptor, HostError> {
    let mut descriptor = PluginDescriptorV1::empty_for_host();
    let get_descriptor = api
        .get_descriptor
        .expect("validated native API has get_descriptor");
    // SAFETY: The function pointer and context came from a validated API table;
    // descriptor points to current protocol-1 writable storage.
    let status = unsafe { get_descriptor(api.plugin_context, &mut descriptor) };
    require_status("get_descriptor", status)?;
    descriptor.validate_header()?;
    validate_descriptor_isolation(descriptor.isolation)?;

    let id = {
        // SAFETY: Descriptor views remain valid until destroy. Each is copied
        // and bounded before any subsequent plugin call.
        unsafe { abi::copy_string_view(descriptor.id, MAX_DESCRIPTOR_ID_BYTES, "descriptor id") }
    }?;
    // SAFETY: Same descriptor lifetime and bounds as above.
    let name = unsafe {
        abi::copy_string_view(
            descriptor.name,
            MAX_DESCRIPTOR_NAME_BYTES,
            "descriptor name",
        )
    }?;
    // SAFETY: Same descriptor lifetime and bounds as above.
    let version = unsafe {
        abi::copy_string_view(
            descriptor.version,
            MAX_DESCRIPTOR_VERSION_BYTES,
            "descriptor version",
        )
    }?;
    // SAFETY: Same descriptor lifetime and bounds as above.
    let capabilities_json = unsafe {
        abi::copy_byte_view(
            descriptor.capabilities_json_utf8,
            max_message_bytes,
            "descriptor capabilities JSON",
        )
    }?;
    // SAFETY: Same descriptor lifetime and bounds as above.
    let permissions_json = unsafe {
        abi::copy_byte_view(
            descriptor.requested_permissions_json_utf8,
            max_message_bytes,
            "descriptor permissions JSON",
        )
    }?;

    if id != manifest.id.as_str()
        || name != manifest.name
        || version != manifest.version.to_string()
    {
        return Err(HostError::Abi(
            "plugin descriptor identity does not match its manifest".to_owned(),
        ));
    }
    let mut capabilities =
        parse_identifier_array::<PluginCapability>(&capabilities_json, "descriptor capabilities")?;
    let expected_capabilities = manifest
        .capabilities
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if capabilities.iter().cloned().collect::<BTreeSet<_>>() != expected_capabilities {
        return Err(HostError::Abi(
            "plugin descriptor capabilities do not match its manifest".to_owned(),
        ));
    }
    let mut requested_permissions = parse_identifier_array::<PluginPermission>(
        &permissions_json,
        "descriptor requested permissions",
    )?;
    let expected_permissions = manifest
        .permissions
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if requested_permissions
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_permissions
    {
        return Err(HostError::Abi(
            "plugin descriptor permissions do not match its manifest".to_owned(),
        ));
    }
    capabilities.sort();
    requested_permissions.sort();
    Ok(ValidatedDescriptor {
        id,
        name,
        version,
        capabilities,
        requested_permissions,
    })
}

fn validate_descriptor_isolation(isolation: u32) -> Result<(), HostError> {
    if matches!(
        isolation,
        ISOLATION_OUT_OF_PROCESS | ISOLATION_TRUSTED_IN_PROCESS_ALLOWED
    ) {
        Ok(())
    } else {
        Err(HostError::Abi(format!(
            "plugin descriptor reports unsupported isolation value {isolation}"
        )))
    }
}

#[cfg(unix)]
fn reject_loader_environment() -> Result<(), HostError> {
    let influencing = std::env::vars_os()
        .find(|(name, value)| !value.is_empty() && loader_environment_variable(name.as_os_str()));
    if let Some((name, _value)) = influencing {
        return Err(HostError::Load(format!(
            "refusing loader-influencing environment variable `{}`; the parent must launch the native host with a sanitized environment",
            name.to_string_lossy()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn loader_environment_variable(name: &OsStr) -> bool {
    let name = name.as_encoded_bytes();
    name.starts_with(b"LD_")
        || name.starts_with(b"DYLD_")
        || matches!(name, b"LIBPATH" | b"SHLIB_PATH")
}

#[cfg(windows)]
fn reject_loader_environment() -> Result<(), HostError> {
    // `load_library()` uses LOAD_LIBRARY_SEARCH_* flags and therefore excludes
    // the ambient current directory and PATH search order.
    Ok(())
}

trait ManifestIdentifier: Sized {
    fn parse(value: String) -> Result<Self, String>;
}

impl ManifestIdentifier for PluginCapability {
    fn parse(value: String) -> Result<Self, String> {
        Self::new(value).map_err(|error| error.to_string())
    }
}

impl ManifestIdentifier for PluginPermission {
    fn parse(value: String) -> Result<Self, String> {
        Self::new(value).map_err(|error| error.to_string())
    }
}

fn parse_identifier_array<T>(bytes: &[u8], label: &str) -> Result<Vec<String>, HostError>
where
    T: ManifestIdentifier + ToString,
{
    let values = serde_json::from_slice::<Vec<String>>(bytes)
        .map_err(|error| HostError::Abi(format!("invalid {label} JSON: {error}")))?;
    if values.len() > MAX_DESCRIPTOR_IDENTIFIERS {
        return Err(HostError::Abi(format!(
            "{label} exceeds the {MAX_DESCRIPTOR_IDENTIFIERS}-item limit"
        )));
    }
    let mut unique = BTreeSet::new();
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let value = T::parse(value)
            .map_err(|error| HostError::Abi(format!("invalid {label} value: {error}")))?
            .to_string();
        if !unique.insert(value.clone()) {
            return Err(HostError::Abi(format!("{label} contains a duplicate")));
        }
        parsed.push(value);
    }
    Ok(parsed)
}

fn run_lifecycle(
    api: &PluginApiV1,
    context: &CallbackContext,
    input: &HostInput,
) -> Option<PluginRejection> {
    let initialize = api.initialize.expect("validated native API has initialize");
    let health_check = api
        .health_check
        .expect("validated native API has health_check");
    let analyze = api.analyze.expect("validated native API has analyze");
    let shutdown = api.shutdown.expect("validated native API has shutdown");
    let destroy = api.destroy.expect("validated native API has destroy");

    context.set_phase(CallbackPhase::Initializing);
    // SAFETY: The API and context were validated, and the JSON buffer remains
    // live and immutable for the complete synchronous call.
    let initialize_status =
        unsafe { initialize(api.plugin_context, byte_view(input.hello_json.as_slice())) };
    let initialized = initialize_status == STATUS_OK;
    let mut rejection = rejection_for_status("initialize", initialize_status);
    if rejection.is_none() {
        // SAFETY: The validated plugin owns its context until destroy.
        let health_status = unsafe { health_check(api.plugin_context) };
        rejection = rejection_for_status("health_check", health_status);
    }
    if rejection.is_none() {
        context.set_phase(CallbackPhase::Analyzing);
        // SAFETY: The request bytes remain live and immutable for the complete
        // synchronous analyze call.
        let analyze_status =
            unsafe { analyze(api.plugin_context, byte_view(input.request_json.as_slice())) };
        rejection = rejection_for_status("analyze", analyze_status);
    }

    context.set_phase(CallbackPhase::ShuttingDown);
    if initialized {
        // SAFETY: The function came from the validated API table, initialize
        // completed successfully, and lifecycle calls are serialized here.
        unsafe { shutdown(api.plugin_context) };
    }
    // SAFETY: Destroy came from the validated API table and is the mandatory
    // final release operation even when initialize rejected the request.
    unsafe { destroy(api.plugin_context) };
    context.set_phase(CallbackPhase::Destroyed);
    rejection
}

fn byte_view(bytes: &[u8]) -> ByteView {
    ByteView {
        data: bytes.as_ptr(),
        length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    }
}

fn require_status(operation: &'static str, status: i32) -> Result<(), HostError> {
    if status == STATUS_OK {
        Ok(())
    } else {
        Err(HostError::PluginStatus { operation, status })
    }
}

fn rejection_for_status(operation: &'static str, status: i32) -> Option<PluginRejection> {
    if status == STATUS_OK {
        return None;
    }
    let code = match status {
        STATUS_INVALID_ARGUMENT => "invalid-argument",
        STATUS_INCOMPATIBLE_ABI => "incompatible-api",
        STATUS_PERMISSION_DENIED => "permission-denied",
        STATUS_UNAVAILABLE => "unavailable",
        STATUS_CANCELLED => "cancelled",
        STATUS_RESOURCE_LIMIT => "resource-limit",
        _ => "internal",
    };
    Some(PluginRejection {
        code,
        message: format!("native plugin returned status {status} from {operation}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_arrays_reject_duplicates() {
        let error = parse_identifier_array::<PluginPermission>(
            br#"["claims.submit","claims.submit"]"#,
            "permissions",
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn native_statuses_map_to_existing_wire_error_codes() {
        assert_eq!(
            rejection_for_status("analyze", STATUS_UNAVAILABLE)
                .unwrap()
                .code,
            "unavailable"
        );
        assert_eq!(
            rejection_for_status("analyze", 999).unwrap().code,
            "internal"
        );
    }

    #[test]
    fn descriptor_accepts_both_public_native_isolation_values() {
        assert!(validate_descriptor_isolation(ISOLATION_OUT_OF_PROCESS).is_ok());
        assert!(validate_descriptor_isolation(ISOLATION_TRUSTED_IN_PROCESS_ALLOWED).is_ok());
        assert!(validate_descriptor_isolation(0).is_err());
        assert!(validate_descriptor_isolation(3).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn loader_environment_filter_rejects_search_and_injection_variables() {
        assert!(loader_environment_variable(OsStr::new("LD_LIBRARY_PATH")));
        assert!(loader_environment_variable(OsStr::new("LD_PRELOAD")));
        assert!(loader_environment_variable(OsStr::new(
            "DYLD_INSERT_LIBRARIES"
        )));
        assert!(!loader_environment_variable(OsStr::new("TMPDIR")));
        assert!(!loader_environment_variable(OsStr::new("RUST_BACKTRACE")));
    }

    #[test]
    fn fingerprint_result_rechecks_a_new_disable_sentinel() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("artifact.bin"), b"approved").unwrap();
        let expected = fingerprint_plugin_directory(directory.path(), FingerprintLimits::default())
            .unwrap()
            .fingerprint;
        std::fs::write(directory.path().join(DISABLED_SENTINEL), b"disabled").unwrap();

        assert!(verify_fingerprint_result(directory.path(), expected, expected).is_err());
    }
}
