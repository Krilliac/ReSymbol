use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
};

use resymbol_core::{
    BinaryFormat, BinaryId, BinaryIdentity, DiscoveredPlugin, PluginDiscoveryOptions, PluginSource,
    SymbolAssertion, discover_plugins,
    plugin_api::{PluginCapability, PluginHealthState, PluginPermission, PluginRuntime},
};
use resymbol_plugin_runtime::{
    ExternalProcessRequest, ManagedPeImage, ManagedPeImageSection, ManagedProcessHost,
    PluginMethod, RuntimeLimits,
};
use resymbol_plugin_state::{FingerprintLimits, fingerprint_plugin_directory};
use serde_json::{Map, json};
use tempfile::TempDir;

const HOST_ENV: &str = "RESYMBOL_MANAGED_E2E_HOST";
const PLUGIN_ENV: &str = "RESYMBOL_MANAGED_E2E_PLUGIN_DIR";
const PLUGIN_ID: &str = "dev.resymbol.example.managed-matcher";
const PLUGIN_NAME: &str = "Example Managed Function Matcher";
const PLUGIN_VERSION: &str = "0.1.0";
const ENTRY_ASSEMBLY: &str = "Example.ManagedMatcher.dll";
const LOAD_ATTEMPTED_MARKER: &str = "@resymbol-managed-host/load-attempted/v1@";

/// This is an intentionally opt-in test because it requires a RID-specific,
/// self-contained .NET helper and a separately built managed plugin. The
/// managed SDK workflow provides both inputs and runs this exact test. Calling
/// the ignored test without either input is a hard failure, never a skip.
#[test]
#[ignore = "requires a published managed host and managed example plugin"]
fn real_managed_process_round_trip() {
    let helper = required_absolute_path(HOST_ENV, false);
    let plugin_root = required_absolute_path(PLUGIN_ENV, true);
    assert_no_private_sdk_copy(&plugin_root);

    let entry = plugin_root.join(ENTRY_ASSEMBLY);
    assert!(
        entry.is_file(),
        "{PLUGIN_ENV} does not contain {ENTRY_ASSEMBLY}: {}",
        plugin_root.display()
    );

    let expected_artifact =
        fingerprint_plugin_directory(&plugin_root, FingerprintLimits::default())
            .expect("fingerprint staged managed plugin")
            .fingerprint;
    let plugin = discover_staged_plugin(&plugin_root);

    let temporary = TempDir::new().expect("create managed E2E fixture directory");
    let binary_bytes = deterministic_pe_x86_64();
    let binary_path = temporary.path().join("deterministic-x86_64.exe");
    fs::write(&binary_path, &binary_bytes).expect("write deterministic PE fixture");
    let identity = BinaryIdentity {
        id: BinaryId::digest(&binary_bytes),
        size: u64::try_from(binary_bytes.len()).expect("fixture size fits u64"),
        format: BinaryFormat::Pe,
        architecture: "x86_64".to_owned(),
        image_base: 0x0000_0001_4000_0000,
    };
    let image = ManagedPeImage::new(
        identity.clone(),
        0x200,
        0x2000,
        vec![ManagedPeImageSection {
            virtual_address: 0x1000,
            virtual_size: 0x100,
            raw_data_offset: 0x200,
            raw_data_size: 0x200,
        }],
    )
    .expect("construct exact PE image map");
    let request = ExternalProcessRequest::new(
        "managed-e2e-request",
        "managed-e2e-session",
        PluginMethod::Analyze,
        Map::from_iter([
            (
                "binary".to_owned(),
                serde_json::to_value(&identity).expect("encode exact binary identity"),
            ),
            ("phase".to_owned(), json!("managed-e2e")),
            (
                "options".to_owned(),
                json!({ "fixture": "deterministic-pe-x86_64" }),
            ),
            (
                "base_analysis".to_owned(),
                json!({
                    "fixture": "deterministic-pe-x86_64",
                    "binary": identity,
                }),
            ),
        ]),
    )
    .expect("construct managed analyze request")
    .with_granted_permissions(manifest_permissions());

    let execution = ManagedProcessHost::new(&helper, RuntimeLimits::default())
        .expect("construct managed process host")
        .execute_trusted(&plugin, &request, expected_artifact, &binary_path, &image)
        .expect("real managed helper and example plugin must complete successfully");

    assert_eq!(execution.descriptor.id, PLUGIN_ID);
    assert_eq!(execution.descriptor.name, PLUGIN_NAME);
    assert_eq!(execution.descriptor.version, PLUGIN_VERSION);
    assert_eq!(
        execution.descriptor.capabilities,
        [PluginCapability::MATCHER_FUNCTIONS]
    );
    assert_eq!(
        execution.descriptor.requested_permissions,
        [
            PluginPermission::BINARY_READ,
            PluginPermission::CLAIMS_SUBMIT,
            PluginPermission::SYMBOLS_READ,
        ]
    );
    assert_eq!(execution.response.id, "managed-e2e-request");
    assert_eq!(execution.response.result, json!({ "accepted": true }));
    assert_eq!(execution.claims.len(), 1);
    assert!(matches!(
        execution.claims[0].assertion(),
        SymbolAssertion::Comment { text }
            if text == "Managed example verified the DOS MZ signature via binary.read."
    ));
    assert_eq!(execution.logs.len(), 1);
    assert_eq!(execution.logs[0].level, "debug");
    assert_eq!(
        execution.logs[0].message,
        "Example received base analysis and submitted one exact MZ evidence claim."
    );
    assert_eq!(execution.exit_code, Some(0));

    // A successful managed invocation proves that both the Rust launcher and
    // the .NET helper independently accepted the exact artifact fingerprint
    // and binary SHA-256. Verify they remained byte-identical after plugin
    // execution, and that the private load-attempted marker was stripped from
    // operator-facing diagnostics.
    assert_eq!(
        fingerprint_plugin_directory(&plugin_root, FingerprintLimits::default())
            .expect("post-run fingerprint staged managed plugin")
            .fingerprint,
        expected_artifact
    );
    assert_eq!(
        fs::read(&binary_path).expect("read post-run PE fixture"),
        binary_bytes
    );
    assert_eq!(BinaryId::digest(&binary_bytes), identity.id);
    assert!(!execution.diagnostics.stderr.contains(LOAD_ATTEMPTED_MARKER));
    assert!(
        execution.diagnostics.stderr.is_empty(),
        "unexpected managed helper diagnostics: {}",
        execution.diagnostics.stderr
    );
}

fn required_absolute_path(variable: &str, directory: bool) -> PathBuf {
    let value = env::var_os(variable).unwrap_or_else(|| {
        panic!("required managed E2E environment variable {variable} is absent")
    });
    let path = PathBuf::from(value);
    assert!(
        path.is_absolute(),
        "{variable} must be an absolute path: {}",
        path.display()
    );
    let canonical = fs::canonicalize(&path)
        .unwrap_or_else(|error| panic!("cannot resolve {variable} {}: {error}", path.display()));
    if directory {
        assert!(
            canonical.is_dir(),
            "{variable} must identify a directory: {}",
            canonical.display()
        );
    } else {
        assert!(
            canonical.is_file(),
            "{variable} must identify a file: {}",
            canonical.display()
        );
    }
    canonical
}

fn discover_staged_plugin(plugin_root: &Path) -> DiscoveredPlugin {
    let collection_root = plugin_root
        .parent()
        .expect("staged managed plugin must have a collection root");
    let report = discover_plugins(collection_root, &PluginDiscoveryOptions::default())
        .expect("discover staged managed plugin manifest");
    assert_eq!(
        report.plugins.len(),
        1,
        "managed E2E collection must contain exactly one plugin"
    );
    let plugin = report
        .plugins
        .into_iter()
        .next()
        .expect("one discovered managed plugin");
    assert_eq!(plugin.source, PluginSource::Directory);
    assert_eq!(plugin.path, plugin_root);
    assert_eq!(plugin.health.state, PluginHealthState::Enabled);
    assert!(plugin.is_loadable());

    let manifest = plugin
        .manifest
        .as_ref()
        .expect("staged plugin.toml must parse into a manifest");
    assert_eq!(manifest.id.as_str(), PLUGIN_ID);
    assert_eq!(manifest.name, PLUGIN_NAME);
    assert_eq!(manifest.version.to_string(), PLUGIN_VERSION);
    assert_eq!(manifest.api.to_string(), "^0.1.0");
    assert!(matches!(
        &manifest.runtime,
        PluginRuntime::Managed { entrypoint } if entrypoint == Path::new(ENTRY_ASSEMBLY)
    ));
    assert_eq!(
        manifest
            .capabilities
            .iter()
            .map(PluginCapability::as_str)
            .collect::<Vec<_>>(),
        [PluginCapability::MATCHER_FUNCTIONS]
    );
    assert_eq!(manifest.permissions, manifest_permissions());
    plugin
}

fn manifest_permissions() -> BTreeSet<PluginPermission> {
    [
        PluginPermission::BINARY_READ,
        PluginPermission::SYMBOLS_READ,
        PluginPermission::CLAIMS_SUBMIT,
    ]
    .into_iter()
    .map(|permission| PluginPermission::new(permission).expect("valid example permission"))
    .collect()
}

fn assert_no_private_sdk_copy(plugin_root: &Path) {
    let mut pending = vec![plugin_root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", directory.display()))
        {
            let entry = entry.expect("read staged managed plugin entry");
            let file_type = entry
                .file_type()
                .expect("inspect staged managed plugin entry");
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                assert!(
                    !entry
                        .file_name()
                        .to_string_lossy()
                        .eq_ignore_ascii_case("ReSymbol.PluginSdk.dll"),
                    "managed plugin must bind the helper's SDK and not ship a private copy: {}",
                    entry.path().display()
                );
            }
        }
    }
}

/// Minimal deterministic PE32+ AMD64 file accepted by both the Rust-owned map
/// validation and System.Reflection.PortableExecutable in the managed helper.
fn deterministic_pe_x86_64() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

    let coff = 0x84;
    put_u16(&mut bytes, coff, 0x8664);
    put_u16(&mut bytes, coff + 2, 1);
    put_u16(&mut bytes, coff + 16, 0x00f0);
    put_u16(&mut bytes, coff + 18, 0x0022);

    let optional = coff + 20;
    put_u16(&mut bytes, optional, 0x020b);
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u32(&mut bytes, optional + 20, 0x1000);
    put_u64(&mut bytes, optional + 24, 0x0000_0001_4000_0000);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x0200);
    put_u16(&mut bytes, optional + 40, 6);
    put_u16(&mut bytes, optional + 48, 6);
    put_u32(&mut bytes, optional + 56, 0x2000);
    put_u32(&mut bytes, optional + 60, 0x0200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u16(&mut bytes, optional + 70, 0x8160);
    put_u64(&mut bytes, optional + 72, 0x10_0000);
    put_u64(&mut bytes, optional + 80, 0x1000);
    put_u64(&mut bytes, optional + 88, 0x10_0000);
    put_u64(&mut bytes, optional + 96, 0x1000);
    put_u32(&mut bytes, optional + 108, 16);

    let section = optional + 0x00f0;
    bytes[section..section + 5].copy_from_slice(b".text");
    put_u32(&mut bytes, section + 8, 0x0100);
    put_u32(&mut bytes, section + 12, 0x1000);
    put_u32(&mut bytes, section + 16, 0x0200);
    put_u32(&mut bytes, section + 20, 0x0200);
    put_u32(&mut bytes, section + 36, 0x6000_0020);
    bytes[0x200] = 0xc3;
    bytes
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
