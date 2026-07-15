use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::Arc,
};

use resymbol_core::{
    BinaryFormat, BinaryId, BinaryIdentity, DiscoveredPlugin, PluginSource,
    plugin_api::{
        MANIFEST_VERSION, PluginCapability, PluginHealth, PluginHealthState, PluginId,
        PluginManifest, PluginPermission, PluginRuntime,
    },
};
use resymbol_plugin_runtime::{
    ExternalProcessRequest, PluginMethod, PluginRuntimeError, WasmComponentHost, WasmPeImage,
    WasmRuntimeLimits,
};
use resymbol_plugin_state::{FingerprintLimits, fingerprint_plugin_directory};
use semver::{Version, VersionReq};
use serde_json::Map;
use tempfile::TempDir;

fn main() {
    limits_are_validated_before_engine_creation();
    component_reads_are_bounded_by_the_configured_limit();
    exact_image_identity_is_required();
    core_modules_are_not_accepted_as_components();
    components_without_the_versioned_guest_export_are_rejected();
    propagated_and_swallowed_host_errors_keep_policy_precedence();
    checked_in_example_round_trips_through_the_sandbox();
    checked_in_example_obeys_read_and_fuel_budgets();
}

fn limits_are_validated_before_engine_creation() {
    let invalid = WasmRuntimeLimits::default().with_fuel(0);
    assert!(matches!(
        WasmComponentHost::new(invalid),
        Err(PluginRuntimeError::InvalidLimits(_))
    ));
}

fn component_reads_are_bounded_by_the_configured_limit() {
    let fixture = PluginFixture::new(&[0_u8; 1024]);
    let error = fixture
        .execute_with_limits(WasmRuntimeLimits::default().with_max_component_bytes(8))
        .expect_err("the component exceeds its pre-read and in-read bound");
    assert!(matches!(
        error,
        PluginRuntimeError::WasmResourceLimit {
            resource: "component bytes",
            limit: 8,
        }
    ));
}

fn exact_image_identity_is_required() {
    let bytes = minimal_pe();
    let mut identity = identity(&bytes);
    identity.id = BinaryId::digest(b"different bytes");
    assert!(matches!(
        WasmPeImage::new(identity, 0x200, 0x1000, Vec::new(), Arc::from(bytes)),
        Err(PluginRuntimeError::InvalidWasmContext(_))
    ));
}

fn core_modules_are_not_accepted_as_components() {
    let fixture = PluginFixture::new(&[0, 97, 115, 109, 1, 0, 0, 0]);
    let error = fixture
        .execute()
        .expect_err("a core module is not a component");
    assert!(matches!(
        error,
        PluginRuntimeError::WasmComponent {
            stage: "component validation",
            ..
        }
    ));
}

fn components_without_the_versioned_guest_export_are_rejected() {
    // Component Model magic/version followed by an empty component body.
    let fixture = PluginFixture::new(&[0, 97, 115, 109, 13, 0, 1, 0]);
    let error = fixture
        .execute()
        .expect_err("the required resymbol:plugin/guest export is absent");
    assert!(matches!(
        error,
        PluginRuntimeError::WasmComponent {
            stage: "component instantiation",
            ..
        }
    ));
}

fn propagated_and_swallowed_host_errors_keep_policy_precedence() {
    for session in [
        "wrong-phase-propagated",
        "wrong-phase-swallowed",
        "wrong-phase-then-trap",
    ] {
        let error = execute_violation_fixture(session, Vec::new())
            .expect_err("wrong-phase claim submission must remain host-attributed");
        assert!(matches!(
            error,
            PluginRuntimeError::ClaimEventNotAllowed { .. }
        ));
    }

    let error = execute_violation_fixture("ungranted-propagated", Vec::new())
        .expect_err("a propagated guest error must not mask permission denial");
    assert!(matches!(
        error,
        PluginRuntimeError::PermissionDenied { ref permission, .. }
            if permission.as_str() == PluginPermission::BINARY_READ
    ));
}

fn execute_violation_fixture(
    session: &str,
    grants: Vec<PluginPermission>,
) -> Result<resymbol_plugin_runtime::PluginExecution, PluginRuntimeError> {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("component.wasm"),
        include_bytes!("fixtures/wasm-violations/component.wasm"),
    )
    .unwrap();
    fs::write(directory.path().join("plugin.toml"), "test fixture").unwrap();
    let plugin = DiscoveredPlugin {
        source: PluginSource::Directory,
        path: directory.path().to_path_buf(),
        manifest: Some(violation_manifest()),
        health: PluginHealth::new(PluginHealthState::Enabled),
    };
    let bytes = minimal_pe();
    let identity = identity(&bytes);
    let image = WasmPeImage::new(
        identity.clone(),
        0x200,
        0x1000,
        Vec::new(),
        Arc::from(bytes),
    )
    .unwrap();
    let mut payload = Map::new();
    payload.insert("binary".to_owned(), serde_json::to_value(identity).unwrap());
    let request = ExternalProcessRequest::new("request", session, PluginMethod::Analyze, payload)
        .unwrap()
        .with_granted_permissions(grants);
    let fingerprint = fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default())
        .unwrap()
        .fingerprint;
    WasmComponentHost::new(WasmRuntimeLimits::default())?.execute_sandboxed(
        &plugin,
        &request,
        fingerprint,
        &image,
    )
}

fn checked_in_example_round_trips_through_the_sandbox() {
    let (execution, binary) = execute_example(WasmRuntimeLimits::default()).unwrap();
    assert_eq!(
        execution.descriptor.id,
        "dev.resymbol.example.wasm-resolver"
    );
    assert_eq!(execution.claims.len(), 1);
    assert_eq!(execution.claims[0].subject().binary(), &binary);
    assert_eq!(execution.logs.len(), 2);
    assert_eq!(execution.response.result["health"], "healthy");
}

fn checked_in_example_obeys_read_and_fuel_budgets() {
    let read_error = execute_example(WasmRuntimeLimits::default().with_max_binary_read_bytes(1))
        .expect_err("the example requests two bytes");
    assert!(matches!(
        read_error,
        PluginRuntimeError::WasmResourceLimit {
            resource: "aggregate binary.read bytes",
            limit: 1,
        }
    ));

    let fuel_error = execute_example(WasmRuntimeLimits::default().with_fuel(1))
        .expect_err("one unit of fuel cannot complete the lifecycle");
    assert!(matches!(
        fuel_error,
        PluginRuntimeError::WasmResourceLimit {
            resource: "fuel",
            limit: 1,
        }
    ));
}

fn execute_example(
    limits: WasmRuntimeLimits,
) -> Result<(resymbol_plugin_runtime::PluginExecution, BinaryId), PluginRuntimeError> {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("example-resolver.wasm"),
        include_bytes!("../../../examples/plugins/wasm/example-resolver.wasm"),
    )
    .unwrap();
    fs::write(
        directory.path().join("plugin.toml"),
        include_str!("../../../examples/plugins/wasm/plugin.toml"),
    )
    .unwrap();
    let plugin = DiscoveredPlugin {
        source: PluginSource::Directory,
        path: directory.path().to_path_buf(),
        manifest: Some(example_manifest()),
        health: PluginHealth::new(PluginHealthState::Enabled),
    };
    let bytes = minimal_pe();
    let identity = identity(&bytes);
    let image = WasmPeImage::new(
        identity.clone(),
        0x200,
        0x1000,
        Vec::new(),
        Arc::from(bytes),
    )
    .unwrap();
    let mut payload = Map::new();
    payload.insert("binary".to_owned(), serde_json::to_value(identity).unwrap());
    let request = ExternalProcessRequest::new("request", "session", PluginMethod::Analyze, payload)
        .unwrap()
        .with_granted_permissions([
            PluginPermission::new(PluginPermission::BINARY_READ).unwrap(),
            PluginPermission::new(PluginPermission::CLAIMS_SUBMIT).unwrap(),
        ]);
    let fingerprint = fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default())
        .unwrap()
        .fingerprint;
    let host = WasmComponentHost::new(limits)?;
    let binary = image.identity.id.clone();
    host.execute_sandboxed(&plugin, &request, fingerprint, &image)
        .map(|execution| (execution, binary))
}

struct PluginFixture {
    _directory: TempDir,
    plugin: DiscoveredPlugin,
    request: ExternalProcessRequest,
    image: WasmPeImage,
}

impl PluginFixture {
    fn new(component: &[u8]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("plugin.wasm"), component).unwrap();
        fs::write(directory.path().join("plugin.toml"), "test fixture").unwrap();
        let manifest = manifest();
        let plugin = DiscoveredPlugin {
            source: PluginSource::Directory,
            path: directory.path().to_path_buf(),
            manifest: Some(manifest),
            health: PluginHealth::new(PluginHealthState::Enabled),
        };
        let bytes = minimal_pe();
        let identity = identity(&bytes);
        let image = WasmPeImage::new(
            identity.clone(),
            0x200,
            0x1000,
            Vec::new(),
            Arc::from(bytes),
        )
        .unwrap();
        let mut payload = Map::new();
        payload.insert("binary".to_owned(), serde_json::to_value(identity).unwrap());
        let request =
            ExternalProcessRequest::new("request", "session", PluginMethod::Analyze, payload)
                .unwrap();
        Self {
            _directory: directory,
            plugin,
            request,
            image,
        }
    }

    fn execute(&self) -> Result<resymbol_plugin_runtime::PluginExecution, PluginRuntimeError> {
        self.execute_with_limits(WasmRuntimeLimits::default())
    }

    fn execute_with_limits(
        &self,
        limits: WasmRuntimeLimits,
    ) -> Result<resymbol_plugin_runtime::PluginExecution, PluginRuntimeError> {
        let fingerprint =
            fingerprint_plugin_directory(&self.plugin.path, FingerprintLimits::default())
                .unwrap()
                .fingerprint;
        let host = WasmComponentHost::new(limits).unwrap();
        host.execute_sandboxed(&self.plugin, &self.request, fingerprint, &self.image)
    }
}

fn manifest() -> PluginManifest {
    PluginManifest {
        manifest_version: MANIFEST_VERSION,
        id: PluginId::new("dev.resymbol.wasm-test").unwrap(),
        name: "Wasm test".to_owned(),
        version: Version::new(1, 0, 0),
        api: VersionReq::parse("^0.1").unwrap(),
        runtime: PluginRuntime::Wasm {
            entrypoint: PathBuf::from("plugin.wasm"),
        },
        capabilities: BTreeSet::<PluginCapability>::new(),
        permissions: BTreeSet::<PluginPermission>::new(),
        dependencies: BTreeMap::new(),
        description: None,
        authors: Vec::new(),
        license: None,
        homepage: None,
    }
}

fn example_manifest() -> PluginManifest {
    PluginManifest {
        manifest_version: MANIFEST_VERSION,
        id: PluginId::new("dev.resymbol.example.wasm-resolver").unwrap(),
        name: "Example WASM Symbol Resolver".to_owned(),
        version: Version::new(0, 1, 0),
        api: VersionReq::parse("^0.1.0").unwrap(),
        runtime: PluginRuntime::Wasm {
            entrypoint: PathBuf::from("example-resolver.wasm"),
        },
        capabilities: [
            PluginCapability::new(PluginCapability::ANALYZER_BINARY).unwrap(),
            PluginCapability::new(PluginCapability::RESOLVER_SYMBOLS).unwrap(),
        ]
        .into_iter()
        .collect(),
        permissions: [
            PluginPermission::new(PluginPermission::BINARY_READ).unwrap(),
            PluginPermission::new(PluginPermission::CLAIMS_SUBMIT).unwrap(),
        ]
        .into_iter()
        .collect(),
        dependencies: BTreeMap::new(),
        description: Some(
            "Source-backed sandboxed Component Model analyzer that verifies the DOS MZ signature."
                .to_owned(),
        ),
        authors: Vec::new(),
        license: None,
        homepage: None,
    }
}

fn violation_manifest() -> PluginManifest {
    PluginManifest {
        manifest_version: MANIFEST_VERSION,
        id: PluginId::new("dev.resymbol.test.wasm-violations").unwrap(),
        name: "Wasm violation fixture".to_owned(),
        version: Version::new(0, 0, 0),
        api: VersionReq::parse("^0.1.0").unwrap(),
        runtime: PluginRuntime::Wasm {
            entrypoint: PathBuf::from("component.wasm"),
        },
        capabilities: BTreeSet::new(),
        permissions: [
            PluginPermission::new(PluginPermission::BINARY_READ).unwrap(),
            PluginPermission::new(PluginPermission::CLAIMS_SUBMIT).unwrap(),
        ]
        .into_iter()
        .collect(),
        dependencies: BTreeMap::new(),
        description: None,
        authors: Vec::new(),
        license: None,
        homepage: None,
    }
}

fn identity(bytes: &[u8]) -> BinaryIdentity {
    BinaryIdentity {
        id: BinaryId::digest(bytes),
        size: bytes.len() as u64,
        format: BinaryFormat::Pe,
        architecture: "x86_64".to_owned(),
        image_base: 0x0001_4000_0000,
    }
}

fn minimal_pe() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x200];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[coff + 2..coff + 4].copy_from_slice(&0_u16.to_le_bytes());
    bytes[coff + 16..coff + 18].copy_from_slice(&0xf0_u16.to_le_bytes());
    let optional = coff + 20;
    bytes[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[optional + 24..optional + 32].copy_from_slice(&0x0001_4000_0000_u64.to_le_bytes());
    bytes[optional + 32..optional + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional + 36..optional + 40].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[optional + 56..optional + 60].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[optional + 108..optional + 112].copy_from_slice(&16_u32.to_le_bytes());
    bytes
}
