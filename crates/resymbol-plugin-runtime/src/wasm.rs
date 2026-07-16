//! Sandboxed WebAssembly Component Model plugin execution.
//!
//! This host deliberately links only the ReSymbol WIT imports. In particular,
//! it does not link WASI, so a component cannot acquire ambient filesystem,
//! network, process, clock, or environment access through this runtime.

use std::{
    collections::BTreeSet,
    fs::File,
    io::Read as _,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use resymbol_core::{
    BinaryFormat, BinaryId, BinaryIdentity, DiscoveredPlugin, PluginSource,
    plugin_api::{
        PLUGIN_API_VERSION, PluginCapability, PluginManifest, PluginPermission, PluginRuntime,
    },
};
use resymbol_plugin_state::{ArtifactFingerprint, FingerprintLimits, fingerprint_plugin_directory};
use serde_json::{Map, Value, json};
use wasmtime::{
    Config, Engine, Store, StoreLimits, StoreLimitsBuilder, Trap,
    component::{Component, HasSelf, Linker},
};

use crate::{
    ExternalProcessRequest, PluginDescriptor, PluginExecution, PluginLog, PluginMethod,
    PluginResponse, PluginRuntimeError, ProcessDiagnostics, RuntimeLimits, claim::decode_claim,
    host::resolve_entrypoint,
};

mod bindings {
    wasmtime::component::bindgen!({
        path: "../../sdk/wit",
        world: "resymbol-plugin",
    });
}

use bindings::resymbol::plugin::{host, types};

const MAX_PE_SECTIONS: usize = 96;
const HARD_MAX_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_MAX_COMPONENT_BYTES: u64 = 64 * 1024 * 1024;
const HARD_MAX_COMPONENT_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_FUEL: u64 = 100_000_000;
const HARD_MAX_FUEL: u64 = 10_000_000_000;
const DEFAULT_MAX_BINARY_READ_BYTES: u64 = 64 * 1024 * 1024;
const HARD_MAX_BINARY_READ_BYTES: u64 = HARD_MAX_BINARY_BYTES;
const MAX_READ_CALL_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_WASM_STACK_BYTES: usize = 2 * 1024 * 1024;
const MIN_WASM_STACK_BYTES: usize = 64 * 1024;
const HARD_MAX_WASM_STACK_BYTES: usize = 8 * 1024 * 1024;
const HARD_MAX_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const HARD_MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const HARD_MAX_MESSAGES: usize = 1_000_000;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_METADATA_NAME_BYTES: usize = 4_096;
const MAX_METADATA_VERSION_BYTES: usize = 128;
const MAX_METADATA_IDENTIFIERS: usize = 4_096;
const MAX_HEALTH_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_TABLE_ELEMENTS: usize = 100_000;

/// Enforced ceilings for one sandboxed component invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmRuntimeLimits {
    runtime: RuntimeLimits,
    max_component_bytes: u64,
    fuel: u64,
    max_binary_read_bytes: u64,
    max_wasm_stack_bytes: usize,
}

impl WasmRuntimeLimits {
    pub fn new(runtime: RuntimeLimits) -> Result<Self, PluginRuntimeError> {
        let limits = Self {
            runtime,
            max_component_bytes: DEFAULT_MAX_COMPONENT_BYTES,
            fuel: DEFAULT_FUEL,
            max_binary_read_bytes: DEFAULT_MAX_BINARY_READ_BYTES,
            max_wasm_stack_bytes: DEFAULT_MAX_WASM_STACK_BYTES,
        };
        limits.validate()?;
        Ok(limits)
    }

    #[must_use]
    pub const fn runtime(&self) -> &RuntimeLimits {
        &self.runtime
    }

    #[must_use]
    pub const fn max_component_bytes(&self) -> u64 {
        self.max_component_bytes
    }

    #[must_use]
    pub const fn fuel(&self) -> u64 {
        self.fuel
    }

    #[must_use]
    pub const fn max_binary_read_bytes(&self) -> u64 {
        self.max_binary_read_bytes
    }

    #[must_use]
    pub const fn max_wasm_stack_bytes(&self) -> usize {
        self.max_wasm_stack_bytes
    }

    #[must_use]
    pub const fn with_max_component_bytes(mut self, bytes: u64) -> Self {
        self.max_component_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel = fuel;
        self
    }

    #[must_use]
    pub const fn with_max_binary_read_bytes(mut self, bytes: u64) -> Self {
        self.max_binary_read_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn with_max_wasm_stack_bytes(mut self, bytes: usize) -> Self {
        self.max_wasm_stack_bytes = bytes;
        self
    }

    fn validate(&self) -> Result<(), PluginRuntimeError> {
        self.runtime.validate()?;
        if self.max_component_bytes == 0 || self.max_component_bytes > HARD_MAX_COMPONENT_BYTES {
            return Err(PluginRuntimeError::InvalidLimits(
                "Wasm max_component_bytes must be in 1..=268435456",
            ));
        }
        if self.fuel == 0 || self.fuel > HARD_MAX_FUEL {
            return Err(PluginRuntimeError::InvalidLimits(
                "Wasm fuel must be in 1..=10000000000",
            ));
        }
        if self.max_binary_read_bytes == 0
            || self.max_binary_read_bytes > HARD_MAX_BINARY_READ_BYTES
        {
            return Err(PluginRuntimeError::InvalidLimits(
                "Wasm max_binary_read_bytes must be in 1..=1073741824",
            ));
        }
        if !(MIN_WASM_STACK_BYTES..=HARD_MAX_WASM_STACK_BYTES).contains(&self.max_wasm_stack_bytes)
        {
            return Err(PluginRuntimeError::InvalidLimits(
                "Wasm max_wasm_stack_bytes must be in 65536..=8388608",
            ));
        }
        if self.runtime.advertised_max_memory_bytes > HARD_MAX_MEMORY_BYTES {
            return Err(PluginRuntimeError::InvalidLimits(
                "Wasm advertised_max_memory_bytes must not exceed 4294967296",
            ));
        }
        if self.runtime.request_timeout > HARD_MAX_TIMEOUT {
            return Err(PluginRuntimeError::InvalidLimits(
                "Wasm request_timeout must not exceed 24 hours",
            ));
        }
        if self.runtime.max_messages > HARD_MAX_MESSAGES {
            return Err(PluginRuntimeError::InvalidLimits(
                "Wasm max_messages must not exceed 1000000",
            ));
        }
        Ok(())
    }
}

impl Default for WasmRuntimeLimits {
    fn default() -> Self {
        Self::new(RuntimeLimits::default()).expect("default Wasm limits are valid")
    }
}

/// One exact PE file-to-image section mapping exposed through `binary.read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmPeImageSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_offset: u32,
    pub raw_data_size: u32,
}

impl WasmPeImageSection {
    const fn loaded_size(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_data_size
        } else {
            self.virtual_size
        }
    }

    const fn file_backed_size(&self) -> u32 {
        let loaded_size = self.loaded_size();
        if self.raw_data_size < loaded_size {
            self.raw_data_size
        } else {
            loaded_size
        }
    }
}

/// Immutable exact PE bytes and their validated file-to-image mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmPeImage {
    pub identity: BinaryIdentity,
    pub size_of_headers: u32,
    pub size_of_image: u32,
    pub sections: Vec<WasmPeImageSection>,
    bytes: Arc<[u8]>,
}

impl WasmPeImage {
    pub fn new(
        identity: BinaryIdentity,
        size_of_headers: u32,
        size_of_image: u32,
        sections: Vec<WasmPeImageSection>,
        bytes: Arc<[u8]>,
    ) -> Result<Self, PluginRuntimeError> {
        let image = Self {
            identity,
            size_of_headers,
            size_of_image,
            sections,
            bytes,
        };
        image.validate()?;
        Ok(image)
    }

    /// Revalidate the identity, digest, PE headers, and every mapped range.
    pub fn validate(&self) -> Result<(), PluginRuntimeError> {
        self.identity
            .validate()
            .map_err(|error| invalid_context(error.to_string()))?;
        if !matches!(self.identity.format, BinaryFormat::Pe) {
            return Err(invalid_context("the Wasm v1 host accepts only PE images"));
        }
        if self.identity.architecture != "x86_64" {
            return Err(invalid_context(
                "the Wasm v1 host accepts only x86_64 images",
            ));
        }
        if self.identity.size > HARD_MAX_BINARY_BYTES {
            return Err(invalid_context(format!(
                "analysis binary exceeds {HARD_MAX_BINARY_BYTES} bytes"
            )));
        }
        if u64::try_from(self.bytes.len()).ok() != Some(self.identity.size) {
            return Err(invalid_context(
                "exact analysis bytes do not match the declared binary size",
            ));
        }
        if BinaryId::digest(&self.bytes) != self.identity.id {
            return Err(invalid_context(
                "exact analysis bytes do not match the declared SHA-256 identity",
            ));
        }
        let parsed = parse_pe_image(&self.bytes)?;
        if parsed.image_base != self.identity.image_base
            || parsed.size_of_headers != self.size_of_headers
            || parsed.size_of_image != self.size_of_image
            || parsed.sections != self.sections
        {
            return Err(invalid_context(
                "PE header/section map does not match the exact analysis bytes",
            ));
        }
        Ok(())
    }

    fn read_rva(&self, rva: u64, length: u32) -> Result<Vec<u8>, BinaryReadFailure> {
        let length = usize::try_from(length).map_err(|_| BinaryReadFailure::OutsideImage)?;
        if length > MAX_READ_CALL_BYTES {
            return Err(BinaryReadFailure::CallLimit);
        }
        let rva = u32::try_from(rva).map_err(|_| BinaryReadFailure::OutsideImage)?;
        if rva >= self.size_of_image {
            return Err(BinaryReadFailure::OutsideImage);
        }
        if length == 0 {
            return Ok(Vec::new());
        }

        if rva < self.size_of_headers {
            let start = usize::try_from(rva).map_err(|_| BinaryReadFailure::OutsideImage)?;
            let available = usize::try_from(self.size_of_headers - rva)
                .map_err(|_| BinaryReadFailure::OutsideImage)?;
            return Ok(copy_available(&self.bytes, start, available, length));
        }

        let Some(section) = self.sections.iter().find(|section| {
            let start = u64::from(section.virtual_address);
            let size = u64::from(section.loaded_size());
            (start..start.saturating_add(size)).contains(&u64::from(rva))
        }) else {
            return Ok(Vec::new());
        };
        let delta = rva
            .checked_sub(section.virtual_address)
            .ok_or(BinaryReadFailure::OutsideImage)?;
        let file_backed_size = section.file_backed_size();
        if delta >= file_backed_size {
            return Ok(Vec::new());
        }
        let start = u64::from(section.raw_data_offset)
            .checked_add(u64::from(delta))
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(BinaryReadFailure::OutsideImage)?;
        let available = usize::try_from(file_backed_size - delta)
            .map_err(|_| BinaryReadFailure::OutsideImage)?;
        Ok(copy_available(&self.bytes, start, available, length))
    }
}

/// In-process Wasmtime host with no ambient WASI capabilities.
pub struct WasmComponentHost {
    engine: Engine,
    limits: WasmRuntimeLimits,
    // Epoch increments are engine-wide. Serialize stores created by this host
    // so one request's deadline cannot interrupt another request.
    execution: Mutex<()>,
}

impl std::fmt::Debug for WasmComponentHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmComponentHost")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl WasmComponentHost {
    pub fn new(limits: WasmRuntimeLimits) -> Result<Self, PluginRuntimeError> {
        limits.validate()?;
        let mut config = Config::new();
        config
            .wasm_component_model(true)
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(limits.max_wasm_stack_bytes)
            .wasm_backtrace(false)
            .debug_info(false);
        let engine =
            Engine::new(&config).map_err(|error| PluginRuntimeError::WasmEngineUnavailable {
                reason: error.to_string(),
            })?;
        Ok(Self {
            engine,
            limits,
            execution: Mutex::new(()),
        })
    }

    #[must_use]
    pub const fn limits(&self) -> &WasmRuntimeLimits {
        &self.limits
    }

    /// Execute a trusted Wasm component after independently rechecking its
    /// complete plugin-directory fingerprint before and after execution.
    pub fn execute_sandboxed(
        &self,
        plugin: &DiscoveredPlugin,
        request: &ExternalProcessRequest,
        expected_artifact: ArtifactFingerprint,
        image: &WasmPeImage,
    ) -> Result<PluginExecution, PluginRuntimeError> {
        self.limits.validate()?;
        request.validate()?;
        validate_wasm_request(request)?;
        image.validate()?;
        let manifest = validate_wasm_plugin(plugin, request)?;
        validate_request_binary(request, &image.identity)?;

        let _serial = self
            .execution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        verify_artifact(&plugin.path, expected_artifact, "before component load")?;
        let result = self.execute_inner(plugin, manifest, request, image);
        verify_artifact(&plugin.path, expected_artifact, "after component execution")?;
        result
    }

    fn execute_inner(
        &self,
        plugin: &DiscoveredPlugin,
        manifest: &PluginManifest,
        request: &ExternalProcessRequest,
        image: &WasmPeImage,
    ) -> Result<PluginExecution, PluginRuntimeError> {
        let (entrypoint, _root) = resolve_entrypoint(&plugin.path, manifest)?;
        let component_file = File::open(&entrypoint).map_err(|source| PluginRuntimeError::Io {
            operation: "open Wasm component",
            source,
        })?;
        let opened = component_file
            .metadata()
            .map_err(|source| PluginRuntimeError::Io {
                operation: "inspect opened Wasm component",
                source,
            })?;
        if !opened.is_file() {
            return Err(PluginRuntimeError::EntrypointNotFile);
        }
        if opened.len() > self.limits.max_component_bytes {
            return Err(PluginRuntimeError::WasmResourceLimit {
                resource: "component bytes",
                limit: self.limits.max_component_bytes,
            });
        }
        let read_limit = self.limits.max_component_bytes.checked_add(1).ok_or(
            PluginRuntimeError::InvalidLimits(
                "Wasm max_component_bytes cannot be bounded for reading",
            ),
        )?;
        let mut component_bytes = Vec::new();
        component_file
            .take(read_limit)
            .read_to_end(&mut component_bytes)
            .map_err(|source| PluginRuntimeError::Io {
                operation: "read Wasm component",
                source,
            })?;
        let observed = u64::try_from(component_bytes.len()).unwrap_or(u64::MAX);
        if observed > self.limits.max_component_bytes {
            return Err(PluginRuntimeError::WasmResourceLimit {
                resource: "component bytes",
                limit: self.limits.max_component_bytes,
            });
        }
        if observed != opened.len() {
            return Err(PluginRuntimeError::WasmArtifactMismatch {
                reason: "component changed while it was being read".to_owned(),
            });
        }

        let deadline = Instant::now()
            .checked_add(self.limits.runtime.request_timeout)
            .ok_or(PluginRuntimeError::InvalidLimits(
                "Wasm request_timeout is too large for the platform clock",
            ))?;
        let state = HostState::new(manifest, request, image, &self.limits, deadline)?;
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.store_limits);
        store.set_fuel(self.limits.fuel).map_err(|error| {
            PluginRuntimeError::WasmEngineUnavailable {
                reason: error.to_string(),
            }
        })?;
        store.set_epoch_deadline(1);
        store.epoch_deadline_trap();
        let _timer = EpochTimer::start(self.engine.clone(), self.limits.runtime.request_timeout)?;

        let component = Component::from_binary(&self.engine, &component_bytes)
            .map_err(|error| component_error("component validation", error))?;
        let mut linker = Linker::new(&self.engine);
        host::add_to_linker::<_, HasSelf<_>>(&mut linker, |state: &mut HostState| state).map_err(
            |error| PluginRuntimeError::WasmEngineUnavailable {
                reason: format!("could not link the ReSymbol host interface: {error}"),
            },
        )?;
        let guest = bindings::ResymbolPlugin::instantiate(&mut store, &component, &linker)
            .map_err(|error| map_wasmtime_error("component instantiation", error, &self.limits))?;

        run_lifecycle(&guest, &mut store, manifest, request, &self.limits)?;
        if let Some(failure) = store.data_mut().deferred_failure.take() {
            return Err(failure.into_error());
        }
        let state = store.into_data();
        let descriptor =
            state
                .descriptor
                .ok_or_else(|| PluginRuntimeError::WasmEngineUnavailable {
                    reason: "successful lifecycle did not retain authenticated metadata".to_owned(),
                })?;
        Ok(PluginExecution {
            descriptor,
            response: PluginResponse {
                id: request.id().to_owned(),
                result: json!({ "health": state.health.unwrap_or("healthy") }),
            },
            claims: state.claims,
            logs: state.logs,
            diagnostics: ProcessDiagnostics::default(),
            exit_code: None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecyclePhase {
    Metadata,
    Initialize,
    Health,
    Analyze,
    Shutdown,
}

#[derive(Debug)]
enum DeferredFailure {
    Permission(String),
    ClaimPhase,
    Resource { resource: &'static str, limit: u64 },
    InvalidClaim(String),
    InvalidHostCall(String),
}

impl DeferredFailure {
    fn into_error(self) -> PluginRuntimeError {
        match self {
            Self::Permission(permission) => PluginRuntimeError::PermissionDenied {
                permission,
                diagnostics: ProcessDiagnostics::default(),
            },
            Self::ClaimPhase => PluginRuntimeError::ClaimEventNotAllowed {
                method: "Wasm lifecycle".to_owned(),
                diagnostics: ProcessDiagnostics::default(),
            },
            Self::Resource { resource, limit } => {
                PluginRuntimeError::WasmResourceLimit { resource, limit }
            }
            Self::InvalidClaim(reason) => PluginRuntimeError::WasmComponent {
                stage: "claim validation",
                reason,
            },
            Self::InvalidHostCall(reason) => PluginRuntimeError::WasmComponent {
                stage: "host import",
                reason,
            },
        }
    }
}

struct HostState {
    manifest: PluginManifest,
    request: ExternalProcessRequest,
    image: WasmPeImage,
    store_limits: StoreLimits,
    deadline: Instant,
    phase: LifecyclePhase,
    descriptor: Option<PluginDescriptor>,
    health: Option<&'static str>,
    claims: Vec<resymbol_core::SymbolClaim>,
    logs: Vec<PluginLog>,
    event_count: usize,
    output_bytes: usize,
    binary_read_bytes: u64,
    max_messages: usize,
    max_output_bytes: usize,
    max_message_bytes: usize,
    max_binary_read_bytes: u64,
    deferred_failure: Option<DeferredFailure>,
}

impl HostState {
    fn new(
        manifest: &PluginManifest,
        request: &ExternalProcessRequest,
        image: &WasmPeImage,
        limits: &WasmRuntimeLimits,
        deadline: Instant,
    ) -> Result<Self, PluginRuntimeError> {
        let memory_size =
            usize::try_from(limits.runtime.advertised_max_memory_bytes).map_err(|_| {
                PluginRuntimeError::InvalidLimits(
                    "Wasm advertised_max_memory_bytes does not fit this host",
                )
            })?;
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(memory_size)
            .table_elements(MAX_TABLE_ELEMENTS)
            .instances(32)
            .tables(2)
            .memories(1)
            .trap_on_grow_failure(true)
            .build();
        Ok(Self {
            manifest: manifest.clone(),
            request: request.clone(),
            image: image.clone(),
            store_limits,
            deadline,
            phase: LifecyclePhase::Metadata,
            descriptor: None,
            health: None,
            claims: Vec::new(),
            logs: Vec::new(),
            event_count: 0,
            output_bytes: 0,
            binary_read_bytes: 0,
            max_messages: limits.runtime.max_messages,
            max_output_bytes: limits.runtime.max_stdout_bytes,
            max_message_bytes: limits.runtime.max_message_bytes,
            max_binary_read_bytes: limits.max_binary_read_bytes,
            deferred_failure: None,
        })
    }

    fn grant(&self, permission: &str) -> bool {
        self.request
            .granted_permissions()
            .iter()
            .any(|item| item.as_str() == permission)
    }

    fn record_event(&mut self, bytes: usize) -> Result<(), DeferredFailure> {
        if bytes > self.max_message_bytes {
            return Err(DeferredFailure::Resource {
                resource: "event bytes",
                limit: u64::try_from(self.max_message_bytes).unwrap_or(u64::MAX),
            });
        }
        let next_count = self
            .event_count
            .checked_add(1)
            .ok_or(DeferredFailure::Resource {
                resource: "event count",
                limit: u64::try_from(self.max_messages).unwrap_or(u64::MAX),
            })?;
        if next_count > self.max_messages {
            return Err(DeferredFailure::Resource {
                resource: "event count",
                limit: u64::try_from(self.max_messages).unwrap_or(u64::MAX),
            });
        }
        let next_bytes = self
            .output_bytes
            .checked_add(bytes)
            .ok_or(DeferredFailure::Resource {
                resource: "output bytes",
                limit: u64::try_from(self.max_output_bytes).unwrap_or(u64::MAX),
            })?;
        if next_bytes > self.max_output_bytes {
            return Err(DeferredFailure::Resource {
                resource: "output bytes",
                limit: u64::try_from(self.max_output_bytes).unwrap_or(u64::MAX),
            });
        }
        self.event_count = next_count;
        self.output_bytes = next_bytes;
        Ok(())
    }

    fn defer(&mut self, failure: DeferredFailure) {
        if self.deferred_failure.is_none() {
            self.deferred_failure = Some(failure);
        }
    }
}

impl host::Host for HostState {
    fn log(&mut self, level: types::LogLevel, message: String) {
        if self.deferred_failure.is_some() {
            return;
        }
        let bytes = message.len().saturating_add(16);
        if let Err(failure) = self.record_event(bytes) {
            self.defer(failure);
            return;
        }
        self.logs.push(PluginLog {
            level: log_level_name(level).to_owned(),
            message,
        });
    }

    fn read_binary(&mut self, rva: u64, length: u32) -> Result<Vec<u8>, types::PluginError> {
        if self.deferred_failure.is_some() {
            return Err(types::PluginError::Unavailable(
                "the invocation has already failed".to_owned(),
            ));
        }
        if !matches!(
            self.phase,
            LifecyclePhase::Initialize | LifecyclePhase::Analyze
        ) {
            let reason = format!("binary.read is unavailable during {:?}", self.phase);
            self.defer(DeferredFailure::InvalidHostCall(reason.clone()));
            return Err(types::PluginError::Unavailable(reason));
        }
        if !self.grant(PluginPermission::BINARY_READ) {
            self.defer(DeferredFailure::Permission(
                PluginPermission::BINARY_READ.to_owned(),
            ));
            return Err(types::PluginError::PermissionDenied(
                "binary.read was not granted".to_owned(),
            ));
        }
        if usize::try_from(length).unwrap_or(usize::MAX) > MAX_READ_CALL_BYTES {
            self.defer(DeferredFailure::Resource {
                resource: "binary.read call bytes",
                limit: MAX_READ_CALL_BYTES as u64,
            });
            return Err(types::PluginError::ResourceLimit(format!(
                "one binary.read call is limited to {MAX_READ_CALL_BYTES} bytes"
            )));
        }
        let Some(next) = self.binary_read_bytes.checked_add(u64::from(length)) else {
            self.defer(DeferredFailure::Resource {
                resource: "aggregate binary.read bytes",
                limit: self.max_binary_read_bytes,
            });
            return Err(types::PluginError::ResourceLimit(format!(
                "aggregate binary.read is limited to {} bytes",
                self.max_binary_read_bytes
            )));
        };
        if next > self.max_binary_read_bytes {
            self.defer(DeferredFailure::Resource {
                resource: "aggregate binary.read bytes",
                limit: self.max_binary_read_bytes,
            });
            return Err(types::PluginError::ResourceLimit(format!(
                "aggregate binary.read is limited to {} bytes",
                self.max_binary_read_bytes
            )));
        }
        match self.image.read_rva(rva, length) {
            Ok(bytes) => {
                // Charge requested bytes, not returned bytes, so sparse reads
                // cannot be used as an unbounded address-space oracle.
                self.binary_read_bytes = next;
                Ok(bytes)
            }
            Err(BinaryReadFailure::OutsideImage) => Err(types::PluginError::InvalidArgument(
                "binary.read RVA is outside the image".to_owned(),
            )),
            Err(BinaryReadFailure::CallLimit) => Err(types::PluginError::ResourceLimit(
                "binary.read call exceeds its byte limit".to_owned(),
            )),
        }
    }

    fn submit_claim(&mut self, claim: types::SymbolClaim) -> Result<(), types::PluginError> {
        if self.deferred_failure.is_some() {
            return Err(types::PluginError::Unavailable(
                "the invocation has already failed".to_owned(),
            ));
        }
        if self.phase != LifecyclePhase::Analyze {
            self.defer(DeferredFailure::ClaimPhase);
            return Err(types::PluginError::Unavailable(
                "claims are accepted only during analyze".to_owned(),
            ));
        }
        if !self.grant(PluginPermission::CLAIMS_SUBMIT) {
            self.defer(DeferredFailure::Permission(
                PluginPermission::CLAIMS_SUBMIT.to_owned(),
            ));
            return Err(types::PluginError::PermissionDenied(
                "claims.submit was not granted".to_owned(),
            ));
        }

        let encoded_bytes = claim
            .subject_json
            .len()
            .saturating_add(claim.claim_json.len())
            .saturating_add(
                claim
                    .evidence
                    .iter()
                    .map(|item| {
                        item.kind.len()
                            + item.description.len()
                            + item.data_json.as_ref().map_or(0, String::len)
                    })
                    .sum::<usize>(),
            )
            .saturating_add(64);
        if let Err(failure) = self.record_event(encoded_bytes) {
            self.defer(failure);
            return Err(types::PluginError::ResourceLimit(
                "claim output exceeds a host limit".to_owned(),
            ));
        }

        let payload = match component_claim_json(&claim) {
            Ok(payload) => payload,
            Err(reason) => {
                self.defer(DeferredFailure::InvalidClaim(reason.clone()));
                return Err(types::PluginError::InvalidArgument(reason));
            }
        };
        let decoded = match decode_claim(payload, &self.manifest, &self.request) {
            Ok(claim) => claim,
            Err(error) => {
                let reason = error.to_string();
                self.defer(DeferredFailure::InvalidClaim(reason.clone()));
                return Err(types::PluginError::InvalidArgument(reason));
            }
        };
        if decoded.subject().binary() != &self.image.identity.id {
            let reason = "claim subject does not identify the exact analysis binary".to_owned();
            self.defer(DeferredFailure::InvalidClaim(reason.clone()));
            return Err(types::PluginError::InvalidArgument(reason));
        }
        self.claims.push(decoded);
        Ok(())
    }

    fn is_cancelled(&mut self) -> bool {
        Instant::now() >= self.deadline
    }
}

fn run_lifecycle(
    guest: &bindings::ResymbolPlugin,
    store: &mut Store<HostState>,
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    limits: &WasmRuntimeLimits,
) -> Result<(), PluginRuntimeError> {
    let result = (|| {
        store.data_mut().phase = LifecyclePhase::Metadata;
        let metadata = guest.resymbol_plugin_guest().call_metadata(&mut *store);
        take_deferred_failure(store)?;
        let metadata = metadata.map_err(|error| map_wasmtime_error("metadata", error, limits))?;
        let descriptor = validate_component_metadata(metadata, manifest)?;
        store.data_mut().descriptor = Some(descriptor);

        store.data_mut().phase = LifecyclePhase::Initialize;
        let initialization = initialization(request, limits)?;
        let initialized = guest
            .resymbol_plugin_guest()
            .call_initialize(&mut *store, &initialization);
        take_deferred_failure(store)?;
        let initialized =
            initialized.map_err(|error| map_wasmtime_error("initialize", error, limits))?;
        map_guest_result(initialized, limits)?;

        store.data_mut().phase = LifecyclePhase::Health;
        let health = guest.resymbol_plugin_guest().call_health(&mut *store);
        take_deferred_failure(store)?;
        let health = health.map_err(|error| map_wasmtime_error("health", error, limits))?;
        let health = map_guest_value(health, limits)?;
        validate_health(&health, limits)?;
        store.data_mut().health = Some(match health.state {
            types::HealthState::Healthy => "healthy",
            types::HealthState::Degraded => "degraded",
            types::HealthState::Unhealthy => {
                return Err(PluginRuntimeError::PluginRejected {
                    code: "unhealthy".to_owned(),
                    message: health
                        .message
                        .unwrap_or_else(|| "plugin reported an unhealthy state".to_owned()),
                    data: health
                        .details_json
                        .as_deref()
                        .and_then(|value| serde_json::from_str(value).ok()),
                    diagnostics: ProcessDiagnostics::default(),
                });
            }
        });
        store.data_mut().phase = LifecyclePhase::Analyze;
        let analysis = analysis_request(request, &store.data().image.identity)?;
        let analyzed = guest
            .resymbol_plugin_guest()
            .call_analyze(&mut *store, &analysis);
        take_deferred_failure(store)?;
        let analyzed = analyzed.map_err(|error| map_wasmtime_error("analyze", error, limits))?;
        map_guest_result(analyzed, limits)
    })();

    store.data_mut().phase = LifecyclePhase::Shutdown;
    let shutdown = guest.resymbol_plugin_guest().call_shutdown(&mut *store);
    // A host policy violation during shutdown is more authoritative than an
    // earlier guest-reported failure. Otherwise a guest could intentionally
    // fail an earlier stage and use that transient error to mask forbidden
    // shutdown behavior.
    take_deferred_failure(store)?;
    let shutdown = shutdown.map_err(|error| map_wasmtime_error("shutdown", error, limits));
    match (result, shutdown) {
        (Err(primary), _) => Err(primary),
        (Ok(()), Err(shutdown)) => Err(shutdown),
        (Ok(()), Ok(())) => take_deferred_failure(store),
    }
}

fn take_deferred_failure(store: &mut Store<HostState>) -> Result<(), PluginRuntimeError> {
    match store.data_mut().deferred_failure.take() {
        Some(failure) => Err(failure.into_error()),
        None => Ok(()),
    }
}

fn initialization(
    request: &ExternalProcessRequest,
    limits: &WasmRuntimeLimits,
) -> Result<types::Initialization, PluginRuntimeError> {
    let (api_major, api_minor, api_patch) = plugin_api_version_parts()?;
    Ok(types::Initialization {
        session_id: request.session_id().to_owned(),
        host_api_major: api_major,
        host_api_minor: api_minor,
        host_api_patch: api_patch,
        granted_permissions: request
            .granted_permissions()
            .iter()
            .map(ToString::to_string)
            .collect(),
        limits: types::PluginLimits {
            max_memory_bytes: limits.runtime.advertised_max_memory_bytes,
            max_message_bytes: u64::try_from(limits.runtime.max_message_bytes).map_err(|_| {
                PluginRuntimeError::InvalidLimits(
                    "Wasm max_message_bytes does not fit the WIT contract",
                )
            })?,
            analyze_timeout_ms: u64::try_from(limits.runtime.request_timeout.as_millis()).map_err(
                |_| {
                    PluginRuntimeError::InvalidLimits(
                        "Wasm request_timeout does not fit the WIT contract",
                    )
                },
            )?,
        },
        options_json: "{}".to_owned(),
    })
}

fn plugin_api_version_parts() -> Result<(u32, u32, u32), PluginRuntimeError> {
    let mut parts = PLUGIN_API_VERSION.split('.');
    let version = (
        parse_plugin_api_version_part(parts.next(), "major")?,
        parse_plugin_api_version_part(parts.next(), "minor")?,
        parse_plugin_api_version_part(parts.next(), "patch")?,
    );
    if parts.next().is_some() {
        return Err(PluginRuntimeError::WasmEngineUnavailable {
            reason: "built-in plugin API version has unsupported components".to_owned(),
        });
    }
    Ok(version)
}

fn parse_plugin_api_version_part(
    part: Option<&str>,
    label: &'static str,
) -> Result<u32, PluginRuntimeError> {
    part.ok_or_else(|| PluginRuntimeError::WasmEngineUnavailable {
        reason: format!("built-in plugin API version is missing its {label} component"),
    })?
    .parse::<u32>()
    .map_err(|error| PluginRuntimeError::WasmEngineUnavailable {
        reason: format!("invalid built-in plugin API {label} version: {error}"),
    })
}

fn analysis_request(
    request: &ExternalProcessRequest,
    identity: &BinaryIdentity,
) -> Result<types::AnalysisRequest, PluginRuntimeError> {
    Ok(types::AnalysisRequest {
        request_id: request.id().to_owned(),
        binary: types::BinaryIdentity {
            sha256: identity.id.to_string(),
            format: binary_format_name(&identity.format),
            architecture: identity.architecture.clone(),
            image_size: identity.size,
        },
        phase: "analysis".to_owned(),
        options_json: "{}".to_owned(),
    })
}

fn validate_component_metadata(
    metadata: types::PluginMetadata,
    manifest: &PluginManifest,
) -> Result<PluginDescriptor, PluginRuntimeError> {
    if metadata.id.len() > MAX_IDENTIFIER_BYTES
        || metadata.name.len() > MAX_METADATA_NAME_BYTES
        || metadata.version.len() > MAX_METADATA_VERSION_BYTES
        || metadata.capabilities.len() > MAX_METADATA_IDENTIFIERS
        || metadata.requested_permissions.len() > MAX_METADATA_IDENTIFIERS
        || metadata
            .capabilities
            .iter()
            .chain(&metadata.requested_permissions)
            .any(|value| value.len() > MAX_IDENTIFIER_BYTES)
    {
        return Err(component_reason(
            "metadata",
            "component metadata exceeds a bounded field or item limit",
        ));
    }
    let capabilities =
        parse_metadata_values::<PluginCapability>(&metadata.capabilities, "capability")?;
    let permissions =
        parse_metadata_values::<PluginPermission>(&metadata.requested_permissions, "permission")?;
    if metadata.id != manifest.id.as_str()
        || metadata.name != manifest.name
        || metadata.version != manifest.version.to_string()
        || capabilities != manifest.capabilities
        || permissions != manifest.permissions
    {
        return Err(component_reason(
            "metadata",
            "component metadata does not exactly match the installed manifest",
        ));
    }
    Ok(PluginDescriptor {
        id: metadata.id,
        name: metadata.name,
        version: metadata.version,
        capabilities: metadata.capabilities,
        requested_permissions: metadata.requested_permissions,
    })
}

fn parse_metadata_values<T>(
    values: &[String],
    label: &'static str,
) -> Result<BTreeSet<T>, PluginRuntimeError>
where
    T: std::str::FromStr + Ord,
    T::Err: std::fmt::Display,
{
    let parsed = values
        .iter()
        .map(|value| {
            value.parse::<T>().map_err(|error| {
                component_reason("metadata", format!("invalid {label} `{value}`: {error}"))
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if parsed.len() != values.len() {
        return Err(component_reason(
            "metadata",
            format!("component metadata contains a duplicate {label}"),
        ));
    }
    Ok(parsed)
}

fn validate_health(
    health: &types::PluginHealth,
    limits: &WasmRuntimeLimits,
) -> Result<(), PluginRuntimeError> {
    if health
        .message
        .as_ref()
        .is_some_and(|message| message.len() > MAX_HEALTH_MESSAGE_BYTES)
    {
        return Err(PluginRuntimeError::WasmResourceLimit {
            resource: "health message bytes",
            limit: MAX_HEALTH_MESSAGE_BYTES as u64,
        });
    }
    if let Some(details) = &health.details_json {
        if details.len() > limits.runtime.max_message_bytes {
            return Err(PluginRuntimeError::WasmResourceLimit {
                resource: "health details bytes",
                limit: u64::try_from(limits.runtime.max_message_bytes).unwrap_or(u64::MAX),
            });
        }
        let value = serde_json::from_str::<Value>(details).map_err(|error| {
            component_reason("health", format!("invalid details JSON: {error}"))
        })?;
        if !value.is_object() {
            return Err(component_reason(
                "health",
                "health details JSON must be an object",
            ));
        }
    }
    Ok(())
}

fn map_guest_result(
    result: Result<(), types::PluginError>,
    limits: &WasmRuntimeLimits,
) -> Result<(), PluginRuntimeError> {
    result.map_err(|error| plugin_rejected(error, limits))
}

fn map_guest_value<T>(
    result: Result<T, types::PluginError>,
    limits: &WasmRuntimeLimits,
) -> Result<T, PluginRuntimeError> {
    result.map_err(|error| plugin_rejected(error, limits))
}

fn plugin_rejected(error: types::PluginError, limits: &WasmRuntimeLimits) -> PluginRuntimeError {
    let (code, message) = match error {
        types::PluginError::InvalidArgument(message) => ("invalid-argument", message),
        types::PluginError::PermissionDenied(message) => ("permission-denied", message),
        types::PluginError::Unavailable(message) => ("unavailable", message),
        types::PluginError::Cancelled => ("cancelled", "plugin cancelled".to_owned()),
        types::PluginError::ResourceLimit(message) => ("resource-limit", message),
        types::PluginError::Internal(message) => ("internal", message),
    };
    if message.len() > limits.runtime.max_message_bytes {
        return PluginRuntimeError::WasmResourceLimit {
            resource: "plugin error bytes",
            limit: u64::try_from(limits.runtime.max_message_bytes).unwrap_or(u64::MAX),
        };
    }
    PluginRuntimeError::PluginRejected {
        code: code.to_owned(),
        message,
        data: None,
        diagnostics: ProcessDiagnostics::default(),
    }
}

fn map_wasmtime_error(
    stage: &'static str,
    error: wasmtime::Error,
    limits: &WasmRuntimeLimits,
) -> PluginRuntimeError {
    if matches!(error.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)) {
        return PluginRuntimeError::WasmResourceLimit {
            resource: "fuel",
            limit: limits.fuel,
        };
    }
    if matches!(error.downcast_ref::<Trap>(), Some(Trap::Interrupt)) {
        return PluginRuntimeError::Timeout {
            timeout: limits.runtime.request_timeout,
            diagnostics: ProcessDiagnostics::default(),
        };
    }
    let reason = error.to_string();
    if reason.contains("memory")
        && (reason.contains("limit") || reason.contains("grow") || reason.contains("minimum size"))
    {
        return PluginRuntimeError::WasmResourceLimit {
            resource: "linear memory bytes",
            limit: limits.runtime.advertised_max_memory_bytes,
        };
    }
    component_reason(stage, reason)
}

fn component_error(stage: &'static str, error: wasmtime::Error) -> PluginRuntimeError {
    component_reason(stage, error.to_string())
}

fn component_reason(stage: &'static str, reason: impl Into<String>) -> PluginRuntimeError {
    PluginRuntimeError::WasmComponent {
        stage,
        reason: reason.into(),
    }
}

fn component_claim_json(claim: &types::SymbolClaim) -> Result<Value, String> {
    let subject = serde_json::from_str::<Value>(&claim.subject_json)
        .map_err(|error| format!("invalid subject JSON: {error}"))?;
    let assertion = serde_json::from_str::<Value>(&claim.claim_json)
        .map_err(|error| format!("invalid claim JSON: {error}"))?;
    let confidence = serde_json::Number::from_f64(claim.confidence)
        .ok_or_else(|| "claim confidence must be finite".to_owned())?;
    let evidence = claim
        .evidence
        .iter()
        .map(|item| {
            let mut value = Map::new();
            value.insert("kind".to_owned(), Value::String(item.kind.clone()));
            value.insert(
                "description".to_owned(),
                Value::String(item.description.clone()),
            );
            if let Some(data) = &item.data_json {
                value.insert(
                    "data".to_owned(),
                    serde_json::from_str(data)
                        .map_err(|error| format!("invalid evidence data JSON: {error}"))?,
                );
            }
            Ok(Value::Object(value))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!({
        "subject": subject,
        "claim": assertion,
        "confidence": Value::Number(confidence),
        "evidence": evidence,
    }))
}

fn log_level_name(level: types::LogLevel) -> &'static str {
    match level {
        types::LogLevel::Trace => "trace",
        types::LogLevel::Debug => "debug",
        types::LogLevel::Info => "info",
        types::LogLevel::Warn => "warn",
        types::LogLevel::Error => "error",
    }
}

fn binary_format_name(format: &BinaryFormat) -> String {
    match format {
        BinaryFormat::Pe => "pe".to_owned(),
        BinaryFormat::Elf => "elf".to_owned(),
        BinaryFormat::MachO => "mach-o".to_owned(),
        BinaryFormat::Wasm => "wasm".to_owned(),
        BinaryFormat::Other(value) => value.clone(),
        _ => "unknown".to_owned(),
    }
}

fn validate_wasm_plugin<'a>(
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
    if !matches!(&manifest.runtime, PluginRuntime::Wasm { .. }) {
        return Err(PluginRuntimeError::UnsupportedRuntime(
            manifest.runtime.kind(),
        ));
    }
    if manifest.id.as_str().len() > MAX_IDENTIFIER_BYTES
        || manifest.name.len() > MAX_METADATA_NAME_BYTES
        || manifest.version.to_string().len() > MAX_METADATA_VERSION_BYTES
        || manifest.capabilities.len() > MAX_METADATA_IDENTIFIERS
        || manifest.permissions.len() > MAX_METADATA_IDENTIFIERS
        || manifest
            .capabilities
            .iter()
            .map(PluginCapability::as_str)
            .chain(manifest.permissions.iter().map(PluginPermission::as_str))
            .any(|value| value.len() > MAX_IDENTIFIER_BYTES)
    {
        return Err(invalid_context(
            "manifest exceeds a Wasm metadata field or item limit",
        ));
    }
    for permission in request.granted_permissions() {
        if !manifest.permissions.contains(permission) {
            return Err(PluginRuntimeError::PermissionNotRequested(
                permission.to_string(),
            ));
        }
        if !matches!(
            permission.as_str(),
            PluginPermission::BINARY_READ | PluginPermission::CLAIMS_SUBMIT
        ) {
            return Err(invalid_context(format!(
                "Wasm protocol 0.1 does not expose `{permission}`"
            )));
        }
    }
    Ok(manifest)
}

fn validate_wasm_request(request: &ExternalProcessRequest) -> Result<(), PluginRuntimeError> {
    if request.method() != PluginMethod::Analyze {
        return Err(invalid_context(
            "the Wasm v1 host accepts only analyze requests",
        ));
    }
    if request.id().len() > MAX_IDENTIFIER_BYTES
        || request.session_id().len() > MAX_IDENTIFIER_BYTES
    {
        return Err(invalid_context(
            "Wasm request and session identifiers must be at most 128 UTF-8 bytes",
        ));
    }
    if request.granted_permissions().len() > MAX_METADATA_IDENTIFIERS {
        return Err(invalid_context(
            "Wasm request exceeds the granted-permission item limit",
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
        .ok_or_else(|| invalid_context("Wasm analyze request is missing its binary identity"))?;
    let found = serde_json::from_value::<BinaryIdentity>(value.clone()).map_err(|error| {
        invalid_context(format!(
            "Wasm analyze request has an invalid binary identity: {error}"
        ))
    })?;
    if &found != expected {
        return Err(invalid_context(
            "Wasm analyze request binary identity does not match the exact PE image",
        ));
    }
    Ok(())
}

fn verify_artifact(
    root: &std::path::Path,
    expected: ArtifactFingerprint,
    stage: &'static str,
) -> Result<(), PluginRuntimeError> {
    let report =
        fingerprint_plugin_directory(root, FingerprintLimits::default()).map_err(|error| {
            PluginRuntimeError::WasmArtifactMismatch {
                reason: format!("could not fingerprint plugin {stage}: {error}"),
            }
        })?;
    if report.fingerprint != expected {
        return Err(PluginRuntimeError::WasmArtifactMismatch {
            reason: format!(
                "fingerprint {stage} was {}, expected {expected}",
                report.fingerprint
            ),
        });
    }
    Ok(())
}

fn invalid_context(reason: impl Into<String>) -> PluginRuntimeError {
    PluginRuntimeError::InvalidWasmContext(reason.into())
}

struct EpochTimer {
    cancel: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}

impl EpochTimer {
    fn start(engine: Engine, timeout: Duration) -> Result<Self, PluginRuntimeError> {
        let (cancel, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("resymbol-wasm-deadline".to_owned())
            .spawn(move || {
                if receiver.recv_timeout(timeout).is_err() {
                    engine.increment_epoch();
                }
            })
            .map_err(|error| PluginRuntimeError::WasmEngineUnavailable {
                reason: format!("could not start deadline worker: {error}"),
            })?;
        Ok(Self {
            cancel,
            worker: Some(worker),
        })
    }
}

impl Drop for EpochTimer {
    fn drop(&mut self) {
        let _ = self.cancel.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryReadFailure {
    OutsideImage,
    CallLimit,
}

fn copy_available(bytes: &[u8], start: usize, available: usize, requested: usize) -> Vec<u8> {
    let count = available
        .min(requested)
        .min(bytes.len().saturating_sub(start));
    bytes
        .get(start..start.saturating_add(count))
        .unwrap_or_default()
        .to_vec()
}

const DOS_HEADER_SIZE: usize = 64;
const MAX_PE_HEADER_OFFSET: u32 = 16 * 1024 * 1024;
const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const OPTIONAL_HEADER_MIN_SIZE: usize = 112;
const DATA_DIRECTORY_SIZE: usize = 8;
const MAX_DATA_DIRECTORIES: usize = 16;
const MACHINE_AMD64: u16 = 0x8664;
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x20b;

#[derive(Debug, PartialEq, Eq)]
struct ParsedPeImage {
    image_base: u64,
    size_of_headers: u32,
    size_of_image: u32,
    sections: Vec<WasmPeImageSection>,
}

fn parse_pe_image(bytes: &[u8]) -> Result<ParsedPeImage, PluginRuntimeError> {
    if read_bytes(bytes, 0, 2, "DOS signature")? != b"MZ" {
        return Err(invalid_context(
            "analysis bytes do not have an MZ signature",
        ));
    }
    read_bytes(bytes, 0, DOS_HEADER_SIZE, "DOS header")?;
    let pe_offset_u32 = read_u32(bytes, 0x3c, "DOS e_lfanew")?;
    if !(u32::try_from(DOS_HEADER_SIZE).unwrap_or(u32::MAX)..=MAX_PE_HEADER_OFFSET)
        .contains(&pe_offset_u32)
    {
        return Err(invalid_context(
            "DOS e_lfanew is outside the supported range",
        ));
    }
    let pe_offset = usize::try_from(pe_offset_u32)
        .map_err(|_| invalid_context("PE header offset does not fit this host"))?;
    if read_bytes(bytes, pe_offset, PE_SIGNATURE_SIZE, "PE signature")? != b"PE\0\0" {
        return Err(invalid_context("analysis bytes do not have a PE signature"));
    }

    let coff_offset = checked_add(pe_offset, PE_SIGNATURE_SIZE, "COFF header offset")?;
    read_bytes(bytes, coff_offset, COFF_HEADER_SIZE, "COFF header")?;
    if read_u16(bytes, coff_offset, "COFF machine")? != MACHINE_AMD64 {
        return Err(invalid_context("PE machine is not AMD64"));
    }
    let section_count = usize::from(read_u16(bytes, coff_offset + 2, "COFF section count")?);
    if section_count > MAX_PE_SECTIONS {
        return Err(invalid_context(format!(
            "PE exceeds the {MAX_PE_SECTIONS}-section limit"
        )));
    }
    let optional_size = usize::from(read_u16(
        bytes,
        coff_offset + 16,
        "COFF optional-header size",
    )?);
    if optional_size < OPTIONAL_HEADER_MIN_SIZE {
        return Err(invalid_context("PE32+ optional header is too small"));
    }
    let optional_offset = checked_add(coff_offset, COFF_HEADER_SIZE, "optional-header offset")?;
    read_bytes(
        bytes,
        optional_offset,
        optional_size,
        "PE32+ optional header",
    )?;
    if read_u16(bytes, optional_offset, "optional-header magic")? != OPTIONAL_MAGIC_PE32_PLUS {
        return Err(invalid_context(
            "analysis bytes do not use the PE32+ optional header",
        ));
    }

    let image_base = read_u64(bytes, optional_offset + 24, "PE image base")?;
    let section_alignment = read_u32(bytes, optional_offset + 32, "section alignment")?;
    let file_alignment = read_u32(bytes, optional_offset + 36, "file alignment")?;
    if section_alignment == 0 || file_alignment == 0 {
        return Err(invalid_context("PE section/file alignment must be nonzero"));
    }
    let size_of_image = read_u32(bytes, optional_offset + 56, "size of image")?;
    let size_of_headers = read_u32(bytes, optional_offset + 60, "size of headers")?;
    if size_of_headers == 0 || size_of_image == 0 || size_of_headers > size_of_image {
        return Err(invalid_context(
            "PE header and image sizes are inconsistent",
        ));
    }
    let headers_size = usize::try_from(size_of_headers)
        .map_err(|_| invalid_context("PE header size does not fit this host"))?;
    read_bytes(bytes, 0, headers_size, "declared PE headers")?;

    let directory_count = usize::try_from(read_u32(
        bytes,
        optional_offset + 108,
        "data-directory count",
    )?)
    .map_err(|_| invalid_context("PE directory count does not fit this host"))?;
    if directory_count > MAX_DATA_DIRECTORIES {
        return Err(invalid_context(format!(
            "PE exceeds the {MAX_DATA_DIRECTORIES}-data-directory limit"
        )));
    }
    let required_optional_size = checked_add(
        OPTIONAL_HEADER_MIN_SIZE,
        checked_mul(
            directory_count,
            DATA_DIRECTORY_SIZE,
            "data-directory table size",
        )?,
        "required optional-header size",
    )?;
    if optional_size < required_optional_size {
        return Err(invalid_context(
            "PE optional header truncates its data-directory table",
        ));
    }

    let sections_offset = checked_add(optional_offset, optional_size, "section-table offset")?;
    let section_table_size = checked_mul(section_count, SECTION_HEADER_SIZE, "section-table size")?;
    let section_table_end = checked_add(sections_offset, section_table_size, "section-table end")?;
    if section_table_end > headers_size {
        return Err(invalid_context(
            "PE section table extends beyond the declared headers",
        ));
    }
    read_bytes(
        bytes,
        sections_offset,
        section_table_size,
        "PE section table",
    )?;

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = checked_add(
            sections_offset,
            checked_mul(index, SECTION_HEADER_SIZE, "section-header position")?,
            "section-header offset",
        )?;
        let section = WasmPeImageSection {
            virtual_size: read_u32(bytes, offset + 8, "section virtual size")?,
            virtual_address: read_u32(bytes, offset + 12, "section virtual address")?,
            raw_data_size: read_u32(bytes, offset + 16, "section raw-data size")?,
            raw_data_offset: read_u32(bytes, offset + 20, "section raw-data offset")?,
        };
        validate_parsed_section(bytes, size_of_headers, size_of_image, index, &section)?;
        sections.push(section);
    }
    validate_section_overlaps(&sections)?;

    Ok(ParsedPeImage {
        image_base,
        size_of_headers,
        size_of_image,
        sections,
    })
}

fn validate_parsed_section(
    bytes: &[u8],
    size_of_headers: u32,
    size_of_image: u32,
    index: usize,
    section: &WasmPeImageSection,
) -> Result<(), PluginRuntimeError> {
    let virtual_size = section.loaded_size();
    let virtual_end = section
        .virtual_address
        .checked_add(virtual_size)
        .ok_or_else(|| invalid_context(format!("PE section {index} virtual range overflows")))?;
    if virtual_end > size_of_image
        || (virtual_size != 0 && section.virtual_address < size_of_headers)
    {
        return Err(invalid_context(format!(
            "PE section {index} has an invalid virtual range"
        )));
    }

    let raw_end = section
        .raw_data_offset
        .checked_add(section.raw_data_size)
        .ok_or_else(|| invalid_context(format!("PE section {index} file range overflows")))?;
    if usize::try_from(raw_end).map_or(true, |end| end > bytes.len())
        || (section.raw_data_size != 0 && section.raw_data_offset < size_of_headers)
    {
        return Err(invalid_context(format!(
            "PE section {index} has an invalid file range"
        )));
    }
    Ok(())
}

fn validate_section_overlaps(sections: &[WasmPeImageSection]) -> Result<(), PluginRuntimeError> {
    for first in 0..sections.len() {
        for second in first + 1..sections.len() {
            let left = &sections[first];
            let right = &sections[second];
            if ranges_overlap(
                left.virtual_address,
                left.loaded_size(),
                right.virtual_address,
                right.loaded_size(),
            )? {
                return Err(invalid_context(format!(
                    "PE sections {first} and {second} overlap in virtual memory"
                )));
            }
            if ranges_overlap(
                left.raw_data_offset,
                left.raw_data_size,
                right.raw_data_offset,
                right.raw_data_size,
            )? {
                return Err(invalid_context(format!(
                    "PE sections {first} and {second} overlap in the source file"
                )));
            }
        }
    }
    Ok(())
}

fn ranges_overlap(
    left_start: u32,
    left_size: u32,
    right_start: u32,
    right_size: u32,
) -> Result<bool, PluginRuntimeError> {
    if left_size == 0 || right_size == 0 {
        return Ok(false);
    }
    let left_end = left_start
        .checked_add(left_size)
        .ok_or_else(|| invalid_context("PE section range overflows"))?;
    let right_end = right_start
        .checked_add(right_size)
        .ok_or_else(|| invalid_context("PE section range overflows"))?;
    Ok(left_start < right_end && right_start < left_end)
}

fn read_bytes<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    field: &'static str,
) -> Result<&'a [u8], PluginRuntimeError> {
    let end = checked_add(offset, length, field)?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid_context(format!("PE truncates {field}")))
}

fn read_u16(bytes: &[u8], offset: usize, field: &'static str) -> Result<u16, PluginRuntimeError> {
    let value = read_bytes(bytes, offset, 2, field)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize, field: &'static str) -> Result<u32, PluginRuntimeError> {
    let value = read_bytes(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize, field: &'static str) -> Result<u64, PluginRuntimeError> {
    let value = read_bytes(bytes, offset, 8, field)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn checked_add(
    left: usize,
    right: usize,
    field: &'static str,
) -> Result<usize, PluginRuntimeError> {
    left.checked_add(right)
        .ok_or_else(|| invalid_context(format!("PE {field} overflows")))
}

fn checked_mul(
    left: usize,
    right: usize,
    field: &'static str,
) -> Result<usize, PluginRuntimeError> {
    left.checked_mul(right)
        .ok_or_else(|| invalid_context(format!("PE {field} overflows")))
}

#[cfg(test)]
mod pe_image_tests {
    use super::*;

    fn section(
        virtual_address: u32,
        virtual_size: u32,
        raw_data_offset: u32,
    ) -> WasmPeImageSection {
        WasmPeImageSection {
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size: 0x200,
        }
    }

    #[test]
    fn rva_reads_exclude_raw_padding_and_keep_zero_virtual_size_fallback() {
        let bytes = (0_u8..=255).cycle().take(0x800).collect::<Vec<_>>();
        let mut image = WasmPeImage {
            identity: BinaryIdentity {
                id: BinaryId::digest(&bytes),
                size: bytes.len() as u64,
                format: BinaryFormat::Pe,
                architecture: "x86_64".to_owned(),
                image_base: 0x0001_4000_0000,
            },
            size_of_headers: 0x200,
            size_of_image: 0x2000,
            sections: vec![section(0x1000, 0x100, 0x200)],
            bytes: Arc::from(bytes),
        };

        assert_eq!(image.read_rva(0x10ff, 2).unwrap().len(), 1);
        assert!(image.read_rva(0x1100, 1).unwrap().is_empty());

        image.sections[0].virtual_size = 0;
        assert_eq!(image.read_rva(0x11ff, 2).unwrap().len(), 1);
        assert!(image.read_rva(0x1200, 1).unwrap().is_empty());
    }

    #[test]
    fn overlap_validation_uses_the_loaded_extent() {
        let mut sections = vec![
            WasmPeImageSection {
                raw_data_size: 0x1200,
                ..section(0x1000, 0x100, 0x200)
            },
            WasmPeImageSection {
                raw_data_size: 0x1200,
                ..section(0x2000, 0x100, 0x1400)
            },
        ];
        validate_section_overlaps(&sections)
            .expect("raw alignment padding does not overlap loaded sections");

        sections[0].virtual_size = 0;
        assert!(validate_section_overlaps(&sections).is_err());
    }
}
