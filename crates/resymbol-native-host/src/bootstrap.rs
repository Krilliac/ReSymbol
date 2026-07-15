use std::{
    collections::{BTreeSet, HashSet},
    io::{self, BufRead, Read},
    str::FromStr,
};

use resymbol_core::{BinaryFormat, BinaryIdentity};
use resymbol_plugin_api::{PluginId, PluginPermission};
use resymbol_plugin_state::ArtifactFingerprint;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::error::HostError;

pub(crate) const NATIVE_HOST_PROTOCOL: &str = "resymbol.native-host";
pub(crate) const PLUGIN_WIRE_PROTOCOL: &str = "resymbol.plugin-wire";
pub(crate) const PROTOCOL_MAJOR: u32 = 1;
pub(crate) const PROTOCOL_MINOR: u32 = 0;
const MAX_BOOTSTRAP_BYTES: usize = 256 * 1024;
const MAX_INITIAL_WIRE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SESSION_ID_BYTES: usize = 128;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_GRANTED_PERMISSIONS: usize = 256;
const MAX_REQUEST_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_ADVERTISED_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MIN_OUTPUT_MESSAGES: usize = 2;
const MIN_STDOUT_BYTES: usize = 1_024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeHostBootstrap {
    protocol: String,
    version: ProtocolVersion,
    expected_artifact_sha256: String,
    pub(crate) output_limits: NativeHostOutputLimits,
    pub(crate) binary: BinaryIdentity,
    pub(crate) image: PeImageMap,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeHostOutputLimits {
    pub(crate) max_messages: usize,
    pub(crate) max_stdout_bytes: usize,
}

impl NativeHostBootstrap {
    pub(crate) fn artifact_fingerprint(&self) -> Result<ArtifactFingerprint, HostError> {
        ArtifactFingerprint::from_str(&self.expected_artifact_sha256).map_err(|error| {
            HostError::Bootstrap(format!("invalid expected artifact fingerprint: {error}"))
        })
    }

    fn validate(&self) -> Result<(), HostError> {
        validate_versioned_protocol(
            &self.protocol,
            &self.version,
            NATIVE_HOST_PROTOCOL,
            "native-host bootstrap",
        )?;
        self.artifact_fingerprint()?;
        self.binary
            .validate()
            .map_err(|error| HostError::Bootstrap(error.to_string()))?;
        if !matches!(self.binary.format, BinaryFormat::Pe) {
            return Err(HostError::Bootstrap(
                "the first native host accepts only PE binary maps".to_owned(),
            ));
        }
        if self.binary.architecture != "x86_64" {
            return Err(HostError::Bootstrap(
                "the first native host accepts only x86_64 binary maps".to_owned(),
            ));
        }
        if self.output_limits.max_messages < MIN_OUTPUT_MESSAGES {
            return Err(HostError::Bootstrap(format!(
                "max_messages must reserve at least {MIN_OUTPUT_MESSAGES} protocol messages"
            )));
        }
        if self.output_limits.max_stdout_bytes < MIN_STDOUT_BYTES {
            return Err(HostError::Bootstrap(format!(
                "max_stdout_bytes must be at least {MIN_STDOUT_BYTES}"
            )));
        }
        self.image.validate(&self.binary)
    }

    fn validate_output_limits(&self, limits: &WireLimits) -> Result<(), HostError> {
        if self.output_limits.max_stdout_bytes < limits.max_message_bytes {
            return Err(HostError::Bootstrap(
                "max_stdout_bytes must be at least max_message_bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeImageMap {
    pub(crate) size_of_headers: u32,
    pub(crate) size_of_image: u32,
    pub(crate) sections: Vec<PeImageSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeImageSection {
    pub(crate) virtual_address: u32,
    pub(crate) virtual_size: u32,
    pub(crate) raw_data_offset: u32,
    pub(crate) raw_data_size: u32,
}

impl PeImageMap {
    fn validate(&self, identity: &BinaryIdentity) -> Result<(), HostError> {
        if self.size_of_headers == 0 || self.size_of_image == 0 {
            return Err(HostError::Bootstrap(
                "PE image and header sizes must be nonzero".to_owned(),
            ));
        }
        if self.size_of_headers > self.size_of_image
            || u64::from(self.size_of_headers) > identity.size
        {
            return Err(HostError::Bootstrap(
                "PE header size is inconsistent with the exact binary".to_owned(),
            ));
        }
        if self.sections.len() > 96 {
            return Err(HostError::Bootstrap(
                "PE image map exceeds the 96-section limit".to_owned(),
            ));
        }

        let mut virtual_ranges = Vec::with_capacity(self.sections.len());
        for section in &self.sections {
            let virtual_start = u64::from(section.virtual_address);
            let virtual_size = u64::from(section.virtual_size.max(section.raw_data_size));
            let virtual_end = virtual_start.checked_add(virtual_size).ok_or_else(|| {
                HostError::Bootstrap("PE section virtual range overflows".to_owned())
            })?;
            if virtual_end > u64::from(self.size_of_image) {
                return Err(HostError::Bootstrap(
                    "PE section extends beyond the declared image".to_owned(),
                ));
            }
            let raw_end = u64::from(section.raw_data_offset)
                .checked_add(u64::from(section.raw_data_size))
                .ok_or_else(|| {
                    HostError::Bootstrap("PE section file range overflows".to_owned())
                })?;
            if raw_end > identity.size {
                return Err(HostError::Bootstrap(
                    "PE section extends beyond the exact binary".to_owned(),
                ));
            }
            if virtual_size != 0 {
                virtual_ranges.push((virtual_start, virtual_end));
            }
        }
        virtual_ranges.sort_unstable();
        if virtual_ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(HostError::Bootstrap(
                "PE image map contains overlapping virtual sections".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolVersion {
    major: u32,
    minor: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostHello {
    protocol: String,
    version: ProtocolVersion,
    kind: String,
    session_id: String,
    plugin_id: String,
    granted_permissions: Vec<String>,
    limits: WireLimits,
    isolation: WireIsolation,
}

impl HostHello {
    pub(crate) fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub(crate) const fn limits(&self) -> &WireLimits {
        &self.limits
    }

    pub(crate) fn granted_permissions(&self) -> Result<BTreeSet<PluginPermission>, HostError> {
        self.granted_permissions
            .iter()
            .map(|permission| {
                PluginPermission::new(permission.clone())
                    .map_err(|error| HostError::Wire(error.to_string()))
            })
            .collect()
    }

    fn validate(&self) -> Result<(), HostError> {
        validate_versioned_protocol(
            &self.protocol,
            &self.version,
            PLUGIN_WIRE_PROTOCOL,
            "plugin hello",
        )?;
        if self.kind != "hello" {
            return Err(HostError::Wire(
                "first wire message is not hello".to_owned(),
            ));
        }
        validate_text("session id", &self.session_id, MAX_SESSION_ID_BYTES)?;
        PluginId::new(self.plugin_id.clone())
            .map_err(|error| HostError::Wire(format!("invalid hello plugin id: {error}")))?;
        if self.granted_permissions.len() > MAX_GRANTED_PERMISSIONS {
            return Err(HostError::Wire(format!(
                "hello exceeds the {MAX_GRANTED_PERMISSIONS}-permission limit"
            )));
        }
        let mut unique = HashSet::with_capacity(self.granted_permissions.len());
        for permission in &self.granted_permissions {
            PluginPermission::new(permission.clone())
                .map_err(|error| HostError::Wire(format!("invalid granted permission: {error}")))?;
            if !unique.insert(permission) {
                return Err(HostError::Wire(
                    "hello contains a duplicate granted permission".to_owned(),
                ));
            }
        }
        self.limits.validate()?;
        if self.isolation.mode != "process" || !self.isolation.required {
            return Err(HostError::Wire(
                "native helper requires process isolation".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireLimits {
    pub(crate) max_message_bytes: usize,
    pub(crate) max_memory_bytes: u64,
    pub(crate) request_timeout_ms: u64,
}

impl WireLimits {
    fn validate(&self) -> Result<(), HostError> {
        if !(1_024..=MAX_INITIAL_WIRE_BYTES).contains(&self.max_message_bytes) {
            return Err(HostError::Wire(format!(
                "max_message_bytes must be in 1024..={MAX_INITIAL_WIRE_BYTES}"
            )));
        }
        if !(1_048_576..=MAX_ADVERTISED_MEMORY_BYTES).contains(&self.max_memory_bytes) {
            return Err(HostError::Wire(
                "max_memory_bytes is outside the supported range".to_owned(),
            ));
        }
        if !(1..=MAX_REQUEST_TIMEOUT_MS).contains(&self.request_timeout_ms) {
            return Err(HostError::Wire(
                "request_timeout_ms is outside the supported range".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIsolation {
    mode: String,
    required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostRequest {
    protocol: String,
    version: ProtocolVersion,
    kind: String,
    direction: String,
    id: String,
    method: String,
    payload: Map<String, Value>,
}

impl HostRequest {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self, bootstrap: &NativeHostBootstrap) -> Result<(), HostError> {
        validate_versioned_protocol(
            &self.protocol,
            &self.version,
            PLUGIN_WIRE_PROTOCOL,
            "plugin request",
        )?;
        if self.kind != "request" || self.direction != "host-to-plugin" {
            return Err(HostError::Wire(
                "second wire message is not a host-to-plugin request".to_owned(),
            ));
        }
        validate_text("request id", &self.id, MAX_REQUEST_ID_BYTES)?;
        if self.method != "analyze" {
            return Err(HostError::Wire(
                "the first native host supports only analyze requests".to_owned(),
            ));
        }
        let request_binary = self.payload.get("binary").ok_or_else(|| {
            HostError::Wire("analyze request is missing its binary identity".to_owned())
        })?;
        let request_binary = serde_json::from_value::<BinaryIdentity>(request_binary.clone())
            .map_err(|error| HostError::Json {
                kind: "request binary identity",
                source: error,
            })?;
        if request_binary != bootstrap.binary {
            return Err(HostError::Wire(
                "request binary identity does not match native-host bootstrap".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct HostInput {
    pub(crate) bootstrap: NativeHostBootstrap,
    pub(crate) hello: HostHello,
    pub(crate) request: HostRequest,
    pub(crate) hello_json: Vec<u8>,
    pub(crate) request_json: Vec<u8>,
}

impl HostInput {
    pub(crate) fn read(reader: impl io::Read) -> Result<Self, HostError> {
        let mut reader = io::BufReader::new(reader);
        let bootstrap_json = read_line(&mut reader, "native-host bootstrap", MAX_BOOTSTRAP_BYTES)?;
        let bootstrap = decode::<NativeHostBootstrap>(&bootstrap_json, "native-host bootstrap")?;
        bootstrap.validate()?;

        let hello_json = read_line(&mut reader, "plugin hello", MAX_INITIAL_WIRE_BYTES)?;
        let hello = decode::<HostHello>(&hello_json, "plugin hello")?;
        hello.validate()?;
        bootstrap.validate_output_limits(&hello.limits)?;
        if hello_json.len() > hello.limits.max_message_bytes {
            return Err(HostError::InputLimit {
                kind: "plugin hello",
                limit: hello.limits.max_message_bytes,
            });
        }

        let request_json = read_line(
            &mut reader,
            "plugin request",
            hello.limits.max_message_bytes,
        )?;
        let request = decode::<HostRequest>(&request_json, "plugin request")?;
        request.validate(&bootstrap)?;

        let mut trailing = [0_u8; 1];
        if reader
            .read(&mut trailing)
            .map_err(|error| HostError::io("read native-host stdin", error))?
            != 0
        {
            return Err(HostError::Wire(
                "native-host input contains trailing data".to_owned(),
            ));
        }

        Ok(Self {
            bootstrap,
            hello,
            request,
            hello_json,
            request_json,
        })
    }
}

fn read_line(
    reader: &mut impl BufRead,
    kind: &'static str,
    limit: usize,
) -> Result<Vec<u8>, HostError> {
    let mut bytes = Vec::with_capacity(limit.min(8_192));
    let read = Read::by_ref(reader)
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(2))
        .read_until(b'\n', &mut bytes)
        .map_err(|error| HostError::io("read native-host stdin", error))?;
    if read == 0 {
        return Err(HostError::Wire(format!("missing {kind}")));
    }
    if bytes.last() != Some(&b'\n') {
        if bytes.len() > limit {
            return Err(HostError::InputLimit { kind, limit });
        }
        return Err(HostError::Wire(format!("{kind} is not newline terminated")));
    }
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(HostError::Wire(format!("{kind} must not be empty")));
    }
    if bytes.len() > limit {
        return Err(HostError::InputLimit { kind, limit });
    }
    Ok(bytes)
}

fn decode<T>(bytes: &[u8], kind: &'static str) -> Result<T, HostError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(bytes).map_err(|source| HostError::Json { kind, source })
}

fn validate_versioned_protocol(
    protocol: &str,
    version: &ProtocolVersion,
    expected: &str,
    context: &str,
) -> Result<(), HostError> {
    if protocol != expected || version.major != PROTOCOL_MAJOR || version.minor != PROTOCOL_MINOR {
        return Err(HostError::Wire(format!(
            "unsupported {context} protocol/version"
        )));
    }
    Ok(())
}

fn validate_text(label: &str, text: &str, limit: usize) -> Result<(), HostError> {
    if text.is_empty() || text.len() > limit || text.chars().any(|character| character.is_control())
    {
        return Err(HostError::Wire(format!("invalid {label}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bootstrap_with_output_limits(
        max_messages: usize,
        max_stdout_bytes: usize,
    ) -> NativeHostBootstrap {
        NativeHostBootstrap {
            protocol: NATIVE_HOST_PROTOCOL.to_owned(),
            version: ProtocolVersion { major: 1, minor: 0 },
            expected_artifact_sha256: "11".repeat(32),
            output_limits: NativeHostOutputLimits {
                max_messages,
                max_stdout_bytes,
            },
            binary: BinaryIdentity {
                id: resymbol_core::BinaryId::digest(&[0]),
                size: 1,
                format: BinaryFormat::Pe,
                architecture: "x86_64".to_owned(),
                image_base: 0x0001_4000_0000,
            },
            image: PeImageMap {
                size_of_headers: 1,
                size_of_image: 1,
                sections: Vec::new(),
            },
        }
    }

    #[test]
    fn image_map_rejects_overlapping_sections() {
        let identity = BinaryIdentity {
            id: resymbol_core::BinaryId::digest(&vec![0_u8; 0x500]),
            size: 0x500,
            format: BinaryFormat::Pe,
            architecture: "x86_64".to_owned(),
            image_base: 0x0001_4000_0000,
        };
        let section = |virtual_address| PeImageSection {
            virtual_address,
            virtual_size: 0x200,
            raw_data_offset: 0x100,
            raw_data_size: 0x200,
        };
        let map = PeImageMap {
            size_of_headers: 0x100,
            size_of_image: 0x3000,
            sections: vec![section(0x1000), section(0x1100)],
        };
        assert!(map.validate(&identity).is_err());
    }

    #[test]
    fn input_requires_exactly_bootstrap_hello_and_analyze_request() {
        let identity = json!({
            "id": "00".repeat(32),
            "size": 1,
            "format": "pe",
            "architecture": "x86_64",
            "image_base": 0x0001_4000_0000_u64
        });
        let bootstrap = json!({
            "protocol": NATIVE_HOST_PROTOCOL,
            "version": { "major": 1, "minor": 0 },
            "expected_artifact_sha256": "11".repeat(32),
            "output_limits": {
                "max_messages": 4096,
                "max_stdout_bytes": 8388608
            },
            "binary": identity,
            "image": {
                "size_of_headers": 1,
                "size_of_image": 1,
                "sections": []
            }
        });
        let hello = json!({
            "protocol": PLUGIN_WIRE_PROTOCOL,
            "version": { "major": 1, "minor": 0 },
            "kind": "hello",
            "session_id": "session-1",
            "plugin_id": "dev.example.plugin",
            "granted_permissions": ["claims.submit"],
            "limits": {
                "max_message_bytes": 4096,
                "max_memory_bytes": 1048576,
                "request_timeout_ms": 30000
            },
            "isolation": { "mode": "process", "required": true }
        });
        let request = json!({
            "protocol": PLUGIN_WIRE_PROTOCOL,
            "version": { "major": 1, "minor": 0 },
            "kind": "request",
            "direction": "host-to-plugin",
            "id": "request-1",
            "method": "analyze",
            "payload": { "binary": identity }
        });
        let input = format!("{bootstrap}\n{hello}\n{request}\n");
        let parsed = HostInput::read(input.as_bytes()).unwrap();
        assert_eq!(parsed.hello.plugin_id(), "dev.example.plugin");
        assert_eq!(parsed.request.id(), "request-1");

        let trailing = format!("{input}unexpected");
        assert!(HostInput::read(trailing.as_bytes()).is_err());
    }

    #[test]
    fn bootstrap_output_limits_reserve_protocol_framing_and_parent_capacity() {
        let wire = WireLimits {
            max_message_bytes: 4_096,
            max_memory_bytes: 1_048_576,
            request_timeout_ms: 30_000,
        };
        let valid = bootstrap_with_output_limits(2, 4_096);
        valid.validate().unwrap();
        valid.validate_output_limits(&wire).unwrap();

        assert!(bootstrap_with_output_limits(1, 4_096).validate().is_err());
        assert!(bootstrap_with_output_limits(2, 1_023).validate().is_err());
        let undersized = bootstrap_with_output_limits(2, 2_048);
        undersized.validate().unwrap();
        assert!(undersized.validate_output_limits(&wire).is_err());
    }
}
