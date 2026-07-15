use std::{
    collections::BTreeSet,
    io::{self, Write},
};

#[cfg(test)]
use resymbol_core::{EvidenceKind, StringEncoding, SymbolAssertion};
use resymbol_core::{
    SymbolClaim,
    plugin_api::{PluginCapability, PluginId, PluginManifest, PluginPermission},
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

#[cfg(test)]
use crate::claim::WireClaim;
use crate::{
    ExternalProcessRequest, PluginDescriptor, PluginExecution, PluginLog, PluginResponse,
    PluginRuntimeError, ProcessDiagnostics, RuntimeLimits, StreamKind,
    claim::{ClaimDecodeError, decode_claim},
};

const PROTOCOL: &str = "resymbol.plugin-wire";
const PROTOCOL_MAJOR: u32 = 1;
const PROTOCOL_MINOR: u32 = 0;

#[derive(Serialize)]
struct ProtocolVersion {
    major: u32,
    minor: u32,
}

#[derive(Serialize)]
struct WireLimits {
    max_message_bytes: usize,
    max_memory_bytes: u64,
    request_timeout_ms: u64,
}

#[derive(Serialize)]
struct ProcessIsolation {
    mode: &'static str,
    required: bool,
}

#[derive(Serialize)]
struct HostHello<'a> {
    protocol: &'static str,
    version: ProtocolVersion,
    kind: &'static str,
    session_id: &'a str,
    plugin_id: &'a str,
    granted_permissions: Vec<&'a str>,
    limits: WireLimits,
    isolation: ProcessIsolation,
}

#[derive(Serialize)]
struct HostRequest<'a> {
    protocol: &'static str,
    version: ProtocolVersion,
    kind: &'static str,
    direction: &'static str,
    id: &'a str,
    method: &'static str,
    payload: &'a Map<String, Value>,
}

pub(crate) fn encode_input(
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    limits: &RuntimeLimits,
) -> Result<Vec<u8>, PluginRuntimeError> {
    let request_timeout_ms = u64::try_from(limits.request_timeout.as_millis()).map_err(|_| {
        PluginRuntimeError::InvalidLimits(
            "request_timeout cannot be represented in protocol milliseconds",
        )
    })?;
    let granted_permissions = request
        .granted_permissions()
        .iter()
        .map(PluginPermission::as_str)
        .collect();
    let hello = HostHello {
        protocol: PROTOCOL,
        version: protocol_version(),
        kind: "hello",
        session_id: request.session_id(),
        plugin_id: manifest.id.as_str(),
        granted_permissions,
        limits: WireLimits {
            max_message_bytes: limits.max_message_bytes,
            max_memory_bytes: limits.advertised_max_memory_bytes,
            request_timeout_ms,
        },
        isolation: process_isolation(),
    };
    let wire_request = HostRequest {
        protocol: PROTOCOL,
        version: protocol_version(),
        kind: "request",
        direction: "host-to-plugin",
        id: request.id(),
        method: request.method().as_str(),
        payload: request.payload(),
    };

    let mut input = encode_message(&hello, limits.max_message_bytes)?;
    input.push(b'\n');
    input.extend(encode_message(&wire_request, limits.max_message_bytes)?);
    input.push(b'\n');
    Ok(input)
}

fn protocol_version() -> ProtocolVersion {
    ProtocolVersion {
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR,
    }
}

fn process_isolation() -> ProcessIsolation {
    ProcessIsolation {
        mode: "process",
        required: true,
    }
}

fn encode_message(
    value: &impl Serialize,
    max_message_bytes: usize,
) -> Result<Vec<u8>, PluginRuntimeError> {
    let mut writer = BoundedWriter::new(max_message_bytes);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(writer.bytes),
        Err(_error) if writer.exceeded => Err(PluginRuntimeError::StreamLimit {
            stream: StreamKind::Stdin,
            limit: max_message_bytes,
            diagnostics: ProcessDiagnostics::default(),
        }),
        Err(error) => Err(PluginRuntimeError::EncodeInput(error)),
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(4_096)),
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON message exceeded its limit"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum PluginOutput {
    HelloResult {
        protocol: String,
        version: WireProtocolVersion,
        descriptor: WireDescriptor,
    },
    Response {
        protocol: String,
        version: WireProtocolVersion,
        direction: String,
        id: String,
        ok: bool,
        #[serde(default)]
        result: Present<Value>,
        #[serde(default)]
        error: Present<WireError>,
    },
    Event {
        protocol: String,
        version: WireProtocolVersion,
        direction: String,
        method: String,
        payload: Value,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProtocolVersion {
    major: u32,
    minor: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIsolation {
    mode: String,
    required: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDescriptor {
    id: String,
    name: String,
    version: String,
    capabilities: Vec<String>,
    requested_permissions: Vec<String>,
    isolation: WireIsolation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    code: String,
    message: String,
    #[serde(default)]
    data: Present<Value>,
}

#[derive(Debug, Default)]
enum Present<T> {
    #[default]
    Missing,
    Value(T),
}

impl<'de, T> Deserialize<'de> for Present<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Value)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLog {
    level: String,
    message: String,
}

pub(crate) fn parse_output(
    stdout: &[u8],
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    limits: &RuntimeLimits,
    diagnostics: ProcessDiagnostics,
    exit_code: Option<i32>,
) -> Result<PluginExecution, PluginRuntimeError> {
    if stdout.is_empty() {
        return Err(protocol_error(
            1,
            "plugin produced no protocol output",
            diagnostics,
        ));
    }
    if !stdout.ends_with(b"\n") {
        return Err(protocol_error(
            1,
            "the final NDJSON message is not newline terminated",
            diagnostics,
        ));
    }

    let mut descriptor = None;
    let mut response = None;
    let mut claims = Vec::new();
    let mut logs = Vec::new();
    let mut message_count = 0_usize;

    for (index, raw_line) in stdout[..stdout.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        let line_number = index + 1;
        message_count = message_count.saturating_add(1);
        if message_count > limits.max_messages {
            return Err(PluginRuntimeError::MessageLimit {
                limit: limits.max_messages,
                diagnostics,
            });
        }
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if raw_line.is_empty() {
            return Err(protocol_error(
                line_number,
                "empty NDJSON messages are not allowed",
                diagnostics,
            ));
        }
        if raw_line.len() > limits.max_message_bytes {
            return Err(PluginRuntimeError::StreamLimit {
                stream: StreamKind::Stdout,
                limit: limits.max_message_bytes,
                diagnostics,
            });
        }

        let output = serde_json::from_slice::<PluginOutput>(raw_line).map_err(|source| {
            PluginRuntimeError::InvalidJson {
                line: line_number,
                source,
                diagnostics: diagnostics.clone(),
            }
        })?;
        match output {
            PluginOutput::HelloResult {
                protocol,
                version,
                descriptor: wire_descriptor,
            } => {
                validate_protocol(&protocol, &version, line_number, &diagnostics)?;
                if descriptor.is_some()
                    || response.is_some()
                    || !claims.is_empty()
                    || !logs.is_empty()
                {
                    return Err(protocol_error(
                        line_number,
                        "hello-result must be the first and only handshake response",
                        diagnostics,
                    ));
                }
                descriptor = Some(validate_descriptor(
                    wire_descriptor,
                    manifest,
                    line_number,
                    &diagnostics,
                )?);
            }
            PluginOutput::Event {
                protocol,
                version,
                direction,
                method,
                payload,
            } => {
                validate_protocol(&protocol, &version, line_number, &diagnostics)?;
                require_plugin_direction(&direction, line_number, &diagnostics)?;
                if descriptor.is_none() {
                    return Err(protocol_error(
                        line_number,
                        "event arrived before hello-result",
                        diagnostics,
                    ));
                }
                if response.is_some() {
                    return Err(protocol_error(
                        line_number,
                        "event arrived after the request response",
                        diagnostics,
                    ));
                }
                match method.as_str() {
                    "log" => logs.push(parse_log(payload, line_number, &diagnostics)?),
                    "claim" => {
                        if request.method() != crate::PluginMethod::Analyze {
                            return Err(PluginRuntimeError::ClaimEventNotAllowed {
                                method: request.method().as_str().to_owned(),
                                diagnostics,
                            });
                        }
                        let may_submit_claims =
                            request.granted_permissions().iter().any(|permission| {
                                permission.as_str() == PluginPermission::CLAIMS_SUBMIT
                            });
                        if !may_submit_claims {
                            return Err(PluginRuntimeError::PermissionDenied {
                                permission: PluginPermission::CLAIMS_SUBMIT.to_owned(),
                                diagnostics,
                            });
                        }
                        claims.push(parse_claim(
                            payload,
                            manifest,
                            request,
                            line_number,
                            &diagnostics,
                        )?);
                    }
                    _ => {
                        return Err(protocol_error(
                            line_number,
                            format!("unsupported event method `{method}`"),
                            diagnostics,
                        ));
                    }
                }
            }
            PluginOutput::Response {
                protocol,
                version,
                direction,
                id,
                ok,
                result,
                error,
            } => {
                validate_protocol(&protocol, &version, line_number, &diagnostics)?;
                require_plugin_direction(&direction, line_number, &diagnostics)?;
                if descriptor.is_none() {
                    return Err(protocol_error(
                        line_number,
                        "response arrived before hello-result",
                        diagnostics,
                    ));
                }
                if response.is_some() {
                    return Err(protocol_error(
                        line_number,
                        "plugin emitted more than one request response",
                        diagnostics,
                    ));
                }
                if id != request.id() {
                    return Err(protocol_error(
                        line_number,
                        format!(
                            "response id `{id}` does not match request id `{}`",
                            request.id()
                        ),
                        diagnostics,
                    ));
                }

                match (ok, result, error) {
                    (true, Present::Value(result), Present::Missing) => {
                        response = Some(PluginResponse { id, result });
                    }
                    (false, Present::Missing, Present::Value(error)) => {
                        validate_error_code(&error.code, line_number, &diagnostics)?;
                        let data = match error.data {
                            Present::Missing => None,
                            Present::Value(data) => Some(data),
                        };
                        return Err(PluginRuntimeError::PluginRejected {
                            code: error.code,
                            message: error.message,
                            data,
                            diagnostics,
                        });
                    }
                    _ => {
                        return Err(protocol_error(
                            line_number,
                            "successful responses require only result; failed responses require only error",
                            diagnostics,
                        ));
                    }
                }
            }
        }
    }

    let descriptor = descriptor.ok_or_else(|| {
        protocol_error(
            message_count.saturating_add(1),
            "plugin did not emit hello-result",
            diagnostics.clone(),
        )
    })?;
    let response = response.ok_or_else(|| {
        protocol_error(
            message_count.saturating_add(1),
            "plugin did not emit a matching response",
            diagnostics.clone(),
        )
    })?;
    Ok(PluginExecution {
        descriptor,
        response,
        claims,
        logs,
        diagnostics,
        exit_code,
    })
}

fn validate_protocol(
    protocol: &str,
    version: &WireProtocolVersion,
    line: usize,
    diagnostics: &ProcessDiagnostics,
) -> Result<(), PluginRuntimeError> {
    if protocol != PROTOCOL {
        return Err(protocol_error(
            line,
            format!("unexpected protocol `{protocol}`"),
            diagnostics.clone(),
        ));
    }
    if version.major != PROTOCOL_MAJOR || version.minor != PROTOCOL_MINOR {
        return Err(protocol_error(
            line,
            format!(
                "unsupported protocol version {}.{}; host supports {PROTOCOL_MAJOR}.{PROTOCOL_MINOR}",
                version.major, version.minor
            ),
            diagnostics.clone(),
        ));
    }
    Ok(())
}

fn require_plugin_direction(
    direction: &str,
    line: usize,
    diagnostics: &ProcessDiagnostics,
) -> Result<(), PluginRuntimeError> {
    if direction == "plugin-to-host" {
        Ok(())
    } else {
        Err(protocol_error(
            line,
            format!("unexpected message direction `{direction}`"),
            diagnostics.clone(),
        ))
    }
}

fn validate_descriptor(
    wire: WireDescriptor,
    manifest: &PluginManifest,
    line: usize,
    diagnostics: &ProcessDiagnostics,
) -> Result<PluginDescriptor, PluginRuntimeError> {
    let parsed_id = PluginId::new(wire.id.clone()).map_err(|error| {
        protocol_error(
            line,
            format!("invalid descriptor plugin id: {error}"),
            diagnostics.clone(),
        )
    })?;
    if parsed_id != manifest.id {
        return Err(protocol_error(
            line,
            format!(
                "descriptor id `{}` does not match manifest id `{}`",
                parsed_id, manifest.id
            ),
            diagnostics.clone(),
        ));
    }
    if wire.name.trim().is_empty() || wire.name != manifest.name {
        return Err(protocol_error(
            line,
            "descriptor name does not match the manifest",
            diagnostics.clone(),
        ));
    }
    if wire.version != manifest.version.to_string() {
        return Err(protocol_error(
            line,
            "descriptor version does not match the manifest",
            diagnostics.clone(),
        ));
    }
    if wire.isolation.mode != "process" || !wire.isolation.required {
        return Err(protocol_error(
            line,
            "descriptor must require process isolation",
            diagnostics.clone(),
        ));
    }

    let capabilities = validate_unique_identifiers(
        &wire.capabilities,
        "capability",
        line,
        diagnostics,
        |value| PluginCapability::new(value.to_owned()).map(|item| item.to_string()),
    )?;
    let manifest_capabilities = manifest
        .capabilities
        .iter()
        .map(|item| item.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if capabilities != manifest_capabilities {
        return Err(protocol_error(
            line,
            "descriptor capabilities do not match the manifest",
            diagnostics.clone(),
        ));
    }

    let permissions = validate_unique_identifiers(
        &wire.requested_permissions,
        "requested permission",
        line,
        diagnostics,
        |value| PluginPermission::new(value.to_owned()).map(|item| item.to_string()),
    )?;
    let manifest_permissions = manifest
        .permissions
        .iter()
        .map(|item| item.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if permissions != manifest_permissions {
        return Err(protocol_error(
            line,
            "descriptor requested permissions do not match the manifest",
            diagnostics.clone(),
        ));
    }

    Ok(PluginDescriptor {
        id: wire.id,
        name: wire.name,
        version: wire.version,
        capabilities: wire.capabilities,
        requested_permissions: wire.requested_permissions,
    })
}

fn validate_unique_identifiers<F>(
    values: &[String],
    label: &str,
    line: usize,
    diagnostics: &ProcessDiagnostics,
    mut parse: F,
) -> Result<BTreeSet<String>, PluginRuntimeError>
where
    F: FnMut(&str) -> Result<String, resymbol_core::plugin_api::ManifestValidationError>,
{
    let mut parsed = BTreeSet::new();
    for value in values {
        let value = parse(value).map_err(|error| {
            protocol_error(
                line,
                format!("invalid descriptor {label}: {error}"),
                diagnostics.clone(),
            )
        })?;
        if !parsed.insert(value) {
            return Err(protocol_error(
                line,
                format!("descriptor contains a duplicate {label}"),
                diagnostics.clone(),
            ));
        }
    }
    Ok(parsed)
}

fn parse_log(
    payload: Value,
    line: usize,
    diagnostics: &ProcessDiagnostics,
) -> Result<PluginLog, PluginRuntimeError> {
    let log = serde_json::from_value::<WireLog>(payload).map_err(|source| {
        PluginRuntimeError::InvalidJson {
            line,
            source,
            diagnostics: diagnostics.clone(),
        }
    })?;
    if !matches!(
        log.level.as_str(),
        "trace" | "debug" | "info" | "warn" | "error"
    ) {
        return Err(protocol_error(
            line,
            format!("invalid log level `{}`", log.level),
            diagnostics.clone(),
        ));
    }
    Ok(PluginLog {
        level: log.level,
        message: log.message,
    })
}

fn parse_claim(
    payload: Value,
    manifest: &PluginManifest,
    request: &ExternalProcessRequest,
    line: usize,
    diagnostics: &ProcessDiagnostics,
) -> Result<SymbolClaim, PluginRuntimeError> {
    decode_claim(payload, manifest, request).map_err(|error| match error {
        ClaimDecodeError::Json(source) => PluginRuntimeError::InvalidJson {
            line,
            source,
            diagnostics: diagnostics.clone(),
        },
        ClaimDecodeError::Validation(source) => PluginRuntimeError::InvalidClaim {
            line,
            source,
            diagnostics: diagnostics.clone(),
        },
    })
}

fn validate_error_code(
    code: &str,
    line: usize,
    diagnostics: &ProcessDiagnostics,
) -> Result<(), PluginRuntimeError> {
    if matches!(
        code,
        "invalid-argument"
            | "incompatible-api"
            | "permission-denied"
            | "unavailable"
            | "cancelled"
            | "resource-limit"
            | "internal"
    ) {
        Ok(())
    } else {
        Err(protocol_error(
            line,
            format!("invalid plugin error code `{code}`"),
            diagnostics.clone(),
        ))
    }
}

fn protocol_error(
    line: usize,
    message: impl Into<String>,
    diagnostics: ProcessDiagnostics,
) -> PluginRuntimeError {
    PluginRuntimeError::Protocol {
        line,
        message: message.into(),
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PluginMethod;
    use resymbol_core::plugin_api::{MANIFEST_VERSION, PluginRuntime};
    use semver::{Version, VersionReq};
    use std::{collections::BTreeMap, path::PathBuf};

    fn manifest() -> PluginManifest {
        PluginManifest {
            manifest_version: MANIFEST_VERSION,
            id: PluginId::new("dev.resymbol.test").expect("valid id"),
            name: "Test".to_owned(),
            version: Version::new(1, 2, 3),
            api: VersionReq::parse("^0.1").expect("valid requirement"),
            runtime: PluginRuntime::ExternalProcess {
                entrypoint: PathBuf::from("plugin"),
                args: Vec::new(),
            },
            capabilities: BTreeSet::new(),
            permissions: BTreeSet::new(),
            dependencies: BTreeMap::new(),
            description: None,
            authors: Vec::new(),
            license: None,
            homepage: None,
        }
    }

    fn request() -> ExternalProcessRequest {
        ExternalProcessRequest::new("one", "session", PluginMethod::Analyze, Map::new())
            .expect("valid request")
    }

    #[test]
    fn bounded_encoder_rejects_large_payload_before_launch() {
        let mut payload = Map::new();
        payload.insert("value".to_owned(), Value::String("x".repeat(2_000)));
        let request = ExternalProcessRequest::new("one", "session", PluginMethod::Analyze, payload)
            .expect("valid request");
        let limits = RuntimeLimits {
            max_message_bytes: 1_024,
            ..RuntimeLimits::default()
        };
        assert!(matches!(
            encode_input(&manifest(), &request, &limits),
            Err(PluginRuntimeError::StreamLimit {
                stream: StreamKind::Stdin,
                ..
            })
        ));
    }

    #[test]
    fn parser_requires_handshake_before_response() {
        let output = concat!(
            "{\"protocol\":\"resymbol.plugin-wire\",\"version\":{\"major\":1,\"minor\":0},",
            "\"kind\":\"response\",\"direction\":\"plugin-to-host\",\"id\":\"one\",",
            "\"ok\":true,\"result\":null}\n"
        );
        assert!(matches!(
            parse_output(
                output.as_bytes(),
                &manifest(),
                &request(),
                &RuntimeLimits::default(),
                ProcessDiagnostics::default(),
                Some(0),
            ),
            Err(PluginRuntimeError::Protocol { .. })
        ));
    }

    #[test]
    fn control_flow_claims_use_the_published_wire_shapes() {
        let subject = serde_json::json!({
            "kind": "function",
            "binary": "0000000000000000000000000000000000000000000000000000000000000000",
            "rva": 4096
        });
        let evidence = serde_json::json!([{
            "kind": "control-flow",
            "description": "validated test edge"
        }]);
        let parse = |claim: Value| {
            serde_json::from_value::<WireClaim>(serde_json::json!({
                "subject": subject,
                "claim": claim,
                "confidence": 0.8,
                "evidence": evidence
            }))
            .expect("published control-flow claim shape")
        };

        let entry = parse(serde_json::json!({ "kind": "function-entry" }));
        assert!(matches!(entry.claim, SymbolAssertion::FunctionEntry));

        let call = parse(serde_json::json!({
            "kind": "direct-call",
            "call_site_rva": 4100,
            "target": { "kind": "import-iat", "iat_rva": 8192 }
        }));
        assert!(matches!(
            call.claim,
            SymbolAssertion::DirectCall {
                call_site_rva: 4100,
                target: resymbol_core::ControlFlowTarget::ImportIat { iat_rva: 8192 },
            }
        ));

        let thunk = parse(serde_json::json!({
            "kind": "thunk-target",
            "target": { "kind": "function", "rva": 12288 }
        }));
        assert!(matches!(
            thunk.claim,
            SymbolAssertion::ThunkTarget {
                target: resymbol_core::ControlFlowTarget::Function { rva: 12288 },
            }
        ));
    }

    #[test]
    fn string_and_data_reference_claims_use_the_published_wire_shapes() {
        let version = protocol_version();
        assert_eq!((version.major, version.minor), (1, 0));

        let string_payload = serde_json::json!({
            "subject": {
                "kind": "global",
                "binary": "0000000000000000000000000000000000000000000000000000000000000000",
                "rva": 12288,
                "size": 26
            },
            "claim": {
                "kind": "string-literal",
                "encoding": "utf-16-le",
                "value": "Recovered 世界"
            },
            "confidence": 0.95,
            "evidence": [{
                "kind": "string-literal",
                "description": "decoded terminated UTF-16LE bytes"
            }]
        });
        let string_claim = parse_claim(
            string_payload,
            &manifest(),
            &request(),
            1,
            &ProcessDiagnostics::default(),
        )
        .expect("published string-literal wire shape");
        assert!(matches!(
            string_claim.assertion(),
            SymbolAssertion::StringLiteral {
                encoding: StringEncoding::Utf16Le,
                value,
            } if value == "Recovered 世界"
        ));
        assert_eq!(
            string_claim.evidence()[0].kind.as_str(),
            EvidenceKind::STRING_LITERAL
        );

        let reference_payload = serde_json::json!({
            "subject": {
                "kind": "function",
                "binary": "0000000000000000000000000000000000000000000000000000000000000000",
                "rva": 4096
            },
            "claim": {
                "kind": "data-reference",
                "instruction_rva": 4104,
                "instruction_size": 7,
                "target_rva": 12288
            },
            "confidence": 0.9,
            "evidence": [{
                "kind": "data-flow",
                "description": "decoded image-relative operand"
            }]
        });
        let reference_claim = parse_claim(
            reference_payload,
            &manifest(),
            &request(),
            2,
            &ProcessDiagnostics::default(),
        )
        .expect("published data-reference wire shape");
        assert!(matches!(
            reference_claim.assertion(),
            SymbolAssertion::DataReference {
                instruction_rva: 4104,
                instruction_size: 7,
                target_rva: 12288,
            }
        ));
    }

    #[test]
    fn string_and_data_reference_wire_shapes_reject_unknown_fields() {
        let subject = serde_json::json!({
                "kind": "global",
                "binary": "0000000000000000000000000000000000000000000000000000000000000000",
                "rva": 12288,
                "size": 26
        });
        let evidence = serde_json::json!([{
            "kind": "string-literal",
            "description": "decoded bytes"
        }]);
        for claim in [
            serde_json::json!({
                "kind": "string-literal",
                "encoding": "ascii",
                "value": "text",
                "unexpected": true
            }),
            serde_json::json!({
                "kind": "data-reference",
                "instruction_rva": 4104,
                "instruction_size": 7,
                "target_rva": 12288,
                "unexpected": true
            }),
        ] {
            let error = serde_json::from_value::<WireClaim>(serde_json::json!({
                "subject": subject,
                "claim": claim,
                "confidence": 0.8,
                "evidence": evidence
            }))
            .expect_err("unknown assertion property must fail");
            assert!(error.to_string().contains("unknown field `unexpected`"));
        }

        let error = serde_json::from_value::<WireClaim>(serde_json::json!({
            "subject": subject,
            "claim": {
                "kind": "string-literal",
                "encoding": "utf16-le",
                "value": "text"
            },
            "confidence": 0.8,
            "evidence": evidence
        }))
        .expect_err("non-canonical encoding must fail");
        assert!(error.to_string().contains("unknown variant `utf16-le`"));
    }

    #[test]
    fn checked_in_schema_lists_the_additive_claim_shapes() {
        let schema: Value =
            serde_json::from_str(include_str!("../../../protocol/plugin-wire.schema.json"))
                .expect("plugin wire schema is valid JSON");
        assert_eq!(
            schema["$defs"]["protocolVersion"]["properties"]["major"]["const"],
            serde_json::json!(PROTOCOL_MAJOR)
        );
        assert_eq!(
            schema["$defs"]["protocolVersion"]["properties"]["minor"]["const"],
            serde_json::json!(PROTOCOL_MINOR)
        );
        assert_eq!(
            schema["$defs"]["stringEncoding"]["enum"],
            serde_json::json!(["ascii", "utf-16-le"])
        );
        let assertions = schema["$defs"]["symbolAssertion"]["oneOf"]
            .as_array()
            .expect("assertion variants");
        for kind in ["string-literal", "data-reference"] {
            assert!(assertions.iter().any(|assertion| {
                assertion["properties"]["kind"]["const"] == serde_json::json!(kind)
            }));
        }
        let data_reference = assertions
            .iter()
            .find(|assertion| assertion["properties"]["kind"]["const"] == "data-reference")
            .expect("data-reference assertion schema");
        assert!(
            data_reference["required"]
                .as_array()
                .expect("required data-reference fields")
                .iter()
                .any(|field| field == "instruction_size")
        );
        assert_eq!(
            data_reference["properties"]["instruction_size"]["minimum"],
            1
        );
        assert_eq!(
            data_reference["properties"]["instruction_size"]["maximum"],
            255
        );
    }
}
