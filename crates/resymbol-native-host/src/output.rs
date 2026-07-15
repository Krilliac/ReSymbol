use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    bootstrap::{PLUGIN_WIRE_PROTOCOL, PROTOCOL_MAJOR, PROTOCOL_MINOR},
    callbacks::BufferedEvent,
    error::HostError,
};

const HARD_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const NON_EVENT_FRAME_COUNT: usize = 2;

#[derive(Debug, Clone)]
pub(crate) struct ValidatedDescriptor {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) capabilities: Vec<String>,
    pub(crate) requested_permissions: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PluginRejection {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeExecution {
    pub(crate) descriptor: ValidatedDescriptor,
    pub(crate) events: Vec<BufferedEvent>,
    pub(crate) rejection: Option<PluginRejection>,
}

pub(crate) fn encode_execution(
    execution: NativeExecution,
    request_id: &str,
    max_message_bytes: usize,
    max_stdout_bytes: usize,
) -> Result<Vec<u8>, HostError> {
    let aggregate_limit = aggregate_output_limit(max_stdout_bytes);
    let NativeExecution {
        descriptor,
        events,
        rejection,
    } = execution;
    let mut output = Vec::new();
    append_line(
        &mut output,
        &json!({
            "protocol": PLUGIN_WIRE_PROTOCOL,
            "version": version(),
            "kind": "hello-result",
            "descriptor": {
                "id": descriptor.id,
                "name": descriptor.name,
                "version": descriptor.version,
                "capabilities": descriptor.capabilities,
                "requested_permissions": descriptor.requested_permissions,
                "isolation": { "mode": "process", "required": true }
            }
        }),
        max_message_bytes,
        aggregate_limit,
    )?;

    for event in &events {
        append_encoded_line(
            &mut output,
            encode_event_line(event, max_message_bytes)?,
            aggregate_limit,
        )?;
    }

    let response = match rejection {
        None => json!({
            "protocol": PLUGIN_WIRE_PROTOCOL,
            "version": version(),
            "kind": "response",
            "direction": "plugin-to-host",
            "id": request_id,
            "ok": true,
            "result": { "accepted": true }
        }),
        Some(rejection) => json!({
            "protocol": PLUGIN_WIRE_PROTOCOL,
            "version": version(),
            "kind": "response",
            "direction": "plugin-to-host",
            "id": request_id,
            "ok": false,
            "error": { "code": rejection.code, "message": rejection.message }
        }),
    };
    append_line(&mut output, &response, max_message_bytes, aggregate_limit)?;
    Ok(output)
}

/// Returns the aggregate byte budget available to callback event lines after
/// reserving a worst-case hello-result and response, including their newlines.
/// Saturating arithmetic deliberately turns undersized custom limits into a
/// zero-event budget rather than wrapping around.
pub(crate) fn callback_event_budget(max_message_bytes: usize, max_stdout_bytes: usize) -> usize {
    let maximum_frame_bytes = max_message_bytes.saturating_add(1);
    let reserved_non_event_bytes = maximum_frame_bytes.saturating_mul(NON_EVENT_FRAME_COUNT);
    aggregate_output_limit(max_stdout_bytes).saturating_sub(reserved_non_event_bytes)
}

/// Serializes an event exactly as the final encoder will and includes its NDJSON
/// newline in the returned length. This is the callback acceptance gate; the
/// final encoder independently repeats the same per-message and aggregate
/// checks before writing stdout.
pub(crate) fn encoded_event_line_len(
    event: &BufferedEvent,
    max_message_bytes: usize,
) -> Result<usize, HostError> {
    Ok(encode_event_line(event, max_message_bytes)?.len())
}

fn aggregate_output_limit(max_stdout_bytes: usize) -> usize {
    max_stdout_bytes.min(HARD_MAX_OUTPUT_BYTES)
}

fn encode_event_line(
    event: &BufferedEvent,
    max_message_bytes: usize,
) -> Result<Vec<u8>, HostError> {
    let (method, payload) = match event {
        BufferedEvent::Log { level, message } => {
            ("log", json!({ "level": level, "message": message }))
        }
        BufferedEvent::Claim(claim) => ("claim", claim.clone()),
    };
    encode_line(
        &json!({
            "protocol": PLUGIN_WIRE_PROTOCOL,
            "version": version(),
            "kind": "event",
            "direction": "plugin-to-host",
            "method": method,
            "payload": payload
        }),
        max_message_bytes,
    )
}

fn version() -> Value {
    json!({ "major": PROTOCOL_MAJOR, "minor": PROTOCOL_MINOR })
}

fn append_line(
    output: &mut Vec<u8>,
    message: &impl Serialize,
    max_message_bytes: usize,
    aggregate_limit: usize,
) -> Result<(), HostError> {
    let encoded = encode_line(message, max_message_bytes)?;
    append_encoded_line(output, encoded, aggregate_limit)
}

fn encode_line(message: &impl Serialize, max_message_bytes: usize) -> Result<Vec<u8>, HostError> {
    let mut encoded = serde_json::to_vec(message).map_err(HostError::Output)?;
    if encoded.len() > max_message_bytes {
        return Err(HostError::InputLimit {
            kind: "native-host output message",
            limit: max_message_bytes,
        });
    }
    encoded
        .try_reserve_exact(1)
        .map_err(|_| HostError::InputLimit {
            kind: "native-host aggregate output",
            limit: HARD_MAX_OUTPUT_BYTES,
        })?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn append_encoded_line(
    output: &mut Vec<u8>,
    encoded: Vec<u8>,
    aggregate_limit: usize,
) -> Result<(), HostError> {
    let next = output
        .len()
        .checked_add(encoded.len())
        .ok_or(HostError::InputLimit {
            kind: "native-host aggregate output",
            limit: aggregate_limit,
        })?;
    if next > aggregate_limit {
        return Err(HostError::InputLimit {
            kind: "native-host aggregate output",
            limit: aggregate_limit,
        });
    }
    output.extend_from_slice(&encoded);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_newline_delimited_and_uses_one_response() {
        let execution = NativeExecution {
            descriptor: ValidatedDescriptor {
                id: "dev.example.plugin".to_owned(),
                name: "Example".to_owned(),
                version: "1.0.0".to_owned(),
                capabilities: vec!["analyzer.binary".to_owned()],
                requested_permissions: Vec::new(),
            },
            events: vec![BufferedEvent::Log {
                level: "info",
                message: "hello".to_owned(),
            }],
            rejection: None,
        };
        let bytes = encode_execution(execution, "request-1", 4_096, 8 * 1024 * 1024).unwrap();
        assert!(bytes.ends_with(b"\n"));
        assert_eq!(bytes.split(|byte| *byte == b'\n').count(), 4);
        assert_eq!(
            String::from_utf8(bytes)
                .unwrap()
                .matches("\"kind\":\"response\"")
                .count(),
            1
        );
    }

    #[test]
    fn output_honors_the_parent_aggregate_stdout_limit() {
        let execution = NativeExecution {
            descriptor: ValidatedDescriptor {
                id: "dev.example.plugin".to_owned(),
                name: "Example".to_owned(),
                version: "1.0.0".to_owned(),
                capabilities: Vec::new(),
                requested_permissions: Vec::new(),
            },
            events: vec![BufferedEvent::Log {
                level: "info",
                message: "x".repeat(2_048),
            }],
            rejection: None,
        };
        let error = encode_execution(execution, "request-1", 4_096, 1_024).unwrap_err();
        assert!(matches!(
            error,
            HostError::InputLimit {
                kind: "native-host aggregate output",
                limit: 1_024
            }
        ));
    }

    #[test]
    fn callback_budget_saturates_for_small_or_overflowing_limits() {
        assert_eq!(callback_event_budget(1_024, 2_049), 0);
        assert_eq!(callback_event_budget(1_024, 2_050), 0);
        assert_eq!(callback_event_budget(1_024, 2_051), 1);
        assert_eq!(callback_event_budget(usize::MAX, usize::MAX), 0);
    }

    #[test]
    fn exact_event_length_includes_json_escaping_and_newline() {
        let message = "line one\n\"quoted\"\\tail".to_owned();
        let event = BufferedEvent::Log {
            level: "info",
            message: message.clone(),
        };
        let encoded = encode_event_line(&event, 4_096).unwrap();
        assert_eq!(
            encoded_event_line_len(&event, 4_096).unwrap(),
            encoded.len()
        );
        assert!(encoded.ends_with(b"\n"));
        assert!(encoded.len() > message.len());
        assert!(
            String::from_utf8(encoded)
                .unwrap()
                .contains("\\n\\\"quoted\\\"\\\\tail")
        );
    }
}
