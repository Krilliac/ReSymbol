//! Strict typed control-message codecs layered over [`crate::host_wire`].
//!
//! Large memory buffers are carried exactly once as the frame's raw payload.
//! The JSON control document contains an explicit layout descriptor and empty
//! byte-vector placeholders, preventing ambiguous inline/raw representations.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::host_wire::{
    ControlBody, FrameHeader, FrameSequence, MessageKind, ProtocolVersion as WireProtocolVersion,
    WireError, decode_frame, encode_control,
};
use crate::protocol::{
    CommandEnvelope, DebugCommand, DebugEvent, EventEnvelope, MAX_MEMORY_READ_BYTES,
    MAX_MEMORY_WRITE_BYTES, ProtocolValidationError, ProtocolVersion,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandControl {
    envelope: CommandEnvelope,
    raw_layout: CommandRawLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "raw", rename_all = "kebab-case", deny_unknown_fields)]
enum CommandRawLayout {
    None,
    WriteMemory { expected_len: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventControl {
    envelope: EventEnvelope,
    raw_layout: EventRawLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "raw", rename_all = "kebab-case", deny_unknown_fields)]
enum EventRawLayout {
    None,
    MemoryRead,
    MemoryWritten { before_len: u32 },
}

/// An owned frame suitable for a queue or pipe transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFrame {
    header: FrameHeader,
    raw: Vec<u8>,
}

impl HostFrame {
    pub fn new(header: FrameHeader, raw: Vec<u8>) -> Result<Self, HostCodecError> {
        header.validate()?;
        let actual = u32::try_from(raw.len()).map_err(|_| HostCodecError::LengthOverflow)?;
        if actual != header.raw_len {
            return Err(HostCodecError::RawLengthMismatch {
                declared: header.raw_len,
                actual,
            });
        }
        Ok(Self { header, raw })
    }

    #[must_use]
    pub const fn header(&self) -> &FrameHeader {
        &self.header
    }

    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    #[must_use]
    pub fn into_parts(self) -> (FrameHeader, Vec<u8>) {
        (self.header, self.raw)
    }

    /// Serializes one already-bounded frame. This is a convenience for tests
    /// and queue transports; streaming transports should write the control and
    /// raw buffers separately.
    pub fn to_bytes(&self) -> Result<Vec<u8>, HostCodecError> {
        let mut bytes = encode_control(&self.header)?;
        bytes.extend_from_slice(&self.raw);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HostCodecError> {
        let mut sequence = crate::host_wire::SequenceTracker::default();
        let decoded = decode_frame(bytes, &mut sequence)?;
        if decoded.consumed != bytes.len() {
            return Err(HostCodecError::TrailingBytes {
                consumed: decoded.consumed,
                available: bytes.len(),
            });
        }
        Self::new(decoded.header, decoded.raw.to_vec())
    }
}

pub fn encode_command_frame(
    sequence: FrameSequence,
    envelope: &CommandEnvelope,
) -> Result<HostFrame, HostCodecError> {
    require_protocol_version(envelope.version, WireProtocolVersion::CURRENT)?;
    envelope.validate()?;
    let mut control_envelope = envelope.clone();
    let (raw_layout, raw_address, raw) = match &mut control_envelope.command {
        DebugCommand::WriteMemory {
            expected,
            replacement,
            ..
        } => {
            let expected_len =
                u32::try_from(expected.len()).map_err(|_| HostCodecError::LengthOverflow)?;
            let total = expected
                .len()
                .checked_add(replacement.len())
                .ok_or(HostCodecError::LengthOverflow)?;
            let mut raw = Vec::with_capacity(total);
            raw.extend_from_slice(expected);
            raw.extend_from_slice(replacement);
            expected.clear();
            replacement.clear();
            (CommandRawLayout::WriteMemory { expected_len }, None, raw)
        }
        _ => (CommandRawLayout::None, None, Vec::new()),
    };
    encode_json_frame(
        sequence,
        MessageKind::Command,
        raw_address,
        &CommandControl {
            envelope: control_envelope,
            raw_layout,
        },
        raw,
    )
}

pub fn decode_command_frame(frame: &HostFrame) -> Result<CommandEnvelope, HostCodecError> {
    let mut control: CommandControl = decode_json_frame(frame, MessageKind::Command)?;
    require_protocol_version(control.envelope.version, frame.header.version)?;
    match (&mut control.envelope.command, control.raw_layout) {
        (
            DebugCommand::WriteMemory {
                expected,
                replacement,
                ..
            },
            CommandRawLayout::WriteMemory { expected_len },
        ) => {
            require_empty_placeholders(expected, replacement)?;
            require_absent_raw_address(frame)?;
            let split =
                usize::try_from(expected_len).map_err(|_| HostCodecError::LengthOverflow)?;
            if split == 0 || split > MAX_MEMORY_WRITE_BYTES {
                return Err(HostCodecError::InvalidRawLayout);
            }
            let total = split.checked_mul(2).ok_or(HostCodecError::LengthOverflow)?;
            if frame.raw.len() != total {
                return Err(HostCodecError::InvalidRawLayout);
            }
            expected.extend_from_slice(&frame.raw[..split]);
            replacement.extend_from_slice(&frame.raw[split..]);
        }
        (DebugCommand::WriteMemory { .. }, CommandRawLayout::None)
        | (_, CommandRawLayout::WriteMemory { .. }) => {
            return Err(HostCodecError::InvalidRawLayout);
        }
        (_, CommandRawLayout::None) => require_no_raw(frame)?,
    }
    control.envelope.validate()?;
    Ok(control.envelope)
}

pub fn encode_event_frame(
    sequence: FrameSequence,
    event: &EventEnvelope,
) -> Result<HostFrame, HostCodecError> {
    require_protocol_version(event.version, WireProtocolVersion::CURRENT)?;
    event.validate()?;
    let mut control_envelope = event.clone();
    let (raw_layout, raw_address, raw) = match &mut control_envelope.event {
        DebugEvent::MemoryRead { address, bytes, .. } => {
            let raw = std::mem::take(bytes);
            (EventRawLayout::MemoryRead, Some(address.get()), raw)
        }
        DebugEvent::MemoryWritten { before, after, .. } => {
            let before_len =
                u32::try_from(before.len()).map_err(|_| HostCodecError::LengthOverflow)?;
            let total = before
                .len()
                .checked_add(after.len())
                .ok_or(HostCodecError::LengthOverflow)?;
            let mut raw = Vec::with_capacity(total);
            raw.extend_from_slice(before);
            raw.extend_from_slice(after);
            before.clear();
            after.clear();
            (EventRawLayout::MemoryWritten { before_len }, None, raw)
        }
        _ => (EventRawLayout::None, None, Vec::new()),
    };
    encode_json_frame(
        sequence,
        MessageKind::Event,
        raw_address,
        &EventControl {
            envelope: control_envelope,
            raw_layout,
        },
        raw,
    )
}

pub fn decode_event_frame(frame: &HostFrame) -> Result<EventEnvelope, HostCodecError> {
    let mut control: EventControl = decode_json_frame(frame, MessageKind::Event)?;
    require_protocol_version(control.envelope.version, frame.header.version)?;
    match (&mut control.envelope.event, control.raw_layout) {
        (DebugEvent::MemoryRead { address, bytes, .. }, EventRawLayout::MemoryRead) => {
            if !bytes.is_empty()
                || frame.raw.is_empty()
                || frame.raw.len() > MAX_MEMORY_READ_BYTES as usize
            {
                return Err(HostCodecError::InvalidRawLayout);
            }
            require_raw_address(frame, address.get())?;
            bytes.extend_from_slice(&frame.raw);
        }
        (
            DebugEvent::MemoryWritten { before, after, .. },
            EventRawLayout::MemoryWritten { before_len },
        ) => {
            require_empty_placeholders(before, after)?;
            require_absent_raw_address(frame)?;
            let split = usize::try_from(before_len).map_err(|_| HostCodecError::LengthOverflow)?;
            if split == 0 || split > MAX_MEMORY_WRITE_BYTES {
                return Err(HostCodecError::InvalidRawLayout);
            }
            let total = split.checked_mul(2).ok_or(HostCodecError::LengthOverflow)?;
            if frame.raw.len() != total {
                return Err(HostCodecError::InvalidRawLayout);
            }
            before.extend_from_slice(&frame.raw[..split]);
            after.extend_from_slice(&frame.raw[split..]);
        }
        (DebugEvent::MemoryRead { .. }, _)
        | (DebugEvent::MemoryWritten { .. }, _)
        | (_, EventRawLayout::MemoryRead | EventRawLayout::MemoryWritten { .. }) => {
            return Err(HostCodecError::InvalidRawLayout);
        }
        (_, EventRawLayout::None) => require_no_raw(frame)?,
    }
    control.envelope.validate()?;
    Ok(control.envelope)
}

fn encode_json_frame<T: Serialize>(
    sequence: FrameSequence,
    kind: MessageKind,
    raw_address: Option<u64>,
    value: &T,
    raw: Vec<u8>,
) -> Result<HostFrame, HostCodecError> {
    let bytes = serde_json::to_vec(value).map_err(json_error)?;
    let raw_len = u32::try_from(raw.len()).map_err(|_| HostCodecError::LengthOverflow)?;
    let header = FrameHeader::new(
        sequence,
        kind,
        raw_len,
        raw_address,
        ControlBody::Bytes(bytes),
    )?;
    HostFrame::new(header, raw)
}

fn decode_json_frame<T: DeserializeOwned>(
    frame: &HostFrame,
    expected: MessageKind,
) -> Result<T, HostCodecError> {
    frame.header.validate()?;
    if frame.header.kind != expected {
        return Err(HostCodecError::UnexpectedMessageKind {
            expected,
            actual: frame.header.kind,
        });
    }
    let ControlBody::Bytes(control) = &frame.header.body else {
        return Err(HostCodecError::UnexpectedHelloBody);
    };
    serde_json::from_slice(control).map_err(json_error)
}

fn json_error(error: serde_json::Error) -> HostCodecError {
    HostCodecError::Json(error.to_string())
}

fn require_no_raw(frame: &HostFrame) -> Result<(), HostCodecError> {
    if frame.raw.is_empty() && frame.header.raw_address.is_none() {
        Ok(())
    } else {
        Err(HostCodecError::UnexpectedRawPayload)
    }
}

fn require_raw_address(frame: &HostFrame, expected: u64) -> Result<(), HostCodecError> {
    if frame.header.raw_address == Some(expected) {
        Ok(())
    } else {
        Err(HostCodecError::RawAddressMismatch {
            expected,
            actual: frame.header.raw_address,
        })
    }
}

fn require_absent_raw_address(frame: &HostFrame) -> Result<(), HostCodecError> {
    if let Some(actual) = frame.header.raw_address {
        Err(HostCodecError::UnexpectedRawAddress { actual })
    } else {
        Ok(())
    }
}

fn require_empty_placeholders(first: &[u8], second: &[u8]) -> Result<(), HostCodecError> {
    if first.is_empty() && second.is_empty() {
        Ok(())
    } else {
        Err(HostCodecError::InlineRawPayload)
    }
}

fn require_protocol_version(
    protocol: ProtocolVersion,
    wire: WireProtocolVersion,
) -> Result<(), HostCodecError> {
    if protocol.major == wire.major && protocol.minor == wire.minor {
        Ok(())
    } else {
        Err(HostCodecError::ProtocolVersionMismatch {
            wire_major: wire.major,
            wire_minor: wire.minor,
            envelope_major: protocol.major,
            envelope_minor: protocol.minor,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostCodecError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    #[error("invalid typed host control JSON: {0}")]
    Json(String),
    #[error("raw payload length {actual} does not match declared length {declared}")]
    RawLengthMismatch { declared: u32, actual: u32 },
    #[error("typed {expected:?} frame received {actual:?}")]
    UnexpectedMessageKind {
        expected: MessageKind,
        actual: MessageKind,
    },
    #[error("typed command/event frame cannot contain a hello body")]
    UnexpectedHelloBody,
    #[error("typed command/event codec does not accept an inline raw payload")]
    UnexpectedRawPayload,
    #[error("raw layout does not exactly match the typed protocol envelope")]
    InvalidRawLayout,
    #[error("protocol bytes must not appear both inline and in the raw payload")]
    InlineRawPayload,
    #[error("raw payload address mismatch: expected {expected:#x}, received {actual:?}")]
    RawAddressMismatch { expected: u64, actual: Option<u64> },
    #[error("paired raw payload unexpectedly carried address {actual:#x}")]
    UnexpectedRawAddress { actual: u64 },
    #[error("frame length does not fit the wire representation")]
    LengthOverflow,
    #[error(
        "wire protocol {wire_major}.{wire_minor} does not match envelope protocol {envelope_major}.{envelope_minor}"
    )]
    ProtocolVersionMismatch {
        wire_major: u16,
        wire_minor: u16,
        envelope_major: u16,
        envelope_minor: u16,
    },
    #[error("frame contains trailing bytes: consumed {consumed}, available {available}")]
    TrailingBytes { consumed: usize, available: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        BreakpointChange, BreakpointId, BreakpointKind, BreakpointPersistence, BreakpointScope,
        BreakpointSpec, CommandId, DebugCommand, DebugEvent, EventEnvelope, EventSequence,
        MemoryAddress, ProtocolVersion, ReadViewToken, SessionId, StateGeneration, StateToken,
        StopId, StopToken,
    };

    fn close_command() -> CommandEnvelope {
        let session_id = SessionId::new(4).expect("session id");
        let state = StateToken {
            session_id,
            generation: StateGeneration::new(3).expect("generation"),
        };
        CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(8).expect("command id"),
            session_id: Some(session_id),
            expected_state: Some(state),
            command: DebugCommand::Close { state },
        }
    }

    fn write_command() -> CommandEnvelope {
        let session_id = SessionId::new(7).unwrap();
        let state = StateToken {
            session_id,
            generation: StateGeneration::new(3).unwrap(),
        };
        CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(9).unwrap(),
            session_id: Some(session_id),
            expected_state: Some(state),
            command: DebugCommand::WriteMemory {
                stop: StopToken {
                    state,
                    stop_id: StopId::new(2).unwrap(),
                },
                address: MemoryAddress::new(0x1400),
                expected: vec![1, 2, 3],
                replacement: vec![4, 5, 6],
            },
        }
    }

    fn breakpoint_command(persistence: BreakpointPersistence) -> CommandEnvelope {
        let session_id = SessionId::new(11).expect("session id");
        let state = StateToken {
            session_id,
            generation: StateGeneration::new(5).expect("generation"),
        };
        CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id: CommandId::new(12).expect("command id"),
            session_id: Some(session_id),
            expected_state: Some(state),
            command: DebugCommand::SetBreakpoint {
                stop: StopToken {
                    state,
                    stop_id: StopId::new(3).expect("stop id"),
                },
                breakpoint: BreakpointSpec {
                    id: BreakpointId::new(4).expect("breakpoint id"),
                    address: MemoryAddress::new(0x401234),
                    kind: BreakpointKind::Software,
                    scope: BreakpointScope::Process,
                },
                persistence,
            },
        }
    }

    #[test]
    fn typed_command_round_trips_through_owned_frame() {
        let command = close_command();
        let frame = encode_command_frame(FrameSequence::new(1).unwrap(), &command).unwrap();
        let bytes = frame.to_bytes().unwrap();
        let decoded = HostFrame::from_bytes(&bytes).unwrap();
        assert_eq!(decode_command_frame(&decoded).unwrap(), command);
    }

    #[test]
    fn typed_codec_rejects_unknown_fields_and_wrong_kinds() {
        let command = close_command();
        let encoded = encode_command_frame(FrameSequence::new(1).unwrap(), &command).unwrap();
        let ControlBody::Bytes(control) = &encoded.header().body else {
            panic!("command control must be bytes")
        };
        let mut json: serde_json::Value = serde_json::from_slice(control).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("future-field".to_owned(), serde_json::json!(true));
        let frame = HostFrame::new(
            FrameHeader::new(
                FrameSequence::new(1).unwrap(),
                MessageKind::Command,
                0,
                None,
                ControlBody::Bytes(serde_json::to_vec(&json).unwrap()),
            )
            .unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert!(matches!(
            decode_command_frame(&frame),
            Err(HostCodecError::Json(_))
        ));
        assert!(matches!(
            decode_event_frame(&frame),
            Err(HostCodecError::UnexpectedMessageKind { .. })
        ));
    }

    #[test]
    fn typed_codec_binds_envelope_version_to_wire_version() {
        let mut control = CommandControl {
            envelope: close_command(),
            raw_layout: CommandRawLayout::None,
        };
        control.envelope.version.major += 1;
        let frame = HostFrame::new(
            FrameHeader::new(
                FrameSequence::new(1).unwrap(),
                MessageKind::Command,
                0,
                None,
                ControlBody::Bytes(serde_json::to_vec(&control).unwrap()),
            )
            .unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert!(matches!(
            decode_command_frame(&frame),
            Err(HostCodecError::ProtocolVersionMismatch {
                wire_major: crate::host_wire::PROTOCOL_MAJOR,
                envelope_major,
                ..
            }) if envelope_major == crate::protocol::PROTOCOL_MAJOR + 1
        ));
    }

    #[test]
    fn breakpoint_persistence_is_required_and_round_trips_on_set_commands() {
        for (persistence, encoded_name) in [
            (BreakpointPersistence::Persistent, "persistent"),
            (BreakpointPersistence::Temporary, "temporary"),
        ] {
            let command = breakpoint_command(persistence);
            let frame = encode_command_frame(FrameSequence::new(1).unwrap(), &command).unwrap();
            assert_eq!(decode_command_frame(&frame).unwrap(), command);
            let ControlBody::Bytes(control) = &frame.header().body else {
                panic!("command control must be bytes")
            };
            let json: serde_json::Value = serde_json::from_slice(control).unwrap();
            assert_eq!(
                json.pointer("/envelope/command/parameters/persistence")
                    .and_then(serde_json::Value::as_str),
                Some(encoded_name)
            );
        }

        let frame = encode_command_frame(
            FrameSequence::new(1).unwrap(),
            &breakpoint_command(BreakpointPersistence::Temporary),
        )
        .unwrap();
        let ControlBody::Bytes(control) = &frame.header().body else {
            panic!("command control must be bytes")
        };
        let mut missing: serde_json::Value = serde_json::from_slice(control).unwrap();
        missing
            .pointer_mut("/envelope/command/parameters")
            .and_then(serde_json::Value::as_object_mut)
            .expect("set-breakpoint parameters")
            .remove("persistence");
        let missing = HostFrame::new(
            FrameHeader::new(
                FrameSequence::new(1).unwrap(),
                MessageKind::Command,
                0,
                None,
                ControlBody::Bytes(serde_json::to_vec(&missing).unwrap()),
            )
            .unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert!(matches!(
            decode_command_frame(&missing),
            Err(HostCodecError::Json(_))
        ));
    }

    #[test]
    fn breakpoint_set_evidence_echoes_policy_and_removal_makes_no_policy_claim() {
        let command = breakpoint_command(BreakpointPersistence::Temporary);
        let DebugCommand::SetBreakpoint {
            stop, breakpoint, ..
        } = command.command
        else {
            unreachable!()
        };
        let event = |change| EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(1).unwrap(),
            session_id: Some(stop.state.session_id),
            state: Some(stop.state),
            caused_by: Some(command.command_id),
            event: DebugEvent::BreakpointChanged {
                stop,
                breakpoint: breakpoint.clone(),
                change,
            },
        };

        let set = event(BreakpointChange::Set {
            persistence: BreakpointPersistence::Temporary,
        });
        let set_frame = encode_event_frame(FrameSequence::new(2).unwrap(), &set).unwrap();
        assert_eq!(decode_event_frame(&set_frame).unwrap(), set);
        let ControlBody::Bytes(set_control) = &set_frame.header().body else {
            panic!("event control must be bytes")
        };
        assert!(
            std::str::from_utf8(set_control)
                .unwrap()
                .contains("\"persistence\":\"temporary\"")
        );

        let removed = event(BreakpointChange::Removed);
        let removed_frame = encode_event_frame(FrameSequence::new(3).unwrap(), &removed).unwrap();
        assert_eq!(decode_event_frame(&removed_frame).unwrap(), removed);
        let ControlBody::Bytes(removed_control) = &removed_frame.header().body else {
            panic!("event control must be bytes")
        };
        assert!(
            !std::str::from_utf8(removed_control)
                .unwrap()
                .contains("persistence")
        );

        let mut claimed_policy: serde_json::Value =
            serde_json::from_slice(removed_control).unwrap();
        *claimed_policy
            .pointer_mut("/envelope/event/payload/change")
            .expect("breakpoint change") =
            serde_json::json!({ "removed": { "persistence": "temporary" } });
        let claimed_policy = HostFrame::new(
            FrameHeader::new(
                FrameSequence::new(4).unwrap(),
                MessageKind::Event,
                0,
                None,
                ControlBody::Bytes(serde_json::to_vec(&claimed_policy).unwrap()),
            )
            .unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert!(matches!(
            decode_event_frame(&claimed_policy),
            Err(HostCodecError::Json(_))
        ));
    }

    #[test]
    fn owned_frame_rejects_trailing_or_mismatched_raw_bytes() {
        let frame = encode_command_frame(FrameSequence::new(1).unwrap(), &close_command()).unwrap();
        let mut bytes = frame.to_bytes().unwrap();
        bytes.push(0);
        assert!(matches!(
            HostFrame::from_bytes(&bytes),
            Err(HostCodecError::TrailingBytes { .. })
        ));
        let mut header = frame.header().clone();
        header.raw_len = 1;
        assert!(matches!(
            HostFrame::new(header, Vec::new()),
            Err(HostCodecError::RawLengthMismatch { .. })
        ));

        assert!(matches!(
            FrameHeader::new(
                FrameSequence::new(1).unwrap(),
                MessageKind::Command,
                0,
                None,
                ControlBody::Bytes(vec![0; crate::host_wire::MAX_CONTROL_BYTES]),
            ),
            Err(WireError::ControlTooLarge { .. })
        ));
    }

    #[test]
    fn memory_write_round_trips_with_bytes_only_in_raw_payload() {
        let command = write_command();
        let frame = encode_command_frame(FrameSequence::new(2).unwrap(), &command).unwrap();
        assert_eq!(frame.header().raw_address, None);
        assert_eq!(frame.raw(), &[1, 2, 3, 4, 5, 6]);
        let ControlBody::Bytes(control) = &frame.header().body else {
            panic!("command control must be bytes")
        };
        assert!(!std::str::from_utf8(control).unwrap().contains("[1,2,3]"));
        assert_eq!(decode_command_frame(&frame).unwrap(), command);
    }

    #[test]
    fn memory_read_round_trips_with_exact_address_and_raw_layout() {
        let state = StateToken {
            session_id: SessionId::new(7).unwrap(),
            generation: StateGeneration::new(3).unwrap(),
        };
        let event = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(1).unwrap(),
            session_id: Some(state.session_id),
            state: Some(state),
            caused_by: None,
            event: DebugEvent::MemoryRead {
                view: ReadViewToken::Offline { state },
                address: MemoryAddress::new(0x2200),
                bytes: vec![9, 8, 7],
            },
        };
        let frame = encode_event_frame(FrameSequence::new(2).unwrap(), &event).unwrap();
        assert_eq!(frame.header().raw_address, Some(0x2200));
        assert_eq!(frame.raw(), &[9, 8, 7]);
        assert_eq!(decode_event_frame(&frame).unwrap(), event);
    }

    #[test]
    fn memory_written_pairs_round_trip_without_claiming_double_address_span() {
        let state = StateToken {
            session_id: SessionId::new(7).unwrap(),
            generation: StateGeneration::new(3).unwrap(),
        };
        let event = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(1).unwrap(),
            session_id: Some(state.session_id),
            state: Some(state),
            caused_by: None,
            event: DebugEvent::MemoryWritten {
                stop: StopToken {
                    state,
                    stop_id: StopId::new(2).unwrap(),
                },
                address: MemoryAddress::new(u64::MAX - 2),
                before: vec![1, 2],
                after: vec![3, 4],
            },
        };
        let frame = encode_event_frame(FrameSequence::new(2).unwrap(), &event).unwrap();
        assert_eq!(frame.header().raw_address, None);
        assert_eq!(frame.raw(), &[1, 2, 3, 4]);
        assert_eq!(decode_event_frame(&frame).unwrap(), event);
    }

    #[test]
    fn raw_address_and_inline_duplicates_are_rejected() {
        let command = write_command();
        let frame = encode_command_frame(FrameSequence::new(2).unwrap(), &command).unwrap();
        let (mut header, raw) = frame.into_parts();
        header.raw_address = Some(0x1401);
        let wrong_address = HostFrame::new(header, raw).unwrap();
        assert!(matches!(
            decode_command_frame(&wrong_address),
            Err(HostCodecError::UnexpectedRawAddress { actual: 0x1401 })
        ));

        let mut duplicate = command;
        let DebugCommand::WriteMemory { replacement, .. } = &mut duplicate.command else {
            unreachable!()
        };
        replacement.clear();
        let control = CommandControl {
            envelope: duplicate,
            raw_layout: CommandRawLayout::WriteMemory { expected_len: 3 },
        };
        let duplicate = encode_json_frame(
            FrameSequence::new(2).unwrap(),
            MessageKind::Command,
            None,
            &control,
            vec![1, 2, 3, 4, 5, 6],
        )
        .unwrap();
        assert_eq!(
            decode_command_frame(&duplicate),
            Err(HostCodecError::InlineRawPayload)
        );
    }
}
