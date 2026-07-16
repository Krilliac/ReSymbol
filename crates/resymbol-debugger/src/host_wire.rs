//! Bounded binary framing for the debugger host.
//!
//! A frame is `u32_le control_len | binary control header | raw payload`.
//! The prefix excludes the raw payload, whose independent length is carried in
//! the control header. Newlines have no framing meaning: this is not NDJSON.

use thiserror::Error;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 1;
pub const MAX_CONTROL_BYTES: usize = 64 * 1024;
pub const MAX_RAW_BYTES: u32 = 8 * 1024 * 1024;
pub const MAX_BUILD_ID_BYTES: usize = 256;

const PREFIX_BYTES: usize = 4;
const FIXED_CONTROL_BYTES: usize = 32;
const HELLO_FIXED_BYTES: usize = 20;
const MAGIC: [u8; 4] = *b"RSYM";
const ADDRESS_FLAG: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const CURRENT: Self = Self {
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR,
    };

    fn validate(self) -> Result<(), WireError> {
        if self.major != PROTOCOL_MAJOR || self.minor > PROTOCOL_MINOR {
            return Err(WireError::UnsupportedVersion {
                major: self.major,
                minor: self.minor,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameSequence(u64);

impl FrameSequence {
    pub fn new(value: u64) -> Result<Self, WireError> {
        (value != 0)
            .then_some(Self(value))
            .ok_or(WireError::ZeroSequence)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageKind {
    Hello = 1,
    HelloAck = 2,
    Command = 3,
    Event = 4,
    Cancel = 5,
    Close = 6,
}

impl TryFrom<u8> for MessageKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloAck),
            3 => Ok(Self::Command),
            4 => Ok(Self::Event),
            5 => Ok(Self::Cancel),
            6 => Ok(Self::Close),
            _ => Err(WireError::UnknownMessageKind { value }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointRole {
    Controller = 1,
    Host = 2,
}

impl EndpointRole {
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::Controller => Self::Host,
            Self::Host => Self::Controller,
        }
    }

    #[must_use]
    pub const fn outbound_direction(self) -> MessageDirection {
        match self {
            Self::Controller => MessageDirection::ControllerToHost,
            Self::Host => MessageDirection::HostToController,
        }
    }
}

impl TryFrom<u8> for EndpointRole {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Controller),
            2 => Ok(Self::Host),
            _ => Err(WireError::UnknownEndpointRole { value }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageDirection {
    ControllerToHost = 1,
    HostToController = 2,
}

impl TryFrom<u8> for MessageDirection {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ControllerToHost),
            2 => Ok(Self::HostToController),
            _ => Err(WireError::UnknownMessageDirection { value }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloIdentity {
    pub nonce: [u8; 16],
    pub role: EndpointRole,
    pub direction: MessageDirection,
    pub build_identity: String,
}

impl HelloIdentity {
    pub fn new(
        nonce: [u8; 16],
        role: EndpointRole,
        direction: MessageDirection,
        build_identity: impl Into<String>,
    ) -> Result<Self, WireError> {
        let build_identity = build_identity.into();
        let hello = Self {
            nonce,
            role,
            direction,
            build_identity,
        };
        hello.validate()?;
        Ok(hello)
    }

    fn validate(&self) -> Result<(), WireError> {
        if self.nonce.iter().all(|byte| *byte == 0) {
            return Err(WireError::ZeroHelloNonce);
        }
        if self.direction != self.role.outbound_direction() {
            return Err(WireError::RoleDirectionMismatch);
        }
        validate_build_identity(&self.build_identity)?;
        Ok(())
    }
}

fn validate_build_identity(build_identity: &str) -> Result<(), WireError> {
    if build_identity.is_empty() || build_identity.chars().any(char::is_control) {
        return Err(WireError::InvalidBuildIdentity);
    }
    if build_identity.len() > MAX_BUILD_ID_BYTES {
        return Err(WireError::BuildIdentityTooLong {
            actual: build_identity.len(),
            maximum: MAX_BUILD_ID_BYTES,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Ready,
    AwaitingHello,
    AwaitingAcknowledgement,
    Established,
    Failed,
}

/// Directional nonce, role, version, and build-identity binding for one frame exchange.
///
/// The machine deliberately owns no transport. Each side has an independent
/// frame sequence, so the initial `Hello` and `HelloAck` are both sequence one.
/// Any validation failure is terminal: callers must discard the channel rather
/// than attempting to recover on bytes whose identity is no longer trusted.
/// This handshake detects reflection, replay, downgrade, and accidental peer
/// mismatch; it is not cryptographic peer authentication. A platform adapter
/// must separately authenticate the transport and the helper it created.
#[derive(Debug)]
pub struct HandshakeMachine {
    role: EndpointRole,
    local_build_identity: String,
    expected_peer_build_identity: String,
    offered_version: ProtocolVersion,
    negotiated_version: Option<ProtocolVersion>,
    nonce: Option<[u8; 16]>,
    state: HandshakeState,
}

impl HandshakeMachine {
    pub fn initiator(
        role: EndpointRole,
        nonce: [u8; 16],
        local_build_identity: impl Into<String>,
        expected_peer_build_identity: impl Into<String>,
    ) -> Result<Self, HandshakeError> {
        Self::initiator_for_version(
            role,
            nonce,
            local_build_identity,
            expected_peer_build_identity,
            ProtocolVersion::CURRENT,
        )
    }

    /// Offers one explicitly supported protocol version. The responder either
    /// acknowledges that exact version or fails the channel; there is no
    /// ambiguous downgrade or silent fallback.
    pub fn initiator_for_version(
        role: EndpointRole,
        nonce: [u8; 16],
        local_build_identity: impl Into<String>,
        expected_peer_build_identity: impl Into<String>,
        offered_version: ProtocolVersion,
    ) -> Result<Self, HandshakeError> {
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(WireError::ZeroHelloNonce.into());
        }
        offered_version.validate()?;
        Self::new(
            role,
            local_build_identity.into(),
            expected_peer_build_identity.into(),
            offered_version,
            Some(nonce),
            HandshakeState::Ready,
        )
    }

    pub fn responder(
        role: EndpointRole,
        local_build_identity: impl Into<String>,
        expected_peer_build_identity: impl Into<String>,
    ) -> Result<Self, HandshakeError> {
        Self::new(
            role,
            local_build_identity.into(),
            expected_peer_build_identity.into(),
            ProtocolVersion::CURRENT,
            None,
            HandshakeState::AwaitingHello,
        )
    }

    fn new(
        role: EndpointRole,
        local_build_identity: String,
        expected_peer_build_identity: String,
        offered_version: ProtocolVersion,
        nonce: Option<[u8; 16]>,
        state: HandshakeState,
    ) -> Result<Self, HandshakeError> {
        validate_build_identity(&local_build_identity)?;
        validate_build_identity(&expected_peer_build_identity)?;
        Ok(Self {
            role,
            local_build_identity,
            expected_peer_build_identity,
            offered_version,
            negotiated_version: None,
            nonce,
            state,
        })
    }

    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    #[must_use]
    pub const fn negotiated_version(&self) -> Option<ProtocolVersion> {
        self.negotiated_version
    }

    pub fn begin(&mut self, sequence: FrameSequence) -> Result<FrameHeader, HandshakeError> {
        let result = self.begin_inner(sequence);
        if result.is_err() {
            self.state = HandshakeState::Failed;
        }
        result
    }

    fn begin_inner(&mut self, sequence: FrameSequence) -> Result<FrameHeader, HandshakeError> {
        match self.state {
            HandshakeState::Ready => {}
            HandshakeState::AwaitingAcknowledgement | HandshakeState::Established => {
                return Err(HandshakeError::ReplayOrDuplicate);
            }
            HandshakeState::AwaitingHello => return Err(HandshakeError::WrongHandshakeSide),
            HandshakeState::Failed => return Err(HandshakeError::Terminal),
        }
        require_handshake_sequence(sequence)?;
        let nonce = self.nonce.ok_or(HandshakeError::WrongHandshakeSide)?;
        let mut frame = FrameHeader::new(
            sequence,
            MessageKind::Hello,
            0,
            None,
            ControlBody::Hello(HelloIdentity::new(
                nonce,
                self.role,
                self.role.outbound_direction(),
                self.local_build_identity.clone(),
            )?),
        )?;
        frame.version = self.offered_version;
        frame.validate()?;
        self.state = HandshakeState::AwaitingAcknowledgement;
        Ok(frame)
    }

    /// Accepts the peer handshake frame. A responder returns the acknowledgement
    /// it must send; an initiator returns `None` after validating that response.
    pub fn accept(&mut self, frame: &FrameHeader) -> Result<Option<FrameHeader>, HandshakeError> {
        let result = self.accept_inner(frame);
        if result.is_err() {
            self.state = HandshakeState::Failed;
        }
        result
    }

    fn accept_inner(&mut self, frame: &FrameHeader) -> Result<Option<FrameHeader>, HandshakeError> {
        if matches!(self.state, HandshakeState::Established) {
            return Err(HandshakeError::ReplayOrDuplicate);
        }
        if matches!(self.state, HandshakeState::Failed) {
            return Err(HandshakeError::Terminal);
        }
        frame.validate()?;
        require_handshake_sequence(frame.sequence)?;
        let hello = match &frame.body {
            ControlBody::Hello(hello) => hello,
            ControlBody::Bytes(_) => return Err(HandshakeError::MissingHelloIdentity),
        };
        match self.state {
            HandshakeState::AwaitingHello => {
                require_kind(frame.kind, MessageKind::Hello)?;
                self.validate_peer(hello)?;
                let mut acknowledgement = FrameHeader::new(
                    FrameSequence::new(1)?,
                    MessageKind::HelloAck,
                    0,
                    None,
                    ControlBody::Hello(HelloIdentity::new(
                        hello.nonce,
                        self.role,
                        self.role.outbound_direction(),
                        self.local_build_identity.clone(),
                    )?),
                )?;
                acknowledgement.version = frame.version;
                acknowledgement.validate()?;
                self.nonce = Some(hello.nonce);
                self.negotiated_version = Some(frame.version);
                self.state = HandshakeState::Established;
                Ok(Some(acknowledgement))
            }
            HandshakeState::AwaitingAcknowledgement => {
                require_kind(frame.kind, MessageKind::HelloAck)?;
                self.validate_peer(hello)?;
                if frame.version != self.offered_version {
                    return Err(HandshakeError::ProtocolVersionMismatch);
                }
                if self.nonce != Some(hello.nonce) {
                    return Err(HandshakeError::NonceMismatch);
                }
                self.negotiated_version = Some(frame.version);
                self.state = HandshakeState::Established;
                Ok(None)
            }
            HandshakeState::Ready => Err(HandshakeError::HandshakeNotStarted),
            HandshakeState::Established => Err(HandshakeError::ReplayOrDuplicate),
            HandshakeState::Failed => Err(HandshakeError::Terminal),
        }
    }

    fn validate_peer(&self, hello: &HelloIdentity) -> Result<(), HandshakeError> {
        if hello.role != self.role.peer() {
            return Err(HandshakeError::PeerRoleMismatch);
        }
        if hello.direction != hello.role.outbound_direction() {
            return Err(HandshakeError::PeerDirectionMismatch);
        }
        if hello.build_identity != self.expected_peer_build_identity {
            return Err(HandshakeError::PeerBuildIdentityMismatch);
        }
        Ok(())
    }
}

fn require_handshake_sequence(sequence: FrameSequence) -> Result<(), HandshakeError> {
    if sequence.get() == 1 {
        Ok(())
    } else {
        Err(HandshakeError::UnexpectedSequence {
            expected: 1,
            actual: sequence.get(),
        })
    }
}

fn require_kind(actual: MessageKind, expected: MessageKind) -> Result<(), HandshakeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(HandshakeError::UnexpectedMessageKind { expected, actual })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlBody {
    Hello(HelloIdentity),
    /// Opaque bounded control bytes for a versioned codec above this layer.
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: ProtocolVersion,
    pub sequence: FrameSequence,
    pub kind: MessageKind,
    pub raw_len: u32,
    pub raw_address: Option<u64>,
    pub body: ControlBody,
}

impl FrameHeader {
    pub fn new(
        sequence: FrameSequence,
        kind: MessageKind,
        raw_len: u32,
        raw_address: Option<u64>,
        body: ControlBody,
    ) -> Result<Self, WireError> {
        let header = Self {
            version: ProtocolVersion::CURRENT,
            sequence,
            kind,
            raw_len,
            raw_address,
            body,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn validate(&self) -> Result<(), WireError> {
        self.version.validate()?;
        if self.raw_len > MAX_RAW_BYTES {
            return Err(WireError::RawTooLarge {
                declared: self.raw_len,
                maximum: MAX_RAW_BYTES,
            });
        }
        if let Some(address) = self.raw_address {
            if self.raw_len == 0 {
                return Err(WireError::AddressWithoutPayload);
            }
            address
                .checked_add(u64::from(self.raw_len))
                .ok_or(WireError::AddressOverflow {
                    address,
                    length: self.raw_len,
                })?;
        }
        let hello_kind = matches!(self.kind, MessageKind::Hello | MessageKind::HelloAck);
        match (&self.body, hello_kind) {
            (ControlBody::Hello(hello), true) => {
                hello.validate()?;
                if self.raw_len != 0 || self.raw_address.is_some() {
                    return Err(WireError::Malformed("hello carries raw payload"));
                }
            }
            (ControlBody::Bytes(_), false) => {}
            _ => return Err(WireError::Malformed("message kind/body mismatch")),
        }
        self.control_len()?;
        Ok(())
    }

    fn control_len(&self) -> Result<usize, WireError> {
        let body = match &self.body {
            ControlBody::Hello(hello) => HELLO_FIXED_BYTES
                .checked_add(hello.build_identity.len())
                .ok_or(WireError::LengthOverflow)?,
            ControlBody::Bytes(bytes) => bytes.len(),
        };
        let total = FIXED_CONTROL_BYTES
            .checked_add(body)
            .ok_or(WireError::LengthOverflow)?;
        validate_control_len(total)?;
        Ok(total)
    }

    pub fn frame_len(&self) -> Result<usize, WireError> {
        let raw = usize::try_from(self.raw_len).map_err(|_| WireError::LengthOverflow)?;
        PREFIX_BYTES
            .checked_add(self.control_len()?)
            .and_then(|value| value.checked_add(raw))
            .ok_or(WireError::LengthOverflow)
    }
}

/// Encodes the prefix and control header. The caller then streams exactly
/// `header.raw_len` raw bytes without folding them into the control allocation.
pub fn encode_control(header: &FrameHeader) -> Result<Vec<u8>, WireError> {
    header.validate()?;
    let control_len = header.control_len()?;
    let capacity = PREFIX_BYTES
        .checked_add(control_len)
        .ok_or(WireError::LengthOverflow)?;
    let wire_len = u32::try_from(control_len).map_err(|_| WireError::LengthOverflow)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&wire_len.to_le_bytes());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&header.version.major.to_le_bytes());
    out.extend_from_slice(&header.version.minor.to_le_bytes());
    out.extend_from_slice(&header.sequence.get().to_le_bytes());
    out.push(header.kind as u8);
    out.push(u8::from(header.raw_address.is_some()) * ADDRESS_FLAG);
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&header.raw_len.to_le_bytes());
    out.extend_from_slice(&header.raw_address.unwrap_or(0).to_le_bytes());
    match &header.body {
        ControlBody::Hello(hello) => {
            out.extend_from_slice(&hello.nonce);
            out.push(hello.role as u8);
            out.push(hello.direction as u8);
            let length =
                u16::try_from(hello.build_identity.len()).map_err(|_| WireError::LengthOverflow)?;
            out.extend_from_slice(&length.to_le_bytes());
            out.extend_from_slice(hello.build_identity.as_bytes());
        }
        ControlBody::Bytes(bytes) => out.extend_from_slice(bytes),
    }
    Ok(out)
}

pub fn decode_control(control: &[u8]) -> Result<FrameHeader, WireError> {
    if control.len() < FIXED_CONTROL_BYTES {
        return Err(WireError::ControlTooSmall {
            declared: control.len(),
            minimum: FIXED_CONTROL_BYTES,
        });
    }
    validate_control_len(control.len())?;
    if array::<4>(control, 0)? != MAGIC {
        return Err(WireError::InvalidMagic);
    }
    let version = ProtocolVersion {
        major: u16::from_le_bytes(array(control, 4)?),
        minor: u16::from_le_bytes(array(control, 6)?),
    };
    let sequence = FrameSequence::new(u64::from_le_bytes(array(control, 8)?))?;
    let kind = MessageKind::try_from(control[16])?;
    let flags = control[17];
    if flags & !ADDRESS_FLAG != 0 || u16::from_le_bytes(array(control, 18)?) != 0 {
        return Err(WireError::Malformed("unknown flags or reserved bits"));
    }
    let raw_len = u32::from_le_bytes(array(control, 20)?);
    let address = u64::from_le_bytes(array(control, 24)?);
    let raw_address = if flags & ADDRESS_FLAG != 0 {
        Some(address)
    } else if address == 0 {
        None
    } else {
        return Err(WireError::Malformed("noncanonical absent address"));
    };
    let bytes = &control[FIXED_CONTROL_BYTES..];
    let body = if matches!(kind, MessageKind::Hello | MessageKind::HelloAck) {
        if bytes.len() < HELLO_FIXED_BYTES {
            return Err(WireError::Malformed("truncated hello"));
        }
        let nonce = array::<16>(bytes, 0)?;
        let role = EndpointRole::try_from(bytes[16])?;
        let direction = MessageDirection::try_from(bytes[17])?;
        let build_len = usize::from(u16::from_le_bytes(array(bytes, 18)?));
        let expected = HELLO_FIXED_BYTES
            .checked_add(build_len)
            .ok_or(WireError::LengthOverflow)?;
        if expected != bytes.len() {
            return Err(WireError::Malformed("hello length mismatch"));
        }
        let build = std::str::from_utf8(&bytes[HELLO_FIXED_BYTES..])
            .map_err(|_| WireError::InvalidBuildIdentity)?;
        ControlBody::Hello(HelloIdentity::new(nonce, role, direction, build)?)
    } else {
        ControlBody::Bytes(bytes.to_vec())
    };
    let header = FrameHeader {
        version,
        sequence,
        kind,
        raw_len,
        raw_address,
        body,
    };
    header.validate()?;
    Ok(header)
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], WireError> {
    let end = offset.checked_add(N).ok_or(WireError::LengthOverflow)?;
    let source = bytes.get(offset..end).ok_or(WireError::ControlTooSmall {
        declared: bytes.len(),
        minimum: end,
    })?;
    let mut value = [0_u8; N];
    value.copy_from_slice(source);
    Ok(value)
}

fn validate_control_len(length: usize) -> Result<(), WireError> {
    if length == 0 {
        return Err(WireError::ZeroControlLength);
    }
    if length > MAX_CONTROL_BYTES {
        return Err(WireError::ControlTooLarge {
            declared: length,
            maximum: MAX_CONTROL_BYTES,
        });
    }
    Ok(())
}

#[derive(Debug)]
pub struct DecodedFrame<'a> {
    pub header: FrameHeader,
    pub raw: &'a [u8],
    pub consumed: usize,
}

pub fn decode_frame<'a>(
    bytes: &'a [u8],
    sequences: &mut SequenceTracker,
) -> Result<DecodedFrame<'a>, WireError> {
    if bytes.len() < PREFIX_BYTES {
        return Err(WireError::Truncated {
            needed: PREFIX_BYTES,
            available: bytes.len(),
        });
    }
    let control_len = usize::try_from(u32::from_le_bytes(array(bytes, 0)?))
        .map_err(|_| WireError::LengthOverflow)?;
    validate_control_len(control_len)?; // Bound before parsing or allocating.
    let control_end = PREFIX_BYTES
        .checked_add(control_len)
        .ok_or(WireError::LengthOverflow)?;
    if bytes.len() < control_end {
        return Err(WireError::Truncated {
            needed: control_end,
            available: bytes.len(),
        });
    }
    let header = decode_control(&bytes[PREFIX_BYTES..control_end])?;
    let raw_len = usize::try_from(header.raw_len).map_err(|_| WireError::LengthOverflow)?;
    let total = control_end
        .checked_add(raw_len)
        .ok_or(WireError::LengthOverflow)?;
    if bytes.len() < total {
        return Err(WireError::Truncated {
            needed: total,
            available: bytes.len(),
        });
    }
    sequences.observe(header.sequence)?;
    Ok(DecodedFrame {
        header,
        raw: &bytes[control_end..total],
        consumed: total,
    })
}

#[derive(Debug, Default)]
pub struct SequenceTracker(Option<FrameSequence>);

impl SequenceTracker {
    pub fn observe(&mut self, sequence: FrameSequence) -> Result<(), WireError> {
        if let Some(previous) = self.0 {
            if sequence <= previous {
                return Err(WireError::OutOfOrder {
                    previous: previous.get(),
                    received: sequence.get(),
                });
            }
        }
        self.0 = Some(sequence);
        Ok(())
    }
}

/// Incrementally reads only the four-byte prefix and bounded control header.
/// It never buffers raw payload bytes.
#[derive(Debug, Default)]
pub struct HeaderDecoder {
    prefix: [u8; PREFIX_BYTES],
    prefix_used: usize,
    expected: Option<usize>,
    control: Vec<u8>,
    done: bool,
}

impl HeaderDecoder {
    pub fn push(&mut self, input: &[u8]) -> Result<(usize, Option<FrameHeader>), WireError> {
        if self.done {
            return Err(WireError::DecoderComplete);
        }
        let mut consumed = 0;
        if self.prefix_used < PREFIX_BYTES {
            let take = (PREFIX_BYTES - self.prefix_used).min(input.len());
            self.prefix[self.prefix_used..self.prefix_used + take].copy_from_slice(&input[..take]);
            self.prefix_used += take;
            consumed += take;
            if self.prefix_used < PREFIX_BYTES {
                return Ok((consumed, None));
            }
            let expected = usize::try_from(u32::from_le_bytes(self.prefix))
                .map_err(|_| WireError::LengthOverflow)?;
            validate_control_len(expected)?; // Reject before Vec allocation.
            self.control = Vec::with_capacity(expected);
            self.expected = Some(expected);
        }
        let expected = self.expected.ok_or(WireError::LengthOverflow)?;
        let take = (expected - self.control.len()).min(input.len() - consumed);
        self.control
            .extend_from_slice(&input[consumed..consumed + take]);
        consumed += take;
        if self.control.len() == expected {
            let header = decode_control(&self.control)?;
            self.done = true;
            return Ok((consumed, Some(header)));
        }
        Ok((consumed, None))
    }

    pub fn finish(&self) -> Result<(), WireError> {
        if self.done {
            return Ok(());
        }
        let needed = self
            .expected
            .and_then(|value| PREFIX_BYTES.checked_add(value))
            .unwrap_or(PREFIX_BYTES);
        let available = self
            .prefix_used
            .checked_add(self.control.len())
            .ok_or(WireError::LengthOverflow)?;
        Err(WireError::Truncated { needed, available })
    }

    #[must_use]
    pub fn buffered_control_bytes(&self) -> usize {
        self.control.len()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("unsupported protocol {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("frame sequence must be nonzero")]
    ZeroSequence,
    #[error("hello nonce must be nonzero")]
    ZeroHelloNonce,
    #[error("invalid build identity")]
    InvalidBuildIdentity,
    #[error("unknown endpoint role {value}")]
    UnknownEndpointRole { value: u8 },
    #[error("unknown message direction {value}")]
    UnknownMessageDirection { value: u8 },
    #[error("hello endpoint role and direction disagree")]
    RoleDirectionMismatch,
    #[error("build identity has {actual} bytes; maximum is {maximum}")]
    BuildIdentityTooLong { actual: usize, maximum: usize },
    #[error("control length cannot be zero")]
    ZeroControlLength,
    #[error("control has {declared} bytes; minimum is {minimum}")]
    ControlTooSmall { declared: usize, minimum: usize },
    #[error("control has {declared} bytes; maximum is {maximum}")]
    ControlTooLarge { declared: usize, maximum: usize },
    #[error("raw payload has {declared} bytes; maximum is {maximum}")]
    RawTooLarge { declared: u32, maximum: u32 },
    #[error("raw address {address:#x}+{length:#x} overflows")]
    AddressOverflow { address: u64, length: u32 },
    #[error("raw address requires a nonempty payload")]
    AddressWithoutPayload,
    #[error("frame length arithmetic overflow")]
    LengthOverflow,
    #[error("invalid control magic")]
    InvalidMagic,
    #[error("unknown message kind {value}")]
    UnknownMessageKind { value: u8 },
    #[error("malformed control: {0}")]
    Malformed(&'static str),
    #[error("truncated frame: need {needed} bytes, have {available}")]
    Truncated { needed: usize, available: usize },
    #[error("sequence {received} is not newer than {previous}")]
    OutOfOrder { previous: u64, received: u64 },
    #[error("header decoder already completed")]
    DecoderComplete,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandshakeError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("handshake frame sequence {actual} does not equal required sequence {expected}")]
    UnexpectedSequence { expected: u64, actual: u64 },
    #[error("expected {expected:?} during handshake, received {actual:?}")]
    UnexpectedMessageKind {
        expected: MessageKind,
        actual: MessageKind,
    },
    #[error("handshake frame did not contain a hello identity")]
    MissingHelloIdentity,
    #[error("handshake protocol version does not exactly match")]
    ProtocolVersionMismatch,
    #[error("handshake peer role does not match the opposite endpoint")]
    PeerRoleMismatch,
    #[error("handshake peer direction does not match its endpoint role")]
    PeerDirectionMismatch,
    #[error("handshake peer build identity does not match the expected identity")]
    PeerBuildIdentityMismatch,
    #[error("handshake acknowledgement nonce does not match the challenge")]
    NonceMismatch,
    #[error("handshake has not been started")]
    HandshakeNotStarted,
    #[error("this endpoint cannot initiate the configured handshake")]
    WrongHandshakeSide,
    #[error("handshake frame is a replay or duplicate")]
    ReplayOrDuplicate,
    #[error("handshake is terminal after a validation failure")]
    Terminal,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(sequence: u64) -> FrameHeader {
        FrameHeader::new(
            FrameSequence::new(sequence).unwrap(),
            MessageKind::Hello,
            0,
            None,
            ControlBody::Hello(
                HelloIdentity::new(
                    [0x5a; 16],
                    EndpointRole::Controller,
                    MessageDirection::ControllerToHost,
                    "controller/test",
                )
                .unwrap(),
            ),
        )
        .unwrap()
    }

    #[test]
    fn incremental_header_round_trips() {
        let encoded = encode_control(&hello(1)).unwrap();
        let mut decoder = HeaderDecoder::default();
        assert_eq!(decoder.push(&encoded[..2]).unwrap(), (2, None));
        let (used, decoded) = decoder.push(&encoded[2..]).unwrap();
        assert_eq!(used, encoded.len() - 2);
        assert_eq!(decoded.unwrap(), hello(1));
        decoder.finish().unwrap();
    }

    #[test]
    fn oversized_and_zero_lengths_fail_before_allocation() {
        let mut oversized = HeaderDecoder::default();
        let prefix = u32::try_from(MAX_CONTROL_BYTES + 1).unwrap().to_le_bytes();
        assert!(matches!(
            oversized.push(&prefix),
            Err(WireError::ControlTooLarge { .. })
        ));
        assert_eq!(oversized.buffered_control_bytes(), 0);
        let mut zero = HeaderDecoder::default();
        assert_eq!(
            zero.push(&0_u32.to_le_bytes()).unwrap_err(),
            WireError::ZeroControlLength
        );
        assert_eq!(zero.buffered_control_bytes(), 0);
    }

    #[test]
    fn truncated_frames_are_explicit() {
        let encoded = encode_control(&hello(1)).unwrap();
        let mut sequences = SequenceTracker::default();
        assert!(matches!(
            decode_frame(&encoded[..encoded.len() - 1], &mut sequences),
            Err(WireError::Truncated { .. })
        ));
        let mut decoder = HeaderDecoder::default();
        decoder.push(&encoded[..7]).unwrap();
        assert!(matches!(decoder.finish(), Err(WireError::Truncated { .. })));
    }

    #[test]
    fn zero_and_out_of_order_sequences_fail() {
        let mut encoded = encode_control(&hello(1)).unwrap();
        encoded[12..20].fill(0);
        let mut sequences = SequenceTracker::default();
        assert_eq!(
            decode_frame(&encoded, &mut sequences).unwrap_err(),
            WireError::ZeroSequence
        );
        sequences.observe(FrameSequence::new(9).unwrap()).unwrap();
        assert!(matches!(
            sequences.observe(FrameSequence::new(8).unwrap()),
            Err(WireError::OutOfOrder { .. })
        ));
    }

    #[test]
    fn raw_bounds_and_address_overflow_fail() {
        let sequence = FrameSequence::new(1).unwrap();
        assert!(matches!(
            FrameHeader::new(
                sequence,
                MessageKind::Event,
                MAX_RAW_BYTES + 1,
                None,
                ControlBody::Bytes(vec![])
            ),
            Err(WireError::RawTooLarge { .. })
        ));
        assert_eq!(
            FrameHeader::new(
                sequence,
                MessageKind::Event,
                4,
                Some(u64::MAX - 1),
                ControlBody::Bytes(vec![])
            )
            .unwrap_err(),
            WireError::AddressOverflow {
                address: u64::MAX - 1,
                length: 4
            }
        );
    }

    #[test]
    fn raw_bytes_are_separate_and_newline_safe() {
        let header = FrameHeader::new(
            FrameSequence::new(1).unwrap(),
            MessageKind::Event,
            3,
            Some(0x1400_001000),
            ControlBody::Bytes(vec![0, b'\n', 0xff]),
        )
        .unwrap();
        let mut frame = encode_control(&header).unwrap();
        frame.extend_from_slice(&[1, 2, 3]);
        let decoded = decode_frame(&frame, &mut SequenceTracker::default()).unwrap();
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.raw, &[1, 2, 3]);
        assert_eq!(decoded.consumed, frame.len());
    }

    #[test]
    fn handshake_binds_nonce_roles_directions_builds_and_sequences() {
        let nonce = [0x91; 16];
        let mut controller = HandshakeMachine::initiator(
            EndpointRole::Controller,
            nonce,
            "controller/build-7",
            "host/build-4",
        )
        .unwrap();
        let mut host =
            HandshakeMachine::responder(EndpointRole::Host, "host/build-4", "controller/build-7")
                .unwrap();

        let hello = controller.begin(FrameSequence::new(1).unwrap()).unwrap();
        let acknowledgement = host.accept(&hello).unwrap().unwrap();
        assert_eq!(host.state(), HandshakeState::Established);
        assert_eq!(host.negotiated_version(), Some(ProtocolVersion::CURRENT));
        assert_eq!(controller.accept(&acknowledgement).unwrap(), None);
        assert_eq!(controller.state(), HandshakeState::Established);
        assert_eq!(
            controller.negotiated_version(),
            Some(ProtocolVersion::CURRENT)
        );
        assert!(matches!(
            controller.accept(&acknowledgement),
            Err(HandshakeError::ReplayOrDuplicate)
        ));
        assert_eq!(controller.state(), HandshakeState::Failed);
    }

    #[test]
    fn handshake_rejects_reflection_and_becomes_terminal() {
        let mut controller = HandshakeMachine::initiator(
            EndpointRole::Controller,
            [0x71; 16],
            "controller/build",
            "host/build",
        )
        .unwrap();
        let reflected = controller.begin(FrameSequence::new(1).unwrap()).unwrap();
        assert!(matches!(
            controller.accept(&reflected),
            Err(HandshakeError::UnexpectedMessageKind {
                expected: MessageKind::HelloAck,
                actual: MessageKind::Hello
            })
        ));
        assert_eq!(controller.state(), HandshakeState::Failed);
        assert_eq!(controller.accept(&reflected), Err(HandshakeError::Terminal));
    }

    #[test]
    fn handshake_rejects_nonce_build_and_order_mismatches() {
        let mut out_of_order = HandshakeMachine::initiator(
            EndpointRole::Controller,
            [0x31; 16],
            "controller/build",
            "host/build",
        )
        .unwrap();
        assert_eq!(
            out_of_order.begin(FrameSequence::new(2).unwrap()),
            Err(HandshakeError::UnexpectedSequence {
                expected: 1,
                actual: 2
            })
        );

        let mut controller = HandshakeMachine::initiator(
            EndpointRole::Controller,
            [0x31; 16],
            "controller/build",
            "host/build",
        )
        .unwrap();
        controller.begin(FrameSequence::new(1).unwrap()).unwrap();
        let wrong_nonce = FrameHeader::new(
            FrameSequence::new(1).unwrap(),
            MessageKind::HelloAck,
            0,
            None,
            ControlBody::Hello(
                HelloIdentity::new(
                    [0x32; 16],
                    EndpointRole::Host,
                    MessageDirection::HostToController,
                    "host/build",
                )
                .unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(
            controller.accept(&wrong_nonce),
            Err(HandshakeError::NonceMismatch)
        );

        let mut host =
            HandshakeMachine::responder(EndpointRole::Host, "host/build", "controller/expected")
                .unwrap();
        assert_eq!(
            host.accept(&hello(1)),
            Err(HandshakeError::PeerBuildIdentityMismatch)
        );
    }

    #[test]
    fn handshake_rejects_an_unsupported_offered_version_before_exchange() {
        assert!(matches!(
            HandshakeMachine::initiator_for_version(
                EndpointRole::Controller,
                [0x41; 16],
                "controller/build",
                "host/build",
                ProtocolVersion {
                    major: PROTOCOL_MAJOR + 1,
                    minor: 0,
                },
            ),
            Err(HandshakeError::Wire(WireError::UnsupportedVersion { .. }))
        ));
    }

    #[test]
    fn hello_codec_rejects_unknown_or_inconsistent_direction_bytes() {
        let encoded = encode_control(&hello(1)).unwrap();
        let control = &encoded[PREFIX_BYTES..];
        let mut unknown_role = control.to_vec();
        unknown_role[FIXED_CONTROL_BYTES + 16] = 9;
        assert_eq!(
            decode_control(&unknown_role),
            Err(WireError::UnknownEndpointRole { value: 9 })
        );

        let mut reflected_direction = control.to_vec();
        reflected_direction[FIXED_CONTROL_BYTES + 17] = MessageDirection::HostToController as u8;
        assert_eq!(
            decode_control(&reflected_direction),
            Err(WireError::RoleDirectionMismatch)
        );
    }
}
