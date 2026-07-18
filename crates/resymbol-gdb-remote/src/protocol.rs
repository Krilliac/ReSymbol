//! GDB Remote Serial Protocol (RSP) framing: packet encoding, an incremental
//! packet decoder, escaping, run-length decoding, and hex helpers.
//!
//! A packet on the wire is `$<body>#<cc>` where `<cc>` is a two-digit lowercase
//! hex checksum equal to the modulo-256 sum of every byte of `<body>` (the
//! bytes actually transmitted between `$` and `#`, i.e. after escaping). This
//! matches the checksum GDB and gdbserver compute, so packets produced here
//! interoperate with real stubs and debuggers.
//!
//! Escaping: within a body, each of `#`, `$`, `}`, and `*` is transmitted as
//! `}` followed by the original byte XOR `0x20`. Decoding reverses this and
//! additionally expands run-length encoding: a data byte followed by `*` and a
//! count byte `n` repeats the preceding decoded byte `n - 29` additional times
//! (so `0* ` — with a trailing space, value 32 — decodes to `0000`).
//!
//! This module performs no I/O and contains no `unsafe`. The [`PacketReader`]
//! consumes bytes one at a time and yields [`PacketEvent`]s, keeping the
//! transport layer free of protocol state.

/// The escape prefix byte (`}`) and the XOR mask applied to escaped bytes.
const ESCAPE_BYTE: u8 = b'}';
const ESCAPE_MASK: u8 = 0x20;

/// The run-length marker (`*`) and the bias applied to its count byte.
const RLE_MARKER: u8 = b'*';
const RLE_BIAS: u8 = 29;

/// Encode `payload` into a complete RSP packet (`$<escaped-body>#<checksum>`).
///
/// Each of `#`, `$`, `}`, and `*` in `payload` is escaped; the checksum is the
/// modulo-256 sum of the transmitted body bytes.
#[must_use]
pub fn encode_packet(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.push(b'$');
    let mut checksum: u8 = 0;
    for &byte in payload {
        match byte {
            b'#' | b'$' | ESCAPE_BYTE | RLE_MARKER => {
                checksum = checksum.wrapping_add(ESCAPE_BYTE);
                out.push(ESCAPE_BYTE);
                let escaped = byte ^ ESCAPE_MASK;
                checksum = checksum.wrapping_add(escaped);
                out.push(escaped);
            }
            other => {
                checksum = checksum.wrapping_add(other);
                out.push(other);
            }
        }
    }
    out.push(b'#');
    let [hi, lo] = hex_byte(checksum);
    out.push(hi);
    out.push(lo);
    out
}

/// Decode an RSP packet body: reverse escaping and expand run-length encoding.
///
/// `body` is the raw sequence of bytes transmitted between `$` and `#`.
/// Returns `None` if the body is malformed (a dangling escape, a run-length
/// marker with no preceding byte, or an out-of-range count byte).
#[must_use]
pub fn decode_body(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        match body[index] {
            ESCAPE_BYTE => {
                let escaped = *body.get(index + 1)?;
                out.push(escaped ^ ESCAPE_MASK);
                index += 2;
            }
            RLE_MARKER => {
                let count_byte = *body.get(index + 1)?;
                let additional = count_byte.checked_sub(RLE_BIAS)?;
                let previous = *out.last()?;
                for _ in 0..additional {
                    out.push(previous);
                }
                index += 2;
            }
            literal => {
                out.push(literal);
                index += 1;
            }
        }
    }
    Some(out)
}

/// The modulo-256 checksum of `body` (its transmitted bytes).
#[must_use]
pub fn checksum(body: &[u8]) -> u8 {
    body.iter().copied().fold(0u8, u8::wrapping_add)
}

/// An event produced by [`PacketReader`] as bytes are consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketEvent {
    /// A positive acknowledgement (`+`).
    Ack,
    /// A negative acknowledgement (`-`); the peer wants a resend.
    Nack,
    /// An out-of-band interrupt request (`0x03`, Ctrl-C).
    Interrupt,
    /// A fully framed packet. `checksum_ok` is false when the received checksum
    /// did not match or the body could not be decoded, in which case `payload`
    /// is empty and the receiver should send a `-`.
    Packet {
        /// The decoded payload (empty when `checksum_ok` is false).
        payload: Vec<u8>,
        /// Whether the checksum verified and the body decoded cleanly.
        checksum_ok: bool,
    },
}

/// Internal parser state for [`PacketReader`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Awaiting a `$`, an ack byte, or an interrupt.
    Idle,
    /// Accumulating body bytes until `#`.
    Body,
    /// Reading the first checksum hex digit.
    Checksum1,
    /// Reading the second checksum hex digit.
    Checksum2,
}

/// An incremental RSP packet decoder.
///
/// Feed received bytes one at a time via [`PacketReader::push`]; each byte may
/// complete an event. The reader tolerates leading garbage before `$` and
/// recognises `+`, `-`, and the `0x03` interrupt outside of packets.
#[derive(Debug)]
pub struct PacketReader {
    state: State,
    body: Vec<u8>,
    running_checksum: u8,
    expected_checksum: u8,
}

impl Default for PacketReader {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketReader {
    /// Create a reader in its initial idle state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            body: Vec::new(),
            running_checksum: 0,
            expected_checksum: 0,
        }
    }

    /// Consume one received byte, returning an event when one completes.
    pub fn push(&mut self, byte: u8) -> Option<PacketEvent> {
        match self.state {
            State::Idle => match byte {
                b'$' => {
                    self.body.clear();
                    self.running_checksum = 0;
                    self.state = State::Body;
                    None
                }
                b'+' => Some(PacketEvent::Ack),
                b'-' => Some(PacketEvent::Nack),
                0x03 => Some(PacketEvent::Interrupt),
                _ => None,
            },
            State::Body => {
                if byte == b'#' {
                    self.state = State::Checksum1;
                } else {
                    self.running_checksum = self.running_checksum.wrapping_add(byte);
                    self.body.push(byte);
                }
                None
            }
            State::Checksum1 => {
                match from_hex_digit(byte) {
                    Some(value) => {
                        self.expected_checksum = value << 4;
                        self.state = State::Checksum2;
                        None
                    }
                    None => {
                        // Malformed checksum digit: abandon the frame.
                        self.state = State::Idle;
                        Some(PacketEvent::Packet {
                            payload: Vec::new(),
                            checksum_ok: false,
                        })
                    }
                }
            }
            State::Checksum2 => {
                self.state = State::Idle;
                let low = match from_hex_digit(byte) {
                    Some(value) => value,
                    None => {
                        return Some(PacketEvent::Packet {
                            payload: Vec::new(),
                            checksum_ok: false,
                        });
                    }
                };
                self.expected_checksum |= low;
                let matches = self.expected_checksum == self.running_checksum;
                if !matches {
                    return Some(PacketEvent::Packet {
                        payload: Vec::new(),
                        checksum_ok: false,
                    });
                }
                match decode_body(&self.body) {
                    Some(payload) => Some(PacketEvent::Packet {
                        payload,
                        checksum_ok: true,
                    }),
                    None => Some(PacketEvent::Packet {
                        payload: Vec::new(),
                        checksum_ok: false,
                    }),
                }
            }
        }
    }
}

/// Encode `data` as lowercase ASCII hex (two digits per byte).
#[must_use]
pub fn hex_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2);
    for &byte in data {
        let [hi, lo] = hex_byte(byte);
        out.push(hi);
        out.push(lo);
    }
    out
}

/// Decode ASCII hex `data` into bytes, or `None` if it is not valid hex.
#[must_use]
pub fn hex_decode(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() / 2);
    for pair in data.chunks_exact(2) {
        let hi = from_hex_digit(pair[0])?;
        let lo = from_hex_digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Parse an ASCII hex string into a `u64`, or `None` on empty/invalid input.
#[must_use]
pub fn parse_hex_u64(data: &[u8]) -> Option<u64> {
    if data.is_empty() || data.len() > 16 {
        return None;
    }
    let mut value: u64 = 0;
    for &byte in data {
        value = (value << 4) | u64::from(from_hex_digit(byte)?);
    }
    Some(value)
}

/// The two lowercase hex digits of `byte`, high nibble first.
#[must_use]
fn hex_byte(byte: u8) -> [u8; 2] {
    [hex_digit(byte >> 4), hex_digit(byte & 0x0f)]
}

/// Map a nibble (0..=15) to its lowercase hex ASCII digit.
#[must_use]
fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    }
}

/// Map a hex ASCII digit to its value, or `None` if not a hex digit.
#[must_use]
fn from_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(reader: &mut PacketReader, bytes: &[u8]) -> Vec<PacketEvent> {
        let mut events = Vec::new();
        for &byte in bytes {
            if let Some(event) = reader.push(byte) {
                events.push(event);
            }
        }
        events
    }

    #[test]
    fn encodes_simple_payload_with_correct_checksum() {
        // "OK" -> 'O'(0x4f) + 'K'(0x4b) = 0x9a.
        assert_eq!(encode_packet(b"OK"), b"$OK#9a");
    }

    #[test]
    fn round_trips_through_reader() {
        let packet = encode_packet(b"qSupported:swbreak+");
        let mut reader = PacketReader::new();
        let events = drain(&mut reader, &packet);
        assert_eq!(
            events,
            vec![PacketEvent::Packet {
                payload: b"qSupported:swbreak+".to_vec(),
                checksum_ok: true,
            }]
        );
    }

    #[test]
    fn escapes_and_unescapes_all_four_special_bytes() {
        let payload = b"a#b$c}d*e";
        let packet = encode_packet(payload);
        // Each special byte becomes `}` + (byte ^ 0x20); none appears raw.
        for special in [b'#', b'$', b'}', b'*'] {
            let raw_count = packet[1..packet.len() - 3]
                .iter()
                .filter(|&&b| b == special && b != ESCAPE_BYTE)
                .count();
            // `}` legitimately appears as the escape prefix, so only assert the
            // other three never appear unescaped in the body.
            if special != ESCAPE_BYTE {
                assert_eq!(raw_count, 0, "special {special:#x} leaked into body");
            }
        }
        let mut reader = PacketReader::new();
        let events = drain(&mut reader, &packet);
        assert_eq!(
            events,
            vec![PacketEvent::Packet {
                payload: payload.to_vec(),
                checksum_ok: true,
            }]
        );
    }

    #[test]
    fn expands_run_length_encoding_gdb_example() {
        // Canonical GDB example: `0* ` decodes to "0000" (space = 32, 32-29=3
        // additional zeros beyond the leading '0').
        assert_eq!(decode_body(b"0* ").unwrap(), b"0000");
    }

    #[test]
    fn run_length_inside_a_full_packet() {
        // Body "0* " has checksum 0x30 + 0x2a + 0x20 = 0x7a.
        let mut reader = PacketReader::new();
        let events = drain(&mut reader, b"$0* #7a");
        assert_eq!(
            events,
            vec![PacketEvent::Packet {
                payload: b"0000".to_vec(),
                checksum_ok: true,
            }]
        );
    }

    #[test]
    fn detects_bad_checksum() {
        let mut reader = PacketReader::new();
        // Correct checksum for "OK" is 9a; feed a wrong one.
        let events = drain(&mut reader, b"$OK#00");
        assert_eq!(
            events,
            vec![PacketEvent::Packet {
                payload: Vec::new(),
                checksum_ok: false,
            }]
        );
    }

    #[test]
    fn recognises_acks_and_interrupt() {
        let mut reader = PacketReader::new();
        assert_eq!(
            drain(&mut reader, b"+-\x03"),
            vec![PacketEvent::Ack, PacketEvent::Nack, PacketEvent::Interrupt]
        );
    }

    #[test]
    fn ignores_leading_garbage_before_dollar() {
        let mut reader = PacketReader::new();
        let events = drain(&mut reader, b"junk$OK#9a");
        assert_eq!(
            events,
            vec![PacketEvent::Packet {
                payload: b"OK".to_vec(),
                checksum_ok: true,
            }]
        );
    }

    #[test]
    fn dangling_escape_is_rejected() {
        assert_eq!(decode_body(b"abc}"), None);
    }

    #[test]
    fn run_length_without_preceding_byte_is_rejected() {
        assert_eq!(decode_body(b"* "), None);
    }

    #[test]
    fn hex_round_trips() {
        let data = &[0x00, 0x7f, 0x80, 0xff, 0xde, 0xad];
        let encoded = hex_encode(data);
        assert_eq!(encoded, b"007f80ffdead");
        assert_eq!(hex_decode(&encoded).unwrap(), data);
    }

    #[test]
    fn parses_hex_u64() {
        assert_eq!(parse_hex_u64(b"deadbeef"), Some(0xdead_beef));
        assert_eq!(parse_hex_u64(b"0"), Some(0));
        assert_eq!(parse_hex_u64(b""), None);
        assert_eq!(parse_hex_u64(b"xyz"), None);
    }
}
