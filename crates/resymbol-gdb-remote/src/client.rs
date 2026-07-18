//! An RSP client that drives a remote stub (a QEMU gdbstub, a kernel debug
//! stub, or ReSymbol's own [`crate::server`]) over a [`Transport`].
//!
//! Each request goes out as a framed packet and is acknowledged; each reply is
//! read, its checksum verified, and acknowledged in turn. The typed helpers
//! wrap the common packets (`g`/`G`, `m`/`M`, `c`/`s`, `Z0`/`z0`, `qSupported`)
//! and surface protocol errors (`Exx`) as [`io::Error`]s.

use crate::protocol::{PacketEvent, PacketReader, encode_packet, hex_decode, hex_encode};
use crate::target::StopReply;
use crate::transport::Transport;
use std::io;

/// The maximum number of times a request is resent after a `-` (nack).
const MAX_RESENDS: usize = 8;

/// An RSP client bound to one transport.
#[derive(Debug)]
pub struct GdbRemoteClient<T: Transport> {
    transport: T,
    reader: PacketReader,
}

impl<T: Transport> GdbRemoteClient<T> {
    /// Wrap `transport` in a client.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            reader: PacketReader::new(),
        }
    }

    /// Send `payload` as a framed packet and wait for the peer's `+`, resending
    /// on `-` up to [`MAX_RESENDS`] times.
    ///
    /// # Errors
    ///
    /// Propagates transport I/O errors and reports EOF before acknowledgement.
    pub fn send_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        let packet = encode_packet(payload);
        let mut resends = 0;
        loop {
            self.transport.write_all(&packet)?;
            self.transport.flush()?;
            match self.await_ack()? {
                true => return Ok(()),
                false if resends < MAX_RESENDS => resends += 1,
                false => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "peer rejected packet after maximum resends",
                    ));
                }
            }
        }
    }

    /// Receive one packet, verify its checksum, and acknowledge it.
    ///
    /// # Errors
    ///
    /// Propagates transport I/O errors and EOF.
    pub fn recv_packet(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let byte = self.transport.read_byte()?;
            match self.reader.push(byte) {
                Some(PacketEvent::Packet {
                    payload,
                    checksum_ok: true,
                }) => {
                    self.transport.write_all(b"+")?;
                    self.transport.flush()?;
                    return Ok(payload);
                }
                Some(PacketEvent::Packet {
                    checksum_ok: false, ..
                }) => {
                    self.transport.write_all(b"-")?;
                    self.transport.flush()?;
                }
                Some(_) | None => {}
            }
        }
    }

    /// Send a request and return its reply, handling both acknowledgements.
    ///
    /// # Errors
    ///
    /// Propagates transport I/O errors.
    pub fn transact(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.send_packet(payload)?;
        self.recv_packet()
    }

    /// Read the full register file as raw `g`-packet bytes.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn read_registers(&mut self) -> io::Result<Vec<u8>> {
        let reply = self.transact(b"g")?;
        decode_hex_reply(&reply)
    }

    /// Write the full register file from raw `g`-packet bytes.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn write_registers(&mut self, raw: &[u8]) -> io::Result<()> {
        let mut request = Vec::with_capacity(raw.len() * 2 + 1);
        request.push(b'G');
        request.extend_from_slice(&hex_encode(raw));
        let reply = self.transact(&request)?;
        expect_ok(&reply)
    }

    /// Read `len` bytes at `addr`.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn read_memory(&mut self, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        let request = format!("m{addr:x},{len:x}").into_bytes();
        let reply = self.transact(&request)?;
        decode_hex_reply(&reply)
    }

    /// Write `data` at `addr`.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn write_memory(&mut self, addr: u64, data: &[u8]) -> io::Result<()> {
        let mut request = format!("M{addr:x},{:x}:", data.len()).into_bytes();
        request.extend_from_slice(&hex_encode(data));
        let reply = self.transact(&request)?;
        expect_ok(&reply)
    }

    /// Resume the target until it next stops.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn cont(&mut self) -> io::Result<StopReply> {
        let reply = self.transact(b"c")?;
        parse_stop_reply(&reply)
    }

    /// Single-step one instruction.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn step(&mut self) -> io::Result<StopReply> {
        let reply = self.transact(b"s")?;
        parse_stop_reply(&reply)
    }

    /// Set a software breakpoint at `addr` (kind `1` byte).
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn set_breakpoint(&mut self, addr: u64) -> io::Result<()> {
        let request = format!("Z0,{addr:x},1").into_bytes();
        let reply = self.transact(&request)?;
        expect_ok(&reply)
    }

    /// Remove the software breakpoint at `addr` (kind `1` byte).
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn remove_breakpoint(&mut self, addr: u64) -> io::Result<()> {
        let request = format!("z0,{addr:x},1").into_bytes();
        let reply = self.transact(&request)?;
        expect_ok(&reply)
    }

    /// Query the stub's supported features (`qSupported`).
    ///
    /// # Errors
    ///
    /// Propagates I/O errors.
    pub fn query_supported(&mut self) -> io::Result<Vec<u8>> {
        self.transact(b"qSupported:multiprocess+;swbreak+")
    }

    /// Wait for an ack byte, returning `true` for `+` and `false` for `-`.
    fn await_ack(&mut self) -> io::Result<bool> {
        loop {
            let byte = self.transport.read_byte()?;
            match self.reader.push(byte) {
                Some(PacketEvent::Ack) => return Ok(true),
                Some(PacketEvent::Nack) => return Ok(false),
                Some(_) | None => {}
            }
        }
    }
}

/// Interpret a reply that should carry hex-encoded payload bytes.
fn decode_hex_reply(reply: &[u8]) -> io::Result<Vec<u8>> {
    if is_error_reply(reply) {
        return Err(stub_error(reply));
    }
    hex_decode(reply)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reply was not valid hex"))
}

/// Interpret a reply that should be exactly `OK`.
fn expect_ok(reply: &[u8]) -> io::Result<()> {
    if reply == b"OK" {
        Ok(())
    } else if is_error_reply(reply) {
        Err(stub_error(reply))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected OK, got {}", String::from_utf8_lossy(reply)),
        ))
    }
}

/// Parse a stop-reply packet (`Sxx`, `Txx...`, `Wxx`, or `Xxx`).
fn parse_stop_reply(reply: &[u8]) -> io::Result<StopReply> {
    let Some((&tag, rest)) = reply.split_first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty stop reply",
        ));
    };
    let code = parse_two_hex(rest).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "stop reply missing signal byte")
    })?;
    match tag {
        b'S' | b'T' => Ok(StopReply::Signal(code)),
        b'W' => Ok(StopReply::Exited(code)),
        b'X' => Ok(StopReply::Terminated(code)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected stop reply tag {}", tag as char),
        )),
    }
}

/// Parse the first two bytes of `bytes` as a hex byte.
fn parse_two_hex(bytes: &[u8]) -> Option<u8> {
    let pair = bytes.get(..2)?;
    hex_decode(pair)?.first().copied()
}

/// Whether `reply` is an `Exx` error reply.
fn is_error_reply(reply: &[u8]) -> bool {
    reply.len() == 3
        && reply[0] == b'E'
        && reply[1].is_ascii_hexdigit()
        && reply[2].is_ascii_hexdigit()
}

/// Build an [`io::Error`] describing a stub `Exx` reply.
fn stub_error(reply: &[u8]) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("remote stub error: {}", String::from_utf8_lossy(reply)),
    )
}
