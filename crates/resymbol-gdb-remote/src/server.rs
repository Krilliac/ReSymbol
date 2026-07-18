//! An RSP server that exposes a [`RemoteTarget`] to any GDB-compatible client
//! (gdb, lldb, IDA, Ghidra, ...) over a [`Transport`].
//!
//! The server implements the packet acknowledgement handshake and the subset
//! of the protocol needed to drive live debugging: stop-reason queries,
//! register and memory access, continue/step, software breakpoints, and the
//! handful of `q`/`H`/`v` queries a client sends during connection setup. Any
//! unrecognised packet is answered with the empty packet `$#00`, as the
//! protocol requires.

use crate::protocol::{
    PacketEvent, PacketReader, encode_packet, hex_decode, hex_encode, parse_hex_u64,
};
use crate::target::{RemoteTarget, StopReply, WatchKind};
use crate::transport::Transport;
use std::io;

/// The largest packet payload advertised to clients via `qSupported`.
const ADVERTISED_PACKET_SIZE: usize = 1000;

/// The maximum number of times a reply is resent after a `-` (nack).
const MAX_RESENDS: usize = 8;

/// What the dispatcher decided to do with a received packet.
enum Disposition {
    /// Send this reply and keep serving.
    Reply(Vec<u8>),
    /// Send this reply, then stop serving (client detached).
    Detach(Vec<u8>),
    /// Stop serving without a reply (client killed the target).
    Kill,
}

/// An RSP server bound to one transport.
#[derive(Debug)]
pub struct GdbStubServer<T: Transport> {
    transport: T,
    reader: PacketReader,
}

impl<T: Transport> GdbStubServer<T> {
    /// Wrap `transport` in a server.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            reader: PacketReader::new(),
        }
    }

    /// Serve `target` until the client detaches, kills the target, or the
    /// transport reaches EOF.
    ///
    /// # Errors
    ///
    /// Propagates transport I/O errors other than a clean peer disconnect.
    pub fn serve<R: RemoteTarget + ?Sized>(&mut self, target: &mut R) -> io::Result<()> {
        loop {
            let payload = match self.next_packet()? {
                Some(payload) => payload,
                None => return Ok(()),
            };
            match dispatch(&payload, target) {
                Disposition::Reply(reply) => self.send_packet(&reply)?,
                Disposition::Detach(reply) => {
                    self.send_packet(&reply)?;
                    return Ok(());
                }
                Disposition::Kill => return Ok(()),
            }
        }
    }

    /// Read the next well-formed packet, acknowledging it. Returns `Ok(None)`
    /// on a clean EOF. Nacks corrupted packets so the peer resends.
    fn next_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let byte = match self.transport.read_byte() {
                Ok(byte) => byte,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(error) => return Err(error),
            };
            match self.reader.push(byte) {
                Some(PacketEvent::Packet {
                    payload,
                    checksum_ok: true,
                }) => {
                    self.transport.write_all(b"+")?;
                    self.transport.flush()?;
                    return Ok(Some(payload));
                }
                Some(PacketEvent::Packet {
                    checksum_ok: false, ..
                }) => {
                    self.transport.write_all(b"-")?;
                    self.transport.flush()?;
                }
                // Acks for our own replies and interrupts are handled inline by
                // `send_packet`; any that arrive here are simply ignored.
                Some(_) | None => {}
            }
        }
    }

    /// Send `payload` as a framed packet and wait for the peer's `+`,
    /// resending on `-` up to [`MAX_RESENDS`] times.
    fn send_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        let packet = encode_packet(payload);
        let mut resends = 0;
        loop {
            self.transport.write_all(&packet)?;
            self.transport.flush()?;
            match self.await_ack()? {
                Some(true) => return Ok(()),
                Some(false) if resends < MAX_RESENDS => resends += 1,
                // Give up waiting for an ack (peer gone or exhausted resends);
                // the reply is on the wire, so continue serving.
                Some(false) | None => return Ok(()),
            }
        }
    }

    /// Wait for an ack byte. `Some(true)` = `+`, `Some(false)` = `-`,
    /// `None` = EOF before any ack arrived.
    fn await_ack(&mut self) -> io::Result<Option<bool>> {
        loop {
            let byte = match self.transport.read_byte() {
                Ok(byte) => byte,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(error) => return Err(error),
            };
            match self.reader.push(byte) {
                Some(PacketEvent::Ack) => return Ok(Some(true)),
                Some(PacketEvent::Nack) => return Ok(Some(false)),
                // Ignore any interrupts or stray packet frames while awaiting
                // the acknowledgement of our reply.
                Some(_) | None => {}
            }
        }
    }
}

/// Serve `target` over `transport` until detach, kill, or EOF.
///
/// # Errors
///
/// Propagates transport I/O errors other than a clean peer disconnect.
pub fn serve_one<T: Transport, R: RemoteTarget>(target: &mut R, transport: T) -> io::Result<()> {
    GdbStubServer::new(transport).serve(target)
}

/// Format a stop reply as its RSP wire form (`Sxx`, `Wxx`, or `Xxx`).
/// Build a stop reply, tagging it with the stopping thread when the target
/// knows it. A signal stop with a known thread uses the `T AA thread:tid;`
/// form GDB expects for thread-aware stops; exit/terminate stay `W`/`X`.
fn stop_reply_for<R: RemoteTarget + ?Sized>(reply: StopReply, target: &mut R) -> Vec<u8> {
    if let StopReply::Signal(signal) = reply {
        if let Some(thread) = target.stopped_thread() {
            return format!("T{signal:02x}thread:{thread:x};").into_bytes();
        }
    }
    stop_reply_packet(reply)
}

fn stop_reply_packet(reply: StopReply) -> Vec<u8> {
    match reply {
        StopReply::Signal(signal) => format!("S{signal:02x}").into_bytes(),
        StopReply::Exited(code) => format!("W{code:02x}").into_bytes(),
        StopReply::Terminated(signal) => format!("X{signal:02x}").into_bytes(),
    }
}

/// The empty packet used for unsupported requests.
fn empty_reply() -> Vec<u8> {
    Vec::new()
}

/// A generic error reply.
fn error_reply() -> Vec<u8> {
    b"E01".to_vec()
}

/// Decide how to answer one received packet, driving `target` as needed.
fn dispatch<R: RemoteTarget + ?Sized>(payload: &[u8], target: &mut R) -> Disposition {
    let Some((&first, rest)) = payload.split_first() else {
        // An empty request is answered with the empty reply.
        return Disposition::Reply(empty_reply());
    };
    match first {
        b'?' => Disposition::Reply(stop_reply_for(target.stop_reason(), target)),
        b'g' => match target.read_registers() {
            Ok(bytes) => Disposition::Reply(hex_encode(&bytes)),
            Err(_) => Disposition::Reply(error_reply()),
        },
        b'G' => match hex_decode(rest) {
            Some(raw) => match target.write_registers(&raw) {
                Ok(()) => Disposition::Reply(b"OK".to_vec()),
                Err(_) => Disposition::Reply(error_reply()),
            },
            None => Disposition::Reply(error_reply()),
        },
        b'm' => Disposition::Reply(handle_read_memory(rest, target)),
        b'M' => Disposition::Reply(handle_write_memory(rest, target)),
        b'c' => Disposition::Reply(match target.cont() {
            Ok(reply) => stop_reply_for(reply, target),
            Err(_) => error_reply(),
        }),
        b's' => Disposition::Reply(match target.step() {
            Ok(reply) => stop_reply_for(reply, target),
            Err(_) => error_reply(),
        }),
        b'Z' => Disposition::Reply(handle_breakpoint(rest, target, true)),
        b'z' => Disposition::Reply(handle_breakpoint(rest, target, false)),
        b'q' => Disposition::Reply(handle_query(rest, target)),
        b'H' => Disposition::Reply(handle_set_thread(rest, target)),
        b'T' => Disposition::Reply(handle_is_thread_alive(rest, target)),
        b'v' => Disposition::Reply(handle_v_packet(rest, target)),
        b'D' => Disposition::Detach(b"OK".to_vec()),
        b'k' => Disposition::Kill,
        _ => Disposition::Reply(empty_reply()),
    }
}

/// Handle `m addr,len`.
fn handle_read_memory<R: RemoteTarget + ?Sized>(rest: &[u8], target: &mut R) -> Vec<u8> {
    let Some((addr, len)) = parse_addr_len(rest) else {
        return error_reply();
    };
    let Ok(len) = usize::try_from(len) else {
        return error_reply();
    };
    match target.read_memory(addr, len) {
        Ok(bytes) => hex_encode(&bytes),
        Err(_) => error_reply(),
    }
}

/// Handle `M addr,len:hexdata`.
fn handle_write_memory<R: RemoteTarget + ?Sized>(rest: &[u8], target: &mut R) -> Vec<u8> {
    let Some(colon) = rest.iter().position(|&b| b == b':') else {
        return error_reply();
    };
    let (spec, data) = rest.split_at(colon);
    let data = &data[1..];
    let Some((addr, _len)) = parse_addr_len(spec) else {
        return error_reply();
    };
    let Some(bytes) = hex_decode(data) else {
        return error_reply();
    };
    match target.write_memory(addr, &bytes) {
        Ok(()) => b"OK".to_vec(),
        Err(_) => error_reply(),
    }
}

/// Handle `Ztype,addr,kind[;...]` / `ztype,addr,kind[;...]`. Supports software
/// breakpoints (`0`), hardware execute breakpoints (`1`), and write/read/access
/// watchpoints (`2`/`3`/`4`). Any other type yields the empty reply, as the
/// protocol requires for an unknown packet. For watchpoints the third field is
/// the byte length; for `Z0`/`Z1` it is the (ignored) instruction kind. The
/// optional `;cond`/`;cmd` list after the third field is ignored.
fn handle_breakpoint<R: RemoteTarget + ?Sized>(rest: &[u8], target: &mut R, set: bool) -> Vec<u8> {
    let Some((&bptype, after_type)) = rest.split_first() else {
        return error_reply();
    };
    // `after_type` is ",addr,kind[;...]"; drop the leading comma, then drop any
    // trailing ";cond/command" list before parsing the two numeric fields.
    let fields = after_type.strip_prefix(b",").unwrap_or(after_type);
    let fields = match fields.iter().position(|&b| b == b';') {
        Some(semi) => &fields[..semi],
        None => fields,
    };
    let (addr_bytes, third_bytes) = match fields.iter().position(|&b| b == b',') {
        Some(comma) => (&fields[..comma], Some(&fields[comma + 1..])),
        None => (fields, None),
    };
    let Some(addr) = parse_hex_u64(addr_bytes) else {
        return error_reply();
    };
    // The third field is the length (watchpoints) or kind (breakpoints).
    let third = third_bytes.and_then(parse_hex_u64);

    let result = match bptype {
        b'0' => {
            if set {
                target.set_sw_breakpoint(addr)
            } else {
                target.remove_sw_breakpoint(addr)
            }
        }
        b'1' => {
            if set {
                target.set_hw_breakpoint(addr)
            } else {
                target.remove_hw_breakpoint(addr)
            }
        }
        b'2' | b'3' | b'4' => {
            let watch = match bptype {
                b'2' => WatchKind::Write,
                b'3' => WatchKind::Read,
                _ => WatchKind::Access,
            };
            let len = third.unwrap_or(1);
            if set {
                target.set_watchpoint(addr, len, watch)
            } else {
                target.remove_watchpoint(addr, len, watch)
            }
        }
        // A genuinely unknown breakpoint type: the empty reply signals "not
        // supported" per the protocol.
        _ => return empty_reply(),
    };
    match result {
        Ok(()) => b"OK".to_vec(),
        Err(_) => error_reply(),
    }
}

/// Handle the `q...` query packets used during connection setup, including the
/// thread-enumeration queries.
fn handle_query<R: RemoteTarget + ?Sized>(rest: &[u8], target: &mut R) -> Vec<u8> {
    if rest.starts_with(b"Supported") {
        return format!("PacketSize={ADVERTISED_PACKET_SIZE:x};swbreak+;hwbreak+").into_bytes();
    }
    if rest == b"Attached" || rest.starts_with(b"Attached") {
        return b"1".to_vec();
    }
    if rest == b"C" {
        // Current thread id.
        return match target.current_thread() {
            Ok(tid) => format!("QC{tid:x}").into_bytes(),
            Err(_) => b"QC01".to_vec(),
        };
    }
    if rest == b"fThreadInfo" {
        // First batch: the whole (bounded) thread list in one `m...` reply.
        return match target.thread_ids() {
            Ok(ids) if !ids.is_empty() => {
                let mut out = vec![b'm'];
                for (index, id) in ids.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(format!("{id:x}").as_bytes());
                }
                out
            }
            _ => b"l".to_vec(),
        };
    }
    if rest == b"sThreadInfo" {
        // Subsequent batch: end of list (the whole list fit in the first batch).
        return b"l".to_vec();
    }
    empty_reply()
}

/// Handle `Hg<tid>` / `Hc<tid>`: select the current thread for subsequent
/// register/memory (`g`) or step/continue (`c`) operations. A tid of `0` or the
/// all-threads sentinel `-1` leaves the selection unchanged.
fn handle_set_thread<R: RemoteTarget + ?Sized>(rest: &[u8], target: &mut R) -> Vec<u8> {
    // rest is "<op><thread-id>", e.g. "g1a" or "c-1".
    let Some((_op, id_bytes)) = rest.split_first() else {
        return b"OK".to_vec();
    };
    match parse_thread_id(id_bytes) {
        // "any"/"all" or the leader: leave the current selection unchanged.
        None | Some(0) => b"OK".to_vec(),
        Some(tid) => match target.set_current_thread(tid) {
            Ok(()) => b"OK".to_vec(),
            Err(_) => error_reply(),
        },
    }
}

/// Handle `T<tid>` (is-thread-alive): `OK` if the thread is listed, else `E01`.
fn handle_is_thread_alive<R: RemoteTarget + ?Sized>(rest: &[u8], target: &mut R) -> Vec<u8> {
    let Some(tid) = parse_thread_id(rest) else {
        return error_reply();
    };
    match target.thread_ids() {
        Ok(ids) if ids.contains(&tid) => b"OK".to_vec(),
        _ => b"E01".to_vec(),
    }
}

/// Parse a GDB thread-id field: a hex id, or `-1` (all threads) / `0` (any)
/// which map to `None` (no specific thread). A leading `p<pid>.` multiprocess
/// prefix is tolerated by taking the portion after the last `.`.
fn parse_thread_id(bytes: &[u8]) -> Option<u64> {
    let tail = match bytes.iter().rposition(|&b| b == b'.') {
        Some(dot) => &bytes[dot + 1..],
        None => bytes,
    };
    let tail = tail.strip_prefix(b"p").unwrap_or(tail);
    if tail == b"-1" {
        return None;
    }
    parse_hex_u64(tail)
}

/// Handle `v...` packets: `vCont?` advertises continue/step support and
/// `vCont;c`/`vCont;s` execute them. A per-action `:tid` suffix selects the
/// thread before a step (all-stop: `c` resumes every thread).
fn handle_v_packet<R: RemoteTarget + ?Sized>(rest: &[u8], target: &mut R) -> Vec<u8> {
    if rest == b"Cont?" {
        return b"vCont;c;s;t".to_vec();
    }
    if let Some(actions) = rest.strip_prefix(b"Cont;") {
        // Take the first action (e.g. "c", "s", or "s:1a"); honor a :tid suffix.
        let first_action = actions.split(|&b| b == b';').next().unwrap_or(actions);
        let (letter, thread) = match first_action.iter().position(|&b| b == b':') {
            Some(colon) => (
                first_action.first().copied(),
                parse_thread_id(&first_action[colon + 1..]),
            ),
            None => (first_action.first().copied(), None),
        };
        if let Some(tid) = thread {
            let _ = target.set_current_thread(tid);
        }
        return match letter {
            Some(b'c') | Some(b'C') => match target.cont() {
                Ok(reply) => stop_reply_for(reply, target),
                Err(_) => error_reply(),
            },
            Some(b's') | Some(b'S') => match target.step() {
                Ok(reply) => stop_reply_for(reply, target),
                Err(_) => error_reply(),
            },
            _ => empty_reply(),
        };
    }
    empty_reply()
}

/// Parse the `addr,len` form (two hex numbers separated by a comma).
fn parse_addr_len(bytes: &[u8]) -> Option<(u64, u64)> {
    let comma = bytes.iter().position(|&b| b == b',')?;
    let addr = parse_hex_u64(&bytes[..comma])?;
    let len = parse_hex_u64(&bytes[comma + 1..])?;
    Some((addr, len))
}
