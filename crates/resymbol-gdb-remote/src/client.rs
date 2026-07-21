//! An RSP client that drives a remote stub (a QEMU gdbstub, a kernel debug
//! stub, or ReSymbol's own [`crate::server`]) over a [`Transport`].
//!
//! Each request goes out as a framed packet and is acknowledged; each reply is
//! read, its checksum verified, and acknowledged in turn. The typed helpers
//! wrap the common packets (`g`/`G`, `m`/`M`, `c`/`s`, `Z0`/`z0`, `qSupported`)
//! and surface protocol errors (`Exx`) as [`io::Error`]s.

use crate::protocol::{
    PacketEvent, PacketReader, ProtocolLimits, encode_packet, hex_decode, hex_encode,
};
use crate::target::StopReply;
use crate::target_description::{AMD64_TARGET_XML, TargetByteOrder};
use crate::transport::Transport;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use std::io;
use std::time::{Duration, Instant};

/// The maximum number of times a request is resent after a `-` (nack).
const MAX_RESENDS: usize = 8;

/// Default whole-operation deadline for client requests.
pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// An RSP client bound to one transport.
#[derive(Debug)]
pub struct GdbRemoteClient<T: Transport> {
    transport: T,
    reader: PacketReader,
    limits: ProtocolLimits,
    operation_timeout: Duration,
}

/// One register declared by a remote `target.xml`, normalized into increasing
/// register-number order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRegisterDescription {
    /// Register name used by GDB expressions.
    pub name: String,
    /// Register width in bits.
    pub bitsize: u32,
    /// RSP register number and `g`/`G` ordering key.
    pub regnum: u32,
    /// Feature element which owns the register.
    pub feature: String,
    /// Optional target XML type (for example `code_ptr` or `float`).
    pub type_name: Option<String>,
    /// Optional display group.
    pub group: Option<String>,
}

/// Parsed and bounded metadata fetched from `qXfer:features:read:target.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTargetDescription {
    xml: String,
    architecture: Option<String>,
    registers: Vec<RemoteRegisterDescription>,
    expected_gpacket_bytes: Option<usize>,
    byte_order: Option<TargetByteOrder>,
    software_breakpoint_kind: Option<u64>,
}

impl RemoteTargetDescription {
    /// Parse one complete target XML document.
    ///
    /// # Errors
    ///
    /// Rejects malformed XML, missing/duplicate register numbers, duplicate
    /// names, zero-width registers, and non-byte-sized register layouts.
    pub fn parse(xml: String) -> io::Result<Self> {
        parse_target_description(xml)
    }

    /// Original target XML exactly as received.
    #[must_use]
    pub fn xml(&self) -> &str {
        &self.xml
    }

    /// Architecture declared by `<architecture>`, when present.
    #[must_use]
    pub fn architecture(&self) -> Option<&str> {
        self.architecture.as_deref()
    }

    /// Registers sorted by increasing RSP register number.
    #[must_use]
    pub fn registers(&self) -> &[RemoteRegisterDescription] {
        &self.registers
    }

    /// Exact decoded byte length expected from `g` and accepted by `G`.
    #[must_use]
    pub const fn expected_gpacket_bytes(&self) -> Option<usize> {
        self.expected_gpacket_bytes
    }

    /// Known byte order for a recognized ReSymbol schema.
    ///
    /// Standard target XML has no endian element, so unknown documents return
    /// `None` rather than guessing from an architecture name.
    #[must_use]
    pub const fn byte_order(&self) -> Option<TargetByteOrder> {
        self.byte_order
    }

    /// Known software-breakpoint kind for a recognized ReSymbol schema.
    #[must_use]
    pub const fn software_breakpoint_kind(&self) -> Option<u64> {
        self.software_breakpoint_kind
    }

    /// Validate raw `g`/`G` bytes against the declared register widths.
    ///
    /// # Errors
    ///
    /// Returns `InvalidData` when the packet length is not exact.
    pub fn validate_gpacket(&self, raw: &[u8]) -> io::Result<()> {
        let Some(expected) = self.expected_gpacket_bytes else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "target description does not declare a register layout",
            ));
        };
        if raw.len() == expected {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "target description requires {} register bytes, got {}",
                    expected,
                    raw.len()
                ),
            ))
        }
    }
}

impl<T: Transport> GdbRemoteClient<T> {
    /// Wrap `transport` in a client.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self::with_limits(transport, ProtocolLimits::default())
    }

    /// Wrap `transport` in a client with explicit fail-closed resource limits.
    #[must_use]
    pub fn with_limits(transport: T, limits: ProtocolLimits) -> Self {
        Self {
            transport,
            reader: PacketReader::with_max_payload(limits.max_packet_payload),
            limits,
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
        }
    }

    /// Override the finite deadline applied to each public client operation.
    ///
    /// `read_target_description` applies one deadline to the complete
    /// multi-chunk fetch, not a fresh timeout per chunk.
    #[must_use]
    pub fn with_operation_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = timeout;
        self
    }

    /// Current whole-operation timeout.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    /// Send `payload` as a framed packet and wait for the peer's `+`, resending
    /// on `-` up to [`MAX_RESENDS`] times.
    ///
    /// # Errors
    ///
    /// Propagates transport I/O errors and reports EOF before acknowledgement.
    pub fn send_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        let deadline = self.new_deadline()?;
        self.send_packet_until(payload, deadline)
    }

    /// Send a packet while sharing an absolute deadline with a larger
    /// operation.
    ///
    /// # Errors
    ///
    /// Returns `TimedOut` once `deadline` is reached, or propagates transport
    /// and protocol failures.
    pub fn send_packet_until(&mut self, payload: &[u8], deadline: Instant) -> io::Result<()> {
        let result = self.send_packet_inner(payload, deadline);
        self.finish_deadlined(result)
    }

    fn send_packet_inner(&mut self, payload: &[u8], deadline: Instant) -> io::Result<()> {
        if payload.len() > self.limits.max_packet_payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RSP request exceeds configured packet limit",
            ));
        }
        let packet = encode_packet(payload);
        let mut resends = 0;
        loop {
            self.prepare_io(deadline)?;
            self.transport.write_all(&packet)?;
            self.transport.flush()?;
            ensure_before(deadline)?;
            match self.await_ack_until(deadline)? {
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
        let deadline = self.new_deadline()?;
        self.recv_packet_until(deadline)
    }

    /// Receive one packet before an absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns `TimedOut` once `deadline` is reached, or propagates transport
    /// and protocol failures.
    pub fn recv_packet_until(&mut self, deadline: Instant) -> io::Result<Vec<u8>> {
        let result = self.recv_packet_inner(deadline);
        self.finish_deadlined(result)
    }

    fn recv_packet_inner(&mut self, deadline: Instant) -> io::Result<Vec<u8>> {
        loop {
            self.prepare_io(deadline)?;
            let byte = self.transport.read_byte()?;
            ensure_before(deadline)?;
            match self.reader.push(byte) {
                Some(PacketEvent::Packet {
                    payload,
                    checksum_ok: true,
                }) => {
                    self.prepare_io(deadline)?;
                    self.transport.write_all(b"+")?;
                    self.transport.flush()?;
                    ensure_before(deadline)?;
                    return Ok(payload);
                }
                Some(PacketEvent::Packet {
                    checksum_ok: false, ..
                }) => {
                    self.prepare_io(deadline)?;
                    self.transport.write_all(b"-")?;
                    self.transport.flush()?;
                    ensure_before(deadline)?;
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
        let deadline = self.new_deadline()?;
        self.transact_until(payload, deadline)
    }

    /// Send a request and receive its reply under one absolute deadline.
    ///
    /// This is the primitive for compound operations which must not refresh a
    /// per-packet timeout. A transport that honors [`Transport::set_io_timeout`]
    /// cannot block one I/O call beyond the remaining duration. Other
    /// transports are checked between calls and may overrun by at most their
    /// own blocking-I/O timeout.
    ///
    /// # Errors
    ///
    /// Returns `TimedOut` once `deadline` is reached, or propagates transport
    /// and protocol failures.
    pub fn transact_until(&mut self, payload: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        let result = (|| {
            self.send_packet_inner(payload, deadline)?;
            self.recv_packet_inner(deadline)
        })();
        self.finish_deadlined(result)
    }

    /// Read the full register file as raw `g`-packet bytes.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn read_registers(&mut self) -> io::Result<Vec<u8>> {
        let reply = self.transact(b"g")?;
        decode_register_reply(&reply)
    }

    /// Write the full register file from raw `g`-packet bytes.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn write_registers(&mut self, raw: &[u8]) -> io::Result<()> {
        if raw
            .len()
            .checked_mul(2)
            .and_then(|encoded| encoded.checked_add(1))
            .is_none_or(|encoded| encoded > self.limits.max_packet_payload)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "register packet exceeds configured packet limit",
            ));
        }
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
        if len > self.limits.max_memory_transfer
            || len > self.limits.max_packet_payload.saturating_sub(1) / 2
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory read exceeds configured transfer limit",
            ));
        }
        let request = format!("m{addr:x},{len:x}").into_bytes();
        let reply = self.transact(&request)?;
        let bytes = decode_hex_reply(&reply)?;
        if bytes.len() != len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "remote returned a partial or oversized memory read",
            ));
        }
        Ok(bytes)
    }

    /// Write `data` at `addr`.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn write_memory(&mut self, addr: u64, data: &[u8]) -> io::Result<()> {
        if data.len() > self.limits.max_memory_transfer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory write exceeds configured transfer limit",
            ));
        }
        let mut request = format!("M{addr:x},{:x}:", data.len()).into_bytes();
        request.extend_from_slice(&hex_encode(data));
        if request.len() > self.limits.max_packet_payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "encoded memory write exceeds configured packet limit",
            ));
        }
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

    /// Set a software breakpoint at `addr` using the legacy one-byte kind.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn set_breakpoint(&mut self, addr: u64) -> io::Result<()> {
        self.set_breakpoint_with_kind(addr, 1)
    }

    /// Set a software breakpoint with an explicit architecture-specific kind.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn set_breakpoint_with_kind(&mut self, addr: u64, kind: u64) -> io::Result<()> {
        let request = format!("Z0,{addr:x},{kind:x}").into_bytes();
        let reply = self.transact(&request)?;
        expect_ok(&reply)
    }

    /// Remove a software breakpoint at `addr` using the legacy one-byte kind.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn remove_breakpoint(&mut self, addr: u64) -> io::Result<()> {
        self.remove_breakpoint_with_kind(addr, 1)
    }

    /// Remove a software breakpoint with an explicit architecture-specific
    /// kind.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and reports a stub error reply.
    pub fn remove_breakpoint_with_kind(&mut self, addr: u64, kind: u64) -> io::Result<()> {
        let request = format!("z0,{addr:x},{kind:x}").into_bytes();
        let reply = self.transact(&request)?;
        expect_ok(&reply)
    }

    /// Query the stub's supported features (`qSupported`).
    ///
    /// # Errors
    ///
    /// Propagates I/O errors.
    pub fn query_supported(&mut self) -> io::Result<Vec<u8>> {
        let reply = self.transact(b"qSupported:multiprocess+;swbreak+;qXfer:features:read+")?;
        validate_supported_reply(reply)
    }

    /// Fetch and parse the remote `target.xml` in bounded `qXfer` chunks.
    ///
    /// Returns `Ok(None)` when the stub answers with the empty unsupported
    /// packet. The aggregate document and every individual packet are bounded
    /// by this client's [`ProtocolLimits`].
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and rejects malformed chunk replies, oversized
    /// documents, invalid UTF-8, and invalid register metadata.
    pub fn read_target_description(&mut self) -> io::Result<Option<RemoteTargetDescription>> {
        let deadline = self.new_deadline()?;
        let chunk_size = self.limits.max_packet_payload.saturating_sub(1).min(0x800);
        if chunk_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet limit leaves no room for qXfer data",
            ));
        }
        let mut offset = 0usize;
        let mut xml = Vec::new();
        loop {
            let request = format!("qXfer:features:read:target.xml:{offset:x},{chunk_size:x}");
            let reply = self.transact_until(request.as_bytes(), deadline)?;
            if reply.is_empty() && offset == 0 {
                return Ok(None);
            }
            if is_error_reply(&reply) {
                return Err(stub_error(&reply));
            }
            let Some((&marker, chunk)) = reply.split_first() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty qXfer reply after target description began",
                ));
            };
            if !matches!(marker, b'm' | b'l') || chunk.len() > chunk_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed or oversized qXfer target-description chunk",
                ));
            }
            if marker == b'm' && chunk.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-final qXfer target-description chunk was empty",
                ));
            }
            let new_len = xml.len().checked_add(chunk.len()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "target description size overflow",
                )
            })?;
            if new_len > self.limits.max_target_description {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "target description exceeds configured aggregate limit",
                ));
            }
            xml.extend_from_slice(chunk);
            if marker == b'l' {
                break;
            }
            offset = new_len;
        }

        let xml = String::from_utf8(xml).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "target description was not valid UTF-8",
            )
        })?;
        RemoteTargetDescription::parse(xml).map(Some)
    }

    /// Wait for an ack byte, returning `true` for `+` and `false` for `-`.
    fn await_ack_until(&mut self, deadline: Instant) -> io::Result<bool> {
        loop {
            self.prepare_io(deadline)?;
            let byte = self.transport.read_byte()?;
            ensure_before(deadline)?;
            match self.reader.push(byte) {
                Some(PacketEvent::Ack) => return Ok(true),
                Some(PacketEvent::Nack) => return Ok(false),
                Some(_) | None => {}
            }
        }
    }

    fn new_deadline(&self) -> io::Result<Instant> {
        Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "operation deadline overflow")
            })
    }

    fn prepare_io(&mut self, deadline: Instant) -> io::Result<()> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(operation_timed_out)?;
        self.transport.set_io_timeout(Some(remaining))
    }

    fn finish_deadlined<R>(&mut self, result: io::Result<R>) -> io::Result<R> {
        let clear = self.transport.set_io_timeout(None);
        match (result, clear) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
}

fn ensure_before(deadline: Instant) -> io::Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(operation_timed_out())
    }
}

fn operation_timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "RSP operation deadline reached")
}

fn parse_target_description(xml: String) -> io::Result<RemoteTargetDescription> {
    let mut reader = Reader::from_str(&xml);
    reader.config_mut().trim_text(true);
    let mut saw_target = false;
    let mut architecture = None;
    let mut current_feature: Option<String> = None;
    let mut next_regnum = 0u32;
    let mut registers = Vec::new();

    loop {
        match reader.read_event().map_err(xml_error)? {
            Event::Start(event) if event.name().as_ref() == b"target" => {
                saw_target = true;
            }
            Event::Start(event) if event.name().as_ref() == b"architecture" => {
                if architecture.is_some() {
                    return Err(invalid_xml("duplicate architecture element"));
                }
                let text = reader
                    .read_text(event.name())
                    .map_err(xml_error)?
                    .into_owned();
                if text.is_empty() {
                    return Err(invalid_xml("empty architecture element"));
                }
                architecture = Some(text);
            }
            Event::Start(event) if event.name().as_ref() == b"feature" => {
                current_feature = Some(required_attribute(&reader, &event, b"name")?);
            }
            Event::End(event) if event.name().as_ref() == b"feature" => {
                current_feature = None;
            }
            Event::Start(event) | Event::Empty(event) if event.name().as_ref() == b"reg" => {
                let feature = current_feature
                    .as_ref()
                    .ok_or_else(|| invalid_xml("register outside a feature"))?;
                let register = parse_register(&reader, &event, feature, next_regnum)?;
                next_regnum = register
                    .regnum
                    .checked_add(1)
                    .ok_or_else(|| invalid_xml("register number overflow"))?;
                registers.push(register);
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if !saw_target {
        return Err(invalid_xml("missing target root element"));
    }

    registers.sort_by_key(|register| register.regnum);
    for pair in registers.windows(2) {
        if pair[0].regnum == pair[1].regnum {
            return Err(invalid_xml("duplicate register number"));
        }
    }
    let mut names = std::collections::BTreeSet::new();
    let mut expected_bytes = 0usize;
    for register in &registers {
        if register.bitsize == 0 || register.bitsize % 8 != 0 {
            return Err(invalid_xml(
                "register width must be a non-zero whole number of bytes",
            ));
        }
        if !names.insert(register.name.to_ascii_lowercase()) {
            return Err(invalid_xml("duplicate register name"));
        }
        expected_bytes = expected_bytes
            .checked_add(register.bitsize as usize / 8)
            .ok_or_else(|| invalid_xml("register packet size overflow"))?;
    }
    let expected_gpacket_bytes = (!registers.is_empty()).then_some(expected_bytes);
    let (byte_order, software_breakpoint_kind) = recognized_schema(
        &xml,
        architecture.as_deref(),
        &registers,
        expected_gpacket_bytes,
    );

    Ok(RemoteTargetDescription {
        xml,
        architecture,
        registers,
        expected_gpacket_bytes,
        byte_order,
        software_breakpoint_kind,
    })
}

fn parse_register(
    reader: &Reader<&[u8]>,
    event: &BytesStart<'_>,
    feature: &str,
    inferred_regnum: u32,
) -> io::Result<RemoteRegisterDescription> {
    let name = required_attribute(reader, event, b"name")?;
    let bitsize = required_attribute(reader, event, b"bitsize")?
        .parse::<u32>()
        .map_err(|_| invalid_xml("register bitsize was not a decimal u32"))?;
    let regnum =
        optional_attribute(reader, event, b"regnum")?.map_or(Ok(inferred_regnum), |value| {
            value
                .parse::<u32>()
                .map_err(|_| invalid_xml("register regnum was not a decimal u32"))
        })?;
    Ok(RemoteRegisterDescription {
        name,
        bitsize,
        regnum,
        feature: feature.to_owned(),
        type_name: optional_attribute(reader, event, b"type")?,
        group: optional_attribute(reader, event, b"group")?,
    })
}

fn required_attribute(
    reader: &Reader<&[u8]>,
    event: &BytesStart<'_>,
    name: &[u8],
) -> io::Result<String> {
    optional_attribute(reader, event, name)?
        .ok_or_else(|| invalid_xml("required XML attribute missing"))
}

fn optional_attribute(
    reader: &Reader<&[u8]>,
    event: &BytesStart<'_>,
    name: &[u8],
) -> io::Result<Option<String>> {
    for attribute in event.attributes() {
        let attribute = attribute.map_err(xml_error)?;
        if attribute.key.as_ref() == name {
            let value = attribute
                .decode_and_unescape_value(reader.decoder())
                .map_err(xml_error)?
                .into_owned();
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn recognized_schema(
    xml: &str,
    architecture: Option<&str>,
    registers: &[RemoteRegisterDescription],
    expected_bytes: Option<usize>,
) -> (Option<TargetByteOrder>, Option<u64>) {
    if xml == AMD64_TARGET_XML {
        return (Some(TargetByteOrder::Little), Some(1));
    }
    if architecture == Some("mips:5900")
        && expected_bytes == Some(crate::target_description::PS2_EE_GPACKET_BYTES)
        && matches_ps2_ee_registers(registers)
    {
        // Endianness is a property of ReSymbol's named EE schema, not an XML
        // inference: standard target descriptions have no endian element.
        return (Some(TargetByteOrder::Little), Some(4));
    }
    (None, None)
}

fn matches_ps2_ee_registers(registers: &[RemoteRegisterDescription]) -> bool {
    for index in 0..32u32 {
        let low_name = format!("r{index}");
        if !register_matches(registers, &low_name, index, 64, "org.gnu.gdb.mips.cpu") {
            return false;
        }
        let upper_name = format!("r{index}_upper");
        if !register_matches(
            registers,
            &upper_name,
            73 + index,
            64,
            "org.openomega.ps2.ee",
        ) {
            return false;
        }
    }
    [
        ("status", 32, 32, "org.gnu.gdb.mips.cp0"),
        ("lo", 33, 64, "org.gnu.gdb.mips.cpu"),
        ("hi", 34, 64, "org.gnu.gdb.mips.cpu"),
        ("badvaddr", 35, 32, "org.gnu.gdb.mips.cp0"),
        ("cause", 36, 32, "org.gnu.gdb.mips.cp0"),
        ("pc", 37, 32, "org.gnu.gdb.mips.cpu"),
        ("fcsr", 70, 32, "org.gnu.gdb.mips.fpu"),
        ("fir", 71, 32, "org.gnu.gdb.mips.fpu"),
        ("epc", 72, 32, "org.openomega.ps2.ee"),
        ("lo_upper", 105, 64, "org.openomega.ps2.ee"),
        ("hi_upper", 106, 64, "org.openomega.ps2.ee"),
        ("sa", 107, 32, "org.openomega.ps2.ee"),
        ("fpu_acc", 108, 32, "org.openomega.ps2.ee"),
    ]
    .into_iter()
    .all(|(name, regnum, bitsize, feature)| {
        register_matches(registers, name, regnum, bitsize, feature)
    }) && (0..32u32).all(|index| {
        register_matches(
            registers,
            &format!("f{index}"),
            38 + index,
            32,
            "org.gnu.gdb.mips.fpu",
        )
    })
}

fn register_matches(
    registers: &[RemoteRegisterDescription],
    name: &str,
    regnum: u32,
    bitsize: u32,
    feature: &str,
) -> bool {
    registers.iter().any(|register| {
        register.name == name
            && register.regnum == regnum
            && register.bitsize == bitsize
            && register.feature == feature
    })
}

fn invalid_xml(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn xml_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid target XML: {error}"),
    )
}

/// Interpret a reply that should carry hex-encoded payload bytes.
fn decode_hex_reply(reply: &[u8]) -> io::Result<Vec<u8>> {
    if is_error_reply(reply) {
        return Err(stub_error(reply));
    }
    hex_decode(reply)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reply was not valid hex"))
}

fn decode_register_reply(reply: &[u8]) -> io::Result<Vec<u8>> {
    let registers = decode_hex_reply(reply)?;
    if registers.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "remote stub did not support the g register packet",
        ))
    } else {
        Ok(registers)
    }
}

fn validate_supported_reply(reply: Vec<u8>) -> io::Result<Vec<u8>> {
    if is_error_reply(&reply) {
        Err(stub_error(&reply))
    } else {
        Ok(reply)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target_description::{PS2_EE_GPACKET_BYTES, PS2_EE_TARGET_XML};
    use crate::transport::memory_pair;

    #[test]
    fn parses_lossless_ps2_schema_in_register_number_order() {
        let description =
            RemoteTargetDescription::parse(PS2_EE_TARGET_XML.to_owned()).expect("valid EE XML");
        assert_eq!(description.architecture(), Some("mips:5900"));
        assert_eq!(
            description.expected_gpacket_bytes(),
            Some(PS2_EE_GPACKET_BYTES)
        );
        assert_eq!(description.byte_order(), Some(TargetByteOrder::Little));
        assert_eq!(description.software_breakpoint_kind(), Some(4));
        assert_eq!(description.registers().len(), 109);
        assert_eq!(description.registers()[32].name, "status");
        assert_eq!(description.registers()[33].name, "lo");
        assert_eq!(description.registers()[37].name, "pc");
        assert_eq!(description.registers()[73].name, "r0_upper");
        assert_eq!(description.registers()[108].name, "fpu_acc");
        assert!(
            description
                .validate_gpacket(&vec![0; PS2_EE_GPACKET_BYTES])
                .is_ok()
        );
        assert!(
            description
                .validate_gpacket(&vec![0; PS2_EE_GPACKET_BYTES - 1])
                .is_err()
        );
    }

    #[test]
    fn target_xml_without_registers_keeps_packet_shape_unknown() {
        let xml = "<target version=\"1.0\"><architecture>mips</architecture></target>";
        let description = RemoteTargetDescription::parse(xml.to_owned()).unwrap();
        assert_eq!(description.expected_gpacket_bytes(), None);
        assert_eq!(description.byte_order(), None);
        assert!(description.validate_gpacket(&[]).is_err());
    }

    #[test]
    fn duplicate_register_numbers_are_rejected() {
        let xml = r#"<target version="1.0"><feature name="example"><reg name="a" bitsize="32" regnum="0"/><reg name="b" bitsize="32" regnum="0"/></feature></target>"#;
        assert!(RemoteTargetDescription::parse(xml.to_owned()).is_err());
    }

    #[test]
    fn zero_operation_timeout_fails_before_blocking_io() {
        let (_peer, transport) = memory_pair();
        let mut client = GdbRemoteClient::new(transport).with_operation_timeout(Duration::ZERO);
        let error = client.transact(b"?").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn semantic_errors_are_not_capabilities() {
        assert!(validate_supported_reply(b"E01".to_vec()).is_err());
        assert_eq!(
            validate_supported_reply(b"PacketSize=1000".to_vec()).unwrap(),
            b"PacketSize=1000"
        );
    }

    #[test]
    fn empty_register_reply_is_unsupported() {
        let error = decode_register_reply(b"").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
