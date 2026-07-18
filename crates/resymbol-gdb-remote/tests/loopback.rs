//! In-process loopback: an [`GdbStubServer`] wraps a deterministic mock target
//! over an in-memory transport pair, and a [`GdbRemoteClient`] drives it from a
//! background thread. No sockets, no ptrace — this runs in the normal test
//! gate.

use resymbol_gdb_remote::target::{Amd64CoreRegisters, RemoteTarget, StopReply, TargetError};
use resymbol_gdb_remote::{GdbRemoteClient, GdbStubServer, memory_pair};
use std::collections::BTreeMap;

/// A deterministic in-memory target: fixed registers, a sparse memory map, a
/// breakpoint set, and a scripted stop reply.
struct MockTarget {
    registers: Amd64CoreRegisters,
    memory: BTreeMap<u64, u8>,
    breakpoints: Vec<u64>,
    stop: StopReply,
}

impl MockTarget {
    fn new() -> Self {
        let registers = Amd64CoreRegisters {
            rax: 0x1122_3344_5566_7788,
            rip: 0x0000_0000_0040_1000,
            rsp: 0x0000_7fff_ffff_e000,
            ..Amd64CoreRegisters::default()
        };
        let mut memory = BTreeMap::new();
        for (offset, byte) in [0x48, 0x89, 0xe5, 0x90].into_iter().enumerate() {
            memory.insert(0x0040_1000 + offset as u64, byte);
        }
        Self {
            registers,
            memory,
            breakpoints: Vec::new(),
            stop: StopReply::Signal(5),
        }
    }

    fn byte(&self, addr: u64) -> u8 {
        self.memory.get(&addr).copied().unwrap_or(0)
    }
}

impl RemoteTarget for MockTarget {
    fn read_registers(&mut self) -> Result<Vec<u8>, TargetError> {
        Ok(self.registers.to_gpacket())
    }

    fn write_registers(&mut self, raw: &[u8]) -> Result<(), TargetError> {
        self.registers.apply_gpacket(raw)
    }

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, TargetError> {
        Ok((0..len as u64).map(|i| self.byte(addr + i)).collect())
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), TargetError> {
        for (i, &byte) in data.iter().enumerate() {
            self.memory.insert(addr + i as u64, byte);
        }
        Ok(())
    }

    fn cont(&mut self) -> Result<StopReply, TargetError> {
        self.stop = StopReply::Signal(5);
        Ok(self.stop)
    }

    fn step(&mut self) -> Result<StopReply, TargetError> {
        self.stop = StopReply::Signal(5);
        Ok(self.stop)
    }

    fn set_sw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError> {
        if !self.breakpoints.contains(&addr) {
            self.breakpoints.push(addr);
        }
        Ok(())
    }

    fn remove_sw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError> {
        self.breakpoints.retain(|&a| a != addr);
        Ok(())
    }

    fn stop_reason(&mut self) -> StopReply {
        self.stop
    }
}

#[test]
fn client_drives_server_over_in_memory_transport() {
    let (server_transport, client_transport) = memory_pair();

    let server = std::thread::spawn(move || {
        let mut target = MockTarget::new();
        let mut server = GdbStubServer::new(server_transport);
        server.serve(&mut target).expect("server loop");
    });

    let mut client = GdbRemoteClient::new(client_transport);

    // qSupported negotiation advertises swbreak.
    let supported = client.query_supported().expect("qSupported");
    let supported = String::from_utf8(supported).unwrap();
    assert!(supported.contains("swbreak+"), "got: {supported}");
    assert!(supported.contains("PacketSize="), "got: {supported}");

    // Read registers and confirm the g-packet decodes to the mock's values.
    let raw = client.read_registers().expect("read registers");
    let registers = resymbol_gdb_remote::amd64_gpacket_to_registers(&raw).unwrap();
    assert_eq!(registers.rax, 0x1122_3344_5566_7788);
    assert_eq!(registers.rip, 0x0040_1000);

    // Write registers back with a modified rax and read it again.
    let mut modified = registers;
    modified.rax = 0xdead_beef;
    client
        .write_registers(&modified.to_gpacket())
        .expect("write registers");
    let raw = client.read_registers().expect("re-read registers");
    let registers = resymbol_gdb_remote::amd64_gpacket_to_registers(&raw).unwrap();
    assert_eq!(registers.rax, 0xdead_beef);

    // Memory read of the seeded bytes.
    let code = client.read_memory(0x0040_1000, 4).expect("read memory");
    assert_eq!(code, vec![0x48, 0x89, 0xe5, 0x90]);

    // Memory write round-trip.
    client
        .write_memory(0x0040_2000, &[0xaa, 0xbb, 0xcc])
        .expect("write memory");
    let read_back = client.read_memory(0x0040_2000, 3).expect("read back");
    assert_eq!(read_back, vec![0xaa, 0xbb, 0xcc]);

    // Breakpoint set/remove both acknowledge OK.
    client.set_breakpoint(0x0040_1002).expect("set breakpoint");
    client
        .remove_breakpoint(0x0040_1002)
        .expect("remove breakpoint");

    // Continue produces a stop reply.
    assert_eq!(client.cont().expect("continue"), StopReply::Signal(5));
    assert_eq!(client.step().expect("step"), StopReply::Signal(5));

    // Kill ends the server loop; the send is acked so the client returns.
    client.send_packet(b"k").expect("kill");

    server.join().expect("server thread");
}
