//! In-process loopback: an [`GdbStubServer`] wraps a deterministic mock target
//! over an in-memory transport pair, and a [`GdbRemoteClient`] drives it from a
//! background thread. No sockets, no ptrace — this runs in the normal test
//! gate.

use resymbol_gdb_remote::target::{
    Amd64CoreRegisters, RemoteTarget, StopReply, TargetError, WatchKind,
};
use resymbol_gdb_remote::{
    AMD64_GPACKET_BYTES, AMD64_TARGET_DESCRIPTION, GdbRemoteClient, GdbStubServer, TargetByteOrder,
    TargetDescription, memory_pair,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

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
    fn target_description(&self) -> Option<TargetDescription<'_>> {
        Some(AMD64_TARGET_DESCRIPTION)
    }

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

/// One recorded hardware breakpoint/watchpoint request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HwCall {
    SetHwBreak(u64),
    RemoveHwBreak(u64),
    SetWatch(u64, u64, WatchKind),
    RemoveWatch(u64, u64, WatchKind),
}

/// A target that records the hardware-related [`RemoteTarget`] calls the server
/// dispatches to it, so a test can assert the `Z1`/`Z2`/`Z3`/`Z4` (and `z*`)
/// packets were parsed correctly.
struct RecordingTarget {
    calls: Arc<Mutex<Vec<HwCall>>>,
}

impl RemoteTarget for RecordingTarget {
    fn read_registers(&mut self) -> Result<Vec<u8>, TargetError> {
        Ok(Amd64CoreRegisters::default().to_gpacket())
    }
    fn write_registers(&mut self, _raw: &[u8]) -> Result<(), TargetError> {
        Ok(())
    }
    fn read_memory(&mut self, _addr: u64, len: usize) -> Result<Vec<u8>, TargetError> {
        Ok(vec![0u8; len])
    }
    fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<(), TargetError> {
        Ok(())
    }
    fn cont(&mut self) -> Result<StopReply, TargetError> {
        Ok(StopReply::Signal(5))
    }
    fn step(&mut self) -> Result<StopReply, TargetError> {
        Ok(StopReply::Signal(5))
    }
    fn set_sw_breakpoint(&mut self, _addr: u64) -> Result<(), TargetError> {
        Ok(())
    }
    fn remove_sw_breakpoint(&mut self, _addr: u64) -> Result<(), TargetError> {
        Ok(())
    }
    fn set_hw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError> {
        self.calls.lock().unwrap().push(HwCall::SetHwBreak(addr));
        Ok(())
    }
    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<(), TargetError> {
        self.calls.lock().unwrap().push(HwCall::RemoveHwBreak(addr));
        Ok(())
    }
    fn set_watchpoint(&mut self, addr: u64, len: u64, kind: WatchKind) -> Result<(), TargetError> {
        self.calls
            .lock()
            .unwrap()
            .push(HwCall::SetWatch(addr, len, kind));
        Ok(())
    }
    fn remove_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> Result<(), TargetError> {
        self.calls
            .lock()
            .unwrap()
            .push(HwCall::RemoveWatch(addr, len, kind));
        Ok(())
    }
    fn stop_reason(&mut self) -> StopReply {
        StopReply::Signal(5)
    }
}

#[test]
fn server_dispatches_hardware_breakpoint_packets() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let target_calls = Arc::clone(&calls);
    let (server_transport, client_transport) = memory_pair();

    let server = std::thread::spawn(move || {
        let mut target = RecordingTarget {
            calls: target_calls,
        };
        let mut server = GdbStubServer::new(server_transport);
        server.serve(&mut target).expect("server loop");
    });

    let mut client = GdbRemoteClient::new(client_transport);

    // Z1: hardware execute breakpoint. Third field is an ignored kind byte.
    assert_eq!(client.transact(b"Z1,401000,1").unwrap(), b"OK");
    // Z2/Z3/Z4: watchpoints, third field is the byte length.
    assert_eq!(client.transact(b"Z2,401010,4").unwrap(), b"OK");
    assert_eq!(client.transact(b"Z3,401020,2").unwrap(), b"OK");
    assert_eq!(client.transact(b"Z4,401030,8").unwrap(), b"OK");
    // A trailing ";cond" list must be ignored.
    assert_eq!(client.transact(b"Z1,401040,1;X1,0").unwrap(), b"OK");
    // Removals.
    assert_eq!(client.transact(b"z1,401000,1").unwrap(), b"OK");
    assert_eq!(client.transact(b"z2,401010,4").unwrap(), b"OK");
    // An unknown breakpoint type gets the empty reply.
    assert_eq!(client.transact(b"Z9,401000,1").unwrap(), b"");

    client.send_packet(b"k").expect("kill");
    server.join().expect("server thread");

    let recorded = calls.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec![
            HwCall::SetHwBreak(0x40_1000),
            HwCall::SetWatch(0x40_1010, 4, WatchKind::Write),
            HwCall::SetWatch(0x40_1020, 2, WatchKind::Read),
            HwCall::SetWatch(0x40_1030, 8, WatchKind::Access),
            HwCall::SetHwBreak(0x40_1040),
            HwCall::RemoveHwBreak(0x40_1000),
            HwCall::RemoveWatch(0x40_1010, 4, WatchKind::Write),
        ]
    );
}

/// A target reporting two threads, with a mutable current-thread selection, so
/// the thread packets (`qfThreadInfo`, `qC`, `Hg`, `T`, thread-tagged stops)
/// can be exercised through the real server dispatch.
struct ThreadedTarget {
    threads: Vec<u64>,
    current: u64,
}

impl RemoteTarget for ThreadedTarget {
    fn read_registers(&mut self) -> Result<Vec<u8>, TargetError> {
        Ok(Amd64CoreRegisters::default().to_gpacket())
    }
    fn write_registers(&mut self, _raw: &[u8]) -> Result<(), TargetError> {
        Ok(())
    }
    fn read_memory(&mut self, _addr: u64, len: usize) -> Result<Vec<u8>, TargetError> {
        Ok(vec![0u8; len])
    }
    fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<(), TargetError> {
        Ok(())
    }
    fn cont(&mut self) -> Result<StopReply, TargetError> {
        Ok(StopReply::Signal(5))
    }
    fn step(&mut self) -> Result<StopReply, TargetError> {
        Ok(StopReply::Signal(5))
    }
    fn set_sw_breakpoint(&mut self, _addr: u64) -> Result<(), TargetError> {
        Ok(())
    }
    fn remove_sw_breakpoint(&mut self, _addr: u64) -> Result<(), TargetError> {
        Ok(())
    }
    fn stop_reason(&mut self) -> StopReply {
        StopReply::Signal(5)
    }
    fn thread_ids(&mut self) -> Result<Vec<u64>, TargetError> {
        Ok(self.threads.clone())
    }
    fn current_thread(&mut self) -> Result<u64, TargetError> {
        Ok(self.current)
    }
    fn set_current_thread(&mut self, id: u64) -> Result<(), TargetError> {
        self.current = id;
        Ok(())
    }
    fn stopped_thread(&mut self) -> Option<u64> {
        Some(self.threads[0])
    }
}

#[test]
fn server_dispatches_thread_packets() {
    let (server_transport, client_transport) = memory_pair();

    let server = std::thread::spawn(move || {
        let mut target = ThreadedTarget {
            threads: vec![1, 7],
            current: 1,
        };
        let mut server = GdbStubServer::new(server_transport);
        server.serve(&mut target).expect("server loop");
    });

    let mut client = GdbRemoteClient::new(client_transport);

    // Thread list: first batch carries both ids, second batch ends the list.
    assert_eq!(client.transact(b"qfThreadInfo").unwrap(), b"m1,7");
    assert_eq!(client.transact(b"qsThreadInfo").unwrap(), b"l");
    // Current thread.
    assert_eq!(client.transact(b"qC").unwrap(), b"QC1");
    // Select thread 7 for continue/step; qC then reflects it.
    assert_eq!(client.transact(b"Hc7").unwrap(), b"OK");
    assert_eq!(client.transact(b"qC").unwrap(), b"QC7");
    // is-thread-alive: known -> OK, unknown -> E01.
    assert_eq!(client.transact(b"T7").unwrap(), b"OK");
    assert_eq!(client.transact(b"T9").unwrap(), b"E01");
    // The stop reply is tagged with the stopping thread.
    assert_eq!(client.transact(b"?").unwrap(), b"T05thread:1;");
    // vCont advertises only the implemented continue and step actions.
    assert_eq!(client.transact(b"vCont?").unwrap(), b"vCont;c;s");

    client.send_packet(b"k").expect("kill");
    server.join().expect("server thread");
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
    assert!(
        supported.contains("qXfer:features:read+"),
        "got: {supported}"
    );

    // Target XML is fetched over multiple bounded qXfer chunks and parsed.
    let description = client
        .read_target_description()
        .expect("target description request")
        .expect("mock advertises target description");
    assert_eq!(description.architecture(), Some("i386:x86-64"));
    assert_eq!(
        description.expected_gpacket_bytes(),
        Some(AMD64_GPACKET_BYTES)
    );
    assert_eq!(description.byte_order(), Some(TargetByteOrder::Little));

    // Oversized and internally inconsistent memory requests fail closed.
    assert_eq!(client.transact(b"m401000,801").unwrap(), b"E01");
    assert_eq!(client.transact(b"M402000,2:aa").unwrap(), b"E01");

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
    assert!(client.set_breakpoint_with_kind(0x0040_1002, 4).is_err());
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
