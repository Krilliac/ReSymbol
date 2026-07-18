//! Real end-to-end RSP exercise over a localhost TCP socket. `#[ignore]`d and
//! gated on Linux + the `gdb-remote-e2e` feature, because a sandboxed CI
//! environment may forbid ptrace (yama `ptrace_scope`, seccomp) or restrict
//! loopback sockets. Compiles under `--all-features`; run explicitly with:
//!
//! ```text
//! cargo test -p resymbol-gdb-remote --features gdb-remote-e2e \
//!     --test gdb_remote_e2e -- --ignored --exact serve_ptrace_target_over_tcp
//! ```

#![cfg(all(target_os = "linux", feature = "gdb-remote-e2e"))]

use resymbol_gdb_remote::target::StopReply;
use resymbol_gdb_remote::{
    GdbRemoteClient, GdbStubServer, PtraceRemoteTarget, TcpServerListener, TcpTransport,
};
use resymbol_linux_debug_host::{LaunchSpec, launch};

#[test]
#[ignore = "requires ptrace permission and loopback sockets; run explicitly"]
fn serve_ptrace_target_over_tcp() {
    let fixture = env!("CARGO_BIN_EXE_resymbol-gdb-remote-fixture");

    // Launch the traced child and wrap it as an RSP target. ptrace requires the
    // tracer thread to own the target, so the server runs on this thread and
    // the client drives it from a spawned thread.
    let session = launch(&LaunchSpec::new(fixture)).expect("launch traced child");
    let mut target = PtraceRemoteTarget::new(session);

    let listener = TcpServerListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    let client_thread = std::thread::spawn(move || {
        let transport = TcpTransport::connect(addr).expect("client connect");
        let mut client = GdbRemoteClient::new(transport);

        // Registers and the code at RIP must be readable.
        let raw = client.read_registers().expect("read registers");
        let registers = resymbol_gdb_remote::amd64_gpacket_to_registers(&raw).unwrap();
        assert_ne!(registers.rip, 0, "entry RIP should be nonzero");

        let code = client
            .read_memory(registers.rip, 8)
            .expect("read code at RIP");
        assert_eq!(code.len(), 8);

        // Single-step a few times, then run to completion.
        for _ in 0..4 {
            match client.step().expect("step") {
                StopReply::Signal(_) => {}
                StopReply::Exited(_) | StopReply::Terminated(_) => return,
            }
        }
        while let StopReply::Signal(_) = client.cont().expect("continue") {
            // Keep running until the target exits or is terminated.
        }
        // Dropping the client closes the socket, ending the server loop.
    });

    let transport = listener.accept().expect("accept client");
    GdbStubServer::new(transport)
        .serve(&mut target)
        .expect("serve loop");

    client_thread.join().expect("client thread");
}

#[test]
#[ignore = "requires ptrace permission and loopback sockets; run explicitly"]
fn hardware_breakpoint_is_set_and_hit_over_tcp() {
    let fixture = env!("CARGO_BIN_EXE_resymbol-gdb-remote-fixture");

    let session = launch(&LaunchSpec::new(fixture)).expect("launch traced child");
    let mut target = PtraceRemoteTarget::new(session);

    let listener = TcpServerListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    let client_thread = std::thread::spawn(move || {
        let transport = TcpTransport::connect(addr).expect("client connect");
        let mut client = GdbRemoteClient::new(transport);

        // Entry RIP.
        let entry_raw = client.read_registers().expect("read registers");
        let entry = resymbol_gdb_remote::amd64_gpacket_to_registers(&entry_raw).unwrap();

        // Single-step once to discover the address of the second instruction,
        // then rewind RIP to entry so continuing re-executes toward it.
        match client.step().expect("step") {
            StopReply::Signal(_) => {}
            other => panic!("unexpected stop after step: {other:?}"),
        }
        let second_raw = client.read_registers().expect("read registers after step");
        let second = resymbol_gdb_remote::amd64_gpacket_to_registers(&second_raw).unwrap();
        assert_ne!(second.rip, entry.rip, "step advanced RIP");

        // Arm a hardware execute breakpoint (Z1) at the second instruction.
        let request = format!("Z1,{:x},1", second.rip).into_bytes();
        assert_eq!(client.transact(&request).expect("Z1"), b"OK");

        // Rewind RIP to entry and continue; the breakpoint must fire at `second`.
        client
            .write_registers(&entry_raw)
            .expect("rewind registers to entry");
        assert_eq!(
            client.cont().expect("continue to hw breakpoint"),
            StopReply::Signal(5)
        );
        let hit_raw = client.read_registers().expect("read registers at hit");
        let hit = resymbol_gdb_remote::amd64_gpacket_to_registers(&hit_raw).unwrap();
        assert_eq!(hit.rip, second.rip, "trapped at the hardware breakpoint");

        // Remove it (z1) and run to completion.
        let remove = format!("z1,{:x},1", second.rip).into_bytes();
        assert_eq!(client.transact(&remove).expect("z1"), b"OK");
        while let StopReply::Signal(_) = client.cont().expect("continue") {}
    });

    let transport = listener.accept().expect("accept client");
    GdbStubServer::new(transport)
        .serve(&mut target)
        .expect("serve loop");

    client_thread.join().expect("client thread");
}
