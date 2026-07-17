#![cfg(all(windows, feature = "windows-debug-host-test-fixture"))]

use std::{
    fs::File,
    io::{BufRead as _, BufReader, Write as _},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use resymbol_core::BinaryId;
use resymbol_debugger::{
    AttachMode, AttachScope, AttachTarget, CommandEnvelope, CommandId, DebugCommand,
    DebugTargetRequest, HelperBuildId, HostRiskLeaseIssuer, HostRiskOperation, MemoryAddress,
    ProcessId, ProcessStartKey, ProtocolVersion, ProvisioningEpoch, ReadViewToken, SessionId,
    SessionState,
};
use resymbol_windows_debug_host::{
    DebugAttachLimits, DebugHostWorkerState, SessionWorkerHealth, WindowsSessionWorker,
};
use resymbol_windows_live_access::{OpenLiveProcessRequest, ReadOnlyLiveProcessAccess};

const EXPECTED_BYTES: &[u8; 8] = b"RSYMHOST";
const PATCHED_BYTES: &[u8; 8] = b"RSYMH0ST";
const FIXTURE_WATCHDOG: Duration = Duration::from_secs(10);
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

struct OwnedFixtureChild {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl OwnedFixtureChild {
    fn release_and_wait(&mut self) {
        if let Some(mut stdin) = self.stdin.take() {
            writeln!(stdin).expect("release owned debug-host fixture");
            stdin.flush().expect("flush fixture release line");
        }
        let deadline = Instant::now() + FIXTURE_WATCHDOG;
        let status = loop {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("poll owned debug-host fixture")
            {
                break status;
            }
            if Instant::now() >= deadline {
                self.terminate_and_wait();
                panic!("owned debug-host fixture did not exit within {FIXTURE_WATCHDOG:?}");
            }
            thread::sleep(EXIT_POLL_INTERVAL);
        };
        assert!(status.success(), "debug-host fixture failed: {status}");
    }

    fn terminate_and_wait(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for OwnedFixtureChild {
    fn drop(&mut self) {
        self.terminate_and_wait();
    }
}

#[test]
fn owned_child_attach_stopped_read_continue_and_detach() {
    let fixture = env!("CARGO_BIN_EXE_resymbol-windows-debug-host-fixture");
    let mut child = Command::new(fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn owned debug-host fixture");
    let stdin = child.stdin.take().expect("fixture stdin");
    let stdout = child.stdout.take().expect("fixture stdout");
    let mut owned = OwnedFixtureChild {
        child,
        stdin: Some(stdin),
    };

    let (identity_sender, identity_receiver) = mpsc::sync_channel(1);
    let identity_reader = thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = identity_sender.send((result, line));
    });
    let line = match identity_receiver.recv_timeout(FIXTURE_WATCHDOG) {
        Ok((Ok(0), _)) => panic!("fixture exited before emitting its identity"),
        Ok((Ok(_), line)) => line,
        Ok((Err(error), _)) => panic!("read fixture identity line: {error}"),
        Err(RecvTimeoutError::Timeout) => {
            owned.terminate_and_wait();
            identity_reader
                .join()
                .expect("identity reader exits after watchdog termination");
            panic!("fixture did not emit its identity within {FIXTURE_WATCHDOG:?}");
        }
        Err(RecvTimeoutError::Disconnected) => {
            panic!("fixture identity reader disconnected unexpectedly");
        }
    };
    identity_reader
        .join()
        .expect("fixture identity reader did not panic");
    let mut fields = line.split_ascii_whitespace();
    let start_key = parse_hex(fields.next(), "start key");
    let image_base = parse_hex(fields.next(), "image base");
    let read_address = parse_hex(fields.next(), "read address");
    assert!(
        fields.next().is_none(),
        "fixture emits exactly three fields"
    );

    let process_id = ProcessId::new(owned.child.id()).expect("child PID is nonzero");
    let start_key = ProcessStartKey::new(start_key).expect("fixture start key is nonzero");
    let image_base = MemoryAddress::new(image_base);
    let (binary_id, _) =
        BinaryId::digest_reader(File::open(fixture).expect("open exact fixture executable"))
            .expect("hash exact fixture executable");

    // Reuse the existing exact preflight boundary to obtain SizeOfImage. The
    // debug worker repeats that complete validation before DebugActiveProcess.
    let preflight = ReadOnlyLiveProcessAccess::open_read_only(OpenLiveProcessRequest::new(
        process_id, start_key, image_base, binary_id,
    ))
    .expect("derive exact owned-child binding");
    let binding = preflight.binding().clone();
    drop(preflight);

    let session_id = SessionId::new(1).expect("nonzero test session");
    let provisioning_epoch =
        ProvisioningEpoch::new("a".repeat(64)).expect("test provisioning epoch");
    let helper_build =
        HelperBuildId::new("windows-debug-host-owned-child").expect("test helper build");
    let mut issuer = HostRiskLeaseIssuer::new().expect("host-risk issuer");
    let (lease, _verifier) = issuer
        .issue(
            session_id,
            provisioning_epoch.clone(),
            HostRiskOperation::Attach {
                process: binding.process().clone(),
                mode: AttachMode::Debug,
            },
        )
        .expect("issue exact attach authority");
    let risk_lease = lease.id().clone();
    let mut worker = WindowsSessionWorker::new(
        session_id,
        provisioning_epoch,
        helper_build,
        DebugAttachLimits::default(),
    );
    worker
        .register_host_risk_lease(lease)
        .expect("register exact attach authority");
    let open = CommandEnvelope {
        version: ProtocolVersion::current(),
        command_id: CommandId::new(1).expect("open command id"),
        session_id: Some(session_id),
        expected_state: Some(worker.state().state_token()),
        command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
            scope: AttachScope::Host {
                process: binding.process().clone(),
                risk_lease,
            },
            mode: AttachMode::Debug,
        })),
    };
    let attach = worker
        .open_debug_attach(open, binding.clone())
        .expect("owned-child attach reaches initial breakpoint");
    assert_eq!(attach.pending_stop().process_id(), process_id);
    assert_eq!(worker.provider_state(), DebugHostWorkerState::Stopped);
    assert_eq!(worker.binding(), Some(&binding));
    assert_eq!(worker.health(), SessionWorkerHealth::Ready);
    let write_address = MemoryAddress::new(read_address);
    let initial_read_command =
        stopped_read_command(&worker, session_id, 2, write_address, EXPECTED_BYTES.len());
    let initial_read = worker
        .read_memory(initial_read_command)
        .expect("read exact bytes under retained attach stop");
    assert_eq!(initial_read.bytes(), EXPECTED_BYTES);
    let write_command = stopped_write_command(
        &worker,
        session_id,
        3,
        write_address,
        EXPECTED_BYTES,
        PATCHED_BYTES,
    );
    let receipt = worker
        .write_memory(write_command)
        .expect("write exact bytes under retained attach stop");
    assert_eq!(receipt.provider().pending_stop(), attach.pending_stop());
    assert_eq!(receipt.provider().binding(), &binding);
    assert_eq!(receipt.provider().address(), write_address);
    assert_eq!(receipt.provider().before(), EXPECTED_BYTES);
    assert_eq!(receipt.provider().after(), PATCHED_BYTES);
    let patched_read_command =
        stopped_read_command(&worker, session_id, 4, write_address, PATCHED_BYTES.len());
    let patched_read = worker
        .read_memory(patched_read_command)
        .expect("read patched bytes under retained attach stop");
    assert_eq!(patched_read.bytes(), PATCHED_BYTES);
    let restore_command = stopped_write_command(
        &worker,
        session_id,
        5,
        write_address,
        PATCHED_BYTES,
        EXPECTED_BYTES,
    );
    let restore_receipt = worker
        .write_memory(restore_command)
        .expect("restore exact fixture bytes under retained attach stop");
    assert_eq!(restore_receipt.provider().binding(), &binding);
    assert_eq!(restore_receipt.provider().address(), write_address);
    assert_eq!(restore_receipt.provider().before(), PATCHED_BYTES);
    assert_eq!(restore_receipt.provider().after(), EXPECTED_BYTES);
    let restored_read_command =
        stopped_read_command(&worker, session_id, 6, write_address, EXPECTED_BYTES.len());
    let restored_read = worker
        .read_memory(restored_read_command)
        .expect("read restored bytes under retained attach stop");
    assert_eq!(restored_read.bytes(), EXPECTED_BYTES);

    let cleanup = worker.cleanup();
    assert!(cleanup.complete());
    assert_eq!(cleanup.health(), SessionWorkerHealth::Closed);
    assert_eq!(worker.provider_state(), DebugHostWorkerState::Detached);
    owned.release_and_wait();
}

fn parse_hex(field: Option<&str>, label: &str) -> u64 {
    u64::from_str_radix(field.unwrap_or_else(|| panic!("fixture emits {label}")), 16)
        .unwrap_or_else(|error| panic!("fixture {label} is hexadecimal: {error}"))
}

fn stopped_read_command(
    worker: &WindowsSessionWorker,
    session_id: SessionId,
    command_id: u64,
    address: MemoryAddress,
    size: usize,
) -> CommandEnvelope {
    let SessionState::Stopped { token: stop, .. } = worker.state() else {
        panic!("session worker is stopped")
    };
    CommandEnvelope {
        version: ProtocolVersion::current(),
        command_id: CommandId::new(command_id).expect("read command id"),
        session_id: Some(session_id),
        expected_state: Some(stop.state),
        command: DebugCommand::ReadMemory {
            view: ReadViewToken::Stopped { stop: *stop },
            address,
            size: u32::try_from(size).expect("fixture read size fits u32"),
        },
    }
}

fn stopped_write_command(
    worker: &WindowsSessionWorker,
    session_id: SessionId,
    command_id: u64,
    address: MemoryAddress,
    expected: &[u8],
    replacement: &[u8],
) -> CommandEnvelope {
    let SessionState::Stopped { token: stop, .. } = worker.state() else {
        panic!("session worker is stopped")
    };
    CommandEnvelope {
        version: ProtocolVersion::current(),
        command_id: CommandId::new(command_id).expect("write command id"),
        session_id: Some(session_id),
        expected_state: Some(stop.state),
        command: DebugCommand::WriteMemory {
            stop: *stop,
            address,
            expected: expected.to_vec(),
            replacement: replacement.to_vec(),
        },
    }
}
