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
    DebugTargetRequest, HelperBuildId, HostRiskLeaseIssuer, HostRiskOperation, LiveTargetBinding,
    MemoryAddress, ProcessId, ProcessStartKey, ProtocolVersion, ProvisioningEpoch,
    RemoteCommandCheckpoint, SessionId, SessionMachine, SessionState, StopReason, ThreadId,
    ValidatedLiveMemoryWrite,
};
use resymbol_windows_debug_host::{
    DebugAttachLimits, DebugHostWorkerState, WindowsDebugHostWorker,
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

    let mut worker = WindowsDebugHostWorker::new();
    let stop = worker
        .attach_after_authorization(&binding, DebugAttachLimits::default())
        .expect("owned-child attach reaches initial breakpoint");
    assert_eq!(stop.process_id(), process_id);
    assert_eq!(worker.state(), DebugHostWorkerState::Stopped);
    assert_eq!(worker.binding(), Some(&binding));
    assert_eq!(
        worker
            .read_stopped_main_image(MemoryAddress::new(read_address), EXPECTED_BYTES.len())
            .expect("read exact bytes under retained attach stop"),
        EXPECTED_BYTES
    );
    let write_address = MemoryAddress::new(read_address);
    let mut session = ValidatedWriteSession::new(&binding, stop.thread_id());
    let (checkpoint, write) = session.begin_write(write_address, EXPECTED_BYTES, PATCHED_BYTES);
    let protocol_stop = write.stop();
    let receipt = worker
        .write_stopped_main_image_after_protocol_validation(&stop, &checkpoint, write)
        .expect("write exact bytes under retained attach stop");
    assert_eq!(receipt.stop(), protocol_stop);
    assert_eq!(receipt.pending_stop(), &stop);
    assert_eq!(receipt.binding(), &binding);
    assert_eq!(receipt.address(), write_address);
    assert_eq!(receipt.before(), EXPECTED_BYTES);
    assert_eq!(receipt.after(), PATCHED_BYTES);
    session.commit(checkpoint, receipt.command_id());
    assert_eq!(
        worker
            .read_stopped_main_image(write_address, PATCHED_BYTES.len())
            .expect("read patched bytes under retained attach stop"),
        PATCHED_BYTES
    );
    let (restore_checkpoint, restore) =
        session.begin_write(write_address, PATCHED_BYTES, EXPECTED_BYTES);
    let restore_stop = restore.stop();
    let restore_receipt = worker
        .write_stopped_main_image_after_protocol_validation(&stop, &restore_checkpoint, restore)
        .expect("restore exact fixture bytes under retained attach stop");
    assert_eq!(restore_receipt.stop(), restore_stop);
    assert_eq!(restore_receipt.pending_stop(), &stop);
    assert_eq!(restore_receipt.binding(), &binding);
    assert_eq!(restore_receipt.address(), write_address);
    assert_eq!(restore_receipt.before(), PATCHED_BYTES);
    assert_eq!(restore_receipt.after(), EXPECTED_BYTES);
    session.commit(restore_checkpoint, restore_receipt.command_id());
    assert_eq!(
        worker
            .read_stopped_main_image(write_address, EXPECTED_BYTES.len())
            .expect("read restored bytes under retained attach stop"),
        EXPECTED_BYTES
    );

    worker
        .detach()
        .expect("continue retained breakpoint and stop debugging");
    assert_eq!(worker.state(), DebugHostWorkerState::Detached);
    owned.release_and_wait();
}

fn parse_hex(field: Option<&str>, label: &str) -> u64 {
    u64::from_str_radix(field.unwrap_or_else(|| panic!("fixture emits {label}")), 16)
        .unwrap_or_else(|error| panic!("fixture {label} is hexadecimal: {error}"))
}

struct ValidatedWriteSession {
    machine: SessionMachine,
    binding: LiveTargetBinding,
    next_command_id: u64,
}

impl ValidatedWriteSession {
    fn new(binding: &LiveTargetBinding, stopped_thread: ThreadId) -> Self {
        let session_id = SessionId::new(1).expect("nonzero test session");
        let provisioning_epoch =
            ProvisioningEpoch::new("a".repeat(64)).expect("test provisioning epoch");
        let helper_build =
            HelperBuildId::new("windows-debug-host-owned-child").expect("test helper build");
        let process = binding.process().clone();
        let mut issuer = HostRiskLeaseIssuer::new().expect("host-risk issuer");
        let (lease, _verifier) = issuer
            .issue(
                session_id,
                provisioning_epoch.clone(),
                HostRiskOperation::Attach {
                    process: process.clone(),
                    mode: AttachMode::Debug,
                },
            )
            .expect("issue exact attach authority");
        let risk_lease = lease.id().clone();
        let mut machine = SessionMachine::new(session_id, provisioning_epoch, helper_build);
        machine
            .register_host_risk_lease(lease)
            .expect("register exact attach authority");
        let initial = machine.state().state_token();
        machine
            .accept_command(&CommandEnvelope {
                version: ProtocolVersion::current(),
                command_id: CommandId::new(1).expect("open command id"),
                session_id: Some(session_id),
                expected_state: Some(initial),
                command: DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                    scope: AttachScope::Host {
                        process,
                        risk_lease,
                    },
                    mode: AttachMode::Debug,
                })),
            })
            .expect("accept exact debug attach");
        machine
            .mark_stopped(StopReason::Initial, stopped_thread)
            .expect("debug attach reaches stopped state");
        Self {
            machine,
            binding: binding.clone(),
            next_command_id: 2,
        }
    }

    fn begin_write(
        &mut self,
        address: MemoryAddress,
        expected: &[u8],
        replacement: &[u8],
    ) -> (RemoteCommandCheckpoint, ValidatedLiveMemoryWrite) {
        let SessionState::Stopped { token: stop, .. } = self.machine.state() else {
            panic!("validated write session is stopped")
        };
        let command_id = CommandId::new(self.next_command_id).expect("write command id");
        let envelope = CommandEnvelope {
            version: ProtocolVersion::current(),
            command_id,
            session_id: Some(stop.state.session_id),
            expected_state: Some(stop.state),
            command: DebugCommand::WriteMemory {
                stop: *stop,
                address,
                expected: expected.to_vec(),
                replacement: replacement.to_vec(),
            },
        };
        let transaction = self
            .machine
            .begin_live_memory_write(envelope, self.binding.clone())
            .expect("mint exact validated write ticket");
        self.next_command_id += 1;
        transaction
    }

    fn commit(&mut self, checkpoint: RemoteCommandCheckpoint, command_id: CommandId) {
        self.machine
            .commit_remote_command(checkpoint, command_id)
            .expect("commit exact write checkpoint");
    }
}
