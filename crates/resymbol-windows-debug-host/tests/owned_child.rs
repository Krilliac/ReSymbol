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
    MemoryAddress, ProcessId, ProcessStartKey, SessionId, StateGeneration, StateToken, StopId,
    StopToken,
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
    let protocol_stop = protocol_stop();
    let receipt = worker
        .write_stopped_main_image_after_protocol_validation(
            &stop,
            protocol_stop,
            write_address,
            EXPECTED_BYTES,
            PATCHED_BYTES,
        )
        .expect("write exact bytes under retained attach stop");
    assert_eq!(receipt.pending_stop(), &stop);
    assert_eq!(receipt.binding(), &binding);
    assert_eq!(receipt.address(), write_address);
    assert_eq!(receipt.before(), EXPECTED_BYTES);
    assert_eq!(receipt.after(), PATCHED_BYTES);
    assert_eq!(
        worker
            .read_stopped_main_image(write_address, PATCHED_BYTES.len())
            .expect("read patched bytes under retained attach stop"),
        PATCHED_BYTES
    );
    let restore_receipt = worker
        .write_stopped_main_image_after_protocol_validation(
            &stop,
            protocol_stop,
            write_address,
            PATCHED_BYTES,
            EXPECTED_BYTES,
        )
        .expect("restore exact fixture bytes under retained attach stop");
    assert_eq!(restore_receipt.pending_stop(), &stop);
    assert_eq!(restore_receipt.binding(), &binding);
    assert_eq!(restore_receipt.address(), write_address);
    assert_eq!(restore_receipt.before(), PATCHED_BYTES);
    assert_eq!(restore_receipt.after(), EXPECTED_BYTES);
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

fn protocol_stop() -> StopToken {
    StopToken {
        state: StateToken {
            session_id: SessionId::new(1).expect("nonzero test session"),
            generation: StateGeneration::new(1).expect("nonzero test generation"),
        },
        stop_id: StopId::new(1).expect("nonzero test stop"),
    }
}
