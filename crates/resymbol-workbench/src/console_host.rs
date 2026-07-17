//! Opt-in companion-console process transport.
//!
//! The GUI owns lifecycle and application state. The helper owns only its
//! terminal window, while anonymous process pipes carry bounded JSON string
//! frames in each direction. This keeps terminal close events and blocking
//! console input out of the workbench process.

use std::{
    process::Child,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError},
    },
    time::{Duration, Instant},
};

#[cfg(target_os = "windows")]
use std::{
    io::{BufReader, BufWriter, Write},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
};

use crate::console::MAX_CONSOLE_OUTPUT_BYTES;
#[cfg(target_os = "windows")]
use crate::console::{ConsoleToHostFrame, MAX_COMMAND_LINE_BYTES, read_bounded_line};

#[cfg(target_os = "windows")]
const OUTPUT_QUEUE_CAPACITY: usize = 256;
#[cfg(target_os = "windows")]
const EVENT_QUEUE_CAPACITY: usize = 128;
#[cfg(target_os = "windows")]
const MAX_WIRE_FRAME_BYTES: usize = 32 * 1024;

trait StartupChild {
    fn terminate_and_wait(&mut self);
}

impl StartupChild for Child {
    fn terminate_and_wait(&mut self) {
        let _ = self.kill();
        let _ = self.wait();
    }
}

#[cfg(any(target_os = "windows", test))]
struct PendingChild<C: StartupChild> {
    child: Option<C>,
}

#[cfg(any(target_os = "windows", test))]
impl<C: StartupChild> PendingChild<C> {
    fn new(child: C) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut C {
        self.child
            .as_mut()
            .expect("pending child remains owned until commit")
    }

    fn commit(mut self) -> C {
        self.child
            .take()
            .expect("pending child remains owned until commit")
    }
}

#[cfg(any(target_os = "windows", test))]
impl<C: StartupChild> Drop for PendingChild<C> {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            child.terminate_and_wait();
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn initialize_owned_child<C, T, E>(
    child: C,
    initialize: impl FnOnce(&mut C) -> Result<T, E>,
) -> Result<(C, T), E>
where
    C: StartupChild,
{
    let mut pending = PendingChild::new(child);
    let initialized = initialize(pending.child_mut())?;
    Ok((pending.commit(), initialized))
}

/// An event produced by the companion transport for the GUI event loop.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) enum ConsoleHostEvent {
    Ready,
    CommandLine(String),
    Closed(Option<i32>),
    Error(String),
    Fatal(String),
}

/// GUI-owned lifecycle for the optional companion console.
#[derive(Debug, Default)]
pub(crate) struct ConsoleHost {
    session: Option<ConsoleSession>,
}

impl ConsoleHost {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.session.is_some()
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.session.as_ref().is_some_and(|session| session.ready)
    }

    pub(crate) fn enable(&mut self) -> Result<(), String> {
        if self.session.is_some() {
            return Ok(());
        }
        self.session = Some(spawn_session()?);
        Ok(())
    }

    pub(crate) fn disable(&mut self) {
        if let Some(mut session) = self.session.take() {
            session.stop();
        }
    }

    /// Queue one already-bounded display message without blocking the UI.
    pub(crate) fn try_send_line(&self, message: impl Into<String>) -> bool {
        let Some(session) = &self.session else {
            return false;
        };
        let mut message = message.into();
        if message.len() > MAX_CONSOLE_OUTPUT_BYTES {
            let mut end = MAX_CONSOLE_OUTPUT_BYTES;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        let dropped = session.dropped_output.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let notice = format!("[warning] {dropped} console output line(s) were dropped");
            match session.output_sender.try_send(notice) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    session
                        .dropped_output
                        .fetch_add(dropped.saturating_add(1), Ordering::Relaxed);
                    return false;
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        match session.output_sender.try_send(message) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                session.dropped_output.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    pub(crate) fn drain_events(&mut self, maximum: usize) -> Vec<ConsoleHostEvent> {
        let Some(session) = self.session.as_mut() else {
            return Vec::new();
        };
        let mut events = Vec::new();
        while events.len() < maximum {
            match session.event_receiver.try_recv() {
                Ok(event) => {
                    let fatal = matches!(&event, ConsoleHostEvent::Fatal(_));
                    match &event {
                        ConsoleHostEvent::Ready => session.ready = true,
                        ConsoleHostEvent::Closed(_) => session.reported_closed = true,
                        ConsoleHostEvent::CommandLine(_)
                        | ConsoleHostEvent::Error(_)
                        | ConsoleHostEvent::Fatal(_) => {}
                    }
                    events.push(event);
                    if fatal {
                        let _ = session.child.kill();
                        let exit_code = session.child.wait().ok().and_then(|status| status.code());
                        session.reported_closed = true;
                        if events.len() < maximum {
                            events.push(ConsoleHostEvent::Closed(exit_code));
                        }
                        break;
                    }
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        if !session.ready
            && !session.reported_closed
            && session.started_at.elapsed() >= Duration::from_secs(3)
            && events.len().saturating_add(2) <= maximum
        {
            let _ = session.child.kill();
            let exit_code = session.child.wait().ok().and_then(|status| status.code());
            session.reported_closed = true;
            events.push(ConsoleHostEvent::Error(
                "companion console ready handshake timed out".to_owned(),
            ));
            events.push(ConsoleHostEvent::Closed(exit_code));
            return events;
        }
        if !session.reported_closed && events.len() < maximum {
            match session.child.try_wait() {
                Ok(Some(status)) => {
                    session.reported_closed = true;
                    events.push(ConsoleHostEvent::Closed(status.code()));
                }
                Ok(None) => {}
                Err(error) => {
                    session.reported_closed = true;
                    events.push(ConsoleHostEvent::Fatal(format!(
                        "cannot inspect companion console: {error}"
                    )));
                }
            }
        }
        events
    }
}

impl Drop for ConsoleHost {
    fn drop(&mut self) {
        self.disable();
    }
}

#[derive(Debug)]
struct ConsoleSession {
    child: Child,
    output_sender: SyncSender<String>,
    event_receiver: Receiver<ConsoleHostEvent>,
    dropped_output: AtomicUsize,
    started_at: Instant,
    ready: bool,
    reported_closed: bool,
}

impl ConsoleSession {
    fn stop(&mut self) {
        self.child.terminate_and_wait();
    }
}

#[cfg(target_os = "windows")]
struct InitializedConsoleSession {
    output_sender: SyncSender<String>,
    event_receiver: Receiver<ConsoleHostEvent>,
}

#[cfg(target_os = "windows")]
fn spawn_console_worker(
    name: &'static str,
    task: impl FnOnce() + Send + 'static,
) -> Result<(), String> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(task)
        .map(|_| ())
        .map_err(|error| format!("cannot start {name} worker: {error}"))
}

#[cfg(target_os = "windows")]
fn spawn_session() -> Result<ConsoleSession, String> {
    use std::os::windows::process::CommandExt;

    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

    let current_executable = std::env::current_exe()
        .map_err(|error| format!("cannot locate the workbench executable: {error}"))?;
    let helper_path = current_executable.with_file_name("resymbol-workbench-console.exe");
    if !helper_path.is_file() {
        return Err(format!(
            "companion helper is missing at {}; build or install both workbench executables",
            helper_path.display()
        ));
    }

    let child = Command::new(&helper_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map_err(|error| format!("cannot spawn {}: {error}", helper_path.display()))?;

    let (child, initialized) = initialize_owned_child(child, |child| {
        let child_input = child
            .stdin
            .take()
            .ok_or_else(|| "companion console did not expose its input pipe".to_owned())?;
        let child_output = child
            .stdout
            .take()
            .ok_or_else(|| "companion console did not expose its output pipe".to_owned())?;
        let child_error = child
            .stderr
            .take()
            .ok_or_else(|| "companion console did not expose its diagnostics pipe".to_owned())?;

        let (output_sender, output_receiver) = mpsc::sync_channel(OUTPUT_QUEUE_CAPACITY);
        let (event_sender, event_receiver) = mpsc::sync_channel(EVENT_QUEUE_CAPACITY);

        let writer_events = event_sender.clone();
        spawn_console_worker("companion-console-writer", move || {
            let mut writer = BufWriter::new(child_input);
            while let Ok(message) = output_receiver.recv() {
                if serde_json::to_writer(&mut writer, &message)
                    .and_then(|()| writer.write_all(b"\n").map_err(serde_json::Error::io))
                    .and_then(|()| writer.flush().map_err(serde_json::Error::io))
                    .is_err()
                {
                    let _ = writer_events.send(ConsoleHostEvent::Fatal(
                        "companion console output pipe closed".to_owned(),
                    ));
                    break;
                }
            }
        })?;

        let reader_events = event_sender.clone();
        spawn_console_worker("companion-console-reader", move || {
            let mut reader = BufReader::new(child_output);
            let mut expecting_ready = true;
            loop {
                match read_bounded_line(&mut reader, MAX_WIRE_FRAME_BYTES) {
                    Ok(None) => {
                        let _ = reader_events.send(ConsoleHostEvent::Fatal(
                            "companion command pipe closed".to_owned(),
                        ));
                        break;
                    }
                    Ok(Some(frame)) => {
                        match serde_json::from_str::<ConsoleToHostFrame>(frame.trim_end()) {
                            Ok(ConsoleToHostFrame::Ready) if expecting_ready => {
                                expecting_ready = false;
                                let _ = reader_events.send(ConsoleHostEvent::Ready);
                            }
                            Ok(ConsoleToHostFrame::Ready | ConsoleToHostFrame::Command(_))
                                if expecting_ready =>
                            {
                                let _ = reader_events.send(ConsoleHostEvent::Fatal(
                                    "companion console did not complete its ready handshake"
                                        .to_owned(),
                                ));
                                break;
                            }
                            Ok(ConsoleToHostFrame::Ready) => {
                                let _ = reader_events.send(ConsoleHostEvent::Fatal(
                                    "companion console repeated its ready handshake".to_owned(),
                                ));
                                break;
                            }
                            Ok(ConsoleToHostFrame::Command(line))
                                if line.len() <= MAX_COMMAND_LINE_BYTES =>
                            {
                                if reader_events
                                    .send(ConsoleHostEvent::CommandLine(line))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Ok(ConsoleToHostFrame::Command(_)) => {
                                let _ = reader_events.send(ConsoleHostEvent::Error(
                                    "companion command exceeds the 4096-byte limit".to_owned(),
                                ));
                            }
                            Ok(ConsoleToHostFrame::Fatal(error)) => {
                                let _ = reader_events.send(ConsoleHostEvent::Fatal(format!(
                                    "companion console: {error}"
                                )));
                                break;
                            }
                            Err(error) => {
                                let _ = reader_events.send(ConsoleHostEvent::Fatal(format!(
                                    "invalid companion command frame: {error}"
                                )));
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        let _ = reader_events.send(ConsoleHostEvent::Fatal(format!(
                            "cannot read companion commands: {error}"
                        )));
                        break;
                    }
                }
            }
        })?;

        spawn_console_worker("companion-console-diagnostics", move || {
            let mut reader = BufReader::new(child_error);
            loop {
                match read_bounded_line(&mut reader, MAX_WIRE_FRAME_BYTES) {
                    Ok(Some(line)) if !line.trim().is_empty() => {
                        let _ = event_sender.send(ConsoleHostEvent::Error(format!(
                            "companion console: {}",
                            line.trim_end()
                        )));
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(error) => {
                        let _ = event_sender.send(ConsoleHostEvent::Fatal(format!(
                            "cannot read companion diagnostics: {error}"
                        )));
                        break;
                    }
                }
            }
        })?;

        Ok(InitializedConsoleSession {
            output_sender,
            event_receiver,
        })
    })?;

    Ok(ConsoleSession {
        child,
        output_sender: initialized.output_sender,
        event_receiver: initialized.event_receiver,
        dropped_output: AtomicUsize::new(0),
        started_at: Instant::now(),
        ready: false,
        reported_closed: false,
    })
}

#[cfg(not(target_os = "windows"))]
fn spawn_session() -> Result<ConsoleSession, String> {
    Err("the external companion console is currently available on Windows only".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Default)]
    struct CleanupCounters {
        terminations: AtomicUsize,
        waits: AtomicUsize,
    }

    struct FakeStartupChild {
        counters: Arc<CleanupCounters>,
    }

    impl StartupChild for FakeStartupChild {
        fn terminate_and_wait(&mut self) {
            self.counters.terminations.fetch_add(1, Ordering::SeqCst);
            self.counters.waits.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn fake_startup_child() -> (FakeStartupChild, Arc<CleanupCounters>) {
        let counters = Arc::new(CleanupCounters::default());
        (
            FakeStartupChild {
                counters: Arc::clone(&counters),
            },
            counters,
        )
    }

    fn assert_cleaned_up(counters: &CleanupCounters) {
        assert_eq!(counters.terminations.load(Ordering::SeqCst), 1);
        assert_eq!(counters.waits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn disabled_host_drops_output_without_blocking() {
        let host = ConsoleHost::new();
        assert!(!host.is_enabled());
        assert!(!host.try_send_line("ignored"));
    }

    #[test]
    fn pipe_initialization_failure_cleans_up_pending_child() {
        let (child, counters) = fake_startup_child();

        let result = initialize_owned_child(child, |_| -> Result<(), &'static str> {
            Err("input pipe unavailable")
        });

        assert!(matches!(result, Err("input pipe unavailable")));
        assert_cleaned_up(&counters);
    }

    #[test]
    fn worker_initialization_failure_cleans_up_pending_child() {
        let (child, counters) = fake_startup_child();

        let result = initialize_owned_child(child, |_| -> Result<(), &'static str> {
            Err("reader worker unavailable")
        });

        assert!(matches!(result, Err("reader worker unavailable")));
        assert_cleaned_up(&counters);
    }

    #[test]
    fn successful_initialization_transfers_child_without_implicit_cleanup() {
        let (child, counters) = fake_startup_child();

        let (mut child, initialized) = initialize_owned_child(child, |_| Ok::<_, &'static str>(7))
            .expect("fake initialization succeeds");

        assert_eq!(initialized, 7);
        assert_eq!(counters.terminations.load(Ordering::SeqCst), 0);
        assert_eq!(counters.waits.load(Ordering::SeqCst), 0);

        child.terminate_and_wait();
        assert_cleaned_up(&counters);
    }
}
