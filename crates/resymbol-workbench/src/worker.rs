use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
};

use resymbol_app::{AppServices, ExportFormat, ProjectSnapshot, ReviewLedger};

use crate::model::LoadedProject;

const COMMAND_QUEUE_CAPACITY: usize = 4;
const EVENT_QUEUE_CAPACITY: usize = COMMAND_QUEUE_CAPACITY + 1;

/// Correlates a worker result with the exact UI request that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationId(u64);

impl OperationId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Monotonic operation identifiers owned by the UI event loop.
#[derive(Debug)]
pub struct OperationSequence {
    next: u64,
}

impl Default for OperationSequence {
    fn default() -> Self {
        Self { next: 1 }
    }
}

impl OperationSequence {
    #[must_use]
    pub fn issue(&mut self) -> OperationId {
        let operation = OperationId(self.next);
        self.next = self
            .next
            .checked_add(1)
            .expect("operation identifier space exhausted");
        operation
    }
}

/// Tracks the only result currently allowed to update one category of UI state.
#[derive(Debug, Default)]
pub struct OperationGate {
    current: Option<OperationId>,
}

impl OperationGate {
    pub fn begin(&mut self, operation: OperationId) {
        self.current = Some(operation);
    }

    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.current.is_some()
    }

    /// Complete only the current request. Older results are stale and leave the
    /// current request pending.
    pub fn finish(&mut self, operation: OperationId) -> bool {
        if self.current != Some(operation) {
            return false;
        }
        self.current = None;
        true
    }

    pub fn invalidate(&mut self) {
        self.current = None;
    }
}

/// Export jobs available to the current workbench without a review editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerExportKind {
    Package,
    Service(ExportFormat),
}

impl WorkerExportKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Package => "ReSymbol package",
            Self::Service(format) => format.label(),
        }
    }
}

#[derive(Debug)]
pub struct ExportOutcome {
    pub kind: WorkerExportKind,
    pub path: PathBuf,
}

/// Long-running application-service work never runs on egui's render thread.
pub struct ServiceWorker {
    commands: Option<SyncSender<WorkerCommand>>,
    events: Option<Receiver<WorkerEvent>>,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ServiceWorker {
    pub fn start(repaint: eframe::egui::Context) -> Self {
        let (commands, command_rx) = sync_channel(COMMAND_QUEUE_CAPACITY);
        let (event_tx, events) = sync_channel(EVENT_QUEUE_CAPACITY);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let join = thread::Builder::new()
            .name("resymbol-app-services".to_owned())
            .spawn(move || worker_loop(command_rx, event_tx, repaint, worker_shutdown))
            .expect("the application-service worker thread must start");
        Self {
            commands: Some(commands),
            events: Some(events),
            shutdown,
            join: Some(join),
        }
    }

    pub fn submit(&self, command: WorkerCommand) -> Result<(), String> {
        let Some(commands) = &self.commands else {
            return Err("the application-service worker is shutting down".to_owned());
        };
        commands.try_send(command).map_err(|error| match error {
            TrySendError::Full(_) => {
                "the application-service queue is full; wait for the current operation".to_owned()
            }
            TrySendError::Disconnected(_) => {
                "the application-service worker stopped unexpectedly".to_owned()
            }
        })
    }

    pub fn try_recv(&self) -> Result<Option<WorkerEvent>, String> {
        let Some(events) = &self.events else {
            return Ok(None);
        };
        match events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                Err("the application-service worker stopped unexpectedly".to_owned())
            }
        }
    }

    fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(commands) = self.commands.take() {
            let _ = commands.try_send(WorkerCommand::Shutdown);
            drop(commands);
        }
        // A full event queue must not leave the worker blocked while it is joined.
        self.events.take();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for ServiceWorker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub enum WorkerCommand {
    Analyze {
        operation: OperationId,
        path: PathBuf,
    },
    OpenPackage {
        operation: OperationId,
        path: PathBuf,
    },
    VerifySource {
        operation: OperationId,
        project: Arc<ProjectSnapshot>,
        path: PathBuf,
    },
    Export {
        operation: OperationId,
        project: Arc<ProjectSnapshot>,
        kind: WorkerExportKind,
        path: PathBuf,
    },
    Shutdown,
}

pub enum WorkerEvent {
    ProjectOpened {
        operation: OperationId,
        result: Result<LoadedProject, String>,
    },
    SourceVerified {
        operation: OperationId,
        result: Result<LoadedProject, String>,
    },
    ExportCompleted {
        operation: OperationId,
        result: Result<ExportOutcome, String>,
    },
}

fn worker_loop(
    commands: Receiver<WorkerCommand>,
    events: SyncSender<WorkerEvent>,
    repaint: eframe::egui::Context,
    shutdown: Arc<AtomicBool>,
) {
    let services = AppServices::default();
    while !shutdown.load(Ordering::Acquire) {
        let Ok(command) = commands.recv() else {
            break;
        };
        if shutdown.load(Ordering::Acquire) || matches!(&command, WorkerCommand::Shutdown) {
            break;
        }

        let event = match command {
            WorkerCommand::Analyze { operation, path } => WorkerEvent::ProjectOpened {
                operation,
                result: services
                    .analyze_binary(&path)
                    .map_err(|error| error.to_string())
                    .and_then(|snapshot| {
                        LoadedProject::from_snapshot(snapshot).map_err(|error| error.to_string())
                    }),
            },
            WorkerCommand::OpenPackage { operation, path } => WorkerEvent::ProjectOpened {
                operation,
                result: services
                    .open_package(&path)
                    .map_err(|error| error.to_string())
                    .and_then(|snapshot| {
                        LoadedProject::from_snapshot(snapshot).map_err(|error| error.to_string())
                    }),
            },
            WorkerCommand::VerifySource {
                operation,
                project,
                path,
            } => WorkerEvent::SourceVerified {
                operation,
                result: services
                    .verify_source_binary(&project, &path)
                    .map_err(|error| error.to_string())
                    .and_then(|snapshot| {
                        LoadedProject::from_snapshot(snapshot).map_err(|error| error.to_string())
                    }),
            },
            WorkerCommand::Export {
                operation,
                project,
                kind,
                path,
            } => {
                let result = match kind {
                    WorkerExportKind::Package => services
                        .save_package_new(&project, &path)
                        .map_err(|error| error.to_string()),
                    WorkerExportKind::Service(format) => {
                        ReviewLedger::for_session(project.session())
                            .map_err(|error| error.to_string())
                            .and_then(|reviews| {
                                services
                                    .prepare_export(&project, &reviews, format)
                                    .map_err(|error| error.to_string())
                            })
                            .and_then(|prepared| {
                                services
                                    .publish_export_new(&prepared, &path)
                                    .map_err(|error| error.to_string())
                            })
                    }
                }
                .map(|()| ExportOutcome { kind, path });
                WorkerEvent::ExportCompleted { operation, result }
            }
            WorkerCommand::Shutdown => break,
        };
        if events.send(event).is_err() {
            break;
        }
        repaint.request_repaint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_gate_rejects_stale_results_without_clearing_the_current_request() {
        let mut sequence = OperationSequence::default();
        let first = sequence.issue();
        let second = sequence.issue();
        let mut gate = OperationGate::default();

        gate.begin(first);
        gate.begin(second);

        assert!(!gate.finish(first));
        assert!(gate.is_pending());
        assert!(gate.finish(second));
        assert!(!gate.is_pending());
    }

    #[test]
    fn operation_ids_are_nonzero_and_monotonic() {
        let mut sequence = OperationSequence::default();
        let first = sequence.issue();
        let second = sequence.issue();

        assert_ne!(first.get(), 0);
        assert!(second > first);
    }
}
