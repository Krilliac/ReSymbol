use std::{
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender},
    },
    thread,
};

use resymbol_app::{
    AppServices, ExportFormat, PluginCatalog, PreparedExport, ProjectSnapshot, ReviewLedger,
};

/// Long-running application-service work never runs on egui's render thread.
pub struct ServiceWorker {
    commands: Sender<WorkerCommand>,
    events: Receiver<WorkerEvent>,
}

impl ServiceWorker {
    pub fn start(repaint: eframe::egui::Context) -> Self {
        let (commands, command_rx) = mpsc::channel();
        let (event_tx, events) = mpsc::channel();
        thread::Builder::new()
            .name("resymbol-app-services".to_owned())
            .spawn(move || worker_loop(command_rx, event_tx, repaint))
            .expect("the application-service worker thread must start");
        Self { commands, events }
    }

    pub fn send(&self, command: WorkerCommand) -> Result<(), String> {
        self.commands
            .send(command)
            .map_err(|_| "the application-service worker stopped unexpectedly".to_owned())
    }

    pub fn try_recv(&self) -> Option<WorkerEvent> {
        self.events.try_recv().ok()
    }
}

impl Drop for ServiceWorker {
    fn drop(&mut self) {
        let _ = self.commands.send(WorkerCommand::Shutdown);
    }
}

pub enum WorkerCommand {
    Analyze(PathBuf),
    OpenPackage(PathBuf),
    VerifySource {
        project: Arc<ProjectSnapshot>,
        path: PathBuf,
    },
    DiscoverPlugins {
        root: PathBuf,
        safe_mode: bool,
    },
    SavePackage {
        project: Arc<ProjectSnapshot>,
        path: PathBuf,
    },
    LoadReview {
        project: Arc<ProjectSnapshot>,
        path: PathBuf,
    },
    SaveReview {
        ledger: ReviewLedger,
        path: PathBuf,
        revision: u64,
    },
    PrepareExport {
        project: Arc<ProjectSnapshot>,
        ledger: ReviewLedger,
        format: ExportFormat,
    },
    PublishExport {
        prepared: Arc<PreparedExport>,
        path: PathBuf,
    },
    Shutdown,
}

pub enum WorkerEvent {
    ProjectOpened(Result<Arc<ProjectSnapshot>, String>),
    SourceVerified(Result<Arc<ProjectSnapshot>, String>),
    PluginsDiscovered(Result<PluginCatalog, String>),
    PackageSaved(Result<PathBuf, String>),
    ReviewLoaded(Result<(ReviewLedger, PathBuf), String>),
    ReviewSaved(Result<(PathBuf, u64), String>),
    ExportPrepared(Result<PreparedExport, String>),
    ExportPublished(Result<PathBuf, String>),
}

fn worker_loop(
    commands: Receiver<WorkerCommand>,
    events: Sender<WorkerEvent>,
    repaint: eframe::egui::Context,
) {
    let services = AppServices::default();
    while let Ok(command) = commands.recv() {
        let event = match command {
            WorkerCommand::Analyze(path) => WorkerEvent::ProjectOpened(
                services
                    .analyze_binary(&path)
                    .map_err(|error| error.to_string()),
            ),
            WorkerCommand::OpenPackage(path) => WorkerEvent::ProjectOpened(
                services
                    .open_package(&path)
                    .map_err(|error| error.to_string()),
            ),
            WorkerCommand::VerifySource { project, path } => WorkerEvent::SourceVerified(
                services
                    .verify_source_binary(&project, &path)
                    .map_err(|error| error.to_string()),
            ),
            WorkerCommand::DiscoverPlugins { root, safe_mode } => WorkerEvent::PluginsDiscovered(
                services
                    .discover_plugins(&root, safe_mode)
                    .map_err(|error| error.to_string()),
            ),
            WorkerCommand::SavePackage { project, path } => {
                let result = services
                    .save_package_new(&project, &path)
                    .map(|()| path)
                    .map_err(|error| error.to_string());
                WorkerEvent::PackageSaved(result)
            }
            WorkerCommand::LoadReview { project, path } => {
                let result = ReviewLedger::load_for_session(&path, project.session())
                    .map(|ledger| (ledger, path))
                    .map_err(|error| error.to_string());
                WorkerEvent::ReviewLoaded(result)
            }
            WorkerCommand::SaveReview {
                ledger,
                path,
                revision,
            } => {
                let result = ledger
                    .save_atomic(&path)
                    .map(|()| (path, revision))
                    .map_err(|error| error.to_string());
                WorkerEvent::ReviewSaved(result)
            }
            WorkerCommand::PrepareExport {
                project,
                ledger,
                format,
            } => WorkerEvent::ExportPrepared(
                services
                    .prepare_export(&project, &ledger, format)
                    .map_err(|error| error.to_string()),
            ),
            WorkerCommand::PublishExport { prepared, path } => {
                let result = services
                    .publish_export_new(&prepared, &path)
                    .map(|()| path)
                    .map_err(|error| error.to_string());
                WorkerEvent::ExportPublished(result)
            }
            WorkerCommand::Shutdown => break,
        };
        if events.send(event).is_err() {
            break;
        }
        repaint.request_repaint();
    }
}
