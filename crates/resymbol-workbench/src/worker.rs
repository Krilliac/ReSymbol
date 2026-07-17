use std::{
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
};

use resymbol_app::{
    AppServices, ExportFormat, PluginCatalog, ProjectSnapshot, PublishedStaticPatch, ReviewLedger,
    StaticPatchEditRequest, StaticPatchPlan, StaticPatchSetManifest,
};
use resymbol_core::BinaryIdentity;
use resymbol_debugger::{
    CapabilityAvailability, ClientConnectionState, CommandOutcome, DebugCapability, DebugCommand,
    DebugEvent, DebugHostClient, DebugTargetRequest, HelperBuildId, MemoryAddress,
    OfflineImageDebugHost, ProvisioningEpoch, ReadViewToken, SandboxProviderProbeBackend,
    SandboxProviderReadinessService, SessionId, SessionState, SessionStateKind,
    SystemSandboxProviderProbe, VerifiedOfflineImage,
};
use thiserror::Error;

use crate::{
    model::LoadedProject,
    readiness::{DebuggerReadinessEvidence, DebuggerReadinessOutcome, SandboxProviderChoice},
};

const COMMAND_QUEUE_CAPACITY: usize = 4;
const EVENT_QUEUE_CAPACITY: usize = COMMAND_QUEUE_CAPACITY + 1;
/// Maximum byte count accepted from one UI-triggered offline image read.
pub const MAX_OFFLINE_IMAGE_UI_READ_BYTES: u32 = 256;
/// Maximum retained diagnostic size for an unavailable offline image span.
pub const MAX_OFFLINE_IMAGE_UNAVAILABLE_DETAIL_BYTES: usize = 1024;
/// Maximum printable diagnostic retained for a worker pipeline failure.
pub const MAX_OFFLINE_IMAGE_PIPELINE_DETAIL_BYTES: usize = 1024;

const OFFLINE_RANGE_UNAVAILABLE_CODE: &str = "offline-range-unavailable";
const OFFLINE_CONTROLLER_BUILD: &str = "resymbol-workbench-offline-controller";
const OFFLINE_HOST_BUILD: &str = "resymbol-workbench-offline-host";
const OFFLINE_HELPER_BUILD: &str = "resymbol-workbench-offline-helper";

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

/// Mutating file-publication domains that share one exclusive reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationKind {
    Export,
    StaticPatch,
    PatchSet,
}

impl PublicationKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Export => "export",
            Self::StaticPatch => "static patch",
            Self::PatchSet => "patch-set save",
        }
    }
}

/// Canonical parent plus final create-new filename reserved by the UI loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationDestination {
    canonical_path: PathBuf,
}

impl PublicationDestination {
    pub fn resolve(path: &Path) -> Result<Self, PublicationReservationError> {
        let file_name =
            path.file_name()
                .ok_or_else(|| PublicationReservationError::InvalidDestination {
                    path: path.to_path_buf(),
                })?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let canonical_parent = fs::canonicalize(parent).map_err(|source| {
            PublicationReservationError::ResolveParent {
                path: path.to_path_buf(),
                source,
            }
        })?;
        Ok(Self {
            canonical_path: canonical_parent.join(file_name),
        })
    }

    #[cfg(test)]
    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    fn refers_to_same_destination(&self, other: &Self) -> bool {
        #[cfg(windows)]
        {
            let left = self.canonical_path.to_string_lossy();
            let right = other.canonical_path.to_string_lossy();
            left.eq_ignore_ascii_case(right.as_ref())
        }
        #[cfg(not(windows))]
        {
            self.canonical_path == other.canonical_path
        }
    }
}

#[derive(Debug, Error)]
pub enum PublicationReservationError {
    #[error("publication destination `{path}` does not name a file")]
    InvalidDestination { path: PathBuf },
    #[error("cannot resolve publication destination parent for `{path}`: {source}")]
    ResolveParent {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "{requested_kind} publication cannot use `{destination}` because the current {active_kind} publication already reserves that destination"
    )]
    DestinationReserved {
        requested_kind: &'static str,
        active_kind: &'static str,
        destination: PathBuf,
    },
    #[error(
        "wait for the current {active_kind} publication to `{destination}` before starting a {requested_kind} publication"
    )]
    PublicationBusy {
        requested_kind: &'static str,
        active_kind: &'static str,
        destination: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicationReservation {
    operation: OperationId,
    kind: PublicationKind,
    destination: PublicationDestination,
}

/// One exclusive, canonical destination reservation for every mutating export.
#[derive(Debug, Default)]
pub struct PublicationGate {
    current: Option<PublicationReservation>,
}

impl PublicationGate {
    pub fn begin(
        &mut self,
        operation: OperationId,
        kind: PublicationKind,
        destination: PublicationDestination,
    ) -> Result<(), PublicationReservationError> {
        if let Some(current) = &self.current {
            let error = if current.destination.refers_to_same_destination(&destination) {
                PublicationReservationError::DestinationReserved {
                    requested_kind: kind.label(),
                    active_kind: current.kind.label(),
                    destination: current.destination.canonical_path.clone(),
                }
            } else {
                PublicationReservationError::PublicationBusy {
                    requested_kind: kind.label(),
                    active_kind: current.kind.label(),
                    destination: current.destination.canonical_path.clone(),
                }
            };
            return Err(error);
        }
        self.current = Some(PublicationReservation {
            operation,
            kind,
            destination,
        });
        Ok(())
    }

    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.current.is_some()
    }

    #[must_use]
    pub fn is_kind(&self, kind: PublicationKind) -> bool {
        self.current
            .as_ref()
            .is_some_and(|current| current.kind == kind)
    }

    #[must_use]
    pub fn kind(&self) -> Option<PublicationKind> {
        self.current.as_ref().map(|current| current.kind)
    }

    #[cfg(test)]
    #[must_use]
    pub fn destination(&self) -> Option<&Path> {
        self.current
            .as_ref()
            .map(|current| current.destination.canonical_path())
    }

    /// Complete only the current operation in its exact publication domain.
    pub fn finish(&mut self, operation: OperationId, kind: PublicationKind) -> bool {
        if !self
            .current
            .as_ref()
            .is_some_and(|current| current.operation == operation && current.kind == kind)
        {
            return false;
        }
        self.current = None;
        true
    }

    pub fn invalidate(&mut self) -> Option<PublicationKind> {
        self.current.take().map(|current| current.kind)
    }
}

/// Export jobs available to the current workbench.
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

/// Validated patch-set document completed by the application-service worker.
#[derive(Debug)]
pub struct PatchSetOutcome {
    pub path: PathBuf,
    pub manifest: StaticPatchSetManifest,
}

/// Exact ledger snapshot and destination completed by one save operation.
#[derive(Debug)]
pub struct ReviewSaveOutcome {
    pub ledger: ReviewLedger,
    pub path: PathBuf,
}

/// A strictly loaded ledger and the reviewed model derived from that same
/// immutable project snapshot on the service worker.
#[derive(Debug)]
pub struct ReviewLoadOutcome {
    pub ledger: ReviewLedger,
    pub path: PathBuf,
    pub project: LoadedProject,
    pub orphaned_decisions: usize,
}

#[derive(Debug)]
pub struct ReviewApplyOutcome {
    pub project: LoadedProject,
    pub orphaned_decisions: usize,
}

/// Exact immutable project identity and canonical source bound to one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineImageBinding {
    identity: BinaryIdentity,
    source_path: PathBuf,
}

impl OfflineImageBinding {
    #[must_use]
    pub const fn identity(&self) -> &BinaryIdentity {
        &self.identity
    }

    #[must_use]
    pub fn source_path(&self) -> &std::path::Path {
        &self.source_path
    }
}

/// Validated image-relative read span accepted by the worker boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineImageReadSpan {
    rva: u64,
    size: u32,
}

impl OfflineImageReadSpan {
    pub fn new(rva: u64, size: u32) -> Result<Self, OfflineImageReadFailure> {
        if size == 0 || size > MAX_OFFLINE_IMAGE_UI_READ_BYTES {
            return Err(OfflineImageReadFailure::InvalidSize {
                actual: size,
                maximum: MAX_OFFLINE_IMAGE_UI_READ_BYTES,
            });
        }
        let _ = rva
            .checked_add(u64::from(size))
            .ok_or(OfflineImageReadFailure::AddressOverflow { rva, size })?;
        Ok(Self { rva, size })
    }

    #[must_use]
    pub const fn rva(self) -> u64 {
        self.rva
    }

    #[must_use]
    pub const fn size(self) -> u32 {
        self.size
    }
}

/// Bounded typed evidence explaining why an exact static span was unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineImageReadUnavailable {
    detail: String,
}

impl OfflineImageReadUnavailable {
    fn from_validated_host_rejection(detail: String) -> Result<Self, OfflineImageReadFailure> {
        if detail.is_empty()
            || detail.len() > MAX_OFFLINE_IMAGE_UNAVAILABLE_DETAIL_BYTES
            || detail.chars().any(char::is_control)
        {
            return Err(OfflineImageReadFailure::pipeline(
                "read response validation",
                "offline range rejection carried an invalid diagnostic",
            ));
        }
        Ok(Self { detail })
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        OFFLINE_RANGE_UNAVAILABLE_CODE
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Exact bounded result of one requested RVA span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineImageReadAvailability {
    Available { bytes: Vec<u8> },
    Unavailable(OfflineImageReadUnavailable),
}

impl OfflineImageReadAvailability {
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Available { bytes } => Some(bytes),
            Self::Unavailable(_) => None,
        }
    }
}

/// Observable receipt for the one-shot non-executing host lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineImageLifecycleReceipt {
    session_id: SessionId,
    capability_count: usize,
    session_opened: bool,
    session_closed: bool,
    session_released: bool,
    control_disconnected: bool,
}

impl OfflineImageLifecycleReceipt {
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn capability_count(self) -> usize {
        self.capability_count
    }

    #[must_use]
    pub const fn session_opened(self) -> bool {
        self.session_opened
    }

    #[must_use]
    pub const fn session_closed(self) -> bool {
        self.session_closed
    }

    #[must_use]
    pub const fn session_released(self) -> bool {
        self.session_released
    }

    #[must_use]
    pub const fn control_disconnected(self) -> bool {
        self.control_disconnected
    }

    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.session_opened
            && self.session_closed
            && self.session_released
            && self.control_disconnected
    }
}

/// Worker-owned evidence for one exact offline image byte request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineImageReadOutcome {
    binding: OfflineImageBinding,
    span: OfflineImageReadSpan,
    availability: OfflineImageReadAvailability,
    lifecycle: OfflineImageLifecycleReceipt,
}

impl OfflineImageReadOutcome {
    #[must_use]
    pub const fn binding(&self) -> &OfflineImageBinding {
        &self.binding
    }

    #[must_use]
    pub const fn span(&self) -> OfflineImageReadSpan {
        self.span
    }

    #[must_use]
    pub const fn availability(&self) -> &OfflineImageReadAvailability {
        &self.availability
    }

    #[must_use]
    pub const fn lifecycle(&self) -> OfflineImageLifecycleReceipt {
        self.lifecycle
    }
}

/// Failures that prevent an exact one-shot offline read from producing evidence.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OfflineImageReadFailure {
    #[error("the project has no exact identity-verified source snapshot")]
    VerifiedSourceRequired,
    #[error("the project source path and retained source snapshot disagree")]
    VerifiedSourceInvariant,
    #[error("offline image read size {actual} must be between 1 and {maximum} bytes")]
    InvalidSize { actual: u32, maximum: u32 },
    #[error("offline image read at RVA {rva:#x} with size {size} overflows the address space")]
    AddressOverflow { rva: u64, size: u32 },
    #[error("operating-system entropy was unavailable for the offline debugger session")]
    EntropyUnavailable,
    #[error("{0}")]
    Pipeline(OfflineImagePipelineFailure),
}

impl OfflineImageReadFailure {
    fn pipeline(stage: &'static str, error: impl std::fmt::Display) -> Self {
        Self::Pipeline(OfflineImagePipelineFailure {
            stage,
            detail: bounded_pipeline_detail(error.to_string()),
        })
    }
}

/// Bounded printable failure evidence safe for direct workbench display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineImagePipelineFailure {
    stage: &'static str,
    detail: String,
}

impl OfflineImagePipelineFailure {
    #[must_use]
    pub const fn stage(&self) -> &'static str {
        self.stage
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for OfflineImagePipelineFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "offline image pipeline failed during {}: {}",
            self.stage, self.detail
        )
    }
}

fn bounded_pipeline_detail(detail: String) -> String {
    let mut bounded =
        String::with_capacity(detail.len().min(MAX_OFFLINE_IMAGE_PIPELINE_DETAIL_BYTES));
    for character in detail.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if bounded.len() + character.len_utf8() > MAX_OFFLINE_IMAGE_PIPELINE_DETAIL_BYTES {
            break;
        }
        bounded.push(character);
    }
    let bounded = bounded.trim();
    if bounded.is_empty() {
        "offline image pipeline returned no printable diagnostic".to_owned()
    } else {
        bounded.to_owned()
    }
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
        reviews: ReviewLedger,
        path: PathBuf,
    },
    Export {
        operation: OperationId,
        project: Arc<ProjectSnapshot>,
        reviews: ReviewLedger,
        kind: WorkerExportKind,
        path: PathBuf,
    },
    SaveReview {
        operation: OperationId,
        ledger: ReviewLedger,
        path: PathBuf,
    },
    ApplyReview {
        operation: OperationId,
        project: Arc<ProjectSnapshot>,
        ledger: ReviewLedger,
    },
    LoadReview {
        operation: OperationId,
        project: Arc<ProjectSnapshot>,
        path: PathBuf,
    },
    /// Refresh the presentation-only plugin catalog without loading or executing plugins.
    RefreshPluginCatalog {
        operation: OperationId,
        root: PathBuf,
    },
    ProbeSandboxProvider {
        operation: OperationId,
        evidence: DebuggerReadinessEvidence,
        choice: SandboxProviderChoice,
    },
    /// Read one exact file-backed RVA span through the non-executing host path.
    ReadOfflineImage {
        operation: OperationId,
        project: Arc<ProjectSnapshot>,
        rva: u64,
        size: u32,
    },
    /// Validate and create-new publish exact static edits away from the UI thread.
    PublishStaticPatch {
        operation: OperationId,
        project: Arc<ProjectSnapshot>,
        requests: Vec<StaticPatchEditRequest>,
        path: PathBuf,
    },
    /// Validate and create-new save a portable static patch set.
    SaveStaticPatchSet {
        operation: OperationId,
        project: Arc<ProjectSnapshot>,
        requests: Vec<StaticPatchEditRequest>,
        path: PathBuf,
    },
    /// Bounded-load and validate a portable static patch set.
    LoadStaticPatchSet {
        operation: OperationId,
        project: Arc<ProjectSnapshot>,
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
    ReviewSaved {
        operation: OperationId,
        result: Result<ReviewSaveOutcome, String>,
    },
    ReviewApplied {
        operation: OperationId,
        ledger: ReviewLedger,
        result: Result<ReviewApplyOutcome, String>,
    },
    ReviewLoaded {
        operation: OperationId,
        result: Result<ReviewLoadOutcome, String>,
    },
    PluginCatalogRefreshed {
        operation: OperationId,
        result: Result<PluginCatalog, String>,
    },
    SandboxProviderProbed {
        operation: OperationId,
        result: Result<DebuggerReadinessOutcome, String>,
    },
    OfflineImageRead {
        operation: OperationId,
        result: Result<OfflineImageReadOutcome, OfflineImageReadFailure>,
    },
    StaticPatchPublished {
        operation: OperationId,
        result: Result<PublishedStaticPatch, String>,
    },
    StaticPatchSetSaved {
        operation: OperationId,
        result: Result<PatchSetOutcome, String>,
    },
    StaticPatchSetLoaded {
        operation: OperationId,
        result: Result<PatchSetOutcome, String>,
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

        let Some(event) = process_command(&services, command) else {
            break;
        };
        if events.send(event).is_err() {
            break;
        }
        repaint.request_repaint();
    }
}

fn process_command(services: &AppServices, command: WorkerCommand) -> Option<WorkerEvent> {
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
            reviews,
            path,
        } => WorkerEvent::SourceVerified {
            operation,
            result: services
                .verify_source_binary(&project, &path)
                .map_err(|error| error.to_string())
                .and_then(|snapshot| {
                    let projection = snapshot
                        .reviewed_projection(&reviews)
                        .map_err(|error| error.to_string())?;
                    LoadedProject::from_snapshot_with_projection(snapshot, projection)
                        .map_err(|error| error.to_string())
                }),
        },
        WorkerCommand::Export {
            operation,
            project,
            reviews,
            kind,
            path,
        } => {
            let result = match kind {
                WorkerExportKind::Package => services
                    .save_package_new(&project, &path)
                    .map_err(|error| error.to_string()),
                WorkerExportKind::Service(format) => services
                    .prepare_export(&project, &reviews, format)
                    .map_err(|error| error.to_string())
                    .and_then(|prepared| {
                        services
                            .publish_export_new(&prepared, &path)
                            .map_err(|error| error.to_string())
                    }),
            }
            .map(|()| ExportOutcome { kind, path });
            WorkerEvent::ExportCompleted { operation, result }
        }
        WorkerCommand::SaveReview {
            operation,
            ledger,
            path,
        } => WorkerEvent::ReviewSaved {
            operation,
            result: ledger
                .save_new(&path)
                .map_err(|error| error.to_string())
                .map(|()| ReviewSaveOutcome { ledger, path }),
        },
        WorkerCommand::ApplyReview {
            operation,
            project,
            ledger,
        } => {
            let result = apply_reviews(project, &ledger);
            WorkerEvent::ReviewApplied {
                operation,
                ledger,
                result,
            }
        }
        WorkerCommand::LoadReview {
            operation,
            project,
            path,
        } => WorkerEvent::ReviewLoaded {
            operation,
            result: ReviewLedger::load_for_session(&path, project.session())
                .map_err(|error| error.to_string())
                .and_then(|ledger| {
                    let reviewed = apply_reviews(project, &ledger)?;
                    Ok(ReviewLoadOutcome {
                        ledger,
                        path,
                        project: reviewed.project,
                        orphaned_decisions: reviewed.orphaned_decisions,
                    })
                }),
        },
        WorkerCommand::RefreshPluginCatalog { operation, root } => {
            WorkerEvent::PluginCatalogRefreshed {
                operation,
                result: services
                    .inspect_plugin_catalog(root)
                    .map_err(|error| error.to_string()),
            }
        }
        WorkerCommand::ProbeSandboxProvider {
            operation,
            evidence,
            choice,
        } => {
            process_sandbox_provider_probe(operation, evidence, choice, SystemSandboxProviderProbe)
        }
        WorkerCommand::ReadOfflineImage {
            operation,
            project,
            rva,
            size,
        } => WorkerEvent::OfflineImageRead {
            operation,
            result: read_offline_image(project, rva, size),
        },
        WorkerCommand::PublishStaticPatch {
            operation,
            project,
            requests,
            path,
        } => {
            let result = StaticPatchPlan::new(
                project.session().base_analysis().identity(),
                project.session().base_analysis(),
                requests,
            )
            .map_err(|error| error.to_string())
            .and_then(|plan| {
                services
                    .publish_static_patch_new(&project, &plan, &path)
                    .map_err(|error| error.to_string())
            });
            WorkerEvent::StaticPatchPublished { operation, result }
        }
        WorkerCommand::SaveStaticPatchSet {
            operation,
            project,
            requests,
            path,
        } => WorkerEvent::StaticPatchSetSaved {
            operation,
            result: services
                .save_static_patch_set_new(&project, requests, &path)
                .map(|manifest| PatchSetOutcome { path, manifest })
                .map_err(|error| error.to_string()),
        },
        WorkerCommand::LoadStaticPatchSet {
            operation,
            project,
            path,
        } => WorkerEvent::StaticPatchSetLoaded {
            operation,
            result: services
                .load_static_patch_set(&project, &path)
                .map(|manifest| PatchSetOutcome { path, manifest })
                .map_err(|error| error.to_string()),
        },
        WorkerCommand::Shutdown => return None,
    };
    Some(event)
}

fn process_sandbox_provider_probe<B>(
    operation: OperationId,
    evidence: DebuggerReadinessEvidence,
    choice: SandboxProviderChoice,
    backend: B,
) -> WorkerEvent
where
    B: SandboxProviderProbeBackend,
{
    let result = choice
        .probe_request()
        .map_err(|error| error.to_string())
        .and_then(|request| {
            let report = SandboxProviderReadinessService::new(backend).probe(&request);
            DebuggerReadinessOutcome::new(evidence, choice, report)
                .map_err(|error| error.to_string())
        });
    WorkerEvent::SandboxProviderProbed { operation, result }
}

/// Runs entirely on the application-service worker. The client is deliberately
/// created and destroyed in this call because it is thread-affine and because
/// an offline byte request must not leave session or transport ownership behind.
fn read_offline_image(
    project: Arc<ProjectSnapshot>,
    rva: u64,
    size: u32,
) -> Result<OfflineImageReadOutcome, OfflineImageReadFailure> {
    let span = OfflineImageReadSpan::new(rva, size)?;
    let (source_path, source_bytes) = match (
        project.verified_source_path(),
        project.verified_source_bytes_arc(),
    ) {
        (Some(path), Some(bytes)) => (path.to_path_buf(), bytes),
        (None, None) => return Err(OfflineImageReadFailure::VerifiedSourceRequired),
        _ => return Err(OfflineImageReadFailure::VerifiedSourceInvariant),
    };
    let expected_identity = project.session().base_analysis().identity().clone();
    let image = VerifiedOfflineImage::from_snapshot(&source_path, expected_identity, source_bytes)
        .map_err(|error| OfflineImageReadFailure::pipeline("image verification", error))?;
    let binding = OfflineImageBinding {
        identity: image.identity().clone(),
        source_path: image.origin_path().to_path_buf(),
    };
    let target = image.target();

    let entropy = OfflineSessionEntropy::generate()?;
    let helper_build = HelperBuildId::new(OFFLINE_HELPER_BUILD)
        .map_err(|error| OfflineImageReadFailure::pipeline("host identity", error))?;
    let host = OfflineImageDebugHost::new(
        image,
        OFFLINE_HOST_BUILD,
        OFFLINE_CONTROLLER_BUILD,
        entropy.provisioning_epoch.clone(),
        helper_build.clone(),
    )
    .map_err(|error| OfflineImageReadFailure::pipeline("host construction", error))?;
    let mut client = DebugHostClient::connect(
        host,
        entropy.handshake_nonce,
        OFFLINE_CONTROLLER_BUILD,
        OFFLINE_HOST_BUILD,
    )
    .map_err(|error| OfflineImageReadFailure::pipeline("host connection", error))?;

    let capabilities = client
        .probe_capabilities()
        .map_err(|error| OfflineImageReadFailure::pipeline("capability probe", error))?;
    verify_offline_only_capabilities(&capabilities.statuses)?;
    let capability_count = capabilities.statuses.len();

    client
        .begin_session(entropy.session_id, entropy.provisioning_epoch, helper_build)
        .map_err(|error| OfflineImageReadFailure::pipeline("session begin", error))?;
    let open = client
        .submit(DebugCommand::Open(DebugTargetRequest::Offline(target)))
        .map_err(|error| OfflineImageReadFailure::pipeline("offline open", error))?;
    require_succeeded("offline open", &open.outcome)?;
    let SessionState::Offline { token } = client.session_state().ok_or_else(|| {
        OfflineImageReadFailure::pipeline("offline open", "host omitted the opened session state")
    })?
    else {
        return Err(OfflineImageReadFailure::pipeline(
            "offline open",
            "host did not enter the offline state",
        ));
    };
    let read_view = ReadViewToken::Offline { state: *token };
    let read = client
        .submit(DebugCommand::ReadMemory {
            view: read_view,
            address: MemoryAddress::new(span.rva()),
            size: span.size(),
        })
        .map_err(|error| OfflineImageReadFailure::pipeline("offline read", error))?;
    let availability = exact_read_availability(read, read_view, span)?;

    let close_state = client
        .session_state()
        .ok_or_else(|| {
            OfflineImageReadFailure::pipeline("session close", "host omitted session state")
        })?
        .state_token();
    let close = client
        .submit(DebugCommand::Close { state: close_state })
        .map_err(|error| OfflineImageReadFailure::pipeline("session close", error))?;
    require_succeeded("session close", &close.outcome)?;
    if client.session_state().map(SessionState::kind) != Some(SessionStateKind::Closed) {
        return Err(OfflineImageReadFailure::pipeline(
            "session close",
            "host did not enter the closed state",
        ));
    }
    client
        .release_closed_session()
        .map_err(|error| OfflineImageReadFailure::pipeline("session release", error))?;
    client
        .disconnect()
        .map_err(|error| OfflineImageReadFailure::pipeline("control disconnect", error))?;
    if client.connection_state() != ClientConnectionState::Disconnected {
        return Err(OfflineImageReadFailure::pipeline(
            "control disconnect",
            "client did not confirm the disconnected state",
        ));
    }

    Ok(OfflineImageReadOutcome {
        binding,
        span,
        availability,
        lifecycle: OfflineImageLifecycleReceipt {
            session_id: entropy.session_id,
            capability_count,
            session_opened: true,
            session_closed: true,
            session_released: true,
            control_disconnected: true,
        },
    })
}

fn verify_offline_only_capabilities(
    statuses: &[resymbol_debugger::CapabilityStatus],
) -> Result<(), OfflineImageReadFailure> {
    if statuses.len() != DebugCapability::ALL.len() {
        return Err(OfflineImageReadFailure::pipeline(
            "capability boundary",
            "offline host did not report the complete capability set",
        ));
    }
    for capability in DebugCapability::ALL {
        let status = statuses
            .iter()
            .find(|status| status.capability == capability)
            .ok_or_else(|| {
                OfflineImageReadFailure::pipeline(
                    "capability boundary",
                    format!("offline host omitted {capability:?}"),
                )
            })?;
        let exact = match capability {
            DebugCapability::OfflineAnalysis => {
                matches!(&status.availability, CapabilityAvailability::Available)
            }
            _ => matches!(
                &status.availability,
                CapabilityAvailability::Unavailable { .. }
            ),
        };
        if !exact {
            return Err(OfflineImageReadFailure::pipeline(
                "capability boundary",
                format!("offline host advertised an invalid {capability:?} capability"),
            ));
        }
    }
    Ok(())
}

fn require_succeeded(
    stage: &'static str,
    outcome: &CommandOutcome,
) -> Result<(), OfflineImageReadFailure> {
    match outcome {
        CommandOutcome::Succeeded => Ok(()),
        CommandOutcome::Rejected { code, message } => Err(OfflineImageReadFailure::pipeline(
            stage,
            format!("host rejected the command ({code}): {message}"),
        )),
    }
}

fn exact_read_availability(
    receipt: resymbol_debugger::CommandReceipt,
    expected_view: ReadViewToken,
    span: OfflineImageReadSpan,
) -> Result<OfflineImageReadAvailability, OfflineImageReadFailure> {
    match receipt.outcome {
        CommandOutcome::Succeeded => {
            let mut exact_bytes = None;
            for envelope in receipt.events {
                if let DebugEvent::MemoryRead {
                    view,
                    address,
                    bytes,
                } = envelope.event
                {
                    if view != expected_view
                        || address != MemoryAddress::new(span.rva())
                        || bytes.len() != span.size() as usize
                        || exact_bytes.replace(bytes).is_some()
                    {
                        return Err(OfflineImageReadFailure::pipeline(
                            "read response validation",
                            "host returned memory evidence outside the exact requested span",
                        ));
                    }
                }
            }
            let bytes = exact_bytes.ok_or_else(|| {
                OfflineImageReadFailure::pipeline(
                    "read response validation",
                    "host succeeded without exact memory evidence",
                )
            })?;
            Ok(OfflineImageReadAvailability::Available { bytes })
        }
        CommandOutcome::Rejected { code, message } if code == OFFLINE_RANGE_UNAVAILABLE_CODE => {
            if receipt
                .events
                .iter()
                .any(|event| matches!(&event.event, DebugEvent::MemoryRead { .. }))
            {
                return Err(OfflineImageReadFailure::pipeline(
                    "read response validation",
                    "rejected read carried memory evidence",
                ));
            }
            OfflineImageReadUnavailable::from_validated_host_rejection(message)
                .map(OfflineImageReadAvailability::Unavailable)
        }
        CommandOutcome::Rejected { code, message } => Err(OfflineImageReadFailure::pipeline(
            "offline read",
            format!("host rejected the command ({code}): {message}"),
        )),
    }
}

struct OfflineSessionEntropy {
    session_id: SessionId,
    handshake_nonce: [u8; 16],
    provisioning_epoch: ProvisioningEpoch,
}

impl OfflineSessionEntropy {
    fn generate() -> Result<Self, OfflineImageReadFailure> {
        let session_bytes = nonzero_random_bytes::<8>()?;
        let session_id = SessionId::new(u64::from_le_bytes(session_bytes))
            .map_err(|error| OfflineImageReadFailure::pipeline("session entropy", error))?;
        let handshake_nonce = nonzero_random_bytes::<16>()?;
        let epoch_bytes = nonzero_random_bytes::<32>()?;
        let mut epoch_hex = String::with_capacity(64);
        for byte in epoch_bytes {
            write!(&mut epoch_hex, "{byte:02x}").map_err(|error| {
                OfflineImageReadFailure::pipeline("provisioning epoch encoding", error)
            })?;
        }
        let provisioning_epoch = ProvisioningEpoch::new(epoch_hex).map_err(|error| {
            OfflineImageReadFailure::pipeline("provisioning epoch encoding", error)
        })?;
        Ok(Self {
            session_id,
            handshake_nonce,
            provisioning_epoch,
        })
    }
}

fn nonzero_random_bytes<const N: usize>() -> Result<[u8; N], OfflineImageReadFailure> {
    loop {
        let mut bytes = [0; N];
        getrandom::fill(&mut bytes).map_err(|_| OfflineImageReadFailure::EntropyUnavailable)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
}

fn apply_reviews(
    project: Arc<ProjectSnapshot>,
    ledger: &ReviewLedger,
) -> Result<ReviewApplyOutcome, String> {
    let orphaned_decisions = ledger
        .orphaned_decision_count(project.session())
        .map_err(|error| error.to_string())?;
    let projection = project
        .reviewed_projection(ledger)
        .map_err(|error| error.to_string())?;
    let project = LoadedProject::from_snapshot_with_projection(project, projection)
        .map_err(|error| error.to_string())?;
    Ok(ReviewApplyOutcome {
        project,
        orphaned_decisions,
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write as _};

    use resymbol_app::PluginArtifactPolicyStatus;
    use resymbol_core::{BinaryFormat, BinaryId, BinaryIdentity};
    use resymbol_debugger::{
        DiagnosticText, ProviderProbeObservation, SandboxProviderProbeRequest,
    };
    use tempfile::{NamedTempFile, tempdir};

    use super::*;

    const STRIPPED_FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");
    const SYMBOLIZED_FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-symbolized.exe");
    const THUNK_RVA: u32 = 0x1184;
    const THUNK_FILE_OFFSET: usize = 0x584;
    const THUNK_BYTES: [u8; 5] = [0xe9, 0x03, 0x00, 0x00, 0x00];

    fn project_snapshot() -> Arc<ProjectSnapshot> {
        let (_source, snapshot) = project_snapshot_with_source();
        snapshot
    }

    fn project_snapshot_with_source() -> (NamedTempFile, Arc<ProjectSnapshot>) {
        project_snapshot_with_bytes(STRIPPED_FIXTURE)
    }

    fn project_snapshot_with_bytes(bytes: &[u8]) -> (NamedTempFile, Arc<ProjectSnapshot>) {
        let mut source = NamedTempFile::new().expect("temporary PE");
        source.write_all(bytes).expect("write fixture PE");
        let snapshot = AppServices::default()
            .analyze_binary(source.path())
            .expect("analyze worker fixture");
        (source, snapshot)
    }

    #[test]
    fn plugin_catalog_refresh_runs_as_a_non_executing_worker_workflow() {
        let temporary = tempdir().expect("temporary plugin root");
        let plugin = temporary.path().join("worker-wasm");
        fs::create_dir(&plugin).expect("create plugin directory");
        fs::write(plugin.join("plugin.wasm"), b"not executable wasm").expect("write entrypoint");
        fs::write(
            plugin.join("plugin.toml"),
            r#"manifest_version = 1
id = "community.resymbol.worker-wasm"
name = "Worker WASM"
version = "1.0.0"
api = "^0.1"
capabilities = ["analyzer.binary"]
permissions = ["binary.read", "claims.submit"]

[runtime]
kind = "wasm"
entrypoint = "plugin.wasm"
"#,
        )
        .expect("write plugin manifest");
        let operation = OperationSequence::default().issue();

        let event = process_command(
            &AppServices::default(),
            WorkerCommand::RefreshPluginCatalog {
                operation,
                root: temporary.path().to_path_buf(),
            },
        )
        .expect("plugin catalog event");
        let WorkerEvent::PluginCatalogRefreshed {
            operation: actual,
            result,
        } = event
        else {
            panic!("unexpected worker event")
        };
        assert_eq!(actual, operation);
        let catalog = result.expect("worker catalog refresh");
        assert_eq!(catalog.entries().len(), 1);
        assert_eq!(
            catalog.entries()[0].artifact_policy,
            PluginArtifactPolicyStatus::Sandboxed
        );
        let entrypoint = fs::read(plugin.join("plugin.wasm")).expect("entrypoint unchanged");
        assert_eq!(entrypoint.as_slice(), b"not executable wasm");
    }

    fn offline_read(
        operation: OperationId,
        project: Arc<ProjectSnapshot>,
        rva: u64,
        size: u32,
    ) -> Result<OfflineImageReadOutcome, OfflineImageReadFailure> {
        match process_command(
            &AppServices::default(),
            WorkerCommand::ReadOfflineImage {
                operation,
                project,
                rva,
                size,
            },
        )
        .expect("offline read event")
        {
            WorkerEvent::OfflineImageRead {
                operation: actual,
                result,
            } => {
                assert_eq!(actual, operation);
                result
            }
            _ => panic!("unexpected worker event"),
        }
    }

    #[derive(Debug, Clone)]
    struct ExactFakeProbe;

    impl SandboxProviderProbeBackend for ExactFakeProbe {
        fn probe(&self, request: &SandboxProviderProbeRequest) -> ProviderProbeObservation {
            ProviderProbeObservation::ready(
                request.provider().clone(),
                request.required_boundary(),
                request.required_guarantees().clone(),
                DiagnosticText::new("Deterministic read-only test observation.")
                    .expect("bounded diagnostic"),
            )
            .expect("valid fake observation")
        }
    }

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
    fn publication_gate_exclusively_reserves_canonical_destinations_across_domains() {
        let directory = tempdir().expect("temporary publication directory");
        let export_destination =
            PublicationDestination::resolve(&directory.path().join(".").join("artifact.exe"))
                .expect("canonical export destination");
        let same_destination =
            PublicationDestination::resolve(&directory.path().join("artifact.exe"))
                .expect("canonical patch destination");
        let other_destination =
            PublicationDestination::resolve(&directory.path().join("other.exe"))
                .expect("other canonical destination");
        assert!(export_destination.refers_to_same_destination(&same_destination));

        let mut sequence = OperationSequence::default();
        let export = sequence.issue();
        let patch = sequence.issue();
        let mut gate = PublicationGate::default();
        gate.begin(export, PublicationKind::Export, export_destination)
            .expect("reserve export destination");

        assert!(matches!(
            gate.begin(patch, PublicationKind::StaticPatch, same_destination),
            Err(PublicationReservationError::DestinationReserved {
                requested_kind: "static patch",
                active_kind: "export",
                ..
            })
        ));
        assert!(matches!(
            gate.begin(patch, PublicationKind::StaticPatch, other_destination),
            Err(PublicationReservationError::PublicationBusy {
                requested_kind: "static patch",
                active_kind: "export",
                ..
            })
        ));
        assert!(!gate.finish(export, PublicationKind::StaticPatch));
        assert!(!gate.finish(patch, PublicationKind::Export));
        assert!(gate.is_pending());
        assert_eq!(gate.kind(), Some(PublicationKind::Export));
        assert!(gate.destination().is_some());
        assert!(gate.finish(export, PublicationKind::Export));
        assert!(!gate.is_pending());

        let patch = sequence.issue();
        let export = sequence.issue();
        let patch_destination =
            PublicationDestination::resolve(&directory.path().join("artifact.exe"))
                .expect("reverse patch destination");
        let export_destination =
            PublicationDestination::resolve(&directory.path().join(".").join("artifact.exe"))
                .expect("reverse export destination");
        gate.begin(patch, PublicationKind::StaticPatch, patch_destination)
            .expect("reserve patch destination");
        assert!(matches!(
            gate.begin(export, PublicationKind::Export, export_destination),
            Err(PublicationReservationError::DestinationReserved {
                requested_kind: "export",
                active_kind: "static patch",
                ..
            })
        ));
        assert!(gate.finish(patch, PublicationKind::StaticPatch));

        let patch_set = sequence.issue();
        let export = sequence.issue();
        let patch_set_destination =
            PublicationDestination::resolve(&directory.path().join("artifact.respatch.json"))
                .expect("patch-set destination");
        let same_destination = PublicationDestination::resolve(
            &directory.path().join(".").join("artifact.respatch.json"),
        )
        .expect("same patch-set destination");
        gate.begin(patch_set, PublicationKind::PatchSet, patch_set_destination)
            .expect("reserve patch-set publication");
        assert!(matches!(
            gate.begin(export, PublicationKind::Export, same_destination),
            Err(PublicationReservationError::DestinationReserved {
                requested_kind: "export",
                active_kind: "patch-set save",
                ..
            })
        ));
        assert!(gate.finish(patch_set, PublicationKind::PatchSet));
    }

    #[cfg(windows)]
    #[test]
    fn publication_destination_reservation_is_case_insensitive_on_windows() {
        let directory = tempdir().expect("temporary publication directory");
        let lowercase = PublicationDestination::resolve(&directory.path().join("artifact.exe"))
            .expect("lowercase destination");
        let uppercase = PublicationDestination::resolve(&directory.path().join("ARTIFACT.EXE"))
            .expect("uppercase destination");
        assert!(lowercase.refers_to_same_destination(&uppercase));
    }

    #[test]
    fn operation_ids_are_nonzero_and_monotonic() {
        let mut sequence = OperationSequence::default();
        let first = sequence.issue();
        let second = sequence.issue();

        assert_ne!(first.get(), 0);
        assert!(second > first);
    }

    #[test]
    fn worker_review_save_preserves_operation_id_and_refuses_clobber() {
        let identity = BinaryIdentity {
            id: BinaryId::digest(b"review-worker-fixture"),
            size: 21,
            format: BinaryFormat::Pe,
            architecture: "x86_64".to_owned(),
            image_base: 0x0001_4000_0000,
        };
        let ledger = ReviewLedger::new(&identity);
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("review.json");
        let mut sequence = OperationSequence::default();
        let first = sequence.issue();

        let event = process_command(
            &AppServices::default(),
            WorkerCommand::SaveReview {
                operation: first,
                ledger: ledger.clone(),
                path: path.clone(),
            },
        )
        .expect("save event");
        match event {
            WorkerEvent::ReviewSaved {
                operation,
                result: Ok(outcome),
            } => {
                assert_eq!(operation, first);
                assert_eq!(outcome.ledger, ledger);
                assert_eq!(outcome.path, path);
            }
            _ => panic!("unexpected worker event"),
        }

        let second = sequence.issue();
        let event = process_command(
            &AppServices::default(),
            WorkerCommand::SaveReview {
                operation: second,
                ledger,
                path,
            },
        )
        .expect("second save event");
        assert!(matches!(
            event,
            WorkerEvent::ReviewSaved {
                operation,
                result: Err(_),
            } if operation == second
        ));
    }

    #[test]
    fn worker_owns_checked_create_new_static_patch_publication() {
        let (source, project) = project_snapshot_with_bytes(SYMBOLIZED_FIXTURE);
        let directory = tempdir().expect("temporary patch directory");
        let path = directory.path().join("patched.exe");
        let request = || {
            StaticPatchEditRequest::nop_instruction(
                THUNK_RVA,
                THUNK_BYTES,
                "Disable internal jump thunk",
            )
            .expect("valid exact instruction request")
        };
        let mut sequence = OperationSequence::default();
        let first = sequence.issue();

        let event = process_command(
            &AppServices::default(),
            WorkerCommand::PublishStaticPatch {
                operation: first,
                project: Arc::clone(&project),
                requests: vec![request()],
                path: path.clone(),
            },
        )
        .expect("static patch event");
        match event {
            WorkerEvent::StaticPatchPublished {
                operation,
                result: Ok(outcome),
            } => {
                assert_eq!(operation, first);
                assert_eq!(outcome.path(), path);
                assert_eq!(
                    outcome.source_identity(),
                    project.session().base_analysis().identity()
                );
                assert_ne!(outcome.output_identity(), outcome.source_identity());
                assert_eq!(outcome.warnings().len(), 2);
            }
            _ => panic!("unexpected worker event"),
        }
        let patched = fs::read(&path).expect("read patched output");
        assert_eq!(
            &patched[THUNK_FILE_OFFSET..THUNK_FILE_OFFSET + THUNK_BYTES.len()],
            &[0x90; THUNK_BYTES.len()]
        );
        assert_eq!(
            fs::read(source.path()).expect("read unchanged source"),
            SYMBOLIZED_FIXTURE
        );

        let second = sequence.issue();
        let event = process_command(
            &AppServices::default(),
            WorkerCommand::PublishStaticPatch {
                operation: second,
                project,
                requests: vec![request()],
                path,
            },
        )
        .expect("second static patch event");
        assert!(matches!(
            event,
            WorkerEvent::StaticPatchPublished {
                operation,
                result: Err(_),
            } if operation == second
        ));
    }

    #[test]
    fn worker_owns_strict_patch_set_save_and_load_with_operation_ids() {
        let (_source, project) = project_snapshot_with_bytes(SYMBOLIZED_FIXTURE);
        let directory = tempdir().expect("temporary patch-set directory");
        let path = directory.path().join("worker.respatch.json");
        let request = || {
            StaticPatchEditRequest::nop_instruction(
                THUNK_RVA,
                THUNK_BYTES,
                "Disable internal jump thunk",
            )
            .expect("valid exact instruction request")
        };
        let mut sequence = OperationSequence::default();
        let save = sequence.issue();

        let event = process_command(
            &AppServices::default(),
            WorkerCommand::SaveStaticPatchSet {
                operation: save,
                project: Arc::clone(&project),
                requests: vec![request()],
                path: path.clone(),
            },
        )
        .expect("patch-set save event");
        let WorkerEvent::StaticPatchSetSaved {
            operation,
            result: Ok(saved),
        } = event
        else {
            panic!("unexpected patch-set save event")
        };
        assert_eq!(operation, save);
        assert_eq!(saved.path, path);
        assert_eq!(saved.manifest.edit_count(), 1);
        assert_eq!(
            saved.manifest.source_identity(),
            project.session().base_analysis().identity()
        );

        let load = sequence.issue();
        let event = process_command(
            &AppServices::default(),
            WorkerCommand::LoadStaticPatchSet {
                operation: load,
                project: Arc::clone(&project),
                path: path.clone(),
            },
        )
        .expect("patch-set load event");
        let WorkerEvent::StaticPatchSetLoaded {
            operation,
            result: Ok(loaded),
        } = event
        else {
            panic!("unexpected patch-set load event")
        };
        assert_eq!(operation, load);
        assert_eq!(loaded.path, path);
        assert_eq!(loaded.manifest, saved.manifest);

        let duplicate = sequence.issue();
        let event = process_command(
            &AppServices::default(),
            WorkerCommand::SaveStaticPatchSet {
                operation: duplicate,
                project,
                requests: vec![request()],
                path,
            },
        )
        .expect("duplicate patch-set event");
        assert!(matches!(
            event,
            WorkerEvent::StaticPatchSetSaved {
                operation,
                result: Err(_),
            } if operation == duplicate
        ));
    }

    #[test]
    fn worker_loads_and_projects_a_binary_bound_review_with_its_operation_id() {
        let project = project_snapshot();
        let ledger = ReviewLedger::for_session(project.session()).expect("bound review ledger");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("review.json");
        ledger.save_new(&path).expect("save review fixture");
        let operation = OperationSequence::default().issue();

        let event = process_command(
            &AppServices::default(),
            WorkerCommand::LoadReview {
                operation,
                project: Arc::clone(&project),
                path: path.clone(),
            },
        )
        .expect("load event");
        match event {
            WorkerEvent::ReviewLoaded {
                operation: actual,
                result: Ok(outcome),
            } => {
                assert_eq!(actual, operation);
                assert_eq!(outcome.path, path);
                assert_eq!(outcome.ledger, ledger);
                assert_eq!(outcome.orphaned_decisions, 0);
                assert_eq!(outcome.project.snapshot.session(), project.session());
                assert_eq!(outcome.project.projection, project.projection_arc());
            }
            _ => panic!("unexpected worker event"),
        }
    }

    #[test]
    fn worker_probe_preserves_operation_provider_and_static_binary_binding() {
        let snapshot = project_snapshot();
        let project = LoadedProject::from_snapshot(snapshot).expect("loaded project");
        let evidence = DebuggerReadinessEvidence::from_project(&project);
        let expected_evidence = evidence.clone();
        let choice = SandboxProviderChoice::WindowsSandbox;
        let operation = OperationSequence::default().issue();

        let event = process_sandbox_provider_probe(operation, evidence, choice, ExactFakeProbe);
        match event {
            WorkerEvent::SandboxProviderProbed {
                operation: actual,
                result: Ok(outcome),
            } => {
                assert_eq!(actual, operation);
                assert_eq!(outcome.choice(), choice);
                assert_eq!(outcome.evidence(), &expected_evidence);
                assert_eq!(outcome.report().provider(), &choice.selection());
                assert!(outcome.matches(&project, choice));
            }
            _ => panic!("unexpected worker event"),
        }
    }

    #[test]
    fn worker_reads_mz_through_the_exact_offline_host_lifecycle() {
        let (_source, project) = project_snapshot_with_source();
        let operation = OperationSequence::default().issue();

        let outcome = offline_read(operation, project, 0, 2).expect("read MZ header");

        assert_eq!(outcome.span(), OfflineImageReadSpan::new(0, 2).unwrap());
        assert_eq!(outcome.availability().bytes(), Some(b"MZ".as_slice()));
    }

    #[test]
    fn package_only_project_rejects_offline_reads_without_rereading_a_path() {
        let (_source, analyzed) = project_snapshot_with_source();
        let directory = tempdir().expect("temporary package directory");
        let package_path = directory.path().join("offline-read.resym");
        let services = AppServices::default();
        services
            .save_package_new(&analyzed, &package_path)
            .expect("save package");
        let package_only = services.open_package(&package_path).expect("open package");

        let result = offline_read(OperationSequence::default().issue(), package_only, 0, 2);

        assert_eq!(result, Err(OfflineImageReadFailure::VerifiedSourceRequired));
    }

    #[test]
    fn offline_worker_rejects_empty_oversized_and_overflowing_spans() {
        let (_source, project) = project_snapshot_with_source();
        let mut sequence = OperationSequence::default();

        assert_eq!(
            offline_read(sequence.issue(), Arc::clone(&project), 0, 0),
            Err(OfflineImageReadFailure::InvalidSize {
                actual: 0,
                maximum: MAX_OFFLINE_IMAGE_UI_READ_BYTES,
            })
        );
        assert_eq!(
            offline_read(
                sequence.issue(),
                Arc::clone(&project),
                0,
                MAX_OFFLINE_IMAGE_UI_READ_BYTES + 1,
            ),
            Err(OfflineImageReadFailure::InvalidSize {
                actual: MAX_OFFLINE_IMAGE_UI_READ_BYTES + 1,
                maximum: MAX_OFFLINE_IMAGE_UI_READ_BYTES,
            })
        );
        assert_eq!(
            offline_read(sequence.issue(), project, u64::MAX, 1),
            Err(OfflineImageReadFailure::AddressOverflow {
                rva: u64::MAX,
                size: 1,
            })
        );
    }

    #[test]
    fn offline_pipeline_failure_diagnostics_are_bounded_and_printable() {
        let failure = OfflineImageReadFailure::pipeline(
            "test stage",
            format!(
                "{}\n\t",
                "x".repeat(MAX_OFFLINE_IMAGE_PIPELINE_DETAIL_BYTES * 2)
            ),
        );
        let OfflineImageReadFailure::Pipeline(failure) = failure else {
            panic!("pipeline failure")
        };

        assert_eq!(failure.stage(), "test stage");
        assert!(!failure.detail().is_empty());
        assert!(failure.detail().len() <= MAX_OFFLINE_IMAGE_PIPELINE_DETAIL_BYTES);
        assert!(!failure.detail().chars().any(char::is_control));

        let fallback = OfflineImageReadFailure::pipeline("empty", "\n\t");
        let OfflineImageReadFailure::Pipeline(fallback) = fallback else {
            panic!("pipeline fallback")
        };
        assert_eq!(
            fallback.detail(),
            "offline image pipeline returned no printable diagnostic"
        );
    }

    #[test]
    fn offline_worker_reports_gap_and_crossing_spans_as_bounded_unavailable() {
        let mut bytes = STRIPPED_FIXTURE.to_vec();
        let pe_offset = usize::try_from(u32::from_le_bytes(
            bytes[0x3c..0x40].try_into().expect("e_lfanew bytes"),
        ))
        .expect("PE offset");
        let size_of_image = pe_offset + 24 + 56;
        let prior_image_size = u32::from_le_bytes(
            bytes[size_of_image..size_of_image + 4]
                .try_into()
                .expect("SizeOfImage bytes"),
        );
        bytes[size_of_image..size_of_image + 4]
            .copy_from_slice(&prior_image_size.saturating_add(0x1000).to_le_bytes());
        let (_source, project) = project_snapshot_with_bytes(&bytes);
        let image = VerifiedOfflineImage::from_snapshot(
            project.verified_source_path().expect("verified path"),
            project.session().base_analysis().identity().clone(),
            project
                .verified_source_bytes_arc()
                .expect("verified source snapshot"),
        )
        .expect("verified offline image");
        let gap_rva = image
            .address_space()
            .regions()
            .iter()
            .find(|region| matches!(&region.kind, resymbol_debugger::StaticRegionKind::ImageGap))
            .expect("fixture image gap")
            .range
            .start()
            .get();
        let crossing_rva = image
            .address_space()
            .regions()
            .iter()
            .find_map(|region| {
                let backing = region.file_backing?;
                (backing.size >= 1)
                    .then(|| region.range.start().get() + backing.size.saturating_sub(1))
            })
            .expect("file-backed fixture region");
        let mut sequence = OperationSequence::default();

        for (rva, size) in [(gap_rva, 1), (crossing_rva, 2)] {
            let outcome = offline_read(sequence.issue(), Arc::clone(&project), rva, size)
                .expect("typed unavailable read");
            let OfflineImageReadAvailability::Unavailable(unavailable) = outcome.availability()
            else {
                panic!("range must be unavailable")
            };
            assert_eq!(unavailable.code(), OFFLINE_RANGE_UNAVAILABLE_CODE);
            assert!(!unavailable.detail().is_empty());
            assert!(unavailable.detail().len() <= MAX_OFFLINE_IMAGE_UNAVAILABLE_DETAIL_BYTES);
        }
    }

    #[test]
    fn offline_read_outcome_is_bound_to_the_exact_identity_source_and_span() {
        let (_source, project) = project_snapshot_with_source();
        let expected_identity = project.session().base_analysis().identity().clone();
        let expected_source = fs::canonicalize(
            project
                .verified_source_path()
                .expect("verified source path"),
        )
        .expect("canonical source");

        let outcome = offline_read(
            OperationSequence::default().issue(),
            Arc::clone(&project),
            0x10,
            8,
        )
        .expect("bound header read");

        assert_eq!(outcome.binding().identity(), &expected_identity);
        assert_eq!(outcome.binding().source_path(), expected_source.as_path());
        assert_eq!(outcome.span().rva(), 0x10);
        assert_eq!(outcome.span().size(), 8);
    }

    #[test]
    fn offline_read_exposes_complete_release_and_disconnect_evidence() {
        let (_source, project) = project_snapshot_with_source();

        let outcome = offline_read(OperationSequence::default().issue(), project, 0, 2)
            .expect("complete offline read");
        let lifecycle = outcome.lifecycle();

        assert_ne!(lifecycle.session_id().get(), 0);
        assert_eq!(lifecycle.capability_count(), DebugCapability::ALL.len());
        assert!(lifecycle.session_opened());
        assert!(lifecycle.session_closed());
        assert!(lifecycle.session_released());
        assert!(lifecycle.control_disconnected());
        assert!(lifecycle.is_complete());
    }
}
