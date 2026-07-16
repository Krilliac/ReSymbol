use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
#[cfg(feature = "screenshot")]
use std::{fs::OpenOptions, io::BufWriter};

use eframe::egui::{self, Align, Key, Layout, RichText, ScrollArea, Sense, TextEdit};
use egui_extras::{Column, TableBuilder};
use resymbol_analysis::BinaryAnalysis;
use resymbol_app::{
    DecisionAction, ExportFormat, MAX_REVIEW_ANNOTATION_BYTES, MAX_REVIEWER_BYTES, ReviewSubject,
};
use resymbol_core::{
    BinaryIdentity, DiscoveredPlugin, PluginDiscoveryOptions, PluginDiscoveryReport,
    discover_plugins, plugin_api::PluginHealthState,
};
use resymbol_debugger::{
    IsolationBoundary, MemoryAccess, ProtectionSeverity, SandboxGuarantee,
    SandboxProviderReadiness, SandboxProviderReadinessReason, SandboxProviderRequirement,
    SandboxProviderSelection, StaticRegionKind,
};
use resymbol_export::{ExportControlFlowTarget, ExportProducer};
use serde::{Deserialize, Serialize};

use crate::{
    console::{
        ConsoleCommand, ConsoleExportKind, ConsolePanel, ConsolePanelAction, ConsoleTab,
        ConsoleTheme, format_activity, format_command_result, format_help, parse_command,
    },
    console_host::{ConsoleHost, ConsoleHostEvent},
    graph::{
        GRAPH_MAX_DEPTH, GRAPH_MAX_EDGES, GRAPH_MAX_NODES, GraphEdge, GraphEdgeKind,
        GraphEdgeOrigin, GraphImportKind, GraphNode, GraphNodeId, GraphNodeKind, GraphRootKind,
        ReconstructionGraph, ReconstructionGraphView, ReconstructionGraphViewNode,
    },
    model::{
        FunctionFilter, FunctionSort, FunctionSortKey, FunctionStatus, LoadedProject,
        ProtectionAssessment, SortDirection,
    },
    readiness::{
        DebuggerReadinessEvidence, DebuggerReadinessOutcome, ReadinessProtectionStatus,
        SandboxProviderChoice,
    },
    review_state::BoundReviewLedger,
    theme::{SemanticColors, ThemePreset},
    worker::{
        MAX_OFFLINE_IMAGE_UI_READ_BYTES, OfflineImageReadAvailability, OfflineImageReadOutcome,
        OfflineImageReadSpan, OperationGate, OperationId, OperationSequence, ServiceWorker,
        WorkerCommand, WorkerEvent, WorkerExportKind,
    },
};

const STORAGE_KEY: &str = "resymbol-workbench-preferences-v1";
const MAX_ACTIVITY_ENTRIES: usize = 512;
const MAX_ACTIVITY_MESSAGE_BYTES: usize = 512;
const OFFLINE_READ_SIZES: [u32; 5] = [16, 32, 64, 128, MAX_OFFLINE_IMAGE_UI_READ_BYTES];
const OFFLINE_HEX_ROW_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkflowStage {
    Open,
    Analyze,
    Review,
    Export,
}

impl WorkflowStage {
    const ALL: [Self; 4] = [Self::Open, Self::Analyze, Self::Review, Self::Export];

    const fn label(self) -> &'static str {
        match self {
            Self::Open => "Open Binary",
            Self::Analyze => "Analyze",
            Self::Review => "Review",
            Self::Export => "Export",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MainTab {
    Overview,
    Functions,
    Types,
    Relationships,
    Graph,
    AddressSpace,
    DebuggerSandbox,
    Exports,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectAcceptance {
    NewProject,
    VerifiedSource,
}

impl MainTab {
    const ALL: [Self; 8] = [
        Self::Overview,
        Self::Functions,
        Self::Types,
        Self::Relationships,
        Self::Graph,
        Self::AddressSpace,
        Self::DebuggerSandbox,
        Self::Exports,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Functions => "Functions",
            Self::Types => "Types",
            Self::Relationships => "Relationships",
            Self::Graph => "Graph",
            Self::AddressSpace => "Address Space",
            Self::DebuggerSandbox => "Debugger / Sandbox",
            Self::Exports => "Exports",
        }
    }

    const fn workflow_stage(self) -> WorkflowStage {
        match self {
            Self::Exports => WorkflowStage::Export,
            _ => WorkflowStage::Review,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivityTab {
    Progress,
    Plugins,
    Warnings,
    Log,
}

impl ActivityTab {
    const ALL: [Self; 4] = [Self::Progress, Self::Plugins, Self::Warnings, Self::Log];

    const fn label(self) -> &'static str {
        match self {
            Self::Progress => "Analysis progress",
            Self::Plugins => "Plugin health",
            Self::Warnings => "Warnings",
            Self::Log => "Log",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportKind {
    Package,
    NeutralJson,
    Markdown,
    Map,
    Pdb,
    IdaPython,
    GhidraJava,
}

impl ExportKind {
    const ALL: [Self; 7] = [
        Self::Package,
        Self::NeutralJson,
        Self::Markdown,
        Self::Map,
        Self::Pdb,
        Self::IdaPython,
        Self::GhidraJava,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Package => "ReSymbol package",
            Self::NeutralJson => "Neutral JSON",
            Self::Markdown => "Markdown report",
            Self::Map => "Microsoft-style MAP",
            Self::Pdb => "Public-symbol PDB",
            Self::IdaPython => "IDA Python",
            Self::GhidraJava => "Ghidra Java",
        }
    }

    const fn worker_kind(self) -> WorkerExportKind {
        match self {
            Self::Package => WorkerExportKind::Package,
            Self::NeutralJson => WorkerExportKind::Service(ExportFormat::Json),
            Self::Markdown => WorkerExportKind::Service(ExportFormat::Markdown),
            Self::Map => WorkerExportKind::Service(ExportFormat::Map),
            Self::Pdb => WorkerExportKind::Service(ExportFormat::Pdb),
            Self::IdaPython => WorkerExportKind::Service(ExportFormat::IdaPython),
            Self::GhidraJava => WorkerExportKind::Service(ExportFormat::GhidraJava),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Preferences {
    theme: ThemePreset,
    left_panel_open: bool,
    right_panel_open: bool,
    bottom_panel_open: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: ThemePreset::Graphite,
            left_panel_open: true,
            right_panel_open: true,
            bottom_panel_open: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivityLevel {
    Info,
    Success,
    Warning,
    Error,
}

enum ReviewUiAction {
    Apply {
        subject: Box<ReviewSubject>,
        action: DecisionAction,
    },
    Undo,
    Redo,
    Save(PathBuf),
    Load(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseDialogAction {
    SaveNew,
    DiscardAndClose,
    Cancel,
}

impl ActivityLevel {
    const fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Success => "SUCCESS",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone)]
struct ActivityEntry {
    elapsed_seconds: f64,
    level: ActivityLevel,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfflineSourceBinding {
    identity: BinaryIdentity,
    canonical_source_path: PathBuf,
}

impl OfflineSourceBinding {
    fn from_project(project: &LoadedProject) -> Option<Self> {
        if !project.snapshot.has_verified_source()
            || project.snapshot.verified_source_bytes().is_none()
        {
            return None;
        }
        Some(Self {
            identity: project.session().base_analysis().identity().clone(),
            canonical_source_path: project.snapshot.verified_source_path()?.to_path_buf(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfflineReadRequestBinding {
    source: OfflineSourceBinding,
    span: OfflineImageReadSpan,
}

impl OfflineReadRequestBinding {
    fn matches_outcome(&self, outcome: &OfflineImageReadOutcome) -> bool {
        outcome.binding().identity() == &self.source.identity
            && outcome.binding().source_path() == self.source.canonical_source_path.as_path()
            && outcome.span() == self.span
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingOfflineRead {
    operation: OperationId,
    binding: OfflineReadRequestBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OfflineReadPresentation {
    Outcome(OfflineImageReadOutcome),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OfflineReadEventDisposition {
    Stale,
    Available { byte_count: usize },
    Unavailable { detail: String },
    Failed { detail: String },
    Mismatched { detail: String },
}

#[derive(Debug, Default)]
struct OfflineReadUiState {
    operation: OperationGate,
    pending: Option<PendingOfflineRead>,
    presentation: Option<OfflineReadPresentation>,
}

impl OfflineReadUiState {
    fn begin(&mut self, operation: OperationId, binding: OfflineReadRequestBinding) {
        self.operation.begin(operation);
        self.pending = Some(PendingOfflineRead { operation, binding });
        self.presentation = None;
    }

    fn clear(&mut self) {
        self.operation.invalidate();
        self.pending = None;
        self.presentation = None;
    }

    fn present_error(&mut self, detail: impl Into<String>) {
        self.presentation = Some(OfflineReadPresentation::Error(bounded_message(
            detail.into(),
        )));
    }

    fn is_pending(&self) -> bool {
        self.operation.is_pending()
    }

    fn accept(
        &mut self,
        operation: OperationId,
        result: Result<OfflineImageReadOutcome, crate::worker::OfflineImageReadFailure>,
        current_source: Option<OfflineSourceBinding>,
    ) -> OfflineReadEventDisposition {
        if !self.operation.finish(operation) {
            return OfflineReadEventDisposition::Stale;
        }
        let Some(pending) = self.pending.take() else {
            return self.fail_mismatch("offline read completed without an exact pending binding");
        };
        if pending.operation != operation {
            return self.fail_mismatch("offline read operation did not match its pending binding");
        }
        if current_source.as_ref() != Some(&pending.binding.source) {
            return self.fail_mismatch(
                "offline read no longer matches the active full identity and canonical source path",
            );
        }

        match result {
            Err(error) => {
                let detail = bounded_message(error.to_string());
                self.presentation = Some(OfflineReadPresentation::Error(detail.clone()));
                OfflineReadEventDisposition::Failed { detail }
            }
            Ok(outcome) => {
                if !pending.binding.matches_outcome(&outcome) {
                    return self.fail_mismatch(
                        "offline read response did not match the exact identity, source, RVA, and size request",
                    );
                }
                if !outcome.lifecycle().is_complete() {
                    return self.fail_mismatch(
                        "offline read response omitted complete close, release, or disconnect evidence",
                    );
                }
                if outcome
                    .availability()
                    .bytes()
                    .is_some_and(|bytes| bytes.len() != pending.binding.span.size() as usize)
                {
                    return self.fail_mismatch(
                        "offline read response byte count did not match the exact requested size",
                    );
                }
                let disposition = match outcome.availability() {
                    OfflineImageReadAvailability::Available { bytes } => {
                        OfflineReadEventDisposition::Available {
                            byte_count: bytes.len(),
                        }
                    }
                    OfflineImageReadAvailability::Unavailable(unavailable) => {
                        OfflineReadEventDisposition::Unavailable {
                            detail: unavailable.detail().to_owned(),
                        }
                    }
                };
                self.presentation = Some(OfflineReadPresentation::Outcome(outcome));
                disposition
            }
        }
    }

    fn fail_mismatch(&mut self, detail: impl Into<String>) -> OfflineReadEventDisposition {
        let detail = bounded_message(detail.into());
        self.presentation = Some(OfflineReadPresentation::Error(detail.clone()));
        OfflineReadEventDisposition::Mismatched { detail }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfflineHexRow {
    rva: u64,
    hex: String,
    ascii: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfflineReadDisplay<'a> {
    Available { byte_count: usize },
    Unavailable { code: &'static str, detail: &'a str },
}

/// Native ReSymbol evidence-review workbench.
pub struct WorkbenchApp {
    preferences: Preferences,
    stage: WorkflowStage,
    main_tab: MainTab,
    activity_tab: ActivityTab,
    started_at: Instant,
    project: Option<LoadedProject>,
    service_worker: ServiceWorker,
    operation_sequence: OperationSequence,
    project_operation: OperationGate,
    export_operation: OperationGate,
    review_operation: OperationGate,
    readiness_operation: OperationGate,
    worker_disconnected: bool,
    analysis_path: Option<PathBuf>,
    function_filter: FunctionFilter,
    function_sort: FunctionSort,
    selected_projection_index: Option<usize>,
    selected_review_subject: Option<ReviewSubject>,
    graph_root_rva: Option<u64>,
    reconstruction_graph: Option<ReconstructionGraph>,
    activity: Vec<ActivityEntry>,
    console_host: ConsoleHost,
    plugin_report: Result<PluginDiscoveryReport, String>,
    export_kind: ExportKind,
    export_destination: String,
    export_result: Option<Result<String, String>>,
    #[cfg(feature = "screenshot")]
    screenshot_destination: Option<PathBuf>,
    #[cfg(feature = "screenshot")]
    screenshot_frame_count: u8,
    #[cfg(feature = "screenshot")]
    screenshot_requested: bool,
    review: Option<BoundReviewLedger>,
    review_reviewer: String,
    review_rationale: String,
    review_destination: String,
    review_result: Option<Result<String, String>>,
    pending_review_rollback: Option<BoundReviewLedger>,
    review_orphaned_decisions: usize,
    close_confirmation_open: bool,
    close_after_review_save: bool,
    allow_dirty_close: bool,
    readiness_choice: SandboxProviderChoice,
    readiness_outcome: Option<DebuggerReadinessOutcome>,
    readiness_error: Option<String>,
    offline_read: OfflineReadUiState,
    offline_read_rva_input: String,
    offline_read_size: u32,
}

impl WorkbenchApp {
    pub fn new(creation_context: &eframe::CreationContext<'_>) -> Self {
        #[cfg(feature = "screenshot")]
        if let Ok(value) = std::env::var("RESYMBOL_WORKBENCH_SCREENSHOT_ZOOM") {
            let zoom = value
                .parse::<f32>()
                .unwrap_or_else(|error| panic!("invalid screenshot zoom {value:?}: {error}"));
            assert!(
                zoom.is_finite() && zoom > 0.0,
                "screenshot zoom must be positive"
            );
            creation_context.egui_ctx.set_zoom_factor(zoom);
        }
        let preferences: Preferences = if cfg!(feature = "screenshot") {
            Preferences::default()
        } else {
            creation_context
                .storage
                .and_then(|storage| eframe::get_value(storage, STORAGE_KEY))
                .unwrap_or_default()
        };
        preferences.theme.apply(&creation_context.egui_ctx);
        #[cfg(feature = "screenshot")]
        creation_context.egui_ctx.style_mut(|style| {
            style.animation_time = 0.0;
            // Floating scrollbars expand when the pointer happens to overlap them. Captures
            // must not depend on the host cursor position, so keep their width fixed.
            style.spacing.scroll = egui::style::ScrollStyle::solid();
        });
        #[cfg(feature = "screenshot")]
        for panel_id in [
            "project_navigation",
            "contextual_inspector",
            "activity_and_diagnostics",
        ] {
            let _ = creation_context.egui_ctx.animate_bool_with_time(
                egui::Id::new(panel_id).with("animation"),
                true,
                0.0,
            );
        }

        let plugin_options = PluginDiscoveryOptions {
            safe_mode: true,
            ..PluginDiscoveryOptions::default()
        };
        let plugin_report = discover_plugins("plugins", &plugin_options)
            .map_err(|error| bounded_message(format!("cannot inspect plugin directory: {error}")));

        let mut app = Self {
            preferences,
            stage: WorkflowStage::Open,
            main_tab: MainTab::Overview,
            activity_tab: ActivityTab::Progress,
            started_at: Instant::now(),
            project: None,
            service_worker: ServiceWorker::start(creation_context.egui_ctx.clone()),
            operation_sequence: OperationSequence::default(),
            project_operation: OperationGate::default(),
            export_operation: OperationGate::default(),
            review_operation: OperationGate::default(),
            readiness_operation: OperationGate::default(),
            worker_disconnected: false,
            analysis_path: None,
            function_filter: FunctionFilter::default(),
            function_sort: FunctionSort::default(),
            selected_projection_index: None,
            selected_review_subject: None,
            graph_root_rva: None,
            reconstruction_graph: None,
            activity: Vec::new(),
            console_host: ConsoleHost::new(),
            plugin_report,
            export_kind: ExportKind::Package,
            export_destination: String::new(),
            export_result: None,
            #[cfg(feature = "screenshot")]
            screenshot_destination: std::env::var_os("RESYMBOL_WORKBENCH_SCREENSHOT_TO")
                .map(PathBuf::from),
            #[cfg(feature = "screenshot")]
            screenshot_frame_count: 0,
            #[cfg(feature = "screenshot")]
            screenshot_requested: false,
            review: None,
            review_reviewer: String::new(),
            review_rationale: String::new(),
            review_destination: String::new(),
            review_result: None,
            pending_review_rollback: None,
            review_orphaned_decisions: 0,
            close_confirmation_open: false,
            close_after_review_save: false,
            allow_dirty_close: false,
            readiness_choice: SandboxProviderChoice::default(),
            readiness_outcome: None,
            readiness_error: None,
            offline_read: OfflineReadUiState::default(),
            offline_read_rva_input: "0x00000000".to_owned(),
            offline_read_size: 64,
        };
        app.log(
            ActivityLevel::Info,
            "Workbench ready in core-only safe review mode",
        );

        let startup_path = std::env::args_os().nth(1).map(PathBuf::from);

        #[cfg(feature = "screenshot")]
        if let Ok(tab) = std::env::var("RESYMBOL_WORKBENCH_SCREENSHOT_TAB") {
            let path = startup_path
                .as_ref()
                .expect("screenshot mode requires an input binary path");
            let project = LoadedProject::from_path(path).unwrap_or_else(|error| {
                panic!("cannot load {} for screenshot: {error}", path.display())
            });
            app.selected_projection_index = project
                .functions
                .first()
                .map(|function| function.projection_index);
            let reconstruction_graph = ReconstructionGraph::from_project(&project);
            app.graph_root_rva = reconstruction_graph.default_root().map(|root| root.rva);
            if tab == "graph" {
                app.selected_projection_index = app.graph_root_rva.and_then(|root_rva| {
                    project
                        .functions
                        .iter()
                        .find(|function| function.rva == root_rva)
                        .map(|function| function.projection_index)
                });
            }
            app.reconstruction_graph = Some(reconstruction_graph);
            app.export_destination = default_export_path(&project, app.export_kind)
                .to_string_lossy()
                .into_owned();
            app.review_destination = default_review_path(&project).to_string_lossy().into_owned();
            app.review = Some(
                BoundReviewLedger::for_session(project.session())
                    .unwrap_or_else(|error| panic!("cannot bind screenshot review state: {error}")),
            );
            app.analysis_path = Some(path.clone());
            app.stage = WorkflowStage::Review;
            app.main_tab = match tab.as_str() {
                "overview" => MainTab::Overview,
                "functions" => MainTab::Functions,
                "graph" => MainTab::Graph,
                "address-space" | "memory-map" => MainTab::AddressSpace,
                "debugger-sandbox" | "readiness" => MainTab::DebuggerSandbox,
                "exports" => {
                    app.stage = WorkflowStage::Export;
                    MainTab::Exports
                }
                _ => panic!("unsupported screenshot tab {tab:?}"),
            };
            app.project = Some(project);
            if app.main_tab == MainTab::DebuggerSandbox {
                app.queue_sandbox_readiness_probe()
                    .unwrap_or_else(|error| panic!("cannot queue readiness capture: {error}"));
            }
            app.log(
                ActivityLevel::Success,
                format!("Loaded {} for visual regression capture", path.display()),
            );
            return app;
        }

        if let Some(path) = startup_path {
            if let Err(error) = app.start_analysis(path) {
                app.log(ActivityLevel::Error, error);
            }
        }
        app
    }

    fn log(&mut self, level: ActivityLevel, message: impl Into<String>) {
        let elapsed = self.started_at.elapsed();
        let message = bounded_message(message.into());
        if self.activity.len() == MAX_ACTIVITY_ENTRIES {
            self.activity.remove(0);
        }
        self.activity.push(ActivityEntry {
            elapsed_seconds: elapsed.as_secs_f64(),
            level,
            message: message.clone(),
        });
        if self.console_host.is_ready() {
            let _ =
                self.console_host
                    .try_send_line(format_activity(elapsed, level.label(), &message));
        }
    }

    #[cfg(feature = "screenshot")]
    fn advance_screenshot_capture(&mut self, context: &egui::Context) {
        const SETTLE_FRAMES: u8 = 12;
        if self.screenshot_destination.is_none() {
            return;
        }

        let captured = context.input(|input| {
            input.events.iter().find_map(|event| match event {
                egui::Event::Screenshot { image, .. } => Some(Arc::clone(image)),
                _ => None,
            })
        });
        if let Some(image) = captured {
            let destination = self
                .screenshot_destination
                .take()
                .expect("capture destination remains present");
            write_screenshot_new(&destination, &image).unwrap_or_else(|error| {
                panic!(
                    "cannot write workbench screenshot {}: {error}",
                    destination.display()
                )
            });
            context.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        if self.main_tab == MainTab::DebuggerSandbox && self.readiness_operation.is_pending() {
            self.screenshot_frame_count = 0;
            context.request_repaint();
            return;
        }

        if !self.screenshot_requested {
            self.screenshot_frame_count = self.screenshot_frame_count.saturating_add(1);
            if self.screenshot_frame_count >= SETTLE_FRAMES {
                context.send_viewport_cmd(egui::ViewportCommand::Screenshot(
                    egui::UserData::default(),
                ));
                self.screenshot_requested = true;
            }
        }
        context.request_repaint();
    }

    fn request_close(&mut self, context: &egui::Context) -> bool {
        let review_is_dirty = self
            .review
            .as_ref()
            .is_some_and(BoundReviewLedger::is_dirty);
        if close_requires_confirmation(review_is_dirty, self.allow_dirty_close) {
            if !self.close_confirmation_open {
                self.log(
                    ActivityLevel::Warning,
                    "Close paused: save or explicitly discard unsaved review decisions",
                );
            }
            self.close_confirmation_open = true;
            return false;
        }

        self.allow_dirty_close = false;
        context.send_viewport_cmd(egui::ViewportCommand::Close);
        true
    }

    fn choose_new_review_sidecar(&self, title: &str) -> Option<PathBuf> {
        let default = PathBuf::from(self.review_destination.trim());
        let mut dialog = rfd::FileDialog::new()
            .set_title(title)
            .add_filter("ReSymbol review", &["json"]);
        if let Some(parent) = default
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            dialog = dialog.set_directory(parent);
        }
        if let Some(name) = default.file_name().and_then(|name| name.to_str()) {
            dialog = dialog.set_file_name(name);
        } else {
            dialog = dialog.set_file_name("project.review.json");
        }
        dialog.save_file()
    }

    fn show_close_confirmation(&mut self, context: &egui::Context) {
        if !self.close_confirmation_open {
            return;
        }
        if !self
            .review
            .as_ref()
            .is_some_and(BoundReviewLedger::is_dirty)
        {
            self.close_confirmation_open = false;
            self.close_after_review_save = false;
            self.request_close(context);
            return;
        }

        let review_busy = self.project_operation.is_pending()
            || self.review_operation.is_pending()
            || self.export_operation.is_pending();
        let response = egui::Modal::new(egui::Id::new("dirty_review_close_confirmation")).show(
            context,
            |ui| {
                ui.set_min_width(430.0);
                ui.heading("Unsaved review decisions");
                ui.label(
                    "Closing now would discard the in-memory review history for this binary.",
                );
                ui.small(
                    "Review sidecars are create-new: saving never overwrites a loaded or previously saved file.",
                );
                if self.close_after_review_save && self.review_operation.is_pending() {
                    ui.separator();
                    ui.label("Saving the exact current ledger snapshot before closing...");
                }
                if let Some(Err(error)) = &self.review_result {
                    ui.separator();
                    ui.colored_label(
                        self.preferences
                            .theme
                            .semantic_colors()
                            .destructive_quarantined,
                        format!("[ERROR] {error}"),
                    );
                }
                ui.separator();
                let mut action = None;
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(!review_busy, egui::Button::new("Save New..."))
                        .on_hover_text("Choose a new binary-bound review sidecar, then close only after that exact snapshot is durable")
                        .clicked()
                    {
                        action = Some(CloseDialogAction::SaveNew);
                    }
                    if ui.button("Discard and Close").clicked() {
                        action = Some(CloseDialogAction::DiscardAndClose);
                    }
                    if ui.button("Cancel").clicked() {
                        action = Some(CloseDialogAction::Cancel);
                    }
                });
                action
            },
        );
        let should_cancel = response.should_close();
        let action = response
            .inner
            .or_else(|| should_cancel.then_some(CloseDialogAction::Cancel));

        match action {
            Some(CloseDialogAction::SaveNew) => {
                if let Some(path) = self.choose_new_review_sidecar(
                    "Save review decisions to a new sidecar before closing",
                ) {
                    match self.queue_review_save(path) {
                        Ok(_) => {
                            self.close_after_review_save = true;
                            self.close_confirmation_open = true;
                        }
                        Err(error) => {
                            self.close_after_review_save = false;
                            self.review_result = Some(Err(error.clone()));
                            self.log(
                                ActivityLevel::Error,
                                format!("Review save before close failed: {error}"),
                            );
                        }
                    }
                }
            }
            Some(CloseDialogAction::DiscardAndClose) => {
                self.close_confirmation_open = false;
                self.close_after_review_save = false;
                self.allow_dirty_close = true;
                context.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Some(CloseDialogAction::Cancel) => {
                self.close_confirmation_open = false;
                self.close_after_review_save = false;
                self.allow_dirty_close = false;
            }
            None => {}
        }
    }

    fn set_console_enabled(&mut self, enabled: bool) {
        if enabled == self.console_host.is_enabled() {
            return;
        }
        if enabled {
            if cfg!(feature = "screenshot") {
                self.log(
                    ActivityLevel::Warning,
                    "Companion console is disabled during screenshot capture",
                );
                return;
            }
            match self.console_host.enable() {
                Ok(()) => self.log(ActivityLevel::Info, "Starting companion console"),
                Err(error) => self.log(
                    ActivityLevel::Error,
                    format!("Cannot enable companion console: {error}"),
                ),
            }
        } else {
            self.console_host.disable();
            self.log(ActivityLevel::Info, "Companion console disabled");
        }
    }

    fn poll_console(&mut self, context: &egui::Context) {
        let events = self.console_host.drain_events(32);
        let mut closed = None;
        for event in events {
            match event {
                ConsoleHostEvent::Ready => self.on_console_ready(),
                ConsoleHostEvent::CommandLine(line) => {
                    if !self.apply_console_line(&line, context) {
                        break;
                    }
                }
                ConsoleHostEvent::Closed(exit_code) => closed = Some(exit_code),
                ConsoleHostEvent::Error(error) => {
                    self.log(
                        ActivityLevel::Warning,
                        format!("Console transport: {error}"),
                    );
                }
                ConsoleHostEvent::Fatal(error) => {
                    self.log(ActivityLevel::Error, format!("Console transport: {error}"));
                    closed = Some(None);
                }
            }
        }
        if let Some(exit_code) = closed {
            self.console_host.disable();
            self.log(
                ActivityLevel::Info,
                exit_code.map_or_else(
                    || "Companion console closed".to_owned(),
                    |code| format!("Companion console closed with exit code {code}"),
                ),
            );
        }
    }

    fn on_console_ready(&mut self) {
        if !self.console_host.is_ready() {
            return;
        }
        let backlog = self
            .activity
            .iter()
            .rev()
            .take(8)
            .rev()
            .map(|entry| {
                format_activity(
                    Duration::from_secs_f64(entry.elapsed_seconds),
                    entry.level.label(),
                    &entry.message,
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        if !backlog.is_empty() {
            let _ = self.console_host.try_send_line(backlog);
        }
        self.log(ActivityLevel::Success, "Companion console ready");
    }

    fn apply_console_line(&mut self, line: &str, context: &egui::Context) -> bool {
        match parse_command(line) {
            Ok(command) => {
                let is_quit = matches!(command, ConsoleCommand::Quit);
                self.apply_console_command(command, context);
                !is_quit || self.close_confirmation_open
            }
            Err(error) => {
                self.console_reply(false, error);
                true
            }
        }
    }

    fn apply_console_command(&mut self, command: ConsoleCommand, context: &egui::Context) {
        match command {
            ConsoleCommand::Help => {
                let _ = self.console_host.try_send_line(format_help());
            }
            ConsoleCommand::Status => {
                let analysis = if self.project_operation.is_pending() {
                    "running"
                } else if self.project.is_some() {
                    "ready"
                } else {
                    "idle"
                };
                let project = self
                    .project
                    .as_ref()
                    .map_or("none", |project| project.identity.display_name.as_str());
                let function_count = self
                    .project
                    .as_ref()
                    .map_or(0, |project| project.functions.len());
                let graph_root = self
                    .graph_root_rva
                    .map_or_else(|| "none".to_owned(), |rva| format!("0x{rva:X}"));
                let console = if self.console_host.is_ready() {
                    "ready"
                } else if self.console_host.is_enabled() {
                    "starting"
                } else {
                    "off"
                };
                self.console_reply(
                    true,
                    format!(
                        "project={project} analysis={analysis} stage={} tab={} functions={function_count} graph-root={graph_root} theme={} panels={}/{}/{} console={console}",
                        self.stage.label(),
                        self.main_tab.label(),
                        self.preferences.theme.label(),
                        panel_state(self.preferences.left_panel_open),
                        panel_state(self.preferences.right_panel_open),
                        panel_state(self.preferences.bottom_panel_open),
                    ),
                );
            }
            ConsoleCommand::Open(path) => match self.start_analysis(path) {
                Ok(message) => self.console_reply(true, message),
                Err(error) => self.console_reply(false, error),
            },
            ConsoleCommand::Tab(tab) => {
                if self.project.is_none() && tab != ConsoleTab::Overview {
                    self.console_reply(false, "open a binary before selecting that tab");
                    return;
                }
                self.main_tab = match tab {
                    ConsoleTab::Overview => MainTab::Overview,
                    ConsoleTab::Functions => MainTab::Functions,
                    ConsoleTab::Types => MainTab::Types,
                    ConsoleTab::Relationships => MainTab::Relationships,
                    ConsoleTab::Graph => MainTab::Graph,
                    ConsoleTab::AddressSpace => MainTab::AddressSpace,
                    ConsoleTab::DebuggerSandbox => MainTab::DebuggerSandbox,
                    ConsoleTab::Exports => MainTab::Exports,
                };
                if tab == ConsoleTab::Exports {
                    self.stage = WorkflowStage::Export;
                } else if self.project.is_some() {
                    self.stage = WorkflowStage::Review;
                }
                self.console_reply(true, format!("opened {} tab", tab.as_str()));
            }
            ConsoleCommand::Focus(rva) => {
                let projection_index = self.project.as_ref().and_then(|project| {
                    project
                        .functions
                        .iter()
                        .find(|function| function.rva == rva)
                        .map(|function| function.projection_index)
                });
                if let Some(projection_index) = projection_index {
                    self.selected_projection_index = Some(projection_index);
                    self.graph_root_rva = Some(rva);
                    self.main_tab = MainTab::Graph;
                    self.stage = WorkflowStage::Review;
                    self.console_reply(true, format!("focused graph at 0x{rva:X}"));
                } else {
                    self.console_reply(false, format!("no projected function at 0x{rva:X}"));
                }
            }
            ConsoleCommand::Theme(theme) => {
                self.preferences.theme = match theme {
                    ConsoleTheme::Graphite => ThemePreset::Graphite,
                    ConsoleTheme::Light => ThemePreset::Light,
                    ConsoleTheme::Ida => ThemePreset::IdaInspired,
                    ConsoleTheme::Classic => ThemePreset::ClassicDebugger,
                };
                self.preferences.theme.apply(context);
                self.console_reply(true, format!("theme set to {}", theme.as_str()));
            }
            ConsoleCommand::Panel { panel, action } => {
                let open = match panel {
                    ConsolePanel::Left => &mut self.preferences.left_panel_open,
                    ConsolePanel::Right => &mut self.preferences.right_panel_open,
                    ConsolePanel::Bottom => &mut self.preferences.bottom_panel_open,
                };
                *open = match action {
                    ConsolePanelAction::Show => true,
                    ConsolePanelAction::Hide => false,
                    ConsolePanelAction::Toggle => !*open,
                };
                let state = panel_state(*open);
                self.console_reply(true, format!("{} panel is {state}", panel.as_str()));
            }
            ConsoleCommand::ResetLayout => {
                self.preferences.left_panel_open = true;
                self.preferences.right_panel_open = true;
                self.preferences.bottom_panel_open = true;
                context.memory_mut(|memory| *memory = egui::Memory::default());
                self.console_reply(true, "layout reset");
            }
            ConsoleCommand::Export { kind, path } => {
                let kind = match kind {
                    ConsoleExportKind::Resym => ExportKind::Package,
                    ConsoleExportKind::Json => ExportKind::NeutralJson,
                    ConsoleExportKind::Markdown => ExportKind::Markdown,
                    ConsoleExportKind::Map => ExportKind::Map,
                    ConsoleExportKind::Pdb => ExportKind::Pdb,
                    ConsoleExportKind::IdaPython => ExportKind::IdaPython,
                    ConsoleExportKind::GhidraJava => ExportKind::GhidraJava,
                };
                self.export_kind = kind;
                self.export_destination = path.to_string_lossy().into_owned();
                self.stage = WorkflowStage::Export;
                self.main_tab = MainTab::Exports;
                match self.queue_export(kind, path) {
                    Ok(message) => self.console_reply(true, message),
                    Err(error) => self.console_reply(false, error),
                }
            }
            ConsoleCommand::Quit => {
                if self.request_close(context) {
                    self.console_reply(true, "closing workbench");
                } else {
                    self.console_reply(
                        false,
                        "close paused: save or explicitly discard unsaved review decisions in the workbench",
                    );
                }
            }
        }
    }

    fn console_reply(&self, success: bool, message: impl AsRef<str>) {
        let _ = self
            .console_host
            .try_send_line(format_command_result(success, message.as_ref()));
    }

    fn start_analysis(&mut self, path: PathBuf) -> Result<String, String> {
        if self.project_operation.is_pending() {
            return Err("a project operation is already running".to_owned());
        }
        if self.export_operation.is_pending() || self.review_operation.is_pending() {
            return Err("wait for the current export or review operation first".to_owned());
        }
        if self.offline_read.is_pending() {
            return Err(
                "wait for the exact offline byte read before replacing the project".to_owned(),
            );
        }
        if self
            .review
            .as_ref()
            .is_some_and(BoundReviewLedger::is_dirty)
        {
            return Err(
                "the current project has unsaved review decisions; save them to a new sidecar before replacing the project"
                    .to_owned(),
            );
        }
        let operation = self.operation_sequence.issue();
        let command = if is_package_path(&path) {
            WorkerCommand::OpenPackage {
                operation,
                path: path.clone(),
            }
        } else {
            WorkerCommand::Analyze {
                operation,
                path: path.clone(),
            }
        };
        self.service_worker.submit(command)?;
        self.project_operation.begin(operation);
        self.analysis_path = Some(path.clone());
        self.stage = WorkflowStage::Analyze;
        let action = if is_package_path(&path) {
            "package open"
        } else {
            "bounded core analysis"
        };
        let message = format!("Queued {action} for {}", path.display());
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn select_sandbox_provider(&mut self, choice: SandboxProviderChoice) {
        if self.readiness_choice == choice {
            return;
        }
        self.readiness_choice = choice;
        self.readiness_operation.invalidate();
        self.readiness_outcome = None;
        self.readiness_error = None;
        self.log(
            ActivityLevel::Info,
            format!(
                "Selected {} for read-only capability discovery; no provider was activated",
                choice.label()
            ),
        );
    }

    fn queue_sandbox_readiness_probe(&mut self) -> Result<String, String> {
        if self.readiness_operation.is_pending() {
            return Err("a provider readiness check is already running".to_owned());
        }
        if self.project_operation.is_pending() {
            return Err(
                "wait for the current project operation before checking readiness".to_owned(),
            );
        }
        let project = self
            .project
            .as_ref()
            .ok_or_else(|| "open a project before checking provider readiness".to_owned())?;
        let evidence = DebuggerReadinessEvidence::from_project(project);
        let project_name = project.identity.display_name.clone();
        let operation = self.operation_sequence.issue();
        self.service_worker
            .submit(WorkerCommand::ProbeSandboxProvider {
                operation,
                evidence,
                choice: self.readiness_choice,
            })?;
        self.readiness_operation.begin(operation);
        self.readiness_outcome = None;
        self.readiness_error = None;
        let message = format!(
            "Queued read-only {} readiness check for {}; no target will be opened or executed",
            self.readiness_choice.label(),
            project_name
        );
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn queue_offline_image_read(&mut self) -> Result<String, String> {
        if self.offline_read.is_pending() {
            return Err("an exact offline image read is already running".to_owned());
        }
        if self.worker_disconnected {
            return Err("the application-service worker is unavailable".to_owned());
        }
        if self.project_operation.is_pending() {
            return Err(
                "wait for the current project or source operation before reading bytes".to_owned(),
            );
        }
        if !OFFLINE_READ_SIZES.contains(&self.offline_read_size) {
            return Err("choose a supported offline read size".to_owned());
        }
        let rva = parse_hex_rva(&self.offline_read_rva_input)?;
        let span = OfflineImageReadSpan::new(rva, self.offline_read_size)
            .map_err(|error| bounded_message(error.to_string()))?;
        let (snapshot, source, project_name) = {
            let project = self
                .project
                .as_ref()
                .ok_or_else(|| "open a project before reading offline bytes".to_owned())?;
            let source = OfflineSourceBinding::from_project(project).ok_or_else(|| {
                "the exact source binary must be verified before reading offline bytes".to_owned()
            })?;
            (
                Arc::clone(&project.snapshot),
                source,
                project.identity.display_name.clone(),
            )
        };
        let operation = self.operation_sequence.issue();
        self.service_worker
            .submit(WorkerCommand::ReadOfflineImage {
                operation,
                project: snapshot,
                rva: span.rva(),
                size: span.size(),
            })?;
        self.offline_read
            .begin(operation, OfflineReadRequestBinding { source, span });
        let message = format!(
            "Queued exact offline read of {} byte(s) at RVA 0x{:X} for {project_name}",
            span.size(),
            span.rva()
        );
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn queue_export(&mut self, kind: ExportKind, path: PathBuf) -> Result<String, String> {
        if path.as_os_str().is_empty() {
            return Err("choose a destination path".to_owned());
        }
        if self.export_operation.is_pending() {
            return Err("an export is already running".to_owned());
        }
        if self.project_operation.is_pending() {
            return Err("wait for the current project operation before exporting".to_owned());
        }
        if self.review_operation.is_pending() {
            return Err("wait for the current review save or load before exporting".to_owned());
        }
        let project = self
            .project
            .as_ref()
            .ok_or_else(|| "open a binary or package before exporting".to_owned())?;
        if kind == ExportKind::Pdb && !project.snapshot.has_verified_source() {
            return Err(
                "PDB export requires the exact source binary; package-only projects must verify it first"
                    .to_owned(),
            );
        }
        let reviews = self
            .review
            .as_ref()
            .ok_or_else(|| "the current project has no bound review ledger".to_owned())?
            .ledger()
            .clone();

        let operation = self.operation_sequence.issue();
        self.service_worker.submit(WorkerCommand::Export {
            operation,
            project: Arc::clone(&project.snapshot),
            reviews,
            kind: kind.worker_kind(),
            path: path.clone(),
        })?;
        self.export_operation.begin(operation);
        self.export_result = None;
        let message = format!("Queued {} export to {}", kind.label(), path.display());
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn queue_source_verification(&mut self, path: PathBuf) -> Result<String, String> {
        if self.project_operation.is_pending() {
            return Err("a project operation is already running".to_owned());
        }
        if self.review_operation.is_pending() {
            return Err("wait for the current review save or load first".to_owned());
        }
        let project = self
            .project
            .as_ref()
            .ok_or_else(|| "open a package before verifying its source binary".to_owned())?;
        if project.snapshot.has_verified_source() {
            return Err("the exact source binary is already verified".to_owned());
        }
        let reviews = self
            .review
            .as_ref()
            .ok_or_else(|| "the current project has no bound review ledger".to_owned())?
            .ledger()
            .clone();

        let operation = self.operation_sequence.issue();
        self.service_worker.submit(WorkerCommand::VerifySource {
            operation,
            project: Arc::clone(&project.snapshot),
            reviews,
            path: path.clone(),
        })?;
        self.project_operation.begin(operation);
        let message = format!(
            "Queued exact-source identity verification for {}",
            path.display()
        );
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn queue_review_save(&mut self, path: PathBuf) -> Result<String, String> {
        if path.as_os_str().is_empty() {
            return Err("choose a review sidecar destination".to_owned());
        }
        if self.project_operation.is_pending() {
            return Err("wait for the current project operation before saving reviews".to_owned());
        }
        if self.review_operation.is_pending() {
            return Err("a review save or load is already running".to_owned());
        }
        let review = self
            .review
            .as_ref()
            .ok_or_else(|| "open a project before saving reviews".to_owned())?;
        if review.persisted_path() == Some(path.as_path()) {
            return Err(
                "choose a new sidecar path; an existing loaded or saved sidecar is never replaced"
                    .to_owned(),
            );
        }
        let ledger = review.ledger().clone();
        let operation = self.operation_sequence.issue();
        self.service_worker.submit(WorkerCommand::SaveReview {
            operation,
            ledger,
            path: path.clone(),
        })?;
        self.review_operation.begin(operation);
        self.review_result = None;
        let message = format!("Queued create-new review save to {}", path.display());
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn queue_review_load(&mut self, path: PathBuf) -> Result<String, String> {
        if path.as_os_str().is_empty() {
            return Err("choose a review sidecar to load".to_owned());
        }
        if self.project_operation.is_pending() {
            return Err("wait for the current project operation before loading reviews".to_owned());
        }
        if self.export_operation.is_pending() {
            return Err("wait for the current export before loading reviews".to_owned());
        }
        if self.review_operation.is_pending() {
            return Err("a review save or load is already running".to_owned());
        }
        if self
            .review
            .as_ref()
            .is_some_and(BoundReviewLedger::is_dirty)
        {
            return Err(
                "the current ledger has unsaved decisions; save them before loading another sidecar"
                    .to_owned(),
            );
        }
        let project = self
            .project
            .as_ref()
            .ok_or_else(|| "open a project before loading reviews".to_owned())?;
        let operation = self.operation_sequence.issue();
        self.service_worker.submit(WorkerCommand::LoadReview {
            operation,
            project: Arc::clone(&project.snapshot),
            path: path.clone(),
        })?;
        self.review_operation.begin(operation);
        self.review_result = None;
        let message = format!("Queued bound review sidecar load from {}", path.display());
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn queue_review_projection(
        &mut self,
        next: BoundReviewLedger,
        description: String,
    ) -> Result<String, String> {
        if self.project_operation.is_pending() {
            return Err("wait for the current project operation before reviewing".to_owned());
        }
        if self.export_operation.is_pending() {
            return Err("wait for the current export before changing reviews".to_owned());
        }
        if self.review_operation.is_pending() {
            return Err("a review operation is already running".to_owned());
        }
        let project = self
            .project
            .as_ref()
            .ok_or_else(|| "open a project before reviewing claims".to_owned())?;
        let operation = self.operation_sequence.issue();
        self.service_worker.submit(WorkerCommand::ApplyReview {
            operation,
            project: Arc::clone(&project.snapshot),
            ledger: next.ledger().clone(),
        })?;
        self.pending_review_rollback = self.review.replace(next);
        self.review_operation.begin(operation);
        self.review_result = None;
        self.log(ActivityLevel::Info, &description);
        Ok(description)
    }

    fn apply_review_ui_action(&mut self, action: ReviewUiAction) {
        match action {
            ReviewUiAction::Apply { subject, action } => {
                let reviewer = self.review_reviewer.clone();
                let rationale = self.review_rationale.clone();
                let result = self
                    .review
                    .as_ref()
                    .ok_or_else(|| "the current project has no bound review ledger".to_owned())
                    .and_then(|review| {
                        let mut next = review.clone();
                        next.apply_disposition(&subject, action.clone(), &reviewer, &rationale)
                            .map_err(|error| error.to_string())?;
                        Ok(next)
                    });
                match result {
                    Ok(next) => {
                        let message = format!(
                            "Applying {} to exact name claim `{}`",
                            decision_action_label(&action),
                            subject.name()
                        );
                        match self.queue_review_projection(next, message) {
                            Ok(_) => self.review_rationale.clear(),
                            Err(error) => {
                                self.review_result = Some(Err(error.clone()));
                                self.log(
                                    ActivityLevel::Error,
                                    format!("Review decision failed: {error}"),
                                );
                            }
                        }
                    }
                    Err(error) => {
                        self.review_result = Some(Err(error.clone()));
                        self.log(
                            ActivityLevel::Error,
                            format!("Review decision failed: {error}"),
                        );
                    }
                }
            }
            ReviewUiAction::Undo => {
                let next = self
                    .review
                    .clone()
                    .and_then(|mut next| next.undo().then_some(next));
                let result = next.map(|next| {
                    self.queue_review_projection(
                        next,
                        "Applying review undo to the active projection".to_owned(),
                    )
                });
                if let Some(Err(error)) = result {
                    self.review_result = Some(Err(error.clone()));
                    self.log(ActivityLevel::Error, format!("Review undo failed: {error}"));
                }
            }
            ReviewUiAction::Redo => {
                let next = self
                    .review
                    .clone()
                    .and_then(|mut next| next.redo().then_some(next));
                let result = next.map(|next| {
                    self.queue_review_projection(
                        next,
                        "Applying review redo to the active projection".to_owned(),
                    )
                });
                if let Some(Err(error)) = result {
                    self.review_result = Some(Err(error.clone()));
                    self.log(ActivityLevel::Error, format!("Review redo failed: {error}"));
                }
            }
            ReviewUiAction::Save(path) => {
                if let Err(error) = self.queue_review_save(path) {
                    self.review_result = Some(Err(error.clone()));
                    self.log(ActivityLevel::Error, format!("Review save failed: {error}"));
                }
            }
            ReviewUiAction::Load(path) => {
                if let Err(error) = self.queue_review_load(path) {
                    self.review_result = Some(Err(error.clone()));
                    self.log(ActivityLevel::Error, format!("Review load failed: {error}"));
                }
            }
        }
    }

    fn poll_service_worker(&mut self, context: &egui::Context) {
        loop {
            let event = match self.service_worker.try_recv() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(error) => {
                    if !self.worker_disconnected {
                        self.worker_disconnected = true;
                        self.project_operation.invalidate();
                        self.export_operation.invalidate();
                        self.review_operation.invalidate();
                        self.readiness_operation.invalidate();
                        self.offline_read.clear();
                        if let Some(previous) = self.pending_review_rollback.take() {
                            self.review = Some(previous);
                        }
                        self.close_after_review_save = false;
                        self.log(ActivityLevel::Error, error);
                    }
                    break;
                }
            };

            match event {
                WorkerEvent::ProjectOpened { operation, result } => {
                    if !self.project_operation.finish(operation) {
                        self.log(
                            ActivityLevel::Warning,
                            format!(
                                "Ignored stale project result for operation {}",
                                operation.get()
                            ),
                        );
                        continue;
                    }
                    match result {
                        Ok(project) => self.accept_project(project, ProjectAcceptance::NewProject),
                        Err(error) => {
                            self.stage = if self.project.is_some() {
                                WorkflowStage::Review
                            } else {
                                WorkflowStage::Open
                            };
                            self.log(
                                ActivityLevel::Error,
                                format!("Project open failed: {error}"),
                            );
                        }
                    }
                }
                WorkerEvent::SourceVerified { operation, result } => {
                    if !self.project_operation.finish(operation) {
                        self.log(
                            ActivityLevel::Warning,
                            format!(
                                "Ignored stale source verification for operation {}",
                                operation.get()
                            ),
                        );
                        continue;
                    }
                    match result {
                        Ok(project) => {
                            self.accept_project(project, ProjectAcceptance::VerifiedSource)
                        }
                        Err(error) => {
                            self.stage = WorkflowStage::Review;
                            self.log(
                                ActivityLevel::Error,
                                format!("Source verification failed: {error}"),
                            );
                        }
                    }
                }
                WorkerEvent::ExportCompleted { operation, result } => {
                    if !self.export_operation.finish(operation) {
                        self.log(
                            ActivityLevel::Warning,
                            format!(
                                "Ignored stale export result for operation {}",
                                operation.get()
                            ),
                        );
                        continue;
                    }
                    match result {
                        Ok(outcome) => {
                            let message = format!(
                                "Wrote {} to {}",
                                outcome.kind.label(),
                                outcome.path.display()
                            );
                            self.export_result = Some(Ok(message.clone()));
                            self.console_reply(true, &message);
                            self.log(ActivityLevel::Success, message);
                        }
                        Err(error) => {
                            self.export_result = Some(Err(error.clone()));
                            self.console_reply(false, &error);
                            self.log(ActivityLevel::Error, format!("Export failed: {error}"));
                        }
                    }
                }
                WorkerEvent::ReviewSaved { operation, result } => {
                    if !self.review_operation.finish(operation) {
                        self.log(
                            ActivityLevel::Warning,
                            format!(
                                "Ignored stale review-save result for operation {}",
                                operation.get()
                            ),
                        );
                        continue;
                    }
                    match result {
                        Ok(outcome) => {
                            let current = self.review.as_mut().is_some_and(|review| {
                                review.mark_saved(&outcome.ledger, outcome.path.clone())
                            });
                            let message = if current {
                                format!("Saved review sidecar to {}", outcome.path.display())
                            } else {
                                format!(
                                    "Saved an earlier review snapshot to {}; newer in-memory decisions remain unsaved",
                                    outcome.path.display()
                                )
                            };
                            self.review_destination = outcome.path.to_string_lossy().into_owned();
                            self.review_result = Some(Ok(message.clone()));
                            self.log(ActivityLevel::Success, message);
                            if self.close_after_review_save {
                                self.close_after_review_save = false;
                                if current {
                                    self.close_confirmation_open = false;
                                    context.send_viewport_cmd(egui::ViewportCommand::Close);
                                } else {
                                    self.close_confirmation_open = true;
                                }
                            }
                        }
                        Err(error) => {
                            let was_closing_after_save = self.close_after_review_save;
                            self.close_after_review_save = false;
                            if was_closing_after_save {
                                self.close_confirmation_open = true;
                            }
                            self.review_result = Some(Err(error.clone()));
                            self.log(ActivityLevel::Error, format!("Review save failed: {error}"));
                        }
                    }
                }
                WorkerEvent::ReviewApplied {
                    operation,
                    ledger,
                    result,
                } => {
                    if !self.review_operation.finish(operation) {
                        self.log(
                            ActivityLevel::Warning,
                            format!(
                                "Ignored stale reviewed-projection result for operation {}",
                                operation.get()
                            ),
                        );
                        continue;
                    }
                    let ledger_is_current = self
                        .review
                        .as_ref()
                        .is_some_and(|review| review.ledger() == &ledger);
                    if !ledger_is_current {
                        if let Some(previous) = self.pending_review_rollback.take() {
                            self.review = Some(previous);
                        }
                        self.log(
                            ActivityLevel::Warning,
                            "Ignored reviewed projection for a superseded ledger snapshot",
                        );
                        continue;
                    }
                    match result {
                        Ok(outcome) => {
                            self.pending_review_rollback = None;
                            self.review_orphaned_decisions = outcome.orphaned_decisions;
                            self.accept_reviewed_project(outcome.project);
                            let message = "Review decision applied to the active projection";
                            self.review_result = Some(Ok(message.to_owned()));
                            self.log(ActivityLevel::Success, message);
                        }
                        Err(error) => {
                            if let Some(previous) = self.pending_review_rollback.take() {
                                self.review = Some(previous);
                            }
                            self.review_result = Some(Err(error.clone()));
                            self.log(
                                ActivityLevel::Error,
                                format!(
                                    "Reviewed projection failed; decision rolled back: {error}"
                                ),
                            );
                        }
                    }
                }
                WorkerEvent::ReviewLoaded { operation, result } => {
                    if !self.review_operation.finish(operation) {
                        self.log(
                            ActivityLevel::Warning,
                            format!(
                                "Ignored stale review-load result for operation {}",
                                operation.get()
                            ),
                        );
                        continue;
                    }
                    match result {
                        Ok(outcome) => {
                            let bound = BoundReviewLedger::from_loaded(
                                outcome.project.session(),
                                outcome.ledger,
                                outcome.path.clone(),
                            )
                            .map_err(|error| error.to_string());
                            match bound {
                                Ok(review) => {
                                    self.review = Some(review);
                                    self.pending_review_rollback = None;
                                    self.review_orphaned_decisions = outcome.orphaned_decisions;
                                    self.review_destination =
                                        outcome.path.to_string_lossy().into_owned();
                                    self.accept_reviewed_project(outcome.project);
                                    let message = format!(
                                        "Loaded review sidecar from {} ({} orphaned decision(s))",
                                        outcome.path.display(),
                                        outcome.orphaned_decisions
                                    );
                                    self.review_result = Some(Ok(message.clone()));
                                    self.log(ActivityLevel::Success, message);
                                }
                                Err(error) => {
                                    self.review_result = Some(Err(error.clone()));
                                    self.log(
                                        ActivityLevel::Error,
                                        format!("Review load failed: {error}"),
                                    );
                                }
                            }
                        }
                        Err(error) => {
                            self.review_result = Some(Err(error.clone()));
                            self.log(ActivityLevel::Error, format!("Review load failed: {error}"));
                        }
                    }
                }
                WorkerEvent::SandboxProviderProbed { operation, result } => {
                    if !self.readiness_operation.finish(operation) {
                        self.log(
                            ActivityLevel::Warning,
                            format!(
                                "Ignored stale sandbox readiness result for operation {}",
                                operation.get()
                            ),
                        );
                        continue;
                    }
                    match result {
                        Ok(outcome) => {
                            let current = self.project.as_ref().is_some_and(|project| {
                                outcome.matches(project, self.readiness_choice)
                            });
                            if !current {
                                self.readiness_outcome = None;
                                self.readiness_error = Some(
                                    "Readiness result did not match the current binary evidence or selected provider"
                                        .to_owned(),
                                );
                                self.log(
                                    ActivityLevel::Warning,
                                    "Ignored sandbox readiness result for stale binary evidence or provider selection",
                                );
                                continue;
                            }
                            let message = format!(
                                "Read-only {} readiness check completed for {}; no target was opened or executed",
                                outcome.choice().label(),
                                short_hash(outcome.evidence().binary_id().as_str())
                            );
                            self.readiness_error = None;
                            self.readiness_outcome = Some(outcome);
                            self.console_reply(true, &message);
                            self.log(ActivityLevel::Success, message);
                        }
                        Err(error) => {
                            self.readiness_outcome = None;
                            self.readiness_error = Some(error.clone());
                            self.console_reply(false, &error);
                            self.log(
                                ActivityLevel::Error,
                                format!("Sandbox readiness check failed closed: {error}"),
                            );
                        }
                    }
                }
                WorkerEvent::OfflineImageRead { operation, result } => {
                    let current_source = self
                        .project
                        .as_ref()
                        .and_then(OfflineSourceBinding::from_project);
                    match self.offline_read.accept(operation, result, current_source) {
                        OfflineReadEventDisposition::Stale => self.log(
                            ActivityLevel::Warning,
                            format!(
                                "Ignored stale offline image result for operation {}",
                                operation.get()
                            ),
                        ),
                        OfflineReadEventDisposition::Available { byte_count } => self.log(
                            ActivityLevel::Success,
                            format!(
                                "Read {byte_count} exact frozen source byte(s) through the offline host"
                            ),
                        ),
                        OfflineReadEventDisposition::Unavailable { detail } => self.log(
                            ActivityLevel::Warning,
                            format!("Exact offline byte span is unavailable: {detail}"),
                        ),
                        OfflineReadEventDisposition::Failed { detail } => self.log(
                            ActivityLevel::Error,
                            format!("Offline image read failed: {detail}"),
                        ),
                        OfflineReadEventDisposition::Mismatched { detail } => self.log(
                            ActivityLevel::Error,
                            format!("Offline image response failed closed: {detail}"),
                        ),
                    }
                }
            }
        }
    }

    fn accept_project(&mut self, project: LoadedProject, acceptance: ProjectAcceptance) {
        let preserve_context = acceptance == ProjectAcceptance::VerifiedSource;
        let reviews_still_bound = preserve_context
            && self.review.as_ref().is_some_and(|review| {
                review
                    .ledger()
                    .validate_for_binary(project.session().base_analysis().identity())
                    .is_ok()
            });
        let selected_rva = if reviews_still_bound {
            self.selected_projection_index
                .and_then(|index| self.project.as_ref()?.functions.get(index))
                .map(|row| row.rva)
        } else {
            None
        };
        let previous_graph_root = if reviews_still_bound {
            self.graph_root_rva
        } else {
            None
        };
        let previous_main_tab = self.main_tab;
        let replacement_reviews = if reviews_still_bound {
            None
        } else {
            match BoundReviewLedger::for_session(project.session()) {
                Ok(review) => Some(review),
                Err(error) => {
                    self.log(
                        ActivityLevel::Error,
                        format!("Project review ledger could not be bound: {error}"),
                    );
                    return;
                }
            }
        };
        let updated_orphaned_decisions = if reviews_still_bound {
            match self
                .review
                .as_ref()
                .expect("a preserved review ledger is present")
                .orphaned_count(project.session())
            {
                Ok(count) => count,
                Err(error) => {
                    self.log(
                        ActivityLevel::Error,
                        format!("Project review ledger could not be reprojected: {error}"),
                    );
                    return;
                }
            }
        } else {
            0
        };
        let function_count = project.functions.len();
        let warning_count = project.projection.warnings.len();
        let protection_count = project.protection_assessment.findings().len();
        let protection_requires_review = project.protection_assessment.requires_acknowledgement();
        let protection_unavailable = project
            .protection_assessment
            .unavailable_reason()
            .map(ToOwned::to_owned);
        self.export_operation.invalidate();
        self.review_operation.invalidate();
        self.readiness_operation.invalidate();
        self.offline_read.clear();
        self.pending_review_rollback = None;
        self.readiness_outcome = None;
        self.readiness_error = None;
        self.export_destination = default_export_path(&project, self.export_kind)
            .to_string_lossy()
            .into_owned();
        self.export_result = None;
        self.analysis_path = Some(project.identity.active_binary_path().to_path_buf());
        self.selected_projection_index = selected_rva
            .and_then(|rva| {
                project
                    .functions
                    .iter()
                    .find(|row| row.rva == rva)
                    .map(|row| row.projection_index)
            })
            .or_else(|| project.functions.first().map(|row| row.projection_index));
        if !reviews_still_bound {
            self.selected_review_subject = None;
        }
        let reconstruction_graph = ReconstructionGraph::from_project(&project);
        self.graph_root_rva = previous_graph_root
            .filter(|rva| project.functions.iter().any(|row| row.rva == *rva))
            .or_else(|| reconstruction_graph.default_root().map(|root| root.rva));
        self.reconstruction_graph = Some(reconstruction_graph);
        if !reviews_still_bound {
            self.function_filter = FunctionFilter::default();
        }
        if let Some(review) = replacement_reviews {
            self.review_destination = default_review_path(&project).to_string_lossy().into_owned();
            self.review_result = None;
            self.review = Some(review);
        }
        self.review_orphaned_decisions = updated_orphaned_decisions;
        self.project = Some(project);
        self.main_tab = if reviews_still_bound {
            previous_main_tab
        } else {
            MainTab::Overview
        };
        self.stage = self.main_tab.workflow_stage();
        if protection_requires_review {
            self.activity_tab = ActivityTab::Warnings;
            self.log(
                ActivityLevel::Warning,
                format!(
                    "Static protection assessment requires offline review: {protection_count} finding(s); no target code executed"
                ),
            );
        } else if let Some(reason) = protection_unavailable {
            self.activity_tab = ActivityTab::Warnings;
            self.log(ActivityLevel::Warning, reason);
        }
        self.log(
            ActivityLevel::Success,
            format!(
                "Project ready: {function_count} functions, {protection_count} protection findings, {warning_count} projection warnings"
            ),
        );
    }

    fn accept_reviewed_project(&mut self, project: LoadedProject) {
        let Some(current) = self.project.as_ref() else {
            self.log(
                ActivityLevel::Warning,
                "Ignored reviewed projection because no project is open",
            );
            return;
        };
        if current.identity.sha256 != project.identity.sha256
            || current.identity.file_size != project.identity.file_size
        {
            self.log(
                ActivityLevel::Warning,
                "Ignored reviewed projection for a different project identity",
            );
            return;
        }
        let offline_source_changed = OfflineSourceBinding::from_project(current)
            != OfflineSourceBinding::from_project(&project);

        let selected_rva = self
            .selected_projection_index
            .and_then(|index| current.functions.get(index))
            .map(|row| row.rva);
        let previous_graph_root = self.graph_root_rva;
        let reconstruction_graph = ReconstructionGraph::from_project(&project);
        self.selected_projection_index = selected_rva
            .and_then(|rva| {
                project
                    .functions
                    .iter()
                    .find(|row| row.rva == rva)
                    .map(|row| row.projection_index)
            })
            .or_else(|| project.functions.first().map(|row| row.projection_index));
        self.graph_root_rva = previous_graph_root
            .filter(|rva| project.functions.iter().any(|row| row.rva == *rva))
            .or_else(|| reconstruction_graph.default_root().map(|root| root.rva));
        self.reconstruction_graph = Some(reconstruction_graph);
        self.export_result = None;
        if offline_source_changed {
            self.offline_read.clear();
        }
        self.project = Some(project);
    }

    fn choose_binary(&mut self, _context: &egui::Context) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Open a PE32+ x86-64 binary or current ReSymbol package")
            .add_filter("Windows binaries", &["exe", "dll", "sys"])
            .add_filter("ReSymbol packages", &["resym"])
            .pick_file()
        else {
            return;
        };
        if let Err(error) = self.start_analysis(path) {
            self.log(ActivityLevel::Error, error);
        }
    }

    fn handle_inputs(&mut self, context: &egui::Context) {
        if self.close_confirmation_open {
            return;
        }
        let (open_shortcut, load_review_shortcut, save_review_shortcut, save_review_as_shortcut) =
            context.input(|input| {
                let command = input.modifiers.command;
                (
                    command && !input.modifiers.shift && input.key_pressed(Key::O),
                    command && input.modifiers.shift && input.key_pressed(Key::O),
                    command && !input.modifiers.shift && input.key_pressed(Key::S),
                    command && input.modifiers.shift && input.key_pressed(Key::S),
                )
            });
        if open_shortcut {
            self.choose_binary(context);
        }
        if (save_review_shortcut || save_review_as_shortcut) && self.review.is_some() {
            let destination = PathBuf::from(self.review_destination.trim());
            let persisted_path = self
                .review
                .as_ref()
                .and_then(BoundReviewLedger::persisted_path);
            let needs_dialog = save_review_as_shortcut
                || review_save_requires_dialog(&destination, persisted_path);
            let path = if needs_dialog {
                self.choose_new_review_sidecar("Create a new ReSymbol review sidecar")
            } else {
                Some(destination)
            };
            if let Some(path) = path {
                self.apply_review_ui_action(ReviewUiAction::Save(path));
            }
        } else if load_review_shortcut
            && self
                .review
                .as_ref()
                .is_some_and(|review| !review.is_dirty())
        {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Load a binary-bound ReSymbol review sidecar")
                .add_filter("ReSymbol review", &["json"])
                .pick_file()
            {
                self.apply_review_ui_action(ReviewUiAction::Load(path));
            }
        }

        let (undo_review, redo_review) = context.input(|input| {
            let command = input.modifiers.command;
            let undo = command && !input.modifiers.shift && input.key_pressed(Key::Z);
            let redo = command
                && ((input.modifiers.shift && input.key_pressed(Key::Z))
                    || input.key_pressed(Key::Y));
            (undo, redo)
        });
        if !context.wants_keyboard_input()
            && !self.project_operation.is_pending()
            && !self.review_operation.is_pending()
            && !self.export_operation.is_pending()
        {
            if undo_review {
                self.apply_review_ui_action(ReviewUiAction::Undo);
            } else if redo_review {
                self.apply_review_ui_action(ReviewUiAction::Redo);
            }
        }

        let dropped = context.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .find_map(|file| file.path.clone())
        });
        if let Some(path) = dropped {
            if let Err(error) = self.start_analysis(path) {
                self.log(ActivityLevel::Error, error);
            }
        }
    }

    fn show_header(&mut self, context: &egui::Context) {
        let colors = self.preferences.theme.semantic_colors();
        egui::TopBottomPanel::top("workbench_header")
            .exact_height(112.0)
            .frame(
                egui::Frame::new()
                    .fill(colors.panel)
                    .stroke(egui::Stroke::new(1.0, colors.border))
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .show(context, |ui| {
                ui.horizontal(|ui| {
                    let (mark_rect, _) =
                        ui.allocate_exact_size(egui::vec2(32.0, 32.0), Sense::hover());
                    ui.painter().rect_filled(mark_rect, 5.0, colors.selection);
                    ui.painter().text(
                        mark_rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "R",
                        egui::FontId::proportional(17.0),
                        colors.primary_text,
                    );
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("ReSymbol").heading().strong());
                            ui.label(
                                RichText::new("WORKBENCH")
                                    .small()
                                    .color(colors.secondary_text),
                            );
                        });
                        ui.label(
                            RichText::new("BINARY INTELLIGENCE / EVIDENCE REVIEW")
                                .small()
                                .color(colors.secondary_text),
                        );
                    });
                    ui.add_space(16.0);
                    if let Some(project) = &self.project {
                        egui::Frame::new()
                            .fill(colors.raised)
                            .stroke(egui::Stroke::new(1.0, colors.border))
                            .inner_margin(egui::Margin::symmetric(10, 5))
                            .corner_radius(4)
                            .show(ui, |ui| {
                                ui.label(RichText::new(&project.identity.display_name).strong());
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new("[EXACT] Exact identity")
                                            .color(colors.exact_extracted),
                                    );
                                    ui.label(
                                        RichText::new(short_hash(project.identity.sha256.as_str()))
                                            .monospace()
                                            .small()
                                            .color(colors.secondary_text),
                                    )
                                    .on_hover_text(format!(
                                        "SHA-256 {}",
                                        project.identity.sha256.as_str()
                                    ));
                                });
                            });
                    } else if let Some(path) = &self.analysis_path {
                        ui.label(path.display().to_string());
                    } else {
                        ui.label(
                            RichText::new("No binary open - drop a PE or press Ctrl+O")
                                .color(colors.secondary_text),
                        );
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let primary_label = if self.project_operation.is_pending() {
                            "Analyzing..."
                        } else if self.project.is_some() {
                            "Export Symbols"
                        } else {
                            "Open Binary"
                        };
                        if ui
                            .add_enabled(
                                !self.project_operation.is_pending(),
                                egui::Button::new(RichText::new(primary_label).strong())
                                    .fill(colors.selection)
                                    .stroke(egui::Stroke::new(1.0, colors.exact_extracted))
                                    .corner_radius(4),
                            )
                            .clicked()
                        {
                            if self.project.is_some() {
                                self.stage = WorkflowStage::Export;
                                self.main_tab = MainTab::Exports;
                            } else {
                                self.choose_binary(context);
                            }
                        }

                        egui::ComboBox::from_id_salt("header_theme_selector")
                            .selected_text(self.preferences.theme.label())
                            .show_ui(ui, |ui| {
                                for preset in ThemePreset::ALL {
                                    if ui
                                        .selectable_value(
                                            &mut self.preferences.theme,
                                            preset,
                                            preset.label(),
                                        )
                                        .clicked()
                                    {
                                        preset.apply(context);
                                    }
                                }
                            });

                        ui.menu_button("View", |ui| {
                            ui.checkbox(&mut self.preferences.left_panel_open, "Project panel");
                            ui.checkbox(&mut self.preferences.right_panel_open, "Inspector panel");
                            ui.checkbox(&mut self.preferences.bottom_panel_open, "Activity panel");
                            ui.separator();
                            let mut console_enabled = self.console_host.is_enabled();
                            let console_toggle = ui.add_enabled(
                                cfg!(target_os = "windows") && !cfg!(feature = "screenshot"),
                                egui::Checkbox::new(
                                    &mut console_enabled,
                                    "Companion console",
                                ),
                            );
                            if console_toggle.changed() {
                                self.set_console_enabled(console_enabled);
                            }
                            if !cfg!(target_os = "windows") {
                                console_toggle.on_hover_text(
                                    "The external companion console is currently available on Windows only",
                                );
                            }
                            ui.separator();
                            if ui.button("Reset Layout").clicked() {
                                self.preferences.left_panel_open = true;
                                self.preferences.right_panel_open = true;
                                self.preferences.bottom_panel_open = true;
                                context.memory_mut(|memory| *memory = egui::Memory::default());
                                ui.close();
                            }
                        });
                    });
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    for (index, stage) in WorkflowStage::ALL.into_iter().enumerate() {
                        let enabled = match stage {
                            WorkflowStage::Open => true,
                            WorkflowStage::Analyze => self.project_operation.is_pending(),
                            WorkflowStage::Review | WorkflowStage::Export => self.project.is_some(),
                        };
                        let selected = self.stage == stage;
                        let mut button = egui::Button::selectable(
                            selected,
                            format!("{}  {}", index + 1, stage.label()),
                        )
                        .min_size(egui::vec2(118.0, 30.0))
                        .corner_radius(4);
                        if selected {
                            button = button
                                .fill(colors.selection)
                                .stroke(egui::Stroke::new(1.0, colors.exact_extracted));
                        }
                        if ui.add_enabled(enabled, button).clicked() {
                            self.stage = stage;
                            self.main_tab = match stage {
                                WorkflowStage::Export => MainTab::Exports,
                                WorkflowStage::Review => MainTab::Functions,
                                _ => MainTab::Overview,
                            };
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let (cue, text, color) = if self.project_operation.is_pending() {
                            ("[RUN]", "Core analyzer working", colors.inferred)
                        } else if self.project.is_some() {
                            ("[READY]", "Validated projection", colors.healthy)
                        } else {
                            ("[IDLE]", "Awaiting binary", colors.fallback)
                        };
                        ui.label(RichText::new(format!("{cue} {text}")).color(color));
                    });
                });
            });
    }

    fn show_project_panel(&mut self, context: &egui::Context) {
        let colors = self.preferences.theme.semantic_colors();
        egui::SidePanel::left("project_navigation")
            .default_width(220.0)
            .width_range(170.0..=360.0)
            .resizable(true)
            .frame(
                egui::Frame::new()
                    .fill(colors.panel)
                    .stroke(egui::Stroke::new(1.0, colors.border))
                    .inner_margin(egui::Margin::same(12)),
            )
            .show_animated(context, self.preferences.left_panel_open, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Project");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Hide").clicked() {
                            self.preferences.left_panel_open = false;
                        }
                    });
                });
                ui.separator();
                if let Some(project) = &self.project {
                    egui::Frame::new()
                        .fill(colors.raised)
                        .stroke(egui::Stroke::new(1.0, colors.border))
                        .inner_margin(egui::Margin::same(9))
                        .corner_radius(4)
                        .show(ui, |ui| {
                            ui.label(RichText::new(&project.identity.display_name).strong());
                            ui.label(
                                RichText::new("[EXACT] SHA-256 bound")
                                    .color(colors.exact_extracted),
                            );
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    RichText::new(format!("{} bytes", project.identity.file_size))
                                        .monospace()
                                        .color(colors.secondary_text),
                                );
                                ui.label(
                                    RichText::new(&project.identity.architecture)
                                        .color(colors.secondary_text),
                                );
                            });
                        });
                    ui.add_space(8.0);
                    ui.collapsing("Analysis session", |ui| {
                        ui.label(format!(
                            "Schema {}",
                            project.snapshot.package().schema_version()
                        ));
                        ui.label("Core-only safe review mode");
                    });
                    if ui
                        .selectable_label(
                            self.main_tab == MainTab::Functions,
                            format!("Functions ({})", project.functions.len()),
                        )
                        .clicked()
                    {
                        self.main_tab = MainTab::Functions;
                        self.stage = WorkflowStage::Review;
                    }
                    if ui
                        .selectable_label(
                            self.main_tab == MainTab::Types,
                            format!("Types ({})", project.projection.types.len()),
                        )
                        .clicked()
                    {
                        self.main_tab = MainTab::Types;
                    }
                    if ui
                        .selectable_label(self.main_tab == MainTab::Relationships, "Relationships")
                        .clicked()
                    {
                        self.main_tab = MainTab::Relationships;
                    }
                    if ui
                        .selectable_label(self.main_tab == MainTab::Graph, "Reconstruction graph")
                        .clicked()
                    {
                        self.main_tab = MainTab::Graph;
                        self.stage = WorkflowStage::Review;
                    }
                    if ui
                        .selectable_label(
                            self.main_tab == MainTab::AddressSpace,
                            format!(
                                "Address space ({})",
                                project.static_address_space.regions().len()
                            ),
                        )
                        .clicked()
                    {
                        self.main_tab = MainTab::AddressSpace;
                        self.stage = WorkflowStage::Review;
                    }
                    if ui
                        .selectable_label(
                            self.main_tab == MainTab::DebuggerSandbox,
                            "Debugger / Sandbox readiness",
                        )
                        .clicked()
                    {
                        self.main_tab = MainTab::DebuggerSandbox;
                        self.stage = WorkflowStage::Review;
                    }
                } else {
                    ui.label(RichText::new("Open a binary to create a project").weak());
                }

                ui.separator();
                ui.collapsing("Plugins (read-only safe mode)", |ui| {
                    self.show_plugin_list(ui);
                });
                ui.separator();
                ui.label(RichText::new("Review sidecar").strong());
                if let Some(review) = &self.review {
                    let state = if review.is_dirty() { "UNSAVED" } else { "CLEAN" };
                    let state_color = if review.is_dirty() {
                        colors.warning_conflict
                    } else {
                        colors.healthy
                    };
                    ui.label(RichText::new(format!(
                        "[{state}] {} applied / {} history / {} redo",
                        review.applied_count(),
                        review.history_count(),
                        review.redo_count()
                    )).color(state_color));
                    if self.review_orphaned_decisions != 0 {
                        ui.label(
                            RichText::new(format!(
                                "[ORPHANED] {} exact claim decision(s) are retained but not applied",
                                self.review_orphaned_decisions
                            ))
                            .color(colors.warning_conflict),
                        );
                    }
                    if let Some(path) = review.persisted_path() {
                        ui.small(format!("Last sidecar: {}", path.display()));
                    } else {
                        ui.small("Use the Evidence inspector to save or load review history.");
                    }
                } else {
                    ui.small("Open a project to create an exact binary-bound review ledger.");
                }
            });
    }

    fn show_plugin_list(&self, ui: &mut egui::Ui) {
        match &self.plugin_report {
            Ok(report) if report.plugins.is_empty() => {
                ui.label("[--] No plugins discovered");
            }
            Ok(report) => {
                for plugin in &report.plugins {
                    show_plugin(ui, plugin, self.preferences.theme.semantic_colors());
                }
            }
            Err(error) => {
                ui.colored_label(
                    self.preferences
                        .theme
                        .semantic_colors()
                        .destructive_quarantined,
                    format!("[ERROR] {error}"),
                );
            }
        }
    }

    fn show_inspector(&mut self, context: &egui::Context) {
        let colors = self.preferences.theme.semantic_colors();
        let panel = egui::SidePanel::right("contextual_inspector")
            .default_width(330.0)
            .width_range(260.0..=520.0)
            .resizable(true)
            .frame(
                egui::Frame::new()
                    .fill(colors.panel)
                    .stroke(egui::Stroke::new(1.0, colors.border))
                    .inner_margin(egui::Margin::same(12)),
            );
        let is_open = self.preferences.right_panel_open;
        let mut pending_review_action = None;
        let contents = |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                ui.heading("Evidence inspector");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.small_button("Hide").clicked() {
                        self.preferences.right_panel_open = false;
                    }
                });
            });
            ui.separator();
            let Some(project) = &self.project else {
                ui.label(RichText::new("Select a result after analysis").weak());
                return;
            };
            let Some(index) = self.selected_projection_index else {
                ui.label(RichText::new("Select a function row").weak());
                return;
            };
            let Some(row) = project.functions.get(index) else {
                ui.label("The selected result is no longer available");
                return;
            };
            let colors = self.preferences.theme.semantic_colors();
            ScrollArea::vertical().show(ui, |ui| {
                egui::Frame::new()
                    .fill(colors.raised)
                    .stroke(egui::Stroke::new(1.0, colors.border))
                    .inner_margin(egui::Margin::same(12))
                    .corner_radius(4)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(&row.display_name)
                                .strong()
                                .monospace()
                                .size(17.0),
                        );
                        status_badge(ui, row.status, colors);
                        if ui.button("Open focused graph").clicked() {
                            self.graph_root_rva = Some(row.rva);
                            self.main_tab = MainTab::Graph;
                            self.stage = WorkflowStage::Review;
                        }
                    });
                ui.add_space(8.0);
                egui::Frame::new()
                    .fill(colors.canvas)
                    .stroke(egui::Stroke::new(1.0, colors.border))
                    .inner_margin(egui::Margin::same(10))
                    .corner_radius(4)
                    .show(ui, |ui| {
                        ui.label(RichText::new("Properties").strong());
                        egui::Grid::new("inspector_summary")
                            .num_columns(2)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.label("RVA");
                                ui.label(RichText::new(format!("0x{:08X}", row.rva)).monospace());
                                ui.end_row();
                                ui.label("Size");
                                ui.label(row.size.map_or_else(
                                    || "Unavailable".to_owned(),
                                    |size| format!("0x{size:X}"),
                                ));
                                ui.end_row();
                                ui.label("Confidence");
                                ui.label(row.confidence.map_or_else(
                                    || "Unavailable".to_owned(),
                                    |value| format!("{:.1}%", value * 100.0),
                                ));
                                ui.end_row();
                                ui.label("Source");
                                ui.label(&row.source).on_hover_text(&row.source);
                                ui.end_row();
                            });
                    });

                if !row.alternate_names.is_empty() {
                    ui.add_space(8.0);
                    egui::Frame::new()
                        .fill(colors.canvas)
                        .stroke(egui::Stroke::new(1.0, colors.warning_conflict))
                        .inner_margin(egui::Margin::same(10))
                        .corner_radius(4)
                        .show(ui, |ui| {
                            ui.label(RichText::new("Competing names").strong());
                            for alternate in &row.alternate_names {
                                ui.label(RichText::new(&alternate.name).monospace());
                                ui.label(
                                    RichText::new(format!(
                                        "{:.1}% - {}",
                                        alternate.confidence * 100.0,
                                        alternate.producer.label()
                                    ))
                                    .color(colors.secondary_text),
                                );
                            }
                        });
                }

                if let Some(detail) = project.function_detail(index) {
                    let selected_is_available = self.selected_review_subject.as_ref().is_some_and(
                        |selected| {
                            detail.claims.iter().any(|claim| {
                                claim.review_subject().is_some_and(|subject| subject == selected)
                            })
                        },
                    );
                    if !selected_is_available {
                        self.selected_review_subject = detail
                            .claims
                            .iter()
                            .find_map(|claim| claim.review_subject().cloned());
                    }
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(format!("Claims and provenance ({})", detail.claims.len()))
                            .strong(),
                    );
                    for (claim_index, claim) in detail.claims.iter().enumerate() {
                        egui::Frame::new()
                            .fill(colors.raised)
                            .stroke(egui::Stroke::new(1.0, colors.border))
                            .inner_margin(egui::Margin::symmetric(8, 5))
                            .corner_radius(4)
                            .show(ui, |ui| {
                                if let Some(subject) = claim.review_subject() {
                                    let selected = self.selected_review_subject.as_ref()
                                        == Some(subject);
                                    let response = ui
                                        .selectable_label(
                                            selected,
                                            RichText::new(format!(
                                                "[NAME CLAIM] {}",
                                                claim.value
                                            ))
                                            .monospace(),
                                        )
                                        .on_hover_text(
                                            "Select this exact fingerprinted name claim for review",
                                        );
                                    if response.clicked() {
                                        self.selected_review_subject = Some(subject.clone());
                                    }
                                } else {
                                    ui.label(format!("{:?}: {}", claim.kind, claim.value));
                                }
                                egui::CollapsingHeader::new("Evidence details")
                                    .id_salt(("claim-evidence", row.rva, claim_index))
                                    .show(ui, |ui| {
                                    ui.label(format!(
                                        "Confidence: {:.1}%",
                                        claim.confidence * 100.0
                                    ));
                                    ui.label(format!("Producer: {}", claim.producer.label()));
                                    ui.label(format!("Method: {}", claim.method));
                                    if let Some(run_id) = &claim.run_id {
                                        ui.label(format!("Run: {run_id}"));
                                    }
                                    for evidence in &claim.evidence {
                                        ui.group(|ui| {
                                            ui.label(
                                                RichText::new(format!("[{}]", evidence.kind))
                                                    .strong(),
                                            );
                                            ui.label(&evidence.summary);
                                            if let Some(confidence) = evidence.confidence {
                                                ui.label(format!(
                                                    "Evidence value: {:.1}%",
                                                    confidence * 100.0
                                                ));
                                            }
                                            for (key, value) in &evidence.artifacts {
                                                ui.label(
                                                    RichText::new(format!("{key}: {value}"))
                                                        .monospace()
                                                        .small(),
                                                );
                                            }
                                        });
                                    }
                                    if claim.evidence.is_empty() {
                                        ui.label("No evidence cards retained");
                                    }
                                    ui.small(format!(
                                        "Claim {} of {}",
                                        claim_index + 1,
                                        detail.claims.len()
                                    ));
                                    });
                            });
                        ui.add_space(5.0);
                    }
                }
                egui::Frame::new()
                    .fill(colors.canvas)
                    .stroke(egui::Stroke::new(1.0, colors.border))
                    .inner_margin(egui::Margin::same(10))
                    .corner_radius(4)
                    .show(ui, |ui| {
                        ui.label(RichText::new("Review decisions").strong());
                        let review_busy = self.project_operation.is_pending()
                            || self.review_operation.is_pending()
                            || self.export_operation.is_pending();
                        let selected_subject = self.selected_review_subject.as_ref();
                        let (current, history, can_undo, can_redo, dirty, persisted_path) = self
                            .review
                            .as_ref()
                            .map_or_else(
                                || {
                                    (
                                        None,
                                        Vec::new(),
                                        false,
                                        false,
                                        false,
                                        None,
                                    )
                                },
                                |review| {
                                    let ledger = review.ledger();
                                    let current = selected_subject.and_then(|subject| {
                                        ledger.latest_disposition(subject).map(|decision| {
                                            format!(
                                                "#{} {} by {}",
                                                decision.sequence(),
                                                decision_action_label(decision.action()),
                                                decision.reviewer().unwrap_or("anonymous reviewer")
                                            )
                                        })
                                    });
                                    let applied_count = ledger.applied_history().len();
                                    let history = selected_subject.map_or_else(Vec::new, |subject| {
                                        ledger
                                            .history()
                                            .iter()
                                            .enumerate()
                                            .rev()
                                            .filter(|(_, decision)| decision.subject() == subject)
                                            .take(8)
                                            .map(|(history_index, decision)| {
                                                let state = if history_index < applied_count {
                                                    "APPLIED"
                                                } else {
                                                    "REDO"
                                                };
                                                format!(
                                                    "[{state}] #{} {}",
                                                    decision.sequence(),
                                                    decision_history_label(decision.action())
                                                )
                                            })
                                            .collect::<Vec<_>>()
                                    });
                                    (
                                        current,
                                        history,
                                        review.can_undo(),
                                        review.can_redo(),
                                        review.is_dirty(),
                                        review
                                            .persisted_path()
                                            .map(|path| path.to_path_buf()),
                                    )
                                },
                            );

                        match selected_subject {
                            Some(subject) => {
                                ui.label(
                                    RichText::new(format!(
                                        "Selected exact name: {}",
                                        subject.name()
                                    ))
                                    .monospace(),
                                );
                                ui.small(format!(
                                    "Claim SHA-256 {}",
                                    subject.claim_sha256()
                                ));
                            }
                            None => {
                                ui.label(
                                    RichText::new(
                                        "Select a [NAME CLAIM] above; non-name claims remain read-only",
                                    )
                                    .color(colors.secondary_text),
                                );
                            }
                        }
                        ui.label(current.map_or_else(
                            || "Current disposition: none".to_owned(),
                            |value| format!("Current disposition: {value}"),
                        ));

                        if history.is_empty() {
                            ui.small("No history for the selected claim");
                        } else {
                            ui.collapsing("Selected claim history", |ui| {
                                for entry in history {
                                    ui.label(RichText::new(entry).monospace().small());
                                }
                            });
                        }

                        ui.separator();
                        ui.label("Reviewer (optional)");
                        let reviewer = ui.add(
                            TextEdit::singleline(&mut self.review_reviewer)
                                .char_limit(MAX_REVIEWER_BYTES)
                                .hint_text("Name or handle")
                                .desired_width(ui.available_width()),
                        );
                        if reviewer.changed() {
                            truncate_utf8_bytes(&mut self.review_reviewer, MAX_REVIEWER_BYTES);
                        }
                        ui.small(format!(
                            "{} / {} UTF-8 bytes",
                            self.review_reviewer.len(),
                            MAX_REVIEWER_BYTES
                        ));

                        ui.label("Rationale (optional audit annotation)");
                        let rationale = ui.add(
                            TextEdit::multiline(&mut self.review_rationale)
                                .char_limit(MAX_REVIEW_ANNOTATION_BYTES)
                                .hint_text("Evidence-based reason retained as an annotation")
                                .desired_rows(2)
                                .desired_width(ui.available_width()),
                        );
                        if rationale.changed() {
                            truncate_utf8_bytes(
                                &mut self.review_rationale,
                                MAX_REVIEW_ANNOTATION_BYTES,
                            );
                        }
                        ui.small(format!(
                            "{} / {} UTF-8 bytes",
                            self.review_rationale.len(),
                            MAX_REVIEW_ANNOTATION_BYTES
                        ));

                        let can_decide = selected_subject.is_some()
                            && self.review.is_some()
                            && !review_busy;
                        ui.horizontal_wrapped(|ui| {
                            let accept = ui
                                .add_enabled(can_decide, egui::Button::new("Accept Primary"))
                                .on_hover_text(
                                    "Promote the selected exact name claim to the reviewed primary",
                                );
                            if accept.clicked() {
                                pending_review_action = selected_subject.cloned().map(|subject| {
                                    ReviewUiAction::Apply {
                                        subject: Box::new(subject),
                                        action: DecisionAction::AcceptPrimary,
                                    }
                                });
                            }
                            let keep_alias = ui
                                .add_enabled(can_decide, egui::Button::new("Keep as Alias"))
                                .on_hover_text(
                                    "Keep this selected existing name claim as an alternate; arbitrary new aliases are not invented",
                                );
                            if keep_alias.clicked() {
                                pending_review_action = selected_subject.cloned().map(|subject| {
                                    ReviewUiAction::Apply {
                                        subject: Box::new(subject),
                                        action: DecisionAction::KeepAlias,
                                    }
                                });
                            }
                            let reject = ui
                                .add_enabled(can_decide, egui::Button::new("Reject"))
                                .on_hover_text(
                                    "Reject this exact claim; a rationale is retained when supplied",
                                );
                            if reject.clicked() {
                                pending_review_action = selected_subject.cloned().map(|subject| {
                                    ReviewUiAction::Apply {
                                        subject: Box::new(subject),
                                        action: DecisionAction::Reject,
                                    }
                                });
                            }
                        });

                        ui.horizontal(|ui| {
                            let undo = ui
                                .add_enabled(can_undo && !review_busy, egui::Button::new("Undo"))
                                .on_hover_text("Undo review history (Ctrl+Z outside text fields)");
                            if undo.clicked() {
                                pending_review_action = Some(ReviewUiAction::Undo);
                            }
                            let redo = ui
                                .add_enabled(can_redo && !review_busy, egui::Button::new("Redo"))
                                .on_hover_text(
                                    "Redo review history (Ctrl+Shift+Z or Ctrl+Y outside text fields)",
                                );
                            if redo.clicked() {
                                pending_review_action = Some(ReviewUiAction::Redo);
                            }
                            ui.label(if dirty { "[UNSAVED]" } else { "[CLEAN]" });
                        });

                        ui.separator();
                        ui.label(RichText::new("Review sidecar").strong());
                        ui.add(
                            TextEdit::singleline(&mut self.review_destination)
                                .desired_width(ui.available_width()),
                        );
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Choose new...").clicked() {
                                let default = PathBuf::from(&self.review_destination);
                                let mut dialog = rfd::FileDialog::new()
                                    .set_title("Create a new ReSymbol review sidecar")
                                    .add_filter("ReSymbol review", &["json"]);
                                if let Some(parent) = default.parent() {
                                    dialog = dialog.set_directory(parent);
                                }
                                if let Some(name) =
                                    default.file_name().and_then(|name| name.to_str())
                                {
                                    dialog = dialog.set_file_name(name);
                                }
                                if let Some(path) = dialog.save_file() {
                                    self.review_destination =
                                        path.to_string_lossy().into_owned();
                                }
                            }
                            let destination = PathBuf::from(self.review_destination.trim());
                            let destination_is_known_existing =
                                persisted_path.as_ref() == Some(&destination);
                            let can_save = self.review.is_some()
                                && !review_busy
                                && !self.review_destination.trim().is_empty()
                                && !destination_is_known_existing;
                            let save = ui
                                .add_enabled(can_save, egui::Button::new("Save New"))
                                .on_hover_text(if destination_is_known_existing {
                                    "Choose a new path; the loaded or previously saved sidecar is never replaced"
                                } else {
                                    "Create a new sidecar; an existing path is never replaced"
                                });
                            if save.clicked() {
                                pending_review_action = Some(ReviewUiAction::Save(destination));
                            }
                            let can_load = self.review.is_some() && !review_busy && !dirty;
                            let load = ui
                                .add_enabled(can_load, egui::Button::new("Load..."))
                                .on_hover_text(if dirty {
                                    "Save unsaved decisions before loading another sidecar"
                                } else {
                                    "Load a strictly validated sidecar bound to this exact binary"
                                });
                            if load.clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .set_title("Load a ReSymbol review sidecar")
                                    .add_filter("ReSymbol review", &["json"])
                                    .pick_file()
                                {
                                    pending_review_action = Some(ReviewUiAction::Load(path));
                                }
                            }
                        });
                        if let Some(path) = persisted_path {
                            ui.small(format!("Last loaded/saved: {}", path.display()));
                        }
                        if self.review_operation.is_pending() {
                            ui.small("Review operation running on the bounded worker...");
                        }
                        if let Some(result) = &self.review_result {
                            match result {
                                Ok(message) => {
                                    ui.colored_label(colors.healthy, format!("[OK] {message}"));
                                }
                                Err(error) => {
                                    ui.colored_label(
                                        colors.destructive_quarantined,
                                        format!("[ERROR] {error}"),
                                    );
                                }
                            }
                        }
                    });
            });
        };
        if cfg!(feature = "screenshot") {
            panel.show(context, contents);
        } else {
            panel.show_animated(context, is_open, contents);
        }
        if let Some(action) = pending_review_action {
            self.apply_review_ui_action(action);
        }
    }

    fn show_activity_panel(&mut self, context: &egui::Context) {
        let colors = self.preferences.theme.semantic_colors();
        let panel = egui::TopBottomPanel::bottom("activity_and_diagnostics")
            .default_height(190.0)
            .height_range(110.0..=420.0)
            .resizable(true)
            .frame(
                egui::Frame::new()
                    .fill(colors.panel)
                    .stroke(egui::Stroke::new(1.0, colors.border))
                    .inner_margin(egui::Margin::same(8)),
            );
        let is_open = self.preferences.bottom_panel_open;
        let contents = |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                for tab in ActivityTab::ALL {
                    ui.selectable_value(&mut self.activity_tab, tab, tab.label());
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.small_button("Hide").clicked() {
                        self.preferences.bottom_panel_open = false;
                    }
                    let mut console_enabled = self.console_host.is_enabled();
                    let console_toggle = ui.add_enabled(
                        cfg!(target_os = "windows") && !cfg!(feature = "screenshot"),
                        egui::Checkbox::new(&mut console_enabled, "Companion console"),
                    );
                    if console_toggle.changed() {
                        self.set_console_enabled(console_enabled);
                    }
                });
            });
            ui.separator();
            match self.activity_tab {
                ActivityTab::Progress => self.show_progress(ui),
                ActivityTab::Plugins => self.show_plugin_list(ui),
                ActivityTab::Warnings => self.show_warnings(ui),
                ActivityTab::Log => self.show_log(ui),
            }
        };
        if cfg!(feature = "screenshot") {
            panel.show(context, contents);
        } else {
            panel.show_animated(context, is_open, contents);
        }
    }

    fn show_progress(&self, ui: &mut egui::Ui) {
        let colors = self.preferences.theme.semantic_colors();
        let (fraction, label, color) = if self.project_operation.is_pending() {
            (0.55, "Application service running", colors.inferred)
        } else if self.project.is_some() {
            (1.0, "Analysis completed", colors.exact_extracted)
        } else {
            (0.0, "Waiting for a binary", colors.fallback)
        };
        ui.label(RichText::new(format!("Stage: {label}")).strong());
        ui.add(
            egui::ProgressBar::new(fraction)
                .desired_width(ui.available_width())
                .text(format!("{label} - {:.0}%", fraction * 100.0))
                .fill(color),
        );
        ui.horizontal_wrapped(|ui| {
            let protection_complete = self
                .project
                .as_ref()
                .is_some_and(|project| project.protection_assessment.is_available());
            for (label, complete) in [
                ("Identity", self.project.is_some()),
                ("Base analysis", self.project.is_some()),
                ("Static address map", self.project.is_some()),
                ("Protection scan", protection_complete),
                ("Evidence projection", self.project.is_some()),
                ("Export preview", self.main_tab == MainTab::Exports),
            ] {
                let (cue, color) = if complete {
                    ("[OK]", colors.healthy)
                } else {
                    ("[--]", colors.fallback)
                };
                ui.label(RichText::new(format!("{cue} {label}")).color(color));
            }
        });
        ui.small("Analysis is bounded and runs off the UI event loop. Plugin execution remains disabled in this core-only slice.");
    }

    fn show_warnings(&self, ui: &mut egui::Ui) {
        let Some(project) = &self.project else {
            ui.label("No static findings or projection warnings until analysis completes");
            return;
        };
        let protection_findings = project.protection_assessment.findings();
        let protection_unavailable = project.protection_assessment.unavailable_reason();
        if protection_findings.is_empty()
            && protection_unavailable.is_none()
            && project.projection.warnings.is_empty()
        {
            ui.label("[OK] No static protection indicators or neutral-projection losses");
            return;
        }
        ScrollArea::vertical().show(ui, |ui| {
            if let Some(reason) = protection_unavailable {
                ui.label(
                    RichText::new(format!("[UNAVAILABLE] {reason}"))
                        .strong()
                        .color(self.preferences.theme.semantic_colors().warning_conflict),
                );
                ui.small("The package still provides a validated static address map; no executable bytes are embedded or inferred.");
            }
            if !protection_findings.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "Static protection indicators ({})",
                        protection_findings.len()
                    ))
                    .strong(),
                );
                ui.small(
                    "These are bounded artifact findings, not proof of intent or runtime behavior.",
                );
                for (finding_index, finding) in protection_findings.iter().enumerate() {
                    let (cue, color) = protection_severity_visual(
                        finding.severity,
                        self.preferences.theme.semantic_colors(),
                    );
                    ui.colored_label(
                        color,
                        RichText::new(format!("[{cue}] {}", finding.title)).strong(),
                    );
                    ui.indent(("protection-finding", finding_index), |ui| {
                        ui.label(&finding.summary);
                    });
                }
            }
            if (!protection_findings.is_empty() || protection_unavailable.is_some())
                && !project.projection.warnings.is_empty()
            {
                ui.separator();
            }
            if !project.projection.warnings.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "Neutral projection losses ({})",
                        project.projection.warnings.len()
                    ))
                    .strong(),
                );
            }
            for warning in &project.projection.warnings {
                ui.label(format!(
                    "[LOSS] {:?} x{} - {}",
                    warning.code, warning.occurrences, warning.message
                ));
            }
        });
    }

    fn show_log(&self, ui: &mut egui::Ui) {
        let colors = self.preferences.theme.semantic_colors();
        ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            for entry in &self.activity {
                let (prefix, color) = match entry.level {
                    ActivityLevel::Info => ("INFO", colors.secondary_text),
                    ActivityLevel::Success => ("OK", colors.healthy),
                    ActivityLevel::Warning => ("WARN", colors.warning_conflict),
                    ActivityLevel::Error => ("ERROR", colors.destructive_quarantined),
                };
                ui.colored_label(
                    color,
                    RichText::new(format!(
                        "[+{:07.2}s] [{prefix}] {}",
                        entry.elapsed_seconds, entry.message
                    ))
                    .monospace(),
                );
            }
        });
    }

    fn show_central(&mut self, context: &egui::Context) {
        let colors = self.preferences.theme.semantic_colors();
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(colors.canvas)
                    .inner_margin(egui::Margin::same(12)),
            )
            .show(context, |ui| {
                ui.horizontal_wrapped(|ui| {
                    for tab in MainTab::ALL {
                        if ui
                            .add_sized(
                                [112.0, 32.0],
                                egui::Button::selectable(self.main_tab == tab, tab.label())
                                    .corner_radius(4),
                            )
                            .clicked()
                        {
                            self.main_tab = tab;
                            self.stage = if tab == MainTab::Exports {
                                WorkflowStage::Export
                            } else if self.project.is_some() {
                                WorkflowStage::Review
                            } else {
                                WorkflowStage::Open
                            };
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if !self.preferences.right_panel_open
                            && ui.button("Show inspector").clicked()
                        {
                            self.preferences.right_panel_open = true;
                        }
                        if !self.preferences.left_panel_open && ui.button("Show project").clicked()
                        {
                            self.preferences.left_panel_open = true;
                        }
                        if !self.preferences.bottom_panel_open
                            && ui.button("Show activity").clicked()
                        {
                            self.preferences.bottom_panel_open = true;
                        }
                    });
                });
                ui.separator();

                if self.project.is_none() {
                    self.show_empty_state(ui, context);
                    return;
                }

                self.show_protection_banner(ui);
                ui.add_space(8.0);

                match self.main_tab {
                    MainTab::Overview => self.show_overview(ui),
                    MainTab::Functions => self.show_functions(ui),
                    MainTab::Types => self.show_types(ui),
                    MainTab::Relationships => self.show_relationships(ui),
                    MainTab::Graph => self.show_graph(ui),
                    MainTab::AddressSpace => self.show_address_space(ui),
                    MainTab::DebuggerSandbox => self.show_debugger_sandbox_readiness(ui),
                    MainTab::Exports => self.show_exports(ui),
                }
            });
    }

    fn show_protection_banner(&mut self, ui: &mut egui::Ui) {
        let Some(project) = self.project.as_ref() else {
            return;
        };
        let colors = self.preferences.theme.semantic_colors();
        let finding_count = project.protection_assessment.findings().len();
        let unavailable = project
            .protection_assessment
            .unavailable_reason()
            .map(ToOwned::to_owned);
        let needs_source = matches!(
            &project.protection_assessment,
            ProtectionAssessment::ExactSourceRequired
        );
        let mut verify_source = false;

        egui::Frame::new()
            .fill(colors.raised)
            .stroke(egui::Stroke::new(1.0, colors.warning_conflict))
            .inner_margin(egui::Margin::symmetric(10, 7))
            .corner_radius(4)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("[OFFLINE] No target code has executed")
                            .strong()
                            .color(colors.healthy),
                    );
                    if let Some(reason) = unavailable.as_deref() {
                        ui.label(RichText::new(reason).color(colors.warning_conflict));
                    } else if finding_count == 0 {
                        ui.label(
                            RichText::new(
                                "The bounded static scan found no supported protection indicators.",
                            )
                            .color(colors.secondary_text),
                        );
                    } else {
                        ui.label(
                            RichText::new(format!(
                                "{} static protection or anti-analysis indicator(s) require review",
                                finding_count
                            ))
                            .strong()
                            .color(colors.warning_conflict),
                        );
                        ui.label(
                            RichText::new(
                                "These bounded findings are evidence, not proof of intent or runtime behavior.",
                            )
                            .color(colors.secondary_text),
                        );
                    }
                    if needs_source
                        && ui
                            .add_enabled(
                                !self.project_operation.is_pending(),
                                egui::Button::new("Verify exact source..."),
                            )
                            .clicked()
                    {
                        verify_source = true;
                    }
                });
                ui.small(
                    "Live launch/attach is not performed here. Any future live action must use a separate acknowledgement bound to the exact target identity and execution policy.",
                );
            });

        if verify_source {
            let Some(path) = rfd::FileDialog::new()
                .set_title("Verify the exact original PE for this package")
                .add_filter("Windows binaries", &["exe", "dll", "sys"])
                .pick_file()
            else {
                return;
            };
            if let Err(error) = self.queue_source_verification(path) {
                self.log(ActivityLevel::Error, error);
            }
        }
    }

    fn show_empty_state(&mut self, ui: &mut egui::Ui, context: &egui::Context) {
        ui.with_layout(Layout::top_down_justified(Align::Center), |ui| {
            ui.add_space(70.0);
            ui.heading(if self.project_operation.is_pending() {
                "Analyzing exact binary bytes"
            } else {
                "Open a binary to begin"
            });
            ui.label(
                "Open a native Windows PE32+ x86-64 binary or a current ReSymbol package.",
            );
            ui.label("The workbench keeps identity, status, confidence, and provenance visible independently.");
            ui.add_space(18.0);
            if ui
                .add_enabled(
                    !self.project_operation.is_pending(),
                    egui::Button::new(if self.project_operation.is_pending() {
                        "Core analysis running..."
                    } else {
                        "Open Binary (Ctrl+O)"
                    }),
                )
                .clicked()
            {
                self.choose_binary(context);
            }
            ui.add_space(10.0);
            ui.small("You can also drag an .exe, .dll, .sys, or .resym file onto this window.");
        });
    }

    fn show_overview(&self, ui: &mut egui::Ui) {
        let project = self.project.as_ref().expect("checked by caller");
        let colors = self.preferences.theme.semantic_colors();
        ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Analysis overview");
            ui.label(
                RichText::new("Validated results for the exact active binary build")
                    .color(colors.secondary_text),
            );
            ui.label(
                RichText::new(project.identity.active_binary_path_display())
                    .monospace()
                    .small()
                    .color(colors.secondary_text),
            );
            ui.add_space(12.0);

            ui.columns(3, |columns| {
                summary_card(
                    &mut columns[0],
                    "Functions",
                    project.functions.len(),
                    colors.exact_extracted,
                    colors,
                );
                summary_card(
                    &mut columns[1],
                    "Globals",
                    project.projection.globals.len(),
                    colors.inferred,
                    colors,
                );
                summary_card(
                    &mut columns[2],
                    "Types",
                    project.projection.types.len(),
                    colors.plugin_provenance,
                    colors,
                );
            });
            ui.add_space(8.0);
            ui.columns(3, |columns| {
                summary_card(
                    &mut columns[0],
                    "Relationships",
                    project.projection.direct_calls.len()
                        + project.projection.thunks.len()
                        + project.projection.data_references.len(),
                    colors.healthy,
                    colors,
                );
                summary_card(
                    &mut columns[1],
                    "Protection indicators",
                    project.protection_assessment.findings().len(),
                    if project.protection_assessment.is_available()
                        && project.protection_assessment.findings().is_empty()
                    {
                        colors.healthy
                    } else {
                        colors.warning_conflict
                    },
                    colors,
                );
                summary_card(
                    &mut columns[2],
                    "Projection losses",
                    project.projection.warnings.len(),
                    if project.projection.warnings.is_empty() {
                        colors.healthy
                    } else {
                        colors.warning_conflict
                    },
                    colors,
                );
            });

            ui.add_space(14.0);
            ui.columns(2, |columns| {
                workbench_card(colors).show(&mut columns[0], |ui| {
                    ui.heading("Binary identity");
                    property_row(ui, "SHA-256", project.identity.sha256.as_str(), true);
                    property_row(ui, "Size", &format_bytes(project.identity.file_size), false);
                    property_row(ui, "Architecture", &project.identity.architecture, false);
                    property_row(
                        ui,
                        "Image base",
                        &format!("0x{:X}", project.identity.image_base),
                        true,
                    );
                    property_row(
                        ui,
                        "Image size",
                        &format_bytes(project.identity.image_size),
                        false,
                    );
                    if project.snapshot.has_verified_source() {
                        ui.label(
                            RichText::new("[EXACT] Source bytes verified and analyzed")
                                .color(colors.exact_extracted),
                        );
                    } else {
                        ui.label(
                            RichText::new(
                                "[BOUND] Package identity validated; executable bytes are not loaded",
                            )
                            .color(colors.warning_conflict),
                        );
                    }
                });

                workbench_card(colors).show(&mut columns[1], |ui| {
                    ui.heading("PE inventory");
                    match project.session().base_analysis() {
                        BinaryAnalysis::Pe(pe) => {
                            property_row(ui, "Sections", &pe.sections.len().to_string(), false);
                            property_row(ui, "Imports", &pe.imports.len().to_string(), false);
                            property_row(
                                ui,
                                "Delay imports",
                                &pe.delay_imports.len().to_string(),
                                false,
                            );
                            property_row(ui, "Exports", &pe.exports.len().to_string(), false);
                            property_row(
                                ui,
                                "Runtime functions",
                                &pe.runtime_functions.len().to_string(),
                                false,
                            );
                            property_row(
                                ui,
                                "Recovered strings",
                                &pe.strings.len().to_string(),
                                false,
                            );
                        }
                        _ => {
                            ui.label("No PE inventory is available for this format.");
                        }
                    };
                });
            });

            ui.add_space(14.0);
            ui.heading("PE sections");
            match project.session().base_analysis() {
                BinaryAnalysis::Pe(pe) => {
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .column(Column::initial(150.0).at_least(100.0))
                        .column(Column::initial(130.0).at_least(110.0))
                        .column(Column::initial(140.0).at_least(110.0))
                        .column(Column::remainder().at_least(180.0))
                        .header(30.0, |mut header| {
                            header.col(|ui| {
                                ui.strong("Name");
                            });
                            header.col(|ui| {
                                ui.strong("RVA");
                            });
                            header.col(|ui| {
                                ui.strong("Virtual size");
                            });
                            header.col(|ui| {
                                ui.strong("Characteristics");
                            });
                        })
                        .body(|mut body| {
                            for section in &pe.sections {
                                body.row(28.0, |mut row| {
                                    row.col(|ui| {
                                        ui.monospace(&section.name);
                                    });
                                    row.col(|ui| {
                                        ui.monospace(format!("0x{:08X}", section.virtual_address));
                                    });
                                    row.col(|ui| {
                                        ui.monospace(format!("0x{:X}", section.virtual_size));
                                    });
                                    row.col(|ui| {
                                        ui.monospace(format!("0x{:08X}", section.characteristics));
                                    });
                                });
                            }
                        });
                }
                _ => {
                    ui.label(
                        RichText::new("No section table is available.")
                            .color(colors.secondary_text),
                    );
                }
            }
        });
    }

    fn show_address_space(&mut self, ui: &mut egui::Ui) {
        let colors = self.preferences.theme.semantic_colors();

        ui.heading("Static address space");
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("[OFFLINE] No target code has executed")
                    .strong()
                    .color(colors.healthy),
            );
            ui.label(
                RichText::new("Preferred PE layout; live mappings may differ after load")
                    .color(colors.secondary_text),
            );
        });
        ui.add_space(8.0);

        self.show_offline_byte_reader(ui, colors);
        ui.add_space(8.0);

        let project = self.project.as_ref().expect("checked by caller");
        let address_space = &project.static_address_space;
        let indicator_text = project
            .protection_assessment
            .unavailable_reason()
            .map_or_else(
                || project.protection_assessment.findings().len().to_string(),
                |_| "source required".to_owned(),
            );

        egui::Frame::new()
            .fill(colors.raised)
            .stroke(egui::Stroke::new(1.0, colors.border))
            .inner_margin(egui::Margin::same(10))
            .corner_radius(4)
            .show(ui, |ui| {
                ui.columns(3, |columns| {
                    property_cell(
                        &mut columns[0],
                        "Preferred base",
                        &format!("0x{:016X}", address_space.preferred_image_base),
                        true,
                    );
                    property_cell(
                        &mut columns[1],
                        "Image size",
                        &format!("0x{:X}", address_space.image_size),
                        true,
                    );
                    property_cell(
                        &mut columns[2],
                        "Section / file align",
                        &format!(
                            "0x{:X} / 0x{:X}",
                            address_space.section_alignment, address_space.file_alignment
                        ),
                        true,
                    );
                });
                ui.add_space(8.0);
                ui.columns(3, |columns| {
                    property_cell(
                        &mut columns[0],
                        "Entry RVA",
                        &address_space.entry_point.map_or_else(
                            || "none".to_owned(),
                            |entry| format!("0x{:08X}", entry.get()),
                        ),
                        true,
                    );
                    property_cell(
                        &mut columns[1],
                        "Regions",
                        &address_space.regions().len().to_string(),
                        false,
                    );
                    property_cell(&mut columns[2], "Indicators", &indicator_text, false);
                });
            });

        let findings = project.protection_assessment.findings();
        if !findings.is_empty() {
            ui.add_space(8.0);
            egui::Frame::new()
                .fill(colors.raised)
                .stroke(egui::Stroke::new(1.0, colors.warning_conflict))
                .inner_margin(egui::Margin::symmetric(10, 7))
                .corner_radius(4)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} static protection indicator(s)",
                                findings.len()
                            ))
                            .strong()
                            .color(colors.warning_conflict),
                        );
                        for finding in findings.iter().take(3) {
                            let (cue, color) = protection_severity_visual(finding.severity, colors);
                            ui.colored_label(color, format!("[{cue}] {}", finding.title));
                        }
                        if findings.len() > 3 {
                            ui.label(format!("+{} more in Warnings", findings.len() - 3));
                        }
                    });
                });
        }

        ui.add_space(8.0);
        let available_height = ui.available_height().max(180.0);
        ScrollArea::horizontal()
            .id_salt("static-address-space-horizontal")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_min_width(870.0);
                TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .min_scrolled_height(available_height)
                    .column(Column::initial(170.0).at_least(120.0))
                    .column(Column::initial(195.0).at_least(160.0))
                    .column(Column::initial(165.0).at_least(145.0))
                    .column(Column::initial(165.0).at_least(130.0))
                    .column(Column::initial(75.0).at_least(65.0))
                    .column(Column::remainder().at_least(110.0))
                    .header(30.0, |mut header| {
                        header.col(|ui| {
                            ui.strong("Region");
                        });
                        header.col(|ui| {
                            ui.strong("RVA range");
                        });
                        header.col(|ui| {
                            ui.strong("Preferred VA");
                        });
                        header.col(|ui| {
                            ui.strong("File backing");
                        });
                        header.col(|ui| {
                            ui.strong("Access");
                        });
                        header.col(|ui| {
                            ui.strong("Tail");
                        });
                    })
                    .body(|mut body| {
                        for region in address_space.regions() {
                            body.row(30.0, |mut row| {
                                row.col(|ui| {
                                    ui.monospace(static_region_name(&region.kind));
                                });
                                row.col(|ui| {
                                    ui.monospace(format!(
                                        "0x{:08X}..0x{:08X}",
                                        region.range.start().get(),
                                        region.range.end()
                                    ));
                                });
                                row.col(|ui| {
                                    let preferred = address_space
                                        .preferred_virtual_address(region.range.start())
                                        .expect("validated preferred range");
                                    ui.monospace(format!("0x{preferred:016X}"));
                                });
                                row.col(|ui| {
                                    if let Some(backing) = region.file_backing {
                                        ui.monospace(format!(
                                            "0x{:X}..0x{:X}",
                                            backing.offset,
                                            backing.offset + backing.size
                                        ));
                                    } else {
                                        ui.label(
                                            RichText::new("unbacked").color(colors.secondary_text),
                                        );
                                    }
                                });
                                row.col(|ui| {
                                    ui.monospace(memory_access_text(region.access));
                                });
                                row.col(|ui| match &region.kind {
                                    StaticRegionKind::ImageGap => {
                                        ui.label(
                                            RichText::new("unowned gap")
                                                .color(colors.secondary_text),
                                        );
                                    }
                                    _ if region.zero_fill_size() != 0
                                        || region.mapped_padding_size() != 0 =>
                                    {
                                        let zero_fill = region.zero_fill_size();
                                        let mapped_padding = region.mapped_padding_size();
                                        let detail = match (zero_fill, mapped_padding) {
                                            (0, padding) => {
                                                format!("0x{padding:X} mapped padding")
                                            }
                                            (zeroes, 0) => format!("0x{zeroes:X} zero-fill"),
                                            (zeroes, padding) => format!(
                                                "0x{zeroes:X} zero-fill + 0x{padding:X} padding"
                                            ),
                                        };
                                        ui.monospace(detail);
                                    }
                                    _ => {
                                        ui.label(
                                            RichText::new("fully backed").color(colors.healthy),
                                        );
                                    }
                                });
                            });
                        }
                    });
            });
    }

    fn show_offline_byte_reader(&mut self, ui: &mut egui::Ui, colors: SemanticColors) {
        let source_ready = self
            .project
            .as_ref()
            .and_then(OfflineSourceBinding::from_project)
            .is_some();
        let pending = self.offline_read.is_pending();
        let presentation = self.offline_read.presentation.clone();
        let can_queue = source_ready
            && !pending
            && !self.worker_disconnected
            && !self.project_operation.is_pending();
        let mut queue_requested = false;

        egui::Frame::new()
            .fill(colors.raised)
            .stroke(egui::Stroke::new(1.0, colors.border))
            .inner_margin(egui::Margin::same(10))
            .corner_radius(4)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("Exact offline bytes")
                            .strong()
                            .color(colors.exact_extracted),
                    );
                    ui.label(
                        RichText::new(
                            "Frozen verified source bytes through the in-process offline host; no process, live mapping, or sandbox is created.",
                        )
                        .color(colors.secondary_text),
                    );
                });
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("RVA (hex)").strong());
                    ui.add_enabled(
                        !pending,
                        TextEdit::singleline(&mut self.offline_read_rva_input)
                            .id_salt("offline_read_rva")
                            .desired_width(150.0)
                            .char_limit(18)
                            .hint_text("0x00000000"),
                    );
                    ui.add_enabled_ui(!pending, |ui| {
                        egui::ComboBox::from_id_salt("offline_read_size")
                            .selected_text(format!("{} bytes", self.offline_read_size))
                            .show_ui(ui, |ui| {
                                for size in OFFLINE_READ_SIZES {
                                    ui.selectable_value(
                                        &mut self.offline_read_size,
                                        size,
                                        format!("{size} bytes"),
                                    );
                                }
                            });
                    });
                    let button_label = if !source_ready {
                        "[SOURCE REQUIRED]"
                    } else if self.worker_disconnected {
                        "[WORKER UNAVAILABLE]"
                    } else if pending {
                        "[READING...]"
                    } else {
                        "Read frozen bytes"
                    };
                    queue_requested = ui
                        .add_enabled(can_queue, egui::Button::new(button_label))
                        .clicked();
                    if pending {
                        ui.spinner();
                    }
                });

                if let Some(presentation) = presentation {
                    ui.add_space(7.0);
                    match presentation {
                        OfflineReadPresentation::Error(error) => {
                            ui.colored_label(
                                colors.destructive_quarantined,
                                format!("[FAILED CLOSED] {error}"),
                            );
                        }
                        OfflineReadPresentation::Outcome(outcome) => {
                            match outcome.availability() {
                                OfflineImageReadAvailability::Available { bytes } => {
                                    ui.colored_label(
                                        colors.healthy,
                                        offline_read_banner(
                                            OfflineReadDisplay::Available {
                                                byte_count: bytes.len(),
                                            },
                                            outcome.span().rva(),
                                        ),
                                    );
                                    ui.label(
                                        RichText::new(offline_lifecycle_text(&outcome))
                                            .color(colors.secondary_text),
                                    );
                                    ScrollArea::both()
                                        .id_salt("offline_hex_rows_scroll")
                                        .auto_shrink([false, true])
                                        .max_height(124.0)
                                        .show(ui, |ui| {
                                            egui::Grid::new("offline_hex_rows")
                                                .num_columns(3)
                                                .spacing([12.0, 2.0])
                                                .striped(true)
                                                .show(ui, |ui| {
                                                    for row in format_offline_hex_rows(
                                                        outcome.span().rva(),
                                                        bytes,
                                                    ) {
                                                        ui.monospace(format!(
                                                            "0x{:016X}",
                                                            row.rva
                                                        ));
                                                        ui.monospace(row.hex);
                                                        ui.monospace(format!("|{}|", row.ascii));
                                                        ui.end_row();
                                                    }
                                                });
                                        });
                                }
                                OfflineImageReadAvailability::Unavailable(unavailable) => {
                                    ui.colored_label(
                                        colors.warning_conflict,
                                        offline_read_banner(
                                            OfflineReadDisplay::Unavailable {
                                                code: unavailable.code(),
                                                detail: unavailable.detail(),
                                            },
                                            outcome.span().rva(),
                                        ),
                                    );
                                    ui.label(
                                        RichText::new(offline_lifecycle_text(&outcome))
                                            .color(colors.secondary_text),
                                    );
                                }
                            }
                        }
                    }
                }
            });

        if queue_requested {
            if let Err(error) = self.queue_offline_image_read() {
                let error = bounded_message(error);
                self.offline_read.present_error(error.clone());
                self.log(
                    ActivityLevel::Error,
                    format!("Cannot queue offline image read: {error}"),
                );
            }
        }
    }

    fn show_functions(&mut self, ui: &mut egui::Ui) {
        let Some(project) = &self.project else {
            return;
        };
        let colors = self.preferences.theme.semantic_colors();
        egui::Frame::new()
            .fill(colors.raised)
            .stroke(egui::Stroke::new(1.0, colors.border))
            .inner_margin(egui::Margin::symmetric(10, 6))
            .corner_radius(4)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Search").strong());
                    ui.add(
                        TextEdit::singleline(&mut self.function_filter.search)
                            .id_salt("function_search")
                            .desired_width(300.0)
                            .hint_text("name, RVA, status, or source"),
                    );
                    egui::ComboBox::from_id_salt("function_status_filter")
                        .selected_text(if self.function_filter.statuses.is_empty() {
                            "All statuses".to_owned()
                        } else {
                            format!("{} status filter(s)", self.function_filter.statuses.len())
                        })
                        .show_ui(ui, |ui| {
                            if ui.button("All statuses").clicked() {
                                self.function_filter.statuses.clear();
                            }
                            for status in all_function_statuses() {
                                let mut selected = self.function_filter.statuses.contains(&status);
                                if ui.checkbox(&mut selected, status.label()).changed() {
                                    if selected {
                                        self.function_filter.statuses.insert(status);
                                    } else {
                                        self.function_filter.statuses.remove(&status);
                                    }
                                }
                            }
                        });
                    if (!self.function_filter.search.is_empty()
                        || !self.function_filter.statuses.is_empty())
                        && ui.button("Clear filter").clicked()
                    {
                        self.function_filter = FunctionFilter::default();
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{} total", project.functions.len()))
                                .color(colors.secondary_text),
                        );
                    });
                });
            });

        let visible = project.visible_function_indices(&self.function_filter, self.function_sort);
        ui.label(
            RichText::new(format!(
                "Showing {} of {} functions",
                visible.len(),
                project.functions.len()
            ))
            .small()
            .color(colors.secondary_text),
        );
        let mut selected = None;
        let mut sort = self.function_sort;
        let available_height = ui.available_height();
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .min_scrolled_height(available_height)
            .column(Column::initial(145.0).at_least(125.0))
            .column(Column::initial(105.0).at_least(95.0))
            .column(Column::remainder().at_least(180.0))
            .column(Column::initial(145.0).at_least(120.0))
            .column(Column::initial(175.0).at_least(130.0))
            .column(Column::initial(90.0).at_least(75.0))
            .header(30.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Status");
                });
                header.col(|ui| sort_header(ui, "RVA", FunctionSortKey::Rva, &mut sort));
                header.col(|ui| {
                    sort_header(ui, "Reconstructed name", FunctionSortKey::Name, &mut sort)
                });
                header.col(|ui| {
                    sort_header(ui, "Confidence", FunctionSortKey::Confidence, &mut sort)
                });
                header.col(|ui| sort_header(ui, "Source", FunctionSortKey::Source, &mut sort));
                header.col(|ui| sort_header(ui, "Size", FunctionSortKey::Size, &mut sort));
            })
            .body(|body| {
                body.rows(28.0, visible.len(), |mut table_row| {
                    let row_index = visible[table_row.index()];
                    let row = &project.functions[row_index];
                    table_row
                        .set_selected(self.selected_projection_index == Some(row.projection_index));
                    table_row.col(|ui| {
                        if status_badge(ui, row.status, colors).clicked() {
                            selected = Some(row.projection_index);
                        }
                    });
                    table_row.col(|ui| {
                        if ui
                            .selectable_label(
                                false,
                                RichText::new(format!("0x{:08X}", row.rva)).monospace(),
                            )
                            .clicked()
                        {
                            selected = Some(row.projection_index);
                        }
                    });
                    table_row.col(|ui| {
                        if ui
                            .selectable_label(false, RichText::new(&row.display_name).monospace())
                            .clicked()
                        {
                            selected = Some(row.projection_index);
                        }
                    });
                    table_row.col(|ui| {
                        if let Some(confidence) = row.confidence {
                            ui.add(
                                egui::ProgressBar::new(confidence as f32)
                                    .desired_width(ui.available_width())
                                    .text(format!("{:.0}%", confidence * 100.0))
                                    .fill(status_color(row.status, colors)),
                            );
                        } else {
                            ui.label("--");
                        }
                    });
                    table_row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&row.source).color(colors.secondary_text),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&row.source);
                    });
                    table_row.col(|ui| {
                        ui.label(
                            RichText::new(
                                row.size
                                    .map_or_else(|| "--".to_owned(), |size| format!("0x{size:X}")),
                            )
                            .monospace(),
                        );
                    });
                });
            });
        self.function_sort = sort;
        if let Some(index) = selected {
            self.selected_projection_index = Some(index);
            self.graph_root_rva = project.functions.get(index).map(|row| row.rva);
        }
    }

    fn show_types(&self, ui: &mut egui::Ui) {
        let project = self.project.as_ref().expect("checked by caller");
        let colors = self.preferences.theme.semantic_colors();
        ui.heading("Recovered types");
        ui.label(
            RichText::new(format!(
                "{} projected type candidate(s)",
                project.projection.types.len()
            ))
            .color(colors.secondary_text),
        );
        ui.add_space(8.0);
        if project.projection.types.is_empty() {
            empty_result(ui, "No type claims are present in this analysis.", colors);
            return;
        }
        let available_height = ui.available_height();
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .min_scrolled_height(available_height)
            .column(Column::initial(220.0).at_least(150.0))
            .column(Column::initial(240.0).at_least(160.0))
            .column(Column::remainder().at_least(220.0))
            .header(30.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Type key");
                });
                header.col(|ui| {
                    ui.strong("Selected name");
                });
                header.col(|ui| {
                    ui.strong("Definitions and alternatives");
                });
            })
            .body(|mut body| {
                for value in &project.projection.types {
                    body.row(28.0, |mut row| {
                        row.col(|ui| {
                            ui.monospace(&value.key);
                        });
                        row.col(|ui| {
                            ui.monospace(
                                value
                                    .selected_name
                                    .as_ref()
                                    .map_or("--", |name| name.source.text.as_str()),
                            );
                        });
                        row.col(|ui| {
                            ui.label(format!(
                                "{} definition(s) - {} alternate name(s)",
                                value.definitions.len(),
                                value.alternate_names.len()
                            ));
                        });
                    });
                }
            });
    }

    fn show_relationships(&self, ui: &mut egui::Ui) {
        let project = self.project.as_ref().expect("checked by caller");
        let colors = self.preferences.theme.semantic_colors();
        ui.heading("Recovered relationships");
        ui.label(
            RichText::new("Attributed control-flow and data-reference inventory")
                .color(colors.secondary_text),
        );
        ui.add_space(8.0);
        ui.columns(3, |columns| {
            summary_card(
                &mut columns[0],
                "Direct calls",
                project.projection.direct_calls.len(),
                colors.inferred,
                colors,
            );
            summary_card(
                &mut columns[1],
                "Thunks",
                project.projection.thunks.len(),
                colors.plugin_provenance,
                colors,
            );
            summary_card(
                &mut columns[2],
                "Data references",
                project.projection.data_references.len(),
                colors.exact_extracted,
                colors,
            );
        });
        ui.add_space(10.0);
        if project.projection.direct_calls.is_empty()
            && project.projection.thunks.is_empty()
            && project.projection.data_references.is_empty()
        {
            empty_result(
                ui,
                "No relationships were retained in this projection.",
                colors,
            );
            return;
        }
        ScrollArea::vertical().show(ui, |ui| {
            if !project.projection.direct_calls.is_empty() {
                ui.label(RichText::new("Direct calls").strong());
                for call in &project.projection.direct_calls {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("[CALL]").color(colors.inferred));
                        ui.monospace(format!(
                            "0x{:08X} + site 0x{:08X}",
                            call.caller_rva, call.call_site_rva
                        ));
                        ui.label("to");
                        ui.monospace(control_flow_target(&call.target));
                    });
                }
                ui.separator();
            }
            if !project.projection.thunks.is_empty() {
                ui.label(RichText::new("Thunks").strong());
                for thunk in &project.projection.thunks {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("[THUNK]").color(colors.plugin_provenance));
                        ui.monospace(format!("0x{:08X}", thunk.rva));
                        ui.label("jumps to");
                        ui.monospace(control_flow_target(&thunk.target));
                    });
                }
                ui.separator();
            }
            if !project.projection.data_references.is_empty() {
                ui.label(RichText::new("Data references").strong());
                for reference in &project.projection.data_references {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("[DATA]").color(colors.exact_extracted));
                        ui.monospace(format!("0x{:08X}", reference.instruction_rva));
                        ui.label("references");
                        ui.monospace(format!("0x{:08X}", reference.target_rva));
                        if let Some(string_rva) = reference.referenced_string_rva {
                            ui.label(
                                RichText::new(format!("string @ 0x{string_rva:08X}"))
                                    .color(colors.healthy),
                            );
                        }
                    });
                }
            }
        });
    }

    fn show_graph(&mut self, ui: &mut egui::Ui) {
        let (Some(project), Some(graph_index)) = (&self.project, &self.reconstruction_graph) else {
            return;
        };
        let colors = self.preferences.theme.semantic_colors();
        let default_root = graph_index.default_root();
        let default_rva = default_root.map(|root| root.rva);
        let entry_rva = default_root
            .filter(|root| root.kind == GraphRootKind::EntryPoint)
            .map(|root| root.rva);
        let root_rva = self
            .graph_root_rva
            .filter(|rva| project.functions.iter().any(|row| row.rva == *rva))
            .or(default_rva)
            .or_else(|| project.functions.first().map(|row| row.rva));
        let Some(root_rva) = root_rva else {
            empty_result(ui, "No projected functions are available to graph.", colors);
            return;
        };
        let selected_rva = self
            .selected_projection_index
            .and_then(|index| project.functions.get(index))
            .map(|row| row.rva);
        let graph = graph_index.view(root_rva);
        let root_name = graph
            .nodes
            .iter()
            .find(|node| node.node.id == GraphNodeId::Function(root_rva))
            .map(|node| node.node.name.clone());

        ui.horizontal(|ui| {
            ui.heading("Binary reconstruction graph");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Functions table").clicked() {
                    self.main_tab = MainTab::Functions;
                }
                if ui
                    .add_enabled(
                        selected_rva.is_some() && selected_rva != Some(root_rva),
                        egui::Button::new("Focus selected"),
                    )
                    .clicked()
                {
                    self.graph_root_rva = selected_rva;
                }
                if ui
                    .add_enabled(
                        entry_rva.is_some() && entry_rva != Some(root_rva),
                        egui::Button::new("PE entry point"),
                    )
                    .clicked()
                {
                    self.graph_root_rva = entry_rva;
                }
                if ui
                    .add_enabled(
                        default_rva != Some(root_rva),
                        egui::Button::new("Reset root"),
                    )
                    .clicked()
                {
                    self.graph_root_rva = default_rva;
                }
            });
        });
        ui.label(
            RichText::new(
                "Only retained calls, thunk targets, and import slots are connected; proximity never invents an edge.",
            )
            .color(colors.secondary_text),
        );
        ui.add_space(8.0);

        egui::Frame::new()
            .fill(colors.raised)
            .stroke(egui::Stroke::new(1.0, colors.border))
            .inner_margin(egui::Margin::symmetric(12, 8))
            .corner_radius(4)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let cue = if entry_rva == Some(root_rva) {
                        "[PE ENTRY]"
                    } else if default_rva == Some(root_rva) {
                        "[LOWEST-RVA ROOT]"
                    } else {
                        "[FUNCTION FOCUS]"
                    };
                    ui.label(RichText::new(cue).strong().color(colors.exact_extracted));
                    if let Some(name) = &root_name {
                        ui.label(RichText::new(name).strong().monospace());
                    }
                    ui.label(
                        RichText::new(format!("0x{root_rva:08X}"))
                            .monospace()
                            .color(colors.secondary_text),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{} node(s) - {} retained edge(s)",
                            graph.nodes.len(),
                            graph.edges.len()
                        ))
                        .color(colors.secondary_text),
                    );
                    if graph.is_truncated() {
                        ui.label(
                            RichText::new(format!(
                                "[BOUNDED] +{} frontier node(s), +{} edge(s) omitted (limits: {GRAPH_MAX_NODES} nodes / {GRAPH_MAX_EDGES} edges / {GRAPH_MAX_DEPTH} tiers)",
                                graph.omitted_node_count, graph.omitted_edge_count,
                            ))
                            .color(colors.warning_conflict),
                        );
                    }
                });
                if default_rva == Some(root_rva)
                    && default_root.is_some_and(|root| {
                        root.kind == GraphRootKind::LowestProjectedFunction
                    })
                {
                    ui.label(
                        RichText::new(
                            "The PE entry point is not a projected function; this deterministic lowest-RVA root is a navigation fallback, not an inferred main().",
                        )
                        .color(colors.warning_conflict),
                    );
                }
            });

        ui.add_space(8.0);
        let (clicked_index, focused_rva) =
            show_function_graph_canvas(ui, &graph, root_rva, entry_rva, selected_rva, colors);
        if let Some(index) = clicked_index {
            self.selected_projection_index = Some(index);
        }
        if let Some(rva) = focused_rva {
            self.graph_root_rva = Some(rva);
        }
    }

    fn show_debugger_sandbox_readiness(&mut self, ui: &mut egui::Ui) {
        let Some(project) = self.project.as_ref() else {
            return;
        };
        let colors = self.preferences.theme.semantic_colors();
        let evidence = DebuggerReadinessEvidence::from_project(project);
        let binary_name = project.identity.display_name.clone();
        let binary_path = project.identity.active_binary_path_display();

        ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Debugger / Sandbox readiness");
            ui.label(
                RichText::new(
                    "Read-only provider discovery bound to the exact active binary and static protection evidence",
                )
                .color(colors.secondary_text),
            );
            ui.add_space(10.0);

            egui::Frame::new()
                .fill(colors.raised)
                .stroke(egui::Stroke::new(1.0, colors.warning_conflict))
                .inner_margin(egui::Margin::same(12))
                .corner_radius(4)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("[NON-EXECUTING] Discovery only")
                            .strong()
                            .color(colors.healthy),
                    );
                    ui.label(
                        "This tab cannot open, attach, launch, resume, or modify a target. It cannot create an AppContainer profile or VM, activate a provider, or produce an attestation.",
                    );
                    ui.label(
                        RichText::new(
                            "A ready result permits only a future provisioning attempt. It is not a containment guarantee.",
                        )
                        .strong()
                        .color(colors.warning_conflict),
                    );
                });

            ui.add_space(12.0);
            ui.heading("Requested provider");
            ui.label(
                RichText::new(
                    "Selecting a provider changes only this request. ReSymbol never substitutes another provider.",
                )
                .color(colors.secondary_text),
            );
            let mut requested_choice = self.readiness_choice;
            ui.horizontal_wrapped(|ui| {
                for choice in SandboxProviderChoice::ALL {
                    ui.selectable_value(
                        &mut requested_choice,
                        choice,
                        format!("{} - {}", choice.label(), choice.boundary_label()),
                    );
                }
            });
            if requested_choice != self.readiness_choice {
                self.select_sandbox_provider(requested_choice);
            }

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                let pending = self.readiness_operation.is_pending();
                if ui
                    .add_enabled(
                        !pending,
                        egui::Button::new(if pending {
                            "Read-only check running..."
                        } else {
                            "Run read-only readiness check"
                        }),
                    )
                    .clicked()
                {
                    if let Err(error) = self.queue_sandbox_readiness_probe() {
                        self.readiness_error = Some(error.clone());
                        self.log(ActivityLevel::Error, error);
                    }
                }
                ui.label(
                    RichText::new(format!(
                        "Exact request: {} / {}",
                        self.readiness_choice.label(),
                        self.readiness_choice.boundary_label()
                    ))
                    .monospace()
                    .color(colors.secondary_text),
                );
            });

            ui.add_space(10.0);
            ui.columns(2, |columns| {
                workbench_card(colors).show(&mut columns[0], |ui| {
                    ui.heading("Current binary binding");
                    property_row(ui, "File", &binary_name, false);
                    property_row(ui, "SHA-256", evidence.binary_id().as_str(), true);
                    property_row(ui, "Size", &format_bytes(evidence.file_size()), false);
                    ui.label(
                        RichText::new(evidence.source_status().label())
                            .color(colors.exact_extracted),
                    );
                    ui.label(
                        RichText::new(binary_path)
                            .small()
                            .monospace()
                            .color(colors.secondary_text),
                    );
                });
                workbench_card(colors).show(&mut columns[1], |ui| {
                    ui.heading("Static protection evidence");
                    let (cue, color) = match evidence.protection_status() {
                        ReadinessProtectionStatus::Available {
                            findings: 0,
                            requires_acknowledgement: false,
                        } => ("[AVAILABLE]", colors.healthy),
                        ReadinessProtectionStatus::Available { .. } => {
                            ("[REVIEW]", colors.warning_conflict)
                        }
                        ReadinessProtectionStatus::ExactSourceRequired
                        | ReadinessProtectionStatus::UnsupportedFormat => {
                            ("[UNAVAILABLE]", colors.warning_conflict)
                        }
                    };
                    ui.label(RichText::new(cue).strong().color(color));
                    ui.label(evidence.protection_status().label());
                    ui.label(
                        RichText::new(
                            "Protection findings are offline evidence, not permission to execute.",
                        )
                        .color(colors.secondary_text),
                    );
                });
            });

            if let Some(error) = &self.readiness_error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!("[FAIL CLOSED] {error}"))
                        .color(colors.destructive_quarantined),
                );
            }

            ui.add_space(12.0);
            if let Some(outcome) = &self.readiness_outcome {
                show_sandbox_readiness_outcome(ui, outcome, colors);
            } else if !self.readiness_operation.is_pending() && self.readiness_error.is_none() {
                ui.label(
                    RichText::new(
                        "No readiness observation for this provider and binary evidence snapshot.",
                    )
                    .color(colors.secondary_text),
                );
            }
        });
    }

    fn show_exports(&mut self, ui: &mut egui::Ui) {
        let Some(project) = &self.project else {
            return;
        };
        let colors = self.preferences.theme.semantic_colors();
        let mut queued_export = None;
        ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Validated export");
            ui.label(
                RichText::new(
                    "Preview target capabilities and losses before creating a new artifact.",
                )
                .color(colors.secondary_text),
            );
            ui.add_space(10.0);

            egui::Frame::new()
                .fill(colors.raised)
                .stroke(egui::Stroke::new(1.0, colors.border))
                .inner_margin(egui::Margin::same(14))
                .corner_radius(4)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("[READY] Export preview")
                                .strong()
                                .color(colors.healthy),
                        );
                        ui.label(
                            RichText::new(self.export_kind.label())
                                .color(colors.secondary_text),
                        );
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Format").strong());
                        let previous = self.export_kind;
                        egui::ComboBox::from_id_salt("export_kind")
                            .selected_text(self.export_kind.label())
                            .show_ui(ui, |ui| {
                                for kind in ExportKind::ALL {
                                    ui.selectable_value(
                                        &mut self.export_kind,
                                        kind,
                                        kind.label(),
                                    );
                                }
                            });
                        if self.export_kind != previous {
                            self.export_destination =
                                default_export_path(project, self.export_kind)
                                    .to_string_lossy()
                                    .into_owned();
                            self.export_result = None;
                        }
                        ui.label(
                            RichText::new(export_kind_description(self.export_kind))
                                .color(colors.secondary_text),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Destination").strong());
                        let destination_width = (ui.available_width() - 100.0).max(260.0);
                        ui.add(
                            TextEdit::singleline(&mut self.export_destination)
                                .desired_width(destination_width),
                        );
                        if ui.button("Choose...").clicked() {
                            let default = PathBuf::from(&self.export_destination);
                            let mut dialog = rfd::FileDialog::new()
                                .set_title("Choose a new export destination");
                            if let Some(parent) = default.parent() {
                                dialog = dialog.set_directory(parent);
                            }
                            if let Some(name) =
                                default.file_name().and_then(|name| name.to_str())
                            {
                                dialog = dialog.set_file_name(name);
                            }
                            if let Some(path) = dialog.save_file() {
                                self.export_destination = path.to_string_lossy().into_owned();
                            }
                        }
                    });
                    ui.label(
                        RichText::new(format!(
                            "[EXACT] Target SHA-256 {}",
                            project.identity.sha256
                        ))
                        .monospace()
                        .small()
                        .color(colors.exact_extracted),
                    );
                });

            ui.add_space(12.0);
            ui.columns(4, |columns| {
                summary_card(
                    &mut columns[0],
                    "Functions",
                    project.projection.functions.len(),
                    colors.exact_extracted,
                    colors,
                );
                summary_card(
                    &mut columns[1],
                    "Globals",
                    project.projection.globals.len(),
                    colors.inferred,
                    colors,
                );
                summary_card(
                    &mut columns[2],
                    "Types",
                    project.projection.types.len(),
                    colors.plugin_provenance,
                    colors,
                );
                summary_card(
                    &mut columns[3],
                    "Losses",
                    project.projection.warnings.len(),
                    colors.warning_conflict,
                    colors,
                );
            });

            ui.add_space(12.0);
            ui.columns(2, |columns| {
                workbench_card(colors).show(&mut columns[0], |ui| {
                    ui.heading("Target capability");
                    ui.label(RichText::new(self.export_kind.label()).strong());
                    ui.label(export_kind_description(self.export_kind));
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("[SAFE] Create-new only; existing files are never replaced")
                            .color(colors.healthy),
                    );
                    ui.label(
                        RichText::new("Uses the same validated projection as the CLI")
                            .color(colors.secondary_text),
                    );
                });

                workbench_card(colors).show(&mut columns[1], |ui| {
                    ui.heading("Projection losses");
                    if project.projection.warnings.is_empty() {
                        ui.label(
                            RichText::new("[OK] No neutral-projection losses")
                                .color(colors.healthy),
                        );
                    } else {
                        let mut grouped = BTreeMap::<String, u64>::new();
                        for warning in &project.projection.warnings {
                            *grouped.entry(format!("{:?}", warning.code)).or_default() +=
                                warning.occurrences;
                        }
                        for (code, occurrences) in grouped {
                            ui.label(
                                RichText::new(format!("[WARN] {code}: {occurrences}"))
                                    .color(colors.warning_conflict),
                            );
                        }
                    }
                });
            });

            ui.add_space(12.0);
            let exact_source_ready = project.snapshot.has_verified_source();
            let can_export = !self.export_operation.is_pending()
                && !self.project_operation.is_pending()
                && !self.review_operation.is_pending()
                && (self.export_kind != ExportKind::Pdb || exact_source_ready);
            let action_label = if self.export_operation.is_pending() {
                "Exporting...".to_owned()
            } else if self.project_operation.is_pending() {
                "Project operation running...".to_owned()
            } else {
                format!("Create {} artifact", self.export_kind.label())
            };
            let write = ui.add_enabled(
                can_export,
                egui::Button::new(RichText::new(action_label).strong())
                    .min_size(egui::vec2(ui.available_width(), 38.0))
                    .fill(colors.selection)
                    .stroke(egui::Stroke::new(1.0, colors.exact_extracted))
                    .corner_radius(4),
            );
            if self.export_kind == ExportKind::Pdb && !exact_source_ready {
                ui.label(
                    RichText::new(
                        "[SOURCE REQUIRED] Verify the exact original PE before creating a PDB.",
                    )
                    .color(colors.warning_conflict),
                );
            }
            if write.clicked() {
                queued_export = Some((
                    self.export_kind,
                    PathBuf::from(&self.export_destination),
                ));
            }
            if let Some(result) = &self.export_result {
                match result {
                    Ok(message) => ui.colored_label(colors.healthy, format!("[OK] {message}")),
                    Err(error) => ui.colored_label(
                        colors.destructive_quarantined,
                        format!("[ERROR] {error}"),
                    ),
                };
            }
            ui.small("Rendering and create-new staged publication run on the bounded application-service worker, never the egui event loop.");
        });
        if let Some((kind, path)) = queued_export {
            if let Err(error) = self.queue_export(kind, path) {
                self.export_result = Some(Err(error.clone()));
                self.log(ActivityLevel::Error, format!("Export failed: {error}"));
            }
        }
    }
}

impl eframe::App for WorkbenchApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        #[cfg(feature = "screenshot")]
        context.input_mut(|input| {
            // Visual captures are evidence artifacts, not interactive sessions. Discard the
            // host cursor before laying out widgets so hover highlights and scrollbar handles
            // cannot make otherwise identical captures depend on its desktop position.
            input.pointer = egui::PointerState::default();
        });
        self.preferences.theme.apply(context);
        self.poll_console(context);
        self.poll_service_worker(context);
        if context.input(|input| input.viewport().close_requested()) && !self.request_close(context)
        {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        self.handle_inputs(context);
        self.show_header(context);
        self.show_project_panel(context);
        self.show_inspector(context);
        self.show_activity_panel(context);
        self.show_central(context);
        self.show_close_confirmation(context);

        #[cfg(feature = "screenshot")]
        self.advance_screenshot_capture(context);
        if !cfg!(feature = "screenshot")
            && (self.project_operation.is_pending()
                || self.export_operation.is_pending()
                || self.review_operation.is_pending()
                || self.readiness_operation.is_pending()
                || self.offline_read.is_pending()
                || self.console_host.is_enabled())
        {
            context.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        self.preferences
            .theme
            .semantic_colors()
            .canvas
            .to_normalized_gamma_f32()
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, STORAGE_KEY, &self.preferences);
    }
}

fn show_sandbox_readiness_outcome(
    ui: &mut egui::Ui,
    outcome: &DebuggerReadinessOutcome,
    colors: SemanticColors,
) {
    let report = outcome.report();
    let (status, status_color) = match report.readiness() {
        SandboxProviderReadiness::ReadyForProvisioningAttempt => {
            ("READY FOR PROVISIONING ATTEMPT", colors.healthy)
        }
        SandboxProviderReadiness::Unavailable => ("UNAVAILABLE", colors.warning_conflict),
        SandboxProviderReadiness::Indeterminate => ("INDETERMINATE", colors.warning_conflict),
    };

    egui::Frame::new()
        .fill(colors.raised)
        .stroke(egui::Stroke::new(1.0, status_color))
        .inner_margin(egui::Margin::same(12))
        .corner_radius(4)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!("[{status}]"))
                        .strong()
                        .color(status_color),
                );
                ui.label(
                    RichText::new(provider_selection_label(report.provider()))
                        .strong()
                        .monospace(),
                );
                ui.label(
                    RichText::new(isolation_boundary_label(report.required_boundary()))
                        .color(colors.secondary_text),
                );
            });
            ui.label(
                RichText::new(format!(
                    "Reason: {}",
                    readiness_reason_label(report.reason())
                ))
                .color(status_color),
            );
            ui.label(report.detail().as_str());
            ui.label(
                RichText::new(format!(
                    "Bound binary: {} / {}",
                    outcome.evidence().binary_id(),
                    format_bytes(outcome.evidence().file_size())
                ))
                .small()
                .monospace()
                .color(colors.secondary_text),
            );

            ui.add_space(8.0);
            ui.columns(2, |columns| {
                columns[0].label(RichText::new("Required policy properties").strong());
                for guarantee in report.required_guarantees() {
                    columns[0].label(format!("- {}", sandbox_guarantee_label(*guarantee)));
                }

                columns[1].label(RichText::new("Unresolved requirements").strong());
                if report.requirements().is_empty() {
                    columns[1].label(
                        RichText::new("None observed by this read-only probe")
                            .color(colors.healthy),
                    );
                } else {
                    for requirement in report.requirements() {
                        columns[1].label(format!(
                            "- {}",
                            sandbox_requirement_label(requirement)
                        ));
                    }
                }
            });

            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "No target or sandbox instance exists. Suspended creation, exact runtime attestation, and cleanup proof remain mandatory future gates.",
                )
                .strong()
                .color(colors.warning_conflict),
            );
        });
}

fn provider_selection_label(provider: &SandboxProviderSelection) -> String {
    match provider {
        SandboxProviderSelection::LocalAppContainer => "Local AppContainer".to_owned(),
        SandboxProviderSelection::WindowsSandbox => "Windows Sandbox".to_owned(),
        SandboxProviderSelection::HyperV => "Hyper-V".to_owned(),
        SandboxProviderSelection::Registered { descriptor } => format!(
            "Registered {} ({})",
            descriptor.id, descriptor.build_identity
        ),
    }
}

const fn isolation_boundary_label(boundary: IsolationBoundary) -> &'static str {
    match boundary {
        IsolationBoundary::UserMode => "User mode / shared kernel",
        IsolationBoundary::Hypervisor => "Hypervisor",
    }
}

const fn readiness_reason_label(reason: SandboxProviderReadinessReason) -> &'static str {
    match reason {
        SandboxProviderReadinessReason::ConfirmedByReadOnlyProbe => {
            "confirmed by a read-only capability probe"
        }
        SandboxProviderReadinessReason::UnsupportedPlatform => "unsupported platform",
        SandboxProviderReadinessReason::FeatureDisabled => "required feature disabled",
        SandboxProviderReadinessReason::AdministrativePolicy => "administrative policy",
        SandboxProviderReadinessReason::ResourceUnavailable => "resource unavailable",
        SandboxProviderReadinessReason::ProbeBackendUnavailable => "probe backend unavailable",
        SandboxProviderReadinessReason::CapabilitiesUnverified => "capabilities unverified",
        SandboxProviderReadinessReason::ProviderIdentityMismatch => "provider identity mismatch",
        SandboxProviderReadinessReason::BoundaryMismatch => "isolation boundary mismatch",
        SandboxProviderReadinessReason::MissingRequiredGuarantees => {
            "required provider properties missing"
        }
        SandboxProviderReadinessReason::InvalidProbeObservation => "invalid probe observation",
    }
}

fn sandbox_requirement_label(requirement: &SandboxProviderRequirement) -> String {
    match requirement {
        SandboxProviderRequirement::WindowsOperatingSystem => "Windows operating system".to_owned(),
        SandboxProviderRequirement::StableReadOnlyCapabilityProbe => {
            "Stable read-only Windows capability probe".to_owned()
        }
        SandboxProviderRequirement::AppContainerApiAvailability => {
            "AppContainer API availability".to_owned()
        }
        SandboxProviderRequirement::WindowsOptionalFeature { feature } => {
            format!("Windows optional feature `{}`", feature.feature_name())
        }
        SandboxProviderRequirement::HardwareVirtualization => "Hardware virtualization".to_owned(),
        SandboxProviderRequirement::HypervisorActive => "Active Windows hypervisor".to_owned(),
        SandboxProviderRequirement::AdministrativePolicyApproval => {
            "Administrative policy permits the provider".to_owned()
        }
        SandboxProviderRequirement::ProviderHelperAvailable => {
            "Exact provider helper build available".to_owned()
        }
        SandboxProviderRequirement::SealedVmImageAvailable => {
            "Registered sealed VM image available".to_owned()
        }
        SandboxProviderRequirement::RegisteredProviderProbe { id, build_identity } => {
            format!("Registered provider {id} build {build_identity}")
        }
        SandboxProviderRequirement::ExactProviderIdentity => "Exact provider identity".to_owned(),
        SandboxProviderRequirement::ProviderMatchingBoundary { boundary } => format!(
            "Provider matching {} boundary",
            isolation_boundary_label(*boundary)
        ),
        SandboxProviderRequirement::ProviderSupportingRequiredGuarantees => {
            "Provider supporting every requested policy property".to_owned()
        }
    }
}

const fn sandbox_guarantee_label(guarantee: SandboxGuarantee) -> &'static str {
    match guarantee {
        SandboxGuarantee::FileSystemRedirection => "File-system redirection",
        SandboxGuarantee::RegistryRedirection => "Registry redirection",
        SandboxGuarantee::DisposableFileSystem => "Disposable file system",
        SandboxGuarantee::DisposableRegistry => "Disposable registry",
        SandboxGuarantee::RollbackOnClose => "Rollback on close",
        SandboxGuarantee::NetworkDisabled => "Network disabled",
        SandboxGuarantee::IsolatedNetworkSimulation => "Isolated network simulation",
        SandboxGuarantee::ResourceLimits => "Resource limits",
        SandboxGuarantee::ChildProcessControl => "Child-process control",
        SandboxGuarantee::ProcessMitigations => "Process mitigations",
        SandboxGuarantee::JobAssignmentAtCreation => "Job assignment at creation",
        SandboxGuarantee::HypervisorBoundary => "Hypervisor boundary",
    }
}

#[cfg(feature = "screenshot")]
fn write_screenshot_new(path: &Path, image: &egui::ColorImage) -> Result<(), String> {
    const MAX_CAPTURE_DIMENSION: usize = 8_192;
    let [width, height] = image.size;
    if width == 0 || height == 0 || width > MAX_CAPTURE_DIMENSION || height > MAX_CAPTURE_DIMENSION
    {
        return Err(format!("invalid capture dimensions {width}x{height}"));
    }
    let pixel_count = width
        .checked_mul(height)
        .ok_or_else(|| "capture dimensions overflow".to_owned())?;
    if image.pixels.len() != pixel_count {
        return Err("capture pixel count does not match its dimensions".to_owned());
    }
    let byte_count = pixel_count
        .checked_mul(4)
        .ok_or_else(|| "capture byte count overflows".to_owned())?;
    let mut rgba = Vec::with_capacity(byte_count);
    for pixel in &image.pixels {
        rgba.extend_from_slice(&pixel.to_array());
    }

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create-new failed: {error}"))?;
    let width = u32::try_from(width).map_err(|_| "capture width exceeds u32".to_owned())?;
    let height = u32::try_from(height).map_err(|_| "capture height exceeds u32".to_owned())?;
    let mut encoder = png::Encoder::new(BufWriter::new(file), width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder
        .write_header()
        .map_err(|error| format!("PNG header failed: {error}"))?;
    writer
        .write_image_data(&rgba)
        .map_err(|error| format!("PNG data failed: {error}"))?;
    writer
        .finish()
        .map_err(|error| format!("PNG finish failed: {error}"))
}

fn show_plugin(ui: &mut egui::Ui, plugin: &DiscoveredPlugin, colors: SemanticColors) {
    let (prefix, color) = match plugin.health.state {
        PluginHealthState::Discovered | PluginHealthState::Enabled => ("OK", colors.healthy),
        PluginHealthState::Disabled => ("OFF", colors.fallback),
        PluginHealthState::Incompatible => ("INCOMPATIBLE", colors.warning_conflict),
        PluginHealthState::Quarantined | PluginHealthState::DevelopmentError => {
            ("QUARANTINED", colors.destructive_quarantined)
        }
        _ => ("STATE", colors.fallback),
    };
    let name = plugin.manifest.as_ref().map_or_else(
        || plugin.path.display().to_string(),
        |manifest| manifest.name.clone(),
    );
    ui.collapsing(
        RichText::new(format!("[{prefix}] {name}")).color(color),
        |ui| {
            ui.label(format!("State: {:?}", plugin.health.state));
            ui.label(format!("Path: {}", plugin.path.display()));
            for diagnostic in &plugin.health.diagnostics {
                ui.label(format!("{:?}: {}", diagnostic.severity, diagnostic.message));
            }
            if plugin.health.diagnostics.is_empty() {
                ui.label("No diagnostics");
            }
        },
    );
}

fn status_badge(
    ui: &mut egui::Ui,
    status: FunctionStatus,
    colors: SemanticColors,
) -> egui::Response {
    let prefix = match status {
        FunctionStatus::Conflict => "[!]",
        FunctionStatus::Reviewed => "[R]",
        FunctionStatus::Inferred => "[?]",
        FunctionStatus::Extracted => "[E]",
        FunctionStatus::EvidenceBacked => "[+]",
        FunctionStatus::AutomaticFallback => "[--]",
    };
    let text = format!("{prefix} {}", status.label());
    ui.add(
        egui::Label::new(RichText::new(&text).color(status_color(status, colors)))
            .truncate()
            .sense(Sense::click()),
    )
    .on_hover_text(text)
}

fn status_color(status: FunctionStatus, colors: SemanticColors) -> egui::Color32 {
    match status {
        FunctionStatus::Conflict => colors.warning_conflict,
        FunctionStatus::Reviewed | FunctionStatus::Extracted => colors.exact_extracted,
        FunctionStatus::Inferred => colors.inferred,
        FunctionStatus::EvidenceBacked => colors.healthy,
        FunctionStatus::AutomaticFallback => colors.fallback,
    }
}

fn sort_header(ui: &mut egui::Ui, label: &str, key: FunctionSortKey, sort: &mut FunctionSort) {
    let suffix = if sort.key == key {
        match sort.direction {
            SortDirection::Ascending => " ^",
            SortDirection::Descending => " v",
        }
    } else {
        ""
    };
    if ui.button(format!("{label}{suffix}")).clicked() {
        if sort.key == key {
            sort.direction = match sort.direction {
                SortDirection::Ascending => SortDirection::Descending,
                SortDirection::Descending => SortDirection::Ascending,
            };
        } else {
            sort.key = key;
            sort.direction = SortDirection::Ascending;
        }
    }
}

fn workbench_card(colors: SemanticColors) -> egui::Frame {
    egui::Frame::new()
        .fill(colors.panel)
        .stroke(egui::Stroke::new(1.0, colors.border))
        .inner_margin(egui::Margin::same(14))
        .corner_radius(4)
}

fn summary_card(
    ui: &mut egui::Ui,
    label: &str,
    count: usize,
    color: egui::Color32,
    colors: SemanticColors,
) {
    workbench_card(colors).show(ui, |ui| {
        ui.label(
            RichText::new(count.to_string())
                .size(24.0)
                .strong()
                .color(color),
        );
        ui.label(RichText::new(label).color(colors.secondary_text));
    });
}

fn property_row(ui: &mut egui::Ui, label: &str, value: &str, monospace: bool) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{label}:")).strong());
        if monospace {
            ui.label(RichText::new(value).monospace());
        } else {
            ui.label(value);
        }
    });
}

fn property_cell(ui: &mut egui::Ui, label: &str, value: &str, monospace: bool) {
    ui.vertical(|ui| {
        ui.label(RichText::new(label).small().strong());
        if monospace {
            ui.label(RichText::new(value).monospace());
        } else {
            ui.label(value);
        }
    });
}

fn short_hash(value: &str) -> String {
    if value.len() <= 24 {
        value.to_owned()
    } else {
        format!("{}...{}", &value[..12], &value[value.len() - 8..])
    }
}

fn static_region_name(kind: &StaticRegionKind) -> String {
    match kind {
        StaticRegionKind::Headers => "PE headers".to_owned(),
        StaticRegionKind::Section {
            table_index, name, ..
        } => format!("#{table_index} {name}"),
        StaticRegionKind::ImageGap => "Image gap".to_owned(),
    }
}

fn memory_access_text(access: MemoryAccess) -> String {
    [
        if access.readable { 'R' } else { '-' },
        if access.writable { 'W' } else { '-' },
        if access.executable { 'X' } else { '-' },
    ]
    .into_iter()
    .collect()
}

fn parse_hex_rva(input: &str) -> Result<u64, String> {
    let input = input.trim();
    let digits = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    if digits.is_empty() {
        return Err("enter a hexadecimal RVA".to_owned());
    }
    if digits.len() > 16 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("RVA must contain at most 16 hexadecimal digits".to_owned());
    }
    u64::from_str_radix(digits, 16).map_err(|_| "RVA is outside the u64 range".to_owned())
}

fn format_offline_hex_rows(start_rva: u64, bytes: &[u8]) -> Vec<OfflineHexRow> {
    let bounded = &bytes[..bytes.len().min(MAX_OFFLINE_IMAGE_UI_READ_BYTES as usize)];
    bounded
        .chunks(OFFLINE_HEX_ROW_BYTES)
        .enumerate()
        .map(|(index, chunk)| OfflineHexRow {
            rva: start_rva.saturating_add((index * OFFLINE_HEX_ROW_BYTES) as u64),
            hex: chunk
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" "),
            ascii: chunk
                .iter()
                .map(|byte| {
                    if matches!(*byte, 0x20..=0x7e) {
                        char::from(*byte)
                    } else {
                        '.'
                    }
                })
                .collect(),
        })
        .collect()
}

fn offline_read_banner(display: OfflineReadDisplay<'_>, rva: u64) -> String {
    match display {
        OfflineReadDisplay::Available { byte_count } => {
            format!("[EXACT BYTES] {byte_count} byte(s) at RVA 0x{rva:X}")
        }
        OfflineReadDisplay::Unavailable { code, detail } => {
            format!("[RANGE UNAVAILABLE:{code}] RVA 0x{rva:X}: {detail}")
        }
    }
}

fn offline_lifecycle_status(complete: bool, capability_count: usize) -> String {
    if complete {
        format!(
            "Lifecycle complete: {capability_count} capabilities probed; session closed, released, and control disconnected"
        )
    } else {
        "Lifecycle incomplete: result is not safe to present".to_owned()
    }
}

fn offline_lifecycle_text(outcome: &OfflineImageReadOutcome) -> String {
    let lifecycle = outcome.lifecycle();
    format!(
        "Session {} | {}",
        lifecycle.session_id().get(),
        offline_lifecycle_status(lifecycle.is_complete(), lifecycle.capability_count())
    )
}

fn protection_severity_visual(
    severity: ProtectionSeverity,
    colors: SemanticColors,
) -> (&'static str, egui::Color32) {
    match severity {
        ProtectionSeverity::Notice => ("NOTICE", colors.inferred),
        ProtectionSeverity::Warning => ("WARNING", colors.warning_conflict),
        ProtectionSeverity::High => ("HIGH", colors.destructive_quarantined),
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    let value = bytes as f64;
    if value >= MIB {
        format!("{:.2} MiB", value / MIB)
    } else if value >= KIB {
        format!("{:.1} KiB", value / KIB)
    } else {
        format!("{bytes} bytes")
    }
}

fn export_kind_description(kind: ExportKind) -> &'static str {
    match kind {
        ExportKind::Package => "Canonical analysis package; review history stays in its sidecar",
        ExportKind::NeutralJson => "Debugger-neutral structured symbol projection",
        ExportKind::Markdown => "Bounded human-review report",
        ExportKind::Map => "Microsoft-linker-style public symbol map",
        ExportKind::Pdb => "Public-symbol PDB bound to the verified original PE",
        ExportKind::IdaPython => "Identity-gated IDA importer script",
        ExportKind::GhidraJava => "Identity-gated Ghidra importer script",
    }
}

fn empty_result(ui: &mut egui::Ui, message: &str, colors: SemanticColors) {
    ui.add_space(36.0);
    ui.vertical_centered(|ui| {
        ui.label(
            RichText::new("[--] No results")
                .heading()
                .color(colors.fallback),
        );
        ui.label(RichText::new(message).color(colors.secondary_text));
    });
}

fn control_flow_target(target: &ExportControlFlowTarget) -> String {
    match target {
        ExportControlFlowTarget::Function { rva } => format!("function 0x{rva:08X}"),
        ExportControlFlowTarget::ImportIat { iat_rva } => {
            format!("import slot 0x{iat_rva:08X}")
        }
        ExportControlFlowTarget::FunctionPointer { slot_rva, rva } => {
            format!("function 0x{rva:08X} via slot 0x{slot_rva:08X}")
        }
        _ => "unsupported target".to_owned(),
    }
}

fn show_function_graph_canvas(
    ui: &mut egui::Ui,
    graph: &ReconstructionGraphView,
    root_rva: u64,
    entry_rva: Option<u64>,
    selected_rva: Option<u64>,
    colors: SemanticColors,
) -> (Option<usize>, Option<u64>) {
    const NODE_WIDTH: f32 = 98.0;
    const NODE_HEIGHT: f32 = 74.0;
    const NODE_GAP: f32 = 5.0;
    const TIER_GAP: f32 = 46.0;
    const CANVAS_PADDING: f32 = 18.0;

    let mut layers = BTreeMap::<usize, Vec<&ReconstructionGraphViewNode>>::new();
    for node in &graph.nodes {
        layers.entry(node.depth).or_default().push(node);
    }
    for nodes in layers.values_mut() {
        nodes.sort_by_key(|node| node.node.id);
    }

    let widest_layer = layers.values().map(Vec::len).max().unwrap_or(1);
    let layer_width =
        widest_layer as f32 * NODE_WIDTH + widest_layer.saturating_sub(1) as f32 * NODE_GAP;
    let canvas_width = ui.available_width().max(layer_width + CANVAS_PADDING * 2.0);
    let deepest_layer = layers.keys().next_back().copied().unwrap_or(0);
    let canvas_height = CANVAS_PADDING * 2.0
        + (deepest_layer + 1) as f32 * NODE_HEIGHT
        + deepest_layer as f32 * TIER_GAP;
    let viewport_height = ui.available_height().max(330.0);
    let mut clicked_index = None;
    let mut focused_rva = None;

    ScrollArea::both()
        .id_salt(("reconstruction_graph_canvas", root_rva))
        .auto_shrink([false, false])
        .max_height(viewport_height)
        .show(ui, |ui| {
            let (canvas_rect, _) = ui.allocate_exact_size(
                egui::vec2(canvas_width, canvas_height.max(viewport_height)),
                Sense::hover(),
            );
            let painter = ui.painter_at(canvas_rect);
            painter.rect_filled(canvas_rect, 4, colors.canvas);
            painter.rect_stroke(
                canvas_rect,
                4,
                egui::Stroke::new(1.0, colors.border),
                egui::StrokeKind::Inside,
            );

            let mut positions = BTreeMap::<GraphNodeId, egui::Rect>::new();
            let node_names = graph
                .nodes
                .iter()
                .map(|node| (node.node.id, node.node.name.as_str()))
                .collect::<BTreeMap<_, _>>();
            for (depth, nodes) in &layers {
                let width = nodes.len() as f32 * NODE_WIDTH
                    + nodes.len().saturating_sub(1) as f32 * NODE_GAP;
                let start_x = canvas_rect.center().x - width / 2.0;
                let y =
                    canvas_rect.top() + CANVAS_PADDING + *depth as f32 * (NODE_HEIGHT + TIER_GAP);
                painter.text(
                    egui::pos2(canvas_rect.left() + 8.0, y + NODE_HEIGHT / 2.0),
                    egui::Align2::LEFT_CENTER,
                    format!("TIER {depth}"),
                    egui::FontId::monospace(10.0),
                    colors.secondary_text,
                );
                for (index, view_node) in nodes.iter().enumerate() {
                    let x = start_x + index as f32 * (NODE_WIDTH + NODE_GAP);
                    positions.insert(
                        view_node.node.id,
                        egui::Rect::from_min_size(
                            egui::pos2(x, y),
                            egui::vec2(NODE_WIDTH, NODE_HEIGHT),
                        ),
                    );
                }
            }

            for (edge_index, edge) in graph.edges.iter().enumerate() {
                let (Some(source), Some(target)) =
                    (positions.get(&edge.source), positions.get(&edge.target))
                else {
                    continue;
                };
                let edge_color = graph_edge_color(edge, colors);
                let stroke = egui::Stroke::new(1.5, edge_color);
                let chip_center = if edge.source == edge.target {
                    let x = source.right() + 14.0;
                    let top = source.top() + 18.0;
                    let bottom = source.bottom() - 18.0;
                    painter.line_segment(
                        [egui::pos2(source.right(), top), egui::pos2(x, top)],
                        stroke,
                    );
                    painter.line_segment([egui::pos2(x, top), egui::pos2(x, bottom)], stroke);
                    painter.line_segment(
                        [egui::pos2(x, bottom), egui::pos2(source.right(), bottom)],
                        stroke,
                    );
                    paint_left_arrow_tip(&painter, egui::pos2(source.right(), bottom), stroke);
                    egui::pos2(x + 2.0, source.center().y)
                } else {
                    let start = source.center_bottom();
                    let end = target.center_top();
                    let mid_y = start.y + (end.y - start.y) * 0.48;
                    painter.line_segment([start, egui::pos2(start.x, mid_y)], stroke);
                    painter.line_segment(
                        [egui::pos2(start.x, mid_y), egui::pos2(end.x, mid_y)],
                        stroke,
                    );
                    painter.line_segment([egui::pos2(end.x, mid_y), end], stroke);
                    paint_down_arrow_tip(&painter, end, stroke);
                    egui::pos2(
                        (start.x + end.x) / 2.0 + ((edge_index % 3) as f32 - 1.0) * 12.0,
                        mid_y,
                    )
                };
                let badge = graph_edge_badge(edge);
                let chip_width = 10.0 + badge.len() as f32 * 6.5;
                let chip_rect = egui::Rect::from_center_size(
                    chip_center,
                    egui::vec2(chip_width.max(26.0), 18.0),
                );
                painter.rect_filled(chip_rect, 3, colors.panel);
                painter.rect_stroke(
                    chip_rect,
                    3,
                    egui::Stroke::new(1.0, edge_color),
                    egui::StrokeKind::Inside,
                );
                painter.text(
                    chip_rect.center(),
                    egui::Align2::CENTER_CENTER,
                    badge,
                    egui::FontId::monospace(9.0),
                    edge_color,
                );
                ui.interact(
                    chip_rect,
                    egui::Id::new(("reconstruction_graph_edge", root_rva, edge_index)),
                    Sense::hover(),
                )
                .on_hover_text(graph_edge_tooltip(edge, &node_names));
            }

            for view_node in &graph.nodes {
                let node = &view_node.node;
                let Some(rect) = positions.get(&node.id).copied() else {
                    continue;
                };
                let is_root = node.id == GraphNodeId::Function(root_rva);
                let is_selected = node.projection_index.is_some() && selected_rva == Some(node.rva);
                let fill = if is_selected {
                    colors.selection
                } else if is_root {
                    colors.hover
                } else {
                    colors.raised
                };
                let outline = if is_selected {
                    colors.focus
                } else if is_root {
                    colors.exact_extracted
                } else {
                    colors.border
                };
                painter.rect_filled(rect, 5, fill);
                painter.rect_stroke(
                    rect,
                    5,
                    egui::Stroke::new(if is_selected || is_root { 2.0 } else { 1.0 }, outline),
                    egui::StrokeKind::Inside,
                );
                painter.rect_filled(
                    egui::Rect::from_min_max(
                        rect.min,
                        egui::pos2(rect.left() + 5.0, rect.bottom()),
                    ),
                    3,
                    graph_node_color(node, colors),
                );

                let marker = if entry_rva == Some(node.rva) {
                    "PE ENTRY"
                } else if is_root {
                    "FOCUS ROOT"
                } else {
                    graph_node_marker(node)
                };
                painter.text(
                    rect.left_top() + egui::vec2(10.0, 10.0),
                    egui::Align2::LEFT_TOP,
                    marker,
                    egui::FontId::proportional(9.0),
                    graph_node_color(node, colors),
                );
                painter.text(
                    rect.left_top() + egui::vec2(10.0, 28.0),
                    egui::Align2::LEFT_TOP,
                    graph_node_display_label(&node.name),
                    egui::FontId::monospace(10.5),
                    colors.primary_text,
                );
                let footer = match &node.kind {
                    GraphNodeKind::Function => node.confidence.map_or_else(
                        || format!("0x{:08X}  --", node.rva),
                        |value| format!("0x{:08X}  {:>3.0}%", node.rva, value * 100.0),
                    ),
                    GraphNodeKind::ImportIat { .. } => format!("IAT 0x{:08X}", node.rva),
                };
                painter.text(
                    rect.left_bottom() + egui::vec2(10.0, -10.0),
                    egui::Align2::LEFT_BOTTOM,
                    footer,
                    egui::FontId::monospace(8.5),
                    colors.secondary_text,
                );

                let response = ui
                    .interact(
                        rect,
                        egui::Id::new(("reconstruction_graph_node", root_rva, node.id)),
                        if node.projection_index.is_some() {
                            Sense::click()
                        } else {
                            Sense::hover()
                        },
                    )
                    .on_hover_text(graph_node_tooltip(node, is_root, entry_rva));
                if response.clicked() && node.projection_index.is_some() {
                    clicked_index = node.projection_index;
                }
                if response.double_clicked() && node.projection_index.is_some() {
                    focused_rva = Some(node.rva);
                }
            }
        });

    (clicked_index, focused_rva)
}

fn paint_down_arrow_tip(painter: &egui::Painter, tip: egui::Pos2, stroke: egui::Stroke) {
    painter.line_segment([tip, tip + egui::vec2(-4.5, -7.0)], stroke);
    painter.line_segment([tip, tip + egui::vec2(4.5, -7.0)], stroke);
}

fn paint_left_arrow_tip(painter: &egui::Painter, tip: egui::Pos2, stroke: egui::Stroke) {
    painter.line_segment([tip, tip + egui::vec2(7.0, -4.5)], stroke);
    painter.line_segment([tip, tip + egui::vec2(7.0, 4.5)], stroke);
}

fn graph_node_color(node: &GraphNode, colors: SemanticColors) -> egui::Color32 {
    match &node.kind {
        GraphNodeKind::Function => node
            .status
            .map_or(colors.fallback, |status| status_color(status, colors)),
        GraphNodeKind::ImportIat {
            import_kind: GraphImportKind::Unresolved,
            ..
        } => colors.warning_conflict,
        GraphNodeKind::ImportIat { .. } => colors.exact_extracted,
    }
}

fn graph_node_marker(node: &GraphNode) -> &'static str {
    match &node.kind {
        GraphNodeKind::Function => node.status.map_or("RELATIONSHIP", FunctionStatus::label),
        GraphNodeKind::ImportIat {
            import_kind: GraphImportKind::Normal,
            ..
        } => "IMPORT IAT",
        GraphNodeKind::ImportIat {
            import_kind: GraphImportKind::Delay,
            ..
        } => "DELAY IMPORT",
        GraphNodeKind::ImportIat {
            import_kind: GraphImportKind::Unresolved,
            ..
        } => "UNRESOLVED IAT",
    }
}

fn graph_node_tooltip(node: &GraphNode, is_root: bool, entry_rva: Option<u64>) -> String {
    let mut lines = vec![node.name.clone(), format!("RVA 0x{:08X}", node.rva)];
    if entry_rva == Some(node.rva) {
        lines.push("PE entry point".to_owned());
    } else if is_root {
        lines.push("Current graph focus root".to_owned());
    }
    match &node.kind {
        GraphNodeKind::Function => {
            lines.push(
                node.status
                    .map_or("Relationship-only function".to_owned(), |status| {
                        status.label().to_owned()
                    }),
            );
            if let Some(confidence) = node.confidence {
                lines.push(format!("Confidence {:.1}%", confidence * 100.0));
            }
            if node.projection_index.is_some() {
                lines.push("Click to select; double-click to focus this function".to_owned());
            } else {
                lines.push("No projected table row is available for this target".to_owned());
            }
        }
        GraphNodeKind::ImportIat {
            library,
            symbol,
            import_kind,
        } => {
            lines.push(format!("Library: {library}"));
            lines.push(format!("Symbol: {symbol}"));
            lines.push(format!(
                "Import inventory: {}",
                match import_kind {
                    GraphImportKind::Normal => "normal",
                    GraphImportKind::Delay => "delay-load",
                    GraphImportKind::Unresolved => "unresolved",
                }
            ));
            lines.push("Terminal import-slot node; it cannot become a function root".to_owned());
        }
    }
    lines.join("\n")
}

fn graph_edge_color(edge: &GraphEdge, colors: SemanticColors) -> egui::Color32 {
    match edge.kind {
        GraphEdgeKind::FunctionPointer => colors.healthy,
        GraphEdgeKind::DirectCall => colors.inferred,
        GraphEdgeKind::Thunk => colors.plugin_provenance,
    }
}

fn graph_edge_badge(edge: &GraphEdge) -> &'static str {
    match (edge.origin, edge.kind) {
        (GraphEdgeOrigin::DirectCall, GraphEdgeKind::FunctionPointer) => "CALL PTR",
        (GraphEdgeOrigin::Thunk, GraphEdgeKind::FunctionPointer) => "THUNK PTR",
        (GraphEdgeOrigin::DirectCall, _) => "CALL",
        (GraphEdgeOrigin::Thunk, _) => "THUNK",
    }
}

fn graph_edge_tooltip(edge: &GraphEdge, node_names: &BTreeMap<GraphNodeId, &str>) -> String {
    let relationship = match (edge.origin, edge.kind) {
        (GraphEdgeOrigin::DirectCall, GraphEdgeKind::FunctionPointer) => {
            "Direct call through a retained function-pointer slot"
        }
        (GraphEdgeOrigin::Thunk, GraphEdgeKind::FunctionPointer) => {
            "Thunk through a retained function-pointer slot"
        }
        (GraphEdgeOrigin::DirectCall, _) => "Retained direct call",
        (GraphEdgeOrigin::Thunk, _) => "Retained thunk target",
    };
    let source_name = node_names.get(&edge.source).copied().unwrap_or("<source>");
    let target_name = node_names.get(&edge.target).copied().unwrap_or("<target>");
    let mut lines = vec![
        relationship.to_owned(),
        format!(
            "{} (0x{:08X}) -> {} (0x{:08X})",
            source_name,
            edge.source.rva(),
            target_name,
            edge.target.rva()
        ),
    ];
    if let Some(call_site_rva) = edge.call_site_rva {
        lines.push(format!("Call site RVA: 0x{call_site_rva:08X}"));
    }
    if let Some(pointer_slot_rva) = edge.pointer_slot_rva {
        lines.push(format!("Pointer slot RVA: 0x{pointer_slot_rva:08X}"));
    }
    lines.push(format!(
        "Confidence: {:.1}%",
        edge.attribution.confidence * 100.0
    ));
    lines.push(format!(
        "Producer: {}",
        graph_producer_label(&edge.attribution.producer)
    ));
    lines.push(format!("Method: {}", edge.attribution.method));
    if let Some(run_id) = &edge.attribution.run_id {
        lines.push(format!("Run ID: {run_id}"));
    }
    lines.join("\n")
}

fn graph_producer_label(producer: &ExportProducer) -> String {
    match producer {
        ExportProducer::Core { component, version } => format!("{component} {version}"),
        ExportProducer::Plugin { id, version } => format!("{id} {version}"),
        ExportProducer::User {
            reviewer: Some(reviewer),
        } => format!("User: {reviewer}"),
        ExportProducer::User { reviewer: None } => "User review".to_owned(),
        _ => "Unknown producer".to_owned(),
    }
}

fn compact_graph_label(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let prefix = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

fn graph_node_display_label(value: &str) -> String {
    if let Some((library, symbol)) = value.split_once('!') {
        return format!(
            "{}\n{}",
            compact_graph_label(library, 12),
            compact_graph_label(symbol, 12)
        );
    }
    if let Some(suffix) = value.strip_prefix("fixture_") {
        return format!("fixture_\n{}", compact_graph_label(suffix, 12));
    }
    compact_graph_label(value, 12)
}

fn all_function_statuses() -> [FunctionStatus; 6] {
    [
        FunctionStatus::Conflict,
        FunctionStatus::Reviewed,
        FunctionStatus::Inferred,
        FunctionStatus::Extracted,
        FunctionStatus::EvidenceBacked,
        FunctionStatus::AutomaticFallback,
    ]
}

const fn panel_state(open: bool) -> &'static str {
    if open { "shown" } else { "hidden" }
}

const fn decision_action_label(action: &DecisionAction) -> &'static str {
    match action {
        DecisionAction::AcceptPrimary => "Accept Primary",
        DecisionAction::KeepAlias => "Keep as Alias",
        DecisionAction::Reject => "Reject",
        DecisionAction::Annotation { .. } => "Annotation",
    }
}

fn decision_history_label(action: &DecisionAction) -> String {
    match action {
        DecisionAction::Annotation { text } => {
            format!("Annotation: {}", bounded_text_preview(text, 96))
        }
        _ => decision_action_label(action).to_owned(),
    }
}

fn bounded_text_preview(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

fn is_package_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("resym"))
}

const fn close_requires_confirmation(review_is_dirty: bool, allow_dirty_close: bool) -> bool {
    review_is_dirty && !allow_dirty_close
}

fn review_save_requires_dialog(destination: &Path, persisted_path: Option<&Path>) -> bool {
    destination.as_os_str().is_empty()
        || persisted_path == Some(destination)
        || destination.exists()
}

fn default_export_path(project: &LoadedProject, kind: ExportKind) -> PathBuf {
    let digest = project.identity.sha256.as_str();
    let stem = project
        .snapshot
        .origin_path()
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map_or_else(|| format!("resymbol_{}", &digest[..12]), ToOwned::to_owned);
    let file_name = match kind {
        ExportKind::Package => format!("{stem}.resym"),
        ExportKind::NeutralJson => format!("{stem}.symbols.json"),
        ExportKind::Markdown => format!("{stem}.symbols.md"),
        ExportKind::Map => format!("{stem}.map"),
        ExportKind::Pdb => format!("{stem}.pdb"),
        ExportKind::IdaPython => format!("{stem}.ida.py"),
        ExportKind::GhidraJava => format!("ReSymbolImport_{}.java", &digest[..12]),
    };
    let mut path = project.snapshot.origin_path().to_path_buf();
    path.set_file_name(file_name);
    path
}

fn default_review_path(project: &LoadedProject) -> PathBuf {
    let digest = project.identity.sha256.as_str();
    let stem = project
        .snapshot
        .origin_path()
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map_or_else(|| format!("resymbol_{}", &digest[..12]), ToOwned::to_owned);
    let mut path = project.snapshot.origin_path().to_path_buf();
    path.set_file_name(format!("{stem}.review.json"));
    path
}

fn truncate_utf8_bytes(value: &mut String, maximum_bytes: usize) {
    if value.len() <= maximum_bytes {
        return;
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

fn bounded_message(mut message: String) -> String {
    if message.len() <= MAX_ACTIVITY_MESSAGE_BYTES {
        return message;
    }
    let mut end = MAX_ACTIVITY_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message.push_str("...");
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write as _, path::Path};

    use resymbol_app::AppServices;
    use tempfile::NamedTempFile;

    const STRIPPED_FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");

    fn loaded_project_with_source() -> (NamedTempFile, LoadedProject) {
        let mut source = NamedTempFile::new().expect("temporary PE");
        source.write_all(STRIPPED_FIXTURE).expect("write PE");
        let snapshot = AppServices::default()
            .analyze_binary(source.path())
            .expect("analyze PE");
        let project = LoadedProject::from_snapshot(snapshot).expect("loaded project");
        (source, project)
    }

    #[test]
    fn dirty_close_requires_an_explicit_discard() {
        assert!(close_requires_confirmation(true, false));
        assert!(!close_requires_confirmation(false, false));
        assert!(!close_requires_confirmation(true, true));
    }

    #[test]
    fn save_shortcut_uses_save_as_for_empty_persisted_or_existing_paths() {
        assert!(review_save_requires_dialog(Path::new(""), None));
        assert!(review_save_requires_dialog(
            Path::new("project.review.json"),
            Some(Path::new("project.review.json")),
        ));

        let directory = tempfile::tempdir().expect("create sidecar fixture directory");
        let existing = tempfile::NamedTempFile::new_in(directory.path())
            .expect("create existing sidecar fixture");
        assert!(review_save_requires_dialog(existing.path(), None));
        let new_path = directory.path().join("new-project.review.json");
        assert!(!review_save_requires_dialog(&new_path, None,));
    }

    #[test]
    fn retained_main_tabs_map_to_a_consistent_workflow_stage() {
        for tab in MainTab::ALL {
            let expected = if tab == MainTab::Exports {
                WorkflowStage::Export
            } else {
                WorkflowStage::Review
            };
            assert_eq!(tab.workflow_stage(), expected);
        }
    }

    #[test]
    fn offline_source_guard_requires_the_exact_verified_snapshot() {
        let (_source, project) = loaded_project_with_source();
        let binding = OfflineSourceBinding::from_project(&project).expect("exact source binding");
        assert_eq!(
            &binding.identity,
            project.session().base_analysis().identity()
        );
        assert_eq!(
            binding.canonical_source_path.as_path(),
            project
                .snapshot
                .verified_source_path()
                .expect("verified source")
        );

        let directory = tempfile::tempdir().expect("package directory");
        let package_path = directory.path().join("package-only.resym");
        let services = AppServices::default();
        services
            .save_package_new(&project.snapshot, &package_path)
            .expect("save package");
        let package = services.open_package(&package_path).expect("open package");
        let package = LoadedProject::from_snapshot(package).expect("package project");
        assert!(OfflineSourceBinding::from_project(&package).is_none());
    }

    #[test]
    fn offline_state_rejects_old_operations_full_identity_drift_and_same_hash_other_paths() {
        let (_source, project) = loaded_project_with_source();
        let source = OfflineSourceBinding::from_project(&project).expect("source binding");
        let span = OfflineImageReadSpan::new(0, 64).expect("read span");
        let binding = OfflineReadRequestBinding {
            source: source.clone(),
            span,
        };
        let mut sequence = OperationSequence::default();
        let older = sequence.issue();
        let current = sequence.issue();
        let mut state = OfflineReadUiState::default();
        state.begin(older, binding.clone());
        state.begin(current, binding.clone());

        let disposition = state.accept(
            older,
            Err(crate::worker::OfflineImageReadFailure::VerifiedSourceRequired),
            Some(source.clone()),
        );
        assert_eq!(disposition, OfflineReadEventDisposition::Stale);
        assert!(state.is_pending());
        assert_eq!(
            state.pending.as_ref().map(|pending| pending.operation),
            Some(current)
        );
        assert!(state.presentation.is_none());

        let mut other_path = source.clone();
        other_path.canonical_source_path = PathBuf::from("same-hash-other-path.exe");
        let disposition = state.accept(
            current,
            Err(crate::worker::OfflineImageReadFailure::VerifiedSourceRequired),
            Some(other_path),
        );
        assert!(matches!(
            disposition,
            OfflineReadEventDisposition::Mismatched { .. }
        ));
        assert!(!state.is_pending());
        assert!(matches!(
            state.presentation.as_ref(),
            Some(OfflineReadPresentation::Error(_))
        ));

        let next = sequence.issue();
        state.begin(next, binding);
        let mut changed_identity = source;
        changed_identity
            .identity
            .architecture
            .push_str("-different");
        let disposition = state.accept(
            next,
            Err(crate::worker::OfflineImageReadFailure::VerifiedSourceRequired),
            Some(changed_identity),
        );
        assert!(matches!(
            disposition,
            OfflineReadEventDisposition::Mismatched { .. }
        ));
    }

    #[test]
    fn offline_state_clear_invalidates_pending_and_presented_project_evidence() {
        let (_source, project) = loaded_project_with_source();
        let source = OfflineSourceBinding::from_project(&project).expect("source binding");
        let binding = OfflineReadRequestBinding {
            source,
            span: OfflineImageReadSpan::new(0, 64).expect("span"),
        };
        let operation = OperationSequence::default().issue();
        let mut state = OfflineReadUiState::default();
        state.begin(operation, binding);
        state.present_error("old project presentation");

        state.clear();

        assert!(!state.is_pending());
        assert!(state.pending.is_none());
        assert!(state.presentation.is_none());
    }

    #[test]
    fn offline_state_bounds_ui_failures_before_presentation() {
        let mut state = OfflineReadUiState::default();
        state.present_error("x".repeat(MAX_ACTIVITY_MESSAGE_BYTES * 4));

        let Some(OfflineReadPresentation::Error(error)) = state.presentation.as_ref() else {
            panic!("bounded offline failure presentation");
        };
        assert_eq!(error.len(), MAX_ACTIVITY_MESSAGE_BYTES + 3);
        assert!(error.ends_with("..."));
    }

    #[test]
    fn offline_success_and_unavailable_present_complete_lifecycle_evidence() {
        assert_eq!(
            offline_read_banner(OfflineReadDisplay::Available { byte_count: 64 }, 0x1234),
            "[EXACT BYTES] 64 byte(s) at RVA 0x1234"
        );
        assert_eq!(
            offline_read_banner(
                OfflineReadDisplay::Unavailable {
                    code: "offline-range-unavailable",
                    detail: "span crosses exact file backing",
                },
                0x2000,
            ),
            "[RANGE UNAVAILABLE:offline-range-unavailable] RVA 0x2000: span crosses exact file backing"
        );
        let lifecycle = offline_lifecycle_status(true, 14);
        assert_eq!(
            lifecycle,
            "Lifecycle complete: 14 capabilities probed; session closed, released, and control disconnected"
        );
        assert_eq!(
            offline_lifecycle_status(false, 14),
            "Lifecycle incomplete: result is not safe to present"
        );
    }

    #[test]
    fn offline_hex_formatter_is_deterministic_and_bounded_to_sixteen_byte_rows() {
        let bytes = (0..400)
            .map(|value| (value % 256) as u8)
            .collect::<Vec<_>>();
        let first = format_offline_hex_rows(0x1000, &bytes);
        let second = format_offline_hex_rows(0x1000, &bytes);

        assert_eq!(first, second);
        assert_eq!(first.len(), 16);
        assert_eq!(first[0].rva, 0x1000);
        assert_eq!(first[1].rva, 0x1010);
        assert_eq!(
            first[0].hex,
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
        );
        assert_eq!(first[0].ascii, "................");
        assert!(first.iter().all(|row| row.ascii.len() <= 16));
        assert!(first.iter().all(|row| row.hex.split(' ').count() <= 16));
        assert!(format_offline_hex_rows(0, &[]).is_empty());
    }

    #[test]
    fn offline_rva_parser_accepts_only_bounded_hexadecimal_input() {
        assert_eq!(parse_hex_rva("0x10"), Ok(0x10));
        assert_eq!(parse_hex_rva("10"), Ok(0x10));
        assert_eq!(parse_hex_rva("  0Xabcdef  "), Ok(0xabcdef));
        assert!(parse_hex_rva("").is_err());
        assert!(parse_hex_rva("0x").is_err());
        assert!(parse_hex_rva("-1").is_err());
        assert!(parse_hex_rva("0x10000000000000000").is_err());
        assert!(parse_hex_rva("0x12_G4").is_err());
    }
}
