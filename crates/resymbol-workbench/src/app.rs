use std::{
    cmp::Ordering,
    collections::BTreeSet,
    fs,
    io::BufWriter,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eframe::egui::{
    self, Align, Color32, ComboBox, Frame, Id, Key, KeyboardShortcut, Layout, Margin, Modifiers,
    RichText, ScrollArea, Sense, Stroke, TextEdit, Ui,
};
use egui_extras::{Column, TableBuilder};
use resymbol_analysis::{BinaryAnalysis, PluginRunStatus};
use resymbol_app::{
    DecisionAction, ExportFormat, PluginCatalog, PreparedExport, ProjectSnapshot, ReviewLedger,
};
use resymbol_core::{SymbolAssertion, SymbolClaim, SymbolSubject};
use resymbol_export::{
    ExportAttribution, ExportControlFlowTarget, ExportFunction, ExportProducer, ExportProjection,
};
use serde::{Deserialize, Serialize};

use crate::{
    theme::{ThemePreset, ThemeTokens},
    worker::{ServiceWorker, WorkerCommand, WorkerEvent},
};

const APP_STORAGE_KEY: &str = "resymbol-workbench-state-v1";
const DEFAULT_PLUGIN_ROOT: &str = "plugins";
const MAX_VISIBLE_LOGS: usize = 500;

#[derive(Debug, Clone, Default)]
struct LaunchOptions {
    initial_input: Option<InitialInput>,
    safe_mode: bool,
    theme: Option<ThemePreset>,
    active_tab: Option<WorkTab>,
    capture_path: Option<PathBuf>,
    terminal_output: Option<String>,
    argument_error: Option<String>,
}

#[derive(Debug, Clone)]
enum InitialInput {
    Binary(PathBuf),
    Package(PathBuf),
}

impl LaunchOptions {
    fn from_env() -> Self {
        Self::parse(std::env::args_os().skip(1))
    }

    fn parse(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Self {
        let mut options = Self::default();
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let Some(argument) = argument.to_str() else {
                options.argument_error =
                    Some("command-line options must be valid Unicode".to_owned());
                break;
            };
            match argument {
                "--open" => {
                    let Some(path) = arguments.next() else {
                        options.argument_error = Some("--open requires a binary path".to_owned());
                        break;
                    };
                    if options.initial_input.is_some() {
                        options.argument_error =
                            Some("choose only one startup input: --open or --package".to_owned());
                        break;
                    }
                    options.initial_input = Some(InitialInput::Binary(PathBuf::from(path)));
                }
                "--package" => {
                    let Some(path) = arguments.next() else {
                        options.argument_error =
                            Some("--package requires a .resym path".to_owned());
                        break;
                    };
                    if options.initial_input.is_some() {
                        options.argument_error =
                            Some("choose only one startup input: --open or --package".to_owned());
                        break;
                    }
                    options.initial_input = Some(InitialInput::Package(PathBuf::from(path)));
                }
                "--safe-mode" => options.safe_mode = true,
                "--theme" => {
                    let Some(value) = arguments.next() else {
                        options.argument_error = Some("--theme requires a preset".to_owned());
                        break;
                    };
                    options.theme = match value.to_str() {
                        Some("graphite") => Some(ThemePreset::Graphite),
                        Some("light") => Some(ThemePreset::Light),
                        Some("ida") | Some("ida-inspired") => Some(ThemePreset::IdaInspired),
                        Some("classic") | Some("classic-debugger") => {
                            Some(ThemePreset::ClassicDebugger)
                        }
                        _ => {
                            options.argument_error =
                                Some("--theme expects graphite, light, ida, or classic".to_owned());
                            break;
                        }
                    };
                }
                "--view" => {
                    let Some(value) = arguments.next() else {
                        options.argument_error = Some("--view requires a work area".to_owned());
                        break;
                    };
                    options.active_tab = match value.to_str() {
                        Some("overview") => Some(WorkTab::Overview),
                        Some("functions") => Some(WorkTab::Functions),
                        Some("types") => Some(WorkTab::Types),
                        Some("relationships") => Some(WorkTab::Relationships),
                        Some("exports") => Some(WorkTab::Exports),
                        _ => {
                            options.argument_error = Some(
                                "--view expects overview, functions, types, relationships, or exports"
                                    .to_owned(),
                            );
                            break;
                        }
                    };
                }
                "--capture" => {
                    let Some(path) = arguments.next() else {
                        options.argument_error = Some("--capture requires a PNG path".to_owned());
                        break;
                    };
                    let path = PathBuf::from(path);
                    let is_png = path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("png"));
                    if !is_png {
                        options.argument_error =
                            Some("--capture output must use a .png extension".to_owned());
                        break;
                    }
                    options.capture_path = Some(path);
                }
                "--help" | "-h" => {
                    options.terminal_output = Some(workbench_usage().to_owned());
                    break;
                }
                "--version" | "-V" => {
                    options.terminal_output =
                        Some(format!("resymbol-workbench {}", env!("CARGO_PKG_VERSION")));
                    break;
                }
                unknown => {
                    options.argument_error = Some(format!(
                        "unknown option `{unknown}`; run --help for supported options"
                    ));
                    break;
                }
            }
        }
        if options.capture_path.is_some()
            && options.initial_input.is_none()
            && options.terminal_output.is_none()
            && options.argument_error.is_none()
        {
            options.argument_error =
                Some("--capture requires --open or --package so it renders real data".to_owned());
        }
        options
    }
}

type CaptureOutcome = Arc<Mutex<Option<Result<PathBuf, String>>>>;

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let launch = LaunchOptions::from_env();
    if let Some(output) = &launch.terminal_output {
        println!("{output}");
        return Ok(());
    }
    let capture_mode = launch.capture_path.is_some();
    let capture_outcome = capture_mode.then(|| Arc::new(Mutex::new(None)));
    let app_capture_outcome = capture_outcome.clone();
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("ReSymbol Workbench")
        .with_inner_size([1440.0, 900.0])
        .with_min_inner_size([1100.0, 720.0])
        .with_drag_and_drop(true);
    if capture_mode {
        viewport = viewport
            .with_min_inner_size([1440.0, 900.0])
            .with_max_inner_size([1440.0, 900.0])
            .with_resizable(false);
    }
    let native_options = eframe::NativeOptions {
        viewport,
        persist_window: !capture_mode,
        ..Default::default()
    };
    eframe::run_native(
        "ReSymbol Workbench",
        native_options,
        Box::new(move |creation| {
            Ok(Box::new(WorkbenchApp::new(
                creation,
                launch,
                app_capture_outcome,
            )))
        }),
    )?;
    if let Some(capture_outcome) = capture_outcome {
        let outcome = capture_outcome
            .lock()
            .map_err(|_| std::io::Error::other("capture result lock was poisoned"))?
            .take()
            .ok_or_else(|| {
                std::io::Error::other("the workbench closed before producing its capture")
            })?;
        outcome.map_err(|error| std::io::Error::other(error))?;
    }
    Ok(())
}

const fn workbench_usage() -> &'static str {
    "Usage: resymbol-workbench [--open <binary> | --package <file.resym>] [options]\n\
     \nOptions:\n\
     \x20 --open <PATH>       Analyze a binary when the workbench opens\n\
     \x20 --package <PATH>    Open a .resym package when the workbench opens\n\
     \x20 --safe-mode        Apply safe-mode policy to plugin discovery\n\
     \x20 --theme <PRESET>   Start with graphite, light, ida, or classic\n\
     \x20 --view <AREA>      Start on overview, functions, types, relationships, or exports\n\
     \x20 --capture <PNG>    Save the loaded, rendered workbench as a PNG and exit\n\
     \x20 -h, --help         Print help\n\
     \x20 -V, --version      Print version"
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
enum WorkTab {
    #[default]
    Overview,
    Functions,
    Types,
    Relationships,
    Exports,
}

impl WorkTab {
    const ALL: [Self; 5] = [
        Self::Overview,
        Self::Functions,
        Self::Types,
        Self::Relationships,
        Self::Exports,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Functions => "Functions",
            Self::Types => "Types",
            Self::Relationships => "Relationships",
            Self::Exports => "Exports",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
enum ActivityTab {
    #[default]
    Progress,
    Plugins,
    Warnings,
    Review,
    Logs,
}

impl ActivityTab {
    const ALL: [Self; 5] = [
        Self::Progress,
        Self::Plugins,
        Self::Warnings,
        Self::Review,
        Self::Logs,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Progress => "Analysis progress",
            Self::Plugins => "Plugin runs",
            Self::Warnings => "Warnings",
            Self::Review => "Review history",
            Self::Logs => "Logs",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum WorkflowStage {
    #[default]
    Open,
    Analyze,
    Review,
    Export,
}

impl WorkflowStage {
    const ALL: [Self; 4] = [Self::Open, Self::Analyze, Self::Review, Self::Export];

    const fn label(self) -> &'static str {
        match self {
            Self::Open => "1  Open Binary",
            Self::Analyze => "2  Analyze",
            Self::Review => "3  Review",
            Self::Export => "4  Export",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
enum FunctionSort {
    #[default]
    Rva,
    Name,
    Confidence,
    Size,
    Source,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
enum StatusFilter {
    #[default]
    All,
    Named,
    Unnamed,
    Conflicts,
    Plugin,
}

impl StatusFilter {
    const ALL: [Self; 5] = [
        Self::All,
        Self::Named,
        Self::Unnamed,
        Self::Conflicts,
        Self::Plugin,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::All => "All statuses",
            Self::Named => "Named",
            Self::Unnamed => "Unnamed",
            Self::Conflicts => "Conflicts",
            Self::Plugin => "Plugin-produced",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
struct PersistedState {
    theme: ThemePreset,
    ui_scale: f32,
    monospace_size: f32,
    active_tab: WorkTab,
    activity_tab: ActivityTab,
    left_visible: bool,
    inspector_visible: bool,
    activity_visible: bool,
    safe_mode: bool,
    plugin_root: PathBuf,
    layout_generation: u64,
    function_sort: FunctionSort,
    function_sort_ascending: bool,
    status_filter: StatusFilter,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            theme: ThemePreset::Graphite,
            ui_scale: 1.0,
            monospace_size: 12.5,
            active_tab: WorkTab::Overview,
            activity_tab: ActivityTab::Progress,
            left_visible: true,
            inspector_visible: true,
            activity_visible: true,
            safe_mode: false,
            plugin_root: PathBuf::from(DEFAULT_PLUGIN_ROOT),
            layout_generation: 0,
            function_sort: FunctionSort::Rva,
            function_sort_ascending: true,
            status_filter: StatusFilter::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusyOperation {
    Analyze,
    OpenPackage,
    VerifySource,
    DiscoverPlugins,
    SavePackage,
    LoadReview,
    SaveReview,
    PrepareExport,
    PublishExport,
}

impl BusyOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::Analyze => "Analyzing binary",
            Self::OpenPackage => "Opening analysis package",
            Self::VerifySource => "Verifying exact source binary",
            Self::DiscoverPlugins => "Discovering plugins",
            Self::SavePackage => "Saving analysis package",
            Self::LoadReview => "Opening review sidecar",
            Self::SaveReview => "Saving review sidecar",
            Self::PrepareExport => "Preparing validated export",
            Self::PublishExport => "Writing create-new export",
        }
    }

    const fn stage(self) -> WorkflowStage {
        match self {
            Self::Analyze | Self::OpenPackage | Self::DiscoverPlugins => WorkflowStage::Analyze,
            Self::VerifySource => WorkflowStage::Open,
            Self::SavePackage | Self::PrepareExport | Self::PublishExport => WorkflowStage::Export,
            Self::LoadReview | Self::SaveReview => WorkflowStage::Review,
        }
    }
}

#[derive(Debug)]
struct LogEntry {
    timestamp: String,
    level: LogLevel,
    message: String,
}

#[derive(Debug)]
struct CaptureState {
    path: PathBuf,
    view: WorkTab,
    settled_passes: u8,
    request_sent: bool,
    complete: bool,
    resize_sent: bool,
    started_at: Instant,
    outcome: CaptureOutcome,
}

#[derive(Debug)]
struct CaptureRequest;

#[derive(Debug, Clone)]
struct ReviewViewState {
    projection: Arc<ExportProjection>,
    orphaned_sequences: BTreeSet<u64>,
}

impl ReviewViewState {
    fn build(project: &ProjectSnapshot, review: &ReviewLedger) -> Result<Self, String> {
        let projection = project
            .reviewed_projection(review)
            .map_err(|error| error.to_string())?;
        let orphaned_sequences = review
            .orphaned_decisions(project.session())
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|decision| decision.sequence())
            .collect();
        Ok(Self {
            projection,
            orphaned_sequences,
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

pub struct WorkbenchApp {
    persisted: PersistedState,
    applied_theme: Option<(ThemePreset, u32, u32)>,
    worker: ServiceWorker,
    project: Option<Arc<ProjectSnapshot>>,
    plugins: Option<PluginCatalog>,
    review: Option<ReviewLedger>,
    review_view: Option<ReviewViewState>,
    review_path: Option<PathBuf>,
    review_dirty: bool,
    review_revision: u64,
    prepared_export: Option<Arc<PreparedExport>>,
    prepared_format: Option<ExportFormat>,
    export_format: ExportFormat,
    export_destination: String,
    busy: Option<BusyOperation>,
    selected_function_rva: Option<u64>,
    function_filter: String,
    focus_function_filter: bool,
    annotation: String,
    error: Option<String>,
    logs: Vec<LogEntry>,
    capture: Option<CaptureState>,
}

impl WorkbenchApp {
    fn new(
        creation: &eframe::CreationContext<'_>,
        launch: LaunchOptions,
        capture_outcome: Option<CaptureOutcome>,
    ) -> Self {
        let capture_mode = launch.capture_path.is_some();
        if capture_mode {
            creation
                .egui_ctx
                .memory_mut(|memory| *memory = egui::Memory::default());
        }
        let mut persisted: PersistedState = if capture_mode {
            PersistedState::default()
        } else {
            creation
                .storage
                .and_then(|storage| eframe::get_value(storage, APP_STORAGE_KEY))
                .unwrap_or_default()
        };
        persisted.safe_mode |= launch.safe_mode;
        if let Some(theme) = launch.theme {
            persisted.theme = theme;
        }
        if let Some(active_tab) = launch.active_tab {
            persisted.active_tab = active_tab;
        }
        let capture = launch.capture_path.clone().map(|path| {
            persisted.ui_scale = 1.0;
            persisted.monospace_size = 12.5;
            persisted.left_visible = true;
            persisted.inspector_visible = true;
            persisted.activity_visible = true;
            CaptureState {
                path,
                view: launch.active_tab.unwrap_or(WorkTab::Overview),
                settled_passes: 0,
                request_sent: false,
                complete: false,
                resize_sent: false,
                started_at: Instant::now(),
                outcome: capture_outcome
                    .expect("capture mode always has a shared completion outcome"),
            }
        });
        let worker = ServiceWorker::start(creation.egui_ctx.clone());
        let mut app = Self {
            persisted,
            applied_theme: None,
            worker,
            project: None,
            plugins: None,
            review: None,
            review_view: None,
            review_path: None,
            review_dirty: false,
            review_revision: 0,
            prepared_export: None,
            prepared_format: None,
            export_format: ExportFormat::Json,
            export_destination: String::new(),
            busy: None,
            selected_function_rva: None,
            function_filter: String::new(),
            focus_function_filter: false,
            annotation: String::new(),
            error: launch.argument_error,
            logs: Vec::new(),
            capture,
        };
        app.ensure_theme(&creation.egui_ctx);
        if capture_mode {
            creation
                .egui_ctx
                .style_mut(|style| style.animation_time = 0.0);
        }
        app.log(LogLevel::Info, "Workbench ready");
        if let Some(input) = launch.initial_input {
            match input {
                InitialInput::Binary(path) => app.open_binary(path),
                InitialInput::Package(path) => app.open_package(path),
            }
        }
        app
    }

    fn ensure_theme(&mut self, ctx: &egui::Context) {
        self.persisted.ui_scale = self.persisted.ui_scale.clamp(0.8, 1.6);
        self.persisted.monospace_size = self.persisted.monospace_size.clamp(10.0, 20.0);
        let key = (
            self.persisted.theme,
            self.persisted.ui_scale.to_bits(),
            self.persisted.monospace_size.to_bits(),
        );
        if self.applied_theme != Some(key) {
            self.persisted
                .theme
                .apply(ctx, self.persisted.ui_scale, self.persisted.monospace_size);
            self.applied_theme = Some(key);
        }
    }

    fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        if self.logs.len() == MAX_VISIBLE_LOGS {
            self.logs.remove(0);
        }
        self.logs.push(LogEntry {
            timestamp: utc_clock_text(),
            level,
            message: message.into(),
        });
    }

    fn fail(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.log(LogLevel::Error, message.clone());
        self.error = Some(message);
        self.busy = None;
    }

    fn dispatch(&mut self, operation: BusyOperation, command: WorkerCommand) {
        if self.busy.is_some() {
            self.log(
                LogLevel::Warning,
                "A background operation is already in progress",
            );
            return;
        }
        let label = operation.label();
        match self.worker.send(command) {
            Ok(()) => {
                self.busy = Some(operation);
                self.log(LogLevel::Info, label);
            }
            Err(error) => self.fail(error),
        }
    }

    fn open_binary(&mut self, path: PathBuf) {
        self.dispatch(BusyOperation::Analyze, WorkerCommand::Analyze(path));
    }

    fn open_package(&mut self, path: PathBuf) {
        self.dispatch(BusyOperation::OpenPackage, WorkerCommand::OpenPackage(path));
    }

    fn handle_worker_events(&mut self) {
        while let Some(event) = self.worker.try_recv() {
            self.busy = None;
            match event {
                WorkerEvent::ProjectOpened(result) => match result {
                    Ok(project) => {
                        let review = match ReviewLedger::for_session(project.session()) {
                            Ok(review) => review,
                            Err(error) => {
                                self.fail(error.to_string());
                                continue;
                            }
                        };
                        let review_view = match ReviewViewState::build(&project, &review) {
                            Ok(review_view) => review_view,
                            Err(error) => {
                                self.fail(format!(
                                    "could not build the reviewed workbench projection: {error}"
                                ));
                                continue;
                            }
                        };
                        let name = project
                            .origin_path()
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("analysis project")
                            .to_owned();
                        let review_path = default_review_path(project.origin_path());
                        let load_existing_review = review_path.is_file();
                        self.project = Some(project.clone());
                        self.review = Some(review);
                        self.review_view = Some(review_view);
                        self.review_path = Some(review_path.clone());
                        self.review_dirty = false;
                        self.review_revision = 0;
                        self.prepared_export = None;
                        self.prepared_format = None;
                        self.selected_function_rva = self
                            .review_view
                            .as_ref()
                            .and_then(|view| {
                                view.projection
                                    .functions
                                    .iter()
                                    .find(|function| function.selected_name.is_some())
                                    .or_else(|| view.projection.functions.first())
                            })
                            .map(|function| function.rva);
                        self.persisted.active_tab = self
                            .capture
                            .as_ref()
                            .map_or(WorkTab::Overview, |capture| capture.view);
                        self.log(LogLevel::Success, format!("Opened {name}"));
                        if load_existing_review {
                            self.dispatch(
                                BusyOperation::LoadReview,
                                WorkerCommand::LoadReview {
                                    project,
                                    path: review_path,
                                },
                            );
                        }
                    }
                    Err(error) => self.fail(error),
                },
                WorkerEvent::SourceVerified(result) => match result {
                    Ok(project) => {
                        let review_view = match self
                            .review
                            .as_ref()
                            .map(|review| ReviewViewState::build(&project, review))
                            .transpose()
                        {
                            Ok(review_view) => review_view,
                            Err(error) => {
                                self.fail(format!(
                                    "could not refresh the reviewed workbench projection: {error}"
                                ));
                                continue;
                            }
                        };
                        self.project = Some(project);
                        self.review_view = review_view;
                        self.prepared_export = None;
                        self.prepared_format = None;
                        self.log(LogLevel::Success, "Exact source binary verified");
                    }
                    Err(error) => self.fail(error),
                },
                WorkerEvent::PluginsDiscovered(result) => match result {
                    Ok(catalog) => {
                        let count = catalog.entries().len();
                        self.plugins = Some(catalog);
                        self.log(
                            LogLevel::Success,
                            format!("Plugin discovery completed: {count} candidate(s)"),
                        );
                    }
                    Err(error) => self.fail(error),
                },
                WorkerEvent::PackageSaved(result) => match result {
                    Ok(path) => self.log(
                        LogLevel::Success,
                        format!("Created analysis package {}", path.display()),
                    ),
                    Err(error) => self.fail(error),
                },
                WorkerEvent::ReviewLoaded(result) => match result {
                    Ok((review, path)) => {
                        let Some(project) = self.project.as_ref() else {
                            self.fail("the review sidecar completed without an active project");
                            continue;
                        };
                        let review_view = match ReviewViewState::build(project, &review) {
                            Ok(review_view) => review_view,
                            Err(error) => {
                                self.fail(format!(
                                    "could not apply the loaded review sidecar: {error}"
                                ));
                                continue;
                            }
                        };
                        self.review = Some(review);
                        self.review_view = Some(review_view);
                        self.review_path = Some(path.clone());
                        self.review_dirty = false;
                        self.review_revision = 0;
                        self.prepared_export = None;
                        self.log(
                            LogLevel::Success,
                            format!("Opened review sidecar {}", path.display()),
                        );
                    }
                    Err(error) => {
                        self.log(
                            LogLevel::Warning,
                            "Review sidecar was rejected; the binary-bound in-memory ledger remains unchanged",
                        );
                        self.fail(error);
                    }
                },
                WorkerEvent::ReviewSaved(result) => match result {
                    Ok((path, revision)) => {
                        self.review_path = Some(path.clone());
                        self.review_dirty = self.review_revision != revision;
                        self.log(
                            LogLevel::Success,
                            format!("Saved review sidecar {}", path.display()),
                        );
                        if self.review_dirty {
                            self.queue_review_save();
                        }
                    }
                    Err(error) => self.fail(error),
                },
                WorkerEvent::ExportPrepared(result) => match result {
                    Ok(prepared) => {
                        self.prepared_format = Some(prepared.format());
                        self.export_destination = prepared.suggested_file_name().to_owned();
                        self.prepared_export = Some(Arc::new(prepared));
                        self.log(LogLevel::Success, "Validated export preview is ready");
                    }
                    Err(error) => self.fail(error),
                },
                WorkerEvent::ExportPublished(result) => match result {
                    Ok(path) => self.log(
                        LogLevel::Success,
                        format!("Created export {}", path.display()),
                    ),
                    Err(error) => self.fail(error),
                },
            }
        }
    }

    fn active_stage(&self) -> WorkflowStage {
        if let Some(busy) = self.busy {
            return busy.stage();
        }
        if self.project.is_none() {
            WorkflowStage::Open
        } else if self.persisted.active_tab == WorkTab::Exports {
            WorkflowStage::Export
        } else if self.persisted.active_tab == WorkTab::Overview {
            WorkflowStage::Analyze
        } else {
            WorkflowStage::Review
        }
    }

    fn handle_capture_result(&mut self, ctx: &egui::Context) {
        let image = ctx.input(|input| {
            input.events.iter().find_map(|event| match event {
                egui::Event::Screenshot {
                    user_data, image, ..
                } if user_data
                    .data
                    .as_ref()
                    .is_some_and(|data| data.is::<CaptureRequest>()) =>
                {
                    Some(image.clone())
                }
                _ => None,
            })
        });
        let Some(image) = image else {
            return;
        };
        let Some(path) = self.capture.as_ref().map(|capture| capture.path.clone()) else {
            return;
        };
        if image.size != [1440, 900] {
            self.finish_capture(
                ctx,
                Err(format!(
                    "renderer returned {}x{} pixels; expected 1440x900",
                    image.size[0], image.size[1]
                )),
            );
            return;
        }
        match save_color_image_png(&path, &image) {
            Ok(()) => {
                println!("Saved rendered workbench capture to {}", path.display());
                self.finish_capture(ctx, Ok(path));
            }
            Err(error) => self.finish_capture(ctx, Err(error)),
        }
    }

    fn finish_capture(&mut self, ctx: &egui::Context, result: Result<PathBuf, String>) {
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        if capture.complete {
            return;
        }
        capture.complete = true;
        if let Ok(mut outcome) = capture.outcome.lock() {
            *outcome = Some(result);
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    fn request_capture_when_ready(&mut self, ctx: &egui::Context) {
        let Some(capture) = self.capture.as_ref() else {
            return;
        };
        if capture.complete {
            return;
        }
        if capture.started_at.elapsed() > Duration::from_secs(120) {
            self.finish_capture(ctx, Err("capture timed out after 120 seconds".to_owned()));
            return;
        }
        if capture.request_sent {
            ctx.request_repaint_after(Duration::from_millis(100));
            return;
        }
        if let Some(error) = self.error.clone() {
            self.finish_capture(ctx, Err(error));
            return;
        }
        let capture = self
            .capture
            .as_mut()
            .expect("capture state remains present during capture");
        if !capture.resize_sent {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1440.0, 900.0)));
            capture.resize_sent = true;
            capture.settled_passes = 0;
            ctx.request_repaint_after(Duration::from_millis(40));
            return;
        }
        if self.project.is_none() || self.busy.is_some() {
            ctx.request_repaint_after(Duration::from_millis(40));
            return;
        }
        if capture.settled_passes < 3 {
            capture.settled_passes += 1;
            ctx.request_repaint_after(Duration::from_millis(40));
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::new(
            CaptureRequest,
        )));
        capture.request_sent = true;
        ctx.request_repaint();
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let open = KeyboardShortcut::new(Modifiers::CTRL, Key::O);
        let open_package = KeyboardShortcut::new(Modifiers::CTRL | Modifiers::SHIFT, Key::O);
        let export = KeyboardShortcut::new(Modifiers::CTRL | Modifiers::SHIFT, Key::E);
        let search = KeyboardShortcut::new(Modifiers::CTRL, Key::F);
        let undo = KeyboardShortcut::new(Modifiers::CTRL, Key::Z);
        let redo = KeyboardShortcut::new(Modifiers::CTRL, Key::Y);
        let rerun = KeyboardShortcut::new(Modifiers::NONE, Key::F5);
        if ctx.input_mut(|input| input.consume_shortcut(&open_package)) {
            self.choose_package();
        } else if ctx.input_mut(|input| input.consume_shortcut(&open)) {
            self.choose_binary();
        }
        if ctx.input_mut(|input| input.consume_shortcut(&export)) && self.project.is_some() {
            self.persisted.active_tab = WorkTab::Exports;
        }
        if ctx.input_mut(|input| input.consume_shortcut(&search)) {
            self.persisted.active_tab = WorkTab::Functions;
            self.focus_function_filter = true;
        }
        if ctx.input_mut(|input| input.consume_shortcut(&undo)) {
            self.undo_review();
        }
        if ctx.input_mut(|input| input.consume_shortcut(&redo)) {
            self.redo_review();
        }
        if ctx.input_mut(|input| input.consume_shortcut(&rerun)) && self.busy.is_none() {
            if let Some(path) = self
                .project
                .as_ref()
                .and_then(|project| project.binary_path())
                .map(Path::to_path_buf)
            {
                self.open_binary(path);
            }
        }
        for (index, tab) in WorkTab::ALL.iter().copied().enumerate() {
            let key = match index {
                0 => Key::Num1,
                1 => Key::Num2,
                2 => Key::Num3,
                3 => Key::Num4,
                _ => Key::Num5,
            };
            if ctx.input_mut(|input| {
                input.consume_shortcut(&KeyboardShortcut::new(Modifiers::CTRL, key))
            }) {
                self.persisted.active_tab = tab;
            }
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let paths = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .filter_map(|file| file.path.clone())
                .collect::<Vec<_>>()
        });
        if let Some(path) = paths.into_iter().next() {
            if is_package_path(&path) {
                self.open_package(path);
            } else {
                self.open_binary(path);
            }
        }
    }

    fn choose_binary(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open a binary for deterministic analysis")
            .add_filter("Windows PE", &["exe", "dll", "sys"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            self.open_binary(path);
        }
    }

    fn choose_package(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open a ReSymbol analysis package")
            .add_filter("ReSymbol package", &["resym"])
            .pick_file()
        {
            self.open_package(path);
        }
    }

    fn choose_exact_source(&mut self) {
        let Some(project) = self.project.clone() else {
            return;
        };
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Verify the exact source binary")
            .add_filter("Windows PE", &["exe", "dll", "sys"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            self.dispatch(
                BusyOperation::VerifySource,
                WorkerCommand::VerifySource { project, path },
            );
        }
    }

    fn save_package(&mut self) {
        let Some(project) = self.project.clone() else {
            return;
        };
        let default = project
            .origin_path()
            .file_stem()
            .and_then(|name| name.to_str())
            .map_or_else(
                || "analysis.resym".to_owned(),
                |name| format!("{name}.resym"),
            );
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Create a ReSymbol analysis package")
            .set_file_name(default)
            .add_filter("ReSymbol package", &["resym"])
            .save_file()
        {
            self.dispatch(
                BusyOperation::SavePackage,
                WorkerCommand::SavePackage { project, path },
            );
        }
    }

    fn open_review_sidecar(&mut self) {
        let Some(project) = self.project.clone() else {
            return;
        };
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open a binary-bound review sidecar")
            .add_filter("ReSymbol workbench review", &["json"])
            .pick_file()
        {
            self.dispatch(
                BusyOperation::LoadReview,
                WorkerCommand::LoadReview { project, path },
            );
        }
    }

    fn save_review_sidecar_as(&mut self) {
        let Some(project) = &self.project else {
            return;
        };
        let default = self
            .review_path
            .clone()
            .unwrap_or_else(|| default_review_path(project.origin_path()));
        let mut dialog = rfd::FileDialog::new()
            .set_title("Save the binary-bound review sidecar")
            .add_filter("ReSymbol workbench review", &["json"]);
        if let Some(parent) = default.parent() {
            dialog = dialog.set_directory(parent);
        }
        if let Some(name) = default.file_name().and_then(|name| name.to_str()) {
            dialog = dialog.set_file_name(name);
        }
        if let Some(path) = dialog.save_file() {
            self.review_path = Some(path);
            self.review_dirty = true;
            self.queue_review_save();
        }
    }

    fn undo_review(&mut self) {
        if self.busy.is_some() {
            self.log(
                LogLevel::Warning,
                "Wait for the active operation before changing review history",
            );
            return;
        }
        let (Some(project), Some(mut review)) = (self.project.clone(), self.review.clone()) else {
            return;
        };
        if review.undo().is_none() {
            return;
        }
        match ReviewViewState::build(&project, &review) {
            Ok(review_view) => {
                self.commit_review_state(review, review_view, "Undid review decision")
            }
            Err(error) => self.fail(format!("could not undo the review decision: {error}")),
        }
    }

    fn redo_review(&mut self) {
        if self.busy.is_some() {
            self.log(
                LogLevel::Warning,
                "Wait for the active operation before changing review history",
            );
            return;
        }
        let (Some(project), Some(mut review)) = (self.project.clone(), self.review.clone()) else {
            return;
        };
        if review.redo().is_none() {
            return;
        }
        match ReviewViewState::build(&project, &review) {
            Ok(review_view) => {
                self.commit_review_state(review, review_view, "Reapplied review decision")
            }
            Err(error) => self.fail(format!("could not redo the review decision: {error}")),
        }
    }

    fn commit_review_state(
        &mut self,
        review: ReviewLedger,
        review_view: ReviewViewState,
        message: &'static str,
    ) {
        self.review = Some(review);
        self.review_view = Some(review_view);
        self.review_revision = self.review_revision.wrapping_add(1);
        self.review_dirty = true;
        self.prepared_export = None;
        self.prepared_format = None;
        self.reconcile_function_selection();
        self.log(LogLevel::Success, message);
        self.queue_review_save();
    }

    fn reconcile_function_selection(&mut self) {
        let Some(review_view) = &self.review_view else {
            self.selected_function_rva = None;
            return;
        };
        let selection_still_exists = self.selected_function_rva.is_some_and(|selected| {
            review_view
                .projection
                .functions
                .iter()
                .any(|function| function.rva == selected)
        });
        if !selection_still_exists {
            self.selected_function_rva = review_view
                .projection
                .functions
                .iter()
                .find(|function| function.selected_name.is_some())
                .or_else(|| review_view.projection.functions.first())
                .map(|function| function.rva);
        }
    }

    fn queue_review_save(&mut self) {
        let (Some(ledger), Some(path)) = (self.review.clone(), self.review_path.clone()) else {
            return;
        };
        if self.busy.is_some() {
            return;
        }
        self.dispatch(
            BusyOperation::SaveReview,
            WorkerCommand::SaveReview {
                ledger,
                path,
                revision: self.review_revision,
            },
        );
    }

    fn discover_plugins(&mut self) {
        self.dispatch(
            BusyOperation::DiscoverPlugins,
            WorkerCommand::DiscoverPlugins {
                root: self.persisted.plugin_root.clone(),
                safe_mode: self.persisted.safe_mode,
            },
        );
    }

    fn prepare_export(&mut self) {
        let Some(project) = self.project.clone() else {
            return;
        };
        let Some(ledger) = self.review.clone() else {
            self.fail("the active project has no review ledger");
            return;
        };
        self.prepared_export = None;
        self.prepared_format = None;
        self.dispatch(
            BusyOperation::PrepareExport,
            WorkerCommand::PrepareExport {
                project,
                ledger,
                format: self.export_format,
            },
        );
    }

    fn publish_export(&mut self) {
        let Some(prepared) = self.prepared_export.clone() else {
            return;
        };
        let suggested = prepared.suggested_file_name();
        let mut dialog = rfd::FileDialog::new()
            .set_title("Create validated export")
            .set_file_name(suggested);
        if let Some(extension) = Path::new(suggested)
            .extension()
            .and_then(|value| value.to_str())
        {
            dialog = dialog.add_filter("Selected export format", &[extension]);
        }
        if let Some(path) = dialog.save_file() {
            self.dispatch(
                BusyOperation::PublishExport,
                WorkerCommand::PublishExport { prepared, path },
            );
        }
    }

    fn header(&mut self, ctx: &egui::Context, tokens: ThemeTokens) {
        egui::TopBottomPanel::top("workbench_header")
            .frame(
                Frame::new()
                    .fill(tokens.panel)
                    .inner_margin(Margin::symmetric(16, 8)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("ReSymbol").heading().strong());
                            ui.label(RichText::new("WORKBENCH").small().color(tokens.muted));
                        });
                        if let Some(project) = &self.project {
                            let name = project
                                .origin_path()
                                .file_name()
                                .and_then(|value| value.to_str())
                                .unwrap_or("analysis project");
                            let hash = project.session().base_analysis().identity().id.to_string();
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(name).strong());
                                ui.label(RichText::new("✓ Exact identity").color(tokens.exact));
                                ui.label(
                                    RichText::new(short_hash(&hash))
                                        .monospace()
                                        .color(tokens.muted),
                                )
                                .on_hover_text(format!("SHA-256 {hash}"));
                            });
                        } else {
                            ui.label(
                                RichText::new("No binary open · drop a PE here or press Ctrl+O")
                                    .color(tokens.muted),
                            );
                        }
                    });

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let primary = if self.project.is_some() {
                            "Export Symbols"
                        } else {
                            "Open Binary…"
                        };
                        if ui
                            .add_enabled(self.busy.is_none(), egui::Button::new(primary))
                            .on_hover_text(if self.project.is_some() {
                                "Open the validated export preview (Ctrl+Shift+E)"
                            } else {
                                "Open a PE binary for analysis (Ctrl+O)"
                            })
                            .clicked()
                        {
                            if self.project.is_some() {
                                self.persisted.active_tab = WorkTab::Exports;
                            } else {
                                self.choose_binary();
                            }
                        }
                        ui.add_space(8.0);
                        ComboBox::from_id_salt("theme_selector")
                            .selected_text(self.persisted.theme.label())
                            .show_ui(ui, |ui| {
                                for theme in ThemePreset::ALL {
                                    ui.selectable_value(
                                        &mut self.persisted.theme,
                                        theme,
                                        theme.label(),
                                    );
                                }
                            });
                        ui.menu_button("View", |ui| {
                            ui.checkbox(&mut self.persisted.left_visible, "Project rail");
                            ui.checkbox(&mut self.persisted.inspector_visible, "Inspector");
                            ui.checkbox(&mut self.persisted.activity_visible, "Activity area");
                            ui.separator();
                            ui.label("UI scale");
                            ui.add(
                                egui::Slider::new(&mut self.persisted.ui_scale, 0.8..=1.6)
                                    .step_by(0.05)
                                    .show_value(true),
                            );
                            ui.label("Monospace size");
                            ui.add(
                                egui::Slider::new(&mut self.persisted.monospace_size, 10.0..=20.0)
                                    .step_by(0.5),
                            );
                            if ui.button("Reset layout").clicked() {
                                self.persisted.left_visible = true;
                                self.persisted.inspector_visible = true;
                                self.persisted.activity_visible = true;
                                self.persisted.layout_generation =
                                    self.persisted.layout_generation.wrapping_add(1);
                                ui.close();
                            }
                        });
                        if self.review.as_ref().is_some_and(ReviewLedger::can_redo)
                            && ui.button("Redo").clicked()
                        {
                            self.redo_review();
                        }
                        if self.review.as_ref().is_some_and(ReviewLedger::can_undo)
                            && ui.button("Undo").clicked()
                        {
                            self.undo_review();
                        }
                    });
                });

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let active = self.active_stage();
                    for stage in WorkflowStage::ALL {
                        let selected = stage == active;
                        let response = ui.selectable_label(selected, stage.label());
                        if response.clicked() {
                            match stage {
                                WorkflowStage::Open => self.choose_binary(),
                                WorkflowStage::Analyze => {
                                    self.persisted.active_tab = WorkTab::Overview
                                }
                                WorkflowStage::Review => {
                                    self.persisted.active_tab = WorkTab::Functions
                                }
                                WorkflowStage::Export => {
                                    self.persisted.active_tab = WorkTab::Exports
                                }
                            }
                        }
                    }
                    if let Some(operation) = self.busy {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!("● {}…", operation.label()))
                                    .color(tokens.accent),
                            );
                        });
                    }
                });
            });
    }

    fn project_rail(&mut self, ctx: &egui::Context, tokens: ThemeTokens) {
        if !self.persisted.left_visible {
            return;
        }
        let id = Id::new(("project_rail", self.persisted.layout_generation));
        let reviewed_projection = self
            .review_view
            .as_ref()
            .map(|view| view.projection.clone());
        egui::SidePanel::left(id)
            .default_width(236.0)
            .width_range(190.0..=380.0)
            .resizable(true)
            .frame(
                Frame::new()
                    .fill(tokens.panel)
                    .stroke(Stroke::new(1.0, tokens.border))
                    .inner_margin(Margin::same(12)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Project");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Hide").clicked() {
                            self.persisted.left_visible = false;
                        }
                    });
                });
                ui.horizontal(|ui| {
                    if ui.button("Open binary").clicked() {
                        self.choose_binary();
                    }
                    if ui.button("Open .resym").clicked() {
                        self.choose_package();
                    }
                });
                ui.separator();

                let project = self.project.clone();
                if let Some(project) = project {
                    let projection = reviewed_projection
                        .as_deref()
                        .unwrap_or_else(|| project.projection());
                    egui::CollapsingHeader::new(
                        project
                            .origin_path()
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("Active binary"),
                    )
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.label(RichText::new("✓ Exact SHA-256 identity").color(tokens.exact));
                        if project.has_verified_source() {
                            ui.label(
                                RichText::new("✓ Source bytes available").color(tokens.success),
                            );
                        } else {
                            ui.label(
                                RichText::new("○ Source bytes not attached").color(tokens.muted),
                            );
                            if ui.button("Verify source binary…").clicked() {
                                self.choose_exact_source();
                            }
                        }
                        ui.label(format!("{} functions", projection.functions.len()));
                        ui.label(format!("{} globals", projection.globals.len()));
                        ui.label(format!("{} types", projection.types.len()));
                    });
                    egui::CollapsingHeader::new("Analysis sessions")
                        .default_open(true)
                        .show(ui, |ui| {
                            ui.label("1 deterministic base session");
                            ui.label(format!(
                                "{} recorded plugin run(s)",
                                project.session().plugin_runs().len()
                            ));
                        });
                    if ui
                        .selectable_label(
                            self.persisted.active_tab == WorkTab::Functions,
                            "Functions",
                        )
                        .clicked()
                    {
                        self.persisted.active_tab = WorkTab::Functions;
                    }
                    if ui
                        .selectable_label(self.persisted.active_tab == WorkTab::Types, "Types")
                        .clicked()
                    {
                        self.persisted.active_tab = WorkTab::Types;
                    }
                    if ui
                        .selectable_label(
                            self.persisted.active_tab == WorkTab::Relationships,
                            "Relationships",
                        )
                        .clicked()
                    {
                        self.persisted.active_tab = WorkTab::Relationships;
                    }
                    if ui.button("Save package…").clicked() {
                        self.save_package();
                    }
                    ui.separator();
                    ui.label(RichText::new("Review sidecar").strong());
                    if let Some(path) = &self.review_path {
                        ui.label(
                            RichText::new(path.display().to_string())
                                .monospace()
                                .small()
                                .color(tokens.muted),
                        )
                        .on_hover_text(path.display().to_string());
                    }
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Open review…").clicked() {
                            self.open_review_sidecar();
                        }
                        if ui
                            .add_enabled(
                                self.review.is_some() && self.busy.is_none(),
                                egui::Button::new(if self.review_dirty {
                                    "Save review *"
                                } else {
                                    "Save review"
                                }),
                            )
                            .clicked()
                        {
                            self.review_dirty = true;
                            self.queue_review_save();
                        }
                        if ui.button("Save as…").clicked() {
                            self.save_review_sidecar_as();
                        }
                    });
                } else {
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new("Open a binary or package to begin.").color(tokens.muted),
                    );
                    ui.label("Supported now: PE32+ x86-64");
                }

                ui.separator();
                egui::CollapsingHeader::new("Plugins and health")
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.checkbox(&mut self.persisted.safe_mode, "Safe mode (discovery only)")
                            .on_hover_text(
                                "Lists plugin manifests without loading executable code",
                            );
                        ui.horizontal(|ui| {
                            ui.label("Root:");
                            ui.label(
                                RichText::new(self.persisted.plugin_root.display().to_string())
                                    .monospace()
                                    .small(),
                            );
                        });
                        ui.horizontal(|ui| {
                            if ui.button("Choose…").clicked() {
                                if let Some(root) = rfd::FileDialog::new()
                                    .set_title("Choose plugin root")
                                    .pick_folder()
                                {
                                    self.persisted.plugin_root = root;
                                }
                            }
                            if ui
                                .add_enabled(self.busy.is_none(), egui::Button::new("Scan plugins"))
                                .clicked()
                            {
                                self.discover_plugins();
                            }
                        });
                        if let Some(catalog) = &self.plugins {
                            if catalog.entries().is_empty() {
                                ui.label(
                                    RichText::new("○ No plugin manifests found")
                                        .color(tokens.muted),
                                );
                            }
                            for entry in catalog.entries() {
                                let (cue, color) = plugin_health_cue(&entry.health, tokens);
                                ui.label(
                                    RichText::new(format!(
                                        "{cue} {}",
                                        entry
                                            .name
                                            .as_deref()
                                            .or(entry.id.as_deref())
                                            .unwrap_or("Invalid plugin")
                                    ))
                                    .color(color),
                                )
                                .on_hover_text(format!(
                                    "{}\n{}",
                                    entry.health,
                                    entry.path.display()
                                ));
                            }
                        }
                    });
            });
    }

    fn inspector(&mut self, ctx: &egui::Context, tokens: ThemeTokens) {
        if !self.persisted.inspector_visible {
            return;
        }
        let id = Id::new(("context_inspector", self.persisted.layout_generation));
        let reviewed_projection = self
            .review_view
            .as_ref()
            .map(|view| view.projection.clone());
        egui::SidePanel::right(id)
            .default_width(330.0)
            .width_range(280.0..=520.0)
            .resizable(true)
            .frame(
                Frame::new()
                    .fill(tokens.panel)
                    .stroke(Stroke::new(1.0, tokens.border))
                    .inner_margin(Margin::same(12)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Inspector");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Hide").clicked() {
                            self.persisted.inspector_visible = false;
                        }
                    });
                });
                ui.separator();
                let Some(project) = self.project.clone() else {
                    ui.label(
                        RichText::new("Select a result to inspect its evidence.")
                            .color(tokens.muted),
                    );
                    return;
                };
                let Some(rva) = self.selected_function_rva else {
                    ui.label(RichText::new("Select a function row.").color(tokens.muted));
                    return;
                };
                let projection = reviewed_projection
                    .as_deref()
                    .unwrap_or_else(|| project.projection());
                let Some(function) = projection
                    .functions
                    .iter()
                    .find(|function| function.rva == rva)
                else {
                    ui.label(
                        RichText::new("The selected result is no longer present.")
                            .color(tokens.muted),
                    );
                    return;
                };
                let name = function_name(function);
                let status = function_status(function);
                ScrollArea::vertical().show(ui, |ui| {
                    ui.label(RichText::new(name).heading().monospace());
                    ui.label(RichText::new(status).color(status_color(function, tokens)));
                    ui.add_space(8.0);
                    property_row(ui, "RVA", format!("0x{:08X}", function.rva), true);
                    property_row(
                        ui,
                        "Size",
                        function
                            .size
                            .map_or_else(|| "Unknown".to_owned(), |value| format!("0x{value:X}")),
                        true,
                    );
                    property_row(
                        ui,
                        "Confidence",
                        format!("{:.0}%", function_confidence(function) * 100.0),
                        false,
                    );
                    property_row(ui, "Source", function_source(function), false);
                    ui.separator();

                    ui.strong("Provenance");
                    if let Some(attribution) = function_name_attribution(function) {
                        provenance_card(ui, attribution, tokens);
                    } else if let Some(attribution) = &function.entry_attribution {
                        provenance_card(ui, attribution, tokens);
                    } else {
                        ui.label(RichText::new("No retained attribution").color(tokens.muted));
                    }

                    ui.add_space(8.0);
                    ui.strong("Evidence");
                    ui.label(
                        RichText::new("Last observation: Not recorded by this package")
                            .small()
                            .color(tokens.muted),
                    );
                    let claim = selected_name_claim(&project, function).cloned();
                    if let Some(claim) = &claim {
                        for evidence in claim.evidence() {
                            Frame::new()
                                .fill(tokens.elevated)
                                .stroke(Stroke::new(1.0, tokens.border))
                                .inner_margin(Margin::same(8))
                                .corner_radius(4)
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(evidence.kind.as_str())
                                            .small()
                                            .color(tokens.accent),
                                    );
                                    ui.label(&evidence.summary);
                                    if let Some(confidence) = evidence.confidence {
                                        ui.label(format!(
                                            "Producer-defined contribution: {:.0}%",
                                            confidence.get() * 100.0
                                        ));
                                    }
                                    for (key, value) in &evidence.artifacts {
                                        ui.horizontal_wrapped(|ui| {
                                            ui.label(
                                                RichText::new(format!("{key}:"))
                                                    .color(tokens.muted),
                                            );
                                            ui.label(RichText::new(value).monospace());
                                        });
                                    }
                                });
                            ui.add_space(6.0);
                        }
                    } else {
                        ui.label(
                            RichText::new(
                                "No selected name claim; entry attribution is shown above.",
                            )
                            .color(tokens.muted),
                        );
                    }

                    if !function.alternate_names.is_empty() {
                        ui.add_space(8.0);
                        ui.strong("Competing names");
                        for alternate in &function.alternate_names {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new("⚠").color(tokens.warning));
                                ui.label(RichText::new(&alternate.text).monospace());
                                ui.label(format!(
                                    "{:.0}%",
                                    alternate.attribution.confidence * 100.0
                                ));
                                ui.label(
                                    RichText::new(format_export_producer(
                                        &alternate.attribution.provenance.producer,
                                    ))
                                    .color(tokens.muted),
                                );
                            });
                        }
                    }

                    ui.separator();
                    ui.strong("Review decision");
                    if let Some(claim) = claim {
                        if let (Some(review), Ok(subject)) = (
                            &self.review,
                            resymbol_app::ReviewSubject::from_name_claim(&claim),
                        ) {
                            if let Some(decision) = review.latest_disposition(&subject) {
                                ui.label(
                                    RichText::new(format!(
                                        "Current disposition: {}",
                                        review_action_text(decision.action())
                                    ))
                                    .color(review_action_color(decision.action(), tokens)),
                                );
                            }
                        }
                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .add_enabled(
                                    self.busy.is_none(),
                                    egui::Button::new("Accept primary"),
                                )
                                .clicked()
                            {
                                self.record_review_action(&claim, DecisionAction::AcceptPrimary);
                            }
                            if ui
                                .add_enabled(
                                    self.busy.is_none(),
                                    egui::Button::new("Keep as alias"),
                                )
                                .clicked()
                            {
                                self.record_review_action(&claim, DecisionAction::KeepAlias);
                            }
                            if ui
                                .add_enabled(self.busy.is_none(), egui::Button::new("Reject"))
                                .clicked()
                            {
                                self.record_review_action(&claim, DecisionAction::Reject);
                            }
                        });
                        ui.label("Annotation");
                        ui.add(
                            TextEdit::multiline(&mut self.annotation)
                                .desired_rows(3)
                                .hint_text("Explain the review decision…"),
                        );
                        if ui
                            .add_enabled(
                                self.busy.is_none() && !self.annotation.trim().is_empty(),
                                egui::Button::new("Add annotation"),
                            )
                            .clicked()
                        {
                            let text = self.annotation.trim().to_owned();
                            self.record_review_action(&claim, DecisionAction::Annotation { text });
                            self.annotation.clear();
                        }
                    } else {
                        ui.label(
                            RichText::new("Review actions require a retained name claim.")
                                .color(tokens.muted),
                        );
                    }
                    ui.label(format!(
                        "{} applied decision(s) · {} total history event(s)",
                        self.review
                            .as_ref()
                            .map_or(0, |review| review.applied_history().len()),
                        self.review
                            .as_ref()
                            .map_or(0, |review| review.history().len())
                    ));
                    if ui.button("Show review history").clicked() {
                        self.persisted.activity_visible = true;
                        self.persisted.activity_tab = ActivityTab::Review;
                    }
                });
            });
    }

    fn record_review_action(&mut self, claim: &SymbolClaim, action: DecisionAction) {
        if self.busy.is_some() {
            self.log(
                LogLevel::Warning,
                "Wait for the active operation before recording a review decision",
            );
            return;
        }
        let (Some(project), Some(mut review)) = (self.project.clone(), self.review.clone()) else {
            self.fail("the active project has no review ledger");
            return;
        };
        let result = match action {
            DecisionAction::AcceptPrimary => {
                review.accept_primary(claim, Some("workbench".to_owned()))
            }
            DecisionAction::KeepAlias => review.keep_alias(claim, Some("workbench".to_owned())),
            DecisionAction::Reject => review.reject(claim, Some("workbench".to_owned())),
            DecisionAction::Annotation { text } => {
                review.annotate(claim, text, Some("workbench".to_owned()))
            }
        }
        .map(|_| ());
        match result {
            Ok(()) => match ReviewViewState::build(&project, &review) {
                Ok(review_view) => {
                    self.commit_review_state(review, review_view, "Recorded review decision")
                }
                Err(error) => self.fail(format!(
                    "could not apply the review decision to the workbench: {error}"
                )),
            },
            Err(error) => self.fail(error.to_string()),
        }
    }

    fn activity_area(&mut self, ctx: &egui::Context, tokens: ThemeTokens) {
        if !self.persisted.activity_visible {
            return;
        }
        let id = Id::new(("activity_area", self.persisted.layout_generation));
        egui::TopBottomPanel::bottom(id)
            .default_height(190.0)
            .height_range(120.0..=380.0)
            .resizable(true)
            .frame(
                Frame::new()
                    .fill(tokens.panel)
                    .stroke(Stroke::new(1.0, tokens.border))
                    .inner_margin(Margin::same(8)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    for tab in ActivityTab::ALL {
                        if ui
                            .selectable_label(self.persisted.activity_tab == tab, tab.label())
                            .clicked()
                        {
                            self.persisted.activity_tab = tab;
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Hide").clicked() {
                            self.persisted.activity_visible = false;
                        }
                    });
                });
                ui.separator();
                match self.persisted.activity_tab {
                    ActivityTab::Progress => self.progress_view(ui, tokens),
                    ActivityTab::Plugins => self.plugin_runs_view(ui, tokens),
                    ActivityTab::Warnings => self.warnings_view(ui, tokens),
                    ActivityTab::Review => self.review_history_view(ui, tokens),
                    ActivityTab::Logs => self.logs_view(ui, tokens),
                }
            });
    }

    fn progress_view(&self, ui: &mut Ui, tokens: ThemeTokens) {
        if let Some(operation) = self.busy {
            ui.label(
                RichText::new(format!(
                    "● {} · working on a background thread",
                    operation.label()
                ))
                .color(tokens.accent),
            );
            ui.label(
                RichText::new("This stage does not expose a measurable percentage.")
                    .color(tokens.muted),
            );
        } else if self.project.is_some() {
            ui.label(RichText::new("✓ Analysis ready").color(tokens.success));
            ui.add(
                egui::ProgressBar::new(1.0)
                    .desired_width(ui.available_width())
                    .text("Deterministic analysis and projection complete"),
            );
        } else {
            ui.label(RichText::new("○ Waiting for a binary or package").color(tokens.muted));
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            for (label, complete) in [
                ("Identity", self.project.is_some()),
                ("Base analysis", self.project.is_some()),
                (
                    "Review",
                    self.review
                        .as_ref()
                        .is_some_and(|review| !review.applied_history().is_empty()),
                ),
                ("Export preview", self.prepared_export.is_some()),
            ] {
                let cue = if complete { "✓" } else { "○" };
                let color = if complete {
                    tokens.success
                } else {
                    tokens.muted
                };
                ui.label(RichText::new(format!("{cue} {label}")).color(color));
            }
        });
    }

    fn plugin_runs_view(&self, ui: &mut Ui, tokens: ThemeTokens) {
        let Some(project) = &self.project else {
            ui.label(RichText::new("Open a project to inspect plugin runs.").color(tokens.muted));
            return;
        };
        if project.session().plugin_runs().is_empty() {
            ui.label(
                RichText::new("○ No plugin runs are recorded in this session.").color(tokens.muted),
            );
            return;
        }
        ScrollArea::vertical().show(ui, |ui| {
            for run in project.session().plugin_runs() {
                let (cue, color) = match run.status() {
                    PluginRunStatus::Succeeded => ("✓ Succeeded", tokens.success),
                    PluginRunStatus::Failed => ("⛔ Failed", tokens.danger),
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(cue).color(color));
                    ui.label(format!("{} {}", run.plugin_id(), run.plugin_version()));
                    ui.label(RichText::new(run.run_id()).monospace().color(tokens.muted));
                    ui.label(format!("{} accepted claim(s)", run.accepted_claim_count()));
                });
            }
        });
    }

    fn warnings_view(&self, ui: &mut Ui, tokens: ThemeTokens) {
        let Some(project) = &self.project else {
            ui.label(
                RichText::new("Open a project to inspect projection warnings.").color(tokens.muted),
            );
            return;
        };
        let projection = self
            .review_view
            .as_ref()
            .map_or_else(|| project.projection(), |view| view.projection.as_ref());
        let warnings = &projection.warnings;
        if warnings.is_empty() {
            ui.label(RichText::new("✓ No projection warnings").color(tokens.success));
            return;
        }
        ScrollArea::vertical().show(ui, |ui| {
            for warning in warnings {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("⚠ Warning").color(tokens.warning));
                    ui.label(&warning.message);
                    if warning.occurrences > 1 {
                        ui.label(
                            RichText::new(format!("×{}", warning.occurrences)).color(tokens.muted),
                        );
                    }
                });
            }
        });
    }

    fn logs_view(&self, ui: &mut Ui, tokens: ThemeTokens) {
        ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            for entry in &self.logs {
                let (cue, color) = match entry.level {
                    LogLevel::Info => ("●", tokens.muted),
                    LogLevel::Success => ("✓", tokens.success),
                    LogLevel::Warning => ("⚠", tokens.warning),
                    LogLevel::Error => ("⛔", tokens.danger),
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(&entry.timestamp)
                            .monospace()
                            .color(tokens.muted),
                    );
                    ui.label(RichText::new(cue).color(color));
                    ui.label(&entry.message);
                });
            }
        });
    }

    fn review_history_view(&mut self, ui: &mut Ui, tokens: ThemeTokens) {
        let (Some(review), Some(review_view)) = (self.review.clone(), self.review_view.clone())
        else {
            ui.label(
                RichText::new("Open a project to inspect review history.").color(tokens.muted),
            );
            return;
        };
        let applied_count = review.applied_history().len();
        let redo_count = review.redo_history().len();
        let orphan_count = review_view.orphaned_sequences.len();
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("✓ {applied_count} applied")).color(tokens.success));
            ui.label(RichText::new(format!("↻ {redo_count} redo available")).color(tokens.muted));
            let orphan_color = if orphan_count == 0 {
                tokens.muted
            } else {
                tokens.warning
            };
            ui.label(RichText::new(format!("⚠ {orphan_count} orphaned")).color(orphan_color));
            if ui
                .add_enabled(
                    self.busy.is_none() && review.can_undo(),
                    egui::Button::new("Undo"),
                )
                .clicked()
            {
                self.undo_review();
            }
            if ui
                .add_enabled(
                    self.busy.is_none() && review.can_redo(),
                    egui::Button::new("Redo"),
                )
                .clicked()
            {
                self.redo_review();
            }
        });
        ui.separator();
        if review.history().is_empty() {
            ui.label(
                RichText::new("No review decisions have been recorded for this binary.")
                    .color(tokens.muted),
            );
            return;
        }
        let total = review.history().len();
        if total > 200 {
            ui.label(
                RichText::new(format!("Showing the 200 most recent of {total} decisions"))
                    .small()
                    .color(tokens.muted),
            );
        }
        ScrollArea::vertical().show(ui, |ui| {
            for (index, decision) in review.history().iter().enumerate().rev().take(200) {
                let applied = index < applied_count;
                let orphaned = applied
                    && review_view
                        .orphaned_sequences
                        .contains(&decision.sequence());
                let (state, state_color) = if orphaned {
                    ("Orphaned", tokens.warning)
                } else if applied {
                    ("Applied", tokens.success)
                } else {
                    ("Redo", tokens.muted)
                };
                Frame::new()
                    .fill(tokens.elevated)
                    .stroke(Stroke::new(1.0, tokens.border))
                    .inner_margin(Margin::symmetric(8, 5))
                    .corner_radius(4)
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(format!("#{:04}", decision.sequence()))
                                    .monospace()
                                    .color(tokens.muted),
                            );
                            ui.label(RichText::new(state).color(state_color).strong());
                            ui.label(
                                RichText::new(review_action_text(decision.action()))
                                    .color(review_action_color(decision.action(), tokens)),
                            );
                            ui.label(RichText::new(decision.subject().name()).monospace());
                            ui.label(
                                RichText::new(review_subject_text(decision.subject().symbol()))
                                    .monospace()
                                    .color(tokens.muted),
                            );
                            if let Some(reviewer) = decision.reviewer() {
                                ui.label(
                                    RichText::new(format!("by {reviewer}"))
                                        .small()
                                        .color(tokens.muted),
                                );
                            }
                        });
                    });
                ui.add_space(4.0);
            }
        });
    }

    fn central_work_area(&mut self, ctx: &egui::Context, tokens: ThemeTokens) {
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(tokens.canvas)
                    .inner_margin(Margin::same(12)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    for tab in WorkTab::ALL {
                        if ui
                            .add_sized(
                                [ui.available_width().min(130.0), 34.0],
                                egui::Button::selectable(
                                    self.persisted.active_tab == tab,
                                    tab.label(),
                                ),
                            )
                            .clicked()
                        {
                            self.persisted.active_tab = tab;
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if !self.persisted.inspector_visible
                            && ui.button("Show inspector").clicked()
                        {
                            self.persisted.inspector_visible = true;
                        }
                        if !self.persisted.left_visible && ui.button("Show project").clicked() {
                            self.persisted.left_visible = true;
                        }
                        if !self.persisted.activity_visible && ui.button("Show activity").clicked()
                        {
                            self.persisted.activity_visible = true;
                        }
                    });
                });
                ui.separator();

                let project = self.project.clone();
                let reviewed_projection = self
                    .review_view
                    .as_ref()
                    .map(|view| view.projection.clone());
                match (self.persisted.active_tab, project) {
                    (_, None) => self.empty_project_view(ui, tokens),
                    (WorkTab::Overview, Some(project)) => {
                        let projection = reviewed_projection
                            .as_deref()
                            .unwrap_or_else(|| project.projection());
                        self.overview_view(ui, &project, projection, tokens);
                    }
                    (WorkTab::Functions, Some(project)) => {
                        let projection = reviewed_projection
                            .as_deref()
                            .unwrap_or_else(|| project.projection());
                        self.functions_view(ui, projection, tokens)
                    }
                    (WorkTab::Types, Some(project)) => {
                        let projection = reviewed_projection
                            .as_deref()
                            .unwrap_or_else(|| project.projection());
                        self.types_view(ui, projection, tokens)
                    }
                    (WorkTab::Relationships, Some(project)) => {
                        let projection = reviewed_projection
                            .as_deref()
                            .unwrap_or_else(|| project.projection());
                        self.relationships_view(ui, projection, tokens)
                    }
                    (WorkTab::Exports, Some(project)) => self.exports_view(ui, &project, tokens),
                }
            });
    }

    fn empty_project_view(&mut self, ui: &mut Ui, tokens: ThemeTokens) {
        ui.vertical_centered(|ui| {
            ui.add_space(90.0);
            ui.label(RichText::new("Open a binary to reconstruct symbols").heading().strong());
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "ReSymbol analyzes untrusted bytes without loading or executing the binary.",
                )
                .color(tokens.muted),
            );
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                if ui.button("Open binary…  Ctrl+O").clicked() {
                    self.choose_binary();
                }
                if ui.button("Open package…  Ctrl+Shift+O").clicked() {
                    self.choose_package();
                }
            });
            ui.add_space(18.0);
            Frame::new()
                .fill(tokens.elevated)
                .stroke(Stroke::new(1.0, tokens.border))
                .inner_margin(Margin::same(16))
                .corner_radius(4)
                .show(ui, |ui| {
                    ui.label("You can also drag and drop a PE binary or .resym package anywhere in this window.");
                    ui.label(RichText::new("Current analyzer: PE32+ x86-64").color(tokens.muted));
                });
        });
    }

    fn overview_view(
        &mut self,
        ui: &mut Ui,
        project: &ProjectSnapshot,
        projection: &ExportProjection,
        tokens: ThemeTokens,
    ) {
        ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Analysis overview");
            ui.label(
                RichText::new("Validated results for the exact active binary build")
                    .color(tokens.muted),
            );
            ui.add_space(12.0);
            ui.columns(5, |columns| {
                summary_card(
                    &mut columns[0],
                    "Functions",
                    projection.functions.len(),
                    tokens.accent,
                    tokens,
                );
                summary_card(
                    &mut columns[1],
                    "Globals",
                    projection.globals.len(),
                    tokens.inferred,
                    tokens,
                );
                summary_card(
                    &mut columns[2],
                    "Types",
                    projection.types.len(),
                    tokens.plugin,
                    tokens,
                );
                summary_card(
                    &mut columns[3],
                    "Relationships",
                    projection.direct_calls.len()
                        + projection.thunks.len()
                        + projection.data_references.len(),
                    tokens.success,
                    tokens,
                );
                summary_card(
                    &mut columns[4],
                    "Warnings",
                    projection.warnings.len(),
                    tokens.warning,
                    tokens,
                );
            });
            ui.add_space(16.0);
            ui.columns(2, |columns| {
                Frame::new()
                    .fill(tokens.panel)
                    .stroke(Stroke::new(1.0, tokens.border))
                    .inner_margin(Margin::same(16))
                    .corner_radius(4)
                    .show(&mut columns[0], |ui| {
                        ui.heading("Binary identity");
                        let identity = project.session().base_analysis().identity();
                        property_row(ui, "SHA-256", identity.id.to_string(), true);
                        property_row(ui, "Size", format_bytes(identity.size), false);
                        property_row(ui, "Architecture", identity.architecture.clone(), false);
                        property_row(
                            ui,
                            "Image base",
                            format!("0x{:X}", identity.image_base),
                            true,
                        );
                        property_row(
                            ui,
                            "Source bytes",
                            if project.has_verified_source() {
                                "✓ Verified and available".to_owned()
                            } else {
                                "○ Package identity only".to_owned()
                            },
                            false,
                        );
                    });
                Frame::new()
                    .fill(tokens.panel)
                    .stroke(Stroke::new(1.0, tokens.border))
                    .inner_margin(Margin::same(16))
                    .corner_radius(4)
                    .show(&mut columns[1], |ui| {
                        ui.heading("PE inventory");
                        match project.session().base_analysis() {
                            BinaryAnalysis::Pe(pe) => {
                                property_row(ui, "Sections", pe.sections.len().to_string(), false);
                                property_row(ui, "Imports", pe.imports.len().to_string(), false);
                                property_row(ui, "Exports", pe.exports.len().to_string(), false);
                                property_row(
                                    ui,
                                    "Runtime functions",
                                    pe.runtime_functions.len().to_string(),
                                    false,
                                );
                                property_row(
                                    ui,
                                    "Recovered strings",
                                    pe.strings.len().to_string(),
                                    false,
                                );
                                property_row(
                                    ui,
                                    "MSVC RTTI tables",
                                    pe.msvc_rtti_vftables.len().to_string(),
                                    false,
                                );
                            }
                            _ => {
                                ui.label("This binary format has no PE inventory.");
                            }
                        }
                    });
            });
            ui.add_space(16.0);
            ui.heading("Sections");
            match project.session().base_analysis() {
                BinaryAnalysis::Pe(pe) => {
                    TableBuilder::new(ui)
                        .striped(true)
                        .column(Column::exact(130.0))
                        .column(Column::exact(130.0))
                        .column(Column::exact(130.0))
                        .column(Column::remainder())
                        .header(28.0, |mut header| {
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
                    empty_result(ui, "This binary format has no PE section table.", tokens);
                }
            }
        });
    }

    fn functions_view(&mut self, ui: &mut Ui, projection: &ExportProjection, tokens: ThemeTokens) {
        ui.horizontal(|ui| {
            let response = ui.add(
                TextEdit::singleline(&mut self.function_filter)
                    .id(Id::new("function_filter"))
                    .hint_text("Search name, source, or RVA…")
                    .desired_width(300.0),
            );
            if self.focus_function_filter {
                response.request_focus();
                self.focus_function_filter = false;
            }
            ComboBox::from_id_salt("function_status_filter")
                .selected_text(self.persisted.status_filter.label())
                .show_ui(ui, |ui| {
                    for status in StatusFilter::ALL {
                        ui.selectable_value(
                            &mut self.persisted.status_filter,
                            status,
                            status.label(),
                        );
                    }
                });
            if !self.function_filter.is_empty() && ui.button("Clear filter").clicked() {
                self.function_filter.clear();
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("{} total", projection.functions.len()))
                        .color(tokens.muted),
                );
            });
        });
        ui.add_space(6.0);

        let filter = self.function_filter.to_ascii_lowercase();
        let mut functions = projection
            .functions
            .iter()
            .filter(|function| function_matches(function, &filter, self.persisted.status_filter))
            .collect::<Vec<_>>();
        functions
            .sort_by(|left, right| compare_functions(left, right, self.persisted.function_sort));
        if !self.persisted.function_sort_ascending {
            functions.reverse();
        }

        let available_height = ui.available_height();
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .min_scrolled_height(available_height)
            .column(Column::initial(120.0).at_least(100.0))
            .column(Column::initial(105.0).at_least(95.0))
            .column(Column::remainder().at_least(180.0))
            .column(Column::initial(150.0).at_least(120.0))
            .column(Column::initial(175.0).at_least(120.0))
            .column(Column::initial(90.0).at_least(70.0))
            .header(30.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Status");
                });
                header.col(|ui| sortable_header(ui, "RVA", FunctionSort::Rva, self));
                header.col(|ui| {
                    sortable_header(ui, "Reconstructed name", FunctionSort::Name, self);
                });
                header.col(|ui| {
                    sortable_header(ui, "Confidence", FunctionSort::Confidence, self);
                });
                header.col(|ui| {
                    sortable_header(ui, "Source", FunctionSort::Source, self);
                });
                header.col(|ui| sortable_header(ui, "Size", FunctionSort::Size, self));
            })
            .body(|body| {
                body.rows(28.0, functions.len(), |mut row| {
                    let function = functions[row.index()];
                    row.set_selected(self.selected_function_rva == Some(function.rva));
                    row.col(|ui| {
                        ui.label(
                            RichText::new(function_status(function))
                                .color(status_color(function, tokens)),
                        );
                    });
                    row.col(|ui| {
                        ui.monospace(format!("0x{:08X}", function.rva));
                    });
                    row.col(|ui| {
                        ui.monospace(function_name(function));
                    });
                    row.col(|ui| {
                        let confidence = function_confidence(function) as f32;
                        ui.add(
                            egui::ProgressBar::new(confidence)
                                .desired_width(ui.available_width())
                                .text(format!("{:.0}%", confidence * 100.0)),
                        );
                    });
                    row.col(|ui| {
                        let source = function_source(function);
                        let color = if function_is_plugin(function) {
                            tokens.plugin
                        } else {
                            tokens.muted
                        };
                        ui.label(RichText::new(source).color(color));
                    });
                    row.col(|ui| {
                        ui.monospace(
                            function
                                .size
                                .map_or_else(|| "—".to_owned(), |size| format!("0x{size:X}")),
                        );
                    });
                    if row.response().clicked() {
                        self.selected_function_rva = Some(function.rva);
                    }
                });
            });
    }

    fn types_view(&mut self, ui: &mut Ui, projection: &ExportProjection, tokens: ThemeTokens) {
        ui.heading("Recovered types");
        ui.label(
            RichText::new(format!("{} projected type(s)", projection.types.len()))
                .color(tokens.muted),
        );
        ui.add_space(8.0);
        if projection.types.is_empty() {
            empty_result(ui, "No type claims are present in this analysis.", tokens);
            return;
        }
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .column(Column::initial(220.0))
            .column(Column::initial(220.0))
            .column(Column::remainder())
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
                for value in &projection.types {
                    body.row(28.0, |mut row| {
                        row.col(|ui| {
                            ui.monospace(&value.key);
                        });
                        row.col(|ui| {
                            ui.monospace(
                                value
                                    .selected_name
                                    .as_ref()
                                    .map_or("—", |name| name.source.text.as_str()),
                            );
                        });
                        row.col(|ui| {
                            ui.label(format!(
                                "{} definition(s) · {} alternate name(s)",
                                value.definitions.len(),
                                value.alternate_names.len()
                            ));
                        });
                    });
                }
            });
    }

    fn relationships_view(
        &mut self,
        ui: &mut Ui,
        projection: &ExportProjection,
        tokens: ThemeTokens,
    ) {
        ui.heading("Recovered relationships");
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("{} direct calls", projection.direct_calls.len()));
            ui.label(format!("{} thunks", projection.thunks.len()));
            ui.label(format!(
                "{} data references",
                projection.data_references.len()
            ));
        });
        ui.add_space(8.0);
        if projection.direct_calls.is_empty()
            && projection.thunks.is_empty()
            && projection.data_references.is_empty()
        {
            empty_result(
                ui,
                "No relationships were retained in this projection.",
                tokens,
            );
            return;
        }
        ScrollArea::vertical().show(ui, |ui| {
            if !projection.direct_calls.is_empty() {
                ui.strong("Direct calls");
                for call in &projection.direct_calls {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("→").color(tokens.inferred));
                        ui.monospace(format!(
                            "0x{:08X} + call 0x{:08X}",
                            call.caller_rva, call.call_site_rva
                        ));
                        ui.label("to");
                        ui.monospace(control_flow_target(&call.target));
                        ui.label(
                            RichText::new(format_export_producer(
                                &call.attribution.provenance.producer,
                            ))
                            .color(tokens.muted),
                        );
                    });
                }
                ui.separator();
            }
            if !projection.thunks.is_empty() {
                ui.strong("Thunks");
                for thunk in &projection.thunks {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("⇢").color(tokens.plugin));
                        ui.monospace(format!("0x{:08X}", thunk.rva));
                        ui.label("jumps to");
                        ui.monospace(control_flow_target(&thunk.target));
                    });
                }
                ui.separator();
            }
            if !projection.data_references.is_empty() {
                ui.strong("Data references");
                for reference in &projection.data_references {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("↦").color(tokens.accent));
                        ui.monospace(format!("0x{:08X}", reference.instruction_rva));
                        ui.label("references");
                        ui.monospace(format!("0x{:08X}", reference.target_rva));
                        if let Some(string_rva) = reference.referenced_string_rva {
                            ui.label(
                                RichText::new(format!("string @ 0x{string_rva:08X}"))
                                    .color(tokens.success),
                            );
                        }
                    });
                }
            }
        });
    }

    fn exports_view(&mut self, ui: &mut Ui, project: &ProjectSnapshot, tokens: ThemeTokens) {
        ui.heading("Validated export");
        ui.label(
            RichText::new("Preview target capabilities and losses before creating a new file.")
                .color(tokens.muted),
        );
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label("Format");
            ComboBox::from_id_salt("export_format")
                .selected_text(export_format_label(self.export_format))
                .show_ui(ui, |ui| {
                    for format in export_formats() {
                        if ui
                            .selectable_value(
                                &mut self.export_format,
                                format,
                                export_format_label(format),
                            )
                            .changed()
                        {
                            self.prepared_export = None;
                            self.prepared_format = None;
                        }
                    }
                });
            if ui
                .add_enabled(self.busy.is_none(), egui::Button::new("Prepare preview"))
                .clicked()
            {
                self.prepare_export();
            }
        });

        if self.export_format == ExportFormat::Pdb && !project.has_verified_source() {
            Frame::new()
                .fill(tokens.elevated)
                .stroke(Stroke::new(1.0, tokens.warning))
                .inner_margin(Margin::same(12))
                .corner_radius(4)
                .show(ui, |ui| {
                    ui.label(RichText::new("⚠ Exact source PE required").color(tokens.warning).strong());
                    ui.label("PDB writing requires a SHA-256 match and an unambiguous RSDS GUID+age from the original PE.");
                    if ui.button("Verify exact source binary…").clicked() {
                        self.choose_exact_source();
                    }
                });
        }

        ui.add_space(12.0);
        let Some(prepared) = self.prepared_export.clone() else {
            Frame::new()
                .fill(tokens.panel)
                .stroke(Stroke::new(1.0, tokens.border))
                .inner_margin(Margin::same(16))
                .corner_radius(4)
                .show(ui, |ui| {
                    ui.label(RichText::new("No preview prepared").strong());
                    ui.label(RichText::new("Choose a format, then prepare the same validated projection used by the CLI.").color(tokens.muted));
                });
            return;
        };

        Frame::new()
            .fill(tokens.panel)
            .stroke(Stroke::new(1.0, tokens.border))
            .inner_margin(Margin::same(16))
            .corner_radius(4)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("✓ Preview ready")
                            .color(tokens.success)
                            .strong(),
                    );
                    ui.label(export_format_label(prepared.format()));
                    ui.label(RichText::new(prepared.media_type()).color(tokens.muted));
                });
                ui.separator();
                ui.columns(4, |columns| {
                    summary_card(
                        &mut columns[0],
                        "Functions",
                        prepared.function_count(),
                        tokens.accent,
                        tokens,
                    );
                    summary_card(
                        &mut columns[1],
                        "Globals",
                        prepared.global_count(),
                        tokens.inferred,
                        tokens,
                    );
                    summary_card(
                        &mut columns[2],
                        "Types",
                        prepared.type_count(),
                        tokens.plugin,
                        tokens,
                    );
                    summary_card(
                        &mut columns[3],
                        "Losses",
                        usize::try_from(prepared.warning_occurrences()).unwrap_or(usize::MAX),
                        tokens.warning,
                        tokens,
                    );
                });
                ui.add_space(8.0);
                property_row(
                    ui,
                    "Target binary",
                    project.projection().binary.id.to_string(),
                    true,
                );
                property_row(
                    ui,
                    "Suggested name",
                    prepared.suggested_file_name().to_owned(),
                    true,
                );
                property_row(
                    ui,
                    "Encoded size",
                    format_bytes(prepared.bytes().len() as u64),
                    false,
                );
                ui.label(
                    RichText::new(
                        "Create-new safety is enforced: existing files are never overwritten.",
                    )
                    .color(tokens.muted),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("Destination");
                    ui.add_enabled(
                        false,
                        TextEdit::singleline(&mut self.export_destination).desired_width(300.0),
                    );
                    if ui
                        .add_enabled(self.busy.is_none(), egui::Button::new("Create export…"))
                        .clicked()
                    {
                        self.publish_export();
                    }
                });
            });
    }
}

impl eframe::App for WorkbenchApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_capture_result(ctx);
        self.handle_worker_events();
        self.handle_shortcuts(ctx);
        self.handle_dropped_files(ctx);
        self.ensure_theme(ctx);
        let tokens = self.persisted.theme.tokens();

        self.header(ctx, tokens);
        self.activity_area(ctx, tokens);
        self.project_rail(ctx, tokens);
        self.inspector(ctx, tokens);
        self.central_work_area(ctx, tokens);

        if let Some(message) = self.error.clone() {
            egui::Window::new("ReSymbol could not complete the operation")
                .id(Id::new("operation_error"))
                .collapsible(false)
                .resizable(true)
                .default_width(520.0)
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new("⛔ Operation failed")
                            .color(tokens.danger)
                            .strong(),
                    );
                    ui.add_space(6.0);
                    ui.label(message);
                    ui.add_space(8.0);
                    if ui.button("Close").clicked() {
                        self.error = None;
                    }
                });
        }

        self.request_capture_when_ready(ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if self.capture.is_none() {
            eframe::set_value(storage, APP_STORAGE_KEY, &self.persisted);
        }
    }

    fn persist_egui_memory(&self) -> bool {
        self.capture.is_none()
    }

    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        if self.capture.is_some() {
            raw_input
                .events
                .retain(|event| matches!(event, egui::Event::Screenshot { .. }));
            raw_input.hovered_files.clear();
            raw_input.dropped_files.clear();
            raw_input.modifiers = Modifiers::default();
        }
    }
}

fn summary_card(ui: &mut Ui, label: &str, count: usize, color: Color32, tokens: ThemeTokens) {
    Frame::new()
        .fill(tokens.panel)
        .stroke(Stroke::new(1.0, tokens.border))
        .inner_margin(Margin::same(12))
        .corner_radius(4)
        .show(ui, |ui| {
            ui.label(
                RichText::new(count.to_string())
                    .size(24.0)
                    .strong()
                    .color(color),
            );
            ui.label(RichText::new(label).color(tokens.muted));
        });
}

fn property_row(ui: &mut Ui, label: &str, value: String, monospace: bool) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{label}:")).strong());
        if monospace {
            ui.label(RichText::new(value).monospace());
        } else {
            ui.label(value);
        }
    });
}

fn provenance_card(ui: &mut Ui, attribution: &ExportAttribution, tokens: ThemeTokens) {
    Frame::new()
        .fill(tokens.elevated)
        .stroke(Stroke::new(1.0, tokens.border))
        .inner_margin(Margin::same(8))
        .corner_radius(4)
        .show(ui, |ui| {
            ui.label(
                RichText::new(format_export_producer(&attribution.provenance.producer)).color(
                    match attribution.provenance.producer {
                        ExportProducer::Plugin { .. } => tokens.plugin,
                        ExportProducer::User { .. } => tokens.success,
                        _ => tokens.accent,
                    },
                ),
            );
            property_row(ui, "Method", attribution.provenance.method.clone(), false);
            if let Some(run_id) = &attribution.provenance.run_id {
                property_row(ui, "Run", run_id.clone(), true);
            }
            property_row(
                ui,
                "Claim confidence",
                format!("{:.0}%", attribution.confidence * 100.0),
                false,
            );
        });
}

fn empty_result(ui: &mut Ui, text: &str, tokens: ThemeTokens) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new("○ No results").color(tokens.muted).heading());
        ui.label(RichText::new(text).color(tokens.muted));
    });
}

fn function_name(function: &ExportFunction) -> &str {
    function
        .selected_name
        .as_ref()
        .map_or("<unnamed function>", |name| name.source.text.as_str())
}

fn function_name_attribution(function: &ExportFunction) -> Option<&ExportAttribution> {
    function
        .selected_name
        .as_ref()
        .map(|name| &name.source.attribution)
}

fn function_confidence(function: &ExportFunction) -> f64 {
    function_name_attribution(function)
        .or(function.entry_attribution.as_ref())
        .map_or(0.0, |attribution| attribution.confidence)
}

fn function_source(function: &ExportFunction) -> String {
    function_name_attribution(function)
        .or(function.entry_attribution.as_ref())
        .map_or_else(
            || "No attribution".to_owned(),
            |attribution| format_export_producer(&attribution.provenance.producer),
        )
}

fn function_status(function: &ExportFunction) -> &'static str {
    if function.alternate_names.is_empty() {
        if function.selected_name.is_some() {
            "✓ Extracted"
        } else {
            "◌ Inferred entry"
        }
    } else {
        "⚠ Name conflict"
    }
}

fn function_is_plugin(function: &ExportFunction) -> bool {
    function_name_attribution(function)
        .or(function.entry_attribution.as_ref())
        .is_some_and(|attribution| {
            matches!(
                attribution.provenance.producer,
                ExportProducer::Plugin { .. }
            )
        })
}

fn status_color(function: &ExportFunction, tokens: ThemeTokens) -> Color32 {
    if !function.alternate_names.is_empty() {
        tokens.warning
    } else if function.selected_name.is_some() {
        tokens.exact
    } else {
        tokens.inferred
    }
}

fn function_matches(function: &ExportFunction, filter: &str, status: StatusFilter) -> bool {
    let status_match = match status {
        StatusFilter::All => true,
        StatusFilter::Named => function.selected_name.is_some(),
        StatusFilter::Unnamed => function.selected_name.is_none(),
        StatusFilter::Conflicts => !function.alternate_names.is_empty(),
        StatusFilter::Plugin => function_is_plugin(function),
    };
    if !status_match || filter.is_empty() {
        return status_match;
    }
    function_name(function)
        .to_ascii_lowercase()
        .contains(filter)
        || function_source(function)
            .to_ascii_lowercase()
            .contains(filter)
        || format!("{:x}", function.rva).contains(filter.trim_start_matches("0x"))
}

fn compare_functions(
    left: &ExportFunction,
    right: &ExportFunction,
    sort: FunctionSort,
) -> Ordering {
    match sort {
        FunctionSort::Rva => left.rva.cmp(&right.rva),
        FunctionSort::Name => function_name(left).cmp(function_name(right)),
        FunctionSort::Confidence => function_confidence(left)
            .partial_cmp(&function_confidence(right))
            .unwrap_or(Ordering::Equal),
        FunctionSort::Size => left.size.cmp(&right.size),
        FunctionSort::Source => function_source(left).cmp(&function_source(right)),
    }
    .then_with(|| left.rva.cmp(&right.rva))
}

fn sortable_header(ui: &mut Ui, label: &str, sort: FunctionSort, app: &mut WorkbenchApp) {
    let suffix = if app.persisted.function_sort == sort {
        if app.persisted.function_sort_ascending {
            " ↑"
        } else {
            " ↓"
        }
    } else {
        ""
    };
    if ui.button(format!("{label}{suffix}")).clicked() {
        if app.persisted.function_sort == sort {
            app.persisted.function_sort_ascending = !app.persisted.function_sort_ascending;
        } else {
            app.persisted.function_sort = sort;
            app.persisted.function_sort_ascending = true;
        }
    }
}

fn selected_name_claim<'a>(
    project: &'a ProjectSnapshot,
    function: &ExportFunction,
) -> Option<&'a SymbolClaim> {
    let selected_name = function.selected_name.as_ref()?.source.text.as_str();
    let matches = |claim: &&SymbolClaim| {
        matches!(
            claim.subject(),
            SymbolSubject::Function { rva, .. } if *rva == function.rva
        ) && matches!(
            claim.assertion(),
            SymbolAssertion::Name { name } if name == selected_name
        )
    };
    let mut matches = project
        .session()
        .base_analysis()
        .symbol_graph()
        .claims()
        .iter()
        .chain(project.session().plugin_claims())
        .filter(matches);
    let claim = matches.next()?;
    matches.next().is_none().then_some(claim)
}

fn review_action_text(action: &DecisionAction) -> String {
    match action {
        DecisionAction::AcceptPrimary => "Accepted primary".to_owned(),
        DecisionAction::KeepAlias => "Kept alias".to_owned(),
        DecisionAction::Reject => "Rejected".to_owned(),
        DecisionAction::Annotation { text } => {
            let mut summary = text.chars().take(80).collect::<String>();
            if text.chars().count() > 80 {
                summary.push('…');
            }
            format!("Annotation: {summary}")
        }
    }
}

fn review_action_color(action: &DecisionAction, tokens: ThemeTokens) -> Color32 {
    match action {
        DecisionAction::AcceptPrimary => tokens.success,
        DecisionAction::KeepAlias => tokens.accent,
        DecisionAction::Reject => tokens.danger,
        DecisionAction::Annotation { .. } => tokens.inferred,
    }
}

fn review_subject_text(subject: &SymbolSubject) -> String {
    match subject {
        SymbolSubject::Function { rva, .. } => format!("function 0x{rva:08X}"),
        SymbolSubject::Global { rva, .. } => format!("global 0x{rva:08X}"),
        SymbolSubject::Type { key, .. } => format!("type {key}"),
    }
}

fn format_export_producer(producer: &ExportProducer) -> String {
    match producer {
        ExportProducer::Core { component, version } => format!("Core · {component} {version}"),
        ExportProducer::Plugin { id, version } => format!("Plugin · {id} {version}"),
        ExportProducer::User { reviewer } => reviewer.as_ref().map_or_else(
            || "User review".to_owned(),
            |reviewer| format!("User · {reviewer}"),
        ),
        _ => "Other producer".to_owned(),
    }
}

fn control_flow_target(target: &ExportControlFlowTarget) -> String {
    match target {
        ExportControlFlowTarget::Function { rva } => format!("function 0x{rva:08X}"),
        ExportControlFlowTarget::ImportIat { iat_rva } => format!("IAT 0x{iat_rva:08X}"),
        ExportControlFlowTarget::FunctionPointer { slot_rva, rva } => {
            format!("function 0x{rva:08X} via [0x{slot_rva:08X}]")
        }
        _ => "unsupported target".to_owned(),
    }
}

fn export_formats() -> [ExportFormat; 6] {
    [
        ExportFormat::Json,
        ExportFormat::Markdown,
        ExportFormat::Map,
        ExportFormat::Pdb,
        ExportFormat::IdaPython,
        ExportFormat::GhidraJava,
    ]
}

fn export_format_label(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::Json => "JSON projection",
        ExportFormat::Markdown => "Markdown report",
        ExportFormat::Map => "Microsoft MAP",
        ExportFormat::Pdb => "Exact-RSDS public PDB",
        ExportFormat::IdaPython => "IDA Python",
        ExportFormat::GhidraJava => "Ghidra Java",
    }
}

fn plugin_health_cue(health: &str, tokens: ThemeTokens) -> (&'static str, Color32) {
    let normalized = health.to_ascii_lowercase();
    if normalized.contains("healthy")
        || normalized.contains("loadable")
        || normalized.contains("enabled")
    {
        ("✓ Enabled", tokens.success)
    } else if normalized.contains("quarantined") || normalized.contains("failed") {
        ("⛔ Quarantined", tokens.danger)
    } else if normalized.contains("development-error") {
        ("⛔ Development error", tokens.danger)
    } else if normalized.contains("approval") {
        ("⚠ Approval required", tokens.warning)
    } else if normalized.contains("incompatible") {
        ("⚠ Incompatible", tokens.warning)
    } else if normalized.contains("disabled") {
        ("○ Disabled", tokens.muted)
    } else if normalized.contains("discovered") {
        ("○ Discovered", tokens.muted)
    } else {
        ("○ Unknown state", tokens.muted)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn short_hash(hash: &str) -> String {
    if hash.len() > 20 {
        format!("{}…{}", &hash[..12], &hash[hash.len() - 6..])
    } else {
        hash.to_owned()
    }
}

fn is_package_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("resym"))
}

fn default_review_path(origin: &Path) -> PathBuf {
    let mut file_name = origin
        .file_name()
        .map_or_else(|| "analysis".into(), |name| name.to_os_string());
    file_name.push(".resymbol-workbench.json");
    origin.with_file_name(file_name)
}

fn save_color_image_png(path: &Path, image: &egui::ColorImage) -> Result<(), String> {
    let [width, height] = image.size;
    if width == 0 || height == 0 || image.pixels.len() != width * height {
        return Err("the renderer returned an invalid image buffer".to_owned());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "could not create capture directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        format!(
            "could not create a temporary capture in {}: {error}",
            parent.display()
        )
    })?;
    {
        let mut encoder = png::Encoder::new(
            BufWriter::new(temporary.as_file_mut()),
            width as u32,
            height as u32,
        );
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|error| format!("could not initialize PNG encoding: {error}"))?;
        writer
            .write_image_data(image.as_raw())
            .map_err(|error| format!("could not encode PNG pixels: {error}"))?;
        writer
            .finish()
            .map_err(|error| format!("could not finish PNG encoding: {error}"))?;
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("could not synchronize the PNG capture: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("could not publish {}: {}", path.display(), error.error))?;
    Ok(())
}

fn utc_clock_text() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
        % 86_400;
    format!(
        "{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_arguments_accept_only_real_inputs() {
        let options = LaunchOptions::parse([
            std::ffi::OsString::from("--open"),
            std::ffi::OsString::from("fixture.exe"),
            std::ffi::OsString::from("--safe-mode"),
        ]);
        assert!(matches!(
            options.initial_input,
            Some(InitialInput::Binary(path)) if path == PathBuf::from("fixture.exe")
        ));
        assert!(options.safe_mode);
        assert!(options.argument_error.is_none());
    }

    #[test]
    fn startup_arguments_reject_multiple_inputs() {
        let options = LaunchOptions::parse([
            std::ffi::OsString::from("--open"),
            std::ffi::OsString::from("fixture.exe"),
            std::ffi::OsString::from("--package"),
            std::ffi::OsString::from("fixture.resym"),
        ]);
        assert!(options.argument_error.is_some());
    }

    #[test]
    fn startup_arguments_configure_reproducible_real_app_capture() {
        let options = LaunchOptions::parse([
            std::ffi::OsString::from("--open"),
            std::ffi::OsString::from("fixture.exe"),
            std::ffi::OsString::from("--theme"),
            std::ffi::OsString::from("ida"),
            std::ffi::OsString::from("--view"),
            std::ffi::OsString::from("relationships"),
            std::ffi::OsString::from("--capture"),
            std::ffi::OsString::from("docs/images/workbench-ida.png"),
        ]);
        assert_eq!(options.theme, Some(ThemePreset::IdaInspired));
        assert_eq!(options.active_tab, Some(WorkTab::Relationships));
        assert_eq!(
            options.capture_path,
            Some(PathBuf::from("docs/images/workbench-ida.png"))
        );
        assert!(options.argument_error.is_none());
    }

    #[test]
    fn capture_requires_real_input_and_png_output() {
        let without_input = LaunchOptions::parse([
            std::ffi::OsString::from("--capture"),
            std::ffi::OsString::from("capture.png"),
        ]);
        assert!(without_input.argument_error.is_some());

        let wrong_extension = LaunchOptions::parse([
            std::ffi::OsString::from("--open"),
            std::ffi::OsString::from("fixture.exe"),
            std::ffi::OsString::from("--capture"),
            std::ffi::OsString::from("capture.jpg"),
        ]);
        assert!(wrong_extension.argument_error.is_some());
    }

    #[test]
    fn reviewed_view_changes_live_without_mutating_the_project_snapshot() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/pe-x64-msvc/artifacts/milestone2-symbolized.exe");
        let project = resymbol_app::AppServices::default()
            .analyze_binary(&fixture)
            .expect("checked-in fixture should analyze");
        let original = project.projection().clone();
        let claim = original
            .functions
            .iter()
            .find_map(|function| selected_name_claim(&project, function).cloned())
            .expect("fixture should expose a reviewable selected name claim");
        let mut review = ReviewLedger::for_session(project.session())
            .expect("fixture should create a binary-bound ledger");

        review
            .reject(&claim, Some("test".to_owned()))
            .expect("exact source claim should be reviewable");
        let rejected = ReviewViewState::build(&project, &review)
            .expect("reviewed projection should remain valid");
        assert_ne!(rejected.projection.as_ref(), &original);
        assert_eq!(project.projection(), &original);

        review.undo();
        let restored = ReviewViewState::build(&project, &review)
            .expect("undo should rebuild the base projection");
        assert_eq!(restored.projection.as_ref(), &original);

        review.redo();
        let redone = ReviewViewState::build(&project, &review)
            .expect("redo should rebuild the rejected projection");
        assert_eq!(redone.projection, rejected.projection);
    }

    #[test]
    fn png_capture_publish_is_atomic_and_replaceable() {
        let directory = tempfile::tempdir().expect("temporary directory should be available");
        let path = directory.path().join("capture.png");
        let first = egui::ColorImage::filled([2, 1], Color32::from_rgb(17, 34, 51));
        save_color_image_png(&path, &first).expect("first PNG capture should publish");
        let first_bytes = fs::read(&path).expect("published PNG should be readable");
        assert_eq!(&first_bytes[..8], b"\x89PNG\r\n\x1a\n");

        let second = egui::ColorImage::filled([2, 1], Color32::from_rgb(68, 85, 102));
        save_color_image_png(&path, &second).expect("existing PNG should be atomically replaced");
        let second_bytes = fs::read(&path).expect("replacement PNG should be readable");
        assert_eq!(&second_bytes[..8], b"\x89PNG\r\n\x1a\n");
        assert_ne!(first_bytes, second_bytes);
    }

    #[test]
    fn package_drop_detection_is_case_insensitive() {
        assert!(is_package_path(Path::new("analysis.RESYM")));
        assert!(!is_package_path(Path::new("analysis.exe")));
    }

    #[test]
    fn review_sidecar_defaults_adjacent_to_origin() {
        assert_eq!(
            default_review_path(Path::new("fixtures/sample.exe")),
            PathBuf::from("fixtures/sample.exe.resymbol-workbench.json")
        );
    }
}
