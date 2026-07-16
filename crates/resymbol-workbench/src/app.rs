use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use eframe::egui::{self, Align, Key, Layout, RichText, ScrollArea, Sense, TextEdit};
use egui_extras::{Column, TableBuilder};
use resymbol_analysis::BinaryAnalysis;
use resymbol_core::{
    DiscoveredPlugin, PluginDiscoveryOptions, PluginDiscoveryReport, discover_plugins,
    plugin_api::PluginHealthState,
};
use resymbol_export::{ExportControlFlowTarget, ExportProducer, render_map, render_markdown};
use resymbol_package::write_file_new_bound;
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
        FunctionFilter, FunctionSort, FunctionSortKey, FunctionStatus, LoadedProject, SortDirection,
    },
    theme::{SemanticColors, ThemePreset},
};

const STORAGE_KEY: &str = "resymbol-workbench-preferences-v1";
const MAX_ACTIVITY_ENTRIES: usize = 512;
const MAX_ACTIVITY_MESSAGE_BYTES: usize = 512;

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
    Exports,
}

impl MainTab {
    const ALL: [Self; 6] = [
        Self::Overview,
        Self::Functions,
        Self::Types,
        Self::Relationships,
        Self::Graph,
        Self::Exports,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Functions => "Functions",
            Self::Types => "Types",
            Self::Relationships => "Relationships",
            Self::Graph => "Graph",
            Self::Exports => "Exports",
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
}

impl ExportKind {
    const ALL: [Self; 4] = [Self::Package, Self::NeutralJson, Self::Markdown, Self::Map];

    const fn label(self) -> &'static str {
        match self {
            Self::Package => "ReSymbol package",
            Self::NeutralJson => "Neutral JSON",
            Self::Markdown => "Markdown report",
            Self::Map => "Microsoft-style MAP",
        }
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::Package => "resym",
            Self::NeutralJson => "symbols.json",
            Self::Markdown => "symbols.md",
            Self::Map => "map",
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

/// Native ReSymbol evidence-review workbench.
pub struct WorkbenchApp {
    preferences: Preferences,
    stage: WorkflowStage,
    main_tab: MainTab,
    activity_tab: ActivityTab,
    started_at: Instant,
    project: Option<LoadedProject>,
    analysis_receiver: Option<Receiver<Result<LoadedProject, String>>>,
    analysis_path: Option<PathBuf>,
    function_filter: FunctionFilter,
    function_sort: FunctionSort,
    selected_projection_index: Option<usize>,
    graph_root_rva: Option<u64>,
    reconstruction_graph: Option<ReconstructionGraph>,
    activity: Vec<ActivityEntry>,
    console_host: ConsoleHost,
    plugin_report: Result<PluginDiscoveryReport, String>,
    export_kind: ExportKind,
    export_destination: String,
    export_result: Option<Result<String, String>>,
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
        creation_context
            .egui_ctx
            .style_mut(|style| style.animation_time = 0.0);
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
            analysis_receiver: None,
            analysis_path: None,
            function_filter: FunctionFilter::default(),
            function_sort: FunctionSort::default(),
            selected_projection_index: None,
            graph_root_rva: None,
            reconstruction_graph: None,
            activity: Vec::new(),
            console_host: ConsoleHost::new(),
            plugin_report,
            export_kind: ExportKind::Package,
            export_destination: String::new(),
            export_result: None,
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
            app.analysis_path = Some(path.clone());
            app.stage = WorkflowStage::Review;
            app.main_tab = match tab.as_str() {
                "overview" => MainTab::Overview,
                "functions" => MainTab::Functions,
                "graph" => MainTab::Graph,
                "exports" => {
                    app.stage = WorkflowStage::Export;
                    MainTab::Exports
                }
                _ => panic!("unsupported screenshot tab {tab:?}"),
            };
            app.project = Some(project);
            app.log(
                ActivityLevel::Success,
                format!("Loaded {} for visual regression capture", path.display()),
            );
            return app;
        }

        if let Some(path) = startup_path {
            app.start_analysis(path, creation_context.egui_ctx.clone());
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
                let continue_processing = !matches!(command, ConsoleCommand::Quit);
                self.apply_console_command(command, context);
                continue_processing
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
                let analysis = if self.analysis_receiver.is_some() {
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
            ConsoleCommand::Open(path) => {
                if self.analysis_receiver.is_some() {
                    self.console_reply(false, "an analysis is already running");
                } else {
                    self.console_reply(true, format!("queued {}", path.display()));
                    self.start_analysis(path, context.clone());
                }
            }
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
                };
                let Some(project) = self.project.as_ref() else {
                    self.console_reply(false, "open a binary before exporting");
                    return;
                };
                self.export_kind = kind;
                self.export_destination = path.to_string_lossy().into_owned();
                self.stage = WorkflowStage::Export;
                self.main_tab = MainTab::Exports;
                let result = write_export(project, kind, &path);
                match &result {
                    Ok(message) => {
                        self.console_reply(true, message);
                        self.log(ActivityLevel::Success, message.clone());
                    }
                    Err(error) => {
                        self.console_reply(false, error);
                        self.log(ActivityLevel::Error, format!("Export failed: {error}"));
                    }
                }
                self.export_result = Some(result);
            }
            ConsoleCommand::Quit => {
                self.console_reply(true, "closing workbench");
                context.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn console_reply(&self, success: bool, message: impl AsRef<str>) {
        let _ = self
            .console_host
            .try_send_line(format_command_result(success, message.as_ref()));
    }

    fn start_analysis(&mut self, path: PathBuf, context: egui::Context) {
        if self.analysis_receiver.is_some() {
            self.log(ActivityLevel::Warning, "An analysis is already running");
            return;
        }

        self.project = None;
        self.selected_projection_index = None;
        self.graph_root_rva = None;
        self.reconstruction_graph = None;
        self.function_filter = FunctionFilter::default();
        self.stage = WorkflowStage::Analyze;
        self.main_tab = MainTab::Overview;
        self.export_result = None;
        self.export_destination.clear();
        self.analysis_path = Some(path.clone());
        self.log(
            ActivityLevel::Info,
            format!("Queued core analysis for {}", path.display()),
        );

        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = LoadedProject::from_path(&path).map_err(|error| error.to_string());
            let _ = sender.send(result);
            context.request_repaint();
        });
        self.analysis_receiver = Some(receiver);
    }

    fn poll_analysis(&mut self) {
        let result = match self.analysis_receiver.as_ref().map(Receiver::try_recv) {
            Some(Ok(result)) => Some(result),
            Some(Err(TryRecvError::Disconnected)) => Some(Err(
                "analysis worker stopped without returning a result".to_owned(),
            )),
            Some(Err(TryRecvError::Empty)) | None => None,
        };
        let Some(result) = result else {
            return;
        };
        self.analysis_receiver = None;

        match result {
            Ok(project) => {
                let function_count = project.functions.len();
                let warning_count = project.projection.warnings.len();
                self.export_destination = default_export_path(&project, self.export_kind)
                    .to_string_lossy()
                    .into_owned();
                self.analysis_path = Some(project.identity.path.clone());
                self.selected_projection_index =
                    project.functions.first().map(|row| row.projection_index);
                let reconstruction_graph = ReconstructionGraph::from_project(&project);
                self.graph_root_rva = reconstruction_graph.default_root().map(|root| root.rva);
                self.reconstruction_graph = Some(reconstruction_graph);
                self.project = Some(project);
                self.stage = WorkflowStage::Review;
                self.main_tab = MainTab::Overview;
                self.log(
                    ActivityLevel::Success,
                    format!(
                        "Analysis complete: {function_count} functions, {warning_count} projection warnings"
                    ),
                );
            }
            Err(error) => {
                self.stage = WorkflowStage::Open;
                self.log(ActivityLevel::Error, format!("Analysis failed: {error}"));
            }
        }
    }

    fn choose_binary(&mut self, context: &egui::Context) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Open a PE32+ x86-64 binary")
            .add_filter("Windows binaries", &["exe", "dll", "sys"])
            .pick_file()
        else {
            return;
        };
        self.start_analysis(path, context.clone());
    }

    fn handle_inputs(&mut self, context: &egui::Context) {
        let open_shortcut =
            context.input(|input| input.modifiers.command && input.key_pressed(Key::O));
        if open_shortcut {
            self.choose_binary(context);
        }

        let dropped = context.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .find_map(|file| file.path.clone())
        });
        if let Some(path) = dropped {
            self.start_analysis(path, context.clone());
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
                        let primary_label = if self.analysis_receiver.is_some() {
                            "Analyzing..."
                        } else if self.project.is_some() {
                            "Export Symbols"
                        } else {
                            "Open Binary"
                        };
                        if ui
                            .add_enabled(
                                self.analysis_receiver.is_none(),
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
                            WorkflowStage::Analyze => self.analysis_receiver.is_some(),
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
                        let (cue, text, color) = if self.analysis_receiver.is_some() {
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
                        ui.label(format!("Schema {}", project.package.schema_version()));
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
                } else {
                    ui.label(RichText::new("Open a binary to create a project").weak());
                }

                ui.separator();
                ui.collapsing("Plugins (read-only safe mode)", |ui| {
                    self.show_plugin_list(ui);
                });
                ui.separator();
                ui.label(RichText::new("Project settings").weak());
                ui.small("Durable review decisions are not implemented in this slice.");
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
                                ui.collapsing(format!("{:?}: {}", claim.kind, claim.value), |ui| {
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
                        ui.label(
                            RichText::new("Read-only evidence mode").color(colors.secondary_text),
                        );
                        ui.small(
                            "Durable Accept / Alias / Reject history is the next review slice.",
                        );
                    });
            });
        };
        if cfg!(feature = "screenshot") {
            panel.show(context, contents);
        } else {
            panel.show_animated(context, is_open, contents);
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
        let (fraction, label, color) = if self.analysis_receiver.is_some() {
            (0.55, "Core analyzer running", colors.inferred)
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
            for (label, complete) in [
                ("Identity", self.project.is_some()),
                ("Base analysis", self.project.is_some()),
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
            ui.label("No projection warnings until analysis completes");
            return;
        };
        if project.projection.warnings.is_empty() {
            ui.label("[OK] No neutral-projection losses");
            return;
        }
        ScrollArea::vertical().show(ui, |ui| {
            for warning in &project.projection.warnings {
                ui.label(format!(
                    "[WARN] {:?} x{} - {}",
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
                ui.horizontal(|ui| {
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

                match self.main_tab {
                    MainTab::Overview => self.show_overview(ui),
                    MainTab::Functions => self.show_functions(ui),
                    MainTab::Types => self.show_types(ui),
                    MainTab::Relationships => self.show_relationships(ui),
                    MainTab::Graph => self.show_graph(ui),
                    MainTab::Exports => self.show_exports(ui),
                }
            });
    }

    fn show_empty_state(&mut self, ui: &mut egui::Ui, context: &egui::Context) {
        ui.with_layout(Layout::top_down_justified(Align::Center), |ui| {
            ui.add_space(70.0);
            ui.heading(if self.analysis_receiver.is_some() {
                "Analyzing exact binary bytes"
            } else {
                "Open a binary to begin"
            });
            ui.label("ReSymbol currently accepts native Windows PE32+ x86-64 binaries.");
            ui.label("The workbench keeps identity, status, confidence, and provenance visible independently.");
            ui.add_space(18.0);
            if ui
                .add_enabled(
                    self.analysis_receiver.is_none(),
                    egui::Button::new(if self.analysis_receiver.is_some() {
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
            ui.small("You can also drag an .exe, .dll, or .sys file onto this window.");
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
                RichText::new(project.identity.path.display().to_string())
                    .monospace()
                    .small()
                    .color(colors.secondary_text),
            );
            ui.add_space(12.0);

            ui.columns(5, |columns| {
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
                summary_card(
                    &mut columns[3],
                    "Relationships",
                    project.projection.direct_calls.len()
                        + project.projection.thunks.len()
                        + project.projection.data_references.len(),
                    colors.healthy,
                    colors,
                );
                summary_card(
                    &mut columns[4],
                    "Warnings",
                    project.projection.warnings.len(),
                    colors.warning_conflict,
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
                    ui.label(
                        RichText::new("[EXACT] Source bytes verified and analyzed")
                            .color(colors.exact_extracted),
                    );
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

    fn show_exports(&mut self, ui: &mut egui::Ui) {
        let Some(project) = &self.project else {
            return;
        };
        let colors = self.preferences.theme.semantic_colors();
        let mut export_activity = None;
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
            let write = ui.add_sized(
                [ui.available_width(), 38.0],
                egui::Button::new(
                    RichText::new(format!("Create {} artifact", self.export_kind.label()))
                        .strong(),
                )
                .fill(colors.selection)
                .stroke(egui::Stroke::new(1.0, colors.exact_extracted))
                .corner_radius(4),
            );
            if write.clicked() {
                let result = write_export(
                    project,
                    self.export_kind,
                    Path::new(&self.export_destination),
                );
                self.export_result = Some(result.clone());
                match &result {
                    Ok(message) => {
                        export_activity = Some((ActivityLevel::Success, message.clone()));
                    }
                    Err(error) => {
                        export_activity = Some((
                            ActivityLevel::Error,
                            format!("Export failed: {error}"),
                        ));
                    }
                }
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
            ui.small("PDB, IDAPython, and Ghidra Java remain available from the CLI while their workbench identity and capability panels are completed.");
        });
        if let Some((level, message)) = export_activity {
            self.log(level, message);
        }
    }
}

impl eframe::App for WorkbenchApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.preferences.theme.apply(context);
        self.poll_console(context);
        self.poll_analysis();
        self.handle_inputs(context);
        self.show_header(context);
        self.show_project_panel(context);
        self.show_inspector(context);
        self.show_activity_panel(context);
        self.show_central(context);

        if cfg!(feature = "screenshot") {
            context.request_repaint();
        } else if self.analysis_receiver.is_some() || self.console_host.is_enabled() {
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

fn short_hash(value: &str) -> String {
    if value.len() <= 24 {
        value.to_owned()
    } else {
        format!("{}...{}", &value[..12], &value[value.len() - 8..])
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
        ExportKind::Package => "Canonical loss-aware analysis package",
        ExportKind::NeutralJson => "Debugger-neutral structured symbol projection",
        ExportKind::Markdown => "Bounded human-review report",
        ExportKind::Map => "Microsoft-linker-style public symbol map",
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

fn default_export_path(project: &LoadedProject, kind: ExportKind) -> PathBuf {
    let mut path = project.identity.path.clone();
    path.set_extension(kind.extension());
    path
}

fn write_export(project: &LoadedProject, kind: ExportKind, path: &Path) -> Result<String, String> {
    if path.as_os_str().is_empty() {
        return Err("choose a destination path".to_owned());
    }

    match kind {
        ExportKind::Package => {
            write_file_new_bound(path, &project.package).map_err(|error| error.to_string())?
        }
        ExportKind::NeutralJson => {
            let bytes = serde_json::to_vec_pretty(&project.projection)
                .map_err(|error| format!("cannot render neutral JSON: {error}"))?;
            write_new_bytes(path, &bytes)?;
        }
        ExportKind::Markdown => {
            let text = render_markdown(&project.projection).map_err(|error| error.to_string())?;
            write_new_bytes(path, text.as_bytes())?;
        }
        ExportKind::Map => {
            let module_name = project
                .identity
                .path
                .file_stem()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .unwrap_or("resymbol");
            let text = render_map(project.session(), &project.projection, module_name)
                .map_err(|error| error.to_string())?;
            write_new_bytes(path, text.as_bytes())?;
        }
    }

    Ok(format!("Wrote {} to {}", kind.label(), path.display()))
}

fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot flush {}: {error}", path.display()))
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
