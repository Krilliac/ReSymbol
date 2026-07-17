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
use resymbol_analysis::{
    BinaryAnalysis, LinearDisassemblyLimits, LinearDisassemblyPreview, LinearInstructionRow,
    disassemble_x64_linear,
};
use resymbol_app::{
    DecisionAction, ExportFormat, MAX_REVIEW_ANNOTATION_BYTES, MAX_REVIEWER_BYTES,
    PluginArtifactPolicyStatus, PluginCatalog, PluginCatalogEntry, PublishedStaticPatch,
    ReviewSubject, STATIC_PATCH_SET_SUFFIX, StaticPatchEditRequest,
};
use resymbol_core::BinaryIdentity;
use resymbol_debugger::{
    IsolationBoundary, MemoryAccess, ProtectionSeverity, RelativeAddress, SandboxGuarantee,
    SandboxProviderReadiness, SandboxProviderReadinessReason, SandboxProviderRequirement,
    SandboxProviderSelection, StaticImageLayout, StaticRegionKind,
};
use resymbol_export::{ExportBinaryFormat, ExportControlFlowTarget, ExportProducer};
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
    instruction_actions::{
        ConditionalBranchPatch, InstructionSelectionMove, LiveDebuggerActionContext,
        LiveDebuggerProtocolRoute, LiveInstructionAction, MAX_PENDING_STATIC_PATCH_DRAFTS,
        PatchDraftQueueOutcome, PendingStaticPatchDrafts, StaticPatchDraftKind,
        navigate_instruction_selection,
    },
    model::{
        FunctionFilter, FunctionRow, FunctionSort, FunctionSortKey, FunctionStatus, LoadedProject,
        ProtectionAssessment, SortDirection,
    },
    readiness::{
        DebuggerReadinessEvidence, DebuggerReadinessOutcome, ReadinessProtectionStatus,
        SandboxProviderChoice,
    },
    review_state::BoundReviewLedger,
    theme::{SemanticColors, ThemePreset},
    ui_policy::{
        CycleDirection, DEFAULT_INSPECTOR_PANEL_WIDTH, DEFAULT_PROJECT_PANEL_WIDTH,
        MainTabPresentation, RowNavigation, cycle_index, function_table_layout,
        main_tab_presentation, navigate_visible_selection, shell_chrome_layout,
    },
    worker::{
        MAX_OFFLINE_IMAGE_UI_READ_BYTES, OfflineImageReadAvailability, OfflineImageReadFailure,
        OfflineImageReadOutcome, OfflineImageReadSpan, OperationGate, OperationId,
        OperationSequence, PatchSetOutcome, PublicationDestination, PublicationGate,
        PublicationKind, ReviewSaveOutcome, ServiceWorker, WorkerCommand, WorkerEvent,
        WorkerExportKind,
    },
};

const STORAGE_KEY: &str = "resymbol-workbench-preferences-v1";
const MAX_ACTIVITY_ENTRIES: usize = 512;
const MAX_ACTIVITY_MESSAGE_BYTES: usize = 512;
const MAX_RECENT_BINARIES: usize = 8;
const OFFLINE_READ_SIZES: [u32; 5] = [16, 32, 64, 128, MAX_OFFLINE_IMAGE_UI_READ_BYTES];
const OFFLINE_HEX_ROW_BYTES: usize = 16;
const OFFLINE_DISASSEMBLY_INSTRUCTION_LIMIT: usize = 64;
const FUNCTION_KEYBOARD_PAGE_ROWS: usize = 10;
#[cfg(any(test, feature = "screenshot"))]
const SCREENSHOT_CANONICAL_JCC_RVA: u64 = 0x0000_116E;
#[cfg(any(test, feature = "screenshot"))]
const SCREENSHOT_CANONICAL_JCC_READ_BYTES: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryPickerPurpose {
    OpenBinaryOrPackage,
    VerifyExactBinary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BinaryPickerFilterSpec {
    label: &'static str,
    extensions: &'static [&'static str],
}

const PE_CONTAINER_FILTER: BinaryPickerFilterSpec = BinaryPickerFilterSpec {
    label: "PE containers",
    extensions: &["exe", "dll", "sys", "cpl", "ocx", "scr", "efi"],
};
const ELF_CONTAINER_FILTER: BinaryPickerFilterSpec = BinaryPickerFilterSpec {
    label: "ELF containers",
    extensions: &["elf", "axf"],
};
const RESYMBOL_PACKAGE_FILTER: BinaryPickerFilterSpec = BinaryPickerFilterSpec {
    label: "ReSymbol packages",
    extensions: &["resym"],
};
const ALL_FILES_FILTER: BinaryPickerFilterSpec = BinaryPickerFilterSpec {
    label: "All files (including extensionless containers)",
    extensions: &["*"],
};
const OPEN_BINARY_OR_PACKAGE_FILTERS: &[BinaryPickerFilterSpec] = &[
    PE_CONTAINER_FILTER,
    ELF_CONTAINER_FILTER,
    RESYMBOL_PACKAGE_FILTER,
    ALL_FILES_FILTER,
];
const VERIFY_EXACT_BINARY_FILTERS: &[BinaryPickerFilterSpec] =
    &[PE_CONTAINER_FILTER, ELF_CONTAINER_FILTER, ALL_FILES_FILTER];

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

#[cfg(any(test, feature = "screenshot"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScreenshotScenario {
    OpenEmpty,
    Overview,
    Functions,
    FunctionsFocused,
    Graph,
    AddressSpace,
    Disassembly,
    DisassemblyActions,
    BinarySwitchConfirmation,
    DebuggerSandbox,
    DebuggerReadinessResult,
    Exports,
}

#[cfg(any(test, feature = "screenshot"))]
impl ScreenshotScenario {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "open-empty" => Some(Self::OpenEmpty),
            "overview" => Some(Self::Overview),
            "functions" => Some(Self::Functions),
            "functions-focused" => Some(Self::FunctionsFocused),
            "graph" => Some(Self::Graph),
            "address-space" | "memory-map" => Some(Self::AddressSpace),
            "disassembly" => Some(Self::Disassembly),
            "disassembly-actions" => Some(Self::DisassemblyActions),
            "binary-switch-confirmation" => Some(Self::BinarySwitchConfirmation),
            "debugger-sandbox" | "readiness" => Some(Self::DebuggerSandbox),
            "debugger-readiness-result" => Some(Self::DebuggerReadinessResult),
            "exports" => Some(Self::Exports),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::OpenEmpty => "open-empty",
            Self::Overview => "overview",
            Self::Functions => "functions",
            Self::FunctionsFocused => "functions-focused",
            Self::Graph => "graph",
            Self::AddressSpace => "address-space",
            Self::Disassembly => "disassembly",
            Self::DisassemblyActions => "disassembly-actions",
            Self::BinarySwitchConfirmation => "binary-switch-confirmation",
            Self::DebuggerSandbox => "debugger-sandbox",
            Self::DebuggerReadinessResult => "debugger-readiness-result",
            Self::Exports => "exports",
        }
    }

    const fn needs_offline_read(self) -> bool {
        matches!(self, Self::Disassembly | Self::DisassemblyActions)
    }

    const fn needs_readiness_result(self) -> bool {
        matches!(self, Self::DebuggerSandbox | Self::DebuggerReadinessResult)
    }
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

    const fn compact_label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Functions => "Functions",
            Self::Types => "Types",
            Self::Relationships => "Relations",
            Self::Graph => "Graph",
            Self::AddressSpace => "Address",
            Self::DebuggerSandbox => "Sandbox",
            Self::Exports => "Exports",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Functions => 1,
            Self::Types => 2,
            Self::Relationships => 3,
            Self::Graph => 4,
            Self::AddressSpace => 5,
            Self::DebuggerSandbox => 6,
            Self::Exports => 7,
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

    const fn requires_pe(self) -> bool {
        matches!(self, Self::Map | Self::Pdb)
    }

    fn unavailable_reason(self, format: &ExportBinaryFormat) -> Option<&'static str> {
        (self.requires_pe() && !matches!(format, ExportBinaryFormat::Pe))
            .then_some("Microsoft MAP and PDB exports are available only for PE/x86-64 projects.")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Preferences {
    theme: ThemePreset,
    left_panel_open: bool,
    right_panel_open: bool,
    bottom_panel_open: bool,
    recent_binaries: Vec<PathBuf>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: ThemePreset::Graphite,
            left_panel_open: true,
            right_panel_open: true,
            bottom_panel_open: true,
            recent_binaries: Vec::new(),
        }
    }
}

impl Preferences {
    fn normalize(&mut self) {
        normalize_recent_binaries(&mut self.recent_binaries);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinarySwitchDialogAction {
    SaveNew,
    DiscardAndOpen,
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
    Failure(OfflineImageReadFailure),
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
                let detail = bounded_message(offline_read_failure_text(&error));
                self.presentation = Some(OfflineReadPresentation::Failure(error));
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum OfflineByteView {
    #[default]
    Hex,
    Disassembly,
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
    publication_operation: PublicationGate,
    review_operation: OperationGate,
    plugin_operation: OperationGate,
    readiness_operation: OperationGate,
    patch_set_load_operation: OperationGate,
    worker_disconnected: bool,
    analysis_path: Option<PathBuf>,
    function_filter: FunctionFilter,
    function_sort: FunctionSort,
    function_search_focus_requested: bool,
    function_row_focus_target: Option<usize>,
    function_focused_row_id: Option<egui::Id>,
    selected_projection_index: Option<usize>,
    selected_review_subject: Option<ReviewSubject>,
    graph_root_rva: Option<u64>,
    reconstruction_graph: Option<ReconstructionGraph>,
    activity: Vec<ActivityEntry>,
    console_host: ConsoleHost,
    plugin_catalog: Option<Result<PluginCatalog, String>>,
    export_kind: ExportKind,
    export_destination: String,
    export_result: Option<Result<String, String>>,
    #[cfg(feature = "screenshot")]
    screenshot_scenario: Option<ScreenshotScenario>,
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
    pending_binary_open: Option<PathBuf>,
    open_after_review_save: bool,
    readiness_choice: SandboxProviderChoice,
    readiness_outcome: Option<DebuggerReadinessOutcome>,
    readiness_error: Option<String>,
    offline_read: OfflineReadUiState,
    offline_read_rva_input: String,
    offline_read_size: u32,
    offline_byte_view: OfflineByteView,
    selected_disassembly_instruction: Option<usize>,
    disassembly_row_focus_target: Option<usize>,
    pending_static_patch_drafts: PendingStaticPatchDrafts,
    static_patch_result: Option<Result<PublishedStaticPatch, String>>,
    patch_set_result: Option<Result<String, String>>,
}

impl WorkbenchApp {
    pub fn new(creation_context: &eframe::CreationContext<'_>) -> Self {
        let startup_path = std::env::args_os().nth(1).map(PathBuf::from);
        Self::new_with_startup(creation_context, startup_path)
    }

    fn new_with_startup(
        creation_context: &eframe::CreationContext<'_>,
        startup_path: Option<PathBuf>,
    ) -> Self {
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
        #[cfg(feature = "screenshot")]
        let screenshot_scenario =
            std::env::var("RESYMBOL_WORKBENCH_SCREENSHOT_TAB")
                .ok()
                .map(|value| {
                    ScreenshotScenario::parse(&value)
                        .unwrap_or_else(|| panic!("unsupported screenshot scenario {value:?}"))
                });
        let mut preferences: Preferences = if cfg!(feature = "screenshot") {
            Preferences::default()
        } else {
            creation_context
                .storage
                .and_then(|storage| eframe::get_value(storage, STORAGE_KEY))
                .unwrap_or_default()
        };
        preferences.normalize();
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
            publication_operation: PublicationGate::default(),
            review_operation: OperationGate::default(),
            plugin_operation: OperationGate::default(),
            readiness_operation: OperationGate::default(),
            patch_set_load_operation: OperationGate::default(),
            worker_disconnected: false,
            analysis_path: None,
            function_filter: FunctionFilter::default(),
            function_sort: FunctionSort::default(),
            function_search_focus_requested: false,
            function_row_focus_target: None,
            function_focused_row_id: None,
            selected_projection_index: None,
            selected_review_subject: None,
            graph_root_rva: None,
            reconstruction_graph: None,
            activity: Vec::new(),
            console_host: ConsoleHost::new(),
            plugin_catalog: None,
            export_kind: ExportKind::Package,
            export_destination: String::new(),
            export_result: None,
            #[cfg(feature = "screenshot")]
            screenshot_scenario,
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
            pending_binary_open: None,
            open_after_review_save: false,
            readiness_choice: SandboxProviderChoice::default(),
            readiness_outcome: None,
            readiness_error: None,
            offline_read: OfflineReadUiState::default(),
            offline_read_rva_input: "0x00000000".to_owned(),
            offline_read_size: 64,
            offline_byte_view: OfflineByteView::default(),
            selected_disassembly_instruction: None,
            disassembly_row_focus_target: None,
            pending_static_patch_drafts: PendingStaticPatchDrafts::default(),
            static_patch_result: None,
            patch_set_result: None,
        };
        app.log(
            ActivityLevel::Info,
            "Workbench ready in core-only non-executing review mode",
        );

        #[cfg(feature = "screenshot")]
        if let Some(scenario) = app.screenshot_scenario {
            if scenario == ScreenshotScenario::OpenEmpty {
                app.log(
                    ActivityLevel::Info,
                    "Prepared empty Open Binary visual regression scenario",
                );
                app.begin_initial_plugin_catalog_refresh();
                return app;
            }
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
            if scenario == ScreenshotScenario::Graph {
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
            app.main_tab = match scenario {
                ScreenshotScenario::Overview | ScreenshotScenario::BinarySwitchConfirmation => {
                    MainTab::Overview
                }
                ScreenshotScenario::Functions | ScreenshotScenario::FunctionsFocused => {
                    MainTab::Functions
                }
                ScreenshotScenario::Graph => MainTab::Graph,
                ScreenshotScenario::AddressSpace
                | ScreenshotScenario::Disassembly
                | ScreenshotScenario::DisassemblyActions => MainTab::AddressSpace,
                ScreenshotScenario::DebuggerSandbox
                | ScreenshotScenario::DebuggerReadinessResult => MainTab::DebuggerSandbox,
                ScreenshotScenario::Exports => {
                    app.stage = WorkflowStage::Export;
                    MainTab::Exports
                }
                ScreenshotScenario::OpenEmpty => unreachable!("handled before project load"),
            };
            app.project = Some(project);
            if scenario.needs_offline_read() {
                let (start_rva, read_size) = if scenario == ScreenshotScenario::DisassemblyActions {
                    (
                        SCREENSHOT_CANONICAL_JCC_RVA,
                        SCREENSHOT_CANONICAL_JCC_READ_BYTES,
                    )
                } else {
                    let entry_rva = app
                        .project
                        .as_ref()
                        .and_then(|project| match project.session().base_analysis() {
                            BinaryAnalysis::Pe(analysis) => {
                                Some(u64::from(analysis.entry_point_rva))
                            }
                            _ => None,
                        })
                        .filter(|rva| *rva != 0)
                        .or_else(|| app.project.as_ref()?.functions.first().map(|row| row.rva))
                        .expect("screenshot fixture needs a disassembly seed");
                    (entry_rva, 128)
                };
                app.offline_read_rva_input = format!("0x{start_rva:08X}");
                app.offline_read_size = read_size;
                app.offline_byte_view = OfflineByteView::Disassembly;
                app.selected_disassembly_instruction = Some(0);
                app.queue_offline_image_read()
                    .unwrap_or_else(|error| panic!("cannot queue disassembly capture: {error}"));
            }
            if scenario == ScreenshotScenario::FunctionsFocused {
                app.function_row_focus_target = app.selected_projection_index;
            }
            if scenario.needs_readiness_result() {
                app.queue_sandbox_readiness_probe()
                    .unwrap_or_else(|error| panic!("cannot queue readiness capture: {error}"));
            }
            if scenario == ScreenshotScenario::BinarySwitchConfirmation {
                app.prepare_screenshot_binary_switch_confirmation();
            }
            app.log(
                ActivityLevel::Success,
                format!(
                    "Loaded {} for {} visual regression capture",
                    path.display(),
                    scenario.name()
                ),
            );
            app.begin_initial_plugin_catalog_refresh();
            return app;
        }

        if let Some(path) = startup_path {
            if let Err(error) = app.start_analysis(path) {
                app.log(ActivityLevel::Error, error);
            }
        }
        app.begin_initial_plugin_catalog_refresh();
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

    fn remember_recent_binary(&mut self, path: PathBuf) {
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        push_recent_binary(&mut self.preferences.recent_binaries, path);
    }

    #[cfg(feature = "screenshot")]
    fn prepare_screenshot_binary_switch_confirmation(&mut self) {
        let subject = self
            .project
            .as_ref()
            .and_then(|project| {
                project.functions.iter().find_map(|row| {
                    project
                        .function_detail(row.projection_index)
                        .and_then(|detail| {
                            detail
                                .claims
                                .iter()
                                .find_map(|claim| claim.review_subject().cloned())
                        })
                })
            })
            .expect("screenshot fixture needs a reviewable exact name claim");
        self.review
            .as_mut()
            .expect("screenshot project has a bound review ledger")
            .apply_disposition(
                &subject,
                DecisionAction::Reject,
                "visual-regression",
                "Deterministic unsaved decision for binary-switch confirmation",
            )
            .expect("screenshot fixture accepts a deterministic review decision");
        self.pending_binary_open = Some(PathBuf::from(
            r"C:\visual-regression\replacement-candidate.exe",
        ));
        self.open_after_review_save = false;
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

        let scenario_work_is_pending = self.screenshot_scenario.is_some_and(|scenario| {
            (scenario.needs_readiness_result() && self.readiness_operation.is_pending())
                || (scenario.needs_offline_read() && self.offline_read.is_pending())
        });
        if scenario_work_is_pending {
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
        if self.patch_set_load_operation.is_pending() {
            self.log(
                ActivityLevel::Warning,
                "Close paused until the worker-owned patch-set load finishes",
            );
            return false;
        }
        if self.publication_operation.is_pending() {
            let kind = self
                .publication_operation
                .kind()
                .map_or("file", PublicationKind::label);
            self.log(
                ActivityLevel::Warning,
                format!("Close paused until the worker-owned {kind} publication finishes"),
            );
            return false;
        }
        // A close request supersedes an in-progress project-switch prompt. Keeping both
        // continuations alive could otherwise let one review save trigger two actions.
        self.pending_binary_open = None;
        self.open_after_review_save = false;
        let review_is_dirty = self
            .review
            .as_ref()
            .is_some_and(BoundReviewLedger::is_dirty);
        #[cfg(feature = "screenshot")]
        let screenshot_capture_completed =
            self.screenshot_requested && self.screenshot_destination.is_none();
        #[cfg(not(feature = "screenshot"))]
        let screenshot_capture_completed = false;
        // A deterministic capture closes only after its create-new PNG has been written. Do not
        // re-open the dirty-review prompt while terminating that disposable automation process;
        // the real modal and dirty ledger were still present in the captured frame.
        let close_is_authorized = self.allow_dirty_close || screenshot_capture_completed;
        if close_requires_confirmation(review_is_dirty, close_is_authorized) {
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
            || self.publication_operation.is_pending()
            || self.patch_set_load_operation.is_pending();
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
                    if ui
                        .add_enabled(
                            !self.publication_operation.is_pending()
                                && !self.patch_set_load_operation.is_pending(),
                            egui::Button::new("Discard and Close"),
                        )
                        .clicked()
                    {
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

    fn show_binary_switch_confirmation(&mut self, context: &egui::Context) {
        let Some(target_path) = self.pending_binary_open.clone() else {
            return;
        };
        let review_is_dirty = self
            .review
            .as_ref()
            .is_some_and(BoundReviewLedger::is_dirty);
        if !review_is_dirty {
            if self.review_operation.is_pending() {
                return;
            }
            self.pending_binary_open = None;
            self.open_after_review_save = false;
            if let Err(error) = self.start_analysis(target_path) {
                self.log(ActivityLevel::Error, error);
            }
            return;
        }

        let replacement_busy = self.project_operation.is_pending()
            || self.review_operation.is_pending()
            || self.publication_operation.is_pending()
            || self.patch_set_load_operation.is_pending()
            || self.readiness_operation.is_pending()
            || self.offline_read.is_pending();
        let response = egui::Modal::new(egui::Id::new("dirty_review_binary_switch_confirmation"))
            .show(context, |ui| {
                ui.set_min_width(470.0);
                ui.heading("Open a different binary?");
                ui.label(
                    "The current binary has unsaved review decisions. Replacing it requires an explicit save or discard.",
                );
                ui.add_space(6.0);
                ui.label(RichText::new("Next binary").strong());
                ui.label(
                    RichText::new(target_path.display().to_string())
                        .monospace()
                        .small()
                        .color(self.preferences.theme.semantic_colors().secondary_text),
                );
                ui.small(
                    "If the new binary fails to open, the current project and its review decisions remain active.",
                );
                if self.open_after_review_save && self.review_operation.is_pending() {
                    ui.separator();
                    ui.label("Saving the exact current ledger snapshot before switching...");
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
                        .add_enabled(!replacement_busy, egui::Button::new("Save Review New..."))
                        .on_hover_text(
                            "Create a new binary-bound review sidecar, then open the selected binary only after that exact snapshot is durable",
                        )
                        .clicked()
                    {
                        action = Some(BinarySwitchDialogAction::SaveNew);
                    }
                    if ui
                        .add_enabled(
                            !replacement_busy,
                            egui::Button::new("Discard Review and Open"),
                        )
                        .clicked()
                    {
                        action = Some(BinarySwitchDialogAction::DiscardAndOpen);
                    }
                    if ui.button("Cancel").clicked() {
                        action = Some(BinarySwitchDialogAction::Cancel);
                    }
                });
                action
            });
        let should_cancel = response.should_close();
        let action = response
            .inner
            .or_else(|| should_cancel.then_some(BinarySwitchDialogAction::Cancel));

        match action {
            Some(BinarySwitchDialogAction::SaveNew) => {
                if let Some(path) = self.choose_new_review_sidecar(
                    "Save review decisions to a new sidecar before switching binaries",
                ) {
                    match self.queue_review_save(path) {
                        Ok(_) => {
                            self.close_after_review_save = false;
                            self.open_after_review_save = true;
                        }
                        Err(error) => {
                            self.open_after_review_save = false;
                            self.review_result = Some(Err(error.clone()));
                            self.log(
                                ActivityLevel::Error,
                                format!("Review save before binary switch failed: {error}"),
                            );
                        }
                    }
                }
            }
            Some(BinarySwitchDialogAction::DiscardAndOpen) => {
                self.pending_binary_open = None;
                self.open_after_review_save = false;
                if let Err(error) = self.start_analysis_with_policy(target_path, true) {
                    self.log(ActivityLevel::Error, error);
                }
            }
            Some(BinarySwitchDialogAction::Cancel) => {
                self.pending_binary_open = None;
                self.open_after_review_save = false;
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

    fn request_binary_open(&mut self, path: PathBuf) {
        if self.project_operation.is_pending() {
            self.log(
                ActivityLevel::Warning,
                "Wait for the current project operation before opening another binary",
            );
            return;
        }
        if self.publication_operation.is_pending()
            || self.patch_set_load_operation.is_pending()
            || self.review_operation.is_pending()
        {
            self.log(
                ActivityLevel::Warning,
                "Wait for the current file publication or review operation before opening another binary",
            );
            return;
        }
        if self.offline_read.is_pending() {
            self.log(
                ActivityLevel::Warning,
                "Wait for the exact offline byte read before opening another binary",
            );
            return;
        }
        if self.readiness_operation.is_pending() {
            self.log(
                ActivityLevel::Warning,
                "Wait for the debugger sandbox readiness probe before opening another binary",
            );
            return;
        }
        if self
            .review
            .as_ref()
            .is_some_and(BoundReviewLedger::is_dirty)
        {
            self.close_after_review_save = false;
            self.open_after_review_save = false;
            self.pending_binary_open = Some(path.clone());
            self.log(
                ActivityLevel::Warning,
                format!(
                    "Binary switch paused for unsaved review decisions: {}",
                    path.display()
                ),
            );
            return;
        }
        if let Err(error) = self.start_analysis(path) {
            self.log(ActivityLevel::Error, error);
        }
    }

    fn start_analysis(&mut self, path: PathBuf) -> Result<String, String> {
        self.start_analysis_with_policy(path, false)
    }

    fn start_analysis_with_policy(
        &mut self,
        path: PathBuf,
        allow_dirty_review_replacement: bool,
    ) -> Result<String, String> {
        if self.project_operation.is_pending() {
            return Err("a project operation is already running".to_owned());
        }
        if self.publication_operation.is_pending()
            || self.patch_set_load_operation.is_pending()
            || self.review_operation.is_pending()
        {
            return Err(
                "wait for the current file publication or review operation first".to_owned(),
            );
        }
        if self.offline_read.is_pending() {
            return Err(
                "wait for the exact offline byte read before replacing the project".to_owned(),
            );
        }
        if self.readiness_operation.is_pending() {
            return Err(
                "wait for the debugger sandbox readiness probe before replacing the project"
                    .to_owned(),
            );
        }
        if self
            .review
            .as_ref()
            .is_some_and(BoundReviewLedger::is_dirty)
            && !allow_dirty_review_replacement
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
        self.pending_binary_open = None;
        self.open_after_review_save = false;
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

    fn queue_plugin_catalog_refresh(&mut self) -> Result<String, String> {
        if self.plugin_operation.is_pending() {
            return Err("a plugin catalog refresh is already running".to_owned());
        }
        if self.worker_disconnected {
            return Err("the application-service worker is unavailable".to_owned());
        }
        let operation = self.operation_sequence.issue();
        self.service_worker
            .submit(WorkerCommand::RefreshPluginCatalog {
                operation,
                root: PathBuf::from("plugins"),
            })?;
        self.plugin_operation.begin(operation);
        let message =
            "Queued read-only plugin policy refresh; no plugin will be executed".to_owned();
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn begin_initial_plugin_catalog_refresh(&mut self) {
        if let Err(error) = self.queue_plugin_catalog_refresh() {
            self.plugin_catalog = Some(Err(error.clone()));
            self.log(
                ActivityLevel::Error,
                format!("Plugin catalog refresh failed: {error}"),
            );
        }
    }

    fn accept_plugin_catalog(
        &mut self,
        operation: OperationId,
        result: Result<PluginCatalog, String>,
    ) -> bool {
        if !self.plugin_operation.finish(operation) {
            return false;
        }
        self.plugin_catalog = Some(result);
        true
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
        self.selected_disassembly_instruction = None;
        self.disassembly_row_focus_target = None;
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
        if self.project_operation.is_pending() {
            return Err("wait for the current project operation before exporting".to_owned());
        }
        if self.review_operation.is_pending() {
            return Err("wait for the current review save or load before exporting".to_owned());
        }
        if self.patch_set_load_operation.is_pending() {
            return Err("wait for the current patch-set load before exporting".to_owned());
        }
        let (project, reviews) = {
            let project = self
                .project
                .as_ref()
                .ok_or_else(|| "open a binary or package before exporting".to_owned())?;
            if let Some(reason) = kind.unavailable_reason(&project.identity.format) {
                return Err(reason.to_owned());
            }
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
            (Arc::clone(&project.snapshot), reviews)
        };
        let destination =
            PublicationDestination::resolve(&path).map_err(|error| error.to_string())?;

        let operation = self.operation_sequence.issue();
        self.publication_operation
            .begin(operation, PublicationKind::Export, destination)
            .map_err(|error| error.to_string())?;
        let submit = self.service_worker.submit(WorkerCommand::Export {
            operation,
            project,
            reviews,
            kind: kind.worker_kind(),
            path: path.clone(),
        });
        if let Err(error) = submit {
            let finished = self
                .publication_operation
                .finish(operation, PublicationKind::Export);
            debug_assert!(
                finished,
                "failed export submission releases its reservation"
            );
            return Err(error);
        }
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
        if self.publication_operation.is_pending() {
            return Err("wait for the current file publication first".to_owned());
        }
        if self.patch_set_load_operation.is_pending() {
            return Err("a patch-set load is already running".to_owned());
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
        if self.patch_set_load_operation.is_pending() {
            return Err("wait for the current patch-set load before saving reviews".to_owned());
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
        if self.publication_operation.is_pending() {
            return Err("wait for the current file publication before loading reviews".to_owned());
        }
        if self.patch_set_load_operation.is_pending() {
            return Err("wait for the current patch-set load before loading reviews".to_owned());
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
        if self.publication_operation.is_pending() {
            return Err("wait for the current file publication before changing reviews".to_owned());
        }
        if self.patch_set_load_operation.is_pending() {
            return Err("wait for the current patch-set load before changing reviews".to_owned());
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
                    self.handle_worker_disconnect(error);
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
                    self.finish_project_open(result);
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
                    if !self
                        .publication_operation
                        .finish(operation, PublicationKind::Export)
                    {
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
                        Ok(outcome) => self.finish_review_save(context, outcome),
                        Err(error) => {
                            let was_closing_after_save = self.close_after_review_save;
                            self.close_after_review_save = false;
                            self.open_after_review_save = false;
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
                WorkerEvent::PluginCatalogRefreshed { operation, result } => {
                    let message = match &result {
                        Ok(catalog) => format!(
                            "Plugin policy catalog refreshed: {} candidate(s), {} pass exact-artifact policy; execution is not implied",
                            catalog.entries().len(),
                            catalog.artifact_policy_allowed_count()
                        ),
                        Err(error) => format!("Plugin policy catalog refresh failed: {error}"),
                    };
                    let success = result.is_ok();
                    if !self.accept_plugin_catalog(operation, result) {
                        self.log(
                            ActivityLevel::Warning,
                            format!(
                                "Ignored stale plugin catalog result for operation {}",
                                operation.get()
                            ),
                        );
                        continue;
                    }
                    self.log(
                        if success {
                            ActivityLevel::Success
                        } else {
                            ActivityLevel::Error
                        },
                        message,
                    );
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
                        OfflineReadEventDisposition::Available { byte_count } => {
                            #[cfg(feature = "screenshot")]
                            if self
                                .screenshot_scenario
                                .is_some_and(ScreenshotScenario::needs_offline_read)
                            {
                                self.offline_byte_view = OfflineByteView::Disassembly;
                                self.selected_disassembly_instruction = Some(0);
                                self.disassembly_row_focus_target = Some(0);
                            }
                            self.log(
                                ActivityLevel::Success,
                                format!(
                                    "Read {byte_count} exact frozen source byte(s) through the offline host"
                                ),
                            );
                        }
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
                WorkerEvent::StaticPatchPublished { operation, result } => {
                    self.finish_static_patch_publication(operation, result);
                }
                WorkerEvent::StaticPatchSetSaved { operation, result } => {
                    self.finish_static_patch_set_save(operation, result);
                }
                WorkerEvent::StaticPatchSetLoaded { operation, result } => {
                    self.finish_static_patch_set_load(operation, result);
                }
            }
        }
    }

    fn finish_static_patch_publication(
        &mut self,
        operation: OperationId,
        result: Result<PublishedStaticPatch, String>,
    ) {
        if !self
            .publication_operation
            .finish(operation, PublicationKind::StaticPatch)
        {
            self.log(
                ActivityLevel::Warning,
                format!(
                    "Ignored stale static patch result for operation {}",
                    operation.get()
                ),
            );
            return;
        }
        match result {
            Ok(outcome) => {
                let matches_current = self.project.as_ref().is_some_and(|project| {
                    project.session().base_analysis().identity() == outcome.source_identity()
                });
                if !matches_current {
                    let error = "Static patch receipt did not match the current project identity"
                        .to_owned();
                    self.static_patch_result = Some(Err(error.clone()));
                    self.console_reply(false, &error);
                    self.log(ActivityLevel::Error, error);
                    return;
                }
                let warning_count = outcome.warnings().len();
                let durability = outcome.durability().to_string();
                let durability_warning = !outcome.durability().is_fully_synchronized();
                let message = format!(
                    "Created and reopened-verified patched binary {} with SHA-256 {}, {warning_count} integrity warning(s), and durability status: {durability}",
                    outcome.path().display(),
                    outcome.output_identity().id.as_str()
                );
                self.pending_static_patch_drafts.clear();
                self.static_patch_result = Some(Ok(outcome));
                self.patch_set_result = None;
                self.console_reply(true, &message);
                self.log(ActivityLevel::Success, &message);
                if durability_warning {
                    self.log(
                        ActivityLevel::Warning,
                        format!("Patched binary durability warning: {durability}"),
                    );
                }
            }
            Err(error) => {
                self.static_patch_result = Some(Err(error.clone()));
                self.console_reply(false, &error);
                self.log(
                    ActivityLevel::Error,
                    format!("Static patch publication failed: {error}"),
                );
            }
        }
    }

    fn finish_static_patch_set_save(
        &mut self,
        operation: OperationId,
        result: Result<PatchSetOutcome, String>,
    ) {
        if !self
            .publication_operation
            .finish(operation, PublicationKind::PatchSet)
        {
            self.log(
                ActivityLevel::Warning,
                format!(
                    "Ignored stale patch-set save result for operation {}",
                    operation.get()
                ),
            );
            return;
        }
        match result {
            Ok(outcome) => {
                if !self.patch_set_matches_current_project(&outcome) {
                    let error = "Patch-set save receipt did not match the current project identity"
                        .to_owned();
                    self.patch_set_result = Some(Err(error.clone()));
                    self.console_reply(false, &error);
                    self.log(ActivityLevel::Error, error);
                    return;
                }
                let message = patch_set_outcome_message("Saved", &outcome);
                self.patch_set_result = Some(Ok(message.clone()));
                self.console_reply(true, &message);
                self.log(ActivityLevel::Success, message);
            }
            Err(error) => {
                self.patch_set_result = Some(Err(error.clone()));
                self.console_reply(false, &error);
                self.log(
                    ActivityLevel::Error,
                    format!("Patch-set save failed: {error}"),
                );
            }
        }
    }

    fn finish_static_patch_set_load(
        &mut self,
        operation: OperationId,
        result: Result<PatchSetOutcome, String>,
    ) {
        if !self.patch_set_load_operation.finish(operation) {
            self.log(
                ActivityLevel::Warning,
                format!(
                    "Ignored stale patch-set load result for operation {}",
                    operation.get()
                ),
            );
            return;
        }
        match result {
            Ok(outcome) => {
                if !self.patch_set_matches_current_project(&outcome) {
                    let error =
                        "Loaded patch set did not match the current project identity".to_owned();
                    self.patch_set_result = Some(Err(error.clone()));
                    self.console_reply(false, &error);
                    self.log(ActivityLevel::Error, error);
                    return;
                }
                let replacement = match PendingStaticPatchDrafts::from_requests(
                    outcome.manifest.requests(),
                ) {
                    Ok(replacement) => replacement,
                    Err(error) => {
                        let error = format!(
                            "Validated patch set cannot be represented as workbench drafts: {error}"
                        );
                        self.patch_set_result = Some(Err(error.clone()));
                        self.console_reply(false, &error);
                        self.log(ActivityLevel::Error, error);
                        return;
                    }
                };
                let message = patch_set_outcome_message("Loaded", &outcome);
                self.pending_static_patch_drafts = replacement;
                self.static_patch_result = None;
                self.patch_set_result = Some(Ok(message.clone()));
                self.console_reply(true, &message);
                self.log(ActivityLevel::Success, message);
            }
            Err(error) => {
                self.patch_set_result = Some(Err(error.clone()));
                self.console_reply(false, &error);
                self.log(
                    ActivityLevel::Error,
                    format!("Patch-set load failed: {error}"),
                );
            }
        }
    }

    fn patch_set_matches_current_project(&self, outcome: &PatchSetOutcome) -> bool {
        self.project.as_ref().is_some_and(|project| {
            project.session().base_analysis().identity() == outcome.manifest.source_identity()
        })
    }

    fn handle_worker_disconnect(&mut self, error: String) {
        if self.worker_disconnected {
            return;
        }
        let project_operation_was_pending = self.project_operation.is_pending();
        self.worker_disconnected = true;
        self.project_operation.invalidate();
        let interrupted_publication = self.publication_operation.invalidate();
        let patch_set_load_was_pending = self.patch_set_load_operation.is_pending();
        self.patch_set_load_operation.invalidate();
        self.review_operation.invalidate();
        self.plugin_operation.invalidate();
        self.readiness_operation.invalidate();
        self.offline_read.clear();
        if let Some(previous) = self.pending_review_rollback.take() {
            self.review = Some(previous);
        }
        if project_operation_was_pending {
            self.restore_project_context_after_failed_open();
        }
        self.close_after_review_save = false;
        match interrupted_publication {
            Some(PublicationKind::StaticPatch) => {
                self.static_patch_result = Some(Err(
                    "the application-service worker disconnected during static patch publication"
                        .to_owned(),
                ));
            }
            Some(PublicationKind::Export) => {
                self.export_result = Some(Err(
                    "the application-service worker disconnected during export publication"
                        .to_owned(),
                ));
            }
            Some(PublicationKind::PatchSet) => {
                self.patch_set_result = Some(Err(
                    "the application-service worker disconnected during patch-set save".to_owned(),
                ));
            }
            None => {}
        }
        if patch_set_load_was_pending {
            self.patch_set_result = Some(Err(
                "the application-service worker disconnected during patch-set load".to_owned(),
            ));
        }
        self.log(ActivityLevel::Error, error);
    }

    fn finish_project_open(&mut self, result: Result<LoadedProject, String>) {
        match result {
            Ok(project) => self.accept_project(project, ProjectAcceptance::NewProject),
            Err(error) => {
                self.restore_project_context_after_failed_open();
                self.log(
                    ActivityLevel::Error,
                    format!("Project open failed: {error}"),
                );
            }
        }
    }

    fn restore_project_context_after_failed_open(&mut self) {
        // `analysis_path` temporarily identifies the queued replacement so the
        // chrome can display an [OPENING] label. A failed open or disconnected
        // worker must restore the retained exact project and its visible tab,
        // or return to a genuinely empty Open state.
        self.analysis_path = self
            .project
            .as_ref()
            .map(|project| project.identity.active_binary_path().to_path_buf());
        self.stage = if self.project.is_some() {
            self.main_tab.workflow_stage()
        } else {
            WorkflowStage::Open
        };
    }

    fn finish_review_save(&mut self, context: &egui::Context, outcome: ReviewSaveOutcome) {
        let current = self
            .review
            .as_mut()
            .is_some_and(|review| review.mark_saved(&outcome.ledger, outcome.path.clone()));
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
        if self.open_after_review_save {
            self.open_after_review_save = false;
            if current {
                if let Some(path) = self.pending_binary_open.take() {
                    if let Err(error) = self.start_analysis(path) {
                        self.log(ActivityLevel::Error, error);
                    }
                }
            }
        }
    }

    fn accept_project(&mut self, project: LoadedProject, acceptance: ProjectAcceptance) {
        let recent_path = if acceptance == ProjectAcceptance::NewProject {
            self.analysis_path.clone()
        } else {
            None
        };
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
        self.publication_operation.invalidate();
        self.patch_set_load_operation.invalidate();
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
        if acceptance == ProjectAcceptance::NewProject {
            self.pending_static_patch_drafts.clear();
            self.selected_disassembly_instruction = None;
            self.disassembly_row_focus_target = None;
            self.static_patch_result = None;
            self.patch_set_result = None;
        }
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
        if let Some(path) = recent_path {
            self.remember_recent_binary(path);
        }
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
        let mut dialog = binary_picker_dialog(
            "Open a supported binary container or current ReSymbol package",
            BinaryPickerPurpose::OpenBinaryOrPackage,
        );
        if let Some(directory) = self
            .project
            .as_ref()
            .and_then(|project| project.identity.active_binary_path().parent())
        {
            dialog = dialog.set_directory(directory);
        } else if let Some(directory) = self
            .preferences
            .recent_binaries
            .first()
            .and_then(|path| path.parent())
        {
            dialog = dialog.set_directory(directory);
        }
        let Some(path) = dialog.pick_file() else {
            return;
        };
        self.request_binary_open(path);
    }

    fn select_main_tab(&mut self, tab: MainTab) {
        self.main_tab = tab;
        self.stage = if tab == MainTab::Exports {
            WorkflowStage::Export
        } else if self.project.is_some() {
            WorkflowStage::Review
        } else {
            WorkflowStage::Open
        };
        if tab != MainTab::Functions {
            self.function_row_focus_target = None;
            self.function_focused_row_id = None;
        }
    }

    fn cycle_main_tab(&mut self, direction: CycleDirection) {
        let Some(next_index) = cycle_index(self.main_tab.index(), MainTab::ALL.len(), direction)
        else {
            return;
        };
        self.select_main_tab(MainTab::ALL[next_index]);
    }

    fn navigate_function_selection(&mut self, navigation: RowNavigation) {
        let Some(project) = &self.project else {
            return;
        };
        let visible = project.visible_function_indices(&self.function_filter, self.function_sort);
        let visible_projection_indices = visible
            .iter()
            .map(|index| project.functions[*index].projection_index)
            .collect::<Vec<_>>();
        let Some(next) = navigate_visible_selection(
            &visible_projection_indices,
            self.selected_projection_index,
            navigation,
            FUNCTION_KEYBOARD_PAGE_ROWS,
        ) else {
            return;
        };
        let next_rva = project.functions.get(next).map(|row| row.rva);
        self.selected_projection_index = Some(next);
        self.graph_root_rva = next_rva;
        self.function_row_focus_target = Some(next);
    }

    fn handle_inputs(&mut self, context: &egui::Context) {
        if self.close_confirmation_open || self.pending_binary_open.is_some() {
            return;
        }
        let (tab_cycle, focus_function_search, row_navigation) = context.input(|input| {
            let command = input.modifiers.command;
            let tab_cycle = if command && input.key_pressed(Key::Tab) {
                Some(if input.modifiers.shift {
                    CycleDirection::Previous
                } else {
                    CycleDirection::Next
                })
            } else {
                None
            };
            let focus_function_search = command && input.key_pressed(Key::F);
            let row_navigation = if command || input.modifiers.alt || input.pointer.any_pressed() {
                None
            } else if input.key_pressed(Key::ArrowUp) {
                Some(RowNavigation::Previous)
            } else if input.key_pressed(Key::ArrowDown) {
                Some(RowNavigation::Next)
            } else if input.key_pressed(Key::PageUp) {
                Some(RowNavigation::PagePrevious)
            } else if input.key_pressed(Key::PageDown) {
                Some(RowNavigation::PageNext)
            } else if input.key_pressed(Key::Home) {
                Some(RowNavigation::First)
            } else if input.key_pressed(Key::End) {
                Some(RowNavigation::Last)
            } else {
                None
            };
            (tab_cycle, focus_function_search, row_navigation)
        });
        if let Some(direction) = tab_cycle {
            self.cycle_main_tab(direction);
        }
        if focus_function_search && self.project.is_some() {
            self.select_main_tab(MainTab::Functions);
            self.function_search_focus_requested = true;
            self.function_row_focus_target = None;
            self.function_focused_row_id = None;
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
        let function_row_owns_keyboard = self
            .function_focused_row_id
            .is_some_and(|id| context.memory(|memory| memory.has_focus(id)));
        let another_widget_owns_keyboard =
            context.wants_keyboard_input() && !function_row_owns_keyboard;
        if !another_widget_owns_keyboard
            && !self.project_operation.is_pending()
            && !self.review_operation.is_pending()
            && !self.publication_operation.is_pending()
            && !self.patch_set_load_operation.is_pending()
        {
            if undo_review {
                self.apply_review_ui_action(ReviewUiAction::Undo);
            } else if redo_review {
                self.apply_review_ui_action(ReviewUiAction::Redo);
            }
        }

        if !another_widget_owns_keyboard
            && self.main_tab == MainTab::Functions
            && !self.project_operation.is_pending()
        {
            if let Some(navigation) = row_navigation {
                self.navigate_function_selection(navigation);
            }
        }

        let dropped = context.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .filter_map(|file| file.path.clone())
                .collect::<Vec<_>>()
        });
        match dropped.as_slice() {
            [] => {}
            [path] => self.request_binary_open(path.clone()),
            paths => self.log(
                ActivityLevel::Warning,
                format!(
                    "Ignored {} dropped paths; drop exactly one binary or package at a time",
                    paths.len()
                ),
            ),
        }
    }

    fn show_binary_drop_target(&self, context: &egui::Context) {
        let hovered_count = context.input(|input| input.raw.hovered_files.len());
        if hovered_count == 0 {
            return;
        }
        let colors = self.preferences.theme.semantic_colors();
        let rect = context.screen_rect();
        let size = egui::vec2(430.0, 118.0);
        egui::Area::new(egui::Id::new("binary_drop_target"))
            .order(egui::Order::Foreground)
            .fixed_pos(rect.center() - size / 2.0)
            .show(context, |ui| {
                ui.set_min_size(size);
                egui::Frame::new()
                    .fill(colors.raised)
                    .stroke(egui::Stroke::new(2.0, colors.exact_extracted))
                    .corner_radius(8)
                    .inner_margin(egui::Margin::same(18))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.heading(if hovered_count == 1 {
                                "Drop to open this binary"
                            } else {
                                "Drop exactly one binary"
                            });
                            ui.label(
                                "PE32+ .exe/.dll/.sys/.cpl/.ocx/.scr/.efi, ELF32 .elf/.axf, extensionless containers, and current .resym packages are supported.",
                            );
                            ui.small(
                                "The active project remains intact unless the replacement opens successfully.",
                            );
                        });
                    });
            });
    }

    fn show_header(&mut self, context: &egui::Context) {
        let colors = self.preferences.theme.semantic_colors();
        let viewport = context.screen_rect().size();
        let chrome = shell_chrome_layout(viewport.x, viewport.y);
        let can_open_binary = !self.project_operation.is_pending()
            && !self.publication_operation.is_pending()
            && !self.patch_set_load_operation.is_pending()
            && !self.review_operation.is_pending()
            && !self.readiness_operation.is_pending()
            && !self.offline_read.is_pending()
            && self.pending_binary_open.is_none();
        let recent_binaries = self.preferences.recent_binaries.clone();
        let mut choose_binary_requested = false;
        let mut recent_binary_requested = None;
        let mut clear_recent_requested = false;
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
                                // A Frame inherits its parent's horizontal layout. Keep the
                                // identity lines in an explicit vertical child so their widths
                                // do not add together and collide with the trailing controls.
                                ui.vertical(|ui| {
                                    if chrome.compact_header {
                                        ui.set_max_width(280.0);
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&project.identity.display_name)
                                                    .strong(),
                                            )
                                            .truncate(),
                                        )
                                        .on_hover_text(&project.identity.display_name);
                                    } else {
                                        ui.label(
                                            RichText::new(&project.identity.display_name).strong(),
                                        );
                                    }
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(if chrome.compact_header {
                                                "[EXACT] Identity bound"
                                            } else {
                                                "[EXACT] Exact identity"
                                            })
                                            .color(colors.exact_extracted),
                                        )
                                        .on_hover_text(format!(
                                            "SHA-256 {}",
                                            project.identity.sha256.as_str()
                                        ));
                                        if !chrome.compact_header {
                                            ui.label(
                                                RichText::new(short_hash(
                                                    project.identity.sha256.as_str(),
                                                ))
                                                .monospace()
                                                .small()
                                                .color(colors.secondary_text),
                                            )
                                            .on_hover_text(format!(
                                                "SHA-256 {}",
                                                project.identity.sha256.as_str()
                                            ));
                                        }
                                    });
                                    if self.project_operation.is_pending() {
                                        if let Some(path) = &self.analysis_path {
                                            ui.label(
                                                RichText::new(format!(
                                                    "[OPENING] {}",
                                                    path.file_name()
                                                        .and_then(|name| name.to_str())
                                                        .unwrap_or("selected binary")
                                                ))
                                                .small()
                                                .color(colors.inferred),
                                            )
                                            .on_hover_text(path.display().to_string());
                                        }
                                    }
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
                                choose_binary_requested = true;
                            }
                        }

                        if self.project.is_some()
                            && ui
                                .add_enabled(
                                    can_open_binary,
                                    egui::Button::new("Open Another..."),
                                )
                                .on_hover_text("Open another binary or package (Ctrl+O)")
                                .clicked()
                        {
                            choose_binary_requested = true;
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

                        ui.menu_button("File", |ui| {
                            if ui
                                .add_enabled(
                                    can_open_binary,
                                    egui::Button::new("Open Binary or Package...    Ctrl+O"),
                                )
                                .clicked()
                            {
                                choose_binary_requested = true;
                                ui.close();
                            }
                            ui.menu_button("Open Recent", |ui| {
                                if recent_binaries.is_empty() {
                                    ui.add_enabled(false, egui::Label::new("No recent binaries"));
                                } else {
                                    for path in &recent_binaries {
                                        let label = path
                                            .file_name()
                                            .and_then(|name| name.to_str())
                                            .map_or_else(
                                                || path.display().to_string(),
                                                ToOwned::to_owned,
                                            );
                                        let exists = path.is_file();
                                        let response = ui.add_enabled(
                                            can_open_binary && exists,
                                            egui::Button::new(if exists {
                                                label
                                            } else {
                                                format!("{label}  [missing]")
                                            }),
                                        );
                                        if response
                                            .on_hover_text(path.display().to_string())
                                            .clicked()
                                        {
                                            recent_binary_requested = Some(path.clone());
                                            ui.close();
                                        }
                                    }
                                }
                            });
                            ui.separator();
                            if ui
                                .add_enabled(
                                    !recent_binaries.is_empty(),
                                    egui::Button::new("Clear Recent"),
                                )
                                .clicked()
                            {
                                clear_recent_requested = true;
                                ui.close();
                            }
                        });
                    });
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    for (index, stage) in WorkflowStage::ALL.into_iter().enumerate() {
                        let enabled = match stage {
                            WorkflowStage::Open => can_open_binary,
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
                            if stage == WorkflowStage::Open {
                                choose_binary_requested = true;
                            } else {
                                self.stage = stage;
                                self.main_tab = match stage {
                                    WorkflowStage::Export => MainTab::Exports,
                                    WorkflowStage::Review => MainTab::Functions,
                                    _ => MainTab::Overview,
                                };
                            }
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
        if clear_recent_requested {
            self.preferences.recent_binaries.clear();
        }
        if let Some(path) = recent_binary_requested {
            self.request_binary_open(path);
        } else if choose_binary_requested {
            self.choose_binary(context);
        }
    }

    fn show_project_panel(&mut self, context: &egui::Context) {
        let colors = self.preferences.theme.semantic_colors();
        egui::SidePanel::left("project_navigation")
            .default_width(DEFAULT_PROJECT_PANEL_WIDTH)
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
                        ui.label("Core-only non-executing review mode");
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
                        .add_enabled(
                            project.static_address_space.is_some(),
                            egui::Button::selectable(
                                self.main_tab == MainTab::AddressSpace,
                                project.static_address_space.as_ref().map_or_else(
                                    || "Address space (unavailable)".to_owned(),
                                    |address_space| {
                                        format!("Address space ({})", address_space.regions().len())
                                    },
                                ),
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
                ui.collapsing("Plugins (read-only policy catalog)", |ui| {
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

    fn show_plugin_list(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let can_refresh = !self.plugin_operation.is_pending() && !self.worker_disconnected;
            if ui
                .add_enabled(can_refresh, egui::Button::new("Refresh"))
                .on_hover_text(
                    "Re-scan plugin artifacts and exact-fingerprint policy off the UI thread",
                )
                .clicked()
            {
                if let Err(error) = self.queue_plugin_catalog_refresh() {
                    self.log(
                        ActivityLevel::Error,
                        format!("Plugin catalog refresh failed: {error}"),
                    );
                }
            }
            if self.plugin_operation.is_pending() {
                ui.label(RichText::new("Scanning...").weak());
            }
        });
        ui.small(
            "Discovery health includes manifest, API, entrypoint, duplicate-ID, and declared plugin-dependency checks. Runtime, capability selection, host/helper, granted-permission, target, and launch-time gates are not evaluated. The workbench never executes plugins.",
        );
        match &self.plugin_catalog {
            None => {
                ui.label("[--] Plugin catalog has not completed yet");
            }
            Some(Ok(report)) if report.entries().is_empty() => {
                ui.label("[--] No plugins discovered");
            }
            Some(Ok(report)) => {
                ui.small(format!("Root: {}", report.root().display()));
                for plugin in report.entries() {
                    show_plugin(ui, plugin, self.preferences.theme.semantic_colors());
                }
            }
            Some(Err(error)) => {
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
            .default_width(DEFAULT_INSPECTOR_PANEL_WIDTH)
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
                            || self.publication_operation.is_pending()
                            || self.patch_set_load_operation.is_pending();
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
        let viewport = context.screen_rect().size();
        let chrome = shell_chrome_layout(viewport.x, context.available_rect().height());
        let panel = egui::TopBottomPanel::bottom("activity_and_diagnostics")
            .default_height(chrome.activity_default_height)
            .height_range(chrome.activity_min_height..=chrome.activity_max_height)
            .resizable(true)
            .frame(
                egui::Frame::new()
                    .fill(colors.panel)
                    .stroke(egui::Stroke::new(1.0, colors.border))
                    .inner_margin(egui::Margin::same(8)),
            );
        let is_open = self.preferences.bottom_panel_open;
        let contents = |ui: &mut egui::Ui| {
            if chrome.compact_header {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Activity").strong());
                    egui::ComboBox::from_id_salt("activity_tab_compact_selector")
                        .selected_text(self.activity_tab.label())
                        .width(180.0)
                        .show_ui(ui, |ui| {
                            for tab in ActivityTab::ALL {
                                ui.selectable_value(&mut self.activity_tab, tab, tab.label());
                            }
                        });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Hide").clicked() {
                            self.preferences.bottom_panel_open = false;
                        }
                    });
                });
            } else {
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
            }
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

    fn show_main_tab_bar(&mut self, ui: &mut egui::Ui) {
        let hidden_panel_menu = !self.preferences.left_panel_open
            || !self.preferences.right_panel_open
            || !self.preferences.bottom_panel_open;
        let panel_menu_reserve = if hidden_panel_menu { 76.0 } else { 0.0 };
        let tab_bar_width = (ui.available_width() - panel_menu_reserve).max(180.0);
        let presentation = main_tab_presentation(tab_bar_width, MainTab::ALL.len());
        let mut selected_tab = self.main_tab;

        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(tab_bar_width, 32.0),
                Layout::left_to_right(Align::Center),
                |ui| match presentation {
                    MainTabPresentation::Full | MainTabPresentation::Compact => {
                        ui.spacing_mut().item_spacing.x = presentation.spacing();
                        let button_width = presentation
                            .button_width()
                            .expect("button presentations have a width");
                        for tab in MainTab::ALL {
                            let label = if presentation == MainTabPresentation::Compact {
                                tab.compact_label()
                            } else {
                                tab.label()
                            };
                            let response = ui.add_sized(
                                [button_width, 32.0],
                                egui::Button::selectable(selected_tab == tab, label)
                                    .corner_radius(4),
                            );
                            let response = if presentation == MainTabPresentation::Compact {
                                response.on_hover_text(tab.label())
                            } else {
                                response
                            };
                            response.widget_info(|| {
                                egui::WidgetInfo::selected(
                                    egui::WidgetType::Button,
                                    true,
                                    selected_tab == tab,
                                    tab.label(),
                                )
                            });
                            if response.clicked() {
                                selected_tab = tab;
                            }
                        }
                    }
                    MainTabPresentation::Menu => {
                        ui.label(RichText::new("View").strong());
                        egui::ComboBox::from_id_salt("main_tab_overflow_selector")
                            .selected_text(selected_tab.label())
                            .width((tab_bar_width - 54.0).clamp(140.0, 300.0))
                            .show_ui(ui, |ui| {
                                for tab in MainTab::ALL {
                                    ui.selectable_value(&mut selected_tab, tab, tab.label());
                                }
                            });
                    }
                },
            );

            if hidden_panel_menu {
                ui.menu_button("Panels", |ui| {
                    if !self.preferences.left_panel_open && ui.button("Show project").clicked() {
                        self.preferences.left_panel_open = true;
                        ui.close();
                    }
                    if !self.preferences.right_panel_open && ui.button("Show inspector").clicked() {
                        self.preferences.right_panel_open = true;
                        ui.close();
                    }
                    if !self.preferences.bottom_panel_open && ui.button("Show activity").clicked() {
                        self.preferences.bottom_panel_open = true;
                        ui.close();
                    }
                });
            }
        });

        if selected_tab != self.main_tab {
            self.select_main_tab(selected_tab);
        }
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
                self.show_main_tab_bar(ui);
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
            let Some(path) = binary_picker_dialog(
                "Verify the exact original binary for this package",
                BinaryPickerPurpose::VerifyExactBinary,
            )
            .pick_file() else {
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
                "Open a PE32+ x86-64 binary, bounded ELF32 container, or current ReSymbol package.",
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
            ui.small(
                "You can also drag a supported PE, bounded ELF32 container, extensionless container, or .resym package onto this window.",
            );
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
                    ui.heading("Container inventory");
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
                        BinaryAnalysis::Elf(elf) => {
                            property_row(
                                ui,
                                "Program headers",
                                &elf.program_headers.len().to_string(),
                                false,
                            );
                            property_row(
                                ui,
                                "Load segments",
                                &elf.load_segments.len().to_string(),
                                false,
                            );
                            property_row(
                                ui,
                                "Section headers",
                                &elf.section_headers.len().to_string(),
                                false,
                            );
                            property_row(
                                ui,
                                "ELF flags",
                                &format!("0x{:08X}", elf.flags),
                                true,
                            );
                            ui.label(
                                RichText::new("Container-only: no instruction decoding")
                                    .color(colors.secondary_text),
                            );
                        }
                        _ => {
                            ui.label("No container inventory is available for this format.");
                        }
                    };
                });
            });

            ui.add_space(14.0);
            ui.heading(match project.session().base_analysis() {
                BinaryAnalysis::Pe(_) => "PE sections",
                BinaryAnalysis::Elf(_) => "ELF section headers",
                _ => "Section table",
            });
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
                BinaryAnalysis::Elf(elf) => {
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .column(Column::initial(90.0).at_least(70.0))
                        .column(Column::initial(130.0).at_least(100.0))
                        .column(Column::initial(140.0).at_least(110.0))
                        .column(Column::remainder().at_least(180.0))
                        .header(30.0, |mut header| {
                            header.col(|ui| {
                                ui.strong("Index");
                            });
                            header.col(|ui| {
                                ui.strong("Type");
                            });
                            header.col(|ui| {
                                ui.strong("VA");
                            });
                            header.col(|ui| {
                                ui.strong("Size / flags");
                            });
                        })
                        .body(|mut body| {
                            for section in &elf.section_headers {
                                body.row(28.0, |mut row| {
                                    row.col(|ui| {
                                        ui.monospace(section.table_index.to_string());
                                    });
                                    row.col(|ui| {
                                        ui.monospace(format!("0x{:08X}", section.section_type));
                                    });
                                    row.col(|ui| {
                                        ui.monospace(format!(
                                            "0x{:08X}",
                                            section.virtual_address
                                        ));
                                    });
                                    row.col(|ui| {
                                        ui.monospace(format!(
                                            "0x{:X} / 0x{:08X}",
                                            section.size, section.flags
                                        ));
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
        self.handle_address_space_shortcuts(ui);
        let static_layout = self
            .project
            .as_ref()
            .expect("checked by caller")
            .static_address_space
            .as_ref()
            .map(|address_space| address_space.layout);

        ui.heading("Static address space");
        let Some(static_layout) = static_layout else {
            ui.label(
                RichText::new(
                    "Static address-space and offline-byte views are unavailable for this binary format.",
                )
                .color(colors.secondary_text),
            );
            return;
        };

        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("[OFFLINE] No target code has executed")
                    .strong()
                    .color(colors.healthy),
            );
            ui.label(
                RichText::new(match static_layout {
                    StaticImageLayout::Pe { .. } => {
                        "Preferred PE layout; live mappings may differ after load"
                    }
                    StaticImageLayout::Elf => {
                        "Sparse ELF PT_LOAD layout; virtual gaps are unmapped"
                    }
                })
                .color(colors.secondary_text),
            );
        });
        ui.add_space(8.0);

        self.show_offline_byte_reader(ui, colors);
        ui.add_space(8.0);

        let project = self.project.as_ref().expect("checked by caller");
        let address_space = project
            .static_address_space
            .as_ref()
            .expect("format availability checked above");
        let indicator_text = match &project.protection_assessment {
            ProtectionAssessment::Available(report) => report.findings().len().to_string(),
            ProtectionAssessment::ExactSourceRequired => "source required".to_owned(),
            ProtectionAssessment::UnsupportedFormat => "not applicable".to_owned(),
        };
        let (layout_property_label, layout_property_value) = match address_space.layout {
            StaticImageLayout::Pe {
                section_alignment,
                file_alignment,
            } => (
                "Section / file align",
                format!("0x{section_alignment:X} / 0x{file_alignment:X}"),
            ),
            StaticImageLayout::Elf => (
                "Mapping model",
                format!("{} sparse PT_LOAD", address_space.regions().len()),
            ),
        };

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
                        layout_property_label,
                        &layout_property_value,
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
        let disassembly_available = self.x64_linear_preview_available();
        if !disassembly_available {
            self.offline_byte_view = OfflineByteView::Hex;
            self.selected_disassembly_instruction = None;
            self.disassembly_row_focus_target = None;
        }
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
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Preview").strong());
                    ui.selectable_value(&mut self.offline_byte_view, OfflineByteView::Hex, "Hex")
                        .on_hover_text("Show exact verified bytes (keyboard: H)");
                    ui.add_enabled_ui(disassembly_available, |ui| {
                        ui.selectable_value(
                            &mut self.offline_byte_view,
                            OfflineByteView::Disassembly,
                            "Disassembly",
                        )
                        .on_hover_text("Show bounded x64 linear preview (keyboard: D)");
                    });
                    ui.label(
                        RichText::new(if disassembly_available {
                            "H/D switch view; arrow keys select instructions"
                        } else {
                            "Hex is available; x64 disassembly is PE-only"
                        })
                        .small()
                        .color(colors.secondary_text),
                    );
                });

                if let Some(presentation) = presentation {
                    ui.add_space(7.0);
                    match presentation {
                        OfflineReadPresentation::Failure(error) => {
                            ui.colored_label(
                                colors.destructive_quarantined,
                                format!(
                                    "[FAILED CLOSED] {}",
                                    bounded_message(offline_read_failure_text(&error))
                                ),
                            );
                        }
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
                                    ui.label(
                                        RichText::new(offline_binding_text(&outcome))
                                            .monospace()
                                            .small()
                                            .color(colors.secondary_text),
                                    );
                                    match self.offline_byte_view {
                                        OfflineByteView::Hex => {
                                            self.show_offline_hex_preview(
                                                ui,
                                                outcome.span().rva(),
                                                bytes,
                                            );
                                        }
                                        OfflineByteView::Disassembly => {
                                            self.show_linear_disassembly_preview(
                                                ui,
                                                outcome.span().rva(),
                                                bytes,
                                                colors,
                                            );
                                        }
                                    }
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
                                    ui.label(
                                        RichText::new(offline_binding_text(&outcome))
                                            .monospace()
                                            .small()
                                            .color(colors.secondary_text),
                                    );
                                }
                            }
                        }
                    }
                }
            });

        self.show_pending_static_patch_drafts(ui, colors);

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

    fn handle_address_space_shortcuts(&mut self, ui: &egui::Ui) {
        if ui.ctx().wants_keyboard_input() {
            return;
        }
        let (show_hex, show_disassembly) = ui.ctx().input(|input| {
            let plain = !input.modifiers.command
                && !input.modifiers.ctrl
                && !input.modifiers.alt
                && !input.modifiers.shift;
            (
                plain && input.key_pressed(Key::H),
                plain && input.key_pressed(Key::D),
            )
        });
        if show_hex {
            self.offline_byte_view = OfflineByteView::Hex;
        } else if show_disassembly && self.x64_linear_preview_available() {
            self.offline_byte_view = OfflineByteView::Disassembly;
        }
    }

    fn x64_linear_preview_available(&self) -> bool {
        self.project.as_ref().is_some_and(|project| {
            matches!(project.session().base_analysis(), BinaryAnalysis::Pe(_))
        })
    }

    fn show_offline_hex_preview(&self, ui: &mut egui::Ui, start_rva: u64, bytes: &[u8]) {
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
                        for row in format_offline_hex_rows(start_rva, bytes) {
                            ui.monospace(format!("0x{:016X}", row.rva));
                            ui.monospace(row.hex);
                            ui.monospace(format!("|{}|", row.ascii));
                            ui.end_row();
                        }
                    });
            });
    }

    fn show_linear_disassembly_preview(
        &mut self,
        ui: &mut egui::Ui,
        start_rva: u64,
        bytes: &[u8],
        colors: SemanticColors,
    ) {
        let limits = match LinearDisassemblyLimits::new(
            bytes.len().max(1),
            OFFLINE_DISASSEMBLY_INSTRUCTION_LIMIT,
        ) {
            Ok(limits) => limits,
            Err(error) => {
                ui.colored_label(
                    colors.destructive_quarantined,
                    format!("[FAILED CLOSED] Cannot construct linear preview: {error}"),
                );
                return;
            }
        };
        let preview = disassemble_x64_linear(bytes, start_rva, limits);
        if self
            .selected_disassembly_instruction
            .is_some_and(|index| index >= preview.rows().len())
        {
            self.selected_disassembly_instruction = None;
            self.disassembly_row_focus_target = None;
        }
        self.apply_disassembly_keyboard_navigation(ui, &preview);

        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(LinearDisassemblyPreview::DISCLAIMER)
                    .strong()
                    .color(colors.warning_conflict),
            );
            ui.label(
                RichText::new(format!(
                    "{} instruction(s), {} byte(s) considered; {}",
                    preview.rows().len(),
                    preview.considered_bytes(),
                    preview.stop_reason().label()
                ))
                .small()
                .color(colors.secondary_text),
            );
        });

        let selected_index = self
            .selected_disassembly_instruction
            .filter(|index| *index < preview.rows().len());
        let focus_target = self.disassembly_row_focus_target;
        ScrollArea::both()
            .id_salt("offline_linear_disassembly_scroll")
            .auto_shrink([false, true])
            .max_height(180.0)
            .show(ui, |ui| {
                ui.set_min_width(760.0);
                egui::Grid::new("offline_linear_disassembly_rows")
                    .num_columns(5)
                    .spacing([12.0, 3.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("RVA");
                        ui.strong("Bytes");
                        ui.strong("Instruction");
                        ui.strong("Flow");
                        ui.strong("Len");
                        ui.end_row();
                        for (index, row) in preview.rows().iter().enumerate() {
                            let selected = selected_index == Some(index);
                            let accessible =
                                instruction_row_accessible_label(row, index, preview.rows().len());
                            let rva_response = ui
                                .add(
                                    egui::Label::new(
                                        RichText::new(format!("0x{:016X}", row.rva())).monospace(),
                                    )
                                    .sense(Sense::click()),
                                )
                                .on_hover_text(&accessible);
                            self.bind_instruction_row_context(&rva_response, index, row, colors);
                            let bytes_response = ui
                                .add(
                                    egui::Label::new(
                                        RichText::new(format_instruction_bytes(row.bytes()))
                                            .monospace(),
                                    )
                                    .sense(Sense::click()),
                                )
                                .on_hover_text(&accessible);
                            self.bind_instruction_row_context(&bytes_response, index, row, colors);
                            let response = ui
                                .selectable_label(selected, RichText::new(row.text()).monospace())
                                .on_hover_text(&accessible);
                            response.widget_info(|| {
                                egui::WidgetInfo::selected(
                                    egui::WidgetType::SelectableLabel,
                                    true,
                                    selected,
                                    &accessible,
                                )
                            });
                            if focus_target == Some(index) {
                                response.request_focus();
                                response.scroll_to_me(Some(Align::Center));
                            }
                            self.bind_instruction_row_context(&response, index, row, colors);
                            let flow_response = ui
                                .add(
                                    egui::Label::new(
                                        RichText::new(row.flow_control().label()).monospace(),
                                    )
                                    .sense(Sense::click()),
                                )
                                .on_hover_text(&accessible);
                            self.bind_instruction_row_context(&flow_response, index, row, colors);
                            let length_response = ui
                                .add(
                                    egui::Label::new(
                                        RichText::new(row.length().to_string()).monospace(),
                                    )
                                    .sense(Sense::click()),
                                )
                                .on_hover_text(&accessible);
                            self.bind_instruction_row_context(&length_response, index, row, colors);
                            ui.end_row();
                        }
                    });
            });
        if focus_target.is_some() {
            self.disassembly_row_focus_target = None;
        }

        if let Some(index) = self
            .selected_disassembly_instruction
            .filter(|index| *index < preview.rows().len())
        {
            ui.horizontal_wrapped(|ui| {
                ui.menu_button("Selected instruction actions...", |ui| {
                    self.show_instruction_action_menu(ui, &preview.rows()[index], colors);
                });
                ui.label(
                    RichText::new(
                        "Keyboard: arrows/Home/End select, Ctrl+C copies RVA, Ctrl+Shift+C copies bytes, Alt+N queues a static NOP draft",
                    )
                    .small()
                    .color(colors.secondary_text),
                );
            });
        }
    }

    fn bind_instruction_row_context(
        &mut self,
        response: &egui::Response,
        index: usize,
        row: &LinearInstructionRow,
        colors: SemanticColors,
    ) {
        if response.clicked() || response.secondary_clicked() {
            self.selected_disassembly_instruction = Some(index);
        }
        response.context_menu(|ui| {
            self.show_instruction_action_menu(ui, row, colors);
        });
    }

    fn apply_disassembly_keyboard_navigation(
        &mut self,
        ui: &egui::Ui,
        preview: &LinearDisassemblyPreview,
    ) {
        if ui.ctx().wants_keyboard_input() {
            return;
        }
        let (movement, copy_rva, copy_bytes, queue_nop) = ui.ctx().input(|input| {
            let movement = if input.modifiers.command
                || input.modifiers.ctrl
                || input.modifiers.alt
                || input.modifiers.shift
            {
                None
            } else if input.key_pressed(Key::ArrowUp) {
                Some(InstructionSelectionMove::Previous)
            } else if input.key_pressed(Key::ArrowDown) {
                Some(InstructionSelectionMove::Next)
            } else if input.key_pressed(Key::Home) {
                Some(InstructionSelectionMove::First)
            } else if input.key_pressed(Key::End) {
                Some(InstructionSelectionMove::Last)
            } else {
                None
            };
            let command = input.modifiers.command || input.modifiers.ctrl;
            (
                movement,
                command && !input.modifiers.shift && input.key_pressed(Key::C),
                command && input.modifiers.shift && input.key_pressed(Key::C),
                input.modifiers.alt && input.key_pressed(Key::N),
            )
        });
        if let Some(movement) = movement {
            let selected = navigate_instruction_selection(
                self.selected_disassembly_instruction,
                preview.rows().len(),
                movement,
            );
            self.selected_disassembly_instruction = selected;
            self.disassembly_row_focus_target = selected;
        }
        let Some(row) = self
            .selected_disassembly_instruction
            .and_then(|index| preview.rows().get(index))
        else {
            return;
        };
        if copy_rva {
            ui.ctx().copy_text(format!("0x{:016X}", row.rva()));
        }
        if copy_bytes {
            ui.ctx().copy_text(format_instruction_bytes(row.bytes()));
        }
        if queue_nop {
            self.queue_static_nop_draft(row);
        }
    }

    fn show_instruction_action_menu(
        &mut self,
        ui: &mut egui::Ui,
        row: &LinearInstructionRow,
        colors: SemanticColors,
    ) {
        ui.label(RichText::new(row.text()).monospace().strong());
        if ui.button("Copy RVA").clicked() {
            ui.ctx().copy_text(format!("0x{:016X}", row.rva()));
            ui.close();
        }
        let preferred_address = self.preferred_static_address(row.rva());
        let copy_address = ui
            .add_enabled(
                preferred_address.is_some(),
                egui::Button::new("Copy Preferred Address"),
            )
            .on_disabled_hover_text(
                "The RVA is outside the preferred static image or overflows its preferred base.",
            );
        if copy_address.clicked() {
            ui.ctx().copy_text(format!(
                "0x{:016X}",
                preferred_address.expect("enabled preferred address")
            ));
            ui.close();
        }
        if ui.button("Copy Bytes").clicked() {
            ui.ctx().copy_text(format_instruction_bytes(row.bytes()));
            ui.close();
        }
        if ui.button("Copy Instruction").clicked() {
            ui.ctx().copy_text(row.text().to_owned());
            ui.close();
        }

        let target = row.direct_target_rva();
        let target_readable =
            target.is_some_and(|target| self.static_rva_has_readable_file_backing(target));
        let follow = ui
            .add_enabled(target_readable, egui::Button::new("Follow Direct Target"))
            .on_disabled_hover_text(match target {
                None => "No typed direct branch/call target is present; indirect targets are never guessed.",
                Some(_) => "The direct target is outside readable exact file backing in the verified static image.",
            });
        if follow.clicked() {
            self.follow_static_target(target.expect("enabled direct target"));
            ui.close();
        }
        ui.separator();
        let already_nop_filled = row.bytes().iter().all(|byte| *byte == 0x90);
        let static_nop_disabled_reason = self.static_nop_patchability(row).err();
        let queue_static_nop = ui
            .add_enabled(
                static_nop_disabled_reason.is_none(),
                egui::Button::new("Queue NOP for Patched Binary"),
            )
            .on_disabled_hover_text(
                static_nop_disabled_reason.unwrap_or("The static NOP draft is unavailable."),
            );
        if queue_static_nop.clicked() {
            self.queue_static_nop_draft(row);
            ui.close();
        }
        let static_edit_disabled_reason = self.static_instruction_patchability(row).err();
        for branch_patch in [
            ConditionalBranchPatch::InvertCondition,
            ConditionalBranchPatch::AlwaysTaken,
        ] {
            let replacement = branch_patch.replacement(row.bytes());
            let branch_edit = ui
                .add_enabled(
                    static_edit_disabled_reason.is_none() && replacement.is_some(),
                    egui::Button::new(branch_patch.label()),
                )
                .on_disabled_hover_text(static_edit_disabled_reason.unwrap_or(
                    "Only an exact canonical short or near x86-64 conditional branch can use this action.",
                ));
            if branch_edit.clicked() {
                self.queue_static_conditional_branch_draft(row, branch_patch);
                ui.close();
            }
        }
        ui.label(
            RichText::new(
                "Draft only; NOP means never take a Jcc, while always-taken and invert preserve the exact original target.",
            )
                .small()
                .color(colors.secondary_text),
        );
        ui.separator();
        ui.label(RichText::new("Live debugger").strong());
        let live = LiveDebuggerActionContext::disconnected();
        if let Some(reason) = live
            .availability(LiveInstructionAction::Continue, row.bytes())
            .disabled_reason()
        {
            ui.label(
                RichText::new(format!("Live actions disabled: {reason}"))
                    .small()
                    .color(colors.secondary_text),
            );
        }
        if already_nop_filled {
            ui.label(
                RichText::new("Live NOP disabled: The selected instruction is already NOP-filled.")
                    .small()
                    .color(colors.secondary_text),
            );
        }
        for action in LiveInstructionAction::ALL {
            let availability = live.availability(action, row.bytes());
            let route = protocol_route_text(&action.protocol_route_preview(row.bytes()));
            let button = ui
                .add_enabled(availability.is_enabled(), egui::Button::new(action.label()))
                .on_disabled_hover_text(format!(
                    "{} Typed route: {route}",
                    availability
                        .disabled_reason()
                        .unwrap_or("Action is unavailable.")
                ));
            if button.clicked() {
                // This branch is unreachable while the UI has no authenticated
                // typed client adapter. Keep the failure visible if the policy
                // model and adapter wiring ever diverge.
                self.log(
                    ActivityLevel::Error,
                    format!(
                        "Live action {} has no authenticated workbench client adapter",
                        action.label()
                    ),
                );
            }
        }
    }

    #[cfg(feature = "screenshot")]
    fn screenshot_disassembly_action_row(&self) -> Option<LinearInstructionRow> {
        let OfflineReadPresentation::Outcome(outcome) = self.offline_read.presentation.as_ref()?
        else {
            return None;
        };
        let bytes = outcome.availability().bytes()?;
        let limits =
            LinearDisassemblyLimits::new(bytes.len().max(1), OFFLINE_DISASSEMBLY_INSTRUCTION_LIMIT)
                .ok()?;
        let preview = disassemble_x64_linear(bytes, outcome.span().rva(), limits);
        let row = preview.rows().first()?.clone();
        (row.rva() == SCREENSHOT_CANONICAL_JCC_RVA
            && ConditionalBranchPatch::InvertCondition
                .replacement(row.bytes())
                .is_some())
        .then_some(row)
    }

    #[cfg(feature = "screenshot")]
    fn show_screenshot_scenario_overlay(&mut self, context: &egui::Context) {
        if self.screenshot_scenario == Some(ScreenshotScenario::DebuggerReadinessResult) {
            self.show_screenshot_readiness_result_overlay(context);
            return;
        }
        if self.screenshot_scenario != Some(ScreenshotScenario::DisassemblyActions) {
            return;
        }
        if self.offline_read.is_pending() {
            return;
        }
        let row = self.screenshot_disassembly_action_row().unwrap_or_else(|| {
            panic!(
                "disassembly-actions scenario requires canonical Jcc bytes at fixture RVA 0x{SCREENSHOT_CANONICAL_JCC_RVA:08X}"
            )
        });
        let colors = self.preferences.theme.semantic_colors();
        let screen = context.screen_rect();
        let popup_width = 430.0;
        let position = egui::pos2(
            (screen.center().x - popup_width / 2.0).max(screen.left() + 8.0),
            screen.top() + 128.0,
        );
        egui::Area::new(egui::Id::new("screenshot_disassembly_action_menu"))
            .order(egui::Order::Foreground)
            .fixed_pos(position)
            .movable(false)
            .show(context, |ui| {
                egui::Frame::popup(ui.style()).show(ui, |ui| {
                    ui.set_min_width(popup_width);
                    self.show_instruction_action_menu(ui, &row, colors);
                });
            });
    }

    #[cfg(feature = "screenshot")]
    fn show_screenshot_readiness_result_overlay(&self, context: &egui::Context) {
        if self.readiness_operation.is_pending() {
            return;
        }
        let outcome = self.readiness_outcome.as_ref().unwrap_or_else(|| {
            let detail = self
                .readiness_error
                .as_deref()
                .unwrap_or("probe completed without an outcome or error");
            panic!(
                "debugger-readiness-result scenario requires a typed readiness outcome: {detail}"
            )
        });
        let colors = self.preferences.theme.semantic_colors();
        let screen = context.screen_rect();
        let popup_width = 920.0_f32.min(screen.width() - 32.0);
        let position = egui::pos2(
            (screen.center().x - popup_width / 2.0).max(screen.left() + 8.0),
            screen.top() + 128.0,
        );
        egui::Area::new(egui::Id::new("screenshot_debugger_readiness_result"))
            .order(egui::Order::Foreground)
            .fixed_pos(position)
            .movable(false)
            .show(context, |ui| {
                egui::Frame::popup(ui.style()).show(ui, |ui| {
                    ui.set_width(popup_width);
                    ui.label(RichText::new("Read-only readiness outcome").heading());
                    ui.label(
                        RichText::new(
                            "This capture foregrounds the exact result bound to the selected provider and binary evidence.",
                        )
                        .color(colors.secondary_text),
                    );
                    ui.add_space(8.0);
                    show_sandbox_readiness_outcome(ui, outcome, colors);
                });
            });
    }

    fn static_rva_has_readable_file_backing(&self, rva: u64) -> bool {
        let address = RelativeAddress::new(rva);
        self.project
            .as_ref()
            .and_then(|project| project.static_address_space.as_ref())
            .and_then(|address_space| address_space.region_at(address))
            .is_some_and(|region| {
                region.access.readable && region.file_offset_at(address).is_some()
            })
    }

    fn static_instruction_patchability(
        &self,
        row: &LinearInstructionRow,
    ) -> Result<(), &'static str> {
        if self.publication_operation.is_pending() {
            return Err("A file publication is already running.");
        }
        if self.patch_set_load_operation.is_pending() {
            return Err("A patch-set load is already running.");
        }
        if row.bytes().is_empty() {
            return Err("The selected instruction has no exact source bytes.");
        }
        let project = self.project.as_ref().ok_or("No static project is open.")?;
        if !project.snapshot.has_verified_source() {
            return Err("The exact source binary must be verified before queuing a static edit.");
        }
        let start = RelativeAddress::new(row.rva());
        let last_rva = row
            .rva()
            .checked_add(row.bytes().len() as u64 - 1)
            .ok_or("The selected instruction range overflows the RVA address space.")?;
        let last = RelativeAddress::new(last_rva);
        let region = project
            .static_address_space
            .as_ref()
            .ok_or("Static address-space inspection is unavailable for this binary format.")?
            .region_at(start)
            .ok_or("The selected instruction is outside the preferred static image.")?;
        if !region.access.executable || !matches!(&region.kind, StaticRegionKind::Section { .. }) {
            return Err("Static instruction edits are limited to executable PE sections.");
        }
        if region.file_offset_at(start).is_none() || region.file_offset_at(last).is_none() {
            return Err(
                "The complete instruction is not in one exact file-backed executable region.",
            );
        }
        Ok(())
    }

    fn static_nop_patchability(&self, row: &LinearInstructionRow) -> Result<(), &'static str> {
        self.static_instruction_patchability(row)?;
        if row.bytes().iter().all(|byte| *byte == 0x90) {
            return Err("The selected instruction is already NOP-filled.");
        }
        Ok(())
    }

    fn preferred_static_address(&self, rva: u64) -> Option<u64> {
        self.project
            .as_ref()?
            .static_address_space
            .as_ref()?
            .preferred_virtual_address(RelativeAddress::new(rva))
    }

    fn follow_static_target(&mut self, target_rva: u64) {
        if !self.static_rva_has_readable_file_backing(target_rva) {
            self.log(
                ActivityLevel::Warning,
                format!(
                    "Cannot follow RVA 0x{target_rva:016X}: target is not in readable exact file backing"
                ),
            );
            return;
        }
        self.offline_read_rva_input = format!("0x{target_rva:016X}");
        self.selected_disassembly_instruction = None;
        self.disassembly_row_focus_target = None;
        if let Err(error) = self.queue_offline_image_read() {
            self.log(
                ActivityLevel::Error,
                format!("Cannot follow direct target: {error}"),
            );
        }
    }

    fn queue_static_nop_draft(&mut self, row: &LinearInstructionRow) {
        if let Err(reason) = self.static_nop_patchability(row) {
            self.log(
                ActivityLevel::Error,
                format!("Cannot queue static NOP draft: {reason}"),
            );
            return;
        }
        let label = format!("NOP {} at RVA 0x{:016X}", row.text(), row.rva());
        match self
            .pending_static_patch_drafts
            .queue_nop(row.rva(), row.bytes(), label)
        {
            Ok(PatchDraftQueueOutcome::Added) => {
                self.static_patch_result = None;
                self.patch_set_result = None;
                self.log(
                    ActivityLevel::Success,
                    format!(
                        "Queued unpublished static NOP draft for RVA 0x{:016X}; no file or process was modified",
                        row.rva()
                    ),
                );
            }
            Ok(PatchDraftQueueOutcome::AlreadyQueued) => self.log(
                ActivityLevel::Info,
                format!(
                    "Static NOP draft for RVA 0x{:016X} is already queued",
                    row.rva()
                ),
            ),
            Err(error) => self.log(
                ActivityLevel::Error,
                format!("Cannot queue static NOP draft: {error}"),
            ),
        }
    }

    fn queue_static_conditional_branch_draft(
        &mut self,
        row: &LinearInstructionRow,
        action: ConditionalBranchPatch,
    ) {
        if let Err(reason) = self.static_instruction_patchability(row) {
            self.log(
                ActivityLevel::Error,
                format!("Cannot queue conditional-branch edit: {reason}"),
            );
            return;
        }
        let Some(replacement) = action.replacement(row.bytes()) else {
            self.log(
                ActivityLevel::Error,
                "Cannot queue conditional-branch edit: the instruction is not a supported canonical Jcc encoding",
            );
            return;
        };
        let label = format!(
            "{} at RVA 0x{:016X}",
            match action {
                ConditionalBranchPatch::InvertCondition => "Invert Jcc condition",
                ConditionalBranchPatch::AlwaysTaken => "Make Jcc always taken",
            },
            row.rva()
        );
        match self.pending_static_patch_drafts.queue_replace(
            row.rva(),
            row.bytes(),
            &replacement,
            label,
        ) {
            Ok(PatchDraftQueueOutcome::Added) => {
                self.static_patch_result = None;
                self.patch_set_result = None;
                self.log(
                    ActivityLevel::Success,
                    format!(
                        "Queued unpublished conditional-branch edit for RVA 0x{:016X}; no file or process was modified",
                        row.rva()
                    ),
                );
            }
            Ok(PatchDraftQueueOutcome::AlreadyQueued) => self.log(
                ActivityLevel::Info,
                format!(
                    "Conditional-branch edit for RVA 0x{:016X} is already queued",
                    row.rva()
                ),
            ),
            Err(error) => self.log(
                ActivityLevel::Error,
                format!("Cannot queue conditional-branch edit: {error}"),
            ),
        }
    }

    fn choose_static_patch_destination(&self) -> Option<PathBuf> {
        let default = self.project.as_ref().and_then(default_static_patch_path)?;
        let mut dialog = rfd::FileDialog::new()
            .set_title("Create a new patched binary")
            .add_filter(PE_CONTAINER_FILTER.label, PE_CONTAINER_FILTER.extensions)
            .add_filter(ALL_FILES_FILTER.label, ALL_FILES_FILTER.extensions);
        if let Some(parent) = default
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            dialog = dialog.set_directory(parent);
        }
        if let Some(name) = default.file_name().and_then(|name| name.to_str()) {
            dialog = dialog.set_file_name(name);
        }
        dialog.save_file()
    }

    fn choose_static_patch_set_save_destination(&self) -> Option<PathBuf> {
        let default = default_static_patch_set_path(self.project.as_ref()?);
        let mut dialog = rfd::FileDialog::new()
            .set_title("Save a new ReSymbol patch set")
            .add_filter("ReSymbol patch set", &["json"]);
        if let Some(parent) = default.parent() {
            dialog = dialog.set_directory(parent);
        }
        if let Some(name) = default.file_name().and_then(|name| name.to_str()) {
            dialog = dialog.set_file_name(name);
        }
        dialog.save_file()
    }

    fn choose_static_patch_set_to_load(&self) -> Option<PathBuf> {
        let default = default_static_patch_set_path(self.project.as_ref()?);
        let mut dialog = rfd::FileDialog::new()
            .set_title("Load an exact-source ReSymbol patch set")
            .add_filter("ReSymbol patch set", &["json"]);
        if let Some(parent) = default.parent() {
            dialog = dialog.set_directory(parent);
        }
        dialog.pick_file()
    }

    fn build_static_patch_requests(&self) -> Result<Vec<StaticPatchEditRequest>, String> {
        let drafts = self.pending_static_patch_drafts.drafts();
        if drafts.is_empty() {
            return Err("queue at least one static edit first".to_owned());
        }
        let mut requests = Vec::with_capacity(drafts.len());
        for draft in drafts {
            let rva = u32::try_from(draft.rva()).map_err(|_| {
                format!(
                    "static patch draft RVA 0x{:016X} exceeds the PE RVA range",
                    draft.rva()
                )
            })?;
            let request = match draft.kind() {
                StaticPatchDraftKind::NopInstruction => StaticPatchEditRequest::nop_instruction(
                    rva,
                    draft.expected().to_vec(),
                    draft.label().to_owned(),
                ),
                StaticPatchDraftKind::ReplaceBytes => StaticPatchEditRequest::replace_bytes(
                    rva,
                    draft.expected().to_vec(),
                    draft.replacement().to_vec(),
                    draft.label().to_owned(),
                ),
            }
            .map_err(|error| format!("static patch draft at RVA 0x{rva:08X}: {error}"))?;
            requests.push(request);
        }
        Ok(requests)
    }

    fn queue_static_patch_set_save(&mut self, path: PathBuf) -> Result<String, String> {
        if !is_static_patch_set_path(&path) {
            return Err(format!(
                "patch-set destination must end with {STATIC_PATCH_SET_SUFFIX}"
            ));
        }
        if path.exists() {
            return Err(format!(
                "choose a new patch-set path; {} will not be replaced",
                path.display()
            ));
        }
        if self.worker_disconnected {
            return Err("the application-service worker is unavailable".to_owned());
        }
        if self.project_operation.is_pending() {
            return Err(
                "wait for the current project operation before saving a patch set".to_owned(),
            );
        }
        if self.patch_set_load_operation.is_pending() {
            return Err("wait for the current patch-set load before saving".to_owned());
        }
        let requests = self.build_static_patch_requests()?;
        let (project, source_id) = {
            let project = self
                .project
                .as_ref()
                .ok_or_else(|| "open a project before saving a patch set".to_owned())?;
            (
                Arc::clone(&project.snapshot),
                project.identity.sha256.clone(),
            )
        };
        let destination =
            PublicationDestination::resolve(&path).map_err(|error| error.to_string())?;
        let edit_count = requests.len();
        let operation = self.operation_sequence.issue();
        self.publication_operation
            .begin(operation, PublicationKind::PatchSet, destination)
            .map_err(|error| error.to_string())?;
        let submit = self
            .service_worker
            .submit(WorkerCommand::SaveStaticPatchSet {
                operation,
                project,
                requests,
                path: path.clone(),
            });
        if let Err(error) = submit {
            let finished = self
                .publication_operation
                .finish(operation, PublicationKind::PatchSet);
            debug_assert!(finished, "failed patch-set submission releases reservation");
            return Err(error);
        }
        self.patch_set_result = None;
        let message = format!(
            "Queued create-new save of {edit_count} patch-set edit(s) for exact source {} to {}",
            source_id,
            path.display()
        );
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn queue_static_patch_set_load(&mut self, path: PathBuf) -> Result<String, String> {
        if !is_static_patch_set_path(&path) {
            return Err(format!(
                "patch-set input must end with {STATIC_PATCH_SET_SUFFIX}"
            ));
        }
        if self.worker_disconnected {
            return Err("the application-service worker is unavailable".to_owned());
        }
        if self.project_operation.is_pending() {
            return Err(
                "wait for the current project operation before loading a patch set".to_owned(),
            );
        }
        if self.publication_operation.is_pending() {
            return Err(
                "wait for the current file publication before loading a patch set".to_owned(),
            );
        }
        if self.patch_set_load_operation.is_pending() {
            return Err("a patch-set load is already running".to_owned());
        }
        let project = self
            .project
            .as_ref()
            .ok_or_else(|| "open a project before loading a patch set".to_owned())?;
        let operation = self.operation_sequence.issue();
        self.service_worker
            .submit(WorkerCommand::LoadStaticPatchSet {
                operation,
                project: Arc::clone(&project.snapshot),
                path: path.clone(),
            })?;
        self.patch_set_load_operation.begin(operation);
        self.patch_set_result = None;
        let message = format!("Queued strict patch-set load from {}", path.display());
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn queue_static_patch_publication(&mut self, path: PathBuf) -> Result<String, String> {
        if path.file_name().is_none() {
            return Err("choose a destination that names a new patched binary".to_owned());
        }
        if path.exists() {
            return Err(format!(
                "choose a new path; existing patched destination {} will not be replaced",
                path.display()
            ));
        }
        if self.worker_disconnected {
            return Err("the application-service worker is unavailable".to_owned());
        }
        if self.project_operation.is_pending() {
            return Err(
                "wait for the current project or source operation before publishing a patch"
                    .to_owned(),
            );
        }
        if self.patch_set_load_operation.is_pending() {
            return Err("wait for the current patch-set load before publishing a patch".to_owned());
        }
        let requests = self.build_static_patch_requests()?;
        let (project, project_name, source_path) = {
            let project = self
                .project
                .as_ref()
                .ok_or_else(|| "open a project before publishing a static patch".to_owned())?;
            let source_path = project.snapshot.verified_source_path().ok_or_else(|| {
                "the exact source binary must be verified before publishing a static patch"
                    .to_owned()
            })?;
            (
                Arc::clone(&project.snapshot),
                project.identity.display_name.clone(),
                source_path.to_path_buf(),
            )
        };
        if path == source_path {
            return Err(
                "the patched destination must differ from the verified source path".to_owned(),
            );
        }
        let destination =
            PublicationDestination::resolve(&path).map_err(|error| error.to_string())?;
        let edit_count = requests.len();
        let operation = self.operation_sequence.issue();
        self.publication_operation
            .begin(operation, PublicationKind::StaticPatch, destination)
            .map_err(|error| error.to_string())?;
        let submit = self
            .service_worker
            .submit(WorkerCommand::PublishStaticPatch {
                operation,
                project,
                requests,
                path: path.clone(),
            });
        if let Err(error) = submit {
            let finished = self
                .publication_operation
                .finish(operation, PublicationKind::StaticPatch);
            debug_assert!(
                finished,
                "failed static-patch submission releases its reservation"
            );
            return Err(error);
        }
        self.static_patch_result = None;
        let message = format!(
            "Queued {edit_count} exact static edit(s) for create-new publication to {} from {project_name}",
            path.display()
        );
        self.log(ActivityLevel::Info, &message);
        Ok(message)
    }

    fn show_pending_static_patch_drafts(&mut self, ui: &mut egui::Ui, colors: SemanticColors) {
        ui.add_space(6.0);
        let mut remove_rva = None;
        let mut clear_all = false;
        let mut publish_requested = false;
        let mut save_patch_set_requested = false;
        let mut load_patch_set_requested = false;
        let publication_pending = self.publication_operation.is_pending();
        let patch_set_load_pending = self.patch_set_load_operation.is_pending();
        let patch_set_busy = publication_pending || patch_set_load_pending;
        let static_publication_pending = self
            .publication_operation
            .is_kind(PublicationKind::StaticPatch);
        let patch_set_save_pending = self
            .publication_operation
            .is_kind(PublicationKind::PatchSet);
        let exact_source_ready = self
            .project
            .as_ref()
            .is_some_and(|project| project.snapshot.has_verified_source());
        let source_identity = self.project.as_ref().map(|project| {
            let identity = project.session().base_analysis().identity();
            format!(
                "Exact source: SHA-256 {}, size {}, format {:?}, architecture {}, image base 0x{:X}",
                identity.id.as_str(),
                identity.size,
                &identity.format,
                identity.architecture.as_str(),
                identity.image_base
            )
        });
        egui::Frame::new()
            .fill(colors.raised)
            .stroke(egui::Stroke::new(1.0, colors.border))
            .inner_margin(egui::Margin::same(8))
            .corner_radius(4)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Pending static patch drafts").strong());
                    ui.label(format!(
                        "{} / {}",
                        self.pending_static_patch_drafts.drafts().len(),
                        MAX_PENDING_STATIC_PATCH_DRAFTS
                    ));
                    ui.label(
                        RichText::new(
                            "Unpublished only; a checked publisher must verify exact source bytes and create a new binary.",
                        )
                        .color(colors.secondary_text),
                    );
                    if ui
                        .add_enabled(
                            !patch_set_busy
                                && !self.pending_static_patch_drafts.drafts().is_empty(),
                            egui::Button::new("Clear drafts"),
                        )
                        .clicked()
                    {
                        clear_all = true;
                    }
                });
                if let Some(source_identity) = &source_identity {
                    ui.label(
                        RichText::new(source_identity)
                            .monospace()
                            .small()
                            .color(colors.exact_extracted),
                    );
                }
                if self.pending_static_patch_drafts.drafts().is_empty() {
                    ui.label(
                        RichText::new("No pending static edits")
                            .small()
                            .color(colors.secondary_text),
                    );
                } else {
                    for draft in self.pending_static_patch_drafts.drafts() {
                        let (expected, replacement) = draft.source_check_and_replacement();
                        ui.horizontal_wrapped(|ui| {
                            ui.monospace(format!("0x{:016X}", draft.rva()));
                            ui.monospace(format_instruction_bytes(expected));
                            ui.label("->");
                            ui.monospace(format_instruction_bytes(replacement));
                            ui.label(draft.label());
                            if ui
                                .add_enabled(
                                    !patch_set_busy,
                                    egui::Button::new("Remove").small(),
                                )
                                .clicked()
                            {
                                remove_rva = Some(draft.rva());
                            }
                        });
                    }
                }
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    let can_save_patch_set = !patch_set_busy
                        && !self.worker_disconnected
                        && !self.project_operation.is_pending()
                        && !self.pending_static_patch_drafts.drafts().is_empty();
                    let save_label = if patch_set_save_pending {
                        "Saving Patch Set..."
                    } else {
                        "Save Patch Set..."
                    };
                    save_patch_set_requested = ui
                        .add_enabled(can_save_patch_set, egui::Button::new(save_label))
                        .on_disabled_hover_text(
                            "Saving requires at least one validated draft and an idle application-service worker.",
                        )
                        .clicked();
                    let load_label = if patch_set_load_pending {
                        "Loading Patch Set..."
                    } else {
                        "Load Patch Set..."
                    };
                    load_patch_set_requested = ui
                        .add_enabled(
                            !patch_set_busy
                                && !self.worker_disconnected
                                && !self.project_operation.is_pending()
                                && self.project.is_some(),
                            egui::Button::new(load_label),
                        )
                        .on_disabled_hover_text(
                            "Loading replaces drafts only after strict schema, source identity, edit, and overlap validation succeeds.",
                        )
                        .clicked();
                });
                ui.small(format!(
                    "Patch sets use strict schema v1 JSON and the required *{STATIC_PATCH_SET_SUFFIX} suffix. They contain requests, never file offsets or assembly text."
                ));
                if let Some(result) = &self.patch_set_result {
                    match result {
                        Ok(message) => {
                            ui.colored_label(colors.healthy, format!("[PATCH SET] {message}"));
                        }
                        Err(error) => {
                            ui.colored_label(
                                colors.destructive_quarantined,
                                format!("[PATCH SET FAILED] {error}"),
                            );
                        }
                    }
                }
                ui.separator();
                let can_publish = !patch_set_busy
                    && !self.worker_disconnected
                    && !self.project_operation.is_pending()
                    && exact_source_ready
                    && !self.pending_static_patch_drafts.drafts().is_empty();
                let publish_label = if static_publication_pending {
                    "Publishing patched binary..."
                } else if patch_set_load_pending {
                    "Loading patch set..."
                } else if publication_pending {
                    "Another file publication is running..."
                } else {
                    "Create New Patched Binary..."
                };
                let publish = ui
                    .add_enabled(can_publish, egui::Button::new(publish_label))
                    .on_disabled_hover_text(if publication_pending {
                        "A worker-owned create-new file publication is already running."
                    } else if !exact_source_ready {
                        "Verify the exact source binary before publishing static edits."
                    } else if self.pending_static_patch_drafts.drafts().is_empty() {
                        "Queue at least one exact instruction edit first."
                    } else {
                        "The application-service worker is unavailable or busy with the project."
                    });
                publish_requested = publish.clicked();
                if patch_set_busy {
                    ui.spinner();
                }
                ui.label(
                    RichText::new(
                        "Publication revalidates the exact source identity and expected bytes, creates a new file without replacing source or destination, then reopens and hashes that destination before issuing a receipt.",
                    )
                    .small()
                    .color(colors.secondary_text),
                );
                if let Some(result) = &self.static_patch_result {
                    ui.separator();
                    match result {
                        Ok(outcome) => {
                            ui.colored_label(
                                colors.healthy,
                                format!("[CREATED] {}", outcome.path().display()),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "Output SHA-256 {}",
                                    outcome.output_identity().id.as_str()
                                ))
                                .monospace()
                                .small()
                                .color(colors.exact_extracted),
                            );
                            ui.colored_label(
                                colors.healthy,
                                "[REOPEN VERIFIED] Destination size and SHA-256 match the receipt",
                            );
                            let durability_color = if outcome
                                .durability()
                                .is_fully_synchronized()
                            {
                                colors.healthy
                            } else {
                                colors.warning_conflict
                            };
                            let durability_cue = if outcome
                                .durability()
                                .is_fully_synchronized()
                            {
                                "DURABLE"
                            } else {
                                "DURABILITY WARNING"
                            };
                            ui.colored_label(
                                durability_color,
                                format!("[{durability_cue}] {}", outcome.durability()),
                            );
                            for warning in outcome.warnings() {
                                ui.colored_label(
                                    colors.warning_conflict,
                                    format!("[INTEGRITY WARNING] {warning}"),
                                );
                            }
                        }
                        Err(error) => {
                            ui.colored_label(
                                colors.destructive_quarantined,
                                format!("[PUBLICATION FAILED] {error}"),
                            );
                        }
                    }
                }
            });
        if let Some(rva) = remove_rva {
            let _ = self.pending_static_patch_drafts.remove(rva);
            self.static_patch_result = None;
            self.patch_set_result = None;
        }
        if clear_all {
            self.pending_static_patch_drafts.clear();
            self.static_patch_result = None;
            self.patch_set_result = None;
        }
        if save_patch_set_requested {
            if let Some(path) = self.choose_static_patch_set_save_destination() {
                if let Err(error) = self.queue_static_patch_set_save(path) {
                    self.patch_set_result = Some(Err(error.clone()));
                    self.log(
                        ActivityLevel::Error,
                        format!("Patch-set save failed: {error}"),
                    );
                }
            }
        }
        if load_patch_set_requested {
            if let Some(path) = self.choose_static_patch_set_to_load() {
                if let Err(error) = self.queue_static_patch_set_load(path) {
                    self.patch_set_result = Some(Err(error.clone()));
                    self.log(
                        ActivityLevel::Error,
                        format!("Patch-set load failed: {error}"),
                    );
                }
            }
        }
        if publish_requested {
            if let Some(path) = self.choose_static_patch_destination() {
                if let Err(error) = self.queue_static_patch_publication(path) {
                    self.static_patch_result = Some(Err(error.clone()));
                    self.log(
                        ActivityLevel::Error,
                        format!("Static patch publication failed: {error}"),
                    );
                }
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
                let search_width = (ui.available_width() * 0.42).clamp(150.0, 300.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Search").strong());
                    let search = ui.add(
                        TextEdit::singleline(&mut self.function_filter.search)
                            .id_salt("function_search")
                            .desired_width(search_width)
                            .hint_text("name, RVA, status, or source"),
                    );
                    if self.function_search_focus_requested {
                        search.request_focus();
                        self.function_search_focus_requested = false;
                    }
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
                ui.small(
                    "Keyboard: Ctrl+F searches; Up/Down, Page Up/Page Down, Home, and End navigate rows; Ctrl+Tab changes view.",
                );
            });

        let visible = project.visible_function_indices(&self.function_filter, self.function_sort);
        let visible_projection_indices = visible
            .iter()
            .map(|index| project.functions[*index].projection_index)
            .collect::<Vec<_>>();
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
        let table_layout = function_table_layout(ui.available_width());
        if table_layout.horizontal_overflow {
            ui.small("Scroll horizontally to review all six Function columns.");
        }
        let available_height = ui.available_height();
        let viewport_width = ui.available_width();
        let focus_target = self.function_row_focus_target;
        let scroll_to_row = focus_target.and_then(|target| {
            visible_projection_indices
                .iter()
                .position(|projection_index| *projection_index == target)
        });
        let mut focused_row_id = self
            .function_focused_row_id
            .filter(|id| ui.memory(|memory| memory.has_focus(*id)));
        ScrollArea::horizontal()
            .id_salt("function_results_horizontal")
            .auto_shrink([false, false])
            .max_height(available_height)
            .scroll_bar_visibility(if table_layout.horizontal_overflow {
                egui::scroll_area::ScrollBarVisibility::AlwaysVisible
            } else {
                egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded
            })
            .show(ui, |ui| {
                ui.set_width(table_layout.content_width().max(viewport_width));
                let body_height = (ui.available_height() - 30.0).max(28.0);
                let mut table = TableBuilder::new(ui)
                    .id_salt("function_results")
                    .striped(true)
                    .sense(Sense::click())
                    .min_scrolled_height(body_height)
                    .max_scroll_height(body_height)
                    .column(Column::exact(table_layout.widths[0]))
                    .column(Column::exact(table_layout.widths[1]))
                    .column(Column::exact(table_layout.widths[2]))
                    .column(Column::exact(table_layout.widths[3]))
                    .column(Column::exact(table_layout.widths[4]))
                    .column(Column::exact(table_layout.widths[5]));
                if let Some(row) = scroll_to_row {
                    table = table.scroll_to_row(row, Some(Align::Center));
                }
                table
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
                        header.col(|ui| {
                            sort_header(ui, "Source", FunctionSortKey::Source, &mut sort)
                        });
                        header.col(|ui| sort_header(ui, "Size", FunctionSortKey::Size, &mut sort));
                    })
                    .body(|body| {
                        body.rows(28.0, visible.len(), |mut table_row| {
                            let visible_index = table_row.index();
                            let row_index = visible[visible_index];
                            let row = &project.functions[row_index];
                            let is_selected =
                                self.selected_projection_index == Some(row.projection_index);
                            table_row.set_selected(is_selected);
                            table_row.col(|ui| {
                                status_badge(ui, row.status, colors);
                            });
                            table_row.col(|ui| {
                                ui.label(RichText::new(format!("0x{:08X}", row.rva)).monospace());
                            });
                            table_row.col(|ui| {
                                ui.add(
                                    egui::Label::new(RichText::new(&row.display_name).monospace())
                                        .truncate(),
                                )
                                .on_hover_text(&row.display_name);
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
                                    RichText::new(row.size.map_or_else(
                                        || "--".to_owned(),
                                        |size| format!("0x{size:X}"),
                                    ))
                                    .monospace(),
                                );
                            });

                            let row_response = table_row.response().on_hover_text(
                                "Select this function and update the evidence inspector",
                            );
                            let accessible_label = function_row_accessible_label(
                                row,
                                visible_index + 1,
                                visible.len(),
                                is_selected,
                            );
                            row_response.widget_info(|| {
                                egui::WidgetInfo::selected(
                                    egui::WidgetType::SelectableLabel,
                                    true,
                                    is_selected,
                                    &accessible_label,
                                )
                            });
                            if focus_target == Some(row.projection_index) {
                                row_response.request_focus();
                            }
                            if row_response.clicked() {
                                row_response.request_focus();
                                selected = Some(row.projection_index);
                            }
                            if row_response.has_focus() {
                                focused_row_id = Some(row_response.id);
                                row_response
                                    .ctx
                                    .layer_painter(row_response.layer_id)
                                    .with_clip_rect(row_response.interact_rect)
                                    .rect_stroke(
                                        row_response.rect.shrink(1.0),
                                        1,
                                        egui::Stroke::new(2.0, colors.focus),
                                        egui::StrokeKind::Inside,
                                    );
                            }
                        });
                    });
            });
        self.function_sort = sort;
        self.function_row_focus_target = None;
        self.function_focused_row_id = focused_row_id;
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
                                    let available = kind
                                        .unavailable_reason(&project.identity.format)
                                        .is_none();
                                    ui.add_enabled_ui(available, |ui| {
                                        ui.selectable_value(
                                            &mut self.export_kind,
                                            kind,
                                            kind.label(),
                                        );
                                    });
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
            let format_unavailable = self
                .export_kind
                .unavailable_reason(&project.identity.format);
            let can_export = !self.publication_operation.is_pending()
                && !self.patch_set_load_operation.is_pending()
                && !self.project_operation.is_pending()
                && !self.review_operation.is_pending()
                && format_unavailable.is_none()
                && (self.export_kind != ExportKind::Pdb || exact_source_ready);
            let action_label = if self
                .publication_operation
                .is_kind(PublicationKind::Export)
            {
                "Exporting...".to_owned()
            } else if self.publication_operation.is_pending() {
                "Another file publication is running...".to_owned()
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
            if let Some(reason) = format_unavailable {
                ui.label(
                    RichText::new(format!("[UNAVAILABLE] {reason}"))
                        .color(colors.warning_conflict),
                );
            } else if self.export_kind == ExportKind::Pdb && !exact_source_ready {
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
        self.show_binary_drop_target(context);
        #[cfg(feature = "screenshot")]
        self.show_screenshot_scenario_overlay(context);
        self.show_binary_switch_confirmation(context);
        self.show_close_confirmation(context);

        #[cfg(feature = "screenshot")]
        self.advance_screenshot_capture(context);
        if !cfg!(feature = "screenshot")
            && (self.project_operation.is_pending()
                || self.publication_operation.is_pending()
                || self.patch_set_load_operation.is_pending()
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

fn show_plugin(ui: &mut egui::Ui, plugin: &PluginCatalogEntry, colors: SemanticColors) {
    let color = match plugin.artifact_policy {
        PluginArtifactPolicyStatus::Sandboxed | PluginArtifactPolicyStatus::Trusted => {
            colors.healthy
        }
        PluginArtifactPolicyStatus::ApprovalRequired => colors.warning_conflict,
        PluginArtifactPolicyStatus::Disabled => colors.fallback,
        PluginArtifactPolicyStatus::Quarantined | PluginArtifactPolicyStatus::CorruptState => {
            colors.destructive_quarantined
        }
        PluginArtifactPolicyStatus::Unavailable => colors.warning_conflict,
    };
    let name = plugin
        .name
        .as_ref()
        .map_or_else(|| plugin.path.display().to_string(), |name| name.clone());
    ui.collapsing(
        RichText::new(format!("[{}] {name}", plugin.artifact_policy.badge_label())).color(color),
        |ui| {
            ui.label(format!("Source: {}", plugin.source));
            if let Some(id) = &plugin.id {
                ui.label(format!("ID: {id}"));
            }
            if let Some(version) = &plugin.version {
                ui.label(format!("Version: {version}"));
            }
            if let Some(description) = &plugin.description {
                ui.label(description);
            }
            ui.label(format!("Discovery health: {}", plugin.health));
            ui.label(format!(
                "Discovery loadable: {}",
                if plugin.loadable { "yes" } else { "no" }
            ));
            ui.label(format!(
                "Exact-artifact policy: {}",
                if plugin.artifact_policy.allows_by_artifact_policy() {
                    "passes"
                } else {
                    "blocked"
                }
            ));
            ui.label("Full CLI execution eligibility: not evaluated");
            ui.label("Workbench execution: not supported");
            if let Some(runtime) = &plugin.runtime {
                ui.label(format!("Runtime: {runtime}"));
            }
            if !plugin.capabilities.is_empty() {
                ui.label(format!(
                    "Declared capabilities: {}",
                    plugin.capabilities.join(", ")
                ));
            }
            if !plugin.permissions.is_empty() {
                ui.label(format!(
                    "Requested permissions: {}",
                    plugin.permissions.join(", ")
                ));
            }
            ui.label(format!("Path: {}", plugin.path.display()));
            if let Some(fingerprint) = &plugin.artifact_fingerprint {
                ui.label("Exact artifact SHA-256:");
                ui.monospace(fingerprint);
            } else {
                ui.label("Exact artifact SHA-256: unavailable");
            }
            for diagnostic in &plugin.diagnostics {
                ui.label(diagnostic);
            }
            if plugin.diagnostics.is_empty() {
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
    ui.add(egui::Label::new(RichText::new(&text).color(status_color(status, colors))).truncate())
        .on_hover_text(text)
}

fn function_row_accessible_label(
    row: &FunctionRow,
    visible_row: usize,
    visible_count: usize,
    is_selected: bool,
) -> String {
    let confidence = row.confidence.map_or_else(
        || "unavailable".to_owned(),
        |value| format!("{:.0} percent", value * 100.0),
    );
    let size = row
        .size
        .map_or_else(|| "unavailable".to_owned(), |value| format!("0x{value:X}"));
    format!(
        "Function {visible_row} of {visible_count}: {}; RVA 0x{:08X}; status {}; confidence {confidence}; source {}; size {size}; selected {}",
        row.display_name,
        row.rva,
        row.status.label(),
        row.source,
        if is_selected { "yes" } else { "no" },
    )
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
        StaticRegionKind::LoadSegment {
            program_header_index,
            ..
        } => format!("PH#{program_header_index} PT_LOAD"),
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

fn format_instruction_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn instruction_row_accessible_label(
    row: &LinearInstructionRow,
    index: usize,
    row_count: usize,
) -> String {
    let direct_target = row.direct_target_rva().map_or_else(
        || "no direct target".to_owned(),
        |target| format!("direct target RVA 0x{target:016X}"),
    );
    format!(
        "Linear disassembly instruction {} of {}: RVA 0x{:016X}; bytes {}; {}; flow {}; {}; length {}",
        index + 1,
        row_count,
        row.rva(),
        format_instruction_bytes(row.bytes()),
        row.text(),
        row.flow_control().label(),
        direct_target,
        row.length()
    )
}

fn protocol_route_text(route: &LiveDebuggerProtocolRoute) -> String {
    match route {
        LiveDebuggerProtocolRoute::WriteMemoryCompareBeforeWrite {
            expected,
            replacement,
        } => format!(
            "DebugCommand::WriteMemory compare-before-write ({} exact expected byte(s), {} replacement byte(s))",
            expected.len(),
            replacement.len()
        ),
        LiveDebuggerProtocolRoute::SetBreakpoint {
            kind,
            temporary,
            continue_after_set,
        } => format!(
            "DebugCommand::SetBreakpoint ({kind:?}, temporary={temporary}){}",
            if *continue_after_set {
                " then DebugCommand::Continue"
            } else {
                ""
            }
        ),
        LiveDebuggerProtocolRoute::Step { kind } => {
            format!("DebugCommand::Step {{ kind: {kind:?} }}")
        }
        LiveDebuggerProtocolRoute::Continue => "DebugCommand::Continue".to_owned(),
    }
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

fn offline_pipeline_failure_text(stage: &str, detail: &str) -> String {
    format!("[PIPELINE:{stage}] {detail}")
}

fn offline_read_failure_text(error: &OfflineImageReadFailure) -> String {
    match error {
        OfflineImageReadFailure::Pipeline(failure) => {
            offline_pipeline_failure_text(failure.stage(), failure.detail())
        }
        _ => error.to_string(),
    }
}

fn lifecycle_flag(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn offline_lifecycle_status(
    complete: bool,
    capability_count: usize,
    session_opened: bool,
    session_closed: bool,
    session_released: bool,
    control_disconnected: bool,
) -> String {
    let status = if complete {
        "Lifecycle complete"
    } else {
        "Lifecycle incomplete; result is not safe to present"
    };
    format!(
        "{status}: {capability_count} capabilities probed | opened={} | closed={} | released={} | disconnected={}",
        lifecycle_flag(session_opened),
        lifecycle_flag(session_closed),
        lifecycle_flag(session_released),
        lifecycle_flag(control_disconnected),
    )
}

fn offline_lifecycle_text(outcome: &OfflineImageReadOutcome) -> String {
    let lifecycle = outcome.lifecycle();
    format!(
        "Session {} | {}",
        lifecycle.session_id().get(),
        offline_lifecycle_status(
            lifecycle.is_complete(),
            lifecycle.capability_count(),
            lifecycle.session_opened(),
            lifecycle.session_closed(),
            lifecycle.session_released(),
            lifecycle.control_disconnected(),
        )
    )
}

fn offline_binding_text(outcome: &OfflineImageReadOutcome) -> String {
    let binding = outcome.binding();
    format!(
        "Exact source {} | {} byte span at RVA 0x{:X} | {}",
        short_hash(binding.identity().id.as_str()),
        outcome.span().size(),
        outcome.span().rva(),
        binding.source_path().display(),
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

const fn binary_picker_filter_specs(
    purpose: BinaryPickerPurpose,
) -> &'static [BinaryPickerFilterSpec] {
    match purpose {
        BinaryPickerPurpose::OpenBinaryOrPackage => OPEN_BINARY_OR_PACKAGE_FILTERS,
        BinaryPickerPurpose::VerifyExactBinary => VERIFY_EXACT_BINARY_FILTERS,
    }
}

fn binary_picker_dialog(title: &str, purpose: BinaryPickerPurpose) -> rfd::FileDialog {
    binary_picker_filter_specs(purpose)
        .iter()
        .fold(rfd::FileDialog::new().set_title(title), |dialog, filter| {
            dialog.add_filter(filter.label, filter.extensions)
        })
}

fn is_package_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("resym"))
}

fn is_static_patch_set_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(STATIC_PATCH_SET_SUFFIX))
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

fn default_static_patch_path(project: &LoadedProject) -> Option<PathBuf> {
    let source = project.snapshot.verified_source_path()?;
    let digest = project.identity.sha256.as_str();
    let stem = source
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map_or_else(|| format!("resymbol_{}", &digest[..12]), ToOwned::to_owned);
    let file_name = source
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map_or_else(
            || format!("{stem}-patched"),
            |extension| format!("{stem}-patched.{extension}"),
        );
    let mut path = source.to_path_buf();
    path.set_file_name(file_name);
    Some(path)
}

fn default_static_patch_set_path(project: &LoadedProject) -> PathBuf {
    let digest = project.identity.sha256.as_str();
    let source = project.identity.active_binary_path();
    let stem = source
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map_or_else(|| format!("resymbol_{}", &digest[..12]), ToOwned::to_owned);
    let mut path = source.to_path_buf();
    path.set_file_name(format!("{stem}{STATIC_PATCH_SET_SUFFIX}"));
    path
}

fn patch_set_outcome_message(action: &str, outcome: &PatchSetOutcome) -> String {
    let identity = outcome.manifest.source_identity();
    format!(
        "{action} patch set {} with {} edit(s) for exact source SHA-256 {}, size {}, format {:?}, architecture {}, image base 0x{:X}",
        outcome.path.display(),
        outcome.manifest.edit_count(),
        identity.id.as_str(),
        identity.size,
        &identity.format,
        identity.architecture.as_str(),
        identity.image_base
    )
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

fn push_recent_binary(recent_binaries: &mut Vec<PathBuf>, path: PathBuf) {
    recent_binaries.retain(|existing| existing != &path);
    recent_binaries.insert(0, path);
    recent_binaries.truncate(MAX_RECENT_BINARIES);
}

fn normalize_recent_binaries(recent_binaries: &mut Vec<PathBuf>) {
    let mut normalized = Vec::with_capacity(recent_binaries.len().min(MAX_RECENT_BINARIES));
    for path in recent_binaries.drain(..) {
        if normalized.contains(&path) {
            continue;
        }
        normalized.push(path);
        if normalized.len() == MAX_RECENT_BINARIES {
            break;
        }
    }
    *recent_binaries = normalized;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write as _, path::Path};

    use resymbol_app::{AppServices, StaticPatchPlan, StaticPatchSetManifest};
    use resymbol_core::{
        ClaimProducer, ClaimProvenance, Confidence, Evidence, EvidenceKind, SymbolAssertion,
        SymbolClaim, SymbolSubject,
    };
    use tempfile::NamedTempFile;

    const STRIPPED_FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");
    const SYMBOLIZED_FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-symbolized.exe");
    const THUNK_RVA: u32 = 0x1184;
    const THUNK_BYTES: [u8; 5] = [0xe9, 0x03, 0x00, 0x00, 0x00];

    fn loaded_project_with_source() -> (NamedTempFile, LoadedProject) {
        loaded_project_with_bytes(STRIPPED_FIXTURE)
    }

    fn loaded_project_with_bytes(bytes: &[u8]) -> (NamedTempFile, LoadedProject) {
        let mut source = NamedTempFile::new().expect("temporary PE");
        source.write_all(bytes).expect("write PE");
        let snapshot = AppServices::default()
            .analyze_binary(source.path())
            .expect("analyze PE");
        let project = LoadedProject::from_snapshot(snapshot).expect("loaded project");
        (source, project)
    }

    #[test]
    fn pe_only_exports_are_disabled_for_elf_projects() {
        for kind in [ExportKind::Map, ExportKind::Pdb] {
            assert!(kind.unavailable_reason(&ExportBinaryFormat::Elf).is_some());
            assert!(kind.unavailable_reason(&ExportBinaryFormat::Pe).is_none());
        }
        for kind in [
            ExportKind::Package,
            ExportKind::NeutralJson,
            ExportKind::Markdown,
            ExportKind::IdaPython,
            ExportKind::GhidraJava,
        ] {
            assert!(kind.unavailable_reason(&ExportBinaryFormat::Elf).is_none());
        }
    }

    fn publish_test_patch(project: &LoadedProject, output: &Path) -> PublishedStaticPatch {
        let request = StaticPatchEditRequest::nop_instruction(
            THUNK_RVA,
            THUNK_BYTES,
            "Disable internal jump thunk",
        )
        .expect("valid exact instruction request");
        let analysis = project.session().base_analysis();
        let plan = StaticPatchPlan::new(analysis.identity(), analysis, vec![request])
            .expect("valid fixture patch plan");
        AppServices::default()
            .publish_static_patch_new(&project.snapshot, &plan, output)
            .expect("publish fixture patch")
    }

    fn patch_set_outcome(project: &LoadedProject, path: PathBuf) -> PatchSetOutcome {
        let request =
            StaticPatchEditRequest::nop_instruction(THUNK_RVA, THUNK_BYTES, "Loaded patch-set NOP")
                .expect("valid patch-set request");
        let analysis = project.session().base_analysis();
        let manifest = StaticPatchSetManifest::new(analysis.identity(), analysis, vec![request])
            .expect("valid patch-set manifest");
        PatchSetOutcome { path, manifest }
    }

    fn test_app() -> (egui::Context, WorkbenchApp) {
        let context = egui::Context::default();
        let creation_context = eframe::CreationContext::_new_kittest(context.clone());
        let app = WorkbenchApp::new_with_startup(&creation_context, None);
        (context, app)
    }

    fn review_subject(project: &LoadedProject, name: &str) -> ReviewSubject {
        let row = project.functions.first().expect("projected function");
        let claim = SymbolClaim::new(
            SymbolSubject::Function {
                binary: project.identity.sha256.clone(),
                rva: row.rva,
                size: None,
            },
            SymbolAssertion::Name {
                name: name.to_owned(),
            },
            Confidence::new(0.75).expect("confidence"),
            vec![
                Evidence::new(
                    EvidenceKind::new(EvidenceKind::MODEL_INFERENCE).expect("evidence kind"),
                    "workbench state-transition fixture",
                )
                .expect("evidence"),
            ],
            ClaimProvenance {
                producer: ClaimProducer::User {
                    reviewer: Some("workbench-test".to_owned()),
                },
                method: "workbench.state-transition-fixture".to_owned(),
                run_id: None,
            },
        )
        .expect("name claim");
        ReviewSubject::from_name_claim(&claim).expect("review subject")
    }

    #[test]
    fn screenshot_scenario_names_are_stable_and_complete() {
        let scenarios = [
            ScreenshotScenario::OpenEmpty,
            ScreenshotScenario::Overview,
            ScreenshotScenario::Functions,
            ScreenshotScenario::FunctionsFocused,
            ScreenshotScenario::Graph,
            ScreenshotScenario::AddressSpace,
            ScreenshotScenario::Disassembly,
            ScreenshotScenario::DisassemblyActions,
            ScreenshotScenario::BinarySwitchConfirmation,
            ScreenshotScenario::DebuggerSandbox,
            ScreenshotScenario::DebuggerReadinessResult,
            ScreenshotScenario::Exports,
        ];
        for scenario in scenarios {
            assert_eq!(ScreenshotScenario::parse(scenario.name()), Some(scenario));
        }
        assert!(ScreenshotScenario::parse("unknown-scenario").is_none());
        assert!(ScreenshotScenario::DisassemblyActions.needs_offline_read());
        assert!(ScreenshotScenario::DebuggerReadinessResult.needs_readiness_result());
        assert!(!ScreenshotScenario::OpenEmpty.needs_offline_read());
    }

    #[test]
    fn screenshot_fixture_retains_the_canonical_conditional_branch() {
        let (_source, project) = loaded_project_with_bytes(SYMBOLIZED_FIXTURE);
        let address = RelativeAddress::new(SCREENSHOT_CANONICAL_JCC_RVA);
        let region = project
            .static_address_space
            .as_ref()
            .expect("PE screenshot fixture has a static address space")
            .region_at(address)
            .expect("capture Jcc is mapped");
        let file_offset = usize::try_from(
            region
                .file_offset_at(address)
                .expect("capture Jcc is file backed"),
        )
        .expect("capture Jcc offset fits usize");
        let read_size = usize::try_from(SCREENSHOT_CANONICAL_JCC_READ_BYTES)
            .expect("capture read size fits usize");
        let bytes = &SYMBOLIZED_FIXTURE[file_offset..file_offset + read_size];
        let preview = disassemble_x64_linear(
            bytes,
            SCREENSHOT_CANONICAL_JCC_RVA,
            LinearDisassemblyLimits::new(read_size, OFFLINE_DISASSEMBLY_INSTRUCTION_LIMIT)
                .expect("capture disassembly limits"),
        );
        let row = preview.rows().first().expect("capture Jcc row");

        assert_eq!(row.rva(), SCREENSHOT_CANONICAL_JCC_RVA);
        assert_eq!(row.bytes(), &[0x74, 0x0A]);
        assert!(
            ConditionalBranchPatch::InvertCondition
                .replacement(row.bytes())
                .is_some()
        );
        assert!(
            ConditionalBranchPatch::AlwaysTaken
                .replacement(row.bytes())
                .is_some()
        );
    }

    #[test]
    fn dirty_close_requires_an_explicit_discard() {
        assert!(close_requires_confirmation(true, false));
        assert!(!close_requires_confirmation(false, false));
        assert!(!close_requires_confirmation(true, true));
    }

    #[test]
    fn project_picker_covers_supported_and_extensionless_containers() {
        let filters = binary_picker_filter_specs(BinaryPickerPurpose::OpenBinaryOrPackage);

        assert_eq!(filters.len(), 4);
        assert_eq!(filters[0].label, "PE containers");
        assert_eq!(
            filters[0].extensions,
            &["exe", "dll", "sys", "cpl", "ocx", "scr", "efi"]
        );
        assert_eq!(
            filters[1],
            BinaryPickerFilterSpec {
                label: "ELF containers",
                extensions: &["elf", "axf"],
            }
        );
        assert_eq!(
            filters[2],
            BinaryPickerFilterSpec {
                label: "ReSymbol packages",
                extensions: &["resym"],
            }
        );
        assert_eq!(filters[3].extensions, &["*"]);
        assert!(filters[3].label.contains("extensionless"));
    }

    #[test]
    fn exact_source_picker_keeps_packages_out_of_the_binary_filter_set() {
        let filters = binary_picker_filter_specs(BinaryPickerPurpose::VerifyExactBinary);

        assert_eq!(filters.len(), 3);
        assert_eq!(filters[0].label, "PE containers");
        assert_eq!(filters[1].label, "ELF containers");
        assert_eq!(filters[2].extensions, &["*"]);
        assert!(filters.iter().all(|filter| {
            !filter
                .extensions
                .iter()
                .any(|extension| extension.eq_ignore_ascii_case("resym"))
        }));
    }

    #[test]
    fn resymbol_package_routing_remains_explicit_and_case_insensitive() {
        assert!(is_package_path(Path::new("saved-project.resym")));
        assert!(is_package_path(Path::new("SAVED-PROJECT.RESYM")));
        assert!(!is_package_path(Path::new("extensionless-pe")));
        assert!(!is_package_path(Path::new("control-panel.cpl")));
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
    fn recent_binaries_are_newest_first_deduplicated_and_bounded() {
        let mut recent = Vec::new();
        for index in 0..(MAX_RECENT_BINARIES + 2) {
            push_recent_binary(&mut recent, PathBuf::from(format!("binary-{index}.exe")));
        }
        assert_eq!(recent.len(), MAX_RECENT_BINARIES);
        assert_eq!(recent[0], PathBuf::from("binary-9.exe"));
        assert_eq!(
            recent[MAX_RECENT_BINARIES - 1],
            PathBuf::from("binary-2.exe")
        );

        push_recent_binary(&mut recent, PathBuf::from("binary-5.exe"));
        assert_eq!(recent[0], PathBuf::from("binary-5.exe"));
        assert_eq!(
            recent
                .iter()
                .filter(|path| path.as_path() == Path::new("binary-5.exe"))
                .count(),
            1
        );
    }

    #[test]
    fn plugin_catalog_accepts_only_current_refresh_across_project_acceptance() {
        let (_context, mut app) = test_app();
        let temporary = tempfile::tempdir().expect("temporary plugin root");
        let catalog = resymbol_app::AppServices::default()
            .inspect_plugin_catalog(temporary.path())
            .expect("empty plugin catalog");
        app.plugin_operation.invalidate();
        app.plugin_catalog = None;
        let stale = app.operation_sequence.issue();
        let current = app.operation_sequence.issue();
        app.plugin_operation.begin(current);

        let (source, project) = loaded_project_with_source();
        app.analysis_path = Some(source.path().to_path_buf());
        app.accept_project(project, ProjectAcceptance::NewProject);
        assert!(
            app.plugin_operation.is_pending(),
            "project-independent catalog refresh remains current"
        );

        assert!(!app.accept_plugin_catalog(stale, Ok(catalog.clone())));
        assert!(app.plugin_catalog.is_none());
        assert!(app.plugin_operation.is_pending());

        assert!(app.accept_plugin_catalog(current, Ok(catalog)));
        assert!(!app.plugin_operation.is_pending());
        let accepted = app
            .plugin_catalog
            .as_ref()
            .expect("accepted snapshot")
            .as_ref()
            .expect("successful snapshot");
        assert_eq!(accepted.root(), temporary.path());
    }

    #[test]
    fn plugin_policy_badges_are_explicit_and_unambiguous() {
        for (eligibility, badge) in [
            (PluginArtifactPolicyStatus::Sandboxed, "SANDBOXED"),
            (PluginArtifactPolicyStatus::Trusted, "TRUSTED"),
            (
                PluginArtifactPolicyStatus::ApprovalRequired,
                "APPROVAL REQUIRED",
            ),
            (PluginArtifactPolicyStatus::Disabled, "DISABLED"),
            (PluginArtifactPolicyStatus::Quarantined, "QUARANTINED"),
            (PluginArtifactPolicyStatus::CorruptState, "CORRUPT STATE"),
            (PluginArtifactPolicyStatus::Unavailable, "UNAVAILABLE"),
        ] {
            assert_eq!(eligibility.badge_label(), badge);
        }
    }

    #[test]
    fn persisted_recent_binaries_are_normalized_before_use() {
        let persisted = serde_json::json!({
            "recent_binaries": [
                "binary-0.exe",
                "binary-1.exe",
                "binary-2.exe",
                "binary-2.exe",
                "binary-3.exe",
                "binary-4.exe",
                "binary-5.exe",
                "binary-6.exe",
                "binary-7.exe",
                "binary-8.exe",
                "binary-9.exe"
            ]
        });
        let mut preferences: Preferences =
            serde_json::from_value(persisted).expect("persisted preferences");

        preferences.normalize();

        assert_eq!(preferences.recent_binaries.len(), MAX_RECENT_BINARIES);
        assert_eq!(
            preferences.recent_binaries[0],
            PathBuf::from("binary-0.exe")
        );
        assert_eq!(
            preferences.recent_binaries[2],
            PathBuf::from("binary-2.exe")
        );
        assert_eq!(
            preferences.recent_binaries[7],
            PathBuf::from("binary-7.exe")
        );
        assert_eq!(
            preferences
                .recent_binaries
                .iter()
                .filter(|path| path.as_path() == Path::new("binary-2.exe"))
                .count(),
            1
        );
    }

    #[test]
    fn failed_replacement_preserves_project_dirty_review_and_recents() {
        let (_context, mut app) = test_app();
        let (source, project) = loaded_project_with_source();
        app.analysis_path = Some(source.path().to_path_buf());
        app.finish_project_open(Ok(project));

        let subject = review_subject(app.project.as_ref().expect("active project"), "candidate");
        app.review
            .as_mut()
            .expect("bound review")
            .apply_disposition(&subject, DecisionAction::Reject, "", "")
            .expect("dirty review");
        let prior_identity = app
            .project
            .as_ref()
            .expect("active project")
            .identity
            .clone();
        let prior_analysis_path = app.analysis_path.clone();
        let prior_ledger = app.review.as_ref().expect("bound review").ledger().clone();
        let prior_recents = app.preferences.recent_binaries.clone();

        app.main_tab = MainTab::Exports;
        app.analysis_path = Some(PathBuf::from("replacement-that-failed.exe"));
        app.stage = WorkflowStage::Analyze;
        app.finish_project_open(Err("deterministic replacement failure".to_owned()));

        assert_eq!(
            app.project.as_ref().expect("project retained").identity,
            prior_identity
        );
        let retained_review = app.review.as_ref().expect("review retained");
        assert!(retained_review.is_dirty());
        assert_eq!(retained_review.ledger(), &prior_ledger);
        assert_eq!(app.preferences.recent_binaries, prior_recents);
        assert_eq!(app.analysis_path, prior_analysis_path);
        assert_eq!(app.main_tab, MainTab::Exports);
        assert_eq!(app.stage, WorkflowStage::Export);
    }

    #[test]
    fn initial_open_failure_returns_to_a_genuinely_empty_open_state() {
        let (_context, mut app) = test_app();
        app.analysis_path = Some(PathBuf::from("initial-open-that-failed.exe"));
        app.stage = WorkflowStage::Analyze;

        app.finish_project_open(Err("deterministic initial failure".to_owned()));

        assert!(app.project.is_none());
        assert!(app.analysis_path.is_none());
        assert_eq!(app.stage, WorkflowStage::Open);
    }

    #[test]
    fn worker_disconnect_during_replacement_restores_retained_project_chrome() {
        let (_context, mut app) = test_app();
        let (source, project) = loaded_project_with_source();
        app.analysis_path = Some(source.path().to_path_buf());
        app.finish_project_open(Ok(project));
        let prior_path = app.analysis_path.clone();
        let operation = app.operation_sequence.issue();
        app.project_operation.begin(operation);
        app.main_tab = MainTab::Exports;
        app.analysis_path = Some(PathBuf::from("replacement-interrupted.exe"));
        app.stage = WorkflowStage::Analyze;

        app.handle_worker_disconnect("deterministic worker disconnect".to_owned());

        assert!(app.worker_disconnected);
        assert!(!app.project_operation.is_pending());
        assert_eq!(app.analysis_path, prior_path);
        assert_eq!(app.main_tab, MainTab::Exports);
        assert_eq!(app.stage, WorkflowStage::Export);
    }

    #[test]
    fn only_successful_project_acceptance_adds_a_recent_binary() {
        let (_context, mut app) = test_app();
        app.analysis_path = Some(PathBuf::from("failed.exe"));

        app.finish_project_open(Err("open failed".to_owned()));
        assert!(app.preferences.recent_binaries.is_empty());

        let (source, project) = loaded_project_with_source();
        let requested_path = source.path().to_path_buf();
        app.analysis_path = Some(requested_path.clone());
        app.finish_project_open(Ok(project));

        assert_eq!(app.preferences.recent_binaries.len(), 1);
        assert_eq!(
            app.preferences.recent_binaries[0],
            std::fs::canonicalize(&requested_path).unwrap_or(requested_path)
        );
    }

    #[test]
    fn stale_review_snapshot_does_not_initiate_pending_binary_open() {
        let (context, mut app) = test_app();
        let (source, project) = loaded_project_with_source();
        app.analysis_path = Some(source.path().to_path_buf());
        app.finish_project_open(Ok(project));
        let original_analysis_path = app.analysis_path.clone();
        let original_identity = app
            .project
            .as_ref()
            .expect("active project")
            .identity
            .clone();
        let subject = review_subject(app.project.as_ref().expect("active project"), "candidate");
        let review = app.review.as_mut().expect("bound review");
        review
            .apply_disposition(&subject, DecisionAction::AcceptPrimary, "", "")
            .expect("first edit");
        let saved_snapshot = review.ledger().clone();
        review
            .apply_disposition(&subject, DecisionAction::Reject, "", "")
            .expect("newer edit");

        let pending = PathBuf::from("pending-next-binary.exe");
        app.pending_binary_open = Some(pending.clone());
        app.open_after_review_save = true;
        app.finish_review_save(
            &context,
            ReviewSaveOutcome {
                ledger: saved_snapshot,
                path: PathBuf::from("earlier.review.json"),
            },
        );

        assert!(!app.open_after_review_save);
        assert_eq!(app.pending_binary_open, Some(pending));
        assert!(!app.project_operation.is_pending());
        assert_eq!(app.analysis_path, original_analysis_path);
        assert_eq!(
            app.project.as_ref().expect("project retained").identity,
            original_identity
        );
        assert!(app.review.as_ref().expect("review retained").is_dirty());
    }

    #[test]
    fn legacy_preferences_default_to_an_empty_recent_binary_list() {
        let preferences: Preferences = serde_json::from_str("{}").expect("legacy preferences");
        assert!(preferences.recent_binaries.is_empty());
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
    fn function_row_accessibility_label_carries_visible_identity_and_state() {
        let (_source, project) = loaded_project_with_source();
        let row = project.functions.first().expect("projected function");

        let label = function_row_accessible_label(row, 1, project.functions.len(), true);

        assert!(label.starts_with(&format!("Function 1 of {}:", project.functions.len())));
        assert!(label.contains(&row.display_name));
        assert!(label.contains(&format!("RVA 0x{:08X}", row.rva)));
        assert!(label.contains(row.status.label()));
        assert!(label.contains(&row.source));
        assert!(label.ends_with("selected yes"));
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
    fn offline_state_preserves_typed_worker_failures_for_safe_rendering() {
        let (_source, project) = loaded_project_with_source();
        let source = OfflineSourceBinding::from_project(&project).expect("source binding");
        let binding = OfflineReadRequestBinding {
            source: source.clone(),
            span: OfflineImageReadSpan::new(0, 64).expect("span"),
        };
        let operation = OperationSequence::default().issue();
        let mut state = OfflineReadUiState::default();
        state.begin(operation, binding);

        let disposition = state.accept(
            operation,
            Err(OfflineImageReadFailure::VerifiedSourceRequired),
            Some(source),
        );

        assert!(matches!(
            disposition,
            OfflineReadEventDisposition::Failed { .. }
        ));
        assert_eq!(
            state.presentation,
            Some(OfflineReadPresentation::Failure(
                OfflineImageReadFailure::VerifiedSourceRequired
            ))
        );
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
        let capability_count = resymbol_debugger::DebugCapability::ALL.len();
        let lifecycle = offline_lifecycle_status(true, capability_count, true, true, true, true);
        assert_eq!(
            lifecycle,
            format!(
                "Lifecycle complete: {capability_count} capabilities probed | opened=yes | closed=yes | released=yes | disconnected=yes"
            )
        );
        assert_eq!(
            offline_lifecycle_status(false, capability_count, true, false, true, false),
            format!(
                "Lifecycle incomplete; result is not safe to present: {capability_count} capabilities probed | opened=yes | closed=no | released=yes | disconnected=no"
            )
        );
        assert_eq!(
            offline_pipeline_failure_text("offline read", "host rejected the span"),
            "[PIPELINE:offline read] host rejected the span"
        );
        assert_eq!(
            offline_read_failure_text(&OfflineImageReadFailure::VerifiedSourceRequired),
            "the project has no exact identity-verified source snapshot"
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

    #[test]
    fn instruction_presentation_retains_exact_bytes_and_accessible_context() {
        let limits = LinearDisassemblyLimits::new(16, 4).expect("limits");
        let preview = disassemble_x64_linear(&[0x90, 0xC3], 0x1000, limits);
        let row = preview.rows().first().expect("instruction row");

        assert_eq!(format_instruction_bytes(row.bytes()), "90");
        assert_eq!(
            instruction_row_accessible_label(row, 0, preview.rows().len()),
            "Linear disassembly instruction 1 of 2: RVA 0x0000000000001000; bytes 90; nop; flow sequential; no direct target; length 1"
        );
    }

    #[test]
    fn live_route_text_keeps_run_to_cursor_and_nop_composition_explicit() {
        let run_to = LiveInstructionAction::RunToCursor.protocol_route_preview(&[0x90]);
        let live_nop =
            LiveInstructionAction::NopLiveMemory.protocol_route_preview(&[0x48, 0x89, 0xD8]);

        assert_eq!(
            protocol_route_text(&run_to),
            "DebugCommand::SetBreakpoint (Software, temporary=true) then DebugCommand::Continue"
        );
        assert_eq!(
            protocol_route_text(&live_nop),
            "DebugCommand::WriteMemory compare-before-write (3 exact expected byte(s), 3 replacement byte(s))"
        );
    }

    #[test]
    fn direct_target_navigation_requires_readable_exact_file_backing() {
        let (_source, project) = loaded_project_with_source();
        let address_space = project
            .static_address_space
            .as_ref()
            .expect("PE fixture has a static address space");
        let readable_backed = address_space
            .regions()
            .iter()
            .find_map(|region| {
                (region.access.readable
                    && region.file_backing.is_some_and(|backing| backing.size > 0))
                .then(|| region.range.start().get())
            })
            .expect("readable file-backed fixture address");
        let readable_unbacked = address_space
            .regions()
            .iter()
            .find_map(|region| {
                let first_unbacked = region
                    .range
                    .start()
                    .get()
                    .checked_add(region.file_backing.map_or(0, |backing| backing.size))?;
                (region.access.readable && first_unbacked < region.range.end())
                    .then_some(first_unbacked)
            })
            .expect("readable zero-fill or mapped-padding fixture address");
        let preferred_address = address_space.preferred_image_base + readable_backed;
        let (_context, mut app) = test_app();
        app.project = Some(project);

        assert!(app.static_rva_has_readable_file_backing(readable_backed));
        assert!(!app.static_rva_has_readable_file_backing(readable_unbacked));
        assert_eq!(
            app.preferred_static_address(readable_backed),
            Some(preferred_address)
        );
    }

    #[test]
    fn static_nop_ui_gate_requires_an_exact_file_backed_executable_section() {
        let (_source, project) = loaded_project_with_source();
        let address_space = project
            .static_address_space
            .as_ref()
            .expect("PE fixture has a static address space");
        let executable_backed = address_space
            .regions()
            .iter()
            .find(|region| {
                region.access.executable
                    && matches!(&region.kind, StaticRegionKind::Section { .. })
                    && region.file_backing.is_some_and(|backing| backing.size > 0)
            })
            .expect("file-backed executable fixture region")
            .range
            .start()
            .get();
        let non_executable_backed = address_space
            .regions()
            .iter()
            .find(|region| {
                !region.access.executable
                    && region.file_backing.is_some_and(|backing| backing.size > 0)
            })
            .expect("file-backed non-executable fixture region")
            .range
            .start()
            .get();
        let executable = disassemble_x64_linear(
            &[0xCC],
            executable_backed,
            LinearDisassemblyLimits::new(1, 1).expect("limits"),
        );
        let non_executable = disassemble_x64_linear(
            &[0xCC],
            non_executable_backed,
            LinearDisassemblyLimits::new(1, 1).expect("limits"),
        );
        let already_nop = disassemble_x64_linear(
            &[0x90],
            executable_backed,
            LinearDisassemblyLimits::new(1, 1).expect("limits"),
        );
        let (_context, mut app) = test_app();
        app.project = Some(project);

        assert!(app.static_nop_patchability(&executable.rows()[0]).is_ok());
        assert_eq!(
            app.static_nop_patchability(&non_executable.rows()[0]),
            Err("Static instruction edits are limited to executable PE sections.")
        );
        assert_eq!(
            app.static_nop_patchability(&already_nop.rows()[0]),
            Err("The selected instruction is already NOP-filled.")
        );
    }

    #[test]
    fn patched_binary_suggestion_uses_the_verified_source_path() {
        let directory = tempfile::tempdir().expect("temporary source directory");
        let source = directory.path().join("application.exe");
        std::fs::write(&source, STRIPPED_FIXTURE).expect("write exact source fixture");
        let snapshot = AppServices::default()
            .analyze_binary(&source)
            .expect("analyze exact source fixture");
        let project = LoadedProject::from_snapshot(snapshot).expect("loaded project");
        let verified_directory =
            std::fs::canonicalize(directory.path()).expect("canonical temporary source directory");

        assert_eq!(
            default_static_patch_path(&project),
            Some(verified_directory.join("application-patched.exe"))
        );
    }

    #[test]
    fn patch_request_conversion_revalidates_the_exact_instruction_boundary() {
        let (_context, mut app) = test_app();
        app.pending_static_patch_drafts
            .queue_nop(0x1000, &[0xCC, 0xC3], "two instructions")
            .expect("shape-valid bounded draft");
        assert!(
            app.build_static_patch_requests()
                .expect_err("multi-instruction NOP must fail")
                .contains("exactly one complete x86-64 instruction")
        );

        app.pending_static_patch_drafts.clear();
        app.pending_static_patch_drafts
            .queue_nop(0x1000, &[0xCC], "one instruction")
            .expect("shape-valid exact instruction draft");
        assert_eq!(
            app.build_static_patch_requests()
                .expect("single instruction request")
                .len(),
            1
        );

        app.pending_static_patch_drafts.clear();
        app.pending_static_patch_drafts
            .queue_replace(0x1000, &[0x74, 0x05], &[0x75, 0x05], "Invert Jcc")
            .expect("shape-valid branch replacement draft");
        let requests = app
            .build_static_patch_requests()
            .expect("general exact-byte replacement request");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].kind(),
            resymbol_app::StaticPatchKind::ReplaceBytes
        );
        assert_eq!(requests[0].expected(), &[0x74, 0x05]);
        assert_eq!(requests[0].replacement(), &[0x75, 0x05]);
    }

    #[test]
    fn stale_static_publication_result_cannot_clear_the_current_reservation_or_drafts() {
        let (_context, mut app) = test_app();
        app.pending_static_patch_drafts
            .queue_nop(THUNK_RVA.into(), &THUNK_BYTES, "current draft")
            .expect("queue current draft");
        let directory = tempfile::tempdir().expect("temporary publication directory");
        let destination =
            PublicationDestination::resolve(&directory.path().join("current-patch.exe"))
                .expect("canonical destination");
        let stale = app.operation_sequence.issue();
        let current = app.operation_sequence.issue();
        app.publication_operation
            .begin(current, PublicationKind::StaticPatch, destination)
            .expect("reserve current publication");

        app.finish_static_patch_publication(stale, Err("stale result".to_owned()));

        assert!(app.publication_operation.is_pending());
        assert!(
            app.publication_operation
                .is_kind(PublicationKind::StaticPatch)
        );
        assert_eq!(app.pending_static_patch_drafts.drafts().len(), 1);
        assert!(app.static_patch_result.is_none());
    }

    #[test]
    fn wrong_source_static_receipt_fails_closed_and_preserves_drafts() {
        let (_context, mut app) = test_app();
        let (active_source, active_project) = loaded_project_with_source();
        app.analysis_path = Some(active_source.path().to_path_buf());
        app.finish_project_open(Ok(active_project));
        app.pending_static_patch_drafts
            .queue_nop(THUNK_RVA.into(), &THUNK_BYTES, "retained draft")
            .expect("queue retained draft");

        let (_other_source, other_project) = loaded_project_with_bytes(SYMBOLIZED_FIXTURE);
        let directory = tempfile::tempdir().expect("temporary publication directory");
        let output = directory.path().join("other-source-patch.exe");
        let destination = PublicationDestination::resolve(&output).expect("canonical destination");
        let operation = app.operation_sequence.issue();
        app.publication_operation
            .begin(operation, PublicationKind::StaticPatch, destination)
            .expect("reserve static publication");
        let receipt = publish_test_patch(&other_project, &output);

        app.finish_static_patch_publication(operation, Ok(receipt));

        assert!(!app.publication_operation.is_pending());
        assert_eq!(app.pending_static_patch_drafts.drafts().len(), 1);
        assert!(matches!(
            app.static_patch_result.as_ref(),
            Some(Err(error)) if error.contains("did not match the current project identity")
        ));
    }

    #[test]
    fn matching_static_receipt_completes_lifecycle_and_clears_only_published_drafts() {
        let (_context, mut app) = test_app();
        let (source, project) = loaded_project_with_bytes(SYMBOLIZED_FIXTURE);
        let directory = tempfile::tempdir().expect("temporary publication directory");
        let output = directory.path().join("matching-source-patch.exe");
        let receipt = publish_test_patch(&project, &output);
        app.analysis_path = Some(source.path().to_path_buf());
        app.finish_project_open(Ok(project));
        app.pending_static_patch_drafts
            .queue_nop(THUNK_RVA.into(), &THUNK_BYTES, "published draft")
            .expect("queue published draft");
        let destination = PublicationDestination::resolve(&output).expect("canonical destination");
        let operation = app.operation_sequence.issue();
        app.publication_operation
            .begin(operation, PublicationKind::StaticPatch, destination)
            .expect("reserve static publication");

        app.finish_static_patch_publication(operation, Ok(receipt));

        assert!(!app.publication_operation.is_pending());
        assert!(app.pending_static_patch_drafts.drafts().is_empty());
        assert!(matches!(app.static_patch_result.as_ref(), Some(Ok(_))));
    }

    #[test]
    fn worker_disconnect_releases_static_publication_but_retains_unpublished_drafts() {
        let (_context, mut app) = test_app();
        app.pending_static_patch_drafts
            .queue_nop(THUNK_RVA.into(), &THUNK_BYTES, "recoverable draft")
            .expect("queue recoverable draft");
        let directory = tempfile::tempdir().expect("temporary publication directory");
        let destination =
            PublicationDestination::resolve(&directory.path().join("interrupted-patch.exe"))
                .expect("canonical destination");
        let operation = app.operation_sequence.issue();
        app.publication_operation
            .begin(operation, PublicationKind::StaticPatch, destination)
            .expect("reserve static publication");

        app.handle_worker_disconnect("deterministic worker disconnect".to_owned());

        assert!(!app.publication_operation.is_pending());
        assert_eq!(app.pending_static_patch_drafts.drafts().len(), 1);
        assert!(matches!(
            app.static_patch_result.as_ref(),
            Some(Err(error)) if error.contains("disconnected during static patch publication")
        ));
    }

    #[test]
    fn stale_patch_set_load_cannot_replace_drafts_or_clear_the_current_gate() {
        let (_context, mut app) = test_app();
        app.pending_static_patch_drafts
            .queue_nop(0x1000, &[0xcc], "retained draft")
            .expect("queue retained draft");
        let (_source, project) = loaded_project_with_bytes(SYMBOLIZED_FIXTURE);
        let outcome = patch_set_outcome(&project, PathBuf::from("stale.respatch.json"));
        let stale = app.operation_sequence.issue();
        let current = app.operation_sequence.issue();
        app.patch_set_load_operation.begin(current);

        app.finish_static_patch_set_load(stale, Ok(outcome));

        assert!(app.patch_set_load_operation.is_pending());
        assert_eq!(app.pending_static_patch_drafts.drafts().len(), 1);
        assert_eq!(
            app.pending_static_patch_drafts.drafts()[0].label(),
            "retained draft"
        );
        assert!(app.patch_set_result.is_none());
    }

    #[test]
    fn wrong_source_patch_set_load_fails_closed_and_preserves_current_drafts() {
        let (_context, mut app) = test_app();
        let (active_source, active_project) = loaded_project_with_source();
        app.analysis_path = Some(active_source.path().to_path_buf());
        app.finish_project_open(Ok(active_project));
        app.pending_static_patch_drafts
            .queue_nop(0x1000, &[0xcc], "retained draft")
            .expect("queue retained draft");
        let (_other_source, other_project) = loaded_project_with_bytes(SYMBOLIZED_FIXTURE);
        let outcome =
            patch_set_outcome(&other_project, PathBuf::from("wrong-source.respatch.json"));
        let operation = app.operation_sequence.issue();
        app.patch_set_load_operation.begin(operation);

        app.finish_static_patch_set_load(operation, Ok(outcome));

        assert!(!app.patch_set_load_operation.is_pending());
        assert_eq!(app.pending_static_patch_drafts.drafts().len(), 1);
        assert_eq!(
            app.pending_static_patch_drafts.drafts()[0].label(),
            "retained draft"
        );
        assert!(matches!(
            app.patch_set_result.as_ref(),
            Some(Err(error)) if error.contains("did not match the current project identity")
        ));
    }

    #[test]
    fn validated_patch_set_load_atomically_replaces_drafts_and_reports_identity() {
        let (_context, mut app) = test_app();
        let (source, project) = loaded_project_with_bytes(SYMBOLIZED_FIXTURE);
        let outcome = patch_set_outcome(&project, PathBuf::from("matching-source.respatch.json"));
        app.analysis_path = Some(source.path().to_path_buf());
        app.finish_project_open(Ok(project));
        app.pending_static_patch_drafts
            .queue_nop(0x1000, &[0xcc], "replaced draft")
            .expect("queue replaced draft");
        let operation = app.operation_sequence.issue();
        app.patch_set_load_operation.begin(operation);

        app.finish_static_patch_set_load(operation, Ok(outcome));

        assert!(!app.patch_set_load_operation.is_pending());
        assert_eq!(app.pending_static_patch_drafts.drafts().len(), 1);
        assert_eq!(
            app.pending_static_patch_drafts.drafts()[0].label(),
            "Loaded patch-set NOP"
        );
        assert!(matches!(
            app.patch_set_result.as_ref(),
            Some(Ok(message))
                if message.contains("1 edit(s)")
                    && message.contains("exact source SHA-256")
                    && message.contains("architecture x86_64")
        ));
    }

    #[test]
    fn patch_set_load_error_and_disconnect_preserve_unpublished_drafts() {
        let (_context, mut app) = test_app();
        app.pending_static_patch_drafts
            .queue_nop(0x1000, &[0xcc], "recoverable draft")
            .expect("queue recoverable draft");
        let failed = app.operation_sequence.issue();
        app.patch_set_load_operation.begin(failed);

        app.finish_static_patch_set_load(failed, Err("strict overlap rejection".to_owned()));

        assert_eq!(app.pending_static_patch_drafts.drafts().len(), 1);
        assert!(matches!(
            app.patch_set_result.as_ref(),
            Some(Err(error)) if error.contains("overlap rejection")
        ));

        let disconnected = app.operation_sequence.issue();
        app.patch_set_load_operation.begin(disconnected);
        app.handle_worker_disconnect("deterministic worker disconnect".to_owned());

        assert!(!app.patch_set_load_operation.is_pending());
        assert_eq!(app.pending_static_patch_drafts.drafts().len(), 1);
        assert!(matches!(
            app.patch_set_result.as_ref(),
            Some(Err(error)) if error.contains("disconnected during patch-set load")
        ));
    }

    #[test]
    fn patch_set_save_receipt_preserves_drafts_and_uses_publication_gate() {
        let (_context, mut app) = test_app();
        let (source, project) = loaded_project_with_bytes(SYMBOLIZED_FIXTURE);
        let directory = tempfile::tempdir().expect("temporary publication directory");
        let output = directory.path().join("saved.respatch.json");
        let outcome = patch_set_outcome(&project, output.clone());
        app.analysis_path = Some(source.path().to_path_buf());
        app.finish_project_open(Ok(project));
        app.pending_static_patch_drafts
            .queue_nop(THUNK_RVA.into(), &THUNK_BYTES, "saved draft")
            .expect("queue saved draft");
        let destination =
            PublicationDestination::resolve(&output).expect("canonical patch-set destination");
        let operation = app.operation_sequence.issue();
        app.publication_operation
            .begin(operation, PublicationKind::PatchSet, destination)
            .expect("reserve patch-set save");

        app.finish_static_patch_set_save(operation, Ok(outcome));

        assert!(!app.publication_operation.is_pending());
        assert_eq!(app.pending_static_patch_drafts.drafts().len(), 1);
        assert!(matches!(app.patch_set_result.as_ref(), Some(Ok(_))));
    }

    #[test]
    fn patch_set_paths_use_the_explicit_multi_part_suffix() {
        let (_source, project) = loaded_project_with_source();
        let suggestion = default_static_patch_set_path(&project);
        assert!(is_static_patch_set_path(&suggestion));
        assert!(
            suggestion
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(STATIC_PATCH_SET_SUFFIX))
        );
        assert!(!is_static_patch_set_path(Path::new("patches.json")));
    }

    #[test]
    fn close_remains_paused_during_any_file_publication() {
        let (context, mut app) = test_app();
        let directory = tempfile::tempdir().expect("temporary publication directory");
        let destination =
            PublicationDestination::resolve(&directory.path().join("pending-export.pdb"))
                .expect("canonical destination");
        let operation = app.operation_sequence.issue();
        app.publication_operation
            .begin(operation, PublicationKind::Export, destination)
            .expect("reserve export publication");

        assert!(!app.request_close(&context));
        assert!(app.publication_operation.is_pending());
        assert!(app.publication_operation.is_kind(PublicationKind::Export));

        app.publication_operation.invalidate();
        let load = app.operation_sequence.issue();
        app.patch_set_load_operation.begin(load);
        assert!(!app.request_close(&context));
        assert!(app.patch_set_load_operation.is_pending());
    }
}
