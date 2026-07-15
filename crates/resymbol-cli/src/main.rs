use std::{
    collections::BTreeSet,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use resymbol_analysis::{
    AnalysisSession, BinaryAnalysis, PeAnalysis, PeControlFlowTarget, PluginRunRecord,
    PluginRunStatus, analyze_bytes,
};
use resymbol_core::{
    BinaryId, ClaimProvenance, Confidence, DiscoveredPlugin, Evidence, PLUGIN_DISABLED_SENTINEL,
    PluginDiscoveryOptions, PluginSource, SymbolAssertion, SymbolClaim, SymbolSubject,
    discover_plugins,
    plugin_api::{
        DiagnosticSeverity, PluginCapability, PluginHealthState, PluginId, PluginPermission,
        PluginRuntime, PluginRuntimeKind,
    },
};
use resymbol_export::{
    ExportProjection, MAX_MAP_MODULE_NAME_BYTES, render_ghidra_java, render_ida_python, render_map,
    render_markdown, render_pdb, validate_ghidra_java_class_name,
};
#[cfg(test)]
use resymbol_package::read_file_bound;
use resymbol_package::{
    CURRENT_SCHEMA_VERSION, DEFAULT_MAX_PACKAGE_BYTES, PackageOptions, ResymPackage,
    SchemaCompatibility, read_file_with_options, write_file_new_bound,
};
use resymbol_plugin_runtime::{
    ExternalProcessHost, ExternalProcessRequest, ManagedPeImage, ManagedPeImageSection,
    ManagedProcessHost, NativePeImage, NativePeImageSection, NativeProcessHost, PluginMethod,
    PluginRuntimeError, RuntimeLimits, StreamKind, WasmComponentHost, WasmPeImage,
    WasmPeImageSection, WasmRuntimeLimits,
};
use resymbol_plugin_state::{
    ArtifactFingerprint, ArtifactStateKey, ArtifactTrustPolicy, FingerprintLimits,
    PluginArtifactStatus, PluginExecutionPolicy, PluginStateStore, StateChange,
    fingerprint_plugin_directory,
};
use serde_json::{Map, Value};

const NO_PCHD_BASE_DESCRIPTOR_SCHEMA_VERSION: u32 = 5;
const TRANSITIVE_THUNK_CHAIN_SCHEMA_VERSION: u32 = 6;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

#[derive(Debug, Parser)]
#[command(
    name = "resymbol",
    version,
    about = "Reconstruct symbols and program structure from compiled binaries"
)]
struct Cli {
    /// Start without loading third-party plugins.
    #[arg(long, global = true)]
    safe_mode: bool,

    /// Directory scanned for dropped-in plugins.
    #[arg(long, global = true, default_value = "plugins")]
    plugin_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Analyze a binary and create a validated `.resym` package.
    Analyze(AnalyzeArgs),
    /// Inspect and validate a `.resym` analysis package.
    Inspect(InspectArgs),
    /// Export reconstructed symbols for a debugger or another tool.
    Export(ExportArgs),
    /// Inspect and manage discovered plugins.
    Plugin(PluginArgs),
}

#[derive(Debug, Args)]
struct AnalyzeArgs {
    /// Binary to analyze.
    binary: PathBuf,

    /// Destination package (defaults to the binary path with a `.resym` extension).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Run only the named plugin (repeat for more than one).
    #[arg(long = "plugin", value_name = "ID")]
    plugins: Vec<String>,

    /// Return failure after writing the package if a selected plugin did not succeed.
    #[arg(long)]
    strict_plugins: bool,
}

#[derive(Debug, Args)]
struct InspectArgs {
    /// `.resym` package to validate and inspect.
    package: PathBuf,

    /// Print the complete package as pretty JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ExportArgs {
    /// Validated `.resym` package to export.
    package: PathBuf,

    /// Destination representation to generate.
    #[arg(long, value_enum)]
    format: ExportFormat,

    /// Destination file (defaults beside the package).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Exact original PE required by --format pdb; rejected for other formats.
    #[arg(
        long,
        value_name = "EXACT_ORIGINAL_PE",
        required_if_eq("format", "pdb")
    )]
    binary: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ExportFormat {
    #[value(name = "json")]
    Json,
    #[value(name = "markdown")]
    Markdown,
    #[value(name = "map")]
    Map,
    #[value(name = "pdb")]
    Pdb,
    #[value(name = "ida-python")]
    IdaPython,
    #[value(name = "ghidra-java")]
    GhidraJava,
}

impl ExportFormat {
    const fn label(self) -> &'static str {
        match self {
            Self::Json => "debugger-neutral JSON",
            Self::Markdown => "Markdown report",
            Self::Map => "Microsoft-linker-style MAP",
            Self::Pdb => "exact-RSDS public-symbol PDB",
            Self::IdaPython => "IDA Python",
            Self::GhidraJava => "Ghidra Java",
        }
    }
}

#[derive(Debug, Args)]
struct PluginArgs {
    #[command(subcommand)]
    command: PluginCommand,
}

#[derive(Debug, Subcommand)]
enum PluginCommand {
    /// List discovered plugins and their health state.
    List,
    /// Validate plugin manifests and report actionable diagnostics.
    Doctor,
    /// Enable a plugin by its manifest identifier.
    Enable { id: String },
    /// Disable a plugin by its manifest identifier.
    Disable { id: String },
    /// Trust the exact current contents of one plugin directory.
    Trust {
        id: String,
        /// Require this exact full SHA-256 fingerprint before trusting.
        #[arg(long)]
        fingerprint: Option<String>,
    },
    /// Remove trust from the exact current plugin artifact.
    Untrust { id: String },
    /// Clear quarantine for the exact current plugin artifact without trusting it.
    Reset { id: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Analyze(args) => analyze(args, cli.safe_mode, cli.plugin_dir),
        Command::Inspect(args) => inspect(args),
        Command::Export(args) => export(args),
        Command::Plugin(args) => plugins(args, cli.safe_mode, cli.plugin_dir),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluginAttemptStatus {
    Succeeded,
    Failed,
    Skipped,
}

impl PluginAttemptStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PluginAttempt {
    plugin_id: String,
    status: PluginAttemptStatus,
    detail: String,
}

struct PluginExecutionSummary {
    runs: Vec<PluginRunRecord>,
    claims: Vec<SymbolClaim>,
    attempts: Vec<PluginAttempt>,
}

struct SinglePluginResult {
    run: Option<PluginRunRecord>,
    claims: Vec<SymbolClaim>,
    attempt: PluginAttempt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnalysisPluginRuntime {
    External,
    Managed,
    Native,
    Wasm,
}

struct AnalysisPluginHosts<'a> {
    external: &'a ExternalProcessHost,
    managed: Option<&'a Result<ManagedProcessHost, String>>,
    native: Option<&'a Result<NativeProcessHost, String>>,
    wasm: Option<&'a Result<WasmComponentHost, String>>,
}

fn analyze(args: AnalyzeArgs, safe_mode: bool, plugin_dir: PathBuf) -> Result<()> {
    let binary = args
        .binary
        .canonicalize()
        .with_context(|| format!("cannot open binary {}", args.binary.display()))?;
    let bytes = Arc::<[u8]>::from(
        fs::read(&binary).with_context(|| format!("cannot read binary {}", binary.display()))?,
    );
    let base_analysis = analyze_bytes(&bytes)
        .with_context(|| format!("cannot analyze binary {}", binary.display()))?;
    let output = args.output.unwrap_or_else(|| default_package_path(&binary));
    ensure_output_absent(&output)?;

    let selectors = parse_plugin_selectors(&args.plugins)?;
    let report = scan_plugins(&plugin_dir, safe_mode)?;
    let execution = execute_analysis_plugins(
        &base_analysis,
        &binary,
        &bytes,
        &report,
        &selectors,
        safe_mode,
        &plugin_dir,
    )?;
    let strict_failures = strict_plugin_failure_count(&execution.attempts);
    let session = AnalysisSession::new(base_analysis, execution.runs, execution.claims)
        .context("cannot assemble validated analysis session")?;
    let package = ResymPackage::from_bound_payload(env!("CARGO_PKG_VERSION"), session)
        .context("cannot create analysis package")?;
    write_file_new_bound(&output, &package)
        .with_context(|| format!("cannot write package {}", output.display()))?;

    println!("binary: {}", binary.display());
    print_session_summary(
        package.payload(),
        CodeRecoveryAvailability::Recorded,
        TransitiveThunkRecoveryAvailability::Recorded,
        StringDataRecoveryAvailability::Recorded,
        RttiRecoveryAvailability::Recorded,
    )?;
    println!("package: {}", output.display());
    println!("plugin directory: {}", plugin_dir.display());
    println!("safe mode: {safe_mode}");
    println!(
        "plugins: {} loadable / {} discovered",
        report.loadable().count(),
        report.plugins.len()
    );
    if execution.attempts.is_empty() {
        println!("plugin execution: no analysis candidates selected");
    } else {
        for attempt in &execution.attempts {
            println!(
                "plugin {}: {} — {}",
                attempt.plugin_id,
                attempt.status.label(),
                bounded_single_line(&attempt.detail, 768)
            );
        }
    }

    if args.strict_plugins && strict_failures > 0 {
        bail!(
            "strict plugin policy rejected {strict_failures} plugin outcome(s); package was written to {}",
            output.display()
        );
    }

    Ok(())
}

fn inspect(args: InspectArgs) -> Result<()> {
    let package_path = args
        .package
        .canonicalize()
        .with_context(|| format!("cannot open package {}", args.package.display()))?;
    let loaded = read_analysis_package(&package_path, args.json)
        .with_context(|| format!("cannot read package {}", package_path.display()))?;

    if args.json {
        let json = loaded.to_pretty_inspection_json()?;
        println!("{json}");
        return Ok(());
    }

    println!("package: {}", package_path.display());
    println!("schema: {}", loaded.package.schema_version());
    println!("generator: {}", loaded.package.generator_version());
    print_session_summary(
        loaded.package.payload(),
        loaded.code_recovery_availability,
        loaded.transitive_thunk_recovery_availability,
        loaded.string_data_recovery_availability,
        loaded.rtti_recovery_availability,
    )?;

    Ok(())
}

fn analysis_package_read_options() -> PackageOptions {
    let compatibility = SchemaCompatibility::inclusive(1, CURRENT_SCHEMA_VERSION)
        .expect("the application package compatibility range is valid");
    PackageOptions::new(DEFAULT_MAX_PACKAGE_BYTES, compatibility)
        .expect("the application package size limit is non-zero")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeRecoveryAvailability {
    Recorded,
    RecordedWithoutReadOnlyPointerControlFlow(u32),
    UnavailableSchema1,
}

impl CodeRecoveryAvailability {
    fn export_summary_line(self) -> Option<String> {
        match self {
            Self::Recorded => None,
            Self::RecordedWithoutReadOnlyPointerControlFlow(schema_version) => Some(format!(
                "read-only function-pointer call/thunk resolution: unavailable (schema {schema_version} package predates this recovery data; reanalyze the exact original binary)"
            )),
            Self::UnavailableSchema1 => Some(
                "code recovery: unavailable (schema 1 package predates decoder data; reanalyze the exact original binary)"
                    .to_owned(),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransitiveThunkRecoveryAvailability {
    Recorded,
    RecordedWithoutTransitiveThunkChains(u32),
    UnavailableSchema1,
}

impl TransitiveThunkRecoveryAvailability {
    fn summary_line(self) -> Option<String> {
        match self {
            Self::Recorded | Self::UnavailableSchema1 => None,
            Self::RecordedWithoutTransitiveThunkChains(schema_version) => Some(format!(
                "transitive exact thunk-chain recovery: unavailable (schema {schema_version} package predates this recovery; existing one-hop thunks remain available; reanalyze the exact original binary)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringDataRecoveryAvailability {
    Recorded,
    UnavailableSchema1,
    UnavailableSchema2,
}

impl StringDataRecoveryAvailability {
    const fn export_summary_line(self) -> Option<&'static str> {
        match self {
            Self::Recorded => None,
            Self::UnavailableSchema1 => Some(
                "string/data recovery: unavailable (schema 1 package predates string and data-reference recovery data; reanalyze the exact original binary)",
            ),
            Self::UnavailableSchema2 => Some(
                "string/data recovery: unavailable (schema 2 package predates string and data-reference recovery data; reanalyze the exact original binary)",
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RttiRecoveryAvailability {
    Recorded,
    RecordedWithoutNoPchdBaseDescriptors(u32),
}

impl RttiRecoveryAvailability {
    fn summary_line(self) -> Option<String> {
        match self {
            Self::Recorded => None,
            Self::RecordedWithoutNoPchdBaseDescriptors(schema_version) => Some(format!(
                "MSVC RTTI 24-byte base descriptors without pCHD: unavailable (schema {schema_version} predates this recovery; existing recorded RTTI remains available; reanalyze the exact original binary for current coverage)"
            )),
        }
    }
}

struct LoadedAnalysisPackage {
    package: ResymPackage<AnalysisSession>,
    code_recovery_availability: CodeRecoveryAvailability,
    transitive_thunk_recovery_availability: TransitiveThunkRecoveryAvailability,
    string_data_recovery_availability: StringDataRecoveryAvailability,
    rtti_recovery_availability: RttiRecoveryAvailability,
    schema1_source: Option<ResymPackage<Value>>,
}

impl LoadedAnalysisPackage {
    fn to_pretty_inspection_json(&self) -> Result<String> {
        match &self.schema1_source {
            Some(source) => serde_json::to_string_pretty(source)
                .context("cannot serialize validated schema-v1 package as JSON"),
            None => serde_json::to_string_pretty(&self.package)
                .context("cannot serialize validated package as JSON"),
        }
    }
}

fn read_analysis_package(
    path: &Path,
    preserve_schema1_source: bool,
) -> Result<LoadedAnalysisPackage> {
    let package: ResymPackage<Value> =
        read_file_with_options(path, analysis_package_read_options())?;
    let schema_version = package.schema_version();
    let code_recovery_availability = match schema_version {
        1 => CodeRecoveryAvailability::UnavailableSchema1,
        2 => CodeRecoveryAvailability::RecordedWithoutReadOnlyPointerControlFlow(2),
        3 => CodeRecoveryAvailability::RecordedWithoutReadOnlyPointerControlFlow(3),
        4..=6 => CodeRecoveryAvailability::Recorded,
        _ => bail!("unsupported analysis package schema {schema_version}"),
    };
    let transitive_thunk_recovery_availability = match schema_version {
        1 => TransitiveThunkRecoveryAvailability::UnavailableSchema1,
        2..=5 => TransitiveThunkRecoveryAvailability::RecordedWithoutTransitiveThunkChains(
            schema_version,
        ),
        6 => TransitiveThunkRecoveryAvailability::Recorded,
        _ => bail!("unsupported analysis package schema {schema_version}"),
    };
    let string_data_recovery_availability = match schema_version {
        1 => StringDataRecoveryAvailability::UnavailableSchema1,
        2 => StringDataRecoveryAvailability::UnavailableSchema2,
        3..=6 => StringDataRecoveryAvailability::Recorded,
        _ => bail!("unsupported analysis package schema {schema_version}"),
    };
    let rtti_recovery_availability = match schema_version {
        1..=4 => RttiRecoveryAvailability::RecordedWithoutNoPchdBaseDescriptors(schema_version),
        5..=6 => RttiRecoveryAvailability::Recorded,
        _ => bail!("unsupported analysis package schema {schema_version}"),
    };
    let schema1_source = (preserve_schema1_source && schema_version == 1).then(|| package.clone());
    if schema_version < NO_PCHD_BASE_DESCRIPTOR_SCHEMA_VERSION {
        reject_pre_v5_no_pchd_base_descriptors(package.payload(), schema_version)?;
    }
    if matches!(schema_version, 2 | 3) {
        reject_pre_v4_function_pointer_targets(package.payload(), schema_version)?;
    }
    let package = package.try_map_payload(|payload| match schema_version {
        1 => serde_json::from_value::<SchemaV1AnalysisSession>(payload)
            .context("cannot decode schema-v1 analysis payload")?
            .migrate(),
        2 => serde_json::from_value(payload).context("cannot decode schema-v2 analysis payload"),
        3 => serde_json::from_value(payload).context("cannot decode schema-v3 analysis payload"),
        4 => serde_json::from_value(payload).context("cannot decode schema-v4 analysis payload"),
        5 => serde_json::from_value(payload).context("cannot decode schema-v5 analysis payload"),
        6 => serde_json::from_value(payload).context("cannot decode current analysis payload"),
        _ => bail!("unsupported analysis package schema {schema_version}"),
    })?;
    if (2..TRANSITIVE_THUNK_CHAIN_SCHEMA_VERSION).contains(&schema_version) {
        reject_pre_v6_transitive_thunk_chains(package.payload(), schema_version)?;
    }
    package
        .ensure_payload_binding()
        .context("package envelope and migrated payload identify different binaries")?;
    Ok(LoadedAnalysisPackage {
        package,
        code_recovery_availability,
        transitive_thunk_recovery_availability,
        string_data_recovery_availability,
        rtti_recovery_availability,
        schema1_source,
    })
}

fn reject_pre_v5_no_pchd_base_descriptors(payload: &Value, schema_version: u32) -> Result<()> {
    debug_assert!((1..NO_PCHD_BASE_DESCRIPTOR_SCHEMA_VERSION).contains(&schema_version));
    if value_uses_no_pchd_base_descriptor(payload) {
        bail!(
            "package schema {schema_version} predates 24-byte MSVC RTTI base descriptors without pCHD but its payload contains schema-5 no-pCHD semantics; legacy envelopes cannot be relabeled, so reanalyze the exact original binary"
        );
    }
    Ok(())
}

fn value_uses_no_pchd_base_descriptor(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(value_uses_no_pchd_base_descriptor),
        Value::Object(object) => object.iter().any(|(key, nested)| {
            if key == "msvc_rtti_vftables" {
                rtti_vftable_array_uses_no_pchd_descriptor(nested)
            } else {
                value_uses_no_pchd_base_descriptor(nested)
            }
        }),
        _ => false,
    }
}

fn rtti_vftable_array_uses_no_pchd_descriptor(value: &Value) -> bool {
    value.as_array().is_some_and(|vftables| {
        vftables.iter().any(|vftable| {
            vftable.as_object().is_some_and(|vftable| {
                let is_msvc_rtti_vftable = [
                    "rva",
                    "complete_object_locator_rva",
                    "type_descriptor_rva",
                    "class_hierarchy_descriptor_rva",
                    "base_class_array_rva",
                    "offset",
                    "constructor_displacement_offset",
                    "decorated_class_name",
                    "class_name",
                    "hierarchy_attributes",
                    "base_classes",
                    "virtual_function_rvas",
                ]
                .iter()
                .all(|key| vftable.contains_key(*key));
                is_msvc_rtti_vftable
                    && vftable
                        .get("base_classes")
                        .is_some_and(base_class_array_uses_no_pchd_descriptor)
            })
        })
    })
}

fn base_class_array_uses_no_pchd_descriptor(value: &Value) -> bool {
    value.as_array().is_some_and(|base_classes| {
        base_classes.iter().any(|base| {
            base.as_object().is_some_and(|base| {
                let is_msvc_rtti_base_class = [
                    "array_index",
                    "descriptor_rva",
                    "type_descriptor_rva",
                    "decorated_name",
                    "name",
                    "num_contained_bases",
                    "member_displacement",
                    "vbtable_displacement",
                    "displacement_inside_vbtable",
                    "attributes",
                ]
                .iter()
                .all(|key| base.contains_key(*key));
                is_msvc_rtti_base_class
                    && base
                        .get("class_hierarchy_descriptor_rva")
                        .is_none_or(Value::is_null)
            })
        })
    })
}

fn reject_pre_v4_function_pointer_targets(payload: &Value, schema_version: u32) -> Result<()> {
    debug_assert!(matches!(schema_version, 2 | 3));
    let base_analysis = payload.pointer("/base_analysis/analysis");
    let base_relationship_uses_pointer = base_analysis.is_some_and(|analysis| {
        relationship_array_uses_function_pointer(analysis.get("direct_calls"))
            || relationship_array_uses_function_pointer(analysis.get("thunks"))
            || symbol_graph_uses_function_pointer(analysis.get("symbol_graph"))
    });
    let plugin_claim_uses_pointer = claim_array_uses_function_pointer(payload.get("plugin_claims"));
    if base_relationship_uses_pointer || plugin_claim_uses_pointer {
        bail!(
            "package schema {schema_version} predates function-pointer targets but its payload contains a schema-4 function-pointer target; legacy envelopes cannot be relabeled, so reanalyze the exact original binary"
        );
    }
    Ok(())
}

fn relationship_array_uses_function_pointer(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|relationships| {
            relationships
                .iter()
                .any(|relationship| target_is_function_pointer(relationship.get("target")))
        })
}

fn symbol_graph_uses_function_pointer(value: Option<&Value>) -> bool {
    claim_array_uses_function_pointer(value.and_then(|graph| graph.get("claims")))
}

fn claim_array_uses_function_pointer(value: Option<&Value>) -> bool {
    value.and_then(Value::as_array).is_some_and(|claims| {
        claims.iter().any(|claim| {
            target_is_function_pointer(
                claim
                    .get("assertion")
                    .and_then(|assertion| assertion.get("target")),
            )
        })
    })
}

fn target_is_function_pointer(value: Option<&Value>) -> bool {
    value
        .and_then(|target| target.get("kind"))
        .and_then(Value::as_str)
        == Some("function-pointer")
}

fn reject_pre_v6_transitive_thunk_chains(
    session: &AnalysisSession,
    schema_version: u32,
) -> Result<()> {
    debug_assert!((2..TRANSITIVE_THUNK_CHAIN_SCHEMA_VERSION).contains(&schema_version));
    let BinaryAnalysis::Pe(analysis) = session.base_analysis() else {
        return Ok(());
    };
    let legacy_seeds = legacy_initial_thunk_seeds(analysis);
    if let Some(thunk) = analysis
        .thunks
        .iter()
        .find(|thunk| !legacy_seeds.contains(&thunk.rva))
    {
        bail!(
            "package schema {schema_version} predates transitive exact thunk-chain recovery but its base analysis contains schema-6 transitive thunk source RVA {:#x}; legacy envelopes cannot be relabeled, so reanalyze the exact original binary",
            thunk.rva
        );
    }
    Ok(())
}

fn legacy_initial_thunk_seeds(analysis: &PeAnalysis) -> BTreeSet<u32> {
    let mut seeds = BTreeSet::new();
    if analysis.entry_point_rva != 0 {
        seeds.insert(analysis.entry_point_rva);
    }
    seeds.extend(
        analysis
            .runtime_functions
            .iter()
            .map(|function| function.begin_rva),
    );
    seeds.extend(analysis.exports.iter().filter_map(|export| {
        (export.forwarded_to.is_none())
            .then_some(export.address_rva)
            .flatten()
            .filter(|rva| legacy_range_is_backed_executable(analysis, *rva, 1))
    }));
    seeds.extend(
        analysis
            .direct_calls
            .iter()
            .filter_map(|call| match call.target {
                PeControlFlowTarget::Function { rva }
                | PeControlFlowTarget::FunctionPointer { rva, .. } => Some(rva),
                PeControlFlowTarget::ImportIat { .. } => None,
            }),
    );
    seeds.extend(
        analysis
            .msvc_rtti_vftables
            .iter()
            .flat_map(|vftable| vftable.virtual_function_rvas.iter().copied()),
    );
    seeds
}

fn legacy_range_is_backed_executable(analysis: &PeAnalysis, rva: u32, size: u32) -> bool {
    if size == 0 {
        return false;
    }
    let Some(end) = u64::from(rva).checked_add(u64::from(size)) else {
        return false;
    };
    analysis.sections.iter().any(|section| {
        let start = u64::from(section.virtual_address);
        let backed_end = start.saturating_add(u64::from(section.raw_data_size));
        section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && u64::from(rva) >= start
            && end <= backed_end
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaV1AnalysisSession {
    base_analysis: SchemaV1BinaryAnalysis,
    plugin_runs: Vec<PluginRunRecord>,
    plugin_claims: Vec<SchemaV1SymbolClaim>,
}

impl SchemaV1AnalysisSession {
    fn migrate(self) -> Result<AnalysisSession> {
        let plugin_claims = self
            .plugin_claims
            .into_iter()
            .enumerate()
            .map(|(index, claim)| {
                claim
                    .migrate()
                    .with_context(|| format!("cannot migrate schema-v1 plugin claim {index}"))
            })
            .collect::<Result<Vec<_>>>()?;
        AnalysisSession::new(
            self.base_analysis.migrate()?,
            self.plugin_runs,
            plugin_claims,
        )
        .context("migrated schema-v1 analysis session is invalid")
    }
}

/// Exact assertion vocabulary understood by schema 1.
///
/// This must remain a closed compatibility decoder rather than reusing the
/// current [`SymbolAssertion`] deserializer. Otherwise a package carrying a
/// legacy envelope could opt into claim kinds whose validation and semantics
/// did not exist when schema 1 was defined.
#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum SchemaV1SymbolAssertion {
    Name { name: String },
    FunctionPrototype { declaration: String },
    FunctionBoundary { size: u64 },
    TypeDefinition { declaration: String },
    ClassMembership { class_name: String },
    Comment { text: String },
}

impl From<SchemaV1SymbolAssertion> for SymbolAssertion {
    fn from(assertion: SchemaV1SymbolAssertion) -> Self {
        match assertion {
            SchemaV1SymbolAssertion::Name { name } => Self::Name { name },
            SchemaV1SymbolAssertion::FunctionPrototype { declaration } => {
                Self::FunctionPrototype { declaration }
            }
            SchemaV1SymbolAssertion::FunctionBoundary { size } => Self::FunctionBoundary { size },
            SchemaV1SymbolAssertion::TypeDefinition { declaration } => {
                Self::TypeDefinition { declaration }
            }
            SchemaV1SymbolAssertion::ClassMembership { class_name } => {
                Self::ClassMembership { class_name }
            }
            SchemaV1SymbolAssertion::Comment { text } => Self::Comment { text },
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaV1SymbolClaim {
    subject: SymbolSubject,
    assertion: SchemaV1SymbolAssertion,
    confidence: Confidence,
    evidence: Vec<Evidence>,
    provenance: ClaimProvenance,
}

impl SchemaV1SymbolClaim {
    fn migrate(self) -> Result<SymbolClaim> {
        SymbolClaim::new(
            self.subject,
            self.assertion.into(),
            self.confidence,
            self.evidence,
            self.provenance,
        )
        .context("schema-v1 plugin claim is invalid")
    }
}

#[derive(serde::Deserialize)]
#[serde(tag = "format", content = "analysis", rename_all = "kebab-case")]
enum SchemaV1BinaryAnalysis {
    Pe(SchemaV1PeAnalysis),
}

impl SchemaV1BinaryAnalysis {
    fn migrate(self) -> Result<BinaryAnalysis> {
        match self {
            Self::Pe(analysis) => analysis.migrate().map(BinaryAnalysis::Pe),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaV1PeAnalysis {
    identity: resymbol_core::BinaryIdentity,
    pe_header_offset: u32,
    coff: resymbol_analysis::CoffHeader,
    entry_point_rva: u32,
    size_of_image: u32,
    size_of_headers: u32,
    section_alignment: u32,
    file_alignment: u32,
    subsystem: u16,
    dll_characteristics: u16,
    directories: resymbol_analysis::PeDataDirectories,
    sections: Vec<resymbol_analysis::PeSection>,
    imports: Vec<resymbol_analysis::PeImportLibrary>,
    export_library_name: Option<String>,
    exports: Vec<resymbol_analysis::PeExport>,
    runtime_functions: Vec<resymbol_analysis::RuntimeFunction>,
    #[serde(default)]
    msvc_rtti_scan_truncated: bool,
    #[serde(default)]
    msvc_rtti_vftables: Vec<resymbol_analysis::MsvcRttiVftable>,
    symbol_graph: resymbol_core::SymbolGraph,
}

impl SchemaV1PeAnalysis {
    fn migrate(self) -> Result<PeAnalysis> {
        let mut analysis = PeAnalysis {
            identity: self.identity,
            pe_header_offset: self.pe_header_offset,
            coff: self.coff,
            entry_point_rva: self.entry_point_rva,
            size_of_image: self.size_of_image,
            size_of_headers: self.size_of_headers,
            section_alignment: self.section_alignment,
            file_alignment: self.file_alignment,
            subsystem: self.subsystem,
            dll_characteristics: self.dll_characteristics,
            directories: self.directories,
            sections: self.sections,
            imports: self.imports,
            export_library_name: self.export_library_name,
            exports: self.exports,
            runtime_functions: self.runtime_functions,
            code_recovery_scan_truncated: false,
            direct_calls: Vec::new(),
            thunks: Vec::new(),
            string_recovery_scan_truncated: false,
            strings: Vec::new(),
            data_reference_scan_truncated: false,
            data_references: Vec::new(),
            msvc_rtti_scan_truncated: self.msvc_rtti_scan_truncated,
            msvc_rtti_vftables: self.msvc_rtti_vftables,
            symbol_graph: self.symbol_graph,
        };
        analysis.symbol_graph = analysis
            .rebuild_symbol_graph()
            .context("cannot rebuild claims for a schema-v1 PE analysis")?;
        analysis
            .validate()
            .context("migrated schema-v1 PE analysis is invalid")?;
        Ok(analysis)
    }
}

fn export(args: ExportArgs) -> Result<()> {
    let ExportArgs {
        package,
        format,
        output,
        binary,
    } = args;
    if format != ExportFormat::Pdb && binary.is_some() {
        bail!("--binary is accepted only with --format pdb");
    }
    if format == ExportFormat::Pdb && binary.is_none() {
        bail!("--format pdb requires --binary <EXACT_ORIGINAL_PE>");
    }
    let package_path = package
        .canonicalize()
        .with_context(|| format!("cannot open package {}", package.display()))?;
    let package_data = read_analysis_package(&package_path, false)
        .with_context(|| format!("cannot read package {}", package_path.display()))?;
    let projection = ExportProjection::from_session(package_data.package.payload())
        .context("cannot build debugger export projection")?;
    let source_binary = if format == ExportFormat::Pdb {
        let binary = binary.context("--format pdb requires --binary <EXACT_ORIGINAL_PE>")?;
        let canonical = binary
            .canonicalize()
            .with_context(|| format!("cannot open source binary {}", binary.display()))?;
        let bytes = fs::read(&canonical)
            .with_context(|| format!("cannot read source binary {}", canonical.display()))?;
        Some((canonical, bytes))
    } else {
        None
    };
    let output = output
        .unwrap_or_else(|| default_export_path(&package, format, projection.binary.id.as_str()));

    // Render and validate everything before creating the destination. A failed
    // writer therefore cannot leave a file that looks like a usable export.
    let rendered = match format {
        ExportFormat::Json => {
            let mut json = serde_json::to_string_pretty(&projection)
                .context("cannot serialize debugger-neutral export JSON")?;
            json.push('\n');
            json.into_bytes()
        }
        ExportFormat::Markdown => render_markdown(&projection)
            .context("cannot render Markdown report")?
            .into_bytes(),
        ExportFormat::Map => render_map(
            package_data.package.payload(),
            &projection,
            &map_module_name(&package, projection.binary.id.as_str()),
        )
        .context("cannot render Microsoft-linker-style MAP")?
        .into_bytes(),
        ExportFormat::Pdb => render_pdb(
            package_data.package.payload(),
            &projection,
            source_binary
                .as_ref()
                .expect("PDB source binary was required above")
                .1
                .as_slice(),
        )
        .context("cannot render exact-RSDS public-symbol PDB")?,
        ExportFormat::IdaPython => render_ida_python(&projection)
            .context("cannot render IDA Python import script")?
            .into_bytes(),
        ExportFormat::GhidraJava => {
            let class_name = ghidra_java_class_name(&output)?;
            render_ghidra_java(&projection, class_name)
                .context("cannot render Ghidra Java import script")?
                .into_bytes()
        }
    };
    write_export_new(&output, &rendered)?;

    let warning_occurrences = projection
        .warnings
        .iter()
        .map(|warning| warning.occurrences)
        .sum::<u64>();
    println!("package: {}", package_path.display());
    if let Some((path, _)) = &source_binary {
        println!("source binary: {}", path.display());
    }
    println!("format: {}", format.label());
    println!("output: {}", output.display());
    println!("binary SHA-256: {}", projection.binary.id);
    println!(
        "symbols: {} function(s), {} global(s), {} type(s)",
        projection.functions.len(),
        projection.globals.len(),
        projection.types.len()
    );
    if let Some(line) = package_data
        .code_recovery_availability
        .export_summary_line()
    {
        println!("{line}");
    }
    if let Some(line) = package_data
        .transitive_thunk_recovery_availability
        .summary_line()
    {
        println!("{line}");
    }
    if let Some(line) = package_data
        .string_data_recovery_availability
        .export_summary_line()
    {
        println!("{line}");
    }
    if let Some(line) = package_data.rtti_recovery_availability.summary_line() {
        println!("{line}");
    }
    println!(
        "warnings: {} group(s), {warning_occurrences} occurrence(s)",
        projection.warnings.len()
    );
    for warning in projection.warnings.iter().take(20) {
        match &warning.subject {
            Some(subject) => println!(
                "  {:?} {:?} x{}: {}",
                warning.code, subject, warning.occurrences, warning.message
            ),
            None => println!(
                "  {:?} x{}: {}",
                warning.code, warning.occurrences, warning.message
            ),
        }
    }
    if projection.warnings.len() > 20 {
        println!(
            "  ... {} additional warning group(s) omitted from terminal output",
            projection.warnings.len() - 20
        );
    }
    match format {
        ExportFormat::Json | ExportFormat::Markdown => println!(
            "identity binding: projection records the exact binary SHA-256; no debugger program was modified"
        ),
        ExportFormat::Map => println!(
            "identity notice: MAP comments record the exact binary SHA-256, but a MAP loader cannot enforce it; verify the input manually"
        ),
        ExportFormat::Pdb => println!(
            "identity gate: supplied PE SHA-256 matches the package, and the PDB copies its exact RSDS GUID and age; the PE was not modified"
        ),
        ExportFormat::IdaPython | ExportFormat::GhidraJava => println!(
            "identity gate: importer verifies the loaded program SHA-256 before any mutation"
        ),
    }

    Ok(())
}

fn default_export_path(package: &Path, format: ExportFormat, binary_sha256: &str) -> PathBuf {
    match format {
        ExportFormat::Json => package.with_extension("symbols.json"),
        ExportFormat::Markdown => package.with_extension("symbols.md"),
        ExportFormat::Map => package.with_extension("map"),
        ExportFormat::Pdb => package.with_extension("pdb"),
        ExportFormat::IdaPython => package.with_extension("ida.py"),
        ExportFormat::GhidraJava => {
            let prefix = binary_sha256
                .get(..12)
                .expect("a validated binary SHA-256 has at least 12 ASCII bytes");
            let filename = format!("ReSymbolImport_{prefix}.java");
            package
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join(filename)
        }
    }
}

fn map_module_name(package: &Path, binary_sha256: &str) -> String {
    let fallback = || {
        let prefix = binary_sha256
            .get(..12)
            .expect("a validated binary SHA-256 has at least 12 ASCII bytes");
        format!("resymbol_{prefix}")
    };
    let Some(stem) = package.file_stem().and_then(|value| value.to_str()) else {
        return fallback();
    };

    let mut sanitized = String::with_capacity(stem.len().min(MAX_MAP_MODULE_NAME_BYTES));
    for byte in stem.bytes() {
        if sanitized.len() == MAX_MAP_MODULE_NAME_BYTES {
            break;
        }
        sanitized.push(
            if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.') {
                char::from(byte)
            } else {
                '_'
            },
        );
    }
    if sanitized.is_empty() || matches!(sanitized.as_str(), "." | "..") {
        fallback()
    } else {
        sanitized
    }
}

fn ghidra_java_class_name(output: &Path) -> Result<&str> {
    if output.extension().and_then(|value| value.to_str()) != Some("java") {
        bail!(
            "Ghidra Java output must have a lowercase `.java` extension: {}",
            output.display()
        );
    }
    let class_name = output
        .file_stem()
        .and_then(|value| value.to_str())
        .with_context(|| {
            format!(
                "Ghidra Java output must have a UTF-8 class-name stem: {}",
                output.display()
            )
        })?;
    validate_ghidra_java_class_name(class_name).with_context(|| {
        format!(
            "Ghidra Java output filename stem must be a conservative Java identifier: {}",
            output.display()
        )
    })?;
    Ok(class_name)
}

fn write_export_new(output: &Path, bytes: &[u8]) -> Result<()> {
    match fs::symlink_metadata(output) {
        Ok(_) => bail!("refusing to overwrite existing export {}", output.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("cannot inspect export destination {}", output.display())
            });
        }
    }

    let parent = output
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::Builder::new()
        .prefix(".resymbol-export-")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "cannot create a temporary export beside {}",
                output.display()
            )
        })?;
    staged
        .write_all(bytes)
        .with_context(|| format!("cannot stage export {}", output.display()))?;
    staged
        .as_file()
        .sync_all()
        .with_context(|| format!("cannot flush staged export {}", output.display()))?;

    match staged.persist_noclobber(output) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("refusing to overwrite existing export {}", output.display())
        }
        Err(error) => Err(error.error)
            .with_context(|| format!("cannot publish completed export {}", output.display())),
    }
}

fn ensure_output_absent(output: &Path) -> Result<()> {
    match fs::symlink_metadata(output) {
        Ok(_) => bail!(
            "refusing to overwrite existing package {}",
            output.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("cannot inspect package destination {}", output.display())),
    }
}

fn parse_plugin_selectors(values: &[String]) -> Result<BTreeSet<PluginId>> {
    values
        .iter()
        .map(|value| {
            PluginId::new(value.clone())
                .with_context(|| format!("invalid plugin selector `{value}`"))
        })
        .collect()
}

fn execute_analysis_plugins(
    base_analysis: &BinaryAnalysis,
    binary_path: &Path,
    binary_bytes: &Arc<[u8]>,
    report: &resymbol_core::PluginDiscoveryReport,
    selectors: &BTreeSet<PluginId>,
    safe_mode: bool,
    plugin_dir: &Path,
) -> Result<PluginExecutionSummary> {
    let explicitly_selected = !selectors.is_empty();
    if safe_mode && !explicitly_selected {
        return Ok(PluginExecutionSummary {
            runs: Vec::new(),
            claims: Vec::new(),
            attempts: Vec::new(),
        });
    }
    let mut found = BTreeSet::new();
    let mut runs = Vec::new();
    let mut claims = Vec::new();
    let mut attempts = Vec::new();
    let store = PluginStateStore::new(plugin_dir);
    let external_host = ExternalProcessHost::default();
    let managed_host = report
        .plugins
        .iter()
        .filter_map(|plugin| plugin.manifest.as_ref())
        .any(|manifest| {
            has_analysis_capability(manifest)
                && matches!(&manifest.runtime, PluginRuntime::Managed { .. })
        })
        .then(resolve_managed_host);
    let native_host = report
        .plugins
        .iter()
        .filter_map(|plugin| plugin.manifest.as_ref())
        .any(|manifest| {
            has_analysis_capability(manifest)
                && matches!(
                    &manifest.runtime,
                    PluginRuntime::Native {
                        isolation: resymbol_core::plugin_api::NativeIsolation::OutOfProcess,
                        ..
                    }
                )
        })
        .then(resolve_native_host);
    let wasm_host = report
        .plugins
        .iter()
        .filter_map(|plugin| plugin.manifest.as_ref())
        .any(|manifest| {
            has_analysis_capability(manifest)
                && matches!(&manifest.runtime, PluginRuntime::Wasm { .. })
        })
        .then(|| {
            WasmComponentHost::new(WasmRuntimeLimits::default()).map_err(|error| error.to_string())
        });
    let hosts = AnalysisPluginHosts {
        external: &external_host,
        managed: managed_host.as_ref(),
        native: native_host.as_ref(),
        wasm: wasm_host.as_ref(),
    };

    for plugin in &report.plugins {
        let Some(manifest) = plugin.manifest.as_ref() else {
            continue;
        };
        let selected = selectors.contains(&manifest.id);
        let candidate = if explicitly_selected {
            selected
        } else {
            has_analysis_capability(manifest) && runtime_supports_analysis(&manifest.runtime)
        };
        if !candidate {
            continue;
        }
        if selected {
            found.insert(manifest.id.clone());
        }

        let result = execute_one_plugin(
            base_analysis,
            binary_path,
            binary_bytes,
            plugin,
            safe_mode,
            &store,
            &hosts,
        )?;
        if let Some(run) = result.run {
            runs.push(run);
        }
        claims.extend(result.claims);
        attempts.push(result.attempt);
    }

    for missing in selectors.difference(&found) {
        attempts.push(PluginAttempt {
            plugin_id: missing.to_string(),
            status: PluginAttemptStatus::Skipped,
            detail: "selected plugin was not found as a valid discovered manifest".to_owned(),
        });
    }

    Ok(PluginExecutionSummary {
        runs,
        claims,
        attempts,
    })
}

fn execute_one_plugin(
    base_analysis: &BinaryAnalysis,
    binary_path: &Path,
    binary_bytes: &Arc<[u8]>,
    plugin: &DiscoveredPlugin,
    safe_mode: bool,
    store: &PluginStateStore,
    hosts: &AnalysisPluginHosts<'_>,
) -> Result<SinglePluginResult> {
    let manifest = plugin
        .manifest
        .as_ref()
        .expect("analysis candidates have a discovered manifest");
    let skip = |detail: String| SinglePluginResult {
        run: None,
        claims: Vec::new(),
        attempt: PluginAttempt {
            plugin_id: manifest.id.to_string(),
            status: PluginAttemptStatus::Skipped,
            detail,
        },
    };

    if safe_mode {
        return Ok(skip("safe mode prohibits third-party execution".to_owned()));
    }
    if !has_analysis_capability(manifest) {
        return Ok(skip(
            "manifest declares no supported analysis capability".to_owned(),
        ));
    }
    if plugin.source != PluginSource::Directory {
        return Ok(skip(
            "only installed directory plugins may execute".to_owned(),
        ));
    }
    if !manifest.dependencies.is_empty() {
        return Ok(skip(
            "plugin dependencies are not executed by the initial sequential host".to_owned(),
        ));
    }
    let runtime = match &manifest.runtime {
        PluginRuntime::Wasm { .. } => AnalysisPluginRuntime::Wasm,
        PluginRuntime::ExternalProcess { .. } => AnalysisPluginRuntime::External,
        PluginRuntime::Managed { .. } => AnalysisPluginRuntime::Managed,
        PluginRuntime::Native {
            isolation: resymbol_core::plugin_api::NativeIsolation::OutOfProcess,
            ..
        } => AnalysisPluginRuntime::Native,
        PluginRuntime::Native {
            isolation: resymbol_core::plugin_api::NativeIsolation::InProcess,
            ..
        } => {
            return Ok(skip(
                "in-process native plugins are not supported; use out-of-process isolation"
                    .to_owned(),
            ));
        }
        _ => {
            return Ok(skip(format!(
                "runtime {} is not supported by this host",
                runtime_name(manifest.runtime.kind())
            )));
        }
    };
    if !plugin.is_loadable() {
        return Ok(skip(format!(
            "discovery state {} is not loadable",
            state_name(plugin.health.state)
        )));
    }
    if runtime == AnalysisPluginRuntime::External
        && requests_permission(manifest, PluginPermission::BINARY_READ)
    {
        return Ok(skip(
            "binary.read is unavailable in the current one-shot host".to_owned(),
        ));
    }
    if runtime == AnalysisPluginRuntime::Managed {
        match hosts.managed {
            Some(Ok(_)) => {}
            Some(Err(error)) => return Ok(skip(error.clone())),
            None => {
                return Ok(skip(
                    "managed helper was not resolved for this analysis".to_owned(),
                ));
            }
        }
        if managed_pe_image(base_analysis).is_none() {
            return Ok(skip(
                "managed plugins currently support only PE x86_64 analysis".to_owned(),
            ));
        }
    }
    if runtime == AnalysisPluginRuntime::Native {
        match hosts.native {
            Some(Ok(_)) => {}
            Some(Err(error)) => return Ok(skip(error.clone())),
            None => {
                return Ok(skip(
                    "native helper was not resolved for this analysis".to_owned(),
                ));
            }
        }
        if native_pe_image(base_analysis).is_none() {
            return Ok(skip(
                "native binary.read currently supports PE analysis only".to_owned(),
            ));
        }
    }
    let wasm_image = if runtime == AnalysisPluginRuntime::Wasm {
        match hosts.wasm {
            Some(Ok(_)) => {}
            Some(Err(error)) => return Ok(skip(error.clone())),
            None => {
                return Ok(skip(
                    "WASM component host was not initialized for this analysis".to_owned(),
                ));
            }
        }
        match wasm_pe_image(base_analysis, Arc::clone(binary_bytes)) {
            Some(image) => Some(image),
            None => {
                return Ok(skip(
                    "WASM plugins require an exact validated PE image snapshot".to_owned(),
                ));
            }
        }
    } else {
        None
    };
    if manifest.version.to_string().len() > 128 {
        return Ok(skip(
            "plugin version is too long for the auditable session ledger".to_owned(),
        ));
    }
    let trust_policy = if runtime == AnalysisPluginRuntime::Wasm {
        ArtifactTrustPolicy::Sandboxed
    } else {
        ArtifactTrustPolicy::RequireApproval
    };
    let requires_trust = trust_policy == ArtifactTrustPolicy::RequireApproval;

    let first = match fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default()) {
        Ok(report) => report,
        Err(error) => return Ok(skip(format!("artifact fingerprint failed: {error}"))),
    };
    let key = ArtifactStateKey::new(manifest.id.clone(), first.fingerprint);
    match store.execution_policy(&plugin.path, &key, trust_policy) {
        Ok(PluginExecutionPolicy::Allowed) => {}
        Ok(PluginExecutionPolicy::Disabled) => {
            return Ok(skip("plugin.disabled is present".to_owned()));
        }
        Ok(PluginExecutionPolicy::ApprovalRequired) => {
            return Ok(skip(format!(
                "approval required for exact fingerprint {}",
                first.fingerprint
            )));
        }
        Ok(PluginExecutionPolicy::Quarantined { reason }) => {
            return Ok(skip(format!("exact artifact is quarantined: {reason}")));
        }
        Err(error) => return Ok(skip(format!("plugin state is unsafe or corrupt: {error}"))),
    }

    let run_id = stable_plugin_identifier(
        "run",
        &base_analysis.identity().id,
        &manifest.id,
        first.fingerprint,
    );
    let request_id = stable_plugin_identifier(
        "request",
        &base_analysis.identity().id,
        &manifest.id,
        first.fingerprint,
    );
    let granted_permissions = manifest
        .permissions
        .iter()
        .filter(|permission| {
            let value = permission.as_str();
            (runtime != AnalysisPluginRuntime::Wasm && value == PluginPermission::SYMBOLS_READ)
                || value == PluginPermission::CLAIMS_SUBMIT
                || (matches!(
                    runtime,
                    AnalysisPluginRuntime::Managed
                        | AnalysisPluginRuntime::Native
                        | AnalysisPluginRuntime::Wasm
                ) && value == PluginPermission::BINARY_READ)
        })
        .cloned()
        .collect::<Vec<_>>();
    let symbols_read = granted_permissions
        .iter()
        .any(|permission| permission.as_str() == PluginPermission::SYMBOLS_READ);
    let mut payload = Map::<String, Value>::new();
    payload.insert(
        "binary".to_owned(),
        serde_json::to_value(base_analysis.identity())
            .context("cannot serialize stable binary identity for plugin")?,
    );
    if symbols_read {
        payload.insert(
            "base_analysis".to_owned(),
            serde_json::to_value(base_analysis)
                .context("cannot serialize base analysis for plugin")?,
        );
    }
    let request =
        ExternalProcessRequest::new(request_id, run_id.clone(), PluginMethod::Analyze, payload)
            .context("cannot construct bounded plugin request")?
            .with_granted_permissions(granted_permissions);

    let second = match fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default()) {
        Ok(report) => report,
        Err(error) => {
            return Ok(skip(format!(
                "artifact fingerprint failed immediately before launch: {error}"
            )));
        }
    };
    if second.fingerprint != first.fingerprint {
        let policy = if requires_trust {
            "new approval is required"
        } else {
            "the new sandboxed artifact will be evaluated on the next run"
        };
        return Ok(skip(format!(
            "artifact changed after policy check to {}; {policy}",
            second.fingerprint
        )));
    }
    if let Some(reason) = plugin_execution_policy_blocker(store, &key, &plugin.path, trust_policy) {
        return Ok(skip(format!(
            "plugin policy changed immediately before launch: {reason}"
        )));
    }

    let execution = match runtime {
        AnalysisPluginRuntime::External => hosts.external.execute_trusted(plugin, &request),
        AnalysisPluginRuntime::Managed => {
            let managed_host = hosts
                .managed
                .and_then(|host| host.as_ref().ok())
                .expect("managed host availability was checked before trust");
            let image = managed_pe_image(base_analysis)
                .expect("managed PE x86_64 compatibility was checked before trust");
            managed_host.execute_trusted(plugin, &request, second.fingerprint, binary_path, &image)
        }
        AnalysisPluginRuntime::Native => {
            let native_host = hosts
                .native
                .and_then(|host| host.as_ref().ok())
                .expect("native host availability was checked before trust");
            let image = native_pe_image(base_analysis)
                .expect("native PE compatibility was checked before trust");
            native_host.execute_trusted(plugin, &request, second.fingerprint, binary_path, &image)
        }
        AnalysisPluginRuntime::Wasm => {
            let wasm_host = hosts
                .wasm
                .and_then(|host| host.as_ref().ok())
                .expect("WASM host availability was checked before execution");
            let image = wasm_image
                .as_ref()
                .expect("exact WASM PE image compatibility was checked before execution");
            wasm_host.execute_sandboxed(plugin, &request, second.fingerprint, image)
        }
    };

    if let Some(reason) = plugin_execution_policy_blocker(store, &key, &plugin.path, trust_policy) {
        let failed = failed_run_record(manifest, &run_id, second.fingerprint)?;
        return Ok(SinglePluginResult {
            run: Some(failed),
            claims: Vec::new(),
            attempt: PluginAttempt {
                plugin_id: manifest.id.to_string(),
                status: PluginAttemptStatus::Failed,
                detail: format!(
                    "plugin result was discarded because policy changed during execution: {reason}; the artifact was not newly quarantined"
                ),
            },
        });
    }

    match execution {
        Ok(execution) => {
            let after = fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default());
            if !matches!(&after, Ok(report) if report.fingerprint == second.fingerprint) {
                let reason = match after {
                    Ok(report) => format!(
                        "plugin artifact changed during execution from {} to {}",
                        second.fingerprint, report.fingerprint
                    ),
                    Err(error) => {
                        format!("plugin artifact could not be verified after execution: {error}")
                    }
                };
                let detail = quarantine_failed_artifact(store, &key, &plugin.path, &reason);
                let failed = failed_run_record(manifest, &run_id, second.fingerprint)?;
                return Ok(SinglePluginResult {
                    run: Some(failed),
                    claims: Vec::new(),
                    attempt: PluginAttempt {
                        plugin_id: manifest.id.to_string(),
                        status: PluginAttemptStatus::Failed,
                        detail,
                    },
                });
            }
            let accepted_claim_count = u64::try_from(execution.claims.len())
                .context("plugin claim count does not fit the session ledger")?;
            let succeeded = PluginRunRecord::new(
                manifest.id.clone(),
                manifest.version.to_string(),
                run_id.clone(),
                second.fingerprint.to_hex(),
                PluginRunStatus::Succeeded,
                accepted_claim_count,
            )
            .context("cannot create successful plugin run record")?;
            match AnalysisSession::new(
                base_analysis.clone(),
                vec![succeeded.clone()],
                execution.claims.clone(),
            ) {
                Ok(_) => Ok(SinglePluginResult {
                    run: Some(succeeded),
                    claims: execution.claims,
                    attempt: PluginAttempt {
                        plugin_id: manifest.id.to_string(),
                        status: PluginAttemptStatus::Succeeded,
                        detail: format!(
                            "accepted {accepted_claim_count} claim(s) from {}",
                            second.fingerprint
                        ),
                    },
                }),
                Err(error) => {
                    let detail = quarantine_failed_artifact(
                        store,
                        &key,
                        &plugin.path,
                        &format!("plugin claims failed session validation: {error}"),
                    );
                    let failed = failed_run_record(manifest, &run_id, second.fingerprint)?;
                    Ok(SinglePluginResult {
                        run: Some(failed),
                        claims: Vec::new(),
                        attempt: PluginAttempt {
                            plugin_id: manifest.id.to_string(),
                            status: PluginAttemptStatus::Failed,
                            detail,
                        },
                    })
                }
            }
        }
        Err(error) => {
            if let Some(host_runtime) = pre_attribution_host_runtime(&error) {
                return Ok(skip(format!(
                    "{host_runtime} host-side failure was not attributed to the plugin: {}",
                    plugin_runtime_error_detail(&error)
                )));
            }
            let transient = is_transient_plugin_response(&error);
            let host_side = is_host_side_runtime_failure(&error);
            let error_detail = plugin_runtime_error_detail(&error);
            let detail = if transient {
                format!("transient plugin failure (not quarantined): {error_detail}")
            } else if host_side {
                format!("host-side invocation failure (not quarantined): {error_detail}")
            } else {
                quarantine_failed_artifact(
                    store,
                    &key,
                    &plugin.path,
                    &format!("plugin runtime failure: {error_detail}"),
                )
            };
            let failed = failed_run_record(manifest, &run_id, second.fingerprint)?;
            Ok(SinglePluginResult {
                run: Some(failed),
                claims: Vec::new(),
                attempt: PluginAttempt {
                    plugin_id: manifest.id.to_string(),
                    status: PluginAttemptStatus::Failed,
                    detail,
                },
            })
        }
    }
}

/// Return the helper family only when the trusted marker says execution never
/// crossed into attributable plugin code. These failures are skips rather
/// than failed ledger runs and never quarantine an exact artifact.
fn pre_attribution_host_runtime(error: &PluginRuntimeError) -> Option<&'static str> {
    match error {
        PluginRuntimeError::InvalidNativeContext(_)
        | PluginRuntimeError::NativeHostUnavailable { .. }
        | PluginRuntimeError::NativeHostFailed { .. }
        | PluginRuntimeError::NativeHostArtifactChanged { .. }
        | PluginRuntimeError::NativeSourceBinary { .. }
        | PluginRuntimeError::NativeHostInputChanged { .. }
        | PluginRuntimeError::EncodeNativeBootstrap(_) => Some("native"),
        PluginRuntimeError::InvalidManagedContext(_)
        | PluginRuntimeError::ManagedHostUnavailable { .. }
        | PluginRuntimeError::ManagedHostFailed { .. }
        | PluginRuntimeError::ManagedArtifactMismatch { .. }
        | PluginRuntimeError::ManagedAssemblyClosure { .. }
        | PluginRuntimeError::ManagedSourceBinary { .. }
        | PluginRuntimeError::ManagedHostInputChanged { .. }
        | PluginRuntimeError::ManagedHostArtifactChanged { .. }
        | PluginRuntimeError::EncodeManagedBootstrap(_) => Some("managed"),
        PluginRuntimeError::InvalidWasmContext(_)
        | PluginRuntimeError::WasmEngineUnavailable { .. }
        | PluginRuntimeError::WasmArtifactMismatch { .. } => Some("wasm"),
        _ => None,
    }
}

fn is_transient_plugin_response(error: &PluginRuntimeError) -> bool {
    matches!(
        error,
        PluginRuntimeError::PluginRejected { code, .. } if code == "unavailable"
    )
}

fn is_host_side_runtime_failure(error: &PluginRuntimeError) -> bool {
    pre_attribution_host_runtime(error).is_some()
        || matches!(
            error,
            PluginRuntimeError::InvalidLimits(_)
                | PluginRuntimeError::InvalidRequest(_)
                | PluginRuntimeError::EncodeInput(_)
                | PluginRuntimeError::PermissionNotRequested(_)
                | PluginRuntimeError::StreamLimit {
                    stream: StreamKind::Stdin,
                    ..
                }
                | PluginRuntimeError::WorkerPanicked(_)
                | PluginRuntimeError::ProcessIo { .. }
                | PluginRuntimeError::ProcessWorkerPanicked { .. }
        )
}

fn plugin_runtime_error_detail(error: &PluginRuntimeError) -> String {
    let summary = error.to_string();
    let Some(diagnostics) = error.diagnostics() else {
        return summary;
    };
    let stderr = bounded_single_line(&diagnostics.stderr, 2_048);
    if stderr.is_empty() {
        summary
    } else if diagnostics.stderr_was_lossy {
        format!("{summary}; stderr (lossy UTF-8): {stderr}")
    } else {
        format!("{summary}; stderr: {stderr}")
    }
}

fn failed_run_record(
    manifest: &resymbol_core::plugin_api::PluginManifest,
    run_id: &str,
    fingerprint: ArtifactFingerprint,
) -> Result<PluginRunRecord> {
    PluginRunRecord::new(
        manifest.id.clone(),
        manifest.version.to_string(),
        run_id,
        fingerprint.to_hex(),
        PluginRunStatus::Failed,
        0,
    )
    .context("cannot create failed plugin run record")
}

fn quarantine_failed_artifact(
    store: &PluginStateStore,
    key: &ArtifactStateKey,
    plugin_path: &Path,
    reason: &str,
) -> String {
    let reason = bounded_quarantine_reason(reason);
    match store.quarantine(key, &reason) {
        Ok(_) => format!("{reason}; exact artifact was quarantined"),
        Err(quarantine_error) => {
            let untrust = store.untrust(key);
            let disable = create_disabled_sentinel(plugin_path);
            format!(
                "{reason}; quarantine write failed: {quarantine_error}; trust removal: {}; disable fallback: {}",
                state_change_result(&untrust),
                sentinel_result(&disable, plugin_path)
            )
        }
    }
}

/// Return the current policy reason that prevents an in-flight result from
/// committing. This check is the parent-side linearization point for manual
/// disablement, quarantine, corrupt state, and trust revocation for runtimes
/// that require explicit artifact trust. Sandboxed WASM remains subject to
/// every policy check except approval state.
fn plugin_execution_policy_blocker(
    store: &PluginStateStore,
    key: &ArtifactStateKey,
    plugin_path: &Path,
    trust_policy: ArtifactTrustPolicy,
) -> Option<String> {
    match store.execution_policy(plugin_path, key, trust_policy) {
        Ok(PluginExecutionPolicy::Allowed) => None,
        Ok(PluginExecutionPolicy::Disabled) => Some("plugin.disabled is present".to_owned()),
        Ok(PluginExecutionPolicy::ApprovalRequired) => {
            Some("exact artifact trust was revoked".to_owned())
        }
        Ok(PluginExecutionPolicy::Quarantined { reason }) => {
            Some(format!("exact artifact is quarantined: {reason}"))
        }
        Err(error) => Some(format!("plugin state is unsafe or corrupt: {error}")),
    }
}

fn bounded_quarantine_reason(reason: &str) -> String {
    const MAX_REASON_BYTES: usize = 4_096;
    let sanitized = bounded_single_line(reason, MAX_REASON_BYTES);
    if sanitized.is_empty() {
        "plugin failure without printable diagnostics".to_owned()
    } else {
        sanitized
    }
}

fn bounded_single_line(value: &str, maximum_bytes: usize) -> String {
    const SUFFIX: &str = "...";
    let mut normalized = String::with_capacity(value.len().min(maximum_bytes));
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_control() || character.is_whitespace() {
            pending_space = !normalized.is_empty();
            continue;
        }
        if pending_space {
            normalized.push(' ');
            pending_space = false;
        }
        if character.is_ascii_graphic() {
            normalized.push(character);
        } else {
            normalized.extend(character.escape_default());
        }
    }
    if normalized.len() <= maximum_bytes {
        return normalized;
    }
    if maximum_bytes <= SUFFIX.len() {
        return SUFFIX[..maximum_bytes].to_owned();
    }

    let mut boundary = maximum_bytes - SUFFIX.len();
    while !normalized.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    let mut truncated = normalized[..boundary].to_owned();
    truncated.push_str(SUFFIX);
    truncated
}

fn state_change_result(
    result: &std::result::Result<StateChange, resymbol_plugin_state::StateError>,
) -> String {
    match result {
        Ok(StateChange::Changed) => "removed exact trust".to_owned(),
        Ok(StateChange::Unchanged) => "no exact trust record existed".to_owned(),
        Err(error) => format!("failed ({error})"),
    }
}

fn sentinel_result(result: &Result<bool>, plugin_path: &Path) -> String {
    let path = plugin_path.join(PLUGIN_DISABLED_SENTINEL);
    match result {
        Ok(true) => format!("disabled plugin with {}", path.display()),
        Ok(false) => format!("{} was already a regular file", path.display()),
        Err(error) => format!("failed to create {} ({error:#})", path.display()),
    }
}

fn stable_plugin_identifier(
    kind: &str,
    binary_id: &BinaryId,
    plugin_id: &PluginId,
    fingerprint: ArtifactFingerprint,
) -> String {
    let seed = format!(
        "resymbol.plugin-{kind}\0{}\0{}\0{}",
        binary_id, plugin_id, fingerprint
    );
    format!("{kind}-{}", BinaryId::digest(seed.as_bytes()))
}

fn has_analysis_capability(manifest: &resymbol_core::plugin_api::PluginManifest) -> bool {
    manifest.capabilities.iter().any(|capability| {
        let value = capability.as_str();
        value == PluginCapability::ANALYZER_BINARY
            || value == PluginCapability::ANALYZER_RTTI
            || value == PluginCapability::MATCHER_FUNCTIONS
            || value == PluginCapability::RESOLVER_SYMBOLS
    })
}

fn runtime_supports_analysis(runtime: &PluginRuntime) -> bool {
    matches!(
        runtime,
        PluginRuntime::Wasm { .. }
            | PluginRuntime::ExternalProcess { .. }
            | PluginRuntime::Managed { .. }
    ) || matches!(
        runtime,
        PluginRuntime::Native {
            isolation: resymbol_core::plugin_api::NativeIsolation::OutOfProcess,
            ..
        }
    )
}

fn resolve_managed_host() -> std::result::Result<ManagedProcessHost, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve the ReSymbol executable: {error}"))?;
    let application_directory = executable
        .parent()
        .ok_or_else(|| "the ReSymbol executable has no application directory".to_owned())?;
    resolve_managed_host_in(application_directory)
}

fn resolve_managed_host_in(
    application_directory: &Path,
) -> std::result::Result<ManagedProcessHost, String> {
    let helper_name = format!("resymbol-managed-host{}", std::env::consts::EXE_SUFFIX);
    let helper_path = application_directory.join(helper_name);
    let metadata = fs::symlink_metadata(&helper_path).map_err(|error| {
        format!(
            "managed helper is unavailable at {}: {error}",
            helper_path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "managed helper at {} must be a regular, unlinked sibling executable",
            helper_path.display()
        ));
    }
    ManagedProcessHost::new(helper_path, RuntimeLimits::default())
        .map_err(|error| format!("managed helper is unavailable: {error}"))
}

fn resolve_native_host() -> std::result::Result<NativeProcessHost, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve the ReSymbol executable: {error}"))?;
    let application_directory = executable
        .parent()
        .ok_or_else(|| "the ReSymbol executable has no application directory".to_owned())?;
    let helper_name = format!("resymbol-native-host{}", std::env::consts::EXE_SUFFIX);
    let helper_path = application_directory.join(helper_name);
    let metadata = fs::symlink_metadata(&helper_path).map_err(|error| {
        format!(
            "native helper is unavailable at {}: {error}",
            helper_path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "native helper at {} must be a regular, unlinked sibling executable",
            helper_path.display()
        ));
    }
    NativeProcessHost::new(helper_path, RuntimeLimits::default())
        .map_err(|error| format!("native helper is unavailable: {error}"))
}

fn managed_pe_image(analysis: &BinaryAnalysis) -> Option<ManagedPeImage> {
    match analysis {
        BinaryAnalysis::Pe(pe) if pe.identity.architecture == "x86_64" => ManagedPeImage::new(
            pe.identity.clone(),
            pe.size_of_headers,
            pe.size_of_image,
            pe.sections
                .iter()
                .map(|section| ManagedPeImageSection {
                    virtual_address: section.virtual_address,
                    virtual_size: section.virtual_size,
                    raw_data_offset: section.raw_data_offset,
                    raw_data_size: section.raw_data_size,
                })
                .collect(),
        )
        .ok(),
        _ => None,
    }
}

fn native_pe_image(analysis: &BinaryAnalysis) -> Option<NativePeImage> {
    match analysis {
        BinaryAnalysis::Pe(pe) => Some(NativePeImage {
            identity: pe.identity.clone(),
            size_of_headers: pe.size_of_headers,
            size_of_image: pe.size_of_image,
            sections: pe
                .sections
                .iter()
                .map(|section| NativePeImageSection {
                    virtual_address: section.virtual_address,
                    virtual_size: section.virtual_size,
                    raw_data_offset: section.raw_data_offset,
                    raw_data_size: section.raw_data_size,
                })
                .collect(),
        }),
        _ => None,
    }
}

fn wasm_pe_image(analysis: &BinaryAnalysis, binary_bytes: Arc<[u8]>) -> Option<WasmPeImage> {
    match analysis {
        BinaryAnalysis::Pe(pe) => WasmPeImage::new(
            pe.identity.clone(),
            pe.size_of_headers,
            pe.size_of_image,
            pe.sections
                .iter()
                .map(|section| WasmPeImageSection {
                    virtual_address: section.virtual_address,
                    virtual_size: section.virtual_size,
                    raw_data_offset: section.raw_data_offset,
                    raw_data_size: section.raw_data_size,
                })
                .collect(),
            binary_bytes,
        )
        .ok(),
        _ => None,
    }
}

fn requests_permission(
    manifest: &resymbol_core::plugin_api::PluginManifest,
    requested: &str,
) -> bool {
    manifest
        .permissions
        .iter()
        .any(|permission| permission.as_str() == requested)
}

fn strict_plugin_failure_count(attempts: &[PluginAttempt]) -> usize {
    attempts
        .iter()
        .filter(|attempt| attempt.status != PluginAttemptStatus::Succeeded)
        .count()
}

fn default_package_path(binary: &Path) -> PathBuf {
    binary.with_extension("resym")
}

fn print_session_summary(
    session: &AnalysisSession,
    code_recovery_availability: CodeRecoveryAvailability,
    transitive_thunk_recovery_availability: TransitiveThunkRecoveryAvailability,
    string_data_recovery_availability: StringDataRecoveryAvailability,
    rtti_recovery_availability: RttiRecoveryAvailability,
) -> Result<()> {
    print_analysis_summary(
        session.base_analysis(),
        code_recovery_availability,
        transitive_thunk_recovery_availability,
        string_data_recovery_availability,
        rtti_recovery_availability,
    );
    let succeeded = session
        .plugin_runs()
        .iter()
        .filter(|run| run.status().is_successful())
        .count();
    let failed = session.plugin_runs().len().saturating_sub(succeeded);
    println!(
        "plugin runs: {} ({succeeded} succeeded, {failed} failed)",
        session.plugin_runs().len()
    );
    for run in session.plugin_runs() {
        println!(
            "  {} {} {} run={} artifact={} claims={}",
            if run.status().is_successful() {
                "succeeded"
            } else {
                "failed"
            },
            run.plugin_id(),
            run.plugin_version(),
            run.run_id(),
            run.artifact_sha256(),
            run.accepted_claim_count()
        );
    }
    println!("plugin claims: {}", session.plugin_claims().len());
    println!(
        "combined claims: {}",
        session
            .combined_symbol_graph()
            .context("cannot construct combined symbol graph")?
            .claims()
            .len()
    );
    Ok(())
}

fn print_analysis_summary(
    analysis: &BinaryAnalysis,
    code_recovery_availability: CodeRecoveryAvailability,
    transitive_thunk_recovery_availability: TransitiveThunkRecoveryAvailability,
    string_data_recovery_availability: StringDataRecoveryAvailability,
    rtti_recovery_availability: RttiRecoveryAvailability,
) {
    let identity = analysis.identity();
    println!("size: {} bytes", identity.size);
    println!("sha256: {}", identity.id);
    println!("architecture: {}", identity.architecture);
    println!("image base: 0x{:x}", identity.image_base);

    match analysis {
        BinaryAnalysis::Pe(pe) => {
            let import_count = pe
                .imports
                .iter()
                .map(|library| library.entries.len())
                .sum::<usize>();
            let named_export_count = pe
                .exports
                .iter()
                .map(|export| export.names.len())
                .sum::<usize>();
            let forwarder_count = pe
                .exports
                .iter()
                .filter(|export| export.forwarded_to.is_some())
                .count();
            let rtti_type_count = pe
                .msvc_rtti_vftables
                .iter()
                .flat_map(|vftable| {
                    std::iter::once(vftable.type_descriptor_rva).chain(
                        vftable
                            .base_classes
                            .iter()
                            .map(|base| base.type_descriptor_rva),
                    )
                })
                .collect::<BTreeSet<_>>()
                .len();
            let rtti_slot_count = pe
                .msvc_rtti_vftables
                .iter()
                .map(|vftable| vftable.virtual_function_rvas.len())
                .sum::<usize>();
            let rtti_base_record_count = pe
                .msvc_rtti_vftables
                .iter()
                .map(|vftable| vftable.base_classes.len())
                .sum::<usize>();

            println!("format: PE32+ (x86-64)");
            println!("entry point: RVA 0x{:x}", pe.entry_point_rva);
            println!("sections: {}", pe.sections.len());
            println!(
                "imports: {} symbol(s) from {} library/libraries",
                import_count,
                pe.imports.len()
            );
            println!(
                "exports: {} slot(s), {} name(s), {} forwarder(s)",
                pe.exports.len(),
                named_export_count,
                forwarder_count
            );
            println!("runtime functions: {}", pe.runtime_functions.len());
            for line in code_recovery_summary_lines(pe, code_recovery_availability) {
                println!("{line}");
            }
            if let Some(line) = transitive_thunk_recovery_availability.summary_line() {
                println!("{line}");
            }
            for line in string_data_recovery_summary_lines(pe, string_data_recovery_availability) {
                println!("{line}");
            }
            println!(
                "MSVC RTTI: {} vftable(s), {rtti_type_count} type(s), {rtti_base_record_count} base record(s), {rtti_slot_count} virtual slot(s)",
                pe.msvc_rtti_vftables.len()
            );
            if let Some(line) = rtti_recovery_availability.summary_line() {
                println!("{line}");
            }
            if pe.msvc_rtti_scan_truncated {
                println!("MSVC RTTI scan: partial (a fixed discovery budget was reached)");
            }
        }
        _ => println!("format: supported extension format"),
    }

    println!("base claims: {}", analysis.symbol_graph().claims().len());
}

fn code_recovery_summary_lines(
    pe: &resymbol_analysis::PeAnalysis,
    availability: CodeRecoveryAvailability,
) -> Vec<String> {
    match availability {
        CodeRecoveryAvailability::Recorded => vec![
            format!("recovered direct calls: {}", pe.direct_calls.len()),
            format!("recovered thunks: {}", pe.thunks.len()),
            if pe.code_recovery_scan_truncated {
                "code recovery scan: partial (a fixed discovery budget was reached)".to_owned()
            } else {
                "code recovery scan: complete".to_owned()
            },
        ],
        CodeRecoveryAvailability::RecordedWithoutReadOnlyPointerControlFlow(schema_version) => vec![
            format!("recovered direct calls: {}", pe.direct_calls.len()),
            format!("recovered thunks: {}", pe.thunks.len()),
            if pe.code_recovery_scan_truncated {
                "code recovery scan: partial (a fixed discovery budget was reached)".to_owned()
            } else {
                "code recovery scan: complete".to_owned()
            },
            format!(
                "read-only function-pointer calls/thunks: unavailable (not recorded by schema {schema_version}; reanalyze the exact original binary)"
            ),
        ],
        CodeRecoveryAvailability::UnavailableSchema1 => vec![
            "recovered direct calls: unavailable (not recorded by schema 1)".to_owned(),
            "recovered thunks: unavailable (not recorded by schema 1)".to_owned(),
            "code recovery scan: not run (schema 1 package predates decoder data; reanalyze the exact original binary)"
                .to_owned(),
        ],
    }
}

fn string_data_recovery_summary_lines(
    pe: &resymbol_analysis::PeAnalysis,
    availability: StringDataRecoveryAvailability,
) -> [String; 4] {
    match availability {
        StringDataRecoveryAvailability::Recorded => [
            format!("recovered strings: {}", pe.strings.len()),
            if pe.string_recovery_scan_truncated {
                "string recovery scan: partial (fixed recovery limit reached; deterministic prefix retained)"
                    .to_owned()
            } else {
                "string recovery scan: complete".to_owned()
            },
            format!("recovered data references: {}", pe.data_references.len()),
            if pe.data_reference_scan_truncated {
                "data-reference recovery scan: partial (fixed recovery limit reached; deterministic prefix retained)"
                    .to_owned()
            } else {
                "data-reference recovery scan: complete".to_owned()
            },
        ],
        StringDataRecoveryAvailability::UnavailableSchema1 => {
            unavailable_string_data_summary_lines(1)
        }
        StringDataRecoveryAvailability::UnavailableSchema2 => {
            unavailable_string_data_summary_lines(2)
        }
    }
}

fn unavailable_string_data_summary_lines(schema_version: u32) -> [String; 4] {
    [
        format!("recovered strings: unavailable (not recorded by schema {schema_version})"),
        format!(
            "string recovery scan: not run (schema {schema_version} package predates string recovery data; reanalyze the exact original binary)"
        ),
        format!("recovered data references: unavailable (not recorded by schema {schema_version})"),
        format!(
            "data-reference recovery scan: not run (schema {schema_version} package predates data-reference recovery data; reanalyze the exact original binary)"
        ),
    ]
}

fn plugins(args: PluginArgs, safe_mode: bool, plugin_dir: PathBuf) -> Result<()> {
    match args.command {
        PluginCommand::List => list_plugins(&plugin_dir, safe_mode),
        PluginCommand::Doctor => doctor_plugins(&plugin_dir, safe_mode),
        PluginCommand::Enable { id } => set_plugin_enabled(&plugin_dir, &id, true),
        PluginCommand::Disable { id } => set_plugin_enabled(&plugin_dir, &id, false),
        PluginCommand::Trust { id, fingerprint } => {
            trust_plugin(&plugin_dir, &id, fingerprint.as_deref())
        }
        PluginCommand::Untrust { id } => {
            mutate_current_plugin_state(&plugin_dir, &id, PluginStateMutation::Untrust)
        }
        PluginCommand::Reset { id } => {
            mutate_current_plugin_state(&plugin_dir, &id, PluginStateMutation::Reset)
        }
    }
}

fn scan_plugins(
    plugin_dir: &Path,
    safe_mode: bool,
) -> Result<resymbol_core::PluginDiscoveryReport> {
    let options = PluginDiscoveryOptions {
        safe_mode,
        ..PluginDiscoveryOptions::default()
    };
    discover_plugins(plugin_dir, &options)
        .with_context(|| format!("cannot scan plugin directory {}", plugin_dir.display()))
}

fn list_plugins(plugin_dir: &Path, safe_mode: bool) -> Result<()> {
    let report = scan_plugins(plugin_dir, safe_mode)?;
    let store = PluginStateStore::new(plugin_dir);
    let mut policy_errors = 0_usize;
    println!("plugin directory: {}", report.root.display());
    println!("safe mode: {safe_mode}");

    if report.plugins.is_empty() {
        println!("no plugins discovered");
        return Ok(());
    }

    for plugin in &report.plugins {
        policy_errors = policy_errors.saturating_add(print_plugin(plugin, &store));
    }
    if policy_errors > 0 {
        bail!(
            "plugin listing found {policy_errors} fingerprint/state error(s); execution is denied"
        );
    }

    Ok(())
}

fn doctor_plugins(plugin_dir: &Path, safe_mode: bool) -> Result<()> {
    let report = scan_plugins(plugin_dir, safe_mode)?;
    let store = PluginStateStore::new(plugin_dir);
    let mut errors = 0usize;

    println!("validating plugins in {}", report.root.display());
    for plugin in &report.plugins {
        errors = errors.saturating_add(print_plugin(plugin, &store));
        errors += plugin
            .health
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
            .count();
    }

    println!(
        "doctor: {} plugin(s), {errors} error diagnostic(s)",
        report.plugins.len()
    );
    if errors > 0 {
        bail!("plugin validation found {errors} error diagnostic(s)");
    }

    Ok(())
}

fn print_plugin(plugin: &DiscoveredPlugin, store: &PluginStateStore) -> usize {
    let id = plugin.id().map_or("<unidentified>", |id| id.as_str());
    let runtime = plugin
        .manifest
        .as_ref()
        .map_or("package", |manifest| runtime_name(manifest.runtime.kind()));

    println!(
        "{}  {}  {}  {}",
        state_name(plugin.health.state),
        runtime,
        id,
        bounded_single_line(&plugin.path.display().to_string(), 1_024)
    );
    for diagnostic in &plugin.health.diagnostics {
        println!(
            "  {} {:?}: {}",
            severity_name(diagnostic.severity),
            diagnostic.code,
            bounded_single_line(&diagnostic.message, 768)
        );
    }

    if plugin.source != PluginSource::Directory || plugin.manifest.is_none() {
        return 0;
    }
    let report = match fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default()) {
        Ok(report) => report,
        Err(error) => {
            println!(
                "  error fingerprint: {}",
                bounded_single_line(&error.to_string(), 768)
            );
            return 1;
        }
    };
    println!(
        "  fingerprint: {} ({} file(s), {} byte(s))",
        report.fingerprint, report.file_count, report.total_bytes
    );
    let manifest = plugin
        .manifest
        .as_ref()
        .expect("valid directory branch checked above");
    let sandboxed_wasm = matches!(&manifest.runtime, PluginRuntime::Wasm { .. });
    let trust_policy = if sandboxed_wasm {
        ArtifactTrustPolicy::Sandboxed
    } else {
        ArtifactTrustPolicy::RequireApproval
    };
    let key = ArtifactStateKey::new(manifest.id.clone(), report.fingerprint);
    match store.execution_policy(&plugin.path, &key, trust_policy) {
        Ok(PluginExecutionPolicy::Allowed) if sandboxed_wasm => {
            println!("  policy: sandboxed-autoload");
            0
        }
        Ok(PluginExecutionPolicy::Allowed) => {
            println!("  policy: trusted");
            0
        }
        Ok(PluginExecutionPolicy::Disabled) => {
            println!("  policy: disabled");
            0
        }
        Ok(PluginExecutionPolicy::ApprovalRequired) => {
            println!("  policy: approval-required");
            0
        }
        Ok(PluginExecutionPolicy::Quarantined { reason }) => {
            println!(
                "  policy: quarantined ({})",
                bounded_single_line(&reason, 768)
            );
            0
        }
        Err(error) => {
            println!(
                "  error state: {}",
                bounded_single_line(&error.to_string(), 768)
            );
            1
        }
    }
}

fn trust_plugin(plugin_dir: &Path, id: &str, expected_fingerprint: Option<&str>) -> Result<()> {
    let report = scan_plugins(plugin_dir, false)?;
    let plugin = unique_valid_directory_plugin(&report, id)?;
    let manifest = plugin
        .manifest
        .as_ref()
        .expect("resolved valid directory plugin has a manifest");
    if matches!(&manifest.runtime, PluginRuntime::Wasm { .. }) {
        bail!(
            "plugin trust does not apply to sandboxed WASM plugins; {id} autoloads without ambient authority or an approval record (use plugin disable to block it)"
        );
    }
    let native_process = matches!(
        &manifest.runtime,
        PluginRuntime::Native {
            isolation: resymbol_core::plugin_api::NativeIsolation::OutOfProcess,
            ..
        }
    );
    let managed_process = matches!(&manifest.runtime, PluginRuntime::Managed { .. });
    if !matches!(&manifest.runtime, PluginRuntime::ExternalProcess { .. })
        && !managed_process
        && !native_process
    {
        let detail = if matches!(
            &manifest.runtime,
            PluginRuntime::Native {
                isolation: resymbol_core::plugin_api::NativeIsolation::InProcess,
                ..
            }
        ) {
            "in-process native execution is intentionally unsupported"
        } else {
            "this runtime has no implemented execution host"
        };
        bail!(
            "plugin trust does not apply to {} plugins ({detail}); {id} was not trusted",
            runtime_name(manifest.runtime.kind())
        );
    }
    let fingerprint = fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default())
        .with_context(|| format!("cannot fingerprint plugin `{id}`"))?
        .fingerprint;
    require_expected_fingerprint(expected_fingerprint, fingerprint)?;
    let key = ArtifactStateKey::new(manifest.id.clone(), fingerprint);
    let store = PluginStateStore::new(plugin_dir);
    match store.status(&key) {
        Ok(PluginArtifactStatus::ApprovalRequired | PluginArtifactStatus::Trusted) => {}
        Ok(PluginArtifactStatus::Quarantined { reason }) => bail!(
            "plugin {id}@{fingerprint} is quarantined ({}); run plugin reset before trusting it",
            bounded_single_line(&reason, 768)
        ),
        Err(error) => bail!(
            "plugin state is unsafe or corrupt: {}",
            bounded_single_line(&error.to_string(), 768)
        ),
    }

    println!(
        "plugin: {} ({})",
        bounded_single_line(&manifest.name, 512),
        manifest.id
    );
    println!(
        "executable: {}",
        bounded_single_line(
            &plugin
                .path
                .join(manifest.runtime.entrypoint())
                .display()
                .to_string(),
            1_024
        )
    );
    if let PluginRuntime::ExternalProcess { args, .. } = &manifest.runtime {
        println!(
            "arguments (literal values; escaped and bounded for display; no shell interpretation):"
        );
        if args.is_empty() {
            println!("  (none)");
        } else {
            for (index, argument) in args.iter().enumerate() {
                println!(
                    "  [{index}] {}",
                    bounded_single_line(&format!("{argument:?}"), 1_024)
                );
            }
        }
    }
    println!("fingerprint: {fingerprint}");
    println!("declared permissions:");
    if manifest.permissions.is_empty() {
        println!("  (none)");
    } else {
        for permission in &manifest.permissions {
            println!("  {}", permission.as_str());
        }
    }
    if native_process {
        println!(
            "WARNING: this native library executes in a disposable helper process with your account's ambient filesystem, network, and process authority. The helper contains ordinary crashes; it is not an operating-system sandbox, and protocol permissions are advisory."
        );
    } else if managed_process {
        println!(
            "WARNING: this managed assembly executes in a disposable helper process with your account's ambient filesystem, network, and process authority. The helper contains ordinary crashes; it is not an operating-system sandbox, and protocol permissions are advisory."
        );
    } else {
        println!(
            "WARNING: this plugin executes with your account's ambient filesystem, network, and process authority. Protocol permissions are advisory and are not an operating-system sandbox."
        );
    }

    let change = store
        .trust(&key)
        .with_context(|| format!("cannot record trust for plugin `{id}`"))?;
    match change {
        StateChange::Changed => println!("trusted exact plugin artifact {id}@{fingerprint}"),
        StateChange::Unchanged => {
            println!("exact plugin artifact {id}@{fingerprint} is already trusted");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum PluginStateMutation {
    Untrust,
    Reset,
}

fn mutate_current_plugin_state(
    plugin_dir: &Path,
    id: &str,
    mutation: PluginStateMutation,
) -> Result<()> {
    let report = scan_plugins(plugin_dir, false)?;
    let plugin = unique_valid_directory_plugin(&report, id)?;
    let manifest = plugin
        .manifest
        .as_ref()
        .expect("resolved valid directory plugin has a manifest");
    let fingerprint = fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default())
        .with_context(|| format!("cannot fingerprint plugin `{id}`"))?
        .fingerprint;
    let key = ArtifactStateKey::new(manifest.id.clone(), fingerprint);
    let store = PluginStateStore::new(plugin_dir);
    let change = match mutation {
        PluginStateMutation::Untrust => store.untrust(&key),
        PluginStateMutation::Reset => store.reset(&key),
    }
    .with_context(|| format!("cannot update state for plugin `{id}`"))?;

    let action = match mutation {
        PluginStateMutation::Untrust => "trust removal",
        PluginStateMutation::Reset => "quarantine reset",
    };
    match change {
        StateChange::Changed => println!("{action} completed for {id}@{fingerprint}"),
        StateChange::Unchanged => println!("{action} was already clear for {id}@{fingerprint}"),
    }
    Ok(())
}

fn unique_valid_directory_plugin<'a>(
    report: &'a resymbol_core::PluginDiscoveryReport,
    id: &str,
) -> Result<&'a DiscoveredPlugin> {
    let requested = PluginId::new(id.to_owned())
        .with_context(|| format!("invalid plugin identifier `{id}`"))?;
    let matches = report
        .plugins
        .iter()
        .filter(|plugin| {
            plugin.source == PluginSource::Directory
                && plugin.id().is_some_and(|plugin_id| plugin_id == &requested)
        })
        .collect::<Vec<_>>();
    let [plugin] = matches.as_slice() else {
        if matches.is_empty() {
            bail!(
                "plugin `{id}` was not found as a valid directory plugin in {}",
                report.root.display()
            );
        }
        bail!("plugin id `{id}` is duplicated; no state was changed");
    };
    let manifest = plugin
        .manifest
        .as_ref()
        .expect("plugins with an ID have a manifest");
    manifest
        .validate()
        .with_context(|| format!("plugin `{id}` does not have a valid manifest"))?;
    if matches!(
        plugin.health.state,
        PluginHealthState::Incompatible
            | PluginHealthState::Quarantined
            | PluginHealthState::DevelopmentError
    ) {
        bail!(
            "plugin `{id}` is not valid for this host ({})",
            state_name(plugin.health.state)
        );
    }
    Ok(plugin)
}

fn require_expected_fingerprint(expected: Option<&str>, actual: ArtifactFingerprint) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected = expected
        .parse::<ArtifactFingerprint>()
        .with_context(|| format!("invalid expected fingerprint `{expected}`"))?;
    if expected != actual {
        bail!("plugin fingerprint mismatch: expected {expected}, current artifact is {actual}");
    }
    Ok(())
}

/// Create the disable sentinel without following or overwriting an attacker-controlled path.
/// Returns true when this call created it and false for an existing regular sentinel.
fn create_disabled_sentinel(plugin_path: &Path) -> Result<bool> {
    let root_metadata = fs::symlink_metadata(plugin_path)
        .with_context(|| format!("cannot inspect plugin directory {}", plugin_path.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        bail!(
            "plugin path is linked or not a directory: {}",
            plugin_path.display()
        );
    }

    let sentinel = plugin_path.join(PLUGIN_DISABLED_SENTINEL);
    for _ in 0..2 {
        match fs::symlink_metadata(&sentinel) {
            Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_file() => {
                return Ok(false);
            }
            Ok(_) => bail!(
                "disable sentinel is linked or has an unsafe file type: {}",
                sentinel.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&sentinel)
                {
                    Ok(file) => {
                        file.sync_all().with_context(|| {
                            format!("cannot flush disable sentinel {}", sentinel.display())
                        })?;
                        return Ok(true);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("cannot create disable sentinel {}", sentinel.display())
                        });
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect disable sentinel {}", sentinel.display())
                });
            }
        }
    }
    bail!(
        "disable sentinel changed repeatedly while being created: {}",
        sentinel.display()
    )
}

fn set_plugin_enabled(plugin_dir: &Path, id: &str, enabled: bool) -> Result<()> {
    let report = scan_plugins(plugin_dir, false)?;
    let matches = report
        .plugins
        .iter()
        .filter(|plugin| {
            plugin
                .id()
                .is_some_and(|plugin_id| plugin_id.as_str() == id)
        })
        .collect::<Vec<_>>();

    let [plugin] = matches.as_slice() else {
        if matches.is_empty() {
            bail!("plugin `{id}` was not found in {}", plugin_dir.display());
        }
        bail!("plugin id `{id}` is duplicated; resolve the duplicate before changing it");
    };
    if plugin.source != PluginSource::Directory {
        bail!("packaged plugins cannot be toggled until package installation is implemented");
    }

    let sentinel = plugin.path.join(PLUGIN_DISABLED_SENTINEL);
    if enabled {
        match fs::remove_file(&sentinel) {
            Ok(()) => println!("enabled plugin {id}"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                println!("plugin {id} is already enabled");
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot remove disable sentinel {}", sentinel.display())
                });
            }
        }
    } else if create_disabled_sentinel(&plugin.path)? {
        println!("disabled plugin {id}");
    } else {
        println!("plugin {id} is already disabled");
    }

    Ok(())
}

const fn state_name(state: PluginHealthState) -> &'static str {
    match state {
        PluginHealthState::Discovered => "discovered",
        PluginHealthState::Enabled => "enabled",
        PluginHealthState::Disabled => "disabled",
        PluginHealthState::Incompatible => "incompatible",
        PluginHealthState::Quarantined => "quarantined",
        PluginHealthState::DevelopmentError => "development-error",
        _ => "unknown",
    }
}

const fn runtime_name(runtime: PluginRuntimeKind) -> &'static str {
    match runtime {
        PluginRuntimeKind::Wasm => "wasm",
        PluginRuntimeKind::Native => "native",
        PluginRuntimeKind::Managed => "managed",
        PluginRuntimeKind::ExternalProcess => "external-process",
        PluginRuntimeKind::ToolAdapter => "tool-adapter",
    }
}

const fn severity_name(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PE_OFFSET: usize = 0x80;
    const COFF_OFFSET: usize = PE_OFFSET + 4;
    const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
    const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 0xf0;
    const RAW_OFFSET: usize = 0x200;
    const SECTION_RVA: u32 = 0x1000;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_c_string(bytes: &mut [u8], offset: usize, value: &str) {
        let encoded = value.as_bytes();
        bytes[offset..offset + encoded.len()].copy_from_slice(encoded);
        bytes[offset + encoded.len()] = 0;
    }

    fn file_offset(rva: u32) -> usize {
        RAW_OFFSET + usize::try_from(rva - SECTION_RVA).expect("fixture RVA fits usize")
    }

    fn set_directory(bytes: &mut [u8], index: usize, rva: u32, size: u32) {
        let offset = OPTIONAL_OFFSET + 112 + index * 8;
        put_u32(bytes, offset, rva);
        put_u32(bytes, offset + 4, size);
    }

    fn pe_fixture() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x800];
        bytes[0..2].copy_from_slice(b"MZ");
        put_u32(
            &mut bytes,
            0x3c,
            u32::try_from(PE_OFFSET).expect("fixture offset"),
        );
        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        put_u16(&mut bytes, COFF_OFFSET, 0x8664);
        put_u16(&mut bytes, COFF_OFFSET + 2, 1);
        put_u32(&mut bytes, COFF_OFFSET + 4, 0x1234_5678);
        put_u16(&mut bytes, COFF_OFFSET + 16, 0xf0);
        put_u16(&mut bytes, COFF_OFFSET + 18, 0x2022);

        put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1000);
        put_u64(&mut bytes, OPTIONAL_OFFSET + 24, 0x0000_0001_4000_0000);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x2000);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x200);
        put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
        put_u16(&mut bytes, OPTIONAL_OFFSET + 70, 0x8160);
        put_u32(&mut bytes, OPTIONAL_OFFSET + 108, 16);
        set_directory(&mut bytes, 0, 0x1100, 0x90);
        set_directory(&mut bytes, 1, 0x1200, 40);
        set_directory(&mut bytes, 3, 0x1300, 12);

        bytes[SECTION_OFFSET..SECTION_OFFSET + 5].copy_from_slice(b".all\0");
        put_u32(&mut bytes, SECTION_OFFSET + 8, 0x600);
        put_u32(&mut bytes, SECTION_OFFSET + 12, SECTION_RVA);
        put_u32(&mut bytes, SECTION_OFFSET + 16, 0x600);
        put_u32(
            &mut bytes,
            SECTION_OFFSET + 20,
            u32::try_from(RAW_OFFSET).expect("fixture raw offset"),
        );
        put_u32(&mut bytes, SECTION_OFFSET + 36, 0x6000_0020);

        let export = file_offset(0x1100);
        put_u32(&mut bytes, export + 12, 0x1180);
        put_u32(&mut bytes, export + 16, 1);
        put_u32(&mut bytes, export + 20, 2);
        put_u32(&mut bytes, export + 24, 2);
        put_u32(&mut bytes, export + 28, 0x1140);
        put_u32(&mut bytes, export + 32, 0x1148);
        put_u32(&mut bytes, export + 36, 0x1150);
        put_u32(&mut bytes, file_offset(0x1140), 0x1000);
        put_u32(&mut bytes, file_offset(0x1144), 0);
        put_u32(&mut bytes, file_offset(0x1148), 0x1160);
        put_u32(&mut bytes, file_offset(0x114c), 0x1168);
        put_u16(&mut bytes, file_offset(0x1150), 0);
        put_u16(&mut bytes, file_offset(0x1152), 0);
        put_c_string(&mut bytes, file_offset(0x1160), "ExportA");
        put_c_string(&mut bytes, file_offset(0x1168), "Alias");
        put_c_string(&mut bytes, file_offset(0x1180), "fixture.dll");

        let import = file_offset(0x1200);
        put_u32(&mut bytes, import, 0x1240);
        put_u32(&mut bytes, import + 4, 0x1111_1111);
        put_u32(&mut bytes, import + 8, 0xffff_ffff);
        put_u32(&mut bytes, import + 12, 0x1280);
        put_u32(&mut bytes, import + 16, 0x1260);
        put_u64(&mut bytes, file_offset(0x1240), 0x1290);
        put_u64(&mut bytes, file_offset(0x1248), (1_u64 << 63) | 42);
        put_u64(&mut bytes, file_offset(0x1250), 0);
        put_c_string(&mut bytes, file_offset(0x1280), "KERNEL32.dll");
        put_u16(&mut bytes, file_offset(0x1290), 7);
        put_c_string(&mut bytes, file_offset(0x1292), "Imported");

        let exception = file_offset(0x1300);
        put_u32(&mut bytes, exception, 0x1000);
        put_u32(&mut bytes, exception + 4, 0x1020);
        put_u32(&mut bytes, exception + 8, 0x1350);
        bytes
    }

    fn pe_pdb_fixture() -> Vec<u8> {
        const RAW_GUID: [u8; 16] = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        const DEBUG_DIRECTORY_RVA: u32 = 0x1380;
        const CODEVIEW_RVA: u32 = 0x1400;

        let mut bytes = pe_fixture();
        let mut record = Vec::new();
        record.extend_from_slice(b"RSDS");
        record.extend_from_slice(&RAW_GUID);
        record.extend_from_slice(&7_u32.to_le_bytes());
        record.extend_from_slice(b"resymbol-rsds-x64.pdb\0");

        set_directory(&mut bytes, 6, DEBUG_DIRECTORY_RVA, 28);
        let debug = file_offset(DEBUG_DIRECTORY_RVA);
        put_u32(&mut bytes, debug + 12, 2);
        put_u32(
            &mut bytes,
            debug + 16,
            u32::try_from(record.len()).expect("fixture CodeView record size"),
        );
        put_u32(&mut bytes, debug + 20, CODEVIEW_RVA);
        put_u32(
            &mut bytes,
            debug + 24,
            u32::try_from(file_offset(CODEVIEW_RVA)).expect("fixture CodeView file offset"),
        );
        let record_offset = file_offset(CODEVIEW_RVA);
        bytes[record_offset..record_offset + record.len()].copy_from_slice(&record);
        bytes
    }

    fn pe_code_recovery_fixture() -> Vec<u8> {
        let mut bytes = pe_fixture();

        set_directory(&mut bytes, 3, 0x1300, 24);
        let exception = file_offset(0x1300);
        put_u32(&mut bytes, exception + 4, 0x1010);
        put_u32(&mut bytes, exception + 12, 0x1010);
        put_u32(&mut bytes, exception + 16, 0x1020);
        put_u32(&mut bytes, exception + 20, 0x1350);

        let call = file_offset(0x1000);
        bytes[call] = 0xe8;
        put_u32(&mut bytes, call + 1, 0x0b);

        let thunk = file_offset(0x1010);
        bytes[thunk..thunk + 2].copy_from_slice(&[0xff, 0x25]);
        put_u32(&mut bytes, thunk + 2, 0x24a);
        bytes
    }

    fn pe_transitive_thunk_chain_fixture() -> Vec<u8> {
        let mut bytes = pe_code_recovery_fixture();

        let first_thunk = file_offset(0x1010);
        bytes[first_thunk] = 0xe9;
        put_u32(&mut bytes, first_thunk + 1, 0x0b);

        let second_thunk = file_offset(0x1020);
        bytes[second_thunk] = 0xe9;
        put_u32(&mut bytes, second_thunk + 1, 0x0b);
        bytes
    }

    fn create_plugin(root: &Path, id: &str) -> PathBuf {
        let plugin = root.join("example");
        fs::create_dir(&plugin).expect("create plugin directory");
        fs::write(plugin.join("plugin.wasm"), b"placeholder").expect("write entrypoint");
        fs::write(
            plugin.join("plugin.toml"),
            format!(
                r#"manifest_version = 1
id = "{id}"
name = "CLI test plugin"
version = "0.1.0"
api = "^0.1.0"

[runtime]
kind = "wasm"
entrypoint = "plugin.wasm"
"#
            ),
        )
        .expect("write manifest");
        plugin
    }

    fn create_external_plugin(root: &Path, id: &str) -> PathBuf {
        let plugin = root.join("external");
        fs::create_dir(&plugin).expect("create external plugin directory");
        fs::write(plugin.join("plugin.bin"), b"executable-v1").expect("write entrypoint");
        fs::write(
            plugin.join("plugin.toml"),
            format!(
                r#"manifest_version = 1
id = "{id}"
name = "External CLI test plugin"
version = "1.2.3"
api = "^0.1.0"
capabilities = ["analyzer.binary"]
permissions = ["claims.submit", "symbols.read"]

[runtime]
kind = "external-process"
entrypoint = "plugin.bin"
args = ["--stdio", "literal argument"]
"#
            ),
        )
        .expect("write external plugin manifest");
        plugin
    }

    fn create_native_plugin(root: &Path, id: &str, isolation: &str) -> PathBuf {
        let plugin = root.join("native");
        fs::create_dir(&plugin).expect("create native plugin directory");
        fs::write(plugin.join("plugin.native"), b"native-placeholder")
            .expect("write native entrypoint");
        let permissions = if isolation == "in-process" {
            r#"["binary.read", "claims.submit", "unsafe.in-process"]"#
        } else {
            r#"["binary.read", "claims.submit"]"#
        };
        fs::write(
            plugin.join("plugin.toml"),
            format!(
                r#"manifest_version = 1
id = "{id}"
name = "Native CLI test plugin"
version = "1.2.3"
api = "^0.1.0"
capabilities = ["analyzer.binary"]
permissions = {permissions}

[runtime]
kind = "native"
entrypoint = "plugin.native"
isolation = "{isolation}"
"#
            ),
        )
        .expect("write native plugin manifest");
        plugin
    }

    fn create_managed_plugin(root: &Path, id: &str) -> PathBuf {
        let plugin = root.join("managed");
        fs::create_dir(&plugin).expect("create managed plugin directory");
        fs::write(plugin.join("Plugin.dll"), b"managed-placeholder")
            .expect("write managed entry assembly");
        fs::write(
            plugin.join("plugin.toml"),
            format!(
                r#"manifest_version = 1
id = "{id}"
name = "Managed CLI test plugin"
version = "1.2.3"
api = "^0.1.0"
capabilities = ["analyzer.binary"]
permissions = ["binary.read", "claims.submit"]

[runtime]
kind = "managed"
entrypoint = "Plugin.dll"
"#
            ),
        )
        .expect("write managed plugin manifest");
        plugin
    }

    fn only_state_record(store: &PluginStateStore, kind: &str) -> PathBuf {
        let directory = store.state_root().join("v1").join(kind);
        let records = fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
            .map(|entry| entry.expect("read plugin state record").path())
            .collect::<Vec<_>>();
        let [record] = records.as_slice() else {
            panic!(
                "expected one {kind} record below {}, found {}",
                directory.display(),
                records.len()
            )
        };
        record.clone()
    }

    #[test]
    fn disable_and_enable_manage_the_recovery_sentinel() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let plugin = create_plugin(temp.path(), "dev.resymbol.cli-test");
        let sentinel = plugin.join(PLUGIN_DISABLED_SENTINEL);

        set_plugin_enabled(temp.path(), "dev.resymbol.cli-test", false).expect("disable plugin");
        assert!(sentinel.is_file());
        let report = scan_plugins(temp.path(), false).expect("scan disabled plugin");
        assert_eq!(report.plugins[0].health.state, PluginHealthState::Disabled);

        set_plugin_enabled(temp.path(), "dev.resymbol.cli-test", true).expect("enable plugin");
        assert!(!sentinel.exists());
        let report = scan_plugins(temp.path(), false).expect("scan enabled plugin");
        assert_eq!(report.plugins[0].health.state, PluginHealthState::Enabled);
    }

    #[cfg(unix)]
    #[test]
    fn disable_sentinel_never_follows_an_existing_link() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("create temporary directory");
        let plugin = create_plugin(temp.path(), "dev.resymbol.cli-test");
        let target = temp.path().join("sentinel-target");
        fs::write(&target, b"must remain unchanged").expect("write link target");
        symlink(&target, plugin.join(PLUGIN_DISABLED_SENTINEL)).expect("create sentinel link");

        let error = create_disabled_sentinel(&plugin)
            .expect_err("linked disable sentinel must be rejected");
        assert!(error.to_string().contains("unsafe file type"));
        assert_eq!(
            fs::read(&target).expect("read preserved link target"),
            b"must remain unchanged"
        );
    }

    #[test]
    fn command_line_accepts_analysis_output_and_json_inspection() {
        let cli = Cli::try_parse_from([
            "resymbol",
            "analyze",
            "application.exe",
            "--output",
            "analysis.resym",
            "--plugin",
            "dev.resymbol.first",
            "--plugin",
            "dev.resymbol.second",
            "--strict-plugins",
        ])
        .expect("analyze arguments parse");
        let Command::Analyze(args) = cli.command else {
            panic!("analyze command expected");
        };
        assert_eq!(args.binary, PathBuf::from("application.exe"));
        assert_eq!(args.output, Some(PathBuf::from("analysis.resym")));
        assert_eq!(
            args.plugins,
            [
                "dev.resymbol.first".to_owned(),
                "dev.resymbol.second".to_owned()
            ]
        );
        assert!(args.strict_plugins);

        let cli = Cli::try_parse_from(["resymbol", "inspect", "analysis.resym", "--json"])
            .expect("inspect arguments parse");
        let Command::Inspect(args) = cli.command else {
            panic!("inspect command expected");
        };
        assert_eq!(args.package, PathBuf::from("analysis.resym"));
        assert!(args.json);
    }

    #[test]
    fn command_line_accepts_all_export_formats() {
        for (value, expected) in [
            ("json", ExportFormat::Json),
            ("markdown", ExportFormat::Markdown),
            ("map", ExportFormat::Map),
            ("ida-python", ExportFormat::IdaPython),
            ("ghidra-java", ExportFormat::GhidraJava),
        ] {
            let cli = Cli::try_parse_from([
                "resymbol",
                "export",
                "analysis.resym",
                "--format",
                value,
                "--output",
                "symbols.out",
            ])
            .expect("export arguments parse");
            let Command::Export(args) = cli.command else {
                panic!("export command expected");
            };
            assert_eq!(args.package, PathBuf::from("analysis.resym"));
            assert_eq!(args.format, expected);
            assert_eq!(args.output, Some(PathBuf::from("symbols.out")));
            assert_eq!(args.binary, None);
        }

        let error =
            Cli::try_parse_from(["resymbol", "export", "analysis.resym", "--format", "pdb"])
                .expect_err("PDB format requires its exact source PE at argument parsing time");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(error.to_string().contains("--binary <EXACT_ORIGINAL_PE>"));

        let cli = Cli::try_parse_from([
            "resymbol",
            "export",
            "analysis.resym",
            "--format",
            "pdb",
            "--binary",
            "application.exe",
        ])
        .expect("PDB source binary argument parses");
        let Command::Export(args) = cli.command else {
            panic!("export command expected");
        };
        assert_eq!(args.binary, Some(PathBuf::from("application.exe")));
    }

    #[test]
    fn source_binary_option_is_rejected_for_non_pdb_formats() {
        let error = export(ExportArgs {
            package: PathBuf::from("does-not-need-to-exist.resym"),
            format: ExportFormat::Json,
            output: None,
            binary: Some(PathBuf::from("application.exe")),
        })
        .expect_err("non-PDB export must not accept a misleading source binary");
        assert!(error.to_string().contains("only with --format pdb"));
    }

    #[test]
    fn analysis_summary_reports_code_recovery_counts_and_completion_state() {
        let mut analysis = analyze_bytes(&pe_code_recovery_fixture()).expect("analyze fixture");
        let BinaryAnalysis::Pe(pe) = &mut analysis else {
            panic!("PE analysis expected");
        };
        assert_eq!(pe.direct_calls.len(), 1);
        assert_eq!(pe.thunks.len(), 1);
        assert_eq!(
            code_recovery_summary_lines(pe, CodeRecoveryAvailability::Recorded),
            [
                "recovered direct calls: 1".to_owned(),
                "recovered thunks: 1".to_owned(),
                "code recovery scan: complete".to_owned(),
            ]
        );

        pe.code_recovery_scan_truncated = true;
        assert_eq!(
            code_recovery_summary_lines(pe, CodeRecoveryAvailability::Recorded)[2],
            "code recovery scan: partial (a fixed discovery budget was reached)"
        );
    }

    #[test]
    fn schema_v1_summary_reports_code_recovery_as_unavailable() {
        let analysis = analyze_bytes(&pe_code_recovery_fixture()).expect("analyze fixture");
        let BinaryAnalysis::Pe(pe) = &analysis else {
            panic!("PE analysis expected");
        };

        assert_eq!(
            code_recovery_summary_lines(pe, CodeRecoveryAvailability::UnavailableSchema1),
            [
                "recovered direct calls: unavailable (not recorded by schema 1)".to_owned(),
                "recovered thunks: unavailable (not recorded by schema 1)".to_owned(),
                "code recovery scan: not run (schema 1 package predates decoder data; reanalyze the exact original binary)"
                    .to_owned(),
            ]
        );
        assert_eq!(
            CodeRecoveryAvailability::UnavailableSchema1.export_summary_line(),
            Some(
                "code recovery: unavailable (schema 1 package predates decoder data; reanalyze the exact original binary)"
                    .to_owned()
            )
        );
        assert_eq!(
            CodeRecoveryAvailability::Recorded.export_summary_line(),
            None
        );
        assert_eq!(
            TransitiveThunkRecoveryAvailability::UnavailableSchema1.summary_line(),
            None
        );
        assert_eq!(
            TransitiveThunkRecoveryAvailability::Recorded.summary_line(),
            None
        );
    }

    #[test]
    fn schema_v2_and_v3_summaries_preserve_code_recovery_but_mark_pointer_control_flow_unavailable()
    {
        let analysis = analyze_bytes(&pe_code_recovery_fixture()).expect("analyze fixture");
        let BinaryAnalysis::Pe(pe) = &analysis else {
            panic!("PE analysis expected");
        };

        for schema_version in [2, 3] {
            let availability =
                CodeRecoveryAvailability::RecordedWithoutReadOnlyPointerControlFlow(schema_version);
            assert_eq!(
                code_recovery_summary_lines(pe, availability),
                [
                    "recovered direct calls: 1".to_owned(),
                    "recovered thunks: 1".to_owned(),
                    "code recovery scan: complete".to_owned(),
                    format!(
                        "read-only function-pointer calls/thunks: unavailable (not recorded by schema {schema_version}; reanalyze the exact original binary)"
                    ),
                ]
            );
            assert_eq!(
                availability.export_summary_line(),
                Some(format!(
                    "read-only function-pointer call/thunk resolution: unavailable (schema {schema_version} package predates this recovery data; reanalyze the exact original binary)"
                ))
            );
        }
    }

    #[test]
    fn schemas_v2_through_v5_mark_transitive_thunk_chain_recovery_unavailable() {
        for schema_version in 2..=5 {
            let availability =
                TransitiveThunkRecoveryAvailability::RecordedWithoutTransitiveThunkChains(
                    schema_version,
                );
            assert_eq!(
                availability.summary_line(),
                Some(format!(
                    "transitive exact thunk-chain recovery: unavailable (schema {schema_version} package predates this recovery; existing one-hop thunks remain available; reanalyze the exact original binary)"
                ))
            );
        }
    }

    #[test]
    fn string_and_data_recovery_summary_reports_counts_and_independent_partial_scans() {
        let mut analysis = analyze_bytes(&pe_code_recovery_fixture()).expect("analyze fixture");
        let BinaryAnalysis::Pe(pe) = &mut analysis else {
            panic!("PE analysis expected");
        };
        assert_eq!(
            string_data_recovery_summary_lines(pe, StringDataRecoveryAvailability::Recorded),
            [
                format!("recovered strings: {}", pe.strings.len()),
                "string recovery scan: complete".to_owned(),
                format!("recovered data references: {}", pe.data_references.len()),
                "data-reference recovery scan: complete".to_owned(),
            ]
        );

        pe.string_recovery_scan_truncated = true;
        assert_eq!(
            string_data_recovery_summary_lines(pe, StringDataRecoveryAvailability::Recorded)[1],
            "string recovery scan: partial (fixed recovery limit reached; deterministic prefix retained)"
        );
        assert_eq!(
            string_data_recovery_summary_lines(pe, StringDataRecoveryAvailability::Recorded)[3],
            "data-reference recovery scan: complete"
        );

        pe.data_reference_scan_truncated = true;
        assert_eq!(
            string_data_recovery_summary_lines(pe, StringDataRecoveryAvailability::Recorded)[3],
            "data-reference recovery scan: partial (fixed recovery limit reached; deterministic prefix retained)"
        );
    }

    #[test]
    fn prior_schema_summaries_report_string_and_data_recovery_as_unavailable() {
        let analysis = analyze_bytes(&pe_code_recovery_fixture()).expect("analyze fixture");
        let BinaryAnalysis::Pe(pe) = &analysis else {
            panic!("PE analysis expected");
        };

        for (availability, schema_version) in [
            (StringDataRecoveryAvailability::UnavailableSchema1, 1),
            (StringDataRecoveryAvailability::UnavailableSchema2, 2),
        ] {
            assert_eq!(
                string_data_recovery_summary_lines(pe, availability),
                [
                    format!(
                        "recovered strings: unavailable (not recorded by schema {schema_version})"
                    ),
                    format!(
                        "string recovery scan: not run (schema {schema_version} package predates string recovery data; reanalyze the exact original binary)"
                    ),
                    format!(
                        "recovered data references: unavailable (not recorded by schema {schema_version})"
                    ),
                    format!(
                        "data-reference recovery scan: not run (schema {schema_version} package predates data-reference recovery data; reanalyze the exact original binary)"
                    ),
                ]
            );
        }
        assert_eq!(
            StringDataRecoveryAvailability::UnavailableSchema1.export_summary_line(),
            Some(
                "string/data recovery: unavailable (schema 1 package predates string and data-reference recovery data; reanalyze the exact original binary)"
            )
        );
        assert_eq!(
            StringDataRecoveryAvailability::UnavailableSchema2.export_summary_line(),
            Some(
                "string/data recovery: unavailable (schema 2 package predates string and data-reference recovery data; reanalyze the exact original binary)"
            )
        );
        assert_eq!(
            StringDataRecoveryAvailability::Recorded.export_summary_line(),
            None
        );
    }

    #[test]
    fn prior_schema_summaries_preserve_rtti_but_mark_no_pchd_descriptors_unavailable() {
        for schema_version in 1..=4 {
            let availability =
                RttiRecoveryAvailability::RecordedWithoutNoPchdBaseDescriptors(schema_version);
            assert_eq!(
                availability.summary_line(),
                Some(format!(
                    "MSVC RTTI 24-byte base descriptors without pCHD: unavailable (schema {schema_version} predates this recovery; existing recorded RTTI remains available; reanalyze the exact original binary for current coverage)"
                ))
            );
        }
        assert_eq!(RttiRecoveryAvailability::Recorded.summary_line(), None);
    }

    #[test]
    fn command_line_accepts_exact_plugin_state_commands() {
        let fingerprint = "a".repeat(64);
        let cli = Cli::try_parse_from([
            "resymbol",
            "plugin",
            "trust",
            "dev.resymbol.external",
            "--fingerprint",
            fingerprint.as_str(),
        ])
        .expect("trust arguments parse");
        let Command::Plugin(args) = cli.command else {
            panic!("plugin command expected");
        };
        let PluginCommand::Trust {
            id,
            fingerprint: parsed,
        } = args.command
        else {
            panic!("trust command expected");
        };
        assert_eq!(id, "dev.resymbol.external");
        assert_eq!(parsed.as_deref(), Some(fingerprint.as_str()));

        for action in ["untrust", "reset"] {
            Cli::try_parse_from(["resymbol", "plugin", action, "dev.resymbol.external"])
                .expect("state mutation arguments parse");
        }
    }

    #[test]
    fn default_package_path_replaces_the_binary_extension() {
        assert_eq!(
            default_package_path(Path::new("build/application.exe")),
            PathBuf::from("build/application.resym")
        );
        assert_eq!(
            default_package_path(Path::new("build/application")),
            PathBuf::from("build/application.resym")
        );
    }

    #[test]
    fn export_defaults_and_ghidra_class_names_are_predictable() {
        let package = Path::new("build/application.resym");
        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            default_export_path(package, ExportFormat::Json, sha256),
            PathBuf::from("build/application.symbols.json")
        );
        assert_eq!(
            default_export_path(package, ExportFormat::Markdown, sha256),
            PathBuf::from("build/application.symbols.md")
        );
        assert_eq!(
            default_export_path(package, ExportFormat::Map, sha256),
            PathBuf::from("build/application.map")
        );
        assert_eq!(
            default_export_path(package, ExportFormat::Pdb, sha256),
            PathBuf::from("build/application.pdb")
        );
        assert_eq!(
            default_export_path(package, ExportFormat::IdaPython, sha256),
            PathBuf::from("build/application.ida.py")
        );
        let ghidra = default_export_path(package, ExportFormat::GhidraJava, sha256);
        assert_eq!(
            ghidra,
            PathBuf::from("build/ReSymbolImport_0123456789ab.java")
        );
        assert_eq!(
            ghidra_java_class_name(&ghidra).expect("valid default Ghidra class name"),
            "ReSymbolImport_0123456789ab"
        );
        assert_eq!(
            ghidra_java_class_name(Path::new("Re$Symbol.java"))
                .expect("dollar is valid in the documented conservative subset"),
            "Re$Symbol"
        );

        for invalid in ["Bad-Name.java", "class.java", "WrongExtension.py"] {
            assert!(
                ghidra_java_class_name(Path::new(invalid)).is_err(),
                "{invalid} must be rejected"
            );
        }

        assert_eq!(map_module_name(package, sha256), "application");
        assert_eq!(
            map_module_name(Path::new("build/My App!.resym"), sha256),
            "My_App_"
        );
        assert_eq!(
            map_module_name(Path::new("build/.."), sha256),
            "resymbol_0123456789ab"
        );
    }

    #[test]
    fn export_generates_all_formats_and_never_overwrites() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let binary = temp.path().join("fixture.exe");
        let package = temp.path().join("fixture.resym");
        let plugins = temp.path().join("plugins");
        fs::create_dir(&plugins).expect("create plugin directory");
        let bytes = pe_pdb_fixture();
        fs::write(&binary, &bytes).expect("write PE fixture");
        analyze(
            AnalyzeArgs {
                binary: binary.clone(),
                output: Some(package.clone()),
                plugins: Vec::new(),
                strict_plugins: false,
            },
            true,
            plugins,
        )
        .expect("analyze fixture");

        export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::Json,
            output: None,
            binary: None,
        })
        .expect("export JSON");
        let json_path = package.with_extension("symbols.json");
        let json_bytes = fs::read(&json_path).expect("read JSON export");
        let json: Value = serde_json::from_slice(&json_bytes).expect("parse JSON export");
        assert_eq!(json["schema_version"], Value::from(6_u64));
        assert_eq!(
            json["binary"]["id"],
            Value::String(BinaryId::digest(&bytes).to_string())
        );

        let error = export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::Json,
            output: None,
            binary: None,
        })
        .expect_err("existing export must not be overwritten");
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(
            fs::read(&json_path).expect("read preserved JSON export"),
            json_bytes
        );

        export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::Markdown,
            output: None,
            binary: None,
        })
        .expect("export Markdown report");
        let markdown_path = package.with_extension("symbols.md");
        let markdown_bytes = fs::read(&markdown_path).expect("read Markdown export");
        let markdown = std::str::from_utf8(&markdown_bytes).expect("Markdown export is UTF-8");
        assert!(markdown.contains(BinaryId::digest(&bytes).as_str()));

        let error = export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::Markdown,
            output: None,
            binary: None,
        })
        .expect_err("existing Markdown export must not be overwritten");
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(
            fs::read(&markdown_path).expect("read preserved Markdown export"),
            markdown_bytes
        );

        export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::Map,
            output: None,
            binary: None,
        })
        .expect("export Microsoft-linker-style MAP");
        let map_path = package.with_extension("map");
        let map_bytes = fs::read(&map_path).expect("read MAP export");
        let map = std::str::from_utf8(&map_bytes).expect("MAP export is UTF-8");
        assert!(map.contains("Publics by Value"));
        assert!(map.contains(BinaryId::digest(&bytes).as_str()));

        let error = export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::Map,
            output: None,
            binary: None,
        })
        .expect_err("existing MAP export must not be overwritten");
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(
            fs::read(&map_path).expect("read preserved MAP export"),
            map_bytes
        );

        let error = export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::Pdb,
            output: Some(temp.path().join("missing-source.pdb")),
            binary: None,
        })
        .expect_err("PDB export requires the exact source PE");
        assert!(error.to_string().contains("requires --binary"));

        let wrong_binary = temp.path().join("wrong.exe");
        let mut wrong_bytes = bytes.clone();
        *wrong_bytes.last_mut().expect("non-empty PE fixture") ^= 1;
        fs::write(&wrong_binary, wrong_bytes).expect("write mismatched PE fixture");
        let mismatched_output = temp.path().join("mismatched.pdb");
        let error = export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::Pdb,
            output: Some(mismatched_output.clone()),
            binary: Some(wrong_binary),
        })
        .expect_err("PDB export binds the exact PE digest");
        assert!(format!("{error:#}").contains("binary.id"));
        assert!(!mismatched_output.exists());

        export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::Pdb,
            output: None,
            binary: Some(binary.clone()),
        })
        .expect("export exact-RSDS public-symbol PDB");
        let pdb_path = package.with_extension("pdb");
        let pdb_bytes = fs::read(&pdb_path).expect("read PDB export");
        assert!(pdb_bytes.starts_with(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"));
        assert_eq!(pdb_bytes.len() % 4_096, 0);

        let error = export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::Pdb,
            output: None,
            binary: Some(binary.clone()),
        })
        .expect_err("existing PDB export must not be overwritten");
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(
            fs::read(&pdb_path).expect("read preserved PDB export"),
            pdb_bytes
        );

        export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::IdaPython,
            output: None,
            binary: None,
        })
        .expect("export IDA script");
        let ida_script =
            fs::read_to_string(package.with_extension("ida.py")).expect("read IDA Python export");
        assert!(ida_script.contains("retrieve_input_file_sha256"));
        assert!(ida_script.contains(BinaryId::digest(&bytes).as_str()));

        export(ExportArgs {
            package: package.clone(),
            format: ExportFormat::GhidraJava,
            output: None,
            binary: None,
        })
        .expect("export Ghidra script");
        let ghidra_path = default_export_path(
            &package,
            ExportFormat::GhidraJava,
            BinaryId::digest(&bytes).as_str(),
        );
        let ghidra_script = fs::read_to_string(&ghidra_path).expect("read Ghidra Java export");
        assert!(ghidra_script.contains("public class ReSymbolImport_"));
        assert!(ghidra_script.contains("getExecutableSHA256"));
        assert!(ghidra_script.contains(BinaryId::digest(&bytes).as_str()));

        let staged_exports = fs::read_dir(temp.path())
            .expect("read export test directory")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".resymbol-export-")
            })
            .count();
        assert_eq!(
            staged_exports, 0,
            "completed exports leave no staging files"
        );
    }

    #[test]
    fn analyze_writes_a_bound_package_without_overwriting() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let binary = temp.path().join("fixture.exe");
        let output = temp.path().join("fixture.resym");
        let plugins = temp.path().join("plugins");
        fs::create_dir(&plugins).expect("create plugin directory");
        let bytes = pe_fixture();
        fs::write(&binary, &bytes).expect("write PE fixture");

        analyze(
            AnalyzeArgs {
                binary: binary.clone(),
                output: Some(output.clone()),
                plugins: Vec::new(),
                strict_plugins: false,
            },
            true,
            plugins.clone(),
        )
        .expect("analyze fixture");

        let package: ResymPackage<AnalysisSession> =
            read_file_bound(&output).expect("read bound package");
        assert_eq!(CURRENT_SCHEMA_VERSION, 6);
        assert_eq!(package.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(
            package.binary_sha256(),
            &resymbol_core::BinaryId::digest(&bytes)
        );
        assert_eq!(
            &package.payload().base_analysis().identity().id,
            package.binary_sha256()
        );
        assert_eq!(
            package
                .payload()
                .base_analysis()
                .symbol_graph()
                .claims()
                .len(),
            5
        );
        assert!(package.payload().plugin_runs().is_empty());
        assert!(package.payload().plugin_claims().is_empty());
        assert_eq!(
            package
                .payload()
                .combined_symbol_graph()
                .expect("combine session graph")
                .claims()
                .len(),
            5
        );

        let original = fs::read(&output).expect("read original package bytes");
        let error = analyze(
            AnalyzeArgs {
                binary,
                output: Some(output.clone()),
                plugins: Vec::new(),
                strict_plugins: false,
            },
            true,
            plugins,
        )
        .expect_err("existing package must not be overwritten");
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(
            fs::read(&output).expect("read preserved package bytes"),
            original
        );

        inspect(InspectArgs {
            package: output.clone(),
            json: false,
        })
        .expect("inspect validates package");
        inspect(InspectArgs {
            package: output,
            json: true,
        })
        .expect("JSON inspection serializes validated package");
    }

    fn schema_v1_package_skeleton() -> (Value, BinaryId) {
        let base_analysis = analyze_bytes(&pe_fixture()).expect("analyze PE fixture");
        let binary = base_analysis.identity().id.clone();
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create base-only session");
        let package = ResymPackage::from_bound_payload("0.1.0-alpha.1", session)
            .expect("create current package value");
        let mut value = serde_json::to_value(package).expect("serialize package value");
        value["schema_version"] = serde_json::json!(1);

        let pe = value
            .pointer_mut("/payload/base_analysis/analysis")
            .and_then(Value::as_object_mut)
            .expect("serialized PE analysis object");
        for field in [
            "code_recovery_scan_truncated",
            "direct_calls",
            "thunks",
            "string_recovery_scan_truncated",
            "strings",
            "data_reference_scan_truncated",
            "data_references",
        ] {
            pe.remove(field);
        }
        pe.get_mut("symbol_graph")
            .and_then(|graph| graph.get_mut("claims"))
            .and_then(Value::as_array_mut)
            .expect("serialized base claims")
            .retain(|claim| {
                !matches!(
                    claim.pointer("/assertion/kind").and_then(Value::as_str),
                    Some(
                        "function-entry"
                            | "direct-call"
                            | "thunk-target"
                            | "string-literal"
                            | "data-reference"
                    )
                )
            });
        (value, binary)
    }

    fn schema_v1_plugin_claim(subject: Value, assertion: Value) -> Value {
        serde_json::json!({
            "subject": subject,
            "assertion": assertion,
            "confidence": 0.75,
            "evidence": [{
                "kind": "signature-match",
                "summary": "matched a deterministic legacy signature"
            }],
            "provenance": {
                "producer": {
                    "kind": "plugin",
                    "id": "dev.resymbol.schema1-test",
                    "version": "1.2.3"
                },
                "method": "schema1-test",
                "run_id": "legacy-run-001"
            }
        })
    }

    fn install_schema_v1_plugin_claims(value: &mut Value, claims: Vec<Value>) {
        let accepted_claim_count =
            u64::try_from(claims.len()).expect("test claim count fits the run ledger");
        let run = PluginRunRecord::new(
            PluginId::new("dev.resymbol.schema1-test").expect("valid plugin id"),
            "1.2.3",
            "legacy-run-001",
            BinaryId::digest(b"schema-v1 plugin artifact").to_string(),
            PluginRunStatus::Succeeded,
            accepted_claim_count,
        )
        .expect("valid legacy plugin run");
        value["payload"]["plugin_runs"] =
            serde_json::to_value(vec![run]).expect("serialize legacy plugin run");
        value["payload"]["plugin_claims"] = Value::Array(claims);
    }

    #[test]
    fn schema_v1_migration_accepts_only_the_genuine_legacy_assertion_vocabulary() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("legacy-claims.resym");
        let (mut value, binary) = schema_v1_package_skeleton();
        let function_subject = || {
            serde_json::json!({
                "kind": "function",
                "binary": binary,
                "rva": 0x1000,
                "size": 0x10
            })
        };
        let type_subject = || {
            serde_json::json!({
                "kind": "type",
                "binary": binary,
                "key": "legacy::Widget"
            })
        };
        install_schema_v1_plugin_claims(
            &mut value,
            vec![
                schema_v1_plugin_claim(
                    function_subject(),
                    serde_json::json!({"kind": "name", "name": "LegacyFunction"}),
                ),
                schema_v1_plugin_claim(
                    function_subject(),
                    serde_json::json!({
                        "kind": "function-prototype",
                        "declaration": "void LegacyFunction(void)"
                    }),
                ),
                schema_v1_plugin_claim(
                    function_subject(),
                    serde_json::json!({"kind": "function-boundary", "size": 0x10}),
                ),
                schema_v1_plugin_claim(
                    type_subject(),
                    serde_json::json!({
                        "kind": "type-definition",
                        "declaration": "struct Widget { int value; };"
                    }),
                ),
                schema_v1_plugin_claim(
                    function_subject(),
                    serde_json::json!({
                        "kind": "class-membership",
                        "class_name": "legacy::Widget"
                    }),
                ),
                schema_v1_plugin_claim(
                    function_subject(),
                    serde_json::json!({"kind": "comment", "text": "legacy evidence"}),
                ),
            ],
        );
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("encode schema-v1 package"),
        )
        .expect("write schema-v1 package");

        let decoded = read_analysis_package(&path, false)
            .expect("all genuine schema-v1 assertions migrate and revalidate");
        let claims = decoded.package.payload().plugin_claims();
        assert_eq!(claims.len(), 6);
        assert!(matches!(
            claims[0].assertion(),
            SymbolAssertion::Name { .. }
        ));
        assert!(matches!(
            claims[1].assertion(),
            SymbolAssertion::FunctionPrototype { .. }
        ));
        assert!(matches!(
            claims[2].assertion(),
            SymbolAssertion::FunctionBoundary { .. }
        ));
        assert!(matches!(
            claims[3].assertion(),
            SymbolAssertion::TypeDefinition { .. }
        ));
        assert!(matches!(
            claims[4].assertion(),
            SymbolAssertion::ClassMembership { .. }
        ));
        assert!(matches!(
            claims[5].assertion(),
            SymbolAssertion::Comment { .. }
        ));
        assert_eq!(decoded.package.payload().plugin_runs().len(), 1);
        assert_eq!(
            decoded.package.payload().plugin_runs()[0].accepted_claim_count(),
            6
        );
    }

    #[test]
    fn schema_v1_migration_rejects_post_schema_v1_plugin_assertions() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let cases = [
            (
                "function-entry",
                serde_json::json!({"kind": "function-entry"}),
            ),
            (
                "direct-call",
                serde_json::json!({
                    "kind": "direct-call",
                    "call_site_rva": 0x1000,
                    "target": {"kind": "function", "rva": 0x1010}
                }),
            ),
            (
                "thunk-target",
                serde_json::json!({
                    "kind": "thunk-target",
                    "target": {"kind": "function", "rva": 0x1010}
                }),
            ),
            (
                "string-literal",
                serde_json::json!({
                    "kind": "string-literal",
                    "encoding": "ascii",
                    "value": "legacy smuggling"
                }),
            ),
            (
                "data-reference",
                serde_json::json!({
                    "kind": "data-reference",
                    "instruction_rva": 0x1000,
                    "instruction_size": 7,
                    "target_rva": 0x1100
                }),
            ),
        ];

        for (kind, assertion) in cases {
            let (mut value, binary) = schema_v1_package_skeleton();
            let subject = serde_json::json!({
                "kind": "function",
                "binary": binary,
                "rva": 0x1000,
                "size": 0x10
            });
            install_schema_v1_plugin_claims(
                &mut value,
                vec![schema_v1_plugin_claim(subject, assertion)],
            );
            let path = temp.path().join(format!("smuggled-{kind}.resym"));
            fs::write(
                &path,
                serde_json::to_vec(&value).expect("encode adversarial schema-v1 package"),
            )
            .expect("write adversarial schema-v1 package");

            let error = match read_analysis_package(&path, false) {
                Ok(_) => {
                    panic!("post-schema-v1 assertion {kind} must be rejected by the legacy decoder")
                }
                Err(error) => error,
            };
            let diagnostic = format!("{error:#}");
            assert!(
                diagnostic.contains("unknown variant") && diagnostic.contains(kind),
                "unexpected diagnostic for {kind}: {diagnostic}"
            );
        }
    }

    #[test]
    fn inspect_reads_a_schema_v1_package_without_recovery_fields() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("prior-schema.resym");
        let base_analysis = analyze_bytes(&pe_fixture()).expect("analyze PE fixture");
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create base-only session");
        let package = ResymPackage::from_bound_payload("0.1.0-alpha.1", session)
            .expect("create current package value");
        let mut value = serde_json::to_value(package).expect("serialize package value");
        value["schema_version"] = serde_json::json!(1);
        let pe = value
            .pointer_mut("/payload/base_analysis/analysis")
            .and_then(Value::as_object_mut)
            .expect("serialized PE analysis object");
        pe.remove("code_recovery_scan_truncated");
        pe.remove("direct_calls");
        pe.remove("thunks");
        pe.remove("string_recovery_scan_truncated");
        pe.remove("strings");
        pe.remove("data_reference_scan_truncated");
        pe.remove("data_references");
        let claims = pe
            .get_mut("symbol_graph")
            .and_then(|graph| graph.get_mut("claims"))
            .and_then(Value::as_array_mut)
            .expect("serialized base claims");
        let current_claim_count = claims.len();
        claims.retain(|claim| {
            !matches!(
                claim.pointer("/assertion/kind").and_then(Value::as_str),
                Some(
                    "function-entry"
                        | "direct-call"
                        | "thunk-target"
                        | "string-literal"
                        | "data-reference"
                )
            )
        });
        assert_eq!(current_claim_count - claims.len(), 2);
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("encode prior-schema package"),
        )
        .expect("write prior-schema package");

        let decoded = read_analysis_package(&path, true)
            .expect("CLI compatibility policy migrates a genuine schema-v1 payload");
        assert_eq!(decoded.package.schema_version(), 1);
        assert_eq!(
            decoded.code_recovery_availability,
            CodeRecoveryAvailability::UnavailableSchema1
        );
        assert_eq!(
            decoded.transitive_thunk_recovery_availability,
            TransitiveThunkRecoveryAvailability::UnavailableSchema1
        );
        assert_eq!(
            decoded.string_data_recovery_availability,
            StringDataRecoveryAvailability::UnavailableSchema1
        );
        assert_eq!(
            decoded.rtti_recovery_availability,
            RttiRecoveryAvailability::RecordedWithoutNoPchdBaseDescriptors(1)
        );
        let BinaryAnalysis::Pe(pe) = decoded.package.payload().base_analysis() else {
            panic!("PE analysis expected");
        };
        assert!(!pe.code_recovery_scan_truncated);
        assert!(pe.direct_calls.is_empty());
        assert!(pe.thunks.is_empty());
        assert!(!pe.string_recovery_scan_truncated);
        assert!(pe.strings.is_empty());
        assert!(!pe.data_reference_scan_truncated);
        assert!(pe.data_references.is_empty());
        assert_eq!(pe.symbol_graph.claims().len(), current_claim_count);

        let inspected: Value = serde_json::from_str(
            &decoded
                .to_pretty_inspection_json()
                .expect("serialize validated original schema-v1 representation"),
        )
        .expect("inspection JSON is valid");
        assert_eq!(inspected["schema_version"], 1);
        let inspected_pe = inspected
            .pointer("/payload/base_analysis/analysis")
            .and_then(Value::as_object)
            .expect("schema-v1 PE payload remains an object");
        assert!(!inspected_pe.contains_key("code_recovery_scan_truncated"));
        assert!(!inspected_pe.contains_key("direct_calls"));
        assert!(!inspected_pe.contains_key("thunks"));
        assert!(!inspected_pe.contains_key("string_recovery_scan_truncated"));
        assert!(!inspected_pe.contains_key("strings"));
        assert!(!inspected_pe.contains_key("data_reference_scan_truncated"));
        assert!(!inspected_pe.contains_key("data_references"));
        assert!(
            inspected_pe["symbol_graph"]["claims"]
                .as_array()
                .expect("schema-v1 base claims")
                .iter()
                .all(|claim| !matches!(
                    claim.pointer("/assertion/kind").and_then(Value::as_str),
                    Some(
                        "function-entry"
                            | "direct-call"
                            | "thunk-target"
                            | "string-literal"
                            | "data-reference"
                    )
                ))
        );

        inspect(InspectArgs {
            package: path,
            json: false,
        })
        .expect("CLI inspection accepts the prior package schema");
    }

    #[test]
    fn inspect_reads_schema_v2_with_code_but_without_string_data_recovery() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("schema-v2.resym");
        let base_analysis = analyze_bytes(&pe_code_recovery_fixture()).expect("analyze PE fixture");
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create base-only session");
        let package = ResymPackage::from_bound_payload("0.1.0-alpha.2", session)
            .expect("create current package value");
        let mut value = serde_json::to_value(package).expect("serialize package value");
        value["schema_version"] = serde_json::json!(2);
        let pe = value
            .pointer_mut("/payload/base_analysis/analysis")
            .and_then(Value::as_object_mut)
            .expect("serialized PE analysis object");
        pe.remove("string_recovery_scan_truncated");
        pe.remove("strings");
        pe.remove("data_reference_scan_truncated");
        pe.remove("data_references");
        let claims = pe
            .get_mut("symbol_graph")
            .and_then(|graph| graph.get_mut("claims"))
            .and_then(Value::as_array_mut)
            .expect("serialized base claims");
        claims.retain(|claim| {
            !matches!(
                claim.pointer("/assertion/kind").and_then(Value::as_str),
                Some("string-literal" | "data-reference")
            )
        });
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("encode schema-v2 package"),
        )
        .expect("write schema-v2 package");

        let decoded = read_analysis_package(&path, true)
            .expect("CLI compatibility policy accepts schema 2 through serde defaults");
        assert_eq!(decoded.package.schema_version(), 2);
        assert_eq!(
            decoded.code_recovery_availability,
            CodeRecoveryAvailability::RecordedWithoutReadOnlyPointerControlFlow(2)
        );
        assert_eq!(
            decoded.transitive_thunk_recovery_availability,
            TransitiveThunkRecoveryAvailability::RecordedWithoutTransitiveThunkChains(2)
        );
        assert_eq!(
            decoded.string_data_recovery_availability,
            StringDataRecoveryAvailability::UnavailableSchema2
        );
        assert_eq!(
            decoded.rtti_recovery_availability,
            RttiRecoveryAvailability::RecordedWithoutNoPchdBaseDescriptors(2)
        );
        assert!(decoded.schema1_source.is_none());
        let BinaryAnalysis::Pe(pe) = decoded.package.payload().base_analysis() else {
            panic!("PE analysis expected");
        };
        assert_eq!(pe.direct_calls.len(), 1);
        assert_eq!(pe.thunks.len(), 1);
        assert!(!pe.code_recovery_scan_truncated);
        assert!(!pe.string_recovery_scan_truncated);
        assert!(pe.strings.is_empty());
        assert!(!pe.data_reference_scan_truncated);
        assert!(pe.data_references.is_empty());

        let inspected: Value = serde_json::from_str(
            &decoded
                .to_pretty_inspection_json()
                .expect("serialize decoded schema-v2 representation"),
        )
        .expect("inspection JSON is valid");
        assert_eq!(inspected["schema_version"], 2);
        assert_eq!(
            inspected
                .pointer("/payload/base_analysis/analysis/direct_calls")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            inspected
                .pointer("/payload/base_analysis/analysis/thunks")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );

        inspect(InspectArgs {
            package: path,
            json: false,
        })
        .expect("CLI inspection accepts schema 2");
    }

    #[test]
    fn inspect_and_json_export_accept_schema_v3_with_string_and_data_recovery() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("schema-v3.resym");
        let output = temp.path().join("schema-v3.json");
        let base_analysis = analyze_bytes(&pe_code_recovery_fixture()).expect("analyze PE fixture");
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create base-only session");
        let package = ResymPackage::from_bound_payload("0.1.0-alpha.3", session)
            .expect("create current package value");
        let mut value = serde_json::to_value(package).expect("serialize package value");
        value["schema_version"] = serde_json::json!(3);
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("encode schema-v3 package"),
        )
        .expect("write schema-v3 package");

        let decoded = read_analysis_package(&path, true)
            .expect("CLI compatibility policy accepts schema 3 explicitly");
        assert_eq!(decoded.package.schema_version(), 3);
        assert_eq!(
            decoded.code_recovery_availability,
            CodeRecoveryAvailability::RecordedWithoutReadOnlyPointerControlFlow(3)
        );
        assert_eq!(
            decoded.transitive_thunk_recovery_availability,
            TransitiveThunkRecoveryAvailability::RecordedWithoutTransitiveThunkChains(3)
        );
        assert_eq!(
            decoded.string_data_recovery_availability,
            StringDataRecoveryAvailability::Recorded
        );
        assert_eq!(
            decoded.rtti_recovery_availability,
            RttiRecoveryAvailability::RecordedWithoutNoPchdBaseDescriptors(3)
        );
        assert!(decoded.schema1_source.is_none());
        assert_eq!(
            serde_json::from_str::<Value>(
                &decoded
                    .to_pretty_inspection_json()
                    .expect("serialize decoded schema-v3 representation")
            )
            .expect("inspection JSON is valid")["schema_version"],
            3
        );

        inspect(InspectArgs {
            package: path.clone(),
            json: false,
        })
        .expect("CLI inspection accepts schema 3");
        export(ExportArgs {
            package: path,
            format: ExportFormat::Json,
            output: Some(output.clone()),
            binary: None,
        })
        .expect("JSON export accepts schema 3");
        let projection: Value =
            serde_json::from_slice(&fs::read(output).expect("read schema-v3 JSON projection"))
                .expect("projection JSON is valid");
        assert_eq!(projection["schema_version"], 6);
    }

    #[test]
    fn inspect_and_json_export_accept_schema_v4_with_explicit_legacy_rtti_availability() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("schema-v4.resym");
        let output = temp.path().join("schema-v4.json");
        let mut base_analysis = analyze_bytes(include_bytes!(
            "../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe"
        ))
        .expect("analyze modern-RTTI PE fixture");
        let BinaryAnalysis::Pe(pe) = &mut base_analysis else {
            panic!("PE analysis expected");
        };
        assert!(!pe.msvc_rtti_vftables.is_empty());
        assert!(pe.msvc_rtti_vftables.iter().all(|vftable| {
            vftable
                .base_classes
                .iter()
                .all(|base| base.class_hierarchy_descriptor_rva.is_some())
        }));
        let legacy_thunk_seeds = legacy_initial_thunk_seeds(pe);
        assert!(
            pe.thunks
                .iter()
                .any(|thunk| !legacy_thunk_seeds.contains(&thunk.rva)),
            "fixture must exercise schema-4 one-hop normalization"
        );
        pe.thunks
            .retain(|thunk| legacy_thunk_seeds.contains(&thunk.rva));
        pe.symbol_graph = pe
            .rebuild_symbol_graph()
            .expect("rebuild schema-4 one-hop symbol graph");
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create base-only session");
        let package = ResymPackage::from_bound_payload("0.1.0-alpha.4", session)
            .expect("create current package value");
        let mut value = serde_json::to_value(package).expect("serialize package value");
        value["schema_version"] = serde_json::json!(4);
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("encode schema-v4 package"),
        )
        .expect("write schema-v4 package");

        let decoded = read_analysis_package(&path, true)
            .expect("CLI compatibility policy accepts schema 4 explicitly");
        assert_eq!(decoded.package.schema_version(), 4);
        assert_eq!(
            decoded.code_recovery_availability,
            CodeRecoveryAvailability::Recorded
        );
        assert_eq!(
            decoded.transitive_thunk_recovery_availability,
            TransitiveThunkRecoveryAvailability::RecordedWithoutTransitiveThunkChains(4)
        );
        assert_eq!(
            decoded.string_data_recovery_availability,
            StringDataRecoveryAvailability::Recorded
        );
        assert_eq!(
            decoded.rtti_recovery_availability,
            RttiRecoveryAvailability::RecordedWithoutNoPchdBaseDescriptors(4)
        );
        assert!(decoded.schema1_source.is_none());
        let BinaryAnalysis::Pe(decoded_pe) = decoded.package.payload().base_analysis() else {
            panic!("PE analysis expected");
        };
        assert!(!decoded_pe.msvc_rtti_vftables.is_empty());
        assert!(decoded_pe.msvc_rtti_vftables.iter().all(|vftable| {
            vftable
                .base_classes
                .iter()
                .all(|base| base.class_hierarchy_descriptor_rva.is_some())
        }));

        inspect(InspectArgs {
            package: path.clone(),
            json: false,
        })
        .expect("CLI inspection accepts schema 4");
        export(ExportArgs {
            package: path,
            format: ExportFormat::Json,
            output: Some(output.clone()),
            binary: None,
        })
        .expect("JSON export accepts schema 4");
        let projection: Value =
            serde_json::from_slice(&fs::read(output).expect("read schema-v4 JSON projection"))
                .expect("projection JSON is valid");
        assert_eq!(projection["schema_version"], 6);
    }

    #[test]
    fn inspect_and_json_export_accept_schema_v5_with_one_hop_thunks() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("schema-v5.resym");
        let output = temp.path().join("schema-v5.json");
        let base_analysis = analyze_bytes(&pe_code_recovery_fixture()).expect("analyze PE fixture");
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create base-only session");
        let package = ResymPackage::from_bound_payload("0.1.0-alpha.5", session)
            .expect("create current package value");
        let mut value = serde_json::to_value(package).expect("serialize package value");
        value["schema_version"] = serde_json::json!(5);
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("encode schema-v5 package"),
        )
        .expect("write schema-v5 package");

        let decoded = read_analysis_package(&path, true)
            .expect("CLI compatibility policy accepts schema 5 explicitly");
        assert_eq!(decoded.package.schema_version(), 5);
        assert_eq!(
            decoded.code_recovery_availability,
            CodeRecoveryAvailability::Recorded
        );
        assert_eq!(
            decoded.transitive_thunk_recovery_availability,
            TransitiveThunkRecoveryAvailability::RecordedWithoutTransitiveThunkChains(5)
        );
        assert_eq!(
            decoded.string_data_recovery_availability,
            StringDataRecoveryAvailability::Recorded
        );
        assert_eq!(
            decoded.rtti_recovery_availability,
            RttiRecoveryAvailability::Recorded
        );
        let BinaryAnalysis::Pe(pe) = decoded.package.payload().base_analysis() else {
            panic!("PE analysis expected");
        };
        assert_eq!(pe.direct_calls.len(), 1);
        assert_eq!(pe.thunks.len(), 1);

        inspect(InspectArgs {
            package: path.clone(),
            json: false,
        })
        .expect("CLI inspection accepts schema 5");
        export(ExportArgs {
            package: path,
            format: ExportFormat::Json,
            output: Some(output.clone()),
            binary: None,
        })
        .expect("JSON export accepts schema 5");
        let projection: Value =
            serde_json::from_slice(&fs::read(output).expect("read schema-v5 JSON projection"))
                .expect("projection JSON is valid");
        assert_eq!(projection["schema_version"], 6);
    }

    #[test]
    fn schemas_v2_through_v5_reject_relabeled_schema_v6_transitive_thunk_chains() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let base_analysis = analyze_bytes(&pe_transitive_thunk_chain_fixture())
            .expect("analyze transitive thunk-chain fixture");
        let BinaryAnalysis::Pe(pe) = &base_analysis else {
            panic!("PE analysis expected");
        };
        assert_eq!(
            pe.thunks.iter().map(|thunk| thunk.rva).collect::<Vec<_>>(),
            [0x1010, 0x1020]
        );
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create transitive thunk-chain session");
        let package = ResymPackage::from_bound_payload("0.1.0", session)
            .expect("create current package value");
        let current = serde_json::to_value(package).expect("serialize current package value");
        let current_path = temp.path().join("schema-v6-thunk-chain.resym");
        fs::write(
            &current_path,
            serde_json::to_vec(&current).expect("encode current package"),
        )
        .expect("write current package");
        let decoded = read_analysis_package(&current_path, false)
            .expect("schema 6 accepts transitive thunk-chain recovery");
        assert_eq!(decoded.package.schema_version(), 6);
        assert_eq!(
            decoded.transitive_thunk_recovery_availability,
            TransitiveThunkRecoveryAvailability::Recorded
        );

        for schema_version in 2..TRANSITIVE_THUNK_CHAIN_SCHEMA_VERSION {
            let mut value = current.clone();
            value["schema_version"] = serde_json::json!(schema_version);
            let path = temp.path().join(format!(
                "relabeled-thunk-chain-schema-{schema_version}.resym"
            ));
            fs::write(
                &path,
                serde_json::to_vec(&value).expect("encode relabeled package"),
            )
            .expect("write relabeled package");

            let error = match read_analysis_package(&path, false) {
                Ok(_) => panic!(
                    "schema {schema_version} must reject schema-6 transitive thunk semantics"
                ),
                Err(error) => error,
            };
            let diagnostic = format!("{error:#}");
            assert!(diagnostic.contains("schema-6 transitive thunk source RVA 0x1020"));
            assert!(diagnostic.contains("cannot be relabeled"));
        }
    }

    #[test]
    fn schema_v5_transitive_thunk_gate_ignores_plugin_only_claim_chains() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("schema-v5-plugin-thunk-chain.resym");
        let base_analysis = analyze_bytes(&pe_fixture()).expect("analyze PE fixture");
        let binary = base_analysis.identity().id.clone();
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create base-only session");
        let package = ResymPackage::from_bound_payload("0.1.0-alpha.5", session)
            .expect("create current package value");
        let mut value = serde_json::to_value(package).expect("serialize current package value");
        value["schema_version"] = serde_json::json!(5);
        install_schema_v1_plugin_claims(
            &mut value,
            vec![
                schema_v1_plugin_claim(
                    serde_json::json!({
                        "kind": "function",
                        "binary": binary.as_str(),
                        "rva": 0x1040
                    }),
                    serde_json::json!({
                        "kind": "thunk-target",
                        "target": {"kind": "function", "rva": 0x1060}
                    }),
                ),
                schema_v1_plugin_claim(
                    serde_json::json!({
                        "kind": "function",
                        "binary": binary.as_str(),
                        "rva": 0x1060
                    }),
                    serde_json::json!({
                        "kind": "thunk-target",
                        "target": {"kind": "function", "rva": 0x1080}
                    }),
                ),
            ],
        );
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("encode schema-v5 plugin package"),
        )
        .expect("write schema-v5 plugin package");

        let decoded = read_analysis_package(&path, false)
            .expect("base-only gate must not reject plugin claim relationships");
        assert_eq!(decoded.package.schema_version(), 5);
        assert_eq!(decoded.package.payload().plugin_claims().len(), 2);
    }

    #[test]
    fn legacy_thunk_seeds_exclude_exports_into_non_executable_data() {
        let mut base_analysis =
            analyze_bytes(&pe_code_recovery_fixture()).expect("analyze PE fixture");
        let BinaryAnalysis::Pe(analysis) = &mut base_analysis else {
            panic!("PE analysis expected");
        };
        analysis.exports[1].address_rva = Some(0x1040);
        analysis.exports[1].forwarded_to = None;
        analysis.sections[0].characteristics &= !IMAGE_SCN_MEM_EXECUTE;

        assert!(!legacy_initial_thunk_seeds(analysis).contains(&0x1040));
    }

    #[test]
    fn schemas_v1_through_v4_reject_relabeled_schema_v5_no_pchd_rtti_semantics() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let base_analysis = analyze_bytes(include_bytes!(
            "../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe"
        ))
        .expect("analyze modern-RTTI PE fixture");
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create base-only session");
        let package = ResymPackage::from_bound_payload("0.1.0", session)
            .expect("create current package value");
        let current = serde_json::to_value(package).expect("serialize current package value");

        for schema_version in 1..=4 {
            for omit_pchd_field in [false, true] {
                let mut value = current.clone();
                value["schema_version"] = serde_json::json!(schema_version);
                let base_class = value
                    .pointer_mut(
                        "/payload/base_analysis/analysis/msvc_rtti_vftables/0/base_classes/0",
                    )
                    .expect("fixture contains a modern RTTI base descriptor");
                base_class["attributes"] = serde_json::json!(0);
                if omit_pchd_field {
                    base_class
                        .as_object_mut()
                        .expect("base-class fixture is an object")
                        .remove("class_hierarchy_descriptor_rva");
                } else {
                    base_class["class_hierarchy_descriptor_rva"] = Value::Null;
                }
                let representation = if omit_pchd_field { "missing" } else { "null" };
                let path = temp.path().join(format!(
                    "relabeled-rtti-schema-{schema_version}-{representation}.resym"
                ));
                fs::write(
                    &path,
                    serde_json::to_vec(&value).expect("encode relabeled package"),
                )
                .expect("write relabeled package");

                let error = match read_analysis_package(&path, false) {
                    Ok(_) => panic!(
                        "schema {schema_version} must reject schema-5 RTTI semantics with a {representation} pCHD field"
                    ),
                    Err(error) => error,
                };
                let diagnostic = format!("{error:#}");
                assert!(diagnostic.contains("schema-5 no-pCHD semantics"));
                assert!(diagnostic.contains("cannot be relabeled"));
            }
        }
    }

    #[test]
    fn no_pchd_rtti_gate_follows_wrappers_without_matching_unrelated_null_fields() {
        let base = serde_json::json!({
            "msvc_rtti_vftables": [{
                "rva": 0x2300,
                "complete_object_locator_rva": 0x2180,
                "type_descriptor_rva": 0x2100,
                "class_hierarchy_descriptor_rva": 0x21c0,
                "base_class_array_rva": 0x2200,
                "offset": 0,
                "constructor_displacement_offset": 0,
                "decorated_class_name": ".?AVLegacy@@",
                "class_name": "Legacy",
                "hierarchy_attributes": 0,
                "base_classes": [{
                    "array_index": 0,
                    "descriptor_rva": 0x2220,
                    "type_descriptor_rva": 0x2100,
                    "decorated_name": ".?AVLegacy@@",
                    "name": "Legacy",
                    "num_contained_bases": 0,
                    "member_displacement": 0,
                    "vbtable_displacement": -1,
                    "displacement_inside_vbtable": 0,
                    "attributes": 0,
                    "class_hierarchy_descriptor_rva": null
                }],
                "virtual_function_rvas": [0x1000]
            }]
        });
        let mut omitted = base.clone();
        omitted["msvc_rtti_vftables"][0]["base_classes"][0]
            .as_object_mut()
            .expect("base-class fixture is an object")
            .remove("class_hierarchy_descriptor_rva");
        for payload in [
            base.clone(),
            serde_json::json!({"wrapper": [{"nested": base.clone()}]}),
            omitted.clone(),
            serde_json::json!({"wrapper": [{"nested": omitted.clone()}]}),
        ] {
            reject_pre_v5_no_pchd_base_descriptors(&payload, 4)
                .expect_err("wrapped schema-5 RTTI semantics must be rejected");
        }

        let unrelated = serde_json::json!({
            "class_hierarchy_descriptor_rva": null,
            "metadata": {
                "class_hierarchy_descriptor_rva": null
            }
        });
        reject_pre_v5_no_pchd_base_descriptors(&unrelated, 4)
            .expect("unrelated null fields must not trigger the RTTI semantic gate");

        let unrelated_base_classes = serde_json::json!({
            "extension": {
                "base_classes": [{"class_hierarchy_descriptor_rva": null}]
            }
        });
        reject_pre_v5_no_pchd_base_descriptors(&unrelated_base_classes, 4)
            .expect("an unrelated base_classes extension must not resemble an RTTI descriptor");

        let full_base_descriptor = base["msvc_rtti_vftables"][0]["base_classes"][0].clone();
        let unrelated_full_base_classes = serde_json::json!({
            "extension": {"base_classes": [full_base_descriptor.clone()]},
            "msvc_rtti_vftables": [{"base_classes": [full_base_descriptor]}]
        });
        reject_pre_v5_no_pchd_base_descriptors(&unrelated_full_base_classes, 4).expect(
            "full base-descriptor shapes outside a complete RTTI vftable must not trigger the gate",
        );

        let mut recorded_legacy_descriptor = base;
        recorded_legacy_descriptor["msvc_rtti_vftables"][0]["base_classes"][0]["class_hierarchy_descriptor_rva"] =
            serde_json::json!(0x2400);
        reject_pre_v5_no_pchd_base_descriptors(&recorded_legacy_descriptor, 4)
            .expect("a recorded legacy pCHD RVA remains valid in a schema-4 payload");
    }

    #[test]
    fn schema_v2_and_v3_reject_relabeled_schema_v4_function_pointer_call_targets() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let base_analysis = analyze_bytes(&pe_code_recovery_fixture()).expect("analyze PE fixture");
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create base-only session");
        let package = ResymPackage::from_bound_payload("0.1.0", session)
            .expect("create current package value");
        let current = serde_json::to_value(package).expect("serialize current package value");

        for schema_version in [2, 3] {
            let mut value = current.clone();
            value["schema_version"] = serde_json::json!(schema_version);
            value["payload"]["base_analysis"]["analysis"]["direct_calls"][0]["target"] = serde_json::json!({
                "kind": "function-pointer",
                "slot_rva": 0x1300,
                "rva": 0x1040
            });
            let path = temp
                .path()
                .join(format!("relabeled-schema-{schema_version}.resym"));
            fs::write(
                &path,
                serde_json::to_vec(&value).expect("encode relabeled package"),
            )
            .expect("write relabeled package");

            let error = match read_analysis_package(&path, false) {
                Ok(_) => panic!("schema {schema_version} must reject schema-4 target semantics"),
                Err(error) => error,
            };
            let diagnostic = format!("{error:#}");
            assert!(diagnostic.contains("schema-4 function-pointer target"));
            assert!(diagnostic.contains("cannot be relabeled"));
        }
    }

    #[test]
    fn schema_v2_and_v3_reject_relabeled_schema_v4_function_pointer_thunk_targets() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let base_analysis = analyze_bytes(&pe_code_recovery_fixture()).expect("analyze PE fixture");
        let session = AnalysisSession::new(base_analysis, Vec::new(), Vec::new())
            .expect("create base-only session");
        let package = ResymPackage::from_bound_payload("0.1.0", session)
            .expect("create current package value");
        let current = serde_json::to_value(package).expect("serialize current package value");

        for schema_version in [2, 3] {
            let mut value = current.clone();
            value["schema_version"] = serde_json::json!(schema_version);
            value["payload"]["base_analysis"]["analysis"]["thunks"][0]["target"] = serde_json::json!({
                "kind": "function-pointer",
                "slot_rva": 0x1300,
                "rva": 0x1040
            });
            let path = temp
                .path()
                .join(format!("relabeled-thunk-schema-{schema_version}.resym"));
            fs::write(
                &path,
                serde_json::to_vec(&value).expect("encode relabeled package"),
            )
            .expect("write relabeled package");

            let error = match read_analysis_package(&path, false) {
                Ok(_) => panic!("schema {schema_version} must reject schema-4 thunk semantics"),
                Err(error) => error,
            };
            let diagnostic = format!("{error:#}");
            assert!(diagnostic.contains("schema-4 function-pointer target"));
            assert!(diagnostic.contains("cannot be relabeled"));
        }
    }

    #[test]
    fn pre_v4_function_pointer_gate_covers_base_graph_and_plugin_claim_targets() {
        let target = serde_json::json!({
            "kind": "function-pointer",
            "slot_rva": 0x2000,
            "rva": 0x1000
        });
        for payload in [
            serde_json::json!({
                "base_analysis": {
                    "analysis": {
                        "direct_calls": [],
                        "thunks": [],
                        "symbol_graph": {
                            "claims": [{"assertion": {"target": target.clone()}}]
                        }
                    }
                },
                "plugin_claims": []
            }),
            serde_json::json!({
                "base_analysis": {
                    "analysis": {
                        "direct_calls": [],
                        "thunks": [],
                        "symbol_graph": {"claims": []}
                    }
                },
                "plugin_claims": [{"assertion": {"target": target.clone()}}]
            }),
        ] {
            let error = reject_pre_v4_function_pointer_targets(&payload, 3)
                .expect_err("pre-v4 claim targets must be rejected");
            assert!(
                error
                    .to_string()
                    .contains("schema-4 function-pointer target")
            );
        }
    }

    #[test]
    fn strict_missing_plugin_fails_only_after_writing_valid_base_package() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let binary = temp.path().join("fixture.exe");
        let output = temp.path().join("strict.resym");
        let plugins = temp.path().join("plugins");
        fs::create_dir(&plugins).expect("create plugin directory");
        fs::write(&binary, pe_fixture()).expect("write PE fixture");

        let error = analyze(
            AnalyzeArgs {
                binary,
                output: Some(output.clone()),
                plugins: vec!["dev.resymbol.missing".to_owned()],
                strict_plugins: true,
            },
            false,
            plugins,
        )
        .expect_err("strict missing plugin must return failure");
        assert!(error.to_string().contains("strict plugin policy"));
        assert!(error.to_string().contains("package was written"));
        assert!(output.is_file());

        let package: ResymPackage<AnalysisSession> =
            read_file_bound(&output).expect("strict failure still writes a valid package");
        assert!(package.payload().plugin_runs().is_empty());
        assert!(package.payload().plugin_claims().is_empty());
        assert_eq!(
            package
                .payload()
                .combined_symbol_graph()
                .expect("combine base-only graph")
                .claims()
                .len(),
            5
        );
    }

    #[test]
    fn exact_trust_is_invalidated_by_artifact_changes_and_mismatch_is_rejected() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let plugin_path = create_external_plugin(temp.path(), "dev.resymbol.external");
        let report = scan_plugins(temp.path(), false).expect("discover external plugin");
        let plugin = unique_valid_directory_plugin(&report, "dev.resymbol.external")
            .expect("resolve external plugin");
        let initial = fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default())
            .expect("fingerprint initial artifact")
            .fingerprint;
        require_expected_fingerprint(Some(&initial.to_string()), initial)
            .expect("matching fingerprint is accepted");

        let key = ArtifactStateKey::new(
            PluginId::new("dev.resymbol.external").expect("valid ID"),
            initial,
        );
        let store = PluginStateStore::new(temp.path());
        store.trust(&key).expect("trust initial artifact");
        assert_eq!(
            store.status(&key).expect("read initial trust"),
            PluginArtifactStatus::Trusted
        );

        fs::write(plugin_path.join("plugin.bin"), b"executable-v2").expect("change executable");
        let changed = fingerprint_plugin_directory(&plugin_path, FingerprintLimits::default())
            .expect("fingerprint changed artifact")
            .fingerprint;
        assert_ne!(changed, initial);
        let changed_key = ArtifactStateKey::new(
            PluginId::new("dev.resymbol.external").expect("valid ID"),
            changed,
        );
        assert_eq!(
            store.status(&changed_key).expect("read changed status"),
            PluginArtifactStatus::ApprovalRequired
        );
        assert!(
            require_expected_fingerprint(Some(&initial.to_string()), changed)
                .expect_err("stale expected fingerprint must fail")
                .to_string()
                .contains("fingerprint mismatch")
        );
    }

    #[test]
    fn execution_policy_rechecks_exact_trust_and_disable_sentinel() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let plugin_path = create_external_plugin(temp.path(), "dev.resymbol.policy-race");
        let fingerprint = fingerprint_plugin_directory(&plugin_path, FingerprintLimits::default())
            .expect("fingerprint policy fixture")
            .fingerprint;
        let key = ArtifactStateKey::new(
            PluginId::new("dev.resymbol.policy-race").expect("valid plugin ID"),
            fingerprint,
        );
        let store = PluginStateStore::new(temp.path());
        store.trust(&key).expect("trust exact policy fixture");
        assert!(
            plugin_execution_policy_blocker(
                &store,
                &key,
                &plugin_path,
                ArtifactTrustPolicy::RequireApproval,
            )
            .is_none()
        );

        store.untrust(&key).expect("revoke exact trust");
        assert!(
            plugin_execution_policy_blocker(
                &store,
                &key,
                &plugin_path,
                ArtifactTrustPolicy::RequireApproval,
            )
            .expect("revocation blocks commit")
            .contains("revoked")
        );

        store.trust(&key).expect("restore exact trust");
        fs::write(plugin_path.join(PLUGIN_DISABLED_SENTINEL), b"disabled")
            .expect("create disable sentinel");
        assert!(
            plugin_execution_policy_blocker(
                &store,
                &key,
                &plugin_path,
                ArtifactTrustPolicy::RequireApproval,
            )
            .expect("sentinel blocks commit")
            .contains(PLUGIN_DISABLED_SENTINEL)
        );
    }

    #[test]
    fn sandboxed_wasm_autoload_policy_still_honors_quarantine_and_reset() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let plugin_path = create_plugin(temp.path(), "dev.resymbol.wasm-policy");
        let report = scan_plugins(temp.path(), false).expect("discover WASM policy fixture");
        let plugin = unique_valid_directory_plugin(&report, "dev.resymbol.wasm-policy")
            .expect("resolve WASM policy fixture");
        assert!(runtime_supports_analysis(
            &plugin
                .manifest
                .as_ref()
                .expect("validated manifest")
                .runtime
        ));
        let fingerprint = fingerprint_plugin_directory(&plugin_path, FingerprintLimits::default())
            .expect("fingerprint WASM policy fixture")
            .fingerprint;
        let key = ArtifactStateKey::new(
            PluginId::new("dev.resymbol.wasm-policy").expect("valid plugin ID"),
            fingerprint,
        );
        let store = PluginStateStore::new(temp.path());
        assert_eq!(
            store.status(&key).expect("read initial WASM state"),
            PluginArtifactStatus::ApprovalRequired
        );
        assert!(
            plugin_execution_policy_blocker(
                &store,
                &key,
                &plugin_path,
                ArtifactTrustPolicy::Sandboxed,
            )
            .is_none(),
            "sandboxed WASM must not require an approval record"
        );
        assert!(
            plugin_execution_policy_blocker(
                &store,
                &key,
                &plugin_path,
                ArtifactTrustPolicy::RequireApproval,
            )
            .expect("trust-requiring runtime must remain blocked")
            .contains("revoked")
        );

        store
            .trust(&key)
            .expect("create an irrelevant WASM trust record");
        fs::write(only_state_record(&store, "trust"), b"not valid JSON")
            .expect("corrupt irrelevant WASM trust record");
        assert!(
            plugin_execution_policy_blocker(
                &store,
                &key,
                &plugin_path,
                ArtifactTrustPolicy::Sandboxed,
            )
            .is_none(),
            "sandboxed WASM must not consume irrelevant trust state"
        );
        list_plugins(temp.path(), false)
            .expect("WASM listing must ignore an irrelevant corrupt trust record");
        assert!(
            plugin_execution_policy_blocker(
                &store,
                &key,
                &plugin_path,
                ArtifactTrustPolicy::RequireApproval,
            )
            .expect("corrupt trust must fail closed for ambient runtimes")
            .contains("unsafe or corrupt")
        );

        store
            .quarantine(&key, "attributable WASM trap")
            .expect("quarantine exact WASM artifact");
        assert!(
            plugin_execution_policy_blocker(
                &store,
                &key,
                &plugin_path,
                ArtifactTrustPolicy::Sandboxed,
            )
            .expect("quarantine must block WASM autoload")
            .contains("quarantined")
        );
        fs::write(only_state_record(&store, "quarantine"), b"not valid JSON")
            .expect("corrupt exact WASM quarantine record");
        assert!(
            plugin_execution_policy_blocker(
                &store,
                &key,
                &plugin_path,
                ArtifactTrustPolicy::Sandboxed,
            )
            .expect("corrupt quarantine must fail closed for sandboxed WASM")
            .contains("unsafe or corrupt")
        );
        assert!(
            list_plugins(temp.path(), false)
                .expect_err("WASM listing must fail closed on corrupt quarantine state")
                .to_string()
                .contains("fingerprint/state error")
        );
        store.reset(&key).expect("reset exact WASM quarantine");
        assert!(
            plugin_execution_policy_blocker(
                &store,
                &key,
                &plugin_path,
                ArtifactTrustPolicy::Sandboxed,
            )
            .is_none()
        );

        let error = trust_plugin(temp.path(), "dev.resymbol.wasm-policy", None)
            .expect_err("sandboxed WASM trust must be unnecessary");
        assert!(error.to_string().contains("autoloads without"));
    }

    #[test]
    fn managed_plugins_are_analysis_eligible_and_fingerprint_trustable() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        create_managed_plugin(temp.path(), "dev.resymbol.managed");
        let report = scan_plugins(temp.path(), false).expect("discover managed plugin");
        let plugin = unique_valid_directory_plugin(&report, "dev.resymbol.managed")
            .expect("resolve managed plugin");
        let manifest = plugin.manifest.as_ref().expect("validated manifest");
        assert!(runtime_supports_analysis(&manifest.runtime));

        trust_plugin(temp.path(), "dev.resymbol.managed", None)
            .expect("trust exact managed artifact");
        let fingerprint = fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default())
            .expect("fingerprint managed artifact")
            .fingerprint;
        let key = ArtifactStateKey::new(manifest.id.clone(), fingerprint);
        assert_eq!(
            PluginStateStore::new(temp.path())
                .status(&key)
                .expect("read managed trust state"),
            PluginArtifactStatus::Trusted
        );
    }

    #[test]
    fn managed_helper_resolution_never_falls_back_to_path() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let expected = temp.path().join(format!(
            "resymbol-managed-host{}",
            std::env::consts::EXE_SUFFIX
        ));
        let error = resolve_managed_host_in(temp.path())
            .expect_err("missing app-local managed helper must be rejected");
        assert!(error.contains("managed helper is unavailable"));
        assert!(error.contains(&expected.display().to_string()));
    }

    #[test]
    fn managed_image_map_exactly_projects_validated_pe_sections() {
        let analysis = analyze_bytes(&pe_fixture()).expect("analyze fixture");
        let BinaryAnalysis::Pe(pe) = &analysis else {
            panic!("PE analysis expected")
        };
        let image = managed_pe_image(&analysis).expect("PE x86_64 managed image");
        assert_eq!(image.identity, pe.identity);
        assert_eq!(image.size_of_headers, pe.size_of_headers);
        assert_eq!(image.size_of_image, pe.size_of_image);
        assert_eq!(image.sections.len(), pe.sections.len());
        for (managed, section) in image.sections.iter().zip(&pe.sections) {
            assert_eq!(managed.virtual_address, section.virtual_address);
            assert_eq!(managed.virtual_size, section.virtual_size);
            assert_eq!(managed.raw_data_offset, section.raw_data_offset);
            assert_eq!(managed.raw_data_size, section.raw_data_size);
        }
    }

    #[test]
    fn managed_pre_attribution_errors_are_host_side_but_marked_failures_are_not() {
        use resymbol_plugin_runtime::ProcessDiagnostics;

        let path = PathBuf::from("managed-test-path");
        let json_error = serde_json::from_str::<Value>("{")
            .expect_err("malformed JSON produces an encoding error fixture");
        let host_side = vec![
            PluginRuntimeError::InvalidManagedContext("invalid map".to_owned()),
            PluginRuntimeError::ManagedHostUnavailable {
                path: path.clone(),
                reason: "missing".to_owned(),
            },
            PluginRuntimeError::ManagedHostFailed {
                code: Some(1),
                reason: "pre-load".to_owned(),
                diagnostics: ProcessDiagnostics::default(),
            },
            PluginRuntimeError::ManagedArtifactMismatch {
                reason: "mismatch".to_owned(),
            },
            PluginRuntimeError::ManagedAssemblyClosure {
                path: path.clone(),
                reason: "closure".to_owned(),
            },
            PluginRuntimeError::ManagedSourceBinary {
                path: path.clone(),
                reason: "source".to_owned(),
            },
            PluginRuntimeError::ManagedHostInputChanged {
                path: path.clone(),
                reason: "source changed before marker".to_owned(),
                diagnostics: ProcessDiagnostics::default(),
            },
            PluginRuntimeError::ManagedHostArtifactChanged {
                reason: "artifact changed before marker".to_owned(),
                diagnostics: ProcessDiagnostics::default(),
            },
            PluginRuntimeError::EncodeManagedBootstrap(json_error),
        ];
        for error in &host_side {
            assert_eq!(pre_attribution_host_runtime(error), Some("managed"));
            assert!(is_host_side_runtime_failure(error));
            assert!(!is_transient_plugin_response(error));
        }

        let diagnostics = |stderr: &str| {
            let mut diagnostics = ProcessDiagnostics::default();
            diagnostics.stderr = stderr.to_owned();
            diagnostics
        };
        let process_host_side = [
            PluginRuntimeError::ProcessIo {
                operation: "poll plugin process",
                source: std::io::Error::other("poll failed"),
                diagnostics: diagnostics("plugin detail"),
            },
            PluginRuntimeError::ProcessWorkerPanicked {
                worker: "plugin stderr worker",
                diagnostics: diagnostics("worker detail"),
            },
        ];
        for error in &process_host_side {
            assert_eq!(pre_attribution_host_runtime(error), None);
            assert!(is_host_side_runtime_failure(error));
            assert!(plugin_runtime_error_detail(error).contains("stderr:"));
        }

        let attributable = [
            PluginRuntimeError::ManagedExecutionInputChanged {
                path: path.clone(),
                reason: "source changed after marker".to_owned(),
                diagnostics: ProcessDiagnostics::default(),
            },
            PluginRuntimeError::ManagedExecutionArtifactChanged {
                reason: "artifact changed after marker".to_owned(),
                diagnostics: ProcessDiagnostics::default(),
            },
            PluginRuntimeError::ProcessFailed {
                code: Some(1),
                diagnostics: ProcessDiagnostics::default(),
            },
            PluginRuntimeError::Protocol {
                line: 1,
                message: "bad output".to_owned(),
                diagnostics: ProcessDiagnostics::default(),
            },
            PluginRuntimeError::StreamLimit {
                stream: StreamKind::Stdout,
                limit: 1,
                diagnostics: ProcessDiagnostics::default(),
            },
        ];
        for error in &attributable {
            assert_eq!(pre_attribution_host_runtime(error), None);
            assert!(!is_host_side_runtime_failure(error));
            assert!(!is_transient_plugin_response(error));
        }

        let unavailable_response = PluginRuntimeError::PluginRejected {
            code: "unavailable".to_owned(),
            message: "try later".to_owned(),
            data: None,
            diagnostics: ProcessDiagnostics::default(),
        };
        assert!(is_transient_plugin_response(&unavailable_response));
        assert!(!is_host_side_runtime_failure(&unavailable_response));
    }

    #[test]
    fn wasm_error_attribution_quarantines_only_plugin_controlled_failures() {
        let host_side = [
            PluginRuntimeError::InvalidWasmContext("invalid PE map".to_owned()),
            PluginRuntimeError::WasmEngineUnavailable {
                reason: "engine configuration".to_owned(),
            },
            PluginRuntimeError::WasmArtifactMismatch {
                reason: "changed before compilation".to_owned(),
            },
        ];
        for error in &host_side {
            assert_eq!(pre_attribution_host_runtime(error), Some("wasm"));
            assert!(is_host_side_runtime_failure(error));
        }

        let attributable = [
            PluginRuntimeError::WasmComponent {
                stage: "analyze",
                reason: "guest trap".to_owned(),
            },
            PluginRuntimeError::WasmResourceLimit {
                resource: "fuel",
                limit: 1,
            },
        ];
        for error in &attributable {
            assert_eq!(pre_attribution_host_runtime(error), None);
            assert!(!is_host_side_runtime_failure(error));
        }
    }

    #[test]
    fn native_out_of_process_plugins_are_eligible_and_fingerprint_trustable() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        create_native_plugin(temp.path(), "dev.resymbol.native", "out-of-process");
        let report = scan_plugins(temp.path(), false).expect("discover native plugin");
        let plugin = unique_valid_directory_plugin(&report, "dev.resymbol.native")
            .expect("resolve native plugin");
        let manifest = plugin.manifest.as_ref().expect("validated manifest");
        assert!(runtime_supports_analysis(&manifest.runtime));

        trust_plugin(temp.path(), "dev.resymbol.native", None)
            .expect("trust exact native artifact");
        let fingerprint = fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default())
            .expect("fingerprint native artifact")
            .fingerprint;
        let key = ArtifactStateKey::new(manifest.id.clone(), fingerprint);
        assert_eq!(
            PluginStateStore::new(temp.path())
                .status(&key)
                .expect("read native trust state"),
            PluginArtifactStatus::Trusted
        );
    }

    #[test]
    fn native_in_process_plugins_are_neither_eligible_nor_trustable() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        create_native_plugin(temp.path(), "dev.resymbol.native", "in-process");
        let report = scan_plugins(temp.path(), false).expect("discover native plugin");
        let plugin = unique_valid_directory_plugin(&report, "dev.resymbol.native")
            .expect("resolve native plugin");
        assert!(!runtime_supports_analysis(
            &plugin
                .manifest
                .as_ref()
                .expect("validated manifest")
                .runtime
        ));
        let error = trust_plugin(temp.path(), "dev.resymbol.native", None)
            .expect_err("in-process native trust must be rejected");
        assert!(error.to_string().contains("in-process native execution"));
    }

    #[test]
    fn native_image_map_exactly_projects_validated_pe_sections() {
        let analysis = analyze_bytes(&pe_fixture()).expect("analyze fixture");
        let BinaryAnalysis::Pe(pe) = &analysis else {
            panic!("PE analysis expected")
        };
        let image = native_pe_image(&analysis).expect("PE native image");
        assert_eq!(image.identity, pe.identity);
        assert_eq!(image.size_of_headers, pe.size_of_headers);
        assert_eq!(image.size_of_image, pe.size_of_image);
        assert_eq!(image.sections.len(), pe.sections.len());
        for (native, section) in image.sections.iter().zip(&pe.sections) {
            assert_eq!(native.virtual_address, section.virtual_address);
            assert_eq!(native.virtual_size, section.virtual_size);
            assert_eq!(native.raw_data_offset, section.raw_data_offset);
            assert_eq!(native.raw_data_size, section.raw_data_size);
        }
    }

    #[test]
    fn wasm_image_snapshot_exactly_projects_the_validated_pe() {
        let bytes = Arc::<[u8]>::from(pe_fixture());
        let analysis = analyze_bytes(&bytes).expect("analyze fixture");
        let BinaryAnalysis::Pe(pe) = &analysis else {
            panic!("PE analysis expected")
        };
        let image = wasm_pe_image(&analysis, Arc::clone(&bytes)).expect("exact WASM PE image");
        assert_eq!(image.identity, pe.identity);
        assert_eq!(image.size_of_headers, pe.size_of_headers);
        assert_eq!(image.size_of_image, pe.size_of_image);
        assert_eq!(image.sections.len(), pe.sections.len());
        for (wasm, section) in image.sections.iter().zip(&pe.sections) {
            assert_eq!(wasm.virtual_address, section.virtual_address);
            assert_eq!(wasm.virtual_size, section.virtual_size);
            assert_eq!(wasm.raw_data_offset, section.raw_data_offset);
            assert_eq!(wasm.raw_data_size, section.raw_data_size);
        }

        let mut changed = bytes.as_ref().to_vec();
        changed[0x200] ^= 0xff;
        assert!(
            wasm_pe_image(&analysis, Arc::from(changed)).is_none(),
            "WASM execution must not pair a validated map with changed bytes"
        );
    }

    #[test]
    fn safe_mode_has_no_default_attempts_but_preserves_explicit_skips() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        create_external_plugin(temp.path(), "dev.resymbol.external");
        let report = scan_plugins(temp.path(), true).expect("discover in safe mode");
        let fixture = Arc::<[u8]>::from(pe_fixture());
        let binary = temp.path().join("fixture.exe");
        fs::write(&binary, fixture.as_ref()).expect("write fixture binary");
        let base = analyze_bytes(&fixture).expect("analyze fixture");

        let automatic = execute_analysis_plugins(
            &base,
            &binary,
            &fixture,
            &report,
            &BTreeSet::new(),
            true,
            temp.path(),
        )
        .expect("safe automatic selection");
        assert!(automatic.attempts.is_empty());
        assert!(automatic.runs.is_empty());

        let selected =
            parse_plugin_selectors(&["dev.resymbol.external".to_owned()]).expect("valid selector");
        let explicit = execute_analysis_plugins(
            &base,
            &binary,
            &fixture,
            &report,
            &selected,
            true,
            temp.path(),
        )
        .expect("safe explicit selection");
        assert_eq!(explicit.attempts.len(), 1);
        assert_eq!(explicit.attempts[0].status, PluginAttemptStatus::Skipped);
        assert!(explicit.attempts[0].detail.contains("safe mode"));
    }

    #[test]
    fn strict_policy_counts_only_non_successful_attempts() {
        let attempts = [
            PluginAttempt {
                plugin_id: "dev.resymbol.success".to_owned(),
                status: PluginAttemptStatus::Succeeded,
                detail: "ok".to_owned(),
            },
            PluginAttempt {
                plugin_id: "dev.resymbol.failure".to_owned(),
                status: PluginAttemptStatus::Failed,
                detail: "failed".to_owned(),
            },
            PluginAttempt {
                plugin_id: "dev.resymbol.skip".to_owned(),
                status: PluginAttemptStatus::Skipped,
                detail: "skipped".to_owned(),
            },
        ];
        assert_eq!(strict_plugin_failure_count(&attempts), 2);
    }

    #[test]
    fn plugin_controlled_text_is_bounded_and_single_line() {
        let text = format!("first\n\u{1b}[31m second {}", "x".repeat(1_000));
        let sanitized = bounded_single_line(&text, 64);
        assert!(sanitized.len() <= 64);
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\u{1b}'));
        assert!(sanitized.ends_with("..."));
    }
}
