use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use resymbol_analysis::{
    AnalysisSession, BinaryAnalysis, PluginRunRecord, PluginRunStatus, analyze_bytes,
};
use resymbol_core::{
    BinaryId, DiscoveredPlugin, PLUGIN_DISABLED_SENTINEL, PluginDiscoveryOptions, PluginSource,
    SymbolClaim, discover_plugins,
    plugin_api::{
        DiagnosticSeverity, PluginCapability, PluginHealthState, PluginId, PluginPermission,
        PluginRuntime, PluginRuntimeKind,
    },
};
use resymbol_package::{ResymPackage, read_file_bound, write_file_new_bound};
use resymbol_plugin_runtime::{
    ExternalProcessHost, ExternalProcessRequest, PluginMethod, PluginRuntimeError, StreamKind,
};
use resymbol_plugin_state::{
    ArtifactFingerprint, ArtifactStateKey, FingerprintLimits, PluginArtifactStatus,
    PluginStateStore, StateChange, fingerprint_plugin_directory,
};
use serde_json::{Map, Value};

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

fn analyze(args: AnalyzeArgs, safe_mode: bool, plugin_dir: PathBuf) -> Result<()> {
    let binary = args
        .binary
        .canonicalize()
        .with_context(|| format!("cannot open binary {}", args.binary.display()))?;
    let bytes =
        fs::read(&binary).with_context(|| format!("cannot read binary {}", binary.display()))?;
    let base_analysis = analyze_bytes(&bytes)
        .with_context(|| format!("cannot analyze binary {}", binary.display()))?;
    let output = args.output.unwrap_or_else(|| default_package_path(&binary));
    ensure_output_absent(&output)?;

    let selectors = parse_plugin_selectors(&args.plugins)?;
    let report = scan_plugins(&plugin_dir, safe_mode)?;
    let execution =
        execute_analysis_plugins(&base_analysis, &report, &selectors, safe_mode, &plugin_dir)?;
    let strict_failures = strict_plugin_failure_count(&execution.attempts);
    let session = AnalysisSession::new(base_analysis, execution.runs, execution.claims)
        .context("cannot assemble validated analysis session")?;
    let package = ResymPackage::from_bound_payload(env!("CARGO_PKG_VERSION"), session)
        .context("cannot create analysis package")?;
    write_file_new_bound(&output, &package)
        .with_context(|| format!("cannot write package {}", output.display()))?;

    println!("binary: {}", binary.display());
    print_session_summary(package.payload())?;
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
    let package: ResymPackage<AnalysisSession> = read_file_bound(&package_path)
        .with_context(|| format!("cannot read package {}", package_path.display()))?;

    if args.json {
        let json = serde_json::to_string_pretty(&package)
            .context("cannot serialize validated package as JSON")?;
        println!("{json}");
        return Ok(());
    }

    println!("package: {}", package_path.display());
    println!("schema: {}", package.schema_version());
    println!("generator: {}", package.generator_version());
    print_session_summary(package.payload())?;

    Ok(())
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
    let host = ExternalProcessHost::default();

    for plugin in &report.plugins {
        let Some(manifest) = plugin.manifest.as_ref() else {
            continue;
        };
        let selected = selectors.contains(&manifest.id);
        let candidate = if explicitly_selected {
            selected
        } else {
            has_analysis_capability(manifest)
                && matches!(&manifest.runtime, PluginRuntime::ExternalProcess { .. })
        };
        if !candidate {
            continue;
        }
        if selected {
            found.insert(manifest.id.clone());
        }

        let result = execute_one_plugin(base_analysis, plugin, safe_mode, &store, &host)?;
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
    plugin: &DiscoveredPlugin,
    safe_mode: bool,
    store: &PluginStateStore,
    host: &ExternalProcessHost,
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
    if !matches!(&manifest.runtime, PluginRuntime::ExternalProcess { .. }) {
        return Ok(skip(format!(
            "runtime {} is not supported by this host",
            runtime_name(manifest.runtime.kind())
        )));
    }
    if !plugin.is_loadable() {
        return Ok(skip(format!(
            "discovery state {} is not loadable",
            state_name(plugin.health.state)
        )));
    }
    if requests_permission(manifest, PluginPermission::BINARY_READ) {
        return Ok(skip(
            "binary.read is unavailable in the current one-shot host".to_owned(),
        ));
    }
    if manifest.version.to_string().len() > 128 {
        return Ok(skip(
            "plugin version is too long for the auditable session ledger".to_owned(),
        ));
    }

    let first = match fingerprint_plugin_directory(&plugin.path, FingerprintLimits::default()) {
        Ok(report) => report,
        Err(error) => return Ok(skip(format!("artifact fingerprint failed: {error}"))),
    };
    let key = ArtifactStateKey::new(manifest.id.clone(), first.fingerprint);
    match store.status(&key) {
        Ok(PluginArtifactStatus::Trusted) => {}
        Ok(PluginArtifactStatus::ApprovalRequired) => {
            return Ok(skip(format!(
                "approval required for exact fingerprint {}",
                first.fingerprint
            )));
        }
        Ok(PluginArtifactStatus::Quarantined { reason }) => {
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
            value == PluginPermission::SYMBOLS_READ || value == PluginPermission::CLAIMS_SUBMIT
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
        return Ok(skip(format!(
            "artifact changed after trust check to {}; new approval is required",
            second.fingerprint
        )));
    }

    match host.execute_trusted(plugin, &request) {
        Ok(execution) => {
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
            let transient = matches!(
                &error,
                PluginRuntimeError::PluginRejected { code, .. } if code == "unavailable"
            );
            let host_side = matches!(
                &error,
                PluginRuntimeError::InvalidLimits(_)
                    | PluginRuntimeError::InvalidRequest(_)
                    | PluginRuntimeError::EncodeInput(_)
                    | PluginRuntimeError::PermissionNotRequested(_)
                    | PluginRuntimeError::StreamLimit {
                        stream: StreamKind::Stdin,
                        ..
                    }
                    | PluginRuntimeError::WorkerPanicked(_)
            );
            let detail = if transient {
                format!("transient plugin failure (not quarantined): {error}")
            } else if host_side {
                format!("host-side invocation failure (not quarantined): {error}")
            } else {
                quarantine_failed_artifact(
                    store,
                    &key,
                    &plugin.path,
                    &format!("plugin runtime failure: {error}"),
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

fn print_session_summary(session: &AnalysisSession) -> Result<()> {
    print_analysis_summary(session.base_analysis());
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

fn print_analysis_summary(analysis: &BinaryAnalysis) {
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
        }
        _ => println!("format: supported extension format"),
    }

    println!("base claims: {}", analysis.symbol_graph().claims().len());
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
    let key = ArtifactStateKey::new(manifest.id.clone(), report.fingerprint);
    match store.status(&key) {
        Ok(PluginArtifactStatus::ApprovalRequired) => {
            println!("  policy: approval-required");
            0
        }
        Ok(PluginArtifactStatus::Trusted) => {
            println!("  policy: trusted");
            0
        }
        Ok(PluginArtifactStatus::Quarantined { reason }) => {
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
    if !matches!(&manifest.runtime, PluginRuntime::ExternalProcess { .. }) {
        bail!(
            "plugin trust currently applies only to external-process plugins; {id} uses {}",
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
    println!(
        "arguments (literal values; escaped and bounded for display; no shell interpretation):"
    );
    let args = match &manifest.runtime {
        PluginRuntime::ExternalProcess { args, .. } => args.as_slice(),
        _ => &[],
    };
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
    println!("fingerprint: {fingerprint}");
    println!("declared permissions:");
    if manifest.permissions.is_empty() {
        println!("  (none)");
    } else {
        for permission in &manifest.permissions {
            println!("  {}", permission.as_str());
        }
    }
    println!(
        "WARNING: this plugin executes with your account's ambient filesystem, network, and process authority. Protocol permissions are advisory and are not an operating-system sandbox."
    );

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
            3
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
            3
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
            3
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
    fn safe_mode_has_no_default_attempts_but_preserves_explicit_skips() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        create_external_plugin(temp.path(), "dev.resymbol.external");
        let report = scan_plugins(temp.path(), true).expect("discover in safe mode");
        let base = analyze_bytes(&pe_fixture()).expect("analyze fixture");

        let automatic =
            execute_analysis_plugins(&base, &report, &BTreeSet::new(), true, temp.path())
                .expect("safe automatic selection");
        assert!(automatic.attempts.is_empty());
        assert!(automatic.runs.is_empty());

        let selected =
            parse_plugin_selectors(&["dev.resymbol.external".to_owned()]).expect("valid selector");
        let explicit = execute_analysis_plugins(&base, &report, &selected, true, temp.path())
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
