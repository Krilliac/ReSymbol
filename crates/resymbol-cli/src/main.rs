use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use resymbol_analysis::{BinaryAnalysis, analyze_bytes};
use resymbol_core::{
    DiscoveredPlugin, PLUGIN_DISABLED_SENTINEL, PluginDiscoveryOptions, PluginSource,
    discover_plugins,
    plugin_api::{DiagnosticSeverity, PluginHealthState, PluginRuntimeKind},
};
use resymbol_package::{ResymPackage, read_file_bound, write_file_new_bound};

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Analyze(args) => analyze(args, cli.safe_mode, cli.plugin_dir),
        Command::Inspect(args) => inspect(args),
        Command::Plugin(args) => plugins(args, cli.safe_mode, cli.plugin_dir),
    }
}

fn analyze(args: AnalyzeArgs, safe_mode: bool, plugin_dir: PathBuf) -> Result<()> {
    let binary = args
        .binary
        .canonicalize()
        .with_context(|| format!("cannot open binary {}", args.binary.display()))?;
    let bytes =
        fs::read(&binary).with_context(|| format!("cannot read binary {}", binary.display()))?;
    let analysis = analyze_bytes(&bytes)
        .with_context(|| format!("cannot analyze binary {}", binary.display()))?;
    let package = ResymPackage::from_bound_payload(env!("CARGO_PKG_VERSION"), analysis)
        .context("cannot create analysis package")?;
    let report = scan_plugins(&plugin_dir, safe_mode)?;
    let output = args
        .output
        .unwrap_or_else(|| default_package_path(&binary));
    write_file_new_bound(&output, &package)
        .with_context(|| format!("cannot write package {}", output.display()))?;

    println!("binary: {}", binary.display());
    print_analysis_summary(package.payload());
    println!("package: {}", output.display());
    println!("plugin directory: {}", plugin_dir.display());
    println!("safe mode: {safe_mode}");
    println!(
        "plugins: {} loadable / {} discovered",
        report.loadable().count(),
        report.plugins.len()
    );
    println!("plugin execution: not implemented; loadable plugins were discovered only");

    Ok(())
}

fn inspect(args: InspectArgs) -> Result<()> {
    let package_path = args
        .package
        .canonicalize()
        .with_context(|| format!("cannot open package {}", args.package.display()))?;
    let package: ResymPackage<BinaryAnalysis> = read_file_bound(&package_path)
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
    print_analysis_summary(package.payload());

    Ok(())
}

fn default_package_path(binary: &Path) -> PathBuf {
    binary.with_extension("resym")
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

    println!("claims: {}", analysis.symbol_graph().claims().len());
}

fn plugins(args: PluginArgs, safe_mode: bool, plugin_dir: PathBuf) -> Result<()> {
    match args.command {
        PluginCommand::List => list_plugins(&plugin_dir, safe_mode),
        PluginCommand::Doctor => doctor_plugins(&plugin_dir, safe_mode),
        PluginCommand::Enable { id } => set_plugin_enabled(&plugin_dir, &id, true),
        PluginCommand::Disable { id } => set_plugin_enabled(&plugin_dir, &id, false),
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
    println!("plugin directory: {}", report.root.display());
    println!("safe mode: {safe_mode}");

    if report.plugins.is_empty() {
        println!("no plugins discovered");
        return Ok(());
    }

    for plugin in &report.plugins {
        print_plugin(plugin);
    }

    Ok(())
}

fn doctor_plugins(plugin_dir: &Path, safe_mode: bool) -> Result<()> {
    let report = scan_plugins(plugin_dir, safe_mode)?;
    let mut errors = 0usize;

    println!("validating plugins in {}", report.root.display());
    for plugin in &report.plugins {
        print_plugin(plugin);
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

fn print_plugin(plugin: &DiscoveredPlugin) {
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
        plugin.path.display()
    );
    for diagnostic in &plugin.health.diagnostics {
        println!(
            "  {} {:?}: {}",
            severity_name(diagnostic.severity),
            diagnostic.code,
            diagnostic.message
        );
    }
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
    } else if sentinel.exists() {
        println!("plugin {id} is already disabled");
    } else {
        fs::write(&sentinel, b"")
            .with_context(|| format!("cannot create disable sentinel {}", sentinel.display()))?;
        println!("disabled plugin {id}");
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

    #[test]
    fn command_line_accepts_analysis_output_and_json_inspection() {
        let cli = Cli::try_parse_from([
            "resymbol",
            "analyze",
            "application.exe",
            "--output",
            "analysis.resym",
        ])
        .expect("analyze arguments parse");
        let Command::Analyze(args) = cli.command else {
            panic!("analyze command expected");
        };
        assert_eq!(args.binary, PathBuf::from("application.exe"));
        assert_eq!(args.output, Some(PathBuf::from("analysis.resym")));

        let cli = Cli::try_parse_from(["resymbol", "inspect", "analysis.resym", "--json"])
            .expect("inspect arguments parse");
        let Command::Inspect(args) = cli.command else {
            panic!("inspect command expected");
        };
        assert_eq!(args.package, PathBuf::from("analysis.resym"));
        assert!(args.json);
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
            },
            true,
            plugins.clone(),
        )
        .expect("analyze fixture");

        let package: ResymPackage<BinaryAnalysis> =
            read_file_bound(&output).expect("read bound package");
        assert_eq!(package.binary_sha256(), &resymbol_core::BinaryId::digest(&bytes));
        assert_eq!(&package.payload().identity().id, package.binary_sha256());
        assert_eq!(package.payload().symbol_graph().claims().len(), 3);

        let original = fs::read(&output).expect("read original package bytes");
        let error = analyze(
            AnalyzeArgs {
                binary,
                output: Some(output.clone()),
            },
            true,
            plugins,
        )
        .expect_err("existing package must not be overwritten");
        assert!(error.to_string().contains("cannot write package"));
        assert!(format!("{error:#}").contains("refusing to overwrite"));
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
}
