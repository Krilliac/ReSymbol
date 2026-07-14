use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{self, Command},
    thread,
    time::{Duration, Instant},
};

use resymbol_core::{
    ClaimProducer, DiscoveredPlugin, PluginSource,
    plugin_api::{
        MANIFEST_VERSION, PluginCapability, PluginHealth, PluginHealthState, PluginId,
        PluginManifest, PluginPermission, PluginRuntime,
    },
};
use resymbol_plugin_runtime::{
    ExternalProcessHost, ExternalProcessRequest, PluginMethod, PluginRuntimeError, RuntimeLimits,
    StreamKind,
};
use semver::{Version, VersionReq};
use serde_json::{Map, Value, json};
use tempfile::TempDir;

const MOCK_SWITCH: &str = "--resymbol-mock-plugin";
const PLUGIN_ID: &str = "dev.resymbol.mock";
const PLUGIN_NAME: &str = "Cross-platform mock";
const PLUGIN_VERSION: &str = "1.2.3";
const LITERAL_SHELL_ARG: &str = "; echo this-must-remain-a-literal-argument && exit 99";
const PIPE_HOLDER_SWITCH: &str = "--resymbol-pipe-holder";
const DESCENDANT_READY_MARKER: &str = "descendant-ready.marker";

fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|argument| argument == PIPE_HOLDER_SWITCH)
    {
        thread::sleep(Duration::from_millis(1_500));
        return;
    }
    if arguments.iter().any(|argument| argument == MOCK_SWITCH) {
        mock_plugin_main();
        return;
    }
    exercise_runtime();
}

fn exercise_runtime() {
    let fixture = MockFixture::new();

    let execution = ExternalProcessHost::default()
        .execute_trusted(&fixture.plugin, &fixture.request("success"))
        .expect("mock plugin should complete successfully");
    assert_eq!(execution.descriptor.id, PLUGIN_ID);
    assert_eq!(execution.response.result, json!({ "accepted": true }));
    assert_eq!(execution.claims.len(), 1);
    assert_eq!(execution.logs.len(), 1);
    assert!(execution.diagnostics.stderr.contains("mock diagnostic"));
    match &execution.claims[0].provenance().producer {
        ClaimProducer::Plugin { id, version } => {
            assert_eq!(id.as_str(), PLUGIN_ID);
            assert_eq!(version, PLUGIN_VERSION);
        }
        _ => panic!("claim provenance must be assigned to the plugin by the host"),
    }

    let rejected = ExternalProcessHost::default()
        .execute_trusted(&fixture.plugin, &fixture.request("reject"))
        .expect_err("plugin rejection must be preserved");
    assert!(matches!(
        rejected,
        PluginRuntimeError::PluginRejected { ref code, .. }
            if code == "permission-denied"
    ));

    let invalid_claim = ExternalProcessHost::default()
        .execute_trusted(&fixture.plugin, &fixture.request("invalid-claim"))
        .expect_err("unvalidated claims must not escape the runtime");
    assert!(matches!(
        invalid_claim,
        PluginRuntimeError::InvalidClaim { .. }
    ));

    let claim_during_initialize = ExternalProcessHost::default()
        .execute_trusted(
            &fixture.plugin,
            &fixture.request_with("success", PluginMethod::Initialize, true),
        )
        .expect_err("claim events outside analyze must be rejected");
    assert!(matches!(
        claim_during_initialize,
        PluginRuntimeError::ClaimEventNotAllowed { .. }
    ));

    let claim_without_grant = ExternalProcessHost::default()
        .execute_trusted(
            &fixture.plugin,
            &fixture.request_with("success", PluginMethod::Analyze, false),
        )
        .expect_err("claim events require an explicit claims.submit grant");
    assert!(matches!(
        claim_without_grant,
        PluginRuntimeError::PermissionDenied { .. }
    ));

    let invalid_handshake = ExternalProcessHost::default()
        .execute_trusted(&fixture.plugin, &fixture.request("bad-handshake"))
        .expect_err("a handshake that disagrees with the manifest must fail");
    assert!(matches!(
        invalid_handshake,
        PluginRuntimeError::Protocol { .. }
    ));

    let mut timeout_limits = RuntimeLimits::default();
    timeout_limits.request_timeout = Duration::from_millis(50);
    let timeout_host = ExternalProcessHost::new(timeout_limits).expect("valid timeout limits");
    let timeout = timeout_host
        .execute_trusted(&fixture.plugin, &fixture.request("timeout"))
        .expect_err("hung plugin must be terminated");
    assert!(matches!(timeout, PluginRuntimeError::Timeout { .. }));

    let mut descendant_limits = RuntimeLimits::default();
    descendant_limits.request_timeout = Duration::from_millis(500);
    let descendant_host =
        ExternalProcessHost::new(descendant_limits).expect("valid descendant timeout limits");
    let descendant_started = Instant::now();
    let held_pipes = descendant_host
        .execute_trusted(&fixture.plugin, &fixture.request("descendant-holds-pipes"))
        .expect_err("inherited descendant pipes must not outlive the invocation deadline");
    assert!(matches!(held_pipes, PluginRuntimeError::Timeout { .. }));
    assert!(
        fixture.plugin.path.join(DESCENDANT_READY_MARKER).is_file(),
        "mock direct child did not spawn the pipe-holding descendant"
    );
    let descendant_elapsed = descendant_started.elapsed();
    assert!(
        descendant_elapsed < Duration::from_millis(1_100),
        "execute blocked on detached pipe readers past its deadline"
    );
    thread::sleep(Duration::from_millis(1_600).saturating_sub(descendant_elapsed));

    let mut output_limits = RuntimeLimits::default();
    output_limits.max_message_bytes = 1_024;
    output_limits.max_stdout_bytes = 2_048;
    output_limits.max_stderr_bytes = 1_024;
    let output_host = ExternalProcessHost::new(output_limits).expect("valid output limits");
    let oversized = output_host
        .execute_trusted(&fixture.plugin, &fixture.request("oversized"))
        .expect_err("oversized stdout must terminate the plugin");
    assert!(matches!(
        oversized,
        PluginRuntimeError::StreamLimit {
            stream: StreamKind::Stdout,
            ..
        }
    ));

    let mut message_limits = RuntimeLimits::default();
    message_limits.max_messages = 1;
    let message_host = ExternalProcessHost::new(message_limits).expect("valid message limits");
    let too_many_messages = message_host
        .execute_trusted(&fixture.plugin, &fixture.request("success"))
        .expect_err("message count must be enforced independently of byte limits");
    assert!(matches!(
        too_many_messages,
        PluginRuntimeError::MessageLimit { limit: 1, .. }
    ));

    let failed = ExternalProcessHost::default()
        .execute_trusted(&fixture.plugin, &fixture.request("fail"))
        .expect_err("nonzero process exit must fail");
    assert!(matches!(
        failed,
        PluginRuntimeError::ProcessFailed { code: Some(7), .. }
    ));

    let mut disabled = fixture.plugin.clone();
    disabled.health.state = PluginHealthState::Disabled;
    assert!(matches!(
        ExternalProcessHost::default().execute_trusted(&disabled, &fixture.request("success")),
        Err(PluginRuntimeError::PluginNotLoadable(_))
    ));
}

struct MockFixture {
    _temporary: TempDir,
    plugin: DiscoveredPlugin,
}

impl MockFixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("create temporary plugin directory");
        let plugin_path = temporary.path().join("mock-plugin");
        fs::create_dir(&plugin_path).expect("create installed plugin directory");

        let source_executable = std::env::current_exe().expect("resolve test executable");
        let entrypoint_name = executable_name();
        let installed_executable = plugin_path.join(&entrypoint_name);
        fs::copy(&source_executable, &installed_executable)
            .expect("copy deterministic mock executable beneath plugin directory");
        make_executable(&installed_executable);

        let claims_permission =
            PluginPermission::new(PluginPermission::CLAIMS_SUBMIT).expect("valid permission");
        let manifest = PluginManifest {
            manifest_version: MANIFEST_VERSION,
            id: PluginId::new(PLUGIN_ID).expect("valid plugin id"),
            name: PLUGIN_NAME.to_owned(),
            version: Version::parse(PLUGIN_VERSION).expect("valid version"),
            api: VersionReq::parse("^0.1").expect("valid API requirement"),
            runtime: PluginRuntime::ExternalProcess {
                entrypoint: PathBuf::from(entrypoint_name),
                args: vec![MOCK_SWITCH.to_owned(), LITERAL_SHELL_ARG.to_owned()],
            },
            capabilities: BTreeSet::from([PluginCapability::new(
                PluginCapability::ANALYZER_BINARY,
            )
            .expect("valid capability")]),
            permissions: BTreeSet::from([claims_permission]),
            dependencies: BTreeMap::new(),
            description: None,
            authors: Vec::new(),
            license: None,
            homepage: None,
        };
        manifest.validate().expect("valid mock manifest");
        let plugin = DiscoveredPlugin {
            source: PluginSource::Directory,
            path: plugin_path,
            manifest: Some(manifest),
            health: PluginHealth::new(PluginHealthState::Enabled),
        };
        Self {
            _temporary: temporary,
            plugin,
        }
    }

    fn request(&self, mode: &str) -> ExternalProcessRequest {
        self.request_with(mode, PluginMethod::Analyze, true)
    }

    fn request_with(
        &self,
        mode: &str,
        method: PluginMethod,
        grant_claims: bool,
    ) -> ExternalProcessRequest {
        let payload = Map::from_iter([("mode".to_owned(), Value::String(mode.to_owned()))]);
        let mut request = ExternalProcessRequest::new("request-1", "session-1", method, payload)
            .expect("valid request");
        if grant_claims {
            let permission =
                PluginPermission::new(PluginPermission::CLAIMS_SUBMIT).expect("valid permission");
            request.set_granted_permissions([permission]);
        }
        request
    }
}

fn executable_name() -> String {
    if cfg!(windows) {
        "mock-plugin.exe".to_owned()
    } else {
        "mock-plugin".to_owned()
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)
        .expect("inspect copied mock executable")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("mark mock executable as executable");
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

fn mock_plugin_main() {
    if let Err(error) = run_mock_plugin() {
        let _diagnostic_result = writeln!(io::stderr(), "mock plugin error: {error}");
        process::exit(2);
    }
}

fn run_mock_plugin() -> Result<(), Box<dyn std::error::Error>> {
    if !std::env::args().any(|argument| argument == LITERAL_SHELL_ARG) {
        return Err("shell metacharacters were not delivered as one literal argument".into());
    }
    let mut input = BufReader::new(io::stdin().lock()).lines();
    let hello: Value = serde_json::from_str(&input.next().ok_or("missing hello")??)?;
    let request: Value = serde_json::from_str(&input.next().ok_or("missing request")??)?;
    if hello["kind"] != "hello" || request["kind"] != "request" {
        return Err("unexpected host protocol messages".into());
    }
    let mode = request["payload"]["mode"]
        .as_str()
        .ok_or("missing mock mode")?;
    let request_id = request["id"].as_str().ok_or("missing request id")?;

    if mode == "timeout" {
        thread::sleep(Duration::from_secs(2));
        return Ok(());
    }

    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_json_line(
        &mut output,
        &json!({
            "protocol": "resymbol.plugin-wire",
            "version": { "major": 1, "minor": 0 },
            "kind": "hello-result",
            "descriptor": {
                "id": if mode == "bad-handshake" { "dev.resymbol.wrong" } else { PLUGIN_ID },
                "name": PLUGIN_NAME,
                "version": PLUGIN_VERSION,
                "capabilities": ["analyzer.binary"],
                "requested_permissions": ["claims.submit"],
                "isolation": { "mode": "process", "required": true }
            }
        }),
    )?;

    match mode {
        "success" => {
            write_json_line(
                &mut output,
                &json!({
                    "protocol": "resymbol.plugin-wire",
                    "version": { "major": 1, "minor": 0 },
                    "kind": "event",
                    "direction": "plugin-to-host",
                    "method": "log",
                    "payload": { "level": "info", "message": "mock analysis started" }
                }),
            )?;
            write_claim(&mut output, false)?;
            write_success(&mut output, request_id, json!({ "accepted": true }))?;
            writeln!(io::stderr(), "mock diagnostic")?;
        }
        "invalid-claim" => {
            write_claim(&mut output, true)?;
            write_success(&mut output, request_id, json!({ "accepted": false }))?;
        }
        "bad-handshake" => {
            write_success(&mut output, request_id, json!({ "accepted": false }))?;
        }
        "descendant-holds-pipes" => {
            let _descendant = Command::new(std::env::current_exe()?)
                .args([MOCK_SWITCH, LITERAL_SHELL_ARG, PIPE_HOLDER_SWITCH])
                .spawn()?;
            fs::write(DESCENDANT_READY_MARKER, b"ready")?;
            write_success(&mut output, request_id, json!({ "accepted": true }))?;
        }
        "reject" => write_json_line(
            &mut output,
            &json!({
                "protocol": "resymbol.plugin-wire",
                "version": { "major": 1, "minor": 0 },
                "kind": "response",
                "direction": "plugin-to-host",
                "id": request_id,
                "ok": false,
                "error": {
                    "code": "permission-denied",
                    "message": "mock rejection",
                    "data": { "permission": "binary.read" }
                }
            }),
        )?,
        "oversized" => {
            write_success(&mut output, request_id, Value::String("x".repeat(8_192)))?;
        }
        "fail" => {
            writeln!(io::stderr(), "intentional mock failure")?;
            output.flush()?;
            process::exit(7);
        }
        _ => return Err(format!("unknown mock mode `{mode}`").into()),
    }
    output.flush()?;
    Ok(())
}

fn write_claim(output: &mut impl Write, invalid: bool) -> io::Result<()> {
    let size = if invalid { 0 } else { 16 };
    write_json_line(
        output,
        &json!({
            "protocol": "resymbol.plugin-wire",
            "version": { "major": 1, "minor": 0 },
            "kind": "event",
            "direction": "plugin-to-host",
            "method": "claim",
            "payload": {
                "subject": {
                    "kind": "function",
                    "binary": "0000000000000000000000000000000000000000000000000000000000000000",
                    "rva": 4096,
                    "size": size
                },
                "claim": { "kind": "name", "name": "mock_function" },
                "confidence": 0.9,
                "evidence": [{
                    "kind": "signature-match",
                    "description": "matched the deterministic test signature",
                    "data": { "signature": "00112233" }
                }]
            }
        }),
    )
}

fn write_success(output: &mut impl Write, id: &str, result: Value) -> io::Result<()> {
    write_json_line(
        output,
        &json!({
            "protocol": "resymbol.plugin-wire",
            "version": { "major": 1, "minor": 0 },
            "kind": "response",
            "direction": "plugin-to-host",
            "id": id,
            "ok": true,
            "result": result
        }),
    )
}

fn write_json_line(output: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, value).map_err(io::Error::other)?;
    output.write_all(b"\n")
}
