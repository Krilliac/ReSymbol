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
const SUCCESS_DESCENDANT_READY_MARKER: &str = "success-descendant-ready.marker";
const SUCCESS_DESCENDANT_SURVIVAL_MARKER: &str = "success-descendant-survived.marker";
const TIMEOUT_DESCENDANT_READY_MARKER: &str = "timeout-descendant-ready.marker";
const TIMEOUT_DESCENDANT_SURVIVAL_MARKER: &str = "timeout-descendant-survived.marker";
const STREAM_LIMIT_DESCENDANT_READY_MARKER: &str = "stream-limit-descendant-ready.marker";
const STREAM_LIMIT_DESCENDANT_SURVIVAL_MARKER: &str = "stream-limit-descendant-survived.marker";
#[cfg(unix)]
const ESCAPED_LEADER_READY_MARKER: &str = "escaped-leader-ready.marker";
const DESCENDANT_NATURAL_LIFETIME: Duration = Duration::from_secs(5);
const DESCENDANT_SURVIVAL_GRACE: Duration = Duration::from_secs(2);

fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    if let Some(pipe_holder_index) = arguments
        .iter()
        .position(|argument| argument == PIPE_HOLDER_SWITCH)
    {
        let ready_marker = arguments
            .get(pipe_holder_index + 1)
            .expect("pipe holder requires a ready marker path");
        let survival_marker = arguments
            .get(pipe_holder_index + 2)
            .expect("pipe holder requires a survival marker path");
        fs::write(ready_marker, b"ready")
            .expect("write pipe-holder ready marker before its natural lifetime");
        thread::sleep(DESCENDANT_NATURAL_LIFETIME);
        fs::write(survival_marker, b"survived")
            .expect("write pipe-holder survival marker after its natural lifetime");
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

    let timeout_limits = RuntimeLimits::default().with_request_timeout(Duration::from_secs(3));
    let timeout_host = ExternalProcessHost::new(timeout_limits).expect("valid timeout limits");
    let timeout = timeout_host
        .execute_trusted(&fixture.plugin, &fixture.request("timeout"))
        .expect_err("hung plugin must be terminated");
    assert!(matches!(&timeout, PluginRuntimeError::Timeout { .. }));
    assert_eq!(
        timeout.diagnostics().unwrap().stderr,
        "timeout diagnostic\n"
    );

    let descendant_limits = RuntimeLimits::default().with_request_timeout(Duration::from_secs(3));
    let descendant_host =
        ExternalProcessHost::new(descendant_limits).expect("valid descendant timeout limits");
    let held_pipes = descendant_host
        .execute_trusted(&fixture.plugin, &fixture.request("descendant-holds-pipes"))
        .expect("a completed direct child must tear down descendants holding inherited pipes");
    assert_eq!(held_pipes.response.result, json!({ "accepted": true }));
    assert!(
        fixture
            .plugin
            .path
            .join(SUCCESS_DESCENDANT_READY_MARKER)
            .is_file(),
        "successful invocation did not spawn its pipe-holding descendant"
    );
    let descendant_timeout = descendant_host
        .execute_trusted(&fixture.plugin, &fixture.request("descendant-timeout"))
        .expect_err("a parent and descendant that exceed the deadline must be terminated");
    assert!(matches!(
        descendant_timeout,
        PluginRuntimeError::Timeout { .. }
    ));
    assert!(
        fixture
            .plugin
            .path
            .join(TIMEOUT_DESCENDANT_READY_MARKER)
            .is_file(),
        "timed-out invocation did not spawn its pipe-holding descendant"
    );
    #[cfg(unix)]
    {
        let escaped_leader_started = Instant::now();
        let escaped_leader = descendant_host
            .execute_trusted(&fixture.plugin, &fixture.request("leader-leaves-group"))
            .expect_err("an escaped direct leader must still be terminated at the deadline");
        assert!(matches!(escaped_leader, PluginRuntimeError::Timeout { .. }));
        assert!(
            fixture
                .plugin
                .path
                .join(ESCAPED_LEADER_READY_MARKER)
                .is_file(),
            "mock direct leader did not leave its original process group"
        );
        assert!(
            escaped_leader_started.elapsed() < Duration::from_secs(5),
            "timeout waited for a direct leader after it left the contained process group"
        );
    }
    let output_limits = RuntimeLimits::default().with_output_limits(1_024, 2_048, 1_024);
    let output_host = ExternalProcessHost::new(output_limits).expect("valid output limits");
    let oversized = output_host
        .execute_trusted(&fixture.plugin, &fixture.request("oversized"))
        .expect_err("oversized stdout must terminate the plugin");
    assert!(matches!(
        &oversized,
        PluginRuntimeError::StreamLimit {
            stream: StreamKind::Stdout,
            ..
        }
    ));
    // Closing stdout after the bounded prefix races the mock's BrokenPipe handler, which may append
    // its own bounded error. The pre-limit diagnostic and configured cap are the stable contract.
    let oversized_stderr = &oversized.diagnostics().unwrap().stderr;
    assert!(
        oversized_stderr.starts_with("oversized diagnostic\n"),
        "the diagnostic emitted before the stream violation was lost: {oversized_stderr:?}"
    );
    assert!(
        oversized_stderr.len() <= output_host.limits().max_stderr_bytes,
        "captured stderr exceeded its configured limit"
    );
    let descendant_oversized = output_host
        .execute_trusted(&fixture.plugin, &fixture.request("descendant-oversized"))
        .expect_err("an over-limit child and its descendant must be terminated");
    assert!(matches!(
        descendant_oversized,
        PluginRuntimeError::StreamLimit {
            stream: StreamKind::Stdout,
            ..
        }
    ));
    assert!(
        fixture
            .plugin
            .path
            .join(STREAM_LIMIT_DESCENDANT_READY_MARKER)
            .is_file(),
        "over-limit invocation did not spawn its pipe-holding descendant"
    );
    assert_descendants_were_terminated(
        &fixture.plugin.path,
        &[
            (
                SUCCESS_DESCENDANT_SURVIVAL_MARKER,
                "successful invocation cleanup",
            ),
            (TIMEOUT_DESCENDANT_SURVIVAL_MARKER, "timeout cleanup"),
            (
                STREAM_LIMIT_DESCENDANT_SURVIVAL_MARKER,
                "stream-limit cleanup",
            ),
        ],
    );

    let message_limits = RuntimeLimits::default().with_max_messages(1);
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
        &failed,
        PluginRuntimeError::ProcessFailed { code: Some(7), .. }
    ));
    assert_eq!(
        failed.diagnostics().unwrap().stderr,
        "intentional mock failure\n"
    );

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
        write_diagnostic("timeout diagnostic")?;
        thread::sleep(Duration::from_secs(6));
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
            write_diagnostic("mock diagnostic")?;
        }
        "invalid-claim" => {
            write_claim(&mut output, true)?;
            write_success(&mut output, request_id, json!({ "accepted": false }))?;
        }
        "bad-handshake" => {
            write_success(&mut output, request_id, json!({ "accepted": false }))?;
        }
        "descendant-holds-pipes" => {
            spawn_pipe_holder(
                SUCCESS_DESCENDANT_READY_MARKER,
                SUCCESS_DESCENDANT_SURVIVAL_MARKER,
            )?;
            write_success(&mut output, request_id, json!({ "accepted": true }))?;
        }
        "descendant-timeout" => {
            spawn_pipe_holder(
                TIMEOUT_DESCENDANT_READY_MARKER,
                TIMEOUT_DESCENDANT_SURVIVAL_MARKER,
            )?;
            thread::sleep(Duration::from_secs(6));
        }
        "descendant-oversized" => {
            spawn_pipe_holder(
                STREAM_LIMIT_DESCENDANT_READY_MARKER,
                STREAM_LIMIT_DESCENDANT_SURVIVAL_MARKER,
            )?;
            write_success(&mut output, request_id, Value::String("x".repeat(8_192)))?;
        }
        #[cfg(unix)]
        "leader-leaves-group" => {
            join_parent_process_group()?;
            fs::write(ESCAPED_LEADER_READY_MARKER, b"escaped")?;
            thread::sleep(Duration::from_secs(6));
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
            write_diagnostic("oversized diagnostic")?;
            write_success(&mut output, request_id, Value::String("x".repeat(8_192)))?;
        }
        "fail" => {
            write_diagnostic("intentional mock failure")?;
            output.flush()?;
            process::exit(7);
        }
        _ => return Err(format!("unknown mock mode `{mode}`").into()),
    }
    output.flush()?;
    Ok(())
}

fn write_diagnostic(message: &str) -> io::Result<()> {
    let stderr = io::stderr();
    let mut diagnostic = stderr.lock();
    writeln!(diagnostic, "{message}")?;
    diagnostic.flush()
}

fn spawn_pipe_holder(
    ready_marker: &str,
    survival_marker: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let descendant = Command::new(std::env::current_exe()?)
        .args([PIPE_HOLDER_SWITCH, ready_marker, survival_marker])
        .spawn()?;
    drop(descendant);
    let ready_deadline = Instant::now() + Duration::from_secs(2);
    while !Path::new(ready_marker).is_file() {
        if Instant::now() >= ready_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("pipe-holder descendant did not become ready at `{ready_marker}`"),
            )
            .into());
        }
        thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

#[cfg(unix)]
fn join_parent_process_group() -> Result<(), Box<dyn std::error::Error>> {
    use rustix::process::{getpgid, getppid, setpgid};

    let parent = getppid().ok_or_else(|| io::Error::other("mock process has no parent"))?;
    let parent_group = getpgid(Some(parent))?;
    setpgid(None, Some(parent_group))?;
    Ok(())
}

fn assert_descendants_were_terminated(plugin_path: &Path, descendants: &[(&str, &str)]) {
    thread::sleep(DESCENDANT_NATURAL_LIFETIME + DESCENDANT_SURVIVAL_GRACE);
    for &(survival_marker, context) in descendants {
        assert!(
            !plugin_path.join(survival_marker).exists(),
            "{context} left a descendant alive long enough to write `{survival_marker}`"
        );
    }
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
