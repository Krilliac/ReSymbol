using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ReSymbol.ManagedHost;
using ReSymbol.PluginSdk;

var tests = new (string Name, Func<Task> Run)[]
{
    ("valid plugin emits a committed batch", ValidPluginCommitsAsync),
    ("managed exception rolls back every event", ManagedExceptionRollsBackAsync),
    ("ungranted host service is rejected transactionally", PermissionGateRollsBackAsync),
    ("deadline cancels a runaway managed request", DeadlineCancelsAsync),
    ("strict JSON rejects duplicate properties", StrictJsonRejectsDuplicatesAsync),
    ("bootstrap schema matches managed runtime contracts", BootstrapSchemaContractTests.RunAsync),
    ("managed SDK assembly identity is exact", ManagedSdkIdentityIsExactAsync),
    ("bounded reader rejects trailing input", BoundedReaderRejectsTrailingInputAsync),
    ("lifecycle phases gate host services and late work", LifecyclePhasesGateServicesAsync),
    ("claim validation matches canonical core rules", ClaimValidationMatchesCoreAsync),
    ("pre-cancelled execution never enters plugin code", PreCancelledExecutionSkipsPluginAsync),
    ("abandoned execution closes services and skips cleanup", AbandonedExecutionSkipsCleanupAsync),
    ("ordinary execution still performs bounded cleanup", OrdinaryExecutionPerformsCleanupAsync),
    ("trusted managed load marker is flushed first", ManagedLoadMarkerIsFlushedFirstAsync),
    ("host-owned output and grant preflight precedes marker", HostOwnedPreflightPrecedesMarkerAsync),
    ("symbols.read base analysis is preflighted and detached", SymbolsReadBaseAnalysisContractAsync),
    ("portable package paths and the host SDK are rejected", PortablePathsAndHostSdkAreRejectedAsync),
    ("buffered events retain their validated bytes", BufferedEventsRetainValidatedBytesAsync),
    ("output limits count exact NDJSON framing", OutputLimitsCountExactFramingAsync),
    ("descriptor hello order is canonical", DescriptorHelloOrderIsCanonicalAsync),
    ("committed events reserve exact mandatory output", ExactMandatoryOutputBudgetAsync),
    ("host service failures retain protocol codes", HostServiceFailuresRetainCodesAsync),
    ("artifact fingerprint matches portable v1", ArtifactFingerprintMatchesPortableV1Async),
    ("verified snapshots share one memory budget", VerifiedSnapshotsShareMemoryBudgetAsync),
    ("PE section extents exclude raw alignment padding", CanonicalPeSectionExtentsAsync),
};

foreach (var test in tests)
{
    await test.Run();
    Console.WriteLine($"ok - {test.Name}");
}
return 0;

static async Task ValidPluginCommitsAsync()
{
    var result = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        "dev.resymbol.test.valid-managed",
        ["binary.read", "claims.submit"]);
    Assert(result.ExitCode == 0, result.Diagnostics);
    var messages = DecodeLines(result.Output);
    Assert(messages.Count == 4, "expected handshake, log, claim, and response");
    Assert(messages[0].RootElement.GetProperty("kind").GetString() == "hello-result",
        "missing hello-result");
    Assert(messages[1].RootElement.GetProperty("method").GetString() == "log",
        "missing log event");
    Assert(messages[2].RootElement.GetProperty("method").GetString() == "claim",
        "missing claim event");
    Assert(messages[3].RootElement.GetProperty("ok").GetBoolean(),
        "expected successful response");
    Dispose(messages);
}

static async Task ManagedExceptionRollsBackAsync()
{
    var result = await RunFixtureAsync(
        "failing/ReSymbol.ManagedHost.FailingFixture.dll",
        "dev.resymbol.test.failing-managed",
        []);
    Assert(result.ExitCode == 0, result.Diagnostics);
    var messages = DecodeLines(result.Output);
    Assert(messages.Count == 2, "failed lifecycle must discard its buffered log");
    var response = messages[1].RootElement;
    Assert(!response.GetProperty("ok").GetBoolean(), "expected rejected response");
    Assert(response.GetProperty("error").GetProperty("code").GetString() == "internal",
        "managed exception should use internal error code");
    Dispose(messages);
}

static async Task PermissionGateRollsBackAsync()
{
    var result = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        "dev.resymbol.test.valid-managed",
        ["claims.submit"]);
    Assert(result.ExitCode == 0, result.Diagnostics);
    var messages = DecodeLines(result.Output);
    Assert(messages.Count == 2, "permission failure must not commit events");
    Assert(messages[1].RootElement.GetProperty("error").GetProperty("code").GetString() ==
           "permission-denied", "expected permission-denied response");
    Dispose(messages);
}

static async Task DeadlineCancelsAsync()
{
    var result = await RunFixtureAsync(
        "slow/ReSymbol.ManagedHost.SlowFixture.dll",
        "dev.resymbol.test.slow-managed",
        [],
        requestTimeoutMilliseconds: 500);
    Assert(result.ExitCode == 0, result.Diagnostics);
    var messages = DecodeLines(result.Output);
    Assert(messages.Count == 2, "cancelled lifecycle must not commit events");
    Assert(messages[1].RootElement.GetProperty("error").GetProperty("code").GetString() ==
           "cancelled", "expected cancelled response");
    Dispose(messages);
}

static Task StrictJsonRejectsDuplicatesAsync()
{
    ExpectThrows<HostException>(() => StrictJson.Decode<ProtocolVersion>(
        "{\"major\":1,\"major\":1,\"minor\":0}"u8,
        "test protocol"));
    ExpectThrows<HostException>(() => StrictJson.Decode<BinaryIdentityModel>(
        "{\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"size\":1,\"format\":{\"other\":\"pe\"},\"architecture\":\"x86_64\"}"u8,
        "test binary identity"));
    return Task.CompletedTask;
}

static Task ManagedSdkIdentityIsExactAsync()
{
    Assert(
        typeof(IReSymbolPlugin).Assembly.GetName().Version == new Version(0, 1, 0, 0),
        "managed SDK AssemblyVersion must remain pinned for the 0.1 contract line");
    var mismatched = typeof(ReSymbol.PluginSdk.IReSymbolPlugin).Assembly.GetName();
    mismatched.Version = new Version(99, 0, 0, 0);
    ExpectThrows<FileLoadException>(() => PluginLoadContext.ValidateSdkReference(mismatched));
    PluginLoadContext.ValidateSdkReference(
        typeof(ReSymbol.PluginSdk.IReSymbolPlugin).Assembly.GetName());
    return Task.CompletedTask;
}

static Task CanonicalPeSectionExtentsAsync()
{
    var rawPadding = new PeImageSection(0x1000, 0x101, 0x200, 0x200);
    Assert(rawPadding.LoadedSize == 0x101,
        "nonzero VirtualSize must define the loaded extent");
    Assert(rawPadding.FileBackedSize == 0x101,
        "raw FileAlignment padding must not be exposed through binary.read");

    var zeroFill = new PeImageSection(0x1000, 0x200, 0x200, 0x101);
    Assert(zeroFill.LoadedSize == 0x200, "VirtualSize includes the zero-filled tail");
    Assert(zeroFill.FileBackedSize == 0x101,
        "the zero-filled tail must not claim initializing file bytes");

    var zeroVirtualSize = new PeImageSection(0x1000, 0, 0x200, 0x200);
    Assert(zeroVirtualSize.LoadedSize == 0x200,
        "zero VirtualSize must use the loader-compatible raw-size fallback");
    Assert(zeroVirtualSize.FileBackedSize == 0x200,
        "the zero-VirtualSize fallback remains fully file-backed");
    return Task.CompletedTask;
}

static async Task BoundedReaderRejectsTrailingInputAsync()
{
    await using var input = new MemoryStream("one\ntwo"u8.ToArray());
    var reader = new BoundedNdjsonReader(input);
    _ = await reader.ReadLineAsync("first", 16);
    await ExpectThrowsAsync<HostException>(async () => await reader.RequireEndAsync());
}

static async Task LifecyclePhasesGateServicesAsync()
{
    var source = Path.Combine(
        AppContext.BaseDirectory,
        "fixtures",
        "valid",
        "ReSymbol.ManagedHost.ValidFixture.dll");
    Assert(File.Exists(source), $"missing built fixture: {source}");
    var temporary = Path.Combine(
        Path.GetTempPath(), $"resymbol-managed-phase-test-{Guid.NewGuid():N}");
    Directory.CreateDirectory(temporary);
    try
    {
        var binaryPath = Path.Combine(temporary, "input.exe");
        File.Copy(source, binaryPath);
        var bytes = await File.ReadAllBytesAsync(binaryPath);
        var identity = BinaryIdentity(bytes);
        var input = DirectHostInput(identity, PeMap(bytes));
        var binary = await ExactBinaryImage.OpenAsync(
            binaryPath,
            input.Bootstrap,
            64UL * 1024 * 1024,
            CancellationToken.None);
        var host = new PluginHostContext(binary, input);
        var plugin = new LifecycleProbePlugin(identity.Id);
        var descriptor = new PluginDescriptorModel(
            LifecycleProbePlugin.PluginId,
            "Lifecycle phase probe",
            "0.1.0",
            ["matcher.functions"],
            ["binary.read", "claims.submit"]);
        var loaded = new LoadedManagedPlugin(null!, plugin, descriptor);

        var execution = await ManagedPluginExecutor.ExecuteAsync(
            loaded,
            host,
            binary,
            input,
            CancellationToken.None);
        plugin.ReleasePostFinishAttempt();
        await plugin.PostFinishAttempt;

        Assert(execution.Rejection is null, execution.Rejection?.Message ?? "unexpected rejection");
        Assert(execution.Events.Count == 1,
            "only the claim submitted by the active analysis invocation may commit");
        Assert(execution.Events[0].Method == "claim", "expected the analysis claim event");
        Assert(plugin.AllChecksPassed,
            "one or more lifecycle service gates accepted a disallowed callback");
    }
    finally
    {
        Directory.Delete(temporary, recursive: true);
    }
}

static Task ClaimValidationMatchesCoreAsync()
{
    var binary = new string('a', 64);
    var validSubject = JsonObject(new Dictionary<string, object?>
    {
        ["kind"] = "function",
        ["binary"] = binary,
        ["rva"] = ulong.MaxValue - 1,
        ["size"] = 1UL,
    });
    var validAssertion = JsonObject(new Dictionary<string, object?>
    {
        ["kind"] = "comment",
        ["text"] = " retained ",
    });
    ClaimValidator.Validate(
        Claim(validSubject, validAssertion, [new ClaimEvidence("aa", " evidence ")]),
        binary);
    ClaimValidator.Validate(
        Claim(
            validSubject,
            validAssertion,
            [new ClaimEvidence(new string('a', 128), "bounded kind")]),
        binary);

    var functionPointerCall = JsonObject(new Dictionary<string, object?>
    {
        ["kind"] = "direct-call",
        ["call_site_rva"] = 0x1010UL,
        ["target"] = new Dictionary<string, object?>
        {
            ["kind"] = "function-pointer",
            ["slot_rva"] = 0x3000UL,
            ["rva"] = 0x2000UL,
        },
    });
    ClaimValidator.Validate(Claim(validSubject, functionPointerCall), binary);

    var functionPointerThunk = JsonObject(new Dictionary<string, object?>
    {
        ["kind"] = "thunk-target",
        ["target"] = new Dictionary<string, object?>
        {
            ["kind"] = "function-pointer",
            ["slot_rva"] = 0x3000UL,
            ["rva"] = 0x2000UL,
        },
    });
    ClaimValidator.Validate(Claim(validSubject, functionPointerThunk), binary);

    var incompleteFunctionPointerCall = JsonObject(new Dictionary<string, object?>
    {
        ["kind"] = "direct-call",
        ["call_site_rva"] = 0x1010UL,
        ["target"] = new Dictionary<string, object?>
        {
            ["kind"] = "function-pointer",
            ["rva"] = 0x2000UL,
        },
    });
    RejectClaim(Claim(validSubject, incompleteFunctionPointerCall), binary);

    var overflowingSubject = JsonObject(new Dictionary<string, object?>
    {
        ["kind"] = "global",
        ["binary"] = binary,
        ["rva"] = ulong.MaxValue,
        ["size"] = 1UL,
    });
    RejectClaim(Claim(overflowingSubject, validAssertion), binary);

    var whitespaceType = JsonObject(new Dictionary<string, object?>
    {
        ["kind"] = "type",
        ["binary"] = binary,
        ["key"] = " \t\r\n",
    });
    RejectClaim(Claim(whitespaceType, validAssertion), binary);

    foreach (var (kind, field) in new[]
    {
        ("name", "name"),
        ("function-prototype", "declaration"),
        ("type-definition", "declaration"),
        ("class-membership", "class_name"),
        ("comment", "text"),
    })
    {
        var assertion = JsonObject(new Dictionary<string, object?>
        {
            ["kind"] = kind,
            [field] = " \t",
        });
        RejectClaim(Claim(validSubject, assertion), binary);
    }

    var whitespaceAscii = JsonObject(new Dictionary<string, object?>
    {
        ["kind"] = "string-literal",
        ["encoding"] = "ascii",
        ["value"] = "   ",
    });
    RejectClaim(Claim(validSubject, whitespaceAscii), binary);

    var oversizedInstruction = JsonObject(new Dictionary<string, object?>
    {
        ["kind"] = "data-reference",
        ["instruction_rva"] = 0UL,
        ["instruction_size"] = 256UL,
        ["target_rva"] = 0UL,
    });
    RejectClaim(Claim(validSubject, oversizedInstruction), binary);

    foreach (var evidence in new ClaimEvidence[]
    {
        new("a", "description"),
        new(new string('a', 129), "description"),
        new("Uppercase", "description"),
        new("valid\n", "description"),
        new("valid", " \t\r\n"),
        new("valid", "description", default(JsonElement)),
    })
    {
        RejectClaim(Claim(validSubject, validAssertion, [evidence]), binary);
    }

    RejectClaim(Claim(validSubject, validAssertion, []), binary);
    RejectClaim(Claim(validSubject, validAssertion, confidence: double.NaN), binary);
    return Task.CompletedTask;
}

static async Task PreCancelledExecutionSkipsPluginAsync()
{
    var plugin = new ExecutionBoundaryProbePlugin(failAnalysis: false);
    using var harness = await CreateDirectHarnessAsync(plugin.Metadata, []);
    var loaded = new LoadedManagedPlugin(
        null!,
        plugin,
        Descriptor(plugin.Metadata));
    using var cancellation = new CancellationTokenSource();
    cancellation.Cancel();

    var execution = await ManagedPluginExecutor.ExecuteAsync(
        loaded,
        harness.Host,
        harness.Binary,
        harness.Input,
        cancellation.Token);

    Assert(execution.Rejection?.Code == "cancelled",
        "pre-cancelled execution must return a cancellation rejection");
    Assert(plugin.InitializationCalls == 0 && plugin.HealthCalls == 0 &&
        plugin.AnalysisCalls == 0 && plugin.ShutdownCalls == 0 &&
        plugin.DisposalCalls == 0,
        "a pre-cancelled execution entered plugin code");
}

static async Task AbandonedExecutionSkipsCleanupAsync()
{
    var plugin = new AbandonedExecutionProbePlugin();
    using var harness = await CreateDirectHarnessAsync(
        plugin.Metadata,
        ["claims.submit"]);
    var loaded = new LoadedManagedPlugin(
        null!,
        plugin,
        Descriptor(plugin.Metadata));
    using var cancellation = new CancellationTokenSource();

    var executionTask = ManagedPluginExecutor.ExecuteAsync(
        loaded,
        harness.Host,
        harness.Binary,
        harness.Input,
        cancellation.Token).AsTask();
    await plugin.AnalysisStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
    cancellation.Cancel();
    var execution = await executionTask.WaitAsync(TimeSpan.FromSeconds(5));

    Assert(execution.Rejection?.Code == "cancelled",
        "an abandoned invocation must return a cancellation rejection");
    Assert(plugin.ShutdownCalls == 0 && plugin.DisposalCalls == 0,
        "cleanup ran concurrently with an abandoned plugin invocation");

    plugin.AnalysisRelease.TrySetResult();
    await plugin.AnalysisCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));
    Assert(plugin.LateClaimRejected,
        "an invocation retained host services after its execution boundary closed");
}

static async Task OrdinaryExecutionPerformsCleanupAsync()
{
    var plugin = new ExecutionBoundaryProbePlugin(failAnalysis: true);
    using var harness = await CreateDirectHarnessAsync(plugin.Metadata, []);
    var loaded = new LoadedManagedPlugin(
        null!,
        plugin,
        Descriptor(plugin.Metadata));

    var execution = await ManagedPluginExecutor.ExecuteAsync(
        loaded,
        harness.Host,
        harness.Binary,
        harness.Input,
        CancellationToken.None);

    Assert(execution.Rejection?.Code == "internal",
        "ordinary lifecycle failure must remain an internal rejection");
    Assert(plugin.InitializationCalls == 1 && plugin.HealthCalls == 1 &&
        plugin.AnalysisCalls == 1 && plugin.ShutdownCalls == 1 &&
        plugin.DisposalCalls == 1,
        "ordinary execution did not run its lifecycle cleanup exactly once");
}

static async Task ManagedLoadMarkerIsFlushedFirstAsync()
{
    var loaded = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        "dev.resymbol.test.valid-managed",
        ["binary.read", "claims.submit"]);
    Assert(loaded.ExitCode == 0, loaded.Diagnostics);
    Assert(loaded.FlushSnapshots.Count >= 1,
        "managed host never flushed its load marker");
    Assert(loaded.FlushSnapshots[0] == HostRunner.LoadAttemptedMarker,
        "the first stderr flush was not exactly the trusted load marker");
    Assert(loaded.Diagnostics.StartsWith(
            HostRunner.LoadAttemptedMarker,
            StringComparison.Ordinal),
        "managed load marker was not the leading diagnostic bytes");

    await using var input = new MemoryStream();
    await using var output = new MemoryStream();
    using var diagnostics = new TrackingTextWriter();
    var rejected = await HostRunner.RunProcessAsync([], input, output, diagnostics);
    Assert(rejected == 1, "invalid arguments unexpectedly reached plugin loading");
    Assert(!diagnostics.ToString().Contains(
            HostRunner.LoadAttemptedMarker,
            StringComparison.Ordinal),
        "a preflight failure acquired the trusted load marker");
}

static async Task HostOwnedPreflightPrecedesMarkerAsync()
{
    var undeclaredGrant = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        "dev.resymbol.test.valid-managed",
        ["binary.read", "claims.submit", "network.connect"]);
    Assert(undeclaredGrant.ExitCode == 1,
        "host accepted a grant absent from host-owned manifest metadata");
    Assert(undeclaredGrant.Output.Length == 0,
        "grant preflight emitted partial protocol output");
    Assert(!undeclaredGrant.Diagnostics.Contains(
            HostRunner.LoadAttemptedMarker,
            StringComparison.Ordinal),
        "grant preflight occurred after the managed load marker");

    var expected = ExpectedMetadata("dev.resymbol.test.valid-managed") with
    {
        Name = new string('n', 600),
    };
    var mandatoryOutput = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        expected.Id,
        ["binary.read", "claims.submit"],
        outputLimits: new OutputLimits(16, 1024),
        maxMessageBytes: 1024,
        expectedPlugin: expected,
        requestId: new string('r', ProtocolConstants.MaxIdentifierBytes));
    Assert(mandatoryOutput.ExitCode == 1,
        "host accepted limits that cannot contain mandatory output");
    Assert(mandatoryOutput.Output.Length == 0,
        "mandatory-output preflight emitted partial protocol output");
    Assert(!mandatoryOutput.Diagnostics.Contains(
            HostRunner.LoadAttemptedMarker,
            StringComparison.Ordinal),
        "mandatory-output preflight occurred after the managed load marker");
    Assert(mandatoryOutput.Diagnostics.Contains(
            "mandatory output",
            StringComparison.Ordinal),
        "mandatory-output preflight did not report the negotiated limit");
}

static async Task SymbolsReadBaseAnalysisContractAsync()
{
    var expected = ExpectedMetadata("dev.resymbol.test.valid-managed") with
    {
        RequestedPermissions = ["binary.read", "claims.submit", "symbols.read"],
    };
    var grants = new[] { "binary.read", "claims.submit", "symbols.read" };

    var missing = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        expected.Id,
        grants,
        expectedPlugin: expected);
    AssertPreMarkerRejection(
        missing,
        "without supplying base analysis",
        "missing symbols.read base analysis");

    var malformed = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        expected.Id,
        grants,
        expectedPlugin: expected,
        requestPayloadFactory: identity => JsonObject(new Dictionary<string, object?>
        {
            ["binary"] = identity,
            ["base_analysis"] = null,
        }));
    AssertPreMarkerRejection(
        malformed,
        "base analysis must be an object",
        "malformed symbols.read base analysis");

    var ungranted = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        expected.Id,
        ["binary.read", "claims.submit"],
        expectedPlugin: expected,
        requestPayloadFactory: identity => JsonObject(new Dictionary<string, object?>
        {
            ["binary"] = identity,
            ["base_analysis"] = new Dictionary<string, object?>
            {
                ["symbols"] = Array.Empty<object>(),
            },
        }));
    AssertPreMarkerRejection(
        ungranted,
        "without symbols.read permission",
        "ungranted base analysis");

    var probe = new BaseAnalysisProbePlugin();
    JsonDocument? payloadDocument = null;
    using (var harness = await CreateDirectHarnessAsync(
        probe.Metadata,
        ["symbols.read"],
        requestPayloadFactory: identity =>
        {
            payloadDocument = JsonDocument.Parse(JsonSerializer.Serialize(
                new Dictionary<string, object?>
                {
                    ["binary"] = identity,
                    ["base_analysis"] = new Dictionary<string, object?>
                    {
                        ["symbols"] = new object[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["rva"] = 4096UL,
                                ["name"] = "recovered_entry",
                            },
                        },
                    },
                },
                ProtocolConstants.JsonOptions));
            return payloadDocument.RootElement;
        }))
    {
        HostInputReader.ValidateRequest(
            harness.Input.Request,
            harness.Input.Bootstrap,
            harness.Input.Hello.GrantedPermissions);
        var execution = await ManagedPluginExecutor.ExecuteAsync(
            new LoadedManagedPlugin(null!, probe, Descriptor(probe.Metadata)),
            harness.Host,
            harness.Binary,
            harness.Input,
            CancellationToken.None);
        Assert(execution.Rejection is null,
            execution.Rejection?.Message ?? "valid base analysis was rejected");
    }

    Assert(payloadDocument is not null, "base-analysis payload factory was not invoked");
    payloadDocument!.Dispose();
    var captured = probe.BaseAnalysis ?? throw new InvalidOperationException(
        "symbols.read grant did not expose base analysis to AnalysisRequest");
    var symbol = captured.GetProperty("symbols")[0];
    Assert(symbol.GetProperty("rva").GetUInt64() == 4096 &&
           symbol.GetProperty("name").GetString() == "recovered_entry",
        "AnalysisRequest base analysis changed after its source document was disposed");
}

static async Task PortablePathsAndHostSdkAreRejectedAsync()
{
    foreach (var unsafePath in new[]
    {
        "../escape.dll",
        "/absolute.dll",
        @"C:\absolute.dll",
        "nested//alias.dll",
        @"nested\.\alias.dll",
        "nested/trailing.dll.",
        "nested/AUX.dll",
        "nested/control\u0001.dll",
    })
    {
        ExpectThrows<HostException>(() =>
            HostInputReader.NormalizeRelativePath(unsafePath));
    }
    Assert(HostInputReader.NormalizeRelativePath(@"nested\portable.dll") ==
           "nested/portable.dll",
        "portable package path normalization is host-dependent");

    var traversal = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        "dev.resymbol.test.valid-managed",
        ["binary.read", "claims.submit"],
        bootstrapTransform: bootstrap => bootstrap with
        {
            EntryAssembly = "../escape.dll",
        });
    AssertPreMarkerRejection(
        traversal,
        "non-portable path component",
        "entry assembly traversal");

    var privateSdk = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        "dev.resymbol.test.valid-managed",
        ["binary.read", "claims.submit"],
        bootstrapTransform: bootstrap => bootstrap with
        {
            Assemblies =
            [
                .. bootstrap.Assemblies,
                new ExpectedAssembly(
                    "lib/RESYMBOL.PLUGINSDK.DLL",
                    new string('0', 64)),
            ],
        });
    AssertPreMarkerRejection(
        privateSdk,
        "must not enter the private closure",
        "private host SDK assembly");

    var sdkEntry = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        "dev.resymbol.test.valid-managed",
        ["binary.read", "claims.submit"],
        bootstrapTransform: bootstrap => bootstrap with
        {
            EntryAssembly = "ReSymbol.PluginSdk.dll",
            Assemblies =
            [
                new ExpectedAssembly(
                    "ReSymbol.PluginSdk.dll",
                    new string('0', 64)),
            ],
        });
    AssertPreMarkerRejection(
        sdkEntry,
        "cannot be the plugin entry assembly",
        "host SDK entry assembly");
}

static void AssertPreMarkerRejection(
    FixtureResult result,
    string expectedDiagnostic,
    string description)
{
    Assert(result.ExitCode == 1, $"host accepted {description}");
    Assert(result.Output.Length == 0, $"{description} emitted partial protocol output");
    Assert(!result.Diagnostics.Contains(
            HostRunner.LoadAttemptedMarker,
            StringComparison.Ordinal),
        $"{description} was rejected after the managed load marker");
    Assert(result.Diagnostics.Contains(expectedDiagnostic, StringComparison.Ordinal),
        $"{description} did not report the expected diagnostic: {result.Diagnostics}");
}

static async Task BufferedEventsRetainValidatedBytesAsync()
{
    var metadata = new PluginMetadata(
        "dev.resymbol.test.output-managed",
        "Output snapshot probe",
        "0.1.0",
        ["matcher.functions"],
        ["claims.submit"]);
    using var harness = await CreateDirectHarnessAsync(metadata, ["claims.submit"]);

    using (harness.Host.EnterPhase(PluginHostPhase.Initialization))
    {
    }
    using (harness.Host.EnterPhase(PluginHostPhase.HealthCheck))
    {
    }

    var subjectDocument = JsonDocument.Parse($$"""
        {"kind":"function","binary":"{{harness.Input.Bootstrap.Binary.Id}}","rva":0}
        """);
    var assertionDocument = JsonDocument.Parse("""
        {"kind":"function-entry"}
        """);
    var evidence = new List<ClaimEvidence>
    {
        new("control-flow", "validated before buffering"),
    };
    using (harness.Host.EnterPhase(PluginHostPhase.Analysis))
    {
        await harness.Host.SubmitClaimAsync(new SymbolClaim(
            subjectDocument.RootElement,
            assertionDocument.RootElement,
            1.0,
            evidence));
    }

    // Neither later collection mutation nor disposal of the source JsonElements
    // may affect the already validated and charged event bytes.
    evidence.Clear();
    subjectDocument.Dispose();
    assertionDocument.Dispose();
    var execution = new ManagedExecution(
        Descriptor(metadata),
        harness.Host.Finish(commit: true),
        null);
    var encoded = WireOutput.EncodeExecution(
        execution,
        harness.Input.Request.Id,
        harness.Input.Hello.Limits.MaxMessageBytes,
        harness.Input.Bootstrap.OutputLimits.MaxStdoutBytes);
    var messages = DecodeLines(encoded);
    Assert(messages.Count == 3, "expected descriptor, frozen claim, and response");
    var payload = messages[1].RootElement.GetProperty("payload");
    Assert(payload.GetProperty("evidence").GetArrayLength() == 1,
        "buffered evidence changed after submission");
    Assert(payload.GetProperty("evidence")[0].GetProperty("description").GetString() ==
           "validated before buffering", "buffered claim was reserialized from mutable state");
    Dispose(messages);
}

static Task OutputLimitsCountExactFramingAsync()
{
    var pluginEvent = WireOutput.EncodeEvent(
        "log",
        new { level = "info", message = "exact framing" },
        64 * 1024);
    _ = WireOutput.EncodeEvent(
        "log",
        new { level = "info", message = "exact framing" },
        pluginEvent.EncodedLineLength);
    ExpectHostServiceCode<HostResourceLimitException>(
        () => WireOutput.EncodeEvent(
            "log",
            new { level = "info", message = "exact framing" },
            pluginEvent.EncodedLineLength - 1),
        "resource-limit");

    var execution = new ManagedExecution(
        new PluginDescriptorModel(
            "dev.resymbol.test.output-managed",
            "Output limit probe",
            "0.1.0",
            ["matcher.functions"],
            []),
        [pluginEvent],
        null);
    var complete = WireOutput.EncodeExecution(
        execution,
        "output-limit-request",
        64 * 1024,
        1024 * 1024);
    var exact = WireOutput.EncodeExecution(
        execution,
        "output-limit-request",
        64 * 1024,
        complete.Length);
    Assert(exact.AsSpan().SequenceEqual(complete),
        "exact aggregate limit changed the encoded NDJSON bytes");
    Assert(exact.Count(value => value == (byte)'\n') == 3,
        "aggregate accounting omitted an NDJSON framing newline");
    ExpectThrows<HostException>(() => WireOutput.EncodeExecution(
        execution,
        "output-limit-request",
        64 * 1024,
        complete.Length - 1));

    // Rejections never retain events, so their actual hello + error response
    // is bounded independently instead of reducing successful event capacity.
    var adversarialMessage = string.Concat(Enumerable.Repeat(
        "quoted \\\" path \\\\ control \u0001 snowman \u2603 ",
        8));
    var rejectedExecution = new ManagedExecution(
        execution.Descriptor,
        [],
        new PluginRejection("resource-limit", adversarialMessage));
    var rejected = WireOutput.EncodeExecution(
        rejectedExecution,
        "rejected-output-limit-request",
        64 * 1024,
        1024 * 1024);
    var firstRejectedNewline = Array.IndexOf(rejected, (byte)'\n');
    Assert(firstRejectedNewline > 0 && rejected[^1] == (byte)'\n',
        "rejected output is not two framed NDJSON records");
    var longestRejectedLine = Math.Max(
        firstRejectedNewline,
        rejected.Length - firstRejectedNewline - 2);
    var exactRejected = WireOutput.EncodeExecution(
        rejectedExecution,
        "rejected-output-limit-request",
        longestRejectedLine,
        rejected.Length);
    Assert(exactRejected.AsSpan().SequenceEqual(rejected),
        "exact rejection limits changed the encoded NDJSON bytes");
    Assert(exactRejected.Count(value => value == (byte)'\n') == 2,
        "rejected output retained events or omitted framing");
    var boundedAggregate = WireOutput.EncodeExecution(
        rejectedExecution,
        "rejected-output-limit-request",
        longestRejectedLine,
        rejected.Length - 1);
    Assert(boundedAggregate.Length < rejected.Length,
        "oversized rejection did not fall back to a bounded error envelope");
    var boundedAggregateMessages = DecodeLines(boundedAggregate);
    Assert(boundedAggregateMessages.Count == 2,
        "bounded rejection is not exactly two NDJSON records");
    Assert(boundedAggregateMessages[1].RootElement
            .GetProperty("error").GetProperty("message").GetString() ==
           "managed plugin request failed",
        "bounded rejection did not use the canonical fallback message");
    Dispose(boundedAggregateMessages);

    var boundedMessage = WireOutput.EncodeExecution(
        rejectedExecution,
        "rejected-output-limit-request",
        longestRejectedLine - 1,
        rejected.Length);
    Assert(boundedMessage.Length < rejected.Length,
        "oversized rejection message did not use a bounded envelope");

    var mandatoryFallback = WireOutput.EncodeExecution(
        new ManagedExecution(
            execution.Descriptor,
            [],
            new PluginRejection("internal", "managed plugin request failed")),
        "rejected-output-limit-request",
        64 * 1024,
        1024 * 1024);
    ExpectThrows<HostException>(() => WireOutput.EncodeExecution(
        rejectedExecution,
        "rejected-output-limit-request",
        64 * 1024,
        mandatoryFallback.Length - 1));
    return Task.CompletedTask;
}

static Task DescriptorHelloOrderIsCanonicalAsync()
{
    var first = new PluginDescriptorModel(
        "dev.resymbol.test.canonical-managed",
        "Canonical descriptor probe",
        "0.1.0",
        ["matcher.types", "matcher.functions", "export.symbols"],
        ["claims.submit", "binary.read"]);
    var second = new PluginDescriptorModel(
        first.Id,
        first.Name,
        first.Version,
        ["export.symbols", "matcher.functions", "matcher.types"],
        ["binary.read", "claims.submit"]);
    const string requestId = "canonical request \\\"id\\\"";
    var firstOutput = WireOutput.EncodeExecution(
        new ManagedExecution(first, [], null),
        requestId,
        64 * 1024,
        64 * 1024);
    var secondOutput = WireOutput.EncodeExecution(
        new ManagedExecution(second, [], null),
        requestId,
        64 * 1024,
        64 * 1024);
    Assert(firstOutput.AsSpan().SequenceEqual(secondOutput),
        "descriptor set permutations changed canonical output bytes");

    var messages = DecodeLines(firstOutput);
    var descriptor = messages[0].RootElement.GetProperty("descriptor");
    Assert(descriptor.GetProperty("capabilities").EnumerateArray()
            .Select(value => value.GetString()).SequenceEqual(new[]
            {
                "export.symbols",
                "matcher.functions",
                "matcher.types",
            }),
        "capabilities were not emitted in ordinal order");
    Assert(descriptor.GetProperty("requested_permissions").EnumerateArray()
            .Select(value => value.GetString()).SequenceEqual(new[]
            {
                "binary.read",
                "claims.submit",
            }),
        "requested permissions were not emitted in ordinal order");
    Dispose(messages);
    return Task.CompletedTask;
}

static async Task ExactMandatoryOutputBudgetAsync()
{
    const int maxMessageBytes = 64 * 1024;
    const string requestId = "managed-phase-request";
    var metadata = new PluginMetadata(
        "dev.resymbol.test.exact-output-managed",
        "Exact mandatory output probe",
        "0.1.0",
        ["matcher.types", "matcher.functions"],
        ["claims.submit", "binary.read"]);
    var message = new string('x', 2048);
    var pluginEvent = WireOutput.EncodeEvent(
        "log",
        new { level = "info", message },
        maxMessageBytes);
    var mandatory = WireOutput.EncodeExecution(
        new ManagedExecution(Descriptor(metadata), [], null),
        requestId,
        maxMessageBytes,
        64 * 1024);
    var exactLimit = checked(mandatory.Length + pluginEvent.EncodedLineLength + 1);

    using (var harness = await CreateDirectHarnessAsync(
        metadata,
        [],
        new OutputLimits(3, exactLimit)))
    {
        using (harness.Host.EnterPhase(PluginHostPhase.Initialization))
        {
            harness.Host.Log(PluginLogLevel.Information, message);
        }
        var execution = new ManagedExecution(
            Descriptor(metadata),
            harness.Host.Finish(commit: true),
            null);
        var encoded = WireOutput.EncodeExecution(
            execution,
            requestId,
            maxMessageBytes,
            exactLimit);
        Assert(encoded.Length == exactLimit,
            "exact mandatory/event budget did not consume every framed byte");
    }

    using (var harness = await CreateDirectHarnessAsync(
        metadata,
        [],
        new OutputLimits(3, exactLimit - 1)))
    using (harness.Host.EnterPhase(PluginHostPhase.Initialization))
    {
        ExpectHostServiceCode<HostResourceLimitException>(
            () => harness.Host.Log(PluginLogLevel.Information, message),
            "resource-limit");
    }
}

static async Task HostServiceFailuresRetainCodesAsync()
{
    var metadata = new PluginMetadata(
        "dev.resymbol.test.service-errors-managed",
        "Host service error probe",
        "0.1.0",
        ["matcher.functions"],
        ["binary.read"]);
    using (var harness = await CreateDirectHarnessAsync(metadata, ["binary.read"]))
    {
        ExpectHostServiceCode<HostServiceUnavailableException>(
            () => harness.Host.ReadBinaryAsync(0, new byte[1]).GetAwaiter().GetResult(),
            "unavailable");
        using (harness.Host.EnterPhase(PluginHostPhase.Initialization))
        {
            ExpectHostServiceCode<HostInvalidArgumentException>(
                () => harness.Host.ReadBinaryAsync(ulong.MaxValue, new byte[1])
                    .GetAwaiter().GetResult(),
                "invalid-argument");
            ExpectHostServiceCode<HostResourceLimitException>(
                () => harness.Host.ReadBinaryAsync(
                        0,
                        new byte[ProtocolConstants.MaxBinaryReadCallBytes + 1])
                    .GetAwaiter().GetResult(),
                "resource-limit");
        }
    }

    using (var harness = await CreateDirectHarnessAsync(metadata, []))
    using (harness.Host.EnterPhase(PluginHostPhase.Initialization))
    {
        ExpectHostServiceCode<HostPermissionDeniedException>(
            () => harness.Host.ReadBinaryAsync(0, new byte[1]).GetAwaiter().GetResult(),
            "permission-denied");
    }
}

static async Task ArtifactFingerprintMatchesPortableV1Async()
{
    const string expected =
        "028234f8f3311ee24b94980a4e29dc1a8fcdc13a9a47abdabc3ec3bc3f0ce0b2";
    var temporary = Path.Combine(
        Path.GetTempPath(), $"resymbol-managed-fingerprint-test-{Guid.NewGuid():N}");
    Directory.CreateDirectory(Path.Combine(temporary, "empty"));
    Directory.CreateDirectory(Path.Combine(temporary, "nested"));
    try
    {
        await File.WriteAllBytesAsync(
            Path.Combine(temporary, "a.txt"),
            "A\n"u8.ToArray());
        await File.WriteAllBytesAsync(
            Path.Combine(temporary, "nested", "b.bin"),
            [0, 255]);
        await File.WriteAllTextAsync(
            Path.Combine(temporary, "plugin.disabled"),
            "excluded policy sentinel");

        var actual = Convert.ToHexString(
            await PluginArtifactFingerprint.ComputeAsync(
                temporary,
                CancellationToken.None)).ToLowerInvariant();
        Assert(actual == expected,
            $"portable artifact fingerprint mismatch: {actual}");
        await PluginArtifactFingerprint.VerifyAsync(
            temporary,
            expected,
            CancellationToken.None);

        await File.AppendAllTextAsync(Path.Combine(temporary, "a.txt"), "drift");
        await ExpectThrowsAsync<HostException>(() =>
            PluginArtifactFingerprint.VerifyAsync(
                temporary,
                expected,
                CancellationToken.None).AsTask());
    }
    finally
    {
        Directory.Delete(temporary, recursive: true);
    }
}

static async Task VerifiedSnapshotsShareMemoryBudgetAsync()
{
    var fixture = Path.Combine(
        AppContext.BaseDirectory,
        "fixtures",
        "valid",
        "ReSymbol.ManagedHost.ValidFixture.dll");
    Assert(File.Exists(fixture), $"missing built fixture: {fixture}");
    var assemblyBytes = checked((ulong)new FileInfo(fixture).Length);
    var budget = Math.Max(1_048_576UL, assemblyBytes);
    Assert(assemblyBytes <= budget,
        "assembly fixture does not independently fit the advertised budget");

    var result = await RunFixtureAsync(
        "valid/ReSymbol.ManagedHost.ValidFixture.dll",
        "dev.resymbol.test.valid-managed",
        ["binary.read", "claims.submit"],
        maxMemoryBytes: budget,
        fillBinaryToMemoryBudget: true);
    Assert(result.ExitCode == 1,
        "combined verified snapshots unexpectedly fit independent byte gates");
    Assert(result.Output.Length == 0,
        "snapshot-budget rejection emitted partial protocol output");
    Assert(!result.Diagnostics.Contains(
            HostRunner.LoadAttemptedMarker,
            StringComparison.Ordinal),
        "snapshot-budget rejection occurred after the managed load marker");
    Assert(result.Diagnostics.Contains(
            "verified-snapshot",
            StringComparison.Ordinal),
        "snapshot-budget rejection did not identify the shared snapshot gate");
}

static async Task<DirectHarness> CreateDirectHarnessAsync(
    PluginMetadata metadata,
    IReadOnlyList<string> grants,
    OutputLimits? outputLimits = null,
    Func<BinaryIdentityModel, JsonElement>? requestPayloadFactory = null)
{
    var source = Path.Combine(
        AppContext.BaseDirectory,
        "fixtures",
        "valid",
        "ReSymbol.ManagedHost.ValidFixture.dll");
    Assert(File.Exists(source), $"missing built fixture: {source}");
    var temporary = Path.Combine(
        Path.GetTempPath(), $"resymbol-managed-boundary-test-{Guid.NewGuid():N}");
    Directory.CreateDirectory(temporary);
    try
    {
        var binaryPath = Path.Combine(temporary, "input.exe");
        File.Copy(source, binaryPath);
        var bytes = await File.ReadAllBytesAsync(binaryPath);
        var identity = BinaryIdentity(bytes);
        var input = DirectHostInput(
            identity,
            PeMap(bytes),
            Expected(metadata),
            grants,
            outputLimits,
            requestPayloadFactory);
        var binary = await ExactBinaryImage.OpenAsync(
            binaryPath,
            input.Bootstrap,
            64UL * 1024 * 1024,
            CancellationToken.None);
        return new DirectHarness(temporary, binary, input, new PluginHostContext(binary, input));
    }
    catch
    {
        Directory.Delete(temporary, recursive: true);
        throw;
    }
}

static ExpectedPlugin Expected(PluginMetadata metadata) => new(
    metadata.Id,
    metadata.Name,
    metadata.Version,
    metadata.Capabilities.ToArray(),
    metadata.RequestedPermissions.ToArray());

static PluginDescriptorModel Descriptor(PluginMetadata metadata) => new(
    metadata.Id,
    metadata.Name,
    metadata.Version,
    metadata.Capabilities.ToArray(),
    metadata.RequestedPermissions.ToArray());

static HostInput DirectHostInput(
    BinaryIdentityModel identity,
    PeImageMap image,
    ExpectedPlugin? expectedPlugin = null,
    IReadOnlyList<string>? grants = null,
    OutputLimits? outputLimits = null,
    Func<BinaryIdentityModel, JsonElement>? requestPayloadFactory = null)
{
    expectedPlugin ??= new ExpectedPlugin(
        LifecycleProbePlugin.PluginId,
        "Lifecycle phase probe",
        "0.1.0",
        ["matcher.functions"],
        ["binary.read", "claims.submit"]);
    grants ??= ["binary.read", "claims.submit"];
    var bootstrap = new ManagedHostBootstrap(
        ProtocolConstants.ManagedHost,
        new ProtocolVersion(1, 0),
        new string('0', 64),
        "unused.dll",
        expectedPlugin,
        [],
        outputLimits ?? new OutputLimits(32, 256 * 1024),
        new ServiceLimits(4 * 1024 * 1024),
        identity,
        image);
    var hello = new HostHello(
        ProtocolConstants.PluginWire,
        new ProtocolVersion(1, 0),
        "hello",
        "managed-phase-session",
        expectedPlugin.Id,
        grants,
        new WireLimits(64 * 1024, 64 * 1024 * 1024, 30_000),
        new WireIsolation("process", true));
    var request = new HostRequest(
        ProtocolConstants.PluginWire,
        new ProtocolVersion(1, 0),
        "request",
        "host-to-plugin",
        "managed-phase-request",
        "analyze",
        requestPayloadFactory?.Invoke(identity) ??
            JsonObject(new Dictionary<string, object?> { ["binary"] = identity }));
    return new HostInput(bootstrap, hello, request);
}

static SymbolClaim Claim(
    JsonElement subject,
    JsonElement assertion,
    IReadOnlyList<ClaimEvidence>? evidence = null,
    double confidence = 1.0) => new(
        subject,
        assertion,
        confidence,
        evidence ?? [new ClaimEvidence("evidence", "valid evidence")]);

static void RejectClaim(SymbolClaim claim, string binary) =>
    ExpectThrows<HostException>(() => ClaimValidator.Validate(claim, binary));

static JsonElement JsonObject(IReadOnlyDictionary<string, object?> value) =>
    JsonSerializer.SerializeToElement(value, ProtocolConstants.JsonOptions);

static async Task<FixtureResult> RunFixtureAsync(
    string fixtureRelativePath,
    string pluginId,
    IReadOnlyList<string> grants,
    ulong requestTimeoutMilliseconds = 30_000,
    ulong maxMemoryBytes = 64 * 1024 * 1024,
    bool fillBinaryToMemoryBudget = false,
    OutputLimits? outputLimits = null,
    int maxMessageBytes = 16 * 1024,
    ExpectedPlugin? expectedPlugin = null,
    string requestId = "managed-test-request",
    Func<BinaryIdentityModel, JsonElement>? requestPayloadFactory = null,
    Func<ManagedHostBootstrap, ManagedHostBootstrap>? bootstrapTransform = null)
{
    var fixture = Path.Combine(AppContext.BaseDirectory, "fixtures", fixtureRelativePath);
    Assert(File.Exists(fixture), $"missing built fixture: {fixture}");
    var temporary = Path.Combine(Path.GetTempPath(), $"resymbol-managed-test-{Guid.NewGuid():N}");
    Directory.CreateDirectory(temporary);
    try
    {
        var pluginRoot = Path.Combine(temporary, "plugin");
        Directory.CreateDirectory(pluginRoot);
        var entryName = Path.GetFileName(fixture);
        var entry = Path.Combine(pluginRoot, entryName);
        File.Copy(fixture, entry);
        var binaryPath = Path.Combine(temporary, "input.exe");
        File.Copy(fixture, binaryPath);
        var entryBytes = await File.ReadAllBytesAsync(entry);
        if (fillBinaryToMemoryBudget)
        {
            if (maxMemoryBytes > int.MaxValue || maxMemoryBytes < (ulong)entryBytes.Length)
            {
                throw new InvalidOperationException(
                    "test snapshot budget cannot contain the fixture PE image");
            }
            var expandedBinary = new byte[checked((int)maxMemoryBytes)];
            entryBytes.CopyTo(expandedBinary, 0);
            await File.WriteAllBytesAsync(binaryPath, expandedBinary);
        }
        var binaryBytes = await File.ReadAllBytesAsync(binaryPath);
        var identity = BinaryIdentity(binaryBytes);
        var image = PeMap(binaryBytes);
        var artifactSha256 = Convert.ToHexString(
            await PluginArtifactFingerprint.ComputeAsync(
                pluginRoot,
                CancellationToken.None)).ToLowerInvariant();
        expectedPlugin ??= ExpectedMetadata(pluginId);
        var bootstrap = new ManagedHostBootstrap(
            ProtocolConstants.ManagedHost,
            new ProtocolVersion(1, 0),
            artifactSha256,
            entryName,
            expectedPlugin,
            [new ExpectedAssembly(entryName, Sha256(entryBytes))],
            outputLimits ?? new OutputLimits(16, 64 * 1024),
            new ServiceLimits(4 * 1024 * 1024),
            identity,
            image,
            DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds());
        bootstrap = bootstrapTransform?.Invoke(bootstrap) ?? bootstrap;
        var hello = new HostHello(
            ProtocolConstants.PluginWire,
            new ProtocolVersion(1, 0),
            "hello",
            "managed-test-session",
            pluginId,
            grants,
            new WireLimits(
                maxMessageBytes,
                maxMemoryBytes,
                requestTimeoutMilliseconds),
            new WireIsolation("process", true));
        var payload = requestPayloadFactory?.Invoke(identity) ??
            JsonSerializer.SerializeToElement(
                new Dictionary<string, object?> { ["binary"] = identity },
                ProtocolConstants.JsonOptions);
        var request = new HostRequest(
            ProtocolConstants.PluginWire,
            new ProtocolVersion(1, 0),
            "request",
            "host-to-plugin",
            requestId,
            "analyze",
            payload);
        await using var stdin = new MemoryStream(EncodeInput(bootstrap, hello, request));
        await using var stdout = new MemoryStream();
        using var stderr = new TrackingTextWriter();
        var exitCode = await HostRunner.RunProcessAsync(
            ["--plugin-root", pluginRoot, "--binary", binaryPath],
            stdin,
            stdout,
            stderr);
        return new FixtureResult(
            exitCode,
            stdout.ToArray(),
            stderr.ToString(),
            stderr.FlushSnapshots.ToArray());
    }
    finally
    {
        Directory.Delete(temporary, recursive: true);
    }
}

static ExpectedPlugin ExpectedMetadata(string pluginId) => pluginId switch
{
    "dev.resymbol.test.valid-managed" => new ExpectedPlugin(
        pluginId,
        "Valid managed host fixture",
        "0.1.0",
        ["matcher.functions"],
        ["binary.read", "claims.submit"]),
    "dev.resymbol.test.failing-managed" => new ExpectedPlugin(
        pluginId,
        "Failing managed host fixture",
        "0.1.0",
        ["matcher.functions"],
        []),
    "dev.resymbol.test.slow-managed" => new ExpectedPlugin(
        pluginId,
        "Slow managed host fixture",
        "0.1.0",
        ["matcher.functions"],
        []),
    _ => throw new InvalidOperationException("unknown fixture plugin id"),
};

static byte[] EncodeInput(params object[] messages)
{
    using var output = new MemoryStream();
    foreach (var message in messages)
    {
        output.Write(JsonSerializer.SerializeToUtf8Bytes(message, ProtocolConstants.JsonOptions));
        output.WriteByte((byte)'\n');
    }
    return output.ToArray();
}

static BinaryIdentityModel BinaryIdentity(byte[] bytes) => new(
    Sha256(bytes),
    (ulong)bytes.LongLength,
    "pe",
    "x86_64",
    PeImageBase(bytes));

static ulong PeImageBase(byte[] bytes)
{
    using var reader = new PEReader(new MemoryStream(bytes, writable: false));
    return reader.PEHeaders.PEHeader?.ImageBase
        ?? throw new InvalidOperationException("fixture has no PE header");
}

static PeImageMap PeMap(byte[] bytes)
{
    using var reader = new PEReader(new MemoryStream(bytes, writable: false));
    var headers = reader.PEHeaders;
    var pe = headers.PEHeader ?? throw new InvalidOperationException("fixture has no PE header");
    return new PeImageMap(
        checked((uint)pe.SizeOfHeaders),
        checked((uint)pe.SizeOfImage),
        headers.SectionHeaders.Select(section => new PeImageSection(
            checked((uint)section.VirtualAddress),
            checked((uint)section.VirtualSize),
            checked((uint)section.PointerToRawData),
            checked((uint)section.SizeOfRawData))).ToArray());
}

static string Sha256(byte[] bytes) =>
    Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

static List<JsonDocument> DecodeLines(byte[] output)
{
    Assert(output.Length > 0 && output[^1] == '\n', "output is not NDJSON terminated");
    return Encoding.UTF8.GetString(output).Split('\n', StringSplitOptions.RemoveEmptyEntries)
        .Select(line => JsonDocument.Parse(line)).ToList();
}

static void Dispose(IEnumerable<JsonDocument> documents)
{
    foreach (var document in documents)
    {
        document.Dispose();
    }
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

static void ExpectThrows<T>(Action action) where T : Exception
{
    try
    {
        action();
    }
    catch (T)
    {
        return;
    }
    throw new InvalidOperationException($"expected {typeof(T).Name}");
}

static void ExpectHostServiceCode<T>(Action action, string code)
    where T : Exception, IHostServiceFailure
{
    try
    {
        action();
    }
    catch (T exception)
    {
        Assert(exception.Code == code,
            $"expected host service code {code}, got {exception.Code}");
        return;
    }
    throw new InvalidOperationException($"expected {typeof(T).Name}");
}

static async Task ExpectThrowsAsync<T>(Func<Task> action) where T : Exception
{
    try
    {
        await action();
    }
    catch (T)
    {
        return;
    }
    throw new InvalidOperationException($"expected {typeof(T).Name}");
}

internal sealed record FixtureResult(
    int ExitCode,
    byte[] Output,
    string Diagnostics,
    IReadOnlyList<string> FlushSnapshots);

internal sealed class TrackingTextWriter : StringWriter
{
    internal List<string> FlushSnapshots { get; } = [];

    public override Task FlushAsync()
    {
        FlushSnapshots.Add(ToString());
        return base.FlushAsync();
    }
}

internal sealed record DirectHarness(
    string TemporaryRoot,
    ExactBinaryImage Binary,
    HostInput Input,
    PluginHostContext Host) : IDisposable
{
    public void Dispose() => Directory.Delete(TemporaryRoot, recursive: true);
}

internal sealed class BaseAnalysisProbePlugin : IReSymbolPlugin
{
    internal JsonElement? BaseAnalysis { get; private set; }

    public PluginMetadata Metadata { get; } = new(
        "dev.resymbol.test.base-analysis-managed",
        "Base analysis projection probe",
        "0.1.0",
        ["matcher.functions"],
        ["symbols.read"]);

    public ValueTask InitializeAsync(
        IPluginHost host,
        PluginInitialization initialization,
        CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

    public ValueTask<PluginHealth> CheckHealthAsync(
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new PluginHealth(PluginHealthState.Healthy));

    public ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        BaseAnalysis = request.BaseAnalysis;
        return ValueTask.CompletedTask;
    }

    public ValueTask ShutdownAsync(CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

internal sealed class ExecutionBoundaryProbePlugin(bool failAnalysis) : IReSymbolPlugin
{
    internal int InitializationCalls { get; private set; }
    internal int HealthCalls { get; private set; }
    internal int AnalysisCalls { get; private set; }
    internal int ShutdownCalls { get; private set; }
    internal int DisposalCalls { get; private set; }

    public PluginMetadata Metadata { get; } = new(
        "dev.resymbol.test.execution-boundary-managed",
        "Execution boundary probe",
        "0.1.0",
        ["matcher.functions"],
        []);

    public ValueTask InitializeAsync(
        IPluginHost host,
        PluginInitialization initialization,
        CancellationToken cancellationToken = default)
    {
        InitializationCalls++;
        return ValueTask.CompletedTask;
    }

    public ValueTask<PluginHealth> CheckHealthAsync(
        CancellationToken cancellationToken = default)
    {
        HealthCalls++;
        return ValueTask.FromResult(new PluginHealth(PluginHealthState.Healthy));
    }

    public ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        AnalysisCalls++;
        if (failAnalysis)
        {
            throw new InvalidOperationException("intentional boundary probe failure");
        }
        return ValueTask.CompletedTask;
    }

    public ValueTask ShutdownAsync(CancellationToken cancellationToken = default)
    {
        ShutdownCalls++;
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        DisposalCalls++;
        return ValueTask.CompletedTask;
    }
}

internal sealed class AbandonedExecutionProbePlugin : IReSymbolPlugin
{
    private IPluginHost? host;

    internal TaskCompletionSource AnalysisStarted { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource AnalysisRelease { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource AnalysisCompleted { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int ShutdownCalls { get; private set; }
    internal int DisposalCalls { get; private set; }
    internal bool LateClaimRejected { get; private set; }

    public PluginMetadata Metadata { get; } = new(
        "dev.resymbol.test.abandoned-managed",
        "Abandoned execution probe",
        "0.1.0",
        ["matcher.functions"],
        ["claims.submit"]);

    public ValueTask InitializeAsync(
        IPluginHost pluginHost,
        PluginInitialization initialization,
        CancellationToken cancellationToken = default)
    {
        host = pluginHost;
        return ValueTask.CompletedTask;
    }

    public ValueTask<PluginHealth> CheckHealthAsync(
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new PluginHealth(PluginHealthState.Healthy));

    public async ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        AnalysisStarted.TrySetResult();
        await AnalysisRelease.Task;
        try
        {
            await (host ?? throw new InvalidOperationException("host was not initialized"))
                .SubmitClaimAsync(BoundaryClaim(request.Binary.Sha256), CancellationToken.None);
        }
        catch (HostException)
        {
            LateClaimRejected = true;
        }
        finally
        {
            AnalysisCompleted.TrySetResult();
        }
    }

    public ValueTask ShutdownAsync(CancellationToken cancellationToken = default)
    {
        ShutdownCalls++;
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        DisposalCalls++;
        return ValueTask.CompletedTask;
    }

    private static SymbolClaim BoundaryClaim(string binary) => new(
        JsonSerializer.SerializeToElement(new
        {
            kind = "function",
            binary,
            rva = 0UL,
        }),
        JsonSerializer.SerializeToElement(new { kind = "function-entry" }),
        1.0,
        [new ClaimEvidence("control-flow", "late boundary probe claim")]);
}

internal sealed class LifecycleProbePlugin(string binarySha256) : IReSymbolPlugin
{
    internal const string PluginId = "dev.resymbol.test.lifecycle-managed";

    private readonly TaskCompletionSource initializationBackgroundRelease =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource analysisBackgroundRelease =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource postFinishRelease =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private IPluginHost? host;
    private Task<bool>? initializationBackgroundAttempt;
    private Task<bool>? analysisBackgroundAttempt;
    private Task? postFinishAttempt;

    internal bool InitializationReadAllowed { get; private set; }
    internal bool InitializationClaimRejected { get; private set; }
    internal bool HealthReadRejected { get; private set; }
    internal bool HealthClaimRejected { get; private set; }
    internal bool InitializationBackgroundClaimRejected { get; private set; }
    internal bool AnalysisReadAllowed { get; private set; }
    internal bool AnalysisClaimAllowed { get; private set; }
    internal bool ShutdownReadRejected { get; private set; }
    internal bool ShutdownClaimRejected { get; private set; }
    internal bool AnalysisBackgroundClaimRejected { get; private set; }
    internal bool DisposalReadRejected { get; private set; }
    internal bool DisposalClaimRejected { get; private set; }
    internal bool PostFinishClaimRejected { get; private set; }

    internal bool AllChecksPassed =>
        InitializationReadAllowed &&
        InitializationClaimRejected &&
        HealthReadRejected &&
        HealthClaimRejected &&
        InitializationBackgroundClaimRejected &&
        AnalysisReadAllowed &&
        AnalysisClaimAllowed &&
        ShutdownReadRejected &&
        ShutdownClaimRejected &&
        AnalysisBackgroundClaimRejected &&
        DisposalReadRejected &&
        DisposalClaimRejected &&
        PostFinishClaimRejected;

    internal Task PostFinishAttempt => postFinishAttempt ??
        throw new InvalidOperationException("post-finish attempt was not scheduled");

    public PluginMetadata Metadata { get; } = new(
        PluginId,
        "Lifecycle phase probe",
        "0.1.0",
        ["matcher.functions"],
        ["binary.read", "claims.submit"]);

    public async ValueTask InitializeAsync(
        IPluginHost pluginHost,
        PluginInitialization initialization,
        CancellationToken cancellationToken = default)
    {
        host = pluginHost;
        InitializationReadAllowed = await ReadAllowedAsync(cancellationToken);
        InitializationClaimRejected = await ClaimRejectedAsync(cancellationToken);
        initializationBackgroundAttempt = Task.Run(async () =>
        {
            await initializationBackgroundRelease.Task;
            return await ClaimRejectedAsync(CancellationToken.None);
        });
    }

    public async ValueTask<PluginHealth> CheckHealthAsync(
        CancellationToken cancellationToken = default)
    {
        HealthReadRejected = await ReadRejectedAsync(cancellationToken);
        HealthClaimRejected = await ClaimRejectedAsync(cancellationToken);
        return new PluginHealth(PluginHealthState.Healthy);
    }

    public async ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        AnalysisReadAllowed = await ReadAllowedAsync(cancellationToken);
        await RequireHost().SubmitClaimAsync(ValidClaim(), cancellationToken);
        AnalysisClaimAllowed = true;

        initializationBackgroundRelease.TrySetResult();
        InitializationBackgroundClaimRejected = await
            (initializationBackgroundAttempt ?? throw new InvalidOperationException(
                "initialization background attempt was not scheduled"));

        analysisBackgroundAttempt = Task.Run(async () =>
        {
            await analysisBackgroundRelease.Task;
            return await ClaimRejectedAsync(CancellationToken.None);
        });
    }

    public async ValueTask ShutdownAsync(CancellationToken cancellationToken = default)
    {
        ShutdownReadRejected = await ReadRejectedAsync(cancellationToken);
        ShutdownClaimRejected = await ClaimRejectedAsync(cancellationToken);
        analysisBackgroundRelease.TrySetResult();
        AnalysisBackgroundClaimRejected = await
            (analysisBackgroundAttempt ?? throw new InvalidOperationException(
                "analysis background attempt was not scheduled"));
    }

    public async ValueTask DisposeAsync()
    {
        DisposalReadRejected = await ReadRejectedAsync(CancellationToken.None);
        DisposalClaimRejected = await ClaimRejectedAsync(CancellationToken.None);
        postFinishAttempt = Task.Run(async () =>
        {
            await postFinishRelease.Task;
            PostFinishClaimRejected = await ClaimRejectedAsync(CancellationToken.None);
        });
    }

    internal void ReleasePostFinishAttempt() => postFinishRelease.TrySetResult();

    private async ValueTask<bool> ReadAllowedAsync(CancellationToken cancellationToken)
    {
        var destination = new byte[1];
        return await RequireHost().ReadBinaryAsync(0, destination, cancellationToken) == 1 &&
            destination[0] == 'M';
    }

    private async ValueTask<bool> ReadRejectedAsync(CancellationToken cancellationToken)
    {
        try
        {
            _ = await RequireHost().ReadBinaryAsync(0, new byte[1], cancellationToken);
            return false;
        }
        catch (HostException)
        {
            return true;
        }
    }

    private async ValueTask<bool> ClaimRejectedAsync(CancellationToken cancellationToken)
    {
        try
        {
            await RequireHost().SubmitClaimAsync(ValidClaim(), cancellationToken);
            return false;
        }
        catch (HostException)
        {
            return true;
        }
    }

    private IPluginHost RequireHost() => host ??
        throw new InvalidOperationException("plugin host was not initialized");

    private SymbolClaim ValidClaim()
    {
        var subject = JsonSerializer.SerializeToElement(new
        {
            kind = "function",
            binary = binarySha256,
            rva = 0UL,
        });
        var assertion = JsonSerializer.SerializeToElement(new
        {
            kind = "function-entry",
        });
        return new SymbolClaim(
            subject,
            assertion,
            1.0,
            [new ClaimEvidence("control-flow", "phase-gated fixture claim")]);
    }
}
