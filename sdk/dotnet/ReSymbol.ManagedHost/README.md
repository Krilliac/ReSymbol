# ReSymbol managed plugin host

This directory contains the disposable .NET 8 host for `IReSymbolPlugin` assemblies. Official
archives publish it as one self-contained, app-local executable, so an end user does not need a
system-wide .NET installation. One process handles one PE32+ x86-64 `analyze` request and then
terminates; no in-process managed path is implemented.

The executable accepts only explicit absolute paths:

```text
resymbol-managed-host --plugin-root <DIRECTORY> --binary <EXACT_BINARY>
```

Standard input is exactly three newline-terminated JSON objects followed by EOF:

1. a host-owned `resymbol.managed-host` 1.0 bootstrap;
2. a `resymbol.plugin-wire` 1.0 `hello` object;
3. one host-to-plugin `analyze` request.

Plugin code must treat both output streams as host-owned. Never call `Console.Write*` or otherwise
write directly to stdout: stdout is the strict plugin-wire protocol, and extra bytes invalidate the
entire transaction. Use `IPluginHost.Log` for plugin logging. Stderr is the helper's bounded
diagnostic and load-attempted-marker channel, so `Console.Error` is not a plugin logging API either.

The bootstrap binds the relative entry assembly, expected manifest metadata, the exact trusted
plugin-directory SHA-256, an exact SHA-256 closure of managed DLLs, the analyzed binary identity
and exact PE image map, output/service budgets, and an optional absolute deadline. Unknown or
duplicate JSON fields are rejected.
`managed-host-bootstrap.schema.json` publishes the corresponding integration contract.
This first execution slice accepts the same exact PE32+/x86-64 image map as the native helper.
Assemblies and the binary are read into verified snapshots before plugin code runs. Their combined
byte count must fit the one advertised snapshot budget (256 MiB with the current parent defaults),
in addition to hard ceilings of 512 private DLLs, 512 MiB of private DLLs, and a 1 GiB binary. The
parent keeps any packaged `ReSymbol.PluginSdk.dll` in the complete artifact fingerprint but excludes
that exact basename from the private-DLL closure, so SDK references exact-identity-bind only to the
host-supplied contract assembly. The collectible load context shares that SDK and platform
assemblies; every other private managed dependency must be in the bootstrap closure. Platform
assembly shadow names are rejected, and unmanaged resolution through that load context is denied.
The DLL sources, analyzed binary, complete artifact fingerprint, and `plugin.disabled` sentinel are
checked again before any output is written.

The host exposes permission-gated, phase-leased, per-call and aggregate-bounded `binary.read` and
`claims.submit` services. Binary reads are available only during initialization and analysis;
claims are accepted only during analysis. A callback retained by background work cannot use an
expired phase lease. Logs and claims remain in a transaction until initialization, health,
analysis, shutdown, disposal, and final identity verification complete. Managed exceptions,
cancellation, permission failures, invalid claims, resource limits, or cleanup failures discard
that transaction. Events are serialized into bounded immutable bytes when submitted, and protocol
stdout is written only after the lifecycle finishes; diagnostics are single-line and bounded on
stderr.

After preflight validation and immediately before the first assembly-load operation, the helper
writes and flushes `@resymbol-managed-host/load-attempted/v1@` to stderr. Module initializers and
type discovery can execute plugin code from that point onward. The Rust parent observes and removes
exactly that marker from visible diagnostics: a post-marker failure is attributable to the exact
plugin artifact and may quarantine it, while a failure without the current marker remains a
conservative host-side error. The parent also enforces the wall-clock deadline by killing the
helper, rechecks artifact and binary identity after every child outcome, and commits only the
complete validated batch.

This process boundary is crash and exception isolation, not an operating-system or CLR sandbox.
Managed code still has the ambient filesystem, network, credential, reflection, interop, and
process authority of the launching account and can call framework APIs directly. Explicit
`Assembly.Load*` APIs can attempt loads through another or the default load context, and direct
`NativeLibrary.Load` can reach the platform loader without the custom load context's cooperation.
The verified collectible context closes ordinary private dependency resolution; it does not remove
ambient .NET authority. The parent therefore requires exact-artifact trust, clears nonessential
environment state, uses a private bundle-extraction directory, enforces the wall-clock deadline,
and re-fingerprints the complete package after the helper exits. Same-account replacement, hard
links, and file-identity races between checks remain platform-hardening concerns even though
in-memory snapshots close the ordinary managed-load window.

The parent currently terminates and reaps this direct helper only; it does not place the helper in a
contained Unix process group or Windows Job Object. A managed plugin can therefore leave descendant
processes running after a timeout. If a descendant inherits stdout or stderr, the parent returns
after its bounded 50 ms result drain, but the corresponding capture reader remains blocked until the
descendant closes the inherited handle. Process-tree containment and inherited-handle hardening are
future work.

The no-NuGet test executable builds x64 fixture plugins and exercises, among other cases, a
successful transaction, lifecycle/managed-exception rollback, permission and phase enforcement,
snapshot budgets, marker publication, exact output accounting, duplicate-JSON rejection, and
trailing-input rejection:

```text
dotnet run --project ../ReSymbol.ManagedHost.Tests/ReSymbol.ManagedHost.Tests.csproj
```

## Build and publish from source

Building or developing the host requires the .NET 8 SDK. Ordinary release users do not run these
commands. From this directory, a local test/build is:

```console
dotnet restore ../ReSymbol.ManagedHost.Tests/ReSymbol.ManagedHost.Tests.csproj
dotnet build ../ReSymbol.ManagedHost.Tests/ReSymbol.ManagedHost.Tests.csproj \
  --configuration Release --no-restore -warnaserror -m:1
dotnet run --project ../ReSymbol.ManagedHost.Tests/ReSymbol.ManagedHost.Tests.csproj \
  --configuration Release --no-build
```

Publish a relocatable helper for one supported runtime identifier (`win-x64`, `linux-x64`,
`osx-x64`, or `osx-arm64`):

```console
dotnet restore ReSymbol.ManagedHost.csproj --runtime <RID>
dotnet publish ReSymbol.ManagedHost.csproj \
  --configuration Release --runtime <RID> --self-contained true --no-restore \
  --output ../../../target/managed/<RID>/publish \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:IncludeAllContentForSelfExtract=true \
  -p:PublishTrimmed=false -p:PublishReadyToRun=false -p:PublishAot=false \
  -p:EnableCompressionInSingleFile=false
```

The publish directory should contain exactly `resymbol-managed-host[.exe]`. Place that regular,
unlinked executable beside `resymbol[.exe]`; the CLI never searches `PATH` or a plugin directory for
the helper. Plugin authors target `net8.0`, reference `ReSymbol.PluginSdk` for compilation, and do
not copy `ReSymbol.PluginSdk.dll` into the plugin package because the helper supplies it.
