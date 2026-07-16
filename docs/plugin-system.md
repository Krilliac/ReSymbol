# Plugin system design

This document separates the implemented WebAssembly Component Model, external-process, native
C/C++, and managed/.NET runtimes from the wider plugin architecture. Directory discovery,
trust/quarantine state, sandboxed WASM analysis, one-shot process analysis, the disposable native
and managed helpers, and the initial contracts are current. Tool-hosted execution, packaged-plugin
installation, and richer persistent lifecycle behavior remain design work.

## User experience

The current installation path is deliberately simple:

1. Download a prebuilt plugin.
2. Drop its directory into `plugins/` beside the ReSymbol executable.
3. Launch ReSymbol.
4. A sandboxed WASM component is immediately eligible to autoload. For an external-process,
   native, or managed plugin, explicitly trust the displayed directory fingerprint before its
   first execution.

ReSymbol scans the directory, validates each candidate, resolves compatibility and dependencies,
and autoloads eligible plugins. Sandboxed WASM needs no trust record; an unchanged trusted process
artifact may run automatically during later analyses. Changing any fingerprinted process-plugin
file invalidates trust and requires a new decision. A plugin is never compiled, deleted, or
rewritten automatically when it fails.

An intended portable layout is:

```text
resymbol/
├── resymbol.exe
├── resymbol-native-host.exe
├── resymbol-managed-host.exe
├── plugins/
│   ├── community.msvc-rtti/
│   │   ├── plugin.toml
│   │   └── plugin.wasm
│   ├── vendor.native-matcher/
│   │   ├── plugin.toml
│   │   └── matcher.dll
│   ├── community.managed-resolver/
│   │   ├── plugin.toml
│   │   └── resolver.dll
│   └── .resymbol/              # host-owned trust/quarantine records
└── adapters/
```

Normal distributed plugins are compiled artifacts. ReSymbol does not invoke a compiler simply
because a source file was placed in `plugins/`.

Package-file verification and extraction are planned; a `.resymbol-plugin` archive is not a
substitute for the current unpacked-directory layout.

## Discovery and execution

The current sequence is:

1. Resolve the application-local `plugins/` directory and any explicitly configured additional
   directories.
2. Enumerate unpacked plugin directories, excluding the host-owned `.resymbol/` state directory.
3. Skip entries carrying a `plugin.disabled` sentinel and suppress all third-party execution in
   safe mode.
4. Parse bounded manifests, reject duplicate identities, and validate entrypoints, API ranges,
   runtimes, and dependencies.
5. Fingerprint every file in an eligible executable plugin directory except the manual
   `plugin.disabled` sentinel. Links, special files, excessive depth, and excessive file or byte
   counts are rejected.
6. Read the exact fingerprint's applicable policy records from `plugins/.resymbol/`; corrupt or
   unsafe host state fails closed. WASM ignores approval records but still enforces disablement and
   exact quarantine. Process runtimes require exact trust and enforce exact quarantine.
7. Launch eligible WASM in the no-WASI in-process component host, an eligible trusted
   external-process analyzer directly, or a trusted native/managed analyzer through its
   application-local disposable helper. Validate its complete claim batch before adding it to the
   analysis session.

The application must finish starting even when every third-party plugin is invalid.

## Plugin states

| State | Meaning | Automatic behavior |
|---|---|---|
| Approval required | Valid process artifact, but its exact fingerprint has not been trusted | Discover and report; do not launch |
| Enabled | Valid, compatible, healthy, and allowed under its runtime's policy | Load normally when its capability is eligible |
| Disabled | Explicitly disabled by the user or policy | Do not launch |
| Incompatible | API, ABI, platform, architecture, or dependency does not match | Keep installed and explain why |
| Quarantined | Validation, startup, runtime, or resource-limit failures make loading unsafe | Do not launch until reviewed and reset |
| Development error | An opt-in development build failed | Preserve compiler diagnostics; disable that build |

Trust and quarantine state is recorded outside plugin-controlled directories and is bound to both
plugin ID and exact fingerprint. Updating a process plugin therefore returns the new artifact to
`Approval required`; trust never transfers by filename or version alone. A changed WASM component
remains eligible for sandboxed autoload, but neither an old quarantine nor reset transfers to its
new fingerprint. Unsafe startup, runtime, claim,
protocol, timeout, or output-limit failures attributable to plugin execution quarantine the exact
artifact and preserve a bounded diagnostic. The native and managed helpers write and flush
family-specific versioned markers immediately before their first plugin-load operation. The parent
observes that raw prefix independently of structured diagnostics, strips it from user-visible
stderr, and treats a failure without the current marker conservatively as host-side. A changed
process artifact is not trusted, and no changed artifact is covered by an old quarantine record.

A sentinel file provides an out-of-band recovery mechanism:

```text
plugins/community.msvc-rtti/plugin.disabled
```

This must work even if plugin metadata storage or the normal UI is unavailable.
The parent checks both the sentinel and the exact artifact's applicable policy state immediately
before launch and again before accepting a completed batch. The second check is the commit
linearization point: a disablement, applicable trust revocation, quarantine, or corrupt-state
result observed there discards all claims without newly blaming the plugin; a policy change after
that point applies to later runs.

The management and execution controls are:

```console
resymbol plugin list
resymbol plugin enable community.msvc-rtti
resymbol plugin disable community.msvc-rtti
resymbol plugin doctor
resymbol plugin trust community.process-analyzer
resymbol plugin trust community.process-analyzer --fingerprint <sha256>
resymbol plugin untrust community.process-analyzer
resymbol plugin reset community.process-analyzer
resymbol analyze application.exe --plugin community.process-analyzer
resymbol analyze application.exe --plugin first.id --plugin second.id --strict-plugins
resymbol --safe-mode analyze application.exe
```

`trust` applies only to external-process, native, and managed artifacts and approves only the exact
fingerprint shown by ReSymbol; the optional `--fingerprint` value
lets an automation script fail if the installed artifact is not the one reviewed. `untrust`
removes that approval. `reset` clears quarantine for the current artifact but does not approve a
new one. `plugin.disabled` remains independent of trust, so toggling it does not change the
fingerprint.

Sandboxed WASM reports `sandboxed-autoload`; its `trust` command is rejected with an explanation.
Use `plugin disable`, safe mode, or exact-artifact quarantine to block a component.

By default, analysis runs every eligible sandboxed WASM component and eligible trusted process
analysis plugin. Repeating `--plugin` selects specific IDs. Approval-required process plugins and
quarantined, disabled, incompatible, or safe-mode plugins do not execute. A normal plugin failure
is non-fatal: base analysis and a valid package are still produced, with partial plugin claims
discarded. `--strict-plugins` writes that package first, then returns a failure status when an
explicitly selected or otherwise eligible plugin could not run successfully.

## Current manifest

Each unpacked plugin contains `plugin.toml`. The version 1 manifest parser and validator exist in
the Rust plugin API crate. Package-file verification and extraction are not implemented yet; a
future packaged plugin will contain the same manifest at its archive root.

```toml
manifest_version = 1
id = "community.msvc-rtti"
name = "MSVC RTTI Resolver"
version = "0.1.0"
api = "^0.1.0"

capabilities = [
  "analyzer.rtti",
  "resolver.symbols",
]

permissions = ["binary.read", "claims.submit"]

[runtime]
kind = "native"
entrypoint = "matcher.dll"
isolation = "out-of-process"
```

The current schema also supports dependency requirements and metadata fields. It rejects unknown
fields, unsafe entrypoint paths, unsupported manifest versions, incompatible APIs, and native
in-process requests that omit the `unsafe.in-process` permission. The implemented native host
accepts only `isolation = "out-of-process"`; a manifest cannot opt itself into ReSymbol's process.
Platform selectors, execution limits, permission rationale, integrity metadata, and publisher
information remain planned.

## Capabilities

Capabilities describe services a plugin provides. Planned families include:

- `loader.*` for binary and supplemental-data formats;
- `analyzer.*` for boundaries, control flow, RTTI, vtables, and compiler metadata;
- `matcher.*` for signatures, libraries, sources, and related builds;
- `resolver.*` for names, prototypes, types, fields, and relationships;
- `inference.*` for optional semantic providers;
- `source.*` for symbol, signature, source, and community-pack providers;
- `exporter.*` for PDB, DWARF, MAP, debugger, and report formats; and
- `integration.*` for IDA, Ghidra, Binary Ninja, and debugger bridges.

One plugin may provide multiple capabilities. Capability versions evolve independently where a
single global API version would cause unnecessary breakage.

## Permissions

Plugins receive only the ReSymbol data projections and host protocol operations needed for their
declared work. The one-shot external host uses manifest-declared projection and claim permissions;
its interactive binary reads are reserved. The WASM, native, and managed hosts implement
permission-gated, size-bounded `binary.read` callbacks for file-backed RVAs in the exact PE. Wider
planned permissions include temporary storage, package storage, approved network origins,
subprocess execution, and explicit file selections. A permission grants a host operation; it does
not convert a plugin's output into trusted fact.

For the current external, native, and managed runtimes, those permissions are **not
operating-system restrictions**. Once approved and launched, plugin code has the ambient filesystem, network,
credential, and process access normally available to the account running ReSymbol. A separate
helper contains crashes; it does not create an OS sandbox. Clearing most inherited environment
variables does not change that boundary. Only approve a plugin whose publisher and exact code you
would be willing to execute directly. A future sandbox layer may make declared network or
filesystem permissions enforceable at the OS boundary. Sandboxed WASM already enforces the narrower
linked-interface model described below; it exposes no WASI capability.

The shared process runner owns each external plugin or native/managed helper tree through a POSIX
process group or Windows Job Object. It terminates the whole owned tree when the direct child
completes, a deadline expires, a stdout/stderr capture worker fails, or the runtime guard drops, so
ordinary descendants cannot retain capture pipes after their parent exits. This is lifecycle
containment, not a filesystem, network, credential, process-authority, or general OS sandbox.
Windows uses a safe Rust wrapper to assign the child to its Job Object immediately after spawn,
leaving a narrow pre-assignment escape race. On POSIX a hostile plugin/helper or descendant can
deliberately leave its process group or session and escape later group termination.

The fingerprint proves only which local bytes were approved; it does not authenticate a publisher.
There is also an unavoidable check-to-launch window while plugin files remain mutable. Keep the
plugin directory writable only by the intended user, verify artifacts from their distribution
channel, and re-run analysis if local software could have replaced files during launch.

## Extension families

### WebAssembly (current first host)

WASM is the portable, capability-limited runtime for analyzers, matchers, resolvers, and eventually
exporters. The first host accepts `analyze` work for an exact validated PE32+ x86-64 image and
implements the `resymbol:plugin@0.1.0` Component Model world. It calls metadata, initialize, health,
analyze, and shutdown in a bounded transaction. Descriptor identity, version, capabilities, and
requested permissions must agree with the manifest; every claim is decoded and validated by the
same core rules as a process-plugin claim.

The linker exposes only ReSymbol's WIT `host` interface: bounded logging, `binary.read`,
`submit-claim`, and cancellation. It deliberately links no WASI filesystem, sockets, environment,
clock, random, or process interfaces. A component cannot acquire ambient authority through the
declared host surface. Because this boundary does not require a publisher/code trust decision,
eligible components autoload without an approval record and `resymbol plugin trust` rejects WASM
IDs. Safe mode and `plugin.disabled` still stop execution; attributable validation, lifecycle,
host-call, claim, trap, fuel, timeout, or resource failures discard the transaction and quarantine
the exact ID and fingerprint. `plugin reset` clears that exact quarantine without affecting a
different build.

The host fingerprints the complete plugin directory before component loading and again after the
lifecycle. It reads the component as bounded bytes, validates the Component Model binary, and
checks disable/quarantine policy again before committing output. The PE image exposed through
`binary.read` is an immutable, digest-checked file-to-RVA mapping; reads outside mapped headers or
section data are rejected rather than reaching the host filesystem.

Default input and instantiated-guest ceilings are:

- 64 MiB of component bytes, 256 MiB of linear memory, one memory, two tables, 32 instances, and a
  100,000-element table limit;
- 100,000,000 fuel, a 2 MiB WebAssembly stack, and a 30-second guest epoch deadline;
- 1 MiB per host event, 8 MiB of aggregate event output, and 4,096 events; and
- 1 MiB per `binary.read`, 64 MiB of aggregate requested reads, and a 1 GiB exact source-image
  ceiling.

Configured limits also have hard validation ceilings. Guest-limit exhaustion traps or rejects the
invocation; no partial claim batch is retained. The configurable hard maxima are 256 MiB of
component bytes, 4 GiB of linear memory, 10,000,000,000 fuel, an 8 MiB stack, 1 GiB of aggregate
reads, a 24-hour deadline, and 1,000,000 host events. Wasmtime itself executes and compiles
components inside the ReSymbol process. No-WASI capability isolation therefore does not provide
process containment: an engine, generated-code, or host-binding vulnerability can crash or
compromise ReSymbol. Fuel,
epoch interruption, store limits, and transactional commit constrain instantiated guest behavior,
not sandbox-engine escapes. The epoch timer is armed before synchronous component validation/JIT,
but it cannot interrupt compilation, and the guest store-memory limit does not cap compiler or
other host allocations. Except for the component-byte cap, a pathological component can therefore
exceed the configured guest deadline or memory limit during compilation.

The checked-in WIT package includes additive typed helpers for `string-literal` and
`data-reference` recovery assertions. Protocol 1.0 still carries the canonical tagged assertion
inside `symbol-claim.claim-json`; retaining that field avoids breaking existing component bindings.
The WIT helper enum uses `ascii`/`utf16-le`, while canonical claim JSON continues to use
`ascii`/`utf-16-le`; the WIT data-reference helper requires a nonzero `instruction-size` field.

#### WASM plugin author quickstart

The source-backed example uses the repository's Rust 1.86 toolchain, `wit-bindgen`, and an
example-local `wit-component` encoder. Add the core-WASM target and build it from the repository
root; no `cargo-component`, WASI SDK, C/C++ compiler, or global `wasm-tools` binary is needed:

```console
rustup target add wasm32-unknown-unknown
./examples/plugins/wasm/build.sh
```

Windows authors can run `examples\plugins\wasm\build.ps1`. Both scripts write
`examples/plugins/wasm/example-resolver.wasm` and keep intermediate files under the repository
`target/` directory. Direct dependencies are exact and the checked-in example `Cargo.lock` makes
subsequent builds use `--locked`.

Stage the two runtime files on a POSIX shell:

```console
stage=plugins/dev.resymbol.example.wasm-resolver
mkdir -p "$stage"
cp examples/plugins/wasm/plugin.toml "$stage/"
cp examples/plugins/wasm/example-resolver.wasm "$stage/"
```

Or with PowerShell:

```powershell
$stage = "plugins/dev.resymbol.example.wasm-resolver"
New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item examples/plugins/wasm/plugin.toml $stage
Copy-Item examples/plugins/wasm/example-resolver.wasm $stage
```

The example reads the exact DOS `MZ` bytes through `binary.read`, logs through the host, and submits
one binary-bound comment claim with byte evidence. ReSymbol discovers and autoloads it; use
`plugin disable` or safe mode when you do not want it to participate. Release archives already
contain this two-file example, and CI rebuilds the checked-in component and runs the staged fixture
through each exact platform release CLI.

### Native C and C++ (current first host)

Native support is part of the initial architecture because important reversing libraries and SDKs
already exist in C and C++. The first host supports out-of-process analysis plugins for x86-64 PE
sessions.

- The public binary contract is a versioned C ABI, not the Rust ABI or a compiler-specific C++ ABI.
- The same header is C++11-compatible and adds a `noexcept` declaration macro plus small
  exception-containment helpers without changing the C ABI. C++17 and newer also encode
  `noexcept` in the lifecycle pointer types; C++11/14 definitions must use the macro explicitly.
- Native plugins run in the version-matched `resymbol-native-host[.exe]` process shipped beside
  `resymbol[.exe]`; the application never accepts a helper from a plugin directory.
- The helper validates the manifest, C descriptor, ABI table, lifecycle status, callback bounds,
  exact analyzed-binary identity, and exact approved plugin-directory fingerprint. Claims are
  returned only after a complete successful run and a final fingerprint check.
- The current implementation has no in-process native path. A future explicitly trusted mode would
  need a separate design and warning because native libraries generally cannot be unloaded safely.

`sdk/native/include/resymbol_plugin.h` exposes protocol-1 assertion-kind/encoding constants and
fixed-width `resymbol_string_literal_assertion_v1` and
`resymbol_data_reference_assertion_v1` vocabulary structures. These are not serializers and do not
cross the C ABI: native plugins still submit the strict UTF-8 JSON claim envelope through
`submit_claim`. The examples under `examples/plugins/native/` include a C11 claim contract and a
C++11 exception-safe lifecycle implementation.

Native plugin code must never call `printf`, `puts`, or otherwise write directly to stdout. Stdout
is the helper's strict plugin-wire protocol; use the host `log` callback instead. Stderr is also a
bounded helper-diagnostic and load-attempted-marker channel, not an unbounded plugin log stream.

Protocol 1 caps descriptor IDs and versions at 128 UTF-8 bytes, names at 4,096 UTF-8 bytes, and
each capability/permission list at 4,096 identifiers. The public header defines the same maxima,
and the native runtime rejects an incompatible manifest before launching the helper.

The first helper verifies and buffers at most 1 GiB of exact source PE bytes for bounded synchronous
RVA callbacks. This source-image ceiling is separate from the wire protocol's advertised plugin
memory budget, which is not an enforced process-memory sandbox. A future mapped/chunked image
backend can reduce the helper's resident-memory cost without changing the C callback.

Native libraries are host operating-system and CPU artifacts. A Windows `.dll`, Linux `.so`, and
macOS `.dylib` are separate builds even when they analyze the same Windows executable. Private Unix
dependencies should be bundled beside the plugin and linked relative to it with `$ORIGIN` on Linux
or `@loader_path` on macOS. Windows loading adds only the plugin DLL directory and safe default
application/system directories. The official Linux archive keeps a static musl main executable but
ships a GNU helper built on Ubuntu 22.04 (glibc 2.35 or newer), allowing it to load ordinary glibc
plugins.

End users do not install a compiler, CMake, or Visual C++ build tools to use a prebuilt plugin.
Process separation is crash isolation only: native code still has the ambient authority of the
launching account and therefore requires exact-fingerprint trust.

### Managed/.NET (current first host)

Managed plugins run through the version-matched `resymbol-managed-host[.exe]` sibling and a
strongly typed .NET 8 SDK. Official hosts are published as self-contained single-file executables
for supported platforms, so installing .NET is a plugin-development requirement rather than an
end-user requirement. The current slice accepts one `analyze` request for a PE32+/x86-64 session.

The parent requires exact-fingerprint trust, resolves only its application-local helper, hashes the
complete private DLL closure, supplies an exact PE image map and binary identity, and enforces the
wall-clock deadline by terminating the helper. Any packaged `ReSymbol.PluginSdk.dll` remains in the
complete artifact fingerprint but its exact basename is excluded from the private-DLL closure, so
SDK references exact-identity-bind only to the helper's contract assembly. The helper reads verified
assembly snapshots, shares that SDK and platform assemblies through ordinary dependency resolution,
rejects private platform-assembly shadows, and checks the binary, assembly sources, disable sentinel,
and full artifact fingerprint again before committing output. A managed exception, invalid claim,
permission failure, timeout, cleanup failure, source drift, crash, or protocol violation discards
the transaction. Plugin-attributable failures quarantine only the exact artifact.

The managed SDK provides `StringEncoding`, validated `StringLiteralAssertion` and
`DataReferenceAssertion` records, and `ClaimAssertions` helpers that emit canonical `JsonElement`
payloads. It does not yet provide a typed helper for function-pointer control-flow targets. A
managed plugin that constructs a raw direct-call or thunk assertion may use the additive
`{"kind":"function-pointer","slot_rva":...,"rva":...}` target shape. The managed-host validator
checks its discriminator and required numeric fields, then the Rust session enforces the PE slot
and endpoint section policy. A direct call additionally requires the same-site companion data
reference; a thunk does not.
`examples/plugins/managed/` shows the typed payloads inside complete `SymbolClaim` values; the SDK
rejects unsupported encoding names, invalid literal text, and zero instruction sizes before
submission. `AnalysisRequest.BaseAnalysis` contains the detached canonical base analysis only when
`symbols.read` was granted; without that permission it is `null`.
Package schema 7 adds the TLS directory, callback-table RVA, ordered callback records, and partial
flag to that detached JSON object. Those fields are additive data, not a new managed SDK type or
plugin assertion; the plugin API remains unchanged.

#### Managed plugin author quickstart

From the repository root with the .NET 8 SDK, build the checked-in example exactly as CI does:

```console
dotnet restore examples/plugins/managed/Example.ManagedMatcher.csproj
dotnet build examples/plugins/managed/Example.ManagedMatcher.csproj \
  --configuration Release --no-restore -warnaserror -m:1
```

Stage only its manifest and entry assembly. On PowerShell:

```powershell
$stage = "plugins/dev.resymbol.example.managed-matcher"
New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item examples/plugins/managed/plugin.toml $stage
Copy-Item examples/plugins/managed/bin/Release/net8.0/Example.ManagedMatcher.dll $stage
```

Or on a POSIX shell:

```console
stage=plugins/dev.resymbol.example.managed-matcher
mkdir -p "$stage"
cp examples/plugins/managed/plugin.toml "$stage/"
cp examples/plugins/managed/bin/Release/net8.0/Example.ManagedMatcher.dll "$stage/"
```

For a real plugin, copy its private dependency DLLs into the same directory too, while omitting
`ReSymbol.PluginSdk.dll`. Keep the manifest's portable relative `entrypoint` synchronized with the
staged entry assembly. ReSymbol will discover this directory automatically; inspect it with
`resymbol plugin list`, then approve its exact fingerprint before analysis.

Never call `Console.Write*` or otherwise write directly to stdout from managed plugin code. Stdout
is the strict plugin-wire protocol, so any extra output invalidates the transaction; use
`IPluginHost.Log` instead. Stderr is the helper's bounded diagnostic and load-attempted-marker
channel, so `Console.Error` is not a plugin logging API either.

The verified DLL-plus-binary snapshot has a cumulative byte gate, and individual service calls,
aggregate binary reads, messages, stdout, diagnostics, and lifecycle phases are independently
bounded. That advertised byte gate is not a bound on total CLR process memory.

The collectible load context is a dependency-resolution and ordinary unload boundary, not a
security boundary. Managed code retains ambient framework APIs and may explicitly access files,
network, credentials, processes, the default load context, `Assembly.Load`, `NativeLibrary.Load`,
or other native interop paths. Direct unmanaged resolution through the plugin load context is
denied, but that does not prevent a plugin from invoking equivalent APIs itself. Only approve a
managed plugin whose exact code you would execute directly.

### External process (current first host)

External-process plugins support standalone tools, Python or model runtimes, proprietary SDKs, and
other heavyweight integrations. ReSymbol starts the manifest entrypoint directly without a shell,
confines that entrypoint path to the fingerprinted directory, clears arbitrary inherited
environment variables, and communicates through versioned NDJSON on stdin/stdout. Requests have
identifiers, deadlines, bounded message counts and byte sizes, bounded stderr diagnostics, and
strict descriptor/response validation. Claims require the `claims.submit` permission and are
committed only if the entire run validates.

The first host is one process tree per analysis request. It sends the host greeting and one `analyze`
request, closes input, and waits for the direct child while capturing bounded output. Direct-child
completion, a deadline, a stdout/stderr capture failure, or runtime drop terminates the owned
process tree subject to the deliberate-escape limits above. Stderr already observed before a
timeout, process-control failure, pipe I/O failure, or pipe-worker failure is retained. Deadline
cleanup also performs a bounded worker drain so a native or managed load marker does not depend on
pipe EOF. Process-control, pipe I/O, and pipe-worker failures are host infrastructure failures and
do not quarantine; timeout attribution remains governed by the existing runtime and load-marker
policy. The single request deadline covers helper startup, helper preflight, and plugin execution.
Interactive plugin-to-host `binary.read`/`read-binary`, cancellation, streaming backpressure, and a
persistent lifecycle are reserved by the contracts but not implemented in this host. The process
is not OS-sandboxed; fingerprint-bound trust is therefore mandatory before launch.

An interpreter is not assumed to exist. A plugin that needs Python either ships an appropriate
runtime within its package, declares a clearly diagnosed external prerequisite, or is distributed
as a standalone executable.

These assertion and target additions do not change the external-process protocol version: the
handshake remains `resymbol.plugin-wire` 1.0. Strict claim-event decoding accepts the additive
tagged JSON shapes below and the raw
`{"kind":"function-pointer","slot_rva":...,"rva":...}` control-flow target.
Package schema 5's recovery of both MSVC x64 Rev1 base-class descriptor layouts likewise adds no
plugin assertion or target shape. Package schema 6's transitive built-in thunk discovery composes
the existing exact `thunk-target` assertions instead of adding a chain-depth or terminal-target
shape; the wire handshake remains `resymbol.plugin-wire` 1.0. Plugin-supplied thunk claims remain
independent of the deterministic base analyzer's transitive seed-closure invariant.
Package schema 7's TLS callback discovery likewise reuses existing `function-entry` assertions for
retained callback slots and existing exact `thunk-target` assertions for callback-seeded hops;
it adds no assertion or control-flow target shape. Plugins granted `symbols.read` observe the
additive TLS directory and ordered callback fields in detached base-analysis JSON. The plugin API,
WIT/ABI, `resymbol.plugin-wire` 1.0 handshake, and neutral projection schema 6 remain unchanged.

### Tool-hosted bridges (planned host)

IDA, Ghidra, Binary Ninja, WinDbg, and similar integrations run inside another application's trust
domain. A bridge should remain thin:

1. identify the loaded binary and address mapping;
2. exchange a bounded graph projection or portable analysis package;
3. present proposed changes for review where the tool permits; and
4. apply accepted names, comments, types, and relationships through the tool's supported API.

The bridge never assumes that a matching filename means a matching binary hash.

ReSymbol currently provides standalone IDAPython and Ghidra Java import-script exporters. Those
scripts perform exact binary-identity checks and conservatively apply a small graph subset, but they
are generated artifacts rather than persistent tool-hosted plugins. Interactive preview, selective
application, and round-trip communication remain part of this planned bridge family. See
[exporting.md](exporting.md).

## Claims, not direct mutation

Plugins submit structured claims. A conceptual payload looks like:

```json
{
  "subject": {
    "binary": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "kind": "function",
    "rva": 2769200
  },
  "claim": {
    "kind": "name",
    "name": "NetworkSession::DecodeMovementPacket"
  },
  "confidence": 0.91,
  "evidence": [
    {
      "kind": "structural-match",
      "description": "structural match to an adjacent authorized build"
    }
  ]
}
```

The host attaches plugin identity, version, and run identity to accepted wire claims. The session's
run ledger binds that run to the exact artifact fingerprint. The example is the claim-event payload
rather than a complete NDJSON message.

A recovered UTF-16LE literal uses a sized global subject. `size` is the encoded content plus the
terminator, so the 12 UTF-16 code units below occupy 26 bytes:

```json
{
  "subject": {
    "binary": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "kind": "global",
    "rva": 12288,
    "size": 26
  },
  "claim": {
    "kind": "string-literal",
    "encoding": "utf-16-le",
    "value": "Recovered 世界"
  },
  "confidence": 0.95,
  "evidence": [
    {
      "kind": "string-literal",
      "description": "decoded terminated UTF-16LE bytes"
    }
  ]
}
```

ASCII values contain only bytes `0x20..=0x7e`; both encodings reject empty, whitespace-only,
control-containing, or embedded-NUL text. The value is canonical UTF-8 JSON text even when the
source bytes were UTF-16LE.

A data reference identifies the exact instruction and target RVA without inventing a target name,
data type, width, or read/write meaning:

```json
{
  "subject": {
    "binary": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "kind": "function",
    "rva": 4096,
    "size": 32
  },
  "claim": {
    "kind": "data-reference",
    "instruction_rva": 4104,
    "instruction_size": 7,
    "target_rva": 12288
  },
  "confidence": 0.9,
  "evidence": [
    {
      "kind": "data-flow",
      "description": "validated image-relative instruction operand"
    }
  ]
}
```

Core validation requires `instruction_size` to be nonzero. The current PE x64 session additionally
requires at most 15 bytes, keeps the instruction within its function subject, and verifies that the
target is backed readable initialized data.

The core checks ranges, type validity, confidence semantics, evidence, provenance, and transaction
consistency. Plugin claims remain separate from deterministic base claims in `AnalysisSession`, so
future reconciliation can change a preferred view without erasing unrelated human work.

## Dependencies and ordering

Discovery currently diagnoses duplicate IDs and missing or incompatible dependencies. The target
executor forms a directed acyclic graph before multi-stage execution, with explicit handling for
optional capabilities, cycles, ambiguous providers, and stable ordering.

Analysis-stage dependencies are more granular than package dependencies. For example, a class-name
resolver may wait for RTTI claims without forcing all exports to wait for semantic inference.

## Reload and failure recovery

Persistent hot reload remains a design goal. Its target behavior is transactional:

1. discover and validate the changed package;
2. start a separate new instance and run its health check;
3. stop accepting work for the old instance;
4. cancel or drain bounded in-flight work;
5. atomically switch capability routing; and
6. retire the old instance.

In the current one-shot hosts, a crashed or invalid plugin cannot leave a half-committed claim batch.
ReSymbol preserves bounded diagnostics, quarantines unsafe failures, and still writes deterministic
base analysis and the plugin-run ledger without logging binary contents or secrets by default.

Native in-process execution is not implemented. If it is designed later, the UI and CLI must state
that such plugins generally cannot be unloaded safely and may require an application restart.

## Developer mode and compilation errors

An optional developer mode may watch explicitly configured source-plugin workspaces and invoke a
declared build adapter. It is separate from ordinary plugin discovery because automatically
executing build scripts from a dropped directory would be unsafe.

When a development build fails:

- only that plugin enters `Development error`;
- the previous healthy artifact may remain active if its fingerprint and contract are unchanged;
- compiler output is retained as a bounded diagnostic;
- the core and other plugins continue running; and
- the plugin is retried only after a source change or explicit command.

## SDK expectations

Each supported family should receive:

- versioned contract definitions and generated bindings where appropriate;
- a minimal prebuilt example;
- conformance tests and a protocol test harness;
- manifest validation tooling;
- deterministic fake binary and graph fixtures; and
- packaging commands that produce a drop-in artifact.

The repository currently checks in the shared WIT contract and source-backed component, the
C11/C++11 native header and helper, the .NET contract assembly and managed helper, a strict
out-of-process JSON Schema, and minimal examples. CI reproducibly rebuilds the WASM fixture, runs it
through the real component host and exact release CLI, exercises the native contract with real C and
C++ shared libraries, and builds, tests, and self-contained-publishes the managed host across
supported release platforms.

The SDK is successful when plugin authors need their language's normal toolchain, while plugin users
need only the compiled package and ReSymbol.
