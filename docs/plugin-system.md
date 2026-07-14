# Plugin system design

This document separates the first implemented external-process runtime from the wider plugin
architecture. Directory discovery, trust/quarantine state, one-shot process analysis, and the
initial contracts are current. WASM, native, managed, tool-hosted execution, packaged-plugin
installation, and richer lifecycle behavior remain design work until a release marks them stable.

## User experience

The current installation path is deliberately simple:

1. Download a prebuilt plugin.
2. Drop its directory into `plugins/` beside the ReSymbol executable.
3. Launch ReSymbol.
4. For an external-process plugin, explicitly trust the displayed directory fingerprint before its
   first execution.

ReSymbol scans the directory, validates each candidate, resolves compatibility and dependencies,
and autoloads eligible plugins. An unchanged trusted process artifact may run automatically during
later analyses. Changing any fingerprinted file invalidates trust and requires a new decision. A
plugin is never compiled, deleted, or rewritten automatically when it fails.

An intended portable layout is:

```text
resymbol/
├── resymbol.exe
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
5. Fingerprint every file in an eligible process-plugin directory except the manual
   `plugin.disabled` sentinel. Links, special files, excessive depth, and excessive file or byte
   counts are rejected.
6. Read the exact fingerprint's trust and quarantine records from `plugins/.resymbol/`; corrupt or
   unsafe host state fails closed.
7. Launch an eligible, trusted external-process analyzer for one bounded request and validate its
   complete claim batch before adding it to the analysis session.

The application must finish starting even when every third-party plugin is invalid.

## Plugin states

| State | Meaning | Automatic behavior |
|---|---|---|
| Approval required | Valid process artifact, but its exact fingerprint has not been trusted | Discover and report; do not launch |
| Enabled | Valid, compatible, healthy, trusted, and allowed | Load normally when its capability is eligible |
| Disabled | Explicitly disabled by the user or policy | Do not launch |
| Incompatible | API, ABI, platform, architecture, or dependency does not match | Keep installed and explain why |
| Quarantined | Validation, startup, runtime, or resource-limit failures make loading unsafe | Do not launch until reviewed and reset |
| Development error | An opt-in development build failed | Preserve compiler diagnostics; disable that build |

Trust and quarantine state is recorded outside plugin-controlled directories and is bound to both
plugin ID and exact fingerprint. Updating a plugin therefore returns the new artifact to `Approval
required`; trust never transfers by filename or version alone. Unsafe startup, runtime, claim,
protocol, timeout, or output-limit failures quarantine the exact artifact and preserve a bounded
diagnostic. A changed artifact is neither trusted nor covered by the old quarantine record.

A sentinel file provides an out-of-band recovery mechanism:

```text
plugins/community.msvc-rtti/plugin.disabled
```

This must work even if plugin metadata storage or the normal UI is unavailable.

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

`trust` approves only the exact fingerprint shown by ReSymbol; the optional `--fingerprint` value
lets an automation script fail if the installed artifact is not the one reviewed. `untrust`
removes that approval. `reset` clears quarantine for the current artifact but does not approve a
new one. `plugin.disabled` remains independent of trust, so toggling it does not change the
fingerprint.

By default, analysis runs every eligible trusted external-process analysis plugin. Repeating
`--plugin` selects specific IDs. Untrusted, quarantined, disabled, incompatible, and safe-mode
plugins do not execute. A normal plugin failure is non-fatal: base analysis and a valid package are
still produced, with partial plugin claims discarded. `--strict-plugins` writes that package first,
then returns a failure status when an explicitly selected or otherwise eligible plugin could not
run successfully.

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
kind = "wasm"
entrypoint = "plugin.wasm"
```

The current schema also supports dependency requirements and metadata fields. It rejects unknown
fields, unsafe entrypoint paths, unsupported manifest versions, incompatible APIs, and native
in-process requests that omit the `unsafe.in-process` permission. Platform artifacts, execution
limits, permission rationale, integrity metadata, and publisher information remain planned.

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
declared work. The one-shot process host uses manifest-declared projection and claim permissions;
interactive binary reads are reserved. Wider planned permissions include temporary storage,
package storage, approved network origins, subprocess execution, and explicit file selections. A
permission grants a host operation; it does not convert a plugin's output into trusted fact.

For the current process runtime, those permissions are **not operating-system restrictions**. Once
approved and launched, the child has the ambient filesystem, network, credential, and process
access normally available to the account running ReSymbol. Clearing most inherited environment
variables does not make that child sandboxed. Only approve a process plugin whose publisher and
code you would be willing to execute directly. A future sandbox layer may make declared network or
filesystem permissions enforceable at the OS boundary.

The fingerprint proves only which local bytes were approved; it does not authenticate a publisher.
There is also an unavoidable check-to-launch window while plugin files remain mutable. Keep the
plugin directory writable only by the intended user, verify artifacts from their distribution
channel, and re-run analysis if local software could have replaced files during launch.

## Extension families

### WebAssembly (planned host)

WASM is the intended default for portable analyzers, matchers, resolvers, and exporters. The host
will expose versioned interfaces and capability-scoped resources. Plugins have no ambient
filesystem, network, clock, environment, or process access unless a specific interface grants it.
Memory, fuel or execution time, output size, and concurrency will be bounded.

### Native C and C++ (planned host)

Native support is part of the initial architecture because important reversing libraries and SDKs
already exist in C and C++.

- The public binary contract is a versioned C ABI, not the Rust ABI or a compiler-specific C++ ABI.
- A C++ SDK provides wrappers, ownership helpers, and generated types over that C surface.
- Native plugins will run in a version-matched helper process by default.
- The host will validate every message, handle, range, and returned allocation.
- An explicitly trusted in-process mode may be offered for workloads that justify the risk.

The release archive will supply the native host. End users will not install a compiler, CMake, or
Visual C++ build tools to use a prebuilt plugin. Platform runtime dependencies must be statically
linked or shipped according to their licenses where practical.

### Managed/.NET (planned host)

Managed plugins will run through a version-matched .NET host and a strongly typed SDK. Official
hosts will be published self-contained for supported platforms, so installing .NET is a developer
requirement, not an end-user requirement.

Out-of-process hosting remains the intended default. Assembly loading will be constrained to the
plugin package and declared shared contracts. A managed exception, unload failure, runaway task, or
protocol violation will be able to terminate that host without terminating ReSymbol.

### External process (current first host)

External-process plugins support standalone tools, Python or model runtimes, proprietary SDKs, and
other heavyweight integrations. ReSymbol starts the manifest entrypoint directly without a shell,
confines that entrypoint path to the fingerprinted directory, clears arbitrary inherited
environment variables, and communicates through versioned NDJSON on stdin/stdout. Requests have
identifiers, deadlines, bounded message counts and byte sizes, bounded stderr diagnostics, and
strict descriptor/response validation. Claims require the `claims.submit` permission and are
committed only if the entire run validates.

The first host is one process per analysis request. It sends the host greeting and one `analyze`
request, closes input, and waits for the direct child while capturing bounded output. On a deadline
it stops and reaps that direct child; it does not currently contain or terminate descendant
processes. Interactive plugin-to-host `binary.read`/`read-binary`, cancellation, streaming
backpressure, and a persistent lifecycle are reserved by the contracts but not implemented in this
host. The process is not OS-sandboxed; fingerprint-bound trust is therefore mandatory before
launch.

An interpreter is not assumed to exist. A plugin that needs Python either ships an appropriate
runtime within its package, declares a clearly diagnosed external prerequisite, or is distributed
as a standalone executable.

### Tool-hosted bridges (planned host)

IDA, Ghidra, Binary Ninja, WinDbg, and similar integrations run inside another application's trust
domain. A bridge should remain thin:

1. identify the loaded binary and address mapping;
2. exchange a bounded graph projection or portable analysis package;
3. present proposed changes for review where the tool permits; and
4. apply accepted names, comments, types, and relationships through the tool's supported API.

The bridge never assumes that a matching filename means a matching binary hash.

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

In the current one-shot host, a crashed or invalid plugin cannot leave a half-committed claim batch.
ReSymbol preserves bounded diagnostics, quarantines unsafe failures, and still writes deterministic
base analysis and the plugin-run ledger without logging binary contents or secrets by default.

Native in-process plugins generally cannot be unloaded safely and may require an application
restart. The UI and CLI must state this before enabling that mode.

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

The SDK is successful when plugin authors need their language's normal toolchain, while plugin users
need only the compiled package and ReSymbol.
