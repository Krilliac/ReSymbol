# Plugin system design

This document defines the target plugin architecture. The implementation is under active
development. Sections labeled current describe the initial checked-in contracts; other manifests,
commands, and wire-protocol examples remain design material until a release marks them stable.

## User experience

The primary installation path is deliberately simple:

1. Download a prebuilt plugin.
2. Drop its directory or package into `plugins/` beside the ReSymbol executable.
3. Launch ReSymbol.

ReSymbol scans the directory, validates each candidate, resolves compatibility and dependencies,
and autoloads healthy plugins. It does not automatically delete or rewrite a plugin that fails.

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
│   └── community.managed-resolver.resymbol-plugin
└── adapters/
```

Normal distributed plugins are compiled artifacts. ReSymbol does not invoke a compiler simply
because a source file was placed in `plugins/`.

## Discovery and startup

The planned discovery sequence is:

1. Resolve the application-local `plugins/` directory and any explicitly configured additional
   directories.
2. Enumerate plugin directories and `.resymbol-plugin` packages without following unsafe links or
   escaping the configured roots.
3. Skip entries carrying a `plugin.disabled` sentinel.
4. Parse the manifest with size limits and reject duplicate identities;
5. fingerprint the package and validate its artifact type;
6. negotiate manifest, API, ABI, platform, architecture, and dependency compatibility;
7. calculate requested capabilities and permissions;
8. launch the appropriate isolated host or sandbox; and
9. run a bounded health check before making capabilities available.

The application must finish starting even when every third-party plugin is invalid.

## Plugin states

| State | Meaning | Automatic behavior |
|---|---|---|
| Enabled | Valid, compatible, healthy, and allowed | Load normally |
| Disabled | Explicitly disabled by the user or policy | Do not launch |
| Incompatible | API, ABI, platform, architecture, or dependency does not match | Keep installed and explain why |
| Quarantined | Validation, startup, runtime, or resource-limit failures make loading unsafe | Stop and isolate until reviewed |
| Development error | An opt-in development build failed | Preserve compiler diagnostics; disable that build |

Health state is recorded separately from the plugin package. Updating a plugin changes its
fingerprint and triggers validation again, but does not silently grant new permissions. Repeated
runtime traps, crashes, protocol violations, timeouts, or resource-limit violations can move a
plugin to quarantine. Thresholds and recovery rules must be deterministic and visible.

A sentinel file provides an out-of-band recovery mechanism:

```text
plugins/community.msvc-rtti/plugin.disabled
```

This must work even if plugin metadata storage or the normal UI is unavailable.

The intended management commands are:

```console
resymbol plugin list
resymbol plugin enable community.msvc-rtti
resymbol plugin disable community.msvc-rtti
resymbol plugin reload
resymbol plugin doctor
resymbol --safe-mode
```

These commands are interface goals and may not yet exist. Safe mode starts the core with all
third-party plugins disabled.

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

Plugins receive only the data and host operations needed for their declared work. Planned
permissions include bounded binary-region reads, graph-query projections, claim submission,
temporary storage, package storage, approved network origins, subprocess execution, and explicit
file selections.

Network, arbitrary filesystem access, process execution, and in-process native loading are never
implied by installation. Permission changes on update require renewed approval. A permission grants
access; it does not convert a plugin's output into trusted fact.

## Extension families

### WebAssembly

WASM is the default for portable analyzers, matchers, resolvers, and exporters. The host exposes
versioned interfaces and capability-scoped resources. Plugins have no ambient filesystem, network,
clock, environment, or process access unless a specific interface grants it. Memory, fuel or
execution time, output size, and concurrency are bounded.

### Native C and C++

Native support is part of the initial architecture because important reversing libraries and SDKs
already exist in C and C++.

- The public binary contract is a versioned C ABI, not the Rust ABI or a compiler-specific C++ ABI.
- A C++ SDK provides wrappers, ownership helpers, and generated types over that C surface.
- Native plugins run in a version-matched helper process by default.
- The host validates every message, handle, range, and returned allocation.
- An explicitly trusted in-process mode may be offered for workloads that justify the risk.

The release archive supplies the native host. End users do not install a compiler, CMake, or Visual
C++ build tools to use a prebuilt plugin. Platform runtime dependencies must be statically linked or
shipped according to their licenses where practical.

### Managed/.NET

Managed plugins run through a version-matched .NET host and a strongly typed SDK. Official hosts are
published self-contained for supported platforms, so installing .NET is a developer requirement,
not an end-user requirement.

Process isolation remains the default. Assembly loading is constrained to the plugin package and
declared shared contracts. A managed exception, unload failure, runaway task, or protocol violation
can terminate that host without terminating ReSymbol.

### External process

External-process plugins support Python, model runtimes, proprietary SDKs, and other heavyweight
tools. ReSymbol starts an executable directly without a shell and communicates over a versioned,
framed protocol. The protocol includes request identifiers, cancellation, bounded payloads, health
checks, structured diagnostics, and backpressure.

An interpreter is not assumed to exist. A plugin that needs Python either ships an appropriate
runtime within its package, declares a clearly diagnosed external prerequisite, or is distributed
as a standalone executable.

### Tool-hosted bridges

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
    "binary": "sha256:…",
    "kind": "function",
    "rva": "0x2a4130"
  },
  "claim": {
    "name": "NetworkSession::DecodeMovementPacket",
    "prototype": "bool(NetworkSession*, PacketReader*)"
  },
  "classification": "inferred",
  "confidence": 0.91,
  "evidence": [
    "references movement opcode table",
    "structural match to an adjacent build"
  ]
}
```

The final protocol uses typed evidence references rather than relying on prose. The example shows
the intent: plugin identity, version, run, inputs, and evidence remain attached to the proposal.

The core checks ranges, type validity, confidence semantics, evidence references, conflicts, and
transactions. Disabling a plugin can remove its claims from the preferred view and recalculate
dependent results without erasing unrelated human work.

## Dependencies and ordering

Dependencies form a directed acyclic graph resolved before execution. A plugin can distinguish a
required dependency from an optional capability. Cycles, ambiguous providers, missing versions, and
duplicate IDs produce an incompatible state with an actionable explanation rather than an arbitrary
load order.

Analysis-stage dependencies are more granular than package dependencies. For example, a class-name
resolver may wait for RTTI claims without forcing all exports to wait for semantic inference.

## Reload and failure recovery

Reload is transactional:

1. discover and validate the changed package;
2. start a new isolated instance and run its health check;
3. stop accepting work for the old instance;
4. cancel or drain bounded in-flight work;
5. atomically switch capability routing; and
6. retire the old instance.

If validation or startup fails, the existing healthy version remains active where possible. A
crashed plugin cannot leave a half-committed claim batch. ReSymbol preserves diagnostics and the
last known health event while avoiding binary contents and secrets in default logs.

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
