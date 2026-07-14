# ReSymbol

[![CI](https://github.com/Krilliac/ReSymbol/actions/workflows/ci.yml/badge.svg)](https://github.com/Krilliac/ReSymbol/actions/workflows/ci.yml)
[![Managed SDK](https://github.com/Krilliac/ReSymbol/actions/workflows/managed-sdk.yml/badge.svg)](https://github.com/Krilliac/ReSymbol/actions/workflows/managed-sdk.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Reconstruct symbols. Recover structure. Understand binaries.**

ReSymbol is an extensible symbol-reconstruction and binary-analysis platform. Its goal is to turn
the evidence that remains in a compiled application into portable, confidence-scored function,
type, class, and program-structure information that can be reviewed and exported to tools such as
IDA, Ghidra, debuggers, PDB consumers, and DWARF consumers.

> [!IMPORTANT]
> ReSymbol is an early alpha. The PE analyzer and `.resym` format are usable but intentionally
> narrow. The first external-process plugin runtime is also usable, but it is not an OS sandbox.
> Plugin and data formats may change, and debugger/PDB export is not implemented yet.

## What exists today

The current alpha implements and tests an end-to-end, deliberately narrow analysis slice:

- safe, bounded ingestion of PE32+ x86-64 binaries, including image metadata, sections, imports,
  exports, forwarded exports, and x64 exception-directory (`RUNTIME_FUNCTION`) records;
- conservative symbol-graph generation from exact export names and metadata-backed function
  boundaries, with SHA-256 binary identity, evidence, provenance, confidence, and claim validation;
- canonical JSON `.resym` packages whose `AnalysisSession` payload keeps deterministic base
  analysis, plugin-run records, and plugin claims separate while exposing a validated combined
  graph;
- `resymbol analyze`, which writes a portable package, and `resymbol inspect`, which validates and
  summarizes a package or emits its JSON representation;
- versioned plugin manifests and health diagnostics for WASM, native, managed, external-process,
  and tool-adapter runtime families;
- local plugin-directory discovery, manifest and entrypoint validation, API compatibility checks,
  the `plugin.disabled` sentinel, safe mode, duplicate-ID quarantine, and dependency checks;
- fingerprint-bound approval and host-owned trust/quarantine state for dropped-in plugins: a
  changed artifact loses trust, while an unchanged approved artifact can load on later runs;
- a first external-process analysis runtime with direct no-shell launch, bounded NDJSON,
  permission-gated claims, deadlines, output limits, transactional results, and automatic
  quarantine after unsafe runtime or protocol failures;
- initial native C ABI, managed/.NET, WIT, and process-wire contracts; and
- CLI discovery, diagnosis, enablement, disablement, fingerprint trust/revocation, quarantine reset,
  plugin selection, and strict automation behavior, plus manifest-only plugin examples.

The analyzer does not disassemble or execute its input, and it does not yet infer erased source
names, recover types, analyze RTTI/vtables, or build call graphs. The current process host supports
one-shot analysis requests; interactive binary reads are reserved for a later protocol revision.
Plugin package verification/extraction, WASM/native/managed execution hosts, cross-build matching,
semantic inference, debugger bridges, and PDB/DWARF export are also **not implemented yet**.

## Why ReSymbol?

Stripped or incomplete binaries usually contain more useful evidence than their anonymous
`sub_...` labels suggest: imports, strings, call relationships, exception metadata, RTTI, vtables,
constants, recognizable library code, and similarities to related builds. ReSymbol is designed to
combine those signals without pretending that an erased original name can always be recovered.

Every proposed result is intended to carry provenance:

- whether it was extracted, matched, inferred, or manually reviewed;
- which analyzer or plugin produced it;
- the evidence supporting it;
- a calibrated confidence value and competing hypotheses where relevant; and
- the exact binary identity and address range to which it applies.

The distinction matters. `NetworkSession::DecodeMovementPacket` may be a useful, strongly supported
reconstruction even when the original source used a different spelling.

## Direction

ReSymbol is growing from the working PE/package foundation toward:

- deterministic analysis of PE, ELF, and Mach-O binaries, beginning with native Windows x86-64;
- a format-neutral symbol graph for functions, types, globals, classes, relationships, claims, and
  evidence;
- cross-build, signature, source, and library matching;
- optional semantic inference that remains separate from deterministic facts;
- richer portable symbol packages that can be shared without redistributing the analyzed binary;
- exporters and bridges for IDA, Ghidra, PDB, DWARF, and other debugging formats;
- drop-in plugin discovery from a local `plugins/` directory;
- WASM, native C/C++, managed/.NET, external-process, and debugger-hosted plugin families from the
  initial architecture, with external-process execution implemented first; and
- automatic plugin validation, disablement, bounded execution, and quarantine so a faulty
  extension does not prevent the core application from starting.

See the [analysis-package format](docs/analysis-packages.md),
[architecture](docs/architecture.md), [plugin-system design](docs/plugin-system.md), and
[roadmap](docs/roadmap.md) for the implemented boundaries and the remaining goals.

## Product principles

1. **One uncomplicated download.** Ordinary users should receive a portable `resymbol` executable
   and any required prebuilt hosts or adapters. They should not need Rust, Python, Java, CMake,
   Visual Studio, LLVM, or a .NET installation to run a release.
2. **Facts and hypotheses stay distinguishable.** ReSymbol must never present model output or a
   heuristic guess as recovered ground truth.
3. **Plugins submit claims.** The core validates and reconciles evidence-backed claims instead of
   allowing arbitrary extensions to silently rewrite canonical state.
4. **Safe failure is a feature.** Unhealthy plugins are stopped or quarantined, diagnostics are
   preserved, and user data is not automatically deleted.
5. **Interoperability beats lock-in.** The internal graph is not a PDB, an IDA database, or a Ghidra
   project. Those are import and export targets.
6. **Untrusted input is normal.** Binary parsing and plugin boundaries are designed with malformed
   or hostile input in mind. A child process is a crash boundary, not by itself a security sandbox.

## Quick start

Analyze a supported PE file and inspect the validated package:

```console
resymbol analyze application.exe
resymbol inspect application.resym
resymbol inspect application.resym --json
resymbol plugin list
resymbol plugin doctor
# After reviewing a dropped-in process plugin:
resymbol plugin trust community.example-analyzer --fingerprint <sha256>
resymbol analyze application.exe --plugin community.example-analyzer
```

`analyze` writes `application.resym` by default. Use `--output another.resym` to choose a different
path. ReSymbol refuses to replace an existing package, so an earlier analysis cannot be lost by
accident. `inspect` validates the package schema, payload, and embedded binary identity before
displaying it.

PDB, DWARF, IDA, and Ghidra exports remain roadmap work; there is no `export` command yet. See the
[installation guide](docs/install.md) for portable prerelease archives and source-build steps.

A normal plugin installation is dropping a prebuilt plugin directory into `plugins/`. ReSymbol
discovers it automatically, but an external-process plugin cannot execute until the user explicitly
trusts its exact directory fingerprint. That unchanged artifact autoloads on later analyses; any
file update changes the fingerprint and requires a new decision. A `plugin.disabled` sentinel or a
CLI command disables it without deletion, and `--safe-mode` suppresses every third-party plugin.

Process plugins run with the ambient access granted to an ordinary child process on the host. The
manifest permissions govern ReSymbol protocol operations; they are not filesystem, network, or
process restrictions enforced by the operating system. Only trust process plugins whose code and
publisher you would run directly. A failed plugin never prevents base analysis or package creation;
its partial claims are discarded and unsafe failures are quarantined under `plugins/.resymbol/`.

## Development

The Rust workspace uses the pinned toolchain in `rust-toolchain.toml`:

```console
cargo build --workspace
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Rust is the only required toolchain for the core workspace. The .NET SDK is needed only when
working on managed plugin SDK or host projects. Released managed components are intended to be
self-contained. CI also syntax-checks the stable native header as both C11 and C++11 and validates
the external-process protocol schema.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a substantial protocol or architecture
change. During this early phase, opening an issue first helps avoid parallel designs that cannot be
made compatible later.

## Responsible use

Use ReSymbol only with software you are authorized to inspect. Contributors must not add
proprietary binaries, leaked symbols, secrets, or copyrighted fixtures that the project does not
have permission to redistribute. ReSymbol is not intended to bypass access controls, DRM, license
checks, anti-cheat systems, or other protections.

## License

ReSymbol is licensed, at your option, under either:

- the [Apache License, Version 2.0](LICENSE-APACHE); or
- the [MIT License](LICENSE-MIT).

Unless you explicitly state otherwise, contributions intentionally submitted for inclusion in
ReSymbol are offered under the same dual-license terms.
