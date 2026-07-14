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
> narrow, plugin and data formats may change, and debugger/PDB export is not implemented yet.

## What exists today

The current alpha implements and tests an end-to-end, deliberately narrow analysis slice:

- safe, bounded ingestion of PE32+ x86-64 binaries, including image metadata, sections, imports,
  exports, forwarded exports, and x64 exception-directory (`RUNTIME_FUNCTION`) records;
- conservative symbol-graph generation from exact export names and metadata-backed function
  boundaries, with SHA-256 binary identity, evidence, provenance, confidence, and claim validation;
- canonical JSON `.resym` packages that are bound to the exact analyzed binary, reject invalid or
  unsupported input, use size-bounded reads, and never silently overwrite an existing result;
- `resymbol analyze`, which writes a portable package, and `resymbol inspect`, which validates and
  summarizes a package or emits its JSON representation;
- versioned plugin manifests and health diagnostics for WASM, native, managed, external-process,
  and tool-adapter runtime families;
- local plugin-directory discovery, manifest and entrypoint validation, API compatibility checks,
  the `plugin.disabled` sentinel, safe-mode policy, duplicate-ID quarantine, and dependency checks;
- initial native C ABI, managed/.NET, WIT, and process-wire contracts; and
- CLI discovery, diagnosis, enablement, and disablement of unpacked plugins, plus manifest-only
  plugin examples.

The analyzer does not disassemble or execute its input, and it does not yet infer erased source
names, recover types, analyze RTTI/vtables, or build call graphs. Plugin package
verification/extraction, runtime hosts and plugin execution, cross-build matching, semantic
inference, debugger bridges, and PDB/DWARF export are also **not implemented yet**.

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
  initial architecture; and
- automatic plugin validation, disablement, isolation, and quarantine so a faulty extension does
  not prevent the core application from starting.

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
   or hostile input in mind.

## Quick start

Analyze a supported PE file and inspect the validated package:

```console
resymbol analyze application.exe
resymbol inspect application.resym
resymbol inspect application.resym --json
resymbol plugin list
resymbol plugin doctor
```

`analyze` writes `application.resym` by default. Use `--output another.resym` to choose a different
path. ReSymbol refuses to replace an existing package, so an earlier analysis cannot be lost by
accident. `inspect` validates the package schema, payload, and embedded binary identity before
displaying it.

PDB, DWARF, IDA, and Ghidra exports remain roadmap work; there is no `export` command yet. See the
[installation guide](docs/install.md) for portable prerelease archives and source-build steps.

A normal plugin installation should be as simple as dropping a prebuilt plugin into `plugins/` and
launching ReSymbol. The application discovers compatible plugins automatically. A `plugin.disabled`
sentinel or a CLI command can disable one without deleting it.

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
