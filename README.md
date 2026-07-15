# ReSymbol

[![CI](https://github.com/Krilliac/ReSymbol/actions/workflows/ci.yml/badge.svg)](https://github.com/Krilliac/ReSymbol/actions/workflows/ci.yml)
[![Managed SDK](https://github.com/Krilliac/ReSymbol/actions/workflows/managed-sdk.yml/badge.svg)](https://github.com/Krilliac/ReSymbol/actions/workflows/managed-sdk.yml)
[![PDB compatibility](https://github.com/Krilliac/ReSymbol/actions/workflows/pdb-compat.yml/badge.svg)](https://github.com/Krilliac/ReSymbol/actions/workflows/pdb-compat.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Reconstruct symbols. Recover structure. Understand binaries.**

ReSymbol is an extensible symbol-reconstruction and binary-analysis platform. Its goal is to turn
the evidence that remains in a compiled application into portable, confidence-scored function,
type, class, and program-structure information that can be reviewed and exported to tools such as
IDA, Ghidra, debuggers, PDB consumers, and DWARF consumers.

> [!IMPORTANT]
> ReSymbol is an early alpha. The PE analyzer and `.resym` format are usable but intentionally
> narrow. The no-WASI WebAssembly Component Model, external-process, native C/C++, and
> managed/.NET plugin runtimes are also usable. WASM is capability-limited but executes through an
> in-process engine; the process runtimes provide crash isolation rather than an OS sandbox.
> The initial JSON, Markdown, Microsoft-linker-style MAP, exact-RSDS public-symbol PDB, IDAPython,
> and Ghidra Java exporters are usable but deliberately conservative.
> Plugin and data formats may change; DWARF and interactive debugger bridges are not implemented
> yet.

## What exists today

The current alpha implements and tests an end-to-end, deliberately narrow analysis slice:

- safe, bounded ingestion of PE32+ x86-64 binaries, including image metadata, sections, imports,
  exports, forwarded exports, and x64 exception-directory (`RUNTIME_FUNCTION`) records;
- bounded discovery of modern MSVC x64 Rev1 RTTI and vftables from file-backed compiler metadata,
  including validated class/type names, base-class records, and contiguous executable slot
  candidates;
- bounded pure-Rust x86-64 decoding inside fully file-backed `RUNTIME_FUNCTION` ranges, recovering
  supported direct calls to internal executable targets, exact parsed import-address-table slots,
  or targets resolved one hop through exact read-only in-image function-pointer slots;
  one-instruction thunks to internal targets, exact parsed import slots, or one-hop read-only
  function-pointer targets; and exact supported RIP-relative references into eligible data;
- bounded recovery of exact NUL-terminated ASCII and UTF-16LE strings from file-backed,
  initialized, readable, non-executable sections, including writable data;
- a source-available, byte-reproducible four-artifact MSVC x64 PE fixture matrix spanning optimized
  and unoptimized builds, each with and without CodeView metadata, plus exact hashes and a
  profile-sensitive semantic oracle covering the implemented Milestone 2 evidence families; these
  repository/source fixtures are analyzer test data and are not bundled in portable runtime
  archives;
- conservative symbol-graph generation from exact export names, metadata-backed function
  boundaries, function-entry candidates, direct calls, thunks, recovered strings, and data
  references, with SHA-256 binary identity, evidence, provenance, confidence, and claim validation;
- canonical JSON `.resym` packages whose `AnalysisSession` payload keeps deterministic base
  analysis, plugin-run records, and plugin claims separate while exposing a validated combined
  graph;
- `resymbol analyze`, which writes a portable package, and `resymbol inspect`, which validates and
  summarizes a package or emits its JSON representation;
- a deterministic, debugger-neutral export projection plus `resymbol export`, which writes the
  projection as JSON, renders a bounded human-readable Markdown report, emits deterministic
  Microsoft-linker-style MAP text for compatible tools, creates an exact-RSDS public-symbol PDB
  from the exact original PE, or generates self-contained IDAPython and Ghidra Java import scripts
  with exact-binary identity gates and RVA-aware rebasing; the projection correlates supported data
  references with retained strings at exact or valid content-interior targets;
- versioned plugin manifests and health diagnostics for WASM, native, managed, external-process,
  and tool-adapter runtime families;
- local plugin-directory discovery, manifest and entrypoint validation, API compatibility checks,
  the `plugin.disabled` sentinel, safe mode, duplicate-ID quarantine, and dependency checks;
- fingerprint-bound approval for executable process plugins and host-owned quarantine state for
  every executable family: a changed process artifact loses trust, while an unchanged approved
  artifact can load on later runs;
- a first WebAssembly Component Model analysis runtime that links only the checked-in ReSymbol WIT
  host interface—no WASI—caps component bytes and applies store, fuel, stack, event, binary-read,
  and epoch-deadline controls to instantiated guest execution, validates lifecycle metadata and
  claims transactionally, and autoloads sandboxed components without a trust record while still
  honoring safe mode, manual disablement, exact-artifact quarantine, and reset;
- a first external-process analysis runtime with direct no-shell launch, bounded NDJSON,
  permission-gated claims, deadlines, output limits, transactional results, and automatic
  quarantine after unsafe runtime or protocol failures;
- a first native C/C++ analysis runtime that loads an approved library only in the disposable,
  application-local `resymbol-native-host` sibling process, exposes a permission-gated bounded
  `binary.read` callback for file-backed PE RVAs, and validates the complete claim batch before
  commit, while keeping helper/pre-load failures separate from plugin-attributable faults;
- a first managed/.NET analysis runtime with a strongly typed SDK and self-contained,
  application-local `resymbol-managed-host` sibling process, exact assembly-closure and artifact
  verification, bounded host services, deadline enforcement, and transactional output;
- executable-plugin process-tree lifecycle containment: external, native, and managed launches own
  their descendants through POSIX process groups or Windows Job Objects, and terminate that tree
  when the direct child completes, a deadline or stdout/stderr capture failure occurs, or the
  runtime drops;
- initial native C ABI, WIT, and process-wire contracts; and
- CLI discovery, diagnosis, enablement, disablement, fingerprint trust/revocation, quarantine reset,
  plugin selection, and strict automation behavior, plus source-backed WASM and managed examples
  and native contract examples.

The core PE analyzer never loads or executes its input and requires no network service. Its decoder
is a bounded control-flow-guided block sweep, not a general recursive disassembler: it starts at
validated x64 exception-range entries, follows supported direct same-range branches with a
deterministic ordered worklist, and stops a path at returns, terminal or indirect control flow,
invalid instructions, and ambiguous interior targets. It recognizes supported `E8` direct calls;
exact RIP-relative `FF 15 disp32` and redundant-`REX.W` `48 FF 15 disp32` calls to parsed IAT
slots; and the same two call encodings through a complete eight-byte pointer slot in readable,
initialized, non-writable, non-executable data. Parsed IAT membership takes precedence. Otherwise
the slot's little-endian preferred-image VA is resolved exactly once to a file-backed executable
target; pointer chains and writable slots remain unsupported. A resolved pointer call records its
slot and endpoint explicitly and retains the same instruction as a paired data reference to the
slot. Seeded `E9` and `EB` internal thunks remain supported. Exact RIP-relative `FF 25 disp32` and
redundant-`REX.W` `48 FF 25 disp32` thunks use the same IAT-first policy: a parsed IAT slot remains
an import target, while any other accepted slot resolves one read-only pointer hop to executable
code. A pointer thunk records its slot and endpoint without requiring a paired data reference. The
built-in pass discovers at most 262,144 block starts and retains at most 8,192 direct calls, 32,768
supported RIP-relative data references, and 4,096 thunks. These are heuristic-confidence findings:
reachable embedded data can still decode as instructions, while an invalid encoding or unsupported
branch can omit later relationships on that path. An internal target covered by known
`RUNTIME_FUNCTION` metadata is suppressed unless its RVA matches a recorded runtime-function
begin. The pass does not persist a basic-block graph, infer erased identifiers, invent names or
sizes, recover register-indirect
control flow, or claim a complete call graph. A separate bounded pass retains exact, fully
terminated printable ASCII and valid UTF-16LE strings from eligible data, with deterministic
overlap handling; it does not publish truncated prefixes or infer a variable type from a literal.
The neutral projection correlates a data-reference target with a retained string only at the string
start or within its encoded content. It excludes the NUL terminator and requires UTF-16LE interior
targets to be code-unit aligned. An absent correlation means only that no retained projected string
matched; it is not proof that the target bytes cannot contain a string.
Its RTTI slice recovers
names and relationships actually present in validated compiler metadata and deliberately supports
only modern MSVC x64 Rev1 records whose base-class descriptors use the 28-byte form with an
embedded class-hierarchy reference. Candidate scanning and the vftable/back-pointer, COL, CHD,
BCA, BCD, and nested-CHD records remain in file-backed readable, read-only initialized
non-executable data. Referenced TypeDescriptors may also occupy file-backed readable initialized
non-executable data marked writable, including normal `.data`; writable sections are never
candidate-scanned. The current external-process host supports one-shot analysis requests; its
interactive binary reads are reserved for a later protocol revision. The native host instead
provides a bounded synchronous C callback for file-backed RVAs in the exact PE. The managed host
provides the equivalent bounded asynchronous SDK service for approved .NET plugins. Plugin package
verification/extraction, cross-build matching, semantic inference, interactive debugger bridges,
richer PDB records, and DWARF export are also **not implemented yet**.

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
- conservative standalone import-script exporters for IDA and Ghidra, deterministic
  Microsoft-linker-style MAP output, and exact-RSDS public-symbol PDB output, followed by richer
  bridges, richer PDB records, DWARF, and other debugging formats;
- a desktop workbench GUI for reviewing evidence and conflicts before applying results, with its
  approved layout and themes currently documented as design rather than implemented behavior;
- drop-in plugin discovery from a local `plugins/` directory;
- WASM, native C/C++, managed/.NET, external-process, and debugger-hosted plugin families from the
  initial architecture, with WASM, external-process, native C/C++, and managed/.NET execution
  implemented; and
- automatic plugin validation, disablement, bounded execution, and quarantine so a faulty
  extension does not prevent the core application from starting.

See the [changelog](CHANGELOG.md), [analysis-package format](docs/analysis-packages.md),
[export guide](docs/exporting.md), [architecture](docs/architecture.md),
[plugin-system design](docs/plugin-system.md), [GUI design](docs/gui-design.md), and
[roadmap](docs/roadmap.md) for implemented boundaries, release-facing changes, and remaining goals.

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
resymbol export application.resym --format json
resymbol export application.resym --format markdown
resymbol export application.resym --format map
resymbol export application.resym --format pdb --binary application.exe
resymbol export application.resym --format ida-python
resymbol export application.resym --format ghidra-java
resymbol plugin list
resymbol plugin doctor
# After reviewing a dropped-in executable plugin:
resymbol plugin trust community.example-analyzer --fingerprint <sha256>
resymbol analyze application.exe --plugin community.example-analyzer
```

`analyze` writes `application.resym` by default. Use `--output another.resym` to choose a different
path. ReSymbol refuses to replace an existing package, so an earlier analysis cannot be lost by
accident. `inspect` validates the package schema, payload, and embedded binary identity before
displaying it. `export` stages and flushes a complete artifact before a no-clobber publish; use
`--output` to choose a destination instead of replacing an existing export artifact.

New analyses write package schema 4. `inspect` and `export` also accept schemas 1, 2, and 3 through
validated in-memory compatibility paths. Migration does not rewrite the source package or rerun
analysis because `.resym` does not embed the executable bytes. Schema 1 therefore has no available
recovered calls, thunks, strings, or data references. Schema 2 retains calls and thunks but predates
strings and data references. Schema 3 retains those string/data records, but schemas 2 and 3 both
predate read-only function-pointer call and thunk resolution. Reanalyze the exact original binary
to produce schema 4 with current recovery results. A schema 2 or 3 envelope containing a schema-4
`function-pointer` target is rejected rather than treated as a relabeled legacy package.

The `analyze` and `inspect` summaries report recovered strings, data references, direct calls, and
thunks as well as discovered MSVC RTTI vftables, unique types, base-class records, and virtual
slots. If a fixed string, data-reference, control-flow, or RTTI discovery budget is reached, the
corresponding summary prints a `partial` status; the valid deterministic results remain available
and the package records the truncation explicitly.

The Markdown output is a deterministic, bounded presentation report for people to review. It is
not a stable interchange format; integrations should consume the neutral JSON projection instead.
Without `--output`, it is written as `application.symbols.md` beside the package. Package schema 4
is used by new analyses, export also accepts package schemas 1 through 3 through validated
compatibility paths, and neutral projection schema 6 remains unchanged by this presentation-only
format. Export does not rewrite the source package.

The PE-only `map` format writes deterministic Microsoft-linker-style text to `application.map` by
default for tools that support that format. It maps selected names to one-based PE
`section:offset` values and preferred-image-base-plus-RVA addresses. Its semicolon-prefixed exact
SHA-256 and file-size comments are informational: a MAP file cannot check the binary loaded by a
consumer, so compare the executable with the recorded identity before using the symbols. MAP adds
no fields to package schema 4 or neutral projection schema 6, and it does not rewrite legacy source
packages accepted through compatibility paths. The header module name is the package filename stem;
for a valid UTF-8 stem, unsupported/non-ASCII encoded bytes become `_` and the result is capped at
255 bytes. A non-UTF-8 or otherwise unusable stem falls back to `resymbol_<sha12>`.

The PE32+ x86-64 `pdb` format writes `application.pdb` by default. It rereads the exact original PE
supplied with `--binary`, rejects a SHA-256/session mismatch, requires one unambiguous modern `RSDS`
CodeView record, and copies that record's GUID and age plus the PE's raw section headers. The
deterministic PDB carries selected public function and global names only; it does not synthesize
types, private symbols, locals, line tables, or function extents, and it never rewrites the PE.
Ordinary users do not need Visual Studio, LLVM, or DIA to generate it. See the
[export guide](docs/exporting.md) for bounds, rejected debug-record cases, and manual or symbol-path
loading advice.

The generated IDA and Ghidra scripts verify the exact loaded binary SHA-256 before changing a
database and calculate addresses from the tool's current image base plus each RVA. They preserve
existing user-authored names and apply only the first projection subset: selected function/global
names (including validated vftable global names) and conservative non-overlapping function
boundaries. The neutral JSON projection retains attributed function entries, direct calls, thunks,
recovered strings, data references, their string correlations, explicit function-pointer slot
provenance from projection schema 6, and class-membership relationships, while the current scripts
ignore those relationship and literal records and do not synthesize virtual-method names. See the
[export guide](docs/exporting.md) for report contents, usage, limitations, and in-tool
instructions. Richer PDB records, DWARF, richer type application, and interactive preview bridges
remain roadmap work. See the
[installation guide](docs/install.md) for portable prerelease archives and source-build steps.

A normal plugin installation is dropping a prebuilt plugin directory into `plugins/`. ReSymbol
discovers it automatically. A capability-limited WASM component autoloads without a trust record;
`resymbol plugin trust` intentionally does not apply to this runtime. External-process, native, and
managed plugins cannot execute until the user explicitly trusts their exact directory fingerprint.
That unchanged executable artifact autoloads on later analyses; any fingerprinted-file update
requires a new decision. Every family still honors exact-artifact quarantine, a
`plugin.disabled` sentinel or CLI disable command, and `--safe-mode`.

The WASM host links the ReSymbol WIT imports and no WASI interfaces, so components receive no
ambient filesystem, network, environment, clock, or process access. It is nevertheless embedded in
the ReSymbol process: a defect in Wasmtime, its compiler, or ReSymbol's host bindings could crash or
compromise the application. The component-byte cap applies before compilation; fuel, epoch, stack,
and store limits constrain instantiated guest execution. Those controls do not interrupt
synchronous Wasmtime validation/JIT compilation or cap compiler and other host allocations, so a
pathological component can exceed the configured guest deadline or memory limit while compiling.
None of these controls is a separate-process containment boundary. Official archives include a
prebuilt MZ-checking WASM example under `plugins/dev.resymbol.example.wasm-resolver/`.

Native libraries load only in the version-matched `resymbol-native-host[.exe]` shipped beside the
main executable, never in ReSymbol itself or through a helper supplied by a plugin. The helper
rechecks the approved fingerprint, exact analyzed-binary identity, C ABI and lifecycle, callback
bounds, and complete output batch. A plugin-attributable native crash or post-load ABI, callback,
or output failure discards every claim from that run and quarantines the exact artifact without
preventing base analysis or package creation. Immediately before its first platform loader call,
the helper writes and flushes a versioned marker that the parent removes from diagnostics. A
failure observed with that marker is treated as plugin-attributable; one without the current marker
is conservatively reported as host-side instead.

Managed assemblies load only in the version-matched, self-contained
`resymbol-managed-host[.exe]` sibling. The host snapshots and hashes the declared private DLL
closure, supplies the exact SDK contract, rejects ordinary unmanaged dependency resolution, and
commits no log or claim until the complete lifecycle and final source checks succeed. Its
collectible .NET load context is a dependency and cleanup boundary—not a security sandbox: plugin
code can still call ambient framework APIs, explicitly load code, terminate the helper, or start
background work. The parent therefore applies the same fingerprint trust, marker attribution,
deadline, transaction, and quarantine policy used by the other executable runtimes.

External, native, and managed process plugins retain the ambient filesystem, network, credential,
and process access of the launching account. Manifest permissions govern ReSymbol protocol
operations; they are not restrictions enforced by the operating system. A fingerprint identifies
reviewed local bytes, not a publisher, and mutable plugin files leave a check-to-launch window.
Process-tree ownership is lifecycle containment, not authority sandboxing. On Windows ReSymbol uses
a safe Rust wrapper for immediate post-spawn Job Object assignment, but a narrow pre-assignment
escape race remains. On POSIX a hostile plugin/helper or descendant can deliberately leave its
process group or session. Only trust artifacts whose code and publisher you would run directly.
Official archives bundle both helpers beside `resymbol`; Linux archives pair the static musl main
executable with a GNU native helper built on Ubuntu 22.04 for glibc 2.35 or newer so it can load
ordinary glibc `.so` plugins.

## Development

The Rust workspace uses the pinned Rust 1.86 toolchain in `rust-toolchain.toml`:

```console
cargo build --workspace
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Rust is the only required toolchain for the core workspace; x86-64 decoding uses a pure-Rust crate
and does not require a native disassembler library. The .NET SDK is needed only when working on
managed plugin SDK, example, or host projects; official archives publish the managed helper
self-contained. WASM plugin authors add Rust's `wasm32-unknown-unknown` target and can rebuild the
source-backed example with `examples/plugins/wasm/build.sh` or
`examples/plugins/wasm/build.ps1`; users consume only the prebuilt component. CI rebuilds that
component from its locked source, compiles and runs the native
fixture through the disposable helper, tests the managed SDK and host, runs the exact staged WASM
plugin through each platform's release CLI, syntax-checks the native header as C11 and C++11, and
validates the external-process protocol schema.

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
