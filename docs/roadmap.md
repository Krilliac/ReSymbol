# Roadmap

ReSymbol is being built in capability milestones rather than date promises. Ordering may change as
the implementation and security model are validated. A roadmap item is not implemented merely
because it appears here; the current code, tests, release notes, and issue tracker are authoritative.

## Current checkpoint

The repository foundation and initial graph/plugin-contract work are in place. The first usable
Milestone 2 slice performs bounded PE32+ x86-64 ingestion, extracts sections/imports/exports and x64
exception metadata, and derives conservative metadata-backed claims. Canonical `.resym` packages
now carry an `AnalysisSession`: deterministic base analysis, an auditable plugin-run ledger, and
separately validated plugin claims with a derived combined graph.

The CLI writes package schema 3 and can inspect or export schemas 1 and 2 through explicit
compatibility paths. Schema 1 is migrated in memory by revalidating persisted metadata and
rebuilding the base graph; schema 2 already contains direct-call and thunk recovery. Older packages
do not embed executable bytes, so compatibility loading cannot reconstruct results that were never
recorded. Reanalyzing the exact original binary is required to populate strings and data references
in a new schema 3 package, and also direct calls and thunks when starting from schema 1.

A bounded modern MSVC x64 Rev1 RTTI/vftable slice is now implemented. It validates compiler
metadata through complete object locators, type descriptors, modern 28-byte base-class descriptors,
class hierarchies, and executable virtual-slot targets. It recovers stored class/type names and
vftable names and records function-to-class memberships without inventing virtual-method names.
Fixed scan, record, slot, and name budgets surface partial discovery explicitly.

A bounded pure-Rust x86-64 code-recovery slice is also implemented. Its control-flow-guided block
sweep starts at fully file-backed `RUNTIME_FUNCTION` entries, follows supported direct same-range
branches with a deterministic ordered worklist, and stops paths at terminal, indirect, invalid,
out-of-range, or ambiguous interior control flow. It records exact supported direct calls and
RIP-relative data references and checks the first instruction at metadata-backed entry candidates
for internal or import thunks. It discovers at most 262,144 block starts and retains at most 8,192
direct calls, 32,768 data references, and 4,096 thunks; internal targets covered by known
runtime-function metadata are suppressed unless their RVA matches a recorded runtime-function
begin. A separate
bounded pass recovers complete NUL-terminated ASCII and UTF-16LE literals from readable initialized
non-executable file-backed data. These passes emit attributed claims without inventing names or
extents and preserve independent partial-scan flags. The guided sweep suppresses unreachable
post-terminal bytes and can reach valid blocks after jump-over data, but remains heuristic evidence:
reachable embedded data can produce false positives, and invalid or unsupported flow can omit later
relationships on that path. It does not persist a basic-block graph.

The first external-process analysis host is also implemented. Dropped-in process plugins require an
explicit full-directory-fingerprint trust decision, then unchanged trusted artifacts can autoload.
The host launches directly without a shell, exchanges bounded NDJSON for one analysis request,
enforces deadlines and output limits, and commits claims transactionally. Unsafe failures
quarantine the exact fingerprint without blocking base analysis or package creation. Process
separation is not an OS sandbox, and interactive binary reads remain reserved rather than
implemented.

The first native C/C++ analysis host is implemented for x86-64 PE sessions. An approved drop-in
library loads only in the disposable, version-matched `resymbol-native-host[.exe]` shipped beside
the application; there is no in-process path and a plugin cannot supply the helper. The host checks
the exact plugin fingerprint, binary identity, C ABI and lifecycle, callback limits, and complete
claim batch. Its permission-gated `binary.read` callback returns only bounded file-backed PE RVAs.
A plugin-attributable native fault discards the full batch and quarantines that exact artifact
without blocking package creation. The helper flushes a versioned marker immediately before its
first platform loader call; failures observed without that marker remain conservatively host-side.
This process boundary contains crashes, not ambient filesystem, network, credential, or process
authority, and mutable plugin files retain a check-to-launch window.

The first managed/.NET analysis host is also implemented for PE32+ x86-64 `analyze` sessions.
Approved prebuilt .NET 8 plugin DLLs load only in the disposable, app-local, self-contained
`resymbol-managed-host[.exe]`; end users do not install .NET. The parent binds exact artifact and
binary identities, a verified private-DLL closure, limits, and permissions into the host bootstrap.
The helper supplies the exact `ReSymbol.PluginSdk`, snapshots the DLL closure and binary under one
cumulative byte gate, phase-bounds services, and keeps every log and claim transactional through
the complete lifecycle and final identity checks. Its pre-load marker gives the parent a clear
plugin-attribution point for quarantine without turning helper preflight failures into plugin
faults.

This first managed boundary is ordinary process, exception, and dependency-resolution containment,
not an operating-system or CLR sandbox. Plugin code retains the account's ambient filesystem,
network, credential, and process authority. A collectible load context closes normal private
dependency resolution, but explicit `Assembly.Load*`, default-context, `NativeLibrary.Load`, and
other framework APIs remain available to plugin code. Exact-fingerprint trust therefore remains
mandatory.

Official archives bundle both disposable helpers. Linux releases pair the static musl main
executable with a GNU native helper built on Ubuntu 22.04 for glibc 2.35 or newer so ordinary glibc
`.so` plugins can load. Every archive also carries the matching single-file, self-contained managed
helper, so ordinary users need no compiler, SDK, or separately installed .NET runtime.

The first export checkpoint is implemented as a validated, debugger-neutral projection with
deterministic JSON output, a bounded human-readable Markdown report, PE-only
Microsoft-linker-style MAP text, an exact-RSDS public-symbol PDB, and standalone IDAPython and
Ghidra Java import scripts. Markdown is presentation-only rather than a stable interchange schema;
JSON remains the machine-consumable artifact. New analyses write package schema 3, while export also
accepts package schemas 1 and 2 through validated compatibility paths. The neutral projection is
schema 4; MAP and PDB add no schema fields, and no exporter rewrites its source package. The scripts
bind to the exact loaded binary SHA-256, resolve addresses as loaded image base plus RVA, preserve
user-authored names and existing function bodies, and continue past per-symbol application errors.
They are deliberately narrower than the planned interactive debugger bridges: prototypes, types,
alternate names, provenance comments, and richer relationships are retained or diagnosed by the
projection but are not yet fully applied inside the tools.

The MAP writer emits selected named symbols in deterministic RVA order using one-based PE
`section:offset` and preferred-image-base-plus-RVA values. A selected function wins over a selected
global at the same RVA; an unnamed function suppresses nothing. `<resymbol>` marks synthetic
provenance, and unsafe raw section-name bytes are escaped. Exact SHA-256 and file-size comments are
informational because MAP text cannot enforce the identity of a binary loaded by another tool.

The first PDB slice emits only selected public function and global names. It requires the exact
original PE at export time, verifies its bytes against the package, rejects ambiguous or malformed
CodeView metadata, and copies the PE's one unambiguous RSDS GUID+age and raw section headers into a
deterministic, bounded pure-Rust MSF/PDB. It does not rewrite the PE or require a user-installed
Visual Studio, DIA, LLVM, or compiler toolchain. Windows compatibility CI reads the generated file
with native and DIA-backed `llvm-pdbutil` paths plus a direct DIA identity/public-symbol probe.
Private symbols, types, prototypes, compilands, source lines, and function extents remain outside
this initial writer.

The neutral projection intentionally retains larger model-validation caps of 262,144 direct calls,
262,144 data references, 65,536 strings, and 65,536 thunks. Those bounds support combined or
plugin-produced graphs and are separate from the built-in recovery passes' lower caps. MAP export
separately accepts at most 262,144 selected named function/global candidates and 64 MiB of output.
PDB export applies the same candidate ceiling before same-RVA reduction and independently bounds
its logical streams and MSF container.

The remaining Milestone 2 work is deliberately substantial: broader disassembly-assisted candidate
discovery, indirect control flow and richer call-graph analysis, string-reference correlation,
persisted basic-block modeling, broader RTTI/ABI coverage, an open fixture corpus, benchmarks, and
continued malformed-input/resource-limit validation.
The WASM and debugger-hosted execution paths remain future work; their contracts and architecture
are present, but should not be mistaken for working hosts.

## Milestone 0: repository foundation

Implemented in the current alpha.

- Rust workspace with pinned formatting and lint tooling
- Core, CLI, and plugin-contract crate boundaries
- Cross-platform CI and managed SDK validation
- Architecture, contribution, security, and plugin-system documentation
- Dual MIT or Apache-2.0 licensing
- Reproducible test-fixture policy

## Milestone 1: graph and plugin foundation

This milestone establishes extensibility before analysis behavior becomes difficult to decouple.
Core graph types, plugin discovery/health policy, initial multi-runtime contracts, and the first
external-process, native C/C++, and managed/.NET execution hosts are implemented. Package
installation and the WASM and debugger-hosted runtimes are still outstanding.

- Binary identity and canonical address primitives
- Versioned entities for functions, ranges, names, types, claims, evidence, and plugin runs
- Transactional claim validation and conflict preservation
- Local `plugins/` discovery and autoload
- Manual disablement and `plugin.disabled` sentinel support
- Exact-directory fingerprinting and explicit trust before first process execution
- Host-owned `.resymbol/` trust/quarantine records, update invalidation, and fail-closed reads
- Incompatible, approval-required, quarantined, and development-error health states
- Safe mode and plugin diagnostics
- Version negotiation, dependency compatibility diagnostics, limits, and permission records
- Direct no-shell, timeout- and output-bounded one-shot external-process analysis
- Disposable sibling-process native C/C++ analysis with bounded file-backed PE `binary.read`
  callbacks and full-batch validation
- App-local self-contained managed/.NET analysis helper with a host-supplied SDK, verified private
  DLL and exact-binary snapshots, phase-bounded services, and transactional lifecycle
- Transactional plugin claims and failure-tolerant `AnalysisSession` packaging
- Initial contracts and example packages for:
  - WebAssembly plugins
  - native C ABI and C++ SDK plugins
  - managed/.NET SDK plugins with a self-contained host
  - external-process plugins
  - debugger-hosted bridges

The native and managed families are initial architecture requirements, not post-1.0 add-ons. Their
contracts, SDK foundations, and first out-of-process analysis hosts are implemented. Out-of-process
hosting is the only supported path for both families even if an explicitly trusted fast path is
eventually designed. A child process is a crash boundary, not an OS security sandbox; platform
sandboxing remains separate work. The current runner also owns only its direct child. Containing the
full descendant tree with Unix process groups and Windows Job Objects, and preventing inherited
pipes from retaining capture readers after the bounded drain, remain explicit platform-hardening
work.

## Milestone 2: useful native-binary MVP

The first intentionally narrow analysis target is native Windows x86-64 PE input without packed or
adversarial obfuscation.

- Format, section, import, export, and build-metadata extraction
- Executable-range and candidate function discovery (exception ranges, exports, calls, and seeded
  entries implemented)
- Exception and unwind metadata ingestion
- Strings, constants, references, call relationships, and thunks (bounded exact strings, supported
  RIP-relative data references, direct calls, and one-instruction thunks implemented; broader
  constants and reference correlation remain planned)
- Initial MSVC x64 Rev1 RTTI and vftable analysis (bounded modern-layout slice implemented)
- Portable `.resym` analysis package
- Deterministic, loss-aware JSON symbol projection
- Deterministic, bounded Markdown review report
- Reproducible open-source fixture corpus compiled with and without symbols
- Boundary, coverage, malformed-input, and resource-limit benchmarks

The PE metadata, x64 exception ingestion, bounded string/data-reference/direct-call/thunk recovery,
bounded modern MSVC x64 RTTI/vftable slice, portable package, canonical package encoding, neutral
JSON export projection, bounded Markdown report, and related CLI portions are implemented. The
unfinished parts of the bullets describe the remainder of this milestone.

The MVP should be useful without AI, a network connection, Ghidra, or IDA.

## Milestone 3: matching and tool integration

- Cross-build function and type mapping
- Known-library and reproducible-source signature packs
- Symbolized-build propagation with evidence and confidence
- Standalone IDAPython importer for applying the initial safe graph subset (implemented)
- Standalone Ghidra Java importer with equivalent identity checks (implemented)
- Interactive IDA and Ghidra bridges for preview, selective application, and provenance comments
- MAP or simple public-symbol export (PE MAP implemented for selected named symbols)
- Synthetic PDB export for validated public functions and globals (exact-RSDS public-symbol slice
  implemented)
- Explicit lossy-export diagnostics

The neutral projection already emits structured diagnostics for reductions such as unsupported
assertions, name collisions, conflicting sizes, and overlapping ranges. Target-specific loss
summaries and richer in-tool review remain part of this milestone. The first PE MAP writer is now a
separate `resymbol export` format, and the first synthetic PDB writer covers exact-RSDS public
symbols. Richer MAP coverage, PDB private/type/line information, and interactive bridges remain
planned.

## Milestone 4: richer reconstruction

- Reconstructed prototypes, aggregates, classes, fields, and inheritance
- Calibrated competing hypotheses and human review workflow
- Optional local semantic inference providers
- Richer PDB type and global information
- DWARF and ELF debug-information export
- Additional architectures and ELF/Mach-O analysis
- Incremental analysis and cross-plugin invalidation

Semantic inference remains optional and never converts a hypothesis into an extracted fact.

## Milestone 5: ecosystem and collaboration

- Desktop workbench GUI for project navigation, evidence review, claim comparison, plugin health,
  and export preview; the [approved layout and theme system](gui-design.md) are currently
  design-only
- Signed or verifiable plugin packages and registry metadata
- Hash-addressed community symbol packs without bundled application binaries
- Mergeable annotations and review decisions
- Plugin compatibility, permission, and health UI
- Reproducible benchmark dashboard
- Stable SDKs and conformance suites
- Offline import/export for sensitive analysis environments

## Initial release quality bar

An initial public pre-release should not be cut merely because the CLI runs. It should have:

- clean setup from a portable archive on a supported Windows system;
- no compiler or separately installed language runtime required for ordinary use;
- deterministic behavior on documented open-source fixtures;
- bounded failure on malformed test inputs;
- plugin discovery, disablement, quarantine, and safe-mode tests;
- at least one working example for every initial plugin contract;
- accurate help and documentation that distinguish implemented and planned behavior; and
- CI passing on Linux, Windows, and macOS, even if the first analyzer target is Windows PE.

## Explicitly out of scope for the initial releases

- claiming exact recovery of names or source metadata that no longer exists;
- automatic deobfuscation of every protector or virtual machine;
- bypassing DRM, access controls, anti-cheat, or license enforcement;
- loading arbitrary native plugins in-process without an explicit trust decision;
- requiring cloud inference for baseline analysis; and
- silently applying reconstructed symbols to a binary whose identity does not match.
