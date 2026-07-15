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

The first external-process analysis host is also implemented. Dropped-in process plugins require an
explicit full-directory-fingerprint trust decision, then unchanged trusted artifacts can autoload.
The host launches directly without a shell, exchanges bounded NDJSON for one analysis request,
enforces deadlines and output limits, and commits claims transactionally. Unsafe failures
quarantine the exact fingerprint without blocking base analysis or package creation. Process
separation is not an OS sandbox, and interactive binary reads remain reserved rather than
implemented.

The first export checkpoint is implemented as a validated, debugger-neutral projection with
deterministic JSON output and standalone IDAPython and Ghidra Java import scripts. The scripts bind
to the exact loaded binary SHA-256, resolve addresses as loaded image base plus RVA, preserve
user-authored names and existing function bodies, and continue past per-symbol application errors.
They are deliberately narrower than the planned interactive debugger bridges: prototypes, types,
alternate names, provenance comments, and richer relationships are retained or diagnosed by the
projection but are not yet fully applied inside the tools.

The remaining Milestone 2 work is deliberately substantial: disassembly-assisted candidate
discovery, strings and references, call relationships and thunks, MSVC RTTI/vtables, an open fixture
corpus, reports, benchmarks, and continued malformed-input/resource-limit validation. The WASM,
native C/C++, managed/.NET, and debugger-hosted execution paths remain future work; their contracts
and architecture are present, but should not be mistaken for working hosts.

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
external-process execution host are implemented. Package installation and the other runtime hosts
are still outstanding.

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
- Transactional plugin claims and failure-tolerant `AnalysisSession` packaging
- Initial contracts and example packages for:
  - WebAssembly plugins
  - native C ABI and C++ SDK plugins
  - managed/.NET SDK plugins with a self-contained host
  - external-process plugins
  - debugger-hosted bridges

The native and managed families are initial architecture requirements, not post-1.0 add-ons, but
their current deliverables are contracts and SDK foundations rather than execution hosts.
Out-of-process hosting is the default even when an in-process trusted fast path is eventually available. A
child process is a crash boundary, not an OS security sandbox; platform sandboxing remains separate
work.

## Milestone 2: useful native-binary MVP

The first intentionally narrow analysis target is native Windows x86-64 PE input without packed or
adversarial obfuscation.

- Format, section, import, export, and build-metadata extraction
- Executable-range and candidate function discovery
- Exception and unwind metadata ingestion
- Strings, constants, references, call relationships, and thunks
- Initial MSVC RTTI and vtable analysis
- Portable `.resym` analysis package
- Deterministic, loss-aware JSON symbol projection
- Reproducible open-source fixture corpus compiled with and without symbols
- Boundary, coverage, malformed-input, and resource-limit benchmarks

The PE metadata, x64 exception ingestion, portable package, canonical package encoding, neutral
JSON export projection, and related CLI portions are implemented. Human-readable reports and the
other bullets describe the remainder of this milestone.

The MVP should be useful without AI, a network connection, Ghidra, or IDA.

## Milestone 3: matching and tool integration

- Cross-build function and type mapping
- Known-library and reproducible-source signature packs
- Symbolized-build propagation with evidence and confidence
- Standalone IDAPython importer for applying the initial safe graph subset (implemented)
- Standalone Ghidra Java importer with equivalent identity checks (implemented)
- Interactive IDA and Ghidra bridges for preview, selective application, and provenance comments
- MAP or simple public-symbol export
- Synthetic PDB export for validated public functions
- Explicit lossy-export diagnostics

The neutral projection already emits structured diagnostics for reductions such as unsupported
assertions, name collisions, conflicting sizes, and overlapping ranges. Target-specific loss
summaries and richer in-tool review remain part of this milestone. MAP and PDB are explicitly later
outputs; the first import scripts do not generate either format.

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
