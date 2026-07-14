# Roadmap

ReSymbol is being built in capability milestones rather than date promises. Ordering may change as
the implementation and security model are validated. A roadmap item is not implemented merely
because it appears here; the current code, tests, release notes, and issue tracker are authoritative.

## Milestone 0: repository foundation

- Rust workspace with pinned formatting and lint tooling
- Core, CLI, and plugin-contract crate boundaries
- Cross-platform CI and managed SDK validation
- Architecture, contribution, security, and plugin-system documentation
- Dual MIT or Apache-2.0 licensing
- Reproducible test-fixture policy

## Milestone 1: graph and plugin foundation

This milestone establishes extensibility before analysis behavior becomes difficult to decouple.

- Binary identity and canonical address primitives
- Versioned entities for functions, ranges, names, types, claims, evidence, and plugin runs
- Transactional claim validation and conflict preservation
- Local `plugins/` discovery and autoload
- Manual disablement and `plugin.disabled` sentinel support
- Incompatible, quarantined, and development-error health states
- Safe mode and plugin diagnostics
- Version negotiation, dependency ordering, limits, and permission records
- Initial contracts and example packages for:
  - WebAssembly plugins
  - native C ABI and C++ SDK plugins
  - managed/.NET SDK plugins with a self-contained host
  - external-process plugins
  - debugger-hosted bridges

The native and managed families are initial architecture requirements, not post-1.0 add-ons.
Process isolation is the default even when an in-process trusted fast path is eventually available.

## Milestone 2: useful native-binary MVP

The first intentionally narrow analysis target is native Windows x86-64 PE input without packed or
adversarial obfuscation.

- Format, section, import, export, and build-metadata extraction
- Executable-range and candidate function discovery
- Exception and unwind metadata ingestion
- Strings, constants, references, call relationships, and thunks
- Initial MSVC RTTI and vtable analysis
- Portable `.resym` analysis package
- Deterministic JSON/report export
- Reproducible open-source fixture corpus compiled with and without symbols
- Boundary, coverage, malformed-input, and resource-limit benchmarks

The MVP should be useful without AI, a network connection, Ghidra, or IDA.

## Milestone 3: matching and tool integration

- Cross-build function and type mapping
- Known-library and reproducible-source signature packs
- Symbolized-build propagation with evidence and confidence
- IDA bridge for previewing and applying supported graph information
- Ghidra bridge with equivalent identity checks and provenance comments
- MAP or simple public-symbol export
- Synthetic PDB export for validated public functions
- Explicit lossy-export diagnostics

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

