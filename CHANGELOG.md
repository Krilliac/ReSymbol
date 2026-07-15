# Changelog

All notable user-visible and compatibility-relevant changes to ReSymbol are recorded here. The
project is still in alpha, so public Rust APIs and serialized schemas may change between
prereleases; breaking changes remain explicit.

## Unreleased

### Added

- Added the first sandboxed WebAssembly Component Model analysis host for PE32+ x86-64 sessions.
  Components run in an in-process Wasmtime store that links only the checked-in ReSymbol WIT
  imports and no WASI interfaces, receive permission- and phase-gated `binary.read` and claim
  submission plus bounded logging and cancellation checks, and commit claims only after the
  complete lifecycle and final artifact checks succeed. Eligible WASM plugins autoload without an
  approval record because they have no ambient authority, while safe mode, `plugin.disabled`,
  exact-artifact quarantine, reset, and post-run policy checks still apply.
- Added a source-backed Rust Component Model example that verifies the exact DOS `MZ` bytes,
  submits one evidence-backed comment claim, and is rebuilt reproducibly with ordinary Cargo plus
  an example-local `wit-component` encoder. CI verifies the checked-in component against locked
  source, every release platform runs the staged two-file plugin through its exact release CLI,
  and portable archives include the ready-to-run component under `plugins/`.
- Added the first native C/C++ out-of-process analysis host. Drop-in plugins approved by exact
  directory fingerprint run in a bundled disposable sibling helper, can use a permission-gated,
  size-bounded PE `binary.read` callback, and commit claims only after full-batch validation; native
  plugin faults discard the batch and quarantine that artifact, while confirmed pre-load helper
  failures remain host-side. This is crash isolation, not an OS sandbox. Official Linux archives
  pair the musl CLI with a GNU helper built on Ubuntu 22.04 for glibc 2.35 or newer.
- Added the first managed/.NET out-of-process analysis host for PE32+ x86-64 sessions. Approved
  prebuilt .NET 8 plugins run through a bundled, self-contained `resymbol-managed-host` sibling,
  receive a strongly typed SDK plus permission- and phase-bounded `binary.read` and claim services,
  and commit logs and claims only after their complete lifecycle and final identity checks. The
  parent and helper bind the exact plugin fingerprint, private-DLL closure, source binary, PE map,
  limits, and deadline; family-specific load markers distinguish plugin-attributable quarantine
  from helper preflight failures. This is crash and dependency-resolution isolation, not an OS or
  CLR sandbox, and official archives require no separately installed .NET runtime. The managed SDK
  is also published as a compile-only NuGet release asset; `AnalysisRequest.BaseAnalysis` exposes
  the detached canonical base analysis only when `symbols.read` is granted.
- Added executable-plugin process-tree lifecycle containment. External, native, and managed launches
  own descendants through POSIX process groups or Windows Job Objects and terminate the owned tree
  on direct-child completion, deadline, stdout/stderr capture failure, or runtime drop. This is not
  filesystem, network, or authority sandboxing: Windows retains a narrow spawn-to-Job-assignment
  escape race, and a hostile POSIX plugin/helper or descendant can deliberately leave its process
  group or session.
- Added bounded modern MSVC x64 Rev1 RTTI and vftable discovery, including validated stored type
  names, base-class records, virtual-slot targets, vftable names, and attributed function-to-class
  relationships.
- Expanded the source-available, byte-reproducible MSVC x64 fixture corpus to four PE inputs:
  optimized and unoptimized builds, each with and without CodeView metadata. The existing optimized
  filenames remain stable, exact hashes bind every checked-in executable, and the semantic oracle
  shares portable expectations while keeping layout-sensitive requirements specific to each
  optimization profile. These fixtures are repository/source test data rather than portable runtime
  archive contents; their byte-variable full PDBs remain local build outputs.
- Added a pure-Rust x86-64 decoder that performs a bounded control-flow-guided block sweep of fully
  file-backed `RUNTIME_FUNCTION` ranges for supported direct calls and data references, and checks
  seeded executable candidates for one-instruction internal, import, or read-only function-pointer
  thunks. No native disassembler library or compiler is needed to run a release build.
- Added bounded exact recovery of NUL-terminated printable ASCII and valid UTF-16LE strings from
  file-backed, initialized, readable, non-executable PE sections, with deterministic overlap
  handling and explicit partial-scan state.
- Added supported x64 RIP-relative data-reference recovery to eligible file-backed data, recording
  the caller, instruction RVA and size, and exact target RVA without inventing access semantics or
  target names.
- Added explicit resolution of exact `FF 15 disp32`/`48 FF 15 disp32` calls and exact
  `FF 25 disp32`/`48 FF 25 disp32` thunks through one complete eight-byte slot in read-only
  initialized PE data. Parsed IAT slots retain precedence; accepted non-IAT slots resolve one
  preferred-image VA hop to executable code and preserve both `slot_rva` and the endpoint. Pointer
  calls also retain a paired same-site data reference, while pointer thunks preserve control-flow
  provenance without inventing a data-reference record outside the instruction sweep. Focused
  synthetic PE fixtures cover the encodings, rejection policy, caps, packages, and exports without
  regenerating or changing the hashes of the four checked-in MSVC corpus binaries.
- Added `ControlFlowTarget` and the `FunctionEntry`, `DirectCall`, and `ThunkTarget` symbol
  assertions, plus PE recovery records and graph attribution for PE entry points, recovered targets,
  and validated RTTI virtual slots.
- Extended the external-process plugin wire schema with the corresponding function-entry,
  direct-call, thunk-target, internal-function, import-IAT, and additive `function-pointer` target
  shapes decoded by the host.
- Added deterministic control-flow and class-membership projection, including attributed function
  entries, calls, and thunks in neutral JSON. The IDAPython and Ghidra Java writers remain
  conservative and do not install those relationships.
- Added attributed recovered strings and data references to the deterministic neutral projection.
  Neutral JSON preserves them, while the standalone debugger scripts do not install them yet.
- Added deterministic string-reference correlation to the neutral projection. A data reference now
  identifies a retained string when its target is the string start or a valid content-interior
  address; NUL terminators are excluded, UTF-16LE interior targets must be code-unit aligned, and an
  absent correlation does not prove the target bytes are not a string.
- Added `resymbol export PACKAGE --format markdown`, a deterministic, bounded human-readable
  report with binary-identity, summary, function, global, type, string, direct-call,
  data-reference, thunk, and warning sections. Markdown is a presentation format rather than a
  stable interchange contract; neutral JSON remains the machine-consumable artifact.
- Added `resymbol export PACKAGE --format map`, a deterministic PE-only
  Microsoft-linker-style text writer for tools that support that layout. It emits selected named
  functions and globals as one-based PE `section:offset` and preferred-image-base-plus-RVA values,
  uses `<resymbol>` synthetic provenance, escapes unsafe raw section-name bytes, and retains exact
  SHA-256/file-size identity as informational semicolon comments. The CLI defaults to
  `application.map`; for a valid UTF-8 package stem, unsupported bytes become `_` and the result is
  capped at 255 bytes. Non-UTF-8 or otherwise unusable stems use `resymbol_<sha12>`.
- Added `resymbol export PACKAGE --format pdb --binary EXACT_ORIGINAL_PE`, a deterministic,
  bounded, pure-Rust MSF 7.00 PDB writer for selected public function and global names. It verifies
  the supplied PE bytes against the package, requires one unambiguous CodeView RSDS record, copies
  its exact GUID+age and the PE's raw section headers, and never rewrites the executable. The first
  slice deliberately omits private symbols, compilands, source lines, locals, prototypes, function
  extents, and types; ordinary generation requires no Visual Studio, DIA, LLVM, or compiler
  installation.
- Added Windows PDB compatibility CI covering native `llvm-pdbutil` stream inspection, its
  DIA-backed view, and a direct DIA probe for exact GUID+age validation and public function/global
  enumeration.
- Added `ResymPackage::try_map_payload` so applications can migrate a payload after validating and
  preserving its package envelope.

### Changed

- Expanded exact public parser-boundary regressions for oversized PE header offsets, directory and
  table declarations, runtime-function counts, bounded PE strings, and CodeView payload and
  RSDS-record sizes. The matrix pins fail-fast errors before untrusted declared sizes can drive
  large mappings or allocations where the format permits an early decision.
- Added diagnostic-bearing `ProcessIo` and `ProcessWorkerPanicked` runtime errors. Execution-stage
  process polling, process-tree termination, reaping, pipe I/O, and pipe-worker failures now retain
  the bounded stderr observed before the failure, are classified as host infrastructure failures,
  and no longer quarantine the plugin artifact.
- Raised the pinned Rust source-build toolchain and workspace MSRV to 1.86 for the Component Model
  host. Ordinary release users and users of the bundled WASM example still need no compiler.
- New `.resym` analyses use package schema 4. The new `function-pointer` control-flow target
  persists both the read-only slot RVA and resolved function RVA. Schema 4 validation requires the
  paired same-site slot data reference for a direct call; a pointer thunk does not require one.
- The debugger-neutral JSON projection now uses schema 6. Schema 4 added attributed string and
  data-reference arrays to schema 3's entry attribution and control-flow relationships; schema 5
  added `referenced_string_rva` correlation; and schema 6 adds explicit `function-pointer` targets.
  A retained pointer target losslessly preserves its slot and resolved endpoint. If deterministic
  same-site data-reference reduction selects a conflicting noncompanion reference, the projection
  omits the pointer call with an `unsupported-assertion` warning instead of flattening it.
- `resymbol analyze` and `resymbol inspect` report recovered string, data-reference, direct-call,
  and thunk counts plus their applicable partial-recovery status.
- Address-kind collision diagnostics and both standalone debugger writers now share one
  mutation-aware rule: a same-RVA global is suppressed only when the writer actually emits a
  function record. Entry-only function evidence does not become a debugger mutation.
- Export artifacts are staged and flushed beside their destination, then published with a
  no-clobber operation. Write failures no longer leave a truncated file at the requested final
  path.
- PDB's `--binary` requirement is enforced during CLI argument parsing, and the public Rust writer
  accepts exact PE bytes and performs its own digest and CodeView inspection instead of trusting a
  caller-constructed metadata summary.
- Code recovery now uses a deterministic ordered worklist for direct same-range branch targets,
  stops at terminal or indirect control flow, and refuses to decode branch targets inside an
  already decoded instruction. This suppresses unreachable post-return bytes and can recover valid
  blocks after jump-over data while retaining deterministic bounded relationship ordering.
- New direct-call graph evidence describes the control-flow-guided traversal accurately. Validated
  package reads continue accepting the exact legacy bounded-linear-sweep evidence summary without
  relaxing any other evidence field.

These public-struct field and public-enum variant additions are source-breaking for downstream Rust
code that constructs or destructures the structs directly or matches the enums exhaustively.
ReSymbol is not yet 1.0; downstream users should pin an alpha version and validate serialized
schema versions independently.

### Compatibility

- The CLI can inspect and export package schemas 1 through 3 through explicit, validated in-memory
  compatibility paths. It revalidates persisted metadata, plugin runs and claims, binary binding,
  and rebuilds the deterministic base graph; it does not rewrite a legacy package. `inspect --json`
  preserves the validated original representation instead of mislabeling migrated content.
- Schema 1 plugin claims pass through a closed legacy assertion decoder. Name, prototype,
  boundary, type-definition, class-membership, and comment claims remain accepted and fully
  revalidated; post-schema-1 entry, control-flow, string, data-reference, and unknown assertion
  kinds are rejected under the legacy version label.
- Schema 1 packages do not contain the original executable bytes, so migration cannot run the new
  recovery passes. Migrated direct-call, thunk, string, and data-reference sets remain unavailable
  and are not evidence that no relationships or literals exist. Schema 2 retains its persisted
  direct calls and thunks but predates strings and data references. Schema 3 retains string/data
  recovery, while schemas 2 and 3 both predate read-only function-pointer call and thunk
  resolution.
  Reanalyze the exact original binary to create schema 4 with current recovery. The reader rejects
  schema 2 or 3 envelopes containing schema-4 function-pointer targets in base relationships,
  symbol graphs, or plugin claims instead of accepting a relabeled payload.
- Package schema 4 and neutral projection schema 6 are independent version domains. Generic
  package readers still require an explicit compatibility range and application-defined payload
  migration to accept an older schema.
- Markdown export is presentation-only and does not change either version domain: new analyses
  continue to use package schema 4 and the neutral projection continues to use schema 6.
- MAP export consumes the current validated session and neutral projection without adding fields to
  package schema 4 or projection schema 6.
- PDB export consumes the same current session and projection plus a byte-backed inspection of the
  exact original PE. It does not add fields to package schema 4 or projection schema 6.
- Managed-plugin execution adds no package-schema field: successful runs and validated claims use
  the existing `AnalysisSession` plugin ledger and claim representation.
- WASM-plugin execution likewise adds no package-schema field. It uses the existing plugin ledger,
  claim validation, and exact binary/artifact identity domains; the WIT package remains
  `resymbol:plugin@0.1.0`.

### Safety and limits

- The default WASM invocation accepts a component up to 64 MiB, enforces a 256 MiB linear-memory
  store limit, 100,000,000 fuel, a 2 MiB WebAssembly stack, one memory, two tables, 32 instances,
  and a 100,000-element table limit. It has a 30-second epoch deadline, permits at most 4,096
  host events and 8 MiB of aggregate event data with a 1 MiB per-event ceiling, and permits at
  most 64 MiB of aggregate `binary.read` requests with a 1 MiB per-call ceiling. The first host
  accepts only a validated PE32+ x86-64 image and caps exact input bytes at 1 GiB.
- No WASI interface is linked, so ordinary components have no ambient filesystem, network,
  environment, clock, or process access. Wasmtime and its generated native code execute inside
  ReSymbol, however: an engine, compiler, or host-binding vulnerability can cross the component
  boundary or terminate the application. The component-byte cap applies before compilation, but
  fuel, epoch deadlines, stack, and store limits govern instantiated guest execution. They do not
  interrupt synchronous validation/JIT compilation or cap compiler and other host allocations, so
  compilation can exceed the configured guest time and memory ceilings. Transactional output and
  the guest limits are not process isolation.
- Built-in code recovery is capped at 64 MiB of decoded instruction bytes, 1,000,000 instructions,
  262,144 discovered block starts, 8,192 retained direct calls, 32,768 retained data references,
  and 4,096 retained thunks. Exhaustion retains deterministic valid results and marks the
  applicable relationship sets partial. Neutral projection validation applies separate, larger
  collection caps.
- Built-in string recovery scans at most 64 MiB, retains at most 16,384 literals and 4 MiB of UTF-8
  text in aggregate, and caps each exact value at 4 KiB UTF-8 and 4 KiB encoded data including its
  terminator. Reaching a limit never publishes a truncated prefix and records the scan as partial.
- Internal targets covered by known runtime-function metadata are suppressed unless their RVA
  matches a recorded runtime-function begin. A call to its own next instruction is not promoted to
  a function target. Overlapping runtime-function ranges may be traversed and charged to decoder
  budgets separately.
- Read-only function-pointer calls and thunks are accepted only from exact supported RIP-relative
  encodings. Their non-IAT slot must be eight fully backed bytes of initialized, readable,
  non-writable, non-executable data, and its preferred-image VA must resolve in one hop to
  file-backed executable code. A call is retained only with its exact paired data reference, so
  exhausting the data-reference cap also marks pointer-call recovery partial. A pointer thunk
  preserves the slot and endpoint without requiring a data-reference record.
- The decoder is heuristic-confidence evidence, not complete recursive disassembly or a persisted
  control-flow graph. It avoids unreachable post-terminal bytes and follows supported direct
  branches, but reachable embedded data can still produce false positives and invalid or unsupported
  control flow can omit later relationships on that path. Register-indirect control flow and
  complete call-graph recovery remain out of scope.
- Persisted-package validation can enforce structural, ordering, range, encoding, size, and graph
  invariants, but a `.resym` file does not contain the executable bytes. A later read therefore
  cannot independently byte-compare a recovered string or re-decode a data-reference instruction;
  the package SHA-256 binds those records to the exact binary, and byte-level reproduction requires
  reanalysis.
- RTTI discovery scans at most 64 MiB of eligible read-only data, retains at most 16 MiB of RTTI
  name text, and applies bounded candidate, vftable, hierarchy, base-record, and virtual-slot
  counts. A function retains at most 4,096 projected class memberships.
- Markdown reports retain at most 1,024 rows in each tabular section, truncate projection text to a
  256-byte per-cell budget before escaping, and cannot exceed 16 MiB. Markdown punctuation and
  raw-HTML/entity delimiters are escaped before projection text enters a table.
- MAP export accepts at most 262,144 selected named function/global candidates before same-RVA
  reduction and at most 64 MiB of generated text. A selected function wins over a selected global
  at the same RVA; an unnamed function suppresses nothing. MAP comments cannot enforce exact-binary
  identity, so consumers must compare the recorded SHA-256 and file size independently.
- PDB export accepts at most 262,144 selected named function/global candidates before same-RVA
  reduction and bounds both its logical stream set and complete MSF container. It rejects a missing,
  malformed, or second RSDS identity; a source/session mismatch; a selected symbol outside the PE
  sections; and unsupported names or layouts before creating the destination. A selected function
  wins over a selected global at the same RVA, while an unnamed function suppresses nothing.
- The first managed host accepts at most 512 private DLLs and snapshots at most 512 MiB of private
  assemblies plus a 1 GiB source binary. Their combined bytes must fit the advertised snapshot gate
  (256 MiB with current defaults). Messages, stdout, diagnostics, service calls, binary-read totals,
  phases, and deadlines have independent bounds. These gates do not constrain total CLR process
  memory or the plugin's ambient account authority.
