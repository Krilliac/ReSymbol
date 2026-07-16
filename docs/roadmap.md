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

The first Windows-first desktop slice is now implemented in `crates/resymbol-workbench` with pinned
eframe/egui 0.32.3 dependencies so the workspace can retain Rust 1.86. It runs **Open Binary ->
background core-only Analyze -> Review -> Export**, preserves exact SHA-256 identity, and presents
read-only plugin health in a persistent four-theme, four-region shell. The shell includes a
virtualized sortable/filterable function table, synchronized evidence inspector,
progress/warning/log surface, evidence-first Reconstruction Graph, non-executing static Address
Space/protection view, and read-only Debugger / Sandbox readiness view. That graph roots at the PE
entry point or a clearly labeled deterministic lowest-RVA navigation fallback, shares selection with
the function review surfaces, and displays only retained direct-call, thunk, and import
relationships. Explicit node/tier bounds keep large binaries responsive and visible as truncated
rather than implying complete call-graph recovery. Through the existing shared package, review, and
export models the workbench can open current `.resym` packages, persist binary-bound schema-2
exact-claim review sidecars with transaction-level undo/redo, and create new `.resym`, neutral JSON,
bounded Markdown, MAP, public-symbol PDB, IDA Python, and Ghidra Java files without replacing an
existing destination. **Keep as Alias** remains an alternate rather than an implicit primary;
disposition and rationale are one undo/redo unit. A dirty native close or companion-console `quit`
requires an explicit create-new save, discard, or cancel decision, and save-and-close waits for the
exact queued ledger snapshot to become durable.

An off-by-default companion console can be spawned from the running workbench. It mirrors bounded
timestamped activity and routes status, navigation, layout, export, and lifecycle commands back to
the GUI event loop through private process pipes; it never becomes a second owner of analysis state.

The backend-neutral debugger foundation now includes strict bounded framing, typed commands/events,
command-specific reducers, one-use authorization leases, exact attestation/cleanup evidence models,
a single-owner host-client seam, and a read-only provider-readiness service. The feature-gated
synthetic host supports only test/offline open-close mechanics and reports no platform capability.
Its plaintext build-claim exchange detects protocol mismatch and replay but does not authenticate a
peer or process. No live Windows host transport, AppContainer/Hyper-V provider, target execution,
attach, breakpoint, register, or process-memory service is implemented.

This is a foundation, not the completed workbench or a working sandbox. GUI plugin execution,
legacy-package migration, bulk review, docking, disassembly views, and an interactive debugger
bridge remain planned. A portable Windows archive is the initial GUI packaging target; broader
desktop packaging remains future validation.

The CLI writes package schema 13 and can inspect or export schemas 1 through 12 through explicit
compatibility paths. Schema 1 is migrated in memory by revalidating persisted metadata and
rebuilding the base graph; schema 2 already contains direct-call and thunk recovery, and schema 3
adds string/data recovery. Schema 4 adds read-only pointer control flow but predates legacy 24-byte
RTTI base-class descriptor recovery. Schema 5 adds that RTTI form but predates transitive executable
thunk-chain discovery. Schema 6 adds that closure but predates TLS callback discovery and
callback-based thunk seeding; schema 7 adds TLS callbacks but predates modern delay-import
recovery; schema 8 adds delay imports but predates load-config GuardCF recovery; schema 9 adds
GuardCF functions but predates the modern Guard target inventories; schema 10 adds those inventories
but predates load-config security-anchor recovery; schema 11 adds those earlier anchors but
predates XFG/CastGuard storage-anchor recovery; and schema 12 adds XFG/CastGuard anchors but
predates the GuardMemcpy pointer-slot anchor. Older packages
do not embed executable bytes, so compatibility loading
cannot reconstruct results that were never recorded. Reanalyzing the exact original binary is
required for transitive thunk chains in schemas 1 through 5, 24-byte descriptors in schemas 1
through 4, read-only function-pointer calls and thunks in schemas 2 and 3, strings/data references
in schemas 1 and 2, TLS callbacks in schemas 1 through 6, delay imports in schemas 1 through 7,
GuardCF functions in schemas 1 through 8, Guard address-taken IAT, long-jump, and EH-continuation
inventories in schemas 1 through 9, load-config security-cookie and GuardCF check/dispatch
pointer-slot anchors in schemas 1 through 10, XFG and CastGuard storage anchors in schemas 1 through
11, the GuardMemcpy pointer-slot anchor in schemas 1 through 12, and
all code recovery when starting from
schema 1. Relabeled schema-6-only
transitive base-thunk sources are rejected under schema 1-through-5 envelopes; schemas 1 through 6
also reject schema-7 TLS callback state and callback-only base thunk seeds. Schemas 1 through 7 also
reject the exact schema-8 base-analysis `delay_imports` inventory key and
`directories.delay_imports` directory key. Schemas 8 through 13 require that explicit inventory,
even when empty.
Schemas 1 through 8 reject schema-9 load-config/GuardCF fields,
`directories.load_config`, and core `pe-guard-cf-function` claims; schemas 9 through 13 require an explicit
`guard_cf_functions` inventory even when empty.
Schemas 1 through 9 reject schema-10 Guard target table-RVA and inventory fields; schemas 10 through 13 require
explicit address-taken IAT, long-jump, and EH-continuation inventory arrays even when empty.
Schemas 1 through 10 reject the schema-11 `load_config_security_anchors` base-analysis object;
schemas 11 through 13 require that object even when all three anchors are absent. Schemas 1 through
11 reject schema-12 `load_config_xfg_anchors`; schemas 12 and 13 require that object even when all
four anchors are absent. Schemas 1 through 12 reject schema-13
`load_config_guard_memcpy_anchor`; schema 13 requires that object even when the anchor is absent.

For every supported package schema, 1 through 13, `resymbol inspect` can optionally accept the exact
original binary and require its size and SHA-256 to match before inspection data reaches stdout;
failures report on stderr. Human inspection reports the canonical source path and a matched identity
gate, while JSON remains pure package data. This is an identity check only: it does not rerun
analysis, recover omitted legacy results, or rewrite either file.

A bounded modern MSVC x64 Rev1 RTTI/vftable slice is now implemented. It validates compiler
metadata through complete object locators, type descriptors, legacy 24-byte and `BCD_HASPCHD`
28-byte base-class descriptors, class hierarchies, and executable virtual-slot targets. Descriptor
layouts may be mixed within one hierarchy; root and nested hierarchy links are required only when
the corresponding `pCHD` field exists. It recovers stored class/type names and vftable names and
records function-to-class memberships without inventing virtual-method names. Fixed scan, record,
slot, and name budgets surface partial discovery explicitly.

A bounded PE32+ TLS callback slice is now implemented from optional-header data-directory entry 9.
It requires a fully file-backed declared directory containing at least the 40-byte PE32+
TLS-directory prefix, converts preferred-image callback VAs to RVAs with checked image bounds,
preserves callback-table order and duplicates, requires every eight-byte slot it reads to be
file-backed, and requires retained endpoints to begin in executable file-backed data. It retains at
most 4,096 entries, then probes one more slot: null
proves an exactly capped table complete, while nonzero records an explicit partial prefix without
retaining the extra entry.
Each retained slot emits a `FunctionEntry` claim with `pe-tls-callback` provenance and distinct
slot/index evidence, including duplicate target RVAs. Retained targets join the deterministic
first-instruction thunk seeds without causing a callback-body sweep or executing the input.

A bounded PE32+ load-config GuardCF slice is now implemented from optional-header data-directory
entry 10. A present directory is fully file-backed and contains an internal structure size from 4
through the directory size; at least 148 internal bytes are required before ReSymbol exposes
`GuardCFFunctionTable`, `GuardCFFunctionCount`, and `GuardFlags`. Counts above 262,144, oversized
tables, structural inconsistencies, and malformed records are hard errors; an accepted GFIDS table
is retained in full with strictly increasing unique executable RVAs. Records have stride `4 + n`, where the
high `GuardFlags` nibble selects `n`, and those metadata bytes are retained exactly and opaquely.
The table must be fully backed and disjoint from the load-config directory; disjointness is a
ReSymbol hardening policy. Every structurally valid record, including one marked
`IMAGE_GUARD_FLAG_FID_SUPPRESSED`, `IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED`, or both, emits its existing
`FunctionEntry` claim and joins initial one-instruction thunk seeding. FID suppression describes CFG
eligibility rather than whether the target is a function; export-suppressed RVAs must be 16-byte
aligned. GFIDS does not cause a function-body sweep or name/extent inference.

The later Guard address-taken IAT, long-jump, and EH-continuation tables are now implemented as
bounded inventories. Their load-config field thresholds are 176, 192, and 280 bytes. GIAT,
long-jump, and EH-continuation records use the GFIDS `4 + n` stride and require zero reserved
metadata; GIAT RVAs must equal exact parsed conventional or delay-IAT slots. Long-jump and EH-continuation RVAs
must be strictly increasing, unique, and file-backed executable addresses. Nonempty tables require
their presence flags, every table has a 262,144-record cap, and all nonempty Guard tables must be
fully backed, disjoint from the load-config directory, and pairwise disjoint. The inventories remain
package/plugin-visible metadata only: they add no function claim or thunk seed because continuation
and landing addresses are not necessarily function starts.

The earlier PE32+ load-config security anchors are now retained separately. At internal structure
sizes 96, 120, and 128, ReSymbol reads `SecurityCookie`, `GuardCFCheckFunctionPointer`, and
`GuardCFDispatchFunctionPointer` respectively, treats a zero VA as absent, and converts each
nonzero preferred-image VA to a checked RVA. Every retained eight-byte storage range must lie
wholly within one mapped section, must be disjoint from the declared load-config directory, and
must be pairwise disjoint from the other anchors. Header storage and cross-section ranges are
rejected, while mapped zero-fill tails are valid. ReSymbol records the storage RVAs without
dereferencing initial values, enforcing section permissions, emitting claims, or adding thunk
seeds because the OS loader may patch the GuardCF slots at run time.

The later XFG/CastGuard load-config storage anchors are now retained in a separate always-present
schema-12 object. At internal structure sizes 288, 296, 304, and 312, ReSymbol reads
`GuardXFGCheckFunctionPointer`, `GuardXFGDispatchFunctionPointer`,
`GuardXFGTableDispatchFunctionPointer`, and `CastGuardOsDeterminedFailureMode`. Zero VAs are absent;
nonzero preferred-image VAs become checked RVAs. Their full eight-byte ranges follow the same mapped
section, header exclusion, load-config disjointness, and mapped-zero-fill policy as the earlier
anchors, and pairwise disjointness is enforced across both families. ReSymbol does not dereference
initial values, impose permission requirements, emit claims, or add thunk seeds.

The GuardMemcpy loader slot is now retained in its own always-present schema-13 object. At internal
structure size 320, ReSymbol reads `GuardMemcpyFunctionPointer`; zero is absent and a nonzero
preferred-image VA becomes the checked RVA of the full eight-byte loader-managed slot. The slot
follows the same mapped-section, header exclusion, load-config disjointness, mapped-zero-fill, and
cross-family pairwise-disjointness policy. ReSymbol does not inspect its initial contents, impose
permission requirements, emit claims, or add thunk seeds.

A bounded modern PE32+ delay-import slice is now implemented from optional-header data-directory
entry 13. It accepts an ordered sequence of 32-byte descriptors followed by an all-zero terminator
and only all-zero declared tail padding when the
attributes value is exactly the modern RVA-form `dlattrRva` (`1`); the legacy VA form, zero, and
unknown bits are rejected despite ambiguity in the generic PE table documentation. Each active
descriptor has nonzero name, module-handle (HMOD), delay-IAT, and delay-INT RVAs. HMOD needs an
eight-byte range wholly mapped inside one section but may occupy zero-filled virtual data rather
than file-backed bytes; initial contents and permissions stay opaque. Paired null-terminated 64-bit
INT/IAT arrays and optional bound-IAT (BIAT)
and unload-IAT (UIAT) arrays must be fully backed and pairwise disjoint. Each present BIAT or UIAT
must have a zero slot at the paired INT/IAT entry count. BIAT payload values before that required
slot are otherwise opaque, including whether any is zero, while the complete UIAT must byte-match
the original delay IAT. The package separately preserves descriptor and entry order, the DLL name,
descriptor RVA and exact attributes value, name/HMOD/IAT/INT base RVAs, optional BIAT/UIAT base
RVAs, each entry's lookup/IAT RVAs and hint/name or ordinal, and the timestamp. It does not serialize
raw INT/IAT/BIAT/UIAT array contents. Conventional and delay imports share ceilings of 4,096
libraries, 65,536 symbols, and 16 MiB of names; malformed input or budget exhaustion is a hard
analysis error rather than a partial prefix. Delay-IAT slots join conventional IAT slots for the
existing `ImportIat` call/thunk target and take precedence over read-only function-pointer fallback.

A bounded pure-Rust x86-64 code-recovery slice is also implemented. Its control-flow-guided block
sweep starts at fully file-backed `RUNTIME_FUNCTION` entries, follows supported direct same-range
branches with a deterministic ordered worklist, and stops paths at terminal, indirect, invalid,
out-of-range, or ambiguous interior control flow. It records exact supported direct calls,
including one-hop plain or redundant-`REX.W` RIP-relative calls through complete read-only
eight-byte pointer slots, and RIP-relative data references. At seeded executable candidates it
checks internal thunks and exact `FF 25 disp32`/`48 FF 25 disp32` IAT or one-hop read-only pointer
thunks. Parsed conventional/delay IAT membership takes precedence; each pointer relation preserves its slot and
endpoint, while only a pointer call requires a paired data reference. Original thunk candidates are
checked first in RVA order; internal endpoints of retained thunks form successive sorted layers
until the causal closure is exhausted. Each exact hop is preserved instead of being flattened to a
terminal function. Connected cycles terminate through global candidate deduplication and retain
their exact non-self edges, while disconnected persisted cycles are rejected. Executable endpoint
traversal does not follow pointer-to-pointer slots: every non-IAT slot remains a one-hop
dereference. It discovers at most 262,144 block starts and retains at most 8,192 direct calls,
32,768 data references, and 4,096 thunks. Reaching the shared decode or relationship caps preserves
the deterministic valid prefix and marks the applicable recovery state partial. Internal targets
covered by known runtime-function metadata are allowed only when their RVA matches a recorded
runtime-function begin or a retained GuardCF function start. Every other
interior endpoint remains suppressed regardless of another seed source. A separate bounded pass recovers complete
NUL-terminated ASCII and UTF-16LE literals from readable initialized non-executable file-backed
data. These passes emit attributed claims without inventing names or extents and preserve
independent partial-scan flags. The guided sweep suppresses unreachable post-terminal bytes and can
reach valid blocks after jump-over data, but remains heuristic evidence:
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

The first WebAssembly Component Model analysis host is implemented for the same PE32+ x86-64
sessions. It runs components in an in-process Wasmtime store, links only the versioned ReSymbol WIT
imports, and deliberately links no WASI interfaces. Permission- and phase-bounded `binary.read` and
claim submission, output-bounded logging, and cancellation checks operate under enforced
component-byte limits and instantiated-guest linear-memory, table, instance, stack, fuel, event,
read, and epoch-deadline controls. Lifecycle output is transactional, and the exact plugin
fingerprint and binary identity are checked around execution. Sandboxed WASM autoloads without a
trust record while safe mode, `plugin.disabled`, exact-artifact quarantine, and reset remain
effective.

No-WASI capability isolation removes ambient filesystem, network, environment, clock, and process
interfaces, but the engine and generated native code remain in ReSymbol's process. A Wasmtime,
compiler, or host-binding vulnerability is therefore not crash- or compromise-contained by a
separate process. The guest fuel, epoch, stack, and store controls also do not interrupt synchronous
validation/JIT compilation or cap compiler and other host allocations; except for the
component-byte cap, compilation can exceed the guest deadline or memory limit. The checked-in
source-backed example and locked ordinary-Cargo build are reproducibly rebuilt in CI, exercised
through each exact release CLI, and shipped as a ready-to-run two-file plugin in every portable
archive.

Official archives bundle both disposable helpers. Linux releases pair the static musl main
executable with a GNU native helper built on Ubuntu 22.04 for glibc 2.35 or newer so ordinary glibc
`.so` plugins can load. Every archive also carries the matching single-file, self-contained managed
helper, so ordinary users need no compiler, SDK, or separately installed .NET runtime. Archives
also include the prebuilt WASM example; ordinary users need no Rust or WASM development toolchain.

The first export checkpoint is implemented as a validated, debugger-neutral projection with
deterministic JSON output, a bounded human-readable Markdown report, PE-only
Microsoft-linker-style MAP text, an exact-RSDS public-symbol PDB, and standalone IDAPython and
Ghidra Java import scripts. Markdown is presentation-only rather than a stable interchange schema;
JSON remains the machine-consumable artifact. New analyses write package schema 13, while export also
accepts package schemas 1 through 12 through validated compatibility paths. The neutral projection is
independently schema 6; MAP and PDB add no schema fields, and no exporter rewrites its source
package. Projection schema 5 correlates exact or valid content-interior data-reference targets with
retained strings while excluding NUL terminators and misaligned UTF-16LE interiors; projection
schema 6 preserves function-pointer slot and resolved-target RVAs. TLS callback endpoints reuse its
existing function-entry and thunk shapes, so no TLS-specific projection field is added. Delay-load
descriptor inventory remains package-only, while delay-IAT control flow reuses the existing import
target with its slot RVA. GuardCF claims and supported seeded thunks reuse the existing shapes, so
load-config/GFIDS inventory and suppression evidence remain package-only. The later Guard target
inventories and all three load-config storage-anchor families are also package-only and add no claims, so
projection schema 6 is unchanged. The scripts
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

An initial source-available MSVC x64 fixture corpus is implemented as a byte-reproducible
four-artifact matrix: optimized and unoptimized PE inputs, each symbolized and stripped. Exact
hashes bind every input, while a shared semantic oracle keeps layout-sensitive expectations scoped
to the optimization profile. The matrix covers imports/exports, unwind functions, direct calls,
internal and MSVC `REX.W`-prefixed import thunks, ASCII/UTF-16LE strings,
data references, and modern RTTI/vftables without executing the fixture binaries. These checked-in
inputs are repository/source test data rather than portable runtime archive contents. Read-only
function-pointer calls and thunks, plus all-legacy and mixed 24/28-byte RTTI descriptor
hierarchies, are covered by focused synthetic PE fixtures. Exact transitive thunk chains, connected
cycles, disconnected-cycle rejection, bounded TLS callback discovery, modern delay-import recovery,
load-config GuardCF recovery, and modern Guard target inventories are also synthetic-only coverage.
These focused slices do not change the four corpus binaries, their semantic oracle, or their
recorded hashes.

The remaining Milestone 2 work is deliberately substantial: broader disassembly-assisted candidate
discovery, broader indirect control flow and richer call-graph analysis, persisted basic-block
modeling, broader RTTI/ABI coverage, broader compiler fixtures,
benchmarks, and continued malformed-input/resource-limit validation.
The strictly non-executing offline image host and its bounded workbench byte reader are implemented.
Process-executing debugger-hosted paths remain future work; neither the offline host nor the live
contracts should be mistaken for a working live debugger or malware sandbox.

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
WASM, external-process, native C/C++, and managed/.NET execution hosts are implemented. The
backend-neutral debugger protocol, reducer, host-client, authorization/evidence contracts, and
read-only readiness service are implemented, as is the production in-process offline image host;
package installation and process-executing debugger-hosted runtimes are still outstanding.

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
- POSIX process-group and Windows Job Object lifecycle containment for external, native, and managed
  process trees
- No-WASI Component Model analysis with bounded WIT host services, enforced Wasmtime resource
  limits, sandboxed autoload, transactional claims, and exact-artifact quarantine
- Disposable sibling-process native C/C++ analysis with bounded file-backed PE `binary.read`
  callbacks and full-batch validation
- App-local self-contained managed/.NET analysis helper with a host-supplied SDK, verified private
  DLL and exact-binary snapshots, phase-bounded services, and transactional lifecycle
- Backend-neutral debugger framing, typed reducer/client seam, one-use authorization, exact
  attestation/cleanup evidence models, test-only synthetic mechanics, and read-only provider
  readiness without a live target or claimed sandbox
- Transactional plugin claims and failure-tolerant `AnalysisSession` packaging
- Initial contracts and example packages for:
  - WebAssembly plugins with a source-backed, release-staged component
  - native C ABI and C++ SDK plugins
  - managed/.NET SDK plugins with a self-contained host
  - external-process plugins
  - debugger-hosted bridges

The native and managed families are initial architecture requirements, not post-1.0 add-ons. Their
contracts, SDK foundations, and first out-of-process analysis hosts are implemented. Out-of-process
hosting is the only supported path for both families even if an explicitly trusted fast path is
eventually designed. A child process is a crash boundary, not an OS security sandbox; platform
sandboxing remains separate work. The current runner owns ordinary descendants through POSIX
process groups or Windows Job Objects and terminates the tree on direct-child completion, deadline,
stdout/stderr capture failure, or runtime drop. This lifecycle containment does not restrict ambient
authority. Windows retains a narrow pre-Job-assignment escape race, and a hostile POSIX
plugin/helper or descendant can deliberately leave its process group or session. Linux and macOS
otherwise observe direct-child exit without reaping and terminate the stable group before collecting
the leader's status.

## Milestone 2: useful native-binary MVP

The first intentionally narrow analysis target is native Windows x86-64 PE input without packed or
adversarial obfuscation.

- Format, section, import, export, and build-metadata extraction
- Executable-range and candidate function discovery (exception ranges, exports, calls, seeded
  entries, and the narrow load-config/GFIDS source implemented)
- Exception and unwind metadata ingestion (current x64 `RUNTIME_FUNCTION` boundary slice
  implemented; broader unwind semantics remain planned)
- Strings, constants, references, call relationships, and thunks (bounded exact strings, supported
  RIP-relative data references, direct calls, exact per-hop transitive one-instruction thunks, and
  exact/content-interior string-reference correlation implemented; broader constants remain
  planned)
- Initial MSVC x64 Rev1 RTTI and vftable analysis (bounded dual-descriptor-layout slice implemented)
- Portable `.resym` analysis package
- Deterministic, loss-aware JSON symbol projection
- Deterministic, bounded Markdown review report
- Reproducible open-source fixture corpus across optimization and symbol configurations (initial
  deterministic four-artifact MSVC x64 matrix and profile-sensitive semantic oracle implemented;
  broader compilers remain planned)
- Boundary, coverage, malformed-input, and resource-limit benchmarks

The PE metadata, narrow load-config/GFIDS candidate source, x64 exception ingestion, bounded string,
data-reference, direct-call, and transitive-thunk recovery,
deterministic string-reference correlation, bounded dual-layout MSVC x64 RTTI/vftable slice,
portable package, canonical package encoding, neutral JSON export projection, bounded Markdown
report, initial MSVC fixture matrix, and related CLI
portions are implemented. The unfinished parts of the bullets describe the remainder of this
milestone. Broader load-config/security semantics, including `UmaFunctionPointers` and
architecture-specific SafeSEH metadata, remain planned, as do
names/extents/body recovery beyond the current evidence, broader constants and
compilers, and resource/coverage benchmarks.

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
  bounded retained-relationship graphing, and export preview (initial Windows-first core-only shell,
  synchronized Reconstruction Graph, static Address Space/protection assessment, bounded exact-RVA
  reads from verified source snapshots, non-executing debugger/sandbox readiness, evidence inspector,
  current-package opening, six create-new exports, and transaction-safe exact-claim review with
  versioned sidecars, dirty-close protection, and undo/redo implemented; bulk review, plugin
  execution, docking/disassembly, editable or exhaustive graphing, live debugger bridges, and the
  remaining [approved design](gui-design.md) are planned)
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
