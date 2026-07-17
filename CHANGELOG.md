# Changelog

All notable user-visible and compatibility-relevant changes to ReSymbol are recorded here. The
project is still in alpha, so public Rust APIs and serialized schemas may change between
prereleases; breaking changes remain explicit.

## Unreleased

### Added

- Added `resymbol-windows-live-access`, a narrowly scoped Windows-only process-memory foundation
  for a future authenticated debugger helper. It opens only an explicitly selected PID with an
  expected executable SHA-256 plus previously observed creation `FILETIME` and debug-event image
  base, independently re-derives both runtime values, and retains the exact
  hashed/parsed executable file handle without write/delete sharing for the access object's lifetime.
  Its PE `SizeOfImage` is corroborated against both the Tool Help main-module record and remote PE
  header before constructing `LiveTargetBinding` with the actual ASLR base. Read-only and explicitly
  mutating opens request different least-privilege process rights. Public operations re-derive the
  binding from the retained evidence; reads are exact and bounded to the main image, while writes
  require the exact binding, exact expected bytes, an equal-length changed replacement, and one
  committed executable `MEM_IMAGE` region and one system page. A mutation compare-checks before and
  after changing protection, restores protection without attempting a byte write if either race
  check fails, flushes the instruction cache, verifies readback, and reports truthful recovery
  evidence after any post-protection failure. This primitive
  does not attach, stop, launch, resume, step, set breakpoints, authenticate a transport, or wire the
  workbench, and a future provider must hold the process stopped before granting mutation authority.
  Tool Help module discovery is only corroborating evidence; its size is compared with the retained
  file before a bounded full-image region walk, and the request's image base must come from independent
  authenticated debug-event evidence before the caller treats the binding as authority.
- Added a bounded x64 linear-disassembly preview to the workbench Address Space reader. Hex and
  disassembly views share the same verified frozen-source bytes; independent byte and instruction
  limits, explicit stop reasons, and the visible "not CFG or function-boundary truth" disclaimer
  keep the preview non-executing and non-authoritative. Rows retain exact instruction bytes and only
  expose decoder-proven direct branch/call targets, with keyboard-accessible copy, follow, and action
  menus available from every RVA/opcode/instruction/flow/length cell. Static NOP requests are queued
  as exact-byte drafts; **Create New Patched Binary** converts them to requests that must each decode
  as exactly one complete x64 instruction, then the application-service worker builds a checked
  plan, revalidates source identity and bytes, and no-clobber publishes a separate binary. General
  same-size `ReplaceBytes` requests remain the explicit arbitrary-byte escape hatch. The separate live NOP,
  software-breakpoint, Run to Cursor, Step Into/Over/Out, and Continue actions expose their typed
  debugger routes but remain visibly disabled until an authenticated live provider supplies a
  complete capability report plus current stop/address/thread bindings. Live NOP uses
  compare-before-write with an equal-length `0x90` replacement; Run to Cursor composes a temporary
  software breakpoint with Continue. Static and live NOP actions reject instructions whose exact
  bytes are already entirely `0x90` instead of queuing an unpublishable no-op.
- Added an explicit, guarded binary-replacement workflow to the desktop workbench. Users can open
  another binary or `.resym` package from the loaded-project header, the File menu, Ctrl+O, the
  Open Binary workflow stage, Open Recent, or single-file drag and drop. Dirty review state requires
  Save, Discard, or Cancel before replacement; failed and stale opens preserve the active project,
  review ledger, and recent-file history.
- Added read-only native Windows debugger-readiness observations for AppContainer API availability,
  virtualization-firmware reporting, and Windows Hypervisor Platform presence. The probes load only
  system modules, never enable features or request elevation, and only remove requirements supported
  by positive evidence; they do not claim that a process-executing provider is ready.
- Added `resymbol export --dry-run` for every export format. It preserves package validation,
  target-loss assessment, exact-source PDB verification, and complete writer rendering while
  creating neither the prospective destination nor a staging file; `--fail-on-loss` remains
  enforceable in the same pre-publication flow.
- Added a UI-independent, same-size static PE patch subsystem. Immutable plans bind to the full
  source binary identity and retain deterministic labeled NOP-instruction or general-byte edits
  with exact RVA, provisional file offset, expected bytes, and equal-length replacement bytes. NOP
  spans must decode as exactly one complete valid x86-64 instruction. Application reparses the
  exact source with a new bounded header-only layout inspection, requires the fresh complete
  identity and each executable/file-backed RVA mapping to match the plan, then performs all
  expected-byte comparisons before creating a deterministic output in one separately owned buffer.
  Persisted package section metadata therefore cannot authorize a write. `AppServices` can stage,
  flush, file-synchronize, and create-new publish that image without modifying the source or
  replacing an existing target; failed staging is cleaned automatically. The named destination is
  reopened and its streamed size and SHA-256 must match before a success receipt is returned.
  Static patch and ordinary export jobs share one mutually exclusive canonical destination
  reservation in the workbench. Unix parent-directory synchronization failure after publication is
  reported as a verified-file partial-success durability warning, while Windows reports file-only
  synchronization and makes no power-loss durability claim for the destination directory entry.
  Every result explicitly warns that Authenticode signature validity and the PE checksum may be
  invalidated, and ReSymbol does not repair, recompute, or re-sign them.
- Expanded each disassembly-row context menu with static conditional-branch edits. Exact canonical
  short and near Jcc instructions can be inverted or made always-taken as same-size unpublished
  drafts; NOP remains the never-taken choice. Near always-taken conversion adjusts its displacement
  before appending a NOP so the original target is preserved. Prefix-bearing, displacement-overflow,
  and non-Jcc encodings fail closed, and all edits still pass exact-source compare-before-write and
  create-new publication.
- Added a deterministic visual-regression scenario for the disassembly preview with an exact row
  selected, making the instruction-action affordance, bytes, flow category, and static/live
  separation part of the standard GUI capture artifact set.
- Added a refreshable exact-artifact policy catalog to the desktop workbench. Scans run on the
  bounded application-service worker and replace one owned snapshot, while the UI remains strictly
  non-executing. Every fingerprintable unpacked candidate with a valid manifest reports its exact
  SHA-256 and policy status as `SANDBOXED`, `TRUSTED`, `APPROVAL REQUIRED`, `DISABLED`,
  `QUARANTINED`, `CORRUPT STATE`, or `UNAVAILABLE`. Sandboxed WASM needs no trust record; non-WASM
  runtimes require trust for the exact fingerprint, mutations return to approval-required, and
  policy-relevant corrupt or quarantined state fails closed. Discovery health includes manifest,
  API, entrypoint, duplicate-ID, and declared plugin-dependency checks. Passing this policy does not
  claim full CLI executability; runtime support, capability selection, host/helper availability,
  granted permissions, target compatibility, and launch-time revalidation remain separate.
- Added a responsive, keyboard-first workbench navigation slice. The default 1440x900 review shell
  keeps all eight main views on one compact row and fits all six Function columns with both side
  panels open; the documented 1024x680 minimum uses an explicit all-view selector and a labeled
  horizontal Function-table overflow instead of hiding controls, while compact identity/activity
  chrome preserves a usable row viewport. Ctrl+Tab and Ctrl+Shift+Tab cycle views, Ctrl+F focuses
  Function search, and stable Up/Down, Page Up/Page Down, Home, and End
  navigation follows the active filter and sort with a distinct focus outline and accessible row
  state. Visual CI also captures the focused minimum-viewport state.
- Added durable exact-claim review to the desktop workbench. Function name proposals retain their
  complete-claim fingerprint and provenance, while Accept Primary, Keep as Alias, Reject, optional
  rationale annotations, undo, and redo update a binary-bound ledger. Strict sidecar load,
  create-new save, orphan reporting, and reviewed-projection rebuilds run on the bounded worker;
  operation identifiers, ledger snapshots, and exact binary identity reject stale results. All six
  review-aware symbol exports consume the active ledger, while canonical `.resym` packages keep
  review history in the separate sidecar.
- Added checked PE32+ `GuardMemcpyFunctionPointer` storage-anchor recovery from the versioned load
  configuration. Package schema 13 records the optional checked slot RVA behind an always-present
  marker, while schemas 1 through 12 remain explicitly readable and report the field as unavailable.
  The loader-managed slot is inventory only: it does not create a function, thunk, graph edge,
  claim, or control-flow seed. Malformed, overlapping, cross-section, header, and unbacked layouts
  fail before publication, and schema relabeling is rejected.
- Aligned the static PE address-space model with loader layout rules. It validates
  `FileAlignment`/`SectionAlignment`, rounds header and section mappings without overlap or image
  overflow, treats `VirtualSize == 0` as the checked raw-size fallback, and distinguishes exact
  file-backed bytes, virtual zero-fill, mapped alignment padding, and unowned image gaps in both the
  debugger model and workbench table.
- Added the backend-neutral `resymbol-debugger` foundation without enabling target execution. The
  crate provides an exact-identity static PE address-space partition, bounded protection indicators,
  capability- and token-carrying debugger commands/events, compare-before-write contracts, a
  length-bounded helper wire format, a single-owner typed client, a reducer-backed non-executing test
  host, read-only provider-readiness discovery, and fail-closed sandbox policy, attestation,
  lifecycle, and cleanup records. The workbench now exposes the preferred-image Address Space view
  and evidence for entry-point, TLS, anti-debug-import, packer, entropy, and writable/executable-section
  findings. No process-executing debugger helper, Windows AppContainer provider, Hyper-V guest,
  attach path, authenticated stopped-state authority, or provider/UI live-memory integration is
  implemented yet; the test host, readiness reports, and lower-level Windows live-access primitive
  must not be represented as an operating-system security boundary or working debugger.
- Added a production, strictly non-executing `OfflineImageDebugHost`. It freezes one exact
  identity-verified image snapshot, exposes only bounded canonical file-backed RVA reads, reports a
  complete capability matrix with only `OfflineAnalysis` available, and rejects every live,
  mutating, execution, attach, launch, and sandbox operation without emitting security evidence.
- Added a worker-owned Address Space byte reader backed by that offline host. It accepts an exact RVA
  and a 16/32/64/128/256-byte size, binds results to the full binary identity, canonical verified
  source path, operation, and span, and displays bounded hex/ASCII rows only after close, release,
  and disconnect complete. Package-only projects remain source-required, while gaps, zero-fill,
  padding, and cross-region reads are typed nonfatal unavailability rather than guessed bytes.
- Added the first Windows-first `resymbol-workbench.exe` desktop slice. It runs bounded core-only PE
  analysis away from the UI thread and presents exact identity, evidence- and provenance-first
  function review, read-only plugin health, and a visual Reconstruction Graph rooted at the PE entry
  point or a clearly labeled deterministic lowest-RVA navigation fallback. Graph and table
  selections stay synchronized; edges come only from retained direct-call, thunk, and import
  relationships, and large binaries receive an explicitly bounded rendering instead of a fabricated
  complete call graph. The workbench uses shared package/export models and renderers with a
  consistent create-new policy for `.resym`, neutral JSON, Markdown, MAP, public-symbol PDB, IDA
  Python, and Ghidra Java artifacts. Windows
  release archives package the static-CRT workbench beside `resymbol.exe`. An off-by-default
  companion console can be enabled or disabled from the running workbench to mirror workbench
  activity and accept typed status, navigation, layout, export, and lifecycle commands without
  giving its I/O thread direct ownership of GUI state. GUI plugin execution remains future work.
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
  filesystem, network, or authority sandboxing. Windows creates each child atomically inside a
  preconfigured Job, explicitly terminates the Job during normal cleanup, retains kill-on-close as
  an abrupt-parent fallback when no out-of-scope process holds a duplicate, restricts inheritance
  to the exact standard-stream handles, verifies membership before returning, and has no
  spawn-then-assign fallback. An active same-account process with sufficient process/handle rights
  can still manipulate ReSymbol or its handles; defending against that actor requires a separate OS
  authority boundary. A hostile POSIX plugin/helper or descendant can still deliberately leave its
  process group or session.
- Added bounded modern MSVC x64 Rev1 RTTI and vftable discovery, including validated stored type
  names, base-class records, virtual-slot targets, vftable names, and attributed function-to-class
  relationships. Base-class arrays may mix the legacy 24-byte descriptor with the 28-byte
  `BCD_HASPCHD` form. A hierarchy link is absent for the legacy form and required for the extended
  form; an extended root must link to its owning hierarchy.
- Added bounded PE32+ x86-64 TLS callback discovery from optional-header data-directory entry 9.
  ReSymbol requires the declared directory to be fully file-backed and contain at least the
  40-byte PE32+ TLS-directory prefix, converts `AddressOfCallbacks` and callback preferred-image
  VAs to RVAs with checked image bounds, retains ordered entries including duplicates, and requires
  every retained eight-byte slot and executable endpoint to be file-backed. It retains at most
  4,096 callbacks, then probes one more slot: null means the 4,096-entry table is complete, while
  nonzero records an explicit partial
  flag without retaining the extra entry. Each retained slot produces an exact `FunctionEntry`
  claim with `pe-tls-callback` provenance and distinct slot/index evidence, including when callback
  target RVAs repeat. Retained targets seed only the existing one-instruction thunk check, not a
  callback-body sweep. ReSymbol never loads or executes the image.
- Added bounded modern PE32+ delay-import discovery from optional-header data-directory entry 13.
  ReSymbol accepts only ordered, null-terminated 32-byte RVA-form descriptors with all-zero declared
  tail padding whose attributes are
  exactly `dlattrRva` (`1`), explicitly rejecting the legacy VA form and unknown bits despite the
  generic PE table's ambiguity. The ordered package inventory retains the DLL name, descriptor RVA
  and exact attributes value, name/HMOD/IAT/INT base RVAs, optional BIAT/UIAT base RVAs, per-entry
  lookup/IAT RVAs and hints/names or ordinals, and the timestamp, but not raw array contents.
  INT/IAT and optional BIAT/UIAT arrays must be pairwise
  disjoint. Each present BIAT or UIAT must have a zero slot at the paired INT/IAT entry count; BIAT
  payload values before that slot are otherwise opaque, including whether any is zero, while the
  complete UIAT must byte-match the original delay IAT. Every consumed descriptor, import table,
  and string must be fully file-backed. The nonzero HMOD RVA instead must map an
  eight-byte range wholly inside one section, but that storage may be zero-filled virtual data;
  initial contents and section permissions remain opaque. Conventional and delay imports share
  limits of 4,096 libraries,
  65,536 symbols, and 16 MiB of names; malformed input or any exhausted limit is a hard analysis
  error rather than a partial result. Delay-IAT slots join conventional IAT slots for existing
  `ImportIat` calls and thunks and take precedence over read-only function-pointer fallback, while
  the richer ordered inventory remains package-only.
- Added bounded PE32+ load-config GuardCF recovery from optional-header data-directory entry 10. A
  present load-config directory must be fully file-backed, expose an internal structure size from 4
  through the directory size, and declare at least 148 bytes before ReSymbol consumes the PE32+
  GuardCF fields. A count above 262,144, an oversized table, or any malformed record is a hard
  analysis error; accepted GFIDS tables are retained in full, must be fully file-backed and
  disjoint from the load-config directory, and must contain strictly increasing unique executable
  RVAs. The disjointness requirement is an explicit ReSymbol hardening policy. Record stride is
  `4 + n`, with `n` selected by the high `GuardFlags` nibble; all `n` metadata bytes are retained
  exactly and otherwise treated as opaque. Every structurally valid record, including one marked
  `IMAGE_GUARD_FLAG_FID_SUPPRESSED`, `IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED`, or both, emits the
  existing `FunctionEntry` claim and joins initial one-instruction thunk seeding. FID suppression
  describes CFG eligibility rather than whether the target is a function; export-suppressed RVAs
  must be 16-byte aligned. Claim evidence retains both suppression booleans.
- Added bounded recovery of the later PE32+ Guard address-taken IAT, long-jump, and
  EH-continuation tables. Their load-config field thresholds are 176, 192, and 280 bytes;
  nonempty tables require the corresponding `GuardFlags` presence bit, while a set bit with zero
  fields remains a supported empty table. GIAT, long-jump, and EH-continuation records use the
  GFIDS `4 + n` stride and require every reserved metadata byte to be zero. GIAT entries must name
  exact parsed conventional or delay-IAT slots; long-jump and EH-continuation RVAs must be strictly increasing,
  unique, file-backed executable addresses. Each table has a 262,144-entry hard cap, must be fully
  backed and disjoint from the load-config directory, and all nonempty Guard tables must be
  pairwise disjoint. These package/plugin-visible inventories do not create function claims or
  thunk seeds because continuation/landing addresses are not necessarily function starts.
- Expanded the source-available, byte-reproducible MSVC x64 fixture corpus to four PE inputs:
  optimized and unoptimized builds, each with and without CodeView metadata. The existing optimized
  filenames remain stable, exact hashes bind every checked-in executable, and the semantic oracle
  shares portable expectations while keeping layout-sensitive requirements specific to each
  optimization profile. These fixtures are repository/source test data rather than portable runtime
  archive contents; their byte-variable full PDBs remain local build outputs.
- Added focused synthetic RTTI fixtures for all-legacy and mixed base-class descriptor hierarchies
  alongside the existing extended-form coverage, without regenerating or changing the hashes of
  the four checked-in MSVC corpus binaries.
- Added focused synthetic TLS-directory fixtures for ordered and duplicate callbacks, malformed
  preferred VAs and backing, the 4,096-entry retention boundary, partial scans, graph provenance,
  and callback-seeded thunks without changing the four checked-in MSVC corpus binaries or hashes.
- Added focused synthetic delay-import fixtures for named and ordinal entries, optional BIAT/UIAT
  arrays, malformed modern descriptors and tail padding, cross-family IAT collisions and shared
  library/symbol/name budgets, package compatibility, and delay-IAT
  control flow without changing the four checked-in MSVC corpus binaries, semantic oracle, or
  hashes.
- Added focused synthetic load-config/GuardCF fixtures covering structure-size bounds, table
  presence and backing, strictly sorted unique GFIDS, record-stride metadata, suppression policy,
  graph claims, and thunk seeds without changing the checked-in MSVC corpus or its hashes.
- Added focused synthetic Guard target-table fixtures covering versioned empty tables, short
  structures, flags and table/count consistency, caps before mapping, full backing and overlap,
  reserved metadata, exact IAT membership, executable continuation targets, sorted uniqueness,
  schema markers, legacy defaults, and deserialization tamper rejection.
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
  initialized PE data. Parsed conventional and delay IAT slots retain precedence; accepted non-IAT slots resolve one
  preferred-image VA hop to executable code and preserve both `slot_rva` and the endpoint. Pointer
  calls also retain a paired same-site data reference, while pointer thunks preserve control-flow
  provenance without inventing a data-reference record outside the instruction sweep. Focused
  synthetic PE fixtures cover the encodings, rejection policy, caps, packages, and exports without
  regenerating or changing the hashes of the four checked-in MSVC corpus binaries.
- Added bounded transitive recovery of exact executable thunk chains. Existing metadata, export,
  direct-call, and RTTI candidates are checked first in deterministic RVA order; internal endpoints
  of retained thunks form the next sorted layer until the causal closure is exhausted. Every
  instruction keeps its exact hop (`A -> B`, `B -> C`) rather than being flattened to a terminal
  endpoint. A global visited set terminates connected cycles while retaining their exact edges, and
  persisted disconnected thunk cycles remain invalid. This follows executable thunk endpoints, not
  pointer-to-pointer slot chains: every supported non-IAT pointer operand is still dereferenced
  exactly once. Focused synthetic PE fixtures cover direct, pointer-backed, cyclic, and
  disconnected chains without changing the four checked-in MSVC corpus binaries or their hashes.
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
- Added typed, deterministic export-loss reporting for JSON, Markdown, MAP, PDB, IDAPython, and
  Ghidra Java. Stable machine codes aggregate bounded occurrence counts without per-symbol detail;
  MAP/PDB and debugger-script reports share their writers' exact selection, collision, and function
  size rules. `resymbol export --fail-on-loss` rejects neutral-warning or target-loss occurrences
  before rendering and publication, while every successful export prints both totals.
- Added optional `resymbol inspect PACKAGE --binary EXACT_ORIGINAL_BINARY` verification for package
  schemas 1 through 13. Inspection validates the package first, then requires the supplied file's
  exact size and SHA-256 to match before any inspection output reaches stdout. Failures report on
  stderr. Human summaries add
  `source binary: <canonical-path>` and `identity gate: matched`; `--json` remains pure package JSON.
  The check neither reruns analysis nor rewrites the package or binary.
- Added Windows PDB compatibility CI covering native `llvm-pdbutil` stream inspection, its
  DIA-backed view, and a direct DIA probe for exact GUID+age validation and public function/global
  enumeration.
- Added `ResymPackage::try_map_payload` so applications can migrate a payload after validating and
  preserving its package envelope.

### Changed

- Bumped the debugger wire and typed-command protocol to 1.4. Debug attaches now require one
  correlated, validated `LiveTargetBinding` that matches the exact PID, trusted process-start key,
  and main-module binary identity retained by the active open command. It carries the actual ASLR
  image base and checked PE `SizeOfImage` range for safe static-RVA translation; zero, overflowing,
  out-of-image, stale, duplicate, and replacement bindings fail closed, while terminal/failure
  lifecycle state invalidates accepted evidence. Step Into, Step Over, and Step Out now have
  independent complete-report capability statuses instead of inheriting one coarse execution bit.
  Unsolicited stop/exit batches are staged and validated in full before reducer/cursor commit, so a
  later hostile frame cannot expose an accepted prefix. Legacy 1.3 and earlier peers are rejected.
  These are provider/client contracts only; no process-executing Windows provider is shipped.
- Bumped the debugger wire and typed-command protocol to 1.3. A sandboxed launch now carries the
  exact created PID, trusted process-start key, and executable identity through
  `AwaitingAttestation`, provider attestation, and cleanup. The reducer retains both the created
  identity and the accepted attestation. Launch failures now carry explicit `NotCreated` or exact
  `Created` process evidence bound from retained reducer state; binding an unknown outcome fails.
  Processless cleanup requires a retained `NotCreated` result instead of inferring success from a
  missing state transition. A received failure can only confirm a controller-retained outcome and
  cannot establish `NotCreated` or authorize processless cleanup by itself. Missing, mismatched, and
  replayed evidence fails closed, and the wire rejects legacy 1.2 negotiation because that schema
  lacks the required process fields. These remain contracts for a future execution provider; no
  process-executing sandbox provider is shipped.
- Debugger capability probes must now report every protocol capability exactly once. Unsupported
  capabilities remain explicit typed `Unavailable` entries instead of becoming ambiguous through
  omission; duplicate and partial reports fail protocol validation.
- Hardened x64 exception metadata ingestion and validated package deserialization. ReSymbol now
  preserves `.pdata` source order only when `RUNTIME_FUNCTION` begin RVAs are strictly increasing
  and half-open ranges do not overlap; adjacency remains valid and the table is never silently
  sorted. Legacy packages containing duplicate, decreasing, partial-overlap, or contained ranges
  can now fail validation instead of retaining ambiguous function-boundary evidence.
- Routed CLI analysis and PDB source input through the application service's regular-file,
  exact-length binary reader. Its 1 GiB default gate checks size before fallible allocation, probes
  one byte beyond the declared length, and hashes the same retained snapshot used for identity-bound
  PDB rendering.
- Protocol 1.3 retains and extends the exact sandbox-failure binding introduced in 1.2. Failures
  bind the exact session, provisioning epoch, policy digest, provider, and launch binary/helper or inherited
  process/mode context. The controller validates an exact command-stage-kind-phase matrix before
  rollback or retaining failed ownership. Cleanup providers can additionally report a bounded
  `CleanupAttemptFailed` event with an exact incomplete receipt and advisory retryability; only a
  later exact complete `Closed` receipt verifies cleanup and permits release.
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
- New `.resym` analyses use package schema 13. Schema 4 introduced the `function-pointer`
  control-flow target, which persists both the read-only slot RVA and resolved function RVA and
  requires a paired same-site slot data reference for a direct call but not for a pointer thunk.
  Schema 5 preserves a legacy 24-byte RTTI base-class descriptor with a null
  `class_hierarchy_descriptor_rva`; the 28-byte `BCD_HASPCHD` form retains its validated nonzero
  hierarchy link. Schema 6 permits persisted thunk sources reached through the deterministic
  transitive thunk closure while retaining the same exact per-hop relationship shape. Schema 7
  adds TLS-directory identity, callback-table RVA, ordered callback records, and the independent
  callback-scan partial flag. Schema 8 adds the separate ordered modern delay-import directory and
  inventory. Schema 9 adds load-config size and GuardFlags state plus the ordered GFIDS inventory.
  Schema 10 adds the ordered Guard address-taken IAT, long-jump, and EH-continuation inventories.
  Schema 11 adds checked storage RVAs for the security cookie and the GuardCF check/dispatch
  function-pointer slots. Schema 12 adds checked XFG and CastGuard storage anchors, and schema 13
  adds the checked GuardMemcpy function-pointer-slot anchor. Their versioned objects are serialized
  even when empty;
  each version-introducing inventory or object remains an explicit anti-relabel compatibility marker.
- The debugger-neutral JSON projection now uses schema 6. Schema 4 added attributed string and
  data-reference arrays to schema 3's entry attribution and control-flow relationships; schema 5
  added `referenced_string_rva` correlation; and schema 6 adds explicit `function-pointer` targets.
  A retained pointer target losslessly preserves its slot and resolved endpoint. If deterministic
  same-site data-reference reduction selects a conflicting noncompanion reference, the projection
  omits the pointer call with an `unsupported-assertion` warning instead of flattening it.
- `resymbol analyze` and `resymbol inspect` report recovered string, data-reference, direct-call,
  thunk, security-cookie and GuardCF pointer-slot anchors, GuardCF record/function-candidate and
  FID-/export-suppressed, Guard address-taken IAT,
  long-jump, EH-continuation, TLS-callback, and delay-import library/symbol
  counts plus applicable partial-recovery status for result families that support partial output.
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

- The CLI can inspect and export package schemas 1 through 13 through explicit, validated in-memory
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
  resolution. Schema 4 retains those pointer relationships but predates legacy 24-byte base-class
  descriptor recovery. Schema 5 includes that RTTI recovery but predates transitive executable
  thunk-chain discovery. Schema 6 includes that closure but predates TLS callback discovery and
  callback-based thunk seeding. Schema 7 includes TLS callback discovery but predates modern
  delay-import recovery. Schema 8 includes delay imports but predates load-config GuardCF recovery.
  Schema 9 includes GuardCF functions but predates the Guard address-taken IAT, long-jump, and
  EH-continuation inventories. Schema 10 includes those inventories but predates checked
  security-cookie and GuardCF check/dispatch pointer-slot storage RVAs.
  Schemas 1 through 6 report TLS callback recovery unavailable, schemas 1 through 7 report
  delay-import recovery unavailable, and schemas 1 through 8 report GuardCF recovery unavailable;
  schemas 1 through 9 report modern Guard target inventories unavailable, schemas 1 through 10
  report load-config security anchors unavailable, schemas 1 through 11 report XFG/CastGuard
  anchors unavailable, and schemas 1 through 12 report the GuardMemcpy anchor unavailable. None can
  be synthesized during loading. Reanalyze the exact original binary to create schema 13
  with current recovery. The
  reader rejects schema 2 or 3 envelopes containing schema-4
  function-pointer targets in base relationships,
  symbol graphs, or plugin claims. It also rejects a schema 1-through-4 payload containing an RTTI
  base record whose `class_hierarchy_descriptor_rva` is missing or null instead of accepting
  relabeled schema-5 semantics, and rejects a schema 1-through-5 envelope containing a base thunk
  source that depends on schema-6 transitive endpoint seeding, and rejects schema 1-through-6
  envelopes containing schema-7 TLS callback state or callback-only base thunk seeds. It also
  rejects schema 1-through-7 envelopes containing the exact schema-8 base-analysis `delay_imports`
  inventory key or `directories.delay_imports` directory key. Schemas 8 through 13 require that
  explicit inventory marker, even when empty. Changing only the envelope label is never migration.
  Schemas 1 through 8 also reject schema-9 load-config/GuardCF fields,
  `directories.load_config`, and core `pe-guard-cf-function` claims. Schemas 9 through 13 require
  the explicit `guard_cf_functions` inventory even when empty.
  Schemas 1 through 9 reject schema-10 Guard address-taken IAT, long-jump, and EH-continuation
  table-RVA and inventory fields. Schemas 10 through 13 require all three inventory arrays even
  when empty.
  Schemas 1 through 10 reject the exact schema-11 `load_config_security_anchors` base-analysis key;
  schemas 11 through 13 require that value to be an object even when all anchors are absent. Schemas
  1 through 11 reject the schema-12 `load_config_xfg_anchors` key; schemas 12 and 13 require that
  value to be an object even when all anchors are absent. Schemas 1 through 12 reject the schema-13
  `load_config_guard_memcpy_anchor` key; schema 13 requires an object even when the anchor is absent.
- Package schema 13 and neutral projection schema 6 are independent version domains. Generic
  package readers still require an explicit compatibility range and application-defined payload
  migration to accept an older schema.
- Markdown export is presentation-only and does not change either version domain: new analyses
  continue to use package schema 13 and the neutral projection continues to use schema 6.
- MAP export consumes the current validated session and neutral projection without adding fields to
  package schema 13 or projection schema 6.
- PDB export consumes the same current session and projection plus a byte-backed inspection of the
  exact original PE. It does not add fields to package schema 13 or projection schema 6.
- The external plugin wire remains protocol 1.0. Dual-layout RTTI recovery changes deterministic
  base-analysis/package content but adds no plugin assertion or control-flow target shape.
  Transitive built-in thunk discovery likewise composes existing exact `thunk-target` claims and
  does not add a terminal-target field or change the wire handshake. TLS callback records are an
  additive field in the detached base-analysis JSON exposed by `symbols.read`; they reuse the
  existing `function-entry` assertion and do not change the plugin API, plugin wire, or neutral
  projection schema. Schema 8 delay-import records are another additive `symbols.read` field;
  delay-IAT control flow reuses the existing `import-IAT` target, so the API, WIT/ABI, plugin wire
  1.0 handshake, and projection schema 6 remain unchanged. Schema 9 load-config/GuardCF records are
  likewise additive `symbols.read` state and reuse `function-entry`; they leave the plugin API,
  WIT/ABI, plugin wire 1.0 handshake, and projection schema 6 unchanged.
  Schema 10 Guard target inventories are also additive `symbols.read` state, add no assertion or
  control-flow target shape, and leave those API, wire, and projection versions unchanged.
  Schema 11 load-config security anchors are likewise package-only additive `symbols.read` state;
  they add no claims or thunk seeds and leave those API, wire, and projection versions unchanged.
  Schema 12 XFG/CastGuard anchors and schema 13 GuardMemcpy anchor follow the same package-only
  boundary and likewise leave the plugin API, wire, and projection versions unchanged.
- Managed-plugin execution adds no package-schema field: successful runs and validated claims use
  the existing `AnalysisSession` plugin ledger and claim representation.
- WASM-plugin execution likewise adds no package-schema field. It uses the existing plugin ledger,
  claim validation, and exact binary/artifact identity domains; the WIT package remains
  `resymbol:plugin@0.1.0`.

### Safety and limits

- Static patch plans retain at most 1,024 edits, 4 KiB per general edit, 15 bytes per x86
  instruction-to-NOP edit, and 1 MiB of aggregate replacement bytes. They accept only equal-length
  changes to one fully file-backed executable PE section; instruction-to-NOP edits additionally
  decode as one exact complete x86-64 instruction. Application computes the fresh complete identity
  once from the exact source, validates a strict source-byte-derived layout and every mapping,
  checks every expected byte, and mutates only a newly allocated output buffer. Same-directory
  staged publication is no-clobber and a success receipt additionally requires a reopened
  destination with the expected exact size and SHA-256; it does not make a patched executable
  trusted, signed, checksum-correct, safe to run, semantically valid, or necessarily power-loss
  durable on Windows.
- macOS executable-plugin containment now observes direct-child exit with a `kqueue` process filter,
  terminates the still-stable process group, and only then reaps the leader. XNU registration
  races resolve through an already-exited path that also kills the group before collecting status,
  preventing process-group identifier reuse from redirecting cleanup at an unrelated group.
- Live host launch/attach contracts no longer accept caller-created acknowledgement values or a
  claimed sandbox owner session. A trusted session worker must pre-register a bounded, one-use
  256-bit lease for the exact launch binary or PID/start-key/image/mode attach identity; sandbox-owned
  attaches additionally bind provider, policy digest, and provisioning epoch. Attestation and
  cleanup receipts carry that fresh epoch, rejecting evidence replay from an otherwise identical
  earlier provisioning instance. These remain contracts for future providers, not shipped process
  execution or containment. The debugger-host typed-command protocol is now 1.4, so legacy 1.3 and
  older payload shapes fail typed validation before dispatch instead of being interpreted ambiguously.
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
  and 4,096 retained thunks. Initial thunk seeds are processed before sorted endpoint layers, and
  a candidate is decoded at most once across connected cycles. Exhaustion retains deterministic
  valid exact hops and marks the applicable relationship sets partial. Neutral projection
  validation applies separate, larger collection caps.
- Built-in string recovery scans at most 64 MiB, retains at most 16,384 literals and 4 MiB of UTF-8
  text in aggregate, and caps each exact value at 4 KiB UTF-8 and 4 KiB encoded data including its
  terminator. Reaching a limit never publishes a truncated prefix and records the scan as partial.
- Internal targets covered by known runtime-function metadata are allowed only when their RVA
  matches a recorded runtime-function begin or a retained GuardCF function
  start; every other interior endpoint remains suppressed regardless of another seed source. A call
  to its own next instruction is not promoted to a function target. Overlapping runtime-function
  ranges may be traversed and charged to decoder budgets separately.
- Read-only function-pointer calls and thunks are accepted only from exact supported RIP-relative
  encodings. Their non-IAT slot must be eight fully backed bytes of initialized, readable,
  non-writable, non-executable data, and its preferred-image VA must resolve in one hop to
  file-backed executable code. A call is retained only with its exact paired data reference, so
  exhausting the data-reference cap also marks pointer-call recovery partial. A pointer thunk
  preserves the slot and endpoint without requiring a data-reference record. If that endpoint is
  itself an exact supported thunk, it may seed the next executable thunk layer, but the data slot
  is never followed as a pointer chain.
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
