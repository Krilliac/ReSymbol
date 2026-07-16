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

- safe, bounded ingestion of PE32+ x86-64 binaries, including image metadata, sections,
  conventional imports, modern RVA-form delay imports, exports, forwarded exports, x64
  exception-directory (`RUNTIME_FUNCTION`) records, ordered TLS-directory callback entries, and
  load-config GuardCF function, address-taken IAT, long-jump, and EH-continuation tables;
- bounded discovery of modern MSVC x64 Rev1 RTTI and vftables from file-backed compiler metadata,
  including both legacy 24-byte and `BCD_HASPCHD` 28-byte base-class descriptors, validated
  class/type names, and contiguous executable slot candidates;
- bounded pure-Rust x86-64 decoding inside fully file-backed `RUNTIME_FUNCTION` ranges, recovering
  supported direct calls to internal executable targets, exact parsed conventional or delay
  import-address-table slots,
  or targets resolved one hop through exact read-only in-image function-pointer slots;
  one-instruction thunks to internal targets, exact parsed conventional or delay import slots, or
  one-hop read-only function-pointer targets, including bounded transitive chains of exact
  executable thunk hops;
  and exact supported RIP-relative references into eligible data;
- bounded recovery of exact NUL-terminated ASCII and UTF-16LE strings from file-backed,
  initialized, readable, non-executable sections, including writable data;
- a source-available, byte-reproducible four-artifact MSVC x64 PE fixture matrix spanning optimized
  and unoptimized builds, each with and without CodeView metadata, plus exact hashes and a
  profile-sensitive semantic oracle covering imports, exports, unwind functions, direct calls,
  internal/import thunks, strings, data references, and modern RTTI/vftables; focused synthetic PE
  fixtures cover read-only pointer control flow, dual RTTI descriptor layouts, transitive thunk
  chains, bounded TLS callback discovery, modern delay-load imports, GuardCF function tables, and
  modern Guard address-taken IAT, long-jump, and EH-continuation inventories without changing the
  four corpus binaries, their hashes, or their oracle; these repository/source fixtures are analyzer
  test data and are not bundled in portable runtime archives;
- conservative symbol-graph generation from exact export names, metadata-backed function
  boundaries, entry-point, GuardCF, and TLS-callback function-entry candidates, direct calls, thunks,
  recovered strings, and data references, with SHA-256 binary identity, evidence, provenance,
  confidence, and claim validation;
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
exact RIP-relative `FF 15 disp32` and redundant-`REX.W` `48 FF 15 disp32` calls to parsed
conventional or delay IAT slots; and the same two call encodings through a complete eight-byte
pointer slot in readable, initialized, non-writable, non-executable data. Parsed
conventional/delay IAT membership takes precedence. Otherwise
the slot's little-endian preferred-image VA is resolved exactly once to a file-backed executable
target; pointer-to-pointer slot chains and writable slots remain unsupported. A resolved pointer
call records its slot and endpoint explicitly and retains the same instruction as a paired data
reference to the slot. Seeded `E9` and `EB` internal thunks remain supported. Exact RIP-relative
`FF 25 disp32` and redundant-`REX.W` `48 FF 25 disp32` thunks use the same IAT-first policy: a parsed
conventional or delay IAT slot remains
an import target, while any other accepted slot resolves one read-only pointer hop to executable
code. A pointer thunk records its slot and endpoint without requiring a paired data reference. The
built-in pass checks its original deterministic thunk seeds first, including every retained GuardCF
function and retained TLS callback endpoint, then follows internal endpoints of retained thunks in
sorted hop layers. It
preserves each exact relationship (`A -> B`, `B -> C`)
instead of rewriting the first thunk or a direct call to a terminal endpoint. A global visited set
terminates connected cycles while retaining their exact edges; a disconnected persisted cycle is
not a valid causal chain. This executable-thunk closure does not follow pointer-to-pointer data:
each non-IAT slot is still dereferenced exactly once. The pass discovers at most 262,144 block
starts and retains at most 8,192 direct calls, 32,768 supported RIP-relative data references, and
4,096 thunks. Reaching a shared decode or thunk-retention limit preserves deterministic valid hops
and marks code recovery partial. These are heuristic-confidence findings:
reachable embedded data can still decode as instructions, while an invalid encoding or unsupported
branch can omit later relationships on that path. An internal target covered by known
`RUNTIME_FUNCTION` metadata is suppressed unless its RVA matches an authoritative metadata function
start: a runtime-function begin or retained GuardCF function start. The pass does
not persist a basic-block graph, infer erased identifiers, invent names or
sizes, recover register-indirect
control flow, or claim a complete call graph. A separate bounded pass retains exact, fully
terminated printable ASCII and valid UTF-16LE strings from eligible data, with deterministic
overlap handling; it does not publish truncated prefixes or infer a variable type from a literal.
TLS callback discovery reads optional-header data-directory entry 9, requires its declared range
to be fully file-backed and contain at least the 40-byte PE32+ TLS-directory prefix, and converts
the preferred-image `AddressOfCallbacks` VA and each retained nonzero callback VA to an RVA with
checked image bounds. It retains callback-table order and duplicate entries, requires every
eight-byte slot it reads to be file-backed and every retained callback endpoint to be file-backed
executable data, and retains at most 4,096 callbacks. After the 4,096th entry it probes one
additional slot: a null value proves a complete table, while a nonzero value records an explicit
partial flag without retaining or resolving that extra entry as a callback endpoint.
Each retained table slot becomes an exact `FunctionEntry` claim with `pe-tls-callback` provenance
and `callback_slot_rva` plus `table_index` evidence, so duplicate target RVAs remain separate
claims. Retained callback targets also join the deterministic one-instruction thunk seeds; this
does not turn callback bodies into another instruction sweep. ReSymbol does not execute callbacks
or infer their names or extents.

GuardCF discovery reads PE32+ optional-header data-directory entry 10 as the load-config directory.
A present directory must be fully file-backed and contain its four-byte internal structure-size
field. That internal size must be between 4 and the data-directory size; only a size of at least
148 bytes exposes the PE32+ `GuardCFFunctionTable`, `GuardCFFunctionCount`, and `GuardFlags` fields.
The table VA and count must be both zero or both nonzero, and a nonzero pair requires
`IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT`. ReSymbol converts the preferred-image table VA to a
checked RVA. A count above 262,144, an oversized table, or any malformed record is a hard analysis
error; accepted tables are retained in full rather than truncated to a prefix. Records are `4 + n`
bytes, where `n` is selected by the high `GuardFlags` nibble.
The table must be fully file-backed, disjoint from the load-config directory, and contain strictly
increasing unique RVAs whose targets begin in file-backed executable data. The disjointness rule is
a ReSymbol hardening policy rather than a requirement stated by the PE format. ReSymbol preserves
each record's `n` metadata bytes exactly and opaquely. Every structurally valid record, including a
record marked `IMAGE_GUARD_FLAG_FID_SUPPRESSED`, `IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED`, or both,
produces an exact `FunctionEntry` claim and joins the initial one-instruction thunk seeds. FID
suppression describes CFG eligibility rather than whether the target is a function;
export-suppressed targets must be 16-byte aligned. Claim evidence records both suppression booleans
alongside the table index and raw metadata. ReSymbol does not sweep a GuardCF
function body or infer a name or extent from GFIDS alone.

Later PE32+ load-config versions expose three additional bounded Guard inventories. An internal size
of at least 176 bytes exposes `GuardAddressTakenIatEntryTable` and its count, at least 192 bytes
exposes `GuardLongJumpTargetTable` and its count, and at least 280 bytes exposes
`GuardEHContinuationTable` and its count. A nonzero table/count pair requires its corresponding
presence flag; a set flag with a zero pair is accepted as a versioned empty table. Address-taken IAT,
long-jump, and EH-continuation records use the same `4 + n` stride selected by `GuardFlags`. Their
`n` metadata bytes are reserved and must be zero. Address-taken IAT RVAs must name exact parsed
conventional or delay IAT slots. Long-jump and EH-continuation RVAs must be strictly increasing,
unique, and begin in file-backed executable data. Each table is capped at 262,144 entries and must be fully
file-backed, disjoint from the declared load-config range, and pairwise disjoint from every other
nonempty Guard table. These three inventories are retained for packages and `symbols.read` plugins;
because they identify import slots or valid continuation/landing addresses rather than proven
function starts, they create no `FunctionEntry` claims and do not seed thunk recovery.

Modern PE32+ delay-import discovery reads optional-header data-directory entry 13 as ordered
32-byte descriptors followed by an all-zero descriptor; the rest of the declared range must be
all-zero padding. ReSymbol accepts only the RVA-based
`dlattrRva` form whose attributes value is exactly `1`; it deliberately rejects the legacy VA form,
zero, and unknown attribute bits despite ambiguity in the generic PE table documentation. Every
active descriptor must provide nonzero name, module-handle (HMOD), delay-IAT, and delay-INT RVAs.
The name and import tables must be fully file-backed. The HMOD RVA instead needs an eight-byte
storage range wholly mapped inside one section; that range may be zero-filled virtual data rather
than file-backed. Its initial contents and section permissions remain opaque to this static-analysis
slice.
The paired 64-bit INT/IAT arrays must be fully backed and end together with null entries. INT, IAT,
and each present bound-IAT (BIAT) or unload-IAT (UIAT) must be pairwise disjoint. Each present BIAT
or UIAT must have a zero slot at the paired INT/IAT entry count. BIAT payload values before that
required slot remain opaque, including whether any is zero, while the complete UIAT must byte-match
the original delay IAT. Names, hints, and ordinals are decoded from the INT. The separate package
inventory preserves descriptor and entry order, the DLL name, descriptor RVA and exact attributes
value, name/HMOD/IAT/INT base RVAs, optional BIAT/UIAT base RVAs, each entry's lookup/IAT RVAs and
hint/name or ordinal, and the timestamp;
it does not serialize raw INT/IAT/BIAT/UIAT array contents. Conventional and delay imports share
aggregate limits of 4,096 libraries, 65,536 symbols, and 16 MiB of name bytes. A
malformed record or exceeded limit fails analysis; delay-import parsing never publishes a partial
prefix. Parsed delay-IAT slots join conventional IAT slots for control-flow recovery, so an exact
call or thunk remains the existing `ImportIat` target and wins before read-only function-pointer
fallback. The richer delay-import inventory remains package-only.
The neutral projection correlates a data-reference target with a retained string only at the string
start or within its encoded content. It excludes the NUL terminator and requires UTF-16LE interior
targets to be code-unit aligned. An absent correlation means only that no retained projected string
matched; it is not proof that the target bytes cannot contain a string.
Its RTTI slice recovers names and relationships actually present in validated compiler metadata.
Modern MSVC x64 Rev1 base-class arrays may mix the legacy 24-byte descriptor, which has no `pCHD`
field, with the 28-byte form, whose `BCD_HASPCHD` bit requires a valid class-hierarchy RVA.
The root descriptor is required to point back to its owning hierarchy only when that field exists.
Candidate scanning and the vftable/back-pointer, COL, CHD, BCA, BCD, and any referenced nested-CHD
records remain in file-backed readable, read-only initialized non-executable data. Referenced
TypeDescriptors may also occupy file-backed readable initialized non-executable data marked
writable, including normal `.data`; writable sections are never candidate-scanned. The current
external-process host supports one-shot analysis requests; its interactive binary reads are
reserved for a later protocol revision. The native host instead
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
resymbol inspect application.resym --binary application.exe
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

Pass `inspect --binary EXACT_ORIGINAL_BINARY` to add an optional byte-identity gate. Before printing
inspection data to stdout, ReSymbol validates the package and requires the supplied file's exact
size and SHA-256 to match. Failures remain actionable on stderr. Human output then includes
`source binary: <canonical-path>` and `identity gate: matched`.
With `--json`, stdout remains the pure validated package JSON and does not gain those status lines.
The gate works for every supported package schema, 1 through 10; it does not rerun analysis,
reconstruct missing legacy results, or rewrite either file.

New analyses write package schema 10. `inspect` and `export` also accept schemas 1 through 9 through
validated in-memory compatibility paths. Migration does not rewrite the source package or rerun
analysis because `.resym` does not embed the executable bytes. Schema 1 therefore has no available
recovered calls, thunks, strings, or data references. Schema 2 retains calls and thunks but predates
strings and data references. Schema 3 retains those string/data records, but schemas 2 and 3 both
predate read-only function-pointer call and thunk resolution; schema 4 records that control flow.
Schemas 1 through 4 all predate recovery of legacy 24-byte base-class descriptors; schema 5 records
that RTTI form but predates transitive executable thunk-chain discovery. Schema 6 records that
thunk closure but predates TLS callback discovery and callback-based thunk seeding. Schema 7
records TLS callbacks but predates modern delay-import recovery. Schema 8 records delay imports
but predates load-config GuardCF recovery. Schema 9 records GuardCF functions but predates the Guard
address-taken IAT, long-jump, and EH-continuation inventories. Schemas 2 through 9 keep their
already-recorded direct calls and thunks, but loading cannot synthesize a later result family. TLS
callback recovery is unavailable for every schema 1-through-6 package, delay-import recovery is
unavailable for every schema 1-through-7 package, and GuardCF recovery is unavailable for every
schema 1-through-8 package. The modern Guard target inventories are unavailable for every schema
1-through-9 package. Reanalyze the exact original binary to produce schema 10 with all current
recovery results. A schema 2 or 3 envelope containing a schema-4
`function-pointer` target, or any schema 1-through-4 envelope
containing an RTTI base record whose `class_hierarchy_descriptor_rva` is missing or null, is
rejected rather than treated as a relabeled legacy package. A schema 1-through-5 envelope likewise
cannot contain a base thunk source that is valid only through schema-6 transitive endpoint seeding.
Schemas 1 through 6 likewise cannot contain schema-7 TLS callback records or callback-only base
thunk seeds. Schemas 1 through 7 cannot contain the exact schema-8 base-analysis `delay_imports`
inventory key or `directories.delay_imports` directory key. Schemas 8 through 10 always serialize the
`delay_imports` inventory, including an empty array, and reject a payload missing that marker so a
legacy package cannot be upgraded by relabeling alone.
Schemas 1 through 8 cannot contain schema-9 `load_config_size`, `guard_flags`,
`guard_cf_function_table_rva`, or `guard_cf_functions` fields, the
`directories.load_config` directory key, or core `pe-guard-cf-function` claims. Conversely, schemas
9 and 10 always serialize the `guard_cf_functions` inventory, including an empty array, and reject a
payload missing that marker so a schema-8 package cannot be upgraded by relabeling alone.
Schemas 1 through 9 cannot contain any schema-10 Guard address-taken IAT, long-jump, or
EH-continuation table-RVA or inventory field. Schema 10 always serializes
`guard_address_taken_iat_entries`, `guard_long_jump_targets`, and
`guard_eh_continuation_targets`, including empty arrays, and rejects a payload missing any marker.

TLS callback fields were introduced in package schema 7's deterministic base analysis; package
schema 8 adds the separate ordered delay-import directory and inventory, package schema 9 adds
load-config and GuardCF state, and package schema 10 adds the three modern Guard target inventories.
The independently
versioned neutral projection remains schema 6, and the plugin API and external wire handshake
remain unchanged. A plugin granted `symbols.read` can observe these additive result families in its
base-analysis JSON; a plugin without that permission still receives no base analysis.

The `analyze` and `inspect` summaries report recovered strings, data references, direct calls,
thunks, GuardCF record/function-candidate totals and FID-/export-suppressed counts, Guard
address-taken IAT entries, long-jump targets, EH-continuation targets, TLS callbacks, and delay-import
libraries/symbols as well as discovered MSVC RTTI vftables,
unique types, base-class
records, and virtual slots. If a fixed string, data-reference, control-flow, TLS-callback, or RTTI
discovery budget is reached, the corresponding summary prints a `partial` status; the valid
deterministic results remain available and the package records the truncation explicitly.

The Markdown output is a deterministic, bounded presentation report for people to review. It is
not a stable interchange format; integrations should consume the neutral JSON projection instead.
Without `--output`, it is written as `application.symbols.md` beside the package. Package schema 10
is used by new analyses, export also accepts package schemas 1 through 9 through validated
compatibility paths, and neutral projection schema 6 remains unchanged by this presentation-only
format. Export does not rewrite the source package.

The PE-only `map` format writes deterministic Microsoft-linker-style text to `application.map` by
default for tools that support that format. It maps selected names to one-based PE
`section:offset` values and preferred-image-base-plus-RVA addresses. Its semicolon-prefixed exact
SHA-256 and file-size comments are informational: a MAP file cannot check the binary loaded by a
consumer, so compare the executable with the recorded identity before using the symbols. MAP adds
no fields to package schema 10 or neutral projection schema 6, and it does not rewrite legacy source
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
