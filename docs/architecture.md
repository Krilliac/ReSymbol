# ReSymbol architecture

This document records the intended architecture and the invariants that new components should
preserve. ReSymbol is in early development; sections marked as design describe the target system,
not necessarily behavior implemented in the current checkout.

The current implementation covers bounded PE32+ x86-64 ingestion, including ordered TLS callback,
load-config GuardCF and modern Guard target-table inventories, checked security/XFG/CastGuard/GuardMemcpy
storage anchors, and modern RVA-form delay-import
discovery, a conservative metadata-derived
symbol graph, modern
MSVC x64 Rev1 RTTI/vftable
discovery, canonical JSON `.resym` packages, plugin
discovery/contracts, a no-WASI WebAssembly Component Model host, and trusted external-process,
native C/C++, and managed/.NET analysis runtimes. It also includes a validated, debugger-neutral
export projection, deterministic Microsoft-linker-style MAP output, an exact-RSDS public-symbol PDB
writer, and conservative standalone import-script generators
for IDA and Ghidra. A first Windows-first workbench slice now provides background core analysis,
durable exact-name review, bounded graph navigation, static address/protection inspection,
non-executing debugger/sandbox readiness, and a constrained shared-model export path. Broader
disassembly-assisted discovery, matching, semantic inference, live debugger bridges, richer PDB and
DWARF output, bulk review, and the rest of the workbench design remain future work.

## Goals

ReSymbol should:

- reconstruct useful symbol and type information from evidence left in compiled programs;
- preserve the difference between observed facts, structural matches, semantic inferences, and
  human review;
- support independent analyzers, matchers, symbol sources, inference providers, and exporters;
- run as a portable application without making users assemble a compiler toolchain;
- survive malformed binaries and unhealthy plugins without corrupting an analysis; and
- produce reproducible, portable results that are not tied to one disassembler or debugger.

ReSymbol cannot guarantee recovery of original source identifiers, filenames, line tables, or
types after those details have been removed. Useful reconstruction and exact recovery are different
claims and must remain visibly different in the data model and UI.

## System overview

```mermaid
flowchart TD
    B["Binary and related evidence"] --> I["Ingestion and identity"]
    I --> A["Deterministic base analysis"]
    A --> S["AnalysisSession"]
    P["Plugin hosts"] --> C["Validated plugin runs and claims"]
    C --> S
    S --> R["Validation and reconciliation"]
    R --> G["Canonical symbol graph"]
    G --> E["Validated export projection"]
    E --> X["JSON and tool-specific writers"]
    S --> K["Portable analysis package"]
```

The Rust application owns identity, canonical state, validation, permissions, transactions, and
plugin lifecycle. Extensions perform bounded work through versioned contracts. They submit claims
and evidence; they do not receive an unrestricted mutable reference to the graph.

## Processing stages

### 1. Ingestion and binary identity

The ingestion layer is responsible for:

- cryptographic file identity and format detection;
- architecture, endianness, image base, section, and address-space normalization;
- bounds-checked access to binary regions;
- recording build identifiers when the format exposes them; and
- linking optional related evidence such as another build, an existing symbol file, or a user
  annotation set.

All downstream records use canonical address concepts rather than assuming that file offsets,
virtual addresses, and relative virtual addresses are interchangeable.

### 2. Deterministic analysis

Deterministic analyzers extract information that can be traced directly to the input, including
imports, exports, executable ranges, unwind metadata, strings, cross-references, RTTI, vtables,
thunks, and candidate function boundaries. A finding can still be uncertain, but its uncertainty
must derive from a documented algorithm rather than being silently promoted to fact.

Analysis should be incremental. A plugin that resolves RTTI should not require the user to rerun an
unrelated signature index, and removing a plugin's results should not require rebuilding claims that
have no dependency on that plugin.

The implemented slice extracts PE image/section metadata, conventional and delay imports, exports,
forwarded exports, x64 `RUNTIME_FUNCTION` records, ordered TLS callbacks, load-config GuardCF
function, address-taken IAT, long-jump, and EH-continuation records, bounded exact strings,
supported RIP-relative
data references, bounded direct calls and thunks, and a bounded modern MSVC x64 RTTI/vftable subset
without loading or executing the input. Exact export names, corroborated metadata-backed
boundaries, GuardCF and slot-attributed TLS callback entries, supported decoded function
entries and relationships,
validated string literals, RTTI type/vftable names, and function-to-class relationships from
virtual slots become evidence-bearing graph claims. Broader candidate discovery and unsupported
evidence sources remain planned.

The analyzer is exercised against a checked-in, source-available four-artifact MSVC x64 fixture
matrix. The existing `milestone2-symbolized.exe` and `milestone2-stripped.exe` remain the optimized
pair; `milestone2-unoptimized-symbolized.exe` and `milestone2-unoptimized-stripped.exe` add the
unoptimized pair. Exact SHA-256 values bind every byte-reproducible PE input. A shared semantic
oracle covers imports, exports, unwind functions, calls, internal and import thunks,
ASCII/UTF-16LE strings, data references, and modern RTTI/vftables, while call-site offsets, thunk
shapes, RTTI addresses, and other layout-sensitive requirements remain specific to the optimization
profile. The build script checks repeat PE determinism and keeps the byte-variable
`milestone2-symbolized.pdb` and `milestone2-unoptimized-symbolized.pdb` files as local `target/`
artifacts. The checked-in executables are repository/source analyzer test data, not portable runtime
archive contents.

Read-only function-pointer call and thunk resolution is proven with purpose-built synthetic PE
fixtures for the plain and redundant-`REX.W` encodings, invalid slot/target policy, relationship
caps, and projection behavior. That focused addition did not regenerate the four checked-in MSVC
binaries or change their recorded SHA-256 values.

Transitive executable thunk-chain recovery is likewise proven with focused synthetic PE fixtures,
including exact direct and pointer-backed hops, connected cycles, and disconnected-cycle
rejection. The checked-in four-artifact MSVC corpus and its semantic oracle were not changed to
claim compiler-produced transitive-chain coverage.

PE32+ TLS callback discovery is proven with focused synthetic PE fixtures rather than regenerated
corpus binaries. A present optional-header data-directory entry 9 must expose a fully file-backed
declared range containing at least the 40-byte PE32+ TLS-directory prefix. `AddressOfCallbacks`
and each nonzero callback pointer are preferred-image VAs; checked subtraction converts them to
in-image RVAs. The parser preserves table order and duplicate entries, requires each eight-byte
slot to be fully file-backed and each retained target to begin in file-backed executable data, and
retains at most 4,096 entries. It then probes one additional slot: null proves an exactly capped
table complete, while nonzero records a partial deterministic prefix without retaining that entry.
Graph construction emits one `FunctionEntry` claim per retained slot with `pe-tls-callback`
provenance. The `callback_slot_rva` and `table_index` evidence artifacts keep claims separate when
target RVAs repeat.
The four checked-in MSVC fixture binaries, semantic oracle, and recorded hashes remain unchanged.

PE32+ load-config GuardCF discovery is also proven with focused synthetic fixtures. Optional-header
data-directory entry 10 must be fully file-backed and contain an internal structure size from 4
through the directory size; only an internal size of at least 148 bytes exposes the PE32+
`GuardCFFunctionTable`, `GuardCFFunctionCount`, and `GuardFlags` fields. Counts above 262,144,
oversized tables, structural inconsistencies, and malformed records are hard analysis errors; an
accepted GFIDS table is fully retained, fully file-backed, disjoint from the load-config directory,
and strictly sorted by unique executable target RVA. Disjointness is a ReSymbol hardening policy. Each record has
stride `4 + n`, where `n` comes from the high `GuardFlags` nibble, and the `n` bytes are retained
exactly and treated as opaque. Every structurally valid record, including one marked
`IMAGE_GUARD_FLAG_FID_SUPPRESSED`, `IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED`, or both, emits the existing
`FunctionEntry` claim and joins initial one-instruction thunk seeding. FID suppression describes CFG
eligibility rather than whether the target is a function; export-suppressed RVAs must be 16-byte
aligned. Claims retain both suppression booleans as evidence. The corpus binaries and hashes remain
unchanged.

The later Guard address-taken IAT, long-jump, and EH-continuation tables are covered by the same
synthetic fixture family. Their load-config structure thresholds are 176, 192, and 280 bytes.
Nonempty table/count pairs require their presence flags; GIAT, long-jump, and EH-continuation
records share the GFIDS `4 + n` stride and require zero reserved metadata. GIAT entries must equal
exact parsed conventional or delay-IAT slots. Continuation targets
must be strictly sorted, unique, file-backed executable addresses. Every table has a 262,144-entry
cap and all nonempty Guard tables must be fully backed, disjoint from the load-config directory,
and pairwise disjoint. These inventories are deterministic package/plugin state only: they add no
graph claim and no thunk seed because a valid continuation or landing address is not necessarily a
function start.

The same synthetic fixture family covers checked load-config storage anchors. The earlier
`SecurityCookie`, `GuardCFCheckFunctionPointer`, and `GuardCFDispatchFunctionPointer` fields become
available at internal sizes 96, 120, and 128 bytes. The later `GuardXFGCheckFunctionPointer`,
`GuardXFGDispatchFunctionPointer`, `GuardXFGTableDispatchFunctionPointer`, and
`CastGuardOsDeterminedFailureMode` fields become available at 288, 296, 304, and 312 bytes, and
`GuardMemcpyFunctionPointer` becomes available at 320 bytes. Zero VAs are absent; nonzero
preferred-image VAs become checked RVAs. Each full eight-byte range must occupy
one mapped section, may live in mapped zero-fill, and must be disjoint from the load-config directory
and every other retained anchor across all three families. Headers and cross-section ranges are rejected.
Permissions and initial contents remain opaque, and anchors add neither claims nor thunk seeds.

Modern PE32+ delay-import discovery is likewise proven with focused synthetic fixtures without
regenerating that corpus. Optional-header data-directory entry 13 is a fully file-backed sequence of
32-byte descriptors ending in an all-zero descriptor and then only all-zero declared tail padding.
The parser accepts only the modern RVA form
whose attributes value is exactly `dlattrRva` (`1`) and rejects the legacy VA form, zero, and
unknown bits despite ambiguity in the generic PE table documentation. Each active descriptor has
nonzero name, module-handle (HMOD), delay-IAT, and delay-INT RVAs. HMOD needs an eight-byte range
wholly mapped inside one section but may occupy zero-filled virtual data rather than file-backed
bytes; initial contents and permissions stay opaque. Its paired null-terminated 64-bit INT/IAT
arrays and any nonzero optional bound-IAT (BIAT) or
unload-IAT (UIAT) array must be fully file-backed and pairwise disjoint. Each present BIAT or UIAT
must have a zero slot at the paired INT/IAT entry count. BIAT payload values before that required
slot are otherwise opaque, including whether any is zero, while the complete UIAT must byte-match
the original delay IAT. The deterministic package inventory preserves descriptor and entry order,
the DLL name, descriptor RVA and exact attributes value, name/HMOD/IAT/INT base RVAs, optional
BIAT/UIAT base RVAs, each entry's lookup/IAT RVAs and hint/name or ordinal, and the timestamp. It
does not serialize raw INT/IAT/BIAT/UIAT array contents.

Conventional and delay imports consume shared ceilings of 4,096 libraries, 65,536 symbols, and
16 MiB of names. Structural failure or budget exhaustion rejects the analysis instead of retaining
a partial import prefix. Accepted delay-IAT slots join conventional IAT slots in the existing
control-flow membership set; an exact supported call or thunk becomes `ImportIat` before any
read-only function-pointer fallback. The inventory itself does not create a new graph shape.

The x86-64 decoder is a pure-Rust, bounded control-flow-guided block sweep used only over complete
file-backed executable exception ranges and the first instruction at deterministic thunk seeds.
Each distinct exception range seeds an ordered worklist. Pending supported direct conditional and
unconditional targets within that same range are dequeued by smallest RVA, while permitted
fallthrough continues immediately. Returns, terminal or indirect control flow, invalid
instructions, out-of-range targets, and targets inside a previously decoded instruction stop only
the affected path. The recorded forms include `E8` internal calls; exact RIP-relative
`FF 15 disp32` and `48 FF 15 disp32` calls to parsed conventional or delay IAT slots or one
read-only function-pointer
slot; `E9`/`EB` internal thunks; and exact RIP-relative `FF 25 disp32` or `48 FF 25 disp32` thunks
to parsed conventional or delay IAT slots or one read-only function-pointer slot. Parsed IAT
membership wins before pointer interpretation. A non-IAT slot must be eight fully file-backed bytes in initialized,
readable, non-writable, non-executable data. Its little-endian preferred-image VA is resolved one
hop to a file-backed executable endpoint, and the control-flow target retains both the slot and
endpoint. A pointer call also retains a same-site data reference; a pointer thunk does not require
or invent one. Deterministic metadata, export, call-target, GuardCF, TLS-callback, and RTTI
thunk candidates are processed first in RVA order. A GuardCF or TLS callback endpoint is checked
only as a one-instruction thunk seed, not swept as a function body. Each retained internal thunk
endpoint seeds the next
sorted layer until that causal closure is exhausted. The graph preserves each exact hop instead of
rewriting a direct call
or earlier thunk to a terminal endpoint. A global visited set decodes a candidate once, so connected
cycles retain their exact non-self edges and terminate; persisted disconnected thunk cycles are
invalid. Import-IAT targets stop the executable chain. This endpoint traversal does not follow
pointer-to-pointer data: every non-IAT slot remains a single dereference under the read-only policy.
Internal targets covered by known runtime-function metadata are suppressed unless their RVA matches
an authoritative metadata function start: a runtime-function begin or retained GuardCF function
start. Aggregate limits of 64 MiB, 1,000,000
instructions, 262,144 discovered block starts, 8,192 retained direct calls, 4,096 retained thunks,
and 32,768 retained data references retain deterministic traversal prefixes when exhausted. The
original thunk seeds have priority over later hop layers.
`code_recovery_scan_truncated` and `data_reference_scan_truncated` persist the applicable partial
state independently. A pointer call is not retained if its paired data reference cannot be
retained. Exhausting the shared decode budget makes both instruction-derived sets
partial. Overlapping runtime-function ranges are preserved and traversed separately, with each
decode charged to the shared budgets, so adversarial overlap metadata can make the bounded pass
partial earlier.

This sweep supplies heuristic-confidence evidence rather than complete recursive disassembly. It
suppresses unreachable post-terminal bytes and can reach a valid block after jump-over data, but
reachable embedded data can still decode as instructions and retain false positives; invalid or
unsupported flow can omit later relationships on that path. The ephemeral worklist is not
persisted. The pass does not turn entry evidence into a fabricated source name, size, basic-block
model, or complete control-flow graph.

The RTTI pass candidate-scans only file-backed initialized data sections that are readable,
non-writable, and non-executable. Vftables and their back-pointers, complete object locators,
class-hierarchy descriptors, base-class arrays, base-class descriptors, and any referenced nested
hierarchy descriptors must remain in those read-only scan sections. A referenced TypeDescriptor
may instead
occupy any file-backed initialized, readable, non-executable data section, including normal
writable `.data`; writable sections are never candidate-scanned. A candidate is committed only
after that section policy, the Rev1 structure chain, and executable file-backed virtual targets
agree. Rev1 base-class arrays may mix descriptor layouts entry by entry: a clear `BCD_HASPCHD` bit
selects the legacy 24-byte form with no class-hierarchy pointer, while a set bit selects the 28-byte
form and requires a valid nested class-hierarchy RVA. An extended root must link to the hierarchy
owned by its complete object locator; a legacy root is validated by its TypeDescriptor, PMD, and
preorder invariants without fabricating the absent link. x86 RTTI and other ABI variants are
rejected rather than guessed.

The ABI does not encode a vftable slot count. ReSymbol therefore retains contiguous pointer-sized
entries only while they resolve to file-backed executable bytes, stops at the first nonmatching
entry, caps each table at 4,096 slots, and records slot-to-class relationships below the confidence
of the RTTI type and vftable identity itself.

Discovery scans at most 64 MiB of eligible section data for candidate back-pointers in RVA order;
validating a candidate performs additional individually bounded reads of referenced metadata and
slots. Locator candidates, vftables, base records, virtual slots, and name text are separately
bounded. Retained RTTI names have a 16 MiB aggregate budget. Candidate-local failures discard that
candidate; exhausting a scan or aggregate budget preserves already validated results and marks the
analysis as partial. The deterministic core pass is offline and never executes the analyzed image.

### 3. Matching and semantic inference

Matchers may compare a function or type against:

- known library signatures;
- a symbolized build of the same program;
- an earlier or later application build;
- reproducibly compiled open-source code; or
- an approved community symbol pack.

Optional semantic providers may inspect normalized disassembly, pseudocode, strings, call context,
and established neighboring facts. Their output is an inference and remains labeled as such.
ReSymbol's deterministic features must continue to work without a model or network service.

### 4. Claim validation and reconciliation

A claim identifies a subject, proposed property, confidence, provenance, and supporting evidence.
The core validates at least:

- binary identity and address ownership;
- value and type shape;
- plugin identity and API compatibility;
- evidence references and dependency relationships;
- resource and permission constraints; and
- conflicts with established facts or competing claims.

Reconciliation may select a preferred display value, but it must preserve credible alternatives and
their provenance. Confidence values are not averaged blindly; deterministic extraction, exact build
identity, structural matching, heuristic inference, and human review require distinct semantics.

### 5. Canonical symbol graph

The graph is format-neutral. Its planned entities include:

- binaries, images, sections, modules, and address ranges;
- functions, blocks, call edges, thunks, imports, and exports;
- globals, constants, strings, fields, parameters, and local variables;
- primitive, pointer, array, function, aggregate, enum, and class types;
- inheritance, vtable, ownership, and containment relationships;
- names and aliases with source and confidence;
- claims, evidence, plugin runs, human decisions, and invalidations; and
- export-specific mappings kept separate from canonical meaning.

Stable entity identifiers must not depend on a display name. Analysis packages are bound to binary
hashes and build identity so symbols cannot be silently applied to the wrong executable.

### 6. Persistence and export

The initial persistence boundary is implemented as a versioned, canonical JSON `.resym` envelope.
It binds the validated payload to an exact SHA-256 binary identity, enforces bounded reads, rejects
unsupported schemas or inconsistent identities, and uses create-new writes to avoid silent data
loss. Its `AnalysisSession` payload contains the deterministic base analysis, an auditable plugin
run ledger, and separately validated plugin claims. A combined symbol graph is derived from those
parts rather than allowing plugins to mutate the metadata graph. The serialized schema and future
migrations are the compatibility boundary; a richer storage backend may be added without changing
the canonical graph into a debugger database.

Exporters consume a bounded, read-only projection of one validated session. The initial projection
selects deterministic names and boundaries, preserves competing names, prototypes, type
definitions, attributed function entries, strings, data references, direct calls, thunks, class
memberships, confidence, and provenance where representable, assigns collision-safe output names,
and emits structured warnings when graph information must be reduced or omitted. Writers revalidate
that projection before serializing it.

Neutral projection schema 6 correlates each retained data reference with a retained string when the
target is exactly the string RVA or a valid content-interior address. The terminating NUL code unit
is outside the correlation range, and a UTF-16LE interior target must be aligned to a two-byte code
unit relative to the string start. Correlation is derived only after deterministic string conflict
and overlap reduction. A missing `referenced_string_rva` means no retained projected string matched;
it does not prove the target bytes are not string data, particularly after bounded recovery.
Schema 6 also represents `FunctionPointer { slot_rva, rva }` targets. A retained pointer call or
thunk preserves both the indirection slot and resolved endpoint instead of flattening the relation
to an ordinary function target. Before pairing calls, projection deterministically reduces
competing data references by caller and instruction site. If the selected same-site reference does
not target the pointer slot, projection omits the pointer call with an `unsupported-assertion`
warning. Pointer thunks require no paired data reference.
Transitive thunk chains require no new projection shape: each exact `ThunkTarget` edge projects
independently, every internal hop is a projected function entry, and connected cycles remain exact
relationships rather than an invented terminal destination.
TLS callbacks likewise require no new neutral projection shape: each slot-backed callback claim
uses the existing attributed function-entry assertion. Delay-import descriptor and inventory data
remain package-only, while calls and thunks through delay-IAT slots use the existing import-IAT
target containing the slot RVA. Load-config/GFIDS inventory and suppression evidence are also
package-only; GuardCF claims and any supported seeded thunks reuse the existing attributed shapes.
The later Guard target inventories are also package-only and deliberately produce no claims.
Load-config security-cookie, GuardCF, XFG, CastGuard, and GuardMemcpy storage anchors are likewise
package-only and add no claims or thunk seeds. Package schema 13 therefore leaves neutral projection schema 6
unchanged.

The first writers serialize the projection as JSON, render bounded Markdown or
Microsoft-linker-style MAP text, emit an exact-RSDS public-symbol PDB, or generate self-contained
IDAPython and Ghidra Java import scripts. Each script checks the debugger's recorded input SHA-256
before mutation and maps RVAs through the loaded image base, so ordinary rebasing does not weaken
exact-build binding.
The scripts preserve existing IDA user-authored names and Ghidra names from sources other than
`DEFAULT`/`ANALYSIS`, avoid replacing existing function bodies, and continue after an individual
symbol cannot be applied. This is intentionally narrower than a long-lived tool-hosted bridge:
selected collision-safe function/global names and safe function boundaries are applied, while
source spellings, alternate names, confidence, provenance, prototypes, types, comments, and
relationships remain available in the neutral JSON but are not yet fully represented in the tool
database. In particular, validated vftable global names can be applied, but function entries without
a safe name or extent, direct calls, thunks, RTTI type creation, and function-to-class membership
metadata remain JSON-only; no virtual-method names are invented. The
generated Ghidra Java writer deterministically packs large projections into bounded record-data
literals and small batch methods, avoiding Java class-file string and constant-pool limits while
retaining a fixed 32 MiB source-output ceiling.

The MAP writer consumes both the validated neutral projection and its matching PE analysis session
because the projection intentionally does not duplicate PE section-table detail. It emits one
group per final PE section, one-based `section:offset` addresses, and
preferred-image-base-plus-RVA values. Raw section-name bytes unsafe for the whitespace-delimited
layout are escaped deterministically, and `<resymbol>` identifies synthetic provenance instead of
inventing source object filenames. Only selected named symbols are candidates; when a selected
function and global share an RVA, the function wins, while an unnamed function suppresses nothing.
This is distinct from the mutation-aware IDA/Ghidra rule, where a global is suppressed only when a
function record is actually emitted.

MAP generation is currently PE-only and rejects a mismatched session/projection pair or a selected
symbol outside the real PE sections. It validates at most 262,144 selected function/global
candidates before same-RVA reduction and limits the complete output to 64 MiB. Conventional
semicolon comments retain the exact SHA-256 and file size, but Microsoft does not document those
comments as MAP fields and the text cannot enforce binary identity when consumed. This writer adds
no package or neutral-projection schema fields.

The initial PDB writer is a deliberately narrow PE-only path for selected public function and
global names. `resymbol export --format pdb` requires `--binary` with the exact original PE because
the `.resym` package does not embed executable bytes. Before writing, ReSymbol hashes those bytes
against the package, applies the strict PE32+ x86-64 header checks, and inspects the bounded PE debug
directory for exactly one well-formed CodeView `RSDS` record. Missing, malformed, or multiple RSDS
records fail rather than being guessed. The resulting PDB copies that record's GUID and age and the
PE's raw 40-byte section-table records verbatim; it does not trust the advisory PDB pathname as
identity and never rewrites the PE.

ReSymbol builds the deterministic, bounded MSF 7.00 container and its PDB, DBI, public-symbol,
global/public-index, and section-header streams in pure Rust. Ordinary users therefore need no
Visual Studio, DIA SDK, LLVM, or compiler installation to create the file. Selected names are
emitted as `S_PUB32` records with function/global flags and one-based PE section-relative
addresses. A selected function wins over a selected global at the same RVA, while an unnamed
function suppresses nothing. The first slice does not synthesize private symbols, compilands,
source files or lines, locals, prototypes, function extents, or type records. It is exercised on
Windows CI through native `llvm-pdbutil` stream inspection, its DIA-backed view, and a direct DIA
identity/public-symbol probe. Like MAP export, it adds no package or neutral-projection schema
fields.

PDB, MAP, DWARF, IDA, Ghidra, and other targets have different capabilities and must not force
their assumptions into the canonical graph. Richer PDB types, private symbols, and line data;
DWARF writers; and interactive debugger bridges remain planned. See
[exporting.md](exporting.md) for current behavior.

## Plugin boundary

ReSymbol supports several extension families because no single runtime fits binary parsing,
high-performance native analysis, managed tooling, model experiments, and debugger integration:

| Family | Intended use | Host boundary |
|---|---|---|
| WebAssembly | Portable analyzers, matchers, rules, and exporters | In-process Wasmtime component; no WASI, bounded WIT imports |
| Native C/C++ | Existing reversing libraries and performance-critical work | Disposable sibling-helper tree; bounded C ABI callbacks, but no OS sandbox |
| Managed/.NET | Managed analyzers, SDK consumers, and ecosystem integrations | App-local self-contained sibling-helper tree; verified assembly snapshots, but no OS sandbox |
| External process | Python, model runtimes, proprietary SDKs, or heavyweight tools | Owned process tree; bounded protocol, but no OS sandbox |
| Tool-hosted bridge | IDA, Ghidra, Binary Ninja, and debugger adapters | The host tool's process and API |

Native in-process loading is not implemented. It may eventually be available as an explicit trusted
performance mode, but it is never the safe default. Rust's native ABI is not a public plugin
contract; native plugins use a versioned C ABI with language wrappers.

The implemented WebAssembly host runs Component Model plugins in an in-process Wasmtime engine and
links only the versioned ReSymbol WIT imports. No WASI filesystem, network, environment, clock, or
process interface is linked. The first host accepts exact validated PE32+ x86-64 analysis context,
exposes permission- and phase-bounded file-backed `binary.read` and claim submission plus bounded
logging and cancellation checks, and executes metadata, initialize, health, analyze, and shutdown
as one transaction.
Component bytes are capped before compilation. Store linear memory, tables, instances, guest stack,
fuel, epoch time, host-event bytes and counts, and per-call/aggregate binary reads are bounded after
compilation. The complete plugin fingerprint and exact binary identity are checked around execution,
and no claims commit until lifecycle, resource, claim, and final policy validation succeeds.

Because the no-WASI host grants no ambient authority through its declared surface, eligible WASM
components autoload without a trust record. Manual disablement, safe mode, exact-artifact
quarantine, and reset remain enforced. This is a no-WASI capability boundary inside the process,
not process containment: a vulnerability in Wasmtime, its generated native code, or ReSymbol's host
bindings can cross the boundary or terminate the application. Normal traps, fuel exhaustion,
deadlines, and invalid output are transactionally contained after instantiation, but the fuel,
epoch, stack, and store controls do not interrupt synchronous validation/JIT compilation or cap
compiler and other host allocations. A pathological component can exceed the guest deadline or
memory limit while compiling, and there is no separate process protecting ReSymbol from compiler
resource exhaustion or an engine escape.

The implemented external-process host starts an explicitly approved plugin directly, without a
shell, for one analysis request; exchanges size- and count-bounded NDJSON; enforces a deadline and
bounded diagnostics; and accepts claims only as one validated transaction. Interactive
`binary.read`/`read-binary` requests are reserved and are not serviced by this one-shot host.

The implemented native host keeps the same one-shot transactional boundary while loading the
approved library only inside a disposable, version-matched `resymbol-native-host[.exe]` process
shipped beside the application. ReSymbol never selects a helper from a plugin directory. The helper
validates the manifest, C descriptor and ABI tables, lifecycle results, callback bounds, exact
analyzed-binary identity, and approved directory fingerprint. Its permission-gated, size-bounded
`binary.read` callback exposes only file-backed RVAs from the exact PE. Claims enter the session
only after the complete batch and final fingerprint check validate. A plugin-attributable crash or
post-load ABI, callback, resource, or output failure discards the entire batch and quarantines that
exact artifact without invalidating deterministic analysis or preventing the `.resym` package from
being written. Immediately before the first platform loader call, the helper writes and flushes a
versioned marker that the parent observes independently of structured diagnostics and removes from
user-visible stderr. A failure observed with that marker is plugin-attributable; one without the
current marker is conservatively classified as host-side and does not quarantine the plugin.

The implemented managed host is an `analyze`-only .NET 8 slice for PE32+ x86-64 sessions. The Rust
parent resolves only the regular, unlinked, app-local `resymbol-managed-host[.exe]` sibling, clears
the inherited environment except for required operating-system state, and gives each launch a
private single-file bundle-extraction directory. It binds the exact trusted plugin fingerprint,
source-binary identity and PE map, manifest metadata, granted permissions, deadline, and a
deterministically ordered closure of at most 512 private DLLs into a strict bootstrap. A packaged
`ReSymbol.PluginSdk.dll` remains in the complete artifact fingerprint but its exact basename is
excluded from that closure. The host supplies and exact-identity-checks the SDK, so references bind
only to the host's contract assembly rather than privately loading the packaged copy.

Before assembly loading, both processes verify the plugin artifact and source, and the helper reads
the declared DLL closure plus exact binary into snapshots under one cumulative advertised byte
gate. The custom collectible load context resolves ordinary private dependencies only from those
verified bytes, rejects platform-assembly shadow names, and denies its unmanaged-resolution callback.
Service calls are permission-, phase-, count-, range-, and byte-bounded; claims may be submitted
only during `AnalyzeAsync`. Initialization, health, analysis, shutdown, disposal, logs, and claims
form one transaction. Any lifecycle, service, claim, identity, deadline, or cleanup failure discards
the batch, and final source, assembly, artifact, disable, trust, and quarantine checks run before
commit.

The managed helper writes and flushes its own versioned marker immediately before the first assembly
load, where module initializers or type discovery can begin plugin-controlled execution. The parent
strips exactly that marker from visible stderr and uses it to distinguish attributable failures,
which quarantine the exact artifact, from conservative helper preflight failures. A killed,
crashed, or rejected managed run cannot partially commit claims or prevent base package creation.

External, native, and managed launches own ordinary descendants through a POSIX process group or
Windows Job Object. The shared runner terminates the whole owned tree when the direct child
completes, a deadline expires, a stdout/stderr capture worker fails, or the runtime guard drops.
This is a lifecycle boundary, not an authority boundary. Linux `waitid(WNOWAIT)` and a macOS kqueue
`NOTE_EXIT` observer keep an exited group leader unreaped until the group is terminated, preventing
process-group identifier reuse during normal cleanup. Windows uses a safe Rust wrapper to assign the
child to its Job Object immediately after spawn, while retaining a narrow pre-assignment escape race.
A hostile POSIX plugin/helper or descendant can deliberately leave its process group or session and
escape later group termination.

Process separation contains ordinary crashes, not authority. External, native, and managed child
code still has the ambient filesystem, network, credential, and process access of the account
running ReSymbol. Consequently executable process plugins require explicit approval tied to their
complete directory fingerprint before first execution. The unchanged fingerprint may autoload
later; any fingerprinted-file update invalidates that approval. Manifest permissions constrain
ReSymbol's protocol operations and data projections, not ambient operating-system access. A fingerprint
identifies reviewed local directory bytes but neither authenticates a publisher nor eliminates the
check-to-launch window while those files remain mutable. Native dynamic dependencies remain subject
to the platform loader's documented search rules rather than an immutable dependency snapshot.
Likewise, a managed custom load context closes ordinary dependency resolution only. Plugin code can
call framework APIs directly, including explicit `Assembly.Load*` and `NativeLibrary.Load` paths
that can engage the default load context or platform loader, and can access any other ambient .NET
or operating-system capability available to the account. The managed host is not a CLR security
sandbox.

The current standalone IDAPython and Ghidra Java exporters implement a small identity-checking,
conservative application path without installing a persistent plugin in either tool. They do not
make the planned interactive tool-host boundary complete.

See [plugin-system.md](plugin-system.md) for discovery, health states, and contracts.

## Debugger and sandbox foundation

`crates/resymbol-debugger` implements a backend-neutral, non-executing foundation: bounded control
and raw-byte framing, strict typed commands and events, a command-specific session reducer, one-use
host-risk and sandbox-ownership authority, exact attestation/cleanup evidence models, and a
single-owner host-client seam. Its provider-readiness service performs only read-only discovery and
reports whether provisioning may be attempted for the exact requested provider, boundary, and
guarantees. It cannot provision a sandbox, launch or attach to a target, or attest that containment
exists.

The feature-gated `SyntheticDebugHost` exercises offline open/close protocol mechanics for tests and
explicit test-support builds. It reports no platform capability and fabricates no target,
attestation, or cleanup evidence. The build-claim handshake binds roles, versions, sequences, and a
nonce strongly enough to detect protocol reflection, replay, downgrade, and accidental build
mismatch, but its echoed nonce and self-reported strings are plaintext correlation—not peer or
process authentication. A production transport must independently authenticate the helper channel
and process identity.

No Windows debugger-host process, live transport, AppContainer or Hyper-V provider, guest agent,
live launch/attach, breakpoint engine, register service, or process-memory service is implemented.
The current contracts and readiness UI are therefore not a working malware sandbox or live
debugger. [debugger-sandbox.md](debugger-sandbox.md) records the exact ownership, authorization,
containment, cleanup, and verification gates that future providers must satisfy.

## Workbench GUI

`crates/resymbol-workbench` implements the first Windows-first desktop slice with pinned
eframe/egui 0.32.3 dependencies. That version preserves the workspace's Rust 1.86 minimum. Its
workflow is **Open Binary -> background core-only Analyze -> Review -> Export**: file analysis runs
away from the UI thread, then the shell receives one validated `AnalysisSession`, bound `.resym`
package, and debugger-neutral `ExportProjection` built by the existing analysis, package, and
export crates. The workbench does not fork reconciliation or identity rules from the CLI.

The initial shell implements the approved four-region structure: persistent, resizable and
collapsible project/plugin navigation, a virtualized sortable/filterable function table, a bounded
Reconstruction Graph, a static Address Space/protection view, a non-executing Debugger / Sandbox
readiness view, an evidence inspector, and a progress/warning/log area. It displays exact SHA-256
binary identity and read-only plugin health. Graphite, Light, IDA-inspired, and Classic Debugger are
persisted theme presets; arbitrary docking is not implemented.

The Reconstruction Graph is a read-only projection of retained analysis, not a second analyzer or a
claim of complete call-graph recovery. It roots at the PE entry point when that point is available as
a projected function, otherwise at a deterministic lowest-RVA navigation fallback that is not
presented as an inferred `main`; a selected function can become the focus. Graph node selection
updates the same function selection used by the table and evidence inspector. Edges are created only
for retained direct calls and thunks, including their explicit import-slot endpoints, and never from
address proximity or layout guesses. A fixed node/tier window keeps large binaries responsive, with
a visible bounded/truncation cue whenever the reachable view exceeds that rendering budget.

GUI exports use the same shared models and create-new policy to write canonical `.resym`, neutral
JSON, bounded Markdown, PE MAP, public-symbol PDB, IDA Python, and Ghidra Java files. The workbench
opens current packages, verifies an exact source binary when byte-dependent views require it, and
owns one binary-bound review ledger. **Accept Primary**, **Keep as Alias**, **Reject**, annotations,
undo, and redo apply only to versioned semantic fingerprints of exact name claims; non-name claims
remain read-only. **Keep as Alias** retains an alternate without silently promoting it to primary,
and a disposition plus optional rationale is one indivisible undo/redo transaction. Current schema-2
sidecars strictly migrate supported schema-1 data, stay bound to the exact binary, and use
create-new durable writes. Sidecar I/O and reviewed projection rebuilds run on the bounded worker,
while operation identifiers and exact ledger/project binding reject stale results. A native close
request or companion-console `quit` with unsaved review changes pauses for **Save New...**,
**Discard and Close**, or **Cancel**; save-and-close waits for the exact queued ledger snapshot to
be durable. GUI plugin execution, arbitrary docking, synchronized disassembly/pseudocode views,
editable or exhaustive control-flow graphs, and a live debugger bridge remain planned.

The companion console is an opt-in process rather than a second state owner. The GUI spawns the
packaged console helper only after the user enables it and uses private redirected standard-I/O
pipes for bounded command and activity transport. The helper owns the visible terminal while typed
commands are applied only on the GUI event loop. Disabling or closing the helper tears down only
that console session, while the workbench and analysis state remain alive. The console is off again
on every application launch.

[gui-design.md](gui-design.md) distinguishes implemented behavior from the approved long-term
layout, review semantics, theme variants, semantic-color invariants, and accessibility requirements.

## Packaging boundary

The application is centered on the Rust CLI and workbench plus prebuilt, version-matched plugin
hosts and thin tool adapters as they become implemented. A portable Windows archive is the initial
workbench packaging target; broader desktop packaging remains to be validated. Ordinary users
should not need to install a compiler, language runtime, build system, or package manager. In
particular:

- current archives ship a prebuilt source-backed WASM example under `plugins/`,
  `resymbol-native-host[.exe]`, and a single-file, self-contained
  `resymbol-managed-host[.exe]` beside `resymbol[.exe]`;
- Linux archives pair a static musl CLI with a GNU helper built on Ubuntu 22.04 for glibc 2.35 or
  newer so ordinary glibc `.so` plugins can load;
- ordinary managed-plugin users need neither a system .NET runtime nor SDK;
- ordinary WASM-plugin users need no Rust toolchain, WASI SDK, or component build tool;
- ordinary plugins are distributed already compiled;
- the implemented PDB exporter does not require a separate Visual Studio installation; and
- optional external services remain optional rather than preventing deterministic analysis.

Developer toolchains are a contributor concern, not an end-user installation step.

## Trust boundaries

1. **Input binaries are untrusted.** Parsers apply bounds and resource limits and should avoid
   unsafe code.
2. **WASM components are capability-sandboxed in-process.** They autoload without trust because no
   WASI or ambient interface is linked, but manual disablement and exact quarantine still apply.
   Wasmtime or host-binding vulnerabilities are not process-contained.
3. **Executable process plugins are untrusted by default.** External-process, native, and managed
   code is never launched before an explicit fingerprint-bound trust decision. Trust and
   quarantine records live in the host-owned `plugins/.resymbol/` directory, outside
   plugin-controlled directories.
4. **Native code is crash-isolated, not sandboxed.** It runs only in the disposable sibling helper
   in the current implementation, but retains the launching account's ambient authority. There is
   no in-process native path.
5. **Managed code is process-isolated, not sandboxed.** Its verified assembly closure and
   transactional services constrain normal host integration, but default-context/explicit loading
   APIs and all other ambient authority remain available. There is no in-process managed path.
6. **Remote content is untrusted.** Symbol servers, source indexes, registries, and model endpoints
   cannot directly create trusted facts.
7. **Tool bridges are separate trust domains.** A bridge must validate the binary identity and
   address mapping before applying an analysis inside another program.
8. **Debugger readiness is not containment.** A read-only readiness result authorizes neither
   provisioning nor execution. The current plaintext build-claim exchange does not authenticate a
   helper, and no process-executing debugger provider exists in the current implementation.

The core should retain enough structured diagnostics to explain which boundary failed without
logging binary contents, source material, or secrets by default.

`plugin.disabled` remains an out-of-band manual stop switch and safe mode suppresses all
third-party execution. Plugin-attributable launch, runtime, resource, claim, or protocol failures
quarantine the exact plugin fingerprint; confirmed host/helper preflight failures do not. Corrupt
applicable host state fails closed. Quarantine does not grant trust to an updated process artifact,
plugin failure never deletes the installed files, and a rejected run cannot leave a partially
committed claim batch. Immediately before launch and again before committing a completed batch, the
parent rechecks the disable sentinel and applicable exact policy state. That final recheck is the
policy linearization point; a disablement, trust revocation, or quarantine observed there discards
the full batch.

## Compatibility

Compatibility is negotiated independently for:

- plugin manifest schema;
- plugin protocol or ABI;
- symbol-graph interchange schema;
- analysis package schema; and
- individual exporter behavior.

A plugin declares a supported API range. Unsupported plugins are marked incompatible rather than
loaded optimistically. Schema migrations are explicit and must preserve provenance. Before 1.0,
breaking changes are expected, but they still require version bumps and release notes.

The current CLI writes analysis-package schema 13 and can inspect or export schemas 1 through 12
through explicit compatibility paths. It migrates schema 1 into a validated current session,
rebuilds the base graph from persisted legacy metadata, and never rewrites the source package.
Schema 2 already records direct calls and thunks but predates recovered strings and data references;
schema 3 includes string/data recovery but predates read-only function-pointer call and thunk
resolution; schema 4 records pointer control flow but predates 24-byte RTTI base-class descriptor
recovery; schema 5 records that RTTI form but predates transitive executable thunk-chain discovery;
schema 6 records that closure but predates TLS callback discovery and callback-based thunk seeding;
schema 7 records TLS callbacks but predates modern delay-import recovery; schema 8 records delay
imports but predates load-config GuardCF recovery; schema 9 records GuardCF functions but
predates the modern Guard target inventories; schema 10 records those inventories but predates
load-config security-anchor recovery; schema 11 records those earlier anchors but predates XFG
and CastGuard storage-anchor recovery; and schema 12 records XFG/CastGuard anchors but predates the
GuardMemcpy pointer-slot anchor.
Because a package omits the analyzed binary bytes, compatibility loading cannot recreate absent
recovery results. Schemas 1 through 6 report TLS callbacks unavailable; obtaining every current
result also requires treating delay imports as unavailable in schemas 1 through 7, GuardCF recovery
as unavailable in schemas 1 through 8, and the Guard address-taken IAT, long-jump, and
EH-continuation inventories as unavailable in schemas 1 through 9, and load-config security
anchors as unavailable in schemas 1 through 10, XFG/CastGuard anchors as unavailable in schemas
1 through 11, and the GuardMemcpy anchor as unavailable in schemas 1 through 12, then reanalyzing
the exact original binary into schema 13.
Schemas 2 and 3 are also semantically gated against relabeled schema-4 `function-pointer` targets.
All schemas 1 through 4 are semantically gated against relabeled schema-5 base-class records whose
`class_hierarchy_descriptor_rva` is missing or null. Schemas 1 through 5 reject a deterministic
base thunk source that is valid only under schema-6 transitive endpoint seeding.
Schemas 1 through 6 reject schema-7 TLS fields, core `pe-tls-callback` claims, and callback-only
base thunk seeds rather than accepting a relabeled package.
Schemas 1 through 7 likewise reject the exact schema-8 base-analysis `delay_imports` inventory key
and `directories.delay_imports` directory key. Schemas 8 through 13 always serialize the delay-import
inventory, including an empty array, and reject a payload missing that marker so relabeling alone
cannot upgrade a legacy package.
Schemas 1 through 8 reject schema-9 `load_config_size`, `guard_flags`,
`guard_cf_function_table_rva`, and `guard_cf_functions` fields, the `directories.load_config` key,
and core `pe-guard-cf-function` claims. Schemas 9 through 13 always serialize the GuardCF inventory,
including an empty array, and reject a payload missing that marker.
Schemas 1 through 9 reject schema-10 Guard target table-RVA and inventory fields. Schemas 10 through 13
always serialize the address-taken IAT, long-jump, and EH-continuation inventory arrays, including
empty arrays, and reject a payload missing any marker.
Schemas 1 through 10 reject the schema-11 `load_config_security_anchors` object. Schemas 11 through 13
always serialize that object, including `{}` when every anchor is absent, and reject missing or
non-object markers. Schemas 1 through 11 reject schema-12 `load_config_xfg_anchors`; schemas 12 and
13 always serialize that object, including `{}` when all four anchors are absent, and reject a
missing or non-object marker. Schemas 1 through 12 reject schema-13
`load_config_guard_memcpy_anchor`; schema 13 always serializes that object, including `{}` when the
anchor is absent, and rejects a missing or non-object marker.
The independently versioned debugger-neutral projection is schema 6; its string-reference
correlation and exact per-hop thunk relationships are derived from already validated claims and
therefore do not require a projection-schema change or legacy package rewrite. Package schema 13 and
neutral projection schema 6 remain independent compatibility domains. Package schema 13 also leaves
the plugin API and external wire protocol 1.0 unchanged. Plugins with `symbols.read` can observe the
TLS, delay-import, load-config/GuardCF, modern Guard target, and all three load-config anchor families
in detached base-analysis JSON; plugins without
that permission receive
no base analysis.

## Core invariants

The following responsibilities are not delegated to plugins:

- binary and analysis identity;
- canonical addressing;
- graph transaction and migration rules;
- claim validation and provenance;
- plugin permission and lifecycle enforcement;
- conflict semantics; and
- safe startup, disablement, and quarantine.

Extensions can propose new information and representations. Only the core decides whether a claim
is valid canonical state.
