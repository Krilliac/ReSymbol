# ReSymbol analysis packages

ReSymbol writes analysis results to a portable `.resym` file. The initial format is canonical JSON:
it is easy to inspect, deterministic for the same analysis payload, and independent from IDA,
Ghidra, PDB, or DWARF data models.

Create, inspect, and export a package with the current CLI:

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
```

Use `resymbol analyze application.exe --output another.resym` to select a different destination.
Existing files are never overwritten.

## Envelope

Every package contains four top-level fields:

```json
{
  "binary_sha256": "<64 lowercase hexadecimal characters>",
  "generator_version": "0.1.0-alpha.1",
  "payload": {},
  "schema_version": 8
}
```

- `binary_sha256` binds every result to the exact bytes that were analyzed.
- `generator_version` identifies the ReSymbol build that produced the package.
- `schema_version` controls envelope compatibility independently from the application version.
- `payload` contains one validated `AnalysisSession`: deterministic base analysis, a plugin-run
  ledger, and accepted plugin claims.

This package envelope currently writes schema 8. The CLI can also inspect and export schemas 1
through 7 through the compatibility paths described below, while other schema versions fail
explicitly. The debugger-neutral JSON produced by `resymbol export --format json` is a different
artifact with its own schema version; its current projection is schema 6.

Object keys are sorted recursively and no timestamp is inserted, so encoding the same deterministic
payload produces the same bytes. Arrays preserve analysis order because source-table order can be
meaningful evidence.

## Safety and compatibility

Package reads are size-bounded and reject malformed binary identities, unsupported schema versions,
invalid payloads, and files that exceed the configured limit. Writes use create-new semantics: an
existing destination is never silently replaced.

`resymbol inspect PACKAGE --binary EXACT_ORIGINAL_BINARY` optionally verifies the package against
the bytes it names. ReSymbol fully validates the package, canonicalizes and reads the supplied file,
and requires its exact size and SHA-256 to match before emitting inspection output to stdout.
Failures report on stderr. A successful human summary includes
`source binary: <canonical-path>` and `identity gate: matched`. With `--json`, stdout stays pure
package JSON and omits both status lines. This gate applies to supported schemas 1 through 8 but
performs no reanalysis, legacy-result reconstruction, or rewrite of either input.

A package must not be applied to a loaded program until its SHA-256 identity has been compared with
that program. A matching filename, product version, timestamp, or image size is insufficient.
ReSymbol's generated IDAPython and Ghidra Java scripts perform that exact SHA-256 check inside the
tool before making any database change. They then resolve projected RVAs against the loaded image
base instead of assuming the package's preferred virtual address. See [exporting.md](exporting.md)
for the application policy and current representational limits.

PDB export also enforces byte-backed identity, but at generation time. Because the package omits
the executable bytes, `--format pdb` requires `--binary` with the exact original PE. ReSymbol hashes
the supplied bytes against the package and re-inspects their bounded PE headers and debug directory
before it writes anything. The source must contain exactly one well-formed CodeView `RSDS` record;
the output copies its GUID and age and copies the PE's raw section headers verbatim so normal symbol
matching and section-relative public addresses refer to that exact image. The RSDS pathname is
advisory, not an identity substitute, and the executable is never modified.

Schema changes and plugin API changes are versioned separately. Before ReSymbol 1.0, payload fields
may evolve between prereleases, but an incompatible reader must fail explicitly instead of guessing.
When the CLI opens schema 1, it decodes the legacy payload into a current in-memory
`AnalysisSession`, revalidates the persisted PE metadata, plugin ledger, claims, and binary-identity
binding, and rebuilds the deterministic base graph from the persisted schema 1 analysis. It does
not rewrite or upgrade the package on disk. Legacy plugin claims pass through a closed schema 1
assertion decoder: only name, function-prototype, function-boundary, type-definition,
class-membership, and comment assertions are accepted. Function-entry, direct-call, thunk-target,
string-literal, data-reference, and any future assertion kinds are rejected even if their current
representation would otherwise validate. Accepted legacy assertions still undergo the current
claim, provenance, successful-run ledger, binary-binding, and address-range validation; the
allowlist is not a validation bypass.

A `.resym` package does not contain the original binary
bytes, so migration cannot retroactively run code recovery: direct-call and thunk arrays stay empty
and the migrated session is not evidence that the decoder found no relationships. Schema 2 retains
its recorded calls and thunks but predates recovered strings and data references. Schema 3 retains
strings and data references. Schemas 2 and 3 both predate exact read-only function-pointer call and
thunk resolution, so their recorded code recovery remains available while that newer result family
is reported as unavailable. Schema 4 records pointer control flow but predates recovery of legacy
24-byte MSVC RTTI base-class descriptors without `pCHD`. Existing RTTI recorded by schemas 1
through 4 remains available, but loading cannot discover omitted descriptors without the executable
bytes. Schema 5 records both RTTI descriptor layouts but predates transitive executable thunk-chain
discovery; its existing calls and thunks remain available, but loading cannot add omitted hops.
Schema 6 records that closure but predates TLS callback discovery and callback-based thunk seeding.
Schema 7 records TLS callbacks but predates modern PE32+ delay-import recovery. The TLS callback
result family is therefore reported as unavailable for every schema 1-through-6 package, while
delay imports are unavailable for schemas 1 through 7. Reanalyze the exact original executable to
create a schema 8 package with all current recovery results. The compatibility reader explicitly
rejects a schema 2 or 3 envelope whose base
analysis, base graph, or plugin claims contain a schema-4 `function-pointer` target. It also rejects
any schema 1-through-4 payload whose RTTI base records have a missing or null
`class_hierarchy_descriptor_rva`. Schema 1's closed migration path rejects every persisted
post-schema-1 control-flow record; schemas 2 through 5 explicitly reject a deterministic base thunk
source valid only through schema-6 transitive endpoint seeding. Changing only the envelope label is
not migration. Schemas 1 through 6 also reject schema-7 TLS callback state and callback-only base
thunk seeds. Schemas 1 through 7 reject the exact schema-8 base-analysis `delay_imports` inventory
key and `directories.delay_imports` directory key; schema 8 rejects a payload missing its explicit
delay-import inventory marker.
Plugin-supplied exact thunk claims remain independent of the built-in base-analysis seed invariant.
`inspect --json`, with or without the optional binary gate, emits only package JSON. For every
legacy schema 1 through 7 it preserves the validated original representation rather than placing
the migrated current payload beneath a legacy schema label.

## Current `AnalysisSession` payload

The payload keeps core analysis and extension output deliberately separate:

```json
{
  "base_analysis": {},
  "plugin_runs": [],
  "plugin_claims": []
}
```

- `base_analysis` records PE32+ x86-64 metadata derived by ReSymbol itself;
- `plugin_runs` identifies each attempted plugin, its semantic version, exact artifact SHA-256,
  stable run ID, outcome, and accepted-claim count; and
- `plugin_claims` contains only claims that passed core validation and whose provenance matches a
  successful run in the ledger.

The base analysis includes:

- normalized binary identity and image metadata;
- COFF and optional-header fields used by analysis;
- bounded section, conventional-import, modern delay-import, export, exception-directory, and
  TLS-directory records;
- a separate ordered delay-import inventory retaining the DLL name, descriptor RVA and exact
  attributes value, name/HMOD/IAT/INT base RVAs, optional BIAT/UIAT base RVAs, per-entry lookup/IAT
  RVAs and hints/names or ordinals, and the timestamp, but not raw array contents; schema 8 always
  serializes this inventory, including an empty array, as an explicit compatibility marker;
- x64 `RUNTIME_FUNCTION` entries as evidence-backed candidate function boundaries;
- up to 4,096 ordered PE32+ TLS callback entries with duplicates preserved, their callback-table
  RVA, and an independent partial-scan flag;
- bounded direct-call records with explicit internal-function, exact parsed import-IAT, or read-only
  function-pointer targets; one-instruction thunks may likewise target internal functions, exact
  parsed import-IAT slots, or read-only function-pointer slots, with a persisted partial-scan flag;
- bounded NUL-terminated ASCII and UTF-16LE strings plus exact x64 RIP-relative references to
  eligible data, each with independent persisted partial-scan state;
- validated modern MSVC x64 Rev1 RTTI records, including type descriptors, class hierarchy and
  legacy 24-byte or `BCD_HASPCHD` 28-byte base-class records, vftable locations, and executable
  virtual-slot targets; and
- a symbol graph containing exact export names, metadata-derived boundaries, entry-point and
  TLS-callback function entries, direct calls, thunks, string literals, data references, recovered
  RTTI type names, vftable names, and class-membership claims for virtual-slot targets.

ReSymbol derives the combined symbol graph from the base graph plus `plugin_claims`; it does not
serialize a second independently mutable graph. Session validation rejects duplicate run IDs,
noncanonical artifact fingerprints or versions, claims for another binary or an out-of-image range,
producer/run mismatches, invalid subject/assertion combinations, and ledger counts that do not
match the accepted claims.

Plugins granted `symbols.read` receive the same detached base analysis as JSON, so schema-7
sessions add the TLS directory and callback fields and schema-8 sessions add the delay-import
directory and ordered inventory. This is additive data inside the existing request payload: it does
not change the plugin API or wire protocol 1.0, add a new assertion shape, or change neutral
projection schema 6. Plugins without `symbols.read` still receive no base analysis.

Plugin execution is transactional. A failed process run contributes no claims, so an invalid,
crashed, timed-out, or quarantined plugin cannot corrupt the deterministic base analysis. Ordinary
analysis still writes a valid package after such a failure. With `--strict-plugins`, ReSymbol writes
the package first and then returns a failure status if an explicitly selected or otherwise eligible
plugin could not complete successfully.

The package does not contain the analyzed executable itself. It also does not claim to recover an
original source name when only a reconstructed or inferred name is available.

### PE32+ TLS callback boundary

TLS callback discovery consumes optional-header data-directory entry 9. A present directory must
have a fully file-backed declared range and contain at least the 40-byte PE32+ TLS-directory
prefix. `AddressOfCallbacks` and each nonzero callback entry are preferred-image VAs, not RVAs;
ReSymbol subtracts the preferred image base with checked arithmetic and rejects values outside the
declared image.

The callback table is read as ordered eight-byte slots. Source order and duplicate entries are
preserved in the base analysis, every retained slot must be fully file-backed, and every callback
endpoint must begin in file-backed executable data. ReSymbol retains at most 4,096 nonzero entries,
then performs a cap-plus-one probe. A null next slot proves that the 4,096-entry table is complete;
a nonzero next slot keeps that deterministic prefix and sets `tls_callback_scan_truncated` without
retaining or following the extra entry.

Each retained callback slot produces a `FunctionEntry` claim with exact metadata evidence and
`pe-tls-callback` provenance. The `callback_slot_rva` and `table_index` evidence artifacts keep
claims separate when multiple slots repeat the same target RVA. Callback targets also join the
deterministic initial thunk seeds, so an exact supported first-instruction thunk can be retained
without turning the callback into an unbounded body scan. ReSymbol never executes a callback and
does not infer its name or extent.

### Modern PE32+ delay-import boundary

Modern delay-import discovery consumes optional-header data-directory entry 13 as ordered 32-byte
descriptors terminated by one all-zero descriptor; every remaining descriptor in the declared
range must be all-zero padding. ReSymbol supports only the RVA-based form whose
attributes field is exactly `dlattrRva` (`1`). It explicitly rejects zero, unknown attribute bits,
and the legacy VA form rather than guessing through the ambiguity in generic PE table documentation.

Every active descriptor must carry nonzero name, module-handle (HMOD), delay-IAT, and delay-INT RVAs.
The complete declared descriptor range, each consumed descriptor and string, HMOD storage, paired
64-bit INT/IAT slots and terminators, and optional bound-IAT (BIAT) or unload-IAT (UIAT) arrays must
be fully file-backed. The HMOD slot's initial bytes and section permissions remain opaque. INT, IAT,
and each present BIAT or UIAT must be pairwise disjoint. Each present BIAT or UIAT must have a zero
slot at the paired INT/IAT entry count. BIAT payload values before that required slot are otherwise
opaque, including whether any is zero, while the complete UIAT must byte-match the original delay
IAT. Names, hints, and ordinals are decoded from the INT. The package preserves descriptor and entry
order, the DLL name, descriptor RVA and exact attributes value, name/HMOD/IAT/INT base RVAs,
optional BIAT/UIAT base RVAs, each entry's lookup/IAT RVAs and hint/name or ordinal, and the
timestamp. It does not serialize raw INT/IAT/BIAT/UIAT array contents.

Conventional and delay imports share aggregate ceilings of 4,096 libraries, 65,536 symbols, and
16 MiB of name bytes. Malformation, conflicting table structure, or exhaustion of any shared limit
is a hard analysis error: this slice never serializes a partial delay-import prefix. Each accepted
delay-IAT slot nevertheless joins the existing parsed-IAT membership used by code recovery. Exact
supported calls and thunks use the existing `ImportIat` target and that membership outranks
read-only function-pointer interpretation.

### MSVC x64 RTTI boundary

The built-in RTTI pass follows a pointer immediately before each candidate vftable and accepts a
record only when its complete object locator, type descriptor, class hierarchy, base-class array,
base descriptors, and executable file-backed slot targets agree. Invalid candidates are discarded
atomically; their partial data is not added to the package or graph. Repeated base-descriptor RVAs
and shared complete object locators are preserved because both are valid compiler output.

This slice deliberately supports both MSVC x64 Rev1 base-class descriptor layouts. When
`BCD_HASPCHD` is clear, the descriptor is the legacy 24-byte form and
`class_hierarchy_descriptor_rva` is null because no `pCHD` field exists. When the bit is set, the
descriptor is 28 bytes and its `pCHD` must be nonzero, aligned, and point to a valid
class-hierarchy descriptor. The choice is made independently for each base-class-array entry, so a
validated hierarchy may mix both layouts.

The root entry still has to match the complete object's TypeDescriptor, PMD shape, and preorder
span. If the root uses the 28-byte form, its `pCHD` must equal the hierarchy referenced by the
complete object locator; a 24-byte root is accepted without fabricating that absent link. Any
non-root 28-byte descriptor retains its validated nested hierarchy, while a 24-byte descriptor has
no nested-hierarchy claim. x86 RTTI and other ABI variants are not silently interpreted as Rev1.

Candidate scanning and accepted vftables/back-pointers, complete object locators, class-hierarchy
descriptors, base-class arrays, base-class descriptors, and any referenced nested hierarchy
descriptors are restricted to file-backed, initialized, readable, read-only, non-executable data.
Referenced
TypeDescriptors may be in file-backed initialized, readable, non-executable data that is either
read-only or writable, including the normal `.data` placement. Writable sections are never added
to the candidate scan plan.

Discovery is deterministic and resource-bounded. Eligible initialized, readable, non-writable,
non-executable section bytes are scanned in RVA order, with at most 64 MiB used for candidate
back-pointer scanning and 262,144 locator candidates considered. Candidate validation can perform
additional bounded random reads of referenced metadata and slots. The retained model is limited to
65,536 vftables, 4,096 bases per hierarchy, 262,144 base records in aggregate, 4,096 virtual slots
per vftable, and 262,144 virtual slots in aggregate. Each decorated or demangled RTTI name is
limited to 1,024 bytes, and retained RTTI name text is capped at 16 MiB in aggregate.

Because the ABI does not store a slot count, virtual-slot extent is a bounded contiguous-pointer
heuristic: scanning stops at the first entry that is not an in-image, file-backed executable target.
It can therefore end before an unusual valid target or include adjacent executable-pointer data;
the result is relationship evidence, not an authoritative table-size claim. A candidate with a
known 4,097th executable entry is rejected rather than silently retaining a known-truncated table.
These class-membership relationships carry lower confidence than the validated RTTI type and
vftable names, and ReSymbol does not turn them into invented method names.

Candidate-local structural or size violations reject that candidate. If the section scan or an
aggregate discovery/model budget is exhausted, ReSymbol keeps the already validated records and
sets `msvc_rtti_scan_truncated` instead of pretending discovery was complete. `analyze` and
`inspect` surface this state as `MSVC RTTI scan: partial` along with vftable, unique-type,
base-record, and virtual-slot counts.

### Bounded string-recovery boundary

The built-in string pass scans complete raw ranges from file-backed, initialized, readable,
non-executable PE sections in RVA order. Writable initialized data is eligible. ASCII candidates
use printable bytes, while UTF-16LE candidates start at an even RVA and must decode to valid Unicode
without control characters or unpaired surrogates. Both encodings require a NUL terminator, at least
four code points, and at least one non-whitespace code point. Competing byte-overlapping
interpretations are reduced deterministically, and a literal is published only when its complete
value and terminator fit the model; ReSymbol never records a truncated prefix as an exact string.

The pass scans at most 64 MiB of eligible section data and retains at most 16,384 strings. Each
value is limited to 4 KiB of UTF-8 and 4 KiB of encoded data, with the encoded limit including the
NUL terminator. Aggregate retained UTF-8 content is capped at 4 MiB. Hitting a scan, per-value,
record-count, or aggregate-text limit preserves the deterministic valid results and sets
`string_recovery_scan_truncated`; CLI summaries report that set as partial.

### Bounded x86-64 control-flow boundary

The built-in code-recovery pass is a bounded control-flow-guided block sweep over complete,
file-backed executable ranges supplied by the PE x64 exception directory. Each distinct range
begins with its metadata-backed entry. Pending direct conditional and unconditional targets inside
that same range are dequeued in smallest-RVA order, while fallthrough continues immediately where
the instruction permits it. Returns, terminal or indirect control flow, invalid instructions,
out-of-range targets, and targets inside an already decoded instruction stop the affected path. The
ephemeral traversal is not a persisted basic-block graph or a general recursive disassembler.

The pass recognizes exact five-byte `E8 rel32` calls to file-backed executable RVAs. It also
recognizes exact RIP-relative `FF 15 disp32` and redundant-`REX.W` `48 FF 15 disp32` calls, with
instruction sizes six and seven bytes respectively. At a seeded executable thunk candidate it
recognizes exact RIP-relative `FF 25 disp32` and redundant-`REX.W` `48 FF 25 disp32` jumps of those
same sizes. If the computed slot RVA exactly matches a parsed import-IAT slot, import semantics take
precedence and the slot is not dereferenced. Otherwise the complete eight-byte slot must lie in one
file-backed, initialized, readable, non-writable, non-executable section. Its little-endian
preferred-image VA is resolved exactly one hop to an in-image, file-backed executable RVA. Pointer
to-pointer slot chains, writable slots, other indirect forms, and targets merely located near an
import table are not retained as resolved control flow.

A resolved pointer call or thunk uses the explicit target shape
`{"kind":"function-pointer","slot_rva":...,"rva":...}` in both the base graph and package. Its
control-flow evidence records the slot and resolved endpoint. For a direct call, the same decoded
instruction is retained as a paired data reference to `slot_rva`, preserving both call semantics
and the exact memory dependency. A thunk is checked only at its seeded first instruction and does
not require a paired data-reference record. If that instruction is also encountered during a
runtime-function sweep, an ordinary same-site reference to the non-IAT slot may be retained
independently. An internal endpoint covered by known `RUNTIME_FUNCTION` metadata is suppressed
unless its RVA matches a recorded runtime-function begin, preventing an interior label from being
promoted to a separate function entry.

The same instruction sweep retains exact RIP-relative data references from supported decoded
instructions. It excludes exact parsed-IAT call and jump operands. A resolved read-only pointer
call retains its required same-site slot reference; a resolved pointer thunk may independently have
the same reference when runtime traversal encounters it, but thunk validity never depends on that
record. A data target is accepted only when its computed RVA lies in file-backed, initialized,
readable, non-executable section data. The persisted relationship records caller, instruction RVA
and size, and target RVA; it does not guess a target name, object size, or access mode. The
independently versioned export projection derives string correlation later from the retained
canonical strings.

Thunk candidates come from deterministic seeds: runtime-function starts, the PE entry point, local
executable exports, internal direct-call targets, and validated RTTI virtual slots. Only a
candidate's first instruction is considered. Exact `E9 rel32` and `EB rel8` jumps may target
file-backed executable RVAs. Exact `FF 25 disp32` and `48 FF 25 disp32` jumps use the IAT-first,
one-hop pointer policy above. The original seed set is processed first in RVA order. Internal
function endpoints of retained thunks then form the next sorted layer, and that bounded causal
closure continues until no new endpoint remains. Every relationship retains its exact hop: a call
to `A` followed by thunks `A -> B -> C` stays one call plus `A -> B` and `B -> C`, never a flattened
call or thunk to `C`. A candidate is decoded once, so a connected cycle terminates while preserving
its exact non-self edges. Persisted thunk records must be reachable from the original seed set
through other retained internal thunk endpoints; a disconnected cycle is rejected. An import-IAT
target ends the executable chain. A self-targeting internal jump is not a thunk. Following an
executable endpoint does not relax the data policy: pointer-to-pointer slot chains remain
unsupported and each non-IAT slot is dereferenced at most once.

Decoding is deterministic and bounded to 64 MiB of instruction bytes, 1,000,000 instructions,
262,144 discovered block starts, 8,192 retained direct calls, 32,768 retained data references, and
4,096 retained thunks. Original thunk seeds have priority over later sorted endpoint layers. Each
relationship family retains its deterministic traversal prefix when its record cap is reached;
`code_recovery_scan_truncated` and
`data_reference_scan_truncated` preserve the applicable partial state. A pointer call is retained
only when its paired slot data reference is retained, so exhausting the data-reference cap also
makes the pointer-call result incomplete rather than publishing a call without its provenance.
Exhausting the shared
decode or block-discovery budget makes both instruction-derived sets partial. Overlapping
`RUNTIME_FUNCTION` ranges are preserved and traversed separately, with each decode charged to the
shared budgets, so adversarial overlap metadata can make the scan partial earlier.

The guided sweep is intentionally a heuristic-confidence source. It suppresses unreachable bytes
after terminal control flow and can reach a valid block after jump-over data, but reachable embedded
data can still decode as instructions and therefore retain a false positive. Invalid or unsupported
control flow can omit later relationships on that path. These records establish supported
control-flow relationships and function-entry evidence only. They do not recover source names,
persist basic blocks, infer function sizes, or provide a complete call graph.

### Persisted-record validation boundary

The package stores recovered values and relationships, but not the analyzed executable bytes.
During analysis, ReSymbol checks each string against its source bytes and derives each data
reference from the decoded instruction. On a later package read it can still enforce collection and
text limits, canonical ordering and uniqueness, non-overlap, encoding and exact encoded-size rules,
image and eligible-section ranges, runtime-function/site containment, pointer-slot read-only policy,
required same-site call/reference pairing, and graph agreement. It cannot independently compare a
persisted string with the original bytes, re-decode a persisted instruction, or reread the pointer
value because those bytes are absent. The envelope SHA-256 binds the records to one exact binary;
reanalyze that binary when byte-level reproduction is required.

## Export projection

`resymbol export` validates the package and reduces its combined symbol graph to a bounded,
deterministic projection for one exact binary. The projection retains binary identity, selected and
alternate names, confidence and provenance, supported function/global sizes, prototypes, type
definitions, attributed function-to-class memberships, and structured warnings. Ordering and
collision handling are stable so the same validated session produces the same projection.

The current neutral JSON projection is schema 6. Schema 4 added bounded, attributed `strings` and
`data_references` arrays to schema 3's function-entry, direct-call, and thunk model. Schema 5 added
`referenced_string_rva` to each data reference. Every data-reference object emits the field as a
string RVA or JSON `null`. A numeric value names the retained string when the target is its exact
RVA or a content-interior address; the NUL terminator is excluded, and UTF-16LE interior targets
must be code-unit aligned. `null` means only that no retained projected string matched, not that the
target bytes cannot contain a string. Correlation occurs after deterministic string conflict and
overlap reduction, so the field cannot name a discarded candidate. Schema 6 adds the explicit
`function-pointer` control-flow target with both `slot_rva` and the resolved function `rva`. A
retained pointer call or thunk preserves that slot provenance rather than flattening the relation
into an ordinary function target. Before pairing calls, projection deterministically reduces
competing data references by caller and instruction site. If the selected same-site reference
targets something other than the pointer slot, projection omits the pointer call and emits an
`unsupported-assertion` warning. Pointer thunks do not require that companion relationship.
Internal relation targets must reference projected function entries; import targets retain their
IAT RVA. Conventional and delay-IAT control flow uses that same import target; the ordered
delay-import inventory remains package-only and adds no neutral-projection field. Its
projection/model bounds are intentionally separate from the lower built-in recovery
caps: at most 65,536 strings, 32 MiB of retained string UTF-8 with 16 KiB per value, and 262,144
data references. A function retains at most 4,096 distinct memberships. Overflow is loss-aware
rather than order-dependent: ReSymbol keeps the deterministically strongest 4,096 and emits one
`class-membership-limit-exceeded` warning group for the function, with `occurrences` counting the
omitted distinct relationships.

The JSON export is the loss-aware interchange form. IDAPython and Ghidra Java writers consume the
same projection but currently apply only selected function/global names and conservative function
boundaries. That includes safe vftable global names, but not entry-only candidates, call/thunk
relationships, RTTI type creation, class-membership metadata, or invented names for virtual
functions. They do not silently imply that prototypes, types, competing names, relationships, or
unsupported claims were installed in the debugger.

The exact-RSDS PDB writer consumes the same validated session and projection plus an ephemeral
inspection of the exact original PE. It emits deterministic, bounded, pure-Rust MSF 7.00 output
containing selected public function and global names and verbatim section headers. Same-RVA
function/global collisions prefer the function; unnamed functions do not suppress globals. The
writer does not synthesize private symbols, compilands, source lines, locals, prototypes, function
extents, or type records, and it does not add fields to package schema 8 or neutral projection
schema 6. Generating the file requires no separately installed Visual Studio, DIA, LLVM, or
compiler toolchain; Windows compatibility CI validates it with native and DIA-backed
`llvm-pdbutil` reads and a direct DIA identity/public-symbol probe.

Export files use create-new writes and never replace an existing destination.

## Future packaging

The JSON envelope is deliberately separate from future distribution containers. Compression,
signatures, detached evidence, large indexes, or multi-binary workspaces can be added without making
the canonical graph a debugger-specific database.
