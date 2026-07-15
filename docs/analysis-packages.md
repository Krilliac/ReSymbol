# ReSymbol analysis packages

ReSymbol writes analysis results to a portable `.resym` file. The initial format is canonical JSON:
it is easy to inspect, deterministic for the same analysis payload, and independent from IDA,
Ghidra, PDB, or DWARF data models.

Create, inspect, and export a package with the current CLI:

```console
resymbol analyze application.exe
resymbol inspect application.resym
resymbol inspect application.resym --json
resymbol export application.resym --format json
resymbol export application.resym --format markdown
resymbol export application.resym --format map
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
  "schema_version": 3
}
```

- `binary_sha256` binds every result to the exact bytes that were analyzed.
- `generator_version` identifies the ReSymbol build that produced the package.
- `schema_version` controls envelope compatibility independently from the application version.
- `payload` contains one validated `AnalysisSession`: deterministic base analysis, a plugin-run
  ledger, and accepted plugin claims.

This package envelope currently writes schema 3. The CLI can also inspect and export schema 1 and
schema 2 packages through the compatibility paths described below, while other schema versions
fail explicitly. The debugger-neutral JSON produced by `resymbol export --format json` is a
different artifact with its own schema version; its current projection is schema 4.

Object keys are sorted recursively and no timestamp is inserted, so encoding the same deterministic
payload produces the same bytes. Arrays preserve analysis order because source-table order can be
meaningful evidence.

## Safety and compatibility

Package reads are size-bounded and reject malformed binary identities, unsupported schema versions,
invalid payloads, and files that exceed the configured limit. Writes use create-new semantics: an
existing destination is never silently replaced.

A package must not be applied to a loaded program until its SHA-256 identity has been compared with
that program. A matching filename, product version, timestamp, or image size is insufficient.
ReSymbol's generated IDAPython and Ghidra Java scripts perform that exact SHA-256 check inside the
tool before making any database change. They then resolve projected RVAs against the loaded image
base instead of assuming the package's preferred virtual address. See [exporting.md](exporting.md)
for the application policy and current representational limits.

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
and the migrated session is not evidence that the decoder found no relationships. Analyze the exact
original executable again to create a schema 3 package containing current recovery results. Schema
2 packages retain their recorded calls and thunks, but predate recovered strings and data
references; those newer arrays are empty after compatibility decoding and are likewise reported as
unavailable rather than as a complete empty scan. The `inspect` and `export` terminal summaries
distinguish those cases and recommend reanalysis. `inspect --json` emits the validated original
schema 1 representation rather than placing the migrated current payload beneath a legacy schema
label.

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
- bounded section, import, export, and exception-directory records;
- x64 `RUNTIME_FUNCTION` entries as evidence-backed candidate function boundaries;
- bounded direct-call and one-instruction thunk records, with explicit internal-function or exact
  parsed import-IAT targets and a persisted partial-scan flag;
- bounded NUL-terminated ASCII and UTF-16LE strings plus exact x64 RIP-relative references to
  eligible data, each with independent persisted partial-scan state;
- validated modern MSVC x64 Rev1 RTTI records, including type descriptors, class hierarchy and
  base-class records, vftable locations, and executable virtual-slot targets; and
- a symbol graph containing exact export names, metadata-derived boundaries, function entries,
  direct calls, thunks, string literals, data references, recovered RTTI type names, vftable names,
  and class-membership claims for virtual-slot targets.

ReSymbol derives the combined symbol graph from the base graph plus `plugin_claims`; it does not
serialize a second independently mutable graph. Session validation rejects duplicate run IDs,
noncanonical artifact fingerprints or versions, claims for another binary or an out-of-image range,
producer/run mismatches, invalid subject/assertion combinations, and ledger counts that do not
match the accepted claims.

Plugin execution is transactional. A failed process run contributes no claims, so an invalid,
crashed, timed-out, or quarantined plugin cannot corrupt the deterministic base analysis. Ordinary
analysis still writes a valid package after such a failure. With `--strict-plugins`, ReSymbol writes
the package first and then returns a failure status if an explicitly selected or otherwise eligible
plugin could not complete successfully.

The package does not contain the analyzed executable itself. It also does not claim to recover an
original source name when only a reconstructed or inferred name is available.

### MSVC x64 RTTI boundary

The built-in RTTI pass follows a pointer immediately before each candidate vftable and accepts a
record only when its complete object locator, type descriptor, class hierarchy, base-class array,
base descriptors, and executable file-backed slot targets agree. Invalid candidates are discarded
atomically; their partial data is not added to the package or graph. Repeated base-descriptor RVAs
and shared complete object locators are preserved because both are valid compiler output.

This initial slice deliberately supports the modern MSVC x64 Rev1 layout: a 24-byte complete object
locator and 28-byte base-class descriptors carrying the `BCD_HASPCHD` bit and a nonzero nested
class-hierarchy RVA. Older 24-byte base-class descriptors, x86 RTTI, and other ABI variants are not
silently interpreted as this format.

Candidate scanning and accepted vftables/back-pointers, complete object locators, class-hierarchy
descriptors, base-class arrays, base-class descriptors, and nested hierarchy descriptors are
restricted to file-backed, initialized, readable, read-only, non-executable data. Referenced
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

The built-in code-recovery pass is a bounded linear sweep over complete, file-backed executable
ranges supplied by the PE x64 exception directory; it is not a recursive traversal of reachable
basic blocks. It recognizes exact five-byte `E8 rel32` calls to file-backed executable RVAs and
exact six-byte RIP-relative `FF 15` calls whose computed address is a parsed IAT slot. It does not
retain other indirect-call forms or targets merely located near an import table. An internal target
covered by known `RUNTIME_FUNCTION` metadata is suppressed unless its RVA matches a recorded
runtime-function begin, preventing an interior label from being promoted to a separate function
entry.

The same instruction sweep retains exact RIP-relative data references from supported decoded
instructions. It excludes call and jump operands already represented as control flow and accepts a
target only when the computed RVA lies in file-backed, initialized, readable,
non-executable section data. The relationship records caller, instruction RVA and size, and target
RVA; it does not guess a target name, object size, access mode, or whether the target is a string.

Thunk candidates come from metadata-backed entry points: runtime-function starts, the PE entry
point, local executable exports, internal direct-call targets, and validated RTTI virtual slots.
Only a candidate's first instruction is considered. Exact `E9 rel32` and `EB rel8` jumps may target
file-backed executable RVAs; exact RIP-relative `FF 25` jumps must target a parsed IAT slot. A
self-targeting internal jump is not a thunk.

Decoding is deterministic and bounded to 64 MiB of instruction bytes, 1,000,000 instructions,
8,192 retained direct calls, 32,768 retained data references, and 4,096 retained thunks. Each
relationship family retains its deterministic canonical prefix when its record cap is reached;
`code_recovery_scan_truncated` and `data_reference_scan_truncated` preserve the applicable partial
state. Exhausting the shared decode budget makes both instruction-derived sets partial.
Overlapping `RUNTIME_FUNCTION` ranges are preserved and may be swept and charged to these budgets
separately, so adversarial overlap metadata can make the scan partial earlier.

Linear sweep is intentionally a heuristic-confidence source: it can decode bytes after a terminator
or embedded data as instructions and therefore retain a false positive, while an invalid encoding
stops the affected range and can omit valid control flow located later in that range. These records
establish supported control-flow relationships and function-entry evidence only. They do not
recover source names, basic blocks, function sizes, or a complete call graph.

### Persisted-record validation boundary

The package stores recovered values and relationships, but not the analyzed executable bytes.
During analysis, ReSymbol checks each string against its source bytes and derives each data
reference from the decoded instruction. On a later package read it can still enforce collection and
text limits, canonical ordering and uniqueness, non-overlap, encoding and exact encoded-size rules,
image and eligible-section ranges, runtime-function/site containment, and graph agreement. It
cannot independently compare a persisted string with the original bytes or re-decode a persisted
instruction because those bytes are absent. The envelope SHA-256 binds the records to one exact
binary; reanalyze that binary when byte-level reproduction is required.

## Export projection

`resymbol export` validates the package and reduces its combined symbol graph to a bounded,
deterministic projection for one exact binary. The projection retains binary identity, selected and
alternate names, confidence and provenance, supported function/global sizes, prototypes, type
definitions, attributed function-to-class memberships, and structured warnings. Ordering and
collision handling are stable so the same validated session produces the same projection.

The current neutral JSON projection is schema 4. It adds bounded, attributed `strings` and
`data_references` arrays to schema 3's function-entry, direct-call, and thunk model.
Internal relation targets must reference projected function entries; import targets retain their
IAT RVA. Its projection/model bounds are intentionally separate from the lower built-in recovery
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
Export files use create-new writes and never replace an existing destination.

## Future packaging

The JSON envelope is deliberately separate from future distribution containers. Compression,
signatures, detached evidence, large indexes, or multi-binary workspaces can be added without making
the canonical graph a debugger-specific database.
