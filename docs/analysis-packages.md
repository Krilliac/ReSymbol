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
  "schema_version": 1
}
```

- `binary_sha256` binds every result to the exact bytes that were analyzed.
- `generator_version` identifies the ReSymbol build that produced the package.
- `schema_version` controls envelope compatibility independently from the application version.
- `payload` contains one validated `AnalysisSession`: deterministic base analysis, a plugin-run
  ledger, and accepted plugin claims.

This package envelope currently uses schema 1. The debugger-neutral JSON produced by
`resymbol export --format json` is a different artifact with its own schema version; its current
relationship-bearing projection is schema 2.

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
- validated modern MSVC x64 Rev1 RTTI records, including type descriptors, class hierarchy and
  base-class records, vftable locations, and executable virtual-slot targets; and
- a symbol graph containing exact export names, metadata-derived boundaries, recovered RTTI type
  names, vftable names, and class-membership claims for virtual-slot targets.

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

## Export projection

`resymbol export` validates the package and reduces its combined symbol graph to a bounded,
deterministic projection for one exact binary. The projection retains binary identity, selected and
alternate names, confidence and provenance, supported function/global sizes, prototypes, type
definitions, attributed function-to-class memberships, and structured warnings. Ordering and
collision handling are stable so the same validated session produces the same projection.

The current neutral JSON projection is schema 2, which represents each attributed function-to-class
relationship in that function's `class_memberships` array. A function retains at most 4,096
distinct memberships. Overflow is loss-aware rather than order-dependent: ReSymbol keeps the
deterministically strongest 4,096 and emits one `class-membership-limit-exceeded` warning group for
the function, with `occurrences` counting the omitted distinct relationships.

The JSON export is the loss-aware interchange form. IDAPython and Ghidra Java writers consume the
same projection but currently apply only selected function/global names and conservative function
boundaries. That includes safe vftable global names, but not RTTI type creation, class-membership
metadata, or invented names for virtual functions. They do not silently imply that prototypes,
types, competing names, relationships, or unsupported claims were installed in the debugger.
Export files use create-new writes and never replace an existing destination.

## Future packaging

The JSON envelope is deliberately separate from future distribution containers. Compression,
signatures, detached evidence, large indexes, or multi-binary workspaces can be added without making
the canonical graph a debugger-specific database.
