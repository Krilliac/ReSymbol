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
- x64 `RUNTIME_FUNCTION` entries as evidence-backed candidate function boundaries; and
- a symbol graph containing exact export names and metadata-derived boundaries.

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

## Export projection

`resymbol export` validates the package and reduces its combined symbol graph to a bounded,
deterministic projection for one exact binary. The projection retains binary identity, selected and
alternate names, confidence and provenance, supported function/global sizes, prototypes, type
definitions, and structured warnings. Ordering and collision handling are stable so the same
validated session produces the same projection.

The JSON export is the loss-aware interchange form. IDAPython and Ghidra Java writers consume the
same projection but currently apply only selected function/global names and conservative function
boundaries. They do not silently imply that prototypes, types, competing names, or unsupported
claims were installed in the debugger. Export files use create-new writes and never replace an
existing destination.

## Future packaging

The JSON envelope is deliberately separate from future distribution containers. Compression,
signatures, detached evidence, large indexes, or multi-binary workspaces can be added without making
the canonical graph a debugger-specific database.
