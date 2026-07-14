# ReSymbol analysis packages

ReSymbol writes analysis results to a portable `.resym` file. The initial format is canonical JSON:
it is easy to inspect, deterministic for the same analysis payload, and independent from IDA,
Ghidra, PDB, or DWARF data models.

Create and inspect a package with the current CLI:

```console
resymbol analyze application.exe
resymbol inspect application.resym
resymbol inspect application.resym --json
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
- `payload` contains the format-specific analysis record and validated symbol graph.

Object keys are sorted recursively and no timestamp is inserted, so encoding the same deterministic
payload produces the same bytes. Arrays preserve analysis order because source-table order can be
meaningful evidence.

## Safety and compatibility

Package reads are size-bounded and reject malformed binary identities, unsupported schema versions,
invalid payloads, and files that exceed the configured limit. Writes use create-new semantics: an
existing destination is never silently replaced.

A package must not be applied to a loaded program until its SHA-256 identity has been compared with
that program. A matching filename, product version, timestamp, or image size is insufficient.

Schema changes and plugin API changes are versioned separately. Before ReSymbol 1.0, payload fields
may evolve between prereleases, but an incompatible reader must fail explicitly instead of guessing.

## Current payload

The first payload records PE32+ x86-64 metadata:

- normalized binary identity and image metadata;
- COFF and optional-header fields used by analysis;
- bounded section, import, export, and exception-directory records;
- x64 `RUNTIME_FUNCTION` entries as evidence-backed candidate function boundaries; and
- a symbol graph containing exact export names and metadata-derived boundaries.

The package does not contain the analyzed executable itself. It also does not claim to recover an
original source name when only a reconstructed or inferred name is available.

## Future packaging

The JSON envelope is deliberately separate from future distribution containers. Compression,
signatures, detached evidence, large indexes, or multi-binary workspaces can be added without making
the canonical graph a debugger-specific database.
