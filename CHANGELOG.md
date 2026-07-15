# Changelog

All notable user-visible and compatibility-relevant changes to ReSymbol are recorded here. The
project is still in alpha, so public Rust APIs and serialized schemas may change between
prereleases; breaking changes remain explicit.

## Unreleased

### Added

- Added bounded modern MSVC x64 Rev1 RTTI and vftable discovery, including validated stored type
  names, base-class records, virtual-slot targets, vftable names, and attributed function-to-class
  relationships.
- Added a pure-Rust x86-64 decoder that performs a bounded linear sweep of fully file-backed
  `RUNTIME_FUNCTION` ranges for supported direct calls and checks metadata-backed entries for
  one-instruction internal or import thunks. No native disassembler library or compiler is needed
  to run a release build.
- Added bounded exact recovery of NUL-terminated printable ASCII and valid UTF-16LE strings from
  file-backed, initialized, readable, non-executable PE sections, with deterministic overlap
  handling and explicit partial-scan state.
- Added supported x64 RIP-relative data-reference recovery to eligible file-backed data, recording
  the caller, instruction RVA and size, and exact target RVA without inventing access semantics or
  target names.
- Added `ControlFlowTarget` and the `FunctionEntry`, `DirectCall`, and `ThunkTarget` symbol
  assertions, plus PE recovery records and graph attribution for PE entry points, recovered targets,
  and validated RTTI virtual slots.
- Extended the external-process plugin wire schema with the corresponding function-entry,
  direct-call, thunk-target, internal-function, and import-IAT shapes already accepted by the host.
- Added deterministic control-flow and class-membership projection, including attributed function
  entries, calls, and thunks in neutral JSON. The IDAPython and Ghidra Java writers remain
  conservative and do not install those relationships.
- Added attributed recovered strings and data references to the deterministic neutral projection.
  Neutral JSON preserves them, while the standalone debugger scripts do not install them yet.
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
- Added `ResymPackage::try_map_payload` so applications can migrate a payload after validating and
  preserving its package envelope.

### Changed

- New `.resym` analyses use package schema 3. The `PeAnalysis` public alpha model now carries
  recovered strings, data references, and independent partial-scan state in addition to code
  recovery records.
- The debugger-neutral JSON projection now uses schema 4. Its public alpha model adds attributed
  string and data-reference arrays to schema 3's entry attribution and control-flow relationships.
- `resymbol analyze` and `resymbol inspect` report recovered string, data-reference, direct-call,
  and thunk counts plus their applicable partial-recovery status.
- Address-kind collision diagnostics and both standalone debugger writers now share one
  mutation-aware rule: a same-RVA global is suppressed only when the writer actually emits a
  function record. Entry-only function evidence does not become a debugger mutation.

These public-struct field additions are source-breaking for downstream Rust code that constructs or
destructures the structs directly. ReSymbol is not yet 1.0; downstream users should pin an alpha
version and validate serialized schema versions independently.

### Compatibility

- The CLI can inspect and export package schemas 1 and 2 through explicit, validated in-memory
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
  direct calls and thunks, but predates strings and data references. Reanalyze the exact original
  binary to create a schema 3 package with current recovery.
- Package schema 3 and neutral projection schema 4 are independent version domains. Generic
  package readers still require an explicit compatibility range and application-defined payload
  migration to accept an older schema.
- Markdown export is presentation-only and does not change either version domain: new analyses
  continue to use package schema 3 and the neutral projection continues to use schema 4.
- MAP export consumes the current validated session and neutral projection without adding fields to
  package schema 3 or projection schema 4. PDB output remains planned.

### Safety and limits

- Built-in code recovery is capped at 64 MiB of decoded instruction bytes, 1,000,000 instructions,
  8,192 retained direct calls, 32,768 retained data references, and 4,096 retained thunks.
  Exhaustion retains deterministic valid results and marks the applicable relationship sets
  partial. Neutral projection validation applies separate, larger collection caps.
- Built-in string recovery scans at most 64 MiB, retains at most 16,384 literals and 4 MiB of UTF-8
  text in aggregate, and caps each exact value at 4 KiB UTF-8 and 4 KiB encoded data including its
  terminator. Reaching a limit never publishes a truncated prefix and records the scan as partial.
- Internal targets covered by known runtime-function metadata are suppressed unless their RVA
  matches a recorded runtime-function begin. A call to its own next instruction is not promoted to
  a function target. Overlapping runtime-function ranges may be swept and charged to decoder budgets
  separately.
- The decoder is heuristic-confidence evidence, not recursive disassembly. Post-terminator bytes or
  embedded data can produce false positives, while invalid instructions can omit later control flow
  in the affected range. Register-indirect control flow and complete call-graph recovery remain out
  of scope.
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
