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
- Added `ControlFlowTarget` and the `FunctionEntry`, `DirectCall`, and `ThunkTarget` symbol
  assertions, plus PE recovery records and graph attribution for PE entry points, recovered targets,
  and validated RTTI virtual slots.
- Extended the external-process plugin wire schema with the corresponding function-entry,
  direct-call, thunk-target, internal-function, and import-IAT shapes already accepted by the host.
- Added deterministic control-flow and class-membership projection, including attributed function
  entries, calls, and thunks in neutral JSON. The IDAPython and Ghidra Java writers remain
  conservative and do not install those relationships.
- Added `ResymPackage::try_map_payload` so applications can migrate a payload after validating and
  preserving its package envelope.

### Changed

- New `.resym` analyses use package schema 2. The `PeAnalysis` public alpha model now carries code
  recovery records and partial-scan state.
- The debugger-neutral JSON projection now uses schema 3. The public alpha `ExportFunction` and
  `ExportProjection` structs gained entry attribution and control-flow relationship fields, and new
  export relationship types are public.
- `resymbol analyze` and `resymbol inspect` report recovered direct-call and thunk counts plus
  partial code-recovery status.

These public-struct field additions are source-breaking for downstream Rust code that constructs or
destructures the structs directly. ReSymbol is not yet 1.0; downstream users should pin an alpha
version and validate serialized schema versions independently.

### Compatibility

- The CLI can inspect and export package schema 1 through an explicit, validated in-memory
  migration. It revalidates persisted metadata, plugin runs and claims, binary binding, and rebuilds
  the deterministic base graph; it does not rewrite the legacy package. `inspect --json` preserves
  the validated original schema 1 representation instead of mislabeling migrated content.
- Schema 1 packages do not contain the original executable bytes, so migration cannot run the new
  decoder. Migrated direct-call and thunk sets remain empty and are not evidence that no
  relationships exist. Reanalyze the exact original binary to create a schema 2 package with code
  recovery.
- Package schema 2 and neutral projection schema 3 are independent version domains. Generic package
  readers still require an explicit compatibility range and application-defined payload migration
  to accept an older schema.

### Safety and limits

- Built-in code recovery is capped at 64 MiB of decoded instruction bytes, 1,000,000 instructions,
  8,192 retained direct calls, and 4,096 retained thunks. Exhaustion retains a deterministic prefix
  and marks recovery partial. Neutral projection validation retains separate, larger caps of
  262,144 calls and 65,536 thunks.
- Internal targets covered by known runtime-function metadata are suppressed unless their RVA
  matches a recorded runtime-function begin. A call to its own next instruction is not promoted to
  a function target. Overlapping runtime-function ranges may be swept and charged to decoder budgets
  separately.
- The decoder is heuristic-confidence evidence, not recursive disassembly. Post-terminator bytes or
  embedded data can produce false positives, while invalid instructions can omit later control flow
  in the affected range. Register-indirect control flow and complete call-graph recovery remain out
  of scope.
- RTTI discovery scans at most 64 MiB of eligible read-only data, retains at most 16 MiB of RTTI
  name text, and applies bounded candidate, vftable, hierarchy, base-record, and virtual-slot
  counts. A function retains at most 4,096 projected class memberships.
