# Export ReSymbol results

`resymbol export` turns one validated `.resym` analysis package into a deterministic,
debugger-neutral JSON projection, a bounded human-readable Markdown report,
Microsoft-linker-style MAP text, an exact-RSDS public-symbol PDB, or a self-contained import script
for IDA or Ghidra.

```console
resymbol export PACKAGE --format json [--output PATH]
resymbol export PACKAGE --format markdown [--output PATH]
resymbol export PACKAGE --format map [--output PATH]
resymbol export PACKAGE --format pdb --binary EXACT_ORIGINAL_PE [--output PATH]
resymbol export PACKAGE --format ida-python [--output PATH]
resymbol export PACKAGE --format ghidra-java [--output PATH]
```

The current formats are deliberately small and auditable. JSON is the machine-consumable
interchange artifact, Markdown is a presentation-only report for review, MAP is PE-only text for
tools that support the Microsoft-linker-style layout, PDB is an exact-identity public-symbol export,
and the scripts apply a conservative subset inside their target debugger. They do not require a
ReSymbol plugin or compiler. Ordinary PDB generation is offline and requires no Visual Studio,
LLVM, or DIA installation. Richer type application and interactive in-tool bridges are later
milestones.

## Output paths and overwrite policy

Without `--output`, ReSymbol chooses a deterministic destination beside the package:

| Format | Package | Default output |
|---|---|---|
| `json` | `application.resym` | `application.symbols.json` |
| `markdown` | `application.resym` | `application.symbols.md` |
| `map` | `application.resym` | `application.map` |
| `pdb` | `application.resym` | `application.pdb` |
| `ida-python` | `application.resym` | `application.ida.py` |
| `ghidra-java` | `application.resym` | `ReSymbolImport_<sha12>.java` |

`<sha12>` is the first 12 hexadecimal characters of the analyzed binary's SHA-256. The hash-based
Ghidra name is stable for the exact binary and gives the generated script a conservative Java class
name.

All formats use create-new writes. ReSymbol stages and flushes the complete artifact beside its
destination, then publishes it without replacing an existing path, so a failed write does not leave
a truncated final export. Choose another path with `--output`, move the old export, or remove it
intentionally before exporting again.

A custom Ghidra output must use a lowercase `.java` extension. Its filename stem becomes the
generated public class name and therefore must be a conservative Java identifier: 1 to 128 ASCII
bytes, beginning with an ASCII letter, `_`, or `$`, followed only by ASCII letters, digits, `_`, or
`$`, and not a Java keyword. For example:

```console
resymbol export application.resym \
  --format ghidra-java \
  --output ReviewedSymbols.java
```

The generated source then contains `public class ReviewedSymbols`; renaming only the file afterward
will make Ghidra's Java compilation fail. Regenerate the export under the desired filename instead.

The MAP header's display module name is derived from the package filename stem, independently from
the output filename. Every non-ASCII byte or byte outside `[A-Za-z0-9_.-]` becomes `_`, and the
result is capped at 255 bytes. An empty or non-UTF-8 stem, or a result equal to `.` or `..`, uses the
deterministic fallback `resymbol_<sha12>`. Thus `My App.resym` produces `My_App`. Supplying a custom
MAP `--output` path does not change that module name.

## Safety model

Before writing any format, ReSymbol validates the package, derives its combined symbol graph, and
reduces that graph to a bounded export projection. The projection is tied to one exact binary
SHA-256 and uses RVAs rather than assuming a process or debugger load address.

After a successful write, the CLI prints the destination, binary SHA-256, projected entity counts,
and a bounded summary of projection warning groups. For schemas 1 through 6 it also reports TLS
callback recovery as unavailable; for schemas 1 through 7 it reports delay-import recovery as
unavailable; for schemas 1 through 8 it reports GuardCF recovery as unavailable; and for schemas 1
through 9 it reports the modern Guard target inventories as unavailable; for schemas 1 through 10
it reports the earlier load-config security anchors as unavailable; and for schemas 1 through 11
it reports XFG/CastGuard anchors as unavailable; and for schemas 1 through 12 it reports the
GuardMemcpy pointer-slot anchor as unavailable. These
diagnostics direct the user to reanalyze the exact original binary.
Inspect the warnings before applying a script; the output file is still created when a deliberate
lossy reduction is safe and diagnosed.

Both generated debugger scripts enforce the same application rules:

1. Read the SHA-256 recorded by the tool for the loaded input.
2. Abort before the first database mutation if the hash is missing or does not exactly match.
3. Resolve every symbol as the tool's current image base plus its RVA, which supports normal
   rebasing without weakening the identity check.
4. Preserve existing user-authored names and avoid replacing an existing function body.
5. Validate mapped addresses and ranges before applying them.
6. Report a per-symbol failure and continue with other independent symbols when safe.

A matching hash prevents accidental application to another build; it does not establish that every
claim in the package is trustworthy. Review the package's provenance and the generated source when
using results from someone else. Running an import script changes the current IDA database or
Ghidra program, so use the host tool's normal backup/versioning workflow for important projects.

PDB export has an additional pre-write gate: `--binary` must name the exact original PE used to
create the package. ReSymbol hashes those bytes, matches their identity and PE metadata against the
session, and reads the CodeView identity and raw section headers directly from that file. The PE is
opened read-only for inspection and is never patched or rewritten.

## JSON projection

The `json` format is the loss-aware interchange output. It retains:

- exact binary identity, architecture, preferred image base, and virtual image size;
- selected collision-safe output names and their source spellings;
- competing names, confidence, and producer/run provenance;
- supported function and global boundaries;
- recovered function prototypes and type definitions that fit the neutral model;
- attributed function entries, direct calls (including explicit read-only pointer-slot and resolved
  endpoint provenance), one-instruction thunks, and function-to-class membership relationships;
- attributed recovered strings and exact supported data-reference relationships; and
- structured, counted warnings for information that was reduced or omitted.

The current neutral export uses `schema_version: 6`. Schema 4 added top-level attributed `strings`
and `data_references` arrays to schema 3's function-entry, direct-call, and thunk model; schema 5
added deterministic string correlation to each data reference. Schema 6 adds the
`function-pointer` control-flow target with both `slot_rva` and resolved function `rva`. This
projection schema is independent from the `.resym` package-envelope schema; consumers must validate
the version of the artifact they are actually reading.

The CLI can export package schemas 1 through 12 through validated in-memory compatibility paths.
Migration neither rewrites the package nor reruns analysis: the package does not embed executable
bytes. Schema 1 therefore has no available direct calls, thunks, strings, or data references.
Schema 2 retains its persisted calls and thunks but predates strings and data references. Schema 3
retains those records, but schemas 2 and 3 both predate read-only function-pointer call and thunk
resolution. Schema 4 retains pointer control flow but predates legacy 24-byte MSVC RTTI base-class
descriptor recovery. Schema 5 records both RTTI descriptor layouts but predates transitive
executable thunk-chain discovery. Schema 6 records that closure but predates TLS callback
discovery and callback-based thunk seeding. Schema 7 records TLS callbacks but predates modern
delay-import recovery. Schema 8 records delay imports but predates load-config GuardCF recovery.
Schema 9 records GuardCF functions but predates the Guard address-taken IAT, long-jump, and
EH-continuation inventories. Schema 10 records those inventories but predates checked
security-cookie and GuardCF check/dispatch pointer-slot anchors. Schema 11 records those anchors but
predates XFG and CastGuard storage anchors. Schema 12 records XFG/CastGuard anchors but predates the
GuardMemcpy pointer-slot anchor. Reanalyze the exact original binary to produce schema 13
before expecting all current recovery
relationships in the export. Schemas 1 through 4 reject
relabeled RTTI base records whose `class_hierarchy_descriptor_rva` is missing or null, and schemas 1
through 5 reject a deterministic base thunk source valid only through schema-6 endpoint seeding.
Schemas 1 through 6 reject schema-7 TLS fields, core `pe-tls-callback` claims, and callback-only
base thunk seeds rather than accepting a relabeled package. Schemas 1 through 7 likewise reject
schema-8 delay-import directory and inventory fields, while schemas 8 through 13 require the explicit
`delay_imports` inventory even when empty.
Schemas 1 through 8 reject schema-9 load-config/GuardCF fields,
`directories.load_config`, and core `pe-guard-cf-function` claims; schemas 9 through 13 require an explicit
`guard_cf_functions` inventory even when empty.
Schemas 1 through 9 reject schema-10 Guard address-taken IAT, long-jump, and EH-continuation
table-RVA and inventory fields; schemas 10 through 13 require all three inventory arrays even when
empty. Schemas 1 through 10 reject the schema-11 `load_config_security_anchors` object; schemas 11
through 13 require that object even when every anchor is absent. Schemas 1 through 11 reject the
schema-12 `load_config_xfg_anchors` object; schemas 12 and 13 require it even when all four anchors
are absent. Schemas 1 through 12 reject schema-13 `load_config_guard_memcpy_anchor`; schema 13
requires it even when the anchor is absent.

Entries are emitted in stable order. Name and range conflicts are resolved conservatively, and
colliding selected names receive deterministic output suffixes rather than silently referring to
the same debugger symbol.

The projection's `address-kind-collision` warning states the mutation-aware rule verbatim:

```text
function and global claims share an RVA; debugger bridges suppress the global only when they emit a function record
```

A selected function name or an accepted function size produces such a record; entry-only function
evidence does not. The named global can therefore still be offered for an entry-only collision,
subject to the debugger-state checks described below.

The JSON projection is not a PDB, MAP file, IDA database, or Ghidra project. It is the common input
to target-specific writers and a useful artifact for plugins, review tools, and future exporters.

### Control-flow projection

A projected function may carry `entry_attribution` even when no safe name or size is known. Each
direct-call record identifies its caller entry, call-site RVA, target kind, and attribution. Each
thunk record identifies its entry RVA, selected target kind, and attribution. Internal targets
reference another projected function entry; import targets retain an IAT-slot RVA. A retained
function-pointer target preserves both the read-only slot RVA and resolved function RVA rather than
flattening the indirection. Relations are canonical, bounded to 262,144 direct calls and 65,536
thunks, and validated against the binary's virtual image. These are neutral projection/model caps,
not the built-in decoder's lower recovery caps of 8,192 direct calls and 4,096 thunks. During
analysis, the built-in producer additionally checks exact parsed conventional/delay IAT membership, file-backed
instruction bytes, and the section properties used to resolve any pointer slot.

An executable thunk chain remains a sequence of exact relationships. A call to `A` followed by
`A -> B -> C` projects as that call and two thunk records; projection never substitutes `C` as a
canonical terminal target. Each internal hop references a projected function entry. Connected
cycles are representable as exact non-self edges, while the validated built-in base analysis rejects
cycles disconnected from its deterministic initial thunk seeds. This uses the existing projection
schema 6 relationship model and does not add a chain-depth or terminal-target field.

The ordered TLS directory and callback-table records, including each retained `FunctionEntry`
claim's exact slot/index evidence, remain package/base-graph-only. A callback target can contribute
its `pe-tls-callback` provenance to the existing entry-attribution model, where duplicate claims for
one RVA reduce to one selected attribution; a callback-seeded exact thunk projects through the
existing per-hop relationship. No TLS-specific field is added to neutral projection schema 6, and
callbacks seed only the first-instruction thunk check rather than a body sweep.

The ordered load-config/GFIDS inventory and suppression evidence remain package-only. Every
structurally valid GuardCF record keeps its exact opaque metadata, emits the existing attributed
function entry, and joins one-instruction thunk seeding, including records marked
`IMAGE_GUARD_FLAG_FID_SUPPRESSED`, `IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED`, or both. FID suppression
describes CFG eligibility rather than whether the target is a function; an export-suppressed RVA
must be 16-byte aligned. A thunk relationship appears only when the seeded RVA contains a supported exact
thunk. No GuardCF-specific field or relationship is added to neutral projection schema 6.

The Guard address-taken IAT, long-jump, and EH-continuation inventories are also package-only.
GIAT entries identify import slots and the continuation tables identify valid landing addresses,
not necessarily function starts. ReSymbol therefore emits no function-entry or thunk relationship
from these records, and neutral projection schema 6 remains unchanged.

The checked load-config security, XFG/CastGuard, and GuardMemcpy storage anchors are package-only
and create no claims or thunk seeds. They therefore add no field or relationship to neutral
projection schema 6.

The ordered delay-import descriptors and inventory likewise remain package-only. That inventory
retains the DLL name, descriptor RVA and exact attributes value, name/HMOD/IAT/INT base RVAs,
optional BIAT/UIAT base RVAs, each entry's lookup/IAT RVAs and hint/name or ordinal, and the
timestamp, but not raw INT/IAT/BIAT/UIAT array contents. Delay-IAT slots still participate in
projected control flow through the existing import target containing the slot RVA. Conventional and
delay-IAT membership both outrank read-only
function-pointer fallback; no delay-import-specific field or target is added to neutral projection
schema 6.

Built-in control-flow recovery is a bounded control-flow-guided block sweep with heuristic
confidence, not a complete recursive disassembler. It recognizes only exact RIP-relative
`FF 15 disp32` and redundant-`REX.W` `48 FF 15 disp32` indirect-call encodings. At a deterministic
thunk seed it recognizes exact `FF 25 disp32` and `48 FF 25 disp32` indirect-jump encodings. Exact
parsed IAT membership takes precedence. A non-IAT slot must be fully backed for all
eight bytes in initialized, readable, non-writable, non-executable data; its little-endian
preferred-image VA is resolved exactly one hop to file-backed executable code. The resolved call or
thunk carries explicit slot provenance. A pointer call's instruction is also retained as a paired
data reference to that slot; a pointer thunk does not require one. Pointer-to-pointer slot chains,
writable slots, and other indirect forms are not projected as resolved control flow. A resolved
executable endpoint may itself seed another exact thunk hop, but the pointer slot is never
dereferenced a second time.

Before pairing relations, projection deterministically reduces competing data references by caller
and instruction site. A pointer call is retained only when the selected same-site reference targets
its slot. If a conflicting noncompanion reference wins that reduction, projection omits the pointer
call and emits an `unsupported-assertion` warning instead of flattening or inventing provenance.

The sweep suppresses unreachable post-terminal bytes and can follow supported branches across
jump-over data, but reachable embedded data can still produce false positives, and invalid or
unsupported flow can omit later calls on the affected path. Internal targets covered by known
runtime-function metadata are suppressed unless their RVA matches a recorded runtime-function
begin or a retained GuardCF function start. Consumers must therefore treat the
projected relation set as evidence, not as a complete call graph.

Entry evidence is deliberately not a name or an extent. The standalone IDA and Ghidra writers skip
entry-only functions and currently do not install call or thunk relationships; those records remain
available in neutral JSON for review and future richer bridges. A normal named or bounded function
continues to use the existing conservative application policy.

### String and data-reference projection

Each projected string records its encoding, RVA, encoded byte size, exact recovered value, and
attribution. Each projected data reference records the enclosing caller entry, instruction RVA and
decoded size, exact target RVA, attribution, and `referenced_string_rva`. Every current
data-reference record emits that field as the retained string RVA or JSON `null`. A numeric value
means the target is the string's exact RVA or lies within its encoded content. The NUL terminator is
excluded, and a UTF-16LE interior target must be aligned to a two-byte code unit relative to the
string start.
Correlation is computed after deterministic string conflict and overlap reduction. A `null` value
means no retained projected string matched; it does not prove the target bytes are not a string.
The relationship still does not assert an access mode, target object size, or target name.

The Markdown `Strings` table uses `Encoding`, `RVA`, `Byte size`, `Value`, `Confidence`, and
`Source` columns. `Data references` uses `Caller RVA`, `Instruction RVA`, `Instruction size`,
`Target RVA`, `Referenced string RVA`, `Confidence`, and `Source`. The correlation cell is `-` when
no retained string matches. The `Source` cells retain producer/method provenance; the presentation
report does not discard attribution.

The neutral projection accepts at most 65,536 strings, 32 MiB of retained string UTF-8 in
aggregate, 16 KiB of UTF-8 per string, and 262,144 data references. These model-validation bounds
are intentionally separate from the lower built-in recovery caps below so future or plugin-backed
sources can still use the common interchange model without weakening its resource limits.

Built-in string recovery scans complete raw ranges in file-backed, initialized, readable,
non-executable sections, including writable data. ASCII must be printable and UTF-16LE must begin at
an even RVA and decode without control characters or unpaired surrogates. Both forms require a NUL
terminator, at least four code points, and non-whitespace content. The scan is capped at 64 MiB,
16,384 retained strings, 4 KiB UTF-8 and 4 KiB encoded data per value (including the terminator),
and 4 MiB of retained UTF-8 text in aggregate. Overlaps are resolved deterministically, and reaching
a limit sets `string_recovery_scan_truncated` instead of publishing a truncated prefix.

Built-in data-reference recovery shares the bounded x86-64 instruction sweep described above and
retains at most 32,768 supported RIP-relative references. Call and jump operands are excluded; the
computed target must fall in file-backed, initialized, readable, non-executable data.
Exhausting the shared 64 MiB or 1,000,000-instruction budget makes both instruction-derived result
families partial, while reaching only the data-reference cap sets
`data_reference_scan_truncated` independently.

A package read can validate canonical ordering, uniqueness, collection and text limits, string
encoding and encoded size, address containment, and agreement with the persisted graph. It cannot
independently compare a string with its original bytes or re-decode a reference instruction because
the `.resym` file does not embed the executable. The package SHA-256 binds the records to the exact
input; reanalyze that binary when byte-level reproduction is required. The current standalone IDA
and Ghidra writers do not install string literals or data-reference relationships.

### RTTI-derived projection

Validated modern MSVC x64 RTTI contributes recovered type-descriptor names, selected global names
for vftables, and attributed class-membership relationships for executable virtual-slot targets.
The neutral JSON projection retains those function-to-class relationships with confidence and
provenance. The complete base-class/PMD records remain in the source `.resym` package; the current
neutral projection does not yet turn them into a general inheritance type model.
Supporting the legacy descriptor therefore does not change neutral projection schema 6.

Each function retains at most 4,096 distinct class memberships. If more are projected, ReSymbol
deterministically keeps the strongest 4,096 according to the normal producer-authority,
confidence, and stable tie-break ordering. The remaining distinct relationships are omitted under
one `class-membership-limit-exceeded` warning group for that function, whose `occurrences` value
counts the overflow reductions.

The source records deliberately support both MSVC x64 Rev1 base-class descriptor layouts. A clear
`BCD_HASPCHD` bit selects the legacy 24-byte form with no `pCHD`; a set bit selects the 28-byte form
and requires a valid nonzero `pCHD`. A hierarchy may mix the forms. An extended root must point to
its owning CHD, while a legacy root is validated without inventing a link. Candidate scanning and
the vftable/back-pointer, COL, CHD, BCA, BCD, and any referenced nested-CHD records remain
restricted to file-backed read-only initialized non-executable data. Referenced
TypeDescriptors may occupy file-backed initialized readable non-executable data, including normal
writable `.data`, but writable sections are never candidate-scanned. Discovery is bounded and may
be partial: when the section-scan or aggregate model budget is exhausted, the package retains
validated results and sets `msvc_rtti_scan_truncated`. Inspect that flag before treating the
projected set as exhaustive.

MSVC RTTI does not encode a vftable slot count. ReSymbol therefore derives virtual-slot extent with
a bounded contiguous-pointer heuristic that stops at the first target that is not in-image,
file-backed executable code. A relationship means that the target occupied a validated candidate
slot; it is not an authoritative table-size claim or a recovered source-level method name.

The IDA and Ghidra scripts can apply a projected vftable global name when the address and existing
tool state permit it. They do not create RTTI types, install class-membership metadata, or invent
names for virtual functions. This keeps compiler metadata distinct from a source-level method name
that may no longer exist in the binary.

## Markdown report

Generate a report for review in a text editor, repository, or Markdown viewer:

```console
resymbol export application.resym --format markdown
```

The default destination is `application.symbols.md`. The writer renders the already validated
neutral projection in deterministic order; it does not reanalyze the executable, modify a debugger
database, or add claims to the package. Its fixed section order is:

1. `# ReSymbol Analysis Report`
2. `## Binary identity`
3. `## Summary`
4. `## Functions`
5. `## Globals`
6. `## Types`
7. `## Strings`
8. `## Direct calls`
9. `## Data references`
10. `## Thunks`
11. `## Warnings`

The report is a presentation of the existing projection and does not add a new symbol or
relationship model. Missing categories and row counts are represented consistently so two reports
from the same projection compare cleanly. A function-pointer target is rendered as
`function 0x... via pointer slot 0x...`, preserving the same endpoint and slot provenance as the
schema-6 JSON record.

Markdown is a human-facing presentation format, not a stable interchange contract. Its wording,
table layout, and section organization may evolve between alpha releases. Tools should consume the
`json` output and validate its `schema_version` instead of parsing the report. New analyses write
package schema 13; export also accepts package schemas 1 through 12 through validated compatibility
paths without rewriting them. The current neutral projection is schema 6, and adding this writer
changes neither independently versioned domain.

The report writer applies limits in addition to the projection's own validation bounds:

- each tabular section contains at most 1,024 rows;
- projection text supplied to each table cell has a 256-byte pre-escape budget; and
- the complete UTF-8 report cannot exceed 16 MiB.

Each row-bearing section includes a deterministic notice in this form, including when zero rows are
omitted: `_Showing N of T rows; O omitted by the 1,024-row report limit._` Projection text is
UTF-8-truncated before escaping, with the 256-byte cell budget including the explicit
`… [truncated]` marker. GitHub-Flavored Markdown control punctuation is backslash-escaped, while
`&`, `<`, and `>` are emitted as entities. This prevents projection text from creating table
columns, raw HTML, or unintended entities. If the complete rendered document would exceed 16 MiB,
export fails before creating the output file. These are report-writer limits only; they do not
silently reduce the JSON projection or rewrite the `.resym` package.

## Microsoft-linker-style MAP text

Generate PE MAP text for a consumer that supports a Microsoft-linker-style layout:

```console
resymbol export application.resym --format map
```

The default destination is `application.map`. This is a deterministic text export, not a claim that
every debugger or linker will accept it. ReSymbol currently rejects non-PE sessions and
projections, mismatched session/projection binary fields, selected symbol RVAs outside real PE
sections, and a nonzero entry point outside those sections. New analyses write package schema 13;
export also accepts package schemas 1 through 12 through validated compatibility paths without
rewriting them. The current neutral projection is schema 6, and MAP adds no schema fields.

The writer emits the PE timestamp and preferred load address, one group for each final PE section,
selected public names in RVA order, and the entry-point `section:offset`. Section numbers are
one-based and offsets are relative to the section's virtual address. The `Rva+Base` column is the
preferred image base plus each symbol RVA. Section length uses `VirtualSize` when nonzero and falls
back to `SizeOfRawData` only when `VirtualSize` is zero, so raw file-alignment padding is not mapped
as loaded RVA space. Section bytes safe in the whitespace-delimited format are retained; unsafe
bytes become
`_xhh_` escapes with lowercase hexadecimal digits (for example, a space byte becomes `_x20_`), and
an empty raw name becomes `_x00_`.

Only functions and globals with a selected output name are emitted. A selected function wins over
a selected global at the same RVA; an unnamed function suppresses nothing. This target-specific
rule does not alter the projection warning or the mutating-script policy described above: IDA and
Ghidra suppress a same-RVA global only when they actually emit a function record. Every MAP row uses
`<resymbol>` as explicit synthetic provenance because a parsed final image does not retain a
trustworthy source object/COMDAT mapping.

The header includes semicolon-prefixed comments with the exact binary SHA-256, exact file size, and
virtual image size. Those comments are conventional ReSymbol additions, not fields guaranteed by
Microsoft's published `/MAP` contract. More importantly, text MAP consumers cannot enforce the
identity check performed by the generated IDA and Ghidra scripts. Compare the exact executable's
SHA-256 and file size manually before relying on the symbols, and independently verify compatibility
when a consumer requires byte-for-byte `link.exe` output.

MAP generation counts selected function/global candidates before same-RVA collision reduction and
rejects more than 262,144. The complete UTF-8 output is capped at 64 MiB. Either condition fails
before the create-new destination is written. MAP currently carries selected names and section
addresses only; prototypes, types, alternate names, confidence, recovered strings, relationships,
and other rich projection data remain available through JSON.

## Exact-RSDS public-symbol PDB

Generate a synthetic PDB for the exact original PE represented by the package:

```console
resymbol export application.resym --format pdb --binary application.exe
```

Without `--output`, the destination is `application.pdb` beside the package. PDB uses the same
create-new policy as every other export and never replaces an existing file. Supply `--output` to
choose another filename or directory.

This first PDB slice supports PE32+ x86-64 sessions only. The supplied PE must match the package's
exact SHA-256 identity, file size, architecture, image base, machine, section count, and persisted
section metadata. It must also contain exactly one valid modern `RSDS` record among its
`IMAGE_DEBUG_TYPE_CODEVIEW` entries. ReSymbol copies that record's GUID and age into the PDB and
copies the original 40-byte PE section-table records byte-for-byte into its section-header stream.
Export fails before creating the destination when the source is missing, is a different binary or
build, has only an older `NB10` CodeView record, has no RSDS record, or contains malformed or
multiple RSDS records.

The result contains CodeView `S_PUB32` records for selected named functions and globals. A named
function wins over a named global at the same RVA; an unnamed function suppresses nothing. This is
not a reconstructed compiler PDB: it carries no types, prototypes, private symbols, locals, line
tables, compilands, or function extents. Confidence, alternate names, evidence, recovered strings,
calls, thunks, data references, and relationships remain available in the neutral JSON projection.

Generation is deterministic and offline. The PDB/MSF writer is built into ReSymbol, so ordinary
users do not need Visual Studio, LLVM, DIA, a compiler, or a network service. The writer accepts at
most 262,144 selected function/global candidates before same-RVA reduction, at most 511 bytes per
emitted public name, and a final MSF container of at most 128 MiB. A bound violation aborts before
the create-new destination is written.

The generated PDB does not modify or relink the executable. Load it manually in IDA or another PDB
consumer when that tool offers a symbol-file selection. For automatic discovery, use the PDB
basename recorded in the PE's RSDS path when one is present: copy or rename the export to that
basename and place it beside the binary or in the debugger's configured symbol path. Debuggers
normally use the copied GUID and age to accept the PDB; the stronger SHA-256 check is enforced by
ReSymbol at export time against `--binary`. Do not patch the PE merely to point at the generated
file.

## Import into IDA

Generate the script:

```console
resymbol export application.resym --format ida-python
```

Open the exact binary represented by the package in IDA. After IDA has loaded the input, choose
**File -> Script file...** and select `application.ida.py` (or the path supplied with `--output`).
The script checks IDA's recorded input SHA-256 before doing anything else and prints ReSymbol status
and per-symbol diagnostics in IDA's output window.

For the current projection subset, the script can:

- create a function only when its known range is mapped, non-overlapping, and safe to establish;
- retain an existing function at the same start instead of replacing its body;
- apply a selected function name only after creating its known safe body or finding an existing
  function at that exact start;
- apply a selected global name only when the address is not inside an existing function;
- preserve an existing IDA user-authored name at either kind of address; and
- calculate each effective address from IDA's current image base plus the projected RVA.

If a proposed function start is already inside another function, a range crosses a segment, an
address is unmapped, or IDA rejects a name, that item is reported and the rest of the import
continues.

## Import into Ghidra

Generate the Java script:

```console
resymbol export application.resym --format ghidra-java
```

Open the exact binary represented by the package in Ghidra, open **Window -> Script Manager**, and
make the generated script visible from one of the Script Manager's configured script directories.
Refresh the manager if necessary, then run the script from the **ReSymbol** category. Ghidra
compiles Java scripts through its own scripting environment; no separate JDK setup is required for
an ordinary Ghidra installation.

The `.java` filename must exactly match its generated public class. This is automatic for both the
default `ReSymbolImport_<sha12>.java` name and a valid custom `--output` name. Do not rename the
file without regenerating it.

The script checks `currentProgram`'s executable SHA-256 before mutation, resolves each RVA from the
program image base, and reports individual failures in the Script Manager console. It can create a
mapped, non-overlapping function body and apply selected function/global names as analysis results.
It applies a function name only after creating its known safe body or finding an existing function
at that exact start, and it does not apply a global name inside an existing function. Existing
function bodies are never replaced. A Ghidra name is protected whenever its source is neither
`DEFAULT` nor `ANALYSIS`; this includes user-defined and imported names and avoids overwriting other
stronger or future source categories.

Large projections are packed deterministically into bounded record-data literals and small batch
methods. This avoids Java's per-class constant-pool and per-string limits without weakening the
exact-binary gate; a 67,532-boundary PE such as `VNGame.exe` remains one self-contained script. The
writer still fails before creating the output file if the generated source would exceed its 32 MiB
output limit. The neutral JSON projection remains the loss-aware artifact for the complete projected
set when a writer limit is reached.

## Current losses and conservative omissions

The initial scripts intentionally apply less information than the JSON projection retains:

- **Names:** only the selected collision-safe output name is applied. Its original source spelling,
  alternate names, ambiguity, confidence, and provenance remain in JSON and are not installed as
  debugger comments or metadata. Output names may be rewritten into a portable, bounded form, and
  collisions receive deterministic suffixes.
- **Function boundaries:** ambiguous, invalid, or overlapping candidate ranges may be omitted
  during projection. A writer can omit additional overlapping ranges, and the target tool can
  reject a range that conflicts with its existing database.
- **Prototypes:** recovered function declarations remain in JSON and are not yet applied by either
  script.
- **Types:** type names, alternatives, and definitions remain in JSON and are not yet created in
  IDA or Ghidra.
- **Literals, comments, and relationships:** recovered strings, data references, calls, thunks, and
  class membership are retained in the neutral JSON projection but are not currently installed in
  either debugger. Base-class/PMD records remain in `.resym`, and evidence links and other
  unsupported relationships may be reduced with projection warnings.
- **Existing tool state:** IDA user-authored names, Ghidra names from any source other than
  `DEFAULT`/`ANALYSIS`, and existing function bodies win. The scripts do not offer an override
  switch; an interactive review bridge is planned for choices that require user judgment.

These omissions prevent a low-confidence or lossy conversion from masquerading as full symbol
recovery. Future IDA/Ghidra bridges will add preview and selective application. The current MAP
and PDB writers expose only selected PE function/global names and addresses; richer PDB records
remain a separate milestone.
