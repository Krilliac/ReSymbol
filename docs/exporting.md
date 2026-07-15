# Export ReSymbol results

`resymbol export` turns one validated `.resym` analysis package into either a deterministic,
debugger-neutral JSON projection or a self-contained import script for IDA or Ghidra.

```console
resymbol export PACKAGE --format json [--output PATH]
resymbol export PACKAGE --format ida-python [--output PATH]
resymbol export PACKAGE --format ghidra-java [--output PATH]
```

The current formats are deliberately small and auditable. They do not require a ReSymbol plugin,
compiler, or separately installed language runtime beyond the scripting support included with the
target debugger. PDB and MAP generation, richer type application, and interactive in-tool bridges
are later milestones.

## Output paths and overwrite policy

Without `--output`, ReSymbol chooses a deterministic destination beside the package:

| Format | Package | Default output |
|---|---|---|
| `json` | `application.resym` | `application.symbols.json` |
| `ida-python` | `application.resym` | `application.ida.py` |
| `ghidra-java` | `application.resym` | `ReSymbolImport_<sha12>.java` |

`<sha12>` is the first 12 hexadecimal characters of the analyzed binary's SHA-256. The hash-based
Ghidra name is stable for the exact binary and gives the generated script a conservative Java class
name.

All formats use create-new writes. ReSymbol refuses to replace an existing file; choose another
path with `--output`, move the old export, or remove it intentionally before exporting again.

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

## Safety model

Before writing any format, ReSymbol validates the package, derives its combined symbol graph, and
reduces that graph to a bounded export projection. The projection is tied to one exact binary
SHA-256 and uses RVAs rather than assuming a process or debugger load address.

After a successful write, the CLI prints the destination, binary SHA-256, projected entity counts,
and a bounded summary of projection warning groups. Inspect those warnings before applying a
script; the output file is still created when a deliberate lossy reduction is safe and diagnosed.

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

## JSON projection

The `json` format is the loss-aware interchange output. It retains:

- exact binary identity, architecture, preferred image base, and virtual image size;
- selected collision-safe output names and their source spellings;
- competing names, confidence, and producer/run provenance;
- supported function and global boundaries;
- recovered function prototypes and type definitions that fit the neutral model; and
- structured, counted warnings for information that was reduced or omitted.

Entries are emitted in stable order. Name and range conflicts are resolved conservatively, and
colliding selected names receive deterministic output suffixes rather than silently referring to
the same debugger symbol.

The JSON projection is not a PDB, MAP file, IDA database, or Ghidra project. It is the common input
to target-specific writers and a useful artifact for plugins, review tools, and future exporters.

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

One generated Ghidra Java script can contain at most 20,000 emitted function/global records after
target-specific filtering. This is a deliberate writer limit that keeps the generated class within
practical Java/Ghidra compilation bounds. If the limit is exceeded, export fails before creating
the output file; the neutral JSON projection remains the loss-aware artifact for the complete
projected set.

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
- **Comments and relationships:** unsupported graph assertions, class membership, evidence links,
  and other relationships are not currently installed in the debugger. Projection warnings expose
  reductions where possible.
- **Existing tool state:** IDA user-authored names, Ghidra names from any source other than
  `DEFAULT`/`ANALYSIS`, and existing function bodies win. The scripts do not offer an override
  switch; an interactive review bridge is planned for choices that require user judgment.

These omissions prevent a low-confidence or lossy conversion from masquerading as full symbol
recovery. Future IDA/Ghidra bridges will add preview and selective application. MAP output and a
synthetic PDB writer are planned separately and are not produced by any current export format.
