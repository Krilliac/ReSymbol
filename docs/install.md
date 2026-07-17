# Install ReSymbol

ReSymbol prereleases are portable downloads. Every archive includes the command-line application;
the Windows x64 archive also includes the desktop workbench. You do not need Rust, .NET, Python,
CMake, Visual Studio, LLVM, DIA, or another compiler to run an official archive.

> [!IMPORTANT]
> Release artifacts appear on the GitHub Releases page only after a maintainer pushes a matching
> prerelease tag, such as `v0.1.0-alpha.1`. Until the first such tag exists, build from source as
> described below.

## Current scope

The current analyzer accepts native Windows x86-64 PE32+ input. It also accepts ELF32
little-endian `EM_MIPS` `ET_EXEC` input through a container-only path that retains checked headers,
sparse non-empty `PT_LOAD` mappings, and zero base claims without decoding instructions; see
[elf32-mips-container.md](elf32-mips-container.md). For PE, it safely extracts image and section
metadata, conventional imports, modern RVA-form delay imports, exports, forwarded exports, x64
exception-directory records, ordered TLS callback records, and load-config GuardCF function,
address-taken IAT, long-jump, and EH-continuation records, plus checked security-cookie, GuardCF,
XFG, CastGuard, and GuardMemcpy storage anchors. Exact export names, metadata-backed `RUNTIME_FUNCTION` ranges, GuardCF function records,
and retained TLS callback slots become evidence-bearing symbol-graph claims.
It also performs a bounded pure-Rust x86-64 control-flow-guided block sweep inside fully file-backed
exception ranges and checks seeded executable candidates for one-instruction internal, import,
or read-only function-pointer thunks. It follows supported direct same-range branches, stops paths
at terminal or indirect flow, and retains supported direct calls, including one-hop exact
RIP-relative calls through fully backed read-only eight-byte function-pointer slots, RIP-relative
data references, and thunks without inventing source names or function sizes. Exact
`FF 25 disp32`/`48 FF 25 disp32` pointer thunks use the same conventional/delay-IAT-first, one-hop
slot policy as
`FF 15 disp32`/`48 FF 15 disp32` calls. Resolved pointer control flow preserves both the slot and
endpoint; calls retain a paired same-site data reference, while thunks do not require one. A
retained GuardCF or TLS callback endpoint joins the initial first-instruction thunk seeds,
and a retained internal thunk endpoint seeds the next sorted executable-candidate layer. GuardCF
and TLS callback bodies are not swept. The analyzer therefore preserves exact chains such as
`A -> B` and `B -> C` without
rewriting a call or earlier
thunk to `C`; connected cycles terminate through global candidate deduplication, while a persisted
disconnected cycle is invalid. This is not pointer-slot chaining: every non-IAT pointer operand is
still dereferenced exactly once. A separate bounded pass recovers exact NUL-terminated ASCII and
UTF-16LE strings from eligible file-backed data.
The built-in bounded RTTI pass also validates modern MSVC x64 Rev1 type descriptors, class and base
records, vftables, and executable virtual-slot targets. Recovered class/type names, vftable names,
and function-to-class relationships become evidence-bearing claims, and the result is written to a
portable `.resym` package bound to the input's SHA-256 identity.

On Windows x64, `resymbol-workbench.exe` opens a supported PE, bounded ELF32 container, or current
`.resym` package, runs the
same core analysis away from the UI thread, and presents exact identity, evidence, durable
exact-claim review, a bounded Reconstruction Graph, a static Address Space/protection assessment,
bounded exact-RVA hex and x64 linear-disassembly previews from an exact verified source snapshot,
read-only debugger/sandbox provider readiness, and discovered plugin health. The graph roots at the
PE entry point or a clearly labeled deterministic lowest-RVA navigation fallback, synchronizes
function selection with the inspector, and draws only retained direct-call, thunk, and import
relationships. Its visible bounded state makes large binary truncation explicit instead of
suggesting complete call-graph recovery. Address Space is a preferred-image model rather than a live
process map. Its reader serves at most 256 canonical file-backed bytes through the in-process offline
host and rejects unbacked or crossing spans. The capped linear view reports why it stopped and is not
CFG or function-boundary truth; readiness is only a non-mutating provisioning preflight. Neither
surface executes the input or proves containment. Plugin health is read-only and the GUI does
not execute plugins or migrate
legacy packages. It creates new patched PE binaries, `.resym`, neutral JSON, Markdown, MAP,
public-symbol PDB, IDA Python, and Ghidra Java artifacts, stores review decisions in a separate binary-bound create-new sidecar,
and refuses to replace an existing destination. Its companion console is off by default; enable
**View -> Companion console** to spawn live logs and typed workbench controls, then clear the same
checkbox to close only that console session.

The bounded Address Space preview is not a general disassembler or a full symbol-recovery pipeline.
It does not infer names
erased by compilation, reconstruct general C++ layouts, recover register-indirect control flow, or
name virtual functions merely because their targets appear in a vftable. RTTI support deliberately
accepts both MSVC x64 Rev1 base-class descriptor layouts: the legacy 24-byte form without `pCHD`
and the 28-byte `BCD_HASPCHD` form with a required hierarchy reference. A hierarchy may mix them;
an extended root must link to its owning hierarchy, while a legacy root is validated without
inventing the absent field. x86 RTTI and other ABI variants remain unsupported. It can export a
neutral JSON projection, a bounded human-readable Markdown report, deterministic
Microsoft-linker-style MAP text, an exact-RSDS public-symbol PDB, or self-contained import scripts
for IDA and Ghidra. The PDB slice currently
supports PE32+ x86-64 and public named functions/globals only; richer PDB records, DWARF, native
debugger-database files, packed binaries, .NET assemblies, other CPU architectures, ELF, Mach-O,
and richer debugger integration are future analysis milestones.

The core PE/RTTI analysis is offline and never executes the input. Its narrow decoder is included
in the executable and requires no native library or compiler. Code recovery decodes at most 64 MiB
and 1,000,000 instructions, discovers at most 262,144 block starts, and retains at most 8,192 direct
calls, 32,768 data references, and 4,096 thunks. TLS callback discovery separately retains at most
4,096 ordered entries. Every Guard table rejects a declared count above 262,144 or any malformed
record and never serializes a partial prefix.
Conventional and delay imports share hard ceilings of 4,096 libraries,
65,536 symbols, and 16 MiB of name bytes; exceeding one rejects analysis rather than retaining a
partial import prefix. String recovery has its own bounded scan and retention budgets. Original
thunk seeds are processed before later sorted endpoint layers; reaching a shared decode or
thunk-retention limit preserves deterministic valid hops and marks code recovery
partial. An internal target covered by known `RUNTIME_FUNCTION` metadata is allowed only when its
RVA matches a recorded runtime-function begin or a retained GuardCF function
start. Every other interior endpoint remains suppressed regardless of another seed source. The
guided sweep suppresses unreachable post-terminal bytes and can cross jump-over data, but it
remains heuristic-confidence evidence:
reachable embedded data can produce false positives, while invalid or unsupported flow can omit
later calls or references on that path. It does not persist a basic-block graph. RTTI discovery
scans at most 64 MiB of eligible read-only initialized data for candidate back-pointers; candidate
validation then performs bounded reads of referenced metadata and contiguous executable slot
candidates. It
retains at most 16 MiB of RTTI name text, with additional record-count limits. If an aggregate
limit is reached, the valid prefix is kept and explicitly marked partial rather than reported as a
complete scan.

The current release includes WebAssembly Component Model, external-process, native C/C++, and
managed/.NET analysis plugins. Dropped-in plugins are discovered automatically. Capability-limited
WASM components autoload without a trust record; external-process, native, and managed code requires
explicit approval bound to its exact directory fingerprint. Native libraries and managed assemblies
always load in their disposable `resymbol-native-host` and `resymbol-managed-host` sibling
processes; there is no in-process path for either family. The first WASM and managed slices accept
`analyze` work for PE32+ x86-64 sessions. The strictly non-executing in-process offline image host is
implemented; external process-executing debugger hosts and live providers remain future work.

The WASM host links the checked-in ReSymbol WIT interface and no WASI interfaces. Its default input
cap is a 64 MiB component. Instantiated guest execution receives a 256 MiB linear-memory limit,
100,000,000 fuel, a 2 MiB WebAssembly stack, a 30-second epoch deadline, 4,096 host events/8 MiB of
event output, and 64 MiB of aggregate `binary.read` calls (1 MiB per call). The exact source PE is
capped at 1 GiB. The engine runs inside ReSymbol: no-WASI capability isolation is materially
stronger than an ambient process plugin, but an engine/compiler/host-binding vulnerability is not
contained by a separate process. The guest fuel, epoch, stack, and store limits do not interrupt
synchronous validation/JIT compilation or cap compiler and other host allocations, so compilation
can exceed the configured guest deadline or memory limit.

The first native helper verifies and buffers source PE files up to 1 GiB for its bounded
`binary.read` callback. That explicit source-image limit is independent of the advisory plugin
memory value in the process protocol; process memory is not currently sandbox-enforced.

The managed launcher and helper verify the complete plugin-directory fingerprint, a deterministic
private-DLL closure, and the exact source binary before loading plugin code and again before
committing output. The private closure and binary snapshot share the advertised byte budget (256
MiB by default); the hard ceilings are 512 managed DLLs, 512 MiB of private DLLs, and a 1 GiB source
binary. These are input-buffering gates, not a process-memory sandbox. The helper supplies the exact
`ReSymbol.PluginSdk` assembly, so a plugin package contains its entry DLL and private dependencies,
not a private SDK copy.

The command-line executable is built for every host platform; the workbench is included only in the
Windows x64 archive:

| Archive suffix | Host | Applications |
|---|---|---|
| `windows-x64.zip` | 64-bit Windows 10 or newer | CLI and desktop workbench |
| `linux-x64.tar.gz` | 64-bit x86 Linux; musl CLI plus GNU/glibc native helper | CLI |
| `macos-x64.tar.gz` | Intel Mac | CLI |
| `macos-arm64.tar.gz` | Apple silicon Mac | CLI |

The host platform identifies where ReSymbol runs, not which binary format it can analyze. The
Linux `resymbol` executable remains statically linked with musl. Its sibling native helper is built
on Ubuntu 22.04 for GNU/glibc (glibc 2.35 or newer) so it can load ordinary glibc `.so` plugins; the
helper is needed only when running a native plugin.

## Download and verify

Download the archive for your host and its adjacent `.sha256` file from the GitHub Releases page.
Checksums detect an incomplete or modified download; they are not a substitute for code signing.
Managed plugin authors can also download the matching
`ReSymbol.PluginSdk.<version>.nupkg` and `.nupkg.sha256` release assets; the package is a compile-only
contract and does not install a runtime SDK beside the plugin.

On Windows PowerShell:

```powershell
$expected = (Get-Content .\resymbol-v0.1.0-alpha.1-windows-x64.zip.sha256).Split()[0]
$actual = (Get-FileHash .\resymbol-v0.1.0-alpha.1-windows-x64.zip -Algorithm SHA256).Hash
if ($actual.ToLowerInvariant() -ne $expected.ToLowerInvariant()) { throw "Checksum mismatch" }
Expand-Archive .\resymbol-v0.1.0-alpha.1-windows-x64.zip
```

On Linux:

```console
sha256sum --check resymbol-v0.1.0-alpha.1-linux-x64.tar.gz.sha256
tar -xzf resymbol-v0.1.0-alpha.1-linux-x64.tar.gz
```

On macOS:

```console
shasum -a 256 -c resymbol-v0.1.0-alpha.1-macos-arm64.tar.gz.sha256
tar -xzf resymbol-v0.1.0-alpha.1-macos-arm64.tar.gz
```

Replace the example version and platform with the files from the release you selected.

Official prereleases are not initially code-signed or notarized, so Windows SmartScreen or macOS
Gatekeeper may ask you to confirm that you trust the download. Verify the checksum and obtain the
archive only from the project release page. Do not bypass an operating-system warning for a file
from another source.

## Run

Open a terminal in the extracted directory, then check the executable:

```console
resymbol --version
resymbol analyze path/to/application.exe
resymbol inspect path/to/application.resym
resymbol inspect path/to/application.resym --binary path/to/application.exe
resymbol export path/to/application.resym --format json
resymbol export path/to/application.resym --format markdown
resymbol export path/to/application.resym --format map
resymbol export path/to/application.resym --format pdb --binary path/to/application.exe
resymbol export path/to/application.resym --format ida-python
resymbol export path/to/application.resym --format ghidra-java
resymbol patch path/to/application.exe path/to/reviewed.respatch.json --output path/to/application-patched.exe
resymbol plugin list
resymbol plugin doctor
```

On Windows, start the desktop workbench with a supported PE or bounded ELF32 path, or launch it
without a path and use the file picker. PE-only address-space, offline-byte, MAP, and PDB actions
remain disabled for ELF projects:

```powershell
.\resymbol-workbench.exe .\path\to\application.exe
```

After a project is open, use the persistent **Open Another...** header button, **File -> Open Binary
or Package...**, the **Open Binary** workflow stage, Ctrl+O, **File -> Open Recent**, or drop one file
onto the window to switch inputs. Unsaved review decisions pause replacement for an explicit
create-new save, discard, or cancel choice; a replacement that fails to open leaves the current
project and its review state intact.

The workbench performs background core-only analysis and provides evidence, provenance, durable
exact-claim review, plugin health, a bounded Reconstruction Graph, a static Address Space/protection
assessment, and read-only debugger/sandbox readiness. The graph's root and synchronized selection
controls let you move between the entry point or deterministic lowest-RVA fallback and individual
functions; only retained direct-call, thunk, and import edges are drawn. A **BOUNDED** cue identifies
large views that exceed the rendering budget. With verified source bytes, Address Space can preview
an exact 16/32/64/128/256-byte file-backed RVA span through the in-process offline host as hex or a
capped x64 linear decode. The preview is not CFG or function-boundary truth. **Create New Patched
Binary** accepts queued NOP drafts only when each is one complete x64 instruction, then worker-owned
publication verifies exact source identity/bytes and creates a separate no-clobber binary; live actions remain disabled without an
authenticated provider and current capabilities/tokens. The static and readiness views do not
execute the input, create a sandbox, or prove containment. The workbench
opens current `.resym` packages, can
verify them against an exact source binary, saves review history to a separate create-new sidecar,
and publishes create-new patched PE binaries, `.resym`, neutral JSON, Markdown, MAP, public-symbol
PDB, IDA Python, or Ghidra Java artifacts. It never overwrites an existing destination. Plugin execution and legacy
package migration remain CLI workflows; live launch, attach, and memory mutation are not
implemented.

The **View -> Companion console** checkbox spawns the packaged console helper when you want live
timestamped activity or command control. Enter `help` there for the bounded command set. The helper
is not a standalone analyzer, starts disabled on every launch, and can be closed without ending the
GUI. Its `quit` command and the native window close button both pause on unsaved review changes so
you can save a new sidecar, explicitly discard, or cancel before exiting.

On Linux or macOS, use `./resymbol` instead of `resymbol` unless the extracted directory is on
`PATH`. By default, `analyze` replaces the input extension with `.resym`. Select another destination
with `--output`:

```console
resymbol analyze path/to/application.exe --output results/application.resym
```

ReSymbol uses create-new writes and refuses to overwrite an existing package. Move or remove an old
result, or choose a new output path, before repeating an analysis.

`analyze` accepts only a regular input file and reads it through the same bounded exact-snapshot
service used by the workbench and PDB source export. The default limit is 1 GiB; a declared-length
change during the read is rejected before analysis instead of accepting a prefix or an appended
tail.

`inspect` validates the envelope schema, analysis payload, and agreement between the outer and
embedded binary identities before printing a summary. The package is canonical JSON and can also be
printed in a readable form:

```console
resymbol inspect results/application.resym --json
```

To prove that a package still names the exact original file, add the optional binary gate:

```console
resymbol inspect results/application.resym --binary path/to/application.exe
resymbol inspect results/application.resym --json --binary path/to/application.exe
```

Inspection validates the package first and emits no inspection data to stdout unless the supplied
file's exact size and SHA-256 match; failures report on stderr. Human output includes
`source binary: <canonical-path>` and `identity gate: matched` after a successful check. JSON mode
emits only the validated package JSON, with neither status line mixed into stdout. This works for
supported package schemas 1 through 14 and only verifies identity: it does not rerun analysis, fill
in results absent from an older schema, or rewrite the package or binary.

Both `analyze` and `inspect` report recovered direct-call, thunk, string, data-reference, GuardCF
record/function-candidate and FID-/export-suppressed, Guard address-taken IAT, long-jump,
EH-continuation, TLS callback, and delay-import library/symbol counts and whether
each partial-capable bounded recovery
pass was complete or partial. They also report
MSVC RTTI vftable, unique-type, base-record, and virtual-slot counts. A partial line appears when a
fixed scan, retention, or aggregate discovery budget was reached; the package preserves the
independent flags for downstream review.

For PE32+ inputs, TLS callback discovery reads optional-header data-directory entry 9. ReSymbol
requires the declared directory to be fully file-backed and contain at least the 40-byte PE32+
TLS-directory prefix, converts preferred-image callback VAs to checked RVAs, preserves table order
and duplicate entries, and requires every retained eight-byte slot and callback endpoint to be
file-backed, with retained endpoints in executable data. It retains at most 4,096 callbacks and
then probes one additional slot. Null proves
that an exactly capped table is complete; nonzero records a partial deterministic prefix without
retaining or following the extra entry. Each retained slot becomes `FunctionEntry` evidence with
`pe-tls-callback` provenance and distinct `callback_slot_rva` and `table_index` artifacts, including
when target RVAs repeat. Retained targets seed only the bounded first-instruction thunk check, not
a callback body sweep; no callback is loaded or executed.

For PE32+ inputs, GuardCF discovery reads optional-header data-directory entry 10 as the load-config
directory. A present directory must be fully file-backed and begin with an internal structure size
from 4 through the directory size. Only a structure of at least 148 bytes exposes
`GuardCFFunctionTable`, `GuardCFFunctionCount`, and `GuardFlags`. A count above 262,144, an oversized
table, a structural inconsistency, or any malformed record is a hard analysis error; an accepted
GFIDS table is retained in full, must be fully file-backed and disjoint from the load-config directory, and must
contain strictly increasing unique RVAs that begin in executable file-backed data. Table
disjointness is a ReSymbol hardening policy. Each record is `4 + n` bytes, with `n` selected by the
high `GuardFlags` nibble; ReSymbol retains those metadata bytes exactly and otherwise treats them as
opaque. Every structurally valid record, including one marked `IMAGE_GUARD_FLAG_FID_SUPPRESSED`,
`IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED`, or both, emits a function-entry claim and joins initial
one-instruction thunk seeding. FID suppression describes CFG eligibility rather than whether the
target is a function; export-suppressed RVAs must be 16-byte aligned. GFIDS does not trigger a
function-body sweep or infer a name or extent.

Later load-config versions expose Guard address-taken IAT fields at 176 internal bytes, long-jump
fields at 192 bytes, and EH-continuation fields at 280 bytes. Nonempty table/count pairs require
their presence flags; a present flag with zero fields is a supported empty inventory. GIAT,
long-jump, and EH-continuation records use the `4 + n` Guard stride and require zero reserved
metadata. GIAT RVAs must equal exact parsed conventional or delay-IAT slots. Long-jump and EH-continuation RVAs
must be strictly increasing, unique, and begin in file-backed executable data. Every nonempty Guard
table must be fully backed, disjoint from the load-config directory, and pairwise disjoint from the
other Guard tables. The three inventories are package/plugin data only: import slots and valid
continuation addresses do not become function-entry claims or thunk seeds.

The load-config also exposes checked storage anchors. Internal sizes 96, 120, and 128 expose
`SecurityCookie`, `GuardCFCheckFunctionPointer`, and `GuardCFDispatchFunctionPointer`; sizes 288,
296, 304, and 312 expose `GuardXFGCheckFunctionPointer`, `GuardXFGDispatchFunctionPointer`,
`GuardXFGTableDispatchFunctionPointer`, and `CastGuardOsDeterminedFailureMode`; size 320 exposes
`GuardMemcpyFunctionPointer`. A zero VA is absent;
each nonzero VA is converted to an in-image RVA whose full eight-byte range lies in one mapped
section. Header or cross-section storage, load-config overlap, and pairwise overlap across all three
anchor families are rejected, while mapped zero-fill storage is valid. ReSymbol neither enforces
section permissions nor dereferences initial contents, and these anchors create no claim or thunk
seed.

For PE32+ inputs, modern delay-import discovery reads optional-header data-directory entry 13 as
ordered 32-byte descriptors ending in an all-zero descriptor, followed only by all-zero padding in
the rest of the declared range. ReSymbol accepts only the RVA-based
form whose attributes value is exactly `dlattrRva` (`1`); it deliberately rejects the legacy VA
form, zero, and unknown attribute bits despite ambiguity in the generic PE table documentation.
Each active descriptor must provide nonzero name, module-handle (HMOD), delay-IAT, and delay-INT
RVAs. HMOD needs an eight-byte storage range wholly mapped inside one section but may occupy
zero-filled virtual data rather than file-backed bytes; initial contents and section permissions
remain opaque. Its paired
null-terminated 64-bit INT/IAT arrays and optional nonzero bound-IAT (BIAT) and unload-IAT (UIAT)
arrays must also be fully backed and pairwise disjoint. Each present BIAT or UIAT must have a zero
slot at the paired INT/IAT entry count. BIAT payload values before that required slot are otherwise
opaque, including whether any is zero, while the complete UIAT must byte-match the original delay
IAT. The separate package inventory preserves descriptor and entry order, the DLL name, descriptor
RVA and exact attributes value, name/HMOD/IAT/INT base RVAs, optional BIAT/UIAT base RVAs, each
entry's lookup/IAT RVAs and hint/name or ordinal, and the timestamp; it does not serialize raw
INT/IAT/BIAT/UIAT array contents.
Malformation and shared-budget exhaustion are hard errors, never partial delay-import results.
Delay-IAT slots feed the existing `ImportIat` call/thunk target and outrank
read-only function-pointer fallback; the richer inventory is not added to the neutral projection.

New analyses write package schema 14. `inspect` and `export` can also open schemas 1 through 13.
Schema 1 is migrated into a validated current in-memory session and its base graph is rebuilt;
schemas 2 through 8 use explicit compatibility paths. None rewrites the legacy package. Because
`.resym` does not contain the original executable, compatibility loading cannot run missing
recovery passes: schema 1 has no direct-call or thunk records, schemas 1 and 2 have no string or
data-reference records, and schemas 2 and 3 have no read-only function-pointer call or thunk
results. Schema 4 contains pointer control flow but lacks recovery of 24-byte RTTI base-class
descriptors without `pCHD`; schemas 1 through 4 report that result family as unavailable. Schema 5
contains both RTTI layouts but lacks transitive executable thunk-chain discovery. Schema 6 contains
that closure but lacks TLS callback discovery and callback-based thunk seeding. Schema 7 retains
TLS callback discovery but lacks modern delay-import recovery. Schema 8 retains delay imports but
lacks load-config GuardCF recovery. Schema 9 retains GuardCF functions but lacks the Guard
address-taken IAT, long-jump, and EH-continuation inventories. Schema 10 retains those inventories
but lacks checked security-cookie and GuardCF check/dispatch pointer-slot anchors. Schema 11 retains
those anchors but lacks checked XFG and CastGuard storage anchors. Schema 12 retains XFG/CastGuard
anchors but lacks the checked GuardMemcpy pointer-slot anchor. Schemas 2 through 12 retain their
stored direct calls and thunks,
but omitted result families remain unavailable. Schemas 1 through 7 therefore report delay imports
unavailable, schemas 1 through 8 report GuardCF unavailable, schemas 1 through 9 report modern
Guard target inventories unavailable, schemas 1 through 10 report load-config security anchors
unavailable, schemas 1 through 11 report XFG/CastGuard anchors unavailable, and schemas 1 through 12
report the GuardMemcpy anchor unavailable. Schema 13 retains all current PE recovery families but
predates bounded ELF intake. Analyze the exact original binary again to create schema 14. Relabeling a schema-4 pointer target beneath a
schema 2 or 3
envelope is rejected, as is placing an RTTI base record with
a missing or null `class_hierarchy_descriptor_rva` beneath any schema 1-through-4 envelope. A
schema 1-through-5 envelope also cannot contain a deterministic base thunk source that depends on
schema-6 transitive endpoint seeding. Schemas 1 through 6 also reject schema-7 TLS callback state
and callback-only base thunk seeds. Schemas 1 through 7 reject the exact schema-8 base-analysis
`delay_imports` inventory key and `directories.delay_imports` directory key. PE analyses in schemas 8 through 14 always
serialize the delay-import inventory, even when empty, and reject a payload missing that marker.
Schemas 1 through 8 reject schema-9 load-config/GuardCF fields,
`directories.load_config`, and core `pe-guard-cf-function` claims. PE analyses in schemas 9 through 14 always serialize the
`guard_cf_functions` inventory, even when empty, and reject a payload missing that marker.
Schemas 1 through 9 reject schema-10 Guard target table-RVA and inventory fields. PE analyses in schemas 10 through 14 always
serialize the address-taken IAT, long-jump, and EH-continuation inventory arrays, even when empty,
and reject a payload missing any marker.
Schemas 1 through 10 reject the schema-11 `load_config_security_anchors` object. PE analyses in schemas 11 through 14
always serialize that object, even when empty, and reject a missing or non-object marker. Schemas 1
through 11 reject schema-12 `load_config_xfg_anchors`; PE analyses in schemas 12 through 14 always serialize that
object, even when empty, and reject a missing or non-object marker. Schemas 1 through 12 reject
schema-13 `load_config_guard_memcpy_anchor`; PE analyses in schemas 13 and 14 always serialize that object, even when
empty, and reject a missing or non-object marker.

Export a package to a specific destination with `--output`:

```console
resymbol export results/application.resym --format json --output results/application.symbols.json
resymbol export results/application.resym --format markdown --output results/application.symbols.md
resymbol export results/application.resym --format map --output results/application.map
resymbol export results/application.resym \
  --format pdb \
  --binary path/to/application.exe \
  --output results/application.pdb
resymbol export results/application.resym --format ida-python --output results/application_ida.py
resymbol export results/application.resym --format ghidra-java --output results/ReSymbolImport.java
```

Apply a reviewed portable static patch set to its exact source PE and create a separate binary:

```console
resymbol patch path/to/application.exe \
  results/reviewed.respatch.json \
  --output results/application-patched.exe
```

`patch` analyzes and retains the exact source, bounded-loads the strict schema-v1 manifest, requires
its complete source identity, reconstructs a fresh checked RVA plan, and publishes with the same
no-clobber static-patch service as the workbench. It never executes or rewrites the input and never
uses a serialized file offset. On success it prints the output SHA-256, signature/checksum warnings,
and the filesystem durability established for the published file.

Add `--dry-run` to any format to perform the same package validation, loss assessment, required
PDB source verification, and complete in-memory rendering without creating a destination or staging
file. The summary identifies the prospective path as not written. A dry run does not test whether a
later create-new publication can write to that directory.

Without `--output`, those formats write `application.symbols.json`, `application.symbols.md`,
`application.map`, `application.pdb`, `application.ida.py`, and
`ReSymbolImport_<first-12-binary-sha256>.java` beside the package, respectively. Markdown is a
deterministic presentation report for human review, not a stable machine-interchange format; use
JSON for integrations. New analyses write `.resym` package schema 14; export also accepts package
schemas 1 through 13 through validated compatibility paths without rewriting them. The current
neutral projection is independently schema 6, and MAP/PDB add no schema fields. Projection schema
5 correlates exact or content-interior data-reference targets with retained strings, excluding NUL
terminators and requiring UTF-16LE code-unit alignment; projection schema 6 adds explicit
function-pointer slot and endpoint targets. TLS callback metadata adds no projection field: its
slot-backed function-entry claims and callback-seeded thunks use existing schema-6 shapes. A missing
correlation does not prove the target is not a string. Delay-import inventory is package-only;
delay-IAT calls and thunks reuse the existing import target containing the slot RVA, so projection
schema 6 remains unchanged. Load-config/GFIDS inventory and suppression evidence are likewise
package-only; GuardCF claims and supported seeded thunks reuse existing shapes, so projection schema 6 remains unchanged.
The later Guard target inventories and all three load-config storage-anchor families are also package-only
and add no claims or projection fields.
A custom
Ghidra filename
must use a lowercase `.java` extension and a valid conservative Java-identifier stem; the generated
public class uses that stem.

PDB export must reread the exact original PE because `.resym` intentionally does not contain its
bytes. The source must match the package's SHA-256/session identity and contain exactly one valid
modern RSDS CodeView record; a missing source, different build, NB10-only source, malformed record,
or multiple RSDS records is rejected before output creation. ReSymbol copies the RSDS GUID and age
and raw PE section headers into a deterministic public-symbol-only PDB. It does not emit types,
private symbols, locals, line tables, or function extents, and it never rewrites the PE. Generation
is offline and needs no Visual Studio, LLVM, or DIA installation. Load the PDB manually, or copy or
rename it to the RSDS-recorded basename and place it in the debugger's symbol path. See the export
guide for detailed bounds and loading advice.

MAP export currently accepts PE analysis packages only. Its display module name comes from the
package filename stem: unsupported and non-ASCII UTF-8 bytes become `_`, the result is capped at
255 bytes, and an empty, non-UTF-8, unavailable, `.` or `..` stem falls back to
`resymbol_<first-12-binary-sha256>`. For example, `My App.resym` produces module name `My_App`.
The output uses one-based PE `section:offset` values and preferred-image-base-plus-RVA addresses.
It is Microsoft-linker-style text for tools that support that format, not a guarantee of acceptance
by a particular debugger.

Exports use the same create-new policy as analysis packages and refuse to replace an existing
file. The generated debugger scripts verify the loaded program's exact SHA-256 before making any
changes, then resolve every address from the tool's current image base plus the stored RVA. A MAP
file cannot perform that check: its semicolon-prefixed exact SHA-256 and file-size comments are
informational, so compare the exact binary manually before consuming it. See the
[export guide](https://github.com/Krilliac/ReSymbol/blob/main/docs/exporting.md) before running a
script in IDA or Ghidra; the Ghidra Java source filename and generated public class name must match.

See the
[analysis-package documentation](https://github.com/Krilliac/ReSymbol/blob/main/docs/analysis-packages.md)
for the format and safety guarantees.

The archive is self-contained and may be moved or deleted as one directory. ReSymbol does not
currently use an installer or modify the system `PATH`.

## Plugin directory

The Windows archive contains the representative layout below, plus the project changelog,
contributor/security guides, and the complete `docs/` set. Other platform archives omit the two
Windows-only workbench executables:

```text
resymbol-v0.1.0-alpha.1-<platform>/
├── resymbol[.exe]
├── resymbol-workbench.exe        # Windows x64 archive only
├── resymbol-workbench-console.exe # Windows x64, spawned by the workbench on demand
├── resymbol-native-host[.exe]
├── resymbol-managed-host[.exe]
├── README.md
├── LICENSE-APACHE
├── LICENSE-MIT
├── docs/
│   ├── install.md
│   └── plugin-system.md
└── plugins/
    ├── README.txt
    └── dev.resymbol.example.wasm-resolver/
        ├── plugin.toml
        └── example-resolver.wasm
```

For the simplest portable setup, run ReSymbol from the extracted directory. The default
`plugins/` path is relative to the current working directory. You can select another location from
any directory:

```console
resymbol --plugin-dir /path/to/plugins plugin list
```

An unpacked plugin occupies one child directory and provides a `plugin.toml` plus its prebuilt
entrypoint:

```text
plugins/
├── community.example-wasm-resolver/
│   ├── plugin.toml
│   └── resolver.wasm
├── community.example-process-resolver/
│   ├── plugin.toml
│   └── resolver[.exe]
├── vendor.native-matcher/
│   ├── plugin.toml
│   └── matcher.{dll,so,dylib}
├── vendor.managed-matcher/
│   ├── plugin.toml
│   ├── Matcher.Plugin.dll
│   └── Matcher.PrivateDependency.dll
└── .resymbol/                  # ReSymbol-owned trust/quarantine state
```

Do not place plugin source code in this directory expecting ReSymbol to compile it. A process
plugin must include a runnable entrypoint and any private runtime it needs; on Unix, that entrypoint
must have execute permission. A native library is a prebuilt artifact for one host operating system
and CPU architecture, not a portable Windows-binary analyzer module. Bundle its private libraries
beside it and link Unix search paths relative to the plugin itself (`$ORIGIN` on Linux or
`@loader_path` on macOS). Windows loads the plugin with its own DLL directory plus the safe default
application/system directories. Ordinary users should not need the plugin author's compiler or SDK.

A managed plugin is a prebuilt .NET 8 DLL directory. Its manifest uses `kind = "managed"` and a
portable relative `.dll` entrypoint. Include every private managed dependency beneath that plugin
directory and omit `ReSymbol.PluginSdk.dll`: the app-local, self-contained helper supplies and
identity-checks its own SDK assembly. The first managed host runs only `analyze` against PE32+
x86-64 input. It snapshots the verified DLL closure and exact binary under one cumulative byte
budget before assembly loading. End users do not install .NET and ReSymbol never compiles dropped-in
C# source.

A WASM plugin is a prebuilt Component Model `.wasm` plus its manifest. ReSymbol does not compile
Rust or another guest language during discovery, and ordinary users need no WASM SDK. Official
archives include `dev.resymbol.example.wasm-resolver`, which reads the exact `MZ` signature through
the bounded host interface and submits one evidence-backed comment claim. Disable it normally if
you do not want the example to participate in analysis.

Inspect every artifact and its requested protocol permissions, then approve a process plugin's exact
fingerprint:

```console
resymbol plugin list
resymbol plugin doctor
resymbol plugin trust community.example-process-resolver
```

For scripted installation, pin the value you reviewed so approval fails if the directory changed:

```console
resymbol plugin trust community.example-process-resolver --fingerprint <sha256>
```

An eligible WASM analyzer reports `sandboxed-autoload` and runs without `plugin trust`; attempting
to trust it produces an explanation instead of an approval record. An unchanged trusted external,
native, or managed process analyzer is eligible to run automatically during later analyses. Any
change to a fingerprinted process-plugin file, including `plugin.toml`, its entrypoint, bundled
libraries, or data, invalidates trust. WASM updates also receive a new fingerprint: they still
autoload under the sandboxed policy, but neither an old quarantine nor a reset silently transfers
between artifacts. The host-owned records under `plugins/.resymbol/` are outside plugin
directories; do not copy them as part of a plugin package. Corrupt or unsafe applicable state fails
closed.

> [!WARNING]
> External, native, and managed helpers are separated from ReSymbol for crash containment, but they
> are not operating-system sandboxes. Plugin code retains the ambient filesystem, network,
> credential, and process authority of the account launching ReSymbol. Managed code can invoke
> framework loading APIs directly, including explicit `Assembly` and `NativeLibrary` APIs; the
> verified custom load context governs ordinary dependency resolution, not all .NET process
> authority. Manifest permissions limit ReSymbol protocol operations; they do not restrict ambient
> OS or runtime access. Trust only exact plugin artifacts whose code and publisher you would run
> directly. ReSymbol owns ordinary plugin/helper descendants through a POSIX process group or
> Windows Job Object and terminates the tree when the direct child completes, a deadline or
> stdout/stderr capture failure occurs, or the runtime drops. This is lifecycle containment, not
> authority sandboxing. Windows creates the child atomically inside a preconfigured Job, explicitly
> terminates that Job during normal cleanup, retains kill-on-close as an abrupt-parent fallback when
> no out-of-scope process holds a duplicate, inherits only its exact standard-stream handles,
> verifies membership, and has no spawn-then-assign fallback. This does not defend against an active
> same-account process with sufficient process/handle rights: it can duplicate or remotely close
> ReSymbol's handles and terminate or tamper with the parent. That actor requires a separate OS
> authority boundary. A hostile POSIX plugin/helper or descendant can deliberately leave its process
> group or session.

> [!WARNING]
> WASM components have no linked WASI filesystem, network, environment, clock, or process
> interfaces, but Wasmtime compiles and executes them in the ReSymbol process. Fuel, memory, stack,
> event, read, and epoch-deadline limits constrain instantiated guest execution. Except for the
> component-byte cap, they do not bound synchronous validation/JIT compilation or its allocations,
> and they cannot contain a vulnerability in the engine, generated native code, or ReSymbol host
> bindings.

Run a specific plugin by ID, or let analysis run all eligible sandboxed WASM and trusted process
analyzers:

```console
resymbol analyze path/to/application.exe --plugin community.example-process-resolver
resymbol analyze path/to/application.exe
```

Plugin failures do not prevent base analysis or package creation, and partial claims are discarded.
Unsafe startup, protocol, resource, claim, or runtime failures attributable to plugin execution
quarantine that exact artifact. The native and managed helpers each flush a family-specific,
versioned marker immediately before their first plugin load. The parent removes that marker from
visible diagnostics; failures observed without the current marker remain conservative host-side
diagnostics. Use strict mode in automation when plugin success is required;
ReSymbol still writes the valid package before returning a failure status:

```console
resymbol analyze path/to/application.exe \
  --plugin community.example-process-resolver \
  --strict-plugins
```

The WASM host implements the WIT metadata/initialize/health/analyze/shutdown lifecycle and exposes
permission- and phase-gated claim submission and bounded file-backed PE `binary.read`, plus
output-bounded logging in every phase and cancellation checks. The external-process host supports
one-shot `analyze` requests; its interactive `binary.read`/`read-binary` wire operation remains
reserved. The native helper instead exposes a
permission-gated, size-bounded C callback that reads only file-backed RVAs from the exact PE being
analyzed. The managed helper exposes equivalent permission-gated services through
`IPluginHost.ReadBinaryAsync` and `SubmitClaimAsync`. Service calls are phase-bound, and claim
submission is accepted only during `AnalyzeAsync`. All managed logs and claims remain transactional
through initialization, health, analysis, shutdown, disposal, and final identity checks. A fault or
rejection discards the complete batch.

Disable a discovered plugin without deleting it:

```console
resymbol plugin disable community.example-process-resolver
resymbol plugin enable community.example-process-resolver
resymbol plugin untrust community.example-process-resolver
resymbol plugin reset community.example-process-resolver
resymbol plugin disable dev.resymbol.example.wasm-resolver
resymbol plugin reset dev.resymbol.example.wasm-resolver
```

The disable command creates `plugin.disabled` in that plugin directory. It can also be created by
hand as an emergency recovery measure; it is excluded from the artifact fingerprint so disabling
and re-enabling an unchanged plugin does not silently change its trust identity. `untrust` revokes
process-plugin approval. `reset` clears quarantine for the current artifact; it neither grants
process-plugin trust nor changes the sandboxed policy for a different WASM fingerprint.
ReSymbol rechecks both the sentinel and the exact trust/quarantine record immediately before launch
and at the completed-batch commit gate. A disable or revocation observed at that final gate discards
the result without newly quarantining the plugin; a change after that point governs later runs.

Safe mode suppresses all third-party plugin execution for that run:

```console
resymbol --safe-mode analyze path/to/application.exe
```

## Build from source

Source builds are for contributors and platforms without a prerelease archive. The Rust CLI,
Windows workbench, and native helper require:

- Git;
- `rustup`, which installs the pinned Rust 1.86.0 toolchain from `rust-toolchain.toml`; and
- the normal platform linker: Visual Studio Build Tools with the MSVC C++ workload on Windows,
  Xcode Command Line Tools on macOS, or a C toolchain such as GCC on Linux.

Clone and build the command-line executable:

```console
git clone https://github.com/Krilliac/ReSymbol.git
cd ReSymbol
rustup show active-toolchain
cargo test --workspace --all-features
cargo build --release --bin resymbol --bin resymbol-native-host
```

On Windows, build and launch the desktop executable separately:

```powershell
cargo build --locked --release --bin resymbol-workbench --bin resymbol-workbench-console
.\target\release\resymbol-workbench.exe .\path\to\application.exe
```

Official Windows release jobs build this executable for `x86_64-pc-windows-msvc` with the static
MSVC CRT and package it beside `resymbol.exe`.

To rebuild the source-backed WASM example, add the ordinary Rust core-WASM target and run the
platform script. It uses `wit-bindgen` plus an example-local `wit-component` encoder; no
`cargo-component`, WASI SDK, C/C++ compiler, or global `wasm-tools` executable is required:

```console
rustup target add wasm32-unknown-unknown
./examples/plugins/wasm/build.sh
```

On Windows PowerShell, run `examples\plugins\wasm\build.ps1`. The generated entrypoint is
`examples/plugins/wasm/example-resolver.wasm`. Stage only that component and its manifest:

```console
stage=plugins/dev.resymbol.example.wasm-resolver
mkdir -p "$stage"
cp examples/plugins/wasm/plugin.toml "$stage/"
cp examples/plugins/wasm/example-resolver.wasm "$stage/"
```

ReSymbol discovers the staged component on the next analysis and does not ask for a trust record.
Use `resymbol plugin disable dev.resymbol.example.wasm-resolver` or `--safe-mode` to prevent it from
running.

Keep `target/release/resymbol-native-host[.exe]` beside
`target/release/resymbol[.exe]`; ReSymbol never searches the plugin directory for its trusted
helper. A normal Linux source build uses the host GNU toolchain for both binaries. The official
Linux release workflow instead builds the main CLI for musl and the helper for GNU/glibc.

To run managed plugins from a source build, install the .NET 8 SDK and publish the self-contained
helper for the matching runtime identifier (`win-x64`, `linux-x64`, `osx-x64`, or `osx-arm64`):

```console
dotnet restore sdk/dotnet/ReSymbol.ManagedHost/ReSymbol.ManagedHost.csproj --runtime <RID>
dotnet publish sdk/dotnet/ReSymbol.ManagedHost/ReSymbol.ManagedHost.csproj \
  --configuration Release --runtime <RID> --self-contained true --no-restore \
  --output target/managed/<RID>/publish \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:IncludeAllContentForSelfExtract=true \
  -p:PublishTrimmed=false -p:PublishReadyToRun=false -p:PublishAot=false \
  -p:EnableCompressionInSingleFile=false
```

Copy the one published `resymbol-managed-host[.exe]` beside `resymbol[.exe]`. ReSymbol resolves
only that regular, unlinked application-local sibling; it never searches `PATH` or a plugin
directory. Official archives already include this self-contained helper, so ordinary users need
neither a .NET runtime nor SDK. The SDK is needed only for source publishing or plugin development.
