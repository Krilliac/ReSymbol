# Install ReSymbol

ReSymbol prereleases are portable command-line downloads. You do not need Rust, .NET, Python,
CMake, Visual Studio, LLVM, DIA, or another compiler to run an official archive.

> [!IMPORTANT]
> Release artifacts appear on the GitHub Releases page only after a maintainer pushes a matching
> prerelease tag, such as `v0.1.0-alpha.1`. Until the first such tag exists, build from source as
> described below.

## Current scope

The current analyzer accepts native Windows x86-64 PE32+ input. It safely extracts image and section
metadata, imports, exports, forwarded exports, and x64 exception-directory records. Exact export
names and metadata-backed `RUNTIME_FUNCTION` ranges become evidence-bearing symbol-graph claims.
It also performs a bounded pure-Rust x86-64 control-flow-guided block sweep inside fully file-backed
exception ranges and checks metadata-backed entry candidates for one-instruction internal or import
thunks. It follows supported direct same-range branches, stops paths at terminal or indirect flow,
and retains supported direct calls, RIP-relative data references, and thunks without inventing
source names, function sizes, or target semantics. A separate bounded pass recovers exact
NUL-terminated ASCII and UTF-16LE strings from eligible file-backed data.
The built-in bounded RTTI pass also validates modern MSVC x64 Rev1 type descriptors, class and base
records, vftables, and executable virtual-slot targets. Recovered class/type names, vftable names,
and function-to-class relationships become evidence-bearing claims, and the result is written to a
portable `.resym` package bound to the input's SHA-256 identity.

This is not yet a general disassembler or a full symbol-recovery pipeline. It does not infer names
erased by compilation, reconstruct general C++ layouts, recover register-indirect control flow, or
name virtual functions merely because their targets appear in a vftable. RTTI support deliberately
accepts only the modern x64 Rev1 layout with
28-byte base-class descriptors carrying a nested class-hierarchy reference; older/x86 RTTI and
other ABI variants remain unsupported. It can export a neutral JSON projection, a bounded
human-readable Markdown report, deterministic Microsoft-linker-style MAP text, an exact-RSDS
public-symbol PDB, or self-contained import scripts for IDA and Ghidra. The PDB slice currently
supports PE32+ x86-64 and public named functions/globals only; richer PDB records, DWARF, native
debugger-database files, packed binaries, .NET assemblies, other CPU architectures, ELF, Mach-O,
and richer debugger integration are future analysis milestones.

The core PE/RTTI analysis is offline and never executes the input. Its narrow decoder is included
in the executable and requires no native library or compiler. Code recovery decodes at most 64 MiB
and 1,000,000 instructions, discovers at most 262,144 block starts, and retains at most 8,192 direct
calls, 32,768 data references, and 4,096 thunks. String recovery has its own bounded scan and
retention budgets. An internal target covered by known `RUNTIME_FUNCTION` metadata is suppressed
unless its RVA matches a recorded runtime-function begin. The guided sweep suppresses unreachable
post-terminal bytes and can cross jump-over data, but it remains heuristic-confidence evidence:
reachable embedded data can produce false positives, while invalid or unsupported flow can omit
later calls or references on that path. It does not persist a basic-block graph. RTTI discovery
scans at most 64 MiB of eligible read-only initialized data for candidate back-pointers; candidate
validation then performs bounded reads of referenced metadata and contiguous executable slot
candidates. It
retains at most 16 MiB of RTTI name text, with additional record-count limits. If an aggregate
limit is reached, the valid prefix is kept and explicitly marked partial rather than reported as a
complete scan.

The current release includes external-process analysis plugins and the first native C/C++ analysis
host. Dropped-in plugins are discovered automatically, but executable plugin code requires explicit
approval bound to its exact directory fingerprint before it can run. Native plugins always load in
the disposable `resymbol-native-host` sibling process; there is no in-process native path. WASM,
managed/.NET, and debugger-hosted contracts are present for plugin authors, but their execution
hosts remain future work.

The first native helper verifies and buffers source PE files up to 1 GiB for its bounded
`binary.read` callback. That explicit source-image limit is independent of the advisory plugin
memory value in the process protocol; process memory is not currently sandbox-enforced.

The command-line executable itself is built for these host platforms:

| Archive suffix | Host |
|---|---|
| `windows-x64.zip` | 64-bit Windows 10 or newer |
| `linux-x64.tar.gz` | 64-bit x86 Linux; musl CLI plus GNU/glibc native helper |
| `macos-x64.tar.gz` | Intel Mac |
| `macos-arm64.tar.gz` | Apple silicon Mac |

The host platform identifies where ReSymbol runs, not which binary format it can analyze. The
Linux `resymbol` executable remains statically linked with musl. Its sibling native helper is built
on Ubuntu 22.04 for GNU/glibc (glibc 2.35 or newer) so it can load ordinary glibc `.so` plugins; the
helper is needed only when running a native plugin.

## Download and verify

Download the archive for your host and its adjacent `.sha256` file from the GitHub Releases page.
Checksums detect an incomplete or modified download; they are not a substitute for code signing.

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
resymbol export path/to/application.resym --format json
resymbol export path/to/application.resym --format markdown
resymbol export path/to/application.resym --format map
resymbol export path/to/application.resym --format pdb --binary path/to/application.exe
resymbol export path/to/application.resym --format ida-python
resymbol export path/to/application.resym --format ghidra-java
resymbol plugin list
resymbol plugin doctor
```

On Linux or macOS, use `./resymbol` instead of `resymbol` unless the extracted directory is on
`PATH`. By default, `analyze` replaces the input extension with `.resym`. Select another destination
with `--output`:

```console
resymbol analyze path/to/application.exe --output results/application.resym
```

ReSymbol uses create-new writes and refuses to overwrite an existing package. Move or remove an old
result, or choose a new output path, before repeating an analysis.

`inspect` validates the envelope schema, analysis payload, and agreement between the outer and
embedded binary identities before printing a summary. The package is canonical JSON and can also be
printed in a readable form:

```console
resymbol inspect results/application.resym --json
```

Both `analyze` and `inspect` report recovered direct-call, thunk, string, and data-reference counts
and whether each bounded recovery pass was complete or partial. They also report MSVC RTTI vftable,
unique-type, base-record, and virtual-slot counts. A partial line appears when a fixed scan,
retention, or aggregate discovery budget was reached; the package preserves the independent flags
for downstream review.

New analyses write package schema 3. `inspect` and `export` can also open schemas 1 and 2. Schema 1
is migrated into a validated current in-memory session and its base graph is rebuilt; schema 2 uses
the current model's validated defaults for fields introduced later. Neither path rewrites the
legacy package. Because `.resym` does not contain the original executable, compatibility loading
cannot run missing recovery passes: schema 1 has no direct-call or thunk records, and schemas 1 and
2 have no string or data-reference records. Analyze the exact original binary again to create a
schema 3 package with those results.

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

Without `--output`, those formats write `application.symbols.json`, `application.symbols.md`,
`application.map`, `application.pdb`, `application.ida.py`, and
`ReSymbolImport_<first-12-binary-sha256>.java` beside the package, respectively. Markdown is a
deterministic presentation report for human review, not a stable machine-interchange format; use
JSON for integrations. New analyses write `.resym` package schema 3; export also accepts package
schemas 1 and 2 through validated compatibility paths without rewriting them. The current neutral
projection is schema 4, and MAP/PDB add no schema fields. A custom Ghidra filename must use a
lowercase `.java` extension and a valid conservative Java-identifier stem; the generated public
class uses that stem.

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

Every archive contains this layout:

```text
resymbol-v0.1.0-alpha.1-<platform>/
├── resymbol[.exe]
├── resymbol-native-host[.exe]
├── README.md
├── LICENSE-APACHE
├── LICENSE-MIT
├── docs/
│   ├── install.md
│   └── plugin-system.md
└── plugins/
    └── README.txt
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
├── community.example-process-resolver/
│   ├── plugin.toml
│   └── resolver[.exe]
├── vendor.native-matcher/
│   ├── plugin.toml
│   └── matcher.{dll,so,dylib}
└── .resymbol/                  # ReSymbol-owned trust/quarantine state
```

Do not place plugin source code in this directory expecting ReSymbol to compile it. A process
plugin must include a runnable entrypoint and any private runtime it needs; on Unix, that entrypoint
must have execute permission. A native library is a prebuilt artifact for one host operating system
and CPU architecture, not a portable Windows-binary analyzer module. Bundle its private libraries
beside it and link Unix search paths relative to the plugin itself (`$ORIGIN` on Linux or
`@loader_path` on macOS). Windows loads the plugin with its own DLL directory plus the safe default
application/system directories. Ordinary users should not need the plugin author's compiler or SDK.

Inspect the artifact and its requested protocol permissions, then approve its exact fingerprint:

```console
resymbol plugin list
resymbol plugin doctor
resymbol plugin trust community.example-process-resolver
```

For scripted installation, pin the value you reviewed so approval fails if the directory changed:

```console
resymbol plugin trust community.example-process-resolver --fingerprint <sha256>
```

An unchanged trusted external or native process analyzer is eligible to run automatically during
later analyses. Any change to a fingerprinted file, including `plugin.toml`, its entrypoint, bundled
libraries, or data, invalidates trust. The host-owned records under `plugins/.resymbol/` are outside
plugin directories; do not copy them as part of a plugin package. Corrupt or unsafe state fails
closed.

> [!WARNING]
> External and native helpers are separated from ReSymbol for crash containment, but they are not
> operating-system sandboxes. Plugin code retains the ambient filesystem, network, credential, and
> process authority of the account launching ReSymbol. Manifest permissions limit ReSymbol protocol
> operations; they do not restrict ambient OS access. Trust only exact plugin artifacts whose code
> and publisher you would run directly.

Run a specific approved plugin by ID, or let analysis run all eligible trusted process analyzers:

```console
resymbol analyze path/to/application.exe --plugin community.example-process-resolver
resymbol analyze path/to/application.exe
```

Plugin failures do not prevent base analysis or package creation, and partial claims are discarded.
Unsafe startup, protocol, resource, claim, or runtime failures attributable to plugin execution
quarantine that exact artifact. The native helper flushes a versioned marker immediately before its
first platform loader call; failures observed without the current marker remain conservative
host-side diagnostics. Use strict mode in automation when plugin success is required;
ReSymbol still writes the valid package before returning a failure status:

```console
resymbol analyze path/to/application.exe \
  --plugin community.example-process-resolver \
  --strict-plugins
```

The external-process host supports one-shot `analyze` requests; its interactive
`binary.read`/`read-binary` wire operation remains reserved. The native helper instead exposes a
permission-gated, size-bounded C callback that reads only file-backed RVAs from the exact PE being
analyzed. Native faults terminate that helper process and discard its complete claim batch.

Disable a discovered plugin without deleting it:

```console
resymbol plugin disable community.example-process-resolver
resymbol plugin enable community.example-process-resolver
resymbol plugin untrust community.example-process-resolver
resymbol plugin reset community.example-process-resolver
```

The disable command creates `plugin.disabled` in that plugin directory. It can also be created by
hand as an emergency recovery measure; it is excluded from the artifact fingerprint so disabling
and re-enabling an unchanged plugin does not silently change its trust identity. `untrust` revokes
approval. `reset` clears quarantine for the current artifact but does not trust a changed one.
ReSymbol rechecks both the sentinel and the exact trust/quarantine record immediately before launch
and at the completed-batch commit gate. A disable or revocation observed at that final gate discards
the result without newly quarantining the plugin; a change after that point governs later runs.

Safe mode suppresses all third-party plugin execution for that run:

```console
resymbol --safe-mode analyze path/to/application.exe
```

## Build from source

Source builds are for contributors and platforms without a prerelease archive. They require:

- Git;
- `rustup`, which installs the pinned Rust 1.85.0 toolchain from `rust-toolchain.toml`; and
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

Keep `target/release/resymbol-native-host[.exe]` beside
`target/release/resymbol[.exe]`; ReSymbol never searches the plugin directory for its trusted
helper. A normal Linux source build uses the host GNU toolchain for both binaries. The official
Linux release workflow instead builds the main CLI for musl and the helper for GNU/glibc. The .NET
SDK is required only to develop the managed plugin SDK or host; it is not required for the Rust
workspace or official executable archives.
