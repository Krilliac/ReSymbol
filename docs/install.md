# Install ReSymbol

ReSymbol prereleases are portable command-line downloads. You do not need Rust, .NET, Python,
CMake, Visual Studio, or another compiler to run an official archive.

> [!IMPORTANT]
> Release artifacts appear on the GitHub Releases page only after a maintainer pushes a matching
> prerelease tag, such as `v0.1.0-alpha.1`. Until the first such tag exists, build from source as
> described below.

## Current scope

The current analyzer accepts native Windows x86-64 PE32+ input. It safely extracts image and section
metadata, imports, exports, forwarded exports, and x64 exception-directory records. Exact export
names and metadata-backed `RUNTIME_FUNCTION` ranges become evidence-bearing symbol-graph claims,
and the result is written to a portable `.resym` package bound to the input's SHA-256 identity.

This is not yet a disassembler or a full symbol-recovery pipeline. It does not infer names erased
by compilation, reconstruct types, analyze RTTI/vtables, or produce PDB/debugger files. Packed
binaries, .NET assemblies, other CPU architectures, ELF, Mach-O, and debugger export are future
analysis milestones.

The command-line executable itself is built for these host platforms:

| Archive suffix | Host |
|---|---|
| `windows-x64.zip` | 64-bit Windows 10 or newer |
| `linux-x64.tar.gz` | 64-bit x86 Linux; statically linked with musl |
| `macos-x64.tar.gz` | Intel Mac |
| `macos-arm64.tar.gz` | Apple silicon Mac |

The host platform identifies where ReSymbol runs, not which binary format it can analyze.

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
├── README.md
├── LICENSE-APACHE
├── LICENSE-MIT
├── docs/
│   └── install.md
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
└── community.example-resolver/
    ├── plugin.toml
    └── plugin.wasm
```

Do not place plugin source code in this directory expecting ReSymbol to compile it. Current builds
discover and validate unpacked plugin directories, but the WASM, native, managed, and external
runtime hosts are not implemented yet, so plugin code is not executed during analysis.

Disable a discovered plugin without deleting it:

```console
resymbol plugin disable community.example-resolver
resymbol plugin enable community.example-resolver
```

The disable command creates `plugin.disabled` in that plugin directory. It can also be created by
hand as an emergency recovery measure. Safe mode suppresses all third-party plugins for that run:

```console
resymbol --safe-mode plugin list
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
cargo build --release --bin resymbol
```

The result is `target/release/resymbol.exe` on Windows or `target/release/resymbol` elsewhere. The
.NET SDK is required only to develop the managed plugin SDK or host; it is not required for the
Rust workspace or official executable archives.
