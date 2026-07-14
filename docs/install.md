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

The current release also includes the first external-process analysis-plugin runtime. Dropped-in
plugins are discovered automatically, but process code requires explicit approval bound to its
exact directory fingerprint before it can execute. WASM, native C/C++, managed/.NET, and
debugger-hosted contracts are present for plugin authors; their execution hosts remain future work.

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
├── community.example-process-resolver/
│   ├── plugin.toml
│   └── resolver[.exe]
└── .resymbol/                  # ReSymbol-owned trust/quarantine state
```

Do not place plugin source code in this directory expecting ReSymbol to compile it. A process
plugin must include a runnable entrypoint and any private runtime it needs; on Unix, that entrypoint
must have execute permission. Ordinary users should not need the plugin author's compiler or SDK.

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

An unchanged trusted process analyzer is eligible to run automatically during later analyses. Any
change to a fingerprinted file, including `plugin.toml`, its entrypoint, bundled libraries, or data,
invalidates trust. The host-owned records under `plugins/.resymbol/` are outside plugin directories;
do not copy them as part of a plugin package. Corrupt or unsafe state fails closed.

> [!WARNING]
> The external process is separated from ReSymbol, but it is not operating-system sandboxed. It
> has the ambient filesystem, network, credential, and process access of the user launching it.
> Manifest permissions limit ReSymbol protocol operations; they do not restrict ambient OS access.
> Trust only plugins whose code and publisher you would run directly.

Run a specific approved plugin by ID, or let analysis run all eligible trusted process analyzers:

```console
resymbol analyze path/to/application.exe --plugin community.example-process-resolver
resymbol analyze path/to/application.exe
```

Plugin failures do not prevent base analysis or package creation, and partial claims are discarded.
Unsafe startup, protocol, resource, claim, or runtime failures quarantine that exact artifact. Use
strict mode in automation when plugin success is required; ReSymbol still writes the valid package
before returning a failure status:

```console
resymbol analyze path/to/application.exe \
  --plugin community.example-process-resolver \
  --strict-plugins
```

The first process host supports one-shot `analyze` requests. Interactive `binary.read`/
`read-binary` requests are reserved and not yet available.

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
cargo build --release --bin resymbol
```

The result is `target/release/resymbol.exe` on Windows or `target/release/resymbol` elsewhere. The
.NET SDK is required only to develop the managed plugin SDK or host; it is not required for the
Rust workspace or official executable archives.
