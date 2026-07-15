# Open MSVC x64 analysis fixtures

This directory contains a tiny, source-available PE32+ x86-64 corpus for ReSymbol's native-binary
MVP. The source and generated artifacts are dual-licensed under the repository's MIT or Apache-2.0
terms. They contain no third-party application code and are intended only as parser/analyzer inputs.

`src/milestone2.cpp` deliberately exercises:

- named PE exports and imports;
- unwind-covered functions, direct calls, an internal tail thunk, and an MSVC `REX.W`-prefixed
  import thunk;
- ASCII and UTF-16LE literals plus fixed RIP-relative references;
- modern MSVC x64 Rev1 RTTI, inheritance, vftables, and virtual slots; and
- a writable global reference.

The checked-in corpus is a four-artifact optimization-by-symbol matrix:

- `milestone2-symbolized.exe`: optimized, with CodeView `RSDS` metadata;
- `milestone2-stripped.exe`: optimized, without a debug directory;
- `milestone2-unoptimized-symbolized.exe`: unoptimized, with CodeView `RSDS` metadata; and
- `milestone2-unoptimized-stripped.exe`: unoptimized, without a debug directory.

The existing optimized filenames remain unchanged. The matching `milestone2-symbolized.pdb` and
`milestone2-unoptimized-symbolized.pdb` files are generated under
`target/fixtures/pe-x64-msvc/` for local investigation but are not versioned: MSVC's full PDB
container is not byte-stable across clean LINK invocations even when `/Brepro` produces identical
object files, PE bytes, and RSDS identity.

`expected.json` records every artifact's exact hash and a profile-sensitive semantic oracle.
Portable expectations such as imports, exports, strings, and recovered type names are shared.
Call-site offsets, thunk shapes, RTTI/vftable RVAs, virtual-function RVAs, and other layout-sensitive
requirements are recorded per optimization profile; symbolized and stripped builds of the same
profile share those semantic expectations.

These executables are repository/source analyzer test data. They are present in source checkouts and
source archives but are not installed or bundled in ReSymbol's portable runtime archives.

## Recorded toolchain

- MSVC C++ toolset `14.44.35207` from Visual Studio 2022
- Windows SDK `10.0.26100.0`
- `cl.exe` `19.44.35228.0`
- `link.exe` `14.44.35228.0`
- target `x86_64-pc-windows-msvc`

Both profiles use `/Gy /Gw /GR /MD /GS- /Brepro /experimental:deterministic`. Optimized builds add
`/O2 /Ob1 /Oi`; unoptimized builds add `/Od /Ob0 /Oi-`. Symbolized objects additionally use `/Z7`.
Linking uses a custom entry point, `/INCREMENTAL:NO /OPT:REF /OPT:NOICF /Brepro`, and
`/DEBUG:FULL` only for the symbolized images. `/pathmap` and a stable relative LINK working directory
remove checkout paths from the reproducible PE inputs.

## Rebuild and verify

Select the recorded toolset and SDK explicitly, then run the verifier. The example below uses the
Visual Studio 2022 Community installation path; use the corresponding `vcvars64.bat` path for Build
Tools, Professional, or Enterprise. Visual Studio edition is not part of the recorded identity. The
script instead rejects any other target architecture, toolset, Windows SDK, or exact `cl.exe` and
`link.exe` file version before it builds:

```powershell
cmd /d /c 'call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44.35207 && set CC=cl && set CXX=cl && powershell -NoProfile -File tools\build-analysis-fixtures.ps1 -CheckDeterminism -VerifyCheckedIn'
```

To intentionally regenerate the checked-in PE files after reviewing a compiler or source change:

```powershell
cmd /d /c 'call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44.35207 && set CC=cl && set CXX=cl && powershell -NoProfile -File tools\build-analysis-fixtures.ps1 -CheckDeterminism -Install'
```

For a source-only change, update all four SHA-256 values and the affected shared or profile-specific
semantic expectations after installation. For an intentional compiler or SDK migration, first
update the `toolchain` block, these example commands, and the CI toolset/SDK pin; toolchain
validation remains fail-closed even with `-Install`. Then install the new artifacts, update their
hashes and semantic oracle, and run the analyzer tests. The test suite never executes these
binaries.
