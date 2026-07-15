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

The checked-in `milestone2-symbolized.exe` is linked with CodeView `RSDS` metadata. The matching PDB
is generated into `target/fixtures/pe-x64-msvc/` for local investigation but is not versioned:
MSVC's full PDB container is not byte-stable across clean LINK invocations even when `/Brepro`
produces identical object files, PE bytes, and RSDS identity. The checked-in
`milestone2-stripped.exe` omits the debug directory. `expected.json` records exact artifact hashes
and a semantic oracle shared by both builds.

## Recorded toolchain

- Visual Studio 2022 Community C++ toolset `14.44.35207`
- Windows SDK `10.0.26100.0`
- `cl.exe` `19.44.35228.0`
- `link.exe` `14.44.35228.0`
- target `x86_64-pc-windows-msvc`

Compilation uses `/O2 /Ob1 /Oi /Gy /Gw /GR /MD /GS- /Brepro
/experimental:deterministic`; the symbolized object additionally uses `/Z7`. Linking uses a custom
entry point, `/INCREMENTAL:NO /OPT:REF /OPT:NOICF /Brepro`, and `/DEBUG:FULL` only for the
symbolized image. `/pathmap` and a stable relative LINK working directory remove checkout paths from
the reproducible PE inputs.

## Rebuild and verify

Select the recorded toolset and SDK explicitly, then run the verifier. The script rejects any other
compiler, linker, target architecture, or SDK before it builds:

```powershell
cmd /d /c 'call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44.35207 && set CC=cl && set CXX=cl && powershell -NoProfile -File tools\build-analysis-fixtures.ps1 -CheckDeterminism -VerifyCheckedIn'
```

To intentionally regenerate the checked-in PE files after reviewing a compiler or source change:

```powershell
cmd /d /c 'call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44.35207 && set CC=cl && set CXX=cl && powershell -NoProfile -File tools\build-analysis-fixtures.ps1 -CheckDeterminism -Install'
```

For a source-only change, update the SHA-256 values and semantic oracle after installation. For an
intentional compiler or SDK migration, first update the `toolchain` block, this command, and the CI
pin; toolchain validation remains fail-closed even with `-Install`. Then install the new artifacts,
update their hashes and semantic oracle, and run the analyzer tests. The test suite never executes
these binaries.
