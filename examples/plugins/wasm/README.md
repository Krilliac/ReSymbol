# Source-backed WASM plugin example

This directory contains a real ReSymbol WebAssembly Component Model guest. It has no WASI imports
or ambient filesystem, network, clock, or process authority. The host exposes only the interfaces
in [`sdk/wit/resymbol-plugin.wit`](../../../sdk/wit/resymbol-plugin.wit), gated by the permissions in
`plugin.toml`.

During analysis the guest:

1. reads two bytes at RVA 0 through `binary.read`;
2. verifies the exact `MZ` signature;
3. submits one global comment claim with byte-level evidence; and
4. emits bounded host log messages.

## Rebuild the component

Use the repository-pinned Rust 1.86 toolchain. The only target needed is
`wasm32-unknown-unknown`; no `cargo-component`, WASI SDK, C/C++ compiler, or globally installed
`wasm-tools` binary is required.

On Linux or macOS:

```console
./examples/plugins/wasm/build.sh
```

On Windows PowerShell:

```powershell
.\examples\plugins\wasm\build.ps1
```

Both scripts build the Rust `cdylib`, then run the checked-in `wit-component` helper to encode the
core module as a Component Model binary. The result is `example-resolver.wasm`, exactly the
entrypoint named by `plugin.toml`. Build intermediates go beneath the repository's root `target/`
directory so they never become part of the dropped-in plugin artifact.

Direct dependency versions are exact. The first build creates `Cargo.lock`; check that file in with
the generated component so later builds automatically use Cargo's `--locked` mode. To verify that
source and fixture are in sync, rebuild and confirm that
`git diff --exit-code -- examples/plugins/wasm/example-resolver.wasm` succeeds.
