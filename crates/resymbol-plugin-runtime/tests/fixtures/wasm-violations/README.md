# Wasm host-violation fixture

This test-only Component Model guest deliberately uses ReSymbol host calls in
forbidden ways. Its initialization behavior is selected by the session ID so
the runtime suite can verify that propagated and swallowed guest errors cannot
mask host-recorded phase or permission violations.

Rebuild `component.wasm` from the repository root with:

```console
bash crates/resymbol-plugin-runtime/tests/fixtures/wasm-violations/build.sh
```

The script uses both tracked lockfiles, compiles this crate for
`wasm32-unknown-unknown`, and passes the core module through the pinned encoder
in `examples/plugins/wasm/componentize`. CI rebuilds the component and rejects
any lockfile or binary diff.
