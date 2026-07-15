ReSymbol scans this directory for unpacked plugins.

Install each plugin in its own child directory with a plugin.toml manifest and its prebuilt
entrypoint. ReSymbol does not compile source code dropped here.

The current alpha can execute eligible WebAssembly Component Model, external-process, native C/C++,
and managed/.NET analysis plugins. A WASM plugin is a prebuilt Component Model `.wasm`; ReSymbol
does not compile source during discovery. Native plugins are host OS/CPU artifacts and run through
the resymbol-native-host sibling shipped beside ReSymbol. A managed plugin is a prebuilt .NET 8 DLL
plus its private managed DLLs; its manifest uses `kind = "managed"` and a portable relative `.dll`
entrypoint. Do not bundle ReSymbol.PluginSdk.dll: the app-local, self-contained
resymbol-managed-host sibling supplies the exact SDK, and ordinary users do not need a system .NET
installation. The first WASM and managed slices run only `analyze` against PE32+ x86-64 input.

Official archives include dev.resymbol.example.wasm-resolver as a ready-to-run two-file example.
It uses the no-WASI host to read the exact DOS MZ signature and submit one evidence-backed claim.
Delete its directory or use `resymbol plugin disable dev.resymbol.example.wasm-resolver` if you do
not want the example to participate in normal analysis.

Sandboxed WASM autoloads without `plugin trust`; safe mode, `plugin.disabled`, exact-artifact
quarantine, and reset still apply. Before first execution of an external-process, native, or managed
plugin, review it and run `resymbol plugin trust <id>` to approve its exact directory fingerprint.
Any change to the manifest, entrypoint, libraries, or data invalidates that approval. Managed
execution additionally verifies and snapshots the private-DLL closure and exact source binary under
one cumulative byte budget. Trust only process plugins you would run directly: process separation
protects ReSymbol from ordinary crashes, but is not an operating-system or CLR sandbox and does not
restrict the plugin's ambient user access. Managed code can call explicit Assembly and
NativeLibrary APIs outside the helper's ordinary verified dependency-resolution path.

The WASM host links no WASI filesystem, network, environment, clock, or process interface. It caps
component bytes and applies memory, fuel, stack, event, binary-read, and epoch-deadline controls to
instantiated guest execution. Wasmtime validation/JIT is synchronous and in-process; except for the
component-byte cap, guest controls do not interrupt compilation or cap its allocations. An engine,
generated-code, or host-binding vulnerability is not contained by a separate process.

Native and managed helpers emit a versioned marker immediately before their first plugin load.
Attributable post-marker failures discard the whole claim batch and quarantine that exact
fingerprint; pre-marker helper failures remain host diagnostics and do not blame the plugin.

Start ReSymbol with --safe-mode to suppress third-party plugins. A plugin.disabled file inside a
plugin directory disables that plugin without deleting it or changing its fingerprint. Host-owned
trust and quarantine records are kept in the .resymbol child directory. See docs/install.md and
docs/plugin-system.md for current commands, limitations, and safety guidance.
