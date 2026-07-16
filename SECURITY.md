# Security Policy

ReSymbol processes untrusted binaries and loads third-party extensions. Security reports are taken
seriously even during early development.

## Supported versions

There is no stable release yet. Security fixes are applied to the default branch and, once releases
exist, to versions explicitly listed here. Pre-release builds should not be used as a security
boundary for sensitive or hostile workloads.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's private **Report a vulnerability** flow in the repository's Security tab when it is
available. If private vulnerability reporting is unavailable, contact a maintainer privately using
a contact method published on their GitHub profile and include `ReSymbol security` in the subject.
Do not include exploit details in a public discussion.

Please include:

- the affected commit or release;
- the operating system and architecture;
- the smallest reproducible input or plugin you can safely share;
- expected and observed behavior;
- the security impact and required preconditions; and
- any suggested mitigation.

The maintainers aim to acknowledge a report within seven days and will coordinate disclosure after
assessing impact, reproducing the issue, and preparing a fix. Timelines may vary with severity and
project maturity.

## Especially relevant classes of issue

- out-of-bounds reads, memory exhaustion, path traversal, or command execution caused by an input
  binary;
- capability escapes from a sandboxed plugin host, or confusion between process separation and an
  operating-system sandbox;
- memory-safety, JIT/compiler, or host-binding defects that let a WASM component escape the
  in-process Wasmtime boundary or terminate ReSymbol;
- external-process, native, or managed plugin trust being elevated without explicit consent;
- signature, update, or package-confusion flaws that could substitute plugin code;
- corruption or cross-contamination between analyses;
- unsafe handling of symbol-server, source, or model responses; and
- secrets or analyzed binary contents leaking through logs, telemetry, reports, or network access.

## Security boundaries under development

The plugin isolation, permission, package-signing, and update designs are not yet stable security
guarantees. Current implementation details--not roadmap statements--determine the protection a build
provides. See [docs/plugin-system.md](docs/plugin-system.md) for the intended model.

### Debugger targets and the first-party sandbox

The current debugger work is an offline foundation, not a live debugger or malware sandbox. Static
address-space construction and protection assessment parse bytes without loading the target. The
backend-neutral command, event, wire, policy, attestation, and cleanup types define checks that later
processes must enforce; serializing those types does not create containment.

The live-operation contract accepts only one-use lease identifiers registered locally by the trusted
session worker. Host launch leases bind the exact binary; host attach leases bind PID, a trusted
process-start key, executable identity, and attach mode; sandbox-ownership leases additionally bind provider,
policy digest, and a fresh provisioning epoch. Attestation and cleanup evidence carry that same epoch
to reject replay across otherwise identical provisioning attempts. Identifier constructors validate
shape, not randomness: production hosts must generate lease IDs and epochs with a cryptographically
secure source and must never expose grant registration to untrusted command senders.

There is currently no shipped AppContainer launcher, debugger-host process, Hyper-V guest agent, or
verified cleanup journal. Do not execute a hostile sample through the current workbench. Use a
separately administered disposable virtual machine with host integration and networking disabled
until ReSymbol ships and verifies an execution provider. Ordinary host launch and attach will remain
explicit high-risk operations, never fallbacks from an unavailable sandbox.

The planned local provider is a shared-kernel user-mode boundary. Even after it exists, AppContainer,
Job Object, handle, environment, and mitigation restrictions cannot make a kernel exploit safe. The
planned disposable-VM provider is the stronger boundary for samples that may attack Windows itself.
Neither provider is intended to hide from anti-cheat systems or supply covert kernel debugging.
Protection indicators are evidence for analyst review, not proof that a binary is malicious or safe.

See [Debugger and sandbox architecture](docs/debugger-sandbox.md) for the implemented/planned split
and the fail-closed integration gates.

The current external, native, and managed plugin processes provide crash isolation, not an
operating-system sandbox. Approved plugin code retains the ambient filesystem, network, credential,
and process authority of the account launching ReSymbol. Manifest permissions gate ReSymbol
protocol operations only. Treat an external executable, native library, or managed assembly exactly
as code run directly by that account.

The current WebAssembly host is a different boundary. It links only the versioned ReSymbol WIT
imports and deliberately does not link WASI, so a component has no ambient filesystem, network,
environment, clock, or process interface. `binary.read` and claim submission are permission- and
phase-gated, with range, count, and byte limits. Logging is available in every lifecycle phase but
is count- and output-byte-bounded, while cancellation reports the guest deadline. Fuel, linear
memory, stack, and epoch-deadline limits govern instantiated guest execution. Eligible WASM
plugins therefore autoload without an explicit trust record; `resymbol plugin trust` does not
grant or revoke their execution authority. Safe mode, `plugin.disabled`, exact-artifact
quarantine, reset, component validation, and before/after fingerprint and policy checks still
apply.

Wasmtime executes and compiles the component inside the ReSymbol process. The absence of WASI
removes ambient interfaces but does not place the engine behind a process boundary. A vulnerability
in Wasmtime, its generated native code, or ReSymbol's host bindings could crash or compromise
ReSymbol. A 64 MiB default component-byte cap applies before compilation, but the fuel, epoch,
stack, and store controls do not interrupt synchronous Wasmtime validation/JIT compilation or cap
compiler and other host allocations. A pathological component can therefore exceed the configured
guest deadline or memory limit while compiling. The guest controls and transactional claim commit
protect against ordinary instantiated-component faults and resource abuse; they are not defenses
against compiler resource exhaustion or a sandbox escape. Because a changed eligible WASM artifact
can autoload without a new approval prompt, anyone who can write the plugin directory can choose the
next component presented to the in-process engine. Keep the plugin tree writable only by the
intended account even when every installed plugin is WASM.

The process runner places each external plugin or native/managed helper and its descendants in an
owned POSIX process group or Windows Job Object. It terminates the whole owned tree when the direct
child completes, a deadline expires, a stdout/stderr capture worker fails, or the runtime guard
drops. This is lifecycle containment only: it does not restrict filesystem, network, credentials,
process APIs, or any other ambient authority. Windows uses a safe Rust wrapper to assign the child
to its Job Object immediately after spawn, but a narrow pre-assignment escape race remains. On
POSIX a hostile plugin/helper or descendant can deliberately leave its process group or session
and escape later group termination.

External-process, native, and managed plugins require approval bound to the complete plugin-directory
fingerprint. This binds a decision to exact local bytes but does not authenticate a publisher, and
trust must not transfer to a changed artifact. Sandboxed WASM does not require approval, but its
quarantine remains bound to the exact ID and fingerprint, so replacing a failed component is not a
reset of another artifact. Keep plugin directories writable only by the intended user. Native and
managed plugins are always loaded by the application-local `resymbol-native-host[.exe]` and
`resymbol-managed-host[.exe]` siblings; placing a lookalike helper inside a plugin directory must
never affect host selection. A plugin-attributable process fault should terminate the disposable
helper and discard that run's complete claim batch without terminating ReSymbol; a component fault
must discard the in-process WASM transaction and quarantine that exact artifact.

The first managed host verifies the exact directory fingerprint, private-DLL closure, source-binary
identity, and cumulative DLL-plus-binary snapshot budget before loading an assembly. It supplies the
exact `ReSymbol.PluginSdk`, resolves ordinary private dependencies from verified in-memory bytes,
denies its custom load context's unmanaged-resolution callback, phase-bounds host services, and
commits claims only after the complete lifecycle and final identity checks succeed. These are
integrity and transaction controls, not a CLR sandbox. Plugin code can call framework APIs directly,
including explicit `Assembly.Load*` paths that may engage another/default load context and
`NativeLibrary.Load` paths that reach the platform loader. It can also use ordinary filesystem,
network, environment, credential, reflection, interop, and process APIs with the launching account's
authority.

Native and managed helpers flush distinct versioned markers immediately before their first
plugin-code load attempt. The parent strips the marker from user-visible diagnostics and uses it to
attribute post-marker faults to the exact plugin artifact for quarantine. Pre-marker helper
failures remain conservative host-side diagnostics. File snapshots and repeated fingerprints close
ordinary load windows, but mutable same-account directories, hard links, and file-identity races are
still platform-hardening concerns; install trusted plugins in directories other users and processes
cannot modify.
