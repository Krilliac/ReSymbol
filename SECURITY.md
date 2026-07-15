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
- native or managed plugin trust being elevated without explicit consent;
- signature, update, or package-confusion flaws that could substitute plugin code;
- corruption or cross-contamination between analyses;
- unsafe handling of symbol-server, source, or model responses; and
- secrets or analyzed binary contents leaking through logs, telemetry, reports, or network access.

## Security boundaries under development

The plugin isolation, permission, package-signing, and update designs are not yet stable security
guarantees. Current implementation details—not roadmap statements—determine the protection a build
provides. See [docs/plugin-system.md](docs/plugin-system.md) for the intended model.

The current external and native plugin processes provide crash isolation, not an operating-system
sandbox. Approved plugin code retains the ambient filesystem, network, credential, and process
authority of the account launching ReSymbol. Manifest permissions gate ReSymbol protocol
operations only. Treat an external executable or native library exactly as code run directly by
that account.

Executable plugins require approval bound to the complete plugin-directory fingerprint. This binds
a decision to exact local bytes but does not authenticate a publisher, and trust must not transfer
to a changed artifact. Keep plugin directories writable only by the intended user. Native plugins
are always loaded by the application-local `resymbol-native-host[.exe]` sibling; placing a lookalike
helper inside a plugin directory must never affect host selection. A native fault should terminate
the disposable helper and discard that run's complete claim batch without terminating ReSymbol.
