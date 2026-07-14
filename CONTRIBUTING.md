# Contributing to ReSymbol

Thanks for helping build ReSymbol. The project is at an early stage, so clear boundaries,
reproducible evidence, and small reviewable changes are especially valuable.

## Before you begin

- Search existing issues and pull requests before opening a duplicate.
- Open a design issue before making a broad change to the symbol graph, plugin ABI, persistence
  format, confidence model, or security boundary.
- Never upload a proprietary binary, leaked symbol file, credential, or fixture you cannot legally
  redistribute.
- Keep deterministic findings separate from inferred labels and types.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development setup

The core workspace requires only the Rust toolchain declared in `rust-toolchain.toml`. Installing
[rustup](https://rustup.rs/) and cloning the repository is sufficient; rustup selects the pinned
toolchain automatically.

```console
git clone https://github.com/Krilliac/ReSymbol.git
cd ReSymbol
cargo build --workspace
cargo test --workspace --all-features
```

The .NET 8 SDK is optional and is needed only for managed SDK or host development. Plugins written
with other toolchains should document their contributor requirements, but normal ReSymbol users
must not be required to install those compilers.

## Required checks

Run the checks relevant to your change before opening a pull request:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

When managed projects are present, also run:

```console
dotnet build --configuration Release
```

CI repeats Rust checks on Linux, Windows, and macOS and validates managed projects separately.

## Change guidelines

### Rust

- Prefer safe Rust. The workspace forbids unsafe code unless the architecture is explicitly
  revised through review.
- Return structured errors with actionable context; do not panic on an invalid binary or plugin.
- Keep parsing bounds-checked and put resource limits around attacker-controlled counts and sizes.
- Avoid platform-specific behavior in the core unless it is behind a clear interface.
- Add tests for new behavior, including malformed-input and failure-path cases.

### Plugins and protocols

- Treat published interfaces as versioned contracts, even before 1.0.
- Add capability permissions only when the plugin cannot work with a narrower scope.
- Plugins should emit evidence-backed claims, not mutate the canonical graph directly.
- Native and managed extensions should default to process isolation. An in-process fast path must
  remain an explicit trust decision.
- A plugin failure must remain attributable to that plugin and must not corrupt an analysis.
- Update [docs/plugin-system.md](docs/plugin-system.md) when changing discovery, lifecycle, ABI, or
  health behavior.

### Documentation

- Describe implemented behavior in the present tense and future behavior as planned.
- Include concrete failure cases and security implications where relevant.
- Keep examples free of proprietary application names and data.

## Tests and fixtures

Prefer tiny fixtures produced from source included in the repository. Record the compiler, target,
optimization level, and stripping operation needed to reproduce binary fixtures. Generated files
should be reproducible, and their origin and license must be documented.

Matching and inference changes should eventually report more than raw accuracy. Useful evaluation
includes boundary precision/recall, top-k name or type accuracy, coverage, cross-build mapping
accuracy, and confidence calibration.

## Pull requests

Keep each pull request focused. In its description:

- explain the user-visible outcome;
- identify security, compatibility, and data-format implications;
- list tests performed; and
- call out follow-up work rather than hiding incomplete behavior.

Use short, imperative commit subjects where practical. Maintainers may ask for a change to be split
when independent concerns make review difficult.

## Licensing contributions

By submitting a contribution, you agree that it may be distributed under the terms of both the MIT
License and the Apache License 2.0, at the recipient's option, unless you clearly state otherwise
before the contribution is accepted.

