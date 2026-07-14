## Outcome

<!-- What user-visible or developer-visible result does this change produce? -->

## Approach

<!-- Summarize the implementation and important alternatives or tradeoffs. -->

## Verification

<!-- List commands, fixtures, platforms, and manual checks used. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] Managed/native/plugin-specific checks, if applicable

## Compatibility and security

<!-- Note changes to schemas, plugin APIs/ABIs, permissions, trust boundaries, binary parsing, resource use, or exported formats. Write "None" only after considering them. -->

## Checklist

- [ ] I kept extracted facts distinct from matched or inferred claims.
- [ ] I added or updated tests for behavior and relevant failure paths.
- [ ] I updated documentation and labeled planned behavior accurately.
- [ ] I did not add proprietary binaries, leaked symbols, secrets, or unauthorized fixtures.
- [ ] I called out breaking changes and follow-up work explicitly.

