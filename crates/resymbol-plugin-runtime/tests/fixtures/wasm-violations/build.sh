#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_dir="$(cd -- "${fixture_dir}/../../../../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-${repository_dir}/target/resymbol-wasm-violation-fixture}"
example_dir="${repository_dir}/examples/plugins/wasm"

# Select the repository-pinned toolchain even when this script is invoked from
# another working directory.
cd -- "${repository_dir}"

if command -v rustup >/dev/null 2>&1; then
    rustup target add wasm32-unknown-unknown
fi

cargo build \
    --manifest-path "${fixture_dir}/Cargo.toml" \
    --locked \
    --release \
    --target wasm32-unknown-unknown \
    --target-dir "${target_dir}"

core_module="${target_dir}/wasm32-unknown-unknown/release/resymbol_wasm_violation_fixture.wasm"
cargo run \
    --manifest-path "${example_dir}/Cargo.toml" \
    --locked \
    --release \
    --target-dir "${target_dir}/componentizer" \
    -p resymbol-example-wasm-componentize \
    -- \
    "${core_module}" \
    "${fixture_dir}/component.wasm"
