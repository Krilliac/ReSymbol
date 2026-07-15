#!/usr/bin/env bash
set -euo pipefail

example_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_dir="$(cd -- "${example_dir}/../../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-${repository_dir}/target/resymbol-example-wasm}"
locked=()
if [[ -f "${example_dir}/Cargo.lock" ]]; then
    locked=(--locked)
fi

if command -v rustup >/dev/null 2>&1; then
    rustup target add wasm32-unknown-unknown
fi

cargo build \
    --manifest-path "${example_dir}/Cargo.toml" \
    "${locked[@]}" \
    --release \
    --target wasm32-unknown-unknown \
    --target-dir "${target_dir}" \
    -p resymbol-example-wasm-guest

cargo run \
    --manifest-path "${example_dir}/Cargo.toml" \
    "${locked[@]}" \
    --release \
    --target-dir "${target_dir}" \
    -p resymbol-example-wasm-componentize \
    -- \
    "${target_dir}/wasm32-unknown-unknown/release/resymbol_example_wasm_guest.wasm" \
    "${example_dir}/example-resolver.wasm"
