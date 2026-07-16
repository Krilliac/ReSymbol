$ErrorActionPreference = "Stop"

$ExampleDir = $PSScriptRoot
$RepositoryDir = (Resolve-Path (Join-Path $ExampleDir "../../..")).Path
$TargetDir = if ($env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR
} else {
    Join-Path $RepositoryDir "target/resymbol-example-wasm"
}
[string[]]$LockedArgs = if (Test-Path (Join-Path $ExampleDir "Cargo.lock")) {
    @("--locked")
} else {
    @()
}

if (Get-Command rustup -ErrorAction SilentlyContinue) {
    rustup target add wasm32-unknown-unknown
}

cargo build `
    --manifest-path (Join-Path $ExampleDir "Cargo.toml") `
    @LockedArgs `
    --release `
    --target wasm32-unknown-unknown `
    --target-dir $TargetDir `
    -p resymbol-example-wasm-guest
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$CoreModule = Join-Path `
    $TargetDir `
    "wasm32-unknown-unknown/release/resymbol_example_wasm_guest.wasm"
cargo run `
    --manifest-path (Join-Path $ExampleDir "Cargo.toml") `
    @LockedArgs `
    --release `
    --target-dir $TargetDir `
    -p resymbol-example-wasm-componentize `
    -- `
    $CoreModule `
    (Join-Path $ExampleDir "example-resolver.wasm")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
