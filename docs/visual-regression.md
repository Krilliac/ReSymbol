# Workbench visual captures

ReSymbol keeps four deterministic review views for the checked-in symbolized MSVC fixture:
**Overview**, **Functions**, **Reconstruction Graph**, and **Address Space**. The capture path builds
the workbench with its opt-in `screenshot` feature, disables persisted window state and animation,
uses a fixed UI zoom, and requires every PNG to be exactly 1440x900 pixels.

On Windows, regenerate the views with:

```powershell
./tools/capture-workbench.ps1
```

The default output directory is `docs/images`. Use `-OutputDirectory <path>` for disposable review
artifacts or `-SkipBuild` after explicitly building
`resymbol-workbench --features screenshot --bin resymbol-workbench`. Each run writes the four PNGs
and `capture-manifest.json`, which records dimensions, byte sizes, and SHA-256 hashes for the input
fixture and outputs.

The capture script treats exact pixel dimensions as the DPI gate. A desktop scale that changes the
physical framebuffer fails the run instead of resampling an image and hiding a layout difference.
Each view also has a bounded process timeout so a failed GUI startup cannot occupy a CI runner
indefinitely.

The Windows visual-capture workflow runs for relevant crate, fixture, capture-tool, and Rust
dependency changes. It uploads the validated files for three days with PNG recompression disabled.
These artifacts are for human review: ReSymbol does not compare their pixels until a reviewed,
checked-in baseline and an explicit update policy exist.
