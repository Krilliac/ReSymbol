# Workbench visual captures

ReSymbol's deterministic capture workflow covers six review views for the checked-in symbolized
MSVC fixture: **Overview**, **Functions**, **Reconstruction Graph**, **Address Space**, and the
selected-row **Disassembly** instruction-action surface, plus the non-executing
**Debugger / Sandbox Readiness** surface. The capture path builds the workbench with
its opt-in `screenshot` feature, disables persisted window state and animation, clears interactive
pointer state, sets a fixed native viewport and UI zoom, waits for the workbench panels to settle,
and then uses egui's next-frame screenshot event. The screenshot build disables eframe's normal
monitor-size clamp so a smaller hosted-runner desktop cannot shrink the framebuffer. Every PNG must
be exactly 1440x900 pixels in the default reference run.

On Windows, regenerate the views with:

```powershell
./tools/capture-workbench.ps1
```

For the focused keyboard layout at the documented minimum viewport, write a disposable capture with:

```powershell
./tools/capture-workbench.ps1 -OutputDirectory ./target/workbench-minimum `
  -CaptureWidth 1024 -CaptureHeight 680 -CaptureTabs functions-focused
```

`-CaptureTabs` accepts any supported subset, while `-CaptureWidth` and `-CaptureHeight` retain exact
framebuffer validation. Custom dimensions or interaction scenarios should use a disposable output
directory; they do not replace the default checked-in reference set.

The default output directory is `docs/images`. Use `-OutputDirectory <path>` for disposable review
artifacts or `-SkipBuild` after explicitly building
`resymbol-workbench --features screenshot --bin resymbol-workbench`. Each run writes the six PNGs
and `capture-manifest.json`, which records dimensions, byte sizes, and SHA-256 hashes for the input
fixture and outputs.

The script queries the capture desktop DPI under a per-monitor-aware-v2 context and converts the
fixed physical viewport into logical points with the reciprocal egui zoom. The application then
captures egui's returned native framebuffer without resizing it. This keeps both the pixels and
logical layout stable at supported desktop scales; any mismatch still fails loudly. Each view also
has a bounded process timeout so a failed GUI startup cannot occupy a CI runner indefinitely.

The six PNGs and `capture-manifest.json` under `docs/images` are the current checked-in,
human-reviewed reference captures. They document the accepted appearance and make visual changes
reviewable in source control, but they are not automated pixel-equivalence thresholds.

When intentionally updating the references, run the script with its default output directory,
inspect all six full-size images for layout, clipping, stale/duplicate-widget warnings, incorrect
state, and accidental hover styling, then review the manifest hashes and commit the manifest plus
every PNG whose bytes changed. A manually replaced individual image or manifest-only edit is not a
complete reference refresh; byte-identical regenerated images do not need new Git objects.

The Windows visual-review workflow runs for relevant crate, fixture, capture-tool, and Rust
dependency changes. It regenerates the same six standard views plus a separate focused Functions
view at 1024x680, validates PNG format, each scenario's exact dimensions, completeness, and manifest
metadata, and uploads the files for three days with PNG recompression disabled. CI deliberately does
not compare those pixels with `docs/images`, so a passing job proves capture integrity—not rendering
equivalence. The generated artifact remains available for human comparison with the checked-in
references.

GitHub's hosted Windows runner uses a SHA-256-pinned Mesa llvmpipe build placed beside the capture
binary for that job only. This supplies a deterministic software OpenGL implementation without a
system install. It is a CI startup dependency, not a claim that software-rendered pixels match the
native Glow captures reviewed and checked in from a local Windows desktop.
