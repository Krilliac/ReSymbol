# Workbench visual captures

ReSymbol's standard deterministic capture contract covers thirteen scenarios for the checked-in
symbolized MSVC fixture:

- `open-empty` shows the unmistakable **Open Binary** empty state without invoking a native dialog;
- `overview`, `functions`, `graph`, and `address-space` cover the primary review surfaces;
- `disassembly` covers the selected exact instruction table;
- `disassembly-actions` opens the real instruction-action renderer on the fixture's canonical
  conditional branch at RVA `0x116E`, including static patch actions and the disconnected live-debug
  reason;
- `exact-byte-editor` opens the real static-only editor on that same canonical branch with a
  deterministic same-length condition inversion, preserving immutable original evidence while
  showing a complete replacement decode and an enabled queue action without queuing or publishing;
- `static-patch-confirmation` queues one fixed exact NOP draft, waits for the real worker-owned
  no-write preview, resolves a canonical create-new destination, and opens the explicit publication
  modal with bound source/plan/output hashes and warnings without invoking a picker or writing a
  patched binary;
- `binary-switch-confirmation` binds a real unsaved review decision and shows the deterministic
  replacement confirmation with a synthetic, never-opened path;
- `debugger-sandbox` shows the non-executing discovery surface, while
  `debugger-readiness-result` waits for the read-only probe and scrolls its result card into view;
  and
- `exports` exposes the existing validated export preview without publishing a file.

The capture path builds the workbench with its opt-in `screenshot` feature, disables persisted
window state and animation, clears interactive pointer state, sets a fixed native viewport and UI
zoom, waits for scenario-specific worker results and panel settling, and then uses egui's next-frame
screenshot event. None of the deterministic scenarios depends on a native file picker or user
input. The screenshot build disables eframe's normal monitor-size clamp so a smaller hosted-runner
desktop cannot shrink the framebuffer. Every PNG must be exactly 1440x900 pixels in the default
run.

Scenario-visible text is also machine-independent. Offline lifecycle rows show stable completion
evidence without the request-local session identifier, and exact-source and export rows use the
compact artifact filename instead of a capture-machine directory. The complete session identifier
and canonical paths remain bound in application state. Offline evidence exposes the exact details
as hover text with Windows verbatim path prefixes removed, while normal builds retain the editable
export path. This is only a capture-presentation boundary and does not weaken source identity,
lifecycle validation, or publication destination binding.

On Windows, regenerate the views with:

```powershell
./tools/capture-workbench.ps1
```

For the focused keyboard layout at the documented minimum viewport, write a disposable capture with:

```powershell
./tools/capture-workbench.ps1 -OutputDirectory ./target/workbench-minimum `
  -CaptureWidth 1024 -CaptureHeight 680 -CaptureTabs functions-focused
```

`-CaptureTabs` accepts any supported subset, including the separate `functions-focused` keyboard
scenario, while `-CaptureWidth` and `-CaptureHeight` retain exact framebuffer validation. Duplicate
scenario names fail before launch. Custom dimensions or interaction scenarios should use a
disposable output directory; they do not replace the default checked-in reference set.

The default output directory is `docs/images`. Use `-OutputDirectory <path>` for disposable review
artifacts or `-SkipBuild` after explicitly building
`resymbol-workbench --features screenshot --bin resymbol-workbench`. A default run writes the thirteen
standard PNGs and `capture-manifest.json`. Manifest schema 2 records the capture-set name, requested
view names, exact expected artifact names, dimensions, byte sizes, and SHA-256 hashes for the input
fixture and outputs. The script refuses to write a successful manifest when the captured artifact
sequence differs from that scenario contract.

The script queries the capture desktop DPI under a per-monitor-aware-v2 context and converts the
fixed physical viewport into logical points with the reciprocal egui zoom. The application then
captures egui's returned native framebuffer without resizing it. This keeps both the pixels and
logical layout stable at supported desktop scales; any mismatch still fails loudly. Each view also
has a bounded process timeout so a failed GUI startup cannot occupy a CI runner indefinitely.

`docs/images/capture-manifest.json` declares the current checked-in, human-reviewed reference set.
Its `requested_views`, `expected_artifacts`, and `captures` entries must agree with every
`workbench-*.png` actually present in that directory. These captures document accepted appearance
and make visual changes reviewable in source control, but they are not automated pixel-equivalence
thresholds. The current manifest identifies the twelve previously reviewed reference PNGs
explicitly; the next intentional default refresh promotes the complete thirteen-scenario standard
set without pretending that the new confirmation pixels have already been reviewed.

When intentionally updating the references, run the script with its default output directory,
inspect all thirteen full-size images for layout, clipping, stale or duplicate widget warnings,
incorrect state, and accidental hover styling, then review the manifest hashes and commit the
manifest plus every PNG whose bytes changed. A manually replaced individual image or manifest-only
edit is not a complete reference refresh; CI compares the reference manifest's declared view and
artifact names with the files on disk. Byte-identical regenerated images do not need new Git
objects.

The Windows visual-review workflow runs for relevant crate, fixture, capture-tool, reference, and
Rust dependency changes. It regenerates all thirteen standard scenarios plus a separate focused
Functions view at 1024x680. CI validates PNG format, each scenario's exact dimensions, schema-2
manifest metadata, the complete stable view and artifact-name contract, and checked-in reference
manifest/file agreement. It uploads the files for three days with PNG recompression disabled. CI
deliberately does not compare pixels with `docs/images`, so a passing job proves capture integrity,
not rendering equivalence. The generated artifact remains available for human comparison with the
checked-in references.

GitHub's hosted Windows runner uses a SHA-256-pinned Mesa llvmpipe build placed beside the capture
binary for that job only. This supplies a deterministic software OpenGL implementation without a
system install. It is a CI startup dependency, not a claim that software-rendered pixels match the
native Glow captures reviewed and checked in from a local Windows desktop.
