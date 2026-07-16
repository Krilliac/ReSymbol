# ReSymbol workbench GUI design

This document records both the first implemented ReSymbol workbench slice and the approved
long-term direction. `crates/resymbol-workbench` is a Windows-first desktop application built with
the pinned eframe/egui 0.32.3 stack; that version was selected to preserve the workspace's Rust 1.86
minimum. The `resymbol` CLI remains supported and currently exposes capabilities that the GUI does
not. Sections that describe later review, docking, disassembly, or debugger integration are target
design rather than current behavior.

The workbench should feel familiar to people who spend time in disassemblers and debuggers while
making ReSymbol's evidence, confidence, provenance, and plugin health more visible than a typical
single-name symbol list.

## Primary workflow

The application shell follows four visible stages:

1. **Open Binary** — select an input and establish its exact identity.
2. **Analyze** — run the core analyzer without blocking the UI.
3. **Review** — inspect reconstructed symbols, conflicts, evidence, and losses.
4. **Export** — preview target capabilities and write a package, projection, or tool-specific
   output.

The first slice implements **Open Binary -> background core-only Analyze -> Review -> Export**.
Opening a binary queues analysis away from the egui event loop, then publishes one validated shared
session and export projection to the review surface. Plugin execution and analysis configuration
are not wired into this flow yet. The stage indicator remains orientation rather than a blocking
wizard, and the primary action changes with the active stage.

The title/identity area shows the active binary and the exact SHA-256 identity bound to the analysis
package. A short status label accompanies the hash so identity is never communicated by color
alone.

## Approved workbench layout

The implemented shell has the approved four persistent regions:

```text
┌──────────────── active binary / SHA-256 / workflow / primary action ────────────────┐
│ Project and plugins │ Main result tabs and table/work area │ Contextual inspector  │
│ navigation          │                                    │ evidence and decisions │
├─────────────────────┴────────────────────────────────────┼────────────────────────┤
│ Analysis progress     │ Plugin runs         │ Warnings    │ Logs                   │
└──────────────────────────────────────────────────────────┴────────────────────────┘
```

The left navigation, right inspector, and bottom activity area are resizable and collapsible. Panel
sizes and collapsed state persist with the application, and **Reset Layout** restores the supported
default. This is a splitter-based shell rather than a docking system; arbitrary tab docking remains
deferred.

### Project navigation

The approved left rail presents the current project as a tree:

- active binary and exact-identity status;
- analysis sessions;
- symbols;
- types;
- relationships;
- plugins and their health; and
- project settings.

The plugin node can expand to individual analyzers and matchers. Healthy, disabled, incompatible,
approval-required, and quarantined states use an icon plus text. A quarantined plugin remains
visible with its reason and recovery path; it does not disappear or prevent the project from
opening.

The first slice shows discovered plugin health as read-only information. It does not execute,
enable, disable, approve, or recover plugins from the GUI, and analyzed sessions contain only core
results.

### Main work area

The main region retains the approved task-tab model. The first slice implements the dense
**Functions** table and the evidence-first **Reconstruction Graph** tab. The table includes:

- status;
- RVA;
- reconstructed name;
- confidence value and compact meter;
- producing source or sources; and
- known size.

Search and status filtering sit immediately above the results. Rows are virtualized, and sorting by
the exposed columns operates on stable indexes without reordering the canonical shared model.
Addresses, sizes, hashes, and disassembly-oriented data use a readable monospace face; controls and
prose use the normal UI face.

Table status distinguishes at least verified/extracted results, conflicts, inferred hypotheses,
review decisions, and automatic fallback labels. Plugin origin is provenance, not an epistemic
status, and remains visible in the source column or badge. Confidence never acts as a substitute
for provenance: the numeric value, status, and source remain visible independently.

The Reconstruction Graph is a bounded navigator over retained relationships, not a visual inference
engine. Its default root is the PE entry point when that address is a projected function; otherwise
it uses a deterministic lowest-RVA navigation fallback, explicitly not an inferred `main`.
**Focus selected** can make the current function the root, selecting a graph node updates the shared
function selection and evidence inspector, and the Functions table remains the full
sortable/filterable inventory.

Every displayed edge corresponds to a retained direct-call or thunk record. Function targets connect
to projected function nodes and import targets connect to explicit import-slot nodes; spatial
proximity, RVA ordering, and drawing layout never create relationships. This keeps the view aligned
with the same evidence and provenance shown in the inspector rather than presenting a plausible but
unsupported call graph.

Rendering is deliberately bounded for large binaries. The graph expands a fixed number of tiers and
nodes from the active root, reports the retained node/edge count for that view, and shows an explicit
**BOUNDED** cue when more reachable content exists. Refocusing is how the user inspects another local
region; truncation is never hidden or described as complete recovery.

The layout can later host synchronized disassembly, pseudocode, hex, and cross-reference views
without changing the surrounding navigation and inspector model. Editable and exhaustive
control-flow graphing remains later work.

### Static address space and protection assessment

The implemented **Address Space** tab is a non-executing preferred-image view for supported PE32+
inputs. It partitions `SizeOfImage` into headers, declared sections and zero-filled tails, and
explicit gaps; shows preferred virtual addresses, file backing, and declared read/write/execute
attributes; and stays bound to the same exact SHA-256 identity as the analysis package. It is not a
live process map and must not imply that ASLR, runtime allocations, loaded modules, guard pages, or
changed page protections have been observed.

Protection assessment shows bounded artifact evidence for entry-point placement and backing,
TLS-before-entry behavior, anti-debug imports, common packer section names, high-entropy samples, and
writable/executable sections. These are review cues, not malware verdicts. Offline opening keeps the
evidence visible without granting permission to run the target. A future live launch or attach must
use a separate blocking acknowledgement bound to the exact binary, operation, provider, and sandbox
policy; dismissing an offline finding can never authorize execution.

Static and future live mappings remain distinct views. See
[Debugger and sandbox architecture](debugger-sandbox.md) for the ownership and containment gates.

### Contextual inspector

Selecting a function opens the implemented evidence inspector on the right. It shows the selected
name and status, RVA, size, confidence, producer/source information, competing names, uncollapsed
claims, provenance, and evidence with any producer-defined confidence and artifacts.

The complete approved inspector model contains:

- selected reconstructed name and status;
- RVA, size, confidence, sources, and last analysis observation;
- provenance grouped by producer/run;
- evidence cards with short explanations and analyzer-defined contribution or context values;
- competing names with their independent confidence and source;
- **Accept**, **Keep as Alias**, and **Reject** review actions;
- an annotation field; and
- relevant diagnostics or links to the full log.

The inspector implements **Accept Primary**, **Keep as Alias**, and **Reject** for exact name claims.
Each proposal displays its retained producer, method, run identifier, evidence, and complete-claim
SHA-256 fingerprint. Decisions and optional rationale annotations enter a binary-bound ledger with
undo/redo history; non-name claims remain explicitly read-only. Sidecar loads, create-new saves, and
reviewed-projection rebuilds run on the bounded service worker, and stale operation or ledger results
cannot replace current UI state. Bulk review remains future work.

An evidence percentage is shown only when its producer defines that quantity. The UI must not imply
that evidence scores are universally additive or that adding the displayed values computes the
claim confidence.

### Activity and diagnostics

The bottom area keeps long-running work understandable without covering the result table. The first
slice exposes analysis progress, warnings, and timestamped log messages. Its approved complete
panel set is:

- stage-by-stage analysis progress;
- plugin runs with outcome and elapsed/completion information;
- warnings grouped by actionable cause; and
- a timestamped log with a full-log view.

Warnings link to the affected results or plugin details. Export preparation belongs in the same
progress model and must surface lossy conversions before the user writes a debugger-specific
artifact.

Plugin-run activity remains empty until GUI plugin execution is implemented; read-only plugin
health in the navigation is not represented as a run.

An optional external companion console mirrors the same timestamped activity and accepts bounded
typed commands for status, project loading, tab/function focus, themes, panel visibility, exports,
and shutdown. It is off by default and can be spawned or disabled from the workbench. Console input
never mutates widgets or analysis state directly; the UI event loop remains the single state owner.

## Export experience

The implemented GUI consumes the same validated `AnalysisSession`, `.resym` package envelope, and
neutral export projection as the CLI; it has no independent reconciliation path. Active review
decisions are projected through the shared application service before review-aware exports. The GUI
writes only new files and refuses to replace an existing destination. It can create:

- a canonical `.resym` package;
- the debugger-neutral JSON projection;
- the bounded Markdown review report; and
- Microsoft-linker-style MAP output;
- an exact-RSDS public-symbol PDB; and
- identity-gated IDA Python and Ghidra Java import scripts.

The broader export surface should show:

- exact target binary identity;
- selected format and destination;
- counts of functions, globals, and types that can be represented;
- grouped projection and target-specific losses;
- existing-file/create-new behavior; and
- a reviewable summary before writing.

The PDB panel requires the exact verified original PE and describes the current output as public
function/global names only, without implying that types, private symbols, source lines, or function
extents are present. IDA and Ghidra scripts retain their identity gate. An interactive debugger
bridge may add preview and selective application, but it must still use the core identity and
projection rules.

The first slice opens and analyzes binaries; it does not open legacy `.resym` packages. Supporting
legacy package review must use the CLI's explicit compatibility paths and must not relabel missing
analysis as current recovery.

## Theme system

Themes are token sets over one layout and interaction model. A theme can change surfaces,
typography tuning, borders, syntax colors, and selection treatment. It cannot change the meaning
of a status or hide required identity, provenance, warning, or focus cues.

Graphite, Light, IDA-inspired, and Classic Debugger are implemented and persist as application
preferences. They share the same layout, density, status meanings, and evidence requirements.

Theme selection is an application preference, not analysis data, and is remembered across
projects. Switching themes must not change table density, hide panels, or alter a review/export
decision unless the user separately changes those settings.

### Graphite (default)

A modern charcoal/near-black workbench with restrained teal primary actions and selection accents.
It favors long analysis sessions, clear panel separation, and low visual noise. This is ReSymbol's
default identity rather than an imitation of another tool.

### Light

A white and soft-neutral workspace with the same information density and teal ReSymbol accents.
Borders and alternating surfaces replace dark-theme elevation; muted text remains high-contrast
enough for long tables. Every screen must be designed and tested in Light rather than produced by a
last-minute color inversion.

### IDA-inspired

A dense navy/blue technical workspace with crisp cyan or blue focus accents, compact tabs, and
strong monospace data presentation. It should provide familiarity without copying proprietary
icons, exact colors, trademarks, or layout assets.

### Classic Debugger (OllyDbg-inspired)

A compact light-gray, bordered presentation with traditional menu/tool chrome, royal-blue row
selection, and high information density. This preset deliberately evokes classic Windows debugger
ergonomics while retaining ReSymbol's modern evidence and plugin-health model.

### x64dbg-inspired (later)

A darker blue debugger-oriented preset is approved as a later addition after the base theme token
system and the first four presets are stable. It follows the same non-copying and semantic-color
rules.

The names “IDA-inspired,” “OllyDbg-inspired,” and “x64dbg-inspired” describe familiarity
presets; they do not imply affiliation with or endorsement by those projects.

## Semantic status invariants

Themes may tune shades for contrast, but the concepts remain stable:

| Meaning | Default family | Required redundant cue |
|---|---|---|
| Verified or exact | teal/cyan | shield/check icon and text |
| Healthy or completed | green | success icon and outcome text |
| Conflict, warning, or review needed | amber/orange | warning icon and reason |
| Plugin provenance (orthogonal to truth status) | purple | plugin icon and source label |
| Inferred hypothesis | purple/blue | hypothesis icon and explicit inferred label |
| Quarantined, failed, or destructive action | red | stop/error icon and explicit text |
| Automatic fallback or unavailable | neutral gray | state icon and text |

“Verified” must mean an exact or explicitly reviewed state defined by the data model; a high
confidence score alone never receives that label. Plugin-produced information does not become
verified merely because the plugin completed successfully.

## Accessibility and interaction requirements

The workbench is not feature-complete until all themes support:

- text and essential control contrast targeting WCAG 2.2 AA;
- status conveyed by label and icon as well as color;
- visible keyboard focus that remains distinct from row selection;
- full keyboard navigation for trees, tabs, tables, splitters, menus, review actions, and dialogs;
- scalable UI and independent monospace/editor font sizing;
- color-blind checks for common red/green and blue/purple confusion;
- screen-reader names for icons, meters, badges, and evidence controls;
- reduced-motion behavior and no required time-sensitive animation; and
- high-contrast operating-system settings where the selected UI framework supports them.

Confidence meters always include a numeric value. Progress bars include stage text and outcome.
Tooltips supplement visible labels; they do not contain the only explanation of a status.

The existence of the initial alpha shell does not mark this checklist complete. Keyboard traversal,
assistive-technology naming, contrast, scaling, reduced motion, and high-contrast behavior remain
workbench-completion and pre-1.0 requirements for every theme and workflow.

## Current boundaries and deliberately deferred work

eframe/egui 0.32.3 with the glow renderer is selected for the initial application shell, and a
portable Windows archive is the first packaging target. Cross-platform release packaging remains a
later validation task.

The current slice has no GUI plugin execution, legacy-package migration, bulk-review workflow,
docking, disassembly/pseudocode views, editable or exhaustive control-flow graphing, live debugger
bridge, process-executing debugger host, verified AppContainer/VM provider, multi-binary workspace,
or remote collaboration. Current-package opening, exact-claim Accept Primary/Keep as Alias/Reject,
undo/redo, binary-bound review sidecars, and all six symbol export formats are implemented. The
backend-neutral debugger and sandbox contracts are foundations for later live features, not proof
that an operating-system boundary exists. Future choices must still be evaluated against startup
size, portability, accessibility, crash isolation, exact identity, and the one-download product
principle.
