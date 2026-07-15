# ReSymbol workbench GUI design

This document records the approved direction for ReSymbol's graphical workbench. It is a design
target, not implemented behavior. The current usable interface remains the `resymbol` CLI, and the
choice of UI framework is intentionally not fixed by this document.

The workbench should feel familiar to people who spend time in disassemblers and debuggers while
making ReSymbol's evidence, confidence, provenance, and plugin health more visible than a typical
single-name symbol list.

## Primary workflow

The application shell follows four visible stages:

1. **Open Binary** — select an input and establish its exact identity.
2. **Analyze** — configure and run core analyzers and eligible plugins.
3. **Review** — inspect reconstructed symbols, conflicts, evidence, and losses.
4. **Export** — preview target capabilities and write a package, projection, or tool-specific
   output.

The stage indicator is orientation, not a blocking wizard. An experienced user can move among
project, analysis, review, and export surfaces without discarding state. The primary action at the
top right changes with the stage; during review it is **Export Symbols**, with a menu for choosing
the target.

The title/identity area always shows the active binary and its SHA-256 verification state. A short
status label and icon accompany the hash so verification is never communicated by color alone.

## Approved workbench layout

The default desktop layout has four persistent regions:

```text
┌──────────────── active binary / SHA-256 / workflow / primary action ────────────────┐
│ Project and plugins │ Main result tabs and table/work area │ Contextual inspector  │
│ navigation          │                                    │ evidence and decisions │
├─────────────────────┴────────────────────────────────────┼────────────────────────┤
│ Analysis progress     │ Plugin runs         │ Warnings    │ Logs                   │
└──────────────────────────────────────────────────────────┴────────────────────────┘
```

Splitters should make the left navigation, right inspector, and bottom activity area resizable and
collapsible. The application remembers a user's layout. A **Reset Layout** action restores the
supported default, which is important when plugins or future panels have changed the workspace.

### Project navigation

The left rail presents the current project as a tree:

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

### Main work area

The main region uses task tabs for **Overview**, **Functions**, **Types**, **Relationships**, and
**Exports**. The approved Functions view is a dense, sortable table with:

- status;
- RVA;
- reconstructed name;
- confidence value and compact meter;
- producing source or sources; and
- known size.

Search, a filter button, and a status selector sit immediately above the results. Large result sets
use virtualized rows and stable paging or equivalent position-preserving navigation. Addresses,
sizes, hashes, and disassembly-oriented data use a readable monospace face; controls and prose can
use the normal UI face.

Table status distinguishes at least verified/extracted results, conflicts, inferred hypotheses,
review decisions, and automatic fallback labels. Plugin origin is provenance, not an epistemic
status, and remains visible in the source column or badge. Confidence never acts as a substitute
for provenance: the numeric value, status, and source remain visible independently.

The layout can later host synchronized disassembly, pseudocode, graph, hex, and cross-reference
views without changing the surrounding navigation and inspector model.

### Contextual inspector

Selecting a symbol opens its inspector on the right. The approved function inspector contains:

- selected reconstructed name and status;
- RVA, size, confidence, sources, and last analysis observation;
- provenance grouped by producer/run;
- evidence cards with short explanations and analyzer-defined contribution or context values;
- competing names with their independent confidence and source;
- **Accept**, **Keep as Alias**, and **Reject** review actions;
- an annotation field; and
- relevant diagnostics or links to the full log.

Review actions create explicit user decisions with provenance; they do not destructively erase the
underlying alternatives. Undo/redo and a decision history are required before bulk review is
considered complete.

An evidence percentage is shown only when its producer defines that quantity. The UI must not imply
that evidence scores are universally additive or that adding the displayed values computes the
claim confidence.

### Activity and diagnostics

The bottom area keeps long-running work understandable without covering the result table. Its
default panels are:

- stage-by-stage analysis progress;
- plugin runs with outcome and elapsed/completion information;
- warnings grouped by actionable cause; and
- a timestamped log with a full-log view.

Warnings link to the affected results or plugin details. Export preparation belongs in the same
progress model and must surface lossy conversions before the user writes a debugger-specific
artifact.

## Export experience

The GUI should consume the same validated export projection as the CLI. It must not maintain an
independent reconciliation path. The export surface should show:

- exact target binary identity;
- selected format and destination;
- counts of functions, globals, and types that can be represented;
- grouped projection and target-specific losses;
- existing-file/create-new behavior; and
- a reviewable summary before writing.

IDA/Ghidra script export and the current MAP and exact-RSDS public-symbol PDB CLI targets should
differ only in their target capability panels. A future PDB panel must require selection of the
exact original PE, show that its SHA-256 matches the package, and report the unambiguous RSDS
GUID+age gate before enabling the write action. It must describe the current output as public
function/global names only, without implying that types, private symbols, source lines, or
function extents are present. This records how the existing CLI capability should appear; it does
not claim that the GUI exists. An interactive debugger bridge may add preview and selective
application, but it still uses the core identity and projection rules.

## Theme system

Themes are token sets over one layout and interaction model. A theme can change surfaces,
typography tuning, borders, syntax colors, and selection treatment. It cannot change the meaning
of a status or hide required identity, provenance, warning, or focus cues.

The approved presets are described below. This theme catalog is design-only until the desktop
workbench itself is implemented.

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

The workbench is not complete until all shipped themes support:

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

## Deliberately deferred decisions

This design does not yet select a GUI framework, docking library, renderer, or packaging strategy.
It also does not claim that disassembly editing, live debugging, multi-binary workspaces, remote
collaboration, or interactive IDA/Ghidra connectivity exists. Those choices should be evaluated
against startup size, portability, accessibility, crash isolation, and the one-download product
principle when GUI implementation begins.
