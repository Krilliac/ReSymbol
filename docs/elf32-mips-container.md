# ELF32 MIPS container intake

Package schema 14 adds a deliberately bounded first ELF slice. `resymbol analyze`
accepts ELF32, little-endian, version-1 `ET_EXEC` files whose machine field is
`EM_MIPS`. The parser treats every byte as untrusted and does not load or execute
the input.

The retained evidence is container metadata only:

- exact file size and SHA-256 identity;
- OS ABI, ABI version, type, machine, entry VA/RVA, flags, and table geometry;
- bounded program- and section-header records;
- sorted non-empty `PT_LOAD` mappings, including exact file/memory sizes,
  permissions, and alignment; and
- one identity-bound `SymbolGraph` with zero base claims.

Zero-sized `PT_LOAD` records do not expand the image. Virtual gaps remain gaps:
ReSymbol stores a small segment vector and never allocates a buffer spanning the
preferred virtual extent. File ranges, table arithmetic, segment congruence,
entry backing, collection counts, and the reconstructed sparse extent are all
revalidated during package deserialization.

`EM_MIPS` is only a container fact. It is not evidence that a generic MIPS32 or
MIPS64 decoder models the executable correctly; PlayStation 2 software may
target the Emotion Engine/R5900 family. Although this document specifies the
ELF32 little-endian intake, the decoder-selection rule applies to all four
canonical container identities: `elf32-em-mips-le`, `elf32-em-mips-be`,
`elf64-em-mips-le`, and `elf64-em-mips-be`. None infers a target architecture or
dispatches a generic MIPS decoder; generic MIPS decoding requires an explicit
caller request. This rule is independent of retained symbol-table metadata and
does not itself authorize instruction-decoding or control-flow claims.

Callers may explicitly select the exact in-memory decoder profile
`ps2-ee-r5900-le-core-v1`. It returns an always-available pure-Rust decoder for
a frozen, fail-closed scalar R5900 core whitelist and never consults generic
MIPS or Capstone. The separate immutable profile
`ps2-ee-r5900-le-core-v1-mmi-word-shift-v1` preserves that entire contract and
adds only canonical `PSLLW`, `PSRLW`, and `PSRAW` encodings with `rs = 0`.
The further immutable profile
`ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1` preserves both
earlier profiles and adds only `PAND`, `POR`, `PXOR`, and `PNOR`. The next immutable profile
`ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1-packed-add-v1` preserves all three
earlier profiles and adds only `PADDW`, `PADDH`, and `PADDB`. The following immutable profile
`ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1-packed-add-v1-packed-sub-v1` preserves
all four earlier profiles and adds only `PSUBW`, `PSUBH`, and `PSUBB`. The next immutable profile
`ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1-packed-add-v1-packed-sub-v1-packed-compare-gt-v1`
preserves all five earlier profiles and adds only `PCGTW`, `PCGTH`, and `PCGTB`.
Recognized-but-unmodeled residual MMI, coprocessor, VU macro, and conditional-trap spaces return
typed unsupported outcomes; reserved and unknown words remain invalid.
`DecoderProfile::PS2_EE_R5900_LATEST` currently resolves to that exact packed-compare-gt-v1 variant;
stored selections retain the resolved variant rather than the moving alias.

The Workbench can use this opt-in decoder only for a structured ELF32, little-endian, `ET_EXEC`,
`EM_MIPS` analysis with an exact verified source. It never infers R5900 from `EM_MIPS` or an
architecture string. The user must explicitly select the exact bundled profile, and the transient
binding includes full identity, canonical source path, requested RVA span, and resolved profile.
The existing profile-agnostic offline worker still reads the bytes; a pure planner decodes at the
checked preferred VA, then maps every row and stop address back to RVA. This preserves correct
high-base J/JAL targets. Follow is available only for a translated target with exact file backing.
No Workbench selection is serialized into preferences, packages, projections, plugins, reviews, or
worker/debugger protocols, and the preview does not model delay slots, CFG, or function boundaries.

`resymbol ps2 observe EXACT_PS2_EE_ELF --profile EXACT_R5900_PROFILE --output
NEW_PRIVATE_REPORT.resym` is a separate, non-executing CLI consumer. It accepts only the six exact
profile names above, never `PS2_EE_R5900_LATEST` or a generic MIPS alias, reads one exact eligible ELF
snapshot, and records the resolved profile in a binary-bound canonical-JSON `.resym` package. The
write is capped at 64 MiB, uses create-new semantics, and never replaces an existing destination.
Because the report may retain target-derived string anchors, keep it private and outside version
control.

Debugger-neutral JSON and Markdown projection, IDAPython, and Ghidra Java can
represent the empty validated graph. The format-neutral static address-space
model and offline host retain exactly one region per non-empty `PT_LOAD`, so the
workbench can show mapped permissions and exact file-backed bytes as hex while
rejecting virtual gaps, zero-fill, cross-segment spans, and partial backing.
MAP, PDB, static patch, PE plugin-host, and protection-analysis actions remain PE/x86-64-only. The
explicit R5900 preview exposes read-only copy and file-backed direct-target navigation actions only;
all x64 editing, NOP/Jcc, live-debugger sections, and Alt+N are suppressed.

The regression fixture is assembled from explicit, independently chosen
synthetic fields in `resymbol-analysis/tests/elf_analysis.rs`. It contains no
third-party bytes or identifiers and exercises zero-sized load records plus a
large sparse gap.
