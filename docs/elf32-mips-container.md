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

Callers may name the exact in-memory decoder profile
`ps2-ee-r5900-le-core-v1`, but the profile is deliberately unavailable in this
release. Selecting it returns a typed error before any generic MIPS or Capstone
path is consulted. The declaration does not identify an input automatically,
decode any R5900 instruction, create graph evidence, or change a package,
projection, plugin, CLI, or wire schema.

Debugger-neutral JSON and Markdown projection, IDAPython, and Ghidra Java can
represent the empty validated graph. The format-neutral static address-space
model and offline host retain exactly one region per non-empty `PT_LOAD`, so the
workbench can show mapped permissions and exact file-backed bytes as hex while
rejecting virtual gaps, zero-fill, cross-segment spans, and partial backing.
PE/x86-64-only MAP, PDB, static patch, linear-disassembly, PE plugin-host, and
protection-analysis actions remain explicitly unavailable.

The regression fixture is assembled from explicit, independently chosen
synthetic fields in `resymbol-analysis/tests/elf_analysis.rs`. It contains no
third-party bytes or identifiers and exercises zero-sized load records plus a
large sparse gap.
