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

`EM_MIPS` is only a container fact. It is not evidence that a generic MIPS32
decoder models the executable correctly; PlayStation 2 software may target the
Emotion Engine/R5900 family. This slice therefore performs no instruction
decoding and emits no function, call, thunk, string, or data-reference claims.
The serialized architecture token is `elf32-em-mips-le`; it describes the
validated container identity only and must not dispatch a generic MIPS decoder.

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
