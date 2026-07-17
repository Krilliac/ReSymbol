# Synthetic ELF32 MIPS fixture

The fixture used by `resymbol-analysis/tests/elf_analysis.rs` is assembled from
independently chosen header fields in Rust. Every byte is synthetic and
redistributable; the test does not embed, read, hash, or name any third-party
executable.

The image deliberately contains a zero-sized `PT_LOAD` record and a large gap
between two non-empty mappings. These cases verify that ReSymbol retains sparse
segment metadata instead of allocating the full virtual extent.
