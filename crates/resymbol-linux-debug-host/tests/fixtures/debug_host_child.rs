//! A tiny, deterministic child used by the ignored end-to-end ptrace test.
//!
//! It performs a trivial computation and exits with status 0. The traced test
//! launches it, single-steps a few instructions, reads registers and memory,
//! then lets it run to completion.

fn main() {
    let mut total: u64 = 0;
    for value in 0..8u64 {
        total = total.wrapping_add(std::hint::black_box(value));
    }
    // 0+1+...+7 = 28; exit 0 iff the arithmetic is intact.
    std::process::exit(i32::from(total != 28));
}
