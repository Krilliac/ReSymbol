//! A tiny, deterministic child used by the ignored end-to-end RSP test.
//!
//! It performs a trivial computation and exits with status 0. The end-to-end
//! test launches it under the ptrace host, serves it over TCP with the RSP
//! server, drives it from an RSP client, and lets it run to completion.

fn main() {
    let mut total: u64 = 0;
    for value in 0..8u64 {
        total = total.wrapping_add(std::hint::black_box(value));
    }
    // 0+1+...+7 = 28; exit 0 iff the arithmetic is intact.
    std::process::exit(i32::from(total != 28));
}
