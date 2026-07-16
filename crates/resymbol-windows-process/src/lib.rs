//! Safe, narrow process-tree containment for Windows.
//!
//! This crate is intentionally not a general replacement for
//! [`std::process::Command`]. It owns the security-sensitive Win32 process
//! creation sequence needed by ReSymbol: a kill-on-close Job Object and an
//! exact standard-I/O handle allow-list are attached through `STARTUPINFOEX`
//! before the child's first instruction can execute.
//!
//! This is lifecycle containment, not authority sandboxing. Normal cleanup
//! explicitly terminates the Job; kill-on-close is an abrupt-parent fallback
//! only while no out-of-scope process retains a duplicate handle. An active
//! same-account process with sufficient process/handle rights remains outside
//! this crate's threat model.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{ContainedChild, ContainedCommand, Stdio};
