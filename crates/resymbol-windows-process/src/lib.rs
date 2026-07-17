//! Safe, narrow Win32 process-containment and console-bootstrap boundaries.
//!
//! This crate is intentionally not a general replacement for
//! [`std::process::Command`]. It owns the security-sensitive Win32 process
//! creation sequence needed by ReSymbol: a kill-on-close Job Object and an
//! exact standard-I/O handle allow-list are attached through `STARTUPINFOEX`
//! before the child's first instruction can execute. Callers may also opt into
//! validated active-process and committed-memory Job limits; those limits are
//! configured on the empty Job before `CreateProcessW` and never silently
//! dropped when configuration fails.
//!
//! This is lifecycle containment, not authority sandboxing. Normal cleanup
//! explicitly requests Job termination; kill-on-close is an abrupt-parent fallback
//! only while no out-of-scope process retains a duplicate handle. An active
//! same-account process with sufficient process/handle rights remains outside
//! this crate's threat model.
//!
//! The separate console bootstrap API selects UTF-8 directly through Win32. It
//! never resolves or launches an environment-derived system executable.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod console;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use console::{Utf8ConsoleError, configure_utf8_console};

#[cfg(windows)]
pub use windows::{
    ContainedChild, ContainedCommand, JobResourceLimitError, JobResourceLimits,
    JobTerminationStatus, Stdio,
};
