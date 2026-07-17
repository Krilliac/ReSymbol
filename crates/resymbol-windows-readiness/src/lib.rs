//! Narrow, read-only Windows sandbox-capability observations.
//!
//! This crate exists to keep platform FFI out of the backend-neutral debugger
//! crate. Its public API returns inert values, owns no lasting operating-system
//! handles, and never provisions resources, enables features, requests
//! elevation, or executes an external command.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{CapabilityObservation, SandboxCapabilitySnapshot, observe_sandbox_capabilities};
