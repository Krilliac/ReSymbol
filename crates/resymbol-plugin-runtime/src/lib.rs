//! Bounded execution for ReSymbol external-process plugins.
//!
//! This crate intentionally supports only manifests whose runtime kind is
//! `external-process`. It launches the manifest entrypoint directly (never via
//! a shell), exchanges bounded newline-delimited JSON over pipes, terminates
//! processes that exceed their deadline, and converts claim events into
//! validated [`resymbol_core::SymbolClaim`] values.
//!
//! Process isolation is not a full operating-system sandbox. Protocol grants
//! are advisory until a platform sandbox layer enforces filesystem, network,
//! memory, and child-process restrictions. Before calling
//! [`ExternalProcessHost::execute_trusted`], callers **MUST** verify the plugin ID and exact
//! artifact fingerprint against host-owned trust state immediately before execution.

mod error;
mod host;
mod types;
mod wire;

pub use error::{PluginRuntimeError, StreamKind};
pub use host::ExternalProcessHost;
pub use types::{
    ExternalProcessRequest, PluginDescriptor, PluginExecution, PluginLog, PluginMethod,
    PluginResponse, ProcessDiagnostics, RuntimeLimits,
};
