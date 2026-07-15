//! Bounded execution for ReSymbol out-of-process plugins.
//!
//! External-process manifests launch their entrypoint directly. Native
//! manifests launch a versioned sibling helper that contains dynamic-library
//! faults outside the main ReSymbol process. Both paths avoid a shell,
//! exchange bounded newline-delimited JSON over pipes, terminate processes
//! that exceed their deadline, and convert claim events into validated
//! [`resymbol_core::SymbolClaim`] values.
//!
//! Process isolation is not a full operating-system sandbox. Protocol grants
//! are advisory until a platform sandbox layer enforces filesystem, network,
//! memory, and child-process restrictions. Before calling
//! [`ExternalProcessHost::execute_trusted`] or
//! [`NativeProcessHost::execute_trusted`], callers **MUST** verify the plugin
//! ID and exact artifact fingerprint against host-owned trust state
//! immediately before execution.

mod error;
mod host;
mod native;
mod types;
mod wire;

pub use error::{PluginRuntimeError, StreamKind};
pub use host::ExternalProcessHost;
pub use native::{NativePeImage, NativePeImageSection, NativeProcessHost};
pub use types::{
    ExternalProcessRequest, PluginDescriptor, PluginExecution, PluginLog, PluginMethod,
    PluginResponse, ProcessDiagnostics, RuntimeLimits,
};
