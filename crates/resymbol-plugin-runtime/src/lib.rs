//! Bounded execution for ReSymbol out-of-process plugins.
//!
//! External-process manifests launch their entrypoint directly. Native and
//! managed manifests launch versioned sibling helpers that contain library or
//! runtime faults outside the main ReSymbol process. Every path avoids a shell,
//! exchange bounded newline-delimited JSON over pipes, terminate processes
//! that exceed their deadline, and convert claim events into validated
//! [`resymbol_core::SymbolClaim`] values.
//!
//! Process isolation is not a full operating-system sandbox. Protocol grants
//! are advisory until a platform sandbox layer enforces filesystem, network,
//! memory, and child-process restrictions. Before calling
//! [`ExternalProcessHost::execute_trusted`],
//! [`NativeProcessHost::execute_trusted`], or
//! [`ManagedProcessHost::execute_trusted`], callers **MUST** verify the plugin
//! ID and exact artifact fingerprint against host-owned trust state
//! immediately before execution.
//! [`ManagedProcessHost::execute_trusted`] additionally performs its own
//! pre-launch and post-child artifact checks.

mod error;
mod host;
mod managed;
mod native;
mod types;
mod wire;

pub use error::{PluginRuntimeError, StreamKind};
pub use host::ExternalProcessHost;
pub use managed::{ManagedPeImage, ManagedPeImageSection, ManagedProcessHost};
pub use native::{NativePeImage, NativePeImageSection, NativeProcessHost};
pub use types::{
    ExternalProcessRequest, PluginDescriptor, PluginExecution, PluginLog, PluginMethod,
    PluginResponse, ProcessDiagnostics, RuntimeLimits,
};
