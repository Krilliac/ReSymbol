//! Bounded execution for ReSymbol plugins.
//!
//! WebAssembly components run in a capability-limited Wasmtime store without
//! WASI. External-process manifests launch their entrypoint directly. Native and
//! managed manifests launch versioned sibling helpers that contain library or
//! runtime faults outside the main ReSymbol process. Process paths avoid a shell,
//! exchange bounded newline-delimited JSON over pipes, and own ordinary descendants
//! through POSIX process groups or Windows Job Objects. The owned tree is terminated
//! when the direct child completes, a deadline or stdout/stderr capture failure occurs,
//! or the runtime guard drops. Every host converts claim events into validated
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

mod claim;
mod error;
mod host;
mod managed;
mod native;
mod process_tree;
mod types;
mod wasm;
mod wire;

pub use error::{PluginRuntimeError, StreamKind};
pub use host::ExternalProcessHost;
pub use managed::{ManagedPeImage, ManagedPeImageSection, ManagedProcessHost};
pub use native::{NativePeImage, NativePeImageSection, NativeProcessHost};
pub use types::{
    ExternalProcessRequest, PluginDescriptor, PluginExecution, PluginLog, PluginMethod,
    PluginResponse, ProcessDiagnostics, RuntimeLimits,
};
pub use wasm::{WasmComponentHost, WasmPeImage, WasmPeImageSection, WasmRuntimeLimits};
