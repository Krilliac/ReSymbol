//! Language-neutral contracts shared by ReSymbol and its plugin SDKs.
//!
//! The wire-facing types in this crate deliberately use strings and versioned
//! enums instead of Rust-specific traits. Native, managed, WebAssembly, and
//! process-isolated SDKs can therefore expose the same manifest vocabulary.

mod health;
mod manifest;

pub use health::{
    DiagnosticSeverity, PluginDiagnostic, PluginDiagnosticCode, PluginHealth, PluginHealthState,
};
pub use manifest::{
    MANIFEST_VERSION, ManifestValidationError, NativeIsolation, PLUGIN_API_VERSION,
    PluginCapability, PluginId, PluginManifest, PluginPermission, PluginRuntime, PluginRuntimeKind,
};
