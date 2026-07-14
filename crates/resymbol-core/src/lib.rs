//! Trusted core types for ReSymbol.
//!
//! Plugins submit evidence-backed [`SymbolClaim`] values. They never mutate the
//! canonical graph directly. The host validates claims, plugin manifests, and
//! health before accepting either into trusted state.

mod plugin_discovery;
mod symbols;

pub use plugin_discovery::{
    DiscoveredPlugin, PluginDiscoveryOptions, PluginDiscoveryReport, PluginSource,
    PLUGIN_DISABLED_SENTINEL, PLUGIN_MANIFEST_FILE, PLUGIN_PACKAGE_EXTENSION,
    discover_plugins,
};
pub use resymbol_plugin_api as plugin_api;
pub use symbols::{
    BinaryFormat, BinaryId, BinaryIdentity, ClaimProducer, ClaimProvenance,
    ClaimValidationError, Confidence, Evidence, EvidenceKind, GraphValidationError,
    SymbolAssertion, SymbolClaim, SymbolGraph, SymbolSubject,
};
