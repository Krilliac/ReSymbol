//! Deterministic, debugger-neutral symbol export projection.
//!
//! The analysis package remains the evidence-bearing source of truth. This
//! crate reduces one validated binary's claim graph into a small, stable model
//! that format writers can consume without independently reconciling claims.
//! Competing names remain visible, every selected value retains attribution,
//! function-to-class relationships remain available to richer consumers, and
//! claims that cannot be represented become structured warnings.

mod error;
mod ghidra_java;
mod ida_python;
mod map;
mod markdown;
mod model;
mod pdb;
mod project;

pub use error::{ExportError, ProjectionValidationError};
pub use ghidra_java::{GhidraJavaError, render_ghidra_java, validate_ghidra_java_class_name};
pub use ida_python::{IdaPythonError, render_ida_python};
pub use map::{MAX_MAP_MODULE_NAME_BYTES, MAX_MAP_SYMBOLS, MapError, render_map};
pub use markdown::{MarkdownError, render_markdown};
pub use model::{
    AttributedText, ExportAttribution, ExportBinary, ExportBinaryFormat, ExportControlFlowTarget,
    ExportDataReference, ExportDirectCall, ExportFunction, ExportGlobal, ExportName,
    ExportProducer, ExportProjection, ExportProvenance, ExportRecoveredString,
    ExportStringEncoding, ExportSubject, ExportThunk, ExportType, ProjectionWarning,
    ProjectionWarningCode,
};
pub use pdb::{MAX_PDB_PUBLIC_SYMBOLS, PdbError, render_pdb};
pub use project::NameSelection;

/// Maximum UTF-8 byte length accepted for a source symbol name.
pub const MAX_NAME_BYTES: usize = 1_024;
/// Maximum bytes in a debugger-facing identifier (IDA's 512-byte buffer minus NUL).
pub const MAX_OUTPUT_NAME_BYTES: usize = 511;
/// Maximum UTF-8 byte length accepted for a type identity key.
pub const MAX_TYPE_KEY_BYTES: usize = 1_024;
/// Maximum UTF-8 byte length accepted for a prototype or type declaration.
pub const MAX_DECLARATION_BYTES: usize = 16_384;
/// Maximum UTF-8 byte length retained for each provenance field.
pub const MAX_PROVENANCE_TEXT_BYTES: usize = 1_024;
/// Maximum distinct class relationships retained for one function.
pub const MAX_CLASS_MEMBERSHIPS_PER_FUNCTION: usize = 4_096;
/// Maximum direct-call relationships retained by one neutral projection.
pub const MAX_DIRECT_CALLS: usize = 262_144;
/// Maximum thunk relationships retained by one neutral projection.
pub const MAX_THUNKS: usize = 65_536;
