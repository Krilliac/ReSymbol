//! Deterministic, debugger-neutral symbol export projection.
//!
//! The analysis package remains the evidence-bearing source of truth. This
//! crate reduces one validated binary's claim graph into a small, stable model
//! that format writers can consume without independently reconciling claims.
//! Competing names remain visible, every selected value retains attribution,
//! and claims that cannot be represented become structured warnings.

mod error;
mod ghidra_java;
mod ida_python;
mod model;
mod project;

pub use error::{ExportError, ProjectionValidationError};
pub use ghidra_java::{GhidraJavaError, render_ghidra_java, validate_ghidra_java_class_name};
pub use ida_python::{IdaPythonError, render_ida_python};
pub use model::{
    AttributedText, ExportAttribution, ExportBinary, ExportBinaryFormat, ExportFunction,
    ExportGlobal, ExportName, ExportProducer, ExportProjection, ExportProvenance, ExportSubject,
    ExportType, ProjectionWarning, ProjectionWarningCode,
};

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
