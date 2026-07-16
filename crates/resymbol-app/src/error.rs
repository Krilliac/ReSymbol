#![forbid(unsafe_code)]

use std::{collections::TryReserveError, io, path::PathBuf};

use resymbol_analysis::{AnalysisError, SessionValidationError};
use resymbol_export::{
    ExportError, GhidraJavaError, IdaPythonError, MapError, MarkdownError, PdbError,
};
use resymbol_package::PackageError;
use thiserror::Error;

/// Failures produced by the UI-neutral application workflows.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AppError {
    #[error("the binary size limit must be greater than zero")]
    InvalidBinarySizeLimit,

    #[error("cannot {operation} `{path}`: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("`{path}` is not a regular file")]
    NotRegularFile { path: PathBuf },

    #[error("binary `{path}` is {actual} bytes; the configured limit is {maximum} bytes")]
    BinaryTooLarge {
        path: PathBuf,
        actual: u64,
        maximum: u64,
    },

    #[error("cannot reserve {requested} bytes for binary `{path}`: {source}")]
    BinaryBufferAllocation {
        path: PathBuf,
        requested: usize,
        #[source]
        source: TryReserveError,
    },

    #[error(
        "binary `{path}` changed while it was read: metadata reported {expected} bytes, but {actual} bytes were read"
    )]
    FileSizeChanged {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },

    #[error(
        "source binary `{path}` has {actual} bytes, but the project describes exactly {expected} bytes"
    )]
    SourceSizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },

    #[error("source binary `{path}` has SHA-256 {actual}, but the project is bound to {expected}")]
    SourceIdentityMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("PDB export requires the exact source PE; verify or analyze the original binary first")]
    ExactSourceRequired,

    #[error("refusing to overwrite existing export `{path}`")]
    TargetAlreadyExists { path: PathBuf },

    #[error(
        "Ghidra requires its source filename to match the public class; expected `{expected}`, found `{actual}`"
    )]
    GhidraFileNameMismatch { expected: String, actual: String },

    #[error("review decisions could not be applied: {reason}")]
    ReviewProjection { reason: String },

    #[error("binary analysis failed: {0}")]
    Analysis(#[from] AnalysisError),

    #[error("analysis session validation failed: {0}")]
    Session(#[from] SessionValidationError),

    #[error("package operation failed: {0}")]
    Package(#[from] PackageError),

    #[error("export projection failed: {0}")]
    Projection(#[from] ExportError),

    #[error("JSON export failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Markdown export failed: {0}")]
    Markdown(#[from] MarkdownError),

    #[error("MAP export failed: {0}")]
    Map(#[from] MapError),

    #[error("PDB export failed: {0}")]
    Pdb(#[from] PdbError),

    #[error("IDA Python export failed: {0}")]
    IdaPython(#[from] IdaPythonError),

    #[error("Ghidra Java export failed: {0}")]
    GhidraJava(#[from] GhidraJavaError),
}

impl AppError {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }
}
