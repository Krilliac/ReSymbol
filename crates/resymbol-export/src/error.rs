use resymbol_analysis::SessionValidationError;
use resymbol_core::{BinaryId, GraphValidationError};
use thiserror::Error;

/// Failure to construct a deterministic export projection.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExportError {
    #[error("analysis session is invalid: {0}")]
    InvalidSession(#[source] SessionValidationError),
    #[error("symbol graph is invalid: {0}")]
    InvalidGraph(#[source] GraphValidationError),
    #[error("this analysis format does not yet have an export projection")]
    UnsupportedAnalysisFormat,
    #[error("this binary container format does not yet have an export projection")]
    UnsupportedBinaryFormat,
    #[error("an export projection requires exactly one graph binary, found {count}")]
    UnexpectedBinaryCount { count: usize },
    #[error("graph binary {found} does not match requested binary {expected}")]
    BinaryIdentityMismatch { expected: BinaryId, found: BinaryId },
    #[error("virtual image size must be greater than zero")]
    ZeroImageSize,
    #[error("image base plus virtual image size overflows the address space")]
    ImageAddressOverflow,
    #[error("name-selection count {found} does not match graph claim count {expected}")]
    NameSelectionCountMismatch { expected: usize, found: usize },
    #[error("claim {index} is marked alias-only but is not a name claim")]
    AliasOnlyNonNameClaim { index: usize },
    #[error("binary field `{field}` is not bounded canonical text")]
    InvalidBinaryText { field: &'static str },
    #[error("export {resource} limit of {limit} was exceeded")]
    LimitExceeded {
        resource: &'static str,
        limit: usize,
    },
    #[error("constructed projection is invalid: {0}")]
    InvalidProjection(#[from] ProjectionValidationError),
}

/// Failure to revalidate an export model before a writer consumes it.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionValidationError {
    #[error("binary field `{field}` is invalid")]
    InvalidBinaryField { field: &'static str },
    #[error("{collection} are not in strictly increasing canonical order")]
    UnsortedCollection { collection: &'static str },
    #[error("{collection} exceeds its fixed projection limit")]
    CollectionLimit { collection: &'static str },
    #[error("{field} contains invalid or oversized text")]
    InvalidText { field: &'static str },
    #[error("symbol at RVA {rva:#x} with size {size:?} is outside the virtual image")]
    AddressOutsideImage { rva: u64, size: Option<u64> },
    #[error("a selected output name is not unique: `{name}`")]
    DuplicateOutputName { name: String },
    #[error("an alternate name duplicates the selected source name")]
    DuplicateSelectedAlternate,
    #[error("selected function ranges overlap")]
    OverlappingFunctionRanges,
    #[error("a text candidate is duplicated")]
    DuplicateTextCandidate,
    #[error("projection warnings are not in canonical order")]
    UnsortedWarnings,
    #[error("a warning occurrence count must be greater than zero")]
    ZeroWarningOccurrences,
    #[error("confidence must be finite and in the inclusive range 0.0..=1.0")]
    InvalidConfidence,
}
