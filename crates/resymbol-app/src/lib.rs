//! UI-neutral application workflows shared by ReSymbol frontends.

#![forbid(unsafe_code)]

mod error;
mod export;
mod plugins;
mod project;
mod review;

pub use error::AppError;
pub use export::{ExportFormat, PreparedExport};
pub use plugins::{PluginCatalog, PluginCatalogEntry};
pub use project::{AppServices, ProjectSnapshot};
pub use review::{
    DecisionAction, MAX_REVIEW_ANNOTATION_BYTES, MAX_REVIEW_DECISIONS, MAX_REVIEW_SIDECAR_BYTES,
    MAX_REVIEWER_BYTES, REVIEW_CLAIM_FINGERPRINT_VERSION, REVIEW_LEDGER_SCHEMA_VERSION,
    ReviewDecision, ReviewError, ReviewLedger, ReviewSubject, ReviewValidationError,
};
