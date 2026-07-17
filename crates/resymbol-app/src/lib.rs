//! UI-neutral application workflows shared by ReSymbol frontends, including
//! exact-source analysis, review/export, and bounded same-size static patching.

#![forbid(unsafe_code)]

mod error;
mod export;
mod patch;
mod patch_set;
mod plugins;
mod project;
mod review;

pub use error::AppError;
pub use export::{ExportFormat, PreparedExport};
pub use patch::{
    MAX_STATIC_PATCH_BYTES, MAX_STATIC_PATCH_BYTES_PER_EDIT, MAX_STATIC_PATCH_EDITS,
    MAX_STATIC_PATCH_LABEL_BYTES, MAX_STATIC_PATCH_NOP_INSTRUCTION_BYTES, PatchedBinaryImage,
    PublishedStaticPatch, StaticPatchDurability, StaticPatchEdit, StaticPatchEditRequest,
    StaticPatchError, StaticPatchKind, StaticPatchPlan, StaticPatchWarning,
};
pub use patch_set::{
    MAX_STATIC_PATCH_SET_FILE_BYTES, STATIC_PATCH_SET_SCHEMA_VERSION, STATIC_PATCH_SET_SUFFIX,
    StaticPatchSetError, StaticPatchSetManifest,
};
pub use plugins::{PluginArtifactPolicyStatus, PluginCatalog, PluginCatalogEntry};
pub use project::{AppServices, DEFAULT_MAX_BINARY_BYTES, ExactBinary, ProjectSnapshot};
pub use review::{
    DecisionAction, MAX_REVIEW_ANNOTATION_BYTES, MAX_REVIEW_DECISIONS, MAX_REVIEW_SIDECAR_BYTES,
    MAX_REVIEWER_BYTES, REVIEW_CLAIM_FINGERPRINT_VERSION, REVIEW_LEDGER_SCHEMA_VERSION,
    ReviewDecision, ReviewError, ReviewLedger, ReviewSubject, ReviewValidationError,
};
