#![forbid(unsafe_code)]

use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Read as _, Write as _},
    path::{Path, PathBuf},
};

use resymbol_analysis::BinaryAnalysis;
use resymbol_core::{BinaryFormat, BinaryId, BinaryIdentity, ClaimValidationError};
use serde::{Deserialize, Serialize};
use tempfile::Builder;
use thiserror::Error;

use crate::{
    AppServices, MAX_STATIC_PATCH_EDITS, ProjectSnapshot, StaticPatchEditRequest, StaticPatchError,
    StaticPatchKind, StaticPatchPlan,
};

/// Exact JSON schema accepted for portable static patch sets.
pub const STATIC_PATCH_SET_SCHEMA_VERSION: u32 = 1;
/// Required multi-part suffix for a ReSymbol static patch-set document.
pub const STATIC_PATCH_SET_SUFFIX: &str = ".respatch.json";
/// Maximum encoded bytes accepted or emitted for one patch-set document.
///
/// The 16 MiB envelope comfortably contains the compact JSON representation
/// of the 1 MiB aggregate patch-byte limit, including exact expected and
/// replacement arrays, while bounding untrusted input before deserialization.
pub const MAX_STATIC_PATCH_SET_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Validated, deterministic static edit requests bound to one complete binary identity.
///
/// The manifest deliberately contains no file offsets. Constructing it always
/// builds a [`StaticPatchPlan`] against the supplied analysis, which derives
/// provisional offsets from that analysis and later reparses exact source bytes
/// before any patched image can be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPatchSetManifest {
    source_identity: BinaryIdentity,
    requests: Vec<StaticPatchEditRequest>,
}

impl StaticPatchSetManifest {
    /// Validate, sort, and freeze an in-memory patch set without performing I/O.
    ///
    /// Threading: any thread. The returned requests are deterministically
    /// ordered by RVA and remain immutable.
    pub fn new(
        source_identity: &BinaryIdentity,
        analysis: &BinaryAnalysis,
        mut requests: Vec<StaticPatchEditRequest>,
    ) -> Result<Self, StaticPatchSetError> {
        requests.sort_by_key(StaticPatchEditRequest::rva);
        StaticPatchPlan::new(source_identity, analysis, requests.clone())
            .map_err(StaticPatchSetError::InvalidPatchSet)?;
        Ok(Self {
            source_identity: source_identity.clone(),
            requests,
        })
    }

    #[must_use]
    pub const fn source_identity(&self) -> &BinaryIdentity {
        &self.source_identity
    }

    #[must_use]
    pub fn requests(&self) -> &[StaticPatchEditRequest] {
        &self.requests
    }

    #[must_use]
    pub fn edit_count(&self) -> usize {
        self.requests.len()
    }
}

impl AppServices {
    /// Validate and create-new save a deterministic static patch-set document.
    ///
    /// Threading: any thread. The source binary and project are never mutated.
    /// Encoding, flush, and file synchronization complete in a same-directory
    /// staging file before no-clobber publication. The destination's parent
    /// directory is not claimed to be power-loss synchronized.
    pub fn save_static_patch_set_new(
        &self,
        project: &ProjectSnapshot,
        requests: Vec<StaticPatchEditRequest>,
        output: impl AsRef<Path>,
    ) -> Result<StaticPatchSetManifest, StaticPatchSetError> {
        let output = output.as_ref();
        validate_patch_set_path(output)?;
        let analysis = project.session().base_analysis();
        let manifest = StaticPatchSetManifest::new(analysis.identity(), analysis, requests)?;
        save_manifest_new(&manifest, output)?;
        Ok(manifest)
    }

    /// Bounded-load and completely validate a patch set for the current project.
    ///
    /// Threading: any thread. Unknown fields and non-v1 schemas fail closed.
    /// The complete serialized source identity must equal the current analysis
    /// identity. Every edit is reconstructed through the public request
    /// constructors and a fresh plan; no serialized offset is accepted.
    pub fn load_static_patch_set(
        &self,
        project: &ProjectSnapshot,
        input: impl AsRef<Path>,
    ) -> Result<StaticPatchSetManifest, StaticPatchSetError> {
        let input = input.as_ref();
        validate_patch_set_path(input)?;
        let document = load_document(input)?;
        if document.schema_version != STATIC_PATCH_SET_SCHEMA_VERSION {
            return Err(StaticPatchSetError::UnsupportedSchemaVersion {
                path: input.to_path_buf(),
                expected: STATIC_PATCH_SET_SCHEMA_VERSION,
                found: document.schema_version,
            });
        }

        let found_identity = document.source_identity.into_identity();
        found_identity
            .validate()
            .map_err(StaticPatchSetError::InvalidSourceIdentity)?;
        let analysis = project.session().base_analysis();
        let expected_identity = analysis.identity();
        if &found_identity != expected_identity {
            return Err(StaticPatchSetError::SourceIdentityMismatch {
                expected: expected_identity.clone(),
                found: found_identity,
            });
        }
        if document.edits.len() > MAX_STATIC_PATCH_EDITS {
            return Err(StaticPatchSetError::InvalidPatchSet(
                StaticPatchError::TooManyEdits {
                    actual: document.edits.len(),
                    maximum: MAX_STATIC_PATCH_EDITS,
                },
            ));
        }

        let mut requests = Vec::with_capacity(document.edits.len());
        for edit in document.edits {
            requests.push(edit.into_request()?);
        }
        StaticPatchSetManifest::new(expected_identity, analysis, requests)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PatchSetKindV1 {
    NopInstruction,
    ReplaceBytes,
}

impl From<StaticPatchKind> for PatchSetKindV1 {
    fn from(value: StaticPatchKind) -> Self {
        match value {
            StaticPatchKind::NopInstruction => Self::NopInstruction,
            StaticPatchKind::ReplaceBytes => Self::ReplaceBytes,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryIdentityV1 {
    id: BinaryId,
    size: u64,
    format: BinaryFormat,
    architecture: String,
    image_base: u64,
}

impl BinaryIdentityV1 {
    fn from_identity(identity: &BinaryIdentity) -> Self {
        Self {
            id: identity.id.clone(),
            size: identity.size,
            format: identity.format.clone(),
            architecture: identity.architecture.clone(),
            image_base: identity.image_base,
        }
    }

    fn into_identity(self) -> BinaryIdentity {
        BinaryIdentity {
            id: self.id,
            size: self.size,
            format: self.format,
            architecture: self.architecture,
            image_base: self.image_base,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchSetEditV1 {
    kind: PatchSetKindV1,
    rva: u32,
    expected: Vec<u8>,
    replacement: Vec<u8>,
    label: String,
}

impl PatchSetEditV1 {
    fn from_request(request: &StaticPatchEditRequest) -> Self {
        Self {
            kind: request.kind().into(),
            rva: request.rva(),
            expected: request.expected().to_vec(),
            replacement: request.replacement().to_vec(),
            label: request.label().to_owned(),
        }
    }

    fn into_request(self) -> Result<StaticPatchEditRequest, StaticPatchSetError> {
        match self.kind {
            PatchSetKindV1::NopInstruction => {
                let request =
                    StaticPatchEditRequest::nop_instruction(self.rva, self.expected, self.label)
                        .map_err(StaticPatchSetError::InvalidPatchSet)?;
                if request.replacement() != self.replacement {
                    return Err(StaticPatchSetError::InvalidSerializedNopReplacement {
                        rva: self.rva,
                    });
                }
                Ok(request)
            }
            PatchSetKindV1::ReplaceBytes => StaticPatchEditRequest::replace_bytes(
                self.rva,
                self.expected,
                self.replacement,
                self.label,
            )
            .map_err(StaticPatchSetError::InvalidPatchSet),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchSetDocumentV1 {
    schema_version: u32,
    source_identity: BinaryIdentityV1,
    edits: Vec<PatchSetEditV1>,
}

impl PatchSetDocumentV1 {
    fn from_manifest(manifest: &StaticPatchSetManifest) -> Self {
        Self {
            schema_version: STATIC_PATCH_SET_SCHEMA_VERSION,
            source_identity: BinaryIdentityV1::from_identity(manifest.source_identity()),
            edits: manifest
                .requests()
                .iter()
                .map(PatchSetEditV1::from_request)
                .collect(),
        }
    }
}

fn validate_patch_set_path(path: &Path) -> Result<(), StaticPatchSetError> {
    let valid = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(STATIC_PATCH_SET_SUFFIX));
    if !valid {
        return Err(StaticPatchSetError::InvalidPath {
            path: path.to_path_buf(),
            required_suffix: STATIC_PATCH_SET_SUFFIX,
        });
    }
    Ok(())
}

fn load_document(path: &Path) -> Result<PatchSetDocumentV1, StaticPatchSetError> {
    let file = File::open(path).map_err(|source| StaticPatchSetError::Io {
        operation: "open",
        path: path.to_path_buf(),
        source,
    })?;
    let read_limit = MAX_STATIC_PATCH_SET_FILE_BYTES
        .checked_add(1)
        .expect("patch-set file limit leaves one-byte sentinel headroom");
    let mut encoded = Vec::new();
    BufReader::new(file)
        .take(read_limit)
        .read_to_end(&mut encoded)
        .map_err(|source| StaticPatchSetError::Io {
            operation: "read",
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(encoded.len()).map_or(true, |length| length > MAX_STATIC_PATCH_SET_FILE_BYTES)
    {
        return Err(StaticPatchSetError::DocumentTooLarge {
            path: path.to_path_buf(),
            limit: MAX_STATIC_PATCH_SET_FILE_BYTES,
        });
    }
    serde_json::from_slice(&encoded).map_err(|source| StaticPatchSetError::Deserialize {
        path: path.to_path_buf(),
        source,
    })
}

fn save_manifest_new(
    manifest: &StaticPatchSetManifest,
    path: &Path,
) -> Result<(), StaticPatchSetError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = Builder::new()
        .prefix(".resymbol-patch-set-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|source| StaticPatchSetError::Io {
            operation: "create staging file for",
            path: path.to_path_buf(),
            source,
        })?;
    {
        let buffered = BufWriter::new(temporary.as_file_mut());
        let mut writer = LimitedWriter::new(buffered, MAX_STATIC_PATCH_SET_FILE_BYTES);
        let document = PatchSetDocumentV1::from_manifest(manifest);
        if let Err(source) = serde_json::to_writer(&mut writer, &document) {
            if writer.limit_exceeded() {
                return Err(StaticPatchSetError::DocumentTooLarge {
                    path: path.to_path_buf(),
                    limit: MAX_STATIC_PATCH_SET_FILE_BYTES,
                });
            }
            return Err(StaticPatchSetError::Serialize {
                path: path.to_path_buf(),
                source,
            });
        }
        if let Err(source) = writer.write_all(b"\n") {
            if writer.limit_exceeded() {
                return Err(StaticPatchSetError::DocumentTooLarge {
                    path: path.to_path_buf(),
                    limit: MAX_STATIC_PATCH_SET_FILE_BYTES,
                });
            }
            return Err(StaticPatchSetError::Io {
                operation: "write",
                path: path.to_path_buf(),
                source,
            });
        }
        writer.flush().map_err(|source| StaticPatchSetError::Io {
            operation: "flush",
            path: path.to_path_buf(),
            source,
        })?;
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| StaticPatchSetError::Io {
            operation: "synchronize",
            path: path.to_path_buf(),
            source,
        })?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            Err(StaticPatchSetError::TargetAlreadyExists {
                path: path.to_path_buf(),
            })
        }
        Err(error) => Err(StaticPatchSetError::Io {
            operation: "publish new",
            path: path.to_path_buf(),
            source: error.error,
        }),
    }
}

struct LimitedWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
    limit_exceeded: bool,
}

impl<W> LimitedWriter<W> {
    const fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            written: 0,
            limit,
            limit_exceeded: false,
        }
    }

    const fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }
}

impl<W: io::Write> io::Write for LimitedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len())
            .map_err(|_| io::Error::other("patch-set write length exceeds u64"))?;
        if self
            .written
            .checked_add(requested)
            .is_none_or(|total| total > self.limit)
        {
            self.limit_exceeded = true;
            return Err(io::Error::other("patch-set encoded size limit exceeded"));
        }
        let written = self.inner.write(buffer)?;
        self.written = self
            .written
            .checked_add(u64::try_from(written).unwrap_or(u64::MAX))
            .ok_or_else(|| io::Error::other("patch-set written byte count overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Strict patch-set validation, encoding, and create-new publication failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StaticPatchSetError {
    #[error("patch-set path `{path}` must end with `{required_suffix}`")]
    InvalidPath {
        path: PathBuf,
        required_suffix: &'static str,
    },
    #[error(
        "unsupported patch-set schema version {found} in `{path}`; expected exactly {expected}"
    )]
    UnsupportedSchemaVersion {
        path: PathBuf,
        expected: u32,
        found: u32,
    },
    #[error("patch-set source identity is invalid: {0}")]
    InvalidSourceIdentity(ClaimValidationError),
    #[error("patch set belongs to source {found:?}, not the current exact source {expected:?}")]
    SourceIdentityMismatch {
        expected: BinaryIdentity,
        found: BinaryIdentity,
    },
    #[error("serialized NOP edit at RVA {rva:#x} does not contain its exact derived NOP bytes")]
    InvalidSerializedNopReplacement { rva: u32 },
    #[error("invalid static patch set: {0}")]
    InvalidPatchSet(StaticPatchError),
    #[error("patch-set document `{path}` exceeds the {limit}-byte limit")]
    DocumentTooLarge { path: PathBuf, limit: u64 },
    #[error("cannot decode strict patch-set document `{path}`: {source}")]
    Deserialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("cannot encode patch-set document `{path}`: {source}")]
    Serialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("refusing to replace existing patch-set document `{path}`")]
    TargetAlreadyExists { path: PathBuf },
    #[error("cannot {operation} patch-set document `{path}`: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}
