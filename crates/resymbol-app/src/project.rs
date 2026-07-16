#![forbid(unsafe_code)]

use std::{
    fs::{self, File},
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use resymbol_analysis::{AnalysisSession, analyze_bytes};
use resymbol_core::{BinaryId, BinaryIdentity};
use resymbol_export::ExportProjection;
use resymbol_package::{ResymPackage, read_file_bound, write_file_new_bound};

use crate::{AppError, ReviewLedger};

/// Default maximum exact binary size retained by one workbench project: 1 GiB.
pub const DEFAULT_MAX_BINARY_BYTES: u64 = 1024 * 1024 * 1024;

/// Stateless workflow configuration shared by command, desktop, and test frontends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppServices {
    generator_version: String,
    max_binary_bytes: u64,
}

impl AppServices {
    /// Build services that stamp new packages with `generator_version`.
    #[must_use]
    pub fn new(generator_version: impl Into<String>) -> Self {
        Self {
            generator_version: generator_version.into(),
            max_binary_bytes: DEFAULT_MAX_BINARY_BYTES,
        }
    }

    /// Apply a non-zero bound to binaries read and retained by this service.
    pub fn with_binary_size_limit(mut self, maximum: u64) -> Result<Self, AppError> {
        if maximum == 0 {
            return Err(AppError::InvalidBinarySizeLimit);
        }
        self.max_binary_bytes = maximum;
        Ok(self)
    }

    #[must_use]
    pub fn generator_version(&self) -> &str {
        &self.generator_version
    }

    #[must_use]
    pub const fn max_binary_bytes(&self) -> u64 {
        self.max_binary_bytes
    }

    /// Read and analyze one exact binary without loading or executing it.
    pub fn analyze_binary(&self, path: impl AsRef<Path>) -> Result<Arc<ProjectSnapshot>, AppError> {
        let exact_source = self.read_binary_exact(path, None)?;
        let analysis = analyze_bytes(exact_source.bytes())?;
        let session = AnalysisSession::new(analysis, Vec::new(), Vec::new())?;
        let package = ResymPackage::from_bound_payload(&self.generator_version, session)?;
        let projection = ExportProjection::from_session(package.payload())?;
        let canonical = exact_source.path().to_path_buf();

        Ok(Arc::new(ProjectSnapshot {
            origin_path: canonical.clone(),
            binary_path: Some(canonical),
            package_path: None,
            package: Arc::new(package),
            projection: Arc::new(projection),
            exact_source: Some(exact_source),
        }))
    }

    /// Open an exact current-schema `.resym` package.
    ///
    /// Older packages are deliberately rejected here rather than silently
    /// migrated; the GUI and CLI can share a separate explicit migration flow.
    pub fn open_package(&self, path: impl AsRef<Path>) -> Result<Arc<ProjectSnapshot>, AppError> {
        let requested = path.as_ref();
        let canonical = fs::canonicalize(requested)
            .map_err(|source| AppError::io("resolve package path", requested, source))?;
        let metadata = fs::metadata(&canonical)
            .map_err(|source| AppError::io("inspect package", &canonical, source))?;
        if !metadata.is_file() {
            return Err(AppError::NotRegularFile { path: canonical });
        }

        let package: ResymPackage<AnalysisSession> = read_file_bound(&canonical)?;
        package.payload().validate()?;
        let projection = ExportProjection::from_session(package.payload())?;

        Ok(Arc::new(ProjectSnapshot {
            origin_path: canonical.clone(),
            binary_path: None,
            package_path: Some(canonical),
            package: Arc::new(package),
            projection: Arc::new(projection),
            exact_source: None,
        }))
    }

    /// Persist the project's validated current-schema package using create-new semantics.
    pub fn save_package_new(
        &self,
        project: &ProjectSnapshot,
        path: impl AsRef<Path>,
    ) -> Result<(), AppError> {
        write_file_new_bound(path, project.package.as_ref())?;
        Ok(())
    }

    /// Bind the exact original binary to an opened package and return a new snapshot.
    ///
    /// The file is read once, bounded by the project identity and service limit,
    /// and retained as the same bytes whose SHA-256 passed the identity gate.
    pub fn verify_source_binary(
        &self,
        project: &ProjectSnapshot,
        path: impl AsRef<Path>,
    ) -> Result<Arc<ProjectSnapshot>, AppError> {
        let identity = project.session().base_analysis().identity();
        let exact_source = self.read_binary_exact(path, Some(identity))?;
        project.package.ensure_bound_to(&identity.id)?;

        let mut verified = ProjectSnapshot::clone(project);
        verified.binary_path = Some(exact_source.path().to_path_buf());
        verified.exact_source = Some(exact_source);
        Ok(Arc::new(verified))
    }

    /// Read one regular file into an exact, bounded immutable snapshot.
    ///
    /// The open handle's declared length is checked before allocation, the read
    /// probes one byte beyond that length, and the retained length must match
    /// exactly. When `expected_identity` is present, both its size and SHA-256
    /// must match the retained bytes before this method returns them.
    pub fn read_binary_exact(
        &self,
        requested: impl AsRef<Path>,
        expected_identity: Option<&BinaryIdentity>,
    ) -> Result<ExactBinary, AppError> {
        let requested = requested.as_ref();
        let canonical = fs::canonicalize(requested)
            .map_err(|source| AppError::io("resolve binary path", requested, source))?;
        let file = File::open(&canonical)
            .map_err(|source| AppError::io("open binary", &canonical, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| AppError::io("inspect binary", &canonical, source))?;
        if !metadata.is_file() {
            return Err(AppError::NotRegularFile { path: canonical });
        }
        let declared_size = metadata.len();
        if let Some(expected) = expected_identity {
            if declared_size != expected.size {
                return Err(AppError::SourceSizeMismatch {
                    path: canonical,
                    expected: expected.size,
                    actual: declared_size,
                });
            }
        }
        if declared_size > self.max_binary_bytes {
            return Err(AppError::BinaryTooLarge {
                path: canonical,
                actual: declared_size,
                maximum: self.max_binary_bytes,
            });
        }

        let reserve = usize::try_from(declared_size).map_err(|_| AppError::BinaryTooLarge {
            path: canonical.clone(),
            actual: declared_size,
            maximum: self.max_binary_bytes,
        })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(reserve)
            .map_err(|source| AppError::BinaryBufferAllocation {
                path: canonical.clone(),
                requested: reserve,
                source,
            })?;
        file.take(declared_size.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| AppError::io("read binary", &canonical, source))?;
        let actual_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual_size != declared_size {
            return Err(AppError::FileSizeChanged {
                path: canonical,
                expected: declared_size,
                actual: actual_size,
            });
        }
        let bytes = Arc::<[u8]>::from(bytes);
        if let Some(expected) = expected_identity {
            let actual = BinaryId::digest(bytes.as_ref());
            if actual != expected.id {
                return Err(AppError::SourceIdentityMismatch {
                    path: canonical,
                    expected: expected.id.to_string(),
                    actual: actual.to_string(),
                });
            }
        }
        Ok(ExactBinary {
            path: canonical,
            bytes,
        })
    }
}

impl Default for AppServices {
    fn default() -> Self {
        Self::new(env!("CARGO_PKG_VERSION"))
    }
}

/// Immutable, shareable state for one validated analysis project.
#[derive(Debug, Clone)]
pub struct ProjectSnapshot {
    origin_path: PathBuf,
    binary_path: Option<PathBuf>,
    package_path: Option<PathBuf>,
    package: Arc<ResymPackage<AnalysisSession>>,
    projection: Arc<ExportProjection>,
    exact_source: Option<ExactBinary>,
}

impl ProjectSnapshot {
    #[must_use]
    pub fn origin_path(&self) -> &Path {
        &self.origin_path
    }

    #[must_use]
    pub fn binary_path(&self) -> Option<&Path> {
        self.binary_path.as_deref()
    }

    #[must_use]
    pub fn package_path(&self) -> Option<&Path> {
        self.package_path.as_deref()
    }

    #[must_use]
    pub fn package(&self) -> &ResymPackage<AnalysisSession> {
        self.package.as_ref()
    }

    #[must_use]
    pub fn session(&self) -> &AnalysisSession {
        self.package.payload()
    }

    #[must_use]
    pub fn projection(&self) -> &ExportProjection {
        self.projection.as_ref()
    }

    /// Clone the shared immutable projection without rebuilding or copying it.
    #[must_use]
    pub fn projection_arc(&self) -> Arc<ExportProjection> {
        Arc::clone(&self.projection)
    }

    #[must_use]
    pub const fn has_verified_source(&self) -> bool {
        self.exact_source.is_some()
    }

    #[must_use]
    pub fn verified_source_path(&self) -> Option<&Path> {
        self.exact_source
            .as_ref()
            .map(|source| source.path.as_path())
    }

    /// Exact source bytes retained by the same identity gate used for analysis.
    ///
    /// Frontends may derive byte-dependent, read-only views from this slice. It
    /// is absent for package-only projects until the original binary has been
    /// verified by [`AppServices::verify_source_binary`].
    #[must_use]
    pub fn verified_source_bytes(&self) -> Option<&[u8]> {
        self.exact_source
            .as_ref()
            .map(|source| source.bytes.as_ref())
    }

    /// Clone ownership of the exact, identity-verified source snapshot.
    ///
    /// This shares the retained allocation through [`Arc`] without copying the
    /// binary. It is intended for bounded worker-side consumers that must keep
    /// the verified snapshot alive independently of the project handle.
    #[must_use]
    pub fn verified_source_bytes_arc(&self) -> Option<Arc<[u8]>> {
        self.exact_source
            .as_ref()
            .map(|source| Arc::clone(&source.bytes))
    }

    /// Apply the current review ledger to a fresh export projection.
    pub fn reviewed_projection(
        &self,
        reviews: &ReviewLedger,
    ) -> Result<Arc<ExportProjection>, AppError> {
        reviews
            .reviewed_projection(self.session())
            .map(Arc::new)
            .map_err(|error| AppError::ReviewProjection {
                reason: error.to_string(),
            })
    }

    pub(crate) fn exact_source_bytes(&self) -> Option<&[u8]> {
        self.verified_source_bytes()
    }

    pub(crate) fn suggested_stem(&self) -> String {
        self.origin_path
            .file_stem()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .map_or_else(
                || {
                    let digest = self.session().base_analysis().identity().id.as_str();
                    format!("resymbol_{}", &digest[..12])
                },
                ToOwned::to_owned,
            )
    }
}

/// Canonical path and immutable bytes from one completed bounded file read.
#[derive(Debug, Clone)]
pub struct ExactBinary {
    path: PathBuf,
    bytes: Arc<[u8]>,
}

impl ExactBinary {
    /// Canonical path resolved before the file handle was opened.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Exact immutable bytes retained by the bounded read and optional identity gate.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Clone shared ownership of the retained allocation without copying it.
    #[must_use]
    pub fn bytes_arc(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }

    /// Consume this snapshot into its canonical path and shared retained bytes.
    #[must_use]
    pub fn into_parts(self) -> (PathBuf, Arc<[u8]>) {
        (self.path, self.bytes)
    }
}
