#![forbid(unsafe_code)]

use std::{io::Write as _, path::Path, sync::Arc};

use resymbol_export::{
    ExportProjection, MAX_MAP_MODULE_NAME_BYTES, render_ghidra_java, render_ida_python, render_map,
    render_markdown, render_pdb,
};

use crate::{AppError, AppServices, ProjectSnapshot, ReviewLedger};

/// Built-in export targets backed by the one reviewed neutral projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    Json,
    Markdown,
    Map,
    Pdb,
    IdaPython,
    GhidraJava,
}

impl ExportFormat {
    pub const ALL: [Self; 6] = [
        Self::Json,
        Self::Markdown,
        Self::Map,
        Self::Pdb,
        Self::IdaPython,
        Self::GhidraJava,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Markdown => "Markdown",
            Self::Map => "Microsoft MAP",
            Self::Pdb => "PDB",
            Self::IdaPython => "IDA Python",
            Self::GhidraJava => "Ghidra Java",
        }
    }
}

/// Fully rendered export bytes, safe to publish without invoking another writer.
#[derive(Debug, Clone)]
pub struct PreparedExport {
    format: ExportFormat,
    bytes: Arc<[u8]>,
    suggested_file_name: String,
    media_type: &'static str,
    projection: Arc<ExportProjection>,
}

impl PreparedExport {
    #[must_use]
    pub const fn format(&self) -> ExportFormat {
        self.format
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    #[must_use]
    pub fn suggested_file_name(&self) -> &str {
        &self.suggested_file_name
    }

    #[must_use]
    pub const fn media_type(&self) -> &'static str {
        self.media_type
    }

    #[must_use]
    pub fn projection(&self) -> &ExportProjection {
        self.projection.as_ref()
    }

    #[must_use]
    pub fn function_count(&self) -> usize {
        self.projection.functions.len()
    }

    #[must_use]
    pub fn global_count(&self) -> usize {
        self.projection.globals.len()
    }

    #[must_use]
    pub fn type_count(&self) -> usize {
        self.projection.types.len()
    }

    #[must_use]
    pub fn warning_occurrences(&self) -> u64 {
        self.projection
            .warnings
            .iter()
            .map(|warning| warning.occurrences)
            .sum()
    }
}

impl AppServices {
    /// Render one export from a review-filtered projection without creating files.
    pub fn prepare_export(
        &self,
        project: &ProjectSnapshot,
        reviews: &ReviewLedger,
        format: ExportFormat,
    ) -> Result<PreparedExport, AppError> {
        let projection = project.reviewed_projection(reviews)?;
        let digest = projection.binary.id.as_str();
        let stem = project.suggested_stem();
        let (bytes, suggested_file_name, media_type) = match format {
            ExportFormat::Json => {
                let mut rendered = serde_json::to_string_pretty(projection.as_ref())?;
                rendered.push('\n');
                (
                    rendered.into_bytes(),
                    format!("{stem}.symbols.json"),
                    "application/json",
                )
            }
            ExportFormat::Markdown => (
                render_markdown(projection.as_ref())?.into_bytes(),
                format!("{stem}.symbols.md"),
                "text/markdown; charset=utf-8",
            ),
            ExportFormat::Map => {
                let module_name = map_module_name(&stem, digest);
                (
                    render_map(project.session(), projection.as_ref(), &module_name)?.into_bytes(),
                    format!("{stem}.map"),
                    "text/plain; charset=utf-8",
                )
            }
            ExportFormat::Pdb => {
                let source = project
                    .exact_source_bytes()
                    .ok_or(AppError::ExactSourceRequired)?;
                (
                    render_pdb(project.session(), projection.as_ref(), source)?,
                    format!("{stem}.pdb"),
                    "application/octet-stream",
                )
            }
            ExportFormat::IdaPython => (
                render_ida_python(projection.as_ref())?.into_bytes(),
                format!("{stem}.ida.py"),
                "text/x-python; charset=utf-8",
            ),
            ExportFormat::GhidraJava => {
                let class_name = format!("ReSymbolImport_{}", &digest[..12]);
                (
                    render_ghidra_java(projection.as_ref(), &class_name)?.into_bytes(),
                    format!("{class_name}.java"),
                    "text/x-java-source; charset=utf-8",
                )
            }
        };

        Ok(PreparedExport {
            format,
            bytes: Arc::from(bytes),
            suggested_file_name,
            media_type,
            projection,
        })
    }

    /// Publish already-rendered bytes with the operating system's create-new primitive.
    ///
    /// Existing files, directories, and links are never replaced or truncated.
    pub fn publish_export_new(
        &self,
        prepared: &PreparedExport,
        path: impl AsRef<Path>,
    ) -> Result<(), AppError> {
        let path = path.as_ref();
        if prepared.format == ExportFormat::GhidraJava {
            let actual = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            if actual != prepared.suggested_file_name {
                return Err(AppError::GhidraFileNameMismatch {
                    expected: prepared.suggested_file_name.clone(),
                    actual,
                });
            }
        }

        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut staged = tempfile::Builder::new()
            .prefix(".resymbol-export-")
            .tempfile_in(parent)
            .map_err(|source| AppError::io("create staged export beside", path, source))?;
        staged
            .write_all(prepared.bytes())
            .map_err(|source| AppError::io("write staged export", path, source))?;
        staged
            .as_file()
            .sync_all()
            .map_err(|source| AppError::io("flush staged export", path, source))?;

        match staged.persist_noclobber(path) {
            Ok(_) => Ok(()),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(AppError::TargetAlreadyExists {
                    path: path.to_path_buf(),
                })
            }
            Err(error) => Err(AppError::io("publish completed export", path, error.error)),
        }
    }
}

fn map_module_name(stem: &str, binary_sha256: &str) -> String {
    let fallback = || format!("resymbol_{}", &binary_sha256[..12]);
    let mut sanitized = String::with_capacity(stem.len().min(MAX_MAP_MODULE_NAME_BYTES));
    for byte in stem.bytes() {
        if sanitized.len() == MAX_MAP_MODULE_NAME_BYTES {
            break;
        }
        sanitized.push(
            if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.') {
                char::from(byte)
            } else {
                '_'
            },
        );
    }
    if sanitized.is_empty() || matches!(sanitized.as_str(), "." | "..") {
        fallback()
    } else {
        sanitized
    }
}
