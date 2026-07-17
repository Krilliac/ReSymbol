#![forbid(unsafe_code)]

use std::{
    collections::TryReserveError,
    fmt, fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use resymbol_analysis::{
    AnalysisError, BinaryAnalysis, ExactX64InstructionError, PeSection, inspect_pe_layout,
    validate_exact_x64_instruction,
};
use resymbol_core::{BinaryFormat, BinaryId, BinaryIdentity, ClaimValidationError};
use thiserror::Error;

use crate::{AppServices, ProjectSnapshot};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const X86_NOP: u8 = 0x90;

/// Maximum number of edits retained by one immutable static patch plan.
pub const MAX_STATIC_PATCH_EDITS: usize = 1_024;
/// Maximum expected/replacement span for one static patch edit: 4 KiB.
pub const MAX_STATIC_PATCH_BYTES_PER_EDIT: usize = 4 * 1_024;
/// Maximum aggregate replacement span for one static patch plan: 1 MiB.
pub const MAX_STATIC_PATCH_BYTES: usize = 1_024 * 1_024;
/// Maximum UTF-8 byte length of a stable user-facing edit label.
pub const MAX_STATIC_PATCH_LABEL_BYTES: usize = 256;
/// Architectural maximum length of one x86/x86-64 instruction.
pub const MAX_STATIC_PATCH_NOP_INSTRUCTION_BYTES: usize =
    resymbol_analysis::MAX_X64_INSTRUCTION_BYTES;

/// Stable semantic classification for a same-size static binary edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum StaticPatchKind {
    /// Replace one complete, caller-identified instruction with x86 `NOP` bytes.
    NopInstruction,
    /// Replace an exact same-size byte span with caller-supplied bytes.
    ReplaceBytes,
}

impl StaticPatchKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NopInstruction => "nop-instruction",
            Self::ReplaceBytes => "replace-bytes",
        }
    }
}

/// One unresolved same-size edit request supplied by a frontend.
///
/// The request owns its expected and replacement bytes. Its fields are private
/// so a successfully constructed request cannot be mutated around validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPatchEditRequest {
    rva: u32,
    expected: Vec<u8>,
    replacement: Vec<u8>,
    label: String,
    kind: StaticPatchKind,
}

impl StaticPatchEditRequest {
    /// Construct an exact instruction-to-NOP request.
    ///
    /// Threading: any thread; construction owns all input values and has no I/O.
    pub fn nop_instruction(
        rva: u32,
        expected: impl Into<Vec<u8>>,
        label: impl Into<String>,
    ) -> Result<Self, StaticPatchError> {
        let expected = expected.into();
        validate_edit_size(expected.len())?;
        let replacement = vec![X86_NOP; expected.len()];
        Self::validated(
            rva,
            expected,
            replacement,
            label.into(),
            StaticPatchKind::NopInstruction,
        )
    }

    /// Construct an exact general same-size replacement request.
    ///
    /// Threading: any thread; construction owns all input values and has no I/O.
    pub fn replace_bytes(
        rva: u32,
        expected: impl Into<Vec<u8>>,
        replacement: impl Into<Vec<u8>>,
        label: impl Into<String>,
    ) -> Result<Self, StaticPatchError> {
        Self::validated(
            rva,
            expected.into(),
            replacement.into(),
            label.into(),
            StaticPatchKind::ReplaceBytes,
        )
    }

    fn validated(
        rva: u32,
        expected: Vec<u8>,
        replacement: Vec<u8>,
        label: String,
        kind: StaticPatchKind,
    ) -> Result<Self, StaticPatchError> {
        validate_request_shape(rva, &expected, &replacement, &label, kind)?;
        Ok(Self {
            rva,
            expected,
            replacement,
            label,
            kind,
        })
    }

    #[must_use]
    pub const fn rva(&self) -> u32 {
        self.rva
    }

    #[must_use]
    pub fn expected(&self) -> &[u8] {
        &self.expected
    }

    #[must_use]
    pub fn replacement(&self) -> &[u8] {
        &self.replacement
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub const fn kind(&self) -> StaticPatchKind {
        self.kind
    }
}

/// One validated file-backed executable edit with a derived source file offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPatchEdit {
    rva: u32,
    file_offset: u64,
    expected: Vec<u8>,
    replacement: Vec<u8>,
    label: String,
    kind: StaticPatchKind,
}

impl StaticPatchEdit {
    #[must_use]
    pub const fn rva(&self) -> u32 {
        self.rva
    }

    /// Provisional offset derived from the supplied analysis model.
    ///
    /// This value is informational until application reparses the exact source
    /// bytes and requires the fresh executable, file-backed mapping to match.
    #[must_use]
    pub const fn file_offset(&self) -> u64 {
        self.file_offset
    }

    #[must_use]
    pub fn expected(&self) -> &[u8] {
        &self.expected
    }

    #[must_use]
    pub fn replacement(&self) -> &[u8] {
        &self.replacement
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub const fn kind(&self) -> StaticPatchKind {
        self.kind
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.expected.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expected.is_empty()
    }
}

/// Canonical immutable plan for patching one exact analyzed source image.
///
/// Edits are sorted by RVA regardless of caller order. Every edit is resolved
/// provisionally to one fully file-backed executable PE range and overlaps are
/// rejected in both RVA and file-offset space before the plan is published.
/// Applying the plan reparses the exact source bytes and requires every fresh
/// mapping to match; serialized analysis metadata never authorizes a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPatchPlan {
    source_identity: BinaryIdentity,
    edits: Vec<StaticPatchEdit>,
    total_patch_bytes: usize,
}

impl StaticPatchPlan {
    /// Validate and freeze an edit plan against one exact analysis identity.
    ///
    /// Threading: any thread; the resulting value is immutable and owns its
    /// identity and edit metadata. No file is opened and no byte image is changed.
    pub fn new(
        source_identity: &BinaryIdentity,
        analysis: &BinaryAnalysis,
        requests: Vec<StaticPatchEditRequest>,
    ) -> Result<Self, StaticPatchError> {
        source_identity
            .validate()
            .map_err(StaticPatchError::InvalidSourceIdentity)?;
        analysis
            .validate()
            .map_err(StaticPatchError::InvalidAnalysis)?;
        if analysis.identity() != source_identity {
            return Err(StaticPatchError::AnalysisIdentityMismatch {
                expected: source_identity.id.clone(),
                actual: analysis.identity().id.clone(),
            });
        }
        if !matches!(&source_identity.format, BinaryFormat::Pe) {
            return Err(StaticPatchError::UnsupportedBinaryFormat);
        }
        if requests.is_empty() {
            return Err(StaticPatchError::EmptyPlan);
        }
        if requests.len() > MAX_STATIC_PATCH_EDITS {
            return Err(StaticPatchError::TooManyEdits {
                actual: requests.len(),
                maximum: MAX_STATIC_PATCH_EDITS,
            });
        }

        let pe = match analysis {
            BinaryAnalysis::Pe(pe) => pe,
            _ => return Err(StaticPatchError::UnsupportedBinaryFormat),
        };
        let mut edits = Vec::new();
        edits
            .try_reserve_exact(requests.len())
            .map_err(StaticPatchError::PlanAllocation)?;
        let mut total_patch_bytes = 0usize;
        for request in requests {
            validate_request_shape(
                request.rva,
                &request.expected,
                &request.replacement,
                &request.label,
                request.kind,
            )?;
            total_patch_bytes = total_patch_bytes
                .checked_add(request.expected.len())
                .ok_or(StaticPatchError::TotalPatchBytesExceeded {
                    actual: usize::MAX,
                    maximum: MAX_STATIC_PATCH_BYTES,
                })?;
            if total_patch_bytes > MAX_STATIC_PATCH_BYTES {
                return Err(StaticPatchError::TotalPatchBytesExceeded {
                    actual: total_patch_bytes,
                    maximum: MAX_STATIC_PATCH_BYTES,
                });
            }
            let file_offset = resolve_file_offset(
                pe.size_of_image,
                &pe.sections,
                request.rva,
                request.expected.len(),
                source_identity.size,
            )?;
            edits.push(StaticPatchEdit {
                rva: request.rva,
                file_offset,
                expected: request.expected,
                replacement: request.replacement,
                label: request.label,
                kind: request.kind,
            });
        }

        edits.sort_by_key(|edit| edit.rva);
        validate_no_rva_overlap(&edits)?;
        validate_no_file_overlap(&edits)?;

        Ok(Self {
            source_identity: source_identity.clone(),
            edits,
            total_patch_bytes,
        })
    }

    #[must_use]
    pub const fn source_identity(&self) -> &BinaryIdentity {
        &self.source_identity
    }

    #[must_use]
    pub fn edits(&self) -> &[StaticPatchEdit] {
        &self.edits
    }

    #[must_use]
    pub const fn total_patch_bytes(&self) -> usize {
        self.total_patch_bytes
    }

    /// Compare and apply this plan to an immutable exact source snapshot.
    ///
    /// Threading: any thread. All source identity and expected-byte checks finish
    /// before the output allocation is modified. The caller's source slice is
    /// never mutated, including on error.
    pub fn apply(&self, source_bytes: &[u8]) -> Result<PatchedBinaryImage, StaticPatchError> {
        let actual_size = u64::try_from(source_bytes.len()).unwrap_or(u64::MAX);
        if actual_size != self.source_identity.size {
            return Err(StaticPatchError::SourceSizeMismatch {
                expected: self.source_identity.size,
                actual: actual_size,
            });
        }
        let source_layout =
            inspect_pe_layout(source_bytes).map_err(StaticPatchError::InvalidSourceLayout)?;
        if source_layout.identity().id != self.source_identity.id {
            return Err(StaticPatchError::SourceIdentityMismatch {
                expected: self.source_identity.id.clone(),
                actual: source_layout.identity().id.clone(),
            });
        }
        if source_layout.identity() != &self.source_identity {
            return Err(StaticPatchError::SourceIdentityMetadataMismatch {
                expected: self.source_identity.clone(),
                actual: source_layout.identity().clone(),
            });
        }

        for edit in &self.edits {
            let fresh_file_offset = resolve_file_offset(
                source_layout.size_of_image(),
                source_layout.sections(),
                edit.rva,
                edit.len(),
                actual_size,
            )?;
            if fresh_file_offset != edit.file_offset {
                return Err(StaticPatchError::SourceLayoutMismatch {
                    rva: edit.rva,
                    planned_file_offset: edit.file_offset,
                    actual_file_offset: fresh_file_offset,
                });
            }
        }

        for edit in &self.edits {
            let range = edit_source_range(edit, source_bytes.len())?;
            let actual = &source_bytes[range];
            if actual != edit.expected {
                return Err(StaticPatchError::StaleExpectedBytes {
                    rva: edit.rva,
                    file_offset: edit.file_offset,
                    expected: edit.expected.clone(),
                    actual: actual.to_vec(),
                });
            }
        }

        let mut output = Vec::new();
        output
            .try_reserve_exact(source_bytes.len())
            .map_err(StaticPatchError::OutputAllocation)?;
        output.extend_from_slice(source_bytes);
        for edit in &self.edits {
            let range = edit_source_range(edit, output.len())?;
            output[range].copy_from_slice(&edit.replacement);
        }

        let output_identity = BinaryIdentity {
            id: BinaryId::digest(&output),
            size: self.source_identity.size,
            format: self.source_identity.format.clone(),
            architecture: self.source_identity.architecture.clone(),
            image_base: self.source_identity.image_base,
        };
        Ok(PatchedBinaryImage {
            bytes: Arc::new(output),
            source_identity: self.source_identity.clone(),
            output_identity,
            warnings: [
                StaticPatchWarning::AuthenticodeMayBeInvalid,
                StaticPatchWarning::PeChecksumMayBeInvalid,
            ],
        })
    }
}

/// Explicit integrity caveats attached to every produced static PE image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StaticPatchWarning {
    /// Same-size code changes may invalidate an existing Authenticode signature.
    AuthenticodeMayBeInvalid,
    /// Same-size code changes may invalidate the PE optional-header checksum.
    PeChecksumMayBeInvalid,
}

impl fmt::Display for StaticPatchWarning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticodeMayBeInvalid => formatter.write_str(
                "the patched bytes may invalidate an existing Authenticode signature; ReSymbol does not repair or re-sign it",
            ),
            Self::PeChecksumMayBeInvalid => formatter.write_str(
                "the patched bytes may invalidate the PE checksum; ReSymbol does not recompute or repair it",
            ),
        }
    }
}

/// Newly allocated patched bytes and their deterministic exact identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchedBinaryImage {
    bytes: Arc<Vec<u8>>,
    source_identity: BinaryIdentity,
    output_identity: BinaryIdentity,
    warnings: [StaticPatchWarning; 2],
}

impl PatchedBinaryImage {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Clone the shared owning buffer without copying the patched image.
    #[must_use]
    pub fn bytes_arc(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.bytes)
    }

    #[must_use]
    pub const fn source_identity(&self) -> &BinaryIdentity {
        &self.source_identity
    }

    #[must_use]
    pub const fn output_identity(&self) -> &BinaryIdentity {
        &self.output_identity
    }

    #[must_use]
    pub const fn warnings(&self) -> &[StaticPatchWarning] {
        &self.warnings
    }
}

/// Receipt returned after a staged patched image becomes visible at a new path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedStaticPatch {
    path: PathBuf,
    source_identity: BinaryIdentity,
    output_identity: BinaryIdentity,
    warnings: [StaticPatchWarning; 2],
}

impl PublishedStaticPatch {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn source_identity(&self) -> &BinaryIdentity {
        &self.source_identity
    }

    #[must_use]
    pub const fn output_identity(&self) -> &BinaryIdentity {
        &self.output_identity
    }

    #[must_use]
    pub const fn warnings(&self) -> &[StaticPatchWarning] {
        &self.warnings
    }
}

impl AppServices {
    /// Apply an immutable plan to a project's retained exact source snapshot.
    ///
    /// Threading: any thread. This allocates a distinct result and never mutates
    /// the project, its retained source, or any path on disk.
    pub fn apply_static_patch(
        &self,
        project: &ProjectSnapshot,
        plan: &StaticPatchPlan,
    ) -> Result<PatchedBinaryImage, StaticPatchError> {
        let project_identity = project.session().base_analysis().identity();
        if project_identity != plan.source_identity() {
            return Err(StaticPatchError::ProjectIdentityMismatch {
                expected: plan.source_identity().id.clone(),
                actual: project_identity.id.clone(),
            });
        }
        if project_identity.size > self.max_binary_bytes() {
            return Err(StaticPatchError::SourceTooLarge {
                actual: project_identity.size,
                maximum: self.max_binary_bytes(),
            });
        }
        let source = project
            .verified_source_bytes()
            .ok_or(StaticPatchError::ExactSourceRequired)?;
        plan.apply(source)
    }

    /// Stage, flush, file-synchronize, and publish a patched binary at a new path.
    ///
    /// Threading: any thread. Competing publications to the same destination are
    /// race-safe because no-clobber publication permits at most one success.
    /// Publication uses same-directory staging; an existing target is never
    /// replaced. A failed staging operation drops and removes its staging file.
    /// On Unix, the parent directory is synchronized after publication and an
    /// error can therefore be reported after the target becomes visible. The
    /// Windows path has no portable parent-directory synchronization here, so
    /// success does not claim that the new directory entry survives power loss.
    pub fn publish_static_patch_new(
        &self,
        project: &ProjectSnapshot,
        plan: &StaticPatchPlan,
        output: impl AsRef<Path>,
    ) -> Result<PublishedStaticPatch, StaticPatchError> {
        let output = output.as_ref();
        if project
            .verified_source_path()
            .is_some_and(|source| paths_refer_to_same_location(source, output))
        {
            return Err(StaticPatchError::OutputMatchesSource {
                path: output.to_path_buf(),
            });
        }
        let image = self.apply_static_patch(project, plan)?;
        publish_image_new(&image, output)
    }
}

fn paths_refer_to_same_location(source: &Path, output: &Path) -> bool {
    if source == output {
        return true;
    }
    let normalize = |path: &Path| -> Option<PathBuf> {
        if let Ok(canonical) = fs::canonicalize(path) {
            return Some(canonical);
        }
        let file_name = path.file_name()?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::canonicalize(parent)
            .ok()
            .map(|canonical| canonical.join(file_name))
    };
    let (Some(source), Some(output)) = (normalize(source), normalize(output)) else {
        return false;
    };
    #[cfg(windows)]
    {
        let source = source.to_string_lossy();
        let output = output.to_string_lossy();
        source.eq_ignore_ascii_case(output.as_ref())
    }
    #[cfg(not(windows))]
    {
        source == output
    }
}

fn validate_request_shape(
    rva: u32,
    expected: &[u8],
    replacement: &[u8],
    label: &str,
    kind: StaticPatchKind,
) -> Result<(), StaticPatchError> {
    validate_edit_size(expected.len())?;
    if expected.len() != replacement.len() {
        return Err(StaticPatchError::ReplacementSizeMismatch {
            rva,
            expected: expected.len(),
            replacement: replacement.len(),
        });
    }
    if expected == replacement {
        return Err(StaticPatchError::NoOpReplacement { rva });
    }
    if matches!(kind, StaticPatchKind::NopInstruction)
        && expected.len() > MAX_STATIC_PATCH_NOP_INSTRUCTION_BYTES
    {
        return Err(StaticPatchError::NopInstructionTooLarge {
            rva,
            actual: expected.len(),
            maximum: MAX_STATIC_PATCH_NOP_INSTRUCTION_BYTES,
        });
    }
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err(StaticPatchError::EmptyLabel { rva });
    }
    if label.len() > MAX_STATIC_PATCH_LABEL_BYTES {
        return Err(StaticPatchError::LabelTooLong {
            rva,
            actual: label.len(),
            maximum: MAX_STATIC_PATCH_LABEL_BYTES,
        });
    }
    if trimmed != label || label.chars().any(char::is_control) {
        return Err(StaticPatchError::InvalidLabel { rva });
    }
    if matches!(kind, StaticPatchKind::NopInstruction)
        && replacement.iter().any(|byte| *byte != X86_NOP)
    {
        return Err(StaticPatchError::InvalidNopReplacement { rva });
    }
    if matches!(kind, StaticPatchKind::NopInstruction) {
        validate_exact_x64_instruction(u64::from(rva), expected)
            .map_err(|source| StaticPatchError::InvalidNopInstruction { rva, source })?;
    }
    Ok(())
}

fn validate_edit_size(size: usize) -> Result<(), StaticPatchError> {
    if size == 0 {
        return Err(StaticPatchError::EmptyEdit);
    }
    if size > MAX_STATIC_PATCH_BYTES_PER_EDIT {
        return Err(StaticPatchError::EditTooLarge {
            actual: size,
            maximum: MAX_STATIC_PATCH_BYTES_PER_EDIT,
        });
    }
    Ok(())
}

fn resolve_file_offset(
    image_size: u32,
    sections: &[PeSection],
    rva: u32,
    size: usize,
    source_size: u64,
) -> Result<u64, StaticPatchError> {
    let size = u64::try_from(size).map_err(|_| StaticPatchError::AddressOverflow { rva })?;
    let end = u64::from(rva)
        .checked_add(size)
        .ok_or(StaticPatchError::AddressOverflow { rva })?;
    if end > u64::from(image_size) {
        return Err(StaticPatchError::RangeOutsideImage {
            rva,
            size: usize::try_from(size).unwrap_or(usize::MAX),
            image_size,
        });
    }

    let section =
        section_containing_start(sections, rva).ok_or(StaticPatchError::RangeOutsideSections {
            rva,
            size: usize::try_from(size).unwrap_or(usize::MAX),
        })?;
    let section_start = u64::from(section.virtual_address);
    let section_end = section_start
        .checked_add(u64::from(section.loaded_size()))
        .ok_or(StaticPatchError::AddressOverflow { rva })?;
    if end > section_end {
        return Err(StaticPatchError::RangeCrossesSection {
            rva,
            size: usize::try_from(size).unwrap_or(usize::MAX),
            section: section.name.clone(),
        });
    }
    if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
        return Err(StaticPatchError::RangeNotExecutable {
            rva,
            size: usize::try_from(size).unwrap_or(usize::MAX),
            section: section.name.clone(),
        });
    }

    let delta = u64::from(rva) - section_start;
    if delta
        .checked_add(size)
        .is_none_or(|range_end| range_end > u64::from(section.file_backed_size()))
    {
        return Err(StaticPatchError::RangeNotFileBacked {
            rva,
            size: usize::try_from(size).unwrap_or(usize::MAX),
            section: section.name.clone(),
        });
    }
    let file_offset = u64::from(section.raw_data_offset)
        .checked_add(delta)
        .ok_or(StaticPatchError::AddressOverflow { rva })?;
    if file_offset
        .checked_add(size)
        .is_none_or(|range_end| range_end > source_size)
    {
        return Err(StaticPatchError::RangeNotFileBacked {
            rva,
            size: usize::try_from(size).unwrap_or(usize::MAX),
            section: section.name.clone(),
        });
    }
    Ok(file_offset)
}

fn section_containing_start(sections: &[PeSection], rva: u32) -> Option<&PeSection> {
    let rva = u64::from(rva);
    sections.iter().find(|section| {
        let start = u64::from(section.virtual_address);
        start
            .checked_add(u64::from(section.loaded_size()))
            .is_some_and(|end| rva >= start && rva < end)
    })
}

fn validate_no_rva_overlap(edits: &[StaticPatchEdit]) -> Result<(), StaticPatchError> {
    for pair in edits.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if previous.rva == current.rva {
            return Err(StaticPatchError::DuplicateEdit { rva: current.rva });
        }
        let previous_end = u64::from(previous.rva)
            .checked_add(u64::try_from(previous.len()).unwrap_or(u64::MAX))
            .ok_or(StaticPatchError::AddressOverflow { rva: previous.rva })?;
        if u64::from(current.rva) < previous_end {
            return Err(StaticPatchError::OverlappingEdits {
                first_rva: previous.rva,
                second_rva: current.rva,
            });
        }
    }
    Ok(())
}

fn validate_no_file_overlap(edits: &[StaticPatchEdit]) -> Result<(), StaticPatchError> {
    let mut order: Vec<usize> = (0..edits.len()).collect();
    order.sort_by_key(|index| edits[*index].file_offset);
    for pair in order.windows(2) {
        let previous = &edits[pair[0]];
        let current = &edits[pair[1]];
        let previous_end = previous
            .file_offset
            .checked_add(u64::try_from(previous.len()).unwrap_or(u64::MAX))
            .ok_or(StaticPatchError::AddressOverflow { rva: previous.rva })?;
        if current.file_offset < previous_end {
            return Err(StaticPatchError::OverlappingFileRanges {
                first_rva: previous.rva,
                second_rva: current.rva,
            });
        }
    }
    Ok(())
}

fn edit_source_range(
    edit: &StaticPatchEdit,
    source_len: usize,
) -> Result<std::ops::Range<usize>, StaticPatchError> {
    let start = usize::try_from(edit.file_offset)
        .map_err(|_| StaticPatchError::AddressOverflow { rva: edit.rva })?;
    let end = start
        .checked_add(edit.len())
        .ok_or(StaticPatchError::AddressOverflow { rva: edit.rva })?;
    if end > source_len {
        return Err(StaticPatchError::ResolvedRangeOutsideSource {
            rva: edit.rva,
            file_offset: edit.file_offset,
            size: edit.len(),
            source_size: source_len,
        });
    }
    Ok(start..end)
}

fn publish_image_new(
    image: &PatchedBinaryImage,
    output: &Path,
) -> Result<PublishedStaticPatch, StaticPatchError> {
    if output.file_name().is_none() {
        return Err(StaticPatchError::InvalidOutputPath {
            path: output.to_path_buf(),
        });
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".resymbol-patch-")
        .tempfile_in(parent)
        .map_err(|source| StaticPatchError::io("create staging file for", output, source))?;
    temporary
        .as_file_mut()
        .write_all(image.bytes())
        .map_err(|source| StaticPatchError::io("write staged patched binary", output, source))?;
    temporary
        .as_file_mut()
        .flush()
        .map_err(|source| StaticPatchError::io("flush staged patched binary", output, source))?;
    temporary.as_file().sync_all().map_err(|source| {
        StaticPatchError::io("synchronize staged patched binary", output, source)
    })?;

    match temporary.persist_noclobber(output) {
        Ok(_) => sync_parent_directory(parent, output)?,
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(StaticPatchError::TargetAlreadyExists {
                path: output.to_path_buf(),
            });
        }
        Err(error) => {
            return Err(StaticPatchError::io(
                "publish new patched binary",
                output,
                error.error,
            ));
        }
    }

    Ok(PublishedStaticPatch {
        path: output.to_path_buf(),
        source_identity: image.source_identity.clone(),
        output_identity: image.output_identity.clone(),
        warnings: image.warnings,
    })
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path, output: &Path) -> Result<(), StaticPatchError> {
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| StaticPatchError::io("synchronize parent directory for", output, source))
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path, _output: &Path) -> Result<(), StaticPatchError> {
    // `std::fs::File::open` cannot portably open a Windows directory for
    // `sync_all`. The staged file itself was synchronized, but this no-op must
    // not be described as a power-loss durability guarantee for the rename.
    Ok(())
}

/// Validation, identity, compare-before-write, allocation, and publication failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StaticPatchError {
    #[error("the static patch plan must contain at least one edit")]
    EmptyPlan,
    #[error("a static patch edit must contain at least one byte")]
    EmptyEdit,
    #[error("static patch edit has {actual} bytes; the per-edit maximum is {maximum}")]
    EditTooLarge { actual: usize, maximum: usize },
    #[error("static patch plan has {actual} edits; the maximum is {maximum}")]
    TooManyEdits { actual: usize, maximum: usize },
    #[error("static patch plan changes {actual} bytes; the aggregate maximum is {maximum}")]
    TotalPatchBytesExceeded { actual: usize, maximum: usize },
    #[error(
        "static patch edit at RVA {rva:#x} expects {expected} bytes but provides {replacement} replacement bytes"
    )]
    ReplacementSizeMismatch {
        rva: u32,
        expected: usize,
        replacement: usize,
    },
    #[error("static patch edit at RVA {rva:#x} would not change any bytes")]
    NoOpReplacement { rva: u32 },
    #[error(
        "NOP edit at RVA {rva:#x} spans {actual} bytes; one x86 instruction is at most {maximum} bytes"
    )]
    NopInstructionTooLarge {
        rva: u32,
        actual: usize,
        maximum: usize,
    },
    #[error("static patch edit at RVA {rva:#x} must have a non-empty stable label")]
    EmptyLabel { rva: u32 },
    #[error(
        "static patch edit label at RVA {rva:#x} has leading/trailing whitespace or control characters"
    )]
    InvalidLabel { rva: u32 },
    #[error(
        "static patch edit label at RVA {rva:#x} is {actual} UTF-8 bytes; the maximum is {maximum}"
    )]
    LabelTooLong {
        rva: u32,
        actual: usize,
        maximum: usize,
    },
    #[error("NOP edit at RVA {rva:#x} contains a non-NOP replacement byte")]
    InvalidNopReplacement { rva: u32 },
    #[error("NOP edit at RVA {rva:#x} is not exactly one complete x86-64 instruction: {source}")]
    InvalidNopInstruction {
        rva: u32,
        #[source]
        source: ExactX64InstructionError,
    },
    #[error("the source binary identity is invalid: {0}")]
    InvalidSourceIdentity(ClaimValidationError),
    #[error("the analysis model is invalid: {0}")]
    InvalidAnalysis(AnalysisError),
    #[error("static patching currently supports analyzed PE images only")]
    UnsupportedBinaryFormat,
    #[error("analysis identity {actual} does not match requested source identity {expected}")]
    AnalysisIdentityMismatch {
        expected: BinaryId,
        actual: BinaryId,
    },
    #[error("project identity {actual} does not match patch-plan source identity {expected}")]
    ProjectIdentityMismatch {
        expected: BinaryId,
        actual: BinaryId,
    },
    #[error("RVA arithmetic overflow for static patch edit at {rva:#x}")]
    AddressOverflow { rva: u32 },
    #[error("static patch range RVA {rva:#x}+{size} is outside the PE image size {image_size:#x}")]
    RangeOutsideImage {
        rva: u32,
        size: usize,
        image_size: u32,
    },
    #[error("static patch range RVA {rva:#x}+{size} is not owned by a loaded PE section")]
    RangeOutsideSections { rva: u32, size: usize },
    #[error("static patch range RVA {rva:#x}+{size} crosses PE section `{section}`")]
    RangeCrossesSection {
        rva: u32,
        size: usize,
        section: String,
    },
    #[error("static patch range RVA {rva:#x}+{size} is in non-executable PE section `{section}`")]
    RangeNotExecutable {
        rva: u32,
        size: usize,
        section: String,
    },
    #[error(
        "static patch range RVA {rva:#x}+{size} is not fully file-backed in PE section `{section}`"
    )]
    RangeNotFileBacked {
        rva: u32,
        size: usize,
        section: String,
    },
    #[error("duplicate static patch edit starts at RVA {rva:#x}")]
    DuplicateEdit { rva: u32 },
    #[error("static patch edits at RVA {first_rva:#x} and {second_rva:#x} overlap")]
    OverlappingEdits { first_rva: u32, second_rva: u32 },
    #[error(
        "static patch edits at RVA {first_rva:#x} and {second_rva:#x} resolve to overlapping file ranges"
    )]
    OverlappingFileRanges { first_rva: u32, second_rva: u32 },
    #[error("source has {actual} bytes but the static patch plan is bound to {expected} bytes")]
    SourceSizeMismatch { expected: u64, actual: u64 },
    #[error("source has {actual} bytes; the application service limit is {maximum} bytes")]
    SourceTooLarge { actual: u64, maximum: u64 },
    #[error("source SHA-256 {actual} does not match static patch plan identity {expected}")]
    SourceIdentityMismatch {
        expected: BinaryId,
        actual: BinaryId,
    },
    #[error(
        "source byte-derived PE identity metadata does not match the static patch plan: expected {expected:?}, found {actual:?}"
    )]
    SourceIdentityMetadataMismatch {
        expected: BinaryIdentity,
        actual: BinaryIdentity,
    },
    #[error("the exact source PE layout is invalid: {0}")]
    InvalidSourceLayout(AnalysisError),
    #[error(
        "source byte-derived PE layout maps RVA {rva:#x} to file offset {actual_file_offset:#x}, not the plan's untrusted offset {planned_file_offset:#x}"
    )]
    SourceLayoutMismatch {
        rva: u32,
        planned_file_offset: u64,
        actual_file_offset: u64,
    },
    #[error(
        "resolved static patch range RVA {rva:#x} at file offset {file_offset:#x}+{size} exceeds source size {source_size}"
    )]
    ResolvedRangeOutsideSource {
        rva: u32,
        file_offset: u64,
        size: usize,
        source_size: usize,
    },
    #[error(
        "source bytes are stale at RVA {rva:#x} (file offset {file_offset:#x}); expected {expected:02x?}, found {actual:02x?}"
    )]
    StaleExpectedBytes {
        rva: u32,
        file_offset: u64,
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
    #[error("static patch publication requires the project's exact verified source binary")]
    ExactSourceRequired,
    #[error("patched binary output path `{path}` does not name a file")]
    InvalidOutputPath { path: PathBuf },
    #[error("patched binary output path `{path}` is the verified source path")]
    OutputMatchesSource { path: PathBuf },
    #[error("refusing to overwrite existing patched binary `{path}`")]
    TargetAlreadyExists { path: PathBuf },
    #[error("cannot {operation} `{path}`: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot reserve memory for a static patch plan: {0}")]
    PlanAllocation(TryReserveError),
    #[error("cannot reserve memory for a patched binary image: {0}")]
    OutputAllocation(TryReserveError),
}

impl StaticPatchError {
    fn io(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(
        virtual_address: u32,
        virtual_size: u32,
        raw_data_offset: u32,
        raw_data_size: u32,
        characteristics: u32,
    ) -> PeSection {
        PeSection {
            name: ".text".to_owned(),
            raw_name: *b".text\0\0\0",
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size,
            characteristics,
        }
    }

    #[test]
    fn virtual_tail_is_never_resolved_as_patchable_file_data() {
        let sections = [section(0x1000, 0x300, 0x400, 0x200, IMAGE_SCN_MEM_EXECUTE)];
        assert!(matches!(
            resolve_file_offset(0x2000, &sections, 0x1200, 1, 0x600),
            Err(StaticPatchError::RangeNotFileBacked { .. })
        ));
        assert_eq!(
            resolve_file_offset(0x2000, &sections, 0x11ff, 1, 0x600).expect("last backed byte"),
            0x5ff
        );
    }

    #[test]
    fn edit_shape_limits_fail_before_plan_resolution() {
        assert!(matches!(
            StaticPatchEditRequest::nop_instruction(0x1000, [], "empty"),
            Err(StaticPatchError::EmptyEdit)
        ));
        assert!(matches!(
            StaticPatchEditRequest::replace_bytes(0x1000, [0x74, 0x05], [0x90], "short"),
            Err(StaticPatchError::ReplacementSizeMismatch { .. })
        ));
        assert!(matches!(
            StaticPatchEditRequest::replace_bytes(0x1000, [0x74], [0x74], "no-op"),
            Err(StaticPatchError::NoOpReplacement { rva: 0x1000 })
        ));
        assert!(matches!(
            StaticPatchEditRequest::replace_bytes(0x1000, [0x74], [0x90], "bad\nlabel"),
            Err(StaticPatchError::InvalidLabel { rva: 0x1000 })
        ));
        assert!(matches!(
            StaticPatchEditRequest::nop_instruction(
                0x1000,
                vec![0xcc; MAX_STATIC_PATCH_BYTES_PER_EDIT + 1],
                "too large"
            ),
            Err(StaticPatchError::EditTooLarge { .. })
        ));
        assert!(matches!(
            StaticPatchEditRequest::nop_instruction(0x1000, [0xcc; 16], "two instructions"),
            Err(StaticPatchError::NopInstructionTooLarge {
                rva: 0x1000,
                actual: 16,
                maximum: MAX_STATIC_PATCH_NOP_INSTRUCTION_BYTES,
            })
        ));
        assert!(matches!(
            StaticPatchEditRequest::nop_instruction(0x1000, [0xcc, 0xcc], "two instructions"),
            Err(StaticPatchError::InvalidNopInstruction {
                source: ExactX64InstructionError::TrailingBytes { .. },
                ..
            })
        ));
        assert!(matches!(
            StaticPatchEditRequest::nop_instruction(0x1000, [0x0f], "truncated escape"),
            Err(StaticPatchError::InvalidNopInstruction {
                source: ExactX64InstructionError::InvalidOrTruncated { .. },
                ..
            })
        ));
        assert!(matches!(
            StaticPatchEditRequest::nop_instruction(0x1000, [0xe9, 0x00, 0x00], "truncated jump"),
            Err(StaticPatchError::InvalidNopInstruction {
                source: ExactX64InstructionError::InvalidOrTruncated { .. },
                ..
            })
        ));
        StaticPatchEditRequest::nop_instruction(0x1000, [0x74, 0x05], "complete branch")
            .expect("one complete conditional branch");
        StaticPatchEditRequest::replace_bytes(
            0x1000,
            [0xcc, 0xc3],
            [0x90, 0x90],
            "general multi-instruction escape hatch",
        )
        .expect("general same-size replacements may span instructions");
    }
}
