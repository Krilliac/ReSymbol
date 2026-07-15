use std::collections::BTreeSet;

use resymbol_core::BinaryId;
use serde::Serialize;

use crate::{
    MAX_DECLARATION_BYTES, MAX_NAME_BYTES, MAX_OUTPUT_NAME_BYTES, MAX_PROVENANCE_TEXT_BYTES,
    MAX_TYPE_KEY_BYTES, ProjectionValidationError,
};

pub(crate) const MAX_CLAIMS: usize = 1_000_000;
pub(crate) const MAX_ENTITIES: usize = 500_000;
pub(crate) const MAX_NAMES_PER_ENTITY: usize = 256;
pub(crate) const MAX_DECLARATIONS_PER_ENTITY: usize = 256;
pub(crate) const MAX_WARNINGS: usize = 100_000;
pub(crate) const MAX_ARCHITECTURE_BYTES: usize = 128;
const MAX_WARNING_MESSAGE_BYTES: usize = 256;

/// Container format copied into an export without format-specific details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExportBinaryFormat {
    Pe,
    Elf,
    MachO,
    Wasm,
    Other(String),
}

/// Exact build identity and the virtual address space used by every symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportBinary {
    pub id: BinaryId,
    pub file_size: u64,
    pub format: ExportBinaryFormat,
    pub architecture: String,
    pub image_base: u64,
    pub image_size: u64,
}

/// Stable producer identity detached from the source claim representation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExportProducer {
    Core { component: String, version: String },
    Plugin { id: String, version: String },
    User { reviewer: Option<String> },
}

/// Bounded reproducibility details retained for an exported value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ExportProvenance {
    pub producer: ExportProducer,
    pub method: String,
    pub run_id: Option<String>,
}

/// Confidence and source attached to a selected or competing value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportAttribution {
    pub confidence: f64,
    pub provenance: ExportProvenance,
}

/// One bounded, attributed text candidate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AttributedText {
    pub text: String,
    pub attribution: ExportAttribution,
}

/// Selected source name and the unique name reserved for format writers.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportName {
    pub source: AttributedText,
    pub output_name: String,
}

/// A function projected at one relative virtual address.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportFunction {
    pub rva: u64,
    pub size: Option<u64>,
    pub size_attribution: Option<ExportAttribution>,
    pub selected_name: Option<ExportName>,
    pub alternate_names: Vec<AttributedText>,
    pub prototypes: Vec<AttributedText>,
}

/// A global projected at one relative virtual address.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportGlobal {
    pub rva: u64,
    pub size: Option<u64>,
    pub size_attribution: Option<ExportAttribution>,
    pub selected_name: Option<ExportName>,
    pub alternate_names: Vec<AttributedText>,
}

/// A type projected under its source graph key.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportType {
    pub key: String,
    pub selected_name: Option<ExportName>,
    pub alternate_names: Vec<AttributedText>,
    pub definitions: Vec<AttributedText>,
}

/// Canonical reference used by warnings and collision diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExportSubject {
    Function { rva: u64 },
    Global { rva: u64 },
    Type { key: String },
}

/// Machine-readable reason that source claims were reduced or omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProjectionWarningCode {
    UnsupportedAssertion,
    AssertionSubjectMismatch,
    AddressOutsideImage,
    InvalidText,
    TextLimitExceeded,
    InvalidProvenance,
    ConflictingSize,
    AmbiguousSize,
    OverlappingFunctionRange,
    AddressKindCollision,
    NameRewritten,
    AmbiguousName,
    NameCollision,
}

impl ProjectionWarningCode {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::UnsupportedAssertion => {
                "claim assertion is not representable in the neutral export model"
            }
            Self::AssertionSubjectMismatch => {
                "claim assertion does not apply to this neutral subject kind"
            }
            Self::AddressOutsideImage => {
                "address-bearing claim falls outside the binary virtual image"
            }
            Self::InvalidText => "claim text is empty, padded, or contains control characters",
            Self::TextLimitExceeded => "claim text exceeds the neutral export byte limit",
            Self::InvalidProvenance => {
                "claim provenance cannot be represented as bounded canonical text"
            }
            Self::ConflictingSize => {
                "competing symbol sizes were reduced to the highest-ranked value"
            }
            Self::AmbiguousSize => "equal-authority symbol sizes conflict, so the size was omitted",
            Self::OverlappingFunctionRange => {
                "function boundary overlaps a stronger boundary and was omitted"
            }
            Self::AddressKindCollision => {
                "function and global claims share an RVA; debugger bridges prefer the function"
            }
            Self::NameRewritten => "selected name was rewritten to a portable debugger identifier",
            Self::AmbiguousName => {
                "equally ranked names conflict; a deterministic primary was selected"
            }
            Self::NameCollision => {
                "selected name collided and received a deterministic output suffix"
            }
        }
    }
}

/// Aggregated warning. `occurrences` accounts for all equivalent reductions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ProjectionWarning {
    pub code: ProjectionWarningCode,
    pub subject: Option<ExportSubject>,
    pub occurrences: u64,
    pub message: String,
}

/// Stable, writer-friendly reduction of one exact binary's symbol graph.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportProjection {
    pub schema_version: u32,
    pub binary: ExportBinary,
    pub functions: Vec<ExportFunction>,
    pub globals: Vec<ExportGlobal>,
    pub types: Vec<ExportType>,
    pub warnings: Vec<ProjectionWarning>,
}

impl ExportProjection {
    pub(crate) const SCHEMA_VERSION: u32 = 1;

    /// Revalidate ordering, range, text, attribution, and uniqueness invariants.
    pub fn validate(&self) -> Result<(), ProjectionValidationError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(ProjectionValidationError::InvalidBinaryField {
                field: "schema_version",
            });
        }
        validate_binary(&self.binary)?;
        let entity_count = self
            .functions
            .len()
            .checked_add(self.globals.len())
            .and_then(|count| count.checked_add(self.types.len()));
        if entity_count.is_none_or(|count| count > MAX_ENTITIES) {
            return Err(ProjectionValidationError::CollectionLimit {
                collection: "entities",
            });
        }
        if self.warnings.len() > MAX_WARNINGS {
            return Err(ProjectionValidationError::CollectionLimit {
                collection: "warnings",
            });
        }

        if !strictly_increasing_by(&self.functions, |left, right| left.rva < right.rva) {
            return Err(ProjectionValidationError::UnsortedCollection {
                collection: "functions",
            });
        }
        if !strictly_increasing_by(&self.globals, |left, right| left.rva < right.rva) {
            return Err(ProjectionValidationError::UnsortedCollection {
                collection: "globals",
            });
        }
        if !strictly_increasing_by(&self.types, |left, right| {
            left.key.as_str() < right.key.as_str()
        }) {
            return Err(ProjectionValidationError::UnsortedCollection {
                collection: "types",
            });
        }

        let mut output_names = BTreeSet::new();
        for function in &self.functions {
            validate_range(function.rva, function.size, self.binary.image_size)?;
            validate_entity_names(
                function.selected_name.as_ref(),
                &function.alternate_names,
                &mut output_names,
            )?;
            validate_size_attribution(function.size, function.size_attribution.as_ref())?;
            validate_text_candidates(
                &function.prototypes,
                MAX_DECLARATION_BYTES,
                "function.prototype",
                MAX_DECLARATIONS_PER_ENTITY,
            )?;
        }
        let mut previous_end = 0_u64;
        for function in self.functions.iter().filter(|value| value.size.is_some()) {
            if function.rva < previous_end {
                return Err(ProjectionValidationError::OverlappingFunctionRanges);
            }
            previous_end = function
                .rva
                .checked_add(function.size.expect("filtered sized function"))
                .ok_or(ProjectionValidationError::AddressOutsideImage {
                    rva: function.rva,
                    size: function.size,
                })?;
        }
        for global in &self.globals {
            validate_range(global.rva, global.size, self.binary.image_size)?;
            validate_entity_names(
                global.selected_name.as_ref(),
                &global.alternate_names,
                &mut output_names,
            )?;
            validate_size_attribution(global.size, global.size_attribution.as_ref())?;
        }
        for value in &self.types {
            require_text(&value.key, MAX_TYPE_KEY_BYTES, "type.key")?;
            validate_entity_names(
                value.selected_name.as_ref(),
                &value.alternate_names,
                &mut output_names,
            )?;
            validate_text_candidates(
                &value.definitions,
                MAX_DECLARATION_BYTES,
                "type.definition",
                MAX_DECLARATIONS_PER_ENTITY,
            )?;
        }

        if self.warnings.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ProjectionValidationError::UnsortedWarnings);
        }
        for warning in &self.warnings {
            if warning.occurrences == 0 {
                return Err(ProjectionValidationError::ZeroWarningOccurrences);
            }
            require_text(
                &warning.message,
                MAX_WARNING_MESSAGE_BYTES,
                "warning.message",
            )?;
            if warning.message != warning.code.message() {
                return Err(ProjectionValidationError::InvalidText {
                    field: "warning.message",
                });
            }
            if let Some(ExportSubject::Type { key }) = &warning.subject {
                require_text(key, MAX_TYPE_KEY_BYTES, "warning.subject.type.key")?;
            }
        }
        Ok(())
    }
}

fn validate_binary(binary: &ExportBinary) -> Result<(), ProjectionValidationError> {
    if binary.image_size == 0 {
        return Err(ProjectionValidationError::InvalidBinaryField {
            field: "binary.image_size",
        });
    }
    if binary.image_base.checked_add(binary.image_size).is_none() {
        return Err(ProjectionValidationError::InvalidBinaryField {
            field: "binary.image_range",
        });
    }
    require_text(
        &binary.architecture,
        MAX_ARCHITECTURE_BYTES,
        "binary.architecture",
    )?;
    if let ExportBinaryFormat::Other(value) = &binary.format {
        require_text(value, MAX_ARCHITECTURE_BYTES, "binary.format")?;
    }
    Ok(())
}

fn validate_range(
    rva: u64,
    size: Option<u64>,
    image_size: u64,
) -> Result<(), ProjectionValidationError> {
    let span = size.unwrap_or(1);
    if span == 0 || rva >= image_size || rva.checked_add(span).is_none_or(|end| end > image_size) {
        return Err(ProjectionValidationError::AddressOutsideImage { rva, size });
    }
    Ok(())
}

fn validate_size_attribution(
    size: Option<u64>,
    attribution: Option<&ExportAttribution>,
) -> Result<(), ProjectionValidationError> {
    if size.is_some() != attribution.is_some() {
        return Err(ProjectionValidationError::InvalidBinaryField {
            field: "symbol.size_attribution",
        });
    }
    if let Some(attribution) = attribution {
        validate_attribution(attribution)?;
    }
    Ok(())
}

fn validate_entity_names(
    selected: Option<&ExportName>,
    alternates: &[AttributedText],
    output_names: &mut BTreeSet<String>,
) -> Result<(), ProjectionValidationError> {
    if alternates.len() >= MAX_NAMES_PER_ENTITY {
        return Err(ProjectionValidationError::CollectionLimit {
            collection: "alternate_names",
        });
    }
    if let Some(selected) = selected {
        validate_attributed_text(&selected.source, MAX_NAME_BYTES, "symbol.name")?;
        require_text(
            &selected.output_name,
            MAX_OUTPUT_NAME_BYTES,
            "symbol.output_name",
        )?;
        if !is_portable_output_name(&selected.output_name) {
            return Err(ProjectionValidationError::InvalidText {
                field: "symbol.output_name",
            });
        }
        if !output_names.insert(selected.output_name.clone()) {
            return Err(ProjectionValidationError::DuplicateOutputName {
                name: selected.output_name.clone(),
            });
        }
        if alternates
            .iter()
            .any(|candidate| candidate.text == selected.source.text)
        {
            return Err(ProjectionValidationError::DuplicateSelectedAlternate);
        }
    }
    validate_text_candidates(
        alternates,
        MAX_NAME_BYTES,
        "symbol.alternate_name",
        MAX_NAMES_PER_ENTITY,
    )
}

fn validate_text_candidates(
    values: &[AttributedText],
    max_bytes: usize,
    field: &'static str,
    limit: usize,
) -> Result<(), ProjectionValidationError> {
    if values.len() > limit {
        return Err(ProjectionValidationError::CollectionLimit { collection: field });
    }
    for value in values {
        validate_attributed_text(value, max_bytes, field)?;
    }
    if values
        .windows(2)
        .any(|pair| candidate_order(&pair[0], &pair[1]).is_ge())
    {
        return Err(ProjectionValidationError::DuplicateTextCandidate);
    }
    Ok(())
}

fn validate_attributed_text(
    value: &AttributedText,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), ProjectionValidationError> {
    require_text(&value.text, max_bytes, field)?;
    validate_attribution(&value.attribution)
}

fn validate_attribution(value: &ExportAttribution) -> Result<(), ProjectionValidationError> {
    if !value.confidence.is_finite()
        || !(0.0..=1.0).contains(&value.confidence)
        || (value.confidence == 0.0 && value.confidence.is_sign_negative())
    {
        return Err(ProjectionValidationError::InvalidConfidence);
    }
    value.provenance.validate()
}

impl ExportProvenance {
    pub(crate) fn validate(&self) -> Result<(), ProjectionValidationError> {
        require_text(&self.method, MAX_PROVENANCE_TEXT_BYTES, "provenance.method")?;
        if let Some(run_id) = &self.run_id {
            require_text(run_id, MAX_PROVENANCE_TEXT_BYTES, "provenance.run_id")?;
        }
        match &self.producer {
            ExportProducer::Core { component, version } => {
                require_text(
                    component,
                    MAX_PROVENANCE_TEXT_BYTES,
                    "provenance.producer.component",
                )?;
                require_text(
                    version,
                    MAX_PROVENANCE_TEXT_BYTES,
                    "provenance.producer.version",
                )
            }
            ExportProducer::Plugin { id, version } => {
                require_text(id, MAX_PROVENANCE_TEXT_BYTES, "provenance.producer.id")?;
                require_text(
                    version,
                    MAX_PROVENANCE_TEXT_BYTES,
                    "provenance.producer.version",
                )
            }
            ExportProducer::User { reviewer } => {
                if let Some(reviewer) = reviewer {
                    require_text(
                        reviewer,
                        MAX_PROVENANCE_TEXT_BYTES,
                        "provenance.producer.reviewer",
                    )?;
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn candidate_order(left: &AttributedText, right: &AttributedText) -> std::cmp::Ordering {
    producer_authority(&right.attribution.provenance)
        .cmp(&producer_authority(&left.attribution.provenance))
        .then_with(|| {
            right
                .attribution
                .confidence
                .total_cmp(&left.attribution.confidence)
        })
        .then_with(|| left.text.cmp(&right.text))
        .then_with(|| {
            left.attribution
                .provenance
                .cmp(&right.attribution.provenance)
        })
}

pub(crate) const fn producer_authority(provenance: &ExportProvenance) -> u8 {
    match provenance.producer {
        ExportProducer::User { .. } => 3,
        ExportProducer::Core { .. } => 2,
        ExportProducer::Plugin { .. } => 1,
    }
}

pub(crate) fn require_text(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), ProjectionValidationError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(is_disallowed_char)
    {
        return Err(ProjectionValidationError::InvalidText { field });
    }
    Ok(())
}

pub(crate) fn is_portable_output_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_disallowed_char(value: char) -> bool {
    value.is_control()
        || matches!(
            value,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

fn strictly_increasing_by<T>(values: &[T], less: impl Fn(&T, &T) -> bool) -> bool {
    values.windows(2).all(|pair| less(&pair[0], &pair[1]))
}
