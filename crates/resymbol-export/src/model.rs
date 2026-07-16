use std::collections::BTreeSet;

use resymbol_core::BinaryId;
use serde::Serialize;

use crate::{
    MAX_CLASS_MEMBERSHIPS_PER_FUNCTION, MAX_DECLARATION_BYTES, MAX_DIRECT_CALLS, MAX_NAME_BYTES,
    MAX_OUTPUT_NAME_BYTES, MAX_PROVENANCE_TEXT_BYTES, MAX_THUNKS, MAX_TYPE_KEY_BYTES,
    ProjectionValidationError,
};

pub(crate) const MAX_CLAIMS: usize = 1_000_000;
pub(crate) const MAX_ENTITIES: usize = 500_000;
pub(crate) const MAX_NAMES_PER_ENTITY: usize = 256;
pub(crate) const MAX_DECLARATIONS_PER_ENTITY: usize = 256;
pub(crate) const MAX_WARNINGS: usize = 100_000;
pub(crate) const MAX_ARCHITECTURE_BYTES: usize = 128;
const MAX_WARNING_MESSAGE_BYTES: usize = 256;
pub(crate) const MAX_RECOVERED_STRINGS: usize = 65_536;
pub(crate) const MAX_RECOVERED_STRING_BYTES: usize = 16 * 1024;
pub(crate) const MAX_TOTAL_RECOVERED_STRING_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_DATA_REFERENCES: usize = 262_144;
const MAX_X86_INSTRUCTION_BYTES: u8 = 15;

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
    /// Strongest successfully represented claim establishing that this RVA is
    /// a function entry, without implying a name or recoverable extent.
    pub entry_attribution: Option<ExportAttribution>,
    pub size: Option<u64>,
    pub size_attribution: Option<ExportAttribution>,
    pub selected_name: Option<ExportName>,
    pub alternate_names: Vec<AttributedText>,
    pub prototypes: Vec<AttributedText>,
    /// Classes this function is attributed to by the source claim graph.
    ///
    /// Debugger-specific writers may ignore this relationship when their
    /// target format cannot represent it without inventing extra symbols.
    pub class_memberships: Vec<AttributedText>,
}

/// Address target retained for a direct call or thunk relationship.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExportControlFlowTarget {
    Function { rva: u64 },
    ImportIat { iat_rva: u64 },
    FunctionPointer { slot_rva: u64, rva: u64 },
}

/// One attributed direct-call relationship in the binary image.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportDirectCall {
    pub caller_rva: u64,
    pub call_site_rva: u64,
    pub target: ExportControlFlowTarget,
    pub attribution: ExportAttribution,
}

/// One attributed function thunk and its selected target.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportThunk {
    pub rva: u64,
    pub target: ExportControlFlowTarget,
    pub attribution: ExportAttribution,
}

/// Source encoding retained for one recovered string literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[non_exhaustive]
pub enum ExportStringEncoding {
    #[serde(rename = "ascii")]
    Ascii,
    #[serde(rename = "utf-16-le")]
    Utf16Le,
}

/// One bounded, attributed string literal in the binary image.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportRecoveredString {
    pub rva: u64,
    /// Encoded byte size including the terminating NUL code unit.
    pub byte_size: u64,
    pub encoding: ExportStringEncoding,
    pub value: String,
    pub attribution: ExportAttribution,
}

/// One exact attributed x64 RIP-relative relationship to image data.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportDataReference {
    pub caller_rva: u64,
    pub instruction_rva: u64,
    pub instruction_size: u8,
    pub target_rva: u64,
    /// Retained string whose encoded content contains `target_rva`, if any.
    /// UTF-16LE targets must address a code-unit boundary; terminators are excluded.
    pub referenced_string_rva: Option<u64>,
    pub attribution: ExportAttribution,
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
    ClassMembershipLimitExceeded,
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
            Self::ClassMembershipLimitExceeded => {
                "function class membership exceeded the neutral export limit and was omitted"
            }
            Self::ConflictingSize => {
                "competing symbol sizes were reduced to the highest-ranked value"
            }
            Self::AmbiguousSize => "equal-authority symbol sizes conflict, so the size was omitted",
            Self::OverlappingFunctionRange => {
                "function boundary overlaps a stronger boundary and was omitted"
            }
            Self::AddressKindCollision => {
                "function and global claims share an RVA; debugger bridges suppress the global only when they emit a function record"
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
    pub direct_calls: Vec<ExportDirectCall>,
    pub thunks: Vec<ExportThunk>,
    pub strings: Vec<ExportRecoveredString>,
    pub data_references: Vec<ExportDataReference>,
    pub warnings: Vec<ProjectionWarning>,
}

impl ExportProjection {
    pub(crate) const SCHEMA_VERSION: u32 = 6;

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
        if self.direct_calls.len() > MAX_DIRECT_CALLS {
            return Err(ProjectionValidationError::CollectionLimit {
                collection: "direct_calls",
            });
        }
        if self.thunks.len() > MAX_THUNKS {
            return Err(ProjectionValidationError::CollectionLimit {
                collection: "thunks",
            });
        }
        if self.strings.len() > MAX_RECOVERED_STRINGS {
            return Err(ProjectionValidationError::CollectionLimit {
                collection: "strings",
            });
        }
        if self.data_references.len() > MAX_DATA_REFERENCES {
            return Err(ProjectionValidationError::CollectionLimit {
                collection: "data_references",
            });
        }
        let pointer_call_companions = self
            .data_references
            .iter()
            .filter(|reference| matches!(reference.instruction_size, 6 | 7))
            .map(|reference| {
                (
                    reference.caller_rva,
                    reference.instruction_rva,
                    reference.target_rva,
                )
            })
            .collect::<BTreeSet<_>>();

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
            if let Some(attribution) = &function.entry_attribution {
                validate_attribution(attribution)?;
            }
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
            validate_text_candidates(
                &function.class_memberships,
                MAX_NAME_BYTES,
                "function.class_membership",
                MAX_CLASS_MEMBERSHIPS_PER_FUNCTION,
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

        if self
            .direct_calls
            .windows(2)
            .any(|pair| direct_call_key(&pair[0]) >= direct_call_key(&pair[1]))
        {
            return Err(ProjectionValidationError::UnsortedCollection {
                collection: "direct_calls",
            });
        }
        for call in &self.direct_calls {
            validate_point(call.caller_rva, self.binary.image_size)?;
            validate_point(call.call_site_rva, self.binary.image_size)?;
            let caller = require_function_entry(&self.functions, call.caller_rva)?;
            let site_outside_caller = call.call_site_rva < call.caller_rva
                || caller.size.is_some_and(|size| {
                    call.caller_rva
                        .checked_add(size)
                        .is_none_or(|end| call.call_site_rva >= end)
                });
            if site_outside_caller {
                return Err(ProjectionValidationError::InvalidBinaryField {
                    field: "direct_call.call_site",
                });
            }
            validate_control_flow_target(&self.functions, &call.target, &self.binary)?;
            if let ExportControlFlowTarget::FunctionPointer { slot_rva, .. } = call.target {
                if !pointer_call_companions.contains(&(
                    call.caller_rva,
                    call.call_site_rva,
                    slot_rva,
                )) {
                    return Err(ProjectionValidationError::InvalidBinaryField {
                        field: "direct_call.function_pointer_reference",
                    });
                }
            }
            validate_attribution(&call.attribution)?;
        }

        if self
            .thunks
            .windows(2)
            .any(|pair| pair[0].rva >= pair[1].rva)
        {
            return Err(ProjectionValidationError::UnsortedCollection {
                collection: "thunks",
            });
        }
        for thunk in &self.thunks {
            validate_point(thunk.rva, self.binary.image_size)?;
            require_function_entry(&self.functions, thunk.rva)?;
            validate_control_flow_target(&self.functions, &thunk.target, &self.binary)?;
            if control_flow_function_rva(&thunk.target) == Some(thunk.rva) {
                return Err(ProjectionValidationError::InvalidBinaryField {
                    field: "thunk.target",
                });
            }
            validate_attribution(&thunk.attribution)?;
        }

        if !strictly_increasing_by(&self.strings, |left, right| left.rva < right.rva) {
            return Err(ProjectionValidationError::UnsortedCollection {
                collection: "strings",
            });
        }
        let mut total_string_bytes = 0_usize;
        let mut previous_string_end = None;
        for string in &self.strings {
            validate_recovered_string(string, &self.binary)?;
            if previous_string_end.is_some_and(|end| end > string.rva) {
                return Err(ProjectionValidationError::InvalidBinaryField {
                    field: "strings.overlap",
                });
            }
            previous_string_end = string.rva.checked_add(string.byte_size);
            total_string_bytes = total_string_bytes.checked_add(string.value.len()).ok_or(
                ProjectionValidationError::CollectionLimit {
                    collection: "string_bytes",
                },
            )?;
            if total_string_bytes > MAX_TOTAL_RECOVERED_STRING_BYTES {
                return Err(ProjectionValidationError::CollectionLimit {
                    collection: "string_bytes",
                });
            }
        }

        if self
            .data_references
            .windows(2)
            .any(|pair| data_reference_key(&pair[0]) >= data_reference_key(&pair[1]))
        {
            return Err(ProjectionValidationError::UnsortedCollection {
                collection: "data_references",
            });
        }
        for reference in &self.data_references {
            validate_data_reference(reference, &self.functions, &self.strings, &self.binary)?;
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

fn direct_call_key(call: &ExportDirectCall) -> (u64, u64, &ExportControlFlowTarget) {
    (call.caller_rva, call.call_site_rva, &call.target)
}

fn data_reference_key(reference: &ExportDataReference) -> (u64, u64) {
    (reference.caller_rva, reference.instruction_rva)
}

fn validate_recovered_string(
    string: &ExportRecoveredString,
    binary: &ExportBinary,
) -> Result<(), ProjectionValidationError> {
    if string.value.is_empty()
        || string.value.trim().is_empty()
        || string.value.len() > MAX_RECOVERED_STRING_BYTES
    {
        return Err(ProjectionValidationError::InvalidText {
            field: "string.value",
        });
    }
    let encoded_content_bytes = match string.encoding {
        ExportStringEncoding::Ascii => {
            if !string
                .value
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte))
            {
                return Err(ProjectionValidationError::InvalidText {
                    field: "string.value",
                });
            }
            u64::try_from(string.value.len()).map_err(|_| {
                ProjectionValidationError::InvalidBinaryField {
                    field: "string.byte_size",
                }
            })?
        }
        ExportStringEncoding::Utf16Le => {
            if string.value.chars().any(char::is_control) {
                return Err(ProjectionValidationError::InvalidText {
                    field: "string.value",
                });
            }
            u64::try_from(string.value.encode_utf16().count())
                .ok()
                .and_then(|units| units.checked_mul(2))
                .ok_or(ProjectionValidationError::InvalidBinaryField {
                    field: "string.byte_size",
                })?
        }
    };
    let terminator_bytes = match string.encoding {
        ExportStringEncoding::Ascii => 1,
        ExportStringEncoding::Utf16Le => 2,
    };
    let expected_size = encoded_content_bytes.checked_add(terminator_bytes).ok_or(
        ProjectionValidationError::InvalidBinaryField {
            field: "string.byte_size",
        },
    )?;
    if string.byte_size != expected_size
        || string.byte_size
            > u64::try_from(MAX_RECOVERED_STRING_BYTES).expect("string limit fits in u64")
    {
        return Err(ProjectionValidationError::InvalidBinaryField {
            field: "string.byte_size",
        });
    }
    validate_range(string.rva, Some(string.byte_size), binary.image_size)?;
    validate_attribution(&string.attribution)
}

fn validate_data_reference(
    reference: &ExportDataReference,
    functions: &[ExportFunction],
    strings: &[ExportRecoveredString],
    binary: &ExportBinary,
) -> Result<(), ProjectionValidationError> {
    if !(1..=MAX_X86_INSTRUCTION_BYTES).contains(&reference.instruction_size) {
        return Err(ProjectionValidationError::InvalidBinaryField {
            field: "data_reference.instruction_size",
        });
    }
    validate_point(reference.caller_rva, binary.image_size)?;
    validate_range(
        reference.instruction_rva,
        Some(u64::from(reference.instruction_size)),
        binary.image_size,
    )?;
    validate_point(reference.target_rva, binary.image_size)?;
    let caller = require_function_entry(functions, reference.caller_rva)?;
    let instruction_end = reference
        .instruction_rva
        .checked_add(u64::from(reference.instruction_size));
    if reference.instruction_rva < reference.caller_rva
        || caller.size.is_some_and(|size| {
            reference
                .caller_rva
                .checked_add(size)
                .is_none_or(|caller_end| instruction_end.is_none_or(|end| end > caller_end))
        })
    {
        return Err(ProjectionValidationError::InvalidBinaryField {
            field: "data_reference.instruction_rva",
        });
    }
    if reference.referenced_string_rva != referenced_string_rva(strings, reference.target_rva) {
        return Err(ProjectionValidationError::InvalidBinaryField {
            field: "data_reference.referenced_string_rva",
        });
    }
    validate_attribution(&reference.attribution)
}

pub(crate) fn referenced_string_rva(
    strings: &[ExportRecoveredString],
    target_rva: u64,
) -> Option<u64> {
    let index = strings
        .partition_point(|string| string.rva <= target_rva)
        .checked_sub(1)?;
    let string = strings.get(index)?;
    let content_size = match string.encoding {
        ExportStringEncoding::Ascii => string.byte_size.checked_sub(1)?,
        ExportStringEncoding::Utf16Le => string.byte_size.checked_sub(2)?,
    };
    let offset = target_rva.checked_sub(string.rva)?;
    if offset >= content_size
        || matches!(string.encoding, ExportStringEncoding::Utf16Le) && offset % 2 != 0
    {
        return None;
    }
    Some(string.rva)
}

fn validate_point(rva: u64, image_size: u64) -> Result<(), ProjectionValidationError> {
    validate_range(rva, None, image_size)
}

fn require_function_entry(
    functions: &[ExportFunction],
    rva: u64,
) -> Result<&ExportFunction, ProjectionValidationError> {
    let function = functions
        .binary_search_by_key(&rva, |function| function.rva)
        .ok()
        .and_then(|index| functions.get(index));
    let Some(function) = function.filter(|function| function.entry_attribution.is_some()) else {
        return Err(ProjectionValidationError::InvalidBinaryField {
            field: "control_flow.function_entry",
        });
    };
    Ok(function)
}

fn validate_control_flow_target(
    functions: &[ExportFunction],
    target: &ExportControlFlowTarget,
    binary: &ExportBinary,
) -> Result<(), ProjectionValidationError> {
    match target {
        ExportControlFlowTarget::Function { rva } => {
            validate_point(*rva, binary.image_size)?;
            require_function_entry(functions, *rva).map(|_| ())
        }
        ExportControlFlowTarget::ImportIat { iat_rva } => {
            validate_point(*iat_rva, binary.image_size)
        }
        ExportControlFlowTarget::FunctionPointer { slot_rva, rva } => {
            validate_range(*slot_rva, Some(8), binary.image_size)?;
            validate_point(*rva, binary.image_size)?;
            require_function_entry(functions, *rva).map(|_| ())
        }
    }
}

fn control_flow_function_rva(target: &ExportControlFlowTarget) -> Option<u64> {
    match target {
        ExportControlFlowTarget::Function { rva }
        | ExportControlFlowTarget::FunctionPointer { rva, .. } => Some(*rva),
        ExportControlFlowTarget::ImportIat { .. } => None,
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
    if alternates
        .len()
        .checked_add(usize::from(selected.is_some()))
        .is_none_or(|count| count > MAX_NAMES_PER_ENTITY)
    {
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
