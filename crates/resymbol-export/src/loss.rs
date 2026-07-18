use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::{
    ExportProjection, ProjectionValidationError,
    markdown::markdown_loss_metrics,
    selection::{
        SelectedSymbolKind, collect_public_symbols, mutation_plan, public_symbol_candidate_count,
    },
};

/// Maximum number of aggregate entries in one target-loss report.
///
/// Reports contain at most one entry per stable loss code and never include a
/// per-symbol detail list.
pub const MAX_EXPORT_LOSS_ITEMS: usize = 21;
/// Maximum UTF-8 byte length of one fixed target-loss explanation.
pub const MAX_EXPORT_LOSS_MESSAGE_BYTES: usize = 128;

/// Export destination whose representational losses should be measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExportTarget {
    Json,
    Markdown,
    Map,
    Pdb,
    IdaPython,
    GhidraJava,
    Dwarf,
}

impl ExportTarget {
    /// Stable command-line spelling of this target.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "markdown",
            Self::Map => "map",
            Self::Pdb => "pdb",
            Self::IdaPython => "ida-python",
            Self::GhidraJava => "ghidra-java",
            Self::Dwarf => "dwarf",
        }
    }
}

impl fmt::Display for ExportTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable machine-readable reason a target cannot retain projected semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExportLossCode {
    ProjectionMetadataOmitted,
    ReportRowOmitted,
    CandidateDetailOmitted,
    TextTruncated,
    AttributionOmitted,
    FunctionOmitted,
    FunctionSizeOmitted,
    GlobalOmitted,
    GlobalSizeOmitted,
    AddressKindCollision,
    OriginalNameOmitted,
    AlternateNameOmitted,
    PrototypeOmitted,
    ClassMembershipOmitted,
    TypeOmitted,
    TypeDefinitionOmitted,
    DirectCallOmitted,
    ThunkOmitted,
    StringOmitted,
    DataReferenceOmitted,
    ProjectionWarningOmitted,
}

impl ExportLossCode {
    /// Stable kebab-case identifier suitable for logs and policy checks.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProjectionMetadataOmitted => "projection-metadata-omitted",
            Self::ReportRowOmitted => "report-row-omitted",
            Self::CandidateDetailOmitted => "candidate-detail-omitted",
            Self::TextTruncated => "text-truncated",
            Self::AttributionOmitted => "attribution-omitted",
            Self::FunctionOmitted => "function-omitted",
            Self::FunctionSizeOmitted => "function-size-omitted",
            Self::GlobalOmitted => "global-omitted",
            Self::GlobalSizeOmitted => "global-size-omitted",
            Self::AddressKindCollision => "address-kind-collision",
            Self::OriginalNameOmitted => "original-name-omitted",
            Self::AlternateNameOmitted => "alternate-name-omitted",
            Self::PrototypeOmitted => "prototype-omitted",
            Self::ClassMembershipOmitted => "class-membership-omitted",
            Self::TypeOmitted => "type-omitted",
            Self::TypeDefinitionOmitted => "type-definition-omitted",
            Self::DirectCallOmitted => "direct-call-omitted",
            Self::ThunkOmitted => "thunk-omitted",
            Self::StringOmitted => "string-omitted",
            Self::DataReferenceOmitted => "data-reference-omitted",
            Self::ProjectionWarningOmitted => "projection-warning-omitted",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::ProjectionMetadataOmitted => {
                "projection schema or binary identity fields are not represented by the target"
            }
            Self::ReportRowOmitted => "rows exceed a bounded presentation section limit",
            Self::CandidateDetailOmitted => {
                "candidate text exceeds a bounded presentation summary limit"
            }
            Self::TextTruncated => "projected text is shortened by a presentation byte limit",
            Self::AttributionOmitted => {
                "projected confidence or provenance is not represented by the target"
            }
            Self::FunctionOmitted => "projected functions have no target record",
            Self::FunctionSizeOmitted => "projected function extents are not represented",
            Self::GlobalOmitted => "projected globals have no target record",
            Self::GlobalSizeOmitted => "projected global extents are not represented",
            Self::AddressKindCollision => {
                "a target collision rule suppresses a selected global record"
            }
            Self::OriginalNameOmitted => {
                "a rewritten output name is retained without its original source spelling"
            }
            Self::AlternateNameOmitted => "alternate symbol names are not represented",
            Self::PrototypeOmitted => "function prototypes are not represented",
            Self::ClassMembershipOmitted => "function class memberships are not represented",
            Self::TypeOmitted => "projected type records are not represented",
            Self::TypeDefinitionOmitted => "projected type definitions are not represented",
            Self::DirectCallOmitted => "direct-call relationships are not represented",
            Self::ThunkOmitted => "thunk relationships are not represented",
            Self::StringOmitted => "recovered strings are not represented",
            Self::DataReferenceOmitted => "data-reference relationships are not represented",
            Self::ProjectionWarningOmitted => {
                "neutral projection warning groups are not embedded in the target"
            }
        }
    }
}

/// One bounded aggregate of equivalent target-specific losses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportLossItem {
    /// Stable aggregate category.
    code: ExportLossCode,
    /// Number of equivalent projected losses represented by this item.
    occurrences: u64,
    /// Fixed, non-subject-specific explanation for `code`.
    message: &'static str,
}

impl ExportLossItem {
    /// Stable aggregate category.
    pub const fn code(&self) -> ExportLossCode {
        self.code
    }

    /// Number of equivalent projected losses represented by this item.
    pub const fn occurrences(&self) -> u64 {
        self.occurrences
    }

    /// Fixed, non-subject-specific explanation for this category.
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

/// Deterministic target-loss assessment for one validated projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportLossReport {
    /// Destination assessed by this report.
    target: ExportTarget,
    /// Stable code order with at most [`MAX_EXPORT_LOSS_ITEMS`] entries.
    items: Vec<ExportLossItem>,
}

impl ExportLossReport {
    /// Validate `projection` and aggregate only semantics lost by `target`.
    pub fn for_projection(
        target: ExportTarget,
        projection: &ExportProjection,
    ) -> Result<Self, ProjectionValidationError> {
        projection.validate()?;
        let mut losses = LossAccumulator::default();
        match target {
            ExportTarget::Json => {}
            ExportTarget::Markdown => markdown_losses(projection, &mut losses),
            ExportTarget::Map | ExportTarget::Pdb => {
                public_symbol_losses(target, projection, &mut losses)
            }
            ExportTarget::IdaPython | ExportTarget::GhidraJava => {
                mutation_losses(projection, &mut losses)
            }
            ExportTarget::Dwarf => dwarf_losses(projection, &mut losses),
        }
        Ok(Self {
            target,
            items: losses.finish(),
        })
    }

    /// Total number of aggregated loss occurrences.
    pub fn occurrence_count(&self) -> u64 {
        self.items.iter().fold(0_u64, |total, item| {
            total
                .checked_add(item.occurrences)
                .expect("validated projection loss counts fit in u64")
        })
    }

    /// Destination assessed by this report.
    pub const fn target(&self) -> ExportTarget {
        self.target
    }

    /// Stable aggregate items in machine-code order.
    pub fn items(&self) -> &[ExportLossItem] {
        &self.items
    }

    /// Whether the target retains every projected semantic represented here.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[derive(Default)]
struct LossAccumulator {
    occurrences: BTreeMap<ExportLossCode, u64>,
}

impl LossAccumulator {
    fn add_usize(&mut self, code: ExportLossCode, occurrences: usize) {
        self.add(
            code,
            u64::try_from(occurrences).expect("validated projection collection length fits u64"),
        );
    }

    fn add(&mut self, code: ExportLossCode, occurrences: u64) {
        if occurrences == 0 {
            return;
        }
        let value = self.occurrences.entry(code).or_default();
        *value = value
            .checked_add(occurrences)
            .expect("validated projection loss counts fit in u64");
    }

    fn finish(self) -> Vec<ExportLossItem> {
        debug_assert!(self.occurrences.len() <= MAX_EXPORT_LOSS_ITEMS);
        self.occurrences
            .into_iter()
            .map(|(code, occurrences)| {
                let message = code.message();
                debug_assert!(message.len() <= MAX_EXPORT_LOSS_MESSAGE_BYTES);
                ExportLossItem {
                    code,
                    occurrences,
                    message,
                }
            })
            .collect()
    }
}

fn markdown_losses(projection: &ExportProjection, losses: &mut LossAccumulator) {
    let metrics = markdown_loss_metrics(projection);
    losses.add_usize(ExportLossCode::ReportRowOmitted, metrics.rows_omitted);
    losses.add_usize(
        ExportLossCode::CandidateDetailOmitted,
        metrics.candidates_omitted,
    );
    losses.add_usize(ExportLossCode::TextTruncated, metrics.text_truncations);
    losses.add_usize(
        ExportLossCode::AttributionOmitted,
        metrics.attributions_omitted,
    );
}

fn public_symbol_losses(
    target: ExportTarget,
    projection: &ExportProjection,
    losses: &mut LossAccumulator,
) {
    // MAP retains SHA-256, file size, image base, and image size. PDB retains
    // target architecture but not the neutral projection's remaining identity.
    losses.add(
        ExportLossCode::ProjectionMetadataOmitted,
        match target {
            ExportTarget::Map => 3,
            ExportTarget::Pdb => 6,
            _ => unreachable!("public-symbol loss target"),
        },
    );

    let candidate_count = public_symbol_candidate_count(projection)
        .expect("validated projection candidate count fits usize");
    let mut selected = Vec::with_capacity(candidate_count);
    collect_public_symbols(projection, &mut selected);

    for function in &projection.functions {
        let emitted = selected
            .binary_search_by_key(&function.rva, |symbol| symbol.rva)
            .ok()
            .is_some_and(|index| selected[index].kind == SelectedSymbolKind::Function);
        if !emitted {
            losses.add(ExportLossCode::FunctionOmitted, 1);
        }
        if function.size.is_some() {
            losses.add(ExportLossCode::FunctionSizeOmitted, 1);
        }
    }
    for global in &projection.globals {
        let emitted = selected
            .binary_search_by_key(&global.rva, |symbol| symbol.rva)
            .ok()
            .is_some_and(|index| selected[index].kind == SelectedSymbolKind::Global);
        if !emitted {
            losses.add(ExportLossCode::GlobalOmitted, 1);
            if global.selected_name.is_some()
                && projection
                    .functions
                    .binary_search_by_key(&global.rva, |function| function.rva)
                    .is_ok_and(|index| projection.functions[index].selected_name.is_some())
            {
                losses.add(ExportLossCode::AddressKindCollision, 1);
            }
        }
        if global.size.is_some() {
            losses.add(ExportLossCode::GlobalSizeOmitted, 1);
        }
    }
    for symbol in selected {
        if symbol.source_name != symbol.output_name {
            losses.add(ExportLossCode::OriginalNameOmitted, 1);
        }
    }
    common_non_json_losses(projection, losses);
}

fn mutation_losses(projection: &ExportProjection, losses: &mut LossAccumulator) {
    // Mutation bridges retain the exact SHA-256 and resolve projected RVAs
    // against the debugger's loaded image base. Other neutral metadata is not
    // embedded in the generated source.
    losses.add(ExportLossCode::ProjectionMetadataOmitted, 6);
    let plan = mutation_plan(projection);

    for (index, function) in projection.functions.iter().enumerate() {
        let emitted = plan
            .functions
            .binary_search_by_key(&function.rva, |record| record.rva)
            .ok()
            .map(|record_index| &plan.functions[record_index]);
        if emitted.is_none() {
            losses.add(ExportLossCode::FunctionOmitted, 1);
        }
        if function.size.is_some() && plan.accepted_sizes[index].is_none() {
            losses.add(ExportLossCode::FunctionSizeOmitted, 1);
        }
        if emitted.is_some_and(|record| {
            record
                .source_name
                .zip(record.output_name)
                .is_some_and(|(source, output)| source != output)
        }) {
            losses.add(ExportLossCode::OriginalNameOmitted, 1);
        }
    }
    for global in &projection.globals {
        let emitted = plan
            .globals
            .binary_search_by_key(&global.rva, |record| record.rva)
            .ok()
            .map(|record_index| &plan.globals[record_index]);
        if emitted.is_none() {
            losses.add(ExportLossCode::GlobalOmitted, 1);
            if global.selected_name.is_some()
                && projection
                    .functions
                    .binary_search_by_key(&global.rva, |function| function.rva)
                    .is_ok_and(|index| {
                        plan.functions
                            .binary_search_by_key(&projection.functions[index].rva, |record| {
                                record.rva
                            })
                            .is_ok()
                    })
            {
                losses.add(ExportLossCode::AddressKindCollision, 1);
            }
        }
        if global.size.is_some() {
            losses.add(ExportLossCode::GlobalSizeOmitted, 1);
        }
        if emitted.is_some_and(|record| record.source_name != record.output_name) {
            losses.add(ExportLossCode::OriginalNameOmitted, 1);
        }
    }
    common_non_json_losses(projection, losses);
}

fn dwarf_losses(projection: &ExportProjection, losses: &mut LossAccumulator) {
    // The DWARF companion embeds the target architecture (as the ELF machine)
    // and the virtual image span (as the compile unit's low/high PC). The
    // remaining neutral identity fields have no honest DWARF home: the exact
    // binary SHA-256, the file size, the container format, and the projection
    // schema version.
    losses.add(ExportLossCode::ProjectionMetadataOmitted, 4);

    // Every function becomes a subprogram (named exactly, sized via high_pc when
    // known), so no function or function size is dropped. Globals need a name to
    // be useful as a variable DIE; an unnamed global has no target record. A
    // global's byte extent is never represented, because the writer does not
    // synthesize a type for the variable.
    for global in &projection.globals {
        if global.selected_name.is_none() {
            losses.add(ExportLossCode::GlobalOmitted, 1);
        }
        if global.size.is_some() {
            losses.add(ExportLossCode::GlobalSizeOmitted, 1);
        }
    }

    // Named types become class DIEs; unnamed types cannot.
    losses.add_usize(
        ExportLossCode::TypeOmitted,
        projection
            .types
            .iter()
            .filter(|value| value.selected_name.is_none())
            .count(),
    );

    // The remaining neutral relationships have no DWARF representation here.
    // Alternate names, prototypes, provenance, and confidence are all dropped;
    // class memberships are consumed to build class shells and inheritance, but
    // the function->method binding itself is never emitted, so each membership
    // is still counted as a loss. Type definitions contribute only the class
    // name, never their member layout.
    losses.add_usize(
        ExportLossCode::AlternateNameOmitted,
        projection
            .functions
            .iter()
            .map(|value| value.alternate_names.len())
            .chain(
                projection
                    .globals
                    .iter()
                    .map(|value| value.alternate_names.len()),
            )
            .chain(
                projection
                    .types
                    .iter()
                    .map(|value| value.alternate_names.len()),
            )
            .sum(),
    );
    losses.add_usize(
        ExportLossCode::PrototypeOmitted,
        projection
            .functions
            .iter()
            .map(|value| value.prototypes.len())
            .sum(),
    );
    losses.add_usize(
        ExportLossCode::ClassMembershipOmitted,
        projection
            .functions
            .iter()
            .map(|value| value.class_memberships.len())
            .sum(),
    );
    losses.add_usize(
        ExportLossCode::TypeDefinitionOmitted,
        projection
            .types
            .iter()
            .map(|value| value.definitions.len())
            .sum(),
    );
    losses.add_usize(
        ExportLossCode::DirectCallOmitted,
        projection.direct_calls.len(),
    );
    losses.add_usize(ExportLossCode::ThunkOmitted, projection.thunks.len());
    losses.add_usize(ExportLossCode::StringOmitted, projection.strings.len());
    losses.add_usize(
        ExportLossCode::DataReferenceOmitted,
        projection.data_references.len(),
    );
    losses.add_usize(
        ExportLossCode::ProjectionWarningOmitted,
        projection.warnings.len(),
    );
    losses.add_usize(
        ExportLossCode::AttributionOmitted,
        attribution_count(projection),
    );
}

fn common_non_json_losses(projection: &ExportProjection, losses: &mut LossAccumulator) {
    losses.add_usize(
        ExportLossCode::AlternateNameOmitted,
        projection
            .functions
            .iter()
            .map(|value| value.alternate_names.len())
            .chain(
                projection
                    .globals
                    .iter()
                    .map(|value| value.alternate_names.len()),
            )
            .chain(
                projection
                    .types
                    .iter()
                    .map(|value| value.alternate_names.len()),
            )
            .sum(),
    );
    losses.add_usize(
        ExportLossCode::PrototypeOmitted,
        projection
            .functions
            .iter()
            .map(|value| value.prototypes.len())
            .sum(),
    );
    losses.add_usize(
        ExportLossCode::ClassMembershipOmitted,
        projection
            .functions
            .iter()
            .map(|value| value.class_memberships.len())
            .sum(),
    );
    losses.add_usize(ExportLossCode::TypeOmitted, projection.types.len());
    losses.add_usize(
        ExportLossCode::TypeDefinitionOmitted,
        projection
            .types
            .iter()
            .map(|value| value.definitions.len())
            .sum(),
    );
    losses.add_usize(
        ExportLossCode::DirectCallOmitted,
        projection.direct_calls.len(),
    );
    losses.add_usize(ExportLossCode::ThunkOmitted, projection.thunks.len());
    losses.add_usize(ExportLossCode::StringOmitted, projection.strings.len());
    losses.add_usize(
        ExportLossCode::DataReferenceOmitted,
        projection.data_references.len(),
    );
    losses.add_usize(
        ExportLossCode::ProjectionWarningOmitted,
        projection.warnings.len(),
    );
    losses.add_usize(
        ExportLossCode::AttributionOmitted,
        attribution_count(projection),
    );
}

fn attribution_count(projection: &ExportProjection) -> usize {
    projection
        .functions
        .iter()
        .map(|value| {
            usize::from(value.entry_attribution.is_some())
                + usize::from(value.size_attribution.is_some())
                + usize::from(value.selected_name.is_some())
                + value.alternate_names.len()
                + value.prototypes.len()
                + value.class_memberships.len()
        })
        .chain(projection.globals.iter().map(|value| {
            usize::from(value.size_attribution.is_some())
                + usize::from(value.selected_name.is_some())
                + value.alternate_names.len()
        }))
        .chain(projection.types.iter().map(|value| {
            usize::from(value.selected_name.is_some())
                + value.alternate_names.len()
                + value.definitions.len()
        }))
        .sum::<usize>()
        .checked_add(projection.direct_calls.len())
        .and_then(|count| count.checked_add(projection.thunks.len()))
        .and_then(|count| count.checked_add(projection.strings.len()))
        .and_then(|count| count.checked_add(projection.data_references.len()))
        .expect("validated projection attribution count fits usize")
}
