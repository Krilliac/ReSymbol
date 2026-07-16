use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    fmt::Write as _,
};

use resymbol_analysis::{AnalysisSession, BinaryAnalysis};
use resymbol_core::{
    BinaryFormat, BinaryIdentity, ClaimProducer, ClaimProvenance, ControlFlowTarget,
    StringEncoding, SymbolAssertion, SymbolClaim, SymbolGraph, SymbolSubject,
};

use crate::{
    AttributedText, ExportAttribution, ExportBinary, ExportBinaryFormat, ExportControlFlowTarget,
    ExportDirectCall, ExportError, ExportFunction, ExportGlobal, ExportName, ExportProducer,
    ExportProjection, ExportProvenance, ExportSubject, ExportThunk, ExportType,
    MAX_CLASS_MEMBERSHIPS_PER_FUNCTION, MAX_DECLARATION_BYTES, MAX_DIRECT_CALLS, MAX_NAME_BYTES,
    MAX_OUTPUT_NAME_BYTES, MAX_THUNKS, MAX_TYPE_KEY_BYTES, ProjectionWarning,
    ProjectionWarningCode,
    model::{
        ExportDataReference, ExportRecoveredString, ExportStringEncoding, MAX_ARCHITECTURE_BYTES,
        MAX_CLAIMS, MAX_DATA_REFERENCES, MAX_DECLARATIONS_PER_ENTITY, MAX_ENTITIES,
        MAX_NAMES_PER_ENTITY, MAX_RECOVERED_STRING_BYTES, MAX_RECOVERED_STRINGS, MAX_WARNINGS,
        candidate_order, producer_authority, referenced_string_rva, require_text,
    },
};

#[derive(Debug, Default)]
struct AddressAccumulator<'claims> {
    entry_attribution: Option<ExportAttribution>,
    names: NameAccumulator,
    declarations: BTreeMap<String, AttributedText>,
    class_memberships: BTreeMap<String, AttributedText>,
    distinct_class_memberships: BTreeSet<&'claims str>,
    sizes: BTreeMap<u64, ExportAttribution>,
}

type DirectCallKey = (u64, u64, ExportControlFlowTarget);
type ThunkValue = (ExportControlFlowTarget, ExportAttribution);
type DataReferenceKey = (u64, u64);

#[derive(Debug, Default)]
struct TypeAccumulator {
    names: NameAccumulator,
    definitions: BTreeMap<String, AttributedText>,
}

/// Whether one exact name claim may become the selected debugger-facing name.
///
/// Alias-only claims remain represented and attributed, but cannot become the
/// primary name even when no other name proposal exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSelection {
    /// The claim participates in deterministic primary-name selection.
    PrimaryEligible,
    /// The claim is retained only as an attributed alternate name.
    AliasOnly,
}

#[derive(Debug, Default)]
struct NameAccumulator {
    values: BTreeMap<String, NameCandidates>,
}

#[derive(Debug, Default)]
struct NameCandidates {
    primary_eligible: Option<AttributedText>,
    alias_only: Option<AttributedText>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WarningKey {
    code: ProjectionWarningCode,
    subject: Option<ExportSubject>,
}

#[derive(Debug)]
struct WarningAccumulator {
    values: BTreeMap<WarningKey, u64>,
}

impl WarningAccumulator {
    fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    fn add(
        &mut self,
        code: ProjectionWarningCode,
        subject: Option<ExportSubject>,
    ) -> Result<(), ExportError> {
        self.add_occurrences(code, subject, 1)
    }

    fn add_occurrences(
        &mut self,
        code: ProjectionWarningCode,
        subject: Option<ExportSubject>,
        occurrences: u64,
    ) -> Result<(), ExportError> {
        if occurrences == 0 {
            return Ok(());
        }
        let key = WarningKey { code, subject };
        if !self.values.contains_key(&key) && self.values.len() == MAX_WARNINGS {
            return Err(ExportError::LimitExceeded {
                resource: "warning",
                limit: MAX_WARNINGS,
            });
        }
        let count = self.values.entry(key).or_default();
        *count = count
            .checked_add(occurrences)
            .ok_or(ExportError::LimitExceeded {
                resource: "warning occurrence",
                limit: usize::MAX,
            })?;
        Ok(())
    }

    fn finish(self) -> Vec<ProjectionWarning> {
        self.values
            .into_iter()
            .map(|(key, occurrences)| ProjectionWarning {
                code: key.code,
                subject: key.subject,
                occurrences,
                message: key.code.message().to_owned(),
            })
            .collect()
    }
}

impl ExportProjection {
    /// Project a validated analysis session and all accepted plugin claims.
    pub fn from_session(session: &AnalysisSession) -> Result<Self, ExportError> {
        session.validate().map_err(ExportError::InvalidSession)?;
        let image_size = match session.base_analysis() {
            BinaryAnalysis::Pe(analysis) => u64::from(analysis.size_of_image),
            _ => return Err(ExportError::UnsupportedAnalysisFormat),
        };
        let graph = session
            .combined_symbol_graph()
            .map_err(ExportError::InvalidSession)?;
        Self::from_symbol_graph(session.base_analysis().identity(), image_size, &graph)
    }

    /// Project a validated single-binary graph with an explicit virtual image
    /// size. `binary.size` remains the exact file size; `image_size` is the RVA
    /// range accepted by debugger symbols.
    pub fn from_symbol_graph(
        binary: &BinaryIdentity,
        image_size: u64,
        graph: &SymbolGraph,
    ) -> Result<Self, ExportError> {
        Self::project_symbol_graph(binary, image_size, graph, None)
    }

    /// Project a graph while retaining exact alias-only name claims outside
    /// primary-name selection.
    ///
    /// `name_selections` is positionally bound to `graph.claims()` and must
    /// contain one entry per claim. `AliasOnly` is valid only for name claims.
    pub fn from_symbol_graph_with_name_selections(
        binary: &BinaryIdentity,
        image_size: u64,
        graph: &SymbolGraph,
        name_selections: &[NameSelection],
    ) -> Result<Self, ExportError> {
        if name_selections.len() != graph.claims().len() {
            return Err(ExportError::NameSelectionCountMismatch {
                expected: graph.claims().len(),
                found: name_selections.len(),
            });
        }
        if let Some((index, _)) = graph.claims().iter().zip(name_selections).enumerate().find(
            |(_, (claim, selection))| {
                matches!(selection, NameSelection::AliasOnly)
                    && !matches!(claim.assertion(), SymbolAssertion::Name { .. })
            },
        ) {
            return Err(ExportError::AliasOnlyNonNameClaim { index });
        }
        Self::project_symbol_graph(binary, image_size, graph, Some(name_selections))
    }

    fn project_symbol_graph(
        binary: &BinaryIdentity,
        image_size: u64,
        graph: &SymbolGraph,
        name_selections: Option<&[NameSelection]>,
    ) -> Result<Self, ExportError> {
        graph.validate().map_err(ExportError::InvalidGraph)?;
        if graph.binaries().len() != 1 {
            return Err(ExportError::UnexpectedBinaryCount {
                count: graph.binaries().len(),
            });
        }
        let graph_binary = graph
            .binaries()
            .values()
            .next()
            .ok_or(ExportError::UnexpectedBinaryCount { count: 0 })?;
        if graph_binary != binary {
            return Err(ExportError::BinaryIdentityMismatch {
                expected: binary.id.clone(),
                found: graph_binary.id.clone(),
            });
        }
        if image_size == 0 {
            return Err(ExportError::ZeroImageSize);
        }
        if binary.image_base.checked_add(image_size).is_none() {
            return Err(ExportError::ImageAddressOverflow);
        }
        validate_binary_text(binary)?;
        if graph.claims().len() > MAX_CLAIMS {
            return Err(ExportError::LimitExceeded {
                resource: "claim",
                limit: MAX_CLAIMS,
            });
        }

        let mut functions = BTreeMap::<u64, AddressAccumulator<'_>>::new();
        let mut globals = BTreeMap::<u64, AddressAccumulator<'_>>::new();
        let mut types = BTreeMap::<String, TypeAccumulator>::new();
        let mut direct_calls = BTreeMap::<DirectCallKey, ExportAttribution>::new();
        let mut thunks = BTreeMap::<u64, ThunkValue>::new();
        let mut strings = BTreeMap::<u64, ExportRecoveredString>::new();
        let mut data_references = BTreeMap::<DataReferenceKey, ExportDataReference>::new();
        let mut entity_count = 0_usize;
        let mut warnings = WarningAccumulator::new();

        for (index, claim) in graph.claims().iter().enumerate() {
            let name_selection =
                name_selections.map_or(NameSelection::PrimaryEligible, |values| values[index]);
            project_claim(
                claim,
                name_selection,
                image_size,
                &mut functions,
                &mut globals,
                &mut types,
                &mut direct_calls,
                &mut thunks,
                &mut strings,
                &mut data_references,
                &mut entity_count,
                &mut warnings,
            )?;
        }

        let unpaired_pointer_calls = direct_calls
            .keys()
            .filter(|key| !direct_call_has_companion(key, &data_references))
            .cloned()
            .collect::<Vec<_>>();
        for key in unpaired_pointer_calls {
            direct_calls.remove(&key);
            warnings.add(
                ProjectionWarningCode::UnsupportedAssertion,
                Some(ExportSubject::Function { rva: key.0 }),
            )?;
        }
        for ((_, _, target), attribution) in &direct_calls {
            if let Some(target_rva) = control_flow_function_rva(target) {
                let target_function = address_entry(&mut functions, target_rva, &mut entity_count)?;
                insert_entry_attribution(
                    &mut target_function.entry_attribution,
                    attribution.clone(),
                );
            }
        }

        let mut functions = functions
            .into_iter()
            .map(|(rva, value)| finish_function(rva, value, &mut warnings))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let mut globals = globals
            .into_iter()
            .map(|(rva, value)| finish_global(rva, value, &mut warnings))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let mut types = types
            .into_iter()
            .filter_map(|(key, value)| finish_type(key, value))
            .collect::<Vec<_>>();
        let direct_calls = direct_calls
            .into_iter()
            .map(
                |((caller_rva, call_site_rva, target), attribution)| ExportDirectCall {
                    caller_rva,
                    call_site_rva,
                    target,
                    attribution,
                },
            )
            .collect::<Vec<_>>();
        let thunks = thunks
            .into_iter()
            .map(|(rva, (target, attribution))| ExportThunk {
                rva,
                target,
                attribution,
            })
            .collect::<Vec<_>>();
        let strings = select_non_overlapping_strings(strings.into_values().collect());
        let mut data_references = data_references.into_values().collect::<Vec<_>>();
        for reference in &mut data_references {
            reference.referenced_string_rva = referenced_string_rva(&strings, reference.target_rva);
        }

        remove_overlapping_function_sizes(&mut functions, &mut warnings)?;
        functions.retain(|value| {
            value.entry_attribution.is_some()
                || value.size.is_some()
                || value.selected_name.is_some()
                || !value.alternate_names.is_empty()
                || !value.prototypes.is_empty()
                || !value.class_memberships.is_empty()
        });

        normalize_selected_names(&mut functions, &mut globals, &mut types, &mut warnings)?;
        warn_address_kind_collisions(&functions, &globals, &mut warnings)?;
        resolve_name_collisions(&mut functions, &mut globals, &mut types, &mut warnings)?;

        let projection = Self {
            schema_version: Self::SCHEMA_VERSION,
            binary: export_binary(binary, image_size)?,
            functions,
            globals,
            types,
            direct_calls,
            thunks,
            strings,
            data_references,
            warnings: warnings.finish(),
        };
        projection.validate()?;
        Ok(projection)
    }
}

#[allow(clippy::too_many_arguments)]
fn project_claim<'claims>(
    claim: &'claims SymbolClaim,
    name_selection: NameSelection,
    image_size: u64,
    functions: &mut BTreeMap<u64, AddressAccumulator<'claims>>,
    globals: &mut BTreeMap<u64, AddressAccumulator<'claims>>,
    types: &mut BTreeMap<String, TypeAccumulator>,
    direct_calls: &mut BTreeMap<DirectCallKey, ExportAttribution>,
    thunks: &mut BTreeMap<u64, ThunkValue>,
    strings: &mut BTreeMap<u64, ExportRecoveredString>,
    data_references: &mut BTreeMap<DataReferenceKey, ExportDataReference>,
    entity_count: &mut usize,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    let subject = export_subject(claim.subject());
    let provenance = match export_provenance(claim.provenance()) {
        Ok(value) => value,
        Err(()) => {
            warnings.add(ProjectionWarningCode::InvalidProvenance, subject)?;
            return Ok(());
        }
    };
    let attribution = ExportAttribution {
        confidence: normalize_confidence(claim.confidence().get()),
        provenance,
    };

    match claim.subject() {
        SymbolSubject::Function { rva, size, .. } => {
            if !valid_range(*rva, *size, image_size) {
                warnings.add(ProjectionWarningCode::AddressOutsideImage, subject)?;
                return Ok(());
            }
            let function_subject = ExportSubject::Function { rva: *rva };
            match claim.assertion() {
                SymbolAssertion::FunctionEntry => {
                    project_function_entry(functions, *rva, *size, attribution, entity_count)
                }
                SymbolAssertion::DirectCall {
                    call_site_rva,
                    target,
                } => project_direct_call(
                    functions,
                    direct_calls,
                    *rva,
                    *size,
                    *call_site_rva,
                    target,
                    attribution,
                    image_size,
                    entity_count,
                    function_subject,
                    warnings,
                ),
                SymbolAssertion::ThunkTarget { target } => project_thunk(
                    functions,
                    thunks,
                    *rva,
                    *size,
                    target,
                    attribution,
                    image_size,
                    entity_count,
                    function_subject,
                    warnings,
                ),
                SymbolAssertion::DataReference {
                    instruction_rva,
                    instruction_size,
                    target_rva,
                } => project_data_reference(
                    functions,
                    data_references,
                    *rva,
                    *size,
                    *instruction_rva,
                    *instruction_size,
                    *target_rva,
                    attribution,
                    image_size,
                    entity_count,
                    function_subject,
                    warnings,
                ),
                _ => {
                    let value = address_entry(functions, *rva, entity_count)?;
                    let represented = project_address_assertion(
                        claim.assertion(),
                        name_selection,
                        *size,
                        attribution.clone(),
                        value,
                        true,
                        function_subject,
                        warnings,
                    )?;
                    if represented {
                        insert_entry_attribution(&mut value.entry_attribution, attribution);
                    }
                    Ok(())
                }
            }
        }
        SymbolSubject::Global { rva, size, .. } => {
            if !valid_range(*rva, *size, image_size) {
                warnings.add(ProjectionWarningCode::AddressOutsideImage, subject)?;
                return Ok(());
            }
            if let SymbolAssertion::StringLiteral { encoding, value } = claim.assertion() {
                return project_recovered_string(
                    strings,
                    *rva,
                    *size,
                    *encoding,
                    value,
                    attribution,
                    image_size,
                    ExportSubject::Global { rva: *rva },
                    warnings,
                );
            }
            let value = address_entry(globals, *rva, entity_count)?;
            let _ = project_address_assertion(
                claim.assertion(),
                name_selection,
                *size,
                attribution,
                value,
                false,
                ExportSubject::Global { rva: *rva },
                warnings,
            )?;
            Ok(())
        }
        SymbolSubject::Type { key, .. } => {
            let type_subject = if valid_text(key, MAX_TYPE_KEY_BYTES) {
                Some(ExportSubject::Type { key: key.clone() })
            } else {
                None
            };
            if !valid_text(key, MAX_TYPE_KEY_BYTES) {
                warnings.add(text_warning(key, MAX_TYPE_KEY_BYTES), None)?;
                return Ok(());
            }
            let value = match types.entry(key.clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    add_entity(entity_count)?;
                    entry.insert(TypeAccumulator::default())
                }
            };
            project_type_assertion(
                claim.assertion(),
                name_selection,
                attribution,
                value,
                type_subject.expect("validated type subject"),
                warnings,
            )
        }
        _ => warnings.add(ProjectionWarningCode::UnsupportedAssertion, subject),
    }
}

fn project_function_entry(
    functions: &mut BTreeMap<u64, AddressAccumulator<'_>>,
    rva: u64,
    subject_size: Option<u64>,
    attribution: ExportAttribution,
    entity_count: &mut usize,
) -> Result<(), ExportError> {
    let value = address_entry(functions, rva, entity_count)?;
    insert_entry_attribution(&mut value.entry_attribution, attribution.clone());
    if let Some(size) = subject_size {
        insert_size(&mut value.sizes, size, attribution);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn project_direct_call(
    functions: &mut BTreeMap<u64, AddressAccumulator<'_>>,
    direct_calls: &mut BTreeMap<DirectCallKey, ExportAttribution>,
    caller_rva: u64,
    subject_size: Option<u64>,
    call_site_rva: u64,
    target: &ControlFlowTarget,
    attribution: ExportAttribution,
    image_size: u64,
    entity_count: &mut usize,
    subject: ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    let Some(target) = export_control_flow_target(target) else {
        warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject))?;
        return Ok(());
    };
    if !valid_range(call_site_rva, None, image_size)
        || !valid_control_flow_target(&target, image_size)
    {
        warnings.add(ProjectionWarningCode::AddressOutsideImage, Some(subject))?;
        return Ok(());
    }

    {
        let caller = address_entry(functions, caller_rva, entity_count)?;
        insert_entry_attribution(&mut caller.entry_attribution, attribution.clone());
        if let Some(size) = subject_size {
            insert_size(&mut caller.sizes, size, attribution.clone());
        }
    }
    insert_direct_call(
        direct_calls,
        (caller_rva, call_site_rva, target),
        attribution,
    )
}

#[allow(clippy::too_many_arguments)]
fn project_thunk(
    functions: &mut BTreeMap<u64, AddressAccumulator<'_>>,
    thunks: &mut BTreeMap<u64, ThunkValue>,
    rva: u64,
    subject_size: Option<u64>,
    target: &ControlFlowTarget,
    attribution: ExportAttribution,
    image_size: u64,
    entity_count: &mut usize,
    subject: ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    let Some(target) = export_control_flow_target(target) else {
        warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject))?;
        return Ok(());
    };
    if !valid_control_flow_target(&target, image_size) {
        warnings.add(ProjectionWarningCode::AddressOutsideImage, Some(subject))?;
        return Ok(());
    }

    {
        let source = address_entry(functions, rva, entity_count)?;
        insert_entry_attribution(&mut source.entry_attribution, attribution.clone());
        if let Some(size) = subject_size {
            insert_size(&mut source.sizes, size, attribution.clone());
        }
    }
    if let Some(target_rva) = control_flow_function_rva(&target) {
        let target_function = address_entry(functions, target_rva, entity_count)?;
        insert_entry_attribution(&mut target_function.entry_attribution, attribution.clone());
    }
    insert_thunk(thunks, rva, target, attribution)
}

#[allow(clippy::too_many_arguments)]
fn project_data_reference(
    functions: &mut BTreeMap<u64, AddressAccumulator<'_>>,
    data_references: &mut BTreeMap<DataReferenceKey, ExportDataReference>,
    caller_rva: u64,
    subject_size: Option<u64>,
    instruction_rva: u64,
    instruction_size: u8,
    target_rva: u64,
    attribution: ExportAttribution,
    image_size: u64,
    entity_count: &mut usize,
    subject: ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    if !(1..=15).contains(&instruction_size)
        || !valid_range(
            instruction_rva,
            Some(u64::from(instruction_size)),
            image_size,
        )
        || !valid_range(target_rva, None, image_size)
    {
        warnings.add(ProjectionWarningCode::AddressOutsideImage, Some(subject))?;
        return Ok(());
    }
    let instruction_end = instruction_rva
        .checked_add(u64::from(instruction_size))
        .expect("validated instruction range cannot overflow");
    let site_outside_caller = instruction_rva < caller_rva
        || subject_size.is_some_and(|size| {
            caller_rva
                .checked_add(size)
                .is_none_or(|caller_end| instruction_end > caller_end)
        });
    if site_outside_caller {
        warnings.add(
            ProjectionWarningCode::AssertionSubjectMismatch,
            Some(subject),
        )?;
        return Ok(());
    }

    let caller = address_entry(functions, caller_rva, entity_count)?;
    insert_entry_attribution(&mut caller.entry_attribution, attribution.clone());
    if let Some(size) = subject_size {
        insert_size(&mut caller.sizes, size, attribution.clone());
    }
    insert_data_reference(
        data_references,
        ExportDataReference {
            caller_rva,
            instruction_rva,
            instruction_size,
            target_rva,
            referenced_string_rva: None,
            attribution,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn project_recovered_string(
    strings: &mut BTreeMap<u64, ExportRecoveredString>,
    rva: u64,
    subject_size: Option<u64>,
    encoding: StringEncoding,
    value: &str,
    attribution: ExportAttribution,
    image_size: u64,
    subject: ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    let Some((encoding, byte_size)) = export_string_shape(encoding, value) else {
        warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject))?;
        return Ok(());
    };
    if value.len() > MAX_RECOVERED_STRING_BYTES
        || usize::try_from(byte_size).map_or(true, |size| size > MAX_RECOVERED_STRING_BYTES)
    {
        warnings.add(ProjectionWarningCode::TextLimitExceeded, Some(subject))?;
        return Ok(());
    }
    if subject_size != Some(byte_size) {
        warnings.add(
            ProjectionWarningCode::AssertionSubjectMismatch,
            Some(subject),
        )?;
        return Ok(());
    }
    if !valid_range(rva, Some(byte_size), image_size) {
        warnings.add(ProjectionWarningCode::AddressOutsideImage, Some(subject))?;
        return Ok(());
    }
    insert_recovered_string(
        strings,
        ExportRecoveredString {
            rva,
            byte_size,
            encoding,
            value: value.to_owned(),
            attribution,
        },
    )
}

fn export_string_shape(
    encoding: StringEncoding,
    value: &str,
) -> Option<(ExportStringEncoding, u64)> {
    match encoding {
        StringEncoding::Ascii => u64::try_from(value.len())
            .ok()?
            .checked_add(1)
            .map(|size| (ExportStringEncoding::Ascii, size)),
        StringEncoding::Utf16Le => u64::try_from(value.encode_utf16().count())
            .ok()?
            .checked_mul(2)?
            .checked_add(2)
            .map(|size| (ExportStringEncoding::Utf16Le, size)),
        _ => None,
    }
}

fn export_control_flow_target(target: &ControlFlowTarget) -> Option<ExportControlFlowTarget> {
    match target {
        ControlFlowTarget::Function { rva } => {
            Some(ExportControlFlowTarget::Function { rva: *rva })
        }
        ControlFlowTarget::ImportIat { iat_rva } => {
            Some(ExportControlFlowTarget::ImportIat { iat_rva: *iat_rva })
        }
        ControlFlowTarget::FunctionPointer { slot_rva, rva } => {
            Some(ExportControlFlowTarget::FunctionPointer {
                slot_rva: *slot_rva,
                rva: *rva,
            })
        }
        _ => None,
    }
}

fn valid_control_flow_target(target: &ExportControlFlowTarget, image_size: u64) -> bool {
    match target {
        ExportControlFlowTarget::Function { rva } => valid_range(*rva, None, image_size),
        ExportControlFlowTarget::ImportIat { iat_rva } => valid_range(*iat_rva, None, image_size),
        ExportControlFlowTarget::FunctionPointer { slot_rva, rva } => {
            valid_range(*slot_rva, Some(8), image_size) && valid_range(*rva, None, image_size)
        }
    }
}

fn direct_call_has_companion(
    key: &DirectCallKey,
    data_references: &BTreeMap<DataReferenceKey, ExportDataReference>,
) -> bool {
    let (caller_rva, call_site_rva, target) = key;
    let ExportControlFlowTarget::FunctionPointer { slot_rva, .. } = target else {
        return true;
    };
    data_references
        .get(&(*caller_rva, *call_site_rva))
        .is_some_and(|reference| {
            matches!(reference.instruction_size, 6 | 7) && reference.target_rva == *slot_rva
        })
}

fn control_flow_function_rva(target: &ExportControlFlowTarget) -> Option<u64> {
    match target {
        ExportControlFlowTarget::Function { rva }
        | ExportControlFlowTarget::FunctionPointer { rva, .. } => Some(*rva),
        ExportControlFlowTarget::ImportIat { .. } => None,
    }
}

fn project_address_assertion<'claims>(
    assertion: &'claims SymbolAssertion,
    name_selection: NameSelection,
    subject_size: Option<u64>,
    attribution: ExportAttribution,
    value: &mut AddressAccumulator<'claims>,
    is_function: bool,
    subject: ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<bool, ExportError> {
    let represented = match assertion {
        SymbolAssertion::Name { name } => {
            let represented = valid_text(name, MAX_NAME_BYTES);
            insert_name(
                &mut value.names,
                name,
                attribution.clone(),
                name_selection,
                &subject,
                warnings,
            )?;
            if let Some(size) = subject_size {
                insert_size(&mut value.sizes, size, attribution);
            }
            represented
        }
        SymbolAssertion::FunctionPrototype { declaration } if is_function => {
            let represented = valid_text(declaration, MAX_DECLARATION_BYTES);
            insert_text(
                &mut value.declarations,
                declaration,
                MAX_DECLARATION_BYTES,
                attribution.clone(),
                MAX_DECLARATIONS_PER_ENTITY,
                "prototype",
                &subject,
                warnings,
            )?;
            if let Some(size) = subject_size {
                insert_size(&mut value.sizes, size, attribution);
            }
            represented
        }
        SymbolAssertion::FunctionBoundary { size } if is_function => {
            if subject_size.is_some_and(|subject_size| subject_size != *size) {
                warnings.add(
                    ProjectionWarningCode::AssertionSubjectMismatch,
                    Some(subject),
                )?;
                false
            } else {
                insert_size(&mut value.sizes, *size, attribution);
                true
            }
        }
        SymbolAssertion::ClassMembership { class_name } if is_function => {
            let represented = valid_text(class_name, MAX_NAME_BYTES);
            insert_class_membership(
                &mut value.class_memberships,
                &mut value.distinct_class_memberships,
                class_name,
                attribution.clone(),
                &subject,
                warnings,
            )?;
            if let Some(size) = subject_size {
                insert_size(&mut value.sizes, size, attribution);
            }
            represented
        }
        SymbolAssertion::FunctionPrototype { .. }
        | SymbolAssertion::FunctionBoundary { .. }
        | SymbolAssertion::ClassMembership { .. }
        | SymbolAssertion::FunctionEntry
        | SymbolAssertion::DirectCall { .. }
        | SymbolAssertion::ThunkTarget { .. }
        | SymbolAssertion::StringLiteral { .. }
        | SymbolAssertion::DataReference { .. }
        | SymbolAssertion::TypeDefinition { .. } => {
            warnings.add(
                ProjectionWarningCode::AssertionSubjectMismatch,
                Some(subject),
            )?;
            false
        }
        SymbolAssertion::Comment { .. } => {
            warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject))?;
            false
        }
        _ => {
            warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject))?;
            false
        }
    };
    Ok(represented)
}

fn project_type_assertion(
    assertion: &SymbolAssertion,
    name_selection: NameSelection,
    attribution: ExportAttribution,
    value: &mut TypeAccumulator,
    subject: ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    match assertion {
        SymbolAssertion::Name { name } => insert_name(
            &mut value.names,
            name,
            attribution,
            name_selection,
            &subject,
            warnings,
        ),
        SymbolAssertion::TypeDefinition { declaration } => insert_text(
            &mut value.definitions,
            declaration,
            MAX_DECLARATION_BYTES,
            attribution,
            MAX_DECLARATIONS_PER_ENTITY,
            "type definition",
            &subject,
            warnings,
        ),
        SymbolAssertion::FunctionPrototype { .. }
        | SymbolAssertion::FunctionBoundary { .. }
        | SymbolAssertion::ClassMembership { .. }
        | SymbolAssertion::FunctionEntry
        | SymbolAssertion::DirectCall { .. }
        | SymbolAssertion::ThunkTarget { .. }
        | SymbolAssertion::StringLiteral { .. }
        | SymbolAssertion::DataReference { .. } => warnings.add(
            ProjectionWarningCode::AssertionSubjectMismatch,
            Some(subject),
        ),
        SymbolAssertion::Comment { .. } => {
            warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject))
        }
        _ => warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject)),
    }
}

fn insert_name(
    values: &mut NameAccumulator,
    text: &str,
    attribution: ExportAttribution,
    selection: NameSelection,
    subject: &ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    if !valid_text(text, MAX_NAME_BYTES) {
        warnings.add(text_warning(text, MAX_NAME_BYTES), Some(subject.clone()))?;
        return Ok(());
    }
    if !values.values.contains_key(text) && values.values.len() == MAX_NAMES_PER_ENTITY {
        return Err(ExportError::LimitExceeded {
            resource: "name candidate",
            limit: MAX_NAMES_PER_ENTITY,
        });
    }
    let candidate = AttributedText {
        text: text.to_owned(),
        attribution,
    };
    let candidates = values.values.entry(text.to_owned()).or_default();
    let current = match selection {
        NameSelection::PrimaryEligible => &mut candidates.primary_eligible,
        NameSelection::AliasOnly => &mut candidates.alias_only,
    };
    if current
        .as_ref()
        .is_none_or(|current| candidate_order(&candidate, current).is_lt())
    {
        *current = Some(candidate);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_text(
    values: &mut BTreeMap<String, AttributedText>,
    text: &str,
    max_bytes: usize,
    attribution: ExportAttribution,
    limit: usize,
    resource: &'static str,
    subject: &ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    if !valid_text(text, max_bytes) {
        warnings.add(text_warning(text, max_bytes), Some(subject.clone()))?;
        return Ok(());
    }
    let candidate = AttributedText {
        text: text.to_owned(),
        attribution,
    };
    if let Some(current) = values.get_mut(text) {
        if candidate_order(&candidate, current).is_lt() {
            *current = candidate;
        }
        return Ok(());
    }
    if values.len() == limit {
        return Err(ExportError::LimitExceeded { resource, limit });
    }
    values.insert(text.to_owned(), candidate);
    Ok(())
}

fn insert_class_membership<'claims>(
    values: &mut BTreeMap<String, AttributedText>,
    distinct_values: &mut BTreeSet<&'claims str>,
    text: &'claims str,
    attribution: ExportAttribution,
    subject: &ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    if !valid_text(text, MAX_NAME_BYTES) {
        warnings.add(text_warning(text, MAX_NAME_BYTES), Some(subject.clone()))?;
        return Ok(());
    }
    distinct_values.insert(text);
    let candidate = AttributedText {
        text: text.to_owned(),
        attribution,
    };
    if let Some(current) = values.get_mut(text) {
        if candidate_order(&candidate, current).is_lt() {
            *current = candidate;
        }
        return Ok(());
    }
    if values.len() < MAX_CLASS_MEMBERSHIPS_PER_FUNCTION {
        values.insert(text.to_owned(), candidate);
        return Ok(());
    }

    // Keep the strongest bounded set independent of claim arrival order.
    // Omission accounting is deferred until finalization so repeated claims
    // for an overflowed class cannot make warning counts order-dependent.
    let worst_key = values
        .iter()
        .max_by(|left, right| candidate_order(left.1, right.1))
        .map(|(key, _)| key.clone())
        .expect("a full class membership map is non-empty");
    if candidate_order(
        &candidate,
        values
            .get(&worst_key)
            .expect("selected class membership remains present"),
    )
    .is_lt()
    {
        values.remove(&worst_key);
        values.insert(text.to_owned(), candidate);
    }
    Ok(())
}

fn insert_size(
    values: &mut BTreeMap<u64, ExportAttribution>,
    size: u64,
    attribution: ExportAttribution,
) {
    match values.get_mut(&size) {
        Some(current) if attribution_order(&attribution, current).is_lt() => {
            *current = attribution;
        }
        Some(_) => {}
        None => {
            values.insert(size, attribution);
        }
    }
}

fn insert_entry_attribution(current: &mut Option<ExportAttribution>, candidate: ExportAttribution) {
    if current
        .as_ref()
        .is_none_or(|current| attribution_order(&candidate, current).is_lt())
    {
        *current = Some(candidate);
    }
}

fn insert_direct_call(
    values: &mut BTreeMap<DirectCallKey, ExportAttribution>,
    key: DirectCallKey,
    attribution: ExportAttribution,
) -> Result<(), ExportError> {
    if let Some(current) = values.get_mut(&key) {
        if attribution_order(&attribution, current).is_lt() {
            *current = attribution;
        }
        return Ok(());
    }
    if values.len() == MAX_DIRECT_CALLS {
        return Err(ExportError::LimitExceeded {
            resource: "direct call",
            limit: MAX_DIRECT_CALLS,
        });
    }
    values.insert(key, attribution);
    Ok(())
}

fn insert_thunk(
    values: &mut BTreeMap<u64, ThunkValue>,
    rva: u64,
    target: ExportControlFlowTarget,
    attribution: ExportAttribution,
) -> Result<(), ExportError> {
    if let Some((current_target, current_attribution)) = values.get_mut(&rva) {
        let candidate_order = attribution_order(&attribution, current_attribution)
            .then_with(|| target.cmp(current_target));
        if candidate_order.is_lt() {
            *current_target = target;
            *current_attribution = attribution;
        }
        return Ok(());
    }
    if values.len() == MAX_THUNKS {
        return Err(ExportError::LimitExceeded {
            resource: "thunk",
            limit: MAX_THUNKS,
        });
    }
    values.insert(rva, (target, attribution));
    Ok(())
}

fn insert_recovered_string(
    values: &mut BTreeMap<u64, ExportRecoveredString>,
    candidate: ExportRecoveredString,
) -> Result<(), ExportError> {
    if let Some(current) = values.get_mut(&candidate.rva) {
        let candidate_order = attribution_order(&candidate.attribution, &current.attribution)
            .then_with(|| candidate.encoding.cmp(&current.encoding))
            .then_with(|| candidate.value.cmp(&current.value))
            .then_with(|| candidate.byte_size.cmp(&current.byte_size));
        if candidate_order.is_lt() {
            *current = candidate;
        }
        return Ok(());
    }
    if values.len() == MAX_RECOVERED_STRINGS {
        return Err(ExportError::LimitExceeded {
            resource: "recovered string",
            limit: MAX_RECOVERED_STRINGS,
        });
    }
    values.insert(candidate.rva, candidate);
    Ok(())
}

fn insert_data_reference(
    values: &mut BTreeMap<DataReferenceKey, ExportDataReference>,
    candidate: ExportDataReference,
) -> Result<(), ExportError> {
    let key = (candidate.caller_rva, candidate.instruction_rva);
    if let Some(current) = values.get_mut(&key) {
        let candidate_order = attribution_order(&candidate.attribution, &current.attribution)
            .then_with(|| candidate.instruction_size.cmp(&current.instruction_size))
            .then_with(|| candidate.target_rva.cmp(&current.target_rva));
        if candidate_order.is_lt() {
            *current = candidate;
        }
        return Ok(());
    }
    if values.len() == MAX_DATA_REFERENCES {
        return Err(ExportError::LimitExceeded {
            resource: "data reference",
            limit: MAX_DATA_REFERENCES,
        });
    }
    values.insert(key, candidate);
    Ok(())
}

fn select_non_overlapping_strings(
    mut candidates: Vec<ExportRecoveredString>,
) -> Vec<ExportRecoveredString> {
    candidates.sort_by(|left, right| {
        attribution_order(&left.attribution, &right.attribution)
            .then_with(|| left.rva.cmp(&right.rva))
            .then_with(|| left.byte_size.cmp(&right.byte_size))
            .then_with(|| left.encoding.cmp(&right.encoding))
            .then_with(|| left.value.cmp(&right.value))
    });
    let mut retained = BTreeMap::<u64, (u64, ExportRecoveredString)>::new();
    for candidate in candidates {
        let Some(end) = candidate.rva.checked_add(candidate.byte_size) else {
            continue;
        };
        let overlaps_previous = retained
            .range(..=candidate.rva)
            .next_back()
            .is_some_and(|(_, (retained_end, _))| *retained_end > candidate.rva);
        let overlaps_next = retained
            .range(candidate.rva..)
            .next()
            .is_some_and(|(retained_rva, _)| *retained_rva < end);
        if !overlaps_previous && !overlaps_next {
            retained.insert(candidate.rva, (end, candidate));
        }
    }
    retained
        .into_values()
        .map(|(_, candidate)| candidate)
        .collect()
}

fn finish_function(
    rva: u64,
    value: AddressAccumulator<'_>,
    warnings: &mut WarningAccumulator,
) -> Result<Option<ExportFunction>, ExportError> {
    let (size, size_attribution) =
        finish_size(&value.sizes, ExportSubject::Function { rva }, warnings)?;
    let entry_attribution = value.entry_attribution;
    let (selected_name, alternate_names) = finish_names(value.names);
    let prototypes = finish_texts(value.declarations);
    let distinct_class_membership_count = value.distinct_class_memberships.len();
    let class_memberships = finish_texts(value.class_memberships);
    let omitted_class_memberships = distinct_class_membership_count
        .checked_sub(class_memberships.len())
        .expect("retained class memberships are a subset of distinct claims");
    warnings.add_occurrences(
        ProjectionWarningCode::ClassMembershipLimitExceeded,
        Some(ExportSubject::Function { rva }),
        u64::try_from(omitted_class_memberships)
            .expect("class membership count is bounded by the claim limit"),
    )?;
    if entry_attribution.is_none()
        && selected_name.is_none()
        && alternate_names.is_empty()
        && size.is_none()
        && prototypes.is_empty()
        && class_memberships.is_empty()
    {
        return Ok(None);
    }
    Ok(Some(ExportFunction {
        rva,
        entry_attribution,
        size,
        size_attribution,
        selected_name,
        alternate_names,
        prototypes,
        class_memberships,
    }))
}

fn finish_global(
    rva: u64,
    value: AddressAccumulator<'_>,
    warnings: &mut WarningAccumulator,
) -> Result<Option<ExportGlobal>, ExportError> {
    let (size, size_attribution) =
        finish_size(&value.sizes, ExportSubject::Global { rva }, warnings)?;
    let (selected_name, alternate_names) = finish_names(value.names);
    if selected_name.is_none() && alternate_names.is_empty() && size.is_none() {
        return Ok(None);
    }
    Ok(Some(ExportGlobal {
        rva,
        size,
        size_attribution,
        selected_name,
        alternate_names,
    }))
}

fn finish_type(key: String, value: TypeAccumulator) -> Option<ExportType> {
    let (selected_name, alternate_names) = finish_names(value.names);
    let definitions = finish_texts(value.definitions);
    if selected_name.is_none() && alternate_names.is_empty() && definitions.is_empty() {
        return None;
    }
    Some(ExportType {
        key,
        selected_name,
        alternate_names,
        definitions,
    })
}

fn finish_names(values: NameAccumulator) -> (Option<ExportName>, Vec<AttributedText>) {
    let mut eligible = values
        .values
        .values()
        .filter_map(|candidates| candidates.primary_eligible.clone())
        .collect::<Vec<_>>();
    eligible.sort_by(candidate_order);
    let selected = (!eligible.is_empty()).then(|| eligible.remove(0));
    let selected_text = selected.as_ref().map(|value| value.text.as_str());

    let mut alternates = BTreeMap::<String, AttributedText>::new();
    for (text, candidates) in values.values {
        if selected_text == Some(text.as_str()) {
            continue;
        }
        for candidate in [candidates.primary_eligible, candidates.alias_only]
            .into_iter()
            .flatten()
        {
            if alternates
                .get(&text)
                .is_none_or(|current| candidate_order(&candidate, current).is_lt())
            {
                alternates.insert(text.clone(), candidate);
            }
        }
    }
    let alternates = finish_texts(alternates);
    let selected = selected.map(|source| ExportName {
        output_name: source.text.clone(),
        source,
    });
    (selected, alternates)
}

fn finish_texts(values: BTreeMap<String, AttributedText>) -> Vec<AttributedText> {
    let mut values = values.into_values().collect::<Vec<_>>();
    values.sort_by(candidate_order);
    values
}

fn finish_size(
    sizes: &BTreeMap<u64, ExportAttribution>,
    subject: ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(Option<u64>, Option<ExportAttribution>), ExportError> {
    let highest_authority = sizes
        .values()
        .map(|value| producer_authority(&value.provenance))
        .max();
    let highest_sizes = highest_authority.map_or(0, |authority| {
        sizes
            .values()
            .filter(|value| producer_authority(&value.provenance) == authority)
            .count()
    });
    if highest_sizes > 1 {
        warnings.add(ProjectionWarningCode::AmbiguousSize, Some(subject))?;
        return Ok((None, None));
    }
    let selected = sizes
        .iter()
        .filter(|(_, value)| {
            highest_authority
                .is_some_and(|authority| producer_authority(&value.provenance) == authority)
        })
        .min_by(|(left_size, left), (right_size, right)| {
            attribution_order(left, right).then_with(|| left_size.cmp(right_size))
        })
        .map(|(size, attribution)| (*size, attribution.clone()));
    if sizes.len() > 1 {
        warnings.add(ProjectionWarningCode::ConflictingSize, Some(subject))?;
    }
    Ok(selected.map_or((None, None), |(size, attribution)| {
        (Some(size), Some(attribution))
    }))
}

fn resolve_name_collisions(
    functions: &mut [ExportFunction],
    globals: &mut [ExportGlobal],
    types: &mut [ExportType],
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    let mut selections = Vec::<(ExportSubject, ExportName)>::new();
    selections.extend(functions.iter().filter_map(|value| {
        value
            .selected_name
            .as_ref()
            .map(|name| (ExportSubject::Function { rva: value.rva }, name.clone()))
    }));
    selections.extend(globals.iter().filter_map(|value| {
        value
            .selected_name
            .as_ref()
            .map(|name| (ExportSubject::Global { rva: value.rva }, name.clone()))
    }));
    selections.extend(types.iter().filter_map(|value| {
        value.selected_name.as_ref().map(|name| {
            (
                ExportSubject::Type {
                    key: value.key.clone(),
                },
                name.clone(),
            )
        })
    }));
    selections.sort_by(|(left_subject, left), (right_subject, right)| {
        candidate_order(&left.source, &right.source).then_with(|| left_subject.cmp(right_subject))
    });

    let mut used = BTreeMap::<String, ExportSubject>::new();
    let mut resolved = BTreeMap::<ExportSubject, String>::new();
    for (subject, candidate) in selections {
        let mut output = candidate.output_name;
        if used.contains_key(&output) {
            output = collision_name(&output, &subject, &used);
            warnings.add(ProjectionWarningCode::NameCollision, Some(subject.clone()))?;
        }
        used.insert(output.clone(), subject.clone());
        resolved.insert(subject, output);
    }

    for value in functions {
        if let Some(name) = &mut value.selected_name {
            name.output_name = resolved
                .remove(&ExportSubject::Function { rva: value.rva })
                .expect("every selected function name is resolved");
        }
    }
    for value in globals {
        if let Some(name) = &mut value.selected_name {
            name.output_name = resolved
                .remove(&ExportSubject::Global { rva: value.rva })
                .expect("every selected global name is resolved");
        }
    }
    for value in types {
        if let Some(name) = &mut value.selected_name {
            name.output_name = resolved
                .remove(&ExportSubject::Type {
                    key: value.key.clone(),
                })
                .expect("every selected type name is resolved");
        }
    }
    debug_assert!(resolved.is_empty());
    Ok(())
}

fn normalize_selected_names(
    functions: &mut [ExportFunction],
    globals: &mut [ExportGlobal],
    types: &mut [ExportType],
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    for value in functions {
        let ambiguous = has_ambiguous_name(&value.selected_name, &value.alternate_names);
        normalize_selected_name(
            value.selected_name.as_mut(),
            ExportSubject::Function { rva: value.rva },
            ambiguous,
            warnings,
        )?;
    }
    for value in globals {
        let ambiguous = has_ambiguous_name(&value.selected_name, &value.alternate_names);
        normalize_selected_name(
            value.selected_name.as_mut(),
            ExportSubject::Global { rva: value.rva },
            ambiguous,
            warnings,
        )?;
    }
    for value in types {
        let ambiguous = has_ambiguous_name(&value.selected_name, &value.alternate_names);
        normalize_selected_name(
            value.selected_name.as_mut(),
            ExportSubject::Type {
                key: value.key.clone(),
            },
            ambiguous,
            warnings,
        )?;
    }
    Ok(())
}

fn normalize_selected_name(
    name: Option<&mut ExportName>,
    subject: ExportSubject,
    ambiguous: bool,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    let Some(name) = name else {
        return Ok(());
    };
    let output_name = portable_output_name(&name.source.text);
    if ambiguous {
        warnings.add(ProjectionWarningCode::AmbiguousName, Some(subject.clone()))?;
    }
    if output_name != name.source.text {
        warnings.add(ProjectionWarningCode::NameRewritten, Some(subject))?;
    }
    name.output_name = output_name;
    Ok(())
}

fn has_ambiguous_name(selected: &Option<ExportName>, alternates: &[AttributedText]) -> bool {
    let Some(selected) = selected else {
        return false;
    };
    alternates.iter().any(|alternate| {
        producer_authority(&alternate.attribution.provenance)
            == producer_authority(&selected.source.attribution.provenance)
            && alternate
                .attribution
                .confidence
                .total_cmp(&selected.source.attribution.confidence)
                .is_eq()
    })
}

fn warn_address_kind_collisions(
    functions: &[ExportFunction],
    globals: &[ExportGlobal],
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    let mut function_index = 0_usize;
    let mut global_index = 0_usize;
    while function_index < functions.len() && global_index < globals.len() {
        match functions[function_index]
            .rva
            .cmp(&globals[global_index].rva)
        {
            Ordering::Less => function_index += 1,
            Ordering::Greater => global_index += 1,
            Ordering::Equal => {
                warnings.add(
                    ProjectionWarningCode::AddressKindCollision,
                    Some(ExportSubject::Global {
                        rva: globals[global_index].rva,
                    }),
                )?;
                function_index += 1;
                global_index += 1;
            }
        }
    }
    Ok(())
}

fn portable_output_name(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        if character == ':' && characters.peek() == Some(&':') {
            characters.next();
            output.push_str("__");
        } else if character.is_ascii_alphanumeric() || character == '_' {
            output.push(character);
        } else if character.is_ascii() {
            write!(output, "_x{:02x}_", u32::from(character))
                .expect("writing to a String cannot fail");
        } else {
            write!(output, "_u{:x}_", u32::from(character))
                .expect("writing to a String cannot fail");
        }
    }
    if output.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        output.insert_str(0, "rs_");
    }
    if output.len() > MAX_OUTPUT_NAME_BYTES {
        let suffix = format!("__rs_h_{:016x}", stable_hash(source.as_bytes()));
        output.truncate(MAX_OUTPUT_NAME_BYTES - suffix.len());
        output.push_str(&suffix);
    }
    output
}

fn remove_overlapping_function_sizes(
    functions: &mut [ExportFunction],
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    let mut candidates = functions
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            Some((
                index,
                value.rva,
                value.size?,
                value.size_attribution.as_ref()?.clone(),
            ))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        attribution_order(&left.3, &right.3)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });

    let mut accepted = BTreeMap::<u64, (u64, usize)>::new();
    for (index, rva, size, _) in candidates {
        let end = rva
            .checked_add(size)
            .expect("validated function range cannot overflow");
        let overlaps_previous = accepted
            .range(..=rva)
            .next_back()
            .is_some_and(|(_, (accepted_end, _))| *accepted_end > rva);
        let overlaps_next = accepted
            .range(rva..)
            .next()
            .is_some_and(|(accepted_rva, _)| *accepted_rva < end);
        if overlaps_previous || overlaps_next {
            functions[index].size = None;
            functions[index].size_attribution = None;
            warnings.add(
                ProjectionWarningCode::OverlappingFunctionRange,
                Some(ExportSubject::Function { rva }),
            )?;
        } else {
            accepted.insert(rva, (end, index));
        }
    }
    Ok(())
}

fn collision_name(
    source: &str,
    subject: &ExportSubject,
    used: &BTreeMap<String, ExportSubject>,
) -> String {
    let stem = match subject {
        ExportSubject::Function { rva } => format!("__rs_f_{rva:016x}"),
        ExportSubject::Global { rva } => format!("__rs_g_{rva:016x}"),
        ExportSubject::Type { key } => format!("__rs_t_{:016x}", stable_hash(key.as_bytes())),
    };
    let mut ordinal = 1_u64;
    loop {
        let suffix = if ordinal == 1 {
            stem.clone()
        } else {
            format!("{stem}_{ordinal}")
        };
        let prefix = utf8_prefix(source, MAX_OUTPUT_NAME_BYTES.saturating_sub(suffix.len()));
        let candidate = format!("{prefix}{suffix}");
        if !used.contains_key(&candidate) {
            return candidate;
        }
        ordinal = ordinal.saturating_add(1);
    }
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn utf8_prefix(value: &str, max_bytes: usize) -> &str {
    let mut end = value.len().min(max_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn address_entry<'map, 'claims>(
    values: &'map mut BTreeMap<u64, AddressAccumulator<'claims>>,
    rva: u64,
    entity_count: &mut usize,
) -> Result<&'map mut AddressAccumulator<'claims>, ExportError> {
    match values.entry(rva) {
        Entry::Occupied(entry) => Ok(entry.into_mut()),
        Entry::Vacant(entry) => {
            add_entity(entity_count)?;
            Ok(entry.insert(AddressAccumulator::default()))
        }
    }
}

fn add_entity(count: &mut usize) -> Result<(), ExportError> {
    if *count == MAX_ENTITIES {
        return Err(ExportError::LimitExceeded {
            resource: "entity",
            limit: MAX_ENTITIES,
        });
    }
    *count += 1;
    Ok(())
}

fn export_subject(subject: &SymbolSubject) -> Option<ExportSubject> {
    match subject {
        SymbolSubject::Function { rva, .. } => Some(ExportSubject::Function { rva: *rva }),
        SymbolSubject::Global { rva, .. } => Some(ExportSubject::Global { rva: *rva }),
        SymbolSubject::Type { key, .. } if valid_text(key, MAX_TYPE_KEY_BYTES) => {
            Some(ExportSubject::Type { key: key.clone() })
        }
        SymbolSubject::Type { .. } => None,
        _ => None,
    }
}

fn export_provenance(value: &ClaimProvenance) -> Result<ExportProvenance, ()> {
    let producer = match &value.producer {
        ClaimProducer::Core { component, version } => ExportProducer::Core {
            component: component.clone(),
            version: version.clone(),
        },
        ClaimProducer::Plugin { id, version } => ExportProducer::Plugin {
            id: id.as_str().to_owned(),
            version: version.clone(),
        },
        ClaimProducer::User { reviewer } => ExportProducer::User {
            reviewer: reviewer.clone(),
        },
        _ => return Err(()),
    };
    let result = ExportProvenance {
        producer,
        method: value.method.clone(),
        run_id: value.run_id.clone(),
    };
    result.validate().map_err(|_| ())?;
    Ok(result)
}

fn export_binary(binary: &BinaryIdentity, image_size: u64) -> Result<ExportBinary, ExportError> {
    Ok(ExportBinary {
        id: binary.id.clone(),
        file_size: binary.size,
        format: match &binary.format {
            BinaryFormat::Pe => ExportBinaryFormat::Pe,
            BinaryFormat::Elf => ExportBinaryFormat::Elf,
            BinaryFormat::MachO => ExportBinaryFormat::MachO,
            BinaryFormat::Wasm => ExportBinaryFormat::Wasm,
            BinaryFormat::Other(value) => ExportBinaryFormat::Other(value.clone()),
            _ => return Err(ExportError::UnsupportedBinaryFormat),
        },
        architecture: binary.architecture.clone(),
        image_base: binary.image_base,
        image_size,
    })
}

fn validate_binary_text(binary: &BinaryIdentity) -> Result<(), ExportError> {
    require_text(
        &binary.architecture,
        MAX_ARCHITECTURE_BYTES,
        "binary.architecture",
    )
    .map_err(|_| ExportError::InvalidBinaryText {
        field: "architecture",
    })?;
    if let BinaryFormat::Other(value) = &binary.format {
        require_text(value, MAX_ARCHITECTURE_BYTES, "binary.format").map_err(|_| {
            ExportError::InvalidBinaryText {
                field: "format.other",
            }
        })?;
    }
    Ok(())
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    require_text(value, max_bytes, "claim.text").is_ok()
}

fn text_warning(value: &str, max_bytes: usize) -> ProjectionWarningCode {
    if value.len() > max_bytes {
        ProjectionWarningCode::TextLimitExceeded
    } else {
        ProjectionWarningCode::InvalidText
    }
}

fn valid_range(rva: u64, size: Option<u64>, image_size: u64) -> bool {
    let span = size.unwrap_or(1);
    span != 0 && rva < image_size && rva.checked_add(span).is_some_and(|end| end <= image_size)
}

fn attribution_order(left: &ExportAttribution, right: &ExportAttribution) -> Ordering {
    producer_authority(&right.provenance)
        .cmp(&producer_authority(&left.provenance))
        .then_with(|| right.confidence.total_cmp(&left.confidence))
        .then_with(|| left.provenance.cmp(&right.provenance))
}

fn normalize_confidence(value: f64) -> f64 {
    if value == 0.0 { 0.0 } else { value }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_prefix_never_splits_a_scalar_value() {
        assert_eq!(utf8_prefix("abécd", 3), "ab");
        assert_eq!(utf8_prefix("abécd", 4), "abé");
    }

    #[test]
    fn collision_names_are_bounded_and_deterministic_for_utf8_input() {
        let source = "λ".repeat(MAX_NAME_BYTES / 2);
        let subject = ExportSubject::Type {
            key: "type.long-name".to_owned(),
        };
        let mut used = BTreeMap::new();
        used.insert(source.clone(), ExportSubject::Function { rva: 1 });

        let first = collision_name(&source, &subject, &used);
        let second = collision_name(&source, &subject, &used);
        assert_eq!(first, second);
        assert!(first.len() <= MAX_NAME_BYTES);
        assert!(first.is_char_boundary(first.len()));
        assert!(first.contains("__rs_t_"));
    }

    #[test]
    fn stable_hash_does_not_depend_on_process_randomization() {
        assert_eq!(stable_hash(b"type.packet"), stable_hash(b"type.packet"));
        assert_ne!(stable_hash(b"type.packet"), stable_hash(b"type.other"));
    }
}
