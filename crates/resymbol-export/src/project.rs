use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    fmt::Write as _,
};

use resymbol_analysis::{AnalysisSession, BinaryAnalysis};
use resymbol_core::{
    BinaryFormat, BinaryIdentity, ClaimProducer, ClaimProvenance, SymbolAssertion, SymbolClaim,
    SymbolGraph, SymbolSubject,
};

use crate::{
    AttributedText, ExportAttribution, ExportBinary, ExportBinaryFormat, ExportError,
    ExportFunction, ExportGlobal, ExportName, ExportProducer, ExportProjection, ExportProvenance,
    ExportSubject, ExportType, MAX_CLASS_MEMBERSHIPS_PER_FUNCTION, MAX_DECLARATION_BYTES,
    MAX_NAME_BYTES, MAX_OUTPUT_NAME_BYTES, MAX_TYPE_KEY_BYTES, ProjectionWarning,
    ProjectionWarningCode,
    model::{
        MAX_ARCHITECTURE_BYTES, MAX_CLAIMS, MAX_DECLARATIONS_PER_ENTITY, MAX_ENTITIES,
        MAX_NAMES_PER_ENTITY, MAX_WARNINGS, candidate_order, producer_authority, require_text,
    },
};

#[derive(Debug, Default)]
struct AddressAccumulator<'claims> {
    names: BTreeMap<String, AttributedText>,
    declarations: BTreeMap<String, AttributedText>,
    class_memberships: BTreeMap<String, AttributedText>,
    distinct_class_memberships: BTreeSet<&'claims str>,
    sizes: BTreeMap<u64, ExportAttribution>,
}

#[derive(Debug, Default)]
struct TypeAccumulator {
    names: BTreeMap<String, AttributedText>,
    definitions: BTreeMap<String, AttributedText>,
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
        let mut entity_count = 0_usize;
        let mut warnings = WarningAccumulator::new();

        for claim in graph.claims() {
            project_claim(
                claim,
                image_size,
                &mut functions,
                &mut globals,
                &mut types,
                &mut entity_count,
                &mut warnings,
            )?;
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

        remove_overlapping_function_sizes(&mut functions, &mut warnings)?;
        functions.retain(|value| {
            value.size.is_some()
                || value.selected_name.is_some()
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
            warnings: warnings.finish(),
        };
        projection.validate()?;
        Ok(projection)
    }
}

#[allow(clippy::too_many_arguments)]
fn project_claim<'claims>(
    claim: &'claims SymbolClaim,
    image_size: u64,
    functions: &mut BTreeMap<u64, AddressAccumulator<'claims>>,
    globals: &mut BTreeMap<u64, AddressAccumulator<'claims>>,
    types: &mut BTreeMap<String, TypeAccumulator>,
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
            let value = address_entry(functions, *rva, entity_count)?;
            project_address_assertion(
                claim.assertion(),
                *size,
                attribution,
                value,
                true,
                ExportSubject::Function { rva: *rva },
                warnings,
            )
        }
        SymbolSubject::Global { rva, size, .. } => {
            if !valid_range(*rva, *size, image_size) {
                warnings.add(ProjectionWarningCode::AddressOutsideImage, subject)?;
                return Ok(());
            }
            let value = address_entry(globals, *rva, entity_count)?;
            project_address_assertion(
                claim.assertion(),
                *size,
                attribution,
                value,
                false,
                ExportSubject::Global { rva: *rva },
                warnings,
            )
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
                attribution,
                value,
                type_subject.expect("validated type subject"),
                warnings,
            )
        }
        _ => warnings.add(ProjectionWarningCode::UnsupportedAssertion, subject),
    }
}

fn project_address_assertion<'claims>(
    assertion: &'claims SymbolAssertion,
    subject_size: Option<u64>,
    attribution: ExportAttribution,
    value: &mut AddressAccumulator<'claims>,
    is_function: bool,
    subject: ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    match assertion {
        SymbolAssertion::Name { name } => {
            insert_text(
                &mut value.names,
                name,
                MAX_NAME_BYTES,
                attribution.clone(),
                MAX_NAMES_PER_ENTITY,
                "name candidate",
                &subject,
                warnings,
            )?;
            if let Some(size) = subject_size {
                insert_size(&mut value.sizes, size, attribution);
            }
        }
        SymbolAssertion::FunctionPrototype { declaration } if is_function => {
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
        }
        SymbolAssertion::FunctionBoundary { size } if is_function => {
            if subject_size.is_some_and(|subject_size| subject_size != *size) {
                warnings.add(
                    ProjectionWarningCode::AssertionSubjectMismatch,
                    Some(subject),
                )?;
            } else {
                insert_size(&mut value.sizes, *size, attribution);
            }
        }
        SymbolAssertion::ClassMembership { class_name } if is_function => {
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
        }
        SymbolAssertion::FunctionPrototype { .. }
        | SymbolAssertion::FunctionBoundary { .. }
        | SymbolAssertion::ClassMembership { .. }
        | SymbolAssertion::TypeDefinition { .. } => {
            warnings.add(
                ProjectionWarningCode::AssertionSubjectMismatch,
                Some(subject),
            )?;
        }
        SymbolAssertion::Comment { .. } => {
            warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject))?;
        }
        _ => warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject))?,
    }
    Ok(())
}

fn project_type_assertion(
    assertion: &SymbolAssertion,
    attribution: ExportAttribution,
    value: &mut TypeAccumulator,
    subject: ExportSubject,
    warnings: &mut WarningAccumulator,
) -> Result<(), ExportError> {
    match assertion {
        SymbolAssertion::Name { name } => insert_text(
            &mut value.names,
            name,
            MAX_NAME_BYTES,
            attribution,
            MAX_NAMES_PER_ENTITY,
            "name candidate",
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
        | SymbolAssertion::ClassMembership { .. } => warnings.add(
            ProjectionWarningCode::AssertionSubjectMismatch,
            Some(subject),
        ),
        SymbolAssertion::Comment { .. } => {
            warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject))
        }
        _ => warnings.add(ProjectionWarningCode::UnsupportedAssertion, Some(subject)),
    }
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

fn finish_function(
    rva: u64,
    value: AddressAccumulator<'_>,
    warnings: &mut WarningAccumulator,
) -> Result<Option<ExportFunction>, ExportError> {
    let (size, size_attribution) =
        finish_size(&value.sizes, ExportSubject::Function { rva }, warnings)?;
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
    if selected_name.is_none()
        && size.is_none()
        && prototypes.is_empty()
        && class_memberships.is_empty()
    {
        return Ok(None);
    }
    Ok(Some(ExportFunction {
        rva,
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
    if selected_name.is_none() && size.is_none() {
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
    if selected_name.is_none() && definitions.is_empty() {
        return None;
    }
    Some(ExportType {
        key,
        selected_name,
        alternate_names,
        definitions,
    })
}

fn finish_names(
    values: BTreeMap<String, AttributedText>,
) -> (Option<ExportName>, Vec<AttributedText>) {
    let mut values = finish_texts(values);
    if values.is_empty() {
        return (None, Vec::new());
    }
    let selected = values.remove(0);
    let output_name = selected.text.clone();
    (
        Some(ExportName {
            source: selected,
            output_name,
        }),
        values,
    )
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
