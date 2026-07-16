use std::{collections::BTreeMap, sync::Arc};

use msvc_demangler::{DemangleFlags, demangle};

use crate::{
    AnalysisError, MsvcRttiBaseClass, MsvcRttiVftable, PeAnalysis, PeSection,
    pe::{RvaMap, section_for_rva},
};

const COMPLETE_OBJECT_LOCATOR_SIZE: usize = 24;
const CLASS_HIERARCHY_DESCRIPTOR_SIZE: usize = 16;
const BASE_CLASS_DESCRIPTOR_COMMON_SIZE: usize = 24;
const BASE_CLASS_DESCRIPTOR_WITH_PCHD_SIZE: usize = 28;
const TYPE_DESCRIPTOR_HEADER_SIZE: u32 = 16;
const POINTER_SIZE: u32 = 8;

const COL_SIGNATURE_REV1: u32 = 1;
const CHD_SIGNATURE: u32 = 0;
const CHD_KNOWN_ATTRIBUTES: u32 = 0x7;
const BCD_HAS_CLASS_HIERARCHY_DESCRIPTOR: u32 = 0x40;
const BCD_KNOWN_ATTRIBUTES: u32 = 0x7f;

const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub(crate) const MAX_RTTI_SCAN_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_RTTI_VFTABLES: u64 = 65_536;
const MAX_RTTI_LOCATOR_CANDIDATES: u64 = 262_144;
pub(crate) const MAX_RTTI_BASES_PER_HIERARCHY: u64 = 4_096;
pub(crate) const MAX_RTTI_BASE_CLASSES: u64 = 262_144;
pub(crate) const MAX_VIRTUAL_FUNCTIONS_PER_VFTABLE: u64 = 4_096;
pub(crate) const MAX_RTTI_VIRTUAL_FUNCTIONS: u64 = 262_144;
const MAX_RTTI_NAME_BYTES: usize = 1_024;
pub(crate) const MAX_RTTI_TOTAL_NAME_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
struct TypeName {
    descriptor_rva: u32,
    decorated: String,
    demangled: String,
}

#[derive(Debug, Clone)]
struct Hierarchy {
    attributes: u32,
    base_class_array_rva: u32,
    base_classes: Vec<MsvcRttiBaseClass>,
}

#[derive(Debug, Clone)]
struct Locator {
    rva: u32,
    type_descriptor_rva: u32,
    class_hierarchy_descriptor_rva: u32,
    offset: u32,
    constructor_displacement_offset: u32,
    root_type: Arc<TypeName>,
    hierarchy: Arc<Hierarchy>,
}

#[derive(Default)]
struct ParseCaches {
    type_names: BTreeMap<u32, Option<Arc<TypeName>>>,
    hierarchies: BTreeMap<u32, Option<Arc<Hierarchy>>>,
    base_classes: u64,
    name_bytes: u64,
    exhausted: bool,
}

type ScanPlan<'a> = Vec<(&'a PeSection, u32)>;

impl ParseCaches {
    fn type_name(&mut self, mapper: &RvaMap<'_>, rva: u32) -> Option<Arc<TypeName>> {
        if let Some(cached) = self.type_names.get(&rva) {
            return cached.clone();
        }
        let parsed = parse_type_descriptor(mapper, rva).map(Arc::new);
        if let Some(type_name) = &parsed {
            let bytes = type_name_name_bytes(type_name).ok()?;
            if !self.reserve_name_bytes(bytes) {
                return None;
            }
        }
        self.type_names.insert(rva, parsed.clone());
        parsed
    }

    fn hierarchy(&mut self, mapper: &RvaMap<'_>, rva: u32) -> Option<Arc<Hierarchy>> {
        if let Some(cached) = self.hierarchies.get(&rva) {
            return cached.clone();
        }
        let parsed = parse_hierarchy(mapper, rva, self);
        if self.exhausted {
            return None;
        }
        if let Some(hierarchy) = &parsed {
            let base_count = u64::try_from(hierarchy.base_classes.len()).ok()?;
            let Some(next_base_count) = self.base_classes.checked_add(base_count) else {
                self.exhausted = true;
                return None;
            };
            let name_bytes = base_class_name_bytes(&hierarchy.base_classes).ok()?;
            if next_base_count > MAX_RTTI_BASE_CLASSES || !self.reserve_name_bytes(name_bytes) {
                self.exhausted = true;
                return None;
            }
            self.base_classes = next_base_count;
        }
        let parsed = parsed.map(Arc::new);
        self.hierarchies.insert(rva, parsed.clone());
        parsed
    }

    fn reserve_name_bytes(&mut self, bytes: u64) -> bool {
        let Some(next) = self.name_bytes.checked_add(bytes) else {
            self.exhausted = true;
            return false;
        };
        if next > MAX_RTTI_TOTAL_NAME_BYTES {
            self.exhausted = true;
            return false;
        }
        self.name_bytes = next;
        true
    }
}

/// Discover MSVC x64 Rev1 RTTI by validating the pointer stored immediately
/// before each candidate vftable. Random data is ignored unless the complete
/// locator, type descriptor, hierarchy, base descriptors, and executable
/// entries agree.
pub(crate) fn parse_msvc_rtti(
    mapper: &RvaMap<'_>,
    sections: &[PeSection],
    image_base: u64,
    size_of_image: u32,
) -> Result<(Vec<MsvcRttiVftable>, bool), AnalysisError> {
    let (scan_plan, mut scan_truncated) = build_scan_plan(sections, MAX_RTTI_SCAN_BYTES)?;

    let mut vftables = Vec::new();
    let mut locator_cache = BTreeMap::<u32, Option<Locator>>::new();
    let mut parse_caches = ParseCaches::default();
    let mut total_base_classes = 0_u64;
    let mut total_virtual_functions = 0_u64;
    let mut total_name_bytes = 0_u64;

    'sections: for (section, section_scan_bytes) in scan_plan {
        let section_start = section.virtual_address;
        let Some(section_end) = section_start.checked_add(section.file_backed_size()) else {
            return Err(AnalysisError::ArithmeticOverflow(
                "MSVC RTTI scan section range",
            ));
        };
        let section_scan_end = section_start.checked_add(section_scan_bytes).ok_or(
            AnalysisError::ArithmeticOverflow("MSVC RTTI scan section prefix"),
        )?;
        let Some(mut back_pointer_rva) = align_up(section_start, POINTER_SIZE) else {
            return Err(AnalysisError::ArithmeticOverflow(
                "MSVC RTTI scan alignment",
            ));
        };

        while back_pointer_rva
            .checked_add(POINTER_SIZE)
            .is_some_and(|end| end <= section_scan_end)
        {
            let locator_va = match mapper.read_u64(back_pointer_rva, "MSVC RTTI back-pointer") {
                Some(value) => value,
                None => {
                    back_pointer_rva = match back_pointer_rva.checked_add(POINTER_SIZE) {
                        Some(value) => value,
                        None => break,
                    };
                    continue;
                }
            };
            let Some(locator_rva) = va_to_rva(locator_va, image_base, size_of_image) else {
                back_pointer_rva = match back_pointer_rva.checked_add(POINTER_SIZE) {
                    Some(value) => value,
                    None => break,
                };
                continue;
            };

            if !locator_cache.contains_key(&locator_rva) {
                if !looks_like_rev1_locator(mapper, locator_rva) {
                    back_pointer_rva = match back_pointer_rva.checked_add(POINTER_SIZE) {
                        Some(value) => value,
                        None => break,
                    };
                    continue;
                }
                let candidate_count = u64::try_from(locator_cache.len())
                    .map_err(|_| {
                        AnalysisError::IntegerConversion("MSVC RTTI locator candidate count")
                    })?
                    .checked_add(1)
                    .ok_or(AnalysisError::ArithmeticOverflow(
                        "MSVC RTTI locator candidate count",
                    ))?;
                if candidate_count > MAX_RTTI_LOCATOR_CANDIDATES {
                    scan_truncated = true;
                    break 'sections;
                }
                let locator = parse_locator(mapper, locator_rva, &mut parse_caches);
                if parse_caches.exhausted {
                    scan_truncated = true;
                    break 'sections;
                }
                locator_cache.insert(locator_rva, locator);
            }
            let Some(locator) = locator_cache.get(&locator_rva).and_then(Option::as_ref) else {
                back_pointer_rva = match back_pointer_rva.checked_add(POINTER_SIZE) {
                    Some(value) => value,
                    None => break,
                };
                continue;
            };

            if let Some(vftable) = parse_candidate(
                mapper,
                sections,
                back_pointer_rva,
                section_end,
                locator,
                image_base,
                size_of_image,
            ) {
                let base_count = u64::try_from(vftable.base_classes.len())
                    .map_err(|_| AnalysisError::IntegerConversion("MSVC RTTI base-class count"))?;
                let slot_count =
                    u64::try_from(vftable.virtual_function_rvas.len()).map_err(|_| {
                        AnalysisError::IntegerConversion("MSVC RTTI virtual-function count")
                    })?;
                let next_base_classes = total_base_classes.checked_add(base_count).ok_or(
                    AnalysisError::ArithmeticOverflow("MSVC RTTI base-class count"),
                )?;
                let next_virtual_functions =
                    total_virtual_functions.checked_add(slot_count).ok_or(
                        AnalysisError::ArithmeticOverflow("MSVC RTTI virtual-function count"),
                    )?;
                let next_name_bytes = total_name_bytes
                    .checked_add(vftable_name_bytes(&vftable)?)
                    .ok_or(AnalysisError::ArithmeticOverflow(
                        "MSVC RTTI name byte count",
                    ))?;
                let next_vftable_count = u64::try_from(vftables.len())
                    .map_err(|_| AnalysisError::IntegerConversion("MSVC RTTI vftable count"))?
                    .checked_add(1)
                    .ok_or(AnalysisError::ArithmeticOverflow("MSVC RTTI vftable count"))?;
                if next_base_classes > MAX_RTTI_BASE_CLASSES
                    || next_virtual_functions > MAX_RTTI_VIRTUAL_FUNCTIONS
                    || next_name_bytes > MAX_RTTI_TOTAL_NAME_BYTES
                    || next_vftable_count > MAX_RTTI_VFTABLES
                {
                    scan_truncated = true;
                    break 'sections;
                }
                total_base_classes = next_base_classes;
                total_virtual_functions = next_virtual_functions;
                total_name_bytes = next_name_bytes;
                vftables.push(vftable);
            }

            back_pointer_rva = match back_pointer_rva.checked_add(POINTER_SIZE) {
                Some(value) => value,
                None => break,
            };
        }
    }

    vftables.sort_by_key(|vftable| vftable.rva);
    Ok((vftables, scan_truncated))
}

fn build_scan_plan(
    sections: &[PeSection],
    byte_budget: u64,
) -> Result<(ScanPlan<'_>, bool), AnalysisError> {
    let mut eligible = sections
        .iter()
        .filter(|section| is_scan_section(section))
        .collect::<Vec<_>>();
    eligible.sort_by_key(|section| section.virtual_address);

    let mut total_bytes = 0_u64;
    for section in &eligible {
        total_bytes = total_bytes
            .checked_add(u64::from(section.file_backed_size()))
            .ok_or(AnalysisError::ArithmeticOverflow(
                "MSVC RTTI scan byte count",
            ))?;
    }

    let mut remaining = byte_budget;
    let mut plan = Vec::new();
    for section in eligible {
        if remaining < u64::from(POINTER_SIZE) {
            break;
        }
        let prefix = u64::from(section.file_backed_size()).min(remaining);
        remaining -= prefix;
        let prefix = u32::try_from(prefix)
            .map_err(|_| AnalysisError::IntegerConversion("MSVC RTTI scan section size"))?;
        if prefix >= POINTER_SIZE {
            plan.push((section, prefix));
        }
    }
    Ok((plan, total_bytes > byte_budget))
}

fn parse_candidate(
    mapper: &RvaMap<'_>,
    sections: &[PeSection],
    back_pointer_rva: u32,
    scan_section_end: u32,
    locator: &Locator,
    image_base: u64,
    size_of_image: u32,
) -> Option<MsvcRttiVftable> {
    if !locator_metadata_is_in_scan_sections(locator, sections) {
        return None;
    }
    let rva = back_pointer_rva.checked_add(POINTER_SIZE)?;
    let virtual_function_rvas = parse_virtual_functions(
        mapper,
        sections,
        rva,
        scan_section_end,
        image_base,
        size_of_image,
    )?;

    Some(MsvcRttiVftable {
        rva,
        complete_object_locator_rva: locator.rva,
        type_descriptor_rva: locator.type_descriptor_rva,
        class_hierarchy_descriptor_rva: locator.class_hierarchy_descriptor_rva,
        base_class_array_rva: locator.hierarchy.base_class_array_rva,
        offset: locator.offset,
        constructor_displacement_offset: locator.constructor_displacement_offset,
        decorated_class_name: locator.root_type.decorated.clone(),
        class_name: locator.root_type.demangled.clone(),
        hierarchy_attributes: locator.hierarchy.attributes,
        base_classes: locator.hierarchy.base_classes.clone(),
        virtual_function_rvas,
    })
}

fn looks_like_rev1_locator(mapper: &RvaMap<'_>, locator_rva: u32) -> bool {
    let Some(self_field_rva) = locator_rva.checked_add(20) else {
        return false;
    };
    locator_rva % 4 == 0
        && mapper.read_u32(locator_rva, "MSVC RTTI complete object locator")
            == Some(COL_SIGNATURE_REV1)
        && mapper.read_u32(self_field_rva, "MSVC RTTI complete object locator") == Some(locator_rva)
}

fn parse_locator(
    mapper: &RvaMap<'_>,
    locator_rva: u32,
    caches: &mut ParseCaches,
) -> Option<Locator> {
    if locator_rva % 4 != 0 {
        return None;
    }
    let signature = mapper.read_u32(locator_rva, "MSVC RTTI complete object locator")?;
    if signature != COL_SIGNATURE_REV1 {
        return None;
    }
    let offset = mapper.read_u32(
        add_rva(locator_rva, 4)?,
        "MSVC RTTI complete object locator",
    )?;
    let constructor_displacement_offset = mapper.read_u32(
        add_rva(locator_rva, 8)?,
        "MSVC RTTI complete object locator",
    )?;
    let type_descriptor_rva = mapper.read_u32(
        add_rva(locator_rva, 12)?,
        "MSVC RTTI complete object locator",
    )?;
    let class_hierarchy_descriptor_rva = mapper.read_u32(
        add_rva(locator_rva, 16)?,
        "MSVC RTTI complete object locator",
    )?;
    let self_rva = mapper.read_u32(
        add_rva(locator_rva, 20)?,
        "MSVC RTTI complete object locator",
    )?;
    if self_rva != locator_rva
        || type_descriptor_rva == 0
        || type_descriptor_rva % POINTER_SIZE != 0
        || class_hierarchy_descriptor_rva == 0
        || class_hierarchy_descriptor_rva % 4 != 0
    {
        return None;
    }

    let root_type = caches.type_name(mapper, type_descriptor_rva)?;
    let hierarchy = caches.hierarchy(mapper, class_hierarchy_descriptor_rva)?;
    let first_base = hierarchy.base_classes.first()?;
    if first_base.type_descriptor_rva != root_type.descriptor_rva
        || first_base.decorated_name != root_type.decorated
        || first_base.name != root_type.demangled
        || first_base.num_contained_bases.checked_add(1)?
            != u32::try_from(hierarchy.base_classes.len()).ok()?
        || first_base.member_displacement != 0
        || first_base.vbtable_displacement != -1
        || first_base.displacement_inside_vbtable != 0
        || first_base
            .class_hierarchy_descriptor_rva
            .is_some_and(|nested| nested != class_hierarchy_descriptor_rva)
    {
        return None;
    }

    Some(Locator {
        rva: locator_rva,
        type_descriptor_rva,
        class_hierarchy_descriptor_rva,
        offset,
        constructor_displacement_offset,
        root_type,
        hierarchy,
    })
}

fn parse_type_descriptor(mapper: &RvaMap<'_>, descriptor_rva: u32) -> Option<TypeName> {
    if descriptor_rva == 0 || descriptor_rva % POINTER_SIZE != 0 {
        return None;
    }
    let type_info_vftable = mapper.read_u64(descriptor_rva, "MSVC RTTI type descriptor")?;
    let spare = mapper.read_u64(add_rva(descriptor_rva, 8)?, "MSVC RTTI type descriptor")?;
    if type_info_vftable == 0 || spare != 0 {
        return None;
    }
    let name_rva = add_rva(descriptor_rva, TYPE_DESCRIPTOR_HEADER_SIZE)?;
    let decorated = mapper
        .c_string(name_rva, "MSVC RTTI type name", MAX_RTTI_NAME_BYTES + 1)
        .ok()?;
    if decorated.is_empty()
        || decorated.len() > MAX_RTTI_NAME_BYTES
        || !(decorated.starts_with(".?AV") || decorated.starts_with(".?AU"))
        || !decorated.ends_with("@@")
        || decorated.chars().any(is_forbidden_name_char)
    {
        return None;
    }
    let demangled = demangle_rtti_type_name(&decorated)?;
    Some(TypeName {
        descriptor_rva,
        decorated,
        demangled,
    })
}

fn parse_hierarchy(
    mapper: &RvaMap<'_>,
    descriptor_rva: u32,
    caches: &mut ParseCaches,
) -> Option<Hierarchy> {
    if mapper.read_u32(descriptor_rva, "MSVC RTTI class hierarchy")? != CHD_SIGNATURE {
        return None;
    }
    let attributes = mapper.read_u32(add_rva(descriptor_rva, 4)?, "MSVC RTTI class hierarchy")?;
    if attributes & !CHD_KNOWN_ATTRIBUTES != 0 {
        return None;
    }
    let count = mapper.read_u32(add_rva(descriptor_rva, 8)?, "MSVC RTTI class hierarchy")?;
    if count == 0 || u64::from(count) > MAX_RTTI_BASES_PER_HIERARCHY {
        return None;
    }
    let base_class_array_rva =
        mapper.read_u32(add_rva(descriptor_rva, 12)?, "MSVC RTTI class hierarchy")?;
    if base_class_array_rva == 0 || base_class_array_rva % 4 != 0 {
        return None;
    }

    let mut base_classes = Vec::with_capacity(usize::try_from(count).ok()?);
    for array_index in 0..count {
        let entry_delta = array_index.checked_mul(4)?;
        let descriptor = mapper.read_u32(
            add_rva(base_class_array_rva, entry_delta)?,
            "MSVC RTTI base-class array",
        )?;
        if descriptor == 0 || descriptor % 4 != 0 {
            return None;
        }
        let base = parse_base_class(mapper, array_index, count, descriptor, caches)?;
        base_classes.push(base);
    }
    if !has_valid_preorder_spans(&base_classes) {
        return None;
    }

    Some(Hierarchy {
        attributes,
        base_class_array_rva,
        base_classes,
    })
}

fn parse_base_class(
    mapper: &RvaMap<'_>,
    array_index: u32,
    hierarchy_count: u32,
    descriptor_rva: u32,
    caches: &mut ParseCaches,
) -> Option<MsvcRttiBaseClass> {
    let type_descriptor_rva = mapper.read_u32(descriptor_rva, "MSVC RTTI base-class descriptor")?;
    if type_descriptor_rva == 0 || type_descriptor_rva % POINTER_SIZE != 0 {
        return None;
    }
    let num_contained_bases = mapper.read_u32(
        add_rva(descriptor_rva, 4)?,
        "MSVC RTTI base-class descriptor",
    )?;
    let remaining = hierarchy_count.checked_sub(array_index)?.checked_sub(1)?;
    if num_contained_bases > remaining {
        return None;
    }
    let member_displacement = mapper.read_i32(
        add_rva(descriptor_rva, 8)?,
        "MSVC RTTI base-class descriptor",
    )?;
    let vbtable_displacement = mapper.read_i32(
        add_rva(descriptor_rva, 12)?,
        "MSVC RTTI base-class descriptor",
    )?;
    let displacement_inside_vbtable = mapper.read_i32(
        add_rva(descriptor_rva, 16)?,
        "MSVC RTTI base-class descriptor",
    )?;
    if !has_valid_pmd(
        member_displacement,
        vbtable_displacement,
        displacement_inside_vbtable,
    ) {
        return None;
    }
    let attributes = mapper.read_u32(
        add_rva(descriptor_rva, 20)?,
        "MSVC RTTI base-class descriptor",
    )?;
    if attributes & !BCD_KNOWN_ATTRIBUTES != 0 {
        return None;
    }
    let class_hierarchy_descriptor_rva = if attributes & BCD_HAS_CLASS_HIERARCHY_DESCRIPTOR != 0 {
        let nested_hierarchy_rva = mapper.read_u32(
            add_rva(descriptor_rva, 24)?,
            "MSVC RTTI base-class descriptor",
        )?;
        if nested_hierarchy_rva == 0
            || nested_hierarchy_rva % 4 != 0
            || mapper.read_u32(nested_hierarchy_rva, "MSVC RTTI nested hierarchy")? != CHD_SIGNATURE
        {
            return None;
        }
        Some(nested_hierarchy_rva)
    } else {
        None
    };
    let type_name = caches.type_name(mapper, type_descriptor_rva)?;

    Some(MsvcRttiBaseClass {
        array_index,
        descriptor_rva,
        type_descriptor_rva,
        decorated_name: type_name.decorated.clone(),
        name: type_name.demangled.clone(),
        num_contained_bases,
        member_displacement,
        vbtable_displacement,
        displacement_inside_vbtable,
        attributes,
        class_hierarchy_descriptor_rva,
    })
}

fn parse_virtual_functions(
    mapper: &RvaMap<'_>,
    sections: &[PeSection],
    vftable_rva: u32,
    scan_section_end: u32,
    image_base: u64,
    size_of_image: u32,
) -> Option<Vec<u32>> {
    let mut functions = Vec::new();
    for index in 0..=MAX_VIRTUAL_FUNCTIONS_PER_VFTABLE {
        let delta = u32::try_from(index).ok()?.checked_mul(POINTER_SIZE)?;
        let slot_rva = vftable_rva.checked_add(delta)?;
        if slot_rva
            .checked_add(POINTER_SIZE)
            .is_none_or(|end| end > scan_section_end)
        {
            break;
        }
        let target_va = mapper.read_u64(slot_rva, "MSVC RTTI vftable entry")?;
        let Some(target_rva) = va_to_rva(target_va, image_base, size_of_image) else {
            break;
        };
        let Some((_, section)) = section_for_rva(target_rva, sections) else {
            break;
        };
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 || !mapper.is_backed(target_rva, 1)
        {
            break;
        }
        if index == MAX_VIRTUAL_FUNCTIONS_PER_VFTABLE {
            return None;
        }
        functions.push(target_rva);
    }
    (!functions.is_empty()).then_some(functions)
}

pub(crate) fn validate_msvc_rtti(analysis: &PeAnalysis) -> Result<(), AnalysisError> {
    enforce_limit(
        "MSVC RTTI vftable",
        u64::try_from(analysis.msvc_rtti_vftables.len())
            .map_err(|_| AnalysisError::IntegerConversion("MSVC RTTI vftable count"))?,
        MAX_RTTI_VFTABLES,
    )?;
    if analysis
        .msvc_rtti_vftables
        .windows(2)
        .any(|pair| pair[0].rva >= pair[1].rva)
    {
        return invalid("MSVC RTTI vftables", "are not in strict RVA order");
    }

    let mut total_base_classes = 0_u64;
    let mut total_virtual_functions = 0_u64;
    let mut total_name_bytes = 0_u64;
    let mut type_names = BTreeMap::<u32, (&str, &str)>::new();
    let mut complete_object_locators = BTreeMap::<u32, &MsvcRttiVftable>::new();
    let mut class_hierarchies = BTreeMap::<u32, &MsvcRttiVftable>::new();
    let mut base_class_array_slots = BTreeMap::<u32, u32>::new();
    let mut base_class_descriptors = BTreeMap::<u32, &MsvcRttiBaseClass>::new();

    for vftable in &analysis.msvc_rtti_vftables {
        total_name_bytes = total_name_bytes
            .checked_add(vftable_name_bytes(vftable)?)
            .ok_or(AnalysisError::ArithmeticOverflow(
                "MSVC RTTI name byte count",
            ))?;
        enforce_limit(
            "MSVC RTTI name byte",
            total_name_bytes,
            MAX_RTTI_TOTAL_NAME_BYTES,
        )?;
        if vftable.rva < POINTER_SIZE
            || vftable.rva % POINTER_SIZE != 0
            || vftable.complete_object_locator_rva % 4 != 0
            || vftable.type_descriptor_rva % POINTER_SIZE != 0
            || vftable.class_hierarchy_descriptor_rva % 4 != 0
            || vftable.base_class_array_rva % 4 != 0
        {
            return invalid("MSVC RTTI address", "is zero, underflowing, or unaligned");
        }
        if vftable.hierarchy_attributes & !CHD_KNOWN_ATTRIBUTES != 0 {
            return invalid(
                "MSVC RTTI hierarchy attributes",
                "contains unknown attribute bits",
            );
        }
        require_scan_metadata(
            analysis,
            vftable.rva - POINTER_SIZE,
            POINTER_SIZE,
            "MSVC RTTI back-pointer",
        )?;
        require_scan_metadata(
            analysis,
            vftable.complete_object_locator_rva,
            u32::try_from(COMPLETE_OBJECT_LOCATOR_SIZE)
                .map_err(|_| AnalysisError::IntegerConversion("object locator size"))?,
            "MSVC RTTI complete object locator",
        )?;
        require_scan_metadata(
            analysis,
            vftable.class_hierarchy_descriptor_rva,
            u32::try_from(CLASS_HIERARCHY_DESCRIPTOR_SIZE)
                .map_err(|_| AnalysisError::IntegerConversion("class hierarchy size"))?,
            "MSVC RTTI class hierarchy",
        )?;
        validate_type_name(
            analysis,
            vftable.type_descriptor_rva,
            &vftable.decorated_class_name,
            &vftable.class_name,
            &mut type_names,
        )?;

        let base_count = u64::try_from(vftable.base_classes.len())
            .map_err(|_| AnalysisError::IntegerConversion("MSVC RTTI base-class count"))?;
        if base_count == 0 || base_count > MAX_RTTI_BASES_PER_HIERARCHY {
            return invalid(
                "MSVC RTTI base-class count",
                "is zero or exceeds the per-hierarchy limit",
            );
        }
        total_base_classes =
            total_base_classes
                .checked_add(base_count)
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "MSVC RTTI base-class count",
                ))?;
        enforce_limit(
            "MSVC RTTI base class",
            total_base_classes,
            MAX_RTTI_BASE_CLASSES,
        )?;
        let base_array_size = u32::try_from(base_count)
            .ok()
            .and_then(|count| count.checked_mul(4))
            .ok_or(AnalysisError::ArithmeticOverflow(
                "MSVC RTTI base-class array size",
            ))?;
        require_scan_metadata(
            analysis,
            vftable.base_class_array_rva,
            base_array_size,
            "MSVC RTTI base-class array",
        )?;

        for (index, base) in vftable.base_classes.iter().enumerate() {
            let slot_offset = u32::try_from(index)
                .ok()
                .and_then(|index| index.checked_mul(4))
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "MSVC RTTI base-class array slot",
                ))?;
            let slot_rva = vftable
                .base_class_array_rva
                .checked_add(slot_offset)
                .ok_or(AnalysisError::ArithmeticOverflow(
                    "MSVC RTTI base-class array slot",
                ))?;
            if let Some(previous_descriptor_rva) = base_class_array_slots.get(&slot_rva) {
                if *previous_descriptor_rva != base.descriptor_rva {
                    return invalid(
                        "MSVC RTTI shared base-class array slot",
                        "has contradictory descriptor RVAs across references",
                    );
                }
            } else {
                base_class_array_slots.insert(slot_rva, base.descriptor_rva);
            }
            if base.array_index
                != u32::try_from(index)
                    .map_err(|_| AnalysisError::IntegerConversion("MSVC RTTI base index"))?
                || base.descriptor_rva % 4 != 0
                || base.type_descriptor_rva % POINTER_SIZE != 0
            {
                return invalid(
                    "MSVC RTTI base-class descriptor",
                    "has invalid source order or alignment",
                );
            }
            let has_pchd = base.attributes & BCD_HAS_CLASS_HIERARCHY_DESCRIPTOR != 0;
            if base.attributes & !BCD_KNOWN_ATTRIBUTES != 0
                || has_pchd != base.class_hierarchy_descriptor_rva.is_some()
            {
                return invalid(
                    "MSVC RTTI base-class attributes",
                    "do not agree with the optional class-hierarchy link",
                );
            }
            if !has_valid_pmd(
                base.member_displacement,
                base.vbtable_displacement,
                base.displacement_inside_vbtable,
            ) {
                return invalid(
                    "MSVC RTTI base-class displacement",
                    "has an invalid PMD virtual-base shape",
                );
            }
            let remaining = u32::try_from(vftable.base_classes.len() - index - 1)
                .map_err(|_| AnalysisError::IntegerConversion("MSVC RTTI remaining bases"))?;
            if base.num_contained_bases > remaining {
                return invalid(
                    "MSVC RTTI contained-base count",
                    "exceeds the remaining hierarchy entries",
                );
            }
            require_scan_metadata(
                analysis,
                base.descriptor_rva,
                u32::try_from(if has_pchd {
                    BASE_CLASS_DESCRIPTOR_WITH_PCHD_SIZE
                } else {
                    BASE_CLASS_DESCRIPTOR_COMMON_SIZE
                })
                .map_err(|_| AnalysisError::IntegerConversion("base descriptor size"))?,
                "MSVC RTTI base-class descriptor",
            )?;
            if let Some(nested) = base.class_hierarchy_descriptor_rva {
                if nested % 4 != 0 {
                    return invalid("MSVC RTTI nested hierarchy", "is unaligned");
                }
                require_scan_metadata(
                    analysis,
                    nested,
                    u32::try_from(CLASS_HIERARCHY_DESCRIPTOR_SIZE).map_err(|_| {
                        AnalysisError::IntegerConversion("nested class hierarchy size")
                    })?,
                    "MSVC RTTI nested hierarchy",
                )?;
            }
            validate_type_name(
                analysis,
                base.type_descriptor_rva,
                &base.decorated_name,
                &base.name,
                &mut type_names,
            )?;
            if let Some(previous) = base_class_descriptors.get(&base.descriptor_rva) {
                if !same_base_class_descriptor(previous, base) {
                    return invalid(
                        "MSVC RTTI shared base-class descriptor",
                        "has contradictory fields across references",
                    );
                }
            } else {
                base_class_descriptors.insert(base.descriptor_rva, base);
            }
        }
        if !has_valid_preorder_spans(&vftable.base_classes) {
            return invalid(
                "MSVC RTTI base-class hierarchy",
                "does not form bounded preorder subtree spans",
            );
        }
        let root = vftable
            .base_classes
            .first()
            .ok_or_else(|| AnalysisError::InvalidField {
                field: "MSVC RTTI hierarchy",
                reason: "has no self descriptor".to_owned(),
            })?;
        if root.type_descriptor_rva != vftable.type_descriptor_rva
            || root.decorated_name != vftable.decorated_class_name
            || root.name != vftable.class_name
            || root.num_contained_bases.checked_add(1)
                != u32::try_from(vftable.base_classes.len()).ok()
            || root.member_displacement != 0
            || root.vbtable_displacement != -1
            || root.displacement_inside_vbtable != 0
            || root
                .class_hierarchy_descriptor_rva
                .is_some_and(|nested| nested != vftable.class_hierarchy_descriptor_rva)
        {
            return invalid(
                "MSVC RTTI hierarchy",
                "first base descriptor is not the complete class",
            );
        }

        if let Some(previous) = complete_object_locators.get(&vftable.complete_object_locator_rva) {
            if !same_complete_object_locator(previous, vftable) {
                return invalid(
                    "MSVC RTTI shared complete object locator",
                    "has contradictory fields across references",
                );
            }
        } else {
            complete_object_locators.insert(vftable.complete_object_locator_rva, vftable);
        }
        if let Some(previous) = class_hierarchies.get(&vftable.class_hierarchy_descriptor_rva) {
            if !same_class_hierarchy(previous, vftable) {
                return invalid(
                    "MSVC RTTI shared class hierarchy",
                    "has contradictory fields across references",
                );
            }
        } else {
            class_hierarchies.insert(vftable.class_hierarchy_descriptor_rva, vftable);
        }
        let slot_count = u64::try_from(vftable.virtual_function_rvas.len())
            .map_err(|_| AnalysisError::IntegerConversion("MSVC RTTI virtual-function count"))?;
        if slot_count == 0 || slot_count > MAX_VIRTUAL_FUNCTIONS_PER_VFTABLE {
            return invalid(
                "MSVC RTTI virtual-function count",
                "is zero or exceeds the per-vftable limit",
            );
        }
        total_virtual_functions = total_virtual_functions.checked_add(slot_count).ok_or(
            AnalysisError::ArithmeticOverflow("MSVC RTTI virtual-function count"),
        )?;
        enforce_limit(
            "MSVC RTTI virtual function",
            total_virtual_functions,
            MAX_RTTI_VIRTUAL_FUNCTIONS,
        )?;
        let table_size = u32::try_from(slot_count)
            .ok()
            .and_then(|count| count.checked_mul(POINTER_SIZE))
            .ok_or(AnalysisError::ArithmeticOverflow("MSVC RTTI vftable size"))?;
        require_backed(analysis, vftable.rva, table_size, "MSVC RTTI vftable")?;
        let Some((source_section_index, source_section)) =
            section_for_rva(vftable.rva, &analysis.sections)
        else {
            return invalid("MSVC RTTI vftable", "is outside the section table");
        };
        if !is_scan_section(source_section)
            || section_for_rva(
                vftable
                    .rva
                    .checked_add(table_size - 1)
                    .ok_or(AnalysisError::ArithmeticOverflow("MSVC RTTI vftable end"))?,
                &analysis.sections,
            )
            .is_none_or(|(end_index, _)| end_index != source_section_index)
        {
            return invalid(
                "MSVC RTTI vftable",
                "does not remain in one read-only initialized-data section",
            );
        }
        for function_rva in &vftable.virtual_function_rvas {
            let Some((_, section)) = section_for_rva(*function_rva, &analysis.sections) else {
                return invalid("MSVC RTTI virtual function", "lies outside every section");
            };
            if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                return invalid(
                    "MSVC RTTI virtual function",
                    "does not point into an executable section",
                );
            }
            require_backed(analysis, *function_rva, 1, "MSVC RTTI virtual function")?;
        }
    }
    Ok(())
}

fn same_complete_object_locator(left: &MsvcRttiVftable, right: &MsvcRttiVftable) -> bool {
    left.type_descriptor_rva == right.type_descriptor_rva
        && left.class_hierarchy_descriptor_rva == right.class_hierarchy_descriptor_rva
        && left.offset == right.offset
        && left.constructor_displacement_offset == right.constructor_displacement_offset
}

fn same_class_hierarchy(left: &MsvcRttiVftable, right: &MsvcRttiVftable) -> bool {
    left.hierarchy_attributes == right.hierarchy_attributes
        && left.base_class_array_rva == right.base_class_array_rva
        && same_base_class_array(left, right)
}

fn same_base_class_array(left: &MsvcRttiVftable, right: &MsvcRttiVftable) -> bool {
    left.base_classes.len() == right.base_classes.len()
        && left
            .base_classes
            .iter()
            .zip(&right.base_classes)
            .all(|(left, right)| left.descriptor_rva == right.descriptor_rva)
}

fn same_base_class_descriptor(left: &MsvcRttiBaseClass, right: &MsvcRttiBaseClass) -> bool {
    left.type_descriptor_rva == right.type_descriptor_rva
        && left.decorated_name == right.decorated_name
        && left.name == right.name
        && left.num_contained_bases == right.num_contained_bases
        && left.member_displacement == right.member_displacement
        && left.vbtable_displacement == right.vbtable_displacement
        && left.displacement_inside_vbtable == right.displacement_inside_vbtable
        && left.attributes == right.attributes
        && left.class_hierarchy_descriptor_rva == right.class_hierarchy_descriptor_rva
}

fn validate_type_name<'a>(
    analysis: &PeAnalysis,
    descriptor_rva: u32,
    decorated: &'a str,
    demangled: &'a str,
    known: &mut BTreeMap<u32, (&'a str, &'a str)>,
) -> Result<(), AnalysisError> {
    if descriptor_rva == 0
        || descriptor_rva % POINTER_SIZE != 0
        || decorated.is_empty()
        || decorated.len() > MAX_RTTI_NAME_BYTES
        || !(decorated.starts_with(".?AV") || decorated.starts_with(".?AU"))
        || !decorated.ends_with("@@")
        || demangled.is_empty()
        || demangled.len() > MAX_RTTI_NAME_BYTES
        || decorated.trim() != decorated
        || demangled.trim() != demangled
        || decorated.chars().any(is_forbidden_name_char)
        || demangled.chars().any(is_forbidden_name_char)
        || demangle_rtti_type_name(decorated).as_deref() != Some(demangled)
    {
        return invalid(
            "MSVC RTTI type name",
            "is invalid, oversized, or inconsistent with its decorated spelling",
        );
    }
    let name_size = u32::try_from(decorated.len())
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or(AnalysisError::ArithmeticOverflow(
            "MSVC RTTI type-name size",
        ))?;
    require_type_descriptor_metadata(
        analysis,
        descriptor_rva,
        TYPE_DESCRIPTOR_HEADER_SIZE.checked_add(name_size).ok_or(
            AnalysisError::ArithmeticOverflow("MSVC RTTI type-descriptor size"),
        )?,
        "MSVC RTTI type descriptor",
    )?;
    if let Some((known_decorated, known_demangled)) =
        known.insert(descriptor_rva, (decorated, demangled))
    {
        if known_decorated != decorated || known_demangled != demangled {
            return invalid(
                "MSVC RTTI type descriptor",
                "has inconsistent names across references",
            );
        }
    }
    Ok(())
}

fn demangle_rtti_type_name(decorated: &str) -> Option<String> {
    let body = decorated.strip_prefix('.')?;
    let symbol = format!("??_R0{body}@8");
    let flags = DemangleFlags::llvm() | DemangleFlags::NO_CLASS_TYPE;
    let demangled = demangle(&symbol, flags).ok()?;
    let type_name = demangled.strip_suffix("::`RTTI Type Descriptor'")?;
    if type_name.is_empty()
        || type_name.len() > MAX_RTTI_NAME_BYTES
        || type_name.trim() != type_name
        || type_name.chars().any(is_forbidden_name_char)
    {
        None
    } else {
        Some(type_name.to_owned())
    }
}

fn is_scan_section(section: &PeSection) -> bool {
    is_type_descriptor_section(section)
        && section.characteristics & IMAGE_SCN_MEM_WRITE == 0
        && section.file_backed_size() >= POINTER_SIZE
}

fn is_type_descriptor_section(section: &PeSection) -> bool {
    let characteristics = section.characteristics;
    characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
        && characteristics & IMAGE_SCN_MEM_READ != 0
        && characteristics & IMAGE_SCN_MEM_EXECUTE == 0
}

fn locator_metadata_is_in_scan_sections(locator: &Locator, sections: &[PeSection]) -> bool {
    let Some(locator_size) = u32::try_from(COMPLETE_OBJECT_LOCATOR_SIZE).ok() else {
        return false;
    };
    let Some(hierarchy_size) = u32::try_from(CLASS_HIERARCHY_DESCRIPTOR_SIZE).ok() else {
        return false;
    };
    let Some(base_descriptor_common_size) = u32::try_from(BASE_CLASS_DESCRIPTOR_COMMON_SIZE).ok()
    else {
        return false;
    };
    let Some(base_descriptor_with_pchd_size) =
        u32::try_from(BASE_CLASS_DESCRIPTOR_WITH_PCHD_SIZE).ok()
    else {
        return false;
    };
    let Some(root_type_size) = type_descriptor_record_size(&locator.root_type.decorated) else {
        return false;
    };
    let Some(base_array_size) = u32::try_from(locator.hierarchy.base_classes.len())
        .ok()
        .and_then(|count| count.checked_mul(4))
    else {
        return false;
    };

    scan_range_is_backed(locator.rva, locator_size, sections)
        && scan_range_is_backed(
            locator.class_hierarchy_descriptor_rva,
            hierarchy_size,
            sections,
        )
        && scan_range_is_backed(
            locator.hierarchy.base_class_array_rva,
            base_array_size,
            sections,
        )
        && type_descriptor_range_is_backed(
            locator.root_type.descriptor_rva,
            root_type_size,
            sections,
        )
        && locator.hierarchy.base_classes.iter().all(|base| {
            let Some(type_size) = type_descriptor_record_size(&base.decorated_name) else {
                return false;
            };
            let descriptor_size = if base.class_hierarchy_descriptor_rva.is_some() {
                base_descriptor_with_pchd_size
            } else {
                base_descriptor_common_size
            };
            scan_range_is_backed(base.descriptor_rva, descriptor_size, sections)
                && type_descriptor_range_is_backed(base.type_descriptor_rva, type_size, sections)
                && base
                    .class_hierarchy_descriptor_rva
                    .is_none_or(|rva| scan_range_is_backed(rva, hierarchy_size, sections))
        })
}

fn type_descriptor_record_size(decorated: &str) -> Option<u32> {
    TYPE_DESCRIPTOR_HEADER_SIZE
        .checked_add(u32::try_from(decorated.len()).ok()?)?
        .checked_add(1)
}

fn scan_range_is_backed(rva: u32, size: u32, sections: &[PeSection]) -> bool {
    section_range_is_backed(rva, size, sections, is_scan_section)
}

fn type_descriptor_range_is_backed(rva: u32, size: u32, sections: &[PeSection]) -> bool {
    section_range_is_backed(rva, size, sections, is_type_descriptor_section)
}

fn section_range_is_backed(
    rva: u32,
    size: u32,
    sections: &[PeSection],
    section_is_eligible: fn(&PeSection) -> bool,
) -> bool {
    if size == 0 {
        return false;
    }
    let Some(end) = u64::from(rva).checked_add(u64::from(size)) else {
        return false;
    };
    sections.iter().any(|section| {
        let start = u64::from(section.virtual_address);
        let Some(backed_end) = start.checked_add(u64::from(section.file_backed_size())) else {
            return false;
        };
        section_is_eligible(section) && u64::from(rva) >= start && end <= backed_end
    })
}

fn has_valid_pmd(
    member_displacement: i32,
    vbtable_displacement: i32,
    displacement_inside_vbtable: i32,
) -> bool {
    if member_displacement < 0 || displacement_inside_vbtable < 0 {
        return false;
    }
    if vbtable_displacement == -1 {
        displacement_inside_vbtable == 0
    } else {
        vbtable_displacement >= 0
            && displacement_inside_vbtable >= 0
            && displacement_inside_vbtable % 4 == 0
    }
}

fn is_forbidden_name_char(value: char) -> bool {
    value.is_control()
        || matches!(
            value,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn vftable_name_bytes(vftable: &MsvcRttiVftable) -> Result<u64, AnalysisError> {
    type_name_bytes(&vftable.decorated_class_name, &vftable.class_name)?
        .checked_add(base_class_name_bytes(&vftable.base_classes)?)
        .ok_or(AnalysisError::ArithmeticOverflow(
            "MSVC RTTI name byte count",
        ))
}

fn type_name_name_bytes(value: &TypeName) -> Result<u64, AnalysisError> {
    type_name_bytes(&value.decorated, &value.demangled)
}

fn type_name_bytes(decorated: &str, demangled: &str) -> Result<u64, AnalysisError> {
    string_bytes(decorated)?
        .checked_add(string_bytes(demangled)?)
        .ok_or(AnalysisError::ArithmeticOverflow(
            "MSVC RTTI name byte count",
        ))
}

fn base_class_name_bytes(base_classes: &[MsvcRttiBaseClass]) -> Result<u64, AnalysisError> {
    let mut total = 0_u64;
    for base in base_classes {
        for value in [base.decorated_name.as_str(), base.name.as_str()] {
            total = total.checked_add(string_bytes(value)?).ok_or(
                AnalysisError::ArithmeticOverflow("MSVC RTTI name byte count"),
            )?;
        }
    }
    Ok(total)
}

fn string_bytes(value: &str) -> Result<u64, AnalysisError> {
    u64::try_from(value.len()).map_err(|_| AnalysisError::IntegerConversion("MSVC RTTI name size"))
}

fn has_valid_preorder_spans(base_classes: &[MsvcRttiBaseClass]) -> bool {
    let mut active_ends = Vec::<usize>::new();
    for (index, base) in base_classes.iter().enumerate() {
        while active_ends.last() == Some(&index) {
            active_ends.pop();
        }
        if index != 0 && active_ends.is_empty() {
            return false;
        }
        let Some(end) = usize::try_from(base.num_contained_bases)
            .ok()
            .and_then(|count| index.checked_add(1)?.checked_add(count))
        else {
            return false;
        };
        if end > base_classes.len() || active_ends.last().is_some_and(|parent| end > *parent) {
            return false;
        }
        if end > index + 1 {
            active_ends.push(end);
        }
    }
    while active_ends.last() == Some(&base_classes.len()) {
        active_ends.pop();
    }
    active_ends.is_empty()
}

fn va_to_rva(value: u64, image_base: u64, size_of_image: u32) -> Option<u32> {
    let delta = value.checked_sub(image_base)?;
    (delta < u64::from(size_of_image))
        .then(|| u32::try_from(delta).ok())
        .flatten()
}

fn add_rva(rva: u32, delta: u32) -> Option<u32> {
    rva.checked_add(delta)
}

fn align_up(value: u32, alignment: u32) -> Option<u32> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

fn enforce_limit(kind: &'static str, count: u64, limit: u64) -> Result<(), AnalysisError> {
    if count > limit {
        Err(AnalysisError::LimitExceeded { kind, count, limit })
    } else {
        Ok(())
    }
}

fn require_backed(
    analysis: &PeAnalysis,
    rva: u32,
    size: u32,
    field: &'static str,
) -> Result<(), AnalysisError> {
    let end = u64::from(rva)
        .checked_add(u64::from(size))
        .ok_or(AnalysisError::ArithmeticOverflow("MSVC RTTI model range"))?;
    let backed = if rva < analysis.size_of_headers
        && end <= u64::from(analysis.size_of_headers)
        && end <= analysis.identity.size
    {
        true
    } else {
        analysis.sections.iter().any(|section| {
            let start = u64::from(section.virtual_address);
            let backed_end = start.saturating_add(u64::from(section.file_backed_size()));
            u64::from(rva) >= start && end <= backed_end
        })
    };
    if backed {
        Ok(())
    } else {
        invalid(field, "is not fully backed by file data")
    }
}

fn require_scan_metadata(
    analysis: &PeAnalysis,
    rva: u32,
    size: u32,
    field: &'static str,
) -> Result<(), AnalysisError> {
    if scan_range_is_backed(rva, size, &analysis.sections) {
        Ok(())
    } else {
        invalid(
            field,
            "is not fully backed by readable, read-only initialized data",
        )
    }
}

fn require_type_descriptor_metadata(
    analysis: &PeAnalysis,
    rva: u32,
    size: u32,
    field: &'static str,
) -> Result<(), AnalysisError> {
    if type_descriptor_range_is_backed(rva, size, &analysis.sections) {
        Ok(())
    } else {
        invalid(
            field,
            "is not fully backed by readable initialized non-executable data",
        )
    }
}

fn invalid<T>(field: &'static str, reason: impl Into<String>) -> Result<T, AnalysisError> {
    Err(AnalysisError::InvalidField {
        field,
        reason: reason.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_section(rva: u32, raw_data_size: u32) -> PeSection {
        PeSection {
            name: ".rdata".to_owned(),
            raw_name: *b".rdata\0\0",
            virtual_address: rva,
            virtual_size: raw_data_size,
            raw_data_offset: 0,
            raw_data_size,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        }
    }

    #[test]
    fn demangles_bounded_rtti_type_names() {
        assert_eq!(
            demangle_rtti_type_name(".?AVWidget@demo@@").as_deref(),
            Some("demo::Widget")
        );
        assert_eq!(
            demangle_rtti_type_name(".?AUBase@@").as_deref(),
            Some("Base")
        );
        assert!(demangle_rtti_type_name("not-rtti").is_none());
    }

    #[test]
    fn scan_plan_is_rva_ordered_and_surfaces_a_partial_prefix() {
        let sections = [scan_section(0x3000, 16), scan_section(0x1000, 8)];
        let (plan, truncated) = build_scan_plan(&sections, 16).expect("bounded scan plan");

        assert!(truncated);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].0.virtual_address, 0x1000);
        assert_eq!(plan[0].1, 8);
        assert_eq!(plan[1].0.virtual_address, 0x3000);
        assert_eq!(plan[1].1, 8);
    }

    #[test]
    fn pmd_and_name_safety_checks_reject_malformed_metadata() {
        assert!(has_valid_pmd(0, -1, 0));
        assert!(has_valid_pmd(8, 4, 12));
        assert!(!has_valid_pmd(-1, -1, 0));
        assert!(!has_valid_pmd(0, -1, 4));
        assert!(!has_valid_pmd(0, 0, 2));
        assert!(is_forbidden_name_char('\u{202e}'));
        assert!(is_forbidden_name_char('\u{0085}'));
    }
}
