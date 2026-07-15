use std::collections::BTreeSet;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Register};

use crate::{
    AnalysisError, MsvcRttiVftable, PeAnalysis, PeControlFlowTarget, PeDataReference, PeDirectCall,
    PeExport, PeImportLibrary, PeSection, PeThunk, RuntimeFunction,
    pe::{RvaMap, section_for_rva},
};

const MAX_DECODED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DECODED_INSTRUCTIONS: u64 = 1_000_000;
const MAX_DIRECT_CALLS: usize = 8_192;
const MAX_DATA_REFERENCES: usize = 32_768;
const MAX_THUNKS: usize = 4_096;
const MAX_X86_INSTRUCTION_BYTES: usize = 15;

const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

pub(crate) struct CodeRecovery {
    pub scan_truncated: bool,
    pub data_reference_scan_truncated: bool,
    pub direct_calls: Vec<PeDirectCall>,
    pub data_references: Vec<PeDataReference>,
    pub thunks: Vec<PeThunk>,
}

pub(crate) struct CodeRecoveryInput<'a, 'data> {
    pub mapper: &'a RvaMap<'data>,
    pub image_base: u64,
    pub size_of_image: u32,
    pub entry_point_rva: u32,
    pub sections: &'a [PeSection],
    pub imports: &'a [PeImportLibrary],
    pub exports: &'a [PeExport],
    pub runtime_functions: &'a [RuntimeFunction],
    pub msvc_rtti_vftables: &'a [MsvcRttiVftable],
}

struct TargetContext<'a, 'data> {
    mapper: &'a RvaMap<'data>,
    sections: &'a [PeSection],
    import_iat_rvas: &'a BTreeSet<u32>,
    runtime_targets: &'a RuntimeTargetPolicy,
    image_base: u64,
    size_of_image: u32,
}

/// Runtime-function coverage used to reject interior labels without a linear
/// scan through the exception table for every recovered edge.
struct RuntimeTargetPolicy {
    begins: BTreeSet<u32>,
    covered_intervals: Vec<(u32, u32)>,
}

impl RuntimeTargetPolicy {
    fn new(runtime_functions: &[RuntimeFunction]) -> Self {
        let begins = runtime_functions
            .iter()
            .map(|function| function.begin_rva)
            .collect();
        let mut ranges = runtime_functions
            .iter()
            .filter_map(|function| {
                (function.begin_rva < function.end_rva)
                    .then_some((function.begin_rva, function.end_rva))
            })
            .collect::<Vec<_>>();
        ranges.sort_unstable();

        let mut covered_intervals = Vec::<(u32, u32)>::new();
        for (begin_rva, end_rva) in ranges {
            if let Some((_, retained_end_rva)) = covered_intervals.last_mut() {
                if begin_rva <= *retained_end_rva {
                    *retained_end_rva = (*retained_end_rva).max(end_rva);
                } else {
                    covered_intervals.push((begin_rva, end_rva));
                }
            } else {
                covered_intervals.push((begin_rva, end_rva));
            }
        }

        Self {
            begins,
            covered_intervals,
        }
    }

    fn allows_function_target(&self, rva: u32) -> bool {
        if self.begins.contains(&rva) {
            return true;
        }
        let candidate = self
            .covered_intervals
            .partition_point(|(begin_rva, _)| *begin_rva <= rva);
        candidate == 0 || rva >= self.covered_intervals[candidate - 1].1
    }
}

#[derive(Default)]
struct DecodeBudget {
    bytes: u64,
    instructions: u64,
}

impl DecodeBudget {
    fn consume(&mut self, instruction_size: usize) -> bool {
        let Ok(instruction_size) = u64::try_from(instruction_size) else {
            return false;
        };
        let Some(bytes) = self.bytes.checked_add(instruction_size) else {
            return false;
        };
        let Some(instructions) = self.instructions.checked_add(1) else {
            return false;
        };
        if bytes > MAX_DECODED_BYTES || instructions > MAX_DECODED_INSTRUCTIONS {
            return false;
        }
        self.bytes = bytes;
        self.instructions = instructions;
        true
    }
}

pub(crate) fn recover_code(input: CodeRecoveryInput<'_, '_>) -> CodeRecovery {
    let import_iat_rvas = import_iat_rvas(input.imports);
    let runtime_targets = RuntimeTargetPolicy::new(input.runtime_functions);
    let target_context = TargetContext {
        mapper: input.mapper,
        sections: input.sections,
        import_iat_rvas: &import_iat_rvas,
        runtime_targets: &runtime_targets,
        image_base: input.image_base,
        size_of_image: input.size_of_image,
    };
    let mut budget = DecodeBudget::default();
    let mut scan_truncated = false;
    let mut data_reference_scan_truncated = false;
    let mut direct_calls = BTreeSet::new();
    let mut data_references = BTreeSet::new();

    let mut ranges = input
        .runtime_functions
        .iter()
        .map(|function| (function.begin_rva, function.end_rva))
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    ranges.dedup();

    'runtime_functions: for (begin_rva, end_rva) in ranges {
        let Some(size) = end_rva.checked_sub(begin_rva) else {
            continue;
        };
        let Ok(size_usize) = usize::try_from(size) else {
            continue;
        };
        if !is_backed_executable(input.mapper, input.sections, begin_rva, size_usize) {
            continue;
        }
        let Ok(bytes) = input
            .mapper
            .bytes(begin_rva, size_usize, "runtime-function code")
        else {
            continue;
        };
        let Some(ip) = input.image_base.checked_add(u64::from(begin_rva)) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        while decoder.can_decode() {
            let position = decoder.position();
            let instruction = decoder.decode();
            let instruction_size = instruction.len();
            if instruction_size == 0 || !budget.consume(instruction_size) {
                scan_truncated = true;
                data_reference_scan_truncated = true;
                break 'runtime_functions;
            }
            if instruction.is_invalid() {
                break;
            }
            let Some(raw_instruction) = bytes.get(position..position + instruction_size) else {
                break;
            };
            let Ok(position_rva) = u32::try_from(position) else {
                break;
            };
            let Some(instruction_rva) = begin_rva.checked_add(position_rva) else {
                break;
            };
            let Ok(instruction_size) = u8::try_from(instruction_size) else {
                break;
            };

            if let Some(reference) = decode_data_reference(
                begin_rva,
                instruction_rva,
                instruction_size,
                &instruction,
                raw_instruction,
                &target_context,
            ) {
                if !insert_bounded(&mut data_references, reference, MAX_DATA_REFERENCES) {
                    data_reference_scan_truncated = true;
                }
            }

            // Calls and data references share this decode pass, but their
            // retention caps are independent. Reaching either cap must not
            // hide whether the other relationship set also truncated.
            if let Some(target) = decode_call_target(&instruction, raw_instruction, &target_context)
            {
                let call = PeDirectCall {
                    caller_rva: begin_rva,
                    call_site_rva: instruction_rva,
                    instruction_size,
                    target,
                };
                if !insert_bounded(&mut direct_calls, call, MAX_DIRECT_CALLS) {
                    scan_truncated = true;
                }
            }
        }
    }

    let direct_calls = direct_calls.into_iter().collect::<Vec<_>>();
    let data_references = data_references.into_iter().collect::<Vec<_>>();
    let seeds = thunk_seeds(
        input.mapper,
        input.sections,
        input.entry_point_rva,
        input.exports,
        input.runtime_functions,
        &direct_calls,
        input.msvc_rtti_vftables,
    );
    let mut thunks = BTreeSet::new();
    for rva in seeds {
        let Ok(available) = input.mapper.contiguous_bytes(rva, "thunk instruction") else {
            continue;
        };
        let bytes = &available[..available.len().min(MAX_X86_INSTRUCTION_BYTES)];
        let Some(ip) = input.image_base.checked_add(u64::from(rva)) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let instruction_size = instruction.len();
        if instruction_size == 0 || !budget.consume(instruction_size) {
            scan_truncated = true;
            break;
        }
        if instruction.is_invalid() {
            continue;
        }
        let Some(raw_instruction) = bytes.get(..instruction_size) else {
            continue;
        };
        let Some(target) = decode_thunk_target(rva, &instruction, raw_instruction, &target_context)
        else {
            continue;
        };
        let Ok(instruction_size) = u8::try_from(instruction_size) else {
            continue;
        };
        let thunk = PeThunk {
            rva,
            instruction_size,
            target,
        };
        if !thunks.contains(&thunk) && thunks.len() == MAX_THUNKS {
            scan_truncated = true;
            break;
        }
        thunks.insert(thunk);
    }

    CodeRecovery {
        scan_truncated,
        data_reference_scan_truncated,
        direct_calls,
        data_references,
        thunks: thunks.into_iter().collect(),
    }
}

fn decode_data_reference(
    caller_rva: u32,
    instruction_rva: u32,
    instruction_size: u8,
    instruction: &Instruction,
    raw: &[u8],
    context: &TargetContext<'_, '_>,
) -> Option<PeDataReference> {
    let target_rva =
        rip_relative_target_rva(instruction, context.image_base, context.size_of_image)?;
    if is_modeled_iat_control_flow(instruction, raw, target_rva, context.import_iat_rvas) {
        return None;
    }
    if !is_backed_readable_initialized_data(context.mapper, context.sections, target_rva, 1) {
        return None;
    }
    Some(PeDataReference {
        caller_rva,
        instruction_rva,
        instruction_size,
        target_rva,
    })
}

fn rip_relative_target_rva(
    instruction: &Instruction,
    image_base: u64,
    size_of_image: u32,
) -> Option<u32> {
    (instruction.memory_base() == Register::RIP)
        .then(|| instruction.ip_rel_memory_address())
        .and_then(|target| va_to_rva(target, image_base, size_of_image))
}

fn is_modeled_iat_control_flow(
    instruction: &Instruction,
    raw: &[u8],
    target_rva: u32,
    import_iat_rvas: &BTreeSet<u32>,
) -> bool {
    let exact_iat_call =
        instruction.code() == Code::Call_rm64 && raw.len() == 6 && raw.starts_with(&[0xff, 0x15]);
    let exact_iat_jump =
        instruction.code() == Code::Jmp_rm64 && raw.len() == 6 && raw.starts_with(&[0xff, 0x25]);
    (exact_iat_call || exact_iat_jump) && import_iat_rvas.contains(&target_rva)
}

fn insert_bounded<T: Ord>(records: &mut BTreeSet<T>, value: T, limit: usize) -> bool {
    if records.contains(&value) {
        return true;
    }
    if records.len() >= limit {
        return false;
    }
    records.insert(value)
}

fn decode_call_target(
    instruction: &Instruction,
    raw: &[u8],
    context: &TargetContext<'_, '_>,
) -> Option<PeControlFlowTarget> {
    if instruction.code() == Code::Call_rel32_64 && raw.len() == 5 && raw[0] == 0xe8 {
        if instruction.near_branch_target() == instruction.next_ip() {
            return None;
        }
        let rva = va_to_rva(
            instruction.near_branch_target(),
            context.image_base,
            context.size_of_image,
        )?;
        return (context.runtime_targets.allows_function_target(rva)
            && is_backed_executable(context.mapper, context.sections, rva, 1))
        .then_some(PeControlFlowTarget::Function { rva });
    }
    if instruction.code() == Code::Call_rm64
        && raw.len() == 6
        && raw.starts_with(&[0xff, 0x15])
        && instruction.is_ip_rel_memory_operand()
    {
        let iat_rva = va_to_rva(
            instruction.ip_rel_memory_address(),
            context.image_base,
            context.size_of_image,
        )?;
        return context
            .import_iat_rvas
            .contains(&iat_rva)
            .then_some(PeControlFlowTarget::ImportIat { iat_rva });
    }
    None
}

fn decode_thunk_target(
    source_rva: u32,
    instruction: &Instruction,
    raw: &[u8],
    context: &TargetContext<'_, '_>,
) -> Option<PeControlFlowTarget> {
    let direct_jump =
        (instruction.code() == Code::Jmp_rel32_64 && raw.len() == 5 && raw[0] == 0xe9)
            || (instruction.code() == Code::Jmp_rel8_64 && raw.len() == 2 && raw[0] == 0xeb);
    if direct_jump {
        let rva = va_to_rva(
            instruction.near_branch_target(),
            context.image_base,
            context.size_of_image,
        )?;
        return (rva != source_rva
            && context.runtime_targets.allows_function_target(rva)
            && is_backed_executable(context.mapper, context.sections, rva, 1))
        .then_some(PeControlFlowTarget::Function { rva });
    }
    if instruction.code() == Code::Jmp_rm64
        && raw.len() == 6
        && raw.starts_with(&[0xff, 0x25])
        && instruction.is_ip_rel_memory_operand()
    {
        let iat_rva = va_to_rva(
            instruction.ip_rel_memory_address(),
            context.image_base,
            context.size_of_image,
        )?;
        return context
            .import_iat_rvas
            .contains(&iat_rva)
            .then_some(PeControlFlowTarget::ImportIat { iat_rva });
    }
    None
}

fn thunk_seeds(
    mapper: &RvaMap<'_>,
    sections: &[PeSection],
    entry_point_rva: u32,
    exports: &[PeExport],
    runtime_functions: &[RuntimeFunction],
    direct_calls: &[PeDirectCall],
    msvc_rtti_vftables: &[MsvcRttiVftable],
) -> BTreeSet<u32> {
    let mut seeds = BTreeSet::new();
    if entry_point_rva != 0 {
        insert_executable_seed(&mut seeds, mapper, sections, entry_point_rva);
    }
    for rva in runtime_functions.iter().map(|function| function.begin_rva) {
        insert_executable_seed(&mut seeds, mapper, sections, rva);
    }
    for rva in exports.iter().filter_map(|export| {
        (export.forwarded_to.is_none())
            .then_some(export.address_rva)
            .flatten()
    }) {
        insert_executable_seed(&mut seeds, mapper, sections, rva);
    }
    for rva in direct_calls.iter().filter_map(|call| match call.target {
        PeControlFlowTarget::Function { rva } => Some(rva),
        PeControlFlowTarget::ImportIat { .. } => None,
    }) {
        insert_executable_seed(&mut seeds, mapper, sections, rva);
    }
    for rva in msvc_rtti_vftables
        .iter()
        .flat_map(|vftable| vftable.virtual_function_rvas.iter().copied())
    {
        insert_executable_seed(&mut seeds, mapper, sections, rva);
    }
    seeds
}

pub(crate) fn validate_code_recovery(analysis: &PeAnalysis) -> Result<(), AnalysisError> {
    if analysis.direct_calls.len() > MAX_DIRECT_CALLS {
        return invalid("direct calls", "exceed the retained record cap");
    }
    if analysis.thunks.len() > MAX_THUNKS {
        return invalid("thunks", "exceed the retained record cap");
    }
    if !strictly_sorted(&analysis.direct_calls) {
        return invalid("direct calls", "must be strictly sorted and unique");
    }
    if !strictly_sorted(&analysis.thunks) {
        return invalid("thunks", "must be strictly sorted and unique");
    }

    let import_iat_rvas = import_iat_rvas(&analysis.imports);
    let runtime_targets = RuntimeTargetPolicy::new(&analysis.runtime_functions);
    let mut previous_call_site = None;
    for call in &analysis.direct_calls {
        let call_key = (call.caller_rva, call.call_site_rva);
        if previous_call_site == Some(call_key) {
            return invalid(
                "direct calls",
                "contain more than one target for one caller and call site",
            );
        }
        previous_call_site = Some(call_key);
        let call_end = call
            .call_site_rva
            .checked_add(u32::from(call.instruction_size))
            .ok_or(AnalysisError::ArithmeticOverflow(
                "direct-call instruction range",
            ))?;
        let matching_runtime_function = analysis.runtime_functions.iter().any(|function| {
            function.begin_rva == call.caller_rva
                && call.call_site_rva >= function.begin_rva
                && call_end <= function.end_rva
                && model_range_is_backed_executable(
                    analysis,
                    function.begin_rva,
                    function.end_rva - function.begin_rva,
                )
        });
        if !matching_runtime_function {
            return invalid(
                "direct call",
                "caller and call site do not lie in a fully backed matching runtime-function range",
            );
        }
        if matches!(call.target, PeControlFlowTarget::Function { rva } if rva == call_end) {
            return invalid(
                "direct-call target",
                "call-next encodings do not establish a distinct function target",
            );
        }
        validate_target(
            analysis,
            &import_iat_rvas,
            &runtime_targets,
            &call.target,
            "direct-call target",
        )?;
        let supported_size = match call.target {
            PeControlFlowTarget::Function { .. } => call.instruction_size == 5,
            PeControlFlowTarget::ImportIat { .. } => call.instruction_size == 6,
        };
        if !supported_size {
            return invalid(
                "direct-call instruction size",
                "does not match a supported E8 or FF15 encoding",
            );
        }
    }

    let seeds = model_thunk_seeds(analysis);
    let mut previous_rva = None;
    for thunk in &analysis.thunks {
        if previous_rva == Some(thunk.rva) {
            return invalid("thunks", "contain more than one record for a source RVA");
        }
        previous_rva = Some(thunk.rva);
        if !seeds.contains(&thunk.rva)
            || !model_range_is_backed_executable(
                analysis,
                thunk.rva,
                u32::from(thunk.instruction_size),
            )
        {
            return invalid(
                "thunk source",
                "is not a file-backed executable metadata or call target candidate",
            );
        }
        validate_target(
            analysis,
            &import_iat_rvas,
            &runtime_targets,
            &thunk.target,
            "thunk target",
        )?;
        let supported_size = match thunk.target {
            PeControlFlowTarget::Function { rva } => {
                if rva == thunk.rva {
                    return invalid("thunk target", "must differ from its source RVA");
                }
                matches!(thunk.instruction_size, 2 | 5)
            }
            PeControlFlowTarget::ImportIat { .. } => thunk.instruction_size == 6,
        };
        if !supported_size {
            return invalid(
                "thunk instruction size",
                "does not match a supported EB, E9, or FF25 encoding",
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_data_references(
    analysis: &PeAnalysis,
    data_references: &[PeDataReference],
) -> Result<(), AnalysisError> {
    if data_references.len() > MAX_DATA_REFERENCES {
        return invalid("data references", "exceed the retained record cap");
    }
    if !strictly_sorted(data_references) {
        return invalid("data references", "must be strictly sorted and unique");
    }

    let mut previous_instruction = None;
    for reference in data_references {
        let instruction_key = (reference.caller_rva, reference.instruction_rva);
        if previous_instruction == Some(instruction_key) {
            return invalid(
                "data references",
                "contain more than one target for one caller and instruction",
            );
        }
        previous_instruction = Some(instruction_key);

        if !(1..=MAX_X86_INSTRUCTION_BYTES).contains(&usize::from(reference.instruction_size)) {
            return invalid(
                "data-reference instruction size",
                "must be between one and fifteen bytes",
            );
        }
        let instruction_end = reference
            .instruction_rva
            .checked_add(u32::from(reference.instruction_size))
            .ok_or(AnalysisError::ArithmeticOverflow(
                "data-reference instruction range",
            ))?;
        let matching_runtime_function = analysis.runtime_functions.iter().any(|function| {
            function.begin_rva == reference.caller_rva
                && reference.instruction_rva >= function.begin_rva
                && instruction_end <= function.end_rva
        });
        if !matching_runtime_function
            || !model_range_is_backed_executable(
                analysis,
                reference.instruction_rva,
                u32::from(reference.instruction_size),
            )
        {
            return invalid(
                "data-reference source",
                "is not a fully backed executable instruction in its matching runtime function",
            );
        }
        if reference.target_rva >= analysis.size_of_image
            || !model_range_is_backed_readable_initialized_data(analysis, reference.target_rva, 1)
        {
            return invalid(
                "data-reference target",
                "is not fully backed readable initialized non-executable data in the image",
            );
        }
    }
    Ok(())
}

fn model_thunk_seeds(analysis: &PeAnalysis) -> BTreeSet<u32> {
    let mut seeds = BTreeSet::new();
    if analysis.entry_point_rva != 0 {
        seeds.insert(analysis.entry_point_rva);
    }
    seeds.extend(
        analysis
            .runtime_functions
            .iter()
            .map(|function| function.begin_rva),
    );
    seeds.extend(analysis.exports.iter().filter_map(|export| {
        (export.forwarded_to.is_none())
            .then_some(export.address_rva)
            .flatten()
            .filter(|rva| model_range_is_backed_executable(analysis, *rva, 1))
    }));
    seeds.extend(
        analysis
            .direct_calls
            .iter()
            .filter_map(|call| match call.target {
                PeControlFlowTarget::Function { rva } => Some(rva),
                PeControlFlowTarget::ImportIat { .. } => None,
            }),
    );
    seeds.extend(
        analysis
            .msvc_rtti_vftables
            .iter()
            .flat_map(|vftable| vftable.virtual_function_rvas.iter().copied()),
    );
    seeds
}

fn validate_target(
    analysis: &PeAnalysis,
    import_iat_rvas: &BTreeSet<u32>,
    runtime_targets: &RuntimeTargetPolicy,
    target: &PeControlFlowTarget,
    field: &'static str,
) -> Result<(), AnalysisError> {
    match *target {
        PeControlFlowTarget::Function { rva } => {
            if !runtime_targets.allows_function_target(rva) {
                return invalid(
                    field,
                    "internal endpoint lies inside runtime-function metadata but is not a runtime-function begin",
                );
            }
            if !model_range_is_backed_executable(analysis, rva, 1) {
                return invalid(
                    field,
                    "internal endpoint is not file-backed executable data",
                );
            }
        }
        PeControlFlowTarget::ImportIat { iat_rva } => {
            if !import_iat_rvas.contains(&iat_rva) {
                return invalid(
                    field,
                    "does not match an exact parsed import-address-table slot",
                );
            }
        }
    }
    Ok(())
}

fn import_iat_rvas(imports: &[PeImportLibrary]) -> BTreeSet<u32> {
    imports
        .iter()
        .flat_map(|library| library.entries.iter().map(|entry| entry.iat_rva))
        .collect()
}

fn insert_executable_seed(
    seeds: &mut BTreeSet<u32>,
    mapper: &RvaMap<'_>,
    sections: &[PeSection],
    rva: u32,
) {
    if is_backed_executable(mapper, sections, rva, 1) {
        seeds.insert(rva);
    }
}

fn is_backed_executable(
    mapper: &RvaMap<'_>,
    sections: &[PeSection],
    rva: u32,
    size: usize,
) -> bool {
    if size == 0 || !mapper.is_backed(rva, size) {
        return false;
    }
    let Ok(size_u32) = u32::try_from(size) else {
        return false;
    };
    let Some(last_rva) = rva.checked_add(size_u32 - 1) else {
        return false;
    };
    let start_section = section_for_rva(rva, sections);
    let end_section = section_for_rva(last_rva, sections);
    start_section.map(|(index, _)| index) == end_section.map(|(index, _)| index)
        && start_section
            .is_some_and(|(_, section)| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
}

fn is_backed_readable_initialized_data(
    mapper: &RvaMap<'_>,
    sections: &[PeSection],
    rva: u32,
    size: usize,
) -> bool {
    if size == 0 || !mapper.is_backed(rva, size) {
        return false;
    }
    let Ok(size_u32) = u32::try_from(size) else {
        return false;
    };
    sections.iter().any(|section| {
        is_readable_initialized_non_executable(section.characteristics)
            && section_has_file_backed_range(section, rva, size_u32)
    })
}

pub(crate) fn model_range_is_backed_executable(analysis: &PeAnalysis, rva: u32, size: u32) -> bool {
    if size == 0 {
        return false;
    }
    let Some(end) = u64::from(rva).checked_add(u64::from(size)) else {
        return false;
    };
    analysis.sections.iter().any(|section| {
        let start = u64::from(section.virtual_address);
        let backed_end = start.saturating_add(u64::from(section.raw_data_size));
        section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && u64::from(rva) >= start
            && end <= backed_end
    })
}

pub(crate) fn model_range_is_backed_readable_initialized_data(
    analysis: &PeAnalysis,
    rva: u32,
    size: u32,
) -> bool {
    analysis.sections.iter().any(|section| {
        is_readable_initialized_non_executable(section.characteristics)
            && section_has_file_backed_range(section, rva, size)
    })
}

const fn is_readable_initialized_non_executable(characteristics: u32) -> bool {
    characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
        && characteristics & IMAGE_SCN_MEM_READ != 0
        && characteristics & IMAGE_SCN_MEM_EXECUTE == 0
}

fn section_has_file_backed_range(section: &PeSection, rva: u32, size: u32) -> bool {
    if size == 0 {
        return false;
    }
    let start = u64::from(section.virtual_address);
    let backed_end = start.saturating_add(u64::from(section.raw_data_size));
    let rva = u64::from(rva);
    rva >= start
        && rva
            .checked_add(u64::from(size))
            .is_some_and(|end| end <= backed_end)
}

fn va_to_rva(va: u64, image_base: u64, size_of_image: u32) -> Option<u32> {
    let rva = va.checked_sub(image_base)?;
    let rva = u32::try_from(rva).ok()?;
    (rva < size_of_image).then_some(rva)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
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

    const TEST_IMAGE_BASE: u64 = 0x0000_0001_4000_0000;

    fn decode_one(bytes: &[u8], instruction_rva: u32) -> Instruction {
        let ip = TEST_IMAGE_BASE + u64::from(instruction_rva);
        let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        assert!(!instruction.is_invalid(), "test instruction must decode");
        assert_eq!(instruction.len(), bytes.len());
        instruction
    }

    #[test]
    fn decode_budget_accepts_the_exact_limits_and_rejects_the_next_item() {
        let mut byte_budget = DecodeBudget {
            bytes: MAX_DECODED_BYTES - 1,
            instructions: 0,
        };
        assert!(byte_budget.consume(1));
        assert!(!byte_budget.consume(1));
        assert_eq!(byte_budget.bytes, MAX_DECODED_BYTES);
        assert_eq!(byte_budget.instructions, 1);

        let mut instruction_budget = DecodeBudget {
            bytes: 0,
            instructions: MAX_DECODED_INSTRUCTIONS - 1,
        };
        assert!(instruction_budget.consume(1));
        assert!(!instruction_budget.consume(1));
        assert_eq!(instruction_budget.bytes, 1);
        assert_eq!(instruction_budget.instructions, MAX_DECODED_INSTRUCTIONS);
    }

    #[test]
    fn retained_record_caps_bound_graph_growth() {
        assert_eq!(MAX_DIRECT_CALLS, 8_192);
        assert_eq!(MAX_DATA_REFERENCES, 32_768);
        assert_eq!(MAX_THUNKS, 4_096);
    }

    #[test]
    fn rip_relative_lea_load_and_store_resolve_positive_displacements() {
        for opcode in [0x8d, 0x8b, 0x89] {
            let instruction = decode_one(&[0x48, opcode, 0x05, 0xf9, 0x0f, 0, 0], 0x1000);
            assert_eq!(
                rip_relative_target_rva(&instruction, TEST_IMAGE_BASE, 0x4000),
                Some(0x2000)
            );
        }
    }

    #[test]
    fn rip_relative_data_target_resolves_a_negative_displacement() {
        let instruction = decode_one(&[0x48, 0x8b, 0x05, 0xf9, 0xef, 0xff, 0xff], 0x3000);
        assert_eq!(
            rip_relative_target_rva(&instruction, TEST_IMAGE_BASE, 0x4000),
            Some(0x2000)
        );
    }

    #[test]
    fn data_targets_reject_non_rip_and_out_of_image_operands() {
        let register_relative = decode_one(&[0x48, 0x8b, 0x03], 0x1000);
        assert_eq!(
            rip_relative_target_rva(&register_relative, TEST_IMAGE_BASE, 0x4000),
            None
        );

        let eip_relative = decode_one(&[0x67, 0x48, 0x8b, 0x05, 0xf8, 0x0f, 0, 0], 0x1000);
        assert_eq!(eip_relative.memory_base(), Register::EIP);
        assert_eq!(
            rip_relative_target_rva(&eip_relative, TEST_IMAGE_BASE, 0x4000),
            None
        );

        let image_end = decode_one(&[0x48, 0x8b, 0x05, 0xf9, 0x0f, 0, 0], 0x1000);
        assert_eq!(
            rip_relative_target_rva(&image_end, TEST_IMAGE_BASE, 0x2000),
            None
        );
        let before_image = decode_one(&[0x48, 0x8b, 0x05, 0xf8, 0xff, 0xff, 0xff], 0);
        assert_eq!(
            rip_relative_target_rva(&before_image, TEST_IMAGE_BASE, 0x4000),
            None
        );
    }

    #[test]
    fn exact_call_and_jump_iat_operands_are_not_data_references() {
        let import_iat_rvas = BTreeSet::from([0x2000]);
        let call = decode_one(&[0xff, 0x15, 0xfa, 0x0f, 0, 0], 0x1000);
        let jump = decode_one(&[0xff, 0x25, 0xfa, 0x0f, 0, 0], 0x1000);
        let load = decode_one(&[0x48, 0x8b, 0x05, 0xf9, 0x0f, 0, 0], 0x1000);

        assert_eq!(
            rip_relative_target_rva(&call, TEST_IMAGE_BASE, 0x4000),
            Some(0x2000)
        );
        assert_eq!(
            rip_relative_target_rva(&jump, TEST_IMAGE_BASE, 0x4000),
            Some(0x2000)
        );
        assert!(is_modeled_iat_control_flow(
            &call,
            &[0xff, 0x15, 0xfa, 0x0f, 0, 0],
            0x2000,
            &import_iat_rvas
        ));
        assert!(is_modeled_iat_control_flow(
            &jump,
            &[0xff, 0x25, 0xfa, 0x0f, 0, 0],
            0x2000,
            &import_iat_rvas
        ));
        assert!(!is_modeled_iat_control_flow(
            &load,
            &[0x48, 0x8b, 0x05, 0xf9, 0x0f, 0, 0],
            0x2000,
            &import_iat_rvas
        ));
        assert!(!is_modeled_iat_control_flow(
            &call,
            &[0xff, 0x15, 0xfa, 0x0f, 0, 0],
            0x2001,
            &import_iat_rvas
        ));
    }

    #[test]
    fn data_sections_must_be_readable_initialized_and_non_executable() {
        let eligible = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        assert!(is_readable_initialized_non_executable(eligible));
        assert!(!is_readable_initialized_non_executable(
            eligible | IMAGE_SCN_MEM_EXECUTE
        ));
        assert!(!is_readable_initialized_non_executable(IMAGE_SCN_MEM_READ));
        assert!(!is_readable_initialized_non_executable(
            IMAGE_SCN_CNT_INITIALIZED_DATA
        ));

        let section = PeSection {
            name: ".rdata".to_owned(),
            raw_name: [0; 8],
            virtual_address: 0x2000,
            virtual_size: 0x200,
            raw_data_offset: 0x400,
            raw_data_size: 0x100,
            characteristics: eligible,
        };
        assert!(section_has_file_backed_range(&section, 0x2000, 1));
        assert!(section_has_file_backed_range(&section, 0x20ff, 1));
        assert!(!section_has_file_backed_range(&section, 0x2100, 1));
        assert!(!section_has_file_backed_range(&section, 0x20ff, 2));
        assert!(!section_has_file_backed_range(&section, 0x2000, 0));
    }

    #[test]
    fn bounded_relationships_retain_a_deterministic_prefix_independently() {
        let retain = || {
            let mut records = BTreeSet::new();
            let mut truncated = false;
            for value in [10, 10, 20, 30, 40] {
                if !insert_bounded(&mut records, value, 2) {
                    truncated = true;
                }
            }
            (records, truncated)
        };
        assert_eq!(retain(), retain());
        assert_eq!(retain(), (BTreeSet::from([10, 20]), true));

        let mut calls = BTreeSet::new();
        let mut data = BTreeSet::new();
        let mut call_truncated = false;
        let mut data_truncated = false;
        for index in 0..3 {
            if !insert_bounded(&mut calls, index, 1) {
                call_truncated = true;
            }
            if index != 0 && !insert_bounded(&mut data, index, 2) {
                data_truncated = true;
            }
        }
        assert!(call_truncated);
        assert!(!data_truncated);
        assert_eq!(data, BTreeSet::from([1, 2]));
    }

    #[test]
    fn runtime_target_policy_allows_starts_and_outside_addresses_only() {
        let runtime_functions = [
            RuntimeFunction {
                begin_rva: 0x1000,
                end_rva: 0x1100,
                unwind_info_rva: 0x2000,
                table_index: 0,
            },
            RuntimeFunction {
                begin_rva: 0x1080,
                end_rva: 0x1180,
                unwind_info_rva: 0x2004,
                table_index: 1,
            },
        ];
        let policy = RuntimeTargetPolicy::new(&runtime_functions);

        assert!(policy.allows_function_target(0x1000));
        assert!(policy.allows_function_target(0x1080));
        assert!(!policy.allows_function_target(0x107f));
        assert!(!policy.allows_function_target(0x1100));
        assert!(policy.allows_function_target(0x1180));
    }

    #[test]
    fn virtual_addresses_must_resolve_inside_the_image() {
        let image_base = 0x0000_0001_4000_0000;
        assert_eq!(
            va_to_rva(image_base + 0x1234, image_base, 0x2000),
            Some(0x1234)
        );
        assert_eq!(va_to_rva(image_base - 1, image_base, 0x2000), None);
        assert_eq!(va_to_rva(image_base + 0x2000, image_base, 0x2000), None);
    }
}
