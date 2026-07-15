use std::{
    cmp::Reverse,
    collections::{BTreeSet, BinaryHeap, HashMap, HashSet},
};

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::{
    AnalysisError, MsvcRttiVftable, PeAnalysis, PeControlFlowTarget, PeDataReference, PeDirectCall,
    PeExport, PeImportLibrary, PeSection, PeThunk, RuntimeFunction,
    pe::{RvaMap, section_for_rva},
};

const MAX_DECODED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DECODED_INSTRUCTIONS: u64 = 1_000_000;
const MAX_CONTROL_FLOW_BLOCK_STARTS: usize = 262_144;
const MAX_DIRECT_CALLS: usize = 8_192;
const MAX_DATA_REFERENCES: usize = 32_768;
const MAX_THUNKS: usize = 4_096;
const MAX_X86_INSTRUCTION_BYTES: usize = 15;

const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

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

#[derive(Default)]
struct BlockBudget {
    starts: usize,
}

impl BlockBudget {
    fn consume(&mut self) -> bool {
        if self.starts >= MAX_CONTROL_FLOW_BLOCK_STARTS {
            return false;
        }
        self.starts += 1;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueResult {
    Queued,
    AlreadyKnown,
    LimitExceeded,
    AllocationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodedLocation {
    InstructionStart,
    InstructionInterior,
}

#[derive(Default)]
struct FunctionTraversal {
    pending: BinaryHeap<Reverse<u32>>,
    discovered: HashSet<u32>,
    instruction_lengths: HashMap<u32, u8>,
}

impl FunctionTraversal {
    fn queue(&mut self, rva: u32, budget: &mut BlockBudget) -> QueueResult {
        if self.discovered.contains(&rva) || self.decoded_location(rva).is_some() {
            return QueueResult::AlreadyKnown;
        }
        if budget.starts >= MAX_CONTROL_FLOW_BLOCK_STARTS {
            return QueueResult::LimitExceeded;
        }
        if self.pending.try_reserve(1).is_err() || self.discovered.try_reserve(1).is_err() {
            return QueueResult::AllocationFailed;
        }
        if !budget.consume() {
            return QueueResult::LimitExceeded;
        }
        self.discovered.insert(rva);
        self.pending.push(Reverse(rva));
        QueueResult::Queued
    }

    fn pop(&mut self) -> Option<u32> {
        self.pending.pop().map(|Reverse(rva)| rva)
    }

    fn decoded_location(&self, rva: u32) -> Option<DecodedLocation> {
        if self.instruction_lengths.contains_key(&rva) {
            return Some(DecodedLocation::InstructionStart);
        }
        for delta in 1..MAX_X86_INSTRUCTION_BYTES {
            let Some(start) = rva.checked_sub(u32::try_from(delta).ok()?) else {
                break;
            };
            if self
                .instruction_lengths
                .get(&start)
                .is_some_and(|length| usize::from(*length) > delta)
            {
                return Some(DecodedLocation::InstructionInterior);
            }
        }
        None
    }

    fn retain_instruction(&mut self, rva: u32, length: u8) -> Result<(), ()> {
        debug_assert!(length != 0);
        debug_assert!(self.decoded_location(rva).is_none());
        let end = rva.checked_add(u32::from(length)).ok_or(())?;
        for interior in rva.checked_add(1).ok_or(())?..end {
            if self.instruction_lengths.contains_key(&interior) {
                return Err(());
            }
        }
        self.instruction_lengths.try_reserve(1).map_err(|_| ())?;
        self.instruction_lengths.insert(rva, length);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraversalAction {
    Continue,
    ConditionalBranch { target: u64 },
    UnconditionalBranch { target: u64 },
    Stop,
}

fn traversal_action(instruction: &Instruction) -> TraversalAction {
    let mnemonic = instruction.mnemonic();
    let is_near_branch = matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    ) || matches!(
        instruction.op1_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    if mnemonic == Mnemonic::Jmp {
        return if is_near_branch {
            TraversalAction::UnconditionalBranch {
                target: instruction.near_branch_target(),
            }
        } else {
            TraversalAction::Stop
        };
    }
    if is_near_branch && is_conditional_branch_mnemonic(mnemonic) {
        return TraversalAction::ConditionalBranch {
            target: instruction.near_branch_target(),
        };
    }
    if mnemonic == Mnemonic::Jmpe || is_terminal_mnemonic(mnemonic) {
        return TraversalAction::Stop;
    }
    TraversalAction::Continue
}

const fn is_conditional_branch_mnemonic(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Jcxz
            | Mnemonic::Je
            | Mnemonic::Jecxz
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jkzd
            | Mnemonic::Jknzd
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jne
            | Mnemonic::Jno
            | Mnemonic::Jnp
            | Mnemonic::Jns
            | Mnemonic::Jo
            | Mnemonic::Jp
            | Mnemonic::Jrcxz
            | Mnemonic::Js
            | Mnemonic::Loop
            | Mnemonic::Loope
            | Mnemonic::Loopne
            | Mnemonic::Xbegin
    )
}

const fn is_terminal_mnemonic(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Erets
            | Mnemonic::Eretu
            | Mnemonic::Hlt
            | Mnemonic::Int
            | Mnemonic::Int1
            | Mnemonic::Int3
            | Mnemonic::Into
            | Mnemonic::Iret
            | Mnemonic::Iretd
            | Mnemonic::Iretq
            | Mnemonic::Rdm
            | Mnemonic::Ret
            | Mnemonic::Retf
            | Mnemonic::Rsm
            | Mnemonic::Seamret
            | Mnemonic::Skinit
            | Mnemonic::Sysexit
            | Mnemonic::Sysret
            | Mnemonic::Ud0
            | Mnemonic::Ud1
            | Mnemonic::Ud2
            | Mnemonic::Uiret
            | Mnemonic::Xabort
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeScanResult {
    Complete,
    AllocationFailed,
    DecodeBudgetExceeded,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct RelationshipRetention {
    scan_truncated: bool,
    data_reference_scan_truncated: bool,
}

#[allow(clippy::too_many_arguments)]
fn scan_runtime_function(
    begin_rva: u32,
    end_rva: u32,
    bytes: &[u8],
    context: &TargetContext<'_, '_>,
    decode_budget: &mut DecodeBudget,
    block_budget: &mut BlockBudget,
    direct_calls: &mut BTreeSet<PeDirectCall>,
    data_references: &mut BTreeSet<PeDataReference>,
    scan_truncated: &mut bool,
    data_reference_scan_truncated: &mut bool,
) -> RuntimeScanResult {
    let mut traversal = FunctionTraversal::default();
    match traversal.queue(begin_rva, block_budget) {
        QueueResult::Queued => {}
        QueueResult::LimitExceeded => {
            *scan_truncated = true;
            *data_reference_scan_truncated = true;
            return RuntimeScanResult::Complete;
        }
        QueueResult::AllocationFailed => return RuntimeScanResult::AllocationFailed,
        QueueResult::AlreadyKnown => unreachable!("fresh traversal has no queued block"),
    }

    while let Some(block_rva) = traversal.pop() {
        // A target at an existing instruction start is a normal loop or merge.
        // A target in an instruction interior is malformed or deliberately
        // overlapping. In either case it must not start another decoder path.
        if traversal.decoded_location(block_rva).is_some() {
            continue;
        }
        let Some(block_delta) = block_rva.checked_sub(begin_rva) else {
            continue;
        };
        let Ok(block_offset) = usize::try_from(block_delta) else {
            continue;
        };
        let Some(block_bytes) = bytes.get(block_offset..) else {
            continue;
        };
        let Some(ip) = context.image_base.checked_add(u64::from(block_rva)) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, block_bytes, ip, DecoderOptions::NONE);

        while decoder.can_decode() {
            let position = decoder.position();
            let Ok(position_rva) = u32::try_from(position) else {
                break;
            };
            let Some(instruction_rva) = block_rva.checked_add(position_rva) else {
                break;
            };
            if instruction_rva >= end_rva || traversal.decoded_location(instruction_rva).is_some() {
                break;
            }

            let instruction = decoder.decode();
            let instruction_size = instruction.len();
            if instruction_size == 0 {
                break;
            }
            if !decode_budget.consume(instruction_size) {
                return RuntimeScanResult::DecodeBudgetExceeded;
            }
            let Ok(instruction_size_u8) = u8::try_from(instruction_size) else {
                break;
            };
            let Some(instruction_end) = instruction_rva.checked_add(u32::from(instruction_size_u8))
            else {
                break;
            };
            if instruction_end > end_rva {
                break;
            }
            let Some(raw_start) = block_offset.checked_add(position) else {
                break;
            };
            let Some(raw_end) = raw_start.checked_add(instruction_size) else {
                break;
            };
            let Some(raw_instruction) = bytes.get(raw_start..raw_end) else {
                break;
            };

            // A newly reached path may decode backwards into an instruction
            // that was retained by another path. Reject that path atomically.
            if traversal
                .retain_instruction(instruction_rva, instruction_size_u8)
                .is_err()
            {
                if (1..instruction_size)
                    .filter_map(|delta| instruction_rva.checked_add(u32::try_from(delta).ok()?))
                    .any(|rva| traversal.instruction_lengths.contains_key(&rva))
                {
                    break;
                }
                return RuntimeScanResult::AllocationFailed;
            }
            if instruction.is_invalid() {
                break;
            }

            let reference = decode_data_reference(
                begin_rva,
                instruction_rva,
                instruction_size_u8,
                &instruction,
                raw_instruction,
                context,
            );

            // Calls and data references share this decode pass, but their
            // retention caps are independent except that a resolved pointer
            // call is meaningful only while its exact slot reference survives.
            let call = decode_call_target(&instruction, raw_instruction, context).map(|target| {
                PeDirectCall {
                    caller_rva: begin_rva,
                    call_site_rva: instruction_rva,
                    instruction_size: instruction_size_u8,
                    target,
                }
            });
            let retention = retain_instruction_relationships(
                direct_calls,
                data_references,
                call,
                reference,
                MAX_DIRECT_CALLS,
                MAX_DATA_REFERENCES,
            );
            *scan_truncated |= retention.scan_truncated;
            *data_reference_scan_truncated |= retention.data_reference_scan_truncated;

            let queue_target = |target: u64,
                                traversal: &mut FunctionTraversal,
                                block_budget: &mut BlockBudget|
             -> QueueResult {
                let Some(target_rva) = va_to_rva(target, context.image_base, context.size_of_image)
                else {
                    return QueueResult::AlreadyKnown;
                };
                if !(begin_rva..end_rva).contains(&target_rva)
                    || !is_backed_executable(context.mapper, context.sections, target_rva, 1)
                {
                    return QueueResult::AlreadyKnown;
                }
                traversal.queue(target_rva, block_budget)
            };
            let queue_result = match traversal_action(&instruction) {
                TraversalAction::Continue => continue,
                TraversalAction::ConditionalBranch { target } => {
                    Some((queue_target(target, &mut traversal, block_budget), false))
                }
                TraversalAction::UnconditionalBranch { target } => {
                    Some((queue_target(target, &mut traversal, block_budget), true))
                }
                TraversalAction::Stop => break,
            };
            let Some((queue_result, stop_block)) = queue_result else {
                continue;
            };
            match queue_result {
                QueueResult::Queued | QueueResult::AlreadyKnown => {}
                QueueResult::LimitExceeded => {
                    *scan_truncated = true;
                    *data_reference_scan_truncated = true;
                }
                QueueResult::AllocationFailed => return RuntimeScanResult::AllocationFailed,
            }
            if stop_block {
                break;
            }
        }
    }

    RuntimeScanResult::Complete
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

    let mut ranges = Vec::new();
    if ranges
        .try_reserve_exact(input.runtime_functions.len())
        .is_err()
    {
        scan_truncated = true;
        data_reference_scan_truncated = true;
    } else {
        ranges.extend(
            input
                .runtime_functions
                .iter()
                .map(|function| (function.begin_rva, function.end_rva)),
        );
        ranges.sort_unstable();
        ranges.dedup();
    }

    let mut block_budget = BlockBudget::default();
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
        match scan_runtime_function(
            begin_rva,
            end_rva,
            bytes,
            &target_context,
            &mut budget,
            &mut block_budget,
            &mut direct_calls,
            &mut data_references,
            &mut scan_truncated,
            &mut data_reference_scan_truncated,
        ) {
            RuntimeScanResult::Complete => {}
            RuntimeScanResult::AllocationFailed | RuntimeScanResult::DecodeBudgetExceeded => {
                scan_truncated = true;
                data_reference_scan_truncated = true;
                break 'runtime_functions;
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
    let exact_iat_call = instruction.code() == Code::Call_rm64
        && has_exact_rip_relative_indirect_encoding(raw, 0x15);
    let exact_iat_jump =
        instruction.code() == Code::Jmp_rm64 && has_exact_rip_relative_indirect_encoding(raw, 0x25);
    (exact_iat_call || exact_iat_jump) && import_iat_rvas.contains(&target_rva)
}

fn has_exact_rip_relative_indirect_encoding(raw: &[u8], modrm: u8) -> bool {
    matches!(raw, [0xff, actual, _, _, _, _] if *actual == modrm)
        || matches!(raw, [0x48, 0xff, actual, _, _, _, _] if *actual == modrm)
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

fn retain_instruction_relationships(
    direct_calls: &mut BTreeSet<PeDirectCall>,
    data_references: &mut BTreeSet<PeDataReference>,
    call: Option<PeDirectCall>,
    reference: Option<PeDataReference>,
    direct_call_limit: usize,
    data_reference_limit: usize,
) -> RelationshipRetention {
    let mut result = RelationshipRetention::default();
    let reference_retained = reference.as_ref().is_some_and(|reference| {
        insert_bounded(data_references, reference.clone(), data_reference_limit)
    });
    if reference.is_some() && !reference_retained {
        result.data_reference_scan_truncated = true;
    }

    let Some(call) = call else {
        return result;
    };
    let required_reference_retained = match call.target {
        PeControlFlowTarget::FunctionPointer { slot_rva, .. } => {
            reference_retained
                && reference.as_ref().is_some_and(|reference| {
                    reference.caller_rva == call.caller_rva
                        && reference.instruction_rva == call.call_site_rva
                        && reference.instruction_size == call.instruction_size
                        && reference.target_rva == slot_rva
                })
        }
        PeControlFlowTarget::Function { .. } | PeControlFlowTarget::ImportIat { .. } => true,
    };
    if !required_reference_retained || !insert_bounded(direct_calls, call, direct_call_limit) {
        result.scan_truncated = true;
    }
    result
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
        && has_exact_rip_relative_indirect_encoding(raw, 0x15)
        && instruction.is_ip_rel_memory_operand()
    {
        let slot_rva = va_to_rva(
            instruction.ip_rel_memory_address(),
            context.image_base,
            context.size_of_image,
        )?;
        if context.import_iat_rvas.contains(&slot_rva) {
            return Some(PeControlFlowTarget::ImportIat { iat_rva: slot_rva });
        }
        if !is_backed_read_only_initialized_data(context.mapper, context.sections, slot_rva, 8) {
            return None;
        }
        let target_va = context
            .mapper
            .read_u64(slot_rva, "read-only function-pointer slot")?;
        if target_va == instruction.next_ip() {
            return None;
        }
        let rva = va_to_rva(target_va, context.image_base, context.size_of_image)?;
        return (context.runtime_targets.allows_function_target(rva)
            && is_backed_executable(context.mapper, context.sections, rva, 1))
        .then_some(PeControlFlowTarget::FunctionPointer { slot_rva, rva });
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
        && has_exact_rip_relative_indirect_encoding(raw, 0x25)
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
        PeControlFlowTarget::Function { rva }
        | PeControlFlowTarget::FunctionPointer { rva, .. } => Some(rva),
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
        if matches!(
            call.target,
            PeControlFlowTarget::Function { rva }
                | PeControlFlowTarget::FunctionPointer { rva, .. }
                if rva == call_end
        ) {
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
        if let PeControlFlowTarget::FunctionPointer { slot_rva, .. } = call.target {
            let expected_reference = PeDataReference {
                caller_rva: call.caller_rva,
                instruction_rva: call.call_site_rva,
                instruction_size: call.instruction_size,
                target_rva: slot_rva,
            };
            if analysis
                .data_references
                .binary_search(&expected_reference)
                .is_err()
            {
                return invalid(
                    "direct-call data reference",
                    "read-only function-pointer call lacks its exact same-site slot reference",
                );
            }
        }
        let supported_size = match call.target {
            PeControlFlowTarget::Function { .. } => call.instruction_size == 5,
            PeControlFlowTarget::ImportIat { .. } => matches!(call.instruction_size, 6 | 7),
            PeControlFlowTarget::FunctionPointer { .. } => {
                matches!(call.instruction_size, 6 | 7)
            }
        };
        if !supported_size {
            return invalid(
                "direct-call instruction size",
                "does not match a supported E8, FF15, or REX.W-prefixed FF15 encoding",
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
        if matches!(thunk.target, PeControlFlowTarget::FunctionPointer { .. }) {
            return invalid(
                "thunk target",
                "read-only function-pointer resolution is not supported for thunks",
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
            PeControlFlowTarget::ImportIat { .. } => matches!(thunk.instruction_size, 6 | 7),
            PeControlFlowTarget::FunctionPointer { .. } => false,
        };
        if !supported_size {
            return invalid(
                "thunk instruction size",
                "does not match a supported EB, E9, FF25, or REX.W-prefixed FF25 encoding",
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
                PeControlFlowTarget::Function { rva }
                | PeControlFlowTarget::FunctionPointer { rva, .. } => Some(rva),
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
        PeControlFlowTarget::FunctionPointer { slot_rva, rva } => {
            if import_iat_rvas.contains(&slot_rva) {
                return invalid(
                    field,
                    "read-only function-pointer slot collides with an exact parsed import-address-table slot",
                );
            }
            if !model_range_is_backed_read_only_initialized_data(analysis, slot_rva, 8) {
                return invalid(
                    field,
                    "function-pointer slot is not eight fully backed bytes of read-only initialized non-executable data",
                );
            }
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

fn is_backed_read_only_initialized_data(
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
        is_read_only_initialized_non_executable(section.characteristics)
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

pub(crate) fn model_range_is_backed_read_only_initialized_data(
    analysis: &PeAnalysis,
    rva: u32,
    size: u32,
) -> bool {
    analysis.sections.iter().any(|section| {
        is_read_only_initialized_non_executable(section.characteristics)
            && section_has_file_backed_range(section, rva, size)
    })
}

const fn is_readable_initialized_non_executable(characteristics: u32) -> bool {
    characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
        && characteristics & IMAGE_SCN_MEM_READ != 0
        && characteristics & IMAGE_SCN_MEM_EXECUTE == 0
}

const fn is_read_only_initialized_non_executable(characteristics: u32) -> bool {
    is_readable_initialized_non_executable(characteristics)
        && characteristics & IMAGE_SCN_MEM_WRITE == 0
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
        assert_eq!(MAX_CONTROL_FLOW_BLOCK_STARTS, 262_144);
        assert_eq!(MAX_DIRECT_CALLS, 8_192);
        assert_eq!(MAX_DATA_REFERENCES, 32_768);
        assert_eq!(MAX_THUNKS, 4_096);
    }

    #[test]
    fn block_worklist_is_smallest_first_deduplicated_and_exactly_bounded() {
        let mut traversal = FunctionTraversal::default();
        let mut budget = BlockBudget::default();
        assert_eq!(traversal.queue(0x1030, &mut budget), QueueResult::Queued);
        assert_eq!(traversal.queue(0x1010, &mut budget), QueueResult::Queued);
        assert_eq!(traversal.queue(0x1020, &mut budget), QueueResult::Queued);
        assert_eq!(
            traversal.queue(0x1010, &mut budget),
            QueueResult::AlreadyKnown
        );
        assert_eq!(traversal.pop(), Some(0x1010));
        assert_eq!(traversal.pop(), Some(0x1020));
        assert_eq!(traversal.pop(), Some(0x1030));
        assert_eq!(traversal.pop(), None);

        let mut exact = FunctionTraversal::default();
        let mut exact_budget = BlockBudget {
            starts: MAX_CONTROL_FLOW_BLOCK_STARTS - 1,
        };
        assert_eq!(exact.queue(0x2000, &mut exact_budget), QueueResult::Queued);
        assert_eq!(exact_budget.starts, MAX_CONTROL_FLOW_BLOCK_STARTS);
        assert_eq!(
            exact.queue(0x2010, &mut exact_budget),
            QueueResult::LimitExceeded
        );
        assert_eq!(
            exact.queue(0x2000, &mut exact_budget),
            QueueResult::AlreadyKnown
        );
    }

    #[test]
    fn decoded_instruction_map_distinguishes_boundaries_and_interiors() {
        let mut traversal = FunctionTraversal::default();
        traversal
            .retain_instruction(0x1000, 5)
            .expect("first instruction is retained");
        assert_eq!(
            traversal.decoded_location(0x1000),
            Some(DecodedLocation::InstructionStart)
        );
        assert_eq!(
            traversal.decoded_location(0x1001),
            Some(DecodedLocation::InstructionInterior)
        );
        assert_eq!(
            traversal.decoded_location(0x1004),
            Some(DecodedLocation::InstructionInterior)
        );
        assert_eq!(traversal.decoded_location(0x1005), None);
        traversal
            .retain_instruction(0x1005, 2)
            .expect("adjacent instruction is retained");

        assert!(
            traversal.retain_instruction(0x0fff, 2).is_err(),
            "a later-retained instruction start cannot become another instruction's interior"
        );
        let mut budget = BlockBudget::default();
        assert_eq!(
            traversal.queue(0x1002, &mut budget),
            QueueResult::AlreadyKnown,
            "an interior target is dropped without consuming traversal budget"
        );
        assert_eq!(budget.starts, 0);
    }

    #[test]
    fn traversal_actions_follow_direct_branches_and_stop_terminal_flow() {
        let conditional = decode_one(&[0x75, 0x02], 0x1000);
        assert_eq!(
            traversal_action(&conditional),
            TraversalAction::ConditionalBranch {
                target: TEST_IMAGE_BASE + 0x1004,
            }
        );

        let direct_jump = decode_one(&[0xeb, 0x02], 0x1000);
        assert_eq!(
            traversal_action(&direct_jump),
            TraversalAction::UnconditionalBranch {
                target: TEST_IMAGE_BASE + 0x1004,
            }
        );

        for bytes in [&[0xff, 0xe0][..], &[0xc3][..], &[0xcc][..]] {
            assert_eq!(
                traversal_action(&decode_one(bytes, 0x1000)),
                TraversalAction::Stop
            );
        }
        for (bytes, code, mnemonic) in [
            (&[0xf2, 0x0f, 0x01, 0xca][..], Code::Erets, Mnemonic::Erets),
            (&[0xf3, 0x0f, 0x01, 0xca][..], Code::Eretu, Mnemonic::Eretu),
        ] {
            let instruction = decode_one(bytes, 0x1000);
            assert_eq!(instruction.code(), code);
            assert_eq!(instruction.mnemonic(), mnemonic);
            assert_eq!(traversal_action(&instruction), TraversalAction::Stop);
        }
        for bytes in [&[0x90][..], &[0xe8, 0, 0, 0, 0][..], &[0xff, 0xd0][..]] {
            assert_eq!(
                traversal_action(&decode_one(bytes, 0x1000)),
                TraversalAction::Continue
            );
        }
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
        assert!(is_read_only_initialized_non_executable(eligible));
        assert!(!is_read_only_initialized_non_executable(
            eligible | IMAGE_SCN_MEM_WRITE
        ));
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
    fn pointer_call_retention_requires_its_reference_but_not_the_reverse() {
        let call = PeDirectCall {
            caller_rva: 0x1000,
            call_site_rva: 0x1010,
            instruction_size: 6,
            target: PeControlFlowTarget::FunctionPointer {
                slot_rva: 0x2001,
                rva: 0x1100,
            },
        };
        let reference = PeDataReference {
            caller_rva: 0x1000,
            instruction_rva: 0x1010,
            instruction_size: 6,
            target_rva: 0x2001,
        };

        let mut calls = BTreeSet::new();
        let mut references = BTreeSet::new();
        let result = retain_instruction_relationships(
            &mut calls,
            &mut references,
            Some(call.clone()),
            Some(reference.clone()),
            1,
            0,
        );
        assert_eq!(
            result,
            RelationshipRetention {
                scan_truncated: true,
                data_reference_scan_truncated: true,
            }
        );
        assert!(calls.is_empty());
        assert!(references.is_empty());

        let result = retain_instruction_relationships(
            &mut calls,
            &mut references,
            Some(call.clone()),
            Some(reference.clone()),
            0,
            1,
        );
        assert_eq!(
            result,
            RelationshipRetention {
                scan_truncated: true,
                data_reference_scan_truncated: false,
            }
        );
        assert!(calls.is_empty());
        assert_eq!(references, BTreeSet::from([reference.clone()]));

        let result = retain_instruction_relationships(
            &mut calls,
            &mut references,
            Some(call.clone()),
            Some(reference),
            1,
            1,
        );
        assert_eq!(result, RelationshipRetention::default());
        assert_eq!(calls, BTreeSet::from([call]));
        assert_eq!(references.len(), 1);
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
