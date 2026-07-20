//! Bounded, deterministic PlayStation 2 EE observer-site analysis.
//!
//! This pass reparses an exact ELF source, accepts only an explicitly selected
//! bundled R5900 profile, and never executes target code. It scans sparse ELF
//! mappings in guest-address order and owns every value in its report.

use std::collections::{BTreeMap, BTreeSet};

use resymbol_core::BinaryIdentity;
use serde::{Serialize, Serializer};
use thiserror::Error;

use crate::{
    AnalysisError, DecodeOutcome, DecoderProfile, ElfAnalysis, ElfClass, ElfEndian, ElfLoadSegment,
    ElfMachine, ElfSymbol, FlowKind, InstructionDecoder, analyze_elf, decoder_for_profile,
};

/// Hard ceiling for fully file-backed executable bytes scanned by one report.
pub const MAX_PS2_EE_OBSERVER_SCAN_BYTES: u64 = 64 * 1024 * 1024;
/// Stable serialized report schema emitted by this bounded v1 pass.
pub const PS2_EE_OBSERVER_REPORT_SCHEMA_VERSION: u32 = 1;
/// Hard ceiling for aligned executable words scanned by one report.
pub const MAX_PS2_EE_OBSERVER_WORDS: usize = 16_777_216;
/// Hard ceiling for each bounded seed collection.
pub const MAX_PS2_EE_OBSERVER_SEEDS: usize = 262_144;
/// Hard ceiling for retained reachable basic blocks.
pub const MAX_PS2_EE_OBSERVER_BLOCKS: usize = 262_144;
/// Hard ceiling for retained CFG edges.
pub const MAX_PS2_EE_OBSERVER_EDGES: usize = 524_288;
/// Hard ceiling for retained selectable observer sites.
pub const MAX_PS2_EE_OBSERVER_SITES: usize = 262_144;
/// Hard ceiling for each retained xref/materialization collection.
pub const MAX_PS2_EE_OBSERVER_XREFS: usize = 262_144;
/// Hard ceiling for one printable string-anchor scan, including its NUL bound.
pub const MAX_PS2_EE_OBSERVER_STRING_BYTES: usize = 4 * 1024;
/// Hard ceiling for aggregate owned string-anchor content.
pub const MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES: usize = 16 * 1024 * 1024;
/// Exclusive upper bound for executable coverage in the observer's linear
/// block model. Keeping every decoded PC below this boundary guarantees that
/// both `PC + 4` and `PC + 8` remain representable without 32-bit wraparound.
const PS2_EE_OBSERVER_LINEAR_PC_END: u64 = (1_u64 << 32) - 8;
/// First reserved ELF section index. Core-v1 deliberately rejects every
/// reserved index, including SHN_ABS, SHN_COMMON, and SHN_XINDEX, rather than
/// guessing at processor-specific or extended-index semantics.
const ELF_SHN_LORESERVE: u16 = 0xff00;
const ELF_SHT_NULL: u32 = 0;
const ELF_SHT_NOBITS: u32 = 8;
const ELF_SHF_ALLOC: u32 = 0x2;
/// ELF section flag identifying executable instructions.
const ELF_SHF_EXECINSTR: u32 = 0x4;

/// Exact decoder choice retained by the observer pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ps2EeObserverSelection {
    exact_profile: DecoderProfile,
}

impl Ps2EeObserverSelection {
    /// Accept only one of the six explicit bundled little-endian EE profiles.
    pub fn new(exact_profile: DecoderProfile) -> Result<Self, Ps2EeObserverError> {
        if !is_exact_r5900_profile(exact_profile) {
            return Err(Ps2EeObserverError::IneligibleDecoderProfile {
                profile: exact_profile,
            });
        }
        Ok(Self { exact_profile })
    }

    /// Authoritative resolved profile. The moving `LATEST` alias is not stored.
    #[must_use]
    pub const fn exact_profile(self) -> DecoderProfile {
        self.exact_profile
    }
}

/// Caller-selected limits. Every field is nonzero and no greater than its hard
/// ceiling, so a successfully constructed value is safe to retain and reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeObserverLimits {
    maximum_scan_bytes: u64,
    maximum_words: usize,
    maximum_seeds: usize,
    maximum_blocks: usize,
    maximum_edges: usize,
    maximum_sites: usize,
    maximum_xrefs: usize,
    maximum_string_bytes: usize,
    maximum_total_string_bytes: usize,
}

impl Ps2EeObserverLimits {
    /// Validate caller-selected limits. Caller limits may tighten but never
    /// widen the crate-wide ceilings.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maximum_scan_bytes: u64,
        maximum_words: usize,
        maximum_seeds: usize,
        maximum_blocks: usize,
        maximum_edges: usize,
        maximum_sites: usize,
        maximum_xrefs: usize,
        maximum_string_bytes: usize,
        maximum_total_string_bytes: usize,
    ) -> Result<Self, Ps2EeObserverError> {
        validate_limit(
            "executable scan bytes",
            maximum_scan_bytes,
            MAX_PS2_EE_OBSERVER_SCAN_BYTES,
        )?;
        validate_limit(
            "executable words",
            usize_to_u64(maximum_words, "word limit")?,
            usize_to_u64(MAX_PS2_EE_OBSERVER_WORDS, "hard word limit")?,
        )?;
        validate_limit(
            "function seeds",
            usize_to_u64(maximum_seeds, "seed limit")?,
            usize_to_u64(MAX_PS2_EE_OBSERVER_SEEDS, "hard seed limit")?,
        )?;
        validate_limit(
            "basic blocks",
            usize_to_u64(maximum_blocks, "block limit")?,
            usize_to_u64(MAX_PS2_EE_OBSERVER_BLOCKS, "hard block limit")?,
        )?;
        validate_limit(
            "CFG edges",
            usize_to_u64(maximum_edges, "edge limit")?,
            usize_to_u64(MAX_PS2_EE_OBSERVER_EDGES, "hard edge limit")?,
        )?;
        validate_limit(
            "observer sites",
            usize_to_u64(maximum_sites, "site limit")?,
            usize_to_u64(MAX_PS2_EE_OBSERVER_SITES, "hard site limit")?,
        )?;
        validate_limit(
            "data xrefs",
            usize_to_u64(maximum_xrefs, "xref limit")?,
            usize_to_u64(MAX_PS2_EE_OBSERVER_XREFS, "hard xref limit")?,
        )?;
        validate_limit(
            "string bytes",
            usize_to_u64(maximum_string_bytes, "string byte limit")?,
            usize_to_u64(MAX_PS2_EE_OBSERVER_STRING_BYTES, "hard string byte limit")?,
        )?;
        validate_limit(
            "aggregate string bytes",
            usize_to_u64(maximum_total_string_bytes, "aggregate string byte limit")?,
            usize_to_u64(
                MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
                "hard aggregate string byte limit",
            )?,
        )?;
        Ok(Self {
            maximum_scan_bytes,
            maximum_words,
            maximum_seeds,
            maximum_blocks,
            maximum_edges,
            maximum_sites,
            maximum_xrefs,
            maximum_string_bytes,
            maximum_total_string_bytes,
        })
    }

    #[must_use]
    pub const fn maximum_scan_bytes(self) -> u64 {
        self.maximum_scan_bytes
    }

    #[must_use]
    pub const fn maximum_words(self) -> usize {
        self.maximum_words
    }

    #[must_use]
    pub const fn maximum_seeds(self) -> usize {
        self.maximum_seeds
    }

    #[must_use]
    pub const fn maximum_blocks(self) -> usize {
        self.maximum_blocks
    }

    #[must_use]
    pub const fn maximum_edges(self) -> usize {
        self.maximum_edges
    }

    #[must_use]
    pub const fn maximum_sites(self) -> usize {
        self.maximum_sites
    }

    #[must_use]
    pub const fn maximum_xrefs(self) -> usize {
        self.maximum_xrefs
    }

    #[must_use]
    pub const fn maximum_string_bytes(self) -> usize {
        self.maximum_string_bytes
    }

    #[must_use]
    pub const fn maximum_total_string_bytes(self) -> usize {
        self.maximum_total_string_bytes
    }
}

impl Default for Ps2EeObserverLimits {
    fn default() -> Self {
        Self {
            maximum_scan_bytes: MAX_PS2_EE_OBSERVER_SCAN_BYTES,
            maximum_words: MAX_PS2_EE_OBSERVER_WORDS,
            maximum_seeds: MAX_PS2_EE_OBSERVER_SEEDS,
            maximum_blocks: MAX_PS2_EE_OBSERVER_BLOCKS,
            maximum_edges: MAX_PS2_EE_OBSERVER_EDGES,
            maximum_sites: MAX_PS2_EE_OBSERVER_SITES,
            maximum_xrefs: MAX_PS2_EE_OBSERVER_XREFS,
            maximum_string_bytes: MAX_PS2_EE_OBSERVER_STRING_BYTES,
            maximum_total_string_bytes: MAX_PS2_EE_OBSERVER_TOTAL_STRING_BYTES,
        }
    }
}

/// Exact ELF segment permissions retained by coverage, xrefs, and sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeSegmentPermissions {
    pub raw_flags: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl From<&ElfLoadSegment> for Ps2EeSegmentPermissions {
    fn from(segment: &ElfLoadSegment) -> Self {
        Self {
            raw_flags: segment.flags,
            readable: segment.readable(),
            writable: segment.writable(),
            executable: segment.executable(),
        }
    }
}

/// One aligned, fully file-backed executable scan range.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeExecutableCoverage {
    pub program_header_index: u16,
    pub start_guest_va: u64,
    pub start_rva: u64,
    pub end_guest_va: u64,
    pub end_rva: u64,
    pub start_file_offset: u64,
    pub byte_size: u64,
    pub word_count: u64,
    pub permissions: Ps2EeSegmentPermissions,
}

/// Why a deduplicated function seed entered the observer worklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ps2EeFunctionSeedSource {
    EntryPoint,
    ExecutableSegmentStart,
    ElfFunctionSymbol,
    DirectCallTarget,
}

/// One sorted executable function seed with every retained source reason.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeFunctionSeed {
    pub guest_va: u64,
    pub rva: u64,
    pub sources: Vec<Ps2EeFunctionSeedSource>,
}

/// Basic-block terminal classification used by the conservative v1 CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ps2EeBlockTerminator {
    FallThrough,
    ConditionalBranch,
    UnconditionalBranch,
    IndirectBranch,
    DirectCall,
    IndirectCall,
    Return,
    Interrupt,
    ArithmeticTrap,
    Unsupported,
    Invalid,
    MissingDelaySlot,
    EndOfCoverage,
}

/// One sorted reachable basic block. The end address is half-open.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeBasicBlock {
    pub start_guest_va: u64,
    pub start_rva: u64,
    pub end_guest_va: u64,
    pub end_rva: Option<u64>,
    pub decoded_word_count: u64,
    /// PC of the terminal instruction. For an arithmetic trap in a delay slot,
    /// this is the delay instruction's PC rather than the preceding transfer.
    pub terminator_guest_pc: Option<u64>,
    pub terminator_rva: Option<u64>,
    pub terminator: Ps2EeBlockTerminator,
}

/// How a reachable block transfers control to one exact guest target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ps2EeCfgEdgeKind {
    FallThrough,
    Branch,
    BranchTaken,
    BranchNotTaken,
    DirectCall,
    CallContinuation,
}

/// One sorted CFG edge. `target_rva` is absent only when the guest target lies
/// below the ELF image base.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeCfgEdge {
    pub source_block_guest_va: u64,
    pub source_block_rva: u64,
    pub instruction_guest_pc: u64,
    pub instruction_rva: u64,
    pub target_guest_va: u64,
    pub target_rva: Option<u64>,
    pub kind: Ps2EeCfgEdgeKind,
}

/// Classification of an effective access span against sparse PT_LOAD mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ps2EeDataTargetClass {
    FullyFileBacked,
    MappedZeroFill,
    MappedCrossBoundary,
    Unmapped,
}

/// Read/write direction of one resolved memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ps2EeAccessDirection {
    Read,
    Write,
}

/// Frozen scalar/merge form. CACHE, PREF, and coprocessor accesses have no
/// variant and can therefore never leak into xrefs or hook tuples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ps2EeAccessForm {
    ScalarLoad,
    ScalarStore,
    MergeLoadLeft,
    MergeLoadRight,
    MergeStoreLeft,
    MergeStoreRight,
}

impl Ps2EeAccessForm {
    #[must_use]
    pub const fn direction(self) -> Ps2EeAccessDirection {
        match self {
            Self::ScalarLoad | Self::MergeLoadLeft | Self::MergeLoadRight => {
                Ps2EeAccessDirection::Read
            }
            Self::ScalarStore | Self::MergeStoreLeft | Self::MergeStoreRight => {
                Ps2EeAccessDirection::Write
            }
        }
    }
}

/// Exact scalar or merge-unit width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ps2EeAccessWidth {
    Byte,
    Halfword,
    Word,
    Doubleword,
    Quadword,
}

impl Ps2EeAccessWidth {
    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Byte => 1,
            Self::Halfword => 2,
            Self::Word => 4,
            Self::Doubleword => 8,
            Self::Quadword => 16,
        }
    }
}

/// One exact mapped address produced by the closed v1 integer allowlist.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeAddressMaterialization {
    pub instruction_guest_pc: u64,
    pub instruction_rva: u64,
    pub destination_register: u8,
    pub target_guest_va: u64,
    pub target_rva: u64,
    pub target_class: Ps2EeDataTargetClass,
}

/// One constant-base scalar/merge memory reference, including unresolved sparse
/// target classes. Only `FullyFileBacked` records are selectable sites.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeDataXref {
    pub instruction_guest_pc: u64,
    pub instruction_rva: u64,
    pub target_guest_va: u64,
    pub target_rva: Option<u64>,
    pub access_span_guest_va: u64,
    pub access_span_rva: Option<u64>,
    pub direction: Ps2EeAccessDirection,
    pub form: Ps2EeAccessForm,
    pub width: Ps2EeAccessWidth,
    pub target_class: Ps2EeDataTargetClass,
    pub program_header_index: Option<u16>,
    pub file_offset: Option<u64>,
    pub permissions: Option<Ps2EeSegmentPermissions>,
}

/// Owned, bounded printable string beginning exactly at a site's effective
/// target. `byte_size` includes the terminating NUL; `value` does not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeStringAnchor {
    pub guest_va: u64,
    pub rva: u64,
    pub byte_size: u32,
    pub value: String,
}

/// One exact PCSX2-observable memory site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeObserverSite {
    pub instruction_guest_pc: u64,
    pub instruction_rva: u64,
    pub target_guest_va: u64,
    pub target_rva: u64,
    pub access_span_guest_va: u64,
    pub access_span_rva: u64,
    pub direction: Ps2EeAccessDirection,
    pub form: Ps2EeAccessForm,
    pub width: Ps2EeAccessWidth,
    pub program_header_index: u16,
    pub file_offset: u64,
    pub permissions: Ps2EeSegmentPermissions,
    pub string_anchor: Option<Ps2EeStringAnchor>,
}

/// Schema-v1 deterministic observer report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ps2EeObserverReport {
    pub schema_version: u32,
    pub identity: BinaryIdentity,
    #[serde(serialize_with = "serialize_decoder_profile")]
    pub exact_profile: DecoderProfile,
    pub exact_profile_name: String,
    pub limits: Ps2EeObserverLimits,
    pub executable_coverage: Vec<Ps2EeExecutableCoverage>,
    pub scanned_word_count: u64,
    pub function_seeds: Vec<Ps2EeFunctionSeed>,
    pub basic_blocks: Vec<Ps2EeBasicBlock>,
    pub cfg_edges: Vec<Ps2EeCfgEdge>,
    pub address_materializations: Vec<Ps2EeAddressMaterialization>,
    pub data_xrefs: Vec<Ps2EeDataXref>,
    pub observer_sites: Vec<Ps2EeObserverSite>,
}

/// A selector that cannot confuse a sorted site index with a guest PC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2EeObserverSiteSelector {
    Index(usize),
    GuestPc(u64),
}

/// Frozen PCSX2 hook tuple: exact guest PC plus memory form and width.
pub type Ps2EeObserverHook = (u64, Ps2EeAccessForm, Ps2EeAccessWidth);

/// Select one unambiguous observer site and reduce it to the frozen hook tuple.
pub fn select_site(
    report: &Ps2EeObserverReport,
    selector: Ps2EeObserverSiteSelector,
) -> Result<Ps2EeObserverHook, Ps2EeObserverError> {
    let site = match selector {
        Ps2EeObserverSiteSelector::Index(index) => {
            report
                .observer_sites
                .get(index)
                .ok_or(Ps2EeObserverError::SiteIndexOutOfRange {
                    index,
                    count: report.observer_sites.len(),
                })?
        }
        Ps2EeObserverSiteSelector::GuestPc(guest_pc) => {
            let mut matches = report
                .observer_sites
                .iter()
                .filter(|site| site.instruction_guest_pc == guest_pc);
            let site = matches
                .next()
                .ok_or(Ps2EeObserverError::SiteGuestPcNotFound { guest_pc })?;
            if matches.next().is_some() {
                return Err(Ps2EeObserverError::AmbiguousSiteGuestPc { guest_pc });
            }
            site
        }
    };
    Ok((site.instruction_guest_pc, site.form, site.width))
}

/// Path-free observer failure. Cap failures never return a partial report.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Ps2EeObserverError {
    #[error(transparent)]
    Analysis(#[from] AnalysisError),
    #[error("decoder profile `{profile}` is not an explicit bundled PS2 EE R5900 profile")]
    IneligibleDecoderProfile { profile: DecoderProfile },
    #[error("ineligible PS2 EE observer container: requires {requirement}")]
    IneligibleContainer { requirement: &'static str },
    #[error("observer limit `{kind}` must be nonzero")]
    EmptyLimit { kind: &'static str },
    #[error("observer limit `{kind}` value {actual} exceeds hard maximum {maximum}")]
    LimitTooLarge {
        kind: &'static str,
        actual: u64,
        maximum: u64,
    },
    #[error("observer output `{kind}` count {actual} exceeds selected maximum {maximum}")]
    OutputLimitExceeded {
        kind: &'static str,
        actual: u64,
        maximum: u64,
    },
    #[error("the selected exact decoder could not be constructed: {reason}")]
    DecoderUnavailable { reason: String },
    #[error("cannot represent {0} on this platform")]
    IntegerConversion(&'static str),
    #[error("integer arithmetic overflow while computing {0}")]
    ArithmeticOverflow(&'static str),
    #[error("observer site index {index} is outside the {count} sorted sites")]
    SiteIndexOutOfRange { index: usize, count: usize },
    #[error("no observer site exists at guest PC {guest_pc:#x}")]
    SiteGuestPcNotFound { guest_pc: u64 },
    #[error("more than one observer site exists at guest PC {guest_pc:#x}")]
    AmbiguousSiteGuestPc { guest_pc: u64 },
}

fn serialize_decoder_profile<S>(profile: &DecoderProfile, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(profile.name())
}

const fn is_exact_r5900_profile(profile: DecoderProfile) -> bool {
    matches!(
        profile,
        DecoderProfile::Ps2EeR5900LeCoreV1
            | DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1
            | DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1
            | DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1
            | DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1
            | DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1
    )
}

fn validate_limit(kind: &'static str, actual: u64, maximum: u64) -> Result<(), Ps2EeObserverError> {
    if actual == 0 {
        return Err(Ps2EeObserverError::EmptyLimit { kind });
    }
    if actual > maximum {
        return Err(Ps2EeObserverError::LimitTooLarge {
            kind,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn usize_to_u64(value: usize, context: &'static str) -> Result<u64, Ps2EeObserverError> {
    u64::try_from(value).map_err(|_| Ps2EeObserverError::IntegerConversion(context))
}

#[derive(Debug, Clone)]
struct RuntimeCoverage {
    record: Ps2EeExecutableCoverage,
    start_file_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstantValue {
    Unknown,
    Exact(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegisterState {
    registers: [ConstantValue; 32],
}

impl RegisterState {
    fn unknown() -> Self {
        let mut registers = [ConstantValue::Unknown; 32];
        registers[0] = ConstantValue::Exact(0);
        Self { registers }
    }

    fn get(&self, register: u8) -> ConstantValue {
        self.registers[usize::from(register)]
    }

    fn set(&mut self, register: u8, value: ConstantValue) {
        if register != 0 {
            self.registers[usize::from(register)] = value;
        }
        self.registers[0] = ConstantValue::Exact(0);
    }

    fn clear(&mut self) {
        *self = Self::unknown();
    }

    /// Join is exact-same only. It is monotone: an established `Unknown` never
    /// becomes exact because another predecessor later supplies a constant.
    fn join_from(&mut self, incoming: &Self) -> bool {
        let mut changed = false;
        for index in 1..self.registers.len() {
            let joined = if self.registers[index] == incoming.registers[index] {
                self.registers[index]
            } else {
                ConstantValue::Unknown
            };
            if joined != self.registers[index] {
                self.registers[index] = joined;
                changed = true;
            }
        }
        changed
    }
}

#[derive(Debug, Clone, Copy)]
struct ResolvedTarget {
    class: Ps2EeDataTargetClass,
    program_header_index: Option<u16>,
    file_offset: Option<u64>,
    permissions: Option<Ps2EeSegmentPermissions>,
}

struct ObserverAccumulator<'a> {
    bytes: &'a [u8],
    analysis: &'a ElfAnalysis,
    image_base: u64,
    limits: Ps2EeObserverLimits,
    decoder: Box<dyn InstructionDecoder>,
    coverage: Vec<RuntimeCoverage>,
    seeds: BTreeMap<u64, BTreeSet<Ps2EeFunctionSeedSource>>,
    boundaries: BTreeSet<u64>,
    blocks: BTreeMap<u64, Ps2EeBasicBlock>,
    edges: BTreeSet<Ps2EeCfgEdge>,
    materializations: BTreeSet<Ps2EeAddressMaterialization>,
    xrefs: BTreeSet<Ps2EeDataXref>,
    sites: BTreeSet<Ps2EeObserverSite>,
    total_string_bytes: usize,
    cfg_word_steps: usize,
}

/// Reparse and analyze one exact PS2 EE ELF source.
///
/// Every cap is all-or-nothing: an overflow returns a typed error and discards
/// the in-progress owned report.
pub fn scan_ps2_ee_observer_sites(
    exact_elf: &[u8],
    selection: Ps2EeObserverSelection,
    limits: Ps2EeObserverLimits,
) -> Result<Ps2EeObserverReport, Ps2EeObserverError> {
    let analysis = analyze_elf(exact_elf)?;
    require_eligible_container(&analysis)?;
    if analysis.symbol_scan_truncated {
        return Err(Ps2EeObserverError::IneligibleContainer {
            requirement: "a complete bounded ELF symbol scan",
        });
    }
    let image_base = analysis
        .load_segments
        .first()
        .ok_or(Ps2EeObserverError::IneligibleContainer {
            requirement: "at least one non-empty PT_LOAD mapping",
        })?
        .virtual_address;
    let coverage = build_executable_coverage(&analysis, exact_elf, image_base, limits)?;
    if coverage.is_empty() {
        return Err(Ps2EeObserverError::IneligibleContainer {
            requirement: "at least one aligned fully file-backed executable word",
        });
    }
    let scanned_word_count =
        coverage.iter().try_fold(0_u64, |total, range| {
            total.checked_add(range.record.word_count).ok_or(
                Ps2EeObserverError::ArithmeticOverflow("executable word count"),
            )
        })?;
    let decoder = decoder_for_profile(selection.exact_profile()).map_err(|error| {
        Ps2EeObserverError::DecoderUnavailable {
            reason: error.to_string(),
        }
    })?;
    let mut accumulator = ObserverAccumulator {
        bytes: exact_elf,
        analysis: &analysis,
        image_base,
        limits,
        decoder,
        coverage,
        seeds: BTreeMap::new(),
        boundaries: BTreeSet::new(),
        blocks: BTreeMap::new(),
        edges: BTreeSet::new(),
        materializations: BTreeSet::new(),
        xrefs: BTreeSet::new(),
        sites: BTreeSet::new(),
        total_string_bytes: 0,
        cfg_word_steps: 0,
    };

    accumulator.collect_declared_seeds()?;
    accumulator.scan_all_executable_words()?;
    accumulator.propagate_cfg()?;

    let executable_coverage = accumulator
        .coverage
        .iter()
        .map(|range| range.record.clone())
        .collect();
    let function_seeds = accumulator
        .seeds
        .into_iter()
        .map(|(guest_va, sources)| Ps2EeFunctionSeed {
            guest_va,
            rva: guest_va - image_base,
            sources: sources.into_iter().collect(),
        })
        .collect();

    Ok(Ps2EeObserverReport {
        schema_version: PS2_EE_OBSERVER_REPORT_SCHEMA_VERSION,
        identity: analysis.identity.clone(),
        exact_profile: selection.exact_profile(),
        exact_profile_name: selection.exact_profile().name().to_owned(),
        limits,
        executable_coverage,
        scanned_word_count,
        function_seeds,
        basic_blocks: accumulator.blocks.into_values().collect(),
        cfg_edges: accumulator.edges.into_iter().collect(),
        address_materializations: accumulator.materializations.into_iter().collect(),
        data_xrefs: accumulator.xrefs.into_iter().collect(),
        observer_sites: accumulator.sites.into_iter().collect(),
    })
}

fn require_eligible_container(analysis: &ElfAnalysis) -> Result<(), Ps2EeObserverError> {
    if analysis.class != ElfClass::Elf32 {
        return Err(Ps2EeObserverError::IneligibleContainer {
            requirement: "ELFCLASS32",
        });
    }
    if analysis.endian != ElfEndian::Little {
        return Err(Ps2EeObserverError::IneligibleContainer {
            requirement: "little-endian ELF data",
        });
    }
    if analysis.elf_type != 2 {
        return Err(Ps2EeObserverError::IneligibleContainer {
            requirement: "ET_EXEC",
        });
    }
    if ElfMachine::from_raw(analysis.machine, analysis.class) != ElfMachine::Mips {
        return Err(Ps2EeObserverError::IneligibleContainer {
            requirement: "EM_MIPS",
        });
    }
    Ok(())
}

fn build_executable_coverage(
    analysis: &ElfAnalysis,
    exact_elf: &[u8],
    image_base: u64,
    limits: Ps2EeObserverLimits,
) -> Result<Vec<RuntimeCoverage>, Ps2EeObserverError> {
    let mut coverage = Vec::new();
    let mut total_bytes = 0_u64;
    let mut total_words = 0_u64;
    for segment in analysis
        .load_segments
        .iter()
        .filter(|segment| segment.executable())
    {
        let aligned_start = segment.virtual_address.checked_add(3).ok_or(
            Ps2EeObserverError::ArithmeticOverflow("aligned executable guest address"),
        )? & !3;
        let alignment_delta = aligned_start - segment.virtual_address;
        if alignment_delta >= segment.file_size {
            continue;
        }
        let available = segment.file_size - alignment_delta;
        let byte_size = available & !3;
        if byte_size == 0 {
            continue;
        }
        let word_count = byte_size / 4;
        total_bytes =
            total_bytes
                .checked_add(byte_size)
                .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                    "executable scan byte count",
                ))?;
        total_words =
            total_words
                .checked_add(word_count)
                .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                    "executable scan word count",
                ))?;
        enforce_output_limit(
            "executable scan bytes",
            total_bytes,
            limits.maximum_scan_bytes,
        )?;
        enforce_output_limit(
            "executable words",
            total_words,
            usize_to_u64(limits.maximum_words, "selected word limit")?,
        )?;

        let start_file_offset = segment.file_offset.checked_add(alignment_delta).ok_or(
            Ps2EeObserverError::ArithmeticOverflow("executable file offset"),
        )?;
        let end_file_offset = start_file_offset.checked_add(byte_size).ok_or(
            Ps2EeObserverError::ArithmeticOverflow("executable file range"),
        )?;
        let start_file_offset_usize = usize::try_from(start_file_offset)
            .map_err(|_| Ps2EeObserverError::IntegerConversion("executable file offset"))?;
        let end_file_offset_usize = usize::try_from(end_file_offset)
            .map_err(|_| Ps2EeObserverError::IntegerConversion("executable file range"))?;
        if exact_elf
            .get(start_file_offset_usize..end_file_offset_usize)
            .is_none()
        {
            return Err(Ps2EeObserverError::IneligibleContainer {
                requirement: "fully file-backed executable PT_LOAD ranges",
            });
        }
        let end_guest_va =
            aligned_start
                .checked_add(byte_size)
                .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                    "executable guest range",
                ))?;
        if end_guest_va > PS2_EE_OBSERVER_LINEAR_PC_END {
            return Err(Ps2EeObserverError::IneligibleContainer {
                requirement: "executable coverage below the R5900 PC wrap boundary",
            });
        }
        coverage.push(RuntimeCoverage {
            record: Ps2EeExecutableCoverage {
                program_header_index: segment.program_header_index,
                start_guest_va: aligned_start,
                start_rva: aligned_start - image_base,
                end_guest_va,
                end_rva: end_guest_va - image_base,
                start_file_offset,
                byte_size,
                word_count,
                permissions: segment.into(),
            },
            start_file_offset: start_file_offset_usize,
        });
    }
    coverage.sort_by_key(|range| {
        (
            range.record.start_guest_va,
            range.record.program_header_index,
        )
    });
    Ok(coverage)
}

fn enforce_output_limit(
    kind: &'static str,
    actual: u64,
    maximum: u64,
) -> Result<(), Ps2EeObserverError> {
    if actual > maximum {
        return Err(Ps2EeObserverError::OutputLimitExceeded {
            kind,
            actual,
            maximum,
        });
    }
    Ok(())
}

/// Return the first segment whose start is greater than `guest_va`, plus the
/// number of comparisons used. The sorted, non-overlapping PT_LOAD invariant
/// makes the immediately preceding segment the only possible container. The
/// probe count is retained so a unit test can freeze logarithmic lookup without
/// relying on wall-clock timing.
fn load_segment_start_upper_bound(segments: &[ElfLoadSegment], guest_va: u64) -> (usize, usize) {
    let mut low = 0_usize;
    let mut high = segments.len();
    let mut probes = 0_usize;
    while low < high {
        probes += 1;
        let middle = low + (high - low) / 2;
        if segments[middle].virtual_address <= guest_va {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    (low, probes)
}

fn classify_span_in_segments(
    segments: &[ElfLoadSegment],
    start_guest_va: u64,
    byte_size: u64,
) -> ResolvedTarget {
    let Some(end_guest_va) = start_guest_va.checked_add(byte_size) else {
        return ResolvedTarget {
            class: Ps2EeDataTargetClass::Unmapped,
            program_header_index: None,
            file_offset: None,
            permissions: None,
        };
    };
    let (upper_bound, _) = load_segment_start_upper_bound(segments, start_guest_va);
    if let Some(segment) = upper_bound
        .checked_sub(1)
        .and_then(|index| segments.get(index))
    {
        let Some(memory_end) = segment.virtual_address.checked_add(segment.memory_size) else {
            return ResolvedTarget {
                class: Ps2EeDataTargetClass::MappedCrossBoundary,
                program_header_index: Some(segment.program_header_index),
                file_offset: None,
                permissions: Some(segment.into()),
            };
        };
        if start_guest_va < memory_end {
            if end_guest_va > memory_end {
                return ResolvedTarget {
                    class: Ps2EeDataTargetClass::MappedCrossBoundary,
                    program_header_index: Some(segment.program_header_index),
                    file_offset: None,
                    permissions: Some(segment.into()),
                };
            }
            let relative = start_guest_va - segment.virtual_address;
            let permissions = Some(segment.into());
            if relative >= segment.file_size {
                return ResolvedTarget {
                    class: Ps2EeDataTargetClass::MappedZeroFill,
                    program_header_index: Some(segment.program_header_index),
                    file_offset: None,
                    permissions,
                };
            }
            let Some(relative_end) = relative.checked_add(byte_size) else {
                return ResolvedTarget {
                    class: Ps2EeDataTargetClass::MappedCrossBoundary,
                    program_header_index: Some(segment.program_header_index),
                    file_offset: None,
                    permissions,
                };
            };
            if relative_end <= segment.file_size {
                return ResolvedTarget {
                    class: Ps2EeDataTargetClass::FullyFileBacked,
                    program_header_index: Some(segment.program_header_index),
                    file_offset: segment.file_offset.checked_add(relative),
                    permissions,
                };
            }
            return ResolvedTarget {
                class: Ps2EeDataTargetClass::MappedCrossBoundary,
                program_header_index: Some(segment.program_header_index),
                file_offset: None,
                permissions,
            };
        }
    }

    // The span can begin in a gap and still overlap the next mapping.
    if let Some(segment) = segments.get(upper_bound) {
        if end_guest_va > segment.virtual_address {
            return ResolvedTarget {
                class: Ps2EeDataTargetClass::MappedCrossBoundary,
                program_header_index: Some(segment.program_header_index),
                file_offset: None,
                permissions: Some(segment.into()),
            };
        }
    }
    ResolvedTarget {
        class: Ps2EeDataTargetClass::Unmapped,
        program_header_index: None,
        file_offset: None,
        permissions: None,
    }
}

#[derive(Debug, Clone)]
struct BlockSuccessor {
    edge: Ps2EeCfgEdge,
    state: Option<RegisterState>,
}

#[derive(Debug, Clone)]
struct BlockAnalysis {
    block: Ps2EeBasicBlock,
    successors: Vec<BlockSuccessor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DelaySlotOutcome {
    Continue,
    DefiniteTrap { guest_pc: u64 },
    MissingOrUnsupported,
}

impl ObserverAccumulator<'_> {
    fn collect_declared_seeds(&mut self) -> Result<(), Ps2EeObserverError> {
        if !self.is_executable_word(self.analysis.entry_va) {
            return Err(Ps2EeObserverError::IneligibleContainer {
                requirement: "an aligned, complete, file-backed executable entry-point word",
            });
        }
        let segment_starts: Vec<u64> = self
            .coverage
            .iter()
            .map(|range| range.record.start_guest_va)
            .collect();
        for guest_va in segment_starts {
            self.add_seed(guest_va, Ps2EeFunctionSeedSource::ExecutableSegmentStart)?;
        }
        self.add_seed(self.analysis.entry_va, Ps2EeFunctionSeedSource::EntryPoint)?;
        let symbol_values: Vec<u64> = self
            .analysis
            .symbols
            .iter()
            .filter(|symbol| self.is_semantically_defined_function_symbol(symbol))
            .map(|symbol| symbol.value)
            .collect();
        for guest_va in symbol_values {
            self.add_seed(guest_va, Ps2EeFunctionSeedSource::ElfFunctionSymbol)?;
        }
        Ok(())
    }

    fn is_semantically_defined_function_symbol(&self, symbol: &ElfSymbol) -> bool {
        if symbol.info & 0x0f != 2
            || symbol.section_index == 0
            || symbol.section_index >= ELF_SHN_LORESERVE
        {
            return false;
        }
        let Some(section) = self
            .analysis
            .section_headers
            .get(usize::from(symbol.section_index))
            .filter(|section| section.table_index == symbol.section_index)
        else {
            return false;
        };
        if matches!(section.section_type, ELF_SHT_NULL | ELF_SHT_NOBITS)
            || section.flags & (ELF_SHF_ALLOC | ELF_SHF_EXECINSTR)
                != (ELF_SHF_ALLOC | ELF_SHF_EXECINSTR)
        {
            return false;
        }
        let Some(section_end) = section.virtual_address.checked_add(section.size) else {
            return false;
        };
        if symbol.value < section.virtual_address || symbol.value >= section_end {
            return false;
        }
        symbol
            .value
            .checked_add(symbol.size)
            .is_some_and(|symbol_end| symbol_end <= section_end)
    }

    /// Decode every eligible word once. Raw fields below only refine words that
    /// this exact selected profile has already accepted; they never substitute
    /// for the decoder or broaden its instruction set.
    fn scan_all_executable_words(&mut self) -> Result<(), Ps2EeObserverError> {
        let ranges: Vec<(u64, u64)> = self
            .coverage
            .iter()
            .map(|range| (range.record.start_guest_va, range.record.end_guest_va))
            .collect();
        for (start, end) in ranges {
            let mut guest_pc = start;
            while guest_pc < end {
                let word_bytes =
                    self.word_at(guest_pc)
                        .ok_or(Ps2EeObserverError::IneligibleContainer {
                            requirement: "stable executable coverage",
                        })?;
                let word = u32::from_le_bytes(word_bytes);
                if let DecodeOutcome::Decoded(decoded) =
                    self.decoder.decode_one(&word_bytes, guest_pc)
                {
                    match decoded.flow {
                        FlowKind::ConditionalBranch => {
                            if let Some(target) = decoded.direct_target {
                                if is_regimm_link(word) {
                                    self.add_seed(
                                        target,
                                        Ps2EeFunctionSeedSource::DirectCallTarget,
                                    )?;
                                } else {
                                    self.add_boundary_if_executable(target)?;
                                }
                            }
                            self.add_boundary_if_executable(pc_after_delay(guest_pc))?;
                        }
                        FlowKind::UnconditionalBranch => {
                            if let Some(target) = decoded.direct_target {
                                self.add_boundary_if_executable(target)?;
                            }
                        }
                        FlowKind::Call => {
                            if let Some(target) = decoded.direct_target {
                                self.add_seed(target, Ps2EeFunctionSeedSource::DirectCallTarget)?;
                            }
                            self.add_boundary_if_executable(pc_after_delay(guest_pc))?;
                        }
                        FlowKind::IndirectCall => {
                            self.add_boundary_if_executable(pc_after_delay(guest_pc))?;
                        }
                        FlowKind::Sequential
                        | FlowKind::IndirectBranch
                        | FlowKind::Return
                        | FlowKind::Interrupt
                        | FlowKind::Privileged
                        | FlowKind::Invalid => {}
                    }
                }
                guest_pc =
                    guest_pc
                        .checked_add(4)
                        .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                            "executable word address",
                        ))?;
            }
        }
        Ok(())
    }

    fn propagate_cfg(&mut self) -> Result<(), Ps2EeObserverError> {
        let mut entry_states = BTreeMap::<u64, RegisterState>::new();
        let mut pending = BTreeSet::<u64>::new();
        let initial_seeds: Vec<u64> = self.seeds.keys().copied().collect();
        for guest_va in initial_seeds {
            self.insert_entry_state(
                &mut entry_states,
                &mut pending,
                guest_va,
                RegisterState::unknown(),
            )?;
        }

        // Phase one computes only the monotone entry-state fixpoint. Emitting
        // derived facts here would retain stale Exact values after a later
        // predecessor degrades the same block entry to Unknown.
        while let Some(start_guest_va) = pending.pop_first() {
            let state = entry_states.get(&start_guest_va).cloned().ok_or(
                Ps2EeObserverError::IneligibleContainer {
                    requirement: "internally consistent observer worklist",
                },
            )?;
            let analysis = self.analyze_block(start_guest_va, state, false)?;
            for successor in analysis.successors {
                if let Some(state) = successor.state {
                    let target = successor.edge.target_guest_va;
                    if self.is_executable_word(target) {
                        self.insert_entry_state(&mut entry_states, &mut pending, target, state)?;
                    }
                }
            }
        }

        // Phase two rebuilds once from the final entry states. Each phase has
        // its own explicit word-step budget.
        self.blocks.clear();
        self.edges.clear();
        self.materializations.clear();
        self.xrefs.clear();
        self.sites.clear();
        self.total_string_bytes = 0;
        self.cfg_word_steps = 0;
        for (start_guest_va, state) in entry_states {
            let analysis = self.analyze_block(start_guest_va, state, true)?;
            self.blocks.insert(start_guest_va, analysis.block);
            for successor in analysis.successors {
                self.insert_edge(successor.edge)?;
            }
        }
        Ok(())
    }

    fn analyze_block(
        &mut self,
        start_guest_va: u64,
        mut state: RegisterState,
        emit_observations: bool,
    ) -> Result<BlockAnalysis, Ps2EeObserverError> {
        let mut guest_pc = start_guest_va;
        let mut decoded_word_count = 0_u64;
        let mut last_guest_pc = start_guest_va;
        loop {
            if guest_pc != start_guest_va && self.boundaries.contains(&guest_pc) {
                let edge = self.edge(
                    start_guest_va,
                    last_guest_pc,
                    guest_pc,
                    Ps2EeCfgEdgeKind::FallThrough,
                );
                return Ok(BlockAnalysis {
                    block: self.block(
                        start_guest_va,
                        guest_pc,
                        decoded_word_count,
                        None,
                        Ps2EeBlockTerminator::FallThrough,
                    ),
                    successors: vec![BlockSuccessor {
                        edge,
                        state: Some(state),
                    }],
                });
            }

            let Some(word_bytes) = self.word_at(guest_pc) else {
                return Ok(BlockAnalysis {
                    block: self.block(
                        start_guest_va,
                        guest_pc,
                        decoded_word_count,
                        None,
                        Ps2EeBlockTerminator::EndOfCoverage,
                    ),
                    successors: Vec::new(),
                });
            };
            self.bump_cfg_word_steps()?;
            let word = u32::from_le_bytes(word_bytes);
            let decoded = match self.decoder.decode_one(&word_bytes, guest_pc) {
                DecodeOutcome::Decoded(decoded) => decoded,
                DecodeOutcome::Unsupported { .. } => {
                    state.clear();
                    return Ok(BlockAnalysis {
                        block: self.block(
                            start_guest_va,
                            guest_pc.saturating_add(4),
                            decoded_word_count,
                            Some(guest_pc),
                            Ps2EeBlockTerminator::Unsupported,
                        ),
                        successors: Vec::new(),
                    });
                }
                DecodeOutcome::Invalid | DecodeOutcome::Truncated { .. } => {
                    state.clear();
                    return Ok(BlockAnalysis {
                        block: self.block(
                            start_guest_va,
                            guest_pc.saturating_add(4),
                            decoded_word_count,
                            Some(guest_pc),
                            Ps2EeBlockTerminator::Invalid,
                        ),
                        successors: Vec::new(),
                    });
                }
            };
            decoded_word_count =
                decoded_word_count
                    .checked_add(1)
                    .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                        "basic-block word count",
                    ))?;
            last_guest_pc = guest_pc;

            match decoded.flow {
                FlowKind::Sequential => {
                    if self.apply_sequential_effects(
                        word,
                        guest_pc,
                        &mut state,
                        emit_observations,
                    )? == SequentialEffectOutcome::DefiniteTrap
                    {
                        return Ok(BlockAnalysis {
                            block: self.block(
                                start_guest_va,
                                guest_pc.saturating_add(4),
                                decoded_word_count,
                                Some(guest_pc),
                                Ps2EeBlockTerminator::ArithmeticTrap,
                            ),
                            successors: Vec::new(),
                        });
                    }
                    guest_pc =
                        guest_pc
                            .checked_add(4)
                            .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                                "sequential guest PC",
                            ))?;
                }
                FlowKind::ConditionalBranch => {
                    let is_link = is_regimm_link(word);
                    if is_link {
                        state.set(31, ConstantValue::Exact(pc_after_delay(guest_pc)));
                    }
                    let target =
                        decoded
                            .direct_target
                            .ok_or(Ps2EeObserverError::IneligibleContainer {
                                requirement: "direct target for decoded conditional branch",
                            })?;
                    let continuation = pc_after_delay(guest_pc);
                    let mut successors = Vec::with_capacity(if is_link { 3 } else { 2 });
                    let mut delay_trap_pc = None;
                    if is_branch_likely(word) {
                        successors.push(BlockSuccessor {
                            edge: self.edge(
                                start_guest_va,
                                guest_pc,
                                continuation,
                                Ps2EeCfgEdgeKind::BranchNotTaken,
                            ),
                            state: Some(state.clone()),
                        });
                        let mut taken_state = state;
                        match self.execute_delay_slot(
                            guest_pc,
                            &mut taken_state,
                            emit_observations,
                        )? {
                            DelaySlotOutcome::Continue => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                successors.push(BlockSuccessor {
                                    edge: self.edge(
                                        start_guest_va,
                                        guest_pc,
                                        target,
                                        Ps2EeCfgEdgeKind::BranchTaken,
                                    ),
                                    state: Some(taken_state),
                                });
                                if is_link {
                                    successors.push(BlockSuccessor {
                                        edge: self.edge(
                                            start_guest_va,
                                            guest_pc,
                                            continuation,
                                            Ps2EeCfgEdgeKind::CallContinuation,
                                        ),
                                        state: Some(RegisterState::unknown()),
                                    });
                                }
                            }
                            DelaySlotOutcome::DefiniteTrap { guest_pc } => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                delay_trap_pc = Some(guest_pc);
                            }
                            DelaySlotOutcome::MissingOrUnsupported => {}
                        }
                    } else {
                        match self.execute_delay_slot(guest_pc, &mut state, emit_observations)? {
                            DelaySlotOutcome::Continue => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                successors.push(BlockSuccessor {
                                    edge: self.edge(
                                        start_guest_va,
                                        guest_pc,
                                        target,
                                        Ps2EeCfgEdgeKind::BranchTaken,
                                    ),
                                    state: Some(state.clone()),
                                });
                                successors.push(BlockSuccessor {
                                    edge: self.edge(
                                        start_guest_va,
                                        guest_pc,
                                        continuation,
                                        Ps2EeCfgEdgeKind::BranchNotTaken,
                                    ),
                                    state: Some(state),
                                });
                                if is_link {
                                    successors.push(BlockSuccessor {
                                        edge: self.edge(
                                            start_guest_va,
                                            guest_pc,
                                            continuation,
                                            Ps2EeCfgEdgeKind::CallContinuation,
                                        ),
                                        state: Some(RegisterState::unknown()),
                                    });
                                }
                            }
                            DelaySlotOutcome::DefiniteTrap { guest_pc } => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                delay_trap_pc = Some(guest_pc);
                            }
                            DelaySlotOutcome::MissingOrUnsupported => {}
                        }
                    }
                    let (terminator, terminator_guest_pc) =
                        if let Some(trap_pc) = delay_trap_pc.filter(|_| successors.is_empty()) {
                            (Ps2EeBlockTerminator::ArithmeticTrap, trap_pc)
                        } else if successors.is_empty() {
                            (Ps2EeBlockTerminator::MissingDelaySlot, guest_pc)
                        } else {
                            (Ps2EeBlockTerminator::ConditionalBranch, guest_pc)
                        };
                    return Ok(BlockAnalysis {
                        block: self.block(
                            start_guest_va,
                            continuation,
                            decoded_word_count,
                            Some(terminator_guest_pc),
                            terminator,
                        ),
                        successors,
                    });
                }
                FlowKind::UnconditionalBranch => {
                    let target =
                        decoded
                            .direct_target
                            .ok_or(Ps2EeObserverError::IneligibleContainer {
                                requirement: "direct target for decoded unconditional branch",
                            })?;
                    let continuation = pc_after_delay(guest_pc);
                    let mut successors = Vec::new();
                    let (terminator, terminator_guest_pc) =
                        match self.execute_delay_slot(guest_pc, &mut state, emit_observations)? {
                            DelaySlotOutcome::Continue => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                successors.push(BlockSuccessor {
                                    edge: self.edge(
                                        start_guest_va,
                                        guest_pc,
                                        target,
                                        Ps2EeCfgEdgeKind::Branch,
                                    ),
                                    state: Some(state),
                                });
                                (Ps2EeBlockTerminator::UnconditionalBranch, guest_pc)
                            }
                            DelaySlotOutcome::DefiniteTrap { guest_pc: trap_pc } => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                (Ps2EeBlockTerminator::ArithmeticTrap, trap_pc)
                            }
                            DelaySlotOutcome::MissingOrUnsupported => {
                                (Ps2EeBlockTerminator::MissingDelaySlot, guest_pc)
                            }
                        };
                    return Ok(BlockAnalysis {
                        block: self.block(
                            start_guest_va,
                            continuation,
                            decoded_word_count,
                            Some(terminator_guest_pc),
                            terminator,
                        ),
                        successors,
                    });
                }
                FlowKind::Call => {
                    state.set(31, ConstantValue::Exact(pc_after_delay(guest_pc)));
                    let target =
                        decoded
                            .direct_target
                            .ok_or(Ps2EeObserverError::IneligibleContainer {
                                requirement: "direct target for decoded call",
                            })?;
                    let continuation = pc_after_delay(guest_pc);
                    let mut successors = Vec::new();
                    let (terminator, terminator_guest_pc) =
                        match self.execute_delay_slot(guest_pc, &mut state, emit_observations)? {
                            DelaySlotOutcome::Continue => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                successors.push(BlockSuccessor {
                                    edge: self.edge(
                                        start_guest_va,
                                        guest_pc,
                                        target,
                                        Ps2EeCfgEdgeKind::DirectCall,
                                    ),
                                    state: None,
                                });
                                successors.push(BlockSuccessor {
                                    edge: self.edge(
                                        start_guest_va,
                                        guest_pc,
                                        continuation,
                                        Ps2EeCfgEdgeKind::CallContinuation,
                                    ),
                                    state: Some(RegisterState::unknown()),
                                });
                                (Ps2EeBlockTerminator::DirectCall, guest_pc)
                            }
                            DelaySlotOutcome::DefiniteTrap { guest_pc: trap_pc } => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                (Ps2EeBlockTerminator::ArithmeticTrap, trap_pc)
                            }
                            DelaySlotOutcome::MissingOrUnsupported => {
                                (Ps2EeBlockTerminator::MissingDelaySlot, guest_pc)
                            }
                        };
                    return Ok(BlockAnalysis {
                        block: self.block(
                            start_guest_va,
                            continuation,
                            decoded_word_count,
                            Some(terminator_guest_pc),
                            terminator,
                        ),
                        successors,
                    });
                }
                FlowKind::IndirectCall => {
                    let destination = rd(word);
                    state.set(destination, ConstantValue::Exact(pc_after_delay(guest_pc)));
                    let continuation = pc_after_delay(guest_pc);
                    let mut successors = Vec::new();
                    let (terminator, terminator_guest_pc) =
                        match self.execute_delay_slot(guest_pc, &mut state, emit_observations)? {
                            DelaySlotOutcome::Continue => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                successors.push(BlockSuccessor {
                                    edge: self.edge(
                                        start_guest_va,
                                        guest_pc,
                                        continuation,
                                        Ps2EeCfgEdgeKind::CallContinuation,
                                    ),
                                    state: Some(RegisterState::unknown()),
                                });
                                (Ps2EeBlockTerminator::IndirectCall, guest_pc)
                            }
                            DelaySlotOutcome::DefiniteTrap { guest_pc: trap_pc } => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                (Ps2EeBlockTerminator::ArithmeticTrap, trap_pc)
                            }
                            DelaySlotOutcome::MissingOrUnsupported => {
                                (Ps2EeBlockTerminator::MissingDelaySlot, guest_pc)
                            }
                        };
                    return Ok(BlockAnalysis {
                        block: self.block(
                            start_guest_va,
                            continuation,
                            decoded_word_count,
                            Some(terminator_guest_pc),
                            terminator,
                        ),
                        successors,
                    });
                }
                FlowKind::IndirectBranch | FlowKind::Return => {
                    let continuation = pc_after_delay(guest_pc);
                    let is_return = opcode(word) == 0 && function(word) == 0x08 && rs(word) == 31;
                    let (terminator, terminator_guest_pc) =
                        match self.execute_delay_slot(guest_pc, &mut state, emit_observations)? {
                            DelaySlotOutcome::Continue => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                if is_return {
                                    (Ps2EeBlockTerminator::Return, guest_pc)
                                } else {
                                    (Ps2EeBlockTerminator::IndirectBranch, guest_pc)
                                }
                            }
                            DelaySlotOutcome::DefiniteTrap { guest_pc: trap_pc } => {
                                count_delay_slot_word(&mut decoded_word_count)?;
                                (Ps2EeBlockTerminator::ArithmeticTrap, trap_pc)
                            }
                            DelaySlotOutcome::MissingOrUnsupported => {
                                (Ps2EeBlockTerminator::MissingDelaySlot, guest_pc)
                            }
                        };
                    return Ok(BlockAnalysis {
                        block: self.block(
                            start_guest_va,
                            continuation,
                            decoded_word_count,
                            Some(terminator_guest_pc),
                            terminator,
                        ),
                        successors: Vec::new(),
                    });
                }
                FlowKind::Interrupt => {
                    return Ok(BlockAnalysis {
                        block: self.block(
                            start_guest_va,
                            guest_pc.saturating_add(4),
                            decoded_word_count,
                            Some(guest_pc),
                            Ps2EeBlockTerminator::Interrupt,
                        ),
                        successors: Vec::new(),
                    });
                }
                FlowKind::Privileged | FlowKind::Invalid => {
                    state.clear();
                    return Ok(BlockAnalysis {
                        block: self.block(
                            start_guest_va,
                            guest_pc.saturating_add(4),
                            decoded_word_count,
                            Some(guest_pc),
                            Ps2EeBlockTerminator::Invalid,
                        ),
                        successors: Vec::new(),
                    });
                }
            }
        }
    }

    fn execute_delay_slot(
        &mut self,
        branch_guest_pc: u64,
        state: &mut RegisterState,
        emit_observations: bool,
    ) -> Result<DelaySlotOutcome, Ps2EeObserverError> {
        let slot_guest_pc =
            branch_guest_pc
                .checked_add(4)
                .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                    "delay-slot guest PC",
                ))?;
        let Some(word_bytes) = self.word_at(slot_guest_pc) else {
            state.clear();
            return Ok(DelaySlotOutcome::MissingOrUnsupported);
        };
        self.bump_cfg_word_steps()?;
        let word = u32::from_le_bytes(word_bytes);
        match self.decoder.decode_one(&word_bytes, slot_guest_pc) {
            DecodeOutcome::Decoded(decoded) if decoded.flow == FlowKind::Sequential => Ok(
                match self.apply_sequential_effects(
                    word,
                    slot_guest_pc,
                    state,
                    emit_observations,
                )? {
                    SequentialEffectOutcome::Continue => DelaySlotOutcome::Continue,
                    SequentialEffectOutcome::DefiniteTrap => DelaySlotOutcome::DefiniteTrap {
                        guest_pc: slot_guest_pc,
                    },
                },
            ),
            DecodeOutcome::Decoded(_)
            | DecodeOutcome::Invalid
            | DecodeOutcome::Truncated { .. }
            | DecodeOutcome::Unsupported { .. } => {
                state.clear();
                Ok(DelaySlotOutcome::MissingOrUnsupported)
            }
        }
    }

    fn insert_entry_state(
        &self,
        states: &mut BTreeMap<u64, RegisterState>,
        pending: &mut BTreeSet<u64>,
        guest_va: u64,
        incoming: RegisterState,
    ) -> Result<(), Ps2EeObserverError> {
        if let Some(existing) = states.get_mut(&guest_va) {
            if existing.join_from(&incoming) {
                pending.insert(guest_va);
            }
            return Ok(());
        }
        enforce_output_limit(
            "basic blocks",
            usize_to_u64(states.len().saturating_add(1), "basic-block count")?,
            usize_to_u64(self.limits.maximum_blocks, "selected block limit")?,
        )?;
        states.insert(guest_va, incoming);
        pending.insert(guest_va);
        Ok(())
    }

    fn insert_edge(&mut self, edge: Ps2EeCfgEdge) -> Result<(), Ps2EeObserverError> {
        if !self.edges.contains(&edge) {
            enforce_output_limit(
                "CFG edges",
                usize_to_u64(self.edges.len().saturating_add(1), "CFG edge count")?,
                usize_to_u64(self.limits.maximum_edges, "selected edge limit")?,
            )?;
            self.edges.insert(edge);
        }
        Ok(())
    }

    fn add_seed(
        &mut self,
        guest_va: u64,
        source: Ps2EeFunctionSeedSource,
    ) -> Result<(), Ps2EeObserverError> {
        if !self.is_executable_word(guest_va) {
            return Ok(());
        }
        if !self.seeds.contains_key(&guest_va) {
            enforce_output_limit(
                "function seeds",
                usize_to_u64(self.seeds.len().saturating_add(1), "function seed count")?,
                usize_to_u64(self.limits.maximum_seeds, "selected seed limit")?,
            )?;
        }
        self.seeds.entry(guest_va).or_default().insert(source);
        self.add_boundary(guest_va)
    }

    fn add_boundary_if_executable(&mut self, guest_va: u64) -> Result<(), Ps2EeObserverError> {
        if self.is_executable_word(guest_va) {
            self.add_boundary(guest_va)?;
        }
        Ok(())
    }

    fn add_boundary(&mut self, guest_va: u64) -> Result<(), Ps2EeObserverError> {
        if !self.boundaries.contains(&guest_va) {
            enforce_output_limit(
                "basic-block boundaries",
                usize_to_u64(
                    self.boundaries.len().saturating_add(1),
                    "basic-block boundary count",
                )?,
                usize_to_u64(self.limits.maximum_blocks, "selected block limit")?,
            )?;
            self.boundaries.insert(guest_va);
        }
        Ok(())
    }

    fn bump_cfg_word_steps(&mut self) -> Result<(), Ps2EeObserverError> {
        self.cfg_word_steps =
            self.cfg_word_steps
                .checked_add(1)
                .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                    "CFG decoded word steps",
                ))?;
        enforce_output_limit(
            "CFG decoded word steps",
            usize_to_u64(self.cfg_word_steps, "CFG decoded word steps")?,
            usize_to_u64(self.limits.maximum_words, "selected word limit")?,
        )
    }

    fn word_at(&self, guest_va: u64) -> Option<[u8; 4]> {
        if guest_va % 4 != 0 {
            return None;
        }
        let index = self
            .coverage
            .partition_point(|range| range.record.end_guest_va <= guest_va);
        let range = self.coverage.get(index)?;
        if guest_va < range.record.start_guest_va
            || guest_va
                .checked_add(4)
                .is_none_or(|end| end > range.record.end_guest_va)
        {
            return None;
        }
        let delta = usize::try_from(guest_va - range.record.start_guest_va).ok()?;
        let file_offset = range.start_file_offset.checked_add(delta)?;
        let word = self.bytes.get(file_offset..file_offset.checked_add(4)?)?;
        Some([word[0], word[1], word[2], word[3]])
    }

    fn is_executable_word(&self, guest_va: u64) -> bool {
        self.word_at(guest_va).is_some()
    }

    fn rva(&self, guest_va: u64) -> Option<u64> {
        guest_va.checked_sub(self.image_base)
    }

    fn edge(
        &self,
        source_block_guest_va: u64,
        instruction_guest_pc: u64,
        target_guest_va: u64,
        kind: Ps2EeCfgEdgeKind,
    ) -> Ps2EeCfgEdge {
        Ps2EeCfgEdge {
            source_block_guest_va,
            source_block_rva: source_block_guest_va - self.image_base,
            instruction_guest_pc,
            instruction_rva: instruction_guest_pc - self.image_base,
            target_guest_va,
            target_rva: self.rva(target_guest_va),
            kind,
        }
    }

    fn block(
        &self,
        start_guest_va: u64,
        end_guest_va: u64,
        decoded_word_count: u64,
        terminator_guest_pc: Option<u64>,
        terminator: Ps2EeBlockTerminator,
    ) -> Ps2EeBasicBlock {
        Ps2EeBasicBlock {
            start_guest_va,
            start_rva: start_guest_va - self.image_base,
            end_guest_va,
            end_rva: self.rva(end_guest_va),
            decoded_word_count,
            terminator_guest_pc,
            terminator_rva: terminator_guest_pc.and_then(|pc| self.rva(pc)),
            terminator,
        }
    }
}

const fn pc_after_delay(guest_pc: u64) -> u64 {
    guest_pc + 8
}

fn count_delay_slot_word(decoded_word_count: &mut u64) -> Result<(), Ps2EeObserverError> {
    *decoded_word_count =
        decoded_word_count
            .checked_add(1)
            .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                "basic-block delay-slot word count",
            ))?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct MemoryAccessSpec {
    base_register: u8,
    value_register: u8,
    offset: i16,
    form: Ps2EeAccessForm,
    width: Ps2EeAccessWidth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequentialEffectOutcome {
    Continue,
    DefiniteTrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckedConstant {
    Value(ConstantValue),
    DefiniteOverflow,
}

impl ObserverAccumulator<'_> {
    /// Apply only closed base-integer semantics after the selected exact
    /// profile has accepted the word. This raw refinement is not a decoder.
    fn apply_sequential_effects(
        &mut self,
        word: u32,
        guest_pc: u64,
        state: &mut RegisterState,
        emit_observations: bool,
    ) -> Result<SequentialEffectOutcome, Ps2EeObserverError> {
        if let Some(access) = memory_access(word) {
            if emit_observations {
                self.record_memory_access(guest_pc, state, access)?;
            }
            if access.form.direction() == Ps2EeAccessDirection::Read {
                state.set(access.value_register, ConstantValue::Unknown);
            }
            return Ok(SequentialEffectOutcome::Continue);
        }

        let primary = opcode(word);
        match primary {
            0x00 => {
                return self.apply_special_effects(word, guest_pc, state, emit_observations);
            }
            0x01 => {
                // The only sequential REGIMM encodings accepted by core-v1 are
                // MTSAB/Mtsah; neither writes a GPR.
            }
            0x08 => {
                let CheckedConstant::Value(value) =
                    exact_i32_checked_add(state.get(rs(word)), signed_immediate(word))
                else {
                    return Ok(SequentialEffectOutcome::DefiniteTrap);
                };
                state.set(rt(word), value);
                self.maybe_record_materialization(emit_observations, guest_pc, rt(word), value)?;
            }
            0x09 => {
                let value = exact_i32_wrapping_add(state.get(rs(word)), signed_immediate(word));
                state.set(rt(word), value);
                self.maybe_record_materialization(emit_observations, guest_pc, rt(word), value)?;
            }
            0x0a => {
                let value = match state.get(rs(word)) {
                    ConstantValue::Exact(value) => ConstantValue::Exact(u64::from(
                        (value as i64) < i64::from(signed_immediate(word)),
                    )),
                    ConstantValue::Unknown => ConstantValue::Unknown,
                };
                state.set(rt(word), value);
            }
            0x0b => {
                let immediate = sign_extend_i16(signed_immediate(word));
                let value = match state.get(rs(word)) {
                    ConstantValue::Exact(value) => {
                        ConstantValue::Exact(u64::from(value < immediate))
                    }
                    ConstantValue::Unknown => ConstantValue::Unknown,
                };
                state.set(rt(word), value);
            }
            0x0c => {
                let value = map_exact(state.get(rs(word)), |value| {
                    value & u64::from(logical_immediate(word))
                });
                state.set(rt(word), value);
                self.maybe_record_materialization(emit_observations, guest_pc, rt(word), value)?;
            }
            0x0d => {
                let value = map_exact(state.get(rs(word)), |value| {
                    value | u64::from(logical_immediate(word))
                });
                state.set(rt(word), value);
                self.maybe_record_materialization(emit_observations, guest_pc, rt(word), value)?;
            }
            0x0e => {
                let value = map_exact(state.get(rs(word)), |value| {
                    value ^ u64::from(logical_immediate(word))
                });
                state.set(rt(word), value);
                self.maybe_record_materialization(emit_observations, guest_pc, rt(word), value)?;
            }
            0x0f => {
                let value =
                    ConstantValue::Exact(sign_extend_u32(u32::from(logical_immediate(word)) << 16));
                state.set(rt(word), value);
                self.maybe_record_materialization(emit_observations, guest_pc, rt(word), value)?;
            }
            0x18 => {
                let CheckedConstant::Value(value) =
                    exact_i64_checked_add(state.get(rs(word)), signed_immediate(word))
                else {
                    return Ok(SequentialEffectOutcome::DefiniteTrap);
                };
                state.set(rt(word), value);
                self.maybe_record_materialization(emit_observations, guest_pc, rt(word), value)?;
            }
            0x19 => {
                let value = map_exact(state.get(rs(word)), |value| {
                    value.wrapping_add_signed(i64::from(signed_immediate(word)))
                });
                state.set(rt(word), value);
                self.maybe_record_materialization(emit_observations, guest_pc, rt(word), value)?;
            }
            0x2f | 0x33 => {
                // CACHE/PREF `rt` is an operation selector/hint, never a GPR
                // destination and never an observer memory access.
            }
            0x1c => {
                // Additive MMI profiles accept more words than the closed v1
                // scalar lattice. Do not infer their operands from raw fields.
                state.clear();
            }
            _ => {
                // Every supported base scalar load/store was handled above;
                // decoded control transfers are handled by `analyze_block`.
                // A future decoded sequential family stays conservative.
                state.clear();
            }
        }
        Ok(SequentialEffectOutcome::Continue)
    }

    fn apply_special_effects(
        &mut self,
        word: u32,
        guest_pc: u64,
        state: &mut RegisterState,
        emit_observations: bool,
    ) -> Result<SequentialEffectOutcome, Ps2EeObserverError> {
        let destination = rd(word);
        let trapping = match function(word) {
            0x20 => Some(exact_i32_binary_checked(
                state.get(rs(word)),
                state.get(rt(word)),
                i32::checked_add,
            )),
            0x22 => Some(exact_i32_binary_checked(
                state.get(rs(word)),
                state.get(rt(word)),
                i32::checked_sub,
            )),
            0x2c => Some(exact_i64_binary_checked(
                state.get(rs(word)),
                state.get(rt(word)),
                i64::checked_add,
            )),
            0x2e => Some(exact_i64_binary_checked(
                state.get(rs(word)),
                state.get(rt(word)),
                i64::checked_sub,
            )),
            _ => None,
        };
        if let Some(trapping) = trapping {
            let CheckedConstant::Value(value) = trapping else {
                return Ok(SequentialEffectOutcome::DefiniteTrap);
            };
            state.set(destination, value);
            self.maybe_record_materialization(emit_observations, guest_pc, destination, value)?;
            return Ok(SequentialEffectOutcome::Continue);
        }
        let value = match function(word) {
            0x00 => map_exact(state.get(rt(word)), |value| {
                sign_extend_u32((value as u32).wrapping_shl(u32::from(sa(word))))
            }),
            0x02 => map_exact(state.get(rt(word)), |value| {
                sign_extend_u32((value as u32).wrapping_shr(u32::from(sa(word))))
            }),
            0x03 => map_exact(state.get(rt(word)), |value| {
                sign_extend_u32(((value as u32 as i32) >> u32::from(sa(word))) as u32)
            }),
            0x04 => binary_exact(state.get(rt(word)), state.get(rs(word)), |left, right| {
                sign_extend_u32((left as u32).wrapping_shl((right as u32) & 31))
            }),
            0x06 => binary_exact(state.get(rt(word)), state.get(rs(word)), |left, right| {
                sign_extend_u32((left as u32).wrapping_shr((right as u32) & 31))
            }),
            0x07 => binary_exact(state.get(rt(word)), state.get(rs(word)), |left, right| {
                sign_extend_u32(((left as u32 as i32) >> ((right as u32) & 31)) as u32)
            }),
            0x0a => {
                self.apply_conditional_move(word, state, false);
                self.maybe_record_materialization(
                    emit_observations,
                    guest_pc,
                    destination,
                    state.get(destination),
                )?;
                return Ok(SequentialEffectOutcome::Continue);
            }
            0x0b => {
                self.apply_conditional_move(word, state, true);
                self.maybe_record_materialization(
                    emit_observations,
                    guest_pc,
                    destination,
                    state.get(destination),
                )?;
                return Ok(SequentialEffectOutcome::Continue);
            }
            0x10 | 0x12 | 0x28 => ConstantValue::Unknown,
            0x14 => binary_exact(state.get(rt(word)), state.get(rs(word)), |left, right| {
                left.wrapping_shl((right as u32) & 63)
            }),
            0x16 => binary_exact(state.get(rt(word)), state.get(rs(word)), |left, right| {
                left.wrapping_shr((right as u32) & 63)
            }),
            0x17 => binary_exact(state.get(rt(word)), state.get(rs(word)), |left, right| {
                ((left as i64) >> ((right as u32) & 63)) as u64
            }),
            0x18 | 0x19 => ConstantValue::Unknown,
            0x21 => binary_exact(state.get(rs(word)), state.get(rt(word)), |left, right| {
                sign_extend_u32((left as u32).wrapping_add(right as u32))
            }),
            0x23 => binary_exact(state.get(rs(word)), state.get(rt(word)), |left, right| {
                sign_extend_u32((left as u32).wrapping_sub(right as u32))
            }),
            0x24 => binary_exact(state.get(rs(word)), state.get(rt(word)), |left, right| {
                left & right
            }),
            0x25 => binary_exact(state.get(rs(word)), state.get(rt(word)), |left, right| {
                left | right
            }),
            0x26 => binary_exact(state.get(rs(word)), state.get(rt(word)), |left, right| {
                left ^ right
            }),
            0x27 => binary_exact(state.get(rs(word)), state.get(rt(word)), |left, right| {
                !(left | right)
            }),
            0x2a => binary_exact(state.get(rs(word)), state.get(rt(word)), |left, right| {
                u64::from((left as i64) < (right as i64))
            }),
            0x2b => binary_exact(state.get(rs(word)), state.get(rt(word)), |left, right| {
                u64::from(left < right)
            }),
            0x2d => binary_exact(state.get(rs(word)), state.get(rt(word)), u64::wrapping_add),
            0x2f => binary_exact(state.get(rs(word)), state.get(rt(word)), u64::wrapping_sub),
            0x38 => map_exact(state.get(rt(word)), |value| value << u32::from(sa(word))),
            0x3a => map_exact(state.get(rt(word)), |value| value >> u32::from(sa(word))),
            0x3b => map_exact(state.get(rt(word)), |value| {
                ((value as i64) >> u32::from(sa(word))) as u64
            }),
            0x3c => map_exact(state.get(rt(word)), |value| {
                value << (u32::from(sa(word)) + 32)
            }),
            0x3e => map_exact(state.get(rt(word)), |value| {
                value >> (u32::from(sa(word)) + 32)
            }),
            0x3f => map_exact(state.get(rt(word)), |value| {
                ((value as i64) >> (u32::from(sa(word)) + 32)) as u64
            }),
            // MTHI/MTLO/MTSA, DIV/DIVU, SYNC and control-flow SPECIAL
            // encodings do not write a modeled GPR in this sequential path.
            0x0f | 0x11 | 0x13 | 0x1a | 0x1b | 0x29 => {
                return Ok(SequentialEffectOutcome::Continue);
            }
            _ => {
                state.clear();
                return Ok(SequentialEffectOutcome::Continue);
            }
        };
        state.set(destination, value);
        self.maybe_record_materialization(emit_observations, guest_pc, destination, value)?;
        Ok(SequentialEffectOutcome::Continue)
    }

    fn apply_conditional_move(&self, word: u32, state: &mut RegisterState, move_if_nonzero: bool) {
        let condition = state.get(rt(word));
        let source = state.get(rs(word));
        let destination = rd(word);
        let previous = state.get(destination);
        let value = match condition {
            ConstantValue::Exact(value) if (value != 0) == move_if_nonzero => source,
            ConstantValue::Exact(_) => previous,
            ConstantValue::Unknown if previous == source => previous,
            ConstantValue::Unknown => ConstantValue::Unknown,
        };
        state.set(destination, value);
    }

    fn maybe_record_materialization(
        &mut self,
        emit_observations: bool,
        instruction_guest_pc: u64,
        destination_register: u8,
        value: ConstantValue,
    ) -> Result<(), Ps2EeObserverError> {
        if emit_observations {
            self.record_materialization(instruction_guest_pc, destination_register, value)?;
        }
        Ok(())
    }

    fn record_materialization(
        &mut self,
        instruction_guest_pc: u64,
        destination_register: u8,
        value: ConstantValue,
    ) -> Result<(), Ps2EeObserverError> {
        if destination_register == 0 {
            return Ok(());
        }
        let ConstantValue::Exact(value) = value else {
            return Ok(());
        };
        let target_guest_va = canonical_guest_address(value);
        let resolved = self.classify_span(target_guest_va, 1);
        if !matches!(
            resolved.class,
            Ps2EeDataTargetClass::FullyFileBacked | Ps2EeDataTargetClass::MappedZeroFill
        ) {
            return Ok(());
        }
        let Some(target_rva) = self.rva(target_guest_va) else {
            return Ok(());
        };
        let materialization = Ps2EeAddressMaterialization {
            instruction_guest_pc,
            instruction_rva: instruction_guest_pc - self.image_base,
            destination_register,
            target_guest_va,
            target_rva,
            target_class: resolved.class,
        };
        if !self.materializations.contains(&materialization) {
            enforce_output_limit(
                "address materializations",
                usize_to_u64(
                    self.materializations.len().saturating_add(1),
                    "address materialization count",
                )?,
                usize_to_u64(self.limits.maximum_xrefs, "selected xref limit")?,
            )?;
            self.materializations.insert(materialization);
        }
        Ok(())
    }

    fn record_memory_access(
        &mut self,
        instruction_guest_pc: u64,
        state: &RegisterState,
        access: MemoryAccessSpec,
    ) -> Result<(), Ps2EeObserverError> {
        let ConstantValue::Exact(base) = state.get(access.base_register) else {
            return Ok(());
        };
        let target_guest_va =
            canonical_guest_address(base.wrapping_add_signed(i64::from(access.offset)));
        let width_bytes = access.width.bytes();
        let access_span_guest_va = match access.form {
            Ps2EeAccessForm::MergeLoadLeft
            | Ps2EeAccessForm::MergeLoadRight
            | Ps2EeAccessForm::MergeStoreLeft
            | Ps2EeAccessForm::MergeStoreRight => target_guest_va & !(width_bytes - 1),
            Ps2EeAccessForm::ScalarLoad | Ps2EeAccessForm::ScalarStore => target_guest_va,
        };
        let resolved = self.classify_span(access_span_guest_va, width_bytes);
        let xref = Ps2EeDataXref {
            instruction_guest_pc,
            instruction_rva: instruction_guest_pc - self.image_base,
            target_guest_va,
            target_rva: self.rva(target_guest_va),
            access_span_guest_va,
            access_span_rva: self.rva(access_span_guest_va),
            direction: access.form.direction(),
            form: access.form,
            width: access.width,
            target_class: resolved.class,
            program_header_index: resolved.program_header_index,
            file_offset: resolved.file_offset,
            permissions: resolved.permissions,
        };
        if !self.xrefs.contains(&xref) {
            enforce_output_limit(
                "data xrefs",
                usize_to_u64(self.xrefs.len().saturating_add(1), "data xref count")?,
                usize_to_u64(self.limits.maximum_xrefs, "selected xref limit")?,
            )?;
            self.xrefs.insert(xref.clone());
        }
        if resolved.class == Ps2EeDataTargetClass::FullyFileBacked {
            self.record_site(xref, resolved)?;
        }
        Ok(())
    }

    fn record_site(
        &mut self,
        xref: Ps2EeDataXref,
        resolved: ResolvedTarget,
    ) -> Result<(), Ps2EeObserverError> {
        let target_rva = xref
            .target_rva
            .ok_or(Ps2EeObserverError::IneligibleContainer {
                requirement: "RVA for a fully file-backed target",
            })?;
        let access_span_rva =
            xref.access_span_rva
                .ok_or(Ps2EeObserverError::IneligibleContainer {
                    requirement: "RVA for a fully file-backed access span",
                })?;
        let program_header_index =
            resolved
                .program_header_index
                .ok_or(Ps2EeObserverError::IneligibleContainer {
                    requirement: "segment identity for a fully file-backed target",
                })?;
        let file_offset = resolved
            .file_offset
            .ok_or(Ps2EeObserverError::IneligibleContainer {
                requirement: "file offset for a fully file-backed target",
            })?;
        let permissions = resolved
            .permissions
            .ok_or(Ps2EeObserverError::IneligibleContainer {
                requirement: "permissions for a fully file-backed target",
            })?;
        let string_anchor = self.string_anchor(xref.target_guest_va)?;
        let site = Ps2EeObserverSite {
            instruction_guest_pc: xref.instruction_guest_pc,
            instruction_rva: xref.instruction_rva,
            target_guest_va: xref.target_guest_va,
            target_rva,
            access_span_guest_va: xref.access_span_guest_va,
            access_span_rva,
            direction: xref.direction,
            form: xref.form,
            width: xref.width,
            program_header_index,
            file_offset,
            permissions,
            string_anchor,
        };
        if self.sites.contains(&site) {
            return Ok(());
        }
        enforce_output_limit(
            "observer sites",
            usize_to_u64(self.sites.len().saturating_add(1), "observer site count")?,
            usize_to_u64(self.limits.maximum_sites, "selected site limit")?,
        )?;
        if let Some(anchor) = &site.string_anchor {
            let new_total = self
                .total_string_bytes
                .checked_add(anchor.value.len())
                .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                    "aggregate string-anchor bytes",
                ))?;
            enforce_output_limit(
                "aggregate string-anchor bytes",
                usize_to_u64(new_total, "aggregate string-anchor bytes")?,
                usize_to_u64(
                    self.limits.maximum_total_string_bytes,
                    "selected aggregate string byte limit",
                )?,
            )?;
            self.total_string_bytes = new_total;
        }
        self.sites.insert(site);
        Ok(())
    }

    fn classify_span(&self, start_guest_va: u64, byte_size: u64) -> ResolvedTarget {
        classify_span_in_segments(&self.analysis.load_segments, start_guest_va, byte_size)
    }

    fn string_anchor(
        &self,
        target_guest_va: u64,
    ) -> Result<Option<Ps2EeStringAnchor>, Ps2EeObserverError> {
        let segments = &self.analysis.load_segments;
        let (upper_bound, _) = load_segment_start_upper_bound(segments, target_guest_va);
        let Some(segment) = upper_bound
            .checked_sub(1)
            .and_then(|index| segments.get(index))
            .filter(|segment| {
                target_guest_va
                    < segment
                        .virtual_address
                        .checked_add(segment.file_size)
                        .unwrap_or(segment.virtual_address)
            })
        else {
            return Ok(None);
        };
        let relative = target_guest_va - segment.virtual_address;
        let file_offset = segment.file_offset.checked_add(relative).ok_or(
            Ps2EeObserverError::ArithmeticOverflow("string-anchor file offset"),
        )?;
        let remaining = segment.file_size - relative;
        let scan_size = remaining.min(usize_to_u64(
            self.limits.maximum_string_bytes,
            "selected string byte limit",
        )?);
        let start = usize::try_from(file_offset)
            .map_err(|_| Ps2EeObserverError::IntegerConversion("string-anchor file offset"))?;
        let scan_size = usize::try_from(scan_size)
            .map_err(|_| Ps2EeObserverError::IntegerConversion("string-anchor scan size"))?;
        let end = start
            .checked_add(scan_size)
            .ok_or(Ps2EeObserverError::ArithmeticOverflow(
                "string-anchor file range",
            ))?;
        let Some(bytes) = self.bytes.get(start..end) else {
            return Ok(None);
        };
        let Some(nul) = bytes.iter().position(|byte| *byte == 0) else {
            return Ok(None);
        };
        if nul < 4 || !bytes[..nul].iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            return Ok(None);
        }
        let value = std::str::from_utf8(&bytes[..nul])
            .map_err(|_| Ps2EeObserverError::IneligibleContainer {
                requirement: "valid UTF-8 observer string anchors",
            })?
            .to_owned();
        let byte_size = u32::try_from(nul.saturating_add(1))
            .map_err(|_| Ps2EeObserverError::IntegerConversion("string-anchor byte size"))?;
        Ok(Some(Ps2EeStringAnchor {
            guest_va: target_guest_va,
            rva: target_guest_va - self.image_base,
            byte_size,
            value,
        }))
    }
}

fn memory_access(word: u32) -> Option<MemoryAccessSpec> {
    let (form, width) = match opcode(word) {
        0x1a => (Ps2EeAccessForm::MergeLoadLeft, Ps2EeAccessWidth::Doubleword),
        0x1b => (
            Ps2EeAccessForm::MergeLoadRight,
            Ps2EeAccessWidth::Doubleword,
        ),
        0x1e => (Ps2EeAccessForm::ScalarLoad, Ps2EeAccessWidth::Quadword),
        0x1f => (Ps2EeAccessForm::ScalarStore, Ps2EeAccessWidth::Quadword),
        0x20 | 0x24 => (Ps2EeAccessForm::ScalarLoad, Ps2EeAccessWidth::Byte),
        0x21 | 0x25 => (Ps2EeAccessForm::ScalarLoad, Ps2EeAccessWidth::Halfword),
        0x22 => (Ps2EeAccessForm::MergeLoadLeft, Ps2EeAccessWidth::Word),
        0x23 | 0x27 => (Ps2EeAccessForm::ScalarLoad, Ps2EeAccessWidth::Word),
        0x26 => (Ps2EeAccessForm::MergeLoadRight, Ps2EeAccessWidth::Word),
        0x28 => (Ps2EeAccessForm::ScalarStore, Ps2EeAccessWidth::Byte),
        0x29 => (Ps2EeAccessForm::ScalarStore, Ps2EeAccessWidth::Halfword),
        0x2a => (Ps2EeAccessForm::MergeStoreLeft, Ps2EeAccessWidth::Word),
        0x2b => (Ps2EeAccessForm::ScalarStore, Ps2EeAccessWidth::Word),
        0x2c => (
            Ps2EeAccessForm::MergeStoreLeft,
            Ps2EeAccessWidth::Doubleword,
        ),
        0x2d => (
            Ps2EeAccessForm::MergeStoreRight,
            Ps2EeAccessWidth::Doubleword,
        ),
        0x2e => (Ps2EeAccessForm::MergeStoreRight, Ps2EeAccessWidth::Word),
        0x37 => (Ps2EeAccessForm::ScalarLoad, Ps2EeAccessWidth::Doubleword),
        0x3f => (Ps2EeAccessForm::ScalarStore, Ps2EeAccessWidth::Doubleword),
        // CACHE/PREF and all COP/VU spaces are deliberately absent.
        _ => return None,
    };
    Some(MemoryAccessSpec {
        base_register: rs(word),
        value_register: rt(word),
        offset: signed_immediate(word),
        form,
        width,
    })
}

const fn opcode(word: u32) -> u8 {
    ((word >> 26) & 0x3f) as u8
}

const fn rs(word: u32) -> u8 {
    ((word >> 21) & 0x1f) as u8
}

const fn rt(word: u32) -> u8 {
    ((word >> 16) & 0x1f) as u8
}

const fn rd(word: u32) -> u8 {
    ((word >> 11) & 0x1f) as u8
}

const fn sa(word: u32) -> u8 {
    ((word >> 6) & 0x1f) as u8
}

const fn function(word: u32) -> u8 {
    (word & 0x3f) as u8
}

const fn logical_immediate(word: u32) -> u16 {
    (word & 0xffff) as u16
}

const fn signed_immediate(word: u32) -> i16 {
    logical_immediate(word) as i16
}

const fn is_regimm_link(word: u32) -> bool {
    opcode(word) == 0x01 && matches!(rt(word), 0x10..=0x13)
}

const fn is_branch_likely(word: u32) -> bool {
    matches!(opcode(word), 0x14..=0x17)
        || (opcode(word) == 0x01 && matches!(rt(word), 0x02 | 0x03 | 0x12 | 0x13))
}

const fn sign_extend_u32(value: u32) -> u64 {
    (value as i32 as i64) as u64
}

const fn sign_extend_i16(value: i16) -> u64 {
    (value as i64) as u64
}

fn canonical_guest_address(value: u64) -> u64 {
    let low = value as u32;
    let zero_extended = u64::from(low);
    let sign_extended = sign_extend_u32(low);
    if value == zero_extended || value == sign_extended {
        zero_extended
    } else {
        value
    }
}

fn map_exact(value: ConstantValue, operation: impl FnOnce(u64) -> u64) -> ConstantValue {
    match value {
        ConstantValue::Exact(value) => ConstantValue::Exact(operation(value)),
        ConstantValue::Unknown => ConstantValue::Unknown,
    }
}

fn binary_exact(
    left: ConstantValue,
    right: ConstantValue,
    operation: impl FnOnce(u64, u64) -> u64,
) -> ConstantValue {
    match (left, right) {
        (ConstantValue::Exact(left), ConstantValue::Exact(right)) => {
            ConstantValue::Exact(operation(left, right))
        }
        (ConstantValue::Unknown, _) | (_, ConstantValue::Unknown) => ConstantValue::Unknown,
    }
}

fn exact_i32_checked_add(value: ConstantValue, immediate: i16) -> CheckedConstant {
    match value {
        ConstantValue::Exact(value) => {
            match (value as u32 as i32).checked_add(i32::from(immediate)) {
                Some(result) => {
                    CheckedConstant::Value(ConstantValue::Exact(sign_extend_u32(result as u32)))
                }
                None => CheckedConstant::DefiniteOverflow,
            }
        }
        ConstantValue::Unknown => CheckedConstant::Value(ConstantValue::Unknown),
    }
}

fn exact_i32_wrapping_add(value: ConstantValue, immediate: i16) -> ConstantValue {
    map_exact(value, |value| {
        sign_extend_u32((value as u32).wrapping_add_signed(i32::from(immediate)))
    })
}

fn exact_i64_checked_add(value: ConstantValue, immediate: i16) -> CheckedConstant {
    match value {
        ConstantValue::Exact(value) => match (value as i64).checked_add(i64::from(immediate)) {
            Some(result) => CheckedConstant::Value(ConstantValue::Exact(result as u64)),
            None => CheckedConstant::DefiniteOverflow,
        },
        ConstantValue::Unknown => CheckedConstant::Value(ConstantValue::Unknown),
    }
}

fn exact_i32_binary_checked(
    left: ConstantValue,
    right: ConstantValue,
    operation: fn(i32, i32) -> Option<i32>,
) -> CheckedConstant {
    match (left, right) {
        (ConstantValue::Exact(left), ConstantValue::Exact(right)) => {
            match operation(left as u32 as i32, right as u32 as i32) {
                Some(result) => {
                    CheckedConstant::Value(ConstantValue::Exact(sign_extend_u32(result as u32)))
                }
                None => CheckedConstant::DefiniteOverflow,
            }
        }
        (ConstantValue::Unknown, _) | (_, ConstantValue::Unknown) => {
            CheckedConstant::Value(ConstantValue::Unknown)
        }
    }
}

fn exact_i64_binary_checked(
    left: ConstantValue,
    right: ConstantValue,
    operation: fn(i64, i64) -> Option<i64>,
) -> CheckedConstant {
    match (left, right) {
        (ConstantValue::Exact(left), ConstantValue::Exact(right)) => {
            match operation(left as i64, right as i64) {
                Some(result) => CheckedConstant::Value(ConstantValue::Exact(result as u64)),
                None => CheckedConstant::DefiniteOverflow,
            }
        }
        (ConstantValue::Unknown, _) | (_, ConstantValue::Unknown) => {
            CheckedConstant::Value(ConstantValue::Unknown)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_segment_upper_bound_stays_logarithmic_at_large_segment_counts() {
        const SEGMENT_COUNT: usize = 32_768;
        const MAXIMUM_PROBES: usize = 17;
        let segments: Vec<_> = (0..SEGMENT_COUNT)
            .map(|index| ElfLoadSegment {
                program_header_index: u16::try_from(index).expect("test index fits u16"),
                file_offset: u64::try_from(index).expect("test index fits u64") * 0x100,
                file_size: 0x100,
                virtual_address: u64::try_from(index).expect("test index fits u64") * 0x1000,
                memory_size: 0x100,
                flags: 4,
                alignment: 0x100,
            })
            .collect();

        let last_start = segments
            .last()
            .expect("large segment fixture is non-empty")
            .virtual_address;
        for (guest_va, expected_upper_bound) in [
            (0, 1),
            (0x100, 1),
            (0x1000, 2),
            (last_start, SEGMENT_COUNT),
            (u64::MAX, SEGMENT_COUNT),
        ] {
            let (upper_bound, probes) = load_segment_start_upper_bound(&segments, guest_va);
            assert_eq!(upper_bound, expected_upper_bound);
            assert!(
                probes <= MAXIMUM_PROBES,
                "{SEGMENT_COUNT} segments required {probes} probes"
            );
        }
    }

    #[test]
    fn indexed_load_segment_span_classification_preserves_sparse_boundaries() {
        let segments = vec![
            ElfLoadSegment {
                program_header_index: 1,
                file_offset: 0x200,
                file_size: 0x80,
                virtual_address: 0x1000,
                memory_size: 0x100,
                flags: 6,
                alignment: 0x100,
            },
            ElfLoadSegment {
                program_header_index: 2,
                file_offset: 0x400,
                file_size: 0x80,
                virtual_address: 0x1200,
                memory_size: 0x80,
                flags: 4,
                alignment: 0x100,
            },
        ];
        let cases = [
            (
                0x1000,
                1,
                Ps2EeDataTargetClass::FullyFileBacked,
                Some(1),
                Some(0x200),
            ),
            (
                0x107f,
                1,
                Ps2EeDataTargetClass::FullyFileBacked,
                Some(1),
                Some(0x27f),
            ),
            (
                0x107f,
                2,
                Ps2EeDataTargetClass::MappedCrossBoundary,
                Some(1),
                None,
            ),
            (
                0x1080,
                1,
                Ps2EeDataTargetClass::MappedZeroFill,
                Some(1),
                None,
            ),
            (
                0x10ff,
                1,
                Ps2EeDataTargetClass::MappedZeroFill,
                Some(1),
                None,
            ),
            (
                0x10ff,
                2,
                Ps2EeDataTargetClass::MappedCrossBoundary,
                Some(1),
                None,
            ),
            (0x1100, 0x100, Ps2EeDataTargetClass::Unmapped, None, None),
            (
                0x11ff,
                2,
                Ps2EeDataTargetClass::MappedCrossBoundary,
                Some(2),
                None,
            ),
            (
                0x1200,
                0x80,
                Ps2EeDataTargetClass::FullyFileBacked,
                Some(2),
                Some(0x400),
            ),
            (
                0x127f,
                2,
                Ps2EeDataTargetClass::MappedCrossBoundary,
                Some(2),
                None,
            ),
            (u64::MAX, 2, Ps2EeDataTargetClass::Unmapped, None, None),
        ];

        for (start, size, class, program_header_index, file_offset) in cases {
            let resolved = classify_span_in_segments(&segments, start, size);
            assert_eq!(resolved.class, class, "wrong class at {start:#x}+{size:#x}");
            assert_eq!(resolved.program_header_index, program_header_index);
            assert_eq!(resolved.file_offset, file_offset);
        }
    }
}
