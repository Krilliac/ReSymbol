//! Pure planning and presentation values for explicit offline disassembly.
//!
//! This module owns no files, processes, worker messages, preferences, or
//! durable project state. It accepts bytes already returned by the existing
//! identity-bound offline reader and projects one explicitly selected decoder
//! profile into a bounded, read-only linear preview.

use std::path::{Path, PathBuf};

use resymbol_analysis::{
    BinaryAnalysis, DecoderProfile, ElfClass, ElfEndian, ElfMachine, LinearDisassemblyLimits,
    LinearDisassemblyStopReason, LinearFlowControlCategory, decoder_for_profile,
    disassemble_linear,
};
use resymbol_core::BinaryIdentity;
use resymbol_debugger::{RelativeAddress, StaticAddressSpace, StaticImageLayout};
use thiserror::Error;

pub(crate) const R5900_PREVIEW_SIZES: [u32; 5] = [16, 32, 64, 128, 256];
pub(crate) const R5900_MAX_ROWS: usize = 64;
pub(crate) const R5900_WARNING: &str = "Explicit profile; ELF EM_MIPS does not identify R5900. Linear preview only; delay slots, CFG, and function boundaries are not modeled.";

/// The complete read-only action policy for one explicit R5900 row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum R5900InstructionAction {
    CopyRva,
    CopyPreferredAddress,
    CopyBytes,
    CopyInstruction,
    FollowDirectTarget,
}

impl R5900InstructionAction {
    pub(crate) const ALL: [Self; 5] = [
        Self::CopyRva,
        Self::CopyPreferredAddress,
        Self::CopyBytes,
        Self::CopyInstruction,
        Self::FollowDirectTarget,
    ];

    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::CopyRva => "Copy RVA",
            Self::CopyPreferredAddress => "Copy Preferred Address",
            Self::CopyBytes => "Copy Bytes",
            Self::CopyInstruction => "Copy Instruction",
            Self::FollowDirectTarget => "Follow Direct Target",
        }
    }
}

/// Why a structured analysis is ineligible for explicit R5900 decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum R5900EligibilityError {
    #[error("the active analysis is not ELF")]
    NotElf,
    #[error("explicit R5900 preview requires ELF32")]
    NotElf32,
    #[error("explicit R5900 preview requires a little-endian ELF")]
    NotLittleEndian,
    #[error("explicit R5900 preview requires ET_EXEC (e_type 2)")]
    NotExecutable,
    #[error("explicit R5900 preview requires ELF32 EM_MIPS")]
    NotMips,
}

/// Check only authoritative structured ELF fields. Architecture identity text
/// is deliberately not consulted and can never infer an R5900 selection.
pub(crate) fn require_explicit_r5900_eligibility(
    analysis: &BinaryAnalysis,
) -> Result<(), R5900EligibilityError> {
    let BinaryAnalysis::Elf(elf) = analysis else {
        return Err(R5900EligibilityError::NotElf);
    };
    if elf.class != ElfClass::Elf32 {
        return Err(R5900EligibilityError::NotElf32);
    }
    if elf.endian != ElfEndian::Little {
        return Err(R5900EligibilityError::NotLittleEndian);
    }
    if elf.elf_type != 2 {
        return Err(R5900EligibilityError::NotExecutable);
    }
    if ElfMachine::from_raw(elf.machine, elf.class) != ElfMachine::Mips {
        return Err(R5900EligibilityError::NotMips);
    }
    Ok(())
}

/// One transient, explicit decoder choice bound to a full binary identity and
/// canonical verified source path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct R5900DecoderSelection {
    identity: BinaryIdentity,
    canonical_source_path: PathBuf,
    exact_profile: DecoderProfile,
}

impl R5900DecoderSelection {
    pub(crate) fn explicit_latest(
        analysis: &BinaryAnalysis,
        canonical_source_path: &Path,
    ) -> Result<Self, R5900PreviewError> {
        require_explicit_r5900_eligibility(analysis)?;
        Ok(Self {
            identity: analysis.identity().clone(),
            canonical_source_path: canonical_source_path.to_path_buf(),
            // The associated constant is resolved here. The stored value is
            // the exact enum variant and does not move with the alias later.
            exact_profile: DecoderProfile::PS2_EE_R5900_LATEST,
        })
    }

    #[must_use]
    pub(crate) const fn exact_profile(&self) -> DecoderProfile {
        self.exact_profile
    }

    #[must_use]
    pub(crate) fn matches_source(
        &self,
        identity: &BinaryIdentity,
        canonical_source_path: &Path,
    ) -> bool {
        &self.identity == identity && self.canonical_source_path == canonical_source_path
    }

    pub(crate) fn bind_span(
        &self,
        identity: &BinaryIdentity,
        canonical_source_path: &Path,
        start_rva: u64,
        size: u32,
    ) -> Result<R5900PreviewBinding, R5900PreviewError> {
        if !self.matches_source(identity, canonical_source_path) {
            return Err(R5900PreviewError::StaleSelection);
        }
        Ok(R5900PreviewBinding {
            identity: identity.clone(),
            canonical_source_path: canonical_source_path.to_path_buf(),
            start_rva,
            size,
            exact_profile: self.exact_profile,
        })
    }
}

/// Drop a transient selection unless the active full identity and canonical
/// source still match. Returns whether stale state was cleared.
pub(crate) fn retain_current_r5900_selection(
    selection: &mut Option<R5900DecoderSelection>,
    current_source: Option<(&BinaryIdentity, &Path)>,
) -> bool {
    let stale = selection.as_ref().is_some_and(|selection| {
        current_source.is_none_or(|(identity, source)| !selection.matches_source(identity, source))
    });
    if stale {
        *selection = None;
    }
    stale
}

/// Full transient authority for exactly one preview. This value is never
/// serialized and never crosses the existing worker boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct R5900PreviewBinding {
    identity: BinaryIdentity,
    canonical_source_path: PathBuf,
    start_rva: u64,
    size: u32,
    exact_profile: DecoderProfile,
}

impl R5900PreviewBinding {
    #[must_use]
    pub(crate) const fn identity(&self) -> &BinaryIdentity {
        &self.identity
    }

    #[must_use]
    pub(crate) fn canonical_source_path(&self) -> &Path {
        &self.canonical_source_path
    }

    #[must_use]
    pub(crate) const fn start_rva(&self) -> u64 {
        self.start_rva
    }

    #[must_use]
    pub(crate) const fn size(&self) -> u32 {
        self.size
    }

    #[must_use]
    pub(crate) const fn exact_profile(&self) -> DecoderProfile {
        self.exact_profile
    }
}

/// One UI row with both address domains explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct R5900InstructionRow {
    rva: u64,
    preferred_address: u64,
    bytes: Vec<u8>,
    text: String,
    flow_control: LinearFlowControlCategory,
    direct_target_preferred_address: Option<u64>,
    direct_target_rva: Option<u64>,
    follow_direct_target_rva: Option<u64>,
    length: u8,
}

impl R5900InstructionRow {
    #[must_use]
    pub(crate) const fn rva(&self) -> u64 {
        self.rva
    }

    #[must_use]
    pub(crate) const fn preferred_address(&self) -> u64 {
        self.preferred_address
    }

    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub(crate) const fn flow_control(&self) -> LinearFlowControlCategory {
        self.flow_control
    }

    #[must_use]
    pub(crate) const fn direct_target_preferred_address(&self) -> Option<u64> {
        self.direct_target_preferred_address
    }

    #[must_use]
    pub(crate) const fn direct_target_rva(&self) -> Option<u64> {
        self.direct_target_rva
    }

    #[must_use]
    pub(crate) const fn follow_direct_target_rva(&self) -> Option<u64> {
        self.follow_direct_target_rva
    }

    #[must_use]
    pub(crate) const fn length(&self) -> u8 {
        self.length
    }
}

/// Fully projected explicit R5900 preview. All presentation addresses and its
/// stop reason are in RVA space; canonical instruction text remains decoder
/// output and therefore retains preferred VAs for J/JAL operands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct R5900OfflinePreview {
    binding: R5900PreviewBinding,
    start_preferred_address: u64,
    considered_bytes: usize,
    rows: Vec<R5900InstructionRow>,
    stop_reason: LinearDisassemblyStopReason,
}

impl R5900OfflinePreview {
    #[must_use]
    pub(crate) const fn binding(&self) -> &R5900PreviewBinding {
        &self.binding
    }

    #[must_use]
    pub(crate) const fn start_preferred_address(&self) -> u64 {
        self.start_preferred_address
    }

    #[must_use]
    pub(crate) const fn considered_bytes(&self) -> usize {
        self.considered_bytes
    }

    #[must_use]
    pub(crate) fn rows(&self) -> &[R5900InstructionRow] {
        &self.rows
    }

    #[must_use]
    pub(crate) const fn stop_reason(&self) -> &LinearDisassemblyStopReason {
        &self.stop_reason
    }
}

/// Fail-closed planner error for an explicit R5900 preview.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum R5900PreviewError {
    #[error(transparent)]
    Ineligible(#[from] R5900EligibilityError),
    #[error("the explicit R5900 selection is stale for the active identity or source")]
    StaleSelection,
    #[error("the preview binding does not match the active analysis identity")]
    IdentityMismatch,
    #[error("the preview requires the exact current bundled R5900 profile")]
    ProfileMismatch,
    #[error("the static address space is not the active ELF image")]
    AddressSpaceMismatch,
    #[error("R5900 preview size {0} is not one of 16, 32, 64, 128, or 256 bytes")]
    InvalidSize(u32),
    #[error("R5900 preview size {0} is not a multiple of four")]
    SizeMisaligned(u32),
    #[error("R5900 preview RVA 0x{0:016X} is not four-byte aligned")]
    StartRvaMisaligned(u64),
    #[error("R5900 preferred start address 0x{0:016X} is not four-byte aligned")]
    PreferredAddressMisaligned(u64),
    #[error("R5900 preview RVA span overflows")]
    RvaOverflow,
    #[error("R5900 preview span is outside the preferred static image")]
    SpanOutsideImage,
    #[error("R5900 preview preferred address span exceeds the 32-bit ISA domain")]
    PreferredSpanOutsideU32,
    #[error("the exact read returned {actual} bytes for a {expected}-byte binding")]
    ByteCountMismatch { expected: usize, actual: usize },
    #[error("the exact bundled decoder could not be constructed: {0}")]
    DecoderUnavailable(String),
    #[error("a decoded address 0x{0:016X} did not map back into the static image")]
    DecodedAddressOutsideImage(u64),
}

/// Build a bounded R5900 preview from bytes already returned by the unchanged
/// profile-agnostic offline reader.
pub(crate) fn plan_r5900_preview(
    analysis: &BinaryAnalysis,
    address_space: &StaticAddressSpace,
    binding: R5900PreviewBinding,
    exact_bytes: &[u8],
) -> Result<R5900OfflinePreview, R5900PreviewError> {
    require_explicit_r5900_eligibility(analysis)?;
    if analysis.identity() != &binding.identity {
        return Err(R5900PreviewError::IdentityMismatch);
    }
    if binding.canonical_source_path.as_os_str().is_empty() {
        return Err(R5900PreviewError::StaleSelection);
    }
    if binding.exact_profile != DecoderProfile::PS2_EE_R5900_LATEST {
        return Err(R5900PreviewError::ProfileMismatch);
    }
    if address_space.binary_id != binding.identity.id
        || !matches!(address_space.layout, StaticImageLayout::Elf)
        || address_space.preferred_image_base != binding.identity.image_base
        || address_space.image_size
            != match analysis {
                BinaryAnalysis::Elf(elf) => elf.image_size,
                _ => unreachable!("eligibility accepted only ELF"),
            }
    {
        return Err(R5900PreviewError::AddressSpaceMismatch);
    }
    if !R5900_PREVIEW_SIZES.contains(&binding.size) {
        return Err(R5900PreviewError::InvalidSize(binding.size));
    }
    if binding.size % 4 != 0 {
        return Err(R5900PreviewError::SizeMisaligned(binding.size));
    }
    if binding.start_rva % 4 != 0 {
        return Err(R5900PreviewError::StartRvaMisaligned(binding.start_rva));
    }
    let size = u64::from(binding.size);
    let end_rva = binding
        .start_rva
        .checked_add(size)
        .ok_or(R5900PreviewError::RvaOverflow)?;
    let last_rva = end_rva
        .checked_sub(1)
        .ok_or(R5900PreviewError::RvaOverflow)?;
    let start_preferred_address = address_space
        .preferred_virtual_address(RelativeAddress::new(binding.start_rva))
        .ok_or(R5900PreviewError::SpanOutsideImage)?;
    if start_preferred_address % 4 != 0 {
        return Err(R5900PreviewError::PreferredAddressMisaligned(
            start_preferred_address,
        ));
    }
    let last_preferred_address = address_space
        .preferred_virtual_address(RelativeAddress::new(last_rva))
        .ok_or(R5900PreviewError::SpanOutsideImage)?;
    if start_preferred_address > u64::from(u32::MAX) || last_preferred_address > u64::from(u32::MAX)
    {
        return Err(R5900PreviewError::PreferredSpanOutsideU32);
    }
    if exact_bytes.len() != binding.size as usize {
        return Err(R5900PreviewError::ByteCountMismatch {
            expected: binding.size as usize,
            actual: exact_bytes.len(),
        });
    }

    let limits = LinearDisassemblyLimits::new(exact_bytes.len(), R5900_MAX_ROWS)
        .expect("the fixed R5900 preview bounds fit analysis hard ceilings");
    let mut decoder = decoder_for_profile(binding.exact_profile)
        .map_err(|error| R5900PreviewError::DecoderUnavailable(error.to_string()))?;
    let decoded = disassemble_linear(
        decoder.as_mut(),
        exact_bytes,
        start_preferred_address,
        limits,
    );

    let mut rows = Vec::with_capacity(decoded.rows().len());
    for row in decoded.rows() {
        let rva = address_space
            .relative_address(row.address())
            .ok_or(R5900PreviewError::DecodedAddressOutsideImage(row.address()))?
            .get();
        let direct_target_preferred_address = row.direct_target_address();
        let direct_target_rva = direct_target_preferred_address
            .and_then(|target| address_space.relative_address(target))
            .map(RelativeAddress::get);
        let follow_direct_target_rva = direct_target_rva.and_then(|target| {
            let target = RelativeAddress::new(target);
            (address_space.region_at(target).is_some()
                && address_space.file_offset_at(target).is_some())
            .then_some(target.get())
        });
        rows.push(R5900InstructionRow {
            rva,
            preferred_address: row.address(),
            bytes: row.bytes().to_vec(),
            text: row.text().to_owned(),
            flow_control: row.flow_control(),
            direct_target_preferred_address,
            direct_target_rva,
            follow_direct_target_rva,
            length: row.length(),
        });
    }
    debug_assert!(rows.len() <= R5900_MAX_ROWS);
    let stop_reason = map_stop_reason_to_rva(decoded.stop_reason(), address_space)?;

    Ok(R5900OfflinePreview {
        binding,
        start_preferred_address,
        considered_bytes: decoded.considered_bytes(),
        rows,
        stop_reason,
    })
}

fn map_stop_reason_to_rva(
    stop_reason: &LinearDisassemblyStopReason,
    address_space: &StaticAddressSpace,
) -> Result<LinearDisassemblyStopReason, R5900PreviewError> {
    let mut failure = None;
    let mapped = stop_reason.map_address(|address| {
        if let Some(rva) = address_space.relative_address(address) {
            rva.get()
        } else {
            failure = Some(R5900PreviewError::DecodedAddressOutsideImage(address));
            0
        }
    });
    failure.map_or(Ok(mapped), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use resymbol_analysis::{DecodeOutcome, LinearTruncationBoundary, analyze_elf, analyze_pe};
    use resymbol_debugger::StaticAddressSpace;

    fn synthetic_elf(
        class: ElfClass,
        endian: ElfEndian,
        elf_type: u16,
        machine: u16,
        image_base: u32,
    ) -> Vec<u8> {
        const ELF32_HEADER_SIZE: usize = 52;
        const PROGRAM_HEADER_SIZE: usize = 32;
        let mut bytes = vec![0_u8; 0x80];
        bytes[..16].copy_from_slice(&[
            0x7f,
            b'E',
            b'L',
            b'F',
            match class {
                ElfClass::Elf32 => 1,
                ElfClass::Elf64 => 2,
            },
            match endian {
                ElfEndian::Little => 1,
                ElfEndian::Big => 2,
            },
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        let little = endian == ElfEndian::Little;
        let put_u16 = |bytes: &mut [u8], offset: usize, value: u16| {
            let encoded = if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            };
            bytes[offset..offset + 2].copy_from_slice(&encoded);
        };
        let put_u32 = |bytes: &mut [u8], offset: usize, value: u32| {
            let encoded = if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            };
            bytes[offset..offset + 4].copy_from_slice(&encoded);
        };
        // The rejection tests only need structured headers. Keep ELF64
        // deliberately header-only because eligibility rejects class first.
        if class == ElfClass::Elf64 {
            return bytes;
        }
        put_u16(&mut bytes, 16, elf_type);
        put_u16(&mut bytes, 18, machine);
        put_u32(&mut bytes, 20, 1);
        put_u32(&mut bytes, 24, image_base + 0x60);
        put_u32(&mut bytes, 28, ELF32_HEADER_SIZE as u32);
        put_u16(&mut bytes, 40, ELF32_HEADER_SIZE as u16);
        put_u16(&mut bytes, 42, PROGRAM_HEADER_SIZE as u16);
        put_u16(&mut bytes, 44, 1);
        put_u32(&mut bytes, ELF32_HEADER_SIZE, 1);
        put_u32(&mut bytes, ELF32_HEADER_SIZE + 4, 0);
        put_u32(&mut bytes, ELF32_HEADER_SIZE + 8, image_base);
        put_u32(&mut bytes, ELF32_HEADER_SIZE + 12, image_base);
        put_u32(&mut bytes, ELF32_HEADER_SIZE + 16, 0x80);
        put_u32(&mut bytes, ELF32_HEADER_SIZE + 20, 0x100);
        put_u32(&mut bytes, ELF32_HEADER_SIZE + 24, 5);
        put_u32(&mut bytes, ELF32_HEADER_SIZE + 28, 0x10);
        bytes
    }

    fn high_base_fixture() -> (Vec<u8>, BinaryAnalysis, StaticAddressSpace) {
        let mut bytes = synthetic_elf(ElfClass::Elf32, ElfEndian::Little, 2, 8, 0x1200_0000);
        bytes[0x60..0x70].copy_from_slice(&[
            0x1c, 0x00, 0x80, 0x08, // j 0x12000070
            0x20, 0x00, 0x80, 0x0c, // jal 0x12000080
            0x00, 0x00, 0x00, 0x00, // sll $zero, $zero, 0
            0x00, 0x00, 0x00, 0x00, // sll $zero, $zero, 0
        ]);
        let analysis = BinaryAnalysis::Elf(analyze_elf(&bytes).expect("synthetic ELF"));
        let address_space =
            StaticAddressSpace::from_analysis(&analysis).expect("ELF address space");
        (bytes, analysis, address_space)
    }

    fn selection_and_binding(
        analysis: &BinaryAnalysis,
        start_rva: u64,
        size: u32,
    ) -> (R5900DecoderSelection, R5900PreviewBinding) {
        let source = Path::new(r"C:\canonical\synthetic.elf");
        let selection =
            R5900DecoderSelection::explicit_latest(analysis, source).expect("explicit selection");
        let binding = selection
            .bind_span(analysis.identity(), source, start_rva, size)
            .expect("current binding");
        (selection, binding)
    }

    #[test]
    fn selection_is_never_automatic_and_stores_the_resolved_exact_profile() {
        let (_, analysis, _) = high_base_fixture();
        let state: Option<R5900DecoderSelection> = None;
        assert!(state.is_none());

        let (selection, binding) = selection_and_binding(&analysis, 0x60, 16);
        let exact = DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1;
        assert_eq!(selection.exact_profile(), exact);
        assert_eq!(binding.exact_profile(), exact);
        assert_eq!(binding.start_rva(), 0x60);
        assert_eq!(binding.size(), 16);
        assert_eq!(binding.identity(), analysis.identity());
        assert_eq!(
            binding.canonical_source_path(),
            Path::new(r"C:\canonical\synthetic.elf")
        );
        assert_eq!(
            decoder_for_profile(binding.exact_profile())
                .expect("exact factory")
                .profile(),
            exact
        );
    }

    #[test]
    fn r5900_action_policy_is_exactly_the_five_read_only_actions() {
        assert_eq!(
            R5900InstructionAction::ALL.map(R5900InstructionAction::label),
            [
                "Copy RVA",
                "Copy Preferred Address",
                "Copy Bytes",
                "Copy Instruction",
                "Follow Direct Target",
            ]
        );
        assert!(
            R5900InstructionAction::ALL
                .iter()
                .all(|action| !action.label().contains("NOP")
                    && !action.label().contains("Edit")
                    && !action.label().contains("Live"))
        );
    }

    #[test]
    fn eligibility_uses_only_structured_fields_and_rejects_each_wrong_shape() {
        let (_, mut eligible, _) = high_base_fixture();
        require_explicit_r5900_eligibility(&eligible).expect("eligible");
        match &mut eligible {
            BinaryAnalysis::Elf(elf) => elf.identity.architecture = "spoofed-x86_64".to_owned(),
            _ => unreachable!(),
        }
        require_explicit_r5900_eligibility(&eligible)
            .expect("structured fields, not identity text, control eligibility");

        let mut elf = match eligible.clone() {
            BinaryAnalysis::Elf(elf) => elf,
            _ => unreachable!(),
        };
        elf.endian = ElfEndian::Big;
        assert_eq!(
            require_explicit_r5900_eligibility(&BinaryAnalysis::Elf(elf.clone())),
            Err(R5900EligibilityError::NotLittleEndian)
        );
        elf.endian = ElfEndian::Little;
        elf.class = ElfClass::Elf64;
        assert_eq!(
            require_explicit_r5900_eligibility(&BinaryAnalysis::Elf(elf.clone())),
            Err(R5900EligibilityError::NotElf32)
        );
        elf.class = ElfClass::Elf32;
        elf.machine = 62;
        assert_eq!(
            require_explicit_r5900_eligibility(&BinaryAnalysis::Elf(elf.clone())),
            Err(R5900EligibilityError::NotMips)
        );
        elf.machine = 8;
        elf.elf_type = 3;
        assert_eq!(
            require_explicit_r5900_eligibility(&BinaryAnalysis::Elf(elf)),
            Err(R5900EligibilityError::NotExecutable)
        );
        let pe = BinaryAnalysis::Pe(
            analyze_pe(include_bytes!(
                "../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe"
            ))
            .expect("checked-in PE fixture"),
        );
        assert_eq!(
            require_explicit_r5900_eligibility(&pe),
            Err(R5900EligibilityError::NotElf)
        );
    }

    #[test]
    fn high_base_decode_retains_va_text_maps_rows_and_gates_follow_by_file_backing() {
        let (bytes, analysis, address_space) = high_base_fixture();
        let (_, binding) = selection_and_binding(&analysis, 0x60, 16);
        let preview = plan_r5900_preview(&analysis, &address_space, binding, &bytes[0x60..0x70])
            .expect("high-base preview");

        assert_eq!(preview.binding().start_rva(), 0x60);
        assert_eq!(preview.start_preferred_address(), 0x1200_0060);
        assert_eq!(preview.considered_bytes(), 16);
        assert_eq!(preview.rows().len(), 4);
        assert_eq!(preview.rows()[0].rva(), 0x60);
        assert_eq!(preview.rows()[0].preferred_address(), 0x1200_0060);
        assert_eq!(preview.rows()[0].text(), "j 0x12000070");
        assert_eq!(
            preview.rows()[0].direct_target_preferred_address(),
            Some(0x1200_0070)
        );
        assert_eq!(preview.rows()[0].direct_target_rva(), Some(0x70));
        assert_eq!(preview.rows()[0].follow_direct_target_rva(), Some(0x70));
        assert_eq!(preview.rows()[1].text(), "jal 0x12000080");
        assert_eq!(preview.rows()[1].direct_target_rva(), Some(0x80));
        assert_eq!(preview.rows()[1].follow_direct_target_rva(), None);
        assert!(matches!(
            preview.stop_reason(),
            LinearDisassemblyStopReason::EndOfInput
        ));
        assert!(preview.rows().len() <= R5900_MAX_ROWS);
        assert_ne!(preview.rows()[0].text(), "j 0x02000070");
        assert_ne!(preview.rows()[1].text(), "jal 0x02000080");
    }

    #[test]
    fn stale_identity_and_source_are_rejected_before_preview_authority_exists() {
        let (_, analysis, _) = high_base_fixture();
        let source = Path::new(r"C:\canonical\synthetic.elf");
        let selection =
            R5900DecoderSelection::explicit_latest(&analysis, source).expect("explicit selection");
        let mut foreign = analysis.identity().clone();
        foreign.size += 1;

        assert!(matches!(
            selection.bind_span(&foreign, source, 0x60, 16),
            Err(R5900PreviewError::StaleSelection)
        ));
        assert!(matches!(
            selection.bind_span(
                analysis.identity(),
                Path::new(r"C:\canonical\other.elf"),
                0x60,
                16
            ),
            Err(R5900PreviewError::StaleSelection)
        ));

        let mut retained = Some(selection.clone());
        assert!(!retain_current_r5900_selection(
            &mut retained,
            Some((analysis.identity(), source))
        ));
        assert!(retained.is_some());
        assert!(retain_current_r5900_selection(
            &mut retained,
            Some((&foreign, source))
        ));
        assert!(retained.is_none());

        let mut retained = Some(selection);
        assert!(retain_current_r5900_selection(&mut retained, None));
        assert!(retained.is_none());
    }

    #[test]
    fn planner_rejects_alignment_size_span_byte_count_and_u32_failures() {
        let (bytes, analysis, address_space) = high_base_fixture();
        for size in [0, 4, 12, 20, 512] {
            let (_, binding) = selection_and_binding(&analysis, 0x60, size);
            assert!(matches!(
                plan_r5900_preview(&analysis, &address_space, binding, &[]),
                Err(R5900PreviewError::InvalidSize(actual)) if actual == size
            ));
        }
        let (_, binding) = selection_and_binding(&analysis, 0x62, 16);
        assert!(matches!(
            plan_r5900_preview(&analysis, &address_space, binding, &bytes[0x60..0x70]),
            Err(R5900PreviewError::StartRvaMisaligned(0x62))
        ));
        let (_, binding) = selection_and_binding(&analysis, u64::MAX - 15, 16);
        assert!(matches!(
            plan_r5900_preview(&analysis, &address_space, binding, &[0; 16]),
            Err(R5900PreviewError::RvaOverflow)
        ));
        let (_, binding) = selection_and_binding(&analysis, 0xf8, 16);
        assert!(matches!(
            plan_r5900_preview(&analysis, &address_space, binding, &[0; 16]),
            Err(R5900PreviewError::SpanOutsideImage)
        ));
        let (_, binding) = selection_and_binding(&analysis, 0x60, 16);
        assert!(matches!(
            plan_r5900_preview(&analysis, &address_space, binding, &[0; 12]),
            Err(R5900PreviewError::ByteCountMismatch {
                expected: 16,
                actual: 12
            })
        ));

        let mut high_analysis = analysis.clone();
        match &mut high_analysis {
            BinaryAnalysis::Elf(elf) => elf.identity.image_base = 0x1_0000_0000,
            _ => unreachable!(),
        }
        let mut high_space = address_space.clone();
        high_space.preferred_image_base = 0x1_0000_0000;
        let (_, binding) = selection_and_binding(&high_analysis, 0x60, 32);
        assert!(matches!(
            plan_r5900_preview(&high_analysis, &high_space, binding, &[0; 32]),
            Err(R5900PreviewError::PreferredSpanOutsideU32)
        ));

        let mut misaligned_analysis = analysis.clone();
        match &mut misaligned_analysis {
            BinaryAnalysis::Elf(elf) => elf.identity.image_base += 2,
            _ => unreachable!(),
        }
        let mut misaligned_space = address_space.clone();
        misaligned_space.preferred_image_base += 2;
        let (_, binding) = selection_and_binding(&misaligned_analysis, 0x60, 16);
        assert!(matches!(
            plan_r5900_preview(&misaligned_analysis, &misaligned_space, binding, &[0; 16]),
            Err(R5900PreviewError::PreferredAddressMisaligned(0x1200_0062))
        ));
    }

    #[test]
    fn inclusive_u32_top_domain_span_is_valid() {
        let mut bytes = synthetic_elf(ElfClass::Elf32, ElfEndian::Little, 2, 8, 0xffff_ff00);
        bytes.resize(0x100, 0);
        bytes[52 + 16..52 + 20].copy_from_slice(&0x100_u32.to_le_bytes());
        let analysis = BinaryAnalysis::Elf(analyze_elf(&bytes).expect("top-domain ELF"));
        let address_space = StaticAddressSpace::from_analysis(&analysis).expect("top-domain space");
        let (_, binding) = selection_and_binding(&analysis, 0xf0, 16);

        let preview = plan_r5900_preview(&analysis, &address_space, binding, &bytes[0xf0..0x100])
            .expect("inclusive last byte at u32::MAX is valid");

        assert_eq!(preview.start_preferred_address(), 0xffff_fff0);
        assert_eq!(preview.rows().len(), 4);
        assert_eq!(preview.rows()[0].preferred_address(), 0xffff_fff0);
        assert_eq!(preview.rows()[3].preferred_address(), 0xffff_fffc);
        assert_eq!(
            address_space.file_offset_at(RelativeAddress::new(0xff)),
            Some(0xff)
        );
        assert!(matches!(
            preview.stop_reason(),
            LinearDisassemblyStopReason::EndOfInput
        ));
    }

    #[test]
    fn mapped_stop_reasons_keep_unsupported_invalid_truncated_and_exact_end_distinct() {
        let (_, _, address_space) = high_base_fixture();
        let cases = [
            LinearDisassemblyStopReason::UnsupportedInstruction {
                rva: 0x1200_0060,
                offset: 0,
                class: resymbol_analysis::UnsupportedInstructionClass::Ps2EeCop2Encoding,
            },
            LinearDisassemblyStopReason::InvalidInstruction {
                rva: 0x1200_0064,
                offset: 4,
            },
            LinearDisassemblyStopReason::TruncatedInstruction {
                rva: 0x1200_0068,
                available_bytes: 2,
                boundary: LinearTruncationBoundary::InputEnd,
            },
            LinearDisassemblyStopReason::EndOfInput,
        ];
        let mapped = cases
            .iter()
            .map(|reason| map_stop_reason_to_rva(reason, &address_space).expect("mapped"))
            .collect::<Vec<_>>();

        assert!(matches!(
            mapped[0],
            LinearDisassemblyStopReason::UnsupportedInstruction { rva: 0x60, .. }
        ));
        assert!(matches!(
            mapped[1],
            LinearDisassemblyStopReason::InvalidInstruction { rva: 0x64, .. }
        ));
        assert!(matches!(
            mapped[2],
            LinearDisassemblyStopReason::TruncatedInstruction { rva: 0x68, .. }
        ));
        assert!(matches!(mapped[3], LinearDisassemblyStopReason::EndOfInput));
    }

    #[test]
    fn latest_decoder_reports_unsupported_and_invalid_without_conflation() {
        let mut decoder =
            decoder_for_profile(DecoderProfile::PS2_EE_R5900_LATEST).expect("latest decoder");
        assert!(matches!(
            decoder.decode_one(&0x4800_0000_u32.to_le_bytes(), 0x1200_0000),
            DecodeOutcome::Unsupported { .. }
        ));
        assert!(matches!(
            decoder.decode_one(&0x4c00_0000_u32.to_le_bytes(), 0x1200_0000),
            DecodeOutcome::Invalid
        ));
        assert!(matches!(
            decoder.decode_one(&[0, 0], 0x1200_0000),
            DecodeOutcome::Truncated { available: 2 }
        ));
    }
}
