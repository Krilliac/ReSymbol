//! UI-thread models for instruction actions and unpublished static patch drafts.
//!
//! This module owns no debugger client, target process, file writer, or patch
//! publication service. The workbench converts [`StaticPatchDraft`] values
//! through fallible application-service request constructors, then sends those
//! owned requests to the worker for checked plan construction and create-new
//! publication.

use resymbol_app::{
    MAX_STATIC_PATCH_BYTES, MAX_STATIC_PATCH_BYTES_PER_EDIT, MAX_STATIC_PATCH_EDITS,
    MAX_STATIC_PATCH_LABEL_BYTES, MAX_STATIC_PATCH_NOP_INSTRUCTION_BYTES, StaticPatchEditRequest,
    StaticPatchKind,
};
use resymbol_debugger::{
    BreakpointKind, BreakpointPersistence, CapabilityAvailability, CapabilityReport,
    DebugCapability, DebugCommand, MemoryAddress, SessionState, SessionStateKind, StepKind,
    StopToken, ThreadId,
};
use thiserror::Error;

pub(crate) const MAX_PENDING_STATIC_PATCH_DRAFTS: usize = MAX_STATIC_PATCH_EDITS;

/// The application-service constructor used when a draft is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StaticPatchDraftKind {
    NopInstruction,
    ReplaceBytes,
}

/// One bounded, unpublished same-length instruction edit owned by the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticPatchDraft {
    kind: StaticPatchDraftKind,
    rva: u64,
    expected: Vec<u8>,
    replacement: Vec<u8>,
    label: String,
}

impl StaticPatchDraft {
    pub(crate) fn nop_instruction(
        rva: u64,
        expected: &[u8],
        label: impl Into<String>,
    ) -> Result<Self, StaticPatchDraftError> {
        if expected.iter().all(|byte| *byte == 0x90) && !expected.is_empty() {
            return Err(StaticPatchDraftError::AlreadyNopFilled);
        }
        let replacement = vec![0x90; expected.len()];
        Self::new(
            StaticPatchDraftKind::NopInstruction,
            rva,
            expected,
            &replacement,
            label,
        )
    }

    pub(crate) fn replace_bytes(
        rva: u64,
        expected: &[u8],
        replacement: &[u8],
        label: impl Into<String>,
    ) -> Result<Self, StaticPatchDraftError> {
        Self::new(
            StaticPatchDraftKind::ReplaceBytes,
            rva,
            expected,
            replacement,
            label,
        )
    }

    fn new(
        kind: StaticPatchDraftKind,
        rva: u64,
        expected: &[u8],
        replacement: &[u8],
        label: impl Into<String>,
    ) -> Result<Self, StaticPatchDraftError> {
        if expected.is_empty() {
            return Err(StaticPatchDraftError::EmptyInstruction);
        }
        let maximum = match kind {
            StaticPatchDraftKind::NopInstruction => MAX_STATIC_PATCH_NOP_INSTRUCTION_BYTES,
            StaticPatchDraftKind::ReplaceBytes => MAX_STATIC_PATCH_BYTES_PER_EDIT,
        };
        if expected.len() > maximum {
            return Err(StaticPatchDraftError::InstructionTooLarge {
                actual: expected.len(),
                maximum,
            });
        }
        if expected.len() != replacement.len() {
            return Err(StaticPatchDraftError::ReplacementLengthMismatch {
                expected: expected.len(),
                replacement: replacement.len(),
            });
        }
        if expected == replacement {
            return Err(StaticPatchDraftError::UnchangedReplacement);
        }
        if rva.checked_add(expected.len() as u64).is_none() {
            return Err(StaticPatchDraftError::AddressOverflow);
        }
        let label = label.into();
        if label.trim() != label
            || label.is_empty()
            || label.len() > MAX_STATIC_PATCH_LABEL_BYTES
            || label.chars().any(char::is_control)
        {
            return Err(StaticPatchDraftError::InvalidLabel);
        }
        Ok(Self {
            kind,
            rva,
            expected: expected.to_vec(),
            replacement: replacement.to_vec(),
            label,
        })
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> StaticPatchDraftKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn rva(&self) -> u64 {
        self.rva
    }

    #[must_use]
    pub(crate) fn expected(&self) -> &[u8] {
        &self.expected
    }

    #[must_use]
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub(crate) fn replacement(&self) -> &[u8] {
        &self.replacement
    }

    /// Exact source-check bytes and same-length replacement for a future
    /// fallible static-patch adapter. No file or process is modified here.
    #[must_use]
    pub(crate) fn source_check_and_replacement(&self) -> (&[u8], &[u8]) {
        (&self.expected, &self.replacement)
    }

    fn end_rva(&self) -> u64 {
        self.rva + self.expected.len() as u64
    }
}

/// Bounded collection of unpublished static edits.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PendingStaticPatchDrafts {
    drafts: Vec<StaticPatchDraft>,
}

impl PendingStaticPatchDrafts {
    /// Build a complete replacement draft collection before any UI state changes.
    pub(crate) fn from_requests(
        requests: &[StaticPatchEditRequest],
    ) -> Result<Self, StaticPatchDraftError> {
        let mut pending = Self::default();
        for request in requests {
            let outcome = match request.kind() {
                StaticPatchKind::NopInstruction => pending.queue_nop(
                    u64::from(request.rva()),
                    request.expected(),
                    request.label(),
                ),
                StaticPatchKind::ReplaceBytes => pending.queue_replace(
                    u64::from(request.rva()),
                    request.expected(),
                    request.replacement(),
                    request.label(),
                ),
                _ => return Err(StaticPatchDraftError::UnsupportedPatchKind),
            }?;
            debug_assert!(matches!(outcome, PatchDraftQueueOutcome::Added));
        }
        Ok(pending)
    }

    #[must_use]
    pub(crate) fn drafts(&self) -> &[StaticPatchDraft] {
        &self.drafts
    }

    /// Returns a queued draft only when its complete immutable source span is
    /// the exact selected instruction. Matching an RVA alone is deliberately
    /// insufficient: imported general replacements may span more than one
    /// decoded row.
    #[must_use]
    pub(crate) fn draft_for_exact_selection(
        &self,
        rva: u64,
        expected: &[u8],
    ) -> Option<&StaticPatchDraft> {
        self.drafts
            .iter()
            .find(|draft| draft.rva == rva && draft.expected == expected)
    }

    pub(crate) fn queue_nop(
        &mut self,
        rva: u64,
        expected: &[u8],
        label: impl Into<String>,
    ) -> Result<PatchDraftQueueOutcome, StaticPatchDraftError> {
        self.queue(StaticPatchDraft::nop_instruction(rva, expected, label)?)
    }

    pub(crate) fn queue_replace(
        &mut self,
        rva: u64,
        expected: &[u8],
        replacement: &[u8],
        label: impl Into<String>,
    ) -> Result<PatchDraftQueueOutcome, StaticPatchDraftError> {
        self.queue(StaticPatchDraft::replace_bytes(
            rva,
            expected,
            replacement,
            label,
        )?)
    }

    /// Replaces one queued draft at the exact selected source span.
    ///
    /// The candidate is fully validated and queued into a cloned collection
    /// before the current collection is swapped. A malformed replacement,
    /// stale selection, overlap, or aggregate-limit failure therefore leaves
    /// every existing draft untouched and in canonical RVA order.
    pub(crate) fn replace_exact_with_bytes(
        &mut self,
        rva: u64,
        expected: &[u8],
        replacement: &[u8],
        label: impl Into<String>,
    ) -> Result<PatchDraftQueueOutcome, StaticPatchDraftError> {
        let candidate = StaticPatchDraft::replace_bytes(rva, expected, replacement, label)?;
        let Some(index) = self.drafts.iter().position(|draft| draft.rva == rva) else {
            return Err(StaticPatchDraftError::MissingDraftAtSelection { rva });
        };
        if self.drafts[index].expected != expected {
            return Err(StaticPatchDraftError::DraftSourceMismatch { rva });
        }
        if self.drafts[index].replacement == replacement {
            return Ok(PatchDraftQueueOutcome::AlreadyQueued);
        }

        let mut staged = self.clone();
        staged.drafts.remove(index);
        let outcome = staged.queue(candidate)?;
        debug_assert_eq!(outcome, PatchDraftQueueOutcome::Added);
        *self = staged;
        Ok(outcome)
    }

    fn queue(
        &mut self,
        draft: StaticPatchDraft,
    ) -> Result<PatchDraftQueueOutcome, StaticPatchDraftError> {
        if self.drafts.iter().any(|existing| existing == &draft) {
            return Ok(PatchDraftQueueOutcome::AlreadyQueued);
        }
        if let Some(existing) = self
            .drafts
            .iter()
            .find(|existing| draft.rva < existing.end_rva() && existing.rva < draft.end_rva())
        {
            return Err(StaticPatchDraftError::OverlappingDraft {
                existing_rva: existing.rva,
            });
        }
        if self.drafts.len() == MAX_PENDING_STATIC_PATCH_DRAFTS {
            return Err(StaticPatchDraftError::DraftLimitReached {
                maximum: MAX_PENDING_STATIC_PATCH_DRAFTS,
            });
        }
        let current_bytes = self
            .drafts
            .iter()
            .try_fold(0usize, |total, existing| {
                total.checked_add(existing.expected.len())
            })
            .ok_or(StaticPatchDraftError::AggregateBytesExceeded {
                actual: usize::MAX,
                maximum: MAX_STATIC_PATCH_BYTES,
            })?;
        let aggregate = current_bytes.checked_add(draft.expected.len()).ok_or(
            StaticPatchDraftError::AggregateBytesExceeded {
                actual: usize::MAX,
                maximum: MAX_STATIC_PATCH_BYTES,
            },
        )?;
        if aggregate > MAX_STATIC_PATCH_BYTES {
            return Err(StaticPatchDraftError::AggregateBytesExceeded {
                actual: aggregate,
                maximum: MAX_STATIC_PATCH_BYTES,
            });
        }
        self.drafts.push(draft);
        self.drafts.sort_by_key(StaticPatchDraft::rva);
        Ok(PatchDraftQueueOutcome::Added)
    }

    pub(crate) fn remove(&mut self, rva: u64) -> bool {
        let before = self.drafts.len();
        self.drafts.retain(|draft| draft.rva != rva);
        self.drafts.len() != before
    }

    /// Removes only the draft whose complete immutable expected span matches
    /// the selected instruction. This is the static editor's Restore Original
    /// operation: the verified source bytes themselves are never mutated.
    pub(crate) fn remove_exact_selection(&mut self, rva: u64, expected: &[u8]) -> bool {
        let before = self.drafts.len();
        self.drafts
            .retain(|draft| draft.rva != rva || draft.expected != expected);
        self.drafts.len() != before
    }

    pub(crate) fn clear(&mut self) {
        self.drafts.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PatchDraftQueueOutcome {
    Added,
    AlreadyQueued,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum StaticPatchDraftError {
    #[error("cannot queue a NOP edit for an empty instruction")]
    EmptyInstruction,
    #[error("static edit is {actual} bytes; this edit kind is limited to {maximum}")]
    InstructionTooLarge { actual: usize, maximum: usize },
    #[error("instruction is already NOP-filled")]
    AlreadyNopFilled,
    #[error(
        "replacement length {replacement} does not match expected instruction length {expected}"
    )]
    ReplacementLengthMismatch { expected: usize, replacement: usize },
    #[error("replacement bytes are identical to the expected instruction bytes")]
    UnchangedReplacement,
    #[error("instruction range overflows the RVA address space")]
    AddressOverflow,
    #[error("patch draft label must be printable, nonempty, and at most 256 UTF-8 bytes")]
    InvalidLabel,
    #[error("patch draft overlaps the existing edit at RVA 0x{existing_rva:016X}")]
    OverlappingDraft { existing_rva: u64 },
    #[error("pending static patch draft limit {maximum} reached")]
    DraftLimitReached { maximum: usize },
    #[error("pending static patch drafts change {actual} bytes; the limit is {maximum}")]
    AggregateBytesExceeded { actual: usize, maximum: usize },
    #[error("the loaded patch set uses an unsupported future static edit kind")]
    UnsupportedPatchKind,
    #[error("no pending static patch draft exists at RVA 0x{rva:016X}")]
    MissingDraftAtSelection { rva: u64 },
    #[error("the pending draft at RVA 0x{rva:016X} is bound to different source bytes")]
    DraftSourceMismatch { rva: u64 },
}

/// Whether the exact-byte modal will add a draft or transactionally replace
/// the queued draft bound to the same complete source instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StaticExactByteEditMode {
    QueueNew,
    EditQueued,
}

/// UI-thread state for one static-only exact-byte edit.
///
/// Original bytes and decoded text are immutable evidence. Only the bounded
/// canonical replacement text is editable; validation produces a fresh owned
/// byte vector and never changes a draft collection by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticExactByteEdit {
    mode: StaticExactByteEditMode,
    rva: u64,
    original: Vec<u8>,
    original_instruction: String,
    initial_replacement: Vec<u8>,
    replacement_hex: String,
}

impl StaticExactByteEdit {
    pub(crate) fn for_instruction(
        rva: u64,
        original: &[u8],
        original_instruction: impl Into<String>,
    ) -> Result<Self, StaticExactByteEditError> {
        validate_exact_edit_source(rva, original)?;
        Ok(Self {
            mode: StaticExactByteEditMode::QueueNew,
            rva,
            original: original.to_vec(),
            original_instruction: original_instruction.into(),
            initial_replacement: original.to_vec(),
            replacement_hex: canonical_hex_bytes(original),
        })
    }

    pub(crate) fn for_queued_draft(
        draft: &StaticPatchDraft,
        original_instruction: impl Into<String>,
    ) -> Self {
        Self {
            mode: StaticExactByteEditMode::EditQueued,
            rva: draft.rva,
            original: draft.expected.clone(),
            original_instruction: original_instruction.into(),
            initial_replacement: draft.replacement.clone(),
            replacement_hex: canonical_hex_bytes(&draft.replacement),
        }
    }

    #[must_use]
    pub(crate) const fn mode(&self) -> StaticExactByteEditMode {
        self.mode
    }

    #[must_use]
    pub(crate) const fn rva(&self) -> u64 {
        self.rva
    }

    #[must_use]
    pub(crate) fn original(&self) -> &[u8] {
        &self.original
    }

    #[must_use]
    pub(crate) fn original_instruction(&self) -> &str {
        &self.original_instruction
    }

    #[must_use]
    pub(crate) fn replacement_hex(&self) -> &str {
        &self.replacement_hex
    }

    pub(crate) fn replacement_hex_mut(&mut self) -> &mut String {
        &mut self.replacement_hex
    }

    #[must_use]
    pub(crate) fn maximum_replacement_hex_characters(&self) -> usize {
        canonical_hex_character_count(self.original.len())
    }

    /// Parses canonical `AA BB` text with the exact immutable source length.
    /// This intentionally does not apply the change checks so the UI can show
    /// a decoder preview while separately explaining why submission is gated.
    pub(crate) fn parsed_replacement(&self) -> Result<Vec<u8>, StaticExactByteEditError> {
        parse_canonical_exact_hex(&self.replacement_hex, self.original.len())
    }

    /// Returns a submission-ready replacement. New edits must differ from the
    /// immutable source; queued edits must also differ from their current
    /// replacement so clicking Save cannot silently rewrite metadata only.
    pub(crate) fn validated_replacement(&self) -> Result<Vec<u8>, StaticExactByteEditError> {
        let replacement = self.parsed_replacement()?;
        if replacement == self.original {
            return Err(StaticExactByteEditError::UnchangedOriginal);
        }
        if self.mode == StaticExactByteEditMode::EditQueued
            && replacement == self.initial_replacement
        {
            return Err(StaticExactByteEditError::UnchangedQueuedReplacement);
        }
        Ok(replacement)
    }
}

fn validate_exact_edit_source(rva: u64, original: &[u8]) -> Result<(), StaticExactByteEditError> {
    if original.is_empty() {
        return Err(StaticExactByteEditError::EmptySource);
    }
    if original.len() > MAX_STATIC_PATCH_BYTES_PER_EDIT {
        return Err(StaticExactByteEditError::SourceTooLarge {
            actual: original.len(),
            maximum: MAX_STATIC_PATCH_BYTES_PER_EDIT,
        });
    }
    if rva.checked_add(original.len() as u64).is_none() {
        return Err(StaticExactByteEditError::AddressOverflow);
    }
    Ok(())
}

#[must_use]
pub(crate) fn canonical_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn canonical_hex_character_count(byte_count: usize) -> usize {
    byte_count.saturating_mul(3).saturating_sub(1)
}

/// Strict parser for the modal's canonical byte grammar. Every byte is exactly
/// two ASCII hexadecimal digits and adjacent bytes have exactly one ASCII
/// space; prefixes, commas, underscores, and surrounding whitespace fail.
pub(crate) fn parse_canonical_exact_hex(
    input: &str,
    expected_len: usize,
) -> Result<Vec<u8>, StaticExactByteEditError> {
    if input.is_empty() {
        return Err(StaticExactByteEditError::EmptyReplacement);
    }
    let maximum_characters = canonical_hex_character_count(expected_len);
    if input.len() > maximum_characters {
        return Err(StaticExactByteEditError::ReplacementTextTooLong {
            actual: input.len(),
            maximum: maximum_characters,
        });
    }
    let tokens = input.split(' ').collect::<Vec<_>>();
    if tokens
        .iter()
        .any(|token| token.len() != 2 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(StaticExactByteEditError::NonCanonicalHex);
    }
    if tokens.len() != expected_len {
        return Err(StaticExactByteEditError::ReplacementLengthMismatch {
            expected: expected_len,
            actual: tokens.len(),
        });
    }
    tokens
        .into_iter()
        .map(|token| {
            u8::from_str_radix(token, 16).map_err(|_| StaticExactByteEditError::NonCanonicalHex)
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum StaticExactByteEditError {
    #[error("the selected instruction has no immutable source bytes")]
    EmptySource,
    #[error("the selected source span is {actual} bytes; the limit is {maximum}")]
    SourceTooLarge { actual: usize, maximum: usize },
    #[error("the selected instruction range overflows the RVA address space")]
    AddressOverflow,
    #[error("enter replacement bytes as canonical hexadecimal pairs, for example: 75 05")]
    EmptyReplacement,
    #[error(
        "replacement bytes must use exactly two hexadecimal digits per byte and one ASCII space between bytes"
    )]
    NonCanonicalHex,
    #[error(
        "replacement text is {actual} UTF-8 bytes; at most {maximum} are allowed for this instruction"
    )]
    ReplacementTextTooLong { actual: usize, maximum: usize },
    #[error("replacement contains {actual} byte(s); exactly {expected} are required")]
    ReplacementLengthMismatch { expected: usize, actual: usize },
    #[error(
        "replacement bytes are identical to the immutable original; use Restore Original for a queued patch"
    )]
    UnchangedOriginal,
    #[error("replacement bytes are unchanged from the queued patch")]
    UnchangedQueuedReplacement,
}

/// Same-size edits available for canonical x86-64 conditional branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConditionalBranchPatch {
    InvertCondition,
    AlwaysTaken,
}

impl ConditionalBranchPatch {
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::InvertCondition => "Invert Conditional Branch for Patched Binary",
            Self::AlwaysTaken => "Make Conditional Branch Always Taken",
        }
    }

    /// Produces a same-size replacement only for canonical, unprefixed Jcc
    /// encodings. Prefix-bearing or otherwise ambiguous encodings fail closed.
    #[must_use]
    pub(crate) fn replacement(self, bytes: &[u8]) -> Option<Vec<u8>> {
        match (bytes, self) {
            ([opcode @ 0x70..=0x7f, displacement], Self::InvertCondition) => {
                Some(vec![opcode ^ 1, *displacement])
            }
            ([opcode @ 0x70..=0x7f, displacement], Self::AlwaysTaken) => {
                let _ = opcode;
                Some(vec![0xeb, *displacement])
            }
            ([0x0f, opcode @ 0x80..=0x8f, displacement @ ..], Self::InvertCondition)
                if displacement.len() == 4 =>
            {
                let mut replacement = bytes.to_vec();
                replacement[1] = opcode ^ 1;
                Some(replacement)
            }
            ([0x0f, _opcode @ 0x80..=0x8f, displacement @ ..], Self::AlwaysTaken)
                if displacement.len() == 4 =>
            {
                let original = i32::from_le_bytes(displacement.try_into().ok()?);
                let adjusted = original.checked_add(1)?;
                let mut replacement = Vec::with_capacity(6);
                replacement.push(0xe9);
                replacement.extend_from_slice(&adjusted.to_le_bytes());
                replacement.push(0x90);
                Some(replacement)
            }
            _ => None,
        }
    }
}

/// Live debugger actions surfaced beside a static instruction preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveInstructionAction {
    NopLiveMemory,
    SetSoftwareBreakpoint,
    RunToCursor,
    Step(StepKind),
    Continue,
}

impl LiveInstructionAction {
    pub(crate) const ALL: [Self; 7] = [
        Self::NopLiveMemory,
        Self::SetSoftwareBreakpoint,
        Self::RunToCursor,
        Self::Step(StepKind::Into),
        Self::Step(StepKind::Over),
        Self::Step(StepKind::Out),
        Self::Continue,
    ];

    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::NopLiveMemory => "NOP Instruction in Live Memory",
            Self::SetSoftwareBreakpoint => "Set Software Breakpoint",
            Self::RunToCursor => "Run to Cursor",
            Self::Step(StepKind::Into) => "Step Into",
            Self::Step(StepKind::Over) => "Step Over",
            Self::Step(StepKind::Out) => "Step Out",
            Self::Continue => "Continue",
        }
    }

    const fn requires_exact_live_address(self) -> bool {
        matches!(
            self,
            Self::NopLiveMemory | Self::SetSoftwareBreakpoint | Self::RunToCursor
        )
    }

    const fn requires_selected_thread(self) -> bool {
        matches!(self, Self::Step(_))
    }

    const fn required_capabilities(self) -> &'static [DebugCapability] {
        const EXECUTION: &[DebugCapability] = &[DebugCapability::ExecutionControl];
        const STEP_INTO: &[DebugCapability] =
            &[DebugCapability::ExecutionControl, DebugCapability::StepInto];
        const STEP_OVER: &[DebugCapability] =
            &[DebugCapability::ExecutionControl, DebugCapability::StepOver];
        const STEP_OUT: &[DebugCapability] =
            &[DebugCapability::ExecutionControl, DebugCapability::StepOut];
        const LIVE_WRITE: &[DebugCapability] = &[DebugCapability::LiveMemoryWrite];
        const BREAKPOINT: &[DebugCapability] = &[DebugCapability::SoftwareBreakpoints];
        const RUN_TO_CURSOR: &[DebugCapability] = &[
            DebugCapability::SoftwareBreakpoints,
            DebugCapability::ExecutionControl,
        ];
        match self {
            Self::NopLiveMemory => LIVE_WRITE,
            Self::SetSoftwareBreakpoint => BREAKPOINT,
            Self::RunToCursor => RUN_TO_CURSOR,
            Self::Step(StepKind::Into) => STEP_INTO,
            Self::Step(StepKind::Over) => STEP_OVER,
            Self::Step(StepKind::Out) => STEP_OUT,
            Self::Continue => EXECUTION,
        }
    }

    /// Non-authorizing preview of the existing typed debugger primitives that
    /// an authenticated adapter would have to compose for this UI action.
    ///
    /// This value deliberately omits authority-bearing stop/address/thread
    /// fields. It is suitable only for explaining a disabled route; an adapter
    /// must derive the actual `DebugCommand` from the same validated reducer
    /// state used by [`LiveDebuggerActionContext::availability`].
    #[must_use]
    pub(crate) fn protocol_route_preview(
        self,
        instruction_bytes: &[u8],
    ) -> LiveDebuggerProtocolRoute {
        match self {
            Self::NopLiveMemory => LiveDebuggerProtocolRoute::WriteMemoryCompareBeforeWrite {
                expected: instruction_bytes.to_vec(),
                replacement: vec![0x90; instruction_bytes.len()],
            },
            Self::SetSoftwareBreakpoint => LiveDebuggerProtocolRoute::SetBreakpoint {
                kind: BreakpointKind::Software,
                persistence: BreakpointPersistence::Persistent,
                continue_after_set: false,
            },
            Self::RunToCursor => LiveDebuggerProtocolRoute::SetBreakpoint {
                kind: BreakpointKind::Software,
                persistence: BreakpointPersistence::Temporary,
                continue_after_set: true,
            },
            Self::Step(kind) => LiveDebuggerProtocolRoute::Step { kind },
            Self::Continue => LiveDebuggerProtocolRoute::Continue,
        }
    }
}

/// Typed protocol composition an authenticated adapter must perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveDebuggerProtocolRoute {
    WriteMemoryCompareBeforeWrite {
        expected: Vec<u8>,
        replacement: Vec<u8>,
    },
    SetBreakpoint {
        kind: BreakpointKind,
        persistence: BreakpointPersistence,
        continue_after_set: bool,
    },
    Step {
        kind: StepKind,
    },
    Continue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstructionSelectionMove {
    Previous,
    Next,
    First,
    Last,
}

#[must_use]
pub(crate) fn navigate_instruction_selection(
    current: Option<usize>,
    row_count: usize,
    movement: InstructionSelectionMove,
) -> Option<usize> {
    if row_count == 0 {
        return None;
    }
    let last = row_count - 1;
    let current = current.map(|index| index.min(last));
    Some(match movement {
        InstructionSelectionMove::First => 0,
        InstructionSelectionMove::Last => last,
        InstructionSelectionMove::Previous => current.unwrap_or(0).saturating_sub(1),
        InstructionSelectionMove::Next => {
            current.map_or(0, |index| index.saturating_add(1).min(last))
        }
    })
}

/// Read-only projection of a validated live client reducer into UI policy.
///
/// A connected constructor must receive the complete capability report and
/// state derived from the authenticated typed debugger client. This model does
/// not itself authenticate a peer or construct raw commands.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LiveDebuggerActionContext<'a> {
    authenticated: bool,
    session_state: Option<SessionStateKind>,
    stop_token: Option<StopToken>,
    capabilities: Option<&'a CapabilityReport>,
    exact_live_address: Option<MemoryAddress>,
    authenticated_stopped_thread: Option<ThreadId>,
    /// UI selection is an untrusted hint until it exactly matches the thread
    /// carried by the authenticated stopped state.
    selected_thread: Option<ThreadId>,
}

impl LiveDebuggerActionContext<'static> {
    #[must_use]
    pub(crate) const fn disconnected() -> Self {
        Self {
            authenticated: false,
            session_state: None,
            stop_token: None,
            capabilities: None,
            exact_live_address: None,
            authenticated_stopped_thread: None,
            selected_thread: None,
        }
    }
}

impl<'a> LiveDebuggerActionContext<'a> {
    /// Production adapter seam for a future authenticated typed client. The
    /// caller must supply the complete validated reducer state, capability
    /// report, exact module-address binding, and current UI thread selection.
    /// The concrete `StopToken` and sole trusted step-thread identity are
    /// derived only from the supplied `SessionState::Stopped`. A UI selection
    /// can enable a step route only when it exactly matches that authenticated
    /// stopped thread; the current workbench deliberately has no such client.
    #[allow(
        dead_code,
        reason = "kept as the fail-closed production seam for the future authenticated client adapter"
    )]
    pub(crate) fn from_authenticated_session(
        session_state: &SessionState,
        capabilities: &'a CapabilityReport,
        exact_live_address: Option<MemoryAddress>,
        selected_thread: Option<ThreadId>,
    ) -> Self {
        let (stop_token, authenticated_stopped_thread) = match session_state {
            SessionState::Stopped {
                token, thread_id, ..
            } => (Some(*token), Some(*thread_id)),
            _ => (None, None),
        };
        Self {
            authenticated: true,
            session_state: Some(session_state.kind()),
            stop_token,
            capabilities: Some(capabilities),
            exact_live_address,
            authenticated_stopped_thread,
            selected_thread,
        }
    }

    /// Returns the exact stop/thread pair an authenticated step route may use.
    ///
    /// The selected thread never becomes authority. It can only select the
    /// thread identity already carried by the authenticated stopped state.
    #[must_use]
    fn matching_step_route_authority(self) -> Option<(StopToken, ThreadId)> {
        let stop_token = self.stop_token?;
        let stopped_thread = self.authenticated_stopped_thread?;
        (self.authenticated
            && self.session_state == Some(SessionStateKind::Stopped)
            && self.selected_thread == Some(stopped_thread))
        .then_some((stop_token, stopped_thread))
    }

    /// Builds a typed step command only after the same capability, stopped
    /// state, and thread-authority checks used by the visible action policy.
    #[allow(
        dead_code,
        reason = "kept as the fail-closed typed route for the future authenticated client adapter"
    )]
    pub(crate) fn authenticated_step_command(self, kind: StepKind) -> Option<DebugCommand> {
        if !self
            .availability(LiveInstructionAction::Step(kind), &[])
            .is_enabled()
        {
            return None;
        }
        let (stop, thread_id) = self.matching_step_route_authority()?;
        Some(DebugCommand::Step {
            stop,
            thread_id,
            kind,
        })
    }

    #[must_use]
    pub(crate) fn availability(
        self,
        action: LiveInstructionAction,
        instruction_bytes: &[u8],
    ) -> ActionAvailability {
        if action == LiveInstructionAction::NopLiveMemory {
            if instruction_bytes.is_empty() {
                return ActionAvailability::disabled(
                    "The selected instruction has no exact bytes to compare and replace.",
                );
            }
            if instruction_bytes.len() > MAX_STATIC_PATCH_NOP_INSTRUCTION_BYTES {
                return ActionAvailability::disabled(format!(
                    "The selected byte span is {} bytes; one x64 instruction is at most {MAX_STATIC_PATCH_NOP_INSTRUCTION_BYTES} bytes.",
                    instruction_bytes.len()
                ));
            }
            if instruction_bytes.iter().all(|byte| *byte == 0x90) {
                return ActionAvailability::disabled(
                    "The selected instruction is already NOP-filled.",
                );
            }
        }
        if !self.authenticated {
            return ActionAvailability::disabled(
                "No authenticated live debugger session is connected to the workbench.",
            );
        }
        let Some(report) = self.capabilities else {
            return ActionAvailability::disabled(
                "The live session has no complete validated capability report.",
            );
        };
        for capability in action.required_capabilities() {
            if !report
                .statuses
                .iter()
                .any(|status| status.capability == *capability)
            {
                return ActionAvailability::disabled(format!(
                    "Required capability {capability:?} is missing from the live session capability report."
                ));
            }
        }
        if report.validate().is_err() {
            return ActionAvailability::disabled(
                "The live session capability report failed complete protocol validation.",
            );
        }
        if self.session_state != Some(SessionStateKind::Stopped) || self.stop_token.is_none() {
            return ActionAvailability::disabled(
                "The live session must be stopped at an authenticated StopToken.",
            );
        }
        if action.requires_exact_live_address() && self.exact_live_address.is_none() {
            return ActionAvailability::disabled(
                "The static RVA is not bound to an exact address in the authenticated live module.",
            );
        }
        if action.requires_selected_thread() {
            if self.selected_thread.is_none() {
                return ActionAvailability::disabled(
                    "No thread is selected; a typed step command can use only the authenticated stopped thread.",
                );
            }
            if self.matching_step_route_authority().is_none() {
                return ActionAvailability::disabled(
                    "The selected thread does not match the authenticated stopped thread.",
                );
            }
        }
        for capability in action.required_capabilities() {
            let status = report
                .statuses
                .iter()
                .find(|status| status.capability == *capability)
                .expect("complete validated report contains every capability");
            if let CapabilityAvailability::Unavailable { reason, .. } = &status.availability {
                return ActionAvailability::disabled(format!(
                    "Required capability {capability:?} is unavailable: {reason}"
                ));
            }
        }
        ActionAvailability::enabled()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActionAvailability {
    enabled: bool,
    disabled_reason: Option<String>,
}

impl ActionAvailability {
    fn enabled() -> Self {
        Self {
            enabled: true,
            disabled_reason: None,
        }
    }

    fn disabled(reason: impl Into<String>) -> Self {
        Self {
            enabled: false,
            disabled_reason: Some(reason.into()),
        }
    }

    #[must_use]
    pub(crate) const fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub(crate) fn disabled_reason(&self) -> Option<&str> {
        self.disabled_reason.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use resymbol_debugger::{
        CapabilityStatus, CapabilityUnavailableCode, DebugCapability, RunId, RunToken, SessionId,
        SessionStateKind, StateGeneration, StateToken, StopId, StopReason,
    };

    use super::*;

    fn capability_report(unavailable: Option<(DebugCapability, &'static str)>) -> CapabilityReport {
        CapabilityReport {
            statuses: DebugCapability::ALL
                .into_iter()
                .map(|capability| CapabilityStatus {
                    capability,
                    availability: unavailable.as_ref().map_or(
                        CapabilityAvailability::Available,
                        |(unavailable, reason)| {
                            if capability == *unavailable {
                                CapabilityAvailability::Unavailable {
                                    code: CapabilityUnavailableCode::BackendUnavailable,
                                    reason: (*reason).to_owned(),
                                }
                            } else {
                                CapabilityAvailability::Available
                            }
                        },
                    ),
                })
                .collect(),
        }
    }

    fn authenticated_state_token() -> StateToken {
        StateToken {
            session_id: SessionId::new(1).expect("session id"),
            generation: StateGeneration::new(1).expect("state generation"),
        }
    }

    fn authenticated_stop_token() -> StopToken {
        StopToken {
            state: authenticated_state_token(),
            stop_id: StopId::new(1).expect("stop id"),
        }
    }

    fn exact_live_address() -> MemoryAddress {
        MemoryAddress::new(0x0000_0001_4000_1000)
    }

    fn selected_thread() -> ThreadId {
        ThreadId::new(7).expect("thread id")
    }

    fn untrusted_selected_thread() -> ThreadId {
        ThreadId::new(8).expect("untrusted selected thread id")
    }

    fn authenticated_stopped_state() -> SessionState {
        SessionState::Stopped {
            token: authenticated_stop_token(),
            reason: StopReason::UserPause,
            thread_id: selected_thread(),
        }
    }

    fn authenticated_running_state() -> SessionState {
        SessionState::Running {
            token: RunToken {
                state: authenticated_state_token(),
                run_id: RunId::new(1).expect("run id"),
            },
        }
    }

    #[test]
    fn nop_drafts_are_bounded_owned_deduplicated_and_nonoverlapping() {
        let mut drafts = PendingStaticPatchDrafts::default();
        assert_eq!(
            drafts
                .queue_nop(0x1000, &[0x48, 0x89, 0xE5], "NOP mov rbp,rsp")
                .expect("queue draft"),
            PatchDraftQueueOutcome::Added
        );
        assert_eq!(drafts.drafts()[0].replacement(), &[0x90; 3]);
        assert_eq!(
            drafts.drafts()[0].kind(),
            StaticPatchDraftKind::NopInstruction
        );
        assert_eq!(drafts.drafts()[0].expected(), &[0x48, 0x89, 0xE5]);
        assert_eq!(drafts.drafts()[0].label(), "NOP mov rbp,rsp");
        assert_eq!(
            drafts.drafts()[0].source_check_and_replacement(),
            (&[0x48, 0x89, 0xE5][..], &[0x90, 0x90, 0x90][..])
        );
        assert_eq!(
            drafts
                .queue_nop(0x1000, &[0x48, 0x89, 0xE5], "NOP mov rbp,rsp")
                .expect("deduplicate"),
            PatchDraftQueueOutcome::AlreadyQueued
        );
        assert!(matches!(
            drafts.queue_nop(0x1001, &[0xCC], "overlap"),
            Err(StaticPatchDraftError::OverlappingDraft {
                existing_rva: 0x1000
            })
        ));
        assert!(drafts.remove(0x1000));
        assert!(drafts.drafts().is_empty());
    }

    #[test]
    fn nop_draft_rejects_empty_oversized_overflowing_and_control_labels() {
        assert!(matches!(
            StaticPatchDraft::nop_instruction(0, &[], "empty"),
            Err(StaticPatchDraftError::EmptyInstruction)
        ));
        assert!(matches!(
            StaticPatchDraft::nop_instruction(0, &[0; 16], "large"),
            Err(StaticPatchDraftError::InstructionTooLarge { .. })
        ));
        assert!(matches!(
            StaticPatchDraft::nop_instruction(0, &[0x90, 0x90], "already NOP-filled"),
            Err(StaticPatchDraftError::AlreadyNopFilled)
        ));
        assert!(matches!(
            StaticPatchDraft::nop_instruction(u64::MAX, &[0xCC], "overflow"),
            Err(StaticPatchDraftError::AddressOverflow)
        ));
        assert!(matches!(
            StaticPatchDraft::nop_instruction(0, &[0xCC], "bad\nlabel"),
            Err(StaticPatchDraftError::InvalidLabel)
        ));
        assert!(matches!(
            StaticPatchDraft::nop_instruction(0, &[0xCC], " padded"),
            Err(StaticPatchDraftError::InvalidLabel)
        ));
    }

    #[test]
    fn validated_patch_set_requests_build_a_complete_replacement_before_swap() {
        let requests = vec![
            StaticPatchEditRequest::replace_bytes(
                0x2000,
                vec![0x11; 32],
                vec![0x22; 32],
                "loaded general replacement",
            )
            .expect("valid general replacement"),
            StaticPatchEditRequest::nop_instruction(0x1000, [0xcc], "loaded NOP")
                .expect("valid NOP"),
        ];

        let drafts = PendingStaticPatchDrafts::from_requests(&requests)
            .expect("validated requests fit the draft model");

        assert_eq!(drafts.drafts().len(), 2);
        assert_eq!(drafts.drafts()[0].rva(), 0x1000);
        assert_eq!(drafts.drafts()[0].replacement(), &[0x90]);
        assert_eq!(drafts.drafts()[1].rva(), 0x2000);
        assert_eq!(drafts.drafts()[1].expected(), &[0x11; 32]);
        assert_eq!(drafts.drafts()[1].replacement(), &[0x22; 32]);
    }

    #[test]
    fn exact_byte_input_accepts_only_canonical_changed_equal_length_hex() {
        assert_eq!(parse_canonical_exact_hex("75 0a", 2), Ok(vec![0x75, 0x0a]));
        for malformed in ["75,0A", "7 0A", "750A", "GG 0A"] {
            assert_eq!(
                parse_canonical_exact_hex(malformed, 2),
                Err(StaticExactByteEditError::NonCanonicalHex),
                "{malformed:?}"
            );
        }
        for oversized in [" 75 0A", "75 0A ", "75  0A", "0x75 0A"] {
            assert!(matches!(
                parse_canonical_exact_hex(oversized, 2),
                Err(StaticExactByteEditError::ReplacementTextTooLong { maximum: 5, .. })
            ));
        }
        assert_eq!(
            parse_canonical_exact_hex("75", 2),
            Err(StaticExactByteEditError::ReplacementLengthMismatch {
                expected: 2,
                actual: 1,
            })
        );
        assert_eq!(
            parse_canonical_exact_hex("", 2),
            Err(StaticExactByteEditError::EmptyReplacement)
        );

        let mut edit = StaticExactByteEdit::for_instruction(0x1000, &[0x74, 0x05], "je short")
            .expect("bounded exact edit");
        assert_eq!(edit.mode(), StaticExactByteEditMode::QueueNew);
        assert_eq!(edit.replacement_hex(), "74 05");
        assert_eq!(
            edit.validated_replacement(),
            Err(StaticExactByteEditError::UnchangedOriginal)
        );
        *edit.replacement_hex_mut() = "75 05".to_owned();
        assert_eq!(edit.validated_replacement(), Ok(vec![0x75, 0x05]));
    }

    #[test]
    fn queued_exact_byte_edit_requires_a_new_value_and_retains_source_evidence() {
        let draft = StaticPatchDraft::replace_bytes(
            0x2000,
            &[0x0f, 0x84, 0, 0, 0, 0],
            &[0x0f, 0x85, 0, 0, 0, 0],
            "invert branch",
        )
        .expect("queued replacement");
        let mut edit = StaticExactByteEdit::for_queued_draft(&draft, "je near");

        assert_eq!(edit.mode(), StaticExactByteEditMode::EditQueued);
        assert_eq!(edit.rva(), 0x2000);
        assert_eq!(edit.original(), &[0x0f, 0x84, 0, 0, 0, 0]);
        assert_eq!(edit.original_instruction(), "je near");
        assert_eq!(edit.replacement_hex(), "0F 85 00 00 00 00");
        assert_eq!(
            edit.validated_replacement(),
            Err(StaticExactByteEditError::UnchangedQueuedReplacement)
        );
        *edit.replacement_hex_mut() = "0F 84 00 00 00 00".to_owned();
        assert_eq!(
            edit.validated_replacement(),
            Err(StaticExactByteEditError::UnchangedOriginal)
        );
    }

    #[test]
    fn exact_draft_replacement_is_transactional_and_keeps_canonical_order() {
        let mut drafts = PendingStaticPatchDrafts::default();
        drafts
            .queue_nop(0x3000, &[0xcc], "later")
            .expect("later draft");
        drafts
            .queue_nop(0x1000, &[0xcc], "selected")
            .expect("selected draft");
        let before = drafts.clone();

        assert_eq!(
            drafts.replace_exact_with_bytes(0x1000, &[0xcc], &[0x90, 0x90], "invalid replacement",),
            Err(StaticPatchDraftError::ReplacementLengthMismatch {
                expected: 1,
                replacement: 2,
            })
        );
        assert_eq!(drafts, before);
        assert_eq!(
            drafts.replace_exact_with_bytes(0x1000, &[0xcd], &[0x90], "stale source"),
            Err(StaticPatchDraftError::DraftSourceMismatch { rva: 0x1000 })
        );
        assert_eq!(drafts, before);
        assert_eq!(
            drafts.replace_exact_with_bytes(0x2000, &[0xcc], &[0x90], "missing"),
            Err(StaticPatchDraftError::MissingDraftAtSelection { rva: 0x2000 })
        );
        assert_eq!(drafts, before);

        assert_eq!(
            drafts
                .replace_exact_with_bytes(0x1000, &[0xcc], &[0xc3], "exact bytes")
                .expect("transactional replacement"),
            PatchDraftQueueOutcome::Added
        );
        assert_eq!(
            drafts
                .drafts()
                .iter()
                .map(StaticPatchDraft::rva)
                .collect::<Vec<_>>(),
            vec![0x1000, 0x3000]
        );
        let edited = drafts
            .draft_for_exact_selection(0x1000, &[0xcc])
            .expect("edited exact selection");
        assert_eq!(edited.kind(), StaticPatchDraftKind::ReplaceBytes);
        assert_eq!(edited.replacement(), &[0xc3]);
        assert!(drafts.remove_exact_selection(0x1000, &[0xcc]));
        assert!(!drafts.remove_exact_selection(0x3000, &[0xcd]));
        assert_eq!(drafts.drafts()[0].rva(), 0x3000);
    }

    #[test]
    fn conditional_branch_edits_are_exact_same_size_and_fail_closed() {
        assert_eq!(
            ConditionalBranchPatch::InvertCondition.replacement(&[0x74, 0x05]),
            Some(vec![0x75, 0x05])
        );
        assert_eq!(
            ConditionalBranchPatch::AlwaysTaken.replacement(&[0x75, 0xfb]),
            Some(vec![0xeb, 0xfb])
        );
        assert_eq!(
            ConditionalBranchPatch::InvertCondition
                .replacement(&[0x0f, 0x84, 0x12, 0x34, 0x56, 0x78]),
            Some(vec![0x0f, 0x85, 0x12, 0x34, 0x56, 0x78])
        );
        assert_eq!(
            ConditionalBranchPatch::AlwaysTaken.replacement(&[0x0f, 0x85, 0, 0, 0, 0]),
            Some(vec![0xe9, 1, 0, 0, 0, 0x90])
        );
        assert_eq!(
            ConditionalBranchPatch::AlwaysTaken.replacement(&[0x0f, 0x85, 0xff, 0xff, 0xff, 0x7f]),
            None
        );
        assert_eq!(
            ConditionalBranchPatch::InvertCondition.replacement(&[0x66, 0x74, 0x05]),
            None
        );
        assert_eq!(
            ConditionalBranchPatch::AlwaysTaken.replacement(&[0xe9, 0, 0, 0, 0]),
            None
        );

        let mut drafts = PendingStaticPatchDrafts::default();
        drafts
            .queue_replace(0x2000, &[0x74, 0x05], &[0x75, 0x05], "Invert je")
            .expect("queue conditional replacement");
        assert_eq!(
            drafts.drafts()[0].kind(),
            StaticPatchDraftKind::ReplaceBytes
        );
        assert_eq!(drafts.drafts()[0].replacement(), &[0x75, 0x05]);
    }

    #[test]
    fn disconnected_live_actions_share_an_exact_fail_closed_reason() {
        let context = LiveDebuggerActionContext::disconnected();
        for action in LiveInstructionAction::ALL {
            let availability = context.availability(action, &[0xCC]);
            assert!(!availability.is_enabled());
            assert_eq!(
                availability.disabled_reason(),
                Some("No authenticated live debugger session is connected to the workbench.")
            );
        }
    }

    #[test]
    fn live_actions_require_complete_capabilities_stop_address_and_thread() {
        let all = capability_report(None);
        let missing_report = LiveDebuggerActionContext {
            authenticated: true,
            session_state: Some(SessionStateKind::Stopped),
            stop_token: Some(authenticated_stop_token()),
            capabilities: None,
            exact_live_address: Some(exact_live_address()),
            authenticated_stopped_thread: Some(selected_thread()),
            selected_thread: Some(selected_thread()),
        };
        assert_eq!(
            missing_report
                .availability(LiveInstructionAction::Continue, &[0xCC])
                .disabled_reason(),
            Some("The live session has no complete validated capability report.")
        );
        let empty_report = CapabilityReport {
            statuses: Vec::new(),
        };
        let stopped_state = authenticated_stopped_state();
        let missing_execution = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &empty_report,
            Some(exact_live_address()),
            Some(selected_thread()),
        );
        assert_eq!(
            missing_execution
                .availability(LiveInstructionAction::Continue, &[0xCC])
                .disabled_reason(),
            Some(
                "Required capability ExecutionControl is missing from the live session capability report."
            )
        );

        let required_only_report = CapabilityReport {
            statuses: vec![CapabilityStatus {
                capability: DebugCapability::ExecutionControl,
                availability: CapabilityAvailability::Available,
            }],
        };
        let incomplete_capabilities = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &required_only_report,
            Some(exact_live_address()),
            Some(selected_thread()),
        );
        assert_eq!(
            incomplete_capabilities
                .availability(LiveInstructionAction::Continue, &[0xCC])
                .disabled_reason(),
            Some("The live session capability report failed complete protocol validation.")
        );

        let running_state = authenticated_running_state();
        let running = LiveDebuggerActionContext::from_authenticated_session(
            &running_state,
            &all,
            Some(exact_live_address()),
            Some(selected_thread()),
        );
        assert_eq!(
            running
                .availability(LiveInstructionAction::Continue, &[0xCC])
                .disabled_reason(),
            Some("The live session must be stopped at an authenticated StopToken.")
        );

        let no_address = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &all,
            None,
            Some(selected_thread()),
        );
        assert!(
            no_address
                .availability(LiveInstructionAction::SetSoftwareBreakpoint, &[0xCC])
                .disabled_reason()
                .expect("disabled reason")
                .contains("not bound to an exact address")
        );

        let no_thread = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &all,
            Some(exact_live_address()),
            None,
        );
        assert!(
            no_thread
                .availability(LiveInstructionAction::Step(StepKind::Out), &[0xCC])
                .disabled_reason()
                .expect("disabled reason")
                .contains("stopped thread")
        );

        let unavailable = capability_report(Some((
            DebugCapability::ExecutionControl,
            "provider has no execution controller",
        )));
        let no_execution = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &unavailable,
            Some(exact_live_address()),
            Some(selected_thread()),
        );
        assert!(
            no_execution
                .availability(LiveInstructionAction::Continue, &[0xCC])
                .disabled_reason()
                .expect("disabled reason")
                .contains("provider has no execution controller")
        );

        for (capability, action) in [
            (
                DebugCapability::LiveMemoryWrite,
                LiveInstructionAction::NopLiveMemory,
            ),
            (
                DebugCapability::SoftwareBreakpoints,
                LiveInstructionAction::SetSoftwareBreakpoint,
            ),
            (
                DebugCapability::SoftwareBreakpoints,
                LiveInstructionAction::RunToCursor,
            ),
            (
                DebugCapability::ExecutionControl,
                LiveInstructionAction::RunToCursor,
            ),
        ] {
            let report =
                capability_report(Some((capability, "provider denied required capability")));
            let context = LiveDebuggerActionContext::from_authenticated_session(
                &stopped_state,
                &report,
                Some(exact_live_address()),
                Some(selected_thread()),
            );
            let availability = context.availability(action, &[0xCC]);
            let reason = availability
                .disabled_reason()
                .expect("required capability reason");
            assert!(reason.contains(&format!("{capability:?}")));
            assert!(reason.contains("provider denied required capability"));
        }
    }

    #[test]
    fn matching_stopped_thread_is_the_only_step_route_authority() {
        let all = capability_report(None);
        let stopped_state = authenticated_stopped_state();
        let context = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &all,
            Some(exact_live_address()),
            Some(selected_thread()),
        );

        assert_eq!(
            context.authenticated_step_command(StepKind::Into),
            Some(DebugCommand::Step {
                stop: authenticated_stop_token(),
                thread_id: selected_thread(),
                kind: StepKind::Into,
            })
        );
        for kind in [StepKind::Into, StepKind::Over, StepKind::Out] {
            assert!(
                context
                    .availability(LiveInstructionAction::Step(kind), &[0xCC])
                    .is_enabled(),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn running_state_has_no_step_thread_authority() {
        let all = capability_report(None);
        let running_state = authenticated_running_state();
        let context = LiveDebuggerActionContext::from_authenticated_session(
            &running_state,
            &all,
            Some(exact_live_address()),
            Some(selected_thread()),
        );

        assert_eq!(context.authenticated_step_command(StepKind::Into), None);
        for kind in [StepKind::Into, StepKind::Over, StepKind::Out] {
            assert_eq!(
                context
                    .availability(LiveInstructionAction::Step(kind), &[0xCC])
                    .disabled_reason(),
                Some("The live session must be stopped at an authenticated StopToken."),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn missing_thread_selection_never_enables_a_step_route() {
        let all = capability_report(None);
        let stopped_state = authenticated_stopped_state();
        let context = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &all,
            Some(exact_live_address()),
            None,
        );

        assert_eq!(context.authenticated_step_command(StepKind::Into), None);
        for kind in [StepKind::Into, StepKind::Over, StepKind::Out] {
            assert_eq!(
                context
                    .availability(LiveInstructionAction::Step(kind), &[0xCC])
                    .disabled_reason(),
                Some(
                    "No thread is selected; a typed step command can use only the authenticated stopped thread."
                ),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn mismatched_ui_thread_never_becomes_step_route_authority() {
        let all = capability_report(None);
        let stopped_state = authenticated_stopped_state();
        let context = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &all,
            Some(exact_live_address()),
            Some(untrusted_selected_thread()),
        );

        assert_eq!(context.authenticated_step_command(StepKind::Into), None);
        for kind in [StepKind::Into, StepKind::Over, StepKind::Out] {
            assert_eq!(
                context
                    .availability(LiveInstructionAction::Step(kind), &[0xCC])
                    .disabled_reason(),
                Some("The selected thread does not match the authenticated stopped thread."),
                "{kind:?}"
            );
        }
        assert!(
            context
                .availability(LiveInstructionAction::Continue, &[0xCC])
                .is_enabled(),
            "an untrusted thread selection must not mint step authority or disable thread-neutral Continue"
        );
    }

    #[test]
    fn step_actions_require_matching_granular_capability() {
        let stopped_state = authenticated_stopped_state();
        let step_matrix = [
            (StepKind::Into, DebugCapability::StepInto),
            (StepKind::Over, DebugCapability::StepOver),
            (StepKind::Out, DebugCapability::StepOut),
        ];

        for &(unavailable_kind, unavailable_capability) in &step_matrix {
            let report = capability_report(Some((
                unavailable_capability,
                "provider denied this granular step mode",
            )));
            let context = LiveDebuggerActionContext::from_authenticated_session(
                &stopped_state,
                &report,
                Some(exact_live_address()),
                Some(selected_thread()),
            );

            for &(candidate_kind, candidate_capability) in &step_matrix {
                let availability =
                    context.availability(LiveInstructionAction::Step(candidate_kind), &[0xCC]);
                if candidate_capability == unavailable_capability {
                    let reason = availability
                        .disabled_reason()
                        .expect("matching granular capability must fail closed");
                    assert!(!availability.is_enabled(), "{unavailable_kind:?}");
                    assert!(reason.contains(&format!("{unavailable_capability:?}")));
                    assert!(reason.contains("provider denied this granular step mode"));
                } else {
                    assert!(availability.is_enabled(), "{candidate_kind:?}");
                    assert_eq!(availability.disabled_reason(), None);
                }
            }
            assert_eq!(context.authenticated_step_command(unavailable_kind), None);

            let mut missing_report = capability_report(None);
            missing_report
                .statuses
                .retain(|status| status.capability != unavailable_capability);
            let missing_context = LiveDebuggerActionContext::from_authenticated_session(
                &stopped_state,
                &missing_report,
                Some(exact_live_address()),
                Some(selected_thread()),
            );
            let expected_missing_reason = format!(
                "Required capability {unavailable_capability:?} is missing from the live session capability report."
            );
            assert_eq!(
                missing_context
                    .availability(LiveInstructionAction::Step(unavailable_kind), &[0xCC])
                    .disabled_reason(),
                Some(expected_missing_reason.as_str())
            );
            assert_eq!(
                missing_context.authenticated_step_command(unavailable_kind),
                None
            );
        }

        let report = capability_report(Some((
            DebugCapability::ExecutionControl,
            "provider denied execution control",
        )));
        let context = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &report,
            Some(exact_live_address()),
            Some(selected_thread()),
        );
        for &(kind, _) in &step_matrix {
            let availability = context.availability(LiveInstructionAction::Step(kind), &[0xCC]);
            let reason = availability
                .disabled_reason()
                .expect("all step actions also require execution control");
            assert!(!availability.is_enabled(), "{kind:?}");
            assert!(reason.contains("ExecutionControl"));
            assert!(reason.contains("provider denied execution control"));
        }
    }

    #[test]
    fn fully_bound_actions_map_to_existing_capability_contracts() {
        let all = capability_report(None);
        let stopped_state = authenticated_stopped_state();
        let context = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &all,
            Some(exact_live_address()),
            Some(selected_thread()),
        );
        for action in [
            LiveInstructionAction::NopLiveMemory,
            LiveInstructionAction::SetSoftwareBreakpoint,
            LiveInstructionAction::RunToCursor,
            LiveInstructionAction::Step(StepKind::Into),
            LiveInstructionAction::Step(StepKind::Over),
            LiveInstructionAction::Step(StepKind::Out),
            LiveInstructionAction::Continue,
        ] {
            let availability = context.availability(action, &[0xCC]);
            assert!(availability.is_enabled(), "{action:?}");
            assert_eq!(availability.disabled_reason(), None);
        }
        assert_eq!(
            LiveInstructionAction::SetSoftwareBreakpoint.protocol_route_preview(&[0xCC]),
            LiveDebuggerProtocolRoute::SetBreakpoint {
                kind: BreakpointKind::Software,
                persistence: BreakpointPersistence::Persistent,
                continue_after_set: false,
            }
        );
        assert_eq!(
            LiveInstructionAction::RunToCursor.protocol_route_preview(&[0x75, 0x02]),
            LiveDebuggerProtocolRoute::SetBreakpoint {
                kind: BreakpointKind::Software,
                persistence: BreakpointPersistence::Temporary,
                continue_after_set: true,
            }
        );
        assert_eq!(
            LiveInstructionAction::Step(StepKind::Out).protocol_route_preview(&[0x90]),
            LiveDebuggerProtocolRoute::Step {
                kind: StepKind::Out
            }
        );
        assert_eq!(
            LiveInstructionAction::NopLiveMemory.protocol_route_preview(&[0x48, 0x89, 0xE5]),
            LiveDebuggerProtocolRoute::WriteMemoryCompareBeforeWrite {
                expected: vec![0x48, 0x89, 0xE5],
                replacement: vec![0x90; 3],
            }
        );
        assert_eq!(
            context
                .availability(LiveInstructionAction::NopLiveMemory, &[0x90, 0x90])
                .disabled_reason(),
            Some("The selected instruction is already NOP-filled.")
        );
        assert_eq!(
            context
                .availability(LiveInstructionAction::NopLiveMemory, &[])
                .disabled_reason(),
            Some("The selected instruction has no exact bytes to compare and replace.")
        );
        assert!(
            context
                .availability(LiveInstructionAction::NopLiveMemory, &[0xCC; 16])
                .disabled_reason()
                .expect("oversized instruction reason")
                .contains("one x64 instruction is at most 15 bytes")
        );
    }

    #[test]
    fn keyboard_navigation_is_bounded_and_recovers_without_a_selection() {
        assert_eq!(
            navigate_instruction_selection(None, 3, InstructionSelectionMove::Next),
            Some(0)
        );
        assert_eq!(
            navigate_instruction_selection(Some(0), 3, InstructionSelectionMove::Previous),
            Some(0)
        );
        assert_eq!(
            navigate_instruction_selection(Some(2), 3, InstructionSelectionMove::Next),
            Some(2)
        );
        assert_eq!(
            navigate_instruction_selection(Some(1), 3, InstructionSelectionMove::First),
            Some(0)
        );
        assert_eq!(
            navigate_instruction_selection(Some(1), 3, InstructionSelectionMove::Last),
            Some(2)
        );
        assert_eq!(
            navigate_instruction_selection(Some(1), 0, InstructionSelectionMove::Next),
            None
        );
        assert_eq!(
            navigate_instruction_selection(Some(99), 3, InstructionSelectionMove::Previous),
            Some(1)
        );
    }
}
