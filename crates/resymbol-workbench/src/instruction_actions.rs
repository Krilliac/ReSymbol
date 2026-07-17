//! UI-thread models for instruction actions and unpublished static patch drafts.
//!
//! This module owns no debugger client, target process, file writer, or patch
//! publication service. The workbench converts [`StaticNopPatchDraft`] values
//! through the fallible `StaticPatchEditRequest::nop_instruction` constructor,
//! then sends those owned requests to the application-service worker for
//! checked plan construction and create-new publication.

use resymbol_debugger::{
    BreakpointKind, CapabilityAvailability, CapabilityReport, DebugCapability, MemoryAddress,
    SessionState, SessionStateKind, StepKind, StopToken, ThreadId,
};
use thiserror::Error;

const MAX_X64_INSTRUCTION_BYTES: usize = 15;
const MAX_PATCH_DRAFT_LABEL_BYTES: usize = 128;
pub(crate) const MAX_PENDING_STATIC_PATCH_DRAFTS: usize = 128;

/// One bounded, unpublished same-length NOP edit owned by the workbench UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticNopPatchDraft {
    rva: u64,
    expected: Vec<u8>,
    label: String,
}

impl StaticNopPatchDraft {
    pub(crate) fn new(
        rva: u64,
        expected: &[u8],
        label: impl Into<String>,
    ) -> Result<Self, StaticPatchDraftError> {
        if expected.is_empty() {
            return Err(StaticPatchDraftError::EmptyInstruction);
        }
        if expected.len() > MAX_X64_INSTRUCTION_BYTES {
            return Err(StaticPatchDraftError::InstructionTooLarge {
                actual: expected.len(),
                maximum: MAX_X64_INSTRUCTION_BYTES,
            });
        }
        if expected.iter().all(|byte| *byte == 0x90) {
            return Err(StaticPatchDraftError::AlreadyNopFilled);
        }
        if rva.checked_add(expected.len() as u64).is_none() {
            return Err(StaticPatchDraftError::AddressOverflow);
        }
        let label = label.into();
        if label.trim() != label
            || label.is_empty()
            || label.len() > MAX_PATCH_DRAFT_LABEL_BYTES
            || label.chars().any(char::is_control)
        {
            return Err(StaticPatchDraftError::InvalidLabel);
        }
        Ok(Self {
            rva,
            expected: expected.to_vec(),
            label,
        })
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
    pub(crate) fn replacement(&self) -> Vec<u8> {
        vec![0x90; self.expected.len()]
    }

    /// Exact source-check bytes and same-length replacement for a future
    /// fallible static-patch adapter. No file or process is modified here.
    #[must_use]
    pub(crate) fn source_check_and_replacement(&self) -> (&[u8], Vec<u8>) {
        (&self.expected, self.replacement())
    }

    fn end_rva(&self) -> u64 {
        self.rva + self.expected.len() as u64
    }
}

/// Bounded collection of unpublished static edits.
#[derive(Debug, Default)]
pub(crate) struct PendingStaticPatchDrafts {
    drafts: Vec<StaticNopPatchDraft>,
}

impl PendingStaticPatchDrafts {
    #[must_use]
    pub(crate) fn drafts(&self) -> &[StaticNopPatchDraft] {
        &self.drafts
    }

    pub(crate) fn queue_nop(
        &mut self,
        rva: u64,
        expected: &[u8],
        label: impl Into<String>,
    ) -> Result<PatchDraftQueueOutcome, StaticPatchDraftError> {
        let draft = StaticNopPatchDraft::new(rva, expected, label)?;
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
        self.drafts.push(draft);
        self.drafts.sort_by_key(StaticNopPatchDraft::rva);
        Ok(PatchDraftQueueOutcome::Added)
    }

    pub(crate) fn remove(&mut self, rva: u64) -> bool {
        let before = self.drafts.len();
        self.drafts.retain(|draft| draft.rva != rva);
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
    #[error("instruction is {actual} bytes; x64 instructions are limited to {maximum}")]
    InstructionTooLarge { actual: usize, maximum: usize },
    #[error("instruction is already NOP-filled")]
    AlreadyNopFilled,
    #[error("instruction range overflows the RVA address space")]
    AddressOverflow,
    #[error("patch draft label must be printable, nonempty, and at most 128 UTF-8 bytes")]
    InvalidLabel,
    #[error("patch draft overlaps the existing edit at RVA 0x{existing_rva:016X}")]
    OverlappingDraft { existing_rva: u64 },
    #[error("pending static patch draft limit {maximum} reached")]
    DraftLimitReached { maximum: usize },
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
            Self::Step(_) | Self::Continue => EXECUTION,
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
                temporary: false,
                continue_after_set: false,
            },
            Self::RunToCursor => LiveDebuggerProtocolRoute::SetBreakpoint {
                kind: BreakpointKind::Software,
                temporary: true,
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
        temporary: bool,
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
            selected_thread: None,
        }
    }
}

impl<'a> LiveDebuggerActionContext<'a> {
    /// Production adapter seam for a future authenticated typed client. The
    /// caller must supply the complete validated reducer state, capability
    /// report, exact module-address binding, and authenticated thread
    /// selection. The concrete `StopToken` is derived only from the supplied
    /// `SessionState::Stopped`; the current workbench deliberately has no such
    /// client.
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
        let stop_token = match session_state {
            SessionState::Stopped { token, .. } => Some(*token),
            _ => None,
        };
        Self {
            authenticated: true,
            session_state: Some(session_state.kind()),
            stop_token,
            capabilities: Some(capabilities),
            exact_live_address,
            selected_thread,
        }
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
            if instruction_bytes.len() > MAX_X64_INSTRUCTION_BYTES {
                return ActionAvailability::disabled(format!(
                    "The selected byte span is {} bytes; one x64 instruction is at most {MAX_X64_INSTRUCTION_BYTES} bytes.",
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
        if action.requires_selected_thread() && self.selected_thread.is_none() {
            return ActionAvailability::disabled(
                "No authenticated stopped thread is selected for the typed step command.",
            );
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
        assert_eq!(drafts.drafts()[0].replacement(), vec![0x90; 3]);
        assert_eq!(drafts.drafts()[0].expected(), &[0x48, 0x89, 0xE5]);
        assert_eq!(drafts.drafts()[0].label(), "NOP mov rbp,rsp");
        assert_eq!(
            drafts.drafts()[0].source_check_and_replacement(),
            (&[0x48, 0x89, 0xE5][..], vec![0x90; 3])
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
            StaticNopPatchDraft::new(0, &[], "empty"),
            Err(StaticPatchDraftError::EmptyInstruction)
        ));
        assert!(matches!(
            StaticNopPatchDraft::new(0, &[0; 16], "large"),
            Err(StaticPatchDraftError::InstructionTooLarge { .. })
        ));
        assert!(matches!(
            StaticNopPatchDraft::new(0, &[0x90, 0x90], "already NOP-filled"),
            Err(StaticPatchDraftError::AlreadyNopFilled)
        ));
        assert!(matches!(
            StaticNopPatchDraft::new(u64::MAX, &[0xCC], "overflow"),
            Err(StaticPatchDraftError::AddressOverflow)
        ));
        assert!(matches!(
            StaticNopPatchDraft::new(0, &[0xCC], "bad\nlabel"),
            Err(StaticPatchDraftError::InvalidLabel)
        ));
        assert!(matches!(
            StaticNopPatchDraft::new(0, &[0xCC], " padded"),
            Err(StaticPatchDraftError::InvalidLabel)
        ));
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
            selected_thread: Some(selected_thread()),
        };
        assert_eq!(
            missing_report
                .availability(LiveInstructionAction::Continue, &[0xCC])
                .disabled_reason(),
            Some("The live session has no complete validated capability report.")
        );
        let invalid_report = CapabilityReport {
            statuses: Vec::new(),
        };
        let stopped_state = authenticated_stopped_state();
        let invalid_capabilities = LiveDebuggerActionContext::from_authenticated_session(
            &stopped_state,
            &invalid_report,
            Some(exact_live_address()),
            Some(selected_thread()),
        );
        assert_eq!(
            invalid_capabilities
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
            LiveInstructionAction::RunToCursor.protocol_route_preview(&[0x75, 0x02]),
            LiveDebuggerProtocolRoute::SetBreakpoint {
                kind: BreakpointKind::Software,
                temporary: true,
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
