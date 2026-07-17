//! Bounded, receipt-driven history for compare-before-write live patches.
//!
//! This module is a pure controller-side reducer. It neither authorizes nor
//! performs a process-memory operation. Callers must dispatch the returned
//! [`DebugCommand`] through an authenticated host and resolve the pending
//! operation only with that host client's already-validated [`CommandReceipt`].
//! A reservation must be explicitly marked for dispatch before its command is
//! exposed; it may be cancelled only while dispatch is proven not to have begun.

use thiserror::Error;

use crate::{
    CommandId, CommandOutcome, CommandReceipt, DebugCommand, DebugEvent, LiveTargetBinding,
    LiveTargetBindingError, MAX_MEMORY_WRITE_BYTES, MEMORY_WRITE_FAILURE_REJECTION_CODE,
    MemoryAddress, MemoryWriteFailure, SessionId, SessionState, StateToken, StopToken,
};

/// Maximum number of committed forward writes retained for strict-LIFO undo.
pub const MAX_LIVE_PATCH_HISTORY_ENTRIES: usize = 256;

/// Maximum aggregate bytes retained across every entry's before/after images.
pub const MAX_LIVE_PATCH_HISTORY_STORED_BYTES: usize = 1024 * 1024;

/// One exact live write that was verified and committed to the undo stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePatchEntry {
    address: MemoryAddress,
    before: Vec<u8>,
    after: Vec<u8>,
    applied_stop: StopToken,
    resulting_stop: StopToken,
    command_id: CommandId,
}

impl LivePatchEntry {
    #[must_use]
    pub const fn address(&self) -> MemoryAddress {
        self.address
    }

    #[must_use]
    pub fn before(&self) -> &[u8] {
        &self.before
    }

    #[must_use]
    pub fn after(&self) -> &[u8] {
        &self.after
    }

    #[must_use]
    pub const fn applied_stop(&self) -> StopToken {
        self.applied_stop
    }

    #[must_use]
    pub const fn resulting_stop(&self) -> StopToken {
        self.resulting_stop
    }

    #[must_use]
    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }

    fn stored_bytes(&self) -> usize {
        self.before.len() + self.after.len()
    }
}

/// Kind of tracked operation awaiting exact host evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivePatchOperationKind {
    ForwardWrite,
    Undo,
}

/// Whether a reserved operation may still be cancelled without target risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivePatchOperationPhase {
    Reserved,
    Dispatched,
}

/// Exact compare-before-write operation reserved before dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLivePatchOperation {
    kind: LivePatchOperationKind,
    phase: LivePatchOperationPhase,
    stop: StopToken,
    address: MemoryAddress,
    expected: Vec<u8>,
    replacement: Vec<u8>,
}

impl PendingLivePatchOperation {
    #[must_use]
    pub const fn kind(&self) -> LivePatchOperationKind {
        self.kind
    }

    #[must_use]
    pub const fn phase(&self) -> LivePatchOperationPhase {
        self.phase
    }

    #[must_use]
    pub const fn stop(&self) -> StopToken {
        self.stop
    }

    #[must_use]
    pub const fn address(&self) -> MemoryAddress {
        self.address
    }

    #[must_use]
    pub fn expected(&self) -> &[u8] {
        &self.expected
    }

    #[must_use]
    pub fn replacement(&self) -> &[u8] {
        &self.replacement
    }

    fn command(&self) -> DebugCommand {
        DebugCommand::WriteMemory {
            stop: self.stop,
            address: self.address,
            expected: self.expected.clone(),
            replacement: self.replacement.clone(),
        }
    }

    fn reserved_history_bytes(&self) -> usize {
        match self.kind {
            LivePatchOperationKind::ForwardWrite => self.expected.len() + self.replacement.len(),
            LivePatchOperationKind::Undo => 0,
        }
    }
}

/// Structural reason that receipt evidence could not safely mutate history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivePatchReceiptMismatch {
    NonMonotonicCommandId {
        previous: CommandId,
        actual: CommandId,
    },
    SessionDrift,
    TargetDrift,
    EmptyReceipt,
    EventCorrelation,
    EventSession,
    CommandResultCount,
    CommandResultMismatch,
    CommandResultNotLast,
    DuplicateWriteEvidence,
    DuplicateFailureEvidence,
    WriteEvidenceMismatch,
    FailureEvidenceMismatch,
    StateEvidenceMismatch,
    ContradictoryWriteEvidence,
    MissingSuccessEvidence,
    FailureReportedAsSuccess,
    UnexpectedSuccessEffect,
    ReservedFailureCodeWithoutEvidence,
    RejectionProducedEffect,
    SafeFailureProducedStateChange,
    IndeterminateStateEvidenceMismatch,
}

/// Why mutation tracking became inspection-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivePatchFreezeCause {
    /// Dispatch began, but no exact host receipt is available.
    TransportOutcomeUnknown,
    /// The host proved that the target's post-write state is indeterminate.
    IndeterminateWrite(MemoryWriteFailure),
    /// Receipt/context evidence was not the exact evidence required.
    ReceiptMismatch(LivePatchReceiptMismatch),
}

/// Bounded evidence retained when further writes and undo are unsafe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePatchFreezeEvidence {
    pending: PendingLivePatchOperation,
    receipt_command_id: Option<CommandId>,
    cause: LivePatchFreezeCause,
}

impl LivePatchFreezeEvidence {
    #[must_use]
    pub const fn pending(&self) -> &PendingLivePatchOperation {
        &self.pending
    }

    #[must_use]
    pub const fn receipt_command_id(&self) -> Option<CommandId> {
        self.receipt_command_id
    }

    #[must_use]
    pub const fn cause(&self) -> &LivePatchFreezeCause {
        &self.cause
    }
}

/// Verified resolution of one pending live-patch operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivePatchResolution {
    ForwardCommitted(LivePatchEntry),
    UndoCommitted(LivePatchEntry),
    RejectedNoEffect,
    Frozen,
}

/// Pure reducer errors detected before dispatch or without receipt evidence.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LivePatchHistoryError {
    #[error("live patch history is frozen for inspection")]
    InspectionOnly,
    #[error("another live patch operation is already pending")]
    OperationPending,
    #[error("no live patch operation is pending")]
    NoPendingOperation,
    #[error("live patch operation was already marked for dispatch")]
    OperationAlreadyDispatched,
    #[error("live patch operation has not been marked for dispatch")]
    OperationNotDispatched,
    #[error("a dispatched live patch operation cannot be cancelled as pre-dispatch")]
    CannotCancelDispatched,
    #[error("live patch receipt {command_id:?} was already resolved")]
    DuplicateReceipt { command_id: CommandId },
    #[error("live patch receipt {received:?} precedes resolved receipt {last:?}")]
    OutOfOrderReceipt {
        last: CommandId,
        received: CommandId,
    },
    #[error("there is no committed live patch to undo")]
    NothingToUndo,
    #[error("live patch session differs from the immutable history session")]
    SessionDrift,
    #[error("live target binding differs from the immutable history target")]
    TargetDrift,
    #[error("stop token session differs from the immutable history session")]
    StopSessionDrift,
    #[error("stop token regressed or advanced generation and stop id inconsistently")]
    NonMonotonicStopToken,
    #[error("live patch bytes cannot be empty")]
    EmptyPatch,
    #[error("live patch before length {before} differs from after length {after}")]
    LengthMismatch { before: usize, after: usize },
    #[error("live patch replacement must differ from expected bytes")]
    UnchangedPatch,
    #[error("live patch is {actual} bytes; protocol maximum is {maximum}")]
    PatchTooLarge { actual: usize, maximum: usize },
    #[error("live patch span is outside the exact main-image binding: {0}")]
    InvalidImageSpan(#[from] LiveTargetBindingError),
    #[error("live patch history already contains {maximum} entries")]
    EntryLimit { maximum: usize },
    #[error("live patch history would retain {actual} bytes; maximum is {maximum}")]
    ByteLimit { actual: usize, maximum: usize },
}

/// Strict-LIFO history for one immutable session and concrete process binding.
///
/// Forward writes reserve entry/byte capacity before a command may be
/// dispatched. Only an exact successful receipt pushes or pops. There is no
/// eviction or redo path. Unknown or contradictory evidence permanently
/// freezes the reducer for inspection so it cannot guess target state.
/// The reducer is intentionally non-cloneable so reservation and dispatch
/// ownership remain linear.
#[derive(Debug, PartialEq, Eq)]
pub struct LivePatchHistory {
    session_id: SessionId,
    binding: LiveTargetBinding,
    entries: Vec<LivePatchEntry>,
    stored_bytes: usize,
    last_stop: Option<StopToken>,
    last_receipt_command_id: Option<CommandId>,
    pending: Option<PendingLivePatchOperation>,
    freeze_evidence: Option<LivePatchFreezeEvidence>,
}

impl LivePatchHistory {
    #[must_use]
    pub const fn new(session_id: SessionId, binding: LiveTargetBinding) -> Self {
        Self {
            session_id,
            binding,
            entries: Vec::new(),
            stored_bytes: 0,
            last_stop: None,
            last_receipt_command_id: None,
            pending: None,
            freeze_evidence: None,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn binding(&self) -> &LiveTargetBinding {
        &self.binding
    }

    #[must_use]
    pub fn entries(&self) -> &[LivePatchEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn stored_bytes(&self) -> usize {
        self.stored_bytes
    }

    /// Includes bytes retained by a pending or frozen forward write.
    #[must_use]
    pub fn reserved_bytes(&self) -> usize {
        let pending = self.pending.as_ref().or_else(|| {
            self.freeze_evidence
                .as_ref()
                .map(LivePatchFreezeEvidence::pending)
        });
        self.stored_bytes + pending.map_or(0, PendingLivePatchOperation::reserved_history_bytes)
    }

    #[must_use]
    pub const fn pending(&self) -> Option<&PendingLivePatchOperation> {
        self.pending.as_ref()
    }

    #[must_use]
    pub const fn freeze_evidence(&self) -> Option<&LivePatchFreezeEvidence> {
        self.freeze_evidence.as_ref()
    }

    #[must_use]
    pub const fn is_inspection_only(&self) -> bool {
        self.freeze_evidence.is_some()
    }

    /// Reserves one exact forward compare-before-write operation.
    pub fn begin_forward_write(
        &mut self,
        session_id: SessionId,
        binding: &LiveTargetBinding,
        stop: StopToken,
        address: MemoryAddress,
        before: Vec<u8>,
        after: Vec<u8>,
    ) -> Result<(), LivePatchHistoryError> {
        self.require_ready_context(session_id, binding, stop)?;
        Self::validate_patch_bytes(&before, &after)?;
        self.validate_image_span(address, before.len())?;
        if self.entries.len() >= MAX_LIVE_PATCH_HISTORY_ENTRIES {
            return Err(LivePatchHistoryError::EntryLimit {
                maximum: MAX_LIVE_PATCH_HISTORY_ENTRIES,
            });
        }
        let added = before.len() + after.len();
        let prospective =
            self.stored_bytes
                .checked_add(added)
                .ok_or(LivePatchHistoryError::ByteLimit {
                    actual: usize::MAX,
                    maximum: MAX_LIVE_PATCH_HISTORY_STORED_BYTES,
                })?;
        if prospective > MAX_LIVE_PATCH_HISTORY_STORED_BYTES {
            return Err(LivePatchHistoryError::ByteLimit {
                actual: prospective,
                maximum: MAX_LIVE_PATCH_HISTORY_STORED_BYTES,
            });
        }

        let pending = PendingLivePatchOperation {
            kind: LivePatchOperationKind::ForwardWrite,
            phase: LivePatchOperationPhase::Reserved,
            stop,
            address,
            expected: before,
            replacement: after,
        };
        self.last_stop = Some(stop);
        self.pending = Some(pending);
        Ok(())
    }

    /// Reserves a strict-LIFO undo using the caller's fresh current stop.
    pub fn begin_undo(
        &mut self,
        session_id: SessionId,
        binding: &LiveTargetBinding,
        current_stop: StopToken,
    ) -> Result<(), LivePatchHistoryError> {
        self.require_ready_context(session_id, binding, current_stop)?;
        let entry = self
            .entries
            .last()
            .ok_or(LivePatchHistoryError::NothingToUndo)?;
        self.validate_image_span(entry.address, entry.after.len())?;
        let pending = PendingLivePatchOperation {
            kind: LivePatchOperationKind::Undo,
            phase: LivePatchOperationPhase::Reserved,
            stop: current_stop,
            address: entry.address,
            expected: entry.after.clone(),
            replacement: entry.before.clone(),
        };
        self.last_stop = Some(current_stop);
        self.pending = Some(pending);
        Ok(())
    }

    /// Marks the reserved operation as dispatched and returns its exact command.
    ///
    /// This transition is single-use. Once it succeeds, cancellation is unsafe:
    /// the caller must resolve an exact receipt or freeze an unknown outcome.
    pub fn mark_for_dispatch(&mut self) -> Result<DebugCommand, LivePatchHistoryError> {
        if self.freeze_evidence.is_some() {
            return Err(LivePatchHistoryError::InspectionOnly);
        }
        let pending = self
            .pending
            .as_mut()
            .ok_or(LivePatchHistoryError::NoPendingOperation)?;
        if pending.phase == LivePatchOperationPhase::Dispatched {
            return Err(LivePatchHistoryError::OperationAlreadyDispatched);
        }
        pending.phase = LivePatchOperationPhase::Dispatched;
        Ok(pending.command())
    }

    /// Cancels a reservation only while dispatch is proven not to have begun.
    pub fn cancel_before_dispatch(&mut self) -> Result<(), LivePatchHistoryError> {
        if self.freeze_evidence.is_some() {
            return Err(LivePatchHistoryError::InspectionOnly);
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or(LivePatchHistoryError::NoPendingOperation)?;
        if pending.phase == LivePatchOperationPhase::Dispatched {
            return Err(LivePatchHistoryError::CannotCancelDispatched);
        }
        self.pending = None;
        Ok(())
    }

    /// Resolves a dispatched operation from one exact verified host receipt.
    ///
    /// Context drift or malformed/contradictory evidence freezes rather than
    /// discarding the pending operation because a target-side effect cannot be
    /// ruled out at this boundary.
    pub fn resolve_receipt(
        &mut self,
        session_id: SessionId,
        binding: &LiveTargetBinding,
        receipt: &CommandReceipt,
    ) -> Result<LivePatchResolution, LivePatchHistoryError> {
        if self.freeze_evidence.is_some() {
            return Err(LivePatchHistoryError::InspectionOnly);
        }
        if self.pending.is_none() {
            return match self.last_receipt_command_id {
                Some(last) if receipt.command_id == last => {
                    Err(LivePatchHistoryError::DuplicateReceipt {
                        command_id: receipt.command_id,
                    })
                }
                Some(last) if receipt.command_id < last => {
                    Err(LivePatchHistoryError::OutOfOrderReceipt {
                        last,
                        received: receipt.command_id,
                    })
                }
                _ => Err(LivePatchHistoryError::NoPendingOperation),
            };
        }
        if self.pending.as_ref().expect("pending checked above").phase
            != LivePatchOperationPhase::Dispatched
        {
            return Err(LivePatchHistoryError::OperationNotDispatched);
        }
        if session_id != self.session_id {
            return Ok(self.freeze(
                Some(receipt.command_id),
                LivePatchFreezeCause::ReceiptMismatch(LivePatchReceiptMismatch::SessionDrift),
            ));
        }
        if binding != &self.binding {
            return Ok(self.freeze(
                Some(receipt.command_id),
                LivePatchFreezeCause::ReceiptMismatch(LivePatchReceiptMismatch::TargetDrift),
            ));
        }
        if let Some(previous) = self.last_receipt_command_id {
            if receipt.command_id <= previous {
                return Ok(self.freeze(
                    Some(receipt.command_id),
                    LivePatchFreezeCause::ReceiptMismatch(
                        LivePatchReceiptMismatch::NonMonotonicCommandId {
                            previous,
                            actual: receipt.command_id,
                        },
                    ),
                ));
            }
        }

        let pending = self.pending.as_ref().expect("pending checked above");
        let scan = match ReceiptScan::inspect(self.session_id, pending, receipt) {
            Ok(scan) => scan,
            Err(mismatch) => {
                return Ok(self.freeze(
                    Some(receipt.command_id),
                    LivePatchFreezeCause::ReceiptMismatch(mismatch),
                ));
            }
        };

        match &receipt.outcome {
            CommandOutcome::Succeeded => {
                if scan.failure.is_some() {
                    return Ok(self.freeze(
                        Some(receipt.command_id),
                        LivePatchFreezeCause::ReceiptMismatch(
                            LivePatchReceiptMismatch::FailureReportedAsSuccess,
                        ),
                    ));
                }
                if scan.unexpected_effect {
                    return Ok(self.freeze(
                        Some(receipt.command_id),
                        LivePatchFreezeCause::ReceiptMismatch(
                            LivePatchReceiptMismatch::UnexpectedSuccessEffect,
                        ),
                    ));
                }
                if !scan.memory_written {
                    return Ok(self.freeze(
                        Some(receipt.command_id),
                        LivePatchFreezeCause::ReceiptMismatch(
                            LivePatchReceiptMismatch::MissingSuccessEvidence,
                        ),
                    ));
                }
                let Some(resulting_stop) = scan.success_stop(pending) else {
                    return Ok(self.freeze(
                        Some(receipt.command_id),
                        LivePatchFreezeCause::ReceiptMismatch(
                            LivePatchReceiptMismatch::UnexpectedSuccessEffect,
                        ),
                    ));
                };
                self.commit_success(receipt.command_id, resulting_stop)
            }
            CommandOutcome::Rejected { code, message } => {
                if scan.memory_written {
                    return Ok(self.freeze(
                        Some(receipt.command_id),
                        LivePatchFreezeCause::ReceiptMismatch(
                            LivePatchReceiptMismatch::ContradictoryWriteEvidence,
                        ),
                    ));
                }
                let Some(failure) = scan.failure else {
                    if code == MEMORY_WRITE_FAILURE_REJECTION_CODE {
                        return Ok(self.freeze(
                            Some(receipt.command_id),
                            LivePatchFreezeCause::ReceiptMismatch(
                                LivePatchReceiptMismatch::ReservedFailureCodeWithoutEvidence,
                            ),
                        ));
                    }
                    if scan.state_changes != 0
                        || scan.unexpected_effect
                        || scan.command_result_state != Some(pending.stop.state)
                    {
                        return Ok(self.freeze(
                            Some(receipt.command_id),
                            LivePatchFreezeCause::ReceiptMismatch(
                                LivePatchReceiptMismatch::RejectionProducedEffect,
                            ),
                        ));
                    }
                    self.clear_safe_rejection(receipt.command_id);
                    return Ok(LivePatchResolution::RejectedNoEffect);
                };

                if code != MEMORY_WRITE_FAILURE_REJECTION_CODE || message != &failure.detail {
                    return Ok(self.freeze(
                        Some(receipt.command_id),
                        LivePatchFreezeCause::ReceiptMismatch(
                            LivePatchReceiptMismatch::FailureEvidenceMismatch,
                        ),
                    ));
                }
                if scan.unexpected_effect {
                    return Ok(self.freeze(
                        Some(receipt.command_id),
                        LivePatchFreezeCause::ReceiptMismatch(
                            LivePatchReceiptMismatch::RejectionProducedEffect,
                        ),
                    ));
                }
                if failure.recovery.is_rollback_safe() {
                    if scan.state_changes != 0
                        || scan.command_result_state != Some(pending.stop.state)
                    {
                        return Ok(self.freeze(
                            Some(receipt.command_id),
                            LivePatchFreezeCause::ReceiptMismatch(
                                LivePatchReceiptMismatch::SafeFailureProducedStateChange,
                            ),
                        ));
                    }
                    self.clear_safe_rejection(receipt.command_id);
                    Ok(LivePatchResolution::RejectedNoEffect)
                } else if scan.indeterminate_state_evidence_matches(pending, failure) {
                    Ok(self.freeze(
                        Some(receipt.command_id),
                        LivePatchFreezeCause::IndeterminateWrite(failure.clone()),
                    ))
                } else {
                    Ok(self.freeze(
                        Some(receipt.command_id),
                        LivePatchFreezeCause::ReceiptMismatch(
                            LivePatchReceiptMismatch::IndeterminateStateEvidenceMismatch,
                        ),
                    ))
                }
            }
        }
    }

    /// Freezes a dispatched pending operation whose transport outcome is not
    /// backed by an exact [`CommandReceipt`].
    pub fn mark_transport_outcome_unknown(
        &mut self,
    ) -> Result<LivePatchResolution, LivePatchHistoryError> {
        self.require_dispatched_pending()?;
        Ok(self.freeze(None, LivePatchFreezeCause::TransportOutcomeUnknown))
    }

    fn require_ready_context(
        &self,
        session_id: SessionId,
        binding: &LiveTargetBinding,
        stop: StopToken,
    ) -> Result<(), LivePatchHistoryError> {
        if self.freeze_evidence.is_some() {
            return Err(LivePatchHistoryError::InspectionOnly);
        }
        if self.pending.is_some() {
            return Err(LivePatchHistoryError::OperationPending);
        }
        if session_id != self.session_id {
            return Err(LivePatchHistoryError::SessionDrift);
        }
        if binding != &self.binding {
            return Err(LivePatchHistoryError::TargetDrift);
        }
        if stop.state.session_id != self.session_id {
            return Err(LivePatchHistoryError::StopSessionDrift);
        }
        if let Some(previous) = self.last_stop {
            let generation_order = stop
                .state
                .generation
                .get()
                .cmp(&previous.state.generation.get());
            let stop_order = stop.stop_id.get().cmp(&previous.stop_id.get());
            let coherent = matches!(
                (generation_order, stop_order),
                (std::cmp::Ordering::Equal, std::cmp::Ordering::Equal)
                    | (std::cmp::Ordering::Greater, std::cmp::Ordering::Greater)
            );
            if !coherent {
                return Err(LivePatchHistoryError::NonMonotonicStopToken);
            }
        }
        Ok(())
    }

    fn require_dispatched_pending(&self) -> Result<(), LivePatchHistoryError> {
        if self.freeze_evidence.is_some() {
            Err(LivePatchHistoryError::InspectionOnly)
        } else {
            match self.pending.as_ref() {
                None => Err(LivePatchHistoryError::NoPendingOperation),
                Some(pending) if pending.phase == LivePatchOperationPhase::Reserved => {
                    Err(LivePatchHistoryError::OperationNotDispatched)
                }
                Some(_) => Ok(()),
            }
        }
    }

    fn validate_patch_bytes(before: &[u8], after: &[u8]) -> Result<(), LivePatchHistoryError> {
        if before.is_empty() {
            return Err(LivePatchHistoryError::EmptyPatch);
        }
        if before.len() != after.len() {
            return Err(LivePatchHistoryError::LengthMismatch {
                before: before.len(),
                after: after.len(),
            });
        }
        if before == after {
            return Err(LivePatchHistoryError::UnchangedPatch);
        }
        if before.len() > MAX_MEMORY_WRITE_BYTES {
            return Err(LivePatchHistoryError::PatchTooLarge {
                actual: before.len(),
                maximum: MAX_MEMORY_WRITE_BYTES,
            });
        }
        Ok(())
    }

    fn validate_image_span(
        &self,
        address: MemoryAddress,
        size: usize,
    ) -> Result<(), LivePatchHistoryError> {
        let size = u64::try_from(size).map_err(|_| {
            LivePatchHistoryError::InvalidImageSpan(LiveTargetBindingError::AddressSpanOverflow {
                address: address.get(),
                size: u64::MAX,
            })
        })?;
        self.binding.rva_for_address_span(address, size)?;
        Ok(())
    }

    fn clear_safe_rejection(&mut self, command_id: CommandId) {
        self.last_receipt_command_id = Some(command_id);
        let pending = self
            .pending
            .take()
            .expect("pending checked before rejection");
        self.last_stop = Some(pending.stop);
    }

    fn commit_success(
        &mut self,
        command_id: CommandId,
        resulting_stop: StopToken,
    ) -> Result<LivePatchResolution, LivePatchHistoryError> {
        let pending = self.pending.take().expect("pending checked before commit");
        self.last_receipt_command_id = Some(command_id);
        self.last_stop = Some(resulting_stop);
        match pending.kind {
            LivePatchOperationKind::ForwardWrite => {
                let entry = LivePatchEntry {
                    address: pending.address,
                    before: pending.expected,
                    after: pending.replacement,
                    applied_stop: pending.stop,
                    resulting_stop,
                    command_id,
                };
                self.stored_bytes += entry.stored_bytes();
                self.entries.push(entry.clone());
                Ok(LivePatchResolution::ForwardCommitted(entry))
            }
            LivePatchOperationKind::Undo => {
                let entry = self
                    .entries
                    .pop()
                    .expect("undo reservation requires a history entry");
                debug_assert_eq!(entry.address, pending.address);
                debug_assert_eq!(entry.after, pending.expected);
                debug_assert_eq!(entry.before, pending.replacement);
                self.stored_bytes -= entry.stored_bytes();
                Ok(LivePatchResolution::UndoCommitted(entry))
            }
        }
    }

    fn freeze(
        &mut self,
        receipt_command_id: Option<CommandId>,
        cause: LivePatchFreezeCause,
    ) -> LivePatchResolution {
        let pending = self.pending.take().expect("pending checked before freeze");
        self.freeze_evidence = Some(LivePatchFreezeEvidence {
            pending,
            receipt_command_id,
            cause,
        });
        LivePatchResolution::Frozen
    }
}

struct ReceiptScan<'a> {
    memory_written: bool,
    failure: Option<&'a MemoryWriteFailure>,
    state_changes: usize,
    states: Vec<&'a SessionState>,
    command_result_state: Option<StateToken>,
    unexpected_effect: bool,
}

impl<'a> ReceiptScan<'a> {
    fn inspect(
        session_id: SessionId,
        pending: &PendingLivePatchOperation,
        receipt: &'a CommandReceipt,
    ) -> Result<Self, LivePatchReceiptMismatch> {
        if receipt.events.is_empty() {
            return Err(LivePatchReceiptMismatch::EmptyReceipt);
        }
        let mut memory_written = false;
        let mut failure = None;
        let mut command_results = 0_usize;
        let mut result_index = None;
        let mut state_changes = 0_usize;
        let mut states = Vec::new();
        let mut command_result_state = None;
        let mut unexpected_effect = false;

        for (index, envelope) in receipt.events.iter().enumerate() {
            if envelope.caused_by != Some(receipt.command_id) {
                return Err(LivePatchReceiptMismatch::EventCorrelation);
            }
            if envelope.session_id != Some(session_id) {
                return Err(LivePatchReceiptMismatch::EventSession);
            }
            match &envelope.event {
                DebugEvent::CommandResult {
                    command_id,
                    outcome,
                } => {
                    command_results += 1;
                    result_index = Some(index);
                    command_result_state = envelope.state;
                    if *command_id != receipt.command_id || outcome != &receipt.outcome {
                        return Err(LivePatchReceiptMismatch::CommandResultMismatch);
                    }
                }
                DebugEvent::MemoryWritten {
                    stop,
                    address,
                    before,
                    after,
                } => {
                    if memory_written {
                        return Err(LivePatchReceiptMismatch::DuplicateWriteEvidence);
                    }
                    if *stop != pending.stop
                        || *address != pending.address
                        || before != &pending.expected
                        || after != &pending.replacement
                        || envelope.state != Some(pending.stop.state)
                    {
                        return Err(LivePatchReceiptMismatch::WriteEvidenceMismatch);
                    }
                    memory_written = true;
                }
                DebugEvent::MemoryWriteFailed(actual) => {
                    if failure.is_some() {
                        return Err(LivePatchReceiptMismatch::DuplicateFailureEvidence);
                    }
                    if actual.stop != pending.stop
                        || actual.address != pending.address
                        || usize::try_from(actual.size).ok() != Some(pending.expected.len())
                        || envelope.state != Some(pending.stop.state)
                        || actual.validate().is_err()
                    {
                        return Err(LivePatchReceiptMismatch::FailureEvidenceMismatch);
                    }
                    failure = Some(actual);
                }
                DebugEvent::StateChanged(state) => {
                    if envelope.state != Some(state.state_token()) {
                        return Err(LivePatchReceiptMismatch::StateEvidenceMismatch);
                    }
                    state_changes += 1;
                    states.push(state);
                }
                DebugEvent::Warning { .. } => {}
                DebugEvent::Capabilities(_)
                | DebugEvent::LiveTargetBound { .. }
                | DebugEvent::MemoryRead { .. }
                | DebugEvent::BreakpointChanged { .. }
                | DebugEvent::SandboxAttested(_)
                | DebugEvent::SandboxLifecycle(_) => unexpected_effect = true,
            }
        }

        if command_results != 1 {
            return Err(LivePatchReceiptMismatch::CommandResultCount);
        }
        if result_index != Some(receipt.events.len() - 1) {
            return Err(LivePatchReceiptMismatch::CommandResultNotLast);
        }
        Ok(Self {
            memory_written,
            failure,
            state_changes,
            states,
            command_result_state,
            unexpected_effect,
        })
    }

    fn indeterminate_state_evidence_matches(
        &self,
        pending: &PendingLivePatchOperation,
        failure: &MemoryWriteFailure,
    ) -> bool {
        let [
            SessionState::Stopped {
                token: refreshed, ..
            },
            SessionState::Failed { token, message },
        ] = self.states.as_slice()
        else {
            return false;
        };
        refreshed.state.session_id == pending.stop.state.session_id
            && pending.stop.state.generation.get().checked_add(1)
                == Some(refreshed.state.generation.get())
            && pending.stop.stop_id.get().checked_add(1) == Some(refreshed.stop_id.get())
            && token.session_id == pending.stop.state.session_id
            && refreshed.state.generation.get().checked_add(1) == Some(token.generation.get())
            && self.command_result_state == Some(*token)
            && message == &failure.detail
    }

    fn success_stop(&self, pending: &PendingLivePatchOperation) -> Option<StopToken> {
        let [SessionState::Stopped { token, .. }] = self.states.as_slice() else {
            return None;
        };
        (token.state.session_id == pending.stop.state.session_id
            && pending.stop.state.generation.get().checked_add(1)
                == Some(token.state.generation.get())
            && pending.stop.stop_id.get().checked_add(1) == Some(token.stop_id.get())
            && self.command_result_state == Some(token.state))
        .then_some(*token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EventEnvelope, EventSequence, MemoryWriteRecovery, MemoryWriteStage, ProcessId,
        ProcessIdentity, ProcessStartKey, ProtocolVersion, StateGeneration, StopId, StopReason,
        ThreadId,
    };
    use resymbol_core::BinaryId;

    fn session_id() -> SessionId {
        SessionId::new(7).expect("session id")
    }

    fn binding(start_key: u64) -> LiveTargetBinding {
        let binary_id = BinaryId::digest(b"live-patch-history-fixture");
        LiveTargetBinding::new(
            ProcessIdentity {
                process_id: ProcessId::new(42).expect("process id"),
                start_key: ProcessStartKey::new(start_key).expect("start key"),
                binary_id: binary_id.clone(),
            },
            binary_id,
            MemoryAddress::new(0x0001_4000_0000),
            0x20_0000,
        )
        .expect("binding")
    }

    fn stop(generation: u64, stop_id: u64) -> StopToken {
        StopToken {
            state: StateToken {
                session_id: session_id(),
                generation: StateGeneration::new(generation).expect("generation"),
            },
            stop_id: StopId::new(stop_id).expect("stop id"),
        }
    }

    fn address(offset: u64) -> MemoryAddress {
        MemoryAddress::new(0x0001_4000_0000 + offset)
    }

    fn successor_stop(prior: StopToken) -> StopToken {
        StopToken {
            state: StateToken {
                session_id: prior.state.session_id,
                generation: StateGeneration::new(prior.state.generation.get() + 1)
                    .expect("successor generation"),
            },
            stop_id: StopId::new(prior.stop_id.get() + 1).expect("successor stop id"),
        }
    }

    fn event(
        sequence: u64,
        command_id: CommandId,
        state: StateToken,
        event: DebugEvent,
    ) -> EventEnvelope {
        EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: EventSequence::new(sequence).expect("event sequence"),
            session_id: Some(session_id()),
            state: Some(state),
            caused_by: Some(command_id),
            event,
        }
    }

    fn success_receipt(command_id: u64, pending: &PendingLivePatchOperation) -> CommandReceipt {
        let command_id = CommandId::new(command_id).expect("command id");
        let resulting_stop = successor_stop(pending.stop);
        CommandReceipt {
            command_id,
            outcome: CommandOutcome::Succeeded,
            events: vec![
                event(
                    1,
                    command_id,
                    pending.stop.state,
                    DebugEvent::MemoryWritten {
                        stop: pending.stop,
                        address: pending.address,
                        before: pending.expected.clone(),
                        after: pending.replacement.clone(),
                    },
                ),
                event(
                    2,
                    command_id,
                    resulting_stop.state,
                    DebugEvent::StateChanged(SessionState::Stopped {
                        token: resulting_stop,
                        reason: StopReason::Initial,
                        thread_id: ThreadId::new(11).expect("thread id"),
                    }),
                ),
                event(
                    3,
                    command_id,
                    resulting_stop.state,
                    DebugEvent::CommandResult {
                        command_id,
                        outcome: CommandOutcome::Succeeded,
                    },
                ),
            ],
        }
    }

    fn rejection_receipt(
        command_id: u64,
        pending: &PendingLivePatchOperation,
        failure: Option<MemoryWriteFailure>,
    ) -> CommandReceipt {
        let command_id = CommandId::new(command_id).expect("command id");
        let outcome = failure.as_ref().map_or_else(
            || CommandOutcome::Rejected {
                code: "write-conflict".to_owned(),
                message: "expected bytes changed".to_owned(),
            },
            |failure| CommandOutcome::Rejected {
                code: MEMORY_WRITE_FAILURE_REJECTION_CODE.to_owned(),
                message: failure.detail.clone(),
            },
        );
        let mut events = Vec::new();
        if let Some(failure) = failure {
            events.push(event(
                1,
                command_id,
                pending.stop.state,
                DebugEvent::MemoryWriteFailed(failure),
            ));
        }
        events.push(event(
            4,
            command_id,
            pending.stop.state,
            DebugEvent::CommandResult {
                command_id,
                outcome: outcome.clone(),
            },
        ));
        CommandReceipt {
            command_id,
            outcome,
            events,
        }
    }

    fn begin(history: &mut LivePatchHistory, binding: &LiveTargetBinding, stop: StopToken) {
        history
            .begin_forward_write(
                session_id(),
                binding,
                stop,
                address(0x100),
                vec![0x75, 0x05],
                vec![0x74, 0x05],
            )
            .expect("begin forward write");
    }

    fn dispatch(history: &mut LivePatchHistory) -> DebugCommand {
        history.mark_for_dispatch().expect("mark for dispatch")
    }

    fn commit(
        history: &mut LivePatchHistory,
        binding: &LiveTargetBinding,
        command_id: u64,
    ) -> LivePatchResolution {
        if history.pending().expect("pending").phase() == LivePatchOperationPhase::Reserved {
            dispatch(history);
        }
        let receipt = success_receipt(command_id, history.pending().expect("pending"));
        history
            .resolve_receipt(session_id(), binding, &receipt)
            .expect("resolve receipt")
    }

    #[test]
    fn forward_success_pushes_only_after_exact_receipt() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(3, 1));
        assert!(history.entries().is_empty());
        assert_eq!(history.stored_bytes(), 0);
        assert_eq!(history.reserved_bytes(), 4);

        let result = commit(&mut history, &binding, 9);
        let LivePatchResolution::ForwardCommitted(entry) = result else {
            panic!("forward write did not commit")
        };
        assert_eq!(entry.before(), [0x75, 0x05]);
        assert_eq!(entry.after(), [0x74, 0x05]);
        assert_eq!(entry.resulting_stop(), stop(4, 2));
        assert_eq!(entry.command_id().get(), 9);
        assert_eq!(history.entries(), &[entry]);
        assert_eq!(history.stored_bytes(), 4);
        assert!(history.pending().is_none());
    }

    #[test]
    fn reserved_operation_can_cancel_or_dispatch_exactly_once() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(7, 4));
        assert_eq!(
            history.pending().expect("reserved").phase(),
            LivePatchOperationPhase::Reserved
        );
        assert_eq!(history.cancel_before_dispatch(), Ok(()));
        assert!(history.pending().is_none());
        assert_eq!(
            history.mark_for_dispatch(),
            Err(LivePatchHistoryError::NoPendingOperation)
        );
        assert_eq!(
            history.begin_forward_write(
                session_id(),
                &binding,
                stop(5, 3),
                address(0x100),
                vec![0x75, 0x05],
                vec![0x74, 0x05],
            ),
            Err(LivePatchHistoryError::NonMonotonicStopToken)
        );

        begin(&mut history, &binding, stop(7, 4));
        assert_eq!(
            dispatch(&mut history),
            DebugCommand::WriteMemory {
                stop: stop(7, 4),
                address: address(0x100),
                expected: vec![0x75, 0x05],
                replacement: vec![0x74, 0x05],
            }
        );
        assert_eq!(
            history.pending().expect("dispatched").phase(),
            LivePatchOperationPhase::Dispatched
        );
        assert_eq!(
            history.mark_for_dispatch(),
            Err(LivePatchHistoryError::OperationAlreadyDispatched)
        );
        assert_eq!(
            history.cancel_before_dispatch(),
            Err(LivePatchHistoryError::CannotCancelDispatched)
        );
    }

    #[test]
    fn receipt_and_unknown_transport_require_dispatch() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(3, 1));
        let receipt = success_receipt(4, history.pending().expect("pending"));
        assert_eq!(
            history.resolve_receipt(session_id(), &binding, &receipt),
            Err(LivePatchHistoryError::OperationNotDispatched)
        );
        assert_eq!(
            history.mark_transport_outcome_unknown(),
            Err(LivePatchHistoryError::OperationNotDispatched)
        );
        dispatch(&mut history);
        assert!(matches!(
            history.resolve_receipt(session_id(), &binding, &receipt),
            Ok(LivePatchResolution::ForwardCommitted(_))
        ));
    }

    #[test]
    fn undo_is_strict_lifo_and_uses_the_fresh_stop() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(3, 1));
        commit(&mut history, &binding, 2);
        history
            .begin_forward_write(
                session_id(),
                &binding,
                stop(4, 2),
                address(0x200),
                vec![0x90],
                vec![0xcc],
            )
            .expect("second forward write");
        commit(&mut history, &binding, 4);

        let fresh = stop(7, 4);
        history
            .begin_undo(session_id(), &binding, fresh)
            .expect("begin undo");
        let command = dispatch(&mut history);
        assert_eq!(
            command,
            DebugCommand::WriteMemory {
                stop: fresh,
                address: address(0x200),
                expected: vec![0xcc],
                replacement: vec![0x90],
            }
        );
        let result = commit(&mut history, &binding, 8);
        let LivePatchResolution::UndoCommitted(undone) = result else {
            panic!("undo did not commit")
        };
        assert_eq!(undone.address(), address(0x200));
        assert_eq!(history.entries().len(), 1);
        assert_eq!(history.entries()[0].address(), address(0x100));
    }

    #[test]
    fn overlapping_writes_undo_in_byte_layer_order() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        history
            .begin_forward_write(
                session_id(),
                &binding,
                stop(3, 1),
                address(0x300),
                vec![0xaa, 0xbb],
                vec![0xcc, 0xdd],
            )
            .expect("first byte layer");
        commit(&mut history, &binding, 1);
        history
            .begin_forward_write(
                session_id(),
                &binding,
                stop(4, 2),
                address(0x300),
                vec![0xcc, 0xdd],
                vec![0xee, 0xff],
            )
            .expect("second byte layer");
        commit(&mut history, &binding, 2);

        history
            .begin_undo(session_id(), &binding, stop(5, 3))
            .expect("undo second layer");
        assert_eq!(
            dispatch(&mut history),
            DebugCommand::WriteMemory {
                stop: stop(5, 3),
                address: address(0x300),
                expected: vec![0xee, 0xff],
                replacement: vec![0xcc, 0xdd],
            }
        );
        commit(&mut history, &binding, 3);
        history
            .begin_undo(session_id(), &binding, stop(6, 4))
            .expect("undo first layer");
        assert_eq!(
            dispatch(&mut history),
            DebugCommand::WriteMemory {
                stop: stop(6, 4),
                address: address(0x300),
                expected: vec![0xcc, 0xdd],
                replacement: vec![0xaa, 0xbb],
            }
        );
    }

    #[test]
    fn failed_undo_retains_the_top_entry() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(3, 1));
        commit(&mut history, &binding, 2);
        history
            .begin_undo(session_id(), &binding, stop(4, 2))
            .expect("begin undo");
        dispatch(&mut history);
        let receipt = rejection_receipt(3, history.pending().expect("pending"), None);
        assert_eq!(
            history.resolve_receipt(session_id(), &binding, &receipt),
            Ok(LivePatchResolution::RejectedNoEffect)
        );
        assert_eq!(history.entries().len(), 1);
        assert_eq!(history.stored_bytes(), 4);
    }

    #[test]
    fn safe_failure_clears_pending_without_changing_history() {
        let binding = binding(100);
        for (stage, recovery) in [
            (
                MemoryWriteStage::ChangeProtection,
                MemoryWriteRecovery::NoWriteAttempted {
                    protection_restored: true,
                },
            ),
            (
                MemoryWriteStage::WriteReplacement,
                MemoryWriteRecovery::Restored,
            ),
        ] {
            let mut history = LivePatchHistory::new(session_id(), binding.clone());
            begin(&mut history, &binding, stop(3, 1));
            dispatch(&mut history);
            let pending = history.pending().expect("pending");
            let failure = MemoryWriteFailure {
                stop: pending.stop,
                address: pending.address,
                size: 2,
                stage,
                recovery,
                detail: "original state proved unchanged or restored".to_owned(),
            };
            let receipt = rejection_receipt(5, pending, Some(failure));
            assert_eq!(
                history.resolve_receipt(session_id(), &binding, &receipt),
                Ok(LivePatchResolution::RejectedNoEffect)
            );
            assert!(history.entries().is_empty());
            assert!(!history.is_inspection_only());
        }
    }

    #[test]
    fn indeterminate_failure_freezes_with_pending_evidence() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(3, 1));
        dispatch(&mut history);
        let pending = history.pending().expect("pending");
        let failure = MemoryWriteFailure {
            stop: pending.stop,
            address: pending.address,
            size: 2,
            stage: MemoryWriteStage::FlushReplacement,
            recovery: MemoryWriteRecovery::Indeterminate {
                bytes_restored: false,
                instruction_cache_flushed: false,
                protection_restored: true,
            },
            detail: "instruction cache state is unknown".to_owned(),
        };
        let mut receipt = rejection_receipt(5, pending, Some(failure.clone()));
        let refreshed = stop(4, 2);
        let failed_state = StateToken {
            session_id: session_id(),
            generation: StateGeneration::new(5).expect("failed generation"),
        };
        let mut result = receipt.events.pop().expect("command result");
        result.state = Some(failed_state);
        receipt.events.push(event(
            2,
            receipt.command_id,
            refreshed.state,
            DebugEvent::StateChanged(SessionState::Stopped {
                token: refreshed,
                reason: StopReason::Initial,
                thread_id: ThreadId::new(11).expect("thread id"),
            }),
        ));
        receipt.events.push(event(
            3,
            receipt.command_id,
            failed_state,
            DebugEvent::StateChanged(SessionState::Failed {
                token: failed_state,
                message: failure.detail.clone(),
            }),
        ));
        receipt.events.push(result);

        assert_eq!(
            history.resolve_receipt(session_id(), &binding, &receipt),
            Ok(LivePatchResolution::Frozen)
        );
        let evidence = history.freeze_evidence().expect("freeze evidence");
        assert_eq!(
            evidence.cause(),
            &LivePatchFreezeCause::IndeterminateWrite(failure)
        );
        assert_eq!(evidence.pending().expected(), [0x75, 0x05]);
        assert!(history.entries().is_empty());
        assert_eq!(
            history.begin_undo(session_id(), &binding, stop(6, 3)),
            Err(LivePatchHistoryError::InspectionOnly)
        );
    }

    #[test]
    fn unknown_transport_freezes_without_guessing() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(3, 1));
        dispatch(&mut history);
        assert_eq!(
            history.mark_transport_outcome_unknown(),
            Ok(LivePatchResolution::Frozen)
        );
        let evidence = history.freeze_evidence().expect("freeze evidence");
        assert_eq!(
            evidence.cause(),
            &LivePatchFreezeCause::TransportOutcomeUnknown
        );
        assert_eq!(evidence.receipt_command_id(), None);
        assert_eq!(history.reserved_bytes(), 4);
    }

    #[test]
    fn mismatched_success_evidence_freezes() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(3, 1));
        dispatch(&mut history);
        let mut receipt = success_receipt(4, history.pending().expect("pending"));
        let DebugEvent::MemoryWritten { after, .. } = &mut receipt.events[0].event else {
            panic!("write evidence")
        };
        after[0] ^= 1;
        assert_eq!(
            history.resolve_receipt(session_id(), &binding, &receipt),
            Ok(LivePatchResolution::Frozen)
        );
        assert!(matches!(
            history.freeze_evidence().expect("freeze evidence").cause(),
            LivePatchFreezeCause::ReceiptMismatch(LivePatchReceiptMismatch::WriteEvidenceMismatch)
        ));
    }

    #[test]
    fn duplicate_and_out_of_order_receipts_are_rejected() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(3, 1));
        dispatch(&mut history);
        let receipt = success_receipt(8, history.pending().expect("pending"));
        history
            .resolve_receipt(session_id(), &binding, &receipt)
            .expect("first receipt");
        assert_eq!(
            history.resolve_receipt(session_id(), &binding, &receipt),
            Err(LivePatchHistoryError::DuplicateReceipt {
                command_id: receipt.command_id,
            })
        );
        let mut older = receipt.clone();
        older.command_id = CommandId::new(7).expect("older command id");
        assert_eq!(
            history.resolve_receipt(session_id(), &binding, &older),
            Err(LivePatchHistoryError::OutOfOrderReceipt {
                last: receipt.command_id,
                received: older.command_id,
            })
        );

        history
            .begin_undo(session_id(), &binding, stop(4, 2))
            .expect("begin undo");
        dispatch(&mut history);
        let replay = success_receipt(8, history.pending().expect("pending"));
        assert_eq!(
            history.resolve_receipt(session_id(), &binding, &replay),
            Ok(LivePatchResolution::Frozen)
        );
        assert!(matches!(
            history.freeze_evidence().expect("freeze evidence").cause(),
            LivePatchFreezeCause::ReceiptMismatch(
                LivePatchReceiptMismatch::NonMonotonicCommandId { .. }
            )
        ));
    }

    #[test]
    fn session_target_and_new_process_drift_are_rejected() {
        let current_binding = binding(100);
        let replacement_process = binding(101);
        assert_eq!(
            current_binding.main_module_binary_id(),
            replacement_process.main_module_binary_id()
        );
        let mut history = LivePatchHistory::new(session_id(), current_binding.clone());
        assert_eq!(
            history.begin_forward_write(
                SessionId::new(8).expect("other session"),
                &current_binding,
                stop(3, 1),
                address(0x100),
                vec![1],
                vec![2],
            ),
            Err(LivePatchHistoryError::SessionDrift)
        );
        assert_eq!(
            history.begin_forward_write(
                session_id(),
                &replacement_process,
                stop(3, 1),
                address(0x100),
                vec![1],
                vec![2],
            ),
            Err(LivePatchHistoryError::TargetDrift)
        );
        let wrong_stop = StopToken {
            state: StateToken {
                session_id: SessionId::new(8).expect("other session"),
                generation: StateGeneration::new(3).expect("generation"),
            },
            stop_id: StopId::new(1).expect("stop id"),
        };
        assert_eq!(
            history.begin_forward_write(
                session_id(),
                &current_binding,
                wrong_stop,
                address(0x100),
                vec![1],
                vec![2],
            ),
            Err(LivePatchHistoryError::StopSessionDrift)
        );
    }

    #[test]
    fn resolve_context_drift_freezes_the_dispatched_operation() {
        let current_binding = binding(100);
        let replacement_process = binding(101);
        let mut history = LivePatchHistory::new(session_id(), current_binding.clone());
        begin(&mut history, &current_binding, stop(3, 1));
        dispatch(&mut history);
        let receipt = success_receipt(4, history.pending().expect("pending"));
        assert_eq!(
            history.resolve_receipt(session_id(), &replacement_process, &receipt),
            Ok(LivePatchResolution::Frozen)
        );
        assert_eq!(
            history.freeze_evidence().expect("freeze evidence").cause(),
            &LivePatchFreezeCause::ReceiptMismatch(LivePatchReceiptMismatch::TargetDrift)
        );
    }

    #[test]
    fn patch_validation_is_fail_closed() {
        let binding = binding(100);
        let make = || LivePatchHistory::new(session_id(), binding.clone());
        let mut empty = make();
        assert_eq!(
            empty.begin_forward_write(
                session_id(),
                &binding,
                stop(3, 1),
                address(0x100),
                Vec::new(),
                Vec::new(),
            ),
            Err(LivePatchHistoryError::EmptyPatch)
        );
        let mut mismatch = make();
        assert_eq!(
            mismatch.begin_forward_write(
                session_id(),
                &binding,
                stop(3, 1),
                address(0x100),
                vec![1],
                vec![2, 3],
            ),
            Err(LivePatchHistoryError::LengthMismatch {
                before: 1,
                after: 2,
            })
        );
        let mut unchanged = make();
        assert_eq!(
            unchanged.begin_forward_write(
                session_id(),
                &binding,
                stop(3, 1),
                address(0x100),
                vec![1],
                vec![1],
            ),
            Err(LivePatchHistoryError::UnchangedPatch)
        );
        let mut oversized = make();
        assert!(matches!(
            oversized.begin_forward_write(
                session_id(),
                &binding,
                stop(3, 1),
                address(0x100),
                vec![1; MAX_MEMORY_WRITE_BYTES + 1],
                vec![2; MAX_MEMORY_WRITE_BYTES + 1],
            ),
            Err(LivePatchHistoryError::PatchTooLarge { .. })
        ));
        let mut outside = make();
        assert!(matches!(
            outside.begin_forward_write(
                session_id(),
                &binding,
                stop(3, 1),
                binding.image_end(),
                vec![1],
                vec![2],
            ),
            Err(LivePatchHistoryError::InvalidImageSpan(_))
        ));
    }

    #[test]
    fn one_pending_operation_is_enforced() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(3, 1));
        assert_eq!(
            history.begin_forward_write(
                session_id(),
                &binding,
                stop(3, 1),
                address(0x200),
                vec![1],
                vec![2],
            ),
            Err(LivePatchHistoryError::OperationPending)
        );
    }

    #[test]
    fn stop_tokens_may_repeat_but_cannot_regress_or_advance_halfway() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        begin(&mut history, &binding, stop(5, 3));
        dispatch(&mut history);
        let receipt = rejection_receipt(2, history.pending().expect("pending"), None);
        history
            .resolve_receipt(session_id(), &binding, &receipt)
            .expect("safe rejection");

        begin(&mut history, &binding, stop(5, 3));
        dispatch(&mut history);
        let receipt = rejection_receipt(3, history.pending().expect("pending"), None);
        history
            .resolve_receipt(session_id(), &binding, &receipt)
            .expect("same-stop rejection");

        assert_eq!(
            history.begin_forward_write(
                session_id(),
                &binding,
                stop(4, 2),
                address(0x100),
                vec![1],
                vec![2],
            ),
            Err(LivePatchHistoryError::NonMonotonicStopToken)
        );
        assert_eq!(
            history.begin_forward_write(
                session_id(),
                &binding,
                stop(6, 3),
                address(0x100),
                vec![1],
                vec![2],
            ),
            Err(LivePatchHistoryError::NonMonotonicStopToken)
        );
    }

    #[test]
    fn entry_limit_reserves_without_evicting() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        for index in 0..MAX_LIVE_PATCH_HISTORY_ENTRIES {
            history
                .begin_forward_write(
                    session_id(),
                    &binding,
                    stop(index as u64 + 3, index as u64 + 1),
                    address(0x100 + index as u64),
                    vec![0],
                    vec![1],
                )
                .expect("bounded forward write");
            commit(&mut history, &binding, index as u64 + 1);
        }
        assert_eq!(history.entries().len(), MAX_LIVE_PATCH_HISTORY_ENTRIES);
        assert!(matches!(
            history.begin_forward_write(
                session_id(),
                &binding,
                stop(
                    MAX_LIVE_PATCH_HISTORY_ENTRIES as u64 + 3,
                    MAX_LIVE_PATCH_HISTORY_ENTRIES as u64 + 1,
                ),
                address(0x500),
                vec![0],
                vec![1],
            ),
            Err(LivePatchHistoryError::EntryLimit { .. })
        ));
        assert_eq!(history.entries().len(), MAX_LIVE_PATCH_HISTORY_ENTRIES);
    }

    #[test]
    fn byte_limit_is_reserved_before_dispatch_without_eviction() {
        let binding = binding(100);
        let mut history = LivePatchHistory::new(session_id(), binding.clone());
        for index in 0..8_u64 {
            history
                .begin_forward_write(
                    session_id(),
                    &binding,
                    stop(index + 3, index + 1),
                    address(0x1000 + index * 0x1_0000),
                    vec![index as u8; MAX_MEMORY_WRITE_BYTES],
                    vec![index as u8 + 1; MAX_MEMORY_WRITE_BYTES],
                )
                .expect("bounded forward write");
            assert!(history.reserved_bytes() <= MAX_LIVE_PATCH_HISTORY_STORED_BYTES);
            commit(&mut history, &binding, index + 1);
        }
        assert_eq!(history.stored_bytes(), MAX_LIVE_PATCH_HISTORY_STORED_BYTES);
        assert!(matches!(
            history.begin_forward_write(
                session_id(),
                &binding,
                stop(11, 9),
                address(0x100),
                vec![1],
                vec![2],
            ),
            Err(LivePatchHistoryError::ByteLimit { .. })
        ));
        assert_eq!(history.entries().len(), 8);
    }
}
