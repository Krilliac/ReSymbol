//! Transactional planning for backend-owned x86 software breakpoints.
//!
//! This module never reads or writes target memory and never drives execution.
//! It only produces exact one-byte compare/replace plans and advances its
//! acknowledged lifecycle after a caller reports exact success. The caller owns
//! the debugger backend and is responsible for proving that report.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::{
    BreakpointId, BreakpointKind, BreakpointSpec, MemoryAddress, ProtocolValidationError,
    SessionId, StopToken,
};

/// The x86/x64 one-byte `INT3` opcode used by software breakpoints.
pub const INT3_OPCODE: u8 = 0xcc;

/// Hard upper bound for breakpoints retained by one state machine.
pub const MAX_SOFTWARE_BREAKPOINTS: usize = 1_024;

/// Whether a breakpoint survives its first acknowledged hit restoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareBreakpointPersistence {
    /// Restore for one externally driven single step, then rearm.
    Persistent,
    /// Restore and forget the breakpoint after its first acknowledged hit.
    Temporary,
}

/// Monotonic identity for one planned byte operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SoftwareBreakpointOperationId(u64);

impl SoftwareBreakpointOperationId {
    /// Constructs an operation identity. Zero is never valid.
    pub fn new(value: u64) -> Result<Self, SoftwareBreakpointOperationIdError> {
        if value == 0 {
            Err(SoftwareBreakpointOperationIdError)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the underlying nonzero value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Error returned for a zero software-breakpoint operation identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("software-breakpoint operation identifier must be nonzero")]
pub struct SoftwareBreakpointOperationIdError;

/// The lifecycle meaning of an exact byte action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareBreakpointAction {
    /// Install `INT3` over the exact original byte.
    Arm,
    /// Restore the original byte after a breakpoint hit.
    Restore,
    /// Install `INT3` again after an externally acknowledged single-step stop.
    Rearm,
    /// Restore the original byte while explicitly removing a breakpoint.
    Remove,
}

/// Exact compare/replace material shared by every action plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareBreakpointBytePlan {
    /// Unique operation identity allocated by this state machine.
    pub operation_id: SoftwareBreakpointOperationId,
    /// Session that owns the breakpoint.
    pub session_id: SessionId,
    /// Exact stopped-state token under which the operation was planned.
    pub stop_token: StopToken,
    /// Complete software-breakpoint specification.
    pub breakpoint: BreakpointSpec,
    /// Byte that the backend must compare before replacing.
    pub expected_byte: u8,
    /// Byte that the backend may write only after the comparison succeeds.
    pub replacement_byte: u8,
}

/// One exact backend action requested by the pure state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareBreakpointActionPlan {
    /// Initial `original -> INT3` plan.
    Arm(SoftwareBreakpointBytePlan),
    /// Hit-time `INT3 -> original` plan.
    Restore(SoftwareBreakpointBytePlan),
    /// Post-single-step `original -> INT3` plan.
    Rearm(SoftwareBreakpointBytePlan),
    /// Explicit-removal `INT3 -> original` plan.
    Remove(SoftwareBreakpointBytePlan),
}

impl SoftwareBreakpointActionPlan {
    /// Returns the plan's lifecycle action.
    #[must_use]
    pub const fn action(self) -> SoftwareBreakpointAction {
        match self {
            Self::Arm(_) => SoftwareBreakpointAction::Arm,
            Self::Restore(_) => SoftwareBreakpointAction::Restore,
            Self::Rearm(_) => SoftwareBreakpointAction::Rearm,
            Self::Remove(_) => SoftwareBreakpointAction::Remove,
        }
    }

    /// Returns the exact byte plan.
    #[must_use]
    pub const fn bytes(self) -> SoftwareBreakpointBytePlan {
        match self {
            Self::Arm(plan) | Self::Restore(plan) | Self::Rearm(plan) | Self::Remove(plan) => plan,
        }
    }

    /// Returns the unique operation identity.
    #[must_use]
    pub const fn operation_id(self) -> SoftwareBreakpointOperationId {
        self.bytes().operation_id
    }
}

/// Caller-supplied report that one exact action plan succeeded.
///
/// Constructing this value proves nothing by itself. A trusted backend owner
/// must create it only after its compare/replace operation succeeded exactly.
/// The state machine checks every field against its sole pending plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareBreakpointActionAcknowledgement {
    /// Action reported as successful.
    pub action: SoftwareBreakpointAction,
    /// Exact planned operation identity.
    pub operation_id: SoftwareBreakpointOperationId,
    /// Exact owning session.
    pub session_id: SessionId,
    /// Exact stopped-state token used for the operation.
    pub stop_token: StopToken,
    /// Exact complete breakpoint specification.
    pub breakpoint: BreakpointSpec,
    /// Exact byte compared by the backend.
    pub expected_byte: u8,
    /// Exact byte reported as installed by the backend.
    pub replacement_byte: u8,
}

/// Correlation record supplied after the session owner has established a later
/// stopped state for a persistent breakpoint.
///
/// This is deliberately not a protocol event and is not proof that the target
/// executed one instruction. It only binds the restore operation and hit token
/// to a distinct later token before this reducer will plan a rearm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareBreakpointSingleStepAcknowledgement {
    /// Owning session.
    pub session_id: SessionId,
    /// Persistent breakpoint awaiting the later stop.
    pub breakpoint_id: BreakpointId,
    /// Exact restore operation that created the wait state.
    pub restore_operation_id: SoftwareBreakpointOperationId,
    /// Exact hit stop carried by that restore operation.
    pub hit_stop_token: StopToken,
    /// Distinct later stop under which rearming may be planned.
    pub stepped_stop_token: StopToken,
}

/// Acknowledgement material retained when fail-closed poisoning occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareBreakpointAcknowledgement {
    /// Exact byte-action success report.
    Action(SoftwareBreakpointActionAcknowledgement),
    /// External later-stop correlation for the single-step/rearm flow.
    SingleStep(SoftwareBreakpointSingleStepAcknowledgement),
}

/// Last acknowledged lifecycle of a retained breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareBreakpointPhase {
    /// The last exact acknowledgement reported `INT3` installed.
    Armed,
    /// The original byte was restored after a hit. A persistent breakpoint
    /// needs a later stop token before a rearm plan can be issued.
    AwaitingSingleStep,
    /// A distinct later stop was exactly correlated; rearm may now be planned.
    ReadyToRearm,
}

/// Bounded public snapshot of one retained breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareBreakpointSnapshot {
    /// Complete validated software-breakpoint specification.
    pub breakpoint: BreakpointSpec,
    /// Exact original byte retained for restoration.
    pub original_byte: u8,
    /// Persistent or one-shot behavior.
    pub persistence: SoftwareBreakpointPersistence,
    /// Last acknowledged lifecycle phase.
    pub phase: SoftwareBreakpointPhase,
    /// Stop token carried by the last successfully acknowledged byte action.
    pub acknowledged_byte_stop_token: StopToken,
    /// Restore operation associated with an awaiting/ready single-step flow.
    pub restore_operation_id: Option<SoftwareBreakpointOperationId>,
    /// Exactly correlated later stop, present only while ready to rearm.
    pub single_step_stop_token: Option<StopToken>,
}

/// Transition applied only after an exact success acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareBreakpointTransition {
    /// A breakpoint was inserted into the acknowledged table as armed.
    Armed { breakpoint_id: BreakpointId },
    /// A persistent hit restored its original byte and now awaits a later stop.
    RestoredForSingleStep { breakpoint_id: BreakpointId },
    /// A temporary hit restored its original byte and removed its table entry.
    TemporaryRemoved { breakpoint_id: BreakpointId },
    /// A persistent breakpoint was rearmed.
    Rearmed { breakpoint_id: BreakpointId },
    /// An armed breakpoint was explicitly restored and removed.
    Removed { breakpoint_id: BreakpointId },
}

/// Why an acknowledgement could not be the exact pending success report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SoftwareBreakpointAcknowledgementRejection {
    /// The acknowledgement repeated an operation already completed or passed.
    #[error("duplicate software-breakpoint acknowledgement for operation {operation_id:?}")]
    Duplicate {
        /// Repeated operation identity.
        operation_id: SoftwareBreakpointOperationId,
    },
    /// The acknowledgement skipped or reordered the pending operation.
    #[error(
        "out-of-order software-breakpoint acknowledgement: expected {expected:?}, received {actual:?}"
    )]
    OutOfOrder {
        /// Pending operation identity, if one exists.
        expected: Option<SoftwareBreakpointOperationId>,
        /// Received operation identity.
        actual: SoftwareBreakpointOperationId,
    },
    /// The acknowledgement named a different session.
    #[error(
        "software-breakpoint acknowledgement session mismatch: expected {expected:?}, received {actual:?}"
    )]
    WrongSession {
        /// Planned session.
        expected: SessionId,
        /// Reported session.
        actual: SessionId,
    },
    /// The acknowledgement carried a different stopped-state token.
    #[error("software-breakpoint acknowledgement stop token mismatch")]
    WrongStopToken {
        /// Planned token.
        expected: StopToken,
        /// Reported token.
        actual: StopToken,
    },
    /// Action, breakpoint, address, or byte material differed from the plan.
    #[error("software-breakpoint acknowledgement payload did not exactly match its plan")]
    PayloadMismatch,
}

/// Bounded cleanup snapshot retained after fail-closed poisoning.
///
/// `acknowledged_breakpoints` contains only last-exact acknowledgement state.
/// `uncertain_operation` must never be interpreted as clean: the mismatched
/// report cannot establish whether that exact compare/replace took effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftwareBreakpointCleanupEvidence {
    /// Session whose breakpoints require reconciliation.
    pub session_id: SessionId,
    /// Bounded last-acknowledged breakpoint snapshots.
    pub acknowledged_breakpoints: Vec<SoftwareBreakpointSnapshot>,
    /// Exact pending plan whose physical outcome is unknown, if any.
    pub uncertain_operation: Option<SoftwareBreakpointActionPlan>,
}

/// First acknowledgement mismatch and its retained cleanup evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftwareBreakpointPoisonEvidence {
    /// First acknowledgement rejection; later calls cannot overwrite it.
    pub rejection: SoftwareBreakpointAcknowledgementRejection,
    /// Mismatched acknowledgement that caused the poison.
    pub received: SoftwareBreakpointAcknowledgement,
    /// Exact bounded reconciliation material frozen at first mismatch.
    pub cleanup: SoftwareBreakpointCleanupEvidence,
}

/// Validation or lifecycle failure from the software-breakpoint reducer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SoftwareBreakpointError {
    /// Requested capacity was zero or exceeded the hard bound.
    #[error("software-breakpoint capacity must be in 1..={maximum}, received {requested}")]
    InvalidCapacity {
        /// Requested table capacity.
        requested: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// The supplied original byte was already the replacement opcode.
    #[error("software breakpoint cannot retain 0xCC as its original byte")]
    OriginalByteIsInt3,
    /// The supplied breakpoint specification was not a software breakpoint.
    #[error("software-breakpoint planner rejects hardware breakpoint specifications")]
    NotSoftwareBreakpoint,
    /// The supplied software-breakpoint specification was structurally invalid.
    #[error("invalid software-breakpoint specification: {0}")]
    InvalidBreakpointSpec(ProtocolValidationError),
    /// A retained breakpoint already uses this identity.
    #[error("duplicate software-breakpoint identity {breakpoint_id:?}")]
    DuplicateBreakpointId {
        /// Duplicate identity.
        breakpoint_id: BreakpointId,
    },
    /// A retained breakpoint already uses this address.
    #[error("duplicate software-breakpoint address {address:?}")]
    DuplicateAddress {
        /// Duplicate address.
        address: MemoryAddress,
    },
    /// The configured table capacity has been reached.
    #[error("software-breakpoint capacity {capacity} is exhausted")]
    CapacityExceeded {
        /// Configured capacity.
        capacity: usize,
    },
    /// Another action must be acknowledged before a new one can be planned.
    #[error("software-breakpoint operation {operation_id:?} is still pending")]
    OperationPending {
        /// Sole pending operation.
        operation_id: SoftwareBreakpointOperationId,
    },
    /// No retained breakpoint has this identity.
    #[error("unknown software-breakpoint identity {breakpoint_id:?}")]
    UnknownBreakpoint {
        /// Missing identity.
        breakpoint_id: BreakpointId,
    },
    /// A lifecycle action is not valid in the acknowledged phase.
    #[error(
        "software-breakpoint action {action:?} is invalid while breakpoint {breakpoint_id:?} is {phase:?}"
    )]
    InvalidPhase {
        /// Requested action.
        action: SoftwareBreakpointAction,
        /// Breakpoint identity.
        breakpoint_id: BreakpointId,
        /// Current acknowledged phase.
        phase: SoftwareBreakpointPhase,
    },
    /// A stop token belongs to a different session.
    #[error(
        "software-breakpoint stop token session mismatch: expected {expected:?}, received {actual:?}"
    )]
    WrongSession {
        /// Owning session.
        expected: SessionId,
        /// Session carried by the stop token.
        actual: SessionId,
    },
    /// A hit or single-step stop token did not advance beyond its predecessor.
    #[error("software-breakpoint stop token did not advance")]
    StopTokenDidNotAdvance {
        /// Last acknowledged token.
        previous: StopToken,
        /// Candidate later token.
        actual: StopToken,
    },
    /// The monotonic operation counter cannot allocate another identity.
    #[error("software-breakpoint operation identifier space is exhausted")]
    OperationIdExhausted,
    /// The first acknowledgement mismatch poisoned the state machine.
    #[error("software-breakpoint acknowledgement rejected: {0}")]
    AcknowledgementRejected(SoftwareBreakpointAcknowledgementRejection),
    /// The state machine is poisoned and can only expose cleanup evidence.
    #[error("software-breakpoint state machine is poisoned")]
    Poisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BreakpointEntry {
    breakpoint: BreakpointSpec,
    original_byte: u8,
    persistence: SoftwareBreakpointPersistence,
    phase: SoftwareBreakpointPhase,
    acknowledged_byte_stop_token: StopToken,
    restore_operation_id: Option<SoftwareBreakpointOperationId>,
    single_step_stop_token: Option<StopToken>,
}

impl BreakpointEntry {
    const fn snapshot(self) -> SoftwareBreakpointSnapshot {
        SoftwareBreakpointSnapshot {
            breakpoint: self.breakpoint,
            original_byte: self.original_byte,
            persistence: self.persistence,
            phase: self.phase,
            acknowledged_byte_stop_token: self.acknowledged_byte_stop_token,
            restore_operation_id: self.restore_operation_id,
            single_step_stop_token: self.single_step_stop_token,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingTransition {
    Arm { entry: BreakpointEntry },
    Restore { breakpoint_id: BreakpointId },
    Rearm { breakpoint_id: BreakpointId },
    Remove { breakpoint_id: BreakpointId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingOperation {
    plan: SoftwareBreakpointActionPlan,
    transition: PendingTransition,
}

/// Pure, bounded, single-owner transactional software-breakpoint reducer.
///
/// Planning reserves one operation identity and the sole pending slot, but does
/// not change the acknowledged breakpoint table or lifecycle phase. Only an
/// exact call to [`Self::acknowledge_success`] applies the planned transition.
/// The type performs no synchronization; one session worker should own it.
#[derive(Debug)]
pub struct SoftwareBreakpointStateMachine {
    session_id: SessionId,
    capacity: usize,
    next_operation_id: Option<u64>,
    last_acknowledged_operation: Option<SoftwareBreakpointOperationId>,
    breakpoints: BTreeMap<BreakpointId, BreakpointEntry>,
    pending: Option<PendingOperation>,
    poison_evidence: Option<SoftwareBreakpointPoisonEvidence>,
}

impl SoftwareBreakpointStateMachine {
    /// Constructs a state machine with the hard maximum capacity.
    #[must_use]
    pub fn new(session_id: SessionId) -> Self {
        Self::with_capacity(session_id, MAX_SOFTWARE_BREAKPOINTS)
            .expect("the built-in software-breakpoint capacity is valid")
    }

    /// Constructs a state machine with a smaller explicit capacity.
    pub fn with_capacity(
        session_id: SessionId,
        capacity: usize,
    ) -> Result<Self, SoftwareBreakpointError> {
        if capacity == 0 || capacity > MAX_SOFTWARE_BREAKPOINTS {
            return Err(SoftwareBreakpointError::InvalidCapacity {
                requested: capacity,
                maximum: MAX_SOFTWARE_BREAKPOINTS,
            });
        }
        Ok(Self {
            session_id,
            capacity,
            next_operation_id: Some(1),
            last_acknowledged_operation: None,
            breakpoints: BTreeMap::new(),
            pending: None,
            poison_evidence: None,
        })
    }

    /// Returns the owning session.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the configured retained-breakpoint capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of acknowledged retained breakpoints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.breakpoints.len()
    }

    /// Returns whether there are no acknowledged retained breakpoints.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }

    /// Returns whether an acknowledgement mismatch permanently froze the reducer.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poison_evidence.is_some()
    }

    /// Returns the sole pending plan, if any.
    #[must_use]
    pub fn pending_plan(&self) -> Option<SoftwareBreakpointActionPlan> {
        self.pending.map(|pending| pending.plan)
    }

    /// Returns one acknowledged breakpoint snapshot.
    #[must_use]
    pub fn breakpoint(&self, breakpoint_id: BreakpointId) -> Option<SoftwareBreakpointSnapshot> {
        self.breakpoints
            .get(&breakpoint_id)
            .copied()
            .map(BreakpointEntry::snapshot)
    }

    /// Returns first-mismatch cleanup evidence. It remains available after poison.
    #[must_use]
    pub fn poison_evidence(&self) -> Option<&SoftwareBreakpointPoisonEvidence> {
        self.poison_evidence.as_ref()
    }

    /// Returns the frozen cleanup snapshot after poisoning.
    #[must_use]
    pub fn cleanup_evidence(&self) -> Option<&SoftwareBreakpointCleanupEvidence> {
        self.poison_evidence
            .as_ref()
            .map(|evidence| &evidence.cleanup)
    }

    /// Returns bounded reconciliation material for controlled shutdown,
    /// transport loss, or backend abandonment.
    ///
    /// A pending plan is reported as uncertain because this pure reducer cannot
    /// know whether an external backend dispatched or partially performed it.
    /// Once poisoned, this returns the frozen first-mismatch snapshot rather
    /// than recomputing evidence from mutable bookkeeping.
    #[must_use]
    pub fn cleanup_snapshot(&self) -> SoftwareBreakpointCleanupEvidence {
        self.poison_evidence.as_ref().map_or_else(
            || self.current_cleanup_evidence(),
            |evidence| evidence.cleanup.clone(),
        )
    }

    /// Plans initial installation without inserting or arming table state.
    pub fn plan_arm(
        &mut self,
        stop_token: StopToken,
        breakpoint: BreakpointSpec,
        original_byte: u8,
        persistence: SoftwareBreakpointPersistence,
    ) -> Result<SoftwareBreakpointActionPlan, SoftwareBreakpointError> {
        self.require_ready(stop_token)?;
        if breakpoint.kind != BreakpointKind::Software {
            return Err(SoftwareBreakpointError::NotSoftwareBreakpoint);
        }
        breakpoint
            .validate()
            .map_err(SoftwareBreakpointError::InvalidBreakpointSpec)?;
        if original_byte == INT3_OPCODE {
            return Err(SoftwareBreakpointError::OriginalByteIsInt3);
        }
        if self.breakpoints.contains_key(&breakpoint.id) {
            return Err(SoftwareBreakpointError::DuplicateBreakpointId {
                breakpoint_id: breakpoint.id,
            });
        }
        if self
            .breakpoints
            .values()
            .any(|entry| entry.breakpoint.address == breakpoint.address)
        {
            return Err(SoftwareBreakpointError::DuplicateAddress {
                address: breakpoint.address,
            });
        }
        if self.breakpoints.len() >= self.capacity {
            return Err(SoftwareBreakpointError::CapacityExceeded {
                capacity: self.capacity,
            });
        }

        let operation_id = self.allocate_operation_id()?;
        let bytes = SoftwareBreakpointBytePlan {
            operation_id,
            session_id: self.session_id,
            stop_token,
            breakpoint,
            expected_byte: original_byte,
            replacement_byte: INT3_OPCODE,
        };
        let plan = SoftwareBreakpointActionPlan::Arm(bytes);
        self.pending = Some(PendingOperation {
            plan,
            transition: PendingTransition::Arm {
                entry: BreakpointEntry {
                    breakpoint,
                    original_byte,
                    persistence,
                    phase: SoftwareBreakpointPhase::Armed,
                    acknowledged_byte_stop_token: stop_token,
                    restore_operation_id: None,
                    single_step_stop_token: None,
                },
            },
        });
        Ok(plan)
    }

    /// Plans exact original-byte restoration for an acknowledged armed hit.
    ///
    /// The hit token must be strictly later than the token of the last
    /// acknowledged arm/rearm operation. This method does not claim why the new
    /// stop occurred; the session owner remains responsible for event identity.
    pub fn plan_restore_after_hit(
        &mut self,
        breakpoint_id: BreakpointId,
        hit_stop_token: StopToken,
    ) -> Result<SoftwareBreakpointActionPlan, SoftwareBreakpointError> {
        self.require_ready(hit_stop_token)?;
        let entry = self.require_breakpoint(breakpoint_id)?;
        self.require_phase(
            entry,
            SoftwareBreakpointAction::Restore,
            SoftwareBreakpointPhase::Armed,
        )?;
        self.require_advanced_stop(entry.acknowledged_byte_stop_token, hit_stop_token)?;

        let plan = SoftwareBreakpointActionPlan::Restore(SoftwareBreakpointBytePlan {
            operation_id: self.allocate_operation_id()?,
            session_id: self.session_id,
            stop_token: hit_stop_token,
            breakpoint: entry.breakpoint,
            expected_byte: INT3_OPCODE,
            replacement_byte: entry.original_byte,
        });
        self.pending = Some(PendingOperation {
            plan,
            transition: PendingTransition::Restore { breakpoint_id },
        });
        Ok(plan)
    }

    /// Plans reinstallation after an externally established later stop.
    ///
    /// The later token is structural correlation only. This reducer does not
    /// request a single step and does not claim that one succeeded.
    pub fn plan_rearm_after_single_step(
        &mut self,
        breakpoint_id: BreakpointId,
    ) -> Result<SoftwareBreakpointActionPlan, SoftwareBreakpointError> {
        self.require_healthy_and_idle()?;
        let entry = self.require_breakpoint(breakpoint_id)?;
        self.require_phase(
            entry,
            SoftwareBreakpointAction::Rearm,
            SoftwareBreakpointPhase::ReadyToRearm,
        )?;
        let stepped_stop_token = entry
            .single_step_stop_token
            .expect("ready-to-rearm state retains its correlated stop token");

        let plan = SoftwareBreakpointActionPlan::Rearm(SoftwareBreakpointBytePlan {
            operation_id: self.allocate_operation_id()?,
            session_id: self.session_id,
            stop_token: stepped_stop_token,
            breakpoint: entry.breakpoint,
            expected_byte: entry.original_byte,
            replacement_byte: INT3_OPCODE,
        });
        self.pending = Some(PendingOperation {
            plan,
            transition: PendingTransition::Rearm { breakpoint_id },
        });
        Ok(plan)
    }

    /// Accepts exact later-stop correlation for a persistent breakpoint.
    ///
    /// A mismatch is an acknowledgement mismatch and permanently poisons the
    /// reducer. An exact record changes only the local lifecycle to
    /// [`SoftwareBreakpointPhase::ReadyToRearm`]; it does not claim that a
    /// debugger backend successfully single-stepped the target.
    pub fn acknowledge_single_step(
        &mut self,
        acknowledgement: SoftwareBreakpointSingleStepAcknowledgement,
    ) -> Result<(), SoftwareBreakpointError> {
        if self.is_poisoned() {
            return Err(SoftwareBreakpointError::Poisoned);
        }
        if self.pending.is_some() {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::PayloadMismatch,
                SoftwareBreakpointAcknowledgement::SingleStep(acknowledgement),
            );
        }
        if acknowledgement.session_id != self.session_id {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::WrongSession {
                    expected: self.session_id,
                    actual: acknowledgement.session_id,
                },
                SoftwareBreakpointAcknowledgement::SingleStep(acknowledgement),
            );
        }
        if acknowledgement.stepped_stop_token.state.session_id != self.session_id {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::WrongSession {
                    expected: self.session_id,
                    actual: acknowledgement.stepped_stop_token.state.session_id,
                },
                SoftwareBreakpointAcknowledgement::SingleStep(acknowledgement),
            );
        }

        let Some(entry) = self
            .breakpoints
            .get(&acknowledgement.breakpoint_id)
            .copied()
        else {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::PayloadMismatch,
                SoftwareBreakpointAcknowledgement::SingleStep(acknowledgement),
            );
        };
        if entry.phase == SoftwareBreakpointPhase::ReadyToRearm
            && entry.restore_operation_id == Some(acknowledgement.restore_operation_id)
            && entry.acknowledged_byte_stop_token == acknowledgement.hit_stop_token
            && entry.single_step_stop_token == Some(acknowledgement.stepped_stop_token)
        {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::Duplicate {
                    operation_id: acknowledgement.restore_operation_id,
                },
                SoftwareBreakpointAcknowledgement::SingleStep(acknowledgement),
            );
        }
        if entry.phase != SoftwareBreakpointPhase::AwaitingSingleStep
            || entry.restore_operation_id != Some(acknowledgement.restore_operation_id)
        {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::PayloadMismatch,
                SoftwareBreakpointAcknowledgement::SingleStep(acknowledgement),
            );
        }
        if entry.acknowledged_byte_stop_token != acknowledgement.hit_stop_token {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::WrongStopToken {
                    expected: entry.acknowledged_byte_stop_token,
                    actual: acknowledgement.hit_stop_token,
                },
                SoftwareBreakpointAcknowledgement::SingleStep(acknowledgement),
            );
        }
        if let Err(SoftwareBreakpointError::StopTokenDidNotAdvance { .. }) = self
            .require_advanced_stop(
                acknowledgement.hit_stop_token,
                acknowledgement.stepped_stop_token,
            )
        {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::WrongStopToken {
                    expected: acknowledgement.hit_stop_token,
                    actual: acknowledgement.stepped_stop_token,
                },
                SoftwareBreakpointAcknowledgement::SingleStep(acknowledgement),
            );
        }

        let entry = self
            .breakpoints
            .get_mut(&acknowledgement.breakpoint_id)
            .expect("validated single-step acknowledgement retains its breakpoint");
        entry.phase = SoftwareBreakpointPhase::ReadyToRearm;
        entry.single_step_stop_token = Some(acknowledgement.stepped_stop_token);
        Ok(())
    }

    /// Plans exact original-byte restoration and explicit removal while armed.
    pub fn plan_remove(
        &mut self,
        breakpoint_id: BreakpointId,
        stop_token: StopToken,
    ) -> Result<SoftwareBreakpointActionPlan, SoftwareBreakpointError> {
        self.require_ready(stop_token)?;
        let entry = self.require_breakpoint(breakpoint_id)?;
        self.require_phase(
            entry,
            SoftwareBreakpointAction::Remove,
            SoftwareBreakpointPhase::Armed,
        )?;
        self.require_current_or_advanced_stop(entry.acknowledged_byte_stop_token, stop_token)?;

        let plan = SoftwareBreakpointActionPlan::Remove(SoftwareBreakpointBytePlan {
            operation_id: self.allocate_operation_id()?,
            session_id: self.session_id,
            stop_token,
            breakpoint: entry.breakpoint,
            expected_byte: INT3_OPCODE,
            replacement_byte: entry.original_byte,
        });
        self.pending = Some(PendingOperation {
            plan,
            transition: PendingTransition::Remove { breakpoint_id },
        });
        Ok(plan)
    }

    /// Applies a transition only when every acknowledgement field exactly
    /// matches the sole pending action. Any discrepancy poisons the reducer.
    pub fn acknowledge_success(
        &mut self,
        acknowledgement: SoftwareBreakpointActionAcknowledgement,
    ) -> Result<SoftwareBreakpointTransition, SoftwareBreakpointError> {
        if self.is_poisoned() {
            return Err(SoftwareBreakpointError::Poisoned);
        }

        let Some(pending) = self.pending else {
            let rejection = if self
                .last_acknowledged_operation
                .is_some_and(|last| acknowledgement.operation_id <= last)
            {
                SoftwareBreakpointAcknowledgementRejection::Duplicate {
                    operation_id: acknowledgement.operation_id,
                }
            } else {
                SoftwareBreakpointAcknowledgementRejection::OutOfOrder {
                    expected: None,
                    actual: acknowledgement.operation_id,
                }
            };
            return self.poison(
                rejection,
                SoftwareBreakpointAcknowledgement::Action(acknowledgement),
            );
        };

        let expected = pending.plan.bytes();
        if acknowledgement.operation_id != expected.operation_id {
            let rejection = if self
                .last_acknowledged_operation
                .is_some_and(|last| acknowledgement.operation_id <= last)
            {
                SoftwareBreakpointAcknowledgementRejection::Duplicate {
                    operation_id: acknowledgement.operation_id,
                }
            } else {
                SoftwareBreakpointAcknowledgementRejection::OutOfOrder {
                    expected: Some(expected.operation_id),
                    actual: acknowledgement.operation_id,
                }
            };
            return self.poison(
                rejection,
                SoftwareBreakpointAcknowledgement::Action(acknowledgement),
            );
        }
        if acknowledgement.session_id != expected.session_id {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::WrongSession {
                    expected: expected.session_id,
                    actual: acknowledgement.session_id,
                },
                SoftwareBreakpointAcknowledgement::Action(acknowledgement),
            );
        }
        if acknowledgement.stop_token != expected.stop_token {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::WrongStopToken {
                    expected: expected.stop_token,
                    actual: acknowledgement.stop_token,
                },
                SoftwareBreakpointAcknowledgement::Action(acknowledgement),
            );
        }
        if acknowledgement.action != pending.plan.action()
            || acknowledgement.breakpoint != expected.breakpoint
            || acknowledgement.expected_byte != expected.expected_byte
            || acknowledgement.replacement_byte != expected.replacement_byte
        {
            return self.poison(
                SoftwareBreakpointAcknowledgementRejection::PayloadMismatch,
                SoftwareBreakpointAcknowledgement::Action(acknowledgement),
            );
        }

        self.pending = None;
        self.last_acknowledged_operation = Some(expected.operation_id);
        let transition = match pending.transition {
            PendingTransition::Arm { entry } => {
                self.breakpoints.insert(entry.breakpoint.id, entry);
                SoftwareBreakpointTransition::Armed {
                    breakpoint_id: entry.breakpoint.id,
                }
            }
            PendingTransition::Restore { breakpoint_id } => {
                let entry = self
                    .breakpoints
                    .get_mut(&breakpoint_id)
                    .expect("pending restore retains its breakpoint");
                match entry.persistence {
                    SoftwareBreakpointPersistence::Persistent => {
                        entry.phase = SoftwareBreakpointPhase::AwaitingSingleStep;
                        entry.acknowledged_byte_stop_token = expected.stop_token;
                        entry.restore_operation_id = Some(expected.operation_id);
                        entry.single_step_stop_token = None;
                        SoftwareBreakpointTransition::RestoredForSingleStep { breakpoint_id }
                    }
                    SoftwareBreakpointPersistence::Temporary => {
                        self.breakpoints.remove(&breakpoint_id);
                        SoftwareBreakpointTransition::TemporaryRemoved { breakpoint_id }
                    }
                }
            }
            PendingTransition::Rearm { breakpoint_id } => {
                let entry = self
                    .breakpoints
                    .get_mut(&breakpoint_id)
                    .expect("pending rearm retains its breakpoint");
                entry.phase = SoftwareBreakpointPhase::Armed;
                entry.acknowledged_byte_stop_token = expected.stop_token;
                entry.restore_operation_id = None;
                entry.single_step_stop_token = None;
                SoftwareBreakpointTransition::Rearmed { breakpoint_id }
            }
            PendingTransition::Remove { breakpoint_id } => {
                self.breakpoints.remove(&breakpoint_id);
                SoftwareBreakpointTransition::Removed { breakpoint_id }
            }
        };
        Ok(transition)
    }

    fn require_ready(&self, stop_token: StopToken) -> Result<(), SoftwareBreakpointError> {
        self.require_healthy_and_idle()?;
        let actual = stop_token.state.session_id;
        if actual != self.session_id {
            return Err(SoftwareBreakpointError::WrongSession {
                expected: self.session_id,
                actual,
            });
        }
        Ok(())
    }

    fn require_healthy_and_idle(&self) -> Result<(), SoftwareBreakpointError> {
        if self.is_poisoned() {
            return Err(SoftwareBreakpointError::Poisoned);
        }
        if let Some(pending) = self.pending {
            return Err(SoftwareBreakpointError::OperationPending {
                operation_id: pending.plan.operation_id(),
            });
        }
        Ok(())
    }

    fn require_breakpoint(
        &self,
        breakpoint_id: BreakpointId,
    ) -> Result<BreakpointEntry, SoftwareBreakpointError> {
        self.breakpoints
            .get(&breakpoint_id)
            .copied()
            .ok_or(SoftwareBreakpointError::UnknownBreakpoint { breakpoint_id })
    }

    fn require_phase(
        &self,
        entry: BreakpointEntry,
        action: SoftwareBreakpointAction,
        required: SoftwareBreakpointPhase,
    ) -> Result<(), SoftwareBreakpointError> {
        if entry.phase == required {
            Ok(())
        } else {
            Err(SoftwareBreakpointError::InvalidPhase {
                action,
                breakpoint_id: entry.breakpoint.id,
                phase: entry.phase,
            })
        }
    }

    fn require_advanced_stop(
        &self,
        previous: StopToken,
        actual: StopToken,
    ) -> Result<(), SoftwareBreakpointError> {
        let generation_advanced = actual.state.generation.get() > previous.state.generation.get();
        let stop_advanced = actual.stop_id.get() > previous.stop_id.get();
        if generation_advanced && stop_advanced {
            Ok(())
        } else {
            Err(SoftwareBreakpointError::StopTokenDidNotAdvance { previous, actual })
        }
    }

    fn require_current_or_advanced_stop(
        &self,
        previous: StopToken,
        actual: StopToken,
    ) -> Result<(), SoftwareBreakpointError> {
        if actual == previous {
            Ok(())
        } else {
            self.require_advanced_stop(previous, actual)
        }
    }

    fn allocate_operation_id(
        &mut self,
    ) -> Result<SoftwareBreakpointOperationId, SoftwareBreakpointError> {
        let value = self
            .next_operation_id
            .ok_or(SoftwareBreakpointError::OperationIdExhausted)?;
        let operation_id = SoftwareBreakpointOperationId(value);
        self.next_operation_id = value.checked_add(1);
        Ok(operation_id)
    }

    fn current_cleanup_evidence(&self) -> SoftwareBreakpointCleanupEvidence {
        SoftwareBreakpointCleanupEvidence {
            session_id: self.session_id,
            acknowledged_breakpoints: self
                .breakpoints
                .values()
                .copied()
                .map(BreakpointEntry::snapshot)
                .collect(),
            uncertain_operation: self.pending.map(|pending| pending.plan),
        }
    }

    fn poison<T>(
        &mut self,
        rejection: SoftwareBreakpointAcknowledgementRejection,
        received: SoftwareBreakpointAcknowledgement,
    ) -> Result<T, SoftwareBreakpointError> {
        let cleanup = self.current_cleanup_evidence();
        self.poison_evidence = Some(SoftwareBreakpointPoisonEvidence {
            rejection,
            received,
            cleanup,
        });
        Err(SoftwareBreakpointError::AcknowledgementRejected(rejection))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BreakpointScope, HardwareAccess, StateGeneration, StateToken, StopId, ThreadId};

    const ORIGINAL: u8 = 0x90;

    fn session(value: u64) -> SessionId {
        SessionId::new(value).expect("nonzero session")
    }

    fn breakpoint_id(value: u64) -> BreakpointId {
        BreakpointId::new(value).expect("nonzero breakpoint")
    }

    fn stop(session_id: SessionId, generation: u64, stop_id: u64) -> StopToken {
        StopToken {
            state: StateToken {
                session_id,
                generation: StateGeneration::new(generation).expect("nonzero generation"),
            },
            stop_id: StopId::new(stop_id).expect("nonzero stop"),
        }
    }

    fn software_spec(id: u64, address: u64) -> BreakpointSpec {
        BreakpointSpec {
            id: breakpoint_id(id),
            address: MemoryAddress::new(address),
            kind: BreakpointKind::Software,
            scope: BreakpointScope::Process,
        }
    }

    fn action_acknowledgement(
        plan: SoftwareBreakpointActionPlan,
    ) -> SoftwareBreakpointActionAcknowledgement {
        let bytes = plan.bytes();
        SoftwareBreakpointActionAcknowledgement {
            action: plan.action(),
            operation_id: bytes.operation_id,
            session_id: bytes.session_id,
            stop_token: bytes.stop_token,
            breakpoint: bytes.breakpoint,
            expected_byte: bytes.expected_byte,
            replacement_byte: bytes.replacement_byte,
        }
    }

    fn acknowledge(
        machine: &mut SoftwareBreakpointStateMachine,
        plan: SoftwareBreakpointActionPlan,
    ) -> SoftwareBreakpointTransition {
        machine
            .acknowledge_success(action_acknowledgement(plan))
            .expect("exact acknowledgement")
    }

    fn arm(
        machine: &mut SoftwareBreakpointStateMachine,
        stop_token: StopToken,
        breakpoint: BreakpointSpec,
        persistence: SoftwareBreakpointPersistence,
    ) -> SoftwareBreakpointActionPlan {
        let plan = machine
            .plan_arm(stop_token, breakpoint, ORIGINAL, persistence)
            .expect("arm plan");
        assert_eq!(
            acknowledge(machine, plan),
            SoftwareBreakpointTransition::Armed {
                breakpoint_id: breakpoint.id,
            }
        );
        plan
    }

    fn restore_persistent(
        machine: &mut SoftwareBreakpointStateMachine,
        breakpoint_id: BreakpointId,
        hit_stop: StopToken,
    ) -> SoftwareBreakpointActionPlan {
        let plan = machine
            .plan_restore_after_hit(breakpoint_id, hit_stop)
            .expect("restore plan");
        assert_eq!(
            acknowledge(machine, plan),
            SoftwareBreakpointTransition::RestoredForSingleStep { breakpoint_id }
        );
        plan
    }

    fn step_acknowledgement(
        machine: &SoftwareBreakpointStateMachine,
        breakpoint_id: BreakpointId,
        stepped_stop_token: StopToken,
    ) -> SoftwareBreakpointSingleStepAcknowledgement {
        let snapshot = machine.breakpoint(breakpoint_id).expect("breakpoint");
        SoftwareBreakpointSingleStepAcknowledgement {
            session_id: machine.session_id(),
            breakpoint_id,
            restore_operation_id: snapshot.restore_operation_id.expect("restore operation"),
            hit_stop_token: snapshot.acknowledged_byte_stop_token,
            stepped_stop_token,
        }
    }

    #[test]
    fn arm_plan_is_exact_and_does_not_commit_before_acknowledgement() {
        let session_id = session(1);
        let initial_stop = stop(session_id, 1, 1);
        let breakpoint = software_spec(7, 0x401000);
        let mut machine = SoftwareBreakpointStateMachine::with_capacity(session_id, 2).unwrap();

        let plan = machine
            .plan_arm(
                initial_stop,
                breakpoint,
                0x55,
                SoftwareBreakpointPersistence::Persistent,
            )
            .unwrap();
        assert_eq!(machine.len(), 0);
        assert_eq!(machine.breakpoint(breakpoint.id), None);
        assert_eq!(machine.pending_plan(), Some(plan));
        assert_eq!(
            machine.cleanup_snapshot(),
            SoftwareBreakpointCleanupEvidence {
                session_id,
                acknowledged_breakpoints: Vec::new(),
                uncertain_operation: Some(plan),
            }
        );
        assert_eq!(plan.action(), SoftwareBreakpointAction::Arm);
        assert_eq!(
            plan.bytes(),
            SoftwareBreakpointBytePlan {
                operation_id: SoftwareBreakpointOperationId::new(1).unwrap(),
                session_id,
                stop_token: initial_stop,
                breakpoint,
                expected_byte: 0x55,
                replacement_byte: INT3_OPCODE,
            }
        );

        assert_eq!(
            acknowledge(&mut machine, plan),
            SoftwareBreakpointTransition::Armed {
                breakpoint_id: breakpoint.id,
            }
        );
        let snapshot = machine.breakpoint(breakpoint.id).unwrap();
        assert_eq!(snapshot.phase, SoftwareBreakpointPhase::Armed);
        assert_eq!(snapshot.original_byte, 0x55);
        assert_eq!(snapshot.acknowledged_byte_stop_token, initial_stop);
        let cleanup = machine.cleanup_snapshot();
        assert_eq!(cleanup.acknowledged_breakpoints, vec![snapshot]);
        assert!(cleanup.uncertain_operation.is_none());
    }

    #[test]
    fn persistent_flow_requires_restore_step_correlation_rearm_and_remove_acks() {
        let session_id = session(1);
        let arm_stop = stop(session_id, 1, 1);
        let hit_stop = stop(session_id, 3, 2);
        let stepped_stop = stop(session_id, 5, 3);
        let breakpoint = software_spec(1, 0x1000);
        let mut machine = SoftwareBreakpointStateMachine::new(session_id);

        let arm_plan = arm(
            &mut machine,
            arm_stop,
            breakpoint,
            SoftwareBreakpointPersistence::Persistent,
        );
        assert_eq!(arm_plan.operation_id().get(), 1);

        let restore_plan = machine
            .plan_restore_after_hit(breakpoint.id, hit_stop)
            .unwrap();
        assert_eq!(restore_plan.operation_id().get(), 2);
        assert_eq!(restore_plan.action(), SoftwareBreakpointAction::Restore);
        assert_eq!(restore_plan.bytes().expected_byte, INT3_OPCODE);
        assert_eq!(restore_plan.bytes().replacement_byte, ORIGINAL);
        assert_eq!(
            machine.breakpoint(breakpoint.id).unwrap().phase,
            SoftwareBreakpointPhase::Armed
        );
        assert_eq!(
            acknowledge(&mut machine, restore_plan),
            SoftwareBreakpointTransition::RestoredForSingleStep {
                breakpoint_id: breakpoint.id,
            }
        );
        assert_eq!(
            machine.breakpoint(breakpoint.id).unwrap().phase,
            SoftwareBreakpointPhase::AwaitingSingleStep
        );
        assert!(matches!(
            machine.plan_rearm_after_single_step(breakpoint.id),
            Err(SoftwareBreakpointError::InvalidPhase {
                action: SoftwareBreakpointAction::Rearm,
                phase: SoftwareBreakpointPhase::AwaitingSingleStep,
                ..
            })
        ));

        let step_ack = step_acknowledgement(&machine, breakpoint.id, stepped_stop);
        machine.acknowledge_single_step(step_ack).unwrap();
        assert_eq!(
            machine.breakpoint(breakpoint.id).unwrap().phase,
            SoftwareBreakpointPhase::ReadyToRearm
        );

        let rearm_plan = machine.plan_rearm_after_single_step(breakpoint.id).unwrap();
        assert_eq!(rearm_plan.operation_id().get(), 3);
        assert_eq!(rearm_plan.bytes().stop_token, stepped_stop);
        assert_eq!(rearm_plan.bytes().expected_byte, ORIGINAL);
        assert_eq!(rearm_plan.bytes().replacement_byte, INT3_OPCODE);
        assert_eq!(
            machine.breakpoint(breakpoint.id).unwrap().phase,
            SoftwareBreakpointPhase::ReadyToRearm
        );
        assert_eq!(
            acknowledge(&mut machine, rearm_plan),
            SoftwareBreakpointTransition::Rearmed {
                breakpoint_id: breakpoint.id,
            }
        );
        assert_eq!(
            machine.breakpoint(breakpoint.id).unwrap().phase,
            SoftwareBreakpointPhase::Armed
        );

        let remove_plan = machine.plan_remove(breakpoint.id, stepped_stop).unwrap();
        assert_eq!(remove_plan.operation_id().get(), 4);
        assert_eq!(remove_plan.action(), SoftwareBreakpointAction::Remove);
        assert_eq!(remove_plan.bytes().expected_byte, INT3_OPCODE);
        assert_eq!(remove_plan.bytes().replacement_byte, ORIGINAL);
        assert!(machine.breakpoint(breakpoint.id).is_some());
        assert_eq!(
            acknowledge(&mut machine, remove_plan),
            SoftwareBreakpointTransition::Removed {
                breakpoint_id: breakpoint.id,
            }
        );
        assert!(machine.is_empty());
    }

    #[test]
    fn temporary_hit_restore_acknowledgement_removes_without_rearm() {
        let session_id = session(1);
        let breakpoint = software_spec(1, 0x1000);
        let mut machine = SoftwareBreakpointStateMachine::new(session_id);
        arm(
            &mut machine,
            stop(session_id, 1, 1),
            breakpoint,
            SoftwareBreakpointPersistence::Temporary,
        );

        let restore = machine
            .plan_restore_after_hit(breakpoint.id, stop(session_id, 3, 2))
            .unwrap();
        assert!(machine.breakpoint(breakpoint.id).is_some());
        assert_eq!(
            acknowledge(&mut machine, restore),
            SoftwareBreakpointTransition::TemporaryRemoved {
                breakpoint_id: breakpoint.id,
            }
        );
        assert!(machine.breakpoint(breakpoint.id).is_none());
        assert!(matches!(
            machine.plan_rearm_after_single_step(breakpoint.id),
            Err(SoftwareBreakpointError::UnknownBreakpoint { .. })
        ));
    }

    #[test]
    fn rejects_int3_hardware_duplicate_id_address_and_capacity() {
        let session_id = session(1);
        let stopped = stop(session_id, 1, 1);
        let mut machine = SoftwareBreakpointStateMachine::with_capacity(session_id, 1).unwrap();
        let first = software_spec(1, 0x1000);

        assert_eq!(
            machine.plan_arm(
                stopped,
                first,
                INT3_OPCODE,
                SoftwareBreakpointPersistence::Persistent,
            ),
            Err(SoftwareBreakpointError::OriginalByteIsInt3)
        );
        let hardware = BreakpointSpec {
            kind: BreakpointKind::Hardware {
                access: HardwareAccess::Execute,
                size: 1,
            },
            ..first
        };
        assert_eq!(
            machine.plan_arm(
                stopped,
                hardware,
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            ),
            Err(SoftwareBreakpointError::NotSoftwareBreakpoint)
        );
        assert!(matches!(
            machine.plan_arm(
                stopped,
                software_spec(9, u64::MAX),
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            ),
            Err(SoftwareBreakpointError::InvalidBreakpointSpec(
                ProtocolValidationError::AddressOverflow { .. }
            ))
        ));

        arm(
            &mut machine,
            stopped,
            first,
            SoftwareBreakpointPersistence::Persistent,
        );
        assert!(matches!(
            machine.plan_arm(
                stopped,
                first,
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            ),
            Err(SoftwareBreakpointError::DuplicateBreakpointId { .. })
        ));
        let same_address_different_scope = BreakpointSpec {
            id: breakpoint_id(2),
            scope: BreakpointScope::Thread {
                thread_id: ThreadId::new(9).unwrap(),
            },
            ..first
        };
        assert!(matches!(
            machine.plan_arm(
                stopped,
                same_address_different_scope,
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            ),
            Err(SoftwareBreakpointError::DuplicateAddress { .. })
        ));
        assert_eq!(
            machine.plan_arm(
                stopped,
                software_spec(3, 0x2000),
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            ),
            Err(SoftwareBreakpointError::CapacityExceeded { capacity: 1 })
        );
    }

    #[test]
    fn capacity_configuration_is_strictly_bounded() {
        let session_id = session(1);
        assert!(matches!(
            SoftwareBreakpointStateMachine::with_capacity(session_id, 0),
            Err(SoftwareBreakpointError::InvalidCapacity {
                requested: 0,
                maximum: MAX_SOFTWARE_BREAKPOINTS,
            })
        ));
        assert!(matches!(
            SoftwareBreakpointStateMachine::with_capacity(session_id, MAX_SOFTWARE_BREAKPOINTS + 1),
            Err(SoftwareBreakpointError::InvalidCapacity { .. })
        ));
        assert_eq!(
            SoftwareBreakpointStateMachine::new(session_id).capacity(),
            MAX_SOFTWARE_BREAKPOINTS
        );
    }

    #[test]
    fn wrong_session_and_nonadvancing_stop_tokens_are_rejected_before_planning() {
        let session_id = session(1);
        let other_session = session(2);
        let breakpoint = software_spec(1, 0x1000);
        let mut machine = SoftwareBreakpointStateMachine::new(session_id);
        assert!(matches!(
            machine.plan_arm(
                stop(other_session, 1, 1),
                breakpoint,
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            ),
            Err(SoftwareBreakpointError::WrongSession {
                expected,
                actual,
            }) if expected == session_id && actual == other_session
        ));

        let arm_stop = stop(session_id, 1, 1);
        arm(
            &mut machine,
            arm_stop,
            breakpoint,
            SoftwareBreakpointPersistence::Persistent,
        );
        for wrong in [arm_stop, stop(session_id, 2, 1), stop(session_id, 1, 2)] {
            assert!(matches!(
                machine.plan_restore_after_hit(breakpoint.id, wrong),
                Err(SoftwareBreakpointError::StopTokenDidNotAdvance { .. })
            ));
        }
        assert!(matches!(
            machine.plan_remove(breakpoint.id, stop(session_id, 2, 1)),
            Err(SoftwareBreakpointError::StopTokenDidNotAdvance { .. })
        ));
        assert!(machine.pending_plan().is_none());
    }

    #[test]
    fn only_one_action_can_be_pending() {
        let session_id = session(1);
        let stopped = stop(session_id, 1, 1);
        let mut machine = SoftwareBreakpointStateMachine::new(session_id);
        let first = machine
            .plan_arm(
                stopped,
                software_spec(1, 0x1000),
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            )
            .unwrap();
        assert_eq!(
            machine.plan_arm(
                stopped,
                software_spec(2, 0x2000),
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            ),
            Err(SoftwareBreakpointError::OperationPending {
                operation_id: first.operation_id(),
            })
        );
        assert_eq!(machine.pending_plan(), Some(first));
        assert!(machine.is_empty());
    }

    fn pending_arm() -> (
        SoftwareBreakpointStateMachine,
        SoftwareBreakpointActionPlan,
        SoftwareBreakpointActionAcknowledgement,
    ) {
        let session_id = session(1);
        let mut machine = SoftwareBreakpointStateMachine::new(session_id);
        let plan = machine
            .plan_arm(
                stop(session_id, 1, 1),
                software_spec(1, 0x1000),
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            )
            .unwrap();
        (machine, plan, action_acknowledgement(plan))
    }

    fn assert_payload_mismatch(mutate: impl FnOnce(&mut SoftwareBreakpointActionAcknowledgement)) {
        let (mut machine, plan, mut acknowledgement) = pending_arm();
        mutate(&mut acknowledgement);
        assert_eq!(
            machine.acknowledge_success(acknowledgement),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::PayloadMismatch
            ))
        );
        assert!(machine.is_poisoned());
        assert_eq!(machine.pending_plan(), Some(plan));
        assert!(machine.is_empty());
        assert_eq!(
            machine.cleanup_evidence().unwrap().uncertain_operation,
            Some(plan)
        );
    }

    #[test]
    fn every_action_acknowledgement_payload_field_is_exact() {
        assert_payload_mismatch(|ack| ack.action = SoftwareBreakpointAction::Remove);
        assert_payload_mismatch(|ack| ack.breakpoint.id = breakpoint_id(2));
        assert_payload_mismatch(|ack| ack.breakpoint.address = MemoryAddress::new(0x2000));
        assert_payload_mismatch(|ack| {
            ack.breakpoint.scope = BreakpointScope::Thread {
                thread_id: ThreadId::new(1).unwrap(),
            };
        });
        assert_payload_mismatch(|ack| {
            ack.breakpoint.kind = BreakpointKind::Hardware {
                access: HardwareAccess::Execute,
                size: 1,
            };
        });
        assert_payload_mismatch(|ack| ack.expected_byte ^= 1);
        assert_payload_mismatch(|ack| ack.replacement_byte ^= 1);
    }

    #[test]
    fn wrong_acknowledgement_session_and_stop_token_poison_without_committing() {
        let (mut wrong_session_machine, plan, mut wrong_session_ack) = pending_arm();
        wrong_session_ack.session_id = session(2);
        assert!(matches!(
            wrong_session_machine.acknowledge_success(wrong_session_ack),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::WrongSession { .. }
            ))
        ));
        assert_eq!(
            wrong_session_machine
                .cleanup_evidence()
                .unwrap()
                .uncertain_operation,
            Some(plan)
        );

        let (mut wrong_stop_machine, plan, mut wrong_stop_ack) = pending_arm();
        wrong_stop_ack.stop_token = stop(session(1), 9, 9);
        assert!(matches!(
            wrong_stop_machine.acknowledge_success(wrong_stop_ack),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::WrongStopToken { .. }
            ))
        ));
        assert_eq!(
            wrong_stop_machine
                .cleanup_evidence()
                .unwrap()
                .uncertain_operation,
            Some(plan)
        );
    }

    #[test]
    fn future_acknowledgement_is_out_of_order_and_ack_without_plan_poisons() {
        let (mut machine, plan, mut acknowledgement) = pending_arm();
        acknowledgement.operation_id = SoftwareBreakpointOperationId::new(2).unwrap();
        assert_eq!(
            machine.acknowledge_success(acknowledgement),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::OutOfOrder {
                    expected: Some(plan.operation_id()),
                    actual: SoftwareBreakpointOperationId::new(2).unwrap(),
                }
            ))
        );

        let session_id = session(1);
        let mut empty = SoftwareBreakpointStateMachine::new(session_id);
        let acknowledgement = SoftwareBreakpointActionAcknowledgement {
            action: SoftwareBreakpointAction::Arm,
            operation_id: SoftwareBreakpointOperationId::new(1).unwrap(),
            session_id,
            stop_token: stop(session_id, 1, 1),
            breakpoint: software_spec(1, 0x1000),
            expected_byte: ORIGINAL,
            replacement_byte: INT3_OPCODE,
        };
        assert!(matches!(
            empty.acknowledge_success(acknowledgement),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::OutOfOrder { expected: None, .. }
            ))
        ));
        assert!(
            empty
                .cleanup_evidence()
                .unwrap()
                .uncertain_operation
                .is_none()
        );
    }

    #[test]
    fn duplicate_and_stale_acknowledgements_poison_and_retain_cleanup_state() {
        let session_id = session(1);
        let stopped = stop(session_id, 1, 1);
        let breakpoint = software_spec(1, 0x1000);
        let mut machine = SoftwareBreakpointStateMachine::new(session_id);
        let arm_plan = machine
            .plan_arm(
                stopped,
                breakpoint,
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            )
            .unwrap();
        let arm_ack = action_acknowledgement(arm_plan);
        machine.acknowledge_success(arm_ack).unwrap();
        assert!(matches!(
            machine.acknowledge_success(arm_ack),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::Duplicate { .. }
            ))
        ));
        let cleanup = machine.cleanup_evidence().unwrap();
        assert_eq!(cleanup.acknowledged_breakpoints.len(), 1);
        assert_eq!(
            cleanup.acknowledged_breakpoints[0].phase,
            SoftwareBreakpointPhase::Armed
        );
        assert!(cleanup.uncertain_operation.is_none());

        let mut stale = SoftwareBreakpointStateMachine::new(session_id);
        let first = stale
            .plan_arm(
                stopped,
                breakpoint,
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            )
            .unwrap();
        let first_ack = action_acknowledgement(first);
        stale.acknowledge_success(first_ack).unwrap();
        let remove = stale.plan_remove(breakpoint.id, stopped).unwrap();
        assert!(matches!(
            stale.acknowledge_success(first_ack),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::Duplicate { .. }
            ))
        ));
        assert_eq!(
            stale.cleanup_evidence().unwrap().uncertain_operation,
            Some(remove)
        );
    }

    #[test]
    fn exact_step_correlation_is_required_and_mismatch_poisons() {
        let session_id = session(1);
        let breakpoint = software_spec(1, 0x1000);
        let mut machine = SoftwareBreakpointStateMachine::new(session_id);
        arm(
            &mut machine,
            stop(session_id, 1, 1),
            breakpoint,
            SoftwareBreakpointPersistence::Persistent,
        );
        restore_persistent(&mut machine, breakpoint.id, stop(session_id, 3, 2));

        let mut wrong = step_acknowledgement(&machine, breakpoint.id, stop(session_id, 5, 3));
        wrong.restore_operation_id = SoftwareBreakpointOperationId::new(99).unwrap();
        assert_eq!(
            machine.acknowledge_single_step(wrong),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::PayloadMismatch
            ))
        );
        assert!(machine.is_poisoned());
        let cleanup = machine.cleanup_evidence().unwrap();
        assert_eq!(cleanup.acknowledged_breakpoints.len(), 1);
        assert_eq!(
            cleanup.acknowledged_breakpoints[0].phase,
            SoftwareBreakpointPhase::AwaitingSingleStep
        );
        assert!(cleanup.uncertain_operation.is_none());
    }

    #[test]
    fn nonadvancing_and_duplicate_step_acknowledgements_poison() {
        let session_id = session(1);
        let breakpoint = software_spec(1, 0x1000);
        let mut nonadvancing = SoftwareBreakpointStateMachine::new(session_id);
        arm(
            &mut nonadvancing,
            stop(session_id, 1, 1),
            breakpoint,
            SoftwareBreakpointPersistence::Persistent,
        );
        restore_persistent(&mut nonadvancing, breakpoint.id, stop(session_id, 3, 2));
        let same_stop = nonadvancing
            .breakpoint(breakpoint.id)
            .unwrap()
            .acknowledged_byte_stop_token;
        let bad_step = step_acknowledgement(&nonadvancing, breakpoint.id, same_stop);
        assert!(matches!(
            nonadvancing.acknowledge_single_step(bad_step),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::WrongStopToken { .. }
            ))
        ));

        let mut duplicate = SoftwareBreakpointStateMachine::new(session_id);
        arm(
            &mut duplicate,
            stop(session_id, 1, 1),
            breakpoint,
            SoftwareBreakpointPersistence::Persistent,
        );
        restore_persistent(&mut duplicate, breakpoint.id, stop(session_id, 3, 2));
        let step = step_acknowledgement(&duplicate, breakpoint.id, stop(session_id, 5, 3));
        duplicate.acknowledge_single_step(step).unwrap();
        assert!(matches!(
            duplicate.acknowledge_single_step(step),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::Duplicate { .. }
            ))
        ));
    }

    fn assert_uncertain_action(
        machine: &SoftwareBreakpointStateMachine,
        plan: SoftwareBreakpointActionPlan,
        acknowledged_phase: Option<SoftwareBreakpointPhase>,
    ) {
        let cleanup = machine.cleanup_evidence().expect("cleanup evidence");
        assert_eq!(cleanup.uncertain_operation, Some(plan));
        assert_eq!(
            cleanup
                .acknowledged_breakpoints
                .first()
                .map(|snapshot| snapshot.phase),
            acknowledged_phase
        );
    }

    fn poison_pending_plan(
        machine: &mut SoftwareBreakpointStateMachine,
        plan: SoftwareBreakpointActionPlan,
    ) {
        let mut acknowledgement = action_acknowledgement(plan);
        acknowledgement.replacement_byte ^= 1;
        assert!(matches!(
            machine.acknowledge_success(acknowledgement),
            Err(SoftwareBreakpointError::AcknowledgementRejected(
                SoftwareBreakpointAcknowledgementRejection::PayloadMismatch
            ))
        ));
    }

    #[test]
    fn cleanup_marks_arm_restore_rearm_and_remove_outcomes_uncertain() {
        let session_id = session(1);
        let breakpoint = software_spec(1, 0x1000);

        let (mut arm_machine, arm_plan, _) = pending_arm();
        poison_pending_plan(&mut arm_machine, arm_plan);
        assert_uncertain_action(&arm_machine, arm_plan, None);

        let mut restore_machine = SoftwareBreakpointStateMachine::new(session_id);
        arm(
            &mut restore_machine,
            stop(session_id, 1, 1),
            breakpoint,
            SoftwareBreakpointPersistence::Persistent,
        );
        let restore_plan = restore_machine
            .plan_restore_after_hit(breakpoint.id, stop(session_id, 3, 2))
            .unwrap();
        poison_pending_plan(&mut restore_machine, restore_plan);
        assert_uncertain_action(
            &restore_machine,
            restore_plan,
            Some(SoftwareBreakpointPhase::Armed),
        );

        let mut rearm_machine = SoftwareBreakpointStateMachine::new(session_id);
        arm(
            &mut rearm_machine,
            stop(session_id, 1, 1),
            breakpoint,
            SoftwareBreakpointPersistence::Persistent,
        );
        restore_persistent(&mut rearm_machine, breakpoint.id, stop(session_id, 3, 2));
        let step = step_acknowledgement(&rearm_machine, breakpoint.id, stop(session_id, 5, 3));
        rearm_machine.acknowledge_single_step(step).unwrap();
        let rearm_plan = rearm_machine
            .plan_rearm_after_single_step(breakpoint.id)
            .unwrap();
        poison_pending_plan(&mut rearm_machine, rearm_plan);
        assert_uncertain_action(
            &rearm_machine,
            rearm_plan,
            Some(SoftwareBreakpointPhase::ReadyToRearm),
        );

        let mut remove_machine = SoftwareBreakpointStateMachine::new(session_id);
        arm(
            &mut remove_machine,
            stop(session_id, 1, 1),
            breakpoint,
            SoftwareBreakpointPersistence::Persistent,
        );
        let remove_plan = remove_machine
            .plan_remove(breakpoint.id, stop(session_id, 1, 1))
            .unwrap();
        poison_pending_plan(&mut remove_machine, remove_plan);
        assert_uncertain_action(
            &remove_machine,
            remove_plan,
            Some(SoftwareBreakpointPhase::Armed),
        );
    }

    #[test]
    fn poison_is_permanent_and_preserves_first_evidence() {
        let (mut machine, plan, mut acknowledgement) = pending_arm();
        acknowledgement.expected_byte ^= 1;
        machine.acknowledge_success(acknowledgement).unwrap_err();
        let evidence = machine.poison_evidence().unwrap().clone();

        assert_eq!(
            machine.acknowledge_success(action_acknowledgement(plan)),
            Err(SoftwareBreakpointError::Poisoned)
        );
        assert_eq!(
            machine.plan_arm(
                stop(session(1), 2, 2),
                software_spec(2, 0x2000),
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            ),
            Err(SoftwareBreakpointError::Poisoned)
        );
        assert_eq!(machine.poison_evidence(), Some(&evidence));
    }

    #[test]
    fn cleanup_snapshots_are_deterministic_and_bounded() {
        let session_id = session(1);
        let stopped = stop(session_id, 1, 1);
        let mut machine = SoftwareBreakpointStateMachine::with_capacity(session_id, 3).unwrap();
        for id in [3, 1, 2] {
            arm(
                &mut machine,
                stopped,
                software_spec(id, 0x1000 + id * 0x10),
                SoftwareBreakpointPersistence::Persistent,
            );
        }
        let remove = machine
            .plan_remove(breakpoint_id(2), stopped)
            .expect("remove plan");
        poison_pending_plan(&mut machine, remove);
        let ids: Vec<_> = machine
            .cleanup_evidence()
            .unwrap()
            .acknowledged_breakpoints
            .iter()
            .map(|snapshot| snapshot.breakpoint.id.get())
            .collect();
        assert_eq!(ids, vec![1, 2, 3]);
        assert!(ids.len() <= machine.capacity());
    }

    #[test]
    fn operation_ids_are_nonzero_monotonic_and_checked_at_exhaustion() {
        assert_eq!(
            SoftwareBreakpointOperationId::new(0),
            Err(SoftwareBreakpointOperationIdError)
        );

        let session_id = session(1);
        let stopped = stop(session_id, 1, 1);
        let mut machine = SoftwareBreakpointStateMachine::with_capacity(session_id, 2).unwrap();
        machine.next_operation_id = Some(u64::MAX);
        let final_plan = machine
            .plan_arm(
                stopped,
                software_spec(1, 0x1000),
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            )
            .unwrap();
        assert_eq!(final_plan.operation_id().get(), u64::MAX);
        acknowledge(&mut machine, final_plan);
        assert_eq!(
            machine.plan_arm(
                stopped,
                software_spec(2, 0x2000),
                ORIGINAL,
                SoftwareBreakpointPersistence::Persistent,
            ),
            Err(SoftwareBreakpointError::OperationIdExhausted)
        );
        assert_eq!(machine.len(), 1);
    }
}
