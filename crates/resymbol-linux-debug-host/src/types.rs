//! Backend-neutral, `unsafe`-free types shared by the ptrace backend and the
//! session worker.
//!
//! Nothing in this module touches process memory or performs FFI. The real
//! implementation lives behind the [`PtraceOps`] trait so the worker
//! ([`crate::session::LinuxDebugSession`]) can be exercised deterministically
//! against an in-memory mock.

use thiserror::Error;

/// The x86-64 software-breakpoint byte (`INT3`).
pub const BREAKPOINT_BYTE: u8 = 0xCC;

/// Maximum bytes a single memory read/write request may cover.
pub const MAX_MEMORY_TRANSFER_BYTES: usize = 16 * 1024 * 1024;

/// Maximum concurrently armed software breakpoints in one session.
pub const MAX_SOFTWARE_BREAKPOINTS: usize = 4096;

/// Number of x86-64 hardware debug-register slots (`DR0`-`DR3`).
pub const HARDWARE_SLOTS: usize = 4;

/// USER-area byte offset of `offsetof(struct user, u_debugreg)` on x86-64.
///
/// The debug registers live in the ptrace USER area (accessed via
/// `PTRACE_PEEKUSER`/`PTRACE_POKEUSER`), not in general-purpose register space.
/// `u_debugreg[n]` sits at [`USER_DEBUGREG_OFFSET`]` + n * 8`. These offsets are
/// shared by the safe worker (which decides *which* register to touch) and the
/// real backend (which performs the FFI), so they live in this backend-neutral
/// module.
pub const USER_DEBUGREG_OFFSET: usize = 848;

/// USER-area byte offsets of `DR0`..=`DR3` (the four breakpoint address slots).
pub const DR_ADDRESS_OFFSETS: [usize; HARDWARE_SLOTS] = [
    USER_DEBUGREG_OFFSET,      // DR0 = 848
    USER_DEBUGREG_OFFSET + 8,  // DR1 = 856
    USER_DEBUGREG_OFFSET + 16, // DR2 = 864
    USER_DEBUGREG_OFFSET + 24, // DR3 = 872
];

/// USER-area byte offset of `DR6`, the debug *status* register.
pub const DR6_OFFSET: usize = USER_DEBUGREG_OFFSET + 48; // 896

/// USER-area byte offset of `DR7`, the debug *control* register.
pub const DR7_OFFSET: usize = USER_DEBUGREG_OFFSET + 56; // 904

/// The kind of a hardware breakpoint or watchpoint condition.
///
/// These map onto the two-bit `R/W` field of a `DR7` slot. x86-64 has no
/// pure *read-only* watchpoint: the hardware offers execute, write-only, and
/// read/write (data access) conditions. A GDB "read watchpoint" (`Z3`) is
/// therefore mapped to [`HardwareKind::ReadWrite`] by callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareKind {
    /// Break when the instruction at the address is about to execute
    /// (`R/W = 00`, length must be 1).
    Execute,
    /// Break when the data at the address is written (`R/W = 01`).
    Write,
    /// Break when the data at the address is read or written (`R/W = 11`).
    ReadWrite,
}

/// A complete x86-64 general-purpose and control register snapshot.
///
/// Field order and naming mirror `user_regs_struct` on Linux/x86-64 so the
/// backend can convert one-to-one without reinterpreting bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct X64Registers {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

impl X64Registers {
    /// The current instruction pointer (`RIP`).
    #[must_use]
    pub const fn instruction_pointer(&self) -> u64 {
        self.rip
    }

    /// Overwrite the instruction pointer (`RIP`).
    pub const fn set_instruction_pointer(&mut self, value: u64) {
        self.rip = value;
    }

    /// The current stack pointer (`RSP`).
    #[must_use]
    pub const fn stack_pointer(&self) -> u64 {
        self.rsp
    }
}

/// What a traced target did when it next stopped or exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopEvent {
    /// The target stopped in a ptrace-stop delivering `signal`.
    Stopped { signal: i32 },
    /// The target exited normally with `code`.
    Exited { code: i32 },
    /// The target was terminated by `signal`.
    Terminated { signal: i32 },
}

impl StopEvent {
    /// Whether this event is a `SIGTRAP` ptrace-stop (single-step or an
    /// executed `INT3`).
    #[must_use]
    pub const fn is_trap(&self) -> bool {
        matches!(self, Self::Stopped { signal } if *signal == SIGTRAP)
    }

    /// Whether the target is no longer alive.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Exited { .. } | Self::Terminated { .. })
    }
}

/// `SIGTRAP` signal number on Linux (stable across supported architectures).
pub const SIGTRAP: i32 = 5;

/// How a session ended when the worker relinquished the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The target reached a ptrace-stop; the worker retains control.
    Stopped(StopEvent),
    /// The target terminated; the session is finished.
    Finished(StopEvent),
    /// The target hit an armed software breakpoint; `RIP` has been rewound to
    /// the breakpoint address, which is reported here. Also reported for a
    /// hardware *execute* breakpoint, whose trap fires before the instruction
    /// runs (so `RIP` already sits at `address` and no rewind is needed).
    BreakpointHit { address: u64 },
    /// The target hit an armed hardware data watchpoint; the watched address is
    /// reported here. Unlike an execute stop, `RIP` points past the
    /// instruction that performed the access.
    WatchpointHit { address: u64 },
}

/// A specification for launching a new traced child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// Absolute path to the executable to launch.
    pub program: String,
    /// Full argument vector, including `argv[0]`.
    pub arguments: Vec<String>,
    /// When set, disable address-space randomization so RVAs are stable.
    pub disable_aslr: bool,
}

impl LaunchSpec {
    /// A launch of `program` with a single `argv[0]` and ASLR disabled.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        let program = program.into();
        Self {
            arguments: vec![program.clone()],
            program,
            disable_aslr: true,
        }
    }
}

/// A fault raised by the ptrace backend or by the safe worker logic.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostError {
    /// A raw ptrace/`fork`/`exec`/`waitpid` call failed with this `errno`.
    #[error("ptrace operation `{operation}` failed with errno {errno}")]
    Syscall {
        /// The failing operation name.
        operation: &'static str,
        /// The captured `errno`.
        errno: i32,
    },
    /// A launch could not be prepared (e.g. an interior NUL in an argument).
    #[error("invalid launch specification: {0}")]
    InvalidLaunch(String),
    /// A memory transfer exceeded [`MAX_MEMORY_TRANSFER_BYTES`].
    #[error("memory transfer of {requested} bytes exceeds the {limit}-byte limit")]
    TransferTooLarge {
        /// Bytes requested.
        requested: usize,
        /// The enforced ceiling.
        limit: usize,
    },
    /// Compare-before-write found a byte other than the expected value.
    #[error(
        "memory at {address:#x} held {found:#04x} but {expected:#04x} was required before writing"
    )]
    UnexpectedByte {
        /// The address inspected.
        address: u64,
        /// The byte that was found.
        found: u8,
        /// The byte the caller required.
        expected: u8,
    },
    /// A breakpoint address was already armed.
    #[error("a software breakpoint is already armed at {address:#x}")]
    BreakpointExists {
        /// The duplicate address.
        address: u64,
    },
    /// A breakpoint address was not armed.
    #[error("no software breakpoint is armed at {address:#x}")]
    BreakpointMissing {
        /// The missing address.
        address: u64,
    },
    /// The software-breakpoint capacity was exhausted.
    #[error("the {limit}-breakpoint capacity is exhausted")]
    BreakpointCapacity {
        /// The enforced ceiling.
        limit: usize,
    },
    /// All four hardware debug-register slots (`DR0`-`DR3`) are in use.
    #[error("no free hardware debug-register slot (all {limit} are in use)")]
    NoHardwareSlot {
        /// The number of hardware slots.
        limit: usize,
    },
    /// A hardware breakpoint/watchpoint was already armed at this address.
    #[error("a hardware breakpoint or watchpoint is already armed at {address:#x}")]
    HardwareBreakpointExists {
        /// The duplicate address.
        address: u64,
    },
    /// No hardware breakpoint/watchpoint was armed at this address.
    #[error("no hardware breakpoint or watchpoint is armed at {address:#x}")]
    HardwareBreakpointMissing {
        /// The missing address.
        address: u64,
    },
    /// A watchpoint length was not one of the hardware-supported `{1, 2, 4, 8}`
    /// (or an execute breakpoint requested a length other than 1).
    #[error("invalid hardware watchpoint length {length}; must be 1, 2, 4, or 8")]
    InvalidWatchpointLength {
        /// The rejected length.
        length: u64,
    },
    /// An operation required a live, stopped target but the target had exited.
    #[error("the target is no longer alive")]
    TargetNotAlive,
}

/// The narrow, safe ptrace primitive surface the worker drives.
///
/// The real implementation ([`crate::linux::PtraceBackend`]) performs FFI; the
/// worker never calls libc directly. Addresses are absolute virtual addresses
/// in the target. Every method requires the target to be in a ptrace-stop
/// except [`PtraceOps::wait`].
pub trait PtraceOps {
    /// The target process id.
    fn pid(&self) -> i32;

    /// Resume the target, delivering `signal` (0 = none) and running until the
    /// next stop.
    fn cont(&mut self, signal: i32) -> Result<(), HostError>;

    /// Execute exactly one instruction, delivering `signal` (0 = none).
    fn single_step(&mut self, signal: i32) -> Result<(), HostError>;

    /// Block until the target next stops, exits, or is terminated.
    fn wait(&mut self) -> Result<StopEvent, HostError>;

    /// Read the full register file from the stopped target.
    fn read_registers(&mut self) -> Result<X64Registers, HostError>;

    /// Write the full register file to the stopped target.
    fn write_registers(&mut self, registers: &X64Registers) -> Result<(), HostError>;

    /// Read `len` bytes starting at `address` from the target.
    fn read_memory(&mut self, address: u64, len: usize) -> Result<Vec<u8>, HostError>;

    /// Write `bytes` starting at `address` into the target, bypassing page
    /// protections (so executable text can be patched for breakpoints).
    fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), HostError>;

    /// Read one word from the ptrace USER area at byte `offset` (the real
    /// backend uses `PTRACE_PEEKUSER`). Used for the debug registers
    /// (`DR0`-`DR7`); see [`DR_ADDRESS_OFFSETS`], [`DR6_OFFSET`], [`DR7_OFFSET`].
    fn peek_user(&mut self, offset: usize) -> Result<u64, HostError>;

    /// Write one word into the ptrace USER area at byte `offset` (the real
    /// backend uses `PTRACE_POKEUSER`). Used for the debug registers.
    fn poke_user(&mut self, offset: usize, value: u64) -> Result<(), HostError>;

    /// Detach, leaving the target running.
    fn detach(&mut self) -> Result<(), HostError>;

    /// Kill the target.
    fn kill(&mut self) -> Result<(), HostError>;
}
