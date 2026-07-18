//! The real Linux ptrace backend. **This is the only module in the crate that
//! contains `unsafe` code.** Every FFI call is wrapped with a `// SAFETY:`
//! justification; the safe worker in [`crate::session`] never calls libc.

use std::ffi::CString;
use std::io;
use std::ptr;

use libc::{c_void, pid_t, user_regs_struct};

use crate::types::{HostError, LaunchSpec, PtraceOps, StopEvent, X64Registers};

/// Bytes per ptrace `PEEKTEXT`/`POKETEXT` word on a 64-bit target.
const WORD: usize = 8;

/// A live ptrace-controlled child. Owns the target pid and drives it through
/// the raw ptrace request interface.
#[derive(Debug)]
pub struct PtraceBackend {
    pid: pid_t,
}

impl PtraceBackend {
    /// Launch `spec` as a new traced child, stopped at its `execve` entry
    /// (before the first user instruction runs).
    pub fn launch(spec: &LaunchSpec) -> Result<Self, HostError> {
        // Build all C strings BEFORE forking so the child performs no
        // allocation between fork and exec (async-signal-safety).
        let program = CString::new(spec.program.as_bytes())
            .map_err(|_| HostError::InvalidLaunch("program path contains a NUL".to_owned()))?;
        let mut argv_owned = Vec::with_capacity(spec.arguments.len());
        for argument in &spec.arguments {
            argv_owned.push(
                CString::new(argument.as_bytes())
                    .map_err(|_| HostError::InvalidLaunch("argument contains a NUL".to_owned()))?,
            );
        }
        let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|s| s.as_ptr()).collect();
        argv.push(ptr::null());
        let disable_aslr = spec.disable_aslr;

        // SAFETY: `fork` is async-signal-safe. It returns 0 in the child and the
        // child pid in the parent, or -1 on error.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(last_errno("fork"));
        }
        if pid == 0 {
            // Child: only async-signal-safe calls until exec. Any failure exits
            // immediately with a distinct status; no unwinding, no allocation.
            // SAFETY: PTRACE_TRACEME takes no memory arguments and requests that
            // this process be traced by its parent.
            unsafe {
                if libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    ptr::null_mut::<c_void>(),
                    ptr::null_mut::<c_void>(),
                ) < 0
                {
                    libc::_exit(126);
                }
                if disable_aslr {
                    // Best-effort determinism; ignore failure.
                    libc::personality(libc::ADDR_NO_RANDOMIZE as libc::c_ulong);
                }
                libc::execvp(program.as_ptr(), argv.as_ptr());
                // Only reached if exec failed.
                libc::_exit(127);
            }
        }

        let mut backend = Self { pid };
        // Consume the initial exec ptrace-stop so the caller starts stopped.
        match backend.wait()? {
            StopEvent::Stopped { .. } => Ok(backend),
            terminal => Err(HostError::Syscall {
                operation: "launch: unexpected initial exit",
                errno: terminal_errno(terminal),
            }),
        }
    }

    /// Attach to an already-running process, stopping it.
    pub fn attach(pid: i32) -> Result<Self, HostError> {
        // SAFETY: PTRACE_ATTACH stops the target `pid`; no memory arguments.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_ATTACH,
                pid,
                ptr::null_mut::<c_void>(),
                ptr::null_mut::<c_void>(),
            )
        };
        if rc < 0 {
            return Err(last_errno("PTRACE_ATTACH"));
        }
        let mut backend = Self { pid };
        backend.wait()?;
        Ok(backend)
    }

    fn peek_word(&self, address: u64) -> Result<u64, HostError> {
        // Clear errno: PEEKTEXT returns the word as the return value, so -1 is
        // ambiguous and must be disambiguated via errno.
        // SAFETY: writing errno is always sound; libc exposes it via a helper.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: PEEKTEXT reads one word at `address` from the traced target's
        // address space; the pointer is used only by the kernel, not us.
        let value = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKTEXT,
                self.pid,
                address as *mut c_void,
                ptr::null_mut::<c_void>(),
            )
        };
        if value == -1 {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno != 0 {
                return Err(HostError::Syscall {
                    operation: "PTRACE_PEEKTEXT",
                    errno,
                });
            }
        }
        Ok(value as u64)
    }

    fn poke_word(&self, address: u64, word: u64) -> Result<(), HostError> {
        // SAFETY: POKETEXT writes one word at `address` into the traced target,
        // bypassing page protections; both pointers are consumed by the kernel.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_POKETEXT,
                self.pid,
                address as *mut c_void,
                word as *mut c_void,
            )
        };
        if rc < 0 {
            return Err(last_errno("PTRACE_POKETEXT"));
        }
        Ok(())
    }
}

impl PtraceOps for PtraceBackend {
    fn pid(&self) -> i32 {
        self.pid
    }

    fn cont(&mut self, signal: i32) -> Result<(), HostError> {
        // SAFETY: PTRACE_CONT resumes the stopped target, delivering `signal`.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_CONT,
                self.pid,
                ptr::null_mut::<c_void>(),
                signal as *mut c_void,
            )
        };
        if rc < 0 {
            return Err(last_errno("PTRACE_CONT"));
        }
        Ok(())
    }

    fn single_step(&mut self, signal: i32) -> Result<(), HostError> {
        // SAFETY: PTRACE_SINGLESTEP executes one instruction in the target.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_SINGLESTEP,
                self.pid,
                ptr::null_mut::<c_void>(),
                signal as *mut c_void,
            )
        };
        if rc < 0 {
            return Err(last_errno("PTRACE_SINGLESTEP"));
        }
        Ok(())
    }

    fn wait(&mut self) -> Result<StopEvent, HostError> {
        let mut status: libc::c_int = 0;
        // SAFETY: `waitpid` writes the child status through `&mut status`.
        let rc = unsafe { libc::waitpid(self.pid, &mut status, 0) };
        if rc < 0 {
            return Err(last_errno("waitpid"));
        }
        Ok(decode_status(status))
    }

    fn read_registers(&mut self) -> Result<X64Registers, HostError> {
        let mut regs = empty_user_regs();
        // SAFETY: PTRACE_GETREGS fills the `user_regs_struct` we point at; the
        // struct is fully owned and correctly sized for this target.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                self.pid,
                ptr::null_mut::<c_void>(),
                (&mut regs as *mut user_regs_struct).cast::<c_void>(),
            )
        };
        if rc < 0 {
            return Err(last_errno("PTRACE_GETREGS"));
        }
        Ok(from_user_regs(&regs))
    }

    fn write_registers(&mut self, registers: &X64Registers) -> Result<(), HostError> {
        let mut regs = to_user_regs(registers);
        // SAFETY: PTRACE_SETREGS reads the `user_regs_struct` we point at and
        // installs it into the stopped target.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGS,
                self.pid,
                ptr::null_mut::<c_void>(),
                (&mut regs as *mut user_regs_struct).cast::<c_void>(),
            )
        };
        if rc < 0 {
            return Err(last_errno("PTRACE_SETREGS"));
        }
        Ok(())
    }

    fn read_memory(&mut self, address: u64, len: usize) -> Result<Vec<u8>, HostError> {
        let mut out = Vec::with_capacity(len);
        let mut read = 0usize;
        while read < len {
            let current = address.wrapping_add(read as u64);
            let aligned = current & !((WORD as u64) - 1);
            let start = (current - aligned) as usize;
            let word = self.peek_word(aligned)?.to_ne_bytes();
            let take = (WORD - start).min(len - read);
            out.extend_from_slice(&word[start..start + take]);
            read += take;
        }
        Ok(out)
    }

    fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), HostError> {
        let mut written = 0usize;
        while written < bytes.len() {
            let current = address.wrapping_add(written as u64);
            let aligned = current & !((WORD as u64) - 1);
            let start = (current - aligned) as usize;
            let mut word = self.peek_word(aligned)?.to_ne_bytes();
            let take = (WORD - start).min(bytes.len() - written);
            word[start..start + take].copy_from_slice(&bytes[written..written + take]);
            self.poke_word(aligned, u64::from_ne_bytes(word))?;
            written += take;
        }
        Ok(())
    }

    fn detach(&mut self) -> Result<(), HostError> {
        // SAFETY: PTRACE_DETACH releases the target, leaving it running.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                self.pid,
                ptr::null_mut::<c_void>(),
                ptr::null_mut::<c_void>(),
            )
        };
        if rc < 0 {
            return Err(last_errno("PTRACE_DETACH"));
        }
        Ok(())
    }

    fn kill(&mut self) -> Result<(), HostError> {
        // SAFETY: sending SIGKILL to the target pid terminates it.
        let rc = unsafe { libc::kill(self.pid, libc::SIGKILL) };
        if rc < 0 {
            return Err(last_errno("kill"));
        }
        Ok(())
    }
}

fn decode_status(status: libc::c_int) -> StopEvent {
    if libc::WIFEXITED(status) {
        StopEvent::Exited {
            code: libc::WEXITSTATUS(status),
        }
    } else if libc::WIFSIGNALED(status) {
        StopEvent::Terminated {
            signal: libc::WTERMSIG(status),
        }
    } else {
        // Stopped (WIFSTOPPED); report the delivering signal.
        StopEvent::Stopped {
            signal: libc::WSTOPSIG(status),
        }
    }
}

fn empty_user_regs() -> user_regs_struct {
    // SAFETY: `user_regs_struct` is plain-old-data (integer fields only), so an
    // all-zero bit pattern is a valid, fully-initialized value.
    unsafe { std::mem::zeroed() }
}

fn from_user_regs(regs: &user_regs_struct) -> X64Registers {
    X64Registers {
        r15: regs.r15,
        r14: regs.r14,
        r13: regs.r13,
        r12: regs.r12,
        rbp: regs.rbp,
        rbx: regs.rbx,
        r11: regs.r11,
        r10: regs.r10,
        r9: regs.r9,
        r8: regs.r8,
        rax: regs.rax,
        rcx: regs.rcx,
        rdx: regs.rdx,
        rsi: regs.rsi,
        rdi: regs.rdi,
        orig_rax: regs.orig_rax,
        rip: regs.rip,
        cs: regs.cs,
        eflags: regs.eflags,
        rsp: regs.rsp,
        ss: regs.ss,
        fs_base: regs.fs_base,
        gs_base: regs.gs_base,
        ds: regs.ds,
        es: regs.es,
        fs: regs.fs,
        gs: regs.gs,
    }
}

fn to_user_regs(regs: &X64Registers) -> user_regs_struct {
    let mut out = empty_user_regs();
    out.r15 = regs.r15;
    out.r14 = regs.r14;
    out.r13 = regs.r13;
    out.r12 = regs.r12;
    out.rbp = regs.rbp;
    out.rbx = regs.rbx;
    out.r11 = regs.r11;
    out.r10 = regs.r10;
    out.r9 = regs.r9;
    out.r8 = regs.r8;
    out.rax = regs.rax;
    out.rcx = regs.rcx;
    out.rdx = regs.rdx;
    out.rsi = regs.rsi;
    out.rdi = regs.rdi;
    out.orig_rax = regs.orig_rax;
    out.rip = regs.rip;
    out.cs = regs.cs;
    out.eflags = regs.eflags;
    out.rsp = regs.rsp;
    out.ss = regs.ss;
    out.fs_base = regs.fs_base;
    out.gs_base = regs.gs_base;
    out.ds = regs.ds;
    out.es = regs.es;
    out.fs = regs.fs;
    out.gs = regs.gs;
    out
}

fn last_errno(operation: &'static str) -> HostError {
    HostError::Syscall {
        operation,
        errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
    }
}

const fn terminal_errno(event: StopEvent) -> i32 {
    match event {
        StopEvent::Exited { code } => code,
        StopEvent::Terminated { signal } => signal,
        StopEvent::Stopped { signal } => signal,
    }
}
