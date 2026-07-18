//! GDB Remote Serial Protocol (RSP) for ReSymbol.
//!
//! This crate speaks the same wire protocol GDB and gdbserver use, in both
//! directions and over two kinds of link:
//!
//! * As a **server** ([`GdbStubServer`], [`serve_one`]) it exposes a
//!   [`RemoteTarget`] — most usefully the Linux ptrace host via
//!   [`PtraceRemoteTarget`] — to any GDB-compatible front end (gdb, lldb, IDA,
//!   Ghidra), so those tools can drive a live ReSymbol debug target.
//! * As a **client** ([`GdbRemoteClient`]) it drives a remote stub such as a
//!   QEMU `gdbstub` or a kernel debug stub.
//!
//! Both roles run over any [`Transport`]: a TCP socket ([`TcpTransport`],
//! [`TcpServerListener`]) or a raw serial line ([`SerialTransport`], Unix
//! only). The protocol codec lives in [`protocol`] and is heavily unit-tested;
//! it performs no I/O.
//!
//! # Safety
//!
//! The workspace forbids `unsafe` by default. This crate is a deliberately
//! narrow exception: the **only** `unsafe` code is in [`serial`], where libc
//! `termios` calls switch a tty into raw mode, each block carrying a
//! `// SAFETY:` justification. Everything else — framing, transports, the
//! server and client loops, and the ptrace adapter — is entirely safe.

pub mod client;
pub mod core_dump;
pub mod protocol;
pub mod server;
pub mod target;
pub mod transport;

#[cfg(unix)]
pub mod serial;

#[cfg(target_os = "linux")]
pub mod ptrace_target;

pub use client::GdbRemoteClient;
pub use core_dump::{CoreClass, CoreDump, CoreDumpError, CoreDumpTarget, CoreEndian, CoreRegion};
pub use protocol::{PacketEvent, PacketReader, encode_packet};
pub use server::{GdbStubServer, serve_one};
pub use target::{
    AMD64_GPACKET_BYTES, Amd64CoreRegisters, RemoteTarget, StopReply, TargetError,
    amd64_gpacket_to_registers, amd64_registers_to_gpacket,
};
pub use transport::{
    MemoryStream, StreamTransport, TcpServerListener, TcpTransport, Transport, memory_pair,
};

#[cfg(unix)]
pub use serial::SerialTransport;

#[cfg(target_os = "linux")]
pub use ptrace_target::PtraceRemoteTarget;
