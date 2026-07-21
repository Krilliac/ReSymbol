# GDB remote targets

`resymbol-gdb-remote` keeps RSP framing separate from target ownership. A
`GdbStubServer` owns only its transport and packet limits; the caller owns the
`RemoteTarget` and decides which thread may read or mutate target state. An
emulator adapter must therefore marshal requests onto its emulation thread
rather than exposing live guest state directly to the socket thread.

Targets may return a `TargetDescription` to enable
`qXfer:features:read:target.xml`. Descriptions declare the exact decoded
`g`/`G` byte count and software-breakpoint kind. Undescribed legacy targets
retain the previous one-byte breakpoint behavior and do not advertise target
XML.

## PlayStation 2 EE schema

`PS2_EE_TARGET_DESCRIPTION` identifies `mips:5900` and uses the established GDB
MIPS packet order. Every multi-byte field is little-endian and registers are
encoded by increasing `regnum`:

| Registers | Regnums | Width | Byte offsets |
|---|---:|---:|---:|
| `r0..r31` low halves | 0-31 | 64 | 0-255 |
| `status` | 32 | 32 | 256-259 |
| `lo`, `hi` low halves | 33-34 | 64 | 260-275 |
| `badvaddr`, `cause`, `pc` | 35-37 | 32 | 276-287 |
| `f0..f31`, `fcsr`, `fir` | 38-71 | 32 | 288-423 |
| `epc` | 72 | 32 | 424-427 |
| `r0_upper..r31_upper` | 73-104 | 64 | 428-683 |
| `lo_upper`, `hi_upper` | 105-106 | 64 | 684-699 |
| `sa`, `fpu_acc` | 107-108 | 32 | 700-707 |

GDB's standard MIPS feature permits 32- or 64-bit core registers, while the
EE physically retains 128-bit GPR, HI, and LO state. The custom
`org.openomega.ps2.ee` feature carries every upper half, so the 708-byte packet
round-trips the complete values without truncation. `Z0`/`z0` use kind `4`,
the fixed EE instruction size.

Target XML has no endian element. ReSymbol recognizes this complete named
schema as little-endian; it does not infer endian from arbitrary MIPS XML.
External GDB sessions without a loaded little-endian PS2 ELF may need
`set endian little` before connecting to the remote endpoint.

## Bounds and unsupported behavior

The default packet payload is 4 KiB, one memory transaction is limited to 2
KiB, and one assembled target description is limited to 256 KiB. Declared
memory lengths must match payloads, register packets must match a described
layout exactly, and non-final `qXfer` chunks must make progress. The server does
not advertise asynchronous interrupt/stop support; `vCont?` reports only the
implemented continue and step actions.

Client operations have one finite 30-second deadline spanning request framing,
acknowledgement, and reply. A multi-chunk target-description fetch shares one
deadline across every `qXfer` request, so a trickling peer cannot refresh it.
`TcpTransport::from_connected_stream` shrinks the socket read/write timeout to
the remaining deadline before each blocking call. Generic transports are
clock-checked between calls and may overrun only by their own blocking-I/O
timeout; callers needing strict cancellation must provide a timeout-aware
transport.

## Provenance

The user-owned GDB endpoint proposed in
[MaNGOS Zero server PR #406](https://github.com/mangoszero/server/pull/406) is
the conceptual lineage for applying RSP to a live application and for keeping
socket I/O separate from target-state execution. The Rust codec, limits,
target-description parser, register layouts, and tests in ReSymbol are an
independent implementation against the public GDB RSP specification; no MaNGOS
or DuetOS source was copied. This distinction preserves ReSymbol's existing
MIT OR Apache-2.0 licensing and keeps any later emulator adapter independently
reviewable.
