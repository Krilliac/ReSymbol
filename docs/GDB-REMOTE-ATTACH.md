# Workbench outbound GDB/RSP attach

The Workbench can open one experimental inspection-only TCP connection to a GDB
Remote Serial Protocol target. Its initial use is a PCSX2 guest-state endpoint,
but the controller has no PCSX2 dependency. This is a transport-specific,
read-only, best-effort observer, not an authenticated `resymbol-debugger`
session or an execution-control bridge.

## Ownership and thread affinity

```text
egui / WorkbenchApp
    owns RemoteSessionController and ephemeral presentation state
    holds only a cloned shutdown handle for interrupting pending I/O
             |
             | capacity-one request channel
             v
resymbol-gdb-remote-client thread
    exclusively owns the protocol read/write stream,
    GdbRemoteClient<TcpTransport>, and target.xml
```

- Every controller entry point is non-blocking and runs on the egui thread.
- Connect, packet framing, acknowledgement waits, and replies run only on the
  named remote-I/O thread.
- Connect has a finite deadline. Every public RSP operation has one two-second
  absolute deadline covering request, acknowledgement, and reply; the complete
  multi-chunk `target.xml` fetch shares one deadline. The TCP transport reduces
  each blocking socket timeout to the remaining operation time. A cloned socket
  handle lets the egui controller interrupt pending I/O without taking protocol
  read/write ownership away from the remote-I/O thread. The controller has no
  operation that can use this clone for RSP traffic; it is shutdown-only.
- Cancel remains available while an operation is pending. Cancellation closes
  the connection, ignores that request's stale completion, and scrubs target
  observations.
- Dropping the controller signals cancellation, closes its request/result
  channels, and detaches the sole owner thread; UI teardown never joins a
  network thread.
- One request may be outstanding. A second request fails closed as busy rather
  than queuing stale target operations.
- A protocol or transport error discards the connection because the packet
  stream may no longer be synchronized.

## Security and evidence boundary

- The default endpoint is `127.0.0.1:1234`.
- Endpoints must be numeric. A non-loopback address requires an explicit UI
  opt-in for that Workbench process. Neither the opt-in nor TCP connection
  authenticates the RSP peer or target process.
- This observer does not enter the `resymbol-debugger` session/token layer.
  Connection establishment creates no `SessionId`, stopped-state token,
  one-use lease, capability authority, attestation, or cleanup evidence.
- A connection becomes visible only after `qSupported` and a bounded
  `qXfer:features:read:target.xml` fetch succeed. Target XML is mandatory for
  this typed surface; missing architecture or register layout fails closed.
- The current policy exposes only schema-validated raw register reads, memory
  reads of at most 256 bytes, and one typed EE program-counter read. Every `g`
  reply must have the exact byte length declared by the connected target
  description.
- A target declaring `mips:5900` must structurally match ReSymbol's canonical
  109-register, 708-byte PS2 EE schema, including register type and group
  metadata. Near-matches are rejected rather than silently narrowing the EE's
  128-bit GPR, HI, or LO state.
- Writes, breakpoints, continue, and step are absent from both the UI routing
  and the advertised Workbench capability policy.
- Endpoint text, feature replies, derived target metadata, addresses, register
  packets, and memory bytes are ephemeral UI state. The complete target XML
  and parsed register description remain worker-owned. None are serialized into
  preferences, `.resym` packages, review ledgers, or repository artifacts.
- Connected-target identity, features, target metadata, register previews,
  memory previews, and the EE program-counter preview are scrubbed on a new
  connection attempt, disconnect, cancellation, worker loss, connection loss,
  or session replacement so observations cannot be attributed to a later
  endpoint. A result that arrives for an already-cancelled or superseded
  request never reaches presentation state.
- Capability badges describe the read-only routes implemented by Workbench;
  they do not claim that a disconnected or unprobed target supports a route.
- There is no route from these observations to project state, `.resym`
  packages, review ledgers, exports, or evidence publication. They cannot
  authorize launch, attach, write, breakpoint, continue, step, or any other
  live action. Any future sanitized export is a separate explicit workflow and
  must not inherit authority from this connection.

## Last-observed EE program counter

One explicit, capacity-one, read-only operation reads the EE program counter.

- The route is offered only for a live connection whose target description
  matched the exact canonical 109-register, 708-byte PS2 EE schema. Every other
  target — including a `mips:5900` near-match and any non-EE architecture — has
  no button and fails closed on submission.
- The schema is enforced twice. The egui-side gate refuses to submit, and the
  remote-I/O worker re-derives the same decision from its own retained target
  description before touching the socket, so the UI gate is never the sole
  enforcement point. Both resolve "canonical EE schema" through one shared
  structural comparison.
- The worker reads `g`, validates the reply against the connected description,
  re-checks the exact canonical 708-byte length, and parses it with the
  protocol crate's `ps2_ee_gpacket_to_registers`. Workbench does not carry a
  second EE register decoder.
- Only the typed `u32` program counter crosses the worker/UI channel. The raw
  packet and every other decoded register, including the EE's 128-bit GPR, HI,
  and LO state, stay worker-local and are dropped there.
- The value is displayed as a fixed-width `0xXXXXXXXX` literal in the remote
  session panel's **Last observed EE PC** row. It is one best-effort snapshot,
  never a claim that the target is still stopped there, and is ephemeral UI
  state on the same terms as every other observation above.
- That row is the value's only presentation. The notice announcing a completed
  read is deliberately value-free and identical for every observed program
  counter. Notices are forwarded to the bounded Workbench activity log and to
  the companion console, and no session scrub can reach either, so a notice
  carrying the value would outlive every scrub this route promises and stay
  attributable after the connection it came from is gone.
- The operation is a strict narrowing of the existing read-register route: it
  issues the same `g` read and adds no capability. It is a single explicit
  read, never a poll, and carries no execution control, memory or instruction
  read, disassembly, breakpoint, write, export, or persistence.
- A worker-side schema rejection does not discard the connection, because
  nothing was read and the packet stream is still synchronized. A protocol or
  transport failure discards it on the same terms as any other operation.

## Deliberately deferred

The protocol crate now owns bounded target-description parsing, exact register
packet sizing, recognized byte order, and architecture-specific software
breakpoint kinds. Workbench consumes those APIs and does not carry a second XML
parser or RSP state machine. Mutating or execution-control UI remains deferred
until all of the following exist:

1. Asynchronous target interrupt and stop-state handling so continue cannot
   monopolize the capacity-one session or delay application shutdown.
2. Explicit write/control authorization separate from connection
   establishment and the current read-only routing policy.
3. Typed register interpretation and evidence-export policy beyond the current
   ephemeral, schema-validated raw preview and the single typed EE
   program-counter read described above. Broader typed decoding, any polled or
   continuously refreshed view, instruction reads, and disassembly are not part
   of this surface.

The displayed software-breakpoint kind is descriptor metadata only. Workbench
does not route breakpoint, register-write, memory-write, continue, or step
commands.
