# Workbench outbound GDB/RSP attach

The Workbench can open one inspection-only TCP connection to a GDB Remote
Serial Protocol target. Its initial use is a PCSX2 guest-state endpoint, but
the controller has no PCSX2 dependency.

## Ownership and thread affinity

```text
egui / WorkbenchApp
    owns RemoteSessionController and ephemeral presentation state
             |
             | capacity-one request channel
             v
resymbol-gdb-remote-client thread
    exclusively owns TcpStream, GdbRemoteClient<TcpTransport>, and target.xml
```

- Every controller entry point is non-blocking and runs on the egui thread.
- Connect, packet framing, acknowledgement waits, and replies run only on the
  named remote-I/O thread.
- Connect has a finite deadline. Every public RSP operation has one two-second
  absolute deadline covering request, acknowledgement, and reply; the complete
  multi-chunk `target.xml` fetch shares one deadline. The TCP transport reduces
  each blocking socket timeout to the remaining operation time. A cloned socket
  handle lets the egui controller interrupt pending I/O without taking socket
  ownership away from the remote-I/O thread.
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
  opt-in for that Workbench process.
- A connection becomes visible only after `qSupported` and a bounded
  `qXfer:features:read:target.xml` fetch succeed. Target XML is mandatory for
  this typed surface; missing architecture or register layout fails closed.
- The current policy exposes only schema-validated raw register reads and
  memory reads of at most 256 bytes. Every `g` reply must have the exact byte
  length declared by the connected target description.
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
- Connected-target identity, features, target metadata, register previews, and
  memory previews are scrubbed on a new connection attempt, disconnect,
  cancellation, worker loss, or connection loss so observations cannot be
  attributed to a later endpoint.
- Capability badges describe the read-only routes implemented by Workbench;
  they do not claim that a disconnected or unprobed target supports a route.
- Exporting a sanitized observation remains a separate explicit workflow.

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
   ephemeral, schema-validated raw preview.

The displayed software-breakpoint kind is descriptor metadata only. Workbench
does not route breakpoint, register-write, memory-write, continue, or step
commands.
