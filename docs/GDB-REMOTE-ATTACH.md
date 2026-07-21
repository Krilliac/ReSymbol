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
    exclusively owns TcpStream and GdbRemoteClient<TcpTransport>
```

- Every controller entry point is non-blocking and runs on the egui thread.
- Connect, packet framing, acknowledgement waits, and replies run only on the
  named remote-I/O thread.
- Connect and socket I/O have finite deadlines. Dropping the controller closes
  its request/result channels and joins the sole owner thread.
- One request may be outstanding. A second request fails closed as busy rather
  than queuing stale target operations.
- A protocol or transport error discards the connection because the packet
  stream may no longer be synchronized.

## Security and evidence boundary

- The default endpoint is `127.0.0.1:1234`.
- Endpoints must be numeric. A non-loopback address requires an explicit UI
  opt-in for that Workbench process.
- The current policy exposes only raw register reads and memory reads of at
  most 256 bytes.
- Writes, breakpoints, continue, and step are absent from both the UI routing
  and the advertised Workbench capability policy.
- Endpoint text, feature replies, addresses, register packets, and memory bytes
  are ephemeral UI state. They are not serialized into preferences, `.resym`
  packages, review ledgers, or repository artifacts.
- Exporting a sanitized observation remains a separate explicit workflow.

## Deliberately deferred

The RSP crate currently lacks architecture-neutral target-description support
and cancellable execution control. Before the Workbench can safely expose more
than raw inspection, the protocol layer should provide:

1. `qXfer:features:read:target.xml` retrieval with bounded packet assembly.
2. Parsed architecture/register metadata, including an R5900 description.
3. Breakpoint requests with an explicit target instruction-size `kind`.
4. Asynchronous interrupt and cancellation so a long-running continue cannot
   monopolize the capacity-one session or delay application shutdown.
5. Explicit write/control authorization that remains separate from connection
   establishment.

The Workbench controller should consume those APIs once they exist rather than
growing a second XML parser or a competing RSP state machine.
