# Debugger and sandbox architecture

## Status

ReSymbol currently implements the non-executing foundation for debugger and sandbox work:

- a complete preferred-image partition for supported PE32+ inputs that validates file/section
  alignment and distinguishes exact file backing, virtual zero-fill, loader padding, and image gaps;
- exact-binary-bound protection findings for entry-point layout, TLS-before-entry behavior,
  anti-debug imports, common packer section names, high-entropy samples, and writable/executable
  sections;
- backend-neutral target, capability, command, event, state-token, breakpoint, memory-read, and
  compare-before-write memory-mutation contracts;
- a bounded control/raw-byte frame format, direction- and identity-checked handshake, exact protocol
  version binding, strict typed command/event codec, and single-owner host-client seam;
- a deterministic in-memory host that drives the real session and sandbox reducers for integration
  tests without reading an artifact, opening a process, or executing target code; and
- sandbox policy, attestation, failure, lifecycle, resource-limit, and cleanup-receipt data models.

The debugger crate also exposes a bounded provider-readiness service. It is discovery only: it
cannot execute a target, create an AppContainer profile, enable a Windows feature, create a VM, or
provision any other resource. A readiness result means only that a caller may attempt provisioning;
the suspended target still needs the exact policy/provider/build attestation described below.

The Windows debugger host process, pipe transport, AppContainer provider, Hyper-V provider, guest
agent, live process attach, breakpoint engine, register access, memory access, and instruction
editing are not implemented. `InMemoryDebugHost` is a protocol test double, not a security boundary
or a platform provider. The current types and UI must not be described as a working malware sandbox
or live debugger.

## Ownership and thread affinity

The intended ownership chain is:

```text
Workbench UI thread
  -> one DebugHostClient (owns helper process and bounded pipes)
    -> resymbol-debugger-host helper
      -> one SessionWorker thread
        -> one selected provider/backend
          -> opaque platform RAII handles
```

- The UI owns product state and never receives a platform handle.
- `DebugHostClient` is deliberately `!Send` and `!Sync`. One connection worker constructs and owns
  it; UI code uses bounded queues. Its synchronous exchange calls are never made on the UI thread.
- One client owns one connection and at most one session. It cannot release a session before the
  reducer reports `Closed`, and it cannot disconnect while it still owns that session.
- One `SessionWorker` owns every debug event, target process/thread, Job, profile, staging directory,
  provider, and cleanup transition for a session.
- Provider and debug-event methods are worker-thread-only and non-hot-reloadable until close and
  cleanup complete.
- The backend-neutral crate forbids unsafe code. Platform FFI belongs in a narrow Windows provider
  crate whose public types are opaque and whose cleanup behavior is testable.

## Read-only provider discovery

`SandboxProviderReadinessService` owns one injected `SandboxProviderProbeBackend`. Both are safe to
replace between calls and own no provider or operating-system handles. A probe may run on any thread,
but it must be read-only and thread-safe. The service rejects a mismatched provider identity,
boundary, or required-guarantee set and returns an indeterminate result rather than weakening the
request.

Reports are strict, bounded Serde values containing the exact requested provider, boundary, and
guarantees; a typed reason; and a deterministic set of unresolved requirements. The requested
guarantees in a report are requirements, not claims about a created sandbox. Only
`ready-for-provisioning-attempt` is available—there is deliberately no "sandbox guaranteed" state.

`SystemSandboxProviderProbe` is intentionally conservative. It uses only the compile-time platform
target. Off Windows it reports `unsupported-platform`. On Windows it reports
`capabilities-unverified` plus exact AppContainer, optional-feature, virtualization, policy, helper,
or sealed-image requirements. It does not trust environment variables, registry implementation
details, localized command output, or paths found through the user `PATH`; it does not invoke DISM or
PowerShell; and it never enables a feature or requests elevation. A future Windows adapter may
return readiness only after non-mutating, stable operating-system capability checks.

Deterministic fake backends exercise ready, unavailable, missing-capability, and provider-mismatch
paths without touching the host. Production provisioning and runtime attestation remain separate
subsystems.

### Workbench readiness surface

The Workbench **Debugger / Sandbox** tab combines provider discovery with only the active project's
validated SHA-256, size, exact-source state, and bounded static protection summary. The selected
Local AppContainer, Windows Sandbox, or Hyper-V request is submitted to the existing single
application-service worker with a monotonic operation identifier. Results are accepted only when
the operation, exact project evidence snapshot, and selected provider still match; changing the
project, verifying source bytes, or choosing another provider makes an older result stale.

The surface shows the exact provider, requested boundary and policy properties, typed readiness
reason, and every unresolved prerequisite. It never opens, attaches, launches, or resumes a target;
creates a profile or VM; activates a provider; fabricates an attestation; or substitutes another
provider. Even `ready-for-provisioning-attempt` is explicitly presented as a preflight observation,
not a containment guarantee. The `tab debugger-sandbox` companion-console command only navigates to
this same non-executing surface.

## Target modes

Target selection is explicit and capability-reported:

| Mode | Executes target code | Intended first capability |
|---|---:|---|
| Offline image | No | Static address/protection/disassembly data |
| Dump | No | Read captured memory and register state |
| Snapshot | No new execution | Immutable read-only capture of an authorized process |
| Observe | Existing process | Read-only process observation |
| Debug attach | Existing process | Standard operating-system debug attach |
| Launch | Yes | Suspended, identity-bound, attested launch |

Unavailable modes return a typed reason. ReSymbol must never silently replace a requested sandbox,
target mode, mitigation, or read-only boundary with a weaker option.

## Session safety contract

Before a live backend is allowed, one pure state reducer must prove these invariants with exhaustive
tests:

1. Every command is bound to one session and a monotonically increasing correlation identifier.
2. State-sensitive commands carry the exact current generation and, when stopped, a fresh stop
   token. Accepted mutations invalidate queued stop-sensitive actions.
3. Launch binds the exact source `BinaryId`, requested provider, canonical policy digest, helper
   build, and provider descriptor.
4. A target is created suspended. Continue is impossible until the expected attestation is accepted
   for that exact session, binary, policy, provider, and build.
5. Memory writes are bounded equal-length compare-before-write operations with complete-write and
   readback verification.
6. Events are ordered, command outcomes are correlated, replayed commands are rejected, and terminal
   states cannot return to a live state.
7. Helper loss enters cleanup; it never implies that containment or cleanup succeeded.

The pure reducers, typed client, and in-memory host now exercise these ordering and binding rules. They
remain requirements for a future process-executing provider, not evidence that such a provider exists.

## Implemented host seam

The current seam is intentionally narrow:

- a four-byte length prefix is validated before allocating a bounded control buffer;
- controller and host roles, directions, nonzero challenge nonce, expected build identities, offered
  protocol version, response kind, and independent frame sequences are verified before commands;
- the wire handshake detects reflection, replay, downgrade, and accidental peer mismatch but is not
  cryptographic authentication; a future platform transport must authenticate the helper channel;
- malformed, reflected, duplicate, replayed, stale, cross-session, overlong, and unknown-field inputs
  fail closed;
- command IDs and event IDs are independent monotonic domains, while each synchronous response batch
  must contain exactly one command result and only events correlated to that command;
- session generations and stop/run identifiers must advance exactly through a legal reducer
  transition, non-transition events must carry the exact current state token, and a rejected command
  may not change client state;
- connection-level capability probing is explicit; the in-memory host reports every platform
  capability as unavailable and rejects target-data operations it cannot honestly model;
- only `Closed` sessions can be released, and sandbox closure requires the exact cleanup receipt that
  the reducer validates; and
- the client and transport expose value types only. Future process, pipe, token, Job, VM, and provider
  handles stay opaque inside the owning host implementation.

The JSON typed-control codec retains the 64 KiB control ceiling. Memory-write pairs and memory-read or
memory-written event buffers are carried exactly once through the separately bounded raw channel, with
an exact address and split descriptor in the control document. Inline/raw duplicates, mismatched
lengths, and raw payloads on other message kinds are rejected. A future pipe transport must preserve
that separation rather than increasing the control allocation.

After a transport or validation failure, the client disconnects and remains terminal. Callers may
abandon the poisoned client-side session to recover its last observed state for diagnostics, but this
does not produce a cleanup receipt, mark the session `Closed`, or permit channel reuse.

## Local AppContainer boundary

The planned local provider is a fast, disposable, shared-kernel boundary for routine user-mode
analysis. Its v1 contract is:

- a unique AppContainer profile with no network capabilities;
- a newly owned, no-reparse staging tree containing the exact re-hashed artifact snapshot;
- read/execute access only to staged inputs and one private writable scratch/profile tree;
- an allowlisted environment without inherited credentials, proxy settings, user `PATH`, desktop,
  console, or generic handles;
- Job-at-creation ownership with kill-on-close, no breakaway, and active-process/memory/CPU limits;
- creation-time mitigations, child-process policy, and an explicit inherited-handle list;
- suspended creation followed by token, SID, capability, integrity, Job, mitigation, limit, and image
  identity attestation before resume; and
- terminate-and-reap, handle closure, profile deletion, owned-path deletion, and a durable cleanup
  receipt/journal on every exit path.

Unsupported targets fail with a typed reason. The provider never requests elevation and never falls
back to direct host execution.

This boundary shares the Windows kernel. It is not sufficient for a sample that may exploit the
kernel, a privileged service, a driver, or a platform escape.

## Disposable VM boundary

The planned higher-assurance provider names a registered sealed base-image identifier and expected
hash. It creates a per-session differencing disk, attaches no virtual NIC by default, disables
clipboard/enhanced-session/host-folder/Guest-Services integration, and uses an authenticated,
nonce-bound, versioned Hyper-V socket channel. The guest receives exact sample bytes rather than a
host-mounted path and returns only bounded artifacts. Cleanup must prove channel closure and
differencing-disk discard.

Hyper-V unavailability, image mismatch, or channel/policy mismatch fails closed. It does not trigger
an elevation prompt or a local/host fallback.

## Static workbench semantics

The Address Space tab is a declared preferred-image model. It is not a live `VirtualQuery` map and
does not show ASLR, dynamically allocated pages, loaded modules, copy-on-write state, guard pages, or
runtime protection changes. A future live view must show the preferred and actual mappings as
separate address spaces.

Protection findings are bounded artifact evidence. They are neither malware signatures nor an
authorization to execute. Offline opening should keep those findings reviewable without training the
user to dismiss an execution warning. A blocking acknowledgement belongs at the live launch/attach
boundary and must be bound to the exact binary, operation, provider, policy digest, and expiration.

## Verification gates

No process-executing provider should merge until the project has evidence for:

- legal session transitions, replay rejection, stale generation/stop rejection, attestation-gated
  resume, compare-write conflicts, sequence overflow, and terminal cleanup behavior;
- strict wire decoding, Hello-first/once handshake, role/build/version/nonce agreement, bounded
  allocation before payload reads, and crash recovery;
- benign Windows probes showing allowed staged reads and scratch writes while profile sentinels,
  network, unlisted handles, inherited secrets, and forbidden child creation fail;
- target code not reaching a safe TLS/CRT marker before explicit resume;
- exact token/SID/integrity/capability/Job/mitigation/limit/image attestation; and
- cleanup after normal exit, provider failure, helper crash, and parent crash without deleting paths
  not owned by the cleanup journal.

VM verification is opt-in on a controlled self-hosted machine and must additionally prove the sealed
image hash, absent host integration, authenticated channel, exact target identity, and differencing
disk discard.

## Platform references

- [Implementing an AppContainer](https://learn.microsoft.com/windows/win32/secauthz/implementing-an-appcontainer)
- [Job Objects](https://learn.microsoft.com/windows/win32/procthread/job-objects)
- [Process and thread attribute lists](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [Process mitigation policies](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)
- [Windows container isolation](https://learn.microsoft.com/virtualization/windowscontainers/manage-containers/container-security)
