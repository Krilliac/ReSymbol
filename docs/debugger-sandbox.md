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
- a bounded control/raw-byte frame format, direction-checked plaintext build-claim correlation,
  exact wire/typed protocol version binding, strict typed command/event codec, cumulative
  response-allocation budget, and single-owner host-client seam;
- a feature-gated synthetic host that models only offline open/close reducer mechanics, rejects
  every unsupported operation, and never fabricates target, attestation, or cleanup evidence; and
- sandbox policy, attestation, failure, lifecycle, resource-limit, and cleanup-receipt data models.

The debugger crate also exposes a bounded provider-readiness service. It is discovery only: it
cannot execute a target, create an AppContainer profile, enable a Windows feature, create a VM, or
provision any other resource. A readiness result means only that a caller may attempt provisioning;
the suspended target still needs the exact policy/provider/build attestation described below.

The Windows debugger host process, pipe transport, AppContainer provider, Hyper-V provider, guest
agent, live process attach, breakpoint engine, register access, memory access, and instruction
editing are not implemented. `SyntheticDebugHost` is available only to crate tests or the explicit
`test-support` feature. It is not a security boundary or platform provider. The current types and UI
must not be described as a working malware sandbox or live debugger.

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
- One client owns one connection and at most one session. Graceful release and disconnect require
  reducer state `Closed`. Explicit abandon, transport failure, or client drop may sever only the
  control channel while preserving the last non-`Closed` state; none supplies cleanup evidence.
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
3. Host launch and attach require a host-local, registered one-use risk lease. A launch lease binds
   the session, provisioning epoch, `BinaryId`, exact executable path, argument vector, working
   directory, host environment, and stop-before-entry mode. An attach lease binds PID, trusted
   process-start key, executable `BinaryId`, and attach mode. A wire payload cannot mint authority.
4. A target is created suspended. Continue is impossible until the expected attestation is accepted
   for that exact session, binary, policy, provider, build, and fresh 256-bit provisioning epoch.
5. Memory writes are bounded equal-length compare-before-write operations with complete-write and
   readback verification.
6. Events are ordered, command outcomes are correlated, replayed commands are rejected, and terminal
   states cannot return to a live state.
7. A sandbox-owned attach requires a provider/host-registered one-use ownership lease bound to the
   exact process identity, attach mode, provider, policy digest, session, and provisioning epoch. A PID or claimed
   owner session in a command is never proof of ownership.
8. Cleanup receipts carry the same provisioning epoch as attestation, so evidence from an otherwise
   identical earlier provisioning instance is rejected. An inherited-sandbox attach also binds its
   receipt to the exact process identity, provider, policy digest, and session retained from the
   provider-issued ownership lease. Helper loss never implies cleanup succeeded.

The pure reducers and typed client now exercise these ordering and binding rules. The client
independently replays each command through its reducer and accepts only command-specific state and
operation evidence, including exact attestation and cleanup bindings. The synthetic host covers only
execution-neutral protocol mechanics. These remain requirements for a future process-executing
provider, not evidence that such a provider exists.

## Implemented host seam

The current seam is intentionally narrow:

- debugger wire and typed-command protocol 1.2 carries the lease identifiers, provisioning epoch,
  and explicit incomplete cleanup-attempt evidence;
- a four-byte length prefix is validated before allocating a bounded control buffer;
- controller and host roles, directions, nonzero challenge nonce, expected plaintext build claims,
  offered protocol version, response kind, and independent frame sequences are correlated before
  commands;
- `BuildClaimHandshake` detects reflection, replay, downgrade, and accidental build mismatch, but
  its echoed nonce and self-reported strings do not authenticate either peer. A future platform
  transport must independently authenticate the helper channel and process identity;
- malformed, reflected, duplicate, replayed, stale, cross-session, overlong, and unknown-field inputs
  fail closed;
- the connection owner supplies immutable response limits to the transport: at most 256 frames,
  one typed frame no larger than the 64 KiB control ceiling plus the 1 MiB memory-read ceiling and
  framing, and at most 8 MiB of encoded response data in total. A transport must reject the
  peer-declared count before allocating the batch and preflight each decoded header before reading
  its raw payload;
- the returned batch has private invariants, but the client does not trust them: it independently
  recomputes every encoded frame length and the cumulative byte count with checked arithmetic before
  handshake or event decoding. Count, per-frame, total, or arithmetic failures disconnect and poison
  the connection;
- command IDs and event IDs are independent monotonic domains, while each synchronous response batch
  must contain exactly one command result and only events correlated to that command;
- session generations and stop/run identifiers must advance exactly through the command-specific
  reducer path; non-transition events carry the exact current state token, and memory/breakpoint
  evidence must match the request. An ordinary rejected command may not claim any effect. The sole
  retained-rejection exception is an exact cleanup-required failure: it may preserve `Failed` state
  and a validated `CleanupAttemptFailed` event while its command identifier and any presented one-use
  authority remain consumed without cloning the reducer or lease;
- `RemoteCommandCheckpoint` is a public opaque transaction value so an external host worker can use
  the same begin/reject semantics. It restores only ordinary visible state; command, run/stop, and
  one-use authorization watermarks remain consumed;
- attestation and cleanup events are bound both to the outer event session and to the reducer's exact
  binary, policy, provider, build, provisioning epoch, and cleanup expectation before `Closed` can be
  accepted or released;
- connection-level capability probing is explicit; the synthetic host reports every platform
  capability as unavailable, supports only offline open/close, and rejects every other operation
  without producing security evidence;
- host-risk and sandbox-ownership grant objects are host-local and non-serializable. Commands carry
  only strict 64-character lowercase-hex lease IDs; the host reducer bounds registrations, consumes
  a presented lease even on mismatch, and drops every unused lease after a target opens. The client
  receives only a cloneable non-authority verifier record, while the sole move-only lease transfers
  to the host worker;
- authority-bearing lease values and each `SessionMachine` consumption registry are deliberately
  non-cloneable. Pure lease IDs, exact launch/attach comparison records, and retained sandbox
  evidence remain cloneable value data without granting host authority;
- only `Closed` sessions can be released, and both newly provisioned and inherited sandbox closure
  require a complete receipt. Inherited cleanup is validated against the retained session,
  provisioning epoch, provider, policy digest, and PID/start-key/image process identity before the
  reducer can enter `Closed`. `CleanupAttemptFailed` is a separate, retryable cleanup-stage failure
  carrying an exact `Incomplete` receipt with at least one bounded residual. It retains `Failed`
  state and sandbox ownership for another cleanup attempt, leaves cleanup unverified, and can never
  imply `Closed` or permit release. Complete, forged, mismatched, duplicate, wrong-stage, or
  success-associated incomplete receipts fail the connection. Active abandon, transport loss, and
  client drop invoke the transport's mandatory non-panicking abort contract, including kill-on-close
  ownership where applicable, but never imply cleanup or synthesize `Closed`; and
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
user to dismiss an execution warning. A blocking approval belongs at the live launch/attach boundary
and becomes a host-local, one-use lease bound to the exact operation and target identity. Production
lease IDs and provisioning epochs require 256 bits from a cryptographically secure random source;
their constructors validate the wire representation, not entropy provenance.

## Verification gates

No process-executing provider should merge until the project has evidence for:

- legal session transitions, cross-target and replayed lease rejection, stale generation/stop
  rejection, provisioning-epoch-bound attestation and cleanup, attestation-gated resume,
  compare-write conflicts, sequence overflow, and terminal cleanup behavior;
- strict wire decoding, Hello-first/once build-claim exchange, role/build/version/nonce correlation,
  independent transport authentication, bounded allocation before payload reads, and crash recovery;
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
