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
  every unsupported operation, and never fabricates target, attestation, or cleanup evidence;
- a production, in-process `OfflineImageDebugHost` that freezes an identity-checked image snapshot,
  advertises only offline analysis, and serves bounded reads from exact canonical file-backed image
  ranges without opening a process or executing target code; and
- sandbox policy, attestation, failure, lifecycle, resource-limit, and cleanup-receipt data models.

The debugger crate also exposes a bounded provider-readiness service. It is discovery only: it
cannot execute a target, create an AppContainer profile, enable a Windows feature, create a VM, or
provision any other resource. A readiness result means only that a caller may attempt provisioning;
the suspended target still needs the exact policy/provider/build attestation described below.

The Windows debugger host process, pipe transport, AppContainer provider, Hyper-V provider, guest
agent, live process attach, breakpoint engine, register access, live memory access, and instruction
editing are not implemented. `SyntheticDebugHost` is available only to crate tests or the explicit
`test-support` feature. It is not a security boundary or platform provider. The current types and UI
must not be described as a working malware sandbox or live debugger.

## Ownership and thread affinity

The intended ownership chain is:

```text
Workbench UI thread
  -> bounded application-service worker queue
    -> one thread-affine DebugHostClient
      -> in-process OfflineImageDebugHost (offline image only; no process or sandbox)
      OR
      -> authenticated bounded transport (future live modes)
        -> resymbol-debugger-host helper
          -> one SessionWorker thread
            -> one selected provider/backend
              -> opaque platform RAII handles
```

- The UI owns product state and never receives a platform handle.
- `DebugHostClient` is deliberately `!Send` and `!Sync`. One connection worker constructs and owns
  it; UI code uses bounded queues. Its synchronous exchange calls are never made on the UI thread.
- One client owns one connection and at most one session. The offline client owns no helper or pipe;
  a future live client owns its authenticated helper transport. Graceful release and disconnect
  require reducer state `Closed`. Explicit abandon, transport failure, or client drop may sever only
  the control channel while preserving the last non-`Closed` state; none supplies cleanup evidence.
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

`SystemSandboxProviderProbe` is intentionally conservative. Off Windows it reports
`unsupported-platform`. On Windows it uses the narrow `resymbol-windows-readiness` adapter to make
three independent, read-only observations through stable operating-system APIs:

- the required AppContainer profile entry points are present in the system32 `userenv.dll`;
- `PF_VIRT_FIRMWARE_ENABLED` reports firmware virtualization enabled and available to Windows; and
- `WHvCapabilityCodeHypervisorPresent` reports a running Windows hypervisor through the Windows
  Hypervisor Platform API.

These observations remove only their matching unresolved requirements. AppContainer exports do not
prove that a profile can be created under current policy. Firmware virtualization and a running
hypervisor do not prove that Windows Sandbox or Hyper-V optional features are enabled, that provider
policy permits use, or that a sealed image or exact helper is available. A missing observed
capability is reported unavailable; inability to load or call the stable query remains typed and
indeterminate. No positive observation is promoted to provider readiness by itself.

Optional-feature state, administrative policy approval, packaged provider-helper identity, and
sealed-VM-image identity remain unresolved until equally bounded adapters exist. The probe does not
trust environment variables, registry implementation details, localized command output, or paths
found through the user `PATH`; it does not invoke DISM or PowerShell; and it never enables a feature
or requests elevation.

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

### Verified offline image host

`VerifiedOfflineImage` is an immutable, non-executing input boundary. Construction canonicalizes a
regular-file origin, rejects a direct symbolic-link target, enforces the 1 GiB application ingestion
ceiling before allocating, reads no more than the metadata-declared length plus one byte, and checks
the open file and path metadata again after the read. Caller-supplied snapshots use the same size
ceiling. The snapshot's size and SHA-256 are recomputed, its bytes are parsed, every field of the
resulting `BinaryIdentity` must equal the caller's expected identity, and the canonical static
address space must validate. The host retains the resulting `Arc<[u8]>`; later disk replacement does
not alter an established snapshot.

The only accepted open target is the exact canonical `OfflineTarget.path` returned for that verified
image. In this host, `MemoryAddress` unambiguously means an RVA. A read must be nonempty, no larger
than the protocol's 1 MiB memory-read ceiling, remain within one canonical region, and remain wholly
inside that region's initialized file-backed prefix. Header/section bytes are returned from the
frozen snapshot. Image gaps, section zero-fill, loader-rounded padding, raw file-alignment bytes
beyond a smaller `VirtualSize`, address overflow, image overrun, and cross-region or cross-backing
spans are rejected without a memory-read event.

`OfflineImageDebugHost` advertises `OfflineAnalysis` as available, reports every other capability as
typed read-only or backend unavailability, and supports only capability probing, that exact offline
open, bounded RVA reads, and close. Dump, snapshot, observe, attach, launch, execution, write,
register, breakpoint, terminate, and sandbox operations are rejected through the same
public-but-opaque, host-owned remote-command transaction path. Rejections restore visible reducer
state while retaining command and authority-consumption watermarks, and emit only a correlated
rejected command result. This host never emits sandbox attestation, lifecycle, or cleanup evidence.
Graceful shutdown and the mandatory non-panicking abort/drop paths close only the in-process control
boundary; they do not claim target or sandbox cleanup.

The Workbench Address Space reader owns this client only on the bounded application-service worker.
Each request is limited to 256 bytes, and the UI publishes bytes only after the full identity,
canonical source path, operation, span, and close/release/disconnect receipt match the current
project. A package without verified source bytes cannot queue a read. The UI may render those exact
bytes as hex/ASCII or pass them through the pure bounded x64 linear-preview transformer. That
transformer has independent byte and instruction caps, reports an explicit stop reason, never
executes the input, and does not claim CFG or function-boundary truth. It exposes only decoded direct
branch/call targets; indirect targets remain unavailable and are never inferred.

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
4. A target is created suspended, and `AwaitingAttestation` records its exact PID, trusted
   process-start key, and executable identity. Continue is impossible until the provider's actual
   attestation matches that retained process plus the exact session, binary, policy, provider,
   build, and fresh 256-bit provisioning epoch.
5. Memory writes are bounded equal-length compare-before-write operations with complete-write and
   readback verification.
6. Events are ordered, command outcomes are correlated, replayed commands are rejected, and terminal
   states cannot return to a live state.
7. A sandbox-owned attach requires a provider/host-registered one-use ownership lease bound to the
   exact process identity, attach mode, provider, policy digest, session, and provisioning epoch. A
   PID or claimed owner session in a command is never proof of ownership.
8. Cleanup receipts carry the same provisioning epoch as attestation, so evidence from an otherwise
   identical earlier provisioning instance is rejected. Cleanup after a newly created target binds
   the exact process identity retained at creation. A retained launch failure explicitly reports
   `NotCreated` or `Created` with the exact PID/start-key/image identity. A processless receipt is
   accepted only after the reducer validates and retains exact `NotCreated` evidence; omission of
   `AwaitingAttestation` leaves creation unknown and fails closed. An inherited-sandbox attach
   likewise binds its receipt to the exact process identity, provider, policy digest, and session
   retained from the provider-issued ownership lease. Helper loss never implies cleanup succeeded.

The pure reducers and typed client now exercise these ordering and binding rules. The client
independently replays each command through its reducer and accepts only command-specific state and
operation evidence, including exact attestation and cleanup bindings. The synthetic host covers only
execution-neutral protocol mechanics. These remain requirements for a future process-executing
provider, not evidence that such a provider exists.

## Implemented host seam

The current seam is intentionally narrow:

- debugger wire and typed-command protocol 1.3 carries the lease identifiers, provisioning epoch,
  exact suspended-target process identity through state and attestation, exact failure operation
  context including the explicit target-creation outcome, and process-bound incomplete or complete
  cleanup evidence. The wire supports exactly 1.3; a 1.2 Hello is rejected before negotiation
  because it cannot represent the required process fields;
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
  evidence must match the request. Policy and discovery failures can roll back only before any
  command-state event or operation evidence is observed, from the exact accepted Opening or
  Provisioning post-state. A resource-retaining sandbox rejection must follow its exact
  command-state transition, match the command/stage/kind/reducer phase, bind the full launch and its
  explicit `NotCreated` or exact `Created` process outcome (or the inherited-attach context), and end
  in one exact `Failed` state while cleanup ownership remains held. A cleanup-stage retained
  rejection additionally requires exactly one validated `CleanupAttemptFailed` event carrying its
  incomplete receipt. Every rejected command
  still consumes its command identifier and any presented one-use authority;
- the audited controller and host-client path uses the public-but-opaque, move-only
  `RemoteCommandCheckpoint`, bound to the exact reducer instance, command ID, and post-accept state;
  future external helper or provider crates must preserve the same transaction boundary. Exactly one
  transaction may be active. Dropping or forgetting its checkpoint leaves that reducer permanently
  pending and fail-closed; it never implies rollback. An effect-free rejection restores the exact
  pre-command visible state and state token; its speculative generation never becomes wire-visible,
  so the next accepted transition remains exactly +1. A host must validate the complete remote
  evidence before explicitly committing successful or cleanup-required effects. Stale, foreign,
  mismatched, already-resolved, and post-effect rollback attempts fail closed; command, run/stop, and
  one-use authorization watermarks remain consumed;
- failure, attestation, and cleanup events are bound both to the outer event session and to the
  reducer's exact created or inherited process, binary, policy, provider, helper build,
  provisioning epoch, and cleanup expectation before failure can be retained or `Closed` can be
  accepted and released. The reducer retains the provider attestation it accepted rather than only
  a Boolean gate. A trusted host path must record explicit `NotCreated` before binding a pre-target
  launch failure; the binder rejects an unknown target-creation result. Missing target-creation
  state is not treated as evidence. Raw expected-attestation and cleanup comparison helpers are
  crate-private; public acceptance routes through reducer-held identity;
- connection-level capability probing is explicit and complete: every protocol capability must
  appear exactly once as available or with a typed unavailability reason. The synthetic host
  reports every platform capability as unavailable, supports only offline open/close, and rejects
  every other operation without producing security evidence;
- the production offline-image host reports only offline analysis as available, binds open to one
  preverified canonical snapshot, treats memory addresses as RVAs, and returns only exact
  file-backed header/section prefixes under the protocol and response budgets;
- host-risk and sandbox-ownership grant objects are host-local and non-serializable. Commands carry
  only strict 64-character lowercase-hex lease IDs. Non-cloneable trusted issuers derive each ID from
  an operating-system-entropy-backed secret and a monotonic sequence, and return the sole move-only
  lease together with a cloneable non-authority verifier; caller-chosen IDs cannot construct a grant.
  Host launch issuance atomically binds the fresh ID to the exact pre-approved launch intent, so no
  placeholder authority value is needed. Issuer ownership must remain inside the trusted approval or
  provider boundary: entropy prevents payload forgery, but does not authenticate code already allowed
  to invoke a trusted issuer.
  The host reducer bounds registrations, rejects duplicate registration, consumes a presented lease
  even on mismatch, and drops every unused lease after a target opens. The verifier goes only to the
  controller-side shadow reducer, while the lease transfers to the host worker;
- authority-bearing lease values and each `SessionMachine` consumption registry are deliberately
  non-cloneable. Pure lease IDs, exact launch/attach comparison records, and retained sandbox
  evidence remain cloneable value data without granting host authority;
- only `Closed` sessions can be released, and both newly provisioned and inherited sandbox closure
  require a complete receipt. Cleanup after target creation is validated against the retained
  session, provisioning epoch, provider, policy digest, and PID/start-key/image process identity
  before the reducer can enter `Closed`; a receipt without a process identity requires a previously
  validated and retained exact `NotCreated` failure outcome. An unknown target-creation outcome
  fails closed. `CleanupAttemptFailed` is a separate cleanup-stage failure carrying an
  exact `Incomplete` receipt with at least one bounded residual; its `retryable` flag is advisory and
  never weakens fail-closed ownership. It retains `Failed` state and sandbox ownership for another
  cleanup attempt, leaves cleanup unverified, and can never imply `Closed` or permit release.
  Complete, forged, mismatched, duplicate, wrong-stage, or success-associated incomplete receipts
  fail the connection. Active abandon, transport loss, and client drop invoke the transport's
  mandatory non-panicking abort contract, including kill-on-close ownership where applicable, but
  never imply cleanup or synthesize `Closed`; and
- the client and transport expose value types only. Future process, pipe, token, Job, VM, and provider
  handles stay opaque inside the owning host implementation.

### Sandbox failure acceptance matrix

The client validates both the failure kind and the exact reducer phase before accepting a rejected
command. Policy and discovery are the only effect-free rollback stages; every other accepted failure
retains the observed command-state transition and, where applicable, sandbox cleanup ownership.

| Stage | Allowed kinds | Required command and observed phase |
| --- | --- | --- |
| Policy | `InvalidPolicy`, `ProtocolViolation` | Sandboxed `Open` at the exact accepted `Opening` / `Provisioning` post-state, with no command-state event, attestation, or operation effect. |
| Discovery | `ProviderUnavailable`, `HelperFailure`, `ProtocolViolation` | Sandboxed `Open` under the same effect-free rollback conditions as Policy. |
| Provisioning | `ProviderUnavailable`, `ResourceLimitReached`, `HelperFailure`, `ProtocolViolation` | Sandboxed `Open` after its state event, still exactly `Opening` / `Provisioning`, before attestation. |
| Attestation | `AttestationRejected`, `HelperFailure`, `ProtocolViolation` | Sandboxed `Open` after its state event at `AwaitingAttestation` / `TargetCreatedSuspended`, before an accepted attestation. |
| Launch | `LaunchDenied`, `ResourceLimitReached`, `HelperFailure`, `ProtocolViolation` | Sandboxed `Open` after its state event, either at `Opening` / `Provisioning` before attestation or at the exact accepted-attestation phase with matching evidence. |
| Runtime | `ResourceLimitReached`, `HelperFailure`, `ProtocolViolation` | The command-specific observed phase: sandboxed open after attestation, inherited-sandbox open, running `Continue` / `Step`, pausing `Pause`, or closing `Terminate`. |
| Cleanup | `CleanupIncomplete` | `Close` or `Terminate` after its state event at `Closing` / `Cleanup` (or the inherited equivalent), with exactly one matching `CleanupAttemptFailed` event and incomplete receipt. |

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

Its optional byte reader is a bounded view of the frozen verified source snapshot. It never reads a
process, maps the image through the operating-system loader, provisions a sandbox, or treats virtual
zero-fill and loader padding as file bytes. Typed range unavailability remains evidence, not a reason
to guess or fall back to disk. Its linear disassembly is only another bounded rendering of those
bytes, not execution or authoritative control-flow recovery.

The instruction action menu maintains three separate authority domains:

1. Static preview is read-only and non-executing. Copy and decoder-proven direct-target navigation
   operate only on the frozen preferred-image model.
2. A queued static NOP is an exact-RVA, exact-byte draft. Publication requires revalidating the source
   bytes and writing a new binary; it must never alter the open source file or a live process.
3. Live actions are typed and visible but remain disabled until a real authenticated provider
   supplies a complete capability report, a current authenticated stop token, and the exact address
   or stopped-thread bindings required by the action. Live NOP requires `LiveMemoryWrite` and a
   `DebugCommand::WriteMemory` compare-before-write with the exact selected bytes and an equal-length
   `0x90` replacement. Run to Cursor requires both software-breakpoint and execution-control
   capability and composes a temporary software breakpoint with Continue. Step Into/Over/Out,
   Continue, and persistent software breakpoint creation stay on the same typed command path.

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
- strict wire decoding, exact-1.3 Hello-first/once build-claim exchange including legacy-1.2
  rejection, role/build/version/nonce correlation, independent transport authentication, bounded
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
