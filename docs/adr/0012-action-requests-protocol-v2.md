# 0012. Expiring requests, a journal on the agent, and protocol version 2

- Status: Accepted
- Date: 2026-10-18
- Requirements: RF-15, RNF-02, RNF-13, RNF-18, RNF-21

## Context

The protocol of M1 was written before anything ran. `ActionRequest` names a manifest by
`manifest_id` and `manifest_version` and has no expiry, although T4 promises short-lived
requests. The `Initiator` fields are free strings. `ActionResult.output` and the `reason` of
`Failed` and `Rejected` are free text bounded only by `MAX_MESSAGE_BYTES` (256 KiB), and
that text comes from the machine (invariant 4). The agent answers every `RunAction` with a
rejection from inside the session loop, and the server drops every `ActionResult`, since
it never asks for anything.

M2 makes these messages carry real work. A request must run at most once even if it is
sent twice, the agent restarts, or the connection drops halfway (RNF-18). A result must
survive the same events. ADR-0010 puts the signed manifest in the request, which changes
its type, and ADR-0006 says retyping a field is a breaking change that needs a new version
and an ADR. Raising `MIN_PROTOCOL_VERSION` needs one too (`crates/protocol/AGENTS.md`).

## Decision

### The request

`ActionRequest { request_id, manifest, expires_at, initiator }`, where `manifest` is a
`SignedManifest` (ADR-0010) and `expires_at` is in seconds since the Unix epoch, at most
24 hours after the server created the request. The agent refuses a request that has expired
or whose `expires_at` lies more than 24 hours and 5 minutes ahead of its clock.

The expiry is not a defence against a compromised server, which writes it. It bounds how
long a request may wait and how long the agent must remember its `RequestId`, so that a
request recorded and replayed later is refused as expired after the journal has forgotten
it. Against a compromised server the defences stay the signature, the local policy and its
limits (ADR-0011). Binding a request to a human approval signed outside the server takes a
key the server never holds: the technician's, which comes with the console in M3, in an
ADR of its own. A signer the server can reach would sign whatever the server asks.

`Initiator` keeps its shape, but `user_id`, `client_id` and `ticket_ref` become `Label`s.
It is recorded for audit and decides nothing on the agent.

### The result

- `output` is at most 64 KiB once serialized. The primitives of M2 produce none.
- `Failed { reason: FailReason, step }` and `Rejected { reason: RejectReason }` carry
  enums, never text: an unknown key, a bad signature, an expired manifest, a clock that
  went back, a service outside the list, a refused primitive, a rate limit, a full
  journal, a failed precondition, a failed verification, an interrupted run, and the rest
  of what ADR-0010 and ADR-0011 refuse. `step` is the index of the step that was running,
  if any. A new value is a new protocol version (ADR-0006).
- The agent's log gets the same codes and indexes, never a name, a path or a message from
  Windows.

### Version 2, and only version 2

`PROTOCOL_VERSION = MIN_PROTOCOL_VERSION = 2`. Keeping version 1 would mean two types for
every message that changed, because a session that negotiated version 1 still parses a
`RunAction`, and there is no agent in the field to keep working. The same version also
bounds what is left unbounded: a service name in telemetry follows the name rule of
manifests restricted to ASCII (at most 256 characters), a mount is a `Label`, and a
snapshot lists at most 32 services and 32 disks. A manifest is at most 16 KiB (ADR-0010).

An agent of M1 needs the new binary. Its device key still proves who it is, since the
transcripts only change in the version they cover, except on Windows: there the key moves
under DPAPI and the agent refuses the plain file M1 left (ADR-0013), so a lab machine of M1
enrolls again. The plan of M2 said every M1 identity would stay valid; on Windows it does
not.

### The journal

The agent keeps a journal of requests on disk, keyed by `RequestId`.

- A `RequestId` already in the journal gets the stored answer back, before any other
  check, without the `output`. The check runs when the request arrives and again when it
  leaves the queue. A duplicate that arrives while the first is queued or running waits
  in the queue like any request, and the check at dequeue answers it with the first one's
  recorded outcome.
- A request is marked "started" after its preconditions pass and before its first step,
  in one write-through write. Preconditions only read the machine, so nothing has acted
  before the mark. The write is a conditional insert that fails when the id is already in
  the journal, and that failure is answered as a duplicate, so at-most-once does not rest
  on there being one executor. There is one anyway: for each request, the check at
  dequeue, the preconditions, the mark and the steps happen in one turn of it. An entry found "started" with no end when the agent starts becomes
  `Failed { reason: Interrupted }` and never runs again. A crash before the mark leaves no
  entry: nothing acted, and a resend is checked from the start.
- An entry is kept until the request's expiry plus 24 hours, and never longer than 48 hours
  from when it was written.
- "Started" entries are what the at-most-once promise rests on, and they are never dropped
  early. The rate limits of ADR-0011 count exactly these entries, so the same test bounds
  both: at most 60 an hour by configuration, at most 2,880 in 48 hours, against room for
  4,096. A full journal refuses new requests, and so does a journal the agent cannot
  write, read or parse: an unreadable entry is never taken as "not seen".
- Everything that ends before the mark (a refusal, a failed precondition) is recorded too,
  so a repeat gets the same answer, but in a separate ring of 1,024 entries where the
  oldest goes first. A request that never started cannot run twice, so dropping its entry
  costs at most a new evaluation if it comes back, and a stream of requests that never
  start cannot fill the journal.
- The journal, the clock mark of ADR-0010 and the identity files are written through:
  `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`. That is the
  "renames written through to the disk" the roadmap promised for M2.

### The executor lives outside the session

Today everything happens inside the session's loop, so a dropped connection would lose a
result. In M2 the session hands `RunAction` and `CancelAction` to an executor that outlives
it.

- At most 4 requests wait in its queue; more are refused. One runs at a time.
- A finished result waits until a session sends it, and every new session first sends the
  results that are waiting.
- The server sends again, when a session starts, every request it marked `sent` that has no
  result yet. The agent answers it from the journal. If a connection drops after the agent
  sent a result and before the server stored it, the resend recovers the outcome but not
  the `output`. The primitives of M2 have none; a primitive that does brings an
  acknowledgement message with it.
- The server accepts a result only from the device the request was sent to, and only for a
  request in `sent`, in one atomic `UPDATE`. Anything else is dropped and logged at a
  bounded rate. A second result for a request that already has one is logged as an
  anomaly with the device and the request id, under the same bound: it can mean that a
  refusal fell out of the agent's ring and a resend then ran, so the stored outcome may
  not be what happened.

### Cancelling

Only a request that is still queued can be cancelled; it ends `Cancelled`. A running one
runs to its end. Cancelling between steps would let a compromised server leave the ERP
stopped. The "one at a time" lock is released only when the blocking task has truly
returned: a `timeout` around `spawn_blocking` stops waiting but not the work, and another
action would start beside it. Each wait on the service manager is bounded by the time the
manifest has left, and an action that runs out of it ends `TimedOut`.

### How an operator asks for an action

`ponte-server action run <device> <manifest-id> [--version N] [--minutes M]` writes a row
in `action_requests`, the table M3 turns into the approval queue. It refuses a device that
is pending or revoked, and `--minutes` cannot go past the 24 hours above. The server sweeps
the table every 500 ms and claims what is due for its connected devices in one
`UPDATE ... RETURNING`, so a request reaches an online agent well inside the second of
RNF-13. Queued requests that expire are marked `expired`. `action show`, `action list` and
`action cancel` complete it. Each step is an audit event (`action_requested`, `action_sent`,
`action_finished`), and `output` never reaches a log. There is no HTTP endpoint for this:
nothing on the server authenticates a person yet.

### What a compromised server can still do

Taking the server, or terminating TLS in front of it (ADR-0009), gives an attacker every
message the agent receives. Within M2 that is enough to:

- run any manifest that is signed by a key the agent trusts, not expired, and allowed by
  the agent's local policy, on any device that trusts that key, at a moment of its
  choosing: restart the ERP during a sale, delete a lock file the configuration lets it
  delete, or run a manifest that stops a service and never send the one that starts it,
  leaving the ERP down;
- do that as often as the limits allow: 20 actions an hour and one run of a manifest every
  10 minutes per device by default, one at a time;
- run a version of a manifest that the catalog has replaced but that has not expired,
  since the agent does not know which version is current;
- hold a request back and deliver it up to 24 hours and 5 minutes later, since it writes
  `expires_at` itself;
- lie about who asked (`Initiator`), withhold or delay requests and results, and keep the
  queue full so that the device refuses whatever else arrives;
- read what the agent already sends: telemetry, outcomes, and `output` when a primitive
  produces one (none in M2).

It cannot run a manifest that is unsigned, altered, expired or signed by another key;
choose a path, a service or a step; go past the risk ceiling, the service list, the roots
or the limits; run the refused primitives or anything `high`; or make one request run
twice. Every one of those refusals is on the agent, which is the point of ADR-0003.

## Consequences

- Every agent must be updated at once, and M1 lab machines on Windows enroll again. That
  is cheap now and would not be later.
- The journal is new state on disk, written before acting, that the at-most-once promise
  rests on. Its tests fail the disk at every write, like those of `identity.rs`.
- An action interrupted by a crash or a power cut is never retried, even when retrying
  would have been harmless. The ERP may be left stopped until someone asks again with a
  new request. That is the price of RNF-18.
- A running action cannot be cancelled. The timeout of the manifest (at most 600 seconds)
  is the bound.
- Codes instead of text make a refusal less descriptive. The codes are fine-grained and the
  agent logs the step index, but a message from Windows never reaches the server.
- Sweeping the table costs one query every 500 ms even when nothing is due. `LISTEN` and
  `NOTIFY` wait until the load test of M5 shows the need.
- In a narrow window the `output` of a result can be lost while its outcome survives.
- Until M3, nothing ties a request to a person. The audit trail records the initiator the
  server claims.

## Alternatives considered

- **Keep version 1 alongside version 2**: lets an M1 agent connect, at the cost of two
  types per message and a version nobody uses. No agent is in the field.
- **A request signed by a server key**: the server holds that key, so a compromised server
  signs whatever it wants. It proves nothing the TLS connection does not.
- **Free-text reasons with a length limit**: easier to debug, but the text comes from the
  machine and travels towards technicians and models (invariant 4).
- **Cancel between steps**: more control for a technician, and the same control for a
  compromised server, which could stop a service and never start it again.
- **Retry an interrupted action**: kinder to the ERP after a power cut, and a double run of
  anything that is not idempotent. RNF-18 forbids it.
- **An HTTP endpoint to request actions**: needs authentication the server does not have
  until the console.
- **`LISTEN`/`NOTIFY` instead of a sweep**: faster in theory, but it holds one of the 16
  connections of the pool for good and does not go through the checked `query!` macros.
