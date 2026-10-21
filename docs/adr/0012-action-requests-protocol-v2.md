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
  the journal, and that failure makes the request a duplicate, which gets the first one's
  outcome once that ends and never an outcome of its own. At-most-once therefore does not
  rest on there being one executor. There is one anyway: for each request, the check at
  dequeue, the preconditions, the mark and the steps happen in one turn of it.
- An entry found "started" with no end when the agent starts becomes
  `Failed { reason: Interrupted }` and never runs again. A crash before the mark leaves no
  entry: nothing acted, and a resend is checked from the start.
- An entry is kept until the request's expiry plus 24 hours, by the clock's high-water
  mark. Step 4 of M2 dropped the "never longer than 48 hours" this ADR first had: see
  below.
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

### Step 4 of M2 settled the details

Building the executor showed a few places where the text above was not enough, or not
right. The code follows this section.

- **The order, exactly.** On arrival: the journal, then whether the agent is stopping, has
  manifest keys and has room in the queue. Out of the queue: the journal again; the clock
  (no mark, or a clock more than one hour behind it, is `ClockWentBack`, since ADR-0010
  already refuses every action then and the checks after it read the clock); the request's
  expiry; the hourly limit and the room in the journal, before any signature is checked;
  `verify`; the interval per manifest, which needs the manifest's id and so comes after
  `verify`, the only door to that id; `validate`. Then one blocking task does the rest: the
  structural refusal of every service named, the preconditions, the "started" entry, the
  steps, the verification and the end.
- **The request's expiry is checked against the clock**, not the mark: expired when
  `expires_at` is not after the clock, too far ahead when it is more than 24 hours and 5
  minutes after it. The server writes `expires_at`, so this is no defence against it, and
  what the expiry protects is the journal: an entry stays a day past the expiry by the
  mark, and any clock the agent accepts is at most one hour behind the mark.
- **No cap of 48 hours.** Entries are kept by the mark, which moves only with a monotonic
  clock while the agent runs. If the clock is corrected forward while the agent runs, the
  mark falls behind it; a cap counted from the start could then drop an entry whose
  request the clock still finds valid, and a copy sent later would run again. Without the
  cap, the bound of 2,880 started entries holds while the clock and the mark agree; in the
  odd case where they do not, the journal fills and refuses (`JournalFull`), which fails
  closed. The ring keeps the same rule, or its size.
- **Two files.** `journal.json` holds the started requests and is written at once on a
  start and on an end; the start is written before it joins the journal in memory, so
  nothing ever sees a start the disk does not hold. `ended.json` is the ring. The ring and
  the marks of what a session sent are written at most once a minute and when the agent
  stops: a server sending requests that are refused in a loop would otherwise get a disk
  write per request. A refusal lost in a crash costs a new evaluation, as above; a
  delivered mark lost in a crash, an identical result sent again.
- **Refusals that describe the agent are sent, not recorded**: `ActionsDisabled`,
  `QueueFull`, `ShuttingDown`, `JournalFull`, `JournalUnavailable` and `ClockWentBack`. A
  repeat is decided again, which is safe because nothing started, and a flood of
  `QueueFull` writes nothing.
- **One `RequestId`, one entry.** A start or a refusal is not recorded for an id the
  journal knows, and a file that names an id twice makes the journal unavailable. Across
  the two files the disk can lag: an id that left the ring in memory may still be in the
  last `ended.json` written when it starts, and a crash before the next write of the ring
  leaves both. When the journal is read the start wins, since with it the request never
  runs again; the security review of step 4 found that refusing such a journal would let a
  compromised server, by pushing an id out of the ring and then starting it, leave every
  crash refusing everything for good. Lazy writes also put `journal.json` before
  `ended.json`, so an id that left the started requests reaches the ring on disk only
  after.
- **One process holds the journal.** `journal.lock`, in the data directory, is locked for
  the life of the process (`File::try_lock`). Two agents on one data directory, a service
  and a console, would each trust their own copy and could both run a request; the second
  one refuses everything with `JournalUnavailable`. It tries for about ten seconds first, for an agent that is still
  stopping, and then leaves the clock's mark alone as well, so the two never write the same
  file.
- **The queue counts duplicates.** A copy of a request that runs or waits takes a place in
  the queue of 4 like any request, so copies cannot grow the memory.
- **Cancelling a request that left the queue** takes its waiting copies and answers
  nothing: the request being decided keeps its own answer, and a `Cancelled` recorded for
  it would name the id twice.
- **What the server may see twice.** A result sent again for a copy that arrives after the
  first answer went out; a result sent again after a crash lost its delivered mark; and,
  after a refusal that describes the agent, a second, different result once a copy is
  decided again. The first two are identical and harmless. Step 6 logs a different second
  result as the anomaly described above, and an identical one at debug level.
- **What the security review of step 4 left as it is**, with reasons:
  - A request is its id and its expiry. Once its entry is gone (a day past the expiry by the
    mark), the same id sent with a later `expires_at` is a new request and may run. Only the
    server can do that, it can as easily choose a new id, and the limits still apply.
  - A clock set ahead before a restart, then back within the hour of tolerance, moves the
    window of the limits by up to an hour per restart. It takes control of the clock and a
    restart, and each round pushes the mark further ahead, which the validity of manifests
    bounds.
  - Deciding on a request costs a parse, a signature check and, for one that gets that far,
    reads of the service manager, and nothing limits how often a server asks. The queue of
    4 and one at a time bound it; the load test of M5 decides whether it needs a budget,
    as the review of step 1 already said.
  - Renames are not yet written through (`MoveFileExW` with `MOVEFILE_WRITE_THROUGH`), so a
    power cut could roll a start back. Nothing acts until step 5, which brings both, and the
    Windows machine must not land without it. Step 5 of M2 brought them: on Windows the
    journal, the mark and the identity are written to a new temporary file, flushed,
    renamed over the old one through the temporary file's own handle (`FileRenameInfo`,
    replacing), and flushed again. The security review of step 5 pointed out that
    `MOVEFILE_WRITE_THROUGH` documents its promise only for a move done as a copy; flushing
    the handle after the rename commits the NTFS log that holds it.
  - Step 5 of M2: a service the service manager could not read, or not in time, is
    answered `ServiceRefused` and not recorded, like the refusals that describe the agent
    (ADR-0011, "Step 5 of M2 settled the details").

### Step 6 of M2 settled the details

Building the server's queue showed where the text above was not enough. The code follows
this section; `crates/server/AGENTS.md` keeps the rules.

- **One request in flight per device.** The sweep claims a device's oldest queued request
  only when no other request of that device is sent, unanswered and not expired. The agent
  runs one at a time anyway, and what waits on the server stays `queued`, where an operator
  can still cancel it. A sent request that expired with no answer no longer holds the turn,
  so one the agent cannot read (ADR-0010) blocks the device for its validity at most.
  Across devices the oldest requests go first, at most 64 a sweep.
- **Who may be sent what.** Only an active device, checked when a request is queued and
  again in the statement that claims it, and only an envelope signed by a key the server
  still trusts (`catalog key remove` stops what was already queued, which then expires).
- **Limits.** At most 16 open requests per device, counting queued ones and sent ones that
  have not expired; a sent one that expired unanswered does not count, or an agent that
  never answers would lock its device out for good. `--minutes` is 1 to 1440, 60 by
  default.
- **"Sends again every request it marked `sent`"** became: when a session starts, the sent
  requests of that device with no answer, signed by a key still trusted, the unexpired
  first, at most four, none expired for more than 23 hours. Older ones stay `sent` with no
  answer: the agent forgets a request a day past its expiry, and a resend would then get a
  `request_expired` that may not be what happened. The window protects the record, not the
  machine: the agent refuses what has expired on its own.
- **A request that never reached a connection goes back to the queue.** The sweep marks a
  request sent before its session has it; if the session is gone or not taking requests,
  the request returns to `queued`, and `action_sent` is audited only once a session holds it.
- **Identical** means the same status, reason and step. The duration and the `output` do
  not count: the journal answers with what it recorded, without the `output`.
- **The refusals that describe the agent can be replaced.** `actions_disabled`,
  `queue_full`, `shutting_down`, `journal_full`, `journal_unavailable` and
  `clock_went_back` say that the copy which got them did not run, not that the request never
  will: another copy may still wait in the agent's queue. A later answer of the same device
  about the request itself (not another of these six) replaces one of them, once, audited
  with `replaced`; any other second answer that differs is the anomaly above and changes
  nothing. The security review of step 6 found that letting one of the six replace another
  let a device rewrite its answer back and forth.
- **A store that fails never ends a session over a result.** The request stays `sent` and is
  sent again at the next session; ending the session would bring the same result back in a
  loop. Results that reach the store are bounded to 32 a minute per session, and lines about
  dropped results and anomalies to 8 per session and 8 every 10 minutes per device, so a
  noisy device can neither tie up the database's connections nor silence another device.
- **Atomicity.** Claiming, cancelling and expiring each check `status = 'queued'` again on
  the row they write, so whichever commits first wins; a result is judged in a transaction
  that holds its row, so two answers to one request (a session that was replaced, and the
  new one) take turns.
- Results for a `sent` request are taken after its expiry: the agent may have run it in
  time and answered late.

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
