//! The executor: takes requests from the session, decides on each in the order of
//! ADR-0012, runs at most one at a time, and keeps every result until a session sends it.
//!
//! It lives outside the session (ADR-0012), so a dropped connection loses no result, and
//! one task does all its work, so the journal has one writer and its writes land in order.
//!
//! **When a request arrives** ([`Actions::submit`], from the session, without waiting):
//! the journal first, then whether the agent is stopping, has manifest keys, and has room
//! in the queue ([`MAX_QUEUED`], duplicates counted). Those refusals describe the agent,
//! not the request, so they are sent and not recorded: a repeat is decided again, and
//! since nothing started, nothing can run twice.
//!
//! **When it leaves the queue**, in this order:
//!
//! 1. the journal: a request it knows gets the stored answer;
//! 2. the clock: no mark, or a clock more than an hour behind it, refuses (ADR-0010);
//! 3. the request's expiry, against the clock;
//! 4. the hourly limit and the room in the journal, before any signature is checked;
//! 5. `verify`, with the clock and the mark;
//! 6. the interval between runs of the manifest, which needs its verified id;
//! 7. `validate` against the local policy, which makes the only thing that runs, a
//!    [`RunnableManifest`];
//! 8. then one blocking task, waited for to its end with no timeout around it, so that
//!    the "one at a time" lock is only released when the work has truly returned: the
//!    structure of every service the manifest names, the preconditions, the "started"
//!    entry on disk, the steps, the verification and the end on disk. Every call gets the
//!    time the manifest has left.
//!
//! What ends before "started" is recorded in the ring of the journal, except the refusals
//! that describe the agent (no keys, a full queue or journal, a journal or a clock that
//! cannot be trusted, a stop).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ponte_actions::{Manifest, RunnableManifest, verify};
use ponte_protocol::{
    ActionOutcome, ActionRequest, ActionResult, FailReason, RejectReason, RequestId,
};
use tokio::sync::{Notify, watch};
use tokio::task::{JoinHandle, spawn_blocking};
use tokio::time::{Instant, sleep_until};
use tracing::{debug, error, info, warn};

use super::clock::{self, Clock, HighWater, MarkDisk, Reading};
use super::journal::{Ended, Journal, JournalDisk, JournalFile, Known, StartError, Unavailable};
use super::machine::{CheckError, Machine, ServiceRefusal, StepError};
use crate::config::ActionSettings;

/// Most requests waiting in the queue, the running one not counted (ADR-0012).
pub(crate) const MAX_QUEUED: usize = 4;
/// Most answers waiting to be sent that the journal does not hold. More are dropped; the
/// server sends a request again when a session starts.
pub(crate) const MAX_UNRECORDED: usize = 16;
/// How far ahead of the clock a request's expiry may be: 24 hours and 5 minutes
/// (ADR-0012).
pub(crate) const MAX_REQUEST_AHEAD_SECS: u64 = 24 * 60 * 60 + 5 * 60;
/// How often the ring and the delivered marks go to disk, at most. A refusal lost in a
/// crash costs a new evaluation; a write per refusal would let a server wear the disk.
pub(crate) const LAZY_WRITES_EVERY: Duration = Duration::from_secs(60);
/// How often, a second apart, the journal's lock is tried at start: about ten seconds for
/// an agent that is still stopping to let go of it.
const LOCK_ATTEMPTS: u32 = 10;
const LOCK_RETRY: Duration = Duration::from_secs(1);
/// The window of `max_actions_per_hour`.
const HOUR_SECS: u64 = 60 * 60;
/// Refusals, cancels and failed starts the executor logs per [`LOG_WINDOW`]. A server that
/// sends refused or cancelled requests in a loop must not fill the machine's disk, nor push
/// the lines of what did run out of the log.
const LOGGED_PER_WINDOW: u32 = 20;
const LOG_WINDOW: Duration = Duration::from_secs(10 * 60);

/// What the session holds: a way to hand requests in and take results out.
#[derive(Clone)]
pub(crate) struct Actions {
    shared: Arc<Shared>,
}

/// The executor and the task that keeps the clock's mark, until they are stopped.
pub(crate) struct ActionRunner {
    actions: Actions,
    executor: JoinHandle<()>,
    keeper: JoinHandle<()>,
    stop_keeper: watch::Sender<bool>,
}

/// Names one answer handed to a session, so that [`Actions::sent`] confirms that one and
/// no other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ticket {
    Unrecorded(u64),
    Recorded(RequestId),
}

struct Shared {
    state: Mutex<State>,
    /// Something for the executor: a request, a stop, a file to write.
    work: Notify,
    /// Something for the session to send.
    outbox: Notify,
    settings: ActionSettings,
    clock: Arc<dyn Clock>,
    mark: Arc<HighWater>,
    disk: Arc<dyn JournalDisk>,
    machine: Arc<dyn Machine>,
}

struct State {
    journal: Result<Journal, Unavailable>,
    queue: VecDeque<Box<ActionRequest>>,
    /// The request out of the queue and not yet ended, if any.
    evaluating: Option<RequestId>,
    /// Answers the journal does not hold, oldest first, numbered.
    unrecorded: VecDeque<(u64, ActionResult)>,
    next_ticket: u64,
    stopping: bool,
    log: LogBudget,
}

/// How many refusals were logged in the current window.
struct LogBudget {
    window_start: Option<Duration>,
    used: u32,
}

impl LogBudget {
    /// Whether this one gets a line, at `now` by the monotonic clock. The first one that
    /// does not gets a notice.
    fn take(&mut self, now: Duration) -> bool {
        let fresh = self
            .window_start
            .is_none_or(|start| now.saturating_sub(start) >= LOG_WINDOW);
        if fresh {
            self.window_start = Some(now);
            self.used = 0;
        }
        self.used = self.used.saturating_add(1);
        if self.used == LOGGED_PER_WINDOW + 1 {
            warn!("further refused or cancelled requests are not logged for ten minutes");
        }
        self.used <= LOGGED_PER_WINDOW
    }
}

fn answer(request_id: RequestId, outcome: ActionOutcome, duration_ms: u64) -> ActionResult {
    ActionResult {
        request_id,
        outcome,
        output: None,
        duration_ms,
    }
}

fn rejected(request_id: RequestId, reason: RejectReason, duration_ms: u64) -> ActionResult {
    answer(request_id, ActionOutcome::Rejected { reason }, duration_ms)
}

/// Refusals that describe the agent rather than the request: sent, never recorded.
const fn is_about_the_agent(reason: RejectReason) -> bool {
    matches!(
        reason,
        RejectReason::ActionsDisabled
            | RejectReason::QueueFull
            | RejectReason::ShuttingDown
            | RejectReason::JournalFull
            | RejectReason::JournalUnavailable
            | RejectReason::ClockWentBack
    )
}

/// Milliseconds, saturating: a run is at most ten minutes.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Reads the journal and the mark, then starts the executor and the task that keeps the
/// mark.
pub(crate) async fn start(
    settings: ActionSettings,
    disk: Arc<dyn JournalDisk>,
    mark_disk: Arc<dyn MarkDisk>,
    clock: Arc<dyn Clock>,
    machine: Arc<dyn Machine>,
) -> ActionRunner {
    // An agent that is still on its way out holds the journal for a moment.
    let mut attempt = 1;
    let mut journal = loop {
        let disk = Arc::clone(&disk);
        let journal = spawn_blocking(move || Journal::load(disk.as_ref()))
            .await
            // Only in a build that unwinds: a release build ends the process on a panic.
            .unwrap_or(Err(Unavailable::Read));
        if journal.as_ref().err() != Some(&Unavailable::Locked) || attempt == LOCK_ATTEMPTS {
            break journal;
        }
        attempt += 1;
        tokio::time::sleep(LOCK_RETRY).await;
    };
    // Another process runs the actions of this data directory: this one leaves the mark
    // alone too, so that the two never write the same file.
    let locked = journal.as_ref().err() == Some(&Unavailable::Locked);
    let mark = if locked {
        HighWater::unavailable(Arc::clone(&clock))
    } else {
        let floor = journal.as_ref().map_or(0, Journal::latest_time);
        let (mark_disk, clock) = (Arc::clone(&mark_disk), Arc::clone(&clock));
        spawn_blocking({
            let clock = Arc::clone(&clock);
            move || HighWater::start(clock, mark_disk.as_ref(), floor)
        })
        .await
        .unwrap_or_else(|_| HighWater::unavailable(clock))
    };
    match &mut journal {
        Ok(journal) => {
            if let Some(reading) = mark.reading() {
                journal.prune(reading.mark);
            }
            let interrupted = journal.interrupted();
            if interrupted > 0 {
                warn!(
                    interrupted,
                    "requests were running when the agent last stopped: they are reported as \
                     interrupted and never run again"
                );
            }
        }
        Err(Unavailable::Locked) => error!(
            "another agent process holds the journal of this data directory: this one runs \
             no action. Stop the other one (a console started by hand, or a second service) \
             and start this one again"
        ),
        Err(problem) => error!(
            %problem,
            "the journal of actions cannot be used: every request is refused. If the file \
             cannot be repaired, an administrator may remove journal.json and ended.json, \
             which forgets what ran in the last day"
        ),
    }

    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            journal,
            queue: VecDeque::new(),
            evaluating: None,
            unrecorded: VecDeque::new(),
            next_ticket: 0,
            stopping: false,
            log: LogBudget {
                window_start: None,
                used: 0,
            },
        }),
        work: Notify::new(),
        outbox: Notify::new(),
        settings,
        clock,
        mark: Arc::new(mark),
        disk,
        machine,
    });
    let (stop_keeper, keeper_stopped) = watch::channel(false);
    let keeper = if locked {
        tokio::spawn(async {})
    } else {
        tokio::spawn(clock::keep(
            Arc::clone(&shared.mark),
            mark_disk,
            keeper_stopped,
        ))
    };
    let executor = tokio::spawn(Arc::clone(&shared).execute());
    ActionRunner {
        actions: Actions { shared },
        executor,
        keeper,
        stop_keeper,
    }
}

impl ActionRunner {
    pub(crate) fn actions(&self) -> Actions {
        self.actions.clone()
    }

    /// Takes no new request and drops the queue without answering: the server sends those
    /// again. At once, when the agent is told to stop, so that nothing more starts while
    /// the session closes.
    pub(crate) fn halt(&self) {
        {
            let mut state = self.actions.shared.lock();
            state.stopping = true;
            state.queue.clear();
        }
        self.actions.shared.work.notify_one();
    }

    /// [`ActionRunner::halt`], then waits up to `timeout` for the running action, the last
    /// writes of the journal and the last write of the mark. A run that does not end in time stays
    /// "started" on disk and is reported interrupted at the next start; the ring and the
    /// delivered marks since the last write are then lost.
    pub(crate) async fn stop(self, timeout: Duration) {
        self.halt();
        let _ = self.stop_keeper.send(true);
        let done = async {
            let _ = self.executor.await;
            let _ = self.keeper.await;
        };
        if tokio::time::timeout(timeout, done).await.is_err() {
            warn!(
                timeout_secs = timeout.as_secs(),
                "the running action did not end in time: it is reported as interrupted at the \
                 next start"
            );
        }
    }

    /// Ends both tasks at once, as a crash would. Tests only.
    #[cfg(test)]
    pub(crate) fn crash(self) {
        self.executor.abort();
        self.keeper.abort();
    }
}

impl Actions {
    /// Takes a request from the session. Never waits.
    pub(crate) fn submit(&self, request: Box<ActionRequest>) {
        let shared = &self.shared;
        let id = request.request_id;
        let mut state = shared.lock();
        let refusal = match &state.journal {
            Err(_) => Some(RejectReason::JournalUnavailable),
            Ok(journal) => match journal.lookup(id) {
                Some(Known::Ended { result, delivered }) => {
                    if delivered {
                        shared.push_unrecorded(&mut state, result);
                    } else {
                        // It goes out with the other results that are waiting.
                        shared.outbox.notify_one();
                    }
                    return;
                }
                // A duplicate of what runs now waits its turn, and the check when it
                // leaves the queue answers it with the first one's outcome.
                Some(Known::Running) | None => {
                    if state.stopping {
                        Some(RejectReason::ShuttingDown)
                    } else if shared.settings.keys.is_none() {
                        Some(RejectReason::ActionsDisabled)
                    } else if state.queue.len() >= MAX_QUEUED {
                        Some(RejectReason::QueueFull)
                    } else {
                        None
                    }
                }
            },
        };
        match refusal {
            Some(reason) => {
                shared.log_refusal(&mut state, id, reason);
                shared.push_unrecorded(&mut state, rejected(id, reason, 0));
            }
            None => {
                debug!(request = %id, "action queued");
                state.queue.push_back(request);
                drop(state);
                shared.work.notify_one();
            }
        }
    }

    /// Takes `id` out of the queue, every copy of it. A request that left the queue runs
    /// to its end: cancelling between steps would let a compromised server leave a service
    /// stopped (ADR-0012).
    pub(crate) fn cancel(&self, id: RequestId) {
        let shared = &self.shared;
        let mut state = shared.lock();
        let mut taken = None;
        state.queue.retain(|request| {
            if request.request_id == id {
                taken.get_or_insert(request.expires_at);
                false
            } else {
                true
            }
        });
        let Some(expires_at) = taken else {
            debug!(request = %id, "cancel ignored: the request is not waiting");
            return;
        };
        let evaluating = state.evaluating == Some(id);
        let mark = shared.mark.reading().map_or(0, |reading| reading.mark);
        let Ok(journal) = &mut state.journal else {
            return;
        };
        // The copies taken were duplicates of a request that is deciding, running or done:
        // that one's answer is the answer.
        if evaluating || journal.lookup(id).is_some() {
            return;
        }
        let cancelled = answer(id, ActionOutcome::Cancelled {}, 0);
        if journal.record_ended(Ended::new(&cancelled, expires_at, mark)) {
            drop(state);
            if shared.log_allowed() {
                info!(request = %id, "action cancelled while it waited");
            }
            shared.outbox.notify_one();
            shared.work.notify_one();
        }
    }

    /// A new session: what the last one did not send of the unrecorded answers is dropped
    /// (the server asks again), and every recorded answer not sent yet goes first.
    pub(crate) fn session_started(&self) {
        self.shared.lock().unrecorded.clear();
        self.shared.outbox.notify_one();
    }

    /// The next answer to send, if any. Confirm it with [`Actions::sent`] once it is out.
    pub(crate) fn next_to_send(&self) -> Option<(Ticket, ActionResult)> {
        let state = self.shared.lock();
        if let Some((ticket, result)) = state.unrecorded.front() {
            return Some((Ticket::Unrecorded(*ticket), result.clone()));
        }
        let journal = state.journal.as_ref().ok()?;
        let result = journal.undelivered().next()?;
        Some((Ticket::Recorded(result.request_id), result))
    }

    /// The answer `ticket` names went out. There is no acknowledgement in protocol 2: a
    /// result lost after this comes back when the server sends the request again.
    pub(crate) fn sent(&self, ticket: Ticket) {
        let mut state = self.shared.lock();
        match ticket {
            Ticket::Unrecorded(number) => state.unrecorded.retain(|(n, _)| *n != number),
            Ticket::Recorded(id) => {
                if let Ok(journal) = &mut state.journal {
                    journal.mark_delivered(id);
                    drop(state);
                    self.shared.work.notify_one();
                }
            }
        }
    }

    /// Completes when there may be something to send. A wake-up may find nothing, and one
    /// that came while nobody waited is kept for the next call.
    pub(crate) async fn ready(&self) {
        self.shared.outbox.notified().await;
    }
}

/// How step 8 ended, before or after "started".
enum RunEnd {
    /// Ended before "started": recorded in the ring unless it describes the agent.
    Refused(RejectReason),
    /// The journal knows the id already: its answer is the answer.
    Duplicate,
    /// Started, ran and ended: recorded already.
    Done,
}

impl Shared {
    /// The state. A panic while it was held only happens in a build that unwinds, and the
    /// state is still whole: every change under the lock is a single step.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn push_unrecorded(&self, state: &mut State, result: ActionResult) {
        let known = state
            .unrecorded
            .iter()
            .any(|(_, waiting)| waiting.request_id == result.request_id);
        if known || state.unrecorded.len() >= MAX_UNRECORDED {
            debug!(request = %result.request_id, "answer dropped: the server asks again");
            return;
        }
        let ticket = state.next_ticket;
        state.next_ticket = ticket.wrapping_add(1);
        state.unrecorded.push_back((ticket, result));
        self.outbox.notify_one();
    }

    /// Whether one more line about a request fits in the budget. Every line a server can
    /// cause once per request goes through it.
    fn log_allowed(&self) -> bool {
        let now = self.clock.monotonic();
        self.lock().log.take(now)
    }

    fn log_refusal(&self, state: &mut State, id: RequestId, reason: RejectReason) {
        if state.log.take(self.clock.monotonic()) {
            // Only the id and the code: the rest of a request is text the server chose.
            warn!(request = %id, reason = ?reason, "action refused");
        }
    }

    /// The executor's loop: one request at a time, and the lazy writes in between.
    async fn execute(self: Arc<Self>) {
        // What the load changed (interrupted runs) goes to disk first.
        self.write_dirty().await;
        let mut written = Instant::now();
        loop {
            let next = {
                let mut state = self.lock();
                if state.stopping {
                    break;
                }
                let next = state.queue.pop_front();
                state.evaluating = next.as_ref().map(|request| request.request_id);
                next
            };
            if let Some(request) = next {
                self.process(request).await;
                self.lock().evaluating = None;
                continue;
            }
            let dirty = self.is_dirty();
            let due = written + LAZY_WRITES_EVERY;
            tokio::select! {
                () = self.work.notified() => {}
                () = sleep_until(due), if dirty => {
                    self.write_dirty().await;
                    written = Instant::now();
                }
            }
        }
        self.write_dirty().await;
    }

    fn is_dirty(&self) -> bool {
        self.lock()
            .journal
            .as_ref()
            .is_ok_and(|journal| journal.dirty() != (false, false))
    }

    /// Writes whichever file changed since it was last written.
    async fn write_dirty(&self) {
        let (started, ended) = {
            let mut state = self.lock();
            let Ok(journal) = &mut state.journal else {
                return;
            };
            let (started, ended) = journal.dirty();
            (
                started.then(|| journal.take_started()),
                ended.then(|| journal.take_ended()),
            )
        };
        // The started requests first: an id that left them in memory may be in the ring
        // now, and the ring must not reach the disk before the file it left does.
        let mut failed = false;
        for (file, text) in [(JournalFile::Started, started), (JournalFile::Ended, ended)] {
            let Some(text) = text else { continue };
            if failed {
                self.not_written(file);
                continue;
            }
            let disk = Arc::clone(&self.disk);
            let written = !text.is_empty()
                && matches!(
                    spawn_blocking(move || disk.write(file, &text)).await,
                    Ok(Ok(()))
                );
            if !written {
                failed = true;
                self.not_written(file);
            }
        }
    }

    fn not_written(&self, file: JournalFile) {
        if let Ok(journal) = &mut self.lock().journal {
            journal.still_dirty(file);
        }
        warn!(
            ?file,
            "the journal could not be written; it is tried again later"
        );
    }

    /// Steps 1 to 9 of the module's list for one request out of the queue.
    async fn process(self: &Arc<Self>, request: Box<ActionRequest>) {
        let began = self.clock.monotonic();
        let id = request.request_id;
        {
            let mut state = self.lock();
            let known = match &state.journal {
                Ok(journal) => journal.lookup(id),
                Err(_) => {
                    let refusal = rejected(id, RejectReason::JournalUnavailable, 0);
                    self.push_unrecorded(&mut state, refusal);
                    return;
                }
            };
            match known {
                Some(Known::Ended { result, delivered }) => {
                    if delivered {
                        self.push_unrecorded(&mut state, result);
                    } else {
                        self.outbox.notify_one();
                    }
                    return;
                }
                // Nothing else runs: only a request whose blocking task was lost.
                Some(Known::Running) => {
                    error!(request = %id, "a duplicate of a request with no end is not answered");
                    return;
                }
                None => {}
            }
        }

        let (runnable, reading) = match self.decide(&request) {
            Ok(decided) => decided,
            Err(reason) => {
                self.end_before_start(&request, reason, began);
                return;
            }
        };
        let shared = Arc::clone(self);
        let request = Arc::new(*request);
        // The blocking task logs where this task logs.
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let run = spawn_blocking({
            let request = Arc::clone(&request);
            move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    shared.run(&request, &runnable, reading.mark, began)
                })
            }
        })
        .await;
        match run {
            Ok(RunEnd::Done) => {}
            Ok(RunEnd::Refused(reason)) => self.end_before_start(&request, reason, began),
            Ok(RunEnd::Duplicate) => self.answer_known(id),
            // Only in a build that unwinds. Whether a step acted is not known, so the
            // request ends interrupted, as after a crash.
            Err(_) => {
                error!(request = %id, "an action's blocking task failed");
                let interrupted = ActionOutcome::Failed {
                    reason: FailReason::Interrupted,
                    step: None,
                };
                self.finish(
                    id,
                    interrupted,
                    millis(self.clock.monotonic().saturating_sub(began)),
                );
            }
        }
    }

    /// Steps 2 to 7: everything that needs neither the machine nor the disk.
    fn decide(&self, request: &ActionRequest) -> Result<(RunnableManifest, Reading), RejectReason> {
        let reading = self
            .mark
            .reading()
            .filter(|reading| !reading.went_back())
            .ok_or(RejectReason::ClockWentBack)?;
        if request.expires_at <= reading.clock {
            return Err(RejectReason::RequestExpired);
        }
        if request.expires_at > reading.clock.saturating_add(MAX_REQUEST_AHEAD_SECS) {
            return Err(RejectReason::RequestTooFarAhead);
        }
        {
            let mut state = self.lock();
            let journal = state
                .journal
                .as_mut()
                .map_err(|_| RejectReason::JournalUnavailable)?;
            journal.prune(reading.mark);
            if journal.started_within(reading.mark, HOUR_SECS)
                >= usize::try_from(self.settings.max_per_hour).unwrap_or(usize::MAX)
            {
                return Err(RejectReason::RateLimited);
            }
            if journal.is_full() {
                return Err(RejectReason::JournalFull);
            }
        }
        let keys = self
            .settings
            .keys
            .as_ref()
            .ok_or(RejectReason::ActionsDisabled)?;
        let verified = verify(&request.manifest, keys, reading.clock, reading.mark)
            .map_err(|error| error.reject_reason())?;
        {
            let state = self.lock();
            let journal = state
                .journal
                .as_ref()
                .map_err(|_| RejectReason::JournalUnavailable)?;
            let id = &verified.manifest().id;
            if journal.manifest_started_within(id, reading.mark, self.settings.min_interval_secs) {
                return Err(RejectReason::TooSoon);
            }
        }
        let runnable = verified
            .validate(&self.settings.policy)
            .map_err(|error| error.reject_reason())?;
        Ok((runnable, reading))
    }

    /// Step 8, in a blocking task: the machine and the disk.
    fn run(
        &self,
        request: &ActionRequest,
        runnable: &RunnableManifest,
        mark: u64,
        began: Duration,
    ) -> RunEnd {
        let id = request.request_id;
        let manifest = runnable.manifest();
        let deadline = self
            .clock
            .monotonic()
            .saturating_add(Duration::from_secs(manifest.timeout_secs.into()));
        let left = || deadline.saturating_sub(self.clock.monotonic());

        for name in named_services(manifest) {
            let remaining = left();
            let allowed = if remaining.is_zero() {
                Err(ServiceRefusal::TimedOut)
            } else {
                self.machine.service_allowed(name, remaining)
            };
            if let Err(refusal) = allowed {
                debug!(request = %id, ?refusal, "a service is refused by its structure");
                return RunEnd::Refused(RejectReason::ServiceRefused);
            }
        }
        for (index, check) in manifest.preconditions.iter().enumerate() {
            let remaining = left();
            let holds = !remaining.is_zero() && self.machine.check(check, remaining) == Ok(true);
            if !holds {
                debug!(request = %id, precondition = index, "a precondition did not hold");
                return RunEnd::Refused(RejectReason::PreconditionFailed);
            }
        }

        // "Started", on disk before the first step and before anything can see it.
        let pending = {
            let state = self.lock();
            if state.stopping {
                return RunEnd::Refused(RejectReason::ShuttingDown);
            }
            let Ok(journal) = &state.journal else {
                return RunEnd::Refused(RejectReason::JournalUnavailable);
            };
            match journal.prepare_start(id, &manifest.id, mark, request.expires_at) {
                Ok(pending) => pending,
                Err(StartError::Duplicate) => return RunEnd::Duplicate,
                Err(StartError::Full) => return RunEnd::Refused(RejectReason::JournalFull),
                Err(StartError::Unwritable) => {
                    return RunEnd::Refused(RejectReason::JournalUnavailable);
                }
            }
        };
        if !self.write_now(JournalFile::Started, pending.text()) {
            if self.log_allowed() {
                warn!(request = %id, "the start could not be written: the action does not run");
            }
            return RunEnd::Refused(RejectReason::JournalUnavailable);
        }
        let committed = match &mut self.lock().journal {
            Ok(journal) => journal.commit(pending),
            Err(_) => Err(StartError::Duplicate),
        };
        if committed.is_err() {
            // Cannot happen: the id is in `evaluating`, which nothing records. The disk
            // is set back to what the journal holds, and nothing runs.
            error!(request = %id, "the start was not recorded: the action does not run");
            self.rewrite_started();
            return RunEnd::Duplicate;
        }
        info!(
            request = %id,
            manifest = %manifest.id,
            version = manifest.version,
            "action started"
        );

        let outcome = self.steps_and_verification(id, manifest, &left);
        let duration = millis(self.clock.monotonic().saturating_sub(began));
        info!(request = %id, outcome = ?outcome, duration_ms = duration, "action ended");
        self.finish(id, outcome, duration);
        RunEnd::Done
    }

    fn steps_and_verification(
        &self,
        id: RequestId,
        manifest: &Manifest,
        left: &dyn Fn() -> Duration,
    ) -> ActionOutcome {
        for (index, step) in manifest.steps.iter().enumerate() {
            let remaining = left();
            if remaining.is_zero() {
                warn!(request = %id, step = index, "the manifest's time ran out");
                return ActionOutcome::TimedOut {};
            }
            let reason = match self.machine.step(step, remaining) {
                Ok(()) => continue,
                Err(StepError::TimedOut) => {
                    warn!(request = %id, step = index, "the manifest's time ran out");
                    return ActionOutcome::TimedOut {};
                }
                Err(StepError::Failed) => FailReason::StepFailed,
                Err(StepError::PathRefused) => FailReason::PathRefused,
            };
            warn!(request = %id, step = index, reason = ?reason, "a step failed");
            return ActionOutcome::Failed {
                reason,
                step: u8::try_from(index).ok(),
            };
        }
        for (index, check) in manifest.verify.iter().enumerate() {
            let remaining = left();
            let holds = if remaining.is_zero() {
                Err(CheckError::TimedOut)
            } else {
                self.machine.check(check, remaining)
            };
            match holds {
                Ok(true) => {}
                Err(CheckError::TimedOut) => {
                    warn!(request = %id, verify = index, "the manifest's time ran out");
                    return ActionOutcome::TimedOut {};
                }
                Ok(false) | Err(CheckError::Failed) => {
                    warn!(request = %id, verify = index, "a verify check did not hold");
                    return ActionOutcome::Failed {
                        reason: FailReason::VerifyFailed,
                        step: None,
                    };
                }
            }
        }
        ActionOutcome::Succeeded {}
    }

    /// Records the end of a started request and writes it, then tells the session.
    fn finish(&self, id: RequestId, outcome: ActionOutcome, duration_ms: u64) {
        let text = {
            let mut state = self.lock();
            let Ok(journal) = &mut state.journal else {
                return;
            };
            if !journal.finish(id, outcome, duration_ms) {
                return;
            }
            journal.take_started()
        };
        if !self.write_now(JournalFile::Started, &text) {
            // Kept in memory and sent; written with the next write that goes through.
            self.not_written(JournalFile::Started);
        }
        self.outbox.notify_one();
    }

    fn rewrite_started(&self) {
        let text = match &mut self.lock().journal {
            Ok(journal) => journal.take_started(),
            Err(_) => return,
        };
        if !self.write_now(JournalFile::Started, &text) {
            self.not_written(JournalFile::Started);
        }
    }

    /// Writes `text` from a blocking task. An empty text is a serialization that failed,
    /// and never replaces a journal.
    fn write_now(&self, file: JournalFile, text: &str) -> bool {
        !text.is_empty() && self.disk.write(file, text).is_ok()
    }

    /// A request that ended before "started": its answer, recorded in the ring unless it
    /// describes the agent.
    fn end_before_start(&self, request: &ActionRequest, reason: RejectReason, began: Duration) {
        let id = request.request_id;
        let refusal = rejected(
            id,
            reason,
            millis(self.clock.monotonic().saturating_sub(began)),
        );
        let mut state = self.lock();
        self.log_refusal(&mut state, id, reason);
        if is_about_the_agent(reason) {
            self.push_unrecorded(&mut state, refusal);
            return;
        }
        let mark = self.mark.reading().map_or(0, |reading| reading.mark);
        let recorded = match &mut state.journal {
            Ok(journal) => journal.record_ended(Ended::new(&refusal, request.expires_at, mark)),
            Err(_) => false,
        };
        drop(state);
        if recorded {
            self.outbox.notify_one();
        } else {
            // The journal came to know the id: its answer is the only one.
            self.answer_known(id);
        }
    }

    /// The journal knows `id`: its stored answer, if it was sent already, goes again.
    fn answer_known(&self, id: RequestId) {
        let mut state = self.lock();
        let known = state
            .journal
            .as_ref()
            .ok()
            .and_then(|journal| journal.lookup(id));
        match known {
            Some(Known::Ended {
                result,
                delivered: true,
            }) => self.push_unrecorded(&mut state, result),
            _ => self.outbox.notify_one(),
        }
    }
}

/// An executor on disks in memory, a clock set by hand and a machine that refuses
/// everything: what the session's tests talk to.
#[cfg(test)]
pub(crate) async fn in_memory(
    settings: ActionSettings,
    clock: crate::testkit::FakeClock,
) -> (ActionRunner, super::journal::tests::FakeJournalDisk) {
    let disk = super::journal::tests::FakeJournalDisk::default();
    let runner = start(
        settings,
        Arc::new(disk.clone()),
        Arc::new(crate::testkit::MemoryMark::default()),
        Arc::new(clock),
        Arc::new(super::machine::Unsupported),
    )
    .await;
    (runner, disk)
}

/// Every service the manifest names, in steps and checks.
fn named_services(manifest: &Manifest) -> impl Iterator<Item = &str> {
    let steps = manifest.steps.iter().filter_map(|step| step.service());
    let checks = manifest
        .preconditions
        .iter()
        .chain(&manifest.verify)
        .filter_map(|check| check.service());
    steps.chain(checks)
}
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::{io, sync};

    use ed25519_dalek::{Signer, SigningKey};
    use ponte_actions::{Check, Primitive};
    use ponte_protocol::{Initiator, PublicKey, Signature, SignedManifest, manifest_transcript};
    use tokio::sync::mpsc;

    use super::super::journal::MAX_STARTED;
    use super::super::journal::tests::{FakeJournalDisk, id};
    use super::super::machine::Unsupported;
    use super::*;
    use crate::AgentConfig;
    use crate::testkit::{FakeClock, MemoryMark};

    const RESTART: &str = include_str!("../../../../manifests/examples/erp-restart-service.toml");
    const CLEAR_LOCK: &str =
        include_str!("../../../../manifests/examples/erp-clear-stale-lock.toml");
    /// A manifest that only deletes, with what coverage asks of it.
    const DELETE_ONLY: &str = r"
id = 'erp.delete-lock'
version = 1
title = 'Delete the lock'
description = 'Deletes the lock.'
ai_description = 'Never.'
risk = 'medium'

[[preconditions]]
check = 'path_exists'
path = 'C:\FakeErp\run\erp.lock'

[[steps]]
op = 'delete_file'
path = 'C:\FakeErp\run\erp.lock'

[[verify]]
check = 'path_absent'
path = 'C:\FakeErp\run\erp.lock'
";
    const NOW: u64 = 1_792_300_000;
    const HOUR: u64 = 60 * 60;
    const DAY: u64 = 24 * HOUR;

    // ----- Manifests and requests ------------------------------------------------------

    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key_hex(seed: u8) -> String {
        crate::testkit::manifest_key_hex(seed)
    }

    fn sign(text: &str, seed: u8, issued_at: u64, expires_at: u64) -> SignedManifest {
        let mut signed = SignedManifest {
            manifest: text.parse().unwrap(),
            issued_at,
            expires_at,
            public_key: PublicKey::from_bytes(signer(seed).verifying_key().to_bytes()),
            signature: Signature::from_bytes([0; 64]),
        };
        let signature = signer(seed).sign(manifest_transcript(&signed).expose_bytes());
        signed.signature = Signature::from_bytes(signature.to_bytes());
        signed
    }

    /// Signed by the trusted key an hour ago, for 90 days: what `ponte-sign` writes.
    fn signed(text: &str) -> SignedManifest {
        sign(text, 1, NOW - HOUR, NOW - HOUR + 90 * DAY)
    }

    /// The same envelope with a signature that does not verify.
    fn badly_signed(text: &str) -> SignedManifest {
        let mut manifest = signed(text);
        manifest.signature = Signature::from_bytes([7; 64]);
        manifest
    }

    fn request_with(n: u128, manifest: SignedManifest, expires_at: u64) -> Box<ActionRequest> {
        Box::new(ActionRequest {
            request_id: id(n),
            manifest,
            expires_at,
            initiator: Initiator::Human {
                user_id: "operator-7".parse().unwrap(),
            },
        })
    }

    /// Request `n` for `text`, valid for an hour.
    fn request(n: u128, text: &str) -> Box<ActionRequest> {
        request_with(n, signed(text), NOW + HOUR)
    }

    fn succeeded() -> ActionOutcome {
        ActionOutcome::Succeeded {}
    }

    fn refused(reason: RejectReason) -> ActionOutcome {
        ActionOutcome::Rejected { reason }
    }

    fn interrupted() -> ActionOutcome {
        ActionOutcome::Failed {
            reason: FailReason::Interrupted,
            step: None,
        }
    }

    // ----- The machine -----------------------------------------------------------------

    #[derive(Default)]
    struct MachineState {
        /// Services refused by their structure.
        refused: Vec<&'static str>,
        /// Answers to checks, in order; after them every check holds.
        checks: VecDeque<Result<bool, CheckError>>,
        /// Answers to steps, in order; after them every step works.
        steps: VecDeque<Result<(), StepError>>,
        /// Every call, in order.
        calls: Vec<String>,
        /// The time left each check and step was given.
        remaining: Vec<Duration>,
        active: usize,
        most_active: usize,
        gate: Option<Gate>,
        /// Whether the gate holds checks too, not only steps.
        gate_checks: bool,
        /// How long a step takes, on the clock below.
        step_takes: Duration,
        clock: Option<FakeClock>,
    }

    /// Holds every step until the test lets it go.
    #[derive(Clone)]
    struct Gate {
        started: mpsc::UnboundedSender<()>,
        release: Arc<sync::Mutex<sync::mpsc::Receiver<()>>>,
    }

    /// The test's end of a [`Gate`].
    struct GateKeeper {
        started: mpsc::UnboundedReceiver<()>,
        release: sync::mpsc::Sender<()>,
    }

    impl GateKeeper {
        /// Waits until a step is held at the gate.
        async fn step_started(&mut self) {
            self.started.recv().await.unwrap();
        }

        /// Lets one held step go, now or when it comes.
        fn release(&self) {
            let _ = self.release.send(());
        }
    }

    #[derive(Clone, Default)]
    struct FakeMachine(Arc<sync::Mutex<MachineState>>);

    impl FakeMachine {
        fn state(&self) -> sync::MutexGuard<'_, MachineState> {
            self.0.lock().unwrap()
        }

        fn gate(&self) -> GateKeeper {
            let (started, started_rx) = mpsc::unbounded_channel();
            let (release, release_rx) = sync::mpsc::channel();
            self.state().gate = Some(Gate {
                started,
                release: Arc::new(sync::Mutex::new(release_rx)),
            });
            GateKeeper {
                started: started_rx,
                release,
            }
        }

        /// Steps that start from now on are not held. One held already still waits.
        fn open(&self) {
            self.state().gate = None;
        }

        fn calls(&self) -> Vec<String> {
            self.state().calls.clone()
        }

        fn steps(&self) -> usize {
            self.calls()
                .iter()
                .filter(|call| call.starts_with("step"))
                .count()
        }
    }

    impl Machine for FakeMachine {
        fn service_allowed(&self, name: &str, remaining: Duration) -> Result<(), ServiceRefusal> {
            let mut state = self.state();
            state.calls.push(format!("service {name}"));
            state.remaining.push(remaining);
            if state.refused.contains(&name) {
                Err(ServiceRefusal::Structure)
            } else {
                Ok(())
            }
        }

        fn check(&self, check: &Check, remaining: Duration) -> Result<bool, CheckError> {
            let mut state = self.state();
            let kind = match check {
                Check::ServiceState { .. } => "service_state",
                Check::PathExists { .. } => "path_exists",
                Check::PathAbsent { .. } => "path_absent",
                Check::DiskFreeAtLeast { .. } => "disk_free_at_least",
            };
            state.calls.push(format!("check {kind}"));
            state.remaining.push(remaining);
            let gate = state.gate.clone().filter(|_| state.gate_checks);
            drop(state);
            if let Some(gate) = gate {
                let _ = gate.started.send(());
                let _ = gate.release.lock().unwrap().recv();
            }
            self.state().checks.pop_front().unwrap_or(Ok(true))
        }

        fn step(&self, step: &Primitive, remaining: Duration) -> Result<(), StepError> {
            let gate = {
                let mut state = self.state();
                let op = match step {
                    Primitive::ServiceRestart { .. } => "service_restart",
                    Primitive::ServiceStart { .. } => "service_start",
                    Primitive::ServiceStop { .. } => "service_stop",
                    Primitive::DeleteFile { .. } => "delete_file",
                    _ => "other",
                };
                state.calls.push(format!("step {op}"));
                state.remaining.push(remaining);
                state.active += 1;
                state.most_active = state.most_active.max(state.active);
                state.gate.clone()
            };
            if let Some(gate) = gate {
                let _ = gate.started.send(());
                let _ = gate.release.lock().unwrap().recv();
            }
            let mut state = self.state();
            state.active -= 1;
            if let Some(clock) = &state.clock {
                clock.advance(state.step_takes);
            }
            state.steps.pop_front().unwrap_or(Ok(()))
        }
    }

    // ----- Disks -----------------------------------------------------------------------

    /// The journal's disk as one run of the agent sees it. When that run ends, whatever
    /// it still tries to write is lost, as it would be.
    struct LiveDisk {
        inner: FakeJournalDisk,
        alive: Arc<AtomicBool>,
    }

    impl JournalDisk for LiveDisk {
        fn read(&self, file: JournalFile) -> io::Result<Option<String>> {
            self.inner.read(file)
        }

        fn write(&self, file: JournalFile, text: &str) -> io::Result<()> {
            if !self.alive.load(Ordering::SeqCst) {
                return Err(io::Error::other("the process is gone"));
            }
            self.inner.write(file, text)
        }

        fn lock(&self) -> io::Result<()> {
            self.inner.lock()
        }
    }

    // ----- The harness -----------------------------------------------------------------

    /// An executor on fake clocks, disks and machine, which outlive a restart.
    struct Harness {
        clock: FakeClock,
        disk: FakeJournalDisk,
        mark: MemoryMark,
        machine: FakeMachine,
        settings: ActionSettings,
        alive: Arc<AtomicBool>,
        runner: Option<ActionRunner>,
        unsupported: bool,
    }

    fn settings(more: &str) -> ActionSettings {
        let toml = format!(
            "server_url = 'wss://ponte.example.com'\ndata_dir = 'data'\n\
             allowed_roots = ['C:\\FakeErp']\ndelete_roots = ['C:\\FakeErp\\run']\n\
             allowed_services = ['FakeErp']\n{more}"
        );
        toml.parse::<AgentConfig>().unwrap().actions
    }

    fn with_keys(more: &str) -> String {
        format!("manifest_keys = ['{}']\n{more}", key_hex(1))
    }

    impl Harness {
        fn new(more: &str) -> Self {
            Self::configured(settings(&with_keys(more)))
        }

        fn configured(settings: ActionSettings) -> Self {
            let clock = FakeClock::at(NOW);
            let machine = FakeMachine::default();
            machine.state().clock = Some(clock.clone());
            Self {
                clock,
                disk: FakeJournalDisk::default(),
                mark: MemoryMark::default(),
                machine,
                settings,
                alive: Arc::new(AtomicBool::new(true)),
                runner: None,
                unsupported: false,
            }
        }

        async fn start(&mut self) -> Actions {
            self.alive = Arc::new(AtomicBool::new(true));
            let machine: Arc<dyn Machine> = if self.unsupported {
                Arc::new(Unsupported)
            } else {
                Arc::new(self.machine.clone())
            };
            let runner = start(
                self.settings.clone(),
                Arc::new(LiveDisk {
                    inner: self.disk.clone(),
                    alive: Arc::clone(&self.alive),
                }),
                Arc::new(self.mark.clone()),
                Arc::new(self.clock.clone()),
                machine,
            )
            .await;
            let actions = runner.actions();
            self.runner = Some(runner);
            actions
        }

        /// The agent stops as it should, and its process ends.
        async fn stop(&mut self) {
            let runner = self.runner.take().unwrap();
            runner.stop(self.settings.shutdown_timeout).await;
            self.alive.store(false, Ordering::SeqCst);
        }

        /// The power goes: nothing more reaches the disk, and memory is gone.
        fn crash(&mut self) {
            self.alive.store(false, Ordering::SeqCst);
            self.runner.take().unwrap().crash();
        }

        async fn restart(&mut self) -> Actions {
            self.stop().await;
            self.start().await
        }

        async fn crash_and_restart(&mut self) -> Actions {
            self.crash();
            self.start().await
        }
    }

    /// Lets every task that can move do so. A task waiting on a held step cannot.
    async fn settle() {
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
    }

    /// The next answer, sent as a session would send it.
    async fn next(actions: &Actions) -> ActionResult {
        let wait = async {
            loop {
                if let Some((ticket, result)) = actions.next_to_send() {
                    actions.sent(ticket);
                    return result;
                }
                actions.ready().await;
            }
        };
        tokio::time::timeout(Duration::from_secs(DAY), wait)
            .await
            .expect("no answer")
    }

    /// Every answer waiting now, sent.
    fn drain(actions: &Actions) -> Vec<ActionResult> {
        std::iter::from_fn(|| {
            let (ticket, result) = actions.next_to_send()?;
            actions.sent(ticket);
            Some(result)
        })
        .collect()
    }

    fn outcomes(results: Vec<ActionResult>) -> Vec<ActionOutcome> {
        results.into_iter().map(|result| result.outcome).collect()
    }

    /// Submits `request` and returns its outcome.
    async fn outcome(actions: &Actions, request: Box<ActionRequest>) -> ActionOutcome {
        let id = request.request_id;
        actions.submit(request);
        let result = next(actions).await;
        assert_eq!(result.request_id, id);
        assert_eq!(result.output, None);
        result.outcome
    }

    /// A request for `manifest` that started at `at` and succeeded, on disk before the
    /// agent starts.
    fn started_before(harness: &Harness, manifest: &str, at: u64) {
        let entry = started_entry(1 << 100, manifest, at);
        harness.disk.files().started = Some(format!(r#"{{"format":1,"started":[{entry}]}}"#));
    }

    fn started_entry(n: u128, manifest: &str, at: u64) -> String {
        format!(
            r#"{{"request_id":"{}","manifest_id":"{manifest}","started_at":{at},"expires_at":{},"end":{{"outcome":{{"status":"succeeded"}},"duration_ms":1}},"delivered":true}}"#,
            id(n),
            NOW + DAY
        )
    }

    /// As many started requests as the journal holds, outside the hourly window.
    fn fill_journal(harness: &Harness) {
        let entries: Vec<String> = (0..u128::try_from(MAX_STARTED).unwrap())
            .map(|n| started_entry((1 << 100) + n, "erp.other", NOW - 2 * HOUR))
            .collect();
        harness.disk.files().started = Some(format!(
            r#"{{"format":1,"started":[{}]}}"#,
            entries.join(",")
        ));
    }

    // ----- What runs, and how it ends --------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn a_signed_manifest_inside_the_policy_runs_once_and_succeeds() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;

        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        assert_eq!(
            harness.machine.calls(),
            [
                "service FakeErp",
                "service FakeErp",
                "check disk_free_at_least",
                "step service_restart",
                "check service_state",
            ]
        );
        // The start and the end go to disk at once.
        let writes = harness.disk.files().writes.clone();
        assert_eq!(writes, [JournalFile::Started, JournalFile::Started]);
    }

    #[tokio::test(start_paused = true)]
    async fn every_call_gets_the_time_the_manifest_has_left() {
        let mut harness = Harness::new("");
        harness.machine.state().step_takes = Duration::from_secs(25);
        let actions = harness.start().await;
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        // `timeout_secs = 60`: the two services, the precondition, the step, then the check
        // 25 s later.
        let full = Duration::from_secs(60);
        assert_eq!(
            harness.machine.state().remaining,
            [full, full, full, full, Duration::from_secs(35)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_step_that_fails_ends_the_run_with_its_index() {
        for (error, wanted) in [
            (
                StepError::Failed,
                ActionOutcome::Failed {
                    reason: FailReason::StepFailed,
                    step: Some(0),
                },
            ),
            (
                StepError::PathRefused,
                ActionOutcome::Failed {
                    reason: FailReason::PathRefused,
                    step: Some(0),
                },
            ),
            (StepError::TimedOut, ActionOutcome::TimedOut {}),
        ] {
            let mut harness = Harness::new("");
            harness.machine.state().steps.push_back(Err(error));
            let actions = harness.start().await;
            assert_eq!(outcome(&actions, request(1, CLEAR_LOCK)).await, wanted);
            // Nothing after the failed step: no second step, no verification.
            let calls = harness.machine.calls();
            assert_eq!(calls.last().map(String::as_str), Some("step delete_file"));
        }
        // The index is the step's.
        let mut harness = Harness::new("");
        harness
            .machine
            .state()
            .steps
            .extend([Ok(()), Err(StepError::Failed)]);
        let actions = harness.start().await;
        assert_eq!(
            outcome(&actions, request(1, CLEAR_LOCK)).await,
            ActionOutcome::Failed {
                reason: FailReason::StepFailed,
                step: Some(1)
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_verification_that_does_not_hold_fails_the_run() {
        for answer in [Ok(false), Err(CheckError::Failed)] {
            let mut harness = Harness::new("");
            // The precondition holds, the verification does not.
            harness.machine.state().checks.extend([Ok(true), answer]);
            let actions = harness.start().await;
            assert_eq!(
                outcome(&actions, request(1, RESTART)).await,
                ActionOutcome::Failed {
                    reason: FailReason::VerifyFailed,
                    step: None
                }
            );
        }
        let mut harness = Harness::new("");
        harness
            .machine
            .state()
            .checks
            .extend([Ok(true), Err(CheckError::TimedOut)]);
        let actions = harness.start().await;
        assert_eq!(
            outcome(&actions, request(1, RESTART)).await,
            ActionOutcome::TimedOut {}
        );
    }

    /// A step that returns after the deadline leaves no time for what comes next.
    #[tokio::test(start_paused = true)]
    async fn a_run_past_its_time_ends_timed_out() {
        let mut harness = Harness::new("");
        harness.machine.state().step_takes = Duration::from_secs(61);
        let actions = harness.start().await;
        assert_eq!(
            outcome(&actions, request(1, CLEAR_LOCK)).await,
            ActionOutcome::TimedOut {}
        );
        assert_eq!(harness.machine.steps(), 1);
    }

    // ----- Every refusal ---------------------------------------------------------------

    /// One case for each `RejectReason` the agent produces, and whether the machine was
    /// asked anything for it. Nothing ever steps.
    #[tokio::test(start_paused = true)]
    async fn every_refusal_the_agent_gives() {
        struct Case {
            reason: RejectReason,
            config: String,
            prepare: fn(&Harness),
            request: Box<ActionRequest>,
            asks_the_machine: bool,
        }
        fn case(reason: RejectReason, request: Box<ActionRequest>) -> Case {
            Case {
                reason,
                config: with_keys(""),
                prepare: |_| {},
                request,
                asks_the_machine: false,
            }
        }
        let cases = [
            Case {
                config: String::new(),
                ..case(RejectReason::ActionsDisabled, request(1, RESTART))
            },
            case(
                RejectReason::UnknownKey,
                request_with(1, sign(RESTART, 2, NOW - HOUR, NOW + DAY), NOW + HOUR),
            ),
            case(
                RejectReason::BadSignature,
                request_with(1, badly_signed(RESTART), NOW + HOUR),
            ),
            case(
                RejectReason::ManifestNotYetValid,
                request_with(1, sign(RESTART, 1, NOW + 301, NOW + DAY), NOW + HOUR),
            ),
            case(
                RejectReason::ManifestExpired,
                request_with(1, sign(RESTART, 1, NOW - DAY, NOW), NOW + HOUR),
            ),
            case(
                RejectReason::ValidityTooLong,
                request_with(
                    1,
                    sign(RESTART, 1, NOW - HOUR, NOW - HOUR + 366 * DAY),
                    NOW + HOUR,
                ),
            ),
            Case {
                prepare: |harness| {
                    harness
                        .mark
                        .set(Some(format!("high_water = {}\n", NOW + HOUR + 1)));
                },
                ..case(RejectReason::ClockWentBack, request(1, RESTART))
            },
            case(
                RejectReason::RequestExpired,
                request_with(1, signed(RESTART), NOW),
            ),
            case(
                RejectReason::RequestTooFarAhead,
                request_with(1, signed(RESTART), NOW + DAY + 5 * 60 + 1),
            ),
            case(
                RejectReason::InvalidManifest,
                request(1, "id = 'erp.nothing'\n"),
            ),
            case(
                RejectReason::PrimitiveRefused,
                request(
                    1,
                    &RESTART.replace(
                        "op = \"service_restart\"\nservice = \"FakeErp\"",
                        "op = \"clear_temp_dir\"",
                    ),
                ),
            ),
            Case {
                config: with_keys("max_risk = 'low'"),
                ..case(RejectReason::RiskAboveCeiling, request(1, RESTART))
            },
            case(
                RejectReason::ServiceNotAllowed,
                request(1, &RESTART.replace("FakeErp", "OtherErp")),
            ),
            Case {
                prepare: |harness| harness.machine.state().refused.push("FakeErp"),
                asks_the_machine: true,
                ..case(RejectReason::ServiceRefused, request(1, RESTART))
            },
            case(
                RejectReason::PathNotAllowed,
                request(
                    1,
                    &CLEAR_LOCK.replace(r"C:\FakeErp\run", r"C:\FakeErp\data"),
                ),
            ),
            Case {
                config: with_keys("max_actions_per_hour = 1"),
                prepare: |harness| started_before(harness, "erp.other", NOW - 60),
                ..case(RejectReason::RateLimited, request(1, RESTART))
            },
            Case {
                prepare: |harness| started_before(harness, "erp.restart-service", NOW - 599),
                ..case(RejectReason::TooSoon, request(1, RESTART))
            },
            Case {
                prepare: fill_journal,
                ..case(RejectReason::JournalFull, request(1, RESTART))
            },
            Case {
                prepare: |harness| harness.disk.files().ended = Some("{}".to_owned()),
                ..case(RejectReason::JournalUnavailable, request(1, RESTART))
            },
            Case {
                prepare: |harness| harness.machine.state().checks.push_back(Ok(false)),
                asks_the_machine: true,
                ..case(RejectReason::PreconditionFailed, request(1, RESTART))
            },
        ];
        for case in cases {
            let mut harness = Harness::configured(settings(&case.config));
            (case.prepare)(&harness);
            let actions = harness.start().await;
            assert_eq!(
                outcome(&actions, case.request).await,
                refused(case.reason),
                "{:?}",
                case.reason
            );
            let calls = harness.machine.calls();
            assert_eq!(
                !calls.is_empty(),
                case.asks_the_machine,
                "{:?}: {calls:?}",
                case.reason
            );
            assert_eq!(harness.machine.steps(), 0, "{:?}", case.reason);
        }
    }

    /// `QueueFull` and `ShuttingDown`, which need something to be running.
    #[tokio::test(start_paused = true)]
    async fn a_full_queue_and_a_stop_refuse_what_arrives() {
        let mut harness = Harness::new("");
        let mut gate = harness.machine.gate();
        let actions = harness.start().await;
        actions.submit(request(1, RESTART));
        gate.step_started().await;
        // Four wait, a duplicate of the running one among them; the fifth is refused.
        actions.submit(request(1, RESTART));
        for n in 2..=4 {
            actions.submit(request(n, DELETE_ONLY));
        }
        actions.submit(request(5, DELETE_ONLY));
        assert_eq!(
            drain(&actions),
            [rejected(id(5), RejectReason::QueueFull, 0)]
        );
        // Duplicates are no way around the limit.
        actions.submit(request(1, RESTART));
        assert_eq!(
            drain(&actions),
            [rejected(id(1), RejectReason::QueueFull, 0)]
        );
        harness.machine.open();
        gate.release();
        harness.stop().await;

        actions.submit(request(6, RESTART));
        let answers: Vec<ActionResult> = drain(&actions)
            .into_iter()
            .filter(|result| result.request_id == id(6))
            .collect();
        assert_eq!(answers, [rejected(id(6), RejectReason::ShuttingDown, 0)]);
    }

    /// The first rule a request breaks is the one it hears about, in the order of
    /// ADR-0012. A limit that is reached spares the signature check.
    #[tokio::test(start_paused = true)]
    async fn the_first_rule_broken_is_the_answer() {
        let mut harness = Harness::new("max_actions_per_hour = 1");
        harness
            .mark
            .set(Some(format!("high_water = {}\n", NOW + 2 * HOUR)));
        let actions = harness.start().await;
        assert_eq!(
            outcome(&actions, request_with(1, badly_signed(RESTART), NOW)).await,
            refused(RejectReason::ClockWentBack)
        );

        let mut harness = Harness::new("max_actions_per_hour = 1");
        started_before(&harness, "erp.other", NOW - 60);
        let actions = harness.start().await;
        assert_eq!(
            outcome(&actions, request_with(2, badly_signed(RESTART), NOW)).await,
            refused(RejectReason::RequestExpired)
        );
        assert_eq!(
            outcome(&actions, request_with(3, badly_signed(RESTART), NOW + HOUR)).await,
            refused(RejectReason::RateLimited)
        );

        let mut harness = Harness::new("");
        started_before(&harness, "erp.restart-service", NOW - 60);
        let actions = harness.start().await;
        assert_eq!(
            outcome(&actions, request_with(4, badly_signed(RESTART), NOW + HOUR)).await,
            refused(RejectReason::BadSignature)
        );
        assert_eq!(
            outcome(
                &actions,
                request(5, &RESTART.replace("FakeErp", "OtherErp"))
            )
            .await,
            refused(RejectReason::TooSoon)
        );
        // The machine's refusal comes before any precondition is read.
        harness.machine.state().refused.push("FakeErp");
        assert_eq!(
            outcome(&actions, request(6, CLEAR_LOCK)).await,
            refused(RejectReason::ServiceRefused)
        );
        assert!(
            !harness
                .machine
                .calls()
                .iter()
                .any(|call| call.starts_with("check"))
        );
    }

    /// The compiled list wins over the configuration: a refused service is refused, not
    /// "not allowed", and never reaches the machine.
    #[tokio::test(start_paused = true)]
    async fn the_refused_services_win_over_allowed_services() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;
        for (n, name) in [(1, "WinDefend"), (2, "windefend"), (3, "PonteAgent")] {
            assert_eq!(
                outcome(&actions, request(n, &RESTART.replace("FakeErp", name))).await,
                refused(RejectReason::ServiceRefused),
                "{name}"
            );
        }
        assert_eq!(harness.machine.calls(), Vec::<String>::new());
    }

    /// Outside Windows nothing gets to "started" with the manifests of M2.
    #[tokio::test(start_paused = true)]
    async fn the_unsupported_platform_starts_nothing() {
        let mut harness = Harness::new("");
        harness.unsupported = true;
        let actions = harness.start().await;
        assert_eq!(
            outcome(&actions, request(1, RESTART)).await,
            refused(RejectReason::ServiceRefused)
        );
        assert_eq!(
            outcome(&actions, request(2, CLEAR_LOCK)).await,
            refused(RejectReason::ServiceRefused)
        );
        assert_eq!(
            outcome(&actions, request(3, DELETE_ONLY)).await,
            refused(RejectReason::PreconditionFailed)
        );
        harness.stop().await;
        assert_eq!(harness.disk.files().started, None);
    }

    // ----- At most once ----------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn a_repeat_gets_the_stored_answer_before_and_after_a_restart() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;

        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        assert_eq!(
            outcome(&actions, request_with(2, badly_signed(RESTART), NOW + HOUR)).await,
            refused(RejectReason::BadSignature)
        );
        // Sent again: the stored answers, and nothing runs. This copy of request 2 is well
        // signed, and that changes nothing.
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        assert_eq!(
            outcome(&actions, request(2, RESTART)).await,
            refused(RejectReason::BadSignature)
        );
        assert_eq!(harness.machine.steps(), 1);

        let actions = harness.restart().await;
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        assert_eq!(
            outcome(&actions, request(2, RESTART)).await,
            refused(RejectReason::BadSignature)
        );
        // A crash loses nothing that started.
        let actions = harness.crash_and_restart().await;
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        assert_eq!(harness.machine.steps(), 1);
    }

    /// A duplicate that arrives while the first one runs waits, and gets the first one's
    /// answer.
    #[tokio::test(start_paused = true)]
    async fn a_duplicate_that_waits_gets_the_first_ones_answer() {
        let mut harness = Harness::new("min_manifest_interval_secs = 60");
        // Longer than the interval below, so that the first run outlives it.
        let slow = RESTART.replace("timeout_secs = 60", "timeout_secs = 120");
        let mut gate = harness.machine.gate();
        let actions = harness.start().await;
        actions.submit(request(1, &slow));
        gate.step_started().await;
        actions.submit(request(1, &slow));
        actions.submit(request(1, &slow));
        // Past the interval: only the journal stands between the copies and the machine.
        harness.clock.advance(Duration::from_secs(61));
        harness.machine.open();
        gate.release();
        assert_eq!(next(&actions).await.outcome, succeeded());
        settle().await;
        let more = drain(&actions);
        assert!(
            more.iter()
                .all(|result| result.request_id == id(1) && result.outcome == succeeded()),
            "{more:?}"
        );
        assert_eq!(harness.machine.steps(), 1);
        // The copies were answered when they left the queue, before anything was read.
        assert_eq!(harness.machine.calls().len(), 5);
    }

    /// A repeat of a request that ended is answered when it arrives, before the queue is
    /// looked at: a full queue does not turn a stored answer into `QueueFull`.
    #[tokio::test(start_paused = true)]
    async fn a_repeat_is_answered_on_arrival_even_with_a_full_queue() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());

        let mut gate = harness.machine.gate();
        actions.submit(request(2, DELETE_ONLY));
        gate.step_started().await;
        for n in 3..=6 {
            actions.submit(request(n, CLEAR_LOCK));
        }
        actions.submit(request(1, RESTART));
        let answers: Vec<(RequestId, ActionOutcome)> = drain(&actions)
            .into_iter()
            .map(|result| (result.request_id, result.outcome))
            .collect();
        assert_eq!(answers, [(id(1), succeeded())]);
        harness.machine.open();
        gate.release();
    }

    /// The power goes while a step runs. The request never runs again, and the server
    /// hears that it was interrupted.
    #[tokio::test(start_paused = true)]
    async fn a_crash_between_started_and_the_end_is_an_interruption() {
        let mut harness = Harness::new("");
        let mut gate = harness.machine.gate();
        let actions = harness.start().await;
        actions.submit(request(1, CLEAR_LOCK));
        gate.step_started().await;
        harness.crash();
        drop(actions);
        harness.machine.open();

        let actions = harness.start().await;
        assert_eq!(next(&actions).await.outcome, interrupted());
        assert_eq!(
            outcome(&actions, request(1, CLEAR_LOCK)).await,
            interrupted()
        );
        let actions = harness.restart().await;
        assert_eq!(
            outcome(&actions, request(1, CLEAR_LOCK)).await,
            interrupted()
        );
        assert_eq!(harness.machine.steps(), 1);
        // The thread of the run that was cut off comes back to a process that is gone.
        gate.release();
    }

    /// A result whose session dropped before it went out goes with the next session, also
    /// after a crash.
    #[tokio::test(start_paused = true)]
    async fn a_result_that_was_not_sent_goes_out_with_the_next_session() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;
        actions.submit(request(1, RESTART));
        let first = loop {
            if let Some((_, waiting)) = actions.next_to_send() {
                break waiting;
            }
            actions.ready().await;
        };
        // The session ends before sending it; the next one finds it.
        actions.session_started();
        assert_eq!(
            actions.next_to_send().map(|(_, result)| result),
            Some(first.clone())
        );

        let actions = harness.crash_and_restart().await;
        actions.session_started();
        let (ticket, after) = actions.next_to_send().unwrap();
        assert_eq!(after, first);
        actions.sent(ticket);
        assert_eq!(actions.next_to_send(), None);

        // Sent, and the delivery written at stop: nothing to send after a restart.
        let actions = harness.restart().await;
        assert_eq!(actions.next_to_send(), None);
        assert_eq!(harness.machine.steps(), 1);
    }

    /// The disk fails at each write in turn, the power goes, and the agent starts again
    /// with a disk that works. The request never runs twice, and the journal left behind
    /// is always one this build reads.
    #[tokio::test(start_paused = true)]
    async fn a_disk_that_fails_at_any_write_never_runs_a_request_twice() {
        for failing in 0..6 {
            let mut harness = Harness::new("");
            harness.disk.fail_after(failing);
            let actions = harness.start().await;
            let first = outcome(&actions, request(1, DELETE_ONLY)).await;
            tokio::time::sleep(2 * LAZY_WRITES_EVERY).await;
            harness.crash();
            harness.disk.works_again();

            let actions = harness.start().await;
            let again = outcome(&actions, request(1, DELETE_ONLY)).await;
            assert_ne!(
                again,
                refused(RejectReason::JournalUnavailable),
                "write {failing}"
            );
            assert!(harness.machine.steps() <= 1, "write {failing}: ran twice");
            if first == succeeded() {
                assert!(
                    again == succeeded() || again == interrupted(),
                    "write {failing}: {again:?}"
                );
            }
            harness.stop().await;
        }
    }

    // ----- Limits ----------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn the_hourly_limit_counts_started_requests_across_a_restart() {
        let mut harness = Harness::new("max_actions_per_hour = 2\nmin_manifest_interval_secs = 60");
        let actions = harness.start().await;
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        // A failed precondition starts nothing, so it counts for nothing.
        harness.machine.state().checks.push_back(Ok(false));
        assert_eq!(
            outcome(&actions, request(2, CLEAR_LOCK)).await,
            refused(RejectReason::PreconditionFailed)
        );
        assert_eq!(outcome(&actions, request(3, CLEAR_LOCK)).await, succeeded());

        let actions = harness.restart().await;
        assert_eq!(
            outcome(&actions, request(4, DELETE_ONLY)).await,
            refused(RejectReason::RateLimited)
        );
        // An hour after the first two started, by the mark, there is room again.
        harness.clock.advance(Duration::from_secs(HOUR));
        assert_eq!(
            outcome(
                &actions,
                request_with(5, signed(DELETE_ONLY), NOW + 2 * HOUR)
            )
            .await,
            succeeded()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_interval_between_runs_of_a_manifest_holds_across_versions_and_restarts() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;
        assert_eq!(outcome(&actions, request(1, CLEAR_LOCK)).await, succeeded());
        harness.clock.advance(Duration::from_secs(599));
        let version_3 = CLEAR_LOCK.replace("version = 2", "version = 3");
        assert_eq!(
            outcome(&actions, request(2, &version_3)).await,
            refused(RejectReason::TooSoon)
        );
        let actions = harness.restart().await;
        assert_eq!(
            outcome(&actions, request(3, CLEAR_LOCK)).await,
            refused(RejectReason::TooSoon)
        );
        // Another manifest is not held back.
        assert_eq!(outcome(&actions, request(4, RESTART)).await, succeeded());
        harness.clock.advance(Duration::from_secs(1));
        assert_eq!(outcome(&actions, request(5, &version_3)).await, succeeded());
    }

    /// The limits follow the mark: a clock set back makes no room.
    #[tokio::test(start_paused = true)]
    async fn setting_the_clock_back_does_not_reset_the_limits() {
        let mut harness = Harness::new("max_actions_per_hour = 1");
        let actions = harness.start().await;
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        harness.clock.advance(Duration::from_secs(30 * 60));
        harness.clock.set_wall(NOW - 30 * 60);
        let early = |n| {
            request_with(
                n,
                sign(DELETE_ONLY, 1, NOW - 2 * HOUR, NOW + DAY),
                NOW + HOUR,
            )
        };
        assert_eq!(
            outcome(&actions, early(2)).await,
            refused(RejectReason::RateLimited)
        );
        let actions = harness.restart().await;
        assert_eq!(
            outcome(&actions, early(3)).await,
            refused(RejectReason::RateLimited)
        );
    }

    /// The limits follow the mark: a clock thrown ahead while the agent runs makes no
    /// room either.
    #[tokio::test(start_paused = true)]
    async fn a_clock_thrown_ahead_does_not_reset_the_limits() {
        let mut harness = Harness::new("max_actions_per_hour = 1");
        let actions = harness.start().await;
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        harness.clock.set_wall(NOW + 2 * HOUR);
        assert_eq!(
            outcome(
                &actions,
                request_with(2, signed(DELETE_ONLY), NOW + 3 * HOUR)
            )
            .await,
            refused(RejectReason::RateLimited)
        );
    }

    // ----- The queue, cancelling, the lock and stopping --------------------------------

    #[tokio::test(start_paused = true)]
    async fn only_a_waiting_request_can_be_cancelled() {
        let mut harness = Harness::new("");
        let mut gate = harness.machine.gate();
        let actions = harness.start().await;
        actions.submit(request(1, RESTART));
        gate.step_started().await;
        actions.submit(request(2, CLEAR_LOCK));
        actions.submit(request(2, CLEAR_LOCK));
        actions.submit(request(3, DELETE_ONLY));

        // The running one runs on.
        actions.cancel(id(1));
        // Both copies of the waiting one go, with one answer.
        actions.cancel(id(2));
        actions.cancel(id(9));
        assert_eq!(
            drain(&actions),
            [answer(id(2), ActionOutcome::Cancelled {}, 0)]
        );

        harness.machine.open();
        gate.release();
        let mut rest = vec![next(&actions).await, next(&actions).await];
        rest.sort_by_key(|result| result.request_id);
        assert_eq!(outcomes(rest), [succeeded(), succeeded()]);
        // Cancelled is the answer for good, also after a restart.
        assert_eq!(
            outcome(&actions, request(2, CLEAR_LOCK)).await,
            ActionOutcome::Cancelled {}
        );
        let actions = harness.restart().await;
        assert_eq!(
            outcome(&actions, request(2, CLEAR_LOCK)).await,
            ActionOutcome::Cancelled {}
        );
        assert_eq!(harness.machine.steps(), 2);
    }

    /// Cancelling a request that left the queue takes its waiting copies and nothing else:
    /// a "cancelled" for a request that then runs would name the id twice in the journal.
    #[tokio::test(start_paused = true)]
    async fn a_request_being_decided_is_not_cancelled() {
        // Cancelled while its preconditions are read, and again once it started.
        for hold_checks in [true, false] {
            let mut harness = Harness::new("");
            let mut gate = harness.machine.gate();
            harness.machine.state().gate_checks = hold_checks;
            let actions = harness.start().await;
            actions.submit(request(1, RESTART));
            gate.step_started().await;
            actions.submit(request(1, RESTART));
            actions.cancel(id(1));
            assert_eq!(drain(&actions), [], "{hold_checks}");
            harness.machine.open();
            gate.release();
            assert_eq!(next(&actions).await.outcome, succeeded(), "{hold_checks}");
            assert_eq!(harness.machine.steps(), 1, "{hold_checks}");
            let actions = harness.restart().await;
            assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        }
    }

    /// One at a time, and the lock is only released when the blocking work has returned,
    /// however far past its deadline.
    #[tokio::test(start_paused = true)]
    async fn one_action_at_a_time_even_past_its_deadline() {
        let mut harness = Harness::new("");
        let mut gate = harness.machine.gate();
        let actions = harness.start().await;
        actions.submit(request(1, RESTART));
        gate.step_started().await;
        actions.submit(request(2, CLEAR_LOCK));
        // Far past the manifest's 60 seconds, the step has not returned.
        harness.clock.advance(Duration::from_secs(10 * 60));
        // The runtime's clock too: a timeout around the blocking task would fire now.
        tokio::time::advance(Duration::from_secs(10 * 60)).await;
        settle().await;
        assert_eq!(harness.machine.steps(), 1);
        assert_eq!(drain(&actions), []);

        gate.release();
        assert_eq!(next(&actions).await.outcome, ActionOutcome::TimedOut {});
        gate.step_started().await;
        harness.machine.open();
        gate.release();
        assert_eq!(next(&actions).await.outcome, succeeded());
        assert_eq!(harness.machine.state().most_active, 1);
    }

    /// A stop waits up to `shutdown_timeout_secs` for the running action. What does not
    /// end in time is interrupted, and what waited in the queue is dropped unanswered.
    #[tokio::test(start_paused = true)]
    async fn a_stop_waits_for_the_running_action_up_to_its_timeout() {
        let mut harness = Harness::new("shutdown_timeout_secs = 10");
        let mut gate = harness.machine.gate();
        let actions = harness.start().await;
        actions.submit(request(1, RESTART));
        gate.step_started().await;
        actions.submit(request(2, CLEAR_LOCK));

        let runner = harness.runner.take().unwrap();
        let stopping = tokio::spawn(runner.stop(Duration::from_secs(10)));
        settle().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        settle().await;
        assert!(!stopping.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        stopping.await.unwrap();
        // The process ends here; the step comes back to nothing.
        harness.alive.store(false, Ordering::SeqCst);
        harness.machine.open();
        gate.release();

        let actions = harness.start().await;
        assert_eq!(outcomes(drain(&actions)), [interrupted()]);
        // Request 2 was dropped: sent again, it is decided now.
        assert_eq!(outcome(&actions, request(2, CLEAR_LOCK)).await, succeeded());
    }

    /// A stop that comes while a request is in its preconditions starts nothing new.
    #[tokio::test(start_paused = true)]
    async fn a_request_is_not_started_once_the_agent_stops() {
        let mut harness = Harness::new("");
        let mut gate = harness.machine.gate();
        harness.machine.state().gate_checks = true;
        let actions = harness.start().await;
        actions.submit(request(1, RESTART));
        gate.step_started().await;
        let runner = harness.runner.take().unwrap();
        let stopping = tokio::spawn(runner.stop(Duration::from_secs(10)));
        settle().await;
        harness.machine.open();
        gate.release();
        stopping.await.unwrap();
        assert_eq!(
            outcomes(drain(&actions)),
            [refused(RejectReason::ShuttingDown)]
        );
        assert_eq!(harness.machine.steps(), 0);
        assert_eq!(harness.disk.files().started, None);
    }

    /// The moment the agent is told to stop, the queue is gone and nothing new starts, even
    /// before the session has closed and the runner is waited for.
    #[tokio::test(start_paused = true)]
    async fn a_halt_drops_the_queue_at_once() {
        let mut harness = Harness::new("");
        let mut gate = harness.machine.gate();
        let actions = harness.start().await;
        actions.submit(request(1, RESTART));
        gate.step_started().await;
        actions.submit(request(2, CLEAR_LOCK));
        harness.runner.as_ref().unwrap().halt();
        actions.submit(request(3, CLEAR_LOCK));
        harness.machine.open();
        gate.release();
        assert_eq!(next(&actions).await.request_id, id(3));
        assert_eq!(next(&actions).await.outcome, succeeded());
        settle().await;
        assert_eq!(drain(&actions), []);
        assert_eq!(harness.machine.steps(), 1);
        harness.stop().await;
    }

    /// The twin of the test above: an action that ends in time ends as it should.
    #[tokio::test(start_paused = true)]
    async fn a_stop_lets_an_action_that_ends_in_time_finish() {
        let mut harness = Harness::new("");
        let mut gate = harness.machine.gate();
        let actions = harness.start().await;
        actions.submit(request(1, RESTART));
        gate.step_started().await;
        let runner = harness.runner.take().unwrap();
        let stopping = tokio::spawn(runner.stop(Duration::from_secs(10)));
        settle().await;
        gate.release();
        stopping.await.unwrap();
        harness.alive.store(false, Ordering::SeqCst);
        harness.machine.open();
        drop(actions);

        let actions = harness.start().await;
        assert_eq!(outcomes(drain(&actions)), [succeeded()]);
    }

    // ----- The disk, and what is written when ------------------------------------------

    /// Refusals reach the disk at most once a minute: a server that sends refused
    /// requests in a loop does not get a write per request.
    #[tokio::test(start_paused = true)]
    async fn refusals_are_written_at_most_once_a_minute() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;
        let writes = |harness: &Harness| harness.disk.files().writes.len();
        for n in 1..=50 {
            assert_eq!(
                outcome(&actions, request_with(n, badly_signed(RESTART), NOW + HOUR)).await,
                refused(RejectReason::BadSignature)
            );
        }
        // A second past the write, which the runtime's clock only reaches once the
        // blocking task that writes has returned: `settle` alone does not wait for it.
        tokio::time::sleep(LAZY_WRITES_EVERY + Duration::from_secs(1)).await;
        assert_eq!(writes(&harness), 1);
        assert_eq!(harness.disk.files().writes, [JournalFile::Ended]);
        assert_eq!(LAZY_WRITES_EVERY, Duration::from_secs(60));
        // And they are there after a restart.
        let actions = harness.crash_and_restart().await;
        assert_eq!(
            outcome(&actions, request(50, RESTART)).await,
            refused(RejectReason::BadSignature)
        );
    }

    /// An id that left the ring in memory, while the ring on disk still holds it, starts;
    /// the power goes before the ring's next write. Both files name it, and the journal
    /// must still be usable: the start wins, and the request never runs again.
    #[tokio::test(start_paused = true)]
    async fn a_crash_with_an_id_in_both_files_leaves_a_usable_journal() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;
        assert_eq!(
            outcome(&actions, request_with(1, badly_signed(RESTART), NOW + HOUR)).await,
            refused(RejectReason::BadSignature)
        );
        tokio::time::sleep(LAZY_WRITES_EVERY + Duration::from_secs(1)).await;
        settle().await;
        let first = id(1).to_string();
        assert!(
            harness
                .disk
                .files()
                .ended
                .as_deref()
                .unwrap()
                .contains(&first)
        );
        // A thousand and more refusals push it out of the ring, in memory only.
        for n in 2..=1025 {
            actions.submit(request_with(n, badly_signed(RESTART), NOW + HOUR));
            settle().await;
            drain(&actions);
        }
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        {
            let files = harness.disk.files();
            assert!(files.started.as_deref().unwrap().contains(&first));
            assert!(files.ended.as_deref().unwrap().contains(&first));
        }
        let actions = harness.crash_and_restart().await;
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        assert_eq!(
            outcome(&actions, request(2000, CLEAR_LOCK)).await,
            succeeded()
        );
        assert_eq!(harness.machine.steps(), 3);
    }

    /// The lazy writes put the started requests first, and leave the ring for later when
    /// that write fails: the ring never reaches the disk before the file an id left.
    #[tokio::test(start_paused = true)]
    async fn the_ring_waits_for_the_started_requests_to_be_written() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
        assert_eq!(
            outcome(&actions, request_with(2, badly_signed(RESTART), NOW + HOUR)).await,
            refused(RejectReason::BadSignature)
        );
        // Both files are dirty now: the delivered mark of 1, the refusal of 2.
        let before = harness.disk.files().writes.len();
        harness.disk.fail_after(0);
        // A second past the write, which the runtime's clock only reaches once the
        // blocking task that writes has returned: `settle` alone does not wait for it.
        tokio::time::sleep(LAZY_WRITES_EVERY + Duration::from_secs(1)).await;
        assert_eq!(
            harness.disk.files().writes[before..],
            [JournalFile::Started]
        );
        harness.disk.works_again();
        // A second past the write, which the runtime's clock only reaches once the
        // blocking task that writes has returned: `settle` alone does not wait for it.
        tokio::time::sleep(LAZY_WRITES_EVERY + Duration::from_secs(1)).await;
        assert_eq!(
            harness.disk.files().writes[before..],
            [
                JournalFile::Started,
                JournalFile::Started,
                JournalFile::Ended
            ]
        );
    }

    /// A disk that refuses every start costs the log no more than refusals do.
    #[tokio::test(start_paused = true)]
    async fn starts_that_cannot_be_written_are_logged_within_the_budget() {
        let log = crate::testkit::LogCapture::start();
        let mut harness = Harness::new("min_manifest_interval_secs = 60");
        let actions = harness.start().await;
        harness.disk.fail_after(0);
        for n in 1..=100 {
            assert_eq!(
                outcome(&actions, request(n, RESTART)).await,
                refused(RejectReason::JournalUnavailable)
            );
        }
        let text = log.text();
        let lines = text.matches("the start could not be written").count()
            + text.matches("action refused").count();
        assert_eq!(lines, 20, "{text}");
    }

    /// A text that could not be serialized is empty, and never replaces a journal.
    #[tokio::test(start_paused = true)]
    async fn an_empty_text_is_never_written() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;
        assert!(!actions.shared.write_now(JournalFile::Started, ""));
        assert!(actions.shared.write_now(JournalFile::Started, "{}"));
        assert_eq!(harness.disk.files().writes, [JournalFile::Started]);
    }

    /// A start that cannot be written runs nothing.
    #[tokio::test(start_paused = true)]
    async fn nothing_runs_without_its_start_on_disk() {
        let mut harness = Harness::new("");
        let actions = harness.start().await;
        harness.disk.fail_after(0);
        assert_eq!(
            outcome(&actions, request(1, RESTART)).await,
            refused(RejectReason::JournalUnavailable)
        );
        assert_eq!(harness.machine.steps(), 0);
        // Nothing was recorded: once the disk works, the same request is decided again.
        harness.disk.works_again();
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
    }

    /// Another agent holds the journal: after about ten seconds of trying, everything is
    /// refused, and this one leaves the mark alone.
    #[tokio::test(start_paused = true)]
    async fn a_journal_another_process_holds_refuses_everything() {
        let mut harness = Harness::new("");
        harness.disk.files().locked = true;
        let began = tokio::time::Instant::now();
        let actions = harness.start().await;
        assert_eq!(began.elapsed(), Duration::from_secs(9));
        assert_eq!(
            outcome(&actions, request(1, RESTART)).await,
            refused(RejectReason::JournalUnavailable)
        );
        assert_eq!(harness.machine.calls(), Vec::<String>::new());
        harness.stop().await;
        assert_eq!(*harness.mark.0.lock().unwrap(), None);
    }

    /// The twin: an agent that is still stopping lets go in time.
    #[tokio::test(start_paused = true)]
    async fn a_journal_let_go_of_in_time_is_taken() {
        let mut harness = Harness::new("");
        harness.disk.files().locked = true;
        let disk = harness.disk.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2_500)).await;
            disk.files().locked = false;
        });
        let began = tokio::time::Instant::now();
        let actions = harness.start().await;
        assert_eq!(began.elapsed(), Duration::from_secs(3));
        assert_eq!(outcome(&actions, request(1, RESTART)).await, succeeded());
    }

    /// A mark that cannot be read refuses everything, like a clock set back. And the
    /// journal holds the mark when its file is gone.
    #[tokio::test(start_paused = true)]
    async fn a_mark_that_cannot_be_read_refuses_everything() {
        let mut harness = Harness::new("");
        harness.mark.set(Some("not a mark".to_owned()));
        let actions = harness.start().await;
        assert_eq!(
            outcome(&actions, request(1, RESTART)).await,
            refused(RejectReason::ClockWentBack)
        );

        let mut harness = Harness::new("");
        let actions = harness.start().await;
        harness.clock.advance(Duration::from_secs(3 * HOUR));
        assert_eq!(
            outcome(&actions, request_with(1, signed(RESTART), NOW + 4 * HOUR)).await,
            succeeded()
        );
        harness.stop().await;
        harness.mark.set(None);
        harness.clock.set_wall(NOW);
        let actions = harness.start().await;
        assert_eq!(
            outcome(&actions, request(2, RESTART)).await,
            refused(RejectReason::ClockWentBack)
        );
    }

    // ----- Logs ------------------------------------------------------------------------

    /// What the executor logs: codes, ids and indexes. Never a service, a path, or text the
    /// server chose.
    #[tokio::test(start_paused = true)]
    async fn the_log_holds_no_name_no_path_and_no_text_of_the_request() {
        let log = crate::testkit::LogCapture::start();

        let mut harness = Harness::new("");
        let actions = harness.start().await;
        outcome(&actions, request(1, CLEAR_LOCK)).await;
        harness
            .machine
            .state()
            .steps
            .push_back(Err(StepError::Failed));
        outcome(&actions, request(2, RESTART)).await;
        harness.machine.state().checks.push_back(Ok(false));
        outcome(&actions, request(3, DELETE_ONLY)).await;
        outcome(
            &actions,
            request(4, &RESTART.replace("FakeErp", "SecretErp")),
        )
        .await;
        let elsewhere = CLEAR_LOCK.replace(r"C:\FakeErp\run", r"C:\FakeErp\Clientes");
        outcome(&actions, request(5, &elsewhere)).await;
        outcome(
            &actions,
            request(6, "id = 'campo.escolhido'\nsenha = 'x'\n"),
        )
        .await;
        harness.machine.state().refused.push("FakeErp");
        outcome(&actions, request(7, RESTART)).await;
        harness.stop().await;

        let log = log.text();
        assert!(log.contains("action started"), "{log}");
        assert!(log.contains("action refused"), "{log}");
        assert!(log.contains("a step failed"), "{log}");
        for secret in [
            "FakeErp",
            "SecretErp",
            "erp.lock",
            "Clientes",
            "senha",
            "campo",
            "operator-7",
        ] {
            assert!(!log.contains(secret), "{secret} in:\n{log}");
        }
    }

    /// Cancelling in a loop costs the server the same budget as refusals.
    #[tokio::test(start_paused = true)]
    async fn cancels_in_a_loop_are_logged_within_the_budget() {
        let log = crate::testkit::LogCapture::start();
        let mut harness = Harness::new("");
        let mut gate = harness.machine.gate();
        let actions = harness.start().await;
        actions.submit(request(1, RESTART));
        gate.step_started().await;
        for n in 2..=1001 {
            actions.submit(request(n, RESTART));
            actions.cancel(id(n));
        }
        harness.machine.open();
        gate.release();
        let lines = log
            .text()
            .matches("action cancelled while it waited")
            .count();
        assert_eq!(lines, 20);
        assert!(
            log.text()
                .contains("further refused or cancelled requests are not logged")
        );
    }

    #[test]
    fn only_the_first_refusals_of_a_window_are_logged() {
        let mut budget = LogBudget {
            window_start: None,
            used: 0,
        };
        let logged = (0..100).filter(|_| budget.take(Duration::ZERO)).count();
        assert_eq!(logged, 20);
        assert!(!budget.take(LOG_WINDOW - Duration::from_secs(1)));
        assert!(budget.take(LOG_WINDOW));
    }

    #[test]
    fn the_limits_are_what_the_documents_say() {
        assert_eq!(MAX_QUEUED, 4);
        assert_eq!(MAX_REQUEST_AHEAD_SECS, 24 * 60 * 60 + 5 * 60);
        assert_eq!(MAX_UNRECORDED, 16);
    }
}
