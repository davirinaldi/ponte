//! Getting requests to agents, and keeping their answers from flooding the log (ADR-0012).
//!
//! Every [`SWEEP_EVERY`] the server expires the queued requests that waited too long and
//! claims, in one atomic step, what is due for the devices that have a session in this
//! process (`ActionStore::claim_due`). Each claimed request is handed to its session, which
//! writes it to the connection; one that cannot be handed over never reached the wire and
//! goes back to the queue. A session that starts sends again, first, what its device was
//! sent and never answered (`session.rs`).
//!
//! Nothing here can make a request run: the agent verifies the signature, the validity and
//! its own policy (ADR-0003). What is guarded here is the server's own state, and its log.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError, Weak};
use std::time::Duration;

use chrono::{DateTime, Utc};

use ponte_protocol::DeviceId;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{debug, error, warn};

use super::Gateway;
use super::audit::{self, AuditEvent};
use super::store::actions::{ActionStore, Outgoing};

/// How often the queue is swept. A request reaches an online agent well inside the second
/// of RNF-13.
pub(crate) const SWEEP_EVERY: Duration = Duration::from_millis(500);

/// While the store keeps failing, one line every this many sweeps: one a minute.
const FAILURES_LOGGED_EVERY: u32 = 120;

/// How long the requests of a claim that failed are put back, sweep after sweep, counted
/// from when it failed by a monotonic clock. A claim given up at `CALL_LIMIT` may still be
/// committing in the database, and an `unclaim` that runs before that commit finds
/// nothing: only a later one puts its requests back. The database stops the statement
/// within 5 s of receiving it, but not its commit, which a database in trouble can delay;
/// a minute covers what such a database still answers, and past it the requests wait for
/// their device's next session, as before.
const UNCLAIM_FOR: Duration = Duration::from_secs(60);

/// The most claims that failed kept for [`UNCLAIM_FOR`]: two minutes of sweeps whose claim
/// takes the whole `CALL_LIMIT`.
const MAX_FAILED_CLAIMS: usize = 16;

/// The claims that failed recently, oldest first: the instant each claimed at, which its
/// rows carry, and until when (by a monotonic clock, which no clock step moves) they are
/// put back.
#[derive(Debug, Default)]
pub(crate) struct FailedClaims(Mutex<VecDeque<(DateTime<Utc>, Instant)>>);

impl FailedClaims {
    fn add(&self, claimed_at: DateTime<Utc>) {
        let mut claims = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if claims.len() == MAX_FAILED_CLAIMS {
            claims.pop_front();
        }
        claims.push_back((claimed_at, Instant::now() + UNCLAIM_FOR));
    }

    /// The instants still to put back; the claims whose time is up are forgotten.
    fn due(&self) -> Vec<DateTime<Utc>> {
        let now = Instant::now();
        let mut claims = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        claims.retain(|(_, until)| now < *until);
        claims.iter().map(|(claimed_at, _)| *claimed_at).collect()
    }
}

/// Sweeps until the router that owns `gateway` is gone.
pub(crate) async fn run<D: ActionStore>(gateway: Weak<Gateway<D>>) {
    let mut every = tokio::time::interval(SWEEP_EVERY);
    every.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut failures: u32 = 0;
    loop {
        every.tick().await;
        let Some(gateway) = gateway.upgrade() else {
            return;
        };
        match sweep_once(&gateway).await {
            Ok(()) => {
                if failures > 0 {
                    warn!(failures, "the action queue is swept again");
                }
                failures = 0;
            }
            Err(error) => {
                if failures.is_multiple_of(FAILURES_LOGGED_EVERY) {
                    error!(%error, failures, "the action queue could not be swept; retrying");
                }
                failures = failures.saturating_add(1);
            }
        }
    }
}

/// One sweep: put back what failed claims marked, expire, claim, hand over.
pub(crate) async fn sweep_once<D: ActionStore>(gateway: &Gateway<D>) -> Result<(), D::Error> {
    let now = gateway.now();
    // All in one statement, so a database in trouble gets one more call per sweep.
    match gateway.store.unclaim(&gateway.failed_claims.due()).await {
        Ok(0) => {}
        Ok(count) => warn!(count, "requests of a claim that failed were queued again"),
        // At `debug`: while the database fails, the sweep's own error says so.
        Err(error) => {
            debug!(%error, "the requests of a claim that failed are not queued again yet");
        }
    }
    for (request, device) in gateway.store.expire(now).await? {
        audit::record(&AuditEvent::ActionExpired { request, device });
    }

    let online = gateway.registry.online();
    if online.is_empty() {
        return Ok(());
    }
    let claimed = match gateway.store.claim_due(&online, now).await {
        Ok(claimed) => claimed,
        Err(error) => {
            // The claim may have committed, or may commit yet, and lost its answer: what it
            // marked would stay `sent`, delivered to nobody, until each device's next
            // session. It is put back now, and again by the next sweeps.
            gateway.failed_claims.add(now);
            if let Err(again) = gateway.store.unclaim(&[now]).await {
                debug!(error = %again, "the requests of a claim that failed are not queued again yet");
            }
            return Err(error);
        }
    };
    for Outgoing {
        device,
        id,
        version,
        request,
    } in claimed
    {
        let request_id = request.request_id;
        match gateway.registry.deliver(device, request) {
            Ok(()) => audit::record(&AuditEvent::ActionSent {
                request: request_id,
                device,
                manifest: id,
                version,
                resent: false,
            }),
            Err(_) => {
                // The session ended, or is not taking requests, since the registry was
                // read. Nothing was written to a connection, so the request waits again.
                debug!(device = %device, request = %request_id, "request not handed to a session; queued again");
                match gateway.store.release(request_id).await {
                    Ok(_) => {}
                    Err(error) => {
                        // It stays `sent`: the device's next session sends it again.
                        warn!(device = %device, request = %request_id, %error, "a request that was not sent could not be queued again");
                    }
                }
            }
        }
    }
    Ok(())
}

/// What one device may put in the log about action results it sent: dropped results and
/// anomalies, [`DeviceLogs::LINES`] every [`DeviceLogs::WINDOW`]. Counted per device and not
/// per session, so reconnecting does not refill it, and per device and not for the whole
/// server, so a noisy device does not silence what another one does.
#[derive(Debug, Default)]
pub(crate) struct DeviceLogs(Mutex<Windows>);

#[derive(Debug, Default)]
struct Windows {
    by_device: HashMap<DeviceId, Window>,
    /// When windows that are over were last forgotten.
    pruned: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    started: Instant,
    lines: u32,
    suppressed: u32,
}

impl DeviceLogs {
    pub(crate) const LINES: u32 = 8;
    pub(crate) const WINDOW: Duration = Duration::from_secs(10 * 60);
    /// Past this many devices, windows that are over are forgotten.
    const PRUNE_ABOVE: usize = 10_000;

    /// Whether `device` may log one more line now. When a window that suppressed lines
    /// ends, the first line of the next one says how many.
    pub(crate) fn allow(&self, device: DeviceId) -> bool {
        let now = Instant::now();
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let windows = &mut *guard;
        // At most once a window: past the bound, every call would walk the whole map.
        let due = windows
            .pruned
            .is_none_or(|pruned| now.duration_since(pruned) >= Self::WINDOW);
        if windows.by_device.len() > Self::PRUNE_ABOVE && due {
            windows
                .by_device
                .retain(|_, window| now.duration_since(window.started) < Self::WINDOW);
            windows.pruned = Some(now);
        }
        let window = windows.by_device.entry(device).or_insert(Window {
            started: now,
            lines: 0,
            suppressed: 0,
        });
        if now.duration_since(window.started) >= Self::WINDOW {
            if window.suppressed > 0 {
                warn!(device = %device, suppressed = window.suppressed, "lines about the action results of a device were suppressed");
            }
            *window = Window {
                started: now,
                lines: 0,
                suppressed: 0,
            };
        }
        if window.lines < Self::LINES {
            window.lines += 1;
            true
        } else {
            window.suppressed = window.suppressed.saturating_add(1);
            false
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod failed_claims_tests {
    use super::*;
    use crate::agents::testkit::at;

    /// A failed claim is put back for a minute after it failed, by a clock no step of the
    /// wall clock moves, and no more than the last 16 are kept.
    #[tokio::test(start_paused = true)]
    async fn a_failed_claim_is_put_back_for_a_minute_and_sixteen_at_most() {
        let claims = FailedClaims::default();
        assert!(claims.due().is_empty());
        claims.add(at(0));
        tokio::time::advance(UNCLAIM_FOR - Duration::from_millis(1)).await;
        assert_eq!(claims.due(), [at(0)]);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(claims.due().is_empty());

        for second in 0..20 {
            claims.add(at(second));
        }
        let due = claims.due();
        assert_eq!(due.len(), MAX_FAILED_CLAIMS);
        assert_eq!(due.first(), Some(&at(4)));
        assert_eq!(due.last(), Some(&at(19)));
    }
}
