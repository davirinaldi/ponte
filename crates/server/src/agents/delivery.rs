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

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError, Weak};
use std::time::Duration;

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

/// One sweep: expire, claim, hand over.
pub(crate) async fn sweep_once<D: ActionStore>(gateway: &Gateway<D>) -> Result<(), D::Error> {
    let now = gateway.now();
    for (request, device) in gateway.store.expire(now).await? {
        audit::record(&AuditEvent::ActionExpired { request, device });
    }

    let online = gateway.registry.online();
    if online.is_empty() {
        return Ok(());
    }
    for Outgoing {
        device,
        id,
        version,
        request,
    } in gateway.store.claim_due(&online, now).await?
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
pub(crate) struct DeviceLogs(Mutex<HashMap<DeviceId, Window>>);

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
        let mut windows = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() > Self::PRUNE_ABOVE {
            windows.retain(|_, window| now.duration_since(window.started) < Self::WINDOW);
        }
        let window = windows.entry(device).or_insert(Window {
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
