//! Ponte agent.
//!
//! Runs on the supported machine (a point-of-sale PC, for example) as a privileged
//! Windows service. It only ever opens *outbound* connections, reports telemetry,
//! and runs actions from the signed catalog after checking its own local policy.
//!
//! Current state (M2, in progress): the agent connects to the server, enrolls with a
//! token, proves its device key on every connection, sends a heartbeat with real telemetry
//! every minute and connects again by itself when the connection is lost. It decides on
//! action requests (signature, validity, local policy, limits, journal) and runs them
//! through the platform layer, which on every platform still refuses everything: Windows
//! comes in step 5 of M2.
//!
//! | Module | What it does |
//! |---|---|
//! | `config` | The configuration file, and the server URL as a type |
//! | `actions` | Action requests: the clock's mark, the journal, the executor |
//! | `identity` | The device key, the id the server gave it, the enrollment token |
//! | `transport` | TCP, TLS and the WebSocket upgrade with its protocol version |
//! | `handshake` | Answers the server's challenge. No socket |
//! | `session` | Heartbeats, what the server asks, and whether it is still there. No socket |
//! | `telemetry` | Reads the machine |
//! | `backoff` | How long to wait before connecting again |
//! | `platform` | What depends on the operating system |
//!
//! Read `AGENTS.md` in this crate before changing what the agent signs, stores or logs.

mod actions;
mod backoff;
mod config;
mod handshake;
mod identity;
mod platform;
mod session;
mod telemetry;
mod transport;
mod wire;

#[cfg(test)]
mod testkit;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::{SplitSink, SplitStream};
use ponte_protocol::Label;
use tokio::sync::watch;
use tokio::task::spawn_blocking;
use tokio::time::{Instant, sleep, timeout};
use tracing::{debug, error, info, warn};

pub use config::{AgentConfig, ConfigError, InvalidServerUrl, ServerUrl};
pub use platform::NAME as PLATFORM;

use actions::ActionFiles;
use actions::clock::SystemClock;
use actions::runner::{self as executor, Actions};
use config::Security;
use handshake::{About, Accepted};
use identity::{DataDir, IdentityStore};
use platform::keystore;
use session::SessionEnd;
use telemetry::Collector;
use tokio::task::JoinHandle;
use transport::{Socket, Tls};
use wire::Message;

/// How long the agent waits for each thing, and how often it does what it repeats.
///
/// The values of [`Timing::default`] are the agent's. This is public so that tests can run
/// an agent that does in milliseconds what a real one does in minutes.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// From the first packet to the end of the upgrade. Generous: checking the
    /// certificate can make the operating system fetch what it is missing (ADR-0009).
    pub connect: Duration,
    /// For the server's challenge, which it sends at once.
    pub challenge: Duration,
    /// For the server's verdict on the answer. Its store has no deadline of its own.
    pub verdict: Duration,
    /// For one frame to go out.
    pub send: Duration,
    /// For the server to acknowledge a close.
    pub close: Duration,
    /// Between heartbeats.
    pub heartbeat: Duration,
    /// The least time between two readings of the machine, whoever asks.
    pub min_collect_gap: Duration,
    /// Between pings.
    pub ping: Duration,
    /// With no frame from the server for this long, the connection is given up.
    pub silence: Duration,
    /// A session that lasted this long counts as a working connection: the next wait
    /// starts from the beginning again.
    pub stable_session: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(30),
            challenge: Duration::from_secs(10),
            verdict: Duration::from_secs(30),
            send: Duration::from_secs(10),
            close: Duration::from_secs(2),
            heartbeat: Duration::from_secs(60),
            min_collect_gap: Duration::from_secs(5),
            ping: Duration::from_secs(30),
            silence: Duration::from_secs(90),
            stable_session: Duration::from_secs(60),
        }
    }
}

/// The runtime the agent runs on: two worker threads, whatever the machine has.
///
/// Checking a server certificate can hold the thread it runs on for as long as the system's
/// verifier takes (see `transport::connect`). With a single worker, which is what a
/// one-core machine would get by default, that would stop every timer with it: the
/// connection deadline, the stop signal, the shutdown. The second worker keeps them going.
/// More than two is of no use to one connection.
///
/// # Errors
/// The operating system refused the threads.
pub fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}

/// Runs the agent until `shutdown` completes: connects, enrolls if it has to, keeps a
/// session going and connects again whenever it ends.
///
/// Nothing that the server, the network or the disk does ends it. It only returns once
/// `shutdown` has completed.
pub async fn run(config: AgentConfig, shutdown: impl Future<Output = ()>) {
    let timing = Timing {
        heartbeat: Duration::from_secs(config.heartbeat_secs),
        ..Timing::default()
    };
    run_with(config, timing, shutdown).await;
}

/// [`run`] with the waits of the caller's choosing, `heartbeat` included.
#[doc(hidden)]
pub async fn run_with(config: AgentConfig, timing: Timing, shutdown: impl Future<Output = ()>) {
    let actions = &config.actions;
    // Numbers and a ceiling only: the names of services and roots stay out of the log.
    info!(
        actions = if actions.keys.is_some() { "enabled" } else { "disabled" },
        max_risk = ?actions.policy.max_risk,
        max_actions_per_hour = actions.max_per_hour,
        min_manifest_interval_secs = actions.min_interval_secs,
        shutdown_timeout_secs = actions.shutdown_timeout.as_secs(),
        "action policy"
    );
    if actions.keys.is_none() {
        warn!("the configuration names no manifest_keys: this agent runs no action (ADR-0010)");
    }
    let files = Arc::new(ActionFiles::new(&config.data_dir));
    let runner = executor::start(
        config.actions.clone(),
        Arc::clone(&files) as _,
        files,
        Arc::new(SystemClock::new()),
        platform::machine(&config.actions.policy.roots),
    )
    .await;
    let (stop, stopped) = watch::channel(false);
    let agent = Agent::new(&config, timing, runner.actions());
    let work = agent.run(stopped);
    tokio::pin!(work);
    tokio::select! {
        () = &mut work => {}
        () = shutdown => {
            let _ = stop.send(true);
            // Everything `work` waits on also watches the signal, so this is a matter of
            // closing the connection politely.
            work.await;
        }
    }
    // The running action, if any, gets `shutdown_timeout_secs` to end (ADR-0013).
    runner.stop(config.actions.shutdown_timeout).await;
}

/// Completes once the agent was told to stop. Also when the sender is gone, which only
/// happens when the agent is being torn down.
async fn stop_signal(stopped: &mut watch::Receiver<bool>) {
    let _ = stopped.wait_for(|stop| *stop).await;
}

/// How one attempt to be connected ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// It never got to a session: nothing to connect with, the connection failed, or the
    /// server did not accept the device.
    Failed,
    /// The server enrolled the device and closed. The next attempt is the device's first
    /// real connection.
    Enrolled,
    /// There was a session and it ended.
    Session {
        lasted: Duration,
    },
    Stopped,
}

/// How many failures in a row count after `outcome`, having counted `failures` before.
///
/// Only a session that lasted starts the count again. One that the server ends right after
/// its `Welcome` is a failure like any other: counting it as a success would have the
/// agent back within a second every time, signing a challenge on each visit, for as long
/// as the server cared to repeat it.
fn failures_after(failures: u32, outcome: Outcome, stable_session: Duration) -> u32 {
    match outcome {
        Outcome::Session { lasted } if lasted >= stable_session => 0,
        Outcome::Enrolled | Outcome::Stopped => failures,
        Outcome::Failed | Outcome::Session { .. } => failures.saturating_add(1),
    }
}

/// A task that is cancelled when its handle goes, instead of being left to run.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

type Sink = SplitSink<Socket, Message>;
type Stream = SplitStream<Socket>;

struct Agent {
    url: ServerUrl,
    identity: Arc<IdentityStore<DataDir>>,
    collector: Collector,
    actions: Actions,
    about: About,
    timing: Timing,
}

impl Agent {
    fn new(config: &AgentConfig, timing: Timing, actions: Actions) -> Self {
        let disk = DataDir::new(&config.data_dir, config.enrollment_token_file.as_deref());
        Self {
            url: config.server_url.clone(),
            identity: Arc::new(IdentityStore::new(disk)),
            collector: Collector::new(),
            actions,
            about: About {
                agent_version: Label::from_lossy(env!("CARGO_PKG_VERSION")),
                os: telemetry::os_label(),
            },
            timing,
        }
    }

    async fn run(&self, mut stopped: watch::Receiver<bool>) {
        if !keystore::PROTECTED {
            warn!(
                "the device key is stored without encryption, and the key and the token keep \
                 the permissions of their folder: any local user who can read it can copy \
                 them. This build is for development only (ADR-0008)"
            );
        }
        if self.url.security() == Security::PlainLoopback {
            warn!(
                "server_url is plain ws:// to this machine: the token and the handshake are not \
                 encrypted, and any local process that takes the port first receives them. For \
                 development only"
            );
        }
        self.collector.warm_up();
        let mut tls = Tls::default();
        let mut failures = 0;
        loop {
            let outcome = self.connection(&mut tls, &mut stopped).await;
            failures = failures_after(failures, outcome, self.timing.stable_session);
            match outcome {
                Outcome::Stopped => return,
                // Straight back in, this time as the device it now is.
                Outcome::Enrolled => continue,
                Outcome::Failed | Outcome::Session { .. } => {}
            }
            let wait = backoff::delay(failures, backoff::random());
            debug!(
                wait_ms = wait.as_millis(),
                failures, "waiting before connecting again"
            );
            tokio::select! {
                () = sleep(wait) => {}
                () = stop_signal(&mut stopped) => return,
            }
        }
    }

    /// One connection, from reading the identity to the end of the session.
    async fn connection(&self, tls: &mut Tls, stopped: &mut watch::Receiver<bool>) -> Outcome {
        let greeted = tokio::select! {
            greeted = self.greet(tls) => greeted,
            () = stop_signal(stopped) => return Outcome::Stopped,
        };
        let (mut sink, mut stream) = match greeted {
            Ok(halves) => halves,
            Err(outcome) => return outcome,
        };

        info!(server = %self.url, "connected: the server accepted this device");
        let started = Instant::now();
        let end = session::run(
            &mut stream,
            &mut sink,
            &self.collector,
            &self.actions,
            &self.timing,
            stopped,
        )
        .await;
        wire::close(&mut stream, &mut sink, self.timing.close).await;
        let lasted = started.elapsed();
        info!(?end, lasted_secs = lasted.as_secs(), "session ended");

        match end {
            SessionEnd::Stopped => Outcome::Stopped,
            _ => Outcome::Session { lasted },
        }
    }

    /// Everything before a session: the identity, the connection, the handshake. `Err` is
    /// how the attempt ended when it did not end in one.
    async fn greet(&self, tls: &mut Tls) -> Result<(Sink, Stream), Outcome> {
        // The key and the token are read before there is a connection, so the answer to
        // the server's challenge does not wait for a disk.
        let identity = Arc::clone(&self.identity);
        let credentials = match spawn_blocking(move || identity.credentials()).await {
            Ok(Ok(Some(credentials))) => credentials,
            Ok(Ok(None)) => {
                warn!(
                    "this machine has no device identity and no enrollment token to get one: \
                     there is nothing to connect with. The token file is looked for again later"
                );
                return Err(Outcome::Failed);
            }
            Ok(Err(error)) => {
                error!(%error, "the device identity could not be read");
                return Err(Outcome::Failed);
            }
            // Only in a build that unwinds: a release build ends the process on a panic.
            Err(_) => {
                error!("reading the device identity failed");
                return Err(Outcome::Failed);
            }
        };
        let enrolling = credentials.enrollment().is_some();

        let tls = match self.url.security() {
            Security::Tls => match tls.config() {
                Ok(config) => Some(config),
                Err(error) => {
                    warn!(server = %self.url, %error, "connection failed");
                    return Err(Outcome::Failed);
                }
            },
            Security::PlainLoopback => None,
        };
        // A task of its own, because checking a certificate can block the thread it runs on
        // (see `transport::connect`). The deadline and the stop signal apply to it all the
        // same, and dropping the guard cancels what is left of the attempt.
        let mut attempt = AbortOnDrop(tokio::spawn(transport::connect(self.url.clone(), tls)));
        let connected = timeout(self.timing.connect, &mut attempt.0).await;
        let (version, socket) = match connected {
            Ok(Ok(Ok(connection))) => connection,
            Ok(Ok(Err(error))) => {
                warn!(server = %self.url, %error, "connection failed");
                return Err(Outcome::Failed);
            }
            // Only in a build that unwinds: a release build ends the process on a panic.
            Ok(Err(_)) => {
                error!(server = %self.url, "connecting failed");
                return Err(Outcome::Failed);
            }
            Err(_) => {
                warn!(server = %self.url, "connection failed: it took too long");
                return Err(Outcome::Failed);
            }
        };
        debug!(version = version.number(), "upgrade done");
        let (mut sink, mut stream) = socket.split();

        let accepted = handshake::run(
            &mut stream,
            &mut sink,
            version,
            credentials,
            &self.about,
            &self.timing,
        )
        .await;
        match accepted {
            Ok(Accepted::Welcome) => Ok((sink, stream)),
            Ok(Accepted::Enrolled {
                device_id,
                enrollment,
            }) => {
                // On disk first. If this fails, the next attempt is the same enrollment
                // again and the server answers with the same id.
                let identity = Arc::clone(&self.identity);
                let stored =
                    spawn_blocking(move || identity.enrolled(&enrollment, device_id)).await;
                wire::close(&mut stream, &mut sink, self.timing.close).await;
                match stored {
                    Ok(Ok(())) => {
                        info!(device = %device_id, "enrolled: the server gave this device its id");
                        Err(Outcome::Enrolled)
                    }
                    Ok(Err(error)) => {
                        error!(%error, "enrolled, and the device id could not be stored");
                        Err(Outcome::Failed)
                    }
                    // Only in a build that unwinds, like the one above.
                    Err(_) => {
                        error!("enrolled, and storing the device id failed");
                        Err(Outcome::Failed)
                    }
                }
            }
            Err(reason) if enrolling => {
                warn!(
                    %reason,
                    "enrollment was not accepted. The server never says why: the token may be \
                     mistyped, expired, used up or revoked. A new token file starts a new \
                     enrollment"
                );
                Err(Outcome::Failed)
            }
            Err(reason) => {
                warn!(
                    %reason,
                    "the server did not accept this device. It never says why: the device may \
                     have been revoked, or the server may not know it"
                );
                Err(Outcome::Failed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STABLE: Duration = Duration::from_secs(60);

    fn session(secs: u64) -> Outcome {
        Outcome::Session {
            lasted: Duration::from_secs(secs),
        }
    }

    #[test]
    fn failures_in_a_row_are_counted_until_a_session_lasts() {
        assert_eq!(failures_after(0, Outcome::Failed, STABLE), 1);
        assert_eq!(failures_after(7, Outcome::Failed, STABLE), 8);
        assert_eq!(failures_after(7, session(60), STABLE), 0);
        assert_eq!(failures_after(7, session(86_400), STABLE), 0);
        assert_eq!(failures_after(u32::MAX, Outcome::Failed, STABLE), u32::MAX);
    }

    /// A server that welcomes the device and closes at once gets the agent back, and one
    /// more signature, every time. That must cost it a longer wait each time, not none.
    #[test]
    fn a_session_that_did_not_last_is_a_failure() {
        assert_eq!(failures_after(0, session(0), STABLE), 1);
        assert_eq!(failures_after(3, session(59), STABLE), 4);
    }

    #[test]
    fn enrolling_neither_adds_a_failure_nor_forgives_the_earlier_ones() {
        assert_eq!(failures_after(0, Outcome::Enrolled, STABLE), 0);
        assert_eq!(failures_after(5, Outcome::Enrolled, STABLE), 5);
    }

    /// A task that holds its thread, as a certificate check can, must not stop the clock
    /// for the rest of the agent. Two workers see to that, on any machine.
    #[test]
    fn a_task_that_blocks_its_thread_does_not_stop_the_deadlines() {
        let runtime = runtime().unwrap();
        runtime.block_on(async {
            let start = std::time::Instant::now();
            let blocked = tokio::spawn(async {
                std::thread::sleep(Duration::from_secs(2));
            });
            assert!(timeout(Duration::from_millis(200), blocked).await.is_err());
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "{:?}",
                start.elapsed()
            );
        });
    }

    #[test]
    fn the_default_timing_is_what_the_documents_say() {
        let timing = Timing::default();
        assert_eq!(timing.connect, Duration::from_secs(30));
        // Under the server's own ten seconds for the answer to its challenge.
        assert_eq!(timing.challenge, Duration::from_secs(10));
        assert_eq!(timing.heartbeat, Duration::from_secs(60));
        assert_eq!(timing.ping, Duration::from_secs(30));
        assert_eq!(timing.silence, 3 * timing.ping);
        assert_eq!(timing.stable_session, Duration::from_secs(60));
    }
}
