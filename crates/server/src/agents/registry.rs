//! Which session speaks for each connected device.
//!
//! A device has one session at a time. When it authenticates again, the new session takes
//! over and the old one is told to stop: the old connection is usually already dead and the
//! server has not noticed yet. If it is not dead, two machines hold the same key, and
//! whoever is watching the audit log wants to know.
//!
//! The store also records which session a device is online under. The two agree because
//! the sessions of one device start one at a time: see [`Registry::starting`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use ponte_protocol::DeviceId;
use tokio::sync::{Notify, OwnedMutexGuard};

use super::store::SessionId;

/// How many connections of one device may be starting a session or waiting to. A machine
/// has one agent, so more than a couple is a reconnect storm or somebody with the key
/// opening connections on purpose, and each of them would cost a store call.
const MAX_STARTING: usize = 4;

#[derive(Debug, Default)]
pub(crate) struct Registry {
    sessions: Mutex<HashMap<DeviceId, Entry>>,
    /// One entry per device with a session starting, gone when none is.
    starting: Mutex<HashMap<DeviceId, Starting>>,
}

#[derive(Debug)]
struct Entry {
    session: SessionId,
    replaced: Arc<Notify>,
}

#[derive(Debug)]
struct Starting {
    turn: Arc<tokio::sync::Mutex<()>>,
    /// Connections that hold the turn or wait for it.
    connections: usize,
}

/// A session's place in the [`Registry`]. Dropping it gives the place up, unless another
/// session already took it.
#[derive(Debug)]
pub(crate) struct Registration<'a> {
    registry: &'a Registry,
    device: DeviceId,
    session: SessionId,
    replaced: Arc<Notify>,
}

/// The turn of one connection to start a session for its device. Dropping it passes the
/// turn on.
#[derive(Debug)]
pub(crate) struct Turn<'a> {
    registry: &'a Registry,
    device: DeviceId,
    /// `None` while still waiting.
    held: Option<OwnedMutexGuard<()>>,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Nothing panics while holding these locks, and each map is whole between any two
    // statements that touch it.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Registry {
    /// Waits for the turn of `device` to start a session. Hold it from the moment the
    /// store is told about the new session until [`Registry::register`] returned.
    ///
    /// Without it two connections of one device could reach the store in one order and the
    /// registry in the other. The store would then show the device under the session that
    /// lost, and offline as soon as that one ended, while the winner is still connected.
    ///
    /// A device waits only behind itself: no other device is held up by it. `None` when
    /// too many connections of this device are already starting; the caller drops this one.
    pub(crate) async fn starting(&self, device: DeviceId) -> Option<Turn<'_>> {
        let turn = {
            let mut starting = locked(&self.starting);
            let entry = starting.entry(device).or_insert_with(|| Starting {
                turn: Arc::default(),
                connections: 0,
            });
            if entry.connections >= MAX_STARTING {
                return None;
            }
            entry.connections += 1;
            Arc::clone(&entry.turn)
        };
        // Counted from here on. If this connection goes away while it waits, dropping the
        // `Turn` takes it out of the count again.
        let mut waiting = Turn {
            registry: self,
            device,
            held: None,
        };
        waiting.held = Some(turn.lock_owned().await);
        Some(waiting)
    }

    /// Makes `session` the one that speaks for `device`. Returns its place and the session
    /// that held it until now, which is told to stop.
    pub(crate) fn register(
        &self,
        device: DeviceId,
        session: SessionId,
    ) -> (Registration<'_>, Option<SessionId>) {
        let replaced = Arc::new(Notify::new());
        let entry = Entry {
            session,
            replaced: Arc::clone(&replaced),
        };
        let previous = locked(&self.sessions).insert(device, entry).map(|old| {
            // `notify_one` keeps the notice for a session that is not waiting right now.
            old.replaced.notify_one();
            old.session
        });
        let registration = Registration {
            registry: self,
            device,
            session,
            replaced,
        };
        (registration, previous)
    }

    #[cfg(test)]
    pub(crate) fn current(&self, device: DeviceId) -> Option<SessionId> {
        locked(&self.sessions)
            .get(&device)
            .map(|entry| entry.session)
    }

    /// How many devices have a session starting right now.
    #[cfg(test)]
    pub(crate) fn devices_starting(&self) -> usize {
        locked(&self.starting).len()
    }
}

impl Registration<'_> {
    /// Completes once a newer session of the same device has registered, even if that
    /// happened before this was called.
    pub(crate) async fn replaced(&self) {
        self.replaced.notified().await;
    }
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let mut sessions = locked(&self.registry.sessions);
        // Only its own place: a session that was replaced ends after the new one began.
        if sessions
            .get(&self.device)
            .is_some_and(|entry| entry.session == self.session)
        {
            sessions.remove(&self.device);
        }
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        // The turn first, so whoever is next can take it, then the count.
        self.held = None;
        let mut starting = locked(&self.registry.starting);
        if let Some(entry) = starting.get_mut(&self.device) {
            entry.connections = entry.connections.saturating_sub(1);
            if entry.connections == 0 {
                starting.remove(&self.device);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    async fn is_replaced(registration: &Registration<'_>) -> bool {
        timeout(Duration::from_secs(1), registration.replaced())
            .await
            .is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_holds_its_place_until_it_ends() {
        let registry = Registry::default();
        let device = DeviceId::new();
        let session = SessionId::new();
        assert_eq!(registry.current(device), None);

        let (registration, previous) = registry.register(device, session);
        assert_eq!(previous, None);
        assert_eq!(registry.current(device), Some(session));
        assert!(!is_replaced(&registration).await);

        drop(registration);
        assert_eq!(registry.current(device), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_session_of_the_same_device_takes_the_place_of_the_old_one() {
        let registry = Registry::default();
        let device = DeviceId::new();
        let (old, new) = (SessionId::new(), SessionId::new());

        let (old_registration, _) = registry.register(device, old);
        let (new_registration, previous) = registry.register(device, new);
        assert_eq!(previous, Some(old));
        assert_eq!(registry.current(device), Some(new));

        // The old session is told, although it was not listening when it happened.
        assert!(is_replaced(&old_registration).await);
        assert!(!is_replaced(&new_registration).await);

        // On its way out it must not take the new session's place with it.
        drop(old_registration);
        assert_eq!(registry.current(device), Some(new));
        drop(new_registration);
        assert_eq!(registry.current(device), None);
    }

    #[tokio::test(start_paused = true)]
    async fn devices_do_not_replace_each_other() {
        let registry = Registry::default();
        let (one, other) = (DeviceId::new(), DeviceId::new());

        let (first, _) = registry.register(one, SessionId::new());
        let (second, previous) = registry.register(other, SessionId::new());
        assert_eq!(previous, None);
        assert!(!is_replaced(&first).await);
        assert!(!is_replaced(&second).await);

        drop(first);
        assert!(registry.current(one).is_none());
        assert!(registry.current(other).is_some());
    }
    /// The turn is what keeps the store and the registry in the same order.
    #[tokio::test(start_paused = true)]
    async fn the_sessions_of_one_device_start_one_at_a_time() {
        let registry = Registry::default();
        let device = DeviceId::new();

        let turn = registry.starting(device).await.unwrap();
        let waits = timeout(Duration::from_secs(1), registry.starting(device)).await;
        assert!(
            waits.is_err(),
            "a second session started alongside the first"
        );

        drop(turn);
        let next = timeout(Duration::from_secs(1), registry.starting(device)).await;
        assert!(next.is_ok_and(|turn| turn.is_some()), "the turn was lost");
    }

    /// A device that opens many connections, or whose store call is slow, holds up nobody
    /// but itself.
    #[tokio::test(start_paused = true)]
    async fn a_device_waits_only_behind_itself() {
        let registry = Registry::default();
        let busy = DeviceId::new();
        let _held = registry.starting(busy).await.unwrap();

        for _ in 0..1_000 {
            let other = timeout(Duration::ZERO, registry.starting(DeviceId::new())).await;
            assert!(
                other.is_ok_and(|turn| turn.is_some()),
                "a device waited for another"
            );
        }
        // And nothing is kept about the devices that are done.
        assert_eq!(registry.devices_starting(), 1);
    }

    /// One agent per machine. Past a few connections starting at once, the rest are
    /// turned away instead of each queueing a store call.
    #[tokio::test(start_paused = true)]
    async fn a_device_gets_a_few_connections_starting_at_once_and_no_more() {
        let registry = Arc::new(Registry::default());
        let device = DeviceId::new();
        let held = registry.starting(device).await.unwrap();

        // These wait for the turn, and count while they do.
        let mut waiting = Vec::new();
        for _ in 1..MAX_STARTING {
            let registry = Arc::clone(&registry);
            waiting.push(tokio::spawn(async move {
                let turn = registry.starting(device).await;
                assert!(turn.is_some());
                // Long enough for the test to look, then the turn goes to the next.
                tokio::time::sleep(Duration::from_secs(1)).await;
            }));
        }
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }

        // Turned away at once: it neither gets the turn nor waits for it.
        let one_more = timeout(Duration::ZERO, registry.starting(device)).await;
        assert!(one_more.is_ok_and(|turn| turn.is_none()), "one too many");
        assert!(registry.starting(DeviceId::new()).await.is_some());

        // A connection that goes away while it waits gives its place back.
        waiting.pop().unwrap().abort();
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        let late = tokio::spawn({
            let registry = Arc::clone(&registry);
            async move { registry.starting(device).await.is_some() }
        });

        drop(held);
        for task in waiting {
            task.await.unwrap();
        }
        assert!(late.await.unwrap());
        assert_eq!(registry.devices_starting(), 0);
    }
}
