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
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use ponte_protocol::DeviceId;
use tokio::sync::Notify;

use super::store::SessionId;

/// How many sessions can be starting at the same moment. Two devices that share a lock
/// only wait for each other for the length of one store call.
const START_LOCKS: usize = 64;

#[derive(Debug)]
pub(crate) struct Registry {
    sessions: Mutex<HashMap<DeviceId, Entry>>,
    starting: Box<[tokio::sync::Mutex<()>]>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            sessions: Mutex::default(),
            starting: (0..START_LOCKS)
                .map(|_| tokio::sync::Mutex::default())
                .collect(),
        }
    }
}

#[derive(Debug)]
struct Entry {
    session: SessionId,
    replaced: Arc<Notify>,
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

impl Registry {
    fn lock(&self) -> MutexGuard<'_, HashMap<DeviceId, Entry>> {
        // Nothing panics while holding the lock, and the map is whole between any two
        // statements that touch it.
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits for the turn of `device` to start a session. Hold the guard from the moment
    /// the store is told about the new session until [`Registry::register`] returned.
    ///
    /// Without it two connections of one device could reach the store in one order and the
    /// registry in the other. The store would then show the device under the session that
    /// lost, and offline as soon as that one ended, while the winner is still connected.
    pub(crate) async fn starting(&self, device: DeviceId) -> tokio::sync::MutexGuard<'_, ()> {
        let mut hasher = DefaultHasher::new();
        device.hash(&mut hasher);
        let locks = self.starting.len() as u64;
        // The remainder is below `START_LOCKS`, so it always fits.
        let index = usize::try_from(hasher.finish() % locks).unwrap_or(0);
        self.starting[index].lock().await
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
        let previous = self.lock().insert(device, entry).map(|old| {
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
        self.lock().get(&device).map(|entry| entry.session)
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
        let mut sessions = self.registry.lock();
        // Only its own place: a session that was replaced ends after the new one began.
        if sessions
            .get(&self.device)
            .is_some_and(|entry| entry.session == self.session)
        {
            sessions.remove(&self.device);
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

        let turn = registry.starting(device).await;
        let waits = timeout(Duration::from_secs(1), registry.starting(device)).await;
        assert!(
            waits.is_err(),
            "a second session started alongside the first"
        );

        drop(turn);
        let next = timeout(Duration::from_secs(1), registry.starting(device)).await;
        assert!(next.is_ok(), "the turn was never passed on");
    }

    /// Enough locks that devices seldom share one, and the same lock every time for the
    /// same device.
    #[tokio::test(start_paused = true)]
    async fn starting_devices_wait_only_for_the_few_that_share_their_lock() {
        let registry = Registry::default();
        let held = registry.starting(DeviceId::new()).await;

        let mut free = 0;
        for _ in 0..200 {
            let other = timeout(Duration::from_secs(1), registry.starting(DeviceId::new()));
            if other.await.is_ok() {
                free += 1;
            }
        }
        assert!(free >= 180, "only {free} of 200 devices could start");
        drop(held);
    }
}
