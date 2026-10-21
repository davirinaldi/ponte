//! The machine of Windows: what the executor asks of the operating system (ADR-0011,
//! ADR-0012).
//!
//! **One at a time, for real.** Every call takes the machine's one slot, waiting for it
//! no longer than the time the manifest has left, and does its work on a thread of its own
//! that holds the slot until the work returns. The executor gets its answer by the
//! deadline whatever Windows does, and a call that overran it (a `StartServiceW` waiting
//! on a slow service, a file held under an oplock) keeps the slot until it truly ends: the
//! next action then times out instead of deleting a lock while the ERP is still starting.
//!
//! **Paths** go through `files`: the final path of every file must lie in a root as the
//! roots resolved at start, the allowed ones for checks and the delete ones for
//! `delete_file`. **Services** go through `services`: refused by their structure, read,
//! started and stopped. A service that was started is read again five seconds later: one
//! that the service manager accepted and that fell over at once has not started.

use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ponte_actions::{Check, ExpectedServiceState, Primitive};
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

use super::files::{self, PathError, Segments};
use super::roots::ResolvedRoots;
use super::services::{self, Refused, State};
use crate::actions::machine::{CheckError, Machine, ServiceRefusal, StepError};

/// How long after a start a service is read again.
const RECHECK: Duration = Duration::from_secs(5);
/// How often a service's state is read while it starts or stops.
const POLL: Duration = Duration::from_millis(250);

/// The machine's one slot.
#[derive(Default)]
pub(crate) struct Slot {
    busy: Mutex<bool>,
    freed: Condvar,
}

/// The slot, taken. Given back when dropped, from whatever thread holds it then.
pub(crate) struct Held(Arc<Slot>);

impl Slot {
    /// Takes the slot, waiting for it until `deadline` at most.
    pub(crate) fn take(self: &Arc<Self>, deadline: Instant) -> Option<Held> {
        let mut busy = self.busy.lock().unwrap_or_else(PoisonError::into_inner);
        while *busy {
            let left = deadline.checked_duration_since(Instant::now())?;
            busy = self
                .freed
                .wait_timeout(busy, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *busy = true;
        Some(Held(Arc::clone(self)))
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        *self.0.busy.lock().unwrap_or_else(PoisonError::into_inner) = false;
        self.0.freed.notify_all();
    }
}

/// Why a bounded call gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unanswered {
    /// The deadline came first. The work goes on, holding the slot, until it returns.
    TimedOut,
    /// No thread could be made for it, or it failed.
    Failed,
}

/// Runs `work` on a thread of its own that holds `held` until `work` returns, and waits
/// for its answer until `deadline`.
pub(crate) fn bounded<T: Send + 'static>(
    held: Held,
    deadline: Instant,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<(T, Held), Unanswered> {
    let (send, receive) = sync_channel(1);
    // The slot goes back when the thread drops it, answered or not.
    std::thread::Builder::new()
        .name("ponte-machine".to_owned())
        .spawn(move || {
            let answer = work();
            let _ = send.send((answer, held));
        })
        .map_err(|_| Unanswered::Failed)?;
    let left = deadline.saturating_duration_since(Instant::now());
    receive.recv_timeout(left).map_err(|error| match error {
        RecvTimeoutError::Timeout => Unanswered::TimedOut,
        RecvTimeoutError::Disconnected => Unanswered::Failed,
    })
}

/// The machine of Windows, with the roots as they resolved at start.
pub(crate) struct WindowsMachine {
    roots: Arc<ResolvedRoots>,
    /// The Windows folder, as named and as resolved: no service's binary may lie in it.
    windows: Arc<Vec<Segments>>,
    slot: Arc<Slot>,
    recheck: Duration,
}

impl WindowsMachine {
    pub(crate) fn new(roots: ResolvedRoots, windows: Vec<Segments>) -> Self {
        Self {
            roots: Arc::new(roots),
            windows: Arc::new(windows),
            slot: Arc::new(Slot::default()),
            recheck: RECHECK,
        }
    }

    /// Runs `work` holding the slot, by `deadline`.
    fn run<T: Send + 'static>(
        &self,
        held: Held,
        deadline: Instant,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<(T, Held), Unanswered> {
        bounded(held, deadline, work)
    }

    fn state(&self, name: &str, held: Held, deadline: Instant) -> Result<(State, Held), StepError> {
        let name = name.to_owned();
        match self.run(held, deadline, move || services::state(&name)) {
            Ok((Ok(state), held)) => Ok((state, held)),
            Ok((Err(_), _)) | Err(Unanswered::Failed) => Err(StepError::Failed),
            Err(Unanswered::TimedOut) => Err(StepError::TimedOut),
        }
    }

    /// Reads the state of `name` until it is `target`, by `deadline`. A service that stops
    /// while it should start has failed.
    fn wait_for(
        &self,
        name: &str,
        target: State,
        mut held: Held,
        deadline: Instant,
    ) -> Result<Held, StepError> {
        loop {
            let (state, again) = self.state(name, held, deadline)?;
            held = again;
            if state == target {
                return Ok(held);
            }
            if target == State::Running && state == State::Stopped {
                return Err(StepError::Failed);
            }
            if Instant::now() + POLL >= deadline {
                return Err(StepError::TimedOut);
            }
            std::thread::sleep(POLL);
        }
    }

    fn start(&self, name: &str, held: Held, deadline: Instant) -> Result<Held, StepError> {
        let owned = name.to_owned();
        let held = match self.run(held, deadline, move || services::start(&owned)) {
            Ok((Ok(()), held)) => held,
            Ok((Err(_), _)) | Err(Unanswered::Failed) => return Err(StepError::Failed),
            Err(Unanswered::TimedOut) => return Err(StepError::TimedOut),
        };
        let held = self.wait_for(name, State::Running, held, deadline)?;
        // Accepted and running; still running a little later is what counts as started.
        if !second_look_fits(Instant::now(), self.recheck, deadline) {
            return Err(StepError::TimedOut);
        }
        std::thread::sleep(self.recheck);
        match self.state(name, held, deadline)? {
            (State::Running, held) => Ok(held),
            _ => Err(StepError::Failed),
        }
    }

    fn stop(&self, name: &str, held: Held, deadline: Instant) -> Result<Held, StepError> {
        let owned = name.to_owned();
        let held = match self.run(held, deadline, move || services::stop(&owned)) {
            Ok((Ok(()), held)) => held,
            Ok((Err(_), _)) | Err(Unanswered::Failed) => return Err(StepError::Failed),
            Err(Unanswered::TimedOut) => return Err(StepError::TimedOut),
        };
        self.wait_for(name, State::Stopped, held, deadline)
    }
}

/// Whether the second look at a started service, `recheck` from `now`, comes before the
/// deadline. If not, the start was not seen to hold: timed out, even if Windows accepted it.
fn second_look_fits(now: Instant, recheck: Duration, deadline: Instant) -> bool {
    now + recheck < deadline
}

/// Whether the drive `mount` (`C:`) has at least `percent` of its space free.
fn disk_free_at_least(mount: &str, percent: u8) -> Option<bool> {
    let bytes = mount.as_bytes();
    if !(bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':') {
        return None;
    }
    let root: Vec<u16> = format!("{mount}\\").encode_utf16().chain(Some(0)).collect();
    let (mut free, mut total) = (0_u64, 0_u64);
    // SAFETY: `root` is NUL-terminated; the outputs live through the call, and the one not
    // asked for is null.
    let read =
        unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut free, &mut total, std::ptr::null_mut()) };
    if read == 0 || total == 0 {
        return None;
    }
    Some(u128::from(free) * 100 >= u128::from(percent) * u128::from(total))
}

impl Machine for WindowsMachine {
    fn service_allowed(&self, name: &str, remaining: Duration) -> Result<(), ServiceRefusal> {
        let deadline = Instant::now() + remaining;
        let held = self.slot.take(deadline).ok_or(ServiceRefusal::TimedOut)?;
        let (name, windows) = (name.to_owned(), Arc::clone(&self.windows));
        match self.run(held, deadline, move || services::structure(&name, &windows)) {
            Ok((Ok(()), _)) => Ok(()),
            Ok((Err(Refused::Unreadable), _)) | Err(Unanswered::Failed) => {
                Err(ServiceRefusal::Unreadable)
            }
            Ok((Err(_), _)) => Err(ServiceRefusal::Structure),
            Err(Unanswered::TimedOut) => Err(ServiceRefusal::TimedOut),
        }
    }

    fn check(&self, check: &Check, remaining: Duration) -> Result<bool, CheckError> {
        let deadline = Instant::now() + remaining;
        let held = self.slot.take(deadline).ok_or(CheckError::TimedOut)?;
        let answered = match check.clone() {
            Check::ServiceState { service, state } => self
                .run(held, deadline, move || services::state(&service))
                .map(|(state_now, _)| {
                    state_now.ok().map(|now| {
                        now == match state {
                            ExpectedServiceState::Running => State::Running,
                            ExpectedServiceState::Stopped => State::Stopped,
                        }
                    })
                }),
            Check::PathExists { path } => {
                let roots = Arc::clone(&self.roots);
                self.run(held, deadline, move || files::probe(&path, &roots.allowed))
                    .map(|(found, _)| found.ok().map(|found| found.is_some()))
            }
            Check::PathAbsent { path } => {
                let roots = Arc::clone(&self.roots);
                self.run(held, deadline, move || files::probe(&path, &roots.allowed))
                    .map(|(found, _)| found.ok().map(|found| found.is_none()))
            }
            Check::DiskFreeAtLeast { mount, percent } => self
                .run(held, deadline, move || disk_free_at_least(&mount, percent))
                .map(|(free, _)| free),
        };
        match answered {
            Ok(Some(holds)) => Ok(holds),
            Ok(None) | Err(Unanswered::Failed) => Err(CheckError::Failed),
            Err(Unanswered::TimedOut) => Err(CheckError::TimedOut),
        }
    }

    fn step(&self, step: &Primitive, remaining: Duration) -> Result<(), StepError> {
        let deadline = Instant::now() + remaining;
        let held = self.slot.take(deadline).ok_or(StepError::TimedOut)?;
        match step {
            Primitive::ServiceStart { service } => self.start(service, held, deadline).map(drop),
            Primitive::ServiceStop { service } => self.stop(service, held, deadline).map(drop),
            Primitive::ServiceRestart { service } => {
                let held = self.stop(service, held, deadline)?;
                self.start(service, held, deadline).map(drop)
            }
            Primitive::DeleteFile { path } => {
                let (path, roots) = (path.clone(), Arc::clone(&self.roots));
                match self.run(held, deadline, move || files::delete(&path, &roots.delete)) {
                    Ok((Ok(()), _)) => Ok(()),
                    Ok((Err(PathError::Refused), _)) => Err(StepError::PathRefused),
                    Ok((Err(PathError::Failed), _)) | Err(Unanswered::Failed) => {
                        Err(StepError::Failed)
                    }
                    Err(Unanswered::TimedOut) => Err(StepError::TimedOut),
                }
            }
            // Refused by `validate_shape` before anything reaches the machine. Listed one by
            // one: a primitive the agent runs must say how.
            Primitive::ReadFileTail { .. }
            | Primitive::ClearTempDir {}
            | Primitive::KillProcess { .. }
            | Primitive::SqlReadonly { .. } => Err(StepError::Failed),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::platform::windows::files::tests::junction;
    use crate::platform::windows::services::windows_folder;
    use crate::testkit::TempDir;

    fn machine_on(roots: ResolvedRoots) -> WindowsMachine {
        WindowsMachine::new(roots, windows_folder().unwrap())
    }

    const SECOND: Duration = Duration::from_secs(1);

    /// A call that overran its deadline keeps the slot until it returns: whatever the next
    /// action asks, it gets "timed out", never a turn beside it.
    #[test]
    fn a_call_that_overran_keeps_the_machine_until_it_returns() {
        let machine = machine_on(ResolvedRoots::default());
        let held = machine.slot.take(Instant::now() + SECOND).unwrap();
        let begun = Instant::now();
        let overran = bounded(held, Instant::now() + Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_millis(600));
        });
        assert_eq!(overran.err(), Some(Unanswered::TimedOut));
        assert!(begun.elapsed() < Duration::from_millis(400));

        let short = Duration::from_millis(100);
        assert_eq!(
            machine.service_allowed("Schedule", short),
            Err(ServiceRefusal::TimedOut)
        );
        let lock = Check::PathAbsent {
            path: r"C:\FakeErp\run\erp.lock".to_owned(),
        };
        assert_eq!(machine.check(&lock, short), Err(CheckError::TimedOut));
        let delete = Primitive::DeleteFile {
            path: r"C:\FakeErp\run\erp.lock".to_owned(),
        };
        assert_eq!(machine.step(&delete, short), Err(StepError::TimedOut));

        // Once it returned, the machine is free again.
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(
            machine.service_allowed("Schedule", SECOND * 10),
            Err(ServiceRefusal::Structure)
        );
    }

    #[test]
    fn a_call_in_time_gives_the_slot_back() {
        let slot = Arc::new(Slot::default());
        let held = slot.take(Instant::now() + SECOND).unwrap();
        let (answer, held) = bounded(held, Instant::now() + SECOND, || 7).unwrap();
        assert_eq!(answer, 7);
        assert!(
            slot.take(Instant::now() + Duration::from_millis(10))
                .is_none()
        );
        drop(held);
        assert!(
            slot.take(Instant::now() + Duration::from_millis(10))
                .is_some()
        );
    }

    #[test]
    fn services_are_refused_and_read_through_the_machine() {
        let machine = machine_on(ResolvedRoots::default());
        let ten = SECOND * 10;
        assert_eq!(
            machine.service_allowed("Schedule", ten),
            Err(ServiceRefusal::Structure)
        );
        assert_eq!(
            machine.service_allowed("ponte-surely-not-a-service", ten),
            Err(ServiceRefusal::Structure)
        );
        let running = Check::ServiceState {
            service: "Schedule".to_owned(),
            state: ExpectedServiceState::Running,
        };
        assert_eq!(machine.check(&running, ten), Ok(true));
        let stopped = Check::ServiceState {
            service: "Schedule".to_owned(),
            state: ExpectedServiceState::Stopped,
        };
        assert_eq!(machine.check(&stopped, ten), Ok(false));
        let missing = Check::ServiceState {
            service: "ponte-surely-not-a-service".to_owned(),
            state: ExpectedServiceState::Stopped,
        };
        assert_eq!(machine.check(&missing, ten), Err(CheckError::Failed));
    }

    #[test]
    fn paths_are_checked_and_deleted_inside_the_resolved_roots_only() {
        let dir = TempDir::new();
        let erp = dir.path().join("FakeErp");
        let run = erp.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let roots = super::super::roots::resolve_roots(
            &[erp.to_str().unwrap().to_owned()],
            &[run.to_str().unwrap().to_owned()],
            &[],
            &windows_folder().unwrap(),
        )
        .unwrap();
        let machine = machine_on(roots);
        let ten = SECOND * 10;
        let lock = run.join("erp.lock").to_str().unwrap().to_owned();
        let db = erp.join("erp.db").to_str().unwrap().to_owned();
        std::fs::write(&lock, b"").unwrap();
        std::fs::write(&db, b"").unwrap();

        let exists = |path: &str| Check::PathExists {
            path: path.to_owned(),
        };
        let absent = |path: &str| Check::PathAbsent {
            path: path.to_owned(),
        };
        assert_eq!(machine.check(&exists(&lock), ten), Ok(true));
        assert_eq!(machine.check(&absent(&lock), ten), Ok(false));
        assert_eq!(machine.check(&exists(&db), ten), Ok(true));
        // Allowed to look at, not to delete.
        let delete = |path: &str| Primitive::DeleteFile {
            path: path.to_owned(),
        };
        assert_eq!(machine.step(&delete(&db), ten), Err(StepError::PathRefused));
        assert_eq!(machine.step(&delete(&lock), ten), Ok(()));
        assert_eq!(machine.check(&absent(&lock), ten), Ok(true));
        assert_eq!(machine.check(&exists(&lock), ten), Ok(false));
        assert_eq!(machine.step(&delete(&lock), ten), Err(StepError::Failed));

        // A junction planted in the delete root, pointing at the rest of the ERP.
        let link = run.join("data");
        junction(&link, &erp);
        let through = link.join("erp.db").to_str().unwrap().to_owned();
        assert_eq!(
            machine.step(&delete(&through), ten),
            Err(StepError::PathRefused)
        );
        assert!(std::path::Path::new(&db).exists());
        // A path somewhere no root reaches.
        let outside = TempDir::new();
        let elsewhere = outside.path().join("x").to_str().unwrap().to_owned();
        std::fs::write(&elsewhere, b"").unwrap();
        assert_eq!(
            machine.check(&exists(&elsewhere), ten),
            Err(CheckError::Failed)
        );
    }

    #[test]
    fn free_space_is_a_share_of_the_drive() {
        let machine = machine_on(ResolvedRoots::default());
        let ten = SECOND * 10;
        let at_least = |percent| Check::DiskFreeAtLeast {
            mount: "C:".to_owned(),
            percent,
        };
        assert_eq!(machine.check(&at_least(0), ten), Ok(true));
        assert_eq!(machine.check(&at_least(100), ten), Ok(false));
        let nowhere = Check::DiskFreeAtLeast {
            mount: "C:\\Windows".to_owned(),
            percent: 0,
        };
        assert_eq!(machine.check(&nowhere, ten), Err(CheckError::Failed));
        assert_eq!(disk_free_at_least("1:", 0), None);
    }

    /// A start that leaves less than the five seconds of the second look has not been seen
    /// to start: timed out, even if the service manager accepted it.
    #[test]
    fn a_start_with_no_time_for_the_second_look_times_out() {
        let now = Instant::now();
        assert_eq!(RECHECK, Duration::from_secs(5));
        assert!(second_look_fits(now, RECHECK, now + Duration::from_secs(6)));
        assert!(!second_look_fits(now, RECHECK, now + RECHECK));
        assert!(!second_look_fits(
            now,
            RECHECK,
            now + Duration::from_secs(4)
        ));
    }
}
