//! The clock the agent decides with, and its high-water mark (ADR-0010).
//!
//! A manifest's validity and a request's expiry are checked against the wall clock, which
//! anyone who can set the time controls: an administrator, or whoever answers an NTP query
//! that is not authenticated. So the agent also keeps the latest time it ever saw, the
//! mark, in its data directory:
//!
//! - When the agent starts, the mark becomes the latest of the stored mark, the clock and
//!   the latest time the journal recorded. The journal holds the mark too, so a mark file
//!   that could not be written, or went missing, does not let a clock set back in.
//! - While it runs, the mark moves only by the time a monotonic counter saw pass. A clock
//!   that jumps ahead and is corrected while the agent runs leaves no mark behind.
//! - It is written every five minutes and when the agent stops, so a clock set back
//!   across a restart finds a mark at most five minutes old, well inside the one hour the
//!   agent tolerates.
//! - A mark that cannot be read refuses every action until an administrator removes it,
//!   and the agent never writes over it. Only a missing file means "no mark yet".

use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ponte_actions::MAX_CLOCK_BACK_SECS;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::spawn_blocking;
use tracing::{error, warn};

/// How often the mark goes to disk while the agent runs (ADR-0010).
pub(crate) const SAVE_EVERY: Duration = Duration::from_secs(5 * 60);

/// The two clocks the agent reads. A trait so that tests can move time either way.
pub(crate) trait Clock: Send + Sync + 'static {
    /// Seconds since the Unix epoch, by the wall clock. A clock before 1970 reads 0.
    fn wall_secs(&self) -> u64;
    /// Time since some fixed moment, which never goes back and is not set by anyone.
    fn monotonic(&self) -> Duration;
}

/// The system's clocks. The monotonic one is the platform's: on Windows
/// `QueryInterruptTime`, which also counts the time the machine slept, so the mark keeps
/// up with a machine that sleeps.
pub(crate) struct SystemClock {
    started: Duration,
}

impl SystemClock {
    pub(crate) fn new() -> Self {
        Self {
            started: crate::platform::monotonic(),
        }
    }
}

impl Clock for SystemClock {
    fn wall_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    }

    fn monotonic(&self) -> Duration {
        crate::platform::monotonic().saturating_sub(self.started)
    }
}

/// The time, as the agent decides with it: the wall clock and the mark, in seconds since
/// the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reading {
    pub(crate) clock: u64,
    pub(crate) mark: u64,
}

impl Reading {
    /// Whether the clock is more than one hour behind the mark: then every action is
    /// refused (ADR-0010).
    pub(crate) fn went_back(&self) -> bool {
        self.clock < self.mark.saturating_sub(MAX_CLOCK_BACK_SECS)
    }
}

/// Where the mark rests. A trait so that tests can fail the disk.
pub(crate) trait MarkDisk: Send + Sync + 'static {
    /// `None` if there is no mark file.
    fn read_mark(&self) -> io::Result<Option<String>>;
    fn write_mark(&self, text: &str) -> io::Result<()>;
}

/// What `clock.toml` holds. Its format is pinned by a test.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    high_water: u64,
}

/// The high-water mark of this run.
pub(crate) struct HighWater {
    clock: Arc<dyn Clock>,
    /// `None` when the stored mark could not be read: every action is refused.
    anchor: Option<Anchor>,
}

/// The mark at one moment of the monotonic clock. Every later reading is counted from it.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    mark: u64,
    monotonic: Duration,
}

impl HighWater {
    /// Reads the stored mark and starts from the latest of it, the clock and `floor`, the
    /// latest time the journal recorded.
    pub(crate) fn start(clock: Arc<dyn Clock>, disk: &dyn MarkDisk, floor: u64) -> Self {
        let stored = match disk.read_mark() {
            Ok(None) => Some(0),
            // Not the error's text: it quotes the file.
            Ok(Some(text)) => toml::from_str::<Stored>(&text)
                .map(|stored| stored.high_water)
                .ok(),
            Err(_) => None,
        };
        if stored.is_none() {
            error!(
                "the clock's high-water mark cannot be read: every action is refused until an \
                 administrator removes the file (ADR-0010)"
            );
        }
        let anchor = stored.map(|stored| Anchor {
            mark: stored.max(clock.wall_secs()).max(floor),
            monotonic: clock.monotonic(),
        });
        Self { clock, anchor }
    }

    /// A mark that could not be read: every action is refused.
    pub(crate) fn unavailable(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            anchor: None,
        }
    }

    /// The clock and the mark now, or `None` if the mark could not be read.
    pub(crate) fn reading(&self) -> Option<Reading> {
        let anchor = self.anchor?;
        let passed = self
            .clock
            .monotonic()
            .saturating_sub(anchor.monotonic)
            .as_secs();
        Some(Reading {
            clock: self.clock.wall_secs(),
            mark: anchor.mark.saturating_add(passed),
        })
    }

    /// Writes the mark as it is now. A mark that could not be read is left as it is.
    pub(crate) fn save(&self, disk: &dyn MarkDisk) -> io::Result<()> {
        let Some(reading) = self.reading() else {
            return Ok(());
        };
        let text = toml::to_string(&Stored {
            high_water: reading.mark,
        })
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        disk.write_mark(&text)
    }
}

/// Writes the mark now, every [`SAVE_EVERY`] after that, and once more when the agent is
/// told to stop. The only writer of the mark file.
pub(crate) async fn keep(
    mark: Arc<HighWater>,
    disk: Arc<dyn MarkDisk>,
    mut stopped: watch::Receiver<bool>,
) {
    loop {
        save(&mark, &disk).await;
        tokio::select! {
            () = tokio::time::sleep(SAVE_EVERY) => {}
            () = crate::stop_signal(&mut stopped) => break,
        }
    }
    save(&mark, &disk).await;
}

async fn save(mark: &Arc<HighWater>, disk: &Arc<dyn MarkDisk>) {
    let (mark, disk) = (Arc::clone(mark), Arc::clone(disk));
    match spawn_blocking(move || mark.save(disk.as_ref())).await {
        Ok(Ok(())) => {}
        // A mark that is not written only weakens the next start; the journal still holds
        // the latest time it recorded.
        Ok(Err(error)) => {
            warn!(kind = ?error.kind(), "the clock's high-water mark could not be written")
        }
        Err(_) => warn!("writing the clock's high-water mark failed"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::testkit::FakeClock;

    const NOW: u64 = 1_792_300_000;
    const HOUR: u64 = 60 * 60;

    #[derive(Default)]
    struct Files {
        mark: Option<String>,
        unreadable: bool,
        failing: bool,
        writes: usize,
    }

    #[derive(Clone, Default)]
    struct FakeDisk(Arc<Mutex<Files>>);

    impl FakeDisk {
        fn with(text: &str) -> Self {
            let disk = Self::default();
            disk.files().mark = Some(text.to_owned());
            disk
        }

        fn files(&self) -> std::sync::MutexGuard<'_, Files> {
            self.0.lock().unwrap()
        }

        fn stored(&self) -> Option<u64> {
            let text = self.files().mark.clone()?;
            Some(toml::from_str::<Stored>(&text).unwrap().high_water)
        }
    }

    impl MarkDisk for FakeDisk {
        fn read_mark(&self) -> io::Result<Option<String>> {
            let files = self.files();
            if files.unreadable {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok(files.mark.clone())
        }

        fn write_mark(&self, text: &str) -> io::Result<()> {
            let mut files = self.files();
            files.writes += 1;
            if files.failing {
                return Err(io::Error::other("the disk is gone"));
            }
            files.mark = Some(text.to_owned());
            Ok(())
        }
    }

    fn start(clock: &FakeClock, disk: &FakeDisk, floor: u64) -> HighWater {
        HighWater::start(Arc::new(clock.clone()), disk, floor)
    }

    #[test]
    fn the_mark_file_format_is_stable() {
        let clock = FakeClock::at(NOW);
        let disk = FakeDisk::default();
        start(&clock, &disk, 0).save(&disk).unwrap();
        assert_eq!(
            disk.files().mark.as_deref(),
            Some("high_water = 1792300000\n")
        );
    }

    #[test]
    fn without_a_file_the_mark_starts_at_the_clock() {
        let clock = FakeClock::at(NOW);
        let mark = start(&clock, &FakeDisk::default(), 0);
        assert_eq!(
            mark.reading(),
            Some(Reading {
                clock: NOW,
                mark: NOW
            })
        );
    }

    /// The latest of the stored mark, the clock and the journal.
    #[test]
    fn the_mark_starts_at_the_latest_time_anything_saw() {
        let clock = FakeClock::at(NOW);
        let later = format!("high_water = {}", NOW + 600);
        assert_eq!(
            start(&clock, &FakeDisk::with(&later), 0)
                .reading()
                .unwrap()
                .mark,
            NOW + 600
        );
        let earlier = format!("high_water = {}", NOW - 600);
        assert_eq!(
            start(&clock, &FakeDisk::with(&earlier), 0)
                .reading()
                .unwrap()
                .mark,
            NOW
        );
        // The mark file was not written for a day, and the journal saw the time since.
        let stale = format!("high_water = {}", NOW - 24 * HOUR);
        clock.set_wall(NOW - 2 * HOUR);
        let reading = start(&clock, &FakeDisk::with(&stale), NOW)
            .reading()
            .unwrap();
        assert_eq!(reading.mark, NOW);
        assert!(reading.went_back());
    }

    /// Only a missing file means "no mark". Anything else that is not a mark refuses every
    /// action, and is left for an administrator to look at.
    #[test]
    fn a_mark_that_cannot_be_read_refuses_everything_and_stays() {
        let clock = FakeClock::at(NOW);
        for text in [
            "",
            "high_water = -1",
            "high_water = \"1792300000\"",
            "high_water = 1792300000\nlow_water = 0",
            "1792300000",
            "high_water = 1.5",
        ] {
            let disk = FakeDisk::with(text);
            let mark = start(&clock, &disk, 0);
            assert_eq!(mark.reading(), None, "{text:?}");
            mark.save(&disk).unwrap();
            assert_eq!(disk.files().writes, 0, "{text:?}");
            assert_eq!(disk.files().mark.as_deref(), Some(text));
        }
        let disk = FakeDisk::default();
        disk.files().unreadable = true;
        assert_eq!(start(&clock, &disk, 0).reading(), None);
    }

    /// The clock may be up to one hour behind the mark, never more.
    #[test]
    fn a_clock_more_than_an_hour_behind_the_mark_went_back() {
        let at = |clock: u64| Reading { clock, mark: NOW };
        assert!(!at(NOW).went_back());
        assert!(!at(NOW + HOUR).went_back());
        assert!(!at(NOW - HOUR).went_back());
        assert!(at(NOW - HOUR - 1).went_back());
        assert!(at(0).went_back());
        assert!(!Reading { clock: 0, mark: 0 }.went_back());
    }

    /// While the agent runs, the mark follows the monotonic clock and nothing else.
    #[test]
    fn the_mark_moves_with_the_monotonic_clock_only() {
        let clock = FakeClock::at(NOW);
        let mark = start(&clock, &FakeDisk::default(), 0);

        clock.advance(Duration::from_secs(90));
        assert_eq!(
            mark.reading(),
            Some(Reading {
                clock: NOW + 90,
                mark: NOW + 90
            })
        );

        // A bad time sync throws the clock a day ahead, and another brings it back.
        clock.set_wall(NOW + 90 + 24 * HOUR);
        assert_eq!(mark.reading().unwrap().mark, NOW + 90);
        clock.set_wall(NOW + 90);
        let reading = mark.reading().unwrap();
        assert_eq!(reading.mark, NOW + 90);
        assert!(!reading.went_back());

        // Set back by two hours, it is found out.
        clock.set_wall(NOW + 90 - 2 * HOUR);
        assert!(mark.reading().unwrap().went_back());
    }

    #[test]
    fn a_monotonic_clock_that_jumps_does_not_wrap_the_mark() {
        let clock = FakeClock::at(u64::MAX - 10);
        let mark = start(&clock, &FakeDisk::default(), 0);
        clock.advance(Duration::from_secs(100));
        assert_eq!(mark.reading().unwrap().mark, u64::MAX);
    }

    /// Across a restart the mark is the one written last, with the clock set back.
    #[test]
    fn a_saved_mark_holds_across_a_restart() {
        let clock = FakeClock::at(NOW);
        let disk = FakeDisk::default();
        let mark = start(&clock, &disk, 0);
        clock.advance(Duration::from_secs(4 * HOUR));
        mark.save(&disk).unwrap();
        assert_eq!(disk.stored(), Some(NOW + 4 * HOUR));

        clock.set_wall(NOW);
        let reading = start(&clock, &disk, 0).reading().unwrap();
        assert_eq!(reading.mark, NOW + 4 * HOUR);
        assert!(reading.went_back());
    }

    #[tokio::test(start_paused = true)]
    async fn the_mark_is_written_at_start_every_five_minutes_and_at_stop() {
        let clock = FakeClock::at(NOW);
        let disk = FakeDisk::default();
        let mark = Arc::new(start(&clock, &disk, 0));
        let (stop, stopped) = watch::channel(false);
        let keeper = tokio::spawn(keep(
            Arc::clone(&mark),
            Arc::new(disk.clone()) as Arc<dyn MarkDisk>,
            stopped,
        ));

        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(disk.files().writes, 1);
        assert_eq!(disk.stored(), Some(NOW));

        clock.advance(Duration::from_secs(300));
        tokio::time::sleep(Duration::from_secs(299)).await;
        assert_eq!(disk.files().writes, 1);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(disk.files().writes, 2);
        assert_eq!(disk.stored(), Some(NOW + 300));
        assert_eq!(SAVE_EVERY, Duration::from_secs(300));

        clock.advance(Duration::from_secs(42));
        stop.send(true).unwrap();
        keeper.await.unwrap();
        assert_eq!(disk.files().writes, 3);
        assert_eq!(disk.stored(), Some(NOW + 342));
    }

    /// A disk that fails is logged and tried again; it never stops the agent.
    #[tokio::test(start_paused = true)]
    async fn a_mark_that_cannot_be_written_is_tried_again() {
        let clock = FakeClock::at(NOW);
        let disk = FakeDisk::default();
        disk.files().failing = true;
        let mark = Arc::new(start(&clock, &disk, 0));
        let (stop, stopped) = watch::channel(false);
        let keeper = tokio::spawn(keep(
            mark,
            Arc::new(disk.clone()) as Arc<dyn MarkDisk>,
            stopped,
        ));
        tokio::time::sleep(SAVE_EVERY + Duration::from_secs(1)).await;
        assert_eq!(disk.files().writes, 2);
        disk.files().failing = false;
        stop.send(true).unwrap();
        keeper.await.unwrap();
        assert_eq!(disk.stored(), Some(NOW));
    }
}
