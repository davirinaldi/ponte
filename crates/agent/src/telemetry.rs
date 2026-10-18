//! The snapshot of the machine that goes in every heartbeat (RF-05).
//!
//! What is read is deliberately little (RNF-09): how long the machine is up, how busy its
//! processors are, how much memory and disk is in use. Nothing here lists processes,
//! users, network interfaces or host names, and no text from the machine goes out except
//! a drive letter. Services (RF-06) come with the Windows platform layer in M2.

use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use chrono::{DateTime, Utc};
use ponte_protocol::{DiskUsage, Label, MemoryUsage, TelemetrySnapshot};
use sysinfo::{DiskRefreshKind, Disks, System};
use tracing::warn;

/// Something that can say how the machine is doing right now.
pub(crate) trait Collect {
    /// `None` if the reading failed. A heartbeat is then skipped, not made up.
    fn snapshot(&self) -> impl Future<Output = Option<TelemetrySnapshot>> + Send;
}

/// Reads the machine through `sysinfo`.
///
/// It lives as long as the agent: processor usage is the share of time spent busy since
/// the reading before, so each heartbeat reports the average since the last one.
///
/// The very first reading of the processors takes the system about half a second, so it
/// happens on a blocking thread, like every other one, and never on the async runtime.
#[derive(Clone)]
pub(crate) struct Collector(Arc<Mutex<Option<Probe>>>);

struct Probe {
    system: System,
    disks: Disks,
}

impl Collector {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    /// Takes the first reading in the background, so that the first heartbeat has one
    /// to compare with and does not wait for it.
    pub(crate) fn warm_up(&self) {
        let probe = Arc::clone(&self.0);
        drop(tokio::task::spawn_blocking(move || {
            locked(&probe).get_or_insert_with(Probe::new);
        }));
    }
}

/// The lock of the probe. A release build ends the process on a panic, so a poisoned lock
/// only happens in a build that unwinds, and even then nothing in it is half-written that
/// matters: everything is read again each time.
fn locked(probe: &Mutex<Option<Probe>>) -> std::sync::MutexGuard<'_, Option<Probe>> {
    probe.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Collect for Collector {
    async fn snapshot(&self) -> Option<TelemetrySnapshot> {
        let probe = Arc::clone(&self.0);
        // Reading disks is a handful of system calls that may wait on a slow drive.
        let reading = tokio::task::spawn_blocking(move || {
            locked(&probe).get_or_insert_with(Probe::new).read()
        })
        .await;
        match reading {
            Ok(reading) => Some(snapshot_of(reading, Utc::now())),
            // Only in a build that unwinds: a release build ends the process on a panic.
            Err(_) => {
                warn!("reading the machine's telemetry failed: this heartbeat is skipped");
                None
            }
        }
    }
}

/// What the operating system said, before any of it is trusted to be sane.
struct Reading {
    uptime_secs: u64,
    cpu_percent: f32,
    memory_total: u64,
    memory_used: u64,
    disks: Vec<DiskReading>,
}

struct DiskReading {
    mount: String,
    total: u64,
    available: u64,
    removable: bool,
}

impl Probe {
    fn new() -> Self {
        let mut system = System::new();
        // The first reading of the processors has nothing to compare with. It is taken
        // now, so that the next one has.
        system.refresh_cpu_usage();
        Self {
            system,
            disks: Disks::new(),
        }
    }

    fn read(&mut self) -> Reading {
        self.system.refresh_memory();
        self.system.refresh_cpu_usage();
        self.disks
            .refresh_specifics(true, DiskRefreshKind::nothing().with_storage());
        Reading {
            uptime_secs: System::uptime(),
            cpu_percent: self.system.global_cpu_usage(),
            memory_total: self.system.total_memory(),
            memory_used: self.system.used_memory(),
            disks: self
                .disks
                .list()
                .iter()
                .map(|disk| DiskReading {
                    mount: disk.mount_point().to_string_lossy().into_owned(),
                    total: disk.total_space(),
                    available: disk.available_space(),
                    removable: disk.is_removable(),
                })
                .collect(),
        }
    }
}

/// Turns a reading into what goes on the wire, keeping every number inside what the
/// receiver can make sense of.
fn snapshot_of(reading: Reading, collected_at: DateTime<Utc>) -> TelemetrySnapshot {
    let mut disks: Vec<DiskUsage> = reading
        .disks
        .into_iter()
        .filter(|disk| !disk.removable)
        .filter_map(|disk| {
            Some(DiskUsage {
                mount: mount_name(&disk.mount)?,
                total_bytes: disk.total,
                available_bytes: disk.available.min(disk.total),
            })
        })
        .collect();
    disks.sort_by(|a, b| a.mount.as_str().cmp(b.mount.as_str()));
    // With these names there are at most 27 of them, under the `MAX_LISTED` of the protocol.
    disks.dedup_by(|a, b| a.mount == b.mount);

    TelemetrySnapshot {
        collected_at,
        uptime_secs: reading.uptime_secs,
        // JSON has no NaN: it would go out as `null` and the server would drop the whole
        // heartbeat.
        cpu_percent: if reading.cpu_percent.is_finite() {
            reading.cpu_percent.clamp(0.0, 100.0)
        } else {
            0.0
        },
        memory: MemoryUsage {
            total_bytes: reading.memory_total,
            used_bytes: reading.memory_used.min(reading.memory_total),
        },
        disks,
        services: Vec::new(),
    }
}

/// The name a disk is reported under: `C:` for a Windows drive, `/` for the root of
/// anything else. Every other mount point is left out, because a path can carry a user
/// name or the label somebody gave a volume (invariant 6 in `AGENTS.md`).
fn mount_name(mount: &str) -> Option<Label> {
    let name = match mount.as_bytes() {
        [b'/'] => "/".to_owned(),
        [letter, b':'] | [letter, b':', b'\\'] if letter.is_ascii_alphabetic() => {
            format!("{}:", char::from(letter.to_ascii_uppercase()))
        }
        _ => return None,
    };
    // Both shapes are labels already, so nothing is replaced.
    Some(Label::from_lossy(&name))
}

/// What the agent says its operating system is, in `Enroll` and `Hello`.
pub(crate) fn os_label() -> Label {
    Label::from_lossy(&System::long_os_version().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> DateTime<Utc> {
        "2026-01-01T00:00:00Z".parse().unwrap()
    }

    fn reading() -> Reading {
        Reading {
            uptime_secs: 60,
            cpu_percent: 12.5,
            memory_total: 8,
            memory_used: 3,
            disks: Vec::new(),
        }
    }

    fn disk(mount: &str) -> DiskReading {
        DiskReading {
            mount: mount.to_owned(),
            total: 10,
            available: 4,
            removable: false,
        }
    }

    #[test]
    fn a_sane_reading_goes_out_as_it_is() {
        let snapshot = snapshot_of(
            Reading {
                disks: vec![disk(r"C:\")],
                ..reading()
            },
            at(),
        );
        assert_eq!(
            snapshot,
            TelemetrySnapshot {
                collected_at: at(),
                uptime_secs: 60,
                cpu_percent: 12.5,
                memory: MemoryUsage {
                    total_bytes: 8,
                    used_bytes: 3,
                },
                disks: vec![DiskUsage {
                    mount: "C:".parse().unwrap(),
                    total_bytes: 10,
                    available_bytes: 4,
                }],
                services: Vec::new(),
            }
        );
    }

    /// Whatever the operating system says, the heartbeat must be one the server can read.
    #[test]
    fn numbers_that_make_no_sense_are_brought_back_in_range() {
        for (read, sent) in [
            (f32::NAN, 0.0),
            (f32::INFINITY, 0.0),
            (f32::NEG_INFINITY, 0.0),
            (-1.0, 0.0),
            (250.0, 100.0),
            (0.0, 0.0),
            (100.0, 100.0),
        ] {
            let snapshot = snapshot_of(
                Reading {
                    cpu_percent: read,
                    ..reading()
                },
                at(),
            );
            assert_eq!(snapshot.cpu_percent, sent, "{read}");
            let wire = serde_json::to_string(&snapshot).unwrap();
            assert!(
                serde_json::from_str::<TelemetrySnapshot>(&wire).is_ok(),
                "{wire}"
            );
        }

        let snapshot = snapshot_of(
            Reading {
                memory_total: 8,
                memory_used: 9,
                disks: vec![DiskReading {
                    available: 11,
                    ..disk(r"C:\")
                }],
                ..reading()
            },
            at(),
        );
        assert_eq!(snapshot.memory.used_bytes, 8);
        assert_eq!(snapshot.disks[0].available_bytes, 10);
    }

    /// A mount point is a path, and a path can name a person. Only a drive letter or the
    /// root goes out.
    #[test]
    fn only_drive_letters_and_the_root_are_reported() {
        assert_eq!(mount_name(r"C:\").as_ref().map(Label::as_str), Some("C:"));
        assert_eq!(mount_name("d:").as_ref().map(Label::as_str), Some("D:"));
        assert_eq!(mount_name("/").as_ref().map(Label::as_str), Some("/"));
        for left_out in [
            "",
            r"C:\Users\someone\mounted",
            r"\\server\share",
            r"\\?\Volume{0e5d3a9c-0000-0000-0000-100000000000}\",
            "/home/someone",
            "/media/someone/Family photos",
            "/boot",
            "1:",
            r"CD:\",
            "\u{e9}:",
            "C:/",
        ] {
            assert_eq!(mount_name(left_out), None, "{left_out}");
        }
    }

    #[test]
    fn disks_are_fixed_ones_once_each() {
        let snapshot = snapshot_of(
            Reading {
                disks: vec![
                    disk(r"D:\"),
                    disk(r"C:\"),
                    disk(r"c:\"),
                    disk("/home/someone"),
                    DiskReading {
                        removable: true,
                        ..disk(r"E:\")
                    },
                ],
                ..reading()
            },
            at(),
        );
        let mounts: Vec<&str> = snapshot.disks.iter().map(|d| d.mount.as_str()).collect();
        assert_eq!(mounts, ["C:", "D:"]);
    }

    /// The real thing, on whatever machine runs the tests.
    #[tokio::test]
    async fn a_snapshot_of_this_machine_is_plausible() {
        let collector = Collector::new();
        collector.warm_up();
        let before = Utc::now();
        let snapshot = collector.snapshot().await.expect("the reading failed");

        assert!(snapshot.collected_at >= before);
        assert!(snapshot.uptime_secs > 0);
        assert!(snapshot.cpu_percent.is_finite());
        assert!((0.0..=100.0).contains(&snapshot.cpu_percent));
        assert!(snapshot.memory.total_bytes > 0);
        assert!(snapshot.memory.used_bytes <= snapshot.memory.total_bytes);
        assert!(snapshot.disks.len() <= 27);
        for disk in &snapshot.disks {
            assert!(disk.available_bytes <= disk.total_bytes, "{disk:?}");
            assert!(
                disk.mount.as_str() == "/" || disk.mount.as_str().len() == 2,
                "{disk:?}"
            );
        }
        assert!(snapshot.services.is_empty());

        // It is what the server expects, and small.
        let wire = serde_json::to_string(&snapshot).unwrap();
        assert!(serde_json::from_str::<TelemetrySnapshot>(&wire).is_ok());
        assert!(wire.len() < 4096, "{}", wire.len());

        // A second reading works on the same collector, and a clone shares it.
        assert!(collector.clone().snapshot().await.is_some());
    }

    #[test]
    fn the_os_name_is_a_label() {
        let os = os_label();
        assert!(os.as_str().parse::<Label>().is_ok());
    }
}
