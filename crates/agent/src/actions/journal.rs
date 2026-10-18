//! The journal of action requests, keyed by `RequestId` (ADR-0012). It is what "at most
//! once" (RNF-18) rests on.
//!
//! Two files, in the data directory:
//!
//! | File | What | Written |
//! |---|---|---|
//! | `journal.json` | requests that **started**: their preconditions passed and their steps were about to run | the start and the end at once; the delivered marks later |
//! | `ended.json` | requests that ended **before** starting: refused, a precondition that failed, cancelled | at most every minute, and at stop |
//!
//! - A started request is on disk before its first step, and it never leaves the journal
//!   before the request's expiry plus 24 hours by the mark. Any clock the agent accepts is
//!   at most one hour behind the mark, so a request that left is expired for it too, and a
//!   copy that arrives later is refused as expired: it can never run twice.
//! - What ended before starting cannot run twice, since it never ran. Losing one of those
//!   entries costs a new evaluation, so they live in a ring of [`MAX_ENDED`] where the
//!   oldest goes first, and a stream of refused requests cannot fill the journal.
//! - A started request with no end when the agent starts was cut short: it ends
//!   `Failed { interrupted }` and never runs again.
//! - In memory, a `RequestId` is in at most one entry of both files together. On disk the
//!   ring can lag behind: a crash after a start and before the ring's next write can leave
//!   an id in both, and the start wins when the journal is read. An id twice in one file,
//!   or anything else this build cannot read in full, makes the journal unavailable, and
//!   an unavailable journal refuses everything: an entry that cannot be read is never
//!   taken as "not seen".
//!
//! Times are seconds since the Unix epoch, by the clock's high-water mark (`clock.rs`),
//! which only moves forward; `expires_at` is the request's own.

use std::collections::{HashSet, VecDeque};
use std::io;

use ponte_actions::MAX_ID_LEN;
use ponte_protocol::{ActionOutcome, ActionResult, FailReason, RequestId};
use serde::{Deserialize, Serialize};

/// Most started requests the journal holds. The rate limit (at most 60 an hour) and the
/// time an entry stays (a day past an expiry at most a day ahead) keep it under 2,880
/// while the clock and the mark agree; past this the journal refuses, which fails closed.
pub(crate) const MAX_STARTED: usize = 4_096;
/// Most requests that ended before starting the ring keeps.
pub(crate) const MAX_ENDED: usize = 1_024;
/// How long an entry outlives the request's expiry, by the mark.
pub(crate) const KEPT_AFTER_EXPIRY_SECS: u64 = 24 * 60 * 60;
/// Largest `journal.json` read: a full journal is about a quarter of it.
pub(crate) const MAX_STARTED_BYTES: usize = 4 * 1024 * 1024;
/// Largest `ended.json` read: a full ring is about a third of it.
pub(crate) const MAX_ENDED_BYTES: usize = 512 * 1024;

/// The layout of both files. A new layout is a new number, and this build refuses any
/// other: an agent upgraded across one must read the old layout too.
const FORMAT: u32 = 1;

/// Which of the two files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalFile {
    Started,
    Ended,
}

/// Where the journal rests. A trait so that tests can fail the disk at any write.
pub(crate) trait JournalDisk: Send + Sync + 'static {
    /// `None` if there is no such file yet.
    fn read(&self, file: JournalFile) -> io::Result<Option<String>>;
    /// Replaces the file whole: whoever reads it later finds the old text or the new one.
    fn write(&self, file: JournalFile, text: &str) -> io::Result<()>;
    /// Takes the journal for this process, for as long as it lives. Two agents on one data
    /// directory would each trust their own copy and could run the same request twice.
    fn lock(&self) -> io::Result<()>;
}

/// Why the journal cannot be used. Says what kind of problem, never what the file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Unavailable {
    #[error("another process holds the journal")]
    Locked,
    #[error("the journal cannot be read from the disk")]
    Read,
    #[error("the journal is not in a layout this build reads")]
    Parse,
    #[error("the journal names a request twice, holds too many entries, or a bad one")]
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartedFile {
    format: u32,
    started: Vec<Started>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndedFile {
    format: u32,
    ended: Vec<Ended>,
}

/// A request whose steps were about to run when it was written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Started {
    request_id: RequestId,
    /// The id of the signed manifest, for the interval between two runs of it.
    manifest_id: String,
    /// By the mark.
    started_at: u64,
    /// The request's.
    expires_at: u64,
    /// `None` while it runs, and in a journal left by an agent that stopped meanwhile.
    end: Option<End>,
    /// Whether a session sent the result. There is no acknowledgement (ADR-0012).
    delivered: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct End {
    outcome: ActionOutcome,
    duration_ms: u64,
}

/// A request that ended before its steps could run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ended {
    request_id: RequestId,
    outcome: ActionOutcome,
    duration_ms: u64,
    /// The request's.
    expires_at: u64,
    /// By the mark.
    written_at: u64,
    delivered: bool,
}

impl Ended {
    pub(crate) fn new(result: &ActionResult, expires_at: u64, written_at: u64) -> Self {
        Self {
            request_id: result.request_id,
            outcome: result.outcome.clone(),
            duration_ms: result.duration_ms,
            expires_at,
            written_at,
            delivered: false,
        }
    }
}

/// What the journal knows of a request.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Known {
    /// It ended, and this is the answer. `delivered` says whether a session sent it.
    Ended {
        result: ActionResult,
        delivered: bool,
    },
    /// It started and has not ended: it is running now.
    Running,
}

/// Why a start was not recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartError {
    /// The journal knows the id already: the request is a duplicate.
    Duplicate,
    /// [`MAX_STARTED`] requests are in the journal.
    Full,
}

/// A start that is ready to be written. It joins the journal only once it is on disk
/// ([`Journal::commit`]): nothing may see a start the disk does not hold.
#[derive(Debug)]
pub(crate) struct PendingStart {
    entry: Started,
    /// `journal.json` with the entry in it.
    text: String,
}

impl PendingStart {
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

/// The journal in memory. It does no input or output: the executor reads and writes the
/// files through a [`JournalDisk`], and is the only one that does.
#[derive(Debug, Default)]
pub(crate) struct Journal {
    started: Vec<Started>,
    ended: VecDeque<Ended>,
    /// Changed since `journal.json` was last written.
    started_dirty: bool,
    /// Changed since `ended.json` was last written.
    ended_dirty: bool,
}

fn result(request_id: RequestId, outcome: &ActionOutcome, duration_ms: u64) -> ActionResult {
    ActionResult {
        request_id,
        outcome: outcome.clone(),
        // The answer is kept without its output (ADR-0012).
        output: None,
        duration_ms,
    }
}

impl Journal {
    /// Reads both files, after taking the journal for this process. A started request
    /// with no end becomes `Failed { interrupted }`, still to be delivered, and the
    /// journal is left dirty so that the next write records it.
    ///
    /// # Errors
    /// Another process holds it, or a file cannot be read or holds anything this build
    /// does not read in full.
    pub(crate) fn load(disk: &dyn JournalDisk) -> Result<Self, Unavailable> {
        disk.lock().map_err(|_| Unavailable::Locked)?;
        let started = match disk.read(JournalFile::Started) {
            Ok(None) => Vec::new(),
            Ok(Some(text)) => {
                let file: StartedFile =
                    serde_json::from_str(&text).map_err(|_| Unavailable::Parse)?;
                (file.format == FORMAT)
                    .then_some(file.started)
                    .ok_or(Unavailable::Parse)?
            }
            Err(_) => return Err(Unavailable::Read),
        };
        let ended = match disk.read(JournalFile::Ended) {
            Ok(None) => Vec::new(),
            Ok(Some(text)) => {
                let file: EndedFile =
                    serde_json::from_str(&text).map_err(|_| Unavailable::Parse)?;
                (file.format == FORMAT)
                    .then_some(file.ended)
                    .ok_or(Unavailable::Parse)?
            }
            Err(_) => return Err(Unavailable::Read),
        };

        if started.len() > MAX_STARTED || ended.len() > MAX_ENDED {
            return Err(Unavailable::Invalid);
        }
        // Within a file an id is there once, or the file is not one this build wrote.
        let mut started_ids = HashSet::new();
        let mut ended_ids = HashSet::new();
        let unique = started
            .iter()
            .all(|entry| started_ids.insert(entry.request_id))
            && ended.iter().all(|entry| ended_ids.insert(entry.request_id));
        if !unique {
            return Err(Unavailable::Invalid);
        }
        // Across the two, it can be: a start goes to disk at once, and the ring that had
        // dropped the same id from memory waits for its lazy write, so a crash in between
        // leaves both. The start is the stronger fact, and with it the request never runs
        // again, so it wins.
        let mut ended = ended;
        let before = ended.len();
        ended.retain(|entry| !started_ids.contains(&entry.request_id));
        let ended_dirty = ended.len() != before;
        if started
            .iter()
            .any(|entry| entry.manifest_id.is_empty() || entry.manifest_id.len() > MAX_ID_LEN)
        {
            return Err(Unavailable::Invalid);
        }

        let mut journal = Self {
            started,
            ended: ended.into(),
            started_dirty: false,
            ended_dirty,
        };
        for entry in &mut journal.started {
            if entry.end.is_none() {
                entry.end = Some(End {
                    outcome: ActionOutcome::Failed {
                        reason: FailReason::Interrupted,
                        step: None,
                    },
                    duration_ms: 0,
                });
                entry.delivered = false;
                journal.started_dirty = true;
            }
        }
        Ok(journal)
    }

    /// How many requests ended `Failed { interrupted }` and are still to be delivered.
    pub(crate) fn interrupted(&self) -> usize {
        self.started
            .iter()
            .filter(|entry| {
                !entry.delivered
                    && matches!(
                        entry.end,
                        Some(End {
                            outcome: ActionOutcome::Failed {
                                reason: FailReason::Interrupted,
                                ..
                            },
                            ..
                        })
                    )
            })
            .count()
    }

    /// The latest time any entry recorded, by the mark: the clock's mark starts no earlier.
    pub(crate) fn latest_time(&self) -> u64 {
        let started = self.started.iter().map(|entry| entry.started_at);
        let ended = self.ended.iter().map(|entry| entry.written_at);
        started.chain(ended).max().unwrap_or(0)
    }

    /// Drops what ended and whose request expired more than [`KEPT_AFTER_EXPIRY_SECS`]
    /// ago by `mark`. A running request stays whatever its dates.
    pub(crate) fn prune(&mut self, mark: u64) {
        let gone = |expires_at: u64| mark >= expires_at.saturating_add(KEPT_AFTER_EXPIRY_SECS);
        let before = self.started.len();
        self.started
            .retain(|entry| entry.end.is_none() || !gone(entry.expires_at));
        self.started_dirty |= self.started.len() != before;
        let before = self.ended.len();
        self.ended.retain(|entry| !gone(entry.expires_at));
        self.ended_dirty |= self.ended.len() != before;
    }

    pub(crate) fn lookup(&self, id: RequestId) -> Option<Known> {
        if let Some(entry) = self.started.iter().find(|entry| entry.request_id == id) {
            return Some(match &entry.end {
                Some(end) => Known::Ended {
                    result: result(id, &end.outcome, end.duration_ms),
                    delivered: entry.delivered,
                },
                None => Known::Running,
            });
        }
        self.ended
            .iter()
            .find(|entry| entry.request_id == id)
            .map(|entry| Known::Ended {
                result: result(id, &entry.outcome, entry.duration_ms),
                delivered: entry.delivered,
            })
    }

    fn contains(&self, id: RequestId) -> bool {
        self.started.iter().any(|entry| entry.request_id == id)
            || self.ended.iter().any(|entry| entry.request_id == id)
    }

    /// Requests that started less than `window` seconds before `mark`. The rate limits
    /// count exactly these (ADR-0011).
    pub(crate) fn started_within(&self, mark: u64, window: u64) -> usize {
        self.started
            .iter()
            .filter(|entry| entry.started_at.saturating_add(window) > mark)
            .count()
    }

    /// Whether a request for the manifest `id`, any version, started less than `window`
    /// seconds before `mark`.
    pub(crate) fn manifest_started_within(&self, id: &str, mark: u64, window: u64) -> bool {
        self.started
            .iter()
            .any(|entry| entry.manifest_id == id && entry.started_at.saturating_add(window) > mark)
    }

    pub(crate) fn is_full(&self) -> bool {
        self.started.len() >= MAX_STARTED
    }

    /// Prepares the start of `id`: the text of `journal.json` with it, to be written before
    /// [`Journal::commit`] adds it here.
    ///
    /// # Errors
    /// The journal knows `id` already, or is full.
    pub(crate) fn prepare_start(
        &self,
        id: RequestId,
        manifest_id: &str,
        started_at: u64,
        expires_at: u64,
    ) -> Result<PendingStart, StartError> {
        if self.contains(id) {
            return Err(StartError::Duplicate);
        }
        if self.is_full() {
            return Err(StartError::Full);
        }
        let entry = Started {
            request_id: id,
            manifest_id: manifest_id.to_owned(),
            started_at,
            expires_at,
            end: None,
            delivered: false,
        };
        let mut started = self.started.clone();
        started.push(entry.clone());
        let text = started_text(started);
        Ok(PendingStart { entry, text })
    }

    /// Adds a start that is on disk. The journal is then as the disk holds it.
    ///
    /// # Errors
    /// The journal came to know the id meanwhile; nothing is added.
    pub(crate) fn commit(&mut self, start: PendingStart) -> Result<(), StartError> {
        if self.contains(start.entry.request_id) {
            return Err(StartError::Duplicate);
        }
        self.started.push(start.entry);
        Ok(())
    }

    /// Records how a started request ended, to be delivered. `false` if `id` is not a
    /// running request.
    pub(crate) fn finish(
        &mut self,
        id: RequestId,
        outcome: ActionOutcome,
        duration_ms: u64,
    ) -> bool {
        let Some(entry) = self
            .started
            .iter_mut()
            .find(|entry| entry.request_id == id && entry.end.is_none())
        else {
            return false;
        };
        entry.end = Some(End {
            outcome,
            duration_ms,
        });
        entry.delivered = false;
        self.started_dirty = true;
        true
    }

    /// Records a request that ended before starting, to be delivered. `false`, and
    /// nothing recorded, if the journal knows the id already: one entry per id.
    pub(crate) fn record_ended(&mut self, entry: Ended) -> bool {
        if self.contains(entry.request_id) {
            return false;
        }
        if self.ended.len() == MAX_ENDED {
            self.ended.pop_front();
        }
        self.ended.push_back(entry);
        self.ended_dirty = true;
        true
    }

    /// Notes that a session sent the answer for `id`.
    pub(crate) fn mark_delivered(&mut self, id: RequestId) {
        if let Some(entry) = self.started.iter_mut().find(|entry| entry.request_id == id) {
            if entry.end.is_some() && !entry.delivered {
                entry.delivered = true;
                self.started_dirty = true;
            }
        } else if let Some(entry) = self
            .ended
            .iter_mut()
            .find(|entry| entry.request_id == id && !entry.delivered)
        {
            entry.delivered = true;
            self.ended_dirty = true;
        }
    }

    /// The answers no session sent yet, oldest first within each file.
    pub(crate) fn undelivered(&self) -> impl Iterator<Item = ActionResult> + '_ {
        let started = self
            .started
            .iter()
            .filter(|entry| !entry.delivered)
            .filter_map(|entry| {
                let end = entry.end.as_ref()?;
                Some(result(entry.request_id, &end.outcome, end.duration_ms))
            });
        let ended = self
            .ended
            .iter()
            .filter(|entry| !entry.delivered)
            .map(|entry| result(entry.request_id, &entry.outcome, entry.duration_ms));
        started.chain(ended)
    }

    /// Whether `journal.json` or `ended.json` changed since they were last taken.
    pub(crate) fn dirty(&self) -> (bool, bool) {
        (self.started_dirty, self.ended_dirty)
    }

    /// The text of `journal.json`, which is no longer dirty: a write that fails must call
    /// [`Journal::still_dirty`].
    pub(crate) fn take_started(&mut self) -> String {
        self.started_dirty = false;
        started_text(self.started.clone())
    }

    /// The text of `ended.json`, which is no longer dirty: a write that fails must call
    /// [`Journal::still_dirty`].
    pub(crate) fn take_ended(&mut self) -> String {
        self.ended_dirty = false;
        let file = EndedFile {
            format: FORMAT,
            ended: self.ended.iter().cloned().collect(),
        };
        serde_json::to_string(&file).unwrap_or_default()
    }

    /// A write of `file` did not go through: it is tried again with the next one.
    pub(crate) fn still_dirty(&mut self, file: JournalFile) {
        match file {
            JournalFile::Started => self.started_dirty = true,
            JournalFile::Ended => self.ended_dirty = true,
        }
    }
}

/// `serde_json` cannot fail on these types: no map with keys that are not strings, no
/// float. An empty text would be refused at the next load, which fails closed.
fn started_text(started: Vec<Started>) -> String {
    serde_json::to_string(&StartedFile {
        format: FORMAT,
        started,
    })
    .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use ponte_protocol::RejectReason;

    use super::*;

    const NOW: u64 = 1_792_300_000;
    const HOUR: u64 = 60 * 60;

    /// A request id that says which one it is.
    pub(crate) fn id(n: u128) -> RequestId {
        let hex = format!("{n:032x}");
        let uuid = format!(
            "\"{}-{}-{}-{}-{}\"",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        serde_json::from_str(&uuid).unwrap()
    }

    #[derive(Default)]
    pub(crate) struct Files {
        pub(crate) started: Option<String>,
        pub(crate) ended: Option<String>,
        pub(crate) unreadable: bool,
        /// One file that cannot be read, the other one fine.
        pub(crate) unreadable_file: Option<JournalFile>,
        pub(crate) locked: bool,
        /// Every write, in order, whether or not it went through.
        pub(crate) writes: Vec<JournalFile>,
        /// How many more writes go through. After that the disk fails.
        pub(crate) writes_left: Option<usize>,
    }

    /// A disk in memory that remembers what was written to it, and can fail.
    #[derive(Clone, Default)]
    pub(crate) struct FakeJournalDisk(pub(crate) Arc<Mutex<Files>>);

    impl FakeJournalDisk {
        pub(crate) fn files(&self) -> std::sync::MutexGuard<'_, Files> {
            self.0.lock().unwrap()
        }

        pub(crate) fn fail_after(&self, writes: usize) {
            self.files().writes_left = Some(writes);
        }

        pub(crate) fn works_again(&self) {
            self.files().writes_left = None;
        }
    }

    impl JournalDisk for FakeJournalDisk {
        fn read(&self, file: JournalFile) -> io::Result<Option<String>> {
            let files = self.files();
            if files.unreadable || files.unreadable_file == Some(file) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok(match file {
                JournalFile::Started => files.started.clone(),
                JournalFile::Ended => files.ended.clone(),
            })
        }

        fn write(&self, file: JournalFile, text: &str) -> io::Result<()> {
            let mut files = self.files();
            files.writes.push(file);
            match &mut files.writes_left {
                Some(0) => return Err(io::Error::other("the disk is gone")),
                Some(left) => *left -= 1,
                None => {}
            }
            match file {
                JournalFile::Started => files.started = Some(text.to_owned()),
                JournalFile::Ended => files.ended = Some(text.to_owned()),
            }
            Ok(())
        }

        fn lock(&self) -> io::Result<()> {
            if self.files().locked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(())
        }
    }

    fn rejected(reason: RejectReason) -> ActionOutcome {
        ActionOutcome::Rejected { reason }
    }

    fn ended(n: u128, expires_at: u64) -> Ended {
        Ended::new(
            &result(id(n), &rejected(RejectReason::BadSignature), 3),
            expires_at,
            NOW,
        )
    }

    /// Starts `n` for `manifest` at `at` and writes nothing: the commit after the write.
    fn start(journal: &mut Journal, n: u128, manifest: &str, at: u64, expires_at: u64) {
        let pending = journal
            .prepare_start(id(n), manifest, at, expires_at)
            .unwrap();
        journal.commit(pending).unwrap();
    }

    /// Fills the journal with started requests, without the cost of a write per start.
    fn fill(journal: &mut Journal, manifest: &str, at: u64) {
        for n in 0..u128::try_from(MAX_STARTED).unwrap() {
            journal.started.push(Started {
                request_id: id(n),
                manifest_id: manifest.to_owned(),
                started_at: at,
                expires_at: at,
                end: None,
                delivered: false,
            });
        }
    }

    fn reload(journal: &mut Journal) -> Journal {
        let disk = FakeJournalDisk::default();
        disk.files().started = Some(journal.take_started());
        disk.files().ended = Some(journal.take_ended());
        Journal::load(&disk).unwrap()
    }

    #[test]
    fn the_formats_of_the_files_are_stable() {
        let mut journal = Journal::default();
        start(&mut journal, 1, "erp.restart-service", NOW, NOW + HOUR);
        journal.finish(id(1), ActionOutcome::Succeeded {}, 1_500);
        journal.mark_delivered(id(1));
        start(&mut journal, 2, "erp.clear-stale-lock", NOW + 1, NOW + HOUR);
        journal.record_ended(ended(3, NOW + HOUR));

        assert_eq!(
            journal.take_started(),
            concat!(
                r#"{"format":1,"started":["#,
                r#"{"request_id":"00000000-0000-0000-0000-000000000001","manifest_id":"erp.restart-service","#,
                r#""started_at":1792300000,"expires_at":1792303600,"#,
                r#""end":{"outcome":{"status":"succeeded"},"duration_ms":1500},"delivered":true},"#,
                r#"{"request_id":"00000000-0000-0000-0000-000000000002","manifest_id":"erp.clear-stale-lock","#,
                r#""started_at":1792300001,"expires_at":1792303600,"end":null,"delivered":false}]}"#,
            )
        );
        assert_eq!(
            journal.take_ended(),
            concat!(
                r#"{"format":1,"ended":[{"request_id":"00000000-0000-0000-0000-000000000003","#,
                r#""outcome":{"status":"rejected","reason":"bad_signature"},"duration_ms":3,"#,
                r#""expires_at":1792303600,"written_at":1792300000,"delivered":false}]}"#,
            )
        );
    }

    #[test]
    fn a_journal_without_files_is_empty() {
        let journal = Journal::load(&FakeJournalDisk::default()).unwrap();
        assert_eq!(journal.lookup(id(1)), None);
        assert_eq!(journal.latest_time(), 0);
        assert_eq!(journal.dirty(), (false, false));
    }

    /// Anything this build cannot read in full refuses everything, never "not seen".
    #[test]
    fn a_journal_that_cannot_be_read_in_full_is_unavailable() {
        let mut full = Journal::default();
        start(&mut full, 1, "erp.restart-service", NOW, NOW + HOUR);
        full.record_ended(ended(2, NOW + HOUR));
        let started = full.take_started();
        let ended_text = full.take_ended();

        let load = |started: Option<&str>, ended: Option<&str>| {
            let disk = FakeJournalDisk::default();
            disk.files().started = started.map(str::to_owned);
            disk.files().ended = ended.map(str::to_owned);
            Journal::load(&disk).map(|_| ())
        };
        assert_eq!(load(Some(&started), Some(&ended_text)), Ok(()));
        for broken in [
            String::new(),
            "{}".to_owned(),
            "not json".to_owned(),
            started.replace("\"format\":1", "\"format\":2"),
            started.replace("\"delivered\":false", "\"delivered\":false,\"retry\":true"),
            started.replace("\"started_at\":1792300000", "\"started_at\":-1"),
            started.replace("00000000-0000-0000-0000-000000000001", "not-a-uuid"),
            started[..started.len() - 1].to_owned(),
        ] {
            assert_eq!(
                load(Some(&broken), None),
                Err(Unavailable::Parse),
                "{broken}"
            );
        }
        for broken in [
            ended_text.replace("\"format\":1", "\"format\":0"),
            ended_text.replace("bad_signature", "bad_signature_v3"),
        ] {
            assert_eq!(
                load(None, Some(&broken)),
                Err(Unavailable::Parse),
                "{broken}"
            );
        }

        // One id twice in one file. Across both files see `an_id_in_both_files_is_the_start`.
        let mut twice = Journal::default();
        start(&mut twice, 1, "erp.restart-service", NOW, NOW + HOUR);
        let mut entries = twice.started.clone();
        entries.extend(twice.started.clone());
        let doubled = started_text(entries);
        assert_eq!(load(Some(&doubled), None), Err(Unavailable::Invalid));
        let mut ring: Vec<Ended> = full.ended.iter().cloned().collect();
        ring.extend(ring.clone());
        let doubled_ring = serde_json::to_string(&EndedFile {
            format: FORMAT,
            ended: ring,
        })
        .unwrap();
        assert_eq!(load(None, Some(&doubled_ring)), Err(Unavailable::Invalid));
        // A manifest id no manifest can have.
        let long = started.replace("erp.restart-service", &"a".repeat(MAX_ID_LEN + 1));
        assert_eq!(load(Some(&long), None), Err(Unavailable::Invalid));
        let empty = started.replace("erp.restart-service", "");
        assert_eq!(load(Some(&empty), None), Err(Unavailable::Invalid));

        let disk = FakeJournalDisk::default();
        disk.files().unreadable = true;
        assert_eq!(Journal::load(&disk).map(|_| ()), Err(Unavailable::Read));
        // Either file alone is enough.
        for file in [JournalFile::Started, JournalFile::Ended] {
            let disk = FakeJournalDisk::default();
            disk.files().unreadable_file = Some(file);
            assert_eq!(
                Journal::load(&disk).map(|_| ()),
                Err(Unavailable::Read),
                "{file:?}"
            );
        }
        let disk = FakeJournalDisk::default();
        disk.files().locked = true;
        assert_eq!(Journal::load(&disk).map(|_| ()), Err(Unavailable::Locked));
    }

    /// A start on disk and the same id still in the ring written before it: a crash between
    /// the start and the ring's lazy write. The start wins, and the journal stays usable.
    #[test]
    fn an_id_in_both_files_is_the_start() {
        let mut journal = Journal::default();
        start(&mut journal, 1, "erp.restart-service", NOW, NOW + HOUR);
        journal.finish(id(1), ActionOutcome::Succeeded {}, 10);
        let disk = FakeJournalDisk::default();
        disk.files().started = Some(journal.take_started());
        let mut ring = Journal::default();
        ring.record_ended(ended(1, NOW + HOUR));
        ring.record_ended(ended(2, NOW + HOUR));
        disk.files().ended = Some(ring.take_ended());

        let journal = Journal::load(&disk).unwrap();
        assert!(matches!(
            journal.lookup(id(1)),
            Some(Known::Ended { result, .. }) if result.outcome == ActionOutcome::Succeeded {}
        ));
        assert!(journal.lookup(id(2)).is_some());
        // The ring is written again without the copy.
        assert_eq!(journal.dirty(), (false, true));
    }

    #[test]
    fn too_many_entries_are_not_a_journal() {
        let mut journal = Journal::default();
        for n in 0..=u128::try_from(MAX_STARTED).unwrap() {
            journal.started.push(Started {
                request_id: id(n),
                manifest_id: "erp.restart-service".to_owned(),
                started_at: NOW,
                expires_at: NOW,
                end: None,
                delivered: false,
            });
        }
        let disk = FakeJournalDisk::default();
        disk.files().started = Some(journal.take_started());
        assert_eq!(Journal::load(&disk).map(|_| ()), Err(Unavailable::Invalid));
    }

    /// A request the agent stopped in the middle of never runs again.
    #[test]
    fn a_start_with_no_end_was_interrupted() {
        let mut journal = Journal::default();
        start(&mut journal, 1, "erp.restart-service", NOW, NOW + HOUR);
        assert_eq!(journal.lookup(id(1)), Some(Known::Running));

        let journal = reload(&mut journal);
        let interrupted = ActionResult {
            request_id: id(1),
            outcome: ActionOutcome::Failed {
                reason: FailReason::Interrupted,
                step: None,
            },
            output: None,
            duration_ms: 0,
        };
        assert_eq!(
            journal.lookup(id(1)),
            Some(Known::Ended {
                result: interrupted.clone(),
                delivered: false
            })
        );
        assert_eq!(journal.interrupted(), 1);
        assert_eq!(journal.undelivered().collect::<Vec<_>>(), [interrupted]);
        assert_eq!(journal.dirty(), (true, false));
    }

    #[test]
    fn an_entry_stays_a_day_past_its_expiry_by_the_mark() {
        let mut journal = Journal::default();
        start(&mut journal, 1, "erp.restart-service", NOW, NOW + HOUR);
        journal.finish(id(1), ActionOutcome::Succeeded {}, 10);
        start(&mut journal, 2, "erp.restart-service", NOW, NOW + HOUR);
        journal.record_ended(ended(3, NOW + HOUR));
        journal.record_ended(ended(4, u64::MAX));
        journal.take_started();
        journal.take_ended();

        let kept_until = NOW + HOUR + KEPT_AFTER_EXPIRY_SECS;
        journal.prune(kept_until - 1);
        assert_eq!(journal.dirty(), (false, false));
        assert!(journal.lookup(id(1)).is_some());
        assert!(journal.lookup(id(3)).is_some());

        journal.prune(kept_until);
        assert_eq!(journal.lookup(id(1)), None);
        assert_eq!(journal.lookup(id(3)), None);
        // Running: it stays whatever its dates. An expiry that far away never comes.
        assert_eq!(journal.lookup(id(2)), Some(Known::Running));
        assert!(journal.lookup(id(4)).is_some());
        assert_eq!(journal.dirty(), (true, true));
        journal.prune(u64::MAX - 1);
        assert!(journal.lookup(id(4)).is_some());
    }

    #[test]
    fn the_ring_drops_its_oldest_entry() {
        let mut journal = Journal::default();
        let max = u128::try_from(MAX_ENDED).unwrap();
        for n in 0..max {
            assert!(journal.record_ended(ended(n, NOW + HOUR)));
        }
        assert!(journal.lookup(id(0)).is_some());
        assert!(journal.record_ended(ended(max, NOW + HOUR)));
        assert_eq!(journal.lookup(id(0)), None);
        assert!(journal.lookup(id(1)).is_some());
        assert!(journal.lookup(id(max)).is_some());
        assert_eq!(journal.ended.len(), MAX_ENDED);
    }

    /// One entry per id: the agent never writes a journal it would refuse to read.
    #[test]
    fn an_id_is_recorded_once() {
        let mut journal = Journal::default();
        start(&mut journal, 1, "erp.restart-service", NOW, NOW + HOUR);
        assert!(journal.record_ended(ended(2, NOW + HOUR)));

        assert!(!journal.record_ended(ended(1, NOW + HOUR)));
        assert!(!journal.record_ended(ended(2, NOW + HOUR)));
        assert_eq!(
            journal
                .prepare_start(id(1), "erp.restart-service", NOW, NOW + HOUR)
                .unwrap_err(),
            StartError::Duplicate
        );
        assert_eq!(
            journal
                .prepare_start(id(2), "erp.restart-service", NOW, NOW + HOUR)
                .unwrap_err(),
            StartError::Duplicate
        );

        // A start prepared before the journal came to know the id is not added.
        let pending = journal
            .prepare_start(id(3), "erp.restart-service", NOW, NOW + HOUR)
            .unwrap();
        assert!(journal.record_ended(ended(3, NOW + HOUR)));
        assert_eq!(journal.commit(pending), Err(StartError::Duplicate));
        assert!(reload(&mut journal).lookup(id(3)).is_some());
    }

    /// Nothing sees a start before it is on disk.
    #[test]
    fn a_start_joins_the_journal_only_when_committed() {
        let mut journal = Journal::default();
        let pending = journal
            .prepare_start(id(1), "erp.restart-service", NOW, NOW + HOUR)
            .unwrap();
        assert_eq!(journal.lookup(id(1)), None);
        assert_eq!(journal.started_within(NOW, HOUR), 0);
        assert_eq!(journal.dirty(), (false, false));

        // The text to write holds it, and loads as running-then-interrupted.
        let disk = FakeJournalDisk::default();
        disk.files().started = Some(pending.text().to_owned());
        assert_eq!(Journal::load(&disk).unwrap().interrupted(), 1);

        journal.commit(pending).unwrap();
        assert_eq!(journal.lookup(id(1)), Some(Known::Running));
        // The disk holds it already.
        assert_eq!(journal.dirty(), (false, false));
    }

    #[test]
    fn a_full_journal_takes_no_start() {
        let mut journal = Journal::default();
        fill(&mut journal, "erp.restart-service", NOW);
        assert!(journal.is_full());
        assert_eq!(
            journal
                .prepare_start(id(1 << 64), "erp.restart-service", NOW, NOW + HOUR)
                .unwrap_err(),
            StartError::Full
        );
    }

    /// The rate limits count started requests, and only those, by the mark.
    #[test]
    fn limits_count_started_requests_by_the_mark() {
        let mut journal = Journal::default();
        start(
            &mut journal,
            1,
            "erp.restart-service",
            NOW - HOUR,
            NOW + HOUR,
        );
        start(
            &mut journal,
            2,
            "erp.restart-service",
            NOW - HOUR + 1,
            NOW + HOUR,
        );
        start(
            &mut journal,
            3,
            "erp.clear-stale-lock",
            NOW - 10,
            NOW + HOUR,
        );
        journal.record_ended(ended(4, NOW + HOUR));

        assert_eq!(journal.started_within(NOW, HOUR), 2);
        assert_eq!(journal.started_within(NOW + 9, 20), 1);
        assert_eq!(journal.started_within(NOW + 10, 10), 0);
        assert!(journal.manifest_started_within("erp.clear-stale-lock", NOW, 600));
        assert!(!journal.manifest_started_within("erp.clear-stale-lock", NOW + 590, 600));
        assert!(journal.manifest_started_within("erp.restart-service", NOW, HOUR));
        assert!(!journal.manifest_started_within("erp.restart-service", NOW + 1, HOUR));
        assert!(!journal.manifest_started_within("erp.other", NOW, HOUR));
        assert_eq!(journal.latest_time(), NOW);
        // Saturating: a mark at the end of time, a window as long as time.
        assert_eq!(journal.started_within(u64::MAX - 1, u64::MAX), 3);
    }

    #[test]
    fn an_end_and_a_delivery_are_recorded_once_each() {
        let mut journal = Journal::default();
        start(&mut journal, 1, "erp.restart-service", NOW, NOW + HOUR);
        assert!(!journal.finish(id(2), ActionOutcome::Succeeded {}, 1));
        assert!(journal.finish(id(1), ActionOutcome::TimedOut {}, 60_000));
        assert!(!journal.finish(id(1), ActionOutcome::Succeeded {}, 1));
        journal.record_ended(ended(2, NOW + HOUR));

        let ids: Vec<RequestId> = journal
            .undelivered()
            .map(|result| result.request_id)
            .collect();
        assert_eq!(ids, [id(1), id(2)]);
        journal.take_started();
        journal.take_ended();
        journal.mark_delivered(id(1));
        assert_eq!(journal.dirty(), (true, false));
        journal.mark_delivered(id(2));
        assert_eq!(journal.dirty(), (true, true));
        assert_eq!(journal.undelivered().count(), 0);

        let journal = reload(&mut journal);
        assert!(matches!(
            journal.lookup(id(1)),
            Some(Known::Ended { delivered: true, result }) if result.outcome == ActionOutcome::TimedOut {}
        ));
    }

    /// What this build writes at its fullest, it reads back.
    #[test]
    fn a_full_journal_fits_in_what_is_read_back() {
        let mut journal = Journal::default();
        fill(&mut journal, &"a".repeat(MAX_ID_LEN), u64::MAX);
        for entry in &mut journal.started {
            entry.end = Some(End {
                outcome: ActionOutcome::Failed {
                    reason: FailReason::Interrupted,
                    step: Some(u8::MAX),
                },
                duration_ms: u64::MAX,
            });
        }
        for n in 0..u128::try_from(MAX_ENDED).unwrap() {
            let mut entry = ended(n + (1 << 64), u64::MAX);
            entry.duration_ms = u64::MAX;
            entry.outcome = rejected(RejectReason::RequestTooFarAhead);
            journal.record_ended(entry);
        }
        let started = journal.take_started();
        let ended_text = journal.take_ended();
        assert!(started.len() < MAX_STARTED_BYTES / 2, "{}", started.len());
        assert!(
            ended_text.len() < MAX_ENDED_BYTES / 2,
            "{}",
            ended_text.len()
        );
    }
}
