//! A durable [`LogStore`] on [redb](https://docs.rs/redb): the server's log survives a restart.
//!
//! One file holds every log of a server. Each entry is one row keyed `(log, EntryID)`; each
//! append is one write transaction that inserts the entry, advances the log's counter and evicts
//! down to the capacity together, so a power loss leaves either the whole append or none of it.
//! By default every append is durable before `append` returns ([`SyncPolicy::EveryEntry`]).
//!
//! A record is the six-octet `EntryTime` (so a time filter reads nothing else), a flags octet,
//! the reason code, and each value as MMS `Data` BER — the same codec the wire uses.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use iec61850_rs::server::{Ied, RedbLog, Server};
//!
//! let ied = Ied::from_scl_file("relay.cid", None)?;
//! let mut server = Server::bind("0.0.0.0:102", ied)?;
//! let logs = server.log_references();
//! server.set_log_store(Box::new(RedbLog::open("relay-log.redb", logs, 10_000)?));
//! server.run()?;
//! # Ok(()) }
//! ```

use std::path::{Path, PathBuf};

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

use super::log::{Entry, LogBounds, LogError, LogPage, LogStore, NewEntry, in_window};
use crate::common::{EntryTime, Limits, ReasonCode};
use crate::proto::data::{Value, decode_all};

/// Every entry: `(log, EntryID)` → record.
const ENTRIES: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("entries");
/// Every log: name → `(next EntryID, entry count)`.
const LOGS: TableDefinition<&str, (u64, u64)> = TableDefinition::new("logs");
/// The record format: `"version"` → [`FORMAT`].
const SCHEMA: TableDefinition<&str, u64> = TableDefinition::new("schema");
/// The record format this build reads and writes.
const FORMAT: u64 = 1;

/// When an append reaches the disk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncPolicy {
    /// Every append is durable before [`LogStore::append`] returns. The default.
    #[default]
    EveryEntry,
    /// Appends are committed but not flushed; [`RedbLog::sync`] makes everything so far durable.
    /// A power loss loses the entries since the last sync, never more, and never tears one —
    /// for flash that wears under an fsync per entry.
    Deferred,
}

/// A [`LogStore`] in a redb file.
pub struct RedbLog {
    db: Database,
    path: PathBuf,
    capacity: u64,
    sync: SyncPolicy,
}

impl core::fmt::Debug for RedbLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RedbLog").field("path", &self.path).field("capacity", &self.capacity).field("sync", &self.sync).finish_non_exhaustive()
    }
}

/// A redb error, as the [`LogError`] the trait speaks.
fn storage(e: impl core::fmt::Display) -> LogError {
    LogError::Storage(e.to_string())
}

impl RedbLog {
    /// Open (or create) the store at `path` for the logs `logs` names, holding at most `capacity`
    /// entries per log (at least one).
    ///
    /// A log the file already holds keeps its entries and identifiers; one it does not is added
    /// empty; one the file holds but `logs` does not name is kept and not served. A log holding
    /// more than `capacity` entries is evicted down to it. A new file is created readable and
    /// writable by its owner only (on Unix).
    ///
    /// # Errors
    /// [`LogError::Storage`] when the file is open in another store (redb's lock), is of another
    /// format version, or cannot be read or written.
    pub fn open(path: impl AsRef<Path>, logs: impl IntoIterator<Item = String>, capacity: usize) -> Result<RedbLog, LogError> {
        let path = path.as_ref().to_path_buf();
        create_owner_only(&path)?;
        let db = Database::create(&path).map_err(|e| match e {
            redb::DatabaseError::DatabaseAlreadyOpen => LogError::Storage(format!("{} is already open in another log store", path.display())),
            other => LogError::Storage(format!("{}: {other}", path.display())),
        })?;
        let store = RedbLog { db, path, capacity: u64::try_from(capacity.max(1)).unwrap_or(u64::MAX), sync: SyncPolicy::default() };
        store.prepare(logs)?;
        Ok(store)
    }

    /// The same store with a different [`SyncPolicy`].
    #[must_use]
    pub fn with_sync(mut self, sync: SyncPolicy) -> RedbLog {
        self.sync = sync;
        self
    }

    /// Make every append so far durable. A no-op under [`SyncPolicy::EveryEntry`].
    ///
    /// # Errors
    /// [`LogError::Storage`] when the flush fails.
    pub fn sync(&self) -> Result<(), LogError> {
        let mut txn = self.db.begin_write().map_err(storage)?;
        txn.set_durability(Durability::Immediate).map_err(storage)?;
        txn.commit().map_err(storage)
    }

    /// Check the format, add the logs the file lacks, and evict down to the capacity.
    fn prepare(&self, logs: impl IntoIterator<Item = String>) -> Result<(), LogError> {
        let txn = self.db.begin_write().map_err(storage)?;
        {
            let mut schema = txn.open_table(SCHEMA).map_err(storage)?;
            let found = schema.get("version").map_err(storage)?.map(|v| v.value());
            match found {
                None => {
                    schema.insert("version", FORMAT).map_err(storage)?;
                }
                Some(FORMAT) => {}
                Some(other) => {
                    return Err(LogError::Storage(format!("{} holds log database format {other}; this build reads format {FORMAT}", self.path.display())));
                }
            }
            let mut table = txn.open_table(LOGS).map_err(storage)?;
            let mut entries = txn.open_table(ENTRIES).map_err(storage)?;
            for log in logs {
                let (next, mut count) = table.get(log.as_str()).map_err(storage)?.map_or((1, 0), |v| v.value());
                count = evict(&mut entries, &log, count, self.capacity)?;
                table.insert(log.as_str(), (next, count)).map_err(storage)?;
            }
        }
        txn.commit().map_err(storage)
    }

    fn counters(&self, log: &str) -> Result<(u64, u64), LogError> {
        let txn = self.db.begin_read().map_err(storage)?;
        let table = txn.open_table(LOGS).map_err(storage)?;
        table.get(log).map_err(storage)?.map(|v| v.value()).ok_or(LogError::UnknownLog)
    }

    /// Entries of `log` from `start` on, oldest first, that `keep` accepts — at most `limit`.
    fn scan(&self, log: &str, start: u64, limit: usize, keep: impl Fn(EntryTime) -> bool) -> Result<LogPage, LogError> {
        let txn = self.db.begin_read().map_err(storage)?;
        let entries = txn.open_table(ENTRIES).map_err(storage)?;
        let limit = limit.max(1);
        let mut page = LogPage::default();
        for row in entries.range((log, start)..=(log, u64::MAX)).map_err(storage)? {
            let (key, record) = row.map_err(storage)?;
            let record = record.value();
            if !keep(record_time(record)?) {
                continue;
            }
            if page.entries.len() == limit {
                page.more = true;
                break;
            }
            page.entries.push(decode_record(key.value().1, record)?);
        }
        Ok(page)
    }
}

/// Remove the oldest entries of `log` until at most `capacity` remain; the new count.
fn evict(entries: &mut redb::Table<'_, (&'static str, u64), &'static [u8]>, log: &str, mut count: u64, capacity: u64) -> Result<u64, LogError> {
    while count > capacity {
        let oldest = entries.range((log, 0)..=(log, u64::MAX)).map_err(storage)?.next().transpose().map_err(storage)?.map(|(k, _)| k.value().1);
        let Some(id) = oldest else {
            // The counter said there were more entries than there are; believe the rows.
            return Ok(0);
        };
        entries.remove((log, id)).map_err(storage)?;
        count -= 1;
    }
    Ok(count)
}

/// Create `path` with owner-only permissions if it does not exist yet. redb then opens the
/// existing (empty) file and keeps its mode.
fn create_owner_only(path: &Path) -> Result<(), LogError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(LogError::Storage(format!("{}: {e}", path.display()))),
    }
}

impl LogStore for RedbLog {
    fn append(&mut self, log: &str, entry: NewEntry) -> Result<LogBounds, LogError> {
        let record = encode_record(&entry)?;
        let mut txn = self.db.begin_write().map_err(storage)?;
        if self.sync == SyncPolicy::Deferred {
            txn.set_durability(Durability::None).map_err(storage)?;
        }
        let bounds = {
            let mut logs = txn.open_table(LOGS).map_err(storage)?;
            let (entry_id, count) = logs.get(log).map_err(storage)?.map(|v| v.value()).ok_or(LogError::UnknownLog)?;
            let mut entries = txn.open_table(ENTRIES).map_err(storage)?;
            entries.insert((log, entry_id), record.as_slice()).map_err(storage)?;
            let count = evict(&mut entries, log, count.saturating_add(1), self.capacity)?;
            logs.insert(log, (entry_id.saturating_add(1), count)).map_err(storage)?;
            let oldest = entries.range((log, 0)..=(log, u64::MAX)).map_err(storage)?.next().transpose().map_err(storage)?;
            let oldest = match oldest {
                Some((k, v)) => (k.value().1, record_time(v.value())?),
                None => (entry_id, entry.occurred),
            };
            LogBounds { oldest, newest: (entry_id, entry.occurred) }
        };
        txn.commit().map_err(storage)?;
        Ok(bounds)
    }

    fn by_time(&self, log: &str, from: Option<EntryTime>, to: Option<EntryTime>, limit: usize) -> Result<LogPage, LogError> {
        self.counters(log)?;
        self.scan(log, 0, limit, |t| in_window(t, from, to))
    }

    fn after_entry(&self, log: &str, entry_id: u64, at: EntryTime, limit: usize) -> Result<LogPage, LogError> {
        self.counters(log)?;
        let held = {
            let txn = self.db.begin_read().map_err(storage)?;
            let entries = txn.open_table(ENTRIES).map_err(storage)?;
            entries.get((log, entry_id)).map_err(storage)?.is_some()
        };
        if held { self.scan(log, entry_id.saturating_add(1), limit, |_| true) } else { self.scan(log, 0, limit, |t| t > at) }
    }

    fn bounds(&self, log: &str) -> Result<Option<LogBounds>, LogError> {
        self.counters(log)?;
        let txn = self.db.begin_read().map_err(storage)?;
        let entries = txn.open_table(ENTRIES).map_err(storage)?;
        let mut range = entries.range((log, 0)..=(log, u64::MAX)).map_err(storage)?;
        let first = range.next().transpose().map_err(storage)?;
        let last = range.next_back().transpose().map_err(storage)?;
        Ok(match first {
            None => None,
            Some((fk, fv)) => {
                let oldest = (fk.value().1, record_time(fv.value())?);
                let newest = match last {
                    Some((lk, lv)) => (lk.value().1, record_time(lv.value())?),
                    None => oldest,
                };
                Some(LogBounds { oldest, newest })
            }
        })
    }

    fn len(&self, log: &str) -> Result<usize, LogError> {
        let (_, count) = self.counters(log)?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    fn purge(&mut self, log: &str) -> Result<(), LogError> {
        let txn = self.db.begin_write().map_err(storage)?;
        {
            let mut logs = txn.open_table(LOGS).map_err(storage)?;
            let (next, _) = logs.get(log).map_err(storage)?.map(|v| v.value()).ok_or(LogError::UnknownLog)?;
            let mut entries = txn.open_table(ENTRIES).map_err(storage)?;
            entries.retain_in((log, 0)..=(log, u64::MAX), |_, _| false).map_err(storage)?;
            logs.insert(log, (next, 0)).map_err(storage)?;
        }
        txn.commit().map_err(storage)
    }
}

/// The record of one entry (see the module documentation).
fn encode_record(entry: &NewEntry) -> Result<Vec<u8>, LogError> {
    let mut out = Vec::with_capacity(16 + entry.values.len() * 24);
    out.extend_from_slice(&entry.occurred.to_octets());
    let (_, reason) = entry.reason.unwrap_or(ReasonCode::NONE).to_bit_string();
    out.push(u8::from(entry.reason.is_some()));
    out.push(reason.first().copied().unwrap_or(0));
    out.extend_from_slice(&u32::try_from(entry.values.len()).map_err(storage)?.to_be_bytes());
    for (reference, value) in &entry.values {
        out.extend_from_slice(&u16::try_from(reference.len()).map_err(storage)?.to_be_bytes());
        out.extend_from_slice(reference.as_bytes());
        let ber = Value::encode_all(core::slice::from_ref(value)).map_err(storage)?;
        out.extend_from_slice(&u32::try_from(ber.len()).map_err(storage)?.to_be_bytes());
        out.extend_from_slice(&ber);
    }
    Ok(out)
}

/// The time of a record, from its first six octets.
fn record_time(record: &[u8]) -> Result<EntryTime, LogError> {
    let head: [u8; 6] = record.get(..6).and_then(|h| h.try_into().ok()).ok_or_else(|| LogError::Storage("truncated log record".into()))?;
    Ok(EntryTime::from_octets(head))
}

/// Decode one record. Total: any octets give an entry or [`LogError::Storage`], never a panic,
/// and no allocation is sized by a length the record states before the octets are there.
pub fn decode_record(entry_id: u64, record: &[u8]) -> Result<Entry, LogError> {
    let bad = |what: &str| LogError::Storage(format!("corrupt log record {entry_id}: {what}"));
    let occurred = record_time(record)?;
    let mut rest = record.get(6..).unwrap_or_default();
    let mut take = |n: usize| -> Result<&[u8], LogError> {
        let (head, tail) = rest.split_at_checked(n).ok_or_else(|| bad("truncated"))?;
        rest = tail;
        Ok(head)
    };
    let flags = *take(1)?.first().ok_or_else(|| bad("flags"))?;
    let reason_octet = *take(1)?.first().ok_or_else(|| bad("reason"))?;
    let count = u32::from_be_bytes(take(4)?.try_into().map_err(|_| bad("count"))?);
    let limits = Limits::default();
    let mut values = Vec::new();
    for _ in 0..count {
        let len = u16::from_be_bytes(take(2)?.try_into().map_err(|_| bad("reference length"))?);
        let reference = core::str::from_utf8(take(usize::from(len))?).map_err(|_| bad("reference"))?.to_string();
        let len = u32::from_be_bytes(take(4)?.try_into().map_err(|_| bad("value length"))?);
        let ber = take(usize::try_from(len).map_err(|_| bad("value length"))?)?;
        let mut decoded = decode_all(ber, &limits).map_err(|_| bad("value"))?;
        let value = decoded.pop().filter(|_| decoded.is_empty()).ok_or_else(|| bad("value count"))?;
        values.push((reference, value));
    }
    if !rest.is_empty() {
        return Err(bad("trailing octets"));
    }
    let reason = (flags & 1 == 1).then(|| ReasonCode::from_bit_string(&[reason_octet]));
    Ok(Entry { entry_id, occurred, values, reason })
}
