//! Logs, server side: what a log control block writes and what `ReadJournal` answers.
//!
//! A log is the *durable* half of reporting. The same triggers that make a report make an
//! entry, but an entry survives the client not being there — which is why the two queries
//! resume by `EntryID` and time rather than by a sequence number, and why the log control
//! block carries `OldEnt`/`NewEnt`/`OldEntrTm`/`NewEntrTm` for a client to page between.
//!
//! Where the entries live is a [`LogStore`]. The default, [`MemoryLog`], is a bounded ring;
//! `RedbLog` (feature `log-redb`) keeps them in a file across restarts. Everything above the
//! trait — the trigger evaluation, the control-block bookkeeping, the two queries — is the same
//! whichever store is underneath, and [`check_log_store`] is the contract every store meets.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use super::ied::{BlockKind, Ied};
use crate::common::{EntryTime, ReasonCode, TrgOps};
use crate::proto::data::Value;

/// How many entries one log keeps before the oldest is dropped.
pub const DEFAULT_LOG_CAPACITY: usize = 1024;

/// One entry of a log.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// The `EntryID`, strictly increasing within a log.
    pub entry_id: u64,
    /// When it was made.
    pub occurred: EntryTime,
    /// The values it recorded: the data attribute's reference and what it was.
    pub values: Vec<(String, Value)>,
    /// Why, when the control block records reasons.
    pub reason: Option<ReasonCode>,
}

/// An entry as the engine hands it over, before a store has given it an identifier.
///
/// The `EntryID` belongs to the **store**: it is what a client resumes after, so whatever
/// holds the entries keeps it ordered and unique — across a restart too.
#[derive(Clone, Debug, PartialEq)]
pub struct NewEntry {
    /// When it was made.
    pub occurred: EntryTime,
    /// The values it records.
    pub values: Vec<(String, Value)>,
    /// Why, when the control block records reasons.
    pub reason: Option<ReasonCode>,
}

/// The oldest and newest entry a log holds — what `OldEnt`/`OldEntrTm`/`NewEnt`/`NewEntrTm`
/// publish, and where a client with no stored position starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogBounds {
    /// The oldest entry's identifier and time.
    pub oldest: (u64, EntryTime),
    /// The newest entry's identifier and time.
    pub newest: (u64, EntryTime),
}

/// One page of a query: the entries, oldest first, and whether more matched.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LogPage {
    /// The entries returned.
    pub entries: Vec<Entry>,
    /// Whether more entries matched than were returned.
    pub more: bool,
}

/// Why a [`LogStore`] could not do what it was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogError {
    /// The store holds no log of that name.
    UnknownLog,
    /// The storage underneath failed; the message says how.
    Storage(String),
}

impl core::fmt::Display for LogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LogError::UnknownLog => f.write_str("no such log"),
            LogError::Storage(why) => write!(f, "log storage failed: {why}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LogError {}

/// Where a server's log entries live.
///
/// [`MemoryLog`] is the default; `RedbLog` (feature `log-redb`) survives a restart. Implement it
/// over SQLite or a flash ring for anything else and run [`check_log_store`] against it: the
/// trigger evaluation, the control-block bookkeeping and the two ACSI queries are above this
/// trait and do not change.
///
/// `Debug` is a supertrait because the store is a field of a server that derives `Debug`.
pub trait LogStore: core::fmt::Debug + Send + Sync {
    /// Append an entry to `log`, assign it the next `EntryID`, evict the oldest entry if the
    /// log is full, and report what the log now holds.
    ///
    /// # Errors
    /// [`LogError::UnknownLog`], or [`LogError::Storage`] when the entry could not be kept. A
    /// failed append leaves the log as it was.
    fn append(&mut self, log: &str, entry: NewEntry) -> Result<LogBounds, LogError>;

    /// Entries whose time lies in `from..=to`, oldest first, at most `limit` (at least one) —
    /// IEC 61850's `QueryLogByTime`.
    ///
    /// # Errors
    /// As [`LogStore::append`].
    fn by_time(&self, log: &str, from: Option<EntryTime>, to: Option<EntryTime>, limit: usize) -> Result<LogPage, LogError>;

    /// Entries after `entry_id`, oldest first, at most `limit` — `QueryLogAfterEntry`.
    ///
    /// An identifier the store no longer holds falls back to the *time*: everything after `at`.
    /// A client that missed the window still gets everything after the moment it stopped.
    ///
    /// # Errors
    /// As [`LogStore::append`].
    fn after_entry(&self, log: &str, entry_id: u64, at: EntryTime, limit: usize) -> Result<LogPage, LogError>;

    /// The oldest and newest entry, or `None` for an empty log.
    ///
    /// # Errors
    /// As [`LogStore::append`].
    fn bounds(&self, log: &str) -> Result<Option<LogBounds>, LogError>;

    /// How many entries `log` holds.
    ///
    /// # Errors
    /// As [`LogStore::append`].
    fn len(&self, log: &str) -> Result<usize, LogError>;

    /// Forget every entry in `log`. The next entry's identifier still follows the last one's.
    ///
    /// # Errors
    /// As [`LogStore::append`].
    fn purge(&mut self, log: &str) -> Result<(), LogError>;
}

/// The default [`LogStore`]: a bounded ring per log, in memory.
///
/// It drops the oldest entry when it is full, which is what a real IED does; what it does not
/// do is survive a restart.
#[derive(Debug)]
pub struct MemoryLog {
    logs: BTreeMap<String, Journal>,
    capacity: usize,
}

impl MemoryLog {
    /// A store holding at most `capacity` entries per log (at least one), knowing no log yet.
    pub fn new(capacity: usize) -> MemoryLog {
        MemoryLog { logs: BTreeMap::new(), capacity: capacity.max(1) }
    }

    /// A store for the logs `references` names, each empty.
    ///
    /// A log the model declares exists from the start, which is what makes `ReadJournal` on
    /// an empty log an empty answer rather than *object-non-existent*.
    pub fn for_logs(references: impl IntoIterator<Item = String>, capacity: usize) -> MemoryLog {
        let mut store = MemoryLog::new(capacity);
        for reference in references {
            store.logs.insert(reference, Journal { entries: VecDeque::new(), next_id: 1 });
        }
        store
    }

    fn journal(&self, log: &str) -> Result<&Journal, LogError> {
        self.logs.get(log).ok_or(LogError::UnknownLog)
    }
}

impl Default for MemoryLog {
    fn default() -> MemoryLog {
        MemoryLog::new(DEFAULT_LOG_CAPACITY)
    }
}

impl LogStore for MemoryLog {
    fn append(&mut self, log: &str, entry: NewEntry) -> Result<LogBounds, LogError> {
        let capacity = self.capacity;
        let journal = self.logs.get_mut(log).ok_or(LogError::UnknownLog)?;
        let entry_id = journal.next_id;
        journal.next_id = journal.next_id.saturating_add(1);
        journal.entries.push_back(Entry { entry_id, occurred: entry.occurred, values: entry.values, reason: entry.reason });
        while journal.entries.len() > capacity {
            journal.entries.pop_front();
        }
        let oldest = journal.entries.front().map_or((entry_id, entry.occurred), |e| (e.entry_id, e.occurred));
        Ok(LogBounds { oldest, newest: (entry_id, entry.occurred) })
    }

    fn by_time(&self, log: &str, from: Option<EntryTime>, to: Option<EntryTime>, limit: usize) -> Result<LogPage, LogError> {
        let journal = self.journal(log)?;
        Ok(page(journal.entries.iter().filter(|e| in_window(e.occurred, from, to)), limit))
    }

    fn after_entry(&self, log: &str, entry_id: u64, at: EntryTime, limit: usize) -> Result<LogPage, LogError> {
        let journal = self.journal(log)?;
        Ok(match journal.entries.iter().position(|e| e.entry_id == entry_id) {
            Some(i) => page(journal.entries.iter().skip(i + 1), limit),
            None => page(journal.entries.iter().filter(|e| e.occurred > at), limit),
        })
    }

    fn bounds(&self, log: &str) -> Result<Option<LogBounds>, LogError> {
        let journal = self.journal(log)?;
        Ok(match (journal.entries.front(), journal.entries.back()) {
            (Some(o), Some(n)) => Some(LogBounds { oldest: (o.entry_id, o.occurred), newest: (n.entry_id, n.occurred) }),
            _ => None,
        })
    }

    fn len(&self, log: &str) -> Result<usize, LogError> {
        Ok(self.journal(log)?.entries.len())
    }

    fn purge(&mut self, log: &str) -> Result<(), LogError> {
        self.logs.get_mut(log).ok_or(LogError::UnknownLog)?.entries.clear();
        Ok(())
    }
}

/// One log and everything written into it.
#[derive(Debug)]
struct Journal {
    entries: VecDeque<Entry>,
    next_id: u64,
}

/// Whether `t` lies in the inclusive window `from..=to`.
pub(crate) fn in_window(t: EntryTime, from: Option<EntryTime>, to: Option<EntryTime>) -> bool {
    from.is_none_or(|f| t >= f) && to.is_none_or(|end| t <= end)
}

/// The first `limit` (at least one) of `matching`, and whether there were more.
fn page<'a>(mut matching: impl Iterator<Item = &'a Entry>, limit: usize) -> LogPage {
    let entries: Vec<Entry> = matching.by_ref().take(limit.max(1)).cloned().collect();
    LogPage { entries, more: matching.next().is_some() }
}

/// Check that `store` keeps the [`LogStore`] contract, using `log`, which it must hold and
/// which must be empty, with room for `capacity` entries (at least two).
///
/// This is the suite [`MemoryLog`] and `RedbLog` pass; a third-party store runs it too. It
/// appends `capacity + 4` entries and purges the log at the end.
///
/// # Errors
/// The first violation, described.
pub fn check_log_store(store: &mut dyn LogStore, log: &str, capacity: usize) -> Result<(), String> {
    macro_rules! ensure {
        ($cond:expr, $($why:tt)+) => {
            if !$cond {
                return Err(alloc::format!($($why)+));
            }
        };
    }
    let fail = |what: &str, e: LogError| alloc::format!("{what}: {e}");
    ensure!(capacity >= 2, "the check needs room for two entries, not {capacity}");

    // An empty log is a log, with nothing in it.
    ensure!(store.len(log).map_err(|e| fail("len of the empty log", e))? == 0, "the log is not empty to begin with");
    ensure!(store.bounds(log).map_err(|e| fail("bounds of the empty log", e))?.is_none(), "an empty log has bounds");
    ensure!(store.by_time(log, None, None, 8).map_err(|e| fail("by_time on the empty log", e))? == LogPage::default(), "an empty log answers by_time");
    ensure!(
        store.after_entry(log, 1, EntryTime::default(), 8).map_err(|e| fail("after_entry on the empty log", e))? == LogPage::default(),
        "an empty log answers after_entry"
    );

    // A log the store does not hold is an error, not an empty answer.
    let ghost = "\u{1}no such log";
    ensure!(store.len(ghost) == Err(LogError::UnknownLog), "len of an unknown log is not UnknownLog");
    ensure!(store.bounds(ghost) == Err(LogError::UnknownLog), "bounds of an unknown log is not UnknownLog");
    let probe = NewEntry { occurred: EntryTime::default(), values: Vec::new(), reason: None };
    ensure!(store.append(ghost, probe) == Err(LogError::UnknownLog), "append to an unknown log is not UnknownLog");

    // `capacity + 3` entries, one second apart: the first three are evicted.
    let time = |i: usize| EntryTime { millis_of_day: u32::try_from(i + 1).unwrap_or(u32::MAX).saturating_mul(1000), days_since_1984: 15_000 };
    let total = capacity + 3;
    let mut appended: Vec<Entry> = Vec::with_capacity(total);
    for i in 0..total {
        let reason = (i % 2 == 0).then(|| ReasonCode::NONE.with_data_change(true).with_quality_change(i % 4 == 0));
        let values = alloc::vec![
            (alloc::format!("LD0/GGIO1$ST$Ind{i}$stVal"), Value::Boolean(i % 3 == 0)),
            (String::from("LD0/MMXU1$MX$TotW$mag$f"), Value::Float32(f32::from(u16::try_from(i).unwrap_or(u16::MAX)) * 0.5)),
        ];
        let bounds = store.append(log, NewEntry { occurred: time(i), values: values.clone(), reason }).map_err(|e| fail("append", e))?;
        if let Some(previous) = appended.last() {
            ensure!(bounds.newest.0 > previous.entry_id, "entry {i}: EntryID {} does not follow {}", bounds.newest.0, previous.entry_id);
        }
        ensure!(bounds.newest.1 == time(i), "entry {i}: the newest bound is not the entry just appended");
        appended.push(Entry { entry_id: bounds.newest.0, occurred: time(i), values, reason });
    }
    // `capacity >= 2` was checked, so the log holds at least two entries and three were evicted.
    let held = appended.get(3..).unwrap_or_default();
    let (Some(first_held), Some(second_held), Some(last), Some(evicted), Some(evicted_next)) =
        (held.first(), held.get(1), appended.last(), appended.first(), appended.get(1))
    else {
        return Err(String::from("fewer entries than the check appended"));
    };
    ensure!(store.len(log).map_err(|e| fail("len", e))? == capacity, "the log holds more or fewer than its capacity");
    let bounds = store.bounds(log).map_err(|e| fail("bounds", e))?.ok_or("a full log has no bounds")?;
    ensure!(bounds.oldest == (first_held.entry_id, first_held.occurred), "the oldest bound is not the oldest entry kept");
    ensure!(bounds.newest == (last.entry_id, last.occurred), "the newest bound is not the last entry");

    // Everything kept, in order, exactly as appended.
    let all = store.by_time(log, None, None, total + 8).map_err(|e| fail("by_time", e))?;
    ensure!(all.entries == held && !all.more, "by_time over everything does not return the kept entries as appended");
    // Paging.
    let page_one = store.by_time(log, None, None, 1).map_err(|e| fail("by_time page", e))?;
    ensure!(page_one.entries.as_slice() == core::slice::from_ref(first_held) && page_one.more, "a one-entry page is not the oldest entry with more to come");
    // An inclusive window: both ends included.
    let window = store.by_time(log, Some(first_held.occurred), Some(second_held.occurred), 8).map_err(|e| fail("by_time window", e))?;
    ensure!(window.entries.as_slice() == held.get(..2).unwrap_or_default(), "a time window is not inclusive at both ends");

    // After an entry the log holds: everything after it.
    let after = store.after_entry(log, first_held.entry_id, EntryTime::default(), total).map_err(|e| fail("after_entry", e))?;
    ensure!(after.entries.as_slice() == held.get(1..).unwrap_or_default(), "after_entry does not resume after the entry named");
    // After an evicted entry: everything after its time.
    let fallback = store.after_entry(log, evicted.entry_id, evicted_next.occurred, total).map_err(|e| fail("after_entry fallback", e))?;
    ensure!(fallback.entries == held, "after_entry on an evicted EntryID does not fall back to the time");

    // The wall clock stepped back: the identifier still grows, and the time is kept as given.
    let early = EntryTime { millis_of_day: 0, days_since_1984: 15_000 };
    let stepped = store.append(log, NewEntry { occurred: early, values: Vec::new(), reason: None }).map_err(|e| fail("append", e))?;
    ensure!(stepped.newest.0 > last.entry_id, "an entry with an earlier time did not get a larger EntryID");
    let found = store.by_time(log, Some(early), Some(early), 8).map_err(|e| fail("by_time", e))?;
    ensure!(found.entries.iter().map(|e| e.entry_id).eq([stepped.newest.0]), "an entry is not found by its own time");

    // Purge: empty, and identifiers keep counting up.
    store.purge(log).map_err(|e| fail("purge", e))?;
    ensure!(store.len(log).map_err(|e| fail("len after purge", e))? == 0, "purge left entries behind");
    ensure!(store.bounds(log).map_err(|e| fail("bounds after purge", e))?.is_none(), "a purged log has bounds");
    let next = store.append(log, NewEntry { occurred: early, values: Vec::new(), reason: None }).map_err(|e| fail("append after purge", e))?;
    ensure!(next.newest.0 > stepped.newest.0, "purge reset the EntryID");
    store.purge(log).map_err(|e| fail("purge", e))?;
    Ok(())
}

/// One log control block, as the engine needs it.
#[derive(Clone, Debug)]
struct Control {
    /// `IED1LD0/LLN0$LG$lcb01`.
    block: String,
    /// The log it writes into, `IED1LD0/LLN0$GeneralLog`.
    log: String,
    /// SCL `LogControl/@reasonCode`: whether an entry records *why* it was made.
    reason_code: bool,
}

/// The log engine over every log control block of an [`Ied`].
///
/// It owns the model's side of logging — which control block writes into which log, what its
/// triggers are, and the `OldEnt`/`NewEnt` bookkeeping — and hands the entries themselves to a
/// [`LogStore`].
#[derive(Debug)]
pub struct Logs {
    /// The logs the model declares, as full references.
    declared: Vec<String>,
    /// The control blocks that write into them.
    controls: Vec<Control>,
    store: Box<dyn LogStore>,
    /// Entries the store refused to keep.
    failed_appends: u64,
}

impl Logs {
    /// Build the engine from the model, with the default in-memory store.
    pub fn new(ied: &Ied) -> Logs {
        let mut logs: Vec<String> = Vec::new();
        for domain in ied.domain_names() {
            for name in ied.log_names(&domain) {
                logs.push(alloc::format!("{domain}/{name}"));
            }
        }
        let controls = ied
            .blocks()
            .iter()
            .filter(|b| b.kind == BlockKind::Log)
            .filter_map(|b| {
                let log = ied.value(&alloc::format!("{}$LogRef", b.reference)).and_then(string_of)?;
                // `reasonCode` is an SCL attribute of the control block and not an MMS one,
                // so it comes from the model rather than from a value a client could write.
                let reason_code = ied
                    .model
                    .logical_devices
                    .iter()
                    .find(|ld| ld.name == b.domain)
                    .and_then(|ld| ld.logical_nodes.iter().find(|ln| ln.name == b.node))
                    .and_then(|ln| ln.log_controls.iter().find(|lcb| lcb.name == b.name))
                    .is_some_and(|lcb| lcb.reason_code);
                Some(Control { block: b.reference.clone(), log, reason_code })
            })
            .collect();
        let store = Box::new(MemoryLog::for_logs(logs.iter().cloned(), DEFAULT_LOG_CAPACITY));
        Logs { declared: logs, controls, store, failed_appends: 0 }
    }

    /// Serve the entries out of `store` instead of the default in-memory one, and publish what
    /// it already holds in every log control block's `OldEnt`/`OldEntrTm`/`NewEnt`/`NewEntrTm` —
    /// which is what a restarted server owes a client before it has written anything new.
    ///
    /// The store has to know the same logs the model does; [`Logs::log_references`] is the list
    /// to build one from.
    pub fn set_store(&mut self, ied: &mut Ied, store: Box<dyn LogStore>) {
        self.store = store;
        for log in &self.declared {
            if let Ok(Some(bounds)) = self.store.bounds(log) {
                publish(ied, &self.controls, log, bounds);
            }
        }
    }

    /// The logs the model declares, as full references.
    pub fn log_references(&self) -> &[String] {
        &self.declared
    }

    /// Entries a log holds (zero when the store cannot say).
    pub fn len(&self, reference: &str) -> usize {
        self.store.len(reference).unwrap_or(0)
    }

    /// How many entries the store has refused to keep since the server started.
    pub const fn failed_appends(&self) -> u64 {
        self.failed_appends
    }

    /// Whether the engine knows this log.
    ///
    /// The **model** decides, not the store: a log the file declares and nothing has written
    /// to yet is an empty log, and answering `object-non-existent` for it would be a lie
    /// about the model.
    pub fn has(&self, reference: &str) -> bool {
        self.declared.iter().any(|l| l == reference)
    }

    /// Write an entry into every log whose control block asked for what just changed.
    ///
    /// The trigger evaluation is the report engine's, so a client that configures a log and a
    /// report with the same `TrgOps` gets the same events in both.
    pub fn commit(&mut self, ied: &mut Ied, dirty: &BTreeMap<String, TrgOps>, wall: EntryTime) {
        let controls = self.controls.clone();
        for Control { block, log: log_reference, reason_code } in controls {
            if !ied.value(&alloc::format!("{block}$LogEna")).and_then(bool_of).unwrap_or(false) {
                continue;
            }
            let Some(data_set) = ied.value(&alloc::format!("{block}$DatSet")).and_then(string_of) else { continue };
            let Some(ds) = ied.data_set(&data_set).cloned() else { continue };
            let trg_ops = ied.value(&alloc::format!("{block}$TrgOps")).and_then(TrgOps::from_value).unwrap_or(TrgOps::NONE);

            // A log entry records the data set's **members**, as a report does, through the same
            // evaluation ([`super::rcb::reason_for`]).
            let mut values = Vec::new();
            let mut reason = ReasonCode::NONE;
            for member in &ds.members {
                let mut hit = ReasonCode::NONE;
                for leaf in &member.leaves {
                    if let Some(trigger) = dirty.get(leaf) {
                        hit = or_reason(hit, super::rcb::reason_for(*trigger, trg_ops));
                    }
                }
                if !hit.is_empty() {
                    reason = or_reason(reason, hit);
                    if let Some(v) = ied.read_reference(&member.reference) {
                        values.push((member.reference.clone(), v));
                    }
                }
            }
            if values.is_empty() {
                continue;
            }
            self.append(ied, &log_reference, values, reason_code.then_some(reason), wall);
        }
    }

    /// Append one entry and update the control blocks that point at this log.
    ///
    /// A store that refuses the entry leaves the bounds where they were and is counted: the
    /// published bounds always describe entries the store actually holds.
    fn append(&mut self, ied: &mut Ied, log_reference: &str, values: Vec<(String, Value)>, reason: Option<ReasonCode>, occurred: EntryTime) {
        match self.store.append(log_reference, NewEntry { occurred, values, reason }) {
            Ok(bounds) => publish(ied, &self.controls, log_reference, bounds),
            Err(_) => self.failed_appends = self.failed_appends.saturating_add(1),
        }
    }

    /// `QueryLogByTime`: entries between two moments, inclusive.
    ///
    /// # Errors
    /// [`LogError::UnknownLog`] for a log the model does not declare; the store's error otherwise.
    pub fn by_time(&self, reference: &str, from: Option<EntryTime>, to: Option<EntryTime>, limit: usize) -> Result<LogPage, LogError> {
        if !self.has(reference) {
            return Err(LogError::UnknownLog);
        }
        self.store.by_time(reference, from, to, limit)
    }

    /// `QueryLogAfterEntry`: everything after the entry a client last saw, or after its time
    /// when the store no longer holds the entry.
    ///
    /// # Errors
    /// As [`Logs::by_time`].
    pub fn after_entry(&self, reference: &str, entry_id: u64, at: EntryTime, limit: usize) -> Result<LogPage, LogError> {
        if !self.has(reference) {
            return Err(LogError::UnknownLog);
        }
        self.store.after_entry(reference, entry_id, at, limit)
    }
}

/// Write `bounds` into every control block that writes into `log`. `OldEnt` moving is how a
/// client that has been away learns its resume point is gone.
fn publish(ied: &mut Ied, controls: &[Control], log: &str, bounds: LogBounds) {
    for Control { block, log: target, .. } in controls {
        if target != log {
            continue;
        }
        let _ = ied.set_internal(&alloc::format!("{block}$OldEnt"), Value::OctetString(bounds.oldest.0.to_be_bytes().to_vec()));
        let _ = ied.set_internal(&alloc::format!("{block}$OldEntrTm"), Value::BinaryTime(bounds.oldest.1.to_octets().to_vec()));
        let _ = ied.set_internal(&alloc::format!("{block}$NewEnt"), Value::OctetString(bounds.newest.0.to_be_bytes().to_vec()));
        let _ = ied.set_internal(&alloc::format!("{block}$NewEntrTm"), Value::BinaryTime(bounds.newest.1.to_octets().to_vec()));
    }
}

/// Bitwise-or of two reason codes.
fn or_reason(a: ReasonCode, b: ReasonCode) -> ReasonCode {
    let (_, mut left) = a.to_bit_string();
    let (_, right) = b.to_bit_string();
    for (l, r) in left.iter_mut().zip(&right) {
        *l |= *r;
    }
    ReasonCode::from_bit_string(&left)
}

fn bool_of(v: &Value) -> Option<bool> {
    match v {
        Value::Boolean(b) => Some(*b),
        _ => None,
    }
}

fn string_of(v: &Value) -> Option<String> {
    match v {
        Value::VisibleString(s) | Value::MmsString(s) => (!s.is_empty()).then(|| s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_memory_log_keeps_the_log_store_contract() {
        for capacity in [2, 3, 16] {
            let mut store = MemoryLog::for_logs([String::from("LD0/LLN0$Log")], capacity);
            check_log_store(&mut store, "LD0/LLN0$Log", capacity).unwrap_or_else(|why| panic!("capacity {capacity}: {why}"));
        }
    }

    /// A store that refuses an entry leaves the published bounds where they were and is counted,
    /// so `OldEnt`/`NewEnt` never claim an entry the store does not hold.
    #[test]
    fn a_refused_append_is_counted_and_moves_no_bound() {
        #[derive(Debug)]
        struct Full;
        impl LogStore for Full {
            fn append(&mut self, _: &str, _: NewEntry) -> Result<LogBounds, LogError> {
                Err(LogError::Storage(String::from("disk full")))
            }
            fn by_time(&self, _: &str, _: Option<EntryTime>, _: Option<EntryTime>, _: usize) -> Result<LogPage, LogError> {
                Ok(LogPage::default())
            }
            fn after_entry(&self, _: &str, _: u64, _: EntryTime, _: usize) -> Result<LogPage, LogError> {
                Ok(LogPage::default())
            }
            fn bounds(&self, _: &str) -> Result<Option<LogBounds>, LogError> {
                Ok(None)
            }
            fn len(&self, _: &str) -> Result<usize, LogError> {
                Ok(0)
            }
            fn purge(&mut self, _: &str) -> Result<(), LogError> {
                Ok(())
            }
        }

        let mut ied = Ied::from_scl(include_str!("../../tests/fixtures/relay.icd"), None).expect("relay");
        let mut logs = Logs::new(&ied);
        logs.set_store(&mut ied, Box::new(Full));
        let before = ied.value("IED1LD0/LLN0$LG$lcb01$NewEnt").cloned();
        ied.set_internal("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).expect("set");
        let dirty: BTreeMap<String, TrgOps> = [(String::from("IED1LD0/PTRC1$ST$Tr$general"), TrgOps::NONE.with_data_change(true))].into_iter().collect();
        logs.commit(&mut ied, &dirty, EntryTime { millis_of_day: 1000, days_since_1984: 15_000 });
        assert_eq!(logs.failed_appends(), 1, "the refused entry is counted");
        assert_eq!(ied.value("IED1LD0/LLN0$LG$lcb01$NewEnt").cloned(), before, "and NewEnt did not move");
    }

    /// The check is only worth something if it fails a store that breaks the contract.
    #[test]
    fn the_check_fails_a_store_that_forgets_to_evict() {
        #[derive(Debug)]
        struct Unbounded(MemoryLog);
        impl LogStore for Unbounded {
            fn append(&mut self, log: &str, entry: NewEntry) -> Result<LogBounds, LogError> {
                self.0.append(log, entry)
            }
            fn by_time(&self, log: &str, from: Option<EntryTime>, to: Option<EntryTime>, limit: usize) -> Result<LogPage, LogError> {
                self.0.by_time(log, from, to, limit)
            }
            fn after_entry(&self, log: &str, entry_id: u64, at: EntryTime, limit: usize) -> Result<LogPage, LogError> {
                self.0.after_entry(log, entry_id, at, limit)
            }
            fn bounds(&self, log: &str) -> Result<Option<LogBounds>, LogError> {
                self.0.bounds(log)
            }
            fn len(&self, log: &str) -> Result<usize, LogError> {
                self.0.len(log)
            }
            fn purge(&mut self, log: &str) -> Result<(), LogError> {
                self.0.purge(log)
            }
        }
        // Told the capacity is 4, it actually holds 64.
        let mut store = Unbounded(MemoryLog::for_logs([String::from("L")], 64));
        let why = check_log_store(&mut store, "L", 4).unwrap_err();
        assert!(why.contains("capacity"), "{why}");
    }
}
