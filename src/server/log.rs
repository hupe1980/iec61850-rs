//! Logs, server side: what a log control block writes and what `ReadJournal` answers.
//!
//! A log is the *durable* half of reporting. The same triggers that make a report make an
//! entry, but an entry survives the client not being there — which is why the two queries
//! resume by `EntryID` and time rather than by a sequence number, and why the log control
//! block carries `OldEnt`/`NewEnt`/`OldEntrTm`/`NewEntrTm` for a client to page between.
//!
//! Where the entries actually live is a [`LogStore`]. The default, [`MemoryLog`], is a bounded
//! ring: right for a simulator and wrong for a device that must survive a restart, which is
//! why it is behind a trait rather than behind a `Vec` (D5). Everything above it — the trigger
//! evaluation, the control-block bookkeeping, the two queries — is the same whichever store is
//! underneath, and `OldEnt` moving is how a client that comes back after a long absence learns
//! that the gap it wanted is gone.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
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
    /// The `EntryID`, monotonic within a log.
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
/// holds the entries is what has to keep it ordered and unique — including across the restart
/// a durable store exists to survive.
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

/// Where a server's log entries live.
///
/// The default is [`MemoryLog`]. Implement this over `redb`, SQLite or a flash ring to make a
/// log survive a restart — which is the difference between a simulator and an IED, and the
/// only thing that differs: the trigger evaluation, the control-block bookkeeping and the two
/// ACSI queries are above this line and do not change.
///
/// `Debug` is a supertrait for the same reason [`FileStore`](super::FileStore) has one: the
/// store is a field of a server that derives `Debug`.
pub trait LogStore: core::fmt::Debug + Send + Sync {
    /// Append an entry to `log`, assign it an identifier, and report what the log now holds.
    ///
    /// `None` when there is no such log, which cannot happen for a log the model declares.
    fn append(&mut self, log: &str, entry: NewEntry) -> Option<LogBounds>;

    /// Entries between two moments, oldest first — IEC 61850's `QueryLogByTime`.
    ///
    /// At most `limit`; the flag says whether more matched than were returned.
    fn by_time(&self, log: &str, from: Option<EntryTime>, to: Option<EntryTime>, limit: usize) -> (Vec<Entry>, bool);

    /// Entries after `entry_id` — `QueryLogAfterEntry`.
    ///
    /// An identifier the store no longer holds falls back to the *time*, which is why the
    /// query carries both: a client that missed the window still gets everything after the
    /// moment it stopped rather than nothing at all.
    fn after_entry(&self, log: &str, entry_id: u64, at: EntryTime, limit: usize) -> (Vec<Entry>, bool);

    /// How many entries `log` holds.
    fn len(&self, log: &str) -> usize;

    /// Forget everything in `log`. The default does nothing, for a store that cannot.
    fn purge(&mut self, log: &str) {
        let _ = log;
    }
}

/// The default [`LogStore`]: a bounded ring per log, in memory.
///
/// It drops the oldest entry when it is full, which is what a real IED does; what it does not
/// do is survive a restart, and an IED that must should be given a store that does.
#[derive(Debug)]
pub struct MemoryLog {
    logs: BTreeMap<String, Journal>,
    capacity: usize,
}

impl MemoryLog {
    /// A store holding at most `capacity` entries per log (at least one).
    pub fn new(capacity: usize) -> MemoryLog {
        MemoryLog { logs: BTreeMap::new(), capacity: capacity.max(1) }
    }

    /// A store for the logs `references` names.
    ///
    /// A log the model declares exists from the start with no entries, which is what makes
    /// `ReadJournal` on an empty log an empty answer rather than *object-non-existent*.
    pub fn for_logs(references: impl IntoIterator<Item = String>, capacity: usize) -> MemoryLog {
        let mut store = MemoryLog::new(capacity);
        for reference in references {
            store.logs.insert(reference, Journal { entries: Vec::new(), next_id: 1 });
        }
        store
    }
}

impl Default for MemoryLog {
    fn default() -> MemoryLog {
        MemoryLog::new(DEFAULT_LOG_CAPACITY)
    }
}

impl LogStore for MemoryLog {
    fn append(&mut self, log: &str, entry: NewEntry) -> Option<LogBounds> {
        let capacity = self.capacity;
        let journal = self.logs.get_mut(log)?;
        let entry_id = journal.next_id;
        journal.next_id = journal.next_id.wrapping_add(1);
        journal.entries.push(Entry { entry_id, occurred: entry.occurred, values: entry.values, reason: entry.reason });
        if journal.entries.len() > capacity {
            journal.entries.remove(0);
        }
        let oldest = journal.entries.first().map_or((entry_id, entry.occurred), |e| (e.entry_id, e.occurred));
        Some(LogBounds { oldest, newest: (entry_id, entry.occurred) })
    }

    fn by_time(&self, log: &str, from: Option<EntryTime>, to: Option<EntryTime>, limit: usize) -> (Vec<Entry>, bool) {
        let Some(journal) = self.logs.get(log) else { return (Vec::new(), false) };
        let matching: Vec<&Entry> = journal.entries.iter().filter(|e| from.is_none_or(|f| e.occurred >= f) && to.is_none_or(|t| e.occurred <= t)).collect();
        page(&matching, limit)
    }

    fn after_entry(&self, log: &str, entry_id: u64, at: EntryTime, limit: usize) -> (Vec<Entry>, bool) {
        let Some(journal) = self.logs.get(log) else { return (Vec::new(), false) };
        let matching: Vec<&Entry> = match journal.entries.iter().position(|e| e.entry_id == entry_id) {
            Some(i) => journal.entries.iter().skip(i + 1).collect(),
            None => journal.entries.iter().filter(|e| e.occurred > at).collect(),
        };
        page(&matching, limit)
    }

    fn len(&self, log: &str) -> usize {
        self.logs.get(log).map_or(0, |j| j.entries.len())
    }

    fn purge(&mut self, log: &str) {
        if let Some(journal) = self.logs.get_mut(log) {
            journal.entries.clear();
        }
    }
}

/// One log and everything written into it.
#[derive(Debug)]
struct Journal {
    entries: Vec<Entry>,
    next_id: u64,
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
        Logs { declared: logs, controls, store }
    }

    /// Serve the entries out of `store` instead of the default in-memory one.
    ///
    /// The store has to know the same logs the model does; [`MemoryLog::for_logs`] is what the
    /// default does, and [`Logs::log_references`] is the list to build any other one from.
    pub fn set_store(&mut self, store: Box<dyn LogStore>) {
        self.store = store;
    }

    /// The logs the model declares, as full references.
    pub fn log_references(&self) -> &[String] {
        &self.declared
    }

    /// Entries a log holds.
    pub fn len(&self, reference: &str) -> usize {
        self.store.len(reference)
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
    /// The trigger evaluation is the report engine's, deliberately: a client that configures
    /// a log and a report with the same `TrgOps` must get the same events in both, and two
    /// implementations of "did this change matter" is how they drift apart.
    pub fn commit(&mut self, ied: &mut Ied, dirty: &BTreeMap<String, TrgOps>, wall: EntryTime) {
        let controls = self.controls.clone();
        for Control { block, log: log_reference, reason_code } in controls {
            if !ied.value(&alloc::format!("{block}$LogEna")).and_then(bool_of).unwrap_or(false) {
                continue;
            }
            let Some(data_set) = ied.value(&alloc::format!("{block}$DatSet")).and_then(string_of) else { continue };
            let Some(ds) = ied.data_set(&data_set).cloned() else { continue };
            let trg_ops = ied.value(&alloc::format!("{block}$TrgOps")).and_then(TrgOps::from_value).unwrap_or(TrgOps::NONE);

            // A log entry records the data set's **members**, exactly as a report does: the
            // two share this evaluation ([`super::rcb::reason_for`]) so that a client which
            // configures a log and a report with the same `TrgOps` cannot be given two
            // different answers about what changed.
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
    fn append(&mut self, ied: &mut Ied, log_reference: &str, values: Vec<(String, Value)>, reason: Option<ReasonCode>, occurred: EntryTime) {
        let Some(bounds) = self.store.append(log_reference, NewEntry { occurred, values, reason }) else { return };
        // `OldEnt` moving is how a client that has been away learns its resume point is gone.
        for Control { block, log, .. } in &self.controls {
            if log != log_reference {
                continue;
            }
            let _ = ied.set_internal(&alloc::format!("{block}$OldEnt"), Value::OctetString(bounds.oldest.0.to_be_bytes().to_vec()));
            let _ = ied.set_internal(&alloc::format!("{block}$OldEntrTm"), Value::BinaryTime(bounds.oldest.1.to_octets().to_vec()));
            let _ = ied.set_internal(&alloc::format!("{block}$NewEnt"), Value::OctetString(bounds.newest.0.to_be_bytes().to_vec()));
            let _ = ied.set_internal(&alloc::format!("{block}$NewEntrTm"), Value::BinaryTime(bounds.newest.1.to_octets().to_vec()));
        }
    }

    /// `QueryLogByTime`: entries between two moments, inclusive.
    pub fn by_time(&self, reference: &str, from: Option<EntryTime>, to: Option<EntryTime>, limit: usize) -> (Vec<Entry>, bool) {
        if !self.has(reference) {
            return (Vec::new(), false);
        }
        self.store.by_time(reference, from, to, limit)
    }

    /// `QueryLogAfterEntry`: everything after the entry a client last saw.
    ///
    /// Both halves of the resume point are used. An `EntryID` alone is not ordered across a
    /// restart, so an identifier the log does not hold falls back to the *time*, which is what
    /// lets a client that missed the window still get everything after the moment it stopped
    /// rather than nothing at all.
    pub fn after_entry(&self, reference: &str, entry_id: u64, at: EntryTime, limit: usize) -> (Vec<Entry>, bool) {
        if !self.has(reference) {
            return (Vec::new(), false);
        }
        self.store.after_entry(reference, entry_id, at, limit)
    }
}

fn page(matching: &[&Entry], limit: usize) -> (Vec<Entry>, bool) {
    let limit = limit.max(1);
    let more = matching.len() > limit;
    (matching.iter().take(limit).map(|e| (*e).clone()).collect(), more)
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
