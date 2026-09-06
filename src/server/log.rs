//! Logs, server side: what a log control block writes and what `ReadJournal` answers.
//!
//! A log is the *durable* half of reporting. The same triggers that make a report make an
//! entry, but an entry survives the client not being there — which is why the two queries
//! resume by `EntryID` and time rather than by a sequence number, and why the log control
//! block carries `OldEnt`/`NewEnt`/`OldEntrTm`/`NewEntrTm` for a client to page between.
//!
//! The store is bounded and drops the oldest entry when it is full, which is what a real IED
//! does; `OldEnt` moving is how a client that comes back after a long absence learns that the
//! gap it wanted is gone.

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

/// One log and everything written into it.
#[derive(Debug)]
struct Journal {
    /// `IED1LD0/LLN0$GeneralLog`.
    reference: String,
    entries: Vec<Entry>,
    next_id: u64,
}

/// The log engine over every log control block of an [`Ied`].
#[derive(Debug)]
pub struct Logs {
    journals: Vec<Journal>,
    /// The control blocks that write into them, as `(block reference, log reference)`.
    controls: Vec<(String, String)>,
    capacity: usize,
}

impl Logs {
    /// Build the engine from the model.
    pub fn new(ied: &Ied) -> Logs {
        let mut journals: Vec<Journal> = Vec::new();
        for domain in ied.domain_names() {
            for name in ied.log_names(&domain) {
                journals.push(Journal { reference: alloc::format!("{domain}/{name}"), entries: Vec::new(), next_id: 1 });
            }
        }
        let controls = ied
            .blocks()
            .iter()
            .filter(|b| b.kind == BlockKind::Log)
            .filter_map(|b| ied.value(&alloc::format!("{}$LogRef", b.reference)).and_then(string_of).map(|log| (b.reference.clone(), log)))
            .collect();
        Logs { journals, controls, capacity: DEFAULT_LOG_CAPACITY }
    }

    /// Entries a log holds.
    pub fn len(&self, reference: &str) -> usize {
        self.journals.iter().find(|l| l.reference == reference).map_or(0, |l| l.entries.len())
    }

    /// Whether the engine knows this log.
    pub fn has(&self, reference: &str) -> bool {
        self.journals.iter().any(|l| l.reference == reference)
    }

    /// Write an entry into every log whose control block asked for what just changed.
    ///
    /// The trigger evaluation is the report engine's, deliberately: a client that configures
    /// a log and a report with the same `TrgOps` must get the same events in both, and two
    /// implementations of "did this change matter" is how they drift apart.
    pub fn commit(&mut self, ied: &mut Ied, dirty: &BTreeMap<String, TrgOps>, wall: EntryTime) {
        let controls = self.controls.clone();
        for (block, log_reference) in controls {
            if !ied.value(&alloc::format!("{block}$LogEna")).and_then(bool_of).unwrap_or(false) {
                continue;
            }
            let Some(data_set) = ied.value(&alloc::format!("{block}$DatSet")).and_then(string_of) else { continue };
            let Some(ds) = ied.data_set(&data_set).cloned() else { continue };
            let trg_ops = ied.value(&alloc::format!("{block}$TrgOps")).and_then(TrgOps::from_value).unwrap_or(TrgOps::NONE);

            let mut values = Vec::new();
            let mut reason = ReasonCode::NONE;
            for leaf in &ds.leaves {
                let Some(trigger) = dirty.get(leaf) else { continue };
                let mut hit = false;
                if trigger.data_change() && trg_ops.data_change() {
                    reason = reason.with_data_change(true);
                    hit = true;
                }
                if trigger.quality_change() && trg_ops.quality_change() {
                    reason = reason.with_quality_change(true);
                    hit = true;
                }
                if trigger.data_update() && trg_ops.data_update() {
                    reason = reason.with_data_update(true);
                    hit = true;
                }
                if hit {
                    if let Some(v) = ied.value(leaf) {
                        values.push((leaf.clone(), v.clone()));
                    }
                }
            }
            if values.is_empty() {
                continue;
            }
            let record_reason = ied.value(&alloc::format!("{block}$TrgOps")).is_some();
            self.append(ied, &log_reference, values, record_reason.then_some(reason), wall);
        }
    }

    /// Append one entry and update the control blocks that point at this log.
    fn append(&mut self, ied: &mut Ied, log_reference: &str, values: Vec<(String, Value)>, reason: Option<ReasonCode>, occurred: EntryTime) {
        let Some(log) = self.journals.iter_mut().find(|l| l.reference == log_reference) else { return };
        let entry_id = log.next_id;
        log.next_id = log.next_id.wrapping_add(1);
        log.entries.push(Entry { entry_id, occurred, values, reason });
        if log.entries.len() > self.capacity {
            log.entries.remove(0);
        }
        let (oldest, oldest_at) = log.entries.first().map_or((entry_id, occurred), |e| (e.entry_id, e.occurred));
        // `OldEnt` moving is how a client that has been away learns its resume point is gone.
        for (block, reference) in &self.controls {
            if reference != log_reference {
                continue;
            }
            let _ = ied.set_internal(&alloc::format!("{block}$OldEnt"), Value::OctetString(oldest.to_be_bytes().to_vec()));
            let _ = ied.set_internal(&alloc::format!("{block}$OldEntrTm"), Value::BinaryTime(oldest_at.to_octets().to_vec()));
            let _ = ied.set_internal(&alloc::format!("{block}$NewEnt"), Value::OctetString(entry_id.to_be_bytes().to_vec()));
            let _ = ied.set_internal(&alloc::format!("{block}$NewEntrTm"), Value::BinaryTime(occurred.to_octets().to_vec()));
        }
    }

    /// `QueryLogByTime`: entries between two moments, inclusive.
    pub fn by_time(&self, reference: &str, from: Option<EntryTime>, to: Option<EntryTime>, limit: usize) -> (Vec<Entry>, bool) {
        let Some(log) = self.journals.iter().find(|l| l.reference == reference) else { return (Vec::new(), false) };
        let matching: Vec<&Entry> = log.entries.iter().filter(|e| from.is_none_or(|f| e.occurred >= f) && to.is_none_or(|t| e.occurred <= t)).collect();
        page(&matching, limit)
    }

    /// `QueryLogAfterEntry`: everything after the entry a client last saw.
    ///
    /// Both halves of the resume point are used. An `EntryID` alone is not ordered across a
    /// restart, so an identifier the log does not hold falls back to the *time*, which is what
    /// lets a client that missed the window still get everything after the moment it stopped
    /// rather than nothing at all.
    pub fn after_entry(&self, reference: &str, entry_id: u64, at: EntryTime, limit: usize) -> (Vec<Entry>, bool) {
        let Some(log) = self.journals.iter().find(|l| l.reference == reference) else { return (Vec::new(), false) };
        let matching: Vec<&Entry> = match log.entries.iter().position(|e| e.entry_id == entry_id) {
            Some(i) => log.entries.iter().skip(i + 1).collect(),
            None => log.entries.iter().filter(|e| e.occurred > at).collect(),
        };
        page(&matching, limit)
    }
}

fn page(matching: &[&Entry], limit: usize) -> (Vec<Entry>, bool) {
    let limit = limit.max(1);
    let more = matching.len() > limit;
    (matching.iter().take(limit).map(|e| (*e).clone()).collect(), more)
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
