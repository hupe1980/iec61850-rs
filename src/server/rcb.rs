//! The report engine: what a control block does when the model changes.
//!
//! A report control block is a *state machine over one client's subscription*, and almost
//! everything about it is a rule about ownership or timing rather than about encoding:
//!
//! - **A block belongs to one client.** `RptEna` is the reservation, and a second client that
//!   writes it while another has it gets `object-access-denied`. That is why an indexed block
//!   with `RptEnabled max="3"` is *three* blocks — one per client — and why the server has to
//!   know which association is asking.
//! - **A block cannot be reconfigured while it is enabled** (IEC 61850-7-2 §17.2). Every write
//!   but `RptEna`, `GI` and `PurgeBuf` is refused while `RptEna` is true, which is the rule the
//!   client's "settings first, `RptEna` last" ordering exists for.
//! - **`BufTm` is a gathering window, not a delay.** Changes that arrive inside it go into the
//!   *same* report, which is what stops a three-phase trip becoming three reports.
//! - **A buffered block keeps its entries when nobody is listening**, and a client that
//!   reconnects resumes after the `EntryID` it last saw. That is the whole difference between
//!   `BR` and `RP`, and it is why `EntryID` is writable.
//!
//! The engine is sans-IO like everything else: [`Engine::commit`] takes what changed and the
//! caller's `now`, and returns the reports to send and who to send them to.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::result::Result;

use super::acsi::AssocId;
use super::ied::{BlockKind, DATA_ACCESS_DENIED, Ied};
use crate::common::{EntryTime, Instant, OptFlds, ReasonCode, TrgOps};
use crate::proto::data::Value;
use crate::proto::mms::report::{Report, ReportEntry};
use crate::proto::mms::{AccessResult, Mms, ObjectName, Unconfirmed, VariableAccess};

/// How many entries a buffered control block keeps before it starts dropping the oldest.
///
/// SCL says nothing about buffer size — `bufTime` is a window and `RptEnabled max` is a count
/// of instances — so it is a server setting. Overflow drops the *oldest* entry and raises
/// `BufOvfl` on the next report, which is what tells a client that reconnected that it has a
/// hole rather than a gap it can resume across.
pub const DEFAULT_BUFFER: usize = 64;

/// One control block's state.
#[derive(Debug)]
struct Rcb {
    buffered: bool,
    /// The association that has `RptEna` set, if any.
    owner: Option<AssocId>,
    /// Reserved by a client that set `Resv` (unbuffered) or `ResvTms` (buffered) without
    /// enabling it yet.
    reserved: Option<AssocId>,
    /// Changes gathered but not yet sent, and why each was included.
    pending: BTreeMap<String, ReasonCode>,
    /// When the gathering window closes; `None` when nothing is pending.
    due: Option<Instant>,
    /// When the next integrity report is due.
    integrity_due: Option<Instant>,
    /// Entries a buffered block has kept for a client that is not listening.
    buffer: Vec<Buffered>,
    /// The next `EntryID`, which is a monotonic counter here.
    next_entry: u64,
    /// Whether the buffer dropped anything since the last report went out.
    overflowed: bool,
}

#[derive(Clone, Debug)]
struct Buffered {
    entry_id: u64,
    at: EntryTime,
    reasons: BTreeMap<String, ReasonCode>,
    values: BTreeMap<String, Value>,
}

/// The report engine over every control block of an [`Ied`].
#[derive(Debug)]
pub struct Engine {
    blocks: BTreeMap<String, Rcb>,
    buffer_len: usize,
}

/// One report to send, and the association to send it on.
#[derive(Clone, Debug, PartialEq)]
pub struct Outgoing {
    /// Who asked for it.
    pub assoc: AssocId,
    /// The encoded `unconfirmed-PDU`.
    pub pdu: Vec<u8>,
}

impl Engine {
    /// An engine over the control blocks `ied` defines.
    pub fn new(ied: &Ied) -> Engine {
        let blocks = ied
            .blocks()
            .iter()
            .filter(|b| matches!(b.kind, BlockKind::Unbuffered | BlockKind::Buffered))
            .map(|b| {
                (
                    b.reference.clone(),
                    Rcb {
                        buffered: matches!(b.kind, BlockKind::Buffered),
                        owner: None,
                        reserved: None,
                        pending: BTreeMap::new(),
                        due: None,
                        integrity_due: None,
                        buffer: Vec::new(),
                        next_entry: 1,
                        overflowed: false,
                    },
                )
            })
            .collect();
        Engine { blocks, buffer_len: DEFAULT_BUFFER }
    }

    /// Whether `reference` names a report control block this engine owns.
    pub fn has(&self, reference: &str) -> bool {
        self.blocks.contains_key(reference)
    }

    /// The association that currently has a block enabled.
    pub fn owner(&self, reference: &str) -> Option<AssocId> {
        self.blocks.get(reference)?.owner
    }

    /// Decide whether `assoc` may write `attribute` of `block`, and apply the side effect.
    ///
    /// Returns `Ok(())` when the write may proceed to the value store, or a `DataAccessError`
    /// code when it may not.
    pub fn on_write(&mut self, assoc: AssocId, ied: &Ied, block: &str, attribute: &str, value: &Value, now: Instant) -> Result<(), i64> {
        // `now` starts the integrity period; everything else here is ownership.
        let enabled = ied.value(&alloc::format!("{block}$RptEna")).and_then(bool_of).unwrap_or(false);
        let Some(rcb) = self.blocks.get_mut(block) else { return Ok(()) };

        match attribute {
            "RptEna" => {
                let want = bool_of(value).unwrap_or(false);
                if want {
                    // Two clients cannot have the same block. This is the reservation, and it
                    // is the reason an indexed block exists at all.
                    if rcb.owner.is_some_and(|o| o != assoc) || rcb.reserved.is_some_and(|r| r != assoc) {
                        return Err(DATA_ACCESS_DENIED);
                    }
                    rcb.owner = Some(assoc);
                    rcb.pending.clear();
                    rcb.due = None;
                    let period = ied.value(&alloc::format!("{block}$IntgPd")).and_then(unsigned_of).unwrap_or(0);
                    rcb.integrity_due = (period > 0).then(|| now.plus_millis(u64::from(period)));
                } else {
                    if rcb.owner.is_some_and(|o| o != assoc) {
                        return Err(DATA_ACCESS_DENIED);
                    }
                    rcb.owner = None;
                    rcb.integrity_due = None;
                    rcb.pending.clear();
                    rcb.due = None;
                }
                Ok(())
            }
            // A general interrogation and a buffer purge are legal while enabled — they are
            // the two things a client does *to* a running block rather than to its settings.
            "GI" | "PurgeBuf" => {
                if rcb.owner.is_some_and(|o| o != assoc) {
                    return Err(DATA_ACCESS_DENIED);
                }
                Ok(())
            }
            // `Resv` reserves an unbuffered block and `ResvTms` a buffered one; both mean
            // "this block is mine even though I have not enabled it yet", and both are
            // released by writing the falsy value.
            "Resv" | "ResvTms" => {
                let want = match attribute {
                    "Resv" => bool_of(value).unwrap_or(false),
                    _ => integer_of(value).unwrap_or(0) > 0,
                };
                if want {
                    if rcb.reserved.is_some_and(|r| r != assoc) || rcb.owner.is_some_and(|o| o != assoc) {
                        return Err(DATA_ACCESS_DENIED);
                    }
                    rcb.reserved = Some(assoc);
                } else if rcb.reserved == Some(assoc) {
                    rcb.reserved = None;
                }
                Ok(())
            }
            // Everything else is a *setting*, and IEC 61850-7-2 §17.2 forbids changing one
            // while the block is enabled. A server that allows it produces reports whose
            // shape changes halfway through a sequence, which is worse than a refusal.
            _ if enabled || rcb.owner.is_some_and(|o| o != assoc) || rcb.reserved.is_some_and(|r| r != assoc) => Err(DATA_ACCESS_DENIED),
            _ => Ok(()),
        }
    }

    /// An association ended: release everything it held.
    ///
    /// An **unbuffered** block simply stops. A **buffered** one keeps its entries — that is
    /// the whole difference between the two — so the client that comes back can resume after
    /// the `EntryID` it last saw.
    pub fn on_association_closed(&mut self, assoc: AssocId) {
        for rcb in self.blocks.values_mut() {
            if rcb.owner == Some(assoc) {
                rcb.owner = None;
                rcb.due = None;
                rcb.pending.clear();
                if !rcb.buffered {
                    rcb.buffer.clear();
                }
            }
            if rcb.reserved == Some(assoc) {
                rcb.reserved = None;
            }
        }
    }

    /// Fold a batch of changes into every block that reports them, and emit what is due.
    pub fn commit(&mut self, ied: &mut Ied, dirty: &BTreeMap<String, TrgOps>, now: Instant) -> Vec<Outgoing> {
        let references: Vec<String> = self.blocks.keys().cloned().collect();
        for reference in &references {
            self.gather(ied, reference, dirty, now);
        }
        self.emit_due(ied, now)
    }

    /// Time passed: send whatever the gathering window or the integrity period has made due.
    pub fn on_timeout(&mut self, ied: &mut Ied, now: Instant) -> Vec<Outgoing> {
        self.emit_due(ied, now)
    }

    /// When the engine next needs [`Engine::on_timeout`].
    pub fn next_timeout(&self) -> Option<Instant> {
        self.blocks.values().filter_map(|r| min_of(r.due, r.integrity_due)).min()
    }

    /// Take the changes that concern one block into its pending set.
    fn gather(&mut self, ied: &Ied, reference: &str, dirty: &BTreeMap<String, TrgOps>, now: Instant) {
        let Some(rcb) = self.blocks.get(reference) else { return };
        // A block nobody has enabled still buffers, if it is buffered; an unbuffered one with
        // no owner has nothing to do at all.
        if rcb.owner.is_none() && !rcb.buffered {
            return;
        }
        let Some(data_set) = ied.value(&alloc::format!("{reference}$DatSet")).and_then(string_of) else { return };
        let Some(ds) = ied.data_set(&data_set) else { return };
        let trg_ops = ied.value(&alloc::format!("{reference}$TrgOps")).and_then(TrgOps::from_value).unwrap_or(TrgOps::NONE);
        let buf_tm = ied.value(&alloc::format!("{reference}$BufTm")).and_then(unsigned_of).unwrap_or(0);

        let mut hits: Vec<(String, ReasonCode)> = Vec::new();
        for leaf in &ds.leaves {
            let Some(trigger) = dirty.get(leaf) else { continue };
            // What the block asked for, intersected with what happened.
            let mut reason = ReasonCode::NONE;
            if trigger.data_change() && trg_ops.data_change() {
                reason = reason.with_data_change(true);
            }
            if trigger.quality_change() && trg_ops.quality_change() {
                reason = reason.with_quality_change(true);
            }
            if trigger.data_update() && trg_ops.data_update() {
                reason = reason.with_data_update(true);
            }
            if !reason.is_empty() {
                hits.push((leaf.clone(), reason));
            }
        }
        if hits.is_empty() {
            return;
        }
        let Some(rcb) = self.blocks.get_mut(reference) else { return };
        for (leaf, reason) in hits {
            let slot = rcb.pending.entry(leaf).or_insert(ReasonCode::NONE);
            *slot = merge_reason(*slot, reason);
        }
        // `BufTm` gathers: the window opens at the first change and everything inside it goes
        // into one report, which is what stops a three-phase trip becoming three reports.
        if rcb.due.is_none() {
            rcb.due = Some(now.plus_millis(u64::from(buf_tm)));
        }
    }

    /// Emit every report whose window has closed or whose integrity period has elapsed.
    fn emit_due(&mut self, ied: &mut Ied, now: Instant) -> Vec<Outgoing> {
        let mut out = Vec::new();
        let references: Vec<String> = self.blocks.keys().cloned().collect();
        for reference in references {
            // A general interrogation is a *write* of `GI = true`, and it is consumed here so
            // that one write produces exactly one report.
            let gi = ied.value(&alloc::format!("{reference}$GI")).and_then(bool_of).unwrap_or(false);
            if gi {
                let _ = ied.write_leaf(&alloc::format!("{reference}$GI"), Value::Boolean(false));
                if let Some(report) = self.build(ied, &reference, Trigger::GeneralInterrogation, now) {
                    out.push(report);
                }
            }
            if ied.value(&alloc::format!("{reference}$PurgeBuf")).and_then(bool_of).unwrap_or(false) {
                let _ = ied.write_leaf(&alloc::format!("{reference}$PurgeBuf"), Value::Boolean(false));
                if let Some(rcb) = self.blocks.get_mut(&reference) {
                    rcb.buffer.clear();
                    rcb.overflowed = false;
                }
            }
            let (due, integrity_due) = match self.blocks.get(&reference) {
                Some(r) => (r.due, r.integrity_due),
                None => continue,
            };
            if integrity_due.is_some_and(|d| now >= d) {
                let period = ied.value(&alloc::format!("{reference}$IntgPd")).and_then(unsigned_of).unwrap_or(0);
                if let Some(rcb) = self.blocks.get_mut(&reference) {
                    rcb.integrity_due = (period > 0).then(|| now.plus_millis(u64::from(period)));
                }
                if let Some(report) = self.build(ied, &reference, Trigger::Integrity, now) {
                    out.push(report);
                }
            }
            if due.is_some_and(|d| now >= d) {
                if let Some(report) = self.build(ied, &reference, Trigger::Change, now) {
                    out.push(report);
                }
            }
        }
        out
    }

    /// Build one report, buffer it if nobody is listening, and encode it if somebody is.
    fn build(&mut self, ied: &mut Ied, reference: &str, trigger: Trigger, now: Instant) -> Option<Outgoing> {
        let data_set = ied.value(&alloc::format!("{reference}$DatSet")).and_then(string_of)?;
        let ds = ied.data_set(&data_set)?.clone();
        let opt_flds = ied.value(&alloc::format!("{reference}$OptFlds")).and_then(OptFlds::from_value).unwrap_or(OptFlds::NONE);
        let rpt_id = ied.value(&alloc::format!("{reference}$RptID")).and_then(string_of).unwrap_or_else(|| String::from(reference));
        let conf_rev = ied.value(&alloc::format!("{reference}$ConfRev")).and_then(unsigned_of).unwrap_or(0);

        let reasons: BTreeMap<String, ReasonCode> = match trigger {
            // A general interrogation and an integrity scan both report *every* member; what
            // differs is the reason code each carries, and a client acts on the difference.
            Trigger::GeneralInterrogation => ds.leaves.iter().map(|l| (l.clone(), ReasonCode::NONE.with_general_interrogation(true))).collect(),
            Trigger::Integrity => ds.leaves.iter().map(|l| (l.clone(), ReasonCode::NONE.with_integrity(true))).collect(),
            Trigger::Change => {
                let rcb = self.blocks.get_mut(reference)?;
                rcb.due = None;
                core::mem::take(&mut rcb.pending)
            }
        };
        if reasons.is_empty() {
            return None;
        }

        let values: BTreeMap<String, Value> = reasons.keys().filter_map(|l| ied.value(l).map(|v| (l.clone(), v.clone()))).collect();
        let entry_time = EntryTime::from_unix_millis(now.0 / 1_000_000);

        let rcb = self.blocks.get_mut(reference)?;
        let entry_id = rcb.next_entry;
        rcb.next_entry = rcb.next_entry.wrapping_add(1);

        let Some(assoc) = rcb.owner else {
            // Nobody is listening. A buffered block keeps the entry; an unbuffered one drops
            // it, which is the whole difference between `BR` and `RP`.
            if rcb.buffered {
                if rcb.buffer.len() >= self.buffer_len {
                    rcb.buffer.remove(0);
                    rcb.overflowed = true;
                }
                rcb.buffer.push(Buffered { entry_id, at: entry_time, reasons, values });
            }
            return None;
        };

        let overflowed = core::mem::take(&mut rcb.overflowed);
        let buffered = rcb.buffered;
        let seq_reference = alloc::format!("{reference}$SqNum");
        let seq = ied.value(&seq_reference).and_then(unsigned_of).unwrap_or(0);
        let next_seq = if buffered { u64::from(seq.wrapping_add(1)) % 0x1_0000 } else { u64::from(seq.wrapping_add(1)) % 0x100 };
        let _ = ied.write_leaf(&seq_reference, Value::Unsigned(next_seq));
        if buffered {
            let _ = ied.write_leaf(&alloc::format!("{reference}$EntryID"), Value::OctetString(entry_id.to_be_bytes().to_vec()));
            let _ = ied.write_leaf(&alloc::format!("{reference}$TimeOfEntry"), Value::BinaryTime(entry_time.to_octets().to_vec()));
        }

        let report = assemble(
            &rpt_id,
            opt_flds,
            &ds.leaves,
            &reasons,
            &values,
            &ReportHeader { seq_num: next_seq as u32, entry_time, data_set: data_set.clone(), conf_rev, entry_id, buffered, overflowed },
        );
        let pdu = encode(&report, &data_set).ok()?;
        // The counters the report just published are part of the model, so a `commit` that
        // was caused by a report does not itself trigger another one.
        ied.take_dirty();
        Some(Outgoing { assoc, pdu })
    }
}

/// Why a report is being built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trigger {
    /// A `dchg`/`qchg`/`dupd` gathering window closed.
    Change,
    /// The integrity period elapsed.
    Integrity,
    /// The client wrote `GI = true`.
    GeneralInterrogation,
}

struct ReportHeader {
    seq_num: u32,
    entry_time: EntryTime,
    data_set: String,
    conf_rev: u32,
    entry_id: u64,
    buffered: bool,
    overflowed: bool,
}

/// Turn a set of included members into the report IEC 61850-8-1 Table 40 describes.
fn assemble(
    rpt_id: &str,
    opt_flds: OptFlds,
    leaves: &[String],
    reasons: &BTreeMap<String, ReasonCode>,
    values: &BTreeMap<String, Value>,
    header: &ReportHeader,
) -> Report {
    // `BufOvfl` and `EntryID` exist only on a **buffered** control block (IEC 61850-7-2 §17.2
    // gives the URCB neither), and SCL's `bufOvfl` attribute defaults to *true* — so a
    // perfectly ordinary `<OptFields/>` on an unbuffered block asks for a field that block
    // cannot have. The report is built from the flags that actually apply, and the header it
    // publishes says the same thing, or a client reads the field after it at the wrong offset.
    let opt_flds = if header.buffered { opt_flds } else { opt_flds.with_buffer_overflow(false).with_entry_id(false) };
    let included: Vec<usize> = leaves.iter().enumerate().filter(|(_, l)| reasons.contains_key(*l)).map(|(i, _)| i).collect();
    let entries = included
        .iter()
        .map(|i| {
            let leaf = leaves.get(*i).cloned().unwrap_or_default();
            ReportEntry {
                index: *i,
                reference: opt_flds.data_reference().then(|| leaf.clone()),
                value: values.get(&leaf).cloned().unwrap_or(Value::Boolean(false)),
                reason: opt_flds.reason_for_inclusion().then(|| reasons.get(&leaf).copied().unwrap_or(ReasonCode::NONE)),
            }
        })
        .collect();
    Report {
        rpt_id: String::from(rpt_id),
        opt_flds,
        seq_num: opt_flds.sequence_number().then_some(header.seq_num),
        time_of_entry: opt_flds.report_time_stamp().then_some(header.entry_time),
        data_set: opt_flds.data_set_name().then(|| header.data_set.clone()),
        buf_ovfl: opt_flds.buffer_overflow().then_some(header.overflowed),
        entry_id: opt_flds.entry_id().then(|| header.entry_id.to_be_bytes().to_vec()),
        conf_rev: opt_flds.conf_revision().then_some(header.conf_rev),
        sub_seq_num: None,
        more_segments_follow: false,
        inclusion: Report::inclusion_for(leaves.len(), &included),
        entries,
    }
}

/// A report as the `unconfirmed-PDU` that carries it.
fn encode(report: &Report, data_set: &str) -> crate::common::Result<Vec<u8>> {
    let values = report.to_values()?;
    let encoded: Vec<Vec<u8>> = values.iter().map(|v| Value::encode_all(core::slice::from_ref(v))).collect::<crate::common::Result<_>>()?;
    let mut results = Vec::with_capacity(encoded.len());
    for bytes in &encoded {
        results.push(AccessResult::Success(crate::ber::Cursor::new(bytes).next_required()?));
    }
    // The `variableAccessSpecification` of a report names the **control block**, not the data
    // set: that is what tells a client which of its subscriptions the report belongs to.
    let (domain, item) = report.rpt_id.split_once('/').unwrap_or(("", report.rpt_id.as_str()));
    let _ = data_set;
    Mms::Unconfirmed(Unconfirmed::InformationReport { access: VariableAccess::VariableListName(ObjectName::DomainSpecific { domain, item }), results }).to_vec()
}

impl Engine {
    /// Entries a buffered block is holding for a client that is not listening.
    pub fn buffered(&self, reference: &str) -> usize {
        self.blocks.get(reference).map_or(0, |r| r.buffer.len())
    }

    /// Hand a newly-enabling client everything the block buffered while nobody was listening,
    /// resuming after `after` when the client wrote an `EntryID`.
    ///
    /// This is what a buffered control block is *for*: a client that lost its association gets
    /// the events it missed rather than a gap it cannot see.
    pub fn drain_buffer(&mut self, ied: &mut Ied, reference: &str, after: Option<u64>, now: Instant) -> Vec<Outgoing> {
        let Some(rcb) = self.blocks.get_mut(reference) else { return Vec::new() };
        let Some(assoc) = rcb.owner else { return Vec::new() };
        let start = match after {
            Some(id) => rcb.buffer.iter().position(|b| b.entry_id == id).map_or(0, |i| i + 1),
            None => 0,
        };
        let pending: Vec<Buffered> = rcb.buffer.split_off(start.min(rcb.buffer.len()));
        rcb.buffer.clear();
        let overflowed = core::mem::take(&mut rcb.overflowed);
        let mut out = Vec::new();
        let _ = now;
        for (n, entry) in pending.iter().enumerate() {
            let Some(report) = Engine::replay(ied, reference, assoc, entry, n == 0 && overflowed) else { continue };
            out.push(report);
        }
        out
    }

    fn replay(ied: &mut Ied, reference: &str, assoc: AssocId, entry: &Buffered, overflowed: bool) -> Option<Outgoing> {
        let data_set = ied.value(&alloc::format!("{reference}$DatSet")).and_then(string_of)?;
        let ds = ied.data_set(&data_set)?.clone();
        let opt_flds = ied.value(&alloc::format!("{reference}$OptFlds")).and_then(OptFlds::from_value).unwrap_or(OptFlds::NONE);
        let rpt_id = ied.value(&alloc::format!("{reference}$RptID")).and_then(string_of).unwrap_or_else(|| String::from(reference));
        let conf_rev = ied.value(&alloc::format!("{reference}$ConfRev")).and_then(unsigned_of).unwrap_or(0);
        let seq_reference = alloc::format!("{reference}$SqNum");
        let seq = ied.value(&seq_reference).and_then(unsigned_of).unwrap_or(0);
        let next_seq = u64::from(seq.wrapping_add(1)) % 0x1_0000;
        let _ = ied.write_leaf(&seq_reference, Value::Unsigned(next_seq));
        let _ = ied.write_leaf(&alloc::format!("{reference}$EntryID"), Value::OctetString(entry.entry_id.to_be_bytes().to_vec()));
        let _ = ied.write_leaf(&alloc::format!("{reference}$TimeOfEntry"), Value::BinaryTime(entry.at.to_octets().to_vec()));
        let report = assemble(
            &rpt_id,
            opt_flds,
            &ds.leaves,
            &entry.reasons,
            &entry.values,
            &ReportHeader {
                seq_num: next_seq as u32,
                entry_time: entry.at,
                data_set: data_set.clone(),
                conf_rev,
                entry_id: entry.entry_id,
                buffered: true,
                overflowed,
            },
        );
        let pdu = encode(&report, &data_set).ok()?;
        ied.take_dirty();
        Some(Outgoing { assoc, pdu })
    }
}

fn merge_reason(a: ReasonCode, b: ReasonCode) -> ReasonCode {
    let (_, mut left) = a.to_bit_string();
    let (_, right) = b.to_bit_string();
    for (l, r) in left.iter_mut().zip(&right) {
        *l |= *r;
    }
    ReasonCode::from_bit_string(&left)
}

fn min_of(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn bool_of(v: &Value) -> Option<bool> {
    match v {
        Value::Boolean(b) => Some(*b),
        _ => None,
    }
}

fn unsigned_of(v: &Value) -> Option<u32> {
    match v {
        Value::Unsigned(n) => u32::try_from(*n).ok(),
        Value::Integer(n) => u32::try_from(*n).ok(),
        _ => None,
    }
}

fn integer_of(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(n) => Some(*n),
        Value::Unsigned(n) => i64::try_from(*n).ok(),
        _ => None,
    }
}

fn string_of(v: &Value) -> Option<String> {
    match v {
        Value::VisibleString(s) | Value::MmsString(s) => (!s.is_empty()).then(|| s.clone()),
        _ => None,
    }
}
