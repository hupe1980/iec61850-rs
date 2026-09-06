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
    reserved: Option<Reservation>,
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
    /// `SqNum` of the next report. Server-owned (D39) and **reset when the block is
    /// enabled** (IEC 61850-7-2 §17.2.2), so a client that re-enables a block sees a
    /// sequence that starts again rather than one that carries a previous client's count.
    seq: u32,
}

/// A client's claim on a control block it has not enabled.
///
/// `Resv` is a boolean and lives only as long as the association that set it. `ResvTms` is a
/// **time in seconds** ⚠, and the reason it is a time rather than a flag is that it has to
/// survive the association: a client that loses its link and comes back within the window
/// finds its buffered block still its own, which is the case the attribute exists for. A
/// reservation the server never expires is a block one client holds for ever.
#[derive(Clone, Copy, Debug)]
struct Reservation {
    assoc: AssocId,
    /// Seconds the claim outlives the association, from `ResvTms`; `None` for a `Resv`, which
    /// does not outlive it at all.
    linger_secs: Option<u32>,
    /// When it lapses. `None` while the association that made it is still open.
    until: Option<Instant>,
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
    /// What each association said it would accept, from `Initiate`. A report larger than
    /// this is **segmented**, not dropped.
    pdu: BTreeMap<AssocId, usize>,
    /// The budget for an association that has not said — the server's own configured size.
    default_pdu: usize,
    /// Blocks the engine released **itself** since the last time anyone asked: an association
    /// that ended, or a reservation that ran out. IEC 61850-7-2 §15.3.2.2.2 tracks exactly
    /// those two as `InternalChange`, and only the engine knows they happened.
    released: Vec<String>,
}

/// The PDU budget assumed for an association whose `Initiate` did not say.
///
/// ISO 9506 lets `localDetailCalling` be absent, which means "no limit stated"; a server that
/// then sends whatever it likes is one that works against every peer it was tested with. This
/// is the size the segmenter uses instead, and it is the conservative end of what stacks in
/// the field negotiate.
pub const DEFAULT_MAX_PDU: usize = 65_000;

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
                        seq: 0,
                    },
                )
            })
            .collect();
        Engine { blocks, buffer_len: DEFAULT_BUFFER, pdu: BTreeMap::new(), default_pdu: DEFAULT_MAX_PDU, released: Vec::new() }
    }

    /// What `assoc` negotiated as the largest MMS PDU it will accept.
    ///
    /// A report longer than this is split into segments rather than dropped, which is the
    /// difference between a client with a small buffer seeing a big data set and seeing
    /// nothing at all.
    pub fn set_max_pdu(&mut self, assoc: AssocId, max_pdu: usize) {
        self.pdu.insert(assoc, max_pdu);
    }

    /// The budget every association gets before it has negotiated one.
    pub fn set_default_max_pdu(&mut self, max_pdu: usize) {
        self.default_pdu = max_pdu.max(MIN_SEGMENT_BUDGET);
    }

    fn budget(&self, assoc: AssocId) -> usize {
        self.pdu.get(&assoc).copied().unwrap_or(self.default_pdu).max(MIN_SEGMENT_BUDGET)
    }

    /// The blocks the engine released on its own since this was last called.
    ///
    /// Not "which blocks changed": a client that writes `RptEna = false` is a *service* and is
    /// tracked as one. These are the changes with no service behind them.
    pub fn take_released(&mut self) -> Vec<String> {
        core::mem::take(&mut self.released)
    }

    /// Whether `reference` names a report control block this engine owns.
    pub fn has(&self, reference: &str) -> bool {
        self.blocks.contains_key(reference)
    }

    /// The association that currently has a block enabled.
    pub fn owner(&self, reference: &str) -> Option<AssocId> {
        self.blocks.get(reference)?.owner
    }

    /// The association that holds a block, whether it has enabled it or only reserved it.
    ///
    /// This is what `Owner` publishes: a client that has written `Resv`/`ResvTms` holds the
    /// block just as firmly as one that has enabled it, and an operator looking for who has
    /// the block wants the same answer in both cases.
    pub fn holder(&self, reference: &str) -> Option<AssocId> {
        let rcb = self.blocks.get(reference)?;
        rcb.owner.or_else(|| rcb.reserved.map(|r| r.assoc))
    }

    /// Every block `assoc` holds, so a caller can clear what it published about them.
    pub fn held_by(&self, assoc: AssocId) -> Vec<String> {
        self.blocks.iter().filter(|(_, r)| r.owner == Some(assoc) || r.reserved.is_some_and(|s| s.assoc == assoc)).map(|(k, _)| k.clone()).collect()
    }

    /// Decide whether `assoc` may write `attribute` of `block`, and apply the side effect.
    ///
    /// Returns `Ok(())` when the write may proceed to the value store, or a `DataAccessError`
    /// code when it may not.
    pub fn on_write(&mut self, assoc: AssocId, ied: &mut Ied, block: &str, attribute: &str, value: &Value, now: Instant) -> Result<(), i64> {
        // `now` starts the integrity period; everything else here is ownership.
        let enabled = ied.value(&alloc::format!("{block}$RptEna")).and_then(bool_of).unwrap_or(false);
        if !self.blocks.contains_key(block) {
            return Ok(());
        }

        let Some(rcb) = self.blocks.get_mut(block) else { return Ok(()) };
        match attribute {
            "RptEna" => {
                let want = bool_of(value).unwrap_or(false);
                if want {
                    // Two clients cannot have the same block. This is the reservation, and it
                    // is the reason an indexed block exists at all.
                    if rcb.owner.is_some_and(|o| o != assoc) || rcb.reserved.is_some_and(|r| r.assoc != assoc) {
                        return Err(DATA_ACCESS_DENIED);
                    }
                    rcb.owner = Some(assoc);
                    rcb.pending.clear();
                    rcb.due = None;
                    // IEC 61850-7-2 §17.2.2: `SqNum` starts again when the block is enabled,
                    // so a client cannot be handed a sequence that begins in the middle of
                    // the previous client's — which is the one thing a client uses `SqNum`
                    // for. libiec61850 zeroes it in the same place 🌐 (`reporting.c`).
                    rcb.seq = 0;
                    rcb.integrity_due = integrity_period(ied, block).map(|ms| now.plus_millis(u64::from(ms)));
                    let _ = ied.set_internal(&alloc::format!("{block}$SqNum"), Value::Unsigned(0));
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
            // A general interrogation and a buffer purge are the two things a client does *to*
            // a running block rather than to its settings, so they are legal while enabled —
            // and **only** then. A `GI` on a block nobody has enabled has nowhere to send its
            // report, and honouring it would fill a buffered block with an interrogation the
            // next client to connect never asked for.
            "GI" | "PurgeBuf" => {
                if rcb.owner != Some(assoc) {
                    return Err(DATA_ACCESS_DENIED);
                }
                Ok(())
            }
            // `Resv` reserves an unbuffered block and `ResvTms` a buffered one; both mean
            // "this block is mine even though I have not enabled it yet", and both are
            // released by writing the falsy value.
            "Resv" | "ResvTms" => {
                let linger = match attribute {
                    "Resv" => bool_of(value).unwrap_or(false).then_some(None),
                    // `ResvTms` is a count of seconds the reservation outlives the
                    // association; zero releases it and a negative value is not a duration ⚠.
                    _ => match integer_of(value).unwrap_or(0) {
                        n if n > 0 => Some(Some(u32::try_from(n).unwrap_or(u32::MAX))),
                        _ => None,
                    },
                };
                if let Some(linger_secs) = linger {
                    if rcb.reserved.is_some_and(|r| r.assoc != assoc) || rcb.owner.is_some_and(|o| o != assoc) {
                        return Err(DATA_ACCESS_DENIED);
                    }
                    rcb.reserved = Some(Reservation { assoc, linger_secs, until: None });
                } else if rcb.reserved.is_some_and(|r| r.assoc == assoc) {
                    rcb.reserved = None;
                }
                Ok(())
            }
            // `DatSet` is the one setting that changes what every *other* client's cached
            // picture of this block means, so IEC 61850-7-2 §17.2.2 makes it bump `ConfRev`:
            // a client caches the data set's member list against that number, and an
            // inclusion bit string is only readable against the list it was built from.
            // A data set the model has not got is refused rather than stored — a block
            // pointing at a name nothing answers reports nothing and says nothing about why.
            "DatSet" if !(enabled || rcb.owner.is_some_and(|o| o != assoc) || rcb.reserved.is_some_and(|r| r.assoc != assoc)) => {
                let Some(name) = string_of(value) else { return Err(super::ied::DATA_ACCESS_VALUE_INVALID) };
                if ied.data_set(&name).is_none() {
                    return Err(super::ied::DATA_ACCESS_VALUE_INVALID);
                }
                if ied.value(&alloc::format!("{block}$DatSet")).and_then(string_of).as_deref() != Some(name.as_str()) {
                    let conf_rev = ied.value(&alloc::format!("{block}$ConfRev")).and_then(unsigned_of).unwrap_or(0);
                    let _ = ied.set_internal(&alloc::format!("{block}$ConfRev"), Value::Unsigned(u64::from(conf_rev.wrapping_add(1))));
                }
                Ok(())
            }
            // Everything else is a *setting*, and IEC 61850-7-2 §17.2 forbids changing one
            // while the block is enabled. A server that allows it produces reports whose
            // shape changes halfway through a sequence, which is worse than a refusal.
            _ if enabled || rcb.owner.is_some_and(|o| o != assoc) || rcb.reserved.is_some_and(|r| r.assoc != assoc) => Err(DATA_ACCESS_DENIED),
            _ => Ok(()),
        }
    }

    /// An association ended: release everything it held.
    ///
    /// An **unbuffered** block simply stops. A **buffered** one keeps its entries — that is
    /// the whole difference between the two — so the client that comes back can resume after
    /// the `EntryID` it last saw.
    pub fn on_association_closed(&mut self, ied: &mut Ied, assoc: AssocId, now: Instant) {
        self.pdu.remove(&assoc);
        let references: Vec<String> = self.blocks.keys().cloned().collect();
        for reference in references {
            let Some(rcb) = self.blocks.get_mut(&reference) else { continue };
            if rcb.owner == Some(assoc) {
                rcb.owner = None;
                rcb.due = None;
                rcb.pending.clear();
                if !rcb.buffered {
                    rcb.buffer.clear();
                }
                // The engine's `owner` and the model's `RptEna` are two views of one fact, and
                // the model is the one every *client* sees. Leaving it true hands the next
                // client a block that reads as enabled, owned by nobody, and — because
                // `on_write` refuses every setting while `RptEna` is true — impossible to
                // configure without first guessing that it has to be turned off.
                for (attribute, value) in [("RptEna", false), ("GI", false), ("PurgeBuf", false), ("Resv", false)] {
                    if ied.value(&alloc::format!("{reference}${attribute}")).is_some() {
                        let _ = ied.set_internal(&alloc::format!("{reference}${attribute}"), Value::Boolean(value));
                    }
                }
                self.released.push(reference.clone());
            }
            match rcb.reserved {
                // A `ResvTms` reservation outlives the association by the seconds it names,
                // which is the whole reason the attribute is a duration and not a flag.
                Some(Reservation { assoc: held, linger_secs: Some(secs), .. }) if held == assoc => {
                    rcb.reserved = Some(Reservation { assoc, linger_secs: Some(secs), until: Some(now.plus_millis(u64::from(secs) * 1000)) });
                }
                Some(r) if r.assoc == assoc => {
                    rcb.reserved = None;
                    release_reservation(ied, &reference);
                }
                _ => {}
            }
        }
    }

    /// Drop reservations whose linger time has run out, and say so in the model.
    fn expire_reservations(&mut self, ied: &mut Ied, now: Instant) {
        let references: Vec<String> = self.blocks.keys().cloned().collect();
        for reference in references {
            let Some(rcb) = self.blocks.get_mut(&reference) else { continue };
            if rcb.reserved.is_some_and(|r| r.until.is_some_and(|u| now >= u)) {
                rcb.reserved = None;
                release_reservation(ied, &reference);
                self.released.push(reference.clone());
            }
        }
    }

    /// Fold a batch of changes into every block that reports them, and emit what is due.
    pub fn commit(&mut self, ied: &mut Ied, dirty: &BTreeMap<String, TrgOps>, wall: EntryTime, now: Instant) -> Vec<Outgoing> {
        let references: Vec<String> = self.blocks.keys().cloned().collect();
        for reference in &references {
            self.gather(ied, reference, dirty, now);
        }
        self.emit_due(ied, wall, now)
    }

    /// Time passed: send whatever the gathering window or the integrity period has made due.
    pub fn on_timeout(&mut self, ied: &mut Ied, wall: EntryTime, now: Instant) -> Vec<Outgoing> {
        self.expire_reservations(ied, now);
        self.emit_due(ied, wall, now)
    }

    /// When the engine next needs [`Engine::on_timeout`].
    pub fn next_timeout(&self) -> Option<Instant> {
        self.blocks.values().filter_map(|r| min_of(min_of(r.due, r.integrity_due), r.reserved.and_then(|s| s.until))).min()
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

        // A **member** is what a report is granular in, so the triggers of every leaf it
        // covers are folded into one reason code. A data set whose member is a data object
        // reports the object whole, with one inclusion bit and one `ReasonCode`
        // (IEC 61850-8-1 §17.2.2, TISSUE 361 🌐) — reporting its attributes separately would
        // give the client an inclusion bit string of a length its own data-set directory
        // says nothing about.
        let mut hits: Vec<(String, ReasonCode)> = Vec::new();
        for member in &ds.members {
            let mut reason = ReasonCode::NONE;
            for leaf in &member.leaves {
                if let Some(trigger) = dirty.get(leaf) {
                    reason = merge_reason(reason, reason_for(*trigger, trg_ops));
                }
            }
            if !reason.is_empty() {
                hits.push((member.reference.clone(), reason));
            }
        }
        if hits.is_empty() {
            return;
        }
        let Some(rcb) = self.blocks.get_mut(reference) else { return };
        for (member, reason) in hits {
            let slot = rcb.pending.entry(member).or_insert(ReasonCode::NONE);
            *slot = merge_reason(*slot, reason);
        }
        // `BufTm` gathers: the window opens at the first change and everything inside it goes
        // into one report, which is what stops a three-phase trip becoming three reports.
        if rcb.due.is_none() {
            rcb.due = Some(now.plus_millis(u64::from(buf_tm)));
        }
    }

    /// Emit every report whose window has closed or whose integrity period has elapsed.
    fn emit_due(&mut self, ied: &mut Ied, wall: EntryTime, now: Instant) -> Vec<Outgoing> {
        let mut out = Vec::new();
        let references: Vec<String> = self.blocks.keys().cloned().collect();
        for reference in references {
            // A general interrogation is a *write* of `GI = true`, and it is consumed here so
            // that one write produces exactly one report.
            // Only a block somebody has enabled: `on_write` refuses `GI` otherwise, and this
            // is the second half of that rule — a flag left set by an association that has
            // since gone must not produce a report for the next client to enable the block.
            let gi =
                self.blocks.get(&reference).is_some_and(|r| r.owner.is_some()) && ied.value(&alloc::format!("{reference}$GI")).and_then(bool_of) == Some(true);
            if gi {
                let _ = ied.set_internal(&alloc::format!("{reference}$GI"), Value::Boolean(false));
                out.extend(self.build(ied, &reference, Trigger::GeneralInterrogation, wall));
            }
            if ied.value(&alloc::format!("{reference}$PurgeBuf")).and_then(bool_of).unwrap_or(false) {
                let _ = ied.set_internal(&alloc::format!("{reference}$PurgeBuf"), Value::Boolean(false));
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
                let period = integrity_period(ied, &reference);
                if let Some(rcb) = self.blocks.get_mut(&reference) {
                    rcb.integrity_due = period.map(|ms| now.plus_millis(u64::from(ms)));
                }
                out.extend(self.build(ied, &reference, Trigger::Integrity, wall));
            }
            if due.is_some_and(|d| now >= d) {
                out.extend(self.build(ied, &reference, Trigger::Change, wall));
            }
        }
        out
    }

    /// Build one report, buffer it if nobody is listening, and encode it if somebody is.
    ///
    /// The result is a *list* because a report longer than the association's negotiated PDU
    /// is split into segments rather than dropped ([`segments`]).
    fn build(&mut self, ied: &mut Ied, reference: &str, trigger: Trigger, wall: EntryTime) -> Vec<Outgoing> {
        let Some(data_set) = ied.value(&alloc::format!("{reference}$DatSet")).and_then(string_of) else { return Vec::new() };
        let Some(ds) = ied.data_set(&data_set).cloned() else { return Vec::new() };
        let opt_flds = ied.value(&alloc::format!("{reference}$OptFlds")).and_then(OptFlds::from_value).unwrap_or(OptFlds::NONE);
        let rpt_id = ied.value(&alloc::format!("{reference}$RptID")).and_then(string_of).unwrap_or_else(|| String::from(reference));
        let conf_rev = ied.value(&alloc::format!("{reference}$ConfRev")).and_then(unsigned_of).unwrap_or(0);
        let members = ds.references();

        let mut reasons: BTreeMap<String, ReasonCode> = match trigger {
            // A general interrogation and an integrity scan both report *every* member; what
            // differs is the reason code each carries, and a client acts on the difference.
            Trigger::GeneralInterrogation => members.iter().map(|m| (m.clone(), ReasonCode::NONE.with_general_interrogation(true))).collect(),
            Trigger::Integrity => members.iter().map(|m| (m.clone(), ReasonCode::NONE.with_integrity(true))).collect(),
            Trigger::Change => {
                let Some(rcb) = self.blocks.get_mut(reference) else { return Vec::new() };
                rcb.due = None;
                core::mem::take(&mut rcb.pending)
            }
        };
        // A member with no value is not reported at all. Including it would need a
        // placeholder, and a placeholder in a report is a value the client will act on —
        // worse than the member being absent, which the inclusion bit string already says.
        // A member that names a data object is read **whole**, as the structure it is.
        let values: BTreeMap<String, Value> = reasons.keys().filter_map(|m| ied.read_reference(m).map(|v| (m.clone(), v))).collect();
        reasons.retain(|m, _| values.contains_key(m));
        if reasons.is_empty() {
            return Vec::new();
        }
        let entry_time = wall;

        let Some(rcb) = self.blocks.get_mut(reference) else { return Vec::new() };
        let entry_id = rcb.next_entry;
        rcb.next_entry = rcb.next_entry.wrapping_add(1);

        // A buffered block buffers **every** entry, whether or not anyone is listening —
        // which is what makes `EntryID` a position a client can resume from. Keeping only
        // the entries made while nobody was there would leave the last delivered identifier
        // outside the buffer, so a reconnecting client's resume point would look *lost* and
        // it would be sent the whole buffer again. An unbuffered block keeps nothing, which
        // is the whole difference between `BR` and `RP`.
        //
        // A general interrogation is not an event; it is an answer to a request, and
        // buffering it would replay the client's own question to whoever connects next.
        if rcb.buffered && trigger != Trigger::GeneralInterrogation {
            if rcb.buffer.len() >= self.buffer_len {
                rcb.buffer.remove(0);
                rcb.overflowed = true;
            }
            rcb.buffer.push(Buffered { entry_id, at: entry_time, reasons: reasons.clone(), values: values.clone() });
        }

        let Some(assoc) = rcb.owner else { return Vec::new() };

        let overflowed = core::mem::take(&mut rcb.overflowed);
        let buffered = rcb.buffered;
        let seq = rcb.seq;
        rcb.seq = if buffered { seq.wrapping_add(1) % 0x1_0000 } else { seq.wrapping_add(1) % 0x100 };
        // The attribute a client reads back is the `SqNum` of the report it has just been
        // sent, not the one after it — that is the number the report itself carries.
        let _ = ied.set_internal(&alloc::format!("{reference}$SqNum"), Value::Unsigned(u64::from(seq)));
        if buffered {
            let _ = ied.set_internal(&alloc::format!("{reference}$EntryID"), Value::OctetString(entry_id.to_be_bytes().to_vec()));
            let _ = ied.set_internal(&alloc::format!("{reference}$TimeOfEntry"), Value::BinaryTime(entry_time.to_octets().to_vec()));
        }

        let report = assemble(
            &rpt_id,
            opt_flds,
            &members,
            &reasons,
            &values,
            &ReportHeader { seq_num: seq, entry_time, data_set: data_set.clone(), conf_rev, entry_id, buffered, overflowed },
        );
        segments(&report, self.budget(assoc)).into_iter().map(|pdu| Outgoing { assoc, pdu }).collect()
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
///
/// `members` is the data set's member list — one inclusion bit, one value and one
/// `ReasonCode` each. A member that names a data object contributes the whole structure, not
/// its attributes one at a time: the inclusion bit string is as long as the data set's
/// *directory* is, or a client indexing one against the other reads every value at the wrong
/// place (IEC 61850-8-1 §17.2.2, TISSUE 361 🌐).
fn assemble(
    rpt_id: &str,
    opt_flds: OptFlds,
    members: &[String],
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
    // `segmentation` belongs to the **segmenter**, not to the configuration. SCL's `<OptFields>`
    // has the attribute and a file may set it, but a report that fits in one PDU carries no
    // `SubSeqNum` to go with it — and a flag promising a field that is not there is the one
    // thing the decoder may not forgive (D28). [`segments`] sets it on the segments it makes.
    let opt_flds = opt_flds.with_segmentation(false);
    // A member is included only when there is a *value* for it. A placeholder in a report is
    // a number the client will act on, so the inclusion bit string and the entries are built
    // from the same filter rather than from two.
    let included: Vec<usize> = members.iter().enumerate().filter(|(_, m)| reasons.contains_key(*m) && values.contains_key(*m)).map(|(i, _)| i).collect();
    let entries: Vec<ReportEntry> = included
        .iter()
        .filter_map(|i| {
            let member = members.get(*i)?;
            Some(ReportEntry {
                index: *i,
                reference: opt_flds.data_reference().then(|| member.clone()),
                value: values.get(member)?.clone(),
                reason: opt_flds.reason_for_inclusion().then(|| reasons.get(member).copied().unwrap_or(ReasonCode::NONE)),
            })
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
        inclusion: Report::inclusion_for(members.len(), &included),
        entries,
    }
}

/// The smallest PDU the segmenter will aim at.
///
/// A report's header alone — `RptID`, `OptFlds` and whichever of the eight optional fields
/// the block asks for — is a couple of hundred octets, so a budget below this cannot be met
/// by splitting and pretending otherwise would produce a segment per member and still not
/// fit. Peers do not negotiate anything this small; the floor exists so a nonsense
/// `localDetail` cannot turn one report into thousands.
pub const MIN_SEGMENT_BUDGET: usize = 512;

/// Encode `report`, splitting it into segments when it does not fit `budget`.
///
/// IEC 61850-8-1 §17.2.2: a report larger than the negotiated MMS PDU is sent as several
/// `InformationReport`s that share `RptID` and `SqNum`, each with its own `SubSeqNum`, its own
/// inclusion bit string naming only the members *it* carries, and `MoreSegmentsFollow` set on
/// all but the last. Nothing else distinguishes a segment from a whole report, which is why
/// the `segmentation` flag has to be set in the `OptFlds` the segments publish even when the
/// control block's own `OptFlds` does not ask for it: it is the only thing that tells the
/// client's decoder that the two values after `ConfRev` are a segment number and a flag
/// rather than the inclusion bit string (D28).
///
/// The alternative — dropping a report that does not fit — is what this server did before,
/// and it is invisible: no error reaches the client, and the data set simply never reports.
fn segments(report: &Report, budget: usize) -> Vec<Vec<u8>> {
    match encode(report) {
        Ok(whole) if whole.len() <= budget => return alloc::vec![whole],
        // A report with nothing in it cannot be split; if it does not encode at all there is
        // nothing to send and no segmentation would change that.
        _ if report.entries.is_empty() => return Vec::new(),
        _ => {}
    }
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut sub = 0u32;
    while start < report.entries.len() {
        let remaining = report.entries.len() - start;
        // The largest number of entries that still fits, by bisection: `lo` always fits (one
        // entry is emitted whatever its size, because a single member cannot be split) and
        // `hi` is the first count known not to.
        let (mut lo, mut hi) = (1usize, remaining + 1);
        let mut best = encode(&segment(report, start, 1, sub, remaining > 1)).unwrap_or_default();
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            match encode(&segment(report, start, mid, sub, start + mid < report.entries.len())) {
                Ok(bytes) if bytes.len() <= budget => {
                    lo = mid;
                    best = bytes;
                }
                _ => hi = mid,
            }
        }
        if best.is_empty() {
            return out;
        }
        out.push(best);
        start += lo;
        sub = sub.wrapping_add(1);
    }
    out
}

/// One segment: `count` entries from `start`, with the inclusion bits of just those members.
fn segment(report: &Report, start: usize, count: usize, sub: u32, more: bool) -> Report {
    let entries: Vec<ReportEntry> = report.entries.get(start..start + count).unwrap_or_default().to_vec();
    let included: Vec<usize> = entries.iter().map(|e| e.index).collect();
    Report {
        opt_flds: report.opt_flds.with_segmentation(true),
        sub_seq_num: Some(sub),
        more_segments_follow: more,
        inclusion: Report::inclusion_for(inclusion_len(&report.inclusion), &included),
        entries,
        ..report.clone()
    }
}

/// How many members the report's own inclusion bit string describes.
fn inclusion_len((unused, bytes): &(u8, Vec<u8>)) -> usize {
    (bytes.len() * 8).saturating_sub(usize::from(*unused))
}

/// The `variableListName` every IEC 61850 report is reported under.
///
/// A report's `variableAccessSpecification` does **not** name the control block, the data set
/// or the `RptID`: IEC 61850-8-1 maps every `InformationReport` carrying a report onto the
/// VMD-specific name `RPT`, and libiec61850 writes exactly `a1 05 80 03 "RPT"` there
/// (`reporting.c`, `BerEncoder_encodeStringWithTag(0x80, "RPT", …)`) 🌐. What tells a client
/// *which* subscription a report belongs to is the `RptID` inside it, which is why `RptID` is
/// writable — and why the name may not be derived from it: `rptID` is a plain SCL attribute,
/// and a file that sets it to anything but a reference would yield an unparseable
/// `domain-specific` name.
pub const REPORT_LIST_NAME: &str = "RPT";

/// A report as the `unconfirmed-PDU` that carries it.
fn encode(report: &Report) -> crate::common::Result<Vec<u8>> {
    let values = report.to_values()?;
    let encoded: Vec<Vec<u8>> = values.iter().map(|v| Value::encode_all(core::slice::from_ref(v))).collect::<crate::common::Result<_>>()?;
    let mut results = Vec::with_capacity(encoded.len());
    for bytes in &encoded {
        results.push(AccessResult::Success(crate::ber::Cursor::new(bytes).next_required()?));
    }
    Mms::Unconfirmed(Unconfirmed::InformationReport { access: VariableAccess::VariableListName(ObjectName::VmdSpecific(REPORT_LIST_NAME)), results }).to_vec()
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
    pub fn drain_buffer(&mut self, ied: &mut Ied, reference: &str, after: Option<u64>) -> Vec<Outgoing> {
        let Some(rcb) = self.blocks.get_mut(reference) else { return Vec::new() };
        let Some(assoc) = rcb.owner else { return Vec::new() };
        // A client that asks to resume after an `EntryID` the buffer no longer holds has a
        // hole it cannot see. IEC 61850-7-2 §17.2 answers that with `BufOvfl`, which is the
        // only thing that tells "here is everything since you left" from "here is everything
        // I still have" — so a resume point that is gone raises it rather than replaying the
        // buffer as if nothing had been lost.
        let (start, lost) = match after {
            Some(id) => match rcb.buffer.iter().position(|b| b.entry_id == id) {
                Some(i) => (i + 1, false),
                None => (0, true),
            },
            None => (0, false),
        };
        // The entries **stay**. The buffer is a ring the `EntryID` indexes into, not a queue
        // that empties on read: a client that reconnects and asks to resume from an earlier
        // point gets what it asks for, and the ring is bounded by `buffer_len` either way.
        let pending: Vec<Buffered> = rcb.buffer.get(start.min(rcb.buffer.len())..).map(<[Buffered]>::to_vec).unwrap_or_default();
        let overflowed = core::mem::take(&mut rcb.overflowed) || lost;
        let budget = self.budget(assoc);
        let mut out = Vec::new();
        for (n, entry) in pending.iter().enumerate() {
            let Some(rcb) = self.blocks.get_mut(reference) else { break };
            let seq = rcb.seq;
            rcb.seq = seq.wrapping_add(1) % 0x1_0000;
            out.extend(Engine::replay(ied, reference, assoc, entry, n == 0 && overflowed, seq, budget));
        }
        out
    }

    fn replay(ied: &mut Ied, reference: &str, assoc: AssocId, entry: &Buffered, overflowed: bool, seq: u32, budget: usize) -> Vec<Outgoing> {
        let Some(data_set) = ied.value(&alloc::format!("{reference}$DatSet")).and_then(string_of) else { return Vec::new() };
        let Some(ds) = ied.data_set(&data_set).cloned() else { return Vec::new() };
        let opt_flds = ied.value(&alloc::format!("{reference}$OptFlds")).and_then(OptFlds::from_value).unwrap_or(OptFlds::NONE);
        let rpt_id = ied.value(&alloc::format!("{reference}$RptID")).and_then(string_of).unwrap_or_else(|| String::from(reference));
        let conf_rev = ied.value(&alloc::format!("{reference}$ConfRev")).and_then(unsigned_of).unwrap_or(0);
        let _ = ied.set_internal(&alloc::format!("{reference}$SqNum"), Value::Unsigned(u64::from(seq)));
        let _ = ied.set_internal(&alloc::format!("{reference}$EntryID"), Value::OctetString(entry.entry_id.to_be_bytes().to_vec()));
        let _ = ied.set_internal(&alloc::format!("{reference}$TimeOfEntry"), Value::BinaryTime(entry.at.to_octets().to_vec()));
        let report = assemble(
            &rpt_id,
            opt_flds,
            &ds.references(),
            &entry.reasons,
            &entry.values,
            &ReportHeader { seq_num: seq, entry_time: entry.at, data_set: data_set.clone(), conf_rev, entry_id: entry.entry_id, buffered: true, overflowed },
        );
        segments(&report, budget).into_iter().map(|pdu| Outgoing { assoc, pdu }).collect()
    }
}

/// What a block's `TrgOps` makes of a leaf's triggers: the reason it is included, or nothing.
///
/// The **log** engine uses this too. A client that configures a log control block and a report
/// control block with the same `TrgOps` must get the same events in both, and two
/// implementations of "did this change matter" is exactly how they stop agreeing.
pub(crate) fn reason_for(trigger: TrgOps, trg_ops: TrgOps) -> ReasonCode {
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
    reason
}

/// Say in the model that nobody is holding this block any more.
fn release_reservation(ied: &mut Ied, reference: &str) {
    for (attribute, value) in [("Resv", Value::Boolean(false)), ("ResvTms", Value::Integer(0)), ("Owner", Value::OctetString(Vec::new()))] {
        let path = alloc::format!("{reference}${attribute}");
        if ied.value(&path).is_some() {
            let _ = ied.set_internal(&path, value);
        }
    }
}

/// The integrity period of a block, when it has one **and** asks for integrity reports.
///
/// IEC 61850-7-2 §17.2.2 makes `IntgPd` meaningful only while `TrgOps.integrity` is set: the
/// period is how often, and the trigger is whether. A server that scans on the period alone
/// sends a client reports it did not subscribe to, and `ied scl validate` already reports the
/// mismatch as a finding (`FindingCode::ReportTriggers`) — so the engine had better agree with
/// the validator about what the file means.
fn integrity_period(ied: &Ied, block: &str) -> Option<u32> {
    let trg_ops = ied.value(&alloc::format!("{block}$TrgOps")).and_then(TrgOps::from_value).unwrap_or(TrgOps::NONE);
    if !trg_ops.integrity() {
        return None;
    }
    ied.value(&alloc::format!("{block}$IntgPd")).and_then(unsigned_of).filter(|p| *p > 0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::mms::report::ReportEntry;

    fn report(members: usize, value: &Value) -> Report {
        let included: Vec<usize> = (0..members).collect();
        Report {
            rpt_id: String::from("IED1LD0/LLN0$RP$urcb"),
            opt_flds: OptFlds::NONE.with_sequence_number(true).with_data_reference(true).with_reason_for_inclusion(true),
            seq_num: Some(3),
            time_of_entry: None,
            data_set: None,
            buf_ovfl: None,
            entry_id: None,
            conf_rev: None,
            sub_seq_num: None,
            more_segments_follow: false,
            inclusion: Report::inclusion_for(members, &included),
            entries: included
                .iter()
                .map(|i| ReportEntry {
                    index: *i,
                    reference: Some(alloc::format!("IED1LD0/GGIO1$ST$Ind{i}$stVal")),
                    value: value.clone(),
                    reason: Some(ReasonCode::NONE.with_data_change(true)),
                })
                .collect(),
        }
    }

    /// The ordinary case: what fits goes out whole, and what does not is split into pieces
    /// that each fit, share the report's identity and between them carry every member once.
    #[test]
    fn a_report_is_split_only_as_far_as_the_budget_makes_necessary() {
        let r = report(40, &Value::Boolean(true));
        let whole = segments(&r, 60_000);
        assert_eq!(whole.len(), 1, "a report that fits is one PDU");
        assert!(!Report::from_values(&decode(&whole[0])).unwrap().opt_flds.segmentation(), "and claims no segmentation");

        let parts = segments(&r, MIN_SEGMENT_BUDGET);
        assert!(parts.len() > 1, "a report that does not fit is split");
        let mut seen: Vec<usize> = Vec::new();
        for (n, pdu) in parts.iter().enumerate() {
            assert!(pdu.len() <= MIN_SEGMENT_BUDGET, "segment {n} is {} octets", pdu.len());
            let seg = Report::from_values(&decode(pdu)).expect("each segment decodes on its own");
            assert!(seg.opt_flds.segmentation(), "a segment has to say it is one");
            assert_eq!(seg.sub_seq_num, Some(n as u32));
            assert_eq!(seg.more_segments_follow, n + 1 < parts.len());
            assert_eq!(seg.seq_num, r.seq_num, "every segment carries the report's own SqNum");
            seen.extend(seg.entries.iter().map(|e| e.index));
        }
        assert_eq!(seen, (0..40).collect::<Vec<_>>(), "every member exactly once, in order");
    }

    /// A single member larger than the whole budget cannot be split any further. Emitting it
    /// oversized is the honest answer — the alternative is a report the client never hears
    /// about at all, which is what this code was written to stop.
    #[test]
    fn a_member_that_cannot_be_split_is_sent_anyway() {
        let big = Value::OctetString(alloc::vec![0u8; 4096]);
        let parts = segments(&report(3, &big), MIN_SEGMENT_BUDGET);
        assert_eq!(parts.len(), 3, "one segment per member, and no more");
        assert!(parts.iter().all(|p| p.len() > MIN_SEGMENT_BUDGET), "each is over budget because it has to be");
    }

    /// A report with nothing in it is not a report, and no amount of splitting makes it one.
    #[test]
    fn an_empty_report_produces_nothing() {
        assert!(segments(&report(0, &Value::Boolean(true)), 8).is_empty());
    }

    /// The `AccessResult`s of an encoded `InformationReport`, as values.
    fn decode(pdu: &[u8]) -> Vec<Value> {
        let limits = crate::common::Limits::DEFAULT;
        match Mms::parse(pdu, &limits).expect("the segment is an MMS PDU") {
            Mms::Unconfirmed(Unconfirmed::InformationReport { results, .. }) => results
                .iter()
                .map(|r| match r {
                    AccessResult::Success(t) => crate::proto::data::DataView::from_tlv(*t).expect("a value").to_owned(&limits).expect("owned"),
                    AccessResult::Failure(_) => panic!("a report carries no failures"),
                })
                .collect(),
            other => panic!("not an information report: {other:?}"),
        }
    }
}
