//! IEC 61850 reports: the `InformationReport` a report control block emits, decoded.
//!
//! A report is an MMS `InformationReport` naming the **report control block** and carrying a
//! list of `AccessResult`s that is not a data set — it is a header whose fields are present
//! or absent according to `OptFlds`, followed by an inclusion bit string, then the values of
//! whichever data-set members the bit string says are included. Nothing on the wire separates
//! the header from the values, so a decoder that has not read `OptFlds` cannot tell them apart.
//!
//! ```text
//! RptID, OptFlds, [SqNum], [TimeOfEntry], [DatSet], [BufOvfl], [EntryID], [ConfRev],
//! [SubSeqNum, MoreSegmentsFollow], Inclusion, [DataRef …], Value …, [ReasonCode …]
//! ```
//!
//! Field order is IEC 61850-8-1 Table 40, the flag numbering Table 38 (clause and table
//! verified ✅; the orders themselves from libiec61850's `client_report.c` 🌐). The values are
//! ordinary [`Value`]s — the same type GOOSE carries — so [`Typed`] reads them.
//!
//! [`Typed`]: crate::proto::data::Typed

use alloc::string::String;
use alloc::vec::Vec;

use super::AccessResult;
use crate::common::{DecodeReason, EntryTime, Error, Limits, Result};
use crate::proto::data::{DataView, Typed, Value};

// The three packed option types are IEC 61850-7-2's, not MMS's: the SCL loader and the
// server need them too, so they live in `common` and are re-exported here, where a reader of
// the report codec looks for them.
pub use crate::common::{OptFlds, ReasonCode, TrgOps};

/// One member of a data set, as a report delivered it.
#[derive(Clone, Debug, PartialEq)]
pub struct ReportEntry {
    /// Index of this member in the data set, from the inclusion bit string. A client that
    /// has read the data set's directory can name the member from this alone, which is what
    /// makes `data-reference` optional in the first place.
    pub index: usize,
    /// The `data-reference`, when `OptFlds.data_reference` asked for one.
    pub reference: Option<String>,
    /// The value.
    pub value: Value,
    /// Why it was included, when `OptFlds.reason_for_inclusion` asked.
    pub reason: Option<ReasonCode>,
}

/// A decoded IEC 61850 report.
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    /// `RptID` — what the control block calls itself. Always present.
    pub rpt_id: String,
    /// `OptFlds` — which of the fields below the sender chose to include. Always present.
    pub opt_flds: OptFlds,
    /// `SqNum` — the control block's report counter.
    pub seq_num: Option<u32>,
    /// `TimeOfEntry` — when the entry was created, in MMS `BinaryTime`.
    pub time_of_entry: Option<EntryTime>,
    /// `DatSet` — the data set, in MMS form (`LD/LLN0$dsTrip`).
    pub data_set: Option<String>,
    /// `BufOvfl` — the server dropped entries this client had not read.
    pub buf_ovfl: Option<bool>,
    /// `EntryID` — where to resume a buffered report control block after a reconnection.
    pub entry_id: Option<Vec<u8>>,
    /// `ConfRev` — the data set's configuration revision.
    pub conf_rev: Option<u32>,
    /// `SubSeqNum` — this segment's number, when the report is segmented.
    pub sub_seq_num: Option<u32>,
    /// `MoreSegmentsFollow` — another segment of this report is coming.
    pub more_segments_follow: bool,
    /// The inclusion bit string: one bit per data-set member, most significant bit first.
    /// Kept as `(unused_bits, octets)` so it re-encodes exactly.
    pub inclusion: (u8, Vec<u8>),
    /// The members that were included, in order.
    pub entries: Vec<ReportEntry>,
}

/// How many members the data set has, according to the inclusion bit string.
fn inclusion_len(unused: u8, bytes: &[u8]) -> usize {
    (bytes.len() * 8).saturating_sub(usize::from(unused))
}

fn included_indices(unused: u8, bytes: &[u8]) -> Vec<usize> {
    (0..inclusion_len(unused, bytes)).filter(|i| bytes.get(i / 8).is_some_and(|b| b >> (7 - (i % 8)) & 1 == 1)).collect()
}

impl Report {
    /// Decode a report from the `AccessResult`s of an `InformationReport`.
    ///
    /// Fails when a field the `OptFlds` promised is missing or has the wrong type. That is
    /// deliberately strict: unlike a multicast frame, a report arrives over a connection
    /// where a mismatch means the two ends disagree about the *shape* of every report that
    /// follows, and quietly guessing would misalign every value after the first bad field.
    pub fn parse(results: &[AccessResult<'_>], limits: &Limits) -> Result<Report> {
        let mut values = Vec::with_capacity(results.len());
        for r in results {
            match r {
                AccessResult::Success(t) => values.push(DataView::from_tlv(*t)?.to_owned(limits)?),
                AccessResult::Failure(code) => return Err(Error::DataAccess(*code)),
            }
        }
        Report::from_values(&values)
    }

    /// Decode a report from already-decoded values.
    #[allow(clippy::too_many_lines)] // the field order *is* the specification; splitting it hides it
    pub fn from_values(values: &[Value]) -> Result<Report> {
        let mut at = 0usize;
        let mut next = |what: &'static str| -> Result<&Value> {
            let v = values.get(at).ok_or(Error::NotFound(what))?;
            at += 1;
            Ok(v)
        };

        let rpt_id = String::from(next("RptID")?.as_str().ok_or(Error::InvalidValue("RptID is not a string"))?);
        let opt_flds = OptFlds::from_value(next("OptFlds")?).ok_or(Error::InvalidValue("OptFlds is not a bit string"))?;

        let seq_num = if opt_flds.sequence_number() { Some(unsigned(next("SqNum")?, "SqNum")?) } else { None };
        let time_of_entry = if opt_flds.report_time_stamp() { Some(entry_time(next("TimeOfEntry")?)?) } else { None };
        let data_set =
            if opt_flds.data_set_name() { Some(String::from(next("DatSet")?.as_str().ok_or(Error::InvalidValue("DatSet is not a string"))?)) } else { None };
        let buf_ovfl = if opt_flds.buffer_overflow() { Some(next("BufOvfl")?.as_bool().ok_or(Error::InvalidValue("BufOvfl is not a boolean"))?) } else { None };
        let entry_id = if opt_flds.entry_id() {
            match next("EntryID")? {
                Value::OctetString(b) => Some(b.clone()),
                _ => return Err(Error::InvalidValue("EntryID is not an octet string")),
            }
        } else {
            None
        };
        let conf_rev = if opt_flds.conf_revision() { Some(unsigned(next("ConfRev")?, "ConfRev")?) } else { None };
        let (sub_seq_num, more_segments_follow) = if opt_flds.segmentation() {
            let n = unsigned(next("SubSeqNum")?, "SubSeqNum")?;
            let more = next("MoreSegmentsFollow")?.as_bool().ok_or(Error::InvalidValue("MoreSegmentsFollow is not a boolean"))?;
            (Some(n), more)
        } else {
            (None, false)
        };

        let inclusion = match next("Inclusion")? {
            Value::BitString { unused, bytes } => (*unused, bytes.clone()),
            _ => return Err(Error::InvalidValue("the inclusion field is not a bit string")),
        };
        let indices = included_indices(inclusion.0, &inclusion.1);

        // Every remaining field is one-per-included-member, in three consecutive runs.
        let mut references = Vec::new();
        if opt_flds.data_reference() {
            for _ in &indices {
                references.push(String::from(next("data-reference")?.as_str().ok_or(Error::InvalidValue("a data reference is not a string"))?));
            }
        }
        let mut entry_values = Vec::with_capacity(indices.len());
        for _ in &indices {
            entry_values.push(next("value")?.clone());
        }
        let mut reasons = Vec::new();
        if opt_flds.reason_for_inclusion() {
            for _ in &indices {
                reasons.push(ReasonCode::from_value(next("ReasonCode")?).ok_or(Error::InvalidValue("a reason code is not a bit string"))?);
            }
        }
        if at != values.len() {
            return Err(Error::decode(DecodeReason::TrailingBytes, at));
        }

        let entries = indices
            .into_iter()
            .enumerate()
            .map(|(n, index)| ReportEntry {
                index,
                reference: references.get(n).cloned(),
                value: entry_values.get(n).cloned().unwrap_or(Value::Boolean(false)),
                reason: reasons.get(n).copied(),
            })
            .collect();

        Ok(Report { rpt_id, opt_flds, seq_num, time_of_entry, data_set, buf_ovfl, entry_id, conf_rev, sub_seq_num, more_segments_follow, inclusion, entries })
    }

    /// The values of this report, in the order IEC 61850-8-1 Table 40 puts them.
    ///
    /// The inverse of [`Report::from_values`], and what a server sends. Fields are written
    /// according to `opt_flds`, so a report whose `opt_flds` disagrees with its own fields
    /// is refused here rather than confusing a client.
    pub fn to_values(&self) -> Result<Vec<Value>> {
        let mut out = Vec::with_capacity(6 + self.entries.len() * 3);
        out.push(Value::VisibleString(self.rpt_id.clone()));
        out.push(self.opt_flds.to_value());
        let mut push = |flag: bool, field: &'static str, value: Option<Value>| -> Result<()> {
            match (flag, value) {
                (true, Some(v)) => {
                    out.push(v);
                    Ok(())
                }
                (true, None) => Err(Error::InvalidValue(field)),
                (false, _) => Ok(()),
            }
        };
        push(self.opt_flds.sequence_number(), "OptFlds promises SqNum but the report has none", self.seq_num.map(|n| Value::Unsigned(u64::from(n))))?;
        push(
            self.opt_flds.report_time_stamp(),
            "OptFlds promises TimeOfEntry but the report has none",
            self.time_of_entry.map(|t| Value::BinaryTime(t.to_octets().to_vec())),
        )?;
        push(self.opt_flds.data_set_name(), "OptFlds promises DatSet but the report has none", self.data_set.clone().map(Value::VisibleString))?;
        push(self.opt_flds.buffer_overflow(), "OptFlds promises BufOvfl but the report has none", self.buf_ovfl.map(Value::Boolean))?;
        push(self.opt_flds.entry_id(), "OptFlds promises EntryID but the report has none", self.entry_id.clone().map(Value::OctetString))?;
        push(self.opt_flds.conf_revision(), "OptFlds promises ConfRev but the report has none", self.conf_rev.map(|n| Value::Unsigned(u64::from(n))))?;
        if self.opt_flds.segmentation() {
            let n = self.sub_seq_num.ok_or(Error::InvalidValue("OptFlds promises SubSeqNum but the report has none"))?;
            out.push(Value::Unsigned(u64::from(n)));
            out.push(Value::Boolean(self.more_segments_follow));
        }
        out.push(Value::BitString { unused: self.inclusion.0, bytes: self.inclusion.1.clone() });

        if included_indices(self.inclusion.0, &self.inclusion.1).len() != self.entries.len() {
            return Err(Error::InvalidValue("the inclusion bit string does not match the number of entries"));
        }
        if self.opt_flds.data_reference() {
            for e in &self.entries {
                out.push(Value::VisibleString(e.reference.clone().ok_or(Error::InvalidValue("OptFlds promises data references but an entry has none"))?));
            }
        }
        for e in &self.entries {
            out.push(e.value.clone());
        }
        if self.opt_flds.reason_for_inclusion() {
            for e in &self.entries {
                out.push(e.reason.ok_or(Error::InvalidValue("OptFlds promises reason codes but an entry has none"))?.to_value());
            }
        }
        Ok(out)
    }

    /// Build the inclusion bit string for `total` data-set members of which `included` are
    /// present, so a server does not have to pack bits by hand.
    pub fn inclusion_for(total: usize, included: &[usize]) -> (u8, Vec<u8>) {
        let octets = total.div_ceil(8);
        let mut bytes = alloc::vec![0u8; octets];
        for i in included.iter().filter(|i| **i < total) {
            if let Some(b) = bytes.get_mut(i / 8) {
                *b |= 1 << (7 - (i % 8));
            }
        }
        (((octets * 8) - total) as u8, bytes)
    }

    /// How many members the data set has, as the inclusion bit string reports it.
    pub fn data_set_len(&self) -> usize {
        inclusion_len(self.inclusion.0, &self.inclusion.1)
    }

    /// True when this is one segment of a longer report and more are coming.
    pub const fn is_partial(&self) -> bool {
        self.more_segments_follow
    }
}

/// Joins the segments of a segmented report back into one report.
///
/// A server whose report is larger than the negotiated MMS PDU splits it: each segment
/// carries the same `RptID` and `SqNum`, its own `SubSeqNum`, and an inclusion bit string
/// naming only the members *that segment* carries. `MoreSegmentsFollow` is false on the last
/// one. Nothing else distinguishes them, so a client that ignores segmentation sees a report
/// with a hole in it and no indication that there is one.
///
/// The assembler is sans-IO like everything else: feed it every report, and it hands back the
/// ones that are complete. An unsegmented report passes straight through, so a caller does
/// not have to know which kind it is holding.
///
/// ```
/// # use iec61850_rs::proto::mms::report::{Report, ReportAssembler};
/// # fn handle(_: Report) {}
/// let mut assembler = ReportAssembler::new(8);
/// # let incoming: Vec<Report> = Vec::new();
/// for segment in incoming {
///     if let Some(whole) = assembler.push(segment) {
///         handle(whole);
///     }
/// }
/// ```
#[derive(Debug)]
pub struct ReportAssembler {
    partial: Vec<Pending>,
    capacity: usize,
    max_entries: usize,
    stats: AssemblerStats,
}

/// What an assembler had to throw away.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AssemblerStats {
    /// Reports completed from more than one segment.
    pub reassembled: u64,
    /// Segment runs abandoned because a segment number was skipped or repeated — the report
    /// cannot be rebuilt, and half of one is worse than none.
    pub out_of_order: u64,
    /// Segment runs evicted because too many reports were in flight at once.
    pub evicted: u64,
    /// Segment runs abandoned because one report grew past [`ReportAssembler::max_entries`].
    ///
    /// Bounding the *number* of runs is not the same as bounding the size of one: a peer that
    /// keeps sending segments with `MoreSegmentsFollow` set and an advancing `SubSeqNum`
    /// grows a single run without limit, which is the same defect one layer up from an
    /// unbounded decoder.
    pub oversized: u64,
}

#[derive(Debug)]
struct Pending {
    key: (String, Option<u32>),
    next_sub_seq: u32,
    report: Report,
}

impl ReportAssembler {
    /// An assembler holding at most `capacity` partially-received reports at once, each of at
    /// most [`Limits::DEFAULT`]`.max_dataset_members` entries.
    ///
    /// **Two** bounds, because they stop different things. `capacity` stops a peer that starts
    /// many segment runs and finishes none; `max_entries` stops one that keeps a *single* run
    /// going for ever. A count of runs says nothing about the size of one, and the run is
    /// where the memory actually is.
    ///
    /// One run is enough for a single control block; a handful covers a client subscribed to
    /// several at once. The entry bound is the data set's member count, because a report has
    /// one entry per included member and a data set larger than that is not one this stack
    /// would have created.
    pub fn new(capacity: usize) -> ReportAssembler {
        ReportAssembler::with_max_entries(capacity, Limits::DEFAULT.max_dataset_members)
    }

    /// An assembler with an explicit entry bound, for a data set larger than the default.
    pub fn with_max_entries(capacity: usize, max_entries: usize) -> ReportAssembler {
        ReportAssembler { partial: Vec::new(), capacity: capacity.max(1), max_entries: max_entries.max(1), stats: AssemblerStats::default() }
    }

    /// The largest number of entries one reassembled report may reach.
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// The counters.
    pub const fn stats(&self) -> AssemblerStats {
        self.stats
    }

    /// Partially-received reports being held.
    pub fn pending(&self) -> usize {
        self.partial.len()
    }

    /// Feed one report. Returns the whole report once its last segment arrives.
    ///
    /// An unsegmented report is returned immediately. A segment that does not follow the one
    /// before it abandons the run: `SubSeqNum` is the only thing tying segments together, and
    /// guessing past a gap would silently attribute one member's value to another.
    pub fn push(&mut self, report: Report) -> Option<Report> {
        if !report.opt_flds.segmentation() {
            return Some(report);
        }
        let key = (report.rpt_id.clone(), report.seq_num);
        let sub = report.sub_seq_num.unwrap_or(0);
        let more = report.more_segments_follow;
        match self.partial.iter().position(|p| p.key == key) {
            Some(i) => {
                let expected = self.partial.get(i).map_or(0, |p| p.next_sub_seq);
                if sub != expected {
                    self.partial.swap_remove(i);
                    self.stats.out_of_order = self.stats.out_of_order.saturating_add(1);
                    // The first segment of a *new* run may legitimately arrive right after a
                    // broken one, so it starts a run rather than being dropped with it.
                    return self.start(key, report, sub, more);
                }
                // A run that has grown past the bound is abandoned rather than merged into:
                // half a report is worse than none, and an unbounded one is worse than both.
                let max = self.max_entries;
                let p = self.partial.get_mut(i)?;
                if p.report.entries.len().saturating_add(report.entries.len()) > max {
                    self.partial.swap_remove(i);
                    self.stats.oversized = self.stats.oversized.saturating_add(1);
                    return None;
                }
                let p = self.partial.get_mut(i)?;
                merge(&mut p.report, report);
                p.next_sub_seq = sub.saturating_add(1);
                if more {
                    return None;
                }
                let mut done = self.partial.swap_remove(i).report;
                done.more_segments_follow = false;
                self.stats.reassembled = self.stats.reassembled.saturating_add(1);
                Some(done)
            }
            None => self.start(key, report, sub, more),
        }
    }

    /// Throw away every partially-received report, for a client that has reconnected.
    pub fn clear(&mut self) {
        self.partial.clear();
    }

    fn start(&mut self, key: (String, Option<u32>), report: Report, sub: u32, more: bool) -> Option<Report> {
        if !more {
            // A single segment that says nothing follows is a whole report already.
            return Some(report);
        }
        // A run begins at `SubSeqNum` 0. Beginning one anywhere else would mean rebuilding a
        // report from the middle — the members before the joining point are simply missing,
        // and nothing downstream could tell. It is also what stops a peer from restarting a
        // run indefinitely after each one is abandoned.
        if sub != 0 {
            self.stats.out_of_order = self.stats.out_of_order.saturating_add(1);
            return None;
        }
        if report.entries.len() > self.max_entries {
            self.stats.oversized = self.stats.oversized.saturating_add(1);
            return None;
        }
        if self.partial.len() >= self.capacity {
            self.partial.remove(0);
            self.stats.evicted = self.stats.evicted.saturating_add(1);
        }
        self.partial.push(Pending { key, next_sub_seq: sub.saturating_add(1), report });
        None
    }
}

/// Fold `segment` into `whole`: the entries in index order, the inclusion bits OR-ed.
fn merge(whole: &mut Report, segment: Report) {
    for (a, b) in whole.inclusion.1.iter_mut().zip(&segment.inclusion.1) {
        *a |= *b;
    }
    if segment.inclusion.1.len() > whole.inclusion.1.len() {
        whole.inclusion.1.extend_from_slice(segment.inclusion.1.get(whole.inclusion.1.len()..).unwrap_or(&[]));
        whole.inclusion.0 = segment.inclusion.0;
    }
    whole.entries.extend(segment.entries);
    whole.entries.sort_by_key(|e| e.index);
    whole.sub_seq_num = segment.sub_seq_num;
    // A later segment may carry a `BufOvfl` the first did not.
    if segment.buf_ovfl == Some(true) {
        whole.buf_ovfl = Some(true);
    }
}

fn unsigned(v: &Value, what: &'static str) -> Result<u32> {
    let n = match v {
        Value::Unsigned(n) => *n,
        // A server that writes a counter as a signed integer is out there; the field is
        // unsigned in the standard, and a negative one is genuinely wrong.
        Value::Integer(i) if *i >= 0 => *i as u64,
        _ => return Err(Error::InvalidValue(what)),
    };
    u32::try_from(n).map_err(|_| Error::InvalidValue(what))
}

fn entry_time(v: &Value) -> Result<EntryTime> {
    match v {
        Value::BinaryTime(b) => <[u8; 6]>::try_from(b.as_slice()).map(EntryTime::from_octets).map_err(|_| Error::InvalidValue("TimeOfEntry is not six octets")),
        // Ed1 servers exist that stamp the entry with a UtcTime instead of a BinaryTime.
        Value::UtcTime(t) => Ok(EntryTime::from_unix_millis(t.to_unix_nanos() / 1_000_000)),
        _ => Err(Error::InvalidValue("TimeOfEntry is not a binary time")),
    }
}

#[cfg(test)]
mod tests {
    /// The assembler bounds the number of runs *and* the size of one. A peer that keeps a
    /// single run going — `MoreSegmentsFollow` set for ever, `SubSeqNum` advancing — would
    /// otherwise grow the client's memory without limit, which the run-count bound does not
    /// cover.
    #[test]
    fn one_segment_run_cannot_grow_without_limit() {
        let mut a = ReportAssembler::with_max_entries(4, 8);
        assert_eq!(a.max_entries(), 8);

        let mut fed = 0usize;
        // Twenty segments of two entries each: far past the eight-entry bound.
        for sub in 0..20u32 {
            let base = (sub as usize) * 2;
            assert_eq!(a.push(segment("flood", 7, sub, true, 64, &[base % 64, (base + 1) % 64])), None, "no whole report may escape");
            fed += 2;
        }
        assert!(fed > a.max_entries());
        assert_eq!(a.stats().oversized, 1, "the run is abandoned when it passes the bound");
        assert_eq!(a.pending(), 0, "and nothing is held afterwards: a run restarts only at SubSeqNum 0");
        assert_eq!(a.stats().reassembled, 0);
    }

    /// A single oversized segment is refused before it is ever stored.
    #[test]
    fn an_oversized_first_segment_is_not_stored() {
        let mut a = ReportAssembler::with_max_entries(4, 2);
        assert_eq!(a.push(segment("big", 1, 0, true, 64, &[0, 1, 2, 3])), None);
        assert_eq!(a.pending(), 0);
        assert_eq!(a.stats().oversized, 1);
    }

    use super::*;
    use crate::common::{Quality, TimeQuality, UtcTime};

    fn sample() -> Report {
        let opt_flds = OptFlds::NONE
            .with_sequence_number(true)
            .with_report_time_stamp(true)
            .with_data_set_name(true)
            .with_data_reference(true)
            .with_reason_for_inclusion(true)
            .with_conf_revision(true);
        Report {
            rpt_id: String::from("IED1LD0/LLN0$RP$urcb01"),
            opt_flds,
            seq_num: Some(7),
            time_of_entry: Some(EntryTime::from_unix_millis(1_700_000_000_500)),
            data_set: Some(String::from("IED1LD0/LLN0$dsTrip")),
            buf_ovfl: None,
            entry_id: None,
            conf_rev: Some(3),
            sub_seq_num: None,
            more_segments_follow: false,
            // Four members, of which the first and the last are included.
            inclusion: Report::inclusion_for(4, &[0, 3]),
            entries: alloc::vec![
                ReportEntry {
                    index: 0,
                    reference: Some(String::from("IED1LD0/PTRC1$ST$Tr$general")),
                    value: Value::Boolean(true),
                    reason: Some(ReasonCode::NONE.with_data_change(true)),
                },
                ReportEntry {
                    index: 3,
                    reference: Some(String::from("IED1LD0/PTRC1$ST$Tr$q")),
                    value: Value::quality(Quality::GOOD),
                    reason: Some(ReasonCode::NONE.with_quality_change(true)),
                },
            ],
        }
    }

    #[test]
    fn a_report_round_trips_through_the_order_table_40_defines() {
        let r = sample();
        let values = r.to_values().unwrap();
        // RptID, OptFlds, SqNum, TimeOfEntry, DatSet, ConfRev, inclusion, 2 refs, 2 values,
        // 2 reasons = 13. No BufOvfl, EntryID or segmentation, because OptFlds says so.
        assert_eq!(values.len(), 13, "{values:#?}");
        assert_eq!(Report::from_values(&values).unwrap(), r);
    }

    #[test]
    fn the_option_flags_decide_which_fields_are_on_the_wire() {
        // The same report with nothing optional: RptID, OptFlds, inclusion, two values.
        let mut r = sample();
        r.opt_flds = OptFlds::NONE;
        r.seq_num = None;
        r.time_of_entry = None;
        r.data_set = None;
        r.conf_rev = None;
        for e in &mut r.entries {
            e.reference = None;
            e.reason = None;
        }
        let values = r.to_values().unwrap();
        assert_eq!(values.len(), 5);
        assert_eq!(Report::from_values(&values).unwrap(), r);

        // And a header that promises a field the report does not have is refused rather
        // than emitted short — a client would read the next value as `SqNum`.
        let mut lying = r.clone();
        lying.opt_flds = OptFlds::NONE.with_sequence_number(true);
        assert!(lying.to_values().is_err());
    }

    #[test]
    fn the_inclusion_bit_string_says_which_members_arrived() {
        let r = sample();
        assert_eq!(r.data_set_len(), 4, "the data set has four members");
        assert_eq!(r.entries.iter().map(|e| e.index).collect::<Vec<_>>(), [0, 3]);
        assert_eq!(r.inclusion, (4, alloc::vec![0b1001_0000]));
        // Sixteen members, three included, spans two octets with none unused.
        assert_eq!(Report::inclusion_for(16, &[0, 8, 15]), (0, alloc::vec![0b1000_0000, 0b1000_0001]));
        assert_eq!(Report::inclusion_for(3, &[1]), (5, alloc::vec![0b0100_0000]));
    }

    #[test]
    fn a_segmented_report_carries_its_segment_number() {
        let mut r = sample();
        r.opt_flds = r.opt_flds.with_segmentation(true);
        r.sub_seq_num = Some(2);
        r.more_segments_follow = true;
        let values = r.to_values().unwrap();
        let back = Report::from_values(&values).unwrap();
        assert_eq!((back.sub_seq_num, back.more_segments_follow), (Some(2), true));
        assert!(back.is_partial());
    }

    #[test]
    fn a_report_that_does_not_match_its_own_header_is_an_error_not_a_guess() {
        // Truncated after the inclusion bit string: the values are simply missing.
        let r = sample();
        let mut values = r.to_values().unwrap();
        values.truncate(8);
        assert!(Report::from_values(&values).is_err());
        // Too many values: something is being read as the wrong field, which is worse than
        // an error because every value after it is misattributed.
        let mut extra = r.to_values().unwrap();
        extra.push(Value::Boolean(false));
        assert!(matches!(Report::from_values(&extra), Err(Error::Decode { reason: DecodeReason::TrailingBytes, .. })));
        // A first field of the wrong type.
        assert!(Report::from_values(&[Value::Boolean(true), Value::Boolean(true)]).is_err());
    }

    #[test]
    fn opt_flds_and_trg_ops_pack_the_way_the_tables_number_them() {
        // IEC 61850-8-1 Table 38: bit 0 is reserved, so `sequence-number` is bit 1 — the
        // most significant bit but one of the first octet.
        let (unused, bytes) = OptFlds::NONE.with_sequence_number(true).to_bit_string();
        assert_eq!((unused, bytes.as_slice()), (6, &[0b0100_0000, 0][..]), "ten bits over two octets");
        assert_eq!(OptFlds::from_bit_string(&[0b0100_0000, 0]), OptFlds::NONE.with_sequence_number(true));

        // Segmentation is bit 9: the most significant bit of the second octet but one.
        let (_, seg) = OptFlds::NONE.with_segmentation(true).to_bit_string();
        assert_eq!(seg.as_slice(), &[0, 0b0100_0000]);

        // TrgOps is six bits in one octet: data-change 1 … general-interrogation 5.
        let (unused, bytes) = TrgOps::EVENTS.to_bit_string();
        assert_eq!((unused, bytes.as_slice()), (2, &[0b0110_0100][..]), "data-change 1, quality-change 2, GI 5, MSB first");
        let t = TrgOps::EVENTS;
        assert!(t.data_change() && t.quality_change() && t.general_interrogation());
        assert!(!t.integrity() && !t.data_update());
        assert_eq!(TrgOps::from_bit_string(&bytes), TrgOps::EVENTS);
        assert!(TrgOps::NONE.is_empty());

        // And a round trip through the `Value` a control block is written with.
        assert_eq!(OptFlds::from_value(&OptFlds::NONE.with_entry_id(true).to_value()), Some(OptFlds::NONE.with_entry_id(true)));
        assert_eq!(TrgOps::from_value(&Value::Boolean(true)), None);
    }

    /// `total` members of which `included` are in this segment, carrying `values`.
    fn segment(rpt_id: &str, seq: u32, sub: u32, more: bool, total: usize, included: &[usize]) -> Report {
        Report {
            rpt_id: String::from(rpt_id),
            opt_flds: OptFlds::NONE.with_sequence_number(true).with_segmentation(true),
            seq_num: Some(seq),
            time_of_entry: None,
            data_set: None,
            buf_ovfl: None,
            entry_id: None,
            conf_rev: None,
            sub_seq_num: Some(sub),
            more_segments_follow: more,
            inclusion: Report::inclusion_for(total, included),
            entries: included.iter().map(|i| ReportEntry { index: *i, reference: None, value: Value::Unsigned(*i as u64), reason: None }).collect(),
        }
    }

    #[test]
    fn the_segments_of_one_report_are_joined_into_it() {
        let mut a = ReportAssembler::new(4);
        // Four members over three segments, the last one saying nothing more follows.
        assert!(a.push(segment("u1", 7, 0, true, 4, &[0])).is_none());
        assert_eq!(a.pending(), 1);
        assert!(a.push(segment("u1", 7, 1, true, 4, &[1, 2])).is_none());
        let whole = a.push(segment("u1", 7, 2, false, 4, &[3])).expect("the last segment completes it");
        assert_eq!(whole.entries.iter().map(|e| e.index).collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert_eq!(whole.data_set_len(), 4);
        assert_eq!(whole.inclusion, Report::inclusion_for(4, &[0, 1, 2, 3]), "the inclusion bits are the union of the segments'");
        assert!(!whole.is_partial());
        assert_eq!(a.pending(), 0);
        assert_eq!(a.stats().reassembled, 1);
        // And the joined report is a well-formed report: it re-encodes.
        assert_eq!(Report::from_values(&whole.to_values().unwrap()).unwrap().entries.len(), 4);
    }

    #[test]
    fn an_unsegmented_report_passes_straight_through() {
        let mut a = ReportAssembler::new(4);
        let r = sample();
        assert_eq!(a.push(r.clone()), Some(r));
        assert_eq!(a.pending(), 0);
        // So does a segmented one that is its own last segment.
        let single = segment("u1", 1, 0, false, 2, &[0, 1]);
        assert_eq!(a.push(single.clone()), Some(single));
        assert_eq!(a.stats().reassembled, 0, "nothing was reassembled — nothing was split");
    }

    #[test]
    fn a_missing_segment_abandons_the_run_rather_than_inventing_the_hole() {
        // `SubSeqNum` is the only thing tying segments together. Skipping one and carrying on
        // would put the third segment's values at the second's indices, which is a report
        // that decodes and lies.
        let mut a = ReportAssembler::new(4);
        assert!(a.push(segment("u1", 7, 0, true, 4, &[0])).is_none());
        assert!(a.push(segment("u1", 7, 2, true, 4, &[2])).is_none(), "segment 1 never arrived");
        // Both the broken run *and* the segment that broke it are dropped. Keeping the
        // latter as the start of a fresh run is the very failure this test is named for:
        // segment 2 is the middle of a report, so a run begun there is missing members 0 and
        // 1 with nothing downstream able to tell. A run starts at `SubSeqNum` 0 or not at all.
        assert_eq!(a.stats().out_of_order, 2);
        assert_eq!(a.pending(), 0);
        // A genuinely new report *does* start a run, because its first segment is numbered 0.
        assert!(a.push(segment("u1", 8, 0, true, 4, &[0])).is_none());
        assert_eq!(a.pending(), 1);
        // Two reports in flight at once are told apart by their `SqNum`.
        let mut b = ReportAssembler::new(4);
        assert!(b.push(segment("u1", 1, 0, true, 2, &[0])).is_none());
        assert!(b.push(segment("u1", 2, 0, true, 2, &[0])).is_none());
        assert_eq!(b.pending(), 2);
        let first = b.push(segment("u1", 1, 1, false, 2, &[1])).expect("report 1 completes");
        assert_eq!(first.seq_num, Some(1));
        assert_eq!(b.pending(), 1);
    }

    #[test]
    fn a_server_that_never_finishes_a_report_cannot_grow_a_clients_memory() {
        let mut a = ReportAssembler::new(2);
        for seq in 0..10 {
            assert!(a.push(segment("u1", seq, 0, true, 2, &[0])).is_none());
        }
        assert_eq!(a.pending(), 2);
        assert_eq!(a.stats().evicted, 8);
        a.clear();
        assert_eq!(a.pending(), 0);
    }

    #[test]
    fn an_ed1_server_that_stamps_a_utc_time_is_still_understood() {
        // The field is a six-octet BinaryTime, but Ed1 devices exist that send a UtcTime.
        // Decoding is lenient here and encoding is not — the same rule the process bus uses.
        let mut values = sample().to_values().unwrap();
        values[3] = Value::UtcTime(UtcTime::from_unix(1_700_000_000, 500_000_000, TimeQuality::SYNCHRONIZED));
        let back = Report::from_values(&values).unwrap();
        assert_eq!(back.time_of_entry, Some(EntryTime::from_unix_millis(1_700_000_000_500)));
        assert!(matches!(back.to_values().unwrap()[3], Value::BinaryTime(_)), "and it goes back out as the standard's type");
    }
}
