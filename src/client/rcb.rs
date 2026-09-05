//! Report control blocks: reading one, configuring it, and turning it on.
//!
//! A report control block is not a service — it is a **structured variable** under the `RP`
//! (unbuffered) or `BR` (buffered) functional constraint, and a client configures reporting
//! by writing its attributes. IEC 61850-7-2 fixes the attributes and IEC 61850-8-1 Tables 37
//! and 39 map them to MMS ✅ (the attribute names from libiec61850's `reporting.c` 🌐).
//!
//! Two rules matter and both are enforced here rather than left to the caller:
//!
//! 1. **`RptEna` is written last.** A server refuses a write to any other attribute while
//!    reporting is enabled, so the settings go in one `Write` and the enable in a second.
//! 2. **Attributes are addressed by name, never by position.** A buffered block has
//!    `PurgeBuf`, `EntryID` and `TimeOfEntry` where an unbuffered one has `Resv`, and
//!    Edition 1 has neither `ResvTms` nor `Owner`. Reading the whole structure and indexing
//!    into it is how a client ends up writing a trigger option into a sequence number.

use alloc::string::String;
use alloc::vec::Vec;

use super::Client;
use crate::common::{EntryTime, Error, Fc, ObjectReference, Result};
use crate::proto::data::{Typed, Value};
use crate::proto::mms::report::{OptFlds, TrgOps};

/// A report control block, as the server currently has it.
///
/// Every field is optional because a server need not have it: the buffered-only attributes
/// are absent from an unbuffered block, and `ResvTms`/`Owner` arrived with Edition 2.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rcb {
    /// The reference this was read from, in MMS form (`IED1LD0/LLN0$RP$urcb01`).
    pub reference: String,
    /// True for a buffered control block (`BR`), false for an unbuffered one (`RP`).
    pub buffered: bool,
    /// `RptID` — what reports from this block call themselves.
    pub rpt_id: Option<String>,
    /// `RptEna` — reporting is on.
    pub rpt_ena: bool,
    /// `DatSet` — the data set being reported, in MMS form.
    pub data_set: Option<String>,
    /// `ConfRev` — the data set's configuration revision.
    pub conf_rev: Option<u32>,
    /// `OptFlds` — which fields the reports will carry.
    pub opt_flds: Option<OptFlds>,
    /// `BufTm` — how long the server may hold events together into one report, in ms.
    pub buf_tm: Option<u32>,
    /// `SqNum` — the report counter.
    pub sq_num: Option<u32>,
    /// `TrgOps` — what causes a report.
    pub trg_ops: Option<TrgOps>,
    /// `IntgPd` — the integrity period in ms, when `TrgOps.integrity` is set.
    pub intg_pd: Option<u32>,
    /// `GI` — writing `true` asks for a general interrogation.
    pub gi: Option<bool>,
    /// `Resv` — unbuffered only: this block is reserved for one client.
    pub resv: Option<bool>,
    /// `PurgeBuf` — buffered only: writing `true` discards the buffer.
    pub purge_buf: Option<bool>,
    /// `EntryID` — buffered only: where the client's reading has got to.
    pub entry_id: Option<Vec<u8>>,
    /// `TimeOfEntry` — buffered only: when that entry was made.
    pub time_of_entry: Option<EntryTime>,
    /// `ResvTms` — buffered only, Edition 2: reservation time in seconds.
    pub resv_tms: Option<i64>,
    /// `Owner` — Edition 2: which client holds the block.
    pub owner: Option<Vec<u8>>,
}

/// What to write into a control block before enabling it.
///
/// Every field is `None` by default, meaning "leave whatever the server has". That matters:
/// a control block engineered in the SCD usually already has the right data set and options,
/// and overwriting them with a client's guesses is how a commissioned report stops matching
/// the engineering file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RcbSettings {
    /// `RptID`.
    pub rpt_id: Option<String>,
    /// `DatSet`, in MMS form (`IED1LD0/LLN0$dsTrip`).
    pub data_set: Option<String>,
    /// `OptFlds`.
    pub opt_flds: Option<OptFlds>,
    /// `TrgOps`.
    pub trg_ops: Option<TrgOps>,
    /// `BufTm`, in milliseconds.
    pub buf_tm: Option<u32>,
    /// `IntgPd`, in milliseconds.
    pub intg_pd: Option<u32>,
    /// `ResvTms`, in seconds (buffered, Edition 2).
    pub resv_tms: Option<i64>,
    /// `EntryID` — resume a buffered block after this entry, which is what makes a
    /// reconnecting client pick up where it left off instead of losing the gap.
    pub entry_id: Option<Vec<u8>>,
}

impl RcbSettings {
    /// Nothing set: enable the block exactly as it was engineered.
    pub fn new() -> RcbSettings {
        RcbSettings::default()
    }

    /// Ask for the fields a client normally wants in every report: the sequence number, the
    /// timestamp, the data set name, the reason for inclusion and the configuration revision.
    #[must_use]
    pub fn with_useful_fields(mut self) -> RcbSettings {
        self.opt_flds = Some(
            OptFlds::NONE
                .with_sequence_number(true)
                .with_report_time_stamp(true)
                .with_data_set_name(true)
                .with_reason_for_inclusion(true)
                .with_conf_revision(true),
        );
        self
    }

    /// Set the trigger options.
    #[must_use]
    pub const fn with_trg_ops(mut self, trg_ops: TrgOps) -> RcbSettings {
        self.trg_ops = Some(trg_ops);
        self
    }

    /// Set the buffer time in milliseconds.
    #[must_use]
    pub const fn with_buf_tm(mut self, ms: u32) -> RcbSettings {
        self.buf_tm = Some(ms);
        self
    }

    /// Set the integrity period in milliseconds. Implies `TrgOps.integrity` at the server,
    /// so set that too if the block does not already have it.
    #[must_use]
    pub const fn with_intg_pd(mut self, ms: u32) -> RcbSettings {
        self.intg_pd = Some(ms);
        self
    }

    /// Resume a buffered control block after this `EntryID`.
    #[must_use]
    pub fn resume_after(mut self, entry_id: Vec<u8>) -> RcbSettings {
        self.entry_id = Some(entry_id);
        self
    }
}

/// The attributes that exist on both kinds of control block.
const COMMON: &[&str] = &["RptID", "RptEna", "DatSet", "ConfRev", "OptFlds", "BufTm", "SqNum", "TrgOps", "IntgPd", "GI", "Owner"];
/// Buffered only.
///
/// **Both spellings of the entry time are asked for.** IEC 61850-7-2 names the attribute
/// `TimeOfEntry`; libiec61850 — which is most of the open-source servers in the field, and a
/// good share of the closed ones — names the MMS component `TimeofEntry`, with a lower-case
/// `o`, consistently 🌐. A client that asks for only one of them gets
/// `object-non-existent` from half the servers it meets and reports a buffered control block
/// with no entry time. Asking for both costs one name in a read that is already
/// multi-variable, and whichever the server has answers. That is the rule this crate applies
/// everywhere — decode like the field, encode like the standard — reaching a name here rather
/// than an encoding.
const BUFFERED: &[&str] = &["PurgeBuf", "EntryID", "TimeOfEntry", "TimeofEntry", "ResvTms"];
/// Unbuffered only.
const UNBUFFERED: &[&str] = &["Resv"];

impl Client {
    /// Read a report control block.
    ///
    /// `reference` is the block, in either spelling — `IED1LD0/LLN0$RP$urcb01`, which carries
    /// its own functional constraint, or `IED1LD0/LLN0.urcb01` with `fc` saying `RP` or `BR`.
    ///
    /// One `Read` fetches every attribute at once: a server answers a multi-variable read
    /// with one result per variable, so the attributes an Edition 1 device does not have come
    /// back as failures beside the ones it does, and neither spoils the other.
    pub fn read_rcb(&mut self, reference: &str, fc: Fc) -> Result<Rcb> {
        let (base, buffered) = rcb_base(reference, fc)?;
        let names: Vec<String> = attribute_names(buffered).map(|a| alloc::format!("{base}${a}")).collect();
        let refs: Vec<(&str, Fc)> = names.iter().map(|n| (n.as_str(), Fc::ST)).collect();
        let values = self.read_many_results(&refs)?;

        let mut rcb = Rcb { reference: base.clone(), buffered, ..Rcb::default() };
        for (attribute, value) in attribute_names(buffered).zip(values) {
            let Ok(v) = value else { continue };
            match attribute {
                "RptID" => rcb.rpt_id = v.as_str().map(String::from),
                "RptEna" => rcb.rpt_ena = v.as_bool().unwrap_or(false),
                "DatSet" => rcb.data_set = v.as_str().map(String::from),
                "ConfRev" => rcb.conf_rev = unsigned(&v),
                "OptFlds" => rcb.opt_flds = OptFlds::from_value(&v),
                "BufTm" => rcb.buf_tm = unsigned(&v),
                "SqNum" => rcb.sq_num = unsigned(&v),
                "TrgOps" => rcb.trg_ops = TrgOps::from_value(&v),
                "IntgPd" => rcb.intg_pd = unsigned(&v),
                "GI" => rcb.gi = v.as_bool(),
                "Resv" => rcb.resv = v.as_bool(),
                "PurgeBuf" => rcb.purge_buf = v.as_bool(),
                "EntryID" => rcb.entry_id = octets(&v),
                // Whichever spelling the server has; the other comes back as a failure and
                // is skipped above, so the first one that answers wins.
                "TimeOfEntry" | "TimeofEntry" => {
                    if let Value::BinaryTime(b) = &v {
                        rcb.time_of_entry = <[u8; 6]>::try_from(b.as_slice()).ok().map(EntryTime::from_octets).or(rcb.time_of_entry);
                    }
                }
                "ResvTms" => rcb.resv_tms = v.as_i64(),
                "Owner" => rcb.owner = octets(&v),
                _ => {}
            }
        }
        if rcb.rpt_id.is_none() && rcb.data_set.is_none() && rcb.opt_flds.is_none() {
            // Nothing at all came back: this is not a control block, or the server hides it.
            return Err(Error::NotFound("report control block"));
        }
        Ok(rcb)
    }

    /// Write settings into a report control block, without enabling it.
    ///
    /// Fails if the block is enabled, because the server would refuse every write and a
    /// caller reading the result attribute by attribute would not necessarily notice.
    pub fn write_rcb(&mut self, reference: &str, fc: Fc, settings: &RcbSettings) -> Result<()> {
        let (base, buffered) = rcb_base(reference, fc)?;
        let writes = settings_writes(&base, buffered, settings);
        if writes.is_empty() {
            return Ok(());
        }
        // The first failure is the answer: a server that refuses one attribute of a control
        // block has refused the configuration, and reporting the rest as successful would
        // leave a caller believing a block is set up when it is half set up.
        self.write_many(&writes)?.into_iter().collect::<Result<Vec<()>>>().map(|_| ())
    }

    /// Configure a report control block and turn it on.
    ///
    /// The settings go out in one `Write` and `RptEna` in a second, in that order, because
    /// IEC 61850-7-2 forbids changing a block's configuration while it is enabled. The block
    /// is read back afterwards, so the caller sees what the server actually accepted rather
    /// than what it was asked for — servers silently clamp `BufTm` and `IntgPd`.
    pub fn enable_rcb(&mut self, reference: &str, fc: Fc, settings: &RcbSettings) -> Result<Rcb> {
        let (base, buffered) = rcb_base(reference, fc)?;
        // A block that is already enabled — by this client or another one — cannot be
        // reconfigured, so it has to be turned off first. That is *taking it over*, so it is
        // done only when there is something to write, and a refusal is reported rather than
        // swallowed: a server that will not let go of a block is exactly what a caller needs
        // to be told about.
        if !settings_writes(&base, buffered, settings).is_empty() && self.read_rcb(&base, fc)?.rpt_ena {
            self.write_one(&alloc::format!("{base}$RptEna"), Value::Boolean(false))?;
        }
        self.write_rcb(&base, fc, settings)?;
        self.write_one(&alloc::format!("{base}$RptEna"), Value::Boolean(true))?;
        let rcb = self.read_rcb(&base, fc)?;
        if !rcb.rpt_ena {
            return Err(Error::InvalidValue("the server accepted the write but did not enable reporting"));
        }
        Ok(rcb)
    }

    /// Turn reporting off.
    pub fn disable_rcb(&mut self, reference: &str, fc: Fc) -> Result<()> {
        let (base, _) = rcb_base(reference, fc)?;
        self.write_one(&alloc::format!("{base}$RptEna"), Value::Boolean(false))
    }

    /// Ask for a general interrogation: one report carrying every member of the data set.
    ///
    /// Only meaningful while the block is enabled and `TrgOps.general_interrogation` is set.
    pub fn general_interrogation(&mut self, reference: &str, fc: Fc) -> Result<()> {
        let (base, _) = rcb_base(reference, fc)?;
        self.write_one(&alloc::format!("{base}$GI"), Value::Boolean(true))
    }

    fn write_one(&mut self, reference: &str, value: Value) -> Result<()> {
        match self.write_many(&[(String::from(reference), value)])?.into_iter().next() {
            Some(r) => r,
            None => Err(Error::InvalidValue("empty Write response")),
        }
    }
}

fn attribute_names(buffered: bool) -> impl Iterator<Item = &'static str> {
    COMMON.iter().chain(if buffered { BUFFERED } else { UNBUFFERED }).copied()
}

fn settings_writes(base: &str, buffered: bool, s: &RcbSettings) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let mut push = |name: &str, v: Value| out.push((alloc::format!("{base}${name}"), v));
    if let Some(v) = &s.rpt_id {
        push("RptID", Value::VisibleString(v.clone()));
    }
    if let Some(v) = &s.data_set {
        push("DatSet", Value::VisibleString(v.clone()));
    }
    if let Some(v) = s.opt_flds {
        push("OptFlds", v.to_value());
    }
    if let Some(v) = s.trg_ops {
        push("TrgOps", v.to_value());
    }
    if let Some(v) = s.buf_tm {
        push("BufTm", Value::Unsigned(u64::from(v)));
    }
    if let Some(v) = s.intg_pd {
        push("IntgPd", Value::Unsigned(u64::from(v)));
    }
    if buffered {
        if let Some(v) = s.resv_tms {
            push("ResvTms", Value::Integer(v));
        }
        if let Some(v) = &s.entry_id {
            push("EntryID", Value::OctetString(v.clone()));
        }
    }
    out
}

/// Normalise a control block reference to `LD/LN$FC$name`, and say whether it is buffered.
fn rcb_base(reference: &str, fc: Fc) -> Result<(String, bool)> {
    let parsed = ObjectReference::parse(reference)?;
    let fc = parsed.fc.unwrap_or(fc);
    if !matches!(fc, Fc::RP | Fc::BR) {
        return Err(Error::InvalidReference("a report control block is under RP or BR"));
    }
    let (domain, item) = parsed.to_mms(fc);
    Ok((alloc::format!("{domain}/{item}"), matches!(fc, Fc::BR)))
}

fn unsigned(v: &Value) -> Option<u32> {
    match v {
        Value::Unsigned(n) => u32::try_from(*n).ok(),
        Value::Integer(i) => u32::try_from(*i).ok(),
        _ => None,
    }
}

fn octets(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::OctetString(b) | Value::BinaryTime(b) => Some(b.clone()),
        Value::VisibleString(s) | Value::MmsString(s) => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_normalises_from_either_spelling() {
        assert_eq!(rcb_base("IED1LD0/LLN0$RP$urcb01", Fc::BR).unwrap(), (String::from("IED1LD0/LLN0$RP$urcb01"), false));
        assert_eq!(rcb_base("IED1LD0/LLN0.urcb01", Fc::RP).unwrap(), (String::from("IED1LD0/LLN0$RP$urcb01"), false));
        assert_eq!(rcb_base("IED1LD0/LLN0.brcb01", Fc::BR).unwrap(), (String::from("IED1LD0/LLN0$BR$brcb01"), true));
        // A reference under any other functional constraint is not a control block, and
        // guessing one would write trigger options into a measurement.
        assert!(rcb_base("IED1LD0/LLN0.urcb01", Fc::ST).is_err());
        assert!(rcb_base("IED1LD0/LLN0$MX$x", Fc::RP).is_err());
    }

    #[test]
    fn a_buffered_block_has_different_attributes_from_an_unbuffered_one() {
        let buffered: Vec<&str> = attribute_names(true).collect();
        let unbuffered: Vec<&str> = attribute_names(false).collect();
        assert!(buffered.contains(&"EntryID") && buffered.contains(&"ResvTms") && buffered.contains(&"PurgeBuf"));
        // Both spellings of the entry time: the standard's and libiec61850's.
        assert!(buffered.contains(&"TimeOfEntry") && buffered.contains(&"TimeofEntry"));
        assert!(!buffered.contains(&"Resv"));
        assert!(unbuffered.contains(&"Resv"));
        assert!(!unbuffered.contains(&"EntryID"));
        // `Owner` is on both, because Edition 2 put it there.
        assert!(buffered.contains(&"Owner") && unbuffered.contains(&"Owner"));
    }

    #[test]
    fn settings_are_written_by_name_and_only_when_set() {
        // The default writes nothing at all: a block engineered in the SCD keeps its
        // engineering, which is the point.
        assert!(settings_writes("LD/LLN0$RP$u", false, &RcbSettings::new()).is_empty());

        let s = RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS).with_buf_tm(100).with_intg_pd(1000);
        let writes = settings_writes("LD/LLN0$RP$u", false, &s);
        let names: Vec<&str> = writes.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["LD/LLN0$RP$u$OptFlds", "LD/LLN0$RP$u$TrgOps", "LD/LLN0$RP$u$BufTm", "LD/LLN0$RP$u$IntgPd"]);

        // The buffered-only settings are dropped on an unbuffered block rather than sent and
        // rejected: an unbuffered block has no `EntryID` to resume from.
        let resumed = RcbSettings::new().resume_after(alloc::vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(settings_writes("LD/LLN0$RP$u", false, &resumed).is_empty());
        assert_eq!(settings_writes("LD/LLN0$BR$b", true, &resumed).len(), 1);
    }
}
