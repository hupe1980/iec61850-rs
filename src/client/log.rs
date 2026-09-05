//! Logs: the log control block, and the two queries that read a log's entries.
//!
//! IEC 61850 has three log services and they map onto two very different MMS things.
//! `GetLCBValues`/`SetLCBValues` and `GetLogStatusValues` are ordinary reads and writes of the
//! **log control block**, a structured variable under the `LG` functional constraint;
//! `QueryLogByTime` and `QueryLogAfterEntry` are the MMS **journal** service `ReadJournal`.
//! Nothing on the wire says so — that is IEC 61850-8-1's mapping, and it is the reason a
//! client that treats a log as "one more control block" gets no entries out of it.
//!
//! The resume pattern is the point of `QueryLogAfterEntry`: a client that has stored the last
//! `EntryID` and `TimeOfEntry` it saw picks up exactly there after a reconnection, so a
//! sequence-of-events log survives a lost association without a gap and without duplicates.

use alloc::string::String;
use alloc::vec::Vec;

use super::Client;
use crate::common::{EntryTime, Error, Fc, ObjectReference, Result};
use crate::proto::data::{DataView, Typed, Value};
use crate::proto::mms::journal::{AfterEntry, TimeOfDay};
use crate::proto::mms::report::TrgOps;
use crate::proto::mms::{ConfirmedRequest, ConfirmedResponse, Mms, ObjectName, ReadJournal};

/// One entry of a log, as the server delivered it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LogEntry {
    /// `EntryID` — what [`Client::query_log_after_entry`] resumes after.
    pub entry_id: Vec<u8>,
    /// When the entry was made.
    pub occurred: EntryTime,
    /// The values it recorded: the data attribute's reference and what it was.
    pub variables: Vec<(String, Value)>,
    /// The text, for an annotation entry.
    pub annotation: Option<String>,
}

impl LogEntry {
    /// The `EntryID` and time to resume after, ready for [`Client::query_log_after_entry`].
    pub fn resume_point(&self) -> (Vec<u8>, EntryTime) {
        (self.entry_id.clone(), self.occurred)
    }
}

/// A page of log entries.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LogPage {
    /// The entries, oldest first.
    pub entries: Vec<LogEntry>,
    /// Whether the server has more to give. Ask again from the last entry's resume point.
    pub more_follows: bool,
}

/// A log control block, as the server currently has it.
///
/// Every field is optional for the same reason a report control block's are: an Edition 1
/// device does not have all of them, and a client that reads the structure positionally
/// writes one attribute's value into another.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lcb {
    /// The reference this was read from, in MMS form (`IED1LD0/LLN0$LG$lcb01`).
    pub reference: String,
    /// `LogEna` — logging is on.
    pub log_ena: bool,
    /// `LogRef` — the log this block writes into, as `LD/LLN0$Log`.
    pub log_ref: Option<String>,
    /// `DatSet` — the data set being logged.
    pub data_set: Option<String>,
    /// `OldEntrTm` — when the oldest entry was made.
    pub old_entry_time: Option<EntryTime>,
    /// `NewEntrTm` — when the newest was.
    pub new_entry_time: Option<EntryTime>,
    /// `OldEnt` — the oldest `EntryID`.
    pub old_entry: Option<Vec<u8>>,
    /// `NewEnt` — the newest `EntryID`.
    pub new_entry: Option<Vec<u8>>,
    /// `TrgOps` — what causes an entry.
    pub trg_ops: Option<TrgOps>,
    /// `IntgPd` — the integrity period in ms.
    pub intg_pd: Option<u32>,
}

impl Lcb {
    /// Where a client with no stored position should start reading: the oldest entry.
    ///
    /// `None` when the log is empty, which is not an error and is worth telling apart from
    /// "the server would not say".
    pub fn oldest(&self) -> Option<(Vec<u8>, EntryTime)> {
        Some((self.old_entry.clone()?, self.old_entry_time?))
    }
}

/// The attributes of a log control block (IEC 61850-7-2 §17).
const LCB_ATTRIBUTES: &[&str] = &["LogEna", "LogRef", "DatSet", "OldEntrTm", "NewEntrTm", "OldEnt", "NewEnt", "TrgOps", "IntgPd"];

impl Client {
    /// Read a log control block — `GetLCBValues` and `GetLogStatusValues` in one round trip.
    ///
    /// The two ACSI services read the same variable; splitting them into two reads would cost
    /// a round trip and buy nothing.
    pub fn read_lcb(&mut self, reference: &str, fc: Fc) -> Result<Lcb> {
        let base = lcb_base(reference, fc)?;
        let names: Vec<String> = LCB_ATTRIBUTES.iter().map(|a| alloc::format!("{base}${a}")).collect();
        let refs: Vec<(&str, Fc)> = names.iter().map(|n| (n.as_str(), Fc::LG)).collect();
        let values = self.read_many_results(&refs)?;
        let mut lcb = Lcb { reference: base, ..Lcb::default() };
        for (attribute, value) in LCB_ATTRIBUTES.iter().zip(values) {
            let Ok(v) = value else { continue };
            match *attribute {
                "LogEna" => lcb.log_ena = v.as_bool().unwrap_or(false),
                "LogRef" => lcb.log_ref = v.as_str().map(String::from),
                "DatSet" => lcb.data_set = v.as_str().map(String::from),
                "OldEntrTm" => lcb.old_entry_time = entry_time(&v),
                "NewEntrTm" => lcb.new_entry_time = entry_time(&v),
                "OldEnt" => lcb.old_entry = octets(&v),
                "NewEnt" => lcb.new_entry = octets(&v),
                "TrgOps" => lcb.trg_ops = TrgOps::from_value(&v),
                "IntgPd" => lcb.intg_pd = v.as_u64().and_then(|n| u32::try_from(n).ok()),
                _ => {}
            }
        }
        if lcb.log_ref.is_none() && lcb.data_set.is_none() && lcb.old_entry.is_none() {
            return Err(Error::NotFound("log control block"));
        }
        Ok(lcb)
    }

    /// Turn logging on or off (`SetLCBValues` for `LogEna`).
    pub fn set_log_enabled(&mut self, reference: &str, fc: Fc, on: bool) -> Result<()> {
        let base = lcb_base(reference, fc)?;
        match self.write_many(&[(alloc::format!("{base}$LogEna"), Value::Boolean(on))])?.into_iter().next() {
            Some(r) => r,
            None => Err(Error::InvalidValue("empty Write response")),
        }
    }

    /// `QueryLogByTime`: every entry between two moments.
    ///
    /// `log` is the log itself — `IED1LD0/LLN0$GeneralLog`, or the `LogRef` an [`Lcb`] gave.
    /// `to` of `None` means "up to now".
    pub fn query_log_by_time(&mut self, log: &str, from: EntryTime, to: Option<EntryTime>) -> Result<LogPage> {
        let (domain, item) = log_name(log)?;
        let name = ObjectName::DomainSpecific { domain: &domain, item: &item };
        self.read_journal(&ReadJournal::by_time(name, TimeOfDay::dated(from), to.map(TimeOfDay::dated)))
    }

    /// `QueryLogAfterEntry`: every entry after the one a client last saw.
    ///
    /// Both halves of the resume point are needed — an `EntryID` is not ordered across a
    /// server restart on its own, which is why the service carries the time beside it.
    /// [`LogEntry::resume_point`] and [`Lcb::oldest`] both produce one.
    pub fn query_log_after_entry(&mut self, log: &str, entry_id: &[u8], time: EntryTime) -> Result<LogPage> {
        let (domain, item) = log_name(log)?;
        let name = ObjectName::DomainSpecific { domain: &domain, item: &item };
        self.read_journal(&ReadJournal::after_entry(name, AfterEntry { time: TimeOfDay::dated(time), entry_id }))
    }

    /// Every entry a log holds, following `moreFollows` to the end.
    ///
    /// `max_entries` bounds what the caller is willing to hold: a station log can be tens of
    /// thousands of entries, and reading all of them into memory should be a decision rather
    /// than a surprise.
    pub fn read_whole_log(&mut self, log: &str, from: EntryTime, max_entries: usize) -> Result<Vec<LogEntry>> {
        let mut out = Vec::new();
        let mut page = self.query_log_by_time(log, from, None)?;
        loop {
            let resume = page.entries.last().map(LogEntry::resume_point);
            out.append(&mut page.entries);
            if !page.more_follows {
                return Ok(out);
            }
            if out.len() >= max_entries {
                return Err(Error::LimitExceeded { limit: "max_entries", value: out.len() });
            }
            // No last entry with `moreFollows` set would loop for ever.
            let Some((entry_id, time)) = resume else { return Ok(out) };
            page = self.query_log_after_entry(log, &entry_id, time)?;
        }
    }

    fn read_journal(&mut self, request: &ReadJournal<'_>) -> Result<LogPage> {
        let pdu = self.call(&ConfirmedRequest::ReadJournal(request.clone()))?;
        let Mms::ConfirmedResponse { service: ConfirmedResponse::ReadJournal { entries, more_follows }, .. } = Mms::parse(&pdu, &self.limits)? else {
            return Err(Error::InvalidValue("not a ReadJournal response"));
        };
        let mut out = Vec::with_capacity(entries.len());
        for e in &entries {
            let mut variables = Vec::with_capacity(e.variables.len());
            for v in &e.variables {
                let value = DataView::from_tlv(v.value)?.to_owned(&self.limits)?;
                variables.push((String::from(v.tag), value));
            }
            out.push(LogEntry { entry_id: e.entry_id.to_vec(), occurred: e.occurred.time, variables, annotation: e.annotation.map(String::from) });
        }
        Ok(LogPage { entries: out, more_follows })
    }
}

/// Split a log reference into the MMS domain and item a journal is named by.
///
/// A log is `LD/LLN0$GeneralLog` on the wire — the logical device is the domain and the rest
/// is the journal name. Either spelling of the reference is accepted, as everywhere else.
fn log_name(log: &str) -> Result<(String, String)> {
    let (ld, rest) = log.split_once('/').ok_or(Error::InvalidReference("a log is `LD/LN$LogName`"))?;
    if ld.is_empty() || rest.is_empty() {
        return Err(Error::InvalidReference("a log is `LD/LN$LogName`"));
    }
    Ok((String::from(ld), rest.replace('.', "$")))
}

/// Normalise a log control block reference to `LD/LN$LG$name`.
fn lcb_base(reference: &str, fc: Fc) -> Result<String> {
    let parsed = ObjectReference::parse(reference)?;
    let fc = parsed.fc.unwrap_or(fc);
    if fc != Fc::LG {
        return Err(Error::InvalidReference("a log control block is under LG"));
    }
    let (domain, item) = parsed.to_mms(fc);
    Ok(alloc::format!("{domain}/{item}"))
}

fn entry_time(v: &Value) -> Option<EntryTime> {
    match v {
        Value::BinaryTime(b) => <[u8; 6]>::try_from(b.as_slice()).ok().map(EntryTime::from_octets),
        Value::UtcTime(t) => Some(EntryTime::from_unix_millis(t.to_unix_nanos() / 1_000_000)),
        _ => None,
    }
}

fn octets(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::OctetString(b) | Value::BinaryTime(b) => Some(b.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_reference_splits_into_the_journal_a_server_knows() {
        assert_eq!(log_name("IED1LD0/LLN0$GeneralLog").unwrap(), (String::from("IED1LD0"), String::from("LLN0$GeneralLog")));
        // The dotted spelling is accepted too, because a `LogRef` may arrive either way.
        assert_eq!(log_name("IED1LD0/LLN0.EventLog").unwrap(), (String::from("IED1LD0"), String::from("LLN0$EventLog")));
        assert!(log_name("nolyslash").is_err());
        assert!(log_name("IED1LD0/").is_err());
    }

    #[test]
    fn a_control_block_reference_must_name_the_log_constraint() {
        assert_eq!(lcb_base("IED1LD0/LLN0$LG$lcb01", Fc::ST).unwrap(), "IED1LD0/LLN0$LG$lcb01");
        assert_eq!(lcb_base("IED1LD0/LLN0.lcb01", Fc::LG).unwrap(), "IED1LD0/LLN0$LG$lcb01");
        // Under any other constraint it is not a log control block, and guessing would read
        // a measurement as one.
        assert!(lcb_base("IED1LD0/LLN0.lcb01", Fc::RP).is_err());
    }
}
