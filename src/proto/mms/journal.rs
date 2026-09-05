//! MMS journals — what IEC 61850 calls **logs**.
//!
//! `QueryLogByTime`, `QueryLogAfterEntry` and the log's own entries map onto the single MMS
//! `ReadJournal` service; the log control block (`LCB`) is an ordinary structured variable
//! under the `LG` functional constraint and is read with `Read` like any other.
//!
//! ```text
//! ReadJournal-Request ::= SEQUENCE {
//!   journalName            [0] ObjectName,
//!   rangeStartSpecification [1] CHOICE { startingTime [0] TimeOfDay, startingEntry [1] OCTET STRING } OPTIONAL,
//!   rangeStopSpecification  [2] CHOICE { endingTime   [0] TimeOfDay, numberOfEntries [1] Integer32 } OPTIONAL,
//!   listOfVariables        [4] SEQUENCE OF VisibleString OPTIONAL,
//!   entryToStartAfter      [5] SEQUENCE { timeSpecification [0] TimeOfDay, entrySpecification [1] OCTET STRING } }
//!
//! JournalEntry ::= SEQUENCE { entryIdentifier [0] OCTET STRING,
//!                             originatingApplication [1] ApplicationReference,
//!                             entryContent [2] EntryContent }
//! EntryContent ::= SEQUENCE { occurenceTime [0] TimeOfDay, additionalDetail [1] OPTIONAL,
//!                             entryForm CHOICE { data [2] { event [0] OPTIONAL, listOfVariables [1] OPTIONAL },
//!                                                annotation [3] VisibleString } }
//! ```
//!
//! Structures from ISO 9506-2 as `../specs/asn1-wireshark/mms.asn` states them ✅; that
//! `entryToStartAfter` is the field IEC 61850's `QueryLogAfterEntry` uses, and that a log
//! entry's variables are `(tag, Data)` pairs where the tag is the data attribute's reference,
//! from libiec61850's `mms_client_journals.c` 🌐.

use alloc::vec::Vec;

use crate::ber::{Encoder, Tag, Tlv, universal};
use crate::common::{DecodeReason, EntryTime, Error, Limits, Result};
use crate::proto::data::DataView;

/// An MMS `TimeOfDay`, which is `BinaryTime` in either of its two widths.
///
/// Four octets are milliseconds since midnight with no date; six add the day count since
/// 1984-01-01. Both are on the wire — the same servers that stamp a report's `TimeOfEntry`
/// with six octets stamp a journal entry with four — and the width is kept so a decoded
/// entry re-encodes as it arrived.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeOfDay {
    /// The time itself. A four-octet value has `days_since_1984 == 0`.
    pub time: EntryTime,
    /// True when the wire form carried the day count.
    pub dated: bool,
}

impl TimeOfDay {
    /// A dated (six-octet) time.
    pub const fn dated(time: EntryTime) -> TimeOfDay {
        TimeOfDay { time, dated: true }
    }

    /// From Unix milliseconds, as the six-octet form.
    pub const fn from_unix_millis(millis: u64) -> TimeOfDay {
        TimeOfDay::dated(EntryTime::from_unix_millis(millis))
    }

    /// Decode from the contents octets of a `TimeOfDay`.
    pub fn from_octets(bytes: &[u8]) -> Result<TimeOfDay> {
        match bytes {
            [a, b, c, d] => Ok(TimeOfDay { time: EntryTime { millis_of_day: u32::from_be_bytes([*a, *b, *c, *d]), days_since_1984: 0 }, dated: false }),
            _ if bytes.len() == 6 => {
                let six = <[u8; 6]>::try_from(bytes).map_err(|_| Error::decode(DecodeReason::BadValue, 0))?;
                Ok(TimeOfDay::dated(EntryTime::from_octets(six)))
            }
            _ => Err(Error::decode(DecodeReason::BadValue, 0)),
        }
    }

    /// The wire octets: four when undated, six when dated.
    pub fn to_octets(self) -> Vec<u8> {
        let six = self.time.to_octets();
        if self.dated { six.to_vec() } else { six.get(..4).unwrap_or(&six).to_vec() }
    }
}

/// Where a `ReadJournal` should start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeStart<'a> {
    /// `startingTime [0]` — every entry from this moment on. IEC 61850's `QueryLogByTime`.
    Time(TimeOfDay),
    /// `startingEntry [1]` — every entry from this `EntryID` on.
    Entry(&'a [u8]),
}

/// Where a `ReadJournal` should stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeStop {
    /// `endingTime [0]`.
    Time(TimeOfDay),
    /// `numberOfEntries [1]`.
    Count(i32),
}

/// The entry a `QueryLogAfterEntry` resumes after: an `EntryID` and the time it was made.
///
/// Both are needed — the `EntryID` alone is not ordered across a server restart, which is why
/// IEC 61850's `QueryLogAfterEntry` carries `TimeOfEntry` beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AfterEntry<'a> {
    /// `timeSpecification`.
    pub time: TimeOfDay,
    /// `entrySpecification` — the `EntryID`.
    pub entry_id: &'a [u8],
}

/// One value inside a journal entry: the reference of a data attribute and what it was.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct JournalVariable<'a> {
    /// `variableTag` — the data attribute's reference, in MMS form.
    pub tag: &'a str,
    /// `valueSpecification`, kept as the encoded element so it re-encodes exactly;
    /// [`DataView::from_tlv`] decodes it and parsing has already checked that it will.
    pub value: Tlv<'a>,
}

impl<'a> JournalVariable<'a> {
    /// The value, decoded.
    pub fn value(&self) -> Option<DataView<'a>> {
        DataView::from_tlv(self.value).ok()
    }
}

/// One entry of a log.
#[derive(Clone, Debug, PartialEq)]
pub struct JournalEntry<'a> {
    /// `entryIdentifier` — the `EntryID` a client resumes after.
    pub entry_id: &'a [u8],
    /// `occurenceTime` — when the entry was made.
    pub occurred: TimeOfDay,
    /// The values the entry recorded. Empty for an annotation-only entry.
    pub variables: Vec<JournalVariable<'a>>,
    /// `annotation`, for the entries that carry text instead of values.
    pub annotation: Option<&'a str>,
    /// `originatingApplication`, kept encoded — nothing in IEC 61850 reads it, and dropping
    /// it would stop the entry re-encoding as it arrived.
    origin: Option<Tlv<'a>>,
}

const TAG_SEQUENCE: Tag = Tag::universal(universal::SEQUENCE, true);

impl<'a> JournalEntry<'a> {
    /// An entry recording values.
    pub fn new(entry_id: &'a [u8], occurred: TimeOfDay, variables: Vec<JournalVariable<'a>>) -> JournalEntry<'a> {
        JournalEntry { entry_id, occurred, variables, annotation: None, origin: None }
    }

    /// An entry recording text instead of values.
    pub fn annotated(entry_id: &'a [u8], occurred: TimeOfDay, annotation: &'a str) -> JournalEntry<'a> {
        JournalEntry { entry_id, occurred, variables: Vec::new(), annotation: Some(annotation), origin: None }
    }

    pub(super) fn parse(t: &Tlv<'a>, limits: &Limits) -> Result<JournalEntry<'a>> {
        let mut c = t.expect(TAG_SEQUENCE)?.children();
        let entry_id = c.next_tag(Tag::context(0))?.value;
        if entry_id.len() > limits.max_primitive_len {
            return Err(Error::LimitExceeded { limit: "max_primitive_len", value: entry_id.len() });
        }
        let origin = c.next_if_tag(Tag::context_constructed(1))?;
        let content = c.next_tag(Tag::context_constructed(2))?;
        let mut cc = content.children();
        let occurred = TimeOfDay::from_octets(cc.next_tag(Tag::context(0))?.value)?;
        // `additionalDetail [1]` "shall be omitted from the abstract syntax defined in this
        // standard", so it is skipped rather than modelled.
        let _ = cc.next_if_tag(Tag::context_constructed(1))?;
        let mut variables = Vec::new();
        let mut annotation = None;
        match cc.next_required() {
            Ok(form) if form.tag == Tag::context_constructed(2) => {
                let mut f = form.children();
                // `event [0]` is an event-condition name and a state; IEC 61850 logs do not
                // use it, and it is skipped rather than guessed at.
                let _ = f.next_if_tag(Tag::context_constructed(0))?;
                if let Some(list) = f.next_if_tag(Tag::context_constructed(1))? {
                    for v in list.children() {
                        if variables.len() >= limits.max_dataset_members {
                            return Err(Error::LimitExceeded { limit: "max_dataset_members", value: variables.len() + 1 });
                        }
                        let mut m = v?.expect(TAG_SEQUENCE)?.children();
                        let tag = m.next_tag(Tag::context(0))?.visible_string()?;
                        let value = m.next_tag(Tag::context_constructed(1))?.children().next_required()?;
                        DataView::from_tlv(value)?;
                        variables.push(JournalVariable { tag, value });
                    }
                }
            }
            Ok(form) if form.tag == Tag::context(3) => annotation = Some(form.visible_string()?),
            Ok(form) => return Err(Error::decode(DecodeReason::UnexpectedTag, form.offset)),
            Err(e) => return Err(e),
        }
        Ok(JournalEntry { entry_id, occurred, variables, annotation, origin })
    }

    pub(super) fn write(&self, e: &mut Encoder) -> Result<()> {
        e.constructed(TAG_SEQUENCE, |e| {
            e.primitive(Tag::context(0), self.entry_id)?;
            if let Some(o) = self.origin {
                e.primitive(o.tag, o.value)?;
            }
            e.constructed(Tag::context_constructed(2), |e| {
                e.primitive(Tag::context(0), &self.occurred.to_octets())?;
                match self.annotation {
                    Some(a) => {
                        e.visible_string(Tag::context(3), a)?;
                    }
                    None => {
                        e.constructed(Tag::context_constructed(2), |e| {
                            e.constructed(Tag::context_constructed(1), |e| {
                                for v in &self.variables {
                                    e.constructed(TAG_SEQUENCE, |e| {
                                        e.visible_string(Tag::context(0), v.tag)?;
                                        e.constructed(Tag::context_constructed(1), |e| {
                                            e.primitive(v.value.tag, v.value.value)?;
                                            Ok(())
                                        })?;
                                        Ok(())
                                    })?;
                                }
                                Ok(())
                            })?;
                            Ok(())
                        })?;
                    }
                }
                Ok(())
            })?;
            Ok(())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_of_day_keeps_the_width_it_arrived_in() {
        let dated = TimeOfDay::from_unix_millis(1_700_000_000_500);
        assert!(dated.dated);
        assert_eq!(dated.to_octets().len(), 6);
        assert_eq!(TimeOfDay::from_octets(&dated.to_octets()).unwrap(), dated);

        // A server that stamps four octets says only the time of day, and re-encoding it as
        // six would invent a date it never sent.
        let plain = TimeOfDay::from_octets(&[0, 0, 0x27, 0x10]).unwrap();
        assert!(!plain.dated);
        assert_eq!(plain.time.millis_of_day, 10_000);
        assert_eq!(plain.to_octets(), [0, 0, 0x27, 0x10]);
        assert!(TimeOfDay::from_octets(&[0, 0, 0]).is_err());
    }
}
