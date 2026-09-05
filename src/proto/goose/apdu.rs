use alloc::string::String;
use alloc::vec::Vec;

use crate::ber::{Cursor, Encoder, Tag};
use crate::common::{Limits, Result, UtcTime};
use crate::proto::data::{self, DataView, Value};

/// `goosePdu [APPLICATION 1]`.
pub const TAG_GOOSE_PDU: Tag = Tag::application_constructed(1);

/// A zero-copy view of a decoded `goosePdu`.
///
/// Field tags per IEC 61850-8-1 (verified against Wireshark's `goose.asn`): `gocbRef [0]`,
/// `timeAllowedtoLive [1]`, `datSet [2]`, `goID [3]`, `t [4]`, `stNum [5]`, `sqNum [6]`,
/// `simulation [7]` (`test` in Ed1), `confRev [8]`, `ndsCom [9]`, `numDatSetEntries [10]`,
/// `allData [11]`, `security [12]` OPTIONAL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoosePduView<'a> {
    /// `gocbRef`.
    pub gocb_ref: &'a str,
    /// `timeAllowedtoLive` in milliseconds.
    pub time_allowed_to_live: u32,
    /// `datSet`.
    pub dat_set: &'a str,
    /// `goID`, if present.
    pub go_id: Option<&'a str>,
    /// `t` — the time of the last state change, as the publisher stamped it.
    pub t: UtcTime,
    /// `stNum`.
    pub st_num: u32,
    /// `sqNum`.
    pub sq_num: u32,
    /// `simulation` (Ed2) / `test` (Ed1).
    pub simulation: bool,
    /// `confRev`.
    pub conf_rev: u32,
    /// `ndsCom`.
    pub nds_com: bool,
    /// `numDatSetEntries` as the publisher declared it. Compare with the members actually
    /// present using [`GoosePduView::member_count_matches`].
    pub num_dat_set_entries: u32,
    /// The `allData` element. Its contents are the encoded data-set members; keeping the
    /// element rather than the contents is what makes decode errors inside it report an
    /// offset in the APDU rather than in an anonymous sub-slice.
    all_data: crate::ber::Tlv<'a>,
    /// `security`, raw, if present (IEC 62351-6).
    pub security: Option<&'a [u8]>,
    /// The whole APDU, which is what a message authentication code is computed over.
    pub raw: &'a [u8],
}

impl<'a> GoosePduView<'a> {
    /// Decode a GOOSE APDU (the bytes after the 8-octet link-layer header).
    pub fn parse(apdu: &'a [u8]) -> Result<GoosePduView<'a>> {
        let pdu = Cursor::new(apdu).next_tag(TAG_GOOSE_PDU)?;
        let mut c = pdu.children();
        let gocb_ref = c.next_tag(Tag::context(0))?.visible_string()?;
        let time_allowed_to_live = c.next_tag(Tag::context(1))?.unsigned_lenient_u32()?;
        let dat_set = c.next_tag(Tag::context(2))?.visible_string()?;
        let go_id = c.next_if_tag(Tag::context(3))?.map(|t| t.visible_string()).transpose()?;
        let t = c.next_tag(Tag::context(4))?.utc_time()?;
        let st_num = c.next_tag(Tag::context(5))?.unsigned_lenient_u32()?;
        let sq_num = c.next_tag(Tag::context(6))?.unsigned_lenient_u32()?;
        // `simulation [7]` and `ndsCom [9]` are `DEFAULT FALSE`, so BER permits a publisher
        // to omit them. Everything we have a capture of writes them, but a conforming
        // publisher need not, and refusing such a frame would be refusing valid GOOSE.
        let simulation = c.next_if_tag(Tag::context(7))?.map(|t| t.boolean()).transpose()?.unwrap_or(false);
        let conf_rev = c.next_tag(Tag::context(8))?.unsigned_lenient_u32()?;
        let nds_com = c.next_if_tag(Tag::context(9))?.map(|t| t.boolean()).transpose()?.unwrap_or(false);
        let num_dat_set_entries = c.next_tag(Tag::context(10))?.unsigned_lenient_u32()?;
        let all_data = c.next_tag(Tag::context_constructed(11))?;
        // `security [12]` is `ANY`, which cannot be implicitly tagged: the IEC 62351-6
        // extension arrives constructed. Accept the primitive spelling too rather than
        // failing on a publisher that chose it.
        let security = match c.next_if_tag(Tag::context_constructed(12))? {
            Some(t) => Some(t.value),
            None => c.next_if_tag(Tag::context(12))?.map(|t| t.value),
        };
        c.finish()?;
        Ok(GoosePduView {
            gocb_ref,
            time_allowed_to_live,
            dat_set,
            go_id,
            t,
            st_num,
            sq_num,
            simulation,
            conf_rev,
            nds_com,
            num_dat_set_entries,
            all_data,
            security,
            raw: apdu.get(..pdu.total_len()).unwrap_or(apdu),
        })
    }

    /// The encoded members of `allData`, back to back.
    pub fn all_data_bytes(&self) -> &'a [u8] {
        self.all_data.value
    }

    /// Iterate over the `allData` members as borrowed views; nothing is allocated.
    pub fn all_data(&self) -> impl Iterator<Item = Result<DataView<'a>>> {
        self.all_data.children().map(|r| r.and_then(DataView::from_tlv))
    }

    /// Decode `allData` into owned values, enforcing `limits`.
    pub fn all_data_owned(&self, limits: &Limits) -> Result<Vec<Value>> {
        data::collect(self.all_data.children(), limits)
    }

    /// Number of `allData` members actually present, or `None` if they do not decode.
    pub fn member_count(&self) -> Option<usize> {
        let mut n = 0;
        for t in self.all_data.children() {
            t.ok()?;
            n += 1;
        }
        Some(n)
    }

    /// True when `numDatSetEntries` agrees with the members present. A publisher whose
    /// count disagrees is either misconfigured or the frame was tampered with, and a
    /// subscriber must not use it.
    pub fn member_count_matches(&self) -> bool {
        self.member_count() == Some(self.num_dat_set_entries as usize)
    }
}

/// The owned, encodable form of a `goosePdu`.
#[derive(Clone, Debug, PartialEq)]
pub struct GoosePdu {
    /// `gocbRef`.
    pub gocb_ref: String,
    /// `timeAllowedtoLive` in milliseconds.
    pub time_allowed_to_live: u32,
    /// `datSet`.
    pub dat_set: String,
    /// `goID`.
    pub go_id: Option<String>,
    /// `t`.
    pub t: UtcTime,
    /// `stNum`.
    pub st_num: u32,
    /// `sqNum`.
    pub sq_num: u32,
    /// `simulation`.
    pub simulation: bool,
    /// `confRev`.
    pub conf_rev: u32,
    /// `ndsCom`.
    pub nds_com: bool,
    /// The data set members.
    pub all_data: Vec<Value>,
}

/// Everything in a `goosePdu` except the data set — what the publisher varies per frame.
///
/// Splitting it out is what lets the publisher keep one encoded `allData` body and re-encode
/// only the short header, without a second copy of the encoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GooseHeader<'a> {
    /// `gocbRef`.
    pub gocb_ref: &'a str,
    /// `timeAllowedtoLive` in milliseconds.
    pub time_allowed_to_live: u32,
    /// `datSet`.
    pub dat_set: &'a str,
    /// `goID`.
    pub go_id: Option<&'a str>,
    /// `t`.
    pub t: UtcTime,
    /// `stNum`.
    pub st_num: u32,
    /// `sqNum`.
    pub sq_num: u32,
    /// `simulation`.
    pub simulation: bool,
    /// `confRev`.
    pub conf_rev: u32,
    /// `ndsCom`.
    pub nds_com: bool,
    /// `numDatSetEntries` — the number of members in `all_data_body`.
    pub num_dat_set_entries: u32,
}

/// Encode a `goosePdu` from a header and an already-encoded `allData` body into `out`.
///
/// This is the single GOOSE encoder: [`GoosePdu::encode`] encodes its members and calls it.
///
/// `simulation` and `ndsCom` are always written, even when false. BER would allow omitting
/// them (they are `DEFAULT FALSE`) but every publisher in the field writes them, and a
/// subscriber that does not implement the default is more likely than one that trips over
/// an explicit `FALSE`. The decoder accepts both.
pub fn encode_into(header: &GooseHeader<'_>, all_data_body: &[u8], out: &mut Encoder) -> Result<()> {
    out.constructed(TAG_GOOSE_PDU, |e| {
        e.visible_string(Tag::context(0), header.gocb_ref)?;
        e.unsigned(Tag::context(1), u64::from(header.time_allowed_to_live))?;
        e.visible_string(Tag::context(2), header.dat_set)?;
        if let Some(id) = header.go_id {
            e.visible_string(Tag::context(3), id)?;
        }
        e.utc_time(Tag::context(4), header.t)?;
        e.unsigned(Tag::context(5), u64::from(header.st_num))?;
        e.unsigned(Tag::context(6), u64::from(header.sq_num))?;
        e.boolean(Tag::context(7), header.simulation)?;
        e.unsigned(Tag::context(8), u64::from(header.conf_rev))?;
        e.boolean(Tag::context(9), header.nds_com)?;
        e.unsigned(Tag::context(10), u64::from(header.num_dat_set_entries))?;
        e.constructed(Tag::context_constructed(11), |e| {
            e.raw(all_data_body);
            Ok(())
        })?;
        Ok(())
    })?;
    Ok(())
}

impl GoosePdu {
    /// The header of this PDU, borrowing its strings.
    pub fn header(&self) -> GooseHeader<'_> {
        GooseHeader {
            gocb_ref: &self.gocb_ref,
            time_allowed_to_live: self.time_allowed_to_live,
            dat_set: &self.dat_set,
            go_id: self.go_id.as_deref(),
            t: self.t,
            st_num: self.st_num,
            sq_num: self.sq_num,
            simulation: self.simulation,
            conf_rev: self.conf_rev,
            nds_com: self.nds_com,
            num_dat_set_entries: self.all_data.len() as u32,
        }
    }

    /// Encode as an APDU. `numDatSetEntries` is derived from `all_data`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = Value::encode_all(&self.all_data)?;
        let mut e = Encoder::with_capacity(96 + body.len());
        encode_into(&self.header(), &body, &mut e)?;
        Ok(e.into_vec())
    }

    /// Build an owned PDU from a view (deep copy of the data).
    pub fn from_view(v: &GoosePduView<'_>, limits: &Limits) -> Result<GoosePdu> {
        Ok(GoosePdu {
            gocb_ref: String::from(v.gocb_ref),
            time_allowed_to_live: v.time_allowed_to_live,
            dat_set: String::from(v.dat_set),
            go_id: v.go_id.map(String::from),
            t: v.t,
            st_num: v.st_num,
            sq_num: v.sq_num,
            simulation: v.simulation,
            conf_rev: v.conf_rev,
            nds_com: v.nds_com,
            all_data: v.all_data_owned(limits)?,
        })
    }
}

#[cfg(test)]
mod tests {
    // `vec!` is `std`'s prelude, and these tests run under `--no-default-features` too.
    use alloc::vec;

    use super::*;
    use crate::common::{Quality, TimeQuality};

    fn sample() -> GoosePdu {
        GoosePdu {
            gocb_ref: String::from("IED1LD0/LLN0$GO$gcb1"),
            time_allowed_to_live: 2000,
            dat_set: String::from("IED1LD0/LLN0$ds1"),
            go_id: Some(String::from("IED1")),
            t: UtcTime::from_unix(1_700_000_000, 0, TimeQuality::SYNCHRONIZED),
            st_num: 23,
            sq_num: 521,
            simulation: false,
            conf_rev: 1,
            nds_com: false,
            all_data: vec![Value::Boolean(true), Value::quality(Quality::GOOD)],
        }
    }

    #[test]
    fn round_trip() {
        let pdu = sample();
        let bytes = pdu.encode().unwrap();
        assert_eq!(bytes[0], 0x61);
        let v = GoosePduView::parse(&bytes).unwrap();
        assert_eq!(v.gocb_ref, pdu.gocb_ref);
        assert_eq!((v.st_num, v.sq_num, v.num_dat_set_entries), (23, 521, 2));
        assert_eq!(v.go_id, Some("IED1"));
        assert!(v.member_count_matches());
        assert_eq!(v.all_data().count(), 2);
        assert_eq!(GoosePdu::from_view(&v, &Limits::DEFAULT).unwrap(), pdu);
        assert_eq!(v.raw, &bytes[..]);
    }

    #[test]
    fn member_count_is_checked_against_the_declaration() {
        let mut pdu = sample();
        let honest = pdu.encode().unwrap();
        assert!(GoosePduView::parse(&honest).unwrap().member_count_matches());
        // A publisher that declares more members than it sends.
        pdu.all_data.push(Value::Boolean(false));
        let body = Value::encode_all(&pdu.all_data[..2]).unwrap();
        let mut e = Encoder::new();
        encode_into(&pdu.header(), &body, &mut e).unwrap();
        let lying = e.into_vec();
        let v = GoosePduView::parse(&lying).unwrap();
        assert_eq!(v.num_dat_set_entries, 3);
        assert_eq!(v.member_count(), Some(2));
        assert!(!v.member_count_matches());
    }

    #[test]
    fn optional_defaults_may_be_omitted_on_the_wire() {
        // `simulation [7]` and `ndsCom [9]` are DEFAULT FALSE; a publisher may leave them out.
        let full = sample().encode().unwrap();
        let mut stripped = Vec::new();
        let mut c = Cursor::new(&full).next_required().unwrap().children();
        let mut inner = Encoder::new();
        while let Some(Ok(t)) = c.next() {
            if matches!(t.tag.number, 7 | 9) && t.tag == Tag::context(t.tag.number) {
                continue;
            }
            inner.raw(full.get(t.offset..t.offset + t.total_len()).unwrap());
        }
        let body = inner.into_vec();
        let mut e = Encoder::new();
        e.constructed(TAG_GOOSE_PDU, |e| {
            e.raw(&body);
            Ok(())
        })
        .unwrap();
        stripped.extend_from_slice(e.as_bytes());
        let v = GoosePduView::parse(&stripped).unwrap();
        assert!(!v.simulation && !v.nds_com);
        assert_eq!(v.st_num, 23);
        assert_eq!(v.all_data().count(), 2);
    }

    #[test]
    fn a_constructed_security_extension_is_accepted() {
        // IEC 62351-6 appends `security [12] ANY`, which is constructed because ANY cannot
        // carry an implicit tag.
        let pdu = sample();
        let body = Value::encode_all(&pdu.all_data).unwrap();
        let mut inner = Encoder::new();
        encode_into(&pdu.header(), &body, &mut inner).unwrap();
        let inner = inner.into_vec();
        // Re-open the APDU and append the extension inside it.
        let content = &inner[2..];
        let mut e = Encoder::new();
        e.constructed(TAG_GOOSE_PDU, |e| {
            e.raw(content);
            e.constructed(Tag::context_constructed(12), |e| {
                e.primitive(Tag::universal(4, false), &[0xAA; 16])?;
                Ok(())
            })?;
            Ok(())
        })
        .unwrap();
        let bytes = e.into_vec();
        let v = GoosePduView::parse(&bytes).unwrap();
        assert_eq!(v.security.map(<[u8]>::len), Some(18));
        assert_eq!(v.st_num, 23);
    }

    #[test]
    fn truncation_is_an_error_not_a_panic() {
        let bytes = sample().encode().unwrap();
        for cut in 0..bytes.len() {
            assert!(GoosePduView::parse(&bytes[..cut]).is_err());
        }
    }
}
