use alloc::string::String;
use alloc::vec::Vec;

use crate::ber::{Cursor, Encoder, Tag, universal, unsigned_width};
use crate::common::{DecodeReason, Error, Limits, Result, UtcTime};

/// `savPdu [APPLICATION 0]`.
pub const TAG_SAV_PDU: Tag = Tag::application_constructed(0);
const TAG_ASDU: Tag = Tag::universal(universal::SEQUENCE, true);

/// `smpSynch` (IEC 61850-9-2 Ed2): how the samples are synchronised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpSynch {
    /// 0 — not synchronised.
    None,
    /// 1 — an unspecified local area clock.
    Local,
    /// 2 — a global area clock (time traceable).
    Global,
    /// 5–254 — the local area clock with this identity number.
    LocalClock(u8),
    /// 3, 4, 255 — reserved values, kept verbatim.
    Reserved(u8),
}

impl SmpSynch {
    /// From the wire value.
    pub const fn from_u8(v: u8) -> SmpSynch {
        match v {
            0 => SmpSynch::None,
            1 => SmpSynch::Local,
            2 => SmpSynch::Global,
            5..=254 => SmpSynch::LocalClock(v),
            _ => SmpSynch::Reserved(v),
        }
    }

    /// To the wire value.
    pub const fn to_u8(self) -> u8 {
        match self {
            SmpSynch::None => 0,
            SmpSynch::Local => 1,
            SmpSynch::Global => 2,
            SmpSynch::LocalClock(v) | SmpSynch::Reserved(v) => v,
        }
    }

    /// True for anything but `None`.
    pub const fn is_synchronized(self) -> bool {
        !matches!(self, SmpSynch::None)
    }
}

/// A zero-copy view of one ASDU.
///
/// Tags (verified against Wireshark's `sv.asn`): `svID [0]`, `datSet [1]?`, `smpCnt [2]`,
/// `confRev [3]`, `refrTm [4]?`, `smpSynch [5]?`, `smpRate [6]?`, `sample [7]`, `smpMod [8]?`,
/// `gmIdentity [9]?`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsduView<'a> {
    /// `svID`.
    pub sv_id: &'a str,
    /// `datSet`.
    pub dat_set: Option<&'a str>,
    /// `smpCnt`.
    pub smp_cnt: u16,
    /// `confRev`.
    pub conf_rev: u32,
    /// `refrTm`.
    pub refr_tm: Option<UtcTime>,
    /// `smpSynch`.
    pub smp_synch: Option<SmpSynch>,
    /// `smpRate`.
    pub smp_rate: Option<u16>,
    /// The raw sample block (`Data` as an octet string — the data-set members back to back).
    pub sample: &'a [u8],
    /// `smpMod`: 0 = samples per nominal period, 1 = samples per second, 2 = seconds per sample.
    pub smp_mod: Option<u8>,
    /// `gmIdentity` (8 octets).
    pub gm_identity: Option<&'a [u8]>,
    /// Where each patchable field's contents octets sit in the APDU this ASDU was decoded
    /// from. A publisher patches a pre-encoded frame through these, which is sound only
    /// because the encoder writes those fields at a fixed width.
    pub at: AsduOffsets,
}

/// A patchable field: where its contents octets start, and how many there are.
///
/// The width matters as much as the offset. An unsigned field is written at whatever width
/// keeps it a positive BER INTEGER for the whole range the stream can produce, so `smpCnt` is
/// two octets on a 4 kHz stream and three on a 96 kHz one; a patcher that assumed two would
/// write past a field on one and short of it on the other.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Field {
    /// Offset of the first contents octet.
    pub at: usize,
    /// Contents octets.
    pub len: usize,
}

/// Offsets, from the start of the APDU, of the ASDU fields a publisher rewrites in place.
///
/// They come from the decoder rather than from the encoder's own bookkeeping, so a template
/// and the codec cannot disagree about where a field is or how wide it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AsduOffsets {
    /// `smpCnt`.
    pub smp_cnt: Field,
    /// `smpSynch`, if the ASDU carries one.
    pub smp_synch: Option<Field>,
    /// First contents octet of `refrTm` (eight octets), if present.
    pub refr_tm: Option<usize>,
    /// First octet of the sample block.
    pub sample: usize,
    /// First contents octet of `gmIdentity` (eight octets), if present.
    pub gm_identity: Option<usize>,
}

impl<'a> AsduView<'a> {
    fn parse(t: crate::ber::Tlv<'a>) -> Result<AsduView<'a>> {
        let mut c = t.expect(TAG_ASDU)?.children();
        let sv_id = c.next_tag(Tag::context(0))?.visible_string()?;
        let dat_set = c.next_if_tag(Tag::context(1))?.map(|t| t.visible_string()).transpose()?;
        let smp_cnt_tlv = c.next_tag(Tag::context(2))?;
        let smp_cnt = u16::try_from(smp_cnt_tlv.unsigned_lenient_u32()?).map_err(|_| Error::decode(DecodeReason::BadValue, c.offset()))?;
        let conf_rev = c.next_tag(Tag::context(3))?.unsigned_lenient_u32()?;
        let refr_tm_tlv = c.next_if_tag(Tag::context(4))?;
        let refr_tm = refr_tm_tlv.map(|t| t.utc_time()).transpose()?;
        let smp_synch_tlv = c.next_if_tag(Tag::context(5))?;
        let smp_synch = match smp_synch_tlv {
            Some(t) => {
                let v = u8::try_from(t.unsigned_lenient_u32()?).map_err(|_| Error::decode(DecodeReason::BadValue, c.offset()))?;
                Some(SmpSynch::from_u8(v))
            }
            None => None,
        };
        let smp_rate = match c.next_if_tag(Tag::context(6))?.map(|t| t.unsigned_lenient_u32()).transpose()? {
            Some(v) => Some(u16::try_from(v).map_err(|_| Error::decode(DecodeReason::BadValue, c.offset()))?),
            None => None,
        };
        let sample_tlv = c.next_tag(Tag::context(7))?;
        let smp_mod = match c.next_if_tag(Tag::context(8))?.map(|t| t.unsigned_lenient_u32()).transpose()? {
            Some(v) => Some(u8::try_from(v).map_err(|_| Error::decode(DecodeReason::BadValue, c.offset()))?),
            None => None,
        };
        let gm_tlv = c.next_if_tag(Tag::context(9))?;
        c.finish()?;
        Ok(AsduView {
            sv_id,
            dat_set,
            smp_cnt,
            conf_rev,
            refr_tm,
            smp_synch,
            smp_rate,
            sample: sample_tlv.value,
            smp_mod,
            gm_identity: gm_tlv.map(|t| t.value),
            at: AsduOffsets {
                smp_cnt: Field { at: smp_cnt_tlv.value_offset, len: smp_cnt_tlv.value.len() },
                smp_synch: smp_synch_tlv.map(|t| Field { at: t.value_offset, len: t.value.len() }),
                refr_tm: refr_tm_tlv.map(|t| t.value_offset),
                sample: sample_tlv.value_offset,
                gm_identity: gm_tlv.map(|t| t.value_offset),
            },
        })
    }
}

/// A zero-copy view of a `savPdu`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavPduView<'a> {
    /// `noASDU`.
    pub no_asdu: u16,
    /// `security`, raw, if present.
    pub security: Option<&'a [u8]>,
    /// The `SEQUENCE OF ASDU` element. Kept as the element rather than as its contents so
    /// that the offsets in [`AsduOffsets`] stay relative to the whole APDU.
    asdus: crate::ber::Tlv<'a>,
    /// The whole APDU.
    pub raw: &'a [u8],
}

impl<'a> SavPduView<'a> {
    /// Decode an SV APDU (the bytes after the 8-octet link-layer header).
    pub fn parse(apdu: &'a [u8], limits: &Limits) -> Result<SavPduView<'a>> {
        let pdu = Cursor::new(apdu).next_tag(TAG_SAV_PDU)?;
        let mut c = pdu.children();
        let no_asdu = c.next_tag(Tag::context(0))?.unsigned_lenient_u32()?;
        let no_asdu = u16::try_from(no_asdu).map_err(|_| Error::decode(DecodeReason::BadValue, c.offset()))?;
        if usize::from(no_asdu) > limits.max_asdus {
            return Err(Error::LimitExceeded { limit: "max_asdus", value: usize::from(no_asdu) });
        }
        // `security [1] ANY OPTIONAL` (IEC 61850-9-2 AMD1). ANY cannot be implicitly
        // tagged, so the IEC 62351-6 extension arrives constructed; accept both spellings.
        let security = match c.next_if_tag(Tag::context_constructed(1))? {
            Some(t) => Some(t.value),
            None => c.next_if_tag(Tag::context(1))?.map(|t| t.value),
        };
        let asdus = c.next_tag(Tag::context_constructed(2))?;
        c.finish()?;
        let view = SavPduView { no_asdu, security, asdus, raw: apdu.get(..pdu.total_len()).unwrap_or(apdu) };
        // Validate the count now so iteration cannot surprise the caller.
        let mut n = 0u16;
        for a in view.asdus() {
            a?;
            n = n.saturating_add(1);
        }
        if n != no_asdu {
            return Err(Error::decode(DecodeReason::BadValue, c.offset()));
        }
        Ok(view)
    }

    /// Iterate over the ASDUs.
    pub fn asdus(&self) -> Asdus<'a> {
        Asdus { c: self.asdus.children() }
    }
}

/// Iterator over ASDUs.
#[derive(Clone, Debug)]
pub struct Asdus<'a> {
    c: Cursor<'a>,
}

impl<'a> Iterator for Asdus<'a> {
    type Item = Result<AsduView<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.c.next().map(|r| r.and_then(AsduView::parse))
    }
}

/// An owned ASDU for encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asdu {
    /// `svID`.
    pub sv_id: String,
    /// `datSet`.
    pub dat_set: Option<String>,
    /// `smpCnt`.
    pub smp_cnt: u16,
    /// `confRev`.
    pub conf_rev: u32,
    /// `refrTm`.
    pub refr_tm: Option<UtcTime>,
    /// `smpSynch`.
    pub smp_synch: Option<SmpSynch>,
    /// `smpRate`.
    pub smp_rate: Option<u16>,
    /// The sample block.
    pub sample: Vec<u8>,
    /// `smpMod`.
    pub smp_mod: Option<u8>,
    /// `gmIdentity`.
    pub gm_identity: Option<[u8; 8]>,
}

impl Asdu {
    /// Contents octets `smpCnt` occupies for a stream whose count reaches `max_smp_cnt`.
    ///
    /// The publisher sizes its template with this so that every value the stream produces
    /// fits the field it patches.
    pub const fn smp_cnt_width(max_smp_cnt: u16) -> usize {
        unsigned_width(max_smp_cnt as u64, 2)
    }

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.constructed(TAG_ASDU, |e| {
            e.visible_string(Tag::context(0), &self.sv_id)?;
            if let Some(d) = &self.dat_set {
                e.visible_string(Tag::context(1), d)?;
            }
            // The widths the vendor captures show — `82 02` for smpCnt, `83 04` for confRev,
            // `85 01` for smpSynch, `86 02` for smpRate — widened by one octet only when the
            // value would otherwise be a negative INTEGER. A publisher patches smpCnt and
            // smpSynch in place, so the width has to be constant for the whole stream; that
            // is why the template is encoded from the largest value the stream can produce.
            e.unsigned_fixed_min(Tag::context(2), u64::from(self.smp_cnt), 2)?;
            e.unsigned_fixed_min(Tag::context(3), u64::from(self.conf_rev), 4)?;
            if let Some(t) = self.refr_tm {
                e.utc_time(Tag::context(4), t)?;
            }
            if let Some(s) = self.smp_synch {
                e.unsigned_fixed_min(Tag::context(5), u64::from(s.to_u8()), 1)?;
            }
            if let Some(r) = self.smp_rate {
                e.unsigned_fixed_min(Tag::context(6), u64::from(r), 2)?;
            }
            e.primitive(Tag::context(7), &self.sample)?;
            if let Some(m) = self.smp_mod {
                e.unsigned_fixed_min(Tag::context(8), u64::from(m), 1)?;
            }
            if let Some(g) = &self.gm_identity {
                e.primitive(Tag::context(9), g)?;
            }
            Ok(())
        })?;
        Ok(())
    }
}

/// An owned `savPdu` for encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavPdu {
    /// The ASDUs (`noASDU` is derived).
    pub asdus: Vec<Asdu>,
}

impl SavPdu {
    /// Encode as an APDU.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::with_capacity(32 + self.asdus.len() * 96);
        e.constructed(TAG_SAV_PDU, |e| {
            e.unsigned_fixed_min(Tag::context(0), self.asdus.len() as u64, 1)?;
            e.constructed(Tag::context_constructed(2), |e| {
                for a in &self.asdus {
                    a.encode(e)?;
                }
                Ok(())
            })?;
            Ok(())
        })?;
        Ok(e.into_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let pdu = SavPdu {
            asdus: alloc::vec![Asdu {
                sv_id: "4001".into(),
                dat_set: None,
                smp_cnt: 280,
                conf_rev: 1,
                refr_tm: None,
                smp_synch: Some(SmpSynch::Global),
                smp_rate: None,
                sample: alloc::vec![0u8; 64],
                smp_mod: None,
                gm_identity: None,
            }],
        };
        let bytes = pdu.encode().unwrap();
        assert_eq!(&bytes[..6], &[0x60, 0x5C, 0x80, 0x01, 0x01, 0xA2]);
        let v = SavPduView::parse(&bytes, &Limits::DEFAULT).unwrap();
        assert_eq!(v.no_asdu, 1);
        let a = v.asdus().next().unwrap().unwrap();
        assert_eq!(a.sv_id, "4001");
        assert_eq!(a.smp_cnt, 280);
        assert_eq!(a.smp_synch, Some(SmpSynch::Global));
        assert_eq!(a.sample.len(), 64);
    }

    #[test]
    fn count_mismatch_and_limits() {
        let mut pdu = SavPdu { asdus: Vec::new() };
        for _ in 0..3 {
            pdu.asdus.push(Asdu {
                sv_id: "x".into(),
                dat_set: None,
                smp_cnt: 0,
                conf_rev: 1,
                refr_tm: None,
                smp_synch: None,
                smp_rate: None,
                sample: Vec::new(),
                smp_mod: None,
                gm_identity: None,
            });
        }
        let mut bytes = pdu.encode().unwrap();
        bytes[4] = 2; // noASDU says 2, three present
        assert!(SavPduView::parse(&bytes, &Limits::DEFAULT).is_err());
        bytes[4] = 3;
        assert!(SavPduView::parse(&bytes, &Limits { max_asdus: 2, ..Limits::DEFAULT }).is_err());
        assert!(SavPduView::parse(&bytes, &Limits::DEFAULT).is_ok());
    }
}
