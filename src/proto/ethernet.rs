// Indexing below follows explicit length checks; see `Frame::parse` and `FrameHeader::write`.
#![allow(clippy::indexing_slicing)]

//! The Ethernet + IEC 61850 link-layer header shared by GOOSE (0x88B8) and SV (0x88BA):
//! destination, source, optional 802.1Q tag, `EtherType`, APPID, Length, Reserved1, Reserved2.

use alloc::vec::Vec;

use crate::common::{DecodeReason, Error, Result};

/// The link-layer address. Defined in [`crate::common`] because the SCL model needs it
/// whether or not the process-bus codecs are compiled in; re-exported here because this is
/// where a reader of the framing code looks for it.
pub use crate::common::MacAddr;

/// `EtherType` of GOOSE.
pub const ETHERTYPE_GOOSE: u16 = 0x88B8;
/// `EtherType` of GSE management (Ed1, deprecated).
pub const ETHERTYPE_GSE_MGMT: u16 = 0x88B9;
/// `EtherType` of Sampled Values.
pub const ETHERTYPE_SV: u16 = 0x88BA;
/// `EtherType` of an 802.1Q VLAN tag.
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// The simulation bit in `Reserved1` (IEC 61850-8-1 Ed2).
pub const RESERVED1_SIMULATION: u16 = 0x8000;

/// An 802.1Q tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VlanTag {
    /// Priority code point (0–7).
    pub priority: u8,
    /// Drop-eligible indicator.
    pub dei: bool,
    /// VLAN identifier (0–4095).
    pub id: u16,
}

impl VlanTag {
    /// The default for GOOSE and SV: priority 4, VLAN 0.
    pub const DEFAULT: VlanTag = VlanTag { priority: 4, dei: false, id: 0 };

    const fn tci(self) -> u16 {
        ((self.priority as u16 & 7) << 13) | ((self.dei as u16) << 12) | (self.id & 0x0FFF)
    }

    const fn from_tci(tci: u16) -> VlanTag {
        VlanTag { priority: (tci >> 13) as u8, dei: tci & 0x1000 != 0, id: tci & 0x0FFF }
    }
}

/// The parsed header of a GOOSE or SV frame, borrowing the APDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Destination MAC.
    pub dst: MacAddr,
    /// Source MAC.
    pub src: MacAddr,
    /// VLAN tag if the frame was tagged.
    pub vlan: Option<VlanTag>,
    /// 0x88B8 (GOOSE) or 0x88BA (SV).
    pub ethertype: u16,
    /// APPID.
    pub appid: u16,
    /// The `Length` field: APPID..end of APDU.
    pub length: u16,
    /// Reserved1 (bit 15 = simulation).
    pub reserved1: u16,
    /// Reserved2.
    pub reserved2: u16,
    /// The APDU bytes (`length - 8` of them).
    pub apdu: &'a [u8],
    /// Offset of the APDU within the frame, for error reporting.
    pub apdu_offset: usize,
}

impl<'a> Frame<'a> {
    /// Parse an Ethernet frame. Fails unless the `EtherType` (after an optional VLAN tag) is
    /// GOOSE or SV and the `Length` field is consistent with the frame.
    pub fn parse(frame: &'a [u8]) -> Result<Frame<'a>> {
        let err = |off| Error::decode(DecodeReason::NotProcessBusFrame, off);
        if frame.len() < 14 {
            return Err(err(0));
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&frame[0..6]);
        src.copy_from_slice(&frame[6..12]);
        let mut pos = 12;
        let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let mut vlan = None;
        if ethertype == ETHERTYPE_VLAN {
            let tci = frame.get(14..16).ok_or(err(14))?;
            vlan = Some(VlanTag::from_tci(u16::from_be_bytes([tci[0], tci[1]])));
            let et = frame.get(16..18).ok_or(err(16))?;
            ethertype = u16::from_be_bytes([et[0], et[1]]);
            pos = 16;
        }
        if ethertype != ETHERTYPE_GOOSE && ethertype != ETHERTYPE_SV && ethertype != ETHERTYPE_GSE_MGMT {
            return Err(err(pos));
        }
        pos += 2;
        let hdr = frame.get(pos..pos + 8).ok_or(err(pos))?;
        let appid = u16::from_be_bytes([hdr[0], hdr[1]]);
        let length = u16::from_be_bytes([hdr[2], hdr[3]]);
        let reserved1 = u16::from_be_bytes([hdr[4], hdr[5]]);
        let reserved2 = u16::from_be_bytes([hdr[6], hdr[7]]);
        if length < 8 {
            return Err(Error::decode(DecodeReason::BadLength, pos + 2));
        }
        let apdu_offset = pos + 8;
        let apdu = frame.get(apdu_offset..pos + usize::from(length)).ok_or(Error::decode(DecodeReason::Truncated, apdu_offset))?;
        Ok(Frame { dst: MacAddr(dst), src: MacAddr(src), vlan, ethertype, appid, length, reserved1, reserved2, apdu, apdu_offset })
    }

    /// The simulation bit of `Reserved1`.
    pub const fn simulation(&self) -> bool {
        self.reserved1 & RESERVED1_SIMULATION != 0
    }
}

/// The addressing fields of a process-bus frame, readable even when the rest of it is not.
///
/// A subscriber needs this to tell *its own* malformed frame from someone else's. The
/// destination address, the `EtherType` and the APPID sit in the first twenty octets and
/// survive whatever is wrong further in, so a frame that fails [`Frame::parse`] can still
/// be attributed to a stream — which is the difference between a counter that means
/// "somebody is sending me rubbish" and one that means "there is other traffic on this
/// segment".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameAddress {
    /// Destination MAC.
    pub dst: MacAddr,
    /// `EtherType` after an optional VLAN tag.
    pub ethertype: u16,
    /// APPID.
    pub appid: u16,
}

impl FrameAddress {
    /// Read the addressing fields, or `None` if the frame is too short or is not a
    /// process-bus frame at all.
    pub fn peek(frame: &[u8]) -> Option<FrameAddress> {
        let mut dst = [0u8; 6];
        dst.copy_from_slice(frame.get(0..6)?);
        let mut pos = 12;
        let mut ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
        if ethertype == ETHERTYPE_VLAN {
            ethertype = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
            pos = 16;
        }
        if ethertype != ETHERTYPE_GOOSE && ethertype != ETHERTYPE_SV && ethertype != ETHERTYPE_GSE_MGMT {
            return None;
        }
        let appid = u16::from_be_bytes([*frame.get(pos + 2)?, *frame.get(pos + 3)?]);
        Some(FrameAddress { dst: MacAddr(dst), ethertype, appid })
    }
}

/// What a frame builder needs to write the link-layer header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Destination MAC.
    pub dst: MacAddr,
    /// Source MAC.
    pub src: MacAddr,
    /// VLAN tag, or untagged.
    pub vlan: Option<VlanTag>,
    /// `EtherType`.
    pub ethertype: u16,
    /// APPID.
    pub appid: u16,
    /// Reserved1 (set bit 15 for simulation).
    pub reserved1: u16,
    /// Reserved2.
    pub reserved2: u16,
}

impl FrameHeader {
    /// Number of bytes this header occupies (14 or 18, plus 8).
    // A header always occupies bytes, so there is no `is_empty` to pair with this.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        (if self.vlan.is_some() { 18 } else { 14 }) + 8
    }

    /// Write the header followed by `apdu` into `out`, returning the frame length.
    /// `out` must be at least `self.len() + apdu.len()` bytes.
    pub fn write(&self, apdu: &[u8], out: &mut [u8]) -> Result<usize> {
        let total = self.len() + apdu.len();
        if out.len() < total || apdu.len() + 8 > usize::from(u16::MAX) {
            return Err(Error::Encode("frame buffer too small or APDU too large"));
        }
        out[0..6].copy_from_slice(&self.dst.0);
        out[6..12].copy_from_slice(&self.src.0);
        let mut pos = 12;
        if let Some(v) = self.vlan {
            out[12..14].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
            out[14..16].copy_from_slice(&v.tci().to_be_bytes());
            pos = 16;
        }
        out[pos..pos + 2].copy_from_slice(&self.ethertype.to_be_bytes());
        out[pos + 2..pos + 4].copy_from_slice(&self.appid.to_be_bytes());
        out[pos + 4..pos + 6].copy_from_slice(&((apdu.len() + 8) as u16).to_be_bytes());
        out[pos + 6..pos + 8].copy_from_slice(&self.reserved1.to_be_bytes());
        out[pos + 8..pos + 10].copy_from_slice(&self.reserved2.to_be_bytes());
        out[pos + 10..pos + 10 + apdu.len()].copy_from_slice(apdu);
        Ok(total)
    }

    /// Build a complete frame in a new `Vec`.
    pub fn to_frame(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut v = alloc::vec![0u8; self.len() + apdu.len()];
        self.write(apdu, &mut v)?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip_with_vlan() {
        let h = FrameHeader {
            dst: MacAddr::GOOSE_BASE,
            src: MacAddr([2, 0, 0, 0, 0, 1]),
            vlan: Some(VlanTag { priority: 4, dei: false, id: 1 }),
            ethertype: ETHERTYPE_GOOSE,
            appid: 0x0003,
            reserved1: RESERVED1_SIMULATION,
            reserved2: 0,
        };
        let apdu = [0x61, 0x02, 0x80, 0x00];
        let frame = h.to_frame(&apdu).unwrap();
        assert_eq!(frame.len(), 18 + 8 + 4);
        let p = Frame::parse(&frame).unwrap();
        assert_eq!(p.vlan, h.vlan);
        assert_eq!(p.appid, 3);
        assert_eq!(p.length, 12);
        assert!(p.simulation());
        assert_eq!(p.apdu, &apdu);
        assert_eq!(p.apdu_offset, 26);
        assert!(p.dst.is_goose_multicast());
        assert!(!p.dst.is_sv_multicast());
    }

    #[test]
    fn rejects_non_process_bus() {
        let mut f = [0u8; 60];
        f[12] = 0x08;
        assert!(Frame::parse(&f).is_err());
        assert!(Frame::parse(&f[..10]).is_err());
        let h = FrameHeader { dst: MacAddr::SV_BASE, src: MacAddr::default(), vlan: None, ethertype: ETHERTYPE_SV, appid: 0x4000, reserved1: 0, reserved2: 0 };
        let mut frame = h.to_frame(&[0x60, 0x00]).unwrap();
        frame[16] = 0xFF; // bogus length
        assert!(Frame::parse(&frame).is_err());
    }

    #[test]
    fn the_address_is_readable_even_when_the_frame_is_not() {
        let h = FrameHeader {
            dst: MacAddr::GOOSE_BASE,
            src: MacAddr::default(),
            vlan: Some(VlanTag::DEFAULT),
            ethertype: ETHERTYPE_GOOSE,
            appid: 0x0007,
            reserved1: 0,
            reserved2: 0,
        };
        let frame = h.to_frame(&[0x61, 0x02, 0x80, 0x00]).unwrap();
        let want = FrameAddress { dst: MacAddr::GOOSE_BASE, ethertype: ETHERTYPE_GOOSE, appid: 7 };
        assert_eq!(FrameAddress::peek(&frame), Some(want));
        // Truncated past the header: `parse` fails, the address still reads.
        assert!(Frame::parse(&frame[..24]).is_err());
        assert_eq!(FrameAddress::peek(&frame[..24]), Some(want));
        // Not process bus, and too short to tell.
        assert_eq!(FrameAddress::peek(&[0u8; 60]), None);
        assert_eq!(FrameAddress::peek(&frame[..8]), None);
    }

    #[test]
    fn mac_parse_display() {
        let m = MacAddr::parse("01-0c-cd-04-01-ff").unwrap();
        assert!(m.is_sv_multicast());
        assert_eq!(alloc::format!("{m}"), "01-0C-CD-04-01-FF");
        assert!(MacAddr::parse("01-0c-cd").is_err());
    }
}
