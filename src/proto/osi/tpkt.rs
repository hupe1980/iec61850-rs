//! TPKT (RFC 1006): the four-octet header that carries an OSI TPDU over TCP.
//!
//! ```text
//! 0         1         2 .. 3
//! version   reserved  length, big-endian, of the whole packet including these four octets
//! ```
//!
//! There is nothing else to it, and that is the point: TCP is a byte stream and TPKT is what
//! tells one TPDU from the next. The only subtlety is that the header may arrive in a segment
//! of its own — the reference capture does exactly that, sending `03 00 00 16` and then the
//! TPDU in the next segment — so anything reading TPKT off a socket has to be a state machine
//! over a growing buffer rather than a function over a packet. [`Reader`] is that machine.

use alloc::vec::Vec;

use crate::common::{DecodeReason, Error, Result};

/// The version octet of TPKT: 3.
pub const VERSION: u8 = 3;
/// Octets in a TPKT header.
pub const HEADER_LEN: usize = 4;
/// The largest packet a TPKT length field can describe.
pub const MAX_PACKET: usize = u16::MAX as usize;

/// The length of the packet that starts at `buf`, or `None` while the header is incomplete.
///
/// An error means the stream is not TPKT and cannot be resynchronised: the caller must drop
/// the connection rather than hunt for the next plausible header.
pub fn packet_len(buf: &[u8]) -> Result<Option<usize>> {
    let (Some(&version), Some(&hi), Some(&lo)) = (buf.first(), buf.get(2), buf.get(3)) else {
        return Ok(None);
    };
    if version != VERSION {
        return Err(Error::decode(DecodeReason::UnexpectedTag, 0));
    }
    let len = usize::from(u16::from_be_bytes([hi, lo]));
    if len < HEADER_LEN {
        return Err(Error::decode(DecodeReason::BadLength, 2));
    }
    Ok(Some(len))
}

/// The TPKT header for a payload of `payload_len` octets.
pub fn header(payload_len: usize) -> Result<[u8; HEADER_LEN]> {
    let total = payload_len.checked_add(HEADER_LEN).filter(|n| *n <= MAX_PACKET).ok_or(Error::Encode("TPKT packet exceeds 65535 octets"))?;
    let n = total as u16;
    Ok([VERSION, 0, (n >> 8) as u8, n as u8])
}

/// Reassembles a TCP byte stream into whole TPDUs.
///
/// Feed it whatever the socket returned and take complete TPDUs out one at a time. Each one
/// borrows the reader's own buffer and stays valid until the next call, which is the same
/// contract a publisher's `poll_transmit` has and for the same reason: an association that
/// reads thousands of PDUs should not allocate one buffer per PDU.
#[derive(Debug, Default)]
pub struct Reader {
    buf: Vec<u8>,
    /// Octets handed out by the previous [`Reader::next_tpdu`], removed by the next one.
    consumed: usize,
}

impl Reader {
    /// An empty reader.
    pub fn new() -> Reader {
        Reader { buf: Vec::new(), consumed: 0 }
    }

    /// Append received bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Octets held that are not yet a complete packet the caller has taken.
    pub fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.consumed)
    }

    /// Take the next complete TPDU — the packet without its TPKT header — if one is there.
    ///
    /// `Ok(None)` means "more bytes needed", not "end of stream". An `Err` means the stream
    /// is not TPKT at all and the connection has to go.
    pub fn next_tpdu(&mut self) -> Result<Option<&[u8]>> {
        if self.consumed > 0 {
            self.buf.drain(..self.consumed.min(self.buf.len()));
            self.consumed = 0;
        }
        let Some(len) = packet_len(&self.buf)? else { return Ok(None) };
        if self.buf.len() < len {
            return Ok(None);
        }
        self.consumed = len;
        Ok(self.buf.get(HEADER_LEN..len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_split_across_segments_still_frames() {
        // What the reference capture does: the four header octets in one TCP segment and the
        // TPDU in the next. A reader that assumed one packet per read would stall here.
        let mut r = Reader::new();
        r.push(&[0x03, 0x00]);
        assert!(r.next_tpdu().unwrap().is_none());
        r.push(&[0x00, 0x07, 0x02]);
        assert!(r.next_tpdu().unwrap().is_none(), "the payload is still short");
        r.push(&[0xF0, 0x80]);
        assert_eq!(r.next_tpdu().unwrap(), Some(&[0x02, 0xF0, 0x80][..]));
        assert!(r.next_tpdu().unwrap().is_none());
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn several_packets_in_one_read_come_out_one_at_a_time() {
        let mut r = Reader::new();
        r.push(&[0x03, 0x00, 0x00, 0x05, 0xAA, 0x03, 0x00, 0x00, 0x06, 0xBB, 0xCC, 0x03]);
        assert_eq!(r.next_tpdu().unwrap(), Some(&[0xAA][..]));
        assert_eq!(r.next_tpdu().unwrap(), Some(&[0xBB, 0xCC][..]));
        assert_eq!(r.next_tpdu().unwrap(), None);
        assert_eq!(r.buffered(), 1, "the start of the third packet is kept");
    }

    #[test]
    fn a_stream_that_is_not_tpkt_is_an_error_not_a_resynchronisation() {
        let mut r = Reader::new();
        r.push(&[0x16, 0x03, 0x01, 0x00]); // a TLS record: someone connected to the wrong port
        assert!(r.next_tpdu().is_err());
        let mut z = Reader::new();
        z.push(&[0x03, 0x00, 0x00, 0x02]);
        assert!(z.next_tpdu().is_err(), "a length below the header is not a packet");
    }

    #[test]
    fn headers_round_trip() {
        assert_eq!(header(3).unwrap(), [3, 0, 0, 7]);
        assert_eq!(packet_len(&header(3).unwrap()).unwrap(), Some(7));
        assert_eq!(header(MAX_PACKET - HEADER_LEN).unwrap(), [3, 0, 0xFF, 0xFF]);
        assert!(header(MAX_PACKET).is_err());
    }
}
