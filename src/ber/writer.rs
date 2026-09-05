// Every index below follows a length check or a fixed-size array; the lint cannot see that.
#![allow(clippy::indexing_slicing)]

use alloc::vec::Vec;

use super::Tag;
use crate::common::{Error, Result, UtcTime};

/// A BER encoder writing minimal definite-length encodings into a `Vec<u8>`.
///
/// Constructed elements are written by [`Encoder::constructed`], which writes the
/// children first and then inserts the length — the same two-pass shape libiec61850 uses,
/// without the separate size-computation pass.
#[derive(Debug, Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// An empty encoder.
    pub fn new() -> Self {
        Encoder { buf: Vec::new() }
    }

    /// An encoder with `capacity` bytes reserved.
    pub fn with_capacity(capacity: usize) -> Self {
        Encoder { buf: Vec::with_capacity(capacity) }
    }

    /// The bytes written so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the encoder.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Make room for at least `additional` more bytes than are currently written.
    ///
    /// A publisher that reserves its worst case once never grows its buffer again, which is
    /// what turns "allocates nothing in the steady state" into something a counting
    /// allocator can assert rather than something the prose merely claims.
    pub fn reserve(&mut self, additional: usize) {
        self.buf.reserve(additional);
    }

    /// Drop everything written, keeping the allocation.
    ///
    /// This is what lets a publisher re-encode a header every few milliseconds without
    /// allocating: the buffer is written, sent, cleared and written again.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Current length, useful to record patch offsets.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True if nothing was written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Write a primitive element with raw contents.
    pub fn primitive(&mut self, tag: Tag, contents: &[u8]) -> Result<&mut Self> {
        self.write_tag(tag);
        self.write_length(contents.len())?;
        self.buf.extend_from_slice(contents);
        Ok(self)
    }

    /// Write a constructed element whose children are produced by `f`.
    pub fn constructed<F>(&mut self, tag: Tag, f: F) -> Result<&mut Self>
    where
        F: FnOnce(&mut Encoder) -> Result<()>,
    {
        self.write_tag(tag);
        let len_pos = self.buf.len();
        self.buf.push(0); // placeholder for a one-octet length
        f(self)?;
        let content_len = self.buf.len() - len_pos - 1;
        let mut len_octets = [0u8; 5];
        let n = encode_length_into(content_len, &mut len_octets)?;
        if n == 1 {
            self.buf[len_pos] = len_octets[0];
        } else {
            // Grow the placeholder to `n` octets, shifting the contents right.
            let extra = n - 1;
            let old_len = self.buf.len();
            self.buf.resize(old_len + extra, 0);
            self.buf.copy_within(len_pos + 1..old_len, len_pos + 1 + extra);
            self.buf[len_pos..len_pos + n].copy_from_slice(&len_octets[..n]);
        }
        Ok(self)
    }

    /// Two's-complement INTEGER, minimal.
    pub fn integer(&mut self, tag: Tag, value: i64) -> Result<&mut Self> {
        let bytes = value.to_be_bytes();
        let mut start = 0;
        while start < 7 && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0) || (bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0)) {
            start += 1;
        }
        self.primitive(tag, &bytes[start..])
    }

    /// Unsigned INTEGER, minimal (with the leading zero octet BER requires when the top
    /// bit is set).
    pub fn unsigned(&mut self, tag: Tag, value: u64) -> Result<&mut Self> {
        let bytes = value.to_be_bytes();
        let mut start = 0;
        while start < 7 && bytes[start] == 0 && bytes[start + 1] & 0x80 == 0 {
            start += 1;
        }
        if bytes[start] & 0x80 != 0 {
            let mut with_zero = [0u8; 9];
            with_zero[1..].copy_from_slice(&bytes);
            return self.primitive(tag, &with_zero[start..]);
        }
        self.primitive(tag, &bytes[start..])
    }

    /// Unsigned INTEGER encoded with exactly `width` contents octets, big-endian, with no
    /// leading zero octet even when the top bit is set.
    ///
    /// This is deliberately the *field* encoding rather than the minimal one: a
    /// sampled-value publisher writes `smpCnt`, `confRev` and `smpSynch` at a constant
    /// width so no length can shift underneath a template patch, and fixed-length encoded
    /// GOOSE writes every integer at the width of its `bType`. Every deployed publisher we
    /// have a capture of does this, so [`Tlv::unsigned_lenient_u64`] reads it back
    /// symmetrically. Fails only if the value does not fit in `width` octets.
    ///
    /// [`Tlv::unsigned_lenient_u64`]: crate::ber::Tlv::unsigned_lenient_u64
    pub fn unsigned_fixed(&mut self, tag: Tag, value: u64, width: usize) -> Result<&mut Self> {
        if width == 0 || width > 8 || (width < 8 && value >> (width * 8) != 0) {
            return Err(Error::Encode("value does not fit the fixed width"));
        }
        let bytes = value.to_be_bytes();
        self.primitive(tag, &bytes[8 - width..])
    }

    /// BOOLEAN. `TRUE` is written as `0x01`, which is what deployed IEDs (SEL) and
    /// libiec61850 emit; the reader accepts any non-zero octet as BER allows.
    pub fn boolean(&mut self, tag: Tag, value: bool) -> Result<&mut Self> {
        self.primitive(tag, &[u8::from(value)])
    }

    /// BIT STRING from contents octets and the number of unused bits in the last one.
    pub fn bit_string(&mut self, tag: Tag, unused_bits: u8, contents: &[u8]) -> Result<&mut Self> {
        if unused_bits > 7 || (contents.is_empty() && unused_bits != 0) {
            return Err(Error::Encode("bit string unused bits"));
        }
        self.write_tag(tag);
        self.write_length(contents.len() + 1)?;
        self.buf.push(unused_bits);
        self.buf.extend_from_slice(contents);
        Ok(self)
    }

    /// `VisibleString` (ASCII only).
    pub fn visible_string(&mut self, tag: Tag, s: &str) -> Result<&mut Self> {
        if !s.is_ascii() {
            return Err(Error::Encode("VisibleString must be ASCII"));
        }
        self.primitive(tag, s.as_bytes())
    }

    /// ISO 9506 `FloatingPoint`, single precision (exponent width 8).
    pub fn float32(&mut self, tag: Tag, value: f32) -> Result<&mut Self> {
        let b = value.to_be_bytes();
        self.primitive(tag, &[8, b[0], b[1], b[2], b[3]])
    }

    /// ISO 9506 `FloatingPoint`, double precision (exponent width 11).
    pub fn float64(&mut self, tag: Tag, value: f64) -> Result<&mut Self> {
        let b = value.to_be_bytes();
        let mut o = [11u8; 9];
        o[1..].copy_from_slice(&b);
        self.primitive(tag, &o)
    }

    /// IEC 61850 `UtcTime`.
    pub fn utc_time(&mut self, tag: Tag, t: UtcTime) -> Result<&mut Self> {
        self.primitive(tag, &t.to_octets())
    }

    /// Append raw, already-encoded bytes.
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    fn write_tag(&mut self, tag: Tag) {
        self.buf.push(tag.first_octet());
        if tag.number >= 31 {
            // Base-128 with continuation bits, most significant group first.
            let mut groups = [0u8; 5];
            let mut n = 0;
            let mut v = tag.number;
            loop {
                groups[n] = (v & 0x7F) as u8;
                n += 1;
                v >>= 7;
                if v == 0 {
                    break;
                }
            }
            for i in (0..n).rev() {
                self.buf.push(groups[i] | if i > 0 { 0x80 } else { 0 });
            }
        }
    }

    fn write_length(&mut self, len: usize) -> Result<()> {
        let mut o = [0u8; 5];
        let n = encode_length_into(len, &mut o)?;
        self.buf.extend_from_slice(&o[..n]);
        Ok(())
    }
}

/// Encode a definite length into `out`, returning how many octets were used.
fn encode_length_into(len: usize, out: &mut [u8; 5]) -> Result<usize> {
    if len < 0x80 {
        out[0] = len as u8;
        return Ok(1);
    }
    let len = u32::try_from(len).map_err(|_| Error::Encode("length exceeds u32"))?;
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    let n = 4 - skip;
    out[0] = 0x80 | n as u8;
    out[1..=n].copy_from_slice(&bytes[skip..]);
    Ok(n + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::Cursor;

    #[test]
    fn minimal_integers() {
        let mut e = Encoder::new();
        e.integer(Tag::context(5), 0).unwrap();
        e.integer(Tag::context(5), 127).unwrap();
        e.integer(Tag::context(5), 128).unwrap();
        e.integer(Tag::context(5), -129).unwrap();
        e.unsigned(Tag::context(6), 255).unwrap();
        e.unsigned(Tag::context(6), u64::from(u32::MAX)).unwrap();
        assert_eq!(e.as_bytes(), &[0x85, 1, 0, 0x85, 1, 127, 0x85, 2, 0, 128, 0x85, 2, 0xFF, 0x7F, 0x86, 2, 0, 255, 0x86, 5, 0, 255, 255, 255, 255]);
        let mut c = Cursor::new(e.as_bytes());
        assert_eq!(c.next_required().unwrap().integer_i64().unwrap(), 0);
        assert_eq!(c.next_required().unwrap().integer_i64().unwrap(), 127);
        assert_eq!(c.next_required().unwrap().integer_i64().unwrap(), 128);
        assert_eq!(c.next_required().unwrap().integer_i64().unwrap(), -129);
        assert_eq!(c.next_required().unwrap().unsigned_u32().unwrap(), 255);
        assert_eq!(c.next_required().unwrap().unsigned_u32().unwrap(), u32::MAX);
    }

    #[test]
    fn constructed_with_long_length() {
        let mut e = Encoder::new();
        e.constructed(Tag::context_constructed(11), |e| {
            for _ in 0..50 {
                e.integer(Tag::context(5), 1)?;
            }
            Ok(())
        })
        .unwrap();
        let b = e.as_bytes();
        assert_eq!(&b[..3], &[0xAB, 0x81, 150]);
        assert_eq!(b.len(), 153);
        let t = Cursor::new(b).next_required().unwrap();
        assert_eq!(t.children().count_children(), 50);
    }

    #[test]
    fn fixed_width_and_floats() {
        let mut e = Encoder::new();
        e.unsigned_fixed(Tag::context(5), 1, 4).unwrap();
        assert!(e.unsigned_fixed(Tag::context(5), 0x100, 1).is_err(), "a value wider than the field must not be truncated");
        e.float32(Tag::context(7), 1.5).unwrap();
        e.bit_string(Tag::context(4), 3, &[0x40, 0x00]).unwrap();
        assert_eq!(e.as_bytes(), &[0x85, 4, 0, 0, 0, 1, 0x87, 5, 8, 0x3F, 0xC0, 0, 0, 0x84, 3, 3, 0x40, 0]);
    }

    #[test]
    fn fixed_width_fields_round_trip_through_the_lenient_reader() {
        // A field-width encoding sets the top bit without a leading zero octet — an
        // `smpCnt` of 40 000, or a fixed-length-GOOSE `INT32U` of 0xFFFF_FFFF. The strict
        // reader is right to refuse it as an ASN.1 INTEGER; the lenient one is what the
        // wire needs.
        let mut e = Encoder::new();
        e.unsigned_fixed(Tag::context(2), 40_000, 2).unwrap();
        e.unsigned_fixed(Tag::context(6), u64::from(u32::MAX), 4).unwrap();
        assert_eq!(e.as_bytes(), &[0x82, 2, 0x9C, 0x40, 0x86, 4, 0xFF, 0xFF, 0xFF, 0xFF]);
        let mut c = Cursor::new(e.as_bytes());
        let a = c.next_required().unwrap();
        assert_eq!(a.unsigned_lenient_u32().unwrap(), 40_000);
        assert!(a.unsigned_u32().is_err(), "the strict reader still refuses it");
        assert_eq!(c.next_required().unwrap().unsigned_lenient_u64().unwrap(), u64::from(u32::MAX));
    }

    impl Cursor<'_> {
        fn count_children(mut self) -> usize {
            let mut n = 0;
            while let Some(Ok(_)) = self.next() {
                n += 1;
            }
            n
        }
    }
}
