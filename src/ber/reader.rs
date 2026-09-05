use super::{Class, Float, Tag};
use crate::common::{DecodeReason, Error, Result, UtcTime};

/// One decoded element: its tag, its contents, and where it sits in the buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The tag.
    pub tag: Tag,
    /// The contents octets.
    pub value: &'a [u8],
    /// Offset of the identifier octet from the start of the outermost buffer.
    pub offset: usize,
    /// Offset of the first contents octet.
    pub value_offset: usize,
}

impl<'a> Tlv<'a> {
    /// Length of the whole element (identifier + length + contents).
    pub fn total_len(&self) -> usize {
        self.value_offset.saturating_sub(self.offset).saturating_add(self.value.len())
    }

    /// A cursor over the contents, for constructed elements.
    pub fn children(&self) -> Cursor<'a> {
        Cursor { buf: self.value, pos: 0, base: self.value_offset }
    }

    /// Fail unless the tag is `expected`.
    pub fn expect(self, expected: Tag) -> Result<Self> {
        if self.tag == expected { Ok(self) } else { Err(Error::decode(DecodeReason::UnexpectedTag, self.offset)) }
    }

    /// Two's-complement INTEGER (1–8 contents octets).
    pub fn integer_i64(&self) -> Result<i64> {
        let v = self.value;
        if v.is_empty() || v.len() > 8 {
            return Err(Error::decode(DecodeReason::BadValue, self.value_offset));
        }
        let mut acc: i64 = if v.first().is_some_and(|b| b & 0x80 != 0) { -1 } else { 0 };
        for b in v {
            acc = (acc << 8) | i64::from(*b);
        }
        Ok(acc)
    }

    /// INTEGER that must fit in `i32`.
    pub fn integer_i32(&self) -> Result<i32> {
        let v = self.integer_i64()?;
        i32::try_from(v).map_err(|_| Error::decode(DecodeReason::BadValue, self.value_offset))
    }

    /// Unsigned INTEGER (1–5 contents octets; a leading zero octet is allowed for values
    /// with the top bit set).
    pub fn unsigned_u32(&self) -> Result<u32> {
        let v = self.unsigned_u64()?;
        u32::try_from(v).map_err(|_| Error::decode(DecodeReason::BadValue, self.value_offset))
    }

    /// Unsigned INTEGER up to `u64`.
    pub fn unsigned_u64(&self) -> Result<u64> {
        let v = self.value;
        let first = *v.first().ok_or(Error::decode(DecodeReason::BadValue, self.value_offset))?;
        if v.len() > 9 || (v.len() == 9 && first != 0) || first & 0x80 != 0 {
            return Err(Error::decode(DecodeReason::BadValue, self.value_offset));
        }
        let mut acc: u64 = 0;
        for b in v {
            acc = (acc << 8) | u64::from(*b);
        }
        Ok(acc)
    }

    /// Unsigned INTEGER read leniently: up to 8 contents octets taken as big-endian
    /// unsigned **regardless of the top bit**, plus an optional leading zero octet.
    ///
    /// This is what the field actually emits and what Wireshark reads. Two encodings make
    /// it necessary. Sampled-value publishers write `smpCnt` and `confRev` at a fixed width
    /// so that a subscriber (and our own template patcher) can find them at a constant
    /// offset, and libiec61850 does the same; and fixed-length encoded GOOSE
    /// (IEC 61850-8-1 Ed 2.1, `GSEControl.fixedOffs`) writes *every* integer at the width
    /// of its `bType`, so an `INT32U` above `0x7FFF_FFFF` arrives as four octets with the
    /// top bit set. A strict reader rejects both, and would be rejecting real traffic.
    pub fn unsigned_lenient_u64(&self) -> Result<u64> {
        let v = match self.value {
            [0, rest @ ..] if rest.len() == 8 => rest,
            v if !v.is_empty() && v.len() <= 8 => v,
            _ => return Err(Error::decode(DecodeReason::BadValue, self.value_offset)),
        };
        let mut acc: u64 = 0;
        for b in v {
            acc = (acc << 8) | u64::from(*b);
        }
        Ok(acc)
    }

    /// [`Tlv::unsigned_lenient_u64`] narrowed to `u32`.
    pub fn unsigned_lenient_u32(&self) -> Result<u32> {
        u32::try_from(self.unsigned_lenient_u64()?).map_err(|_| Error::decode(DecodeReason::BadValue, self.value_offset))
    }

    /// BOOLEAN (exactly one contents octet; any non-zero is true, as BER allows).
    pub fn boolean(&self) -> Result<bool> {
        match self.value {
            [b] => Ok(*b != 0),
            _ => Err(Error::decode(DecodeReason::BadValue, self.value_offset)),
        }
    }

    /// BIT STRING: `(unused_bits, contents)`.
    pub fn bit_string(&self) -> Result<(u8, &'a [u8])> {
        match self.value {
            [unused, rest @ ..] if *unused <= 7 && (!rest.is_empty() || *unused == 0) => Ok((*unused, rest)),
            _ => Err(Error::decode(DecodeReason::BadValue, self.value_offset)),
        }
    }

    /// The contents as a `VisibleString` (must be ASCII).
    pub fn visible_string(&self) -> Result<&'a str> {
        if self.value.is_ascii() {
            core::str::from_utf8(self.value).map_err(|_| Error::decode(DecodeReason::NotAscii, self.value_offset))
        } else {
            Err(Error::decode(DecodeReason::NotAscii, self.value_offset))
        }
    }

    /// The contents as UTF-8 (`MMSString`).
    pub fn utf8_string(&self) -> Result<&'a str> {
        core::str::from_utf8(self.value).map_err(|_| Error::decode(DecodeReason::BadValue, self.value_offset))
    }

    /// ISO 9506 `FloatingPoint`: one exponent-width octet followed by an IEEE 754 value.
    /// Exponent width 8 is single precision (5 octets), width 11 double (9 octets). The
    /// precision is part of the answer so that a value can be re-encoded as it arrived.
    pub fn floating_point(&self) -> Result<Float> {
        match self.value {
            [8, a, b, c, d] => Ok(Float::Single(f32::from_be_bytes([*a, *b, *c, *d]))),
            [11, rest @ ..] if rest.len() == 8 => {
                let mut o = [0u8; 8];
                o.copy_from_slice(rest);
                Ok(Float::Double(f64::from_be_bytes(o)))
            }
            _ => Err(Error::decode(DecodeReason::BadValue, self.value_offset)),
        }
    }

    /// `FloatingPoint` that must be single precision.
    pub fn float32(&self) -> Result<f32> {
        match self.floating_point()? {
            Float::Single(f) => Ok(f),
            Float::Double(_) => Err(Error::decode(DecodeReason::BadValue, self.value_offset)),
        }
    }

    /// IEC 61850 `UtcTime` (8 octets).
    pub fn utc_time(&self) -> Result<UtcTime> {
        match <[u8; 8]>::try_from(self.value) {
            Ok(o) => Ok(UtcTime::from_octets(o)),
            Err(_) => Err(Error::decode(DecodeReason::BadValue, self.value_offset)),
        }
    }
}

/// A cursor over a sequence of BER elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor over `buf`, reporting offsets relative to its start.
    pub const fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0, base: 0 }
    }

    /// True when every byte has been consumed.
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Offset (in the outermost buffer) of the next element.
    pub const fn offset(&self) -> usize {
        self.base.saturating_add(self.pos)
    }

    /// The unread remainder.
    pub fn remaining(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// Decode the next element; error if there is none.
    pub fn next_required(&mut self) -> Result<Tlv<'a>> {
        self.next().unwrap_or(Err(Error::decode(DecodeReason::MissingField, self.offset())))
    }

    /// Decode the next element and fail unless it carries `tag`.
    pub fn next_tag(&mut self, tag: Tag) -> Result<Tlv<'a>> {
        self.next_required()?.expect(tag)
    }

    /// Peek at the next element's tag without consuming it.
    pub fn peek_tag(&self) -> Option<Tag> {
        let mut c = *self;
        c.next().and_then(Result::ok).map(|t| t.tag)
    }

    /// If the next element carries `tag`, consume and return it.
    pub fn next_if_tag(&mut self, tag: Tag) -> Result<Option<Tlv<'a>>> {
        if self.peek_tag() == Some(tag) { self.next_required().map(Some) } else { Ok(None) }
    }

    /// Fail if anything is left.
    pub fn finish(&self) -> Result<()> {
        if self.is_empty() { Ok(()) } else { Err(Error::decode(DecodeReason::TrailingBytes, self.offset())) }
    }

    fn next_inner(&mut self) -> Result<Tlv<'a>> {
        let start = self.pos;
        let abs = |p: usize| self.base.saturating_add(p);
        let first = *self.buf.get(self.pos).ok_or(Error::decode(DecodeReason::Truncated, abs(self.pos)))?;
        self.pos += 1;
        let class = match first >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::Context,
            _ => Class::Private,
        };
        let constructed = first & 0x20 != 0;
        let mut number = u32::from(first & 0x1F);
        if number == 31 {
            // High tag number form: base-128, most significant group first, continuation bit
            // set on every group but the last. The first group may not be `0x80` (that is a
            // non-minimal encoding of a number that fits a shorter form) and the accumulator
            // must actually be checked for overflow — `checked_shl(7)` never fails on a `u32`
            // and so checks nothing.
            number = 0;
            let mut groups = 0u32;
            loop {
                let b = *self.buf.get(self.pos).ok_or(Error::decode(DecodeReason::Truncated, abs(self.pos)))?;
                self.pos += 1;
                if groups == 0 && b == 0x80 {
                    return Err(Error::decode(DecodeReason::BadValue, abs(start)));
                }
                if number > u32::MAX >> 7 {
                    return Err(Error::decode(DecodeReason::BadValue, abs(start)));
                }
                number = (number << 7) | u32::from(b & 0x7F);
                groups += 1;
                if b & 0x80 == 0 {
                    break;
                }
                if groups >= 5 {
                    return Err(Error::decode(DecodeReason::BadValue, abs(start)));
                }
            }
            if number < 31 {
                // A number below 31 has a one-octet form, so the long one is not minimal.
                return Err(Error::decode(DecodeReason::BadValue, abs(start)));
            }
        }
        let len_first = *self.buf.get(self.pos).ok_or(Error::decode(DecodeReason::Truncated, abs(self.pos)))?;
        self.pos += 1;
        let len = if len_first < 0x80 {
            usize::from(len_first)
        } else {
            let n = usize::from(len_first & 0x7F);
            if n == 0 {
                return Err(Error::decode(DecodeReason::IndefiniteLength, abs(self.pos - 1)));
            }
            if n > 4 {
                return Err(Error::decode(DecodeReason::BadLength, abs(self.pos - 1)));
            }
            let bytes = self.buf.get(self.pos..self.pos + n).ok_or(Error::decode(DecodeReason::Truncated, abs(self.pos)))?;
            self.pos += n;
            let mut l: usize = 0;
            for b in bytes {
                l = (l << 8) | usize::from(*b);
            }
            l
        };
        let value_offset = self.pos;
        let value = self.buf.get(self.pos..self.pos.saturating_add(len)).ok_or(Error::decode(DecodeReason::Truncated, abs(value_offset)))?;
        self.pos += len;
        Ok(Tlv { tag: Tag { class, constructed, number }, value, offset: abs(start), value_offset: abs(value_offset) })
    }
}

/// A cursor yields the elements it decodes; a malformed element yields one `Err` and then
/// the iterator ends, so a caller that ignores errors cannot loop forever.
///
/// The cursor is `Copy` on purpose: copying one and reading ahead is how [`Cursor::peek_tag`]
/// works, and the copy advancing independently is the wanted behaviour, not a surprise.
#[allow(clippy::copy_iterator)]
impl<'a> Iterator for Cursor<'a> {
    type Item = Result<Tlv<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_empty() {
            return None;
        }
        let r = self.next_inner();
        if r.is_err() {
            // Stop: the remaining bytes cannot be framed.
            self.pos = self.buf.len();
        }
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_and_long_lengths() {
        let mut c = Cursor::new(&[0x85, 0x01, 0x07, 0x8A, 0x81, 0x03, b'a', b'b', b'c']);
        let a = c.next_required().unwrap();
        assert_eq!(a.tag, Tag::context(5));
        assert_eq!(a.integer_i64().unwrap(), 7);
        let s = c.next_required().unwrap();
        assert_eq!(s.visible_string().unwrap(), "abc");
        assert_eq!(s.total_len(), 6);
        assert!(c.is_empty());
        c.finish().unwrap();
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(Cursor::new(&[0x85, 0x80]).next_required().unwrap_err(), Error::decode(DecodeReason::IndefiniteLength, 1));
        assert_eq!(Cursor::new(&[0x85, 0x05, 0x01]).next_required().unwrap_err(), Error::decode(DecodeReason::Truncated, 2));
        assert_eq!(Cursor::new(&[0x85]).next_required().unwrap_err(), Error::decode(DecodeReason::Truncated, 1));
        assert!(Cursor::new(&[0x85, 0x00]).next_required().unwrap().integer_i64().is_err());
        assert!(Cursor::new(&[0x86, 0x01, 0xFF]).next_required().unwrap().unsigned_u32().is_err());
        assert!(Cursor::new(&[0x87, 0x03, 0x08, 0, 0]).next_required().unwrap().float32().is_err());
    }

    #[test]
    fn integers_and_floats() {
        let t = Cursor::new(&[0x85, 0x02, 0xFF, 0x00]).next_required().unwrap();
        assert_eq!(t.integer_i64().unwrap(), -256);
        let u = Cursor::new(&[0x86, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]).next_required().unwrap();
        assert_eq!(u.unsigned_u32().unwrap(), u32::MAX);
        let f = Cursor::new(&[0x87, 0x05, 0x08, 0x3F, 0x80, 0x00, 0x00]).next_required().unwrap();
        assert!((f.float32().unwrap() - 1.0).abs() < f32::EPSILON);
        let d = Cursor::new(&[0x87, 0x09, 0x0B, 0x3F, 0xF0, 0, 0, 0, 0, 0, 0]).next_required().unwrap();
        assert_eq!(d.floating_point().unwrap(), Float::Double(1.0));
        assert!(d.float32().is_err(), "a double must not silently narrow");
    }

    #[test]
    fn high_tag_numbers() {
        let mut c = Cursor::new(&[0x9F, 0x21, 0x01, 0x01]);
        assert_eq!(c.next_required().unwrap().tag, Tag::context(33));
        // The MMS services above 30 live here: `readJournal [65]` is `BF 41`, `fileOpen [72]`
        // is `BF 48`, and `fileRead [73]` is primitive, `9F 49`.
        assert_eq!(Cursor::new(&[0xBF, 0x41, 0x00]).next_required().unwrap().tag, Tag::context_constructed(65));
        assert_eq!(Cursor::new(&[0x9F, 0x49, 0x01, 0x02]).next_required().unwrap().tag, Tag::context(73));
    }

    #[test]
    fn a_tag_number_that_does_not_fit_is_refused_rather_than_wrapped() {
        // Five groups of seven bits is 35, and the number is a `u32`: the old check used
        // `checked_shl(7)`, which never fails, so `9F FF FF FF FF 7F` decoded as a wrapped
        // tag number and two different tags compared equal.
        assert!(Cursor::new(&[0x9F, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00]).next_required().is_err());
        // Six groups is a tag number nothing can represent, and it must stop rather than
        // read on into the length octet.
        assert!(Cursor::new(&[0x9F, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00]).next_required().is_err());
        // Non-minimal forms: a leading `0x80` group, and a number that fits the short form.
        assert!(Cursor::new(&[0x9F, 0x80, 0x21, 0x00]).next_required().is_err());
        assert!(Cursor::new(&[0x9F, 0x05, 0x00]).next_required().is_err());
    }
}
