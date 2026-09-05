//! The ISO 9506 `Data` type as IEC 61850 encodes it in GOOSE `allData` and elsewhere:
//! zero-copy views for decoding, an owned [`Value`] for building, and the encoder.
//!
//! Both forms implement [`Typed`], which reads a decoded element as the IEC 61850-7-3 type
//! it claims to be and returns `None` rather than converting — an integer where a boolean
//! was engineered is a fault to report, not a number to coerce.
//!
//! Context tags (ISO 9506-2 `Data` CHOICE, with the IEC 61850-8-1 addition of `utc-time [17]`):
//! `array [1]`, `structure [2]`, `boolean [3]`, `bit-string [4]`, `integer [5]`, `unsigned [6]`,
//! `floating-point [7]`, `real [8]`, `octet-string [9]`, `visible-string [10]`,
//! `generalized-time [11]`, `binary-time [12]`, `bcd [13]`, `boolean-array [14]`,
//! `obj-id [15]`, `mms-string [16]`, `utc-time [17]`.
//!
//! The ones IEC 61850 actually puts in a data set have their own [`Value`] variant; the rest —
//! `real [8]` (ASN.1 REAL, which nothing emits), `bcd`, `boolean-array`, `obj-id`,
//! `generalized-time` — round-trip as [`Value::Other`] with their tag and octets, so a frame
//! carrying one still re-encodes exactly.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ber::{Cursor, Encoder, Float, Tag, Tlv};
use crate::common::{DecodeReason, Error, Limits, Quality, Result, UtcTime};

/// Tag numbers of the `Data` CHOICE.
pub mod tag {
    #![allow(missing_docs)]
    pub const ARRAY: u32 = 1;
    pub const STRUCTURE: u32 = 2;
    pub const BOOLEAN: u32 = 3;
    pub const BIT_STRING: u32 = 4;
    pub const INTEGER: u32 = 5;
    pub const UNSIGNED: u32 = 6;
    pub const FLOATING_POINT: u32 = 7;
    pub const OCTET_STRING: u32 = 9;
    pub const VISIBLE_STRING: u32 = 10;
    pub const GENERALIZED_TIME: u32 = 11;
    pub const BINARY_TIME: u32 = 12;
    pub const BCD: u32 = 13;
    pub const BOOLEAN_ARRAY: u32 = 14;
    pub const OBJ_ID: u32 = 15;
    pub const MMS_STRING: u32 = 16;
    pub const UTC_TIME: u32 = 17;
}

/// IEC 61850-7-3 `Dbpos`: the position of a double-point status, as the two-bit code the
/// wire carries.
///
/// It is its own type because the two intermediate codes are the interesting ones — a
/// disconnector that reports `Intermediate` is moving and `BadState` is broken, and an
/// implementation that reduces the pair to a `bool` throws exactly that away.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Dbpos {
    /// 0 — the two contacts disagree in the "both open" direction: in transit.
    #[default]
    Intermediate,
    /// 1 — open.
    Off,
    /// 2 — closed.
    On,
    /// 3 — the two contacts disagree in the "both closed" direction: faulty.
    BadState,
}

impl Dbpos {
    /// From the two-bit code.
    pub const fn from_code(code: u8) -> Dbpos {
        match code & 3 {
            0 => Dbpos::Intermediate,
            1 => Dbpos::Off,
            2 => Dbpos::On,
            _ => Dbpos::BadState,
        }
    }

    /// The two-bit code.
    pub const fn to_code(self) -> u8 {
        match self {
            Dbpos::Intermediate => 0,
            Dbpos::Off => 1,
            Dbpos::On => 2,
            Dbpos::BadState => 3,
        }
    }

    /// True only for [`Dbpos::On`]. The two disagreeing states are neither on nor off, and
    /// this is deliberately not `From<Dbpos> for bool`: the conversion has to be a decision
    /// the caller makes in the open.
    pub const fn is_on(self) -> bool {
        matches!(self, Dbpos::On)
    }
}

/// Reading a decoded value as the type IEC 61850-7-3 says it is.
///
/// [`Value`] and [`DataView`] both implement it, so the same code works on the owned form a
/// GOOSE state change hands over and on the borrowed form a zero-copy pass sees. Every
/// accessor returns `None` rather than converting: a `stVal` that arrived as an integer
/// where a boolean was engineered is a fault to report, not a number to coerce.
pub trait Typed {
    /// `boolean [3]`.
    fn as_bool(&self) -> Option<bool>;
    /// `integer [5]`.
    fn as_i64(&self) -> Option<i64>;
    /// `unsigned [6]`.
    fn as_u64(&self) -> Option<u64>;
    /// `floating-point [7]`, at either precision.
    fn as_f64(&self) -> Option<f64>;
    /// `visible-string [10]` or `mms-string [16]`.
    fn as_str(&self) -> Option<&str>;
    /// `utc-time [17]`.
    fn as_utc_time(&self) -> Option<UtcTime>;
    /// A `bit-string [4]` read as an IEC 61850-7-3 `Quality`.
    fn as_quality(&self) -> Option<Quality>;
    /// A `bit-string [4]` of two bits read as a [`Dbpos`].
    fn as_dbpos(&self) -> Option<Dbpos>;
}

/// A bit string read as an IEC 61850-7-3 `Quality`.
///
/// `Quality` is thirteen bits (fourteen with 9-2LE's `derived`), so it occupies two octets
/// and nothing shorter can be one. Refusing a one-octet bit string is what keeps a `Dbpos`
/// — two bits in one octet — from decoding as a quality whose validity happens to be the
/// position code, which is a coercion, not a read.
fn quality_of(bytes: &[u8]) -> Option<Quality> {
    (bytes.len() >= 2).then(|| Quality::from_octets(bytes))
}

/// The two-bit code of a `Dbpos`/`Tcmd` bit string: the most significant bits of the first
/// contents octet.
fn dbpos_code(unused: u8, bytes: &[u8]) -> Option<Dbpos> {
    // Exactly two significant bits in one octet. A wider bit string is a `Quality` or
    // something else, and reading its top two bits as a position would be an invention.
    match (unused, bytes) {
        (6, [b]) => Some(Dbpos::from_code(b >> 6)),
        _ => None,
    }
}

/// A borrowed view of one `Data` element.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DataView<'a> {
    /// `array [1]` — the members, as a cursor.
    Array(Cursor<'a>),
    /// `structure [2]` — the members, as a cursor.
    Structure(Cursor<'a>),
    /// `boolean [3]`.
    Boolean(bool),
    /// `bit-string [4]`: unused bits and contents.
    BitString {
        /// Unused bits in the last octet.
        unused: u8,
        /// The bit-string contents.
        bytes: &'a [u8],
    },
    /// `integer [5]`.
    Integer(i64),
    /// `unsigned [6]`.
    Unsigned(u64),
    /// `floating-point [7]`, single precision (5 contents octets).
    Float32(f32),
    /// `floating-point [7]`, double precision (9 contents octets).
    Float64(f64),
    /// `octet-string [9]`.
    OctetString(&'a [u8]),
    /// `visible-string [10]`.
    VisibleString(&'a str),
    /// `mms-string [16]` (UTF-8).
    MmsString(&'a str),
    /// `utc-time [17]`.
    UtcTime(UtcTime),
    /// `binary-time [12]` (4 or 6 octets, raw).
    BinaryTime(&'a [u8]),
    /// Any other choice, raw.
    Other(Tlv<'a>),
}

impl<'a> DataView<'a> {
    /// Decode one element.
    pub fn from_tlv(t: Tlv<'a>) -> Result<DataView<'a>> {
        if t.tag.class != crate::ber::Class::Context {
            return Err(Error::decode(DecodeReason::UnexpectedTag, t.offset));
        }
        Ok(match (t.tag.number, t.tag.constructed) {
            (tag::ARRAY, true) => DataView::Array(t.children()),
            (tag::STRUCTURE, true) => DataView::Structure(t.children()),
            (tag::BOOLEAN, false) => DataView::Boolean(t.boolean()?),
            (tag::BIT_STRING, false) => {
                let (unused, bytes) = t.bit_string()?;
                DataView::BitString { unused, bytes }
            }
            (tag::INTEGER, false) => DataView::Integer(t.integer_i64()?),
            (tag::UNSIGNED, false) => DataView::Unsigned(t.unsigned_lenient_u64()?),
            (tag::FLOATING_POINT, false) => match t.floating_point()? {
                Float::Single(f) => DataView::Float32(f),
                Float::Double(f) => DataView::Float64(f),
            },
            (tag::OCTET_STRING, false) => DataView::OctetString(t.value),
            (tag::VISIBLE_STRING, false) => DataView::VisibleString(t.visible_string()?),
            (tag::MMS_STRING, false) => DataView::MmsString(t.utf8_string()?),
            (tag::UTC_TIME, false) => DataView::UtcTime(t.utc_time()?),
            (tag::BINARY_TIME, false) => DataView::BinaryTime(t.value),
            _ => DataView::Other(t),
        })
    }

    /// The members of an `array [1]` or `structure [2]`, as a cursor.
    pub fn members(&self) -> Option<Cursor<'a>> {
        match self {
            DataView::Array(c) | DataView::Structure(c) => Some(*c),
            _ => None,
        }
    }

    /// Deep-copy into an owned [`Value`], enforcing `limits`.
    pub fn to_owned(&self, limits: &Limits) -> Result<Value> {
        self.to_owned_depth(limits, 0)
    }

    fn to_owned_depth(self, limits: &Limits, depth: usize) -> Result<Value> {
        if depth > limits.max_depth {
            return Err(Error::LimitExceeded { limit: "max_depth", value: depth });
        }
        Ok(match self {
            DataView::Array(c) | DataView::Structure(c) => {
                let members = collect_depth(c, limits, depth + 1)?;
                if matches!(self, DataView::Array(_)) { Value::Array(members) } else { Value::Structure(members) }
            }
            DataView::Boolean(b) => Value::Boolean(b),
            DataView::BitString { unused, bytes } => {
                check_len(bytes.len(), limits)?;
                Value::BitString { unused, bytes: bytes.to_vec() }
            }
            DataView::Integer(i) => Value::Integer(i),
            DataView::Unsigned(u) => Value::Unsigned(u),
            DataView::Float32(f) => Value::Float32(f),
            DataView::Float64(f) => Value::Float64(f),
            DataView::OctetString(b) => {
                check_len(b.len(), limits)?;
                Value::OctetString(b.to_vec())
            }
            DataView::VisibleString(s) => {
                check_len(s.len(), limits)?;
                Value::VisibleString(String::from(s))
            }
            DataView::MmsString(s) => {
                check_len(s.len(), limits)?;
                Value::MmsString(String::from(s))
            }
            DataView::UtcTime(t) => Value::UtcTime(t),
            DataView::BinaryTime(b) => {
                check_len(b.len(), limits)?;
                Value::BinaryTime(b.to_vec())
            }
            DataView::Other(t) => {
                check_len(t.value.len(), limits)?;
                Value::Other { tag: t.tag.number, constructed: t.tag.constructed, bytes: t.value.to_vec() }
            }
        })
    }
}

impl Typed for DataView<'_> {
    fn as_bool(&self) -> Option<bool> {
        match self {
            DataView::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            DataView::Integer(i) => Some(*i),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            DataView::Unsigned(u) => Some(*u),
            _ => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            DataView::Float32(f) => Some(f64::from(*f)),
            DataView::Float64(f) => Some(*f),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            DataView::VisibleString(s) | DataView::MmsString(s) => Some(s),
            _ => None,
        }
    }

    fn as_utc_time(&self) -> Option<UtcTime> {
        match self {
            DataView::UtcTime(t) => Some(*t),
            _ => None,
        }
    }

    fn as_quality(&self) -> Option<Quality> {
        match self {
            DataView::BitString { bytes, .. } => quality_of(bytes),
            _ => None,
        }
    }

    fn as_dbpos(&self) -> Option<Dbpos> {
        match self {
            DataView::BitString { unused, bytes } => dbpos_code(*unused, bytes),
            _ => None,
        }
    }
}

fn check_len(len: usize, limits: &Limits) -> Result<()> {
    if len > limits.max_primitive_len { Err(Error::LimitExceeded { limit: "max_primitive_len", value: len }) } else { Ok(()) }
}

/// Decode a cursor's elements into owned values, enforcing `limits`.
pub(crate) fn collect(c: Cursor<'_>, limits: &Limits) -> Result<Vec<Value>> {
    collect_depth(c, limits, 0)
}

fn collect_depth(c: Cursor<'_>, limits: &Limits, depth: usize) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for t in c {
        if out.len() >= limits.max_dataset_members {
            return Err(Error::LimitExceeded { limit: "max_dataset_members", value: out.len() + 1 });
        }
        out.push(DataView::from_tlv(t?)?.to_owned_depth(limits, depth)?);
    }
    Ok(out)
}

/// Decode a sequence of `Data` elements (e.g. a GOOSE `allData`) into owned values.
pub fn decode_all(bytes: &[u8], limits: &Limits) -> Result<Vec<Value>> {
    collect(Cursor::new(bytes), limits)
}

/// An owned `Data` value, for building frames and for applications that keep values.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `array [1]`.
    Array(Vec<Value>),
    /// `structure [2]`.
    Structure(Vec<Value>),
    /// `boolean [3]`.
    Boolean(bool),
    /// `bit-string [4]`.
    BitString {
        /// Unused bits in the last octet.
        unused: u8,
        /// Contents.
        bytes: Vec<u8>,
    },
    /// `integer [5]`.
    Integer(i64),
    /// `unsigned [6]`.
    Unsigned(u64),
    /// `floating-point [7]`, single precision on the wire (what IEC 61850 uses for
    /// `FLOAT32`, which is nearly everything).
    Float32(f32),
    /// `floating-point [7]`, double precision on the wire.
    Float64(f64),
    /// `octet-string [9]`.
    OctetString(Vec<u8>),
    /// `visible-string [10]`.
    VisibleString(String),
    /// `mms-string [16]`.
    MmsString(String),
    /// `utc-time [17]`.
    UtcTime(UtcTime),
    /// `binary-time [12]`.
    BinaryTime(Vec<u8>),
    /// Anything else, raw. `constructed` is kept so that a choice this crate does not know
    /// re-encodes exactly as it arrived — the byte-for-byte re-encoding of the reference
    /// captures is worth nothing if an unknown element quietly changes shape.
    Other {
        /// The context tag number.
        tag: u32,
        /// Whether the element was constructed.
        constructed: bool,
        /// The raw contents.
        bytes: Vec<u8>,
    },
}

impl Typed for Value {
    fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Unsigned(u) => Some(*u),
            _ => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float32(f) => Some(f64::from(*f)),
            Value::Float64(f) => Some(*f),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Value::VisibleString(s) | Value::MmsString(s) => Some(s),
            _ => None,
        }
    }

    fn as_utc_time(&self) -> Option<UtcTime> {
        match self {
            Value::UtcTime(t) => Some(*t),
            _ => None,
        }
    }

    fn as_quality(&self) -> Option<Quality> {
        match self {
            Value::BitString { bytes, .. } => quality_of(bytes),
            _ => None,
        }
    }

    fn as_dbpos(&self) -> Option<Dbpos> {
        match self {
            Value::BitString { unused, bytes } => dbpos_code(*unused, bytes),
            _ => None,
        }
    }
}

impl Value {
    /// An IEC 61850-7-3 `Quality` as the 13-bit bit string.
    pub fn quality(q: Quality) -> Value {
        Value::BitString { unused: 3, bytes: q.to_octets().to_vec() }
    }

    /// An IEC 61850-7-3 `Dbpos` as the two-bit bit string.
    pub fn dbpos(pos: Dbpos) -> Value {
        Value::BitString { unused: 6, bytes: alloc::vec![pos.to_code() << 6] }
    }

    /// The members of an `array [1]` or `structure [2]`.
    ///
    /// A data-set member is usually a structure — `Tr` as an `ACT` is `{general, q, t}` —
    /// so this plus [`Typed`] is what turns a decoded GOOSE data set into values without
    /// writing a `match` per field.
    pub fn members(&self) -> Option<&[Value]> {
        match self {
            Value::Array(m) | Value::Structure(m) => Some(m),
            _ => None,
        }
    }

    /// The `i`-th member of an array or structure.
    pub fn member(&self, i: usize) -> Option<&Value> {
        self.members()?.get(i)
    }

    /// Encode this value (with its context tag) into `e`.
    pub fn encode(&self, e: &mut Encoder) -> Result<()> {
        match self {
            Value::Array(m) | Value::Structure(m) => {
                let n = if matches!(self, Value::Array(_)) { tag::ARRAY } else { tag::STRUCTURE };
                e.constructed(Tag::context_constructed(n), |e| {
                    for v in m {
                        v.encode(e)?;
                    }
                    Ok(())
                })?;
            }
            Value::Boolean(b) => {
                e.boolean(Tag::context(tag::BOOLEAN), *b)?;
            }
            Value::BitString { unused, bytes } => {
                e.bit_string(Tag::context(tag::BIT_STRING), *unused, bytes)?;
            }
            Value::Integer(i) => {
                e.integer(Tag::context(tag::INTEGER), *i)?;
            }
            Value::Unsigned(u) => {
                e.unsigned(Tag::context(tag::UNSIGNED), *u)?;
            }
            Value::Float32(f) => {
                e.float32(Tag::context(tag::FLOATING_POINT), *f)?;
            }
            Value::Float64(f) => {
                e.float64(Tag::context(tag::FLOATING_POINT), *f)?;
            }
            Value::OctetString(b) => {
                e.primitive(Tag::context(tag::OCTET_STRING), b)?;
            }
            Value::VisibleString(s) => {
                e.visible_string(Tag::context(tag::VISIBLE_STRING), s)?;
            }
            Value::MmsString(s) => {
                e.primitive(Tag::context(tag::MMS_STRING), s.as_bytes())?;
            }
            Value::UtcTime(t) => {
                e.utc_time(Tag::context(tag::UTC_TIME), *t)?;
            }
            Value::BinaryTime(b) => {
                e.primitive(Tag::context(tag::BINARY_TIME), b)?;
            }
            Value::Other { tag: n, constructed, bytes } => {
                let tag = if *constructed { Tag::context_constructed(*n) } else { Tag::context(*n) };
                e.primitive(tag, bytes)?;
            }
        }
        Ok(())
    }

    /// Encode a list of values back to back (a GOOSE `allData` body).
    pub fn encode_all(values: &[Value]) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        for v in values {
            v.encode(&mut e)?;
        }
        Ok(e.into_vec())
    }
}

/// The [`Value`] conversions for the IEC 61850-7-2 packed option types.
///
/// The types themselves live in [`crate::common`] — three layers need them and only one of
/// those is MMS — but a bit string is only a `Value` where `Value` exists, so the conversion
/// lives here rather than dragging `proto::data` into `common`.
macro_rules! packed_value {
    ($($t:ty),+) => {
        $(
            impl $t {
                /// The bit string as a [`Value`], ready to write into a control block.
                pub fn to_value(self) -> Value {
                    let (unused, bytes) = self.to_bit_string();
                    Value::BitString { unused, bytes }
                }

                /// Read from a decoded [`Value`], which must be a bit string.
                pub fn from_value(v: &Value) -> Option<Self> {
                    match v {
                        Value::BitString { bytes, .. } => Some(Self::from_bit_string(bytes)),
                        _ => None,
                    }
                }
            }
        )+
    };
}

packed_value!(crate::common::OptFlds, crate::common::TrgOps, crate::common::ReasonCode);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let values = alloc::vec![
            Value::Boolean(true),
            Value::quality(Quality::GOOD),
            Value::Integer(-5),
            Value::Unsigned(300),
            Value::Float32(2.5),
            Value::Float64(-1.5),
            Value::VisibleString(String::from("SEL")),
            Value::UtcTime(UtcTime::default()),
            Value::Structure(alloc::vec![Value::Boolean(false), Value::dbpos(Dbpos::On)]),
            Value::OctetString(alloc::vec![1, 2, 3]),
        ];
        let bytes = Value::encode_all(&values).unwrap();
        assert_eq!(decode_all(&bytes, &Limits::DEFAULT).unwrap(), values, "every value must survive a round trip unchanged");
    }

    #[test]
    fn typed_accessors_read_what_is_there_and_nothing_else() {
        let t = UtcTime::from_unix(1_700_000_000, 0, crate::common::TimeQuality::SYNCHRONIZED);
        // A data-set member as a `DPC`-shaped structure: position, quality, timestamp.
        let pos = Value::Structure(alloc::vec![Value::dbpos(Dbpos::On), Value::quality(Quality::GOOD), Value::UtcTime(t)]);
        assert_eq!(pos.member(0).and_then(Typed::as_dbpos), Some(Dbpos::On));
        assert_eq!(pos.member(1).and_then(Typed::as_quality), Some(Quality::GOOD));
        assert_eq!(pos.member(2).and_then(Typed::as_utc_time), Some(t));
        assert_eq!(pos.members().map(<[Value]>::len), Some(3));
        assert!(pos.as_bool().is_none(), "a structure is not a boolean");

        // Nothing is coerced. An integer where a boolean was engineered is a fault to
        // report, not a number to reinterpret.
        assert_eq!(Value::Integer(1).as_bool(), None);
        assert_eq!(Value::Boolean(true).as_i64(), None);
        assert_eq!(Value::Unsigned(7).as_i64(), None);
        // Both float widths read back as `f64`, because the width is a wire detail.
        assert_eq!(Value::Float32(1.5).as_f64(), Some(1.5));
        assert_eq!(Value::Float64(1.5).as_f64(), Some(1.5));
        assert_eq!(Value::VisibleString(String::from("SEL")).as_str(), Some("SEL"));

        // A `Quality` bit string is thirteen bits and a `Dbpos` is two: neither reads as
        // the other, so a mislabelled member cannot silently decode in either direction.
        assert_eq!(Value::quality(Quality::GOOD).as_dbpos(), None);
        assert_eq!(Value::dbpos(Dbpos::On).as_quality(), None, "two bits are not a quality");

        // And the same accessors on the borrowed view, over the encoded bytes.
        let bytes = Value::encode_all(&[pos]).unwrap();
        let member = DataView::from_tlv(Cursor::new(&bytes).next_required().unwrap()).unwrap();
        let mut fields = member.members().unwrap();
        let first = DataView::from_tlv(fields.next_required().unwrap()).unwrap();
        assert_eq!(first.as_dbpos(), Some(Dbpos::On));
        let second = DataView::from_tlv(fields.next_required().unwrap()).unwrap();
        assert_eq!(second.as_quality(), Some(Quality::GOOD));
    }

    #[test]
    fn dbpos_keeps_the_two_states_a_bool_would_lose() {
        for pos in [Dbpos::Intermediate, Dbpos::Off, Dbpos::On, Dbpos::BadState] {
            assert_eq!(Value::dbpos(pos).as_dbpos(), Some(pos));
            assert_eq!(Dbpos::from_code(pos.to_code()), pos);
        }
        assert!(Dbpos::On.is_on());
        assert!(!Dbpos::BadState.is_on(), "a disconnector reporting both contacts closed is not closed");
        assert!(!Dbpos::Intermediate.is_on(), "one in transit is not closed either");
    }

    #[test]
    fn limits_are_enforced() {
        let deep = (0..40).fold(Value::Boolean(true), |v, _| Value::Structure(alloc::vec![v]));
        let bytes = Value::encode_all(&[deep]).unwrap();
        assert!(matches!(decode_all(&bytes, &Limits::DEFAULT), Err(Error::LimitExceeded { limit: "max_depth", .. })));
        let many: Vec<Value> = (0..600).map(|_| Value::Boolean(true)).collect();
        let bytes = Value::encode_all(&many).unwrap();
        assert!(matches!(decode_all(&bytes, &Limits::DEFAULT), Err(Error::LimitExceeded { limit: "max_dataset_members", .. })));
    }
}
