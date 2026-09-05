//! The layout of a sampled-value sample block: what the octets of an ASDU's `sample` mean.
//!
//! IEC 61850-9-2 does not tag the values inside an ASDU. The `sample` field is the data
//! set's members written back to back at the width of each one's `bType`, in data-set
//! order, and nothing on the wire says where one channel ends and the next begins. That is
//! what makes an ASDU a constant size and a merging unit's frame a patchable template — and
//! it is also why a subscriber cannot decode a stream it has not been told the shape of.
//!
//! 9-2LE fixes one shape ([`super::le::PhsMeas1`]: four currents and four voltages, each an
//! `INT32` and a quality word) and most implementations stop there. IEC 61869-9 does not
//! fix one: the data set is engineered, and the SCL file is what says what it holds. A
//! [`SampleLayout`] is that description, and
//! [`IedModel::sv_sample_layout`](crate::model::IedModel::sv_sample_layout) builds one
//! straight out of the file, so a merging unit with its own data set needs no special case
//! anywhere.

use alloc::string::String;
use alloc::vec::Vec;

use crate::common::{Error, Quality, Result, UtcTime};

/// What one channel of a sample block holds.
///
/// The widths are the ones IEC 61850-9-2 writes inside an ASDU, which are the widths of the
/// `bType` and not the widths of the tagged MMS encoding: `Quality` is the four-octet word,
/// not the thirteen-bit string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelType {
    /// One octet, non-zero is true.
    Boolean,
    /// Two's-complement signed integer of 1, 2, 3, 4 or 8 octets. A width outside 1..=8 is
    /// not a sampled-value integer and is clamped into that range by
    /// [`ChannelType::width`] rather than being allowed to shift past the end of a `u64`.
    Int(u8),
    /// Unsigned integer of 1, 2, 3, 4 or 8 octets, clamped the same way.
    Unsigned(u8),
    /// A four-octet signed enumeration.
    Enum,
    /// IEEE 754 single precision, four octets.
    Float32,
    /// IEEE 754 double precision, eight octets.
    Float64,
    /// The four-octet quality word (IEC 61850-7-3 bits from the most significant end).
    Quality,
    /// The eight-octet `Timestamp`.
    Timestamp,
}

impl ChannelType {
    /// Octets this channel occupies in the sample block, always 1..=8.
    ///
    /// The clamp is not cosmetic. Every reader here folds the channel's octets into a `u64`
    /// and then shifts by `64 - 8 * width`; a width of 0 or 9 shifts past the end of the
    /// register, which is a panic in a crate whose whole promise is that decoding cannot
    /// panic. The variants are public, so the guard belongs here rather than in a comment.
    pub const fn width(self) -> usize {
        match self {
            ChannelType::Boolean => 1,
            ChannelType::Int(w) | ChannelType::Unsigned(w) => {
                if w == 0 {
                    1
                } else if w > 8 {
                    8
                } else {
                    w as usize
                }
            }
            ChannelType::Enum | ChannelType::Float32 | ChannelType::Quality => 4,
            ChannelType::Float64 | ChannelType::Timestamp => 8,
        }
    }
}

/// One decoded channel value.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum ChannelValue {
    /// From [`ChannelType::Boolean`].
    Boolean(bool),
    /// From [`ChannelType::Int`] or [`ChannelType::Enum`].
    Int(i64),
    /// From [`ChannelType::Unsigned`].
    Unsigned(u64),
    /// From [`ChannelType::Float32`] or [`ChannelType::Float64`].
    Float(f64),
    /// From [`ChannelType::Quality`].
    Quality(Quality),
    /// From [`ChannelType::Timestamp`].
    Timestamp(UtcTime),
}

impl ChannelValue {
    /// The value as an `i64`, for the integer channels a merging unit actually sends.
    pub const fn as_i64(self) -> Option<i64> {
        match self {
            ChannelValue::Int(v) => Some(v),
            ChannelValue::Unsigned(v) if v <= i64::MAX as u64 => Some(v as i64),
            _ => None,
        }
    }

    /// The value as an `f64`, for a float channel.
    pub const fn as_f64(self) -> Option<f64> {
        match self {
            ChannelValue::Float(v) => Some(v),
            _ => None,
        }
    }

    /// The quality word, for a quality channel.
    pub const fn as_quality(self) -> Option<Quality> {
        match self {
            ChannelValue::Quality(q) => Some(q),
            _ => None,
        }
    }
}

/// One channel of a sample block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Channel {
    /// What the engineering file calls it — the data-set member's reference.
    pub name: String,
    /// What it holds.
    pub kind: ChannelType,
    /// First octet of the channel within the sample block.
    pub offset: usize,
}

/// The shape of one ASDU's sample block: its channels in data-set order.
///
/// Build one from an SCL data set with
/// [`IedModel::sv_sample_layout`](crate::model::IedModel::sv_sample_layout), or from the
/// channel types directly with [`SampleLayout::new`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SampleLayout {
    channels: Vec<Channel>,
    len: usize,
}

impl SampleLayout {
    /// A layout of `(name, kind)` pairs in data-set order; offsets follow from the widths.
    pub fn new(channels: impl IntoIterator<Item = (String, ChannelType)>) -> SampleLayout {
        let mut out = Vec::new();
        let mut offset = 0usize;
        for (name, kind) in channels {
            out.push(Channel { name, kind, offset });
            offset += kind.width();
        }
        SampleLayout { channels: out, len: offset }
    }

    /// Octets in one sample block — what [`super::SvProfile::sample_len`] has to be.
    // A layout with no channels describes nothing, so `is_empty` would be `channels`'.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// The channels, in data-set order.
    pub fn channels(&self) -> &[Channel] {
        &self.channels
    }

    /// True when the layout describes nothing.
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Read channel `i` out of a sample block.
    ///
    /// `None` if there is no such channel or the block is shorter than the layout says —
    /// a stream whose ASDU does not match the engineering file, which is a finding and not
    /// something to guess at.
    pub fn value(&self, sample: &[u8], i: usize) -> Option<ChannelValue> {
        let c = self.channels.get(i)?;
        let bytes = sample.get(c.offset..c.offset + c.kind.width())?;
        Some(read(c.kind, bytes))
    }

    /// Every channel of a sample block, in order.
    ///
    /// The iterator ends early if the block is short, so a truncated ASDU yields what it
    /// really holds rather than zeros.
    pub fn decode<'a>(&'a self, sample: &'a [u8]) -> impl Iterator<Item = (&'a Channel, ChannelValue)> + 'a {
        self.channels.iter().enumerate().map_while(move |(i, c)| self.value(sample, i).map(|v| (c, v)))
    }

    /// True when a block of `len` octets fits this layout exactly.
    pub const fn fits(&self, len: usize) -> bool {
        self.len == len
    }

    /// Write channel `i` into a sample block a publisher is building.
    ///
    /// The mirror of [`SampleLayout::value`]: a merging unit with an engineered data set
    /// fills its block through the same description the subscriber decodes it with, instead
    /// of hand-computing offsets on both sides.
    pub fn write(&self, sample: &mut [u8], i: usize, value: ChannelValue) -> Result<()> {
        let c = self.channels.get(i).ok_or(Error::InvalidValue("no such channel"))?;
        let width = c.kind.width();
        let slot = sample.get_mut(c.offset..c.offset + width).ok_or(Error::InvalidValue("sample block is shorter than the layout"))?;
        let bytes = match (c.kind, value) {
            (ChannelType::Boolean, ChannelValue::Boolean(b)) => u64::from(b).to_be_bytes(),
            (ChannelType::Int(_) | ChannelType::Enum, ChannelValue::Int(v)) => (v as u64).to_be_bytes(),
            (ChannelType::Unsigned(_), ChannelValue::Unsigned(v)) => v.to_be_bytes(),
            (ChannelType::Float32, ChannelValue::Float(v)) => {
                slot.copy_from_slice(&(v as f32).to_be_bytes());
                return Ok(());
            }
            (ChannelType::Float64, ChannelValue::Float(v)) => {
                slot.copy_from_slice(&v.to_be_bytes());
                return Ok(());
            }
            (ChannelType::Quality, ChannelValue::Quality(q)) => u64::from(q.to_bits_msb()).to_be_bytes(),
            (ChannelType::Timestamp, ChannelValue::Timestamp(t)) => {
                slot.copy_from_slice(&t.to_octets());
                return Ok(());
            }
            _ => return Err(Error::InvalidValue("value does not match the channel type")),
        };
        // The integer cases share one path: the low `width` octets, big-endian. A value that
        // does not fit is a fault, not something to truncate into a plausible sample.
        let (skip, kept) = bytes.split_at(8 - width);
        let sign_extension = if matches!(value, ChannelValue::Int(v) if v < 0) { 0xFF } else { 0x00 };
        if skip.iter().any(|b| *b != sign_extension) || (matches!(c.kind, ChannelType::Int(_) | ChannelType::Enum) && !fits_signed(bytes, width)) {
            return Err(Error::InvalidValue("value does not fit the channel width"));
        }
        slot.copy_from_slice(kept);
        Ok(())
    }
}

/// True when the two's-complement value in `bytes` survives truncation to `width` octets.
fn fits_signed(bytes: [u8; 8], width: usize) -> bool {
    match bytes.get(8 - width) {
        // The kept octets must already carry the sign of the discarded ones.
        Some(first) => {
            let negative = bytes.first().is_some_and(|b| b & 0x80 != 0);
            (first & 0x80 != 0) == negative
        }
        None => false,
    }
}

/// Read `bytes` (exactly `kind.width()` of them) as `kind`.
fn read(kind: ChannelType, bytes: &[u8]) -> ChannelValue {
    let unsigned = bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    match kind {
        ChannelType::Boolean => ChannelValue::Boolean(unsigned != 0),
        ChannelType::Int(_) => {
            // From the clamped width, never from the raw one: `64 - 8 * 9` underflows and
            // `64 - 8 * 0` shifts a `u64` by 64.
            let bits = 64 - 8 * (kind.width() as u32);
            ChannelValue::Int(((unsigned << bits) as i64) >> bits)
        }
        ChannelType::Enum => ChannelValue::Int(i64::from(unsigned as u32 as i32)),
        ChannelType::Unsigned(_) => ChannelValue::Unsigned(unsigned),
        ChannelType::Float32 => ChannelValue::Float(f64::from(f32::from_bits(unsigned as u32))),
        ChannelType::Float64 => ChannelValue::Float(f64::from_bits(unsigned)),
        ChannelType::Quality => ChannelValue::Quality(Quality::from_bits_msb(unsigned as u32)),
        ChannelType::Timestamp => {
            let mut o = [0u8; 8];
            o.copy_from_slice(&unsigned.to_be_bytes());
            ChannelValue::Timestamp(UtcTime::from_octets(o))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{TimeQuality, Validity};
    use crate::proto::sv::le::{PhsMeas1, SAMPLE_LEN};

    /// The 9-2LE data set, described the way an SCL file describes it.
    fn phs_meas1() -> SampleLayout {
        let mut ch = Vec::new();
        for name in ["Ia", "Ib", "Ic", "In", "Ua", "Ub", "Uc", "Un"] {
            ch.push((alloc::format!("{name}.instMag.i"), ChannelType::Int(4)));
            ch.push((alloc::format!("{name}.q"), ChannelType::Quality));
        }
        SampleLayout::new(ch)
    }

    #[test]
    fn a_channel_width_outside_the_range_is_clamped_rather_than_shifting_off_the_end() {
        // The variants are public, so a caller can build `Int(0)` or `Int(9)`. Every reader
        // shifts by `64 - 8 * width`, which panics for either — in a crate whose promise is
        // that decoding cannot panic.
        for kind in [ChannelType::Int(0), ChannelType::Int(9), ChannelType::Int(255), ChannelType::Unsigned(0), ChannelType::Unsigned(200)] {
            assert!((1..=8).contains(&kind.width()), "{kind:?} has width {}", kind.width());
            let layout = SampleLayout::new([(String::from("x"), kind)]);
            let block = alloc::vec![0xFFu8; 8];
            assert!(layout.value(&block, 0).is_some());
        }
        assert_eq!(SampleLayout::new([(String::from("x"), ChannelType::Int(0))]).value(&[0xFF], 0), Some(ChannelValue::Int(-1)));
    }

    #[test]
    fn the_layout_decodes_what_the_9_2le_struct_decodes() {
        // The generic path and the hard-coded 9-2LE one must agree octet for octet, or the
        // generic one is not a replacement for it.
        let layout = phs_meas1();
        assert_eq!(layout.len(), SAMPLE_LEN);
        assert!(layout.fits(SAMPLE_LEN));
        assert_eq!(layout.channels().len(), 16);

        let q = Quality { validity: Validity::Questionable, derived: true, ..Quality::GOOD };
        let block = PhsMeas1 {
            currents: [1, -2, 3, i32::MIN],
            current_quality: [Quality::GOOD, q, Quality::GOOD, Quality::GOOD],
            voltages: [100_000, -100_000, 0, i32::MAX],
            voltage_quality: [Quality::GOOD; 4],
        }
        .encode();

        let values: Vec<ChannelValue> = layout.decode(&block).map(|(_, v)| v).collect();
        assert_eq!(values.len(), 16);
        assert_eq!(values[0].as_i64(), Some(1));
        assert_eq!(values[2].as_i64(), Some(-2));
        assert_eq!(values[3].as_quality(), Some(q));
        assert_eq!(values[6].as_i64(), Some(i64::from(i32::MIN)));
        assert_eq!(values[8].as_i64(), Some(100_000));
        assert_eq!(values[14].as_i64(), Some(i64::from(i32::MAX)));
        assert_eq!(layout.channels()[2].name, "Ib.instMag.i");
        assert_eq!(layout.channels()[2].offset, 8);
    }

    #[test]
    fn a_block_shorter_than_the_layout_yields_what_it_holds() {
        let layout = phs_meas1();
        assert_eq!(layout.decode(&[0u8; 20]).count(), 5, "two channels and a half");
        assert_eq!(layout.value(&[0u8; 20], 5), None);
        assert!(!layout.fits(20));
    }

    #[test]
    fn every_width_round_trips_through_write_and_value() {
        let layout = SampleLayout::new([
            (String::from("b"), ChannelType::Boolean),
            (String::from("i8"), ChannelType::Int(1)),
            (String::from("i24"), ChannelType::Int(3)),
            (String::from("u16"), ChannelType::Unsigned(2)),
            (String::from("f32"), ChannelType::Float32),
            (String::from("f64"), ChannelType::Float64),
            (String::from("q"), ChannelType::Quality),
            (String::from("t"), ChannelType::Timestamp),
            (String::from("e"), ChannelType::Enum),
            (String::from("i64"), ChannelType::Int(8)),
        ]);
        assert_eq!(layout.len(), 1 + 1 + 3 + 2 + 4 + 8 + 4 + 8 + 4 + 8);
        let t = UtcTime::from_unix(1_700_000_000, 500_000_000, TimeQuality::SYNCHRONIZED);
        let written = [
            ChannelValue::Boolean(true),
            ChannelValue::Int(-128),
            ChannelValue::Int(-8_388_608),
            ChannelValue::Unsigned(65_535),
            ChannelValue::Float(1.5),
            ChannelValue::Float(-2.25),
            ChannelValue::Quality(Quality { validity: Validity::Invalid, ..Quality::GOOD }),
            ChannelValue::Timestamp(t),
            ChannelValue::Int(7),
            ChannelValue::Int(i64::MIN),
        ];
        let mut block = alloc::vec![0u8; layout.len()];
        for (i, v) in written.iter().enumerate() {
            layout.write(&mut block, i, *v).unwrap();
        }
        let read: Vec<ChannelValue> = layout.decode(&block).map(|(_, v)| v).collect();
        assert_eq!(read, written);
    }

    #[test]
    fn a_value_that_does_not_fit_is_refused_rather_than_truncated() {
        let layout = SampleLayout::new([(String::from("i16"), ChannelType::Int(2)), (String::from("u8"), ChannelType::Unsigned(1))]);
        let mut block = alloc::vec![0u8; layout.len()];
        assert!(layout.write(&mut block, 0, ChannelValue::Int(32_767)).is_ok());
        assert!(layout.write(&mut block, 0, ChannelValue::Int(-32_768)).is_ok());
        assert!(layout.write(&mut block, 0, ChannelValue::Int(32_768)).is_err(), "a sample must not wrap into a plausible value");
        assert!(layout.write(&mut block, 0, ChannelValue::Int(-32_769)).is_err());
        assert!(layout.write(&mut block, 1, ChannelValue::Unsigned(255)).is_ok());
        assert!(layout.write(&mut block, 1, ChannelValue::Unsigned(256)).is_err());
        // The type has to match, too: a float is not an integer channel.
        assert!(layout.write(&mut block, 0, ChannelValue::Float(1.0)).is_err());
        assert!(layout.write(&mut block, 9, ChannelValue::Int(0)).is_err(), "no such channel");
        assert!(layout.write(&mut [0u8; 1], 0, ChannelValue::Int(0)).is_err(), "block too short");
    }
}
