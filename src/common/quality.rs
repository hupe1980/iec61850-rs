/// The `validity` component of [`Quality`] (IEC 61850-7-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Validity {
    /// Good.
    #[default]
    Good,
    /// Invalid.
    Invalid,
    /// Reserved value (2) — never emitted, accepted on decode.
    Reserved,
    /// Questionable.
    Questionable,
}

/// The `source` component of [`Quality`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Source {
    /// Value comes from the process.
    #[default]
    Process,
    /// Value was substituted.
    Substituted,
}

/// IEC 61850-7-3 `Quality`: the 13-bit packed bit string, plus the 14th bit `derived`
/// that the 9-2LE guideline adds for sampled values.
///
/// Bit numbering follows the standard (bit 0 is the most significant bit of the first
/// octet): 0–1 validity, 2 overflow, 3 outOfRange, 4 badReference, 5 oscillatory,
/// 6 failure, 7 oldData, 8 inconsistent, 9 inaccurate, 10 source, 11 test,
/// 12 operatorBlocked, 13 derived (9-2LE).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Quality {
    /// Validity.
    pub validity: Validity,
    /// Overflow.
    pub overflow: bool,
    /// Out of range.
    pub out_of_range: bool,
    /// Bad reference.
    pub bad_reference: bool,
    /// Oscillatory.
    pub oscillatory: bool,
    /// Failure.
    pub failure: bool,
    /// Old data.
    pub old_data: bool,
    /// Inconsistent.
    pub inconsistent: bool,
    /// Inaccurate.
    pub inaccurate: bool,
    /// Source.
    pub source: Source,
    /// Test.
    pub test: bool,
    /// Operator blocked.
    pub operator_blocked: bool,
    /// Derived (9-2LE, sampled values only).
    pub derived: bool,
}

impl Quality {
    /// Good quality, no flags.
    pub const GOOD: Quality = Quality {
        validity: Validity::Good,
        overflow: false,
        out_of_range: false,
        bad_reference: false,
        oscillatory: false,
        failure: false,
        old_data: false,
        inconsistent: false,
        inaccurate: false,
        source: Source::Process,
        test: false,
        operator_blocked: false,
        derived: false,
    };

    /// Number of significant bits without `derived` (IEC 61850-7-3).
    pub const BITS: u8 = 13;
    /// Number of significant bits with `derived` (9-2LE sampled values).
    pub const BITS_SV: u8 = 14;

    /// Pack into an integer whose bit 31 is quality bit 0 (the layout of the first octets
    /// of the BER bit string and of the 32-bit quality word in 9-2LE sample data).
    pub const fn to_bits_msb(self) -> u32 {
        let validity = match self.validity {
            Validity::Good => 0,
            Validity::Invalid => 1,
            Validity::Reserved => 2,
            Validity::Questionable => 3,
        };
        let mut v: u32 = validity << 30;
        macro_rules! bit {
            ($field:expr, $n:expr) => {
                if $field {
                    v |= 1 << (31 - $n);
                }
            };
        }
        bit!(self.overflow, 2);
        bit!(self.out_of_range, 3);
        bit!(self.bad_reference, 4);
        bit!(self.oscillatory, 5);
        bit!(self.failure, 6);
        bit!(self.old_data, 7);
        bit!(self.inconsistent, 8);
        bit!(self.inaccurate, 9);
        bit!(matches!(self.source, Source::Substituted), 10);
        bit!(self.test, 11);
        bit!(self.operator_blocked, 12);
        bit!(self.derived, 13);
        v
    }

    /// Unpack from the layout produced by [`Quality::to_bits_msb`].
    pub const fn from_bits_msb(v: u32) -> Quality {
        const fn bit(v: u32, n: u32) -> bool {
            (v >> (31 - n)) & 1 == 1
        }
        Quality {
            validity: match v >> 30 {
                0 => Validity::Good,
                1 => Validity::Invalid,
                2 => Validity::Reserved,
                _ => Validity::Questionable,
            },
            overflow: bit(v, 2),
            out_of_range: bit(v, 3),
            bad_reference: bit(v, 4),
            oscillatory: bit(v, 5),
            failure: bit(v, 6),
            old_data: bit(v, 7),
            inconsistent: bit(v, 8),
            inaccurate: bit(v, 9),
            source: if bit(v, 10) { Source::Substituted } else { Source::Process },
            test: bit(v, 11),
            operator_blocked: bit(v, 12),
            derived: bit(v, 13),
        }
    }

    /// The two octets of the BER bit-string contents (without the unused-bits octet), for
    /// the 13-bit MMS encoding.
    pub const fn to_octets(self) -> [u8; 2] {
        let v = self.to_bits_msb() & !(1 << (31 - 13));
        [(v >> 24) as u8, (v >> 16) as u8]
    }

    /// Decode from up to four bit-string content octets (bit 0 = MSB of the first octet).
    pub fn from_octets(octets: &[u8]) -> Quality {
        let mut v: u32 = 0;
        for (i, b) in octets.iter().take(4).enumerate() {
            v |= u32::from(*b) << (24 - 8 * i);
        }
        Quality::from_bits_msb(v)
    }

    /// True if validity is `Good` and no flag other than `derived` is set.
    pub const fn is_good(self) -> bool {
        matches!(self.validity, Validity::Good) && (self.to_bits_msb() & !(1 << (31 - 13))) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bits() {
        let q = Quality { validity: Validity::Questionable, test: true, derived: true, ..Quality::GOOD };
        let v = q.to_bits_msb();
        assert_eq!(v >> 30, 3);
        assert_eq!(Quality::from_bits_msb(v), q);
        assert_eq!(Quality::from_octets(&q.to_octets()), Quality { derived: false, ..q });
        assert!(Quality::GOOD.is_good());
        assert!(!q.is_good());
        assert!(Quality { derived: true, ..Quality::GOOD }.is_good());
    }
}
