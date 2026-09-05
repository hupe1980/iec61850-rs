use core::fmt;

/// The quality octet of an IEC 61850 `Timestamp` (IEC 61850-7-2 §6.2.3.7 / 8-1 §8.1.3.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeQuality {
    /// Leap seconds are known (the clock is UTC, not TAI-offset-unknown).
    pub leap_seconds_known: bool,
    /// The clock has failed.
    pub clock_failure: bool,
    /// The clock is not synchronised to an external reference.
    pub clock_not_synchronized: bool,
    /// Number of significant bits in the fraction (0..=24); 31 = unspecified.
    pub accuracy: u8,
}

impl TimeQuality {
    /// Synchronised, leap seconds known, accuracy unspecified.
    pub const SYNCHRONIZED: TimeQuality =
        TimeQuality { leap_seconds_known: true, clock_failure: false, clock_not_synchronized: false, accuracy: TimeQuality::ACCURACY_UNSPECIFIED };
    /// Not synchronised, leap seconds unknown.
    pub const UNSYNCHRONIZED: TimeQuality =
        TimeQuality { leap_seconds_known: false, clock_failure: false, clock_not_synchronized: true, accuracy: TimeQuality::ACCURACY_UNSPECIFIED };
    /// The `accuracy` value meaning "unspecified".
    pub const ACCURACY_UNSPECIFIED: u8 = 31;

    /// Pack into the quality octet.
    pub const fn to_octet(self) -> u8 {
        (if self.leap_seconds_known { 0x80 } else { 0 })
            | (if self.clock_failure { 0x40 } else { 0 })
            | (if self.clock_not_synchronized { 0x20 } else { 0 })
            | (self.accuracy & 0x1F)
    }

    /// Unpack from the quality octet.
    pub const fn from_octet(b: u8) -> TimeQuality {
        TimeQuality { leap_seconds_known: b & 0x80 != 0, clock_failure: b & 0x40 != 0, clock_not_synchronized: b & 0x20 != 0, accuracy: b & 0x1F }
    }
}

impl Default for TimeQuality {
    fn default() -> Self {
        TimeQuality::UNSYNCHRONIZED
    }
}

/// IEC 61850 `Timestamp` as encoded on the wire: 32-bit seconds since 1970-01-01 00:00:00
/// UTC, a 24-bit binary fraction of a second, and a quality octet. Eight octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct UtcTime {
    /// Seconds since the Unix epoch.
    pub seconds: u32,
    /// Fraction of a second in units of 2⁻²⁴ s (only the low 24 bits are significant).
    pub fraction: u32,
    /// Quality.
    pub quality: TimeQuality,
}

impl UtcTime {
    /// Build from Unix seconds and nanoseconds within the second.
    ///
    /// A `nanos` of a second or more carries into `seconds` rather than wrapping the
    /// fraction: masking it off would turn a caller's off-by-one into a timestamp a whole
    /// second wrong, silently, in the one field a protection engineer reads first.
    pub const fn from_unix(seconds: u32, nanos: u32, quality: TimeQuality) -> UtcTime {
        let seconds = seconds.saturating_add(nanos / 1_000_000_000);
        // fraction = nanos / 1e9 * 2^24, computed in u64 without overflow.
        let fraction = (((nanos % 1_000_000_000) as u64) << 24) / 1_000_000_000;
        UtcTime { seconds, fraction: fraction as u32 & 0x00FF_FFFF, quality }
    }

    /// Build from whole Unix nanoseconds (saturating at the 32-bit second limit).
    pub const fn from_unix_nanos(nanos: u64, quality: TimeQuality) -> UtcTime {
        let s = nanos / 1_000_000_000;
        let seconds = if s > u32::MAX as u64 { u32::MAX } else { s as u32 };
        UtcTime::from_unix(seconds, (nanos % 1_000_000_000) as u32, quality)
    }

    /// Nanoseconds within the second (rounded down).
    pub const fn nanos(self) -> u32 {
        (((self.fraction & 0x00FF_FFFF) as u64 * 1_000_000_000) >> 24) as u32
    }

    /// Whole Unix nanoseconds.
    pub const fn to_unix_nanos(self) -> u64 {
        self.seconds as u64 * 1_000_000_000 + self.nanos() as u64
    }

    /// The eight wire octets.
    pub const fn to_octets(self) -> [u8; 8] {
        let s = self.seconds.to_be_bytes();
        let f = self.fraction & 0x00FF_FFFF;
        [s[0], s[1], s[2], s[3], (f >> 16) as u8, (f >> 8) as u8, f as u8, self.quality.to_octet()]
    }

    /// Decode from the eight wire octets.
    pub const fn from_octets(o: [u8; 8]) -> UtcTime {
        UtcTime {
            seconds: u32::from_be_bytes([o[0], o[1], o[2], o[3]]),
            fraction: ((o[4] as u32) << 16) | ((o[5] as u32) << 8) | o[6] as u32,
            quality: TimeQuality::from_octet(o[7]),
        }
    }
}

/// IEC 61850 `EntryTime` — ISO 9506 `BinaryTime` in its six-octet form (`BTIME6`).
///
/// Four octets of milliseconds since midnight, then two of days since **1984-01-01**, which
/// is MMS's epoch rather than Unix's. It is what a report's `TimeOfEntry` and a buffered
/// report control block's `TimeOfEntry` carry, and it is a different type from [`UtcTime`]
/// on the wire and here — one is 8 octets with a quality byte, the other is 6 with neither.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryTime {
    /// Milliseconds since midnight (`0..86_400_000`).
    pub millis_of_day: u32,
    /// Days since 1984-01-01.
    pub days_since_1984: u16,
}

/// Days from the Unix epoch to MMS's 1984-01-01.
const MMS_EPOCH_DAYS: u64 = 5113;

impl EntryTime {
    /// The six wire octets.
    pub const fn to_octets(self) -> [u8; 6] {
        let ms = self.millis_of_day.to_be_bytes();
        let d = self.days_since_1984.to_be_bytes();
        [ms[0], ms[1], ms[2], ms[3], d[0], d[1]]
    }

    /// Decode from the six wire octets.
    pub const fn from_octets(o: [u8; 6]) -> EntryTime {
        EntryTime { millis_of_day: u32::from_be_bytes([o[0], o[1], o[2], o[3]]), days_since_1984: u16::from_be_bytes([o[4], o[5]]) }
    }

    /// Build from Unix milliseconds. Saturates below 1984 and above the 16-bit day count,
    /// because the field cannot say "before its own epoch" and silently wrapping would put
    /// a report entry in the wrong century.
    pub const fn from_unix_millis(millis: u64) -> EntryTime {
        let day = millis / 86_400_000;
        let ms = (millis % 86_400_000) as u32;
        if day < MMS_EPOCH_DAYS {
            return EntryTime { millis_of_day: 0, days_since_1984: 0 };
        }
        let days = day - MMS_EPOCH_DAYS;
        if days > u16::MAX as u64 {
            return EntryTime { millis_of_day: 86_399_999, days_since_1984: u16::MAX };
        }
        EntryTime { millis_of_day: ms, days_since_1984: days as u16 }
    }

    /// Unix milliseconds.
    pub const fn to_unix_millis(self) -> u64 {
        (self.days_since_1984 as u64 + MMS_EPOCH_DAYS) * 86_400_000 + self.millis_of_day as u64
    }
}

impl fmt::Display for EntryTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let millis = self.to_unix_millis();
        let (y, m, d, hh, mm, ss) = civil_from_unix((millis / 1000).min(u64::from(u32::MAX)) as u32);
        write!(f, "{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{:03}Z", millis % 1000)
    }
}

impl fmt::Display for UtcTime {
    /// ISO-8601-like `YYYY-MM-DDThh:mm:ss.nnnnnnnnnZ` plus a quality suffix.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, m, d, hh, mm, ss) = civil_from_unix(self.seconds);
        write!(f, "{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{:09}Z", self.nanos())?;
        if self.quality.clock_not_synchronized {
            f.write_str(" (unsynchronized)")?;
        }
        if self.quality.clock_failure {
            f.write_str(" (clock failure)")?;
        }
        Ok(())
    }
}

/// Days-from-civil inverse (Howard Hinnant's algorithm), valid for the u32 range.
const fn civil_from_unix(secs: u32) -> (u32, u32, u32, u32, u32, u32) {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32, rem / 3600, (rem / 60) % 60, rem % 60)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn octets_round_trip() {
        let t = UtcTime::from_unix(1_700_000_000, 500_000_000, TimeQuality::SYNCHRONIZED);
        assert_eq!(t.fraction, 0x0080_0000);
        let o = t.to_octets();
        assert_eq!(o[7], 0x80 | 31);
        assert_eq!(UtcTime::from_octets(o), t);
        assert_eq!(t.nanos(), 500_000_000);
        assert_eq!(t.to_string(), "2023-11-14T22:13:20.500000000Z");
    }

    #[test]
    fn a_nanosecond_field_that_overflows_carries_into_the_second() {
        // Masking it into the 24-bit fraction would leave a timestamp a whole second wrong
        // with nothing to say so, in the one field a protection engineer reads first.
        let t = UtcTime::from_unix(10, 1_500_000_000, TimeQuality::SYNCHRONIZED);
        assert_eq!(t.seconds, 11);
        assert_eq!(t.nanos(), 500_000_000, "and the half second that is left is exactly representable");
        assert_eq!(UtcTime::from_unix(0, 0, TimeQuality::SYNCHRONIZED), UtcTime::from_unix_nanos(0, TimeQuality::SYNCHRONIZED));
    }

    #[test]
    fn nanos_precision_is_within_one_lsb() {
        let t = UtcTime::from_unix(0, 999_999_999, TimeQuality::SYNCHRONIZED);
        assert!(999_999_999 - t.nanos() < 60); // 2^-24 s ≈ 59.6 ns
        assert_eq!(UtcTime::from_unix_nanos(1_000_000_001, TimeQuality::SYNCHRONIZED).seconds, 1);
    }

    #[test]
    fn entry_time_counts_from_1984_not_from_1970() {
        // MMS's BinaryTime epoch is 1984-01-01, which is 5113 days after Unix's. Getting
        // that offset wrong puts every buffered report entry fourteen years out.
        let t = EntryTime::from_unix_millis(441_763_200_000);
        assert_eq!(t, EntryTime { millis_of_day: 0, days_since_1984: 0 }, "1984-01-01T00:00:00Z is day zero");
        assert_eq!(t.to_string(), "1984-01-01T00:00:00.000Z");
        let now = EntryTime::from_unix_millis(1_700_000_000_500);
        assert_eq!(EntryTime::from_octets(now.to_octets()), now);
        assert_eq!(now.to_unix_millis(), 1_700_000_000_500);
        assert_eq!(now.to_string(), "2023-11-14T22:13:20.500Z");
        // Before the epoch and past the 16-bit day count saturate rather than wrap.
        assert_eq!(EntryTime::from_unix_millis(0), EntryTime::default());
        assert_eq!(EntryTime::from_unix_millis(u64::MAX).days_since_1984, u16::MAX);
    }

    #[test]
    fn epoch_display() {
        assert_eq!(UtcTime::default().to_string(), "1970-01-01T00:00:00.000000000Z (unsynchronized)");
    }
}
