//! The IEC 61850-7-2 modelling types more than one layer shares.
//!
//! `TrgOps` says what makes a server send a report or write a log entry, `OptFlds` says which
//! fields that report carries, and `ReasonCode` says what actually happened to one member.
//! All three are bit strings whose **bit 0 is reserved**, numbered from the most significant
//! bit of the first octet (IEC 61850-8-1 Tables 38 and 39).
//!
//! They live in `common` rather than beside the report codec because three layers need them
//! and only one of those is MMS: the SCL loader reads a control block's engineered defaults
//! into them ([`crate::model::ReportControl`]), the server evaluates triggers with them, and
//! the report codec puts them on the wire. One definition, so a control block written from an
//! SCD and a report decoded off the wire cannot disagree about which bit `dchg` is.
//!
//! The [`Value`](crate::proto::data::Value) conversions are in [`crate::proto::data`], which
//! is where the type they convert to lives.

use alloc::vec::Vec;

/// A packed list of report options (`OptFlds`, IEC 61850-8-1 Table 38).
///
/// Ten bits, of which bit 0 is reserved. This is not a convenience: which fields a report
/// carries is *entirely* determined by these bits, so decoding one without them is guessing.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct OptFlds(u16);

/// A packed list of report trigger options (`TrgOps`).
///
/// Six bits, bit 0 reserved: what makes the server send a report at all.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct TrgOps(u8);

/// Why one member was included in a report (`ReasonCode`), one per included value.
///
/// The same six bits as [`TrgOps`], answering the question the other way round: `TrgOps` is
/// what the client asked to be told about, `ReasonCode` is what actually happened.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ReasonCode(u8);

macro_rules! packed_bits {
    ($t:ty, $width:expr, $($name:ident = $bit:expr, $set:ident, $doc:expr;)+) => {
        impl $t {
            /// No options set.
            pub const NONE: $t = Self(0);
            /// Significant bits on the wire, including the reserved bit 0.
            pub const BITS: usize = $width;

            $(
                #[doc = $doc]
                pub const fn $name(self) -> bool {
                    self.0 & (1 << $bit) != 0
                }

                #[doc = concat!("Set [`Self::", stringify!($name), "`].")]
                #[must_use]
                pub const fn $set(mut self, on: bool) -> Self {
                    if on { self.0 |= 1 << $bit } else { self.0 &= !(1 << $bit) }
                    self
                }
            )+

            /// True when nothing is set.
            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }

            /// Read from the contents octets of a BER bit string, where bit 0 is the most
            /// significant bit of the first octet.
            pub fn from_bit_string(bytes: &[u8]) -> Self {
                let mut v = 0u16;
                for bit in 0..$width {
                    let (octet, shift) = (bit / 8, 7 - (bit % 8));
                    if bytes.get(octet).is_some_and(|b| b >> shift & 1 == 1) {
                        v |= 1 << bit;
                    }
                }
                #[allow(clippy::cast_possible_truncation)]
                Self(v as _)
            }

            /// The contents octets of a BER bit string, and the number of unused bits in the
            /// last one.
            pub fn to_bit_string(self) -> (u8, Vec<u8>) {
                let octets = usize::div_ceil($width, 8);
                let mut out = alloc::vec![0u8; octets];
                for bit in 0..$width {
                    if u16::from(self.0) & (1 << bit) != 0 {
                        let (octet, shift) = (bit / 8, 7 - (bit % 8));
                        if let Some(b) = out.get_mut(octet) {
                            *b |= 1 << shift;
                        }
                    }
                }
                (((octets * 8) - $width) as u8, out)
            }
        }

        /// Named flags rather than a packed number: these end up in logs and in a `{:?}` of
        /// every report, where `ReasonCode(32)` says nothing a reader can act on.
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(stringify!($t))?;
                f.write_str("(")?;
                let mut first = true;
                $(
                    if self.$name() {
                        if !first {
                            f.write_str(" | ")?;
                        }
                        first = false;
                        f.write_str(stringify!($name))?;
                    }
                )+
                if first {
                    f.write_str("none")?;
                }
                f.write_str(")")
            }
        }
    };
}

packed_bits!(OptFlds, 10,
    sequence_number = 1, with_sequence_number, "`SqNum` is present.";
    report_time_stamp = 2, with_report_time_stamp, "`TimeOfEntry` is present.";
    reason_for_inclusion = 3, with_reason_for_inclusion, "A `ReasonCode` follows every value.";
    data_set_name = 4, with_data_set_name, "`DatSet` is present.";
    data_reference = 5, with_data_reference, "A reference precedes every value.";
    buffer_overflow = 6, with_buffer_overflow, "`BufOvfl` is present (buffered control blocks).";
    entry_id = 7, with_entry_id, "`EntryID` is present (buffered control blocks).";
    conf_revision = 8, with_conf_revision, "`ConfRev` is present.";
    segmentation = 9, with_segmentation, "`SubSeqNum` and `MoreSegmentsFollow` are present.";
);

packed_bits!(TrgOps, 6,
    data_change = 1, with_data_change, "Report when a value changes.";
    quality_change = 2, with_quality_change, "Report when a quality changes.";
    data_update = 3, with_data_update, "Report on every update, changed or not.";
    integrity = 4, with_integrity, "Report periodically, every `IntgPd` milliseconds.";
    general_interrogation = 5, with_general_interrogation, "Report when the client asks (`GI`).";
);

packed_bits!(ReasonCode, 6,
    data_change = 1, with_data_change, "A value changed.";
    quality_change = 2, with_quality_change, "A quality changed.";
    data_update = 3, with_data_update, "The value was updated without changing.";
    integrity = 4, with_integrity, "The integrity period elapsed.";
    general_interrogation = 5, with_general_interrogation, "The client asked (`GI`).";
);

impl TrgOps {
    /// The trigger options a client usually wants: data change, quality change and general
    /// interrogation — everything that is an *event*, without the periodic integrity scan.
    pub const EVENTS: TrgOps = TrgOps(0b0010_0110);
}

/// The control model of a controllable object (`ctlModel`, IEC 61850-7-3).
///
/// It decides which services are legal: whether a select is required first, and whether the
/// server answers the operate immediately or only after the switchgear has actually moved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ControlModel {
    /// 0 — the object reports a status and cannot be operated.
    StatusOnly,
    /// 1 — write `Oper`; the response is the answer.
    #[default]
    DirectNormal,
    /// 2 — read `SBO` to reserve, then write `Oper`.
    SboNormal,
    /// 3 — write `Oper`; the *final* answer is a `CommandTermination`.
    DirectEnhanced,
    /// 4 — write `SBOw` to reserve with the value, then `Oper`, then `CommandTermination`.
    SboEnhanced,
}

impl ControlModel {
    /// From the `ctlModel` enumeration value.
    pub const fn from_code(code: i64) -> Option<ControlModel> {
        Some(match code {
            0 => ControlModel::StatusOnly,
            1 => ControlModel::DirectNormal,
            2 => ControlModel::SboNormal,
            3 => ControlModel::DirectEnhanced,
            4 => ControlModel::SboEnhanced,
            _ => return None,
        })
    }

    /// The `ctlModel` enumeration value.
    pub const fn to_code(self) -> i64 {
        match self {
            ControlModel::StatusOnly => 0,
            ControlModel::DirectNormal => 1,
            ControlModel::SboNormal => 2,
            ControlModel::DirectEnhanced => 3,
            ControlModel::SboEnhanced => 4,
        }
    }

    /// True when the object must be selected before it may be operated.
    pub const fn needs_select(self) -> bool {
        matches!(self, ControlModel::SboNormal | ControlModel::SboEnhanced)
    }

    /// True when the select carries the value (`SBOw`) rather than being a bare reservation
    /// (`SBO`).
    pub const fn select_carries_value(self) -> bool {
        matches!(self, ControlModel::SboEnhanced)
    }

    /// True when the server owes a `CommandTermination` after the operate response.
    pub const fn enhanced_security(self) -> bool {
        matches!(self, ControlModel::DirectEnhanced | ControlModel::SboEnhanced)
    }
}
