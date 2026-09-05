//! IEC 61850 controls: the `Oper`, `SBOw` and `Cancel` structures, and what comes back.
//!
//! Operating a breaker is an MMS `Write` to a structured variable under the `CO` functional
//! constraint — `IED1LD0/CSWI1$CO$Pos$Oper` — whose components IEC 61850-8-1 Annex E fixes
//! (Tables E.8 `SBOw`, E.9 `Oper`, E.10 `Cancel` ✅; the component order from libiec61850's
//! `client_control.c` 🌐).
//!
//! ```text
//! Oper   ::= { ctlVal, [operTm], origin { orCat, orIdent }, ctlNum, T, Test, Check }
//! SBOw   ::= the same
//! Cancel ::= the same without Check
//! ```
//!
//! Two things are easy to get wrong. `Check` is a **two-bit** bit string whose bit 0 is the
//! synchrocheck and bit 1 the interlock check 🌐 — the reverse of the order prose lists them
//! in. And a negative answer to an enhanced-security control is not an error response: it
//! arrives later, unsolicited, as [`LastApplError`] carrying the [`AddCause`] that says why
//! ([8-1] Tables 76 and 77).

use alloc::string::String;
use alloc::vec::Vec;

use crate::common::{Error, Result, UtcTime};

pub use crate::common::ControlModel;
use crate::proto::data::{Typed, Value};

/// Who issued a control (`orCat`, IEC 61850-7-3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum OriginCategory {
    NotSupported,
    BayControl,
    StationControl,
    #[default]
    RemoteControl,
    AutomaticBay,
    AutomaticStation,
    AutomaticRemote,
    Maintenance,
    Process,
    /// A value outside the enumeration, kept so it re-encodes as it arrived.
    Other(i64),
}

impl OriginCategory {
    /// From the wire value.
    pub const fn from_code(code: i64) -> OriginCategory {
        match code {
            0 => OriginCategory::NotSupported,
            1 => OriginCategory::BayControl,
            2 => OriginCategory::StationControl,
            3 => OriginCategory::RemoteControl,
            4 => OriginCategory::AutomaticBay,
            5 => OriginCategory::AutomaticStation,
            6 => OriginCategory::AutomaticRemote,
            7 => OriginCategory::Maintenance,
            8 => OriginCategory::Process,
            other => OriginCategory::Other(other),
        }
    }

    /// The wire value.
    pub const fn to_code(self) -> i64 {
        match self {
            OriginCategory::NotSupported => 0,
            OriginCategory::BayControl => 1,
            OriginCategory::StationControl => 2,
            OriginCategory::RemoteControl => 3,
            OriginCategory::AutomaticBay => 4,
            OriginCategory::AutomaticStation => 5,
            OriginCategory::AutomaticRemote => 6,
            OriginCategory::Maintenance => 7,
            OriginCategory::Process => 8,
            OriginCategory::Other(v) => v,
        }
    }
}

/// The originator of a control (`origin`): a category and an opaque identifier.
///
/// The identifier is octets rather than a string on purpose — IEC 62351-6 §5.5 fills it with
/// a certificate serial number, which is not text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Origin {
    /// Where the command came from.
    pub category: OriginCategory,
    /// `orIdent` — who, as octets.
    pub identifier: Vec<u8>,
}

impl Origin {
    /// An originator with a textual identifier, which is what a tool usually has.
    pub fn new(category: OriginCategory, identifier: &str) -> Origin {
        Origin { category, identifier: identifier.as_bytes().to_vec() }
    }

    /// The `origin` structure.
    pub fn to_value(&self) -> Value {
        Value::Structure(alloc::vec![Value::Integer(self.category.to_code()), Value::OctetString(self.identifier.clone())])
    }

    /// Read an `origin` structure.
    pub fn from_value(v: &Value) -> Option<Origin> {
        let members = v.members()?;
        let category = match members.first()? {
            Value::Integer(i) => OriginCategory::from_code(*i),
            Value::Unsigned(u) => OriginCategory::from_code(i64::try_from(*u).ok()?),
            _ => return None,
        };
        let identifier = match members.get(1)? {
            Value::OctetString(b) => b.clone(),
            Value::VisibleString(s) | Value::MmsString(s) => s.as_bytes().to_vec(),
            _ => return None,
        };
        Some(Origin { category, identifier })
    }

    /// The identifier as text, when it is text.
    pub fn identifier_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.identifier).ok()
    }
}

/// The `Check` field: the two conditions a server may be asked to verify before it operates.
///
/// A two-bit bit string. **Bit 0 is the synchrocheck and bit 1 the interlock check** 🌐 —
/// getting them the wrong way round asks a substation to skip the check it was meant to make.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Check {
    /// Verify that the two sides are in synchronism before closing.
    pub synchro: bool,
    /// Verify the interlocking conditions.
    pub interlock: bool,
}

impl Check {
    /// Ask for neither check — which is what most direct controls send.
    pub const NONE: Check = Check { synchro: false, interlock: false };
    /// Ask for both.
    pub const BOTH: Check = Check { synchro: true, interlock: true };

    /// The two-bit bit string.
    pub fn to_value(self) -> Value {
        let byte = u8::from(self.synchro) << 7 | u8::from(self.interlock) << 6;
        Value::BitString { unused: 6, bytes: alloc::vec![byte] }
    }

    /// Read the two-bit bit string. A bit string of another width is not a `Check`.
    pub fn from_value(v: &Value) -> Option<Check> {
        match v {
            Value::BitString { unused: 6, bytes } => {
                let b = *bytes.first()?;
                Some(Check { synchro: b & 0x80 != 0, interlock: b & 0x40 != 0 })
            }
            _ => None,
        }
    }
}

/// An `Oper`, `SBOw` or `Cancel` structure.
///
/// One type for all three, because Annex E gives them the same components and `Cancel` simply
/// stops before `Check` — which is exactly the kind of near-duplication that turns into two
/// implementations disagreeing about `ctlNum`.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlRequest {
    /// `ctlVal` — the value to write. Its type is the CDC's: a boolean for `SPC`, a `Dbpos`
    /// bit string for `DPC`, an integer for `INC`, a float for `APC`.
    pub ctl_val: Value,
    /// `operTm` — operate at this time instead of now. Present only on objects engineered
    /// for time-activated operate, and its presence *changes the structure*, so it is an
    /// explicit option rather than a defaulted field.
    pub oper_tm: Option<UtcTime>,
    /// `origin` — who is asking.
    pub origin: Origin,
    /// `ctlNum` — the sequence number tying a select, an operate and its termination
    /// together. Every request of one control sequence carries the same number.
    pub ctl_num: u8,
    /// `T` — when the client issued this.
    pub t: UtcTime,
    /// `Test` — this is a test command; a server not in test mode must refuse it.
    pub test: bool,
    /// `Check` — omitted from a `Cancel`.
    pub check: Check,
}

impl ControlRequest {
    /// A request with the defaults a tool wants: remote control, no checks, not a test.
    pub fn new(ctl_val: Value, ctl_num: u8, t: UtcTime) -> ControlRequest {
        ControlRequest { ctl_val, oper_tm: None, origin: Origin::default(), ctl_num, t, test: false, check: Check::NONE }
    }

    /// The `Oper` / `SBOw` structure.
    pub fn to_value(&self) -> Value {
        let mut members = Vec::with_capacity(7);
        members.push(self.ctl_val.clone());
        if let Some(tm) = self.oper_tm {
            members.push(Value::UtcTime(tm));
        }
        members.push(self.origin.to_value());
        members.push(Value::Unsigned(u64::from(self.ctl_num)));
        members.push(Value::UtcTime(self.t));
        members.push(Value::Boolean(self.test));
        members.push(self.check.to_value());
        Value::Structure(members)
    }

    /// The `Cancel` structure: the same without `Check`.
    pub fn to_cancel_value(&self) -> Value {
        let mut v = self.to_value();
        if let Value::Structure(members) = &mut v {
            members.pop();
        }
        v
    }

    /// Read an `Oper`, `SBOw` or `Cancel` structure.
    ///
    /// `operTm` and `Check` are both optional *and* untagged, so the shape is resolved by
    /// counting members and checking types rather than by position alone — which is the only
    /// way, since the structure carries no field names on the wire.
    pub fn from_value(v: &Value) -> Result<ControlRequest> {
        let members = v.members().ok_or(Error::InvalidValue("a control request is a structure"))?;
        let bad = || Error::InvalidValue("control request structure");
        let ctl_val = members.first().ok_or_else(bad)?.clone();
        let mut at = 1usize;
        // `operTm` is a UtcTime where `origin` is a structure: the two cannot be confused.
        let oper_tm = match members.get(at) {
            Some(Value::UtcTime(t)) => {
                at += 1;
                Some(*t)
            }
            _ => None,
        };
        let origin = Origin::from_value(members.get(at).ok_or_else(bad)?).ok_or_else(bad)?;
        at += 1;
        // `ctlNum` is present only on objects engineered with it, and `T` — a `UtcTime` —
        // follows it either way, so the two are told apart by type rather than by position.
        // An `Oper` echoed by a device without `ctlNum` is a valid `Oper`, and refusing it
        // turns a command termination into an unrecognised report.
        let ctl_num = match members.get(at) {
            Some(Value::UtcTime(_)) | None => 0,
            Some(v) => {
                at += 1;
                u8::try_from(v.as_u64().ok_or_else(bad)?).map_err(|_| bad())?
            }
        };
        let t = members.get(at).ok_or_else(bad)?.as_utc_time().ok_or_else(bad)?;
        at += 1;
        let test = members.get(at).ok_or_else(bad)?.as_bool().ok_or_else(bad)?;
        at += 1;
        // Absent on a `Cancel`, present on everything else.
        let check = match members.get(at) {
            Some(v) => Check::from_value(v).ok_or_else(bad)?,
            None => Check::NONE,
        };
        Ok(ControlRequest { ctl_val, oper_tm, origin, ctl_num, t, test, check })
    }
}

/// The `error` component of [`LastApplError`] (IEC 61850-8-1 Table 76).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ControlError {
    #[default]
    NoError,
    Unknown,
    TimeoutTestNotOk,
    OperatorTestNotOk,
    /// A value outside the enumeration.
    Other(i64),
}

impl ControlError {
    /// From the wire value.
    pub const fn from_code(code: i64) -> ControlError {
        match code {
            0 => ControlError::NoError,
            1 => ControlError::Unknown,
            2 => ControlError::TimeoutTestNotOk,
            3 => ControlError::OperatorTestNotOk,
            other => ControlError::Other(other),
        }
    }

    /// The wire value.
    pub const fn to_code(self) -> i64 {
        match self {
            ControlError::NoError => 0,
            ControlError::Unknown => 1,
            ControlError::TimeoutTestNotOk => 2,
            ControlError::OperatorTestNotOk => 3,
            ControlError::Other(v) => v,
        }
    }
}

/// Why a control was refused or abandoned (`AddCause`, IEC 61850-8-1 Table 77).
///
/// This is the field that turns "the breaker did not close" into a diagnosis, so every value
/// is named rather than left as a number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AddCause {
    #[default]
    Unknown,
    NotSupported,
    BlockedBySwitchingHierarchy,
    SelectFailed,
    InvalidPosition,
    PositionReached,
    ParameterChangeInExecution,
    StepLimit,
    BlockedByMode,
    BlockedByProcess,
    BlockedByInterlocking,
    BlockedBySynchrocheck,
    CommandAlreadyInExecution,
    BlockedByHealth,
    OneOfNControl,
    AbortionByCancel,
    TimeLimitOver,
    AbortionByTrip,
    ObjectNotSelected,
    ObjectAlreadySelected,
    NoAccessAuthority,
    EndedWithOvershoot,
    AbortionDueToDeviation,
    AbortionByCommunicationLoss,
    AbortionByCommand,
    None,
    InconsistentParameters,
    LockedByOtherClient,
    /// A value outside the enumeration; Edition 2.1 extends the list.
    Other(i64),
}

impl AddCause {
    /// From the wire value.
    pub const fn from_code(code: i64) -> AddCause {
        match code {
            0 => AddCause::Unknown,
            1 => AddCause::NotSupported,
            2 => AddCause::BlockedBySwitchingHierarchy,
            3 => AddCause::SelectFailed,
            4 => AddCause::InvalidPosition,
            5 => AddCause::PositionReached,
            6 => AddCause::ParameterChangeInExecution,
            7 => AddCause::StepLimit,
            8 => AddCause::BlockedByMode,
            9 => AddCause::BlockedByProcess,
            10 => AddCause::BlockedByInterlocking,
            11 => AddCause::BlockedBySynchrocheck,
            12 => AddCause::CommandAlreadyInExecution,
            13 => AddCause::BlockedByHealth,
            14 => AddCause::OneOfNControl,
            15 => AddCause::AbortionByCancel,
            16 => AddCause::TimeLimitOver,
            17 => AddCause::AbortionByTrip,
            18 => AddCause::ObjectNotSelected,
            19 => AddCause::ObjectAlreadySelected,
            20 => AddCause::NoAccessAuthority,
            21 => AddCause::EndedWithOvershoot,
            22 => AddCause::AbortionDueToDeviation,
            23 => AddCause::AbortionByCommunicationLoss,
            24 => AddCause::AbortionByCommand,
            25 => AddCause::None,
            26 => AddCause::InconsistentParameters,
            27 => AddCause::LockedByOtherClient,
            other => AddCause::Other(other),
        }
    }

    /// The wire value.
    pub const fn to_code(self) -> i64 {
        match self {
            AddCause::Unknown => 0,
            AddCause::NotSupported => 1,
            AddCause::BlockedBySwitchingHierarchy => 2,
            AddCause::SelectFailed => 3,
            AddCause::InvalidPosition => 4,
            AddCause::PositionReached => 5,
            AddCause::ParameterChangeInExecution => 6,
            AddCause::StepLimit => 7,
            AddCause::BlockedByMode => 8,
            AddCause::BlockedByProcess => 9,
            AddCause::BlockedByInterlocking => 10,
            AddCause::BlockedBySynchrocheck => 11,
            AddCause::CommandAlreadyInExecution => 12,
            AddCause::BlockedByHealth => 13,
            AddCause::OneOfNControl => 14,
            AddCause::AbortionByCancel => 15,
            AddCause::TimeLimitOver => 16,
            AddCause::AbortionByTrip => 17,
            AddCause::ObjectNotSelected => 18,
            AddCause::ObjectAlreadySelected => 19,
            AddCause::NoAccessAuthority => 20,
            AddCause::EndedWithOvershoot => 21,
            AddCause::AbortionDueToDeviation => 22,
            AddCause::AbortionByCommunicationLoss => 23,
            AddCause::AbortionByCommand => 24,
            AddCause::None => 25,
            AddCause::InconsistentParameters => 26,
            AddCause::LockedByOtherClient => 27,
            AddCause::Other(v) => v,
        }
    }
}

/// `LastApplError` — why a control failed (IEC 61850-8-1 Table 76).
///
/// A five-component structure sent unsolicited, alongside the `Oper` value, in the
/// `InformationReport` that carries a negative `CommandTermination`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LastApplError {
    /// `cntrlObj` — the control object, as `LD/LN$CO$DO$Oper`.
    pub control_object: String,
    /// `error`.
    pub error: ControlError,
    /// `origin` — echoed from the request.
    pub origin: Origin,
    /// `ctlNum` — echoed from the request, which is what ties it to a command.
    pub ctl_num: u8,
    /// `addCause` — the diagnosis.
    pub add_cause: AddCause,
}

impl LastApplError {
    /// Read the five-component structure.
    pub fn from_value(v: &Value) -> Result<LastApplError> {
        let m = v.members().ok_or(Error::InvalidValue("LastApplError is a structure"))?;
        let bad = || Error::InvalidValue("LastApplError structure");
        Ok(LastApplError {
            control_object: String::from(m.first().ok_or_else(bad)?.as_str().ok_or_else(bad)?),
            error: ControlError::from_code(m.get(1).ok_or_else(bad)?.as_i64().ok_or_else(bad)?),
            origin: Origin::from_value(m.get(2).ok_or_else(bad)?).ok_or_else(bad)?,
            ctl_num: u8::try_from(m.get(3).ok_or_else(bad)?.as_u64().ok_or_else(bad)?).map_err(|_| bad())?,
            add_cause: AddCause::from_code(m.get(4).ok_or_else(bad)?.as_i64().ok_or_else(bad)?),
        })
    }

    /// The five-component structure.
    pub fn to_value(&self) -> Value {
        Value::Structure(alloc::vec![
            Value::VisibleString(self.control_object.clone()),
            Value::Integer(self.error.to_code()),
            self.origin.to_value(),
            Value::Unsigned(u64::from(self.ctl_num)),
            Value::Integer(self.add_cause.to_code()),
        ])
    }
}

/// The final answer to an enhanced-security control, which arrives unsolicited.
///
/// A positive termination is an `InformationReport` naming only the `Oper` variable; a
/// negative one names `LastApplError` as well, and *that* is where the reason is.
#[derive(Clone, Debug, PartialEq)]
pub enum CommandTermination {
    /// The command completed. The switchgear reached the commanded position.
    Positive {
        /// The control object, as `LD/LN$CO$DO$Oper`.
        control_object: String,
        /// The `Oper` structure the server echoed back.
        request: ControlRequest,
    },
    /// The command failed or was abandoned.
    Negative {
        /// Why.
        error: LastApplError,
        /// The `Oper` structure the server echoed back, if it sent one.
        request: Option<ControlRequest>,
    },
}

impl CommandTermination {
    /// The `ctlNum` this termination belongs to, which is how a client with several commands
    /// in flight tells them apart.
    pub fn ctl_num(&self) -> u8 {
        match self {
            CommandTermination::Positive { request, .. } => request.ctl_num,
            CommandTermination::Negative { error, .. } => error.ctl_num,
        }
    }

    /// The control object this termination is about.
    pub fn control_object(&self) -> &str {
        match self {
            CommandTermination::Positive { control_object, .. } => control_object,
            CommandTermination::Negative { error, .. } => &error.control_object,
        }
    }

    /// True when the command succeeded.
    pub const fn is_positive(&self) -> bool {
        matches!(self, CommandTermination::Positive { .. })
    }

    /// Why the command failed, for a negative termination.
    pub const fn add_cause(&self) -> Option<AddCause> {
        match self {
            CommandTermination::Negative { error, .. } => Some(error.add_cause),
            CommandTermination::Positive { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::TimeQuality;
    use crate::proto::data::Dbpos;

    fn now() -> UtcTime {
        UtcTime::from_unix(1_700_000_000, 0, TimeQuality::SYNCHRONIZED)
    }

    #[test]
    fn an_oper_round_trips_with_and_without_oper_tm() {
        let mut r = ControlRequest::new(Value::dbpos(Dbpos::On), 4, now());
        r.origin = Origin::new(OriginCategory::StationControl, "hmi-1");
        r.check = Check::BOTH;
        let v = r.to_value();
        assert_eq!(v.members().map(<[Value]>::len), Some(6), "ctlVal, origin, ctlNum, T, Test, Check");
        assert_eq!(ControlRequest::from_value(&v).unwrap(), r);

        // With a time-activated operate the structure grows a member, and the decoder has to
        // notice — `operTm` is untagged and sits exactly where `origin` otherwise would.
        r.oper_tm = Some(now());
        let v = r.to_value();
        assert_eq!(v.members().map(<[Value]>::len), Some(7));
        assert_eq!(ControlRequest::from_value(&v).unwrap(), r);
    }

    #[test]
    fn an_oper_from_a_device_without_ctl_num_still_decodes() {
        // `ctlNum` is present only when the object was engineered with it. A device that
        // omits it echoes `{ctlVal, origin, T, Test, Check}`, and a decoder that insists on
        // reading the fourth member as a number turns a command termination into an
        // unrecognised report — the one place a caller is waiting for an answer.
        let v = Value::Structure(alloc::vec![
            Value::Boolean(true),
            Origin::new(OriginCategory::StationControl, "hmi").to_value(),
            Value::UtcTime(now()),
            Value::Boolean(false),
            Check::NONE.to_value(),
        ]);
        let r = ControlRequest::from_value(&v).unwrap();
        assert_eq!((r.ctl_num, r.t, r.oper_tm), (0, now(), None));
        assert_eq!(r.ctl_val, Value::Boolean(true));
    }

    #[test]
    fn a_cancel_is_an_oper_without_the_check() {
        let r = ControlRequest::new(Value::Boolean(true), 9, now());
        let v = r.to_cancel_value();
        assert_eq!(v.members().map(<[Value]>::len), Some(5));
        let back = ControlRequest::from_value(&v).unwrap();
        assert_eq!(back.check, Check::NONE, "a cancel asks for no checks because it carries none");
        assert_eq!((back.ctl_num, back.ctl_val), (9, Value::Boolean(true)));
    }

    #[test]
    fn the_check_bits_are_synchro_then_interlock() {
        // Bit 0 is the synchrocheck and bit 1 the interlock check. Swapping them asks a
        // substation to skip the check it was told to make, which is the whole point of
        // pinning it in a test.
        assert_eq!(Check { synchro: true, interlock: false }.to_value(), Value::BitString { unused: 6, bytes: alloc::vec![0b1000_0000] });
        assert_eq!(Check { synchro: false, interlock: true }.to_value(), Value::BitString { unused: 6, bytes: alloc::vec![0b0100_0000] });
        for c in [Check::NONE, Check::BOTH, Check { synchro: true, interlock: false }, Check { synchro: false, interlock: true }] {
            assert_eq!(Check::from_value(&c.to_value()), Some(c));
        }
        // A quality is thirteen bits, so it is not a Check. A `Dbpos` *is* two bits and is
        // therefore indistinguishable from one on the wire — only its position in the
        // structure says which it is, which is worth knowing rather than papering over.
        assert_eq!(Check::from_value(&Value::quality(crate::common::Quality::GOOD)), None);
        assert_eq!(Check::from_value(&Value::Boolean(true)), None);
        assert_eq!(Check::from_value(&Value::dbpos(Dbpos::On)), Some(Check { synchro: true, interlock: false }));
    }

    #[test]
    fn last_appl_error_names_the_reason_a_breaker_did_not_move() {
        let e = LastApplError {
            control_object: String::from("IED1LD0/CSWI1$CO$Pos$Oper"),
            error: ControlError::Unknown,
            origin: Origin::new(OriginCategory::RemoteControl, "scada"),
            ctl_num: 4,
            add_cause: AddCause::BlockedByInterlocking,
        };
        assert_eq!(LastApplError::from_value(&e.to_value()).unwrap(), e);
        assert_eq!(e.add_cause.to_code(), 10);
        // The whole table round-trips, including a value Ed2.1 may have added since.
        for code in 0..=27 {
            assert_eq!(AddCause::from_code(code).to_code(), code);
        }
        assert_eq!(AddCause::from_code(99), AddCause::Other(99));
        for code in 0..=3 {
            assert_eq!(ControlError::from_code(code).to_code(), code);
        }
    }

    #[test]
    fn the_control_model_says_which_services_are_legal() {
        assert!(!ControlModel::DirectNormal.needs_select());
        assert!(ControlModel::SboNormal.needs_select() && !ControlModel::SboNormal.select_carries_value());
        assert!(ControlModel::SboEnhanced.select_carries_value());
        assert!(ControlModel::SboEnhanced.enhanced_security() && ControlModel::DirectEnhanced.enhanced_security());
        assert!(!ControlModel::DirectNormal.enhanced_security());
        for code in 0..=4 {
            assert_eq!(ControlModel::from_code(code).unwrap().to_code(), code);
        }
        assert_eq!(ControlModel::from_code(5), None);
    }

    #[test]
    fn an_origin_identifier_may_be_octets_or_text() {
        let o = Origin::new(OriginCategory::Maintenance, "tool");
        assert_eq!(Origin::from_value(&o.to_value()), Some(o.clone()));
        assert_eq!(o.identifier_str(), Some("tool"));
        // IEC 62351-6 fills it with a certificate serial number, which is not text.
        let binary = Origin { category: OriginCategory::Process, identifier: alloc::vec![0x00, 0xFF, 0x80] };
        assert_eq!(binary.identifier_str(), None);
        assert_eq!(Origin::from_value(&binary.to_value()), Some(binary));
        assert_eq!(OriginCategory::from_code(42), OriginCategory::Other(42));
    }

    #[test]
    fn a_termination_is_tied_to_its_command_by_ctl_num() {
        let r = ControlRequest::new(Value::Boolean(true), 7, now());
        let positive = CommandTermination::Positive { control_object: String::from("IED1LD0/CSWI1$CO$Pos$Oper"), request: r.clone() };
        assert!(positive.is_positive());
        assert_eq!(positive.ctl_num(), 7);
        let negative = CommandTermination::Negative {
            error: LastApplError {
                control_object: String::from("IED1LD0/CSWI1$CO$Pos$Oper"),
                ctl_num: 7,
                add_cause: AddCause::TimeLimitOver,
                ..Default::default()
            },
            request: Some(r),
        };
        assert!(!negative.is_positive());
        assert_eq!((negative.ctl_num(), negative.control_object()), (7, "IED1LD0/CSWI1$CO$Pos$Oper"));
    }
}
