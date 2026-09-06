//! The two enumerations IEC 61850-7-2 service **tracking** is written in, and the classes it
//! defines. The engine that fills them in is [`server::tracking`](crate::server::Tracking).
//!
//! Both lists are the standard's own, in the standard's own order ✅ ([`ServiceType`] from
//! Table 26, [`ServiceError`] from Table 5). The **ordinals** are not: the name-to-number
//! mapping belongs to IEC 61850-8-1, which is paywalled (R2), so the server reads them out of
//! the `EnumType` the SCL file declares (D9) and falls back to the standard's list position
//! only when the file declares none.

use alloc::string::String;
use alloc::vec::Vec;

/// The service a tracking data object is reporting on (IEC 61850-7-2 Table 26 ✅).
///
/// The whole list, not only the tracked half: §15.3.2 says a `GetBRCBValues` is not tracked,
/// but the enumeration is what a client decodes against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[allow(missing_docs)] // each variant *is* its documentation: the name is the service.
pub enum ServiceType {
    GetServerDirectory,
    Associate,
    Abort,
    Release,
    GetLogicalDeviceDirectory,
    GetAllDataValues,
    GetDataValues,
    SetDataValues,
    GetDataDirectory,
    GetDataDefinition,
    GetDataSetValues,
    SetDataSetValues,
    CreateDataSet,
    DeleteDataSet,
    GetDataSetDirectory,
    SelectActiveSG,
    SelectEditSG,
    SetEditSGValue,
    ConfirmEditSGValues,
    GetEditSGValue,
    GetSGCBValues,
    Report,
    GetBRCBValues,
    SetBRCBValues,
    GetURCBValues,
    SetURCBValues,
    GetLCBValues,
    SetLCBValues,
    QueryLogByTime,
    QueryLogAfter,
    GetLogStatusValues,
    SendGOOSEMessage,
    GetGoCBValues,
    SetGoCBValues,
    GetGoReference,
    GetGOOSEElementNumber,
    SendMSVMessage,
    GetMSVCBValues,
    SetMSVCBValues,
    SendUSVMessage,
    GetUSVCBValues,
    SetUSVCBValues,
    Select,
    SelectWithValue,
    Cancel,
    Operate,
    CommandTermination,
    TimeActivatedOperate,
    GetFile,
    SetFile,
    DeleteFile,
    GetFileAttributeValues,
    TimeSynchronization,
    /// Something the *server* did on its own: an association that ended and released a control
    /// block, or a reservation that ran out. §15.3.2.2.2 names exactly those two.
    InternalChange,
}

/// The names, in the order IEC 61850-7-2 Table 26 lists them ✅.
///
/// The order is load-bearing twice over: it is the fallback ordinal for a file that declares no
/// `EnumType`, and it is what [`ServiceType::parse`] matches an `EnumVal` against.
const SERVICE_TYPES: [(ServiceType, &str); 54] = [
    (ServiceType::GetServerDirectory, "GetServerDirectory"),
    (ServiceType::Associate, "Associate"),
    (ServiceType::Abort, "Abort"),
    (ServiceType::Release, "Release"),
    (ServiceType::GetLogicalDeviceDirectory, "GetLogicalDeviceDirectory"),
    (ServiceType::GetAllDataValues, "GetAllDataValues"),
    (ServiceType::GetDataValues, "GetDataValues"),
    (ServiceType::SetDataValues, "SetDataValues"),
    (ServiceType::GetDataDirectory, "GetDataDirectory"),
    (ServiceType::GetDataDefinition, "GetDataDefinition"),
    (ServiceType::GetDataSetValues, "GetDataSetValues"),
    (ServiceType::SetDataSetValues, "SetDataSetValues"),
    (ServiceType::CreateDataSet, "CreateDataSet"),
    (ServiceType::DeleteDataSet, "DeleteDataSet"),
    (ServiceType::GetDataSetDirectory, "GetDataSetDirectory"),
    (ServiceType::SelectActiveSG, "SelectActiveSG"),
    (ServiceType::SelectEditSG, "SelectEditSG"),
    (ServiceType::SetEditSGValue, "SetEditSGValue"),
    (ServiceType::ConfirmEditSGValues, "ConfirmEditSGValues"),
    (ServiceType::GetEditSGValue, "GetEditSGValue"),
    (ServiceType::GetSGCBValues, "GetSGCBValues"),
    (ServiceType::Report, "Report"),
    (ServiceType::GetBRCBValues, "GetBRCBValues"),
    (ServiceType::SetBRCBValues, "SetBRCBValues"),
    (ServiceType::GetURCBValues, "GetURCBValues"),
    (ServiceType::SetURCBValues, "SetURCBValues"),
    (ServiceType::GetLCBValues, "GetLCBValues"),
    (ServiceType::SetLCBValues, "SetLCBValues"),
    (ServiceType::QueryLogByTime, "QueryLogByTime"),
    (ServiceType::QueryLogAfter, "QueryLogAfter"),
    (ServiceType::GetLogStatusValues, "GetLogStatusValues"),
    (ServiceType::SendGOOSEMessage, "SendGOOSEMessage"),
    (ServiceType::GetGoCBValues, "GetGoCBValues"),
    (ServiceType::SetGoCBValues, "SetGoCBValues"),
    (ServiceType::GetGoReference, "GetGoReference"),
    (ServiceType::GetGOOSEElementNumber, "GetGOOSEElementNumber"),
    (ServiceType::SendMSVMessage, "SendMSVMessage"),
    (ServiceType::GetMSVCBValues, "GetMSVCBValues"),
    (ServiceType::SetMSVCBValues, "SetMSVCBValues"),
    (ServiceType::SendUSVMessage, "SendUSVMessage"),
    (ServiceType::GetUSVCBValues, "GetUSVCBValues"),
    (ServiceType::SetUSVCBValues, "SetUSVCBValues"),
    (ServiceType::Select, "Select"),
    (ServiceType::SelectWithValue, "SelectWithValue"),
    (ServiceType::Cancel, "Cancel"),
    (ServiceType::Operate, "Operate"),
    (ServiceType::CommandTermination, "CommandTermination"),
    (ServiceType::TimeActivatedOperate, "TimeActivatedOperate"),
    (ServiceType::GetFile, "GetFile"),
    (ServiceType::SetFile, "SetFile"),
    (ServiceType::DeleteFile, "DeleteFile"),
    (ServiceType::GetFileAttributeValues, "GetFileAttributeValues"),
    (ServiceType::TimeSynchronization, "TimeSynchronization"),
    (ServiceType::InternalChange, "InternalChange"),
];

impl ServiceType {
    /// The name IEC 61850-7-2 gives it, which is also what an SCL `EnumVal` spells.
    pub fn as_str(self) -> &'static str {
        SERVICE_TYPES.iter().find(|(v, _)| *v == self).map_or("InternalChange", |(_, n)| *n)
    }

    /// The service of that name, if the standard has one.
    pub fn parse(name: &str) -> Option<ServiceType> {
        SERVICE_TYPES.iter().find(|(_, n)| *n == name).map(|(v, _)| *v)
    }

    /// Its position in Table 26 — the ordinal to use when the file declares no `EnumType`.
    ///
    /// This is a **fallback and not a claim**: the name-to-number mapping is IEC 61850-8-1's
    /// and is paywalled (R2), so a file that declares the enumeration wins, always.
    pub fn table_ordinal(self) -> i64 {
        SERVICE_TYPES.iter().position(|(v, _)| *v == self).map_or(0, |i| i as i64)
    }
}

impl core::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result a tracking data object reports (IEC 61850-7-2 Table 5 ✅).
///
/// `NoError` is not "nothing to say": a successful service is tracked too, because an operator
/// asking who enabled a control block needs the yes as much as the no.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[allow(missing_docs)] // as above: the name is the error.
pub enum ServiceError {
    InstanceNotAvailable,
    InstanceInUse,
    AccessViolation,
    AccessNotAllowedInCurrentState,
    ParameterValueInappropriate,
    ParameterValueInconsistent,
    ClassNotSupported,
    InstanceLockedByOtherClient,
    ControlMustBeSelected,
    TypeConflict,
    FailedDueToCommunicationsConstraint,
    FailedDueToServerConstraint,
    NoError,
}

/// The names, in the order IEC 61850-7-2 Table 5 lists them ✅.
const SERVICE_ERRORS: [(ServiceError, &str); 13] = [
    (ServiceError::InstanceNotAvailable, "instance-not-available"),
    (ServiceError::InstanceInUse, "instance-in-use"),
    (ServiceError::AccessViolation, "access-violation"),
    (ServiceError::AccessNotAllowedInCurrentState, "access-not-allowed-in-current-state"),
    (ServiceError::ParameterValueInappropriate, "parameter-value-inappropriate"),
    (ServiceError::ParameterValueInconsistent, "parameter-value-inconsistent"),
    (ServiceError::ClassNotSupported, "class-not-supported"),
    (ServiceError::InstanceLockedByOtherClient, "instance-locked-by-other-client"),
    (ServiceError::ControlMustBeSelected, "control-must-be-selected"),
    (ServiceError::TypeConflict, "type-conflict"),
    (ServiceError::FailedDueToCommunicationsConstraint, "failed-due-to-communications-constraint"),
    (ServiceError::FailedDueToServerConstraint, "failed-due-to-server-constraint"),
    (ServiceError::NoError, "no-error"),
];

impl ServiceError {
    /// The name IEC 61850-7-2 gives it, which is also what an SCL `EnumVal` spells.
    pub fn as_str(self) -> &'static str {
        SERVICE_ERRORS.iter().find(|(v, _)| *v == self).map_or("no-error", |(_, n)| *n)
    }

    /// The error of that name, if the standard has one.
    pub fn parse(name: &str) -> Option<ServiceError> {
        SERVICE_ERRORS.iter().find(|(_, n)| *n == name).map(|(v, _)| *v)
    }

    /// Its position in Table 5 — the ordinal for a file that declares no `EnumType`.
    pub fn table_ordinal(self) -> i64 {
        SERVICE_ERRORS.iter().position(|(v, _)| *v == self).map_or(0, |i| i as i64)
    }

    /// The tracking error an ISO 9506 `DataAccessError` code maps to.
    ///
    /// The MMS mapping refuses with a `DataAccessError` and the tracking object publishes a
    /// 7-2 `ServiceError`, so one has to become the other. Where the tables do not line up the
    /// answer is the nearest true *statement*, not the nearest number.
    pub const fn from_data_access(code: i64) -> ServiceError {
        match code {
            // `object-invalidated`, `object-undefined`, `object-non-existent`
            0 | 4 | 10 => ServiceError::InstanceNotAvailable,
            // `temporarily-unavailable`
            2 => ServiceError::AccessNotAllowedInCurrentState,
            // `object-access-denied`
            3 => ServiceError::AccessViolation,
            // `invalid-address`, `object-value-invalid`
            5 | 11 => ServiceError::ParameterValueInappropriate,
            // `type-unsupported`, `type-inconsistent`
            6 | 7 => ServiceError::TypeConflict,
            // `object-attribute-inconsistent`
            8 => ServiceError::ParameterValueInconsistent,
            // `object-access-unsupported`
            9 => ServiceError::ClassNotSupported,
            // `hardware-fault`, and anything the table does not name.
            _ => ServiceError::FailedDueToServerConstraint,
        }
    }
}

impl core::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The common data classes IEC 61850-7-2 §14/§15.3.2/§20.6.2 defines for tracking ✅.
///
/// A logical device holds **no more than one** data object of each (§14.1). IEC 61850-7-4 names
/// them, which this crate does not need to know: the file declares the `cdc` and the server
/// finds the object by that.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrackingCdc {
    /// Common service tracking — anything not covered by a more specific one.
    Cst,
    /// Buffered report control block.
    Bts,
    /// Unbuffered report control block.
    Uts,
    /// Log control block.
    Lts,
    /// A log, and the two queries over it.
    Ots,
    /// GOOSE control block.
    Gts,
    /// Multicast sampled-value control block.
    Mts,
    /// Unicast sampled-value control block.
    Nts,
    /// Setting group control block.
    Sts,
    /// Control services on a controllable object.
    Cts,
}

impl TrackingCdc {
    /// The `cdc` string an SCL `DOType` carries for it.
    pub const fn as_str(self) -> &'static str {
        match self {
            TrackingCdc::Cst => "CST",
            TrackingCdc::Bts => "BTS",
            TrackingCdc::Uts => "UTS",
            TrackingCdc::Lts => "LTS",
            TrackingCdc::Ots => "OTS",
            TrackingCdc::Gts => "GTS",
            TrackingCdc::Mts => "MTS",
            TrackingCdc::Nts => "NTS",
            TrackingCdc::Sts => "STS",
            TrackingCdc::Cts => "CTS",
        }
    }

    /// The tracking class of that `cdc`, if it is one.
    pub fn parse(cdc: &str) -> Option<TrackingCdc> {
        [
            TrackingCdc::Cst,
            TrackingCdc::Bts,
            TrackingCdc::Uts,
            TrackingCdc::Lts,
            TrackingCdc::Ots,
            TrackingCdc::Gts,
            TrackingCdc::Mts,
            TrackingCdc::Nts,
            TrackingCdc::Sts,
            TrackingCdc::Cts,
        ]
        .into_iter()
        .find(|c| c.as_str() == cdc)
    }
}

/// One service, as a tracking data object records it.
///
/// The block-specific half — `rptID`, `goEna`, `actSG`, … — is deliberately absent: those are
/// the control block's own attributes with a lower-case first letter, so the engine copies them
/// from the block [`Tracked::obj_ref`] names.
#[derive(Clone, Debug, PartialEq)]
pub struct Tracked {
    /// Which tracking data object records it.
    pub cdc: TrackingCdc,
    /// `objRef` — the control block that was accessed, or the object that was controlled.
    pub obj_ref: String,
    /// `serviceType`.
    pub service: ServiceType,
    /// `errorCode` — `NoError` for a service that worked, which is tracked too.
    pub error: ServiceError,
    /// `originatorID` — who asked. The peer's network address, which is what the transport
    /// knows and the ACSI layer cannot invent (the same octets `Owner` carries).
    pub originator: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lists_are_the_standards_lists() {
        // Round-trip every name, because the name is what an SCL `EnumVal` spells and the
        // whole ordinal-from-the-file design rests on matching it.
        for (v, n) in SERVICE_TYPES {
            assert_eq!(ServiceType::parse(n), Some(v));
            assert_eq!(v.as_str(), n);
        }
        for (v, n) in SERVICE_ERRORS {
            assert_eq!(ServiceError::parse(n), Some(v));
            assert_eq!(v.as_str(), n);
        }
        // The fallback ordinals are positions in Table 26 and Table 5.
        assert_eq!(ServiceType::GetServerDirectory.table_ordinal(), 0);
        assert_eq!(ServiceType::SetBRCBValues.table_ordinal(), 23);
        assert_eq!(ServiceError::NoError.table_ordinal(), 12);
        assert_eq!(ServiceType::parse("NoSuchService"), None);
    }

    #[test]
    fn a_refused_service_keeps_its_meaning_across_the_two_tables() {
        // The MMS mapping answers with a `DataAccessError` and the tracking object publishes a
        // 7-2 `ServiceError`; what has to survive is the *statement*, not the number.
        // The codes are ISO 9506's `DataAccessError`, and 0 is `object-invalidated` rather
        // than success — a success never reaches here, because `Ok(())` is `NoError` directly.
        assert_eq!(ServiceError::from_data_access(3), ServiceError::AccessViolation);
        assert_eq!(ServiceError::from_data_access(10), ServiceError::InstanceNotAvailable);
        assert_eq!(ServiceError::from_data_access(0), ServiceError::InstanceNotAvailable);
        assert_eq!(ServiceError::from_data_access(7), ServiceError::TypeConflict);
        // Anything the table does not name is a server constraint rather than a guess.
        assert_eq!(ServiceError::from_data_access(99), ServiceError::FailedDueToServerConstraint);
    }

    #[test]
    fn a_tracking_cdc_is_recognised_by_the_cdc_the_file_declares() {
        assert_eq!(TrackingCdc::parse("BTS"), Some(TrackingCdc::Bts));
        assert_eq!(TrackingCdc::parse("CTS"), Some(TrackingCdc::Cts));
        // An ordinary data object is not a tracker, which is what stops the engine writing
        // into a breaker position that happens to sit in the same logical device.
        assert_eq!(TrackingCdc::parse("DPC"), None);
    }
}
