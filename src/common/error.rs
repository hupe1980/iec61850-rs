use core::fmt;

use alloc::string::String;

/// The one error type of the crate.
///
/// Decoders never panic on input; every malformed byte becomes an [`Error::Decode`] with a
/// stable reason and the byte offset it was found at.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input did not decode. `offset` is measured from the start of the buffer handed
    /// to the decoder.
    Decode {
        /// What was wrong.
        reason: DecodeReason,
        /// Byte offset of the problem.
        offset: usize,
    },
    /// A configured limit (see [`crate::common::Limits`]) was exceeded before allocation.
    LimitExceeded {
        /// Which limit.
        limit: &'static str,
        /// The value that exceeded it.
        value: usize,
    },
    /// The value cannot be encoded as requested (e.g. a string that is not ASCII in a
    /// `VisibleString`, or a length above `u32::MAX`).
    Encode(&'static str),
    /// An object reference or SCL name is malformed.
    InvalidReference(&'static str),
    /// A referenced thing (IED, type, data set …) does not exist.
    NotFound(&'static str),
    /// A value is outside its domain (e.g. an APPID outside the GOOSE range).
    InvalidValue(&'static str),
    /// The SCL document is not well formed or violates the schema in a way the loader
    /// cannot work around. The string is the loader's message.
    Scl(String),
    /// The transport failed: the socket errored, or the peer closed the connection under an
    /// association that was still up.
    Io(String),
    /// The peer answered a confirmed request with an MMS `ServiceError`. `class` is the
    /// `errorClass` choice tag (7 = access, 8 = initiate, …) and `code` the integer inside
    /// it, which is what IEC 61850-8-1 maps the ACSI service errors onto.
    Service {
        /// The `errorClass` choice tag.
        class: u32,
        /// The integer that choice carries.
        code: i64,
    },
    /// One value of a `Read` or `Write` failed with an MMS `DataAccessError`: 10 is
    /// object-non-existent, 3 object-access-denied, 11 object-access-unsupported.
    DataAccess(i64),
    /// The peer **rejected** the PDU rather than failing the service: an unrecognised
    /// service, an invoke identifier it cannot use, more requests outstanding than were
    /// negotiated, or octets it could not read as a PDU at all. Distinct from
    /// [`Error::Service`], which is a service that ran and failed.
    ///
    /// The reason is carried as its two wire numbers rather than as the typed
    /// `RejectReason`, for the same reason [`Error::ControlRejected`] carries a bare
    /// `add_cause`: this module is `common`, and an error type that names a `proto::mms`
    /// type cannot be built without the `mms` feature. `RejectReason::from_parts(tag, code)`
    /// turns the pair back into the named value, and the tag matters — the same code means
    /// different things under different tags.
    Rejected {
        /// The request it rejects, when the peer named one.
        invoke_id: Option<i64>,
        /// The `rejectReason` choice tag: 1 confirmed-request, 2 confirmed-response,
        /// 3 confirmed-error, 4 unconfirmed, 5 pdu-error, …
        reason_tag: u32,
        /// The integer inside that choice.
        code: i64,
    },
    /// A control was refused or abandoned. `add_cause` is the IEC 61850-8-1 Table 77 value —
    /// `AddCause::from_code` names it — and it is the field that turns "the breaker did not
    /// close" into a diagnosis.
    ControlRejected {
        /// The `AddCause`.
        add_cause: i64,
    },
}

/// Why a decode failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeReason {
    /// Fewer bytes than the encoding requires.
    Truncated,
    /// A BER length that cannot be represented or is not allowed here.
    BadLength,
    /// Indefinite-length encoding, which this decoder does not accept.
    IndefiniteLength,
    /// A tag that is not valid at this position.
    UnexpectedTag,
    /// A required element is missing.
    MissingField,
    /// A primitive value is malformed (empty integer, bad float exponent width, …).
    BadValue,
    /// Nesting deeper than the configured limit.
    TooDeep,
    /// Trailing bytes after a complete element where none are allowed.
    TrailingBytes,
    /// A value that is not ASCII in a `VisibleString`.
    NotAscii,
    /// The Ethernet frame is not a GOOSE/SV frame (wrong `EtherType`) or too short.
    NotProcessBusFrame,
}

/// The ISO 9506-2 name of a `DataAccessError` code ✅ (`mms.asn`).
///
/// A bare number is the most common thing a user of an IEC 61850 client is left holding, and
/// `3` versus `10` is the difference between "you may not" and "it is not there" — two
/// completely different next steps. Naming it costs a table.
pub const fn data_access_reason(code: i64) -> Option<&'static str> {
    Some(match code {
        0 => "object-invalidated",
        1 => "hardware-fault",
        2 => "temporarily-unavailable",
        3 => "object-access-denied",
        4 => "object-undefined",
        5 => "invalid-address",
        6 => "type-unsupported",
        7 => "type-inconsistent",
        8 => "object-attribute-inconsistent",
        9 => "object-access-unsupported",
        10 => "object-non-existent",
        11 => "object-value-invalid",
        _ => return None,
    })
}

/// `Result` with the crate's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    pub(crate) const fn decode(reason: DecodeReason, offset: usize) -> Self {
        Error::Decode { reason, offset }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode { reason, offset } => write!(f, "decode error at byte {offset}: {reason:?}"),
            Error::LimitExceeded { limit, value } => write!(f, "limit `{limit}` exceeded by {value}"),
            Error::Encode(what) => write!(f, "encode error: {what}"),
            Error::InvalidReference(what) => write!(f, "invalid object reference: {what}"),
            Error::NotFound(what) => write!(f, "not found: {what}"),
            Error::InvalidValue(what) => write!(f, "invalid value: {what}"),
            Error::Scl(msg) => write!(f, "SCL: {msg}"),
            Error::Io(msg) => write!(f, "transport: {msg}"),
            Error::Service { class, code } => write!(f, "MMS service error: class {class}, code {code}"),
            Error::DataAccess(code) => match data_access_reason(*code) {
                Some(name) => write!(f, "MMS data access error {code} ({name})"),
                None => write!(f, "MMS data access error {code}"),
            },
            Error::Rejected { invoke_id, reason_tag, code } => match invoke_id {
                Some(id) => write!(f, "the peer rejected invoke {id}: reason {reason_tag}/{code}"),
                None => write!(f, "the peer rejected the PDU: reason {reason_tag}/{code}"),
            },
            Error::ControlRejected { add_cause } => write!(f, "control rejected, AddCause {add_cause}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Reading a file into a model, or a socket into an association, is the ordinary thing to do
/// with this crate, and both start with an `io::Error`. Without this a caller's `?` has to be
/// spelt out at every boundary, which is the sort of friction that pushes people to
/// `unwrap()`.
#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e.to_string())
    }
}
