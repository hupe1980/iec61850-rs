//! The MMS `reject-PDU` (ISO 9506-2): what a peer says when a PDU is not a service failure
//! but a PDU it cannot make sense of at all.
//!
//! The distinction matters and is easy to get wrong. A **confirmed-error** answers a service
//! that was recognised and failed; a **reject** answers a PDU that was malformed, named a
//! service the peer does not implement, carried an invoke identifier it cannot use, or
//! exceeded what was negotiated. ISO 9506-2 gives the reject its own PDU with its own reason
//! table for each PDU type it can be provoked by, and the reason is the diagnosis — a client
//! told `max-serv-outstanding-exceeded` knows to slow down, and one told
//! `unrecognized-service` knows not to ask again.
//!
//! A reject also **answers an outstanding request**. Treating it as anything else is how a
//! client ends up waiting out its whole request timeout for an answer that already arrived:
//! the `originalInvokeID` names the request that will never be answered any other way.

use alloc::vec::Vec;

use crate::ber::{Encoder, Tag, Tlv};
use crate::common::{DecodeReason, Error, Result};

/// Which PDU the peer was rejecting, and why.
///
/// The reason codes are per-PDU-type tables in ISO 9506-2's `RejectPDU`, verified against
/// `mms.asn` ✅. The numbers differ between the tables — `invalid-invokeID` is 3 under
/// `ConfirmedRequest` and 2 under `ConfirmedResponse` — so the pair is kept together rather
/// than flattened into one code, which is the mistake that makes a reject unreadable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    /// `confirmed-requestPDU [1]`: 0 other, 1 unrecognized-service, 2 unrecognized-modifier,
    /// 3 invalid-invokeID, 4 invalid-argument, 5 invalid-modifier,
    /// 6 max-serv-outstanding-exceeded, 8 max-recursion-exceeded, 9 value-out-of-range.
    ConfirmedRequest(i64),
    /// `confirmed-responsePDU [2]`.
    ConfirmedResponse(i64),
    /// `confirmed-errorPDU [3]`.
    ConfirmedError(i64),
    /// `unconfirmedPDU [4]`.
    Unconfirmed(i64),
    /// `pdu-error [5]`: 0 unknown-pdu-type, 1 invalid-pdu, 2 illegal-acse-mapping.
    PduError(i64),
    /// `cancel-requestPDU [6]`.
    CancelRequest(i64),
    /// `cancel-responsePDU [7]`.
    CancelResponse(i64),
    /// `cancel-errorPDU [8]`.
    CancelError(i64),
    /// `conclude-requestPDU [9]`.
    ConcludeRequest(i64),
    /// `conclude-responsePDU [10]`.
    ConcludeResponse(i64),
    /// `conclude-errorPDU [11]`.
    ConcludeError(i64),
    /// A tag this table does not have, kept so a reject from a peer that knows more than we
    /// do is still reported rather than swallowed.
    Other {
        /// The context tag number.
        tag: u32,
        /// The value.
        code: i64,
    },
}

/// `confirmed-requestPDU`: the service is not one this peer implements.
pub const UNRECOGNIZED_SERVICE: i64 = 1;
/// `confirmed-requestPDU`: the invoke identifier cannot be used — it is already outstanding.
pub const INVALID_INVOKE_ID: i64 = 3;
/// `confirmed-requestPDU`: the argument did not decode as the service requires.
pub const INVALID_ARGUMENT: i64 = 4;
/// `confirmed-requestPDU`: more requests are outstanding than were negotiated.
pub const MAX_SERV_OUTSTANDING_EXCEEDED: i64 = 6;
/// `pdu-error`: the tag is not a PDU type this peer knows.
pub const UNKNOWN_PDU_TYPE: i64 = 0;
/// `pdu-error`: the octets are not a PDU.
pub const INVALID_PDU: i64 = 1;

impl RejectReason {
    /// The context tag this reason travels under, and its code.
    pub const fn parts(self) -> (u32, i64) {
        match self {
            RejectReason::ConfirmedRequest(c) => (1, c),
            RejectReason::ConfirmedResponse(c) => (2, c),
            RejectReason::ConfirmedError(c) => (3, c),
            RejectReason::Unconfirmed(c) => (4, c),
            RejectReason::PduError(c) => (5, c),
            RejectReason::CancelRequest(c) => (6, c),
            RejectReason::CancelResponse(c) => (7, c),
            RejectReason::CancelError(c) => (8, c),
            RejectReason::ConcludeRequest(c) => (9, c),
            RejectReason::ConcludeResponse(c) => (10, c),
            RejectReason::ConcludeError(c) => (11, c),
            RejectReason::Other { tag, code } => (tag, code),
        }
    }

    /// From the tag and code on the wire.
    pub const fn from_parts(tag: u32, code: i64) -> RejectReason {
        match tag {
            1 => RejectReason::ConfirmedRequest(code),
            2 => RejectReason::ConfirmedResponse(code),
            3 => RejectReason::ConfirmedError(code),
            4 => RejectReason::Unconfirmed(code),
            5 => RejectReason::PduError(code),
            6 => RejectReason::CancelRequest(code),
            7 => RejectReason::CancelResponse(code),
            8 => RejectReason::CancelError(code),
            9 => RejectReason::ConcludeRequest(code),
            10 => RejectReason::ConcludeResponse(code),
            11 => RejectReason::ConcludeError(code),
            tag => RejectReason::Other { tag, code },
        }
    }
}

impl core::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (kind, names): (&str, &[&str]) = match self {
            RejectReason::ConfirmedRequest(_) => (
                "confirmed-request",
                &[
                    "other",
                    "unrecognized-service",
                    "unrecognized-modifier",
                    "invalid-invokeID",
                    "invalid-argument",
                    "invalid-modifier",
                    "max-serv-outstanding-exceeded",
                    "",
                    "max-recursion-exceeded",
                    "value-out-of-range",
                ],
            ),
            RejectReason::ConfirmedResponse(_) => (
                "confirmed-response",
                &["other", "unrecognized-service", "invalid-invokeID", "invalid-result", "", "max-recursion-exceeded", "value-out-of-range"],
            ),
            RejectReason::ConfirmedError(_) => {
                ("confirmed-error", &["other", "unrecognized-service", "invalid-invokeID", "invalid-serviceError", "value-out-of-range"])
            }
            RejectReason::Unconfirmed(_) => {
                ("unconfirmed", &["other", "unrecognized-service", "invalid-argument", "max-recursion-exceeded", "value-out-of-range"])
            }
            RejectReason::PduError(_) => ("pdu-error", &["unknown-pdu-type", "invalid-pdu", "illegal-acse-mapping"]),
            RejectReason::CancelRequest(_) | RejectReason::CancelResponse(_) => ("cancel", &["other", "invalid-invokeID"]),
            RejectReason::CancelError(_) => ("cancel-error", &["other", "invalid-invokeID", "invalid-serviceError", "value-out-of-range"]),
            RejectReason::ConcludeRequest(_) => ("conclude-request", &["other", "invalid-argument"]),
            RejectReason::ConcludeResponse(_) => ("conclude-response", &["other", "invalid-result"]),
            RejectReason::ConcludeError(_) => ("conclude-error", &["other", "invalid-serviceError", "value-out-of-range"]),
            RejectReason::Other { tag, code } => return write!(f, "reject({tag}): {code}"),
        };
        let (_, code) = self.parts();
        match usize::try_from(code).ok().and_then(|i| names.get(i)).copied().filter(|n| !n.is_empty()) {
            Some(name) => write!(f, "{kind}: {name}"),
            None => write!(f, "{kind}: {code}"),
        }
    }
}

/// A decoded `reject-PDU`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reject {
    /// The request being rejected, when the peer names one. Absent for a PDU that carried no
    /// usable invoke identifier at all.
    pub original_invoke_id: Option<i64>,
    /// Why.
    pub reason: RejectReason,
}

impl Reject {
    /// A reject of the confirmed request `invoke_id`.
    pub const fn confirmed_request(invoke_id: i64, code: i64) -> Reject {
        Reject { original_invoke_id: Some(invoke_id), reason: RejectReason::ConfirmedRequest(code) }
    }

    /// A reject of a PDU that could not be read as one at all.
    pub const fn pdu_error(code: i64) -> Reject {
        Reject { original_invoke_id: None, reason: RejectReason::PduError(code) }
    }

    /// Decode the contents of a `rejectPDU [4]`.
    ///
    /// The `rejectReason` CHOICE is `[1]`–`[11] IMPLICIT INTEGER`: every alternative is a
    /// **primitive** context tag, and `[0]` is `originalInvokeID` rather than a reason. Both
    /// have to be checked, because round-tripping depends on it — a constructed `[0]` read as
    /// a reason re-encodes as a primitive `[0]`, which parses back as an `originalInvokeID`
    /// with no reason after it: a PDU that decodes once and not twice.
    pub fn parse(t: &Tlv<'_>) -> Result<Reject> {
        let mut c = t.children();
        // `Unsigned32`: a negative or oversized identifier names no request this peer could
        // have issued. Coercing it to 0 would report a reject of invoke 0 and release a slot
        // the peer never mentioned.
        let original_invoke_id = match c.next_if_tag(Tag::context(0))? {
            Some(t) => {
                let v = t.integer_i64()?;
                if !(0..=i64::from(u32::MAX)).contains(&v) {
                    return Err(Error::decode(DecodeReason::BadValue, t.value_offset));
                }
                Some(v)
            }
            None => None,
        };
        let reason = c.next_required()?;
        if reason.tag.class != crate::ber::Class::Context || reason.tag.constructed || reason.tag.number == 0 {
            return Err(Error::decode(DecodeReason::UnexpectedTag, reason.offset));
        }
        // Nothing may follow the reason: this codec does not keep unknown trailing octets, so
        // accepting them would mean re-encoding fewer bytes than arrived.
        c.finish()?;
        Ok(Reject { original_invoke_id, reason: RejectReason::from_parts(reason.tag.number, reason.integer_i64()?) })
    }

    /// Encode as a whole `rejectPDU [4]`.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        self.write(&mut e)?;
        Ok(e.into_vec())
    }

    /// Encode into `out` as a whole `rejectPDU [4]`.
    pub fn write(&self, out: &mut Encoder) -> Result<()> {
        let (tag, code) = self.reason.parts();
        out.constructed(Tag::context_constructed(4), |e| {
            if let Some(id) = self.original_invoke_id {
                // `originalInvokeID [0] IMPLICIT Unsigned32` ✅ — unsigned, so an identifier
                // above `i32::MAX` gets the leading zero octet rather than going negative.
                // Invoke identifiers here wrap just below the 32-bit ceiling, so that range
                // is reachable rather than theoretical. One outside `Unsigned32` is an error
                // rather than a value quietly replaced by a different one.
                let id = u32::try_from(id).map_err(|_| Error::Encode("originalInvokeID is Unsigned32"))?;
                e.unsigned(Tag::context(0), u64::from(id))?;
            }
            e.integer(Tag::context(tag), code)?;
            Ok(())
        })?;
        Ok(())
    }
}

impl Reject {
    /// The three numbers [`crate::common::Error::Rejected`] carries.
    ///
    /// `common` cannot name this type — it is the module every feature builds on — so the
    /// error carries the wire numbers and this is the one place that takes them apart.
    pub const fn to_error_parts(&self) -> (Option<i64>, u32, i64) {
        let (tag, code) = self.reason.parts();
        (self.original_invoke_id, tag, code)
    }
}

impl core::fmt::Display for Reject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.original_invoke_id {
            Some(id) => write!(f, "reject of invoke {id}: {}", self.reason),
            None => write!(f, "reject: {}", self.reason),
        }
    }
}

#[cfg(test)]
mod tests {
    // `ToString` is in `std`'s prelude and not in `alloc`'s, and these tests build under
    // `--no-default-features`.
    use alloc::string::ToString;

    use super::*;
    use crate::ber::Cursor;

    fn round_trip(r: Reject) -> Reject {
        let bytes = r.to_vec().expect("encode");
        let t = Cursor::new(&bytes).next_required().expect("frame");
        assert_eq!(t.tag, Tag::context_constructed(4));
        let back = Reject::parse(&t).expect("decode");
        assert_eq!(back, r);
        back
    }

    #[test]
    fn every_reason_table_round_trips() {
        for reason in [
            RejectReason::ConfirmedRequest(UNRECOGNIZED_SERVICE),
            RejectReason::ConfirmedRequest(MAX_SERV_OUTSTANDING_EXCEEDED),
            RejectReason::ConfirmedResponse(2),
            RejectReason::ConfirmedError(3),
            RejectReason::Unconfirmed(1),
            RejectReason::PduError(INVALID_PDU),
            RejectReason::CancelRequest(1),
            RejectReason::CancelResponse(0),
            RejectReason::CancelError(2),
            RejectReason::ConcludeRequest(1),
            RejectReason::ConcludeResponse(0),
            RejectReason::ConcludeError(0),
            RejectReason::Other { tag: 20, code: 7 },
        ] {
            round_trip(Reject { original_invoke_id: Some(42), reason });
            round_trip(Reject { original_invoke_id: None, reason });
        }
    }

    /// The reason codes are per-table: the same number means different things under different
    /// tags, which is why the pair travels together.
    #[test]
    fn a_code_is_read_against_its_own_table() {
        assert_eq!(RejectReason::ConfirmedRequest(3).to_string(), "confirmed-request: invalid-invokeID");
        assert_eq!(RejectReason::ConfirmedResponse(3).to_string(), "confirmed-response: invalid-result");
        assert_eq!(RejectReason::PduError(1).to_string(), "pdu-error: invalid-pdu");
        // A gap in a table (7 is not defined under confirmed-request) prints the number.
        assert_eq!(RejectReason::ConfirmedRequest(7).to_string(), "confirmed-request: 7");
        assert_eq!(RejectReason::Other { tag: 20, code: 7 }.to_string(), "reject(20): 7");
    }

    #[test]
    fn the_wire_shape_is_the_one_the_asn1_module_describes() {
        // `a4 06 80 01 2a 81 01 01` — rejectPDU { originalInvokeID 42, confirmed-requestPDU
        // unrecognized-service }.
        let r = Reject::confirmed_request(42, UNRECOGNIZED_SERVICE);
        assert_eq!(r.to_vec().unwrap(), [0xA4, 0x06, 0x80, 0x01, 42, 0x81, 0x01, 0x01]);
    }

    /// `originalInvokeID` is `Unsigned32`, and this crate's invoke identifiers run to just
    /// below the 32-bit ceiling — so the top half of the range has to encode as a positive
    /// integer rather than as a negative one.
    #[test]
    fn an_invoke_identifier_above_i32_max_stays_positive() {
        let r = Reject::confirmed_request(i64::from(u32::MAX) - 1, UNRECOGNIZED_SERVICE);
        let bytes = r.to_vec().unwrap();
        assert_eq!(&bytes[2..8], &[0x80, 0x05, 0x00, 0xFF, 0xFF, 0xFF], "the leading zero keeps it unsigned");
        assert_eq!(round_trip(r).original_invoke_id, Some(i64::from(u32::MAX) - 1));
    }

    /// The `rejectReason` alternatives are primitive context tags `[1]`–`[11]`; `[0]` is the
    /// `originalInvokeID`. A constructed `[0]` read as a reason re-encodes as a primitive one
    /// and parses back as an invoke identifier with no reason behind it — a PDU that decodes
    /// once and not twice (`fuzz/regressions/mms_stack`).
    #[test]
    fn a_reason_must_be_a_primitive_tag_that_is_not_the_invoke_identifier() {
        // `a4 0a a0 08 …` — rejectPDU whose only child is a *constructed* [0].
        let wire = [0xA4, 0x0A, 0xA0, 0x08, 0x1A, 0x03, 0x4C, 0x44, 0x35, 0x1A, 0x01, 0x54];
        let t = Cursor::new(&wire).next_required().unwrap();
        assert!(Reject::parse(&t).is_err(), "a constructed [0] is not a reject reason");

        // A constructed tag that *is* in the table is refused too: the alternatives are
        // `IMPLICIT INTEGER`, and an INTEGER is never constructed.
        let wire = [0xA4, 0x03, 0xA1, 0x01, 0x01];
        let t = Cursor::new(&wire).next_required().unwrap();
        assert!(Reject::parse(&t).is_err());

        // And the primitive spelling of the same thing is fine.
        let wire = [0xA4, 0x03, 0x81, 0x01, 0x01];
        let t = Cursor::new(&wire).next_required().unwrap();
        assert_eq!(Reject::parse(&t).unwrap().reason, RejectReason::ConfirmedRequest(UNRECOGNIZED_SERVICE));
    }

    /// Every reason table, spelled out against `mms.asn`.
    ///
    /// The tables are *not* the same list under different tags, and three of them nearly are:
    /// `conclude-request` code 1 is `invalid-argument`, `conclude-response` code 1 is
    /// `invalid-result`, and `conclude-error` code 1 is `invalid-serviceError`. Sharing one
    /// array between them reads two thirds of a reject as the wrong diagnosis, and nothing but
    /// the standard's own text says so.
    #[test]
    fn every_table_matches_the_asn1_module() {
        let cases: &[(RejectReason, &str)] = &[
            (RejectReason::ConfirmedRequest(0), "confirmed-request: other"),
            (RejectReason::ConfirmedRequest(2), "confirmed-request: unrecognized-modifier"),
            (RejectReason::ConfirmedRequest(5), "confirmed-request: invalid-modifier"),
            (RejectReason::ConfirmedRequest(6), "confirmed-request: max-serv-outstanding-exceeded"),
            (RejectReason::ConfirmedRequest(8), "confirmed-request: max-recursion-exceeded"),
            (RejectReason::ConfirmedRequest(9), "confirmed-request: value-out-of-range"),
            (RejectReason::ConfirmedResponse(5), "confirmed-response: max-recursion-exceeded"),
            (RejectReason::ConfirmedResponse(6), "confirmed-response: value-out-of-range"),
            (RejectReason::ConfirmedError(3), "confirmed-error: invalid-serviceError"),
            (RejectReason::ConfirmedError(4), "confirmed-error: value-out-of-range"),
            (RejectReason::Unconfirmed(2), "unconfirmed: invalid-argument"),
            (RejectReason::Unconfirmed(4), "unconfirmed: value-out-of-range"),
            (RejectReason::PduError(0), "pdu-error: unknown-pdu-type"),
            (RejectReason::PduError(2), "pdu-error: illegal-acse-mapping"),
            (RejectReason::CancelRequest(1), "cancel: invalid-invokeID"),
            (RejectReason::CancelResponse(1), "cancel: invalid-invokeID"),
            (RejectReason::CancelError(3), "cancel-error: value-out-of-range"),
            // The three that are nearly the same list and are not.
            (RejectReason::ConcludeRequest(1), "conclude-request: invalid-argument"),
            (RejectReason::ConcludeResponse(1), "conclude-response: invalid-result"),
            (RejectReason::ConcludeError(1), "conclude-error: invalid-serviceError"),
            (RejectReason::ConcludeError(2), "conclude-error: value-out-of-range"),
        ];
        for (reason, want) in cases {
            assert_eq!(&reason.to_string(), want);
        }
        // A code the table has no name for prints as the number rather than as a neighbour's
        // name: `confirmed-request` has no 7, and `conclude-response` has no 2.
        assert_eq!(RejectReason::ConfirmedRequest(7).to_string(), "confirmed-request: 7");
        assert_eq!(RejectReason::ConcludeResponse(2).to_string(), "conclude-response: 2");
        assert_eq!(RejectReason::ConfirmedResponse(4).to_string(), "confirmed-response: 4");
    }

    /// `originalInvokeID` is `Unsigned32`. A negative one names no request any peer could
    /// have issued; reading it as 0 would report a reject of invoke 0 and release a slot the
    /// peer never mentioned.
    #[test]
    fn an_invoke_identifier_outside_unsigned32_is_refused_rather_than_coerced() {
        // `a4 06 80 01 fb 81 01 01` — originalInvokeID −5.
        let wire = [0xA4, 0x06, 0x80, 0x01, 0xFB, 0x81, 0x01, 0x01];
        let t = Cursor::new(&wire).next_required().unwrap();
        assert!(Reject::parse(&t).is_err(), "−5 is not an Unsigned32");

        // Five octets that exceed `u32::MAX`.
        let wire = [0xA4, 0x0A, 0x80, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x81, 0x01, 0x01];
        let t = Cursor::new(&wire).next_required().unwrap();
        assert!(Reject::parse(&t).is_err());

        // …and the encoder refuses the same rather than writing a different number.
        assert!(Reject::confirmed_request(-5, UNRECOGNIZED_SERVICE).to_vec().is_err());
        assert!(Reject::confirmed_request(i64::from(u32::MAX) + 1, UNRECOGNIZED_SERVICE).to_vec().is_err());
        // The whole legal range still encodes.
        assert!(Reject::confirmed_request(0, UNRECOGNIZED_SERVICE).to_vec().is_ok());
        assert!(Reject::confirmed_request(i64::from(u32::MAX), UNRECOGNIZED_SERVICE).to_vec().is_ok());
    }

    /// Anything after the reason would be dropped by the encoder, so it is refused instead.
    #[test]
    fn trailing_content_after_the_reason_is_refused() {
        let wire = [0xA4, 0x06, 0x81, 0x01, 0x01, 0x82, 0x01, 0x02];
        let t = Cursor::new(&wire).next_required().unwrap();
        assert!(Reject::parse(&t).is_err());
    }

    #[test]
    fn a_truncated_reject_is_an_error_not_a_panic() {
        let bytes = Reject::confirmed_request(1, 1).to_vec().unwrap();
        for cut in 0..bytes.len() {
            if let Ok(t) = Cursor::new(&bytes[..cut]).next_required() {
                let _ = Reject::parse(&t);
            }
        }
    }
}
