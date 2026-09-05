//! ACSE, the association control service element (ISO/IEC 8650-1 / ITU-T X.227).
//!
//! ACSE is the layer that says *who* is associating and *what for*: the application context
//! name (`1.0.9506.2.3` for MMS), the AP-titles and AE-qualifiers that address the peer, and
//! — the part IEC 61850-8-1 actually uses for security — an authentication value, which on
//! this profile is a password.
//!
//! The MMS `Initiate` PDU rides inside the AARQ's `user-information`, wrapped in an
//! `EXTERNAL` whose `indirect-reference` is the presentation context identifier. So one
//! `Associate` request on the wire is a session CONNECT carrying a presentation CP carrying
//! an ACSE AARQ carrying an MMS Initiate — four layers, one TCP segment.

use alloc::vec::Vec;

use super::oid::Oid;
use crate::ber::{Class, Cursor, Encoder, Tag, universal};
use crate::common::{DecodeReason, Error, Result};

/// `AARQ-apdu [APPLICATION 0]`.
pub const TAG_AARQ: Tag = Tag::application_constructed(0);
/// `AARE-apdu [APPLICATION 1]`.
pub const TAG_AARE: Tag = Tag::application_constructed(1);
/// `RLRQ-apdu [APPLICATION 2]`.
pub const TAG_RLRQ: Tag = Tag::application_constructed(2);
/// `RLRE-apdu [APPLICATION 3]`.
pub const TAG_RLRE: Tag = Tag::application_constructed(3);
/// `ABRT-apdu [APPLICATION 4]`.
pub const TAG_ABRT: Tag = Tag::application_constructed(4);
/// `EXTERNAL [UNIVERSAL 8]`.
const TAG_EXTERNAL: Tag = Tag::universal(8, true);

/// `Associate-result`: accepted.
pub const RESULT_ACCEPTED: i64 = 0;
/// `Associate-result`: rejected (permanent).
pub const RESULT_REJECTED_PERMANENT: i64 = 1;
/// `Associate-result`: rejected (transient).
pub const RESULT_REJECTED_TRANSIENT: i64 = 2;

/// An ACSE APDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Apdu<'a> {
    /// AARQ — associate request.
    Associate(Associate<'a>),
    /// AARE — associate response.
    AssociateResponse(Associate<'a>),
    /// RLRQ — release request, with its reason.
    Release(Option<i64>),
    /// RLRE — release response.
    ReleaseResponse(Option<i64>),
    /// ABRT — abort, with its source.
    Abort(Option<i64>),
}

/// The fields of an AARQ or AARE.
///
/// One type for both, because they differ in three fields and share nine. `result` and
/// `result_source_diagnostic` are the AARE's; everything else appears in both.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Associate<'a> {
    /// `protocol-version` as its bit-string contents; version 1 is `(7, [0x80])`.
    pub protocol_version: Option<(u8, &'a [u8])>,
    /// The application context name — `1.0.9506.2.3` for MMS.
    pub context_name: Option<Oid<'a>>,
    /// `result` (AARE only).
    pub result: Option<i64>,
    /// `result-source-diagnostic`, kept as the encoded choice so it re-encodes exactly.
    pub result_diagnostic: Option<&'a [u8]>,
    /// Called AP-title, as its encoded `AP-title` choice.
    pub called_ap_title: Option<&'a [u8]>,
    /// Called AE-qualifier.
    pub called_ae_qualifier: Option<&'a [u8]>,
    /// Responding AP-title (AARE).
    pub responding_ap_title: Option<&'a [u8]>,
    /// Responding AE-qualifier (AARE).
    pub responding_ae_qualifier: Option<&'a [u8]>,
    /// Calling AP-title (AARQ).
    pub calling_ap_title: Option<&'a [u8]>,
    /// Calling AE-qualifier (AARQ).
    pub calling_ae_qualifier: Option<&'a [u8]>,
    /// `sender-acse-requirements`, the bit string that says authentication is in use.
    pub sender_requirements: Option<(u8, &'a [u8])>,
    /// `mechanism-name` — [`Oid::PASSWORD_MECHANISM`] for the IEC 61850-8-1 password.
    pub mechanism_name: Option<Oid<'a>>,
    /// The authentication value, as its encoded choice; `[0]` is a `GraphicString` password.
    pub authentication_value: Option<&'a [u8]>,
    /// The `user-information`: the MMS PDU and the presentation context it is encoded in.
    pub user_information: Option<UserInformation<'a>>,
}

/// The `EXTERNAL` inside `user-information`, which is how the MMS PDU travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserInformation<'a> {
    /// `direct-reference`, the transfer syntax — `2.1.1`, and often omitted.
    pub direct_reference: Option<Oid<'a>>,
    /// `indirect-reference`, the presentation context identifier the value belongs to.
    pub indirect_reference: Option<i64>,
    /// The encoded value — an MMS `Initiate` PDU.
    pub value: &'a [u8],
}

impl<'a> Associate<'a> {
    /// The AARQ IEC 61850-8-1 sends: MMS application context, the four naming fields, and
    /// the MMS Initiate PDU as user information in the MMS presentation context.
    pub fn request(called_ap_title: Option<&'a [u8]>, calling_ap_title: Option<&'a [u8]>, mms_context: i64, initiate: &'a [u8]) -> Associate<'a> {
        Associate {
            protocol_version: Some((7, &[0x80])),
            context_name: Some(Oid::MMS_APPLICATION_CONTEXT),
            called_ap_title,
            calling_ap_title,
            user_information: Some(UserInformation { direct_reference: Some(Oid::BER), indirect_reference: Some(mms_context), value: initiate }),
            ..Associate::default()
        }
    }

    /// True when this AARE accepted the association.
    pub fn accepted(&self) -> bool {
        self.result == Some(RESULT_ACCEPTED)
    }

    /// The encoded MMS PDU the association information carries.
    pub fn mms_pdu(&self) -> Option<&'a [u8]> {
        self.user_information.map(|u| u.value)
    }
}

fn parse_external<'a>(t: &crate::ber::Tlv<'a>) -> Result<UserInformation<'a>> {
    let mut c = t.expect(TAG_EXTERNAL)?.children();
    let mut out = UserInformation { direct_reference: None, indirect_reference: None, value: &[] };
    let mut next = c.next_required()?;
    if next.tag == Tag::universal(universal::OID, false) {
        out.direct_reference = Some(Oid(next.value));
        next = c.next_required()?;
    }
    if next.tag == Tag::universal(universal::INTEGER, false) {
        out.indirect_reference = Some(next.integer_i64()?);
        next = c.next_required()?;
    }
    // `encoding ::= CHOICE { single-ASN1-type [0], octet-aligned [1], arbitrary [2] }`.
    out.value = match (next.tag.class, next.tag.number) {
        (Class::Context, 0 | 1) => next.value,
        _ => return Err(Error::decode(DecodeReason::UnexpectedTag, next.offset)),
    };
    Ok(out)
}

impl<'a> Apdu<'a> {
    /// Decode an ACSE APDU.
    pub fn parse(buf: &'a [u8]) -> Result<Apdu<'a>> {
        let top = Cursor::new(buf).next_required()?;
        if top.tag.class != Class::Application {
            return Err(Error::decode(DecodeReason::UnexpectedTag, top.offset));
        }
        match top.tag.number {
            0 | 1 => {
                let mut a = Associate::default();
                for field in top.children() {
                    let f = field?;
                    if f.tag.class != Class::Context {
                        continue;
                    }
                    match f.tag.number {
                        0 => a.protocol_version = Some(f.bit_string()?),
                        1 => a.context_name = Some(Oid(f.children().next_required()?.value)),
                        2 if top.tag.number == 0 => a.called_ap_title = Some(f.value),
                        2 => a.result = Some(f.children().next_required()?.integer_i64()?),
                        3 if top.tag.number == 0 => a.called_ae_qualifier = Some(f.value),
                        3 => a.result_diagnostic = Some(f.value),
                        4 if top.tag.number == 1 => a.responding_ap_title = Some(f.value),
                        5 if top.tag.number == 1 => a.responding_ae_qualifier = Some(f.value),
                        6 => a.calling_ap_title = Some(f.value),
                        7 => a.calling_ae_qualifier = Some(f.value),
                        8 if top.tag.number == 1 => a.sender_requirements = Some(f.bit_string()?),
                        10 if top.tag.number == 0 => a.sender_requirements = Some(f.bit_string()?),
                        9 if top.tag.number == 1 => a.mechanism_name = Some(Oid(f.value)),
                        11 if top.tag.number == 0 => a.mechanism_name = Some(Oid(f.value)),
                        10 if top.tag.number == 1 => a.authentication_value = Some(f.value),
                        12 if top.tag.number == 0 => a.authentication_value = Some(f.value),
                        30 => a.user_information = Some(parse_external(&f.children().next_required()?)?),
                        // Fields this profile does not use — invocation identifiers, the
                        // context-name list, implementation information — are skipped rather
                        // than refused: a peer may send more than we need.
                        _ => {}
                    }
                }
                Ok(if top.tag.number == 0 { Apdu::Associate(a) } else { Apdu::AssociateResponse(a) })
            }
            2..=4 => {
                let mut value = None;
                for field in top.children() {
                    let f = field?;
                    if f.tag.class == Class::Context && f.tag.number == 0 {
                        value = Some(f.integer_i64()?);
                    }
                }
                Ok(match top.tag.number {
                    2 => Apdu::Release(value),
                    3 => Apdu::ReleaseResponse(value),
                    _ => Apdu::Abort(value),
                })
            }
            _ => Err(Error::decode(DecodeReason::UnexpectedTag, top.offset)),
        }
    }

    /// Encode into `out`.
    #[allow(clippy::too_many_lines)] // one field per line, in tag order; splitting it hides the order
    pub fn write(&self, out: &mut Encoder) -> Result<()> {
        match self {
            Apdu::Associate(a) | Apdu::AssociateResponse(a) => {
                let request = matches!(self, Apdu::Associate(_));
                let tag = if request { TAG_AARQ } else { TAG_AARE };
                out.constructed(tag, |e| {
                    if let Some((unused, bytes)) = a.protocol_version {
                        e.bit_string(Tag::context(0), unused, bytes)?;
                    }
                    if let Some(oid) = a.context_name {
                        e.constructed(Tag::context_constructed(1), |e| {
                            e.primitive(Tag::universal(universal::OID, false), oid.0)?;
                            Ok(())
                        })?;
                    }
                    if request {
                        for (n, v) in [(2, a.called_ap_title), (3, a.called_ae_qualifier)] {
                            if let Some(v) = v {
                                e.primitive(Tag::context_constructed(n), v)?;
                            }
                        }
                    } else {
                        if let Some(r) = a.result {
                            e.constructed(Tag::context_constructed(2), |e| {
                                e.integer(Tag::universal(universal::INTEGER, false), r)?;
                                Ok(())
                            })?;
                        }
                        if let Some(d) = a.result_diagnostic {
                            e.primitive(Tag::context_constructed(3), d)?;
                        }
                        for (n, v) in [(4, a.responding_ap_title), (5, a.responding_ae_qualifier)] {
                            if let Some(v) = v {
                                e.primitive(Tag::context_constructed(n), v)?;
                            }
                        }
                    }
                    for (n, v) in [(6, a.calling_ap_title), (7, a.calling_ae_qualifier)] {
                        if let Some(v) = v {
                            e.primitive(Tag::context_constructed(n), v)?;
                        }
                    }
                    // The requirement, mechanism and authentication fields sit at different
                    // tags in the AARQ (10, 11, 12) and the AARE (8, 9, 10).
                    let (req, mech, auth) = if request { (10, 11, 12) } else { (8, 9, 10) };
                    if let Some((unused, bytes)) = a.sender_requirements {
                        e.bit_string(Tag::context(req), unused, bytes)?;
                    }
                    if let Some(oid) = a.mechanism_name {
                        e.primitive(Tag::context(mech), oid.0)?;
                    }
                    if let Some(v) = a.authentication_value {
                        e.primitive(Tag::context_constructed(auth), v)?;
                    }
                    if let Some(u) = a.user_information {
                        e.constructed(Tag::context_constructed(30), |e| {
                            e.constructed(TAG_EXTERNAL, |e| {
                                if let Some(oid) = u.direct_reference {
                                    e.primitive(Tag::universal(universal::OID, false), oid.0)?;
                                }
                                if let Some(i) = u.indirect_reference {
                                    e.integer(Tag::universal(universal::INTEGER, false), i)?;
                                }
                                e.constructed(Tag::context_constructed(0), |e| {
                                    e.raw(u.value);
                                    Ok(())
                                })?;
                                Ok(())
                            })?;
                            Ok(())
                        })?;
                    }
                    Ok(())
                })?;
                Ok(())
            }
            Apdu::Release(v) | Apdu::ReleaseResponse(v) | Apdu::Abort(v) => {
                let tag = match self {
                    Apdu::Release(_) => TAG_RLRQ,
                    Apdu::ReleaseResponse(_) => TAG_RLRE,
                    _ => TAG_ABRT,
                };
                out.constructed(tag, |e| {
                    if let Some(v) = v {
                        e.integer(Tag::context(0), *v)?;
                    }
                    Ok(())
                })?;
                Ok(())
            }
        }
    }

    /// Encode into a new buffer.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        self.write(&mut e)?;
        Ok(e.into_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AARQ of frame 11 of the reference capture, byte for byte, with the MMS Initiate
    /// PDU cut to two octets.
    const REFERENCE_AARQ: &[u8] = &[
        0x60, 0x32, // AARQ
        0x80, 0x02, 0x07, 0x80, // protocol-version
        0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x01, 0x01, // aSO-context-name 1.0.9506.1.1
        0xA2, 0x04, 0x06, 0x02, 0x29, 0x02, // called-AP-title 1.1.2
        0xA3, 0x03, 0x02, 0x01, 0x02, // called-AE-qualifier 2
        0xA6, 0x04, 0x06, 0x02, 0x29, 0x01, // calling-AP-title 1.1.1
        0xA7, 0x03, 0x02, 0x01, 0x01, // calling-AE-qualifier 1
        0xBE, 0x0D, // user-information
        0x28, 0x0B, 0x06, 0x02, 0x51, 0x01, 0x02, 0x01, 0x03, // EXTERNAL: BER, context 3
        0xA0, 0x02, 0xA8, 0x00, // single-ASN1-type { initiate-RequestPDU }
    ];

    #[test]
    fn the_reference_associate_request_round_trips_byte_for_byte() {
        let Apdu::Associate(a) = Apdu::parse(REFERENCE_AARQ).unwrap() else { panic!("not an AARQ") };
        assert_eq!(a.protocol_version, Some((7, &[0x80][..])));
        assert_eq!(a.context_name, Some(Oid::MMS_APPLICATION_CONTEXT_9506));
        assert_eq!(a.called_ap_title, Some(&[0x06, 0x02, 0x29, 0x02][..]));
        assert_eq!(a.calling_ae_qualifier, Some(&[0x02, 0x01, 0x01][..]));
        let u = a.user_information.unwrap();
        assert_eq!(u.direct_reference, Some(Oid::BER));
        assert_eq!(u.indirect_reference, Some(3));
        assert_eq!(a.mms_pdu(), Some(&[0xA8, 0x00][..]));
        assert_eq!(Apdu::Associate(a).to_vec().unwrap(), REFERENCE_AARQ);
    }

    #[test]
    fn an_associate_response_carries_the_result_and_the_external_may_omit_its_syntax() {
        // Frame 14's shape: the AARE's EXTERNAL has no direct-reference, only the context.
        let wire: &[u8] = &[
            0x61, 0x24, // AARE
            0x80, 0x02, 0x07, 0x80, // protocol-version
            0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x01, 0x01, // aSO-context-name
            0xA2, 0x03, 0x02, 0x01, 0x00, // result: accepted
            0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00, // result-source-diagnostic
            0xBE, 0x09, 0x28, 0x07, 0x02, 0x01, 0x03, 0xA0, 0x02, 0xA9, 0x00,
        ];
        let Apdu::AssociateResponse(a) = Apdu::parse(wire).unwrap() else { panic!("not an AARE") };
        assert!(a.accepted());
        assert_eq!(a.result_diagnostic, Some(&[0xA1, 0x03, 0x02, 0x01, 0x00][..]));
        let u = a.user_information.unwrap();
        assert_eq!((u.direct_reference, u.indirect_reference), (None, Some(3)));
        assert_eq!(a.mms_pdu(), Some(&[0xA9, 0x00][..]));
        assert_eq!(Apdu::AssociateResponse(a).to_vec().unwrap(), wire);
    }

    #[test]
    fn the_password_fields_sit_at_different_tags_in_the_request_and_the_response() {
        // IEC 61850-8-1's ACSE password: sender-acse-requirements says authentication is in
        // use, mechanism-name names it, and the value carries it. The AARQ numbers those
        // 10/11/12 and the AARE 8/9/10 — reading one set into the other is the classic way
        // to make a server reject a correct password.
        let mut a = Associate::request(None, None, 3, &[0xA8, 0x00]);
        a.sender_requirements = Some((7, &[0x80]));
        a.mechanism_name = Some(Oid::PASSWORD_MECHANISM);
        a.authentication_value = Some(&[0x80, 0x04, b'p', b'a', b's', b's']);
        let wire = Apdu::Associate(a).to_vec().unwrap();
        assert!(wire.windows(2).any(|w| w == [0x8A, 0x02]), "sender-acse-requirements is [10] in an AARQ");
        assert!(wire.windows(2).any(|w| w == [0x8B, 0x03]), "mechanism-name is [11]");
        assert!(wire.windows(2).any(|w| w == [0xAC, 0x06]), "calling-authentication-value is [12]");
        let Apdu::Associate(back) = Apdu::parse(&wire).unwrap() else { panic!() };
        assert_eq!(back.mechanism_name, Some(Oid::PASSWORD_MECHANISM));
        assert_eq!(back.authentication_value, Some(&[0x80, 0x04, b'p', b'a', b's', b's'][..]));

        let mut r = Associate { result: Some(RESULT_ACCEPTED), ..Associate::default() };
        r.sender_requirements = Some((7, &[0x80]));
        r.mechanism_name = Some(Oid::PASSWORD_MECHANISM);
        let wire = Apdu::AssociateResponse(r).to_vec().unwrap();
        assert!(wire.windows(2).any(|w| w == [0x88, 0x02]), "responder-acse-requirements is [8] in an AARE");
        assert!(wire.windows(2).any(|w| w == [0x89, 0x03]), "mechanism-name is [9]");
    }

    #[test]
    fn release_and_abort_round_trip() {
        for (apdu, first) in [(Apdu::Release(Some(0)), 0x62u8), (Apdu::ReleaseResponse(Some(0)), 0x63), (Apdu::Abort(Some(1)), 0x64)] {
            let wire = apdu.to_vec().unwrap();
            assert_eq!(wire.first(), Some(&first));
            assert_eq!(Apdu::parse(&wire).unwrap(), apdu);
        }
        assert_eq!(Apdu::parse(&[0x62, 0x00]).unwrap(), Apdu::Release(None));
    }

    #[test]
    fn truncation_is_an_error_not_a_panic() {
        for cut in 0..REFERENCE_AARQ.len() {
            let _ = Apdu::parse(&REFERENCE_AARQ[..cut]);
        }
        assert!(Apdu::parse(&[]).is_err());
        assert!(Apdu::parse(&[0x30, 0x00]).is_err(), "a SEQUENCE is not an ACSE APDU");
        assert!(Apdu::parse(&[0x6F, 0x00]).is_err(), "an unknown application tag");
    }
}
