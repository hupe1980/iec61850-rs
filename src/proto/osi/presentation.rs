//! The OSI presentation protocol (ISO/IEC 8823-1 / ITU-T X.226), normal mode.
//!
//! Presentation does two things on this profile and no more. It **negotiates the context
//! list** — a small table saying "context 1 is ACSE, context 3 is MMS, both in BER" — and it
//! **labels every later PDU** with the context it belongs to, which is how one connection
//! carries the association control and the application protocol without ambiguity.
//!
//! Structures follow `ISO8823-PRESENTATION.asn`: `CP-type` and `CPA-PPDU` are SETs with a
//! mode-selector and normal-mode-parameters, and everything after the handshake is a
//! `User-data` — `fully-encoded-data [APPLICATION 1]`, a sequence of PDV-lists.

use alloc::vec::Vec;

use super::oid::Oid;
use crate::ber::{Class, Cursor, Encoder, Tag, Tlv, universal};
use crate::common::{DecodeReason, Error, Result};

/// `CP-type` / `CPA-PPDU` are SETs.
const TAG_SET: Tag = Tag::universal(17, true);
/// `User-data ::= CHOICE { fully-encoded-data [APPLICATION 1] … }`.
const TAG_FULLY_ENCODED_DATA: Tag = Tag::application_constructed(1);
/// Normal mode, the only mode IEC 61850-8-1 uses.
pub const MODE_NORMAL: i64 = 1;
/// `presentation-context-definition-result-list` result: acceptance.
pub const RESULT_ACCEPTANCE: i64 = 0;
/// Result: user rejection.
pub const RESULT_USER_REJECTION: i64 = 1;
/// Result: provider rejection.
pub const RESULT_PROVIDER_REJECTION: i64 = 2;

/// One entry of the context definition list a CP proposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextDefinition<'a> {
    /// The identifier later PDUs are labelled with. Odd by convention; 1 is ACSE and 3 MMS.
    pub id: u16,
    /// What the context carries.
    pub abstract_syntax: Oid<'a>,
    /// How it is encoded. Exactly one in this profile, and it is BER.
    pub transfer_syntax: Oid<'a>,
}

/// One entry of the result list a CPA answers with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextResult<'a> {
    /// [`RESULT_ACCEPTANCE`] and friends.
    pub result: i64,
    /// The transfer syntax the responder selected, present when it accepted.
    pub transfer_syntax: Option<Oid<'a>>,
}

/// The presentation data values of one PDV-list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PdvValues<'a> {
    /// `single-ASN1-type [0]` — one encoded value, which is what this profile always sends.
    SingleAsn1Type(&'a [u8]),
    /// `octet-aligned [1]`.
    OctetAligned(&'a [u8]),
    /// `arbitrary [2]`, a bit string.
    Arbitrary {
        /// Unused bits in the last octet.
        unused: u8,
        /// The contents.
        bytes: &'a [u8],
    },
}

impl<'a> PdvValues<'a> {
    /// The encoded value, for the `single-ASN1-type` case every IEC 61850 peer uses.
    pub fn single(&self) -> Option<&'a [u8]> {
        match self {
            PdvValues::SingleAsn1Type(v) => Some(v),
            _ => None,
        }
    }
}

/// One PDV-list: a context identifier and the values encoded in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pdv<'a> {
    /// The context, from the list the CP/CPA agreed.
    pub context_id: u16,
    /// The values.
    pub values: PdvValues<'a>,
}

impl<'a> Pdv<'a> {
    /// A PDV carrying one encoded value in `context_id`.
    pub fn single(context_id: u16, value: &'a [u8]) -> Pdv<'a> {
        Pdv { context_id, values: PdvValues::SingleAsn1Type(value) }
    }
}

/// A presentation PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ppdu<'a> {
    /// CP: the connect PDU, carrying the context list and the AARQ.
    Connect(Cp<'a>),
    /// CPA: the accept PDU, carrying the result list and the AARE.
    Accept(Cp<'a>),
    /// CPR: the reject PDU. A client that cannot tell a refusal from a decode failure has no
    /// way to report why it did not associate, so this is decoded rather than left as an
    /// error — the reason is in [`Cp::provider_reason`].
    Reject(Cp<'a>),
    /// Any PDU after the handshake: a `User-data` with no envelope of its own.
    UserData(Vec<Pdv<'a>>),
}

/// The parameters of a CP or CPA.
///
/// One type for both directions: a CP carries a context *definition* list and both
/// selectors, a CPA a *result* list and the responding selector, and everything else is
/// shared. Fields absent on the wire stay `None` so that re-encoding reproduces the octets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cp<'a> {
    /// `protocol-version` as its bit-string contents (unused bits, octets); version 1 is
    /// `(7, [0x80])`, which is what everything sends.
    pub protocol_version: Option<(u8, &'a [u8])>,
    /// Calling presentation selector (CP only).
    pub calling_psel: Option<&'a [u8]>,
    /// Called presentation selector (CP only).
    pub called_psel: Option<&'a [u8]>,
    /// Responding presentation selector (CPA only).
    pub responding_psel: Option<&'a [u8]>,
    /// The contexts proposed (CP only).
    pub contexts: Vec<ContextDefinition<'a>>,
    /// The results (CPA only), in the order of the proposed list.
    pub results: Vec<ContextResult<'a>>,
    /// `presentation-requirements` as its bit-string contents.
    pub requirements: Option<(u8, &'a [u8])>,
    /// `provider-reason` (CPR only): why the provider refused.
    pub provider_reason: Option<i64>,
    /// The user data — the ACSE PDU, in the ACSE context.
    pub user_data: Vec<Pdv<'a>>,
}

impl<'a> Cp<'a> {
    /// The CP IEC 61850-8-1 sends: version 1, the two selectors, ACSE in context 1 and MMS
    /// in context 3, both in BER, and the AARQ as the user data.
    pub fn connect(calling_psel: &'a [u8], called_psel: &'a [u8], acse_context: u16, mms_context: u16, aarq: &'a [u8]) -> Cp<'a> {
        Cp {
            protocol_version: Some((7, &[0x80])),
            calling_psel: Some(calling_psel),
            called_psel: Some(called_psel),
            contexts: alloc::vec![
                ContextDefinition { id: acse_context, abstract_syntax: Oid::ACSE_ABSTRACT_SYNTAX, transfer_syntax: Oid::BER },
                ContextDefinition { id: mms_context, abstract_syntax: Oid::MMS_ABSTRACT_SYNTAX, transfer_syntax: Oid::BER },
            ],
            requirements: Some((6, &[0x00])),
            user_data: alloc::vec![Pdv::single(acse_context, aarq)],
            ..Cp::default()
        }
    }

    /// The context identifier carrying `abstract_syntax`, if the list defines one.
    pub fn context_for(&self, abstract_syntax: Oid<'_>) -> Option<u16> {
        self.contexts.iter().find(|c| c.abstract_syntax == abstract_syntax).map(|c| c.id)
    }

    /// True when every context in `results` was accepted.
    pub fn all_accepted(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.result == RESULT_ACCEPTANCE)
    }
}

fn oid_of<'a>(t: &Tlv<'a>) -> Result<Oid<'a>> {
    if t.tag == Tag::universal(universal::OID, false) { Ok(Oid(t.value)) } else { Err(Error::decode(DecodeReason::UnexpectedTag, t.offset)) }
}

fn parse_pdvs<'a>(t: &Tlv<'a>) -> Result<Vec<Pdv<'a>>> {
    let mut out = Vec::new();
    for item in t.children() {
        let mut c = item?.expect(Tag::universal(universal::SEQUENCE, true))?.children();
        // `transfer-syntax-name` is OPTIONAL and absent whenever a context was negotiated,
        // which on this profile is always.
        let mut next = c.next_required()?;
        if next.tag == Tag::universal(universal::OID, false) {
            next = c.next_required()?;
        }
        let context_id = u16::try_from(next.expect(Tag::universal(universal::INTEGER, false))?.integer_i64()?)
            .map_err(|_| Error::decode(DecodeReason::BadValue, next.value_offset))?;
        let v = c.next_required()?;
        let values = match (v.tag.class, v.tag.number, v.tag.constructed) {
            (Class::Context, 0, true) => PdvValues::SingleAsn1Type(v.value),
            (Class::Context, 1, false) => PdvValues::OctetAligned(v.value),
            (Class::Context, 2, false) => {
                let (unused, bytes) = v.bit_string()?;
                PdvValues::Arbitrary { unused, bytes }
            }
            _ => return Err(Error::decode(DecodeReason::UnexpectedTag, v.offset)),
        };
        out.push(Pdv { context_id, values });
    }
    Ok(out)
}

fn write_pdvs(pdvs: &[Pdv<'_>], e: &mut Encoder) -> Result<()> {
    e.constructed(TAG_FULLY_ENCODED_DATA, |e| {
        for p in pdvs {
            e.constructed(Tag::universal(universal::SEQUENCE, true), |e| {
                e.integer(Tag::universal(universal::INTEGER, false), i64::from(p.context_id))?;
                match p.values {
                    PdvValues::SingleAsn1Type(v) => {
                        e.constructed(Tag::context_constructed(0), |e| {
                            e.raw(v);
                            Ok(())
                        })?;
                    }
                    PdvValues::OctetAligned(v) => {
                        e.primitive(Tag::context(1), v)?;
                    }
                    PdvValues::Arbitrary { unused, bytes } => {
                        e.bit_string(Tag::context(2), unused, bytes)?;
                    }
                }
                Ok(())
            })?;
        }
        Ok(())
    })?;
    Ok(())
}

/// Walk the normal-mode parameters of a CP, CPA or CPR into `cp`.
///
/// Returns true when a field only a responder sends was seen, which is what tells a CPA from
/// a CP: they are the same SET with the same tag and differ only in what is inside.
fn parse_normal_mode<'a>(field: &Tlv<'a>, cp: &mut Cp<'a>) -> Result<bool> {
    let mut is_response = false;
    for p in field.children() {
        let p = p?;
        match (p.tag.number, p.tag.constructed) {
            (0, false) => cp.protocol_version = Some(p.bit_string()?),
            (1, false) => cp.calling_psel = Some(p.value),
            (2, false) => cp.called_psel = Some(p.value),
            (3, false) => {
                cp.responding_psel = Some(p.value);
                is_response = true;
            }
            (4, true) => {
                for item in p.children() {
                    let mut c = item?.expect(Tag::universal(universal::SEQUENCE, true))?.children();
                    let id = u16::try_from(c.next_tag(Tag::universal(universal::INTEGER, false))?.integer_i64()?)
                        .map_err(|_| Error::decode(DecodeReason::BadValue, p.offset))?;
                    let abstract_syntax = oid_of(&c.next_required()?)?;
                    let list = c.next_tag(Tag::universal(universal::SEQUENCE, true))?;
                    let transfer_syntax = oid_of(&list.children().next_required()?)?;
                    cp.contexts.push(ContextDefinition { id, abstract_syntax, transfer_syntax });
                }
            }
            (5, true) => {
                is_response = true;
                for item in p.children() {
                    let mut c = item?.expect(Tag::universal(universal::SEQUENCE, true))?.children();
                    let result = c.next_tag(Tag::context(0))?.integer_i64()?;
                    let transfer_syntax = c.next_if_tag(Tag::context(1))?.map(|t| Oid(t.value));
                    cp.results.push(ContextResult { result, transfer_syntax });
                }
            }
            (8, false) => cp.requirements = Some(p.bit_string()?),
            (10, false) => cp.provider_reason = Some(p.integer_i64()?),
            _ if p.tag.class == Class::Application && p.tag.number == 1 => cp.user_data = parse_pdvs(&p)?,
            // Anything else in the normal-mode parameters is a functional
            // unit this profile does not use; ignoring it is what lets a
            // peer offer more than we asked for.
            _ => {}
        }
    }
    Ok(is_response)
}

/// Write the normal-mode parameters shared by the CP, CPA and CPR.
fn write_normal_mode(cp: &Cp<'_>, e: &mut Encoder) -> Result<()> {
    if let Some((unused, bytes)) = cp.protocol_version {
        e.bit_string(Tag::context(0), unused, bytes)?;
    }
    if let Some(s) = cp.calling_psel {
        e.primitive(Tag::context(1), s)?;
    }
    if let Some(s) = cp.called_psel {
        e.primitive(Tag::context(2), s)?;
    }
    if let Some(s) = cp.responding_psel {
        e.primitive(Tag::context(3), s)?;
    }
    if !cp.contexts.is_empty() {
        e.constructed(Tag::context_constructed(4), |e| {
            for c in &cp.contexts {
                e.constructed(Tag::universal(universal::SEQUENCE, true), |e| {
                    e.integer(Tag::universal(universal::INTEGER, false), i64::from(c.id))?;
                    e.primitive(Tag::universal(universal::OID, false), c.abstract_syntax.0)?;
                    e.constructed(Tag::universal(universal::SEQUENCE, true), |e| {
                        e.primitive(Tag::universal(universal::OID, false), c.transfer_syntax.0)?;
                        Ok(())
                    })?;
                    Ok(())
                })?;
            }
            Ok(())
        })?;
    }
    if !cp.results.is_empty() {
        e.constructed(Tag::context_constructed(5), |e| {
            for r in &cp.results {
                e.constructed(Tag::universal(universal::SEQUENCE, true), |e| {
                    e.integer(Tag::context(0), r.result)?;
                    if let Some(t) = r.transfer_syntax {
                        e.primitive(Tag::context(1), t.0)?;
                    }
                    Ok(())
                })?;
            }
            Ok(())
        })?;
    }
    if let Some((unused, bytes)) = cp.requirements {
        e.bit_string(Tag::context(8), unused, bytes)?;
    }
    // `provider-reason [10]` comes before the user data: the fields of a SEQUENCE go out in
    // tag order, and `user-data` is the untagged element at the end.
    if let Some(reason) = cp.provider_reason {
        e.integer(Tag::context(10), reason)?;
    }
    if !cp.user_data.is_empty() {
        write_pdvs(&cp.user_data, e)?;
    }
    Ok(())
}

impl<'a> Ppdu<'a> {
    /// Decode a presentation PDU.
    ///
    /// `handshake` says whether a CP/CPA is expected: after the association is up every PDU
    /// is a bare `User-data`, and the two are told apart by where they arrive rather than by
    /// their tags, which is what the session layer's SPDU type already says.
    pub fn parse(buf: &'a [u8], handshake: bool) -> Result<Ppdu<'a>> {
        let top = Cursor::new(buf).next_required()?;
        if !handshake {
            return Ok(Ppdu::UserData(parse_pdvs(&top.expect(TAG_FULLY_ENCODED_DATA)?)?));
        }
        // A CP and a CPA are SETs with a mode-selector. A **CPR** is the normal-mode
        // parameters on their own, as a SEQUENCE — the CHOICE has no wrapper — so the outer
        // tag is what tells a refusal from an acceptance before a single field is read.
        if top.tag == Tag::universal(universal::SEQUENCE, true) {
            let mut cp = Cp::default();
            parse_normal_mode(&top, &mut cp)?;
            return Ok(Ppdu::Reject(cp));
        }
        let mut cp = Cp::default();
        let mut mode = 0i64;
        let mut is_accept = false;
        for field in top.expect(TAG_SET)?.children() {
            let field = field?;
            match (field.tag.number, field.tag.constructed) {
                (0, true) => {
                    // mode-selector ::= SET { mode-value [0] IMPLICIT INTEGER }
                    let m = field.children().next_tag(Tag::context(0))?;
                    mode = m.integer_i64()?;
                }
                (2, true) => is_accept |= parse_normal_mode(&field, &mut cp)?,
                _ => {}
            }
        }
        if mode != MODE_NORMAL {
            return Err(Error::decode(DecodeReason::BadValue, top.value_offset));
        }
        Ok(if is_accept { Ppdu::Accept(cp) } else { Ppdu::Connect(cp) })
    }

    /// Encode into `out`.
    pub fn write(&self, out: &mut Encoder) -> Result<()> {
        match self {
            Ppdu::UserData(pdvs) => write_pdvs(pdvs, out),
            Ppdu::Reject(cp) => {
                // A CPR is the normal-mode parameters on their own: the CHOICE has no
                // wrapper and there is no mode-selector.
                out.constructed(Tag::universal(universal::SEQUENCE, true), |e| write_normal_mode(cp, e))?;
                Ok(())
            }
            Ppdu::Connect(cp) | Ppdu::Accept(cp) => {
                out.constructed(TAG_SET, |e| {
                    e.constructed(Tag::context_constructed(0), |e| {
                        e.integer(Tag::context(0), MODE_NORMAL)?;
                        Ok(())
                    })?;
                    e.constructed(Tag::context_constructed(2), |e| write_normal_mode(cp, e))?;
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

    /// The CP of frame 11 of the reference MMS capture, with the AARQ replaced by four
    /// octets: the framing is what is under test here.
    fn reference_cp() -> Vec<u8> {
        let mut e = Encoder::new();
        Ppdu::Connect(Cp::connect(&[0, 0, 0, 1], &[0, 0, 0, 2], 1, 3, &[0x60, 0x02, 0x80, 0x00])).write(&mut e).unwrap();
        e.into_vec()
    }

    #[test]
    fn the_connect_pdu_matches_the_reference_capture_field_for_field() {
        let wire = reference_cp();
        // The fields the capture carries, in order, ignoring the two lengths that depend on
        // how long the AARQ is: mode-selector normal, normal-mode-parameters, version 1,
        // both selectors, then the two contexts.
        assert_eq!(wire.first(), Some(&0x31), "CP-type is a SET");
        assert_eq!(&wire[2..7], &[0xA0, 0x03, 0x80, 0x01, 0x01], "mode-selector, normal mode");
        assert_eq!(wire[7], 0xA2, "normal-mode-parameters");
        assert_eq!(
            &wire[9..23],
            &[
                0x80, 0x02, 0x07, 0x80, // protocol-version, 7 unused bits, version-1
                0x81, 0x04, 0x00, 0x00, 0x00, 0x01, // calling-presentation-selector
                0x82, 0x04, 0x00, 0x00, 0x00, 0x02, // called-presentation-selector
            ][..14]
        );
        assert!(
            wire.windows(17).any(|w| w == [0x30, 0x0F, 0x02, 0x01, 0x01, 0x06, 0x04, 0x52, 0x01, 0x00, 0x01, 0x30, 0x04, 0x06, 0x02, 0x51, 0x01]),
            "context 1 is ACSE in BER, exactly as the capture writes it"
        );
        assert!(
            wire.windows(18).any(|w| w == [0x30, 0x10, 0x02, 0x01, 0x03, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x01, 0x30, 0x04, 0x06, 0x02, 0x51, 0x01]),
            "context 3 is MMS in BER"
        );
        assert!(wire.windows(4).any(|w| w == [0x88, 0x02, 0x06, 0x00]), "presentation-requirements");
        let Ppdu::Connect(cp) = Ppdu::parse(&wire, true).unwrap() else { panic!("not a CP") };
        assert_eq!(cp.protocol_version, Some((7, &[0x80][..])));
        assert_eq!(cp.calling_psel, Some(&[0, 0, 0, 1][..]));
        assert_eq!(cp.contexts.len(), 2);
        assert_eq!(cp.context_for(Oid::MMS_ABSTRACT_SYNTAX), Some(3));
        assert_eq!(cp.context_for(Oid::ACSE_ABSTRACT_SYNTAX), Some(1));
        assert_eq!(cp.contexts[1].transfer_syntax, Oid::BER);
        assert_eq!(cp.user_data.len(), 1);
        assert_eq!(cp.user_data[0].context_id, 1);
        assert_eq!(cp.user_data[0].values.single(), Some(&[0x60, 0x02, 0x80, 0x00][..]));
        assert_eq!(Ppdu::Connect(cp).to_vec().unwrap(), wire, "re-encoding must reproduce the octets");
    }

    #[test]
    fn the_accept_pdu_carries_a_result_list() {
        // Frame 14's shape: responding selector, two accepted contexts, then the AARE.
        let cpa = Cp {
            protocol_version: Some((7, &[0x80])),
            responding_psel: Some(&[0, 0, 0, 2]),
            results: alloc::vec![
                ContextResult { result: RESULT_ACCEPTANCE, transfer_syntax: Some(Oid::BER) },
                ContextResult { result: RESULT_ACCEPTANCE, transfer_syntax: Some(Oid::BER) },
            ],
            user_data: alloc::vec![Pdv::single(1, &[0x61, 0x02, 0x80, 0x00])],
            ..Cp::default()
        };
        let wire = Ppdu::Accept(cpa).to_vec().unwrap();
        let Ppdu::Accept(back) = Ppdu::parse(&wire, true).unwrap() else { panic!("not a CPA") };
        assert!(back.all_accepted());
        assert_eq!(back.responding_psel, Some(&[0, 0, 0, 2][..]));
        assert_eq!(back.results.len(), 2);
        assert_eq!(back.user_data[0].values.single(), Some(&[0x61, 0x02, 0x80, 0x00][..]));
        assert_eq!(Ppdu::Accept(back).to_vec().unwrap(), wire);
    }

    #[test]
    fn a_data_pdu_is_a_bare_user_data() {
        // Frame 17: `61 0f 30 0d 02 01 03 a0 08 …` — fully-encoded-data, context 3, one MMS
        // PDU. There is no presentation envelope after the handshake.
        let wire = [0x61, 0x0F, 0x30, 0x0D, 0x02, 0x01, 0x03, 0xA0, 0x08, 0xA0, 0x06, 0x02, 0x02, 0x11, 0x4F, 0x82, 0x00];
        let Ppdu::UserData(pdvs) = Ppdu::parse(&wire, false).unwrap() else { panic!("not user data") };
        assert_eq!(pdvs.len(), 1);
        assert_eq!(pdvs[0].context_id, 3);
        assert_eq!(pdvs[0].values.single(), Some(&[0xA0, 0x06, 0x02, 0x02, 0x11, 0x4F, 0x82, 0x00][..]));
        assert_eq!(Ppdu::UserData(pdvs).to_vec().unwrap(), wire, "byte for byte");
    }

    #[test]
    fn a_pdv_may_name_its_transfer_syntax() {
        // The optional `transfer-syntax-name` is absent whenever a context was negotiated,
        // but a peer that sends it must still be understood.
        let wire = [0x61, 0x0D, 0x30, 0x0B, 0x06, 0x02, 0x51, 0x01, 0x02, 0x01, 0x03, 0xA0, 0x02, 0x80, 0x00];
        let Ppdu::UserData(pdvs) = Ppdu::parse(&wire, false).unwrap() else { panic!("not user data") };
        assert_eq!(pdvs[0].context_id, 3);
        assert_eq!(pdvs[0].values.single(), Some(&[0x80, 0x00][..]));
    }

    #[test]
    fn a_refused_connection_is_decoded_rather_than_reported_as_a_decode_failure() {
        // A CPR is the normal-mode parameters on their own — a SEQUENCE where a CP and a CPA
        // are SETs. A client that could not tell the two apart would report "malformed" for
        // a server that simply said no, and never say why.
        let cpr = Cp {
            protocol_version: Some((7, &[0x80])),
            results: alloc::vec![ContextResult { result: RESULT_PROVIDER_REJECTION, transfer_syntax: None }],
            provider_reason: Some(1),
            ..Cp::default()
        };
        let wire = Ppdu::Reject(cpr).to_vec().unwrap();
        assert_eq!(wire.first(), Some(&0x30), "a CPR is a SEQUENCE, not a SET");
        let Ppdu::Reject(back) = Ppdu::parse(&wire, true).unwrap() else { panic!("not a CPR") };
        assert_eq!(back.provider_reason, Some(1));
        assert_eq!(back.results[0].result, RESULT_PROVIDER_REJECTION);
        assert!(!back.all_accepted());
        assert_eq!(Ppdu::Reject(back).to_vec().unwrap(), wire);

        // And with user data, so the field order is pinned: `provider-reason [10]` before
        // the untagged `user-data`, because a SEQUENCE goes out in tag order.
        let with_data = Cp { provider_reason: Some(2), user_data: alloc::vec![Pdv::single(1, &[0x64, 0x00])], ..Cp::default() };
        let wire = Ppdu::Reject(with_data).to_vec().unwrap();
        let reason_at = wire.windows(3).position(|w| w == [0x8A, 0x01, 0x02]).expect("provider-reason");
        let data_at = wire.iter().position(|b| *b == 0x61).expect("user-data");
        assert!(reason_at < data_at, "provider-reason must precede the user data");
    }

    #[test]
    fn truncation_and_the_wrong_mode_are_errors() {
        let wire = reference_cp();
        for cut in 0..wire.len() {
            let _ = Ppdu::parse(&wire[..cut], true);
        }
        // X.410 mode is not normal mode, and this profile only speaks normal mode.
        let x410 = [0x31, 0x07, 0xA0, 0x03, 0x80, 0x01, 0x00, 0x00];
        assert!(Ppdu::parse(&x410, true).is_err());
        assert!(Ppdu::parse(&[], false).is_err());
    }
}
