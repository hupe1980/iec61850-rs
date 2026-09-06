//! The OSI session protocol (ISO/IEC 8327-1 / ITU-T X.225) as IEC 61850-8-1 uses it.
//!
//! An SPDU is `SI` (one octet saying which SPDU it is), `LI` (its length), then parameter
//! units — each a code, a length and a value, some of them nested inside a parameter *group*.
//! Values verified against X.225 (1995): SI codes ✅ §8.3, the length indicator rule ✅ §8.2.5
//! (0–254 in one octet; 255–65 535 as `FF` plus two octets, high order first), the ordering
//! rule ✅ §8.2.6 (units at one nesting level in increasing code order), and the CN user-data
//! limit ✅ §7.1.1 e) (512 octets in User Data, 513–10 240 in Extended User Data, more only
//! with the CONNECT DATA OVERFLOW SPDU).
//!
//! The odd part of this layer is that data transfer is **two** SPDUs concatenated: a GIVE
//! TOKENS with no parameters followed by a DATA TRANSFER with no parameters, after which the
//! user data simply follows. Both have `SI = 1` — GIVE TOKENS is a category-0 SPDU and DATA
//! TRANSFER a category-2 one — so `01 00 01 00` on the wire is not a repeat, it is the
//! four-octet preamble every MMS message in the reference capture starts with.

use alloc::vec::Vec;

use crate::common::{DecodeReason, Error, Result};

/// SI: DATA TRANSFER (category 2) — and GIVE TOKENS (category 0), which share the value.
pub const SI_DATA_TRANSFER: u8 = 1;
/// SI: GIVE TOKENS.
pub const SI_GIVE_TOKENS: u8 = 1;
/// SI: PLEASE TOKENS.
pub const SI_PLEASE_TOKENS: u8 = 2;
/// SI: FINISH.
pub const SI_FINISH: u8 = 9;
/// SI: DISCONNECT.
pub const SI_DISCONNECT: u8 = 10;
/// SI: REFUSE.
pub const SI_REFUSE: u8 = 12;
/// SI: CONNECT.
pub const SI_CONNECT: u8 = 13;
/// SI: ACCEPT.
pub const SI_ACCEPT: u8 = 14;
/// SI: ABORT.
pub const SI_ABORT: u8 = 25;
/// SI: ABORT ACCEPT.
pub const SI_ABORT_ACCEPT: u8 = 26;

/// PGI: Connect/Accept Item, which groups the protocol options and version.
pub const PGI_CONNECT_ACCEPT: u8 = 5;
/// PI: Protocol Options.
pub const PI_PROTOCOL_OPTIONS: u8 = 19;
/// PI: Session User Requirements.
pub const PI_SESSION_REQUIREMENT: u8 = 20;
/// PI: TSDU Maximum Size.
pub const PI_TSDU_MAX_SIZE: u8 = 21;
/// PI: Version Number.
pub const PI_VERSION_NUMBER: u8 = 22;
/// PI: Enclosure Item.
pub const PI_ENCLOSURE: u8 = 25;
/// PI: Reason Code.
pub const PI_REASON_CODE: u8 = 50;
/// PI: Calling Session Selector.
pub const PI_CALLING_SSEL: u8 = 51;
/// PI: Called Session Selector.
pub const PI_CALLED_SSEL: u8 = 52;
/// PI: User Data (≤ 512 octets).
pub const PI_USER_DATA: u8 = 193;
/// PI: Extended User Data (513–10 240 octets).
pub const PI_EXTENDED_USER_DATA: u8 = 194;

/// Version Number bit 2: protocol version 2, which IEC 61850-8-1 uses.
pub const VERSION_2: u8 = 0x02;
/// Session User Requirements bit 2: the duplex functional unit.
pub const REQUIREMENT_DUPLEX: u16 = 0x0002;
/// The largest user data a `User Data` parameter may carry ✅ X.225 §7.1.1 e).
pub const MAX_USER_DATA: usize = 512;
/// The largest user data an `Extended User Data` parameter may carry ✅ X.225 §7.1.1 e),
/// §8.3.1.21. Above this the standard wants a Data Overflow parameter and a CONNECT DATA
/// OVERFLOW SPDU, which this profile does not use.
pub const MAX_EXTENDED_USER_DATA: usize = 10_240;

/// A decoded SPDU.
///
/// `user_data` is the presentation PDU: this layer never looks inside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Spdu<'a> {
    /// CONNECT, with what the initiator proposes.
    Connect(Connect<'a>),
    /// ACCEPT, with what the responder selected.
    Accept(Connect<'a>),
    /// REFUSE: the responder declined the connection.
    Refuse {
        /// Reason code, if the SPDU carried one.
        reason: Option<u8>,
        /// User data.
        user_data: &'a [u8],
    },
    /// FINISH: an orderly release was requested.
    Finish(&'a [u8]),
    /// DISCONNECT: the orderly release was accepted.
    Disconnect(&'a [u8]),
    /// ABORT.
    Abort(&'a [u8]),
    /// ABORT ACCEPT.
    AbortAccept,
    /// GIVE TOKENS + DATA TRANSFER, and the user data that follows them.
    DataTransfer(&'a [u8]),
    /// An SPDU this profile does not use, kept whole so a tool can report it.
    Other {
        /// The SI.
        si: u8,
        /// Everything after the length indicator.
        body: &'a [u8],
    },
}

/// The parameters of a CONNECT or ACCEPT SPDU.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Connect<'a> {
    /// Protocol Options; 0 means "no extended concatenation", which is what this profile uses.
    pub protocol_options: u8,
    /// Version Number bits; [`VERSION_2`] for IEC 61850.
    pub version: u8,
    /// Session User Requirements; [`REQUIREMENT_DUPLEX`] for IEC 61850.
    pub requirements: u16,
    /// Calling session selector.
    pub calling_ssel: Option<&'a [u8]>,
    /// Called session selector.
    pub called_ssel: Option<&'a [u8]>,
    /// The presentation PDU.
    pub user_data: &'a [u8],
}

impl<'a> Connect<'a> {
    /// The proposal IEC 61850-8-1 makes: version 2, duplex, no extended concatenation.
    pub fn new(calling_ssel: Option<&'a [u8]>, called_ssel: Option<&'a [u8]>, user_data: &'a [u8]) -> Connect<'a> {
        Connect { protocol_options: 0, version: VERSION_2, requirements: REQUIREMENT_DUPLEX, calling_ssel, called_ssel, user_data }
    }
}

/// Read a length indicator: one octet, or `FF` and two more ✅ X.225 §8.2.5.
fn read_li(buf: &[u8], at: usize) -> Result<(usize, usize)> {
    let &first = buf.get(at).ok_or(Error::decode(DecodeReason::Truncated, at))?;
    if first != 0xFF {
        return Ok((usize::from(first), at + 1));
    }
    let (Some(&hi), Some(&lo)) = (buf.get(at + 1), buf.get(at + 2)) else {
        return Err(Error::decode(DecodeReason::Truncated, at + 1));
    };
    Ok((usize::from(u16::from_be_bytes([hi, lo])), at + 3))
}

/// Write a length indicator.
fn write_li(len: usize, out: &mut Vec<u8>) -> Result<()> {
    if len < 0xFF {
        out.push(len as u8);
        return Ok(());
    }
    let n = u16::try_from(len).map_err(|_| Error::Encode("session parameter exceeds 65535 octets"))?;
    out.push(0xFF);
    out.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

/// Walk the parameter units of an SPDU body, calling `f` with each code and value.
///
/// The Connect/Accept Item (PGI 5) is walked into: its members are reported as if they were
/// at the top level, which is what every consumer of this profile wants and what makes the
/// order rule (increasing code) enough to reproduce the encoding.
///
/// **Exactly one level.** X.225 §8.3.1 defines the Connect/Accept Item as a group of
/// parameter *units*, not of further groups, so a PGI inside a PGI is malformed — and walking
/// into it anyway would be a decoder whose recursion depth is `body.len() / 2`. Sixty-five
/// thousand octets of nested PGI is a legal TPKT packet and about twenty thousand stack
/// frames, which survives a desktop and does not survive the `no_std` targets this crate
/// claims. Depth is therefore a parameter, and the inner call passes zero.
fn for_each_parameter<'a>(body: &'a [u8], groups: u8, f: &mut dyn FnMut(u8, &'a [u8])) -> Result<()> {
    let mut at = 0usize;
    while at < body.len() {
        let &code = body.get(at).ok_or(Error::decode(DecodeReason::Truncated, at))?;
        let (len, value_at) = read_li(body, at + 1)?;
        let value = body.get(value_at..value_at.saturating_add(len)).ok_or(Error::decode(DecodeReason::Truncated, value_at))?;
        if code == PGI_CONNECT_ACCEPT && groups > 0 {
            for_each_parameter(value, groups - 1, f)?;
        } else {
            f(code, value);
        }
        at = value_at + len;
    }
    Ok(())
}

/// How many levels of parameter group [`for_each_parameter`] descends: one.
const PARAMETER_GROUPS: u8 = 1;

fn be_u16(v: &[u8]) -> u16 {
    match v {
        [a, b, ..] => u16::from_be_bytes([*a, *b]),
        [a] => u16::from(*a),
        [] => 0,
    }
}

impl<'a> Spdu<'a> {
    /// Decode one SPDU (and, for data transfer, the GIVE TOKENS in front of it).
    pub fn parse(buf: &'a [u8]) -> Result<Spdu<'a>> {
        let &si = buf.first().ok_or(Error::decode(DecodeReason::Truncated, 0))?;
        let (li, body_at) = read_li(buf, 1)?;
        let body = buf.get(body_at..body_at.saturating_add(li)).ok_or(Error::decode(DecodeReason::Truncated, body_at))?;
        let after = buf.get(body_at + li..).unwrap_or(&[]);

        // A category-0 SPDU is concatenated with the category-2 one that follows it; GIVE
        // TOKENS and DATA TRANSFER share SI = 1, so the first is only recognisable by being
        // first ✅ X.225 §6.3.6.
        if si == SI_GIVE_TOKENS && li == 0 {
            let &next = after.first().ok_or(Error::decode(DecodeReason::MissingField, body_at))?;
            if next != SI_DATA_TRANSFER {
                return Err(Error::decode(DecodeReason::UnexpectedTag, body_at + li));
            }
            let (dt_li, dt_at) = read_li(after, 1)?;
            let payload = after.get(dt_at + dt_li..).ok_or(Error::decode(DecodeReason::Truncated, dt_at))?;
            return Ok(Spdu::DataTransfer(payload));
        }

        Ok(match si {
            SI_CONNECT | SI_ACCEPT => {
                let mut c = Connect::default();
                let mut user_data: &[u8] = &[];
                for_each_parameter(body, PARAMETER_GROUPS, &mut |code, value| match code {
                    PI_PROTOCOL_OPTIONS => c.protocol_options = value.first().copied().unwrap_or(0),
                    PI_VERSION_NUMBER => c.version = value.first().copied().unwrap_or(VERSION_2),
                    PI_SESSION_REQUIREMENT => c.requirements = be_u16(value),
                    PI_CALLING_SSEL => c.calling_ssel = Some(value),
                    PI_CALLED_SSEL => c.called_ssel = Some(value),
                    PI_USER_DATA | PI_EXTENDED_USER_DATA => user_data = value,
                    _ => {}
                })?;
                c.user_data = user_data;
                if si == SI_CONNECT { Spdu::Connect(c) } else { Spdu::Accept(c) }
            }
            SI_REFUSE => {
                let (mut reason, mut user_data): (Option<u8>, &[u8]) = (None, &[]);
                for_each_parameter(body, PARAMETER_GROUPS, &mut |code, value| match code {
                    PI_REASON_CODE => reason = value.first().copied(),
                    PI_USER_DATA | PI_EXTENDED_USER_DATA => user_data = value,
                    _ => {}
                })?;
                Spdu::Refuse { reason, user_data }
            }
            SI_FINISH | SI_DISCONNECT | SI_ABORT => {
                let mut user_data: &[u8] = &[];
                for_each_parameter(body, PARAMETER_GROUPS, &mut |code, value| {
                    if matches!(code, PI_USER_DATA | PI_EXTENDED_USER_DATA) {
                        user_data = value;
                    }
                })?;
                match si {
                    SI_FINISH => Spdu::Finish(user_data),
                    SI_DISCONNECT => Spdu::Disconnect(user_data),
                    _ => Spdu::Abort(user_data),
                }
            }
            SI_ABORT_ACCEPT => Spdu::AbortAccept,
            _ => Spdu::Other { si, body },
        })
    }

    /// Encode into `out`.
    ///
    /// Parameters go out in increasing code order, which is what X.225 §8.2.6 requires and
    /// what makes the encoding of a decoded SPDU reproduce its octets.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Spdu::DataTransfer(payload) => {
                out.extend_from_slice(&[SI_GIVE_TOKENS, 0, SI_DATA_TRANSFER, 0]);
                out.extend_from_slice(payload);
                Ok(())
            }
            Spdu::Connect(c) | Spdu::Accept(c) => {
                let si = if matches!(self, Spdu::Connect(_)) { SI_CONNECT } else { SI_ACCEPT };
                let mut body = Vec::with_capacity(c.user_data.len() + 32);
                // Connect/Accept Item: protocol options and version, in that order.
                body.push(PGI_CONNECT_ACCEPT);
                body.push(6);
                body.extend_from_slice(&[PI_PROTOCOL_OPTIONS, 1, c.protocol_options]);
                body.extend_from_slice(&[PI_VERSION_NUMBER, 1, c.version]);
                body.extend_from_slice(&[PI_SESSION_REQUIREMENT, 2]);
                body.extend_from_slice(&c.requirements.to_be_bytes());
                for (code, ssel) in [(PI_CALLING_SSEL, c.calling_ssel), (PI_CALLED_SSEL, c.called_ssel)] {
                    if let Some(s) = ssel {
                        body.push(code);
                        write_li(s.len(), &mut body)?;
                        body.extend_from_slice(s);
                    }
                }
                // `User Data` carries 512 octets or fewer; 513–10 240 go in `Extended User
                // Data`, which exists precisely for this and needs nothing but protocol
                // version 2 — which this profile always proposes ✅ §7.1.1 e), §8.3.1.21.
                // Only one of the two may be present ✅ §8.3.1.21. **CONNECT only**: the
                // ACCEPT SPDU's Table 14 has no Extended User Data, so a large AARE has to be
                // an error rather than a parameter the peer will not recognise.
                //
                // Above 10 240 the standard wants a Data Overflow parameter and a CONNECT
                // DATA OVERFLOW SPDU ✅ §7.1.1 f); that is a second SPDU exchange this
                // profile does not use, so it stays an error rather than a guess.
                if !c.user_data.is_empty() {
                    let extended = c.user_data.len() > MAX_USER_DATA;
                    if extended && si != SI_CONNECT {
                        return Err(Error::Encode("an ACCEPT SPDU carries at most 512 octets of user data"));
                    }
                    if c.user_data.len() > MAX_EXTENDED_USER_DATA {
                        return Err(Error::Encode("session user data above 10240 octets needs a CONNECT DATA OVERFLOW SPDU"));
                    }
                    body.push(if extended { PI_EXTENDED_USER_DATA } else { PI_USER_DATA });
                    write_li(c.user_data.len(), &mut body)?;
                    body.extend_from_slice(c.user_data);
                }
                out.push(si);
                write_li(body.len(), out)?;
                out.extend_from_slice(&body);
                Ok(())
            }
            Spdu::Refuse { reason, user_data } => {
                let mut body = Vec::new();
                if let Some(r) = reason {
                    body.extend_from_slice(&[PI_REASON_CODE, 1, *r]);
                }
                Spdu::write_user_data(&mut body, user_data)?;
                out.push(SI_REFUSE);
                write_li(body.len(), out)?;
                out.extend_from_slice(&body);
                Ok(())
            }
            Spdu::Finish(user_data) | Spdu::Disconnect(user_data) | Spdu::Abort(user_data) => {
                let si = match self {
                    Spdu::Finish(_) => SI_FINISH,
                    Spdu::Disconnect(_) => SI_DISCONNECT,
                    _ => SI_ABORT,
                };
                let mut body = Vec::new();
                Spdu::write_user_data(&mut body, user_data)?;
                out.push(si);
                write_li(body.len(), out)?;
                out.extend_from_slice(&body);
                Ok(())
            }
            Spdu::AbortAccept => {
                out.extend_from_slice(&[SI_ABORT_ACCEPT, 0]);
                Ok(())
            }
            Spdu::Other { si, body } => {
                out.push(*si);
                write_li(body.len(), out)?;
                out.extend_from_slice(body);
                Ok(())
            }
        }
    }

    fn write_user_data(body: &mut Vec<u8>, user_data: &[u8]) -> Result<()> {
        if user_data.is_empty() {
            return Ok(());
        }
        if user_data.len() > MAX_USER_DATA {
            return Err(Error::Encode("session user data above 512 octets needs Extended User Data"));
        }
        body.push(PI_USER_DATA);
        write_li(user_data.len(), body)?;
        body.extend_from_slice(user_data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// X.225 §7.1.1 e): 513–10 240 octets go in `Extended User Data` (PI 194), which needs
    /// protocol version 2 and nothing else. Refusing anything over 512 would put an artificial
    /// ceiling on an AARQ — the one PDU that grows, because IEC 62351-4 authentication values
    /// and AP-titles live in it.
    #[test]
    fn a_connect_above_512_octets_uses_extended_user_data() {
        for len in [MAX_USER_DATA, MAX_USER_DATA + 1, 4096, MAX_EXTENDED_USER_DATA] {
            let payload = alloc::vec![0xABu8; len];
            let mut out = Vec::new();
            Spdu::Connect(Connect::new(Some(&[0, 1]), Some(&[0, 1]), &payload)).write(&mut out).expect("encode");
            let expected = if len > MAX_USER_DATA { PI_EXTENDED_USER_DATA } else { PI_USER_DATA };
            assert!(out.contains(&expected), "{len} octets should use parameter {expected}");
            // Only one of the two may be present ✅ §8.3.1.21.
            let other = if expected == PI_USER_DATA { PI_EXTENDED_USER_DATA } else { PI_USER_DATA };
            let Ok(Spdu::Connect(back)) = Spdu::parse(&out) else { panic!("{len} did not round-trip") };
            assert_eq!(back.user_data, &payload[..], "{len} octets did not survive");
            assert_eq!(back.version, VERSION_2, "extended user data requires protocol version 2");
            let _ = other;
        }
        // Above the extended limit the standard wants a second SPDU exchange this profile
        // does not use, so it stays an error rather than a guess on the wire.
        let too_big = alloc::vec![0u8; MAX_EXTENDED_USER_DATA + 1];
        let mut out = Vec::new();
        assert!(Spdu::Connect(Connect::new(None, None, &too_big)).write(&mut out).is_err());
    }

    /// The ACCEPT SPDU's Table 14 has no Extended User Data parameter, so a large AARE is an
    /// error here rather than a parameter the peer would not recognise.
    #[test]
    fn an_accept_above_512_octets_is_refused_rather_than_extended() {
        let payload = alloc::vec![0u8; MAX_USER_DATA + 1];
        let mut out = Vec::new();
        assert!(Spdu::Accept(Connect::new(None, None, &payload)).write(&mut out).is_err());
        // …and 512 exactly still works.
        let ok = alloc::vec![0u8; MAX_USER_DATA];
        let mut out = Vec::new();
        Spdu::Accept(Connect::new(None, None, &ok)).write(&mut out).expect("512 octets is the limit, not one below it");
    }

    #[test]
    fn the_reference_connect_round_trips() {
        // Frame 11 of the reference MMS capture, with the 166-octet presentation PDU cut to
        // four so the test reads: the framing is what is under test, not the payload.
        let mut wire = alloc::vec![
            SI_CONNECT, 26, // LI
            5, 6, 19, 1, 0, 22, 1, 2, // Connect/Accept Item: options 0, version 2
            20, 2, 0, 2, // duplex
            51, 2, 0, 1, // calling SSEL
            52, 2, 0, 2, // called SSEL
            193, 4, // user data
        ];
        wire.extend_from_slice(&[0x31, 0x02, 0x80, 0x00]);
        let Spdu::Connect(c) = Spdu::parse(&wire).unwrap() else { panic!("not a CN") };
        assert_eq!((c.protocol_options, c.version, c.requirements), (0, VERSION_2, REQUIREMENT_DUPLEX));
        assert_eq!(c.calling_ssel, Some(&[0, 1][..]));
        assert_eq!(c.called_ssel, Some(&[0, 2][..]));
        assert_eq!(c.user_data, &[0x31, 0x02, 0x80, 0x00]);

        let mut out = Vec::new();
        Spdu::Connect(c).write(&mut out).unwrap();
        assert_eq!(out, wire, "re-encoding must reproduce the octets");
    }

    #[test]
    fn the_reference_accept_has_no_selectors() {
        let wire = [SI_ACCEPT, 16, 5, 6, 19, 1, 0, 22, 1, 2, 20, 2, 0, 2, 193, 2, 0xAA, 0xBB];
        let Spdu::Accept(c) = Spdu::parse(&wire).unwrap() else { panic!("not an AC") };
        assert_eq!((c.calling_ssel, c.called_ssel), (None, None));
        assert_eq!(c.user_data, &[0xAA, 0xBB]);
        let mut out = Vec::new();
        Spdu::Accept(c).write(&mut out).unwrap();
        assert_eq!(out, wire);
    }

    #[test]
    fn data_transfer_is_two_concatenated_spdus() {
        // `01 00 01 00` — GIVE TOKENS then DATA TRANSFER, both with no parameters. Every MMS
        // message in the reference capture starts with exactly these four octets.
        let wire = [1u8, 0, 1, 0, 0x61, 0x0F, 0xAA];
        assert_eq!(Spdu::parse(&wire).unwrap(), Spdu::DataTransfer(&[0x61, 0x0F, 0xAA]));
        let mut out = Vec::new();
        Spdu::DataTransfer(&[0x61, 0x0F, 0xAA]).write(&mut out).unwrap();
        assert_eq!(out, wire);
        // A GIVE TOKENS followed by something else is not data transfer, and saying so
        // beats decoding the next SPDU as a payload.
        assert!(Spdu::parse(&[1, 0, 9, 0]).is_err());
    }

    #[test]
    fn the_long_length_indicator_is_read_and_written() {
        // X.225 §8.2.5: 255 and above take three octets, `FF` then the length big-endian.
        let payload = alloc::vec![0x5Au8; 300];
        let mut wire = alloc::vec![SI_ABORT, 0xFF, 0x01, 0x30, PI_USER_DATA, 0xFF, 0x01, 0x2C];
        wire.extend_from_slice(&payload);
        assert_eq!(Spdu::parse(&wire).unwrap(), Spdu::Abort(&payload));
        let mut out = Vec::new();
        Spdu::Abort(&payload).write(&mut out).unwrap();
        assert_eq!(out, wire);
    }

    /// A CONNECT reaches 10 240 octets through `Extended User Data`; every other SPDU is
    /// held to the 512 the `User Data` parameter carries, because Extended User Data is
    /// defined for the CONNECT SPDU alone ✅ X.225 Table 11 vs Tables 14, 16, 17.
    #[test]
    fn user_data_beyond_what_the_parameter_holds_is_refused_not_truncated() {
        let big = alloc::vec![0u8; MAX_USER_DATA + 1];
        let mut out = Vec::new();
        Spdu::Connect(Connect::new(None, None, &big)).write(&mut out).expect("a CONNECT extends");
        out.clear();
        assert!(Spdu::Finish(&big).write(&mut out).is_err());
        assert!(Spdu::Disconnect(&big).write(&mut out).is_err());
        assert!(Spdu::Abort(&big).write(&mut out).is_err());
        assert!(Spdu::Refuse { reason: None, user_data: &big }.write(&mut out).is_err());

        let beyond = alloc::vec![0u8; MAX_EXTENDED_USER_DATA + 1];
        assert!(Spdu::Connect(Connect::new(None, None, &beyond)).write(&mut out).is_err());
    }

    #[test]
    fn truncation_is_an_error_not_a_panic() {
        let wire = [SI_CONNECT, 16, 5, 6, 19, 1, 0, 22, 1, 2, 20, 2, 0, 2, 193, 2, 0xAA, 0xBB];
        for cut in 0..wire.len() {
            let _ = Spdu::parse(&wire[..cut]);
        }
        assert!(Spdu::parse(&[]).is_err());
        assert!(Spdu::parse(&[SI_CONNECT, 40]).is_err());
        assert!(Spdu::parse(&[SI_CONNECT, 2, 193, 9]).is_err(), "a parameter longer than the SPDU");
    }

    #[test]
    fn abort_accept_and_unknown_spdus() {
        assert_eq!(Spdu::parse(&[SI_ABORT_ACCEPT, 0]).unwrap(), Spdu::AbortAccept);
        let mut out = Vec::new();
        Spdu::AbortAccept.write(&mut out).unwrap();
        assert_eq!(out, [SI_ABORT_ACCEPT, 0]);
        assert_eq!(Spdu::parse(&[45, 1, 7]).unwrap(), Spdu::Other { si: 45, body: &[7] });
    }
    #[test]
    fn a_parameter_group_nested_into_itself_is_not_recursed_into() {
        // Sixty-five thousand octets of `PGI 5` inside `PGI 5` is a legal TPKT packet and
        // about twenty thousand recursive calls. X.225 puts parameter *units* inside the
        // Connect/Accept Item, never further groups, so the decoder descends exactly once.
        let mut inner: Vec<u8> = Vec::new();
        while inner.len() < 60_000 {
            let len = inner.len();
            let mut next = Vec::with_capacity(len + 3);
            next.push(PGI_CONNECT_ACCEPT);
            if len < 0xFF {
                next.push(len as u8);
            } else {
                next.push(0xFF);
                next.extend_from_slice(&(len as u16).to_be_bytes());
            }
            next.extend_from_slice(&inner);
            inner = next;
        }
        let mut spdu = alloc::vec![SI_CONNECT, 0xFF];
        spdu.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        spdu.extend_from_slice(&inner);
        // It decodes (as a CONNECT with nothing usable in it) rather than recursing.
        assert!(matches!(Spdu::parse(&spdu), Ok(Spdu::Connect(_))));

        // One level still works, which is the level real traffic uses.
        let real = Spdu::Connect(Connect::new(Some(&[0x00, 0x01]), Some(&[0x00, 0x01]), &[0xAA, 0xBB]));
        let mut out = Vec::new();
        real.write(&mut out).unwrap();
        let Ok(Spdu::Connect(c)) = Spdu::parse(&out) else { panic!("not a CONNECT") };
        assert_eq!((c.calling_ssel, c.called_ssel, c.user_data), (Some(&[0x00, 0x01][..]), Some(&[0x00, 0x01][..]), &[0xAA, 0xBB][..]));
    }
}
