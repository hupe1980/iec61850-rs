//! COTP class 0 (ISO 8073 / ITU-T X.224) as IEC 61850-8-1 uses it: connect, accept, data.
//!
//! Class 0 is the simplest transport class there is — no flow control, no error recovery, no
//! multiplexing, because TCP underneath already does all of it. What it still provides, and
//! what MMS depends on, is a **TSDU**: a data unit that may be longer than one TPDU and is
//! reassembled from a run of DT TPDUs ending with the end-of-transmission bit. A 4 KiB
//! `GetNameList` response over a 1024-octet negotiated size arrives as four TPDUs and one
//! TSDU, and every layer above sees only the TSDU.
//!
//! A TPDU is length-prefixed rather than tagged: the first octet is the length of everything
//! after it up to (but not including) the user data.

use alloc::vec::Vec;

use crate::common::{DecodeReason, Error, Result};

/// Connection request.
pub const CR: u8 = 0xE0;
/// Connection confirm.
pub const CC: u8 = 0xD0;
/// Disconnect request.
pub const DR: u8 = 0x80;
/// Disconnect confirm.
pub const DC: u8 = 0xC0;
/// Data.
pub const DT: u8 = 0xF0;
/// Error.
pub const ER: u8 = 0x70;

/// The end-of-transmission bit of a DT TPDU's `TPDU-NR and EOT` octet.
pub const EOT: u8 = 0x80;

/// Parameter code: TPDU size, as a power of two.
pub const PARAM_TPDU_SIZE: u8 = 0xC0;
/// Parameter code: calling transport selector.
pub const PARAM_SRC_TSAP: u8 = 0xC1;
/// Parameter code: called transport selector.
pub const PARAM_DST_TSAP: u8 = 0xC2;

/// The TPDU sizes class 0 may negotiate, as the exponent the parameter carries.
///
/// 7 = 128 octets … 13 = 8192. Class 0's maximum is 2048 in the base standard, but every
/// deployed IEC 61850 stack negotiates 8192 (libiec61850's default), so the ceiling here is
/// what the field can express rather than what the class nominally allows.
pub const TPDU_SIZE_MIN_EXP: u8 = 7;
/// The largest TPDU size exponent (8192 octets).
pub const TPDU_SIZE_MAX_EXP: u8 = 13;

/// Octets in a TPDU of the size `exp` describes.
pub const fn tpdu_size(exp: u8) -> usize {
    let e = if exp < TPDU_SIZE_MIN_EXP {
        TPDU_SIZE_MIN_EXP
    } else if exp > TPDU_SIZE_MAX_EXP {
        TPDU_SIZE_MAX_EXP
    } else {
        exp
    };
    1usize << e
}

/// A transport selector (TSAP), as SCL's `ConnectedAP/Address` writes it.
///
/// Up to four octets in practice; IEC 61850-8-1 uses two, and 9 out of 10 files write
/// `0001`/`0002` or `0000`. Kept as bytes because it is an opaque identifier.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Tsel(pub Vec<u8>);

impl Tsel {
    /// A selector from its octets.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Tsel {
        Tsel(bytes.into())
    }

    /// True when the selector carries no octets, which is how a peer says "any".
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A decoded COTP TPDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tpdu<'a> {
    /// Connection request.
    ConnectionRequest(Connect),
    /// Connection confirm.
    ConnectionConfirm(Connect),
    /// Disconnect request, with the reason octet.
    DisconnectRequest {
        /// Destination reference.
        dst_ref: u16,
        /// Source reference.
        src_ref: u16,
        /// Reason.
        reason: u8,
    },
    /// Data, with the end-of-transmission flag and the user data.
    Data {
        /// True when this TPDU ends the TSDU.
        eot: bool,
        /// The user data.
        payload: &'a [u8],
    },
    /// Anything else, kept as its code and body so a tool can report it.
    Other {
        /// The TPDU code.
        code: u8,
        /// Everything after the code, up to the end of the TPDU.
        body: &'a [u8],
    },
}

/// The parameters of a CR or CC TPDU.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Connect {
    /// Destination reference (zero in a CR).
    pub dst_ref: u16,
    /// Source reference.
    pub src_ref: u16,
    /// Class and options octet; class 0 with no options is 0.
    pub class_options: u8,
    /// Negotiated TPDU size as its exponent, if the parameter is present.
    pub tpdu_size_exp: Option<u8>,
    /// Calling transport selector.
    pub src_tsel: Option<Tsel>,
    /// Called transport selector.
    pub dst_tsel: Option<Tsel>,
}

impl Connect {
    /// A class-0 connection request with the given selectors and size.
    pub fn request(src_ref: u16, src_tsel: Tsel, dst_tsel: Tsel, tpdu_size_exp: u8) -> Connect {
        Connect {
            dst_ref: 0,
            src_ref,
            class_options: 0,
            tpdu_size_exp: Some(tpdu_size_exp.clamp(TPDU_SIZE_MIN_EXP, TPDU_SIZE_MAX_EXP)),
            src_tsel: Some(src_tsel),
            dst_tsel: Some(dst_tsel),
        }
    }

    /// Octets of user data one DT TPDU may carry, given what was negotiated.
    ///
    /// The TPDU size counts the whole TPDU, and a class-0 DT header is three octets.
    pub fn max_data(&self) -> usize {
        tpdu_size(self.tpdu_size_exp.unwrap_or(TPDU_SIZE_MIN_EXP)).saturating_sub(3)
    }

    fn parse(body: &[u8]) -> Result<Connect> {
        let (Some(&a), Some(&b), Some(&c), Some(&d), Some(&class)) = (body.first(), body.get(1), body.get(2), body.get(3), body.get(4)) else {
            return Err(Error::decode(DecodeReason::Truncated, 0));
        };
        let mut out = Connect { dst_ref: u16::from_be_bytes([a, b]), src_ref: u16::from_be_bytes([c, d]), class_options: class, ..Connect::default() };
        let mut rest = body.get(5..).unwrap_or(&[]);
        while let Some((&code, tail)) = rest.split_first() {
            let (&len, tail) = tail.split_first().ok_or(Error::decode(DecodeReason::Truncated, 0))?;
            let value = tail.get(..usize::from(len)).ok_or(Error::decode(DecodeReason::Truncated, 0))?;
            match code {
                PARAM_TPDU_SIZE => out.tpdu_size_exp = value.first().copied(),
                PARAM_SRC_TSAP => out.src_tsel = Some(Tsel::new(value)),
                PARAM_DST_TSAP => out.dst_tsel = Some(Tsel::new(value)),
                // Unknown parameters are skipped, not refused: X.224 allows a peer to offer
                // options we do not implement, and class 0 ignores what it did not ask for.
                _ => {}
            }
            rest = tail.get(usize::from(len)..).unwrap_or(&[]);
        }
        Ok(out)
    }

    fn write(&self, code: u8, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.push(0); // length indicator, filled in below
        out.push(code);
        out.extend_from_slice(&self.dst_ref.to_be_bytes());
        out.extend_from_slice(&self.src_ref.to_be_bytes());
        out.push(self.class_options);
        if let Some(exp) = self.tpdu_size_exp {
            out.extend_from_slice(&[PARAM_TPDU_SIZE, 1, exp]);
        }
        for (param, tsel) in [(PARAM_SRC_TSAP, &self.src_tsel), (PARAM_DST_TSAP, &self.dst_tsel)] {
            if let Some(t) = tsel {
                let len = u8::try_from(t.0.len()).map_err(|_| Error::Encode("transport selector too long"))?;
                out.push(param);
                out.push(len);
                out.extend_from_slice(&t.0);
            }
        }
        let li = out.len() - start - 1;
        let li = u8::try_from(li).map_err(|_| Error::Encode("COTP header too long"))?;
        match out.get_mut(start) {
            Some(slot) => *slot = li,
            None => return Err(Error::Encode("COTP header")),
        }
        Ok(())
    }
}

impl<'a> Tpdu<'a> {
    /// Decode one TPDU — the payload of a TPKT packet.
    pub fn parse(tpdu: &'a [u8]) -> Result<Tpdu<'a>> {
        let (&li, rest) = tpdu.split_first().ok_or(Error::decode(DecodeReason::Truncated, 0))?;
        let header = rest.get(..usize::from(li)).ok_or(Error::decode(DecodeReason::Truncated, 1))?;
        let payload = rest.get(usize::from(li)..).unwrap_or(&[]);
        let (&code, body) = header.split_first().ok_or(Error::decode(DecodeReason::Truncated, 1))?;
        Ok(match code {
            CR => Tpdu::ConnectionRequest(Connect::parse(body)?),
            CC => Tpdu::ConnectionConfirm(Connect::parse(body)?),
            DR => {
                let (Some(&a), Some(&b), Some(&c), Some(&d), Some(&reason)) = (body.first(), body.get(1), body.get(2), body.get(3), body.get(4)) else {
                    return Err(Error::decode(DecodeReason::Truncated, 1));
                };
                Tpdu::DisconnectRequest { dst_ref: u16::from_be_bytes([a, b]), src_ref: u16::from_be_bytes([c, d]), reason }
            }
            DT => {
                let &nr_eot = body.first().ok_or(Error::decode(DecodeReason::Truncated, 1))?;
                Tpdu::Data { eot: nr_eot & EOT != 0, payload }
            }
            _ => Tpdu::Other { code, body },
        })
    }

    /// Encode into `out`.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Tpdu::ConnectionRequest(c) => c.write(CR, out),
            Tpdu::ConnectionConfirm(c) => c.write(CC, out),
            Tpdu::DisconnectRequest { dst_ref, src_ref, reason } => {
                out.push(6);
                out.push(DR);
                out.extend_from_slice(&dst_ref.to_be_bytes());
                out.extend_from_slice(&src_ref.to_be_bytes());
                out.push(*reason);
                Ok(())
            }
            Tpdu::Data { eot, payload } => {
                out.extend_from_slice(&[2, DT, if *eot { EOT } else { 0 }]);
                out.extend_from_slice(payload);
                Ok(())
            }
            Tpdu::Other { code, body } => {
                let li = u8::try_from(body.len() + 1).map_err(|_| Error::Encode("COTP header too long"))?;
                out.push(li);
                out.push(*code);
                out.extend_from_slice(body);
                Ok(())
            }
        }
    }
}

/// Reassembles DT TPDUs into TSDUs.
///
/// A TSDU that never ends is a memory leak with a protocol in front of it, so the limit is a
/// parameter and exceeding it is an error rather than an allocation.
#[derive(Debug)]
pub struct Reassembler {
    parts: Vec<u8>,
    limit: usize,
}

impl Reassembler {
    /// A reassembler that refuses a TSDU longer than `limit` octets.
    pub fn new(limit: usize) -> Reassembler {
        Reassembler { parts: Vec::new(), limit }
    }

    /// Octets held for a TSDU that is still incomplete.
    pub fn buffered(&self) -> usize {
        self.parts.len()
    }

    /// Drop a partial TSDU — after a transport error, or when an association restarts.
    pub fn reset(&mut self) {
        self.parts.clear();
    }

    /// Feed one DT TPDU. Returns the whole TSDU once the end-of-transmission bit arrives.
    ///
    /// The common case — a TSDU that fits one TPDU — hands back the caller's own slice and
    /// copies nothing; only a segmented TSDU is assembled into the buffer.
    pub fn push<'a>(&'a mut self, eot: bool, payload: &'a [u8]) -> Result<Option<&'a [u8]>> {
        if self.parts.is_empty() && eot {
            return Ok(Some(payload));
        }
        if self.parts.len().saturating_add(payload.len()) > self.limit {
            return Err(Error::LimitExceeded { limit: "max_tsdu", value: self.parts.len() + payload.len() });
        }
        self.parts.extend_from_slice(payload);
        if eot { Ok(Some(&self.parts)) } else { Ok(None) }
    }

    /// Forget the TSDU the last [`Reassembler::push`] returned.
    ///
    /// Kept separate so the caller can decode the TSDU while it is still borrowed and clear
    /// it afterwards; forgetting to call it would make the next TSDU start with this one.
    pub fn take(&mut self) {
        self.parts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_connection_request_round_trips() {
        // Frame 5 of the reference MMS capture, byte for byte.
        let wire = [0x11u8, 0xE0, 0x00, 0x00, 0xB0, 0x01, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x00, 0x01, 0xC2, 0x02, 0x00, 0x02];
        let Tpdu::ConnectionRequest(cr) = Tpdu::parse(&wire).unwrap() else { panic!("not a CR") };
        assert_eq!((cr.dst_ref, cr.src_ref, cr.class_options), (0, 0xB001, 0));
        assert_eq!(cr.tpdu_size_exp, Some(10));
        assert_eq!(cr.max_data(), 1021);
        assert_eq!(cr.src_tsel, Some(Tsel::new([0, 1])));
        assert_eq!(cr.dst_tsel, Some(Tsel::new([0, 2])));

        let mut out = Vec::new();
        Tpdu::ConnectionRequest(cr).write(&mut out).unwrap();
        assert_eq!(out, wire, "re-encoding must reproduce the captured octets");
    }

    #[test]
    fn the_reference_connection_confirm_round_trips() {
        // Frame 8: the server accepts, and offers the same size.
        let wire = [0x09u8, 0xD0, 0xB0, 0x01, 0x18, 0x02, 0x00, 0xC0, 0x01, 0x0A];
        let Tpdu::ConnectionConfirm(cc) = Tpdu::parse(&wire).unwrap() else { panic!("not a CC") };
        assert_eq!((cc.dst_ref, cc.src_ref, cc.tpdu_size_exp), (0xB001, 0x1802, Some(10)));
        assert_eq!(cc.src_tsel, None);
        let mut out = Vec::new();
        Tpdu::ConnectionConfirm(cc).write(&mut out).unwrap();
        assert_eq!(out, wire);
    }

    #[test]
    fn data_tpdus_carry_the_end_of_transmission_bit() {
        let wire = [0x02u8, 0xF0, 0x80, 0xAA, 0xBB];
        assert_eq!(Tpdu::parse(&wire).unwrap(), Tpdu::Data { eot: true, payload: &[0xAA, 0xBB] });
        let mut out = Vec::new();
        Tpdu::Data { eot: true, payload: &[0xAA, 0xBB] }.write(&mut out).unwrap();
        assert_eq!(out, wire);
        assert_eq!(Tpdu::parse(&[0x02, 0xF0, 0x00, 0xAA]).unwrap(), Tpdu::Data { eot: false, payload: &[0xAA] });
    }

    #[test]
    fn a_segmented_tsdu_is_reassembled_and_a_whole_one_is_not_copied() {
        let mut r = Reassembler::new(64);
        assert_eq!(r.push(true, &[1, 2, 3]).unwrap(), Some(&[1, 2, 3][..]));
        assert_eq!(r.buffered(), 0, "a TSDU that fits one TPDU is handed straight back");
        r.take();

        assert_eq!(r.push(false, &[1, 2]).unwrap(), None);
        assert_eq!(r.push(false, &[3]).unwrap(), None);
        assert_eq!(r.push(true, &[4, 5]).unwrap(), Some(&[1, 2, 3, 4, 5][..]));
        r.take();
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn a_tsdu_that_never_ends_is_refused_rather_than_buffered() {
        let mut r = Reassembler::new(8);
        assert!(r.push(false, &[0; 8]).is_ok());
        assert!(matches!(r.push(false, &[0; 8]), Err(Error::LimitExceeded { .. })));
        r.reset();
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn truncation_and_unknown_codes_are_errors_or_data_never_panics() {
        for cut in 0..6 {
            let _ = Tpdu::parse(&[0x11, 0xE0, 0, 0, 0xB0, 0x01][..cut]);
        }
        assert!(Tpdu::parse(&[]).is_err());
        assert!(Tpdu::parse(&[0x05, 0xE0, 0x00]).is_err(), "the length indicator must fit");
        assert!(matches!(Tpdu::parse(&[0x02, 0x70, 0x01]).unwrap(), Tpdu::Other { code: ER, .. }));
    }

    #[test]
    fn a_disconnect_request_round_trips() {
        let wire = [0x06u8, 0x80, 0x18, 0x02, 0xB0, 0x01, 0x00];
        let dr = Tpdu::parse(&wire).unwrap();
        assert_eq!(dr, Tpdu::DisconnectRequest { dst_ref: 0x1802, src_ref: 0xB001, reason: 0 });
        let mut out = Vec::new();
        dr.write(&mut out).unwrap();
        assert_eq!(out, wire);
    }
}
