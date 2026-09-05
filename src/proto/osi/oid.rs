//! Object identifiers, as the OSI layers exchange them.
//!
//! An OID is kept as its **encoded contents octets** rather than as a list of arcs: the
//! layers below MMS use a handful of fixed identifiers and compare them for equality, and
//! keeping the encoding means a decoded PDU re-encodes to the octets it arrived as, arc for
//! arc, without a round trip through an arc representation that could normalise something.

use alloc::vec::Vec;
use core::fmt;

/// An object identifier's contents octets (what follows the tag and length).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Oid<'a>(pub &'a [u8]);

impl<'a> Oid<'a> {
    /// `2.2.1.0.1` — the ACSE abstract syntax.
    pub const ACSE_ABSTRACT_SYNTAX: Oid<'static> = Oid(&[0x52, 0x01, 0x00, 0x01]);
    /// `1.0.9506.2.1` — the MMS abstract syntax (`mms-abstract-syntax-version1`).
    pub const MMS_ABSTRACT_SYNTAX: Oid<'static> = Oid(&[0x28, 0xCA, 0x22, 0x02, 0x01]);
    /// `1.0.9506.2.3` — the MMS application context (`mms-annex-version1`), which is what
    /// IEC 61850-8-1 names in the AARQ.
    pub const MMS_APPLICATION_CONTEXT: Oid<'static> = Oid(&[0x28, 0xCA, 0x22, 0x02, 0x03]);
    /// `1.0.9506.1.1` — the ISO 9506 application context, which the ICCP capture uses and
    /// which some IEDs still send.
    pub const MMS_APPLICATION_CONTEXT_9506: Oid<'static> = Oid(&[0x28, 0xCA, 0x22, 0x01, 0x01]);
    /// `2.1.1` — BER, the only transfer syntax this profile uses.
    pub const BER: Oid<'static> = Oid(&[0x51, 0x01]);
    /// `2.2.3.1` — the ACSE password authentication mechanism
    /// (`{joint-iso-itu-t association-control(2) authentication-mechanism(3) password-1(1)}`)
    /// that IEC 61850-8-1 names for the ACSE password.
    pub const PASSWORD_MECHANISM: Oid<'static> = Oid(&[0x52, 0x03, 0x01]);

    /// The arcs, decoded. A malformed identifier ends the walk rather than looping.
    pub fn arcs(&self) -> Arcs<'a> {
        Arcs { rest: self.0, pending: None, first: true }
    }
}

/// The arcs of an [`Oid`], in order.
#[derive(Clone, Debug)]
pub struct Arcs<'a> {
    rest: &'a [u8],
    /// The second half of the first subidentifier, which encodes two arcs in one.
    pending: Option<u32>,
    first: bool,
}

impl Iterator for Arcs<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if let Some(second) = self.pending.take() {
            return Some(second);
        }
        let mut value: u32 = 0;
        loop {
            let (&byte, tail) = self.rest.split_first()?;
            self.rest = tail;
            value = value.checked_mul(128)?.checked_add(u32::from(byte & 0x7F))?;
            if byte & 0x80 == 0 {
                break;
            }
        }
        if core::mem::take(&mut self.first) {
            // X.690 §8.19.4: the first subidentifier is 40 × arc1 + arc2, and arc1 is
            // capped at 2 — so anything from 80 up belongs to the third root arc.
            let (a, b) = if value >= 80 { (2, value - 80) } else { (value / 40, value % 40) };
            self.pending = Some(b);
            return Some(a);
        }
        Some(value)
    }
}

/// Encode `arcs` as the contents octets of an OBJECT IDENTIFIER.
///
/// The inverse of [`Oid::arcs`], and what turns an SCL `OSI-AP-Title` — which the file writes
/// as `1,3,9999,23` — into the identifier an ACSE AARQ carries. Fewer than two arcs cannot be
/// encoded, because the first octet holds two of them.
pub fn encode(arcs: &[u32]) -> Option<Vec<u8>> {
    let (&first, &second) = (arcs.first()?, arcs.get(1)?);
    if first > 2 || (first < 2 && second >= 40) {
        return None;
    }
    // `40 × arc1 + arc2` overflows for a large second arc under the third root arc, and the
    // arcs come out of an SCL file's `OSI-AP-Title`. An identifier that cannot be encoded is
    // `None`, never a wrapped one and never a panic.
    let combined = first.checked_mul(40)?.checked_add(second)?;
    let mut out = Vec::with_capacity(arcs.len() + 2);
    // Base 128, most significant group first, continuation bit on all but the last.
    let push = |value: u32, out: &mut Vec<u8>| {
        let mut shift = 28u32;
        let mut started = false;
        while shift > 0 {
            let group = ((value >> shift) & 0x7F) as u8;
            if group != 0 || started {
                out.push(group | 0x80);
                started = true;
            }
            shift -= 7;
        }
        out.push((value & 0x7F) as u8);
    };
    push(combined, &mut out);
    for &arc in arcs.get(2..).unwrap_or(&[]) {
        push(arc, &mut out);
    }
    Some(out)
}

impl fmt::Display for Oid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arc) in self.arcs().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn the_identifiers_this_profile_uses_decode_to_their_names() {
        assert_eq!(Oid::ACSE_ABSTRACT_SYNTAX.to_string(), "2.2.1.0.1");
        assert_eq!(Oid::MMS_ABSTRACT_SYNTAX.to_string(), "1.0.9506.2.1");
        assert_eq!(Oid::MMS_APPLICATION_CONTEXT.to_string(), "1.0.9506.2.3");
        assert_eq!(Oid::MMS_APPLICATION_CONTEXT_9506.to_string(), "1.0.9506.1.1");
        assert_eq!(Oid::BER.to_string(), "2.1.1");
        // The encoding `52 03 01` is what libiec61850 writes and what the notes recorded;
        // decoding it says the identifier is 2.2.3.1 — association-control(2),
        // authentication-mechanism(3), password-1(1) — and not the "2.3.1" the notes named
        // it. The octets were right and the dotted form was not.
        assert_eq!(Oid::PASSWORD_MECHANISM.to_string(), "2.2.3.1");
        // `1.1.2` and `1.1.1`, the AP-titles in the reference capture.
        assert_eq!(Oid(&[0x29, 0x02]).to_string(), "1.1.2");
        assert_eq!(Oid(&[0x29, 0x01]).to_string(), "1.1.1");
    }

    #[test]
    fn arcs_encode_back_to_the_octets_they_came_from() {
        for oid in [Oid::ACSE_ABSTRACT_SYNTAX, Oid::MMS_ABSTRACT_SYNTAX, Oid::MMS_APPLICATION_CONTEXT, Oid::BER, Oid::PASSWORD_MECHANISM] {
            let arcs: Vec<u32> = oid.arcs().collect();
            assert_eq!(encode(&arcs).as_deref(), Some(oid.0), "{oid}");
        }
        // What an SCL `OSI-AP-Title` looks like: `1,3,9999,23`.
        let title = encode(&[1, 3, 9999, 23]).unwrap();
        assert_eq!(Oid(&title).to_string(), "1.3.9999.23");
        assert_eq!(encode(&[1]), None, "the first octet holds two arcs");
        assert_eq!(encode(&[3, 1]), None, "there is no root arc 3");
        // `40 × arc1 + arc2` overflows for a large second arc under root 2, and the arcs come
        // out of an SCL file. Refusing beats wrapping, and both beat a panic.
        assert_eq!(encode(&[2, u32::MAX]), None);
        assert_eq!(encode(&[2, u32::MAX - 79]), None);
        assert_eq!(Oid(&encode(&[2, u32::MAX - 80]).unwrap()).arcs().collect::<Vec<_>>(), [2, u32::MAX - 80]);
    }

    #[test]
    fn a_malformed_identifier_ends_rather_than_looping() {
        assert_eq!(Oid(&[]).arcs().collect::<Vec<_>>(), Vec::<u32>::new());
        // A continuation bit with nothing after it: the iterator ends.
        assert_eq!(Oid(&[0x80]).arcs().count(), 0);
        assert_eq!(Oid(&[0xFF; 8]).arcs().count(), 0, "an arc that overflows u32 ends the walk");
    }
}
