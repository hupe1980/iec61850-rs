//! `AlternateAccess` — naming one *part* of a named variable.
//!
//! A named variable is the whole of `MHAI1$MX$HA$phsAHar`. When that is an array of sixteen
//! harmonics, a client that wants the third one's magnitude does **not** get a name of its own
//! to read: IEC 61850 gives it the reference `MHAI1.HA.phsAHar(2).cVal.mag.f`, and ISO 9506
//! carries the part after the name as an `alternateAccess` beside the variable specification.
//!
//! ```text
//! AlternateAccess ::= SEQUENCE OF CHOICE {
//!   unnamed AlternateAccessSelection,
//!   named [5] IMPLICIT SEQUENCE { componentName [0], accesst AlternateAccessSelection } }
//!
//! AlternateAccessSelection ::= CHOICE {
//!   selectAlternateAccess [0] IMPLICIT SEQUENCE {
//!     accessSelection CHOICE { component [0], index [1], indexRange [2], allElements [3] },
//!     alternateAccess AlternateAccess },
//!   selectAccess CHOICE { component [1], index [2], indexRange [3], allElements [4] } }
//! ```
//! ✅ (`../specs/asn1-wireshark/mms.asn`).
//!
//! The recursion says one thing twice. A step with more after it is `selectAlternateAccess`
//! and tags its selection `[0]`–`[3]`; the last step is `selectAccess` and tags the same four
//! `[1]`–`[4]`. Nothing else differs, so this models it as a flat [`Path`] of [`Selector`]s
//! with the two tag sets in one place.
//!
//! **A selection this crate cannot read is refused, never approximated.** The ASN.1 allows a
//! `SEQUENCE OF` at every level and IEC 61850 never sends one; reading it as "the first of
//! them" would answer a different question with no error on it.

use alloc::vec::Vec;

use crate::ber::{Cursor, Encoder, Tag, Tlv, universal};
pub use crate::common::Selector;
use crate::common::{DecodeReason, Error, Result};

/// How deep a chain of selectors may go.
///
/// A reference like `phsAHar(2).cVal.mag.f` is four steps; the deepest thing IEC 61850 models
/// is not much more. The limit is what stops a crafted PDU from recursing the decoder.
pub const MAX_DEPTH: usize = 16;

/// The context tag a selector takes as the **last** step (`selectAccess`).
const fn last_tag(s: &Selector<'_>) -> u32 {
    match s {
        Selector::Component(_) => 1,
        Selector::Index(_) => 2,
        Selector::IndexRange { .. } => 3,
        Selector::AllElements => 4,
    }
}

/// The tag the same selector takes when more steps follow (`accessSelection`), which is the
/// same list shifted down by one — the whole of the difference between the two CHOICEs.
const fn inner_tag(s: &Selector<'_>) -> u32 {
    last_tag(s) - 1
}

/// The chain of selectors an `alternateAccess` names, outermost first.
///
/// `phsAHar(2).cVal.mag.f` is `[Index(2), Component("cVal"), Component("mag"), Component("f")]`.
/// An empty path is not an alternate access at all and is never encoded — the absence of the
/// field is what "the whole variable" means.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Path<'a> {
    steps: Vec<Selector<'a>>,
}

impl<'a> Path<'a> {
    /// A path from its steps.
    pub fn new(steps: Vec<Selector<'a>>) -> Path<'a> {
        Path { steps }
    }

    /// The steps, outermost first.
    pub fn steps(&self) -> &[Selector<'a>] {
        &self.steps
    }

    /// Whether this names nothing — in which case the whole variable is meant.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Decode an `alternateAccess [5]` element.
    pub fn parse(t: &Tlv<'a>) -> Result<Path<'a>> {
        let mut steps = Vec::new();
        Path::parse_into(t, &mut steps, 0)?;
        Ok(Path { steps })
    }

    /// Read one `AlternateAccess` — a `SEQUENCE OF` that this profile requires to hold exactly
    /// one selection, because a wider one would have to be answered by guessing.
    fn parse_into(t: &Tlv<'a>, out: &mut Vec<Selector<'a>>, depth: usize) -> Result<()> {
        if depth >= MAX_DEPTH {
            return Err(Error::LimitExceeded { limit: "alternate_access_depth", value: depth + 1 });
        }
        let mut c = t.children();
        let first = c.next_required()?;
        if !c.is_empty() {
            // Two selections at one level. Legal ASN.1, never IEC 61850, and unanswerable
            // without deciding which one the client meant.
            return Err(Error::decode(DecodeReason::BadValue, first.offset));
        }
        if first.tag == Tag::context_constructed(0) {
            // `selectAlternateAccess`: a selection, then the rest of the chain.
            let mut inner = first.children();
            let selection = inner.next_required()?;
            out.push(Path::selector(&selection, selection.tag.number.wrapping_add(1))?);
            let rest = inner.next_tag(Tag::universal(universal::SEQUENCE, true))?;
            inner.finish()?;
            return Path::parse_into(&rest, out, depth + 1);
        }
        // `selectAccess`: the last step.
        out.push(Path::selector(&first, first.tag.number)?);
        Ok(())
    }

    /// One selection, read against the **last-step** tag numbers.
    ///
    /// `as_last` is the tag the same selection would carry as a final step, so the two tag
    /// sets meet here instead of in two near-identical `match`es.
    fn selector(t: &Tlv<'a>, as_last: u32) -> Result<Selector<'a>> {
        if t.tag.class != crate::ber::Class::Context {
            return Err(Error::decode(DecodeReason::UnexpectedTag, t.offset));
        }
        Ok(match as_last {
            1 => Selector::Component(t.visible_string()?),
            2 => Selector::Index(t.unsigned_lenient_u32()?),
            3 => {
                let mut c = t.children();
                let low = c.next_tag(Tag::context(0))?.unsigned_lenient_u32()?;
                let count = c.next_tag(Tag::context(1))?.unsigned_lenient_u32()?;
                Selector::IndexRange { low, count }
            }
            4 => Selector::AllElements,
            _ => return Err(Error::decode(DecodeReason::UnexpectedTag, t.offset)),
        })
    }

    /// Encode this path as the `alternateAccess [5]` element of a variable list item.
    pub fn write(&self, e: &mut Encoder) -> Result<()> {
        if self.steps.is_empty() {
            return Ok(());
        }
        e.constructed(Tag::context_constructed(5), |e| Path::write_steps(&self.steps, e))?;
        Ok(())
    }

    fn write_steps(steps: &[Selector<'_>], e: &mut Encoder) -> Result<()> {
        let Some((first, rest)) = steps.split_first() else { return Ok(()) };
        if rest.is_empty() {
            return Path::write_selector(first, last_tag(first), e);
        }
        e.constructed(Tag::context_constructed(0), |e| {
            Path::write_selector(first, inner_tag(first), e)?;
            e.constructed(Tag::universal(universal::SEQUENCE, true), |e| Path::write_steps(rest, e))?;
            Ok(())
        })?;
        Ok(())
    }

    fn write_selector(s: &Selector<'_>, tag: u32, e: &mut Encoder) -> Result<()> {
        match s {
            Selector::Component(name) => {
                e.visible_string(Tag::context(tag), name)?;
            }
            Selector::Index(i) => {
                e.unsigned(Tag::context(tag), u64::from(*i))?;
            }
            Selector::IndexRange { low, count } => {
                e.constructed(Tag::context_constructed(tag), |e| {
                    e.unsigned(Tag::context(0), u64::from(*low))?;
                    e.unsigned(Tag::context(1), u64::from(*count))?;
                    Ok(())
                })?;
            }
            Selector::AllElements => {
                e.primitive(Tag::context(tag), &[])?;
            }
        }
        Ok(())
    }
}

impl core::fmt::Display for Path<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for s in &self.steps {
            write!(f, "{s}")?;
        }
        Ok(())
    }
}

/// The `alternateAccess [5]` of a variable list item, if it has one.
pub(crate) fn next_alternate<'a>(c: &mut Cursor<'a>) -> Result<Option<Path<'a>>> {
    match c.next_if_tag(Tag::context_constructed(5))? {
        Some(t) => Path::parse(&t).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    /// The octets libiec61850 puts on the wire for the four references its own array example
    /// reads 🌐 — one per depth, which is what makes the two tag sets visible.
    ///
    /// Nothing in this repository could have produced them: the encoder and the decoder were
    /// both absent, and the *server* answered a request carrying one of these by ignoring it
    /// and returning the whole array — a different answer to a different question, with no
    /// error on it.
    #[test]
    fn the_octets_a_second_stack_writes_for_an_array_element() {
        // `phsAHar(2)` — one step, so the `selectAccess` tag set: index is [2].
        let one: &[u8] = &[0xa5, 0x03, 0x82, 0x01, 0x02];
        // `phsAHar(2).cVal` — two steps: index as [1] inside `selectAlternateAccess`, then
        // the component as [1] of `selectAccess`.
        let two: &[u8] = &[0xa5, 0x0d, 0xa0, 0x0b, 0x81, 0x01, 0x02, 0x30, 0x06, 0x81, 0x04, b'c', b'V', b'a', b'l'];
        // `phsAHar(2).cVal.mag`
        let three: &[u8] =
            &[0xa5, 0x16, 0xa0, 0x14, 0x81, 0x01, 0x02, 0x30, 0x0f, 0xa0, 0x0d, 0x80, 0x04, b'c', b'V', b'a', b'l', 0x30, 0x05, 0x81, 0x03, b'm', b'a', b'g'];
        // `phsAHar(2).cVal.mag.f`
        let four: &[u8] = &[
            0xa5, 0x1d, 0xa0, 0x1b, 0x81, 0x01, 0x02, 0x30, 0x16, 0xa0, 0x14, 0x80, 0x04, b'c', b'V', b'a', b'l', 0x30, 0x0c, 0xa0, 0x0a, 0x80, 0x03, b'm',
            b'a', b'g', 0x30, 0x03, 0x81, 0x01, b'f',
        ];

        let cases: [(&[u8], Vec<Selector<'_>>, &str); 4] = [
            (one, vec![Selector::Index(2)], "(2)"),
            (two, vec![Selector::Index(2), Selector::Component("cVal")], "(2).cVal"),
            (three, vec![Selector::Index(2), Selector::Component("cVal"), Selector::Component("mag")], "(2).cVal.mag"),
            (four, vec![Selector::Index(2), Selector::Component("cVal"), Selector::Component("mag"), Selector::Component("f")], "(2).cVal.mag.f"),
        ];
        for (wire, steps, shown) in cases {
            let tlv = Cursor::new(wire).next_required().unwrap();
            let path = Path::parse(&tlv).unwrap_or_else(|e| panic!("{shown}: {e}"));
            assert_eq!(path.steps(), &steps[..], "{shown}");
            assert_eq!(path.to_string(), shown);
            // …and we write what it writes, byte for byte.
            let mut e = Encoder::new();
            path.write(&mut e).unwrap();
            assert_eq!(e.into_vec(), wire, "{shown}");
        }
    }

    #[test]
    fn a_range_and_all_elements_round_trip_at_both_depths() {
        for steps in [
            vec![Selector::IndexRange { low: 1, count: 4 }],
            vec![Selector::AllElements],
            vec![Selector::Component("cVal"), Selector::AllElements],
            vec![Selector::IndexRange { low: 0, count: 16 }, Selector::Component("q")],
        ] {
            let path = Path::new(steps.clone());
            let mut e = Encoder::new();
            path.write(&mut e).unwrap();
            let bytes = e.into_vec();
            let tlv = Cursor::new(&bytes).next_required().unwrap();
            assert_eq!(Path::parse(&tlv).unwrap().steps(), &steps[..]);
        }
        // Nothing selected is not an empty element — it is no element at all.
        let mut e = Encoder::new();
        Path::default().write(&mut e).unwrap();
        assert!(e.into_vec().is_empty());
    }

    /// A selection this decoder cannot read is refused rather than narrowed to its first
    /// alternative: answering a different question with no error is worse than an error.
    #[test]
    fn a_selection_that_picks_two_things_at_once_is_refused() {
        // `a5 06 81 01 61 81 01 62` — two components at one level.
        let wire: &[u8] = &[0xa5, 0x06, 0x81, 0x01, b'a', 0x81, 0x01, b'b'];
        let tlv = Cursor::new(wire).next_required().unwrap();
        assert!(Path::parse(&tlv).is_err());
        // An empty selection names nothing and is not "the whole variable" either.
        assert!(Path::parse(&Cursor::new(&[0xa5, 0x00]).next_required().unwrap()).is_err());
        // A tag outside the two sets.
        assert!(Path::parse(&Cursor::new(&[0xa5, 0x03, 0x87, 0x01, 0x02]).next_required().unwrap()).is_err());
    }

    /// A chain deeper than the limit ends rather than recursing the decoder.
    ///
    /// Written through this crate's own encoder on purpose: a hand-built one would be testing
    /// whether the octets were typed correctly, and what is under test is the limit.
    #[test]
    fn a_chain_deeper_than_the_limit_is_refused() {
        let deep = Path::new(vec![Selector::Component("c"); MAX_DEPTH + 4]);
        let mut e = Encoder::new();
        deep.write(&mut e).unwrap();
        let bytes = e.into_vec();
        let tlv = Cursor::new(&bytes).next_required().unwrap();
        assert!(matches!(Path::parse(&tlv), Err(Error::LimitExceeded { limit: "alternate_access_depth", .. })));

        // …and one exactly at the limit still decodes, so the check is a limit and not an
        // off-by-one that shortens every real reference.
        let ok = Path::new(vec![Selector::Component("c"); MAX_DEPTH]);
        let mut e = Encoder::new();
        ok.write(&mut e).unwrap();
        let bytes = e.into_vec();
        let tlv = Cursor::new(&bytes).next_required().unwrap();
        assert_eq!(Path::parse(&tlv).unwrap().steps().len(), MAX_DEPTH);
    }
}
