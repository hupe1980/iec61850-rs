//! `TypeSpecification` — what `GetVariableAccessAttributes` answers with.
//!
//! This is how a client learns the *shape* of a variable before it writes one: that
//! `CSWI1$CO$Pos$Oper` is a structure of seven components whose first is a two-bit bit string
//! and whose fifth is a `utc-time`, or that `MMXU1$MX$TotW$mag$f` is a floating point. Every
//! prior stack makes a caller know that in advance; reading it costs one round trip and turns
//! "the write was refused with type-inconsistent" into something a tool can explain.
//!
//! ```text
//! TypeSpecification ::= CHOICE {
//!   typeName [0] ObjectName, array [1] { packed, numberOfElements, elementType },
//!   structure [2] { packed, components [1] SEQUENCE OF { componentName [0]?, componentType [1] } },
//!   boolean [3] NULL, bit-string [4] Integer32, integer [5] Unsigned8, unsigned [6] Unsigned8,
//!   octet-string [9] Integer32, visible-string [10] Integer32, generalized-time [11] NULL,
//!   binary-time [12] BOOLEAN, bcd [13] Unsigned8, objId [15] NULL }
//! ```
//!
//! plus `floating-point [7] { format-width [0], exponent-width [1] }`, which ISO 9506-2 has
//! and Wireshark's stripped module drops, and `mMSString [16]` / `utc-time [17]`, which
//! IEC 61850-8-1 adds alongside the `Data` choices of the same numbers 🌐. Everything else is
//! ISO 9506-2 as `../specs/asn1-wireshark/mms.asn` states it ✅. `objId [15]` is not modelled
//! and arrives as [`TypeSpec::Other`]; nothing in IEC 61850 is one.
//!
//! A negative `bit-string`, `octet-string` or `visible-string` length means "at most that
//! many"; the sign is kept rather than normalised, because it is the difference between a
//! fixed-width field and a bounded one.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ber::{Cursor, Encoder, Tag, Tlv};
use crate::common::{DecodeReason, Error, Limits, Result};
use crate::proto::data::tag;

/// One component of a structure type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    /// `componentName`, when the server named it — IEC 61850 servers always do, because the
    /// name is the data attribute (`ctlVal`, `origin`, `ctlNum`, …).
    pub name: Option<String>,
    /// The component's own type.
    pub type_spec: TypeSpec,
}

/// The type of an MMS variable.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypeSpec {
    /// `typeName [0]` — a named type defined elsewhere in the VMD.
    Named {
        /// The domain, when the name is domain-specific.
        domain: Option<String>,
        /// The name.
        item: String,
    },
    /// `array [1]`.
    Array {
        /// `packed`.
        packed: bool,
        /// How many elements.
        elements: u32,
        /// What each element is.
        element_type: Box<TypeSpec>,
    },
    /// `structure [2]` — a data object or a functionally-constrained data attribute.
    Structure {
        /// `packed`.
        packed: bool,
        /// The components, in the order the server returns them, which is the order a
        /// `Read` returns their values in.
        components: Vec<Component>,
    },
    /// `boolean [3]`.
    Boolean,
    /// `bit-string [4]`, with its length in bits (negative = "at most").
    BitString(i32),
    /// `integer [5]`, with its width in bits.
    Integer(u8),
    /// `unsigned [6]`, with its width in bits.
    Unsigned(u8),
    /// `floating-point [7]`: total width and exponent width, in bits.
    FloatingPoint {
        /// Total format width in bits (32 or 64).
        format_width: u8,
        /// Exponent width in bits (8 or 11).
        exponent_width: u8,
    },
    /// `octet-string [9]`, with its length (negative = "at most").
    OctetString(i32),
    /// `visible-string [10]`, with its length (negative = "at most").
    VisibleString(i32),
    /// `generalized-time [11]`.
    GeneralizedTime,
    /// `binary-time [12]`: true when the six-octet form with a date.
    BinaryTime(bool),
    /// `bcd [13]`, with its number of digits.
    Bcd(u8),
    /// `mMSString [16]`, with its length (negative = "at most").
    MmsString(i32),
    /// `utc-time [17]` — the IEC 61850 `Timestamp`.
    UtcTime,
    /// A choice this codec does not model, kept as its tag number so a tool can name it.
    Other(u32),
}

/// `floating-point [7] IMPLICIT SEQUENCE { format-width [0] Unsigned8, exponent-width [1] Unsigned8 }`.
const FLOATING_POINT: u32 = 7;

impl TypeSpec {
    /// Decode one `TypeSpecification`.
    pub fn parse(t: &Tlv<'_>, limits: &Limits) -> Result<TypeSpec> {
        TypeSpec::parse_depth(t, limits, 0)
    }

    fn parse_depth(t: &Tlv<'_>, limits: &Limits, depth: usize) -> Result<TypeSpec> {
        if depth > limits.max_depth {
            return Err(Error::LimitExceeded { limit: "max_depth", value: depth });
        }
        if t.tag.class != crate::ber::Class::Context {
            return Err(Error::decode(DecodeReason::UnexpectedTag, t.offset));
        }
        Ok(match t.tag.number {
            0 => {
                let name = super::ObjectName::parse(&t.children().next_required()?)?;
                match name {
                    super::ObjectName::DomainSpecific { domain, item } => TypeSpec::Named { domain: Some(String::from(domain)), item: String::from(item) },
                    super::ObjectName::VmdSpecific(n) | super::ObjectName::AaSpecific(n) => TypeSpec::Named { domain: None, item: String::from(n) },
                }
            }
            1 => {
                let mut c = t.children();
                let packed = c.next_if_tag(Tag::context(0))?.map(|t| t.boolean()).transpose()?.unwrap_or(false);
                let elements = c.next_tag(Tag::context(1))?.unsigned_lenient_u32()?;
                let element_type = TypeSpec::parse_depth(&c.next_tag(Tag::context_constructed(2))?.children().next_required()?, limits, depth + 1)?;
                TypeSpec::Array { packed, elements, element_type: Box::new(element_type) }
            }
            2 => {
                let mut c = t.children();
                let packed = c.next_if_tag(Tag::context(0))?.map(|t| t.boolean()).transpose()?.unwrap_or(false);
                let list = c.next_tag(Tag::context_constructed(1))?;
                let mut components = Vec::new();
                for item in list.children() {
                    if components.len() >= limits.max_dataset_members {
                        return Err(Error::LimitExceeded { limit: "max_dataset_members", value: components.len() + 1 });
                    }
                    let mut m = item?.expect(Tag::universal(crate::ber::universal::SEQUENCE, true))?.children();
                    let name = m.next_if_tag(Tag::context(0))?.map(|t| t.visible_string()).transpose()?.map(String::from);
                    let type_spec = TypeSpec::parse_depth(&m.next_tag(Tag::context_constructed(1))?.children().next_required()?, limits, depth + 1)?;
                    components.push(Component { name, type_spec });
                }
                TypeSpec::Structure { packed, components }
            }
            tag::BOOLEAN => TypeSpec::Boolean,
            tag::BIT_STRING => TypeSpec::BitString(t.integer_i32()?),
            tag::INTEGER => TypeSpec::Integer(width(t)?),
            tag::UNSIGNED => TypeSpec::Unsigned(width(t)?),
            FLOATING_POINT => {
                // The two widths are **unnamed** members of the SEQUENCE, so ISO 9506-2
                // encodes them as universal INTEGERs — not as `[0]`/`[1]`. Wireshark's
                // stripped module has no `floating-point` in `TypeSpecification` at all, so
                // the oracle cannot tell the two apart and only a second stack can: this is
                // what libiec61850 writes and reads 🌐. The context-tagged form is accepted
                // too, because this crate itself emitted it before the interop run and a
                // decoder that refuses a peer's octets over a tag it can read is D11's
                // mistake in the other direction.
                let mut c = t.children();
                let format_width = width(&next_width(&mut c, 0)?)?;
                let exponent_width = width(&next_width(&mut c, 1)?)?;
                TypeSpec::FloatingPoint { format_width, exponent_width }
            }
            tag::OCTET_STRING => TypeSpec::OctetString(t.integer_i32()?),
            tag::VISIBLE_STRING => TypeSpec::VisibleString(t.integer_i32()?),
            tag::GENERALIZED_TIME => TypeSpec::GeneralizedTime,
            tag::BINARY_TIME => TypeSpec::BinaryTime(t.boolean()?),
            tag::BCD => TypeSpec::Bcd(width(t)?),
            tag::MMS_STRING => TypeSpec::MmsString(t.integer_i32()?),
            tag::UTC_TIME => TypeSpec::UtcTime,
            other => TypeSpec::Other(other),
        })
    }

    /// Encode this type specification into `e`.
    pub fn write(&self, e: &mut Encoder) -> Result<()> {
        match self {
            TypeSpec::Named { domain, item } => {
                e.constructed(Tag::context_constructed(0), |e| match domain {
                    Some(d) => super::ObjectName::DomainSpecific { domain: d, item }.write(e),
                    None => super::ObjectName::VmdSpecific(item).write(e),
                })?;
            }
            TypeSpec::Array { packed, elements, element_type } => {
                e.constructed(Tag::context_constructed(1), |e| {
                    if *packed {
                        e.boolean(Tag::context(0), true)?;
                    }
                    e.unsigned(Tag::context(1), u64::from(*elements))?;
                    e.constructed(Tag::context_constructed(2), |e| element_type.write(e))?;
                    Ok(())
                })?;
            }
            TypeSpec::Structure { packed, components } => {
                e.constructed(Tag::context_constructed(2), |e| {
                    if *packed {
                        e.boolean(Tag::context(0), true)?;
                    }
                    e.constructed(Tag::context_constructed(1), |e| {
                        for c in components {
                            e.constructed(Tag::universal(crate::ber::universal::SEQUENCE, true), |e| {
                                if let Some(n) = &c.name {
                                    e.visible_string(Tag::context(0), n)?;
                                }
                                e.constructed(Tag::context_constructed(1), |e| c.type_spec.write(e))?;
                                Ok(())
                            })?;
                        }
                        Ok(())
                    })?;
                    Ok(())
                })?;
            }
            TypeSpec::Boolean => {
                e.primitive(Tag::context(tag::BOOLEAN), &[])?;
            }
            TypeSpec::BitString(n) => {
                e.integer(Tag::context(tag::BIT_STRING), i64::from(*n))?;
            }
            TypeSpec::Integer(w) => {
                e.unsigned(Tag::context(tag::INTEGER), u64::from(*w))?;
            }
            TypeSpec::Unsigned(w) => {
                e.unsigned(Tag::context(tag::UNSIGNED), u64::from(*w))?;
            }
            TypeSpec::FloatingPoint { format_width, exponent_width } => {
                e.constructed(Tag::context_constructed(FLOATING_POINT), |e| {
                    e.unsigned(Tag::universal(crate::ber::universal::INTEGER, false), u64::from(*format_width))?;
                    e.unsigned(Tag::universal(crate::ber::universal::INTEGER, false), u64::from(*exponent_width))?;
                    Ok(())
                })?;
            }
            TypeSpec::OctetString(n) => {
                e.integer(Tag::context(tag::OCTET_STRING), i64::from(*n))?;
            }
            TypeSpec::VisibleString(n) => {
                e.integer(Tag::context(tag::VISIBLE_STRING), i64::from(*n))?;
            }
            TypeSpec::GeneralizedTime => {
                e.primitive(Tag::context(tag::GENERALIZED_TIME), &[])?;
            }
            TypeSpec::BinaryTime(dated) => {
                e.boolean(Tag::context(tag::BINARY_TIME), *dated)?;
            }
            TypeSpec::Bcd(n) => {
                e.unsigned(Tag::context(tag::BCD), u64::from(*n))?;
            }
            TypeSpec::MmsString(n) => {
                e.integer(Tag::context(tag::MMS_STRING), i64::from(*n))?;
            }
            TypeSpec::UtcTime => {
                e.primitive(Tag::context(tag::UTC_TIME), &[])?;
            }
            TypeSpec::Other(n) => {
                e.primitive(Tag::context(*n), &[])?;
            }
        }
        Ok(())
    }

    /// The component with this name, for a structure.
    pub fn component(&self, name: &str) -> Option<&TypeSpec> {
        match self {
            TypeSpec::Structure { components, .. } => components.iter().find(|c| c.name.as_deref() == Some(name)).map(|c| &c.type_spec),
            _ => None,
        }
    }

    /// The component names of a structure, in order.
    pub fn component_names(&self) -> Vec<&str> {
        match self {
            TypeSpec::Structure { components, .. } => components.iter().filter_map(|c| c.name.as_deref()).collect(),
            _ => Vec::new(),
        }
    }
}

/// One width of a `floating-point` type specification, in either encoding.
///
/// ISO 9506-2 leaves `format-width` and `exponent-width` unnamed, so the conformant octets are
/// universal INTEGERs; `tag` is the context number this crate used to write instead, and is
/// still accepted on the way in.
fn next_width<'a>(c: &mut Cursor<'a>, tag: u32) -> Result<Tlv<'a>> {
    let t = c.next_required()?;
    if t.tag == Tag::universal(crate::ber::universal::INTEGER, false) || t.tag == Tag::context(tag) {
        Ok(t)
    } else {
        Err(Error::decode(DecodeReason::UnexpectedTag, t.offset))
    }
}

fn width(t: &Tlv<'_>) -> Result<u8> {
    u8::try_from(t.unsigned_lenient_u32()?).map_err(|_| Error::decode(DecodeReason::BadValue, t.value_offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::Cursor;

    fn round_trip(spec: &TypeSpec) -> TypeSpec {
        let mut e = Encoder::new();
        spec.write(&mut e).unwrap();
        let bytes = e.into_vec();
        let back = TypeSpec::parse(&Cursor::new(&bytes).next_required().unwrap(), &Limits::DEFAULT).unwrap();
        assert_eq!(&back, spec);
        back
    }

    /// The octets a second stack actually puts on the wire for `MMXU1$MX$TotW$mag`.
    ///
    /// `floating-point [7]`'s two widths are **unnamed** members of the SEQUENCE, so they are
    /// universal INTEGERs and not `[0]`/`[1]`. Nothing in this repository could have caught
    /// the difference: Wireshark's stripped module has no `floating-point` in
    /// `TypeSpecification` at all, so the oracle dissects either form without complaint, and
    /// both halves of this crate shared the wrong encoder. libiec61850 refused what we wrote
    /// and we refused what it wrote — in both directions, silently, as a timeout.
    #[test]
    fn a_floating_point_type_is_the_octets_the_field_writes() {
        // libiec61850 1.6.2, `GetVariableAccessAttributes` for `GGIO1$MX$AnIn1` 🌐.
        const VENDOR: &[u8] = &[
            0xa2, 0x31, 0xa1, 0x2f, 0x30, 0x1a, 0x80, 0x03, b'm', b'a', b'g', 0xa1, 0x13, 0xa2, 0x11, 0xa1, 0x0f, 0x30, 0x0d, 0x80, 0x01, b'f', 0xa1, 0x08,
            0xa7, 0x06, 0x02, 0x01, 0x20, 0x02, 0x01, 0x08, 0x30, 0x08, 0x80, 0x01, b'q', 0xa1, 0x03, 0x84, 0x01, 0xf3, 0x30, 0x07, 0x80, 0x01, b't', 0xa1,
            0x02, 0x91, 0x00,
        ];
        let spec = TypeSpec::parse(&Cursor::new(VENDOR).next_required().unwrap(), &Limits::DEFAULT).expect("the field's octets decode");
        assert_eq!(spec.component_names(), ["mag", "q", "t"]);
        assert_eq!(spec.component("mag").and_then(|m| m.component("f")), Some(&TypeSpec::FloatingPoint { format_width: 32, exponent_width: 8 }));
        // And we write what it writes, byte for byte — which is the half a round trip through
        // our own encoder can never prove.
        let mut e = Encoder::new();
        spec.write(&mut e).unwrap();
        assert_eq!(e.into_vec(), VENDOR);
    }

    /// The context-tagged form this crate used to emit is still read, because a peer's octets
    /// that can be understood are understood (D11) — even when the peer was us.
    #[test]
    fn the_older_context_tagged_widths_are_still_accepted() {
        const LEGACY: &[u8] = &[0xa7, 0x06, 0x80, 0x01, 0x40, 0x81, 0x01, 0x0b];
        let spec = TypeSpec::parse(&Cursor::new(LEGACY).next_required().unwrap(), &Limits::DEFAULT).expect("decode");
        assert_eq!(spec, TypeSpec::FloatingPoint { format_width: 64, exponent_width: 11 });
        // Anything else in that position is still a refusal rather than a guess.
        assert!(TypeSpec::parse(&Cursor::new(&[0xa7, 0x06, 0x83, 0x01, 0x40, 0x81, 0x01, 0x0b]).next_required().unwrap(), &Limits::DEFAULT).is_err());
    }

    #[test]
    fn the_shape_of_an_oper_is_what_a_client_needs_before_it_writes_one() {
        // What a server answers for `CSWI1$CO$Pos$Oper`: the structure a control is.
        let oper = TypeSpec::Structure {
            packed: false,
            components: alloc::vec![
                Component { name: Some(String::from("ctlVal")), type_spec: TypeSpec::BitString(2) },
                Component {
                    name: Some(String::from("origin")),
                    type_spec: TypeSpec::Structure {
                        packed: false,
                        components: alloc::vec![
                            Component { name: Some(String::from("orCat")), type_spec: TypeSpec::Integer(8) },
                            Component { name: Some(String::from("orIdent")), type_spec: TypeSpec::OctetString(-64) },
                        ],
                    },
                },
                Component { name: Some(String::from("ctlNum")), type_spec: TypeSpec::Unsigned(8) },
                Component { name: Some(String::from("T")), type_spec: TypeSpec::UtcTime },
                Component { name: Some(String::from("Test")), type_spec: TypeSpec::Boolean },
                Component { name: Some(String::from("Check")), type_spec: TypeSpec::BitString(2) },
            ],
        };
        let back = round_trip(&oper);
        assert_eq!(back.component_names(), ["ctlVal", "origin", "ctlNum", "T", "Test", "Check"]);
        assert_eq!(back.component("Check"), Some(&TypeSpec::BitString(2)));
        // A bounded string keeps its sign: -64 is "at most 64", 64 would be "exactly 64".
        assert_eq!(back.component("origin").and_then(|o| o.component("orIdent")), Some(&TypeSpec::OctetString(-64)));
    }

    #[test]
    fn every_simple_type_round_trips() {
        for spec in [
            TypeSpec::Boolean,
            TypeSpec::BitString(13),
            TypeSpec::Integer(32),
            TypeSpec::Unsigned(16),
            TypeSpec::FloatingPoint { format_width: 32, exponent_width: 8 },
            TypeSpec::OctetString(-8),
            TypeSpec::VisibleString(129),
            TypeSpec::GeneralizedTime,
            TypeSpec::BinaryTime(true),
            TypeSpec::Bcd(4),
            TypeSpec::MmsString(-255),
            TypeSpec::UtcTime,
            TypeSpec::Named { domain: Some(String::from("LD0")), item: String::from("MyType") },
            TypeSpec::Named { domain: None, item: String::from("Global") },
            TypeSpec::Array { packed: false, elements: 4, element_type: Box::new(TypeSpec::Boolean) },
        ] {
            round_trip(&spec);
        }
    }

    #[test]
    fn a_type_nested_deeper_than_the_limit_is_refused_rather_than_recursed() {
        let deep =
            (0..40).fold(TypeSpec::Boolean, |t, _| TypeSpec::Structure { packed: false, components: alloc::vec![Component { name: None, type_spec: t }] });
        let mut e = Encoder::new();
        deep.write(&mut e).unwrap();
        let bytes = e.into_vec();
        assert!(matches!(
            TypeSpec::parse(&Cursor::new(&bytes).next_required().unwrap(), &Limits::DEFAULT),
            Err(Error::LimitExceeded { limit: "max_depth", .. })
        ));
    }
}
