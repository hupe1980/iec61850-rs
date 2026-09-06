//! A panic-free BER (ITU-T X.690) codec for the subset IEC 61850 uses.
//!
//! The reader is a zero-copy cursor over a byte slice; every element is returned as a
//! [`Tlv`] view. Both halves are `no_std`, and indefinite lengths are rejected outright —
//! nothing in IEC 61850-8-1/9-2 emits them.
//!
//! The writer produces minimal definite-length encodings, plus one deliberate exception:
//! [`Encoder::unsigned_fixed`] writes an integer at a constant width with no leading zero
//! octet. Sampled-value publishers encode `smpCnt`, `confRev` and `smpSynch` that way so a
//! frame can be patched in place without any length shifting underneath, and fixed-length
//! encoded GOOSE writes every integer at the width of its `bType`. The matching reader is
//! [`Tlv::unsigned_lenient_u64`]; the strict [`Tlv::unsigned_u64`] stays for the MMS path.

mod reader;
mod writer;

pub use reader::{Cursor, Tlv};

/// An ISO 9506 `FloatingPoint` value with the precision it was encoded at.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Float {
    /// Exponent width 8: IEEE 754 single precision.
    Single(f32),
    /// Exponent width 11: IEEE 754 double precision.
    Double(f64),
}

impl Float {
    /// The value as `f64`.
    pub fn as_f64(self) -> f64 {
        match self {
            Float::Single(f) => f64::from(f),
            Float::Double(f) => f,
        }
    }
}
pub use writer::{Encoder, unsigned_width};

/// The class of a BER tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Universal (0).
    Universal,
    /// Application (1).
    Application,
    /// Context-specific (2).
    Context,
    /// Private (3).
    Private,
}

/// A BER tag: class, constructed bit, number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tag {
    /// The class.
    pub class: Class,
    /// Constructed (true) or primitive (false).
    pub constructed: bool,
    /// The tag number.
    pub number: u32,
}

impl Tag {
    /// A primitive context-specific tag `[n]`.
    pub const fn context(number: u32) -> Tag {
        Tag { class: Class::Context, constructed: false, number }
    }
    /// A constructed context-specific tag `[n]`.
    pub const fn context_constructed(number: u32) -> Tag {
        Tag { class: Class::Context, constructed: true, number }
    }
    /// A constructed application tag `[APPLICATION n]`.
    pub const fn application_constructed(number: u32) -> Tag {
        Tag { class: Class::Application, constructed: true, number }
    }
    /// A primitive application tag `[APPLICATION n]`.
    pub const fn application(number: u32) -> Tag {
        Tag { class: Class::Application, constructed: false, number }
    }
    /// A universal tag.
    pub const fn universal(number: u32, constructed: bool) -> Tag {
        Tag { class: Class::Universal, constructed, number }
    }

    /// The identifier octet.
    ///
    /// Tag numbers of 31 and above take the high-tag-number form, whose continuation octets
    /// [`Encoder`] writes after this one — the MMS file and journal services live up there
    /// (`readJournal [65]`, `fileOpen [72]`, `fileDirectory [77]`).
    pub const fn first_octet(self) -> u8 {
        let class = match self.class {
            Class::Universal => 0,
            Class::Application => 0x40,
            Class::Context => 0x80,
            Class::Private => 0xC0,
        };
        class | (if self.constructed { 0x20 } else { 0 }) | (if self.number < 31 { self.number as u8 } else { 31 })
    }
}

/// Universal tag numbers used here.
pub mod universal {
    /// BOOLEAN.
    pub const BOOLEAN: u32 = 1;
    /// INTEGER.
    pub const INTEGER: u32 = 2;
    /// BIT STRING.
    pub const BIT_STRING: u32 = 3;
    /// OCTET STRING.
    pub const OCTET_STRING: u32 = 4;
    /// NULL.
    pub const NULL: u32 = 5;
    /// OBJECT IDENTIFIER.
    pub const OID: u32 = 6;
    /// SEQUENCE / SEQUENCE OF.
    pub const SEQUENCE: u32 = 16;
    /// `GraphicString` — what an MMS `FileName` component is.
    pub const GRAPHIC_STRING: u32 = 25;
    /// `VisibleString`.
    pub const VISIBLE_STRING: u32 = 26;
}
