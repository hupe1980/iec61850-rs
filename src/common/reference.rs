use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::Error;

/// Functional constraint (IEC 61850-7-2 §5.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Fc {
    ST,
    MX,
    SP,
    SV,
    CF,
    DC,
    SG,
    SE,
    SR,
    OR,
    BL,
    EX,
    CO,
    US,
    MS,
    RP,
    BR,
    LG,
    GO,
    GS,
    XX,
}

impl Fc {
    /// Parse the two-letter code as written in SCL and object references.
    pub fn parse(s: &str) -> Option<Fc> {
        Some(match s {
            "ST" => Fc::ST,
            "MX" => Fc::MX,
            "SP" => Fc::SP,
            "SV" => Fc::SV,
            "CF" => Fc::CF,
            "DC" => Fc::DC,
            "SG" => Fc::SG,
            "SE" => Fc::SE,
            "SR" => Fc::SR,
            "OR" => Fc::OR,
            "BL" => Fc::BL,
            "EX" => Fc::EX,
            "CO" => Fc::CO,
            "US" => Fc::US,
            "MS" => Fc::MS,
            "RP" => Fc::RP,
            "BR" => Fc::BR,
            "LG" => Fc::LG,
            "GO" => Fc::GO,
            "GS" => Fc::GS,
            "XX" => Fc::XX,
            _ => return None,
        })
    }

    /// Whether a **client** may write a data attribute under this functional constraint
    /// (IEC 61850-7-2 §5.7, Table 5).
    ///
    /// This is the difference between a server and a value store, and it is not a detail:
    /// `ST` is *status information* — what the process reports — and `MX` is a measurand.
    /// A server that lets a client write them lets it fake a breaker position without
    /// touching the breaker, which is the control model bypassed in one `Write`. Real IEDs
    /// answer `object-access-denied`, and so does this one; the **application** behind the
    /// server writes them through its own path
    /// ([`Txn`](crate::server::Txn)), which is where process data belongs.
    ///
    /// `CO` is absent on purpose: nothing under it is a plain attribute. `Oper`, `SBOw`,
    /// `SBO` and `Cancel` are *services* with their own rules, and everything else under a
    /// controllable object is a component of one of them.
    pub const fn is_client_writable(self) -> bool {
        match self {
            // Settings, substitutions, configuration, descriptions, blocking and the editable
            // copy of a setting group; and the control blocks, which are written to configure
            // and enable them.
            Fc::SP | Fc::SV | Fc::CF | Fc::DC | Fc::SE | Fc::BL | Fc::RP | Fc::BR | Fc::LG | Fc::GO | Fc::GS | Fc::MS | Fc::US => true,
            // Status, measurands, the *active* setting group, service tracking, operate
            // received, extended definitions — all of them are what the server reports.
            Fc::ST | Fc::MX | Fc::SG | Fc::SR | Fc::OR | Fc::EX | Fc::CO | Fc::XX => false,
        }
    }

    /// The two-letter code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Fc::ST => "ST",
            Fc::MX => "MX",
            Fc::SP => "SP",
            Fc::SV => "SV",
            Fc::CF => "CF",
            Fc::DC => "DC",
            Fc::SG => "SG",
            Fc::SE => "SE",
            Fc::SR => "SR",
            Fc::OR => "OR",
            Fc::BL => "BL",
            Fc::EX => "EX",
            Fc::CO => "CO",
            Fc::US => "US",
            Fc::MS => "MS",
            Fc::RP => "RP",
            Fc::BR => "BR",
            Fc::LG => "LG",
            Fc::GO => "GO",
            Fc::GS => "GS",
            Fc::XX => "XX",
        }
    }
}

impl fmt::Display for Fc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One step *inside* a named variable: which part of its value a reference names.
///
/// A reference names a variable and, sometimes, a part of it. `MMXU1.TotW.mag.f` is a
/// variable all the way down, because every component of it has a name in the MMS namespace.
/// `MHAI1.HA.phsAHar(2).cVal.mag.f` is not: `phsAHar` is an **array**, MMS gives its elements
/// no names, and everything from the index on has to be carried beside the name as an
/// `alternateAccess` (`proto::mms::alternate`). This is the modelling half of that; the wire
/// half lives with the codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selector<'a> {
    /// A named component of a structure — `cVal`, `mag`, `f`.
    Component(&'a str),
    /// One element of an array, counted from zero.
    Index(u32),
    /// A run of elements of an array.
    IndexRange {
        /// The first element.
        low: u32,
        /// How many.
        count: u32,
    },
    /// Every element of an array. Distinct from *no* selection: it says the value is an array
    /// and that the client knows it.
    AllElements,
}

impl fmt::Display for Selector<'_> {
    /// The IEC 61850 reference syntax: `.cVal` for a component, `(2)` for an index.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Selector::Component(name) => write!(f, ".{name}"),
            Selector::Index(i) => write!(f, "({i})"),
            Selector::IndexRange { low, count } => write!(f, "({low}..{})", low.saturating_add(*count).saturating_sub(1)),
            Selector::AllElements => f.write_str("(*)"),
        }
    }
}

/// A parsed IEC 61850 object reference: `LDName/LNName.DO[.SDO][.DA[.BDA]]`, optionally
/// with a functional constraint in the MMS form `LDName/LNName$FC$DO$DA`.
///
/// Borrows the input; nothing is allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectReference<'a> {
    /// Logical device name (`IEDNameLDInst` or `ldName`).
    pub ld: &'a str,
    /// Logical node name (`prefix + class + inst`, e.g. `LLN0`, `MMXU1`).
    pub ln: &'a str,
    /// Functional constraint if the reference was in MMS form.
    pub fc: Option<Fc>,
    /// The path below the LN, without separators, e.g. `["Mod", "stVal"]`. Empty for an LN
    /// reference.
    path: &'a str,
}

impl<'a> ObjectReference<'a> {
    /// Parse either form. Returns an error for empty components or illegal characters.
    pub fn parse(s: &'a str) -> Result<Self, Error> {
        let (ld, rest) = s.split_once('/').ok_or(Error::InvalidReference("missing `/` between LD and LN"))?;
        if ld.is_empty() || !ld.bytes().all(is_name_byte) {
            return Err(Error::InvalidReference("logical device name"));
        }
        let (ln, fc, path) = if let Some((ln, tail)) = rest.split_once('$') {
            let (fc_str, path) = match tail.split_once('$') {
                Some((fc, path)) => (fc, path),
                None => (tail, ""),
            };
            let fc = Fc::parse(fc_str).ok_or(Error::InvalidReference("functional constraint"))?;
            (ln, Some(fc), path)
        } else {
            match rest.split_once('.') {
                Some((ln, path)) => (ln, None, path),
                None => (rest, None, ""),
            }
        };
        if ln.is_empty() || !ln.bytes().all(is_name_byte) {
            return Err(Error::InvalidReference("logical node name"));
        }
        for part in path.split(['.', '$']) {
            if path.is_empty() {
                break;
            }
            // `name` or `name(index)`, and nothing else: a stray parenthesis in a reference is
            // a typo that would otherwise become a name no server has.
            let (name, index) = split_index(part);
            if name.is_empty() || !name.bytes().all(is_name_byte) {
                return Err(Error::InvalidReference("data object / attribute name"));
            }
            if index.is_none() && name.len() != part.len() {
                return Err(Error::InvalidReference("array index"));
            }
        }
        Ok(ObjectReference { ld, ln, fc, path })
    }

    /// The components below the LN (`DO`, `SDO`, `DA`, `BDA` …), in order.
    pub fn path(&self) -> impl Iterator<Item = &'a str> + 'a {
        self.parts().map(|(name, _)| name).take(self.named_len())
    }

    /// Every component below the LN with the array index that follows it, if any.
    ///
    /// `HA.phsAHar(2).cVal` is `[("HA", None), ("phsAHar", Some(2)), ("cVal", None)]`.
    fn parts(&self) -> impl Iterator<Item = (&'a str, Option<u32>)> + 'a {
        self.path.split(['.', '$']).filter(|s| !s.is_empty()).map(split_index)
    }

    /// How many components make up the MMS **name**: everything up to and including the first
    /// one that carries an index.
    ///
    /// That is where the namespace stops. `MHAI1$MX$HA$phsAHar` is a named variable and
    /// `phsAHar`'s elements are not, so an index and everything after it is a *selection*
    /// rather than more of the name (IEC 61850-8-1 §7.3).
    fn named_len(&self) -> usize {
        let mut n = 0usize;
        for (_, index) in self.parts() {
            n += 1;
            if index.is_some() {
                break;
            }
        }
        n
    }

    /// The part of this reference that is **not** a name: the array index it selects and
    /// every component after it.
    ///
    /// Empty for the ordinary reference, which names a variable and nothing inside it. A
    /// non-empty one has to travel beside the name as an ISO 9506 `alternateAccess`, and a
    /// caller that drops it reads a whole array where it asked for one element.
    pub fn selection(&self) -> Vec<Selector<'a>> {
        let named = self.named_len();
        let mut out = Vec::new();
        for (n, (name, index)) in self.parts().enumerate() {
            if n + 1 > named {
                out.push(Selector::Component(name));
            }
            if let Some(i) = index {
                out.push(Selector::Index(i));
            }
        }
        out
    }

    /// The data object (first path component), if any.
    pub fn data_object(&self) -> Option<&'a str> {
        self.path().next()
    }

    /// Total length of the canonical dotted form, for the edition's limit
    /// ([`crate::common::Edition::max_object_reference_len`]).
    // A parsed reference is never empty, so there is no `is_empty` to pair with this.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.ld.len() + 1 + self.ln.len() + if self.path.is_empty() { 0 } else { 1 + self.path.len() }
    }

    /// True when this reference fits the object-reference limit of `edition`.
    pub fn fits(&self, edition: crate::common::Edition) -> bool {
        self.len() <= edition.max_object_reference_len()
    }
}

impl ObjectReference<'_> {
    /// The MMS domain and item this reference maps to (IEC 61850-8-1 §7.3).
    ///
    /// The logical device is the MMS **domain** and `LN$FC$DO$DA` is the **item** — the one
    /// mapping every client service goes through, so it lives here rather than being spelt
    /// out at each call site. A reference that already carries a functional constraint keeps
    /// its own; `fc` is what a dotted reference is read with.
    pub fn to_mms(&self, fc: Fc) -> (&str, String) {
        self.to_mms_under(self.fc.unwrap_or(fc))
    }

    /// The same reference under a **different** functional constraint.
    ///
    /// [`ObjectReference::to_mms`] keeps whatever constraint the reference itself carried,
    /// which is what a caller naming one leaf wants. This is the other case: one data object
    /// seen through two constraints. `CSWI1$CO$Pos` is the controllable object and
    /// `CSWI1$CF$Pos$ctlModel` is how it was engineered, and a client holding the first has
    /// to be able to ask for the second — which is exactly what stops it guessing the
    /// control model and building a sequence the server answers with `ObjectNotSelected`.
    pub fn to_mms_under(&self, fc: Fc) -> (&str, String) {
        let mut item = String::with_capacity(self.ln.len() + 3 + self.path.len() + 1);
        item.push_str(self.ln);
        item.push('$');
        item.push_str(fc.as_str());
        for part in self.path() {
            item.push('$');
            item.push_str(part);
        }
        (self.ld, item)
    }
}

impl fmt::Display for ObjectReference<'_> {
    /// Canonical dotted form; the MMS form if an FC is present.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ld, self.ln)?;
        // The raw path is printed, indices and all: a reference that selects an array element
        // has to come back out as the reference that went in.
        match self.fc {
            Some(fc) => {
                write!(f, "${fc}")?;
                for p in self.path.split(['.', '$']).filter(|s| !s.is_empty()) {
                    write!(f, "${p}")?;
                }
            }
            None => {
                for p in self.path.split(['.', '$']).filter(|s| !s.is_empty()) {
                    write!(f, ".{p}")?;
                }
            }
        }
        Ok(())
    }
}

const fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Split `phsAHar(2)` into `("phsAHar", Some(2))`, and anything without a well-formed index
/// into itself and `None`.
///
/// One place, because four layers ask the same question: the reference parser, the server's
/// name resolution, the value store's leaf walk and the data-set member that carries an `ix`.
/// Two spellings of "is this an array element" is two answers waiting to disagree.
pub fn split_index(part: &str) -> (&str, Option<u32>) {
    let Some(open) = part.find('(') else { return (part, None) };
    let (name, rest) = part.split_at(open);
    match rest.strip_prefix('(').and_then(|r| r.strip_suffix(')')).and_then(|d| d.parse::<u32>().ok()) {
        Some(index) => (name, Some(index)),
        None => (part, None),
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    /// One data object, two functional constraints. `to_mms` keeps the reference's own —
    /// which is right for a caller naming a leaf — and `to_mms_under` replaces it, which is
    /// the only way to ask a controllable object how it was engineered.
    #[test]
    fn a_controllable_object_can_be_asked_for_its_configuration() {
        let co = ObjectReference::parse("IED1LD0/CSWI1$CO$Pos").unwrap();
        assert_eq!(co.to_mms(Fc::CF), ("IED1LD0", String::from("CSWI1$CO$Pos")), "the reference's own constraint stands");
        assert_eq!(co.to_mms_under(Fc::CF), ("IED1LD0", String::from("CSWI1$CF$Pos")), "…until it is deliberately replaced");
        // A dotted reference has no constraint of its own, so both agree.
        let dotted = ObjectReference::parse("IED1LD0/CSWI1.Pos").unwrap();
        assert_eq!(dotted.to_mms(Fc::CF), dotted.to_mms_under(Fc::CF));
    }

    #[test]
    fn the_mms_mapping_puts_the_functional_constraint_after_the_logical_node() {
        let r = ObjectReference::parse("IED1LD0/MMXU1.TotW.mag.f").unwrap();
        assert_eq!(r.to_mms(Fc::MX), ("IED1LD0", String::from("MMXU1$MX$TotW$mag$f")));
        // A reference that already names its constraint keeps it.
        let m = ObjectReference::parse("IED1LD0/LLN0$ST$Mod$stVal").unwrap();
        assert_eq!(m.to_mms(Fc::MX), ("IED1LD0", String::from("LLN0$ST$Mod$stVal")));
        // A logical node on its own is the LN with its constraint and nothing under it.
        let ln = ObjectReference::parse("IED1LD0/LLN0").unwrap();
        assert_eq!(ln.to_mms(Fc::ST), ("IED1LD0", String::from("LLN0$ST")));
    }

    #[test]
    fn dotted_and_mms_forms() {
        let r = ObjectReference::parse("IED1LD0/MMXU1.TotW.mag.f").unwrap();
        assert_eq!((r.ld, r.ln, r.fc), ("IED1LD0", "MMXU1", None));
        assert_eq!(r.path().collect::<Vec<_>>(), ["TotW", "mag", "f"]);
        assert_eq!(r.to_string(), "IED1LD0/MMXU1.TotW.mag.f");

        let m = ObjectReference::parse("IED1LD0/LLN0$ST$Mod$stVal").unwrap();
        assert_eq!(m.fc, Some(Fc::ST));
        assert_eq!(m.data_object(), Some("Mod"));
        assert_eq!(m.to_string(), "IED1LD0/LLN0$ST$Mod$stVal");

        let ln = ObjectReference::parse("IED1LD0/LLN0").unwrap();
        assert_eq!(ln.path().count(), 0);
        assert_eq!(ln.len(), 12);
        assert!(ln.fits(crate::common::Edition::Ed1));

        assert!(ObjectReference::parse("nolyslash").is_err());
        assert!(ObjectReference::parse("LD/LN$ZZ$Mod").is_err());
        assert!(ObjectReference::parse("LD/LN..x").is_err());
        assert!(ObjectReference::parse("L D/LN").is_err());
    }
}
