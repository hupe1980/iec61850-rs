use alloc::string::String;
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
            if !path.is_empty() && (part.is_empty() || !part.bytes().all(is_path_byte)) {
                return Err(Error::InvalidReference("data object / attribute name"));
            }
        }
        Ok(ObjectReference { ld, ln, fc, path })
    }

    /// The components below the LN (`DO`, `SDO`, `DA`, `BDA` …), in order.
    pub fn path(&self) -> impl Iterator<Item = &'a str> + 'a {
        let p = self.path;
        p.split(['.', '$']).filter(|s| !s.is_empty())
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
        let fc = self.fc.unwrap_or(fc);
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
        match self.fc {
            Some(fc) => {
                write!(f, "${fc}")?;
                for p in self.path() {
                    write!(f, "${p}")?;
                }
            }
            None => {
                for p in self.path() {
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

const fn is_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'(' || b == b')'
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;

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
