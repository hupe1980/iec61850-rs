/// The IEC 61850 edition a server implements.
///
/// Edition is a property of a server (it is what its SCL file declares), never of an
/// association. It drives attribute sets (RCB `ResvTms`/`Owner`), object-reference length
/// limits, the GOOSE `test`/`simulation` naming and the enumerations that grew between
/// editions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub enum Edition {
    /// IEC 61850 Edition 1 (2003/2004).
    Ed1,
    /// IEC 61850 Edition 2 (2009–2011).
    Ed2,
    /// IEC 61850 Edition 2.1 (2010/2011 + AMD1:2020) — the default.
    #[default]
    Ed2_1,
}

impl Edition {
    /// Maximum length of an object reference (`VisString65` in Ed1, `VisString129` from Ed2).
    pub const fn max_object_reference_len(self) -> usize {
        match self {
            Edition::Ed1 => 65,
            Edition::Ed2 | Edition::Ed2_1 => 129,
        }
    }

    /// The SCL schema namespace revision this edition corresponds to.
    pub const fn scl_version(self) -> &'static str {
        match self {
            Edition::Ed1 => "2003",
            Edition::Ed2 => "2007B",
            Edition::Ed2_1 => "2007B4",
        }
    }
}
