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

    /// The edition an SCL file declares, from its `version`+`revision`+`release` string.
    ///
    /// This is the whole of "edition is a property of the server, and the server's edition is
    /// what its file says": `2003` is Edition 1, `2007A`/`2007B` through release 3 is
    /// Edition 2, and `2007B4` (IEC 61850-6:2009+AMD1) or anything later — `2007C`, the
    /// Ed 2.2 schema — is Edition 2.1. An unrecognised string is read as the newest rather
    /// than the oldest: a file from a schema this crate has not seen is more likely to be
    /// ahead of it than behind, and reading a modern file as Edition 1 would silently drop
    /// `ResvTms` and `Owner` from every report control block.
    pub fn from_scl_version(version: &str) -> Edition {
        let v = version.trim();
        if v.starts_with("2003") {
            return Edition::Ed1;
        }
        if let Some(rest) = v.strip_prefix("2007") {
            // `2007B4` and up are Ed 2.1; `2007A`, `2007B`, `2007B1`..`2007B3` are Ed 2.
            let release: u32 = rest.trim_start_matches(char::is_alphabetic).parse().unwrap_or(0);
            let revision = rest.chars().next().unwrap_or('B');
            return if revision >= 'C' || (revision == 'B' && release >= 4) { Edition::Ed2_1 } else { Edition::Ed2 };
        }
        Edition::Ed2_1
    }

    /// Whether a report control block has `ResvTms` (buffered) and `Owner`.
    ///
    /// Both arrived with Edition 2 (IEC 61850-7-2 §17.2). An Edition 1 server that publishes
    /// them is claiming a reservation service it does not have, and a client that reads the
    /// block positionally then reads every field after them at the wrong offset.
    pub const fn has_rcb_reservation(self) -> bool {
        !matches!(self, Edition::Ed1)
    }
}
