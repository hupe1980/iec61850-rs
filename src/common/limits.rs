/// Resource limits enforced by decoders *before* they allocate.
///
/// The defaults are generous for real substations and small enough that a malicious frame
/// cannot make a subscriber allocate more than a few kilobytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum nesting depth of BER constructed values (arrays and structures).
    pub max_depth: usize,
    /// Maximum number of members in a GOOSE `allData` or SV data set.
    pub max_dataset_members: usize,
    /// Maximum length of a single primitive value in bytes (strings, octet strings).
    pub max_primitive_len: usize,
    /// Maximum number of ASDUs in one SV APDU (IEC 61869-9 uses up to 6; 9-2LE up to 8).
    pub max_asdus: usize,
    /// Maximum number of items in one **page** of a listing service: the identifiers of a
    /// `GetNameList`, the entries of a `ReadJournal` or a `FileDirectory`, the strings of a
    /// `GetCapabilityList`.
    ///
    /// Not [`Limits::max_dataset_members`], and the difference is not cosmetic: a data set is
    /// engineered and small, while a name list is *the whole namespace of a logical device* —
    /// thousands of names on an ordinary IED. The real bound is the association's TSDU limit,
    /// since an identifier costs at least three octets; this is the same order, rounded.
    pub max_list_items: usize,
}

impl Limits {
    /// The defaults.
    pub const DEFAULT: Limits = Limits { max_depth: 32, max_dataset_members: 512, max_primitive_len: 4096, max_asdus: 16, max_list_items: 65_536 };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
