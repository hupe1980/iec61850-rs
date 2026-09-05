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
}

impl Limits {
    /// The defaults.
    pub const DEFAULT: Limits = Limits { max_depth: 32, max_dataset_members: 512, max_primitive_len: 4096, max_asdus: 16 };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
