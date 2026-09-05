//! The 48-bit link-layer address, and the IEC 61850 multicast ranges within it.
//!
//! It lives in `common` rather than in `proto::ethernet` because the SCL model records
//! publisher addresses whether or not the process-bus codecs are compiled in.

use crate::common::{Error, Result};

/// A MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The first address of the GOOSE multicast range `01-0C-CD-01-00-00`.
    pub const GOOSE_BASE: MacAddr = MacAddr([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x00]);
    /// The first address of the SV multicast range `01-0C-CD-04-00-00`.
    pub const SV_BASE: MacAddr = MacAddr([0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00]);

    /// True for `01-0C-CD-01-00-00` … `01-0C-CD-01-01-FF`.
    pub const fn is_goose_multicast(self) -> bool {
        let b = self.0;
        b[0] == 0x01 && b[1] == 0x0C && b[2] == 0xCD && b[3] == 0x01 && b[4] <= 0x01
    }

    /// True for `01-0C-CD-04-00-00` … `01-0C-CD-04-01-FF`.
    pub const fn is_sv_multicast(self) -> bool {
        let b = self.0;
        b[0] == 0x01 && b[1] == 0x0C && b[2] == 0xCD && b[3] == 0x04 && b[4] <= 0x01
    }

    /// Parse `01-0C-CD-01-00-01` or `01:0c:cd:01:00:01`.
    pub fn parse(s: &str) -> Result<MacAddr> {
        let bad = || Error::InvalidValue("MAC address");
        let mut out = [0u8; 6];
        let mut parts = s.split(['-', ':']);
        for slot in &mut out {
            let part = parts.next().ok_or_else(bad)?;
            if part.len() != 2 {
                return Err(bad());
            }
            *slot = u8::from_str_radix(part, 16).map_err(|_| bad())?;
        }
        if parts.next().is_some() {
            return Err(bad());
        }
        Ok(MacAddr(out))
    }
}

impl core::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = self.0;
        write!(f, "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}
