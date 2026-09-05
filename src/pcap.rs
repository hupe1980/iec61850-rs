//! Reading and writing classic pcap files.
//!
//! Enough of the format to replay a capture into the codecs and to record what a publisher
//! produces. That is what makes the tooling testable without a network interface, and what
//! lets an external dissector such as `tshark` judge the frames this crate emits.
//!
//! Only the Ethernet link type is accepted, because that is the only thing a GOOSE or
//! sampled-value frame ever arrives on.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

/// Link type 1: Ethernet.
const LINKTYPE_ETHERNET: u32 = 1;

/// A capture read into memory: frames with their timestamps in nanoseconds.
#[derive(Clone, Debug, Default)]
pub struct Capture {
    /// `(timestamp_nanos, frame)` in file order.
    pub frames: Vec<(u64, Vec<u8>)>,
}

impl Capture {
    /// Read a classic pcap file (either endianness, microsecond or nanosecond resolution).
    pub fn read(path: impl AsRef<Path>) -> io::Result<Capture> {
        Capture::parse(&std::fs::read(path)?)
    }

    /// Parse the bytes of a classic pcap file.
    pub fn parse(data: &[u8]) -> io::Result<Capture> {
        let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_string());
        let magic: [u8; 4] = data.get(..4).ok_or_else(|| bad("file is too short"))?.try_into().map_err(|_| bad("short read"))?;
        let (little, nanos) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
            [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
            [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
            [0x0a, 0x0d, 0x0d, 0x0a] => return Err(bad("this is a pcapng file; convert it with `editcap -F pcap`")),
            _ => return Err(bad("not a classic pcap file")),
        };
        let u32_at = |o: usize| -> io::Result<u32> {
            let b: [u8; 4] = data.get(o..o + 4).ok_or_else(|| bad("truncated"))?.try_into().map_err(|_| bad("short read"))?;
            Ok(if little { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
        };
        if u32_at(20)? != LINKTYPE_ETHERNET {
            return Err(bad("only the Ethernet link type is supported"));
        }
        let mut frames = Vec::new();
        let mut off = 24;
        while off + 16 <= data.len() {
            let secs = u64::from(u32_at(off)?);
            let frac = u64::from(u32_at(off + 4)?);
            let captured = u32_at(off + 8)? as usize;
            let start = off + 16;
            // `captured` is attacker-controlled: on a 32-bit target `start + captured` can
            // wrap, and a wrapped range would silently read the wrong bytes.
            let Some(end) = start.checked_add(captured) else { break };
            let Some(frame) = data.get(start..end) else { break };
            frames.push((secs * 1_000_000_000 + frac * if nanos { 1 } else { 1_000 }, frame.to_vec()));
            off = end;
        }
        Ok(Capture { frames })
    }
}

/// Writes frames to a classic pcap file, microsecond resolution, Ethernet.
#[derive(Debug)]
pub struct Writer {
    out: BufWriter<File>,
}

impl Writer {
    /// Create (or truncate) `path` and write the file header.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Writer> {
        let mut out = BufWriter::new(File::create(path)?);
        out.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&0i32.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;
        out.write_all(&65_535u32.to_le_bytes())?;
        out.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
        Ok(Writer { out })
    }

    /// Append one frame stamped `nanos` since the Unix epoch.
    pub fn write(&mut self, nanos: u64, frame: &[u8]) -> io::Result<()> {
        let len = u32::try_from(frame.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too long"))?;
        self.out.write_all(&((nanos / 1_000_000_000) as u32).to_le_bytes())?;
        self.out.write_all(&((nanos % 1_000_000_000 / 1_000) as u32).to_le_bytes())?;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(frame)
    }

    /// Flush to disk.
    pub fn finish(mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = std::env::temp_dir().join(format!("iec61850-pcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.pcap");
        let mut w = Writer::create(&path).unwrap();
        w.write(1_700_000_000_000_000_000, &[1, 2, 3]).unwrap();
        w.write(1_700_000_000_001_000_000, &[4, 5]).unwrap();
        w.finish().unwrap();
        let c = Capture::read(&path).unwrap();
        assert_eq!(c.frames.len(), 2);
        assert_eq!(c.frames[0].1, [1, 2, 3]);
        assert_eq!(c.frames[1].0 - c.frames[0].0, 1_000_000);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_what_it_cannot_read() {
        assert!(Capture::parse(&[0u8; 4]).is_err());
        assert!(Capture::parse(&[0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0]).unwrap_err().to_string().contains("pcapng"));
        let mut wifi = vec![0xd4, 0xc3, 0xb2, 0xa1];
        wifi.extend_from_slice(&[0u8; 20]);
        wifi[20] = 105; // 802.11
        assert!(Capture::parse(&wifi).is_err());
        // A record claiming more bytes than the file holds ends the read; it does not panic
        // and it does not hand back bytes that were never captured.
        let mut lying = vec![0xd4, 0xc3, 0xb2, 0xa1];
        lying.extend_from_slice(&[0u8; 20]);
        lying[20] = 1;
        lying.extend_from_slice(&[0u8; 8]); // timestamp
        lying.extend_from_slice(&u32::MAX.to_le_bytes()); // captured length
        lying.extend_from_slice(&u32::MAX.to_le_bytes());
        lying.extend_from_slice(&[1, 2, 3]);
        assert!(Capture::parse(&lying).unwrap().frames.is_empty());
    }
}
