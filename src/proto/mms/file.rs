//! The MMS file services IEC 61850-8-1 maps `FileDirectory`, `FileOpen`, `FileRead`,
//! `FileClose` and `FileDelete` onto — the COMTRADE story.
//!
//! ```text
//! FileName      ::= SEQUENCE OF GraphicString
//! FileAttributes ::= SEQUENCE { sizeOfFile [0] Unsigned32, lastModified [1] GeneralizedTime OPTIONAL }
//! DirectoryEntry ::= SEQUENCE { filename [0] FileName, fileAttributes [1] FileAttributes }
//! ```
//!
//! Structures from ISO 9506-2 as `../specs/asn1-wireshark/mms.asn` states them ✅. A file is
//! read by opening it (which returns an `frsmID`), reading until `moreFollows` is false, and
//! closing it — the `frsmID` is a server-side handle and leaking one leaks a file descriptor
//! in an IED, so [`crate::client::Client::read_file`] closes it even when a read fails.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ber::{Cursor, Encoder, Tag, Tlv, universal};
use crate::common::{Error, Limits, Result};

/// `GraphicString`, the type an MMS file-name component is.
pub const TAG_GRAPHIC_STRING: Tag = Tag::universal(universal::GRAPHIC_STRING, false);

/// A borrowed `FileName`: the encoded contents of the `SEQUENCE OF GraphicString`.
///
/// It is the encoded form rather than a list of components because a `FileName` has to
/// survive a decode-and-re-encode byte for byte, and because most servers put the whole path
/// in one component while some split it — neither of which a caller should have to care
/// about. [`FileName::components`] walks it, [`FileName::display`] joins it with `/`, and
/// [`FileNameBuf`] builds one from a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FileName<'a>(&'a [u8]);

impl<'a> FileName<'a> {
    /// A file name over already-encoded contents octets.
    pub const fn from_encoded(contents: &'a [u8]) -> FileName<'a> {
        FileName(contents)
    }

    /// The encoded contents octets.
    pub const fn as_encoded(&self) -> &'a [u8] {
        self.0
    }

    /// The components, in order. A malformed component ends the iteration.
    pub fn components(&self) -> impl Iterator<Item = &'a str> {
        Cursor::new(self.0).map_while(Result::ok).map_while(|t| t.visible_string().ok())
    }

    /// The components joined with `/`, which is how every IED writes a path anyway.
    pub fn display(&self) -> String {
        let mut out = String::new();
        for (n, part) in self.components().enumerate() {
            if n > 0 {
                out.push('/');
            }
            out.push_str(part);
        }
        out
    }

    /// Decode from an element whose contents are the `SEQUENCE OF`, checking every component.
    pub fn parse(t: &Tlv<'a>, limits: &Limits) -> Result<FileName<'a>> {
        let mut n = 0usize;
        for part in t.children() {
            let part = part?;
            if part.value.len() > limits.max_primitive_len {
                return Err(Error::LimitExceeded { limit: "max_primitive_len", value: part.value.len() });
            }
            part.visible_string()?;
            n += 1;
            if n > 32 {
                return Err(Error::LimitExceeded { limit: "file name components", value: n });
            }
        }
        Ok(FileName(t.value))
    }

    /// Write the contents octets into `e` (the caller writes the enclosing tag).
    pub fn write_contents(&self, e: &mut Encoder) {
        e.raw(self.0);
    }
}

/// An owned `FileName`, built from a path a caller typed.
///
/// The path is sent as **one** component, which is what libiec61850 and every IED capture we
/// have does; a server that splits its own names still round-trips, because decoding keeps
/// the encoded form.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FileNameBuf(Vec<u8>);

impl FileNameBuf {
    /// One component holding the whole path.
    pub fn from_path(path: &str) -> Result<FileNameBuf> {
        let mut e = Encoder::new();
        e.visible_string(TAG_GRAPHIC_STRING, path)?;
        Ok(FileNameBuf(e.into_vec()))
    }

    /// Several components.
    pub fn from_components(parts: &[&str]) -> Result<FileNameBuf> {
        let mut e = Encoder::new();
        for p in parts {
            e.visible_string(TAG_GRAPHIC_STRING, p)?;
        }
        Ok(FileNameBuf(e.into_vec()))
    }

    /// Borrow it for a request.
    pub fn as_name(&self) -> FileName<'_> {
        FileName(&self.0)
    }
}

/// `FileAttributes`: how big the file is, and when it was last written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileAttributes<'a> {
    /// `sizeOfFile`, in octets.
    pub size: u32,
    /// `lastModified` as the `GeneralizedTime` string the server sent (`20240131T101500Z`),
    /// kept verbatim rather than parsed: servers disagree about the fractional part and the
    /// zone suffix, and a wrong parse is worse than the text.
    pub last_modified: Option<&'a str>,
}

impl<'a> FileAttributes<'a> {
    pub(super) fn parse(t: &Tlv<'a>) -> Result<FileAttributes<'a>> {
        let mut c = t.children();
        let size = c.next_tag(Tag::context(0))?.unsigned_lenient_u32()?;
        let last_modified = c.next_if_tag(Tag::context(1))?.map(|t| t.visible_string()).transpose()?;
        Ok(FileAttributes { size, last_modified })
    }

    pub(super) fn write(&self, tag: Tag, e: &mut Encoder) -> Result<()> {
        e.constructed(tag, |e| {
            e.unsigned(Tag::context(0), u64::from(self.size))?;
            if let Some(m) = self.last_modified {
                e.visible_string(Tag::context(1), m)?;
            }
            Ok(())
        })?;
        Ok(())
    }
}

/// The `DirectoryEntry` elements inside a `listOfDirectoryEntry [0]`.
///
/// The field is `[0] SEQUENCE OF DirectoryEntry` with **no** `IMPLICIT` ✅, so a conforming
/// server writes `a0 { 30 { 30 … } }` and the entries are the children of the inner
/// `SEQUENCE`. A server that tagged it implicitly puts them directly under `[0]`, and both
/// are in the field; the two are told apart by what the first child *contains* — a
/// `DirectoryEntry` starts with `filename [0]`, the `SEQUENCE OF` wrapper starts with another
/// `SEQUENCE` — so this reads either without guessing.
pub(super) fn directory_entries<'a>(list: &Tlv<'a>) -> Cursor<'a> {
    let mut outer = list.children();
    let Some(Ok(first)) = outer.next() else { return list.children() };
    if first.tag != Tag::universal(universal::SEQUENCE, true) {
        return list.children();
    }
    // Explicit: the wrapper's own first child is a `DirectoryEntry`, i.e. a SEQUENCE. An
    // empty wrapper (`a0 02 30 00`) is an empty listing and is explicit too.
    match first.children().next() {
        Some(Ok(inner)) if inner.tag == Tag::universal(universal::SEQUENCE, true) => first.children(),
        None => first.children(),
        _ => list.children(),
    }
}

/// One entry of a `FileDirectory` response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectoryEntry<'a> {
    /// The file.
    pub name: FileName<'a>,
    /// Its size and modification time.
    pub attributes: FileAttributes<'a>,
}

impl<'a> DirectoryEntry<'a> {
    pub(super) fn parse(t: &Tlv<'a>, limits: &Limits) -> Result<DirectoryEntry<'a>> {
        let mut c = t.expect(Tag::universal(universal::SEQUENCE, true))?.children();
        let name = FileName::parse(&c.next_tag(Tag::context_constructed(0))?, limits)?;
        let attributes = FileAttributes::parse(&c.next_tag(Tag::context_constructed(1))?)?;
        Ok(DirectoryEntry { name, attributes })
    }

    pub(super) fn write(&self, e: &mut Encoder) -> Result<()> {
        e.constructed(Tag::universal(universal::SEQUENCE, true), |e| {
            e.constructed(Tag::context_constructed(0), |e| {
                self.name.write_contents(e);
                Ok(())
            })?;
            self.attributes.write(Tag::context_constructed(1), e)?;
            Ok(())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_one_component_and_reads_back_as_the_path() {
        let buf = FileNameBuf::from_path("COMTRADE/rec0001.cfg").unwrap();
        let name = buf.as_name();
        assert_eq!(name.components().collect::<Vec<_>>(), ["COMTRADE/rec0001.cfg"]);
        assert_eq!(name.display(), "COMTRADE/rec0001.cfg");
        // And a server that splits its own names joins back to the same shape.
        let split = FileNameBuf::from_components(&["COMTRADE", "rec0001.cfg"]).unwrap();
        assert_eq!(split.as_name().display(), "COMTRADE/rec0001.cfg");
        assert_eq!(split.as_name().components().count(), 2);
    }

    #[test]
    fn a_file_name_survives_a_decode_and_re_encode() {
        let buf = FileNameBuf::from_components(&["a", "b"]).unwrap();
        let mut e = Encoder::new();
        e.constructed(Tag::context_constructed(0), |e| {
            buf.as_name().write_contents(e);
            Ok(())
        })
        .unwrap();
        let bytes = e.into_vec();
        let t = Cursor::new(&bytes).next_required().unwrap();
        let name = FileName::parse(&t, &Limits::DEFAULT).unwrap();
        assert_eq!(name.as_encoded(), buf.as_name().as_encoded());
    }
}
