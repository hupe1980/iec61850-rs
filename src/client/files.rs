//! File services: listing a server's files and pulling one off it.
//!
//! This is how a COMTRADE record gets off an IED. The MMS shape is a handle protocol —
//! `FileOpen` returns an `frsmID`, `FileRead` is called with it until the server says no more
//! follows, `FileClose` gives it back — and the handle is a *server-side* resource, so
//! [`Client::read_file`] closes it even when a read fails partway. A leaked `frsmID` is a file
//! left open in a protection relay, and IEDs have very few of them.

use alloc::string::String;
use alloc::vec::Vec;

use super::Client;
use crate::ber::{Encoder, Tag};
use crate::common::{Error, Result};
use crate::proto::mms::file::{FileAttributes, FileName, FileNameBuf};
use crate::proto::mms::reject::{self, Reject, RejectReason};
use crate::proto::mms::{ConfirmedRequest, ConfirmedResponse, Mms, ServiceError, file_error, service_error};

/// What a `set_file` offers the server: one name, its octets, and the one handle it may hold.
#[derive(Debug)]
pub(crate) struct Serving {
    name: String,
    source: Source,
    size: u32,
    /// `(frsmID, next offset)` while the server has the file open.
    open: Option<(i32, u64)>,
}

#[derive(Debug)]
enum Source {
    Bytes(Vec<u8>),
    File(std::fs::File),
}

impl Source {
    fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        match self {
            Source::Bytes(b) => {
                let start = usize::try_from(offset).unwrap_or(usize::MAX).min(b.len());
                let end = start.saturating_add(len).min(b.len());
                Ok(b.get(start..end).unwrap_or_default().to_vec())
            }
            Source::File(f) => {
                use std::io::{Read, Seek, SeekFrom};
                f.seek(SeekFrom::Start(offset)).map_err(|e| Error::Io(e.to_string()))?;
                let mut buf = alloc::vec![0u8; len];
                let mut filled = 0;
                while filled < len {
                    match f.read(buf.get_mut(filled..).unwrap_or_default()) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(Error::Io(e.to_string())),
                    }
                }
                buf.truncate(filled);
                Ok(buf)
            }
        }
    }
}

/// A `confirmed-ErrorPDU` answering `invoke_id`.
fn confirmed_error(invoke_id: i64, class: u32, code: i64) -> Result<Vec<u8>> {
    let body = ServiceError::encode(Tag::context_constructed(2), class, code)?;
    let mut e = Encoder::new();
    e.constructed(Tag::context_constructed(2), |e| {
        e.integer(Tag::context(0), invoke_id)?;
        e.raw(&body);
        Ok(())
    })?;
    Ok(e.into_vec())
}

/// One file on a server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileEntry {
    /// The path, as the server names it.
    pub name: String,
    /// Size in octets.
    pub size: u32,
    /// `lastModified`, as the `GeneralizedTime` string the server sent.
    pub last_modified: Option<String>,
}

impl Client {
    /// List the server's files.
    ///
    /// `specification` restricts the listing the way the server understands it — a directory
    /// name, or `None` for everything. The answer is paged with `moreFollows` exactly like
    /// `GetNameList`, and the paging is done here.
    pub fn file_directory(&mut self, specification: Option<&str>) -> Result<Vec<FileEntry>> {
        let spec = specification.map(FileNameBuf::from_path).transpose()?;
        let mut out: Vec<FileEntry> = Vec::new();
        loop {
            // `continueAfter` is the last name seen, re-encoded as a single component. A
            // server that split its own names into several would not match it and would
            // repeat its first page — which the ceiling below turns into an error rather
            // than a loop. No IED we have a capture of splits them.
            let last = out.last().map(|e| FileNameBuf::from_path(&e.name)).transpose()?;
            let request = ConfirmedRequest::FileDirectory {
                specification: spec.as_ref().map(FileNameBuf::as_name),
                continue_after: last.as_ref().map(FileNameBuf::as_name),
            };
            let pdu = self.call(&request)?;
            let Mms::ConfirmedResponse { service: ConfirmedResponse::FileDirectory { entries, more_follows }, .. } = Mms::parse(&pdu, &self.limits)? else {
                return Err(Error::InvalidValue("not a FileDirectory response"));
            };
            let empty = entries.is_empty();
            for e in entries {
                out.push(FileEntry { name: e.name.display(), size: e.attributes.size, last_modified: e.attributes.last_modified.map(String::from) });
            }
            // A server that says `moreFollows` and then sends nothing would loop for ever.
            if !more_follows || empty {
                return Ok(out);
            }
            if out.len() > self.limits.max_dataset_members * 64 {
                return Err(Error::LimitExceeded { limit: "FileDirectory continuations", value: out.len() });
            }
        }
    }

    /// Read a whole file off the server.
    ///
    /// `max_len` bounds what the caller is willing to hold; a file larger than it is an error
    /// rather than a surprise allocation, because the size a server reports is a number the
    /// server chose.
    pub fn read_file(&mut self, path: &str, max_len: usize) -> Result<Vec<u8>> {
        let name = FileNameBuf::from_path(path)?;
        let (frsm_id, size) = self.file_open(name.as_name(), 0)?;
        if size as usize > max_len {
            // Close it before refusing: the handle is already allocated on the server.
            let _ = self.file_close(frsm_id);
            return Err(Error::LimitExceeded { limit: "max_len", value: size as usize });
        }
        let out = self.read_open_file(frsm_id, max_len);
        // The close happens whatever the reads did. A leaked `frsmID` is a file descriptor
        // left open in an IED, and a client that gives up halfway is exactly when it happens.
        let closed = self.file_close(frsm_id);
        let data = out?;
        closed?;
        Ok(data)
    }

    /// Send `data` to the server, to be stored as `remote` (ACSI `SetFile`, MMS `ObtainFile`).
    ///
    /// The server fetches it from this client with `FileOpen`/`FileRead`/`FileClose` on the same
    /// association before it answers, so this call serves those requests while it waits — for
    /// this one file only, under the last component of `remote`, one handle at a time. Anything
    /// else the server asks for is refused. The call times out only when the server stops
    /// making progress, not when the transfer is merely long.
    ///
    /// # Errors
    /// [`Error::Service`] with the server's reason: `file [11]` `file-access-denied` when it does
    /// not accept files (the default), `duplicate-filename`, `insufficient-space-in-filestore`, …
    pub fn set_file(&mut self, remote: &str, data: &[u8]) -> Result<()> {
        let size = u32::try_from(data.len()).map_err(|_| Error::LimitExceeded { limit: "file size", value: data.len() })?;
        let name = remote.rsplit('/').next().unwrap_or(remote).to_string();
        self.obtain(name, Source::Bytes(data.to_vec()), size, remote)
    }

    /// Send the file at `local` to the server, to be stored as `remote`, reading it in chunks
    /// as the server asks. See [`Client::set_file`].
    ///
    /// # Errors
    /// As [`Client::set_file`], or the local file cannot be read.
    pub fn set_file_path(&mut self, local: &std::path::Path, remote: &str) -> Result<()> {
        let file = std::fs::File::open(local).map_err(|e| Error::Io(alloc::format!("{}: {e}", local.display())))?;
        let len = file.metadata().map_err(|e| Error::Io(e.to_string()))?.len();
        let size = u32::try_from(len).map_err(|_| Error::LimitExceeded { limit: "file size", value: usize::try_from(len).unwrap_or(usize::MAX) })?;
        let name = local.file_name().and_then(|n| n.to_str()).filter(|n| !n.is_empty()).unwrap_or("file").to_string();
        self.obtain(name, Source::File(file), size, remote)
    }

    fn obtain(&mut self, name: String, source: Source, size: u32, remote: &str) -> Result<()> {
        let source_name = FileNameBuf::from_path(&name)?;
        let destination = FileNameBuf::from_path(remote)?;
        self.serving = Some(Serving { name, source, size, open: None });
        let result = self.call(&ConfirmedRequest::ObtainFile { source_server: None, source: source_name.as_name(), destination: destination.as_name() });
        self.serving = None;
        match Mms::parse(&result?, &self.limits)? {
            Mms::ConfirmedResponse { service: ConfirmedResponse::ObtainFile, .. } => Ok(()),
            _ => Err(Error::InvalidValue("not an ObtainFile response")),
        }
    }

    /// Answer a confirmed request the server sent this client. During a `set_file` the file
    /// requests for its one source are served; everything else is refused, never ignored.
    pub(crate) fn answer_peer_request(&mut self, invoke_id: i64, pdu: &[u8]) -> Result<()> {
        let refuse_file = |code: i64| confirmed_error(invoke_id, service_error::FILE, code);
        let max_chunk = self.assoc.negotiated().map_or(512, |n| n.max_pdu).saturating_sub(64).max(64);
        let answer = match (Mms::parse(pdu, &self.limits), self.serving.as_mut()) {
            (Ok(Mms::ConfirmedRequest { service: ConfirmedRequest::FileOpen { name, position }, .. }), Some(s)) => {
                if s.open.is_some() || name.display() != s.name || position > s.size {
                    refuse_file(file_error::FILE_NON_EXISTENT)?
                } else {
                    s.open = Some((1, u64::from(position)));
                    let attributes = FileAttributes { size: s.size, last_modified: None };
                    Mms::ConfirmedResponse { invoke_id, service: ConfirmedResponse::FileOpen { frsm_id: 1, attributes } }.to_vec()?
                }
            }
            (Ok(Mms::ConfirmedRequest { service: ConfirmedRequest::FileRead(frsm), .. }), Some(s)) => match s.open {
                Some((id, offset)) if id == frsm => {
                    let data = s.source.read_at(offset, max_chunk)?;
                    let next = offset.saturating_add(data.len() as u64);
                    s.open = Some((id, next));
                    let more = next < u64::from(s.size) && !data.is_empty();
                    Mms::ConfirmedResponse { invoke_id, service: ConfirmedResponse::FileRead { data: &data, more_follows: more } }.to_vec()?
                }
                _ => refuse_file(file_error::OTHER)?,
            },
            (Ok(Mms::ConfirmedRequest { service: ConfirmedRequest::FileClose(frsm), .. }), Some(s)) => match s.open {
                Some((id, _)) if id == frsm => {
                    s.open = None;
                    Mms::ConfirmedResponse { invoke_id, service: ConfirmedResponse::FileClose }.to_vec()?
                }
                _ => refuse_file(file_error::OTHER)?,
            },
            // A file request outside a `set_file`: this client has no files to give.
            (
                Ok(Mms::ConfirmedRequest {
                    service: ConfirmedRequest::FileOpen { .. } | ConfirmedRequest::FileRead(_) | ConfirmedRequest::FileClose(_), ..
                }),
                None,
            ) => refuse_file(file_error::FILE_ACCESS_DENIED)?,
            // Any other service: a client implements none.
            _ => Reject {
                original_invoke_id: u32::try_from(invoke_id).ok().map(i64::from),
                reason: RejectReason::ConfirmedRequest(reject::UNRECOGNIZED_SERVICE),
            }
            .to_vec()?,
        };
        if self.serving.is_some() {
            self.progress = Some(std::time::Instant::now());
        }
        self.assoc.send_encoded(&answer)?;
        self.flush()
    }

    /// Delete a file.
    pub fn delete_file(&mut self, path: &str) -> Result<()> {
        let name = FileNameBuf::from_path(path)?;
        let pdu = self.call(&ConfirmedRequest::FileDelete(name.as_name()))?;
        match Mms::parse(&pdu, &self.limits)? {
            Mms::ConfirmedResponse { service: ConfirmedResponse::FileDelete, .. } => Ok(()),
            _ => Err(Error::InvalidValue("not a FileDelete response")),
        }
    }

    /// `FileOpen`: the handle and the size the server reports.
    fn file_open(&mut self, name: FileName<'_>, position: u32) -> Result<(i32, u32)> {
        let pdu = self.call(&ConfirmedRequest::FileOpen { name, position })?;
        match Mms::parse(&pdu, &self.limits)? {
            Mms::ConfirmedResponse { service: ConfirmedResponse::FileOpen { frsm_id, attributes }, .. } => Ok((frsm_id, attributes.size)),
            _ => Err(Error::InvalidValue("not a FileOpen response")),
        }
    }

    fn file_close(&mut self, frsm_id: i32) -> Result<()> {
        let pdu = self.call(&ConfirmedRequest::FileClose(frsm_id))?;
        match Mms::parse(&pdu, &self.limits)? {
            Mms::ConfirmedResponse { service: ConfirmedResponse::FileClose, .. } => Ok(()),
            _ => Err(Error::InvalidValue("not a FileClose response")),
        }
    }

    fn read_open_file(&mut self, frsm_id: i32, max_len: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let pdu = self.call(&ConfirmedRequest::FileRead(frsm_id))?;
            let Mms::ConfirmedResponse { service: ConfirmedResponse::FileRead { data, more_follows }, .. } = Mms::parse(&pdu, &self.limits)? else {
                return Err(Error::InvalidValue("not a FileRead response"));
            };
            if out.len().saturating_add(data.len()) > max_len {
                return Err(Error::LimitExceeded { limit: "max_len", value: out.len() + data.len() });
            }
            let empty = data.is_empty();
            out.extend_from_slice(data);
            // A server that says more follows and then sends nothing would loop for ever;
            // an empty chunk ends the file whatever the flag claims.
            if !more_follows || empty {
                return Ok(out);
            }
        }
    }
}
