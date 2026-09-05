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
use crate::common::{Error, Result};
use crate::proto::mms::file::{FileName, FileNameBuf};
use crate::proto::mms::{ConfirmedRequest, ConfirmedResponse, Mms};

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
