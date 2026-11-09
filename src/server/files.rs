//! File services, server side: a **sandboxed** store and the handle protocol over it.
//!
//! This is the service an IED exposes to hand a COMTRADE record to a SCADA system, and it is
//! the one with the worst safety record in the field: libiec61850's changelog lists a path
//! traversal here, and it is the obvious one — a client sends `../../etc/shadow` as a
//! `FileName` and a server that joins it onto a root directory serves it.
//!
//! So the sandbox is the type, not a check a caller might forget. [`DirectoryStore`] takes a
//! root and **every** path it accepts is validated the same way:
//!
//! - no absolute paths, no Windows drive letters, no UNC prefixes;
//! - no `..` component anywhere, before or after normalisation;
//! - the resolved path must still be inside the root, checked after following symlinks —
//!   because a symlink inside the root pointing out of it defeats every textual check.
//!
//! A path that fails any of them is *not found*, never an error that distinguishes "outside
//! the sandbox" from "does not exist": telling a client which is which is how a directory
//! structure gets mapped.
//!
//! A store may also **receive** files (ACSI `SetFile`), through [`FileStore::create`]. A
//! received file is written to a hidden temporary beside its destination, which no read,
//! listing or delete can see, and appears under its name only complete; an aborted transfer
//! leaves nothing behind.

use alloc::string::String;
use alloc::vec::Vec;

/// Why a store would not take a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileError {
    /// The store does not accept files there, or at all.
    Denied,
    /// The name is not one the store would ever create.
    Syntax,
    /// A file of that name exists and the store does not overwrite.
    Exists,
    /// The file, or the store with it, would exceed its limit.
    TooLarge,
    /// Writing failed.
    Io,
}

impl FileError {
    /// The ISO 9506 `file [11]` error code this is answered with.
    pub const fn mms_code(self) -> i64 {
        use crate::proto::mms::file_error;
        match self {
            FileError::Denied => file_error::FILE_ACCESS_DENIED,
            FileError::Syntax => file_error::FILENAME_SYNTAX_ERROR,
            FileError::Exists => file_error::DUPLICATE_FILENAME,
            FileError::TooLarge => file_error::INSUFFICIENT_SPACE,
            FileError::Io => file_error::OTHER,
        }
    }
}

/// A file being received. Dropping it without [`FileWriter::commit`] discards it.
pub trait FileWriter: Send {
    /// The size the sender declared; refused if it is more than the store would hold.
    ///
    /// # Errors
    /// [`FileError::TooLarge`].
    fn expect(&mut self, size: u32) -> Result<(), FileError>;
    /// Append the next chunk.
    ///
    /// # Errors
    /// [`FileError::TooLarge`] past the limit, [`FileError::Io`] when the write fails.
    fn write(&mut self, chunk: &[u8]) -> Result<(), FileError>;
    /// Make the file appear under its name, complete.
    ///
    /// # Errors
    /// [`FileError::Exists`] when a file of that name appeared meanwhile, [`FileError::Io`].
    fn commit(self: Box<Self>) -> Result<(), FileError>;
}

/// One file the server is willing to serve.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileInfo {
    /// The path, as a client names it — always relative and `/`-separated.
    pub name: String,
    /// Size in octets.
    pub size: u32,
    /// `lastModified` as a `GeneralizedTime` string, when the store knows one.
    pub modified: Option<String>,
}

/// Where a server's files come from.
///
/// Implement it to serve records out of a database, a ring buffer or a compressed archive;
/// [`DirectoryStore`] serves a directory, and [`NoFiles`] is the default, because an IED that
/// has no files should say so rather than expose a filesystem by accident.
/// The store is read in **ranges**, never whole. A `FileRead` hands a client one chunk at a
/// time, so a server that reads the whole file to serve the first chunk has made its memory
/// bound the *file* size rather than the chunk size — and a client that opens a 200 MB
/// COMTRADE record five times has then allocated a gigabyte of it. `read_at` is the shape
/// that makes an open cost nothing.
pub trait FileStore: core::fmt::Debug + Send + Sync {
    /// Files matching `spec` — a directory prefix, or everything when `None`.
    fn list(&self, spec: Option<&str>) -> Vec<FileInfo>;
    /// What the store knows about one file, or `None` when there is no such file.
    fn info(&self, path: &str) -> Option<FileInfo>;
    /// Up to `len` octets of `path` from `offset`.
    ///
    /// A short answer means end of file; `None` means there is no such file (any more). The
    /// caller never asks for more than one `FileRead` carries, so an implementation may read
    /// exactly what was asked for and nothing else.
    fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>>;
    /// Delete `path`; `false` when it does not exist or may not be deleted.
    fn delete(&self, path: &str) -> bool {
        let _ = path;
        false
    }
    /// Start receiving a file to be stored as `path`. The default refuses: a store takes files
    /// only when it says so.
    ///
    /// # Errors
    /// Why it will not.
    fn create(&self, path: &str) -> Result<Box<dyn FileWriter>, FileError> {
        let _ = path;
        Err(FileError::Denied)
    }
}

/// A server with no files. The default, deliberately.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFiles;

impl FileStore for NoFiles {
    fn list(&self, _spec: Option<&str>) -> Vec<FileInfo> {
        Vec::new()
    }

    fn info(&self, _path: &str) -> Option<FileInfo> {
        None
    }

    fn read_at(&self, _path: &str, _offset: u64, _len: usize) -> Option<Vec<u8>> {
        None
    }
}

/// A [`FileStore`] over one directory, sandboxed to it.
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct DirectoryStore {
    root: std::path::PathBuf,
    writable: bool,
    overwrite: bool,
    max_file_size: u64,
    max_total_size: u64,
}

/// The default ceiling on one received file: 16 MiB.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 16 << 20;
/// The default ceiling on everything a [`DirectoryStore`] holds once a file is received: 256 MiB.
pub const DEFAULT_MAX_TOTAL_SIZE: u64 = 256 << 20;
/// The prefix of a file being received. Nothing a client names can start with a dot.
#[cfg(feature = "std")]
const INCOMING: &str = ".iec61850-incoming-";

#[cfg(feature = "std")]
impl DirectoryStore {
    /// Serve `root`, read-only.
    pub fn new(root: impl Into<std::path::PathBuf>) -> DirectoryStore {
        DirectoryStore { root: root.into(), writable: false, overwrite: false, max_file_size: DEFAULT_MAX_FILE_SIZE, max_total_size: DEFAULT_MAX_TOTAL_SIZE }
    }

    /// Allow `FileDelete` and receiving files (`SetFile`) as well as reading.
    #[must_use]
    pub fn writable(mut self) -> DirectoryStore {
        self.writable = true;
        self
    }

    /// Let a received file replace an existing one (atomically). Off by default: a `SetFile`
    /// naming an existing file is refused `duplicate-filename`.
    #[must_use]
    pub fn allow_overwrite(mut self) -> DirectoryStore {
        self.overwrite = true;
        self
    }

    /// The largest file it receives, and the most it holds in all once one is received.
    #[must_use]
    pub fn with_limits(mut self, max_file_size: u64, max_total_size: u64) -> DirectoryStore {
        self.max_file_size = max_file_size;
        self.max_total_size = max_total_size;
        self
    }

    /// The octets every file under the root takes, bounded the way a listing is.
    fn total_size(&self) -> u64 {
        let mut all = Vec::new();
        self.walk(&self.root, &mut all, 0);
        all.iter().map(|f| u64::from(f.size)).sum()
    }

    /// Resolve a client's path inside the sandbox, or `None`.
    ///
    /// The textual checks come first because they are cheap and catch the obvious attack; the
    /// canonicalised containment check comes second because it is the only one that survives a
    /// symlink. Both have to pass.
    fn resolve(&self, path: &str) -> Option<std::path::PathBuf> {
        // Nothing a client names starts with a dot, which keeps a file being received — and
        // anything else hidden — out of every read, listing and delete.
        if !is_safe_relative(path) || path.split('/').any(|part| part.starts_with('.')) {
            return None;
        }
        let joined = self.root.join(path);
        let real = joined.canonicalize().ok()?;
        let root = self.root.canonicalize().ok()?;
        real.starts_with(&root).then_some(real)
    }

    /// The path a client would name a file under the root by.
    fn relative(&self, path: &std::path::Path) -> Option<String> {
        let root = self.root.canonicalize().ok()?;
        let rest = path.strip_prefix(&root).ok()?;
        let mut out = String::new();
        for part in rest.components() {
            let std::path::Component::Normal(name) = part else { return None };
            if !out.is_empty() {
                out.push('/');
            }
            out.push_str(name.to_str()?);
        }
        Some(out)
    }

    fn walk(&self, dir: &std::path::Path, out: &mut Vec<FileInfo>, depth: usize) {
        // A directory tree deep enough to recurse into for ever is a directory tree an
        // attacker made, and the answer has to fit one association's memory anyway.
        if depth > 8 || out.len() > 4096 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                self.walk(&path, out, depth + 1);
            } else if meta.is_file() {
                // Only through the sandbox, so a symlink out of the root is not listed even
                // though it is inside the directory being walked.
                let Some(real) = path.canonicalize().ok().filter(|p| self.resolve_ok(p)) else { continue };
                let Some(name) = self.relative(&real) else { continue };
                out.push(FileInfo { name, size: u32::try_from(meta.len()).unwrap_or(u32::MAX), modified: modified_of(&meta) });
            }
        }
    }

    fn resolve_ok(&self, real: &std::path::Path) -> bool {
        self.root.canonicalize().is_ok_and(|root| real.starts_with(&root))
    }
}

#[cfg(feature = "std")]
impl FileStore for DirectoryStore {
    fn list(&self, spec: Option<&str>) -> Vec<FileInfo> {
        let start = match spec {
            None | Some("") => self.root.clone(),
            Some(prefix) => match self.resolve(prefix) {
                Some(p) => p,
                None => return Vec::new(),
            },
        };
        let mut out = Vec::new();
        if start.is_file() {
            if let (Ok(meta), Some(name)) = (std::fs::metadata(&start), self.relative(&start)) {
                out.push(FileInfo { name, size: u32::try_from(meta.len()).unwrap_or(u32::MAX), modified: modified_of(&meta) });
            }
        } else {
            self.walk(&start, &mut out, 0);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    fn info(&self, path: &str) -> Option<FileInfo> {
        let real = self.resolve(path)?;
        let meta = std::fs::metadata(&real).ok()?;
        if !meta.is_file() {
            return None;
        }
        Some(FileInfo { name: self.relative(&real)?, size: u32::try_from(meta.len()).unwrap_or(u32::MAX), modified: modified_of(&meta) })
    }

    fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let real = self.resolve(path)?;
        if !real.is_file() {
            return None;
        }
        let mut file = std::fs::File::open(real).ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        // `len` is one `FileRead` chunk, which the server configures; the buffer is that
        // size and never the file's, which is the whole point of reading in ranges.
        let mut buf = alloc::vec![0u8; len];
        let mut filled = 0usize;
        while filled < len {
            match file.read(buf.get_mut(filled..)?) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        buf.truncate(filled);
        Some(buf)
    }

    fn delete(&self, path: &str) -> bool {
        if !self.writable {
            return false;
        }
        self.resolve(path).is_some_and(|real| real.is_file() && std::fs::remove_file(real).is_ok())
    }

    fn create(&self, path: &str) -> Result<Box<dyn FileWriter>, FileError> {
        if !self.writable {
            return Err(FileError::Denied);
        }
        if !is_safe_relative(path) || path.split('/').any(|part| part.starts_with('.')) {
            return Err(FileError::Syntax);
        }
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        // The directory must already exist and be inside the root after every symlink is
        // followed; the file itself is created below, exclusively, so no link is followed there.
        let root = self.root.canonicalize().map_err(|_| FileError::Denied)?;
        let dir = root.join(parent).canonicalize().map_err(|_| FileError::Denied)?;
        if !dir.starts_with(&root) || !dir.is_dir() {
            return Err(FileError::Denied);
        }
        let dest = dir.join(name);
        match std::fs::symlink_metadata(&dest) {
            Ok(_) if !self.overwrite => return Err(FileError::Exists),
            Ok(meta) if !meta.file_type().is_file() => return Err(FileError::Denied),
            _ => {}
        }
        let total = self.total_size();
        if total >= self.max_total_size {
            return Err(FileError::TooLarge);
        }
        let (file, temp) = create_incoming(&dir)?;
        Ok(Box::new(Incoming {
            file: Some(file),
            temp,
            dest,
            written: 0,
            limit: self.max_file_size.min(self.max_total_size - total),
            overwrite: self.overwrite,
            done: false,
        }))
    }
}

/// Create a fresh hidden temporary in `dir`: exclusively (no existing name, no symlink, is
/// followed) and readable by its owner only.
#[cfg(feature = "std")]
fn create_incoming(dir: &std::path::Path) -> Result<(std::fs::File, std::path::PathBuf), FileError> {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let temp = dir.join(alloc::format!("{INCOMING}{}-{n}", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp) {
            Ok(file) => return Ok((file, temp)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(FileError::Io),
        }
    }
    Err(FileError::Io)
}

/// A file being received into a [`DirectoryStore`].
#[cfg(feature = "std")]
#[derive(Debug)]
struct Incoming {
    file: Option<std::fs::File>,
    temp: std::path::PathBuf,
    dest: std::path::PathBuf,
    written: u64,
    limit: u64,
    overwrite: bool,
    done: bool,
}

#[cfg(feature = "std")]
impl FileWriter for Incoming {
    fn expect(&mut self, size: u32) -> Result<(), FileError> {
        if u64::from(size) > self.limit { Err(FileError::TooLarge) } else { Ok(()) }
    }

    fn write(&mut self, chunk: &[u8]) -> Result<(), FileError> {
        use std::io::Write;
        let written = self.written.saturating_add(chunk.len() as u64);
        if written > self.limit {
            return Err(FileError::TooLarge);
        }
        self.file.as_mut().ok_or(FileError::Io)?.write_all(chunk).map_err(|_| FileError::Io)?;
        self.written = written;
        Ok(())
    }

    fn commit(mut self: Box<Self>) -> Result<(), FileError> {
        let file = self.file.take().ok_or(FileError::Io)?;
        file.sync_all().map_err(|_| FileError::Io)?;
        drop(file);
        if self.overwrite {
            // A rename replaces the name atomically: a reader sees the old file or the new one.
            std::fs::rename(&self.temp, &self.dest).map_err(|_| FileError::Io)?;
        } else {
            // A link fails on any existing name, including one a case-insensitive file system
            // considers equal — which is what makes "never overwrite" hold under a race too.
            std::fs::hard_link(&self.temp, &self.dest)
                .map_err(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { FileError::Exists } else { FileError::Io })?;
            let _ = std::fs::remove_file(&self.temp);
        }
        self.done = true;
        Ok(())
    }
}

#[cfg(feature = "std")]
impl Drop for Incoming {
    fn drop(&mut self) {
        if !self.done {
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

/// A `GeneralizedTime` for a file's modification time, or `None` when the platform will not
/// say. The format is `YYYYMMDDhhmmssZ`, which is what MMS `FileAttributes` carries.
#[cfg(feature = "std")]
fn modified_of(meta: &std::fs::Metadata) -> Option<String> {
    let secs = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    let t = crate::common::UtcTime::from_unix(u32::try_from(secs).ok()?, 0, crate::common::TimeQuality::UNSYNCHRONIZED);
    // `UtcTime`'s display is ISO-8601 with separators; `GeneralizedTime` has none.
    let iso = alloc::format!("{t}");
    let digits: String = iso.chars().filter(char::is_ascii_digit).take(14).collect();
    (digits.len() == 14).then(|| alloc::format!("{digits}Z"))
}

/// Whether a client's path is a relative path with no way out of a sandbox.
///
/// Deliberately strict and textual: a path that is *not obviously safe* is refused rather than
/// normalised into something that looks safe. Normalising is how `..%2f` and `a/../../b` get
/// through.
pub fn is_safe_relative(path: &str) -> bool {
    if path.is_empty() || path.len() > 255 {
        return false;
    }
    // No absolute paths, no drive letters, no UNC.
    if path.starts_with('/') || path.starts_with('\\') || path.get(1..2) == Some(":") {
        return false;
    }
    // A backslash is a separator on one platform and a legal filename character on another,
    // which is exactly the ambiguity a traversal exploits.
    if path.contains('\\') || path.contains('\0') {
        return false;
    }
    path.split('/').all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains(':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_that_could_leave_the_sandbox_is_refused_rather_than_normalised() {
        for good in ["COMTRADE/rec0001.cfg", "a", "a/b/c.dat", "file.with.dots"] {
            assert!(is_safe_relative(good), "`{good}` is an ordinary path");
        }
        for bad in
            ["", "/etc/shadow", "../etc/shadow", "COMTRADE/../../etc/shadow", "a/./b", "a//b", "C:/windows", "\\\\server\\share", "a\\b", "a\0b", "..", "."]
        {
            assert!(!is_safe_relative(bad), "`{bad}` must not be accepted");
        }
        // Length is bounded too: a path a client chose the length of is a path an
        // implementation somewhere has a fixed buffer for.
        assert!(!is_safe_relative(&"a".repeat(256)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn a_directory_store_serves_only_what_is_under_its_root() {
        let dir = std::env::temp_dir().join(alloc::format!("iec61850-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("COMTRADE")).expect("create");
        std::fs::write(dir.join("COMTRADE/rec0001.cfg"), b"STATION,IED1,2013\n").expect("write");
        std::fs::write(dir.join("top.txt"), b"hello").expect("write");
        // A file next to the root, which a traversal would reach.
        let outside = dir.parent().map(|p| p.join("outside.txt"));
        if let Some(p) = &outside {
            let _ = std::fs::write(p, b"secret");
        }

        let store = DirectoryStore::new(&dir);
        let names: Vec<String> = store.list(None).into_iter().map(|f| f.name).collect();
        assert_eq!(names, ["COMTRADE/rec0001.cfg", "top.txt"]);
        assert_eq!(store.read_at("COMTRADE/rec0001.cfg", 0, 64).as_deref(), Some(&b"STATION,IED1,2013\n"[..]));
        assert_eq!(store.info("COMTRADE/rec0001.cfg").map(|f| f.size), Some(18));
        assert_eq!(store.list(Some("COMTRADE")).len(), 1);

        // Every shape of traversal reads as "not found", and never as a different error: a
        // client that can tell the two apart can map the filesystem.
        for escape in ["../outside.txt", "COMTRADE/../../outside.txt", "/etc/hosts", "..%2foutside.txt"] {
            assert!(store.read_at(escape, 0, 64).is_none(), "`{escape}` escaped the sandbox");
            assert!(store.info(escape).is_none(), "`{escape}` escaped the sandbox");
            let v = store.list(Some(escape));
            assert!(v.is_empty(), "{v:?}");
        }
        // Read-only by default: a client cannot delete a record an operator has not agreed
        // to lose.
        assert!(!store.delete("top.txt"));
        assert!(DirectoryStore::new(&dir).writable().delete("top.txt"));
        assert!(store.read_at("top.txt", 0, 64).is_none());

        let _ = std::fs::remove_dir_all(&dir);
        if let Some(p) = &outside {
            let _ = std::fs::remove_file(p);
        }
    }

    /// A store is read in ranges so that a `FileRead` costs one chunk, not one file. The
    /// ranges have to tile the file exactly: a short read means end of file and nothing else,
    /// and an offset past the end is empty rather than an error.
    #[test]
    fn a_range_read_tiles_the_file_and_stops_at_its_end() {
        let dir = std::env::temp_dir().join(alloc::format!("iec61850-ranges-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create");
        let body: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        std::fs::write(dir.join("rec.dat"), &body).expect("write");
        let store = DirectoryStore::new(&dir);

        assert_eq!(store.info("rec.dat").map(|f| f.size), Some(1000));
        let mut got = Vec::new();
        let mut at = 0u64;
        loop {
            let chunk = store.read_at("rec.dat", at, 256).expect("read");
            if chunk.is_empty() {
                break;
            }
            at += chunk.len() as u64;
            got.extend_from_slice(&chunk);
        }
        assert_eq!(got, body, "the ranges reassemble the file exactly");
        // The last range is short, which is how end-of-file is signalled.
        assert_eq!(store.read_at("rec.dat", 768, 256).map(|c| c.len()), Some(232));
        // Past the end is empty, not an error: a client resuming a transfer of a file that
        // shrank has to get a clean end rather than a fault.
        assert_eq!(store.read_at("rec.dat", 5000, 256).map(|c| c.len()), Some(0));
        assert!(store.read_at("missing.dat", 0, 8).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "std")]
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(alloc::format!("iec61850-incoming-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("SETTINGS")).expect("create");
        dir
    }

    /// A received file appears complete under its name, and a dropped one leaves nothing.
    #[cfg(feature = "std")]
    #[test]
    fn a_received_file_appears_whole_or_not_at_all() {
        let dir = scratch("whole");
        let store = DirectoryStore::new(&dir).writable();
        let mut w = store.create("SETTINGS/a.xml").expect("create");
        w.expect(10).unwrap();
        w.write(b"hello").unwrap();
        // While it is being written, nothing is visible: not the name, not the temporary.
        assert!(store.list(None).is_empty(), "{:?}", store.list(None));
        assert!(store.info("SETTINGS/a.xml").is_none());
        w.write(b"world").unwrap();
        w.commit().unwrap();
        assert_eq!(store.read_at("SETTINGS/a.xml", 0, 64).as_deref(), Some(&b"helloworld"[..]));

        let mut w = store.create("SETTINGS/b.xml").expect("create");
        w.write(b"partial").unwrap();
        drop(w);
        let left: Vec<_> = std::fs::read_dir(dir.join("SETTINGS")).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, ["a.xml"], "an abandoned transfer leaves no file and no temporary");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "std")]
    #[test]
    fn a_store_refuses_every_destination_it_should() {
        let dir = scratch("refuse");
        std::fs::write(dir.join("SETTINGS/existing.xml"), b"keep").unwrap();
        assert_eq!(DirectoryStore::new(&dir).create("SETTINGS/x").err(), Some(FileError::Denied), "read-only by default");
        let store = DirectoryStore::new(&dir).writable().with_limits(8, 1 << 20);
        for bad in ["../x", "/etc/x", "a\\b", "SETTINGS/.hidden", ".ssh/authorized_keys", "SETTINGS/../x", "C:/x", "a\0b"] {
            assert_eq!(store.create(bad).err(), Some(FileError::Syntax), "{bad}");
        }
        assert_eq!(store.create("MISSING/x").err(), Some(FileError::Denied), "the directory must exist");
        assert_eq!(store.create("SETTINGS/existing.xml").err(), Some(FileError::Exists));
        let mut w = store.create("SETTINGS/big").unwrap();
        assert_eq!(w.expect(9), Err(FileError::TooLarge));
        assert_eq!(w.write(b"123456789"), Err(FileError::TooLarge), "the limit holds on what arrives too");
        drop(w);
        assert_eq!(std::fs::read(dir.join("SETTINGS/existing.xml")).unwrap(), b"keep");

        // With overwrite, the existing file is replaced whole.
        let store = DirectoryStore::new(&dir).writable().allow_overwrite();
        let mut w = store.create("SETTINGS/existing.xml").unwrap();
        w.write(b"new").unwrap();
        w.commit().unwrap();
        assert_eq!(std::fs::read(dir.join("SETTINGS/existing.xml")).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file of the same name appearing during the transfer is not overwritten: the link fails.
    #[cfg(feature = "std")]
    #[test]
    fn a_name_taken_during_the_transfer_is_not_overwritten() {
        let dir = scratch("race");
        let store = DirectoryStore::new(&dir).writable();
        let mut w = store.create("SETTINGS/r.xml").unwrap();
        w.write(b"late").unwrap();
        std::fs::write(dir.join("SETTINGS/r.xml"), b"first").unwrap();
        assert_eq!(w.commit(), Err(FileError::Exists));
        assert_eq!(std::fs::read(dir.join("SETTINGS/r.xml")).unwrap(), b"first");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A symlink inside the root pointing out of it cannot carry a received file out.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_cannot_carry_a_file_out_of_the_root() {
        let dir = scratch("link");
        let outside = std::env::temp_dir().join(alloc::format!("iec61850-outside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("escape")).unwrap();
        let store = DirectoryStore::new(&dir).writable();
        assert_eq!(store.create("escape/payload").err(), Some(FileError::Denied));
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "nothing was created outside the root");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// The whole store is bounded, not only each file.
    #[cfg(feature = "std")]
    #[test]
    fn the_store_as_a_whole_is_bounded() {
        let dir = scratch("quota");
        std::fs::write(dir.join("SETTINGS/one"), [0u8; 600]).unwrap();
        let store = DirectoryStore::new(&dir).writable().with_limits(1000, 1000);
        let mut w = store.create("SETTINGS/two").unwrap();
        assert_eq!(w.expect(500), Err(FileError::TooLarge), "600 held + 500 > 1000");
        assert!(w.expect(400).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
