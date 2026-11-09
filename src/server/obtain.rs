//! `ObtainFile`, the server side of ACSI `SetFile`: the one service where the **server** calls
//! the client.
//!
//! A client asks the server to fetch a file from it. The server then opens, reads and closes
//! that file on the client with `FileOpen`, `FileRead` and `FileClose` on the same association,
//! writes it into its store, and only then answers the `ObtainFile` ✅ (ISO 9506-2,
//! `mms.asn`; the order is libiec61850's `mmsServer_fileUploadTask` 🌐).
//!
//! [`Obtains`] is that sequence as a state machine, sans-IO like the rest of the server: it
//! says which request to issue next, takes the answers as they arrive, and says when the
//! `ObtainFile` is answered and with what. The connection loop does the I/O, so a client that
//! answers slowly — or never — holds only its own transfer, never the loop and never another
//! association. Every transfer is bounded: one per association, a server-wide count, a deadline
//! for the whole of it, and the store's own size limits on what is declared and what arrives.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::acsi::AssocId;
use super::files::{FileError, FileWriter};
use crate::common::Instant;
use crate::proto::mms::file::FileNameBuf;
use crate::proto::mms::{ConfirmedRequest, ConfirmedResponse, Mms, ServiceError, file_error, obtain_file_error, service_error};

/// How an `ObtainFile` ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The file is in the store.
    Stored,
    /// It is not, and this is the `ServiceError` the `ObtainFile` is answered with.
    Failed(Refusal),
}

/// A refused or failed `ObtainFile`: the `errorClass`, its code, and which side failed
/// ([`obtain_file_error`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The `errorClass` choice tag.
    pub class: u32,
    /// The code inside it.
    pub code: i64,
    /// [`obtain_file_error::SOURCE_FILE`] or [`obtain_file_error::DESTINATION_FILE`].
    pub side: i64,
}

impl Refusal {
    /// A `file [11]` error on the destination (this server's store).
    pub const fn destination(code: i64) -> Refusal {
        Refusal { class: service_error::FILE, code, side: obtain_file_error::DESTINATION_FILE }
    }

    /// A `file [11]` error on the source (the client).
    pub const fn source(code: i64) -> Refusal {
        Refusal { class: service_error::FILE, code, side: obtain_file_error::SOURCE_FILE }
    }

    /// The store's refusal, as the destination error it is answered with.
    pub const fn from_store(e: FileError) -> Refusal {
        Refusal::destination(e.mms_code())
    }
}

/// Where a transfer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// `FileOpen` is to be sent, or has been.
    Open,
    /// The file is open as this `frsmID`; `FileRead` is next.
    Read(i32),
    /// `FileClose` is to be sent, or has been; the transfer then ends.
    Close(i32),
}

/// One transfer, on one association.
struct Transfer {
    /// The client's `ObtainFile`, which is answered at the end. `None` until the connection
    /// loop says which invoke it was.
    obtain_invoke: Option<i64>,
    source: FileNameBuf,
    writer: Option<Box<dyn FileWriter>>,
    stage: Stage,
    /// The request in flight, once issued.
    waiting: Option<i64>,
    /// Whether the next request is still to be issued.
    pending: bool,
    declared: u64,
    received: u64,
    deadline: Instant,
    /// Set once something went wrong; the transfer then only closes and answers this.
    failure: Option<Refusal>,
}

impl core::fmt::Debug for Transfer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Transfer")
            .field("stage", &self.stage)
            .field("waiting", &self.waiting)
            .field("declared", &self.declared)
            .field("received", &self.received)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

/// Every `ObtainFile` in progress on a server.
#[derive(Debug)]
pub struct Obtains {
    transfers: BTreeMap<AssocId, Transfer>,
    max: usize,
    timeout_ms: u64,
}

/// What a transfer that just ended is answered with: the client's invoke, and the outcome.
pub type Finished = (AssocId, i64, Outcome);

impl Obtains {
    /// At most `max` transfers at once, server-wide, each finished within `timeout_ms`.
    pub fn new(max: usize, timeout_ms: u64) -> Obtains {
        Obtains { transfers: BTreeMap::new(), max, timeout_ms }
    }

    /// Whether a new transfer may start on `assoc`: one per association, `max` in all.
    ///
    /// # Errors
    /// `file-busy` on the destination.
    pub fn admit(&self, assoc: AssocId) -> Result<(), Refusal> {
        if self.transfers.contains_key(&assoc) || self.transfers.len() >= self.max {
            return Err(Refusal::destination(file_error::FILE_BUSY));
        }
        Ok(())
    }

    /// Start fetching `source` from the client on `assoc` into `writer`. [`Obtains::admit`]
    /// must have said yes.
    pub fn start(&mut self, assoc: AssocId, source: FileNameBuf, writer: Box<dyn FileWriter>, now: Instant) {
        self.transfers.insert(
            assoc,
            Transfer {
                obtain_invoke: None,
                source,
                writer: Some(writer),
                stage: Stage::Open,
                waiting: None,
                pending: true,
                declared: 0,
                received: 0,
                deadline: now.plus_millis(self.timeout_ms),
                failure: None,
            },
        );
    }

    /// Record which invoke the client's `ObtainFile` was, so the end of the transfer can answer
    /// it.
    pub fn bind(&mut self, assoc: AssocId, obtain_invoke: i64) {
        if let Some(t) = self.transfers.get_mut(&assoc) {
            t.obtain_invoke = Some(obtain_invoke);
        }
    }

    /// The request to issue toward the client on `assoc` now, if any.
    pub fn next_call(&self, assoc: AssocId) -> Option<ConfirmedRequest<'_>> {
        let t = self.transfers.get(&assoc)?;
        if !t.pending || t.waiting.is_some() {
            return None;
        }
        Some(match t.stage {
            Stage::Open => ConfirmedRequest::FileOpen { name: t.source.as_name(), position: 0 },
            Stage::Read(frsm) => ConfirmedRequest::FileRead(frsm),
            Stage::Close(frsm) => ConfirmedRequest::FileClose(frsm),
        })
    }

    /// The request [`Obtains::next_call`] named was issued as `invoke`.
    pub fn issued(&mut self, assoc: AssocId, invoke: i64) {
        if let Some(t) = self.transfers.get_mut(&assoc) {
            t.waiting = Some(invoke);
            t.pending = false;
        }
    }

    /// The request could not be issued, timed out, or its answer did not decode. The client is
    /// no longer a reliable peer for this transfer, so it ends without a `FileClose`.
    pub fn failed(&mut self, assoc: AssocId, invoke: Option<i64>) -> Option<Finished> {
        let t = self.transfers.get(&assoc)?;
        if invoke.is_some() && t.waiting != invoke {
            return None;
        }
        self.finish(assoc, Some(Refusal::source(file_error::OTHER)))
    }

    /// The client answered `invoke` with `pdu`.
    pub fn on_response(&mut self, assoc: AssocId, invoke: i64, pdu: &Mms<'_>) -> Option<Finished> {
        let t = self.transfers.get_mut(&assoc)?;
        if t.waiting != Some(invoke) {
            return None;
        }
        t.waiting = None;
        let error = match pdu {
            Mms::ConfirmedError { error, .. } => Some(ServiceError::parse(error).unwrap_or_default()),
            _ => None,
        };
        let service = match pdu {
            Mms::ConfirmedResponse { service, .. } => Some(service),
            _ => None,
        };
        match (t.stage, service, error) {
            (Stage::Open, Some(ConfirmedResponse::FileOpen { frsm_id, attributes }), _) => {
                t.stage = Stage::Read(*frsm_id);
                t.declared = u64::from(attributes.size);
                if let Err(e) = t.writer.as_mut().map_or(Ok(()), |w| w.expect(attributes.size)) {
                    t.failure = Some(Refusal::from_store(e));
                    t.stage = Stage::Close(*frsm_id);
                }
            }
            // The client could not open its own file: nothing is open, so nothing is closed.
            (Stage::Open, _, Some(e)) => {
                let code = if e.class == service_error::FILE { e.code } else { file_error::FILE_NON_EXISTENT };
                return self.finish(assoc, Some(Refusal::source(code)));
            }
            (Stage::Read(frsm), Some(ConfirmedResponse::FileRead { data, more_follows }), _) => {
                t.received = t.received.saturating_add(data.len() as u64);
                if t.received > t.declared {
                    // More than the client said the file holds: not truncated silently.
                    t.failure = Some(Refusal::source(file_error::POSITION_INVALID));
                    t.stage = Stage::Close(frsm);
                } else if let Err(e) = t.writer.as_mut().map_or(Ok(()), |w| w.write(data)) {
                    t.failure = Some(Refusal::from_store(e));
                    t.stage = Stage::Close(frsm);
                } else if !*more_follows {
                    if t.received != t.declared {
                        t.failure = Some(Refusal::source(file_error::POSITION_INVALID));
                    }
                    t.stage = Stage::Close(frsm);
                }
            }
            (Stage::Read(frsm), _, _) => {
                t.failure = Some(Refusal::source(file_error::OTHER));
                t.stage = Stage::Close(frsm);
            }
            // Whatever the client answers to `FileClose`, the transfer is over.
            (Stage::Close(_), _, _) => {
                let failure = t.failure;
                return self.finish(assoc, failure);
            }
            (Stage::Open, _, None) => return self.finish(assoc, Some(Refusal::source(file_error::OTHER))),
        }
        t.pending = true;
        None
    }

    /// Transfers past their deadline end now; a client that stalls fails only its own.
    pub fn on_timeout(&mut self, now: Instant) -> Vec<Finished> {
        let late: Vec<AssocId> = self.transfers.iter().filter(|(_, t)| now >= t.deadline).map(|(a, _)| *a).collect();
        let timeout = Refusal { class: service_error::SERVICE_PREEMPT, code: service_error::TIMEOUT, side: obtain_file_error::SOURCE_FILE };
        late.into_iter().filter_map(|assoc| self.finish(assoc, Some(timeout))).collect()
    }

    /// The association ended: its transfer, if any, is discarded and nothing is answered.
    pub fn on_closed(&mut self, assoc: AssocId) {
        self.transfers.remove(&assoc);
    }

    /// The earliest deadline.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.transfers.values().map(|t| t.deadline).min()
    }

    /// How many transfers are in progress.
    pub fn len(&self) -> usize {
        self.transfers.len()
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.transfers.is_empty()
    }

    /// End `assoc`'s transfer: commit the file on success, discard it otherwise.
    fn finish(&mut self, assoc: AssocId, failure: Option<Refusal>) -> Option<Finished> {
        let mut t = self.transfers.remove(&assoc)?;
        let outcome = match (failure, t.writer.take()) {
            (None, Some(writer)) => match writer.commit() {
                Ok(()) => Outcome::Stored,
                Err(e) => Outcome::Failed(Refusal::from_store(e)),
            },
            (None, None) => Outcome::Failed(Refusal::destination(file_error::OTHER)),
            (Some(refusal), _) => Outcome::Failed(refusal),
        };
        // A transfer whose ObtainFile invoke was never bound answers nothing: the request it
        // would answer was never acknowledged as deferred.
        Some((assoc, t.obtain_invoke?, outcome))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;

    use super::*;
    use crate::common::Limits;
    use crate::proto::mms::file::FileAttributes;

    /// A writer that records into shared memory, with a size limit.
    #[derive(Clone, Default)]
    struct Memory(Arc<std::sync::Mutex<(Vec<u8>, bool)>>, u64);

    impl FileWriter for Memory {
        fn expect(&mut self, size: u32) -> Result<(), FileError> {
            if u64::from(size) > self.1 { Err(FileError::TooLarge) } else { Ok(()) }
        }
        fn write(&mut self, chunk: &[u8]) -> Result<(), FileError> {
            let mut g = self.0.lock().map_err(|_| FileError::Io)?;
            if g.0.len() as u64 + chunk.len() as u64 > self.1 {
                return Err(FileError::TooLarge);
            }
            g.0.extend_from_slice(chunk);
            Ok(())
        }
        fn commit(self: Box<Self>) -> Result<(), FileError> {
            self.0.lock().map_err(|_| FileError::Io)?.1 = true;
            Ok(())
        }
    }

    fn open(size: u32) -> Vec<u8> {
        Mms::ConfirmedResponse { invoke_id: 0, service: ConfirmedResponse::FileOpen { frsm_id: 5, attributes: FileAttributes { size, last_modified: None } } }
            .to_vec()
            .unwrap()
    }
    fn read(data: &[u8], more: bool) -> Vec<u8> {
        Mms::ConfirmedResponse { invoke_id: 0, service: ConfirmedResponse::FileRead { data, more_follows: more } }.to_vec().unwrap()
    }
    fn close() -> Vec<u8> {
        Mms::ConfirmedResponse { invoke_id: 0, service: ConfirmedResponse::FileClose }.to_vec().unwrap()
    }

    /// Drive one transfer through `answers`, one per issued request; what it finished with.
    fn drive(engine: &mut Obtains, answers: &[Vec<u8>]) -> (Vec<String>, Option<Finished>) {
        let mut calls = Vec::new();
        for (n, answer) in answers.iter().enumerate() {
            let Some(call) = engine.next_call(1) else { break };
            calls.push(alloc::format!("{call:?}").split([' ', '(', '{']).next().unwrap_or("").into());
            let invoke = 100 + i64::try_from(n).unwrap();
            engine.issued(1, invoke);
            let pdu = Mms::parse(answer, &Limits::DEFAULT).unwrap();
            if let Some(done) = engine.on_response(1, invoke, &pdu) {
                return (calls, Some(done));
            }
        }
        (calls, None)
    }

    fn started(limit: u64) -> (Obtains, Memory) {
        let mut engine = Obtains::new(2, 1000);
        let memory = Memory(Arc::default(), limit);
        engine.start(1, FileNameBuf::from_path("local.xml").unwrap(), Box::new(memory.clone()), Instant(0));
        engine.bind(1, 7);
        (engine, memory)
    }

    #[test]
    fn a_transfer_opens_reads_closes_and_stores() {
        let (mut engine, memory) = started(100);
        let (calls, done) = drive(&mut engine, &[open(6), read(b"abc", true), read(b"def", false), close()]);
        assert_eq!(calls, ["FileOpen", "FileRead", "FileRead", "FileClose"]);
        assert_eq!(done, Some((1, 7, Outcome::Stored)));
        assert_eq!(*memory.0.lock().unwrap(), (b"abcdef".to_vec(), true));
        assert!(engine.is_empty());
    }

    #[test]
    fn a_declared_size_over_the_limit_is_refused_before_any_read() {
        let (mut engine, memory) = started(4);
        let (calls, done) = drive(&mut engine, &[open(6), close()]);
        assert_eq!(calls, ["FileOpen", "FileClose"], "closed, never read");
        assert_eq!(done, Some((1, 7, Outcome::Failed(Refusal::destination(file_error::INSUFFICIENT_SPACE)))));
        assert!(!memory.0.lock().unwrap().1, "nothing committed");
    }

    #[test]
    fn more_data_than_declared_fails_the_transfer() {
        let (mut engine, _) = started(100);
        let (_, done) = drive(&mut engine, &[open(2), read(b"abc", false), close()]);
        assert_eq!(done, Some((1, 7, Outcome::Failed(Refusal::source(file_error::POSITION_INVALID)))));
    }

    #[test]
    fn a_client_that_cannot_open_its_file_ends_the_transfer_without_a_close() {
        let (mut engine, _) = started(100);
        let encoded = ServiceError::encode(crate::ber::Tag::context_constructed(2), 11, file_error::FILE_NON_EXISTENT).unwrap();
        let error = crate::ber::Cursor::new(&encoded).next_required().unwrap();
        let pdu = Mms::ConfirmedError { invoke_id: 100, modifier_position: None, error };
        assert!(engine.next_call(1).is_some());
        engine.issued(1, 100);
        assert_eq!(engine.on_response(1, 100, &pdu), Some((1, 7, Outcome::Failed(Refusal::source(file_error::FILE_NON_EXISTENT)))));
    }

    #[test]
    fn a_stalled_client_is_timed_out_and_only_its_own_transfer_ends() {
        let (mut engine, _) = started(100);
        engine.start(2, FileNameBuf::from_path("other").unwrap(), Box::new(Memory(Arc::default(), 10)), Instant(0).plus_millis(500));
        engine.bind(2, 9);
        assert_eq!(engine.admit(3), Err(Refusal::destination(file_error::FILE_BUSY)), "two in flight, max two");
        assert_eq!(engine.admit(1), Err(Refusal::destination(file_error::FILE_BUSY)), "one per association");
        let done = engine.on_timeout(Instant(0).plus_millis(1000));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].0, 1);
        assert!(matches!(done[0].2, Outcome::Failed(Refusal { class: 5, code: 1, .. })));
        assert_eq!(engine.len(), 1, "the other transfer goes on");
    }

    #[test]
    fn an_unexpected_answer_never_panics_and_fails_the_transfer() {
        let (mut engine, _) = started(100);
        let identify =
            Mms::ConfirmedResponse { invoke_id: 0, service: ConfirmedResponse::Status { logical: 0, physical: 0, local_detail: None } }.to_vec().unwrap();
        let (_, done) = drive(&mut engine, &[identify]);
        assert!(matches!(done, Some((1, 7, Outcome::Failed(_)))));
        // An answer to an invoke nobody issued is ignored.
        let (mut engine, _) = started(100);
        let _ = engine.next_call(1);
        engine.issued(1, 1);
        assert_eq!(engine.on_response(1, 99, &Mms::parse(&close(), &Limits::DEFAULT).unwrap()), None);
        let _ = vec![0u8; 0];
    }
}
