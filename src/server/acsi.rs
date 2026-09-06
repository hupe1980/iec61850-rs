//! The ACSI server: a request in, an answer out, no socket and no clock.
//!
//! This is the mirror of [`crate::client`] and it is deliberately the same shape as every
//! other core here — a function of `(state, request, now)`. What it is *not* is a second
//! interpretation of the model: browse walks the same tree a read resolves through, and a
//! report's members are the same names a read resolves ([`super::ied`]).
//!
//! Answers are built **owned** ([`Answer`]) and encoded afterwards. A borrowed
//! `ConfirmedResponse` would have to point into scratch the handler owns, which in a language
//! with lifetimes means the handler and the encoder become one function; splitting them is
//! what lets the whole service layer be tested without a socket, a client or a byte.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::control::{ControlHook, Controls, Termination};
use super::files::{FileInfo, FileStore, NoFiles};
use super::ied::{DATA_ACCESS_DENIED, DATA_ACCESS_NON_EXISTENT, Ied};
use super::log::Logs;
use super::rcb::{Engine, Outgoing};
use super::sg::SettingGroups;
use super::tracking::{self, Tracking};
use super::tree::{self, VarKind};
use crate::ber::{Cursor, Encoder};
use crate::common::{Clock, EntryTime, Error, Instant, Now, Result, ServiceError, ServiceType, SystemClock, Tracked, TrackingCdc};
use alloc::boxed::Box;

/// The `EntryID` a client wrote into a buffered control block, as the number the engine
/// counts with.
fn entry_id_of(v: &Value) -> Option<u64> {
    match v {
        Value::OctetString(b) if b.len() == 8 => <[u8; 8]>::try_from(b.as_slice()).ok().map(u64::from_be_bytes),
        _ => None,
    }
}

/// What the server knows about one open association.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Peer {
    /// The peer's network address, as a report control block's `Owner` publishes it.
    identity: Vec<u8>,
    /// The largest MMS PDU it agreed to accept.
    max_pdu: usize,
}

/// The octets a `GetNameList` page may fill inside a PDU of `max_pdu`.
fn page_budget(max_pdu: usize) -> usize {
    max_pdu.saturating_sub(100).clamp(200, 60_000)
}

/// Which association a request arrived on.
///
/// Associations are numbered by the server as it accepts them; the number is never reused
/// while the association is open, which is all any ownership rule needs.
pub type AssocId = u64;
use crate::proto::data::Value;
use crate::proto::mms::reject::{self, Reject, RejectReason};
use crate::proto::mms::typespec::TypeSpec;
use crate::proto::mms::{
    AccessResult, ConfirmedRequest, ConfirmedResponse, Mms, ObjectName, ObjectScope, VariableAccess, VariableSpecification, WriteResult, delete_scope,
    object_class, vmd_logical, vmd_physical,
};

/// What the server answers, before it is encoded.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Answer {
    /// `Identify`.
    Identify {
        /// Vendor.
        vendor: String,
        /// Model.
        model: String,
        /// Revision.
        revision: String,
    },
    /// `Status` — the VMD's health.
    Status {
        /// `vmdLogicalStatus`.
        logical: i64,
        /// `vmdPhysicalStatus`.
        physical: i64,
    },
    /// `GetCapabilityList`, one page of it.
    CapabilityList {
        /// What this server says it can do.
        capabilities: Vec<String>,
        /// Whether the server has more to give.
        more: bool,
    },
    /// `GetNameList`, one page of it.
    NameList {
        /// The names, in ascending order.
        names: Vec<String>,
        /// Whether the server has more to give.
        more: bool,
    },
    /// `Read`: one result per variable, a `DataAccessError` code where it failed.
    Read(Vec<core::result::Result<Value, i64>>),
    /// `Write`: one result per value.
    Write(Vec<core::result::Result<(), i64>>),
    /// `GetNamedVariableListAttributes`.
    DataSetAttributes {
        /// Whether the client may delete it.
        deletable: bool,
        /// The members, as full MMS references.
        members: Vec<String>,
    },
    /// `GetVariableAccessAttributes`.
    VariableType {
        /// Whether the client may delete it (never, for a model variable).
        deletable: bool,
        /// The shape.
        spec: TypeSpec,
    },
    /// `DefineNamedVariableList`.
    DataSetCreated,
    /// `DeleteNamedVariableList`.
    DataSetDeleted {
        /// How many lists matched the scope.
        matched: u32,
        /// How many were deleted.
        deleted: u32,
    },
    /// `FileDirectory`.
    FileDirectory {
        /// The files.
        entries: Vec<FileInfo>,
        /// Whether the server has more to give.
        more: bool,
    },
    /// `FileOpen`.
    FileOpen {
        /// The handle every subsequent read and the close must carry.
        frsm_id: i32,
        /// Size in octets.
        size: u32,
        /// `lastModified`, when the store knows one.
        modified: Option<String>,
    },
    /// `FileRead`.
    FileRead {
        /// This chunk.
        data: Vec<u8>,
        /// Whether more chunks follow.
        more: bool,
    },
    /// `FileClose`.
    FileClose,
    /// `FileDelete`.
    FileDelete,
    /// `ReadJournal` — the entries of a log.
    Journal {
        /// The entries, oldest first.
        entries: Vec<super::log::Entry>,
        /// Whether the server has more to give.
        more: bool,
    },
    /// A service that ran and failed. `class` is the `errorClass` choice tag and `code` the
    /// integer inside it; it is encoded as a `confirmed-ErrorPDU`.
    Error {
        /// The `errorClass` choice tag.
        class: u32,
        /// The integer that choice carries.
        code: i64,
    },
    /// The PDU could not be acted on at all, which ISO 9506 answers with a **reject** rather
    /// than a service error: an unrecognised service, an argument that did not decode, or
    /// octets that are not a PDU.
    ///
    /// The distinction is not pedantry. A confirmed-error says "this service failed"; a
    /// reject says "there was no service". libiec61850's server draws the same line — an
    /// unsupported service gets `confirmed-requestPDU: unrecognized-service` and an
    /// unreadable PDU `pdu-error: invalid-pdu` 🌐 (`mms_server_connection.c`).
    Reject(RejectReason),
}

/// One journal entry, encoded: its values, its `EntryID` and its `ReasonCode`, all of which
/// have to outlive the borrowed response that points into them.
type EncodedEntry = (Vec<Vec<u8>>, Vec<u8>, Option<Vec<u8>>);

/// One open `FileRead` handle: a name and a position, never a copy of the file.
///
/// An `frsmID` is a server-side resource a client can ask for repeatedly, so what it costs
/// the server has to be a constant rather than the size of whatever it names.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileHandle {
    frsm_id: i32,
    assoc: AssocId,
    path: String,
    /// Octets already delivered — the offset the next `FileRead` starts at.
    delivered: u64,
    /// The size the file had when it was opened, for the `moreFollows` decision.
    size: u32,
}

/// `errorClass` choice tags of ISO 9506 `ServiceError`.
pub mod error_class {
    /// `access(7)` — the object could not be accessed.
    pub const ACCESS: u32 = 7;
    /// `service(5)` — the service itself is not supported here.
    pub const SERVICE: u32 = 5;
    /// `definition(4)` — the request names something that is not defined.
    pub const DEFINITION: u32 = 4;
}

impl Answer {
    /// `object-non-existent`, the answer to a name the model does not have.
    pub const NOT_FOUND: Answer = Answer::Error { class: error_class::ACCESS, code: DATA_ACCESS_NON_EXISTENT };
    /// `object-access-denied`.
    pub const DENIED: Answer = Answer::Error { class: error_class::ACCESS, code: DATA_ACCESS_DENIED };
    /// The service is not one this server implements.
    pub const UNSUPPORTED: Answer = Answer::Reject(RejectReason::ConfirmedRequest(reject::UNRECOGNIZED_SERVICE));
    /// The octets are not a PDU this server can act on.
    pub const INVALID_PDU: Answer = Answer::Reject(RejectReason::PduError(reject::INVALID_PDU));

    /// Encode this answer as the MMS PDU that answers `invoke_id`.
    ///
    /// One arm per service, and the borrowed response is built last over scratch this
    /// function owns — which is the whole reason the answer is an owned type at all.
    #[allow(clippy::too_many_lines)]
    pub fn encode(&self, invoke_id: i64) -> Result<Vec<u8>> {
        // A reject is its own PDU, not a response and not an error: it says the request was
        // never a service call, so there is nothing for a service error to describe.
        if let Answer::Reject(reason) = self {
            // `originalInvokeID` is `Unsigned32`; one outside that range names no request a
            // peer could have issued, so the reject names none. Failing here instead would
            // leave the client waiting for ever for an answer this server could not build —
            // which is strictly worse than a reject it cannot attribute.
            let original_invoke_id = u32::try_from(invoke_id).ok().map(i64::from);
            return Reject { original_invoke_id, reason: *reason }.to_vec();
        }
        // A service error is a `confirmed-ErrorPDU`, not a response with an error in it.
        if let Answer::Error { class, code } = self {
            let mut inner = Encoder::new();
            inner.constructed(crate::ber::Tag::context_constructed(0), |e| {
                e.integer(crate::ber::Tag::context(*class), *code)?;
                Ok(())
            })?;
            let body = inner.into_vec();
            let mut e = Encoder::new();
            e.constructed(crate::ber::Tag::context_constructed(2), |e| {
                e.integer(crate::ber::Tag::context(0), invoke_id)?;
                e.constructed(crate::ber::Tag::context_constructed(2), |e| {
                    e.raw(&body);
                    Ok(())
                })?;
                Ok(())
            })?;
            return Ok(e.into_vec());
        }

        // Everything else needs the owned values to outlive the borrowed response, so the
        // scratch is built first and the response points into it.
        let mut scratch: Vec<Vec<u8>> = Vec::new();
        let mut names: Vec<(String, String)> = Vec::new();
        let mut files: Vec<crate::proto::mms::file::FileNameBuf> = Vec::new();
        let mut journal: Vec<EncodedEntry> = Vec::new();
        match self {
            Answer::FileDirectory { entries, .. } => {
                for e in entries {
                    files.push(crate::proto::mms::file::FileNameBuf::from_path(&e.name)?);
                }
            }
            Answer::Journal { entries, .. } => {
                for e in entries {
                    let values: Vec<Vec<u8>> = e.values.iter().map(|(_, v)| Value::encode_all(core::slice::from_ref(v))).collect::<Result<_>>()?;
                    // Why the entry was made travels as one more variable of it, tagged
                    // `ReasonCode` — which is the shape IEC 61850-8-1 maps a log entry's
                    // reason onto and the one libiec61850 writes 🌐. Dropping it would make
                    // a log a list of values with no story, and `reasonCode` in the SCL file
                    // a setting that changes nothing.
                    let reason = e.reason.map(|r| Value::encode_all(core::slice::from_ref(&r.to_value()))).transpose()?;
                    journal.push((values, e.entry_id.to_be_bytes().to_vec(), reason));
                }
            }
            Answer::Read(results) => {
                for r in results {
                    scratch.push(match r {
                        Ok(v) => Value::encode_all(core::slice::from_ref(v))?,
                        Err(_) => Vec::new(),
                    });
                }
            }
            Answer::DataSetAttributes { members, .. } => {
                for m in members {
                    let (domain, item) = m.split_once('/').unwrap_or(("", m.as_str()));
                    names.push((String::from(domain), String::from(item)));
                }
            }
            _ => {}
        }

        let service = match self {
            Answer::Identify { vendor, model, revision } => ConfirmedResponse::Identify { vendor, model, revision },
            Answer::Status { logical, physical } => ConfirmedResponse::Status { logical: *logical, physical: *physical, local_detail: None },
            Answer::CapabilityList { capabilities, more } => {
                ConfirmedResponse::GetCapabilityList { capabilities: capabilities.iter().map(String::as_str).collect(), more_follows: *more }
            }
            Answer::NameList { names, more } => ConfirmedResponse::GetNameList { identifiers: names.iter().map(String::as_str).collect(), more_follows: *more },
            Answer::Read(results) => {
                let mut out = Vec::with_capacity(results.len());
                for (r, bytes) in results.iter().zip(&scratch) {
                    out.push(match r {
                        Ok(_) => AccessResult::Success(Cursor::new(bytes).next_required()?),
                        Err(code) => AccessResult::Failure(*code),
                    });
                }
                ConfirmedResponse::Read { access: None, results: out }
            }
            Answer::Write(results) => ConfirmedResponse::Write(
                results.iter().map(|r| r.as_ref().map_or_else(|code| WriteResult::Failure(*code), |()| WriteResult::Success)).collect(),
            ),
            Answer::DataSetAttributes { deletable, .. } => ConfirmedResponse::GetNamedVariableListAttributes {
                deletable: *deletable,
                variables: names.iter().map(|(d, i)| VariableSpecification::Name(ObjectName::DomainSpecific { domain: d, item: i })).collect(),
            },
            Answer::VariableType { deletable, spec } => ConfirmedResponse::GetVariableAccessAttributes { deletable: *deletable, type_spec: spec.clone() },
            Answer::DataSetCreated => ConfirmedResponse::DefineNamedVariableList,
            Answer::DataSetDeleted { matched, deleted } => ConfirmedResponse::DeleteNamedVariableList { matched: *matched, deleted: *deleted },
            Answer::FileDirectory { entries, more } => ConfirmedResponse::FileDirectory {
                entries: entries
                    .iter()
                    .zip(&files)
                    .map(|(e, name)| crate::proto::mms::file::DirectoryEntry {
                        name: name.as_name(),
                        attributes: crate::proto::mms::file::FileAttributes { size: e.size, last_modified: e.modified.as_deref() },
                    })
                    .collect(),
                more_follows: *more,
            },
            Answer::FileOpen { frsm_id, size, modified } => ConfirmedResponse::FileOpen {
                frsm_id: *frsm_id,
                attributes: crate::proto::mms::file::FileAttributes { size: *size, last_modified: modified.as_deref() },
            },
            Answer::FileRead { data, more } => ConfirmedResponse::FileRead { data, more_follows: *more },
            Answer::FileClose => ConfirmedResponse::FileClose,
            Answer::FileDelete => ConfirmedResponse::FileDelete,
            Answer::Journal { entries, more } => {
                let mut out = Vec::with_capacity(entries.len());
                for (entry, (values, id, reason)) in entries.iter().zip(&journal) {
                    let mut variables = Vec::with_capacity(values.len() + 1);
                    for ((tag, _), bytes) in entry.values.iter().zip(values) {
                        variables.push(crate::proto::mms::journal::JournalVariable { tag, value: Cursor::new(bytes).next_required()? });
                    }
                    if let Some(bytes) = reason {
                        variables.push(crate::proto::mms::journal::JournalVariable {
                            tag: crate::proto::mms::journal::REASON_CODE_TAG,
                            value: Cursor::new(bytes).next_required()?,
                        });
                    }
                    out.push(crate::proto::mms::journal::JournalEntry::new(id, crate::proto::mms::journal::TimeOfDay::dated(entry.occurred), variables));
                }
                ConfirmedResponse::ReadJournal { entries: out, more_follows: *more }
            }
            // Both are whole PDUs of their own and were returned above. An `Err` rather
            // than an `unreachable!` keeps the crate's "no panics" rule literal even on a
            // branch nothing can reach.
            Answer::Error { .. } | Answer::Reject(_) => return Err(Error::InvalidValue("an error or reject answer is encoded before the service match")),
        };
        Mms::ConfirmedResponse { invoke_id, service }.to_vec()
    }
}

/// How the ACSI layer behaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcsiConfig {
    /// What `Identify` answers.
    pub vendor: String,
    /// What `Identify` answers.
    pub model: String,
    /// What `Identify` answers.
    pub revision: String,
    /// The octet budget one `GetNameList` page may fill. A page larger than the negotiated
    /// MMS PDU is a response the peer rejects, so this is set from the association.
    pub name_list_budget: usize,
    /// Data sets one association may create.
    pub max_created_data_sets: usize,
    /// File handles one association may hold open. An `frsmID` is a server-side resource and
    /// a client that opens without closing must run out rather than the server.
    pub max_file_handles: usize,
    /// Octets one `FileRead` returns.
    pub file_chunk: usize,
    /// Entries one `ReadJournal` answers with before it says `moreFollows`.
    pub max_log_entries: usize,
    /// What `Status` answers as `vmdLogicalStatus`; see [`vmd_logical`].
    pub vmd_logical_status: i64,
    /// What `Status` answers as `vmdPhysicalStatus`; see [`vmd_physical`].
    ///
    /// An application that knows it is degraded sets this, and a SCADA client that polls
    /// `Status` is then told so without having to read a logical node to find out.
    pub vmd_physical_status: i64,
    /// What `GetCapabilityList` answers.
    ///
    /// ISO 9506 leaves the strings to the vendor and IEC 61850-8-1 does not constrain them,
    /// so the default names the edition this server was engineered at — which is the one
    /// thing a client asking the question can act on. Anything claimed here is a claim: a
    /// capability listed and not implemented is a request that gets a reject.
    pub capabilities: Vec<String>,
}

impl Default for AcsiConfig {
    fn default() -> AcsiConfig {
        AcsiConfig {
            vendor: String::from("hupe1980"),
            model: String::from("iec61850-rs"),
            revision: String::from(env!("CARGO_PKG_VERSION")),
            // Conservative: the smallest PDU a peer may negotiate is well above this, and a
            // page that is too small costs a round trip while one that is too big costs the
            // whole answer.
            name_list_budget: 900,
            max_created_data_sets: 32,
            max_file_handles: 4,
            file_chunk: 1024,
            max_log_entries: 64,
            vmd_logical_status: vmd_logical::STATE_CHANGES_ALLOWED,
            vmd_physical_status: vmd_physical::OPERATIONAL,
            capabilities: alloc::vec![String::from("IEC 61850-8-1:2011+AMD1:2020")],
        }
    }
}

/// The ACSI server over one [`Ied`].
#[derive(Debug)]
pub struct Acsi {
    /// The served IED.
    pub ied: Ied,
    /// The report engine over its control blocks.
    reports: Engine,
    /// The control state machine over its controllable objects.
    controls: Controls,
    /// The setting groups of its logical devices.
    groups: SettingGroups,
    /// The service tracking data objects the file declares, if any.
    tracking: Tracking,
    /// The logs it keeps.
    logs: Logs,
    /// Where its files come from. `NoFiles` by default: an IED that has none should say so
    /// rather than expose a filesystem by accident.
    files: Box<dyn FileStore>,
    /// Open file handles. Each is a name and a position, never a copy of the file.
    handles: Vec<FileHandle>,
    next_frsm: i32,
    cfg: AcsiConfig,
    /// Cached name lists, one per domain, built on first use: the list is a pure function of
    /// the model plus the data sets a client has created, and rebuilding it per page turns a
    /// browse into a quadratic walk of the whole model.
    names: BTreeMap<String, Vec<String>>,
    /// Reports produced *inside* a request — a buffered block replaying what it kept — which
    /// must go out after the response to that request rather than in the middle of it.
    deferred: Vec<Outgoing>,
    /// What each open association calls itself, for a report control block's `Owner`.
    ///
    /// `Owner` is the Edition 2 attribute that says *who* has a block reserved, and it is how
    /// an operator finds the client holding one. The value is the peer's network address —
    /// what the transport knows and the ACSI layer does not — so it is handed in when the
    /// association opens rather than invented here.
    peers: BTreeMap<AssocId, Peer>,
    /// Where wall-clock time comes from.
    ///
    /// The `Instant` every core is driven by is **monotonic** and says nothing about the date;
    /// a report's `TimeOfEntry`, a log entry's time and an `SGCB`'s `LActTm` are absolute times
    /// an operator reads. Deriving one from the other puts every timestamp at 1984-01-01, the
    /// floor of the `BinaryTime` epoch, and makes `QueryLogByTime` match nothing. The clock is
    /// a trait so a test can pin it and a PTP- or SNTP-disciplined source can replace it.
    clock: Box<dyn Clock + Send + Sync>,
}

impl Acsi {
    /// A server over `ied` with the defaults.
    pub fn new(ied: Ied) -> Acsi {
        Acsi::with_config(ied, AcsiConfig::default())
    }

    /// A server over `ied`.
    pub fn with_config(ied: Ied, cfg: AcsiConfig) -> Acsi {
        let reports = Engine::new(&ied);
        let mut groups = SettingGroups::new(&ied);
        let logs = Logs::new(&ied);
        let tracking = Tracking::new(&ied);
        let mut acsi = Acsi {
            ied,
            reports,
            controls: Controls::new(),
            groups: SettingGroups::default(),
            tracking,
            logs,
            files: Box::new(NoFiles),
            handles: Vec::new(),
            next_frsm: 1,
            cfg,
            names: BTreeMap::new(),
            deferred: Vec::new(),
            peers: BTreeMap::new(),
            clock: Box::new(SystemClock),
        };
        // The engineered active group is in force from the moment the server starts, not from
        // the first time a client writes `ActSG`.
        groups.activate_initial(&mut acsi.ied);
        acsi.ied.take_dirty();
        acsi.groups = groups;
        acsi
    }

    /// Replace the wall clock every absolute timestamp is read from.
    ///
    /// The default is [`SystemClock`]. A test pins it; a device with a disciplined clock
    /// supplies one whose [`Clock::now`] carries the real [`TimeQuality`](crate::common::TimeQuality).
    pub fn set_clock(&mut self, clock: Box<dyn Clock + Send + Sync>) {
        self.clock = clock;
    }

    /// Both clocks at once — the monotonic instant the caller drove this with, and this
    /// server's wall-clock reading (D33). They travel together so a signature cannot let one
    /// stand in for the other.
    fn now(&self, mono: Instant) -> Now {
        Now::new(mono, self.clock.now())
    }

    /// This server's wall clock, for a timestamp that leaves the process.
    ///
    /// Every absolute time a server publishes comes from here rather than from the monotonic
    /// instant its timers run on (D33), including the `t` a supervision logical node stamps
    /// its status with.
    pub fn wall_clock(&self) -> crate::common::UtcTime {
        self.clock.now()
    }

    /// The configuration.
    pub fn config(&self) -> &AcsiConfig {
        &self.cfg
    }

    /// The report engine, for a caller that wants to see what a control block is holding.
    pub fn reports(&self) -> &Engine {
        &self.reports
    }

    /// Ask `hook` before every select, operate and cancel.
    ///
    /// Without one, a command is accepted and applied to the object's status, which is what a
    /// simulator wants. A device replaces it with a hook that drives the switchgear and
    /// refuses with the [`AddCause`](crate::proto::mms::control::AddCause) that says why.
    pub fn on_control(&mut self, hook: ControlHook) {
        self.controls.on_control(hook);
    }

    /// How long a select-before-operate selection is held before it expires.
    pub fn set_sbo_timeout_ms(&mut self, ms: u64) {
        self.controls.set_sbo_timeout_ms(ms);
    }

    /// Serve files from `store`. Without one the server has no files, which is the default.
    pub fn set_file_store(&mut self, store: Box<dyn FileStore>) {
        self.files = store;
    }

    /// The service tracking objects this model declares, for a caller that wants to see
    /// whether the file engineered any.
    pub const fn tracking(&self) -> &Tracking {
        &self.tracking
    }

    /// The logs, for a caller that wants to see what has been written.
    pub fn logs(&self) -> &Logs {
        &self.logs
    }

    /// Keep the log entries in `store` instead of the default bounded in-memory one.
    ///
    /// The store has to know the same logs the model declares —
    /// [`Logs::log_references`](super::Logs::log_references) is the list to build one from.
    pub fn set_log_store(&mut self, store: Box<dyn super::LogStore>) {
        self.logs.set_store(store);
    }

    /// Set the default page budget from what this server offers, leaving room for the PDU's
    /// own envelope. It is what an association gets until it has negotiated its own.
    pub fn set_max_pdu(&mut self, max_pdu: usize) {
        self.cfg.name_list_budget = page_budget(max_pdu);
        self.reports.set_default_max_pdu(max_pdu);
    }

    /// What one association agreed to accept, once `Initiate` has settled it.
    ///
    /// Two things are sized by it and neither may use the server's own number instead: a
    /// `GetNameList` page, which a peer with a smaller buffer rejects outright, and a report,
    /// which is **segmented** to fit rather than dropped. ISO 9506 negotiates *down*, so the
    /// server's configured size is an upper bound and not an agreement.
    pub fn set_association_max_pdu(&mut self, assoc: AssocId, max_pdu: usize) {
        if let Some(peer) = self.peers.get_mut(&assoc) {
            peer.max_pdu = max_pdu;
        }
        self.reports.set_max_pdu(assoc, max_pdu);
    }

    /// The `GetNameList` page budget for one association.
    fn page_budget(&self, assoc: AssocId) -> usize {
        self.peers.get(&assoc).map_or(self.cfg.name_list_budget, |p| page_budget(p.max_pdu))
    }

    /// Answer one confirmed request.
    ///
    /// `assoc` identifies the association it came in on. It is not decoration: a report
    /// control block belongs to the client that enabled it, a select belongs to the client
    /// that made it, and a file handle belongs to the client that opened it — every one of
    /// those is a rule about *who is asking*, and a server that does not know cannot enforce
    /// any of them.
    pub fn request(&mut self, assoc: AssocId, now: Instant, request: &ConfirmedRequest<'_>) -> Answer {
        match request {
            ConfirmedRequest::Identify => {
                Answer::Identify { vendor: self.cfg.vendor.clone(), model: self.cfg.model.clone(), revision: self.cfg.revision.clone() }
            }
            // `Status` is the first thing many SCADA clients send and the last before they
            // give up on a link. `extendedDerivation` asks the server to re-derive rather
            // than report a cached answer; this server has nothing cached, so both are the
            // same walk and the flag changes nothing but is honoured by not being ignored.
            ConfirmedRequest::Status { .. } => Answer::Status { logical: self.cfg.vmd_logical_status, physical: self.cfg.vmd_physical_status },
            ConfirmedRequest::GetCapabilityList { continue_after } => {
                let all: Vec<String> = self.cfg.capabilities.clone();
                match Answer::from_page(&all, *continue_after, self.page_budget(assoc)) {
                    Answer::NameList { names, more } => Answer::CapabilityList { capabilities: names, more },
                    other => other,
                }
            }
            ConfirmedRequest::GetNameList { object_class, scope, continue_after } => self.name_list(assoc, *object_class, *scope, *continue_after),
            ConfirmedRequest::Read { access, .. } => self.read(assoc, now, access),
            ConfirmedRequest::Write { access, values } => self.write(assoc, now, access, values),
            ConfirmedRequest::GetNamedVariableListAttributes(name) => self.data_set_attributes(name),
            ConfirmedRequest::GetVariableAccessAttributes(name) => self.variable_type(name),
            ConfirmedRequest::DefineNamedVariableList { name, variables } => {
                let answer = self.create_data_set(name, variables);
                self.track_named(assoc, now, name, ServiceType::CreateDataSet, &answer);
                answer
            }
            ConfirmedRequest::DeleteNamedVariableList { scope, names, domain } => {
                let answer = self.delete_data_sets(*scope, names, *domain);
                if let Some(name) = names.first() {
                    self.track_named(assoc, now, name, ServiceType::DeleteDataSet, &answer);
                }
                answer
            }
            ConfirmedRequest::FileDirectory { specification, continue_after } => {
                self.file_directory(specification.map(|n| n.display()).as_deref(), continue_after.map(|n| n.display()).as_deref())
            }
            ConfirmedRequest::FileOpen { name, position } => self.file_open(assoc, &name.display(), *position),
            ConfirmedRequest::FileRead(frsm_id) => self.file_read(assoc, *frsm_id),
            ConfirmedRequest::FileClose(frsm_id) => self.file_close(assoc, *frsm_id),
            ConfirmedRequest::FileDelete(name) => self.file_delete(&name.display()),
            ConfirmedRequest::ReadJournal(request) => {
                let answer = self.read_journal(request);
                self.track_log_query(assoc, now, request, &answer);
                answer
            }
            // Anything else — the services this server does not claim in `servicesSupported`.
            ConfirmedRequest::Other(_) => Answer::UNSUPPORTED,
        }
    }

    /// Publish whatever the last batch of writes triggered.
    ///
    /// Returns the unconfirmed PDUs to send and the association each belongs to: a report
    /// goes only to the client that enabled the control block, which is the whole point of
    /// `RptEna` being per-block rather than per-server.
    pub fn commit(&mut self, now: Instant) -> Vec<(AssocId, Vec<u8>)> {
        let dirty = self.ied.take_dirty();
        let wall = self.now(now).entry();
        // Logging first: a log entry records what the model held at the moment of the change,
        // and the report engine writes counters back into the model as it publishes.
        self.logs.commit(&mut self.ied, &dirty, wall);
        let mut out = self.reports.commit(&mut self.ied, &dirty, wall, now);
        out.extend(core::mem::take(&mut self.deferred));
        out.extend(self.controls.take_pending().into_iter().map(|Termination { assoc, pdu }| Outgoing { assoc, pdu }));
        out.into_iter().map(|Outgoing { assoc, pdu }| (assoc, pdu)).collect()
    }

    /// Time passed: emit whatever a gathering window or an integrity period has made due.
    pub fn on_timeout(&mut self, now: Instant) -> Vec<(AssocId, Vec<u8>)> {
        self.controls.on_timeout(&mut self.ied, now);
        // An edit reservation nobody released: `ResvTms` is what ends it.
        self.groups.on_timeout(&mut self.ied, now);
        // …and a report control block's, which is the other half of §15.3.2.2.2.
        self.track_released(now);
        let wall = self.now(now).entry();
        let mut out = self.reports.on_timeout(&mut self.ied, wall, now);
        // A selection that expired on this tick owes the client a `CommandTermination`, and
        // nothing else will collect it: `commit` only runs when the model changes, and an
        // abandoned select changes nothing.
        out.extend(self.controls.take_pending().into_iter().map(|Termination { assoc, pdu }| Outgoing { assoc, pdu }));
        out.into_iter().map(|Outgoing { assoc, pdu }| (assoc, pdu)).collect()
    }

    /// When the server next needs [`Acsi::on_timeout`].
    pub fn next_timeout(&self) -> Option<Instant> {
        // Both layers own deadlines: a report's gathering window or integrity period, and a
        // selection expiry or a time-activated command. Reporting only one of them is how an
        // event loop sleeps through the other.
        [self.reports.next_timeout(), self.controls.next_timeout(), self.groups.next_timeout()].into_iter().flatten().min()
    }

    /// An association opened, and this is what it calls itself.
    ///
    /// `identity` is what a report control block's `Owner` will carry while this association
    /// has one enabled — the peer's network address, in the octets the transport reports.
    pub fn on_association_opened(&mut self, assoc: AssocId, identity: Vec<u8>) {
        let max_pdu = self.cfg.name_list_budget.saturating_add(100);
        self.peers.insert(assoc, Peer { identity, max_pdu });
    }

    /// An association ended: release everything it owned.
    ///
    /// `now` is the moment it ended, because not everything is released at once: a buffered
    /// control block a client reserved with `ResvTms` stays that client's for the seconds the
    /// attribute names, so it is still there when the client reconnects.
    pub fn on_association_closed(&mut self, assoc: AssocId, now: Instant) {
        // Every block this association had a claim on, asked *before* the claim is dropped.
        let held = self.reports.held_by(assoc);
        self.reports.on_association_closed(&mut self.ied, assoc, now);
        // `Owner` names a client, so it has to stop naming one that has gone — but a
        // `ResvTms` reservation deliberately outlives its association (D44), and while it does
        // the block is still that client's. So the answer is recomputed rather than cleared:
        // an operator asking who holds the block gets the truth in both cases.
        for block in held {
            let reference = alloc::format!("{block}$Owner");
            if self.ied.value(&reference).is_none() {
                continue;
            }
            let identity = self.reports.holder(&block).and_then(|id| self.peers.get(&id)).map(|p| p.identity.clone()).unwrap_or_default();
            let _ = self.ied.set_internal(&reference, Value::OctetString(identity));
        }
        // IEC 61850-7-2 §15.3.2.2.2 names exactly this as an `InternalChange`: `RptEna` at the
        // loss of an association. It carries no `originatorID`, because there is no client
        // behind it — the server did it, and saying otherwise would name a client for a change
        // it did not make.
        self.track_released(now);
        // Last, because the lines above still need to know what this peer called itself.
        self.peers.remove(&assoc);
        self.controls.on_association_closed(assoc);
        self.groups.on_association_closed(assoc);
        // A file handle is a server-side resource; an association that goes away without
        // closing its handles must not leak them.
        self.handles.retain(|h| h.assoc != assoc);
    }

    // ---- browse ---------------------------------------------------------------------

    fn name_list(&mut self, assoc: AssocId, class: i64, scope: ObjectScope<'_>, after: Option<&str>) -> Answer {
        let all: Vec<String> = match (class, scope) {
            // `GetServerDirectory(LOGICAL-DEVICE)`: the MMS domains are the logical devices.
            (object_class::DOMAIN, ObjectScope::VmdSpecific) => {
                let mut v = self.ied.domain_names();
                v.sort();
                v
            }
            (object_class::NAMED_VARIABLE, ObjectScope::DomainSpecific(domain)) => {
                if self.ied.domain(domain).is_none() {
                    return Answer::NOT_FOUND;
                }
                self.variable_names(domain)
            }
            (object_class::NAMED_VARIABLE_LIST, ObjectScope::DomainSpecific(domain)) => {
                if self.ied.domain(domain).is_none() {
                    return Answer::NOT_FOUND;
                }
                self.ied.data_set_names(domain)
            }
            (object_class::JOURNAL, ObjectScope::DomainSpecific(domain)) => {
                if self.ied.domain(domain).is_none() {
                    return Answer::NOT_FOUND;
                }
                self.ied.log_names(domain)
            }
            // An object class this server has none of is an empty list, not an error: the
            // question "what journals do you have" is answerable with "none".
            (_, ObjectScope::DomainSpecific(domain)) if self.ied.domain(domain).is_none() => return Answer::NOT_FOUND,
            // An object class this server has none of is an empty list, not an error.
            (_, ObjectScope::VmdSpecific | ObjectScope::DomainSpecific(_) | ObjectScope::AaSpecific | ObjectScope::Other(_)) => Vec::new(),
        };
        Answer::from_page(&all, after, self.page_budget(assoc))
    }

    /// The flattened namespace of a domain, cached.
    fn variable_names(&mut self, domain: &str) -> Vec<String> {
        if let Some(cached) = self.names.get(domain) {
            return cached.clone();
        }
        let Some(d) = self.ied.domain(domain) else { return Vec::new() };
        let names = d.variable_names();
        self.names.insert(String::from(domain), names.clone());
        names
    }

    // ---- read and write -------------------------------------------------------------

    fn read(&mut self, assoc: AssocId, now: Instant, access: &VariableAccess<'_>) -> Answer {
        let names = match self.access_names(access) {
            Ok(names) => names,
            Err(answer) => return answer,
        };
        let mut out = Vec::with_capacity(names.len());
        for reference in &names {
            let reference = match reference {
                Ok(r) => r,
                Err(code) => {
                    out.push(Err(*code));
                    continue;
                }
            };
            out.push(match self.select_reference(assoc, now, reference) {
                Some(v) => Ok(v),
                None => self.read_reference(assoc, reference),
            });
        }
        Answer::Read(out)
    }

    fn read_reference(&self, assoc: AssocId, reference: &str) -> core::result::Result<Value, i64> {
        let Some((domain, item)) = reference.split_once('/') else { return Err(DATA_ACCESS_NON_EXISTENT) };
        // `GetEditSGValue` is rejected while no group is selected (IEC 61850-7-2 §11): with
        // `EditSG = 0` there is no edit copy, and handing back the scratch the model was
        // seeded with would tell a client it is looking at a setting group when it is not.
        // This is the read half of the rule `on_edit_write` enforces for writes.
        if self.ied.node_at(reference).and_then(|n| n.fc) == Some(crate::common::Fc::SE) {
            self.groups.on_edit_read(assoc, &self.ied, reference)?;
        }
        self.ied.read(domain, item).ok_or(DATA_ACCESS_NON_EXISTENT)
    }

    /// A `Read` of `SBO` is the *select* of a normal-security object, not a read of a value.
    fn select_reference(&mut self, assoc: AssocId, now: Instant, reference: &str) -> Option<Value> {
        let (object, attribute) = Controls::split(reference)?;
        if attribute != "SBO" {
            return None;
        }
        let object = String::from(object);
        let at = self.now(now);
        let answer = self.controls.select(assoc, &self.ied, &object, at);
        // IEC 61850-8-1 maps a refused bare `SBO` onto an **empty string** and gives no
        // reason at all, so the tracker cannot invent one either: what it can say truthfully
        // is that the object was not in a state that allowed the select, which is what every
        // one of the reasons (already selected, blocked by mode, refused by the hook) is.
        let error = if crate::proto::data::Typed::as_str(&answer).is_some_and(str::is_empty) {
            ServiceError::AccessNotAllowedInCurrentState
        } else {
            ServiceError::NoError
        };
        self.track(assoc, at, TrackingCdc::Cts, &object, ServiceType::Select, error);
        Some(answer)
    }

    /// Track a service against a named object, in the common tracker.
    fn track_named(&mut self, assoc: AssocId, now: Instant, name: &ObjectName<'_>, service: ServiceType, answer: &Answer) {
        if self.tracking.is_empty() {
            return;
        }
        let ObjectName::DomainSpecific { domain, item } = name else { return };
        let obj_ref = alloc::format!("{domain}/{item}");
        let error = match answer {
            Answer::Error { code, .. } => ServiceError::from_data_access(*code),
            Answer::Reject(_) => ServiceError::ClassNotSupported,
            _ => ServiceError::NoError,
        };
        let at = self.now(now);
        self.track(assoc, at, TrackingCdc::Cst, &obj_ref, service, error);
    }

    /// Track one log query in the `OTS` object of the log's own logical device.
    ///
    /// The two queries are the one pair of *read* services IEC 61850-7-2 §15.3.2 gives a
    /// tracking class of their own. `GetLogStatusValues` is deliberately **not** tracked:
    /// IEC 61850-8-1 maps it onto an ordinary `Read` of the log control block, so nothing on
    /// the wire tells it from any other read of that block.
    ///
    /// The specific half is the query's own parameters under §14.1's rule — the service
    /// parameter with a lower-case first letter — and only the leaves the file declares are
    /// written ⚠ (the `OTS` attribute table is paywalled, R2).
    fn track_log_query(&mut self, assoc: AssocId, now: Instant, request: &crate::proto::mms::ReadJournal<'_>, answer: &Answer) {
        use crate::proto::mms::journal::{RangeStart, RangeStop};
        if self.tracking.is_empty() {
            return;
        }
        let Some(ObjectName::DomainSpecific { domain, item }) = request.name else { return };
        let obj_ref = alloc::format!("{domain}/{item}");
        // `QueryLogAfterEntry` is the one that names a resume point; everything else is a
        // range over time, which is `QueryLogByTime` whether or not it states its bounds.
        let after_entry = request.after.is_some() || matches!(request.start, Some(RangeStart::Entry(_)));
        let service = if after_entry { ServiceType::QueryLogAfter } else { ServiceType::QueryLogByTime };
        let error = match answer {
            Answer::Error { code, .. } => ServiceError::from_data_access(*code),
            Answer::Reject(_) => ServiceError::ClassNotSupported,
            _ => ServiceError::NoError,
        };
        let mut extra: Vec<(&str, Value)> = Vec::new();
        if let Some(after) = request.after {
            extra.push(("entryID", Value::OctetString(after.entry_id.to_vec())));
            extra.push(("entryTime", Value::BinaryTime(after.time.time.to_octets().to_vec())));
        }
        match request.start {
            Some(RangeStart::Time(t)) => extra.push(("rangeStartTime", Value::BinaryTime(t.time.to_octets().to_vec()))),
            Some(RangeStart::Entry(id)) => extra.push(("entryID", Value::OctetString(id.to_vec()))),
            None => {}
        }
        if let Some(RangeStop::Time(t)) = request.stop {
            extra.push(("rangeStopTime", Value::BinaryTime(t.time.to_octets().to_vec())));
        }
        let originator = self.peers.get(&assoc).map(|p| p.identity.clone()).unwrap_or_default();
        let event = Tracked { cdc: TrackingCdc::Ots, obj_ref, service, error, originator };
        let at = self.now(now);
        self.tracking.record_with(&mut self.ied, &event, &extra, at);
    }

    /// Track the blocks the report engine released on its own as `InternalChange`.
    fn track_released(&mut self, now: Instant) {
        let released = self.reports.take_released();
        if self.tracking.is_empty() || released.is_empty() {
            return;
        }
        let at = self.now(now);
        for block in released {
            let fc = block.split_once('/').map(|(_, item)| tree::split_item(item).1).unwrap_or_default();
            let event = Tracked {
                cdc: tracking::class_for(fc),
                obj_ref: block,
                service: ServiceType::InternalChange,
                error: ServiceError::NoError,
                originator: Vec::new(),
            };
            self.tracking.record(&mut self.ied, &event, at);
        }
    }

    /// Record one service against the tracking object of `cdc`, if the model declares one.
    fn track(&mut self, assoc: AssocId, at: Now, cdc: TrackingCdc, obj_ref: &str, service: ServiceType, error: ServiceError) {
        if self.tracking.is_empty() {
            return;
        }
        let originator = self.peers.get(&assoc).map(|p| p.identity.clone()).unwrap_or_default();
        let event = Tracked { cdc, obj_ref: String::from(obj_ref), service, error, originator };
        self.tracking.record(&mut self.ied, &event, at);
    }

    fn write(&mut self, assoc: AssocId, now: Instant, access: &VariableAccess<'_>, values: &[crate::ber::Tlv<'_>]) -> Answer {
        let names = match self.access_names(access) {
            Ok(names) => names,
            Err(answer) => return answer,
        };
        if names.len() != values.len() {
            return Answer::Error { class: error_class::DEFINITION, code: 0 };
        }
        let mut out = Vec::with_capacity(names.len());
        for (reference, tlv) in names.iter().zip(values) {
            let reference = match reference {
                Ok(r) => r,
                Err(code) => {
                    out.push(Err(*code));
                    continue;
                }
            };
            let decoded = crate::proto::data::DataView::from_tlv(*tlv).ok().and_then(|d| d.to_owned(&crate::common::Limits::DEFAULT).ok());
            // Kept for the tracker: a control's `ctlVal`, `origin`, `ctlNum`, `T`, `Test` and
            // `Check` are components of what the *client sent*, not attributes the server
            // holds, so the only place they exist is here.
            let decoded_for_tracking = decoded.clone();
            let result = match decoded {
                Some(v) => self.write_reference(assoc, now, reference, v),
                None => Err(super::ied::DATA_ACCESS_TYPE_INCONSISTENT),
            };
            // Tracked here rather than inside `write_reference`, because *every* write goes
            // through this one loop and a hook per branch is a hook somebody forgets to add
            // to the next branch (D32's rule: one decision about one question).
            self.track_write(assoc, now, reference, decoded_for_tracking.as_ref(), &result);
            out.push(result);
        }
        Answer::Write(out)
    }

    /// Record a write in the tracking data object it belongs to, if the model has one.
    ///
    /// Which object, and which service, is decided by *what the name is* — a control block
    /// attribute is a `SetXxxValues` on that block, a control attribute is the control service
    /// it names, an `SGCB` attribute is one of the setting-group services, and everything else
    /// is a plain `SetDataValues` against the common tracker.
    fn track_write(&mut self, assoc: AssocId, now: Instant, reference: &str, value: Option<&Value>, result: &core::result::Result<(), i64>) {
        if self.tracking.is_empty() {
            // The `AddCause` is taken either way, so a refusal nobody tracks cannot be
            // reported against the *next* command.
            let _ = self.controls.take_last_cause();
            return;
        }
        let event = self.tracked_write(assoc, reference, result);
        let extra = if event.cdc == TrackingCdc::Cts { self.control_tracking_values(value) } else { Vec::new() };
        let at = self.now(now);
        let borrowed: Vec<(&str, Value)> = extra.iter().map(|(k, v)| (*k, v.clone())).collect();
        self.tracking.record_with(&mut self.ied, &event, &borrowed, at);
    }

    /// The `CTS` half of a control service, out of the structure the client sent.
    ///
    /// IEC 61850-7-2 §20.6.2 note 2 is the reason three of these keep an upper-case first
    /// letter where every other tracking attribute has a lower-case one: `T`, `Test` and
    /// `Check` are spelt as the control object spells them.
    fn control_tracking_values(&mut self, value: Option<&Value>) -> Vec<(&'static str, Value)> {
        let cause = self.controls.take_last_cause().unwrap_or(crate::proto::mms::control::AddCause::Unknown);
        let mut out: Vec<(&'static str, Value)> = alloc::vec![("respAddCause", Value::Integer(cause.to_code()))];
        let Some(request) = value.and_then(|v| crate::proto::mms::control::ControlRequest::from_value(v).ok()) else { return out };
        out.push(("ctlVal", request.ctl_val.clone()));
        if let Some(at) = request.oper_tm {
            out.push(("operTm", Value::UtcTime(at)));
        }
        out.push(("origin", request.origin.to_value()));
        out.push(("ctlNum", Value::Unsigned(u64::from(request.ctl_num))));
        out.push(("T", Value::UtcTime(request.t)));
        out.push(("Test", Value::Boolean(request.test)));
        out.push(("Check", request.check.to_value()));
        out
    }

    /// What a write to `reference` is, in tracking terms.
    fn tracked_write(&self, assoc: AssocId, reference: &str, result: &core::result::Result<(), i64>) -> Tracked {
        let originator = self.peers.get(&assoc).map(|p| p.identity.clone()).unwrap_or_default();
        let error = tracking::error_of(result);
        // A control service: the attribute names it, and `operTm` turns an operate into a
        // time-activated one — which the standard tracks as a service of its own.
        if let Some((object, attribute)) = Controls::split(reference) {
            if self.ied.node_at(reference).is_some() {
                let service = match attribute {
                    "SBO" => ServiceType::Select,
                    "SBOw" => ServiceType::SelectWithValue,
                    "Cancel" => ServiceType::Cancel,
                    _ => ServiceType::Operate,
                };
                return Tracked { cdc: TrackingCdc::Cts, obj_ref: String::from(object), service, error, originator };
            }
        }
        // A control block attribute, whose functional constraint says which block it is and
        // therefore which tracking class records it.
        if let Some((block, attribute)) = reference.rsplit_once(tree::SEP) {
            if let Some(b) = self.ied.block(block) {
                let fc = block.split_once('/').map(|(_, item)| tree::split_item(item).1).unwrap_or_default();
                let service = if b.kind == super::ied::BlockKind::SettingGroup {
                    match attribute {
                        "ActSG" => ServiceType::SelectActiveSG,
                        "EditSG" => ServiceType::SelectEditSG,
                        "CnfEdit" => ServiceType::ConfirmEditSGValues,
                        _ => ServiceType::GetSGCBValues,
                    }
                } else {
                    tracking::set_service(fc)
                };
                return Tracked { cdc: tracking::class_for(fc), obj_ref: String::from(block), service, error, originator };
            }
        }
        // Everything else. A setting under `SE` is `SetEditSGValue`, which IEC 61850-7-2
        // §15.3.2.9.3 puts in the *common* tracker rather than the setting-group one.
        let service = match self.ied.node_at(reference).and_then(|n| n.fc) {
            Some(crate::common::Fc::SE) => ServiceType::SetEditSGValue,
            _ => ServiceType::SetDataValues,
        };
        Tracked { cdc: TrackingCdc::Cst, obj_ref: String::from(reference), service, error, originator }
    }

    /// One write, with whatever behaviour the reference's functional constraint gives it.
    fn write_reference(&mut self, assoc: AssocId, now: Instant, reference: &str, value: Value) -> core::result::Result<(), i64> {
        // A write *inside* a control block is a service, not a store: it reserves the block,
        // enables reporting, asks for a general interrogation or is refused because the block
        // is running. The value only reaches the store once the engine has agreed to it.
        // A control is a *service* on a structured variable under `CO`: a select, an operate
        // or a cancel, each with its own rules about who may do it and in what order.
        if let Some((object, attribute)) = Controls::split(reference) {
            if self.ied.node_at(reference).is_some() {
                let object = String::from(object);
                let at = self.now(now);
                return self.controls.write(assoc, &mut self.ied, &object, attribute, &value, at);
            }
        }
        // Everything else is a *value*, and which values a client may write is not a matter
        // of taste: `ST` and `MX` are what the process reports and a server that accepts a
        // write to them has let a client fake a breaker position with no breaker involved.
        self.ied.client_write_allowed(reference)?;
        // The setting group control block, and the two constraints that reach a setting.
        if let Some((block, attribute)) = self.groups.is_block(reference) {
            let at = self.now(now);
            self.groups.on_block_write(assoc, &mut self.ied, &block, &attribute, &value, at)?;
            let result = self.ied.write_leaf(reference, value);
            if result.is_ok() {
                // `CnfEdit` is a command and the server puts it back, which it can only do
                // once the client's `true` has actually reached the store.
                self.groups.after_block_write(&mut self.ied, &block, &attribute);
            }
            return result;
        }
        match self.ied.node_at(reference).and_then(|n| n.fc) {
            // `SG` is what is in force: it changes by activating a group, never by a write.
            Some(crate::common::Fc::SG) => return SettingGroups::on_active_write(),
            Some(crate::common::Fc::SE) => {
                self.groups.on_edit_write(assoc, &self.ied, reference)?;
                return self.ied.write_leaf(reference, value);
            }
            _ => {}
        }
        if let Some((block, attribute)) = reference.rsplit_once(tree::SEP) {
            if self.reports.has(block) {
                self.reports.on_write(assoc, &mut self.ied, block, attribute, &value, now)?;
                let result = self.ied.write_leaf(reference, value);
                if result.is_ok() && matches!(attribute, "RptEna" | "Resv" | "ResvTms") {
                    self.publish_owner(assoc, block);
                }
                if result.is_ok() && attribute == "RptEna" && self.reports.owner(block) == Some(assoc) {
                    // Enabling a buffered block hands over whatever it kept while nobody was
                    // listening, resuming after the `EntryID` the client wrote if it wrote one.
                    let after = self.ied.value(&alloc::format!("{block}$EntryID")).and_then(entry_id_of);
                    let replay = self.reports.drain_buffer(&mut self.ied, block, after);
                    self.deferred.extend(replay);
                }
                return result;
            }
        }
        self.write_value(reference, value)
    }

    /// Put the current holder of `block` into its `Owner`, or clear it when nobody holds it.
    ///
    /// Edition 2 added `Owner` so that an operator can see *which* client has a report control
    /// block, which is the first question asked when a second one cannot enable it. A server
    /// that publishes the attribute and never fills it in answers that question with silence.
    fn publish_owner(&mut self, assoc: AssocId, block: &str) {
        let reference = alloc::format!("{block}$Owner");
        if self.ied.value(&reference).is_none() {
            // An Edition 1 block has no `Owner` at all.
            return;
        }
        let holder = self.reports.holder(block);
        let identity = match holder {
            Some(id) => self.peers.get(&id).map(|p| p.identity.clone()).unwrap_or_default(),
            None => Vec::new(),
        };
        let _ = assoc;
        let _ = self.ied.set_internal(&reference, Value::OctetString(identity));
    }

    /// A plain write into the value store, with the structure walk.
    fn write_value(&mut self, reference: &str, value: Value) -> core::result::Result<(), i64> {
        // A structure write is applied component by component, in the model's order, so that
        // writing a whole `Oper` and writing its `ctlVal` reach the same place.
        if let Some(node) = self.ied.node_at(reference) {
            if node.is_structure() {
                let Value::Structure(members) = &value else { return Err(super::ied::DATA_ACCESS_TYPE_INCONSISTENT) };
                if members.len() != node.children.len() {
                    return Err(super::ied::DATA_ACCESS_TYPE_INCONSISTENT);
                }
                let paths: Vec<String> = node.children.iter().map(|c| alloc::format!("{reference}{}{}", tree::SEP, c.name)).collect();
                for (path, member) in paths.iter().zip(members) {
                    self.write_value(path, member.clone())?;
                }
                return Ok(());
            }
            if !matches!(node.kind, VarKind::Leaf(_)) {
                return Err(DATA_ACCESS_NON_EXISTENT);
            }
        } else {
            return Err(DATA_ACCESS_NON_EXISTENT);
        }
        self.ied.write_leaf(reference, value)
    }

    /// The full MMS references a variable access names, expanding a data set.
    /// What each item of a variable access addresses, as a full reference.
    ///
    /// An item may carry an `alternateAccess`, which names a *part* of the variable — one
    /// element of an array, then components inside it. That folds straight into the reference,
    /// because the item path is where an index lives here too (`tree::item_with`), so
    /// everything downstream reads and writes an array element through the same one store.
    ///
    /// The per-item `Err` is what stops the server answering a question it was not asked: a
    /// selection naming a *range* has no single value to return, and returning the whole array
    /// would look, on the wire, exactly like a successful read of what was asked for.
    fn access_names(&self, access: &VariableAccess<'_>) -> core::result::Result<Vec<core::result::Result<String, i64>>, Answer> {
        match access {
            VariableAccess::ListOfVariable(list) => {
                let mut out = Vec::with_capacity(list.len());
                for spec in list {
                    out.push(match spec {
                        VariableSpecification::Name(ObjectName::DomainSpecific { domain, item }) => Ok(alloc::format!("{domain}/{item}")),
                        VariableSpecification::Element { name: ObjectName::DomainSpecific { domain, item }, access } => {
                            match tree::item_with(item, access.steps()) {
                                Some(path) => Ok(alloc::format!("{domain}/{path}")),
                                None => Err(super::ied::DATA_ACCESS_UNSUPPORTED),
                            }
                        }
                        // VMD-scope and association-specific names are not used by IEC 61850,
                        // and answering them with someone else's variable would be worse than
                        // saying the object does not exist.
                        _ => Err(DATA_ACCESS_NON_EXISTENT),
                    });
                }
                Ok(out)
            }
            VariableAccess::VariableListName(ObjectName::DomainSpecific { domain, item }) => {
                let reference = alloc::format!("{domain}/{item}");
                match self.ied.data_set(&reference) {
                    Some(ds) => Ok(ds.references().into_iter().map(Ok).collect()),
                    None => Err(Answer::NOT_FOUND),
                }
            }
            VariableAccess::VariableListName(_) => Err(Answer::NOT_FOUND),
        }
    }

    // ---- data sets and types --------------------------------------------------------

    fn data_set_attributes(&self, name: &ObjectName<'_>) -> Answer {
        let ObjectName::DomainSpecific { domain, item } = name else { return Answer::NOT_FOUND };
        match self.ied.data_set(&alloc::format!("{domain}/{item}")) {
            Some(ds) => Answer::DataSetAttributes { deletable: ds.deletable, members: ds.references() },
            None => Answer::NOT_FOUND,
        }
    }

    fn variable_type(&self, name: &ObjectName<'_>) -> Answer {
        let ObjectName::DomainSpecific { domain, item } = name else { return Answer::NOT_FOUND };
        match self.ied.domain(domain).and_then(|d| d.resolve(item)) {
            Some(node) => Answer::VariableType { deletable: false, spec: node.type_spec() },
            None => Answer::NOT_FOUND,
        }
    }

    fn create_data_set(&mut self, name: &ObjectName<'_>, variables: &[VariableSpecification<'_>]) -> Answer {
        let ObjectName::DomainSpecific { domain, item } = name else { return Answer::DENIED };
        if self.ied.domain(domain).is_none() {
            return Answer::NOT_FOUND;
        }
        if self.ied.created_data_sets() >= self.cfg.max_created_data_sets {
            return Answer::DENIED;
        }
        let mut members = Vec::with_capacity(variables.len());
        for spec in variables {
            let VariableSpecification::Name(ObjectName::DomainSpecific { domain, item }) = spec else { return Answer::NOT_FOUND };
            let reference = alloc::format!("{domain}/{item}");
            // A member the model does not have makes the whole data set a lie about what it
            // will report, so it is refused rather than silently dropped.
            if self.ied.node_at(&reference).is_none() {
                return Answer::NOT_FOUND;
            }
            members.push(reference);
        }
        if members.is_empty() {
            return Answer::Error { class: error_class::DEFINITION, code: 0 };
        }
        match self.ied.create_data_set(&alloc::format!("{domain}/{item}"), members) {
            Ok(()) => {
                self.names.remove(*domain);
                Answer::DataSetCreated
            }
            Err(_) => Answer::DENIED,
        }
    }

    fn delete_data_sets(&mut self, scope: i64, names: &[ObjectName<'_>], _domain: Option<&str>) -> Answer {
        if scope != delete_scope::SPECIFIC {
            // Deleting by domain or by association would delete data sets this server did not
            // create, which is a service it does not offer rather than one it gets wrong.
            return Answer::Error { class: error_class::SERVICE, code: 0 };
        }
        let (mut matched, mut deleted) = (0u32, 0u32);
        for name in names {
            let ObjectName::DomainSpecific { domain, item } = name else { continue };
            let (exists, removed) = self.ied.delete_data_set(&alloc::format!("{domain}/{item}"));
            matched += u32::from(exists);
            deleted += u32::from(removed);
            if removed {
                self.names.remove(*domain);
            }
        }
        Answer::DataSetDeleted { matched, deleted }
    }
}

impl Acsi {
    // ---- files ----------------------------------------------------------------------

    fn file_directory(&mut self, specification: Option<&str>, continue_after: Option<&str>) -> Answer {
        let all = self.files.list(specification);
        let start = match continue_after {
            None => 0,
            Some(name) => match all.iter().position(|f| f.name == name) {
                Some(i) => i + 1,
                None => return Answer::FileDirectory { entries: Vec::new(), more: false },
            },
        };
        let mut entries = Vec::new();
        let mut used = 0usize;
        for file in all.iter().skip(start) {
            let cost = file.name.len() + file.modified.as_ref().map_or(0, String::len) + 16;
            if !entries.is_empty() && used + cost > self.cfg.name_list_budget {
                return Answer::FileDirectory { entries, more: true };
            }
            used += cost;
            entries.push(file.clone());
        }
        Answer::FileDirectory { entries, more: false }
    }

    fn file_open(&mut self, assoc: AssocId, path: &str, position: u32) -> Answer {
        if self.handles.iter().filter(|h| h.assoc == assoc).count() >= self.cfg.max_file_handles {
            return Answer::DENIED;
        }
        let Some(info) = self.files.info(path) else { return Answer::NOT_FOUND };
        // An open costs a path and two integers. Holding the file instead would make the
        // server's memory the record's size times the number of handles a client chooses to
        // open — a 200 MB record opened five times on ten associations is ten gigabytes.
        let frsm_id = self.next_frsm;
        self.next_frsm = self.next_frsm.wrapping_add(1).max(1);
        // `initialPosition` past the end is an empty file rather than an error, which is what
        // a client resuming a transfer of a file that shrank should see.
        let delivered = u64::from(position).min(u64::from(info.size));
        self.handles.push(FileHandle { frsm_id, assoc, path: String::from(path), delivered, size: info.size });
        Answer::FileOpen { frsm_id, size: info.size, modified: info.modified }
    }

    fn file_read(&mut self, assoc: AssocId, frsm_id: i32) -> Answer {
        let chunk = self.cfg.file_chunk;
        let Some(handle) = self.handles.iter().find(|h| h.frsm_id == frsm_id && h.assoc == assoc) else {
            // A handle another association opened is not this one's to read.
            return Answer::NOT_FOUND;
        };
        let (path, at) = (handle.path.clone(), handle.delivered);
        // One chunk, read now. A file that vanished under an open handle is an empty last
        // read rather than a panic or a stale copy.
        let data = self.files.read_at(&path, at, chunk).unwrap_or_default();
        let Some(handle) = self.handles.iter_mut().find(|h| h.frsm_id == frsm_id && h.assoc == assoc) else { return Answer::NOT_FOUND };
        handle.delivered = at.saturating_add(data.len() as u64);
        let more = data.len() == chunk && handle.delivered < u64::from(handle.size);
        Answer::FileRead { data, more }
    }

    fn file_close(&mut self, assoc: AssocId, frsm_id: i32) -> Answer {
        let before = self.handles.len();
        self.handles.retain(|h| !(h.frsm_id == frsm_id && h.assoc == assoc));
        if self.handles.len() == before { Answer::NOT_FOUND } else { Answer::FileClose }
    }

    fn file_delete(&mut self, path: &str) -> Answer {
        if self.files.delete(path) { Answer::FileDelete } else { Answer::DENIED }
    }

    // ---- logs -----------------------------------------------------------------------

    fn read_journal(&mut self, request: &crate::proto::mms::ReadJournal<'_>) -> Answer {
        use crate::proto::mms::journal::{RangeStart, RangeStop};
        let Some(ObjectName::DomainSpecific { domain, item }) = request.name else { return Answer::NOT_FOUND };
        let reference = alloc::format!("{domain}/{item}");
        if !self.logs.has(&reference) {
            return Answer::NOT_FOUND;
        }
        let limit = self.cfg.max_log_entries;
        let (entries, more) = match (request.after, request.start) {
            // `QueryLogAfterEntry` — both halves of the resume point matter.
            (Some(after), _) => {
                let id = <[u8; 8]>::try_from(after.entry_id).map_or(0, u64::from_be_bytes);
                self.logs.after_entry(&reference, id, after.time.time, limit)
            }
            (None, Some(RangeStart::Entry(id))) => {
                let id = <[u8; 8]>::try_from(id).map_or(0, u64::from_be_bytes);
                self.logs.after_entry(&reference, id, EntryTime::default(), limit)
            }
            // `QueryLogByTime`.
            (None, start) => {
                let from = match start {
                    Some(RangeStart::Time(t)) => Some(t.time),
                    _ => None,
                };
                let to = match request.stop {
                    Some(RangeStop::Time(t)) => Some(t.time),
                    _ => None,
                };
                self.logs.by_time(&reference, from, to, limit)
            }
        };
        Answer::Journal { entries, more }
    }
}

impl Answer {
    /// One page of a sorted name list, resuming strictly **after** `after`.
    #[allow(clippy::doc_markdown)]
    ///
    /// `continueAfter` is an exact match on a name in the list and the answer resumes at the
    /// one following it 🌐 — not a "greater than", which is why the list has to be sorted and
    /// stable between requests. A `continueAfter` that names nothing is an empty last page
    /// rather than the whole list again, because repeating it is a client that pages for ever.
    fn from_page(all: &[String], after: Option<&str>, budget: usize) -> Answer {
        let start = match after {
            None => 0,
            Some(name) => match all.iter().position(|n| n == name) {
                Some(i) => i + 1,
                None => return Answer::NameList { names: Vec::new(), more: false },
            },
        };
        let mut names = Vec::new();
        let mut used = 0usize;
        for name in all.iter().skip(start) {
            // Two octets of tag and length per name, which is what the identifier costs.
            let cost = name.len() + 2;
            if !names.is_empty() && used + cost > budget {
                return Answer::NameList { names, more: true };
            }
            used += cost;
            names.push(name.clone());
        }
        Answer::NameList { names, more: false }
    }
}
