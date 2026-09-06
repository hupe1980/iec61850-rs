//! A blocking IEC 61850 client over MMS — the ten-line path.
//!
//! [`crate::proto::mms::association::Association`] is the state machine; this is the socket
//! around it. Connect, ask, get a typed answer:
//!
//! ```no_run
//! use iec61850_rs::client::Client;
//! use iec61850_rs::Fc;
//!
//! # fn main() -> iec61850_rs::Result<()> {
//! let mut c = Client::connect("10.0.0.5:102")?;
//! for ld in c.server_directory()? {                      // the logical devices
//!     for name in c.logical_device_directory(&ld)? {      // the logical nodes and data
//!         println!("{ld}/{name}");
//!     }
//! }
//! let w = c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX)?;
//! c.release()?;
//! # Ok(()) }
//! ```
//!
//! **Blocking on purpose.** The core is sans-IO, so an async wrapper is an adapter over the
//! same state machine; blocking needs no runtime and no dependency at all.
//!
//! One association per client. Reports and command terminations that arrive while a request is
//! outstanding are kept, not dropped.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant as StdInstant};

mod control;
mod files;
mod log;
mod rcb;
mod sg;

pub use control::{CONTROL_ATTRIBUTES, Control};
pub use files::FileEntry;
pub use log::{Lcb, LogEntry, LogPage};
pub use rcb::{Rcb, RcbSettings};
pub use sg::Sgcb;

// The report types belong to the codec; re-exported here because a client user reaches for
// them without needing to know which layer they came from.
pub use crate::proto::mms::control::{AddCause, Check, CommandTermination, ControlModel, LastApplError, Origin, OriginCategory};
pub use crate::proto::mms::report::{AssemblerStats, OptFlds, ReasonCode, Report, ReportAssembler, ReportEntry, TrgOps};
pub use crate::proto::mms::typespec::{Component, TypeSpec};

use crate::common::{Error, Fc, Instant, Limits, ObjectReference, Result};
use crate::proto::data::{DataView, Typed, Value};
use crate::proto::mms::association::{Association, AssociationConfig, AssociationEvent, CloseReason, PORT};
use crate::proto::mms::control::ControlRequest;
use crate::proto::mms::{
    AccessResult, ConfirmedRequest, ConfirmedResponse, Mms, ObjectName, ObjectScope, ServiceError, Unconfirmed, VariableAccess, VariableSpecification,
    delete_scope, object_class,
};

/// What a server says it is (`Identify`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Vendor name.
    pub vendor: String,
    /// Model name.
    pub model: String,
    /// Revision.
    pub revision: String,
}

/// Something the server sent without being asked.
///
/// Three things arrive this way on an IEC 61850 association and they are told apart by what
/// the `InformationReport` names, not by a tag: a **report** names a report control block, a
/// **command termination** names a control object's `Oper`, and anything else is handed over
/// as it arrived rather than guessed at.
#[derive(Clone, Debug, PartialEq)]
pub enum Unsolicited {
    /// A report from a report control block, decoded per IEC 61850-8-1 Table 40.
    Report(Box<Report>),
    /// The final answer to an enhanced-security control.
    CommandTermination(Box<CommandTermination>),
    /// An `InformationReport` that is neither — another stack's data set report, or a report
    /// this decoder could not make sense of. The raw PDU comes with it so nothing is lost.
    Other {
        /// What the report named.
        name: String,
        /// The `AccessResult`s, decoded, in the order the server sent them.
        values: Vec<Value>,
        /// The whole encoded MMS PDU.
        raw: Vec<u8>,
    },
}

impl Unsolicited {
    /// Classify an encoded `unconfirmed-PDU`.
    ///
    /// Returns `None` for anything that is not an `InformationReport`, or that does not
    /// decode. Public because the classification is useful without a socket: `ied mms sniff`
    /// runs it over a capture, so what the tool says a report contains is what a client
    /// would have been handed.
    pub fn from_pdu(pdu: &[u8], limits: &Limits) -> Option<Unsolicited> {
        let Ok(Mms::Unconfirmed(Unconfirmed::InformationReport { access, results })) = Mms::parse(pdu, limits) else {
            return None;
        };
        // A failed access inside a report is a hole, not a value, and inventing a placeholder
        // would shift every field after it. So a report with one is not decoded — but it is
        // still handed over, whole, because losing it entirely would be worse.
        let mut values = Vec::with_capacity(results.len());
        let mut complete = true;
        for r in &results {
            match r {
                AccessResult::Success(t) => match DataView::from_tlv(*t).ok().and_then(|d| d.to_owned(limits).ok()) {
                    Some(v) => values.push(v),
                    None => complete = false,
                },
                AccessResult::Failure(_) => complete = false,
            }
        }
        if !complete {
            let name = match &access {
                VariableAccess::VariableListName(n) => object_name(n),
                VariableAccess::ListOfVariable(names) => names.iter().map(specification_name).collect::<Vec<_>>().join(", "),
            };
            return Some(Unsolicited::Other { name, values: Vec::new(), raw: pdu.to_vec() });
        }
        Some(match &access {
            VariableAccess::VariableListName(name) => {
                let name = object_name(name);
                match Report::from_values(&values) {
                    Ok(r) => Unsolicited::Report(Box::new(r)),
                    Err(_) => Unsolicited::Other { name, values, raw: pdu.to_vec() },
                }
            }
            VariableAccess::ListOfVariable(names) => match termination(names, &values) {
                Some(t) => Unsolicited::CommandTermination(Box::new(t)),
                None => Unsolicited::Other { name: names.iter().map(specification_name).collect::<Vec<_>>().join(", "), values, raw: pdu.to_vec() },
            },
        })
    }

    /// The report, when this is one.
    pub fn report(&self) -> Option<&Report> {
        match self {
            Unsolicited::Report(r) => Some(r),
            _ => None,
        }
    }

    /// The command termination, when this is one.
    pub fn termination(&self) -> Option<&CommandTermination> {
        match self {
            Unsolicited::CommandTermination(t) => Some(t),
            _ => None,
        }
    }
}

/// How a client connects.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// The association parameters — selectors, sizes, timeouts, the ACSE password.
    pub association: AssociationConfig,
    /// How long to wait for the TCP connection itself.
    pub connect_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> ClientConfig {
        ClientConfig { association: AssociationConfig::default(), connect_timeout: Duration::from_secs(10) }
    }
}

#[cfg(feature = "scl")]
impl ClientConfig {
    /// Take the association's addressing from an SCL file.
    ///
    /// `Communication/ConnectedAP` is where a station's OSI addressing is engineered — the
    /// transport, session and presentation selectors, the AP-title and the AE-qualifier —
    /// and every one of them has to match or the server refuses the association at a layer
    /// whose error message says nothing useful. Reading them out of the SCD is the same rule
    /// the process bus already follows: **the engineering file is the configuration**.
    ///
    /// Returns the configuration and the `IP` the file gives the access point, when it has
    /// one — a caller that is connecting through a gateway overrides it.
    pub fn from_scl(scl: &crate::scl::Scl<'_>, ied: &str, access_point: Option<&str>) -> Result<(ClientConfig, Option<String>)> {
        let model = scl.model(Some(ied))?;
        let address = model.osi_address(access_point).ok_or(Error::NotFound("ConnectedAP address for this IED"))?;
        let cfg = ClientConfig {
            association: AssociationConfig { remote: crate::proto::mms::association::Selectors::from_address(address), ..AssociationConfig::default() },
            ..ClientConfig::default()
        };
        Ok((cfg, address.ip.clone()))
    }
}

/// A blocking MMS client: one association, one socket.
#[derive(Debug)]
pub struct Client {
    stream: TcpStream,
    assoc: Association,
    limits: Limits,
    /// What the server sent while something else was being waited for.
    unsolicited: VecDeque<Unsolicited>,
    /// Joins the segments of a segmented report before it reaches the queue, so a caller
    /// never sees half of one.
    assembler: ReportAssembler,
    /// The `ctlNum` the next control sequence gets.
    ctl_num: u8,
    epoch: StdInstant,
    rx: Vec<u8>,
    /// How long a confirmed request may go unanswered, from the configuration this client
    /// was built with — not from the default, which is what a `&self` helper would have read.
    request_timeout: Duration,
}

impl Client {
    /// Connect and associate, with the defaults.
    ///
    /// `addr` may omit the port, in which case 102 is used.
    pub fn connect(addr: &str) -> Result<Client> {
        Client::connect_with(addr, &ClientConfig::default())
    }

    /// Connect and associate with an explicit configuration.
    pub fn connect_with(addr: &str, cfg: &ClientConfig) -> Result<Client> {
        let with_port = with_default_port(addr);
        let target =
            with_port.to_socket_addrs().map_err(|e| Error::Io(format!("{addr}: {e}")))?.next().ok_or_else(|| Error::Io(format!("{addr}: no address")))?;
        let stream = TcpStream::connect_timeout(&target, cfg.connect_timeout).map_err(|e| Error::Io(format!("{addr}: {e}")))?;
        stream.set_nodelay(true).map_err(|e| Error::Io(e.to_string()))?;
        let limits = cfg.association.limits;
        let mut c = Client {
            stream,
            assoc: Association::client(cfg.association.clone()),
            limits,
            unsolicited: VecDeque::new(),
            assembler: ReportAssembler::new(8),
            ctl_num: 0,
            epoch: StdInstant::now(),
            rx: alloc_buffer(),
            request_timeout: request_timeout(&cfg.association),
        };
        let now = c.now();
        c.assoc.start(now)?;
        c.flush()?;
        c.pump_while(|a| !a.is_established(), Duration::from_millis(cfg.association.connect_timeout_ms))?;
        Ok(c)
    }

    /// Take a connected socket that is already carrying MMS — a TLS stream's plaintext side,
    /// or a connection an accept loop handed over. `stream` must be at the start of the
    /// TPKT stream.
    pub fn from_stream(stream: TcpStream, cfg: &ClientConfig) -> Result<Client> {
        stream.set_nodelay(true).map_err(|e| Error::Io(e.to_string()))?;
        let limits = cfg.association.limits;
        let mut c = Client {
            stream,
            assoc: Association::client(cfg.association.clone()),
            limits,
            unsolicited: VecDeque::new(),
            assembler: ReportAssembler::new(8),
            ctl_num: 0,
            epoch: StdInstant::now(),
            rx: alloc_buffer(),
            request_timeout: request_timeout(&cfg.association),
        };
        let now = c.now();
        c.assoc.start(now)?;
        c.flush()?;
        c.pump_while(|a| !a.is_established(), Duration::from_millis(cfg.association.connect_timeout_ms))?;
        Ok(c)
    }

    /// Connect to an IED the way its SCD says to.
    ///
    /// The address, the selectors and the ACSE names all come out of
    /// `Communication/ConnectedAP`, so an association is engineered once, in the file, and
    /// never typed a second time into code. `host` overrides the file's `IP` when the server
    /// is reached through a gateway or a test bench; pass `None` to use what the file says.
    #[cfg(feature = "scl")]
    pub fn connect_scl(scl: &crate::scl::Scl<'_>, ied: &str, access_point: Option<&str>, host: Option<&str>) -> Result<Client> {
        let (cfg, ip) = ClientConfig::from_scl(scl, ied, access_point)?;
        let host = match (host, ip.as_deref()) {
            (Some(h), _) => String::from(h),
            (None, Some(ip)) => String::from(ip),
            (None, None) => return Err(Error::NotFound("the SCL file gives this access point no IP address")),
        };
        Client::connect_with(&host, &cfg)
    }

    /// The `ctlModel` of a controllable object, read from the server.
    ///
    /// A control sequence that assumes the wrong model does nothing and says nothing: an
    /// object engineered for select-before-operate answers an unselected `Oper` with
    /// `AddCause::ObjectNotSelected`. One extra `Read` of `$CF$<DO>$ctlModel` removes the
    /// guess, and the answer can be cached for the life of the association.
    pub fn read_control_model(&mut self, reference: &str) -> Result<ControlModel> {
        let parsed = ObjectReference::parse(reference)?;
        let (domain, item) = parsed.to_mms(Fc::CF);
        let full = format!("{domain}/{item}$ctlModel");
        let v = self.read(&full, Fc::CF)?;
        let code = v.as_i64().or_else(|| v.as_u64().and_then(|u| i64::try_from(u).ok())).ok_or(Error::InvalidValue("ctlModel is not an integer"))?;
        ControlModel::from_code(code).ok_or(Error::InvalidValue("ctlModel is outside the enumeration"))
    }

    /// What the two ends agreed on.
    pub fn negotiated(&self) -> Option<crate::proto::mms::association::Negotiated> {
        self.assoc.negotiated()
    }

    /// The association's counters.
    pub fn stats(&self) -> crate::proto::mms::association::AssociationStats {
        self.assoc.stats()
    }

    /// `Identify` — vendor, model and revision.
    pub fn identify(&mut self) -> Result<Identity> {
        let pdu = self.call(&ConfirmedRequest::Identify)?;
        match Mms::parse(&pdu, &self.limits)? {
            Mms::ConfirmedResponse { service: ConfirmedResponse::Identify { vendor, model, revision }, .. } => {
                Ok(Identity { vendor: String::from(vendor), model: String::from(model), revision: String::from(revision) })
            }
            _ => Err(Error::InvalidValue("not an Identify response")),
        }
    }

    /// `GetServerDirectory(LOGICAL-DEVICE)`: the logical devices this server hosts.
    ///
    /// MMS domains are logical devices, which is the whole of the mapping.
    pub fn server_directory(&mut self) -> Result<Vec<String>> {
        self.name_list(object_class::DOMAIN, ObjectScope::VmdSpecific)
    }

    /// `GetLogicalDeviceDirectory(ld)`: every named variable in one logical device.
    ///
    /// These come back in the MMS form (`LLN0$ST$Mod$stVal`), which is what the server holds
    /// them as; [`ObjectReference`] reads either spelling.
    pub fn logical_device_directory(&mut self, ld: &str) -> Result<Vec<String>> {
        self.name_list(object_class::NAMED_VARIABLE, ObjectScope::DomainSpecific(ld))
    }

    /// The data sets (`named variable lists`) of one logical device.
    pub fn data_set_directory(&mut self, ld: &str) -> Result<Vec<String>> {
        self.name_list(object_class::NAMED_VARIABLE_LIST, ObjectScope::DomainSpecific(ld))
    }

    /// The logs (`journals`) of one logical device.
    pub fn log_directory(&mut self, ld: &str) -> Result<Vec<String>> {
        self.name_list(object_class::JOURNAL, ObjectScope::DomainSpecific(ld))
    }

    /// The members of a data set, as MMS-form references.
    pub fn data_set_members(&mut self, ld: &str, name: &str) -> Result<Vec<String>> {
        let pdu = self.call(&ConfirmedRequest::GetNamedVariableListAttributes(ObjectName::DomainSpecific { domain: ld, item: name }))?;
        match Mms::parse(&pdu, &self.limits)? {
            Mms::ConfirmedResponse { service: ConfirmedResponse::GetNamedVariableListAttributes { variables, .. }, .. } => Ok(variables
                .iter()
                .filter_map(|v| match v {
                    VariableSpecification::Name(ObjectName::DomainSpecific { domain, item }) => Some(format!("{domain}/{item}")),
                    VariableSpecification::Name(ObjectName::VmdSpecific(n) | ObjectName::AaSpecific(n)) => Some(String::from(*n)),
                    VariableSpecification::Other(_) => None,
                })
                .collect()),
            _ => Err(Error::InvalidValue("not a GetNamedVariableListAttributes response")),
        }
    }

    /// Read one data attribute or data object.
    ///
    /// `reference` is either form — `IED1LD0/MMXU1.TotW.mag.f` with `fc`, or
    /// `IED1LD0/MMXU1$MX$TotW$mag$f`, which carries its own.
    pub fn read(&mut self, reference: &str, fc: Fc) -> Result<Value> {
        let parsed = ObjectReference::parse(reference)?;
        let (domain, item) = parsed.to_mms(fc);
        let access = VariableAccess::ListOfVariable(vec![VariableSpecification::Name(ObjectName::DomainSpecific { domain, item: &item })]);
        let mut values = self.read_access(&access)?;
        if values.len() == 1 { Ok(values.remove(0)) } else { Err(Error::InvalidValue("server returned the wrong number of values")) }
    }

    /// Read several references in one `Read` — one round trip instead of *n*.
    pub fn read_many(&mut self, references: &[(&str, Fc)]) -> Result<Vec<Value>> {
        let mut items = Vec::with_capacity(references.len());
        for (reference, fc) in references {
            let parsed = ObjectReference::parse(reference)?;
            let (domain, item) = parsed.to_mms(*fc);
            items.push((String::from(domain), item));
        }
        let access =
            VariableAccess::ListOfVariable(items.iter().map(|(d, i)| VariableSpecification::Name(ObjectName::DomainSpecific { domain: d, item: i })).collect());
        self.read_access(&access)
    }

    /// Read several references in one `Read`, keeping the per-value failures.
    ///
    /// A `Read` of many variables answers with one `AccessResult` each, so one missing
    /// reference does not spoil the rest — which is exactly what reading a control block
    /// needs, since Edition 1 servers have no `ResvTms` and no `Owner`.
    pub fn read_many_results(&mut self, references: &[(&str, Fc)]) -> Result<Vec<Result<Value>>> {
        let mut items = Vec::with_capacity(references.len());
        for (reference, fc) in references {
            let parsed = ObjectReference::parse(reference)?;
            let (domain, item) = parsed.to_mms(*fc);
            items.push((String::from(domain), item));
        }
        let access =
            VariableAccess::ListOfVariable(items.iter().map(|(d, i)| VariableSpecification::Name(ObjectName::DomainSpecific { domain: d, item: i })).collect());
        self.read_access_results(&access)
    }

    /// Read a whole data set in one request — the values, in the data set's own order.
    pub fn read_data_set(&mut self, ld: &str, name: &str) -> Result<Vec<Value>> {
        self.read_access(&VariableAccess::VariableListName(ObjectName::DomainSpecific { domain: ld, item: name }))
    }

    /// Write one data attribute.
    pub fn write(&mut self, reference: &str, fc: Fc, value: &Value) -> Result<()> {
        let parsed = ObjectReference::parse(reference)?;
        let (domain, item) = parsed.to_mms(fc);
        let encoded = Value::encode_all(std::slice::from_ref(value))?;
        let element = crate::ber::Cursor::new(&encoded).next_required()?;
        let access = VariableAccess::ListOfVariable(vec![VariableSpecification::Name(ObjectName::DomainSpecific { domain, item: &item })]);
        let pdu = self.call(&ConfirmedRequest::Write { access, values: vec![element] })?;
        match Mms::parse(&pdu, &self.limits)? {
            Mms::ConfirmedResponse { service: ConfirmedResponse::Write(results), .. } => match results.first() {
                Some(crate::proto::mms::WriteResult::Success) => Ok(()),
                Some(crate::proto::mms::WriteResult::Failure(code)) => Err(Error::DataAccess(*code)),
                None => Err(Error::InvalidValue("empty Write response")),
            },
            _ => Err(Error::InvalidValue("not a Write response")),
        }
    }

    /// `GetVariableAccessAttributes`: what *type* a variable is.
    ///
    /// One round trip turns "the write was refused with type-inconsistent" into something a
    /// tool can explain, and it is how a caller learns the component order of an `Oper`
    /// without having the SCD. The answer is stable for the life of the association.
    pub fn variable_type(&mut self, reference: &str, fc: Fc) -> Result<TypeSpec> {
        let parsed = ObjectReference::parse(reference)?;
        let (domain, item) = parsed.to_mms(fc);
        let pdu = self.call(&ConfirmedRequest::GetVariableAccessAttributes(ObjectName::DomainSpecific { domain, item: &item }))?;
        match Mms::parse(&pdu, &self.limits)? {
            Mms::ConfirmedResponse { service: ConfirmedResponse::GetVariableAccessAttributes { type_spec, .. }, .. } => Ok(type_spec),
            _ => Err(Error::InvalidValue("not a GetVariableAccessAttributes response")),
        }
    }

    /// Create a data set (`DefineNamedVariableList`).
    ///
    /// `name` is `LD/LLN0$dsName`; `members` are references in either spelling, each with the
    /// functional constraint to read it under. A data set created this way is *non-persistent*
    /// unless the server chooses otherwise, and IEC 61850-7-2 lets a server refuse to create
    /// one at all — which comes back as a service error rather than a silent no-op.
    pub fn create_data_set(&mut self, name: &str, members: &[(&str, Fc)]) -> Result<()> {
        let (ld, item) = split_data_set(name)?;
        let mut items = Vec::with_capacity(members.len());
        for (reference, fc) in members {
            let parsed = ObjectReference::parse(reference)?;
            let (domain, member) = parsed.to_mms(*fc);
            items.push((String::from(domain), member));
        }
        let variables = items.iter().map(|(d, i)| VariableSpecification::Name(ObjectName::DomainSpecific { domain: d, item: i })).collect::<Vec<_>>();
        let pdu = self.call(&ConfirmedRequest::DefineNamedVariableList { name: ObjectName::DomainSpecific { domain: &ld, item: &item }, variables })?;
        match Mms::parse(&pdu, &self.limits)? {
            Mms::ConfirmedResponse { service: ConfirmedResponse::DefineNamedVariableList, .. } => Ok(()),
            _ => Err(Error::InvalidValue("not a DefineNamedVariableList response")),
        }
    }

    /// Delete a data set (`DeleteNamedVariableList`).
    ///
    /// A server that finds the list but will not let this client delete it answers
    /// "matched 1, deleted 0", which is reported as an error rather than as success — the
    /// difference between "gone" and "refused" is the whole answer.
    pub fn delete_data_set(&mut self, name: &str) -> Result<()> {
        let (ld, item) = split_data_set(name)?;
        let pdu = self.call(&ConfirmedRequest::DeleteNamedVariableList {
            scope: delete_scope::SPECIFIC,
            names: vec![ObjectName::DomainSpecific { domain: &ld, item: &item }],
            domain: None,
        })?;
        match Mms::parse(&pdu, &self.limits)? {
            Mms::ConfirmedResponse { service: ConfirmedResponse::DeleteNamedVariableList { deleted: 1, .. }, .. } => Ok(()),
            Mms::ConfirmedResponse { service: ConfirmedResponse::DeleteNamedVariableList { matched: 0, .. }, .. } => Err(Error::NotFound("data set")),
            Mms::ConfirmedResponse { service: ConfirmedResponse::DeleteNamedVariableList { .. }, .. } => {
                // 3 is object-access-denied.
                Err(Error::DataAccess(3))
            }
            _ => Err(Error::InvalidValue("not a DeleteNamedVariableList response")),
        }
    }

    /// The next unsolicited PDU, waiting up to `timeout` for one to arrive.
    ///
    /// Anything that arrived while another request was in flight is handed back first, in
    /// order, without touching the socket.
    pub fn next_unsolicited(&mut self, timeout: Duration) -> Result<Option<Unsolicited>> {
        self.take_unsolicited(timeout, |_| true)
    }

    /// The next **report**, waiting up to `timeout`.
    ///
    /// Command terminations and anything else stay queued for [`Client::next_unsolicited`]:
    /// a client waiting for a report must not silently drop the answer to a control it
    /// issued a moment ago.
    pub fn next_report(&mut self, timeout: Duration) -> Result<Option<Report>> {
        Ok(self.take_unsolicited(timeout, |u| matches!(u, Unsolicited::Report(_)))?.and_then(|u| match u {
            Unsolicited::Report(r) => Some(*r),
            _ => None,
        }))
    }

    /// The next **command termination**, waiting up to `timeout`. Reports stay queued.
    pub fn next_termination(&mut self, timeout: Duration) -> Result<Option<CommandTermination>> {
        self.take_termination(timeout, None)
    }

    /// The command termination for one `ctlNum`, waiting up to `timeout`.
    ///
    /// A client with two commands in flight gets two terminations, and the only thing tying
    /// each to its command is the sequence number both carry — so taking "the next one" would
    /// hand the second command's answer to the first. Terminations for other commands, and
    /// every report, stay queued.
    pub fn next_termination_for(&mut self, ctl_num: u8, timeout: Duration) -> Result<Option<CommandTermination>> {
        self.take_termination(timeout, Some(ctl_num))
    }

    fn take_termination(&mut self, timeout: Duration, ctl_num: Option<u8>) -> Result<Option<CommandTermination>> {
        let wanted = move |u: &Unsolicited| match u {
            Unsolicited::CommandTermination(t) => ctl_num.is_none_or(|n| t.ctl_num() == n),
            _ => false,
        };
        Ok(self.take_unsolicited(timeout, wanted)?.and_then(|u| match u {
            Unsolicited::CommandTermination(t) => Some(*t),
            _ => None,
        }))
    }

    /// Unsolicited PDUs collected so far and not yet taken.
    pub fn buffered_unsolicited(&self) -> usize {
        self.unsolicited.len()
    }

    /// Take the first queued item `wanted` accepts, reading from the socket until `timeout`
    /// if none is there. Everything it rejects stays in the queue, in order.
    fn take_unsolicited(&mut self, timeout: Duration, wanted: impl Fn(&Unsolicited) -> bool) -> Result<Option<Unsolicited>> {
        let deadline = StdInstant::now() + timeout;
        loop {
            if let Some(i) = self.unsolicited.iter().position(&wanted) {
                return Ok(self.unsolicited.remove(i));
            }
            if StdInstant::now() >= deadline || !self.assoc.is_established() {
                return Ok(None);
            }
            self.read_once(deadline.saturating_duration_since(StdInstant::now()))?;
            self.drain_events()?;
        }
    }

    /// Release the association in an orderly way and close the socket.
    pub fn release(&mut self) -> Result<()> {
        if self.assoc.is_established() {
            let now = self.now();
            self.assoc.release(now)?;
            self.flush()?;
            // The peer's confirmation is worth a short wait and nothing more: the association
            // is over either way, and a server that never answers must not hang a tool.
            let _ = self.pump_while(|a| !matches!(a.state(), crate::proto::mms::association::State::Closed), Duration::from_secs(2));
        }
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }

    // ---- plumbing ------------------------------------------------------------------

    fn name_list(&mut self, class: i64, scope: ObjectScope<'_>) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        loop {
            let after = out.last().cloned();
            let pdu = self.call(&ConfirmedRequest::GetNameList { object_class: class, scope, continue_after: after.as_deref() })?;
            let Mms::ConfirmedResponse { service: ConfirmedResponse::GetNameList { identifiers, more_follows }, .. } = Mms::parse(&pdu, &self.limits)? else {
                return Err(Error::InvalidValue("not a GetNameList response"));
            };
            let empty = identifiers.is_empty();
            out.extend(identifiers.iter().map(|s| String::from(*s)));
            // A server that says `moreFollows` and then sends nothing would loop forever;
            // an empty continuation is the end whatever the flag claims.
            if !more_follows || empty {
                return Ok(out);
            }
            if out.len() > self.limits.max_dataset_members * 64 {
                return Err(Error::LimitExceeded { limit: "GetNameList continuations", value: out.len() });
            }
        }
    }

    fn read_access(&mut self, access: &VariableAccess<'_>) -> Result<Vec<Value>> {
        self.read_access_results(access)?.into_iter().collect()
    }

    fn read_access_results(&mut self, access: &VariableAccess<'_>) -> Result<Vec<Result<Value>>> {
        let pdu = self.call(&ConfirmedRequest::Read { specification_with_result: false, access: access.clone() })?;
        let Mms::ConfirmedResponse { service: ConfirmedResponse::Read { results, .. }, .. } = Mms::parse(&pdu, &self.limits)? else {
            return Err(Error::InvalidValue("not a Read response"));
        };
        Ok(results
            .iter()
            .map(|r| match r {
                AccessResult::Failure(code) => Err(Error::DataAccess(*code)),
                AccessResult::Success(t) => DataView::from_tlv(*t)?.to_owned(&self.limits),
            })
            .collect())
    }

    /// Write several references in one `Write`, keeping the per-value failures.
    pub(crate) fn write_many(&mut self, writes: &[(String, Value)]) -> Result<Vec<Result<()>>> {
        let mut encoded = Vec::with_capacity(writes.len());
        let mut items = Vec::with_capacity(writes.len());
        for (reference, value) in writes {
            let parsed = ObjectReference::parse(reference)?;
            let (domain, item) = parsed.to_mms(Fc::ST);
            items.push((String::from(domain), item));
            encoded.push(Value::encode_all(core::slice::from_ref(value))?);
        }
        let access =
            VariableAccess::ListOfVariable(items.iter().map(|(d, i)| VariableSpecification::Name(ObjectName::DomainSpecific { domain: d, item: i })).collect());
        let mut elements = Vec::with_capacity(encoded.len());
        for bytes in &encoded {
            elements.push(crate::ber::Cursor::new(bytes).next_required()?);
        }
        let pdu = self.call(&ConfirmedRequest::Write { access, values: elements })?;
        let Mms::ConfirmedResponse { service: ConfirmedResponse::Write(results), .. } = Mms::parse(&pdu, &self.limits)? else {
            return Err(Error::InvalidValue("not a Write response"));
        };
        Ok(results
            .iter()
            .map(|r| match r {
                crate::proto::mms::WriteResult::Success => Ok(()),
                crate::proto::mms::WriteResult::Failure(code) => Err(Error::DataAccess(*code)),
            })
            .collect())
    }

    /// The next `ctlNum` for a control sequence: 0–255, wrapping.
    pub(crate) fn next_ctl_num(&mut self) -> u8 {
        self.ctl_num = self.ctl_num.wrapping_add(1);
        self.ctl_num
    }

    /// The request timeout this client was configured with.
    pub(crate) const fn timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Issue a confirmed request and block until its answer arrives.
    fn call(&mut self, service: &ConfirmedRequest<'_>) -> Result<Vec<u8>> {
        if !self.assoc.is_established() {
            return Err(Error::Io(String::from("association is not established")));
        }
        let now = self.now();
        let invoke_id = self.assoc.call(now, service)?;
        self.flush()?;
        let deadline = StdInstant::now() + self.request_timeout;
        loop {
            if let Some(pdu) = self.take_answer(invoke_id)? {
                return Ok(pdu);
            }
            if StdInstant::now() >= deadline {
                return Err(Error::Io(String::from("request timed out")));
            }
            self.read_once(deadline.saturating_duration_since(StdInstant::now()))?;
        }
    }

    /// Drain events, keeping reports and returning the answer to `invoke_id` if it came.
    fn take_answer(&mut self, invoke_id: i64) -> Result<Option<Vec<u8>>> {
        let mut answer = None;
        while let Some(event) = self.assoc.poll_event() {
            match event {
                AssociationEvent::Response { invoke_id: id, pdu } if id == invoke_id => {
                    // A confirmed error is an answer too, and a more useful one than silence.
                    if let Mms::ConfirmedError { error, .. } = Mms::parse(&pdu, &self.limits)? {
                        let e = ServiceError::parse(&error)?;
                        return Err(Error::Service { class: e.class, code: e.code });
                    }
                    answer = Some(pdu);
                }
                AssociationEvent::Timeout { invoke_id: id } if id == invoke_id => {
                    return Err(Error::Io(String::from("request timed out")));
                }
                // A reject *is* the answer: the server will send nothing else, so failing
                // now with the reason it gave beats waiting out the request timeout and
                // reporting silence.
                AssociationEvent::Rejected { invoke_id: Some(id), reject } if id == invoke_id => return Err(rejected(&reject)),
                // One that names no request cannot be attributed, but it is still the peer
                // telling us it could not read what we sent — and it will not answer.
                AssociationEvent::Rejected { invoke_id: None, reject } => return Err(rejected(&reject)),
                AssociationEvent::Unconfirmed { pdu } => self.keep_unsolicited(&pdu),
                AssociationEvent::Refused { layer, code } => {
                    return Err(Error::Io(format!("association refused at {layer}: {code:?}")));
                }
                AssociationEvent::Closed(reason) => return Err(closed(reason)),
                // Another request's answer, timeout or reject, a request from the peer (this
                // end is a client and serves none), an established event, an undecodable PDU:
                // none of them answer *this* request, and none of them end the association.
                AssociationEvent::Response { .. }
                | AssociationEvent::Timeout { .. }
                | AssociationEvent::Rejected { .. }
                | AssociationEvent::Request { .. }
                | AssociationEvent::Malformed(_)
                | AssociationEvent::Established(_) => {}
            }
        }
        self.flush()?;
        Ok(answer)
    }

    /// Counters for the segmented reports this client has had to join.
    pub const fn report_assembler_stats(&self) -> AssemblerStats {
        self.assembler.stats()
    }

    /// Classify an unconfirmed PDU and queue it.
    ///
    /// A segmented report is held until its last segment arrives; the application is handed
    /// the whole report or nothing, never a report with a hole in it.
    fn keep_unsolicited(&mut self, pdu: &[u8]) {
        let Some(item) = Unsolicited::from_pdu(pdu, &self.limits) else { return };
        let item = match item {
            Unsolicited::Report(r) => match self.assembler.push(*r) {
                Some(whole) => Unsolicited::Report(Box::new(whole)),
                None => return,
            },
            other => other,
        };
        // The queue is bounded for the same reason the cores' event queues are: a client
        // that stops draining must not grow memory without limit.
        if self.unsolicited.len() >= 256 {
            self.unsolicited.pop_front();
        }
        self.unsolicited.push_back(item);
    }

    fn drain_events(&mut self) -> Result<()> {
        while let Some(event) = self.assoc.poll_event() {
            // Every variant is named rather than caught by a wildcard. A `_ => {}` here is
            // how `Rejected` was silently absorbed when it was added: the compiler cannot
            // ask about a variant a wildcard already answers for.
            match event {
                AssociationEvent::Unconfirmed { pdu } => self.keep_unsolicited(&pdu),
                AssociationEvent::Closed(reason) => return Err(closed(reason)),
                AssociationEvent::Refused { layer, code } => return Err(Error::Io(format!("association refused at {layer}: {code:?}"))),
                // A reject arriving outside a call answers a request that already timed out,
                // or is the peer objecting to something we sent and are no longer waiting on.
                // The association has released the invoke and counted it in
                // `AssociationStats::rejected`; there is no call left to fail.
                AssociationEvent::Rejected { .. }
                // An answer or a timeout for a request nobody is waiting on any more, a
                // request from the peer (this end serves none), the establishment event, and a
                // PDU that did not decode — one bad report is not a reason to drop a
                // connection, and `AssociationStats::malformed` counts it.
                | AssociationEvent::Response { .. }
                | AssociationEvent::Timeout { .. }
                | AssociationEvent::Request { .. }
                | AssociationEvent::Malformed(_)
                | AssociationEvent::Established(_) => {}
            }
        }
        self.flush()
    }

    /// Read once and feed the association; `Ok(())` even when nothing arrived in time.
    fn read_once(&mut self, timeout: Duration) -> Result<()> {
        let timeout = timeout.max(Duration::from_millis(1));
        self.stream.set_read_timeout(Some(timeout)).map_err(|e| Error::Io(e.to_string()))?;
        match self.stream.read(&mut self.rx) {
            Ok(0) => {
                self.assoc.abort();
                Err(Error::Io(String::from("the peer closed the connection")))
            }
            Ok(n) => {
                let now = self.now();
                // The association borrows the slice, and it also lives in `self`, so the
                // buffer is moved out for the call and put back afterwards. That is what
                // keeps a busy association from allocating one buffer per socket read.
                let buf = core::mem::take(&mut self.rx);
                self.assoc.on_bytes(now, buf.get(..n).unwrap_or(&[]));
                self.rx = buf;
                Ok(())
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                let now = self.now();
                self.assoc.on_timeout(now);
                Ok(())
            }
            Err(e) => Err(Error::Io(e.to_string())),
        }
    }

    /// Read and feed until `keep_going` says stop, or the deadline passes.
    fn pump_while(&mut self, keep_going: impl Fn(&Association) -> bool, timeout: Duration) -> Result<()> {
        let deadline = StdInstant::now() + timeout;
        while keep_going(&self.assoc) {
            if StdInstant::now() >= deadline {
                return Err(Error::Io(String::from("timed out waiting for the peer")));
            }
            self.read_once(deadline.saturating_duration_since(StdInstant::now()))?;
            self.drain_events()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        while let Some(packet) = self.assoc.poll_transmit() {
            // The association owns the buffer it lends; copying is what lets the socket be
            // borrowed mutably at the same time, and an MMS request is not a hot path.
            let packet = packet.to_vec();
            self.stream.write_all(&packet).map_err(|e| Error::Io(e.to_string()))?;
        }
        self.stream.flush().map_err(|e| Error::Io(e.to_string()))
    }

    /// The association's notion of now, on a monotonic clock this client owns.
    fn now(&self) -> Instant {
        Instant(self.epoch.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64)
    }
}

/// An `ObjectName` as the reference a human reads.
fn object_name(name: &ObjectName<'_>) -> String {
    match name {
        ObjectName::DomainSpecific { domain, item } => format!("{domain}/{item}"),
        ObjectName::VmdSpecific(n) | ObjectName::AaSpecific(n) => String::from(*n),
    }
}

fn specification_name(spec: &VariableSpecification<'_>) -> String {
    match spec {
        VariableSpecification::Name(n) => object_name(n),
        VariableSpecification::Other(_) => String::new(),
    }
}

/// Recognise a `CommandTermination` (IEC 61850-8-1 §20.9).
///
/// Positive: one variable, the control object's `$Oper`, with the `Oper` value the client
/// sent. Negative: `LastApplError` first — VMD-specific, with no domain — then the `$Oper`.
fn termination(names: &[VariableSpecification<'_>], values: &[Value]) -> Option<CommandTermination> {
    let named: Vec<String> = names.iter().map(specification_name).collect();
    let is_oper = |n: &String| n.ends_with("$Oper") || n.ends_with("$SBOw") || n.ends_with("$Cancel");
    match (named.as_slice(), values) {
        ([first], [oper]) if is_oper(first) => {
            Some(CommandTermination::Positive { control_object: first.clone(), request: ControlRequest::from_value(oper).ok()? })
        }
        ([first, second], [err, oper]) if first == "LastApplError" && is_oper(second) => {
            Some(CommandTermination::Negative { error: LastApplError::from_value(err).ok()?, request: ControlRequest::from_value(oper).ok() })
        }
        ([only], [err]) if only == "LastApplError" => Some(CommandTermination::Negative { error: LastApplError::from_value(err).ok()?, request: None }),
        _ => None,
    }
}

/// Split `LD/LLN0$dsName` into the MMS domain and item a data set is named by.
fn split_data_set(name: &str) -> Result<(String, String)> {
    let (ld, rest) = name.split_once('/').ok_or(Error::InvalidReference("a data set is `LD/LN$dsName`"))?;
    if ld.is_empty() || rest.is_empty() {
        return Err(Error::InvalidReference("a data set is `LD/LN$dsName`"));
    }
    Ok((String::from(ld), rest.replace('.', "$")))
}

fn alloc_buffer() -> Vec<u8> {
    vec![0u8; 8192]
}

/// Append the MMS port when `addr` does not already carry one.
///
/// A bare IPv6 literal is full of colons, so "contains a colon" is not the question — the
/// question is whether the text ends in `:<port>`, which for an IPv6 literal means it is
/// bracketed. `Client::connect("::1")` has to reach port 102, not fail to resolve.
fn with_default_port(addr: &str) -> String {
    let has_port = match addr.rfind(']') {
        // `[::1]:102` has a port; `[::1]` does not.
        Some(bracket) => addr.get(bracket + 1..).is_some_and(|rest| rest.starts_with(':')),
        None => addr.matches(':').count() == 1,
    };
    if has_port {
        String::from(addr)
    } else if addr.contains(':') && !addr.starts_with('[') {
        // A bare IPv6 literal has to be bracketed before a port can be appended to it.
        format!("[{addr}]:{PORT}")
    } else {
        format!("{addr}:{PORT}")
    }
}

/// `0` means "no request timeout" to the association; a blocking client still needs a
/// ceiling, or a server that never answers blocks the caller for ever.
fn request_timeout(cfg: &AssociationConfig) -> Duration {
    Duration::from_millis(if cfg.request_timeout_ms == 0 { 30_000 } else { cfg.request_timeout_ms })
}

/// The reject as the error a caller sees.
///
/// The named reason lives in `proto::mms::reject`; the error carries the wire numbers,
/// because `common::Error` is built by every feature and cannot name an MMS type.
fn rejected(reject: &crate::proto::mms::reject::Reject) -> Error {
    let (invoke_id, reason_tag, code) = reject.to_error_parts();
    Error::Rejected { invoke_id, reason_tag, code }
}

fn closed(reason: CloseReason) -> Error {
    Error::Io(match reason {
        CloseReason::Released | CloseReason::PeerReleased => String::from("the association was released"),
        CloseReason::Aborted => String::from("the association was aborted"),
        CloseReason::ConnectTimeout => String::from("the association handshake timed out"),
        CloseReason::Refused => String::from("the peer refused the association"),
        CloseReason::ProtocolError => String::from("the peer sent something that is not the protocol"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_without_a_port_gets_102() {
        // Nothing is listening, so the connect fails — but on the address it built, which is
        // what this checks: the error names port 102 rather than a parse failure.
        let e = Client::connect("127.0.0.1").unwrap_err();
        assert!(matches!(e, Error::Io(_)), "{e:?}");
    }

    #[test]
    fn a_host_without_a_port_gets_one_whatever_family_it_is() {
        assert_eq!(with_default_port("10.0.0.5"), "10.0.0.5:102");
        assert_eq!(with_default_port("10.0.0.5:3782"), "10.0.0.5:3782");
        assert_eq!(with_default_port("ied1.substation.local"), "ied1.substation.local:102");
        // An IPv6 literal is full of colons; "contains a colon" is not "carries a port".
        assert_eq!(with_default_port("::1"), "[::1]:102");
        assert_eq!(with_default_port("fe80::1"), "[fe80::1]:102");
        assert_eq!(with_default_port("[::1]"), "[::1]:102");
        assert_eq!(with_default_port("[::1]:102"), "[::1]:102");
    }

    #[test]
    fn a_data_set_name_splits_into_the_domain_and_the_list() {
        assert_eq!(split_data_set("IED1LD0/LLN0$dsTrip").unwrap(), (String::from("IED1LD0"), String::from("LLN0$dsTrip")));
        assert_eq!(split_data_set("IED1LD0/LLN0.dsTrip").unwrap(), (String::from("IED1LD0"), String::from("LLN0$dsTrip")));
        assert!(split_data_set("dsTrip").is_err());
    }

    #[test]
    fn a_closed_reason_becomes_an_error_a_human_can_read() {
        assert_eq!(closed(CloseReason::Refused), Error::Io(String::from("the peer refused the association")));
    }
}
