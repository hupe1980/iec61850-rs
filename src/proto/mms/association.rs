//! The MMS association: the state machine over the six OSI layers, for both roles.
//!
//! [`crate::proto::osi`] and the codec in the parent module know how to turn bytes into PDUs
//! and back. What they do not know is *when* — that a client sends a COTP CR and waits for a
//! CC before it may send a session CONNECT, that the AARQ carries the `Initiate` and the AARE
//! carries the answer, that a `confirmed-RequestPDU` needs an invoke identifier nobody else
//! is using and that an answer may never come. That is this module.
//!
//! Sans-IO, like every other core here: bytes in with the caller's `now`, bytes out, events
//! out, and a deadline saying when to call again. It owns no socket and reads no clock, so the
//! same state machine runs over a TCP socket, over a capture file, or against *itself* — which
//! is what [`Association::client`] and [`Association::server`] are for.
//!
//! ```no_run
//! # use iec61850_rs::common::Instant;
//! # use iec61850_rs::proto::mms::association::{Association, AssociationConfig, AssociationEvent};
//! # use iec61850_rs::proto::mms::ConfirmedRequest;
//! # fn send(_: &[u8]) {}
//! # fn main() -> iec61850_rs::Result<()> {
//! let mut a = Association::client(AssociationConfig::default());
//! a.start(Instant::ZERO)?;
//! while let Some(out) = a.poll_transmit() {
//!     send(out);
//! }
//! // …feed what the socket returns to `a.on_bytes(now, &buf)` and drain `a.poll_event()`.
//! # Ok(()) }
//! ```

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use super::{ConfirmedRequest, ConfirmedResponse, Initiate, Mms};
use crate::ber::Encoder;
use crate::common::{Error, EventQueue, Instant, Limits, Result};
use crate::proto::osi::acse::{self, Apdu, Associate};
use crate::proto::osi::cotp::{self, Tpdu, Tsel};
use crate::proto::osi::presentation::{ContextDefinition, ContextResult, Cp, Pdv, Ppdu, RESULT_ACCEPTANCE};
use crate::proto::osi::session::{self, Spdu};
use crate::proto::osi::{Oid, oid, tpkt};

/// The presentation context identifier ACSE travels in, per IEC 61850-8-1.
pub const ACSE_CONTEXT: u16 = 1;
/// The presentation context identifier MMS travels in, per IEC 61850-8-1.
pub const MMS_CONTEXT: u16 = 3;
/// The plain TCP port for MMS over RFC 1006.
pub const PORT: u16 = 102;
/// This end's COTP reference. One association is one transport connection, so a constant is
/// enough; what may not be constant is the *peer's*, which is read off its CR or CC.
const LOCAL_REF: u16 = 1;
/// The TCP port for MMS over TLS (`iso-tp0s`, IEC 62351-4).
pub const PORT_TLS: u16 = 3782;

/// Which end of the association this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The side that opens the connection and issues confirmed requests.
    Client,
    /// The side that accepts it and answers them.
    Server,
}

/// The OSI addressing of one end: the selectors each layer connects with, and the ACSE names.
///
/// Every field is what SCL's `ConnectedAP/Address` writes, which is why
/// [`Selectors::from_address`] exists: an association is engineered once, in the SCD, and
/// should not be typed a second time into code.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selectors {
    /// `OSI-TSEL` — the COTP transport selector.
    pub t_sel: Vec<u8>,
    /// `OSI-SSEL` — the session selector.
    pub s_sel: Vec<u8>,
    /// `OSI-PSEL` — the presentation selector.
    pub p_sel: Vec<u8>,
    /// `OSI-AP-Title`, as its arcs; encoded into the ACSE AP-title when present.
    pub ap_title: Option<Vec<u32>>,
    /// `OSI-AE-Qualifier`.
    pub ae_qualifier: Option<i64>,
}

impl Selectors {
    /// The defaults every IEC 61850 stack uses when the file says nothing: TSEL `0001`,
    /// empty session and presentation selectors.
    pub fn defaults() -> Selectors {
        Selectors { t_sel: alloc::vec![0x00, 0x01], ..Selectors::default() }
    }

    /// The selectors an SCL access point is addressed by.
    pub fn from_address(a: &crate::model::OsiAddress) -> Selectors {
        Selectors {
            t_sel: a.t_sel.clone().unwrap_or_default(),
            s_sel: a.s_sel.clone().unwrap_or_default(),
            p_sel: a.p_sel.clone().unwrap_or_default(),
            ap_title: a.ap_title.clone(),
            ae_qualifier: a.ae_qualifier,
        }
    }

    /// The encoded ACSE `AP-title` (form 2, an OBJECT IDENTIFIER element), if there is one.
    fn ap_title_element(&self) -> Option<Vec<u8>> {
        let arcs = self.ap_title.as_ref()?;
        let contents = oid::encode(arcs)?;
        let mut e = Encoder::new();
        e.primitive(crate::ber::Tag::universal(crate::ber::universal::OID, false), &contents).ok()?;
        Some(e.into_vec())
    }

    /// The encoded ACSE `AE-qualifier` (form 2, an INTEGER element), if there is one.
    fn ae_qualifier_element(&self) -> Option<Vec<u8>> {
        let q = self.ae_qualifier?;
        let mut e = Encoder::new();
        e.integer(crate::ber::Tag::universal(crate::ber::universal::INTEGER, false), q).ok()?;
        Some(e.into_vec())
    }
}

/// How an association is opened and how patient it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssociationConfig {
    /// This end's addressing.
    pub local: Selectors,
    /// The peer's addressing.
    pub remote: Selectors,
    /// The largest MMS PDU this end will accept (`localDetailCalling`).
    pub max_pdu: u32,
    /// COTP TPDU size as its exponent: 7 = 128 … 13 = 8192.
    ///
    /// Class 0 negotiates **down**, so proposing the largest the field can express gets the
    /// best size the peer will agree to. 13 is what libiec61850 proposes.
    pub tpdu_size_exp: u8,
    /// Confirmed requests this end may have outstanding at once.
    pub max_outstanding: u8,
    /// The ACSE password of IEC 61850-8-1, when the server asks for one.
    pub password: Option<String>,
    /// How long the six-layer handshake may take before the association is abandoned.
    pub connect_timeout_ms: u64,
    /// How long a confirmed request may go unanswered. `0` disables the check.
    pub request_timeout_ms: u64,
    /// The largest TSDU COTP will reassemble, which bounds what one PDU can cost.
    pub max_tsdu: usize,
    /// Decode limits applied to every PDU.
    pub limits: Limits,
    /// Events buffered for the application.
    pub event_capacity: usize,
}

impl Default for AssociationConfig {
    fn default() -> AssociationConfig {
        AssociationConfig {
            local: Selectors::defaults(),
            remote: Selectors::defaults(),
            // 64000 is what libiec61850 and most IEDs settle on; the reference capture's
            // client proposes 32000. Either is well under what a TPKT packet can carry, so
            // the COTP layer segments and nothing here has to care.
            max_pdu: 64_000,
            tpdu_size_exp: cotp::TPDU_SIZE_MAX_EXP,
            max_outstanding: 10,
            password: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 30_000,
            max_tsdu: 256 * 1024,
            limits: Limits::DEFAULT,
            event_capacity: 64,
        }
    }
}

/// What the two ends agreed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// The largest MMS PDU the peer will accept — the ceiling on what this end may send.
    pub max_pdu: usize,
    /// Confirmed requests the peer accepts outstanding.
    pub max_outstanding: usize,
    /// Octets of user data one COTP DT TPDU carries.
    pub tpdu_data: usize,
    /// The presentation context MMS was negotiated into.
    pub mms_context: u16,
}

/// Why an association ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// This end released it and the peer confirmed.
    Released,
    /// The peer released it.
    PeerReleased,
    /// The peer aborted, or this end did.
    Aborted,
    /// The handshake did not finish in time.
    ConnectTimeout,
    /// The peer refused the association.
    Refused,
    /// The byte stream stopped being the protocol.
    ProtocolError,
}

/// What the association tells the layer above.
#[derive(Clone, Debug, PartialEq)]
pub enum AssociationEvent {
    /// The six layers are up and confirmed requests may be issued.
    Established(Negotiated),
    /// The peer refused, at the named layer, with whatever code it gave.
    Refused {
        /// `cotp`, `session`, `presentation`, `acse` or `mms`.
        layer: &'static str,
        /// The reason or result code, when the refusal carried one.
        code: Option<i64>,
    },
    /// A `confirmed-ResponsePDU` or `confirmed-ErrorPDU` answering a request this end made.
    /// The bytes are the whole MMS PDU; decode with [`Mms::parse`].
    Response {
        /// The request it answers.
        invoke_id: i64,
        /// The encoded PDU.
        pdu: Vec<u8>,
    },
    /// A `confirmed-RequestPDU` from the peer (server role).
    Request {
        /// The identifier the answer must carry.
        invoke_id: i64,
        /// The encoded PDU.
        pdu: Vec<u8>,
    },
    /// An `unconfirmed-PDU`: how IEC 61850 delivers a report.
    Unconfirmed {
        /// The encoded PDU.
        pdu: Vec<u8>,
    },
    /// A PDU arrived on an established association that this codec could not decode. The
    /// association survives it — one bad report is not a reason to drop a connection — and
    /// [`AssociationStats::malformed`] counts it.
    Malformed(Error),
    /// The peer **rejected** a PDU: not a service that failed, but one it could not act on
    /// at all — an unrecognised service, an invoke identifier it cannot use, more requests
    /// outstanding than were negotiated, or octets that are not a PDU.
    ///
    /// A reject naming an outstanding request answers it, so the identifier is released and
    /// the caller learns why immediately instead of waiting out its timeout.
    Rejected {
        /// The request it rejects, when the peer named one.
        invoke_id: Option<i64>,
        /// Why.
        reject: crate::proto::mms::reject::Reject,
    },
    /// No answer arrived within `request_timeout_ms`. The invoke identifier is released.
    Timeout {
        /// The request that went unanswered.
        invoke_id: i64,
    },
    /// The association is over.
    Closed(CloseReason),
}

/// Counters an association keeps, for the same reason the subscribers keep theirs: an
/// application that is not draining events still needs to know what happened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AssociationStats {
    /// Confirmed requests issued.
    pub requests_sent: u64,
    /// Confirmed responses and errors received.
    pub responses_received: u64,
    /// Unconfirmed PDUs (reports) received.
    pub reports_received: u64,
    /// Requests that went unanswered.
    pub timeouts: u64,
    /// PDUs that did not decode.
    pub malformed: u64,
    /// PDUs the peer rejected, and PDUs this end rejected.
    pub rejected: u64,
    /// TPKT packets sent.
    pub packets_sent: u64,
    /// TPKT packets received.
    pub packets_received: u64,
    /// Events dropped because the application was not draining the queue.
    pub events_dropped: u64,
}

/// Where the handshake has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Nothing sent yet.
    Idle,
    /// A COTP CR is on the wire (client), or a CR is awaited (server).
    Connecting,
    /// The transport is up and the association handshake is in flight.
    Associating,
    /// Confirmed requests may be issued.
    Established,
    /// A release is in flight.
    Releasing,
    /// Over.
    Closed,
}

/// One end of an MMS association.
#[derive(Debug)]
pub struct Association {
    cfg: AssociationConfig,
    role: Role,
    state: State,
    reader: tpkt::Reader,
    reassembler: cotp::Reassembler,
    /// TPKT packets waiting to go out. MMS is not the 4.8 kHz path, so a queue of owned
    /// buffers is the right trade: the handshake alone puts three packets in flight at once.
    out: VecDeque<Vec<u8>>,
    /// The buffer [`Association::poll_transmit`] currently lends out.
    current: Vec<u8>,
    events: EventQueue<AssociationEvent>,
    stats: AssociationStats,
    /// Outstanding confirmed requests and when each stops being worth waiting for.
    outstanding: BTreeMap<i64, Instant>,
    next_invoke: i64,
    negotiated: Option<Negotiated>,
    /// Deadline for the handshake, dropped once the association is up.
    connect_deadline: Option<Instant>,
    /// The MMS `Initiate` the server received, kept so the response can echo a sane answer.
    peer_max_pdu: usize,
    /// Octets of user data one DT TPDU may carry, once the CC has been seen.
    tpdu_data: usize,
    /// The presentation context ACSE was negotiated into. The identifiers in a CP are the
    /// *proposer's* choice, not constants: a peer is free to number ACSE anything it likes,
    /// and a release PDU arriving on a context this end assumed was MMS would be handed to
    /// the application as a malformed report instead of ending the association.
    acse_context: u16,
    /// The presentation context MMS was negotiated into.
    mms_context: u16,
    /// The peer's COTP source reference, learned from its CR or CC.
    ///
    /// A DR has to name it: a peer that receives a disconnect for a reference it never issued
    /// is entitled to ignore it, and this end only ever agreed with *itself* while the number
    /// was hard-coded — the exact self-consistency trap the reference-capture tests exist to
    /// avoid.
    peer_ref: u16,
}

impl Association {
    /// The client end. Nothing is sent until [`Association::start`].
    pub fn client(cfg: AssociationConfig) -> Association {
        Association::new(cfg, Role::Client)
    }

    /// The server end. It waits for a COTP CR.
    pub fn server(cfg: AssociationConfig) -> Association {
        Association::new(cfg, Role::Server)
    }

    fn new(cfg: AssociationConfig, role: Role) -> Association {
        let events = EventQueue::new(cfg.event_capacity);
        let reassembler = cotp::Reassembler::new(cfg.max_tsdu);
        let tpdu_data = cotp::tpdu_size(cfg.tpdu_size_exp).saturating_sub(3);
        Association {
            cfg,
            role,
            state: State::Idle,
            reader: tpkt::Reader::new(),
            reassembler,
            out: VecDeque::new(),
            current: Vec::new(),
            events,
            stats: AssociationStats::default(),
            outstanding: BTreeMap::new(),
            next_invoke: 1,
            negotiated: None,
            connect_deadline: None,
            peer_max_pdu: 0,
            tpdu_data,
            acse_context: ACSE_CONTEXT,
            mms_context: MMS_CONTEXT,
            peer_ref: 0,
        }
    }

    /// Where the handshake has got to.
    pub const fn state(&self) -> State {
        self.state
    }

    /// True once confirmed requests may be issued.
    pub const fn is_established(&self) -> bool {
        matches!(self.state, State::Established)
    }

    /// What the two ends agreed on, once they have.
    pub const fn negotiated(&self) -> Option<Negotiated> {
        self.negotiated
    }

    /// The counters.
    pub const fn stats(&self) -> AssociationStats {
        self.stats
    }

    /// Confirmed requests waiting for an answer.
    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }

    /// Open the association (client role): queues the COTP connection request.
    pub fn start(&mut self, now: Instant) -> Result<()> {
        if self.role != Role::Client {
            return Err(Error::InvalidValue("only a client association starts a connection"));
        }
        if self.state != State::Idle {
            return Err(Error::InvalidValue("association already started"));
        }
        let cr = Tpdu::ConnectionRequest(cotp::Connect::request(
            LOCAL_REF,
            Tsel::new(self.cfg.local.t_sel.clone()),
            Tsel::new(self.cfg.remote.t_sel.clone()),
            self.cfg.tpdu_size_exp,
        ));
        let mut body = Vec::new();
        cr.write(&mut body)?;
        self.queue_tpkt(&body)?;
        self.state = State::Connecting;
        self.arm_connect_deadline(now);
        Ok(())
    }

    /// Feed bytes read from the transport.
    pub fn on_bytes(&mut self, now: Instant, bytes: &[u8]) {
        if matches!(self.state, State::Closed) {
            return;
        }
        self.reader.push(bytes);
        loop {
            let tpdu = match self.reader.next_tpdu() {
                Ok(Some(t)) => t.to_vec(),
                Ok(None) => return,
                Err(_) => return self.close(CloseReason::ProtocolError),
            };
            self.stats.packets_received = self.stats.packets_received.saturating_add(1);
            if let Err(e) = self.on_tpdu(now, &tpdu) {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                self.emit(AssociationEvent::Malformed(e));
                self.close(CloseReason::ProtocolError);
                return;
            }
            if matches!(self.state, State::Closed) {
                return;
            }
        }
    }

    /// Time passed: expire the handshake and any request that went unanswered.
    pub fn on_timeout(&mut self, now: Instant) {
        if let Some(deadline) = self.connect_deadline {
            if now >= deadline {
                match self.state {
                    // A release this end asked for and the peer never confirmed is still a
                    // release: reporting it as a handshake timeout would name the wrong end.
                    State::Releasing => return self.close(CloseReason::Released),
                    State::Established | State::Closed => {}
                    _ => return self.close(CloseReason::ConnectTimeout),
                }
            }
        }
        if self.cfg.request_timeout_ms == 0 {
            return;
        }
        let expired: Vec<i64> = self.outstanding.iter().filter(|(_, d)| now >= **d).map(|(id, _)| *id).collect();
        for id in expired {
            self.outstanding.remove(&id);
            self.stats.timeouts = self.stats.timeouts.saturating_add(1);
            self.emit(AssociationEvent::Timeout { invoke_id: id });
        }
    }

    /// The next deadline the caller should wake this association at.
    pub fn next_timeout(&self) -> Option<Instant> {
        let handshake = if matches!(self.state, State::Established | State::Closed) { None } else { self.connect_deadline };
        let request = if self.cfg.request_timeout_ms == 0 { None } else { self.outstanding.values().min().copied() };
        match (handshake, request) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The next TPKT packet to write to the transport, borrowing a buffer this association
    /// owns. Valid until the next call.
    pub fn poll_transmit(&mut self) -> Option<&[u8]> {
        self.current = self.out.pop_front()?;
        self.stats.packets_sent = self.stats.packets_sent.saturating_add(1);
        Some(&self.current)
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<AssociationEvent> {
        let e = self.events.pop();
        self.stats.events_dropped = self.events.dropped();
        e
    }

    /// Issue a confirmed request, returning the invoke identifier its answer will carry.
    ///
    /// Fails when the association is not up, or when this end already has
    /// [`AssociationConfig::max_outstanding`] requests in flight — the limit the peer agreed
    /// to in `Initiate`, enforced here rather than discovered as a reject.
    pub fn call(&mut self, now: Instant, service: &ConfirmedRequest<'_>) -> Result<i64> {
        if !self.is_established() {
            return Err(Error::InvalidValue("association is not established"));
        }
        let allowed = self.negotiated.map_or(usize::from(self.cfg.max_outstanding), |n| n.max_outstanding);
        if self.outstanding.len() >= allowed {
            return Err(Error::LimitExceeded { limit: "max_outstanding", value: self.outstanding.len() + 1 });
        }
        let invoke_id = self.take_invoke_id();
        let pdu = Mms::ConfirmedRequest { invoke_id, service: service.clone() };
        self.send(&pdu)?;
        let deadline = now.plus_millis(self.cfg.request_timeout_ms);
        self.outstanding.insert(invoke_id, deadline);
        self.stats.requests_sent = self.stats.requests_sent.saturating_add(1);
        Ok(invoke_id)
    }

    /// Answer a confirmed request (server role).
    pub fn respond(&mut self, invoke_id: i64, service: &ConfirmedResponse<'_>) -> Result<()> {
        self.send(&Mms::ConfirmedResponse { invoke_id, service: service.clone() })
    }

    /// Send any MMS PDU on the established association.
    ///
    /// The PDU is checked against the peer's negotiated `localDetailCalled` before it is
    /// framed: a client that sends more than the server said it would accept gets a reject
    /// PDU and no answer, and finding that out here is cheaper than finding it out there.
    pub fn send(&mut self, pdu: &Mms<'_>) -> Result<()> {
        if !matches!(self.state, State::Established) {
            return Err(Error::InvalidValue("association is not established"));
        }
        let bytes = pdu.to_vec()?;
        if self.peer_max_pdu > 0 && bytes.len() > self.peer_max_pdu {
            return Err(Error::LimitExceeded { limit: "peer max PDU", value: bytes.len() });
        }
        let context = self.mms_context;
        self.send_user_data(context, &bytes)
    }

    /// Send an already-encoded MMS PDU on the established association.
    ///
    /// The server builds its answers as bytes — an owned answer encoded once, rather than a
    /// borrowed response pointing into scratch it also owns — so re-encoding here would be a
    /// second pass over the same PDU. The peer's negotiated size is still enforced.
    pub fn send_encoded(&mut self, pdu: &[u8]) -> Result<()> {
        if !matches!(self.state, State::Established) {
            return Err(Error::InvalidValue("association is not established"));
        }
        if self.peer_max_pdu > 0 && pdu.len() > self.peer_max_pdu {
            return Err(Error::LimitExceeded { limit: "peer max PDU", value: pdu.len() });
        }
        let context = self.mms_context;
        self.send_user_data(context, pdu)
    }

    /// Release the association in an orderly way: an ACSE RLRQ inside a session FINISH.
    pub fn release(&mut self, now: Instant) -> Result<()> {
        if !matches!(self.state, State::Established) {
            return Err(Error::InvalidValue("association is not established"));
        }
        let rlrq = Apdu::Release(Some(0)).to_vec()?;
        let ppdu = Ppdu::UserData(alloc::vec![Pdv::single(self.acse_context, &rlrq)]).to_vec()?;
        let mut spdu = Vec::new();
        Spdu::Finish(&ppdu).write(&mut spdu)?;
        self.send_tsdu(&spdu)?;
        self.state = State::Releasing;
        self.connect_deadline = Some(now.plus_millis(self.cfg.connect_timeout_ms));
        Ok(())
    }

    /// Abort immediately: a COTP disconnect request, and the association is over.
    ///
    /// The transport goes rather than the association, because that is the only refusal
    /// every peer in this profile understands, and because a client that has decided to
    /// abort has by definition stopped trusting the layers above.
    pub fn abort(&mut self) {
        if matches!(self.state, State::Closed) {
            return;
        }
        let dr = Tpdu::DisconnectRequest { dst_ref: self.peer_ref, src_ref: LOCAL_REF, reason: 0 };
        let mut body = Vec::new();
        if dr.write(&mut body).is_ok() {
            let _ = self.queue_tpkt(&body);
        }
        self.close(CloseReason::Aborted);
    }

    // ---- inbound -------------------------------------------------------------------

    fn on_tpdu(&mut self, now: Instant, tpdu: &[u8]) -> Result<()> {
        match Tpdu::parse(tpdu)? {
            Tpdu::ConnectionRequest(c) => self.on_connection_request(now, &c),
            Tpdu::ConnectionConfirm(c) => self.on_connection_confirm(&c),
            Tpdu::DisconnectRequest { .. } => {
                self.close(CloseReason::Aborted);
                Ok(())
            }
            Tpdu::Data { eot, payload } => {
                // The reassembler borrows itself, so the TSDU is copied out before anything
                // else touches `self`. Only a segmented TSDU pays for that copy twice.
                let tsdu = match self.reassembler.push(eot, payload)? {
                    Some(t) => t.to_vec(),
                    None => return Ok(()),
                };
                self.reassembler.take();
                self.on_tsdu(&tsdu)
            }
            Tpdu::Other { .. } => {
                // An ER TPDU, or a class this profile does not speak. Either way the
                // transport is not going to carry an association.
                self.close(CloseReason::ProtocolError);
                Ok(())
            }
        }
    }

    fn on_connection_request(&mut self, now: Instant, c: &cotp::Connect) -> Result<()> {
        if self.role != Role::Server {
            self.close(CloseReason::ProtocolError);
            return Ok(());
        }
        // Class 0 negotiates *down*: the responder may propose no more than the initiator did.
        let exp = c.tpdu_size_exp.unwrap_or(cotp::TPDU_SIZE_MIN_EXP).min(self.cfg.tpdu_size_exp);
        self.tpdu_data = cotp::tpdu_size(exp).saturating_sub(3);
        self.peer_ref = c.src_ref;
        let cc = cotp::Connect {
            dst_ref: c.src_ref,
            src_ref: LOCAL_REF,
            class_options: 0,
            tpdu_size_exp: Some(exp),
            src_tsel: c.dst_tsel.clone(),
            dst_tsel: c.src_tsel.clone(),
        };
        let mut body = Vec::new();
        Tpdu::ConnectionConfirm(cc).write(&mut body)?;
        self.queue_tpkt(&body)?;
        self.state = State::Associating;
        self.arm_connect_deadline(now);
        Ok(())
    }

    fn on_connection_confirm(&mut self, c: &cotp::Connect) -> Result<()> {
        if self.role != Role::Client || self.state != State::Connecting {
            self.close(CloseReason::ProtocolError);
            return Ok(());
        }
        let exp = c.tpdu_size_exp.unwrap_or(cotp::TPDU_SIZE_MIN_EXP).min(self.cfg.tpdu_size_exp);
        self.tpdu_data = cotp::tpdu_size(exp).saturating_sub(3);
        self.peer_ref = c.src_ref;
        self.state = State::Associating;
        self.send_associate_request()
    }

    fn on_tsdu(&mut self, tsdu: &[u8]) -> Result<()> {
        match Spdu::parse(tsdu)? {
            Spdu::Connect(c) => self.on_session_connect(c.user_data),
            Spdu::Accept(c) => self.on_session_accept(c.user_data),
            Spdu::Refuse { reason, .. } => {
                self.emit(AssociationEvent::Refused { layer: "session", code: reason.map(i64::from) });
                self.close(CloseReason::Refused);
                Ok(())
            }
            Spdu::DataTransfer(p) => self.on_user_data(p),
            Spdu::Finish(_) => self.on_peer_finish(),
            Spdu::Disconnect(_) => {
                self.close(CloseReason::Released);
                Ok(())
            }
            Spdu::Abort(_) | Spdu::AbortAccept => {
                self.close(CloseReason::Aborted);
                Ok(())
            }
            Spdu::Other { .. } => {
                self.close(CloseReason::ProtocolError);
                Ok(())
            }
        }
    }

    /// Server: the CP with the AARQ and the MMS `Initiate` inside it.
    fn on_session_connect(&mut self, ppdu_bytes: &[u8]) -> Result<()> {
        if self.role != Role::Server {
            self.close(CloseReason::ProtocolError);
            return Ok(());
        }
        let Ppdu::Connect(cp) = Ppdu::parse(ppdu_bytes, true)? else {
            self.close(CloseReason::ProtocolError);
            return Ok(());
        };
        let mms_context = cp.context_for(Oid::MMS_ABSTRACT_SYNTAX).unwrap_or(MMS_CONTEXT);
        let acse_context = cp.context_for(Oid::ACSE_ABSTRACT_SYNTAX).unwrap_or(ACSE_CONTEXT);
        self.mms_context = mms_context;
        self.acse_context = acse_context;
        let aarq =
            cp.user_data.iter().find(|p| p.context_id == acse_context).and_then(|p| p.values.single()).ok_or(Error::InvalidValue("CP carries no ACSE PDU"))?;
        let Apdu::Associate(a) = Apdu::parse(aarq)? else {
            self.close(CloseReason::ProtocolError);
            return Ok(());
        };
        let initiate_bytes = a.mms_pdu().ok_or(Error::InvalidValue("AARQ carries no Initiate"))?;
        let Mms::InitiateRequest(init) = Mms::parse(initiate_bytes, &self.cfg.limits)? else {
            self.close(CloseReason::ProtocolError);
            return Ok(());
        };
        self.peer_max_pdu = usize::try_from(init.local_detail.unwrap_or(0)).unwrap_or(0);
        // The **called** end's budget: how many requests the client agreed this server may
        // have outstanding toward it, capped by what this server negotiated back.
        let mine = usize::try_from(init.max_serv_outstanding_called).unwrap_or(0).clamp(1, usize::from(self.cfg.max_outstanding).max(1));
        self.answer_associate(&cp, mms_context, acse_context, &init)?;
        self.established(Negotiated {
            max_pdu: if self.peer_max_pdu == 0 { self.cfg.max_pdu as usize } else { self.peer_max_pdu },
            max_outstanding: mine,
            tpdu_data: self.tpdu_data,
            mms_context,
        });
        Ok(())
    }

    /// Client: the CPA with the AARE and the MMS `Initiate` response.
    fn on_session_accept(&mut self, ppdu_bytes: &[u8]) -> Result<()> {
        if self.role != Role::Client {
            self.close(CloseReason::ProtocolError);
            return Ok(());
        }
        let ppdu = Ppdu::parse(ppdu_bytes, true)?;
        let cp = match ppdu {
            Ppdu::Accept(cp) => cp,
            Ppdu::Reject(cp) => {
                self.emit(AssociationEvent::Refused { layer: "presentation", code: cp.provider_reason });
                self.close(CloseReason::Refused);
                return Ok(());
            }
            _ => {
                self.close(CloseReason::ProtocolError);
                return Ok(());
            }
        };
        if !cp.all_accepted() {
            self.emit(AssociationEvent::Refused { layer: "presentation", code: cp.results.iter().map(|r| r.result).find(|r| *r != RESULT_ACCEPTANCE) });
            self.close(CloseReason::Refused);
            return Ok(());
        }
        let acse_context = self.acse_context;
        let aare =
            cp.user_data.iter().find(|p| p.context_id == acse_context).and_then(|p| p.values.single()).ok_or(Error::InvalidValue("CPA carries no ACSE PDU"))?;
        let Apdu::AssociateResponse(a) = Apdu::parse(aare)? else {
            self.close(CloseReason::ProtocolError);
            return Ok(());
        };
        if !a.accepted() {
            self.emit(AssociationEvent::Refused { layer: "acse", code: a.result });
            self.close(CloseReason::Refused);
            return Ok(());
        }
        let initiate_bytes = a.mms_pdu().ok_or(Error::InvalidValue("AARE carries no Initiate response"))?;
        match Mms::parse(initiate_bytes, &self.cfg.limits)? {
            Mms::InitiateResponse(init) => {
                self.peer_max_pdu = usize::try_from(init.local_detail.unwrap_or(0)).unwrap_or(0);
                // `negotiatedMaxServOutstandingCalling` is what limits the **calling** end —
                // this one. `…Called` is the server's own budget for requests it may issue
                // toward us, and taking that number as our own is how a client ends up
                // sending more requests than the server agreed to answer.
                let mine = usize::try_from(init.max_serv_outstanding_calling).unwrap_or(0);
                self.established(Negotiated {
                    max_pdu: if self.peer_max_pdu == 0 { self.cfg.max_pdu as usize } else { self.peer_max_pdu },
                    max_outstanding: mine.clamp(1, usize::from(self.cfg.max_outstanding)),
                    tpdu_data: self.tpdu_data,
                    mms_context: self.mms_context,
                });
                Ok(())
            }
            Mms::InitiateError(_) => {
                self.emit(AssociationEvent::Refused { layer: "mms", code: None });
                self.close(CloseReason::Refused);
                Ok(())
            }
            _ => {
                self.close(CloseReason::ProtocolError);
                Ok(())
            }
        }
    }

    /// A PDU on an established association: a presentation `User-data` with one PDV.
    fn on_user_data(&mut self, ppdu_bytes: &[u8]) -> Result<()> {
        let Ppdu::UserData(pdvs) = Ppdu::parse(ppdu_bytes, false)? else {
            self.close(CloseReason::ProtocolError);
            return Ok(());
        };
        for pdv in pdvs {
            let Some(value) = pdv.values.single() else { continue };
            if pdv.context_id == self.acse_context {
                // ACSE after the handshake means a release or an abort.
                match Apdu::parse(value) {
                    Ok(Apdu::Release(_)) => return self.on_peer_finish(),
                    Ok(Apdu::ReleaseResponse(_)) => {
                        self.close(CloseReason::Released);
                        return Ok(());
                    }
                    Ok(Apdu::Abort(_)) => {
                        self.close(CloseReason::Aborted);
                        return Ok(());
                    }
                    _ => continue,
                }
            }
            self.deliver_mms(value);
        }
        Ok(())
    }

    fn deliver_mms(&mut self, bytes: &[u8]) {
        let pdu = match Mms::parse(bytes, &self.cfg.limits) {
            Ok(p) => p,
            Err(e) => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                self.emit(AssociationEvent::Malformed(e));
                return;
            }
        };
        let event = match &pdu {
            Mms::ConfirmedResponse { invoke_id, .. } | Mms::ConfirmedError { invoke_id, .. } => {
                let invoke_id = *invoke_id;
                // An answer to a request nobody made, or to one that already timed out, is
                // still handed up: the application asked for it once, and a late answer is
                // better evidence than silence. It just does not release a slot twice.
                self.outstanding.remove(&invoke_id);
                self.stats.responses_received = self.stats.responses_received.saturating_add(1);
                AssociationEvent::Response { invoke_id, pdu: bytes.to_vec() }
            }
            Mms::ConfirmedRequest { invoke_id, .. } => AssociationEvent::Request { invoke_id: *invoke_id, pdu: bytes.to_vec() },
            Mms::Unconfirmed(_) => {
                self.stats.reports_received = self.stats.reports_received.saturating_add(1);
                AssociationEvent::Unconfirmed { pdu: bytes.to_vec() }
            }
            Mms::Reject(reject) => {
                let reject = *reject;
                // A reject *answers* the request it names. Releasing the slot here is the
                // whole point: without it the caller blocks for `request_timeout_ms` and then
                // reports a timeout for an answer that arrived at once.
                if let Some(id) = reject.original_invoke_id {
                    self.outstanding.remove(&id);
                }
                self.stats.rejected = self.stats.rejected.saturating_add(1);
                AssociationEvent::Rejected { invoke_id: reject.original_invoke_id, reject }
            }
            Mms::ConcludeRequest => {
                // The MMS-level orderly release. Answer it and go.
                let _ = self.send_pdu_unchecked(&Mms::ConcludeResponse);
                self.close(CloseReason::PeerReleased);
                return;
            }
            Mms::ConcludeResponse => {
                self.close(CloseReason::Released);
                return;
            }
            _ => AssociationEvent::Unconfirmed { pdu: bytes.to_vec() },
        };
        self.emit(event);
    }

    fn on_peer_finish(&mut self) -> Result<()> {
        let rlre = Apdu::ReleaseResponse(Some(0)).to_vec()?;
        let ppdu = Ppdu::UserData(alloc::vec![Pdv::single(self.acse_context, &rlre)]).to_vec()?;
        let mut spdu = Vec::new();
        Spdu::Disconnect(&ppdu).write(&mut spdu)?;
        self.send_tsdu(&spdu)?;
        self.close(CloseReason::PeerReleased);
        Ok(())
    }

    // ---- outbound ------------------------------------------------------------------

    /// The client's CR-follow-up: session CONNECT ▸ presentation CP ▸ AARQ ▸ MMS `Initiate`.
    fn send_associate_request(&mut self) -> Result<()> {
        let initiate =
            Mms::InitiateRequest(Initiate::request(i64::from(self.cfg.max_pdu), i64::from(self.cfg.max_outstanding), PARAMETER_CBB, SERVICES_SUPPORTED))
                .to_vec()?;
        let called = self.cfg.remote.ap_title_element();
        let calling = self.cfg.local.ap_title_element();
        let called_q = self.cfg.remote.ae_qualifier_element();
        let calling_q = self.cfg.local.ae_qualifier_element();
        let password;
        let mut aarq = Associate::request(called.as_deref(), calling.as_deref(), i64::from(MMS_CONTEXT), &initiate);
        aarq.called_ae_qualifier = called_q.as_deref();
        aarq.calling_ae_qualifier = calling_q.as_deref();
        if let Some(p) = &self.cfg.password {
            // ACSE authentication: the requirements bit string says a value is present, the
            // mechanism names the IEC 61850-8-1 password, and the value is the `[0]`
            // GraphicString spelling of `Authentication-value`.
            let mut e = Encoder::new();
            e.primitive(crate::ber::Tag::context(0), p.as_bytes())?;
            password = e.into_vec();
            aarq.sender_requirements = Some((7, &[0x80]));
            aarq.mechanism_name = Some(Oid::PASSWORD_MECHANISM);
            aarq.authentication_value = Some(&password);
        }
        let aarq_bytes = Apdu::Associate(aarq).to_vec()?;
        let cp = Cp::connect(&self.cfg.local.p_sel, &self.cfg.remote.p_sel, ACSE_CONTEXT, MMS_CONTEXT, &aarq_bytes);
        let ppdu = Ppdu::Connect(cp).to_vec()?;
        let mut spdu = Vec::new();
        Spdu::Connect(session::Connect::new(Some(&self.cfg.local.s_sel), Some(&self.cfg.remote.s_sel), &ppdu)).write(&mut spdu)?;
        self.send_tsdu(&spdu)
    }

    /// The server's answer: session ACCEPT ▸ presentation CPA ▸ AARE ▸ `Initiate` response.
    fn answer_associate(&mut self, cp: &Cp<'_>, mms_context: u16, acse_context: u16, peer: &Initiate<'_>) -> Result<()> {
        let max_pdu = i64::from(self.cfg.max_pdu).min(peer.local_detail.unwrap_or(i64::from(self.cfg.max_pdu)));
        let mine = i64::from(self.cfg.max_outstanding);
        let mut init = Initiate::request(max_pdu, mine, PARAMETER_CBB, SERVICES_SUPPORTED);
        // ISO 9506 negotiates *down*, exactly as `localDetail` above does: the negotiated
        // value may not exceed what the client proposed. Answering with this server's own
        // configuration regardless would tell a client that asked for two that it may have
        // ten, and the limit each end enforces would then be a different number.
        init.max_serv_outstanding_calling = mine.min(peer.max_serv_outstanding_calling.max(1));
        init.max_serv_outstanding_called = mine.min(peer.max_serv_outstanding_called.max(1));
        let initiate = Mms::InitiateResponse(init).to_vec()?;
        let responding = self.cfg.local.ap_title_element();
        let responding_q = self.cfg.local.ae_qualifier_element();
        let aare = Associate {
            protocol_version: Some((7, &[0x80])),
            context_name: Some(Oid::MMS_APPLICATION_CONTEXT),
            result: Some(acse::RESULT_ACCEPTED),
            responding_ap_title: responding.as_deref(),
            responding_ae_qualifier: responding_q.as_deref(),
            user_information: Some(acse::UserInformation {
                direct_reference: Some(Oid::BER),
                indirect_reference: Some(i64::from(mms_context)),
                value: &initiate,
            }),
            ..Associate::default()
        };
        let aare_bytes = Apdu::AssociateResponse(aare).to_vec()?;
        // One result per proposed context, in the order they were proposed — which is what
        // makes the identifiers in the CPA line up with the ones the client will use.
        let results: Vec<ContextResult<'_>> =
            cp.contexts.iter().map(|_: &ContextDefinition<'_>| ContextResult { result: RESULT_ACCEPTANCE, transfer_syntax: Some(Oid::BER) }).collect();
        let cpa = Cp {
            protocol_version: Some((7, &[0x80])),
            responding_psel: Some(&self.cfg.local.p_sel),
            results,
            requirements: Some((6, &[0x00])),
            user_data: alloc::vec![Pdv::single(acse_context, &aare_bytes)],
            ..Cp::default()
        };
        let ppdu = Ppdu::Accept(cpa).to_vec()?;
        let mut spdu = Vec::new();
        Spdu::Accept(session::Connect::new(Some(&self.cfg.local.s_sel), Some(&self.cfg.remote.s_sel), &ppdu)).write(&mut spdu)?;
        self.send_tsdu(&spdu)
    }

    fn send_user_data(&mut self, context: u16, value: &[u8]) -> Result<()> {
        let ppdu = Ppdu::UserData(alloc::vec![Pdv::single(context, value)]).to_vec()?;
        let mut spdu = Vec::new();
        Spdu::DataTransfer(&ppdu).write(&mut spdu)?;
        self.send_tsdu(&spdu)
    }

    /// Send a PDU without the peer-size check — used for the answers the association owes
    /// whatever the negotiated size is.
    fn send_pdu_unchecked(&mut self, pdu: &Mms<'_>) -> Result<()> {
        let bytes = pdu.to_vec()?;
        let context = self.mms_context;
        self.send_user_data(context, &bytes)
    }

    /// Split a TSDU across DT TPDUs and frame each in TPKT.
    fn send_tsdu(&mut self, tsdu: &[u8]) -> Result<()> {
        let chunk = self.tpdu_data.max(1);
        let mut at = 0usize;
        loop {
            let end = at.saturating_add(chunk).min(tsdu.len());
            let payload = tsdu.get(at..end).unwrap_or(&[]);
            let eot = end >= tsdu.len();
            let mut body = Vec::with_capacity(payload.len() + 3);
            Tpdu::Data { eot, payload }.write(&mut body)?;
            self.queue_tpkt(&body)?;
            at = end;
            if eot {
                return Ok(());
            }
        }
    }

    fn queue_tpkt(&mut self, tpdu: &[u8]) -> Result<()> {
        let header = tpkt::header(tpdu.len())?;
        let mut packet = Vec::with_capacity(tpkt::HEADER_LEN + tpdu.len());
        packet.extend_from_slice(&header);
        packet.extend_from_slice(tpdu);
        self.out.push_back(packet);
        Ok(())
    }

    // ---- bookkeeping ---------------------------------------------------------------

    fn established(&mut self, n: Negotiated) {
        self.state = State::Established;
        self.connect_deadline = None;
        self.negotiated = Some(n);
        self.emit(AssociationEvent::Established(n));
    }

    fn arm_connect_deadline(&mut self, now: Instant) {
        if self.cfg.connect_timeout_ms > 0 {
            self.connect_deadline = Some(now.plus_millis(self.cfg.connect_timeout_ms));
        }
    }

    fn close(&mut self, reason: CloseReason) {
        if matches!(self.state, State::Closed) {
            return;
        }
        self.state = State::Closed;
        self.connect_deadline = None;
        self.outstanding.clear();
        self.reassembler.reset();
        self.emit(AssociationEvent::Closed(reason));
    }

    /// Invoke identifiers are non-negative and wrap below the 32-bit ceiling every peer
    /// assumes; the value is skipped while one with the same number is still outstanding, so
    /// a long-lived association cannot answer the wrong request after a wrap.
    fn take_invoke_id(&mut self) -> i64 {
        // At most one attempt per outstanding request plus one: the only values that can be
        // skipped are the ones still in flight, and there are never more of those than
        // `max_outstanding`.
        for _ in 0..=self.outstanding.len() {
            let id = self.next_invoke;
            self.next_invoke = if self.next_invoke >= i64::from(u32::MAX) { 1 } else { self.next_invoke + 1 };
            if !self.outstanding.contains_key(&id) {
                return id;
            }
        }
        self.next_invoke
    }

    fn emit(&mut self, event: AssociationEvent) {
        self.events.push(event);
        self.stats.events_dropped = self.events.dropped();
    }
}

/// `parameterCBB` — what a peer may use against us: `str1`, `str2`, `vnam`, `valt`, `vlis`.
///
/// Eleven bits, five of them set, which is what libiec61850 sends and what the reference
/// capture's client sends. `vsca`, `tpy` and `vadr` are not claimed because the services
/// behind them are not implemented, and a claimed bit that is not backed by code is a peer
/// sending a request that gets a reject.
const PARAMETER_CBB: (u8, &[u8]) = (5, &[0xF1, 0x00]);

/// `servicesSupported` — exactly the services this association can issue or answer, and no
/// others.
///
/// Bit 0 is the most significant bit of the first octet. Set here:
/// `getNameList(1)`, `identify(2)`, `read(4)`, `write(5)`,
/// `getVariableAccessAttributes(6)`, `defineNamedVariableList(11)`,
/// `getNamedVariableListAttributes(12)`, `deleteNamedVariableList(13)`, `readJournal(65)`,
/// `fileOpen(72)`, `fileRead(73)`, `fileClose(74)`, `fileDelete(76)`, `fileDirectory(77)`,
/// `informationReport(79)` and `conclude(82)`.
///
/// It is deliberately not the whole table copied from another stack: a bit claimed here and
/// not backed by code is a peer sending a request that gets a reject. `status(0)` is
/// therefore *not* claimed — the reference capture's client does not claim it either.
const SERVICES_SUPPORTED: (u8, &[u8]) = (4, &[0x6E, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xED, 0x20]);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::mms::{ObjectName, ObjectScope, Unconfirmed, VariableAccess, VariableSpecification, object_class};

    fn pair() -> (Association, Association) {
        let cfg = AssociationConfig::default();
        (Association::client(cfg.clone()), Association::server(cfg))
    }

    /// Move everything one side wants to send into the other, until neither has anything.
    fn pump(a: &mut Association, b: &mut Association, now: Instant) {
        for _ in 0..32 {
            let mut moved = false;
            while let Some(packet) = a.poll_transmit() {
                let packet = packet.to_vec();
                b.on_bytes(now, &packet);
                moved = true;
            }
            while let Some(packet) = b.poll_transmit() {
                let packet = packet.to_vec();
                a.on_bytes(now, &packet);
                moved = true;
            }
            if !moved {
                return;
            }
        }
        panic!("the two ends never went quiet");
    }

    fn events(a: &mut Association) -> Vec<AssociationEvent> {
        let mut v = Vec::new();
        while let Some(e) = a.poll_event() {
            v.push(e);
        }
        v
    }

    fn connect() -> (Association, Association) {
        let (mut c, mut s) = pair();
        c.start(Instant::ZERO).unwrap();
        pump(&mut c, &mut s, Instant::ZERO);
        (c, s)
    }

    /// ISO 9506 negotiates the outstanding-call budget *down*, exactly as it does the PDU
    /// size. A server that answers with its own configuration regardless tells a client that
    /// asked for two that it may have ten, and the two ends then enforce different numbers.
    #[test]
    fn the_outstanding_call_budget_is_negotiated_down_from_both_sides() {
        for (client_max, server_max) in [(2u8, 10u8), (10, 2), (4, 4)] {
            let c_cfg = AssociationConfig { max_outstanding: client_max, ..AssociationConfig::default() };
            let s_cfg = AssociationConfig { max_outstanding: server_max, ..AssociationConfig::default() };
            let (mut c, mut s) = (Association::client(c_cfg), Association::server(s_cfg));
            c.start(Instant::ZERO).unwrap();
            pump(&mut c, &mut s, Instant::ZERO);
            let agreed = usize::from(client_max.min(server_max));
            assert_eq!(c.negotiated().unwrap().max_outstanding, agreed, "client with {client_max} against server with {server_max}");
            assert_eq!(s.negotiated().unwrap().max_outstanding, agreed, "server with {server_max} against client with {client_max}");
        }
    }

    /// The budget is the one `call` enforces, so the negotiation is not cosmetic.
    #[test]
    fn a_client_may_not_exceed_the_budget_the_server_agreed_to() {
        let c_cfg = AssociationConfig { max_outstanding: 10, request_timeout_ms: 0, ..AssociationConfig::default() };
        let s_cfg = AssociationConfig { max_outstanding: 2, ..AssociationConfig::default() };
        let (mut c, mut s) = (Association::client(c_cfg), Association::server(s_cfg));
        c.start(Instant::ZERO).unwrap();
        pump(&mut c, &mut s, Instant::ZERO);
        let req = ConfirmedRequest::Identify;
        assert!(c.call(Instant::ZERO, &req).is_ok());
        assert!(c.call(Instant::ZERO, &req).is_ok());
        assert!(matches!(c.call(Instant::ZERO, &req), Err(Error::LimitExceeded { limit: "max_outstanding", .. })), "the third exceeds the agreed two");
    }

    /// A COTP disconnect request has to name the reference the *peer* issued. Hard-coding it
    /// worked only because this crate's own server also hard-coded the same number — the
    /// self-consistency trap the reference-capture tests exist to catch.
    #[test]
    fn a_disconnect_request_names_the_reference_the_peer_issued() {
        let mut c = Association::client(AssociationConfig::default());
        c.start(Instant::ZERO).unwrap();
        while c.poll_transmit().is_some() {}
        // A connection confirm from a peer that picked its own reference, as a real IED does.
        let cc = cotp::Connect { dst_ref: 1, src_ref: 0x1234, class_options: 0, tpdu_size_exp: Some(cotp::TPDU_SIZE_MAX_EXP), src_tsel: None, dst_tsel: None };
        let mut body = Vec::new();
        Tpdu::ConnectionConfirm(cc).write(&mut body).unwrap();
        let mut packet = tpkt::header(body.len()).unwrap().to_vec();
        packet.extend_from_slice(&body);
        c.on_bytes(Instant::ZERO, &packet);
        // Drain the association request the confirm triggered, then abort.
        while c.poll_transmit().is_some() {}
        c.abort();
        let dr = c.poll_transmit().expect("a disconnect request").to_vec();
        let tpdu = Tpdu::parse(dr.get(tpkt::HEADER_LEN..).unwrap()).unwrap();
        assert!(matches!(tpdu, Tpdu::DisconnectRequest { dst_ref: 0x1234, src_ref: LOCAL_REF, .. }), "{tpdu:?}");
    }

    /// ISO 9506's `reject-PDU` **answers** the request it names, so it releases that invoke.
    /// Handing it up as an unconfirmed PDU — a report — instead leaves the identifier
    /// outstanding, and the caller waits out its whole request timeout for an answer that has
    /// already arrived, then reports silence rather than the reason.
    #[test]
    fn a_reject_answers_the_request_it_names_and_releases_it() {
        use crate::proto::mms::reject::{Reject, RejectReason, UNRECOGNIZED_SERVICE};

        let (mut c, mut s) = connect();
        let id = c.call(Instant::ZERO, &ConfirmedRequest::Identify).unwrap();
        pump(&mut c, &mut s, Instant::ZERO);
        assert_eq!(c.outstanding(), 1);
        let _ = events(&mut c);

        // The server rejects it rather than answering the service.
        s.send(&Mms::Reject(Reject::confirmed_request(id, UNRECOGNIZED_SERVICE))).unwrap();
        pump(&mut c, &mut s, Instant::ZERO);

        assert_eq!(c.outstanding(), 0, "the reject released the invoke identifier");
        assert_eq!(c.stats().rejected, 1);
        let seen = events(&mut c);
        assert!(
            matches!(
                seen.as_slice(),
                [AssociationEvent::Rejected { invoke_id: Some(got), reject: Reject { reason: RejectReason::ConfirmedRequest(UNRECOGNIZED_SERVICE), .. } }]
                    if *got == id
            ),
            "{seen:?}"
        );
        // …and it is not counted as a report.
        assert_eq!(c.stats().reports_received, 0);
    }

    /// A reject that names no request cannot release one, but it still has to be reported —
    /// it is the peer saying it could not read what we sent.
    #[test]
    fn a_reject_without_an_invoke_identifier_is_still_reported() {
        use crate::proto::mms::reject::{INVALID_PDU, Reject, RejectReason};

        let (mut c, mut s) = connect();
        let id = c.call(Instant::ZERO, &ConfirmedRequest::Identify).unwrap();
        pump(&mut c, &mut s, Instant::ZERO);
        let _ = events(&mut c);

        s.send(&Mms::Reject(Reject::pdu_error(INVALID_PDU))).unwrap();
        pump(&mut c, &mut s, Instant::ZERO);

        assert_eq!(c.outstanding(), 1, "nothing was named, so nothing is released");
        let seen = events(&mut c);
        assert!(
            matches!(seen.as_slice(), [AssociationEvent::Rejected { invoke_id: None, reject: Reject { reason: RejectReason::PduError(INVALID_PDU), .. } }]),
            "{seen:?}"
        );
        let _ = id;
    }

    #[test]
    fn the_two_ends_complete_the_six_layer_handshake() {
        let (mut c, mut s) = connect();
        assert!(c.is_established(), "client state {:?}", c.state());
        assert!(s.is_established(), "server state {:?}", s.state());
        assert!(matches!(events(&mut c).as_slice(), [AssociationEvent::Established(_)]));
        assert!(matches!(events(&mut s).as_slice(), [AssociationEvent::Established(_)]));
        let n = c.negotiated().unwrap();
        assert_eq!(n.mms_context, MMS_CONTEXT);
        assert_eq!(n.tpdu_data, cotp::tpdu_size(cotp::TPDU_SIZE_MAX_EXP) - 3, "class 0 negotiates down, so both ends land on the smaller proposal");
        assert_eq!(n.max_pdu, AssociationConfig::default().max_pdu as usize);
        assert_eq!(c.next_timeout(), None, "an established association waits for nothing by itself");
    }

    #[test]
    fn a_request_reaches_the_server_and_its_answer_comes_back() {
        let (mut c, mut s) = connect();
        let (_, _) = (events(&mut c), events(&mut s));
        let now = Instant::ZERO;

        let id = c.call(now, &ConfirmedRequest::Identify).unwrap();
        assert_eq!(c.outstanding(), 1);
        assert_eq!(c.next_timeout(), Some(now.plus_millis(30_000)));
        pump(&mut c, &mut s, now);

        let seen = events(&mut s);
        let [AssociationEvent::Request { invoke_id, pdu }] = seen.as_slice() else {
            panic!("the server saw no request: {seen:?}");
        };
        assert_eq!(*invoke_id, id);
        assert!(matches!(Mms::parse(pdu, &Limits::DEFAULT).unwrap(), Mms::ConfirmedRequest { service: ConfirmedRequest::Identify, .. }));

        s.respond(id, &ConfirmedResponse::Identify { vendor: "hupe1980", model: "iec61850-rs", revision: "0.1" }).unwrap();
        pump(&mut c, &mut s, now);

        let seen = events(&mut c);
        let [AssociationEvent::Response { invoke_id, pdu }] = seen.as_slice() else {
            panic!("the client saw no response: {seen:?}");
        };
        assert_eq!(*invoke_id, id);
        let Mms::ConfirmedResponse { service: ConfirmedResponse::Identify { vendor, .. }, .. } = Mms::parse(pdu, &Limits::DEFAULT).unwrap() else {
            panic!("not an Identify response");
        };
        assert_eq!(vendor, "hupe1980");
        assert_eq!(c.outstanding(), 0, "the answer releases the invoke identifier");
        assert_eq!(c.next_timeout(), None);
        assert_eq!(c.stats().requests_sent, 1);
        assert_eq!(c.stats().responses_received, 1);
    }

    #[test]
    fn a_report_arrives_unsolicited() {
        let (mut c, mut s) = connect();
        let (_, _) = (events(&mut c), events(&mut s));
        let report = Mms::Unconfirmed(Unconfirmed::InformationReport {
            access: VariableAccess::VariableListName(ObjectName::DomainSpecific { domain: "IED1LD0", item: "LLN0$RP$urcb01" }),
            results: Vec::new(),
        });
        s.send(&report).unwrap();
        pump(&mut c, &mut s, Instant::ZERO);
        assert!(matches!(events(&mut c).as_slice(), [AssociationEvent::Unconfirmed { .. }]));
        assert_eq!(c.stats().reports_received, 1);
    }

    #[test]
    fn a_request_that_is_never_answered_times_out_and_frees_its_slot() {
        let (mut c, mut s) = connect();
        let (_, _) = (events(&mut c), events(&mut s));
        let now = Instant::ZERO;
        let id =
            c.call(now, &ConfirmedRequest::GetNameList { object_class: object_class::DOMAIN, scope: ObjectScope::VmdSpecific, continue_after: None }).unwrap();
        // Deliberately do not pump: the request is on the wire and nothing answers it.
        c.on_timeout(now.plus_millis(29_999));
        assert!(events(&mut c).is_empty(), "not yet");
        c.on_timeout(now.plus_millis(30_000));
        assert_eq!(events(&mut c).as_slice(), [AssociationEvent::Timeout { invoke_id: id }]);
        assert_eq!(c.outstanding(), 0);
        assert!(c.is_established(), "one unanswered request does not end an association");
        let _ = s;
    }

    #[test]
    fn the_outstanding_limit_is_enforced_here_rather_than_discovered_as_a_reject() {
        let cfg = AssociationConfig { max_outstanding: 2, ..AssociationConfig::default() };
        let (mut c, mut s) = (Association::client(cfg.clone()), Association::server(cfg));
        c.start(Instant::ZERO).unwrap();
        pump(&mut c, &mut s, Instant::ZERO);
        let now = Instant::ZERO;
        c.call(now, &ConfirmedRequest::Identify).unwrap();
        c.call(now, &ConfirmedRequest::Identify).unwrap();
        assert!(matches!(c.call(now, &ConfirmedRequest::Identify), Err(Error::LimitExceeded { limit: "max_outstanding", .. })));
    }

    #[test]
    fn the_clients_budget_is_the_calling_one_and_the_servers_is_the_called_one() {
        // `negotiatedMaxServOutstandingCalling` limits the calling end; `…Called` is the
        // responder's own budget. Reading the wrong one lets a client put more requests on
        // the wire than the server agreed to answer, which surfaces as a reject with no
        // invoke identifier a caller can tie to anything.
        let cfg = AssociationConfig { max_outstanding: 40, ..AssociationConfig::default() };
        let mut c = Association::client(cfg);
        c.start(Instant::ZERO).unwrap();
        let _cr = c.poll_transmit().map(<[u8]>::to_vec).unwrap();
        c.on_bytes(
            Instant::ZERO,
            &tpkt_packet(&{
                let cc = cotp::Connect { dst_ref: 1, src_ref: 2, class_options: 0, tpdu_size_exp: Some(10), src_tsel: None, dst_tsel: None };
                let mut body = Vec::new();
                Tpdu::ConnectionConfirm(cc).write(&mut body).unwrap();
                body
            }),
        );
        let _connect = c.poll_transmit().map(<[u8]>::to_vec).unwrap();

        // A server answering "you may have 5 outstanding, I may have 1".
        let mut init = Initiate::request(16_000, 10, PARAMETER_CBB, SERVICES_SUPPORTED);
        init.max_serv_outstanding_calling = 5;
        init.max_serv_outstanding_called = 1;
        c.on_bytes(Instant::ZERO, &tpkt_packet(&server_accept(&init)));
        assert!(c.is_established(), "state {:?}, events {:?}", c.state(), events(&mut c));
        assert_eq!(c.negotiated().unwrap().max_outstanding, 5, "the calling budget, not the called one");
    }

    /// Wrap a TPDU in TPKT, the way the transport under an association does.
    fn tpkt_packet(tpdu: &[u8]) -> Vec<u8> {
        let mut p = tpkt::header(tpdu.len()).unwrap().to_vec();
        p.extend_from_slice(tpdu);
        p
    }

    /// A session ACCEPT carrying a CPA, an accepting AARE and `init`, as a server sends it.
    fn server_accept(init: &Initiate<'_>) -> Vec<u8> {
        let initiate = Mms::InitiateResponse(*init).to_vec().unwrap();
        let aare = Apdu::AssociateResponse(Associate {
            protocol_version: Some((7, &[0x80])),
            context_name: Some(Oid::MMS_APPLICATION_CONTEXT),
            result: Some(acse::RESULT_ACCEPTED),
            user_information: Some(acse::UserInformation { direct_reference: Some(Oid::BER), indirect_reference: Some(3), value: &initiate }),
            ..Associate::default()
        })
        .to_vec()
        .unwrap();
        let cpa = Cp {
            protocol_version: Some((7, &[0x80])),
            results: alloc::vec![
                ContextResult { result: RESULT_ACCEPTANCE, transfer_syntax: Some(Oid::BER) },
                ContextResult { result: RESULT_ACCEPTANCE, transfer_syntax: Some(Oid::BER) },
            ],
            user_data: alloc::vec![Pdv::single(ACSE_CONTEXT, &aare)],
            ..Cp::default()
        };
        let ppdu = Ppdu::Accept(cpa).to_vec().unwrap();
        let mut spdu = Vec::new();
        Spdu::Accept(session::Connect::new(None, None, &ppdu)).write(&mut spdu).unwrap();
        let mut body = Vec::new();
        Tpdu::Data { eot: true, payload: &spdu }.write(&mut body).unwrap();
        body
    }

    #[test]
    fn a_handshake_that_never_finishes_expires() {
        let mut c = Association::client(AssociationConfig::default());
        c.start(Instant::ZERO).unwrap();
        assert_eq!(c.next_timeout(), Some(Instant::ZERO.plus_millis(10_000)));
        c.on_timeout(Instant::ZERO.plus_millis(10_000));
        assert_eq!(events(&mut c).as_slice(), [AssociationEvent::Closed(CloseReason::ConnectTimeout)]);
        assert_eq!(c.state(), State::Closed);
        assert!(c.call(Instant::ZERO, &ConfirmedRequest::Identify).is_err());
    }

    #[test]
    fn an_orderly_release_ends_both_ends() {
        let (mut c, mut s) = connect();
        let (_, _) = (events(&mut c), events(&mut s));
        c.release(Instant::ZERO).unwrap();
        pump(&mut c, &mut s, Instant::ZERO);
        assert_eq!(events(&mut s).as_slice(), [AssociationEvent::Closed(CloseReason::PeerReleased)]);
        assert_eq!(events(&mut c).as_slice(), [AssociationEvent::Closed(CloseReason::Released)]);
        assert_eq!(c.state(), State::Closed);
    }

    #[test]
    fn a_release_the_peer_never_confirms_is_still_a_release() {
        let (mut c, mut s) = connect();
        let (_, _) = (events(&mut c), events(&mut s));
        c.release(Instant::ZERO).unwrap();
        // Throw the FINISH away instead of delivering it: the peer never answers.
        while c.poll_transmit().is_some() {}
        c.on_timeout(Instant::ZERO.plus_millis(10_000));
        assert_eq!(events(&mut c).as_slice(), [AssociationEvent::Closed(CloseReason::Released)], "not a handshake timeout");
        assert_eq!(c.state(), State::Closed);
    }

    #[test]
    fn a_tsdu_larger_than_a_tpdu_is_segmented_and_reassembled() {
        // The reference capture never segments, so this is the case a capture cannot check.
        // 128-octet TPDUs against a read of forty variables forces several DT TPDUs.
        let cfg = AssociationConfig { tpdu_size_exp: cotp::TPDU_SIZE_MIN_EXP, ..AssociationConfig::default() };
        let (mut c, mut s) = (Association::client(cfg.clone()), Association::server(cfg));
        c.start(Instant::ZERO).unwrap();
        pump(&mut c, &mut s, Instant::ZERO);
        assert!(c.is_established(), "even the handshake needs more than one TPDU here");
        let (_, _) = (events(&mut c), events(&mut s));

        let names: Vec<VariableSpecification<'_>> =
            (0..40).map(|_| VariableSpecification::Name(ObjectName::DomainSpecific { domain: "IED1LD0", item: "MMXU1$MX$TotW$mag$f" })).collect();
        let id = c.call(Instant::ZERO, &ConfirmedRequest::Read { specification_with_result: false, access: VariableAccess::ListOfVariable(names) }).unwrap();
        let before = c.stats().packets_sent;
        pump(&mut c, &mut s, Instant::ZERO);
        assert!(c.stats().packets_sent > before + 1, "the read fitted one TPDU, so nothing was segmented: {:?}", c.stats());
        let seen = events(&mut s);
        let [AssociationEvent::Request { invoke_id, pdu }] = seen.as_slice() else {
            panic!("the segmented request did not arrive whole: {seen:?}");
        };
        assert_eq!(*invoke_id, id);
        let Mms::ConfirmedRequest { service: ConfirmedRequest::Read { access: VariableAccess::ListOfVariable(v), .. }, .. } =
            Mms::parse(pdu, &Limits::DEFAULT).unwrap()
        else {
            panic!("not a read");
        };
        assert_eq!(v.len(), 40, "every variable survived the segmentation");
    }

    #[test]
    fn a_password_travels_in_the_aarq_where_the_server_looks_for_it() {
        let cfg = AssociationConfig {
            password: Some(String::from("s3cret")),
            local: Selectors { ap_title: Some(alloc::vec![1, 3, 9999, 33]), ae_qualifier: Some(12), ..Selectors::defaults() },
            remote: Selectors { ap_title: Some(alloc::vec![1, 3, 9999, 23]), ..Selectors::defaults() },
            ..AssociationConfig::default()
        };
        let mut c = Association::client(cfg);
        c.start(Instant::ZERO).unwrap();
        // The CR, then the session CONNECT carrying the AARQ.
        let _cr = c.poll_transmit().map(<[u8]>::to_vec).unwrap();
        c.on_bytes(Instant::ZERO, &{
            let cc = cotp::Connect { dst_ref: 1, src_ref: 2, class_options: 0, tpdu_size_exp: Some(10), src_tsel: None, dst_tsel: None };
            let mut body = Vec::new();
            Tpdu::ConnectionConfirm(cc).write(&mut body).unwrap();
            let mut p = tpkt::header(body.len()).unwrap().to_vec();
            p.extend_from_slice(&body);
            p
        });
        let connect = c.poll_transmit().map(<[u8]>::to_vec).expect("the session CONNECT");
        let spdu = &connect[tpkt::HEADER_LEN + 3..];
        let Spdu::Connect(sc) = Spdu::parse(spdu).unwrap() else { panic!("not a CONNECT") };
        let Ppdu::Connect(cp) = Ppdu::parse(sc.user_data, true).unwrap() else { panic!("not a CP") };
        let aarq = cp.user_data.iter().find(|p| p.context_id == ACSE_CONTEXT).and_then(|p| p.values.single()).unwrap();
        let Apdu::Associate(a) = Apdu::parse(aarq).unwrap() else { panic!("not an AARQ") };
        assert_eq!(a.mechanism_name, Some(Oid::PASSWORD_MECHANISM));
        assert_eq!(a.authentication_value, Some(&[0x80, 6, b's', b'3', b'c', b'r', b'e', b't'][..]));
        assert!(a.calling_ap_title.is_some() && a.called_ap_title.is_some());
        assert_eq!(a.calling_ae_qualifier, Some(&[0x02, 0x01, 12][..]), "form 2 is an INTEGER element");
        assert!(a.mms_pdu().is_some());
    }

    #[test]
    fn a_stream_that_is_not_the_protocol_closes_the_association_rather_than_looping() {
        let mut c = Association::client(AssociationConfig::default());
        c.start(Instant::ZERO).unwrap();
        c.on_bytes(Instant::ZERO, &[0x16, 0x03, 0x01, 0x00, 0x05]); // a TLS record on port 102
        assert_eq!(c.state(), State::Closed);
        assert_eq!(events(&mut c).as_slice(), [AssociationEvent::Closed(CloseReason::ProtocolError)]);
    }

    #[test]
    fn services_supported_names_exactly_the_services_that_exist() {
        let (unused, bytes) = SERVICES_SUPPORTED;
        let bit = |n: usize| bytes.get(n / 8).is_some_and(|b| b >> (7 - (n % 8)) & 1 == 1);
        for n in [1, 2, 4, 5, 6, 11, 12, 13, 65, 72, 73, 74, 76, 77, 79, 82] {
            assert!(bit(n), "service {n} is implemented and must be claimed");
        }
        for n in [0, 3, 7, 46, 75, 80, 81] {
            assert!(!bit(n), "service {n} is not implemented and must not be claimed");
        }
        assert_eq!(bytes.len() * 8 - usize::from(unused), 84, "the highest claimed bit is 82");
    }

    #[test]
    fn invoke_identifiers_do_not_collide_after_a_wrap() {
        let (mut c, mut s) = connect();
        let (_, _) = (events(&mut c), events(&mut s));
        c.next_invoke = i64::from(u32::MAX) - 1;
        let ids: Vec<i64> = (0..4).map(|_| c.call(Instant::ZERO, &ConfirmedRequest::Identify).unwrap()).collect();
        // It wraps past the ceiling to 1, and then skips the values still outstanding.
        assert_eq!(ids, [i64::from(u32::MAX) - 1, i64::from(u32::MAX), 1, 2]);
    }
}
