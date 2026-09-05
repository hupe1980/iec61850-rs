//! A blocking IEC 61850 server over TCP — the mirror of [`crate::client`].
//!
//! [`crate::proto::mms::association::Association`] is the same state machine the client
//! drives, in the server role; this is the socket and the accept loop around it. One thread
//! per association, one model behind one lock, and no runtime and no dependency — the same
//! trade the client makes, for the same reason: the sans-IO core is what an async wrapper
//! would be written against, so a runtime here would buy nothing and cost every caller.
//!
//! ```no_run
//! use iec61850_rs::server::{Ied, Server};
//!
//! # fn main() -> iec61850_rs::Result<()> {
//! let ied = Ied::from_scl(&std::fs::read_to_string("relay.cid")?, None)?;
//! let server = Server::bind("0.0.0.0:102", ied)?;
//!
//! // The application updates the model through a transaction; the commit is what makes the
//! // change visible to every client at once.
//! let updates = server.handle();
//! std::thread::spawn(move || {
//!     use iec61850_rs::proto::data::Value;
//!     updates.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
//! });
//!
//! server.run()?;
//! # Ok(()) }
//! ```

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant as StdInstant};

use super::acsi::{Acsi, AcsiConfig, AssocId};
use super::ied::Ied;
use crate::common::{Error, Instant, Result};
use crate::proto::data::Value;
use crate::proto::mms::Mms;
use crate::proto::mms::association::{Association, AssociationConfig, AssociationEvent, PORT};

/// How the server behaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// Association parameters — selectors, sizes, timeouts.
    pub association: AssociationConfig,
    /// ACSI parameters — what `Identify` answers, page budgets.
    pub acsi: AcsiConfig,
    /// Associations the server will hold open at once. Beyond this an accepted socket is
    /// closed immediately: an IED has a small, fixed number of association slots, and
    /// pretending otherwise is how one runs out of memory instead of refusing a connection.
    pub max_associations: usize,
    /// How long a connection thread waits on the socket before it looks at its outbound
    /// queue. It bounds how late a report can be, not how fast a response is.
    pub poll_interval: Duration,
}

impl Default for ServerConfig {
    fn default() -> ServerConfig {
        ServerConfig { association: AssociationConfig::default(), acsi: AcsiConfig::default(), max_associations: 16, poll_interval: Duration::from_millis(20) }
    }
}

/// What the connections and the application share: the model, and a way to reach each client.
#[derive(Debug)]
struct Shared {
    acsi: Acsi,
    /// One outbound queue per open association, for the PDUs the server sends unasked —
    /// reports and command terminations.
    outbound: BTreeMap<AssocId, Sender<Vec<u8>>>,
    next_assoc: AssocId,
}

/// Nanoseconds on a monotonic origin shared by every association of this process, so that a
/// report's gathering window means the same thing whichever thread closes it.
fn now_nanos() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<StdInstant> = OnceLock::new();
    EPOCH.get_or_init(StdInstant::now).elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

/// A blocking IEC 61850 server.
#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    shared: Arc<Mutex<Shared>>,
    cfg: ServerConfig,
}

/// A handle the application updates the model through, and asks what the server is doing.
///
/// Cloneable and `Send`: an application usually has one thread reading its process interface
/// and another serving clients, and this is the seam between them.
#[derive(Clone, Debug)]
pub struct ServerHandle {
    shared: Arc<Mutex<Shared>>,
}

impl Server {
    /// Bind and serve `ied`, with the defaults.
    ///
    /// `addr` may omit the port, in which case 102 is used — which needs privileges on most
    /// systems, so a test or a simulator usually asks for `127.0.0.1:0` and reads
    /// [`Server::local_addr`] back.
    pub fn bind(addr: &str, ied: Ied) -> Result<Server> {
        Server::bind_with(addr, ied, &ServerConfig::default())
    }

    /// Bind and serve `ied` with an explicit configuration.
    pub fn bind_with(addr: &str, ied: Ied, cfg: &ServerConfig) -> Result<Server> {
        let with_port = if addr.rfind(':').is_some_and(|i| addr[i + 1..].chars().all(|c| c.is_ascii_digit()) && i + 1 < addr.len()) {
            String::from(addr)
        } else {
            format!("{addr}:{PORT}")
        };
        let target =
            with_port.to_socket_addrs().map_err(|e| Error::Io(format!("{addr}: {e}")))?.next().ok_or_else(|| Error::Io(format!("{addr}: no address")))?;
        let listener = TcpListener::bind(target).map_err(|e| Error::Io(format!("{addr}: {e}")))?;
        let mut acsi = Acsi::with_config(ied, cfg.acsi.clone());
        acsi.set_max_pdu(cfg.association.max_pdu as usize);
        Ok(Server { listener, shared: Arc::new(Mutex::new(Shared { acsi, outbound: BTreeMap::new(), next_assoc: 1 })), cfg: cfg.clone() })
    }

    /// The address the server is listening on, which is how a caller learns the port it got
    /// when it asked for zero.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(|e| Error::Io(e.to_string()))
    }

    /// A handle for the application to update the model through.
    pub fn handle(&self) -> ServerHandle {
        ServerHandle { shared: Arc::clone(&self.shared) }
    }

    /// Ask `hook` before every select, operate and cancel.
    ///
    /// Without one every command is accepted and applied to the object's status, which is
    /// what a simulator wants; a device installs a hook that drives the switchgear and
    /// refuses with the `AddCause` that says why.
    pub fn on_control(&mut self, hook: super::control::ControlHook) {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner).acsi.on_control(hook);
    }

    /// How long a select-before-operate selection is held before it expires.
    pub fn set_sbo_timeout_ms(&mut self, ms: u64) {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner).acsi.set_sbo_timeout_ms(ms);
    }

    /// Serve files from `store` — a [`DirectoryStore`](super::DirectoryStore) over a
    /// directory, or an application's own. Without one the server has no files.
    pub fn set_file_store(&mut self, store: Box<dyn super::files::FileStore>) {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner).acsi.set_file_store(store);
    }

    /// Accept associations for ever, one thread each.
    pub fn run(&self) -> Result<()> {
        loop {
            self.accept_one()?;
        }
    }

    /// Accept one association and serve it on a new thread.
    ///
    /// Returns as soon as the connection is handed over, so a test can accept a known number
    /// of clients without a background accept loop it then has to stop.
    pub fn accept_one(&self) -> Result<()> {
        let (stream, _) = self.listener.accept().map_err(|e| Error::Io(e.to_string()))?;
        let shared = Arc::clone(&self.shared);
        let cfg = self.cfg.clone();
        let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.outbound.len() >= cfg.max_associations {
            // Closing the socket is the honest answer: the association slots are full, and
            // accepting one we cannot serve would be worse than refusing it.
            drop(guard);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
        let id = guard.next_assoc;
        guard.next_assoc += 1;
        let (tx, rx) = channel();
        guard.outbound.insert(id, tx);
        drop(guard);

        std::thread::spawn(move || {
            let _ = serve(id, stream, &shared, &cfg, &rx);
            let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
            guard.outbound.remove(&id);
            guard.acsi.on_association_closed(id);
        });
        Ok(())
    }
}

impl ServerHandle {
    /// Begin a transaction. Nothing is visible to a client until [`Txn::commit`].
    pub fn txn(&self) -> Txn<'_> {
        Txn { handle: self, writes: Vec::new() }
    }

    /// Read a value out of the model, as a client would see it.
    pub fn read(&self, reference: &str) -> Option<Value> {
        let guard = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let (domain, item) = reference.split_once('/')?;
        guard.acsi.ied.read(domain, item)
    }

    /// Associations currently open.
    pub fn associations(&self) -> usize {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner).outbound.len()
    }

    /// Apply a batch of writes and publish what they trigger.
    fn commit(&self, writes: Vec<(String, Value)>) -> Vec<core::result::Result<(), i64>> {
        let mut guard = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = Vec::with_capacity(writes.len());
        for (reference, value) in writes {
            out.push(guard.acsi.ied.write_leaf(&reference, value));
        }
        publish(&mut guard, Instant(now_nanos()));
        out
    }
}

/// A batch of model updates that becomes visible all at once.
///
/// The application never locks anything: writes are collected here and [`Txn::commit`]
/// publishes them to reporting and logging together. That is the whole update model — what
/// was wrong with a lock-and-unlock discipline is not its granularity but that forgetting it
/// tears a report across two states of the model.
#[derive(Debug)]
pub struct Txn<'a> {
    handle: &'a ServerHandle,
    writes: Vec<(String, Value)>,
}

impl Txn<'_> {
    /// Stage a write of a data attribute, by full MMS reference.
    pub fn set(&mut self, reference: &str, value: Value) -> &mut Self {
        self.writes.push((String::from(reference), value));
        self
    }

    /// Apply everything staged. The result is one entry per write, in order.
    pub fn commit(&mut self) -> Vec<core::result::Result<(), i64>> {
        let writes = core::mem::take(&mut self.writes);
        if writes.is_empty() {
            return Vec::new();
        }
        self.handle.commit(writes)
    }
}

/// Turn whatever is dirty into reports and hand each to the association that asked for it.
fn publish(shared: &mut Shared, now: Instant) {
    let outbound: Vec<(AssocId, Sender<Vec<u8>>)> = shared.outbound.iter().map(|(id, tx)| (*id, tx.clone())).collect();
    for (assoc, pdu) in shared.acsi.commit(now) {
        if let Some((_, tx)) = outbound.iter().find(|(id, _)| *id == assoc) {
            let _ = tx.send(pdu);
        }
    }
}

/// One association, from the COTP connection request to the release.
fn serve(id: AssocId, mut stream: TcpStream, shared: &Arc<Mutex<Shared>>, cfg: &ServerConfig, outbound: &Receiver<Vec<u8>>) -> Result<()> {
    stream.set_nodelay(true).map_err(|e| Error::Io(e.to_string()))?;
    stream.set_read_timeout(Some(cfg.poll_interval)).map_err(|e| Error::Io(e.to_string()))?;
    let mut assoc = Association::server(cfg.association.clone());
    let mut buf = vec![0u8; 8192];
    let limits = cfg.association.limits;

    loop {
        let now = Instant(now_nanos());
        match stream.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => assoc.on_bytes(now, buf.get(..n).unwrap_or(&[])),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => assoc.on_timeout(now),
            Err(e) => return Err(Error::Io(e.to_string())),
        }

        {
            // A gathering window or an integrity period may have come due while this thread
            // was in the socket read, and nothing else will notice.
            let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
            let due = guard.acsi.on_timeout(now);
            let outbound: Vec<(AssocId, Sender<Vec<u8>>)> = guard.outbound.iter().map(|(id, tx)| (*id, tx.clone())).collect();
            for (assoc, pdu) in due {
                if let Some((_, tx)) = outbound.iter().find(|(id, _)| *id == assoc) {
                    let _ = tx.send(pdu);
                }
            }
        }

        let mut requests: Vec<(i64, Vec<u8>)> = Vec::new();
        let mut closed = false;
        while let Some(event) = assoc.poll_event() {
            match event {
                AssociationEvent::Request { invoke_id, pdu } => requests.push((invoke_id, pdu)),
                AssociationEvent::Closed(_) => closed = true,
                // A response, a timeout or an undecodable PDU on a server association: none
                // of them is a request, and none of them is a reason to drop the client.
                _ => {}
            }
        }

        for (invoke_id, pdu) in requests {
            let answer = {
                let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
                match Mms::parse(&pdu, &limits) {
                    Ok(Mms::ConfirmedRequest { service, .. }) => guard.acsi.request(id, now, &service),
                    // A PDU that is not a confirmed request cannot be answered as one.
                    _ => super::acsi::Answer::UNSUPPORTED,
                }
            };
            if let Ok(bytes) = answer.encode(invoke_id) {
                let _ = assoc.send_encoded(&bytes);
            }
            // A commit may have happened inside the request — a control that changed a
            // position, a `GI` that asked for a report — so the queues are drained below.
            let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
            publish(&mut guard, now);
        }

        loop {
            match outbound.try_recv() {
                Ok(pdu) => {
                    let _ = assoc.send_encoded(&pdu);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }

        while let Some(packet) = assoc.poll_transmit() {
            let packet = packet.to_vec();
            if stream.write_all(&packet).is_err() {
                return Ok(());
            }
        }
        let _ = stream.flush();
        if closed {
            return Ok(());
        }
    }
}
