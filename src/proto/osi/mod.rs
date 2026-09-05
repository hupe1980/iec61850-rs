//! The OSI upper layers IEC 61850-8-1 puts under MMS.
//!
//! MMS does not run on TCP. It runs on the ISO application layer, and IEC 61850-8-1 mandates
//! the whole stack under it: ACSE for the association, presentation for the context list and
//! the encoding, session for the connect handshake, COTP class 0 for the data unit, and TPKT
//! to frame all of that over TCP. Six layers, most of which do almost nothing on this
//! profile, and every one of which a client has to get exactly right before a single value
//! can be read.
//!
//! Each layer here is a codec, not a connection: parse bytes, build bytes, no sockets and no
//! clocks — the same shape the process-bus cores have. The two stateful pieces are the ones
//! that must be stateful, [`tpkt::Reader`] (TCP is a stream and a TPKT header can arrive
//! split in two) and [`cotp::Reassembler`] (one TSDU may span several TPDUs).

pub mod acse;
pub mod cotp;
pub mod oid;
pub mod presentation;
pub mod session;
pub mod tpkt;

pub use oid::Oid;
