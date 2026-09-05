//! Sans-IO protocol cores: codecs and state machines that own no socket, thread or clock.
//!
//! The process-bus protocols share the Ethernet framing in [`ethernet`] and the MMS
//! `Data` encoding in [`data`]; GOOSE and Sampled Values each get a module. `osi` is the
//! stack IEC 61850-8-1 puts under MMS — TPKT, COTP, session, presentation and ACSE.

pub mod data;
#[cfg(any(feature = "goose", feature = "sv"))]
pub mod ethernet;
#[cfg(feature = "goose")]
pub mod goose;
#[cfg(feature = "mms")]
pub mod mms;
#[cfg(feature = "mms")]
pub mod osi;
#[cfg(feature = "sv")]
pub mod sv;
