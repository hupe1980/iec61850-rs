//! IEC 61850 for the substation process bus and the station bus.
//!
//! The **process bus** protocols carry protection signals and instrument-transformer
//! measurements between intelligent electronic devices: **GOOSE** (IEC 61850-8-1) and
//! **Sampled Values** (IEC 61850-9-2, the 9-2LE guideline, and IEC 61869-9). Both run as
//! multicast frames directly over Ethernet, with no transport layer beneath them to absorb a
//! mistake.
//!
//! The **station bus** carries **MMS** (ISO 9506), which IEC 61850-8-1 maps ACSI onto — and
//! the six OSI layers it needs underneath: TPKT, COTP class 0, session, presentation and
//! ACSE. Those are codecs here ([`proto::osi`], [`proto::mms`]), the association state
//! machine over them is [`proto::mms::association`], and there are blocking ends on both
//! sides of it: [`client`] browses, reads, writes, takes decoded and reassembled reports, runs
//! all four control models, pulls files, reads logs and edits setting groups; [`server`] does
//! the other half of every one of those, straight from an SCL file.
//!
//! # The shape of it
//!
//! Every protocol core in [`proto`] is *sans-IO*: it owns no socket, spawns no thread and
//! never reads a clock. It takes inputs with the caller's notion of "now", yields outputs,
//! and says when it wants to be called again.
//!
//! ```no_run
//! # // Gated so the example still compiles when the crate is built without `goose`.
//! # #[cfg(feature = "goose")]
//! # mod example {
//! # use iec61850_rs::common::Instant;
//! # use iec61850_rs::proto::goose::{Subscriber, SubscriberConfig, SubscriberEvent, SubscriptionKey};
//! # use iec61850_rs::proto::ethernet::MacAddr;
//! # pub fn run() -> iec61850_rs::Result<()> {
//! # let (frame, now) = (&[][..], Instant::ZERO);
//! let mut sub = Subscriber::new(SubscriberConfig::new(SubscriptionKey {
//!     dst: MacAddr::parse("01-0C-CD-01-00-05")?,
//!     appid: 0x0005,
//!     gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into(),
//! }));
//!
//! for event in sub.feed(now, frame) {
//!     match event {
//!         // The publisher's data changed.
//!         SubscriberEvent::NewState { st_num, values, .. } => { /* act on `values` */ }
//!         // Nothing arrived within `timeAllowedtoLive`: the inputs are no longer valid.
//!         SubscriberEvent::Expired => { /* fail safe */ }
//!         _ => {}
//!     }
//! }
//! sub.on_timeout(now);
//! let wake_at = sub.next_timeout();
//! # Ok(()) }
//! # }
//! # fn main() {}
//! ```
//!
//! The same code therefore runs under an async runtime, on a bare-metal timer, or inside a
//! deterministic simulation with no I/O at all — and builds `no_std` on an allocator alone.
//!
//! # Modules
//!
//! | Module | What it holds |
//! |---|---|
//! | [`common`] | The types every layer shares: [`UtcTime`], [`Quality`], [`ObjectReference`], [`Fc`], [`MacAddr`], [`Edition`], [`Limits`], and the IEC 61850-7-2 modelling types `TrgOps`, `OptFlds`, `ReasonCode`, [`ControlModel`](common::ControlModel) and [`ServiceType`](common::ServiceType) |
//! | [`ber`] | A panic-free BER codec for the subset IEC 61850 uses |
//! | [`proto`] | The protocol cores: Ethernet framing, MMS `Data`, GOOSE, Sampled Values |
//! | [`proto::sv::SampleLayout`] | What the octets of a sampled-value ASDU mean, read out of the engineering file |
//! | [`proto::osi`] | The OSI stack under MMS: TPKT and its stream reader, COTP class 0 and TSDU reassembly, session, presentation, ACSE (feature `mms`) |
//! | [`proto::mms`] | The MMS PDUs IEC 61850-8-1 uses, sharing their value codec with GOOSE (feature `mms`) |
//! | [`proto::mms::association`] | The association state machine over those six layers, for both roles (feature `mms`) |
//! | [`proto::mms::report`] | What an IEC 61850 report is on the wire, and what `OptFlds` decides (feature `mms`) |
//! | [`proto::mms::control`] | `Oper`, `SBOw`, `Cancel`, `LastApplError` and `AddCause` (feature `mms`) |
//! | [`proto::mms::file`] | `FileName`, `FileAttributes` and `DirectoryEntry` — the MMS file services (feature `mms`) |
//! | [`proto::mms::journal`] | What a log entry is on the wire, and the ranges `QueryLogByTime`/`QueryLogAfterEntry` map onto (feature `mms`) |
//! | [`proto::mms::typespec`] | `TypeSpecification` — what `GetVariableAccessAttributes` answers with (feature `mms`) |
//! | [`client`] | A blocking MMS client: browse, read, write, reporting, control, files, logs, setting groups (feature `client`) |
//! | [`server`] | A blocking MMS server: the SCL file is the namespace, with a report engine, the four control models, setting groups, service tracking, a sandboxed file store and logs (feature `server`) |
//! | [`model`] | The IED model a publisher takes its addresses and data sets from |
//! | [`scl`] | Reading that model out of an ICD, CID or SCD, resolving what an IED subscribes to, and checking the engineering the schema does not (feature `scl`) |
//! | [`pcap`] | Classic capture files, for replaying traffic and recording what was built (feature `pcap`) |
//!
//! # Safety and limits
//!
//! `#![forbid(unsafe_code)]` throughout, and `unwrap`, `expect`, `panic` and slice indexing
//! are denied by lint: a malformed frame becomes an [`Error`] carrying a reason and a byte
//! offset, never a panic. Decoders enforce [`Limits`] — nesting depth, data-set members,
//! primitive length, ASDUs per frame — *before* allocating, and the event queues every core
//! hands its output through are bounded and count what they drop.
//!
//! Once running, the publishers and the receive path allocate nothing: buffers are cleared
//! and rewritten, never regrown. That is asserted by a counting allocator, not claimed.
//!
//! # Status
//!
//! Pre-release. The process bus is tested against real substation captures; on the station
//! bus, the six OSI layers, the association over them and both ends above it are verified
//! against a real capture, against `tshark` and against each other over a socket. Not
//! included: the raw-socket adapters and the IEC 62351 security profiles.
//! The API will change, and nothing here has been through a conformance laboratory.
//!
//! The guide at <https://hupe1980.github.io/iec61850-rs/> covers the protocols themselves,
//! and is explicit about what is verified and what is not.

#![cfg_attr(not(feature = "std"), no_std)]
// docs.rs builds with every feature and on nightly, so each gated item can carry the
// feature that unlocks it. Answering "which feature do I need for this?" from the page
// itself is worth one nightly-only attribute.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::missing_panics_doc))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod ber;
#[cfg(feature = "client")]
pub mod client;
pub mod common;
pub mod model;
#[cfg(feature = "pcap")]
pub mod pcap;
#[cfg(any(feature = "goose", feature = "sv", feature = "mms"))]
pub mod proto;
#[cfg(feature = "scl")]
pub mod scl;
#[cfg(feature = "server")]
pub mod server;

/// The types most callers need, re-exported at the crate root.
pub use common::{Clock, DecodeReason, Edition, Error, Fc, Instant, Limits, MacAddr, ObjectReference, Quality, Result, TimeQuality, UtcTime, Validity};
