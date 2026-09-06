//! Subscription supervision: what `LGOS` and `LSVS` publish about a stream this IED
//! *receives*.
//!
//! This is where the process bus and the station bus meet inside one IED. A GOOSE or
//! sampled-value subscriber already knows whether its stream is alive, whether the publisher
//! is asking to be commissioned, which `confRev` is arriving and whether what arrives is
//! simulated. IEC 61850-7-4 gives that a home — one `LGOS` per GOOSE subscription and one
//! `LSVS` per sampled-value subscription (TISSUE 1396/1401 🌐) — so a SCADA client can read it
//! and a report can carry it.
//!
//! The data objects, from a vendor MICS that states the class table 🌐:
//!
//! | Object | CDC | | What it says |
//! |---|---|---|---|
//! | `St` | SPS | **M** | the subscription is live — a frame was accepted and its `timeAllowedtoLive` has not run out |
//! | `NdsCom` | SPS | O | the publisher signals `ndsCom`: it needs commissioning and its data is not usable |
//! | `SimSt` | SPS | O | what is being accepted is *simulated* traffic |
//! | `LastStNum` | INS | O | the last `stNum` received (GOOSE only) |
//! | `ConfRevNum` | INS | O | the `confRev` this subscription **expects** |
//! | `RxConfRevNum` | INS | O | the `confRev` that is **arriving** |
//! | `GoCBRef` / `SvCBRef` | ORG | O (Ed2) / M (Ed2.1) | which control block is supervised |
//!
//! `GoCBRef` and `SvCBRef` are **settings**: they come from the SCL file and are not written
//! here. Everything else is status, and [`SubscriptionStatus`] is it.
//!
//! Two rules make this safe to call in a loop: only objects the file declares are written
//! (D9), and an unchanged status writes nothing, so a supervision poll does not make every
//! report control block fire once a second.
//!
//! ```no_run
//! # // Gated: `supervise` is a `server` feature and the subscriber it takes is a `goose` one.
//! # #[cfg(feature = "goose")]
//! # mod example {
//! # use iec61850_rs::server::{ServerHandle, SubscriptionStatus};
//! # pub fn run(updates: &ServerHandle, sub: &iec61850_rs::proto::goose::Subscriber) {
//! updates.txn().supervise("IED1LD0/LGOS1", &SubscriptionStatus::from_goose(sub)).commit();
//! # }
//! # }
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::common::UtcTime;
use crate::proto::data::Value;

/// The status one supervision logical node publishes about one subscription.
///
/// Build it from a subscriber with [`SubscriptionStatus::from_goose`] or
/// [`SubscriptionStatus::from_sv`], or fill it in by hand for a stream this crate does not
/// receive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionStatus {
    /// `St` — the subscription is live.
    pub live: bool,
    /// `NdsCom` — the publisher says it needs commissioning.
    pub needs_commissioning: bool,
    /// `SimSt` — what is being accepted is simulated traffic.
    pub simulated: bool,
    /// `LastStNum` — the last `stNum` received. `None` for a sampled-value stream, which has
    /// no state number.
    pub last_st_num: Option<u32>,
    /// `ConfRevNum` — the `confRev` this subscription expects, when it was engineered with one.
    pub expected_conf_rev: Option<u32>,
    /// `RxConfRevNum` — the `confRev` that is actually arriving.
    pub received_conf_rev: Option<u32>,
}

impl SubscriptionStatus {
    /// The status of a GOOSE subscription.
    #[cfg(feature = "goose")]
    pub fn from_goose(sub: &crate::proto::goose::Subscriber) -> SubscriptionStatus {
        SubscriptionStatus {
            live: sub.is_live(),
            needs_commissioning: sub.needs_commissioning(),
            simulated: sub.simulation_active(),
            last_st_num: sub.st_num(),
            expected_conf_rev: sub.config().expected_conf_rev,
            received_conf_rev: sub.conf_rev(),
        }
    }

    /// The status of one stream of a sampled-value subscriber.
    ///
    /// A sampled-value stream has no `stNum`, so `LastStNum` is absent rather than invented;
    /// "live" is the inverse of the subscriber's own staleness deadline, which is the closest
    /// thing sampled values have to a `timeAllowedtoLive`.
    #[cfg(feature = "sv")]
    pub fn from_sv(sub: &crate::proto::sv::Subscriber, stream: usize) -> Option<SubscriptionStatus> {
        let state = sub.state(stream)?;
        let cfg = sub.stream_config(stream)?;
        Some(SubscriptionStatus {
            // A stream that has never delivered an ASDU is not live either, which `stale`
            // alone does not say: nothing has gone quiet if nothing ever spoke.
            live: state.asdus > 0 && !state.stale,
            // Sampled values have no `ndsCom`; the field stays false rather than guessing.
            needs_commissioning: false,
            simulated: state.simulation_active,
            last_st_num: None,
            expected_conf_rev: cfg.expected_conf_rev,
            received_conf_rev: state.conf_rev,
        })
    }

    /// The candidate writes for a supervision logical node, as full MMS references.
    ///
    /// `node` is the logical node — `IED1LD0/LGOS1` or `IED1LD0/LSVS1`. Every reference is
    /// under `ST`, because all of it is status; the caller keeps the ones its model has.
    pub fn writes(&self, node: &str) -> Vec<(String, Value)> {
        let mut out: Vec<(String, Value)> = Vec::with_capacity(6);
        let mut boolean = |name: &str, v: bool| out.push((alloc::format!("{node}$ST${name}$stVal"), Value::Boolean(v)));
        boolean("St", self.live);
        boolean("NdsCom", self.needs_commissioning);
        boolean("SimSt", self.simulated);
        for (name, value) in [("LastStNum", self.last_st_num), ("ConfRevNum", self.expected_conf_rev), ("RxConfRevNum", self.received_conf_rev)] {
            if let Some(v) = value {
                out.push((alloc::format!("{node}$ST${name}$stVal"), Value::Integer(i64::from(v))));
            }
        }
        out
    }
}

/// The `q` and `t` that belong beside a status value that has just changed.
///
/// A `SPS` or an `INS` is `{stVal, q, t}`, and `t` is the moment `stVal` moved — not the
/// moment it was last polled. Stamping it on every poll would make a supervision loop a data
/// change once a second, and every report control block watching `LGOS` would fire.
pub(super) fn quality_and_time(reference: &str, now: UtcTime) -> [(String, Value); 2] {
    let object = reference.strip_suffix("$stVal").unwrap_or(reference);
    [(alloc::format!("{object}$q"), Value::quality(crate::common::Quality::GOOD)), (alloc::format!("{object}$t"), Value::UtcTime(now))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_writes_are_the_status_objects_under_st() {
        let status = SubscriptionStatus {
            live: true,
            needs_commissioning: false,
            simulated: true,
            last_st_num: Some(42),
            expected_conf_rev: Some(3),
            received_conf_rev: Some(4),
        };
        let writes = status.writes("IED1LD0/LGOS1");
        let names: Vec<&str> = writes.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "IED1LD0/LGOS1$ST$St$stVal",
                "IED1LD0/LGOS1$ST$NdsCom$stVal",
                "IED1LD0/LGOS1$ST$SimSt$stVal",
                "IED1LD0/LGOS1$ST$LastStNum$stVal",
                "IED1LD0/LGOS1$ST$ConfRevNum$stVal",
                "IED1LD0/LGOS1$ST$RxConfRevNum$stVal",
            ]
        );
        assert_eq!(writes[0].1, Value::Boolean(true));
        assert_eq!(writes[3].1, Value::Integer(42));

        // A stream with no state number and no engineered revision publishes neither, rather
        // than publishing a zero a client would read as a real value.
        let sv = SubscriptionStatus { live: false, ..SubscriptionStatus::default() };
        assert_eq!(sv.writes("IED1LD0/LSVS1").len(), 3);
    }

    #[test]
    fn the_timestamp_belongs_to_the_data_object_not_the_attribute() {
        let now = UtcTime::from_unix(1_700_000_000, 0, crate::common::TimeQuality::SYNCHRONIZED);
        let [(q, _), (t, value)] = quality_and_time("IED1LD0/LGOS1$ST$St$stVal", now);
        assert_eq!(q, "IED1LD0/LGOS1$ST$St$q");
        assert_eq!(t, "IED1LD0/LGOS1$ST$St$t");
        assert_eq!(value, Value::UtcTime(now));
    }
}
