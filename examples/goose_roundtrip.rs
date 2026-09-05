//! A GOOSE publisher driving a GOOSE subscriber, with no network and no clock.
//!
//! ```text
//! cargo run --example goose_roundtrip
//! ```
//!
//! Both cores are sans-IO: they take the caller's notion of "now", hand back bytes and
//! events, and say when to call them again. Here "the network" is a variable, and time is a
//! counter — which is exactly how the deterministic simulation in `tests/simulation.rs`
//! works, and why an adversarial network is cheap to write.

use std::error::Error;

use iec61850_rs::common::{Instant, Quality, TimeQuality, UtcTime};
use iec61850_rs::proto::data::Value;
use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, FrameHeader, MacAddr};
use iec61850_rs::proto::goose::{Publisher, PublisherConfig, Retransmission, Subscriber, SubscriberConfig, SubscriberEvent, SubscriptionKey};

const GOCB: &str = "IED1LD0/LLN0$GO$gcbTrip";
const APPID: u16 = 0x0005;

fn main() -> Result<(), Box<dyn Error>> {
    let dst = MacAddr::parse("01-0C-CD-01-00-05")?;

    let header =
        FrameHeader { dst, src: MacAddr::parse("00-30-A7-00-00-01")?, vlan: None, ethertype: ETHERTYPE_GOOSE, appid: APPID, reserved1: 0, reserved2: 0 };
    // T1 = 4 ms after a state change, doubling to T0 = 1 s in the steady state; the
    // `timeAllowedtoLive` a subscriber sees is twice the *next* interval.
    let cfg = PublisherConfig::new(header, GOCB, "IED1LD0/LLN0$dsTrip").with_go_id("IED1").with_retransmission(Retransmission {
        min_time_ms: 4,
        max_time_ms: 1000,
        tal_factor: 2,
    });
    let initial = trip(false, 1_700_000_000);
    let mut publisher = Publisher::new(cfg, &initial, UtcTime::from_unix(1_700_000_000, 0, TimeQuality::SYNCHRONIZED))?;

    let mut subscriber = Subscriber::new(SubscriberConfig::new(SubscriptionKey { dst, appid: APPID, gocb_ref: GOCB.into() }));

    let mut now = Instant::ZERO;
    let mut tripped = false;

    // Twelve wake-ups is enough to see the first state, the retransmission curve, a state
    // change and its curve. A real program sleeps until `next_timeout` instead of stepping.
    for step in 0..12 {
        // The trip happens on the fifth wake-up.
        if step == 5 && !tripped {
            tripped = true;
            let t = UtcTime::from_unix(1_700_000_000 + step, 0, TimeQuality::SYNCHRONIZED);
            // `publish` advances `stNum` and restarts the retransmission curve.
            publisher.publish(now, &trip(true, 1_700_000_000 + step), t)?;
            println!("{:>7} ms  publisher: trip", now.0 / 1_000_000);
        }

        publisher.on_timeout(now)?;
        while let Some(frame) = publisher.poll_transmit() {
            // This is where a socket would go. The subscriber's verdict is the same either way.
            for event in subscriber.feed(now, frame) {
                report(now, &event);
            }
        }
        subscriber.on_timeout(now);
        while let Some(event) = subscriber.poll_event() {
            report(now, &event);
        }

        // Sleep until whichever core wants attention first.
        now = match (publisher.next_timeout(), subscriber.next_timeout()) {
            (Some(a), Some(b)) => a.min(b),
            (a, b) => a.or(b).unwrap_or(now.plus_millis(100)),
        };
    }

    let stats = subscriber.stats();
    println!("\n{} accepted: {} state change(s), {} retransmission(s)", stats.accepted, stats.state_changes, stats.retransmissions);
    println!("{} replay(s) rejected, {} malformed, {} expiry(ies)", stats.replays, stats.malformed, stats.expiries);
    Ok(())
}

/// One data-set member: `PTRC1.Tr` as an `ACT` — `{general, q, t}`.
fn trip(general: bool, seconds: u32) -> Vec<Value> {
    let t = UtcTime::from_unix(seconds, 0, TimeQuality::SYNCHRONIZED);
    vec![Value::Structure(vec![Value::Boolean(general), Value::quality(Quality::GOOD), Value::UtcTime(t)])]
}

fn report(now: Instant, event: &SubscriberEvent) {
    let at = now.0 / 1_000_000;
    match event {
        SubscriberEvent::NewState { st_num, values, .. } => {
            let general = values.first().and_then(|v| v.member(0)).and_then(|v| match v {
                Value::Boolean(b) => Some(*b),
                _ => None,
            });
            println!("{at:>7} ms  subscriber: NEW STATE stNum={st_num}, Tr.general = {general:?}");
        }
        SubscriberEvent::Retransmission { st_num, sq_num } => println!("{at:>7} ms  subscriber: retransmission stNum={st_num} sqNum={sq_num}"),
        // Nothing arrived within `timeAllowedtoLive`: the inputs are no longer valid and a
        // protection function has to fail safe.
        SubscriberEvent::Expired => println!("{at:>7} ms  subscriber: EXPIRED — the inputs are stale"),
        other => println!("{at:>7} ms  subscriber: {other:?}"),
    }
}
