//! Deterministic simulation of the process-bus state machines.
//!
//! The publisher and the subscriber are driven against each other under virtual time with
//! an adversarial network — loss, duplication, reordering, replay and partition — and the
//! invariants the standards give are asserted after every step. There is no runtime, no
//! socket and no clock here: that is what the sans-IO shape buys, and this is the test it
//! was bought for.
//!
//! A failing seed prints the seed; re-run with `SIM_SEED=<n>` to reproduce it exactly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::VecDeque;

use iec61850_rs::common::{Instant, TimeQuality, UtcTime};
use iec61850_rs::proto::data::Value;
use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, FrameHeader, MacAddr};
use iec61850_rs::proto::goose::{Invalid, Publisher, PublisherConfig, Retransmission, Subscriber, SubscriberConfig, SubscriberEvent, SubscriptionKey};

/// A tiny reproducible PRNG (xorshift64*), so a failing case can be replayed from its seed.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// True with probability `percent`.
    fn chance(&mut self, percent: u32) -> bool {
        self.next_u64() % 100 < u64::from(percent)
    }

    fn range(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

fn publisher_config() -> PublisherConfig {
    PublisherConfig {
        header: FrameHeader {
            dst: MacAddr::GOOSE_BASE,
            src: MacAddr([2, 0, 0, 0, 0, 1]),
            vlan: None,
            ethertype: ETHERTYPE_GOOSE,
            appid: 1,
            reserved1: 0,
            reserved2: 0,
        },
        gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into(),
        dat_set: "IED1LD0/LLN0$dsTrip".into(),
        go_id: Some("IED1".into()),
        conf_rev: 1,
        retransmission: Retransmission { min_time_ms: 4, max_time_ms: 100, tal_factor: 2 },
        simulation: false,
        nds_com: false,
    }
}

fn subscriber() -> Subscriber {
    Subscriber::new(SubscriberConfig::new(SubscriptionKey { dst: MacAddr::GOOSE_BASE, appid: 1, gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into() }).with_conf_rev(1))
}

/// One run of the simulation. Returns the number of state changes the subscriber saw.
fn run(seed: u64, steps: u32) -> u64 {
    let mut rng = Rng(seed | 1);
    let mut pubr = Publisher::new(publisher_config(), &[Value::Boolean(false)], UtcTime::default()).unwrap();
    let mut sub = subscriber();

    // Frames in flight: (deliver_at, bytes). The network may hold, drop, duplicate and
    // reorder them, and may replay an old one at any time.
    let mut wire: VecDeque<(Instant, Vec<u8>)> = VecDeque::new();
    let mut seen: Vec<Vec<u8>> = Vec::new();

    let mut now = Instant::ZERO;
    let mut trip = false;
    let mut published_states: u64 = 1;
    // What the subscriber has told the application: the last state it delivered, and
    // whether that state is still live from the application's point of view (an `Expired`
    // event ends it). Both are derived only from the event stream — the point of the
    // invariant is that the event stream alone is enough to keep an application correct.
    let mut last_delivered_st: Option<u32> = None;
    let mut live = false;
    // What the event stream says was missed: the states between two consecutive delivered
    // ones while the subscription stayed live. The subscriber counts the same thing on its
    // own, and the two must agree exactly.
    let mut expected_missed: u64 = 0;
    let mut partitioned_until = Instant::ZERO;

    for step in 0..steps {
        now = now.plus_millis(1 + rng.range(3));

        // The application changes the data set now and then.
        if rng.chance(6) {
            trip = !trip;
            let t = UtcTime::from_unix(1_700_000_000 + step, 0, TimeQuality::SYNCHRONIZED);
            pubr.publish(now, &[Value::Boolean(trip)], t).unwrap();
            published_states += 1;
        } else if pubr.next_timeout().is_some_and(|d| now >= d) {
            pubr.on_timeout(now).unwrap();
        }

        // Collect whatever the publisher produced.
        if let Some(frame) = pubr.poll_transmit() {
            let frame = frame.to_vec();
            seen.push(frame.clone());
            if rng.chance(15) {
                // Lost.
            } else {
                let delay = Instant(now.0 + rng.range(3_000_000));
                wire.push_back((delay, frame.clone()));
                if rng.chance(10) {
                    // Duplicated, with a different delay: the subscriber must not take the
                    // copy for a new state.
                    wire.push_back((Instant(now.0 + rng.range(6_000_000)), frame));
                }
            }
        }

        // An attacker replays an old frame.
        if rng.chance(8) && !seen.is_empty() {
            let old = seen[rng.range(seen.len() as u64) as usize].clone();
            wire.push_back((now, old));
        }

        // The network is partitioned now and then, long enough for the subscription to
        // expire (TAL is at most 2 x 100 ms here). A new partition is only started once the
        // previous one has healed, so that a run cannot end up partitioned throughout.
        if now >= partitioned_until && rng.chance(1) {
            partitioned_until = now.plus_millis(250);
        }

        // Deliver everything that is due, in an order the network chose.
        if rng.chance(50) {
            wire.make_contiguous().sort_by_key(|(t, _)| *t);
        }
        let mut deliverable: Vec<(Instant, Vec<u8>)> = Vec::new();
        wire.retain(|(t, f)| {
            if *t <= now {
                deliverable.push((*t, f.clone()));
                false
            } else {
                true
            }
        });
        for (_, frame) in deliverable {
            if now < partitioned_until {
                continue;
            }
            for event in sub.feed(now, &frame) {
                match event {
                    SubscriberEvent::NewState { st_num, .. } => {
                        // Invariant 1: while the state the application holds is live, the
                        // subscriber only ever moves *forward* in stNum. It may go back only
                        // after telling the application the old state expired — that is how a
                        // restarted publisher is let back in without a replay slipping
                        // through, and it is why `Expired` must precede a backwards state.
                        if let (Some(prev), true) = (last_delivered_st, live) {
                            assert!(st_num > prev, "seed {seed}: went back to stNum {st_num} from {prev} with no Expired in between");
                            expected_missed += u64::from(st_num - prev - 1);
                        }
                        last_delivered_st = Some(st_num);
                        live = true;
                    }
                    SubscriberEvent::Retransmission { .. } => live = true,
                    SubscriberEvent::Expired => live = false,
                    SubscriberEvent::Invalid(Invalid::Malformed(e)) => {
                        panic!("seed {seed}: the publisher emitted a frame its own decoder rejects: {e}")
                    }
                    SubscriberEvent::Invalid(Invalid::MemberCountMismatch | Invalid::SimulationMismatch) => {
                        panic!("seed {seed}: the publisher emitted an inconsistent frame")
                    }
                    SubscriberEvent::ConfRevMismatch { .. } => panic!("seed {seed}: confRev is constant in this run"),
                    _ => {}
                }
            }
        }
        sub.on_timeout(now);
        while let Some(event) = sub.poll_event() {
            if let SubscriberEvent::Expired = event {
                assert!(sub.is_expired(), "seed {seed}: Expired was reported but the flag is not set");
                live = false;
            }
        }

        // Invariant 2: the subscriber never claims a state the publisher has not published.
        if let Some(st) = sub.st_num() {
            assert!(u64::from(st) <= published_states, "seed {seed}: subscriber invented stNum {st} (published {published_states})");
        }
        // Invariant 3: a live subscription always has a deadline to be woken at.
        assert_eq!(sub.next_timeout().is_none(), sub.st_num().is_none() || sub.is_expired(), "seed {seed}: timeout bookkeeping");
    }

    let stats = sub.stats();
    // A run that delivered nothing would assert nothing; catch a degenerate seed here
    // rather than letting it look like a pass.
    assert!(stats.state_changes > 0, "seed {seed}: no state reached the subscriber; the run tested nothing");
    // Invariant 4: every frame the subscriber took in is accounted for exactly once.
    assert_eq!(stats.accepted, stats.state_changes + stats.retransmissions, "seed {seed}: accepted frames must be states or retransmissions");
    // Invariant 5: nothing was silently discarded — every frame for this stream was
    // accepted, replayed, malformed, or dropped by a policy.
    assert_eq!(stats.malformed, 0, "seed {seed}");
    assert_eq!(stats.simulation_mismatches, 0, "seed {seed}");
    // Invariant 6: the state changes the subscriber says it *missed* are exactly the ones
    // the event stream shows it skipped — the states between two consecutive deliveries
    // while the subscription stayed live. (A total counted against `published_states` would
    // be wrong: after an expiry the same range of `stNum`s can legitimately be traversed
    // again, which is the publisher-restart case.)
    assert_eq!(stats.states_missed, expected_missed, "seed {seed}: missed-state count disagrees with the event stream");
    assert_eq!(stats.state_gaps > 0, expected_missed > 0, "seed {seed}: a gap and a missed state must go together");
    stats.state_changes
}

#[test]
fn publisher_and_subscriber_hold_their_invariants_under_an_adversarial_network() {
    let seeds: Vec<u64> = match std::env::var("SIM_SEED") {
        Ok(s) => vec![s.parse().expect("SIM_SEED must be a number")],
        Err(_) => (1..=64).collect(),
    };
    for seed in seeds {
        run(seed, 400);
    }
}

#[test]
fn a_replayed_frame_is_never_accepted_while_the_state_is_live() {
    // The narrow case the fuzzers cannot express: capture a frame, let the publisher move
    // on, and replay the captured frame. IEC 62351-6 requires it to be rejected.
    let mut pubr = Publisher::new(publisher_config(), &[Value::Boolean(false)], UtcTime::default()).unwrap();
    let mut sub = subscriber();
    let now = Instant::ZERO;

    pubr.on_timeout(now).unwrap();
    let first = pubr.poll_transmit().unwrap().to_vec();
    assert!(matches!(sub.feed(now, &first).as_slice(), [SubscriberEvent::NewState { st_num: 1, .. }]));

    pubr.publish(now, &[Value::Boolean(true)], UtcTime::from_unix(2, 0, TimeQuality::SYNCHRONIZED)).unwrap();
    let second = pubr.poll_transmit().unwrap().to_vec();
    assert!(matches!(sub.feed(now, &second).as_slice(), [SubscriberEvent::NewState { st_num: 2, .. }]));

    // Replay of the first frame while state 2 is still live.
    assert!(matches!(sub.feed(now, &first).as_slice(), [SubscriberEvent::Invalid(Invalid::Replay { st_num: 1, .. })]));
    assert_eq!(sub.st_num(), Some(2), "a replay must not move the subscriber back");
    // And of the second.
    assert!(matches!(sub.feed(now, &second).as_slice(), [SubscriberEvent::Invalid(Invalid::Replay { st_num: 2, .. })]));
    assert_eq!(sub.stats().replays, 2);
}

#[test]
fn the_publisher_keeps_the_subscription_alive_by_itself() {
    // Drive only the timers: the retransmission curve must always produce the next frame
    // before the timeAllowedtoLive it advertised runs out, or a quiet publisher would look
    // dead to a conforming subscriber.
    let mut pubr = Publisher::new(publisher_config(), &[Value::Boolean(false)], UtcTime::default()).unwrap();
    let mut sub = subscriber();
    for _ in 0..200 {
        let now = pubr.next_timeout().expect("a publisher always has a next frame due");
        pubr.on_timeout(now).unwrap();
        let frame = pubr.poll_transmit().expect("the timer came due, so there is a frame").to_vec();
        sub.on_frame(now, &frame);
        sub.on_timeout(now);
        while sub.poll_event().is_some() {}
        assert!(!sub.is_expired(), "the subscription expired while the publisher was transmitting on time");
    }
    // One missed interval is survivable (that is what the factor-2 TAL is for); two are not.
    let deadline = sub.next_timeout().unwrap();
    sub.on_timeout(deadline);
    assert!(sub.is_expired(), "the subscription must expire once TAL elapses with no frame");
}
