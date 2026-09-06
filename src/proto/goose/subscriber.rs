use alloc::string::String;
use alloc::vec::Vec;

use super::apdu::GoosePduView;
use crate::common::{Error, EventQueue, Instant, Limits, UtcTime};
use crate::proto::data::Value;
use crate::proto::ethernet::{ETHERTYPE_GOOSE, Frame, FrameAddress, MacAddr};

/// What identifies the GOOSE stream a subscriber wants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionKey {
    /// Destination multicast MAC (from SCL `GSE/Address`).
    pub dst: MacAddr,
    /// APPID.
    pub appid: u16,
    /// `gocbRef` the frames must carry.
    pub gocb_ref: String,
}

/// How this IED treats the Edition 2 simulation bit — the `LPHD.Sim` setting of the
/// *subscribing* device.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SimulationMode {
    /// `LPHD.Sim = false`: only real frames are processed; simulated frames are counted,
    /// reported once as [`SubscriberEvent::IgnoredSimulation`], and never reach the
    /// application.
    #[default]
    Off,
    /// `LPHD.Sim = true`: simulated frames are processed **in preference to** real ones.
    /// Until the first simulated frame arrives the real stream is used; from then on the
    /// real stream is ignored, which is what IEC 61850-8-1 Ed2 requires of a device under
    /// test. [`Subscriber::reset_simulation`] returns to the real stream.
    Preferred,
}

/// Subscriber configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriberConfig {
    /// The stream.
    pub key: SubscriptionKey,
    /// Expected `confRev`; `None` adopts the first one seen.
    pub expected_conf_rev: Option<u32>,
    /// How the simulation bit is treated.
    pub simulation: SimulationMode,
    /// Decode limits.
    pub limits: Limits,
    /// Maximum events buffered for the application (see [`EventQueue`]).
    pub event_capacity: usize,
}

impl SubscriberConfig {
    /// A configuration for `key` with the defaults: adopt the first `confRev`, ignore
    /// simulated frames, default limits, 64 buffered events.
    pub fn new(key: SubscriptionKey) -> Self {
        SubscriberConfig { key, expected_conf_rev: None, simulation: SimulationMode::Off, limits: Limits::DEFAULT, event_capacity: 64 }
    }

    /// Require this `confRev`.
    #[must_use]
    pub fn with_conf_rev(mut self, conf_rev: u32) -> Self {
        self.expected_conf_rev = Some(conf_rev);
        self
    }

    /// Set the simulation mode.
    #[must_use]
    pub fn with_simulation(mut self, mode: SimulationMode) -> Self {
        self.simulation = mode;
        self
    }
}

/// Why a frame was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// A GOOSE frame for this stream that did not decode.
    Malformed(Error),
    /// The link-layer S bit and the PDU `simulation` flag disagree — one of them was
    /// rewritten in flight, or the publisher is broken.
    SimulationMismatch,
    /// The frame repeats or predates the current state: `stNum` went backwards while the
    /// current state was still live, or `sqNum` did not advance (IEC 62351-6 §6.2.1).
    Replay {
        /// The frame's `stNum`.
        st_num: u32,
        /// The frame's `sqNum`.
        sq_num: u32,
    },
    /// `numDatSetEntries` disagrees with the number of members present.
    MemberCountMismatch,
}

/// Events the subscriber emits.
#[derive(Clone, Debug, PartialEq)]
pub enum SubscriberEvent {
    /// A new state (`stNum` advanced, or the first frame): the decoded data-set values.
    NewState {
        /// `stNum`.
        st_num: u32,
        /// `t` of the change, as the publisher stamped it.
        t: UtcTime,
        /// The values.
        values: Vec<Value>,
        /// Whether the frame carried the simulation flag.
        simulation: bool,
    },
    /// A retransmission of the current state (`sqNum` advanced).
    Retransmission {
        /// `stNum`.
        st_num: u32,
        /// `sqNum`.
        sq_num: u32,
    },
    /// No frame arrived within `timeAllowedtoLive`: the subscription is stale and the last
    /// values must be treated as invalid by the application.
    Expired,
    /// The publisher signals `ndsCom` — it needs commissioning and its data is not usable.
    NeedsCommissioning,
    /// The frame's `confRev` differs from the expected one; the frame was dropped. Emitted
    /// once per transition, not per frame.
    ConfRevMismatch {
        /// What the frame carried.
        received: u32,
        /// What was expected.
        expected: u32,
    },
    /// A simulated frame arrived while [`SimulationMode::Off`]; dropped. Emitted once per
    /// transition, not per frame.
    IgnoredSimulation,
    /// Under [`SimulationMode::Preferred`], the first simulated frame arrived: the real
    /// stream is ignored from now on.
    SimulationTakeover,
    /// A frame was rejected.
    Invalid(Invalid),
}

/// Counters maintained by the subscriber.
///
/// These are exactly the semantic checks a rule-based substation IDS performs, which is why
/// they are public: exporting them is cheaper and more reliable than re-parsing the traffic
/// on a mirror port.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriberStats {
    /// Frames that matched the subscription and were accepted.
    pub accepted: u64,
    /// New states seen.
    pub state_changes: u64,
    /// Retransmissions seen.
    pub retransmissions: u64,
    /// Frames rejected as replay or duplicate.
    pub replays: u64,
    /// Times a new state arrived with `stNum` more than one above the last one *while the
    /// previous state was still live* — state changes that were published and never seen.
    pub state_gaps: u64,
    /// How many state changes those gaps add up to.
    pub states_missed: u64,
    /// Frames for this stream that did not decode.
    pub malformed: u64,
    /// Frames whose header S bit and PDU flag disagreed.
    pub simulation_mismatches: u64,
    /// Frames whose `numDatSetEntries` disagreed with the members present.
    pub member_count_mismatches: u64,
    /// Frames dropped because of the simulation policy.
    pub simulation_dropped: u64,
    /// Frames dropped because `confRev` did not match.
    pub conf_rev_dropped: u64,
    /// Times the subscription went stale.
    pub expiries: u64,
    /// Times the publisher started, or stopped, signalling `ndsCom`.
    pub commissioning_changes: u64,
    /// Frames that were not for this stream (other publishers, other protocols).
    pub other_stream: u64,
    /// Events dropped because the application was not draining the queue.
    pub events_dropped: u64,
}

/// The per-frame quantities a substation intrusion-detection system is built on.
///
/// Both the rule-based and the learned literature converge on the same five numbers. The
/// 2026 evaluation of unsupervised and temporal detectors on the ERENO IEC 61850 dataset
/// reports that the informative reduced feature set is exactly the *delta* features —
/// `stDiff`, `sqDiff`, `timestampDiff`, `tDiff` and `timeFromLastChange` — rather than the
/// raw high-cardinality fields, and that the whole detector has to fit inside the 4 ms
/// GOOSE budget (arXiv 2604.14233).
///
/// A subscriber has already computed every one of them in order to reach a verdict. Reading
/// them from here costs nothing; recovering them on a mirror port costs a second parser, a
/// second copy of the traffic and a source of disagreement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameDeltas {
    /// `stNum` of this frame minus the previous one's (`stDiff`). Zero for a retransmission,
    /// one for an orderly state change; anything else is a gap or a rollback.
    pub st_diff: i64,
    /// `sqNum` of this frame minus the previous one's (`sqDiff`). One in a healthy stream.
    pub sq_diff: i64,
    /// Nanoseconds between this frame's arrival and the previous accepted one's
    /// (`timestampDiff`) — measured on the subscriber's own clock, so an attacker cannot
    /// shape it.
    pub arrival_delta: u64,
    /// Nanoseconds between this frame's `t` and the previous one's (`tDiff`). This *is*
    /// attacker-controlled, which is what makes it worth comparing against `arrival_delta`.
    pub t_delta: i64,
    /// Nanoseconds since the last accepted state change (`timeFromLastChange`).
    pub since_state_change: u64,
}

/// The GOOSE subscriber state machine, including the IEC 62351-6 §6.2.1 replay protection
/// that a conforming subscriber must run **whether or not** the stream carries security
/// extensions.
///
/// Sans-IO: it owns no socket and reads no clock. Feed it frames and timer ticks with
/// [`Subscriber::on_frame`] and [`Subscriber::on_timeout`], drain [`Subscriber::poll_event`],
/// and call it again by [`Subscriber::next_timeout`].
#[derive(Debug)]
pub struct Subscriber {
    cfg: SubscriberConfig,
    state: Option<Accepted>,
    conf_rev: Option<u32>,
    conf_rev_mismatch_reported: bool,
    /// The last `ndsCom` seen, so the event is edge-triggered: a publisher in commissioning
    /// retransmits every few milliseconds, and one event per frame would fill the queue and
    /// push out everything that matters.
    nds_com: bool,
    simulation_reported: bool,
    /// Under `SimulationMode::Preferred`: a simulated frame has been seen, so real frames
    /// are now ignored.
    simulation_active: bool,
    expired: bool,
    events: EventQueue<SubscriberEvent>,
    stats: SubscriberStats,
    deltas: Option<FrameDeltas>,
    /// When the last accepted state change arrived, for `timeFromLastChange`.
    state_changed_at: Option<Instant>,
}

/// What the last accepted frame established.
#[derive(Clone, Copy, Debug)]
struct Accepted {
    st_num: u32,
    sq_num: u32,
    /// When it arrived, on the subscriber's clock.
    arrived_at: Instant,
    /// The `t` the publisher stamped it with.
    t: UtcTime,
    /// When the current state stops being live (arrival + `timeAllowedtoLive`).
    expires_at: Instant,
}

impl Subscriber {
    /// A subscriber in the *waiting for the first message* state.
    pub fn new(cfg: SubscriberConfig) -> Subscriber {
        let conf_rev = cfg.expected_conf_rev;
        let events = EventQueue::new(cfg.event_capacity);
        Subscriber {
            cfg,
            state: None,
            conf_rev,
            conf_rev_mismatch_reported: false,
            nds_com: false,
            simulation_reported: false,
            simulation_active: false,
            expired: false,
            events,
            stats: SubscriberStats::default(),
            deltas: None,
            state_changed_at: None,
        }
    }

    /// The counters.
    pub const fn stats(&self) -> SubscriberStats {
        self.stats
    }

    /// The configuration this subscriber was built with.
    pub const fn config(&self) -> &SubscriberConfig {
        &self.cfg
    }

    /// The [`FrameDeltas`] of the most recently accepted frame, or `None` before the second
    /// one arrives — a delta needs two frames.
    pub const fn deltas(&self) -> Option<FrameDeltas> {
        self.deltas
    }

    /// The `stNum` of the current state, if any frame was accepted.
    pub fn st_num(&self) -> Option<u32> {
        self.state.map(|s| s.st_num)
    }

    /// The `confRev` of the stream: the one that was expected, or the first one seen when
    /// the subscription adopts whatever arrives.
    ///
    /// This is what a supervision logical node publishes as `ConfRevNum`, and it is the field
    /// a commissioning engineer looks at first when a subscription is dark for no visible
    /// reason.
    pub const fn conf_rev(&self) -> Option<u32> {
        self.conf_rev
    }

    /// Whether the publisher is signalling `ndsCom` — it needs commissioning and its data is
    /// not usable.
    pub const fn needs_commissioning(&self) -> bool {
        self.nds_com
    }

    /// True when the subscription is **live**: a frame has been accepted and its
    /// `timeAllowedtoLive` has not run out.
    ///
    /// This is `LGOS.St`, and it is deliberately not "a frame has ever arrived": a stream
    /// that stopped an hour ago is not a healthy subscription, and the whole point of the
    /// supervision logical node is to say so.
    pub const fn is_live(&self) -> bool {
        self.state.is_some() && !self.expired
    }

    /// True while no frame has arrived within the last `timeAllowedtoLive`.
    pub const fn is_expired(&self) -> bool {
        self.expired
    }

    /// True when a simulated frame has taken over the stream
    /// ([`SimulationMode::Preferred`]).
    pub const fn simulation_active(&self) -> bool {
        self.simulation_active
    }

    /// Go back to the real stream after a test.
    ///
    /// The simulated stream's counters are forgotten with it: the real publisher's `stNum`
    /// has no relationship to the test set's, and keeping the old one would make the first
    /// real frame look like a replay.
    pub fn reset_simulation(&mut self) {
        self.simulation_active = false;
        self.forget_source();
    }

    /// Forget everything that describes *which* publisher was being followed.
    ///
    /// Used when the stream changes hands — a test set taking over, or the real publisher
    /// being returned to. The counters of the old source say nothing about the new one, and
    /// neither do its edge-triggered flags: a new source that needs commissioning has to be
    /// reported even if the old one already was.
    fn forget_source(&mut self) {
        self.state = None;
        self.expired = false;
        self.deltas = None;
        self.state_changed_at = None;
        self.nds_com = false;
    }

    /// When the subscriber next needs [`Subscriber::on_timeout`], if ever.
    pub fn next_timeout(&self) -> Option<Instant> {
        if self.expired { None } else { self.state.map(|s| s.expires_at) }
    }

    /// Take the next event.
    pub fn poll_event(&mut self) -> Option<SubscriberEvent> {
        let e = self.events.pop();
        self.stats.events_dropped = self.events.dropped();
        e
    }

    /// Time passed. Marks the subscription stale once `timeAllowedtoLive` elapses.
    pub fn on_timeout(&mut self, now: Instant) {
        self.check_expiry(now);
    }

    /// Report the subscription stale if `timeAllowedtoLive` has elapsed by `now`.
    ///
    /// Called both from [`Subscriber::on_timeout`] and on arrival of a frame, so that the
    /// application always learns that the previous state died *before* it is told about a
    /// state that goes backwards. A restarted publisher begins again at `stNum = 1`, and
    /// without this the application would see the counter jump backwards with nothing
    /// telling it that the values it was holding had become invalid.
    fn check_expiry(&mut self, now: Instant) {
        if let Some(s) = self.state {
            if !self.expired && now >= s.expires_at {
                self.expired = true;
                self.stats.expiries = self.stats.expiries.saturating_add(1);
                self.emit(SubscriberEvent::Expired);
            }
        }
    }

    /// Feed one received Ethernet frame.
    ///
    /// Frames that are not GOOSE, or are GOOSE for a different stream, are counted in
    /// [`SubscriberStats::other_stream`] and are not errors — a raw socket delivers
    /// everything on the segment.
    pub fn on_frame(&mut self, now: Instant, frame: &[u8]) {
        // Time has passed even if nobody called `on_timeout`; notice a dead subscription
        // before deciding what this frame means.
        self.check_expiry(now);
        let fr = match Frame::parse(frame) {
            Ok(f) => f,
            // A frame that does not parse is only *ours* if what can still be read of its
            // address says so. Anything else is other traffic on the segment, not a fault
            // to report against this subscription.
            Err(e) => return if self.addressed_to_us(frame) { self.reject(Invalid::Malformed(e)) } else { self.other() },
        };
        if fr.ethertype != ETHERTYPE_GOOSE || fr.dst != self.cfg.key.dst || fr.appid != self.cfg.key.appid {
            return self.other();
        }
        let pdu = match GoosePduView::parse(fr.apdu) {
            Ok(p) => p,
            Err(e) => return self.reject(Invalid::Malformed(e)),
        };
        if pdu.gocb_ref != self.cfg.key.gocb_ref {
            return self.other();
        }
        if pdu.simulation != fr.simulation() {
            return self.reject(Invalid::SimulationMismatch);
        }
        if !pdu.member_count_matches() {
            return self.reject(Invalid::MemberCountMismatch);
        }
        if !self.simulation_policy_admits(pdu.simulation) || !self.conf_rev_admits(pdu.conf_rev) {
            return;
        }

        let mut state_change = false;
        match self.verdict(&pdu) {
            Verdict::Replay => {
                self.reject(Invalid::Replay { st_num: pdu.st_num, sq_num: pdu.sq_num });
                return;
            }
            Verdict::New => {
                let values = match pdu.all_data_owned(&self.cfg.limits) {
                    Ok(v) => v,
                    Err(e) => return self.reject(Invalid::Malformed(e)),
                };
                self.count_missed_states(pdu.st_num);
                self.stats.state_changes = self.stats.state_changes.saturating_add(1);
                state_change = true;
                self.emit(SubscriberEvent::NewState { st_num: pdu.st_num, t: pdu.t, values, simulation: pdu.simulation });
            }
            Verdict::Retransmission => {
                self.stats.retransmissions = self.stats.retransmissions.saturating_add(1);
                self.emit(SubscriberEvent::Retransmission { st_num: pdu.st_num, sq_num: pdu.sq_num });
            }
        }
        self.stats.accepted = self.stats.accepted.saturating_add(1);
        self.deltas = self.state.map(|last| FrameDeltas {
            st_diff: i64::from(pdu.st_num) - i64::from(last.st_num),
            sq_diff: i64::from(pdu.sq_num) - i64::from(last.sq_num),
            arrival_delta: now.nanos_since(last.arrived_at),
            t_delta: pdu.t.to_unix_nanos() as i64 - last.t.to_unix_nanos() as i64,
            since_state_change: self.state_changed_at.map_or(0, |at| now.nanos_since(at)),
        });
        if state_change {
            self.state_changed_at = Some(now);
        }
        self.state = Some(Accepted {
            st_num: pdu.st_num,
            sq_num: pdu.sq_num,
            arrived_at: now,
            t: pdu.t,
            expires_at: now.plus_millis(u64::from(pdu.time_allowed_to_live)),
        });
        self.expired = false;
        if pdu.nds_com != self.nds_com {
            self.nds_com = pdu.nds_com;
            self.stats.commissioning_changes = self.stats.commissioning_changes.saturating_add(1);
            if pdu.nds_com {
                self.emit(SubscriberEvent::NeedsCommissioning);
            }
        }
    }

    /// True when a frame that failed to parse still identifies itself as this stream.
    fn addressed_to_us(&self, frame: &[u8]) -> bool {
        FrameAddress::peek(frame).is_some_and(|a| a.ethertype == ETHERTYPE_GOOSE && a.dst == self.cfg.key.dst && a.appid == self.cfg.key.appid)
    }

    /// IEC 62351-6 §6.2.1 replay protection.
    ///
    /// The rule is about what is **live**. While the last accepted state is still inside its
    /// `timeAllowedtoLive`, a frame is a **new state** when `stNum` advances and a
    /// **retransmission** when `stNum` is unchanged and `sqNum` advances; anything else — a
    /// lower `stNum`, or a `sqNum` that does not move — is a replay and is discarded.
    ///
    /// Once that `timeAllowedtoLive` has elapsed nothing is live any more, and the next
    /// frame is a new state whatever its counters say: that is a publisher which restarted
    /// and began again at `stNum = 1`, not an attacker, and the subscriber has already told
    /// the application the old state expired. Deciding this on liveness rather than on the
    /// counters alone is what stops a restarted publisher whose `sqNum` happens to be lower
    /// than the last one seen from being locked out for good.
    ///
    /// The publisher's own `t` is deliberately *not* consulted. IEC 62351-6 §6.2.1 lists
    /// `lastRcvT` among the state-machine variables, but `t` is attacker-controlled and
    /// depends on the publisher's clock; the arrival time and the advertised
    /// `timeAllowedtoLive` are the subscriber's own, and they are what this uses.
    fn verdict(&self, pdu: &GoosePduView<'_>) -> Verdict {
        // `check_expiry` ran before this, so `expired` is the liveness of the last state.
        let (Some(last), false) = (self.state, self.expired) else { return Verdict::New };
        if pdu.st_num == last.st_num {
            // `sqNum` must advance. It wraps at the top of the range; publishers disagree on
            // whether it resumes at 0 or at 1, so both are accepted.
            if pdu.sq_num > last.sq_num || wrapped(last.sq_num, pdu.sq_num) { Verdict::Retransmission } else { Verdict::Replay }
        } else if pdu.st_num > last.st_num || wrapped(last.st_num, pdu.st_num) {
            Verdict::New
        } else {
            Verdict::Replay
        }
    }

    /// Count state changes that were published and never arrived.
    ///
    /// Only meaningful while the previous state was live: after an expiry the publisher may
    /// have restarted and its `stNum` says nothing about what was missed. `stNum` wraps to
    /// 1 rather than to 0, so a wrap skips nothing.
    fn count_missed_states(&mut self, st_num: u32) {
        let (Some(last), false) = (self.state, self.expired) else { return };
        let missed =
            if wrapped(last.st_num, st_num) { u64::from(st_num.saturating_sub(1)) } else { u64::from(st_num.saturating_sub(last.st_num).saturating_sub(1)) };
        if missed > 0 {
            self.stats.state_gaps = self.stats.state_gaps.saturating_add(1);
            self.stats.states_missed = self.stats.states_missed.saturating_add(missed);
        }
    }

    /// Apply the simulation policy. Returns false when the frame must be dropped.
    fn simulation_policy_admits(&mut self, simulated: bool) -> bool {
        match (self.cfg.simulation, simulated) {
            (SimulationMode::Off, false) => {
                self.simulation_reported = false;
                true
            }
            (SimulationMode::Off, true) => {
                self.stats.simulation_dropped = self.stats.simulation_dropped.saturating_add(1);
                if !self.simulation_reported {
                    self.simulation_reported = true;
                    self.emit(SubscriberEvent::IgnoredSimulation);
                }
                false
            }
            (SimulationMode::Preferred, true) => {
                if !self.simulation_active {
                    self.simulation_active = true;
                    // The simulated stream takes over; the real stream's counters must not
                    // make the first simulated frame look like a replay.
                    self.forget_source();
                    self.emit(SubscriberEvent::SimulationTakeover);
                }
                true
            }
            (SimulationMode::Preferred, false) => {
                if self.simulation_active {
                    self.stats.simulation_dropped = self.stats.simulation_dropped.saturating_add(1);
                    return false;
                }
                true
            }
        }
    }

    /// Apply the `confRev` policy. Returns false when the frame must be dropped.
    fn conf_rev_admits(&mut self, conf_rev: u32) -> bool {
        match self.conf_rev {
            Some(expected) if expected == conf_rev => {
                self.conf_rev_mismatch_reported = false;
                true
            }
            Some(expected) => {
                self.stats.conf_rev_dropped = self.stats.conf_rev_dropped.saturating_add(1);
                if !self.conf_rev_mismatch_reported {
                    self.conf_rev_mismatch_reported = true;
                    self.emit(SubscriberEvent::ConfRevMismatch { received: conf_rev, expected });
                }
                false
            }
            None => {
                self.conf_rev = Some(conf_rev);
                true
            }
        }
    }

    fn emit(&mut self, event: SubscriberEvent) {
        self.events.push(event);
        self.stats.events_dropped = self.events.dropped();
    }

    fn other(&mut self) {
        self.stats.other_stream = self.stats.other_stream.saturating_add(1);
    }

    fn reject(&mut self, why: Invalid) {
        // Every rejection moves a counter: an application that cannot keep up with the
        // event queue still sees, in the statistics, exactly which check failed.
        match why {
            Invalid::Malformed(_) => self.stats.malformed = self.stats.malformed.saturating_add(1),
            Invalid::SimulationMismatch => self.stats.simulation_mismatches = self.stats.simulation_mismatches.saturating_add(1),
            Invalid::MemberCountMismatch => self.stats.member_count_mismatches = self.stats.member_count_mismatches.saturating_add(1),
            Invalid::Replay { .. } => self.stats.replays = self.stats.replays.saturating_add(1),
        }
        self.emit(SubscriberEvent::Invalid(why));
    }

    /// Feed a frame and collect the events it produced. Convenience for tests and tools;
    /// production code drives [`Subscriber::on_frame`] and [`Subscriber::poll_event`].
    pub fn feed(&mut self, now: Instant, frame: &[u8]) -> Vec<SubscriberEvent> {
        self.on_frame(now, frame);
        let mut v = Vec::new();
        while let Some(e) = self.poll_event() {
            v.push(e);
        }
        v
    }
}

/// How far from the top of the range a counter may wrap and still be believed.
const SEQ_WRAP_WINDOW: u32 = 16;

/// True when `new` is plausibly `last` after wrapping at the top of the `u32` range.
const fn wrapped(last: u32, new: u32) -> bool {
    last > u32::MAX - SEQ_WRAP_WINDOW && new <= SEQ_WRAP_WINDOW
}

enum Verdict {
    New,
    Retransmission,
    Replay,
}

#[cfg(test)]
mod tests {
    // `vec!` is `std`'s prelude, and these tests run under `--no-default-features` too.
    use alloc::vec;

    use super::*;
    use crate::common::TimeQuality;
    use crate::proto::ethernet::{FrameHeader, RESERVED1_SIMULATION};
    use crate::proto::goose::GoosePdu;

    const TAL_MS: u32 = 100;

    fn frame(st: u32, sq: u32, sim: bool, values: Vec<Value>) -> Vec<u8> {
        frame_with(st, sq, sim, 1, values)
    }

    /// A frame stamped with an explicit publisher time, for the delta tests.
    fn frame_at(st: u32, sq: u32, secs: u32, nanos: u32) -> Vec<u8> {
        build(st, sq, false, 1, vec![], UtcTime::from_unix(secs, nanos, TimeQuality::SYNCHRONIZED))
    }

    fn frame_with(st: u32, sq: u32, sim: bool, conf_rev: u32, values: Vec<Value>) -> Vec<u8> {
        build(st, sq, sim, conf_rev, values, UtcTime::from_unix(100, 0, TimeQuality::SYNCHRONIZED))
    }

    /// A frame of this stream carrying `ndsCom`.
    fn frame_nds_com(st: u32, nds_com: bool) -> Vec<u8> {
        let mut pdu = pdu_of(st, 0, false, 1, vec![], UtcTime::from_unix(100, 0, TimeQuality::SYNCHRONIZED));
        pdu.nds_com = nds_com;
        wrap(&pdu, false)
    }

    fn build(st: u32, sq: u32, sim: bool, conf_rev: u32, values: Vec<Value>, t: UtcTime) -> Vec<u8> {
        wrap(&pdu_of(st, sq, sim, conf_rev, values, t), sim)
    }

    fn pdu_of(st: u32, sq: u32, sim: bool, conf_rev: u32, values: Vec<Value>, t: UtcTime) -> GoosePdu {
        GoosePdu {
            gocb_ref: "IED1LD0/LLN0$GO$gcb1".into(),
            time_allowed_to_live: TAL_MS,
            dat_set: "IED1LD0/LLN0$ds1".into(),
            go_id: None,
            t,
            st_num: st,
            sq_num: sq,
            simulation: sim,
            conf_rev,
            nds_com: false,
            all_data: values,
        }
    }

    fn wrap(pdu: &GoosePdu, sim: bool) -> Vec<u8> {
        let h = FrameHeader {
            dst: MacAddr::GOOSE_BASE,
            src: MacAddr::default(),
            vlan: None,
            ethertype: ETHERTYPE_GOOSE,
            appid: 1,
            reserved1: if sim { RESERVED1_SIMULATION } else { 0 },
            reserved2: 0,
        };
        h.to_frame(&pdu.encode().unwrap()).unwrap()
    }

    fn key() -> SubscriptionKey {
        SubscriptionKey { dst: MacAddr::GOOSE_BASE, appid: 1, gocb_ref: "IED1LD0/LLN0$GO$gcb1".into() }
    }

    fn sub() -> Subscriber {
        Subscriber::new(SubscriberConfig::new(key()).with_conf_rev(1))
    }

    #[test]
    fn states_and_retransmissions() {
        let mut s = sub();
        let t0 = Instant::ZERO;
        assert!(matches!(s.feed(t0, &frame(5, 0, false, vec![Value::Boolean(true)])).as_slice(), [SubscriberEvent::NewState { st_num: 5, .. }]));
        assert_eq!(s.next_timeout(), Some(t0.plus_millis(u64::from(TAL_MS))));
        assert!(matches!(s.feed(t0, &frame(5, 1, false, vec![])).as_slice(), [SubscriberEvent::Retransmission { sq_num: 1, .. }]));
        assert!(matches!(s.feed(t0, &frame(6, 0, false, vec![])).as_slice(), [SubscriberEvent::NewState { st_num: 6, .. }]));
        assert_eq!(s.stats().state_changes, 2);
        assert_eq!(s.st_num(), Some(6));
    }

    #[test]
    fn replays_are_rejected_while_the_state_is_live() {
        let mut s = sub();
        let t0 = Instant::ZERO;
        s.feed(t0, &frame(5, 3, false, vec![]));
        assert!(matches!(s.feed(t0, &frame(5, 3, false, vec![])).as_slice(), [SubscriberEvent::Invalid(Invalid::Replay { .. })]));
        assert!(matches!(s.feed(t0, &frame(5, 2, false, vec![])).as_slice(), [SubscriberEvent::Invalid(Invalid::Replay { .. })]));
        assert!(matches!(s.feed(t0.plus_millis(50), &frame(4, 9, false, vec![])).as_slice(), [SubscriberEvent::Invalid(Invalid::Replay { .. })]));
        assert_eq!(s.stats().replays, 3);
    }

    #[test]
    fn a_restarted_publisher_is_accepted_once_the_state_expired() {
        // IEC 62351-6: a lower stNum is a replay only while the previous TAL has not
        // elapsed. After it has, the publisher restarted and stNum begins again at 1.
        let mut s = sub();
        s.feed(Instant::ZERO, &frame(500, 0, false, vec![]));
        let after_tal = Instant::ZERO.plus_millis(u64::from(TAL_MS));
        // The application is told the old state died *before* the counter goes backwards.
        let ev = s.feed(after_tal, &frame(1, 0, false, vec![]));
        assert!(matches!(ev.as_slice(), [SubscriberEvent::Expired, SubscriberEvent::NewState { st_num: 1, .. }]), "{ev:?}");
        assert_eq!(s.stats().replays, 0);
        assert!(!s.is_expired(), "the new state revives the subscription");
    }

    #[test]
    fn a_restarted_publisher_is_not_locked_out_by_its_own_sqnum() {
        // The case a counter-only rule gets wrong: the publisher restarts on the same
        // `stNum` it was using, with `sqNum` back at 0. Every frame until it climbs past
        // the old `sqNum` would be a replay — the subscription would stay dark for the
        // length of a whole retransmission curve. Liveness, not the counters, decides.
        let mut s = sub();
        for sq in 0..50 {
            s.feed(Instant::ZERO, &frame(1, sq, false, vec![]));
        }
        let after_tal = Instant::ZERO.plus_millis(u64::from(TAL_MS));
        let ev = s.feed(after_tal, &frame(1, 0, false, vec![Value::Boolean(true)]));
        assert!(matches!(ev.as_slice(), [SubscriberEvent::Expired, SubscriberEvent::NewState { st_num: 1, .. }]), "{ev:?}");
        assert_eq!(s.stats().replays, 0);
        // And it carries on from there.
        assert!(matches!(s.feed(after_tal, &frame(1, 1, false, vec![])).as_slice(), [SubscriberEvent::Retransmission { sq_num: 1, .. }]));
    }

    #[test]
    fn every_rejection_moves_a_counter() {
        let mut s = sub();
        let t0 = Instant::ZERO;
        s.feed(t0, &frame(5, 0, false, vec![]));
        s.feed(t0, &frame(5, 0, false, vec![])); // replay
        s.feed(t0, &frame(1, 0, false, vec![])[..30]); // malformed
        let mut mismatched = frame(6, 0, false, vec![]);
        mismatched[18] |= 0x80; // header S bit set, PDU flag not
        s.feed(t0, &mismatched);
        let st = s.stats();
        assert_eq!((st.replays, st.malformed, st.simulation_mismatches, st.member_count_mismatches), (1, 1, 1, 0));
    }

    #[test]
    fn the_ids_delta_features_come_out_of_the_verdict() {
        // stDiff, sqDiff, timestampDiff, tDiff and timeFromLastChange — the reduced feature
        // set the 2026 GOOSE anomaly-detection literature selects. The subscriber computes
        // all five on the way to a verdict, so exporting them is free.
        let mut s = sub();
        let t0 = Instant::ZERO;
        assert_eq!(s.deltas(), None, "a delta needs two frames");

        s.feed(t0, &frame(5, 0, false, vec![]));
        assert_eq!(s.deltas(), None);

        // A retransmission 4 ms later, stamped 4 ms later by the publisher too.
        let t1 = t0.plus_millis(4);
        s.feed(t1, &frame_at(5, 1, 100, 4_000_000));
        let d = s.deltas().unwrap();
        assert_eq!((d.st_diff, d.sq_diff), (0, 1));
        assert_eq!(d.arrival_delta, 4_000_000);
        // `t` is quantised to 2⁻²⁴ s on the wire, so `t_delta` is within one LSB (~60 ns)
        // of the arrival delta rather than equal to it. That is the format, not an error.
        assert!((d.t_delta - 4_000_000).abs() < 60, "t_delta was {}", d.t_delta);
        assert_eq!(d.since_state_change, 4_000_000);

        // A state change: stDiff 1, sqNum back to 0, and the clock restarts.
        let t2 = t1.plus_millis(6);
        s.feed(t2, &frame_at(6, 0, 100, 10_000_000));
        let d = s.deltas().unwrap();
        assert_eq!((d.st_diff, d.sq_diff), (1, -1));
        assert_eq!(d.arrival_delta, 6_000_000);
        assert_eq!(d.since_state_change, 10_000_000, "measured from the previous change, not this one");
        s.feed(t2.plus_millis(4), &frame_at(6, 1, 100, 14_000_000));
        assert_eq!(s.deltas().unwrap().since_state_change, 4_000_000, "and from this one afterwards");

        // A publisher whose clock disagrees with the wire is exactly what tDiff exposes:
        // the frame arrived 4 ms later but claims to be a second newer.
        s.feed(t2.plus_millis(8), &frame_at(6, 2, 101, 14_000_000));
        let d = s.deltas().unwrap();
        assert_eq!(d.arrival_delta, 4_000_000);
        assert_eq!(d.t_delta, 1_000_000_000, "a whole second of clock skew, with 4 ms on the wire");
    }

    #[test]
    fn counters_may_wrap() {
        let mut s = sub();
        let t0 = Instant::ZERO;
        s.feed(t0, &frame(7, u32::MAX, false, vec![]));
        assert!(matches!(s.feed(t0, &frame(7, 0, false, vec![])).as_slice(), [SubscriberEvent::Retransmission { sq_num: 0, .. }]));
        let mut s2 = sub();
        s2.feed(t0, &frame(u32::MAX, 0, false, vec![]));
        assert!(matches!(s2.feed(t0, &frame(1, 0, false, vec![])).as_slice(), [SubscriberEvent::NewState { st_num: 1, .. }]));
    }

    #[test]
    fn expiry_fires_once() {
        let mut s = sub();
        s.feed(Instant::ZERO, &frame(1, 0, false, vec![]));
        s.on_timeout(Instant::ZERO.plus_millis(50));
        assert!(s.poll_event().is_none());
        s.on_timeout(Instant::ZERO.plus_millis(u64::from(TAL_MS)));
        assert_eq!(s.poll_event(), Some(SubscriberEvent::Expired));
        s.on_timeout(Instant::ZERO.plus_millis(500));
        assert!(s.poll_event().is_none());
        assert!(s.is_expired());
        assert_eq!(s.next_timeout(), None);
        assert_eq!(s.stats().expiries, 1);
    }

    #[test]
    fn simulation_off_ignores_simulated_frames_and_reports_once() {
        let mut s = sub();
        let t0 = Instant::ZERO;
        assert!(matches!(s.feed(t0, &frame(1, 0, true, vec![])).as_slice(), [SubscriberEvent::IgnoredSimulation]));
        assert!(s.feed(t0, &frame(2, 0, true, vec![])).is_empty(), "reported once, not per frame");
        assert_eq!(s.stats().simulation_dropped, 2);
        assert!(matches!(s.feed(t0, &frame(1, 0, false, vec![])).as_slice(), [SubscriberEvent::NewState { .. }]));
    }

    #[test]
    fn simulation_preferred_takes_over_and_then_ignores_the_real_stream() {
        // IEC 61850-8-1 Ed2: with LPHD.Sim true the device processes simulated streams in
        // preference to the real ones.
        let mut s = Subscriber::new(SubscriberConfig::new(key()).with_conf_rev(1).with_simulation(SimulationMode::Preferred));
        let t0 = Instant::ZERO;
        assert!(matches!(s.feed(t0, &frame(10, 0, false, vec![])).as_slice(), [SubscriberEvent::NewState { st_num: 10, .. }]));
        let ev = s.feed(t0, &frame(1, 0, true, vec![]));
        assert!(matches!(ev.as_slice(), [SubscriberEvent::SimulationTakeover, SubscriberEvent::NewState { st_num: 1, simulation: true, .. }]), "{ev:?}");
        assert!(s.simulation_active());
        assert!(s.feed(t0, &frame(11, 0, false, vec![])).is_empty(), "real frames are dropped once simulation took over");
        assert!(matches!(s.feed(t0, &frame(2, 0, true, vec![])).as_slice(), [SubscriberEvent::NewState { st_num: 2, .. }]));
        s.reset_simulation();
        assert!(matches!(s.feed(t0, &frame(12, 0, false, vec![])).as_slice(), [SubscriberEvent::NewState { st_num: 12, .. }]));
    }

    #[test]
    fn conf_rev_mismatch_is_edge_triggered() {
        let mut s = sub();
        let t0 = Instant::ZERO;
        assert!(matches!(s.feed(t0, &frame_with(1, 0, false, 7, vec![])).as_slice(), [SubscriberEvent::ConfRevMismatch { received: 7, expected: 1 }]));
        assert!(s.feed(t0, &frame_with(2, 0, false, 7, vec![])).is_empty(), "reported once, not per frame");
        assert_eq!(s.stats().conf_rev_dropped, 2);
        assert!(matches!(s.feed(t0, &frame(3, 0, false, vec![])).as_slice(), [SubscriberEvent::NewState { .. }]));
        assert!(matches!(s.feed(t0, &frame_with(4, 0, false, 7, vec![])).as_slice(), [SubscriberEvent::ConfRevMismatch { .. }]));
    }

    #[test]
    fn other_traffic_and_malformed_frames() {
        let mut s = sub();
        let t0 = Instant::ZERO;
        assert!(s.feed(t0, &[0u8; 30]).is_empty());
        let mut other = frame(1, 0, false, vec![]);
        other[5] = 0x09;
        assert!(s.feed(t0, &other).is_empty());
        assert_eq!(s.stats().other_stream, 2);
        let truncated = &frame(1, 0, false, vec![])[..30];
        assert!(matches!(s.feed(t0, truncated).as_slice(), [SubscriberEvent::Invalid(Invalid::Malformed(_))]));
        let mut mismatched = frame(1, 0, false, vec![]);
        // Untagged frame: dst(6) src(6) ethertype(2) APPID(2) Length(2) Reserved1 at 18.
        mismatched[18] |= 0x80;
        assert!(matches!(s.feed(t0, &mismatched).as_slice(), [SubscriberEvent::Invalid(Invalid::SimulationMismatch)]));
        assert_eq!(s.stats().simulation_mismatches, 1);
    }

    #[test]
    fn needs_commissioning_is_edge_triggered() {
        // A publisher in commissioning retransmits every few milliseconds. One event per
        // frame would fill the bounded queue and push out everything that matters.
        let mut s = sub();
        let t0 = Instant::ZERO;
        let ev = s.feed(t0, &frame_nds_com(1, true));
        assert!(matches!(ev.as_slice(), [SubscriberEvent::NewState { .. }, SubscriberEvent::NeedsCommissioning]), "{ev:?}");
        for st in 2..20 {
            assert!(s.feed(t0, &frame_nds_com(st, true)).iter().all(|e| !matches!(e, SubscriberEvent::NeedsCommissioning)), "reported once, not per frame");
        }
        // Commissioning finished: the flag clears, which is a transition too.
        assert!(s.feed(t0, &frame_nds_com(20, false)).iter().all(|e| !matches!(e, SubscriberEvent::NeedsCommissioning)));
        assert_eq!(s.stats().commissioning_changes, 2);
        // And it is reported again if the publisher goes back into commissioning.
        assert!(s.feed(t0, &frame_nds_com(21, true)).contains(&SubscriberEvent::NeedsCommissioning));
        // A test set taking the stream over is a different source: its flags are its own,
        // so a fresh `ndsCom` from it is reported even though the real publisher's was.
        let mut p = Subscriber::new(SubscriberConfig::new(key()).with_conf_rev(1).with_simulation(SimulationMode::Preferred));
        assert!(p.feed(t0, &frame_nds_com(1, true)).contains(&SubscriberEvent::NeedsCommissioning));
        p.reset_simulation();
        assert!(p.feed(t0, &frame_nds_com(2, true)).contains(&SubscriberEvent::NeedsCommissioning));
    }

    #[test]
    fn a_malformed_frame_belonging_to_someone_else_is_other_traffic() {
        // `malformed` is an intrusion-detection counter, so it has to mean "somebody is
        // sending *this stream* rubbish" and not "there is other traffic on the segment".
        let mut s = sub();
        let t0 = Instant::ZERO;
        let mine = frame(1, 0, false, vec![]);
        s.feed(t0, &mine[..30]);
        let mut theirs = mine.clone();
        theirs[15] = 0x09; // another APPID
        s.feed(t0, &theirs[..30]);
        let mut sv = mine.clone();
        sv[13] = 0xBA; // sampled values, truncated
        s.feed(t0, &sv[..30]);
        let st = s.stats();
        assert_eq!((st.malformed, st.other_stream), (1, 2));
    }

    #[test]
    fn state_changes_that_never_arrived_are_counted() {
        let mut s = sub();
        let t0 = Instant::ZERO;
        s.feed(t0, &frame(5, 0, false, vec![]));
        s.feed(t0, &frame(6, 0, false, vec![])); // orderly
        assert_eq!((s.stats().state_gaps, s.stats().states_missed), (0, 0));
        s.feed(t0, &frame(9, 0, false, vec![])); // 7 and 8 were published and lost
        assert_eq!((s.stats().state_gaps, s.stats().states_missed), (1, 2));
        // After an expiry the publisher may have restarted, so its counter says nothing
        // about what was missed.
        let later = t0.plus_millis(u64::from(TAL_MS) * 4);
        s.feed(later, &frame(400, 0, false, vec![]));
        assert_eq!((s.stats().state_gaps, s.stats().states_missed), (1, 2));
        // A wrap skips nothing: `stNum` restarts at 1, never at 0.
        let mut w = sub();
        w.feed(t0, &frame(u32::MAX, 0, false, vec![]));
        w.feed(t0, &frame(1, 0, false, vec![]));
        assert_eq!((w.stats().state_gaps, w.stats().states_missed), (0, 0));
    }

    #[test]
    fn the_event_queue_is_bounded() {
        let mut cfg = SubscriberConfig::new(key());
        cfg.event_capacity = 4;
        let mut s = Subscriber::new(cfg);
        for i in 1..50u32 {
            s.on_frame(Instant::ZERO, &frame(i, 0, false, vec![]));
        }
        let mut n = 0;
        while s.poll_event().is_some() {
            n += 1;
        }
        assert_eq!(n, 4);
        assert_eq!(s.stats().events_dropped, 45);
        assert_eq!(s.stats().state_changes, 49, "dropping events must not lose counters");
    }
}
