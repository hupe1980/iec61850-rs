use alloc::string::String;
use alloc::vec::Vec;

use super::apdu::{AsduView, SavPduView, SmpSynch};
use super::layout::{Channel, ChannelValue, SampleLayout};
use crate::common::{Error, EventQueue, Instant, Limits};
use crate::proto::ethernet::{ETHERTYPE_SV, Frame, FrameAddress, MacAddr};

/// Identifies an SV stream: destination MAC, APPID and `svID`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamKey {
    /// Destination multicast MAC.
    pub dst: MacAddr,
    /// APPID.
    pub appid: u16,
    /// `svID`.
    pub sv_id: String,
}

/// How this IED treats the Edition 2 simulation bit — the `LPHD.Sim` setting of the
/// *subscribing* device, which IEC 61850-8-1 Ed 2 applies to sampled values exactly as it
/// does to GOOSE.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SimulationMode {
    /// `LPHD.Sim = false`: only real frames are processed. Simulated frames are counted,
    /// reported once as [`SubscriberEvent::IgnoredSimulation`], and never reach the
    /// consumer.
    #[default]
    Off,
    /// `LPHD.Sim = true`: simulated frames are processed **in preference to** real ones.
    /// Until the first simulated frame arrives the real stream is used; from then on the
    /// real stream is ignored. [`Subscriber::reset_simulation`] returns to the real stream.
    Preferred,
}

/// Per-stream configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// The stream.
    pub key: StreamKey,
    /// The value at which `smpCnt` wraps back to 0, i.e. the samples per second: 4000
    /// (80 per cycle at 50 Hz), 4800 (80 per cycle at 60 Hz, or IEC 61869-9 protection),
    /// 12800, 14400. Gap detection is modulo this value.
    pub samples_per_second: u32,
    /// Expected `confRev`; `None` accepts whatever arrives.
    pub expected_conf_rev: Option<u32>,
    /// Report [`SubscriberEvent::Stale`] when no frame arrived for this long. A stream at
    /// 4800 Hz should be given a few milliseconds, not seconds.
    pub stale_after_ms: u32,
    /// How the simulation bit is treated.
    pub simulation: SimulationMode,
    /// What the octets of each ASDU's sample block mean, when the engineering file says.
    ///
    /// With a layout, [`Sample::channels`] decodes; without one, [`Sample::asdu`] hands over
    /// the raw block and the application decides what it is (9-2LE's fixed set has
    /// [`super::le::PhsMeas1`] for exactly that).
    pub layout: Option<SampleLayout>,
}

impl StreamConfig {
    /// A stream with the 9-2LE protection defaults (4000 samples/s, stale after 10 ms,
    /// simulated frames ignored).
    pub fn new(key: StreamKey) -> Self {
        StreamConfig { key, samples_per_second: 4000, expected_conf_rev: None, stale_after_ms: 10, simulation: SimulationMode::Off, layout: None }
    }

    /// Set the sample rate that `smpCnt` wraps at.
    #[must_use]
    pub fn with_samples_per_second(mut self, samples: u32) -> Self {
        self.samples_per_second = samples;
        self
    }

    /// Require this `confRev`.
    #[must_use]
    pub fn with_conf_rev(mut self, conf_rev: u32) -> Self {
        self.expected_conf_rev = Some(conf_rev);
        self
    }

    /// Report the stream stale after this long without a frame.
    #[must_use]
    pub fn with_stale_after_ms(mut self, ms: u32) -> Self {
        self.stale_after_ms = ms;
        self
    }

    /// Set the simulation mode.
    #[must_use]
    pub fn with_simulation(mut self, mode: SimulationMode) -> Self {
        self.simulation = mode;
        self
    }

    /// Describe the sample block, so that samples decode into channels.
    #[must_use]
    pub fn with_layout(mut self, layout: SampleLayout) -> Self {
        self.layout = Some(layout);
        self
    }

    /// The value `smpCnt` wraps at, never zero ([`super::smp_cnt_wrap`]).
    const fn wrap(&self) -> u32 {
        super::smp_cnt_wrap(self.samples_per_second)
    }
}

/// Runtime state and counters of one stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StreamState {
    /// Last `smpCnt` accepted.
    pub last_smp_cnt: Option<u16>,
    /// Last `confRev` seen — what a supervision logical node publishes as `RxConfRevNum`,
    /// and the first thing a commissioning engineer compares against the file.
    pub conf_rev: Option<u32>,
    /// Last `smpSynch` seen.
    pub smp_synch: Option<SmpSynch>,
    /// Last `gmIdentity` seen.
    pub gm_identity: Option<[u8; 8]>,
    /// Frames accepted (not ASDUs — a 61869-9 frame carries 2 or 6).
    pub frames: u64,
    /// ASDUs accepted.
    pub asdus: u64,
    /// Sample-count discontinuities.
    pub gaps: u64,
    /// Samples missing across all gaps.
    pub samples_lost: u64,
    /// ASDUs dropped because `confRev` did not match.
    pub conf_rev_dropped: u64,
    /// ASDUs dropped by the simulation policy.
    pub simulation_dropped: u64,
    /// ASDUs dropped because the sample block was not the length the configured layout
    /// describes.
    pub layout_mismatches: u64,
    /// Whether a simulated stream has taken over ([`SimulationMode::Preferred`]).
    pub simulation_active: bool,
    /// Whether the stream is currently stale.
    pub stale: bool,
}

/// Stream-level events. Samples themselves go to the consumer closure on the hot path;
/// only these low-rate, edge-triggered facts are queued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriberEvent {
    /// A discontinuity in `smpCnt`.
    Gap {
        /// Index of the stream in the configuration.
        stream: usize,
        /// The `smpCnt` that was expected next.
        expected: u16,
        /// What arrived.
        received: u16,
        /// Samples lost, modulo the wrap.
        lost: u32,
    },
    /// `smpSynch` changed — the merging unit gained or lost its time reference.
    SyncChanged {
        /// Stream index.
        stream: usize,
        /// Previous value.
        from: Option<SmpSynch>,
        /// New value.
        to: Option<SmpSynch>,
    },
    /// `gmIdentity` changed: the PTP grandmaster was replaced, a common root cause of
    /// sampled-value problems.
    GrandmasterChanged {
        /// Stream index.
        stream: usize,
        /// The new identity.
        to: Option<[u8; 8]>,
    },
    /// `confRev` differs from the expected one; the ASDU was dropped. Emitted once per
    /// transition, not per ASDU — a mismatched stream would otherwise emit thousands per
    /// second.
    ConfRevMismatch {
        /// Stream index.
        stream: usize,
        /// What arrived.
        received: u32,
    },
    /// The sample block is not the length the configured [`SampleLayout`] describes, so
    /// the stream is not publishing the data set it was engineered with; the ASDU was
    /// dropped rather than decoded as something it is not. Edge-triggered.
    SampleLengthMismatch {
        /// Stream index.
        stream: usize,
        /// Octets the layout describes.
        expected: usize,
        /// Octets the ASDU carried.
        received: usize,
    },
    /// A simulated frame arrived while [`SimulationMode::Off`]; dropped. Emitted once per
    /// transition, not per frame.
    IgnoredSimulation {
        /// Stream index.
        stream: usize,
    },
    /// Under [`SimulationMode::Preferred`], the first simulated frame arrived: the real
    /// stream is ignored from now on.
    SimulationTakeover {
        /// Stream index.
        stream: usize,
    },
    /// No frame for `stale_after_ms`.
    Stale {
        /// Stream index.
        stream: usize,
    },
    /// The stream resumed after being stale.
    Resumed {
        /// Stream index.
        stream: usize,
    },
    /// A malformed sampled-value frame (counted, never a panic).
    Malformed(Error),
}

/// One accepted ASDU handed to the consumer.
#[derive(Clone, Copy, Debug)]
pub struct Sample<'a> {
    /// Index of the stream in the configuration.
    pub stream: usize,
    /// The ASDU.
    pub asdu: AsduView<'a>,
    /// Whether the frame carried the simulation bit.
    pub simulation: bool,
    /// The stream's sample-block layout, if it was configured with one.
    pub layout: Option<&'a SampleLayout>,
}

impl<'a> Sample<'a> {
    /// The channels of this sample, in data-set order — empty when the stream has no
    /// layout ([`StreamConfig::with_layout`], or an SCL-configured stream).
    ///
    /// Nothing is allocated: the values are read out of the frame's own octets as the
    /// iterator walks them, on the receiving thread.
    pub fn channels(&self) -> impl Iterator<Item = (&'a Channel, ChannelValue)> + 'a {
        let sample = self.asdu.sample;
        self.layout.into_iter().flat_map(move |l| l.decode(sample))
    }

    /// Channel `i` of this sample.
    pub fn channel(&self, i: usize) -> Option<ChannelValue> {
        self.layout?.value(self.asdu.sample, i)
    }
}

/// The multi-stream sampled-value subscriber.
///
/// Sans-IO and allocation-free on the receive path: samples are handed to a closure on the
/// calling thread, and only stream-level changes are queued (bounded — a 4.8 kHz stream and
/// an application that stops draining must not grow memory without limit).
#[derive(Debug)]
pub struct Subscriber {
    streams: Vec<Stream>,
    limits: Limits,
    events: EventQueue<SubscriberEvent>,
    other_stream: u64,
    malformed: u64,
}

#[derive(Debug)]
struct Stream {
    cfg: StreamConfig,
    state: StreamState,
    deadline: Option<Instant>,
    conf_rev_reported: bool,
    simulation_reported: bool,
    layout_reported: bool,
}

impl Subscriber {
    /// A subscriber for `streams`, with the default [`Limits`] and room for 64 buffered
    /// stream-level events.
    pub fn new(streams: Vec<StreamConfig>) -> Subscriber {
        Subscriber {
            streams: streams
                .into_iter()
                .map(|cfg| Stream {
                    cfg,
                    state: StreamState::default(),
                    deadline: None,
                    conf_rev_reported: false,
                    simulation_reported: false,
                    layout_reported: false,
                })
                .collect(),
            limits: Limits::DEFAULT,
            events: EventQueue::new(64),
            other_stream: 0,
            malformed: 0,
        }
    }

    /// Set the decode limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Buffer at most `capacity` stream-level events. Samples never queue — they go to the
    /// consumer on the receiving thread — so this bounds only the low-rate facts.
    #[must_use]
    pub fn with_event_capacity(mut self, capacity: usize) -> Self {
        self.events = EventQueue::new(capacity);
        self
    }

    /// The state of stream `i`.
    pub fn state(&self, i: usize) -> Option<&StreamState> {
        self.streams.get(i).map(|s| &s.state)
    }

    /// The configuration of stream `i`.
    pub fn stream_config(&self, i: usize) -> Option<&StreamConfig> {
        self.streams.get(i).map(|s| &s.cfg)
    }

    /// How many streams are configured.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Frames that matched no configured stream, including non-sampled-value traffic.
    /// A frame counts once however many ASDUs it carries.
    pub const fn other_stream(&self) -> u64 {
        self.other_stream
    }

    /// Sampled-value frames that did not decode.
    pub const fn malformed(&self) -> u64 {
        self.malformed
    }

    /// Stream-level events dropped because the application was not draining.
    pub const fn events_dropped(&self) -> u64 {
        self.events.dropped()
    }

    /// Go back to the real stream on stream `i` after a test.
    pub fn reset_simulation(&mut self, i: usize) {
        if let Some(s) = self.streams.get_mut(i) {
            s.state.simulation_active = false;
            s.state.last_smp_cnt = None;
        }
    }

    /// Feed one received Ethernet frame; every accepted ASDU is passed to `consumer`.
    pub fn on_frame<F: FnMut(Sample<'_>)>(&mut self, now: Instant, frame: &[u8], mut consumer: F) {
        // Time has passed even if nobody called `on_timeout`; notice a stream that went
        // quiet before this frame is reported as resuming.
        self.check_stale(now);
        let fr = match Frame::parse(frame) {
            Ok(f) => f,
            // A frame that does not parse belongs to one of our streams only if what can
            // still be read of its address says so; anything else is other traffic.
            Err(e) => {
                return match FrameAddress::peek(frame) {
                    Some(a) if a.ethertype == ETHERTYPE_SV && self.addressed(a.dst, a.appid) => self.on_malformed(e),
                    _ => self.other(),
                };
            }
        };
        if fr.ethertype != ETHERTYPE_SV || !self.addressed(fr.dst, fr.appid) {
            return self.other();
        }
        let pdu = match SavPduView::parse(fr.apdu, &self.limits) {
            Ok(p) => p,
            Err(e) => return self.on_malformed(e),
        };
        let simulated = fr.simulation();
        // A frame counts once, however many ASDUs it carries.
        let mut matched = false;
        let mut counted: Option<usize> = None;
        for asdu in pdu.asdus() {
            let asdu = match asdu {
                Ok(a) => a,
                // The remaining bytes cannot be trusted once one ASDU fails to frame.
                Err(e) => return self.on_malformed(e),
            };
            let Some(i) = self.streams.iter().position(|s| s.cfg.key.dst == fr.dst && s.cfg.key.appid == fr.appid && s.cfg.key.sv_id == asdu.sv_id) else {
                continue;
            };
            matched = true;
            if !self.simulation_policy_admits(i, simulated) || !self.accept(i, now, &asdu) {
                continue;
            }
            if counted != Some(i) {
                counted = Some(i);
                if let Some(s) = self.streams.get_mut(i) {
                    s.state.frames = s.state.frames.saturating_add(1);
                }
            }
            consumer(Sample { stream: i, asdu, simulation: simulated, layout: self.streams.get(i).and_then(|s| s.cfg.layout.as_ref()) });
        }
        if !matched {
            self.other();
        }
    }

    /// Time passed: mark streams that have gone quiet.
    pub fn on_timeout(&mut self, now: Instant) {
        self.check_stale(now);
    }

    fn check_stale(&mut self, now: Instant) {
        for i in 0..self.streams.len() {
            let due = match self.streams.get(i) {
                Some(s) => matches!(s.deadline, Some(d) if now >= d) && !s.state.stale,
                None => false,
            };
            if due {
                if let Some(s) = self.streams.get_mut(i) {
                    s.state.stale = true;
                    s.deadline = None;
                }
                self.events.push(SubscriberEvent::Stale { stream: i });
            }
        }
    }

    /// When [`Subscriber::on_timeout`] must next be called.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.streams.iter().filter_map(|s| s.deadline).min()
    }

    /// Take the next stream-level event.
    pub fn poll_event(&mut self) -> Option<SubscriberEvent> {
        self.events.pop()
    }

    /// Apply the Edition 2 simulation policy to stream `i`. False means drop the ASDU.
    fn simulation_policy_admits(&mut self, i: usize, simulated: bool) -> bool {
        let Subscriber { streams, events, .. } = self;
        let Some(s) = streams.get_mut(i) else { return false };
        match (s.cfg.simulation, simulated) {
            (SimulationMode::Off, false) => {
                s.simulation_reported = false;
                true
            }
            (SimulationMode::Off, true) => {
                s.state.simulation_dropped = s.state.simulation_dropped.saturating_add(1);
                if !s.simulation_reported {
                    s.simulation_reported = true;
                    events.push(SubscriberEvent::IgnoredSimulation { stream: i });
                }
                false
            }
            (SimulationMode::Preferred, true) => {
                if !s.state.simulation_active {
                    s.state.simulation_active = true;
                    // The simulated stream takes over; the real stream's counter must not
                    // make the first simulated sample look like a gap.
                    s.state.last_smp_cnt = None;
                    events.push(SubscriberEvent::SimulationTakeover { stream: i });
                }
                true
            }
            (SimulationMode::Preferred, false) => {
                if s.state.simulation_active {
                    s.state.simulation_dropped = s.state.simulation_dropped.saturating_add(1);
                    return false;
                }
                true
            }
        }
    }

    /// Update stream `i` from `asdu`. Returns false when the ASDU must be dropped.
    fn accept(&mut self, i: usize, now: Instant, asdu: &AsduView<'_>) -> bool {
        // Borrow the stream and the event queue as disjoint fields so state can be updated
        // and events queued in one pass.
        let Subscriber { streams, events, .. } = self;
        let Some(s) = streams.get_mut(i) else { return false };
        if let Some(expected) = s.cfg.expected_conf_rev {
            if expected != asdu.conf_rev {
                s.state.conf_rev_dropped = s.state.conf_rev_dropped.saturating_add(1);
                if !s.conf_rev_reported {
                    s.conf_rev_reported = true;
                    events.push(SubscriberEvent::ConfRevMismatch { stream: i, received: asdu.conf_rev });
                }
                return false;
            }
            s.conf_rev_reported = false;
        }

        // A sample block that is not the length the engineering file describes is not this
        // data set: decoding it would report channels that are not there. The stream is
        // publishing something else, which is a commissioning finding, not a sample.
        if let Some(layout) = s.cfg.layout.as_ref() {
            if !layout.fits(asdu.sample.len()) {
                s.state.layout_mismatches = s.state.layout_mismatches.saturating_add(1);
                if !s.layout_reported {
                    s.layout_reported = true;
                    events.push(SubscriberEvent::SampleLengthMismatch { stream: i, expected: layout.len(), received: asdu.sample.len() });
                }
                return false;
            }
            s.layout_reported = false;
        }

        if let Some(last) = s.state.last_smp_cnt {
            let wrap = s.cfg.wrap();
            let expected = ((u32::from(last) + 1) % wrap) as u16;
            if asdu.smp_cnt != expected {
                let lost = (u32::from(asdu.smp_cnt) + wrap - u32::from(expected)) % wrap;
                s.state.gaps = s.state.gaps.saturating_add(1);
                s.state.samples_lost = s.state.samples_lost.saturating_add(u64::from(lost));
                events.push(SubscriberEvent::Gap { stream: i, expected, received: asdu.smp_cnt, lost });
            }
        }
        s.state.conf_rev = Some(asdu.conf_rev);
        if s.state.smp_synch != asdu.smp_synch {
            events.push(SubscriberEvent::SyncChanged { stream: i, from: s.state.smp_synch, to: asdu.smp_synch });
            s.state.smp_synch = asdu.smp_synch;
        }
        let gm = asdu.gm_identity.and_then(|g| <[u8; 8]>::try_from(g).ok());
        if gm != s.state.gm_identity {
            s.state.gm_identity = gm;
            events.push(SubscriberEvent::GrandmasterChanged { stream: i, to: gm });
        }
        if s.state.stale {
            s.state.stale = false;
            events.push(SubscriberEvent::Resumed { stream: i });
        }
        s.state.last_smp_cnt = Some(asdu.smp_cnt);
        s.state.asdus = s.state.asdus.saturating_add(1);
        s.deadline = Some(now.plus_millis(u64::from(s.cfg.stale_after_ms)));
        true
    }

    /// True when any configured stream listens on this destination and APPID. The `svID`
    /// lives inside the ASDU and cannot be read from a frame that failed to decode, so this
    /// is as precise as the link layer allows — and it is what keeps another merging unit's
    /// broken frame out of *this* subscriber's malformed count.
    fn addressed(&self, dst: MacAddr, appid: u16) -> bool {
        self.streams.iter().any(|s| s.cfg.key.dst == dst && s.cfg.key.appid == appid)
    }

    fn other(&mut self) {
        self.other_stream = self.other_stream.saturating_add(1);
    }

    fn on_malformed(&mut self, e: Error) {
        self.malformed = self.malformed.saturating_add(1);
        self.events.push(SubscriberEvent::Malformed(e));
    }
}

#[cfg(test)]
mod tests {
    // `vec!` is `std`'s prelude, and these tests run under `--no-default-features` too.
    use alloc::vec;

    use super::*;
    use crate::proto::ethernet::{FrameHeader, RESERVED1_SIMULATION};
    use crate::proto::sv::{Asdu, SavPdu};

    fn asdu(sv_id: &str, cnt: u16, synch: SmpSynch) -> Asdu {
        Asdu {
            sv_id: sv_id.into(),
            dat_set: None,
            smp_cnt: cnt,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: Some(synch),
            smp_rate: None,
            sample: vec![0; 64],
            smp_mod: None,
            gm_identity: None,
        }
    }

    fn frame_of(asdus: Vec<Asdu>, simulated: bool) -> Vec<u8> {
        let pdu = SavPdu { asdus };
        FrameHeader {
            dst: MacAddr::SV_BASE,
            src: MacAddr::default(),
            vlan: None,
            ethertype: ETHERTYPE_SV,
            appid: 0x4000,
            reserved1: if simulated { RESERVED1_SIMULATION } else { 0 },
            reserved2: 0,
        }
        .to_frame(&pdu.encode().unwrap())
        .unwrap()
    }

    fn frame(cnt: u16, synch: SmpSynch) -> Vec<u8> {
        frame_of(vec![asdu("MU01", cnt, synch)], false)
    }

    fn key() -> StreamKey {
        StreamKey { dst: MacAddr::SV_BASE, appid: 0x4000, sv_id: "MU01".into() }
    }

    fn sub() -> Subscriber {
        Subscriber::new(vec![StreamConfig::new(key()).with_conf_rev(1)])
    }

    #[test]
    fn continuity_across_the_wrap() {
        let mut s = sub();
        let mut got = Vec::new();
        for cnt in [3998u16, 3999, 0, 1, 3] {
            s.on_frame(Instant::ZERO, &frame(cnt, SmpSynch::Global), |smp| got.push(smp.asdu.smp_cnt));
        }
        assert_eq!(got, [3998, 3999, 0, 1, 3]);
        assert_eq!(s.poll_event(), Some(SubscriberEvent::SyncChanged { stream: 0, from: None, to: Some(SmpSynch::Global) }));
        assert_eq!(s.poll_event(), Some(SubscriberEvent::Gap { stream: 0, expected: 2, received: 3, lost: 1 }));
        assert_eq!(s.poll_event(), None);
        let st = s.state(0).unwrap();
        assert_eq!((st.gaps, st.samples_lost, st.frames, st.asdus), (1, 1, 5, 5));
    }

    #[test]
    fn a_gap_across_the_wrap_counts_the_short_way() {
        let mut s = sub();
        s.on_frame(Instant::ZERO, &frame(3998, SmpSynch::Global), |_| {});
        let _ = s.poll_event();
        // Expected 3999, got 2: three samples lost across the wrap, not 3996.
        s.on_frame(Instant::ZERO, &frame(2, SmpSynch::Global), |_| {});
        assert_eq!(s.poll_event(), Some(SubscriberEvent::Gap { stream: 0, expected: 3999, received: 2, lost: 3 }));
    }

    #[test]
    fn a_multi_asdu_frame_counts_as_one_frame() {
        // IEC 61869-9 sends 2 (4.8 kHz) or 6 (14.4 kHz) ASDUs per frame.
        let mut s = sub();
        let mut seen = 0;
        s.on_frame(Instant::ZERO, &frame_of(vec![asdu("MU01", 0, SmpSynch::Global), asdu("MU01", 1, SmpSynch::Global)], false), |_| seen += 1);
        assert_eq!(seen, 2);
        let st = s.state(0).unwrap();
        assert_eq!((st.frames, st.asdus, st.gaps), (1, 2, 0));
        assert_eq!(s.other_stream(), 0, "a frame of ours is never other traffic");
    }

    #[test]
    fn conf_rev_mismatch_is_edge_triggered() {
        let mut s = sub();
        let mut bad = asdu("MU01", 0, SmpSynch::Global);
        bad.conf_rev = 9;
        for _ in 0..100 {
            s.on_frame(Instant::ZERO, &frame_of(vec![bad.clone()], false), |_| unreachable!("dropped"));
        }
        assert_eq!(s.poll_event(), Some(SubscriberEvent::ConfRevMismatch { stream: 0, received: 9 }));
        assert_eq!(s.poll_event(), None, "one event, not one per ASDU");
        assert_eq!(s.state(0).unwrap().conf_rev_dropped, 100);
        assert_eq!(s.state(0).unwrap().frames, 0);
        assert_eq!(s.other_stream(), 0, "a stream we know is not other traffic just because we dropped it");
    }

    #[test]
    fn staleness_is_noticed_on_arrival_as_well_as_on_a_timer() {
        let mut s = sub();
        s.on_frame(Instant::ZERO, &frame(0, SmpSynch::Global), |_| {});
        let _ = s.poll_event();
        assert_eq!(s.next_timeout(), Some(Instant::ZERO.plus_millis(10)));
        s.on_timeout(Instant::ZERO.plus_millis(10));
        assert_eq!(s.poll_event(), Some(SubscriberEvent::Stale { stream: 0 }));
        s.on_timeout(Instant::ZERO.plus_millis(20));
        assert_eq!(s.poll_event(), None, "stale is reported once");
        s.on_frame(Instant::ZERO.plus_millis(21), &frame(1, SmpSynch::Global), |_| {});
        assert_eq!(s.poll_event(), Some(SubscriberEvent::Resumed { stream: 0 }));

        // And without any timer tick at all: the gap in time is noticed when the next
        // frame arrives, so an application driven only by the event stream still learns
        // that its samples were invalid in between.
        let mut s = sub();
        s.on_frame(Instant::ZERO, &frame(0, SmpSynch::Global), |_| {});
        while s.poll_event().is_some() {}
        s.on_frame(Instant::ZERO.plus_millis(500), &frame(1, SmpSynch::Global), |_| {});
        assert_eq!(s.poll_event(), Some(SubscriberEvent::Stale { stream: 0 }));
        assert_eq!(s.poll_event(), Some(SubscriberEvent::Resumed { stream: 0 }));
    }

    #[test]
    fn simulated_streams_follow_the_edition_2_rule() {
        // LPHD.Sim = false: simulated frames are dropped and reported once.
        let mut s = sub();
        let simulated = frame_of(vec![asdu("MU01", 0, SmpSynch::Global)], true);
        s.on_frame(Instant::ZERO, &simulated, |_| unreachable!("dropped"));
        assert_eq!(s.poll_event(), Some(SubscriberEvent::IgnoredSimulation { stream: 0 }));
        s.on_frame(Instant::ZERO, &simulated, |_| unreachable!("dropped"));
        assert_eq!(s.poll_event(), None, "reported once, not per frame");
        assert_eq!(s.state(0).unwrap().simulation_dropped, 2);

        // LPHD.Sim = true: the simulated stream takes over and the real one is ignored.
        let mut s = Subscriber::new(vec![StreamConfig::new(key()).with_simulation(SimulationMode::Preferred)]);
        let mut seen = Vec::new();
        s.on_frame(Instant::ZERO, &frame(100, SmpSynch::Global), |smp| seen.push((smp.asdu.smp_cnt, smp.simulation)));
        s.on_frame(Instant::ZERO, &simulated, |smp| seen.push((smp.asdu.smp_cnt, smp.simulation)));
        s.on_frame(Instant::ZERO, &frame(101, SmpSynch::Global), |smp| seen.push((smp.asdu.smp_cnt, smp.simulation)));
        assert_eq!(seen, [(100, false), (0, true)], "the real stream is dropped once simulation took over");
        assert!(s.state(0).unwrap().simulation_active);
        while s.poll_event().is_some() {}
        s.reset_simulation(0);
        s.on_frame(Instant::ZERO, &frame(102, SmpSynch::Global), |smp| seen.push((smp.asdu.smp_cnt, smp.simulation)));
        assert_eq!(seen.last(), Some(&(102, false)));
        assert_eq!(s.poll_event(), None, "returning to the real stream is not a gap");
    }

    #[test]
    fn a_stream_with_a_layout_hands_over_channels_and_one_without_hands_over_octets() {
        use crate::proto::sv::{ChannelType, SampleLayout};
        let layout = SampleLayout::new([(String::from("Ia.instMag.i"), ChannelType::Int(4)), (String::from("Ia.q"), ChannelType::Quality)]);
        let mut with = Subscriber::new(vec![StreamConfig::new(key()).with_layout(layout)]);
        let mut a = asdu("MU01", 0, SmpSynch::Global);
        a.sample = alloc::vec![0, 0, 0x30, 0x39, 0, 0, 0, 0];
        let frame = frame_of(vec![a], false);
        let mut seen = Vec::new();
        with.on_frame(Instant::ZERO, &frame, |s| {
            seen = s.channels().map(|(c, v)| (c.name.clone(), v)).collect();
            assert_eq!(s.channel(0).and_then(ChannelValue::as_i64), Some(12_345));
        });
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, "Ia.instMag.i");
        assert_eq!(seen[0].1.as_i64(), Some(12_345));
        assert_eq!(seen[1].1.as_quality(), Some(crate::common::Quality::GOOD));

        // Without a layout the octets are still there; nothing is invented about them.
        let mut without = sub();
        let mut n = 0;
        without.on_frame(Instant::ZERO, &frame, |s| {
            n = s.channels().count();
            assert_eq!(s.asdu.sample.len(), 8);
            assert_eq!(s.channel(0), None);
        });
        assert_eq!(n, 0);

        // A block that is not the length the file describes is not this data set. Decoding
        // it would name channels that are not there, so the ASDU is dropped and said so
        // once — a merging unit publishing a data set other than the engineered one is a
        // commissioning finding, and a silent one is worse than none.
        let short = SampleLayout::new([(String::from("Ia.instMag.i"), ChannelType::Int(4))]);
        let mut strict = Subscriber::new(vec![StreamConfig::new(key()).with_layout(short)]);
        strict.on_frame(Instant::ZERO, &frame, |_| unreachable!("a mismatched ASDU must not reach the consumer"));
        assert!(matches!(strict.poll_event(), Some(SubscriberEvent::SampleLengthMismatch { expected: 4, received: 8, .. })));
        strict.on_frame(Instant::ZERO, &frame, |_| unreachable!());
        assert!(strict.poll_event().is_none(), "reported once, not per ASDU");
        assert_eq!(strict.state(0).unwrap().layout_mismatches, 2);
        assert_eq!(strict.state(0).unwrap().asdus, 0);
    }

    #[test]
    fn other_traffic_and_malformed_frames() {
        let mut s = sub();
        let mut other = frame(6, SmpSynch::None);
        other[5] = 1;
        s.on_frame(Instant::ZERO, &other, |_| unreachable!());
        s.on_frame(Instant::ZERO, &[0u8; 40], |_| unreachable!());
        assert_eq!(s.other_stream(), 2);
        s.on_frame(Instant::ZERO, &frame(7, SmpSynch::None)[..30], |_| unreachable!());
        assert!(matches!(s.poll_event(), Some(SubscriberEvent::Malformed(_))));
        assert_eq!(s.malformed(), 1);
        // Another merging unit's broken frame is other traffic, not a fault of ours:
        // `malformed` is an intrusion-detection counter and has to mean what it says.
        let mut theirs = frame(8, SmpSynch::None);
        theirs[15] = 0x09; // another APPID
        s.on_frame(Instant::ZERO, &theirs[..30], |_| unreachable!());
        s.on_frame(Instant::ZERO, &theirs, |_| unreachable!());
        assert_eq!((s.malformed(), s.other_stream()), (1, 4));
    }

    #[test]
    fn the_event_queue_is_bounded() {
        let mut s = Subscriber::new(vec![StreamConfig::new(key())]).with_event_capacity(4);
        // Every other sample missing: one gap event per frame, none of them drained.
        for cnt in (0..200u16).step_by(2) {
            s.on_frame(Instant::ZERO, &frame(cnt, SmpSynch::Global), |_| {});
        }
        let mut n = 0;
        while s.poll_event().is_some() {
            n += 1;
        }
        assert_eq!(n, 4);
        assert!(s.events_dropped() > 90);
        assert_eq!(s.state(0).unwrap().gaps, 99, "dropping events must not lose counters");
    }
}
