use alloc::string::String;
use alloc::vec::Vec;

use super::apdu::{GooseHeader, encode_into};
use crate::ber::Encoder;
use crate::common::{Error, Instant, Result, UtcTime};
use crate::proto::data::Value;
use crate::proto::ethernet::{FrameHeader, RESERVED1_SIMULATION};

/// The retransmission curve of IEC 61850-8-1.
///
/// After a state change the frame goes out immediately, then after `min_time` (T1) twice,
/// then at doubling intervals (T2, T3 …) until `max_time` (T0), and at `max_time` for as
/// long as the state holds.
///
/// `timeAllowedtoLive` is `tal_factor` times the interval to the *next* transmission; the
/// conventional factor is 2, so a subscriber that misses one frame still has the full next
/// interval to receive the one after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retransmission {
    /// T1, the first retransmission interval in milliseconds (SCL `GSE/MinTime`).
    pub min_time_ms: u32,
    /// T0, the steady-state interval in milliseconds (SCL `GSE/MaxTime`).
    pub max_time_ms: u32,
    /// `timeAllowedtoLive` = `tal_factor` × the next interval.
    pub tal_factor: u32,
}

impl Retransmission {
    /// 4 ms → 1000 ms with factor 2 — a common protection profile.
    pub const DEFAULT: Retransmission = Retransmission { min_time_ms: 4, max_time_ms: 1000, tal_factor: 2 };

    /// The interval after the `n`-th transmission of a state (`n = 0` is the frame that
    /// carried the state change itself).
    pub const fn interval_after(&self, n: u32) -> u32 {
        let base = if self.min_time_ms == 0 { 1 } else { self.min_time_ms };
        let max = if self.max_time_ms < base { base } else { self.max_time_ms };
        if n <= 1 {
            return base;
        }
        let shift = n - 1;
        if shift >= 31 {
            return max;
        }
        let v = (base as u64) << shift;
        if v >= max as u64 { max } else { v as u32 }
    }

    /// `timeAllowedtoLive` to advertise on the `n`-th transmission.
    pub const fn tal_after(&self, n: u32) -> u32 {
        let factor = if self.tal_factor == 0 { 1 } else { self.tal_factor };
        self.interval_after(n).saturating_mul(factor)
    }
}

/// Static configuration of a publisher: what the SCL `GSEControl` and its `GSE` address
/// element say.
#[derive(Clone, Debug, PartialEq)]
pub struct PublisherConfig {
    /// Link-layer header. Its `reserved1` simulation bit is managed by the publisher.
    pub header: FrameHeader,
    /// `gocbRef`.
    pub gocb_ref: String,
    /// `datSet`.
    pub dat_set: String,
    /// `goID`.
    pub go_id: Option<String>,
    /// `confRev`.
    pub conf_rev: u32,
    /// Retransmission curve.
    pub retransmission: Retransmission,
    /// Publish with the simulation flag set (a test set, not the configured publisher).
    pub simulation: bool,
    /// `ndsCom` — this publisher still needs commissioning and its data is not usable.
    pub nds_com: bool,
}

impl PublisherConfig {
    /// A configuration for one control block, with the defaults: no `goID`, `confRev` 1, the
    /// 4 ms → 1 s retransmission curve, not simulated, commissioned.
    ///
    /// The usual path is [`crate::model::IedModel::goose_publisher_config`], which fills all
    /// of this in from the SCL file. This is for the cases where there is no file.
    pub fn new(header: FrameHeader, gocb_ref: impl Into<String>, dat_set: impl Into<String>) -> PublisherConfig {
        PublisherConfig {
            header,
            gocb_ref: gocb_ref.into(),
            dat_set: dat_set.into(),
            go_id: None,
            conf_rev: 1,
            retransmission: Retransmission::DEFAULT,
            simulation: false,
            nds_com: false,
        }
    }

    /// Set `goID`.
    #[must_use]
    pub fn with_go_id(mut self, go_id: impl Into<String>) -> PublisherConfig {
        self.go_id = Some(go_id.into());
        self
    }

    /// Set `confRev`. It must match what subscribers were engineered with, or they drop the
    /// stream.
    #[must_use]
    pub const fn with_conf_rev(mut self, conf_rev: u32) -> PublisherConfig {
        self.conf_rev = conf_rev;
        self
    }

    /// Set the retransmission curve (SCL `GSE/MinTime` and `MaxTime`).
    #[must_use]
    pub const fn with_retransmission(mut self, retransmission: Retransmission) -> PublisherConfig {
        self.retransmission = retransmission;
        self
    }

    /// Publish with the Edition 2 simulation flag set — a test set, not the configured
    /// publisher.
    #[must_use]
    pub const fn with_simulation(mut self, simulation: bool) -> PublisherConfig {
        self.simulation = simulation;
        self
    }

    /// Publish with `ndsCom`: this publisher still needs commissioning and its data is not
    /// usable.
    #[must_use]
    pub const fn with_nds_com(mut self, nds_com: bool) -> PublisherConfig {
        self.nds_com = nds_com;
        self
    }
}

/// The GOOSE publisher state machine.
///
/// Sans-IO: it owns no socket and reads no clock. Call [`Publisher::publish`] when the
/// application's data changes, [`Publisher::on_timeout`] when [`Publisher::next_timeout`]
/// comes due, and send whatever [`Publisher::poll_transmit`] hands back.
///
/// Frames are built into a buffer the publisher owns and reuses, so steady-state
/// retransmission allocates nothing.
#[derive(Debug)]
pub struct Publisher {
    cfg: PublisherConfig,
    st_num: u32,
    sq_num: u32,
    t: UtcTime,
    simulation: bool,
    /// Transmissions of the current state so far.
    sent_in_state: u32,
    /// The encoded `allData` body, rebuilt only when the values change — into its own
    /// reused buffer, because a state change during a fault is the worst moment to visit
    /// the allocator.
    body: Encoder,
    members: u32,
    /// Scratch the next data set is encoded into before it is compared with [`Self::body`],
    /// so that [`Publisher::publish_if_changed`] can tell a real state change from a
    /// repeated one without allocating.
    scratch: Encoder,
    /// Scratch for the APDU, kept between frames so a retransmission allocates nothing.
    apdu: Encoder,
    /// The frame to send, or empty when there is nothing pending.
    frame: Vec<u8>,
    pending: bool,
    next_send: Option<Instant>,
    /// Frames that were overwritten because the caller did not collect them.
    dropped: u64,
}

impl Publisher {
    /// A publisher holding `initial_values`, ready to send its first frame immediately
    /// ([`Publisher::next_timeout`] returns [`Instant::ZERO`]).
    ///
    /// `t` is the timestamp of the initial state.
    pub fn new(cfg: PublisherConfig, initial_values: &[Value], t: UtcTime) -> Result<Publisher> {
        if !cfg.gocb_ref.is_ascii() || !cfg.dat_set.is_ascii() || cfg.go_id.as_ref().is_some_and(|s| !s.is_ascii()) {
            return Err(Error::Encode("gocbRef, datSet and goID must be ASCII (VisibleString)"));
        }
        let mut body = Encoder::with_capacity(64);
        for v in initial_values {
            v.encode(&mut body)?;
        }
        let simulation = cfg.simulation;
        let bound = apdu_bound(&cfg, body.len());
        let apdu = Encoder::with_capacity(bound);
        let frame = Vec::with_capacity(cfg.header.len() + bound);
        let scratch = Encoder::with_capacity(body.len().max(64));
        Ok(Publisher {
            cfg,
            st_num: 1,
            sq_num: 0,
            t,
            simulation,
            sent_in_state: 0,
            scratch,
            apdu,
            body,
            members: initial_values.len() as u32,
            frame,
            pending: false,
            next_send: Some(Instant::ZERO),
            dropped: 0,
        })
    }

    /// Current `stNum`.
    pub const fn st_num(&self) -> u32 {
        self.st_num
    }

    /// `sqNum` of the frame most recently built.
    pub const fn sq_num(&self) -> u32 {
        self.sq_num
    }

    /// The configuration.
    pub const fn config(&self) -> &PublisherConfig {
        &self.cfg
    }

    /// Frames overwritten because the caller did not collect them before the next one was
    /// due. A healthy publisher never drops any.
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Publish new data-set values as of `t`: `stNum` advances, `sqNum` restarts at 0 and
    /// the retransmission curve begins again, which is exactly what a state change means in
    /// IEC 61850-8-1.
    pub fn publish(&mut self, now: Instant, values: &[Value], t: UtcTime) -> Result<()> {
        self.body.clear();
        for v in values {
            v.encode(&mut self.body)?;
        }
        self.members = values.len() as u32;
        self.advance_state(now, t)
    }

    /// Begin a new state: `stNum` advances, `sqNum` restarts and the curve begins again.
    fn advance_state(&mut self, now: Instant, t: UtcTime) -> Result<()> {
        self.t = t;
        // `stNum` wraps to 1, never to 0: 0 would be indistinguishable from an
        // uninitialised publisher.
        self.st_num = if self.st_num == u32::MAX { 1 } else { self.st_num.saturating_add(1) };
        self.sq_num = 0;
        self.sent_in_state = 0;
        self.build(now)
    }

    /// Publish `values` **only if they differ** from the ones currently being sent, and say
    /// whether they did.
    ///
    /// `stNum` counts *state changes*, and IEC 61850-8-1 gives a state change a whole
    /// retransmission curve of its own. An application that calls [`Publisher::publish`] on
    /// every scan cycle therefore floods the bus and makes every subscriber log a change
    /// that never happened. This compares the encoded data set with the one already in the
    /// buffer and does nothing when they match — the retransmission timer keeps running, so
    /// the stream stays alive either way.
    ///
    /// The comparison is on encoded bytes, into a buffer the publisher keeps, so it costs
    /// one encode and no allocation.
    pub fn publish_if_changed(&mut self, now: Instant, values: &[Value], t: UtcTime) -> Result<bool> {
        self.scratch.clear();
        for v in values {
            v.encode(&mut self.scratch)?;
        }
        if self.members as usize == values.len() && self.scratch.as_bytes() == self.body.as_bytes() {
            return Ok(false);
        }
        core::mem::swap(&mut self.body, &mut self.scratch);
        self.members = values.len() as u32;
        self.advance_state(now, t)?;
        Ok(true)
    }

    /// The retransmission timer came due.
    pub fn on_timeout(&mut self, now: Instant) -> Result<()> {
        match self.next_send {
            Some(due) if now >= due => self.build(now),
            _ => Ok(()),
        }
    }

    /// Turn the simulation flag on or off; it takes effect with the next frame.
    pub fn set_simulation(&mut self, on: bool) {
        self.simulation = on;
    }

    /// When [`Publisher::on_timeout`] must next be called.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.next_send
    }

    /// The frame to send now, or `None`. The slice borrows the publisher's buffer and is
    /// valid until the next call that mutates it.
    pub fn poll_transmit(&mut self) -> Option<&[u8]> {
        if core::mem::take(&mut self.pending) { Some(&self.frame) } else { None }
    }

    /// Build the next frame into the reusable buffers and schedule the one after it.
    ///
    /// Both buffers are the publisher's own and are only cleared, never reallocated, so a
    /// publisher in steady state does not allocate. The APDU is re-encoded rather than
    /// patched because BER's minimal-length rule lets `stNum`, `sqNum` and
    /// `timeAllowedtoLive` change width between frames — encoding a hundred-odd octets is
    /// cheaper than the bookkeeping that would make patching safe.
    fn build(&mut self, now: Instant) -> Result<()> {
        let interval = self.cfg.retransmission.interval_after(self.sent_in_state);
        // Fields are destructured so the header can borrow the configuration while the
        // encoder is borrowed mutably.
        let Publisher { cfg, apdu, body, frame, t, st_num, sq_num, simulation, members, sent_in_state, .. } = self;
        let header = GooseHeader {
            gocb_ref: &cfg.gocb_ref,
            time_allowed_to_live: cfg.retransmission.tal_after(*sent_in_state),
            dat_set: &cfg.dat_set,
            go_id: cfg.go_id.as_deref(),
            t: *t,
            st_num: *st_num,
            sq_num: *sq_num,
            simulation: *simulation,
            conf_rev: cfg.conf_rev,
            nds_com: cfg.nds_com,
            num_dat_set_entries: *members,
        };
        // Both buffers are empty at this point, so `reserve` asks for the whole bound. It is
        // a comparison once the capacity is there, which after the first frame it always is.
        let bound = apdu_bound(cfg, body.len());
        apdu.clear();
        apdu.reserve(bound);
        encode_into(&header, body.as_bytes(), apdu)?;
        let apdu = apdu.as_bytes();

        let mut link = cfg.header;
        link.reserved1 = if *simulation { link.reserved1 | RESERVED1_SIMULATION } else { link.reserved1 & !RESERVED1_SIMULATION };
        frame.clear();
        frame.reserve(link.len() + bound);
        frame.resize(link.len() + apdu.len(), 0);
        link.write(apdu, frame)?;

        if self.pending {
            self.dropped = self.dropped.saturating_add(1);
        }
        self.pending = true;
        self.sent_in_state = self.sent_in_state.saturating_add(1);
        // `sqNum` wraps at the top of the range; 0 marks a state change, so it resumes at 1.
        self.sq_num = if self.sq_num == u32::MAX { 1 } else { self.sq_num + 1 };
        self.next_send = Some(now.plus_millis(u64::from(interval)));
        Ok(())
    }
}

/// An upper bound on the encoded APDU: every field at its widest encoding.
///
/// `stNum`, `sqNum` and `timeAllowedtoLive` change width as they grow, so a buffer sized for
/// the first frame would be reallocated somewhere around the 128th — once, quietly, and in
/// the middle of a retransmission. Reserving the bound up front removes that.
fn apdu_bound(cfg: &PublisherConfig, body_len: usize) -> usize {
    // Tag plus a long-form length, for the PDU itself and for `allData`.
    const WRAPPER: usize = 6;
    // Tag plus up to two length octets, for each of the eleven fields.
    const FIELD: usize = 3 * 11;
    // `timeAllowedtoLive`, `stNum`, `sqNum`, `confRev`, `numDatSetEntries`, each up to five
    // contents octets as an unsigned INTEGER with a leading zero.
    const COUNTERS: usize = 5 * 5;
    // `t`, plus one octet each for `simulation` and `ndsCom`.
    const FLAGS_AND_TIME: usize = 8 + 2;
    WRAPPER * 2 + FIELD + COUNTERS + FLAGS_AND_TIME + cfg.gocb_ref.len() + cfg.dat_set.len() + cfg.go_id.as_ref().map_or(0, String::len) + body_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ethernet::{ETHERTYPE_GOOSE, Frame, MacAddr};
    use crate::proto::goose::GoosePduView;

    fn cfg() -> PublisherConfig {
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
            gocb_ref: "IED1LD0/LLN0$GO$gcb1".into(),
            dat_set: "IED1LD0/LLN0$ds1".into(),
            go_id: None,
            conf_rev: 1,
            retransmission: Retransmission::DEFAULT,
            simulation: false,
            nds_com: false,
        }
    }

    /// (stNum, sqNum, timeAllowedtoLive) of the pending frame.
    fn take(p: &mut Publisher) -> Option<(u32, u32, u32)> {
        let frame = p.poll_transmit()?.to_vec();
        let fr = Frame::parse(&frame).unwrap();
        let pdu = GoosePduView::parse(fr.apdu).unwrap();
        Some((pdu.st_num, pdu.sq_num, pdu.time_allowed_to_live))
    }

    #[test]
    fn the_curve_matches_t1_t1_t2_t3_t0() {
        let r = Retransmission::DEFAULT;
        assert_eq!([0, 1, 2, 3, 4, 8, 9].map(|n| r.interval_after(n)), [4, 4, 8, 16, 32, 512, 1000]);
        assert_eq!(r.tal_after(0), 8);
        // Degenerate configurations do not divide by zero or overflow.
        let z = Retransmission { min_time_ms: 0, max_time_ms: 0, tal_factor: 0 };
        assert_eq!((z.interval_after(0), z.interval_after(40), z.tal_after(3)), (1, 1, 1));
    }

    #[test]
    fn counters_and_scheduling() {
        let mut p = Publisher::new(cfg(), &[Value::Boolean(false)], UtcTime::default()).unwrap();
        assert_eq!(p.next_timeout(), Some(Instant::ZERO));
        assert!(p.poll_transmit().is_none(), "nothing is built before the first tick");

        let mut now = Instant::ZERO;
        p.on_timeout(now).unwrap();
        assert_eq!(take(&mut p), Some((1, 0, 8)));
        assert!(p.poll_transmit().is_none(), "a frame is handed out once");
        assert_eq!(p.next_timeout(), Some(now.plus_millis(4)));

        now = p.next_timeout().unwrap();
        p.on_timeout(now).unwrap();
        assert_eq!(take(&mut p), Some((1, 1, 8)));
        now = p.next_timeout().unwrap();
        p.on_timeout(now).unwrap();
        assert_eq!(take(&mut p), Some((1, 2, 16)));

        // A state change restarts the curve with stNum + 1 and sqNum 0.
        p.publish(now, &[Value::Boolean(true)], UtcTime::default()).unwrap();
        assert_eq!(take(&mut p), Some((2, 0, 8)));
        assert_eq!(p.next_timeout(), Some(now.plus_millis(4)));

        // An early timeout does nothing.
        p.on_timeout(now).unwrap();
        assert!(p.poll_transmit().is_none());
    }

    #[test]
    fn publishing_unchanged_values_is_not_a_state_change() {
        // `stNum` counts state changes, and each one costs a whole retransmission curve.
        // An application that pushes its scan cycle at the publisher must not produce one.
        let mut p = Publisher::new(cfg(), &[Value::Boolean(false)], UtcTime::default()).unwrap();
        p.on_timeout(Instant::ZERO).unwrap();
        assert_eq!(take(&mut p), Some((1, 0, 8)));

        assert!(!p.publish_if_changed(Instant::ZERO, &[Value::Boolean(false)], UtcTime::default()).unwrap());
        assert_eq!(p.st_num(), 1);
        assert!(p.poll_transmit().is_none(), "nothing new to send");
        // The retransmission timer is untouched, so the stream stays alive.
        assert_eq!(p.next_timeout(), Some(Instant::ZERO.plus_millis(4)));

        assert!(p.publish_if_changed(Instant::ZERO, &[Value::Boolean(true)], UtcTime::default()).unwrap());
        assert_eq!(take(&mut p), Some((2, 0, 8)));
        // A different number of members is a change even if the shared prefix matches.
        assert!(p.publish_if_changed(Instant::ZERO, &[Value::Boolean(true), Value::Boolean(true)], UtcTime::default()).unwrap());
        assert_eq!(take(&mut p).unwrap().0, 3);
        assert!(!p.publish_if_changed(Instant::ZERO, &[Value::Boolean(true), Value::Boolean(true)], UtcTime::default()).unwrap());
    }

    #[test]
    fn st_num_wraps_to_one_never_zero() {
        let mut p = Publisher::new(cfg(), &[], UtcTime::default()).unwrap();
        for st in [u32::MAX, 1, 2] {
            p.st_num = st;
            p.publish(Instant::ZERO, &[], UtcTime::default()).unwrap();
            let expected = if st == u32::MAX { 1 } else { st + 1 };
            assert_eq!(take(&mut p).unwrap().0, expected);
        }
    }

    #[test]
    fn uncollected_frames_are_counted_not_queued() {
        let mut p = Publisher::new(cfg(), &[], UtcTime::default()).unwrap();
        let mut now = Instant::ZERO;
        for _ in 0..5 {
            p.on_timeout(now).unwrap();
            now = p.next_timeout().unwrap();
        }
        assert_eq!(p.dropped(), 4, "only the newest frame is kept");
        assert!(p.poll_transmit().is_some());
    }

    #[test]
    fn simulation_sets_both_flags() {
        let mut c = cfg();
        c.simulation = true;
        let mut p = Publisher::new(c, &[], UtcTime::default()).unwrap();
        p.on_timeout(Instant::ZERO).unwrap();
        let frame = p.poll_transmit().unwrap().to_vec();
        let fr = Frame::parse(&frame).unwrap();
        assert!(fr.simulation());
        assert!(GoosePduView::parse(fr.apdu).unwrap().simulation);
    }

    #[test]
    fn non_ascii_configuration_is_rejected_at_construction() {
        let mut c = cfg();
        c.gocb_ref = "IED1LD0/LLN0$GO$gcbü".into();
        assert!(Publisher::new(c, &[], UtcTime::default()).is_err());
    }
}
