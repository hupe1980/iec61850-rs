//! The server's GOOSE and sampled-value publishers, driven by its own control blocks.
//!
//! A `GoCB` or `MSVCB` the SCL file declares is served as MMS variables; writing `GoEna` or
//! `SvEna` makes it publish. This module is that connection, and it is sans-IO like every core
//! here: [`Publishers`] reacts to the model's dirty set and to time, and hands out finished
//! frames through [`Publishers::drain`]. Sending them is the caller's (`Server::publish_on`
//! with the `net` feature, or anything else that can put octets on a wire).
//!
//! - **GOOSE**: the data set is read from the served model when the block is enabled; a
//!   change to any member publishes a new state (`stNum` advances) and the T1…T0
//!   retransmission curve starts again; between changes the curve runs on its own.
//! - **SV**: sample-and-hold — every sample period publishes the model's current values of the
//!   data set, encoded through the channel layout the file implies. A change takes effect
//!   from the next sample.
//! - Only `GoEna`/`SvEna` change anything: rates, addresses and data sets are engineered in
//!   the file, a client cannot write them, and writing `true` to an enabled block restarts
//!   nothing.
//! - A block whose data set cannot be published (an address missing from the file, a member
//!   that is not a fixed-width leaf for SV) is known at load, and enabling it is refused.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::ied::{BlockKind, Ied};
use crate::common::{Instant, MacAddr, TrgOps, UtcTime};
use crate::proto::data::Value;

/// The nominal system frequency used to read `smpRate` when `smpMod` counts samples per
/// period. SCL does not record it; 50 Hz unless the application says otherwise.
pub const DEFAULT_NOMINAL_HZ: u32 = 50;

/// One publishing control block.
#[derive(Debug)]
struct Entry {
    /// `IED1LD0/LLN0$GO$gcbTrip` — what `GoEna`/`SvEna` sit under.
    reference: String,
    /// The same block as the model names it: `IED1LD0/LLN0.gcbTrip`.
    #[cfg_attr(not(any(feature = "goose", feature = "sv")), allow(dead_code))]
    model_ref: String,
    kind: BlockKind,
    /// The data-set members, in order, as full MMS references.
    members: Vec<String>,
    /// Why the block cannot publish, when it cannot.
    refusal: Option<&'static str>,
    state: State,
}

#[derive(Debug)]
enum State {
    Disabled,
    #[cfg(feature = "goose")]
    Goose(crate::proto::goose::Publisher),
    #[cfg(feature = "sv")]
    Sv {
        publisher: crate::proto::sv::Publisher,
        layout: crate::proto::sv::SampleLayout,
        /// The current sample block, rewritten when a member changes.
        sample: Vec<u8>,
        /// When the next frame is due.
        due: Instant,
    },
}

/// The publishers of one served IED.
#[derive(Debug)]
pub struct Publishers {
    entries: Vec<Entry>,
    source: MacAddr,
    nominal_hz: u32,
}

impl Publishers {
    /// Every `GoCB` and `MSVCB` of `ied`, disabled.
    pub fn new(ied: &Ied) -> Publishers {
        let mut entries = Vec::new();
        for block in ied.blocks() {
            if !matches!(block.kind, BlockKind::Goose | BlockKind::SampledValue) {
                continue;
            }
            let model_ref = alloc::format!("{}/{}.{}", block.domain, block.node, block.name);
            let members = block.data_set.as_deref().and_then(|ds| ied.data_set(ds)).map(super::ied::ServedDataSet::references).unwrap_or_default();
            let mut entry = Entry { reference: block.reference.clone(), model_ref, kind: block.kind, members, refusal: None, state: State::Disabled };
            entry.refusal = check(ied, block.kind, &entry);
            entries.push(entry);
        }
        Publishers { entries, source: MacAddr([0; 6]), nominal_hz: DEFAULT_NOMINAL_HZ }
    }

    /// The source address frames are published from — the interface's. Takes effect for
    /// blocks enabled afterwards.
    pub fn set_source(&mut self, mac: MacAddr) {
        self.source = mac;
    }

    /// The system frequency for `smpRate` in samples per period. Takes effect for blocks
    /// enabled afterwards.
    pub fn set_nominal_hz(&mut self, hz: u32) {
        self.nominal_hz = hz;
    }

    /// Whether the block at `reference` (`IED1LD0/LLN0$GO$gcbTrip`) can be enabled, and why not.
    pub fn refusal(&self, reference: &str) -> Option<&'static str> {
        self.entries.iter().find(|e| e.reference == reference).and_then(|e| e.refusal)
    }

    /// Whether any enabled block publishes the data set at `reference`.
    pub fn publishes_data_set(&self, ied: &Ied, reference: &str) -> bool {
        ied.blocks()
            .iter()
            .any(|b| b.data_set.as_deref() == Some(reference) && self.entries.iter().any(|e| e.reference == b.reference && !matches!(e.state, State::Disabled)))
    }

    /// Blocks currently publishing.
    pub fn enabled(&self) -> usize {
        self.entries.iter().filter(|e| !matches!(e.state, State::Disabled)).count()
    }

    /// React to a committed batch of changes: enable or disable blocks whose `GoEna`/`SvEna`
    /// changed, and publish the changed data sets of enabled blocks.
    pub fn on_commit(&mut self, ied: &Ied, dirty: &BTreeMap<String, TrgOps>, now: Instant, t: UtcTime) {
        if dirty.is_empty() {
            return;
        }
        let (source, nominal_hz) = (self.source, self.nominal_hz);
        for e in &mut self.entries {
            let enable_ref = |attr: &str| alloc::format!("{}${attr}", e.reference);
            let flag = ["GoEna", "SvEna"].into_iter().map(enable_ref).find(|r| dirty.contains_key(r));
            if let Some(flag) = flag {
                let on = matches!(ied.value(&flag), Some(v) if *v == Value::Boolean(true));
                match (on, matches!(e.state, State::Disabled)) {
                    (true, true) if e.refusal.is_none() => e.state = start(ied, e, source, nominal_hz, now, t),
                    (false, false) => e.state = State::Disabled,
                    // Enabling an enabled block restarts nothing; disabling a disabled one is a no-op.
                    _ => {}
                }
                continue;
            }
            let changed = e.members.iter().any(|m| dirty.keys().any(|d| d == m || d.strip_prefix(m.as_str()).is_some_and(|rest| rest.starts_with('$'))));
            if changed {
                refresh(ied, e, now, t);
            }
        }
    }

    /// Time passed: retransmit GOOSE whose curve came due and publish SV samples that are due.
    #[cfg_attr(not(any(feature = "goose", feature = "sv")), allow(unused_variables))]
    pub fn on_timeout(&mut self, now: Instant) {
        for e in &mut self.entries {
            match &mut e.state {
                State::Disabled => {}
                #[cfg(feature = "goose")]
                State::Goose(p) => {
                    let _ = p.on_timeout(now);
                }
                #[cfg(feature = "sv")]
                State::Sv { publisher, sample, due, .. } => {
                    if now >= *due {
                        // Scheduled from the due time, not from `now`, so lateness does not
                        // accumulate into drift.
                        if publisher.publish_repeating(*due, sample).is_ok() {
                            *due = publisher.next_timeout().unwrap_or(now);
                        }
                    }
                }
            }
        }
    }

    /// The earliest moment [`Publishers::on_timeout`] has work.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.entries
            .iter()
            .filter_map(|e| match &e.state {
                State::Disabled => None,
                #[cfg(feature = "goose")]
                State::Goose(p) => p.next_timeout(),
                #[cfg(feature = "sv")]
                State::Sv { due, .. } => Some(*due),
            })
            .min()
    }

    /// Hand every frame ready to send to `send`, in block order.
    #[cfg_attr(not(any(feature = "goose", feature = "sv")), allow(unused_variables, unused_mut))]
    pub fn drain(&mut self, mut send: impl FnMut(&[u8])) {
        for e in &mut self.entries {
            match &mut e.state {
                State::Disabled => {}
                #[cfg(feature = "goose")]
                State::Goose(p) => {
                    if let Some(f) = p.poll_transmit() {
                        send(f);
                    }
                }
                #[cfg(feature = "sv")]
                State::Sv { publisher, .. } => {
                    if let Some(f) = publisher.poll_transmit() {
                        send(f);
                    }
                }
            }
        }
    }
}

/// Why a block cannot publish, decided once at load.
#[allow(unused_variables)]
fn check(ied: &Ied, kind: BlockKind, e: &Entry) -> Option<&'static str> {
    if e.members.is_empty() {
        return Some("the control block has no data set");
    }
    match kind {
        #[cfg(feature = "goose")]
        BlockKind::Goose => {
            ied.model.goose_publisher_config(&e.model_ref, MacAddr([0; 6])).err().map(|_| "the GOOSE control block has no address or data set in the file")
        }
        #[cfg(feature = "sv")]
        BlockKind::SampledValue => {
            if ied.model.sv_publisher_config(&e.model_ref, MacAddr([0; 6]), DEFAULT_NOMINAL_HZ).is_err() {
                return Some("the sampled-value control block has no address, rate or fixed-width data set in the file");
            }
            sv_layout(ied, &e.model_ref).is_none().then_some("the data set has no fixed sampled-value layout")
        }
        _ => Some("publishing this kind of block is not built into this configuration"),
    }
}

#[allow(unused_variables)]
fn start(ied: &Ied, e: &Entry, source: MacAddr, nominal_hz: u32, now: Instant, t: UtcTime) -> State {
    match e.kind {
        #[cfg(feature = "goose")]
        BlockKind::Goose => {
            let Ok(cfg) = ied.model.goose_publisher_config(&e.model_ref, source) else { return State::Disabled };
            let values = member_values(ied, &e.members);
            crate::proto::goose::Publisher::new(cfg, &values, t).map_or(State::Disabled, State::Goose)
        }
        #[cfg(feature = "sv")]
        BlockKind::SampledValue => {
            let (Ok(cfg), Some(layout)) = (ied.model.sv_publisher_config(&e.model_ref, source, nominal_hz), sv_layout(ied, &e.model_ref)) else {
                return State::Disabled;
            };
            let mut sample = alloc::vec![0u8; cfg.profile.sample_len];
            if write_sample(ied, &e.members, &layout, &mut sample).is_err() {
                return State::Disabled;
            }
            crate::proto::sv::Publisher::new(cfg).map_or(State::Disabled, |publisher| State::Sv { publisher, layout, sample, due: now })
        }
        _ => State::Disabled,
    }
}

#[allow(unused_variables)]
fn refresh(ied: &Ied, e: &mut Entry, now: Instant, t: UtcTime) {
    match &mut e.state {
        State::Disabled => {}
        #[cfg(feature = "goose")]
        State::Goose(p) => {
            let values = member_values(ied, &e.members);
            let _ = p.publish_if_changed(now, &values, t);
        }
        #[cfg(feature = "sv")]
        State::Sv { layout, sample, .. } => {
            // A value the layout cannot carry leaves the previous sample standing.
            let mut next = sample.clone();
            if write_sample(ied, &e.members, layout, &mut next).is_ok() {
                *sample = next;
            }
        }
    }
}

#[cfg(feature = "goose")]
fn member_values(ied: &Ied, members: &[String]) -> Vec<Value> {
    members.iter().map(|m| ied.read_reference(m).unwrap_or(Value::Structure(Vec::new()))).collect()
}

#[cfg(feature = "sv")]
fn sv_layout(ied: &Ied, model_ref: &str) -> Option<crate::proto::sv::SampleLayout> {
    let (ld, ln, cb) = ied.model.smv_control(model_ref).ok()?;
    let ds = ied.model.data_set(ln, cb.dat_set.as_deref()?)?;
    ied.model.sv_sample_layout(&ld.name, ds)
}

/// Encode the members' current values into `sample` through `layout`, channel `i` being
/// member `i`.
#[cfg(feature = "sv")]
fn write_sample(ied: &Ied, members: &[String], layout: &crate::proto::sv::SampleLayout, sample: &mut [u8]) -> crate::Result<()> {
    use crate::proto::sv::{ChannelType, ChannelValue};
    for (i, (member, channel)) in members.iter().zip(layout.channels()).enumerate() {
        let value = ied.read_reference(member).ok_or(crate::Error::NotFound("data-set member value"))?;
        let v = match (channel.kind, value) {
            (ChannelType::Boolean, Value::Boolean(b)) => ChannelValue::Boolean(b),
            (ChannelType::Int(_) | ChannelType::Enum, Value::Integer(n)) => ChannelValue::Int(n),
            (ChannelType::Unsigned(_), Value::Unsigned(n)) => ChannelValue::Unsigned(n),
            (ChannelType::Unsigned(_), Value::Integer(n)) if n >= 0 => ChannelValue::Unsigned(n as u64),
            (ChannelType::Float32 | ChannelType::Float64, Value::Float32(f)) => ChannelValue::Float(f64::from(f)),
            (ChannelType::Float32 | ChannelType::Float64, Value::Float64(f)) => ChannelValue::Float(f),
            (ChannelType::Quality, Value::BitString { bytes, .. }) => {
                let b0 = bytes.first().copied().unwrap_or(0);
                let b1 = bytes.get(1).copied().unwrap_or(0);
                ChannelValue::Quality(crate::common::Quality::from_bits_msb((u32::from(b0) << 24) | (u32::from(b1) << 16)))
            }
            (ChannelType::Timestamp, Value::UtcTime(t)) => ChannelValue::Timestamp(t),
            _ => return Err(crate::Error::InvalidValue("a data-set member does not match its sampled-value channel")),
        };
        layout.write(sample, i, v)?;
    }
    Ok(())
}

#[cfg(not(feature = "sv"))]
#[allow(dead_code)]
fn sv_layout(_: &Ied, _: &str) -> Option<()> {
    None
}
