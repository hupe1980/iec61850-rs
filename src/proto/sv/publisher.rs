use alloc::string::String;
use alloc::vec::Vec;

use super::apdu::{Asdu, AsduOffsets, Field, SavPdu, SmpSynch};
use crate::common::{Error, Instant, Result, UtcTime};
use crate::proto::ethernet::{FrameHeader, RESERVED1_SIMULATION};

/// How `smpCnt` relates to the nominal period (`smpMod`, IEC 61850-9-2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SmpMod {
    /// 0 — `smpRate` counts samples per nominal period. What 9-2LE uses.
    #[default]
    SamplesPerPeriod,
    /// 1 — `smpRate` counts samples per second. What IEC 61869-9 uses.
    SamplesPerSecond,
    /// 2 — `smpRate` counts seconds per sample.
    SecondsPerSample,
}

impl SmpMod {
    /// The wire value.
    pub const fn to_u8(self) -> u8 {
        match self {
            SmpMod::SamplesPerPeriod => 0,
            SmpMod::SamplesPerSecond => 1,
            SmpMod::SecondsPerSample => 2,
        }
    }

    /// From the wire value.
    pub const fn from_u8(v: u8) -> Option<SmpMod> {
        Some(match v {
            0 => SmpMod::SamplesPerPeriod,
            1 => SmpMod::SamplesPerSecond,
            2 => SmpMod::SecondsPerSample,
            _ => return None,
        })
    }

    /// From the SCL `smpMod` token.
    pub fn parse(s: &str) -> Option<SmpMod> {
        Some(match s {
            "SmpPerPeriod" => SmpMod::SamplesPerPeriod,
            "SmpPerSec" => SmpMod::SamplesPerSecond,
            "SecPerSmp" => SmpMod::SecondsPerSample,
            _ => return None,
        })
    }
}

/// A sampled-value stream profile: the sample rate, how many ASDUs share a frame, and the
/// size of one sample block.
///
/// The constants are the profiles that exist in the field. IEC 61869-9 names its profiles
/// `F<rate>S<asdus>I<currents>U<voltages>`, and both of its preferred profiles put 2400
/// frames per second on the wire — the ASDU count is chosen to keep that constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SvProfile {
    /// Samples per second, which is also the value `smpCnt` wraps at.
    pub samples_per_second: u32,
    /// ASDUs concatenated into one frame.
    pub asdus_per_frame: u8,
    /// `smpMod` to advertise, or `None` to omit it (9-2LE omits it).
    pub smp_mod: Option<SmpMod>,
    /// `smpRate` to advertise, or `None` to omit it.
    pub smp_rate: Option<u16>,
    /// Octets of sample data in one ASDU.
    pub sample_len: usize,
}

impl SvProfile {
    /// 9-2LE `MSVCB01`: 80 samples per nominal cycle at 50 Hz, one ASDU per frame, the
    /// fixed four-current/four-voltage data set.
    pub const LE_80_50HZ: SvProfile =
        SvProfile { samples_per_second: 4000, asdus_per_frame: 1, smp_mod: None, smp_rate: None, sample_len: super::le::SAMPLE_LEN };
    /// 9-2LE `MSVCB01` at 60 Hz: 80 samples per cycle, one ASDU per frame.
    pub const LE_80_60HZ: SvProfile = SvProfile { samples_per_second: 4800, ..SvProfile::LE_80_50HZ };
    /// 9-2LE `MSVCB02`: 256 samples per nominal cycle at 50 Hz, eight ASDUs per frame.
    pub const LE_256_50HZ: SvProfile = SvProfile { samples_per_second: 12_800, asdus_per_frame: 8, ..SvProfile::LE_80_50HZ };
    /// 9-2LE `MSVCB02` at 60 Hz: 256 samples per cycle, eight ASDUs per frame.
    pub const LE_256_60HZ: SvProfile = SvProfile { samples_per_second: 15_360, ..SvProfile::LE_256_50HZ };

    /// IEC 61869-9 `F4800S2I4U4`, the preferred protection profile: 4800 samples per
    /// second, 2 ASDUs per frame — 2400 frames per second.
    pub const F4800S2I4U4: SvProfile = SvProfile {
        samples_per_second: 4800,
        asdus_per_frame: 2,
        smp_mod: Some(SmpMod::SamplesPerSecond),
        smp_rate: Some(4800),
        sample_len: super::le::SAMPLE_LEN,
    };
    /// IEC 61869-9 `F14400S6I4U4`, the preferred metering profile: 14 400 samples per
    /// second, 6 ASDUs per frame — also 2400 frames per second.
    pub const F14400S6I4U4: SvProfile = SvProfile { samples_per_second: 14_400, asdus_per_frame: 6, smp_rate: Some(14_400), ..SvProfile::F4800S2I4U4 };

    /// Frames per second this profile puts on the wire.
    pub const fn frames_per_second(&self) -> u32 {
        let n = if self.asdus_per_frame == 0 { 1 } else { self.asdus_per_frame as u32 };
        self.samples_per_second / n
    }

    /// Nanoseconds between frames.
    pub const fn frame_interval_nanos(&self) -> u64 {
        let fps = self.frames_per_second();
        if fps == 0 { 0 } else { 1_000_000_000 / fps as u64 }
    }

    /// The value `smpCnt` wraps at, clamped to what the 16-bit field can hold
    /// ([`super::smp_cnt_wrap`]).
    pub const fn smp_cnt_wrap(&self) -> u32 {
        super::smp_cnt_wrap(self.samples_per_second)
    }
}

/// Configuration of one sampled-value publisher, as the SCL `SampledValueControl` and its
/// `SMV` address element describe it.
#[derive(Clone, Debug, PartialEq)]
pub struct PublisherConfig {
    /// Link-layer header; its simulation bit is managed by the publisher.
    pub header: FrameHeader,
    /// `svID`.
    pub sv_id: String,
    /// `datSet`, if the stream advertises one.
    pub dat_set: Option<String>,
    /// `confRev`.
    pub conf_rev: u32,
    /// The stream profile.
    pub profile: SvProfile,
    /// Publish with the simulation flag set (a test set, not the configured merging unit).
    pub simulation: bool,
    /// Carry `refrTm` — the time of the first sample in the ASDU. Reserve the field in the
    /// template so [`Publisher::set_refr_tm`] can fill it; 9-2LE leaves it out.
    pub refr_tm: bool,
    /// Carry `gmIdentity` — the PTP grandmaster this merging unit is locked to
    /// (IEC 61850-9-2 Ed 2.1). Reserve the field so [`Publisher::set_gm_identity`] can
    /// fill it.
    pub gm_identity: bool,
}

impl PublisherConfig {
    /// A publisher for `sv_id` on `header`, with `confRev` 1 and no optional fields.
    pub fn new(header: FrameHeader, sv_id: impl Into<String>, profile: SvProfile) -> Self {
        PublisherConfig { header, sv_id: sv_id.into(), dat_set: None, conf_rev: 1, profile, simulation: false, refr_tm: false, gm_identity: false }
    }

    /// Set `confRev`.
    #[must_use]
    pub fn with_conf_rev(mut self, conf_rev: u32) -> Self {
        self.conf_rev = conf_rev;
        self
    }

    /// Advertise a `datSet`.
    #[must_use]
    pub fn with_dat_set(mut self, dat_set: impl Into<String>) -> Self {
        self.dat_set = Some(dat_set.into());
        self
    }

    /// Reserve `refrTm` and `gmIdentity` in every ASDU — what a grandmaster-aware stream
    /// wants, and what lets a subscriber alarm on a grandmaster change.
    #[must_use]
    pub fn with_time_fields(mut self, refr_tm: bool, gm_identity: bool) -> Self {
        self.refr_tm = refr_tm;
        self.gm_identity = gm_identity;
        self
    }

    /// Publish with the simulation flag set.
    #[must_use]
    pub fn with_simulation(mut self, on: bool) -> Self {
        self.simulation = on;
        self
    }
}

/// The sampled-value publisher.
///
/// A whole frame — link-layer header, `savPdu`, every ASDU — is encoded **once** into a
/// template. Publishing then patches only what changes: the `smpCnt` of each ASDU and its
/// sample block, plus `smpSynch`, `refrTm` and `gmIdentity` whenever the clock state moves.
/// That is possible because the encoder writes every one of those fields at a fixed width,
/// so no length can change underneath. At 2400 frames per second this matters: the steady
/// state does no encoding and no allocation.
///
/// Sans-IO: call [`Publisher::publish`] with the next sample blocks, send what
/// [`Publisher::poll_transmit`] returns, and come back at [`Publisher::next_timeout`].
#[derive(Debug)]
pub struct Publisher {
    cfg: PublisherConfig,
    /// The complete frame, patched in place.
    frame: Vec<u8>,
    /// Where each ASDU's patchable fields sit in `frame`.
    at: Vec<AsduOffsets>,
    smp_cnt: u16,
    smp_synch: SmpSynch,
    /// The clock state currently written into every ASDU. Kept rather than only patched,
    /// because a `smpSynch` that no longer fits its reserved width needs the template built
    /// again and the rest of the state has to survive that.
    refr_tm: Option<UtcTime>,
    gm_identity: Option<[u8; 8]>,
    pending: bool,
    next_send: Option<Instant>,
    dropped: u64,
}

impl Publisher {
    /// Build the frame template. Fails if the configuration cannot be encoded.
    pub fn new(cfg: PublisherConfig) -> Result<Publisher> {
        if !cfg.sv_id.is_ascii() || cfg.dat_set.as_ref().is_some_and(|s| !s.is_ascii()) {
            return Err(Error::Encode("svID and datSet must be ASCII (VisibleString)"));
        }
        if cfg.profile.asdus_per_frame == 0 {
            return Err(Error::InvalidValue("a frame must carry at least one ASDU"));
        }
        if cfg.profile.samples_per_second == 0 {
            return Err(Error::InvalidValue("samples_per_second must not be zero"));
        }

        let (frame, at) = build_template(&cfg, SmpSynch::None, None, None)?;
        let mut p = Publisher {
            cfg,
            frame,
            at,
            smp_cnt: 0,
            smp_synch: SmpSynch::None,
            refr_tm: None,
            gm_identity: None,
            pending: false,
            next_send: Some(Instant::ZERO),
            dropped: 0,
        };
        p.write_smp_cnt_fields();
        Ok(p)
    }

    /// The configuration.
    pub const fn config(&self) -> &PublisherConfig {
        &self.cfg
    }

    /// The `smpCnt` the next frame's first ASDU will carry.
    pub const fn smp_cnt(&self) -> u16 {
        self.smp_cnt
    }

    /// Frames overwritten because the caller did not collect them in time.
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Sample blocks one call to [`Publisher::publish`] expects.
    pub const fn asdus_per_frame(&self) -> usize {
        self.cfg.profile.asdus_per_frame as usize
    }

    /// Octets in one sample block.
    pub const fn sample_len(&self) -> usize {
        self.cfg.profile.sample_len
    }

    /// Publish one frame carrying the next `asdus_per_frame` sample blocks.
    ///
    /// `blocks` must hold exactly [`Publisher::asdus_per_frame`] slices of exactly
    /// [`Publisher::sample_len`] octets. `smpCnt` advances by one per ASDU and wraps at
    /// [`SvProfile::smp_cnt_wrap`].
    ///
    /// Everything else the ASDU carries — `smpSynch`, `refrTm`, `gmIdentity` — is stream
    /// state set separately, because it comes from the clock and not from the samples.
    pub fn publish(&mut self, now: Instant, blocks: &[&[u8]]) -> Result<()> {
        if blocks.len() != self.asdus_per_frame() {
            return Err(Error::InvalidValue("one sample block per ASDU is required"));
        }
        if blocks.iter().any(|b| b.len() != self.cfg.profile.sample_len) {
            return Err(Error::InvalidValue("sample block has the wrong length for this profile"));
        }
        for (i, block) in blocks.iter().enumerate() {
            self.patch_asdu(i, block)?;
        }
        self.queue(now);
        Ok(())
    }

    /// Publish a frame whose ASDUs all carry the same block — the shape a test set or a
    /// constant-injection tool wants.
    ///
    /// It patches the template directly rather than building a list of identical slices:
    /// this is a 2400-frame-per-second path and it may not allocate.
    pub fn publish_repeating(&mut self, now: Instant, block: &[u8]) -> Result<()> {
        if block.len() != self.cfg.profile.sample_len {
            return Err(Error::InvalidValue("sample block has the wrong length for this profile"));
        }
        for i in 0..self.asdus_per_frame() {
            self.patch_asdu(i, block)?;
        }
        self.queue(now);
        Ok(())
    }

    /// Write one ASDU's `smpCnt` and sample block into the template, and advance the count.
    ///
    /// The caller has already checked the block length; the offsets came from decoding the
    /// template the encoder produced, so they are in range unless the template is corrupt,
    /// which is an error rather than a panic.
    fn patch_asdu(&mut self, i: usize, block: &[u8]) -> Result<()> {
        let Some(&at) = self.at.get(i) else {
            return Err(Error::InvalidValue("template is missing a patch point"));
        };
        let cnt = self.smp_cnt;
        write_unsigned(&mut self.frame, at.smp_cnt, u64::from(cnt))?;
        let Some(slot) = self.frame.get_mut(at.sample..at.sample + block.len()) else {
            return Err(Error::InvalidValue("template offset out of range"));
        };
        slot.copy_from_slice(block);
        self.smp_cnt = ((u32::from(self.smp_cnt) + 1) % self.cfg.profile.smp_cnt_wrap()) as u16;
        Ok(())
    }

    /// Hand the patched frame to the caller and schedule the next one.
    fn queue(&mut self, now: Instant) {
        if self.pending {
            self.dropped = self.dropped.saturating_add(1);
        }
        self.pending = true;
        self.next_send = Some(now.plus_nanos(self.cfg.profile.frame_interval_nanos()));
    }

    /// The synchronisation state every ASDU advertises. Takes effect with the next frame,
    /// and with every frame after it.
    ///
    /// Almost always a patch of one octet. It is not one when the width has to change:
    /// `smpSynch` is `0..254` and values 5–254 name a local-area clock, so 200 needs the two
    /// octets `00 C8` to stay a positive INTEGER while 2 needs one. Crossing that boundary
    /// re-encodes the template — off the publishing path, and rare, because a merging unit's
    /// clock identity is a configured number rather than something that moves per frame.
    pub fn set_smp_synch(&mut self, synch: SmpSynch) -> Result<()> {
        self.smp_synch = synch;
        let value = u64::from(synch.to_u8());
        let fits = self.at.iter().all(|a| a.smp_synch.is_none_or(|f| f.len >= crate::ber::unsigned_width(value, 1)));
        if !fits {
            return self.rebuild();
        }
        for i in 0..self.at.len() {
            let Some(f) = self.at.get(i).and_then(|a| a.smp_synch) else { continue };
            write_unsigned(&mut self.frame, f, value)?;
        }
        Ok(())
    }

    /// Re-encode the template from the current stream state and re-locate every patch point
    /// from the frame that comes out.
    ///
    /// Transparent to everything else the frame holds: each ASDU's sample block *and* its
    /// `smpCnt` are read out of the old frame and written back into the new one, so a rebuild
    /// between a `publish` and a `poll_transmit` does not renumber the frame that is waiting.
    fn rebuild(&mut self) -> Result<()> {
        let held: Vec<(u64, Vec<u8>)> = self
            .at
            .iter()
            .map(|a| {
                let count = read_unsigned(&self.frame, a.smp_cnt);
                let block = self.frame.get(a.sample..a.sample + self.cfg.profile.sample_len).map(<[u8]>::to_vec).unwrap_or_default();
                (count, block)
            })
            .collect();
        let (frame, at) = build_template(&self.cfg, self.smp_synch, self.refr_tm, self.gm_identity)?;
        self.frame = frame;
        self.at = at;
        for (i, (count, block)) in held.iter().enumerate() {
            let Some(&a) = self.at.get(i) else { continue };
            let _ = write_unsigned(&mut self.frame, a.smp_cnt, *count);
            if block.len() != self.cfg.profile.sample_len {
                continue;
            }
            if let Some(slot) = self.frame.get_mut(a.sample..a.sample + block.len()) {
                slot.copy_from_slice(block);
            }
        }
        Ok(())
    }

    /// Write the current `smpCnt` into every ASDU, without advancing it.
    ///
    /// The template is *encoded* with the largest count the stream can reach, so that the
    /// field is wide enough for every value; this puts the real one back.
    fn write_smp_cnt_fields(&mut self) {
        let mut cnt = u64::from(self.smp_cnt);
        for i in 0..self.at.len() {
            let Some(&a) = self.at.get(i) else { continue };
            let _ = write_unsigned(&mut self.frame, a.smp_cnt, cnt);
            cnt = (cnt + 1) % u64::from(self.cfg.profile.smp_cnt_wrap());
        }
    }

    /// The `smpSynch` currently advertised.
    pub const fn smp_synch(&self) -> SmpSynch {
        self.smp_synch
    }

    /// Set `refrTm`, the time of the **first sample of the frame**. Ignored unless the
    /// configuration reserved the field ([`PublisherConfig::refr_tm`]).
    ///
    /// `refrTm` is per ASDU, and the ASDUs of one frame are consecutive samples, so each
    /// one after the first is stamped a sample interval later than the one before it —
    /// which is what a merging unit sending 2 or 6 ASDUs per frame actually puts on the
    /// wire. The caller passes one timestamp, not six.
    pub fn set_refr_tm(&mut self, t: UtcTime) {
        self.refr_tm = Some(t);
        // Arithmetic in the wire's own unit of 2⁻²⁴ s, so the first ASDU carries exactly the
        // timestamp it was handed rather than one rounded through nanoseconds and back. The
        // offset of ASDU `i` is computed from `i` rather than added a step at a time: one
        // sample interval is not a whole number of 2⁻²⁴ s (at 4800 Hz it is 3495.25), and a
        // repeated addition would drift by a quarter of a unit per ASDU across the frame.
        let rate = u64::from(self.cfg.profile.samples_per_second.max(1));
        let base = (u64::from(t.seconds) << 24) | u64::from(t.fraction & 0x00FF_FFFF);
        for i in 0..self.at.len() {
            let Some(o) = self.at.get(i).and_then(|a| a.refr_tm) else { continue };
            let v = base.saturating_add(((i as u64) << 24) / rate);
            let seconds = u32::try_from(v >> 24).unwrap_or(u32::MAX);
            let octets = UtcTime { seconds, fraction: (v & 0x00FF_FFFF) as u32, quality: t.quality }.to_octets();
            if let Some(slot) = self.frame.get_mut(o..o + 8) {
                slot.copy_from_slice(&octets);
            }
        }
    }

    /// Set `gmIdentity`, the PTP grandmaster clock identity. Ignored unless the
    /// configuration reserved the field ([`PublisherConfig::gm_identity`]).
    pub fn set_gm_identity(&mut self, id: [u8; 8]) {
        self.gm_identity = Some(id);
        for i in 0..self.at.len() {
            let Some(o) = self.at.get(i).and_then(|a| a.gm_identity) else { continue };
            if let Some(slot) = self.frame.get_mut(o..o + 8) {
                slot.copy_from_slice(&id);
            }
        }
    }

    /// When the next frame is due, if the stream is running.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.next_send
    }

    /// The frame to send now, or `None`. Borrows the publisher's own buffer.
    pub fn poll_transmit(&mut self) -> Option<&[u8]> {
        if core::mem::take(&mut self.pending) { Some(&self.frame) } else { None }
    }

    /// Set `smpCnt` — for a merging unit that derives it from an absolute time source
    /// rather than from its own count.
    pub fn set_smp_cnt(&mut self, smp_cnt: u16) {
        self.smp_cnt = (u32::from(smp_cnt) % self.cfg.profile.smp_cnt_wrap()) as u16;
    }
}

/// Read a fixed-width unsigned field back out of a frame. Zero when it is out of range,
/// which cannot happen for offsets the decoder produced.
fn read_unsigned(frame: &[u8], field: Field) -> u64 {
    frame.get(field.at..field.at + field.len).map_or(0, |o| o.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
}

/// Write `value` big-endian into a fixed-width field, zero-padded on the left.
///
/// The field was sized to hold every value the stream can produce, so the padding is the
/// leading zero that keeps the BER INTEGER positive rather than a truncation.
fn write_unsigned(frame: &mut [u8], field: Field, value: u64) -> Result<()> {
    if field.len == 0 || field.len > 8 {
        return Err(Error::InvalidValue("template field has an impossible width"));
    }
    let Some(slot) = frame.get_mut(field.at..field.at + field.len) else {
        return Err(Error::InvalidValue("template offset out of range"));
    };
    let bytes = value.to_be_bytes();
    slot.copy_from_slice(bytes.get(8 - field.len..).unwrap_or(&bytes));
    Ok(())
}

/// Encode one complete frame — link layer, `savPdu`, every ASDU — and report where its
/// patchable fields ended up.
///
/// `smpCnt` is encoded at the **largest** value the stream can reach, so the field is wide
/// enough for every count the publisher will write into it; the caller puts the real count
/// back. Everything else is written at the value it will carry.
fn build_template(cfg: &PublisherConfig, smp_synch: SmpSynch, refr_tm: Option<UtcTime>, gm: Option<[u8; 8]>) -> Result<(Vec<u8>, Vec<AsduOffsets>)> {
    let max_smp_cnt = u16::try_from(cfg.profile.smp_cnt_wrap().saturating_sub(1)).unwrap_or(u16::MAX);
    let asdus: Vec<Asdu> = (0..cfg.profile.asdus_per_frame)
        .map(|_| Asdu {
            sv_id: cfg.sv_id.clone(),
            dat_set: cfg.dat_set.clone(),
            smp_cnt: max_smp_cnt,
            conf_rev: cfg.conf_rev,
            refr_tm: cfg.refr_tm.then(|| refr_tm.unwrap_or_default()),
            smp_synch: Some(smp_synch),
            smp_rate: cfg.profile.smp_rate,
            sample: alloc::vec![0u8; cfg.profile.sample_len],
            smp_mod: cfg.profile.smp_mod.map(SmpMod::to_u8),
            gm_identity: cfg.gm_identity.then(|| gm.unwrap_or_default()),
        })
        .collect();
    let apdu = SavPdu { asdus }.encode()?;

    let mut link = cfg.header;
    link.reserved1 = if cfg.simulation { link.reserved1 | RESERVED1_SIMULATION } else { link.reserved1 & !RESERVED1_SIMULATION };
    let mut frame = alloc::vec![0u8; link.len() + apdu.len()];
    link.write(&apdu, &mut frame)?;
    let apdu_at = link.len();
    // Locate the patch points by decoding what we just wrote: the offsets and widths come
    // from the decoder, so template and codec can never disagree about the layout.
    let at = locate_fields(&frame, apdu_at, cfg)?;
    Ok((frame, at))
}

/// Find the patchable field offsets in an encoded frame by decoding it.
fn locate_fields(frame: &[u8], apdu_at: usize, cfg: &PublisherConfig) -> Result<Vec<AsduOffsets>> {
    use super::apdu::SavPduView;
    use crate::common::Limits;

    let apdu = frame.get(apdu_at..).ok_or(Error::Encode("frame shorter than its header"))?;
    let limits = Limits { max_asdus: usize::from(cfg.profile.asdus_per_frame).max(1), ..Limits::DEFAULT };
    let pdu = SavPduView::parse(apdu, &limits)?;
    let mut out = Vec::with_capacity(usize::from(cfg.profile.asdus_per_frame));
    for asdu in pdu.asdus() {
        let a = asdu?;
        // The decoder reports offsets relative to the APDU; the patcher works on the frame.
        out.push(AsduOffsets {
            smp_cnt: Field { at: apdu_at + a.at.smp_cnt.at, len: a.at.smp_cnt.len },
            smp_synch: a.at.smp_synch.map(|f| Field { at: apdu_at + f.at, len: f.len }),
            refr_tm: a.at.refr_tm.map(|o| apdu_at + o),
            sample: apdu_at + a.at.sample,
            gm_identity: a.at.gm_identity.map(|o| apdu_at + o),
        });
    }
    if out.len() != usize::from(cfg.profile.asdus_per_frame) {
        return Err(Error::Encode("template does not hold the configured number of ASDUs"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{Limits, Quality, TimeQuality};
    use crate::proto::ethernet::{ETHERTYPE_SV, Frame, MacAddr, VlanTag};
    use crate::proto::sv::le::PhsMeas1;
    use crate::proto::sv::{AsduView, SavPduView, SmpSynch};

    fn cfg(profile: SvProfile) -> PublisherConfig {
        PublisherConfig::new(
            FrameHeader {
                dst: MacAddr::SV_BASE,
                src: MacAddr([2, 0, 0, 0, 0, 2]),
                vlan: Some(VlanTag::DEFAULT),
                ethertype: ETHERTYPE_SV,
                appid: 0x4000,
                reserved1: 0,
                reserved2: 0,
            },
            "MU01",
            profile,
        )
    }

    fn sample(v: i32) -> [u8; 64] {
        PhsMeas1 { currents: [v; 4], current_quality: [Quality::GOOD; 4], voltages: [v; 4], voltage_quality: [Quality::GOOD; 4] }.encode()
    }

    /// `smpSynch` 5–254 names a local-area clock (IEC 61850-9-2 Ed2). Written as one octet,
    /// 200 is the ASN.1 INTEGER −56 and Wireshark dissects it as −56; the field has to widen
    /// to keep the value positive, and the template has to stay patchable across the change.
    #[test]
    fn a_local_clock_identity_above_127_stays_a_positive_integer() {
        let mut p = Publisher::new(cfg(SvProfile::LE_80_50HZ)).unwrap();
        // The ordinary values keep the one-octet field every vendor capture shows.
        p.set_smp_synch(SmpSynch::Global).unwrap();
        let frame = publish_one(&mut p, 1);
        let fr = Frame::parse(&frame).unwrap();
        let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).unwrap();
        let a = pdu.asdus().next().unwrap().unwrap();
        assert_eq!(a.smp_synch, Some(SmpSynch::Global));
        assert_eq!(a.at.smp_synch.unwrap().len, 1, "an ordinary smpSynch is one octet, as the vendor capture writes it");

        // Crossing 127 re-encodes the template and the value still reads back as itself.
        p.set_smp_synch(SmpSynch::LocalClock(200)).unwrap();
        let frame = publish_one(&mut p, 2);
        let fr = Frame::parse(&frame).unwrap();
        let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).unwrap();
        let a = pdu.asdus().next().unwrap().unwrap();
        assert_eq!(a.smp_synch, Some(SmpSynch::LocalClock(200)));
        assert_eq!(a.at.smp_synch.unwrap().len, 2, "200 needs the leading zero octet");
        // And it is a *positive* INTEGER, not the two's-complement −56 a bare `C8` would be.
        let octets = &fr.apdu[a.at.smp_synch.unwrap().at..a.at.smp_synch.unwrap().at + 2];
        assert_eq!(octets, &[0x00, 0xC8]);
        // The rest of the stream survived the re-encode.
        assert_eq!(a.sv_id, "MU01");
        assert_eq!(a.sample, &sample(2)[..]);
    }

    /// IEC 61869-9 allows 96 kHz for HV d.c., where `smpCnt` runs to the field's own 65 535.
    /// Two octets of `FF FF` is −1; the width has to come from the stream's maximum.
    #[test]
    fn a_high_rate_stream_numbers_its_samples_without_going_negative() {
        let profile = SvProfile { samples_per_second: 96_000, asdus_per_frame: 1, ..SvProfile::F4800S2I4U4 };
        let mut p = Publisher::new(cfg(profile)).unwrap();
        p.set_smp_cnt(65_535);
        let frame = publish_one(&mut p, 1);
        let fr = Frame::parse(&frame).unwrap();
        let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).unwrap();
        let a = pdu.asdus().next().unwrap().unwrap();
        assert_eq!(a.smp_cnt, 65_535);
        assert_eq!(a.at.smp_cnt.len, 3, "the field is sized from the largest count the stream can reach");
        assert_eq!(&fr.apdu[a.at.smp_cnt.at..a.at.smp_cnt.at + 3], &[0x00, 0xFF, 0xFF]);
        // …and the width is constant across the whole stream, which is what makes it patchable.
        assert_eq!(p.smp_cnt(), 0, "65 535 is the last count before the wrap");
        let frame = publish_one(&mut p, 1);
        let fr = Frame::parse(&frame).unwrap();
        let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).unwrap();
        let a = pdu.asdus().next().unwrap().unwrap();
        assert_eq!(a.smp_cnt, 0);
        assert_eq!(a.at.smp_cnt.len, 3);
    }

    /// A stream at an ordinary rate keeps the exact widths the vendor capture holds —
    /// `82 02` for smpCnt and `83 04` for confRev — because widening is only ever a fix for
    /// a value that would come out negative.
    #[test]
    fn ordinary_streams_keep_the_widths_the_field_uses() {
        let mut p = Publisher::new(cfg(SvProfile::LE_80_50HZ).with_conf_rev(1)).unwrap();
        let frame = publish_one(&mut p, 1);
        let fr = Frame::parse(&frame).unwrap();
        let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).unwrap();
        let a = pdu.asdus().next().unwrap().unwrap();
        assert_eq!(a.at.smp_cnt.len, 2);
        // `83 04 00 00 00 01` — the confRev encoding the reference capture carries.
        let at = fr.apdu.windows(6).position(|w| w == [0x83, 0x04, 0x00, 0x00, 0x00, 0x01]);
        assert!(at.is_some(), "confRev keeps its four-octet field");
    }

    fn publish_one(p: &mut Publisher, v: i32) -> Vec<u8> {
        let block = sample(v);
        p.publish_repeating(Instant::ZERO, &block).unwrap();
        p.poll_transmit().unwrap().to_vec()
    }

    #[test]
    fn profiles_put_2400_frames_per_second_on_the_wire() {
        // IEC 61869-9 chooses the ASDU count to hold the frame rate at 2400.
        assert_eq!(SvProfile::F4800S2I4U4.frames_per_second(), 2400);
        assert_eq!(SvProfile::F14400S6I4U4.frames_per_second(), 2400);
        assert_eq!(SvProfile::F4800S2I4U4.frame_interval_nanos(), 416_666);
        // 9-2LE's protection stream is one ASDU per frame at the sample rate.
        assert_eq!(SvProfile::LE_80_50HZ.frames_per_second(), 4000);
        assert_eq!(SvProfile::LE_256_50HZ.frames_per_second(), 1600);
        assert_eq!(SvProfile::LE_256_60HZ.frames_per_second(), 1920);
    }

    #[test]
    fn patching_the_template_yields_a_decodable_frame() {
        let mut p = Publisher::new(cfg(SvProfile::LE_80_50HZ)).unwrap();
        p.set_smp_synch(SmpSynch::Global).unwrap();
        let frame = publish_one(&mut p, 1234);
        assert!(p.poll_transmit().is_none(), "a frame is handed out once");

        let fr = Frame::parse(&frame).unwrap();
        assert_eq!(fr.appid, 0x4000);
        let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).unwrap();
        assert_eq!(pdu.no_asdu, 1);
        let a = pdu.asdus().next().unwrap().unwrap();
        assert_eq!((a.sv_id, a.smp_cnt, a.conf_rev, a.smp_synch), ("MU01", 0, 1, Some(SmpSynch::Global)));
        assert_eq!(PhsMeas1::decode(a.sample).unwrap().currents[0], 1234);
        assert_eq!(p.smp_cnt(), 1);
    }

    #[test]
    fn multi_asdu_frames_number_their_samples_consecutively() {
        let mut p = Publisher::new(cfg(SvProfile::F4800S2I4U4)).unwrap();
        p.set_smp_synch(SmpSynch::Global).unwrap();
        let (a, b) = (sample(10), sample(20));
        p.publish(Instant::ZERO, &[&a, &b]).unwrap();
        let frame = p.poll_transmit().unwrap().to_vec();
        let pdu = SavPduView::parse(Frame::parse(&frame).unwrap().apdu, &Limits::DEFAULT).unwrap();
        assert_eq!(pdu.no_asdu, 2);
        let seen: Vec<(u16, i32)> = pdu.asdus().map(|a| a.unwrap()).map(|a| (a.smp_cnt, PhsMeas1::decode(a.sample).unwrap().currents[0])).collect();
        assert_eq!(seen, [(0, 10), (1, 20)]);
        assert_eq!(p.smp_cnt(), 2);
        // The 61869-9 profile advertises its rate and mode.
        let first = pdu.asdus().next().unwrap().unwrap();
        assert_eq!((first.smp_rate, first.smp_mod), (Some(4800), Some(1)));
    }

    #[test]
    fn the_clock_fields_are_patched_in_place() {
        // A grandmaster-aware stream: refrTm and gmIdentity are reserved in the template
        // and rewritten without the frame changing length.
        let mut p = Publisher::new(cfg(SvProfile::F4800S2I4U4).with_time_fields(true, true)).unwrap();
        let len = publish_one(&mut p, 0).len();
        let t = UtcTime::from_unix(1_700_000_000, 500_000, TimeQuality::SYNCHRONIZED);
        p.set_refr_tm(t);
        p.set_gm_identity([0xAA, 1, 2, 3, 4, 5, 6, 7]);
        p.set_smp_synch(SmpSynch::Global).unwrap();
        let frame = publish_one(&mut p, 0);
        assert_eq!(frame.len(), len, "patching must not change the frame length");
        let pdu = SavPduView::parse(Frame::parse(&frame).unwrap().apdu, &Limits::DEFAULT).unwrap();
        let seen: Vec<AsduView<'_>> = pdu.asdus().map(Result::unwrap).collect();
        for a in &seen {
            assert_eq!(a.gm_identity, Some(&[0xAA, 1, 2, 3, 4, 5, 6, 7][..]));
            assert_eq!(a.smp_synch, Some(SmpSynch::Global));
        }
        // The ASDUs of one frame are consecutive samples, so their refrTm advances by one
        // sample interval — 1/4800 s here — rather than repeating the frame's timestamp.
        assert_eq!(seen[0].refr_tm, Some(t));
        let step = seen[1].refr_tm.unwrap().to_unix_nanos() - t.to_unix_nanos();
        assert!((step as i64 - 208_333).abs() < 60, "refrTm step was {step} ns");
    }

    #[test]
    fn refr_tm_does_not_drift_across_a_six_asdu_frame() {
        // One sample interval is not a whole number of 2⁻²⁴ s, so stamping each ASDU by
        // adding a step to the one before it drifts. Every ASDU has to be within one unit
        // of the wire's resolution (≈60 ns) of the exact offset, including the last.
        let mut p = Publisher::new(cfg(SvProfile::F14400S6I4U4).with_time_fields(true, false)).unwrap();
        let t = UtcTime::from_unix(1_700_000_000, 0, TimeQuality::SYNCHRONIZED);
        p.set_refr_tm(t);
        let blocks: Vec<[u8; 64]> = (0..6).map(|_| sample(0)).collect();
        let refs: Vec<&[u8]> = blocks.iter().map(<[u8; 64]>::as_slice).collect();
        p.publish(Instant::ZERO, &refs).unwrap();
        let frame = p.poll_transmit().unwrap().to_vec();
        let pdu = SavPduView::parse(Frame::parse(&frame).unwrap().apdu, &Limits::DEFAULT).unwrap();
        for (i, a) in pdu.asdus().map(Result::unwrap).enumerate() {
            let want = t.to_unix_nanos() + (i as u64 * 1_000_000_000) / 14_400;
            let got = a.refr_tm.unwrap().to_unix_nanos();
            assert!(got.abs_diff(want) < 60, "ASDU {i}: refrTm off by {} ns", got.abs_diff(want));
        }
    }

    #[test]
    fn smp_cnt_wraps_at_the_sample_rate() {
        let mut p = Publisher::new(cfg(SvProfile::LE_80_50HZ)).unwrap();
        p.set_smp_cnt(3998);
        let mut seen = Vec::new();
        for _ in 0..4 {
            let frame = publish_one(&mut p, 0);
            let pdu = SavPduView::parse(Frame::parse(&frame).unwrap().apdu, &Limits::DEFAULT).unwrap();
            seen.push(pdu.asdus().next().unwrap().unwrap().smp_cnt);
        }
        assert_eq!(seen, [3998, 3999, 0, 1]);
    }

    #[test]
    fn a_sample_rate_beyond_the_counter_wraps_at_the_field_width() {
        // `smpCnt` is INTEGER (0..65535): a stream faster than that cannot count a second
        // in it. The wrap must fall back to the field's range, not divide by zero.
        let fast = SvProfile { samples_per_second: 96_000, asdus_per_frame: 4, ..SvProfile::F4800S2I4U4 };
        assert_eq!(fast.smp_cnt_wrap(), 65_536);
        let mut p = Publisher::new(cfg(fast)).unwrap();
        p.set_smp_cnt(65_535);
        let frame = publish_one(&mut p, 0);
        let pdu = SavPduView::parse(Frame::parse(&frame).unwrap().apdu, &Limits::DEFAULT).unwrap();
        let seen: Vec<u16> = pdu.asdus().map(|a| a.unwrap().smp_cnt).collect();
        assert_eq!(seen, [65_535, 0, 1, 2]);
    }

    #[test]
    fn the_template_is_encoded_once_and_never_grows() {
        let mut p = Publisher::new(cfg(SvProfile::F14400S6I4U4)).unwrap();
        let blocks: Vec<[u8; 64]> = (0..6).map(|i| sample(i * 100)).collect();
        let refs: Vec<&[u8]> = blocks.iter().map(<[u8; 64]>::as_slice).collect();
        let len = {
            p.publish(Instant::ZERO, &refs).unwrap();
            p.poll_transmit().unwrap().len()
        };
        for _ in 0..100 {
            p.publish(Instant::ZERO, &refs).unwrap();
            assert_eq!(p.poll_transmit().unwrap().len(), len, "patching must not change the frame length");
        }
    }

    #[test]
    fn scheduling_and_dropped_frames() {
        let mut p = Publisher::new(cfg(SvProfile::F4800S2I4U4)).unwrap();
        let (a, b) = (sample(1), sample(2));
        assert_eq!(p.next_timeout(), Some(Instant::ZERO));
        p.publish(Instant::ZERO, &[&a, &b]).unwrap();
        assert_eq!(p.next_timeout(), Some(Instant(416_666)));
        // Publishing again without collecting overwrites, and says so.
        p.publish(Instant(416_666), &[&a, &b]).unwrap();
        assert_eq!(p.dropped(), 1);
        assert!(p.poll_transmit().is_some());
    }

    #[test]
    fn bad_input_is_rejected_not_panicked() {
        let mut p = Publisher::new(cfg(SvProfile::F4800S2I4U4)).unwrap();
        let block = sample(0);
        assert!(p.publish(Instant::ZERO, &[&block]).is_err(), "too few blocks");
        assert!(p.publish(Instant::ZERO, &[&block[..10], &block]).is_err(), "wrong block length");
        let mut bad = cfg(SvProfile::LE_80_50HZ);
        bad.sv_id = "MÜ01".into();
        assert!(Publisher::new(bad).is_err());
        assert!(Publisher::new(cfg(SvProfile { asdus_per_frame: 0, ..SvProfile::LE_80_50HZ })).is_err());
        assert!(Publisher::new(cfg(SvProfile { samples_per_second: 0, ..SvProfile::LE_80_50HZ })).is_err());
    }

    #[test]
    fn simulation_sets_the_header_bit() {
        let mut p = Publisher::new(cfg(SvProfile::LE_80_50HZ).with_simulation(true)).unwrap();
        let frame = publish_one(&mut p, 0);
        assert!(Frame::parse(&frame).unwrap().simulation());
    }
}
