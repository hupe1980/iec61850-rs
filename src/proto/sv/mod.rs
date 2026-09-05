//! Sampled Values (IEC 61850-9-2 / 9-2LE / IEC 61869-9): the APDU codec, the 9-2LE sample
//! layout, a publisher that patches a pre-encoded frame template, and a multi-stream
//! subscriber.
//!
//! A merging unit publishes continuously — 4000 to 14 400 samples a second — so the
//! publisher encodes one frame at construction and afterwards only patches it: `smpCnt` and
//! the sample blocks per frame, and `smpSynch`, `refrTm` and `gmIdentity` whenever the clock
//! state moves. The subscriber hands each sample to a closure on the calling thread and
//! queues only stream-level changes. Neither side allocates once it is running, which
//! `tests/allocation.rs` asserts with a counting allocator rather than claiming.

mod apdu;
mod layout;
mod publisher;
mod subscriber;

/// The value `smpCnt` wraps at for a stream of `samples_per_second`.
///
/// `smpCnt` is `INTEGER (0..65535)` [9-2], so a stream sampling faster than the field can
/// count cannot number a whole second in it and the wrap falls back to the field's own
/// range. Zero is never a modulus.
pub const fn smp_cnt_wrap(samples_per_second: u32) -> u32 {
    match samples_per_second {
        0 => 1,
        n if n > 65_536 => 65_536,
        n => n,
    }
}

pub use apdu::{Asdu, AsduOffsets, AsduView, SavPdu, SavPduView, SmpSynch, TAG_SAV_PDU};
pub use layout::{Channel, ChannelType, ChannelValue, SampleLayout};
pub use publisher::{Publisher, PublisherConfig, SmpMod, SvProfile};
pub use subscriber::{Sample, SimulationMode, StreamConfig, StreamKey, StreamState, Subscriber, SubscriberEvent};

/// The 9-2LE fixed data set `PhsMeas1`: four currents and four voltages, each an `INT32`
/// followed by a 32-bit quality word (64 octets per ASDU).
#[allow(clippy::indexing_slicing, clippy::cast_precision_loss)] // fixed 64-octet layout, checked once
pub mod le {
    use crate::common::Quality;

    /// APPID the guideline mandates.
    pub const APPID: u16 = 0x4000;
    /// Samples per nominal cycle for the protection stream (`MSVCB01`).
    pub const SAMPLES_PER_CYCLE_PROTECTION: u32 = 80;
    /// Samples per nominal cycle for the measurement stream (`MSVCB02`).
    pub const SAMPLES_PER_CYCLE_MEASUREMENT: u32 = 256;
    /// Scale factor of the current channels (A per LSB).
    pub const SCALE_CURRENT: f32 = 0.001;
    /// Scale factor of the voltage channels (V per LSB).
    pub const SCALE_VOLTAGE: f32 = 0.01;
    /// Octets of sample data per ASDU.
    pub const SAMPLE_LEN: usize = 64;

    /// One decoded 9-2LE sample: eight channels with quality.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PhsMeas1 {
        /// `IaAmpsTCTR1`, `IbAmpsTCTR2`, `IcAmpsTCTR3`, `InAmpsTCTR4` raw values.
        pub currents: [i32; 4],
        /// Quality of each current.
        pub current_quality: [Quality; 4],
        /// `UaVoltsTVTR1`, `UbVoltsTVTR2`, `UcVoltsTVTR3`, `UnVoltsTVTR4` raw values.
        pub voltages: [i32; 4],
        /// Quality of each voltage.
        pub voltage_quality: [Quality; 4],
    }

    impl PhsMeas1 {
        /// Decode the 64-octet sample block. `None` if the length is wrong.
        pub fn decode(sample: &[u8]) -> Option<PhsMeas1> {
            if sample.len() != SAMPLE_LEN {
                return None;
            }
            let mut currents = [0i32; 4];
            let mut voltages = [0i32; 4];
            let mut cq = [Quality::GOOD; 4];
            let mut vq = [Quality::GOOD; 4];
            for i in 0..8 {
                let o = i * 8;
                let v = i32::from_be_bytes([sample[o], sample[o + 1], sample[o + 2], sample[o + 3]]);
                let q = Quality::from_bits_msb(u32::from_be_bytes([sample[o + 4], sample[o + 5], sample[o + 6], sample[o + 7]]));
                if i < 4 {
                    currents[i] = v;
                    cq[i] = q;
                } else {
                    voltages[i - 4] = v;
                    vq[i - 4] = q;
                }
            }
            Some(PhsMeas1 { currents, current_quality: cq, voltages, voltage_quality: vq })
        }

        /// Encode into the 64-octet layout.
        pub fn encode(&self) -> [u8; SAMPLE_LEN] {
            let mut out = [0u8; SAMPLE_LEN];
            for i in 0..8 {
                let (v, q) = if i < 4 { (self.currents[i], self.current_quality[i]) } else { (self.voltages[i - 4], self.voltage_quality[i - 4]) };
                let o = i * 8;
                out[o..o + 4].copy_from_slice(&v.to_be_bytes());
                out[o + 4..o + 8].copy_from_slice(&q.to_bits_msb().to_be_bytes());
            }
            out
        }

        /// Currents in amperes.
        pub fn currents_a(&self) -> [f32; 4] {
            self.currents.map(|v| v as f32 * SCALE_CURRENT)
        }

        /// Voltages in volts.
        pub fn voltages_v(&self) -> [f32; 4] {
            self.voltages.map(|v| v as f32 * SCALE_VOLTAGE)
        }
    }
}
