//! A virtual merging unit publishing IEC 61869-9 sampled values, read back by a subscriber.
//!
//! ```text
//! cargo run --example sv_merging_unit
//! cargo run --example sv_merging_unit -- stream.pcap    # …and write what it sent
//! ```
//!
//! `F4800S2I4U4` is 4800 samples per second in two ASDUs per frame — 2400 frames per second
//! on the wire. The whole frame is encoded **once** into a template at construction; each
//! publish patches only `smpCnt` and the sample blocks, which is why the steady state
//! allocates nothing and why the clock fields are setters rather than arguments.

use std::error::Error;

use iec61850_rs::common::{Instant, Quality};
use iec61850_rs::proto::ethernet::{ETHERTYPE_SV, FrameHeader, MacAddr};
use iec61850_rs::proto::sv::le::PhsMeas1;
use iec61850_rs::proto::sv::{Publisher, PublisherConfig, SmpSynch, StreamConfig, StreamKey, Subscriber, SubscriberEvent, SvProfile};

const APPID: u16 = 0x4000;
const SV_ID: &str = "MU01";

fn main() -> Result<(), Box<dyn Error>> {
    let dst = MacAddr::parse("01-0C-CD-04-00-01")?;
    let header = FrameHeader { dst, src: MacAddr::parse("00-30-A7-00-00-02")?, vlan: None, ethertype: ETHERTYPE_SV, appid: APPID, reserved1: 0, reserved2: 0 };

    let profile = SvProfile::F4800S2I4U4;
    let mut mu = Publisher::new(PublisherConfig::new(header, SV_ID, profile).with_conf_rev(1))?;
    // Clock state is publisher state, not a per-frame argument: at 2400 frames a second
    // there is no sense in re-passing the grandmaster's identity 2400 times.
    mu.set_smp_synch(SmpSynch::Global);

    let mut sub = Subscriber::new(vec![
        StreamConfig::new(StreamKey { dst, appid: APPID, sv_id: SV_ID.into() }).with_samples_per_second(profile.samples_per_second).with_conf_rev(1),
    ]);

    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut decoded = 0u64;
    let mut peak = 0i32;
    let mut now = Instant::ZERO;

    // A tenth of a second: 240 frames, 480 ASDUs, 480 samples of a 50 Hz sinusoid.
    for frame_index in 0..240u32 {
        let blocks: Vec<[u8; 64]> = (0..profile.asdus_per_frame)
            .map(|i| sample_block(frame_index * u32::from(profile.asdus_per_frame) + u32::from(i), profile.samples_per_second))
            .collect();
        let refs: Vec<&[u8]> = blocks.iter().map(|b| &b[..]).collect();
        mu.publish(now, &refs)?;

        if let Some(frame) = mu.poll_transmit() {
            if std::env::args().nth(1).is_some() {
                frames.push(frame.to_vec());
            }
            // The receive path allocates nothing: the callback reads the values straight out
            // of the frame's own octets, on the receiving thread.
            let frame = frame.to_vec();
            sub.on_frame(now, &frame, |sample| {
                decoded += 1;
                if let Some(m) = PhsMeas1::decode(sample.asdu.sample) {
                    peak = peak.max(m.currents[0]);
                }
            });
        }
        while let Some(event) = sub.poll_event() {
            // Only low-rate, edge-triggered facts are queued; the samples themselves went to
            // the callback above, on the receiving thread, without allocating.
            match event {
                SubscriberEvent::Gap { .. } | SubscriberEvent::SyncChanged { .. } | SubscriberEvent::GrandmasterChanged { .. } => println!("{event:?}"),
                _ => {}
            }
        }
        now = mu.next_timeout().unwrap_or(now.plus_millis(1));
    }

    let state = sub.state(0).ok_or("no stream state")?;
    println!("{} frames, {} ASDUs ({decoded} reached the consumer)", state.frames, state.asdus);
    println!("{} gap(s), {} sample(s) lost, smpSynch {:?}", state.gaps, state.samples_lost, state.smp_synch);
    println!("peak phase-A current {peak} raw = {:.1} A", f64::from(peak) / 1000.0);

    if let Some(path) = std::env::args().nth(1) {
        // A capture file is the interface until the raw-socket adapters land — and it is
        // what lets `tshark` and `ied sv monitor` check this output.
        let mut w = iec61850_rs::pcap::Writer::create(&path)?;
        for (i, frame) in frames.iter().enumerate() {
            // 2400 frames a second: one frame every 416 667 ns.
            w.write(i as u64 * 416_667, frame)?;
        }
        println!("\nwrote {} frames to {path}", frames.len());
        println!("try:  ied sv monitor {path}   |   tshark -r {path} -Y sv");
    }
    Ok(())
}

/// One 9-2LE sample block: four currents and four voltages, as `INT32` plus a quality word.
///
/// Phase A is a 50 Hz sinusoid at 100 A peak in the guideline's raw units (1 mA per count);
/// B and C follow it by 120°, and the neutral is their sum.
fn sample_block(sample: u32, samples_per_second: u32) -> [u8; 64] {
    let phase = |offset: f64| {
        let t = f64::from(sample) / f64::from(samples_per_second);
        let radians = 2.0 * std::f64::consts::PI * 50.0 * t + offset;
        (radians.sin() * 100_000.0) as i32
    };
    let third = 2.0 * std::f64::consts::PI / 3.0;
    let (a, b, c) = (phase(0.0), phase(-third), phase(third));
    PhsMeas1 {
        currents: [a, b, c, a.wrapping_add(b).wrapping_add(c)],
        current_quality: [Quality::GOOD; 4],
        voltages: [a / 10, b / 10, c / 10, 0],
        voltage_quality: [Quality::GOOD; 4],
    }
    .encode()
}
