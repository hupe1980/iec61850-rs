#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use iec61850_rs::common::{Instant, Limits};
use iec61850_rs::proto::ethernet::{Frame, MacAddr};
use iec61850_rs::proto::sv::le::PhsMeas1;
use iec61850_rs::proto::sv::{ChannelType, SampleLayout, SavPduView, StreamConfig, StreamKey, Subscriber};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(fr) = Frame::parse(data) {
        if let Ok(pdu) = SavPduView::parse(fr.apdu, &Limits::DEFAULT) {
            for a in pdu.asdus().flatten() {
                let _ = PhsMeas1::decode(a.sample);
            }
        }
    }
    // A layout so that the dataset-driven decoding path is fuzzed too: a sample block of
    // any length must yield the channels it really holds and never read past its end.
    let layout = SampleLayout::new([
        (String::from("i"), ChannelType::Int(4)),
        (String::from("q"), ChannelType::Quality),
        (String::from("t"), ChannelType::Timestamp),
        (String::from("f"), ChannelType::Float64),
    ]);
    let mut sub = Subscriber::new(vec![
        StreamConfig::new(StreamKey { dst: MacAddr::SV_BASE, appid: 0x4000, sv_id: String::new() }).with_layout(layout.clone()),
    ])
    .with_event_capacity(16);
    sub.on_frame(Instant::ZERO, data, |s| {
        for (c, v) in s.channels() {
            let _ = (&c.name, v.as_i64(), v.as_f64(), v.as_quality());
        }
    });
    // And the write half, against the same description.
    let mut block = vec![0u8; layout.len()];
    for (i, v) in data.chunks(8).enumerate() {
        let value = iec61850_rs::proto::sv::ChannelValue::Int(v.iter().fold(0i64, |a, b| a.wrapping_shl(8) | i64::from(*b)));
        let _ = layout.write(&mut block, i, value);
    }
    sub.on_timeout(Instant::ZERO.plus_millis(1_000));
    while sub.poll_event().is_some() {}
});
