#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use iec61850_rs::pcap::Capture;
use libfuzzer_sys::fuzz_target;

// The pcap reader is fed files from anywhere, so it must never panic on one.
fuzz_target!(|data: &[u8]| {
    if let Ok(capture) = Capture::parse(data) {
        for (_, frame) in &capture.frames {
            let _ = iec61850_rs::proto::ethernet::Frame::parse(frame);
        }
    }
});
