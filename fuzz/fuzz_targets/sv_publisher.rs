#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use iec61850_rs::common::{Instant, Limits, TimeQuality, UtcTime};
use iec61850_rs::proto::ethernet::{ETHERTYPE_SV, Frame, FrameHeader, MacAddr, VlanTag};
use iec61850_rs::proto::sv::{Publisher, PublisherConfig, SavPduView, SmpSynch, SvProfile};
use libfuzzer_sys::fuzz_target;

// Whatever sample bytes and counters the fuzzer chooses, the frame the publisher builds
// must decode again and carry exactly what was put in. This is the template-patching path:
// if a patch ever wrote outside its field, the decode would disagree.
fuzz_target!(|data: &[u8]| {
    let profile = match data.first().map(|b| b % 5) {
        Some(0) => SvProfile::LE_80_50HZ,
        Some(1) => SvProfile::LE_80_60HZ,
        Some(2) => SvProfile::LE_256_50HZ,
        Some(3) => SvProfile::F4800S2I4U4,
        _ => SvProfile::F14400S6I4U4,
    };
    let header = FrameHeader {
        dst: MacAddr::SV_BASE,
        src: MacAddr::default(),
        vlan: Some(VlanTag::DEFAULT),
        ethertype: ETHERTYPE_SV,
        appid: 0x4000,
        reserved1: 0,
        reserved2: 0,
    };
    // Half the runs carry the optional clock fields, so the patcher's offsets are exercised
    // on both template layouts.
    let with_clock = data.first().is_some_and(|b| b & 0x80 != 0);
    let Ok(mut publisher) = Publisher::new(PublisherConfig::new(header, "FUZZ", profile).with_time_fields(with_clock, with_clock)) else {
        return;
    };
    publisher.set_smp_synch(SmpSynch::Global);
    if with_clock {
        publisher.set_refr_tm(UtcTime::from_unix_nanos(u64::from(u32::from_be_bytes([1, 2, 3, 4])), TimeQuality::SYNCHRONIZED));
        publisher.set_gm_identity([0xAA; 8]);
    }

    let n = publisher.asdus_per_frame();
    let len = publisher.sample_len();
    // Build one block per ASDU from the fuzzer's bytes, cycling if it gave us too few.
    let mut blocks = vec![vec![0u8; len]; n];
    for (i, block) in blocks.iter_mut().enumerate() {
        for (j, byte) in block.iter_mut().enumerate() {
            *byte = data.get((i * len + j) % data.len().max(1)).copied().unwrap_or(0);
        }
    }
    let refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();

    if let Some(&first) = data.get(1) {
        publisher.set_smp_cnt(u16::from(first) * 17);
    }
    let start = publisher.smp_cnt();
    if publisher.publish(Instant::ZERO, &refs).is_err() {
        return;
    }
    let frame = publisher.poll_transmit().expect("a published frame is pending");
    let fr = Frame::parse(frame).expect("the publisher must emit a parsable frame");
    let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).expect("and a decodable savPdu");
    assert_eq!(usize::from(pdu.no_asdu), n);
    for (i, asdu) in pdu.asdus().enumerate() {
        let asdu = asdu.expect("every ASDU decodes");
        assert_eq!(asdu.sv_id, "FUZZ");
        assert_eq!(asdu.sample, &blocks[i][..], "sample block {i} was not written back verbatim");
        let expected = ((u32::from(start) + i as u32) % profile.smp_cnt_wrap()) as u16;
        assert_eq!(asdu.smp_cnt, expected, "smpCnt {i}");
        assert_eq!(asdu.smp_synch, Some(SmpSynch::Global));
        assert_eq!(asdu.gm_identity.is_some(), with_clock);
        assert_eq!(asdu.refr_tm.is_some(), with_clock);
    }
});
