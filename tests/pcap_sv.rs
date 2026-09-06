//! Real 9-2LE traffic (`specs/pcap/sv-9-2LE-normal-traffic.cap`, 10 161 frames, 60 Hz) against
//! the codec and the multi-stream subscriber. Skips when `specs/` is absent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use iec61850_rs::common::{Instant, Limits};
use iec61850_rs::proto::ethernet::{ETHERTYPE_SV, Frame, FrameHeader, MacAddr};
use iec61850_rs::proto::sv::le::PhsMeas1;
use iec61850_rs::proto::sv::{
    Asdu, ChannelType, ChannelValue, Publisher as SvPublisher, PublisherConfig as SvPublisherConfig, SampleLayout, SavPdu, SavPduView, SmpSynch, StreamConfig,
    StreamKey, Subscriber, SubscriberEvent, SvProfile,
};

#[test]
fn decodes_every_sv_frame() {
    let Some(path) = common::spec("pcap/sv-9-2LE-normal-traffic.cap") else { return };
    let frames = common::read_pcap(&path);
    assert_eq!(frames.len(), 10_161);
    let mut max_cnt = 0;
    for (_, f) in &frames {
        let fr = Frame::parse(f).expect("frame");
        assert_eq!(fr.ethertype, ETHERTYPE_SV);
        assert_eq!(fr.appid, 0x4001);
        let vlan = fr.vlan.expect("tagged");
        assert_eq!((vlan.priority, vlan.id), (4, 1));
        let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).expect("savPdu");
        assert_eq!(pdu.no_asdu, 1);
        let a = pdu.asdus().next().unwrap().unwrap();
        assert_eq!(a.sv_id, "4001");
        assert_eq!(a.conf_rev, 1);
        assert_eq!(a.smp_synch, Some(SmpSynch::Global));
        let s = PhsMeas1::decode(a.sample).expect("64-octet 9-2LE sample");
        assert!(s.current_quality.iter().chain(&s.voltage_quality).all(|q| q.is_good()));
        max_cnt = max_cnt.max(a.smp_cnt);
    }
    assert_eq!(max_cnt, 4799, "80 samples per cycle at 60 Hz");
}

#[test]
fn subscriber_tracks_continuity() {
    let Some(path) = common::spec("pcap/sv-9-2LE-normal-traffic.cap") else { return };
    let frames = common::read_pcap(&path);
    let key = StreamKey { dst: MacAddr::parse("01-0c-cd-04-00-02").unwrap(), appid: 0x4001, sv_id: "4001".into() };
    let mut sub = Subscriber::new(vec![StreamConfig::new(key).with_samples_per_second(4800).with_conf_rev(1)]);
    let t0 = frames[0].0;
    let mut samples = 0u64;
    let mut sum_ia: i64 = 0;
    for (ts, f) in &frames {
        sub.on_frame(Instant(ts - t0), f, |s| {
            samples += 1;
            sum_ia += i64::from(PhsMeas1::decode(s.asdu.sample).unwrap().currents[0]);
        });
    }
    assert_eq!(samples, 10_161);
    let st = sub.state(0).unwrap();
    assert_eq!(st.frames, 10_161);
    // A "normal traffic" capture: no discontinuity, and a sinusoid whose mean is near zero.
    assert_eq!((st.gaps, st.samples_lost), (0, 0));
    assert!((sum_ia / samples as i64).abs() < 5_000, "mean Ia raw {}", sum_ia / samples as i64);
    let mut events = Vec::new();
    while let Some(e) = sub.poll_event() {
        events.push(e);
    }
    assert!(matches!(events[0], SubscriberEvent::SyncChanged { to: Some(SmpSynch::Global), .. }));
    assert!(events.iter().all(|e| !matches!(e, SubscriberEvent::Malformed(_) | SubscriberEvent::ConfRevMismatch { .. })));
}

#[test]
fn the_dataset_driven_layout_decodes_the_capture_the_way_the_9_2le_struct_does() {
    // The generic path is only a replacement for the hard-coded one if it agrees with it on
    // real traffic. `PhsMeas1` is 9-2LE's fixed data set; the layout is the same data set
    // described the way an SCL file describes it, and every one of the 10 161 frames has to
    // decode to the same eight currents and voltages through both.
    let Some(path) = common::spec("pcap/sv-9-2LE-normal-traffic.cap") else { return };
    let mut channels = Vec::new();
    for name in ["Ia", "Ib", "Ic", "In", "Ua", "Ub", "Uc", "Un"] {
        channels.push((format!("MU01TCTR.{name}.instMag.i"), ChannelType::Int(4)));
        channels.push((format!("MU01TCTR.{name}.q"), ChannelType::Quality));
    }
    let layout = SampleLayout::new(channels);
    assert_eq!(layout.len(), 64);

    let mut checked = 0u32;
    for (_, f) in common::read_pcap(&path) {
        let fr = Frame::parse(&f).unwrap();
        let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).unwrap();
        for a in pdu.asdus().map(Result::unwrap) {
            let fixed = PhsMeas1::decode(a.sample).unwrap();
            let generic: Vec<ChannelValue> = layout.decode(a.sample).map(|(_, v)| v).collect();
            assert_eq!(generic.len(), 16);
            for (i, raw) in fixed.currents.iter().chain(&fixed.voltages).enumerate() {
                assert_eq!(generic[i * 2].as_i64(), Some(i64::from(*raw)));
            }
            for (i, q) in fixed.current_quality.iter().chain(&fixed.voltage_quality).enumerate() {
                assert_eq!(generic[i * 2 + 1].as_quality(), Some(*q));
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 10_161);
}

#[test]
fn re_encoding_a_captured_frame_reproduces_it_byte_for_byte() {
    // The strongest check available on the encoder: take a real merging unit's frames,
    // decode them, encode them again from the decoded values, and require the same bytes.
    // It catches every width, tag and ordering difference at once.
    let Some(path) = common::spec("pcap/sv-9-2LE-normal-traffic.cap") else { return };
    for (_, f) in common::read_pcap(&path) {
        let fr = Frame::parse(&f).unwrap();
        let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).unwrap();
        let owned = SavPdu {
            asdus: pdu
                .asdus()
                .map(|a| a.unwrap())
                .map(|a| Asdu {
                    sv_id: a.sv_id.into(),
                    dat_set: a.dat_set.map(Into::into),
                    smp_cnt: a.smp_cnt,
                    conf_rev: a.conf_rev,
                    refr_tm: a.refr_tm,
                    smp_synch: a.smp_synch,
                    smp_rate: a.smp_rate,
                    sample: a.sample.to_vec(),
                    smp_mod: a.smp_mod,
                    gm_identity: a.gm_identity.and_then(|g| <[u8; 8]>::try_from(g).ok()),
                })
                .collect(),
        };
        assert_eq!(owned.encode().unwrap(), pdu.raw, "re-encoding differs from the wire bytes");
    }
}

#[test]
fn the_publisher_reproduces_the_captured_stream() {
    // Configure a publisher the way the captured merging unit is configured, feed it the
    // sample blocks from the capture, and require the frames it builds to be the captured
    // frames. This is the publisher, the template patching and the link layer checked in
    // one go against hardware output.
    let Some(path) = common::spec("pcap/sv-9-2LE-normal-traffic.cap") else { return };
    let frames = common::read_pcap(&path);
    let first = Frame::parse(&frames[0].1).unwrap();
    let header = FrameHeader {
        dst: first.dst,
        src: first.src,
        vlan: first.vlan,
        ethertype: ETHERTYPE_SV,
        appid: first.appid,
        reserved1: first.reserved1,
        reserved2: first.reserved2,
    };
    // 80 samples per cycle at 60 Hz, one ASDU per frame — what the capture carries.
    let mut publisher = SvPublisher::new(SvPublisherConfig::new(header, "4001", SvProfile::LE_80_60HZ)).unwrap();

    for (n, (_, wire)) in frames.iter().enumerate().take(500) {
        let fr = Frame::parse(wire).unwrap();
        let pdu = SavPduView::parse(fr.apdu, &Limits::DEFAULT).unwrap();
        let asdu = pdu.asdus().next().unwrap().unwrap();
        publisher.set_smp_cnt(asdu.smp_cnt);
        publisher.set_smp_synch(asdu.smp_synch.unwrap()).unwrap();
        publisher.publish(Instant(n as u64), &[asdu.sample]).unwrap();
        assert_eq!(publisher.poll_transmit().unwrap(), &wire[..], "frame {n} differs from the captured one");
    }
}
