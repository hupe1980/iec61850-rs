//! Real GOOSE traffic (two SEL IEDs, `specs/pcap/goose-mdehus.pcap`) against the codec
//! and the subscriber state machine. Ground truth was taken with `tshark -T fields`.
//! Skips when `specs/` is absent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use iec61850_rs::common::{Instant, Limits};
use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, Frame, MacAddr};
use iec61850_rs::proto::goose::{GoosePdu, GoosePduView, Subscriber, SubscriberConfig, SubscriberEvent, SubscriptionKey};

#[test]
fn decodes_every_goose_frame_like_wireshark() {
    let Some(path) = common::spec("pcap/goose-mdehus.pcap") else { return };
    let frames = common::read_pcap(&path);
    let mut n = 0;
    let mut sq_351 = Vec::new();
    for (_, f) in &frames {
        let Ok(fr) = Frame::parse(f) else { continue };
        if fr.ethertype != ETHERTYPE_GOOSE {
            continue;
        }
        let pdu = GoosePduView::parse(fr.apdu).expect("goose frame decodes");
        assert!(pdu.member_count_matches());
        assert_eq!(pdu.time_allowed_to_live, 2000);
        assert_eq!(pdu.conf_rev, 1);
        assert!(!pdu.simulation && !pdu.nds_com);
        match fr.appid {
            0x0003 => {
                assert_eq!(fr.dst, MacAddr::parse("01-0c-cd-01-00-03").unwrap());
                assert_eq!(pdu.gocb_ref, "SEL_351_1CFG/LLN0$GO$NewGOOSEMessage");
                assert_eq!(pdu.dat_set, "SEL_351_1CFG/LLN0$three51to2411");
                assert_eq!(pdu.go_id, Some("SEL_351_1"));
                assert_eq!((pdu.st_num, pdu.num_dat_set_entries), (23, 1));
                sq_351.push(pdu.sq_num);
            }
            0x0004 => {
                assert_eq!(pdu.gocb_ref, "SEL_2411_1CFG/LLN0$GO$NewGOOSEMessage1");
                assert_eq!(pdu.go_id, Some("SEL_2411_1"));
                assert_eq!((pdu.st_num, pdu.num_dat_set_entries), (27, 19));
            }
            other => panic!("unexpected APPID {other:#06x}"),
        }
        // Owned round trip must re-encode to the very same bytes (minimal BER both sides).
        let owned = GoosePdu::from_view(&pdu, &Limits::DEFAULT).unwrap();
        assert_eq!(owned.encode().unwrap(), pdu.raw, "re-encoding differs from the wire bytes");
        n += 1;
    }
    assert_eq!(n, 16, "tshark counts 16 GOOSE frames");
    assert_eq!(sq_351, [521, 522, 523, 524, 525, 526, 527, 528]);
}

#[test]
fn subscriber_sees_one_state_and_retransmissions() {
    let Some(path) = common::spec("pcap/goose-mdehus.pcap") else { return };
    let frames = common::read_pcap(&path);
    let key = SubscriptionKey { dst: MacAddr::parse("01-0c-cd-01-00-03").unwrap(), appid: 3, gocb_ref: "SEL_351_1CFG/LLN0$GO$NewGOOSEMessage".into() };
    let mut sub = Subscriber::new(SubscriberConfig::new(key));
    let t0 = frames[0].0;
    let mut events = Vec::new();
    for (ts, f) in &frames {
        events.extend(sub.feed(Instant(ts - t0), f));
    }
    assert!(matches!(events[0], SubscriberEvent::NewState { st_num: 23, .. }));
    assert_eq!(events.iter().filter(|e| matches!(e, SubscriberEvent::Retransmission { .. })).count(), 7);
    assert!(events.iter().all(|e| !matches!(e, SubscriberEvent::Invalid(_))), "{events:?}");
    // Everything that is not our stream — the other IED's 8 GOOSE frames and the IP/STP
    // traffic in the capture — is counted, never reported as an error.
    assert_eq!(sub.stats().other_stream, frames.len() as u64 - 8);
    assert_eq!(sub.stats().state_changes, 1);
}
