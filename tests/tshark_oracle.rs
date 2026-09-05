//! Wireshark as the oracle: frames built by our encoders must dissect with no malformed
//! or expert-error markers and with the field values we put in. Skips when `tshark` is
//! not installed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use iec61850_rs::common::{Instant, Quality, TimeQuality, UtcTime};
use iec61850_rs::proto::data::Value;
use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, ETHERTYPE_SV, FrameHeader, MacAddr, RESERVED1_SIMULATION, VlanTag};
use iec61850_rs::proto::goose::GoosePdu;
use iec61850_rs::proto::sv::le::PhsMeas1;
use iec61850_rs::proto::sv::{Asdu, Publisher as SvPublisher, PublisherConfig as SvPublisherConfig, SavPdu, SmpSynch, SvProfile};

fn dissect(frames: &[Vec<u8>]) -> String {
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let tshark = common::tshark().expect("tshark present");
    let dir = std::env::temp_dir().join(format!("iec61850-rs-oracle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Tests run in parallel inside one process: one file per call.
    let pcap = dir.join(format!("frames-{}.pcap", SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    common::write_pcap(&pcap, frames);
    let out = std::process::Command::new(tshark).args(["-r"]).arg(&pcap).args(["-T", "json"]).output().expect("run tshark");
    assert!(out.status.success(), "tshark failed: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(text.trim_start().starts_with('['), "tshark -T json output must be a JSON array");
    text
}

#[test]
fn goose_frame_dissects_cleanly() {
    if common::tshark().is_none() {
        return;
    }
    let pdu = GoosePdu {
        gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into(),
        time_allowed_to_live: 8,
        dat_set: "IED1LD0/LLN0$dsTrip".into(),
        go_id: Some("IED1_Trip".into()),
        t: UtcTime::from_unix(1_700_000_000, 250_000_000, TimeQuality::SYNCHRONIZED),
        st_num: 42,
        sq_num: 300,
        simulation: true,
        conf_rev: 3,
        nds_com: false,
        all_data: vec![Value::Boolean(true), Value::quality(Quality::GOOD), Value::Float32(1.5), Value::Integer(-7), Value::VisibleString("x".into())],
    };
    let h = FrameHeader {
        dst: MacAddr::parse("01-0C-CD-01-00-05").unwrap(),
        src: MacAddr([2, 0, 0, 0, 0, 1]),
        vlan: Some(VlanTag { priority: 4, dei: false, id: 1 }),
        ethertype: ETHERTYPE_GOOSE,
        appid: 5,
        reserved1: RESERVED1_SIMULATION,
        reserved2: 0,
    };
    let frame = h.to_frame(&pdu.encode().unwrap()).unwrap();
    let text = dissect(&[frame]);
    assert!(!text.contains("_ws.malformed"), "{text}");
    assert!(!text.contains("\"_ws.expert.severity\": \"Error\""), "{text}");
    for needle in [
        "\"goose.gocbRef\": \"IED1LD0/LLN0$GO$gcbTrip\"",
        "\"goose.stNum\": \"42\"",
        "\"goose.sqNum\": \"300\"",
        "\"goose.timeAllowedtoLive\": \"8\"",
        "\"goose.simulation\": \"1\"",
        "\"goose.reserve1.s_bit\": \"1\"",
        "\"goose.numDatSetEntries\": \"5\"",
        "\"goose.confRev\": \"3\"",
        "\"vlan.priority\": \"4\"",
    ] {
        assert!(text.contains(needle), "missing {needle} in {text}");
    }
}

#[test]
fn sv_frame_dissects_cleanly() {
    if common::tshark().is_none() {
        return;
    }
    let sample =
        PhsMeas1 { currents: [1000, -1000, 0, 5], current_quality: [Quality::GOOD; 4], voltages: [100_000, 0, 0, 0], voltage_quality: [Quality::GOOD; 4] };
    let pdu = SavPdu {
        asdus: vec![Asdu {
            sv_id: "IED1MU01".into(),
            dat_set: None,
            smp_cnt: 3999,
            conf_rev: 1,
            refr_tm: Some(UtcTime::from_unix(1_700_000_000, 0, TimeQuality::SYNCHRONIZED)),
            smp_synch: Some(SmpSynch::Global),
            smp_rate: Some(80),
            sample: sample.encode().to_vec(),
            smp_mod: Some(0),
            gm_identity: Some([1, 2, 3, 4, 5, 6, 7, 8]),
        }],
    };
    let h = FrameHeader {
        dst: MacAddr::parse("01-0C-CD-04-00-01").unwrap(),
        src: MacAddr([2, 0, 0, 0, 0, 2]),
        vlan: Some(VlanTag::DEFAULT),
        ethertype: ETHERTYPE_SV,
        appid: 0x4001,
        reserved1: 0,
        reserved2: 0,
    };
    let frame = h.to_frame(&pdu.encode().unwrap()).unwrap();
    let text = dissect(&[frame]);
    assert!(!text.contains("_ws.malformed"), "{text}");
    for needle in [
        "\"sv.svID\": \"IED1MU01\"",
        "\"sv.smpCnt\": \"3999\"",
        "\"sv.smpSynch\": \"2\"",
        "\"sv.smpRate\": \"80\"",
        "\"sv.noASDU\": \"1\"",
        "\"sv.appid\": \"0x4001\"",
        "\"sv.gmidentity\": \"0x0102030405060708\"",
    ] {
        assert!(text.contains(needle), "missing {needle} in {text}");
    }
}

#[test]
fn a_patched_template_dissects_as_well_as_an_encoded_one() {
    // The publisher never re-encodes: `smpCnt`, `smpSynch`, `refrTm` and `gmIdentity` are
    // written into a frame that was encoded once. Wireshark is the check that a patched
    // field is still the field it claims to be — nothing in this crate would notice an
    // off-by-one offset that happened to land inside another value of the same width.
    if common::tshark().is_none() {
        return;
    }
    let mut mu = SvPublisher::new(
        SvPublisherConfig::new(
            FrameHeader {
                dst: MacAddr::parse("01-0C-CD-04-00-01").unwrap(),
                src: MacAddr([2, 0, 0, 0, 0, 2]),
                vlan: Some(VlanTag::DEFAULT),
                ethertype: ETHERTYPE_SV,
                appid: 0x4001,
                reserved1: 0,
                reserved2: 0,
            },
            "PATCHED",
            SvProfile::F4800S2I4U4,
        )
        .with_time_fields(true, true),
    )
    .unwrap();
    mu.set_smp_synch(SmpSynch::Global);
    mu.set_gm_identity([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    mu.set_refr_tm(UtcTime::from_unix(1_700_000_000, 0, TimeQuality::SYNCHRONIZED));
    mu.set_smp_cnt(4798);

    let sample = PhsMeas1 { currents: [1, 2, 3, 4], current_quality: [Quality::GOOD; 4], voltages: [5, 6, 7, 8], voltage_quality: [Quality::GOOD; 4] }.encode();
    let mut frames = Vec::new();
    for i in 0..3u64 {
        mu.publish_repeating(Instant(i), &sample).unwrap();
        frames.push(mu.poll_transmit().unwrap().to_vec());
    }
    let text = dissect(&frames);
    assert!(!text.contains("_ws.malformed"), "{text}");
    assert!(!text.contains("\"_ws.expert.severity\": \"Error\""), "{text}");
    for needle in [
        "\"sv.svID\": \"PATCHED\"",
        "\"sv.gmidentity\": \"0x1122334455667788\"",
        "\"sv.smpSynch\": \"2\"",
        "\"sv.smpRate\": \"4800\"",
        // Three frames of two ASDUs: 4798, 4799, the wrap, and on into the next frame.
        "\"sv.smpCnt\": \"4798\"",
        "\"sv.smpCnt\": \"4799\"",
        "\"sv.smpCnt\": \"0\"",
        "\"sv.smpCnt\": \"3\"",
        "\"sv.refrTm\": \"Nov 14, 2023 22:13:20.000000000 UTC\"",
    ] {
        assert!(text.contains(needle), "missing {needle} in {text}");
    }
    // refrTm advances one sample interval per ASDU, not one per frame.
    assert!(text.contains("22:13:20.000208318"), "the second ASDU must be one sample later: {text}");
}
