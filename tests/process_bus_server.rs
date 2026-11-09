//! A server's GOOSE and sampled-value control blocks publish once a client enables them.
//!
//! The server hands its frames to a sink (`Server::publish_to`) — the seam a live interface
//! uses — so this runs on any host: a client writes `GoEna`/`SvEna` over MMS, and the frames
//! are decoded here and, with `tshark` installed, dissected by Wireshark.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use iec61850_rs::client::Client;
use iec61850_rs::common::{Limits, MacAddr};
use iec61850_rs::proto::data::Value;
use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, ETHERTYPE_SV, Frame};
use iec61850_rs::proto::goose::GoosePduView;
use iec61850_rs::proto::sv::SavPduView;
use iec61850_rs::server::{Ied, Server, ServerHandle};
use iec61850_rs::{Error, Fc};

const FIXTURE: &str = include_str!("fixtures/process_bus.icd");
const SOURCE: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x61]);

fn serve() -> (String, ServerHandle, Receiver<(Instant, Vec<u8>)>) {
    let mut server = Server::bind("127.0.0.1:0", Ied::from_scl(FIXTURE, Some("IED1")).unwrap()).unwrap();
    server.set_source_mac(SOURCE);
    let (tx, rx) = channel();
    server
        .publish_to(move |f| {
            let _ = tx.send((Instant::now(), f.to_vec()));
        })
        .unwrap();
    let addr = server.local_addr().unwrap().to_string();
    let handle = server.handle();
    std::thread::spawn(move || server.run());
    (addr, handle, rx)
}

/// Every frame that arrives within `d`.
fn collect(rx: &Receiver<(Instant, Vec<u8>)>, d: Duration) -> Vec<(Instant, Vec<u8>)> {
    let end = Instant::now() + d;
    let mut out = Vec::new();
    while let Ok(f) = rx.recv_timeout(end.saturating_duration_since(Instant::now())) {
        out.push(f);
    }
    out
}

fn goose(frame: &[u8]) -> (u16, String, String, u32, u32, u32, Vec<Value>) {
    let f = Frame::parse(frame).unwrap();
    assert_eq!(f.ethertype, ETHERTYPE_GOOSE);
    let v = GoosePduView::parse(f.apdu).unwrap();
    (f.appid, v.gocb_ref.to_string(), v.dat_set.to_string(), v.conf_rev, v.st_num, v.sq_num, v.all_data_owned(&Limits::default()).unwrap())
}

/// SR-005, SR-006: enabling publishes the file's data set; a change is a new state; enabling
/// again restarts nothing; disabling stops the stream; an unpublishable block is refused; the
/// published data set cannot be deleted.
#[test]
fn enabling_a_goose_control_block_publishes_its_data_set_and_disabling_stops_it() {
    let (addr, handle, rx) = serve();
    let mut c = Client::connect(&addr).unwrap();
    assert!(collect(&rx, Duration::from_millis(150)).is_empty(), "nothing is published before a block is enabled");

    // The block the file gives no address cannot publish, and says so instead of going silent.
    let refused = c.write("IED1LD0/LLN0$GO$gcbBare$GoEna", Fc::GO, &Value::Boolean(true));
    assert!(matches!(refused, Err(Error::DataAccess(11))), "{refused:?}");

    c.write("IED1LD0/LLN0$GO$gcbTrip$GoEna", Fc::GO, &Value::Boolean(true)).unwrap();
    let frames = collect(&rx, Duration::from_millis(250));
    assert!(frames.len() >= 4, "the first frame and its retransmissions: {}", frames.len());
    let (appid, gocb, ds, conf_rev, st, sq0, values) = goose(&frames[0].1);
    assert_eq!((appid, gocb.as_str(), ds.as_str(), conf_rev, st, sq0), (5, "IED1LD0/LLN0$GO$gcbTrip", "IED1LD0/LLN0$dsTrip", 3, 1, 0));
    assert_eq!(values.len(), 2, "both data-set members");
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(&frames[0].1[6..12], &SOURCE.0, "published from the source address");
    for (k, (_, f)) in frames.iter().enumerate() {
        let (.., st_k, sq_k, _) = goose(f);
        assert_eq!((st_k, sq_k), (1, k as u32), "sqNum counts the retransmissions of one state");
    }

    // A change to a member is a new state, on the wire at once.
    let before = Instant::now();
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
    let (at, first) = rx.recv_timeout(Duration::from_millis(200)).unwrap();
    let (.., st, sq, values) = goose(&first);
    assert_eq!((st, sq), (2, 0));
    assert_eq!(values[0], Value::Boolean(true));
    assert!(at.duration_since(before) < Duration::from_millis(50), "a commit wakes the publisher: {:?}", at.duration_since(before));

    // Enabling an enabled block restarts nothing.
    c.write("IED1LD0/LLN0$GO$gcbTrip$GoEna", Fc::GO, &Value::Boolean(true)).unwrap();
    for (_, f) in collect(&rx, Duration::from_millis(150)) {
        assert_eq!(goose(&f).4, 2, "stNum did not advance");
    }

    // The data set it publishes cannot be deleted from under it.
    let deleted = c.delete_data_set("IED1LD0/LLN0$dsTrip");
    assert!(matches!(deleted, Err(Error::DataAccess(3))), "{deleted:?}");

    c.write("IED1LD0/LLN0$GO$gcbTrip$GoEna", Fc::GO, &Value::Boolean(false)).unwrap();
    let _ = collect(&rx, Duration::from_millis(50));
    assert!(collect(&rx, Duration::from_millis(300)).is_empty(), "disabled means silent");
    c.release().unwrap();
}

/// An enabled MSVCB publishes the model's values every sample period, from the next sample
/// after a change.
#[test]
fn enabling_a_sampled_value_control_block_publishes_the_models_values_every_sample() {
    let (addr, handle, rx) = serve();
    let mut c = Client::connect(&addr).unwrap();
    handle.txn().set("IED1MU/TCTR1$MX$AmpSv$instMag$i", Value::Integer(1234)).commit();
    c.write("IED1MU/LLN0$MS$msvcb01$SvEna", Fc::MS, &Value::Boolean(true)).unwrap();

    let frames = collect(&rx, Duration::from_millis(500));
    // 80 samples per 50 Hz period: 4000 frames a second.
    assert!(frames.len() >= 1000, "{} frames in 500 ms", frames.len());
    let mut last = None;
    for (_, f) in &frames {
        let frame = Frame::parse(f).unwrap();
        assert_eq!((frame.ethertype, frame.appid), (ETHERTYPE_SV, 0x4000));
        let pdu = SavPduView::parse(frame.apdu, &Limits::default()).unwrap();
        let asdu = pdu.asdus().next().unwrap().unwrap();
        assert_eq!(asdu.sv_id, "IED1MU01");
        assert_eq!(asdu.sample.len(), 16, "two INT32 channels and two quality words");
        if let Some(prev) = last {
            assert_eq!(asdu.smp_cnt, (prev + 1) % 4000, "no sample skipped");
        }
        last = Some(asdu.smp_cnt);
    }
    let sample = |f: &[u8]| {
        let frame = Frame::parse(f).unwrap();
        let pdu = SavPduView::parse(frame.apdu, &Limits::default()).unwrap();
        pdu.asdus().next().unwrap().unwrap().sample.to_vec()
    };
    assert_eq!(&sample(&frames[0].1)[0..4], &1234i32.to_be_bytes());

    handle.txn().set("IED1MU/TCTR1$MX$AmpSv$instMag$i", Value::Integer(-7)).commit();
    std::thread::sleep(Duration::from_millis(20));
    let later = collect(&rx, Duration::from_millis(50));
    assert_eq!(&sample(&later.last().unwrap().1)[0..4], &(-7i32).to_be_bytes(), "sample-and-hold of the new value");

    c.write("IED1MU/LLN0$MS$msvcb01$SvEna", Fc::MS, &Value::Boolean(false)).unwrap();
    let _ = collect(&rx, Duration::from_millis(50));
    assert_eq!(collect(&rx, Duration::from_millis(100)).len(), 0, "disabled means silent");
    c.release().unwrap();
}

/// What the server publishes dissects in Wireshark as the control block the file declares.
#[test]
fn published_frames_dissect_as_the_file_declares() {
    let Some(tshark) = common::tshark() else { return };
    let (addr, handle, rx) = serve();
    let mut c = Client::connect(&addr).unwrap();
    c.write("IED1LD0/LLN0$GO$gcbTrip$GoEna", Fc::GO, &Value::Boolean(true)).unwrap();
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
    c.write("IED1MU/LLN0$MS$msvcb01$SvEna", Fc::MS, &Value::Boolean(true)).unwrap();
    let frames = collect(&rx, Duration::from_millis(200));
    c.release().unwrap();

    let dir = std::env::temp_dir().join(format!("iec61850-process-bus-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pcap = dir.join("published.pcap");
    let mut w = iec61850_rs::pcap::Writer::create(&pcap).unwrap();
    for (k, (_, f)) in frames.iter().enumerate() {
        w.write(k as u64 * 1000, f).unwrap();
    }
    w.finish().unwrap();
    let out = std::process::Command::new(tshark)
        .arg("-r")
        .arg(&pcap)
        .args([
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-e",
            "goose.gocbRef",
            "-e",
            "goose.datSet",
            "-e",
            "goose.confRev",
            "-e",
            "goose.stNum",
            "-e",
            "sv.svID",
            "-e",
            "_ws.expert",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    let goose_lines: Vec<&str> = text.lines().filter(|l| l.starts_with("IED1LD0")).collect();
    assert!(!goose_lines.is_empty() && goose_lines.iter().all(|l| l.starts_with("IED1LD0/LLN0$GO$gcbTrip|IED1LD0/LLN0$dsTrip|3|")), "{text}");
    assert!(goose_lines.iter().any(|l| l.split('|').nth(3) == Some("2")), "the change is stNum 2: {text}");
    assert!(text.lines().any(|l| l.contains("IED1MU01")), "the SV stream: {text}");
    assert!(text.lines().all(|l| l.split('|').nth(5).is_none_or(str::is_empty)), "no expert info: {text}");
    let _ = std::fs::remove_dir_all(&dir);
}
