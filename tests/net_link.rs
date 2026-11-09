//! GOOSE and sampled values over a real kernel link (Linux).
//!
//! Skips unless `IEC61850_IFACE` and `IEC61850_PEER_IFACE` name the two ends of a veth pair
//! and the process may open raw sockets; `scripts/linux-test.sh` sets that up in a container.
//! `RAWETHER_RX=plain` runs the receive side on the plain path instead of the ring.

#![cfg(target_os = "linux")]
// The counting allocator is the only way to make "no allocation" a measured number.
#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::doc_markdown)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use iec61850_rs::common::{Instant, MacAddr, TimeQuality, UtcTime, monotonic_now};
use iec61850_rs::net::{Link, LinkOptions, Receive};
use iec61850_rs::proto::data::Value;
use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, ETHERTYPE_SV, Frame, FrameHeader, VlanTag};
use iec61850_rs::proto::goose::{Invalid, Publisher, PublisherConfig, Retransmission, Subscriber, SubscriberConfig, SubscriberEvent, SubscriptionKey};

struct Counting;
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards every call to the system allocator unchanged and only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const GOOSE_DST: MacAddr = MacAddr([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x05]);
const GOCB: &str = "IED1LD0/LLN0$GO$gcbTrip";

fn pair() -> Option<(String, String)> {
    Some((std::env::var("IEC61850_IFACE").ok()?, std::env::var("IEC61850_PEER_IFACE").ok()?))
}

fn receive() -> Receive {
    if std::env::var("RAWETHER_RX").as_deref() == Ok("plain") { Receive::Plain } else { Receive::Auto }
}

fn goose_publisher(src: MacAddr, dst: MacAddr) -> Publisher {
    let header =
        FrameHeader { dst, src, vlan: Some(VlanTag { priority: 4, dei: false, id: 1 }), ethertype: ETHERTYPE_GOOSE, appid: 5, reserved1: 0, reserved2: 0 };
    let mut cfg = PublisherConfig::new(header, GOCB, "IED1LD0/LLN0$dsTrip");
    cfg.conf_rev = 3;
    cfg.retransmission = Retransmission { min_time_ms: 4, max_time_ms: 64, tal_factor: 2 };
    Publisher::new(cfg, &[Value::Boolean(false)], UtcTime::from_unix_nanos(1_700_000_000_000_000_000, TimeQuality::default())).unwrap()
}

/// Run `publisher` until `until`, sending every frame it produces.
fn drive(link: &Link, publisher: &mut Publisher, until: Instant) -> Vec<Vec<u8>> {
    let mut sent = Vec::new();
    loop {
        let now = monotonic_now();
        if now >= until {
            return sent;
        }
        publisher.on_timeout(now).unwrap();
        if let Some(f) = publisher.poll_transmit() {
            link.send(f).unwrap();
            sent.push(f.to_vec());
        }
        let next = publisher.next_timeout().unwrap_or(until).min(until);
        std::thread::sleep(Duration::from_nanos(next.nanos_since(monotonic_now())));
    }
}

/// SR-001, SR-002: the retransmission curve arrives intact through the kernel filter, every
/// frame stamped and tagged as it was sent; a replayed frame is judged a replay by the same
/// subscriber; other EtherTypes and unjoined groups never arrive; drop counters are readable.
#[test]
fn goose_crosses_a_real_link_and_the_subscriber_rules_hold_on_it() {
    let Some((iface, peer)) = pair() else { return };
    let mut rx = Link::open(&peer, &LinkOptions::goose().join(GOOSE_DST).receive(receive())).unwrap();
    let tx = Link::open(&iface, &LinkOptions::goose()).unwrap();
    let mut publisher = goose_publisher(tx.mac(), GOOSE_DST);

    // Noise the filter must keep out: another EtherType, and GOOSE to a group nobody joined.
    let mut other = goose_publisher(tx.mac(), MacAddr([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x99]));
    other.on_timeout(Instant::ZERO).unwrap();
    tx.send(other.poll_transmit().unwrap()).unwrap();
    let mut ip = vec![0u8; 60];
    ip[..6].copy_from_slice(&GOOSE_DST.0);
    ip[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    tx.send(&ip).unwrap();

    let sent = drive(&tx, &mut publisher, monotonic_now().plus_millis(300));
    assert!(sent.len() >= 6, "the curve: {}", sent.len());
    tx.send(&sent[1]).unwrap(); // a replay

    let mut sub = Subscriber::new(SubscriberConfig::new(SubscriptionKey { dst: GOOSE_DST, appid: 5, gocb_ref: GOCB.into() }).with_conf_rev(3));
    let (mut received, mut replays, mut states) = (0, 0, 0);
    while let Some(r) = rx.recv(Some(Duration::from_millis(200))).unwrap() {
        assert!(r.wire_time.is_some(), "every frame is timestamped");
        assert!(!r.truncated);
        let f = Frame::parse(r.frame).unwrap();
        assert_eq!(f.ethertype, ETHERTYPE_GOOSE, "only GOOSE passes the filter");
        assert_eq!(f.dst, GOOSE_DST, "only the joined group passes the filter");
        assert_eq!(f.vlan.map(|v| (v.priority, v.id)), Some((4, 1)), "the tag as it was sent");
        received += 1;
        sub.on_frame(r.at, r.frame);
        while let Some(e) = sub.poll_event() {
            match e {
                SubscriberEvent::NewState { .. } => states += 1,
                SubscriberEvent::Invalid(Invalid::Replay { .. }) => replays += 1,
                _ => {}
            }
        }
    }
    assert_eq!(received, sent.len() + 1, "every frame of the curve and the replay");
    assert_eq!((states, replays), (1, 1), "one state, and the replay judged as one");
    assert_eq!(sub.st_num(), Some(1));
    let stats = rx.stats().unwrap();
    assert_eq!(stats.dropped, 0);
}

/// One second of 4800 frames/s sampled values reaches the subscriber without a gap.
#[test]
fn a_second_of_sampled_values_arrives_without_a_gap() {
    use iec61850_rs::proto::sv::{
        Publisher as SvPublisher, PublisherConfig as SvConfig, SmpSynch, StreamConfig, StreamKey, Subscriber as SvSubscriber, SubscriberEvent as SvEvent,
        SvProfile,
    };
    let Some((iface, peer)) = pair() else { return };
    let dst = MacAddr([0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01]);
    let mut rx = Link::open(&peer, &LinkOptions::sv().join(dst).receive(receive())).unwrap();
    let tx = Link::open(&iface, &LinkOptions::sv()).unwrap();
    let profile = SvProfile::LE_80_60HZ; // 4800 frames a second
    let header = FrameHeader { dst, src: tx.mac(), vlan: Some(VlanTag::DEFAULT), ethertype: ETHERTYPE_SV, appid: 0x4000, reserved1: 0, reserved2: 0 };
    let mut publisher = SvPublisher::new(SvConfig::new(header, "MU01", profile)).unwrap();
    publisher.set_smp_synch(SmpSynch::Global).unwrap();
    let block = vec![0u8; profile.sample_len];

    let receiver = std::thread::spawn(move || {
        let mut sub = SvSubscriber::new(vec![StreamConfig::new(StreamKey { dst, appid: 0x4000, sv_id: "MU01".into() }).with_samples_per_second(4800)]);
        let (mut frames, mut gaps) = (0u32, 0u32);
        while let Some(r) = rx.recv(Some(Duration::from_millis(300))).unwrap() {
            frames += 1;
            sub.on_frame(r.at, r.frame, |_| {});
            while let Some(e) = sub.poll_event() {
                if matches!(e, SvEvent::Gap { .. }) {
                    gaps += 1;
                }
            }
        }
        (frames, gaps, rx.stats().unwrap())
    });

    let start = monotonic_now().plus_millis(20);
    let interval = profile.frame_interval_nanos();
    for k in 0..4800u64 {
        let due = start.plus_nanos(k * interval);
        while monotonic_now() < due {
            let left = due.nanos_since(monotonic_now());
            if left > 200_000 {
                std::thread::sleep(Duration::from_nanos(left - 150_000));
            } else {
                std::hint::spin_loop();
            }
        }
        publisher.publish_repeating(due, &block).unwrap();
        tx.send(publisher.poll_transmit().unwrap()).unwrap();
    }
    let (frames, gaps, stats) = receiver.join().unwrap();
    assert_eq!(u64::from(frames) + stats.dropped, 4800, "every frame received or counted as dropped");
    assert_eq!((frames, gaps), (4800, 0), "no gap at 4800 frames/s");
}

/// SR-004: dropping the capability keeps an open link working.
#[test]
fn an_open_link_survives_dropping_the_capability() {
    let Some((iface, peer)) = pair() else { return };
    if std::env::var("IEC61850_DROP_CHILD").is_err() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "an_open_link_survives_dropping_the_capability"])
            .env("IEC61850_DROP_CHILD", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        return;
    }
    let mut rx = Link::open(&peer, &LinkOptions::goose().join(GOOSE_DST).receive(receive())).unwrap();
    let tx = Link::open(&iface, &LinkOptions::goose()).unwrap();
    iec61850_rs::net::drop_capabilities().unwrap();
    let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    for cap in ["CapEff:", "CapPrm:"] {
        assert!(status.lines().any(|l| l.starts_with(cap) && l.ends_with("0000000000000000")), "{status}");
    }
    let mut p = goose_publisher(tx.mac(), GOOSE_DST);
    p.on_timeout(Instant::ZERO).unwrap();
    tx.send(p.poll_transmit().unwrap()).unwrap();
    assert!(rx.recv(Some(Duration::from_secs(2))).unwrap().is_some());
    assert!(Link::open(&peer, &LinkOptions::goose()).unwrap_err().to_string().contains("CAP_NET_RAW"));
}

/// Kills the simulator however the test ends, so a failed assertion leaves no process behind
/// holding the test's output open.
struct Sim(std::process::Child);

impl Drop for Sim {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// SR-004, for the whole process: `ied sim --iface` opens its link, drops the capability and
/// only then starts serving and publishing, so no thread of it — effective or permitted, task by
/// task — keeps `CAP_NET_RAW`. Linux capabilities are per thread, so this is a property of the
/// program's order, and the program is what is checked (`IEC61850_IED` names the binary).
#[test]
fn no_thread_of_ied_sim_keeps_the_capability() {
    use std::io::{BufRead, BufReader};
    let (Some((iface, _)), Ok(ied)) = (pair(), std::env::var("IEC61850_IED")) else { return };
    let scl = std::env::temp_dir().join(format!("iec61850-caps-{}.icd", std::process::id()));
    std::fs::write(&scl, include_str!("fixtures/process_bus.icd")).unwrap();
    let mut child = Sim(std::process::Command::new(ied)
        .args(["sim", scl.to_str().unwrap(), "--ied", "IED1", "--port", "0", "--iface", &iface])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap());
    let stdout = child.0.stdout.take().unwrap();
    let banner: Vec<String> = BufReader::new(stdout).lines().map_while(Result::ok).take_while(|l| !l.starts_with("serving")).collect();
    // The accept loop and the process-bus thread start with `run`, just after the banner.
    std::thread::sleep(Duration::from_millis(300));
    let tasks = std::fs::read_dir(format!("/proc/{}/task", child.0.id())).unwrap();
    let mut seen = Vec::new();
    for task in tasks.flatten() {
        let status = std::fs::read_to_string(task.path().join("status")).unwrap();
        let name = status.lines().find_map(|l| l.strip_prefix("Name:")).unwrap_or("").trim().to_string();
        for cap in ["CapEff:", "CapPrm:"] {
            let line = status.lines().find(|l| l.starts_with(cap)).unwrap();
            assert!(line.ends_with("0000000000000000"), "thread {name} keeps {line}");
        }
        seen.push(name);
    }
    drop(child);
    let _ = std::fs::remove_file(&scl);
    assert!(seen.iter().any(|n| n == "process-bus"), "the publisher thread is running: {seen:?} ({banner:?})");
}

/// SC-004: retransmitting and receiving in the steady state allocates nothing.
#[test]
fn the_live_steady_state_does_not_allocate() {
    let Some((iface, peer)) = pair() else { return };
    let mut rx = Link::open(&peer, &LinkOptions::goose().join(GOOSE_DST).receive(receive())).unwrap();
    let tx = Link::open(&iface, &LinkOptions::goose()).unwrap();
    let mut p = goose_publisher(tx.mac(), GOOSE_DST);
    let mut sub = Subscriber::new(SubscriberConfig::new(SubscriptionKey { dst: GOOSE_DST, appid: 5, gocb_ref: GOCB.into() }));
    let mut now = Instant::ZERO;
    let mut round = |count: &mut u32| {
        now = now.plus_millis(64);
        p.on_timeout(now).unwrap();
        if let Some(f) = p.poll_transmit() {
            tx.send(f).unwrap();
        }
        if let Some(r) = rx.recv(Some(Duration::from_millis(100))).unwrap() {
            sub.on_frame(r.at, r.frame);
            while sub.poll_event().is_some() {}
            *count += 1;
        }
    };
    let mut warm = 0;
    for _ in 0..50 {
        round(&mut warm);
    }
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut seen = 0;
    for _ in 0..500 {
        round(&mut seen);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    assert!(seen > 400, "{seen}");
    if std::env::var("IEC61850_ALLOC_ALONE").is_ok() {
        assert_eq!(after - before, 0, "allocations on the live steady-state path");
    }
}
