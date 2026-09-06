//! The steady state allocates nothing, and this counts the allocations to prove it.
//!
//! "Zero allocations per frame" is the sort of claim that is true when it is written and
//! quietly false three commits later — a `to_vec()` in an error path, a `format!` in a
//! trace, a `Vec` that is rebuilt instead of cleared. A counting allocator turns it into a
//! number a test can assert on, with no dependency and nothing to run by hand.
//!
//! Only the hot paths are covered: a GOOSE publisher retransmitting, a sampled-value
//! publisher patching its template, and a sampled-value subscriber receiving. The GOOSE
//! *subscriber* deliberately allocates on a state change — it hands the application owned
//! values — so it is measured rather than required to be free.
//!
//! One claim here is about **bytes** rather than calls: a file service that serves a record
//! in chunks must cost the chunk, not the record. A count of allocations cannot tell a
//! four-megabyte one from a one-kilobyte one, so the allocator totals the sizes as well.

// The one place in this repository that opts into `unsafe`, and only to implement
// `GlobalAlloc` by delegating every call to the system allocator. The library keeps
// `#![forbid(unsafe_code)]`.
#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use iec61850_rs::common::{Instant, Quality, TimeQuality, UtcTime};
use iec61850_rs::proto::data::Value;
use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, ETHERTYPE_SV, FrameHeader, MacAddr, VlanTag};
use iec61850_rs::proto::goose::{
    Publisher as GoosePublisher, PublisherConfig as GooseConfig, Retransmission, Subscriber as GooseSubscriber, SubscriberConfig, SubscriptionKey,
};
use iec61850_rs::proto::sv::le::PhsMeas1;
use iec61850_rs::proto::sv::{
    ChannelType, Publisher as SvPublisher, PublisherConfig as SvConfig, SampleLayout, SmpSynch, StreamConfig, StreamKey, Subscriber as SvSubscriber, SvProfile,
};

/// Delegates to the system allocator and counts what the *measuring thread* asks for.
///
/// Everything is thread-local and const-initialised, so the test harness's own threads — and
/// the lazy initialisation of the cells themselves — cannot land in the count. Thread-local
/// *counters*, not just a thread-local flag: with a process-wide total, two `#[test]`s in
/// this file measure each other, which is a constraint that quietly turns into a wrong number
/// the day somebody adds the second test.
struct Counting;

thread_local! {
    static MEASURING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
    /// Octets requested, not just requests. Some claims are about how *much* was allocated.
    static BYTES: Cell<u64> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: `layout` is forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` and `layout` are forwarded unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(new_size.saturating_sub(layout.size()));
        // SAFETY: all three arguments are forwarded unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn count(bytes: usize) {
    // `try_with` rather than `with`: during thread teardown the local is gone, and a panic
    // inside the allocator would be considerably worse than a missed count. `Cell::set`
    // allocates nothing, so this cannot recurse.
    let _ = MEASURING.try_with(|m| {
        if m.get() {
            let _ = ALLOCATIONS.try_with(|c| c.set(c.get().saturating_add(1)));
            let _ = BYTES.try_with(|c| c.set(c.get().saturating_add(bytes as u64)));
        }
    });
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Run `f` with the allocation counter on, and return how many allocations it made.
fn allocations(f: impl FnOnce()) -> u64 {
    measure(f).0
}

/// Run `f` with the counter on, and return `(allocations, octets)`.
fn measure(f: impl FnOnce()) -> (u64, u64) {
    ALLOCATIONS.with(|c| c.set(0));
    BYTES.with(|c| c.set(0));
    MEASURING.with(|m| m.set(true));
    f();
    MEASURING.with(|m| m.set(false));
    (ALLOCATIONS.with(Cell::get), BYTES.with(Cell::get))
}

fn goose_header() -> FrameHeader {
    FrameHeader {
        dst: MacAddr::GOOSE_BASE,
        src: MacAddr([2, 0, 0, 0, 0, 1]),
        vlan: Some(VlanTag::DEFAULT),
        ethertype: ETHERTYPE_GOOSE,
        appid: 1,
        reserved1: 0,
        reserved2: 0,
    }
}

fn sv_header() -> FrameHeader {
    FrameHeader {
        dst: MacAddr::SV_BASE,
        src: MacAddr([2, 0, 0, 0, 0, 2]),
        vlan: Some(VlanTag::DEFAULT),
        ethertype: ETHERTYPE_SV,
        appid: 0x4000,
        reserved1: 0,
        reserved2: 0,
    }
}

#[test]
// The counters are thread-local, so tests in this file may run in parallel without measuring
// each other. This one stays a single function because its sections share warmed-up state.
#[allow(clippy::too_many_lines)]
fn the_steady_state_allocates_nothing() {
    // --- GOOSE publisher, retransmitting -------------------------------------------------
    let values = [Value::Boolean(true), Value::quality(Quality::GOOD), Value::Integer(-7), Value::Float32(1.5)];
    let cfg = GooseConfig {
        header: goose_header(),
        gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into(),
        dat_set: "IED1LD0/LLN0$dsTrip".into(),
        go_id: Some("IED1".into()),
        conf_rev: 1,
        retransmission: Retransmission::DEFAULT,
        simulation: false,
        nds_com: false,
    };
    let mut pubr = GoosePublisher::new(cfg, &values, UtcTime::default()).unwrap();
    // Warm the buffers: the first frame is allowed to allocate, every one after it is not.
    let mut now = Instant::ZERO;
    for _ in 0..4 {
        pubr.on_timeout(now).unwrap();
        assert!(pubr.poll_transmit().is_some());
        now = pubr.next_timeout().unwrap();
    }
    let n = allocations(|| {
        for _ in 0..1000 {
            pubr.on_timeout(now).unwrap();
            let frame = pubr.poll_transmit().expect("a frame is due");
            std::hint::black_box(frame.len());
            now = pubr.next_timeout().unwrap();
        }
    });
    assert_eq!(n, 0, "a GOOSE publisher retransmitting must not allocate");

    // --- GOOSE publisher, changing state -------------------------------------------------
    // A state change re-encodes the data set. It must reuse the buffer it already has: a
    // fault is the worst possible moment to visit the allocator.
    let changed = [Value::Boolean(false), Value::quality(Quality::GOOD), Value::Integer(9), Value::Float32(-1.5)];
    let n = allocations(|| {
        for i in 0..1000 {
            let v = if i % 2 == 0 { &changed } else { &values };
            pubr.publish(now, v, UtcTime::default()).unwrap();
            std::hint::black_box(pubr.poll_transmit().expect("a state change always produces a frame").len());
            now = now.plus_millis(1);
        }
    });
    assert_eq!(n, 0, "a GOOSE state change must not allocate either");

    // --- GOOSE publisher, deciding whether the state changed at all ----------------------
    // `publish_if_changed` encodes into a second kept buffer and compares. An application
    // that offers its whole data set every scan cycle is the normal case, so this path has
    // to be free too.
    let n = allocations(|| {
        for i in 0..1000 {
            let v = if i % 100 == 0 { &changed } else { &values };
            std::hint::black_box(pubr.publish_if_changed(now, v, UtcTime::default()).unwrap());
            pubr.poll_transmit();
            now = now.plus_millis(1);
        }
    });
    assert_eq!(n, 0, "comparing the data set against the one on the wire must not allocate");

    // --- Sampled-value publisher, patching its template ----------------------------------
    let mut mu = SvPublisher::new(SvConfig::new(sv_header(), "MU01", SvProfile::F4800S2I4U4).with_time_fields(true, true)).unwrap();
    mu.set_smp_synch(SmpSynch::Global).unwrap();
    let sample = PhsMeas1 { currents: [1, 2, 3, 4], current_quality: [Quality::GOOD; 4], voltages: [5, 6, 7, 8], voltage_quality: [Quality::GOOD; 4] }.encode();
    mu.publish_repeating(Instant::ZERO, &sample).unwrap();
    mu.poll_transmit();
    // The convenience path that repeats one block per ASDU patches the template directly;
    // building a list of identical slices would allocate 2400 times a second.
    let n = allocations(|| {
        for i in 0..2400u64 {
            mu.publish_repeating(Instant(i), &sample).unwrap();
            std::hint::black_box(mu.poll_transmit().expect("a frame is pending").len());
        }
    });
    assert_eq!(n, 0, "publishing one repeated block per ASDU must not allocate");
    let n = allocations(|| {
        let blocks: [&[u8]; 2] = [&sample, &sample];
        for i in 0..2400u64 {
            mu.set_refr_tm(UtcTime::from_unix(1_700_000_000, (i * 416_666) as u32, TimeQuality::SYNCHRONIZED));
            mu.publish(Instant(i), &blocks).unwrap();
            std::hint::black_box(mu.poll_transmit().expect("a frame is pending").len());
        }
    });
    assert_eq!(n, 0, "one second of IEC 61869-9 publishing must not allocate");

    // --- Sampled-value subscriber, receiving ---------------------------------------------
    let frames: Vec<Vec<u8>> = (0..64u64)
        .map(|i| {
            mu.publish(Instant(i), &[&sample, &sample]).unwrap();
            mu.poll_transmit().unwrap().to_vec()
        })
        .collect();
    // With a layout, so that the dataset-driven decoding path is measured too: reading
    // channels out of the frame's own octets must not allocate either.
    let mut channels = Vec::new();
    for name in ["Ia", "Ib", "Ic", "In", "Ua", "Ub", "Uc", "Un"] {
        channels.push((format!("{name}.instMag.i"), ChannelType::Int(4)));
        channels.push((format!("{name}.q"), ChannelType::Quality));
    }
    let mut sub = SvSubscriber::new(vec![
        StreamConfig::new(StreamKey { dst: MacAddr::SV_BASE, appid: 0x4000, sv_id: "MU01".into() })
            .with_samples_per_second(4800)
            .with_layout(SampleLayout::new(channels)),
    ]);
    sub.on_frame(Instant::ZERO, &frames[0], |_| {});
    while sub.poll_event().is_some() {}
    let mut seen = 0u64;
    let n = allocations(|| {
        for (i, f) in frames.iter().enumerate().skip(1) {
            sub.on_frame(Instant(i as u64), f, |s| {
                seen += u64::from(s.asdu.smp_cnt);
                for (_, v) in s.channels() {
                    seen += v.as_i64().unwrap_or(0).unsigned_abs();
                }
            });
        }
    });
    std::hint::black_box(seen);
    assert_eq!(n, 0, "the sampled-value receive path must not allocate");
    assert_eq!(sub.state(0).unwrap().gaps, 0, "the run must have been a clean stream, or it measured nothing");

    // --- GOOSE subscriber: bounded, not free ---------------------------------------------
    // This one *does* allocate, by design: it hands the application owned values. What
    // matters is that a retransmission — the common case by far — does not.
    let mut gsub =
        GooseSubscriber::new(SubscriberConfig::new(SubscriptionKey { dst: MacAddr::GOOSE_BASE, appid: 1, gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into() }));
    pubr.publish(now, &values, UtcTime::default()).unwrap();
    let first = pubr.poll_transmit().unwrap().to_vec();
    let repeats: Vec<Vec<u8>> = (0..100)
        .map(|_| {
            now = pubr.next_timeout().unwrap();
            pubr.on_timeout(now).unwrap();
            pubr.poll_transmit().unwrap().to_vec()
        })
        .collect();
    // Delivered on their own timeline, a millisecond apart, so nothing expires: the point
    // here is what a retransmission costs, not what a restart costs.
    gsub.on_frame(Instant::ZERO, &first);
    while gsub.poll_event().is_some() {}
    let n = allocations(|| {
        for (i, f) in repeats.iter().enumerate() {
            gsub.on_frame(Instant::ZERO.plus_millis(i as u64 + 1), f);
            while gsub.poll_event().is_some() {}
        }
    });
    let stats = gsub.stats();
    assert_eq!((stats.state_changes, stats.retransmissions, stats.expiries), (1, 100, 0), "{stats:?}");
    assert_eq!(n, 0, "a GOOSE retransmission must not allocate; only a state change may");
}

/// A file service costs the **chunk**, not the record.
///
/// `FileOpen` used to read the whole file into the handle, so a client that opened a 200 MB
/// COMTRADE record five times on ten associations had made the server allocate ten gigabytes
/// — remotely, and with no limit anywhere to stop it. The store now reads ranges, so an open
/// costs a path and a read costs one chunk whatever the file's size.
///
/// This is a claim about octets rather than calls: a count of allocations cannot tell a
/// four-megabyte one from a one-kilobyte one, which is exactly the difference at stake.
#[test]
#[cfg(all(feature = "server", feature = "std"))]
fn opening_a_large_file_does_not_allocate_it() {
    use iec61850_rs::common::Instant;
    use iec61850_rs::proto::mms::ConfirmedRequest;
    use iec61850_rs::proto::mms::file::FileNameBuf;
    use iec61850_rs::server::{Acsi, Answer, DirectoryStore, Ied};

    const RECORD: usize = 4 << 20; // 4 MiB — far above any buffer here.

    let dir = std::env::temp_dir().join(format!("iec61850-bigfile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("rec.dat"), vec![0x5Au8; RECORD]).unwrap();

    let mut acsi = Acsi::new(Ied::from_scl(MODEL, Some("IED1")).unwrap());
    acsi.set_file_store(Box::new(DirectoryStore::new(&dir)));

    // Warm every lazily-initialised path (the store's canonicalisation, the answer buffers)
    // so the measurement is the file service and not the first call into it.
    let path = FileNameBuf::from_path("rec.dat").unwrap();
    let name = path.as_name();
    let warm = acsi.request(1, Instant::ZERO, &ConfirmedRequest::FileOpen { name, position: 0 });
    let Answer::FileOpen { frsm_id, size, .. } = warm else { panic!("not an open: {warm:?}") };
    assert_eq!(size as usize, RECORD);
    acsi.request(1, Instant::ZERO, &ConfirmedRequest::FileClose(frsm_id));

    let chunk = acsi.config().file_chunk;
    let mut frsm = 0;
    let (_, open_bytes) = measure(|| {
        let a = acsi.request(1, Instant::ZERO, &ConfirmedRequest::FileOpen { name, position: 0 });
        if let Answer::FileOpen { frsm_id, .. } = a {
            frsm = frsm_id;
        }
    });
    let (_, read_bytes) = measure(|| {
        acsi.request(1, Instant::ZERO, &ConfirmedRequest::FileRead(frsm));
    });

    // Generous ceilings — the point is the order of magnitude, not a golden number. Under
    // the old behaviour `open_bytes` alone was the whole 4 MiB.
    assert!(open_bytes < 64 * 1024, "an open must not allocate the file: {open_bytes} octets for a {RECORD}-octet record");
    assert!(read_bytes < (chunk as u64) * 8, "a read must cost a chunk ({chunk}), not a file: {read_bytes} octets");

    // …and it still delivers the record, in order and whole.
    let mut total = 0usize;
    loop {
        match acsi.request(1, Instant::ZERO, &ConfirmedRequest::FileRead(frsm)) {
            Answer::FileRead { data, more } => {
                assert!(data.iter().all(|b| *b == 0x5A), "the octets are the file's");
                total += data.len();
                if !more {
                    break;
                }
            }
            other => panic!("not a read: {other:?}"),
        }
        assert!(total <= RECORD, "the reads must terminate");
    }
    assert_eq!(total, RECORD - chunk, "the warm read above already took the first chunk");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The smallest model that has a logical device, for the file-service test above.
#[cfg(all(feature = "server", feature = "std"))]
const MODEL: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="f"/>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="INC_T"/></LNodeType>
    <DOType id="INC_T" cdc="INC"><DA name="stVal" fc="ST" bType="INT32"/></DOType>
  </DataTypeTemplates>
</SCL>"#;
