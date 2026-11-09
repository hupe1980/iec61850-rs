//! The durable log store: the `LogStore` contract on redb, a restart, the refusals, the bounds,
//! a kill in the middle of appending, and every operation answered exactly as `MemoryLog`
//! answers it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use iec61850_rs::client::Client;
use iec61850_rs::common::{EntryTime, Fc, ReasonCode};
use iec61850_rs::proto::data::Value;
use iec61850_rs::server::{Ied, LogError, LogStore, MemoryLog, NewEntry, RedbLog, Server, SyncPolicy, check_log_store, decode_record};
use proptest::prelude::*;

const RELAY: &str = include_str!("fixtures/relay.icd");
const LOG: &str = "IED1LD0/LLN0$GeneralLog";

/// A fresh path in the temporary directory, removed when dropped.
struct TempFile(PathBuf);

impl TempFile {
    fn new(tag: &str) -> TempFile {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("iec61850-log-{tag}-{}-{n}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        TempFile(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn logs() -> Vec<String> {
    vec![String::from(LOG)]
}

fn entry(ms: u32, value: i64) -> NewEntry {
    NewEntry {
        occurred: EntryTime { millis_of_day: ms, days_since_1984: 15_000 },
        values: vec![(String::from("IED1LD0/PTRC1$ST$Tr$general"), Value::Integer(value))],
        reason: Some(ReasonCode::NONE.with_data_change(true)),
    }
}

#[test]
fn the_redb_log_keeps_the_log_store_contract() {
    for capacity in [2, 3, 16] {
        let file = TempFile::new("contract");
        let mut store = RedbLog::open(&file.0, logs(), capacity).unwrap();
        check_log_store(&mut store, LOG, capacity).unwrap_or_else(|why| panic!("capacity {capacity}: {why}"));
    }
}

#[test]
fn entries_identifiers_and_bounds_survive_a_restart() {
    let file = TempFile::new("restart");
    let (before, bounds) = {
        let mut store = RedbLog::open(&file.0, logs(), 8).unwrap();
        for i in 0..5 {
            store.append(LOG, entry(1000 * (i + 1), i64::from(i))).unwrap();
        }
        (store.by_time(LOG, None, None, 100).unwrap(), store.bounds(LOG).unwrap())
    };
    let mut store = RedbLog::open(&file.0, logs(), 8).unwrap();
    assert_eq!(store.by_time(LOG, None, None, 100).unwrap(), before, "every entry comes back as it was written");
    assert_eq!(store.bounds(LOG).unwrap(), bounds);
    let next = store.append(LOG, entry(9000, 9)).unwrap();
    assert!(next.newest.0 > bounds.unwrap().newest.0, "identifiers keep counting up across the restart");
}

#[test]
fn a_second_store_on_the_same_file_is_refused_with_a_reason() {
    let file = TempFile::new("lock");
    let _first = RedbLog::open(&file.0, logs(), 8).unwrap();
    let LogError::Storage(why) = RedbLog::open(&file.0, logs(), 8).unwrap_err() else { panic!("a storage error") };
    assert!(why.contains("already open"), "{why}");
}

#[test]
fn a_file_of_another_format_is_refused_naming_both_versions() {
    let file = TempFile::new("format");
    drop(RedbLog::open(&file.0, logs(), 8).unwrap());
    {
        let db = redb::Database::create(&file.0).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(redb::TableDefinition::<&str, u64>::new("schema")).unwrap().insert("version", 2).unwrap();
        txn.commit().unwrap();
    }
    let LogError::Storage(why) = RedbLog::open(&file.0, logs(), 8).unwrap_err() else { panic!("a storage error") };
    assert!(why.contains("format 2") && why.contains("format 1"), "{why}");
}

#[test]
fn the_log_never_holds_more_than_its_capacity_and_the_file_stays_bounded() {
    let file = TempFile::new("bound");
    let mut store = RedbLog::open(&file.0, logs(), 8).unwrap().with_sync(SyncPolicy::Deferred);
    for i in 0..2_000u32 {
        store.append(LOG, entry(i, i64::from(i))).unwrap();
    }
    store.sync().unwrap();
    let after_2k = std::fs::metadata(&file.0).unwrap().len();
    for i in 2_000..10_000u32 {
        store.append(LOG, entry(i, i64::from(i))).unwrap();
    }
    store.sync().unwrap();
    assert_eq!(store.len(LOG).unwrap(), 8);
    let after_10k = std::fs::metadata(&file.0).unwrap().len();
    // Evicted pages are reused: five times the appends does not grow the file.
    assert!(after_10k <= after_2k.max(1 << 20), "the file grew from {after_2k} to {after_10k} octets at a fixed capacity");
    drop(store);

    // Reopened with a smaller capacity, it evicts down to it at once.
    let store = RedbLog::open(&file.0, logs(), 3).unwrap();
    assert_eq!(store.len(LOG).unwrap(), 3);
    assert_eq!(store.by_time(LOG, None, None, 10).unwrap().entries.last().unwrap().values[0].1, Value::Integer(9_999));
}

#[cfg(unix)]
#[test]
fn a_new_log_file_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let file = TempFile::new("mode");
    drop(RedbLog::open(&file.0, logs(), 8).unwrap());
    let mode = std::fs::metadata(&file.0).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "mode {mode:o} grants group or other access");
}

#[test]
fn a_corrupt_record_is_a_storage_error_and_the_store_keeps_working() {
    let file = TempFile::new("corrupt");
    {
        let mut store = RedbLog::open(&file.0, logs(), 8).unwrap();
        store.append(LOG, entry(1000, 1)).unwrap();
        store.append(LOG, entry(2000, 2)).unwrap();
    }
    {
        let db = redb::Database::create(&file.0).unwrap();
        let txn = db.begin_write().unwrap();
        let mut table = txn.open_table(redb::TableDefinition::<(&str, u64), &[u8]>::new("entries")).unwrap();
        // The six time octets intact, everything after them garbage.
        table.insert((LOG, 1), [0u8, 0, 3, 232, 58, 152, 1, 0, 255, 255, 255, 255, 9].as_slice()).unwrap();
        drop(table);
        txn.commit().unwrap();
    }
    let mut store = RedbLog::open(&file.0, logs(), 8).unwrap();
    assert!(matches!(store.by_time(LOG, None, None, 10), Err(LogError::Storage(why)) if why.contains("corrupt")));
    store.append(LOG, entry(3000, 3)).expect("the store still appends");
    assert_eq!(store.after_entry(LOG, 2, EntryTime::default(), 10).unwrap().entries.len(), 1, "and answers what it can decode");
}

proptest! {
    /// Decoding is total: any octets are an entry or an error.
    #[test]
    fn decoding_any_record_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = decode_record(1, &bytes);
    }
}

/// The child half of the kill test: appends until killed. A no-op unless the parent set the
/// variable naming the file.
#[test]
fn child_appends_until_killed() {
    let Some(path) = std::env::var_os("IEC61850_LOG_KILL_CHILD") else { return };
    let mut store = RedbLog::open(PathBuf::from(&path), logs(), 64).unwrap();
    let ready = ready_marker(std::path::Path::new(&path));
    let mut i: u32 = 0;
    loop {
        store.append(LOG, entry(i % 86_400_000, i64::from(i))).unwrap();
        if i == 0 {
            std::fs::write(&ready, b"").unwrap();
        }
        i = i.wrapping_add(1);
    }
}

/// The file the child creates once its first append is committed.
fn ready_marker(store: &std::path::Path) -> PathBuf {
    let mut name = store.as_os_str().to_owned();
    name.push(".ready");
    PathBuf::from(name)
}

/// A process killed while appending leaves a store that reopens consistent: the count is the
/// entries, every entry decodes, and the next identifier is above every stored one.
#[cfg(unix)]
#[test]
fn a_store_killed_mid_append_reopens_consistent() {
    for round in 0..3 {
        let file = TempFile::new("kill");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_appends_until_killed", "--nocapture", "--test-threads=1"])
            .env("IEC61850_LOG_KILL_CHILD", &file.0)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Kill only after the first commit, so a slow runner cannot make the test vacuous, and
        // at a different point in the append stream each round.
        let ready = ready_marker(&file.0);
        let until = std::time::Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(std::time::Instant::now() < until, "round {round}: the child never committed an append");
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(50 + 75 * round));
        child.kill().unwrap(); // SIGKILL
        child.wait().unwrap();
        let _ = std::fs::remove_file(&ready);

        let mut store = RedbLog::open(&file.0, logs(), 64).unwrap();
        let all = store.by_time(LOG, None, None, 1000).expect("every entry decodes");
        assert!(!all.entries.is_empty(), "round {round}: the child appended nothing before it was killed, so nothing was tested");
        assert_eq!(store.len(LOG).unwrap(), all.entries.len(), "round {round}: the count disagrees with the entries");
        assert!(all.entries.windows(2).all(|w| w[0].entry_id < w[1].entry_id));
        let top = all.entries.last().map_or(0, |e| e.entry_id);
        assert!(store.append(LOG, entry(0, 0)).unwrap().newest.0 > top, "round {round}: an EntryID was reused");
    }
}

/// A server on a `RedbLog` is stopped and started again on the same file: the control block
/// publishes the bounds before anything new is logged, and a client resumes exactly.
#[test]
fn a_restarted_server_resumes_its_log() {
    let file = TempFile::new("server");
    let serve = || {
        let mut server = Server::bind("127.0.0.1:0", Ied::from_scl(RELAY, None).unwrap()).unwrap();
        server.set_log_store(Box::new(RedbLog::open(&file.0, server.log_references(), 100).unwrap()));
        let addr = server.local_addr().unwrap().to_string();
        let handle = server.handle();
        let thread = std::thread::spawn(move || {
            let _ = server.accept_one();
        });
        (addr, handle, thread)
    };

    let (addr, handle, thread) = serve();
    for state in [true, false, true] {
        handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(state)).commit();
        std::thread::sleep(Duration::from_millis(3));
    }
    let mut c = Client::connect(&addr).unwrap();
    let first = c.query_log_by_time(LOG, EntryTime::default(), None).unwrap();
    assert_eq!(first.entries.len(), 3);
    c.release().unwrap();
    thread.join().unwrap();
    drop(handle);

    let (addr, _handle, thread) = serve();
    let mut c = Client::connect(&addr).unwrap();
    let lcb = c.read_lcb("IED1LD0/LLN0$LG$lcb01", Fc::LG).unwrap();
    assert_eq!(lcb.new_entry.as_deref(), Some(&3u64.to_be_bytes()[..]), "NewEnt is published from the file, before anything new is logged");
    let resumed = c.query_log_after_entry(LOG, &1u64.to_be_bytes(), EntryTime::default()).unwrap();
    assert_eq!(resumed.entries.len(), 2, "entries 2 and 3 survived the restart");
    assert_eq!(resumed.entries[0].variables, first.entries[1].variables);
    c.release().unwrap();
    thread.join().unwrap();
}

#[derive(Clone, Debug)]
enum Op {
    Append(u32),
    ByTime(Option<u32>, Option<u32>, usize),
    After(u64, u32, usize),
    Bounds,
    Len,
    Purge,
}

fn op() -> impl Strategy<Value = Op> {
    let t = 0u32..50;
    prop_oneof![
        6 => t.clone().prop_map(Op::Append),
        2 => (proptest::option::of(t.clone()), proptest::option::of(t.clone()), 0usize..6).prop_map(|(a, b, l)| Op::ByTime(a, b, l)),
        2 => (0u64..40, t, 0usize..6).prop_map(|(id, at, l)| Op::After(id, at, l)),
        1 => Just(Op::Bounds),
        1 => Just(Op::Len),
        1 => Just(Op::Purge),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Whatever is done to it, `RedbLog` answers exactly what `MemoryLog` answers.
    #[test]
    fn the_redb_log_answers_every_operation_as_the_memory_log_does(capacity in 1usize..8, ops in proptest::collection::vec(op(), 1..40)) {
        let file = TempFile::new("model");
        let mut redb = RedbLog::open(&file.0, logs(), capacity).unwrap().with_sync(SyncPolicy::Deferred);
        let mut memory = MemoryLog::for_logs(logs(), capacity);
        let time = |ms: u32| EntryTime { millis_of_day: ms * 1000, days_since_1984: 15_000 };
        for (i, op) in ops.iter().enumerate() {
            match op {
                Op::Append(ms) => {
                    let e = entry(ms * 1000, i64::try_from(i).unwrap());
                    prop_assert_eq!(redb.append(LOG, e.clone()), memory.append(LOG, e));
                }
                Op::ByTime(a, b, l) => prop_assert_eq!(redb.by_time(LOG, a.map(time), b.map(time), *l), memory.by_time(LOG, a.map(time), b.map(time), *l)),
                Op::After(id, at, l) => prop_assert_eq!(redb.after_entry(LOG, *id, time(*at), *l), memory.after_entry(LOG, *id, time(*at), *l)),
                Op::Bounds => prop_assert_eq!(redb.bounds(LOG), memory.bounds(LOG)),
                Op::Len => prop_assert_eq!(redb.len(LOG), memory.len(LOG)),
                Op::Purge => prop_assert_eq!(redb.purge(LOG), memory.purge(LOG)),
            }
        }
        prop_assert_eq!(redb.len("unknown"), Err(LogError::UnknownLog));
    }
}
