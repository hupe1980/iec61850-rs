//! Interop against stacks nobody here wrote, in both roles, on both buses.
//!
//! Every other test proves consistency: the two halves of this crate share one codec, so they
//! agree by construction, and `tshark` checks the octets but never the *sequence*. This is the
//! missing third — **libiec61850** (C) on the station bus and the process bus, **`IEC61850bean`**
//! (Java) and **csp0924's crates** (Rust) on the station bus.
//!
//! **Running it** needs Docker and nothing else: each peer is an image built from its Dockerfile
//! under `tests/interop/` on first use and cached after that. Without Docker every test skips
//! by name; `IEC61850_REQUIRE_INTEROP=1`, which CI sets, makes that a failure. Disagreements
//! found here, and whose they were, are in `tests/interop/PEERS.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

#[path = "interop/harness.rs"]
mod harness;

use std::time::Duration;

use harness::{HOST, docker, exec, read_file, retry, sh};
use iec61850_rs::Fc;
use iec61850_rs::client::{Client, ControlModel, RcbSettings, TrgOps};
use iec61850_rs::proto::data::{Typed, Value};
use iec61850_rs::server::{Ied, Server, ServerHandle};

const LIB: &str = "libiec61850";
/// The port a peer's server listens on inside its container.
const PEER_PORT: u16 = 10102;

/// This crate's server, serving `xml`, on an address a peer container can reach and the LAN
/// cannot. Returns the port, the handle and the accept thread.
fn serve(xml: &str) -> (u16, ServerHandle, std::thread::JoinHandle<()>) {
    let ied = Ied::from_scl(xml, None).expect("load the model");
    let server = Server::bind(&std::net::SocketAddr::new(harness::bind_addr(), 0).to_string(), ied).expect("bind");
    let port = server.local_addr().expect("addr").port();
    let handle = server.handle();
    let joined = std::thread::spawn(move || {
        for _ in 0..8 {
            if server.accept_one().is_err() {
                return;
            }
        }
    });
    (port, handle, joined)
}

/// Associate with a peer's server through its mapped port, retrying while Docker's proxy
/// accepts TCP before the peer does.
fn associate(addr: std::net::SocketAddr) -> Client {
    retry("associate with the peer", Duration::from_secs(30), || Client::connect(&addr.to_string()).ok())
}

/// Start one of libiec61850's example servers; returns the container and its host address.
fn lib_server(dir: &str, bin: &str) -> (testcontainers::Container<testcontainers::GenericImage>, std::net::SocketAddr) {
    let line = format!("cd examples/{dir} && exec ./{bin} {PEER_PORT}");
    harness::server_container(LIB, PEER_PORT, &["sh", "-c", &line], &[], None)
}

// --- libiec61850, station bus ------------------------------------------------------------------

/// **Their client, our server**: browse, read and type discovery over libiec61850's own model.
#[test]
fn libiec61850_browses_and_reads_this_server() {
    if !docker() {
        return;
    }
    let peer = harness::client_container(LIB);
    let (port, _handle, _joined) = serve(&read_file(&peer, "examples/server_example_threadless/simpleIO_direct_control.cid"));
    let port = port.to_string();
    let util = |extra: &[&str]| exec(&peer, &[&["examples/mms_utility/mms_utility", "-h", HOST, "-p", &port], extra].concat()).0;

    let identity = util(&["-i"]);
    assert!(identity.contains("vendor:"), "their client could not identify this server: {identity}");
    let domains = util(&["-d"]);
    assert!(domains.contains("simpleIOGenericIO"), "the logical device is the MMS domain: {domains}");
    let names = util(&["-t", "simpleIOGenericIO"]);
    for expected in ["GGIO1$MX$AnIn1$mag$f", "GGIO1$CO$SPCSO1$Oper$ctlVal", "LLN0$RP$EventsRCB01$RptEna"] {
        assert!(names.contains(expected), "`{expected}` missing from the browse: {names}");
    }
    let read = util(&["-a", "simpleIOGenericIO", "-r", "GGIO1$MX$AnIn1"]);
    assert!(read.contains("Read SUCCESS"), "their client could not read a measurand: {read}");
}

/// **Their client, our server**: all four control models, including the terminations.
#[test]
fn libiec61850_operates_all_four_control_models_on_this_server() {
    if !docker() {
        return;
    }
    let peer = harness::client_container(LIB);
    let (port, handle, _joined) = serve(&read_file(&peer, "tools/model_generator_dotnet/Tools/ICDFiles/simpleIO_control_tests.cid"));
    let (out, _, _) = exec(&peer, &["timeout", "60", "examples/iec61850_client_example_control/client_example_control", HOST, &port.to_string()]);
    for object in ["SPCSO1", "SPCSO2", "SPCSO3", "SPCSO4"] {
        assert!(out.contains(&format!("{object} operated successfully")), "{object} did not operate: {out}");
    }
    assert!(!out.contains("failed to select"), "a select was refused: {out}");
    assert_eq!(out.matches("Received CommandTermination+.").count(), 3, "one termination per enhanced-security command: {out}");
    assert_eq!(handle.read("simpleIOGenericIO/GGIO1$ST$SPCSO1$stVal").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(handle.read("simpleIOGenericIO/GGIO1$ST$SPCSO4$stVal").and_then(|v| v.as_bool()), Some(true));
}

/// **Their client, our server**: enable a report control block and take the reports. Their client
/// listens for a minute and then disables the block; it is run to completion, because a C
/// program writing to a pipe flushes its output at exit.
#[test]
fn libiec61850_takes_reports_from_this_server() {
    if !docker() {
        return;
    }
    let peer = harness::client_container(LIB);
    let (port, _handle, _joined) = serve(&read_file(&peer, "examples/server_example_threadless/simpleIO_direct_control.cid"));
    let (out, _, _) = exec(&peer, &["timeout", "120", "examples/iec61850_client_example1/client_example1", HOST, &port.to_string()]);
    assert!(out.contains("Connected"), "their client did not associate: {out}");
    assert!(out.contains("received report for simpleIOGenericIO/LLN0.RP.EventsRCB01"), "no report arrived: {out}");
    assert!(out.contains("included for reason 16"), "the general interrogation was not reported as one: {out}");
    assert!(out.contains("included for reason 8"), "no integrity report arrived: {out}");
}

/// **Both directions, arrays**: one element of an array, named as part of a variable.
#[test]
fn an_array_element_is_read_as_one_element_in_both_directions() {
    if !docker() {
        return;
    }
    let peer = harness::client_container(LIB);
    let (port, handle, _joined) = serve(&read_file(&peer, "examples/server_example_complex_array/mhai_array.cid"));
    handle.txn().set("testComplexArray/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f", Value::Float32(12.5)).commit();
    let port = port.to_string();
    let args = ["examples/mms_utility/mms_utility", "-h", HOST, "-p", &port, "-a", "testComplexArray", "-r", "MHAI1$MX$HA$phsAHar"];
    let whole = exec(&peer, &args).0;
    let element = exec(&peer, &[&args[..], &["-y", "2"]].concat()).0;
    let component = exec(&peer, &[&args[..], &["-y", "2", "-c", "cVal"]].concat()).0;
    for (what, out) in [("the array", &whole), ("one element", &element), ("one component", &component)] {
        assert!(out.contains("Read SUCCESS"), "{what}: {out}");
    }
    assert!(whole.matches('Z').count() >= 16, "the whole array is sixteen elements: {whole}");
    assert_eq!(element.matches('Z').count(), 1, "an index reads one element: {element}");
    assert!(element.contains("12.5"), "…and the one that was asked for: {element}");
    assert!(!component.contains('Z'), "a component of an element is smaller still: {component}");

    let (_server, addr) = lib_server("server_example_complex_array", "server_example_ca");
    let mut c = associate(addr);
    let spec = c.variable_type("testComplexArray/MHAI1$MX$HA", Fc::MX).expect("GetVariableAccessAttributes");
    assert!(
        matches!(spec.component("phsAHar"), Some(iec61850_rs::proto::mms::typespec::TypeSpec::Array { elements: 16, .. })),
        "their type says sixteen: {spec:?}"
    );
    let whole = c.read("testComplexArray/MHAI1$MX$HA$phsAHar", Fc::MX).expect("the whole array");
    assert!(matches!(&whole, Value::Array(e) if e.len() == 16), "{whole:?}");
    let leaf = c.read("testComplexArray/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f", Fc::MX).expect("one float");
    assert!(leaf.as_f64().is_some(), "{leaf:?}");
    assert_eq!(c.read("testComplexArray/MHAI1$MX$HA$phsAHar(2)$cVal$mag", Fc::MX).expect("read").members().map(<[Value]>::len), Some(1));
    assert_eq!(c.read("testComplexArray/MHAI1$MX$HA$phsAHar(2)$cVal", Fc::MX).expect("read").members().map(<[Value]>::len), Some(2));
    assert_eq!(c.read("testComplexArray/MHAI1$MX$HA$phsAHar(2)", Fc::MX).expect("read").members().map(<[Value]>::len), Some(3));
    let other = c.read("testComplexArray/MHAI1$MX$HA$phsAHar(3)$cVal$mag$f", Fc::MX).expect("read");
    assert_ne!(leaf.as_f64(), other.as_f64(), "two indices, two values");
    c.release().expect("orderly release");
}

/// **Our client, their server**: everything the client offers, against a stack it did not write.
#[test]
fn this_client_drives_a_libiec61850_server() {
    if !docker() {
        return;
    }
    let (_server, addr) = lib_server("server_example_basic_io", "server_example_basic_io");
    let mut c = associate(addr);
    assert_eq!(c.identify().expect("Identify").vendor, "MZ");
    assert!(c.is_alive(), "Status");
    let devices = c.server_directory().expect("GetServerDirectory");
    assert!(devices.iter().any(|d| d == "simpleIOGenericIO"), "{devices:?}");
    let names = c.logical_device_directory("simpleIOGenericIO").expect("GetLogicalDeviceDirectory");
    assert!(names.len() > 50, "a real namespace is more than a handful of names: {}", names.len());
    assert!(names.iter().any(|n| n == "GGIO1$MX$AnIn1$mag$f"));
    let value = c.read("simpleIOGenericIO/GGIO1$MX$AnIn1", Fc::MX).expect("Read");
    assert!(value.members().is_some_and(|m| m.len() >= 2), "a measurand is a structure: {value:?}");
    let spec = c.variable_type("simpleIOGenericIO/GGIO1$MX$AnIn1", Fc::MX).expect("GetVariableAccessAttributes");
    assert_eq!(spec.component_names(), ["mag", "q", "t"], "{spec:?}");
    let sets = c.data_set_directory("simpleIOGenericIO").expect("GetDataSetDirectory");
    assert!(sets.iter().any(|s| s == "LLN0$Events"), "{sets:?}");
    assert!(!c.data_set_members("simpleIOGenericIO", "LLN0$Events").expect("members").is_empty());
    let rcb = c
        .enable_rcb("simpleIOGenericIO/LLN0$RP$EventsRCB01", Fc::RP, &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS))
        .expect("SetURCBValues");
    assert_eq!(rcb.data_set.as_deref(), Some("simpleIOGenericIO/LLN0$Events"));
    c.general_interrogation("simpleIOGenericIO/LLN0$RP$EventsRCB01", Fc::RP).expect("GI");
    let report = c.next_report(Duration::from_secs(10)).expect("poll").expect("a GI answers with a report");
    assert_eq!(report.entries.len(), report.data_set_len(), "a GI reports every member");
    assert_eq!(c.read_control_model("simpleIOGenericIO/GGIO1.SPCSO1").expect("ctlModel"), ControlModel::DirectNormal);
    c.control("simpleIOGenericIO/GGIO1.SPCSO1").execute(&Value::Boolean(true)).expect("Operate");
    assert_eq!(c.read("simpleIOGenericIO/GGIO1$ST$SPCSO1$stVal", Fc::ST).expect("Read").as_bool(), Some(true));
    c.release().expect("orderly release");
}

/// **Their client, our server**: `SetFile`. libiec61850's `file-tool set` sends an `ObtainFile`
/// and then serves this server's `FileOpen`/`FileRead`/`FileClose` out of its container.
#[test]
fn libiec61850s_file_tool_sends_a_file_to_this_server() {
    use iec61850_rs::server::{AcsiConfig, DirectoryStore, ServerConfig, SetFilePolicy};
    if !docker() {
        return;
    }
    let peer = harness::client_container(LIB);
    let store = std::env::temp_dir().join(format!("iec61850-interop-setfile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);
    std::fs::create_dir_all(&store).unwrap();
    let body = (1..=3000).fold(String::new(), |mut s, i| {
        use std::fmt::Write as _;
        let _ = writeln!(s, "{i}");
        s
    });
    let (_, err, code) = sh(&peer, "seq 1 3000 > /tmp/upload.bin");
    assert_eq!(code, 0, "{err}");

    let cfg = ServerConfig { acsi: AcsiConfig { set_file: SetFilePolicy::Anyone, ..AcsiConfig::default() }, ..ServerConfig::default() };
    let ied = Ied::from_scl(&read_file(&peer, "examples/server_example_threadless/simpleIO_direct_control.cid"), None).expect("their model");
    let mut server = Server::bind_with(&std::net::SocketAddr::new(harness::bind_addr(), 0).to_string(), ied, &cfg).expect("bind");
    server.set_file_store(Box::new(DirectoryStore::new(&store).writable()));
    let port = server.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let _ = server.accept_one();
    });
    let line = format!("cd /tmp && timeout 60 /opt/libiec61850/examples/iec61850_client_example_files/file-tool -h {HOST} -p {port} set upload.bin");
    let (log, _, _) = sh(&peer, &line);
    assert_eq!(std::fs::read_to_string(store.join("upload.bin")).ok().as_deref(), Some(body.as_str()), "their SetFile did not land byte for byte:\n{log}");
    let _ = std::fs::remove_dir_all(&store);
}

/// **Their client, our server, either log store**: libiec61850's `client_example_log` enables the
/// log, reads the control block positionally and resumes with `QueryLogAfter`.
#[test]
fn libiec61850s_log_client_reads_this_servers_log_from_either_store() {
    if !docker() {
        return;
    }
    let peer = harness::client_container(LIB);
    // Their client names the IED `TestIED`; their model names it `simpleIO`. Same model.
    let xml = read_file(&peer, "examples/server_example_logging/simpleIO_direct_control.cid").replace("\"simpleIO\"", "\"TestIED\"");

    let received = |store: Option<Box<dyn iec61850_rs::server::LogStore>>| -> usize {
        let ied = Ied::from_scl(&xml, None).expect("their model");
        let mut server = Server::bind(&std::net::SocketAddr::new(harness::bind_addr(), 0).to_string(), ied).expect("bind");
        if let Some(store) = store {
            server.set_log_store(store);
        }
        let port = server.local_addr().expect("addr").port();
        let handle = server.handle();
        std::thread::spawn(move || {
            let _ = server.accept_one();
        });
        // Their client enables the log, then waits a second for something to happen; make it
        // happen while it waits — once the log is enabled, not on a guess at when that is.
        let writer = std::thread::spawn(move || {
            retry("their client enables the log", Duration::from_secs(30), || {
                (handle.read("TestIEDGenericIO/LLN0$LG$EventLog$LogEna").and_then(|v| v.as_bool()) == Some(true)).then_some(())
            });
            for (i, state) in [true, true, true].into_iter().enumerate() {
                handle.txn().set(&format!("TestIEDGenericIO/GGIO1$ST$SPCSO{}$stVal", i + 1), Value::Boolean(state)).commit();
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let (out, _, _) = exec(&peer, &["timeout", "60", "examples/iec61850_client_example_log/client_example_log", HOST, &port.to_string()]);
        writer.join().unwrap();
        let line = out.lines().find(|l| l.starts_with("Received")).unwrap_or_else(|| panic!("no 'Received' line in:\n{out}"));
        line.split_whitespace().nth(1).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("{line}"))
    };

    let memory = received(None);
    assert_eq!(memory, 2, "their client reads the entries after the oldest one");
    #[cfg(feature = "log-redb")]
    {
        let path = std::env::temp_dir().join(format!("iec61850-interop-log-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = iec61850_rs::server::RedbLog::open(&path, vec![String::from("TestIEDGenericIO/LLN0$EventLog")], 100).expect("open");
        assert_eq!(received(Some(Box::new(store))), memory, "the redb store answers their client exactly as the memory store does");
        let _ = std::fs::remove_file(&path);
    }
}

/// **Our client, their server**: the log services.
#[test]
fn this_client_reads_a_log_out_of_a_libiec61850_server() {
    if !docker() {
        return;
    }
    let (_server, addr) = lib_server("server_example_logging", "server_example_logging");
    let mut c = associate(addr);
    // The example writes one entry a second; one is enough.
    std::thread::sleep(Duration::from_secs(2));
    let lcb = c.read_lcb("simpleIOGenericIO/LLN0$LG$EventLog", Fc::LG).expect("GetLCBValues");
    assert_eq!(lcb.log_ref.as_deref(), Some("simpleIOGenericIO/LLN0$EventLog"));
    let (_, oldest) = lcb.oldest().expect("the buffer cursor, under whichever name the server spells it");
    let page = c.query_log_by_time("simpleIOGenericIO/LLN0$EventLog", oldest, None).expect("QueryLogByTime");
    assert!(!page.entries.is_empty(), "their server logs an entry a second");
    let entry = &page.entries[0];
    assert!(!entry.variables.is_empty(), "an entry carries the data attribute that changed");
    let (id, at) = entry.resume_point();
    let after = c.query_log_after_entry("simpleIOGenericIO/LLN0$EventLog", &id, at).expect("QueryLogAfterEntry");
    assert!(after.entries.iter().all(|e| e.entry_id != id), "a resume starts *after* the entry it names");
    c.release().expect("orderly release");
}

// --- libiec61850, process bus ------------------------------------------------------------------

/// Both sides of one process-bus run: libiec61850's container and this crate's `ied`, on one
/// Docker network, each owning a raw socket on its `eth0`.
struct Bus {
    lib: testcontainers::Container<testcontainers::GenericImage>,
    ied: testcontainers::Container<testcontainers::GenericImage>,
    _net: harness::Network,
}

fn bus(test: &str, ied_files: &[(&str, &str)]) -> Bus {
    let net = harness::Network::new(test);
    let lib = harness::on_network(harness::image(LIB), &net, "lib");
    let ied = harness::ied_container(&net, ied_files);
    Bus { lib, ied, _net: net }
}

/// Run `listener` in one container and, once it is listening, `talker` in the other; returns the
/// listener's standard output.
fn listen_while(
    listen_in: &testcontainers::Container<testcontainers::GenericImage>,
    listener: &str,
    talk_in: &testcontainers::Container<testcontainers::GenericImage>,
    talker: &str,
) -> (String, String) {
    std::thread::scope(|s| {
        let heard = s.spawn(|| sh(listen_in, listener));
        std::thread::sleep(Duration::from_millis(1500));
        let (said, err, _) = sh(talk_in, talker);
        let (out, lerr, _) = heard.join().unwrap();
        (format!("{out}{lerr}"), format!("{said}{err}"))
    })
}

const IED: &str = "/target/debug/ied";

/// **Their publisher, our subscriber**: libiec61850's GOOSE publisher example, read by this crate's
/// subscriber state machine on a live interface.
#[test]
fn process_bus_libiec61850_goose_reaches_this_subscriber() {
    if !docker() {
        return;
    }
    let b = bus("goose-in", &[]);
    let (heard, said) = listen_while(
        &b.ied,
        &format!("{IED} goose sniff --iface eth0 --duration 8"),
        &b.lib,
        "timeout 20 examples/goose_publisher/goose_publisher_example eth0",
    );
    assert!(said.contains("Using interface eth0") && !said.contains("Failed"), "their publisher did not start: {said}");
    assert!(heard.contains("simpleIOGenericIO/LLN0$GO$gcbAnalogValues"), "our subscriber did not see their GoCB:\n{heard}");
}

/// **Our publisher, their subscriber**: a `GoCB` of libiec61850's own GOOSE model, published by
/// `ied goose publish`, decoded by their subscriber example.
#[test]
fn process_bus_this_goose_reaches_libiec61850s_subscriber() {
    if !docker() {
        return;
    }
    let peer = harness::client_container(LIB);
    let model = read_file(&peer, "examples/server_example_goose/simpleIO_direct_control_goose.cid");
    drop(peer);
    let b = bus("goose-out", &[("/tmp/goose.cid", &model)]);
    // SCL writes APPID in hex, so their file's `1000` is 0x1000, while their subscriber example
    // listens for decimal 1000 (PEERS.md). Engineer the block at 0x03E8 with `ied scl edit`, as
    // a file written for that subscriber would be, and publish that.
    let (out, _, code) =
        sh(&b.ied, &format!("{IED} scl edit /tmp/goose.cid gse simpleIO GenericIO gcbAnalogValues --appid 03E8 --force -o /tmp/goose-03e8.cid"));
    assert_eq!(code, 0, "ied scl edit: {out}");
    let publish = format!("{IED} goose publish --iface eth0 --scd /tmp/goose-03e8.cid --gocb simpleIOGenericIO/LLN0.gcbAnalogValues --duration 4");
    let (heard, said) = listen_while(&b.lib, "timeout -s INT 8 examples/goose_subscriber/goose_subscriber_example eth0", &b.ied, &publish);
    assert!(heard.contains("GOOSE event"), "their subscriber received nothing; we said:\n{said}\nthey said:\n{heard}");
    assert!(heard.contains("message is valid"), "their subscriber judged our GOOSE invalid:\n{heard}");
    assert!(!heard.contains("INVALID"), "{heard}");
}

/// **Their publisher, our subscriber**: libiec61850's SV publisher example, tracked by this crate's
/// multi-stream subscriber.
#[test]
fn process_bus_libiec61850_sv_reaches_this_subscriber() {
    if !docker() {
        return;
    }
    let b = bus("sv-in", &[]);
    // Their example publishes to its GOOSE default address, outside the SV range (PEERS.md), so
    // the subscriber joins that group as one engineered from an SCD would.
    let monitor = format!("{IED} sv monitor --iface eth0 --duration 4 --group 01-0C-CD-01-00-01");
    let (heard, said) = listen_while(&b.ied, &monitor, &b.lib, "timeout 3 examples/sv_publisher/sv_publisher eth0");
    assert!(!said.contains("Failed"), "their publisher did not start: {said}");
    assert!(heard.contains("svpub1"), "our subscriber did not see their stream:\n{heard}");
}

/// **Our publisher, their subscriber**: `ied mu` as a 9-2LE merging unit, decoded by their SV
/// subscriber example.
#[test]
fn process_bus_this_sv_reaches_libiec61850s_subscriber() {
    if !docker() {
        return;
    }
    let b = bus("sv-out", &[]);
    let (heard, said) = listen_while(
        &b.lib,
        "timeout -s INT 6 examples/sv_subscriber/sv_subscriber eth0",
        &b.ied,
        &format!("{IED} mu --iface eth0 --profile le80-50 --frames 4000"),
    );
    assert!(heard.contains("svID=(MU01)"), "their subscriber did not decode our stream; we said:\n{said}\nthey said:\n{heard}");
    assert!(heard.contains("smpCnt"), "{heard}");
}

// --- IEC61850bean and csp0924, station bus -----------------------------------------------------

const RELAY: &str = include_str!("fixtures/relay.icd");

/// The `OK`/`FAIL`/`SKIP` lines of a probe run; panics on any `FAIL`.
fn steps(peer: &str, out: &str, expected: &[&str]) {
    let fails: Vec<_> = out.lines().filter(|l| l.starts_with("FAIL")).collect();
    assert!(fails.is_empty(), "{peer} disagreed — record it in tests/interop/PEERS.md:\n{out}");
    for step in expected {
        assert!(out.lines().any(|l| l.starts_with(&format!("OK {step}")) || l.starts_with(&format!("SKIP {step}"))), "{peer}: no `{step}` step in:\n{out}");
    }
}

/// **Their client, our server** (`IEC61850bean`).
#[test]
fn iec61850bean_client_drives_this_server() {
    if !docker() {
        return;
    }
    let peer = harness::client_container("iec61850bean");
    let (port, handle, _joined) = serve(RELAY);
    handle.txn().set("IED1LD0/MMXU1$MX$TotW$mag$f", Value::Float32(42.0)).commit();
    let (out, err, _) = exec(&peer, &["timeout", "60", "java", "-cp", "/opt/probe:/opt/probe/*", "Probe", "client", HOST, &port.to_string()]);
    steps("IEC61850bean", &format!("{out}{err}"), &["associate", "model", "read", "write", "report", "control-direct", "files", "release"]);
}

/// **Our client, their server** (`IEC61850bean`).
#[test]
fn this_client_drives_an_iec61850bean_server() {
    if !docker() {
        return;
    }
    let (_server, addr) =
        harness::server_container("iec61850bean", PEER_PORT, &["server", "10102", "/tmp/model.icd"], &[("/tmp/model.icd", RELAY)], Some("READY"));
    let mut c = associate(addr);
    let devices = c.server_directory().expect("GetServerDirectory");
    assert!(devices.iter().any(|d| d == "IED1LD0"), "{devices:?}");
    let names = c.logical_device_directory("IED1LD0").expect("GetLogicalDeviceDirectory");
    assert!(names.iter().any(|n| n == "MMXU1$MX$TotW$mag$f"), "{names:?}");
    let v = c.read("IED1LD0/MMXU1$MX$TotW$mag$f", Fc::MX).expect("Read");
    assert!(v.as_f64().is_some(), "{v:?}");
    let spec = c.variable_type("IED1LD0/MMXU1$MX$TotW", Fc::MX).expect("GetVariableAccessAttributes");
    assert!(spec.component("mag").is_some(), "{spec:?}");
    let rcb = c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS)).expect("SetURCBValues");
    assert!(rcb.data_set.is_some(), "{rcb:?}");
    c.general_interrogation("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("GI");
    let report = c.next_report(Duration::from_secs(10)).expect("poll").expect("a GI answers with a report");
    assert_eq!(report.entries.len(), report.data_set_len(), "a GI reports every member");
    c.release().expect("orderly release");
}

/// **Their client, our server** (csp0924).
#[test]
fn csp0924_client_drives_this_server() {
    if !docker() {
        return;
    }
    let peer = harness::client_container("csp0924");
    let (port, handle, _joined) = serve(RELAY);
    handle.txn().set("IED1LD0/MMXU1$MX$TotW$mag$f", Value::Float32(42.0)).commit();
    let (out, err, _) = exec(&peer, &["timeout", "60", "probe", "client", HOST, &port.to_string(), "IED1LD0"]);
    steps("csp0924", &format!("{out}{err}"), &["associate", "directory", "model", "read", "write", "report", "control-direct", "release"]);
}

/// **Our client, their server** (csp0924): browse and read. Their server builds its namespace
/// from the SCL file but registers control blocks and control objects in code, so those are not
/// served from the file and are not driven here (`tests/interop/PEERS.md`).
#[test]
fn this_client_drives_a_csp0924_server() {
    if !docker() {
        return;
    }
    let (_server, addr) =
        harness::server_container("csp0924", PEER_PORT, &["server", "10102", "/tmp/model.icd", "IED1"], &[("/tmp/model.icd", RELAY)], Some("READY"));
    let mut c = associate(addr);
    let devices = c.server_directory().expect("GetServerDirectory");
    assert!(devices.iter().any(|d| d == "IED1LD0"), "{devices:?}");
    let names = c.logical_device_directory("IED1LD0").expect("GetLogicalDeviceDirectory");
    assert!(names.iter().any(|n| n == "MMXU1$MX$TotW$mag$f"), "{names:?}");
    let v = c.read("IED1LD0/MMXU1$MX$TotW$mag$f", Fc::MX).expect("Read");
    assert!(v.as_f64().is_some(), "{v:?}");
    let spec = c.variable_type("IED1LD0/MMXU1$MX$TotW", Fc::MX).expect("GetVariableAccessAttributes");
    assert!(spec.component("mag").is_some(), "{spec:?}");
    c.release().expect("orderly release");
}

// --- The harness's own guarantees --------------------------------------------------------------

/// Every artifact an image downloads is pinned and checked, or built from a lock file.
#[test]
fn every_peer_artifact_is_pinned_and_checked() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop");
    let dockerfile = |peer: &str| std::fs::read_to_string(dir.join(peer).join("Dockerfile")).unwrap();
    for peer in ["libiec61850", "iec61850bean"] {
        let text = dockerfile(peer);
        assert!(text.contains("sha256sum -c"), "{peer}: downloads are not checked");
        assert_eq!(text.matches("curl -fsSL").count(), text.matches("sha256sum -c").count(), "{peer}: one checksum per download");
    }
    assert!(dockerfile("csp0924").contains("--locked") && dir.join("csp0924/Cargo.lock").is_file(), "csp0924 builds from its lock file");
}

/// The server a peer client reaches is never on an address the LAN can reach.
#[test]
fn the_test_server_never_listens_on_all_interfaces() {
    if !docker() {
        return;
    }
    let addr = harness::bind_addr();
    assert!(!addr.is_unspecified(), "{addr}");
    assert!(addr.is_loopback() || cfg!(target_os = "linux"), "off Linux it is loopback: {addr}");
}

/// A container is removed when the test that owns it panics.
#[test]
fn a_peer_container_does_not_outlive_a_panicking_test() {
    if !docker() {
        return;
    }
    let id = std::thread::spawn(|| {
        let c = harness::client_container(LIB);
        std::panic::panic_any(c.id().to_string())
    })
    .join()
    .unwrap_err();
    let id = *id.downcast::<String>().expect("the container id");
    let out = std::process::Command::new("docker").args(["ps", "-a", "-q", "--no-trunc", "--filter", &format!("id={id}")]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).trim().is_empty(), "container {id} outlived its test");
}

/// A peer runs as an unprivileged user, unprivileged, on the default bridge, without the socket.
#[test]
fn peer_containers_run_unprivileged() {
    if !docker() {
        return;
    }
    for peer in [LIB, "iec61850bean", "csp0924"] {
        let c = harness::client_container(peer);
        let out = std::process::Command::new("docker")
            .args(["inspect", "-f", "{{.Config.User}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{range .Mounts}}{{.Source}} {{end}}", c.id()])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let parts: Vec<_> = text.split('|').collect();
        assert!(!parts[0].is_empty() && parts[0] != "root" && parts[0] != "0", "{peer} runs as root: {text}");
        assert_eq!(parts[1], "false", "{peer} is privileged: {text}");
        assert_ne!(parts[2], "host", "{peer} is on the host network: {text}");
        assert!(!parts.get(3).is_some_and(|m| m.contains("docker.sock")), "{peer} sees the Docker socket: {text}");
    }
}
