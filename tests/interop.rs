//! Interop against **libiec61850**, in both roles.
//!
//! Every other test here proves consistency: the two halves of this crate share one codec, so
//! they agree by construction, and `tshark` checks the octets but never the *sequence* (D38,
//! README rule 10). This is the missing third: a client nobody here wrote, driving this
//! server; and this client driving a server nobody here wrote.
//!
//! What each test guards is on the test; why the whole file exists is D52 and D53.
//!
//! **Running it.** Point `IEC61850_LIBIEC61850` at a built checkout — `git clone
//! https://github.com/mz-automation/libiec61850 && make examples` — and the tests run.
//! Without it they skip, because the dependency is a C library under a different licence and
//! nothing here vendors it. `IEC61850_REQUIRE_INTEROP=1` turns the skip into a failure, which
//! is what CI sets: an oracle that can quietly stop running is not an oracle.
//!
//! Nothing from libiec61850 is copied here. The models the tests serve are **its** files, read
//! out of its tree: engineering documents this author did not write (README rule 11), and the
//! namespace its examples expect.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use iec61850_rs::Fc;
use iec61850_rs::client::{Client, ControlModel, RcbSettings, TrgOps};
use iec61850_rs::proto::data::{Typed, Value};
use iec61850_rs::server::{Ied, Server, ServerHandle};

/// A built libiec61850 checkout, or `None` (tests skip).
///
/// `IEC61850_REQUIRE_INTEROP=1` makes a missing or unbuilt checkout a failure instead.
fn libiec61850() -> Option<PathBuf> {
    let required = std::env::var("IEC61850_REQUIRE_INTEROP").is_ok_and(|v| v != "0");
    let Ok(root) = std::env::var("IEC61850_LIBIEC61850").map(PathBuf::from) else {
        assert!(!required, "IEC61850_REQUIRE_INTEROP is set, but IEC61850_LIBIEC61850 does not name a libiec61850 checkout");
        eprintln!("skipping: set IEC61850_LIBIEC61850 to a built libiec61850 checkout to run the interop tests");
        return None;
    };
    // One built binary is the proof that `make examples` ran; a source-only checkout is a
    // more confusing failure than a missing one.
    if !root.join("examples/mms_utility/mms_utility").is_file() {
        assert!(!required, "IEC61850_REQUIRE_INTEROP is set, but {} holds no built examples (run `make examples`)", root.display());
        eprintln!("skipping: {} holds no built examples; run `make examples` there", root.display());
        return None;
    }
    Some(root)
}

/// One of libiec61850's own engineering files, read from its tree rather than copied here.
fn model(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// This crate's server, serving `xml`, on a port the OS picked.
fn serve(xml: &str) -> (String, ServerHandle, std::thread::JoinHandle<()>) {
    let ied = Ied::from_scl(xml, None).expect("load libiec61850's own model");
    let server = Server::bind("127.0.0.1:0", ied).expect("bind");
    let addr = server.local_addr().expect("addr").to_string();
    let handle = server.handle();
    let joined = std::thread::spawn(move || {
        // Their examples open one association each; a few spare accepts cost nothing and
        // keep the thread from ending under a client that reconnects.
        for _ in 0..8 {
            if server.accept_one().is_err() {
                return;
            }
        }
    });
    (addr, handle, joined)
}

/// Run one of their tools to completion and return its standard output.
fn run(root: &Path, rel: &str, args: &[&str]) -> String {
    let path = root.join(rel);
    let out = Command::new(&path).args(args).output().unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Start one of their servers on a free port and wait for it to accept.
///
/// The child is handed straight into a [`Reaped`], which is what waits on it.
#[allow(clippy::zombie_processes)]
fn spawn_server(root: &Path, rel: &str, dir: &str) -> (Child, String) {
    // Their examples take the port as `argv[1]` and bind every interface, so a free one has
    // to be chosen here rather than asked for afterwards.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("pick a port");
        let p = l.local_addr().expect("addr").port();
        drop(l);
        p
    };
    let child = Command::new(root.join(rel))
        .arg(port.to_string())
        .current_dir(root.join(dir))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("{rel}: {e}"));
    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(&addr).is_ok() {
            return (child, addr);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{rel} never started listening on {addr}");
}

/// A child that is killed when the test ends, however it ends.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// **Their client, our server**: browse, read and type discovery over libiec61850's own model.
///
/// `mms_utility` is the model-agnostic half of their client — `GetNameList`,
/// `GetVariableAccessAttributes`, `Read` — and it is what proves the namespace this server
/// derives from an SCL file is the one an outside client expects: flattened, sorted, and
/// answering to `LN$FC$DO$DA`.
#[test]
fn libiec61850_browses_and_reads_this_server() {
    let Some(root) = libiec61850() else { return };
    let (addr, _handle, _joined) = serve(&model(&root, "examples/server_example_threadless/simpleIO_direct_control.cid"));
    let (host, port) = addr.split_once(':').expect("host:port");

    let identity = run(&root, "examples/mms_utility/mms_utility", &["-h", host, "-p", port, "-i"]);
    assert!(identity.contains("vendor:"), "their client could not identify this server: {identity}");

    let domains = run(&root, "examples/mms_utility/mms_utility", &["-h", host, "-p", port, "-d"]);
    assert!(domains.contains("simpleIOGenericIO"), "the logical device is the MMS domain: {domains}");

    let names = run(&root, "examples/mms_utility/mms_utility", &["-h", host, "-p", port, "-t", "simpleIOGenericIO"]);
    for expected in ["GGIO1$MX$AnIn1$mag$f", "GGIO1$CO$SPCSO1$Oper$ctlVal", "LLN0$RP$EventsRCB01$RptEna"] {
        assert!(names.contains(expected), "`{expected}` missing from the browse: {names}");
    }

    // A structured read, through their decoder. `AnIn1` is the case that used to fail: its
    // `mag$f` is a `floating-point`, and its *type* was encoded with the wrong tags.
    let read = run(&root, "examples/mms_utility/mms_utility", &["-h", host, "-p", port, "-a", "simpleIOGenericIO", "-r", "GGIO1$MX$AnIn1"]);
    assert!(read.contains("Read SUCCESS"), "their client could not read a measurand: {read}");
}

/// **Their client, our server**: all four control models, including the terminations.
///
/// `client_example_control` is written against `simpleIO_control_tests.cid`, which engineers
/// `SPCSO1` direct-normal, `SPCSO2` SBO-normal, `SPCSO3` direct-enhanced and `SPCSO4`
/// SBO-enhanced — the whole of IEC 61850-7-2 §20 in one file. It reports a select that fails
/// and an operate that fails by name, so a refusal cannot pass as a success.
#[test]
fn libiec61850_operates_all_four_control_models_on_this_server() {
    let Some(root) = libiec61850() else { return };
    let (addr, handle, _joined) = serve(&model(&root, "tools/model_generator_dotnet/Tools/ICDFiles/simpleIO_control_tests.cid"));
    let (host, port) = addr.split_once(':').expect("host:port");

    let out = run(&root, "examples/iec61850_client_example_control/client_example_control", &[host, port]);
    for object in ["SPCSO1", "SPCSO2", "SPCSO3", "SPCSO4"] {
        assert!(out.contains(&format!("{object} operated successfully")), "{object} did not operate: {out}");
    }
    assert!(!out.contains("failed to select"), "a select was refused: {out}");
    // Three of the five objects the example drives are enhanced-security, and each owes a
    // `CommandTermination+`. The example installs a handler only for those three.
    assert_eq!(out.matches("Received CommandTermination+.").count(), 3, "one termination per enhanced-security command: {out}");
    // And the switchgear actually moved, which is the half a printout cannot prove.
    assert_eq!(handle.read("simpleIOGenericIO/GGIO1$ST$SPCSO1$stVal").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(handle.read("simpleIOGenericIO/GGIO1$ST$SPCSO4$stVal").and_then(|v| v.as_bool()), Some(true));
}

/// **Their client, our server**: enable a report control block and take the reports.
///
/// `client_example1` writes `TrgOps`, `IntgPd` and `RptEna` in one `SetRCBValues`, asks for a
/// general interrogation and then listens. What it proves is the *sequence*: that a client
/// nobody here wrote is happy with the order this server answers in, and that its decoder
/// agrees about `OptFlds`, the inclusion bit string and the reason codes.
#[test]
fn libiec61850_takes_reports_from_this_server() {
    let Some(root) = libiec61850() else { return };
    let (addr, _handle, _joined) = serve(&model(&root, "examples/server_example_threadless/simpleIO_direct_control.cid"));
    let (host, port) = addr.split_once(':').expect("host:port");

    // Their client listens for a minute and then disables the block, so this is the slow
    // test of the suite. It is run to *completion* rather than cut short: a C program writing
    // to a pipe buffers its output in blocks and flushes it at exit, so a client killed early
    // says nothing at all — which is exactly what a green-looking empty assertion would be.
    let mut child = Reaped(
        Command::new(root.join("examples/iec61850_client_example1/client_example1"))
            .args([host, port])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start their reporting client"),
    );
    let mut stdout = child.0.stdout.take().expect("piped");
    let text = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match child.0.try_wait() {
            Ok(Some(_)) | Err(_) => break,
            Ok(None) if Instant::now() >= deadline => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    drop(child);
    let out = text.join().unwrap_or_default();

    assert!(out.contains("Connected"), "their client did not associate: {out}");
    assert!(out.contains("received report for simpleIOGenericIO/LLN0.RP.EventsRCB01"), "no report arrived: {out}");
    // Reason 16 is a general interrogation and 8 an integrity scan; both have to be
    // recognisable, because a client acts on the difference.
    assert!(out.contains("included for reason 16"), "the general interrogation was not reported as one: {out}");
    assert!(out.contains("included for reason 8"), "no integrity report arrived: {out}");
}

/// **Both directions, arrays**: the one place where the MMS namespace stops and a client has to
/// name a *part* of a variable instead of a name of its own.
///
/// `mms_utility -y <index>` is the precise half of their client for this, because it prints the
/// value it got rather than only whether the call returned — so "it answered" and "it answered
/// *this*" are different assertions.
#[test]
fn an_array_element_is_read_as_one_element_in_both_directions() {
    let Some(root) = libiec61850() else { return };

    // Their client, our server, over their own harmonics model.
    let (addr, handle, _joined) = serve(&model(&root, "examples/server_example_complex_array/mhai_array.cid"));
    let (host, port) = addr.split_once(':').expect("host:port");
    // One element told apart from the other fifteen, so "it answered" and "it answered *this*"
    // are different assertions.
    handle.txn().set("testComplexArray/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f", Value::Float32(12.5)).commit();

    let args = ["-h", host, "-p", port, "-a", "testComplexArray", "-r", "MHAI1$MX$HA$phsAHar"];
    let whole = run(&root, "examples/mms_utility/mms_utility", &args);
    let element = run(&root, "examples/mms_utility/mms_utility", &[&args[..], &["-y", "2"]].concat());
    let component = run(&root, "examples/mms_utility/mms_utility", &[&args[..], &["-y", "2", "-c", "cVal"]].concat());
    for (what, out) in [("the array", &whole), ("one element", &element), ("one component", &component)] {
        assert!(out.contains("Read SUCCESS"), "{what}: {out}");
    }
    // Each element ends in a timestamp, so counting them counts elements: sixteen for the
    // array and exactly one for the element — which is the assertion the old server failed.
    assert!(whole.matches('Z').count() >= 16, "the whole array is sixteen elements: {whole}");
    assert_eq!(element.matches('Z').count(), 1, "an index reads one element: {element}");
    assert!(element.contains("12.5"), "…and the one that was asked for: {element}");
    assert!(!component.contains('Z'), "a component of an element is smaller still: {component}");

    // Our client, their server, over the same model — the direction that needs the encoder.
    let (child, addr) = spawn_server(&root, "examples/server_example_complex_array/server_example_ca", "examples/server_example_complex_array");
    let _reaped = Reaped(child);
    let mut c = Client::connect(&addr).expect("associate");

    let spec = c.variable_type("testComplexArray/MHAI1$MX$HA", Fc::MX).expect("GetVariableAccessAttributes");
    assert!(
        matches!(spec.component("phsAHar"), Some(iec61850_rs::proto::mms::typespec::TypeSpec::Array { elements: 16, .. })),
        "their type says sixteen: {spec:?}"
    );
    let whole = c.read("testComplexArray/MHAI1$MX$HA$phsAHar", Fc::MX).expect("the whole array");
    assert!(matches!(&whole, Value::Array(e) if e.len() == 16), "{whole:?}");
    // The four references their own array example reads, at four depths.
    let leaf = c.read("testComplexArray/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f", Fc::MX).expect("one float");
    assert!(leaf.as_f64().is_some(), "{leaf:?}");
    assert_eq!(c.read("testComplexArray/MHAI1$MX$HA$phsAHar(2)$cVal$mag", Fc::MX).expect("read").members().map(<[Value]>::len), Some(1));
    assert_eq!(c.read("testComplexArray/MHAI1$MX$HA$phsAHar(2)$cVal", Fc::MX).expect("read").members().map(<[Value]>::len), Some(2));
    assert_eq!(c.read("testComplexArray/MHAI1$MX$HA$phsAHar(2)", Fc::MX).expect("read").members().map(<[Value]>::len), Some(3));
    // …and it is the element that was named: theirs ramps, so element 2 and element 3 differ.
    let other = c.read("testComplexArray/MHAI1$MX$HA$phsAHar(3)$cVal$mag$f", Fc::MX).expect("read");
    assert_ne!(leaf.as_f64(), other.as_f64(), "two indices, two values");
    c.release().expect("orderly release");
}

/// **Our client, their server**: everything the client offers, against a stack it did not
/// write.
///
/// One test rather than five: their server takes a second to start and there is nothing to
/// isolate between the services — a failure names the service it was in.
#[test]
fn this_client_drives_a_libiec61850_server() {
    let Some(root) = libiec61850() else { return };
    let (child, addr) = spawn_server(&root, "examples/server_example_basic_io/server_example_basic_io", "examples/server_example_basic_io");
    let _reaped = Reaped(child);
    let mut c = Client::connect(&addr).expect("associate with libiec61850");

    let identity = c.identify().expect("Identify");
    assert_eq!(identity.vendor, "MZ", "{identity:?}");

    // `Status` is the round trip that needs no model, which is why `is_alive` uses it.
    assert!(c.is_alive(), "Status");

    let devices = c.server_directory().expect("GetServerDirectory");
    assert!(devices.iter().any(|d| d == "simpleIOGenericIO"), "{devices:?}");
    let names = c.logical_device_directory("simpleIOGenericIO").expect("GetLogicalDeviceDirectory");
    assert!(names.len() > 50, "a real namespace is more than a handful of names: {}", names.len());
    assert!(names.iter().any(|n| n == "GGIO1$MX$AnIn1$mag$f"), "the flattened name is what both ends browse by");

    // A measurand: a structure with a float in it, read through this decoder.
    let value = c.read("simpleIOGenericIO/GGIO1$MX$AnIn1", Fc::MX).expect("Read");
    assert!(value.members().is_some_and(|m| m.len() >= 2), "a measurand is a structure: {value:?}");

    // …and its *shape*, which is the service the wrong `floating-point` tags used to hang.
    let spec = c.variable_type("simpleIOGenericIO/GGIO1$MX$AnIn1", Fc::MX).expect("GetVariableAccessAttributes");
    assert_eq!(spec.component_names(), ["mag", "q", "t"], "{spec:?}");
    assert!(spec.component("mag").and_then(|m| m.component("f")).is_some(), "the float is where the type says it is");

    // A data set, and the report control block that carries it.
    let sets = c.data_set_directory("simpleIOGenericIO").expect("GetDataSetDirectory");
    assert!(sets.iter().any(|s| s == "LLN0$Events"), "{sets:?}");
    let members = c.data_set_members("simpleIOGenericIO", "LLN0$Events").expect("GetNamedVariableListAttributes");
    assert!(!members.is_empty(), "their data set has members");
    let rcb = c
        .enable_rcb("simpleIOGenericIO/LLN0$RP$EventsRCB01", Fc::RP, &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS))
        .expect("SetURCBValues");
    assert_eq!(rcb.data_set.as_deref(), Some("simpleIOGenericIO/LLN0$Events"));
    c.general_interrogation("simpleIOGenericIO/LLN0$RP$EventsRCB01", Fc::RP).expect("GI");
    let report = c.next_report(Duration::from_secs(10)).expect("poll").expect("a general interrogation answers with a report");
    assert_eq!(report.entries.len(), report.data_set_len(), "a GI reports every member");

    // A control, with the model read off the server rather than assumed.
    assert_eq!(c.read_control_model("simpleIOGenericIO/GGIO1.SPCSO1").expect("ctlModel"), ControlModel::DirectNormal);
    c.control("simpleIOGenericIO/GGIO1.SPCSO1").execute(&Value::Boolean(true)).expect("Operate");
    assert_eq!(c.read("simpleIOGenericIO/GGIO1$ST$SPCSO1$stVal", Fc::ST).expect("Read").as_bool(), Some(true));

    c.release().expect("orderly release");
}

/// **Our client, their server**: the log services, which is where the two stacks disagree
/// about a *name* and about how much of a range a query has to carry.
#[test]
fn this_client_reads_a_log_out_of_a_libiec61850_server() {
    let Some(root) = libiec61850() else { return };
    let (child, addr) = spawn_server(&root, "examples/server_example_logging/server_example_logging", "examples/server_example_logging");
    let _reaped = Reaped(child);
    // The example writes one entry a second; one is enough.
    std::thread::sleep(Duration::from_secs(2));
    let mut c = Client::connect(&addr).expect("associate");

    // IEC 61850-7-2 names the buffer cursor `OldEnt`/`NewEnt`; libiec61850 publishes
    // `OldEntr`/`NewEntr`. Both are asked for, so `Lcb::oldest` — which is the resume point —
    // is answered either way.
    let lcb = c.read_lcb("simpleIOGenericIO/LLN0$LG$EventLog", Fc::LG).expect("GetLCBValues");
    assert_eq!(lcb.log_ref.as_deref(), Some("simpleIOGenericIO/LLN0$EventLog"));
    let (_, oldest) = lcb.oldest().expect("the buffer cursor, under whichever name this server spells it");

    // `QueryLogByTime` with no upper bound is legal ISO 9506 and is refused by the field:
    // the ACSI service is a range, so the client sends one.
    let page = c.query_log_by_time("simpleIOGenericIO/LLN0$EventLog", oldest, None).expect("QueryLogByTime");
    assert!(!page.entries.is_empty(), "their server logs an entry a second");
    let entry = &page.entries[0];
    assert!(!entry.variables.is_empty(), "an entry carries the data attribute that changed");

    // …and the other query, from the resume point the first one gave.
    let (id, at) = entry.resume_point();
    let after = c.query_log_after_entry("simpleIOGenericIO/LLN0$EventLog", &id, at).expect("QueryLogAfterEntry");
    assert!(after.entries.iter().all(|e| e.entry_id != id), "a resume starts *after* the entry it names");

    c.release().expect("orderly release");
}
