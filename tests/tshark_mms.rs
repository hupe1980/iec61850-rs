//! Wireshark as the oracle for the **station bus**, which is where it was missing.
//!
//! The process-bus oracle (`tshark_oracle.rs`) has checked GOOSE and SV frames from the
//! start; the MMS side had nothing, and the two halves of this crate agreeing with each
//! other is exactly the evidence the notes say is worth nothing (README rule 10). So this
//! runs the real client against the real server through a recording proxy, writes the byte
//! stream as a TCP capture and asks `tshark` what it is.
//!
//! It found a real defect on its first run: `FileDirectory`'s `listOfDirectoryEntry [0]` is
//! **not** implicitly tagged, so the entries live inside an inner `SEQUENCE` — both halves
//! of this crate had it wrong in the same way and therefore agreed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_rs::Fc;
use iec61850_rs::client::Client;
use iec61850_rs::client::RcbSettings;
use iec61850_rs::common::EntryTime;
use iec61850_rs::proto::data::{Dbpos, Value};
use iec61850_rs::server::{DirectoryStore, Ied, Server, ServerHandle};

/// The model of `tests/mms_server.rs`, kept here verbatim so this test is readable on its
/// own: one logical device with a mode, a measurement, a trip, a breaker, a report control
/// block, a log and four setting groups.
const RELAY: &str = include_str!("fixtures/relay.icd");

/// Everything one association exchanged, in wire order.
type Recording = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

/// A TCP relay in front of `target` that records every byte in both directions.
///
/// A capture is what the oracle needs and there is no hook inside the socket; a proxy keeps
/// the client and the server exactly as they ship.
fn recording_proxy(target: String) -> (String, Recording) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let addr = listener.local_addr().expect("addr").to_string();
    let log: Recording = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    std::thread::spawn(move || {
        let Ok((client, _)) = listener.accept() else { return };
        let Ok(server) = TcpStream::connect(&target) else { return };
        let up = copy(client.try_clone().expect("clone"), server.try_clone().expect("clone"), true, Arc::clone(&sink));
        let down = copy(server, client, false, sink);
        let _ = up.join();
        let _ = down.join();
    });
    (addr, log)
}

fn copy(mut from: TcpStream, mut to: TcpStream, to_server: bool, log: Recording) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut l) = log.lock() {
                        l.push((to_server, buf[..n].to_vec()));
                    }
                    if to.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to.shutdown(std::net::Shutdown::Both);
    })
}

/// Start the server, put a file store behind it and return the proxy's address.
fn spawn() -> (String, Recording, ServerHandle, std::path::PathBuf) {
    let ied = Ied::from_scl(RELAY, Some("IED1")).expect("load the model");
    let mut server = Server::bind("127.0.0.1:0", ied).expect("bind");
    let files = std::env::temp_dir().join(format!("iec61850-oracle-files-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&files);
    std::fs::create_dir_all(files.join("COMTRADE")).expect("create");
    std::fs::write(files.join("COMTRADE/rec0001.cfg"), b"STATION,IED1,2013\n").expect("write");
    server.set_file_store(Box::new(DirectoryStore::new(&files)));
    let addr = server.local_addr().expect("addr").to_string();
    let handle = server.handle();
    std::thread::spawn(move || {
        let _ = server.accept_one();
    });
    let (proxy, log) = recording_proxy(addr);
    (proxy, log, handle, files)
}

/// Dissect a recorded association and return `tshark -T json`.
///
/// The capture is named after the caller, not just the process: `cargo test` runs the tests in
/// this file on threads of **one** process, so a shared file name is two tests dissecting each
/// other's bytes — which looks exactly like an encoding defect and is not one.
fn dissect(name: &str, packets: &[(bool, Vec<u8>)]) -> String {
    let tshark = common::tshark().expect("tshark present");
    let dir = std::env::temp_dir().join(format!("iec61850-rs-mms-oracle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pcap = dir.join(format!("{name}.pcap"));
    common::write_pcap_tcp(&pcap, packets);
    let out = std::process::Command::new(tshark).args(["-r"]).arg(&pcap).args(["-T", "json"]).output().expect("run tshark");
    assert!(out.status.success(), "tshark failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// One association exercising every service the server implements, dissected by Wireshark.
///
/// The assertions are deliberately about *Wireshark's* names for things: `mms.confirmed_2`
/// is what its dissector calls a confirmed response, and a field it can name is a field we
/// encoded where the ASN.1 says it goes.
#[test]
fn the_whole_station_bus_dissects_as_what_we_put_in() {
    if common::tshark().is_none() {
        return;
    }
    let (addr, log, handle, files) = spawn();
    exercise(&addr, &handle);
    // The proxy threads may still be draining the last packet.
    std::thread::sleep(Duration::from_millis(200));
    let packets = log.lock().expect("lock").clone();
    let _ = std::fs::remove_dir_all(&files);
    assert!(packets.len() > 10, "the association exchanged only {} packets", packets.len());

    let text = dissect("whole-station-bus", &packets);
    assert!(text.trim_start().starts_with('['), "tshark -T json output must be a JSON array");
    // Wireshark marks anything it cannot frame; a station-bus stack that produces one has
    // produced a PDU no third party can read.
    assert!(!text.contains("_ws.malformed"), "malformed PDU in the capture:\n{text}");
    assert!(!text.contains("\"_ws.expert.severity\": \"Error\""), "expert error in the capture:\n{text}");
    // Every layer under MMS has to be there, or the dissector never reached MMS at all.
    for layer in ["tpkt", "cotp", "ses", "pres", "acse", "mms"] {
        assert!(text.contains(&format!("\"{layer}\":")), "no {layer} layer in the capture:\n{text}");
    }
    // The services the exercise ran, by the names Wireshark gives them.
    for needle in [
        "\"mms.initiate_RequestPDU_element\"",
        "\"mms.initiate_ResponsePDU_element\"",
        "\"mms.confirmed_RequestPDU_element\"",
        "\"mms.confirmed_ResponsePDU_element\"",
        "\"mms.unconfirmed_PDU_element\"",
        "\"mms.getNameList_element\"",
        "\"mms.identify_element\"",
        "\"mms.status_element\"",
        "\"mms.getCapabilityList_element\"",
        "\"mms.read_element\"",
        "\"mms.write_element\"",
        "\"mms.getVariableAccessAttributes_element\"",
        "\"mms.defineNamedVariableList_element\"",
        "\"mms.deleteNamedVariableList_element\"",
        "\"mms.fileDirectory_element\"",
        "\"mms.fileOpen_element\"",
        "\"mms.fileRead_element\"",
        "\"mms.readJournal_element\"",
        "\"mms.informationReport_element\"",
    ] {
        assert!(text.contains(needle), "Wireshark never saw {needle}");
    }
    // …and the values, so that "it dissects" is not "it dissects as something else".
    for needle in [
        "\"mms.vendorName\": \"hupe1980\"",
        // `Status` and `GetCapabilityList` are new encodings that only this crate reads, so
        // they get the oracle before they get a user (D38).
        "\"mms.vmdLogicalStatus\": \"0\"",
        "\"mms.vmdPhysicalStatus\": \"0\"",
        "\"mms.listOfCapabilities_item\": \"IEC 61850-8-1:2011+AMD1:2020\"",
        "\"mms.modelName\": \"iec61850-rs\"",
        "\"mms.domainId\": \"IED1LD0\"",
        "\"mms.Identifier\": \"LLN0$ST$Mod$stVal\"",
        "\"mms.objectName_domain_specific_itemId\": \"LLN0$dsTrip\"",
        "\"mms.FileName_item\": \"COMTRADE/rec0001.cfg\"",
        "\"mms.sizeOfFile\": \"18\"",
        // A log entry, with the `originatingApplication` its SEQUENCE requires.
        "\"mms.originatingApplication_element\"",
        "\"mms.variableTag\": \"IED1LD0/PTRC1$ST$Tr$general\"",
        // A report is an `InformationReport` on the VMD-specific name `RPT`.
        "\"mms.vmd_specific\": \"RPT\"",
    ] {
        assert!(text.contains(needle), "missing {needle} in the dissection");
    }
}

/// The two report shapes a third party is the only honest reader of.
///
/// A data set of **FCDs** reports each member as the structure it is, and a report longer than
/// the negotiated PDU is split into segments. Both are encodings this crate's client is
/// otherwise the only reader of, which is precisely the case rule 10 says proves nothing — so
/// Wireshark reads them here.
/// An `alternateAccess` — the one part of a `Read` that has no name of its own.
///
/// A dissector is the only third party that can say the two tag sets are the right way round:
/// a selection with more steps after it is tagged `[0]`–`[3]` and the last one `[1]`–`[4]`, so
/// getting them backwards produces octets that decode *here* and nowhere else. Wireshark's MMS
/// module models `AlternateAccess` in full, which is what makes this checkable.
#[test]
fn an_array_element_read_dissects_as_the_element_it_names() {
    if common::tshark().is_none() {
        return;
    }
    let ied = Ied::from_scl(include_str!("fixtures/array.icd"), Some("IED1")).expect("load the model");
    let server = Server::bind("127.0.0.1:0", ied).expect("bind");
    let target = server.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        let _ = server.accept_one();
    });
    let (addr, log) = recording_proxy(target);

    let mut c = Client::connect(&addr).expect("associate");
    // Four depths, which is what puts both tag sets on the wire: a one-step selection is the
    // last-step form alone, and everything longer nests the other one inside it.
    for reference in [
        "IED1LD0/MHAI1$MX$HA$phsAHar(2)",
        "IED1LD0/MHAI1$MX$HA$phsAHar(2)$cVal",
        "IED1LD0/MHAI1$MX$HA$phsAHar(2)$cVal$mag",
        "IED1LD0/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f",
    ] {
        c.read(reference, Fc::MX).unwrap_or_else(|e| panic!("{reference}: {e}"));
    }
    c.release().expect("release");

    std::thread::sleep(Duration::from_millis(200));
    let packets = log.lock().expect("lock").clone();
    let text = dissect("alternate-access", &packets);
    assert!(!text.contains("_ws.malformed"), "malformed PDU in the capture:\n{text}");
    assert!(!text.contains("\"_ws.expert.severity\": \"Error\""), "expert error in the capture:\n{text}");
    // The element is named, and the selection dissects as a selection rather than as a name.
    // The *name* stops at the array — four reads, one variable — and the difference between
    // them is entirely in the selection beside it.
    assert!(text.contains("\"mms.objectName_domain_specific_itemId\": \"MHAI1$MX$HA$phsAHar\""), "the array's own name is the variable:\n{text}");
    assert!(text.contains("\"mms.alternateAccess\""), "no alternateAccess in the capture:\n{text}");
    // `accessSelection` is the field that exists **only** inside `selectAlternateAccess`, so
    // it is what says the nested form was used for the steps that have more after them.
    assert!(text.contains("\"mms.accessSelection\""), "the nested form is missing:\n{text}");
    assert!(text.contains("\"mms.index\": \"2\""), "the index we asked for:\n{text}");
    for component in ["cVal", "mag", "f"] {
        assert!(text.contains(&format!("\"mms.component\": \"{component}\"")), "component {component} missing:\n{text}");
    }
}

#[test]
fn segmented_and_structured_reports_dissect_as_what_we_put_in() {
    if common::tshark().is_none() {
        return;
    }
    let ied = Ied::from_scl(include_str!("fixtures/fcd.icd"), Some("IED1")).expect("load the model");
    let server = Server::bind("127.0.0.1:0", ied).expect("bind");
    let target = server.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        let _ = server.accept_one();
    });
    let (addr, log) = recording_proxy(target);

    // A small client, so the twelve-member interrogation cannot fit one PDU.
    let mut cfg = iec61850_rs::client::ClientConfig::default();
    cfg.association.max_pdu = 900;
    let mut c = Client::connect_with(&addr, &cfg).expect("associate");
    let settings = RcbSettings::new().with_useful_fields();
    c.enable_rcb("IED1LD0/LLN0$RP$wide", Fc::RP, &settings).expect("enable rcb");
    c.general_interrogation("IED1LD0/LLN0$RP$wide", Fc::RP).expect("gi");
    let whole = c.next_report(Duration::from_secs(2)).expect("poll").expect("a report");
    assert_eq!(whole.entries.len(), 12);
    assert!(c.report_assembler_stats().reassembled >= 1, "the report was segmented");
    c.release().expect("release");

    std::thread::sleep(Duration::from_millis(200));
    let packets = log.lock().expect("lock").clone();
    let text = dissect("segmented-reports", &packets);
    assert!(!text.contains("_ws.malformed"), "malformed PDU in the capture:\n{text}");
    assert!(!text.contains("\"_ws.expert.severity\": \"Error\""), "expert error in the capture:\n{text}");
    // Several information reports for one interrogation is what segmentation looks like on
    // the wire, and each of them has to be a well-formed report on its own.
    let reports = text.matches("\"mms.informationReport_element\"").count();
    assert!(reports > 1, "one interrogation produced {reports} report PDU(s); segmentation never happened");
    assert!(text.contains("\"mms.vmd_specific\": \"RPT\""));
    // A member that names a data object is carried as the structure it is, not as its
    // attributes flattened out beside each other.
    assert!(text.contains("\"mms.structure_tree\""), "an FCD member was not reported as a structure");
    // …and the structure really is the WYE the file declares, not an empty one.
    assert!(text.contains("\"mms.floating_point\"") && text.contains("\"mms.utc_time\""), "the structure's own members did not dissect");
}

/// Drive one client through every service the server answers.
fn exercise(addr: &str, handle: &ServerHandle) {
    let mut c = Client::connect(addr).expect("associate");

    c.identify().expect("identify");
    // The two services below the model: is the server healthy, and what does it claim?
    c.status(false).expect("status");
    c.capabilities().expect("capabilities");
    let lds = c.server_directory().expect("server directory");
    assert_eq!(lds, ["IED1LD0"]);
    c.logical_device_directory("IED1LD0").expect("ld directory");
    c.data_set_directory("IED1LD0").expect("data set directory");
    c.log_directory("IED1LD0").expect("log directory");
    c.data_set_members("IED1LD0", "LLN0$dsTrip").expect("data set members");

    c.read("IED1LD0/LLN0.Mod.stVal", Fc::ST).expect("read");
    c.read_many(&[("IED1LD0/LLN0.Mod.stVal", Fc::ST), ("IED1LD0/MMXU1.TotW.mag.f", Fc::MX)]).expect("read many");
    c.read_data_set("IED1LD0", "LLN0$dsTrip").expect("read data set");
    c.variable_type("IED1LD0/CSWI1.Pos.Oper", Fc::CO).expect("variable type");

    // A write the model allows: a configuration attribute, not a status one.
    c.write("IED1LD0/LLN0.Mod.ctlModel", Fc::CF, &Value::Integer(1)).ok();

    c.create_data_set("IED1LD0/LLN0$dsAd", &[("IED1LD0/LLN0.Mod.stVal", Fc::ST)]).expect("create data set");
    c.delete_data_set("IED1LD0/LLN0$dsAd").expect("delete data set");

    // A report control block, enabled, and a change that makes it report.
    let settings = RcbSettings::new().with_useful_fields();
    c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &settings).expect("enable rcb");
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
    let _ = c.next_report(Duration::from_millis(500));
    c.general_interrogation("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("gi");
    let _ = c.next_report(Duration::from_millis(500));
    c.disable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("disable rcb");

    // A control, which is a write of a structure under `CO`.
    c.control("IED1LD0/CSWI1.Pos").execute(&Value::dbpos(Dbpos::On)).expect("operate");

    // A log query and the log control block behind it.
    c.read_lcb("IED1LD0/LLN0$LG$lcb01", Fc::LG).expect("read lcb");
    c.query_log_by_time("IED1LD0/LLN0$GeneralLog", EntryTime::default(), None).expect("query log");

    // Setting groups.
    c.read_sgcb("IED1LD0/LLN0$SP$SGCB").expect("read sgcb");
    c.select_active_setting_group("IED1LD0/LLN0$SP$SGCB", 2).expect("select active group");

    // Files.
    let listing = c.file_directory(None).expect("file directory");
    assert!(listing.iter().any(|f| f.name == "COMTRADE/rec0001.cfg"), "the store lists {listing:?}");
    let body = c.read_file("COMTRADE/rec0001.cfg", 4096).expect("read file");
    assert_eq!(body, b"STATION,IED1,2013\n");

    c.release().expect("release");
}
