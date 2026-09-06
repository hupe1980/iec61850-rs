//! The library's client against the library's server, over a loopback socket.
//!
//! The client tests in `mms_client.rs` run against a hand-written test peer with canned
//! answers — enough to prove the socket half of the client, and nothing at all about a
//! server. This runs the real thing: an SCL file loaded into a real model, browsed, read,
//! written and reported over a real association. If the namespace the server publishes and
//! the references the client builds ever disagree, this is where it shows.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::time::Duration;

use iec61850_rs::Fc;
use iec61850_rs::client::Client;
use iec61850_rs::proto::data::{Typed, Value};
use iec61850_rs::server::{Ied, Server, ServerHandle};

/// A relay with one logical device: a mode, a measurement, a trip and a breaker.
pub const RELAY: &str = include_str!("fixtures/relay.icd");

/// Start a server on a loopback port, accepting `clients` associations.
fn spawn(clients: usize) -> (String, ServerHandle) {
    let ied = Ied::from_scl(RELAY, Some("IED1")).expect("load the model");
    let server = Server::bind("127.0.0.1:0", ied).expect("bind");
    let addr = server.local_addr().expect("addr").to_string();
    let handle = server.handle();
    std::thread::spawn(move || {
        for _ in 0..clients {
            if server.accept_one().is_err() {
                return;
            }
        }
    });
    (addr, handle)
}

#[test]
fn a_client_browses_the_namespace_the_scl_file_describes() {
    let (addr, _h) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");

    assert_eq!(c.identify().unwrap().model, "iec61850-rs");
    assert_eq!(c.server_directory().unwrap(), ["IED1LD0"], "MMS domains are logical devices");

    let names = c.logical_device_directory("IED1LD0").unwrap();
    // The logical node names are the ones with no separator — which is exactly how
    // libiec61850's client tells them apart, and it only works because the server publishes
    // the flattened namespace with the bare names in it.
    let lns: Vec<&String> = names.iter().filter(|n| !n.contains('$')).collect();
    assert_eq!(lns, ["CSWI1", "LLN0", "MMXU1", "PTRC1"]);
    // …and every level below them is a name of its own.
    for expected in ["PTRC1$ST", "PTRC1$ST$Tr", "PTRC1$ST$Tr$general", "MMXU1$MX$TotW$mag$f", "CSWI1$CO$Pos$Oper$ctlVal", "LLN0$RP$urcb$RptEna"] {
        assert!(names.iter().any(|n| n == expected), "`{expected}` missing");
    }
    // Sorted, because `continueAfter` paging is an exact match on this order.
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);

    assert_eq!(c.data_set_directory("IED1LD0").unwrap(), ["LLN0$dsTrip"]);
    assert_eq!(c.data_set_members("IED1LD0", "LLN0$dsTrip").unwrap(), ["IED1LD0/PTRC1$ST$Tr$general", "IED1LD0/PTRC1$ST$Tr$q"]);
    c.release().unwrap();
}

#[test]
fn a_read_and_a_write_go_through_the_model() {
    let (addr, handle) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");

    // A leaf, engineered in the file: the instance value wins over the type template.
    assert_eq!(c.read("IED1LD0/CSWI1.Pos.ctlModel", Fc::CF).unwrap().as_i64(), Some(1));
    assert_eq!(c.read_control_model("IED1LD0/CSWI1.Pos").unwrap(), iec61850_rs::client::ControlModel::DirectNormal);

    // A structure is assembled from its components in model order.
    let mag = c.read("IED1LD0/MMXU1.TotW.mag", Fc::MX).unwrap();
    assert_eq!(mag.members().map(<[Value]>::len), Some(1));

    // A write a client is allowed to make: a configuration attribute under `CF`.
    c.write("IED1LD0/CSWI1.Pos.ctlModel", Fc::CF, &Value::Integer(1)).unwrap();
    assert_eq!(handle.read("IED1LD0/CSWI1$CF$Pos$ctlModel").and_then(|v| v.as_i64()), Some(1));

    // Status information is **not** one of them (IEC 61850-7-2 §5.7): `ST` is what the
    // process reports, and a server that lets a client write it lets one fake a trip.
    assert!(
        matches!(c.write("IED1LD0/PTRC1.Tr.general", Fc::ST, &Value::Boolean(true)), Err(iec61850_rs::Error::DataAccess(3))),
        "a client must not be able to write a status attribute"
    );
    assert!(matches!(c.write("IED1LD0/MMXU1.TotW.mag.f", Fc::MX, &Value::Float32(1.0)), Err(iec61850_rs::Error::DataAccess(3))));
    // The application behind the server is the one that owns process data, and its update
    // is what a client sees.
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
    assert_eq!(c.read("IED1LD0/PTRC1.Tr.general", Fc::ST).unwrap().as_bool(), Some(true));
    handle.txn().set("IED1LD0/MMXU1$MX$TotW$mag$f", Value::Float32(1234.5)).commit();
    assert_eq!(c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX).unwrap().as_f64(), Some(1234.5));

    // A name the model does not have is object-non-existent, not a guess.
    assert!(matches!(c.read("IED1LD0/PTRC1.Tr.nosuch", Fc::ST), Err(iec61850_rs::Error::DataAccess(10))));
    // …and a value of the wrong type is refused rather than quietly changing the model.
    assert!(matches!(c.write("IED1LD0/CSWI1.Pos.ctlModel", Fc::CF, &Value::VisibleString("x".into())), Err(iec61850_rs::Error::DataAccess(7))));
    c.release().unwrap();
}

#[test]
fn a_data_set_is_read_created_and_deleted() {
    let (addr, _h) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");

    // Reading the data set reads its members, in order.
    let values = c.read_data_set("IED1LD0", "LLN0$dsTrip").unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].as_bool(), Some(false));
    assert!(values[1].as_quality().is_some());

    c.create_data_set("IED1LD0/LLN0$dsTemp", &[("IED1LD0/MMXU1.TotW.mag.f", Fc::MX)]).expect("create");
    assert!(c.data_set_directory("IED1LD0").unwrap().contains(&String::from("LLN0$dsTemp")));
    assert_eq!(c.read_data_set("IED1LD0", "LLN0$dsTemp").unwrap().len(), 1);
    c.delete_data_set("IED1LD0/LLN0$dsTemp").expect("delete");
    assert!(!c.data_set_directory("IED1LD0").unwrap().contains(&String::from("LLN0$dsTemp")));

    // One the file engineered is matched and refused: the difference between gone and
    // refused is the whole answer.
    assert!(matches!(c.delete_data_set("IED1LD0/LLN0$dsTrip"), Err(iec61850_rs::Error::DataAccess(3))));
    c.release().unwrap();
}

#[test]
fn the_server_answers_what_type_a_variable_is() {
    use iec61850_rs::client::TypeSpec;

    let (addr, _h) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");
    let oper = c.variable_type("IED1LD0/CSWI1.Pos.Oper", Fc::CO).expect("the Oper type");
    assert_eq!(oper.component_names(), ["ctlVal", "origin", "ctlNum", "T", "Test", "Check"]);
    assert_eq!(oper.component("ctlVal"), Some(&TypeSpec::BitString(2)), "a position is exactly two bits");
    assert_eq!(oper.component("Check"), Some(&TypeSpec::BitString(-2)), "a check is at most two");
    assert_eq!(oper.component("T"), Some(&TypeSpec::UtcTime));
    assert_eq!(oper.component("origin").map(TypeSpec::component_names), Some(vec!["orCat", "orIdent"]));
    assert_eq!(c.variable_type("IED1LD0/MMXU1.TotW.mag.f", Fc::MX).unwrap(), TypeSpec::FloatingPoint { format_width: 32, exponent_width: 8 });
    assert_eq!(c.variable_type("IED1LD0/PTRC1.Tr.q", Fc::ST).unwrap(), TypeSpec::BitString(-13));
    c.release().unwrap();
}

#[test]
fn a_browse_that_does_not_fit_one_pdu_is_paged() {
    use iec61850_rs::server::{AcsiConfig, ServerConfig};

    // A budget small enough to force several pages out of this model, so the paging is the
    // thing under test rather than an accident of the model's size.
    let cfg = ServerConfig { acsi: AcsiConfig { name_list_budget: 60, ..AcsiConfig::default() }, ..ServerConfig::default() };
    let ied = Ied::from_scl(RELAY, Some("IED1")).expect("load");
    let server = Server::bind_with("127.0.0.1:0", ied, &cfg).expect("bind");
    let addr = server.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.accept_one());

    let mut c = Client::connect(&addr).expect("associate");
    let paged = c.logical_device_directory("IED1LD0").unwrap();
    assert!(paged.len() > 20, "the model has more names than one small page: {}", paged.len());
    // Every name exactly once, still sorted: a `continueAfter` that resumes at the wrong
    // place either repeats a name or skips one, and both show here.
    let mut unique = paged.clone();
    unique.dedup();
    assert_eq!(unique, paged, "a name was repeated across pages");
    let mut sorted = paged.clone();
    sorted.sort();
    assert_eq!(paged, sorted);
    c.release().unwrap();
}

#[test]
fn two_clients_see_the_same_model() {
    let (addr, handle) = spawn(2);
    let mut a = Client::connect(&addr).expect("first");
    let mut b = Client::connect(&addr).expect("second");
    assert_eq!(handle.associations(), 2);

    a.write("IED1LD0/CSWI1.Pos.ctlModel", Fc::CF, &Value::Integer(1)).unwrap();
    assert_eq!(b.read("IED1LD0/CSWI1.Pos.ctlModel", Fc::CF).unwrap().as_i64(), Some(1));
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
    assert_eq!(b.read("IED1LD0/PTRC1.Tr.general", Fc::ST).unwrap().as_bool(), Some(true));
    a.release().unwrap();
    b.release().unwrap();
    // The slots come back when the associations end.
    for _ in 0..50 {
        if handle.associations() == 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the association slots were not released");
}

#[test]
fn a_report_control_block_is_enabled_and_reports_what_changed() {
    use iec61850_rs::client::{RcbSettings, ReasonCode, TrgOps};

    let (addr, handle) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");

    // The block as the file engineered it: the client reads it before it writes anything.
    let rcb = c.read_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("read the block");
    assert_eq!(rcb.data_set.as_deref(), Some("IED1LD0/LLN0$dsTrip"));
    assert_eq!(rcb.conf_rev, Some(3));
    assert!(!rcb.rpt_ena);
    assert_eq!(rcb.trg_ops.map(|t| (t.data_change(), t.quality_change(), t.general_interrogation())), Some((true, true, true)));
    assert!(rcb.opt_flds.is_some_and(|o| o.sequence_number() && o.report_time_stamp() && o.reason_for_inclusion()));

    let enabled = c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("enable");
    assert!(enabled.rpt_ena);

    // A change to a data-set member produces a report, and only the member that changed.
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
    let r = c.next_report(Duration::from_secs(2)).expect("poll").expect("a report");
    assert_eq!(r.rpt_id, "IED1LD0/LLN0$RP$urcb");
    assert_eq!(r.data_set.as_deref(), Some("IED1LD0/LLN0$dsTrip"));
    assert_eq!(r.data_set_len(), 2, "the data set has two members");
    assert_eq!(r.entries.len(), 1, "one of them changed");
    assert_eq!(r.entries[0].index, 0);
    assert_eq!(r.entries[0].value.as_bool(), Some(true));
    assert_eq!(r.entries[0].reason, Some(ReasonCode::NONE.with_data_change(true)));
    // `SqNum` is zeroed when the block is enabled (IEC 61850-7-2 §17.2.2), so the first
    // report of a subscription carries zero — not a number left over from the client before.
    assert_eq!(r.seq_num, Some(0));
    assert_eq!(r.conf_rev, Some(3));

    // A quality change is a *quality* change, not a data change: `TrgOps` has separate bits
    // and a client that asked for one and not the other must get what it asked for.
    handle
        .txn()
        .set("IED1LD0/PTRC1$ST$Tr$q", Value::quality(iec61850_rs::Quality { validity: iec61850_rs::Validity::Invalid, ..iec61850_rs::Quality::GOOD }))
        .commit();
    let r = c.next_report(Duration::from_secs(2)).expect("poll").expect("a second report");
    assert_eq!(r.entries.len(), 1);
    assert_eq!(r.entries[0].index, 1);
    assert_eq!(r.entries[0].reason, Some(ReasonCode::NONE.with_quality_change(true)));
    assert_eq!(r.seq_num, Some(1));

    // Writing the same value again is not a change, so nothing is reported.
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
    assert!(c.next_report(Duration::from_millis(200)).unwrap().is_none(), "an unchanged write is not a data change");

    c.disable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP).unwrap();
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(false)).commit();
    assert!(c.next_report(Duration::from_millis(200)).unwrap().is_none(), "a disabled block reports nothing");
    c.release().unwrap();
}

#[test]
fn a_general_interrogation_reports_every_member_once() {
    use iec61850_rs::client::{RcbSettings, ReasonCode, TrgOps};

    let (addr, _h) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");
    c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("enable");
    c.general_interrogation("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("GI");

    let r = c.next_report(Duration::from_secs(2)).expect("poll").expect("a GI report");
    assert_eq!(r.entries.len(), 2, "a general interrogation reports the whole data set");
    assert_eq!(r.entries.iter().map(|e| e.index).collect::<Vec<_>>(), [0, 1]);
    for e in &r.entries {
        assert_eq!(e.reason, Some(ReasonCode::NONE.with_general_interrogation(true)), "and says so");
    }
    // One write of `GI` is one report, not a stream of them.
    assert!(c.next_report(Duration::from_millis(200)).unwrap().is_none());
    c.release().unwrap();
}

#[test]
fn a_control_block_belongs_to_one_client_at_a_time() {
    use iec61850_rs::client::{RcbSettings, TrgOps};

    let (addr, _h) = spawn(2);
    let mut a = Client::connect(&addr).expect("first");
    let mut b = Client::connect(&addr).expect("second");

    a.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("the first client gets it");
    // The second client is refused rather than silently taking it over — two clients on one
    // block is how one of them stops receiving reports without being told.
    let e = b.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new()).unwrap_err();
    assert!(matches!(e, iec61850_rs::Error::DataAccess(3)), "{e:?}");

    // And once the first client lets go, the second may have it.
    a.disable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP).unwrap();
    assert!(b.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("handover").rpt_ena);
    a.release().unwrap();
    b.release().unwrap();
}

#[test]
fn a_running_block_refuses_to_be_reconfigured() {
    use iec61850_rs::client::{RcbSettings, TrgOps};

    // IEC 61850-7-2 §17.2: every setting but `RptEna`, `GI` and `PurgeBuf` is refused while
    // reporting is on. This is the rule the client's "settings first, `RptEna` last" ordering
    // exists for, and the server is the half that enforces it.
    let (addr, _h) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");
    c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("enable");
    assert!(matches!(c.write_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_buf_tm(50)), Err(iec61850_rs::Error::DataAccess(3))));

    // Enabling it again through the client works, because the client turns it off first.
    let again = c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_buf_tm(50).with_trg_ops(TrgOps::EVENTS)).expect("take it over");
    assert_eq!(again.buf_tm, Some(50));
    c.release().unwrap();
}

#[test]
fn a_gathering_window_puts_one_report_where_three_changes_happened() {
    use iec61850_rs::client::{RcbSettings, TrgOps};

    let (addr, handle) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");
    // 200 ms of `BufTm`: changes inside the window go into one report, which is what stops a
    // three-phase trip becoming three reports.
    c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS).with_buf_tm(200)).expect("enable");

    let mut txn = handle.txn();
    txn.set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true));
    txn.set("IED1LD0/PTRC1$ST$Tr$q", Value::quality(iec61850_rs::Quality { validity: iec61850_rs::Validity::Questionable, ..iec61850_rs::Quality::GOOD }));
    txn.commit();

    let r = c.next_report(Duration::from_secs(2)).expect("poll").expect("one report");
    assert_eq!(r.entries.len(), 2, "both changes in one report");
    assert!(c.next_report(Duration::from_millis(300)).unwrap().is_none(), "and not a second one");
    c.release().unwrap();
}

#[test]
fn a_buffered_block_keeps_what_happened_while_nobody_was_listening() {
    use iec61850_rs::client::{RcbSettings, TrgOps};

    // The whole difference between `BR` and `RP`: a buffered block holds its entries for the
    // client that is not there, and hands them over when it comes back.
    const BUFFERED: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="b"/>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
      <DataSet name="dsTrip"><FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/></DataSet>
      <ReportControl name="brcb" datSet="dsTrip" confRev="1" buffered="true" indexed="false" bufTime="0">
        <TrgOps dchg="true"/>
        <OptFields seqNum="true" reasonCode="true" entryID="true" bufOvfl="true"/>
      </ReportControl>
    </LN0>
    <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <DOType id="ACT_T" cdc="ACT"><DA name="general" fc="ST" bType="BOOLEAN"/></DOType>
  </DataTypeTemplates>
</SCL>"#;

    let ied = Ied::from_scl(BUFFERED, Some("IED1")).expect("load");
    let server = Server::bind("127.0.0.1:0", ied).expect("bind");
    let addr = server.local_addr().unwrap().to_string();
    let handle = server.handle();
    std::thread::spawn(move || {
        for _ in 0..2 {
            if server.accept_one().is_err() {
                return;
            }
        }
    });

    // Nobody has ever enabled it, and the model changes three times.
    for state in [true, false, true] {
        handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(state)).commit();
        std::thread::sleep(Duration::from_millis(5));
    }

    let mut c = Client::connect(&addr).expect("associate");
    c.enable_rcb("IED1LD0/LLN0$BR$brcb", Fc::BR, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("enable");

    // Enabling hands over what was buffered, oldest first, each with its own `EntryID`.
    let mut seen = Vec::new();
    while let Some(r) = c.next_report(Duration::from_millis(500)).expect("poll") {
        seen.push(r);
        if seen.len() == 3 {
            break;
        }
    }
    assert_eq!(seen.len(), 3, "the three changes that happened while nobody was listening");
    assert_eq!(seen.iter().map(|r| r.entries[0].value.as_bool()).collect::<Vec<_>>(), [Some(true), Some(false), Some(true)]);
    let ids: Vec<&Vec<u8>> = seen.iter().filter_map(|r| r.entry_id.as_ref()).collect();
    assert_eq!(ids.len(), 3, "every buffered entry carries the EntryID a client resumes after");
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "and they are in order: {ids:?}");
    assert!(seen.iter().all(|r| r.buf_ovfl != Some(true)), "nothing was lost, so nothing claims it was");
    c.release().unwrap();

    // The client goes away, two more things happen, and it comes back. It must get **those
    // two** and not the whole buffer again: the block remembers where it got to, and the
    // buffer is a ring the `EntryID` indexes into rather than a queue that empties on read.
    for state in [false, true] {
        handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(state)).commit();
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut c = Client::connect(&addr).expect("re-associate");
    c.enable_rcb("IED1LD0/LLN0$BR$brcb", Fc::BR, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("re-enable");
    let mut again = Vec::new();
    while let Some(r) = c.next_report(Duration::from_millis(300)).expect("poll") {
        again.push(r);
        if again.len() == 3 {
            break;
        }
    }
    assert_eq!(again.len(), 2, "only what happened while it was away: {again:#?}");
    assert_eq!(again.iter().map(|r| r.entries[0].value.as_bool()).collect::<Vec<_>>(), [Some(false), Some(true)]);
    assert!(again.iter().all(|r| r.buf_ovfl != Some(true)), "the resume point was still in the buffer");
    c.release().unwrap();
}

#[test]
fn a_direct_control_operates_the_object_it_names() {
    use iec61850_rs::client::{ControlModel, OriginCategory};
    use iec61850_rs::proto::data::Dbpos;

    let (addr, handle) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");

    // The model says direct-with-normal-security, and the client reads it rather than
    // guessing — one round trip that removes a whole class of "nothing happened".
    assert_eq!(c.read_control_model("IED1LD0/CSWI1.Pos").unwrap(), ControlModel::DirectNormal);
    c.control("IED1LD0/CSWI1.Pos")
        .model(ControlModel::DirectNormal)
        .origin(OriginCategory::StationControl, "hmi-1")
        .execute(&Value::dbpos(Dbpos::On))
        .expect("operate");

    // The command reached the model: the status is what was commanded.
    assert_eq!(handle.read("IED1LD0/CSWI1$ST$Pos$stVal").and_then(|v| v.as_dbpos()), Some(Dbpos::On));
    assert_eq!(c.read("IED1LD0/CSWI1.Pos.stVal", Fc::ST).unwrap().as_dbpos(), Some(Dbpos::On));
    c.release().unwrap();
}

/// The same relay with the breaker engineered select-before-operate, enhanced security.
fn sbo_relay() -> String {
    RELAY.replace("<Val>direct-with-normal-security</Val>", "<Val>sbo-with-enhanced-security</Val>").replace(
        r#"<EnumType id="CtlModel_E"><EnumVal ord="1">direct-with-normal-security</EnumVal></EnumType>"#,
        r#"<EnumType id="CtlModel_E"><EnumVal ord="1">direct-with-normal-security</EnumVal><EnumVal ord="4">sbo-with-enhanced-security</EnumVal></EnumType>"#,
    )
}

/// Every report the client has waiting, plus any that arrives within a short grace period.
fn drain_reports(c: &mut Client) -> Vec<iec61850_rs::client::Report> {
    let mut out = Vec::new();
    while let Ok(Some(r)) = c.next_report(Duration::from_millis(200)) {
        out.push(r);
    }
    out
}

/// Serve the first (and, for every fixture here, the only) IED of `xml`.
fn spawn_xml(xml: &str, clients: usize) -> (String, ServerHandle) {
    let ied = Ied::from_scl(xml, None).expect("load");
    let server = Server::bind("127.0.0.1:0", ied).expect("bind");
    let addr = server.local_addr().unwrap().to_string();
    let handle = server.handle();
    std::thread::spawn(move || {
        for _ in 0..clients {
            if server.accept_one().is_err() {
                return;
            }
        }
    });
    (addr, handle)
}

#[test]
fn select_before_operate_with_enhanced_security_runs_the_whole_sequence() {
    use iec61850_rs::client::{ControlModel, OriginCategory};
    use iec61850_rs::proto::data::Dbpos;

    let (addr, handle) = spawn_xml(&sbo_relay(), 1);
    let mut c = Client::connect(&addr).expect("associate");
    assert_eq!(c.read_control_model("IED1LD0/CSWI1.Pos").unwrap(), ControlModel::SboEnhanced);

    // `SBOw` then `Oper` then the termination — the client's `execute` does all three, and
    // the server enforces the order.
    c.control("IED1LD0/CSWI1.Pos")
        .model(ControlModel::SboEnhanced)
        .origin(OriginCategory::StationControl, "hmi-1")
        .execute(&Value::dbpos(Dbpos::On))
        .expect("select, operate and terminate");
    assert_eq!(handle.read("IED1LD0/CSWI1$ST$Pos$stVal").and_then(|v| v.as_dbpos()), Some(Dbpos::On));
    c.release().unwrap();
}

/// A caller that does not state the control model gets the **server's**, not a guess.
///
/// This is the failure libiec61850's own `server_example_control` made visible: an object
/// engineered for select-before-operate, a client that assumed direct control, and a refusal
/// (`ObjectNotSelected`) that reads exactly like a broken object 🌐. The client has always had
/// `read_control_model`; what it did not have was the habit of using it.
///
/// The reference a caller holds is usually `LN$CO$DO` — the controllable object — while
/// `ctlModel` lives under `CF`, so the lookup has to *replace* the functional constraint
/// rather than keep the one the reference carries.
#[test]
fn a_control_model_nobody_stated_is_read_off_the_server() {
    use iec61850_rs::proto::data::Dbpos;

    let (addr, handle) = spawn_xml(&sbo_relay(), 1);
    let mut c = Client::connect(&addr).expect("associate");

    // No `.model(…)`: `SBOw` ▸ `Oper` ▸ termination all the same, because the server was
    // asked. Both spellings of the object have to work — dotted, and the MMS form with the
    // `CO` constraint already in it.
    c.control("IED1LD0/CSWI1.Pos").execute(&Value::dbpos(Dbpos::On)).expect("the whole sequence");
    assert_eq!(handle.read("IED1LD0/CSWI1$ST$Pos$stVal").and_then(|v| v.as_dbpos()), Some(Dbpos::On));
    c.control("IED1LD0/CSWI1$CO$Pos").execute(&Value::dbpos(Dbpos::Off)).expect("the whole sequence, from the MMS form");
    assert_eq!(handle.read("IED1LD0/CSWI1$ST$Pos$stVal").and_then(|v| v.as_dbpos()), Some(Dbpos::Off));
    c.release().unwrap();
}

#[test]
fn an_operate_without_a_select_is_refused_with_a_reason() {
    use iec61850_rs::client::{AddCause, ControlModel};
    use iec61850_rs::proto::data::Dbpos;

    let (addr, handle) = spawn_xml(&sbo_relay(), 1);
    let mut c = Client::connect(&addr).expect("associate");

    // Operating a select-before-operate object without selecting it first is the classic
    // "nothing happened and nothing said so". The server says which.
    let e = c.control("IED1LD0/CSWI1.Pos").model(ControlModel::DirectEnhanced).execute(&Value::dbpos(Dbpos::On)).unwrap_err();
    assert!(matches!(e, iec61850_rs::Error::ControlRejected { add_cause } if AddCause::from_code(add_cause) == AddCause::ObjectNotSelected), "{e:?}");
    // And the breaker did not move.
    assert_eq!(handle.read("IED1LD0/CSWI1$ST$Pos$stVal").and_then(|v| v.as_dbpos()), Some(Dbpos::Intermediate));
    c.release().unwrap();
}

#[test]
fn a_selection_belongs_to_the_client_that_made_it() {
    use iec61850_rs::client::ControlModel;
    use iec61850_rs::proto::data::Dbpos;

    let (addr, _h) = spawn_xml(&sbo_relay(), 2);
    let mut a = Client::connect(&addr).expect("first");
    let mut b = Client::connect(&addr).expect("second");

    // The first client selects and stops there.
    a.control("IED1LD0/CSWI1.Pos").model(ControlModel::SboEnhanced).select_with_value(&Value::dbpos(Dbpos::On)).expect("select");
    // The second cannot select it — the object is already selected, and the server says so
    // rather than letting two clients believe they each hold the breaker.
    let e = b.control("IED1LD0/CSWI1.Pos").model(ControlModel::SboEnhanced).select_with_value(&Value::dbpos(Dbpos::On)).unwrap_err();
    assert!(matches!(e, iec61850_rs::Error::ControlRejected { .. } | iec61850_rs::Error::DataAccess(_)), "{e:?}");
    a.release().unwrap();
    b.release().unwrap();
}

#[test]
fn an_application_hook_refuses_with_the_cause_it_chooses() {
    use iec61850_rs::client::{AddCause, ControlModel};
    use iec61850_rs::proto::data::Dbpos;
    use iec61850_rs::server::{AcsiConfig, ServerConfig, Stage};

    // The hook is where a device says "the interlocking says no". Without one every command
    // is accepted, which is what a simulator wants and a relay does not.
    let ied = Ied::from_scl(RELAY, Some("IED1")).expect("load");
    let cfg = ServerConfig { acsi: AcsiConfig::default(), ..ServerConfig::default() };
    let mut server = Server::bind_with("127.0.0.1:0", ied, &cfg).expect("bind");
    server.on_control(Box::new(|event| if event.stage == Stage::Operate { Err(AddCause::BlockedByInterlocking) } else { Ok(()) }));
    let addr = server.local_addr().unwrap().to_string();
    let handle = server.handle();
    std::thread::spawn(move || server.accept_one());

    let mut c = Client::connect(&addr).expect("associate");
    let e = c.control("IED1LD0/CSWI1.Pos").model(ControlModel::DirectNormal).execute(&Value::dbpos(Dbpos::On)).unwrap_err();
    assert!(matches!(e, iec61850_rs::Error::ControlRejected { add_cause } if AddCause::from_code(add_cause) == AddCause::BlockedByInterlocking), "{e:?}");
    assert_eq!(handle.read("IED1LD0/CSWI1$ST$Pos$stVal").and_then(|v| v.as_dbpos()), Some(Dbpos::Intermediate), "and the breaker did not move");
    c.release().unwrap();
}

/// A relay whose overcurrent pickup is a setting with four groups.
const SETTINGS: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="s"/>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"><SettingControl numOfSGs="4" actSG="1"/></LN0>
    <LN lnClass="PTOC" inst="1" prefix="" lnType="PTOC_T">
      <DOI name="StrVal"><SDI name="setMag"><DAI name="f">
        <Val sGroup="1">1.0</Val><Val sGroup="2">2.0</Val><Val sGroup="3">3.0</Val><Val sGroup="4">4.0</Val>
      </DAI></SDI></DOI>
    </LN>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="PTOC_T" lnClass="PTOC"><DO name="StrVal" type="ASG_T"/></LNodeType>
    <!-- One declaration, as the schema requires: `uniqueDAorSDOInDOType` makes a `DA` name
         unique within its `DOType`, so `setMag` cannot be written twice. The `SE` view is the
         server's to publish. -->
    <DOType id="ASG_T" cdc="ASG"><DA name="setMag" fc="SG" bType="Struct" type="AV_T"/></DOType>
    <DAType id="AV_T"><BDA name="f" bType="FLOAT32"/></DAType>
  </DataTypeTemplates>
</SCL>"#;

#[test]
fn setting_groups_activate_edit_and_confirm() {
    let (addr, handle) = spawn_xml(SETTINGS, 1);
    let mut c = Client::connect(&addr).expect("associate");

    // A setting-group-dependent setting is published under **both** constraints from the one
    // declaration the schema allows: `SG` is what is in force and `SE` is the edit copy of it.
    // A server that published only what the file spells has no `SE` namespace at all, and then
    // the whole select ▸ write ▸ confirm sequence answers `object-non-existent`.
    let names = c.logical_device_directory("IED1LD0").expect("browse");
    for expected in ["PTOC1$SG$StrVal$setMag$f", "PTOC1$SE$StrVal$setMag$f"] {
        assert!(names.iter().any(|n| n == expected), "`{expected}` missing from {names:?}");
    }

    // Group 1 is engineered active, so its value is what is in force at start-up — before
    // any client has written anything.
    let sgcb = c.read_sgcb("IED1LD0/LLN0$SP$SGCB").expect("read the block");
    assert_eq!((sgcb.num_of_sg, sgcb.act_sg, sgcb.edit_sg), (Some(4), Some(1), Some(0)));
    assert_eq!(handle.read("IED1LD0/PTOC1$SG$StrVal$setMag$f").and_then(|v| v.as_f64()), Some(1.0));

    // Activating group 3 puts *its* engineered value in force.
    c.select_active_setting_group("IED1LD0/LLN0$SP$SGCB", 3).expect("activate");
    assert_eq!(handle.read("IED1LD0/PTOC1$SG$StrVal$setMag$f").and_then(|v| v.as_f64()), Some(3.0));
    assert_eq!(c.read_sgcb("IED1LD0/LLN0$SP$SGCB").unwrap().act_sg, Some(3));

    // A setting under `SG` is what is in force: it changes by activating a group, never by
    // writing a value into it.
    assert!(matches!(c.write("IED1LD0/PTOC1.StrVal.setMag.f", Fc::SG, &Value::Float32(9.0)), Err(iec61850_rs::Error::DataAccess(3))));
    // And an edit with no group selected has nowhere to go — nor is there anything to read:
    // with `EditSG = 0` there is no edit copy, and answering with the scratch the model was
    // seeded with would tell a client it is looking at a setting group when it is not.
    assert!(matches!(c.write_edit_setting("IED1LD0/PTOC1.StrVal.setMag.f", &Value::Float32(9.0)), Err(iec61850_rs::Error::DataAccess(3))));
    assert!(matches!(c.read_edit_setting("IED1LD0/PTOC1.StrVal.setMag.f"), Err(iec61850_rs::Error::DataAccess(3))));

    // With a group selected, the edit copy reads back what that group currently holds — so a
    // client that changes one setting does not blank the rest when it confirms.
    c.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 2).expect("select for editing");
    assert_eq!(c.read_edit_setting("IED1LD0/PTOC1.StrVal.setMag.f").unwrap().as_f64(), Some(2.0));
    c.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 0).expect("release");

    // The whole sequence: select group 2, write it, confirm, release.
    c.edit_setting_group("IED1LD0/LLN0$SP$SGCB", 2, &[("IED1LD0/PTOC1.StrVal.setMag.f", Value::Float32(7.5))]).expect("edit");
    // Group 3 is still in force and untouched…
    assert_eq!(handle.read("IED1LD0/PTOC1$SG$StrVal$setMag$f").and_then(|v| v.as_f64()), Some(3.0));
    // …and group 2 now holds what was written, which activating it proves.
    c.select_active_setting_group("IED1LD0/LLN0$SP$SGCB", 2).expect("activate 2");
    assert_eq!(handle.read("IED1LD0/PTOC1$SG$StrVal$setMag$f").and_then(|v| v.as_f64()), Some(7.5));

    // A group number the device does not have is refused rather than clamped.
    assert!(c.select_active_setting_group("IED1LD0/LLN0$SP$SGCB", 9).is_err());

    // `CnfEdit` is a command, not a state. A server that leaves it true answers "is an edit
    // being confirmed?" with yes for ever — the same rule `GI` and `PurgeBuf` follow. Written
    // out step by step here, because `edit_setting_group` releases the group afterwards and
    // this is about what the *confirm* leaves behind.
    c.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 4).expect("select");
    c.write_edit_setting("IED1LD0/PTOC1.StrVal.setMag.f", &Value::Float32(8.5)).expect("edit");
    c.confirm_edit_setting_group("IED1LD0/LLN0$SP$SGCB").expect("confirm");
    assert_eq!(handle.read("IED1LD0/LLN0$SP$SGCB$CnfEdit").and_then(|v| v.as_bool()), Some(false), "the server put the command back");
    assert_eq!(c.read_sgcb("IED1LD0/LLN0$SP$SGCB").unwrap().edit_sg, Some(4), "confirming does not release the group");
    c.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 0).expect("release");
    c.select_active_setting_group("IED1LD0/LLN0$SP$SGCB", 4).expect("activate 4");
    assert_eq!(handle.read("IED1LD0/PTOC1$SG$StrVal$setMag$f").and_then(|v| v.as_f64()), Some(8.5));
    c.release().unwrap();
}

/// `ResvTms` on the `SGCB` is how long a client may hold the edit reservation. Without it, a
/// client that selects a group and then goes quiet without disconnecting holds a whole logical
/// device's settings for ever.
#[test]
fn an_edit_reservation_lapses_when_its_reservation_time_runs_out() {
    let (addr, handle) = spawn_xml(SETTINGS, 2);
    let mut a = Client::connect(&addr).expect("associate");
    let mut b = Client::connect(&addr).expect("associate");

    a.write("IED1LD0/LLN0$SP$SGCB$ResvTms", Fc::SP, &Value::Unsigned(1)).expect("ask for one second");
    a.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 2).expect("reserve");
    assert!(b.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 3).is_err(), "held by the first client");

    std::thread::sleep(Duration::from_millis(1200));
    // The server's own timer runs on its poll interval, so nudge it and let it fire.
    let _ = b.read_sgcb("IED1LD0/LLN0$SP$SGCB");
    std::thread::sleep(Duration::from_millis(100));

    b.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 3).expect("the reservation lapsed");
    assert_eq!(handle.read("IED1LD0/LLN0$SP$SGCB$EditSG").and_then(|v| v.as_u64()), Some(3));
    a.release().unwrap();
    b.release().unwrap();
}

#[test]
fn an_edit_reservation_belongs_to_one_client() {
    let (addr, _h) = spawn_xml(SETTINGS, 2);
    let mut a = Client::connect(&addr).expect("first");
    let mut b = Client::connect(&addr).expect("second");

    a.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 2).expect("the first client reserves it");
    assert!(b.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 3).is_err(), "the second is refused");
    // Releasing hands it on.
    a.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 0).expect("release");
    b.select_edit_setting_group("IED1LD0/LLN0$SP$SGCB", 3).expect("the second may have it now");
    a.release().unwrap();
    b.release().unwrap();
}

#[test]
fn a_file_is_listed_and_read_off_the_server_and_the_sandbox_holds() {
    use iec61850_rs::server::DirectoryStore;

    // A directory with one record in it, and a file next to the root a traversal would want.
    let dir = std::env::temp_dir().join(format!("iec61850-srv-files-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("COMTRADE")).expect("create");
    let body: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join("COMTRADE/rec0001.dat"), &body).expect("write");
    let secret = dir.parent().map(|p| p.join(format!("secret-{}.txt", std::process::id())));
    if let Some(p) = &secret {
        let _ = std::fs::write(p, b"not yours");
    }

    let ied = Ied::from_scl(RELAY, Some("IED1")).expect("load");
    let mut server = Server::bind("127.0.0.1:0", ied).expect("bind");
    server.set_file_store(Box::new(DirectoryStore::new(&dir)));
    let addr = server.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.accept_one());

    let mut c = Client::connect(&addr).expect("associate");
    let files = c.file_directory(None).expect("directory");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "COMTRADE/rec0001.dat");
    assert_eq!(files[0].size as usize, body.len());

    // Five thousand octets over a one-kilobyte chunk: the client's read loop and the
    // server's `moreFollows` have to agree, or the file arrives short.
    assert_eq!(c.read_file("COMTRADE/rec0001.dat", 1 << 20).expect("read"), body);

    // And the sandbox: every shape of escape is "not found", never a different error.
    for escape in ["../secret.txt", "COMTRADE/../../secret.txt", "/etc/hosts"] {
        assert!(c.read_file(escape, 1 << 20).is_err(), "`{escape}` was served");
    }
    // Read-only by default: a client cannot delete a record nobody agreed to lose.
    assert!(c.delete_file("COMTRADE/rec0001.dat").is_err());
    assert!(dir.join("COMTRADE/rec0001.dat").exists());
    c.release().unwrap();

    let _ = std::fs::remove_dir_all(&dir);
    if let Some(p) = &secret {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn a_log_records_what_changed_and_is_read_back_by_time_and_after_an_entry() {
    use iec61850_rs::common::EntryTime;

    let (addr, handle) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");

    // The log control block is engineered `logEna="true"` by default, so the log is already
    // recording before any client has asked it to.
    let lcb = c.read_lcb("IED1LD0/LLN0$LG$lcb01", Fc::LG).expect("log control block");
    assert!(lcb.log_ena);
    assert_eq!(lcb.log_ref.as_deref(), Some("IED1LD0/LLN0$GeneralLog"));
    assert_eq!(lcb.data_set.as_deref(), Some("IED1LD0/LLN0$dsTrip"));

    for state in [true, false, true] {
        handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(state)).commit();
        std::thread::sleep(Duration::from_millis(3));
    }

    let page = c.query_log_by_time("IED1LD0/LLN0$GeneralLog", EntryTime::default(), None).expect("query by time");
    assert_eq!(page.entries.len(), 3, "one entry per change");
    assert_eq!(page.entries[0].variables[0].0, "IED1LD0/PTRC1$ST$Tr$general");
    assert_eq!(page.entries.iter().map(|e| e.variables[0].1.as_bool()).collect::<Vec<_>>(), [Some(true), Some(false), Some(true)]);
    assert!(!page.more_follows);

    // Resuming after the first entry gives the two that follow — the pattern a client uses
    // after a reconnection, and the reason `QueryLogAfterEntry` carries the time as well.
    let (id, at) = page.entries[0].resume_point();
    let next = c.query_log_after_entry("IED1LD0/LLN0$GeneralLog", &id, at).expect("query after entry");
    assert_eq!(next.entries.len(), 2);
    assert_eq!(next.entries[0].entry_id, page.entries[1].entry_id);

    // The control block tracks the oldest and newest entry, which is where a client with no
    // stored position starts.
    let lcb = c.read_lcb("IED1LD0/LLN0$LG$lcb01", Fc::LG).expect("read back");
    let (oldest, _) = lcb.oldest().expect("the oldest entry");
    assert_eq!(oldest, page.entries[0].entry_id);
    assert_eq!(lcb.new_entry.as_deref(), Some(page.entries[2].entry_id.as_slice()));

    // A log the server does not have is not found, rather than an empty answer that looks
    // like an empty log.
    assert!(c.query_log_by_time("IED1LD0/LLN0$NoSuchLog", EntryTime::default(), None).is_err());
    c.release().unwrap();
}

/// Arrays, and the `alternateAccess` that reaches inside one (ISO 9506, IEC 61850-8-1 §7.3).
///
/// An array is where the MMS namespace **stops**. `MHAI1$MX$HA$phsAHar` is a named variable
/// and its sixteen elements are not, so a client that wants the third harmonic's magnitude has
/// no name to read: the index and everything after it travel beside the name as an
/// `alternateAccess`, and a server that ignores one answers with the whole array — a different
/// answer to a different question, with nothing on the wire to say the question had changed.
mod arrays {
    use iec61850_rs::Fc;
    use iec61850_rs::client::{Client, RcbSettings, TrgOps};
    use iec61850_rs::proto::data::{Typed, Value};
    use iec61850_rs::proto::mms::typespec::TypeSpec;
    use iec61850_rs::server::{Ied, Server, ServerHandle};
    use std::time::Duration;

    const ARRAY: &str = include_str!("fixtures/array.icd");

    fn spawn() -> (String, ServerHandle) {
        let ied = Ied::from_scl(ARRAY, Some("IED1")).expect("load the model");
        let server = Server::bind("127.0.0.1:0", ied).expect("bind");
        let addr = server.local_addr().expect("addr").to_string();
        let handle = server.handle();
        std::thread::spawn(move || while server.accept_one().is_ok() {});
        (addr, handle)
    }

    /// The namespace stops at the array, and the *type* is where its length is published.
    #[test]
    fn an_array_is_one_name_and_a_type_that_says_how_many() {
        let (addr, _h) = spawn();
        let mut c = Client::connect(&addr).expect("associate");

        let names = c.logical_device_directory("IED1LD0").expect("browse");
        assert!(names.iter().any(|n| n == "MHAI1$MX$HA$phsAHar"), "the array is a name");
        assert!(!names.iter().any(|n| n.starts_with("MHAI1$MX$HA$phsAHar$")), "…and nothing below it is: {names:?}");

        let spec = c.variable_type("IED1LD0/MHAI1$MX$HA", Fc::MX).expect("GetVariableAccessAttributes");
        let TypeSpec::Array { elements, element_type, .. } = spec.component("phsAHar").expect("phsAHar") else {
            panic!("phsAHar is an array: {spec:?}");
        };
        assert_eq!(*elements, 16);
        assert_eq!(element_type.component_names(), ["cVal", "q", "t"]);
        // …and `count` may name a sibling instead of holding a number ✅ (`tSDOCount`), which
        // is the other half of the union and resolves to the same thing.
        let TypeSpec::Array { elements, .. } = spec.component("sqHar").expect("sqHar") else { panic!("sqHar is an array too") };
        assert_eq!(*elements, 3, "count=`numHar`, whose engineered value is 3");
        c.release().unwrap();
    }

    /// The whole array, one element, and a component inside one element — three reads that a
    /// server without alternate access answers with the same sixteen values.
    #[test]
    fn a_reference_with_an_index_reads_one_element_and_not_the_array() {
        let (addr, handle) = spawn();
        let mut c = Client::connect(&addr).expect("associate");
        // Make one element tell itself apart from the other fifteen.
        handle.txn().set("IED1LD0/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f", Value::Float32(12.5)).commit();

        let whole = c.read("IED1LD0/MHAI1$MX$HA$phsAHar", Fc::MX).expect("the whole array");
        let Value::Array(elements) = &whole else { panic!("an array reads as one: {whole:?}") };
        assert_eq!(elements.len(), 16);

        assert_eq!(c.read("IED1LD0/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f", Fc::MX).expect("one leaf").as_f64(), Some(12.5));
        let element = c.read("IED1LD0/MHAI1$MX$HA$phsAHar(2)", Fc::MX).expect("one element");
        assert_eq!(element.members().map(<[Value]>::len), Some(3), "cVal, q, t — not sixteen of them");
        let cval = c.read("IED1LD0/MHAI1$MX$HA$phsAHar(2)$cVal", Fc::MX).expect("one component of one element");
        assert_eq!(cval.members().map(<[Value]>::len), Some(2), "mag and ang");
        // A different element is a different value, which is what says the index was used.
        assert_eq!(c.read("IED1LD0/MHAI1$MX$HA$phsAHar(3)$cVal$mag$f", Fc::MX).expect("read").as_f64(), Some(0.0));
        c.release().unwrap();
    }

    /// An index that names nothing is refused. A server that clamped it to the last element,
    /// or ignored it, would answer with a value the client never asked for.
    #[test]
    fn an_index_outside_the_array_is_refused() {
        let (addr, _h) = spawn();
        let mut c = Client::connect(&addr).expect("associate");
        assert!(c.read("IED1LD0/MHAI1$MX$HA$phsAHar(16)$cVal", Fc::MX).is_err(), "one past the end");
        assert!(c.read("IED1LD0/MHAI1$MX$HA$phsAHar(99)", Fc::MX).is_err(), "far past the end");
        // …and an index on something that is not an array at all.
        assert!(c.read("IED1LD0/MHAI1$MX$HA$numHar(0)", Fc::MX).is_err());
        // The association survives all three: a refusal is an answer, not a fault.
        assert!(c.is_alive());
        c.release().unwrap();
    }

    /// `FCDA/@ix` selects one element of an array as a data-set member ✅ (`tFCDA`), and the
    /// index says *which* element and never *which component* is the array — only the type
    /// does. The fixture writes `ix` alone, which is the form the schema asks for.
    #[test]
    fn a_data_set_member_may_be_one_element_of_an_array() {
        let (addr, handle) = spawn();
        let mut c = Client::connect(&addr).expect("associate");
        handle.txn().set("IED1LD0/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f", Value::Float32(7.25)).commit();

        let members = c.data_set_members("IED1LD0", "LLN0$dsHar").expect("GetNamedVariableListAttributes");
        assert_eq!(
            members,
            [
                "IED1LD0/MHAI1$MX$HA$phsAHar(0)",
                "IED1LD0/MHAI1$MX$HA$phsAHar(1)$cVal",
                "IED1LD0/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f",
                "IED1LD0/MHAI1$MX$HA$numHar",
            ],
            "the index belongs to `phsAHar`, whatever depth the member goes to"
        );

        // …and a report over it carries each member at its own depth, not the array four times.
        c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS)).expect("enable");
        c.general_interrogation("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("GI");
        let report = c.next_report(Duration::from_secs(4)).expect("poll").expect("a report");
        assert_eq!(report.entries.len(), 4);
        assert_eq!(report.entries[0].value.members().map(<[Value]>::len), Some(3), "one whole element");
        assert_eq!(report.entries[1].value.members().map(<[Value]>::len), Some(2), "its `cVal`");
        assert_eq!(report.entries[2].value.as_f64(), Some(7.25), "one float, the one that changed");
        assert_eq!(report.entries[3].value.as_u64(), Some(3), "and the scalar beside them");
        c.release().unwrap();
    }

    /// A write reaches one element too, and leaves the other fifteen alone.
    #[test]
    fn a_write_with_an_index_changes_one_element() {
        let (addr, handle) = spawn();
        let mut c = Client::connect(&addr).expect("associate");
        // `MX` is a measurand and a client may not write one (D39), so this goes through the
        // application's own path — which is the point of the test: the *reference* addresses
        // one element, whichever side writes it.
        handle.txn().set("IED1LD0/MHAI1$MX$HA$phsAHar(5)$cVal$ang$f", Value::Float32(-1.5)).commit();
        assert_eq!(c.read("IED1LD0/MHAI1$MX$HA$phsAHar(5)$cVal$ang$f", Fc::MX).expect("read").as_f64(), Some(-1.5));
        assert_eq!(c.read("IED1LD0/MHAI1$MX$HA$phsAHar(4)$cVal$ang$f", Fc::MX).expect("read").as_f64(), Some(0.0));
        // A client write is still refused by the functional constraint, index or no index.
        assert!(c.write("IED1LD0/MHAI1$MX$HA$phsAHar(5)$cVal$ang$f", Fc::MX, &Value::Float32(9.0)).is_err());
        c.release().unwrap();
    }
}

/// Service tracking (IEC 61850-7-2 §14): what happened on the **wire**, which reporting
/// structurally cannot say because a report is about data and a service is not data.
mod service_tracking {
    use std::time::Duration;

    use iec61850_rs::Fc;
    use iec61850_rs::client::{Client, RcbSettings, TrgOps};
    use iec61850_rs::common::{EntryTime, ServiceError, ServiceType};
    use iec61850_rs::proto::data::{Dbpos, Typed, Value};
    use iec61850_rs::server::{Ied, Server, ServerHandle};

    const TRACKING: &str = include_str!("fixtures/tracking.icd");

    fn spawn(clients: usize) -> (String, ServerHandle) {
        let ied = Ied::from_scl(TRACKING, Some("IED1")).expect("load the model");
        let server = Server::bind("127.0.0.1:0", ied).expect("bind");
        let addr = server.local_addr().expect("addr").to_string();
        let handle = server.handle();
        std::thread::spawn(move || {
            for _ in 0..clients {
                if server.accept_one().is_err() {
                    return;
                }
            }
        });
        (addr, handle)
    }

    /// The ordinals come from the **file**, not from a table behind the IEC paywall: the names
    /// are IEC 61850-7-2's and the numbers are IEC 61850-8-1's, and the file has already said.
    fn ordinal(handle: &ServerHandle, tracker: &str, attribute: &str) -> Option<i64> {
        handle.read(&format!("IED1LD0/LLN0$SR${tracker}${attribute}")).and_then(|v| v.as_i64())
    }

    #[test]
    fn a_control_block_write_lands_in_the_tracking_object_the_file_declares() {
        let (addr, handle) = spawn(1);
        let mut c = Client::connect(&addr).expect("associate");

        // The tracking objects are ordinary data objects under `SR`, so a client browses them
        // and a data set holds them like anything else.
        let names = c.logical_device_directory("IED1LD0").expect("browse");
        for expected in ["LLN0$SR$UrcbTrk$objRef", "LLN0$SR$UrcbTrk$rptEna", "LLN0$SR$CtlTrk$respAddCause", "LLN0$SR$GenTrk$serviceType"] {
            assert!(names.iter().any(|n| n == expected), "`{expected}` missing");
        }

        c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("enable");

        // Writing `RptEna` is `SetURCBValues` on that block, and the file says that is 25.
        assert_eq!(ordinal(&handle, "UrcbTrk", "serviceType"), Some(25));
        assert_eq!(ordinal(&handle, "UrcbTrk", "errorCode"), Some(12), "no-error, because a successful service is tracked too");
        assert_eq!(handle.read("IED1LD0/LLN0$SR$UrcbTrk$objRef").and_then(|v| v.as_str().map(str::to_owned)), Some(String::from("IED1LD0/LLN0$RP$urcb")));
        // …and the block-specific half mirrors the block itself: `rptEna` is `RptEna`, which
        // is the one rule that replaces nine tables of attribute names.
        assert_eq!(handle.read("IED1LD0/LLN0$SR$UrcbTrk$rptEna").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(handle.read("IED1LD0/LLN0$SR$UrcbTrk$confRev").and_then(|v| v.as_u64()), Some(1));
        // The originator is the peer's address — the same octets `Owner` carries, which the
        // transport knows and the ACSI layer cannot invent.
        assert!(handle.read("IED1LD0/LLN0$SR$UrcbTrk$originatorID").is_some());

        // A **refused** service is the case tracking exists for. `SqNum` is the server's to
        // count (D39), so writing it is an access violation — and the tracker says so.
        assert!(c.write("IED1LD0/LLN0$RP$urcb$SqNum", Fc::RP, &Value::Unsigned(9)).is_err());
        assert_eq!(ordinal(&handle, "UrcbTrk", "errorCode"), Some(2), "access-violation, as the file numbers it");
        c.release().unwrap();
    }

    /// A control service goes into the `CTS` tracker, whose specific half is not on the object
    /// it names — `ctlVal`, `origin`, `ctlNum`, `T`, `Test` and `Check` are components of what
    /// the *client sent*, and `respAddCause` exists nowhere but in the refusal.
    #[test]
    fn a_control_is_tracked_with_what_the_client_actually_sent() {
        let (addr, handle) = spawn(1);
        let mut c = Client::connect(&addr).expect("associate");

        c.control("IED1LD0/CSWI1.Pos").execute(&Value::dbpos(Dbpos::On)).expect("operate");
        assert_eq!(ordinal(&handle, "CtlTrk", "serviceType"), Some(45), "Operate");
        assert_eq!(ordinal(&handle, "CtlTrk", "errorCode"), Some(12));
        assert_eq!(handle.read("IED1LD0/LLN0$SR$CtlTrk$objRef").and_then(|v| v.as_str().map(str::to_owned)), Some(String::from("IED1LD0/CSWI1$CO$Pos")));
        assert_eq!(handle.read("IED1LD0/LLN0$SR$CtlTrk$ctlVal").and_then(|v| v.as_dbpos()), Some(Dbpos::On));
        assert_eq!(handle.read("IED1LD0/LLN0$SR$CtlTrk$respAddCause").and_then(|v| v.as_i64()), Some(0), "Unknown: nothing went wrong");
        assert_eq!(handle.read("IED1LD0/LLN0$SR$CtlTrk$Test").and_then(|v| v.as_bool()), Some(false));
        assert!(handle.read("IED1LD0/LLN0$SR$CtlTrk$origin").is_some(), "and who asked");
        c.release().unwrap();
    }

    /// The whole point: a tracking object is an ordinary data object, so an ordinary report
    /// control block carries a *service* to the control room with nothing extra written.
    #[test]
    fn a_report_control_block_carries_the_tracking_object_to_a_client() {
        let (addr, _h) = spawn(1);
        let mut c = Client::connect(&addr).expect("associate");
        c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS)).expect("enable");

        // Operating the breaker changes `CtlTrk`, which is the second member of the data set.
        c.control("IED1LD0/CSWI1.Pos").execute(&Value::dbpos(Dbpos::On)).expect("operate");
        // Enabling the block was itself a tracked service, so the first report is about
        // `UrcbTrk`; the one that matters is the next. `CtlTrk` is member **1** of the data
        // set, and the inclusion bit string is what says so — this report asked for no
        // `data-reference`, which is the usual case and the reason `index` exists.
        let mut found = None;
        for _ in 0..4 {
            let Some(r) = c.next_report(Duration::from_secs(2)).expect("poll") else { break };
            assert_eq!(r.data_set_len(), 2, "two members, both of them tracking objects");
            if let Some(e) = r.entries.iter().find(|e| e.index == 1) {
                found = e.value.members().map(<[Value]>::len);
                break;
            }
        }
        assert!(found.is_some_and(|n| n >= 6), "the control tracker arrives as one member, whole: {found:?}");
        c.release().unwrap();
    }

    /// The lower-case rule has exactly one exception, and it is the busiest attribute a
    /// buffered tracker has: the block spells its general interrogation `GI` — two capitals —
    /// while the tracker spells it `gi`, so lower-casing the first letter alone looks for a
    /// `Gi` no model has and leaves the field empty for ever.
    ///
    /// libiec61850's own `LTRK` model is where this became visible: its `BTS` declares `gi`
    /// beside `rptID`, `entryID` and `goID`, all four of which the rule has to get right at
    /// once 🌐.
    #[test]
    fn every_attribute_of_a_whole_buffered_tracker_mirrors_its_block() {
        let (addr, handle) = spawn(1);
        let mut c = Client::connect(&addr).expect("associate");
        c.enable_rcb("IED1LD0/LLN0$BR$brcb", Fc::BR, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("enable");
        c.general_interrogation("IED1LD0/LLN0$BR$brcb", Fc::BR).expect("GI");

        let trk = |a: &str| handle.read(&format!("IED1LD0/LLN0$SR$BrcbTrk${a}"));
        assert_eq!(ordinal(&handle, "BrcbTrk", "serviceType"), Some(23), "SetBRCBValues");
        // The whole specific half, not the three attributes a small fixture happens to have.
        assert_eq!(trk("rptEna").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(trk("gi").and_then(|v| v.as_bool()), Some(true), "`gi` is `GI`, and this is the one place the rule needs to know it");
        assert_eq!(trk("purgeBuf").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(trk("confRev").and_then(|v| v.as_u64()), Some(1));
        assert!(trk("optFlds").is_some(), "optFlds");
        assert!(trk("trgOps").is_some(), "trgOps");
        assert!(trk("entryID").is_some(), "entryID");
        assert!(trk("timeOfEntry").is_some(), "timeOfEntry");
        assert!(trk("sqNum").is_some(), "sqNum");
        assert_eq!(trk("datSet").and_then(|v| v.as_str().map(str::to_owned)), Some(String::from("IED1LD0/LLN0$dsTrk")));
        c.release().unwrap();
    }

    /// The two log **queries** are the one pair of read services with a tracking class of
    /// their own (`OTS`), and `objRef` names the *log* rather than a control block — so
    /// nothing is mirrored and the specific half is the query's own range.
    #[test]
    fn a_log_query_is_tracked_in_the_ots_object() {
        let (addr, handle) = spawn(1);
        let mut c = Client::connect(&addr).expect("associate");

        c.query_log_by_time("IED1LD0/LLN0$EventLog", EntryTime::from_unix_millis(1_000), Some(EntryTime::from_unix_millis(9_000))).expect("query");
        assert_eq!(ordinal(&handle, "LogTrk", "serviceType"), Some(28), "QueryLogByTime");
        assert_eq!(ordinal(&handle, "LogTrk", "errorCode"), Some(12));
        assert_eq!(handle.read("IED1LD0/LLN0$SR$LogTrk$objRef").and_then(|v| v.as_str().map(str::to_owned)), Some(String::from("IED1LD0/LLN0$EventLog")));
        assert!(handle.read("IED1LD0/LLN0$SR$LogTrk$rangeStartTime").is_some(), "the range the client asked for");
        assert!(handle.read("IED1LD0/LLN0$SR$LogTrk$rangeStopTime").is_some());

        // The other query is a different service, and the resume point is its parameter.
        c.query_log_after_entry("IED1LD0/LLN0$EventLog", &[0, 0, 0, 0, 0, 0, 0, 7], EntryTime::from_unix_millis(2_000)).expect("query");
        assert_eq!(ordinal(&handle, "LogTrk", "serviceType"), Some(29), "QueryLogAfter");
        assert!(matches!(handle.read("IED1LD0/LLN0$SR$LogTrk$entryID"), Some(Value::OctetString(b)) if b.ends_with(&[7])));

        // A log the server has not got is refused, and the refusal is tracked as one.
        assert!(c.query_log_by_time("IED1LD0/LLN0$NoSuchLog", EntryTime::default(), None).is_err());
        assert_eq!(ordinal(&handle, "LogTrk", "errorCode"), Some(0), "instance-not-available, as the file numbers it");
        c.release().unwrap();
    }

    /// §14.1 puts one tracking object of each class in a logical device, and `CTS` is the
    /// exception the standard's own logical node makes: IEC 61850-7-4's `LTRK` carries
    /// `SpcTrk`, `DpcTrk`, `IncTrk`, `BscTrk` … — one control tracker per **kind** of
    /// controlled object, because a tracker declares a `ctlVal` and a `ctlVal` has a type 🌐.
    ///
    /// Which one records a command is therefore decided by that type, from the file on both
    /// sides. The fixture declares the boolean tracker *first* on purpose: "the first `CTS` in
    /// the logical device" would put every double-point command into it.
    #[test]
    fn a_control_is_tracked_by_the_tracker_whose_type_matches_it() {
        let (addr, handle) = spawn(1);
        let mut c = Client::connect(&addr).expect("associate");

        c.control("IED1LD0/GGIO1.SPCSO1").execute(&Value::Boolean(true)).expect("operate the single-point object");
        assert_eq!(handle.read("IED1LD0/LLN0$SR$SpcTrk$objRef").and_then(|v| v.as_str().map(str::to_owned)), Some(String::from("IED1LD0/GGIO1$CO$SPCSO1")));
        assert_eq!(handle.read("IED1LD0/LLN0$SR$SpcTrk$ctlVal").and_then(|v| v.as_bool()), Some(true));
        assert!(matches!(handle.read("IED1LD0/LLN0$SR$CtlTrk$objRef"), Some(v) if v.as_str() == Some("")), "and the double-point tracker is untouched");

        c.control("IED1LD0/CSWI1.Pos").execute(&Value::dbpos(Dbpos::On)).expect("operate the double-point object");
        assert_eq!(handle.read("IED1LD0/LLN0$SR$CtlTrk$objRef").and_then(|v| v.as_str().map(str::to_owned)), Some(String::from("IED1LD0/CSWI1$CO$Pos")));
        assert_eq!(handle.read("IED1LD0/LLN0$SR$CtlTrk$ctlVal").and_then(|v| v.as_dbpos()), Some(Dbpos::On));
        // …and the single-point one still holds *its* command, not the last one.
        assert_eq!(handle.read("IED1LD0/LLN0$SR$SpcTrk$objRef").and_then(|v| v.as_str().map(str::to_owned)), Some(String::from("IED1LD0/GGIO1$CO$SPCSO1")));
        c.release().unwrap();
    }

    /// An association that ends releases the control block it held, and that is a change with
    /// **no service behind it** — IEC 61850-7-2 §15.3.2.2.2 calls it `InternalChange`.
    #[test]
    fn a_block_released_with_its_association_is_an_internal_change() {
        let (addr, handle) = spawn(2);
        let mut a = Client::connect(&addr).expect("associate");
        a.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("enable");
        assert_eq!(ordinal(&handle, "UrcbTrk", "serviceType"), Some(25));
        a.release().unwrap();
        drop(a);

        // Nudge the server so the close is processed, then look.
        let mut b = Client::connect(&addr).expect("associate");
        let _ = b.identify();
        std::thread::sleep(Duration::from_millis(100));
        let _ = b.identify();
        assert_eq!(ordinal(&handle, "UrcbTrk", "serviceType"), Some(53), "InternalChange");
        assert_eq!(handle.read("IED1LD0/LLN0$SR$UrcbTrk$rptEna").and_then(|v| v.as_bool()), Some(false));
        // No client did it, so no client is named.
        assert!(matches!(handle.read("IED1LD0/LLN0$SR$UrcbTrk$originatorID"), Some(Value::OctetString(b)) if b.is_empty()));
        b.release().unwrap();
    }

    /// A file that declares no `EnumType` still gets a number, from the standard's own list
    /// order — a fallback, and one the file overrides whenever it has an opinion.
    #[test]
    fn the_standards_list_order_is_the_fallback_and_the_file_is_the_answer() {
        assert_eq!(ServiceType::SetURCBValues.table_ordinal(), 25);
        assert_eq!(ServiceType::Operate.table_ordinal(), 45);
        assert_eq!(ServiceType::InternalChange.table_ordinal(), 53);
        assert_eq!(ServiceError::NoError.table_ordinal(), 12);
        // The fixture happens to agree with the list, which is how the assertions above stay
        // readable; what matters is that the file is consulted first.
        assert_eq!(ServiceType::parse("SetURCBValues"), Some(ServiceType::SetURCBValues));
    }
}

/// The GOOSE and sampled-value control blocks a server publishes, and the one thing that makes
/// them two blocks rather than one.
mod publisher_control_blocks {
    use iec61850_rs::Fc;
    use iec61850_rs::client::Client;
    use iec61850_rs::proto::data::{Typed, Value};
    use iec61850_rs::server::{Ied, Server};

    /// One GOOSE block, one multicast SV stream and one **unicast** one — the last is the
    /// shape a server that publishes everything under `MS` gets wrong.
    const PUBLISHER: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="p"/>
  <Communication><SubNetwork name="S1"><ConnectedAP iedName="IED1" apName="P1">
    <GSE ldInst="LD0" cbName="gcbTrip">
      <Address><P type="MAC-Address">01-0C-CD-01-00-01</P><P type="APPID">0001</P><P type="VLAN-ID">005</P><P type="VLAN-PRIORITY">4</P></Address>
    </GSE>
    <SMV ldInst="LD0" cbName="msvMU">
      <Address><P type="MAC-Address">01-0C-CD-04-00-01</P><P type="APPID">4000</P><P type="VLAN-ID">005</P><P type="VLAN-PRIORITY">4</P></Address>
    </SMV>
  </ConnectedAP></SubNetwork></Communication>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
      <DataSet name="dsTrip"><FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/></DataSet>
      <GSEControl name="gcbTrip" datSet="dsTrip" confRev="3" appID="IED1_Trip" type="GOOSE"/>
      <SampledValueControl name="msvMU" datSet="dsTrip" confRev="1" smvID="MU01" smpRate="80" nofASDU="1" multicast="true"/>
      <SampledValueControl name="usvMU" datSet="dsTrip" confRev="1" smvID="MU02" smpRate="80" nofASDU="1" multicast="false"/>
    </LN0>
    <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <DOType id="ACT_T" cdc="ACT"><DA name="general" fc="ST" bType="BOOLEAN"/></DOType>
  </DataTypeTemplates>
</SCL>"#;

    fn spawn() -> String {
        let ied = Ied::from_scl(PUBLISHER, Some("IED1")).expect("load the model");
        let server = Server::bind("127.0.0.1:0", ied).expect("bind");
        let addr = server.local_addr().expect("addr").to_string();
        std::thread::spawn(move || {
            let _ = server.accept_one();
        });
        addr
    }

    #[test]
    fn a_unicast_stream_is_a_usvcb_and_not_a_multicast_one() {
        let addr = spawn();
        let mut c = Client::connect(&addr).expect("associate");
        let names = c.logical_device_directory("IED1LD0").expect("browse");

        // A multicast stream: `MS`, `MsvID`, and `noASDU`, which is how many ASDUs one frame
        // carries — a concept a unicast stream does not have.
        for expected in ["LLN0$MS$msvMU$MsvID", "LLN0$MS$msvMU$noASDU", "LLN0$MS$msvMU$DstAddress$APPID", "LLN0$GO$gcbTrip$GoID"] {
            assert!(names.iter().any(|n| n == expected), "`{expected}` missing");
        }
        // A unicast one: `US`, `UsvID`, and no `noASDU` at all.
        assert!(names.iter().any(|n| n == "LLN0$US$usvMU$UsvID"), "the unicast block is not a USVCB: {names:?}");
        assert!(!names.iter().any(|n| n.contains("$US$usvMU$noASDU")), "a USVCB has no noASDU");
        assert!(!names.iter().any(|n| n.contains("$MS$usvMU")), "and it is not published under MS as well");

        // The addresses come from the file's `Communication` section, so a client reads the
        // address the publisher will actually use.
        assert_eq!(c.read("IED1LD0/LLN0$GO$gcbTrip$DstAddress$APPID", Fc::GO).unwrap().as_u64(), Some(1));
        assert_eq!(c.read("IED1LD0/LLN0$MS$msvMU$MsvID", Fc::MS).unwrap().as_str().map(str::to_owned), Some(String::from("MU01")));
        assert_eq!(c.read("IED1LD0/LLN0$US$usvMU$UsvID", Fc::US).unwrap().as_str().map(str::to_owned), Some(String::from("MU02")));

        // Only the enable flag is a client's to write (D39) — the rest is engineering.
        c.write("IED1LD0/LLN0$US$usvMU$SvEna", Fc::US, &Value::Boolean(true)).expect("SvEna is writable");
        assert!(c.write("IED1LD0/LLN0$US$usvMU$SmpRate", Fc::US, &Value::Unsigned(96)).is_err(), "SmpRate is not");
        c.release().unwrap();
    }
}

/// A link that drops and comes back, and the state that deliberately does not come back with it.
#[test]
fn a_client_reconnects_and_restores_nothing_behind_your_back() {
    use iec61850_rs::client::{Backoff, RcbSettings, TrgOps};

    let (addr, handle) = spawn(2);
    let mut c = Client::connect(&addr).expect("associate");
    c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS)).expect("enable");
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
    assert!(c.next_report(Duration::from_secs(2)).expect("poll").is_some());

    c.release().expect("release");
    assert!(!c.is_alive(), "the association is gone");

    // Bounded, because a test that retries for ever is a test that hangs.
    c.reconnect(&Backoff::default().bounded(3)).expect("reconnect");
    assert!(c.is_alive(), "and back — six layers, proved by a Status round trip");

    // The control block belonged to the association that ended. Nothing re-enabled it, and a
    // client that assumed otherwise would sit waiting for reports that are not coming.
    //
    // `RptEna` reading true here is worse than cosmetic: the server refuses every *setting*
    // while a block is enabled, so a block left claiming to be on is a block the next client
    // cannot configure without first guessing that it has to be turned off.
    let rcb = c.read_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("read the block");
    assert!(!rcb.rpt_ena, "the server released the block with the association");
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(false)).commit();
    assert!(c.next_report(Duration::from_millis(300)).unwrap().is_none(), "and nothing reports until the caller says so");

    c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS)).expect("re-enable");
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
    let r = c.next_report(Duration::from_secs(2)).expect("poll").expect("a report on the new association");
    assert_eq!(r.seq_num, Some(0), "a new subscription starts its sequence again");
    c.release().unwrap();
}

/// The three services below `Identify` that a SCADA client reaches for before it knows
/// anything about the model, and the one PDU that ends a call without answering it.
#[test]
fn the_vmd_answers_for_itself() {
    let (addr, _h) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");

    // `Status` needs no name, no model and no data set, so an answer is proof that all six
    // layers are up — which is exactly why a supervision loop asks it and nothing else.
    let status = c.status(false).expect("status");
    assert!(status.is_healthy());
    assert_eq!(status.logical, iec61850_rs::proto::mms::vmd_logical::STATE_CHANGES_ALLOWED);
    assert_eq!(status.physical, iec61850_rs::proto::mms::vmd_physical::OPERATIONAL);
    // `extendedDerivation` asks for a fresh derivation; this server has nothing cached, so
    // the answer is the same one and the flag costs a client nothing to set.
    assert_eq!(c.status(true).expect("extended status"), status);
    assert!(c.is_alive());

    let capabilities = c.capabilities().expect("capabilities");
    assert_eq!(capabilities, ["IEC 61850-8-1:2011+AMD1:2020"]);
    c.release().unwrap();
}

/// A `Cancel` for a request that is not outstanding is *answered*, not ignored.
///
/// Before this it fell through to the unconfirmed catch-all and nothing was sent back, which
/// is the reject defect (D35) on a different PDU: the peer waits out its whole request
/// timeout for a reply that was never coming.
#[test]
fn a_cancel_for_a_finished_request_is_refused_rather_than_swallowed() {
    use iec61850_rs::common::{Instant, Limits};
    use iec61850_rs::proto::mms::association::{Association, AssociationConfig};
    use iec61850_rs::proto::mms::{Mms, ServiceError, service_error};

    // Sans-IO, both roles, no socket: the association is its own test peer (D25).
    let mut client = Association::client(AssociationConfig::default());
    let mut server = Association::server(AssociationConfig::default());
    let mut now = Instant::ZERO;
    client.start(now).expect("start");
    for _ in 0..8 {
        now = Instant(now.0 + 1_000_000);
        while let Some(p) = client.poll_transmit() {
            let p = p.to_vec();
            server.on_bytes(now, &p);
        }
        while let Some(p) = server.poll_transmit() {
            let p = p.to_vec();
            client.on_bytes(now, &p);
        }
    }
    assert!(client.is_established() && server.is_established());

    let invoke = client.call(now, &iec61850_rs::proto::mms::ConfirmedRequest::Identify).expect("call");
    client.cancel(invoke).expect("cancel an outstanding request");
    // Cancelling something that was never asked for is a caller error, not a PDU.
    assert!(client.cancel(invoke + 1).is_err());

    let mut to_server = Vec::new();
    while let Some(p) = client.poll_transmit() {
        to_server.extend_from_slice(p);
    }
    server.on_bytes(now, &to_server);

    let mut answered = false;
    while let Some(p) = server.poll_transmit() {
        let p = p.to_vec();
        // The last PDU the server sends is the refusal; find it by decoding.
        client.on_bytes(now, &p);
        answered = true;
    }
    assert!(answered, "the server said something");

    let mut refused = false;
    while let Some(e) = client.poll_event() {
        if let iec61850_rs::proto::mms::association::AssociationEvent::CancelRefused { invoke_id } = e {
            assert_eq!(invoke_id, invoke);
            refused = true;
        }
    }
    assert!(refused, "the cancel was answered with a refusal naming the request");

    // And the refusal says *why*, in the ISO 9506 class the sequencing fault belongs to.
    let encoded =
        ServiceError::encode(iec61850_rs::ber::Tag::context_constructed(1), service_error::SERVICE, service_error::PRIMITIVES_OUT_OF_SEQUENCE).unwrap();
    let tlv = iec61850_rs::ber::Cursor::new(&encoded).next_required().unwrap();
    let round = Mms::CancelError { invoke_id: invoke, error: tlv }.to_vec().unwrap();
    match Mms::parse(&round, &Limits::DEFAULT).unwrap() {
        Mms::CancelError { invoke_id, error } => {
            assert_eq!(invoke_id, invoke);
            let e = ServiceError::parse(&error).unwrap();
            assert_eq!((e.class, e.code), (service_error::SERVICE, service_error::PRIMITIVES_OUT_OF_SEQUENCE));
        }
        other => panic!("not a cancel-Error: {other:?}"),
    }
}

/// A data set of **FCDs** — members that name a data object rather than one attribute.
///
/// This is the shape the report mapping is granular in and the shape none of the other
/// fixtures has, which is exactly why it went wrong: the server flattened every member to the
/// attributes under it, so a two-member data set reported six values under a six-bit inclusion
/// string while the same server's `GetNamedVariableListAttributes` answered with two names.
/// Both halves of this crate agreed, because both flattened. No other client would have.
mod functionally_constrained_data {
    use std::time::Duration;

    use iec61850_rs::Fc;
    use iec61850_rs::client::{Client, ClientConfig, RcbSettings, TrgOps};
    use iec61850_rs::proto::data::Value;
    use iec61850_rs::server::{Ied, Server, ServerHandle};

    const FCD: &str = include_str!("fixtures/fcd.icd");

    fn spawn(clients: usize) -> (String, ServerHandle) {
        let ied = Ied::from_scl(FCD, Some("IED1")).expect("load the model");
        let server = Server::bind("127.0.0.1:0", ied).expect("bind");
        let addr = server.local_addr().expect("addr").to_string();
        let handle = server.handle();
        std::thread::spawn(move || {
            for _ in 0..clients {
                if server.accept_one().is_err() {
                    return;
                }
            }
        });
        (addr, handle)
    }

    /// One member, one value, one inclusion bit — in the directory, in a read of the list and
    /// in a report, which have to be three views of one list rather than three answers.
    #[test]
    fn a_data_object_member_is_one_member_everywhere() {
        let (addr, handle) = spawn(1);
        let mut c = Client::connect(&addr).expect("associate");

        let members = c.data_set_members("IED1LD0", "LLN0$dsPos").unwrap();
        assert_eq!(members, ["IED1LD0/CSWI1$ST$Pos", "IED1LD0/PTRC1$ST$Tr"], "the members are data objects, not their attributes");

        // A `Read` of the list answers one `AccessResult` per member, and each is the whole
        // structure. Three values per member arriving as three results would leave a client
        // that indexed them against the directory above reading `Tr` where `Pos.q` is.
        let values = c.read_data_set("IED1LD0", "LLN0$dsPos").unwrap();
        assert_eq!(values.len(), members.len(), "one result per member");
        assert_eq!(values[0].members().map(<[Value]>::len), Some(3), "Pos is stVal, q and t");

        let enabled = c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS)).expect("enable");
        assert!(enabled.rpt_ena);

        // A change to *one attribute* of an FCD includes the whole member, once.
        handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
        let r = c.next_report(Duration::from_secs(2)).expect("poll").expect("a report");
        assert_eq!(r.data_set_len(), 2, "the inclusion bit string is as long as the directory");
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].index, 1, "Tr is the second member");
        assert_eq!(r.entries[0].value.members().map(<[Value]>::len), Some(3), "the object is reported whole");

        // Two attributes of the same member changing together is still one entry, with the
        // reasons merged — not two entries at two indices the data set does not have.
        handle
            .txn()
            .set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(false))
            .set("IED1LD0/PTRC1$ST$Tr$q", Value::quality(iec61850_rs::Quality { validity: iec61850_rs::Validity::Invalid, ..iec61850_rs::Quality::GOOD }))
            .commit();
        let r = c.next_report(Duration::from_secs(2)).expect("poll").expect("a second report");
        assert_eq!(r.entries.len(), 1);
        let reason = r.entries[0].reason.expect("a reason");
        assert!(reason.data_change() && reason.quality_change(), "both triggers, one member");
        c.release().unwrap();
    }

    /// `ConfRev` is what a client caches its picture of a data set against, and repointing a
    /// block at a different data set is exactly the change that invalidates it.
    #[test]
    fn repointing_a_block_at_another_data_set_moves_conf_rev() {
        let (addr, _h) = spawn(1);
        let mut c = Client::connect(&addr).expect("associate");

        let before = c.read_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("read").conf_rev;
        assert_eq!(before, Some(1));

        // A data set the model has not got is refused, not stored: a block pointing at a
        // name nothing answers reports nothing and never says why.
        assert!(c.write("IED1LD0/LLN0$RP$urcb$DatSet", Fc::RP, &Value::VisibleString("IED1LD0/LLN0$dsNope".into())).is_err());
        assert_eq!(c.read_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("read").conf_rev, before, "a refused write moves nothing");

        c.write("IED1LD0/LLN0$RP$urcb$DatSet", Fc::RP, &Value::VisibleString("IED1LD0/LLN0$dsWide".into())).expect("repoint");
        let after = c.read_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("read");
        assert_eq!(after.data_set.as_deref(), Some("IED1LD0/LLN0$dsWide"));
        assert_eq!(after.conf_rev, Some(2), "and the revision says the cached member list is stale");
        c.release().unwrap();
    }

    /// A report longer than what the client said it would accept is **segmented**, not
    /// dropped. Before this the server encoded it whole, the association refused to frame it,
    /// and the client waited for a report that was never sent and never reported missing.
    #[test]
    fn a_report_too_large_for_the_negotiated_pdu_is_split_into_segments() {
        let (addr, handle) = spawn(1);
        // What a small client negotiates. ISO 9506 negotiates *down*, so this is the number
        // the server has to size its reports by — not its own, which is a hundred times more.
        let mut cfg = ClientConfig::default();
        cfg.association.max_pdu = 900;
        let mut c = Client::connect_with(&addr, &cfg).expect("associate");
        assert_eq!(c.negotiated().map(|n| n.max_pdu), Some(900));

        c.enable_rcb("IED1LD0/LLN0$RP$wide", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS.with_general_interrogation(true))).expect("enable");
        // A general interrogation reports every one of the twelve members, each a five-field
        // structure with a data reference beside it — far past 900 octets.
        c.general_interrogation("IED1LD0/LLN0$RP$wide", Fc::RP).expect("GI");

        let r = c.next_report(Duration::from_secs(2)).expect("poll").expect("a reassembled report");
        assert_eq!(r.data_set_len(), 12);
        assert_eq!(r.entries.len(), 12, "every member arrives, joined from its segments");
        assert!((0..12).all(|i| r.entries.iter().any(|e| e.index == i)), "and none is lost in the join");
        assert_eq!(c.report_assembler_stats().reassembled, 1, "which took more than one segment");
        assert_eq!(c.report_assembler_stats().out_of_order, 0);

        // The same holds for an ordinary change report, and the segments of one report share
        // its `SqNum` — that is what tells them apart from the next report.
        handle.txn().set("IED1LD0/MMXU1$MX$A1$phsA$mag$f", Value::Float32(1.5)).commit();
        let r = c.next_report(Duration::from_secs(2)).expect("poll").expect("a change report");
        assert_eq!(r.entries.len(), 1, "one member changed");
        // A report that fits carries no segmentation flag, even though the client asked for
        // `OptFlds` that a file could perfectly well have set it in: the flag promises a
        // `SubSeqNum`, and a promise the report does not keep is what a decoder cannot forgive.
        assert!(!r.opt_flds.segmentation(), "an unsegmented report claimed segmentation");
        c.release().unwrap();
    }
}

/// The three things a report gets wrong when the engine is driven by the wrong clock, under
/// the wrong name, or with a blunt instrument for its own bookkeeping. All three were real.
mod report_engine {
    use iec61850_rs::client::Unsolicited;
    use iec61850_rs::common::{EntryTime, Instant, Limits};
    use iec61850_rs::proto::data::Value;
    use iec61850_rs::proto::mms::{Mms, ObjectName, Unconfirmed, VariableAccess};
    use iec61850_rs::server::{Engine, Ied};

    const BLOCK: &str = "IED1LD0/LLN0$RP$urcb";
    const MEMBER: &str = "IED1LD0/PTRC1$ST$Tr$general";
    /// 2023-11-14T22:13:20.500Z, well inside the `BinaryTime` epoch.
    const WALL_MS: u64 = 1_700_000_000_500;

    /// A model with `BLOCK` enabled for association 7 and a clean dirty set.
    fn enabled() -> (Ied, Engine) {
        let mut ied = Ied::from_scl(super::RELAY, Some("IED1")).expect("load the model");
        let mut engine = Engine::new(&ied);
        engine.on_write(7, &mut ied, BLOCK, "RptEna", &Value::Boolean(true), Instant::ZERO).expect("enable");
        ied.write_leaf(&format!("{BLOCK}$RptEna"), Value::Boolean(true)).expect("write RptEna");
        ied.take_dirty();
        (ied, engine)
    }

    /// `IntgPd` is *how often*; `TrgOps.integrity` is *whether*. A server that scans on the
    /// period alone sends a client reports it never subscribed to — and `ied scl validate`
    /// already calls a period without a trigger a finding, so the engine has to agree with the
    /// validator about what the file means.
    #[test]
    fn an_integrity_period_without_its_trigger_reports_nothing() {
        use iec61850_rs::common::TrgOps;

        for (integrity, expected) in [(false, 0usize), (true, 1)] {
            let mut ied = Ied::from_scl(super::RELAY, Some("IED1")).expect("load the model");
            let trg_ops = TrgOps::NONE.with_data_change(true).with_integrity(integrity);
            let (unused, bits) = trg_ops.to_bit_string();
            ied.write_leaf(&format!("{BLOCK}$TrgOps"), Value::BitString { unused, bytes: bits }).expect("write TrgOps");
            ied.write_leaf(&format!("{BLOCK}$IntgPd"), Value::Unsigned(100)).expect("write IntgPd");
            let mut engine = Engine::new(&ied);
            engine.on_write(7, &mut ied, BLOCK, "RptEna", &Value::Boolean(true), Instant::ZERO).expect("enable");
            ied.write_leaf(&format!("{BLOCK}$RptEna"), Value::Boolean(true)).expect("write RptEna");
            ied.take_dirty();

            let wall = EntryTime::from_unix_millis(WALL_MS);
            // Well past the period, and nothing else has changed.
            let out = engine.on_timeout(&mut ied, wall, Instant(500_000_000));
            assert_eq!(out.len(), expected, "integrity trigger {integrity}");
            assert_eq!(engine.next_timeout().is_some(), integrity, "and nothing is scheduled without the trigger");
        }
    }

    /// `TimeOfEntry` is an absolute time an operator reads. Deriving it from the monotonic
    /// `Instant` the cores are driven by put every report at 1984-01-01, the floor of the
    /// `BinaryTime` epoch — and made `QueryLogByTime` match nothing.
    #[test]
    fn a_report_carries_the_wall_clock_and_not_the_monotonic_one() {
        let (mut ied, mut engine) = enabled();
        ied.write_leaf(MEMBER, Value::Boolean(true)).expect("write");
        let dirty = ied.take_dirty();
        let wall = EntryTime::from_unix_millis(WALL_MS);
        // `now` is what it always is at the start of a process: a few microseconds.
        let out = engine.commit(&mut ied, &dirty, wall, Instant(12_345));
        assert_eq!(out.len(), 1, "one report");

        let report = match Unsolicited::from_pdu(&out[0].pdu, &Limits::DEFAULT) {
            Some(Unsolicited::Report(r)) => r,
            other => panic!("not a report: {other:?}"),
        };
        assert_eq!(report.time_of_entry, Some(wall));
        assert_eq!(report.time_of_entry.map(EntryTime::to_unix_millis), Some(WALL_MS));
        assert_ne!(report.time_of_entry, Some(EntryTime::default()), "1984-01-01 is what the monotonic instant used to produce");
    }

    /// IEC 61850-8-1 reports every `InformationReport` under the VMD-specific name `RPT`;
    /// libiec61850 writes exactly that. Deriving the name from `RptID` produced an
    /// unparseable `domain-specific` name the moment a file set `rptID` to anything else —
    /// and `rptID` is a plain SCL attribute.
    #[test]
    fn a_report_is_reported_under_the_name_the_mapping_gives_it() {
        let (mut ied, mut engine) = enabled();
        // Exactly what an engineer writes in the SCD, and what used to break the encoding.
        ied.write_leaf(&format!("{BLOCK}$RptID"), Value::VisibleString("Trip report".into())).expect("write RptID");
        ied.take_dirty();
        ied.write_leaf(MEMBER, Value::Boolean(true)).expect("write");
        let dirty = ied.take_dirty();
        let out = engine.commit(&mut ied, &dirty, EntryTime::from_unix_millis(WALL_MS), Instant::ZERO);
        assert_eq!(out.len(), 1);

        let Ok(Mms::Unconfirmed(Unconfirmed::InformationReport { access, .. })) = Mms::parse(&out[0].pdu, &Limits::DEFAULT) else {
            panic!("not an information report");
        };
        assert_eq!(access, VariableAccess::VariableListName(ObjectName::VmdSpecific("RPT")));
        // The `RptID` still travels — inside the report, which is where a client reads it.
        match Unsolicited::from_pdu(&out[0].pdu, &Limits::DEFAULT) {
            Some(Unsolicited::Report(r)) => assert_eq!(r.rpt_id, "Trip report"),
            other => panic!("not a report: {other:?}"),
        }
    }

    /// The engine writes `SqNum`, `EntryID` and `TimeOfEntry` back into the model as it
    /// publishes. It used to clear the *whole* dirty set afterwards to stop those counters
    /// triggering another report — which also threw away any application write that had
    /// landed in between. With more than one association that is a race, and the write is
    /// lost from the report **and** from the log.
    #[test]
    fn publishing_a_report_does_not_swallow_a_write_that_has_not_been_committed() {
        let (mut ied, mut engine) = enabled();
        // A client asks for a general interrogation…
        ied.write_leaf(&format!("{BLOCK}$GI"), Value::Boolean(true)).expect("write GI");
        ied.take_dirty();
        // …and the application writes a value before that interrogation is served.
        ied.write_leaf(MEMBER, Value::Boolean(true)).expect("write");

        let out = engine.on_timeout(&mut ied, EntryTime::from_unix_millis(WALL_MS), Instant::ZERO);
        assert_eq!(out.len(), 1, "the general interrogation is answered");

        let dirty = ied.take_dirty();
        assert!(dirty.contains_key(MEMBER), "the application's write must survive a report built on the way past");
        assert!(!dirty.keys().any(|k| k.starts_with(&format!("{BLOCK}$"))), "the engine's own bookkeeping must never enter the dirty set");

        // And it is still reported, which is the consequence that matters.
        let out = engine.commit(&mut ied, &dirty, EntryTime::from_unix_millis(WALL_MS), Instant::ZERO);
        assert_eq!(out.len(), 1, "the write that survived produces its own report");
    }
}

/// Controls: the timestamp a command writes, and the command that runs later.
mod controls {
    use iec61850_rs::common::{Clock, Instant, Now, TimeQuality, UtcTime};
    use iec61850_rs::proto::data::{Dbpos, Typed, Value};
    use iec61850_rs::proto::mms::control::ControlRequest;
    use iec61850_rs::server::{Controls, Ied};

    const OBJECT: &str = "IED1LD0/CSWI1$CO$Pos";
    const STATUS_T: &str = "IED1LD0/CSWI1$ST$Pos$t";
    /// 2023-11-14T22:13:20Z.
    const WALL_SECS: u32 = 1_700_000_000;

    fn wall() -> UtcTime {
        UtcTime::from_unix(WALL_SECS, 0, TimeQuality::SYNCHRONIZED)
    }

    fn model() -> Ied {
        Ied::from_scl(super::RELAY, Some("IED1")).expect("load the model")
    }

    fn oper(ctl_val: Dbpos, at: Option<UtcTime>) -> Value {
        let mut r = ControlRequest::new(Value::dbpos(ctl_val), 1, wall());
        r.oper_tm = at;
        r.to_value()
    }

    /// The status timestamp an operate writes is a **date**. It used to be the monotonic
    /// instant reinterpreted as a Unix time, which put every operated breaker's `Pos.t` a few
    /// microseconds after 1970-01-01 — the same defect as the report engine's `TimeOfEntry`,
    /// in a fourth place (D33).
    #[test]
    fn an_operate_stamps_the_status_with_the_wall_clock() {
        let (mut ied, mut controls) = (model(), Controls::default());
        controls.write(1, &mut ied, OBJECT, "Oper", &oper(Dbpos::On, None), Now::new(Instant(9_999), wall())).expect("operate");

        assert_eq!(ied.value("IED1LD0/CSWI1$ST$Pos$stVal").and_then(Typed::as_dbpos), Some(Dbpos::On));
        let t = ied.value(STATUS_T).and_then(Typed::as_utc_time).expect("a status timestamp");
        assert_eq!(t.seconds, WALL_SECS, "the status carries the wall clock, not the monotonic instant");
    }

    /// IEC 61850-7-2 time-activated operate: an `operTm` in the future arms the command
    /// instead of running it. The server used to ignore `operTm` and operate immediately —
    /// which is the one behaviour a time-activated command must not have.
    #[test]
    fn an_operate_with_a_future_oper_tm_waits_for_it() {
        let (mut ied, mut controls) = (model(), Controls::default());
        let at = UtcTime::from_unix(WALL_SECS + 5, 0, TimeQuality::SYNCHRONIZED);
        let now = Instant(1_000_000_000);

        controls.write(1, &mut ied, OBJECT, "Oper", &oper(Dbpos::On, Some(at)), Now::new(now, wall())).expect("the write is accepted");
        assert_eq!(ied.value("IED1LD0/CSWI1$ST$Pos$stVal").and_then(Typed::as_dbpos), Some(Dbpos::Intermediate), "nothing has moved yet");
        assert_eq!(controls.next_timeout(), Some(now.plus_millis(5_000)), "the deadline is monotonic, five seconds out");

        // Not yet.
        controls.on_timeout(&mut ied, now.plus_millis(4_999));
        assert_eq!(ied.value("IED1LD0/CSWI1$ST$Pos$stVal").and_then(Typed::as_dbpos), Some(Dbpos::Intermediate));

        // Now.
        controls.on_timeout(&mut ied, now.plus_millis(5_000));
        assert_eq!(ied.value("IED1LD0/CSWI1$ST$Pos$stVal").and_then(Typed::as_dbpos), Some(Dbpos::On), "the command ran when its time came");
        assert_eq!(controls.next_timeout(), None);
    }

    /// An `operTm` that has already passed is a command for now, not a command to drop.
    #[test]
    fn an_operate_with_a_past_oper_tm_runs_immediately() {
        let (mut ied, mut controls) = (model(), Controls::default());
        let at = UtcTime::from_unix(WALL_SECS - 5, 0, TimeQuality::SYNCHRONIZED);
        controls.write(1, &mut ied, OBJECT, "Oper", &oper(Dbpos::On, Some(at)), Now::new(Instant::ZERO, wall())).expect("operate");
        assert_eq!(ied.value("IED1LD0/CSWI1$ST$Pos$stVal").and_then(Typed::as_dbpos), Some(Dbpos::On));
    }

    /// `Cancel` is the only way to disarm one, so it has to work on a command that has no
    /// selection behind it — a server that cannot disarm what it armed is worse than one that
    /// never armed anything.
    #[test]
    fn cancel_withdraws_a_command_that_is_waiting_for_its_time() {
        let (mut ied, mut controls) = (model(), Controls::default());
        let at = UtcTime::from_unix(WALL_SECS + 5, 0, TimeQuality::SYNCHRONIZED);
        let now = Instant(1_000_000_000);
        controls.write(1, &mut ied, OBJECT, "Oper", &oper(Dbpos::On, Some(at)), Now::new(now, wall())).expect("armed");

        let cancel = ControlRequest::new(Value::dbpos(Dbpos::On), 1, wall()).to_value();
        controls.write(1, &mut ied, OBJECT, "Cancel", &cancel, Now::new(now, wall())).expect("cancelled");
        assert_eq!(controls.next_timeout(), None);

        controls.on_timeout(&mut ied, now.plus_millis(10_000));
        assert_eq!(ied.value("IED1LD0/CSWI1$ST$Pos$stVal").and_then(Typed::as_dbpos), Some(Dbpos::Intermediate), "a cancelled command never runs");
    }

    /// And an association that goes away takes its armed commands with it.
    #[test]
    fn an_association_that_ends_disarms_what_it_armed() {
        let (mut ied, mut controls) = (model(), Controls::default());
        let at = UtcTime::from_unix(WALL_SECS + 5, 0, TimeQuality::SYNCHRONIZED);
        let now = Instant(1_000_000_000);
        controls.write(7, &mut ied, OBJECT, "Oper", &oper(Dbpos::On, Some(at)), Now::new(now, wall())).expect("armed");
        controls.on_association_closed(7);
        controls.on_timeout(&mut ied, now.plus_millis(10_000));
        assert_eq!(ied.value("IED1LD0/CSWI1$ST$Pos$stVal").and_then(Typed::as_dbpos), Some(Dbpos::Intermediate));
    }

    /// The clock is pluggable, which is what lets the tests above pin a date at all.
    #[test]
    fn the_system_clock_reports_a_plausible_date() {
        let now = iec61850_rs::common::SystemClock.now();
        assert!(now.seconds > 1_700_000_000, "the system clock is a wall clock: {now}");
    }
}

/// What the server answers when there is no service to answer for.
mod rejects {
    use iec61850_rs::ber::Cursor;
    use iec61850_rs::common::{Instant, Limits};
    use iec61850_rs::proto::mms::reject::{INVALID_PDU, RejectReason, UNRECOGNIZED_SERVICE};
    use iec61850_rs::proto::mms::{ConfirmedRequest, Mms};
    use iec61850_rs::server::{Acsi, Answer, Ied};

    /// ISO 9506 answers an unrecognised *service* with a reject-PDU, not a confirmed-error:
    /// a confirmed-error says "this service failed", and there was no service. libiec61850's
    /// server draws the same line, so this is also what a client in the field expects.
    #[test]
    fn an_unrecognised_service_is_rejected_rather_than_failed() {
        let mut acsi = Acsi::new(Ied::from_scl(super::RELAY, Some("IED1")).expect("model"));
        // A confirmed request whose service tag is one nothing implements.
        let bytes = [0xBF, 0x7F, 0x00];
        let tlv = Cursor::new(&bytes).next_required().expect("frame");
        let answer = acsi.request(1, Instant::ZERO, &ConfirmedRequest::Other(tlv));
        assert_eq!(answer, Answer::UNSUPPORTED);

        let pdu = answer.encode(77).expect("encode");
        match Mms::parse(&pdu, &Limits::DEFAULT).expect("decode") {
            Mms::Reject(r) => {
                assert_eq!(r.original_invoke_id, Some(77), "the reject names the request it rejects");
                assert_eq!(r.reason, RejectReason::ConfirmedRequest(UNRECOGNIZED_SERVICE));
            }
            other => panic!("not a reject: {other:?}"),
        }
        // The wire shape libiec61850 writes: a4 06 80 01 4d 81 01 01.
        assert_eq!(pdu, [0xA4, 0x06, 0x80, 0x01, 77, 0x81, 0x01, 0x01]);
    }

    /// And a PDU that is not a confirmed request at all is a `pdu-error`, which names the PDU
    /// rather than a service that was never called.
    #[test]
    fn something_that_is_not_a_request_is_a_pdu_error() {
        let pdu = Answer::INVALID_PDU.encode(5).expect("encode");
        match Mms::parse(&pdu, &Limits::DEFAULT).expect("decode") {
            Mms::Reject(r) => assert_eq!(r.reason, RejectReason::PduError(INVALID_PDU)),
            other => panic!("not a reject: {other:?}"),
        }
    }
}

/// Edition is a property of the server, and the server's edition is what its file declares.
mod editions {
    use iec61850_rs::common::Edition;
    use iec61850_rs::model::IedModel;
    use iec61850_rs::server::Ied;

    fn components(ied: &Ied, block: &str) -> Vec<String> {
        ied.node_at(block).map(|n| n.children.iter().map(|c| c.name.clone()).collect()).unwrap_or_default()
    }

    /// `ResvTms` and `Owner` arrived with Edition 2. An Edition 1 server that publishes them
    /// claims a reservation service it does not have — and a client that reads a control
    /// block positionally then reads every field after them at the wrong offset.
    #[test]
    fn an_edition_1_report_control_block_has_no_reservation_attributes() {
        let model = IedModel::from_scl(super::RELAY, Some("IED1")).expect("model");

        let ed2 = Ied::with_edition(model.clone(), Edition::Ed2_1).expect("ed2.1");
        let urcb = components(&ed2, "IED1LD0/LLN0$RP$urcb");
        assert!(urcb.contains(&String::from("Owner")), "Edition 2 has Owner: {urcb:?}");
        assert!(ed2.value("IED1LD0/LLN0$RP$urcb$Owner").is_some());

        let ed1 = Ied::with_edition(model, Edition::Ed1).expect("ed1");
        let urcb = components(&ed1, "IED1LD0/LLN0$RP$urcb");
        assert!(ed1.value("IED1LD0/LLN0$RP$urcb$Owner").is_none(), "no value is seeded for an attribute the edition has not got");
        // Everything an Edition 1 block *does* have is still there, in the order 8-1 Table 39
        // puts it — `Resv` third, not trailing.
        assert_eq!(urcb, ["RptID", "RptEna", "Resv", "DatSet", "ConfRev", "OptFlds", "BufTm", "SqNum", "TrgOps", "IntgPd", "GI"]);
    }

    /// The buffered block loses `ResvTms` as well, and keeps everything Edition 1 does have.
    #[test]
    fn an_edition_1_buffered_block_has_no_resv_tms() {
        let buffered = super::RELAY.replacen(
            r#"<ReportControl name="urcb" datSet="dsTrip" confRev="3" indexed="false""#,
            r#"<ReportControl name="brcb" datSet="dsTrip" confRev="3" buffered="true" indexed="false""#,
            1,
        );
        assert!(buffered.contains("brcb"), "the fixture rewrite must apply");
        let model = IedModel::from_scl(&buffered, Some("IED1")).expect("model");

        let ed2 = components(&Ied::with_edition(model.clone(), Edition::Ed2_1).expect("ed2"), "IED1LD0/LLN0$BR$brcb");
        let ed1 = components(&Ied::with_edition(model, Edition::Ed1).expect("ed1"), "IED1LD0/LLN0$BR$brcb");
        assert!(ed2.contains(&String::from("ResvTms")), "{ed2:?}");
        assert!(!ed1.contains(&String::from("ResvTms")), "{ed1:?}");
        assert!(!ed1.contains(&String::from("Owner")), "{ed1:?}");
        // `EntryID` and `TimeOfEntry` are Edition 1 attributes and stay.
        assert!(ed1.contains(&String::from("EntryID")));
        assert!(ed1.contains(&String::from("TimeOfEntry")));
    }

    /// And a server takes its edition from the file rather than from a second setting.
    #[test]
    fn the_edition_comes_from_the_schema_version_the_file_declares() {
        for (version, revision, release, want) in [
            ("2003", "", "", Edition::Ed1),
            ("2007", "A", "", Edition::Ed2),
            ("2007", "B", "", Edition::Ed2),
            ("2007", "B", "3", Edition::Ed2),
            ("2007", "B", "4", Edition::Ed2_1),
            ("2007", "C", "5", Edition::Ed2_1),
        ] {
            let xml = super::RELAY.replacen(
                r#"version="2007" revision="B" release="4""#,
                &format!(r#"version="{version}" revision="{revision}" release="{release}""#),
                1,
            );
            let model = IedModel::from_scl(&xml, Some("IED1")).expect("model");
            assert_eq!(model.edition(), want, "{version}{revision}{release}");
            assert_eq!(Ied::new(model).expect("ied").edition(), want);
        }
        // A schema this crate has not seen is read as the newest, not the oldest: guessing
        // Edition 1 would silently drop attributes from a modern file.
        assert_eq!(Edition::from_scl_version("2030A"), Edition::Ed2_1);
    }
}

/// A control block's *settings* are a client's to write; its counters are the server's.
///
/// IEC 61850-7-2 Tables 25 and 27 draw the line, and it matters: a client that could write
/// `SqNum` could make a report claim a sequence number the server never sent, and one that
/// could write `ConfRev` could tell every other client the data set had been re-engineered.
#[test]
fn a_control_block_counter_is_not_a_client_s_to_write() {
    let (addr, _h) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");

    // Settings: allowed while the block is disabled.
    c.write("IED1LD0/LLN0$RP$urcb$RptID", Fc::RP, &Value::VisibleString("mine".into())).expect("RptID is a setting");
    c.write("IED1LD0/LLN0$RP$urcb$BufTm", Fc::RP, &Value::Unsigned(50)).expect("BufTm is a setting");
    // `GI` is a service performed *on a running block*, so it is refused while nobody has
    // enabled it — there would be nowhere to send the report.
    assert!(matches!(c.write("IED1LD0/LLN0$RP$urcb$GI", Fc::RP, &Value::Boolean(true)), Err(iec61850_rs::Error::DataAccess(3))));
    c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &iec61850_rs::client::RcbSettings::new()).expect("enable");
    c.write("IED1LD0/LLN0$RP$urcb$GI", Fc::RP, &Value::Boolean(true)).expect("GI on a block this client holds");
    c.disable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("disable");

    for owned in ["SqNum", "ConfRev", "Owner"] {
        let reference = format!("IED1LD0/LLN0$RP$urcb${owned}");
        let result = c.write(&reference, Fc::RP, &Value::Unsigned(9));
        assert!(matches!(result, Err(iec61850_rs::Error::DataAccess(3 | 7))), "{owned} must not be writable, got {result:?}");
    }
    // The same for a log control block: `NewEnt` is what the log has, not what a client says.
    assert!(matches!(c.write("IED1LD0/LLN0$LG$lcb01$NewEnt", Fc::LG, &Value::OctetString(vec![0; 8])), Err(iec61850_rs::Error::DataAccess(3))));
    c.write("IED1LD0/LLN0$LG$lcb01$LogEna", Fc::LG, &Value::Boolean(true)).expect("LogEna is a setting");
    c.release().unwrap();
}

/// `Owner` says which client holds a report control block, which is the first question asked
/// when a second one cannot enable it.
#[test]
fn a_report_control_block_names_the_client_that_holds_it() {
    let (addr, _h) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");
    // Before anybody enables it, nobody owns it.
    assert_eq!(c.read("IED1LD0/LLN0$RP$urcb$Owner", Fc::RP).unwrap(), Value::OctetString(Vec::new()));

    c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &iec61850_rs::client::RcbSettings::new()).expect("enable");
    let owner = c.read("IED1LD0/LLN0$RP$urcb$Owner", Fc::RP).unwrap();
    // The loopback client's address, as the transport reports it.
    assert_eq!(owner, Value::OctetString(vec![127, 0, 0, 1]), "Owner is the holder's network address");

    c.disable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP).expect("disable");
    assert_eq!(c.read("IED1LD0/LLN0$RP$urcb$Owner", Fc::RP).unwrap(), Value::OctetString(Vec::new()));
    c.release().unwrap();
}

/// A bay under test does not act on the control room's commands, and the control room's
/// commands are not silently swallowed as tests.
///
/// `Beh` is the half of the control model a server built only from `ctlModel` gets wrong, and
/// it is what makes the `Test` flag mean something rather than travel and change nothing
/// (IEC 61850-7-2 §20, 7-4 `Beh`).
#[test]
fn a_command_is_refused_when_the_logical_node_is_not_in_a_mode_that_takes_it() {
    use iec61850_rs::client::AddCause;
    use iec61850_rs::proto::data::Dbpos;

    // The breaker's logical node gets a `Beh` the test can move.
    let xml = RELAY.replace(
        r#"<LNodeType id="CSWI_T" lnClass="CSWI"><DO name="Pos" type="DPC_T"/></LNodeType>"#,
        r#"<LNodeType id="CSWI_T" lnClass="CSWI"><DO name="Pos" type="DPC_T"/><DO name="Beh" type="INC_T"/></LNodeType>"#,
    );
    let (addr, handle) = spawn_xml(&xml, 1);
    let mut c = Client::connect(&addr).expect("associate");

    // `on`: an ordinary command works.
    handle.txn().set("IED1LD0/CSWI1$ST$Beh$stVal", Value::Integer(1)).commit();
    c.control("IED1LD0/CSWI1.Pos").execute(&Value::dbpos(Dbpos::On)).expect("on");

    // `test`: the ordinary command is refused and the test one is not.
    handle.txn().set("IED1LD0/CSWI1$ST$Beh$stVal", Value::Integer(3)).commit();
    let refused = c.control("IED1LD0/CSWI1.Pos").execute(&Value::dbpos(Dbpos::Off));
    assert!(matches!(refused, Err(iec61850_rs::Error::ControlRejected { add_cause }) if add_cause == AddCause::BlockedByMode.to_code()), "{refused:?}");
    assert_eq!(handle.read("IED1LD0/CSWI1$ST$Pos$stVal").and_then(|v| v.as_dbpos()), Some(Dbpos::On), "nothing moved");
    c.control("IED1LD0/CSWI1.Pos").test(true).execute(&Value::dbpos(Dbpos::Off)).expect("a test command in test mode");

    // `blocked` and `off`: nothing at all.
    for beh in [2, 5] {
        handle.txn().set("IED1LD0/CSWI1$ST$Beh$stVal", Value::Integer(beh)).commit();
        assert!(c.control("IED1LD0/CSWI1.Pos").execute(&Value::dbpos(Dbpos::On)).is_err(), "Beh {beh} must refuse");
        assert!(c.control("IED1LD0/CSWI1.Pos").test(true).execute(&Value::dbpos(Dbpos::On)).is_err(), "Beh {beh} must refuse a test too");
    }
    c.release().unwrap();
}

/// A GOOSE control block is a named variable like any other, and what it says is what the
/// engineering file says — including the address it publishes to.
#[test]
fn a_goose_control_block_is_served_from_the_file_that_configures_it() {
    const PUBLISHER: &str = include_str!("fixtures/publisher.icd");
    let (addr, _h) = spawn_xml(PUBLISHER, 1);
    let mut c = Client::connect(&addr).expect("associate");

    let names = c.logical_device_directory("IED1LD0").expect("browse");
    for expected in ["LLN0$GO$gcbTrip", "LLN0$GO$gcbTrip$GoEna", "LLN0$GO$gcbTrip$DstAddress", "LLN0$GO$gcbTrip$DstAddress$APPID", "LLN0$GO$gcbTrip$FixedOffs"]
    {
        assert!(names.iter().any(|n| n == expected), "`{expected}` missing from the namespace");
    }
    assert_eq!(c.read("IED1LD0/LLN0$GO$gcbTrip$GoID", Fc::GO).unwrap().as_str(), Some("IED1_Trip"));
    assert_eq!(c.read("IED1LD0/LLN0$GO$gcbTrip$DatSet", Fc::GO).unwrap().as_str(), Some("IED1LD0/LLN0$dsTrip"));
    assert_eq!(c.read("IED1LD0/LLN0$GO$gcbTrip$ConfRev", Fc::GO).unwrap().as_u64(), Some(3));
    assert_eq!(c.read("IED1LD0/LLN0$GO$gcbTrip$DstAddress$Addr", Fc::GO).unwrap(), Value::OctetString(vec![0x01, 0x0C, 0xCD, 0x01, 0x00, 0x05]));
    assert_eq!(c.read("IED1LD0/LLN0$GO$gcbTrip$DstAddress$APPID", Fc::GO).unwrap().as_u64(), Some(5));
    assert_eq!(c.read("IED1LD0/LLN0$GO$gcbTrip$MaxTime", Fc::GO).unwrap().as_u64(), Some(1000));

    // `DstAddress` is a structure, and reading the whole block assembles it in model order.
    let block = c.read("IED1LD0/LLN0$GO$gcbTrip", Fc::GO).unwrap();
    assert_eq!(block.members().map(<[Value]>::len), Some(9), "the nine components of a GoCB");
    assert!(block.member(5).and_then(|a| a.member(0)).is_some(), "DstAddress is the sixth, and a structure");

    // Only the enable flag is a client's to write.
    c.write("IED1LD0/LLN0$GO$gcbTrip$GoEna", Fc::GO, &Value::Boolean(true)).expect("GoEna");
    assert!(matches!(c.write("IED1LD0/LLN0$GO$gcbTrip$ConfRev", Fc::GO, &Value::Unsigned(9)), Err(iec61850_rs::Error::DataAccess(3))));
    c.release().unwrap();
}

/// A log entry says *why* it was made, which is what `reasonCode` on the control block asks
/// for and what turns a list of values into a sequence of events.
#[test]
fn a_log_entry_carries_the_reason_it_was_made() {
    use iec61850_rs::common::EntryTime;

    let (addr, handle) = spawn(1);
    let mut c = Client::connect(&addr).expect("associate");
    handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();

    let page = c.query_log_by_time("IED1LD0/LLN0$GeneralLog", EntryTime::default(), None).expect("query");
    assert_eq!(page.entries.len(), 1);
    let entry = &page.entries[0];
    assert!(entry.reason.is_some_and(iec61850_rs::client::ReasonCode::data_change), "the change that made it, {:?}", entry.reason);
    assert_eq!(entry.variables.len(), 1, "the reason is not one of the variables");
    assert_eq!(entry.variables[0].0, "IED1LD0/PTRC1$ST$Tr$general");
    c.release().unwrap();
}

/// The one place the process bus and the station bus meet inside a single IED.
///
/// A GOOSE subscriber knows whether its stream is alive, whether the publisher wants
/// commissioning, which `confRev` is arriving and whether what arrives is simulated.
/// IEC 61850-7-4 gives that a home — one `LGOS` per subscription — and this is the seam:
/// `SubscriptionStatus` reads it out of the subscriber and `Txn::supervise` publishes it,
/// after which it is an ordinary part of the model that a client reads and a report carries.
#[test]
fn a_goose_subscription_is_supervised_by_the_lgos_the_file_declares() {
    use iec61850_rs::common::{Instant, TimeQuality, UtcTime};
    use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, FrameHeader, MacAddr};
    use iec61850_rs::proto::goose::{GoosePdu, Subscriber, SubscriberConfig, SubscriptionKey};
    use iec61850_rs::server::SubscriptionStatus;

    const SUPERVISION: &str = include_str!("fixtures/supervision.icd");
    const LGOS: &str = "IED2LD0/LGOS1";
    const GOCB: &str = "IED1LD0/LLN0$GO$gcbTrip";

    /// One GOOSE frame of the supervised stream.
    fn frame(st_num: u32, sq_num: u32, nds_com: bool) -> Vec<u8> {
        let pdu = GoosePdu {
            gocb_ref: GOCB.into(),
            time_allowed_to_live: 100,
            dat_set: "IED1LD0/LLN0$dsTrip".into(),
            go_id: None,
            t: UtcTime::from_unix(1_700_000_000, 0, TimeQuality::SYNCHRONIZED),
            st_num,
            sq_num,
            simulation: false,
            conf_rev: 3,
            nds_com,
            all_data: vec![Value::Boolean(true)],
        };
        let h = FrameHeader { dst: MacAddr::GOOSE_BASE, src: MacAddr::default(), vlan: None, ethertype: ETHERTYPE_GOOSE, appid: 1, reserved1: 0, reserved2: 0 };
        h.to_frame(&pdu.encode().unwrap()).unwrap()
    }

    let (addr, handle) = spawn_xml(SUPERVISION, 1);
    let mut c = Client::connect(&addr).expect("associate");

    // `GoCBRef` is a *setting*: it says what this LGOS watches and comes from the file, so
    // the runtime never writes it.
    assert_eq!(c.read("IED2LD0/LGOS1.GoCBRef.setSrcRef", Fc::SP).unwrap().as_str(), Some(GOCB));
    // Before anything has been received the subscription is not live.
    assert_eq!(c.read("IED2LD0/LGOS1.St.stVal", Fc::ST).unwrap().as_bool(), Some(false));

    let mut sub = Subscriber::new(SubscriberConfig::new(SubscriptionKey { dst: MacAddr::GOOSE_BASE, appid: 1, gocb_ref: GOCB.into() }).with_conf_rev(3));

    // A report on the supervision data set, so the LGOS is not just readable but *reported*.
    let settings = iec61850_rs::client::RcbSettings::new().with_useful_fields();
    c.enable_rcb("IED2LD0/LLN0$RP$urcbSup", Fc::RP, &settings).expect("enable");

    // The stream comes up.
    sub.on_frame(Instant::ZERO, &frame(7, 0, false));
    handle.txn().supervise(LGOS, &SubscriptionStatus::from_goose(&sub)).commit();

    assert_eq!(c.read("IED2LD0/LGOS1.St.stVal", Fc::ST).unwrap().as_bool(), Some(true));
    assert_eq!(c.read("IED2LD0/LGOS1.LastStNum.stVal", Fc::ST).unwrap().as_i64(), Some(7));
    assert_eq!(c.read("IED2LD0/LGOS1.ConfRevNum.stVal", Fc::ST).unwrap().as_i64(), Some(3), "what the subscription expects");
    assert_eq!(c.read("IED2LD0/LGOS1.RxConfRevNum.stVal", Fc::ST).unwrap().as_i64(), Some(3), "what is arriving");
    assert_eq!(c.read("IED2LD0/LGOS1.NdsCom.stVal", Fc::ST).unwrap().as_bool(), Some(false));
    // `t` is stamped at the change, from the server's wall clock — not left at the epoch.
    let t = c.read("IED2LD0/LGOS1.St.t", Fc::ST).unwrap();
    assert!(t.as_utc_time().is_some_and(|t| t.seconds > 1_600_000_000), "the status is stamped: {t:?}");

    // …and the change was a report, which is the whole point of modelling it. `dsSup` is
    // `[LGOS1.St, LGOS1.NdsCom, LSVS1.St]`, so index 0 is the subscription coming up.
    let mut reports = drain_reports(&mut c);
    assert!(reports.iter().any(|r| r.entries.iter().any(|e| e.index == 0 && e.value.as_bool() == Some(true))), "{reports:#?}");

    // The publisher starts asking for commissioning.
    sub.on_frame(Instant::ZERO.plus_millis(1), &frame(8, 0, true));
    handle.txn().supervise(LGOS, &SubscriptionStatus::from_goose(&sub)).commit();
    assert_eq!(c.read("IED2LD0/LGOS1.NdsCom.stVal", Fc::ST).unwrap().as_bool(), Some(true));
    reports = drain_reports(&mut c);
    assert!(reports.iter().any(|r| r.entries.iter().any(|e| e.index == 1 && e.value.as_bool() == Some(true))), "{reports:#?}");

    // Nothing new arrives for longer than `timeAllowedtoLive`: the subscription is not live,
    // and `LGOS.St` says so. That is the alarm an operator actually sees.
    sub.on_timeout(Instant::ZERO.plus_millis(500));
    handle.txn().supervise(LGOS, &SubscriptionStatus::from_goose(&sub)).commit();
    assert_eq!(c.read("IED2LD0/LGOS1.St.stVal", Fc::ST).unwrap().as_bool(), Some(false));
    reports = drain_reports(&mut c);
    assert!(
        reports.iter().any(|r| r.entries.iter().any(|e| e.index == 0 && e.value.as_bool() == Some(false))),
        "the subscription going down is reported: {reports:#?}"
    );

    // A poll that changes nothing writes nothing, so a supervision loop does not make every
    // report control block fire once a second.
    assert!(handle.txn().supervise(LGOS, &SubscriptionStatus::from_goose(&sub)).commit().is_empty());
    assert!(c.next_report(Duration::from_millis(150)).expect("poll").is_none(), "an unchanged status is not an event");

    // Which LGOS supervises which subscription is **engineering**, so it comes out of the
    // file too: an application wires a subscriber to its supervision node without typing
    // either name a second time.
    let model = iec61850_rs::model::IedModel::from_scl(SUPERVISION, None).expect("model");
    let nodes = model.supervision();
    assert_eq!(nodes.len(), 2, "one LGOS and one LSVS: {nodes:#?}");
    let lgos = nodes.iter().find(|n| n.is_goose()).expect("the LGOS");
    assert_eq!(lgos.node, LGOS);
    assert_eq!(lgos.control_block.as_deref(), Some(GOCB), "which is exactly the subscription's own gocbRef");
    assert_eq!(lgos.control_block.as_deref(), Some(sub.config().key.gocb_ref.as_str()));
    // The LSVS in this file says nothing about what it watches, which is a finding for a
    // commissioning tool and not an error here.
    assert_eq!(nodes.iter().find(|n| !n.is_goose()).and_then(|n| n.control_block.clone()), None);

    // The `LSVS` type declares only `St` and `ConfRevNum`; it must be given only those.
    let status = SubscriptionStatus { live: true, last_st_num: Some(9), received_conf_rev: Some(4), ..SubscriptionStatus::default() };
    let applied = handle.txn().supervise("IED2LD0/LSVS1", &status).commit();
    assert!(applied.iter().all(Result::is_ok), "only what the file declares is written: {applied:?}");
    assert_eq!(c.read("IED2LD0/LSVS1.St.stVal", Fc::ST).unwrap().as_bool(), Some(true));
    assert!(c.read("IED2LD0/LSVS1.LastStNum.stVal", Fc::ST).is_err(), "the type has no LastStNum, so the server has none");
    c.release().unwrap();
}

/// The log's entries live behind a trait, so an IED that must survive a restart replaces a
/// backend rather than the engine (D5).
///
/// This is the seam, exercised: a store of the caller's own is written to by the trigger
/// evaluation and read back by both ACSI queries, with nothing above the trait changed.
#[test]
fn a_log_is_served_out_of_whatever_store_the_application_supplies() {
    use std::sync::{Arc, Mutex};

    use iec61850_rs::common::EntryTime;
    use iec61850_rs::server::{Entry, LogBounds, LogStore, MemoryLog, NewEntry};

    /// A store that keeps everything and counts what it was asked, so the test can see that
    /// the engine really does go through it rather than round it.
    #[derive(Debug, Default)]
    struct Counting {
        entries: Vec<Entry>,
        appends: usize,
        queries: usize,
    }

    #[derive(Debug, Clone, Default)]
    struct Shared(Arc<Mutex<Counting>>);

    impl LogStore for Shared {
        fn append(&mut self, _log: &str, entry: NewEntry) -> Option<LogBounds> {
            let mut g = self.0.lock().ok()?;
            g.appends += 1;
            let entry_id = g.entries.len() as u64 + 1;
            g.entries.push(Entry { entry_id, occurred: entry.occurred, values: entry.values, reason: entry.reason });
            let oldest = g.entries.first().map(|e| (e.entry_id, e.occurred))?;
            Some(LogBounds { oldest, newest: (entry_id, entry.occurred) })
        }

        fn by_time(&self, _log: &str, from: Option<EntryTime>, to: Option<EntryTime>, limit: usize) -> (Vec<Entry>, bool) {
            let Ok(mut g) = self.0.lock() else { return (Vec::new(), false) };
            g.queries += 1;
            let all: Vec<Entry> =
                g.entries.iter().filter(|e| from.is_none_or(|f| e.occurred >= f) && to.is_none_or(|t| e.occurred <= t)).take(limit).cloned().collect();
            (all, false)
        }

        fn after_entry(&self, _log: &str, entry_id: u64, _at: EntryTime, limit: usize) -> (Vec<Entry>, bool) {
            let Ok(mut g) = self.0.lock() else { return (Vec::new(), false) };
            g.queries += 1;
            (g.entries.iter().filter(|e| e.entry_id > entry_id).take(limit).cloned().collect(), false)
        }

        fn len(&self, _log: &str) -> usize {
            self.0.lock().map(|g| g.entries.len()).unwrap_or_default()
        }
    }

    let store = Shared::default();
    let ied = Ied::from_scl(RELAY, None).expect("load");
    let mut server = Server::bind("127.0.0.1:0", ied).expect("bind");
    server.set_log_store(Box::new(store.clone()));
    let addr = server.local_addr().unwrap().to_string();
    let handle = server.handle();
    std::thread::spawn(move || {
        let _ = server.accept_one();
    });

    for state in [true, false, true] {
        handle.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(state)).commit();
        std::thread::sleep(Duration::from_millis(3));
    }

    let mut c = Client::connect(&addr).expect("associate");
    let page = c.query_log_by_time("IED1LD0/LLN0$GeneralLog", EntryTime::default(), None).expect("query");
    assert_eq!(page.entries.len(), 3, "read back out of the application's own store");
    assert_eq!(page.entries[0].variables[0].0, "IED1LD0/PTRC1$ST$Tr$general");

    // …and the control block's bookkeeping followed the store's own identifiers.
    let lcb = c.read_lcb("IED1LD0/LLN0$LG$lcb01", Fc::LG).expect("read lcb");
    assert_eq!(lcb.new_entry.as_deref(), Some(&3u64.to_be_bytes()[..]));

    let after = c.query_log_after_entry("IED1LD0/LLN0$GeneralLog", &1u64.to_be_bytes(), EntryTime::default()).expect("resume");
    assert_eq!(after.entries.len(), 2);

    let counts = store.0.lock().expect("lock");
    assert_eq!(counts.appends, 3, "every entry went through the trait");
    assert_eq!(counts.queries, 2, "and every query came back out of it");
    drop(counts);

    // A log the model declares but nothing has written to is an **empty** log, not a missing
    // one: the model decides what exists, the store decides what is in it.
    let empty = MemoryLog::for_logs(["IED1LD0/LLN0$GeneralLog".to_string()], 8);
    assert_eq!(empty.len("IED1LD0/LLN0$GeneralLog"), 0);
    c.release().unwrap();
}
