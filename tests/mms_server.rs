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
pub const RELAY: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="relay"/>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
      <DataSet name="dsTrip">
        <FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/>
        <FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="q" fc="ST"/>
      </DataSet>
      <ReportControl name="urcb" datSet="dsTrip" confRev="3" indexed="false" bufTime="0">
        <TrgOps dchg="true" qchg="true"/>
        <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true" configRef="true"/>
      </ReportControl>
      <Log name="GeneralLog"/>
      <LogControl name="lcb01" datSet="dsTrip" logName="GeneralLog"><TrgOps dchg="true"/></LogControl>
      <SettingControl numOfSGs="4" actSG="1"/>
    </LN0>
    <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
    <LN lnClass="MMXU" inst="1" prefix="" lnType="MMXU_T"/>
    <LN lnClass="CSWI" inst="1" prefix="" lnType="CSWI_T">
      <DOI name="Pos"><DAI name="ctlModel"><Val>direct-with-normal-security</Val></DAI></DOI>
    </LN>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="INC_T"/></LNodeType>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <LNodeType id="MMXU_T" lnClass="MMXU"><DO name="TotW" type="MV_T"/></LNodeType>
    <LNodeType id="CSWI_T" lnClass="CSWI"><DO name="Pos" type="DPC_T"/></LNodeType>
    <DOType id="INC_T" cdc="INC">
      <DA name="stVal" fc="ST" bType="Enum" type="Mod_E"/>
      <DA name="q" fc="ST" bType="Quality"/>
      <DA name="t" fc="ST" bType="Timestamp"/>
    </DOType>
    <DOType id="ACT_T" cdc="ACT">
      <DA name="general" fc="ST" bType="BOOLEAN"/>
      <DA name="q" fc="ST" bType="Quality"/>
      <DA name="t" fc="ST" bType="Timestamp"/>
    </DOType>
    <DOType id="MV_T" cdc="MV">
      <DA name="mag" fc="MX" bType="Struct" type="AnalogueValue_T"/>
      <DA name="q" fc="MX" bType="Quality"/>
    </DOType>
    <DOType id="DPC_T" cdc="DPC">
      <DA name="stVal" fc="ST" bType="Dbpos"/>
      <DA name="q" fc="ST" bType="Quality"/>
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModel_E"/>
      <DA name="Oper" fc="CO" bType="Struct" type="Oper_T"/>
      <DA name="SBOw" fc="CO" bType="Struct" type="Oper_T"/>
      <DA name="Cancel" fc="CO" bType="Struct" type="Cancel_T"/>
      <DA name="SBO" fc="CO" bType="ObjRef"/>
    </DOType>
    <DAType id="AnalogueValue_T"><BDA name="f" bType="FLOAT32"/></DAType>
    <DAType id="Oper_T">
      <BDA name="ctlVal" bType="Dbpos"/>
      <BDA name="origin" bType="Struct" type="Originator_T"/>
      <BDA name="ctlNum" bType="INT8U"/>
      <BDA name="T" bType="Timestamp"/>
      <BDA name="Test" bType="BOOLEAN"/>
      <BDA name="Check" bType="Check"/>
    </DAType>
    <DAType id="Cancel_T">
      <BDA name="ctlVal" bType="Dbpos"/>
      <BDA name="origin" bType="Struct" type="Originator_T"/>
      <BDA name="ctlNum" bType="INT8U"/>
      <BDA name="T" bType="Timestamp"/>
      <BDA name="Test" bType="BOOLEAN"/>
    </DAType>
    <DAType id="Originator_T"><BDA name="orCat" bType="Enum" type="OrCat_E"/><BDA name="orIdent" bType="Octet64"/></DAType>
    <EnumType id="Mod_E"><EnumVal ord="1">on</EnumVal></EnumType>
    <EnumType id="OrCat_E"><EnumVal ord="3">remote-control</EnumVal></EnumType>
    <EnumType id="CtlModel_E"><EnumVal ord="1">direct-with-normal-security</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;

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

    // A write reaches the model, and the application sees the same value the client wrote.
    c.write("IED1LD0/PTRC1.Tr.general", Fc::ST, &Value::Boolean(true)).unwrap();
    assert_eq!(handle.read("IED1LD0/PTRC1$ST$Tr$general").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(c.read("IED1LD0/PTRC1.Tr.general", Fc::ST).unwrap().as_bool(), Some(true));

    // And so does an update from the application.
    handle.txn().set("IED1LD0/MMXU1$MX$TotW$mag$f", Value::Float32(1234.5)).commit();
    assert_eq!(c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX).unwrap().as_f64(), Some(1234.5));

    // A name the model does not have is object-non-existent, not a guess.
    assert!(matches!(c.read("IED1LD0/PTRC1.Tr.nosuch", Fc::ST), Err(iec61850_rs::Error::DataAccess(10))));
    // …and a value of the wrong type is refused rather than quietly changing the model.
    assert!(matches!(c.write("IED1LD0/PTRC1.Tr.general", Fc::ST, &Value::Integer(1)), Err(iec61850_rs::Error::DataAccess(7))));
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

    a.write("IED1LD0/PTRC1.Tr.general", Fc::ST, &Value::Boolean(true)).unwrap();
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
    assert_eq!(r.seq_num, Some(1));
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
    assert_eq!(r.seq_num, Some(2));

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

fn spawn_xml(xml: &str, clients: usize) -> (String, ServerHandle) {
    let ied = Ied::from_scl(xml, Some("IED1")).expect("load");
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
    <DOType id="ASG_T" cdc="ASG"><DA name="setMag" fc="SG" bType="Struct" type="AV_T"/><DA name="setMag" fc="SE" bType="Struct" type="AV_T"/></DOType>
    <DAType id="AV_T"><BDA name="f" bType="FLOAT32"/></DAType>
  </DataTypeTemplates>
</SCL>"#;

#[test]
fn setting_groups_activate_edit_and_confirm() {
    let (addr, handle) = spawn_xml(SETTINGS, 1);
    let mut c = Client::connect(&addr).expect("associate");

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
    // And an edit with no group selected has nowhere to go.
    assert!(matches!(c.write_edit_setting("IED1LD0/PTOC1.StrVal.setMag.f", &Value::Float32(9.0)), Err(iec61850_rs::Error::DataAccess(3))));

    // The whole sequence: select group 2, write it, confirm, release.
    c.edit_setting_group("IED1LD0/LLN0$SP$SGCB", 2, &[("IED1LD0/PTOC1.StrVal.setMag.f", Value::Float32(7.5))]).expect("edit");
    // Group 3 is still in force and untouched…
    assert_eq!(handle.read("IED1LD0/PTOC1$SG$StrVal$setMag$f").and_then(|v| v.as_f64()), Some(3.0));
    // …and group 2 now holds what was written, which activating it proves.
    c.select_active_setting_group("IED1LD0/LLN0$SP$SGCB", 2).expect("activate 2");
    assert_eq!(handle.read("IED1LD0/PTOC1$SG$StrVal$setMag$f").and_then(|v| v.as_f64()), Some(7.5));

    // A group number the device does not have is refused rather than clamped.
    assert!(c.select_active_setting_group("IED1LD0/LLN0$SP$SGCB", 9).is_err());
    c.release().unwrap();
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
