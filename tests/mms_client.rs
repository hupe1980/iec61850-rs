//! The blocking MMS client against a server built from the same association state machine,
//! over a real loopback socket.
//!
//! The capture test in `pcap_mms.rs` proves the state machine follows traffic a real client
//! and a real server exchanged. It cannot prove the *socket* half: that the TPKT reader
//! survives however TCP happens to split the stream, that `poll_transmit` output reaches the
//! wire in order, that a report arriving while a request is outstanding is kept rather than
//! dropped. That needs two ends and a socket, and the sans-IO core means the second end is
//! twenty lines rather than a second implementation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use common::spawn_mms_server as spawn;
use iec61850_rs::Fc;
use iec61850_rs::client::{Client, ClientConfig};
use iec61850_rs::proto::data::{Typed, Value};
use iec61850_rs::proto::mms::association::AssociationConfig;

#[test]
fn a_client_associates_browses_reads_and_writes() {
    let addr = spawn(0);
    let mut c = Client::connect(&addr).expect("associate");
    let n = c.negotiated().expect("negotiated parameters");
    assert_eq!(n.mms_context, 3);
    assert!(n.max_pdu > 0);

    assert_eq!(c.identify().unwrap().vendor, "hupe1980");
    assert_eq!(c.server_directory().unwrap(), ["IED1LD0"]);

    // Three names across two pages: `moreFollows` has to be followed, or a client silently
    // sees a third of a real IED's model.
    let names = c.logical_device_directory("IED1LD0").unwrap();
    assert_eq!(names, ["LLN0$ST$Beh$stVal", "MMXU1$MX$TotW$mag$f", "PTRC1$ST$Tr$general"]);

    assert_eq!(c.data_set_directory("IED1LD0").unwrap(), ["LLN0$dsTrip"]);
    assert_eq!(c.data_set_members("IED1LD0", "LLN0$dsTrip").unwrap(), ["IED1LD0/PTRC1$ST$Tr$general"]);

    // A dotted reference plus a functional constraint is the ACSI form; the client maps it.
    let v = c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX).unwrap();
    assert_eq!(v.as_f64(), Some(1.5));
    // And the MMS form is accepted unchanged.
    assert_eq!(c.read("IED1LD0/MMXU1$MX$TotW$mag$f", Fc::ST).unwrap().as_f64(), Some(1.5));

    let many = c.read_many(&[("IED1LD0/MMXU1.TotW.mag.f", Fc::MX), ("IED1LD0/PTRC1.Tr.general", Fc::ST)]).unwrap();
    assert_eq!(many.len(), 2, "one round trip, two values");
    assert_eq!(c.read_data_set("IED1LD0", "LLN0$dsTrip").unwrap().len(), 1);

    c.write("IED1LD0/GGIO1.SPCSO1.stVal", Fc::ST, &Value::Boolean(true)).unwrap();

    // Eleven, not ten: `logical_device_directory` needed two because the server paged it.
    assert_eq!(c.stats().requests_sent, 11);
    assert_eq!(c.stats().responses_received, 11);
    c.release().unwrap();
}

#[test]
fn reports_that_arrive_during_a_request_are_kept_rather_than_dropped() {
    let addr = spawn(3);
    let mut c = Client::connect(&addr).expect("associate");
    // The server pushed three reports the moment the association came up, so they are
    // interleaved with the handshake and with whatever is asked next.
    assert_eq!(c.identify().unwrap().model, "iec61850-rs");
    let mut seen = 0;
    while let Some(r) = c.next_report(Duration::from_millis(500)).unwrap() {
        assert_eq!(r.rpt_id, "IED1LD0/LLN0$RP$urcb01");
        seen += 1;
        if seen == 3 {
            break;
        }
    }
    assert_eq!(seen, 3, "a client that is reading must not lose a report");
    assert_eq!(c.stats().reports_received, 3);
    c.release().unwrap();
}

#[test]
fn a_server_that_is_not_there_is_an_error_and_not_a_hang() {
    // Port 1 on loopback: nothing listens, and the connect must fail quickly.
    let cfg = ClientConfig { connect_timeout: Duration::from_millis(250), ..ClientConfig::default() };
    let started = std::time::Instant::now();
    assert!(Client::connect_with("127.0.0.1:1", &cfg).is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn a_peer_that_hangs_up_mid_association_is_reported_rather_than_waited_on() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        // Accept the connection and drop it without answering the COTP CR.
        let _ = listener.accept();
    });
    let cfg =
        ClientConfig { association: AssociationConfig { connect_timeout_ms: 500, ..AssociationConfig::default() }, connect_timeout: Duration::from_secs(2) };
    let e = Client::connect_with(&addr, &cfg).unwrap_err();
    assert!(matches!(e, iec61850_rs::Error::Io(_)), "{e:?}");
}

#[test]
fn a_report_control_block_is_read_configured_enabled_and_decoded() {
    use common::{RCB_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::{RcbSettings, TrgOps};

    let addr = spawn_mms_server_with(ServerBehaviour::default());
    let mut c = Client::connect(&addr).expect("associate");

    // Read it as it was engineered. `Resv` exists on an unbuffered block; `EntryID` does not,
    // and the server says so per-variable rather than failing the whole read.
    let before = c.read_rcb(RCB_REFERENCE, Fc::RP).unwrap();
    assert_eq!(before.reference, RCB_REFERENCE);
    assert!(!before.buffered && !before.rpt_ena);
    assert_eq!(before.data_set.as_deref(), Some(common::DATA_SET_REFERENCE));
    assert_eq!(before.conf_rev, Some(3));
    assert_eq!(before.resv, Some(false), "an unbuffered block has Resv");
    assert_eq!(before.entry_id, None, "and no EntryID");

    // Configure and enable it. The settings go out first and `RptEna` second, because a
    // server refuses every other write while reporting is on.
    let settings = RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS);
    let rcb = c.enable_rcb(RCB_REFERENCE, Fc::RP, &settings).expect("enable");
    assert!(rcb.rpt_ena, "the server enabled it");
    assert_eq!(rcb.trg_ops, Some(TrgOps::EVENTS));
    let opt = rcb.opt_flds.expect("OptFlds");
    assert!(opt.sequence_number() && opt.report_time_stamp() && opt.data_set_name() && opt.reason_for_inclusion() && opt.conf_revision());
    assert!(!opt.data_reference(), "not asked for, so not set");

    // Ask for a general interrogation and decode the report it produces.
    c.general_interrogation(RCB_REFERENCE, Fc::RP).unwrap();
    let r = c.next_report(Duration::from_secs(2)).unwrap().expect("a report");
    assert_eq!(r.rpt_id, RCB_REFERENCE);
    assert_eq!(r.data_set.as_deref(), Some(common::DATA_SET_REFERENCE));
    assert_eq!((r.seq_num, r.conf_rev), (Some(1), Some(3)));
    assert!(r.time_of_entry.is_some());
    assert!(!r.is_partial());

    // Two members, both included, both with a reason. The index is what names them when
    // `data-reference` was not asked for.
    assert_eq!(r.data_set_len(), 2);
    assert_eq!(r.entries.len(), 2);
    assert_eq!(r.entries.iter().map(|e| e.index).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(r.entries[0].value.as_bool(), Some(true));
    assert!(r.entries[0].reason.expect("reason").general_interrogation(), "this report was asked for");
    assert!(r.entries[0].reference.is_none(), "OptFlds did not ask for references");
    assert!(r.entries[1].value.as_quality().is_some());

    // A write to a configured attribute while reporting is on is refused by the server.
    let denied = c.write_rcb(RCB_REFERENCE, Fc::RP, &RcbSettings::new().with_buf_tm(50));
    assert!(matches!(denied, Err(iec61850_rs::Error::DataAccess(3))), "{denied:?}");

    c.disable_rcb(RCB_REFERENCE, Fc::RP).unwrap();
    assert!(!c.read_rcb(RCB_REFERENCE, Fc::RP).unwrap().rpt_ena);
    c.release().unwrap();
}

#[test]
fn a_report_asking_for_references_gets_them() {
    use common::{RCB_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::{OptFlds, RcbSettings, TrgOps};

    let addr = spawn_mms_server_with(ServerBehaviour::default());
    let mut c = Client::connect(&addr).expect("associate");
    let settings = RcbSettings {
        opt_flds: Some(OptFlds::NONE.with_data_reference(true).with_sequence_number(true).with_entry_id(true).with_buffer_overflow(true)),
        trg_ops: Some(TrgOps::EVENTS),
        ..RcbSettings::new()
    };
    c.enable_rcb(RCB_REFERENCE, Fc::RP, &settings).expect("enable");
    c.general_interrogation(RCB_REFERENCE, Fc::RP).unwrap();
    let r = c.next_report(Duration::from_secs(2)).unwrap().expect("a report");
    // Every field the flags asked for is there, and nothing else is.
    assert_eq!(r.entries[0].reference.as_deref(), Some("IED1LD0/PTRC1$ST$Tr$general"));
    assert_eq!(r.entries[1].reference.as_deref(), Some("IED1LD0/PTRC1$ST$Tr$q"));
    assert_eq!(r.buf_ovfl, Some(false));
    assert_eq!(r.entry_id.as_ref().map(Vec::len), Some(8));
    assert_eq!(r.data_set, None, "not asked for");
    assert_eq!(r.conf_rev, None);
    assert!(r.entries[0].reason.is_none(), "not asked for either");
    c.release().unwrap();
}

#[test]
fn a_direct_control_is_one_write() {
    use common::{CONTROL_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::{Check, ControlModel, OriginCategory};
    use iec61850_rs::proto::data::Dbpos;

    let addr = spawn_mms_server_with(ServerBehaviour::default());
    let mut c = Client::connect(&addr).expect("associate");
    let outcome = c
        .control(CONTROL_REFERENCE)
        .model(ControlModel::DirectNormal)
        .origin(OriginCategory::StationControl, "hmi-1")
        .check(Check { synchro: true, interlock: true })
        .execute(&Value::dbpos(Dbpos::On))
        .expect("operate");
    assert!(outcome.is_none(), "normal security has no command termination");
    assert_eq!(c.stats().requests_sent, 1, "one Write and nothing else");
    c.release().unwrap();
}

#[test]
fn select_before_operate_with_enhanced_security_waits_for_the_termination() {
    use common::{CONTROL_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::ControlModel;
    use iec61850_rs::proto::data::Dbpos;

    let addr = spawn_mms_server_with(ServerBehaviour { enhanced_control: true, ..ServerBehaviour::default() });
    let mut c = Client::connect(&addr).expect("associate");
    let t = c
        .control(CONTROL_REFERENCE)
        .model(ControlModel::SboEnhanced)
        .timeout(Duration::from_secs(2))
        .execute(&Value::dbpos(Dbpos::On))
        .expect("operate")
        .expect("a command termination");
    assert!(t.is_positive());
    assert_eq!(t.control_object(), "IED1LD0/CSWI1$CO$Pos$Oper");
    // SBOw then Oper: two writes, and the same ctlNum on both.
    assert_eq!(c.stats().requests_sent, 2);
    c.release().unwrap();
}

#[test]
fn a_refused_control_names_its_add_cause_rather_than_reporting_success() {
    use common::{CONTROL_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::{AddCause, ControlModel};
    use iec61850_rs::proto::data::Dbpos;

    // The write succeeds and the *command* fails, which is the whole reason enhanced
    // security exists and the case a thin wrapper reports as success.
    let addr =
        spawn_mms_server_with(ServerBehaviour { enhanced_control: true, refuse_control: Some(AddCause::BlockedByInterlocking), ..ServerBehaviour::default() });
    let mut c = Client::connect(&addr).expect("associate");
    let e = c.control(CONTROL_REFERENCE).model(ControlModel::DirectEnhanced).timeout(Duration::from_secs(2)).execute(&Value::dbpos(Dbpos::On)).unwrap_err();
    match e {
        iec61850_rs::Error::ControlRejected { add_cause } => {
            assert_eq!(AddCause::from_code(add_cause), AddCause::BlockedByInterlocking);
        }
        other => panic!("expected a rejection, got {other:?}"),
    }
    c.release().unwrap();
}

#[test]
fn a_report_and_a_termination_do_not_consume_each_other() {
    use common::{CONTROL_REFERENCE, RCB_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::{ControlModel, RcbSettings, TrgOps};
    use iec61850_rs::proto::data::Dbpos;

    // Reports and command terminations arrive on the same channel. A client waiting for one
    // must not swallow the other — which is why the queue is scanned rather than popped.
    let addr = spawn_mms_server_with(ServerBehaviour { enhanced_control: true, ..ServerBehaviour::default() });
    let mut c = Client::connect(&addr).expect("associate");
    c.enable_rcb(RCB_REFERENCE, Fc::RP, &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS)).expect("enable");
    c.general_interrogation(RCB_REFERENCE, Fc::RP).unwrap();

    // The report is now queued. Operate: `execute` must take the termination past it.
    let t = c
        .control(CONTROL_REFERENCE)
        .model(ControlModel::DirectEnhanced)
        .timeout(Duration::from_secs(2))
        .execute(&Value::dbpos(Dbpos::Off))
        .expect("operate")
        .expect("a termination");
    assert!(t.is_positive());

    // And the report is still there, untouched.
    let r = c.next_report(Duration::from_millis(200)).unwrap().expect("the report survived");
    assert_eq!(r.rpt_id, RCB_REFERENCE);
    assert_eq!(c.buffered_unsolicited(), 0);
    assert!(c.next_unsolicited(Duration::from_millis(50)).unwrap().is_none(), "and nothing else was invented");
    c.release().unwrap();
}

#[test]
fn the_engineering_file_can_be_the_client_configuration() {
    use iec61850_rs::client::ClientConfig;
    use iec61850_rs::scl::Scl;

    // `Communication/ConnectedAP` is where an association is engineered. Reading the
    // selectors out of it is the same rule the process bus already follows.
    let scd = r#"<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
  <Communication>
    <SubNetwork name="station">
      <ConnectedAP iedName="IED1" apName="S1">
        <Address>
          <P type="IP">10.0.0.5</P>
          <P type="OSI-TSEL">0002</P>
          <P type="OSI-SSEL">0001</P>
          <P type="OSI-PSEL">00000001</P>
          <P type="OSI-AP-Title">1,3,9999,23</P>
          <P type="OSI-AE-Qualifier">12</P>
        </Address>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="IED1"><AccessPoint name="S1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="T1"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="T1" lnClass="LLN0"/>
  </DataTypeTemplates>
</SCL>"#;
    let scl = Scl::parse(scd).expect("parse");
    let (cfg, ip) = ClientConfig::from_scl(&scl, "IED1", None).expect("addressing");
    assert_eq!(ip.as_deref(), Some("10.0.0.5"), "the file says where to connect");
    let remote = &cfg.association.remote;
    assert_eq!(remote.t_sel, [0x00, 0x02], "the transport selector, as octets not as a string");
    assert_eq!(remote.s_sel, [0x00, 0x01]);
    assert_eq!(remote.p_sel, [0x00, 0x00, 0x00, 0x01]);
    assert_eq!(remote.ap_title.as_deref(), Some(&[1, 3, 9999, 23][..]), "the AP-title, as arcs");
    assert_eq!(remote.ae_qualifier, Some(12));

    // An IED the file does not address is an error, not a silent default: connecting with
    // the wrong selectors is refused by the server at a layer whose message says nothing.
    assert!(ClientConfig::from_scl(&scl, "IED2", None).is_err());
}

#[test]
fn a_termination_for_another_command_is_not_mistaken_for_this_one() {
    use common::{CONTROL_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::ControlModel;
    use iec61850_rs::proto::data::Dbpos;

    // The only thing tying a command termination to its command is the `ctlNum` both carry.
    // A client that takes "the next one" reports that a breaker closed when it was a
    // different breaker — so the server sends a stale one first and it must be stepped over.
    let addr = spawn_mms_server_with(ServerBehaviour { enhanced_control: true, stale_termination: true, ..ServerBehaviour::default() });
    let mut c = Client::connect(&addr).expect("associate");
    let mut control = c.control(CONTROL_REFERENCE).model(ControlModel::DirectEnhanced).timeout(Duration::from_secs(2));
    let t = control.execute(&Value::dbpos(Dbpos::On)).expect("operate").expect("a termination");
    let mine = control.current_ctl_num().expect("a ctlNum was taken");
    assert_eq!(t.ctl_num(), mine, "the termination for this command, not the one before it");

    // And the stale one is still queued rather than silently thrown away.
    let stale = c.next_termination(Duration::from_millis(200)).unwrap().expect("the stale termination survived");
    assert_eq!(stale.ctl_num(), mine.wrapping_add(100));
    c.release().unwrap();
}

#[test]
fn enabling_a_control_block_twice_takes_it_over_rather_than_failing() {
    use common::{RCB_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::{RcbSettings, TrgOps};

    // A server refuses every write but `RptEna` while reporting is on, so re-configuring an
    // enabled block has to disable it first. A client that does not is a client that works
    // exactly once per connection.
    let addr = spawn_mms_server_with(ServerBehaviour::default());
    let mut c = Client::connect(&addr).expect("associate");
    let settings = RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS);
    assert!(c.enable_rcb(RCB_REFERENCE, Fc::RP, &settings).expect("first enable").rpt_ena);

    let again =
        c.enable_rcb(RCB_REFERENCE, Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::NONE.with_integrity(true)).with_intg_pd(2000)).expect("second enable");
    assert!(again.rpt_ena);
    assert_eq!(again.trg_ops, Some(TrgOps::NONE.with_integrity(true)), "the new settings took");
    assert_eq!(again.intg_pd, Some(2000));
    c.release().unwrap();
}

#[test]
fn a_status_only_object_is_refused_without_a_round_trip() {
    use common::{CONTROL_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::{AddCause, ControlModel};

    let addr = spawn_mms_server_with(ServerBehaviour::default());
    let mut c = Client::connect(&addr).expect("associate");
    let before = c.stats().requests_sent;
    let e = c.control(CONTROL_REFERENCE).model(ControlModel::StatusOnly).execute(&Value::Boolean(true)).unwrap_err();
    assert!(matches!(e, iec61850_rs::Error::ControlRejected { add_cause } if AddCause::from_code(add_cause) == AddCause::NotSupported), "{e:?}");
    assert_eq!(c.stats().requests_sent, before, "and nothing was put on the wire");
    c.release().unwrap();
}

#[test]
fn a_segmented_report_reaches_the_application_whole_or_not_at_all() {
    use common::{RCB_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::{RcbSettings, TrgOps};

    // The server splits every report into one segment per data-set member. A client that
    // ignores `SubSeqNum`/`MoreSegmentsFollow` sees two reports with one member each and no
    // sign that either is half of something — which is a data set silently read wrong.
    let addr = spawn_mms_server_with(ServerBehaviour { reports: 1, segment_reports: true, ..ServerBehaviour::default() });
    let mut c = Client::connect(&addr).expect("associate");
    c.enable_rcb(RCB_REFERENCE, Fc::RP, &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS)).expect("enable");

    let report = c.next_report(Duration::from_secs(2)).unwrap().expect("a report");
    assert_eq!(report.entries.len(), 2, "both segments, joined");
    assert_eq!(report.entries.iter().map(|e| e.index).collect::<Vec<_>>(), [0, 1]);
    assert!(!report.is_partial());
    assert_eq!(report.data_set_len(), 2);
    assert_eq!(c.report_assembler_stats().reassembled, 1);
    assert!(c.next_report(Duration::from_millis(100)).unwrap().is_none(), "and there is no second, half report behind it");
    c.release().unwrap();
}

#[test]
fn a_variables_type_is_read_from_the_server_rather_than_assumed() {
    use common::{CONTROL_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::client::TypeSpec;

    let addr = spawn_mms_server_with(ServerBehaviour::default());
    let mut c = Client::connect(&addr).expect("associate");

    // The component order of an `Oper` is what a client has to get right to operate a
    // breaker, and this is how it learns it without the SCD.
    let oper = c.variable_type("IED1LD0/CSWI1.Pos.Oper", Fc::CO).expect("the Oper type");
    assert_eq!(oper.component_names(), ["ctlVal", "origin", "ctlNum", "T", "Test", "Check"]);
    assert_eq!(oper.component("Check"), Some(&TypeSpec::BitString(2)));
    assert_eq!(oper.component("origin").map(TypeSpec::component_names), Some(vec!["orCat", "orIdent"]));

    let measurement = c.variable_type("IED1LD0/MMXU1.TotW.mag.f", Fc::MX).expect("a measurement type");
    assert_eq!(measurement, TypeSpec::FloatingPoint { format_width: 32, exponent_width: 8 });
    let _ = CONTROL_REFERENCE;
    c.release().unwrap();
}

#[test]
fn a_data_set_is_created_and_deleted_and_a_refusal_is_not_success() {
    use common::{ServerBehaviour, spawn_mms_server_with};

    let addr = spawn_mms_server_with(ServerBehaviour::default());
    let mut c = Client::connect(&addr).expect("associate");
    c.create_data_set("IED1LD0/LLN0$dsTemp", &[("IED1LD0/PTRC1.Tr.general", Fc::ST), ("IED1LD0/PTRC1.Tr.q", Fc::ST)]).expect("create");
    c.delete_data_set("IED1LD0/LLN0$dsTemp").expect("delete");

    // A data set the server matches but will not delete is *not* success: the difference
    // between "gone" and "refused" is the whole answer.
    let e = c.delete_data_set("IED1LD0/LLN0$dsTrip").unwrap_err();
    assert!(matches!(e, iec61850_rs::Error::DataAccess(3)), "{e:?}");
    // And one it has never heard of is not found.
    assert!(matches!(c.delete_data_set("IED1LD0/LLN0$dsNope").unwrap_err(), iec61850_rs::Error::NotFound(_)));
    c.release().unwrap();
}

#[test]
fn a_file_is_listed_read_and_deleted_and_its_handle_is_given_back() {
    use common::{FILE_CONTENTS, FILE_REFERENCE, ServerBehaviour, spawn_mms_server_with};

    let addr = spawn_mms_server_with(ServerBehaviour::default());
    let mut c = Client::connect(&addr).expect("associate");
    let files = c.file_directory(None).expect("directory");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, FILE_REFERENCE);
    assert_eq!(files[0].size as usize, FILE_CONTENTS.len());
    assert_eq!(files[0].last_modified.as_deref(), Some("20240131T101500Z"));

    // The server hands the file over eight octets at a time; the loop is the client's.
    assert_eq!(c.read_file(FILE_REFERENCE, 64 * 1024).expect("read"), FILE_CONTENTS);
    // A file larger than the caller will hold is an error, and the handle is still closed —
    // the server asserts that, because a leaked frsmID is a file left open in a relay.
    assert!(matches!(c.read_file(FILE_REFERENCE, 4).unwrap_err(), iec61850_rs::Error::LimitExceeded { .. }));
    assert_eq!(c.read_file(FILE_REFERENCE, 64 * 1024).expect("read again"), FILE_CONTENTS, "and the next open still works");
    c.delete_file(FILE_REFERENCE).expect("delete");
    c.release().unwrap();
}

#[test]
fn a_log_is_read_by_time_and_resumed_after_the_last_entry_seen() {
    use common::{LCB_REFERENCE, LOG_REFERENCE, ServerBehaviour, spawn_mms_server_with};
    use iec61850_rs::common::EntryTime;

    let addr = spawn_mms_server_with(ServerBehaviour::default());
    let mut c = Client::connect(&addr).expect("associate");

    // The control block says where the log starts and what it logs, in one round trip.
    let lcb = c.read_lcb(LCB_REFERENCE, Fc::LG).expect("log control block");
    assert!(lcb.log_ena);
    assert_eq!(lcb.log_ref.as_deref(), Some(LOG_REFERENCE));
    let (oldest_id, oldest_time) = lcb.oldest().expect("the oldest entry");
    assert_eq!(oldest_id, [0, 0, 0, 0, 0, 0, 0, 1]);

    let page = c.query_log_by_time(LOG_REFERENCE, oldest_time, None).expect("query by time");
    assert_eq!(page.entries.len(), 1);
    assert!(page.more_follows);
    assert_eq!(page.entries[0].variables.len(), 1);
    assert_eq!(page.entries[0].variables[0].0, "IED1LD0/PTRC1$ST$Tr$general");
    assert_eq!(page.entries[0].variables[0].1.as_bool(), Some(true));

    // Resuming picks up exactly after it, which is what survives a lost association.
    let (id, time) = page.entries[0].resume_point();
    let next = c.query_log_after_entry(LOG_REFERENCE, &id, time).expect("query after entry");
    assert_eq!(next.entries.len(), 1);
    assert!(!next.more_follows);
    assert_eq!(next.entries[0].annotation.as_deref(), Some("power up"));

    // And the paging loop does the same thing on its own.
    let whole = c.read_whole_log(LOG_REFERENCE, EntryTime::default(), 1000).expect("whole log");
    assert_eq!(whole.len(), 2);
    c.release().unwrap();
}

#[test]
fn a_setting_group_is_selected_written_and_confirmed_in_that_order() {
    use common::{SGCB_REFERENCE, ServerBehaviour, spawn_mms_server_with};

    let addr = spawn_mms_server_with(ServerBehaviour::default());
    let mut c = Client::connect(&addr).expect("associate");
    let sgcb = c.read_sgcb(SGCB_REFERENCE).expect("setting group control block");
    assert_eq!((sgcb.num_of_sg, sgcb.act_sg, sgcb.edit_sg), (Some(4), Some(1), Some(0)));

    // The whole sequence: select the edit group, write into it, confirm, release.
    c.edit_setting_group(SGCB_REFERENCE, 2, &[("IED1LD0/PTOC1.StrVal.setMag.f", Value::Float32(1.25))]).expect("edit");
    let after = c.read_sgcb(SGCB_REFERENCE).expect("read back");
    assert!(after.cnf_edit == Some(true), "the edit was confirmed: {after:?}");
    assert_eq!(after.edit_sg, Some(0), "and the reservation was released");

    // Activating a group is a write of its own.
    c.select_active_setting_group(SGCB_REFERENCE, 3).expect("activate");
    assert_eq!(c.read_sgcb(SGCB_REFERENCE).expect("read back").act_sg, Some(3));
    c.release().unwrap();
}
