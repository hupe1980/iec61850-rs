//! A real IEC 61850 server from an SCL file, and a real client against it — in one process,
//! with no device, no network interface and no arguments.
//!
//! This is the whole design in forty lines: the engineering file is the model, the model is
//! the namespace, and both ends of the association are the same state machine in different
//! roles. Run it with `cargo run --example server_from_scl`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::time::Duration;

use iec61850_rs::Fc;
use iec61850_rs::client::{Client, ControlModel, RcbSettings, TrgOps};
use iec61850_rs::proto::data::{Dbpos, Typed, Value};
use iec61850_rs::server::{Ied, Server, Stage};

/// One bay: a trip signal, a measurement and a breaker, with a report control block over a
/// data set of the trip. Everything below is read out of this and nothing else.
const RELAY: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="example"/>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
      <DataSet name="dsTrip">
        <FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/>
        <FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="q" fc="ST"/>
      </DataSet>
      <ReportControl name="urcb" datSet="dsTrip" confRev="1" indexed="false">
        <TrgOps dchg="true" qchg="true"/>
        <OptFields seqNum="true" dataSet="true" reasonCode="true"/>
      </ReportControl>
    </LN0>
    <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
    <LN lnClass="MMXU" inst="1" prefix="" lnType="MMXU_T"/>
    <LN lnClass="CSWI" inst="1" prefix="" lnType="CSWI_T">
      <DOI name="Pos"><DAI name="ctlModel"><Val>direct-with-normal-security</Val></DAI></DOI>
    </LN>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <LNodeType id="MMXU_T" lnClass="MMXU"><DO name="TotW" type="MV_T"/></LNodeType>
    <LNodeType id="CSWI_T" lnClass="CSWI"><DO name="Pos" type="DPC_T"/></LNodeType>
    <DOType id="ACT_T" cdc="ACT"><DA name="general" fc="ST" bType="BOOLEAN"/><DA name="q" fc="ST" bType="Quality"/></DOType>
    <DOType id="MV_T" cdc="MV"><DA name="mag" fc="MX" bType="Struct" type="AV_T"/></DOType>
    <DOType id="DPC_T" cdc="DPC">
      <DA name="stVal" fc="ST" bType="Dbpos"/>
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModel_E"/>
      <DA name="Oper" fc="CO" bType="Struct" type="Oper_T"/>
    </DOType>
    <DAType id="AV_T"><BDA name="f" bType="FLOAT32"/></DAType>
    <DAType id="Oper_T">
      <BDA name="ctlVal" bType="Dbpos"/><BDA name="origin" bType="Struct" type="Or_T"/>
      <BDA name="ctlNum" bType="INT8U"/><BDA name="T" bType="Timestamp"/>
      <BDA name="Test" bType="BOOLEAN"/><BDA name="Check" bType="Check"/>
    </DAType>
    <DAType id="Or_T"><BDA name="orCat" bType="Enum" type="OrCat_E"/><BDA name="orIdent" bType="Octet64"/></DAType>
    <EnumType id="OrCat_E"><EnumVal ord="3">remote-control</EnumVal></EnumType>
    <EnumType id="CtlModel_E"><EnumVal ord="1">direct-with-normal-security</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;

fn main() -> iec61850_rs::Result<()> {
    // ---- the server: one file, one socket, no generated model and no build step ----------
    let mut server = Server::bind("127.0.0.1:0", Ied::from_scl(RELAY, Some("IED1"))?)?;
    server.on_control(Box::new(|event| {
        if event.stage == Stage::Operate {
            println!("server: the breaker is asked for {:?}", event.request.ctl_val);
        }
        Ok(())
    }));
    let addr = server.local_addr()?.to_string();
    let updates = server.handle();
    std::thread::spawn(move || {
        // One client in this example; a real server calls `run()` and never returns.
        let _ = server.accept_one();
        std::thread::park();
    });
    println!("server: serving IED1 on {addr}");

    // ---- the client: the same association, the other way round ---------------------------
    let mut c = Client::connect(&addr)?;
    println!("client: {:?}", c.identify()?);

    for ld in c.server_directory()? {
        let names = c.logical_device_directory(&ld)?;
        let nodes: Vec<&String> = names.iter().filter(|n| !n.contains('$')).collect();
        println!("client: {ld} has {} names over {} logical nodes {nodes:?}", names.len(), nodes.len());
    }

    // Reporting: enable the block the file engineered, then change the model and watch the
    // report arrive with the reason the change actually had.
    c.enable_rcb("IED1LD0/LLN0$RP$urcb", Fc::RP, &RcbSettings::new().with_trg_ops(TrgOps::EVENTS))?;
    updates.txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();

    let report = c.next_report(Duration::from_secs(2))?.expect("a report");
    println!("client: report {} sq={:?} — {} of {} members", report.rpt_id, report.seq_num, report.entries.len(), report.data_set_len());
    for e in &report.entries {
        println!("        [{}] {:?} because {:?}", e.index, e.value, e.reason);
    }

    // A general interrogation reports the whole data set, and says so.
    c.general_interrogation("IED1LD0/LLN0$RP$urcb", Fc::RP)?;
    let gi = c.next_report(Duration::from_secs(2))?.expect("a GI report");
    println!("client: general interrogation returned {} members", gi.entries.len());

    // A control: the model says how, so nobody guesses.
    let model = c.read_control_model("IED1LD0/CSWI1.Pos")?;
    assert_eq!(model, ControlModel::DirectNormal);
    c.control("IED1LD0/CSWI1.Pos").model(model).execute(&Value::dbpos(Dbpos::On))?;
    let position = c.read("IED1LD0/CSWI1.Pos.stVal", Fc::ST)?;
    println!("client: the breaker reads back as {:?}", position.as_dbpos());

    // And a measurement the application published.
    updates.txn().set("IED1LD0/MMXU1$MX$TotW$mag$f", Value::Float32(1234.5)).commit();
    println!("client: TotW = {:?}", c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX)?.as_f64());

    c.release()?;
    println!("done");
    Ok(())
}
