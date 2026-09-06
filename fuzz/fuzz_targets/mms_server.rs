#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

//! The ACSI server from arbitrary bytes: every request a client could send, against a real
//! model loaded from SCL, with the answers encoded back.
//!
//! This is the half a capture cannot reach. The server decides what a name means, who owns a
//! control block, whether a selection is this client's and whether a path is inside the
//! sandbox — and every one of those decisions is made on input a peer chose. Nothing here
//! may panic, and every answer must encode: an `Answer` the encoder refuses is a request that
//! would leave a client waiting for ever.

use iec61850_rs::common::{Instant, Limits};
use iec61850_rs::model::IedModel;
use iec61850_rs::proto::mms::{ConfirmedRequest, Mms};
use iec61850_rs::server::{Acsi, Ied};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// A model with everything the server has a special case for: a report control block of each
/// kind, a controllable object, a log, a setting group, a data set — and the service tracking
/// objects, so that the path that mirrors a control block into one is fuzzed too.
const MODEL: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="f"/>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
      <DataSet name="dsTrip">
        <FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/>
        <FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="q" fc="ST"/>
      </DataSet>
      <ReportControl name="urcb" datSet="dsTrip" confRev="1" indexed="false"><TrgOps dchg="true" qchg="true"/><OptFields seqNum="true" reasonCode="true"/></ReportControl>
      <ReportControl name="brcb" datSet="dsTrip" confRev="1" buffered="true" indexed="false"><TrgOps dchg="true"/><OptFields seqNum="true" entryID="true"/></ReportControl>
      <Log name="GeneralLog"/>
      <LogControl name="lcb01" datSet="dsTrip" logName="GeneralLog"><TrgOps dchg="true"/></LogControl>
      <SettingControl numOfSGs="2" actSG="1"/>
    </LN0>
    <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
    <!-- An **array**, so the `alternateAccess` decoder and the index-aware name resolution
         are reached by a `Read` and not only by a unit test: an index is the one part of a
         reference that can be out of range, and out-of-range is what a fuzzer is for. -->
    <LN lnClass="MHAI" inst="1" prefix="" lnType="MHAI_T"/>
    <LN lnClass="CSWI" inst="1" prefix="" lnType="CSWI_T">
      <DOI name="Pos"><DAI name="ctlModel"><Val>sbo-with-enhanced-security</Val></DAI></DOI>
    </LN>
    <LN lnClass="PTOC" inst="1" prefix="" lnType="PTOC_T">
      <DOI name="StrVal"><SDI name="setMag"><DAI name="f"><Val sGroup="1">1.0</Val><Val sGroup="2">2.0</Val></DAI></SDI></DOI>
    </LN>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="UrcbTrk" type="UTS_T"/><DO name="CtlTrk" type="CTS_T"/></LNodeType>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <LNodeType id="CSWI_T" lnClass="CSWI"><DO name="Pos" type="DPC_T"/></LNodeType>
    <LNodeType id="PTOC_T" lnClass="PTOC"><DO name="StrVal" type="ASG_T"/></LNodeType>
    <LNodeType id="MHAI_T" lnClass="MHAI"><DO name="HA" type="HMV_T"/></LNodeType>
    <DOType id="HMV_T" cdc="HMV"><SDO name="phsAHar" type="CMV_T" count="4"/></DOType>
    <DOType id="CMV_T" cdc="CMV"><DA name="cVal" fc="MX" bType="Struct" type="AV_T"/><DA name="q" fc="MX" bType="Quality"/></DOType>
    <DOType id="ACT_T" cdc="ACT"><DA name="general" fc="ST" bType="BOOLEAN"/><DA name="q" fc="ST" bType="Quality"/></DOType>
    <!-- One declaration: the schema makes a `DA` name unique within its `DOType`, and the
         server publishes the `SE` view of a setting itself. -->
    <DOType id="ASG_T" cdc="ASG"><DA name="setMag" fc="SG" bType="Struct" type="AV_T"/></DOType>
    <DOType id="UTS_T" cdc="UTS">
      <DA name="objRef" fc="SR" bType="ObjRef"/><DA name="serviceType" fc="SR" bType="Enum" type="Svc_E"/>
      <DA name="errorCode" fc="SR" bType="Enum" type="Err_E"/><DA name="originatorID" fc="SR" bType="Octet64"/>
      <DA name="t" fc="SR" bType="Timestamp"/><DA name="rptEna" fc="SR" bType="BOOLEAN"/>
      <DA name="datSet" fc="SR" bType="ObjRef"/><DA name="confRev" fc="SR" bType="INT32U"/>
    </DOType>
    <DOType id="CTS_T" cdc="CTS">
      <DA name="objRef" fc="SR" bType="ObjRef"/><DA name="serviceType" fc="SR" bType="Enum" type="Svc_E"/>
      <DA name="errorCode" fc="SR" bType="Enum" type="Err_E"/><DA name="t" fc="SR" bType="Timestamp"/>
      <DA name="ctlVal" fc="SR" bType="Dbpos"/><DA name="ctlNum" fc="SR" bType="INT8U"/>
      <DA name="T" fc="SR" bType="Timestamp"/><DA name="Test" fc="SR" bType="BOOLEAN"/>
      <DA name="Check" fc="SR" bType="Check"/><DA name="respAddCause" fc="SR" bType="Enum" type="Add_E"/>
    </DOType>
    <DOType id="DPC_T" cdc="DPC">
      <DA name="stVal" fc="ST" bType="Dbpos"/>
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModel_E"/>
      <DA name="Oper" fc="CO" bType="Struct" type="Oper_T"/>
      <DA name="SBOw" fc="CO" bType="Struct" type="Oper_T"/>
      <DA name="Cancel" fc="CO" bType="Struct" type="Oper_T"/>
    </DOType>
    <DAType id="AV_T"><BDA name="f" bType="FLOAT32"/></DAType>
    <DAType id="Oper_T">
      <BDA name="ctlVal" bType="Dbpos"/><BDA name="origin" bType="Struct" type="Or_T"/>
      <BDA name="ctlNum" bType="INT8U"/><BDA name="T" bType="Timestamp"/>
      <BDA name="Test" bType="BOOLEAN"/><BDA name="Check" bType="Check"/>
    </DAType>
    <DAType id="Or_T"><BDA name="orCat" bType="Enum" type="OrCat_E"/><BDA name="orIdent" bType="Octet64"/></DAType>
    <EnumType id="OrCat_E"><EnumVal ord="3">remote-control</EnumVal></EnumType>
    <EnumType id="CtlModel_E"><EnumVal ord="4">sbo-with-enhanced-security</EnumVal></EnumType>
    <EnumType id="Svc_E"><EnumVal ord="25">SetURCBValues</EnumVal><EnumVal ord="45">Operate</EnumVal></EnumType>
    <EnumType id="Err_E"><EnumVal ord="12">no-error</EnumVal></EnumType>
    <EnumType id="Add_E"><EnumVal ord="0">Unknown</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;

/// The model, parsed once. Re-parsing the XML per input costs about twenty times what the
/// server itself does, which would make this the slowest target for no coverage at all.
fn model() -> &'static IedModel {
    static MODEL_ONCE: OnceLock<IedModel> = OnceLock::new();
    MODEL_ONCE.get_or_init(|| IedModel::from_scl(MODEL, Some("IED1")).expect("the fuzz model must load"))
}

fuzz_target!(|data: &[u8]| {
    // A fresh server per input: the state a request leaves behind is part of what is being
    // fuzzed, but it must not leak between unrelated inputs.
    let Ok(ied) = Ied::new(model().clone()) else { return };
    let mut acsi = Acsi::new(ied);

    // Two associations, so the ownership rules — a control block, a selection, a file handle —
    // are exercised rather than trivially satisfied.
    let mut now = Instant::ZERO;
    for (n, chunk) in data.chunks(64).enumerate() {
        let assoc = (n % 2) as u64 + 1;
        now = now.plus_millis(1);
        if let Ok(Mms::ConfirmedRequest { invoke_id, service }) = Mms::parse(chunk, &Limits::DEFAULT) {
            let answer = acsi.request(assoc, now, &service);
            // Every answer must encode. One that does not is a request a client would wait
            // for ever on, which is worse than an error response.
            answer.encode(invoke_id).expect("every answer must encode");
        }
        // Whatever the request changed, publishing it must not panic either — that is where
        // the report engine, the log and the control terminations all run.
        for (_, pdu) in acsi.commit(now) {
            Mms::parse(&pdu, &Limits::DEFAULT).expect("every report the server emits must decode");
        }
        for (_, pdu) in acsi.on_timeout(now) {
            Mms::parse(&pdu, &Limits::DEFAULT).expect("every report the server emits must decode");
        }
    }
    acsi.on_association_closed(1, now);
    acsi.on_association_closed(2, now);
    // A `ResvTms` reservation outlives its association, so the timer that ends it has to run
    // after the close — a reservation nothing expires is a block one client holds for ever.
    for (_, pdu) in acsi.on_timeout(now.plus_millis(3_600_000)) {
        Mms::parse(&pdu, &Limits::DEFAULT).expect("every report the server emits must decode");
    }
    let _ = ConfirmedRequest::Identify;
});
