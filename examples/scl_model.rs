//! The engineering file as the configuration: a model, what an IED subscribes to, and the
//! errors the XML schema permits.
//!
//! ```text
//! cargo run --example scl_model                 # a small SCD built in
//! cargo run --example scl_model -- bay.scd      # …or your own
//! ```
//!
//! Everything here comes out of the SCD and nothing is typed twice: the publisher's MAC and
//! APPID, the subscriber's `confRev`, the sample layout of a merging unit's ASDU, the OSI
//! selectors an MMS association is opened with, and the control model a breaker expects.

use std::error::Error;

use iec61850_rs::Edition;
use iec61850_rs::scl::Scl;

fn main() -> Result<(), Box<dyn Error>> {
    let xml = match std::env::args().nth(1) {
        Some(path) => std::fs::read_to_string(&path)?,
        None => String::from(EXAMPLE_SCD),
    };
    // One parse, then every question is a method on the handle. Parsing per question turns
    // checking a station file into minutes of nothing.
    let scl = Scl::parse(&xml)?;
    println!("SCL {} — {}\n", scl.version(), scl.ied_names().join(", "));

    // --- the model ----------------------------------------------------------------------
    for name in scl.ied_names() {
        let model = scl.model(Some(&name))?;
        println!("{name}");
        for ld in &model.logical_devices {
            println!("  LD {} ({} logical nodes)", ld.inst, ld.logical_nodes.len());
            for ln in &ld.logical_nodes {
                for ds in &ln.data_sets {
                    println!("    data set {}/{}: {} member(s)", ln.name, ds.name, ds.members.len());
                }
                for gcb in &ln.gse_controls {
                    let addr = gcb.address.as_ref().map_or_else(|| String::from("no address"), |a| format!("{} APPID {:#06X}", a.mac, a.appid));
                    println!("    GOOSE {}/{} → {addr}", ln.name, gcb.name);
                }
                for cb in &ln.smv_controls {
                    let addr = cb.address.as_ref().map_or_else(|| String::from("no address"), |a| format!("{} APPID {:#06X}", a.mac, a.appid));
                    println!("    SV    {}/{} → {addr}", ln.name, cb.name);
                }
            }
        }
        // The OSI addressing an MMS association is opened with. Every one of these has to
        // match or the server refuses at a layer whose error message says nothing useful.
        if let Some(a) = model.osi_address(None) {
            println!("  associate at {:?}, TSEL {:02X?}, AP-title {:?}", a.ip, a.t_sel, a.ap_title);
        }
        // The control model is engineered per instance, in a `DAI` — not in the type.
        if let Some(m) = model.control_model("IED1LD0/CSWI1.Pos") {
            println!("  IED1LD0/CSWI1.Pos is {m:?}");
        }
        for d in &model.diagnostics {
            println!("  ! {d}");
        }
        println!();
    }

    // --- what a subscriber subscribes to ------------------------------------------------
    // `ExtRef` names the publisher and the signal but not the address; those are in the
    // *publisher's* section of the same file, so this walks both sides.
    for name in scl.ied_names() {
        let subs = scl.subscriptions(&name, 50)?;
        if subs.goose.is_empty() && subs.sv.is_empty() && subs.unresolved.is_empty() {
            continue;
        }
        println!("{name} subscribes to");
        for s in &subs.goose {
            println!("  GOOSE {} from {} — {} binding(s), confRev {}", s.identifier, s.publisher, s.ext_refs.len(), s.conf_rev);
        }
        for s in &subs.sv {
            let channels = s.layout.as_ref().map_or(0, |l| l.channels().len());
            println!("  SV    {} from {} — {channels} channel(s) in the ASDU", s.identifier, s.publisher);
            if let Some(layout) = &s.layout {
                for c in layout.channels() {
                    println!("        {} at offset {} ({:?})", c.name, c.offset, c.kind);
                }
            }
        }
        // A binding that resolves to nothing is a commissioning finding, not something to
        // hide: an SCD with dangling `ExtRef`s is why a protection scheme does not trip.
        for d in &subs.unresolved {
            println!("  ! {d}");
        }
        println!();
    }

    // --- the errors the schema permits --------------------------------------------------
    let report = scl.validate(50, Edition::Ed2_1)?;
    if report.findings.is_empty() {
        println!("validation: nothing to report");
    } else {
        println!("validation:");
        for f in &report.findings {
            println!("  {f}");
        }
    }
    Ok(())
}

/// A two-IED bay: a protection relay publishing GOOSE, a merging unit publishing sampled
/// values, and a breaker IED that subscribes to both.
const EXAMPLE_SCD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Communication>
    <SubNetwork name="bay">
      <ConnectedAP iedName="IED1" apName="S1">
        <Address>
          <P type="IP">10.0.0.5</P>
          <P type="OSI-TSEL">0001</P>
          <P type="OSI-AP-Title">1,3,9999,23</P>
        </Address>
        <GSE ldInst="LD0" cbName="gcbTrip">
          <Address><P type="MAC-Address">01-0C-CD-01-00-05</P><P type="APPID">0005</P><P type="VLAN-PRIORITY">4</P></Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
        <SMV ldInst="LD0" cbName="msvcb01">
          <Address><P type="MAC-Address">01-0C-CD-04-00-01</P><P type="APPID">4000</P></Address>
        </SMV>
      </ConnectedAP>
    </SubNetwork>
  </Communication>

  <IED name="IED1"><AccessPoint name="S1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
      <DataSet name="dsTrip">
        <FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/>
        <FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="q" fc="ST"/>
      </DataSet>
      <DataSet name="dsMeas">
        <FCDA ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="instMag.i" fc="MX"/>
        <FCDA ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="q" fc="MX"/>
      </DataSet>
      <GSEControl name="gcbTrip" datSet="dsTrip" confRev="1" appID="TRIP"/>
      <SampledValueControl name="msvcb01" datSet="dsMeas" confRev="1" smvID="MU01" smpRate="80" nofASDU="1"/>
    </LN0>
    <LN lnClass="PTRC" inst="1" lnType="PTRC_T"/>
    <LN lnClass="TCTR" inst="1" lnType="TCTR_T"/>
    <LN lnClass="CSWI" inst="1" lnType="CSWI_T">
      <DOI name="Pos"><DAI name="ctlModel"><Val>sbo-with-enhanced-security</Val></DAI></DOI>
    </LN>
  </LDevice></Server></AccessPoint></IED>

  <IED name="IED2"><AccessPoint name="S1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
      <Inputs>
        <ExtRef iedName="IED1" ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" serviceType="GOOSE"/>
        <ExtRef iedName="IED1" ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="instMag.i" serviceType="SMV"/>
        <ExtRef iedName="IED9" ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" serviceType="GOOSE"/>
      </Inputs>
    </LN0>
  </LDevice></Server></AccessPoint></IED>

  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <LNodeType id="TCTR_T" lnClass="TCTR"><DO name="AmpSv" type="SAV_T"/></LNodeType>
    <LNodeType id="CSWI_T" lnClass="CSWI"><DO name="Pos" type="DPC_T"/></LNodeType>
    <DOType id="ACT_T" cdc="ACT">
      <DA name="general" fc="ST" bType="BOOLEAN"/>
      <DA name="q" fc="ST" bType="Quality"/>
    </DOType>
    <DOType id="SAV_T" cdc="SAV">
      <DA name="instMag" fc="MX" bType="Struct" type="AnalogueValue_T"/>
      <DA name="q" fc="MX" bType="Quality"/>
    </DOType>
    <DOType id="DPC_T" cdc="DPC">
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModel_E"><Val>direct-with-normal-security</Val></DA>
    </DOType>
    <DAType id="AnalogueValue_T"><BDA name="i" bType="INT32"/></DAType>
    <EnumType id="CtlModel_E"><EnumVal ord="1">direct-with-normal-security</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;
