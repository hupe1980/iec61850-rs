//! The `ied` binary, end to end.
//!
//! Every subcommand works on capture files, so all of this runs in CI without a network
//! interface. The merging unit generates a stream, and the monitor reads it back: if the
//! encoder and the decoder ever disagree, this fails.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

/// The `ied` binary built alongside this test.
fn ied() -> PathBuf {
    // `CARGO_BIN_EXE_<name>` is set by cargo for every binary target in the package.
    PathBuf::from(env!("CARGO_BIN_EXE_ied"))
}

struct Output {
    stdout: String,
    stderr: String,
    ok: bool,
}

fn run(args: &[&str]) -> Output {
    let out = Command::new(ied()).args(args).output().expect("run ied");
    Output { stdout: String::from_utf8_lossy(&out.stdout).into_owned(), stderr: String::from_utf8_lossy(&out.stderr).into_owned(), ok: out.status.success() }
}

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iec61850-cli-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn help_and_version() {
    let h = run(&["--help"]);
    assert!(h.ok && h.stdout.contains("ied — IEC 61850 command line"), "{h:?}", h = h.stdout);
    assert!(run(&["--version"]).stdout.contains(env!("CARGO_PKG_VERSION")));
    let bad = run(&["nonsense"]);
    assert!(!bad.ok, "an unknown command must fail");
    assert!(bad.stderr.contains("unknown command"), "{}", bad.stderr);
}

#[test]
fn errors_are_reported_not_panicked() {
    for args in [
        vec!["pcap", "info", "/nonexistent.pcap"],
        vec!["goose", "sniff", "/nonexistent.pcap"],
        vec!["scl", "show", "/nonexistent.scl"],
        vec!["mu", "/nonexistent/dir/out.pcap"],
    ] {
        let o = run(&args);
        assert!(!o.ok, "{args:?} should fail");
        assert!(o.stderr.starts_with("ied: "), "{args:?}: {}", o.stderr);
        assert!(!o.stderr.contains("panicked"), "{args:?}: {}", o.stderr);
    }
    // A file that exists but is not a capture.
    let dir = tempdir("notapcap");
    let junk = dir.join("junk.pcap");
    std::fs::write(&junk, b"this is not a pcap").unwrap();
    let o = run(&["pcap", "info", junk.to_str().unwrap()]);
    assert!(!o.ok && o.stderr.contains("not a classic pcap"), "{}", o.stderr);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn merging_unit_output_is_read_back_by_the_monitor() {
    let dir = tempdir("mu");
    for (profile, frames, asdus_per_frame, rate) in [("le80-50", 100u32, 1u32, 4000u32), ("f4800s2", 100, 2, 4800), ("f14400s6", 60, 6, 14_400)] {
        let out = dir.join(format!("{profile}.pcap"));
        let path = out.to_str().unwrap();
        let made = run(&["mu", path, "--profile", profile, "--frames", &frames.to_string(), "--sv-id", "TESTMU"]);
        assert!(made.ok, "{}", made.stderr);
        assert!(made.stdout.contains(&format!("{rate} samples/s")), "{}", made.stdout);

        let mon = run(&["sv", "monitor", path]);
        assert!(mon.ok, "{}", mon.stderr);
        assert!(mon.stdout.contains("svID=TESTMU"), "{}", mon.stdout);
        assert!(mon.stdout.contains(&format!("frames={frames}")), "{}", mon.stdout);
        assert!(mon.stdout.contains(&format!("asdus={}", frames * asdus_per_frame)), "{}", mon.stdout);
        assert!(mon.stdout.contains("gaps=0 samples lost=0"), "the generated stream must be continuous: {}", mon.stdout);

        let info = run(&["pcap", "info", path]);
        assert!(info.stdout.contains(&format!("sampled values {frames}")), "{}", info.stdout);
        assert!(info.stdout.contains(&format!("VLAN-tagged {frames}")), "{}", info.stdout);
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn generated_frames_dissect_cleanly_in_wireshark() {
    let Some(tshark) = common::tshark() else { return };
    let dir = tempdir("oracle");
    let out = dir.join("mu.pcap");
    let path = out.to_str().unwrap();
    assert!(run(&["mu", path, "--profile", "f4800s2", "--frames", "50"]).ok);

    let json = Command::new(tshark).arg("-r").arg(path).args(["-T", "json"]).output().expect("run tshark");
    let text = String::from_utf8_lossy(&json.stdout);
    assert!(json.status.success(), "{}", String::from_utf8_lossy(&json.stderr));
    assert!(!text.contains("_ws.malformed"), "the merging unit produced a malformed frame");
    assert!(text.contains("\"sv.svID\": \"MU01\""), "{text}");
    assert!(text.contains("\"sv.noASDU\": \"2\""), "{text}");
    assert!(text.contains("\"sv.smpRate\": \"4800\""), "{text}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn goose_sniff_reads_a_real_capture() {
    let Some(capture) = common::spec("pcap/goose-mdehus.pcap") else { return };
    let o = run(&["goose", "sniff", capture.to_str().unwrap()]);
    assert!(o.ok, "{}", o.stderr);
    assert!(o.stdout.contains("16 GOOSE frames"), "{}", o.stdout);
    assert!(o.stdout.contains("SEL_351_1CFG/LLN0$GO$NewGOOSEMessage"), "{}", o.stdout);
    assert!(!o.stdout.contains("COUNT-MISMATCH"), "a real capture must not look malformed: {}", o.stdout);
}

#[test]
fn goose_sniff_calls_out_a_replay() {
    // A capture with a frame repeated after the stream has moved on. Decoding it says
    // nothing is wrong — every field is well formed. Running the subscriber state machine
    // over it says what is: the same frame twice is a replay while the state is live.
    let dir = tempdir("replay");
    let path = dir.join("replay.pcap");
    let frames = goose_frames();
    let replayed = vec![frames[0].clone(), frames[1].clone(), frames[0].clone()];
    common::write_pcap(&path, &replayed);

    let o = run(&["goose", "sniff", path.to_str().unwrap()]);
    assert!(o.ok, "{}", o.stderr);
    assert!(o.stdout.contains("Replay"), "the sniffer must name a replay: {}", o.stdout);
    assert!(o.stdout.contains("replays=1"), "{}", o.stdout);
    assert!(o.stdout.contains("3 GOOSE frames in 1 stream(s)"), "{}", o.stdout);
    assert!(o.stdout.contains("stDiff="), "the IDS delta features belong in the summary: {}", o.stdout);
    std::fs::remove_dir_all(&dir).ok();
}

/// Two GOOSE frames of one stream: a state change and the state after it.
fn goose_frames() -> Vec<Vec<u8>> {
    use iec61850_rs::common::{Instant, UtcTime};
    use iec61850_rs::proto::data::Value;
    use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, FrameHeader, MacAddr, VlanTag};
    use iec61850_rs::proto::goose::{Publisher, PublisherConfig, Retransmission};

    let cfg = PublisherConfig {
        header: FrameHeader {
            dst: MacAddr::GOOSE_BASE,
            src: MacAddr([2, 0, 0, 0, 0, 1]),
            vlan: Some(VlanTag::DEFAULT),
            ethertype: ETHERTYPE_GOOSE,
            appid: 1,
            reserved1: 0,
            reserved2: 0,
        },
        gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into(),
        dat_set: "IED1LD0/LLN0$dsTrip".into(),
        go_id: Some("IED1".into()),
        conf_rev: 1,
        retransmission: Retransmission::DEFAULT,
        simulation: false,
        nds_com: false,
    };
    let mut p = Publisher::new(cfg, &[Value::Boolean(false)], UtcTime::default()).unwrap();
    let mut out = Vec::new();
    p.on_timeout(Instant::ZERO).unwrap();
    out.push(p.poll_transmit().unwrap().to_vec());
    p.publish(Instant::ZERO.plus_millis(1), &[Value::Boolean(true)], UtcTime::default()).unwrap();
    out.push(p.poll_transmit().unwrap().to_vec());
    out
}

#[test]
fn mms_sniff_reads_a_real_association() {
    // The reference capture is an ICCP association — MMS over ACSE over presentation over
    // session over COTP over TPKT. Decoding it end to end is the check that the whole OSI
    // stack works on traffic nobody here produced.
    let Some(capture) = common::spec("pcap/mms.pcap") else { return };
    let o = run(&["mms", "sniff", capture.to_str().unwrap()]);
    assert!(o.ok, "{}", o.stderr);
    // The handshake, layer by layer.
    assert!(o.stdout.contains("COTP CR src-ref=0xb001 tpdu-size=1024"), "{}", o.stdout);
    assert!(o.stdout.contains("CP  contexts 1=2.2.1.0.1 3=1.0.9506.2.1"), "the negotiated contexts: {}", o.stdout);
    assert!(o.stdout.contains("AARE accepted"), "{}", o.stdout);
    assert!(o.stdout.contains("Initiate maxPDU=Some(32000)"), "{}", o.stdout);
    // And what the association carried.
    assert!(o.stdout.contains("identify AREVA T&D Corporation e-terracomm 2.3.1"), "the server names itself: {}", o.stdout);
    assert!(o.stdout.contains("data set of 19 member(s)"), "{}", o.stdout);
    assert!(o.stdout.contains("report KIRKLAND/EMS_ANALOG_ICCP_IN (19 values)"), "{}", o.stdout);
    assert!(o.stdout.contains("23 request(s), 23 response(s), 115 report(s), 823 value(s)"), "{}", o.stdout);
    assert!(!o.stdout.contains("did not decode"), "every PDU in the capture must decode: {}", o.stdout);
}

#[test]
fn scl_show_and_validate() {
    let dir = tempdir("scl");
    let file = dir.join("t.icd");
    std::fs::write(&file, GOOD_ICD).unwrap();
    let path = file.to_str().unwrap();

    let show = run(&["scl", "show", path]);
    assert!(show.ok, "{}", show.stderr);
    for expected in ["IED IED1", "LD IED1LD0", "LN LLN0", "GSEControl gcbTrip", "DataSet dsTrip", "IED1LD0/PTRC1$ST$Tr$general"] {
        assert!(show.stdout.contains(expected), "missing {expected} in {}", show.stdout);
    }
    assert!(run(&["scl", "validate", path]).ok, "a conforming file must validate");

    // An APPID outside the GOOSE range is exactly the kind of engineering error a validator
    // exists to catch; the schema permits it.
    let bad = dir.join("bad.icd");
    std::fs::write(&bad, GOOD_ICD.replace("<P type=\"APPID\">0005</P>", "<P type=\"APPID\">4005</P>")).unwrap();
    let o = run(&["scl", "validate", bad.to_str().unwrap()]);
    assert!(!o.ok, "an out-of-range APPID must fail validation");
    assert!(o.stdout.contains("outside 0x0000-0x3FFF"), "{}", o.stdout);
    assert!(o.stdout.contains("error: AppidOutOfRange"), "findings carry a stable code: {}", o.stdout);

    // A warning alone does not fail the build unless it is asked to.
    let warned = dir.join("warn.icd");
    std::fs::write(&warned, GOOD_ICD.replace("<P type=\"VLAN-PRIORITY\">4</P>", "<P type=\"VLAN-PRIORITY\">0</P>")).unwrap();
    let o = run(&["scl", "validate", warned.to_str().unwrap()]);
    assert!(o.ok, "a warning is not an error: {} {}", o.stdout, o.stderr);
    assert!(o.stdout.contains("warning: VlanPriority"), "{}", o.stdout);
    let o = run(&["scl", "validate", warned.to_str().unwrap(), "--strict"]);
    assert!(!o.ok, "--strict promotes it: {}", o.stdout);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn scl_subs_resolves_a_subscriber_against_its_publishers() {
    let dir = tempdir("subs");
    let file = dir.join("bay.scd");
    std::fs::write(&file, SCD).unwrap();
    let path = file.to_str().unwrap();

    let o = run(&["scl", "subs", path, "IED2"]);
    assert!(o.ok, "{} {}", o.stdout, o.stderr);
    assert!(o.stdout.contains("1 GOOSE and 1 sampled-value stream"), "{}", o.stdout);
    assert!(o.stdout.contains("IED1LD0/LLN0$GO$gcbTrip from IED1"), "{}", o.stdout);
    assert!(o.stdout.contains("appid=0x0005 confRev=3"), "{}", o.stdout);
    assert!(o.stdout.contains("MU01 from IED1"), "{}", o.stdout);
    assert!(o.stdout.contains("rate=4000/s"), "{}", o.stdout);
    assert!(o.stdout.contains("[BI1]"), "the internal address the input is wired to: {}", o.stdout);

    // An ExtRef naming a publisher the file does not hold is a commissioning finding, not
    // something to swallow.
    let broken = dir.join("broken.scd");
    std::fs::write(&broken, SCD.replace("iedName=\"IED1\" ldInst=\"LD0\" lnClass=\"PTRC\"", "iedName=\"Ghost\" ldInst=\"LD0\" lnClass=\"PTRC\"")).unwrap();
    let o = run(&["scl", "subs", broken.to_str().unwrap(), "IED2"]);
    assert!(!o.ok);
    assert!(o.stdout.contains("unresolved") && o.stdout.contains("Ghost"), "{}", o.stdout);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn scl_validate_reports_dangling_types_from_the_openscd_corpus() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("specs/fixtures/openscd");
    let file = dir.join("valid2007B4.scd");
    if !file.is_file() {
        return;
    }
    let o = run(&["scl", "validate", file.to_str().unwrap()]);
    // The corpus is known to reference types it does not define; the tool must name them
    // rather than either crashing or silently accepting.
    assert!(!o.ok);
    assert!(o.stdout.contains("MissingLNodeType"), "{}", o.stdout);
    assert!(o.stdout.contains("not found"), "{}", o.stdout);
}

#[test]
fn sv_monitor_reads_the_channels_out_of_the_engineering_file() {
    // Without the file, an ASDU is 64 octets nobody can name. With it, the data set says
    // what each one means — which is the difference between a tool that reads 9-2LE and one
    // that reads whatever a merging unit was engineered to send.
    let dir = tempdir("svscd");
    let capture = dir.join("mu.pcap");
    let scd = dir.join("mu.scd");
    std::fs::write(&scd, MU_SCD).unwrap();
    let path = capture.to_str().unwrap();
    assert!(run(&["mu", path, "--frames", "200"]).ok);

    let o = run(&["sv", "monitor", path, "--scd", scd.to_str().unwrap()]);
    assert!(o.ok, "{}", o.stderr);
    assert!(o.stdout.contains("MU MULD0/LLN0.msvcb01"), "{}", o.stdout);
    assert!(o.stdout.contains("16 channels, 64 octets per ASDU"), "{}", o.stdout);
    assert!(o.stdout.contains("frames=200"), "{}", o.stdout);
    assert!(o.stdout.contains("gaps=0"), "{}", o.stdout);
    // Named channels, decoded values, and the quality word read as a quality.
    assert!(o.stdout.contains("LD0/TCTR1.AmpSv.instMag.i"), "{}", o.stdout);
    assert!(o.stdout.contains("LD0/TVTR3.VolSv.q"), "{}", o.stdout);
    assert!(o.stdout.matches("good").count() >= 8, "{}", o.stdout);

    // The stream in the file has to be the stream on the wire: a capture of something else
    // is reported as such rather than decoded into channels that are not there.
    let other = dir.join("other.pcap");
    assert!(run(&["mu", other.to_str().unwrap(), "--frames", "10", "--appid", "4009"]).ok);
    let miss = run(&["sv", "monitor", other.to_str().unwrap(), "--scd", scd.to_str().unwrap()]);
    assert!(miss.ok, "{}", miss.stderr);
    assert!(miss.stdout.contains("no sample of this stream in the capture"), "{}", miss.stdout);

    // `--ied` narrows it, and naming an IED that is not there is an error, not a silence.
    assert!(run(&["sv", "monitor", path, "--scd", scd.to_str().unwrap(), "--ied", "MU"]).ok);
    let bad = run(&["sv", "monitor", path, "--scd", scd.to_str().unwrap(), "--ied", "NOSUCH"]);
    assert!(!bad.ok && bad.stderr.contains("not found"), "{}", bad.stderr);
    assert!(!run(&["sv", "monitor", path, "--ied", "MU"]).ok, "--ied without --scd means nothing");
    std::fs::remove_dir_all(&dir).ok();
}

/// A merging unit as an engineering file describes it: the whole 9-2LE data set — four
/// currents and four voltages, each an `INT32` sample and a quality word — on the address
/// and APPID `ied mu` publishes to by default. This is what turns the ASDU's 64 octets into
/// sixteen named channels without a line of code knowing what 9-2LE is.
const MU_SCD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="t"/>
  <Communication>
    <SubNetwork name="process">
      <ConnectedAP iedName="MU" apName="P1">
        <SMV ldInst="LD0" cbName="msvcb01">
          <Address><P type="MAC-Address">01-0C-CD-04-00-00</P><P type="APPID">4000</P><P type="VLAN-PRIORITY">4</P></Address>
        </SMV>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="MU" manufacturer="ACME" type="MergingUnit">
    <AccessPoint name="P1"><Server>
      <LDevice inst="LD0">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
          <DataSet name="PhsMeas1">
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="instMag.i" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="q" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="2" doName="AmpSv" daName="instMag.i" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="2" doName="AmpSv" daName="q" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="3" doName="AmpSv" daName="instMag.i" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="3" doName="AmpSv" daName="q" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="4" doName="AmpSv" daName="instMag.i" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="4" doName="AmpSv" daName="q" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TVTR" lnInst="1" doName="VolSv" daName="instMag.i" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TVTR" lnInst="1" doName="VolSv" daName="q" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TVTR" lnInst="2" doName="VolSv" daName="instMag.i" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TVTR" lnInst="2" doName="VolSv" daName="q" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TVTR" lnInst="3" doName="VolSv" daName="instMag.i" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TVTR" lnInst="3" doName="VolSv" daName="q" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TVTR" lnInst="4" doName="VolSv" daName="instMag.i" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TVTR" lnInst="4" doName="VolSv" daName="q" fc="MX"/>
          </DataSet>
          <SampledValueControl name="msvcb01" smvID="MU01" datSet="PhsMeas1" confRev="1" smpRate="80" nofASDU="1"/>
        </LN0>
        <LN lnClass="TCTR" inst="1" prefix="" lnType="TCTR_T"/>
        <LN lnClass="TCTR" inst="2" prefix="" lnType="TCTR_T"/>
        <LN lnClass="TCTR" inst="3" prefix="" lnType="TCTR_T"/>
        <LN lnClass="TCTR" inst="4" prefix="" lnType="TCTR_T"/>
        <LN lnClass="TVTR" inst="1" prefix="" lnType="TVTR_T"/>
        <LN lnClass="TVTR" inst="2" prefix="" lnType="TVTR_T"/>
        <LN lnClass="TVTR" inst="3" prefix="" lnType="TVTR_T"/>
        <LN lnClass="TVTR" inst="4" prefix="" lnType="TVTR_T"/>
      </LDevice>
    </Server></AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <LNodeType id="TCTR_T" lnClass="TCTR"><DO name="AmpSv" type="SAV_T"/></LNodeType>
    <LNodeType id="TVTR_T" lnClass="TVTR"><DO name="VolSv" type="SAV_T"/></LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="Enum" type="Mod_E"/></DOType>
    <DOType id="SAV_T" cdc="SAV"><DA name="instMag" fc="MX" bType="Struct" type="AV_T"/><DA name="q" fc="MX" bType="Quality"/></DOType>
    <DAType id="AV_T"><BDA name="i" bType="INT32"/></DAType>
    <EnumType id="Mod_E"><EnumVal ord="1">on</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;

const GOOD_ICD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="t"/>
  <Communication>
    <SubNetwork name="bus">
      <ConnectedAP iedName="IED1" apName="P1">
        <GSE ldInst="LD0" cbName="gcbTrip">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-05</P>
            <P type="APPID">0005</P>
            <P type="VLAN-ID">001</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
        </GSE>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="IED1" manufacturer="ACME" type="Relay" configVersion="1.0">
    <AccessPoint name="P1"><Server>
      <LDevice inst="LD0">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
          <DataSet name="dsTrip"><FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/></DataSet>
          <GSEControl name="gcbTrip" datSet="dsTrip" confRev="1" appID="IED1_Trip" type="GOOSE"/>
        </LN0>
        <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
      </LDevice>
    </Server></AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="Enum" type="Mod_E"/></DOType>
    <DOType id="ACT_T" cdc="ACT"><DA name="general" fc="ST" bType="BOOLEAN"/></DOType>
    <EnumType id="Mod_E"><EnumVal ord="1">on</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;

/// Two IEDs: a relay that publishes GOOSE and sampled values, and a subscriber wired to
/// both through `Inputs/ExtRef` — the shape of a real SCD, minus everything else.
const SCD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="t"/>
  <Communication>
    <SubNetwork name="bus">
      <ConnectedAP iedName="IED1" apName="P1">
        <GSE ldInst="LD0" cbName="gcbTrip">
          <Address><P type="MAC-Address">01-0C-CD-01-00-05</P><P type="APPID">0005</P></Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
        <SMV ldInst="LD0" cbName="msvcb01">
          <Address><P type="MAC-Address">01-0C-CD-04-00-01</P><P type="APPID">4001</P></Address>
        </SMV>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="IED1" manufacturer="ACME" type="Relay" configVersion="1.0">
    <AccessPoint name="P1"><Server>
      <LDevice inst="LD0">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
          <DataSet name="dsTrip"><FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/></DataSet>
          <DataSet name="PhsMeas1">
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="instMag.i" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="q" fc="MX"/>
          </DataSet>
          <GSEControl name="gcbTrip" datSet="dsTrip" confRev="3" appID="IED1_Trip" type="GOOSE"/>
          <SampledValueControl name="msvcb01" smvID="MU01" datSet="PhsMeas1" confRev="1" smpRate="80" nofASDU="1"/>
        </LN0>
        <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
        <LN lnClass="TCTR" inst="1" prefix="" lnType="TCTR_T"/>
      </LDevice>
    </Server></AccessPoint>
  </IED>
  <IED name="IED2" manufacturer="ACME" type="Merge">
    <AccessPoint name="P1"><Server>
      <LDevice inst="LD0">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
          <Inputs>
            <ExtRef iedName="IED1" ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general"
                    serviceType="GOOSE" srcLDInst="LD0" srcCBName="gcbTrip" intAddr="BI1"/>
            <ExtRef iedName="IED1" ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="instMag.i"
                    serviceType="SMV" srcLDInst="LD0" srcCBName="msvcb01"/>
          </Inputs>
        </LN0>
      </LDevice>
    </Server></AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <LNodeType id="TCTR_T" lnClass="TCTR"><DO name="AmpSv" type="SAV_T"/></LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="Enum" type="Mod_E"/></DOType>
    <DOType id="ACT_T" cdc="ACT"><DA name="general" fc="ST" bType="BOOLEAN"/></DOType>
    <DOType id="SAV_T" cdc="SAV"><DA name="instMag" fc="MX" bType="Struct" type="AV_T"/><DA name="q" fc="MX" bType="Quality"/></DOType>
    <DAType id="AV_T"><BDA name="i" bType="INT32"/></DAType>
    <EnumType id="Mod_E"><EnumVal ord="1">on</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;

#[test]
fn the_mms_client_subcommands_talk_to_a_server() {
    // The server is the crate's own association in the server role (`tests/common`), so
    // every `ied mms` client subcommand is covered in CI without a network or a device.
    let addr = common::spawn_mms_server(0);
    let id = run(&["mms", "identify", &addr]);
    assert!(id.ok, "{}", id.stderr);
    assert!(id.stdout.contains("vendor    hupe1980"), "{}", id.stdout);
    assert!(id.stdout.contains("max PDU"), "{}", id.stdout);

    let browse = run(&["mms", "browse", &common::spawn_mms_server(0)]);
    assert!(browse.ok, "{}", browse.stderr);
    assert!(browse.stdout.contains("IED1LD0"), "{}", browse.stdout);
    assert!(browse.stdout.contains("MMXU1$MX$TotW$mag$f"), "{}", browse.stdout);
    assert!(browse.stdout.contains("data set LLN0$dsTrip"), "{}", browse.stdout);
    assert!(browse.stdout.contains("3 variables, 1 data sets"), "{}", browse.stdout);

    let read = run(&["mms", "read", &common::spawn_mms_server(0), "IED1LD0/MMXU1.TotW.mag.f", "--fc", "MX"]);
    assert!(read.ok, "{}", read.stderr);
    assert_eq!(read.stdout.trim(), "IED1LD0/MMXU1.TotW.mag.f = 1.5");

    let write = run(&["mms", "write", &common::spawn_mms_server(0), "IED1LD0/GGIO1.SPCSO1.stVal", "true", "--type", "bool"]);
    assert!(write.ok, "{}", write.stderr);
    assert!(write.stdout.contains("<- true"), "{}", write.stdout);

    let reports = run(&["mms", "report", &common::spawn_mms_server(2), "--seconds", "2"]);
    assert!(reports.ok, "{}", reports.stderr);
    assert!(reports.stdout.contains("report 2 IED1LD0/LLN0$RP$urcb01"), "{}", reports.stdout);
}

#[test]
fn an_unreachable_server_is_an_error_not_a_panic() {
    let o = run(&["mms", "identify", "127.0.0.1:1", "--timeout", "1"]);
    assert!(!o.ok);
    assert!(o.stderr.starts_with("ied: "), "{}", o.stderr);
    assert!(!o.stderr.contains("panicked"), "{}", o.stderr);
}

#[test]
fn the_mms_report_and_control_subcommands_drive_a_control_block() {
    // `--rcb` enables the block, `--gi` asks for a general interrogation, and the report is
    // printed with its decoded fields rather than as a list of anonymous values.
    let addr = common::spawn_mms_server(0);
    let out = run(&["mms", "report", &addr, "--rcb", common::RCB_REFERENCE, "--gi", "--seconds", "2"]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("enabled IED1LD0/LLN0$RP$urcb01"), "{}", out.stdout);
    assert!(out.stdout.contains("triggers: data change, quality change, GI"), "{}", out.stdout);
    assert!(out.stdout.contains("general interrogation requested"), "{}", out.stdout);
    assert!(out.stdout.contains("dataSet=IED1LD0/LLN0$dsTrip"), "{}", out.stdout);
    assert!(out.stdout.contains("2 of 2 members"), "{}", out.stdout);
    assert!(out.stdout.contains("(general interrogation)"), "{}", out.stdout);

    // `mms rcb` prints the configuration a commissioning engineer needs to see.
    let rcb = run(&["mms", "rcb", &common::spawn_mms_server(0), common::RCB_REFERENCE]);
    assert!(rcb.ok, "{}", rcb.stderr);
    assert!(rcb.stdout.contains("kind       unbuffered (RP)"), "{}", rcb.stdout);
    assert!(rcb.stdout.contains("DatSet     IED1LD0/LLN0$dsTrip"), "{}", rcb.stdout);
    assert!(rcb.stdout.contains("ConfRev    3"), "{}", rcb.stdout);

    // A direct control.
    let ctl = run(&["mms", "control", &common::spawn_mms_server(0), common::CONTROL_REFERENCE, "true", "--type", "bool"]);
    assert!(ctl.ok, "{}", ctl.stderr);
    assert!(ctl.stdout.contains("(accepted)"), "{}", ctl.stdout);
}

#[test]
fn a_refused_control_is_reported_with_its_cause() {
    let addr = common::spawn_mms_server_with(common::ServerBehaviour {
        enhanced_control: true,
        refuse_control: Some(iec61850_rs::client::AddCause::BlockedByInterlocking),
        ..common::ServerBehaviour::default()
    });
    let o = run(&["mms", "control", &addr, common::CONTROL_REFERENCE, "true", "--type", "bool", "--model", "direct-enhanced", "--timeout", "3"]);
    assert!(!o.ok, "a refused control must not exit zero: {}", o.stdout);
    assert!(o.stderr.contains("BlockedByInterlocking"), "{}", o.stderr);
    assert!(!o.stderr.contains("panicked"), "{}", o.stderr);
}

#[test]
fn the_file_log_type_and_setting_group_subcommands_talk_to_a_server() {
    // Each subcommand gets its own server: one association per client, and the harness
    // closes it when the client releases.
    let files = run(&["mms", "files", &common::spawn_mms_server(0)]);
    assert!(files.ok, "{files:?}", files = files.stderr);
    assert!(files.stdout.contains(common::FILE_REFERENCE), "{}", files.stdout);
    assert!(files.stdout.contains("1 file(s)"), "{}", files.stdout);

    let out = tempdir("get").join("rec0001.cfg");
    let get = run(&["mms", "get", &common::spawn_mms_server(0), common::FILE_REFERENCE, out.to_str().unwrap()]);
    assert!(get.ok, "{get:?}", get = get.stderr);
    assert_eq!(std::fs::read(&out).unwrap(), common::FILE_CONTENTS, "the file arrived whole");

    let ty = run(&["mms", "type", &common::spawn_mms_server(0), "IED1LD0/CSWI1.Pos.Oper", "--fc", "CO"]);
    assert!(ty.ok, "{ty:?}", ty = ty.stderr);
    for component in ["ctlVal", "origin", "ctlNum", "T", "Test", "Check"] {
        assert!(ty.stdout.contains(component), "`{component}` missing from:\n{}", ty.stdout);
    }

    let log = run(&["mms", "log", &common::spawn_mms_server(0), common::LOG_REFERENCE, "--lcb", common::LCB_REFERENCE]);
    assert!(log.ok, "{log:?}", log = log.stderr);
    assert!(log.stdout.contains("power up"), "{}", log.stdout);
    assert!(log.stdout.contains("2 entr"), "{}", log.stdout);

    let sg = run(&["mms", "sg", &common::spawn_mms_server(0), common::SGCB_REFERENCE, "--activate", "2"]);
    assert!(sg.ok, "{sg:?}", sg = sg.stderr);
    assert!(sg.stdout.contains("group 2 activated") && sg.stdout.contains("ActSG   2"), "{}", sg.stdout);
}

#[test]
fn sim_serves_an_engineering_file_as_a_real_server() {
    use std::io::{BufRead, BufReader};

    // The whole design in one command: the SCL file is the configuration, so a simulator is
    // the file plus a socket. `ied mms browse` is then run against it — one binary talking to
    // itself over a real association, with no device and no generated model.
    let dir = tempdir("sim");
    let scl = dir.join("relay.icd");
    std::fs::write(&scl, SIM_RELAY).expect("write the file");

    let mut child = Command::new(ied()).args(["sim", scl.to_str().unwrap(), "--port", "0"]).stdout(std::process::Stdio::piped()).spawn().expect("spawn sim");
    // The first line names the address it actually bound, which is how a test asks for port
    // zero and still finds it.
    let stdout = child.stdout.take().expect("stdout");
    let mut lines = BufReader::new(stdout).lines();
    let first = lines.next().expect("a line").expect("readable");
    let addr = first.split_whitespace().nth(2).expect("the address").to_string();
    assert!(first.starts_with("IED1 on "), "{first}");

    let browse = run(&["mms", "browse", &addr]);
    let read = run(&["mms", "read", &addr, "IED1LD0/MMXU1.TotW.mag.f", "--fc", "MX"]);
    let ty = run(&["mms", "type", &addr, "IED1LD0/PTRC1.Tr", "--fc", "ST"]);
    let _ = child.kill();
    let _ = child.wait();

    assert!(browse.ok, "{}", browse.stderr);
    assert!(browse.stdout.contains("IED1LD0"), "{}", browse.stdout);
    assert!(browse.stdout.contains("PTRC1$ST$Tr$general"), "{}", browse.stdout);
    assert!(read.ok && read.stdout.contains("IED1LD0/MMXU1.TotW.mag.f"), "{}{}", read.stdout, read.stderr);
    assert!(ty.ok && ty.stdout.contains("general"), "{}{}", ty.stdout, ty.stderr);
}

const SIM_RELAY: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="sim"/>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/>
    <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
    <LN lnClass="MMXU" inst="1" prefix="" lnType="MMXU_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <LNodeType id="MMXU_T" lnClass="MMXU"><DO name="TotW" type="MV_T"/></LNodeType>
    <DOType id="ACT_T" cdc="ACT"><DA name="general" fc="ST" bType="BOOLEAN"/><DA name="q" fc="ST" bType="Quality"/></DOType>
    <DOType id="MV_T" cdc="MV"><DA name="mag" fc="MX" bType="Struct" type="AV_T"/></DOType>
    <DAType id="AV_T"><BDA name="f" bType="FLOAT32"/></DAType>
  </DataTypeTemplates>
</SCL>"#;
