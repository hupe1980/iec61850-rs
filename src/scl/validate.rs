//! Engineering checks on a whole SCL document — the errors the XML schema is happy to
//! accept and a substation is not.
//!
//! A file can be schema-valid and still publish two streams on one APPID, name a data set
//! that does not exist, or bind an input to a control block nobody configured an address
//! for. None of that is caught by validating against `SCL.xsd`, and all of it is caught in
//! commissioning, expensively. This is the same set of checks moved to the left.
//!
//! The checks live here rather than in the `ied` binary so that they are unit-tested and
//! usable from a build script or a CI job; the command line is a printer over them.

use alloc::string::String;
use alloc::vec::Vec;
use std::collections::HashMap;

use crate::common::{Edition, ObjectReference, Result};
use crate::model::{DiagnosticCode, IedModel};

/// How much a finding matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// The file is wrong and a device configured from it will misbehave.
    Error,
    /// The file is unusual. It may be deliberate, and it is worth a second look.
    Warning,
}

/// A stable identifier for a kind of finding, so a pipeline can allow or forbid one
/// without matching on prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FindingCode {
    /// Something the loader had to work around ([`DiagnosticCode`]).
    Loader(DiagnosticCode),
    /// An APPID outside the range its protocol reserves.
    AppidOutOfRange,
    /// A multicast MAC outside the range its protocol reserves.
    MacOutOfRange,
    /// Two control blocks publish to the same destination MAC **and** APPID: on the wire
    /// they are one stream, and every subscriber to either will see both.
    DuplicateStream,
    /// Two control blocks share an APPID on different addresses. Legal, and almost always
    /// a copy-and-paste.
    DuplicateAppid,
    /// A control block names a data set that its logical node does not define, or names
    /// none at all.
    MissingDataSet,
    /// A data-set member does not resolve against the IED's own type templates.
    UnresolvedFcda,
    /// An object reference is longer than the edition allows.
    ObjectReferenceTooLong,
    /// `MinTime`/`MaxTime` are missing or not in increasing order.
    RetransmissionTimes,
    /// The sampled-value rate, `nofASDU` or data-set layout does not describe a stream that
    /// can be published.
    SampleRate,
    /// A VLAN priority that will not get a process-bus frame through a loaded switch.
    VlanPriority,
    /// An `Inputs/ExtRef` names a source this file does not resolve.
    UnresolvedSubscription,
    /// A controllable object's `ctlModel` promises a service its type does not declare —
    /// select-before-operate with no `SBOw`, or any control model at all with no `Oper`.
    ControlServicesMissing,
}

/// One thing wrong with the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// How much it matters.
    pub severity: Severity,
    /// The stable code.
    pub code: FindingCode,
    /// Where, as an SCL path.
    pub at: String,
    /// What, in words.
    pub message: String,
}

impl core::fmt::Display for Finding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let severity = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{severity}: {:?} at {}: {}", self.code, self.at, self.message)
    }
}

/// What [`validate`] found, and enough context to print a summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The SCL schema version the document declares (`2007B4`, …).
    pub scl_version: String,
    /// The IEDs the document holds.
    pub ieds: Vec<String>,
    /// Everything found, in document order per IED and then per check.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Findings of [`Severity::Error`].
    pub fn errors(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.severity == Severity::Error)
    }

    /// Findings of [`Severity::Warning`].
    pub fn warnings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.severity == Severity::Warning)
    }

    /// True when nothing is wrong enough to fail a build.
    pub fn is_ok(&self) -> bool {
        self.errors().next().is_none()
    }
}

/// The GOOSE APPID range and its multicast MAC range (IEC 61850-8-1).
const GOOSE_APPID: core::ops::RangeInclusive<u16> = 0x0000..=0x3FFF;
/// The sampled-value APPID range (IEC 61850-9-2).
const SV_APPID: core::ops::RangeInclusive<u16> = 0x4000..=0x7FFF;

/// Check every IED in an SCL document.
///
/// `nominal_hz` is the system frequency, needed to turn `smpRate` into samples per second
/// when `smpMod` counts them per cycle; `edition` decides the object-reference length limit.
pub fn validate(xml: &str, nominal_hz: u32, edition: Edition) -> Result<Report> {
    super::Scl::parse(xml)?.validate(nominal_hz, edition)
}

impl super::Scl<'_> {
    /// Check every IED in the document. See [`validate`].
    ///
    /// Every model is built exactly once, including for the subscription pass: an `ExtRef`
    /// names a control block in another IED, so resolving one IED's inputs needs the others,
    /// and building them again per IED is how a check on a station file turns quadratic.
    pub fn validate(&self, nominal_hz: u32, edition: Edition) -> Result<Report> {
        let models = self.models()?;
        let mut report = Report { scl_version: self.version(), ieds: models.iter().map(|m| m.name.clone()).collect(), findings: Vec::new() };
        // (dst, appid) → the control block that claimed it first.
        let mut streams: HashMap<(crate::common::MacAddr, u16), String> = HashMap::new();
        let mut appids: HashMap<u16, String> = HashMap::new();

        for model in &models {
            for d in &model.diagnostics {
                report.findings.push(Finding { severity: Severity::Error, code: FindingCode::Loader(d.code), at: d.at.clone(), message: d.message.clone() });
            }
            check_ied(model, nominal_hz, edition, &mut streams, &mut appids, &mut report);
        }

        // Subscriptions are a whole-document property: an `ExtRef` names a control block in
        // another IED, and only the document as a whole says whether it exists.
        for model in &models {
            let subs = super::resolve(model, |name| models.iter().find(|m| m.name == name), nominal_hz);
            for d in subs.unresolved {
                report.findings.push(Finding { severity: Severity::Error, code: FindingCode::UnresolvedSubscription, at: d.at, message: d.message });
            }
        }
        Ok(report)
    }
}

fn check_ied(
    model: &IedModel,
    nominal_hz: u32,
    edition: Edition,
    streams: &mut HashMap<(crate::common::MacAddr, u16), String>,
    appids: &mut HashMap<u16, String>,
    report: &mut Report,
) {
    for ld in &model.logical_devices {
        for ln in &ld.logical_nodes {
            for gcb in &ln.gse_controls {
                let at = alloc::format!("{}/{}.{}", ld.name, ln.name, gcb.name);
                check_reference_length(&at, edition, report);
                check_data_set(model, ld, ln, gcb.dat_set.as_deref(), &at, report);
                let Some(addr) = &gcb.address else { continue };
                claim(streams, appids, addr.mac, addr.appid, &at, report);
                if !GOOSE_APPID.contains(&addr.appid) {
                    error(report, FindingCode::AppidOutOfRange, &at, alloc::format!("GOOSE APPID {:#06x} is outside 0x0000-0x3FFF", addr.appid));
                }
                if !addr.mac.is_goose_multicast() {
                    error(report, FindingCode::MacOutOfRange, &at, alloc::format!("{} is outside the GOOSE multicast range", addr.mac));
                }
                check_vlan(addr.vlan_priority, &at, report);
                match (addr.min_time_ms, addr.max_time_ms) {
                    (Some(min), Some(max)) if min == 0 || min >= max => {
                        error(report, FindingCode::RetransmissionTimes, &at, alloc::format!("MinTime {min} ms must be above zero and below MaxTime {max} ms"));
                    }
                    (None, _) | (_, None) => {
                        warn(
                            report,
                            FindingCode::RetransmissionTimes,
                            &at,
                            String::from("GSE without MinTime/MaxTime: the publisher falls back to 4 ms / 1000 ms"),
                        );
                    }
                    _ => {}
                }
            }

            check_controls(model, ld, ln, report);

            for cb in &ln.smv_controls {
                let at = alloc::format!("{}/{}.{}", ld.name, ln.name, cb.name);
                check_reference_length(&at, edition, report);
                check_data_set(model, ld, ln, cb.dat_set.as_deref(), &at, report);
                check_sample_rate(model, ld, ln, cb, nominal_hz, &at, report);
                let Some(addr) = &cb.address else { continue };
                claim(streams, appids, addr.mac, addr.appid, &at, report);
                if !SV_APPID.contains(&addr.appid) {
                    error(report, FindingCode::AppidOutOfRange, &at, alloc::format!("SV APPID {:#06x} is outside 0x4000-0x7FFF", addr.appid));
                }
                if !addr.mac.is_sv_multicast() {
                    error(report, FindingCode::MacOutOfRange, &at, alloc::format!("{} is outside the SV multicast range", addr.mac));
                }
                check_vlan(addr.vlan_priority, &at, report);
            }
        }
    }
}

/// Every controllable object must declare the attributes its `ctlModel` needs.
///
/// A `DOType` whose `ctlModel` says `sbo-with-enhanced-security` and which has no `SBOw`
/// attribute is a file that engineers a breaker nobody can operate: the client selects, the
/// server answers `object-non-existent`, and nothing in the schema objects. `Oper` is required
/// by every model but `status-only`; `SBOw` by the enhanced select model and `SBO` by the
/// normal one.
fn check_controls(model: &IedModel, ld: &crate::model::LogicalDevice, ln: &crate::model::LogicalNode, report: &mut Report) {
    for object in &ln.data_objects {
        let reference = alloc::format!("{}/{}.{}", ld.name, ln.name, object.name);
        let Some(ctl_model) = model.control_model(&reference) else { continue };
        if ctl_model == crate::common::ControlModel::StatusOnly {
            continue;
        }
        let has = |name: &str| object.attributes.iter().any(|a| a.name == name && a.fc == crate::common::Fc::CO);
        let mut missing: Vec<&str> = Vec::new();
        if !has("Oper") {
            missing.push("Oper");
        }
        if ctl_model.select_carries_value() && !has("SBOw") {
            missing.push("SBOw");
        }
        if ctl_model.needs_select() && !ctl_model.select_carries_value() && !has("SBO") {
            missing.push("SBO");
        }
        if !missing.is_empty() {
            error(
                report,
                FindingCode::ControlServicesMissing,
                &reference,
                alloc::format!("ctlModel is {ctl_model:?} but the type declares no {} under CO", missing.join(", ")),
            );
        }
    }
}

fn claim(
    streams: &mut HashMap<(crate::common::MacAddr, u16), String>,
    appids: &mut HashMap<u16, String>,
    mac: crate::common::MacAddr,
    appid: u16,
    at: &str,
    report: &mut Report,
) {
    // Same address *and* APPID: on the wire these are one stream, and a subscriber to
    // either receives both. That is an error, and it subsumes the APPID warning.
    if let Some(other) = streams.insert((mac, appid), String::from(at)) {
        return error(report, FindingCode::DuplicateStream, at, alloc::format!("{mac} appid={appid:#06x} is already published by {other}"));
    }
    // Same APPID on a different address is legal — a switch filters on the MAC — and is
    // almost always a control block that was copied and not finished.
    if let Some(other) = appids.insert(appid, String::from(at)) {
        warn(report, FindingCode::DuplicateAppid, at, alloc::format!("APPID {appid:#06x} is also used by {other}, on a different address"));
    }
}

fn check_vlan(priority: u8, at: &str, report: &mut Report) {
    if priority < 4 {
        warn(
            report,
            FindingCode::VlanPriority,
            at,
            alloc::format!("VLAN priority {priority}: process-bus traffic is engineered at 4 or above (9-2LE, TR 90-4)"),
        );
    }
}

fn check_reference_length(reference: &str, edition: Edition, report: &mut Report) {
    let Ok(r) = ObjectReference::parse(reference) else { return };
    if !r.fits(edition) {
        error(
            report,
            FindingCode::ObjectReferenceTooLong,
            reference,
            alloc::format!("{} characters exceeds the {} the {edition:?} object reference allows", r.len(), edition.max_object_reference_len()),
        );
    }
}

fn check_data_set(model: &IedModel, ld: &crate::model::LogicalDevice, ln: &crate::model::LogicalNode, dat_set: Option<&str>, at: &str, report: &mut Report) {
    let Some(name) = dat_set else {
        return error(report, FindingCode::MissingDataSet, at, String::from("control block without a datSet publishes nothing"));
    };
    let Some(ds) = model.data_set(ln, name) else {
        return error(report, FindingCode::MissingDataSet, at, alloc::format!("datSet `{name}` is not defined in {}", ln.name));
    };
    if ds.members.is_empty() {
        error(report, FindingCode::MissingDataSet, at, alloc::format!("datSet `{name}` has no members"));
    }
    for m in &ds.members {
        if m.da_name.is_some() && model.fcda_attribute(&ld.name, m).is_none() {
            error(
                report,
                FindingCode::UnresolvedFcda,
                at,
                alloc::format!("datSet `{name}` member {} does not resolve in this IED", model.fcda_reference(&ld.name, m)),
            );
        }
    }
}

fn check_sample_rate(
    model: &IedModel,
    ld: &crate::model::LogicalDevice,
    ln: &crate::model::LogicalNode,
    cb: &crate::model::SmvControl,
    nominal_hz: u32,
    at: &str,
    report: &mut Report,
) {
    if cb.nof_asdu == 0 {
        return error(report, FindingCode::SampleRate, at, String::from("nofASDU is zero: a frame must carry at least one ASDU"));
    }
    let Some(per_second) = cb.samples_per_second(nominal_hz) else {
        return error(
            report,
            FindingCode::SampleRate,
            at,
            alloc::format!("smpRate {} with smpMod `{}` gives no whole number of samples per second", cb.smp_rate, cb.smp_mod),
        );
    };
    if u8::try_from(cb.nof_asdu).is_err() {
        error(report, FindingCode::SampleRate, at, alloc::format!("nofASDU {} does not fit a frame", cb.nof_asdu));
    }
    let frames = per_second / cb.nof_asdu.max(1);
    if frames > 5000 {
        warn(
            report,
            FindingCode::SampleRate,
            at,
            alloc::format!("{frames} frames/s at {nominal_hz} Hz: IEC 61869-9 chooses nofASDU to hold the frame rate at 2400"),
        );
    }
    // A stream whose data set has no fixed-width layout cannot be published at all: the
    // ASDU length would change from sample to sample.
    if let Some(name) = cb.dat_set.as_deref() {
        if let Some(ds) = model.data_set(ln, name) {
            if !ds.members.is_empty() && model.sv_sample_len(&ld.name, ds).is_none() {
                error(
                    report,
                    FindingCode::SampleRate,
                    at,
                    alloc::format!("datSet `{name}` has no fixed-width sampled-value layout, so the ASDU has no constant length"),
                );
            }
        }
    }
}

fn error(report: &mut Report, code: FindingCode, at: &str, message: String) {
    report.findings.push(Finding { severity: Severity::Error, code, at: String::from(at), message });
}

fn warn(report: &mut Report, code: FindingCode, at: &str, message: String) {
    report.findings.push(Finding { severity: Severity::Warning, code, at: String::from(at), message });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same substation twice: once engineered correctly, once wrong in every way the
    /// XML schema is happy to accept. `{GSE}` and `{CB}` are the two halves that differ.
    fn scl(gse: &str, cb: &str) -> String {
        alloc::format!(
            r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="t"/>
  <Communication><SubNetwork name="bus"><ConnectedAP iedName="IED1" apName="P1">
    {gse}
    <SMV ldInst="LD0" cbName="msvcb01">
      <Address><P type="MAC-Address">01-0C-CD-04-00-01</P><P type="APPID">4001</P><P type="VLAN-PRIORITY">4</P></Address>
    </SMV>
  </ConnectedAP></SubNetwork></Communication>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
      <DataSet name="dsTrip"><FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/></DataSet>
      {cb}
    </LN0>
    <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <DOType id="ACT_T" cdc="ACT"><DA name="general" fc="ST" bType="BOOLEAN"/></DOType>
  </DataTypeTemplates>
</SCL>"#
        )
    }

    const GOOD_GSE: &str = r#"
    <GSE ldInst="LD0" cbName="gcbTrip">
      <Address><P type="MAC-Address">01-0C-CD-01-00-05</P><P type="APPID">0005</P><P type="VLAN-PRIORITY">4</P></Address>
      <MinTime unit="s" multiplier="m">4</MinTime><MaxTime unit="s" multiplier="m">1000</MaxTime>
    </GSE>
    <GSE ldInst="LD0" cbName="gcbSecond">
      <Address><P type="MAC-Address">01-0C-CD-01-00-06</P><P type="APPID">0006</P><P type="VLAN-PRIORITY">4</P></Address>
      <MinTime unit="s" multiplier="m">4</MinTime><MaxTime unit="s" multiplier="m">1000</MaxTime>
    </GSE>"#;

    const GOOD_CB: &str = r#"
      <GSEControl name="gcbTrip" datSet="dsTrip" confRev="1"/>
      <GSEControl name="gcbSecond" datSet="dsTrip" confRev="1"/>
      <SampledValueControl name="msvcb01" smvID="MU01" datSet="dsTrip" confRev="1" smpRate="80" nofASDU="1"/>"#;

    const BAD_GSE: &str = r#"
    <GSE ldInst="LD0" cbName="gcbTrip">
      <Address><P type="MAC-Address">01-0C-CD-01-00-05</P><P type="APPID">0005</P><P type="VLAN-PRIORITY">4</P></Address>
      <MinTime unit="s" multiplier="m">1000</MinTime><MaxTime unit="s" multiplier="m">4</MaxTime>
    </GSE>
    <GSE ldInst="LD0" cbName="gcbSecond">
      <Address><P type="MAC-Address">01-0C-CD-01-00-05</P><P type="APPID">0005</P><P type="VLAN-PRIORITY">1</P></Address>
      <MinTime unit="s" multiplier="m">4</MinTime><MaxTime unit="s" multiplier="m">1000</MaxTime>
    </GSE>"#;

    /// A breaker engineered select-before-operate whose type declares no `SBOw`: schema-valid,
    /// and impossible to operate.
    const UNOPERABLE: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="t"/>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/>
    <LN lnClass="CSWI" inst="1" prefix="" lnType="CSWI_T">
      <DOI name="Pos"><DAI name="ctlModel"><Val>sbo-with-enhanced-security</Val></DAI></DOI>
    </LN>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="CSWI_T" lnClass="CSWI"><DO name="Pos" type="DPC_T"/></LNodeType>
    <DOType id="DPC_T" cdc="DPC">
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModel_E"/>
      <DA name="Oper" fc="CO" bType="Struct" type="Oper_T"/>
    </DOType>
    <DAType id="Oper_T"><BDA name="ctlNum" bType="INT8U"/></DAType>
    <EnumType id="CtlModel_E"><EnumVal ord="4">sbo-with-enhanced-security</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;

    #[test]
    fn a_control_model_that_promises_a_service_the_type_lacks_is_a_finding() {
        // Schema-valid and impossible to operate: the client selects, the server answers
        // `object-non-existent`, and nothing in `SCL.xsd` objects. This is the check moved to
        // the left.
        let report = validate(UNOPERABLE, 50, Edition::Ed2_1).expect("validate");
        assert!(codes(&report, Severity::Error).contains(&FindingCode::ControlServicesMissing), "{:#?}", report.findings);
        let finding = report.errors().find(|f| f.code == FindingCode::ControlServicesMissing).expect("the finding");
        assert!(finding.message.contains("SBOw"), "{}", finding.message);
        assert_eq!(finding.at, "IED1LD0/CSWI1.Pos");
        // And an object with everything its model needs is not a finding.
        let ok = UNOPERABLE.replace(
            r#"<DA name="Oper" fc="CO" bType="Struct" type="Oper_T"/>"#,
            r#"<DA name="Oper" fc="CO" bType="Struct" type="Oper_T"/><DA name="SBOw" fc="CO" bType="Struct" type="Oper_T"/>"#,
        );
        let report = validate(&ok, 50, Edition::Ed2_1).expect("validate");
        assert!(!codes(&report, Severity::Error).contains(&FindingCode::ControlServicesMissing));
    }

    const BAD_CB: &str = r#""
      <DataSet name="dsGhost"><FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="nosuch" fc="ST"/></DataSet>
      <GSEControl name="gcbTrip" datSet="dsTrip" confRev="1"/>
      <GSEControl name="gcbSecond" datSet="dsNope" confRev="1"/>
      <SampledValueControl name="msvcb01" smvID="MU01" datSet="dsGhost" confRev="1" smpRate="80" nofASDU="0"/>"#;

    fn codes(report: &Report, severity: Severity) -> Vec<FindingCode> {
        report.findings.iter().filter(|f| f.severity == severity).map(|f| f.code).collect()
    }

    #[test]
    fn a_correctly_engineered_file_produces_nothing() {
        let r = validate(&scl(GOOD_GSE, GOOD_CB), 50, Edition::Ed2_1).unwrap();
        assert_eq!(r.scl_version, "2007B4");
        assert_eq!(r.ieds, ["IED1"]);
        assert!(r.findings.is_empty(), "{:#?}", r.findings);
        assert!(r.is_ok());
    }

    #[test]
    fn the_schema_valid_and_wrong_file_is_caught() {
        let r = validate(&scl(BAD_GSE, BAD_CB), 50, Edition::Ed2_1).unwrap();
        assert!(!r.is_ok());
        let errors = codes(&r, Severity::Error);
        // Two control blocks on one (MAC, APPID): on the wire they are one stream.
        assert!(errors.contains(&FindingCode::DuplicateStream), "{errors:?}");
        // MinTime above MaxTime would retransmit faster the longer a state holds.
        assert!(errors.contains(&FindingCode::RetransmissionTimes), "{errors:?}");
        // A control block naming a data set nobody defined.
        assert!(errors.contains(&FindingCode::MissingDataSet), "{errors:?}");
        // A data-set member naming an attribute the IED's own types do not have.
        assert!(errors.contains(&FindingCode::UnresolvedFcda), "{errors:?}");
        // `nofASDU` zero cannot be published.
        assert!(errors.contains(&FindingCode::SampleRate), "{errors:?}");
        // Priority 1 will not get a trip through a loaded switch.
        assert!(codes(&r, Severity::Warning).contains(&FindingCode::VlanPriority), "{r:#?}");
    }

    #[test]
    fn one_appid_on_two_addresses_is_a_warning_not_an_error() {
        let gse = GOOD_GSE.replace(r#"<P type="APPID">0006</P>"#, r#"<P type="APPID">0005</P>"#);
        let r = validate(&scl(&gse, GOOD_CB), 50, Edition::Ed2_1).unwrap();
        assert!(r.is_ok(), "a switch filters on the MAC, so this still works: {:#?}", r.findings);
        assert_eq!(codes(&r, Severity::Warning), [FindingCode::DuplicateAppid]);
    }

    #[test]
    fn an_object_reference_longer_than_the_edition_allows() {
        let file = scl(GOOD_GSE, GOOD_CB).replace("inst=\"LD0\"", &alloc::format!("inst=\"LD0{}\"", "X".repeat(60)));
        let r = validate(&file, 50, Edition::Ed1).unwrap();
        assert!(codes(&r, Severity::Error).contains(&FindingCode::ObjectReferenceTooLong), "{r:#?}");
        // The same file is inside Edition 2's longer limit.
        let r2 = validate(&file, 50, Edition::Ed2_1).unwrap();
        assert!(!codes(&r2, Severity::Error).contains(&FindingCode::ObjectReferenceTooLong), "{r2:#?}");
    }

    #[test]
    fn a_dangling_subscription_is_an_error() {
        // An input bound to a publisher the file does not hold: schema-valid, and the
        // device will simply never receive anything.
        let cb = alloc::format!(
            r#"{GOOD_CB}
      <Inputs><ExtRef iedName="Ghost" ldInst="LD0" doName="Tr" serviceType="GOOSE" srcLDInst="LD0" srcCBName="gcbX"/></Inputs>"#
        );
        let r = validate(&scl(GOOD_GSE, &cb), 50, Edition::Ed2_1).unwrap();
        assert!(codes(&r, Severity::Error).contains(&FindingCode::UnresolvedSubscription), "{r:#?}");
    }
}
