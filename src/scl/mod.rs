//! Reading IEC 61850-6 SCL: loading a model, resolving subscriptions, checking engineering.
//!
//! Three things, in the order a project needs them:
//!
//! - [`IedModel::from_scl`] loads one IED of an ICD, CID, IID or SCD into the descriptor a
//!   publisher and a server work from.
//! - [`subscriptions`] answers the question a *subscriber* has — what am I supposed to
//!   receive, and from where — by resolving each `Inputs/ExtRef` against the publisher's own
//!   control block and `Communication` address, somewhere else in the same document.
//! - [`validate`] reports the engineering errors the XML schema is happy to accept: two
//!   streams on one address, a data set nobody defined, a binding that resolves to nothing.
//!
//! Read-only, on `roxmltree`; element names are matched by local name so that files with
//! unusual namespace prefixes still load. Editing and writing SCL is a later layer.
//!
//! The loader is **lenient by default**: real SCL files — `OpenSCD`'s own test corpus among
//! them — carry dangling type references and half-finished control blocks, and a tool that
//! refuses the whole IED for one of them is useless. Everything it works around is recorded
//! as a [`Diagnostic`] with a stable [`DiagnosticCode`] on the model. [`LoadOptions::strict`]
//! turns the first diagnostic into an error instead.

use alloc::string::String;
use alloc::vec::Vec;
use std::collections::HashMap;

use roxmltree::{Document, Node};

mod validate;

pub use validate::{Finding, FindingCode, Report, Severity, validate};

use crate::common::MacAddr;
use crate::common::{Error, Fc, OptFlds, Result, TrgOps};
use crate::model::{
    AccessPoint, BType, DataAttribute, DataObject, DataSet, Diagnostic, DiagnosticCode, EnumType, ExtRef, Fcda, GseAddress, GseControl, IedModel, Log,
    LogControl, LogicalDevice, LogicalNode, OsiAddress, ReportControl, ServiceType, SettingControl, SmvAddress, SmvControl,
};

/// How to load.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// Fail on the first thing that would otherwise become a [`Diagnostic`].
    pub strict: bool,
}

fn scl_err(msg: impl Into<String>) -> Error {
    Error::Scl(msg.into())
}

/// A parsed SCL document.
///
/// Parsing is the expensive half of reading an SCD, and a station file holds every IED in
/// the substation: loading one model per IED, or resolving one IED's subscriptions against
/// the publishers of all the others, means asking the same document many questions. Parse
/// it once and ask [`Scl`].
///
/// The one-shot free functions ([`subscriptions`], [`validate`], [`IedModel::from_scl`]) are
/// this type with the parse inlined, and are the right thing for a single question.
pub struct Scl<'x> {
    doc: Document<'x>,
}

impl<'x> Scl<'x> {
    /// Parse SCL text.
    pub fn parse(xml: &'x str) -> Result<Scl<'x>> {
        Ok(Scl { doc: Document::parse(xml).map_err(|e| scl_err(alloc::format!("XML: {e}")))? })
    }

    fn root(&self) -> Node<'_, 'x> {
        self.doc.root_element()
    }

    /// Names of the IEDs the document holds, in document order.
    pub fn ied_names(&self) -> Vec<String> {
        children(self.root(), "IED").filter_map(|n| n.attribute("name").map(String::from)).collect()
    }

    /// The `version`/`revision`/`release` of the SCL root, as `2007B4`-style text.
    pub fn version(&self) -> String {
        version_of(self.root())
    }

    /// Load one IED leniently. Pass `None` for the only/first IED.
    pub fn model(&self, ied_name: Option<&str>) -> Result<IedModel> {
        self.model_with(ied_name, LoadOptions::default())
    }

    /// Load one IED with options.
    pub fn model_with(&self, ied_name: Option<&str>, options: LoadOptions) -> Result<IedModel> {
        let root = self.root();
        let ied = children(root, "IED").find(|n| ied_name.is_none_or(|want| n.attribute("name") == Some(want))).ok_or(Error::NotFound("IED"))?;
        let name = ied.attribute("name").ok_or_else(|| scl_err("IED without name"))?;
        let mut loader = Loader { t: Templates::collect(root), comm: Communication::default(), diags: Vec::new(), strict: options.strict, ied: name };
        loader.collect_communication(root)?;

        let mut logical_devices = Vec::new();
        let mut access_points = Vec::new();
        for ap in children(ied, "AccessPoint") {
            let ap_name = ap.attribute("name").unwrap_or("");
            access_points.push(AccessPoint { name: String::from(ap_name), address: loader.comm.osi.get(ap_name).cloned() });
            for server in children(ap, "Server") {
                for ld in children(server, "LDevice") {
                    if let Some(ld) = loader.load_ld(ld)? {
                        logical_devices.push(ld);
                    }
                }
            }
        }
        Ok(IedModel {
            name: String::from(name),
            manufacturer: ied.attribute("manufacturer").map(String::from),
            ied_type: ied.attribute("type").map(String::from),
            config_version: ied.attribute("configVersion").map(String::from),
            scl_version: version_of(root),
            access_points,
            logical_devices,
            enum_types: loader.t.enums.clone(),
            diagnostics: loader.diags,
        })
    }

    /// Every IED in the document, loaded leniently.
    pub fn models(&self) -> Result<Vec<IedModel>> {
        self.ied_names().iter().map(|n| self.model(Some(n))).collect()
    }
}

/// Names of the IEDs in an SCL document.
pub fn ied_names(xml: &str) -> Result<Vec<String>> {
    Ok(Scl::parse(xml)?.ied_names())
}

/// The `version`/`revision`/`release` of the SCL root, as `2007B4`-style text.
pub fn scl_version(xml: &str) -> Result<String> {
    Ok(Scl::parse(xml)?.version())
}

fn version_of(root: Node<'_, '_>) -> String {
    let mut v = String::from(root.attribute("version").unwrap_or("2003"));
    v.push_str(root.attribute("revision").unwrap_or(""));
    v.push_str(root.attribute("release").unwrap_or(""));
    v
}

impl IedModel {
    /// Load the IED `ied_name` from SCL text, leniently. Pass `None` for the only/first IED.
    pub fn from_scl(xml: &str, ied_name: Option<&str>) -> Result<IedModel> {
        IedModel::from_scl_with(xml, ied_name, LoadOptions::default())
    }

    /// Load with options.
    pub fn from_scl_with(xml: &str, ied_name: Option<&str>, options: LoadOptions) -> Result<IedModel> {
        Scl::parse(xml)?.model_with(ied_name, options)
    }

    /// Load from a file, leniently.
    pub fn from_scl_file(path: impl AsRef<std::path::Path>, ied_name: Option<&str>) -> Result<IedModel> {
        let xml = std::fs::read_to_string(path).map_err(|e| scl_err(alloc::format!("read: {e}")))?;
        IedModel::from_scl(&xml, ied_name)
    }
}

fn children<'a, 'i>(n: Node<'a, 'i>, local: &'static str) -> impl Iterator<Item = Node<'a, 'i>> {
    n.children().filter(move |c| c.is_element() && c.tag_name().name() == local)
}

fn child<'a, 'i>(n: Node<'a, 'i>, local: &'static str) -> Option<Node<'a, 'i>> {
    children(n, local).next()
}

/// `TrgOps`, with the schema's own defaults — every flag false except `gi`, which is **true**
/// unless the file says otherwise (`SCL_IED.xsd` `tTrgOps` ✅).
fn trg_ops(control: Node<'_, '_>) -> TrgOps {
    let t = child(control, "TrgOps");
    let flag = |name: &str, default: bool| t.map_or(default, |t| attr_bool(t, name, default));
    TrgOps::NONE
        .with_data_change(flag("dchg", false))
        .with_quality_change(flag("qchg", false))
        .with_data_update(flag("dupd", false))
        .with_integrity(flag("period", false))
        .with_general_interrogation(flag("gi", true))
}

/// `OptFields`, with the schema's own defaults — every flag false except `bufOvfl`, which is
/// **true** unless the file says otherwise (`SCL_IED.xsd` `agOptFields` ✅).
///
/// `segmentation` has no SCL attribute in these schema versions: whether a server segments a
/// report is a property of the server's PDU size, not of the engineering, so it is not read
/// here and is decided when a report is built.
fn opt_fields(control: Node<'_, '_>) -> OptFlds {
    let o = child(control, "OptFields");
    let flag = |name: &str, default: bool| o.map_or(default, |o| attr_bool(o, name, default));
    OptFlds::NONE
        .with_sequence_number(flag("seqNum", false))
        .with_report_time_stamp(flag("timeStamp", false))
        .with_reason_for_inclusion(flag("reasonCode", false))
        .with_data_set_name(flag("dataSet", false))
        .with_data_reference(flag("dataRef", false))
        .with_buffer_overflow(flag("bufOvfl", true))
        .with_entry_id(flag("entryID", false))
        .with_conf_revision(flag("configRef", false))
}

fn attr_u32(n: Node<'_, '_>, name: &str, default: u32) -> u32 {
    n.attribute(name).and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

fn attr_bool(n: Node<'_, '_>, name: &str, default: bool) -> bool {
    match n.attribute(name) {
        Some("true") => true,
        Some("false") => false,
        _ => default,
    }
}

const MAX_TYPE_DEPTH: usize = 16;

struct Templates<'a, 'i> {
    lns: HashMap<&'a str, Node<'a, 'i>>,
    dos: HashMap<&'a str, Node<'a, 'i>>,
    das: HashMap<&'a str, Node<'a, 'i>>,
    enums: Vec<EnumType>,
}

impl<'a, 'i> Templates<'a, 'i> {
    fn collect(root: Node<'a, 'i>) -> Self {
        let mut t = Templates { lns: HashMap::new(), dos: HashMap::new(), das: HashMap::new(), enums: Vec::new() };
        if let Some(dtt) = child(root, "DataTypeTemplates") {
            for n in dtt.children().filter(Node::is_element) {
                let Some(id) = n.attribute("id") else { continue };
                match n.tag_name().name() {
                    "LNodeType" => {
                        t.lns.insert(id, n);
                    }
                    "DOType" => {
                        t.dos.insert(id, n);
                    }
                    "DAType" => {
                        t.das.insert(id, n);
                    }
                    "EnumType" => {
                        // `ord` is required; an `EnumVal` without one names nothing the wire
                        // can carry and is dropped rather than given an invented number.
                        let values = children(n, "EnumVal")
                            .filter_map(|v| Some((v.attribute("ord")?.parse().ok()?, String::from(v.text().unwrap_or("").trim()))))
                            .collect();
                        t.enums.push(EnumType { id: String::from(id), values });
                    }
                    _ => {}
                }
            }
        }
        t
    }
}

#[derive(Default)]
struct Communication {
    /// (ldInst, cbName) → address
    gse: HashMap<(String, String), GseAddress>,
    smv: HashMap<(String, String), SmvAddress>,
    /// apName → the OSI addressing a client associates over
    osi: HashMap<String, OsiAddress>,
}

struct Loader<'a, 'i> {
    t: Templates<'a, 'i>,
    comm: Communication,
    diags: Vec<Diagnostic>,
    strict: bool,
    ied: &'a str,
}

impl<'a, 'i> Loader<'a, 'i> {
    /// Record a diagnostic, or fail if strict.
    fn diag(&mut self, code: DiagnosticCode, at: String, message: String) -> Result<()> {
        let d = Diagnostic { code, at, message };
        if self.strict {
            return Err(scl_err(alloc::format!("{d}")));
        }
        self.diags.push(d);
        Ok(())
    }

    fn collect_communication(&mut self, root: Node<'a, 'i>) -> Result<()> {
        let Some(comm) = child(root, "Communication") else { return Ok(()) };
        for sn in children(comm, "SubNetwork") {
            for ap in children(sn, "ConnectedAP").filter(|a| a.attribute("iedName") == Some(self.ied)) {
                // The access point's own address: the selectors an association is opened
                // with, as against the GSE/SMV addresses of the multicast streams below.
                if let Some(addr) = child(ap, "Address") {
                    let osi = osi_address(addr);
                    if !osi.is_empty() {
                        self.comm.osi.insert(String::from(ap.attribute("apName").unwrap_or("")), osi);
                    }
                }
                for g in children(ap, "GSE") {
                    let (Some(ld), Some(cb)) = (g.attribute("ldInst"), g.attribute("cbName")) else {
                        self.diag(DiagnosticCode::MissingAttribute, String::from("Communication/GSE"), String::from("GSE without ldInst/cbName"))?;
                        continue;
                    };
                    let at = alloc::format!("Communication/GSE {ld}.{cb}");
                    let Some(addr) = child(g, "Address") else {
                        self.diag(DiagnosticCode::BadAddress, at, String::from("GSE without Address"))?;
                        continue;
                    };
                    let Some((mac, appid, vlan_id, vlan_priority)) = address_params(addr) else {
                        self.diag(DiagnosticCode::BadAddress, at, String::from("Address without a valid MAC-Address and APPID"))?;
                        continue;
                    };
                    let min_time_ms = child(g, "MinTime").and_then(duration_ms);
                    let max_time_ms = child(g, "MaxTime").and_then(duration_ms);
                    self.comm.gse.insert((String::from(ld), String::from(cb)), GseAddress { mac, appid, vlan_id, vlan_priority, min_time_ms, max_time_ms });
                }
                for s in children(ap, "SMV") {
                    let (Some(ld), Some(cb)) = (s.attribute("ldInst"), s.attribute("cbName")) else {
                        self.diag(DiagnosticCode::MissingAttribute, String::from("Communication/SMV"), String::from("SMV without ldInst/cbName"))?;
                        continue;
                    };
                    let at = alloc::format!("Communication/SMV {ld}.{cb}");
                    let Some(addr) = child(s, "Address") else {
                        self.diag(DiagnosticCode::BadAddress, at, String::from("SMV without Address"))?;
                        continue;
                    };
                    let Some((mac, appid, vlan_id, vlan_priority)) = address_params(addr) else {
                        self.diag(DiagnosticCode::BadAddress, at, String::from("Address without a valid MAC-Address and APPID"))?;
                        continue;
                    };
                    self.comm.smv.insert((String::from(ld), String::from(cb)), SmvAddress { mac, appid, vlan_id, vlan_priority });
                }
            }
        }
        Ok(())
    }

    fn load_ld(&mut self, ld: Node<'a, 'i>) -> Result<Option<LogicalDevice>> {
        let Some(inst) = ld.attribute("inst") else {
            self.diag(DiagnosticCode::MissingAttribute, alloc::format!("{}/LDevice", self.ied), String::from("LDevice without inst"))?;
            return Ok(None);
        };
        let name = match ld.attribute("ldName") {
            Some(n) if !n.is_empty() => String::from(n),
            _ => {
                let mut s = String::from(self.ied);
                s.push_str(inst);
                s
            }
        };
        let mut logical_nodes = Vec::new();
        for n in ld.children().filter(|c| c.is_element() && matches!(c.tag_name().name(), "LN0" | "LN")) {
            if let Some(ln) = self.load_ln(n, inst)? {
                logical_nodes.push(ln);
            }
        }
        Ok(Some(LogicalDevice { inst: String::from(inst), name, logical_nodes }))
    }

    #[allow(clippy::too_many_lines)] // one straight pass over the LN's children
    fn load_ln(&mut self, n: Node<'a, 'i>, ld_inst: &str) -> Result<Option<LogicalNode>> {
        let class = n.attribute("lnClass").unwrap_or("LLN0");
        let inst = n.attribute("inst").unwrap_or("");
        let prefix = n.attribute("prefix").unwrap_or("");
        let mut name = String::from(prefix);
        name.push_str(class);
        name.push_str(inst);
        let at = alloc::format!("{}/{ld_inst}/{name}", self.ied);
        let Some(ln_type) = n.attribute("lnType") else {
            self.diag(DiagnosticCode::MissingAttribute, at, String::from("LN without lnType"))?;
            return Ok(None);
        };

        let mut data_objects = Vec::new();
        if let Some(lnt) = self.t.lns.get(ln_type).copied() {
            for d in children(lnt, "DO") {
                let (Some(dname), Some(dtype)) = (d.attribute("name"), d.attribute("type")) else {
                    self.diag(DiagnosticCode::MissingAttribute, alloc::format!("LNodeType `{ln_type}`"), String::from("DO without name/type"))?;
                    continue;
                };
                if let Some(dobj) = self.data_object(&at, dname, dtype, 0)? {
                    data_objects.push(dobj);
                }
            }
        } else {
            self.diag(DiagnosticCode::MissingLNodeType, at.clone(), alloc::format!("LNodeType `{ln_type}` not found"))?;
        }

        let mut data_sets = Vec::new();
        for ds in children(n, "DataSet") {
            let Some(dname) = ds.attribute("name") else {
                self.diag(DiagnosticCode::MissingAttribute, at.clone(), String::from("DataSet without name"))?;
                continue;
            };
            let mut members = Vec::new();
            for f in children(ds, "FCDA") {
                let Some(fc) = f.attribute("fc").and_then(Fc::parse) else {
                    self.diag(DiagnosticCode::BadFcda, alloc::format!("{at}.{dname}"), String::from("FCDA without a valid fc"))?;
                    continue;
                };
                members.push(Fcda {
                    ld_inst: String::from(f.attribute("ldInst").unwrap_or(ld_inst)),
                    prefix: String::from(f.attribute("prefix").unwrap_or("")),
                    ln_class: String::from(f.attribute("lnClass").unwrap_or("")),
                    ln_inst: String::from(f.attribute("lnInst").unwrap_or("")),
                    do_name: String::from(f.attribute("doName").unwrap_or("")),
                    da_name: f.attribute("daName").filter(|s| !s.is_empty()).map(String::from),
                    fc,
                });
            }
            data_sets.push(DataSet { name: String::from(dname), members });
        }

        let mut gse_controls = Vec::new();
        for g in children(n, "GSEControl") {
            let Some(gname) = g.attribute("name") else {
                self.diag(DiagnosticCode::MissingAttribute, at.clone(), String::from("GSEControl without name"))?;
                continue;
            };
            gse_controls.push(GseControl {
                name: String::from(gname),
                dat_set: g.attribute("datSet").map(String::from),
                conf_rev: attr_u32(g, "confRev", 1),
                go_id: g.attribute("appID").map(String::from),
                fixed_offs: attr_bool(g, "fixedOffs", false),
                address: self.comm.gse.get(&(String::from(ld_inst), String::from(gname))).cloned(),
            });
        }

        let mut smv_controls = Vec::new();
        for s in children(n, "SampledValueControl") {
            let Some(sname) = s.attribute("name") else {
                self.diag(DiagnosticCode::MissingAttribute, at.clone(), String::from("SampledValueControl without name"))?;
                continue;
            };
            smv_controls.push(SmvControl {
                name: String::from(sname),
                smv_id: String::from(s.attribute("smvID").unwrap_or("")),
                dat_set: s.attribute("datSet").map(String::from),
                conf_rev: attr_u32(s, "confRev", 1),
                smp_rate: attr_u32(s, "smpRate", 80),
                nof_asdu: attr_u32(s, "nofASDU", 1),
                smp_mod: String::from(s.attribute("smpMod").unwrap_or("SmpPerPeriod")),
                multicast: attr_bool(s, "multicast", true),
                address: self.comm.smv.get(&(String::from(ld_inst), String::from(sname))).cloned(),
            });
        }

        let mut report_controls = Vec::new();
        for r in children(n, "ReportControl") {
            let Some(rname) = r.attribute("name") else {
                self.diag(DiagnosticCode::MissingAttribute, at.clone(), String::from("ReportControl without name"))?;
                continue;
            };
            report_controls.push(ReportControl {
                name: String::from(rname),
                dat_set: r.attribute("datSet").map(String::from),
                conf_rev: attr_u32(r, "confRev", 1),
                buffered: attr_bool(r, "buffered", false),
                rpt_id: r.attribute("rptID").map(String::from),
                buf_time_ms: attr_u32(r, "bufTime", 0),
                intg_pd_ms: attr_u32(r, "intgPd", 0),
                max_instances: child(r, "RptEnabled").map_or(1, |e| attr_u32(e, "max", 1)),
                indexed: attr_bool(r, "indexed", true),
                trg_ops: trg_ops(r),
                opt_flds: opt_fields(r),
            });
        }

        let mut log_controls = Vec::new();
        for l in children(n, "LogControl") {
            let (Some(lname), Some(log_name)) = (l.attribute("name"), l.attribute("logName")) else {
                self.diag(DiagnosticCode::MissingAttribute, at.clone(), String::from("LogControl without name or logName"))?;
                continue;
            };
            log_controls.push(LogControl {
                name: String::from(lname),
                dat_set: l.attribute("datSet").map(String::from),
                log_name: String::from(log_name),
                log_ld_inst: l.attribute("ldInst").map(String::from),
                log_ena: attr_bool(l, "logEna", true),
                reason_code: attr_bool(l, "reasonCode", true),
                buf_time_ms: attr_u32(l, "bufTime", 0),
                intg_pd_ms: attr_u32(l, "intgPd", 0),
                trg_ops: trg_ops(l),
            });
        }

        // `Log` has an *optional* name: the unnamed one is the logical device's default log.
        let logs: Vec<Log> = children(n, "Log").map(|l| Log { name: String::from(l.attribute("name").unwrap_or("")) }).collect();

        // `SettingControl` is an LN0 element and there is at most one.
        let setting_control = child(n, "SettingControl").map(|sc| SettingControl {
            num_of_sgs: attr_u32(sc, "numOfSGs", 1).max(1),
            act_sg: attr_u32(sc, "actSG", 1).max(1),
            resv_tms: sc.attribute("resvTms").and_then(|v| v.parse().ok()),
        });

        // `Inputs/ExtRef`: what this logical node subscribes to. Real files carry entries
        // that are only half-bound (an operator has picked the signal but not the source
        // control block yet); they are kept as they are rather than dropped, because a
        // tool that reports what is unbound is more useful than one that hides it.
        let mut inputs = Vec::new();
        for ins in children(n, "Inputs") {
            for x in children(ins, "ExtRef") {
                inputs.push(ExtRef {
                    ied_name: x.attribute("iedName").map(String::from),
                    ld_inst: x.attribute("ldInst").map(String::from),
                    prefix: String::from(x.attribute("prefix").unwrap_or("")),
                    ln_class: x.attribute("lnClass").map(String::from),
                    ln_inst: String::from(x.attribute("lnInst").unwrap_or("")),
                    do_name: x.attribute("doName").map(String::from),
                    da_name: x.attribute("daName").filter(|s| !s.is_empty()).map(String::from),
                    service_type: x.attribute("serviceType").and_then(ServiceType::parse),
                    src_ld_inst: x.attribute("srcLDInst").map(String::from),
                    src_prefix: String::from(x.attribute("srcPrefix").unwrap_or("")),
                    src_ln_class: x.attribute("srcLNClass").map(String::from),
                    src_ln_inst: String::from(x.attribute("srcLNInst").unwrap_or("")),
                    src_cb_name: x.attribute("srcCBName").map(String::from),
                    int_addr: x.attribute("intAddr").map(String::from),
                });
            }
        }

        // Instance values (`DOI`/`SDI`/`DAI`/`Val`) override the type template's defaults.
        // This is where a real SCD says a breaker is select-before-operate, what a report
        // control block's `RptID` is, and what a scale factor is set to — none of which is in
        // the `DataTypeTemplates` section. A model that reads only the templates has the
        // *type's* value, which is very often not the device's.
        Self::apply_instance_values(n, &mut data_objects);

        Ok(Some(LogicalNode {
            name,
            class: String::from(class),
            ln_type: String::from(ln_type),
            data_objects,
            data_sets,
            gse_controls,
            smv_controls,
            report_controls,
            log_controls,
            logs,
            setting_control,
            inputs,
        }))
    }

    /// Apply an LN's `DOI` children onto the data objects built from its type.
    fn apply_instance_values(ln: Node<'_, '_>, objects: &mut [DataObject]) {
        for doi in children(ln, "DOI") {
            let Some(name) = doi.attribute("name") else { continue };
            if let Some(obj) = objects.iter_mut().find(|o| o.name == name) {
                Self::apply_to_object(doi, obj, 0);
            }
        }
    }

    fn apply_to_object(node: Node<'_, '_>, obj: &mut DataObject, depth: usize) {
        if depth > MAX_TYPE_DEPTH {
            return;
        }
        for c in node.children().filter(Node::is_element) {
            let Some(name) = c.attribute("name") else { continue };
            match c.tag_name().name() {
                "DAI" => {
                    if let Some(a) = obj.attributes.iter_mut().find(|a| a.name == name) {
                        if let Some(v) = instance_value(c) {
                            a.value = Some(v);
                        }
                        let groups = group_values(c);
                        if !groups.is_empty() {
                            a.group_values = groups;
                        }
                    }
                }
                // An `SDI` is a sub data object *or* a structured attribute; which one it is
                // depends on the type, so both are tried rather than guessed at.
                "SDI" => {
                    if let Some(sub) = obj.sub_objects.iter_mut().find(|o| o.name == name) {
                        Self::apply_to_object(c, sub, depth + 1);
                    } else if let Some(a) = obj.attributes.iter_mut().find(|a| a.name == name) {
                        Self::apply_to_attribute(c, a, depth + 1);
                    }
                }
                _ => {}
            }
        }
    }

    fn apply_to_attribute(node: Node<'_, '_>, attr: &mut DataAttribute, depth: usize) {
        if depth > MAX_TYPE_DEPTH {
            return;
        }
        for c in node.children().filter(Node::is_element) {
            let Some(name) = c.attribute("name") else { continue };
            let Some(child_attr) = attr.children.iter_mut().find(|a| a.name == name) else { continue };
            match c.tag_name().name() {
                "DAI" => {
                    if let Some(v) = instance_value(c) {
                        child_attr.value = Some(v);
                    }
                    let groups = group_values(c);
                    if !groups.is_empty() {
                        child_attr.group_values = groups;
                    }
                }
                "SDI" => Self::apply_to_attribute(c, child_attr, depth + 1),
                _ => {}
            }
        }
    }

    fn data_object(&mut self, at: &str, name: &str, type_id: &str, depth: usize) -> Result<Option<DataObject>> {
        let here = alloc::format!("{at}.{name}");
        if depth > MAX_TYPE_DEPTH {
            self.diag(DiagnosticCode::NestingTooDeep, here, String::from("SDO nesting deeper than 16"))?;
            return Ok(None);
        }
        let Some(dot) = self.t.dos.get(type_id).copied() else {
            self.diag(DiagnosticCode::MissingDOType, here, alloc::format!("DOType `{type_id}` not found"))?;
            return Ok(None);
        };
        let mut attributes = Vec::new();
        let mut sub_objects = Vec::new();
        for n in dot.children().filter(Node::is_element) {
            match n.tag_name().name() {
                "DA" => {
                    if let Some(da) = self.data_attribute(&here, n, None, depth + 1)? {
                        attributes.push(da);
                    }
                }
                "SDO" => {
                    let (Some(sname), Some(stype)) = (n.attribute("name"), n.attribute("type")) else {
                        self.diag(DiagnosticCode::MissingAttribute, here.clone(), String::from("SDO without name/type"))?;
                        continue;
                    };
                    if let Some(sdo) = self.data_object(&here, sname, stype, depth + 1)? {
                        sub_objects.push(sdo);
                    }
                }
                _ => {}
            }
        }
        Ok(Some(DataObject {
            name: String::from(name),
            cdc: String::from(dot.attribute("cdc").unwrap_or("")),
            type_id: String::from(type_id),
            attributes,
            sub_objects,
        }))
    }

    fn data_attribute(&mut self, at: &str, n: Node<'a, 'i>, inherited_fc: Option<Fc>, depth: usize) -> Result<Option<DataAttribute>> {
        let Some(name) = n.attribute("name") else {
            self.diag(DiagnosticCode::MissingAttribute, String::from(at), String::from("DA/BDA without name"))?;
            return Ok(None);
        };
        let here = alloc::format!("{at}.{name}");
        if depth > MAX_TYPE_DEPTH {
            self.diag(DiagnosticCode::NestingTooDeep, here, String::from("Struct nesting deeper than 16"))?;
            return Ok(None);
        }
        let fc = match (n.attribute("fc").map(|f| (f, Fc::parse(f))), inherited_fc) {
            (Some((_, Some(fc))), _) | (None, Some(fc)) => fc,
            (Some((f, None)), _) => {
                self.diag(DiagnosticCode::UnknownFc, here, alloc::format!("unknown fc `{f}`"))?;
                return Ok(None);
            }
            (None, None) => {
                self.diag(DiagnosticCode::MissingFc, here, String::from("DA without fc"))?;
                return Ok(None);
            }
        };
        let btype = BType::parse(n.attribute("bType").unwrap_or(""));
        let type_id = n.attribute("type").map(String::from);
        let value = child(n, "Val").and_then(|v| v.text()).map(|s| String::from(s.trim()));
        let mut children_out = Vec::new();
        if btype == BType::Struct {
            if let Some(dat) = type_id.as_deref().and_then(|tid| self.t.das.get(tid).copied()) {
                for b in children(dat, "BDA") {
                    if let Some(bda) = self.data_attribute(&here, b, Some(fc), depth + 1)? {
                        children_out.push(bda);
                    }
                }
            } else {
                let tid = type_id.clone().unwrap_or_default();
                self.diag(DiagnosticCode::MissingDAType, here.clone(), alloc::format!("DAType `{tid}` not found"))?;
            }
        }
        Ok(Some(DataAttribute { name: String::from(name), fc, btype, type_id, children: children_out, value, group_values: Vec::new() }))
    }
}

/// The `Val` of a `DAI`, ignoring the setting-group variants.
///
/// A `DAI` under a setting-group control carries one `Val` per group (`sGroup="1"`, `"2"`, …);
/// the model holds one value, so the ungrouped one is taken, and the first group's only when
/// there is no ungrouped one. Which group is *active* is a runtime question, not an
/// engineering one.
fn instance_value(dai: Node<'_, '_>) -> Option<String> {
    let text = |v: Node<'_, '_>| v.text().map(|s| String::from(s.trim()));
    children(dai, "Val").find(|v| v.attribute("sGroup").is_none()).and_then(text).or_else(|| children(dai, "Val").next().and_then(text))
}

/// The per-group values of a setting, as `(group, text)` pairs in document order.
fn group_values(dai: Node<'_, '_>) -> Vec<(u32, String)> {
    children(dai, "Val").filter_map(|v| Some((v.attribute("sGroup")?.parse().ok()?, String::from(v.text().unwrap_or("").trim())))).collect()
}

/// An SCL duration element (`MinTime`, `MaxTime`) in milliseconds.
///
/// The value carries `unit="s"` and an SI `multiplier`; every file we have writes
/// `multiplier="m"`, but one that omits it means whole seconds, and reading 1000 there as a
/// millisecond would turn a one-second heartbeat into a 1 ms flood.
fn duration_ms(n: Node<'_, '_>) -> Option<u32> {
    let value: f64 = n.text()?.trim().parse().ok()?;
    let scale = match n.attribute("multiplier").unwrap_or("") {
        "m" => 1.0,
        "u" => 0.001,
        "n" => 0.000_001,
        "k" => 1_000_000.0,
        _ => 1000.0,
    };
    let ms = value * scale;
    (ms.is_finite() && (0.0..=f64::from(u32::MAX)).contains(&ms)).then_some(ms as u32)
}

/// The OSI addressing of a `ConnectedAP/Address`.
///
/// Selectors are hex strings the schema constrains to `[0-9A-F]+`; an odd number of digits
/// is padded on the left rather than refused, because a file that writes `1` for `01` is
/// wrong in a way that is obvious and harmless to read.
fn osi_address(addr: Node<'_, '_>) -> OsiAddress {
    let mut out = OsiAddress::default();
    for p in children(addr, "P") {
        let text = p.text().unwrap_or("").trim();
        match p.attribute("type") {
            Some("IP") => out.ip = Some(String::from(text)),
            Some("OSI-TSEL") => out.t_sel = hex_octets(text),
            Some("OSI-SSEL") => out.s_sel = hex_octets(text),
            Some("OSI-PSEL") => out.p_sel = hex_octets(text),
            Some("OSI-AP-Title") => {
                let arcs: Option<Vec<u32>> = text.split([',', '.']).map(|a| a.trim().parse().ok()).collect();
                out.ap_title = arcs.filter(|a: &Vec<u32>| !a.is_empty());
            }
            Some("OSI-AE-Qualifier") => out.ae_qualifier = text.parse().ok(),
            _ => {}
        }
    }
    out
}

/// A hex string as octets, padded on the left to an even number of digits.
fn hex_octets(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let padded = if text.len() % 2 == 0 { String::from(text) } else { alloc::format!("0{text}") };
    let mut out = Vec::with_capacity(padded.len() / 2);
    let bytes = padded.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let pair = core::str::from_utf8(bytes.get(i..i + 2)?).ok()?;
        out.push(u8::from_str_radix(pair, 16).ok()?);
    }
    Some(out)
}

fn address_params(addr: Node<'_, '_>) -> Option<(MacAddr, u16, u16, u8)> {
    let mut mac = None;
    let mut appid = None;
    let mut vlan_id = 0u16;
    let mut vlan_priority = 4u8;
    for p in children(addr, "P") {
        let text = p.text().unwrap_or("").trim();
        match p.attribute("type") {
            Some("MAC-Address") => mac = MacAddr::parse(text).ok(),
            Some("APPID") => appid = u16::from_str_radix(text, 16).ok(),
            Some("VLAN-ID") => vlan_id = u16::from_str_radix(text, 16).unwrap_or(0),
            Some("VLAN-PRIORITY") => vlan_priority = text.parse().unwrap_or(4),
            _ => {}
        }
    }
    Some((mac?, appid?, vlan_id, vlan_priority))
}

/// A process-bus stream one IED subscribes to, resolved from the `ExtRef`s that name it.
///
/// Everything a subscriber needs is here: the multicast address and APPID come from the
/// publisher's `Communication` section, the `confRev` from its control block, and the list
/// of `ExtRef`s says which of the data set's members this IED actually wired up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    /// `iedName` of the publisher.
    pub publisher: String,
    /// The publisher's control block, as `LDName/LNName.cbName`.
    pub control_block: String,
    /// `gocbRef` for GOOSE (`LDName/LNName$GO$cbName`), or `svID` for sampled values —
    /// the identifier the frames actually carry.
    pub identifier: String,
    /// Destination multicast MAC.
    pub dst: MacAddr,
    /// APPID.
    pub appid: u16,
    /// `confRev` the frames must carry.
    pub conf_rev: u32,
    /// Samples per second, for a sampled-value stream.
    pub samples_per_second: Option<u32>,
    /// What the octets of each ASDU mean, for a sampled-value stream whose data set has a
    /// fixed-width layout — so a subscriber configured from the SCD decodes named channels
    /// and not a block of octets.
    #[cfg(feature = "sv")]
    pub layout: Option<crate::proto::sv::SampleLayout>,
    /// The `ExtRef`s of the subscribing IED that this stream feeds.
    pub ext_refs: Vec<ExtRef>,
}

impl Subscription {
    /// The GOOSE subscriber configuration for this stream.
    #[cfg(feature = "goose")]
    pub fn goose_config(&self) -> crate::proto::goose::SubscriberConfig {
        use crate::proto::goose::{SubscriberConfig, SubscriptionKey};
        SubscriberConfig::new(SubscriptionKey { dst: self.dst, appid: self.appid, gocb_ref: self.identifier.clone() }).with_conf_rev(self.conf_rev)
    }

    /// The sampled-value stream configuration for this stream.
    #[cfg(feature = "sv")]
    pub fn sv_config(&self) -> crate::proto::sv::StreamConfig {
        use crate::proto::sv::{StreamConfig, StreamKey};
        let mut cfg = StreamConfig::new(StreamKey { dst: self.dst, appid: self.appid, sv_id: self.identifier.clone() })
            .with_conf_rev(self.conf_rev)
            .with_samples_per_second(self.samples_per_second.unwrap_or(4000));
        if let Some(layout) = self.layout.clone() {
            cfg = cfg.with_layout(layout);
        }
        cfg
    }
}

/// What one IED subscribes to, according to the SCD.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Subscriptions {
    /// GOOSE streams, one per source control block.
    pub goose: Vec<Subscription>,
    /// Sampled-value streams, one per source control block.
    pub sv: Vec<Subscription>,
    /// `ExtRef`s that name a source this file does not resolve — an unbound input, a
    /// publisher that is not in the file, or a control block without a `Communication`
    /// address. Reported rather than dropped: an SCD with dangling bindings is a real
    /// commissioning finding.
    pub unresolved: Vec<Diagnostic>,
}

/// Resolve everything `ied_name` subscribes to, from a whole SCD.
///
/// Each `Inputs/ExtRef` of the subscribing IED names a signal in another IED, and this walks
/// to the control block that publishes it and to that IED's `Communication` address. One
/// [`Subscription`] comes back per source control block. That is the whole configuration
/// step for a subscriber — no discovery, and no address list to maintain beside the
/// engineering file.
///
/// Two binding styles both work, because both are in the field:
///
/// - **By control block** — the `ExtRef` carries `srcCBName` (and `srcLDInst`). This is the
///   finished binding a system configurator writes, and it is taken as authoritative.
/// - **By signal** — the `ExtRef` names only `iedName`/`ldInst`/`lnClass`/`doName`/`daName`.
///   The publisher's data sets are searched for a member that covers that attribute, and
///   the control block publishing that data set is the answer. Most `ExtRef`s in a real SCD
///   look like this; refusing them would leave the feature useless.
///
/// An `ExtRef` with no `iedName` is an input an engineer has named but not yet bound, and is
/// not a finding. Anything else that fails to resolve is returned in
/// [`Subscriptions::unresolved`] — a dangling binding is a commissioning finding, and
/// hiding it would make the tool worse than the spreadsheet it replaces.
///
/// `nominal_hz` is the system frequency, which SCL does not record but `smpRate` needs when
/// `smpMod` counts samples per period (50 or 60).
pub fn subscriptions(xml: &str, ied_name: &str, nominal_hz: u32) -> Result<Subscriptions> {
    Scl::parse(xml)?.subscriptions(ied_name, nominal_hz)
}

impl Scl<'_> {
    /// Resolve everything `ied_name` subscribes to. See [`subscriptions`].
    ///
    /// Only the publishers this IED actually names are loaded, and each of them once.
    pub fn subscriptions(&self, ied_name: &str, nominal_hz: u32) -> Result<Subscriptions> {
        let subscriber = self.model(Some(ied_name))?;
        let mut publishers: Vec<(String, Option<IedModel>)> = Vec::new();
        for (_, _, x) in subscriber.ext_refs() {
            let Some(name) = x.ied_name.as_deref() else { continue };
            if !publishers.iter().any(|(n, _)| n == name) {
                publishers.push((String::from(name), self.model(Some(name)).ok()));
            }
        }
        Ok(resolve(&subscriber, |name| publishers.iter().find(|(n, _)| n == name).and_then(|(_, m)| m.as_ref()), nominal_hz))
    }
}

/// Resolve one IED's `ExtRef`s against publisher models `lookup` hands back.
///
/// The lookup is a parameter because the caller knows how to get a model cheaply: resolving
/// one IED loads the publishers it names, while validating a whole SCD has already built
/// every model and must not build them again.
pub(crate) fn resolve<'m>(subscriber: &IedModel, lookup: impl Fn(&str) -> Option<&'m IedModel>, nominal_hz: u32) -> Subscriptions {
    let mut out = Subscriptions::default();
    for (ld, ln, x) in subscriber.ext_refs() {
        let at = alloc::format!("{}/{}/{}", subscriber.name, ld.inst, ln.name);
        // No publisher named: an input that has been given a place but not a source.
        let Some(publisher) = x.ied_name.as_deref() else { continue };
        let Some(model) = lookup(publisher) else {
            out.unresolved.push(unresolved(at, alloc::format!("ExtRef names IED `{publisher}`, which is not in this file")));
            continue;
        };
        let located = match x.src_cb_name.as_deref() {
            Some(cb) => by_control_block(model, x, cb, nominal_hz),
            None => by_signal(model, x, nominal_hz),
        };
        match located {
            Ok(found) => merge(&mut out, publisher, &found, x),
            Err(why) => out.unresolved.push(unresolved(at, why)),
        }
    }
    out
}

fn unresolved(at: String, message: String) -> Diagnostic {
    Diagnostic { code: DiagnosticCode::MissingAttribute, at, message }
}

/// A control block found for an `ExtRef`, before it becomes a [`Subscription`].
struct Located<'m> {
    ld: &'m LogicalDevice,
    ln_name: String,
    cb: &'m str,
    smv: bool,
    identifier: String,
    dst: MacAddr,
    appid: u16,
    conf_rev: u32,
    samples_per_second: Option<u32>,
    #[cfg(feature = "sv")]
    layout: Option<crate::proto::sv::SampleLayout>,
}

/// The finished binding: `srcCBName` names the control block outright.
fn by_control_block<'m>(model: &'m IedModel, x: &ExtRef, cb: &str, nominal_hz: u32) -> core::result::Result<Located<'m>, String> {
    let inst = x.source_ld_inst().ok_or_else(|| String::from("ExtRef has srcCBName but no ldInst to find it in"))?;
    let ld = model.logical_device_by_inst(inst).ok_or_else(|| alloc::format!("`{}` has no LDevice `{inst}`", model.name))?;
    let ln_name = x.source_ln_name();
    let ln = ld.logical_nodes.iter().find(|l| l.name == ln_name).ok_or_else(|| alloc::format!("`{}/{inst}` has no logical node `{ln_name}`", model.name))?;
    let smv = x.service_type != Some(ServiceType::Goose) && ln.smv_controls.iter().any(|c| c.name == cb);
    describe(model, ld, ln, cb, smv, nominal_hz)
        .ok_or_else(|| alloc::format!("control block `{}/{ln_name}.{cb}` of `{}` is missing or has no Communication address", ld.name, model.name))
}

/// The common binding: follow the signal into the publisher's data sets.
fn by_signal<'m>(model: &'m IedModel, x: &ExtRef, nominal_hz: u32) -> core::result::Result<Located<'m>, String> {
    let signal = alloc::format!(
        "{}{}{}.{}{}",
        x.prefix,
        x.ln_class.as_deref().unwrap_or(""),
        x.ln_inst,
        x.do_name.as_deref().unwrap_or(""),
        x.da_name.as_deref().map_or_else(String::new, |d| alloc::format!(".{d}"))
    );
    let mut found: Vec<Located<'m>> = Vec::new();
    for ld in &model.logical_devices {
        for ln in &ld.logical_nodes {
            for ds in &ln.data_sets {
                if !ds.members.iter().any(|m| covers(m, x)) {
                    continue;
                }
                for cb in &ln.gse_controls {
                    if cb.dat_set.as_deref() == Some(ds.name.as_str()) && x.service_type != Some(ServiceType::Smv) {
                        found.extend(describe(model, ld, ln, &cb.name, false, nominal_hz));
                    }
                }
                for cb in &ln.smv_controls {
                    if cb.dat_set.as_deref() == Some(ds.name.as_str()) && x.service_type != Some(ServiceType::Goose) {
                        found.extend(describe(model, ld, ln, &cb.name, true, nominal_hz));
                    }
                }
            }
        }
    }
    match found.len() {
        1 => found.pop().ok_or_else(String::new),
        0 => Err(alloc::format!("`{}` publishes no addressed control block carrying {signal}", model.name)),
        n => Err(alloc::format!("{signal} is published by {n} control blocks of `{}`; the ExtRef needs a srcCBName", model.name)),
    }
}

/// True when a data-set member carries the attribute an `ExtRef` asks for.
///
/// A member that names only a data object covers every attribute under it, which is how
/// most data sets are written.
fn covers(m: &Fcda, x: &ExtRef) -> bool {
    let same_ln = x.ld_inst.as_deref().is_none_or(|i| i == m.ld_inst)
        && x.prefix == m.prefix
        && x.ln_class.as_deref().is_some_and(|c| c == m.ln_class)
        && x.ln_inst == m.ln_inst;
    let same_do = x.do_name.as_deref().is_some_and(|d| d == m.do_name);
    let same_da = match (&m.da_name, &x.da_name) {
        (None, _) => true,
        (Some(member), Some(wanted)) => member == wanted,
        (Some(_), None) => false,
    };
    same_ln && same_do && same_da
}

/// Turn a control block into a [`Located`], or `None` when it has no address to subscribe to.
fn describe<'m>(
    #[cfg_attr(not(feature = "sv"), allow(unused_variables))] model: &'m IedModel,
    ld: &'m LogicalDevice,
    ln: &'m LogicalNode,
    cb: &str,
    smv: bool,
    nominal_hz: u32,
) -> Option<Located<'m>> {
    if smv {
        let c = ln.smv_controls.iter().find(|c| c.name == cb)?;
        let a = c.address.as_ref()?;
        Some(Located {
            ld,
            ln_name: ln.name.clone(),
            cb: &c.name,
            smv: true,
            identifier: c.smv_id.clone(),
            dst: a.mac,
            appid: a.appid,
            conf_rev: c.conf_rev,
            samples_per_second: c.samples_per_second(nominal_hz),
            // The publisher's own data set says what the octets of its ASDUs mean, so a
            // subscription resolved from the file carries the channel description with it.
            #[cfg(feature = "sv")]
            layout: c.dat_set.as_deref().and_then(|n| model.data_set(ln, n)).and_then(|ds| model.sv_sample_layout(&ld.name, ds)),
        })
    } else {
        let c = ln.gse_controls.iter().find(|c| c.name == cb)?;
        let a = c.address.as_ref()?;
        Some(Located {
            ld,
            ln_name: ln.name.clone(),
            cb: &c.name,
            smv: false,
            identifier: alloc::format!("{}/{}$GO${}", ld.name, ln.name, c.name),
            dst: a.mac,
            appid: a.appid,
            conf_rev: c.conf_rev,
            samples_per_second: None,
            #[cfg(feature = "sv")]
            layout: None,
        })
    }
}

fn merge(out: &mut Subscriptions, publisher: &str, found: &Located<'_>, x: &ExtRef) {
    let control_block = alloc::format!("{}/{}.{}", found.ld.name, found.ln_name, found.cb);
    let list = if found.smv { &mut out.sv } else { &mut out.goose };
    if let Some(existing) = list.iter_mut().find(|s| s.control_block == control_block && s.publisher == publisher) {
        existing.ext_refs.push(x.clone());
        return;
    }
    list.push(Subscription {
        publisher: String::from(publisher),
        control_block,
        identifier: found.identifier.clone(),
        dst: found.dst,
        appid: found.appid,
        conf_rev: found.conf_rev,
        samples_per_second: found.samples_per_second,
        #[cfg(feature = "sv")]
        layout: found.layout.clone(),
        ext_refs: alloc::vec![x.clone()],
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ObjectReference;

    const ICD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
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
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
        <GSE ldInst="LD0" cbName="gcbBroken"><Address><P type="APPID">0006</P></Address></GSE>
        <SMV ldInst="LD0" cbName="msvcb01">
          <Address>
            <P type="MAC-Address">01-0C-CD-04-00-01</P>
            <P type="APPID">4001</P>
            <P type="VLAN-ID">001</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
        </SMV>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="IED1" manufacturer="ACME" type="Relay" configVersion="1.0">
    <AccessPoint name="P1"><Server>
      <LDevice inst="LD0">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
          <DataSet name="dsTrip"><FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/><FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="q" fc="ST"/></DataSet>
          <ReportControl name="brcbEv" datSet="dsTrip" confRev="2" buffered="true" rptID="r1" bufTime="50" intgPd="1000">
            <TrgOps dchg="true" qchg="true" period="true"/>
            <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true"/>
            <RptEnabled max="3"/>
          </ReportControl>
          <ReportControl name="urcb" datSet="dsTrip" confRev="1" indexed="false"><OptFields/></ReportControl>
          <LogControl name="lcb01" datSet="dsTrip" logName="GeneralLog" bufTime="20"><TrgOps dchg="true"/></LogControl>
          <Log name="GeneralLog"/>
          <SettingControl numOfSGs="4" actSG="2" resvTms="30"/>
          <GSEControl name="gcbTrip" datSet="dsTrip" confRev="3" appID="IED1_Trip" type="GOOSE"/>
          <GSEControl name="gcbBroken" datSet="dsTrip" confRev="1" type="GOOSE"/>
          <DataSet name="PhsMeas1">
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="instMag.i" fc="MX"/>
            <FCDA ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="q" fc="MX"/>
          </DataSet>
          <SampledValueControl name="msvcb01" smvID="IED1MU01" datSet="PhsMeas1" confRev="1" smpRate="80" nofASDU="1" smpMod="SmpPerPeriod"/>
        </LN0>
        <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
        <LN lnClass="TCTR" inst="1" prefix="" lnType="TCTR_T"/>
        <LN lnClass="GGIO" inst="1" prefix="" lnType="Missing_T"/>
      </LDevice>
      <LDevice inst="LD1" ldName="CustomLD"><LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/></LDevice>
    </Server></AccessPoint>
  </IED>
  <IED name="IED2" manufacturer="ACME" type="Merge">
    <AccessPoint name="P1"><Server>
      <LDevice inst="LD0">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
          <Inputs>
            <ExtRef iedName="IED1" ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general"
                    serviceType="GOOSE" srcLDInst="LD0" srcCBName="gcbTrip" intAddr="BI1"/>
            <ExtRef iedName="IED1" ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="q"
                    serviceType="GOOSE" srcLDInst="LD0" srcCBName="gcbTrip"/>
            <ExtRef iedName="IED1" ldInst="LD0" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="instMag.i"
                    serviceType="SMV" srcLDInst="LD0" srcCBName="msvcb01"/>
            <ExtRef iedName="IED1" ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general"
                    serviceType="GOOSE" srcLDInst="LD0" srcCBName="gcbBroken"/>
            <ExtRef iedName="Nobody" ldInst="LD0" doName="Tr" serviceType="GOOSE" srcLDInst="LD0" srcCBName="gcbX"/>
            <ExtRef intAddr="unbound"/>
          </Inputs>
        </LN0>
      </LDevice>
    </Server></AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/><DO name="Beh" type="Nope_T"/></LNodeType>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Tr" type="ACT_T"/></LNodeType>
    <LNodeType id="TCTR_T" lnClass="TCTR"><DO name="AmpSv" type="SAV_T"/></LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="Enum" type="Mod_E"/><DA name="q" fc="ST" bType="Quality"/><DA name="ctlModel" fc="CF" bType="Enum" type="Ctl_E"><Val>status-only</Val></DA></DOType>
    <DOType id="ACT_T" cdc="ACT"><DA name="general" fc="ST" bType="BOOLEAN"/><DA name="q" fc="ST" bType="Quality"/><DA name="t" fc="ST" bType="Timestamp"/><DA name="origin" fc="ST" bType="Struct" type="Orig_T"/></DOType>
    <DOType id="SAV_T" cdc="SAV"><DA name="instMag" fc="MX" bType="Struct" type="AnalogueValue_T"/><DA name="q" fc="MX" bType="Quality"/></DOType>
    <DAType id="Orig_T"><BDA name="orCat" bType="Enum" type="OrCat_E"/><BDA name="orIdent" bType="Octet64"/></DAType>
    <DAType id="AnalogueValue_T"><BDA name="i" bType="INT32"/></DAType>
    <EnumType id="Mod_E"><EnumVal ord="1">on</EnumVal></EnumType>
    <EnumType id="Ctl_E"><EnumVal ord="0">status-only</EnumVal></EnumType>
    <EnumType id="OrCat_E"><EnumVal ord="0">not-supported</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;

    #[test]
    fn loads_model_and_addresses() {
        assert_eq!(ied_names(ICD).unwrap(), ["IED1", "IED2"]);
        assert_eq!(scl_version(ICD).unwrap(), "2007B4");
        let m = IedModel::from_scl(ICD, Some("IED1")).unwrap();
        assert_eq!(m.logical_devices.len(), 2);
        assert_eq!(m.logical_devices[1].name, "CustomLD");
        let ld = m.logical_device("IED1LD0").unwrap();
        assert_eq!(ld.logical_nodes.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), ["LLN0", "PTRC1", "TCTR1", "GGIO1"]);

        let (_, _, gcb) = m.gse_control("IED1LD0/LLN0.gcbTrip").unwrap();
        assert_eq!(gcb.conf_rev, 3);
        let a = gcb.address.as_ref().unwrap();
        assert_eq!((a.appid, a.vlan_id, a.vlan_priority, a.min_time_ms, a.max_time_ms), (5, 1, 4, Some(4), Some(1000)));
        assert!(a.mac.is_goose_multicast());

        // Turning the control block into a publisher configuration needs the GOOSE codec;
        // reading it out of the file does not.
        #[cfg(feature = "goose")]
        {
            let cfg = m.goose_publisher_config("IED1LD0/LLN0$GO$gcbTrip", MacAddr::default()).unwrap();
            assert_eq!(cfg.gocb_ref, "IED1LD0/LLN0$GO$gcbTrip");
            assert_eq!(cfg.dat_set, "IED1LD0/LLN0$dsTrip");
            assert_eq!(cfg.go_id.as_deref(), Some("IED1_Trip"));
            assert_eq!(cfg.retransmission.min_time_ms, 4);
        }

        let (_, _, svcb) = m.smv_control("IED1LD0/LLN0.msvcb01").unwrap();
        assert_eq!(svcb.address.as_ref().unwrap().appid, 0x4001);
        assert_eq!(svcb.smv_id, "IED1MU01");

        let ln0 = &ld.logical_nodes[0];
        let brcb = &ln0.report_controls[0];
        assert_eq!(brcb.max_instances, 3);
        // An indexed block with three instances is three control blocks on the wire, so that
        // three clients can each enable one; an unindexed one is a single block under its own
        // name. `indexed` defaults to **true** in the schema, which is the trap.
        assert_eq!(brcb.instance_names(), ["brcbEv01", "brcbEv02", "brcbEv03"].map(String::from).to_vec());
        assert_eq!(brcb.fc(), Fc::BR);
        assert_eq!(ln0.report_controls[1].instance_names(), ["urcb"].map(String::from).to_vec());
        assert_eq!(ln0.report_controls[1].fc(), Fc::RP);
        // TrgOps and OptFields carry the *engineered* defaults, and the two the schema
        // defaults to `true` are the ones an implementation forgets: `gi` and `bufOvfl`.
        assert!(brcb.trg_ops.data_change() && brcb.trg_ops.quality_change() && brcb.trg_ops.integrity());
        assert!(brcb.trg_ops.general_interrogation(), "gi defaults to true");
        assert!(!brcb.trg_ops.data_update());
        assert!(brcb.opt_flds.sequence_number() && brcb.opt_flds.report_time_stamp() && brcb.opt_flds.data_set_name());
        assert!(brcb.opt_flds.buffer_overflow(), "bufOvfl defaults to true");
        assert!(!brcb.opt_flds.entry_id() && !brcb.opt_flds.data_reference());
        // A block with an empty `OptFields` still gets `bufOvfl`, and one with no `TrgOps`
        // element at all still gets `gi`.
        assert!(ln0.report_controls[1].opt_flds.buffer_overflow() && ln0.report_controls[1].trg_ops.general_interrogation());

        let lcb = &ln0.log_controls[0];
        assert_eq!((lcb.name.as_str(), lcb.log_name.as_str(), lcb.buf_time_ms), ("lcb01", "GeneralLog", 20));
        assert!(lcb.log_ena && lcb.reason_code && lcb.trg_ops.data_change());
        assert_eq!(ln0.logs.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), ["GeneralLog"]);
        let sg = ln0.setting_control.expect("SettingControl");
        assert_eq!((sg.num_of_sgs, sg.act_sg, sg.resv_tms), (4, 2, Some(30)));
        assert!(ln0.report_controls[0].buffered);
        assert_eq!(ln0.data_sets[0].members[1].mms_reference("IED1LD0"), "IED1LD0/PTRC1$ST$Tr$q");

        let a = m.attribute(&ObjectReference::parse("IED1LD0/PTRC1.Tr.origin.orIdent").unwrap()).unwrap();
        assert_eq!((a.fc, &a.btype), (Fc::ST, &BType::Octet64));
        assert!(m.attribute(&ObjectReference::parse("IED1LD0/PTRC1$MX$Tr$general").unwrap()).is_none());
        let ctl = m.attribute(&ObjectReference::parse("IED1LD0/LLN0.Mod.ctlModel").unwrap()).unwrap();
        assert_eq!(ctl.value.as_deref(), Some("status-only"));
        assert!(IedModel::from_scl(ICD, Some("nope")).is_err());
    }

    // The sampled-value half of the model only exists with the `sv` codec compiled in.
    #[cfg(feature = "sv")]
    #[test]
    fn a_sampled_value_publisher_is_configured_from_the_control_block() {
        let m = IedModel::from_scl(ICD, Some("IED1")).unwrap();
        let cfg = m.sv_publisher_config("IED1LD0/LLN0.msvcb01", MacAddr::default(), 50).unwrap();
        assert_eq!(cfg.sv_id, "IED1MU01");
        // 80 samples per nominal cycle at 50 Hz, and the data set is one INT32 plus one
        // 4-octet quality word: both are read off the file, not assumed.
        assert_eq!(cfg.profile.samples_per_second, 4000);
        assert_eq!(cfg.profile.sample_len, 8);
        assert_eq!(cfg.profile.asdus_per_frame, 1);
        assert_eq!((cfg.profile.smp_mod, cfg.profile.smp_rate), (None, None), "9-2LE sends neither");
        assert_eq!(cfg.header.appid, 0x4001);
        assert!(crate::proto::sv::Publisher::new(cfg).is_ok(), "the derived profile must encode");

        let stream = m.sv_stream_config("IED1LD0/LLN0.msvcb01", 50).unwrap();
        assert_eq!((stream.samples_per_second, stream.expected_conf_rev), (4000, Some(1)));
        assert_eq!(stream.key.sv_id, "IED1MU01");
        // And the data set says what the ASDU's octets mean, so a subscriber configured
        // from the file decodes named channels instead of a block of bytes.
        let layout = stream.layout.expect("the data set has a fixed-width layout");
        assert_eq!(layout.len(), 8);
        assert_eq!(layout.channels().len(), 2);
        assert_eq!(layout.channels()[0].name, "LD0/TCTR1.AmpSv.instMag.i");
        assert_eq!(layout.channels()[0].kind, crate::proto::sv::ChannelType::Int(4));
        assert_eq!(layout.channels()[1].kind, crate::proto::sv::ChannelType::Quality);
    }

    // The OSI addressing is only interesting where the OSI stack is compiled in.
    #[cfg(feature = "mms")]
    #[test]
    fn the_access_point_carries_the_osi_addressing_an_association_needs() {
        const ICD_AP: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="t"/>
  <Communication><SubNetwork name="station"><ConnectedAP iedName="IED1" apName="P1">
    <Address>
      <P type="IP">192.168.210.111</P>
      <P type="OSI-AP-Title">1,3,9999,23</P>
      <P type="OSI-AE-Qualifier">23</P>
      <P type="OSI-PSEL">00000001</P>
      <P type="OSI-SSEL">0001</P>
      <P type="OSI-TSEL">1</P>
    </Address>
  </ConnectedAP></SubNetwork></Communication>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates><LNodeType id="T" lnClass="LLN0"/></DataTypeTemplates>
</SCL>"#;
        let m = IedModel::from_scl(ICD_AP, None).unwrap();
        assert_eq!(m.access_points.len(), 1);
        let a = m.osi_address(None).expect("one access point, so no name is needed");
        assert_eq!(a.ip.as_deref(), Some("192.168.210.111"));
        assert_eq!(a.p_sel.as_deref(), Some(&[0, 0, 0, 1][..]));
        assert_eq!(a.s_sel.as_deref(), Some(&[0, 1][..]));
        // An odd number of hex digits is padded rather than refused.
        assert_eq!(a.t_sel.as_deref(), Some(&[1][..]));
        assert_eq!(a.ae_qualifier, Some(23));
        assert_eq!(a.ap_title.as_deref(), Some(&[1, 3, 9999, 23][..]));
        assert_eq!(m.osi_address(Some("P1")), m.osi_address(None));
        assert!(m.osi_address(Some("nosuch")).is_none());
        // The AP-title goes into an AARQ as an encoded identifier.
        let encoded = crate::proto::osi::oid::encode(a.ap_title.as_deref().unwrap()).unwrap();
        assert_eq!(crate::proto::osi::Oid(&encoded).to_string(), "1.3.9999.23");
    }

    #[test]
    fn subscriptions_resolve_to_the_publishers_addresses() {
        let s = subscriptions(ICD, "IED2", 50).unwrap();
        assert_eq!(s.goose.len(), 1, "two ExtRefs on one control block are one subscription");
        let g = &s.goose[0];
        assert_eq!((g.publisher.as_str(), g.control_block.as_str()), ("IED1", "IED1LD0/LLN0.gcbTrip"));
        assert_eq!(g.identifier, "IED1LD0/LLN0$GO$gcbTrip");
        assert_eq!((g.appid, g.conf_rev, g.ext_refs.len()), (5, 3, 2));
        #[cfg(feature = "goose")]
        {
            assert_eq!(g.goose_config().key.gocb_ref, "IED1LD0/LLN0$GO$gcbTrip");
            assert_eq!(g.goose_config().expected_conf_rev, Some(3));
        }
        assert_eq!(g.ext_refs[0].int_addr.as_deref(), Some("BI1"));

        assert_eq!(s.sv.len(), 1);
        assert_eq!(s.sv[0].identifier, "IED1MU01");
        assert_eq!(s.sv[0].samples_per_second, Some(4000));
        #[cfg(feature = "sv")]
        {
            assert_eq!(s.sv[0].sv_config().key.appid, 0x4001);
            // The subscription carries the publisher's sample-block description with it: one
            // call to `subscriptions` is the whole configuration of a subscriber, decoding
            // included.
            assert_eq!(s.sv[0].sv_config().layout.map(|l| l.channels().len()), Some(2));
        }

        // The control block with no Communication address and the publisher that is not in
        // the file are reported, not silently dropped; the unbound ExtRef is not a finding.
        let messages: Vec<&str> = s.unresolved.iter().map(|d| d.message.as_str()).collect();
        assert_eq!(messages.len(), 2, "{messages:?}");
        assert!(messages[0].contains("gcbBroken"), "{messages:?}");
        assert!(messages[1].contains("Nobody"), "{messages:?}");
    }

    #[test]
    fn an_ext_ref_that_names_only_the_signal_still_resolves() {
        // What most `ExtRef`s in a real SCD look like: the publisher and the attribute, no
        // `srcCBName`. The data set carrying it, and the control block publishing that data
        // set, are the answer.
        let file = ICD.replace(
            r#"<ExtRef iedName="IED1" ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general"
                    serviceType="GOOSE" srcLDInst="LD0" srcCBName="gcbTrip" intAddr="BI1"/>"#,
            r#"<ExtRef iedName="IED1" ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" intAddr="BI1"/>"#,
        );
        let s = subscriptions(&file, "IED2", 50).unwrap();
        assert_eq!(s.goose.len(), 1, "{s:#?}");
        assert_eq!(s.goose[0].identifier, "IED1LD0/LLN0$GO$gcbTrip");
        assert_eq!(s.goose[0].conf_rev, 3);
        assert_eq!(s.goose[0].ext_refs.len(), 2, "the explicit and the signal-bound one land on the same control block");
    }

    #[test]
    fn a_member_naming_only_a_data_object_covers_its_attributes() {
        // A data set written as `doName="Tr"` with no `daName` publishes the whole data
        // object, so an input asking for `Tr.general` is carried by it.
        let file = ICD
            .replace(r#"<FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/><FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="q" fc="ST"/>"#,
                     r#"<FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" fc="ST"/>"#)
            .replace(r#"serviceType="GOOSE" srcLDInst="LD0" srcCBName="gcbTrip" intAddr="BI1"/>"#, r#"intAddr="BI1"/>"#);
        let s = subscriptions(&file, "IED2", 50).unwrap();
        assert_eq!(s.goose.len(), 1, "{s:#?}");
        assert_eq!(s.goose[0].identifier, "IED1LD0/LLN0$GO$gcbTrip");
    }

    #[test]
    fn an_unbound_input_is_not_a_finding_but_a_dangling_one_is() {
        let s = subscriptions(ICD, "IED2", 50).unwrap();
        let messages: Vec<&str> = s.unresolved.iter().map(|d| d.message.as_str()).collect();
        // `<ExtRef intAddr="unbound"/>` names no publisher: an engineer has made a place for
        // the signal and not yet said where it comes from. That is a normal state for an SCD
        // under construction, and reporting it would bury the two findings that matter.
        assert_eq!(messages.len(), 2, "{messages:?}");
        assert!(messages.iter().any(|m| m.contains("gcbBroken")), "{messages:?}");
        assert!(messages.iter().any(|m| m.contains("Nobody")), "{messages:?}");
    }

    #[test]
    fn scl_durations_carry_their_multiplier() {
        // `<MinTime unit="s" multiplier="m">4</MinTime>` is 4 ms; the same element without
        // the multiplier is 4 whole seconds, and reading it as 4 ms would turn a heartbeat
        // into a flood.
        let doc = Document::parse(r#"<r><a multiplier="m">4</a><b>2</b><c multiplier="u">500</c><d multiplier="m">x</d></r>"#).unwrap();
        let r = doc.root_element();
        assert_eq!(child(r, "a").and_then(duration_ms), Some(4));
        assert_eq!(child(r, "b").and_then(duration_ms), Some(2000));
        assert_eq!(child(r, "c").and_then(duration_ms), Some(0));
        assert_eq!(child(r, "d").and_then(duration_ms), None);
    }

    #[test]
    fn lenient_by_default_strict_on_request() {
        let m = IedModel::from_scl(ICD, Some("IED1")).unwrap();
        let codes: Vec<DiagnosticCode> = m.diagnostics.iter().map(|d| d.code).collect();
        assert_eq!(codes, [DiagnosticCode::BadAddress, DiagnosticCode::MissingDOType, DiagnosticCode::MissingLNodeType, DiagnosticCode::MissingDOType]);
        assert_eq!(m.diagnostics[1].at, "IED1/LD0/LLN0.Beh");
        assert_eq!(m.diagnostics[2].at, "IED1/LD0/GGIO1");
        // The broken control block exists without an address; the broken LN without DOs.
        assert!(m.gse_control("IED1LD0/LLN0.gcbBroken").unwrap().2.address.is_none());
        assert!(m.logical_device("IED1LD0").unwrap().logical_nodes[3].data_objects.is_empty());

        let err = IedModel::from_scl_with(ICD, Some("IED1"), LoadOptions { strict: true }).unwrap_err();
        assert!(err.to_string().contains("BadAddress at Communication/GSE LD0.gcbBroken"), "{err}");
    }

    // `control_model` answers with the MMS control enumeration, which needs that codec.
    #[cfg(feature = "mms")]
    #[test]
    fn instance_values_override_the_type_template() {
        // `ctlModel` lives in the SCD as a `DAI` under the object's `DOI`. A model that reads
        // only `DataTypeTemplates` has the *type's* value, which for a controllable object is
        // very often not the device's — and a control sequence built on the wrong one silently
        // does nothing.
        let xml = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
  <IED name="IED1"><AccessPoint name="S1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/>
    <LN lnClass="CSWI" inst="1" lnType="CSWI_T">
      <DOI name="Pos">
        <DAI name="ctlModel"><Val>sbo-with-enhanced-security</Val></DAI>
        <SDI name="Oper"><DAI name="ctlNum"><Val>7</Val></DAI></SDI>
      </DOI>
    </LN>
    <LN lnClass="CSWI" inst="2" lnType="CSWI_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="CSWI_T" lnClass="CSWI"><DO name="Pos" type="DPC_T"/></LNodeType>
    <DOType id="DPC_T" cdc="DPC">
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModel_E"><Val>direct-with-normal-security</Val></DA>
      <DA name="Oper" fc="CO" bType="Struct" type="Oper_T"/>
    </DOType>
    <DAType id="Oper_T"><BDA name="ctlNum" bType="INT8U"/></DAType>
    <EnumType id="CtlModel_E"><EnumVal ord="1">direct-with-normal-security</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;
        let model = IedModel::from_scl(xml, Some("IED1")).expect("load");
        // The instance wins over the template …
        assert_eq!(model.control_model("IED1LD0/CSWI1.Pos"), Some(crate::proto::mms::control::ControlModel::SboEnhanced));
        // … and an instance that says nothing keeps the template's value.
        assert_eq!(model.control_model("IED1LD0/CSWI2.Pos"), Some(crate::proto::mms::control::ControlModel::DirectNormal));
        // An `SDI` reaches into a structured attribute.
        let oper = model.attribute(&ObjectReference::parse("IED1LD0/CSWI1.Pos.Oper").expect("reference")).expect("Oper");
        assert_eq!(oper.children.iter().find(|a| a.name == "ctlNum").and_then(|a| a.value.as_deref()), Some("7"));
        // And an object with no `ctlModel` at all is not one that can be controlled.
        assert_eq!(model.control_model("IED1LD0/LLN0.Mod"), None);
    }
}
