//! The engineering edits: each one transaction, with the references that move with it.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{Document, Element, NewElement, Tx};
use crate::common::{Error, Result};
use crate::model::{Fcda, GseAddress, SmvAddress};

/// A logical node within a logical device: `prefix`, `lnClass`, `inst`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct LnRef {
    /// `prefix` (empty when absent).
    pub prefix: String,
    /// `lnClass`.
    pub ln_class: String,
    /// `inst` (empty for `LLN0`).
    pub inst: String,
}

impl LnRef {
    /// `LLN0`, the `LN0` element.
    pub fn lln0() -> LnRef {
        LnRef { prefix: String::new(), ln_class: String::from("LLN0"), inst: String::new() }
    }

    /// Any other logical node.
    pub fn new(prefix: impl Into<String>, ln_class: impl Into<String>, inst: impl Into<String>) -> LnRef {
        LnRef { prefix: prefix.into(), ln_class: ln_class.into(), inst: inst.into() }
    }

    /// `prefix + lnClass + inst`, as an object reference spells it.
    pub fn name(&self) -> String {
        format!("{}{}{}", self.prefix, self.ln_class, self.inst)
    }

    fn is_lln0(&self) -> bool {
        self.ln_class == "LLN0"
    }
}

/// The four kinds of control block an LN carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ControlKind {
    /// `GSEControl` (in `LLN0` only).
    Gse,
    /// `SampledValueControl` (in `LLN0` only).
    Smv,
    /// `ReportControl`.
    Report,
    /// `LogControl`.
    Log,
}

impl ControlKind {
    /// The SCL element name.
    pub fn element(self) -> &'static str {
        match self {
            ControlKind::Gse => "GSEControl",
            ControlKind::Smv => "SampledValueControl",
            ControlKind::Report => "ReportControl",
            ControlKind::Log => "LogControl",
        }
    }

    /// The functional constraints an object reference to such a block uses.
    fn fcs(self) -> &'static [&'static str] {
        match self {
            ControlKind::Gse => &["GO"],
            ControlKind::Smv => &["MS", "US"],
            ControlKind::Report => &["RP", "BR"],
            ControlKind::Log => &["LG"],
        }
    }
}

const CONTROL_ELEMENTS: [&str; 4] = ["GSEControl", "SampledValueControl", "ReportControl", "LogControl"];

/// A control block, as an `ExtRef` names its source's: `srcLDInst`, `srcPrefix`/`srcLNClass`/
/// `srcLNInst`, `srcCBName`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CbRef {
    /// The logical device's `inst`.
    pub ld: String,
    /// The logical node (normally `LLN0`).
    pub ln: LnRef,
    /// The control block's name.
    pub name: String,
}

/// What an `ExtRef` is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtRefSource {
    /// The publishing IED.
    pub ied: String,
    /// `ldInst`.
    pub ld: String,
    /// `prefix`.
    pub prefix: String,
    /// `lnClass`.
    pub ln_class: String,
    /// `lnInst`.
    pub ln_inst: String,
    /// `doName`.
    pub do_name: String,
    /// `daName`, for an attribute rather than a data object.
    pub da_name: Option<String>,
    /// `serviceType` (`GOOSE`, `SMV`, `Report`, `Poll`).
    pub service_type: Option<String>,
    /// The control block the value arrives through.
    pub src_cb: Option<CbRef>,
}

/// A `Header/History/Hitem`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hitem {
    /// `version` (required).
    pub version: String,
    /// `revision` (required).
    pub revision: String,
    /// `when` (required), e.g. an RFC 3339 time.
    pub when: String,
    /// `who`.
    pub who: Option<String>,
    /// `what`.
    pub what: Option<String>,
    /// `why`.
    pub why: Option<String>,
}

impl Hitem {
    fn element(&self) -> NewElement {
        let mut e = NewElement::new("Hitem").attr("version", &self.version).attr("revision", &self.revision).attr("when", &self.when);
        for (k, v) in [("who", &self.who), ("what", &self.what), ("why", &self.why)] {
            if let Some(v) = v {
                e = e.attr(k, v);
            }
        }
        e
    }
}

const EXT_REF_SOURCE: [&str; 13] =
    ["iedName", "ldInst", "prefix", "lnClass", "lnInst", "doName", "daName", "serviceType", "srcLDInst", "srcPrefix", "srcLNClass", "srcLNInst", "srcCBName"];
const EXT_REF_CB: [&str; 5] = ["srcLDInst", "srcPrefix", "srcLNClass", "srcLNInst", "srcCBName"];

fn exists(what: &str, name: &str) -> Error {
    Error::Scl(format!("{what} {name} already exists"))
}

/// `tIEDName`: a letter, then up to 63 letters, digits or underscores; not `None` ✅
/// (`SCL_BaseSimpleTypes.xsd`).
fn check_ied_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let ok =
        chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.all(|c| c.is_ascii_alphanumeric() || c == '_') && name.len() <= 64 && name != "None";
    if ok { Ok(()) } else { Err(Error::Scl(format!("{name:?} is not a valid IED name"))) }
}

fn find_ied<'a>(tx: &Tx<'a>, name: &str) -> Result<Element<'a>> {
    tx.root().children_named("IED").find(|i| i.attribute("name") == Some(name)).ok_or(Error::NotFound("IED"))
}

fn lds(ied: Element<'_>) -> impl Iterator<Item = Element<'_>> {
    ied.children_named("AccessPoint").flat_map(|ap| ap.children_named("Server")).flat_map(|s| s.children_named("LDevice"))
}

fn find_ld<'a>(ied: Element<'a>, inst: &str) -> Result<Element<'a>> {
    lds(ied).find(|ld| ld.attribute("inst") == Some(inst)).ok_or(Error::NotFound("LDevice"))
}

fn ln_matches(el: Element<'_>, ln: &LnRef) -> bool {
    if ln.is_lln0() {
        return el.name() == "LN0";
    }
    el.name() == "LN" && el.attr_or_empty("prefix") == ln.prefix && el.attribute("lnClass") == Some(&ln.ln_class) && el.attr_or_empty("inst") == ln.inst
}

fn find_ln<'a>(ld: Element<'a>, ln: &LnRef) -> Result<Element<'a>> {
    ld.children().find(|e| ln_matches(*e, ln)).ok_or(Error::NotFound("LN"))
}

fn find_ln_in<'a>(tx: &Tx<'a>, ied: &str, ld: &str, ln: &LnRef) -> Result<(Element<'a>, Element<'a>, Element<'a>)> {
    let i = find_ied(tx, ied)?;
    let d = find_ld(i, ld)?;
    let n = find_ln(d, ln)?;
    Ok((i, d, n))
}

/// The logical device's name in object references: `ldName`, or IED name + `inst`.
fn ld_ref(ied: &str, ld: Element<'_>) -> String {
    ld.attribute("ldName").map_or_else(|| format!("{ied}{}", ld.attr_or_empty("inst")), String::from)
}

/// Every `Val` whose text is exactly `from`, set to `to`.
fn retarget_values(tx: &mut Tx<'_>, from: &str, to: &str) {
    let root = tx.root();
    for v in root.descendants().filter(|e| e.name() == "Val" && e.text() == Some(from)) {
        tx.set_text(v, to);
    }
}

fn unbind<'a>(tx: &mut Tx<'a>, ext_ref: Element<'a>, attrs: &[&str]) {
    for a in attrs {
        tx.remove_attribute(ext_ref, a);
    }
}

/// An `LNode` whose host is gone keeps its function and loses its allocation.
fn deallocate<'a>(tx: &mut Tx<'a>, lnode: Element<'a>) {
    tx.set_attribute(lnode, "iedName", "None");
    tx.remove_attribute(lnode, "ldInst");
}

fn fcda_element(f: &Fcda) -> NewElement {
    let mut e = NewElement::new("FCDA")
        .attr("ldInst", &f.ld_inst)
        .attr_if("prefix", &f.prefix)
        .attr("lnClass", &f.ln_class)
        .attr_if("lnInst", &f.ln_inst)
        .attr("doName", &f.do_name);
    if let Some(da) = &f.da_name {
        e = e.attr("daName", da);
    }
    e = e.attr("fc", f.fc.as_str());
    if let Some(ix) = f.ix {
        e = e.attr("ix", ix.to_string());
    }
    e
}

fn fcda_matches(el: Element<'_>, f: &Fcda) -> bool {
    el.attr_or_empty("ldInst") == f.ld_inst
        && el.attr_or_empty("prefix") == f.prefix
        && el.attr_or_empty("lnClass") == f.ln_class
        && el.attr_or_empty("lnInst") == f.ln_inst
        && el.attr_or_empty("doName") == f.do_name
        && el.attribute("daName") == f.da_name.as_deref()
        && el.attribute("fc") == Some(f.fc.as_str())
        && el.attribute("ix").and_then(|v| v.parse().ok()) == f.ix
}

fn find_data_set<'a>(ln: Element<'a>, name: &str) -> Result<Element<'a>> {
    ln.children_named("DataSet").find(|d| d.attribute("name") == Some(name)).ok_or(Error::NotFound("DataSet"))
}

fn find_control<'a>(ln: Element<'a>, kind: ControlKind, name: &str) -> Result<Element<'a>> {
    ln.children_named(kind.element()).find(|c| c.attribute("name") == Some(name)).ok_or(Error::NotFound("control block"))
}

/// An `ExtRef` whose control-block source is `ied`/`ld`/`ln`/`cb`.
fn names_control(e: Element<'_>, ied: &str, ld: &str, ln: &LnRef, cb: &str) -> bool {
    e.name() == "ExtRef"
        && e.attribute("iedName") == Some(ied)
        && e.attribute("srcCBName") == Some(cb)
        && e.attribute("srcLDInst").or_else(|| e.attribute("ldInst")) == Some(ld)
        && e.attribute("srcLNClass").unwrap_or("LLN0") == ln.ln_class
        && e.attr_or_empty("srcPrefix") == ln.prefix
        && e.attr_or_empty("srcLNInst") == ln.inst
}

/// The `GSE`/`SMV` elements that carry `ied`/`ld`/`cb`'s address.
fn comm_entries<'a>(root: Element<'a>, ied: &str, element: &str, ld: &str, cb: &str) -> Vec<Element<'a>> {
    root.children_named("Communication")
        .flat_map(|c| c.children_named("SubNetwork"))
        .flat_map(|s| s.children_named("ConnectedAP"))
        .filter(|a| a.attribute("iedName") == Some(ied))
        .flat_map(Element::children)
        .filter(|g| g.name() == element && g.attribute("ldInst") == Some(ld) && g.attribute("cbName") == Some(cb))
        .collect()
}

fn connected_ap<'a>(root: Element<'a>, ied: &str, ap: &str) -> Result<Element<'a>> {
    root.children_named("Communication")
        .flat_map(|c| c.children_named("SubNetwork"))
        .flat_map(|s| s.children_named("ConnectedAP"))
        .find(|a| a.attribute("iedName") == Some(ied) && a.attribute("apName") == Some(ap))
        .ok_or(Error::NotFound("ConnectedAP"))
}

/// Set `Address/P` values under `parent`, creating `Address` or `P` as needed.
fn set_address<'a>(tx: &mut Tx<'a>, parent: Element<'a>, ps: &[(&str, String)]) {
    if let Some(address) = parent.child("Address") {
        for (t, v) in ps {
            match address.children_named("P").find(|p| p.attribute("type") == Some(*t)) {
                Some(p) => tx.set_text(p, v),
                None => tx.insert(address, &NewElement::new("P").attr("type", *t).text(v.as_str())),
            }
        }
    } else {
        let mut a = NewElement::new("Address");
        for (t, v) in ps {
            a = a.child(NewElement::new("P").attr("type", *t).text(v.as_str()));
        }
        tx.insert(parent, &a);
    }
}

fn duration(name: &str, ms: u32) -> NewElement {
    NewElement::new(name).attr("unit", "s").attr("multiplier", "m").text(ms.to_string())
}

fn mac_ps(mac: String, appid: u16, vlan_id: u16, vlan_priority: u8) -> Vec<(&'static str, String)> {
    alloc::vec![("MAC-Address", mac), ("APPID", format!("{appid:04X}")), ("VLAN-ID", format!("{vlan_id:03X}")), ("VLAN-PRIORITY", vlan_priority.to_string()),]
}

impl Document {
    /// Append a `Hitem` to `Header/History`, creating `History` if there is none.
    pub fn add_history(&mut self, item: &Hitem) -> Result<usize> {
        self.edit("add history item", |tx| {
            let header = tx.root().child("Header").ok_or(Error::NotFound("Header"))?;
            match header.child("History") {
                Some(history) => tx.insert(history, &item.element()),
                None => tx.insert(header, &NewElement::new("History").child(item.element())),
            }
            Ok(())
        })
    }

    /// Rename an IED and every reference to it: `iedName` attributes (`ConnectedAP`, `ExtRef`,
    /// `ClientLN`, `LNode`, `KDC`, …), `IEDName` elements, and `Val` object references into its
    /// logical devices that have no `ldName`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if there is no IED `old`; [`Error::Scl`] if `new` is not a valid IED
    /// name or is taken.
    pub fn rename_ied(&mut self, old: &str, new: &str) -> Result<usize> {
        check_ied_name(new)?;
        if old == new {
            return Ok(0);
        }
        self.edit(&format!("rename IED {old} → {new}"), |tx| {
            let root = tx.root();
            let ied = find_ied(tx, old)?;
            if find_ied(tx, new).is_ok() {
                return Err(exists("IED", new));
            }
            tx.set_attribute(ied, "name", new);
            let prefixes: Vec<(String, String)> = lds(ied)
                .filter(|ld| ld.attribute("ldName").is_none())
                .map(|ld| {
                    let inst = ld.attr_or_empty("inst");
                    (format!("{old}{inst}/"), format!("{new}{inst}/"))
                })
                .collect();
            for el in root.descendants() {
                if el.attribute("iedName") == Some(old) {
                    tx.set_attribute(el, "iedName", new);
                }
                match el.name() {
                    "IEDName" if el.text() == Some(old) => tx.set_text(el, new),
                    "Val" => {
                        if let Some(t) = el.text()
                            && let Some((from, to)) = prefixes.iter().find(|(from, _)| t.starts_with(from.as_str()))
                        {
                            tx.set_text(el, &format!("{to}{}", t.get(from.len()..).unwrap_or("")));
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }

    /// Remove an IED with its `ConnectedAP`s (and any `SubNetwork` or `Communication` left
    /// empty), `IEDName`, `ClientLN` and `KDC` entries naming it; `ExtRef`s bound to it are
    /// unbound and `LNode`s allocated to it become unallocated (`iedName="None"`).
    pub fn remove_ied(&mut self, name: &str) -> Result<usize> {
        self.edit(&format!("remove IED {name}"), |tx| {
            let root = tx.root();
            let ied = find_ied(tx, name)?;
            tx.remove(ied);
            if let Some(comm) = root.child("Communication") {
                let mut kept = 0;
                let mut subnets = 0;
                for sn in comm.children_named("SubNetwork") {
                    subnets += 1;
                    let aps: Vec<_> = sn.children_named("ConnectedAP").collect();
                    let gone: Vec<_> = aps.iter().filter(|a| a.attribute("iedName") == Some(name)).collect();
                    if !aps.is_empty() && gone.len() == aps.len() {
                        tx.remove(sn);
                    } else {
                        kept += 1;
                        for a in gone {
                            tx.remove(*a);
                        }
                    }
                }
                if subnets > 0 && kept == 0 {
                    tx.remove(comm);
                }
            }
            for el in root.descendants() {
                let named = el.attribute("iedName") == Some(name);
                match el.name() {
                    "IEDName" if el.text() == Some(name) => tx.remove(el),
                    "ClientLN" | "KDC" if named => tx.remove(el),
                    "LNode" if named => deallocate(tx, el),
                    "ExtRef" if named => unbind(tx, el, &EXT_REF_SOURCE),
                    _ => {}
                }
            }
            Ok(())
        })
    }

    /// Add a logical node to a logical device.
    pub fn add_ln(&mut self, ied: &str, ld: &str, ln: &LnRef, ln_type: &str) -> Result<usize> {
        if ln.is_lln0() {
            return Err(Error::Scl(String::from("LLN0 exists in every logical device")));
        }
        self.edit(&format!("add LN {}", ln.name()), |tx| {
            let d = find_ld(find_ied(tx, ied)?, ld)?;
            if find_ln(d, ln).is_ok() {
                return Err(exists("LN", &ln.name()));
            }
            let e = NewElement::new("LN").attr_if("prefix", &ln.prefix).attr("lnClass", &ln.ln_class).attr("inst", &ln.inst).attr("lnType", ln_type);
            tx.insert(d, &e);
            Ok(())
        })
    }

    /// Remove a logical node. Data-set members that name it go (and a data set left empty goes
    /// too, with the `datSet` of any control block that used it); `ExtRef`s bound to it are
    /// unbound; `LNode`s allocated to it become unallocated.
    pub fn remove_ln(&mut self, ied: &str, ld: &str, ln: &LnRef) -> Result<usize> {
        if ln.is_lln0() {
            return Err(Error::Scl(String::from("LLN0 cannot be removed")));
        }
        self.edit(&format!("remove LN {}", ln.name()), |tx| {
            let root = tx.root();
            let (i, _, n) = find_ln_in(tx, ied, ld, ln)?;
            tx.remove(n);
            let names_ln = |e: Element<'_>, ld_attr: &str| {
                e.attr_or_empty(ld_attr) == ld
                    && e.attr_or_empty("prefix") == ln.prefix
                    && e.attribute("lnClass") == Some(&ln.ln_class)
                    && e.attr_or_empty("lnInst") == ln.inst
            };
            for ds in i.descendants().filter(|e| e.name() == "DataSet") {
                let members: Vec<_> = ds.children().filter(|c| c.name() == "FCDA" || c.name() == "FCCB").collect();
                let gone: Vec<_> = members.iter().filter(|m| m.name() == "FCDA" && names_ln(**m, "ldInst")).collect();
                if gone.is_empty() {
                    continue;
                }
                if gone.len() == members.len() {
                    tx.remove(ds);
                    if let (Some(owner), Some(dsname)) = (ds.parent(), ds.attribute("name")) {
                        for cb in owner.children().filter(|c| CONTROL_ELEMENTS.contains(&c.name()) && c.attribute("datSet") == Some(dsname)) {
                            tx.remove_attribute(cb, "datSet");
                        }
                    }
                } else {
                    for m in gone {
                        tx.remove(*m);
                    }
                }
            }
            for el in root.descendants().filter(|e| e.attribute("iedName") == Some(ied)) {
                match el.name() {
                    "ExtRef" if names_ln(el, "ldInst") => unbind(tx, el, &EXT_REF_SOURCE),
                    "LNode" if names_ln(el, "ldInst") => deallocate(tx, el),
                    _ => {}
                }
            }
            Ok(())
        })
    }

    /// Add a data set with its members (the schema requires at least one).
    pub fn add_data_set(&mut self, ied: &str, ld: &str, ln: &LnRef, name: &str, members: &[Fcda]) -> Result<usize> {
        if members.is_empty() {
            return Err(Error::Scl(String::from("a data set needs at least one member")));
        }
        self.edit(&format!("add data set {name}"), |tx| {
            let (_, _, n) = find_ln_in(tx, ied, ld, ln)?;
            if find_data_set(n, name).is_ok() {
                return Err(exists("data set", name));
            }
            let mut e = NewElement::new("DataSet").attr("name", name);
            for m in members {
                e = e.child(fcda_element(m));
            }
            tx.insert(n, &e);
            Ok(())
        })
    }

    /// Rename a data set, with the `datSet` of the control blocks in its LN and `Val` object
    /// references to it.
    pub fn rename_data_set(&mut self, ied: &str, ld: &str, ln: &LnRef, old: &str, new: &str) -> Result<usize> {
        self.edit(&format!("rename data set {old} → {new}"), |tx| {
            let (_, d, n) = find_ln_in(tx, ied, ld, ln)?;
            let ds = find_data_set(n, old)?;
            if find_data_set(n, new).is_ok() {
                return Err(exists("data set", new));
            }
            tx.set_attribute(ds, "name", new);
            for cb in n.children().filter(|c| CONTROL_ELEMENTS.contains(&c.name()) && c.attribute("datSet") == Some(old)) {
                tx.set_attribute(cb, "datSet", new);
            }
            let base = format!("{}/{}$", ld_ref(ied, d), ln.name());
            retarget_values(tx, &format!("{base}{old}"), &format!("{base}{new}"));
            Ok(())
        })
    }

    /// Remove a data set; control blocks that used it lose their `datSet`.
    pub fn remove_data_set(&mut self, ied: &str, ld: &str, ln: &LnRef, name: &str) -> Result<usize> {
        self.edit(&format!("remove data set {name}"), |tx| {
            let (_, _, n) = find_ln_in(tx, ied, ld, ln)?;
            let ds = find_data_set(n, name)?;
            tx.remove(ds);
            for cb in n.children().filter(|c| CONTROL_ELEMENTS.contains(&c.name()) && c.attribute("datSet") == Some(name)) {
                tx.remove_attribute(cb, "datSet");
            }
            Ok(())
        })
    }

    /// Append a member to a data set.
    pub fn add_fcda(&mut self, ied: &str, ld: &str, ln: &LnRef, data_set: &str, member: &Fcda) -> Result<usize> {
        self.edit(&format!("add member to {data_set}"), |tx| {
            let (_, _, n) = find_ln_in(tx, ied, ld, ln)?;
            let ds = find_data_set(n, data_set)?;
            if ds.children_named("FCDA").any(|f| fcda_matches(f, member)) {
                return Err(exists("member of", data_set));
            }
            tx.insert(ds, &fcda_element(member));
            Ok(())
        })
    }

    /// Remove a member from a data set. The last member cannot be removed; remove the data set.
    pub fn remove_fcda(&mut self, ied: &str, ld: &str, ln: &LnRef, data_set: &str, member: &Fcda) -> Result<usize> {
        self.edit(&format!("remove member from {data_set}"), |tx| {
            let (_, _, n) = find_ln_in(tx, ied, ld, ln)?;
            let ds = find_data_set(n, data_set)?;
            let f = ds.children_named("FCDA").find(|f| fcda_matches(*f, member)).ok_or(Error::NotFound("FCDA"))?;
            if ds.children().filter(|c| c.name() == "FCDA" || c.name() == "FCCB").count() == 1 {
                return Err(Error::Scl(format!("{data_set} would be left with no members; remove the data set instead")));
            }
            tx.remove(f);
            Ok(())
        })
    }

    /// Add a control block. `element` must be the kind's element (e.g. `GSEControl`) with a
    /// `name`; GOOSE and sampled-value blocks live in `LLN0` only.
    pub fn add_control(&mut self, ied: &str, ld: &str, ln: &LnRef, kind: ControlKind, element: &NewElement) -> Result<usize> {
        if element.name != kind.element() {
            return Err(Error::Scl(format!("expected a {} element, got {}", kind.element(), element.name)));
        }
        if matches!(kind, ControlKind::Gse | ControlKind::Smv) && !ln.is_lln0() {
            return Err(Error::Scl(format!("{} belongs in LLN0", kind.element())));
        }
        let name = element.attributes.iter().find(|(k, _)| k == "name").map(|(_, v)| v.clone()).ok_or(Error::NotFound("name attribute"))?;
        self.edit(&format!("add {} {name}", kind.element()), |tx| {
            let (_, _, n) = find_ln_in(tx, ied, ld, ln)?;
            if find_control(n, kind, &name).is_ok() {
                return Err(exists(kind.element(), &name));
            }
            tx.insert(n, element);
            Ok(())
        })
    }

    /// Rename a control block, with its `GSE`/`SMV` address entry, the `srcCBName` of `ExtRef`s
    /// that receive through it, and `Val` object references to it.
    pub fn rename_control(&mut self, ied: &str, ld: &str, ln: &LnRef, kind: ControlKind, old: &str, new: &str) -> Result<usize> {
        self.edit(&format!("rename {} {old} → {new}", kind.element()), |tx| {
            let root = tx.root();
            let (_, d, n) = find_ln_in(tx, ied, ld, ln)?;
            let cb = find_control(n, kind, old)?;
            if find_control(n, kind, new).is_ok() {
                return Err(exists(kind.element(), new));
            }
            tx.set_attribute(cb, "name", new);
            let comm = match kind {
                ControlKind::Gse => Some("GSE"),
                ControlKind::Smv => Some("SMV"),
                _ => None,
            };
            if let Some(element) = comm {
                for g in comm_entries(root, ied, element, ld, old) {
                    tx.set_attribute(g, "cbName", new);
                }
            }
            for e in root.descendants().filter(|e| names_control(*e, ied, ld, ln, old)) {
                tx.set_attribute(e, "srcCBName", new);
            }
            let base = format!("{}/{}$", ld_ref(ied, d), ln.name());
            for fc in kind.fcs() {
                retarget_values(tx, &format!("{base}{fc}${old}"), &format!("{base}{fc}${new}"));
            }
            Ok(())
        })
    }

    /// Remove a control block with its `GSE`/`SMV` address entry; `ExtRef`s that received
    /// through it keep their data source and lose the control-block half of their binding.
    pub fn remove_control(&mut self, ied: &str, ld: &str, ln: &LnRef, kind: ControlKind, name: &str) -> Result<usize> {
        self.edit(&format!("remove {} {name}", kind.element()), |tx| {
            let root = tx.root();
            let (_, _, n) = find_ln_in(tx, ied, ld, ln)?;
            tx.remove(find_control(n, kind, name)?);
            let comm = match kind {
                ControlKind::Gse => Some("GSE"),
                ControlKind::Smv => Some("SMV"),
                _ => None,
            };
            if let Some(element) = comm {
                for g in comm_entries(root, ied, element, ld, name) {
                    tx.remove(g);
                }
            }
            for e in root.descendants().filter(|e| names_control(*e, ied, ld, ln, name)) {
                unbind(tx, e, &EXT_REF_CB);
            }
            Ok(())
        })
    }

    /// Bind the `ExtRef` with `intAddr` in `ied`/`ld`/`ln` to a source, replacing any previous
    /// binding. `intAddr`, `desc` and the `pServT`/`pLN`/`pDO`/`pDA` restrictions are kept.
    pub fn bind_ext_ref(&mut self, ied: &str, ld: &str, ln: &LnRef, int_addr: &str, source: &ExtRefSource) -> Result<usize> {
        self.edit(&format!("bind {int_addr}"), |tx| {
            let e = find_ext_ref(tx, ied, ld, ln, int_addr)?;
            let cb = source.src_cb.as_ref();
            let values: [(&str, Option<&str>); 13] = [
                ("iedName", Some(source.ied.as_str())),
                ("ldInst", Some(source.ld.as_str())),
                ("prefix", Some(source.prefix.as_str()).filter(|s| !s.is_empty())),
                ("lnClass", Some(source.ln_class.as_str())),
                ("lnInst", Some(source.ln_inst.as_str()).filter(|s| !s.is_empty())),
                ("doName", Some(source.do_name.as_str())),
                ("daName", source.da_name.as_deref()),
                ("serviceType", source.service_type.as_deref()),
                ("srcLDInst", cb.map(|c| c.ld.as_str())),
                ("srcPrefix", cb.map(|c| c.ln.prefix.as_str()).filter(|s| !s.is_empty())),
                ("srcLNClass", cb.map(|c| c.ln.ln_class.as_str())),
                ("srcLNInst", cb.map(|c| c.ln.inst.as_str()).filter(|s| !s.is_empty())),
                ("srcCBName", cb.map(|c| c.name.as_str())),
            ];
            for (k, v) in values {
                match v {
                    Some(v) => tx.set_attribute(e, k, v),
                    None => tx.remove_attribute(e, k),
                }
            }
            Ok(())
        })
    }

    /// Unbind the `ExtRef` with `intAddr`: its source attributes go, the rest stays.
    pub fn unbind_ext_ref(&mut self, ied: &str, ld: &str, ln: &LnRef, int_addr: &str) -> Result<usize> {
        self.edit(&format!("unbind {int_addr}"), |tx| {
            let e = find_ext_ref(tx, ied, ld, ln, int_addr)?;
            unbind(tx, e, &EXT_REF_SOURCE);
            Ok(())
        })
    }

    /// Set a GOOSE control block's address (`MAC-Address`, `APPID`, `VLAN-ID`, `VLAN-PRIORITY`,
    /// and `MinTime`/`MaxTime` when given), creating its `GSE` entry under the `ConnectedAP` of
    /// the access point that holds the logical device if there is none.
    pub fn set_gse_address(&mut self, ied: &str, ld: &str, cb: &str, address: &GseAddress) -> Result<usize> {
        self.edit(&format!("set GSE address of {cb}"), |tx| {
            let ps = mac_ps(address.mac.to_string(), address.appid, address.vlan_id, address.vlan_priority);
            let times = [("MinTime", address.min_time_ms), ("MaxTime", address.max_time_ms)];
            match control_entry(tx, ied, ld, cb, ControlKind::Gse)? {
                Entry::Existing(g) => {
                    set_address(tx, g, &ps);
                    for (name, ms) in times {
                        if let Some(ms) = ms {
                            match g.child(name) {
                                Some(t) => tx.set_text(t, &ms.to_string()),
                                None => tx.insert(g, &duration(name, ms)),
                            }
                        }
                    }
                }
                Entry::New(cap) => {
                    let mut g = NewElement::new("GSE").attr("ldInst", ld).attr("cbName", cb).child(p_address(&ps));
                    for (name, ms) in times {
                        if let Some(ms) = ms {
                            g = g.child(duration(name, ms));
                        }
                    }
                    tx.insert(cap, &g);
                }
            }
            Ok(())
        })
    }

    /// Set a sampled-value control block's address, creating its `SMV` entry if there is none.
    pub fn set_smv_address(&mut self, ied: &str, ld: &str, cb: &str, address: &SmvAddress) -> Result<usize> {
        self.edit(&format!("set SMV address of {cb}"), |tx| {
            let ps = mac_ps(address.mac.to_string(), address.appid, address.vlan_id, address.vlan_priority);
            match control_entry(tx, ied, ld, cb, ControlKind::Smv)? {
                Entry::Existing(s) => set_address(tx, s, &ps),
                Entry::New(cap) => tx.insert(cap, &NewElement::new("SMV").attr("ldInst", ld).attr("cbName", cb).child(p_address(&ps))),
            }
            Ok(())
        })
    }

    /// Set one `P` of an access point's address (`IP`, `IP-SUBNET`, `OSI-TSEL`, …).
    pub fn set_ap_address(&mut self, ied: &str, ap: &str, p_type: &str, value: &str) -> Result<usize> {
        self.edit(&format!("set {p_type} of {ied}/{ap}"), |tx| {
            let cap = connected_ap(tx.root(), ied, ap)?;
            set_address(tx, cap, &[(p_type, String::from(value))]);
            Ok(())
        })
    }
}

fn p_address(ps: &[(&str, String)]) -> NewElement {
    let mut a = NewElement::new("Address");
    for (t, v) in ps {
        a = a.child(NewElement::new("P").attr("type", *t).text(v.as_str()));
    }
    a
}

enum Entry<'a> {
    /// The `GSE`/`SMV` element that already exists.
    Existing(Element<'a>),
    /// The `ConnectedAP` a new one goes under.
    New(Element<'a>),
}

fn control_entry<'a>(tx: &Tx<'a>, ied: &str, ld: &str, cb: &str, kind: ControlKind) -> Result<Entry<'a>> {
    let root = tx.root();
    let i = find_ied(tx, ied)?;
    let d = find_ld(i, ld)?;
    find_control(find_ln(d, &LnRef::lln0())?, kind, cb)?;
    let element = if kind == ControlKind::Gse { "GSE" } else { "SMV" };
    if let Some(g) = comm_entries(root, ied, element, ld, cb).into_iter().next() {
        return Ok(Entry::Existing(g));
    }
    let ap = i
        .children_named("AccessPoint")
        .find(|ap| ap.children_named("Server").flat_map(|s| s.children_named("LDevice")).any(|l| l.attribute("inst") == Some(ld)))
        .and_then(|ap| ap.attribute("name"))
        .ok_or(Error::NotFound("AccessPoint"))?;
    Ok(Entry::New(connected_ap(root, ied, ap)?))
}

fn find_ext_ref<'a>(tx: &Tx<'a>, ied: &str, ld: &str, ln: &LnRef, int_addr: &str) -> Result<Element<'a>> {
    let (_, _, n) = find_ln_in(tx, ied, ld, ln)?;
    n.children_named("Inputs").flat_map(|i| i.children_named("ExtRef")).find(|e| e.attribute("intAddr") == Some(int_addr)).ok_or(Error::NotFound("ExtRef"))
}
