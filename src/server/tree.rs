//! The MMS variable tree of a logical device, built once from the SCL model.
//!
//! IEC 61850-8-1 maps an IED's model onto MMS **named variables** in a domain, and the map is
//! a tree whose levels are the logical node, the functional constraint, the data object, and
//! the data attributes below it:
//!
//! ```text
//! IED1LD0                                  ← MMS domain = logical device
//! └─ LLN0                                  ← named variable = logical node
//!    ├─ ST                                 ← functional constraint
//!    │  └─ Mod
//!    │     ├─ stVal   INTEGER(8)
//!    │     ├─ q       BIT STRING(-13)
//!    │     └─ t       UTC TIME
//!    ├─ RP
//!    │  └─ urcb01     ← a control block is a named variable like any other
//!    └─ SP
//!       └─ SGCB
//! ```
//!
//! Every one of those lines is a name a client can read, and `GetNameList` returns all of
//! them `$`-joined: `LLN0`, `LLN0$ST`, `LLN0$ST$Mod`, `LLN0$ST$Mod$stVal`, … That flattened
//! namespace is **required by the 8-1 mapping** 🌐 (libiec61850 says so in the comment above
//! `CONFIG_MMS_SUPPORT_FLATTED_NAME_SPACE`, and its client browses by parsing exactly these
//! names), and the list must be in **ascending order** — `CONFIG_MMS_SORT_NAME_LIST`, "required
//! by the standard" 🌐 — because `continueAfter` paging is otherwise not well defined.
//!
//! Building the tree once, at load, is what makes browse, read, write and type discovery three
//! walks of the same structure instead of three interpretations of the model.

use alloc::string::String;
use alloc::vec::Vec;

use crate::common::Fc;
use crate::model::{BType, DataAttribute, DataObject, LogicalDevice, LogicalNode};
use crate::proto::mms::typespec::{Component, TypeSpec};

/// The separator IEC 61850-8-1 joins the levels of an MMS item name with.
pub const SEP: char = '$';

/// What a node of the tree is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VarKind {
    /// A structure; its components are the children.
    Structure,
    /// A leaf holding a value of this basic type.
    Leaf(BType),
}

/// One node of the tree: a name, what it is, and what is under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Variable {
    /// The component name at this level (`LLN0`, `ST`, `Mod`, `stVal`).
    pub name: String,
    /// Structure or leaf.
    pub kind: VarKind,
    /// The functional constraint this node sits under, once one is known. The logical node
    /// itself has none; everything from the FC level down carries it, which is what lets a
    /// write to `…$CO$Pos$Oper` be recognised as a control without re-parsing the name.
    pub fc: Option<Fc>,
    /// Components, for a structure.
    pub children: Vec<Variable>,
}

impl Variable {
    /// A structure node.
    fn structure(name: impl Into<String>, fc: Option<Fc>, children: Vec<Variable>) -> Variable {
        Variable { name: name.into(), kind: VarKind::Structure, fc, children }
    }

    /// A leaf node.
    pub fn leaf(name: impl Into<String>, fc: Option<Fc>, btype: BType) -> Variable {
        Variable { name: name.into(), kind: VarKind::Leaf(btype), fc, children: Vec::new() }
    }

    /// True when this node has components.
    pub fn is_structure(&self) -> bool {
        matches!(self.kind, VarKind::Structure)
    }

    /// The component of this structure with `name`.
    pub fn child(&self, name: &str) -> Option<&Variable> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Walk `path` from this node.
    pub fn resolve<'a>(&'a self, path: &mut dyn Iterator<Item = &str>) -> Option<&'a Variable> {
        let mut node = self;
        for part in path {
            node = node.child(part)?;
        }
        Some(node)
    }

    /// The type specification `GetVariableAccessAttributes` answers with.
    ///
    /// The scalar mappings are IEC 61850-8-1's, cross-checked against libiec61850's
    /// `createNamedVariableFromDataAttribute` 🌐 — including the signs, which are not
    /// decoration: `Quality` is `BIT STRING(-13)` (at most thirteen bits) while `Dbpos` is
    /// `BIT STRING(2)` (exactly two), and a client that normalises them away loses the only
    /// thing on the wire that tells the two apart.
    pub fn type_spec(&self) -> TypeSpec {
        match &self.kind {
            VarKind::Structure => TypeSpec::Structure {
                packed: false,
                components: self.children.iter().map(|c| Component { name: Some(c.name.clone()), type_spec: c.type_spec() }).collect(),
            },
            VarKind::Leaf(b) => type_of(b),
        }
    }
}

/// The MMS type of a basic type.
pub fn type_of(btype: &BType) -> TypeSpec {
    match btype {
        BType::Boolean => TypeSpec::Boolean,
        // An enumeration is an eight-bit INTEGER — not an unsigned, and not a 32-bit one —
        // which is why it shares this arm and does not get one of its own.
        BType::Int8 | BType::Enum => TypeSpec::Integer(8),
        BType::Int16 => TypeSpec::Integer(16),
        BType::Int24 => TypeSpec::Integer(24),
        BType::Int32 => TypeSpec::Integer(32),
        BType::Int64 => TypeSpec::Integer(64),
        BType::Int8U => TypeSpec::Unsigned(8),
        BType::Int16U => TypeSpec::Unsigned(16),
        BType::Int24U => TypeSpec::Unsigned(24),
        BType::Int32U => TypeSpec::Unsigned(32),
        BType::Float32 => TypeSpec::FloatingPoint { format_width: 32, exponent_width: 8 },
        BType::Float64 => TypeSpec::FloatingPoint { format_width: 64, exponent_width: 11 },
        // Exactly two bits, because a position code is two bits and nothing else.
        BType::Dbpos | BType::Tcmd => TypeSpec::BitString(2),
        // `PhyComAddr` is a structure of its own (`Addr`, `PRIORITY`, `VID`, `APPID`) and
        // `Struct` is one by definition; both are only reached here when the model gave a
        // structure no components, which is a file that says nothing about its own shape.
        BType::PhyComAddr | BType::Struct | BType::Other(_) => TypeSpec::Structure { packed: false, components: Vec::new() },
        // At most: a quality is thirteen bits and a check is two, and the negative length is
        // what says "at most" rather than "exactly".
        BType::Quality => TypeSpec::BitString(-13),
        BType::Check => TypeSpec::BitString(-2),
        BType::TrgOps => TypeSpec::BitString(-6),
        BType::OptFlds => TypeSpec::BitString(-10),
        BType::SvOptFlds => TypeSpec::BitString(-3),
        BType::Timestamp => TypeSpec::UtcTime,
        BType::EntryTime => TypeSpec::BinaryTime(true),
        BType::VisString32 => TypeSpec::VisibleString(-32),
        BType::VisString64 => TypeSpec::VisibleString(-64),
        BType::VisString65 => TypeSpec::VisibleString(-65),
        BType::VisString129 | BType::ObjRef => TypeSpec::VisibleString(-129),
        BType::VisString255 => TypeSpec::VisibleString(-255),
        BType::Currency => TypeSpec::VisibleString(-3),
        BType::Octet64 => TypeSpec::OctetString(-64),
        BType::EntryID => TypeSpec::OctetString(-8),
        BType::Unicode255 => TypeSpec::MmsString(-255),
    }
}

/// The MMS variable tree of one logical device: its logical nodes, in model order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    /// The MMS domain name, which is the logical device name.
    pub name: String,
    /// The logical nodes, each a structure.
    pub nodes: Vec<Variable>,
}

impl Domain {
    /// The logical node named `name`.
    pub fn node(&self, name: &str) -> Option<&Variable> {
        self.nodes.iter().find(|n| n.name == name)
    }

    /// Resolve an MMS item name (`LLN0$ST$Mod$stVal`) to its node.
    pub fn resolve(&self, item: &str) -> Option<&Variable> {
        let mut parts = item.split(SEP);
        let node = self.node(parts.next()?)?;
        node.resolve(&mut parts)
    }

    /// Every named variable of this domain, `$`-joined and **sorted**, which is the order
    /// `GetNameList` has to answer in for `continueAfter` paging to mean anything.
    pub fn variable_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        for node in &self.nodes {
            push_names(node, &node.name, &mut out);
        }
        out.sort();
        out
    }
}

fn push_names(node: &Variable, prefix: &str, out: &mut Vec<String>) {
    out.push(String::from(prefix));
    for child in &node.children {
        let mut name = String::with_capacity(prefix.len() + 1 + child.name.len());
        name.push_str(prefix);
        name.push(SEP);
        name.push_str(&child.name);
        push_names(child, &name, out);
    }
}

/// Build the MMS variable tree of a logical device.
///
/// `extra` supplies the control blocks, which are named variables under their functional
/// constraint but are not data objects: the report, log, GOOSE and sampled-value blocks and
/// the setting group block. They are passed in rather than built here because their component
/// sets belong to the layers that implement them.
pub fn domain_of(ld: &LogicalDevice, extra: &mut dyn FnMut(&LogicalNode) -> Vec<(Fc, Variable)>) -> Domain {
    let mut nodes = Vec::with_capacity(ld.logical_nodes.len());
    for ln in &ld.logical_nodes {
        let mut by_fc: Vec<(Fc, Vec<Variable>)> = Vec::new();
        for fc in functional_constraints(ln) {
            let children: Vec<Variable> = ln.data_objects.iter().filter_map(|d| object_under(d, fc)).collect();
            if !children.is_empty() {
                by_fc.push((fc, children));
            }
        }
        for (fc, variable) in extra(ln) {
            match by_fc.iter_mut().find(|(f, _)| *f == fc) {
                Some((_, list)) => list.push(variable),
                None => by_fc.push((fc, alloc::vec![variable])),
            }
        }
        // Within a functional constraint the components keep model order; the *names* are
        // sorted when the list is produced, so the tree stays the order the file wrote.
        by_fc.sort_by_key(|(fc, _)| fc.as_str());
        let fcs = by_fc.into_iter().map(|(fc, children)| Variable::structure(fc.as_str(), Some(fc), children)).collect();
        nodes.push(Variable::structure(ln.name.clone(), None, fcs));
    }
    Domain { name: ld.name.clone(), nodes }
}

/// Every functional constraint any attribute of `ln` is under, in a stable order.
fn functional_constraints(ln: &LogicalNode) -> Vec<Fc> {
    let mut out: Vec<Fc> = Vec::new();
    for d in &ln.data_objects {
        collect_fcs(d, &mut out);
    }
    out.sort_by_key(|fc| fc.as_str());
    out
}

fn collect_fcs(object: &DataObject, out: &mut Vec<Fc>) {
    for a in &object.attributes {
        if !out.contains(&a.fc) {
            out.push(a.fc);
        }
    }
    for s in &object.sub_objects {
        collect_fcs(s, out);
    }
}

/// The part of a data object that lives under `fc`, or `None` when none of it does.
fn object_under(object: &DataObject, fc: Fc) -> Option<Variable> {
    let mut children: Vec<Variable> = object.attributes.iter().filter(|a| a.fc == fc).map(attribute_variable).collect();
    children.extend(object.sub_objects.iter().filter_map(|s| object_under(s, fc)));
    if children.is_empty() { None } else { Some(Variable::structure(object.name.clone(), Some(fc), children)) }
}

/// A data attribute and its sub-attributes. A `Struct` with no components is a leaf: the file
/// declared a structure and said nothing about its shape, and inventing one would be worse.
fn attribute_variable(a: &DataAttribute) -> Variable {
    if a.children.is_empty() {
        Variable::leaf(a.name.clone(), Some(a.fc), a.btype.clone())
    } else {
        Variable::structure(a.name.clone(), Some(a.fc), a.children.iter().map(attribute_variable).collect())
    }
}

/// Split an MMS item name into the logical node, the functional constraint and the rest.
///
/// `LLN0$ST$Mod$stVal` → `("LLN0", Some(ST), ["Mod", "stVal"])`. The rest is what a caller
/// walks; the FC is what says whether a write is a control, a control-block setting or a
/// value.
pub fn split_item(item: &str) -> (&str, Option<Fc>, impl Iterator<Item = &str>) {
    let mut parts = item.split(SEP);
    let ln = parts.next().unwrap_or("");
    let mut rest = parts.clone();
    let fc = rest.next().and_then(Fc::parse);
    if fc.is_some() { (ln, fc, rest) } else { (ln, None, parts) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::IedModel;
    use alloc::vec;

    fn model() -> IedModel {
        const ICD: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="t"/>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/>
    <LN lnClass="CSWI" inst="1" prefix="" lnType="CSWI_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="INC_T"/></LNodeType>
    <LNodeType id="CSWI_T" lnClass="CSWI"><DO name="Pos" type="DPC_T"/></LNodeType>
    <DOType id="INC_T" cdc="INC">
      <DA name="stVal" fc="ST" bType="Enum" type="Mod_E"/>
      <DA name="q" fc="ST" bType="Quality"/>
      <DA name="t" fc="ST" bType="Timestamp"/>
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModel_E"/>
    </DOType>
    <DOType id="DPC_T" cdc="DPC">
      <DA name="stVal" fc="ST" bType="Dbpos"/>
      <DA name="q" fc="ST" bType="Quality"/>
      <DA name="Oper" fc="CO" bType="Struct" type="Oper_T"/>
    </DOType>
    <DAType id="Oper_T">
      <BDA name="ctlVal" bType="Dbpos"/>
      <BDA name="ctlNum" bType="INT8U"/>
      <BDA name="T" bType="Timestamp"/>
      <BDA name="Test" bType="BOOLEAN"/>
    </DAType>
    <EnumType id="Mod_E"><EnumVal ord="1">on</EnumVal></EnumType>
    <EnumType id="CtlModel_E"><EnumVal ord="1">direct-with-normal-security</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;
        IedModel::from_scl(ICD, Some("IED1")).expect("load")
    }

    fn domain() -> Domain {
        let m = model();
        domain_of(&m.logical_devices[0], &mut |_| Vec::new())
    }

    #[test]
    fn the_namespace_is_flattened_and_sorted() {
        let names = domain().variable_names();
        // Every level is a name a client can read — the logical node, the functional
        // constraint, the data object and every attribute below it. libiec61850's own client
        // browses by parsing exactly this shape, and its server calls the flattened namespace
        // "required by IEC 61850-8-1".
        for expected in [
            "CSWI1",
            "CSWI1$CO",
            "CSWI1$CO$Pos",
            "CSWI1$CO$Pos$Oper",
            "CSWI1$CO$Pos$Oper$ctlVal",
            "CSWI1$ST$Pos$stVal",
            "LLN0",
            "LLN0$CF",
            "LLN0$CF$Mod$ctlModel",
            "LLN0$ST$Mod$stVal",
            "LLN0$ST$Mod$t",
        ] {
            assert!(names.iter().any(|n| n == expected), "`{expected}` missing from {names:#?}");
        }
        // Sorted: `continueAfter` is an exact match on a name in this list and the answer
        // resumes after it, so an unordered list is a paging loop that skips or repeats.
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        // And the logical node names are the ones with no separator, which is how a client
        // tells `GetLogicalDeviceDirectory` from everything else.
        let lns: Vec<&String> = names.iter().filter(|n| !n.contains(SEP)).collect();
        assert_eq!(lns, ["CSWI1", "LLN0"]);
    }

    #[test]
    fn a_name_resolves_to_the_node_it_denotes() {
        let d = domain();
        assert_eq!(d.resolve("LLN0$ST$Mod$stVal").map(|v| v.kind.clone()), Some(VarKind::Leaf(BType::Enum)));
        assert!(d.resolve("LLN0$ST$Mod").is_some_and(Variable::is_structure));
        assert!(d.resolve("CSWI1$CO$Pos$Oper").is_some_and(Variable::is_structure));
        // A name the model does not have is `None`, not a guess.
        assert!(d.resolve("LLN0$ST$Mod$nosuch").is_none());
        assert!(d.resolve("LLN0$MX$Mod$stVal").is_none(), "the attribute is under ST, not MX");
        assert!(d.resolve("NOPE").is_none());
    }

    #[test]
    fn the_type_of_a_structure_is_its_components_in_order() {
        let d = domain();
        let oper = d.resolve("CSWI1$CO$Pos$Oper").expect("Oper").type_spec();
        assert_eq!(oper.component_names(), ["ctlVal", "ctlNum", "T", "Test"]);
        assert_eq!(oper.component("ctlVal"), Some(&TypeSpec::BitString(2)), "a position code is exactly two bits");
        assert_eq!(oper.component("ctlNum"), Some(&TypeSpec::Unsigned(8)));
        assert_eq!(oper.component("T"), Some(&TypeSpec::UtcTime));
        // A quality is *at most* thirteen bits and a `Dbpos` is *exactly* two: the sign is
        // the only thing on the wire that tells a bounded bit string from a fixed one.
        assert_eq!(type_of(&BType::Quality), TypeSpec::BitString(-13));
        assert_eq!(type_of(&BType::Dbpos), TypeSpec::BitString(2));
        assert_eq!(type_of(&BType::Check), TypeSpec::BitString(-2));
        // An enumeration is an eight-bit INTEGER — not an unsigned, and not thirty-two bits.
        assert_eq!(type_of(&BType::Enum), TypeSpec::Integer(8));
        assert_eq!(type_of(&BType::EntryTime), TypeSpec::BinaryTime(true));
    }

    #[test]
    fn control_blocks_join_the_tree_under_their_functional_constraint() {
        let m = model();
        let d = domain_of(&m.logical_devices[0], &mut |ln| {
            if ln.name == "LLN0" {
                vec![(Fc::RP, Variable::structure("urcb01", Some(Fc::RP), vec![Variable::leaf("RptEna", Some(Fc::RP), BType::Boolean)]))]
            } else {
                Vec::new()
            }
        });
        let names = d.variable_names();
        assert!(names.iter().any(|n| n == "LLN0$RP"));
        assert!(names.iter().any(|n| n == "LLN0$RP$urcb01$RptEna"));
        assert_eq!(d.resolve("LLN0$RP$urcb01$RptEna").map(|v| v.kind.clone()), Some(VarKind::Leaf(BType::Boolean)));
    }

    #[test]
    fn an_item_name_splits_into_node_constraint_and_path() {
        let (ln, fc, rest) = split_item("LLN0$ST$Mod$stVal");
        assert_eq!((ln, fc), ("LLN0", Some(Fc::ST)));
        assert_eq!(rest.collect::<Vec<_>>(), ["Mod", "stVal"]);
        // A logical node on its own has no constraint and nothing under it.
        let (ln, fc, rest) = split_item("LLN0");
        assert_eq!((ln, fc, rest.count()), ("LLN0", None, 0));
        // And a second level that is not a functional constraint is kept as part of the path
        // rather than swallowed.
        let (ln, fc, rest) = split_item("LLN0$dsTrip");
        assert_eq!((ln, fc), ("LLN0", None));
        assert_eq!(rest.collect::<Vec<_>>(), ["dsTrip"]);
    }
}
