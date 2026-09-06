//! The served IED: the model, the namespace it maps to, and the values behind it.
//!
//! Everything a client can name lives here. The SCL file gives the shape ([`super::tree`]),
//! this gives the shape *values*, and [`super::acsi`] answers requests out of both. There is
//! no registry and no build step: [`Ied::from_scl`] is the whole configuration.
//!
//! Values are keyed by their **full MMS reference** — `IED1LD0/LLN0$ST$Mod$stVal` — because
//! that is what a data-set member resolves to, what a report's `DataRef` prints, and what a
//! client writes to. One key shape for all of them is what keeps a report and a read from
//! disagreeing about which attribute changed.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::tree::{self, Domain, VarKind, Variable};
use crate::common::{Edition, EntryTime, Error, Fc, OptFlds, Quality, Result, TrgOps, UtcTime};
use crate::model::{BType, IedModel, LogicalNode, ReportControl};
use crate::proto::data::Value;

/// What a control block is, so that a write to one can be recognised without re-parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// An unbuffered report control block (`RP`).
    Unbuffered,
    /// A buffered report control block (`BR`).
    Buffered,
    /// A log control block (`LG`).
    Log,
    /// The setting group control block (`SP$SGCB`).
    SettingGroup,
    /// A GOOSE control block (`GO`).
    Goose,
    /// A sampled-value control block (`MS`).
    SampledValue,
}

/// One control block of the served model, and where it sits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// The full MMS reference of the block: `IED1LD0/LLN0$RP$urcb01`.
    pub reference: String,
    /// The logical device it is in.
    pub domain: String,
    /// The logical node it is in.
    pub node: String,
    /// Its own name, with the index for an indexed report control block.
    pub name: String,
    /// What kind it is.
    pub kind: BlockKind,
    /// The data set it reports, in MMS form, when it has one.
    pub data_set: Option<String>,
}

/// A data set as the server holds it: its members expanded to the leaves they cover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedDataSet {
    /// `IED1LD0/LLN0$dsTrip`.
    pub reference: String,
    /// The members as the file names them, in order — a member may name a data object, in
    /// which case it covers every attribute under it.
    pub members: Vec<String>,
    /// Every leaf the members cover, in member order. This is what a report's inclusion bit
    /// string indexes into and what a trigger evaluation compares against.
    pub leaves: Vec<String>,
    /// True when a client created it and may delete it again.
    pub deletable: bool,
}

/// The IED a server serves.
#[derive(Debug)]
pub struct Ied {
    /// The model it was built from.
    pub model: IedModel,
    /// The MMS domains, one per logical device, in model order.
    pub domains: Vec<Domain>,
    /// Leaf values, keyed by full MMS reference.
    values: BTreeMap<String, Value>,
    /// Data sets, keyed by reference.
    data_sets: BTreeMap<String, ServedDataSet>,
    /// Control blocks, in namespace order.
    blocks: Vec<Block>,
    /// References written since the last commit, and what triggered each.
    dirty: BTreeMap<String, TrgOps>,
    /// The edition this IED serves — taken from the SCL file, because that is where an
    /// IED's edition is declared. It decides the report control block's attribute set:
    /// `ResvTms` and `Owner` arrived with Edition 2, and a server that publishes them to an
    /// Edition 1 client is claiming a service it does not have.
    edition: Edition,
}

impl Ied {
    /// Load an IED from an SCL document.
    ///
    /// `ied` names the IED in an SCD; a single-IED ICD may pass `None`.
    #[cfg(feature = "scl")]
    pub fn from_scl(xml: &str, ied: Option<&str>) -> Result<Ied> {
        Ied::new(IedModel::from_scl(xml, ied)?)
    }

    /// Load an IED from an SCL file on disk — the twenty-line server's first line.
    #[cfg(all(feature = "scl", feature = "std"))]
    pub fn from_scl_file(path: impl AsRef<std::path::Path>, ied: Option<&str>) -> Result<Ied> {
        Ied::new(IedModel::from_scl_file(path, ied)?)
    }

    /// Build the served IED from a model that is already loaded.
    ///
    /// The edition comes from the file's own schema version ([`IedModel::edition`]);
    /// [`Ied::with_edition`] overrides it for a device whose file says one thing and whose
    /// certificate says another.
    pub fn new(model: IedModel) -> Result<Ied> {
        let edition = model.edition();
        Ied::with_edition(model, edition)
    }

    /// Build the served IED at an explicit edition.
    pub fn with_edition(model: IedModel, edition: Edition) -> Result<Ied> {
        let mut blocks = Vec::new();
        let mut domains = Vec::with_capacity(model.logical_devices.len());
        for ld in &model.logical_devices {
            let ld_name = ld.name.clone();
            let mut found: Vec<Block> = Vec::new();
            let domain = tree::domain_of(ld, &mut |ln| control_blocks(&ld_name, ln, edition, &mut found));
            blocks.extend(found);
            domains.push(domain);
        }

        let mut ied = Ied { model, domains, values: BTreeMap::new(), data_sets: BTreeMap::new(), blocks, dirty: BTreeMap::new(), edition };
        ied.seed_values();
        ied.seed_data_sets();
        ied.seed_blocks();
        Ok(ied)
    }

    /// The edition this IED serves.
    pub const fn edition(&self) -> Edition {
        self.edition
    }

    /// The MMS domain names, which are the logical device names.
    pub fn domain_names(&self) -> Vec<String> {
        self.domains.iter().map(|d| d.name.clone()).collect()
    }

    /// The domain named `name`.
    pub fn domain(&self, name: &str) -> Option<&Domain> {
        self.domains.iter().find(|d| d.name == name)
    }

    /// The control blocks the model defines.
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// The control block at `reference`.
    pub fn block(&self, reference: &str) -> Option<&Block> {
        self.blocks.iter().find(|b| b.reference == reference)
    }

    /// Data-set references in a logical device, sorted.
    pub fn data_set_names(&self, domain: &str) -> Vec<String> {
        let prefix = alloc::format!("{domain}/");
        let mut out: Vec<String> = self.data_sets.keys().filter_map(|k| k.strip_prefix(&prefix).map(String::from)).collect();
        out.sort();
        out
    }

    /// The log names of a logical device, sorted — the MMS journals of that domain.
    ///
    /// A `Log` with no name is the logical device's default log, which IEC 61850-8-1 names
    /// `LLN0$General`; a named one is `LLN0$<name>`.
    pub fn log_names(&self, domain: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(ld) = self.model.logical_devices.iter().find(|ld| ld.name == domain) {
            for ln in &ld.logical_nodes {
                for log in &ln.logs {
                    let name = if log.name.is_empty() { "General" } else { log.name.as_str() };
                    out.push(alloc::format!("{}${name}", ln.name));
                }
            }
        }
        out.sort();
        out
    }

    /// How many data sets a client has created.
    pub fn created_data_sets(&self) -> usize {
        self.data_sets.values().filter(|d| d.deletable).count()
    }

    /// The data set at `reference` (`IED1LD0/LLN0$dsTrip`).
    pub fn data_set(&self, reference: &str) -> Option<&ServedDataSet> {
        self.data_sets.get(reference)
    }

    /// Create a data set. Fails if one of that name already exists.
    pub fn create_data_set(&mut self, reference: &str, members: Vec<String>) -> Result<()> {
        if self.data_sets.contains_key(reference) {
            return Err(Error::InvalidValue("a data set of that name already exists"));
        }
        let leaves = members.iter().flat_map(|m| self.leaves_of(m)).collect();
        self.data_sets.insert(String::from(reference), ServedDataSet { reference: String::from(reference), members, leaves, deletable: true });
        Ok(())
    }

    /// Delete a data set. Returns whether it existed and whether it was deletable.
    pub fn delete_data_set(&mut self, reference: &str) -> (bool, bool) {
        match self.data_sets.get(reference) {
            None => (false, false),
            Some(ds) if !ds.deletable => (true, false),
            Some(_) => {
                self.data_sets.remove(reference);
                (true, true)
            }
        }
    }

    /// The value at a full MMS reference, if it is a leaf that has one.
    pub fn value(&self, reference: &str) -> Option<&Value> {
        self.values.get(reference)
    }

    /// Read a reference as a value: a leaf directly, a structure assembled from its
    /// components in **model order**, which is the order every positional client reads them.
    pub fn read(&self, domain: &str, item: &str) -> Option<Value> {
        let node = self.domain(domain)?.resolve(item)?;
        self.read_node(domain, item, node)
    }

    fn read_node(&self, domain: &str, item: &str, node: &Variable) -> Option<Value> {
        match &node.kind {
            VarKind::Leaf(_) => self.values.get(&reference(domain, item)).cloned(),
            VarKind::Structure => {
                let mut members = Vec::with_capacity(node.children.len());
                for child in &node.children {
                    let path = alloc::format!("{item}{}{}", tree::SEP, child.name);
                    members.push(self.read_node(domain, &path, child)?);
                }
                Some(Value::Structure(members))
            }
        }
    }

    /// Write a value at a full MMS reference without any ACSI behaviour.
    ///
    /// The value must match the leaf's basic type: a server that accepts an integer where a
    /// boolean was engineered has silently changed its own model, and every client that reads
    /// it back gets a type it did not ask for. Returns the `DataAccessError` code on refusal.
    pub fn write_leaf(&mut self, reference: &str, value: Value) -> core::result::Result<(), i64> {
        let Some(node) = self.node_at(reference) else { return Err(DATA_ACCESS_NON_EXISTENT) };
        let VarKind::Leaf(btype) = node.kind.clone() else { return Err(DATA_ACCESS_TYPE_INCONSISTENT) };
        if !accepts(&btype, &value) {
            return Err(DATA_ACCESS_TYPE_INCONSISTENT);
        }
        let changed = self.values.get(reference) != Some(&value);
        let quality = matches!(btype, BType::Quality);
        self.values.insert(String::from(reference), value);
        if changed {
            // A quality that changed is a *quality* change, not a data change: `TrgOps` has
            // separate bits and a client that asked for one and not the other must get what
            // it asked for.
            let trigger = if quality { TrgOps::NONE.with_quality_change(true) } else { TrgOps::NONE.with_data_change(true) };
            let entry = self.dirty.entry(String::from(reference)).or_insert(TrgOps::NONE);
            *entry = TrgOps::from_bit_string(&or_bits(*entry, trigger));
        } else {
            // Written without changing: `dupd`, which is the trigger a client asks for when
            // it wants every update rather than every change.
            let entry = self.dirty.entry(String::from(reference)).or_insert(TrgOps::NONE);
            *entry = TrgOps::from_bit_string(&or_bits(*entry, TrgOps::NONE.with_data_update(true)));
        }
        Ok(())
    }

    /// Write a value without marking it dirty — a write the *server itself* makes.
    ///
    /// A report control block's `SqNum`, `EntryID` and `TimeOfEntry`, a log control block's
    /// `OldEnt`/`NewEnt`, an `SGCB`'s `LActTm` and the `GI`/`PurgeBuf` flags a request
    /// consumes are all bookkeeping the server writes *while publishing*. They are not
    /// application data and no data set contains them, so they must not enter the dirty set.
    /// Publishing through the ordinary write and clearing the set with [`Ied::take_dirty`]
    /// afterwards would also discard any application write that had landed in the meantime —
    /// losing it from the report *and* the log whenever another association's thread committed
    /// at the wrong moment.
    pub fn set_internal(&mut self, reference: &str, value: Value) -> core::result::Result<(), i64> {
        let Some(node) = self.node_at(reference) else { return Err(DATA_ACCESS_NON_EXISTENT) };
        let VarKind::Leaf(btype) = node.kind.clone() else { return Err(DATA_ACCESS_TYPE_INCONSISTENT) };
        if !accepts(&btype, &value) {
            return Err(DATA_ACCESS_TYPE_INCONSISTENT);
        }
        self.values.insert(String::from(reference), value);
        Ok(())
    }

    /// An SCL `Val` text as the value of the attribute at `reference`.
    ///
    /// The type comes from the model and, for an enumeration, so does the symbol table — the
    /// same path a type template's own `Val` takes, so a per-group setting and an ungrouped
    /// one cannot be decoded differently.
    pub fn parse_text(&self, reference: &str, text: &str) -> Option<Value> {
        let node = self.node_at(reference)?;
        let VarKind::Leaf(btype) = &node.kind else { return None };
        // The enumeration table is looked up by the attribute's `type`, which the tree does
        // not carry; the model does, and this is the one place that needs it.
        let type_id = self.attribute_type_id(reference);
        parse_engineered_typed(&self.model, btype, type_id.as_deref(), text)
    }

    /// The `type` attribute of the data attribute at `reference`, for an enumeration.
    ///
    /// The tree carries the basic type but not the `type` id, because only an enumeration
    /// needs it; the model has both, and resolving through it is one lookup rather than a
    /// second walk that could disagree with the first.
    fn attribute_type_id(&self, reference: &str) -> Option<String> {
        let parsed = crate::common::ObjectReference::parse(reference).ok()?;
        self.model.attribute(&parsed)?.type_id.clone()
    }

    /// The tree node a full MMS reference denotes.
    pub fn node_at(&self, reference: &str) -> Option<&Variable> {
        let (domain, item) = reference.split_once('/')?;
        self.domain(domain)?.resolve(item)
    }

    /// What has been written since the last [`Ied::take_dirty`], and what each write triggers.
    pub fn take_dirty(&mut self) -> BTreeMap<String, TrgOps> {
        core::mem::take(&mut self.dirty)
    }

    /// Whether anything is waiting to be committed.
    pub fn is_dirty(&self) -> bool {
        !self.dirty.is_empty()
    }

    /// Every leaf reference a data-set member covers, in namespace order.
    ///
    /// A member that names a data object (`IED1LD0/PTRC1$ST$Tr`) covers every attribute under
    /// it, which is ordinary engineering and is why the inclusion bit string of a report is
    /// not one bit per *member*.
    pub fn leaves_of(&self, reference: &str) -> Vec<String> {
        let Some((domain, item)) = reference.split_once('/') else { return Vec::new() };
        let Some(node) = self.domain(domain).and_then(|d| d.resolve(item)) else { return Vec::new() };
        let mut out = Vec::new();
        collect_leaves(domain, item, node, &mut out);
        out
    }

    // ---- construction --------------------------------------------------------------

    /// Every leaf of every domain gets a value, from the file's `Val` when it has one and
    /// from the type otherwise. A model attribute with no value is still a variable a client
    /// may read, and answering `object-non-existent` for it would be a lie about the model.
    fn seed_values(&mut self) {
        let mut seeded: Vec<(String, Value)> = Vec::new();
        for domain in &self.domains {
            for node in &domain.nodes {
                seed_node(&domain.name, &node.name, node, &mut seeded);
            }
        }
        for (reference, value) in seeded {
            self.values.insert(reference, value);
        }
        // The engineered values from the SCL type templates and instances override the
        // type defaults, which is what makes a `ctlModel` of `sbo-with-enhanced-security`
        // in the file the server's actual behaviour.
        let overrides = self.engineered_values();
        for (reference, value) in overrides {
            self.values.insert(reference, value);
        }
    }

    fn engineered_values(&self) -> Vec<(String, Value)> {
        let mut out = Vec::new();
        for ld in &self.model.logical_devices {
            for ln in &ld.logical_nodes {
                for object in &ln.data_objects {
                    engineered_of(&self.model, &ld.name, &ln.name, &object.name, object, &mut out);
                }
            }
        }
        out
    }

    fn seed_data_sets(&mut self) {
        let mut sets = Vec::new();
        for ld in &self.model.logical_devices {
            for ln in &ld.logical_nodes {
                for ds in &ln.data_sets {
                    sets.push((alloc::format!("{}/{}${}", ld.name, ln.name, ds.name), ld.name.clone(), ds.clone()));
                }
            }
        }
        for (reference, ld_name, ds) in sets {
            let members: Vec<String> = ds.members.iter().map(|m| self.model.fcda_reference(&ld_name, m)).collect();
            let leaves = members.iter().flat_map(|m| self.leaves_of(m)).collect();
            self.data_sets.insert(reference.clone(), ServedDataSet { reference, members, leaves, deletable: false });
        }
    }

    /// Put the engineered defaults into every control block's attributes.
    fn seed_blocks(&mut self) {
        let edition = self.edition;
        let mut writes: Vec<(String, Value)> = Vec::new();
        for ld in &self.model.logical_devices {
            for ln in &ld.logical_nodes {
                for rcb in &ln.report_controls {
                    let data_set = rcb.dat_set.as_ref().map(|d| alloc::format!("{}/{}${d}", ld.name, ln.name));
                    for name in rcb.instance_names() {
                        let base = alloc::format!("{}/{}${}${name}", ld.name, ln.name, rcb.fc().as_str());
                        for (attribute, value) in rcb_defaults(rcb, &base, data_set.as_deref(), edition) {
                            writes.push((alloc::format!("{base}${attribute}"), value));
                        }
                    }
                }
                for lcb in &ln.log_controls {
                    let base = alloc::format!("{}/{}$LG${}", ld.name, ln.name, lcb.name);
                    let log = alloc::format!("{}/{}${}", lcb.log_ld_inst.as_deref().unwrap_or(&ld.name), ln.name, lcb.log_name);
                    for (attribute, value) in lcb_defaults(lcb, &log, ld, ln) {
                        writes.push((alloc::format!("{base}${attribute}"), value));
                    }
                }
                if let Some(sg) = ln.setting_control {
                    let base = alloc::format!("{}/{}$SP$SGCB", ld.name, ln.name);
                    for (attribute, value) in sgcb_defaults(sg) {
                        writes.push((alloc::format!("{base}${attribute}"), value));
                    }
                }
            }
        }
        for (reference, value) in writes {
            self.values.insert(reference, value);
        }
        self.dirty.clear();
    }
}

/// `object-non-existent`.
pub const DATA_ACCESS_NON_EXISTENT: i64 = 10;
/// `type-inconsistent`.
pub const DATA_ACCESS_TYPE_INCONSISTENT: i64 = 7;
/// `object-access-denied`.
pub const DATA_ACCESS_DENIED: i64 = 3;
/// `object-value-invalid`.
pub const DATA_ACCESS_VALUE_INVALID: i64 = 11;

fn or_bits(a: TrgOps, b: TrgOps) -> Vec<u8> {
    let (_, mut left) = a.to_bit_string();
    let (_, right) = b.to_bit_string();
    for (l, r) in left.iter_mut().zip(&right) {
        *l |= *r;
    }
    left
}

/// The full MMS reference of an item in a domain.
fn reference(domain: &str, item: &str) -> String {
    alloc::format!("{domain}/{item}")
}

fn collect_leaves(domain: &str, item: &str, node: &Variable, out: &mut Vec<String>) {
    match node.kind {
        VarKind::Leaf(_) => out.push(reference(domain, item)),
        VarKind::Structure => {
            for child in &node.children {
                collect_leaves(domain, &alloc::format!("{item}{}{}", tree::SEP, child.name), child, out);
            }
        }
    }
}

fn seed_node(domain: &str, item: &str, node: &Variable, out: &mut Vec<(String, Value)>) {
    match &node.kind {
        VarKind::Leaf(b) => out.push((reference(domain, item), default_value(b))),
        VarKind::Structure => {
            for child in &node.children {
                seed_node(domain, &alloc::format!("{item}{}{}", tree::SEP, child.name), child, out);
            }
        }
    }
}

/// The engineered values of one data object, as `(reference, value)` pairs.
///
/// `do_path` is the data object's path below the logical node, `$`-joined: `Pos` for a data
/// object and `Pos$SBO` for a sub data object. Passing only the logical node here is how a
/// nested object's values end up written to the parent's names.
fn engineered_of(model: &IedModel, ld: &str, ln: &str, do_path: &str, object: &crate::model::DataObject, out: &mut Vec<(String, Value)>) {
    fn walk(model: &IedModel, prefix: &str, a: &crate::model::DataAttribute, out: &mut Vec<(String, Value)>) {
        let path = alloc::format!("{prefix}${}", a.name);
        if let Some(text) = &a.value {
            if let Some(v) = parse_engineered(model, a, text) {
                out.push((path.clone(), v));
            }
        }
        for c in &a.children {
            walk(model, &path, c, out);
        }
    }
    for a in &object.attributes {
        walk(model, &alloc::format!("{ld}/{ln}${}${do_path}", a.fc.as_str()), a, out);
    }
    for s in &object.sub_objects {
        engineered_of(model, ld, ln, &alloc::format!("{do_path}${}", s.name), s, out);
    }
}

/// An SCL `Val` as the value of its basic type.
///
/// An enumeration's `Val` is its **symbol** — `direct-with-normal-security`, `on`,
/// `remote-control` — and the wire carries the ordinal. The document's own `EnumType` tables
/// are what turn one into the other, which is why the model loads them: a server that parses
/// the symbol as a number answers `ctlModel = 0` (status-only) for every controllable object
/// in the file, and every control a client then issues is refused for a reason that is not
/// the real one.
fn parse_engineered(model: &IedModel, a: &crate::model::DataAttribute, text: &str) -> Option<Value> {
    parse_engineered_typed(model, &a.btype, a.type_id.as_deref(), text)
}

/// The same, given the type directly.
pub(super) fn parse_engineered_typed(model: &IedModel, btype: &BType, type_id: Option<&str>, text: &str) -> Option<Value> {
    Some(match btype {
        BType::Enum => Value::Integer(model.enum_ord(type_id, text)?),
        BType::Boolean => Value::Boolean(matches!(text, "true" | "1")),
        BType::Int8 | BType::Int16 | BType::Int24 | BType::Int32 | BType::Int64 => Value::Integer(text.parse().ok()?),
        BType::Int8U | BType::Int16U | BType::Int24U | BType::Int32U => Value::Unsigned(text.parse().ok()?),
        BType::Float32 => Value::Float32(text.parse().ok()?),
        BType::Float64 => Value::Float64(text.parse().ok()?),
        BType::VisString32 | BType::VisString64 | BType::VisString65 | BType::VisString129 | BType::VisString255 | BType::ObjRef | BType::Currency => {
            Value::VisibleString(String::from(text))
        }
        BType::Unicode255 => Value::MmsString(String::from(text)),
        _ => return None,
    })
}

/// What a leaf holds before anything has written to it.
pub fn default_value(btype: &BType) -> Value {
    match btype {
        BType::Boolean => Value::Boolean(false),
        BType::Int8 | BType::Int16 | BType::Int24 | BType::Int32 | BType::Int64 | BType::Enum => Value::Integer(0),
        BType::Int8U | BType::Int16U | BType::Int24U | BType::Int32U => Value::Unsigned(0),
        BType::Float32 => Value::Float32(0.0),
        BType::Float64 => Value::Float64(0.0),
        // A quality nobody has set is `Good`, which is the only honest default: a server that
        // starts every attribute `invalid` reports a fault it does not have.
        BType::Quality => Value::quality(Quality::GOOD),
        // Two bits, whether it is a position, a tap command or a check.
        BType::Dbpos | BType::Tcmd | BType::Check => Value::BitString { unused: 6, bytes: alloc::vec![0] },
        BType::TrgOps => TrgOps::NONE.to_value(),
        BType::OptFlds => OptFlds::NONE.to_value(),
        BType::SvOptFlds => Value::BitString { unused: 5, bytes: alloc::vec![0] },
        BType::Timestamp => Value::UtcTime(UtcTime::default()),
        BType::EntryTime => Value::BinaryTime(EntryTime::default().to_octets().to_vec()),
        BType::Octet64 | BType::EntryID | BType::PhyComAddr => Value::OctetString(Vec::new()),
        BType::Unicode255 => Value::MmsString(String::new()),
        BType::Struct | BType::Other(_) => Value::Structure(Vec::new()),
        _ => Value::VisibleString(String::new()),
    }
}

/// Whether a value may be written to a leaf of this basic type.
///
/// Deliberately by *shape*, not by width: a client that writes `Unsigned(3)` where the model
/// says `INT8U` is right, and one that writes a string there is not. Range checking is the
/// application's business — the type is the server's.
pub fn accepts(btype: &BType, value: &Value) -> bool {
    match btype {
        BType::Boolean => matches!(value, Value::Boolean(_)),
        BType::Int8 | BType::Int16 | BType::Int24 | BType::Int32 | BType::Int64 | BType::Enum => {
            matches!(value, Value::Integer(_) | Value::Unsigned(_))
        }
        BType::Int8U | BType::Int16U | BType::Int24U | BType::Int32U => matches!(value, Value::Integer(_) | Value::Unsigned(_)),
        BType::Float32 | BType::Float64 => matches!(value, Value::Float32(_) | Value::Float64(_)),
        BType::Quality | BType::Dbpos | BType::Tcmd | BType::Check | BType::TrgOps | BType::OptFlds | BType::SvOptFlds => {
            matches!(value, Value::BitString { .. })
        }
        BType::Timestamp => matches!(value, Value::UtcTime(_)),
        BType::EntryTime => matches!(value, Value::BinaryTime(_)),
        BType::Octet64 | BType::EntryID | BType::PhyComAddr => matches!(value, Value::OctetString(_)),
        BType::Unicode255 => matches!(value, Value::MmsString(_) | Value::VisibleString(_)),
        BType::Struct | BType::Other(_) => matches!(value, Value::Structure(_)),
        _ => matches!(value, Value::VisibleString(_) | Value::MmsString(_)),
    }
}

/// The components of a report control block, in the order IEC 61850-8-1 Tables 37 and 39 put
/// them — which is not the order the prose lists them in, and not the same for both kinds.
///
/// `Resv` is the **third** component of an unbuffered block, not a trailing one, and the
/// buffered block's `SqNum` is sixteen bits where the unbuffered one's is eight 🌐
/// (libiec61850 `reporting.c`). A client that reads the whole block positionally depends on
/// every one of these.
pub fn rcb_components(buffered: bool, edition: Edition) -> Vec<(&'static str, BType)> {
    let mut out: Vec<(&'static str, BType)> = alloc::vec![("RptID", BType::VisString129), ("RptEna", BType::Boolean)];
    if !buffered {
        out.push(("Resv", BType::Boolean));
    }
    out.extend([
        ("DatSet", BType::VisString129),
        ("ConfRev", BType::Int32U),
        ("OptFlds", BType::OptFlds),
        ("BufTm", BType::Int32U),
        ("SqNum", if buffered { BType::Int16U } else { BType::Int8U }),
        ("TrgOps", BType::TrgOps),
        ("IntgPd", BType::Int32U),
        ("GI", BType::Boolean),
    ]);
    if buffered {
        out.extend([("PurgeBuf", BType::Boolean), ("EntryID", BType::EntryID), ("TimeOfEntry", BType::EntryTime)]);
        // `ResvTms` arrived with Edition 2. An Ed1 server that publishes it claims a
        // reservation service it does not have, and a client reading the block positionally
        // then reads everything after it at the wrong offset.
        if edition.has_rcb_reservation() {
            out.push(("ResvTms", BType::Int16));
        }
    }
    if edition.has_rcb_reservation() {
        out.push(("Owner", BType::Octet64));
    }
    out
}

/// The components of a log control block (IEC 61850-7-2 §17).
pub fn lcb_components() -> Vec<(&'static str, BType)> {
    alloc::vec![
        ("LogEna", BType::Boolean),
        ("LogRef", BType::VisString129),
        ("DatSet", BType::VisString129),
        ("OldEntrTm", BType::EntryTime),
        ("NewEntrTm", BType::EntryTime),
        ("OldEnt", BType::EntryID),
        ("NewEnt", BType::EntryID),
        ("TrgOps", BType::TrgOps),
        ("IntgPd", BType::Int32U),
    ]
}

/// The components of the setting group control block (IEC 61850-7-2 §11).
pub fn sgcb_components() -> Vec<(&'static str, BType)> {
    alloc::vec![
        ("NumOfSG", BType::Int8U),
        ("ActSG", BType::Int8U),
        ("EditSG", BType::Int8U),
        ("CnfEdit", BType::Boolean),
        ("LActTm", BType::EntryTime),
        ("ResvTms", BType::Int16U),
    ]
}

/// The components of a GOOSE control block (IEC 61850-8-1 Table 32).
fn gocb_components() -> Vec<(&'static str, BType)> {
    alloc::vec![
        ("GoEna", BType::Boolean),
        ("GoID", BType::VisString129),
        ("DatSet", BType::VisString129),
        ("ConfRev", BType::Int32U),
        ("NdsCom", BType::Boolean),
    ]
}

/// The components of a sampled-value control block (IEC 61850-8-1 Table 35).
fn msvcb_components() -> Vec<(&'static str, BType)> {
    alloc::vec![
        ("SvEna", BType::Boolean),
        ("MsvID", BType::VisString129),
        ("DatSet", BType::VisString129),
        ("ConfRev", BType::Int32U),
        ("SmpRate", BType::Int16U),
        ("SmpMod", BType::Int8U),
        ("NoASDU", BType::Int16U),
    ]
}

fn rcb_defaults(rcb: &ReportControl, base: &str, data_set: Option<&str>, edition: Edition) -> Vec<(&'static str, Value)> {
    let mut out: Vec<(&'static str, Value)> = alloc::vec![
        // A block with no engineered `rptID` reports under its own reference, which is what
        // IEC 61850-7-2 §17.2.2 says the default is.
        ("RptID", Value::VisibleString(rcb.rpt_id.clone().unwrap_or_else(|| String::from(base)))),
        ("RptEna", Value::Boolean(false)),
        ("DatSet", Value::VisibleString(String::from(data_set.unwrap_or("")))),
        ("ConfRev", Value::Unsigned(u64::from(rcb.conf_rev))),
        // The two flags an unbuffered block cannot honour are cleared here rather than at
        // report time as well: a client that *reads* `OptFlds` should see what the block will
        // actually send. SCL's `bufOvfl` defaults to true, so this is the common case, not a
        // corner one.
        ("OptFlds", if rcb.buffered { rcb.opt_flds.to_value() } else { rcb.opt_flds.with_buffer_overflow(false).with_entry_id(false).to_value() }),
        ("BufTm", Value::Unsigned(u64::from(rcb.buf_time_ms))),
        ("SqNum", Value::Unsigned(0)),
        ("TrgOps", rcb.trg_ops.to_value()),
        ("IntgPd", Value::Unsigned(u64::from(rcb.intg_pd_ms))),
        ("GI", Value::Boolean(false)),
    ];
    if edition.has_rcb_reservation() {
        out.push(("Owner", Value::OctetString(Vec::new())));
    }
    if rcb.buffered {
        out.extend([
            ("PurgeBuf", Value::Boolean(false)),
            ("EntryID", Value::OctetString(Vec::new())),
            ("TimeOfEntry", Value::BinaryTime(EntryTime::default().to_octets().to_vec())),
        ]);
        if edition.has_rcb_reservation() {
            out.push(("ResvTms", Value::Integer(0)));
        }
    } else {
        out.push(("Resv", Value::Boolean(false)));
    }
    out
}

fn lcb_defaults(lcb: &crate::model::LogControl, log: &str, ld: &crate::model::LogicalDevice, ln: &LogicalNode) -> Vec<(&'static str, Value)> {
    let data_set = lcb.dat_set.as_ref().map_or_else(String::new, |d| alloc::format!("{}/{}${d}", ld.name, ln.name));
    alloc::vec![
        ("LogEna", Value::Boolean(lcb.log_ena)),
        ("LogRef", Value::VisibleString(String::from(log))),
        ("DatSet", Value::VisibleString(data_set)),
        ("OldEntrTm", Value::BinaryTime(EntryTime::default().to_octets().to_vec())),
        ("NewEntrTm", Value::BinaryTime(EntryTime::default().to_octets().to_vec())),
        ("OldEnt", Value::OctetString(Vec::new())),
        ("NewEnt", Value::OctetString(Vec::new())),
        ("TrgOps", lcb.trg_ops.to_value()),
        ("IntgPd", Value::Unsigned(u64::from(lcb.intg_pd_ms))),
    ]
}

fn sgcb_defaults(sg: crate::model::SettingControl) -> Vec<(&'static str, Value)> {
    alloc::vec![
        ("NumOfSG", Value::Unsigned(u64::from(sg.num_of_sgs))),
        ("ActSG", Value::Unsigned(u64::from(sg.act_sg))),
        ("EditSG", Value::Unsigned(0)),
        ("CnfEdit", Value::Boolean(false)),
        ("LActTm", Value::BinaryTime(EntryTime::default().to_octets().to_vec())),
        ("ResvTms", Value::Unsigned(u64::from(sg.resv_tms.unwrap_or(0)))),
    ]
}

/// The control-block variables of one logical node, and the [`Block`] record for each.
fn control_blocks(ld_name: &str, ln: &LogicalNode, edition: Edition, found: &mut Vec<Block>) -> Vec<(Fc, Variable)> {
    let mut out = Vec::new();
    let mut add = |fc: Fc, name: String, kind: BlockKind, components: Vec<(&'static str, BType)>, data_set: Option<String>, out: &mut Vec<(Fc, Variable)>| {
        let children = components.into_iter().map(|(n, b)| Variable::leaf(n, Some(fc), b)).collect();
        found.push(Block {
            reference: alloc::format!("{ld_name}/{}${}${name}", ln.name, fc.as_str()),
            domain: String::from(ld_name),
            node: ln.name.clone(),
            name: name.clone(),
            kind,
            data_set,
        });
        out.push((fc, Variable { name, kind: VarKind::Structure, fc: Some(fc), children }));
    };

    for rcb in &ln.report_controls {
        let fc = rcb.fc();
        let kind = if rcb.buffered { BlockKind::Buffered } else { BlockKind::Unbuffered };
        let data_set = rcb.dat_set.as_ref().map(|d| alloc::format!("{ld_name}/{}${d}", ln.name));
        for name in rcb.instance_names() {
            add(fc, name, kind, rcb_components(rcb.buffered, edition), data_set.clone(), &mut out);
        }
    }
    for lcb in &ln.log_controls {
        let data_set = lcb.dat_set.as_ref().map(|d| alloc::format!("{ld_name}/{}${d}", ln.name));
        add(Fc::LG, lcb.name.clone(), BlockKind::Log, lcb_components(), data_set, &mut out);
    }
    for gcb in &ln.gse_controls {
        let data_set = gcb.dat_set.as_ref().map(|d| alloc::format!("{ld_name}/{}${d}", ln.name));
        add(Fc::GO, gcb.name.clone(), BlockKind::Goose, gocb_components(), data_set, &mut out);
    }
    for scb in &ln.smv_controls {
        let data_set = scb.dat_set.as_ref().map(|d| alloc::format!("{ld_name}/{}${d}", ln.name));
        add(Fc::MS, scb.name.clone(), BlockKind::SampledValue, msvcb_components(), data_set, &mut out);
    }
    if ln.setting_control.is_some() {
        add(Fc::SP, String::from("SGCB"), BlockKind::SettingGroup, sgcb_components(), None, &mut out);
    }
    out
}
