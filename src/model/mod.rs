//! The IED model descriptor: what an SCL file says about an IED, in the shape the
//! server, the publishers and the subscribers consume.
//!
//! It is built by [`crate::scl`] from an ICD, CID or SCD file and answers the questions a
//! publisher asks — what is the GOOSE control block `IED1LD0/LLN0.gcbTrip`, which data set
//! does it send, to which multicast address — and the ones a subscriber asks, through the
//! [`ExtRef`] bindings an `LN/Inputs` declares.
//!
//! [`IedModel::goose_publisher_config`] and [`IedModel::sv_publisher_config`] turn a control
//! block into a ready configuration, so an address is written once, in the engineering file,
//! and never a second time in code.

use alloc::string::String;
use alloc::vec::Vec;

use crate::common::{Error, Fc, MacAddr, ObjectReference, OptFlds, Result, TrgOps};

/// Basic type of a data attribute (SCL `bType`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum BType {
    Boolean,
    Int8,
    Int16,
    Int24,
    Int32,
    Int64,
    Int8U,
    Int16U,
    Int24U,
    Int32U,
    Float32,
    Float64,
    Enum,
    Dbpos,
    Tcmd,
    Quality,
    Timestamp,
    VisString32,
    VisString64,
    VisString65,
    VisString129,
    VisString255,
    Octet64,
    Unicode255,
    Struct,
    EntryTime,
    Check,
    ObjRef,
    Currency,
    PhyComAddr,
    EntryID,
    TrgOps,
    OptFlds,
    SvOptFlds,
    LogOptFlds,
    Octet6,
    Octet16,
    /// A `bType` this crate does not know; kept verbatim.
    Other(String),
}

impl BType {
    /// From the SCL `bType` attribute.
    pub fn parse(s: &str) -> BType {
        match s {
            "BOOLEAN" => BType::Boolean,
            "INT8" => BType::Int8,
            "INT16" => BType::Int16,
            "INT24" => BType::Int24,
            "INT32" => BType::Int32,
            "INT64" => BType::Int64,
            "INT8U" => BType::Int8U,
            "INT16U" => BType::Int16U,
            "INT24U" => BType::Int24U,
            "INT32U" => BType::Int32U,
            "FLOAT32" => BType::Float32,
            "FLOAT64" => BType::Float64,
            "Enum" => BType::Enum,
            "Dbpos" => BType::Dbpos,
            "Tcmd" => BType::Tcmd,
            "Quality" => BType::Quality,
            "Timestamp" => BType::Timestamp,
            "VisString32" => BType::VisString32,
            "VisString64" => BType::VisString64,
            "VisString65" => BType::VisString65,
            "VisString129" => BType::VisString129,
            "VisString255" => BType::VisString255,
            "Octet64" => BType::Octet64,
            "Unicode255" => BType::Unicode255,
            "Struct" => BType::Struct,
            "EntryTime" => BType::EntryTime,
            "Check" => BType::Check,
            "ObjRef" => BType::ObjRef,
            "Currency" => BType::Currency,
            "PhyComAddr" => BType::PhyComAddr,
            "EntryID" => BType::EntryID,
            "TrgOps" => BType::TrgOps,
            "OptFlds" => BType::OptFlds,
            "SvOptFlds" => BType::SvOptFlds,
            // Edition 2.1 additions to the SCL `bType` list ✅ (`SCL_Enums.xsd`). Without
            // them a file that uses one gets `BType::Other`, which the server reads as a
            // structure — an octet string modelled as a structure with no components.
            "LogOptFlds" => BType::LogOptFlds,
            "Octet6" => BType::Octet6,
            "Octet16" => BType::Octet16,
            other => BType::Other(String::from(other)),
        }
    }

    /// Width in octets of this type inside a sampled-value sample block, or `None` for a
    /// type whose width is not fixed.
    ///
    /// IEC 61850-9-2 sends the data-set members as fixed-width values back to back rather
    /// than as tagged `Data`, which is what makes an ASDU a constant size and a merging
    /// unit's frame a template. `Quality` is the 4-octet word 9-2 uses, not the 13-bit
    /// bit string of the MMS mapping.
    pub const fn sv_width(&self) -> Option<usize> {
        Some(match self {
            BType::Boolean | BType::Int8 | BType::Int8U => 1,
            BType::Int16 | BType::Int16U => 2,
            BType::Int24 | BType::Int24U => 3,
            BType::Int32 | BType::Int32U | BType::Float32 | BType::Quality | BType::Enum => 4,
            BType::Int64 | BType::Float64 | BType::Timestamp => 8,
            // `EntryTime` is deliberately absent. It is ISO 9506 `BinaryTime` — six octets,
            // not the eight of a `Timestamp` — and no capture or public text says how a
            // sampled-value publisher lays it out. Claiming a width here would shift every
            // channel after it in the sample block, silently, so a data set that contains one
            // has no layout rather than a wrong one.
            _ => return None,
        })
    }
}

#[cfg(feature = "sv")]
impl BType {
    /// How this type appears inside a sampled-value sample block, or `None` for a type
    /// whose width is not fixed and which therefore cannot be in one.
    ///
    /// The same table as [`BType::sv_width`], which is what keeps the layout and the
    /// summed ASDU length from ever disagreeing.
    pub const fn sv_channel(&self) -> Option<crate::proto::sv::ChannelType> {
        use crate::proto::sv::ChannelType as C;
        Some(match self {
            BType::Boolean => C::Boolean,
            BType::Int8 => C::Int(1),
            BType::Int16 => C::Int(2),
            BType::Int24 => C::Int(3),
            BType::Int32 => C::Int(4),
            BType::Int64 => C::Int(8),
            BType::Int8U => C::Unsigned(1),
            BType::Int16U => C::Unsigned(2),
            BType::Int24U => C::Unsigned(3),
            BType::Int32U => C::Unsigned(4),
            BType::Float32 => C::Float32,
            BType::Float64 => C::Float64,
            BType::Quality => C::Quality,
            BType::Timestamp => C::Timestamp,
            BType::Enum => C::Enum,
            _ => return None,
        })
    }
}

/// The service an `ExtRef` binds to (SCL `serviceType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServiceType {
    /// GOOSE.
    Goose,
    /// Sampled values.
    Smv,
    /// Reporting.
    Report,
    /// Polling (client read).
    Poll,
}

impl ServiceType {
    /// From the SCL token.
    pub fn parse(s: &str) -> Option<ServiceType> {
        Some(match s {
            "GOOSE" => ServiceType::Goose,
            "SMV" => ServiceType::Smv,
            "Report" => ServiceType::Report,
            "Poll" => ServiceType::Poll,
            _ => return None,
        })
    }
}

/// One binding in an `LN/Inputs`: an input of this IED wired to a data attribute published
/// by another one.
///
/// This is what makes a subscriber configurable from the engineering file alone — the
/// source control block named here carries the multicast address, the APPID and the
/// `confRev` a subscriber has to match.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtRef {
    /// `iedName` of the publisher.
    pub ied_name: Option<String>,
    /// `ldInst` of the published attribute.
    pub ld_inst: Option<String>,
    /// `prefix` of the publishing logical node.
    pub prefix: String,
    /// `lnClass` of the publishing logical node.
    pub ln_class: Option<String>,
    /// `lnInst` of the publishing logical node.
    pub ln_inst: String,
    /// `doName`.
    pub do_name: Option<String>,
    /// `daName`.
    pub da_name: Option<String>,
    /// `serviceType`.
    pub service_type: Option<ServiceType>,
    /// `srcLDInst` — the logical device holding the source control block; defaults to
    /// `ldInst`.
    pub src_ld_inst: Option<String>,
    /// `srcPrefix`.
    pub src_prefix: String,
    /// `srcLNClass` — defaults to `LLN0`, where control blocks live.
    pub src_ln_class: Option<String>,
    /// `srcLNInst`.
    pub src_ln_inst: String,
    /// `srcCBName` — the `GSEControl` or `SampledValueControl` that publishes it.
    pub src_cb_name: Option<String>,
    /// `intAddr` — the vendor-internal address this input is wired to.
    pub int_addr: Option<String>,
}

impl ExtRef {
    /// The logical device instance holding the source control block.
    pub fn source_ld_inst(&self) -> Option<&str> {
        self.src_ld_inst.as_deref().or(self.ld_inst.as_deref())
    }

    /// The logical node holding the source control block. Control blocks live in `LLN0`
    /// unless the file says otherwise.
    pub fn source_ln_name(&self) -> String {
        match self.src_ln_class.as_deref() {
            None | Some("LLN0") => String::from("LLN0"),
            Some(class) => {
                let mut s = String::from(&self.src_prefix);
                s.push_str(class);
                s.push_str(&self.src_ln_inst);
                s
            }
        }
    }
}

/// A data attribute (DA, BDA) with its functional constraint and type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataAttribute {
    /// Name.
    pub name: String,
    /// Functional constraint (inherited by sub-attributes of a `Struct`).
    pub fc: Fc,
    /// Basic type.
    pub btype: BType,
    /// The `type` attribute (enum or `DAType` id), if any.
    pub type_id: Option<String>,
    /// Sub-attributes when `btype` is `Struct`.
    pub children: Vec<DataAttribute>,
    /// Initial value from the type template (`Val`), if any.
    pub value: Option<String>,
    /// Per-setting-group values (`Val sGroup="n"`), when the attribute is a setting.
    ///
    /// A setting under `SG`/`SE` has one engineered value **per group**, and which group is
    /// active is a runtime question. A model that kept only one of them could not tell a
    /// server what group 2 is set to, which is the whole point of having groups.
    pub group_values: Vec<(u32, String)>,
    /// `count` — the number of elements when this attribute is an **array**.
    ///
    /// SCL's `count` is a union of an unsigned integer and an attribute *name* ✅
    /// (`tDACount`, `SCL_Enums.xsd`): a file may say `count="16"` or point at a sibling
    /// holding the number, and the loader resolves both to a number here. `None` is a plain
    /// scalar, which is nearly everything; `Some(n)` makes this an MMS `array [1]` of `n`
    /// elements and every reference below it needs an index to reach a value.
    pub count: Option<u32>,
}

/// A data object (DO, SDO).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataObject {
    /// Name.
    pub name: String,
    /// Common data class (`cdc`) of its type.
    pub cdc: String,
    /// The `DOType` id.
    pub type_id: String,
    /// Attributes.
    pub attributes: Vec<DataAttribute>,
    /// Sub data objects.
    pub sub_objects: Vec<DataObject>,
    /// `count` on the `SDO` that named this one — the number of elements when it is an
    /// **array** of sub data objects ✅ (`tSDOCount`). `None` for the ordinary case, and
    /// always `None` for a top-level `DO`, which the schema gives no `count`.
    pub count: Option<u32>,
}

/// One member of a data set (SCL `FCDA`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fcda {
    /// `ldInst`.
    pub ld_inst: String,
    /// `prefix`.
    pub prefix: String,
    /// `lnClass`.
    pub ln_class: String,
    /// `lnInst`.
    pub ln_inst: String,
    /// `doName` (may contain dots for SDOs).
    pub do_name: String,
    /// `daName`, if the member is an attribute.
    pub da_name: Option<String>,
    /// `fc`.
    pub fc: Fc,
    /// `ix` — the array index this member selects ✅ (`tFCDA`, `SCL_IED.xsd`).
    ///
    /// A data set may name **one element** of an array rather than the whole of it, which is
    /// what the attribute is for. On the wire it becomes an `alternateAccess`, and the index
    /// applies to the last component of `da_name` that is an array.
    pub ix: Option<u32>,
}

impl Fcda {
    /// The logical node name `prefix + lnClass + lnInst`.
    pub fn ln_name(&self) -> String {
        let mut s = String::with_capacity(self.prefix.len() + self.ln_class.len() + self.ln_inst.len());
        s.push_str(&self.prefix);
        s.push_str(&self.ln_class);
        s.push_str(&self.ln_inst);
        s
    }

    /// The signal this member names, as `ldInst/LNName.DO.DA` — short enough to print in a
    /// channel list and still unambiguous when a data set gathers members from more than
    /// one logical device.
    pub fn signal(&self) -> String {
        let mut s = String::new();
        if !self.ld_inst.is_empty() {
            s.push_str(&self.ld_inst);
            s.push('/');
        }
        s.push_str(&self.ln_name());
        s.push('.');
        s.push_str(&self.do_name);
        if let Some(da) = &self.da_name {
            s.push('.');
            s.push_str(da);
        }
        s
    }

    /// The MMS-form object reference `LD/LN$FC$DO$DA`.
    ///
    /// `ld_name` is the logical device the reference should name. A member that carries its
    /// own `ldInst` may belong to a *different* logical device of the same IED, and only the
    /// model can turn that instance into a name — [`IedModel::fcda_reference`] does the
    /// resolution and should be preferred wherever a model is to hand.
    pub fn mms_reference(&self, ld_name: &str) -> String {
        let mut s = String::from(ld_name);
        s.push('/');
        s.push_str(&self.ln_name());
        s.push('$');
        s.push_str(self.fc.as_str());
        for part in self.do_name.split('.') {
            s.push('$');
            s.push_str(part);
        }
        if let Some(da) = &self.da_name {
            for part in da.split('.') {
                s.push('$');
                s.push_str(part);
            }
        }
        s
    }
}

/// The name of a reference component, without any array index it carries.
fn named(part: &str) -> &str {
    crate::common::split_index(part).0
}

/// One component of a data-set member, as the model sees it.
///
/// What [`IedModel::fcda_walk`] yields, and what the two questions asked of a member — does it
/// resolve, and where does its `ix` belong — are both answered from.
struct FcdaStep {
    /// The MMS reference up to and including this component.
    reference: String,
    /// Its name, without any index.
    name: String,
    /// The array index written in the name, if the file wrote one there.
    index: Option<u32>,
    /// The number of elements its type declares, when it is an array.
    count: Option<u32>,
}

/// Where a walk of a data-set member currently is: a data object, or an attribute under one.
enum FcdaNode<'m> {
    Object(&'m DataObject),
    Attribute(&'m DataAttribute),
}

/// A data set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataSet {
    /// Name.
    pub name: String,
    /// Members.
    pub members: Vec<Fcda>,
}

/// The link-layer address of a GOOSE control block (SCL `Communication/…/GSE`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GseAddress {
    /// `MAC-Address`.
    pub mac: MacAddr,
    /// `APPID`.
    pub appid: u16,
    /// `VLAN-ID` (0 if absent).
    pub vlan_id: u16,
    /// `VLAN-PRIORITY` (4 if absent).
    pub vlan_priority: u8,
    /// `MinTime` in ms, if given.
    pub min_time_ms: Option<u32>,
    /// `MaxTime` in ms, if given.
    pub max_time_ms: Option<u32>,
}

/// A GOOSE control block (SCL `GSEControl`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GseControl {
    /// Name.
    pub name: String,
    /// `datSet` (a data-set name in the same LN).
    pub dat_set: Option<String>,
    /// `confRev`.
    pub conf_rev: u32,
    /// `appID` — the `goID`.
    pub go_id: Option<String>,
    /// `fixedOffs`.
    pub fixed_offs: bool,
    /// Address, if the Communication section configures one.
    pub address: Option<GseAddress>,
}

/// The link-layer address of an SV control block (SCL `Communication/…/SMV`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmvAddress {
    /// `MAC-Address`.
    pub mac: MacAddr,
    /// `APPID`.
    pub appid: u16,
    /// `VLAN-ID`.
    pub vlan_id: u16,
    /// `VLAN-PRIORITY`.
    pub vlan_priority: u8,
}

/// A sampled-value control block (SCL `SampledValueControl`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmvControl {
    /// Name.
    pub name: String,
    /// `smvID`.
    pub smv_id: String,
    /// `datSet`.
    pub dat_set: Option<String>,
    /// `confRev`.
    pub conf_rev: u32,
    /// `smpRate`.
    pub smp_rate: u32,
    /// `nofASDU`.
    pub nof_asdu: u32,
    /// `smpMod` (`SmpPerPeriod`, `SmpPerSec`, `SecPerSmp`).
    pub smp_mod: String,
    /// `multicast`.
    pub multicast: bool,
    /// Address.
    pub address: Option<SmvAddress>,
}

impl SmvControl {
    /// Samples per second, which is what `smpCnt` wraps at and what a subscriber needs for
    /// continuity checking — or `None` when the control block does not describe a whole
    /// number of samples per second.
    ///
    /// `smpRate` alone is ambiguous: with `smpMod` = `SmpPerPeriod` (the default, and what
    /// 9-2LE uses) it counts samples per *nominal cycle*, so the system frequency has to
    /// come from outside the file — SCL does not record it.
    ///
    /// `SecPerSmp` counts **seconds per sample**, so anything above one second per sample
    /// is a sub-hertz stream: it has no samples-per-second modulus at all, and saying so is
    /// the only honest answer. (Computing `1 / smpRate` in integers, which is the obvious
    /// mistake, silently yields zero and makes every sample look like a discontinuity.)
    pub fn samples_per_second(&self, nominal_hz: u32) -> Option<u32> {
        match self.smp_mod.as_str() {
            "SmpPerSec" => (self.smp_rate != 0).then_some(self.smp_rate),
            "SecPerSmp" => (self.smp_rate == 1).then_some(1),
            _ => self.smp_rate.checked_mul(nominal_hz).filter(|n| *n != 0),
        }
    }
}

/// A report control block (SCL `ReportControl`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportControl {
    /// Name.
    pub name: String,
    /// `datSet`.
    pub dat_set: Option<String>,
    /// `confRev`.
    pub conf_rev: u32,
    /// `buffered`.
    pub buffered: bool,
    /// `rptID`.
    pub rpt_id: Option<String>,
    /// `bufTime` in ms.
    pub buf_time_ms: u32,
    /// `intgPd` in ms.
    pub intg_pd_ms: u32,
    /// `RptEnabled/@max` — number of instances.
    pub max_instances: u32,
    /// `indexed` — whether the instances are named `name01`, `name02`, … rather than `name`.
    /// Defaults to **true** in the schema, which is why an unindexed block has to say so.
    pub indexed: bool,
    /// `TrgOps` — what the block reports on, as engineered.
    pub trg_ops: TrgOps,
    /// `OptFields` — which fields its reports carry, as engineered.
    pub opt_flds: OptFlds,
}

impl ReportControl {
    /// The MMS names of this block's instances, in order.
    ///
    /// An `indexed` block with `RptEnabled max="3"` is three separate control blocks on the
    /// wire — `urcb01`, `urcb02`, `urcb03` — so that three clients can each enable one. An
    /// unindexed block is one, under its own name. Getting this wrong is a client that
    /// enables a block another client is already using.
    pub fn instance_names(&self) -> Vec<String> {
        if !self.indexed {
            return alloc::vec![self.name.clone()];
        }
        (1..=self.max_instances.max(1)).map(|n| alloc::format!("{}{n:02}", self.name)).collect()
    }

    /// The functional constraint this block lives under: `BR` when buffered, `RP` when not.
    pub const fn fc(&self) -> Fc {
        if self.buffered { Fc::BR } else { Fc::RP }
    }
}

/// A log control block (SCL `LogControl`).
///
/// It says *what* gets written into a log and *which* log — the log itself is a separate
/// SCL element ([`Log`]) and a separate MMS object (a journal), which is the part that
/// surprises people: the control block is a named variable under `LG` and the log is not a
/// variable at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogControl {
    /// Name.
    pub name: String,
    /// `datSet`.
    pub dat_set: Option<String>,
    /// `logName` — the log this block writes into.
    pub log_name: String,
    /// `ldInst` of the log, when it is in another logical device.
    pub log_ld_inst: Option<String>,
    /// `logEna`.
    pub log_ena: bool,
    /// `reasonCode` — whether entries record why they were made.
    pub reason_code: bool,
    /// `bufTime` in ms.
    pub buf_time_ms: u32,
    /// `intgPd` in ms.
    pub intg_pd_ms: u32,
    /// `TrgOps`.
    pub trg_ops: TrgOps,
}

/// A log (SCL `Log`) — the journal entries are written into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    /// `name`; the unnamed default log is `""` and is addressed as `LLN0$General`.
    pub name: String,
}

/// The setting group control block (SCL `SettingControl`, on `LN0` only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettingControl {
    /// `numOfSGs` — how many groups the device has.
    pub num_of_sgs: u32,
    /// `actSG` — which one is in force at start-up.
    pub act_sg: u32,
    /// `resvTms` — how long an edit reservation lasts, in seconds.
    pub resv_tms: Option<u16>,
}

/// A logical node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalNode {
    /// `prefix + lnClass + inst` (`LLN0` for LN0).
    pub name: String,
    /// `lnClass`.
    pub class: String,
    /// `lnType`.
    pub ln_type: String,
    /// Data objects.
    pub data_objects: Vec<DataObject>,
    /// Data sets.
    pub data_sets: Vec<DataSet>,
    /// GOOSE control blocks.
    pub gse_controls: Vec<GseControl>,
    /// SV control blocks.
    pub smv_controls: Vec<SmvControl>,
    /// Report control blocks.
    pub report_controls: Vec<ReportControl>,
    /// Log control blocks.
    pub log_controls: Vec<LogControl>,
    /// Logs this logical node hosts (`LN0` only in practice).
    pub logs: Vec<Log>,
    /// The setting group control block (`LN0` only).
    pub setting_control: Option<SettingControl>,
    /// `Inputs/ExtRef` — what this logical node subscribes to.
    pub inputs: Vec<ExtRef>,
}

/// The OSI addressing of an access point (SCL `Communication/ConnectedAP/Address`).
///
/// This is what a client needs to open an association and what a server needs to accept one:
/// the three selectors go into the COTP connection request, the session CONNECT and the
/// presentation CP, and the AP-title and AE-qualifier into the ACSE AARQ. All of them are
/// engineered once, in the SCD.
///
/// Selectors are the octets the file's hex string denotes; the AP-title is kept as its arcs
/// because that is how SCL writes it (`1,3,9999,23`), and
/// [`crate::proto::osi::oid::encode`] turns them into the encoded identifier ACSE wants.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OsiAddress {
    /// `IP`, for the TCP connection itself.
    pub ip: Option<String>,
    /// `OSI-TSEL` — the COTP transport selector.
    pub t_sel: Option<Vec<u8>>,
    /// `OSI-SSEL` — the session selector.
    pub s_sel: Option<Vec<u8>>,
    /// `OSI-PSEL` — the presentation selector.
    pub p_sel: Option<Vec<u8>>,
    /// `OSI-AP-Title`, as its arcs.
    pub ap_title: Option<Vec<u32>>,
    /// `OSI-AE-Qualifier`.
    pub ae_qualifier: Option<i64>,
}

impl OsiAddress {
    /// True when the file gave this access point nothing to address it by.
    pub fn is_empty(&self) -> bool {
        *self == OsiAddress::default()
    }
}

/// An access point: what a client connects *to*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessPoint {
    /// `name`, which is what `ConnectedAP/@apName` matches.
    pub name: String,
    /// Its OSI addressing, if the `Communication` section gives it one.
    pub address: Option<OsiAddress>,
}

/// An SCL `EnumType`: the symbols an enumerated data attribute may take, and their ordinals.
///
/// This is not decoration. An SCL `Val` for an enumerated attribute is the **symbol** —
/// `direct-with-normal-security`, `on`, `remote-control` — and the wire carries the ordinal.
/// A model that keeps only the symbol cannot tell a server what `ctlModel` is, and a model
/// that parses the symbol as a number gets zero for every one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumType {
    /// The `id` an attribute's `type` refers to.
    pub id: String,
    /// `(ord, symbol)` pairs, in document order.
    pub values: Vec<(i64, String)>,
}

impl EnumType {
    /// The ordinal of a symbol.
    pub fn ord(&self, symbol: &str) -> Option<i64> {
        self.values.iter().find(|(_, s)| s == symbol).map(|(o, _)| *o)
    }

    /// The symbol of an ordinal.
    pub fn symbol(&self, ord: i64) -> Option<&str> {
        self.values.iter().find(|(o, _)| *o == ord).map(|(_, s)| s.as_str())
    }
}

/// A logical device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalDevice {
    /// `inst`.
    pub inst: String,
    /// The name on the wire: `ldName` if given, else `IEDName + inst`.
    pub name: String,
    /// Logical nodes (LN0 first).
    pub logical_nodes: Vec<LogicalNode>,
}

/// A stable code for something the SCL loader found wrong but could work around.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiagnosticCode {
    /// An `LN`/`LN0` references an `LNodeType` that does not exist; loaded without data objects.
    MissingLNodeType,
    /// A `DO`/`SDO` references a `DOType` that does not exist; skipped.
    MissingDOType,
    /// A `Struct` attribute references a `DAType` that does not exist; loaded without children.
    MissingDAType,
    /// A `DA` has no `fc` and none to inherit; skipped.
    MissingFc,
    /// A `DA`/`BDA` has an unknown `fc` value; skipped.
    UnknownFc,
    /// An `FCDA` has a missing or unknown `fc`; skipped.
    BadFcda,
    /// A `GSE`/`SMV` address in the Communication section is incomplete or unparsable; ignored.
    BadAddress,
    /// Nesting of `SDO`/`Struct` types deeper than the loader follows; truncated.
    NestingTooDeep,
    /// A required attribute (`name`, `type`, `inst`, `lnType`) is missing; the element is skipped.
    MissingAttribute,
    /// A `count` names a sibling attribute that does not exist or holds no number; the
    /// attribute is loaded as a **scalar**. SCL types `count` as a union of an unsigned
    /// integer and an attribute name ✅, and only the first form can be resolved without one.
    UnresolvedArrayCount,
    /// A `count` is larger than the loader expands ([`crate::scl::MAX_ARRAY`]); the attribute
    /// is loaded as a **scalar**. The schema allows any `xs:unsignedInt`, and a server turns
    /// each element into its own set of values — so the file would otherwise decide how much
    /// memory the process takes.
    ArrayTooLarge,
}

/// Something the SCL loader found wrong but could work around.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// The stable code.
    pub code: DiagnosticCode,
    /// Where, as an SCL path such as `IED2/LD0/THARDE1` or `Communication/GSE LD0.gcb1`.
    pub at: String,
    /// What, in words.
    pub message: String,
}

impl core::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?} at {}: {}", self.code, self.at, self.message)
    }
}

/// A subscription supervision logical node, and the control block it was engineered to watch.
///
/// IEC 61850-7-4 gives every GOOSE subscription an `LGOS` and every sampled-value
/// subscription an `LSVS` (TISSUE 1396/1401 🌐), and the *binding* between the two is in the
/// file: the logical node's `GoCBRef`/`SvCBRef` setting names the publisher's control block.
/// Reading it here is what lets an application wire a subscriber to its supervision node
/// without typing either name a second time — the same rule the rest of the configuration
/// follows (D17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Supervision {
    /// The logical node, as a reference: `IED2LD0/LGOS1`.
    pub node: String,
    /// `LGOS` for a GOOSE subscription, `LSVS` for a sampled-value one.
    pub ln_class: String,
    /// The control block it supervises, as the file engineered it — `IED1LD0/LLN0$GO$gcbTrip`.
    /// `None` when the file declares the logical node and does not say what it watches, which
    /// is a commissioning finding rather than an error.
    pub control_block: Option<String>,
}

impl Supervision {
    /// True for a GOOSE subscription supervision node.
    pub fn is_goose(&self) -> bool {
        self.ln_class == "LGOS"
    }

    /// Whether this node watches `control_block`, however either of them is spelt.
    ///
    /// A control block is named `IED1LD0/LLN0$GO$gcbTrip` in the MMS form a `gocbRef` carries
    /// and `IED1LD0/LLN0.gcbTrip` in the dotted form SCL tooling prints, and files use both.
    /// Comparing the strings would make the binding depend on which spelling an engineer's
    /// tool happened to write, so what is compared is the logical device, the logical node
    /// and the block's own name.
    pub fn watches(&self, control_block: &str) -> bool {
        self.control_block.as_deref().is_some_and(|mine| control_block_key(mine) == control_block_key(control_block))
    }
}

/// A control-block reference as `(logical device, logical node, block name)`, whichever
/// spelling it arrived in. An unparsable reference is its own trimmed text, so two of those
/// still compare equal to each other and to nothing else.
fn control_block_key(reference: &str) -> (String, String, String) {
    match ObjectReference::parse(reference) {
        // The functional constraint (`GO`, `MS`) is *where* the block lives, not part of its
        // name, and the dotted spelling does not carry one — so it is dropped from the key.
        Ok(r) => (String::from(r.ld), String::from(r.ln), r.path().last().unwrap_or_default().into()),
        Err(_) => (String::new(), String::new(), String::from(reference.trim())),
    }
}

/// The model of one IED.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IedModel {
    /// IED name.
    pub name: String,
    /// `manufacturer`, `type`, `configVersion` as given.
    pub manufacturer: Option<String>,
    /// `type`.
    pub ied_type: Option<String>,
    /// `configVersion`.
    pub config_version: Option<String>,
    /// The SCL schema version the file declared (e.g. `2007B4`).
    pub scl_version: String,
    /// Access points, with the OSI addressing a client associates over.
    pub access_points: Vec<AccessPoint>,
    /// Logical devices.
    pub logical_devices: Vec<LogicalDevice>,
    /// The enumerated types the document defines, so that a symbolic `Val` can be resolved
    /// to the ordinal the wire carries.
    pub enum_types: Vec<EnumType>,
    /// What the loader had to work around (empty for a fully resolvable file).
    pub diagnostics: Vec<Diagnostic>,
}

impl IedModel {
    /// The IEC 61850 edition this file declares, from [`IedModel::scl_version`].
    ///
    /// Edition is a property of the *server*, never of an association, and this is where a
    /// server gets it from without being told twice
    /// ([`Edition::from_scl_version`](crate::common::Edition::from_scl_version)).
    pub fn edition(&self) -> crate::common::Edition {
        crate::common::Edition::from_scl_version(&self.scl_version)
    }

    /// The enumerated type with this `id`.
    pub fn enum_type(&self, id: &str) -> Option<&EnumType> {
        self.enum_types.iter().find(|e| e.id == id)
    }

    /// The ordinal a symbolic value denotes, for an attribute of this enumerated type.
    pub fn enum_ord(&self, type_id: Option<&str>, symbol: &str) -> Option<i64> {
        // A file may write the ordinal itself, and both spellings are in the field.
        if let Ok(n) = symbol.parse::<i64>() {
            return Some(n);
        }
        self.enum_type(type_id?)?.ord(symbol)
    }

    /// The OSI addressing of `name`, or of the only access point when `None` is passed.
    ///
    /// One access point is the normal case; an IED with several has one per network it sits
    /// on, and then the name is the one from `ConnectedAP/@apName`.
    pub fn osi_address(&self, name: Option<&str>) -> Option<&OsiAddress> {
        let ap = match name {
            Some(n) => self.access_points.iter().find(|a| a.name == n)?,
            None => match self.access_points.as_slice() {
                [only] => only,
                _ => return None,
            },
        };
        ap.address.as_ref()
    }

    /// Find a logical device by wire name (`IEDNameInst` or `ldName`).
    pub fn logical_device(&self, name: &str) -> Option<&LogicalDevice> {
        self.logical_devices.iter().find(|ld| ld.name == name)
    }

    /// Find a logical device by its SCL `inst`, which is how an `ExtRef` names it.
    pub fn logical_device_by_inst(&self, inst: &str) -> Option<&LogicalDevice> {
        self.logical_devices.iter().find(|ld| ld.inst == inst)
    }

    /// Resolve `LD/LN` of an object reference.
    pub fn logical_node(&self, r: &ObjectReference<'_>) -> Option<(&LogicalDevice, &LogicalNode)> {
        let ld = self.logical_device(r.ld)?;
        let ln = ld.logical_nodes.iter().find(|ln| ln.name == r.ln)?;
        Some((ld, ln))
    }

    /// Find a GOOSE control block by reference `LD/LN.name` or `LD/LN$GO$name`.
    pub fn gse_control(&self, reference: &str) -> Result<(&LogicalDevice, &LogicalNode, &GseControl)> {
        let r = ObjectReference::parse(reference)?;
        let (ld, ln) = self.logical_node(&r).ok_or(Error::NotFound("logical node"))?;
        let name = r.data_object().ok_or(Error::InvalidReference("control block name"))?;
        let gcb = ln.gse_controls.iter().find(|g| g.name == name).ok_or(Error::NotFound("GSEControl"))?;
        Ok((ld, ln, gcb))
    }

    /// Find an SV control block by reference.
    pub fn smv_control(&self, reference: &str) -> Result<(&LogicalDevice, &LogicalNode, &SmvControl)> {
        let r = ObjectReference::parse(reference)?;
        let (ld, ln) = self.logical_node(&r).ok_or(Error::NotFound("logical node"))?;
        let name = r.data_object().ok_or(Error::InvalidReference("control block name"))?;
        let cb = ln.smv_controls.iter().find(|g| g.name == name).ok_or(Error::NotFound("SampledValueControl"))?;
        Ok((ld, ln, cb))
    }

    /// Find a data set in a logical node.
    pub fn data_set<'m>(&'m self, ln: &'m LogicalNode, name: &str) -> Option<&'m DataSet> {
        ln.data_sets.iter().find(|d| d.name == name)
    }

    /// Resolve a data attribute by object reference (dotted or MMS form), following SDOs
    /// and `Struct` attributes. Returns the attribute and the effective FC.
    pub fn attribute(&self, r: &ObjectReference<'_>) -> Option<&DataAttribute> {
        let (_, ln) = self.logical_node(r)?;
        let mut parts = r.path();
        let do_name = parts.next()?;
        let mut dobj = ln.data_objects.iter().find(|d| d.name == do_name)?;
        let mut da: Option<&DataAttribute> = None;
        for part in parts {
            if let Some(a) = da {
                da = a.children.iter().find(|c| c.name == part);
                da?;
            } else if let Some(sdo) = dobj.sub_objects.iter().find(|s| s.name == part) {
                dobj = sdo;
            } else {
                da = dobj.attributes.iter().find(|a| a.name == part);
                da?;
            }
        }
        match (da, r.fc) {
            (Some(a), Some(fc)) if a.fc != fc => None,
            (found, _) => found,
        }
    }

    /// The `ctlModel` a controllable object is engineered with.
    ///
    /// This is the value a control sequence has to know before it sends anything: an object
    /// engineered for select-before-operate answers an unselected `Oper` with
    /// `AddCause::ObjectNotSelected` and no state change. It lives in the SCD as a `DAI`
    /// instance value under the object's `DOI`, falling back to the `DOType`'s own `Val`, so
    /// reading it here costs no round trip at all.
    ///
    /// `reference` names the data object — `IED1LD0/CSWI1.Pos` — not one of its attributes.
    pub fn control_model(&self, reference: &str) -> Option<crate::common::ControlModel> {
        let r = ObjectReference::parse(reference).ok()?;
        let (_, ln) = self.logical_node(&r)?;
        let mut object = ln.data_objects.iter().find(|o| Some(o.name.as_str()) == r.data_object())?;
        // Walk any sub data objects the reference names, so `CSWI1.Pos` and a nested
        // `XSWI1.Pos.SubDo` both resolve.
        for part in r.path().skip(1) {
            match object.sub_objects.iter().find(|o| o.name == part) {
                Some(sub) => object = sub,
                None => break,
            }
        }
        let attribute = object.attributes.iter().find(|a| a.name == "ctlModel")?;
        let text = attribute.value.as_deref()?;
        // The document's own `EnumType` first — it is the authority for this file — and the
        // fixed IEC 61850-7-3 symbols as the fallback, for a file whose enumerated types are
        // referenced but not defined.
        self.enum_ord(attribute.type_id.as_deref(), text).and_then(crate::common::ControlModel::from_code).or_else(|| parse_ctl_model(text))
    }

    /// Build a [`crate::proto::goose::PublisherConfig`] for a GOOSE control block, with
    /// `src` as the source MAC. Fails if the block has no address.
    #[cfg(feature = "goose")]
    pub fn goose_publisher_config(&self, reference: &str, src: MacAddr) -> Result<crate::proto::goose::PublisherConfig> {
        use crate::proto::ethernet::{ETHERTYPE_GOOSE, FrameHeader, VlanTag};
        use crate::proto::goose::{PublisherConfig, Retransmission};
        let (ld, ln, gcb) = self.gse_control(reference)?;
        let addr = gcb.address.as_ref().ok_or(Error::NotFound("GSE address for control block"))?;
        let dat_set = gcb.dat_set.as_ref().ok_or(Error::NotFound("datSet of control block"))?;
        let mut gocb_ref = String::from(&ld.name);
        gocb_ref.push('/');
        gocb_ref.push_str(&ln.name);
        gocb_ref.push_str("$GO$");
        gocb_ref.push_str(&gcb.name);
        let mut ds = String::from(&ld.name);
        ds.push('/');
        ds.push_str(&ln.name);
        ds.push('$');
        ds.push_str(dat_set);
        let r = Retransmission::DEFAULT;
        Ok(PublisherConfig {
            header: FrameHeader {
                dst: addr.mac,
                src,
                vlan: Some(VlanTag { priority: addr.vlan_priority, dei: false, id: addr.vlan_id }),
                ethertype: ETHERTYPE_GOOSE,
                appid: addr.appid,
                reserved1: 0,
                reserved2: 0,
            },
            gocb_ref,
            dat_set: ds,
            go_id: gcb.go_id.clone(),
            conf_rev: gcb.conf_rev,
            retransmission: Retransmission {
                min_time_ms: addr.min_time_ms.unwrap_or(r.min_time_ms),
                max_time_ms: addr.max_time_ms.unwrap_or(r.max_time_ms),
                tal_factor: r.tal_factor,
            },
            simulation: false,
            nds_com: false,
        })
    }

    /// The MMS-form reference of a data-set member, with its logical device resolved.
    ///
    /// An `FCDA` carries an `ldInst`, and a data set may gather members from another logical
    /// device of the same IED. Naming them all after the device that *hosts the data set* is
    /// how a report's `DataRef` ends up pointing at a logical device the value is not in.
    pub fn fcda_reference(&self, ld_name: &str, fcda: &Fcda) -> String {
        let resolved = self.logical_device_by_inst(&fcda.ld_inst).map_or(ld_name, |ld| ld.name.as_str());
        let base = fcda.mms_reference(resolved);
        // `ix` selects **one element** of an array, and the attribute says only *which*
        // element — never which component is the array. Only the type does, so the index is
        // placed against the model rather than against the last name in the reference: a file
        // that writes `daName="phsAHar(9).cVal" ix="9"` and one that writes `daName="phsAHar.cVal"
        // ix="9"` mean the same member, and the second is the form the schema asks for ✅.
        match fcda.ix {
            Some(ix) if !base.contains('(') => self.place_index(ld_name, fcda, &base, ix).unwrap_or(base),
            _ => base,
        }
    }

    /// Put `ix` after the first component the model declares as an array.
    ///
    /// `None` when nothing on the path is one, in which case the reference is left alone and
    /// the member simply does not resolve — which is the truth, and what `ied scl validate`
    /// reports.
    fn place_index(&self, ld_name: &str, fcda: &Fcda, base: &str, ix: u32) -> Option<String> {
        let walk = self.fcda_walk(ld_name, fcda).ok()?;
        let step = walk.iter().find(|s| s.count.is_some())?;
        Some(alloc::format!("{}({ix}){}", step.reference, base.strip_prefix(step.reference.as_str())?))
    }

    /// Walk an `FCDA`'s components against the model.
    ///
    /// One walk for both questions asked of a data-set member — does it resolve, and where does
    /// its `ix` belong — because two walks are two chances to disagree about what `daName`
    /// means. And it means more than the schema says: `doName` is meant to carry the whole data
    /// object path and `daName` to start at the first attribute, but libiec61850's own tool
    /// writes a **sub data object** into `daName` 🌐, so each component is looked up as a sub
    /// object first and as an attribute second. That is D50's rule — the loader reads what the
    /// field writes, and the validator is where the finding goes.
    ///
    /// Yields one [`FcdaStep`] per component.
    fn fcda_walk(&self, ld_name: &str, fcda: &Fcda) -> core::result::Result<Vec<FcdaStep>, String> {
        let ld = self
            .logical_device_by_inst(&fcda.ld_inst)
            .or_else(|| self.logical_device(ld_name))
            .ok_or_else(|| alloc::format!("no logical device `{}`", fcda.ld_inst))?;
        let ln_name = fcda.ln_name();
        let ln = ld.logical_nodes.iter().find(|ln| ln.name == ln_name).ok_or_else(|| alloc::format!("no logical node `{ln_name}`"))?;

        let mut prefix = alloc::format!("{}/{}${}", ld.name, ln.name, fcda.fc.as_str());
        let mut here: Option<FcdaNode<'_>> = None;
        let mut out = Vec::new();
        let parts = fcda.do_name.split('.').chain(fcda.da_name.as_deref().unwrap_or("").split('.')).filter(|p| !p.is_empty());
        for part in parts {
            let (name, index) = crate::common::split_index(part);
            let next = match &here {
                None => ln.data_objects.iter().find(|d| d.name == name).map(FcdaNode::Object),
                Some(FcdaNode::Object(o)) => o
                    .sub_objects
                    .iter()
                    .find(|s| s.name == name)
                    .map(FcdaNode::Object)
                    .or_else(|| o.attributes.iter().find(|a| a.name == name).map(FcdaNode::Attribute)),
                Some(FcdaNode::Attribute(a)) => a.children.iter().find(|c| c.name == name).map(FcdaNode::Attribute),
            };
            let next = next.ok_or_else(|| alloc::format!("`{name}` is not declared here"))?;
            let count = match &next {
                FcdaNode::Object(o) => o.count,
                FcdaNode::Attribute(a) => a.count,
            };
            prefix.push('$');
            prefix.push_str(name);
            out.push(FcdaStep { reference: prefix.clone(), name: String::from(name), index, count });
            if let Some(i) = index {
                let _ = core::fmt::Write::write_fmt(&mut prefix, format_args!("({i})"));
            }
            here = Some(next);
        }
        Ok(out)
    }

    /// Whether an `FCDA` names something this IED actually has, and whether its array indices
    /// are inside their bounds.
    ///
    /// Not the same question as [`IedModel::fcda_attribute`], which asks for a **leaf
    /// attribute** and is what a sampled-value width needs: a data-set member may name a data
    /// object, a sub data object or one element of an array.
    ///
    /// `Err(reason)` says *why* it does not resolve, which is the difference between a misspelt
    /// member and one whose index is past the end of its array.
    pub fn fcda_resolves(&self, ld_name: &str, fcda: &Fcda) -> core::result::Result<(), String> {
        let walk = self.fcda_walk(ld_name, fcda)?;
        for FcdaStep { name, index, count, .. } in &walk {
            // The index has to belong to an array and be inside it. A file that indexes a
            // scalar, or that runs past the end, engineers a report member with no value —
            // and a report that silently drops one member shifts every inclusion bit after it.
            match (index, count) {
                (Some(i), Some(n)) if i >= n => return Err(alloc::format!("index {i} is past the end of `{name}`, which has {n} elements")),
                (Some(i), None) => return Err(alloc::format!("`{name}` is not an array, so `({i})` selects nothing")),
                _ => {}
            }
        }
        // `ix` without an index in the name is the schema's own form, and it needs an array
        // somewhere on the path for the index to be placed against.
        if let Some(ix) = fcda.ix {
            if !walk.iter().any(|s| s.index.is_some()) {
                match walk.iter().find(|s| s.count.is_some()) {
                    Some(FcdaStep { name, count: Some(n), .. }) if ix >= *n => {
                        return Err(alloc::format!("ix={ix} is past the end of `{name}`, which has {n} elements"));
                    }
                    Some(_) => {}
                    None => return Err(alloc::format!("ix={ix} but nothing on this path is an array")),
                }
            }
        }
        Ok(())
    }

    /// Resolve an `FCDA` of a data set to the data attribute it names, if it names a leaf.
    ///
    /// An `FCDA` carries its own `ldInst`, and a data set may perfectly well gather members
    /// from another logical device of the same IED — a breaker's data set referring to the
    /// disconnector bay next to it is ordinary engineering. `ld_name` is only the fallback
    /// for a file that leaves `ldInst` out.
    pub fn fcda_attribute(&self, ld_name: &str, fcda: &Fcda) -> Option<&DataAttribute> {
        let da = fcda.da_name.as_deref()?;
        let ld = self.logical_device_by_inst(&fcda.ld_inst).or_else(|| self.logical_device(ld_name))?;
        let ln_name = fcda.ln_name();
        let ln = ld.logical_nodes.iter().find(|ln| ln.name == ln_name)?;
        // Each first component is looked up before `find`, never inside its predicate: a
        // `next()` in there advances the iterator once per candidate it tries, so it matches
        // only when the thing it is looking for happens to be first.
        // A component may carry an array index — a file may write `daName="phsAHar(9).cVal"`
        // beside its `ix`, which is the same member spelt twice. The *name* is what resolves.
        let mut dos = fcda.do_name.split('.');
        let first_do = named(dos.next()?);
        let mut dobj = ln.data_objects.iter().find(|d| d.name == first_do)?;
        for part in dos {
            let part = named(part);
            dobj = dobj.sub_objects.iter().find(|s| s.name == part)?;
        }
        let mut das = da.split('.');
        let first_da = named(das.next()?);
        let mut attr = dobj.attributes.iter().find(|a| a.name == first_da)?;
        for part in das {
            let part = named(part);
            attr = attr.children.iter().find(|c| c.name == part)?;
        }
        Some(attr)
    }

    /// Octets of one sampled-value sample block for `data_set`, or `None` when a member
    /// does not resolve to a fixed-width leaf attribute.
    ///
    /// The 9-2LE `PhsMeas1` data set — four currents and four voltages, each `instMag.i`
    /// plus `q` — comes out as 64, which is what the guideline fixes it at; the sum is
    /// computed from the file rather than assumed, so a merging unit with a different data
    /// set works without a special case.
    pub fn sv_sample_len(&self, ld_name: &str, data_set: &DataSet) -> Option<usize> {
        let mut total = 0usize;
        for m in &data_set.members {
            total = total.checked_add(self.fcda_attribute(ld_name, m)?.btype.sv_width()?)?;
        }
        (total > 0).then_some(total)
    }

    /// The layout of one sampled-value sample block for `data_set`, or `None` when a member
    /// does not resolve to a fixed-width leaf attribute.
    ///
    /// This is what makes an arbitrary engineered data set decodable. IEC 61850-9-2 writes
    /// the members back to back with nothing on the wire to separate them, so a subscriber
    /// that has not been told the shape can only guess — which is why most implementations
    /// support 9-2LE's fixed four-current/four-voltage set and nothing else. The shape is in
    /// the SCL file, and this reads it out of there.
    #[cfg(feature = "sv")]
    pub fn sv_sample_layout(&self, ld_name: &str, data_set: &DataSet) -> Option<crate::proto::sv::SampleLayout> {
        let mut channels = Vec::with_capacity(data_set.members.len());
        for m in &data_set.members {
            channels.push((m.signal(), self.fcda_attribute(ld_name, m)?.btype.sv_channel()?));
        }
        let layout = crate::proto::sv::SampleLayout::new(channels);
        (!layout.is_empty()).then_some(layout)
    }

    /// Build a [`crate::proto::sv::PublisherConfig`] for a sampled-value control block.
    ///
    /// `nominal_hz` is the system frequency, which SCL does not record but `smpRate` needs
    /// when `smpMod` counts samples per period. The sample-block length comes from the
    /// control block's data set; a data set whose members are not fixed-width leaves is an
    /// error rather than a guess.
    #[cfg(feature = "sv")]
    pub fn sv_publisher_config(&self, reference: &str, src: MacAddr, nominal_hz: u32) -> Result<crate::proto::sv::PublisherConfig> {
        use crate::proto::ethernet::{ETHERTYPE_SV, FrameHeader, VlanTag};
        use crate::proto::sv::{PublisherConfig, SmpMod, SvProfile};
        let (ld, ln, cb) = self.smv_control(reference)?;
        let addr = cb.address.as_ref().ok_or(Error::NotFound("SMV address for control block"))?;
        let dat_set = cb.dat_set.as_ref().ok_or(Error::NotFound("datSet of control block"))?;
        let ds = self.data_set(ln, dat_set).ok_or(Error::NotFound("datSet of control block"))?;
        let sample_len = self.sv_sample_len(&ld.name, ds).ok_or(Error::InvalidValue("data set has no fixed sampled-value layout"))?;
        let asdus_per_frame = u8::try_from(cb.nof_asdu).map_err(|_| Error::InvalidValue("nofASDU"))?;
        let smp_mod = SmpMod::parse(&cb.smp_mod);
        let samples_per_second =
            cb.samples_per_second(nominal_hz).ok_or(Error::InvalidValue("smpRate and smpMod do not describe a whole number of samples per second"))?;
        let profile = SvProfile {
            samples_per_second,
            asdus_per_frame,
            // 9-2LE omits both; anything else states what it means.
            smp_mod: smp_mod.filter(|m| !matches!(m, SmpMod::SamplesPerPeriod)),
            smp_rate: u16::try_from(cb.smp_rate).ok().filter(|_| !matches!(smp_mod, None | Some(SmpMod::SamplesPerPeriod))),
            sample_len,
        };
        let header = FrameHeader {
            dst: addr.mac,
            src,
            vlan: Some(VlanTag { priority: addr.vlan_priority, dei: false, id: addr.vlan_id }),
            ethertype: ETHERTYPE_SV,
            appid: addr.appid,
            reserved1: 0,
            reserved2: 0,
        };
        Ok(PublisherConfig::new(header, cb.smv_id.clone(), profile).with_conf_rev(cb.conf_rev))
    }

    /// Build a [`crate::proto::sv::StreamConfig`] for a sampled-value control block — what
    /// a subscriber to *this* IED's stream needs.
    #[cfg(feature = "sv")]
    pub fn sv_stream_config(&self, reference: &str, nominal_hz: u32) -> Result<crate::proto::sv::StreamConfig> {
        use crate::proto::sv::{StreamConfig, StreamKey};
        let (ld, ln, cb) = self.smv_control(reference)?;
        let addr = cb.address.as_ref().ok_or(Error::NotFound("SMV address for control block"))?;
        let samples_per_second =
            cb.samples_per_second(nominal_hz).ok_or(Error::InvalidValue("smpRate and smpMod do not describe a whole number of samples per second"))?;
        let mut config = StreamConfig::new(StreamKey { dst: addr.mac, appid: addr.appid, sv_id: cb.smv_id.clone() })
            .with_samples_per_second(samples_per_second)
            .with_conf_rev(cb.conf_rev);
        // The data set says what the octets of each ASDU mean; a subscriber configured from
        // the file therefore decodes channels, not a byte blob.
        if let Some(layout) = cb.dat_set.as_deref().and_then(|n| self.data_set(ln, n)).and_then(|ds| self.sv_sample_layout(&ld.name, ds)) {
            config = config.with_layout(layout);
        }
        Ok(config)
    }

    /// Every subscription supervision logical node this IED declares, in model order.
    ///
    /// The control block each watches comes from its `GoCBRef`/`SvCBRef` setting. `ORG` has
    /// two attributes that can carry a reference — `setSrcRef` and `setSrcCB` — and the field
    /// disagrees about which one a control-block reference belongs in, so both are read, in
    /// that order 🌐.
    pub fn supervision(&self) -> Vec<Supervision> {
        let mut out = Vec::new();
        for ld in &self.logical_devices {
            for ln in &ld.logical_nodes {
                let setting = match ln.class.as_str() {
                    "LGOS" => "GoCBRef",
                    "LSVS" => "SvCBRef",
                    _ => continue,
                };
                let control_block = ln
                    .data_objects
                    .iter()
                    .find(|o| o.name == setting)
                    .and_then(|o| ["setSrcRef", "setSrcCB"].iter().find_map(|a| o.attributes.iter().find(|d| d.name == *a)?.value.clone()))
                    .filter(|v| !v.is_empty());
                out.push(Supervision { node: alloc::format!("{}/{}", ld.name, ln.name), ln_class: ln.class.clone(), control_block });
            }
        }
        out
    }

    /// Every `ExtRef` of this IED, with the logical node that declares it.
    pub fn ext_refs(&self) -> impl Iterator<Item = (&LogicalDevice, &LogicalNode, &ExtRef)> {
        self.logical_devices.iter().flat_map(|ld| ld.logical_nodes.iter().flat_map(move |ln| ln.inputs.iter().map(move |x| (ld, ln, x))))
    }

    /// Build a GOOSE [`crate::proto::goose::SubscriptionKey`] for a control block of this
    /// (publishing) IED — what a subscriber IED derives from an `ExtRef`.
    #[cfg(feature = "goose")]
    pub fn goose_subscription_key(&self, reference: &str) -> Result<crate::proto::goose::SubscriptionKey> {
        let (ld, ln, gcb) = self.gse_control(reference)?;
        let addr = gcb.address.as_ref().ok_or(Error::NotFound("GSE address for control block"))?;
        let mut gocb_ref = String::from(&ld.name);
        gocb_ref.push('/');
        gocb_ref.push_str(&ln.name);
        gocb_ref.push_str("$GO$");
        gocb_ref.push_str(&gcb.name);
        Ok(crate::proto::goose::SubscriptionKey { dst: addr.mac, appid: addr.appid, gocb_ref })
    }
}

/// An SCL `ctlModel` value: the enumeration literal, or its ordinal.
///
/// SCL writes the literal (`sbo-with-enhanced-security`), but files exist that write the
/// ordinal instead, and both mean the same thing.
fn parse_ctl_model(value: &str) -> Option<crate::common::ControlModel> {
    use crate::common::ControlModel;
    Some(match value.trim() {
        "status-only" => ControlModel::StatusOnly,
        "direct-with-normal-security" => ControlModel::DirectNormal,
        "sbo-with-normal-security" => ControlModel::SboNormal,
        "direct-with-enhanced-security" => ControlModel::DirectEnhanced,
        "sbo-with-enhanced-security" => ControlModel::SboEnhanced,
        other => ControlModel::from_code(other.parse().ok()?)?,
    })
}

#[cfg(test)]
mod supervision_tests {
    use super::*;

    #[test]
    fn a_supervision_node_matches_its_control_block_in_either_spelling() {
        let lgos =
            Supervision { node: String::from("IED2LD0/LGOS1"), ln_class: String::from("LGOS"), control_block: Some(String::from("IED1LD0/LLN0$GO$gcbTrip")) };
        assert!(lgos.is_goose());
        // The MMS form a `gocbRef` carries, and the dotted form SCL tooling prints: a binding
        // that depended on which one an engineer's tool wrote would be no binding at all.
        assert!(lgos.watches("IED1LD0/LLN0$GO$gcbTrip"));
        assert!(lgos.watches("IED1LD0/LLN0.gcbTrip"));
        assert!(!lgos.watches("IED1LD0/LLN0.gcbOther"));
        assert!(!lgos.watches("IED3LD0/LLN0.gcbTrip"));
        // A node the file says nothing about watches nothing, rather than everything.
        let bare = Supervision { control_block: None, ..lgos };
        assert!(!bare.watches("IED1LD0/LLN0$GO$gcbTrip"));
    }
}
