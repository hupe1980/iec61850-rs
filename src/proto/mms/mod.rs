//! MMS (ISO 9506) as IEC 61850-8-1 maps ACSI onto it.
//!
//! Everything an IEC 61850 client does over TCP is an MMS service: reading a data attribute
//! is `Read`, writing one is `Write`, a buffered report is an `InformationReport`, browsing a
//! server is `GetNameList`, and a data set is a *named variable list*. The mapping is what
//! IEC 61850-8-1 clause 7 defines, and it is the reason this crate needs ISO 9506 at all.
//!
//! What is decoded here is the envelope plus the services that carry values — `Read`,
//! `Write`, `InformationReport`, `GetNameList`, `GetNamedVariableListAttributes`, `Identify`
//! and `Initiate`. Anything else keeps its tag and its contents so that it round-trips and a
//! tool can name it; the ACSI state machines that *use* these services are the next layer up
//! and are not written yet.
//!
//! Values reuse [`crate::proto::data`] — the same `Data` type GOOSE carries, because it is
//! the same type. A report's `AccessResult` is an MMS `Data`, and having one decoder for both
//! is the reason a subscriber and a client agree about what a floating point is.

pub mod alternate;
pub mod association;
pub mod control;
pub mod file;
pub mod journal;
pub mod reject;
pub mod report;
pub mod typespec;

use alloc::vec::Vec;

pub use self::alternate::Path as AlternateAccess;
pub use self::alternate::Selector;
use crate::ber::{Class, Cursor, Encoder, Tag, Tlv, universal};
use crate::common::{DecodeReason, Error, Limits, Result};
use crate::proto::data::DataView;
use file::{DirectoryEntry, FileAttributes, FileName};
use journal::{AfterEntry, JournalEntry, RangeStart, RangeStop, TimeOfDay};
use reject::Reject;
use typespec::TypeSpec;

/// `Identifier ::= VisibleString`.
const TAG_IDENTIFIER: Tag = Tag::universal(universal::VISIBLE_STRING, false);
const TAG_INTEGER: Tag = Tag::universal(universal::INTEGER, false);
const TAG_SEQUENCE: Tag = Tag::universal(universal::SEQUENCE, true);

/// `ObjectName ::= CHOICE { vmd-specific [0], domain-specific [1], aa-specific [2] }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectName<'a> {
    /// A name in the VMD's own scope.
    VmdSpecific(&'a str),
    /// A name in a domain — for IEC 61850, the logical device and the object below it.
    DomainSpecific {
        /// The domain, which is the logical device name.
        domain: &'a str,
        /// The item, which is `LN$FC$DO$DA` in the IEC 61850 mapping.
        item: &'a str,
    },
    /// A name private to this association.
    AaSpecific(&'a str),
}

impl<'a> ObjectName<'a> {
    /// Decode one `ObjectName`.
    pub fn parse(t: &Tlv<'a>) -> Result<ObjectName<'a>> {
        if t.tag.class != Class::Context {
            return Err(Error::decode(DecodeReason::UnexpectedTag, t.offset));
        }
        Ok(match t.tag.number {
            0 => ObjectName::VmdSpecific(t.visible_string()?),
            1 => {
                let mut c = t.children();
                let domain = c.next_tag(TAG_IDENTIFIER)?.visible_string()?;
                let item = c.next_tag(TAG_IDENTIFIER)?.visible_string()?;
                ObjectName::DomainSpecific { domain, item }
            }
            2 => ObjectName::AaSpecific(t.visible_string()?),
            _ => return Err(Error::decode(DecodeReason::UnexpectedTag, t.offset)),
        })
    }

    /// Encode this name into `e`.
    pub fn write(&self, e: &mut Encoder) -> Result<()> {
        match self {
            ObjectName::VmdSpecific(s) => {
                e.visible_string(Tag::context(0), s)?;
            }
            ObjectName::DomainSpecific { domain, item } => {
                e.constructed(Tag::context_constructed(1), |e| {
                    e.visible_string(TAG_IDENTIFIER, domain)?;
                    e.visible_string(TAG_IDENTIFIER, item)?;
                    Ok(())
                })?;
            }
            ObjectName::AaSpecific(s) => {
                e.visible_string(Tag::context(2), s)?;
            }
        }
        Ok(())
    }
}

/// A decoded MMS `ServiceError`, the negative answer to a confirmed request.
///
/// `errorClass` is a CHOICE, so the class is its **tag number** and the code is the integer
/// inside it: class 7 (`access`) code 10 is object-non-existent, which is what a client sees
/// when it asks an IED for a reference the SCD promised and the IED does not have.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceError {
    /// The `errorClass` choice tag.
    pub class: u32,
    /// The integer that choice carries.
    pub code: i64,
    /// `additionalCode`, when the server sent one.
    pub additional: Option<i64>,
}

/// `errorClass` choice tags of an ISO 9506 [`ServiceError`], and the codes inside the ones
/// this crate emits.
pub mod service_error {
    /// `service [4]`.
    pub const SERVICE: u32 = 4;
    /// `service: primitives-out-of-sequence (1)` — the PDU arrived where it cannot be acted
    /// on, which is what a `Cancel` naming a request that is no longer outstanding is.
    pub const PRIMITIVES_OUT_OF_SEQUENCE: i64 = 1;
}

impl ServiceError {
    /// The encoded `ServiceError` element for one class and code, under `tag`.
    ///
    /// The PDUs that carry one keep it as raw octets ([`Mms::ConfirmedError`],
    /// [`Mms::CancelError`]) so that a peer's error re-encodes exactly as it arrived; this is
    /// how *this* end builds one to send. The tag belongs to the **PDU**, not to the error —
    /// ISO 9506 puts `serviceError` at `[2]` in a `Confirmed-ErrorPDU` and at `[1]` in a
    /// `Cancel-ErrorPDU` — so the caller names it and a wrong one cannot be defaulted in.
    pub fn encode(tag: Tag, class: u32, code: i64) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        e.constructed(tag, |e| {
            e.constructed(Tag::context_constructed(0), |e| {
                e.integer(Tag::context(class), code)?;
                Ok(())
            })?;
            Ok(())
        })?;
        Ok(e.into_vec())
    }

    /// Decode the `ServiceError` an [`Mms::ConfirmedError`] keeps encoded.
    pub fn parse(t: &Tlv<'_>) -> Result<ServiceError> {
        let mut out = ServiceError::default();
        for field in t.children() {
            let f = field?;
            match (f.tag.class, f.tag.number) {
                (Class::Context, 0) => {
                    let inner = f.children().next_required()?;
                    out.class = inner.tag.number;
                    out.code = inner.integer_i64().unwrap_or(0);
                }
                (Class::Context, 1) => out.additional = Some(f.integer_i64()?),
                _ => {}
            }
        }
        Ok(out)
    }
}

/// The `ObjectClass` values IEC 61850-8-1 asks `GetNameList` for.
///
/// ISO 9506's `basicObjectClass` enumeration. A client browsing a server walks exactly three
/// of them: [`object_class::DOMAIN`] gives the logical devices, [`object_class::NAMED_VARIABLE`]
/// the variables inside one, and [`object_class::NAMED_VARIABLE_LIST`] its data sets.
pub mod object_class {
    /// A named variable — a logical node, a data object or a data attribute.
    pub const NAMED_VARIABLE: i64 = 0;
    /// A scattered access.
    pub const SCATTERED_ACCESS: i64 = 1;
    /// A named variable list — an IEC 61850 **data set**.
    pub const NAMED_VARIABLE_LIST: i64 = 2;
    /// A named type.
    pub const NAMED_TYPE: i64 = 3;
    /// A journal — an IEC 61850 **log**.
    pub const JOURNAL: i64 = 8;
    /// A domain — an IEC 61850 **logical device**.
    pub const DOMAIN: i64 = 9;
}

/// `ObjectScope ::= CHOICE { vmdSpecific [0] NULL, domainSpecific [1] Identifier,
/// aaSpecific [2] NULL }` — where `GetNameList` should look.
///
/// Kept as a type rather than as a raw element so that a client can ask a question without
/// hand-encoding BER: `GetServerDirectory` is `VmdSpecific` with [`object_class::DOMAIN`],
/// and `GetLogicalDeviceDirectory` is `DomainSpecific(ld)` with
/// [`object_class::NAMED_VARIABLE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectScope<'a> {
    /// `vmdSpecific [0]` — the whole server.
    VmdSpecific,
    /// `domainSpecific [1]` — inside one domain (logical device).
    DomainSpecific(&'a str),
    /// `aaSpecific [2]` — objects private to this association.
    AaSpecific,
    /// A scope this codec does not model, kept whole so it re-encodes as it arrived.
    Other(Tlv<'a>),
}

impl<'a> ObjectScope<'a> {
    /// Decode one `ObjectScope`.
    pub fn parse(t: Tlv<'a>) -> Result<ObjectScope<'a>> {
        if t.tag.class != Class::Context {
            return Err(Error::decode(DecodeReason::UnexpectedTag, t.offset));
        }
        Ok(match t.tag.number {
            0 => ObjectScope::VmdSpecific,
            1 => ObjectScope::DomainSpecific(t.visible_string()?),
            2 => ObjectScope::AaSpecific,
            _ => ObjectScope::Other(t),
        })
    }

    /// Encode this scope into `e`.
    pub fn write(&self, e: &mut Encoder) -> Result<()> {
        match self {
            ObjectScope::VmdSpecific => {
                e.primitive(Tag::context(0), &[])?;
            }
            ObjectScope::DomainSpecific(d) => {
                e.visible_string(Tag::context(1), d)?;
            }
            ObjectScope::AaSpecific => {
                e.primitive(Tag::context(2), &[])?;
            }
            ObjectScope::Other(t) => {
                e.primitive(t.tag, t.value)?;
            }
        }
        Ok(())
    }
}

/// `VariableSpecification ::= CHOICE { name [0] ObjectName, … }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariableSpecification<'a> {
    /// `name [0]` — the whole named variable.
    Name(ObjectName<'a>),
    /// `name [0]` with the item's `alternateAccess [5]`: one *part* of the named variable —
    /// an element of an array, a component of a structure, or a path through both.
    ///
    /// The two live in one type because they are one question with two answers, and a caller
    /// that forgets the second reads a sixteen-element array where it asked for one harmonic.
    /// On the wire they are siblings inside the list item, which [`AlternateAccess`] documents.
    Element {
        /// The named variable the selection is relative to.
        name: ObjectName<'a>,
        /// Which part of it.
        access: AlternateAccess<'a>,
    },
    /// Any other form (address, description, scattered access, invalidated), kept whole.
    Other(Tlv<'a>),
}

impl<'a> VariableSpecification<'a> {
    /// The named variable, whichever form this is.
    pub const fn name(&self) -> Option<&ObjectName<'a>> {
        match self {
            VariableSpecification::Name(n) | VariableSpecification::Element { name: n, .. } => Some(n),
            VariableSpecification::Other(_) => None,
        }
    }

    /// The part of it that is selected, if any.
    pub const fn access(&self) -> Option<&AlternateAccess<'a>> {
        match self {
            VariableSpecification::Element { access, .. } => Some(access),
            VariableSpecification::Name(_) | VariableSpecification::Other(_) => None,
        }
    }

    /// A specification for `name`, with `access` when it selects something.
    pub fn of(name: ObjectName<'a>, access: AlternateAccess<'a>) -> VariableSpecification<'a> {
        if access.is_empty() { VariableSpecification::Name(name) } else { VariableSpecification::Element { name, access } }
    }
}

/// `VariableAccessSpecification ::= CHOICE { listOfVariable [0], variableListName [1] }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariableAccess<'a> {
    /// A list of variables, named one by one.
    ListOfVariable(Vec<VariableSpecification<'a>>),
    /// A named variable list — an IEC 61850 **data set**.
    VariableListName(ObjectName<'a>),
}

impl<'a> VariableAccess<'a> {
    /// Decode one `VariableAccessSpecification`.
    ///
    /// The member list is bounded by [`Limits::DEFAULT`] rather than by a caller's limits:
    /// this is reached from several services with no limits to hand, and a hard ceiling on a
    /// list a peer chose the length of is what a decoder owes regardless.
    pub fn parse(t: &Tlv<'a>) -> Result<VariableAccess<'a>> {
        match (t.tag.class, t.tag.number) {
            (Class::Context, 0) => Ok(VariableAccess::ListOfVariable(parse_variable_list(t, &Limits::DEFAULT)?)),
            (Class::Context, 1) => Ok(VariableAccess::VariableListName(ObjectName::parse(&t.children().next_required()?)?)),
            _ => Err(Error::decode(DecodeReason::UnexpectedTag, t.offset)),
        }
    }

    /// Encode this access specification into `e`.
    pub fn write(&self, e: &mut Encoder) -> Result<()> {
        match self {
            VariableAccess::ListOfVariable(items) => write_variable_list(items, Tag::context_constructed(0), e)?,
            VariableAccess::VariableListName(n) => {
                e.constructed(Tag::context_constructed(1), |e| n.write(e))?;
            }
        }
        Ok(())
    }
}

/// `AccessResult ::= CHOICE { failure [0] IMPLICIT DataAccessError, success Data }`.
///
/// The success case keeps the encoded element rather than the decoded value. That is what
/// makes a decoded PDU re-encode to the octets it arrived as — a peer may write `TRUE` as
/// `FF` or an integer non-minimally, and a re-encode from the decoded value would quietly
/// "correct" it. [`AccessResult::value`] decodes on demand, and parsing has already checked
/// that it will succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessResult<'a> {
    /// The server could not deliver the value; the code is a `DataAccessError`.
    Failure(i64),
    /// The value, as the same `Data` type GOOSE carries.
    Success(Tlv<'a>),
}

impl<'a> AccessResult<'a> {
    /// The value, if the access succeeded.
    pub fn value(&self) -> Option<DataView<'a>> {
        match self {
            AccessResult::Success(t) => DataView::from_tlv(*t).ok(),
            AccessResult::Failure(_) => None,
        }
    }

    fn parse(t: Tlv<'a>) -> Result<AccessResult<'a>> {
        // `failure [0] IMPLICIT DataAccessError` cannot collide with `Data`, whose choices
        // start at [1], so a context tag 0 is unambiguously the failure.
        if t.tag == Tag::context(0) {
            return Ok(AccessResult::Failure(t.integer_i64()?));
        }
        // Decoded once here so that a malformed value is a decode error at the PDU level
        // rather than a surprise when the application asks for it.
        DataView::from_tlv(t)?;
        Ok(AccessResult::Success(t))
    }
}

/// `Write-Response ::= SEQUENCE OF CHOICE { failure [0], success [1] IMPLICIT NULL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteResult {
    /// The write failed with this `DataAccessError`.
    Failure(i64),
    /// The write succeeded.
    Success,
}

/// The negotiated parameters of an association (`Initiate-Request/ResponsePDU`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Initiate<'a> {
    /// `localDetailCalling`/`localDetailCalled`: the largest MMS PDU this side accepts.
    pub local_detail: Option<i64>,
    /// Outstanding calls this side may issue.
    pub max_serv_outstanding_calling: i64,
    /// Outstanding calls this side accepts.
    pub max_serv_outstanding_called: i64,
    /// How deep a nested `Data` may be.
    pub data_structure_nesting_level: Option<i64>,
    /// Version number, from the init detail.
    pub version: i64,
    /// `parameterCBB`, as its bit-string contents.
    pub parameter_cbb: (u8, &'a [u8]),
    /// `servicesSupported`, as its bit-string contents.
    pub services_supported: (u8, &'a [u8]),
}

impl<'a> Initiate<'a> {
    /// The proposal one end makes: `max_pdu` octets, `outstanding` calls in each direction,
    /// nesting five, and the services this crate can actually issue.
    ///
    /// `outstanding` is a parameter rather than a constant because it is what the association
    /// then *enforces*: a client that proposes ten and is configured for two would either
    /// have to break its own limit or discover it as a reject. `parameter_cbb` and
    /// `services_supported` are passed in for the same reason — what a peer may ask of us is
    /// a property of the layer above, not of the codec.
    pub fn request(max_pdu: i64, outstanding: i64, parameter_cbb: (u8, &'a [u8]), services_supported: (u8, &'a [u8])) -> Initiate<'a> {
        Initiate {
            local_detail: Some(max_pdu),
            max_serv_outstanding_calling: outstanding,
            max_serv_outstanding_called: outstanding,
            data_structure_nesting_level: Some(5),
            version: 1,
            parameter_cbb,
            services_supported,
        }
    }

    fn parse(t: &Tlv<'a>) -> Result<Initiate<'a>> {
        let mut c = t.children();
        let local_detail = c.next_if_tag(Tag::context(0))?.map(|t| t.integer_i64()).transpose()?;
        let max_serv_outstanding_calling = c.next_tag(Tag::context(1))?.integer_i64()?;
        let max_serv_outstanding_called = c.next_tag(Tag::context(2))?.integer_i64()?;
        let data_structure_nesting_level = c.next_if_tag(Tag::context(3))?.map(|t| t.integer_i64()).transpose()?;
        let detail = c.next_tag(Tag::context_constructed(4))?;
        let mut d = detail.children();
        let version = d.next_tag(Tag::context(0))?.integer_i64()?;
        let parameter_cbb = d.next_tag(Tag::context(1))?.bit_string()?;
        let services_supported = d.next_tag(Tag::context(2))?.bit_string()?;
        Ok(Initiate {
            local_detail,
            max_serv_outstanding_calling,
            max_serv_outstanding_called,
            data_structure_nesting_level,
            version,
            parameter_cbb,
            services_supported,
        })
    }

    fn write(&self, tag: Tag, e: &mut Encoder) -> Result<()> {
        e.constructed(tag, |e| {
            if let Some(d) = self.local_detail {
                e.integer(Tag::context(0), d)?;
            }
            e.integer(Tag::context(1), self.max_serv_outstanding_calling)?;
            e.integer(Tag::context(2), self.max_serv_outstanding_called)?;
            if let Some(n) = self.data_structure_nesting_level {
                e.integer(Tag::context(3), n)?;
            }
            e.constructed(Tag::context_constructed(4), |e| {
                e.integer(Tag::context(0), self.version)?;
                e.bit_string(Tag::context(1), self.parameter_cbb.0, self.parameter_cbb.1)?;
                e.bit_string(Tag::context(2), self.services_supported.0, self.services_supported.1)?;
                Ok(())
            })?;
            Ok(())
        })?;
        Ok(())
    }
}

/// The `scopeOfDelete` values `DeleteNamedVariableList` takes.
pub mod delete_scope {
    /// Delete exactly the named lists.
    pub const SPECIFIC: i64 = 0;
    /// Delete every list private to this association.
    pub const AA_SPECIFIC: i64 = 1;
    /// Delete every list in one domain (logical device).
    pub const DOMAIN: i64 = 2;
    /// Delete every list in the VMD.
    pub const VMD: i64 = 3;
}

/// A `ReadJournal` request: IEC 61850's `QueryLogByTime` and `QueryLogAfterEntry`.
///
/// `QueryLogByTime` sets `start` and `stop` to times; `QueryLogAfterEntry` sets `after`. A
/// request that sets neither reads the whole log, which is what a first poll does.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReadJournal<'a> {
    /// The journal — for IEC 61850, `domain = logical device`, `item = log name`.
    pub name: Option<ObjectName<'a>>,
    /// Where to start.
    pub start: Option<RangeStart<'a>>,
    /// Where to stop.
    pub stop: Option<RangeStop>,
    /// Restrict the answer to these variable tags. Empty means all of them.
    pub variables: Vec<&'a str>,
    /// Resume after this entry (`QueryLogAfterEntry`).
    pub after: Option<AfterEntry<'a>>,
}

impl<'a> ReadJournal<'a> {
    /// Every entry of `name` from `from` onward — `QueryLogByTime` with no upper bound.
    pub fn by_time(name: ObjectName<'a>, from: TimeOfDay, to: Option<TimeOfDay>) -> ReadJournal<'a> {
        ReadJournal { name: Some(name), start: Some(RangeStart::Time(from)), stop: to.map(RangeStop::Time), ..ReadJournal::default() }
    }

    /// Every entry of `name` after `after` — `QueryLogAfterEntry`.
    pub fn after_entry(name: ObjectName<'a>, after: AfterEntry<'a>) -> ReadJournal<'a> {
        ReadJournal { name: Some(name), after: Some(after), ..ReadJournal::default() }
    }

    fn parse(t: &Tlv<'a>) -> Result<ReadJournal<'a>> {
        let mut c = t.children();
        let name = match c.next_if_tag(Tag::context_constructed(0))? {
            Some(n) => Some(ObjectName::parse(&n.children().next_required()?)?),
            None => None,
        };
        let start = match c.next_if_tag(Tag::context_constructed(1))? {
            Some(r) => {
                let inner = r.children().next_required()?;
                Some(match inner.tag.number {
                    0 => RangeStart::Time(TimeOfDay::from_octets(inner.value)?),
                    1 => RangeStart::Entry(inner.value),
                    _ => return Err(Error::decode(DecodeReason::UnexpectedTag, inner.offset)),
                })
            }
            None => None,
        };
        let stop = match c.next_if_tag(Tag::context_constructed(2))? {
            Some(r) => {
                let inner = r.children().next_required()?;
                Some(match inner.tag.number {
                    0 => RangeStop::Time(TimeOfDay::from_octets(inner.value)?),
                    1 => RangeStop::Count(inner.integer_i32()?),
                    _ => return Err(Error::decode(DecodeReason::UnexpectedTag, inner.offset)),
                })
            }
            None => None,
        };
        let mut variables = Vec::new();
        if let Some(list) = c.next_if_tag(Tag::context_constructed(4))? {
            for v in list.children() {
                variables.push(v?.visible_string()?);
            }
        }
        let after = match c.next_if_tag(Tag::context_constructed(5))? {
            Some(a) => {
                let mut m = a.children();
                let time = TimeOfDay::from_octets(m.next_tag(Tag::context(0))?.value)?;
                let entry_id = m.next_tag(Tag::context(1))?.value;
                Some(AfterEntry { time, entry_id })
            }
            None => None,
        };
        Ok(ReadJournal { name, start, stop, variables, after })
    }

    fn write(&self, e: &mut Encoder) -> Result<()> {
        e.constructed(Tag::context_constructed(SERVICE_READ_JOURNAL), |e| {
            if let Some(n) = &self.name {
                e.constructed(Tag::context_constructed(0), |e| n.write(e))?;
            }
            if let Some(s) = &self.start {
                e.constructed(Tag::context_constructed(1), |e| match s {
                    RangeStart::Time(t) => e.primitive(Tag::context(0), &t.to_octets()).map(|_| ()),
                    RangeStart::Entry(id) => e.primitive(Tag::context(1), id).map(|_| ()),
                })?;
            }
            if let Some(s) = &self.stop {
                e.constructed(Tag::context_constructed(2), |e| match s {
                    RangeStop::Time(t) => e.primitive(Tag::context(0), &t.to_octets()).map(|_| ()),
                    RangeStop::Count(n) => e.integer(Tag::context(1), i64::from(*n)).map(|_| ()),
                })?;
            }
            if !self.variables.is_empty() {
                e.constructed(Tag::context_constructed(4), |e| {
                    for v in &self.variables {
                        e.visible_string(TAG_VISIBLE_STRING, v)?;
                    }
                    Ok(())
                })?;
            }
            if let Some(a) = &self.after {
                e.constructed(Tag::context_constructed(5), |e| {
                    e.primitive(Tag::context(0), &a.time.to_octets())?;
                    e.primitive(Tag::context(1), a.entry_id)?;
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(())
    }
}

/// `status`.
const SERVICE_STATUS: u32 = 0;
/// `getVariableAccessAttributes`.
const SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES: u32 = 6;
/// `getCapabilityList`.
const SERVICE_GET_CAPABILITY_LIST: u32 = 71;
/// `defineNamedVariableList`.
const SERVICE_DEFINE_NVL: u32 = 11;
/// `deleteNamedVariableList`.
const SERVICE_DELETE_NVL: u32 = 13;
/// `readJournal`.
const SERVICE_READ_JOURNAL: u32 = 65;
/// `fileOpen`.
const SERVICE_FILE_OPEN: u32 = 72;
/// `fileRead`.
const SERVICE_FILE_READ: u32 = 73;
/// `fileClose`.
const SERVICE_FILE_CLOSE: u32 = 74;
/// `fileDelete`.
const SERVICE_FILE_DELETE: u32 = 76;
/// `fileDirectory`.
const SERVICE_FILE_DIRECTORY: u32 = 77;

const TAG_VISIBLE_STRING: Tag = Tag::universal(universal::VISIBLE_STRING, false);

/// `vmdLogicalStatus` of a `Status` response (ISO 9506-2).
pub mod vmd_logical {
    /// The VMD will accept requests that change its state.
    pub const STATE_CHANGES_ALLOWED: i64 = 0;
    /// It will not.
    pub const NO_STATE_CHANGES_ALLOWED: i64 = 1;
    /// Only some services are available.
    pub const LIMITED_SERVICES_ALLOWED: i64 = 2;
    /// Only support services are available.
    pub const SUPPORT_SERVICES_ALLOWED: i64 = 3;
}

/// `vmdPhysicalStatus` of a `Status` response (ISO 9506-2).
pub mod vmd_physical {
    /// The device is working.
    pub const OPERATIONAL: i64 = 0;
    /// Some of it is.
    pub const PARTIALLY_OPERATIONAL: i64 = 1;
    /// None of it is.
    pub const INOPERABLE: i64 = 2;
    /// It has not been commissioned.
    pub const NEEDS_COMMISSIONING: i64 = 3;
}

/// A confirmed service request.
#[derive(Clone, Debug, PartialEq)]
pub enum ConfirmedRequest<'a> {
    /// `status [0]` — is the VMD healthy? The boolean is `extendedDerivation`: the client
    /// asking the server to *re-derive* its status rather than report the cached one.
    ///
    /// It is the first thing many SCADA clients send and the last thing they send before
    /// giving up on a link, which is why IEC 61850-8-1 keeps it as an ACSI service at all.
    Status {
        /// `extendedDerivation`.
        extended_derivation: bool,
    },
    /// `getCapabilityList [71]` — what the VMD says it can do, as free-form strings.
    GetCapabilityList {
        /// Continue after this capability, when a previous answer said `moreFollows`.
        continue_after: Option<&'a str>,
    },
    /// `getNameList [1]` — browse the server's names.
    GetNameList {
        /// The object class asked for, as its encoded integer.
        object_class: i64,
        /// Where to look.
        scope: ObjectScope<'a>,
        /// Continue after this name, when a previous answer said `moreFollows`.
        continue_after: Option<&'a str>,
    },
    /// `identify [2]`.
    Identify,
    /// `read [4]`.
    Read {
        /// Ask the server to name what it returns.
        specification_with_result: bool,
        /// What to read.
        access: VariableAccess<'a>,
    },
    /// `write [5]`.
    Write {
        /// What to write to.
        access: VariableAccess<'a>,
        /// The values, in the order of the access specification, as their encoded elements —
        /// [`DataView::from_tlv`] decodes one, and parsing has already checked that it will.
        values: Vec<Tlv<'a>>,
    },
    /// `getNamedVariableListAttributes [12]` — what is in a data set.
    GetNamedVariableListAttributes(ObjectName<'a>),
    /// `getVariableAccessAttributes [6]` — what *type* a variable is.
    GetVariableAccessAttributes(ObjectName<'a>),
    /// `defineNamedVariableList [11]` — create a data set.
    DefineNamedVariableList {
        /// The data set's name.
        name: ObjectName<'a>,
        /// Its members.
        variables: Vec<VariableSpecification<'a>>,
    },
    /// `deleteNamedVariableList [13]` — delete data sets.
    DeleteNamedVariableList {
        /// `scopeOfDelete`; see [`delete_scope`].
        scope: i64,
        /// The lists to delete, for [`delete_scope::SPECIFIC`].
        names: Vec<ObjectName<'a>>,
        /// The domain, for [`delete_scope::DOMAIN`].
        domain: Option<&'a str>,
    },
    /// `readJournal [65]` — IEC 61850's `QueryLogByTime` / `QueryLogAfterEntry`.
    ReadJournal(ReadJournal<'a>),
    /// `fileOpen [72]`.
    FileOpen {
        /// The file.
        name: FileName<'a>,
        /// Where in it to start reading.
        position: u32,
    },
    /// `fileRead [73]` — the `frsmID` a `fileOpen` returned.
    FileRead(i32),
    /// `fileClose [74]`.
    FileClose(i32),
    /// `fileDelete [76]`.
    FileDelete(FileName<'a>),
    /// `fileDirectory [77]`.
    FileDirectory {
        /// Which files, as a name or a pattern the server understands. `None` is all of them.
        specification: Option<FileName<'a>>,
        /// Continue after this name, when a previous answer said `moreFollows`.
        continue_after: Option<FileName<'a>>,
    },
    /// A service this codec does not model, kept whole.
    Other(Tlv<'a>),
}

/// A confirmed service response.
#[derive(Clone, Debug, PartialEq)]
pub enum ConfirmedResponse<'a> {
    /// `status [0]`.
    Status {
        /// `vmdLogicalStatus`; see [`vmd_logical`].
        logical: i64,
        /// `vmdPhysicalStatus`; see [`vmd_physical`].
        physical: i64,
        /// `localDetail`, a bit string the vendor defines, kept as `(unused_bits, octets)`.
        local_detail: Option<(u8, &'a [u8])>,
    },
    /// `getCapabilityList [71]`.
    GetCapabilityList {
        /// What the VMD says it can do.
        capabilities: Vec<&'a str>,
        /// Whether the server has more to give.
        more_follows: bool,
    },
    /// `getNameList [1]`.
    GetNameList {
        /// The names.
        identifiers: Vec<&'a str>,
        /// Whether the server has more to give.
        more_follows: bool,
    },
    /// `identify [2]`.
    Identify {
        /// Vendor.
        vendor: &'a str,
        /// Model.
        model: &'a str,
        /// Revision.
        revision: &'a str,
    },
    /// `read [4]`.
    Read {
        /// What the server says it returned, when the request asked.
        access: Option<VariableAccess<'a>>,
        /// One result per variable.
        results: Vec<AccessResult<'a>>,
    },
    /// `write [5]`.
    Write(Vec<WriteResult>),
    /// `getNamedVariableListAttributes [12]`.
    GetNamedVariableListAttributes {
        /// Whether the client may delete this list.
        deletable: bool,
        /// The members.
        variables: Vec<VariableSpecification<'a>>,
    },
    /// `getVariableAccessAttributes [6]`.
    GetVariableAccessAttributes {
        /// Whether the client may delete this variable.
        deletable: bool,
        /// What the variable is.
        type_spec: TypeSpec,
    },
    /// `defineNamedVariableList [11]` — the data set was created.
    DefineNamedVariableList,
    /// `deleteNamedVariableList [13]`.
    DeleteNamedVariableList {
        /// How many lists matched the scope.
        matched: u32,
        /// How many of them were deleted — a list a client may not delete is matched and not
        /// deleted, which is the difference a caller has to see.
        deleted: u32,
    },
    /// `readJournal [65]`.
    ReadJournal {
        /// The entries.
        entries: Vec<JournalEntry<'a>>,
        /// Whether the server has more to give.
        more_follows: bool,
    },
    /// `fileOpen [72]`.
    FileOpen {
        /// The server-side handle every subsequent read and the close must carry.
        frsm_id: i32,
        /// Size and modification time.
        attributes: FileAttributes<'a>,
    },
    /// `fileRead [73]`.
    FileRead {
        /// This chunk.
        data: &'a [u8],
        /// Whether more chunks follow.
        more_follows: bool,
    },
    /// `fileClose [74]`.
    FileClose,
    /// `fileDelete [76]`.
    FileDelete,
    /// `fileDirectory [77]`.
    FileDirectory {
        /// The files.
        entries: Vec<DirectoryEntry<'a>>,
        /// Whether the server has more to give.
        more_follows: bool,
    },
    /// A service this codec does not model, kept whole.
    Other(Tlv<'a>),
}

/// An unconfirmed service.
#[derive(Clone, Debug, PartialEq)]
pub enum Unconfirmed<'a> {
    /// `informationReport [0]` — how IEC 61850 delivers a report.
    InformationReport {
        /// The data set, or the variables, the report is about.
        access: VariableAccess<'a>,
        /// One result per member.
        results: Vec<AccessResult<'a>>,
    },
    /// Anything else, kept whole.
    Other(Tlv<'a>),
}

/// An MMS PDU.
#[derive(Clone, Debug, PartialEq)]
pub enum Mms<'a> {
    /// `confirmed-RequestPDU [0]`.
    ConfirmedRequest {
        /// The invoke identifier the response will carry.
        invoke_id: i64,
        /// The service.
        service: ConfirmedRequest<'a>,
    },
    /// `confirmed-ResponsePDU [1]`.
    ConfirmedResponse {
        /// The request this answers.
        invoke_id: i64,
        /// The service.
        service: ConfirmedResponse<'a>,
    },
    /// `confirmed-ErrorPDU [2]`.
    ConfirmedError {
        /// The request this answers.
        invoke_id: i64,
        /// `modifierPosition`, when the server says which modifier failed.
        modifier_position: Option<u32>,
        /// The `ServiceError`, kept encoded. [`ServiceError::parse`] decodes it.
        error: Tlv<'a>,
    },
    /// `unconfirmed-PDU [3]`.
    Unconfirmed(Unconfirmed<'a>),
    /// `rejectPDU [4]`.
    ///
    /// Decoded rather than kept as octets, because it is an **answer**: its
    /// `originalInvokeID` names a confirmed request that will never be answered any other
    /// way, and a peer that treats it as an unsolicited PDU waits out its whole request
    /// timeout for something that already arrived.
    Reject(Reject),
    /// `cancel-RequestPDU [5]` — withdraw a confirmed request that is still outstanding.
    ///
    /// The value is the `originalInvokeID`: ISO 9506 numbers the *request* being withdrawn,
    /// not the withdrawal, so a cancel carries no invoke identifier of its own and is
    /// answered by `cancel-ResponsePDU` or `cancel-ErrorPDU` naming the same number.
    CancelRequest(i64),
    /// `cancel-ResponsePDU [6]` — the named request was withdrawn.
    CancelResponse(i64),
    /// `cancel-ErrorPDU [7]` — it was not, and this is why. The `ServiceError` is kept
    /// encoded; [`ServiceError::parse`] decodes it.
    CancelError {
        /// The request that could not be withdrawn.
        invoke_id: i64,
        /// The `ServiceError`.
        error: Tlv<'a>,
    },
    /// `initiate-RequestPDU [8]`.
    InitiateRequest(Initiate<'a>),
    /// `initiate-ResponsePDU [9]`.
    InitiateResponse(Initiate<'a>),
    /// `initiate-ErrorPDU [10]`, kept encoded.
    InitiateError(Tlv<'a>),
    /// `conclude-RequestPDU [11]`.
    ConcludeRequest,
    /// `conclude-ResponsePDU [12]`.
    ConcludeResponse,
    /// `conclude-ErrorPDU [13]`, kept encoded.
    ConcludeError(Tlv<'a>),
    /// A PDU this codec does not model (the cancel services), kept whole.
    Other(Tlv<'a>),
}

fn parse_access_results<'a>(t: &Tlv<'a>, limits: &Limits) -> Result<Vec<AccessResult<'a>>> {
    let mut out = Vec::new();
    for r in t.children() {
        if out.len() >= limits.max_dataset_members {
            return Err(Error::LimitExceeded { limit: "max_dataset_members", value: out.len() + 1 });
        }
        out.push(AccessResult::parse(r?)?);
    }
    Ok(out)
}

/// `SEQUENCE OF SEQUENCE { variableSpecification, alternateAccess [5] OPTIONAL }` — the shape
/// a `Read`'s `listOfVariable`, a data set's members and a `DefineNamedVariableList` all share.
///
/// One decoder for the three of them is the point: a data set created by this client and one
/// read back from the server cannot disagree about what a member is.
fn parse_variable_list<'a>(t: &Tlv<'a>, limits: &Limits) -> Result<Vec<VariableSpecification<'a>>> {
    let mut out = Vec::new();
    for item in t.children() {
        if out.len() >= limits.max_dataset_members {
            return Err(Error::LimitExceeded { limit: "max_dataset_members", value: out.len() + 1 });
        }
        let mut c = item?.expect(TAG_SEQUENCE)?.children();
        let spec = c.next_required()?;
        out.push(if spec.tag == Tag::context_constructed(0) {
            let name = ObjectName::parse(&spec.children().next_required()?)?;
            // `alternateAccess [5]` is the sibling that turns "this variable" into "this part
            // of it". A decoder that skips it hands the caller a name it will read whole,
            // which is a *different* answer to a question nobody notices was changed.
            match alternate::next_alternate(&mut c)? {
                Some(access) => VariableSpecification::Element { name, access },
                None => VariableSpecification::Name(name),
            }
        } else {
            VariableSpecification::Other(spec)
        });
    }
    Ok(out)
}

fn write_variable_list(items: &[VariableSpecification<'_>], tag: Tag, e: &mut Encoder) -> Result<()> {
    e.constructed(tag, |e| {
        for item in items {
            e.constructed(TAG_SEQUENCE, |e| match item {
                VariableSpecification::Name(n) => e.constructed(Tag::context_constructed(0), |e| n.write(e)).map(|_| ()),
                VariableSpecification::Element { name, access } => {
                    e.constructed(Tag::context_constructed(0), |e| name.write(e))?;
                    access.write(e)
                }
                VariableSpecification::Other(t) => e.primitive(t.tag, t.value).map(|_| ()),
            })?;
        }
        Ok(())
    })?;
    Ok(())
}

fn write_access_results(results: &[AccessResult<'_>], tag: Tag, e: &mut Encoder) -> Result<()> {
    e.constructed(tag, |e| {
        for r in results {
            match r {
                AccessResult::Failure(code) => {
                    e.integer(Tag::context(0), *code)?;
                }
                AccessResult::Success(t) => {
                    e.primitive(t.tag, t.value)?;
                }
            }
        }
        Ok(())
    })?;
    Ok(())
}

impl<'a> ConfirmedRequest<'a> {
    // One arm per MMS service number: the table *is* ISO 9506's, and splitting it into
    // helpers would hide the one thing a reader comes here to check.
    #[allow(clippy::too_many_lines)]
    fn parse(t: Tlv<'a>, limits: &Limits) -> Result<ConfirmedRequest<'a>> {
        if t.tag.class != Class::Context {
            return Err(Error::decode(DecodeReason::UnexpectedTag, t.offset));
        }
        Ok(match t.tag.number {
            1 => {
                let mut c = t.children();
                let object_class = c.next_tag(Tag::context_constructed(0))?.children().next_required()?.integer_i64()?;
                let scope = ObjectScope::parse(c.next_tag(Tag::context_constructed(1))?.children().next_required()?)?;
                let continue_after = c.next_if_tag(Tag::context(2))?.map(|t| t.visible_string()).transpose()?;
                ConfirmedRequest::GetNameList { object_class, scope, continue_after }
            }
            SERVICE_STATUS => ConfirmedRequest::Status { extended_derivation: t.boolean()? },
            2 => ConfirmedRequest::Identify,
            SERVICE_GET_CAPABILITY_LIST => {
                // `continueAfter` is untagged in ISO 9506-2, so it is a universal
                // `VisibleString` rather than a context tag — the one field of this codec
                // where the optional is recognised by its universal tag.
                ConfirmedRequest::GetCapabilityList { continue_after: t.children().next_if_tag(TAG_VISIBLE_STRING)?.map(|s| s.visible_string()).transpose()? }
            }
            4 => {
                let mut c = t.children();
                let specification_with_result = c.next_if_tag(Tag::context(0))?.map(|t| t.boolean()).transpose()?.unwrap_or(false);
                let access = VariableAccess::parse(&c.next_tag(Tag::context_constructed(1))?.children().next_required()?)?;
                ConfirmedRequest::Read { specification_with_result, access }
            }
            5 => {
                let mut c = t.children();
                let access = VariableAccess::parse(&c.next_required()?)?;
                let list = c.next_tag(Tag::context_constructed(0))?;
                let mut values = Vec::new();
                for v in list.children() {
                    if values.len() >= limits.max_dataset_members {
                        return Err(Error::LimitExceeded { limit: "max_dataset_members", value: values.len() + 1 });
                    }
                    let v = v?;
                    DataView::from_tlv(v)?;
                    values.push(v);
                }
                ConfirmedRequest::Write { access, values }
            }
            12 => ConfirmedRequest::GetNamedVariableListAttributes(ObjectName::parse(&t.children().next_required()?)?),
            SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES => {
                // `name [0] ObjectName` — a CHOICE inside a CHOICE, so both tags are explicit.
                let name = t.children().next_tag(Tag::context_constructed(0))?;
                ConfirmedRequest::GetVariableAccessAttributes(ObjectName::parse(&name.children().next_required()?)?)
            }
            SERVICE_DEFINE_NVL => {
                let mut c = t.children();
                let name = ObjectName::parse(&c.next_required()?)?;
                let variables = parse_variable_list(&c.next_tag(Tag::context_constructed(0))?, limits)?;
                ConfirmedRequest::DefineNamedVariableList { name, variables }
            }
            SERVICE_DELETE_NVL => {
                let mut c = t.children();
                let scope = c.next_if_tag(Tag::context(0))?.map(|t| t.integer_i64()).transpose()?.unwrap_or(delete_scope::SPECIFIC);
                let mut names = Vec::new();
                if let Some(list) = c.next_if_tag(Tag::context_constructed(1))? {
                    for n in list.children() {
                        if names.len() >= limits.max_list_items {
                            return Err(Error::LimitExceeded { limit: "max_list_items", value: names.len() + 1 });
                        }
                        names.push(ObjectName::parse(&n?)?);
                    }
                }
                let domain = c.next_if_tag(Tag::context(2))?.map(|t| t.visible_string()).transpose()?;
                ConfirmedRequest::DeleteNamedVariableList { scope, names, domain }
            }
            SERVICE_READ_JOURNAL => ConfirmedRequest::ReadJournal(ReadJournal::parse(&t)?),
            SERVICE_FILE_OPEN => {
                let mut c = t.children();
                let name = FileName::parse(&c.next_tag(Tag::context_constructed(0))?, limits)?;
                let position = c.next_tag(Tag::context(1))?.unsigned_lenient_u32()?;
                ConfirmedRequest::FileOpen { name, position }
            }
            SERVICE_FILE_READ => ConfirmedRequest::FileRead(t.integer_i32()?),
            SERVICE_FILE_CLOSE => ConfirmedRequest::FileClose(t.integer_i32()?),
            SERVICE_FILE_DELETE => ConfirmedRequest::FileDelete(FileName::parse(&t, limits)?),
            SERVICE_FILE_DIRECTORY => {
                let mut c = t.children();
                let specification = c.next_if_tag(Tag::context_constructed(0))?.map(|t| FileName::parse(&t, limits)).transpose()?;
                let continue_after = c.next_if_tag(Tag::context_constructed(1))?.map(|t| FileName::parse(&t, limits)).transpose()?;
                ConfirmedRequest::FileDirectory { specification, continue_after }
            }
            _ => ConfirmedRequest::Other(t),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn write(&self, e: &mut Encoder) -> Result<()> {
        match self {
            ConfirmedRequest::GetNameList { object_class, scope, continue_after } => {
                e.constructed(Tag::context_constructed(1), |e| {
                    e.constructed(Tag::context_constructed(0), |e| {
                        e.integer(Tag::context(0), *object_class)?;
                        Ok(())
                    })?;
                    e.constructed(Tag::context_constructed(1), |e| scope.write(e))?;
                    if let Some(after) = continue_after {
                        e.visible_string(Tag::context(2), after)?;
                    }
                    Ok(())
                })?;
            }
            ConfirmedRequest::Status { extended_derivation } => {
                // `Status-Request ::= BOOLEAN`, implicitly tagged: a primitive octet.
                e.boolean(Tag::context(SERVICE_STATUS), *extended_derivation)?;
            }
            ConfirmedRequest::GetCapabilityList { continue_after } => {
                e.constructed(Tag::context_constructed(SERVICE_GET_CAPABILITY_LIST), |e| {
                    if let Some(after) = continue_after {
                        e.visible_string(TAG_VISIBLE_STRING, after)?;
                    }
                    Ok(())
                })?;
            }
            ConfirmedRequest::Identify => {
                // `Identify-Request ::= NULL`, so the element is primitive and empty: the
                // reference capture writes `82 00`, not `A2 00`.
                e.primitive(Tag::context(2), &[])?;
            }
            ConfirmedRequest::Read { specification_with_result, access } => {
                e.constructed(Tag::context_constructed(4), |e| {
                    if *specification_with_result {
                        e.boolean(Tag::context(0), true)?;
                    }
                    e.constructed(Tag::context_constructed(1), |e| access.write(e))?;
                    Ok(())
                })?;
            }
            ConfirmedRequest::Write { access, values } => {
                e.constructed(Tag::context_constructed(5), |e| {
                    access.write(e)?;
                    e.constructed(Tag::context_constructed(0), |e| {
                        for v in values {
                            e.primitive(v.tag, v.value)?;
                        }
                        Ok(())
                    })?;
                    Ok(())
                })?;
            }
            ConfirmedRequest::GetNamedVariableListAttributes(name) => {
                e.constructed(Tag::context_constructed(12), |e| name.write(e))?;
            }
            ConfirmedRequest::GetVariableAccessAttributes(name) => {
                e.constructed(Tag::context_constructed(SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES), |e| {
                    e.constructed(Tag::context_constructed(0), |e| name.write(e))?;
                    Ok(())
                })?;
            }
            ConfirmedRequest::DefineNamedVariableList { name, variables } => {
                e.constructed(Tag::context_constructed(SERVICE_DEFINE_NVL), |e| {
                    name.write(e)?;
                    write_variable_list(variables, Tag::context_constructed(0), e)
                })?;
            }
            ConfirmedRequest::DeleteNamedVariableList { scope, names, domain } => {
                e.constructed(Tag::context_constructed(SERVICE_DELETE_NVL), |e| {
                    if *scope != delete_scope::SPECIFIC {
                        e.integer(Tag::context(0), *scope)?;
                    }
                    if !names.is_empty() {
                        e.constructed(Tag::context_constructed(1), |e| {
                            for n in names {
                                n.write(e)?;
                            }
                            Ok(())
                        })?;
                    }
                    if let Some(d) = domain {
                        e.visible_string(Tag::context(2), d)?;
                    }
                    Ok(())
                })?;
            }
            ConfirmedRequest::ReadJournal(r) => r.write(e)?,
            ConfirmedRequest::FileOpen { name, position } => {
                e.constructed(Tag::context_constructed(SERVICE_FILE_OPEN), |e| {
                    e.constructed(Tag::context_constructed(0), |e| {
                        name.write_contents(e);
                        Ok(())
                    })?;
                    e.unsigned(Tag::context(1), u64::from(*position))?;
                    Ok(())
                })?;
            }
            ConfirmedRequest::FileRead(id) => {
                e.integer(Tag::context(SERVICE_FILE_READ), i64::from(*id))?;
            }
            ConfirmedRequest::FileClose(id) => {
                e.integer(Tag::context(SERVICE_FILE_CLOSE), i64::from(*id))?;
            }
            ConfirmedRequest::FileDelete(name) => {
                e.constructed(Tag::context_constructed(SERVICE_FILE_DELETE), |e| {
                    name.write_contents(e);
                    Ok(())
                })?;
            }
            ConfirmedRequest::FileDirectory { specification, continue_after } => {
                e.constructed(Tag::context_constructed(SERVICE_FILE_DIRECTORY), |e| {
                    if let Some(n) = specification {
                        e.constructed(Tag::context_constructed(0), |e| {
                            n.write_contents(e);
                            Ok(())
                        })?;
                    }
                    if let Some(n) = continue_after {
                        e.constructed(Tag::context_constructed(1), |e| {
                            n.write_contents(e);
                            Ok(())
                        })?;
                    }
                    Ok(())
                })?;
            }
            ConfirmedRequest::Other(t) => {
                e.primitive(t.tag, t.value)?;
            }
        }
        Ok(())
    }
}

impl<'a> ConfirmedResponse<'a> {
    #[allow(clippy::too_many_lines)]
    fn parse(t: Tlv<'a>, limits: &Limits) -> Result<ConfirmedResponse<'a>> {
        if t.tag.class != Class::Context {
            return Err(Error::decode(DecodeReason::UnexpectedTag, t.offset));
        }
        Ok(match t.tag.number {
            SERVICE_STATUS => {
                let mut c = t.children();
                let logical = c.next_tag(Tag::context(0))?.integer_i64()?;
                let physical = c.next_tag(Tag::context(1))?.integer_i64()?;
                let local_detail = c.next_if_tag(Tag::context(2))?.map(|t| t.bit_string()).transpose()?;
                ConfirmedResponse::Status { logical, physical, local_detail }
            }
            SERVICE_GET_CAPABILITY_LIST => {
                let mut c = t.children();
                let list = c.next_tag(Tag::context_constructed(0))?;
                let mut capabilities = Vec::new();
                for cap in list.children() {
                    if capabilities.len() >= limits.max_list_items {
                        return Err(Error::LimitExceeded { limit: "max_list_items", value: capabilities.len() + 1 });
                    }
                    capabilities.push(cap?.expect(TAG_VISIBLE_STRING)?.visible_string()?);
                }
                let more_follows = c.next_if_tag(Tag::context(1))?.map(|t| t.boolean()).transpose()?.unwrap_or(true);
                ConfirmedResponse::GetCapabilityList { capabilities, more_follows }
            }
            1 => {
                let mut c = t.children();
                let list = c.next_tag(Tag::context_constructed(0))?;
                let mut identifiers = Vec::new();
                for id in list.children() {
                    // A name list is the whole namespace of a logical device, not a data
                    // set: `max_list_items`, or a real IED cannot be browsed at all.
                    if identifiers.len() >= limits.max_list_items {
                        return Err(Error::LimitExceeded { limit: "max_list_items", value: identifiers.len() + 1 });
                    }
                    identifiers.push(id?.expect(TAG_IDENTIFIER)?.visible_string()?);
                }
                let more_follows = c.next_if_tag(Tag::context(1))?.map(|t| t.boolean()).transpose()?.unwrap_or(true);
                ConfirmedResponse::GetNameList { identifiers, more_follows }
            }
            2 => {
                let mut c = t.children();
                let vendor = c.next_tag(Tag::context(0))?.visible_string()?;
                let model = c.next_tag(Tag::context(1))?.visible_string()?;
                let revision = c.next_tag(Tag::context(2))?.visible_string()?;
                ConfirmedResponse::Identify { vendor, model, revision }
            }
            4 => {
                let mut c = t.children();
                let access = match c.next_if_tag(Tag::context_constructed(0))? {
                    Some(a) => Some(VariableAccess::parse(&a.children().next_required()?)?),
                    None => None,
                };
                let results = parse_access_results(&c.next_tag(Tag::context_constructed(1))?, limits)?;
                ConfirmedResponse::Read { access, results }
            }
            5 => {
                let mut out = Vec::new();
                for r in t.children() {
                    let r = r?;
                    out.push(match r.tag.number {
                        0 => WriteResult::Failure(r.integer_i64()?),
                        _ => WriteResult::Success,
                    });
                }
                ConfirmedResponse::Write(out)
            }
            12 => {
                let mut c = t.children();
                let deletable = c.next_if_tag(Tag::context(0))?.map(|t| t.boolean()).transpose()?.unwrap_or(false);
                let variables = parse_variable_list(&c.next_tag(Tag::context_constructed(1))?, limits)?;
                ConfirmedResponse::GetNamedVariableListAttributes { deletable, variables }
            }
            SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES => {
                let mut c = t.children();
                let deletable = c.next_if_tag(Tag::context(0))?.map(|t| t.boolean()).transpose()?.unwrap_or(false);
                // `address [1]` is optional and nothing in IEC 61850 sends one; skipping it
                // by tag rather than by position is what keeps a server that does from
                // having its type specification read as an address.
                let _ = c.next_if_tag(Tag::context_constructed(1))?;
                let type_spec = TypeSpec::parse(&c.next_tag(Tag::context_constructed(2))?.children().next_required()?, limits)?;
                ConfirmedResponse::GetVariableAccessAttributes { deletable, type_spec }
            }
            SERVICE_DEFINE_NVL => ConfirmedResponse::DefineNamedVariableList,
            SERVICE_DELETE_NVL => {
                let mut c = t.children();
                let matched = c.next_tag(Tag::context(0))?.unsigned_lenient_u32()?;
                let deleted = c.next_tag(Tag::context(1))?.unsigned_lenient_u32()?;
                ConfirmedResponse::DeleteNamedVariableList { matched, deleted }
            }
            SERVICE_READ_JOURNAL => {
                let mut c = t.children();
                let list = c.next_tag(Tag::context_constructed(0))?;
                let mut entries = Vec::new();
                for entry in list.children() {
                    if entries.len() >= limits.max_list_items {
                        return Err(Error::LimitExceeded { limit: "max_list_items", value: entries.len() + 1 });
                    }
                    entries.push(JournalEntry::parse(&entry?, limits)?);
                }
                let more_follows = c.next_if_tag(Tag::context(1))?.map(|t| t.boolean()).transpose()?.unwrap_or(false);
                ConfirmedResponse::ReadJournal { entries, more_follows }
            }
            SERVICE_FILE_OPEN => {
                let mut c = t.children();
                let frsm_id = c.next_tag(Tag::context(0))?.integer_i32()?;
                let attributes = FileAttributes::parse(&c.next_tag(Tag::context_constructed(1))?)?;
                ConfirmedResponse::FileOpen { frsm_id, attributes }
            }
            SERVICE_FILE_READ => {
                let mut c = t.children();
                let data = c.next_tag(Tag::context(0))?.value;
                if data.len() > limits.max_primitive_len {
                    return Err(Error::LimitExceeded { limit: "max_primitive_len", value: data.len() });
                }
                // `moreFollows` is DEFAULT TRUE: a server that omits it has more to give.
                let more_follows = c.next_if_tag(Tag::context(1))?.map(|t| t.boolean()).transpose()?.unwrap_or(true);
                ConfirmedResponse::FileRead { data, more_follows }
            }
            SERVICE_FILE_CLOSE => ConfirmedResponse::FileClose,
            SERVICE_FILE_DELETE => ConfirmedResponse::FileDelete,
            SERVICE_FILE_DIRECTORY => {
                let mut c = t.children();
                let list = c.next_tag(Tag::context_constructed(0))?;
                let mut entries = Vec::new();
                for entry in file::directory_entries(&list) {
                    if entries.len() >= limits.max_list_items {
                        return Err(Error::LimitExceeded { limit: "max_list_items", value: entries.len() + 1 });
                    }
                    entries.push(DirectoryEntry::parse(&entry?, limits)?);
                }
                let more_follows = c.next_if_tag(Tag::context(1))?.map(|t| t.boolean()).transpose()?.unwrap_or(false);
                ConfirmedResponse::FileDirectory { entries, more_follows }
            }
            _ => ConfirmedResponse::Other(t),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn write(&self, e: &mut Encoder) -> Result<()> {
        match self {
            ConfirmedResponse::GetNameList { identifiers, more_follows } => {
                e.constructed(Tag::context_constructed(1), |e| {
                    e.constructed(Tag::context_constructed(0), |e| {
                        for id in identifiers {
                            e.visible_string(TAG_IDENTIFIER, id)?;
                        }
                        Ok(())
                    })?;
                    if !*more_follows {
                        e.boolean(Tag::context(1), false)?;
                    }
                    Ok(())
                })?;
            }
            ConfirmedResponse::Status { logical, physical, local_detail } => {
                e.constructed(Tag::context_constructed(SERVICE_STATUS), |e| {
                    e.integer(Tag::context(0), *logical)?;
                    e.integer(Tag::context(1), *physical)?;
                    if let Some((unused, bits)) = local_detail {
                        e.bit_string(Tag::context(2), *unused, bits)?;
                    }
                    Ok(())
                })?;
            }
            ConfirmedResponse::GetCapabilityList { capabilities, more_follows } => {
                e.constructed(Tag::context_constructed(SERVICE_GET_CAPABILITY_LIST), |e| {
                    e.constructed(Tag::context_constructed(0), |e| {
                        for c in capabilities {
                            e.visible_string(TAG_VISIBLE_STRING, c)?;
                        }
                        Ok(())
                    })?;
                    // `DEFAULT TRUE`, so only the false case is written — the same rule
                    // `GetNameList` follows two arms down.
                    if !*more_follows {
                        e.boolean(Tag::context(1), false)?;
                    }
                    Ok(())
                })?;
            }
            ConfirmedResponse::Identify { vendor, model, revision } => {
                e.constructed(Tag::context_constructed(2), |e| {
                    e.visible_string(Tag::context(0), vendor)?;
                    e.visible_string(Tag::context(1), model)?;
                    e.visible_string(Tag::context(2), revision)?;
                    Ok(())
                })?;
            }
            ConfirmedResponse::Read { access, results } => {
                e.constructed(Tag::context_constructed(4), |e| {
                    if let Some(a) = access {
                        e.constructed(Tag::context_constructed(0), |e| a.write(e))?;
                    }
                    write_access_results(results, Tag::context_constructed(1), e)
                })?;
            }
            ConfirmedResponse::Write(results) => {
                e.constructed(Tag::context_constructed(5), |e| {
                    for r in results {
                        match r {
                            WriteResult::Failure(code) => {
                                e.integer(Tag::context(0), *code)?;
                            }
                            WriteResult::Success => {
                                e.primitive(Tag::context(1), &[])?;
                            }
                        }
                    }
                    Ok(())
                })?;
            }
            ConfirmedResponse::GetNamedVariableListAttributes { deletable, variables } => {
                e.constructed(Tag::context_constructed(12), |e| {
                    e.boolean(Tag::context(0), *deletable)?;
                    write_variable_list(variables, Tag::context_constructed(1), e)
                })?;
            }
            ConfirmedResponse::GetVariableAccessAttributes { deletable, type_spec } => {
                e.constructed(Tag::context_constructed(SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES), |e| {
                    e.boolean(Tag::context(0), *deletable)?;
                    e.constructed(Tag::context_constructed(2), |e| type_spec.write(e))?;
                    Ok(())
                })?;
            }
            ConfirmedResponse::DefineNamedVariableList => {
                e.primitive(Tag::context(SERVICE_DEFINE_NVL), &[])?;
            }
            ConfirmedResponse::DeleteNamedVariableList { matched, deleted } => {
                e.constructed(Tag::context_constructed(SERVICE_DELETE_NVL), |e| {
                    e.unsigned(Tag::context(0), u64::from(*matched))?;
                    e.unsigned(Tag::context(1), u64::from(*deleted))?;
                    Ok(())
                })?;
            }
            ConfirmedResponse::ReadJournal { entries, more_follows } => {
                e.constructed(Tag::context_constructed(SERVICE_READ_JOURNAL), |e| {
                    e.constructed(Tag::context_constructed(0), |e| {
                        for entry in entries {
                            entry.write(e)?;
                        }
                        Ok(())
                    })?;
                    if *more_follows {
                        e.boolean(Tag::context(1), true)?;
                    }
                    Ok(())
                })?;
            }
            ConfirmedResponse::FileOpen { frsm_id, attributes } => {
                e.constructed(Tag::context_constructed(SERVICE_FILE_OPEN), |e| {
                    e.integer(Tag::context(0), i64::from(*frsm_id))?;
                    attributes.write(Tag::context_constructed(1), e)
                })?;
            }
            ConfirmedResponse::FileRead { data, more_follows } => {
                e.constructed(Tag::context_constructed(SERVICE_FILE_READ), |e| {
                    e.primitive(Tag::context(0), data)?;
                    // DEFAULT TRUE, so only `false` goes on the wire.
                    if !*more_follows {
                        e.boolean(Tag::context(1), false)?;
                    }
                    Ok(())
                })?;
            }
            ConfirmedResponse::FileClose => {
                e.primitive(Tag::context(SERVICE_FILE_CLOSE), &[])?;
            }
            ConfirmedResponse::FileDelete => {
                e.primitive(Tag::context(SERVICE_FILE_DELETE), &[])?;
            }
            ConfirmedResponse::FileDirectory { entries, more_follows } => {
                e.constructed(Tag::context_constructed(SERVICE_FILE_DIRECTORY), |e| {
                    // `listOfDirectoryEntry [0] SEQUENCE OF DirectoryEntry` is the one field
                    // of the file services that is **not** implicitly tagged ✅, so the
                    // entries live inside an inner universal SEQUENCE: `a0 { 30 { 30 … } }`.
                    // Writing them straight under `[0]` produces a response Wireshark and
                    // libiec61850 both call malformed — and it is invisible to a suite where
                    // the same codec decodes it again, which is why this has a Wireshark test.
                    e.constructed(Tag::context_constructed(0), |e| {
                        e.constructed(TAG_SEQUENCE, |e| {
                            for entry in entries {
                                entry.write(e)?;
                            }
                            Ok(())
                        })?;
                        Ok(())
                    })?;
                    if *more_follows {
                        e.boolean(Tag::context(1), true)?;
                    }
                    Ok(())
                })?;
            }
            ConfirmedResponse::Other(t) => {
                e.primitive(t.tag, t.value)?;
            }
        }
        Ok(())
    }
}

/// `invokeID` is `Unsigned32` in every PDU that carries one ✅ (`mms.asn`), so a negative or
/// oversized one is not an identifier any peer could have issued.
///
/// Accepting one has a specific cost: the answer has to *name* it, and a name outside the
/// field's range is one the answer cannot encode — leaving the client waiting for ever for a
/// response the server could not build. A PDU whose identifier is unusable is not a request
/// that can be answered at all, so it is refused here rather than patched at the encoder.
fn invoke_id_of(t: &Tlv<'_>) -> Result<i64> {
    let v = t.integer_i64()?;
    if (0..=i64::from(u32::MAX)).contains(&v) { Ok(v) } else { Err(Error::decode(DecodeReason::BadValue, t.value_offset)) }
}

impl<'a> Mms<'a> {
    /// The invoke identifier of a confirmed PDU, read **without** decoding its service.
    ///
    /// A response this codec cannot decode still answers the request it names: the peer has
    /// spoken and will say nothing more, so the caller has to fail now rather than wait out
    /// its whole request timeout on octets that have already arrived (D46). Reading the
    /// identifier is cheap and independent of everything after it — it is the first field of
    /// all four confirmed PDU types — so the failure can be attributed even when the rest is
    /// unreadable. `None` for an unconfirmed PDU, a reject, or bytes that are not a PDU at all.
    pub fn peek_invoke_id(buf: &[u8]) -> Option<i64> {
        let top = Cursor::new(buf).next_required().ok()?;
        if top.tag.class != Class::Context || !matches!(top.tag.number, 0 | 1 | 2 | 5) {
            return None;
        }
        let first = top.children().next()?.ok()?;
        // `confirmed-RequestPDU` and `confirmed-ResponsePDU` write it as a universal INTEGER;
        // `confirmed-ErrorPDU` and `cancel-*` tag it `[0]`.
        if first.tag != TAG_INTEGER && first.tag != Tag::context(0) {
            return None;
        }
        first.integer_i64().ok()
    }

    /// Decode an MMS PDU, enforcing `limits` on the lists inside it.
    pub fn parse(buf: &'a [u8], limits: &Limits) -> Result<Mms<'a>> {
        let top = Cursor::new(buf).next_required()?;
        if top.tag.class != Class::Context {
            return Err(Error::decode(DecodeReason::UnexpectedTag, top.offset));
        }
        Ok(match top.tag.number {
            0 => {
                let mut c = top.children();
                let invoke_id = invoke_id_of(&c.next_tag(TAG_INTEGER)?)?;
                // `listOfModifier` is a SEQUENCE OF and IEC 61850 never sends one; a peer
                // that does would put it here, so it is skipped rather than mistaken for
                // the service.
                let mut next = c.next_required()?;
                if next.tag == TAG_SEQUENCE {
                    next = c.next_required()?;
                }
                Mms::ConfirmedRequest { invoke_id, service: ConfirmedRequest::parse(next, limits)? }
            }
            1 => {
                let mut c = top.children();
                let invoke_id = invoke_id_of(&c.next_tag(TAG_INTEGER)?)?;
                Mms::ConfirmedResponse { invoke_id, service: ConfirmedResponse::parse(c.next_required()?, limits)? }
            }
            2 => {
                // `Confirmed-ErrorPDU ::= SEQUENCE { invokeID [0], modifierPosition [1]
                // OPTIONAL, serviceError [2] }`. The optional field has to be recognised by
                // its tag and *kept*: a decoder that skips "whatever comes first" swallows
                // the service error itself whenever that error is tagged [1], which is a PDU
                // that decodes and then cannot be re-encoded. The fuzzer found exactly that.
                let mut c = top.children();
                let invoke_id = invoke_id_of(&c.next_tag(Tag::context(0))?)?;
                let modifier_position = c.next_if_tag(Tag::context(1))?.map(|t| t.unsigned_lenient_u32()).transpose()?;
                let error = c.next_required()?;
                Mms::ConfirmedError { invoke_id, modifier_position, error }
            }
            3 => {
                let service = top.children().next_required()?;
                Mms::Unconfirmed(if service.tag == Tag::context_constructed(0) {
                    let mut c = service.children();
                    let access = VariableAccess::parse(&c.next_required()?)?;
                    let results = parse_access_results(&c.next_tag(Tag::context_constructed(0))?, limits)?;
                    Unconfirmed::InformationReport { access, results }
                } else {
                    Unconfirmed::Other(service)
                })
            }
            4 => Mms::Reject(Reject::parse(&top)?),
            5 => Mms::CancelRequest(invoke_id_of(&top)?),
            6 => Mms::CancelResponse(invoke_id_of(&top)?),
            7 => {
                let mut c = top.children();
                let invoke_id = invoke_id_of(&c.next_tag(Tag::context(0))?)?;
                Mms::CancelError { invoke_id, error: c.next_required()? }
            }
            8 => Mms::InitiateRequest(Initiate::parse(&top)?),
            9 => Mms::InitiateResponse(Initiate::parse(&top)?),
            10 => Mms::InitiateError(top),
            11 => Mms::ConcludeRequest,
            12 => Mms::ConcludeResponse,
            13 => Mms::ConcludeError(top),
            _ => Mms::Other(top),
        })
    }

    /// Encode into `out`.
    pub fn write(&self, out: &mut Encoder) -> Result<()> {
        match self {
            Mms::ConfirmedRequest { invoke_id, service } => {
                out.constructed(Tag::context_constructed(0), |e| {
                    e.integer(TAG_INTEGER, *invoke_id)?;
                    service.write(e)
                })?;
            }
            Mms::ConfirmedResponse { invoke_id, service } => {
                out.constructed(Tag::context_constructed(1), |e| {
                    e.integer(TAG_INTEGER, *invoke_id)?;
                    service.write(e)
                })?;
            }
            Mms::ConfirmedError { invoke_id, modifier_position, error } => {
                out.constructed(Tag::context_constructed(2), |e| {
                    e.integer(Tag::context(0), *invoke_id)?;
                    if let Some(p) = modifier_position {
                        e.unsigned(Tag::context(1), u64::from(*p))?;
                    }
                    e.primitive(error.tag, error.value)?;
                    Ok(())
                })?;
            }
            Mms::Unconfirmed(service) => {
                out.constructed(Tag::context_constructed(3), |e| match service {
                    Unconfirmed::InformationReport { access, results } => e
                        .constructed(Tag::context_constructed(0), |e| {
                            access.write(e)?;
                            write_access_results(results, Tag::context_constructed(0), e)
                        })
                        .map(|_| ()),
                    Unconfirmed::Other(t) => e.primitive(t.tag, t.value).map(|_| ()),
                })?;
            }
            Mms::CancelRequest(invoke_id) => {
                out.unsigned(Tag::context(5), u64::try_from(*invoke_id).unwrap_or(0))?;
            }
            Mms::CancelResponse(invoke_id) => {
                out.unsigned(Tag::context(6), u64::try_from(*invoke_id).unwrap_or(0))?;
            }
            Mms::CancelError { invoke_id, error } => {
                out.constructed(Tag::context_constructed(7), |e| {
                    e.unsigned(Tag::context(0), u64::try_from(*invoke_id).unwrap_or(0))?;
                    e.primitive(error.tag, error.value)?;
                    Ok(())
                })?;
            }
            Mms::InitiateRequest(i) => i.write(Tag::context_constructed(8), out)?,
            Mms::InitiateResponse(i) => i.write(Tag::context_constructed(9), out)?,
            Mms::ConcludeRequest => {
                out.primitive(Tag::context(11), &[])?;
            }
            Mms::ConcludeResponse => {
                out.primitive(Tag::context(12), &[])?;
            }
            Mms::Reject(r) => r.write(out)?,
            Mms::InitiateError(t) | Mms::ConcludeError(t) | Mms::Other(t) => {
                out.primitive(t.tag, t.value)?;
            }
        }
        Ok(())
    }

    /// Encode into a new buffer.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        self.write(&mut e)?;
        Ok(e.into_vec())
    }

    /// The invoke identifier, for the PDUs that carry one.
    pub fn invoke_id(&self) -> Option<i64> {
        match self {
            Mms::ConfirmedRequest { invoke_id, .. } | Mms::ConfirmedResponse { invoke_id, .. } | Mms::ConfirmedError { invoke_id, .. } => Some(*invoke_id),
            // A cancel names the request it withdraws, which is what an invoke-tracking peer
            // has to release — the cancel itself is not a request and has no number.
            Mms::CancelRequest(id) | Mms::CancelResponse(id) | Mms::CancelError { invoke_id: id, .. } => Some(*id),
            // A reject names the request it rejects, which is what makes it an answer.
            Mms::Reject(r) => r.original_invoke_id,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    /// A name list is the namespace of a whole logical device, not a data set.
    ///
    /// libiec61850's own `LTRK` test model has 643 names in one device, and every real IED has
    /// more. Applying the data-set limit here made the client refuse a page of them — and,
    /// because a refused answer used to leave the request outstanding, report that the server
    /// had never replied. The bound that matters is the reassembled TSDU, which is enforced a
    /// layer down; `max_list_items` is what says so at the decoder.
    #[test]
    fn a_name_list_may_be_larger_than_a_data_set() {
        use crate::ber::{Encoder, Tag};
        use alloc::string::String;
        use alloc::vec::Vec;

        let names: Vec<String> = (0..2_000).map(|i| alloc::format!("GGIO1$ST$Ind{i}$stVal")).collect();
        let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
        let pdu = Mms::ConfirmedResponse { invoke_id: 1, service: ConfirmedResponse::GetNameList { identifiers: borrowed, more_follows: false } }
            .to_vec()
            .expect("encode");
        match Mms::parse(&pdu, &Limits::DEFAULT).expect("a real device's namespace decodes") {
            Mms::ConfirmedResponse { service: ConfirmedResponse::GetNameList { identifiers, .. }, .. } => assert_eq!(identifiers.len(), 2_000),
            other => panic!("not a name list: {other:?}"),
        }
        // It is still bounded: the limit is generous, not absent.
        let tight = Limits { max_list_items: 100, ..Limits::DEFAULT };
        assert!(matches!(Mms::parse(&pdu, &tight), Err(Error::LimitExceeded { limit: "max_list_items", .. })));

        // …and a *data set* is still held to the data-set limit, which is the whole reason
        // the two are separate numbers: an engineered list of 600 members is a file to fix,
        // a namespace of 2 000 names is an ordinary IED.
        let mut e = Encoder::new();
        e.constructed(Tag::universal(universal::SEQUENCE, true), |e| {
            for _ in 0..600 {
                e.constructed(Tag::universal(universal::SEQUENCE, true), |e| {
                    e.constructed(Tag::context_constructed(0), |e| {
                        e.constructed(Tag::context_constructed(1), |e| {
                            e.visible_string(TAG_IDENTIFIER, "IED1LD0")?;
                            e.visible_string(TAG_IDENTIFIER, "GGIO1$ST$Ind1$stVal")?;
                            Ok(())
                        })?;
                        Ok(())
                    })?;
                    Ok(())
                })?;
            }
            Ok(())
        })
        .unwrap();
        let list = e.into_vec();
        let tlv = Cursor::new(&list).next_required().unwrap();
        assert!(matches!(parse_variable_list(&tlv, &Limits::DEFAULT), Err(Error::LimitExceeded { limit: "max_dataset_members", .. })));
    }

    /// `invokeID` is `Unsigned32` in every PDU that carries one. A negative one is not an
    /// identifier a peer could have issued — and accepting it made the *answer* unencodable,
    /// because a reject has to name it and `originalInvokeID` is `Unsigned32` too. A request
    /// a server cannot answer at all is worse than any error response, which is why the
    /// `mms_server` fuzz target asserts it and why this is refused at the decoder.
    #[test]
    fn an_invoke_identifier_outside_unsigned32_is_not_a_pdu() {
        // `a0 05 02 01 ff 9b 00` — confirmed request, invokeID −1, an unknown service.
        let wire = [0xA0u8, 0x05, 0x02, 0x01, 0xFF, 0x9B, 0x00];
        assert!(Mms::parse(&wire, &Limits::DEFAULT).is_err(), "invokeID −1");

        // Five octets above `u32::MAX`.
        let wire = [0xA0u8, 0x09, 0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x9B, 0x00];
        assert!(Mms::parse(&wire, &Limits::DEFAULT).is_err(), "invokeID above u32::MAX");

        // The whole legal range is still a request.
        for id in [0u32, 1, 0x7FFF_FFFF, u32::MAX] {
            let pdu = Mms::ConfirmedRequest { invoke_id: i64::from(id), service: ConfirmedRequest::Identify };
            let bytes = pdu.to_vec().unwrap();
            let back = Mms::parse(&bytes, &Limits::DEFAULT).unwrap();
            assert_eq!(back.invoke_id(), Some(i64::from(id)), "{id}");
        }
    }

    use super::*;
    use crate::proto::data::Typed;
    use file::{DirectoryEntry, FileAttributes};

    fn round_trip(wire: &[u8]) -> Mms<'_> {
        let pdu = Mms::parse(wire, &Limits::DEFAULT).expect("decode");
        assert_eq!(pdu.to_vec().expect("encode"), wire, "re-encoding must reproduce the octets");
        pdu
    }

    #[test]
    fn a_service_error_tagged_like_a_modifier_position_still_re_encodes() {
        // Found by `cargo fuzz run mms_stack`: the decoder skipped "whatever comes after the
        // invoke identifier if it is [1]", so a `Confirmed-ErrorPDU` whose *serviceError*
        // carried tag [1] decoded fine and then re-encoded into something that would not
        // decode at all. The field is optional and has to be recognised, not guessed past.
        // invokeID 7, modifierPosition 2, serviceError { errorClass access(7) = 10 } —
        // which is what a server answers when a client asks for a reference it does not have.
        let wire: &[u8] = &[0xA2, 0x0D, 0x80, 0x01, 0x07, 0x81, 0x01, 0x02, 0xA2, 0x05, 0xA0, 0x03, 0x87, 0x01, 0x0A];
        let pdu = Mms::parse(wire, &Limits::DEFAULT).expect("decode");
        let Mms::ConfirmedError { invoke_id, modifier_position, error } = pdu else {
            panic!("not a confirmed error");
        };
        assert_eq!((invoke_id, modifier_position), (7, Some(2)));
        assert_eq!(error.tag, Tag::context_constructed(2), "the service error is [2], not `whatever is next`");
        let re = pdu.to_vec().expect("encode");
        assert_eq!(re, wire, "and it re-encodes byte for byte");
        assert_eq!(Mms::parse(&re, &Limits::DEFAULT).expect("re-decode").to_vec().expect("re-encode"), re);

        // The exact shape the fuzzer produced: a modifier position too wide for the field.
        let bad: &[u8] = &[130, 18, 128, 4, 2, 3, 42, 2, 129, 8, 0, 128, 4, 0, 0, 239, 255, 255, 129, 0, 0];
        assert!(Mms::parse(bad, &Limits::DEFAULT).is_err(), "a 64-bit modifier position is not one");

        // And the service error itself decodes into something a client can act on.
        let e = ServiceError::parse(&error).expect("service error");
        assert_eq!((e.class, e.code, e.additional), (7, 10, None), "access error, object-non-existent");
    }

    #[test]
    fn the_reference_initiate_request_round_trips() {
        // Frame 11 of the reference capture: the MMS PDU inside the AARQ.
        let wire: &[u8] = &[
            0xA8, 0x25, // initiate-RequestPDU
            0x80, 0x02, 0x7D, 0x00, // localDetailCalling 32000
            0x81, 0x01, 0x14, // proposedMaxServOutstandingCalling 20
            0x82, 0x01, 0x14, // proposedMaxServOutstandingCalled 20
            0x83, 0x01, 0x04, // proposedDataStructureNestingLevel 4
            0xA4, 0x16, // mmsInitRequestDetail
            0x80, 0x01, 0x01, // proposedVersionNumber 1
            0x81, 0x03, 0x05, 0xFB, 0x00, // proposedParameterCBB
            0x82, 0x0C, 0x03, 0x6E, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x01, 0x98, // servicesSupportedCalling
        ];
        let Mms::InitiateRequest(i) = round_trip(wire) else { panic!("not an initiate request") };
        assert_eq!(i.local_detail, Some(32_000));
        assert_eq!((i.max_serv_outstanding_calling, i.max_serv_outstanding_called), (20, 20));
        assert_eq!(i.data_structure_nesting_level, Some(4));
        assert_eq!(i.version, 1);
        assert_eq!(i.parameter_cbb, (5, &[0xFB, 0x00][..]));
    }

    #[test]
    fn the_reference_identify_request_round_trips() {
        // Frame 17: `a0 06 02 02 11 4f 82 00` — a confirmed request whose service is a
        // two-octet empty SEQUENCE. The whole PDU is eight octets.
        let wire: &[u8] = &[0xA0, 0x06, 0x02, 0x02, 0x11, 0x4F, 0x82, 0x00];
        let pdu = round_trip(wire);
        assert_eq!(pdu.invoke_id(), Some(4431));
        assert!(matches!(pdu, Mms::ConfirmedRequest { service: ConfirmedRequest::Identify, .. }));
    }

    /// `listOfDirectoryEntry [0]` is the one file-service field that is **not** implicitly
    /// tagged, so the entries sit inside an inner universal `SEQUENCE`.
    ///
    /// Both halves of this crate had it wrong in the same way and therefore agreed with each
    /// other, which is precisely the failure the Wireshark oracle exists to catch — it did,
    /// on its first run (`tests/tshark_mms.rs`). The octets asserted here are the shape
    /// `mms.asn` states ✅ and libiec61850 writes 🌐: `bf 4d { a0 { 30 { 30 … } } }`.
    #[test]
    fn a_file_directory_response_wraps_its_entries_in_a_sequence() {
        let response = ConfirmedResponse::FileDirectory {
            entries: alloc::vec![DirectoryEntry {
                name: FileName::from_encoded(&[0x19, 0x01, b'a']),
                attributes: FileAttributes { size: 7, last_modified: None },
            }],
            more_follows: false,
        };
        let mut e = Encoder::new();
        Mms::ConfirmedResponse { invoke_id: 1, service: response }.write(&mut e).expect("encode");
        let bytes = e.into_vec();
        // Walk the encoding: response ▸ fileDirectory [77] ▸ listOfDirectoryEntry [0] ▸ the
        // inner `SEQUENCE OF` ▸ one `DirectoryEntry` ▸ its `filename [0]`.
        let mut c = Cursor::new(&bytes).next_required().expect("pdu").children();
        c.next_required().expect("invokeID");
        let service = c.next_tag(Tag::context_constructed(SERVICE_FILE_DIRECTORY)).expect("fileDirectory");
        let list = service.children().next_tag(Tag::context_constructed(0)).expect("listOfDirectoryEntry");
        let inner = list.children().next_required().expect("the SEQUENCE OF");
        assert_eq!(inner.tag, TAG_SEQUENCE, "`listOfDirectoryEntry [0]` is not implicitly tagged");
        let entry = inner.children().next_required().expect("one entry");
        assert_eq!(entry.tag, TAG_SEQUENCE);
        assert_eq!(entry.children().next_required().expect("filename").tag, Tag::context_constructed(0));

        let back = Mms::parse(&bytes, &Limits::DEFAULT).expect("decode");
        let Mms::ConfirmedResponse { service: ConfirmedResponse::FileDirectory { entries, .. }, .. } = &back else { panic!("not a file directory") };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name.display(), "a");
        assert_eq!(entries[0].attributes.size, 7);
        assert_eq!(back.to_vec().expect("re-encode"), bytes);

        // A server that tagged it implicitly is still read, because refusing a peer over a
        // tag we can tell apart would be refusing its file listing for nothing.
        let mut implicit = Encoder::new();
        implicit
            .constructed(Tag::context_constructed(2), |e| {
                e.integer(TAG_INTEGER, 1)?;
                e.constructed(Tag::context_constructed(SERVICE_FILE_DIRECTORY), |e| {
                    e.constructed(Tag::context_constructed(0), |e| {
                        e.constructed(TAG_SEQUENCE, |e| {
                            e.constructed(Tag::context_constructed(0), |e| {
                                e.primitive(file::TAG_GRAPHIC_STRING, b"a")?;
                                Ok(())
                            })?;
                            e.constructed(Tag::context_constructed(1), |e| {
                                e.unsigned(Tag::context(0), 7)?;
                                Ok(())
                            })?;
                            Ok(())
                        })?;
                        Ok(())
                    })?;
                    Ok(())
                })?;
                Ok(())
            })
            .expect("encode");
        let mut implicit = implicit.into_vec();
        implicit[0] = 0xA1; // a confirmed *response*
        let back = Mms::parse(&implicit, &Limits::DEFAULT).expect("decode the implicit spelling");
        let Mms::ConfirmedResponse { service: ConfirmedResponse::FileDirectory { entries, .. }, .. } = back else { panic!("not a file directory") };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name.display(), "a");
    }

    #[test]
    fn the_reference_read_request_names_a_domain_variable() {
        // Frame 20, trimmed to one variable: read a domain-specific name.
        let wire: &[u8] = &[
            0xA0, 0x30, // confirmed-RequestPDU
            0x02, 0x02, 0x11, 0x50, // invokeID 4432
            0xA4, 0x2A, // read
            0xA1, 0x28, // variableAccessSpecification
            0xA0, 0x26, // listOfVariable
            0x30, 0x24, // SEQUENCE
            0xA0, 0x22, // variableSpecification: name
            0xA1, 0x20, // domain-specific
            0x1A, 0x08, b'K', b'I', b'R', b'K', b'L', b'A', b'N', b'D', //
            0x1A, 0x14, b'B', b'i', b'l', b'a', b't', b'e', b'r', b'a', b'l', b'_', b'T', b'a', b'b', b'l', b'e', b'_', b'I', b'D', b'0', b'1',
        ];
        let pdu = round_trip(wire);
        let Mms::ConfirmedRequest { invoke_id, service: ConfirmedRequest::Read { access, specification_with_result } } = pdu else { panic!("not a read") };
        assert_eq!(invoke_id, 4432);
        assert!(!specification_with_result);
        let VariableAccess::ListOfVariable(vars) = access else { panic!("not a list") };
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], VariableSpecification::Name(ObjectName::DomainSpecific { domain: "KIRKLAND", item: "Bilateral_Table_ID01" }));
    }

    #[test]
    fn an_information_report_carries_a_data_set_and_its_values() {
        // The shape of frame 68: a report about a named variable list, with a structure and
        // a floating point in it — decoded by the same `Data` codec GOOSE uses.
        let wire: &[u8] = &[
            0xA3, 0x2B, // unconfirmed-PDU
            0xA0, 0x29, // informationReport
            0xA1, 0x18, // variableAccessSpecification: variableListName
            0xA1, 0x16, // domain-specific
            0x1A, 0x08, b'K', b'I', b'R', b'K', b'L', b'A', b'N', b'D', //
            0x1A, 0x0A, b'E', b'M', b'S', b'_', b'A', b'N', b'A', b'L', b'O', b'G', //
            0xA0, 0x0D, // listOfAccessResult
            0x86, 0x01, 0x01, // unsigned 1
            0x87, 0x05, 0x08, 0x3F, 0x80, 0x00, 0x00, // floating point 1.0
            0x80, 0x01, 0x0A, // failure: object-non-existent
        ];
        let Mms::Unconfirmed(Unconfirmed::InformationReport { access, results }) = round_trip(wire) else { panic!("not a report") };
        assert_eq!(access, VariableAccess::VariableListName(ObjectName::DomainSpecific { domain: "KIRKLAND", item: "EMS_ANALOG" }));
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].value().and_then(|d| d.as_u64()), Some(1));
        assert_eq!(results[1].value().and_then(|d| d.as_f64()), Some(1.0));
        assert_eq!(results[2], AccessResult::Failure(10));
    }

    #[test]
    fn a_read_response_and_a_write_round_trip() {
        let read: &[u8] = &[
            0xA1, 0x0D, // confirmed-ResponsePDU
            0x02, 0x01, 0x07, // invokeID 7
            0xA4, 0x08, // read
            0xA1, 0x06, // listOfAccessResult
            0x83, 0x01, 0xFF, // boolean true
            0x80, 0x01, 0x03, // failure: object-access-denied
        ];
        let Mms::ConfirmedResponse { service: ConfirmedResponse::Read { results, access }, .. } = round_trip(read) else { panic!() };
        assert!(access.is_none());
        assert_eq!(results[0].value().and_then(|d| d.as_bool()), Some(true));
        assert_eq!(results[1], AccessResult::Failure(3));

        let write: &[u8] = &[
            0xA1, 0x0A, // confirmed-ResponsePDU
            0x02, 0x01, 0x08, //
            0xA5, 0x05, // write
            0x81, 0x00, // success
            0x80, 0x01, 0x02, // failure: temporarily-unavailable
        ];
        let Mms::ConfirmedResponse { service: ConfirmedResponse::Write(results), .. } = round_trip(write) else { panic!() };
        assert_eq!(results, [WriteResult::Success, WriteResult::Failure(2)]);
    }

    #[test]
    fn get_name_list_round_trips_in_both_directions() {
        let request: &[u8] = &[
            0xA0, 0x14, //
            0x02, 0x01, 0x01, //
            0xA1, 0x0F, // getNameList
            0xA0, 0x03, 0x80, 0x01, 0x09, // objectClass: domain
            0xA1, 0x08, 0x81, 0x06, b'L', b'D', b'0', b'/', b'L', b'N', // scope: domain-specific
        ];
        let Mms::ConfirmedRequest { service: ConfirmedRequest::GetNameList { object_class, scope, continue_after }, .. } = round_trip(request) else {
            panic!()
        };
        assert_eq!(object_class, 9);
        assert_eq!(scope, ObjectScope::DomainSpecific("LD0/LN"));
        assert!(continue_after.is_none());

        let response: &[u8] = &[
            0xA1, 0x0E, //
            0x02, 0x01, 0x01, //
            0xA1, 0x09, // getNameList
            0xA0, 0x07, 0x1A, 0x02, b'L', b'D', 0x1A, 0x01, b'X', //
        ];
        let Mms::ConfirmedResponse { service: ConfirmedResponse::GetNameList { identifiers, more_follows }, .. } = round_trip(response) else { panic!() };
        assert_eq!(identifiers, ["LD", "X"]);
        assert!(more_follows, "the field is DEFAULT TRUE, so its absence means more");
    }

    #[test]
    fn an_unmodelled_service_keeps_its_octets() {
        // `defineNamedVariable [7]` is not decoded here, and must still survive a decode and
        // a re-encode without losing an octet.
        let wire: &[u8] = &[0xA0, 0x09, 0x02, 0x01, 0x05, 0xA7, 0x04, 0xA0, 0x02, 0x80, 0x00];
        let pdu = round_trip(wire);
        assert!(matches!(pdu, Mms::ConfirmedRequest { service: ConfirmedRequest::Other(_), .. }));
    }

    #[test]
    fn conclude_and_errors_round_trip() {
        assert_eq!(round_trip(&[0x8B, 0x00]), Mms::ConcludeRequest);
        assert_eq!(round_trip(&[0x8C, 0x00]), Mms::ConcludeResponse);
        let err: &[u8] = &[0xA2, 0x08, 0x80, 0x01, 0x07, 0xA2, 0x03, 0x80, 0x01, 0x0B];
        let Mms::ConfirmedError { invoke_id, .. } = round_trip(err) else { panic!() };
        assert_eq!(invoke_id, 7);
    }

    #[test]
    fn the_file_services_round_trip_through_the_high_tag_number_form() {
        // Everything above service 30 uses the long identifier form: `fileOpen [72]` is
        // `BF 48`, and `fileRead [73]` is an `Integer32`, so it is *primitive*: `9F 49`.
        let name = file::FileNameBuf::from_path("COMTRADE/rec1.cfg").unwrap();
        let open = Mms::ConfirmedRequest { invoke_id: 1, service: ConfirmedRequest::FileOpen { name: name.as_name(), position: 0 } };
        let bytes = open.to_vec().unwrap();
        assert!(bytes.windows(2).any(|w| w == [0xBF, 0x48]), "fileOpen is [72] in the high-tag-number form: {bytes:02X?}");
        assert_eq!(round_trip(&bytes), open);

        let read = Mms::ConfirmedRequest { invoke_id: 2, service: ConfirmedRequest::FileRead(9) };
        let bytes = read.to_vec().unwrap();
        assert!(bytes.ends_with(&[0x9F, 0x49, 0x01, 0x09]), "fileRead is a primitive Integer32: {bytes:02X?}");
        assert_eq!(round_trip(&bytes), read);

        for service in [
            ConfirmedRequest::FileClose(9),
            ConfirmedRequest::FileDelete(name.as_name()),
            ConfirmedRequest::FileDirectory { specification: Some(name.as_name()), continue_after: None },
            ConfirmedRequest::FileDirectory { specification: None, continue_after: None },
        ] {
            let pdu = Mms::ConfirmedRequest { invoke_id: 3, service };
            assert_eq!(round_trip(&pdu.to_vec().unwrap()), pdu);
        }

        let answer = Mms::ConfirmedResponse {
            invoke_id: 1,
            service: ConfirmedResponse::FileOpen { frsm_id: 9, attributes: FileAttributes { size: 4096, last_modified: Some("20240131T101500Z") } },
        };
        assert_eq!(round_trip(&answer.to_vec().unwrap()), answer);

        // `moreFollows` is DEFAULT TRUE on a file read, so only `false` is on the wire — and
        // a server that omits it has more to give, which is the direction that matters.
        let last = Mms::ConfirmedResponse { invoke_id: 1, service: ConfirmedResponse::FileRead { data: &[1, 2, 3], more_follows: false } };
        let last_bytes = last.to_vec().unwrap();
        assert_eq!(round_trip(&last_bytes), last);
        let more = Mms::ConfirmedResponse { invoke_id: 1, service: ConfirmedResponse::FileRead { data: &[1, 2, 3], more_follows: true } };
        let more_bytes = more.to_vec().unwrap();
        assert!(more_bytes.len() < last_bytes.len(), "the default is not written");
        assert_eq!(round_trip(&more_bytes), more);

        let dir = Mms::ConfirmedResponse {
            invoke_id: 1,
            service: ConfirmedResponse::FileDirectory {
                entries: alloc::vec![DirectoryEntry { name: name.as_name(), attributes: FileAttributes { size: 12, last_modified: None } }],
                more_follows: true,
            },
        };
        let dir_bytes = dir.to_vec().unwrap();
        let back = round_trip(&dir_bytes);
        let Mms::ConfirmedResponse { service: ConfirmedResponse::FileDirectory { entries, more_follows }, .. } = back else { panic!() };
        assert!(more_follows);
        assert_eq!(entries[0].name.display(), "COMTRADE/rec1.cfg");
        assert_eq!(entries[0].attributes.size, 12);
    }

    #[test]
    fn a_data_set_is_created_and_deleted_by_name() {
        let members = alloc::vec![
            VariableSpecification::Name(ObjectName::DomainSpecific { domain: "IED1LD0", item: "PTRC1$ST$Tr$general" }),
            VariableSpecification::Name(ObjectName::DomainSpecific { domain: "IED1LD0", item: "PTRC1$ST$Tr$q" }),
        ];
        let create = Mms::ConfirmedRequest {
            invoke_id: 1,
            service: ConfirmedRequest::DefineNamedVariableList {
                name: ObjectName::DomainSpecific { domain: "IED1LD0", item: "LLN0$dsTemp" },
                variables: members,
            },
        };
        assert_eq!(round_trip(&create.to_vec().unwrap()), create);
        assert_eq!(
            round_trip(&Mms::ConfirmedResponse { invoke_id: 1, service: ConfirmedResponse::DefineNamedVariableList }.to_vec().unwrap()),
            Mms::ConfirmedResponse { invoke_id: 1, service: ConfirmedResponse::DefineNamedVariableList }
        );

        let delete = Mms::ConfirmedRequest {
            invoke_id: 2,
            service: ConfirmedRequest::DeleteNamedVariableList {
                scope: delete_scope::SPECIFIC,
                names: alloc::vec![ObjectName::DomainSpecific { domain: "IED1LD0", item: "LLN0$dsTemp" }],
                domain: None,
            },
        };
        // `scopeOfDelete` is DEFAULT specific, so the default is not written.
        assert_eq!(round_trip(&delete.to_vec().unwrap()), delete);
        let by_domain = Mms::ConfirmedRequest {
            invoke_id: 3,
            service: ConfirmedRequest::DeleteNamedVariableList { scope: delete_scope::DOMAIN, names: Vec::new(), domain: Some("IED1LD0") },
        };
        assert_eq!(round_trip(&by_domain.to_vec().unwrap()), by_domain);

        // "matched but not deleted" is the answer for a list the client may not delete, and
        // it is the difference between "gone" and "refused".
        let answer = Mms::ConfirmedResponse { invoke_id: 2, service: ConfirmedResponse::DeleteNamedVariableList { matched: 1, deleted: 0 } };
        assert_eq!(round_trip(&answer.to_vec().unwrap()), answer);
    }

    #[test]
    fn a_type_is_asked_for_by_name_and_comes_back_as_a_shape() {
        let ask = Mms::ConfirmedRequest {
            invoke_id: 1,
            service: ConfirmedRequest::GetVariableAccessAttributes(ObjectName::DomainSpecific { domain: "IED1LD0", item: "MMXU1$MX$TotW$mag$f" }),
        };
        let bytes = ask.to_vec().unwrap();
        // `A6 { A0 { A1 { domain, item } } }`: the service tag, the `name [0]` choice, and
        // the `domain-specific [1]` choice inside it — three explicit layers, not one.
        assert!(bytes.windows(4).any(|w| w[0] == 0xA6 && w[2] == 0xA0), "[6] is explicit and wraps the `name [0]` choice: {bytes:02X?}");
        assert_eq!(round_trip(&bytes), ask);

        let answer = Mms::ConfirmedResponse {
            invoke_id: 1,
            service: ConfirmedResponse::GetVariableAccessAttributes {
                deletable: false,
                type_spec: TypeSpec::FloatingPoint { format_width: 32, exponent_width: 8 },
            },
        };
        assert_eq!(round_trip(&answer.to_vec().unwrap()), answer);
    }

    #[test]
    fn a_log_is_read_by_time_and_resumed_after_an_entry() {
        use journal::{AfterEntry, JournalEntry, JournalVariable, RangeStop, TimeOfDay};

        let log = ObjectName::DomainSpecific { domain: "IED1LD0", item: "LLN0$GeneralLog" };
        let from = TimeOfDay::from_unix_millis(1_700_000_000_000);
        let by_time = Mms::ConfirmedRequest { invoke_id: 1, service: ConfirmedRequest::ReadJournal(ReadJournal::by_time(log, from, None)) };
        let bytes = by_time.to_vec().unwrap();
        assert!(bytes.windows(2).any(|w| w == [0xBF, 0x41]), "readJournal is [65]: {bytes:02X?}");
        assert_eq!(round_trip(&bytes), by_time);

        let mut bounded = ReadJournal::by_time(log, from, Some(TimeOfDay::from_unix_millis(1_700_000_060_000)));
        bounded.stop = Some(RangeStop::Count(100));
        bounded.variables = alloc::vec!["IED1LD0/LLN0$ST$Mod$stVal"];
        let pdu = Mms::ConfirmedRequest { invoke_id: 2, service: ConfirmedRequest::ReadJournal(bounded) };
        assert_eq!(round_trip(&pdu.to_vec().unwrap()), pdu);

        let after = Mms::ConfirmedRequest {
            invoke_id: 3,
            service: ConfirmedRequest::ReadJournal(ReadJournal::after_entry(log, AfterEntry { time: from, entry_id: &[1, 2, 3, 4, 5, 6, 7, 8] })),
        };
        assert_eq!(round_trip(&after.to_vec().unwrap()), after);

        // And an answer: one entry with one value, plus an annotation-only entry.
        let value_bytes = crate::proto::data::Value::encode_all(&[crate::proto::data::Value::Boolean(true)]).unwrap();
        let value = Cursor::new(&value_bytes).next_required().unwrap();
        let answer = Mms::ConfirmedResponse {
            invoke_id: 1,
            service: ConfirmedResponse::ReadJournal {
                entries: alloc::vec![
                    JournalEntry::new(&[0, 0, 0, 0, 0, 0, 0, 1], from, alloc::vec![JournalVariable { tag: "IED1LD0/LLN0$ST$Mod$stVal", value }]),
                    JournalEntry::annotated(&[0, 0, 0, 0, 0, 0, 0, 2], from, "power up"),
                ],
                more_follows: false,
            },
        };
        let answer_bytes = answer.to_vec().unwrap();
        let back = round_trip(&answer_bytes);
        let Mms::ConfirmedResponse { service: ConfirmedResponse::ReadJournal { entries, .. }, .. } = back else { panic!() };
        assert_eq!(entries[0].variables[0].tag, "IED1LD0/LLN0$ST$Mod$stVal");
        assert_eq!(entries[0].variables[0].value().and_then(|v| Typed::as_bool(&v)), Some(true));
        assert_eq!(entries[1].annotation, Some("power up"));
        assert_eq!(entries[1].occurred, from);
    }

    #[test]
    fn truncation_is_an_error_not_a_panic() {
        let wire: &[u8] = &[
            0xA3, 0x2B, 0xA0, 0x29, 0xA1, 0x18, 0xA1, 0x16, 0x1A, 0x08, b'K', b'I', b'R', b'K', b'L', b'A', b'N', b'D', 0x1A, 0x0A, b'E', b'M', b'S', b'_',
            b'A', b'N', b'A', b'L', b'O', b'G', 0xA0, 0x0D, 0x86, 0x01, 0x01, 0x87, 0x05, 0x08, 0x3F, 0x80, 0x00, 0x00, 0x80, 0x01, 0x0A,
        ];
        for cut in 0..wire.len() {
            let _ = Mms::parse(&wire[..cut], &Limits::DEFAULT);
        }
        assert!(Mms::parse(&[], &Limits::DEFAULT).is_err());
        assert!(Mms::parse(&[0x30, 0x00], &Limits::DEFAULT).is_err(), "a SEQUENCE is not an MMS PDU");
    }
}
