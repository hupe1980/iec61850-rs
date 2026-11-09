+++
title = "SCL and the IED model"
description = "Load an IEC 61850-6 SCL file — ICD, CID or SCD — into an IED model in Rust, resolve what an IED subscribes to, catch errors the XML schema permits, and edit the file without reformatting it."
weight = 50

[extra]
nav_title = "SCL"
+++

SCL is the XML that describes a substation: which IEDs exist, what data each holds, which
data sets they publish, and on which addresses. The library configures servers, publishers,
subscribers and clients from it.

## Loading

```rust
use iec61850_rs::model::IedModel;

let model = IedModel::from_scl_file("relay.icd", Some("IED1"))?;
// Or from a string, with None for the first/only IED:
let model = IedModel::from_scl(&xml, None)?;
```

The loader reads ICD, IID, CID and SCD files, schema versions 2003 through 2007B4. It matches
elements by local name, so a file with unusual namespace prefixes still loads.

The model:

```rust
for ld in &model.logical_devices {                     // IED1LD0, or an explicit ldName
    for ln in &ld.logical_nodes {                      // LLN0, PTRC1, MMXU1 …
        for ds in &ln.data_sets { /* FCDA members */ }
        for gcb in &ln.gse_controls { /* GOOSE control blocks */ }
        for cb in &ln.smv_controls { /* sampled-value control blocks */ }
        for rcb in &ln.report_controls { /* buffered and unbuffered reports */ }
    }
}
```

## Lenient by default

Real SCL files reference types they never define (OpenSCD's `valid2007B4.scd` does). By
default, what cannot be resolved is skipped and recorded as a diagnostic, and the rest loads.

```rust
let model = IedModel::from_scl(&xml, Some("IED1"))?;
for d in &model.diagnostics {
    println!("{d}");   // MissingLNodeType at IED2/LD0/THARDE1: LNodeType `Dummy.THARDE` not found
}
```

Every diagnostic carries a **stable code** you can match on, and an SCL path saying where:

| Code | Meaning |
|---|---|
| `MissingLNodeType` | An LN references a type the file does not define; loaded with no data objects |
| `MissingDOType` / `MissingDAType` | A DO or a `Struct` attribute references a missing type |
| `MissingFc` / `UnknownFc` | A data attribute has no functional constraint, or an unknown one |
| `BadFcda` | A data-set member has no usable `fc` |
| `BadAddress` | A `GSE` or `SMV` address is incomplete or unparsable |
| `MissingAttribute` | A required `name`, `type`, `inst` or `lnType` is absent |
| `NestingTooDeep` | Type nesting deeper than the loader follows |
| `UnresolvedArrayCount` | A `count` naming an attribute that does not resolve; loaded as a scalar |
| `ArrayTooLarge` | A `count` above `scl::MAX_ARRAY`; loaded as a scalar |

Strict loading rejects instead:

```rust
use iec61850_rs::scl::LoadOptions;

let model = IedModel::from_scl_with(&xml, Some("IED1"), LoadOptions { strict: true })?;
// The first thing that would have been a diagnostic is an error instead.
```

## Building publishers from it

Addresses, APPIDs, VLAN tags and timings come from the engineering file:

```rust
// Everything a GOOSE publisher needs, from one control-block reference.
let cfg = model.goose_publisher_config("IED1LD0/LLN0.gcbTrip", own_mac)?;

// And what a subscriber on the other IED needs to receive it.
let key = model.goose_subscription_key("IED1LD0/LLN0.gcbTrip")?;

// The same for sampled values. 50 is the system frequency — see below.
let sv = model.sv_publisher_config("IED1LD0/LLN0.msvcb01", own_mac, 50)?;
let stream = model.sv_stream_config("IED1LD0/LLN0.msvcb01", 50)?;
```

`goose_publisher_config` fills in the destination MAC, APPID, VLAN identifier and priority
from the `Communication` section, the `gocbRef` and `datSet` from the control block, and
`MinTime`/`MaxTime` from the `GSE` element when the file gives them — with the SI
`multiplier` applied, so a `MaxTime` written in seconds is not read as milliseconds.

`sv_publisher_config` does the same for a merging unit and computes the ASDU sample length by
summing the widths of the data set's members (9-2LE's `PhsMeas1` comes out at 64 octets). A
member whose width is not fixed is an error.

The frequency is a parameter because SCL does not record it: `smpRate` counts samples per
nominal cycle unless `smpMod` is `SmpPerSec`, so `smpRate="80"` is 4000 samples/s at 50 Hz and
4800 at 60 Hz.

## What an IED subscribes to

`Inputs/ExtRef` names the signal an IED consumes; the address, APPID and `confRev` are in the
publisher's part of the file, so subscriptions are resolved over the whole document:

```rust
let subs = iec61850_rs::scl::subscriptions(&scd, "IED2", 50)?;

for s in &subs.goose {
    println!("{} from {} at {} appid={:#06x}", s.identifier, s.publisher, s.dst, s.appid);
    subscribers.push(Subscriber::new(s.goose_config()));   // ready to run
}
for s in &subs.sv {
    streams.push(s.sv_config());     // rate, confRev — and the channel layout
}
```

One entry per source control block, with the `ExtRef`s bound to it and their internal
addresses. A sampled-value subscription carries the publisher's sample layout, so the
subscriber decodes named channels — see
[Sampled Values](@/docs/sampled-values.md#what-the-octets-of-an-asdu-mean).

### Both binding forms

```xml
<!-- Bound to the control block: what a finished system configuration looks like. -->
<ExtRef iedName="IED2" ldInst="CBSW" lnClass="XSWI" lnInst="2" doName="Pos" daName="stVal"
        serviceType="GOOSE" srcLDInst="CBSW" srcCBName="GCB" srcLNClass="LLN0"/>

<!-- Bound to the signal: what most of them look like. -->
<ExtRef iedName="IED1" ldInst="CircuitBreaker_CB1" lnClass="XCBR" lnInst="1"
        doName="Pos" daName="stVal"/>
```

The first is taken as written. For the second, the publisher's data sets are searched for a
member covering the attribute (a member naming a data object covers every attribute under it),
and the control block publishing that data set is the answer. If two control blocks publish
the same signal, the binding is reported as ambiguous.

`ExtRef`s that resolve to nothing — an unknown publisher, a control block with no
`Communication` address — come back in `subs.unresolved`. An `ExtRef` with no `iedName` is an
unbound input and is not reported.

Control blocks resolve by either reference form:

```rust
model.gse_control("IED1LD0/LLN0.gcbTrip")?;      // dotted
model.gse_control("IED1LD0/LLN0$GO$gcbTrip")?;   // MMS form
model.smv_control("IED1LD0/LLN0.msvcb01")?;
```

## Arrays

`count` on a `DA`, `BDA` or `SDO` makes it an array. The schema types it as a **union** of an
unsigned integer and an attribute *name*, so both of these are legal and mean the same thing:

```xml
<SDO name="phsAHar" type="CMV_T" count="16"/>
<SDO name="sqHar"   type="CMV_T" count="numHar"/>   <!-- a sibling whose Val holds the number -->
```

Both resolve to a number in `DataAttribute::count` and `DataObject::count`.

A data set may name **one element** of an array with `FCDA/@ix`:

```xml
<FCDA ldInst="LD0" lnClass="MHAI" lnInst="1" doName="HA" daName="phsAHar.cVal" fc="MX" ix="1"/>
```

The index is placed on the component the type marks with a `count`:
`IedModel::fcda_reference` returns `IED1LD0/MHAI1$MX$HA$phsAHar(1)$cVal`. An index written into
`daName` is read too, and `ied scl validate` reports an index out of range or on a non-array.

## Object references

```rust
use iec61850_rs::{Fc, ObjectReference};

let r = ObjectReference::parse("IED1LD0/MMXU1.TotW.mag.f")?;
assert_eq!((r.ld, r.ln), ("IED1LD0", "MMXU1"));
assert_eq!(r.path().collect::<Vec<_>>(), ["TotW", "mag", "f"]);

let m = ObjectReference::parse("IED1LD0/LLN0$ST$Mod$stVal")?;
assert_eq!(m.fc, Some(Fc::ST));
```

Both forms parse into the same borrowing type. `model.attribute(&r)` resolves one against the
model, through sub-data-objects and `Struct` attributes, and returns `None` if the functional
constraint does not match.

## Instance values, not just type defaults

A `DataTypeTemplates` `<Val>` is the type's default; the instance's value is in the
`DOI`/`SDI`/`DAI`/`Val` tree under the logical node, and the model carries the effective one:

```xml
<LN lnClass="CSWI" inst="1" lnType="CSWI_T">
  <DOI name="Pos">
    <DAI name="ctlModel"><Val>sbo-with-enhanced-security</Val></DAI>
  </DOI>
</LN>
```

```rust
let model = IedModel::from_scl_file("relay.cid", Some("IED1"))?;
match model.control_model("IED1LD0/CSWI1.Pos") {
    Some(ControlModel::SboEnhanced) => { /* select, operate, wait for the termination */ }
    other => { /* … */ }
}
```

### Enumerations

An enumerated `Val` is a symbol; the wire carries the ordinal from the document's own
`EnumType` table, which the loader keeps:

```xml
<EnumType id="CtlModel_E">
  <EnumVal ord="4">sbo-with-enhanced-security</EnumVal>
</EnumType>
```

`IedModel::enum_ord` resolves one; `control_model` uses it.

### Settings per group

A `DAI` under a setting-group control carries one `<Val sGroup="n">` per group, kept in
`DataAttribute::group_values`. A value without `sGroup` applies to every group.

### Control blocks and logs

The model also carries report control blocks with their `TrgOps`, `OptFields` and `indexed`
(whether `RptEnabled max="3"` means `urcb01`…`urcb03` or one block), log control blocks and
their logs, and the setting-group control block — everything
[the server](@/docs/server.md) needs.

## The address a client associates over

`Communication/ConnectedAP/Address` holds what an MMS association needs:

```rust
let a = model.osi_address(None)?;      // None = the only access point
a.ip;                                  // "192.168.210.111"
a.t_sel; a.s_sel; a.p_sel;             // COTP, session and presentation selectors, as octets
a.ap_title;                            // [1, 3, 9999, 23] — ACSE, as arcs
a.ae_qualifier;
```

The selectors go into the COTP CR, session CONNECT and presentation CP; the AP-title and
AE-qualifier into the ACSE AARQ. The [client](@/docs/mms.md#the-client) connects from them:

```rust
let mut c = Client::connect_scl(&scl, "IED1", None, None)?;   // address and selectors from the file
```

```bash
$ ied mms browse - --scd bay.scd --ied IED1
```

## Parsing once

The free functions parse the SCL text on every call. `Scl` is the parsed document, with the
same operations as methods — use it for a station file with many IEDs:

```rust
use iec61850_rs::scl::Scl;

let scl = Scl::parse(&scd)?;          // parsed once
for name in scl.ied_names() {
    let model = scl.model(Some(&name))?;
    let subs = scl.subscriptions(&name, 50)?;
}
let report = scl.validate(50, Edition::Ed2_1)?;   // builds each model exactly once
```

## Validating

`scl::validate` reports engineering errors the schema does not catch:

```rust
use iec61850_rs::common::Edition;
use iec61850_rs::scl::{self, FindingCode};

let report = scl::validate(&scd, 50, Edition::Ed2_1)?;
for f in &report.findings {
    println!("{f}");             // error: DuplicateStream at IED1LD0/LLN0.gcbB: … already published by …
}
assert!(report.is_ok());         // no findings of Severity::Error
```

Every finding has a stable `FindingCode` and a severity; the full list is in
[Command line](@/docs/cli.md#inspect-and-validate-scl).

The loader does not validate against `SCL.xsd`, so `validate` also reports the one schema
violation that changes server behaviour: a type template declaring a member name twice
(`DuplicateTypeMember`).

## Editing

`scl::Document` edits a file without reformatting it. The text is the document: an unedited
document is its input byte for byte — BOM, line endings, quote style, attribute spacing,
comments, CDATA and character references included — and an edit changes only the bytes it is
about, so a review diff shows the change and nothing else.

```rust
use iec61850_rs::scl::{Document, Hitem};

let mut doc = Document::from_bytes(std::fs::read("bay.scd")?)?;
doc.rename_ied("Relay1", "Bay1Relay")?;           // and every reference to it
doc.set_ap_address("Bay1Relay", "AP1", "IP", "10.0.0.5")?;
doc.add_history(&Hitem {
    version: "2".into(), revision: "A".into(), when: "2026-11-09T10:00:00Z".into(),
    who: Some("alice".into()), what: Some("re-address bay 1".into()), why: None,
})?;
std::fs::write("bay.scd", doc.as_str())?;
```

Each operation is one transaction: if its result would not be well-formed XML it is refused and
the document is unchanged, and `undo`/`redo` restore exact bytes. New elements go where the
schema requires them, indented like their siblings, with the file's own line ending.

| Operation | References kept consistent |
|---|---|
| `rename_ied` | every `iedName` (`ConnectedAP`, `ExtRef`, `ClientLN`, `LNode`, …), `IEDName`, and `Val` object references such as an `LGOS.GoCBRef` |
| `remove_ied` | its `ConnectedAP`s (and a `SubNetwork` left empty), `IEDName`/`ClientLN`/`KDC` entries; bound `ExtRef`s are unbound, `LNode`s become `iedName="None"` |
| `add_ln` / `remove_ln` | members that name a removed LN go, a data set left empty goes with its `datSet` references; `ExtRef`s and `LNode`s are released |
| `add_data_set` / `rename_data_set` / `remove_data_set`, `add_fcda` / `remove_fcda` | `datSet` of the LN's control blocks and `Val` references |
| `add_control` / `rename_control` / `remove_control` (GOOSE, SV, report, log) | `GSE`/`SMV` `cbName`, `ExtRef/@srcCBName`, `Val` references |
| `bind_ext_ref` / `unbind_ext_ref` | `intAddr`, `desc` and the `pServT`/`pLN`/`pDO`/`pDA` restrictions are kept |
| `set_gse_address` / `set_smv_address` / `set_ap_address` | an entry is created under the right `ConnectedAP` when there is none |
| `add_history` | creates `History` if needed |

For anything else, `Document::edit` gives raw element, attribute and text operations in one
transaction; `Document::read` gives the same view without editing. A file with a DTD is refused,
so no entity is expanded or fetched; input must be UTF-8.

From the command line, `ied scl edit` makes the common edits —
[Command line](@/docs/cli.md#edit-scl).

## Limits

The loader does not validate against the IEC 61850-7-7 namespace files and generates no typed
Rust model. The editor does not import an IED from an ICD into an SCD (data-type template
merging).
