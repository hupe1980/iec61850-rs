+++
title = "SCL and the IED model"
description = "Load an IEC 61850-6 SCL file — ICD, CID or SCD — into an IED model in Rust, resolve what an IED subscribes to, and catch errors the XML schema permits."
weight = 50

[extra]
nav_title = "SCL"
+++

SCL is the XML that describes a substation: which IEDs exist, what data each holds, which
data sets they publish, and on which multicast addresses. It is the configuration, so it is
what this library configures from.

## Loading

```rust
use iec61850_rs::model::IedModel;

let model = IedModel::from_scl_file("relay.icd", Some("IED1"))?;
// Or from a string, with None for the first/only IED:
let model = IedModel::from_scl(&xml, None)?;
```

The loader reads ICD, IID, CID and SCD files, schema versions 2003 through 2007B4. It matches
elements by local name, so a file with unusual namespace prefixes still loads.

What you get is the model a server answers from and a publisher takes its addresses from:

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

Real SCL files are not clean. OpenSCD's own test corpus — files named `valid2007B4.scd` —
references `LNodeType`s and `DOType`s that the file never defines. A loader that refuses the
whole IED for one dangling reference is a loader nobody can use.

So the default is lenient: what cannot be resolved is skipped, recorded, and the rest loads.

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

When you need the opposite — a build step that must reject a file rather than work around it:

```rust
use iec61850_rs::scl::LoadOptions;

let model = IedModel::from_scl_with(&xml, Some("IED1"), LoadOptions { strict: true })?;
// The first thing that would have been a diagnostic is an error instead.
```

## Building publishers from it

This is the point of loading SCL at all: the addresses, APPIDs, VLAN tags and timings live in
the engineering file, and typing them a second time into your code is how a bay ends up
publishing to the wrong multicast group.

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

`sv_publisher_config` does the same for a merging unit, and works out the ASDU sample length
by **summing the widths of the data set's members**. 9-2LE's `PhsMeas1` comes out at 64
octets because the file says so, not because it is special-cased — so a merging unit with its
own fixed-width data set configures itself too. A data set with a member whose width is not
fixed is an error rather than a guess.

### Why the frequency is a parameter

SCL does not record the system frequency, and `smpRate` counts samples per *nominal cycle*
unless `smpMod` says `SmpPerSec`. `smpRate="80"` therefore means 4000 samples a second at
50 Hz and 4800 at 60 Hz, and nothing in the file distinguishes them. Passing it in is honest;
guessing would produce a subscriber whose gap detection is wrong once per second.

## What an IED subscribes to

`Inputs/ExtRef` says which signal this IED consumes and which control block publishes it —
but the multicast address, the APPID and the `confRev` live in the *publisher's* part of the
same file. Resolving a subscription is therefore a whole-document operation, not a per-IED
one:

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

One entry per source control block, carrying the `ExtRef`s bound to it — so you can see which
members of the data set this IED actually wired up, and to which internal address.

A sampled-value subscription brings the publisher's **sample layout** with it: the data set's
`bType`s give every channel of the ASDU a name, a type and an offset, so the subscriber
decodes named channels rather than a block of octets, for any fixed-width data set and not
only 9-2LE's. See [Sampled Values](@/docs/sampled-values.md#what-the-octets-of-an-asdu-mean).

### Two ways a binding is written, and both work

```xml
<!-- Bound to the control block: what a finished system configuration looks like. -->
<ExtRef iedName="IED2" ldInst="CBSW" lnClass="XSWI" lnInst="2" doName="Pos" daName="stVal"
        serviceType="GOOSE" srcLDInst="CBSW" srcCBName="GCB" srcLNClass="LLN0"/>

<!-- Bound to the signal: what most of them look like. -->
<ExtRef iedName="IED1" ldInst="CircuitBreaker_CB1" lnClass="XCBR" lnInst="1"
        doName="Pos" daName="stVal"/>
```

The first names its control block and is taken as written. The second names only the
attribute, so the publisher's data sets are searched for a member covering it — a member
that names only a data object covers every attribute under it, which is how most data sets
are written — and the control block publishing that data set is the answer.

This is not a nicety. In OpenSCD's `valid2007B4.scd`, **one of seven `ExtRef`s carries
`srcCBName`**; a resolver that handled only the first form would report six of them as
unbound.

If two control blocks publish the same signal, the file is ambiguous and says so rather than
picking one — add a `srcCBName`.

### What comes back unresolved

`ExtRef`s that resolve to nothing come back in `subs.unresolved` rather than being dropped: a
binding that names a publisher the file does not hold, or a control block with no
`Communication` address, is a commissioning finding.

An `ExtRef` with **no `iedName` at all** is not reported. That is an input an engineer has
given a place and not yet a source, which is the normal state of an SCD under construction —
flagging it would bury the findings that matter.

Control blocks resolve by either reference form:

```rust
model.gse_control("IED1LD0/LLN0.gcbTrip")?;      // dotted
model.gse_control("IED1LD0/LLN0$GO$gcbTrip")?;   // MMS form
model.smv_control("IED1LD0/LLN0.msvcb01")?;
```

## Object references

```rust
use iec61850_rs::{Fc, ObjectReference};

let r = ObjectReference::parse("IED1LD0/MMXU1.TotW.mag.f")?;
assert_eq!((r.ld, r.ln), ("IED1LD0", "MMXU1"));
assert_eq!(r.path().collect::<Vec<_>>(), ["TotW", "mag", "f"]);

let m = ObjectReference::parse("IED1LD0/LLN0$ST$Mod$stVal")?;
assert_eq!(m.fc, Some(Fc::ST));
```

Both the dotted form and the MMS `$FC$` form parse into the same type, and it borrows the
input — no allocation. `model.attribute(&r)` resolves one against the loaded model, following
sub-data-objects and `Struct` attributes, and returns `None` if the functional constraint does
not match.

## Instance values, not just type defaults

A `DataTypeTemplates` `<Val>` is the **type's** default. What a device actually does is in the
`DOI` / `SDI` / `DAI` / `Val` tree under the logical node instance — and for a controllable
object the two very often differ:

```xml
<LN lnClass="CSWI" inst="1" lnType="CSWI_T">
  <DOI name="Pos">
    <DAI name="ctlModel"><Val>sbo-with-enhanced-security</Val></DAI>
  </DOI>
</LN>
```

The loader walks that tree, so the model carries the *effective* value:

```rust
let model = IedModel::from_scl_file("relay.cid", Some("IED1"))?;
match model.control_model("IED1LD0/CSWI1.Pos") {
    Some(ControlModel::SboEnhanced) => { /* select, operate, wait for the termination */ }
    other => { /* … */ }
}
```

That matters because a control sequence built on the wrong model does nothing and says
nothing: an object engineered for select-before-operate answers an unselected `Oper` with
`AddCause::ObjectNotSelected`. Reading the file costs no round trip; guessing costs a command.

### An enumerated value is a symbol, not a number

`sbo-with-enhanced-security` above is the **symbol**; the wire carries the ordinal `4`. The
mapping is in the document's own `EnumType` table, which the loader keeps:

```xml
<EnumType id="CtlModel_E">
  <EnumVal ord="4">sbo-with-enhanced-security</EnumVal>
</EnumType>
```

Without it every enumerated `Val` in the file parses as zero — and zero is `status-only`, so a
server built from that model refuses every command in the substation for a reason that is not
the real one. `IedModel::enum_ord` resolves one; `control_model` uses it.

### Settings have a value per group

A `DAI` under a setting-group control carries one `<Val sGroup="n">` per group, and the model
keeps them all in `DataAttribute::group_values` — that is what lets a server answer with
group 2's pickup after `SelectActiveSG(2)`. A setting written once, without `sGroup`, means the
same value in every group.

### What a server needs, the file already has

The model carries the rest of what an IED is, not only its data: a report control block's
engineered `TrgOps` and `OptFields` (and `indexed`, which decides whether `RptEnabled max="3"`
means three blocks named `urcb01`…`urcb03` or one), log control blocks and the logs they write
into, and the setting-group control block. That is why
[the server](@/docs/server.md) needs nothing but the file.

## The address a client associates over

`Communication/ConnectedAP/Address` holds what an MMS association needs, and it is engineered
once, in the file:

```rust
let a = model.osi_address(None)?;      // None = the only access point
a.ip;                                  // "192.168.210.111"
a.t_sel; a.s_sel; a.p_sel;             // COTP, session and presentation selectors, as octets
a.ap_title;                            // [1, 3, 9999, 23] — ACSE, as arcs
a.ae_qualifier;
```

The three selectors go into the COTP connection request, the session CONNECT and the
presentation CP; the AP-title and AE-qualifier into the ACSE AARQ
(`osi::oid::encode` turns the arcs into the identifier ACSE carries). `ied scl show` prints
them — and the [client](@/docs/mms.md#the-client) opens an association straight from them:

```rust
let mut c = Client::connect_scl(&scl, "IED1", None, None)?;   // address and selectors from the file
```

```bash
$ ied mms browse - --scd bay.scd --ied IED1
```

Every one of those fields has to match or the server refuses the association at a layer whose
error message says nothing useful, which is why reading them out of the file rather than
retyping them is worth a section of its own.

## Asking one document many questions

Every function above takes SCL text and parses it. That is the right shape for one question,
and the wrong shape for a station file with a hundred IEDs: `validate` alone would re-parse
the document once per IED, and once more per publisher each of them names.

`Scl` is the parsed document, and every function above is a method on it:

```rust
use iec61850_rs::scl::Scl;

let scl = Scl::parse(&scd)?;          // parsed once
for name in scl.ied_names() {
    let model = scl.model(Some(&name))?;
    let subs = scl.subscriptions(&name, 50)?;
}
let report = scl.validate(50, Edition::Ed2_1)?;   // builds each model exactly once
```

The free functions are exactly this with the parse inlined; use whichever fits.

## Validating

The schema permits things a substation cannot live with, and `scl::validate` is where they
are caught — a library function, so a build script can run it without shelling out:

```rust
use iec61850_rs::common::Edition;
use iec61850_rs::scl::{self, FindingCode};

let report = scl::validate(&scd, 50, Edition::Ed2_1)?;
for f in &report.findings {
    println!("{f}");             // error: DuplicateStream at IED1LD0/LLN0.gcbB: … already published by …
}
assert!(report.is_ok());         // no findings of Severity::Error
```

Every finding carries a stable `FindingCode` and a severity, so a pipeline can forbid a
class of them rather than matching on prose. What it looks for — duplicate streams,
unresolvable data-set members and bindings, out-of-range addresses, retransmission times,
sampled-value rates, object references too long for the edition, and a `ctlModel` that
promises a service its own type does not declare — is tabulated in
[Command line](@/docs/cli.md#inspect-and-validate-scl), which is the same checks with a
printer in front of them.

That last one is worth naming, because it is invisible until commissioning: a breaker
engineered `sbo-with-enhanced-security` whose `DOType` declares no `SBOw` is schema-valid and
impossible to operate. The client selects, the server answers `object-non-existent`, and
nothing in `SCL.xsd` objects.


## Not implemented yet

Writing SCL back, editing round-trips, semantic validation against the IEC 61850-7-7
namespace files, and generating a typed Rust model at build time. Today the loader is
read-only.
