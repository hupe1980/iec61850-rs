+++
title = "Server"
description = "Serve an IEC 61850 model from an SCL file: the MMS namespace, reads and writes, a report engine with buffering, general interrogation and segmentation, all four control models, setting groups, a sandboxed file store and logs — with no generated model and no build step."
weight = 47
+++

An IEC 61850 server is a **model plus a socket**, and the model is the engineering file. That
is the whole configuration:

```rust
use iec61850_rs::server::{Ied, Server};

let ied = Ied::from_scl_file("relay.cid", None)?;      // the SCL file *is* the model
let server = Server::bind("0.0.0.0:102", ied)?;
server.run()?;
```

There is no code generation, no `.cfg` to keep in step with the `.cid`, and no registry to
populate. What a client can browse, read and write is exactly what the file says the IED has,
so the server cannot drift from its own SCD — and the same file that configures the server
configures the publishers and the subscribers.

The command line does the same thing with no code at all:

```bash
$ ied sim relay.icd
IED1 on 127.0.0.1:102 — logical device(s) IED1LD0
serving; ^C to stop
```

## The namespace is the mapping, and it has rules

IEC 61850-8-1 turns a model into MMS **named variables** in a domain, and the map is a tree:
the logical device is the domain, the logical node is the variable, and the functional
constraint, the data object and the attributes are the levels below it.

```text
IED1LD0                        ← MMS domain      = logical device
└─ LLN0                        ← named variable  = logical node
   ├─ ST
   │  └─ Mod
   │     ├─ stVal   INTEGER(8)
   │     ├─ q       BIT STRING(-13)
   │     └─ t       UTC TIME
   └─ RP
      └─ urcb01                ← a control block is a named variable like any other
```

Two properties of that list decide whether a client can browse the server at all, and neither
is obvious:

- **Every level is a name.** `GetNameList` returns `LLN0`, `LLN0$ST`, `LLN0$ST$Mod`,
  `LLN0$ST$Mod$stVal` — the whole flattened namespace, `$`-joined. A client tells the logical
  nodes apart by being the names with no `$` in them, which only works because the bare names
  are in the list.
- **The list is sorted.** `continueAfter` is an *exact match* on a name in it, and the next
  page resumes at the one following — not a "greater than". An unstable order is a browse that
  silently skips or repeats.

The tree is built once, at load, and browse, read, write and `GetVariableAccessAttributes` are
four walks of it rather than four interpretations of the model. That is what stops a report
naming an attribute a read would resolve differently.

The GOOSE and sampled-value control blocks are in it too, with the components the standard
gives them and the address the file's `Communication` section gives them — `DstAddress` is a
structure (`Addr`, `PRIORITY`, `VID`, `APPID`), not an octet string — so a client reads the
address the publisher will actually use rather than being told to look in the SCD.

## Arrays

SCL's `count` makes a data attribute or a sub data object an **array**, and an array is where
the MMS namespace stops: its elements have no names, so a client reaches one with an index
rather than with a longer name.

```xml
<DOType id="HMV_T" cdc="HMV">
  <DA  name="numHar"  fc="MX" bType="INT16U"><Val>3</Val></DA>
  <SDO name="phsAHar" type="CMV_T" count="16"/>       <!-- a number… -->
  <SDO name="sqHar"   type="CMV_T" count="numHar"/>   <!-- …or a sibling that holds one -->
</DOType>
```

Both forms of `count` are legal — the schema types it as a union of an unsigned integer and an
attribute name — and both resolve to a number at load. The server publishes the length in the
type, so `GetVariableAccessAttributes` on `HA` answers `array[16] of struct { cVal, q, t }`,
and a client can ask before it indexes.

Everything below the array is addressed with the index in the reference:

```rust
updates.txn()
    .set("IED1LD0/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f", Value::Float32(12.5))
    .commit();
```

A data set may name **one element** rather than the whole array — `FCDA/@ix` — and the index
says which element, never which component is the array, so the server places it against the
type:

```xml
<FCDA ldInst="LD0" lnClass="MHAI" lnInst="1" doName="HA" daName="phsAHar"          fc="MX" ix="0"/>
<FCDA ldInst="LD0" lnClass="MHAI" lnInst="1" doName="HA" daName="phsAHar.cVal.mag.f" fc="MX" ix="2"/>
```

A report over that data set carries each member at its own depth — one whole element, one
float — rather than the array twice.

**A selection the server cannot serve is refused**, never approximated: an index past the end,
an index on something that is not an array, or an `alternateAccess` naming a range or all
elements.

One limit is the server's rather than the standard's. `count` is an `xs:unsignedInt` and every
element becomes its own set of values at load, so a `count` above `scl::MAX_ARRAY` (4096) is
reported as a finding and loaded as a scalar.

## What a client may write

Not everything that resolves. IEC 61850-7-2 §5.7 says which functional constraints are
writable, and the difference is not bookkeeping: `ST` is *status information* — what the
process reports — and `MX` is a measurand. A server that accepts a write to them lets a client
set a breaker to *closed* with no breaker, no interlock and no `Oper` anywhere near it, and
every other client reads the lie.

| Writable by a client | Not writable as a value |
|---|---|
| `SP` `SV` `CF` `DC` `SE` `BL`, and the control blocks `RP` `BR` `LG` `GO` `GS` `MS` `US` | `ST` `MX` `SG` `SR` `OR` `EX` `CO` `XX` |

`CO` is in the right-hand column because a control is a *service*, not a store: `SBOw`, `Oper`
and `Cancel` go through the control state machine below, which has its own rules about who may
do what and in what order.

Inside a control block the rule is per attribute, because the *settings* are the client's and
the *counters* are the server's: `RptEna`, `DatSet`, `OptFlds`, `BufTm`, `TrgOps`, `IntgPd`,
`GI`, `PurgeBuf` and `EntryID` yes; `SqNum`, `ConfRev`, `TimeOfEntry`, `BufOvfl` and `Owner`
no. `EntryID` is the deliberate exception — writing it is how a client says where to resume.

None of this constrains the **application**: `handle.txn()` is the process interface and is the
one path that may touch `ST` and `MX`. The two were one function, and they are two different
questions.

`Owner` follows from the same rule. Edition 2 added it so an operator can see *which* client
holds a report control block — the first question asked when a second one cannot enable it —
so the server fills it with the holder's network address and clears it when the association
ends.

## Updating the model

The application never locks anything. Writes are staged in a transaction and become visible
together:

```rust
let updates = server.handle();

let mut txn = updates.txn();
txn.set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true));
txn.set("IED1LD0/PTRC1$ST$Tr$q", Value::quality(Quality::GOOD));
txn.commit();                       // → reports, log entries, in that order
```

`commit` is the moment the change happens, for everything: the report engine evaluates
triggers, the log writes its entry, and the report goes to the client that asked for it. A
lock-and-unlock discipline the application has to remember is how a report ends up torn across
two states of the model; here there is nothing to remember.

A write is checked against the model's own type. A client — or an application — that writes an
integer where the file says boolean is refused with `type-inconsistent`, because a server that
accepts it has silently changed its own model and every client that reads it back gets a type
it did not ask for.

## Reporting

The report engine is a state machine per control block, and most of it is rules about
*ownership* and *timing* rather than about encoding:

| Rule | Why |
|---|---|
| A block belongs to **one** client. `RptEna` is the reservation; a second client is refused. | Two clients on one block is how one of them stops receiving reports without being told. An indexed block with `RptEnabled max="3"` is three blocks. |
| A block **cannot be reconfigured while enabled**. Every setting but `RptEna`, `GI` and `PurgeBuf` is refused. | A report whose shape changes halfway through a sequence is worse than a refusal; hence the client's "settings first, `RptEna` last" ordering. |
| `BufTm` **gathers**, it does not delay. | Changes inside the window go into one report, so a three-phase trip is not three reports. |
| A **buffered** block puts every entry into a bounded ring and replays from it when a client enables the block, resuming after the `EntryID`. | The ring is **read, not drained**: `EntryID` is a position in it, so a reconnecting client picks up where it stopped, and one whose resume point has aged out is told with `BufOvfl`. |
| `GI` and `PurgeBuf` are refused unless *this* association has the block enabled. | A general interrogation on a block nobody has enabled has nowhere to send its report, and on a buffered block it would queue the question for whoever connects next. |
| An association that ends releases what it held — `RptEna`, `GI`, `PurgeBuf` and `Resv` — in the model, not only in the engine. | Every setting is refused while `RptEna` is true, so a block left claiming to be enabled is one the next client cannot configure. `Owner` is recomputed rather than cleared, because a `ResvTms` reservation outlives the association. |
| `SqNum` is zeroed when the block is enabled, and `ConfRev` moves when `DatSet` does. A `DatSet` naming a data set the model has not got is refused. | A client caches the member list against `ConfRev`, and an inclusion bit string is only readable against the list it was built from. |
| `ResvTms` is a **duration**: the reservation outlives its association by the seconds it names, and the engine expires it. | The case it exists for is a client whose link drops and comes back. |

`GI` and the integrity period both report every member of the data set; what differs is the
reason code each carries. `IntgPd` is *how often* and `TrgOps.integrity` is *whether* — a period
without the trigger schedules nothing, and `ied scl validate` says so.

### A data set member is the unit

The inclusion bit string is exactly as long as the member list `GetNamedVariableListAttributes`
answers with, and each member contributes **one** bit, **one** value and **one** `ReasonCode`.
That matters most for the shape most engineering tools write:

```xml
<!-- One member. Not three. -->
<FCDA ldInst="LD0" lnClass="CSWI" lnInst="1" doName="Pos" fc="ST"/>
```

`Pos` covers `stVal`, `q` and `t`, and the report carries it as the **structure** it is —
matching the one name `GetNamedVariableListAttributes` answers with, which is what a client
indexes the bit string against.

Triggers are still evaluated per **attribute**, because a `dchg` happens to a leaf: a change to
`Pos.q` alone includes the member with a quality-change reason, and a change to `Pos.stVal` and
`Pos.q` together includes it once, with both reasons merged.

### Reports that do not fit are split

A report longer than what the client negotiated in `Initiate` is sent as several
`InformationReport`s — same `RptID` and `SqNum`, an ascending `SubSeqNum`, `MoreSegmentsFollow`
on all but the last, and an inclusion bit string naming only the members that segment carries.
The budget is the **association's** negotiated size, not the server's configured one, because
ISO 9506 negotiates down and the server's figure is an upper bound rather than an agreement.

The client end joins them, so `next_report` still returns whole reports.

### A client that stops reading is disconnected

Reports and command terminations are queued per association, and the queue is **bounded**
(`ServerConfig::outbound_queue`, 256 PDUs by default). When it fills, the association is closed.

Blocking the producer would stall the application's process interface behind a client that is
not reading its socket, and dropping reports would leave a SCADA client believing it had seen
everything. Closing costs nothing a buffered block does not recover: the entries stay in the
ring and the client resumes from its `EntryID`.

A report leaves as an MMS `InformationReport` under the VMD-specific name **`RPT`** — every
IEC 61850 report does, and what says which subscription it belongs to is the `RptID` inside it.
So `rptID` in the SCD can be any string you like without breaking the encoding.

One trap the server handles for you: SCL's `bufOvfl` attribute **defaults to true**, but
`BufOvfl` and `EntryID` exist only on a buffered block. An ordinary `<OptFields/>` on an
unbuffered one therefore asks for fields that block cannot have; the server clears them, and a
client that reads `OptFlds` back sees what the block will actually send.

## Setting groups: one declaration, two views

A setting-group-dependent setting lives under **two** functional constraints — `SG` is what is
in force and `SE` is the edit copy — and SCL declares it **once**:

```xml
<DOType id="ASG_T" cdc="ASG">
  <DA name="setMag" fc="SG" bType="Struct" type="AnalogueValue"/>
</DOType>
```

It has to be once: the schema makes a `DA` name unique within its `DOType`
(`uniqueDAorSDOInDOType`), and the per-group values hang off a single `DAI` as
`<Val sGroup="1">…<Val sGroup="4">`. So the **server** publishes the `SE` view, and each view
carries its own constraint — an `SE` node claiming to be `SG` would be refused every write by
the rule that what is in force changes only by activating a group.

`CnfEdit` is a *command*: the server puts it back to false once the edit is applied, as it does
for `GI` and `PurgeBuf`. The `SGCB`'s `ResvTms` expires the edit reservation, so a client that
selects a group and goes quiet does not hold a device's settings indefinitely — and unlike a
report control block's, this reservation does **not** outlive the association.

## Publisher control blocks

The GOOSE and sampled-value blocks are served from the file, with the addresses its
`Communication` section gives them, so a client reads the address the publisher will use.
Only `GoEna`/`SvEna` are a client's to write.

A **unicast** sampled-value stream (`SampledValueControl multicast="false"`) is a `USVCB` under
`US`, not an `MSVCB` under `MS`: its identifier is `UsvID` and it has no `noASDU`, which is how
many ASDUs one frame carries and a concept a unicast stream has not got.

## Service tracking

A report says what happened in the **process**. It cannot say what happened on the **wire** —
who enabled that control block, which client was refused and with what, whether the breaker
that did not move was refused by the interlocking or never asked at all. IEC 61850-7-2 §14
answers that with a data object per kind of service, which the server fills in and an ordinary
report control block carries. No new service, no new PDU, nothing else to configure.

Engineer it in the file and the server does the rest:

```xml
<LNodeType id="LLN0_T" lnClass="LLN0">
  <DO name="UrcbTrk" type="UTS_T"/>          <!-- unbuffered report control block -->
  <DO name="CtlTrk"  type="CTS_T"/>          <!-- control services -->
</LNodeType>
<DOType id="UTS_T" cdc="UTS">
  <DA name="objRef" fc="SR" bType="ObjRef"/>
  <DA name="serviceType" fc="SR" bType="Enum" type="ServiceType_E"/>
  <DA name="errorCode"   fc="SR" bType="Enum" type="ServiceError_E"/>
  <DA name="originatorID" fc="SR" bType="Octet64"/>
  <DA name="t" fc="SR" bType="Timestamp"/>
  <DA name="rptEna" fc="SR" bType="BOOLEAN"/>   <!-- the block's own RptEna -->
</DOType>
```

Three rules are all there is to it:

- **The `cdc` finds the object, not the name.** `cdc="UTS"` is what the server looks for, so
  `UrcbTrk` above can be called whatever IEC 61850-7-4 or your tool calls it.
- **The specific half copies itself.** A tracking class's own attributes are the control
  block's with a lower-case first letter — `rptEna` for `RptEna`, `actSG` for `ActSG`. Declare
  the ones you want; leave one out and it is simply not there. (`T`, `Test` and `Check` on the
  control tracker keep an upper-case one, which the standard points out itself.)
- **The `EnumType` gives the numbers.** IEC 61850-7-2 defines the `serviceType` and `errorCode`
  *names*, IEC 61850-8-1 their *numbers*. The server resolves the name against the `EnumType`
  your file declares, and falls back to the standard's list order only when there is none.

`CTS` is the exception, twice over. Its specific half — `ctlVal`, `origin`, `ctlNum`, `T`,
`Test`, `Check`, `respAddCause` — comes from the `Oper` the *client sent* rather than from the
object, so the server supplies it directly. And it is the one class a logical device may hold
**more than one of**: IEC 61850-7-4's `LTRK` carries `SpcTrk`, `DpcTrk`, `IncTrk`, `BscTrk` …,
one per kind of controlled object, so which one records a command is decided by the `bType` of
its `ctlVal`.

`OTS` records the two log **queries**. Its `objRef` names the log rather than a control block,
so nothing is mirrored and the specific half is the query's own range — `rangeStartTime`,
`rangeStopTime`, `entryID`, `entryTime`, each written only if your file declares it.
(`GetLogStatusValues` is deliberately not tracked: IEC 61850-8-1 maps it onto an ordinary read
of the log control block, so nothing on the wire distinguishes it from any other read of that
block, and a server that guessed would record a service the client never asked for.)

Put a tracking object in a data set and every service against that kind of block reaches your
SCADA client as an ordinary report. `ied sim` prints which trackers a file engineered.

## Editions

An IED's edition is a property of the *server*, and the server reads it off its own file — the
SCL schema version says which: `2003` is Edition 1, `2007A`/`2007B` up to release 3 is
Edition 2, `2007B4` and later is Edition 2.1.

It decides the report control block's attribute set. `ResvTms` and `Owner` arrived with
Edition 2, so an Edition 1 file serves a block without them:

```text
Ed 2.1  RptID RptEna Resv DatSet ConfRev OptFlds BufTm SqNum TrgOps IntgPd GI Owner
Ed 1    RptID RptEna Resv DatSet ConfRev OptFlds BufTm SqNum TrgOps IntgPd GI
```

That is not cosmetic: publishing `Owner` on an Edition 1 server claims a reservation service
it does not have, and a client that reads the block positionally then reads every field after
it at the wrong offset.

```bash
$ ied sim valid2003.scd
IED1 on 127.0.0.1:102 — Edition 1 — logical device(s) IED1CircuitBreaker_CB1, IED1Disconnectors
```

`--edition 1|2|2.1` overrides the file, and `Ied::with_edition` does the same in code — for a
device whose certificate says one thing and whose file says another.

## Saying no

There are two ways to refuse, and a client acts on the difference.

A **service error** answers a service that ran and failed — the object does not exist, access
was denied, the value was the wrong type. A **reject** answers a PDU there was no service in:
an unrecognised service, an argument that did not decode, or octets that are not a request at
all. The server sends `confirmed-requestPDU: unrecognized-service` for the first and
`pdu-error: invalid-pdu` for the second, which is what libiec61850's server does and what
ISO 9506 prescribes.

The distinction tells a client whether asking again could ever work. A reject answers the
request it names, so on the client side it arrives as `Error::Rejected` immediately rather
than after the request timeout.

## The clock

Two different clocks run inside the server and they answer different questions.

A **monotonic** instant drives every timer — a `BufTm` gathering window, an integrity period,
a select-before-operate timeout, a request deadline. It carries no date, and it must not: its
origin is arbitrary.

An **absolute** time is what a report's `TimeOfEntry`, a log entry and an `SGCB`'s `LActTm`
carry, and what a `QueryLogByTime` compares against. That comes from a `Clock`:

```rust
use iec61850_rs::common::{Clock, UtcTime};

// The default is the system clock. Replace it to pin time in a test, or to report the
// real time quality from a PTP- or SNTP-disciplined source.
server.set_clock(Box::new(my_disciplined_clock));
```

Deriving the second from the first hides well: both halves of a test agree, because both read
the same wrong number. It puts every `TimeOfEntry` at 1984-01-01 — the floor of the
`BinaryTime` epoch — and makes `QueryLogByTime` match nothing. Only an assertion against a
*pinned* clock catches it.

## Controls

All four models, as one state machine:

```rust
use iec61850_rs::server::Stage;

server.on_control(Box::new(|event| match event.stage {
    Stage::Operate => breaker.operate(&event.request.ctl_val).map_err(|_| AddCause::BlockedByProcess),
    Stage::Select  => interlocking.check().map_err(|_| AddCause::BlockedByInterlocking),
    Stage::Cancel  => Ok(()),
}));
```

Without a hook every command is accepted and applied to the object's `stVal` — which is what a
simulator wants, and what makes `ied sim` a working IED. With one, the hook is where the device
says *no*, and the `AddCause` it returns is what the client is told.

**Time-activated operate** (`operTm`) is a fourth thing the state machine does. An `Oper`
whose `operTm` is in the future is *armed* rather than run: the write succeeds, the command
waits, and the `CommandTermination` arrives when it actually runs — which is what the client is
waiting for anyway. The hook is asked again at that moment, not at acceptance, because an
interlock that has closed in the meantime is precisely what a time-activated command is for.
`Cancel` withdraws one, and so does the association ending: a command nobody is left to tell
about must not run. The wait is computed once, at acceptance, from the difference between
`operTm` and the wall clock — after that it is a monotonic deadline, because a wall clock that
steps must not move a breaker.

Four rules the server enforces, each a way a real substation refuses a command:

- **A selection belongs to one client and one value.** An `Oper` from another association, or
  with a `ctlVal` the `SBOw` did not select, is `ObjectNotSelected` — never a silent operate.
- **A selection expires**, so an abandoned select cannot hold a breaker for ever.
- **Only a refused *operate* on an enhanced-security object succeeds-then-fails.** That is what
  a `CommandTermination` is for. A refused *select* is answered by its own response, because
  `SelectWithValue` has no termination to carry the failure — a server that defers it leaves
  the client believing it holds a breaker it does not.
- **`Beh` decides whether the command is taken at all, and `Test` has to agree with it.** A
  node that is *off*, *blocked* or *test/blocked* refuses everything with
  `AddCause::BlockedByMode`; a node in *test* takes a command carrying `Test` and refuses one
  without it, and a node **not** in test does the reverse. Otherwise `Test` is a field that
  travels and changes nothing, and a test set could operate a live bay unannounced. `Beh` is
  read first, `Mod` is the fallback for files that model only the latter, and a value outside
  `1..=5` reads as *on*. `Cancel` is exempt — a client holding a selection when the node goes
  blocked must still be able to let go.

## Setting groups

A setting has a value **per group**, and the server keeps them all — seeded from the file's own
`<Val sGroup="n">` entries. Two functional constraints reach a setting and they do different
things:

- `SG` is what is **in force**. It is read-only: activating a group changes it, a write never
  does.
- `SE` is the **edit copy**, and it does not exist until a group is selected for editing.
  Writing it changes nothing until `CnfEdit`.

A client that has not selected a group gets `object-access-denied` on `SE` rather than a write
that goes nowhere, and the edit reservation belongs to one client at a time.

## Files

This is how a COMTRADE record leaves an IED, and it is the service with the worst safety record
in the field — libiec61850's changelog lists a path traversal here. So the sandbox is the type,
not a check a caller might forget:

```rust
use iec61850_rs::server::DirectoryStore;

server.set_file_store(Box::new(DirectoryStore::new("/var/lib/ied/records")));
```

`DirectoryStore` refuses absolute paths, drive letters, UNC prefixes, backslashes and any `..`
component — *and* checks that the resolved path is still inside the root after canonicalisation,
because a symlink inside the root defeats every textual check. A path that fails any of them is
`object-non-existent`, never an error that distinguishes "outside the sandbox" from "does not
exist": telling a client which is which is how a filesystem gets mapped. The store is read-only
unless you call `.writable()`.

Files are read in **ranges**, never whole. `FileStore` is `info` plus
`read_at(path, offset, len)`, so a `FileOpen` costs a path and two integers and a `FileRead`
costs one chunk, whatever the record's size. A client picks both how many handles to open and
which file each names, so a store that read the whole file into the handle would make the
server's memory `handles × associations × file size` — on the one service that exists to move
hundred-megabyte records. Opening a 4 MiB record allocates 518 octets, and the test suite holds
it to that number.

Implement `FileStore` yourself to serve records out of a database, a ring buffer or an archive:

```rust
impl FileStore for MyArchive {
    fn list(&self, spec: Option<&str>) -> Vec<FileInfo> { … }
    fn info(&self, path: &str) -> Option<FileInfo> { … }
    fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>> { … }
}
```

The default is `NoFiles`: an IED with no files should say so rather than expose a filesystem by
accident.

## Logs

A log is the durable half of reporting. The same triggers that make a report make an entry —
the *same code* evaluates them, so a log and a report configured alike cannot disagree — but an
entry survives the client not being there. The control block tracks `OldEnt`/`NewEnt` so a
client with no stored position knows where to start, and `OldEnt` moving is how one that has
been away learns its resume point is gone.

An entry also records **why** it was made, when the file's `reasonCode` asks for it (which is
the SCL default). A journal entry has no field for a reason, so IEC 61850 carries it as one
more variable under the reserved tag `ReasonCode`; the client lifts it back out into
`LogEntry::reason` rather than leaving it looking like a data attribute of that name, and
`ied mms log` prints it beside the entry.

Where the entries live is a `LogStore`. The default is a bounded ring in memory — right for a
simulator, wrong for a device that has to survive a restart — so a durable log is a backend
and not a redesign:

```rust
server.set_log_store(Box::new(MyFlashRing::new()));
```

The trait is `append` plus the two queries. Everything above it — which control block writes
into which log, the trigger evaluation it shares with reporting, the `OldEnt`/`NewEnt`
bookkeeping, `QueryLogByTime` and `QueryLogAfterEntry` — is the same whichever store is
underneath. The `EntryID` belongs to the **store**, because it is what a client resumes after
and therefore what has to stay ordered across the restart.

## Supervising what this IED subscribes to

A GOOSE or sampled-value subscriber already knows whether its stream is alive, which `confRev`
is arriving, whether the publisher is asking to be commissioned and whether what arrives is
simulated. IEC 61850-7-4 gives that a home — an `LGOS` per GOOSE subscription, an `LSVS` per
sampled-value one — and this is the one feature that needs both buses at once, which is why
most stacks leave the logical node in the model and never fill it in.

```rust
use iec61850_rs::server::SubscriptionStatus;

updates.txn().supervise("IED2LD0/LGOS1", &SubscriptionStatus::from_goose(&subscriber)).commit();
```

| Object | What it says |
|---|---|
| `St` | the subscription is **live** — a frame was accepted and its `timeAllowedtoLive` has not run out |
| `NdsCom` | the publisher signals `ndsCom`: it needs commissioning and its data is not usable |
| `SimSt` | what is being accepted is *simulated* traffic |
| `LastStNum` | the last `stNum` received (GOOSE only; a sampled-value stream has none) |
| `ConfRevNum` / `RxConfRevNum` | the `confRev` this subscription **expects**, and the one **arriving** |

Two rules make it safe to call in a loop. Only the objects **this IED's own** `LGOS`/`LSVS`
type declares are written — the SCL file decides which exist, as it does everywhere else — and
an unchanged status writes nothing, with `t` stamped at the change rather than at the poll.
Without the second rule a supervision loop would be a data change once a second and every
report control block watching the node would fire.

`GoCBRef` and `SvCBRef` are **settings**, not status: they say what the node was engineered to
watch, so they come from the file and the runtime never writes them. That binding is readable
too, which closes the loop — an application wires a subscriber to its supervision node without
typing either name a second time:

```rust
let node = model.supervision().into_iter().find(|n| n.watches(gocb_ref));
```

`ied scl subs` prints both halves and marks an `LGOS` that watches a control block this IED
does not subscribe to — a supervision that would sit at `St = false` for ever and never say
why. The whole thing runs in `cargo run --example supervised_subscriber`, with no network.

## Driving it yourself

`Server::run` is an accept loop with a thread per association, and it handles the timers for
you. If you drive `Acsi` directly — sans-IO, no socket — `next_timeout` is the one call to get
right: it reports the earliest of a report's gathering window, an integrity period, a
select-before-operate expiry and a time-activated command. An event loop that sleeps past any
of them is a report that arrives late and a breaker that does not move.

## Layers

Four, each testable without the one below it — which is why the whole service layer is tested
with no socket, no client and no byte on a wire:

| | |
|---|---|
| `tree` | what a name means |
| `Ied` | what a name holds, plus data sets and control blocks |
| `Acsi` | a request in, an owned answer out — sans-IO |
| `Server` | associations and threads |

## Not included

`ObtainFile`/`SetFile`. A durable `LogStore` backend — the trait takes one; what ships is a
bounded in-memory ring. TLS (IEC 62351-3). The enumerations that grew between editions
(`AddCause`), though the attribute sets and the object-reference limit do follow the edition.
`GoEna` is served and readable but drives no publisher, which waits on the raw-socket adapters.

The behaviour here is tested three ways: against this crate's own client, which proves the two
halves agree about the mapping rather than that either is right; against Wireshark, which is a
third party for the octets; and against **libiec61850's client**, which is the only one of the
three that can tell you a real client is happy with the sequence.
[Verification](@/docs/verification.md) sets out all three.
