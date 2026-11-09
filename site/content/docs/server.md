+++
title = "Server"
description = "Serve an IEC 61850 model from an SCL file: the MMS namespace, reads and writes, a report engine with buffering, general interrogation and segmentation, all four control models, setting groups, a sandboxed file store and logs — with no generated model and no build step."
weight = 47
+++

An IEC 61850 server is a model plus a socket, and the model is the engineering file:

```rust
use iec61850_rs::server::{Ied, Server};

let ied = Ied::from_scl_file("relay.cid", None)?;
let server = Server::bind("0.0.0.0:102", ied)?;
server.run()?;
```

What a client can browse, read and write is exactly what the file declares. The same from the
command line:

```bash
$ ied sim relay.icd
IED1 on 127.0.0.1:102 — Edition 2.1 — logical device(s) IED1LD0
serving; ^C to stop
```

## The namespace

IEC 61850-8-1 maps the model onto MMS named variables: the logical device is the domain, the
logical node is the variable, and the functional constraint, data object and attributes are the
levels below it.

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

- **Every level is a name.** `GetNameList` returns `LLN0`, `LLN0$ST`, `LLN0$ST$Mod`,
  `LLN0$ST$Mod$stVal` — the flattened namespace.
- **The list is sorted**, and `continueAfter` is an exact match on a name in it.

The tree is built once at load; browse, read, write and `GetVariableAccessAttributes` all walk
it. The GOOSE and sampled-value control blocks are in it too, with the address from the file's
`Communication` section (`DstAddress` is a structure: `Addr`, `PRIORITY`, `VID`, `APPID`).

## Arrays

SCL's `count` makes a data attribute or sub data object an array. Both forms resolve at load:

```xml
<DOType id="HMV_T" cdc="HMV">
  <DA  name="numHar"  fc="MX" bType="INT16U"><Val>3</Val></DA>
  <SDO name="phsAHar" type="CMV_T" count="16"/>       <!-- a number… -->
  <SDO name="sqHar"   type="CMV_T" count="numHar"/>   <!-- …or a sibling that holds one -->
</DOType>
```

The length is published in the type: `GetVariableAccessAttributes` on `HA` answers
`array[16] of struct { cVal, q, t }`. Elements are addressed with an index in the reference:

```rust
updates.txn()
    .set("IED1LD0/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f", Value::Float32(12.5))
    .commit();
```

A data set may name one element with `FCDA/@ix`; a report carries each member at its own depth:

```xml
<FCDA ldInst="LD0" lnClass="MHAI" lnInst="1" doName="HA" daName="phsAHar"          fc="MX" ix="0"/>
<FCDA ldInst="LD0" lnClass="MHAI" lnInst="1" doName="HA" daName="phsAHar.cVal.mag.f" fc="MX" ix="2"/>
```

The server refuses an index past the end, an index on a non-array, and an `alternateAccess`
naming a range or all elements. A `count` above `scl::MAX_ARRAY` (4096) is reported and loaded
as a scalar.

## What a client may write

IEC 61850-7-2 §5.7 decides which functional constraints a client may write:

| Writable by a client | Not writable as a value |
|---|---|
| `SP` `SV` `CF` `DC` `SE` `BL`, and the control blocks `RP` `BR` `LG` `GO` `GS` `MS` `US` | `ST` `MX` `SG` `SR` `OR` `EX` `CO` `XX` |

`CO` goes through the control state machine, not through writes.

Inside a control block the rule is per attribute: `RptEna`, `DatSet`, `OptFlds`, `BufTm`,
`TrgOps`, `IntgPd`, `GI`, `PurgeBuf` and `EntryID` are writable; `SqNum`, `ConfRev`,
`TimeOfEntry`, `BufOvfl` and `Owner` are not. `Owner` holds the network address of the client
holding the block and is cleared when its association ends.

The application is not bound by these rules: `handle.txn()` is the process interface and may
write `ST` and `MX`.

## Updating the model

Writes are staged in a transaction and become visible together:

```rust
let updates = server.handle();

let mut txn = updates.txn();
txn.set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true));
txn.set("IED1LD0/PTRC1$ST$Tr$q", Value::quality(Quality::GOOD));
txn.commit();                       // → reports, log entries, in that order
```

At `commit` the report engine evaluates triggers and the log writes its entry. A value of the
wrong type — from a client or the application — is refused with `type-inconsistent`.

## Reporting

| Rule | Detail |
|---|---|
| A block belongs to one client | `RptEna` is the reservation; a second client is refused. An indexed block with `RptEnabled max="3"` is three blocks. |
| No reconfiguration while enabled | Every setting but `RptEna`, `GI` and `PurgeBuf` is refused. |
| `BufTm` gathers | Changes inside the window go into one report. |
| Buffered blocks replay | Entries go into a bounded ring that is read, not drained; enabling resumes after the client's `EntryID`, and an aged-out resume point is signalled with `BufOvfl`. |
| `GI` and `PurgeBuf` need the block enabled by this association | |
| A closed association releases what it held | `RptEna`, `GI`, `PurgeBuf` and `Resv` are reset in the model; `Owner` is recomputed, since a `ResvTms` reservation outlives the association. |
| `SqNum` and `ConfRev` | `SqNum` is zeroed on enable; `ConfRev` moves when `DatSet` does. A `DatSet` naming an unknown data set is refused. |
| `ResvTms` is a duration | The reservation outlives its association by that many seconds. |

`GI` and the integrity period both report every member; they differ in reason code. `IntgPd` is
how often and `TrgOps.integrity` is whether — a period without the trigger schedules nothing.

**A data-set member is the unit.** Each member contributes one inclusion bit, one value and one
`ReasonCode`. A member naming a data object (`<FCDA … doName="Pos" fc="ST"/>`) is carried as one
structure. Triggers are evaluated per attribute: a change to `Pos.q` includes the member with a
quality-change reason; changes to `Pos.stVal` and `Pos.q` together include it once, with both
reasons.

**Segmentation.** A report longer than the PDU size negotiated in `Initiate` is sent as several
`InformationReport`s with the same `RptID` and `SqNum`, ascending `SubSeqNum`, and
`MoreSegmentsFollow` on all but the last. The client joins them.

**Bounded queues.** Reports and command terminations are queued per association
(`ServerConfig::outbound_queue`, 256 PDUs by default). When the queue fills, the association is
closed; a buffered block's entries stay in the ring for the client to resume.

Reports go out under the VMD-specific name `RPT`, so `rptID` in the SCD can be any string. SCL's
`bufOvfl` defaults to true, but `BufOvfl` and `EntryID` exist only on buffered blocks; on an
unbuffered block the server clears them from `OptFlds`.

## Setting groups

A setting has a value per group, seeded from the file's `<Val sGroup="n">` entries. SCL declares
it once, under `SG`; the server publishes it under two constraints:

- `SG` is what is in force. It is read-only; activating a group changes it.
- `SE` is the edit copy, present only while a group is selected for editing; writes take effect
  at `CnfEdit`. Without a selected group, a write to `SE` is `object-access-denied`.

The edit reservation belongs to one client. `CnfEdit` returns to false once applied. The
`SGCB`'s `ResvTms` expires the reservation, and unlike a report control block's it does not
outlive the association.

## Publisher control blocks

GoCBs and MSVCBs are served from the file with their `Communication` addresses; only
`GoEna`/`SvEna` are writable by a client. A unicast sampled-value stream
(`multicast="false"`) is a `USVCB` under `US`, with `UsvID` and no `noASDU`. Enabling a block
does not start a publisher.

## Service tracking

IEC 61850-7-2 §14 defines a data object per kind of service that records who did what — which
client enabled a block, which was refused and why. The server fills the objects the file
declares, and an ordinary report control block carries them:

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

- **The `cdc` finds the object**, not the name.
- **The specific attributes mirror the control block's**, with a lower-case first letter
  (`rptEna`, `actSG`). Only the declared ones are written. `T`, `Test` and `Check` on the control
  tracker keep upper case.
- **`serviceType` and `errorCode` ordinals come from the file's `EnumType`**, falling back to
  the standard's order when there is none.

`CTS` takes its specific half (`ctlVal`, `origin`, `ctlNum`, `T`, `Test`, `Check`,
`respAddCause`) from the client's `Oper`. A logical device may hold several (`LTRK`'s `SpcTrk`,
`DpcTrk`, `IncTrk`, `BscTrk`, …); the one whose `ctlVal` type matches records the command.

`OTS` records the two log queries, with `rangeStartTime`, `rangeStopTime`, `entryID` and
`entryTime` where declared. `GetLogStatusValues` is not tracked: on the wire it is an ordinary
read of the log control block.

`ied sim` lists the trackers a file declares.

## Editions

The server takes its edition from the file's schema version: `2003` is Edition 1,
`2007A`/`2007B` up to release 3 Edition 2, `2007B4` and later Edition 2.1. An Edition 1 server's
report control blocks have no `ResvTms` and no `Owner`:

```text
Ed 2.1  RptID RptEna Resv DatSet ConfRev OptFlds BufTm SqNum TrgOps IntgPd GI Owner
Ed 1    RptID RptEna Resv DatSet ConfRev OptFlds BufTm SqNum TrgOps IntgPd GI
```

`--edition 1|2|2.1` or `Ied::with_edition` overrides the file. The edition also sets the
object-reference length limit and the `AddCause` values a refusal may carry: Edition 1 defines
0–18, so an Edition 1 server sends `ObjectAlreadySelected` as `SelectFailed` and any other newer
cause — including one the control hook returns — as `Unknown`. `AddCause::for_edition` is the
mapping; `AddCause::since` names the edition that introduced a value.

## Errors and rejects

A **service error** answers a service that ran and failed — object not found, access denied,
wrong type. A **reject** answers a PDU with no service in it: `confirmed-requestPDU:
unrecognized-service` for an unknown service, `pdu-error: invalid-pdu` for undecodable octets.

## The clock

A monotonic instant drives every timer (`BufTm`, integrity periods, select timeouts, request
deadlines). Absolute time — `TimeOfEntry`, log entries, `LActTm`, `QueryLogByTime` — comes from a
`Clock`:

```rust
use iec61850_rs::common::{Clock, UtcTime};

// The default is the system clock. Replace it to pin time in a test, or to report the
// time quality of a PTP- or SNTP-disciplined source.
server.set_clock(Box::new(my_disciplined_clock));
```

## Controls

All four control models, with a hook where the application decides:

```rust
use iec61850_rs::server::Stage;

server.on_control(Box::new(|event| match event.stage {
    Stage::Operate => breaker.operate(&event.request.ctl_val).map_err(|_| AddCause::BlockedByProcess),
    Stage::Select  => interlocking.check().map_err(|_| AddCause::BlockedByInterlocking),
    Stage::Cancel  => Ok(()),
}));
```

Without a hook every command is accepted and applied to the object's `stVal`. The `AddCause` a
hook returns is what the client is told.

**Time-activated operate.** An `Oper` whose `operTm` is in the future is armed: the write
succeeds and the `CommandTermination` arrives when it runs. The hook is asked at execution time.
`Cancel` or the end of the association disarms it. The delay is computed once from `operTm` and
the wall clock, then held as a monotonic deadline.

Rules the server enforces:

- **A selection belongs to one client and one value.** An `Oper` from another association, or
  with a different `ctlVal` than the `SBOw`, is `ObjectNotSelected`.
- **A selection expires.**
- **Only an enhanced-security operate succeeds-then-fails**; a refused select is answered in its
  own response.
- **`Beh` gates the command and `Test` must agree.** *Off*, *blocked* and *test/blocked* refuse
  with `AddCause::BlockedByMode`; *test* accepts only commands with `Test` set, other modes only
  without. `Beh` is read first, `Mod` as fallback; a value outside `1..=5` reads as *on*.
  `Cancel` is exempt.

## Files

```rust
use iec61850_rs::server::DirectoryStore;

server.set_file_store(Box::new(DirectoryStore::new("/var/lib/ied/records")));
```

`DirectoryStore` refuses absolute paths, drive letters, UNC prefixes, backslashes and `..`
components, and checks that the canonicalised path is still inside the root. Every refusal is
`object-non-existent`, indistinguishable from a missing file. Nothing whose path has a
component starting with `.` is ever listed, read or deleted, and `.hiding(path)` keeps a file
the server itself depends on — its log, its SCL file — out of reach even under the root. It is
read-only unless `.writable()`; even then only an association the file-write policy allows
(below) may receive, replace or delete a file.

Files are read in ranges: `FileStore` is `list`, `info` and `read_at(path, offset, len)`, so a
`FileRead` costs one chunk whatever the file's size. Implement it to serve records from anywhere:

```rust
impl FileStore for MyArchive {
    fn list(&self, spec: Option<&str>) -> Vec<FileInfo> { … }
    fn info(&self, path: &str) -> Option<FileInfo> { … }
    fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>> { … }
}
```

The default is `NoFiles`.

### Changing files (`SetFile`, `FileDelete`)

A client sends a file with ACSI `SetFile` (MMS `ObtainFile`); the server then reads it from the
client with `FileOpen`/`FileRead`/`FileClose` on the same association and stores it. Who may
send, replace or delete a file is one policy, `AcsiConfig::file_write`: `FileWritePolicy::Off`
(the default — nobody), `Authenticated` (only an association that presented the server's ACSE
password) or `Anyone`; the store must be writable as well.

```rust
use iec61850_rs::server::{AcsiConfig, DirectoryStore, ServerConfig, FileWritePolicy};

let mut cfg = ServerConfig { acsi: AcsiConfig { file_write: FileWritePolicy::Authenticated, ..AcsiConfig::default() }, ..ServerConfig::default() };
cfg.association.password = Some("s3cret".into());          // every association must present it
let mut server = Server::bind_with("0.0.0.0:102", ied, &cfg)?;
server.set_file_store(Box::new(DirectoryStore::new("/var/lib/ied/settings").writable()));
```

`DirectoryStore` applies the read rules to the destination and more: no component may start
with `.`, the directory must already exist inside the root after symlinks are resolved, and an
existing file is not replaced (`duplicate-filename`) unless `.allow_overwrite()`. The file is
written to a hidden temporary beside its destination and appears under its name only complete;
a refused, failed, timed-out or abandoned transfer leaves nothing. `.with_limits(file, total)`
bounds one file (default 16 MiB) and the whole store (256 MiB); the declared size is checked
before the first read and every chunk after it.

Transfers never hold up the server: the connection loop issues each request and goes on, one
transfer per association and `AcsiConfig::max_obtains` (2) in all, each finished within
`obtain_timeout_ms` (30 s) or answered with an error. A refusal carries the ISO 9506 `file`
error and says which side failed (`ObtainFile-Error`: source or destination). A request naming a
third-party `sourceFileServer` is refused.

A server with `AssociationConfig::password` refuses any association that does not present it,
at ACSE with `authentication-failure`; the comparison is constant-time.

## Logs

Log entries use the same trigger evaluation as reports. The log control block tracks
`OldEnt`/`NewEnt`; `OldEnt` moving tells a returning client its resume point is gone.

When the file's `reasonCode` asks for it (the SCL default), an entry records why it was made, as
a variable under the reserved name `ReasonCode`; the client returns it as `LogEntry::reason`.

Entries live in a `LogStore`. The default, `MemoryLog`, is a bounded in-memory ring. With the
`log-redb` feature, `RedbLog` keeps them in a file that survives a restart:

```rust
use iec61850_rs::server::RedbLog;

let logs = server.log_references();
server.set_log_store(Box::new(RedbLog::open("relay-log.redb", logs, 10_000)?));
```

Each append is one transaction — entry, counter and eviction together — and is on disk before it
returns (`SyncPolicy::Deferred` plus `RedbLog::sync` trades that for fewer flushes). A restarted
server publishes `OldEnt`/`NewEnt` from the file before it logs anything new, and `EntryID`s keep
counting up. The file is created readable by its owner only, and is locked to one store; a file
of another format version is refused, not migrated. `ied sim --log-db` does the same from the
command line.

A store of your own implements the trait (`append`, `by_time`, `after_entry`, `bounds`, `len`,
`purge`, all fallible) and should pass `check_log_store`, the contract both shipped stores pass.
A query the store cannot answer is refused with `resource`/`mass-storage-unavailable`; an entry
it cannot keep moves no bound and is counted in `Acsi::failed_log_appends`.

## Supervising what this IED subscribes to

IEC 61850-7-4's `LGOS` (per GOOSE subscription) and `LSVS` (per sampled-value subscription) are
filled from a live subscriber:

```rust
use iec61850_rs::server::SubscriptionStatus;

updates.txn().supervise("IED2LD0/LGOS1", &SubscriptionStatus::from_goose(&subscriber)).commit();
```

| Object | Meaning |
|---|---|
| `St` | the subscription is live — a frame was accepted and its `timeAllowedtoLive` has not run out |
| `NdsCom` | the publisher signals `ndsCom` |
| `SimSt` | simulated traffic is being accepted |
| `LastStNum` | the last `stNum` received (GOOSE only) |
| `ConfRevNum` / `RxConfRevNum` | the expected and the arriving `confRev` |

Only the objects the node's type declares are written, and an unchanged status writes nothing,
so calling it in a loop does not trigger reports. `GoCBRef`/`SvCBRef` come from the file and
are never written at runtime; `model.supervision()` reads the binding:

```rust
let node = model.supervision().into_iter().find(|n| n.watches(gocb_ref));
```

`cargo run --example supervised_subscriber` runs the whole thing with no network.

## Driving it yourself

`Server::run` is an accept loop with a thread per association. Driving `Acsi` directly (sans-IO)
requires waking at `Acsi::next_timeout`: the earliest gathering window, integrity period,
select expiry or time-activated command.

| Layer | Role |
|---|---|
| `tree` | what a name means |
| `Ied` | what a name holds, plus data sets and control blocks |
| `Acsi` | a request in, an owned answer out — sans-IO |
| `Server` | associations and threads |

## Limits

Not implemented: TLS (IEC 62351-3). `GoEna`/`SvEna` drive no publisher.

The server is tested against this crate's client, Wireshark and libiec61850's client — see
[Verification](@/docs/verification.md).
