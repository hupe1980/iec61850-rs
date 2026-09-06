+++
title = "Server"
description = "Serve an IEC 61850 model from an SCL file: the MMS namespace, reads and writes, a report engine with buffering and general interrogation, all four control models, setting groups, a sandboxed file store and logs — with no generated model and no build step."
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
| A block belongs to **one** client. `RptEna` is the reservation; a second client is refused. | Two clients on one block is how one of them stops receiving reports without being told — and it is why an indexed block with `RptEnabled max="3"` is three blocks. |
| A block **cannot be reconfigured while enabled**. Every setting but `RptEna`, `GI` and `PurgeBuf` is refused. | A report whose shape changes halfway through a sequence is worse than a refusal. This is the rule the client's "settings first, `RptEna` last" ordering exists for. |
| `BufTm` **gathers**, it does not delay. | Changes inside the window go into one report, which is what stops a three-phase trip becoming three reports. |
| A **buffered** block keeps its entries while nobody is listening, and replays them when a client enables it — resuming after the `EntryID` the client wrote. | That *is* the difference between `BR` and `RP`. |

`GI` and the integrity period both report every member of the data set; what differs is the
reason code each carries, and a client acts on the difference.

A report leaves as an MMS `InformationReport` under the VMD-specific name **`RPT`** — every
IEC 61850 report does, and what says which subscription it belongs to is the `RptID` inside it.
So `rptID` in the SCD can be any string you like without breaking the encoding.

One trap the server handles for you: SCL's `bufOvfl` attribute **defaults to true**, but
`BufOvfl` and `EntryID` exist only on a buffered block. An ordinary `<OptFields/>` on an
unbuffered one therefore asks for fields that block cannot have; the server clears them, and a
client that reads `OptFlds` back sees what the block will actually send.

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

Three rules the server enforces, each a way a real substation refuses a command:

- **A selection belongs to one client and one value.** An `Oper` from another association, or
  with a `ctlVal` the `SBOw` did not select, is `ObjectNotSelected` — never a silent operate.
- **A selection expires**, so an abandoned select cannot hold a breaker for ever.
- **Only a refused *operate* on an enhanced-security object succeeds-then-fails.** That is what
  a `CommandTermination` is for. A refused *select* is answered by its own response, because
  `SelectWithValue` has no termination to carry the failure — a server that defers it leaves
  the client believing it holds a breaker it does not.

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

## Not implemented yet

Service tracking. `ObtainFile`/`SetFile`. A durable log store — the current one is bounded and
in memory, which is right for a simulator and wrong for a device that must survive a restart.
Edition: the attribute sets and the object-reference limit follow it, but the enumerations
that grew between editions (`AddCause`) do not yet. TLS underneath (IEC 62351-3). Wiring `GoEna` to an actual GOOSE publisher, which waits
for the raw-socket adapters.

And the honest one: everything here is tested against **this crate's own client**
([Verification](@/docs/verification.md)). That proves the two halves agree about the mapping;
it does not prove either is right. Interop against another stack is the next piece of evidence
worth having.
