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

One trap the server handles for you: SCL's `bufOvfl` attribute **defaults to true**, but
`BufOvfl` and `EntryID` exist only on a buffered block. An ordinary `<OptFields/>` on an
unbuffered one therefore asks for fields that block cannot have; the server clears them, and a
client that reads `OptFlds` back sees what the block will actually send.

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

Implement `FileStore` yourself to serve records out of a database, a ring buffer or an archive.
The default is `NoFiles`: an IED with no files should say so rather than expose a filesystem by
accident.

## Logs

A log is the durable half of reporting. The same triggers that make a report make an entry —
the *same code* evaluates them, so a log and a report configured alike cannot disagree — but an
entry survives the client not being there. The control block tracks `OldEnt`/`NewEnt` so a
client with no stored position knows where to start, and `OldEnt` moving is how one that has
been away learns its resume point is gone.

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
Edition modes: `Edition` drives the object-reference limit but not yet the server's attribute
sets. TLS underneath (IEC 62351-3). Wiring `GoEna` to an actual GOOSE publisher, which waits
for the raw-socket adapters.

And the honest one: everything here is tested against **this crate's own client**
([Verification](@/docs/verification.md)). That proves the two halves agree about the mapping;
it does not prove either is right. Interop against another stack is the next piece of evidence
worth having.
