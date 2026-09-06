+++
title = "MMS"
description = "The IEC 61850 station bus in Rust: the six OSI layers under MMS, the association state machine over them in both roles, and a blocking client that browses, reads, writes, receives decoded reports, operates controllable objects, pulls files, reads logs and edits setting groups."
weight = 45

[extra]
nav_title = "MMS"
+++

Everything an IEC 61850 client does over TCP is an MMS service. Reading a data attribute is
`Read`, writing one is `Write`, a report is an `InformationReport`, browsing a server is
`GetNameList`, and a data set is a *named variable list*. IEC 61850-8-1 clause 7 is that
mapping, and it is why a station-bus stack needs ISO 9506 at all.

What it also needs is everything **underneath** MMS, which is where most of the work is.

## Six layers between TCP and a value

```text
TCP
 └ TPKT            RFC 1006: four octets saying where this PDU ends
   └ COTP class 0  ISO 8073: connect, accept, and a TSDU that may span several TPDUs
     └ Session     ISO 8327: the connect handshake, then GIVE TOKENS + DATA TRANSFER
       └ Presentation  ISO 8823: "context 1 is ACSE, context 3 is MMS, both in BER"
         └ ACSE    ISO 8650: who is associating, with what application context, and a password
           └ MMS   ISO 9506: the service, at last
```

Four of those do almost nothing on this profile, and every one of them has to be exactly
right before a single value can be read. One `Associate` request on the wire is a session
CONNECT carrying a presentation CP carrying an ACSE AARQ carrying an MMS `Initiate` — four
layers in one TCP segment.

Each layer here is a **codec**, in the same shape as the process-bus cores: parse bytes,
build bytes, no sockets and no clocks. Two pieces are stateful because they must be.

```rust
use iec61850_rs::proto::osi::tpkt;

// TCP is a stream, and a TPKT header can arrive split across segments — the reference
// capture does exactly that, every time. So framing is a state machine over a buffer.
let mut reader = tpkt::Reader::new();
reader.push(&bytes_from_socket);
while let Some(tpdu) = reader.next_tpdu()? {
    // …one complete TPDU, borrowing the reader's own buffer
}
```

The other is `cotp::Reassembler`: one TSDU may span several DT TPDUs, ending with the
end-of-transmission bit. A 4 KiB `GetNameList` response over a 1024-octet negotiated size
arrives as four TPDUs and one TSDU, and every layer above sees only the TSDU. It takes a
limit, because a TSDU that never ends is otherwise a memory leak with a protocol in front of
it.

## Decoding a message

```rust
use iec61850_rs::common::Limits;
use iec61850_rs::proto::mms::{ConfirmedResponse, Mms};
use iec61850_rs::proto::osi::cotp::Tpdu;
use iec61850_rs::proto::osi::presentation::Ppdu;
use iec61850_rs::proto::osi::session::Spdu;

let Tpdu::Data { payload, .. } = Tpdu::parse(tpdu)? else { return Ok(()) };
let Spdu::DataTransfer(ppdu) = Spdu::parse(payload)? else { return Ok(()) };
let Ppdu::UserData(pdvs) = Ppdu::parse(ppdu, false)? else { return Ok(()) };

for pdv in pdvs {
    let bytes = pdv.values.single().expect("single-ASN1-type");
    match Mms::parse(bytes, &Limits::DEFAULT)? {
        Mms::ConfirmedResponse { invoke_id, service: ConfirmedResponse::Read { results, .. } } => {
            for r in &results {
                match r.value() {
                    Some(data) => use_it(data),
                    None => log::warn!("access failed: {r:?}"),
                }
            }
        }
        other => log::info!("{other:?}"),
    }
}
```

`pdv.context_id` is what says which layer a PDU belongs to — 1 is ACSE, 3 is MMS, as the CP
negotiated. After the handshake there is no presentation envelope at all, just a `User-data`.

### Values are the same values GOOSE carries

An MMS `AccessResult` **is** the `Data` type of a GOOSE data set, so it is decoded by the same
code: `r.value()` gives a [`DataView`](@/docs/getting-started.md#subscribe-to-a-stream), and the `Typed` trait reads it
as the IEC 61850-7-3 type it claims to be. A report and a GOOSE data set cannot disagree about
what a floating point is, because there is one decoder.

The success case keeps the **encoded** element rather than a decoded copy. That is what lets a
decoded PDU re-encode to the octets it arrived as: a peer may write `TRUE` as `FF`, and
re-encoding from a decoded `bool` would quietly "correct" it.

## What is modelled, and what is kept whole

| Modelled | Kept as tag + octets |
|---|---|
| `Initiate` request/response, `Conclude` | The cancel services |
| `Read`, `Write` | `GetVariableAccessAttributes`, file services, journals |
| `InformationReport` | `DefineNamedVariableList`, the semaphore and program services |
| `GetNameList`, `GetNamedVariableListAttributes`, `Identify` | everything else |

Unmodelled services still round-trip and still print, so a tool can name what it saw. The
services that carry *values* are the ones IEC 61850 is built on, and those are decoded.

## The ACSE password

IEC 61850-8-1's association password is three ACSE fields: `sender-acse-requirements` says
authentication is in use, `mechanism-name` names it (`2.2.3.1` —
`association-control(2) authentication-mechanism(3) password-1(1)`), and
`calling-authentication-value` carries it.

They sit at **[10], [11], [12] in the AARQ and [8], [9], [10] in the AARE**. Reading one set
into the other is the classic way to make a server reject a correct password, so both are
encoded and decoded explicitly and a test pins the tag numbers.

## Verified against a real association

The reference capture is 165 packets of a real client and server: the COTP connect, the
context negotiation, the association, an `Initiate` with a 32 000-octet maximum PDU, then 23
request/response pairs and 115 information reports carrying 823 values. Every packet decodes
through all six layers, and 653 of the 656 encodings come back byte for byte —
[Verification](@/docs/verification.md#vendor-captures-re-encoded-exactly) has the detail.

```bash
$ ied mms sniff station.pcap
     0.552ms -> COTP CR src-ref=0xb001 tpdu-size=1024 tsel [00, 01]->[00, 02]
     1.463ms -> CP  contexts 1=2.2.1.0.1 3=1.0.9506.2.1
     1.463ms -> AARQ context 1.0.9506.1.1
     1.463ms -> Initiate maxPDU=Some(32000) outstanding 20/20 nesting Some(4) version 1
    11.177ms <- AARE accepted
   113.529ms -> invoke 1 identify AREVA T&D Corporation e-terracomm 2.3.1
   322.359ms -> invoke 4434 data set of 19 member(s)
   572.187ms -> report KIRKLAND/EMS_ANALOG_ICCP_IN (19 values)
23 request(s), 23 response(s), 115 report(s), 823 value(s)
```

## The association

Above the six codecs sits `proto::mms::association::Association`: the state machine that knows
*when*. It is **one type with a `Role`**, because the layers are nearly symmetric and because a
client with nothing to talk to cannot be tested.

```rust
use iec61850_rs::common::Instant;
use iec61850_rs::proto::mms::ConfirmedRequest;
use iec61850_rs::proto::mms::association::{Association, AssociationConfig, AssociationEvent};

let mut a = Association::client(AssociationConfig::default());
a.start(now)?;                                     // queues the COTP connection request
while let Some(packet) = a.poll_transmit() {       // …write it to the socket
    socket.write_all(packet)?;
}
a.on_bytes(now, &from_socket);                     // …and feed back what comes in
while let Some(event) = a.poll_event() {
    match event {
        // Invoke identifiers are the association's job; `call` returns the one it used.
        AssociationEvent::Established(_) => { a.call(now, &ConfirmedRequest::Identify)?; }
        AssociationEvent::Response { pdu, .. } => { /* decode with `Mms::parse` */ }
        AssociationEvent::Unconfirmed { pdu } => { /* a report */ }
        other => log::info!("{other:?}"),
    }
}
```

What it owns, so nothing above it has to:

| | |
|---|---|
| The handshake | CR ▸ CC ▸ session CONNECT carrying CP carrying AARQ carrying `Initiate`, then CPA ▸ AARE ▸ `Initiate` response. A refusal is reported **as the layer that refused**, because "connection failed" is not a diagnosis |
| Negotiation | TPDU size down to the smaller proposal, the peer's `localDetailCalled` as the ceiling on what may be sent, and the number of requests in flight — all enforced here, so a client learns its PDU is too big before the server rejects it. The invoke budget is `negotiatedMaxServOutstandingCalling` at the *calling* end and `…Called` at the called one; reading the wrong one lets a client put more requests on the wire than the server agreed to answer |
| Invoke identifiers | allocated, tracked with a deadline each, released on the answer, wrapped below the 32-bit ceiling, and **skipped while still outstanding** so a long-lived association cannot answer the wrong request after a wrap |
| Segmentation | a TSDU longer than one DT TPDU is split and reassembled, with a limit |
| Release | an ACSE RLRQ inside a session FINISH, answered with RLRE inside a DISCONNECT; MMS `Conclude` is answered too; `abort` is a COTP DR and is always terminal |

## The client

`client::Client` is that state machine plus a socket. It is **blocking on purpose**: the core
is sans-IO, so an async wrapper is an adapter over the same machine rather than a second
implementation — and blocking needs no runtime, no executor choice and no dependency at all.

```rust
use iec61850_rs::{Fc, client::Client};

let mut c = Client::connect("10.0.0.5:102")?;      // all six layers, one call
println!("{:?}", c.identify()?);

for ld in c.server_directory()? {                   // GetServerDirectory
    for name in c.logical_device_directory(&ld)? {  // …and everything in it
        println!("{ld}/{name}");
    }
    for set in c.data_set_directory(&ld)? {
        println!("  {set}: {:?}", c.data_set_members(&ld, &set)?);
    }
}

let w = c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX)?;                 // one value
let both = c.read_many(&[("IED1LD0/MMXU1.TotW.mag.f", Fc::MX),
                         ("IED1LD0/PTRC1.Tr.general", Fc::ST)])?;    // one round trip
c.write("IED1LD0/GGIO1.SPCSO1.stVal", Fc::ST, &Value::Boolean(true))?;
c.release()?;
```

Five things worth knowing:

- **`GetNameList` is paged.** A server answering `moreFollows` is asked again with
  `continueAfter`; ignoring the flag shows a fraction of a real IED's model.
- **Nothing unsolicited is dropped.** Reports and command terminations share one channel, so
  the queue is *scanned* rather than popped and what a caller does not want stays behind it.
- **The ACSI mapping is one function.** `ObjectReference::to_mms` turns
  `IED1LD0/MMXU1.TotW.mag.f` plus `Fc::MX` into domain `IED1LD0`, item `MMXU1$MX$TotW$mag$f`.
- **The SCD can be the configuration.** `Client::connect_scl` takes the address, the selectors,
  the AP-title and the AE-qualifier out of `Communication/ConnectedAP`. Every one of them has
  to match or the association is refused at a layer whose error says nothing useful.
- **The server can tell you what a variable is.** `variable_type` is
  `GetVariableAccessAttributes`: one round trip that answers with the recursive shape, so a
  caller does not have to guess a structure's component order from memory.

```rust
let oper = c.variable_type("IED1LD0/CSWI1.Pos.Oper", Fc::CO)?;
assert_eq!(oper.component_names(), ["ctlVal", "origin", "ctlNum", "T", "Test", "Check"]);

// Data sets can be created and deleted too. A list the server *matches* and refuses to
// delete is an error, not success — the difference between gone and refused is the answer.
c.create_data_set("IED1LD0/LLN0$dsTemp", &[("IED1LD0/PTRC1.Tr.general", Fc::ST)])?;
c.delete_data_set("IED1LD0/LLN0$dsTemp")?;
```

## Reports

A report is an `InformationReport` under the VMD-specific `variableListName` **`RPT`** — not
the control block, not the data set and not the `RptID`. IEC 61850-8-1 gives every report that
one name; what says which subscription a report belongs to is the `RptID` *inside* it, which is
why `RptID` is writable. Its `AccessResult`s are **not** a data set. They are a header whose fields are present or absent according to
`OptFlds`, then an inclusion bit string, then the values of whichever members that bit string
says are included:

```text
RptID, OptFlds, [SqNum], [TimeOfEntry], [DatSet], [BufOvfl], [EntryID], [ConfRev],
[SubSeqNum, MoreSegmentsFollow], Inclusion, [DataRef …], Value …, [ReasonCode …]
```

Nothing on the wire separates the three sections — no tags, no lengths, no names. A decoder
that has not read `OptFlds` cannot tell a timestamp from a breaker position, which is why the
flags are a type here and not a hint.

```rust
use iec61850_rs::client::{RcbSettings, TrgOps};

// Configure and enable. The settings go out in one Write and `RptEna` in a second, in that
// order, because a server refuses every other write while reporting is on.
c.enable_rcb("IED1LD0/LLN0$RP$urcb01", Fc::RP,
             &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS))?;
c.general_interrogation("IED1LD0/LLN0$RP$urcb01", Fc::RP)?;

while let Some(r) = c.next_report(Duration::from_secs(5))? {
    println!("{} sq={:?} {} of {} members", r.rpt_id, r.seq_num, r.entries.len(), r.data_set_len());
    for e in &r.entries {
        // `index` is the member's position in the data set — which is what names it when
        // `OptFlds.data_reference` was not asked for, and it usually is not.
        println!("  [{}] {:?}  because {:?}", e.index, e.value, e.reason);
    }
}
```

The control block itself is read and written **attribute by attribute**, never by position: a
buffered block has `PurgeBuf`, `EntryID` and `TimeOfEntry` where an unbuffered one has `Resv`,
and Edition 1 has neither `ResvTms` nor `Owner`. One `Read` of a multi-variable list fetches
them all at once, and the ones a device does not have come back as per-variable failures beside
the ones it does.

Field order is IEC 61850-8-1 **Table 40**, the flag numbering **Table 38**.

### Segments are joined before you see a report

A report larger than the negotiated MMS PDU is split. Each segment carries the same `RptID`
and `SqNum`, its own `SubSeqNum`, and an inclusion bit string naming only the members *that
segment* carries — and nothing else distinguishes one from a whole report. A client that
ignores segmentation therefore sees two reports with a hole in each, and no sign that either
is half of something.

`next_report` returns whole reports only. Behind it a `ReportAssembler` keys segments on
`(RptID, SqNum)`, ORs the inclusion bit strings and concatenates the entries in index order.
Two rules make it safe rather than merely convenient: a **skipped or repeated `SubSeqNum`
abandons the run** instead of guessing past the gap, because a report that decodes with one
member's value at another member's index is worse than no report at all; and the assembler is
**bounded**, so a server that starts segmented reports and never finishes them cannot grow a
client's memory. `Client::report_assembler_stats` counts both.

## Controls

Every control service is a `Read` or a `Write` on a structured variable under `CO`. What
differs between the four control models is which ones, in what order, and whether the answer is
the write response or an unsolicited `CommandTermination` that arrives later:

| Model | Sequence |
|---|---|
| direct, normal security | write `Oper` — the response is the answer |
| SBO, normal security | read `SBO`, then write `Oper` |
| direct, enhanced security | write `Oper`, then wait for a `CommandTermination` |
| SBO, enhanced security | write `SBOw`, write `Oper`, then wait for a `CommandTermination` |

```rust
use iec61850_rs::client::{Check, ControlModel, OriginCategory};
use iec61850_rs::proto::data::Dbpos;

c.control("IED1LD0/CSWI1.Pos")
    .model(c.read_control_model("IED1LD0/CSWI1.Pos")?)   // or take it from the SCD
    .origin(OriginCategory::StationControl, "hmi-1")
    .check(Check { synchro: true, interlock: true })
    .execute(&Value::dbpos(Dbpos::On))?;
```

Two things about the wire are easy to get wrong.

`Check` is a **two-bit** bit string whose bit 0 is the synchrocheck and bit 1 the interlock
check — the reverse of the order prose usually lists them in. Swapping them asks a substation
to skip the check it was told to make.

And a *negative* answer to an enhanced-security control is not an error response. The write
succeeds; the command fails later, and the reason arrives unsolicited as `LastApplError`
carrying an `AddCause` — `BlockedByInterlocking`, `ObjectNotSelected`, `TimeLimitOver` and
twenty-five more. `execute` returns `Err(ControlRejected { add_cause })` rather than reporting
the write's success as the command's.

```bash
$ ied mms control 10.0.0.5 IED1LD0/CSWI1.Pos true --model sbo-enhanced
ied: IED1LD0/CSWI1.Pos: refused — BlockedByInterlocking (AddCause 10)
```

## Files

Getting a COMTRADE record off an IED is the reason the file services exist. On the wire they
are a *handle* protocol: `FileOpen` returns an `frsmID`, `FileRead` is called with it until the
server says no more follows, `FileClose` gives it back.

```rust
for f in c.file_directory(Some("COMTRADE"))? {          // paged on moreFollows
    println!("{:>10}  {}", f.size, f.name);
    let bytes = c.read_file(&f.name, 16 << 20)?;        // open ▸ read ▸ close
    std::fs::write(&f.name, bytes)?;
}
c.delete_file("COMTRADE/rec0001.cfg")?;
```

The handle is a **server-side** resource, so `read_file` closes it even when a read fails
partway or the file is bigger than the ceiling you gave. A leaked `frsmID` is a file left open
in a protection relay, and IEDs have very few of them. The ceiling is not optional either: the
size a server reports is a number the server chose.

## Logs

Three ACSI services, two very different MMS things underneath, and nothing on the wire says so:

| ACSI | MMS |
|---|---|
| `GetLCBValues`, `SetLCBValues`, `GetLogStatusValues` | reads and writes of the **log control block**, a structured variable under `LG` |
| `QueryLogByTime`, `QueryLogAfterEntry` | the MMS **journal** service `ReadJournal` |

```rust
let lcb = c.read_lcb("IED1LD0/LLN0$LG$lcb01", Fc::LG)?;   // one round trip for all of it
let (id, at) = lcb.oldest().expect("the log is not empty");

let page = c.query_log_by_time("IED1LD0/LLN0$GeneralLog", at, None)?;
for e in &page.entries {
    println!("{} {:?}", e.occurred, e.variables);
}

// Resume exactly where you stopped, after a reconnection.
let (id, at) = page.entries.last().unwrap().resume_point();
let next = c.query_log_after_entry("IED1LD0/LLN0$GeneralLog", &id, at)?;
```

`QueryLogAfterEntry` carries **both** the `EntryID` and the time it was made. That is not
redundancy: an `EntryID` is not ordered across a server restart on its own, and the pair is
what lets a reconnecting client pick up without a gap and without duplicates.

## Setting groups

All six ACSI setting-group services are reads and writes of the `SGCB` under `SP`; there is no
MMS service for any of them. The rule that catches everyone is which functional constraint a
*setting* lives under: **`SE` is the edit copy, `SG` is the active one**, and nothing you write
to `SE` changes anything until `CnfEdit`.

```rust
let sgcb = c.read_sgcb("IED1LD0/LLN0$SP$SGCB")?;
println!("{} groups, {} active", sgcb.num_of_sg.unwrap_or(0), sgcb.act_sg.unwrap_or(0));

// select ▸ write ▸ confirm ▸ release, in that order, in one call
c.edit_setting_group("IED1LD0/LLN0$SP$SGCB", 2,
                     &[("IED1LD0/PTOC1.StrVal.setMag.f", Value::Float32(1.25))])?;

c.select_active_setting_group("IED1LD0/LLN0$SP$SGCB", 2)?;   // put it into force
```

`edit_setting_group` refuses to confirm if **any** of the writes was rejected, and releases the
reservation either way. Confirming a half-written protection group and then activating it is
the failure this exists to prevent.

## When a server says no

Two different noes, and they mean different things.

A **service error** is a service that ran and failed: `Error::Service { class, code }` for a
service-level failure, `Error::DataAccess(code)` for one value of a read or a write. Asking
again with a different object might work.

A **reject** is the server saying there was no service to run — an unrecognised service, an
argument it could not decode, or octets that were not a request at all. It arrives as
`Error::Rejected { invoke_id, reason_tag, code }`, and `RejectReason::from_parts(tag, code)`
names the pair (the same code means different things under different tags, which is why both
travel together).

```rust
use iec61850_rs::proto::mms::reject::RejectReason;

match c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX) {
    Err(Error::Rejected { reason_tag, code, .. }) => {
        // e.g. "confirmed-request: unrecognized-service"
        eprintln!("{}", RejectReason::from_parts(reason_tag, code));
    }
    Err(Error::DataAccess(code)) => eprintln!("that value: {code}"),
    other => { other?; }
}
```

A reject **answers** the request it names, so it comes back at once rather than after the
request timeout.

## How it is checked

The reference capture is replayed through **both** roles at once, and fuzz targets drive the
association and the server from arbitrary bytes. A capture only proves the codecs, so the
sequencing is tested by running a real client against a real server over a loopback socket:
everything on this page is the client half, and the **server** — the same association in the
other role, with the SCL file as its namespace — is [its own page](@/docs/server.md).
[Verification](@/docs/verification.md) has the detail.

## Not implemented yet

Service tracking. `ObtainFile` and `SetFile`. Reconnection with backoff. TLS underneath
(IEC 62351-3). The async adapter.
