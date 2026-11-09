+++
title = "MMS"
description = "The IEC 61850 station bus in Rust: the six OSI layers under MMS, the association state machine over them in both roles, and a blocking client that browses, reads, writes, receives decoded reports, operates controllable objects, pulls files, reads logs, edits setting groups and reconnects on a backoff you state."
weight = 45

[extra]
nav_title = "MMS"
+++

Everything an IEC 61850 client does over TCP is an MMS service. Reading a data attribute is
`Read`, writing one is `Write`, a report is an `InformationReport`, browsing a server is
`GetNameList`, and a data set is a *named variable list* (IEC 61850-8-1 clause 7). Underneath
MMS sit five more OSI layers.

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

One `Associate` request on the wire is a session CONNECT carrying a presentation CP carrying an
ACSE AARQ carrying an MMS `Initiate`. Each layer is a codec with no socket and no clock; two
pieces are stateful.

```rust
use iec61850_rs::proto::osi::tpkt;

// A TPKT header can arrive split across TCP segments, so framing is a state machine.
let mut reader = tpkt::Reader::new();
reader.push(&bytes_from_socket);
while let Some(tpdu) = reader.next_tpdu()? {
    // …one complete TPDU, borrowing the reader's own buffer
}
```

The other is `cotp::Reassembler`: one TSDU may span several DT TPDUs, ending with the
end-of-transmission bit, and every layer above sees only the TSDU. It takes a size limit.

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

`pdv.context_id` says which layer a PDU belongs to — 1 is ACSE, 3 is MMS, as the CP
negotiated.

An MMS `AccessResult` is the same `Data` type a GOOSE data set carries and is decoded by the
same code: `r.value()` gives a [`DataView`](@/docs/getting-started.md#subscribe-to-a-stream),
read with the `Typed` trait. The success case keeps the encoded element, so a decoded PDU
re-encodes to the octets it arrived as.

## What is modelled

| Modelled | Kept as tag + octets |
|---|---|
| `Initiate`, `Conclude`, `Cancel`, `reject-PDU` | |
| `Status`, `GetCapabilityList`, `Identify`, `GetNameList` | the semaphore and program services |
| `Read`, `Write`, `InformationReport` | everything else |
| `GetVariableAccessAttributes`; `Get…Attributes`, `Define…` and `DeleteNamedVariableList` | |
| `ReadJournal`; `ObtainFile`, `FileOpen`, `FileRead`, `FileClose`, `FileDelete`, `FileDirectory` | |

Unmodelled services still round-trip and print.

## The ACSE password

IEC 61850-8-1's association password is three ACSE fields: `sender-acse-requirements` says
authentication is in use, `mechanism-name` names it (`2.2.3.1` —
`association-control(2) authentication-mechanism(3) password-1(1)`), and
`calling-authentication-value` carries it.

They are tagged **[10], [11], [12] in the AARQ and [8], [9], [10] in the AARE**.

## A real association

A reference capture of 165 packets — association, 23 request/response pairs, 115 information
reports carrying 823 values — decodes through all six layers, and 653 of its 656 encodings
re-encode byte for byte ([Verification](@/docs/verification.md#vendor-captures-re-encoded-exactly)).

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

`proto::mms::association::Association` is the state machine over the codecs — one type with a
`Role`, client or server.

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

What it handles:

| | |
|---|---|
| The handshake | CR ▸ CC ▸ session CONNECT carrying CP carrying AARQ carrying `Initiate`, then CPA ▸ AARE ▸ `Initiate` response. A refusal is reported as the layer that refused |
| Negotiation | TPDU size, the peer's `localDetailCalled` as the ceiling on what may be sent, and requests in flight (`negotiatedMaxServOutstandingCalling` at the calling end, `…Called` at the called end) — enforced before sending |
| Invoke identifiers | allocated, tracked with a deadline each, released on the answer, wrapped below the 32-bit ceiling, and skipped while still outstanding |
| Segmentation | a TSDU longer than one DT TPDU is split and reassembled, with a limit |
| Release | an ACSE RLRQ inside a session FINISH, answered with RLRE inside a DISCONNECT; MMS `Conclude` is answered too; `abort` is a COTP DR and is always terminal |

## The client

`client::Client` is that state machine plus a blocking TCP socket. It needs no async runtime.

```rust
use iec61850_rs::{Fc, client::Client};

let mut c = Client::connect("10.0.0.5:102")?;      // all six layers, one call
println!("{:?}", c.status(false)?);                 // is it healthy? no model needed
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
c.write("IED1LD0/CSWI1.Pos.ctlModel", Fc::CF, &Value::Integer(1))?;   // a setting, not a status
c.release()?;
```

- **`GetNameList` is paged**: `moreFollows` is followed with `continueAfter`.
- **Nothing unsolicited is dropped**: reports and command terminations share one queue, which
  is scanned rather than popped.
- **`ObjectReference::to_mms`** turns `IED1LD0/MMXU1.TotW.mag.f` plus `Fc::MX` into domain
  `IED1LD0`, item `MMXU1$MX$TotW$mag$f`.
- **`Client::connect_scl`** takes the address, selectors, AP-title and AE-qualifier from
  `Communication/ConnectedAP`.
- **`variable_type`** is `GetVariableAccessAttributes`: the recursive type of a variable.
- **`ST` and `MX` are not writable** over ACSI (IEC 61850-7-2 §5.7); a conforming server
  answers `object-access-denied`. A breaker moves through the control model. `SP`, `SE`, `CF`,
  `SV`, `DC`, `BL` and the control blocks are writable.

```rust
let oper = c.variable_type("IED1LD0/CSWI1.Pos.Oper", Fc::CO)?;
assert_eq!(oper.component_names(), ["ctlVal", "origin", "ctlNum", "T", "Test", "Check"]);

// A data set the server refuses to delete is an error.
c.create_data_set("IED1LD0/LLN0$dsTemp", &[("IED1LD0/PTRC1.Tr.general", Fc::ST)])?;
c.delete_data_set("IED1LD0/LLN0$dsTemp")?;
```

## Is it there?

`Status` needs no model; an answer proves all six layers are alive.

```rust
let s = c.status(false)?;                   // `true` asks the server to re-derive, not cache
println!("healthy: {}", s.is_healthy());    // state-changes-allowed + operational

for capability in c.capabilities()? {       // free-form strings; the vendor decides
    println!("{capability}");
}
```

`Client::is_alive` is that round trip.

## Reports

A report is an `InformationReport` under the VMD-specific `variableListName` `RPT`; the
`RptID` inside it says which subscription it belongs to. Its `AccessResult`s are a header whose
fields are present according to `OptFlds`, an inclusion bit string, and the values of the
included members:

```text
RptID, OptFlds, [SqNum], [TimeOfEntry], [DatSet], [BufOvfl], [EntryID], [ConfRev],
[SubSeqNum, MoreSegmentsFollow], Inclusion, [DataRef …], Value …, [ReasonCode …]
```

Nothing on the wire separates the sections, so `OptFlds` decides every field. The inclusion
bit string has one bit per data-set member (as `data_set_members` returns them); a member
naming a data object (`CSWI1$ST$Pos`) is one bit and one structured value.

```rust
use iec61850_rs::client::{RcbSettings, TrgOps};

// The settings go out in one Write and `RptEna` in a second.
c.enable_rcb("IED1LD0/LLN0$RP$urcb01", Fc::RP,
             &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS))?;
c.general_interrogation("IED1LD0/LLN0$RP$urcb01", Fc::RP)?;

while let Some(r) = c.next_report(Duration::from_secs(5))? {
    println!("{} sq={:?} {} of {} members", r.rpt_id, r.seq_num, r.entries.len(), r.data_set_len());
    for e in &r.entries {
        // `index` is the member's position in the data set.
        println!("  [{}] {:?}  because {:?}", e.index, e.value, e.reason);
    }
}
```

The control block is read and written attribute by attribute, in one multi-variable `Read`;
attributes a device lacks (`PurgeBuf`/`EntryID` vs `Resv`, Edition 1's missing `ResvTms` and
`Owner`) come back as per-variable failures. Field order is IEC 61850-8-1 Table 40, the flag
numbering Table 38.

### Segmented reports

A report larger than the negotiated PDU is split into segments with the same `RptID` and
`SqNum`, consecutive `SubSeqNum`s, and the `segmentation` bit set in `OptFlds`. `next_report`
returns whole reports only: a `ReportAssembler` keys segments on `(RptID, SqNum)` and joins
them. A skipped or repeated `SubSeqNum` abandons the run, and the assembler is bounded;
`Client::report_assembler_stats` counts both.

### When the link drops

```rust
use iec61850_rs::client::Backoff;

if !c.is_alive() {                          // one `Status` round trip, all six layers
    c.reconnect(&Backoff::default())?;      // 500 ms doubling to 30 s, for ever
    // Nothing is restored automatically. Re-enable what you had; a buffered block replays
    // from the last entry you saw.
    c.enable_rcb("IED1LD0/LLN0$BR$brcb01", Fc::BR,
                 &RcbSettings::new().with_useful_fields().resume_after(last_entry_id))?;
}
```

## Arrays

MMS gives array elements no names: `MHAI1$MX$HA$phsAHar` is a named variable, and an element is
that name plus an ISO 9506 `alternateAccess` selection. The client builds the selection from an
index in parentheses, at any depth:

```rust
let whole   = c.read("IED1LD0/MHAI1.HA.phsAHar",              Fc::MX)?; // all sixteen
let element = c.read("IED1LD0/MHAI1.HA.phsAHar(2)",           Fc::MX)?; // one CMV
let cval    = c.read("IED1LD0/MHAI1.HA.phsAHar(2).cVal",      Fc::MX)?; // one component of it
```

The length is in `GetVariableAccessAttributes`:

```rust
use iec61850_rs::proto::mms::typespec::TypeSpec;

let spec = c.variable_type("IED1LD0/MHAI1$MX$HA", Fc::MX)?;
if let Some(TypeSpec::Array { elements, .. }) = spec.component("phsAHar") {
    println!("{elements} harmonics");
}
```

On the server side the array comes from the file — see
[Server](@/docs/server.md#arrays).

The server refuses an index past the end, an index on a non-array, and range or all-elements
selections.

## Controls

Every control service is a `Read` or `Write` on a structured variable under `CO`:

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
    .origin(OriginCategory::StationControl, "hmi-1")
    .check(Check { synchro: true, interlock: true })
    .execute(&Value::dbpos(Dbpos::On))?;
```

Without `.model(…)`, the client reads the server's `CF$…$ctlModel` once before the first
command; `.model(ControlModel::SboEnhanced)` skips that round trip.

`Check` is a two-bit bit string: bit 0 is the synchrocheck, bit 1 the interlock check.

A negative answer to an enhanced-security control arrives later, unsolicited, as
`LastApplError` with an `AddCause` (`BlockedByInterlocking`, `ObjectNotSelected`,
`TimeLimitOver`, …). `execute` returns `Err(ControlRejected { add_cause })`.

```bash
$ ied mms control 10.0.0.5 IED1LD0/CSWI1.Pos true --model sbo-enhanced
ied: IED1LD0/CSWI1.Pos: refused — BlockedByInterlocking (AddCause 10)
```

## Files

The file services are a handle protocol: `FileOpen` returns an `frsmID`, `FileRead` is called
until no more follows, `FileClose` releases it.

```rust
for f in c.file_directory(Some("COMTRADE"))? {          // paged on moreFollows
    println!("{:>10}  {}", f.size, f.name);
    let bytes = c.read_file(&f.name, 16 << 20)?;        // open ▸ read ▸ close
    std::fs::write(&f.name, bytes)?;
}
c.delete_file("COMTRADE/rec0001.cfg")?;
```

`read_file` closes the handle even when a read fails or the file exceeds the size limit, which
is required.

Sending a file is ACSI `SetFile`, MMS `ObtainFile`: the server reads it back from the client on
the same association, and `set_file` serves those reads while it waits — only for the one file
it offered, one handle at a time — and refuses anything else the server asks for.

```rust
c.set_file("SETTINGS/settings.xml", &bytes)?;                   // or set_file_path(local, remote)
```

The call fails with the server's reason (`file-access-denied` when it takes no files, the
default; `duplicate-filename`; `insufficient-space-in-filestore`). It times out only when the
server stops making progress, not because a transfer is long. Outside `set_file` a request from
the server is refused, never left unanswered.

## Logs

Log services map to two different MMS mechanisms:

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

`QueryLogAfterEntry` carries both the `EntryID` and its time, which together resume without
gaps or duplicates across a server restart.

`QueryLogByTime` always sends both bounds (devices refuse a half-open range); `None` is sent as
the largest representable time. `read_lcb` asks for the buffer cursor under both spellings,
`OldEnt`/`NewEnt` (IEC 61850-7-2) and `OldEntr`/`NewEntr` (libiec61850).

## Setting groups

The setting-group services are reads and writes of the `SGCB` under `SP`. `SE` is the edit copy
of a setting, `SG` the active one; writes to `SE` take effect at `CnfEdit`.

```rust
let sgcb = c.read_sgcb("IED1LD0/LLN0$SP$SGCB")?;
println!("{} groups, {} active", sgcb.num_of_sg.unwrap_or(0), sgcb.act_sg.unwrap_or(0));

// select ▸ write ▸ confirm ▸ release, in that order, in one call
c.edit_setting_group("IED1LD0/LLN0$SP$SGCB", 2,
                     &[("IED1LD0/PTOC1.StrVal.setMag.f", Value::Float32(1.25))])?;

c.select_active_setting_group("IED1LD0/LLN0$SP$SGCB", 2)?;   // put it into force
```

`edit_setting_group` does not confirm if any write was rejected, and releases the reservation
either way.

## When a server says no

A **service error** is a service that ran and failed: `Error::Service { class, code }`, or
`Error::DataAccess(code)` for one value of a read or write.

A **reject** means there was no service to run — an unrecognised service or an undecodable
argument: `Error::Rejected { invoke_id, reason_tag, code }`. `RejectReason::from_parts(tag,
code)` names the pair.

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

A reject answers the request it names immediately. `Association::cancel` asks the peer to
withdraw an outstanding request: a `cancel-Response` releases it, a `cancel-Error` leaves it
standing. This server answers every cancel with a `cancel-Error`, since it answers every
service in the turn it arrives.

The server side is on [its own page](@/docs/server.md); testing is described in
[Verification](@/docs/verification.md).

## Limits

Not implemented: unsolicited `Status`, TLS (IEC 62351-3), and an async client.
