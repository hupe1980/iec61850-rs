# iec61850-rs

[![CI](https://github.com/hupe1980/iec61850-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/hupe1980/iec61850-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#licence)

**IEC 61850 in Rust.** Publishers and subscribers for the substation process bus, an MMS
**client and server** for the station bus, panic-free decoders, sans-IO state machines, and
encoders checked against real substation captures frame for frame.

📖 **[Documentation and guide](https://hupe1980.github.io/iec61850-rs/)** · 📋 **[Changelog](CHANGELOG.md)**

> **Pre-release.** The process bus works and is tested; the MMS client associates, browses,
> reads, writes, **receives decoded reports**, **operates controllable objects**, **pulls files
> off a server**, **reads logs** and **edits setting groups** through all six of its OSI
> layers — and the **server** does the other half of every one of those, straight from an SCL
> file. What is not written yet is service tracking, TLS and the raw-socket adapters. The API
> will change, and everything here is tested against itself rather than against another
> vendor's stack — see
> [Verification](https://hupe1980.github.io/iec61850-rs/docs/verification/).

## What works today

| | |
|---|---|
| **GOOSE** (IEC 61850-8-1) | Codec, publisher with the T1…T0 retransmission curve, subscriber with the IEC 62351-6 replay rule, Edition 2 simulation-bit semantics, and the delta features a substation IDS is built on |
| **Sampled Values** (IEC 61850-9-2) | Codec, template-patching publisher for the 9-2LE and IEC 61869-9 profiles — `smpSynch`, `refrTm` and `gmIdentity` patched in place — multi-stream subscriber tracking continuity, sync, grandmaster, staleness and the Edition 2 simulation rule. **Any data set decodes**: the SCL file gives each ASDU channel a name, a type and an offset, so a merging unit that is not 9-2LE needs no special case |
| **MMS** (IEC 61850-8-1) | The whole OSI stack under it — TPKT with a stream reader, COTP class 0 with TSDU reassembly, session, presentation, ACSE — the MMS PDUs, and the **association state machine** over all six: client *and* server roles, invoke tracking, TSDU segmentation, timeouts, orderly release, ACSE password. A service that fails and a PDU that is *rejected* are different answers, decoded and emitted as such. Values share their codec with GOOSE |
| **MMS client** | Blocking, no runtime, no dependency: connect (from the SCD if you like), `Identify`, browse the server with `moreFollows` paging, read one value or many or a whole data set, write, ask what *type* a variable is, create and delete data sets |
| **Reporting** (IEC 61850-8-1 §17) | Read a report control block attribute by attribute, configure it, enable it with `RptEna` written last, ask for a general interrogation — and get reports **decoded**: `RptID`, `SqNum`, `TimeOfEntry`, `EntryID`, the inclusion bit string, and per member its index, reference, value and reason for inclusion. A report split across **segments** is joined before you see it, or not delivered at all |
| **Files** (IEC 61850-8-1 §23) | List a server's files, pull one off it, delete one. The `frsmID` a `FileOpen` returns is given back even when a read fails partway — a leaked handle is a file left open in a relay. The server's store is read in **ranges**, so an open costs a name and a read costs a chunk however big the record is. This is how a COMTRADE record gets off an IED |
| **Logs** (IEC 61850-7-2 §17) | Read a log control block, then `QueryLogByTime` or `QueryLogAfterEntry` — the second carries the `EntryID` *and* its time, so a reconnecting client resumes exactly where it stopped, without a gap and without duplicates |
| **Setting groups** (IEC 61850-7-2 §11) | Read the `SGCB`, activate a group, or select ▸ write ▸ confirm ▸ release an edit in one call — which refuses to confirm if any write was rejected, because a half-written protection group must not be activated |
| **Control** (IEC 61850-7-2 §20) | All four control models behind one `execute` — direct and select-before-operate, normal and enhanced security — with `origin`, `ctlNum`, `Check`, `Test`, time-activated operate and `Cancel`. A refused command comes back as its `AddCause`, not as success |
| **Server** (IEC 61850-8-1) | An SCL file is the whole configuration — no generated model, no build step. It publishes the flattened, sorted namespace the 8-1 mapping requires, answers browse, read, write and type discovery from the model, runs a report engine (one client per block, `BufTm` gathering, `GI`, integrity, and a buffered block that replays what a disconnected client missed), enforces all four control models with an application hook, keeps a value per setting group, serves files from a **sandboxed** store and writes logs. Timers run on a monotonic clock and `TimeOfEntry`, log times and `LActTm` on a pluggable wall clock — two different questions, never derived from one another. It takes its **edition** from the file's own schema version, so an Edition 1 file serves an Edition 1 report control block — no `ResvTms`, no `Owner`. `ied sim relay.icd` is a working IED |
| **SCL** (IEC 61850-6) | Load an IED model from ICD/CID/SCD — data sets, control blocks, addresses — resolve what an IED subscribes to from its `Inputs/ExtRef`, and check the engineering errors the XML schema permits. Lenient by default with stable diagnostic codes; strict on request |
| **`ied`** | Command line: `sim` (serve an SCD's IEDs), `mu`, `sv monitor` (`--scd` to name the channels), `goose sniff`, `mms sniff`, `mms identify/browse/read/write/rcb/report/control/type/files/get/log/sg` against a live server, `pcap info`, `scl validate`, `scl show`, `scl subs` |
| Supporting | Panic-free BER codec, the IEC 61850 wire types, classic pcap reader and writer |

**Not yet:** service tracking, `ObtainFile`, a durable log store, the edition-dependent
enumerations, raw-socket adapters, the IEC 62351-6 authentication extension, routable GOOSE/SV
(IEC TR 61850-90-5), TLS, and *emitting* fixed-length encoded GOOSE — decoding it works; the
widths table that encoding needs is behind the IEC paywall and is not worth guessing.

## Install

```bash
cargo add iec61850-rs
cargo install iec61850-rs --features cli    # the `ied` command line
```

No mandatory dependencies — and none optional either, apart from `roxmltree`, which arrives
only with the `scl` feature. The MMS client is blocking, so it needs no async runtime; the
protocol cores are sans-IO, so an async wrapper is an adapter over the same state machines
rather than a second implementation. Everything below `std` builds `no_std` (with `alloc`) on
`thumbv7em-none-eabihf`.

## Use it

Subscribe to a GOOSE stream — feed it frames and timer ticks, drain its events:

```rust
use iec61850_rs::MacAddr;
use iec61850_rs::proto::goose::{Subscriber, SubscriberConfig, SubscriberEvent, SubscriptionKey};

let mut sub = Subscriber::new(SubscriberConfig::new(SubscriptionKey {
    dst: MacAddr::parse("01-0C-CD-01-00-05")?,
    appid: 0x0005,
    gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into(),
}));

for event in sub.feed(now, &frame) {
    match event {
        SubscriberEvent::NewState { values, .. } => trip_logic(&values),
        SubscriberEvent::Expired => mark_inputs_invalid(),
        other => log::warn!("{other:?}"),
    }
}
```

Every core takes inputs with the caller's notion of *now*, yields outputs, and says when it
wants to be called again — no sockets, no threads, no clock reads, no trait to implement.
That is what lets the same code run under tokio, on a bare-metal timer, or inside a
deterministic simulation.

The engineering file is the configuration, for subscribers too. Addresses, APPIDs and
`confRev` are written once, in the SCD, and never a second time in code:

```rust
let subs = iec61850_rs::scl::subscriptions(&scd, "IED2", 50)?;   // 50 Hz system
for s in &subs.goose {
    subscribers.push(Subscriber::new(s.goose_config()));
}
```

A sampled-value subscription carries the publisher's **channel layout** with it, so samples
arrive decoded rather than as a block of octets — for any engineered data set, not only
9-2LE's fixed one:

```rust
let mut sv = iec61850_rs::proto::sv::Subscriber::new(subs.sv.iter().map(|s| s.sv_config()).collect());
sv.on_frame(now, &frame, |s| {
    for (channel, value) in s.channels() {      // "LD0/TCTR1.AmpSv.instMag.i" = 12345
        protection.feed(&channel.name, value);
    }
});
```

Talking to a real IED is one call — the six OSI layers, the ACSE association and the MMS
`Initiate` are all inside it — and it needs no async runtime and no extra dependency:

```rust
use iec61850_rs::{Fc, client::Client};

let mut c = Client::connect("10.0.0.5:102")?;
for ld in c.server_directory()? {                      // the logical devices
    for name in c.logical_device_directory(&ld)? {      // …and everything in them
        println!("{ld}/{name}");
    }
}
let w = c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX)?;   // one round trip, typed back
c.release()?;
```

Reports come back **decoded**. Which fields a report carries is decided entirely by the
control block's `OptFlds` — there is no tag on the wire to fall back on — so the same code that
enables the block is what knows how to read what it sends:

```rust
use iec61850_rs::client::{RcbSettings, TrgOps};

c.enable_rcb("IED1LD0/LLN0$RP$urcb01", Fc::RP,
             &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS))?;

while let Some(r) = c.next_report(Duration::from_secs(5))? {
    println!("{} sq={:?} {}/{} members", r.rpt_id, r.seq_num, r.entries.len(), r.data_set_len());
    for e in &r.entries {
        println!("  [{}] {:?}  reason {:?}", e.index, e.value, e.reason);
    }
}
```

Controls are one call whichever of the four models the object is engineered with — and a
command the substation *refuses* comes back as a refusal, not as a successful write:

```rust
use iec61850_rs::client::{Check, ControlModel, OriginCategory};
use iec61850_rs::proto::data::Dbpos;

c.control("IED1LD0/CSWI1.Pos")
    .model(ControlModel::SboEnhanced)                  // read it from the SCD, or ask the server
    .origin(OriginCategory::StationControl, "hmi-1")
    .check(Check { synchro: true, interlock: true })
    .execute(&Value::dbpos(Dbpos::On))?;               // Err(ControlRejected { add_cause })
```

A COMTRADE record, a log and a setting group are the three things a commissioning engineer
reaches for after the values, and each is one call:

```rust
for f in c.file_directory(Some("COMTRADE"))? {              // list, then pull
    let bytes = c.read_file(&f.name, 16 << 20)?;            // the handle is closed either way
    std::fs::write(&f.name, bytes)?;
}

let lcb = c.read_lcb("IED1LD0/LLN0$LG$lcb01", Fc::LG)?;     // where the log starts
let (id, at) = lcb.oldest().expect("an entry");
let page = c.query_log_after_entry("IED1LD0/LLN0$GeneralLog", &id, at)?;

c.edit_setting_group("IED1LD0/LLN0$SP$SGCB", 2,             // select ▸ write ▸ confirm ▸ release
                     &[("IED1LD0/PTOC1.StrVal.setMag.f", Value::Float32(1.25))])?;
```

And when a write is refused because the value was the wrong shape, the server will say what
the right one is:

```rust
let oper = c.variable_type("IED1LD0/CSWI1.Pos.Oper", Fc::CO)?;
assert_eq!(oper.component_names(), ["ctlVal", "origin", "ctlNum", "T", "Test", "Check"]);
```

And the other half: an SCL file is a **server**. No generated model, no build step, no second
description of the IED to keep in step with the first.

```rust
use iec61850_rs::server::{Ied, Server, Stage};

let mut server = Server::bind("0.0.0.0:102", Ied::from_scl_file("relay.cid", None)?)?;
server.on_control(Box::new(|event| match event.stage {      // what the switchgear says
    Stage::Operate => breaker.operate(&event.request.ctl_val),
    _ => Ok(()),
}));

let updates = server.handle();                              // the application never locks
std::thread::spawn(move || loop {
    updates.txn()                                           // a batch becomes visible at once
        .set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(tripped()))
        .commit();                                          // → reports, log entries
});
server.run()?;
```

```bash
ied sim relay.icd                                    # …or the same thing with no code at all
ied mu stream.pcap --profile f4800s2 --frames 2000   # a virtual merging unit, IEC 61869-9
ied sv monitor stream.pcap                           # the library's own subscriber, over a capture
ied sv monitor stream.pcap --scd bay.scd             # …with every ASDU channel named by the SCD
ied goose sniff bay.pcap                             # gocbRef, stNum/sqNum, TAL, simulation bit
ied mms sniff station.pcap                           # six OSI layers: association, services, values
ied mms browse 10.0.0.5                              # a live server: devices, data, data sets
ied mms read 10.0.0.5 IED1LD0/MMXU1.TotW.mag.f --fc MX
ied mms rcb 10.0.0.5 IED1LD0/LLN0.urcb01             # a report control block's configuration
ied mms report 10.0.0.5 --rcb IED1LD0/LLN0.urcb01 --gi
ied mms control 10.0.0.5 IED1LD0/CSWI1.Pos true --model sbo-enhanced
ied mms type 10.0.0.5 IED1LD0/CSWI1.Pos.Oper --fc CO   # the shape a write has to match
ied mms files 10.0.0.5                               # what the IED has stored
ied mms get 10.0.0.5 COMTRADE/rec0001.cfg out.cfg    # …and pull one off it
ied mms log 10.0.0.5 IED1LD0/LLN0\$GeneralLog --lcb IED1LD0/LLN0.lcb01
ied mms sg 10.0.0.5 --activate 2                     # put setting group 2 into force
ied scl validate relay.icd                           # the engineering errors the schema permits
ied scl subs bay.scd IED2                            # every ExtRef resolved to its publisher
```

`ied sim` serves every IED in an SCD, each on its own port, and prints the map. It is a real
server — browse it, enable a report control block on it, operate its breaker — which is also
how the `ied mms` subcommands are tested in CI: one binary talking to itself over a real
association, with no device and no network interface.

`goose sniff` and `sv monitor` run the library's own subscriber state machines over the
capture, so what they report about a frame is what a subscribing IED would decide about it —
replays and all, not a second implementation that could drift from the first.

## Examples

Each runs to completion with no device, no network and no arguments:

```bash
cargo run --example server_from_scl     # an SCL file served, browsed, reported and operated
cargo run --example mms_loopback        # the association state machine, both roles, over a socket
cargo run --example goose_roundtrip     # a publisher driving a subscriber
cargo run --example sv_merging_unit     # 2400 frames/s, decoded back
cargo run --example scl_model           # an SCD as the configuration
```

## Why trust it

- Every frame of a two-IED SEL **GOOSE capture** and all **10,161 frames** of a 9-2LE
  sampled-value capture decode and **re-encode byte for byte**. The sampled-value publisher,
  configured as that merging unit was, reproduces its frames exactly.
- A real **MMS association** — 165 packets — decodes through TPKT, COTP, session,
  presentation, ACSE and MMS, and **653 of its 656 encodings come back byte for byte**. The
  three that do not are where that server writes a length non-minimally; those are held to
  being a fixed point instead.
- **The stack is its own test peer, on both sides.** The suite loads an SCL file into the real
  server and runs the real client against it over a loopback socket: browse the namespace and
  check it is sorted and complete, enable a control block and watch a change arrive with the
  right reason code, take that block over from a second client, replay a buffered block to a
  client that was not there, run all four control models, activate a setting group, pull a file
  and fail to escape its sandbox. That proves the two halves agree about the *mapping* — not
  that either is right; two implementations by one author sharing one codec agree by
  construction, and only interop against another stack moves that.
- **Wireshark is the oracle**: frames the encoders emit are dissected by `tshark` on every
  push, and a malformed marker fails the build.
- An **adversarial simulation** runs publisher against subscriber under loss, reordering,
  duplication, replay and partition across 512 seeds in CI, asserting invariants that are
  themselves mutation-tested.
- **Zero allocations** in the steady state is a *measured* number, not a claim: a counting
  global allocator asserts none across a thousand GOOSE retransmissions, a thousand state
  changes, and a second of IEC 61869-9 publishing and reception.
- **Ten fuzz targets**, `#![forbid(unsafe_code)]`, and `unwrap`/`expect`/`panic`/indexing
  denied by lint in library code. An input that once crashed a fuzzer is renamed after the bug
  and kept as a regression test, not left in a gitignored artifacts directory.
- Every MMS, report and control encoder is required to be a **fixed point** — the only
  automatic check on a format with no tags to catch a field read at the wrong offset. Every
  feature builds and tests **on its own** in CI, and so does none of them.
- **A negative is pinned too**: the reference capture's 115 information reports are ICCP
  data-set reports, *not* IEC 61850 reports, and the client's classifier has to say so rather
  than inventing a report identifier out of the first value.
- **Real corpora, not fixtures**: every data-set member of OpenSCD's SCL files must resolve,
  and the SCL-described channel layout must decode all 10,161 captured ASDUs exactly as the
  hard-coded 9-2LE path does.

Details, and an honest list of what this does *not* prove, in
[Verification](https://hupe1980.github.io/iec61850-rs/docs/verification/).

## Develop

```bash
cargo test --all-features                     # captures and tshark tests skip if absent
SIM_SEED=42 cargo test --test simulation      # replay one simulation seed
cargo +nightly fuzz run mms_association -- -max_total_time=60
cargo test --test regressions                 # every input a fuzzer once crashed on
cargo build --no-default-features --features goose,sv,mms --target thumbv7em-none-eabihf
```

IEC standards are copyrighted and are not part of this repository.
`scripts/fetch-specs.sh` fetches the freely available material — ITU-T recommendations, RFCs,
public standard previews, sample captures and OpenSCD test fixtures — into a git-ignored
`specs/`. The tests that use them skip when it is absent.

## Licence

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

An independent implementation, not affiliated with or endorsed by the IEC.
