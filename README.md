# iec61850-rs

[![CI](https://github.com/hupe1980/iec61850-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/hupe1980/iec61850-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#licence)

**IEC 61850 in Rust.** Publishers and subscribers for the substation process bus, an MMS
**client and server** for the station bus, panic-free decoders, sans-IO state machines, and
encoders checked against real substation captures frame for frame.

📖 **[Documentation and guide](https://hupe1980.github.io/iec61850-rs/)** · 📋 **[Changelog](CHANGELOG.md)**

> **Pre-release.** The API will change, and nothing here has been through a conformance
> laboratory — see [Verification](https://hupe1980.github.io/iec61850-rs/docs/verification/).

## What works today

| | |
|---|---|
| **GOOSE** (IEC 61850-8-1) | Codec, publisher with the T1…T0 retransmission curve, subscriber with the IEC 62351-6 replay rule and Edition 2 simulation-bit semantics |
| **Sampled Values** (IEC 61850-9-2) | Codec, template-patching publisher for the 9-2LE and IEC 61869-9 profiles, multi-stream subscriber tracking continuity, sync, grandmaster and staleness. **Any** engineered data set decodes: the SCL file gives each ASDU channel its name, type and offset |
| **MMS** (IEC 61850-8-1) | TPKT, COTP class 0 with TSDU reassembly, session, presentation, ACSE, the MMS PDUs, and the association state machine over all six in **both roles** — invoke tracking, segmentation, timeouts, orderly release, ACSE password, typed rejects |
| **MMS client** | Blocking, no runtime, no dependency. Connect (from the SCD if you like), `Status`, `Identify`, `GetCapabilityList`, browse with `moreFollows` paging, read and write, type discovery, data-set create and delete. Reconnects on a `Backoff` you state; what belonged to the old association is yours to re-enable |
| **Arrays** (IEC 61850-8-1 §7.3) | An array is where the MMS namespace stops, so the reference is the whole API: `read("…/MHAI1.HA.phsAHar(2).cVal.mag.f")` becomes one named variable plus an ISO 9506 selection. SCL's `count` builds the array, `FCDA/@ix` puts one element in a data set, and a selection the server cannot serve is refused rather than answered with the whole array |
| **Reporting** (IEC 61850-8-1 §17) | Configure and enable a control block, request a general interrogation, and receive reports **decoded** — per member its index, reference, value and reason. A member that names a data *object* is one member, carried as the structure it is. Reports too large for the negotiated PDU are **segmented** by the server and rejoined by the client |
| **Files** (IEC 61850-8-1 §23) | List, read and delete. The `frsmID` is released even when a read fails partway; the server's store is read in **ranges**, so a read costs a chunk however big the record is |
| **Logs** (IEC 61850-7-2 §17) | Read the control block, then `QueryLogByTime` or `QueryLogAfterEntry` — the latter carries the `EntryID` *and* its time, so a reconnecting client resumes without a gap or a duplicate. Server-side entries live behind a `LogStore` trait |
| **Supervision** (IEC 61850-7-4) | `LGOS` and `LSVS`: a subscriber's own state — live, `ndsCom`, arriving `confRev`, simulated — published into the logical node the SCL file declares |
| **Service tracking** (IEC 61850-7-2 §14) | What happened on the *wire*, which no report can say: who enabled that control block, which client was refused with what, and who read the sequence-of-events log. The file declares a tracking object by its `cdc`, the server fills it in, and an ordinary report control block carries it. All ten classes, including the log queries (`OTS`) and one control tracker per kind of controlled object |
| **Setting groups** (IEC 61850-7-2 §11) | Read the `SGCB`, activate a group, or select ▸ write ▸ confirm ▸ release an edit in one call, which refuses to confirm if any write was rejected. The server serves a setting under **both** `SG` and `SE` from the one declaration SCL allows, and expires an abandoned edit reservation on `ResvTms` |
| **Control** (IEC 61850-7-2 §20) | All four models behind one `execute`, with `origin`, `ctlNum`, `Check`, `Test`, time-activated operate and `Cancel`. The model is **read off the server** when the caller does not state one, so a select-before-operate object is not driven as a direct control. A refusal comes back as its `AddCause` |
| **Server** (IEC 61850-8-1) | An SCL file is the whole configuration — no generated model, no build step. The 8-1 namespace, browse, read, write, type discovery, a report engine (`BufTm` gathering, `GI`, integrity, buffered replay), all four control models behind an application hook, per-group setting values, a sandboxed file store, logs, and the GOOSE and SV control blocks with the addresses the file gives them. A client may write what the **functional constraint** allows and nothing else; a command is refused unless `Beh` takes it. Monotonic clock for timers, pluggable wall clock for timestamps. The **edition** comes from the file's own schema version. Every queue is bounded, including the one that holds a slow client's reports |
| **SCL** (IEC 61850-6) | Load an IED model from ICD/CID/SCD, resolve what an IED subscribes to from its `Inputs/ExtRef`, and check the engineering errors the XML schema permits — and the few it forbids, since the loader does not validate against the XSD. Lenient by default with stable diagnostic codes; strict on request |
| **`ied`** | `sim`, `mu`, `sv monitor`, `goose sniff`, `mms sniff`, `mms status/identify/browse/read/write/rcb/report/control/type/files/get/log/sg`, `pcap info`, `scl validate`, `scl show`, `scl subs` |
| Supporting | Panic-free BER codec, the IEC 61850 wire types, classic pcap reader and writer |

**Not included:** `ObtainFile`/`SetFile`, a durable `LogStore` backend, the edition-dependent
enumerations, raw-socket adapters, the IEC 62351-6 authentication extension, routable GOOSE/SV
(IEC TR 61850-90-5), TLS, and *emitting* fixed-length encoded GOOSE — decoding it works; the
widths table encoding needs is behind the IEC paywall.

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

The engineering file is the configuration for subscribers too: addresses, APPIDs and
`confRev` are written once, in the SCD.

```rust
let subs = iec61850_rs::scl::subscriptions(&scd, "IED2", 50)?;   // 50 Hz system
for s in &subs.goose {
    subscribers.push(Subscriber::new(s.goose_config()));
}
```

A sampled-value subscription carries the publisher's **channel layout** with it, so samples
arrive decoded rather than as a block of octets — for any engineered data set:

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

Reports come back **decoded**. Which fields one carries is decided entirely by the control
block's `OptFlds`, so the code that enables the block is what knows how to read it:

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

Controls are one call whichever of the four models the object is engineered with, and a
refusal comes back as a refusal rather than as a successful write:

```rust
use iec61850_rs::client::{Check, ControlModel, OriginCategory};
use iec61850_rs::proto::data::Dbpos;

c.control("IED1LD0/CSWI1.Pos")
    .model(ControlModel::SboEnhanced)                  // read it from the SCD, or ask the server
    .origin(OriginCategory::StationControl, "hmi-1")
    .check(Check { synchro: true, interlock: true })
    .execute(&Value::dbpos(Dbpos::On))?;               // Err(ControlRejected { add_cause })
```

A COMTRADE record, a log and a setting group are one call each:

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

When a write is refused for the wrong shape, the server will say what the right one is:

```rust
let oper = c.variable_type("IED1LD0/CSWI1.Pos.Oper", Fc::CO)?;
assert_eq!(oper.component_names(), ["ctlVal", "origin", "ctlNum", "T", "Test", "Check"]);
```

The other half: an SCL file is a **server**. No generated model, no build step, no second
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
ied mms status 10.0.0.5                              # is it alive? the cheapest round trip there is
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

`ied sim` serves every IED in an SCD, each on its own port. It is a real server — browse it,
enable a report control block, operate its breaker — and it is how the `ied mms` subcommands
are tested in CI: one binary talking to itself, with no device and no network interface.

`goose sniff` and `sv monitor` drive the library's own subscriber state machines, so what they
report about a frame is what a subscribing IED would decide about it.

## Examples

Each runs to completion with no device, no network and no arguments:

```bash
cargo run --example server_from_scl     # an SCL file served, browsed, reported and operated
cargo run --example mms_loopback        # the association state machine, both roles, over a socket
cargo run --example goose_roundtrip     # a publisher driving a subscriber
cargo run --example sv_merging_unit     # 2400 frames/s, decoded back
cargo run --example scl_model           # an SCD as the configuration
cargo run --example supervised_subscriber  # a GOOSE subscription's health, published as LGOS
```

## Why trust it

- A two-IED SEL **GOOSE capture** and all **10,161 frames** of a 9-2LE sampled-value capture
  decode and **re-encode byte for byte**; the publisher, configured as that merging unit was,
  reproduces its frames exactly.
- A real 165-packet **MMS association** decodes through all six OSI layers, and 653 of its 656
  encodings come back byte for byte. The three that do not are where that server writes a
  length non-minimally, and are held to being a fixed point instead.
- **Wireshark is the oracle, for both buses.** A recording proxy runs one full association
  between the real client and the real server through every service it answers; the capture is
  dissected as TPKT ▸ COTP ▸ session ▸ presentation ▸ ACSE ▸ MMS and asserted in Wireshark's
  own field names. It found three malformed PDUs that a self-checking suite could not.
- **libiec61850 drives this server, and this client drives libiec61850's**, in CI. Their
  client browses, reads, discovers types, operates all four control models, reads array
  elements and takes reports; this client does the same against their server, plus the log
  services. A dissector says whether a PDU is well-formed; only a peer says whether it is the
  PDU that was expected, in the order it was expected — which is where most of the defects
  found so far have lived.
- **The stack is its own test peer on both sides**, over a loopback socket, from an SCL file.
  That proves the two halves agree about the mapping — not that either is right, which is why
  the two entries above exist.
- An **adversarial simulation** runs publisher against subscriber under loss, reordering,
  duplication, replay and partition across 512 seeds in CI.
- **Zero allocations** in the steady state is a measured number: a counting global allocator
  asserts none across a thousand GOOSE retransmissions and a second of IEC 61869-9 publishing.
- **Ten fuzz targets**, `#![forbid(unsafe_code)]`, and `unwrap`/`expect`/`panic`/indexing
  denied by lint in library code. Every fuzzer crash is kept as a named regression test.
- **Real corpora, not fixtures**: every data-set member of OpenSCD's SCL files must resolve,
  and the SCL-described channel layout must decode all 10,161 captured ASDUs.

Details, and an honest list of what this does *not* prove, in
[Verification](https://hupe1980.github.io/iec61850-rs/docs/verification/).

## Develop

```bash
cargo test --all-features                     # captures and tshark tests skip if absent

# The interop oracle: libiec61850 in both roles. Skips unless it is built and pointed at.
git clone --depth 1 https://github.com/mz-automation/libiec61850 /tmp/libiec61850
make -C /tmp/libiec61850 -j examples
IEC61850_LIBIEC61850=/tmp/libiec61850 cargo test --all-features --test interop

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
