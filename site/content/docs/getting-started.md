+++
title = "Getting started"
description = "Install iec61850-rs, decode a GOOSE frame, subscribe to a stream, publish sampled values, and talk MMS as a client or a server — with the feature flags that keep the build small."
weight = 10
+++

## Install

```bash
cargo add iec61850-rs
```

The package is `iec61850-rs`; the library it provides is `iec61850_rs`, as Cargo's usual
hyphen-to-underscore rule implies. (`iec61850` on crates.io belongs to an unrelated project.)

| Feature | Effect |
|---|---|
| `std` *(default)* | The standard library — files, sockets, `std::error::Error`. Without it the crate is `no_std` |
| `goose` *(default)* | GOOSE codec, publisher and subscriber |
| `sv` *(default)* | Sampled Values codec, publisher and subscriber |
| `mms` *(default)* | The OSI stack (TPKT, COTP, session, presentation, ACSE), the MMS PDUs, and the association state machine over all six |
| `client` *(default)* | The blocking MMS client over TCP — browse, read, write, reporting, control, files, logs, setting groups. Implies `std` and `mms`; adds no dependency |
| `server` *(default)* | The blocking MMS server: an SCL file is the namespace, with a report engine, the four control models, setting groups, a sandboxed file store and logs. Implies `std`, `mms` and `scl` |
| `scl` *(default)* | Load an IED model from ICD/CID/SCD files. Pulls in `roxmltree` |
| `pcap` *(default)* | Read and write classic pcap capture files |
| `cli` | The `ied` command line. Implies every other feature |

There is no `alloc` feature: the encoder is a `Vec`, the model owns `String`s, and the bounded
event queue every core hands its events through is a `VecDeque`, so the crate is `no_std`
**+ alloc** and there is no configuration without an allocator.

Every feature builds on its own — and so does none of them — and CI checks that on every push.

```bash
cargo add iec61850-rs --no-default-features --features goose   # GOOSE on an MCU
cargo install iec61850-rs --features cli                       # the command line
```

The protocol core has **no mandatory dependencies**, and only one optional: `roxmltree`, which
arrives with `scl` and which a device configured at build time does not need. The MMS client is
blocking, so there is no async runtime in the tree either — the cores are sans-IO, so an async
wrapper would be an adapter over the same state machines rather than a second implementation.

## Decode a frame

Everything on the process bus is an Ethernet frame carrying a BER-encoded PDU. Parsing is
two steps, and neither can panic on hostile input:

```rust
use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, Frame};
use iec61850_rs::proto::goose::GoosePduView;

let frame = Frame::parse(bytes)?;          // link layer: MAC, VLAN, APPID, length
if frame.ethertype == ETHERTYPE_GOOSE {
    let pdu = GoosePduView::parse(frame.apdu)?;
    println!("{} stNum={} sqNum={}", pdu.gocb_ref, pdu.st_num, pdu.sq_num);
}
```

`GoosePduView` **borrows** the frame. Nothing is copied until you ask for owned values with
`all_data_owned`, which is what keeps a subscriber allocation-free while a publisher is only
retransmitting.

## Subscribe to a stream

A subscriber is a state machine, not a callback registry. You feed it frames and timer ticks
and drain its events:

```rust
use iec61850_rs::common::Instant;
use iec61850_rs::proto::ethernet::MacAddr;
use iec61850_rs::proto::goose::{Subscriber, SubscriberConfig, SubscriberEvent, SubscriptionKey};

let mut sub = Subscriber::new(SubscriberConfig::new(SubscriptionKey {
    dst: MacAddr::parse("01-0C-CD-01-00-05")?,
    appid: 0x0005,
    gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into(),
}));

for event in sub.feed(now, &frame) {
    match event {
        SubscriberEvent::NewState { st_num, values, .. } => trip_logic(&values),
        SubscriberEvent::Expired => hold_last_state_invalid(),
        other => log::warn!("{other:?}"),
    }
}
sub.on_timeout(now);   // call again by sub.next_timeout()
```

`Expired` is the one you must handle: it means no frame arrived within the publisher's
`timeAllowedtoLive`, so the values you are holding are no longer trustworthy. Everything
else — replays, `confRev` mismatches, simulated frames — is filtered out before it reaches
you, and counted in `sub.stats()`.

The values are the data set's members, and the `Typed` trait reads each one as the
IEC 61850-7-3 type it claims to be rather than making you match on the wire encoding:

```rust
use iec61850_rs::proto::data::{Dbpos, Typed};

let closed = values[0].member(0).and_then(Typed::as_dbpos) == Some(Dbpos::On);
let quality = values[0].member(1).and_then(Typed::as_quality);
```

Nothing is coerced: an integer where a boolean was engineered returns `None`, because that
is a fault to report rather than a number to reinterpret.

## Publish sampled values

```rust
use iec61850_rs::proto::sv::{Publisher, PublisherConfig, SmpSynch, SvProfile};

// 9-2LE, 80 samples per cycle at 50 Hz.
let mut mu = Publisher::new(PublisherConfig::new(header, "MU01", SvProfile::LE_80_50HZ))?;
mu.set_smp_synch(SmpSynch::Global);   // stream state, set when the clock changes

mu.publish(now, &[&sample_block])?;
if let Some(frame) = mu.poll_transmit() {
    socket.send(frame)?;
}
```

`poll_transmit` hands back a slice of a buffer the publisher owns and rewrites, so the
steady state allocates nothing. See [Sampled Values](@/docs/sampled-values.md) for the
profiles and the sample layout.

## Subscribe to sampled values, with the channels named

An ASDU's sample block is the data set's members written back to back with nothing on the
wire to separate them, so a subscriber has to be told the shape. The engineering file is
where the shape is written, and `scl::subscriptions` brings it along:

```rust
use iec61850_rs::proto::sv::Subscriber;

let subs = iec61850_rs::scl::subscriptions(&scd, "IED2", 50)?;
let mut sv = Subscriber::new(subs.sv.iter().map(|s| s.sv_config()).collect());

sv.on_frame(now, &frame, |sample| {
    for (channel, value) in sample.channels() {
        // "LD0/TCTR1.AmpSv.instMag.i" = Int(12345), "LD0/TCTR1.AmpSv.q" = Quality(good)
        protection.feed(&channel.name, value);
    }
});
```

That works for any fixed-width data set, not only 9-2LE's — and it costs nothing, because
the values are read straight out of the frame's octets on the receiving thread. Without a
layout `sample.asdu.sample` is still there as raw octets, and 9-2LE's fixed set has
`le::PhsMeas1::decode` for exactly that.

## Talk to a server

The process bus is multicast frames; the station bus is a connection. `Client::connect` opens
all six OSI layers, the ACSE association and the MMS `Initiate` in one call — and needs no
async runtime, because the state machine underneath it is sans-IO and the socket is a
ninety-line adapter:

```rust
use iec61850_rs::{Fc, client::Client};

let mut c = Client::connect("10.0.0.5:102")?;
for ld in c.server_directory()? {                      // the logical devices
    for name in c.logical_device_directory(&ld)? {      // …and everything in them
        println!("{ld}/{name}");
    }
}
let w = c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX)?;
c.release()?;
```

Reports come back decoded, with every field the control block's `OptFlds` promised — and no
field it did not, because on the wire there is nothing to tell them apart:

```rust
use iec61850_rs::client::{RcbSettings, TrgOps};

c.enable_rcb("IED1LD0/LLN0$RP$urcb01", Fc::RP,
             &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS))?;

while let Some(r) = c.next_report(Duration::from_secs(5))? {
    for e in &r.entries {
        println!("[{}] {:?} because {:?}", e.index, e.value, e.reason);
    }
}
```

And a control is one call whichever of the four models the object is engineered with. A
command the substation *refuses* comes back as a refusal with its `AddCause`, never as a
successful write:

```rust
use iec61850_rs::client::{Check, ControlModel, OriginCategory};
use iec61850_rs::proto::data::Dbpos;

c.control("IED1LD0/CSWI1.Pos")
    .model(ControlModel::SboEnhanced)
    .origin(OriginCategory::StationControl, "hmi-1")
    .check(Check { synchro: true, interlock: true })
    .execute(&Value::dbpos(Dbpos::On))?;
```

The three things a commissioning engineer reaches for after the values are a COMTRADE record,
a log and a setting group, and each is one call:

```rust
let bytes = c.read_file("COMTRADE/rec0001.cfg", 16 << 20)?;   // the handle is closed either way

let lcb = c.read_lcb("IED1LD0/LLN0$LG$lcb01", Fc::LG)?;
let (id, at) = lcb.oldest().expect("an entry");
let page = c.query_log_after_entry("IED1LD0/LLN0$GeneralLog", &id, at)?;

c.edit_setting_group("IED1LD0/LLN0$SP$SGCB", 2,               // select ▸ write ▸ confirm ▸ release
                     &[("IED1LD0/PTOC1.StrVal.setMag.f", Value::Float32(1.25))])?;
```

[MMS](@/docs/mms.md) has the layers, the association, the report format, the control models,
the file and log services and the setting-group rules in full — and [Server](@/docs/server.md)
has the other half, which is an SCL file and a socket:

```rust
use iec61850_rs::server::{Ied, Server};

let server = Server::bind("0.0.0.0:102", Ied::from_scl_file("relay.cid", None)?)?;
server.handle().txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
server.run()?;
```

## Where the frames come from

The library does not open sockets — see [the protocol primer](@/docs/protocols.md#sans-io) for why. Until
the raw-socket adapters land, capture files are the practical source and sink:

```rust
use iec61850_rs::pcap::Capture;

for (nanos, frame) in Capture::read("bay.pcap")?.frames {
    sub.on_frame(Instant(nanos), &frame);
}
```

On Linux you would bind an `AF_PACKET` socket and pass what it gives you to the same
`on_frame`; nothing above changes.

## Runnable examples

Each of these runs to completion with no device, no network and no arguments — clone the
repository and `cargo run --example <name>`.

| Example | What it shows |
|---|---|
| `goose_roundtrip` | A publisher driving a subscriber under virtual time: the T1…T0 curve, a state change, the events |
| `sv_merging_unit` | IEC 61869-9 at 2400 frames/s, decoded back; writes a pcap if given a path |
| `mms_loopback` | The association state machine driving both roles of a real association over a loopback socket |
| `server_from_scl` | A real server built from an SCL file and a real client against it, in one process: browse, report, control |
| `scl_model` | An SCD as the configuration: model, subscriptions, addressing, control models, validation |

## Next

- [How GOOSE and Sampled Values work](@/docs/protocols.md) — what they actually are, and the
  vocabulary the rest of the guide uses.
- [MMS](@/docs/mms.md) and [Server](@/docs/server.md) — the station bus, from each end.
- [Command line](@/docs/cli.md) — the same operations without writing any code.
