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
| `log-redb` | A durable server log in a redb file. Pulls in `redb` |
| `net` | GOOSE and SV on a live interface (Linux AF_PACKET, macOS/FreeBSD BPF) through [`rawether`](https://crates.io/crates/rawether) |
| `cli` | The `ied` command line. Implies every other feature |

There is no `alloc` feature: the crate is `no_std` **+ alloc** in every configuration. Every
feature builds on its own, and so does none of them.

```bash
cargo add iec61850-rs --no-default-features --features goose   # GOOSE on an MCU
brew install hupe1980/tap/ied                                  # the command line
cargo install iec61850-rs --features cli                       # …or from source
```

The crate has **no mandatory dependencies**. The optional ones come with a feature each:
`roxmltree` (`scl`), `redb` (`log-redb`) and `rawether` (`net`). The MMS client and server are
blocking, so there is no async runtime in the tree.

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

`GoosePduView` **borrows** the frame; nothing is copied until you ask for owned values with
`all_data_owned`.

## Subscribe to a stream

A subscriber is a state machine: feed it frames and timer ticks, and drain its events:

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

`Expired` is the one you must handle: no frame arrived within the publisher's
`timeAllowedtoLive`, so the values you hold are no longer trustworthy. Replays, `confRev`
mismatches and simulated frames are filtered out before they reach you, and counted in
`sub.stats()`.

The values are the data set's members; the `Typed` trait reads each as its IEC 61850-7-3 type:

```rust
use iec61850_rs::proto::data::{Dbpos, Typed};

let closed = values[0].member(0).and_then(Typed::as_dbpos) == Some(Dbpos::On);
let quality = values[0].member(1).and_then(Typed::as_quality);
```

Nothing is coerced: an integer where a boolean was engineered returns `None`.

## Publish sampled values

```rust
use iec61850_rs::proto::sv::{Publisher, PublisherConfig, SmpSynch, SvProfile};

// 9-2LE, 80 samples per cycle at 50 Hz.
let mut mu = Publisher::new(PublisherConfig::new(header, "MU01", SvProfile::LE_80_50HZ))?;
mu.set_smp_synch(SmpSynch::Global)?;  // stream state, set when the clock changes

mu.publish(now, &[&sample_block])?;
if let Some(frame) = mu.poll_transmit() {
    socket.send(frame)?;
}
```

`poll_transmit` returns a slice of a buffer the publisher owns, so the steady state allocates
nothing. [Sampled Values](@/docs/sampled-values.md) has the profiles and the sample layout.

## Subscribe to sampled values, with the channels named

An ASDU's sample block is the data set's members written back to back, so a subscriber has to
be told the shape. `scl::subscriptions` reads it from the engineering file:

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

That works for any fixed-width data set, and the values are read straight out of the frame
without allocating. Without a layout `sample.asdu.sample` holds the raw octets, and 9-2LE's
fixed set has `le::PhsMeas1::decode`.

## Talk to a server

The station bus is a connection. `Client::connect` opens all six OSI layers, the ACSE
association and the MMS `Initiate` in one call, with no async runtime:

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

Reports come back decoded, with exactly the fields the control block's `OptFlds` selects:

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

A control is one call whichever of the four models the object uses. A refused command comes
back as `Error::ControlRejected` with its `AddCause`, never as a successful write:

```rust
use iec61850_rs::client::{Check, ControlModel, OriginCategory};
use iec61850_rs::proto::data::Dbpos;

c.control("IED1LD0/CSWI1.Pos")
    .model(ControlModel::SboEnhanced)
    .origin(OriginCategory::StationControl, "hmi-1")
    .check(Check { synchro: true, interlock: true })
    .execute(&Value::dbpos(Dbpos::On))?;
```

Files, logs and setting groups are one call each:

```rust
let bytes = c.read_file("COMTRADE/rec0001.cfg", 16 << 20)?;   // the handle is closed either way

let lcb = c.read_lcb("IED1LD0/LLN0$LG$lcb01", Fc::LG)?;
let (id, at) = lcb.oldest().expect("an entry");
let page = c.query_log_after_entry("IED1LD0/LLN0$GeneralLog", &id, at)?;

c.edit_setting_group("IED1LD0/LLN0$SP$SGCB", 2,               // select ▸ write ▸ confirm ▸ release
                     &[("IED1LD0/PTOC1.StrVal.setMag.f", Value::Float32(1.25))])?;
```

[MMS](@/docs/mms.md) covers the client in full; [Server](@/docs/server.md) covers the other half,
which is an SCL file and a socket:

```rust
use iec61850_rs::server::{Ied, Server};

let server = Server::bind("0.0.0.0:102", Ied::from_scl_file("relay.cid", None)?)?;
server.handle().txn().set("IED1LD0/PTRC1$ST$Tr$general", Value::Boolean(true)).commit();
server.run()?;
```

## Where the frames come from

The protocol cores never open a socket ([why](@/docs/protocols.md#sans-io)); frames come from
wherever you get them. Capture files are a ready source and sink:

```rust
use iec61850_rs::pcap::Capture;

for (nanos, frame) in Capture::read("bay.pcap")?.frames {
    sub.on_frame(Instant(nanos), &frame);
}
```

On a live network, the `net` feature's `Link` hands frames to the same `on_frame`, with the
monotonic instant they arrived at:

```rust
use iec61850_rs::net::{Link, LinkOptions};

let mut link = Link::open("eth1", &LinkOptions::goose().join(key.dst))?;
iec61850_rs::net::drop_capabilities()?;      // CAP_NET_RAW is not needed any more
while let Some(rx) = link.recv(Some(Duration::from_millis(10)))? {
    sub.on_frame(rx.at, rx.frame);           // rx.wire_time: the kernel's timestamp
}
```

The kernel filters on the EtherType and the joined groups before a frame reaches user space.
Grant the capability to the binary (`setcap cap_net_raw+ep`) rather than running as root; on
macOS the program needs access to `/dev/bpf*`.

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
| `supervised_subscriber` | A GOOSE subscription's health published as an `LGOS` and read back by a client |

## Next

- [How GOOSE and Sampled Values work](@/docs/protocols.md) — the vocabulary the rest of the
  guide uses.
- [MMS](@/docs/mms.md) and [Server](@/docs/server.md) — the station bus, from each end.
- [Command line](@/docs/cli.md) — the same operations without writing any code.
