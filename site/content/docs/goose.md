+++
title = "GOOSE"
description = "Publish and subscribe to IEC 61850 GOOSE in Rust: the retransmission curve, the IEC 62351-6 replay rule, Edition 2 simulation, and the counters an IDS wants."
weight = 30
+++

GOOSE carries protection signals between IEDs — a trip, an interlock, a block — as multicast
Ethernet frames that must arrive within 3 ms. There is no acknowledgement: the publisher
repeats itself, and the subscriber decides when it has gone quiet.

## Publishing

A publisher owns its retransmission schedule. You tell it when the data changed; it decides
when to send.

```rust
use iec61850_rs::common::UtcTime;
use iec61850_rs::proto::data::Value;
use iec61850_rs::proto::goose::{Publisher, PublisherConfig, Retransmission};

let mut pubr = Publisher::new(
    PublisherConfig {
        header,                                   // MAC, VLAN, APPID — from SCL (see below)
        gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into(),
        dat_set: "IED1LD0/LLN0$dsTrip".into(),
        go_id: Some("IED1".into()),
        conf_rev: 1,
        retransmission: Retransmission::DEFAULT,  // 4 ms → 1000 ms, TAL factor 2
        simulation: false,
        nds_com: false,
    },
    &[Value::Boolean(false)],                     // initial data set
    clock.now(),
)?;

loop {
    if trip_asserted() {
        pubr.publish(now, &[Value::Boolean(true)], clock.now())?;
    } else {
        pubr.on_timeout(now)?;
    }
    if let Some(frame) = pubr.poll_transmit() {
        socket.send(frame)?;
    }
    sleep_until(pubr.next_timeout());
}
```

`publish` is a **state change**: `stNum` increments, `sqNum` restarts at 0, and the
retransmission curve begins again. `on_timeout` is a repeat: `sqNum` increments and the
interval grows.

If your application has a scan cycle rather than events, hand the whole data set to
`publish_if_changed`. It compares the encoding with the one already on the wire and returns
`false` without touching `stNum` when nothing moved. It allocates nothing either way.

### The retransmission curve

`Retransmission` is the SCL `GSE` element in three numbers:

| Field | Meaning | SCL |
|---|---|---|
| `min_time_ms` | The first interval after a change (T1) | `MinTime` |
| `max_time_ms` | The steady-state heartbeat (T0) | `MaxTime` |
| `tal_factor` | `timeAllowedtoLive` = factor × the *next* interval | — |

With the default 4 ms → 1000 ms the intervals run 4, 4, 8, 16, 32 … 1000 ms, and the
advertised `timeAllowedtoLive` is twice whatever comes next. A subscriber can therefore lose
one frame and still hear the following one in time.

### Frames are borrowed, not allocated

`poll_transmit` returns a slice of a buffer the publisher owns and rewrites. Nothing is
allocated in the steady state or on a state change: both rewrite buffers the publisher already
holds. A frame not collected before the next is built is dropped and counted by
`pubr.dropped()`.

## Subscribing

```rust
use iec61850_rs::proto::goose::{Subscriber, SubscriberConfig, SubscriberEvent, SubscriptionKey};

let mut sub = Subscriber::new(
    SubscriberConfig::new(SubscriptionKey {
        dst: MacAddr::parse("01-0C-CD-01-00-05")?,
        appid: 0x0005,
        gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into(),
    })
    .with_conf_rev(1),
);

sub.on_frame(now, &bytes);
sub.on_timeout(now);
while let Some(event) = sub.poll_event() {
    match event {
        SubscriberEvent::NewState { st_num, t, values, simulation } => apply(&values),
        SubscriberEvent::Retransmission { .. } => {}          // the publisher is alive
        SubscriberEvent::Expired => mark_inputs_invalid(),     // it is not
        SubscriberEvent::NeedsCommissioning => alarm(),        // ndsCom is set
        SubscriberEvent::Invalid(why) => log::warn!("{why:?}"),
        other => log::info!("{other:?}"),
    }
}
```

### Reading the values

`NewState` hands over owned values, one per data-set member. Most members are structures —
`Tr` as an `ACT` is `{general, q, t}` — so the `Typed` trait reads each one as the
IEC 61850-7-3 type it claims to be:

```rust
use iec61850_rs::proto::data::{Dbpos, Typed};

let pos = &values[0];
match pos.member(0).and_then(Typed::as_dbpos) {
    Some(Dbpos::On) => closed(),
    Some(Dbpos::Off) => open(),
    // The two states a `bool` throws away: in transit, and both contacts disagreeing.
    Some(Dbpos::Intermediate | Dbpos::BadState) => alarm(),
    None => reject("Pos.stVal is not a double point"),
}
let quality = pos.member(1).and_then(Typed::as_quality);
```

Nothing is coerced: an integer where a boolean was engineered returns `None`, and a
thirteen-bit `Quality` does not read as a two-bit `Dbpos`.

Three events matter to a protection scheme:

- **`NewState`** — the data changed. The values are decoded and owned.
- **`Expired`** — nothing arrived within `timeAllowedtoLive`. Whatever you were holding must
  now be treated as invalid.
- **`NeedsCommissioning`** — the publisher set `ndsCom`; its data is not usable yet.

Everything else is filtered before it reaches you. Frames for other streams are counted, not
reported.

### What the subscriber rejects

| Rejection | Why |
|---|---|
| `Invalid::Replay` | `stNum` went backwards while the state was still live, or `sqNum` did not advance |
| `Invalid::SimulationMismatch` | The header S bit and the PDU flag disagree |
| `Invalid::MemberCountMismatch` | `numDatSetEntries` disagrees with the members present |
| `Invalid::Malformed` | A frame for *this* stream that did not decode |
| `ConfRevMismatch` | The publisher's configuration revision is not the one you expect |

`ConfRevMismatch` and `IgnoredSimulation` are **edge-triggered**: reported once per
transition, not once per frame.

### The replay rule

Every subscriber runs the IEC 62351-6 §6.2.1 state machine, with no way to switch it off. The
rule itself is in [How GOOSE and Sampled Values work](@/docs/protocols.md#replay-protection).

Two consequences show up in the API:

- **`Expired` always precedes a backwards state.** An application reading only the event
  stream never sees `stNum` jump backwards without first being told that the values it was
  holding had gone invalid.
- **A restarted publisher gets through immediately**, even if it comes back on the `stNum` it
  was already using with `sqNum` at 0.

The publisher's own timestamp is not part of the decision. This is a reading of the clause,
not a conformance claim; see [Verification](@/docs/verification.md#what-is-not-proven).

Two limits of the rule:

- **After an expiry, an old frame is admissible.** Nothing is live, so the next frame is a new
  state whatever its counters say — which also lets an attacker who silences a publisher for
  one `timeAllowedtoLive` replay a captured frame. Only the IEC 62351-6 authentication
  extension closes that.
- **A duplicate and a replay are the same octets**, so the subscriber calls both `Replay`. On a
  PRP network, discard duplicates below this, in the link redundancy entity (IEC 62439-3).

### Simulation

```rust
use iec61850_rs::proto::goose::SimulationMode;

// LPHD.Sim = true: prefer a test set's frames over the real publisher's.
let cfg = SubscriberConfig::new(key).with_simulation(SimulationMode::Preferred);
```

`SimulationMode::Off` (the default) drops simulated frames and reports `IgnoredSimulation`
once. `Preferred` implements the Edition 2 rule for a device under test: follow the real
stream until the first simulated frame, emit `SimulationTakeover`, and ignore the real
publisher from then on. `sub.reset_simulation()` ends the test and forgets the test set's
counters with it.

## Counters, and the numbers an IDS wants

`sub.stats()` returns every count the subscriber keeps: accepted frames, state changes,
retransmissions, replays, malformed frames, simulation mismatches, member-count mismatches,
`confRev` drops, expiries, commissioning transitions, frames for other streams, and events
dropped because the application stopped draining. Counters survive even when the bounded event
queue drops events.

Two of them are worth calling out:

- **`state_gaps` / `states_missed`** — a new state whose `stNum` is more than one above the
  last, *while the previous state was still live*: changes the publisher sent and this
  subscriber never saw. On a healthy bus it is zero.
- **`malformed`** means *this* stream. A frame that fails to parse is attributed through the
  destination and APPID that survive the failure, so another publisher's broken frame counts
  as other traffic.

`ConfRevMismatch`, `IgnoredSimulation` and `NeedsCommissioning` are events on the transition
and counters on every frame, so a repeating condition cannot fill the bounded queue.

These are the semantic checks a rule-based substation intrusion-detection system performs, and
`sub.deltas()` returns the features learned detectors use:

```rust
if let Some(d) = sub.deltas() {
    ids.feed([d.st_diff, d.sq_diff, d.arrival_delta as i64, d.t_delta, d.since_state_change as i64]);
}
```

| Field | The literature's name |
|---|---|
| `st_diff` | `stDiff` — this frame's `stNum` minus the previous one's |
| `sq_diff` | `sqDiff` |
| `arrival_delta` | `timestampDiff` — inter-arrival, on **your** clock |
| `t_delta` | `tDiff` — between the publisher's timestamps, which are attacker-controlled |
| `since_state_change` | `timeFromLastChange` |

These five are the reduced feature set found informative on the ERENO IEC 61850 dataset
([arXiv 2604.14233](https://arxiv.org/abs/2604.14233)). The subscriber has already computed
them to reach its verdict, so reading them costs nothing. `arrival_delta` is your clock and
`t_delta` the publisher's; a divergence between them is worth watching.

### Publishing the status as an `LGOS`

IEC 61850-7-4 gives every GOOSE subscription an `LGOS` logical node, so a SCADA client can read
what this subscriber thinks of its stream, and a report control block can carry it:

```rust
use iec61850_rs::server::SubscriptionStatus;

updates.txn().supervise("IED2LD0/LGOS1", &SubscriptionStatus::from_goose(&subscriber)).commit();
```

`St` is whether the stream is live, `NdsCom` the publisher's own flag, `SimSt` the simulation
takeover, and `LastStNum`/`ConfRevNum`/`RxConfRevNum` what the subscriber already holds. Details are in
[Server](@/docs/server.md#supervising-what-this-ied-subscribes-to);
`cargo run --example supervised_subscriber` runs it with no network.

## From SCL

Rather than filling in MAC addresses by hand, take them from the engineering file:

```rust
let model = IedModel::from_scl_file("relay.icd", Some("IED1"))?;
let cfg = model.goose_publisher_config("IED1LD0/LLN0.gcbTrip", own_mac)?;
let key = model.goose_subscription_key("IED1LD0/LLN0.gcbTrip")?;
```

See [SCL and the IED model](@/docs/scl.md).

And for the other side of the wire, from a whole SCD:

```rust
let subs = iec61850_rs::scl::subscriptions(&scd, "IED2", 50)?;
for s in &subs.goose {
    subscribers.push(Subscriber::new(s.goose_config()));   // address, APPID and confRev resolved
}
```

## What the decoder tolerates

Three things in `goose.asn` that a strict reader gets wrong on real traffic:

- `simulation [7]` and `ndsCom [9]` are `DEFAULT FALSE`, so BER lets a publisher leave them
  out. The default is applied; the encoder always writes them.
- `security [12]` is `ANY`, which cannot carry an implicit tag — the IEC 62351-6 extension
  therefore arrives *constructed*. Both spellings are accepted.
- Fixed-length encoded GOOSE writes every integer at the width of its `bType`, so an
  `INT32U` above `0x7FFF_FFFF` arrives as four octets with the top bit set. Unsigned values
  are read as big-endian unsigned regardless of that bit, as Wireshark does.

The encoder is strict; the decoder accepts what deployed publishers send.

## On a live interface

With the `net` feature, `Link::open(iface, &LinkOptions::goose())` sends what `poll_transmit`
returns and receives what `on_frame` takes; the kernel admits only GOOSE to the GOOSE
multicast range (or to the groups joined with `.join(mac)`), VLAN-tagged or not.

A server publishes its own GoCBs: once a client writes `GoEna` — or the application does,
through a transaction — the block's data set goes out from the address the SCL file gives it,
a member change is a new state, and the retransmission curve runs on its own.
`Server::publish_on(link)` sends on an interface, `Server::publish_to(sink)` anywhere else
(a capture, a test). Writing `true` again restarts nothing; a block the file gives no address
is refused with `object-value-invalid`.

## Not included

*Emitting* fixed-length encoded GOOSE (`GSEControl.fixedOffs`, Edition 2.1 — decoding it
works), the IEC 62351-6 layer-2 authentication extension, routable GOOSE over UDP
(IEC TR 61850-90-5), and Edition 1 GSSE.
