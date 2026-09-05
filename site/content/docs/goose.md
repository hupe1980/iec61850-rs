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
interval grows. That distinction is the protocol, and getting it wrong is the classic GOOSE
implementation bug — a publisher that increments `stNum` on every frame tells every
subscriber the world changed 250 times a second.

If your application has a scan cycle rather than an event, hand the whole data set to
`publish_if_changed` instead. It encodes into a buffer it keeps, compares with the one
already on the wire, and returns `false` without touching `stNum` when nothing moved — so the
classic bug is not something you have to remember not to write. It allocates nothing either
way.

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

`poll_transmit` returns a slice of a buffer the publisher owns and rewrites. In the steady
state — a frame every 4 ms — nothing is allocated, and neither is anything on a state change:
the encoded data set and the APDU are cleared and rewritten into buffers the publisher
already holds, because a state change during a fault is the worst possible moment to visit
the allocator. If you do not collect a frame before the
next is built, the older one is dropped and `pubr.dropped()` counts it; a publisher that
drops frames is telling you its event loop is too slow.

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

Nothing is coerced. An integer where a boolean was engineered returns `None` — that is a
fault to report, not a number to reinterpret — and a thirteen-bit `Quality` will not read as
a two-bit `Dbpos`, so a mislabelled member cannot decode silently into the wrong thing.

Three events matter to a protection scheme:

- **`NewState`** — the data changed. The values are decoded and owned.
- **`Expired`** — nothing arrived within `timeAllowedtoLive`. Whatever you were holding must
  now be treated as invalid.
- **`NeedsCommissioning`** — the publisher set `ndsCom`; its data is not usable yet.

Everything else is filtered before it reaches you. Frames for other streams are counted, not
reported — a raw socket delivers the whole segment, and that is not an error.

### What the subscriber rejects

| Rejection | Why |
|---|---|
| `Invalid::Replay` | `stNum` went backwards while the state was still live, or `sqNum` did not advance |
| `Invalid::SimulationMismatch` | The header S bit and the PDU flag disagree |
| `Invalid::MemberCountMismatch` | `numDatSetEntries` disagrees with the members present |
| `Invalid::Malformed` | A frame for *this* stream that did not decode |
| `ConfRevMismatch` | The publisher's configuration revision is not the one you expect |

`ConfRevMismatch` and `IgnoredSimulation` are **edge-triggered**: reported once per
transition, not once per frame. A misconfigured stream at 250 frames a second would otherwise
bury the log.

### The replay rule

Every subscriber runs the IEC 62351-6 §6.2.1 state machine, with no way to switch it off,
because a conforming subscriber must run it whether or not the stream carries security. The
rule itself — and why it is about liveness rather than about counters — is in
[How GOOSE and Sampled Values work](@/docs/protocols.md#replay-protection).

Two consequences show up in the API:

- **`Expired` always precedes a backwards state.** An application reading only the event
  stream never sees `stNum` jump backwards without first being told that the values it was
  holding had gone invalid.
- **A restarted publisher gets through immediately**, even if it comes back on the `stNum` it
  was already using with `sqNum` at 0. A counter-only reading of the rule would lock it out
  for a whole retransmission curve; a regression test restarts a publisher exactly that way
  and requires the very next frame through.

The publisher's own timestamp is deliberately not part of the decision — it is
attacker-controlled and depends on a clock you do not own. That is a defensible reading of a
clause whose second half is paywalled, and
[Verification](@/docs/verification.md#what-this-does-not-prove) says so rather than claiming
conformance.

Two limits of the rule, neither of them a bug:

- **After an expiry, an old frame is admissible.** Nothing is live, so the next frame is a new
  state whatever its counters say. That is what lets a restarted publisher back in, and
  equally what lets an attacker who can silence a publisher for one `timeAllowedtoLive` replay
  a captured frame afterwards. Only the IEC 62351-6 authentication extension closes that.
- **A duplicate and a replay are the same octets arriving twice**, so the subscriber calls
  both `Replay`. On a PRP network every frame legitimately arrives twice, so duplicate discard
  belongs below this, in the link redundancy entity where IEC 62439-3 puts it.

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
dropped because the application stopped draining. Every rejection moves a counter, so an
application that cannot keep up with the event queue still sees which check failed.

Two of them are worth calling out:

- **`state_gaps` / `states_missed`** — a new state whose `stNum` is more than one above the
  last, *while the previous state was still live*: changes the publisher sent and this
  subscriber never saw. It is the one thing the delta features below cannot express, and on
  a healthy bus it is zero.
- **`malformed`** means *this* stream. A frame that fails to parse is attributed through the
  destination and APPID that survive the failure, so another publisher's broken frame is
  other traffic rather than an attack on you. A counter an IDS acts on has to mean what it
  says.

Everything that can repeat is edge-triggered — `ConfRevMismatch`, `IgnoredSimulation` and
`NeedsCommissioning` are events on the transition and counters on every frame. A publisher in
commissioning retransmits every few milliseconds, and an event per frame would fill the
bounded queue and push out the trip you were waiting for.

These are exactly the semantic checks a rule-based substation intrusion-detection system
performs. And `sub.deltas()` returns what the *learned* detectors want:

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

Those five are not arbitrary. A 2026 evaluation of detectors on the ERENO IEC 61850 dataset
([arXiv 2604.14233](https://arxiv.org/abs/2604.14233)) finds the informative reduced feature
set is exactly these deltas rather than the raw protocol fields — and that a supervised
forest reaching F1 0.9516 needs 21.8 ms per prediction, missing the 4 ms GOOSE budget
outright. A subscriber has already computed all five to reach its verdict, so reading them
here costs nothing; recovering them on a mirror port costs a second parser and a second
chance to disagree with the device that actually acted on the frame.

`arrival_delta` against `t_delta` is the pair to watch: the first is your clock, the second
is the publisher's. On the reference SEL capture they diverge by 1.5 ms per second, and the
publisher marks its own clock unsynchronised.

Counters survive even when the bounded event queue drops events, so a busy application loses
notifications but never statistics.

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

Three things in `goose.asn` that a strict reader gets wrong on real traffic, and this one
does not:

- `simulation [7]` and `ndsCom [9]` are `DEFAULT FALSE`, so BER lets a publisher leave them
  out. The default is applied. (The encoder still writes them, because every publisher we
  have a capture of does.)
- `security [12]` is `ANY`, which cannot carry an implicit tag — the IEC 62351-6 extension
  therefore arrives *constructed*. Both spellings are accepted.
- Fixed-length encoded GOOSE writes every integer at the width of its `bType`, so an
  `INT32U` above `0x7FFF_FFFF` arrives as four octets with the top bit set. Unsigned values
  are read as big-endian unsigned regardless of that bit, which is what Wireshark does.

Strictness on decode buys nothing on a multicast bus where you cannot ask the sender to
retry. It belongs in the encoder, and that is where it stays.

## Not implemented yet

*Emitting* fixed-length encoded GOOSE (`GSEControl.fixedOffs`, Edition 2.1 — decoding it
works), the IEC 62351-6 layer-2 authentication extension, routable GOOSE over UDP
(IEC TR 61850-90-5), and Edition 1 GSSE.

The first and third are blocked on evidence, not effort: the widths table (IEC 61850-8-1
Table A.2) is paywalled, and the R-GOOSE session header is described one way by the TR text
and another by Wireshark's dissector. Emitting a guess would put frames on a bus that a
conforming subscriber parses at the wrong offsets.
