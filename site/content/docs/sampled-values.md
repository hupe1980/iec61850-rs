+++
title = "Sampled Values"
description = "Build an IEC 61850 merging unit in Rust or consume one: the 9-2LE and IEC 61869-9 profiles, decoding any engineered data set, template patching, detecting lost samples."
weight = 40

[extra]
nav_title = "Sampled Values"
+++

Sampled Values carry the output of current and voltage transformers to the IEDs that protect
a bay. A merging unit publishes them continuously, 4000 to 14 400 samples a second.

## Profiles

An `SvProfile` is the sample rate, how many ASDUs share a frame, and the size of one sample
block. The constants are the profiles that exist in the field:

| Constant | Samples/s | ASDUs/frame | Frames/s | Source |
|---|---|---|---|---|
| `LE_80_50HZ` | 4000 | 1 | 4000 | 9-2LE `MSVCB01`, 80 per cycle at 50 Hz |
| `LE_80_60HZ` | 4800 | 1 | 4800 | 9-2LE `MSVCB01` at 60 Hz |
| `LE_256_50HZ` | 12 800 | 8 | 1600 | 9-2LE `MSVCB02`, 256 per cycle |
| `LE_256_60HZ` | 15 360 | 8 | 1920 | 9-2LE `MSVCB02` at 60 Hz |
| `F4800S2I4U4` | 4800 | 2 | **2400** | IEC 61869-9, preferred protection |
| `F14400S6I4U4` | 14 400 | 6 | **2400** | IEC 61869-9, preferred metering |

The 61869-9 names are the standard's own: `F`\<rate\>`S`\<ASDUs\>`I`\<currents\>`U`\<voltages\>.
Both preferred profiles put exactly 2400 frames per second on the wire; that is what the ASDU
count is chosen for.

## Publishing

```rust
use iec61850_rs::proto::sv::{Publisher, PublisherConfig, SmpSynch, SvProfile};

let mut mu = Publisher::new(
    PublisherConfig::new(header, "MU01", SvProfile::F4800S2I4U4)   // header: MAC, VLAN, APPID
        .with_conf_rev(1),
)?;
mu.set_smp_synch(SmpSynch::Global)?;         // stream state, not a per-frame argument

loop {
    let blocks = adc.next_blocks(mu.asdus_per_frame());   // one per ASDU
    mu.publish(now, &blocks)?;
    if let Some(frame) = mu.poll_transmit() {
        socket.send(frame)?;
    }
    sleep_until(mu.next_timeout());
}
```

`publish` takes one sample block per ASDU, each `mu.sample_len()` octets. `smpCnt` advances
by one per ASDU and wraps at the profile's samples per second — the publisher owns the
counter, so consecutive frames are consecutive by construction.

If your merging unit derives `smpCnt` from an absolute time source rather than counting,
`set_smp_cnt` overrides it before a publish.

### The clock fields are set, not passed

`smpSynch`, `refrTm` and `gmIdentity` come from the clock, not the samples, so they are
setters — `set_smp_synch`, `set_refr_tm`, `set_gm_identity` — that patch every ASDU of the
template in place. Whether the two optional fields exist is fixed when the publisher is built,
because it changes the frame length:

```rust
let mut mu = Publisher::new(
    PublisherConfig::new(header, "MU01", SvProfile::F4800S2I4U4)
        .with_time_fields(/* refrTm */ true, /* gmIdentity */ true),
)?;

// Whenever ptp4l says the clock state moved:
mu.set_smp_synch(if traceable { SmpSynch::Global } else { SmpSynch::None })?;
mu.set_gm_identity(grandmaster_identity);
```

`set_smp_synch` is the one setter that returns a `Result`: values above 127 need an extra
octet, so crossing that boundary re-encodes the template. It happens at a clock transition,
never on the publishing path.

`set_refr_tm` takes the timestamp of the **first sample of the frame** and stamps each later
ASDU one sample interval on, computed per ASDU in the wire's unit of 2⁻²⁴ s so it does not
drift across a six-ASDU frame.

9-2LE sends neither field; IEC 61869-9 streams and anything that wants a subscriber to alarm
on a grandmaster change do.

### How it stays fast

A whole frame — link layer, `savPdu`, every ASDU — is encoded **once** into a template.
Publishing patches only each ASDU's `smpCnt` and sample block, so the steady state does no
encoding and no allocation.

The patched fields are written at fixed widths, sized for the stream's whole range — a BER
INTEGER is signed, so `smpSynch = 200` or `smpCnt = 65 535` gets the leading zero octet that
keeps it positive. The patch offsets are taken from decoding the template itself, so encoder
and patcher cannot disagree about the layout. A fuzz target exercises the patching path, and
the Wireshark oracle checks that no field's declared range dissects as negative.

## What the octets of an ASDU mean

An ASDU's `sample` is the data set's members written back to back at the width of each one's
`bType`, with nothing on the wire to say what they are. A `SampleLayout` supplies the shape,
normally read from the engineering file, so any engineered data set decodes — not only
9-2LE's.

```rust
use iec61850_rs::proto::sv::{ChannelType, SampleLayout};

// Usually you do not write this: `IedModel::sv_sample_layout` builds it from a data set,
// and `scl::subscriptions` hands it to you already attached to the stream.
let layout = SampleLayout::new([
    ("LD0/TCTR1.AmpSv.instMag.i".into(), ChannelType::Int(4)),
    ("LD0/TCTR1.AmpSv.q".into(), ChannelType::Quality),
]);

for (channel, value) in layout.decode(asdu.sample) {
    println!("{} = {value:?}", channel.name);
}
```

A layout is a name, a type and an offset per channel; `SampleLayout::write` is the mirror, for
a merging unit filling a block. Decoding reads straight out of the frame and allocates
nothing. The types are the ones IEC 61850-9-2 writes inside an ASDU — `Quality` is the
four-octet word, not the thirteen-bit MMS string.

### The 9-2LE sample layout

The 9-2LE guideline fixes one data set, `PhsMeas1`: four currents and four voltages, each a
32-bit signed raw value followed by a 32-bit quality word. Sixty-four octets per ASDU.

```rust
use iec61850_rs::proto::sv::le::PhsMeas1;
use iec61850_rs::Quality;

let sample = PhsMeas1 {
    currents: [ia, ib, ic, in_],
    current_quality: [Quality::GOOD; 4],
    voltages: [ua, ub, uc, un],
    voltage_quality: [Quality::GOOD; 4],
};
let block = sample.encode();          // [u8; 64]

// And back, from a received ASDU:
let decoded = PhsMeas1::decode(asdu.sample).expect("64 octets");
let amps = decoded.currents_a();      // scaled by 0.001 A per LSB
let volts = decoded.voltages_v();     // scaled by 0.01 V per LSB
```

The values on the wire are raw integers; 9-2LE fixes the scale at 0.001 A and 0.01 V per
least significant bit, which is what `currents_a` and `voltages_v` apply.

Quality here is 14 bits, not the 13 of IEC 61850-7-3: the guideline adds a `derived` bit for
values a merging unit computed rather than measured.

## Subscribing

One subscriber handles many streams. Samples go to a closure on the calling thread — no
queue, no allocation — while only stream-level changes are queued as events.

```rust
use iec61850_rs::proto::sv::{StreamConfig, StreamKey, Subscriber, SubscriberEvent};

let mut sub = Subscriber::new(vec![
    StreamConfig::new(StreamKey { dst, appid: 0x4001, sv_id: "MU01".into() })
        .with_samples_per_second(4800)
        .with_conf_rev(1)
        .with_layout(layout),               // what the ASDU's octets mean, from the SCD
]);

sub.on_frame(now, &bytes, |sample| {
    for (channel, value) in sample.channels() {
        protection.feed(&channel.name, value);
    }
});

sub.on_timeout(now);
while let Some(event) = sub.poll_event() {
    match event {
        SubscriberEvent::Gap { expected, received, lost, .. } => resync(lost),
        SubscriberEvent::SyncChanged { to, .. } => log::warn!("smpSynch now {to:?}"),
        SubscriberEvent::GrandmasterChanged { .. } => log::warn!("PTP grandmaster changed"),
        SubscriberEvent::Stale { .. } => mark_stream_dead(),
        other => log::info!("{other:?}"),
    }
}
```

`samples_per_second` is the value `smpCnt` wraps at, and gap detection is modulo it; set wrong,
every wrap is a spurious gap. `IedModel::sv_stream_config` reads it from the
`SampledValueControl` (see [SCL](@/docs/scl.md)), and `ied sv monitor` infers it from the
capture.

### Simulated streams

Edition 2's [`LPHD.Sim` rule](@/docs/protocols.md#the-simulation-bit) applies here as it does
to GOOSE, and so does the API: `StreamConfig::with_simulation(SimulationMode::Preferred)`
follows the real stream until a test set speaks and ignores it afterwards, with
`SimulationTakeover` marking the switch and `reset_simulation` ending the test. The default,
`Off`, drops simulated frames and reports `IgnoredSimulation` once rather than once per
frame.

One difference from GOOSE: a sampled-value APDU has no `simulation` field inside it, so the
header's S bit is the only signal and there is nothing to cross-check it against.

### What the events tell you

- **`Gap`** — samples were lost; `lost` says how many.
- **`SyncChanged`** — `smpSynch` changed, e.g. global synchronisation was lost.
- **`GrandmasterChanged`** — the PTP grandmaster identity changed; worth alarming on.
- **`Stale`** / **`Resumed`** — no frame for `stale_after_ms` (default 10 ms, set with
  `with_stale_after_ms`). Staleness is detected when the next frame arrives as well as on a
  timer tick, so it is reported before the new samples are.
- **`SampleLengthMismatch`** — the ASDU is not the length the configured layout describes; the
  ASDU is dropped rather than decoded.

`ConfRevMismatch`, `IgnoredSimulation` and `SampleLengthMismatch` are edge-triggered:
reported on the transition, counted on every ASDU.

### Counters

`sub.state(i)` gives one stream's counters: frames, ASDUs, gaps, samples lost, `confRev`
drops, layout mismatches, and whether it is currently stale. A frame counts as **one** frame
however many ASDUs it carries.

## Verified against a vendor capture

A `Publisher` configured as a captured merging unit was, fed that capture's sample blocks,
reproduces its frames **byte for byte**. All 10,161 frames of the reference 9-2LE capture
survive a decode-and-re-encode unchanged, and each decodes identically through the
SCL-described layout and through `PhsMeas1`.

## Configuring from SCL

You rarely have to write an `SvProfile` by hand. `IedModel::sv_publisher_config` builds one
from a `SampledValueControl` and its `Communication/SMV` address, and works out the ASDU
sample length by **summing the widths of the data set's members**, so any fixed-width data set
works without a special case:

```rust
let model = IedModel::from_scl_file("mu.icd", Some("MU1"))?;
let cfg = model.sv_publisher_config("MU1LD0/LLN0.msvcb01", own_mac, 50)?;  // 50 Hz system
let mut mu = Publisher::new(cfg)?;

// The same file, from the subscribing side — rate, confRev and the channel layout:
let stream = model.sv_stream_config("MU1LD0/LLN0.msvcb01", 50)?;
```

The frequency is a parameter because SCL does not record it, and `smpRate` counts samples
per *cycle* unless `smpMod` says `SmpPerSec`. A control block that does not describe a whole
number of samples per second is refused.

`ied sv monitor <capture> --scd <file>` is the same thing from the command line: the file
configures the streams, and every ASDU comes out as named channels.

## On a live interface

`Link::open(iface, &LinkOptions::sv())` with the `net` feature: frames out, frames in, with the
kernel filtering on the SV EtherType and multicast range. On Linux a 4800 frames/s stream
crosses a veth pair without a gap; `LinkOptions::launch_time(true)` with `Link::send_at`
hands each frame to the kernel with the time it is due (`SO_TXTIME`, for an `etf` or `taprio`
qdisc).

A server's MSVCB publishes once `SvEna` is written: every sample period it sends the model's
current values of the data set, encoded through the layout the file implies, and a change
takes effect from the next sample.

## Not included

Unicast sampled values, the IEC 62351-6 authentication extension, and the IEC 62351-6 §6.2.2
replay state machine (the subscriber tracks continuity, sync and staleness, but does not claim
conformance to it).
