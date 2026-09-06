+++
title = "Sampled Values"
description = "Build an IEC 61850 merging unit in Rust or consume one: the 9-2LE and IEC 61869-9 profiles, decoding any engineered data set, template patching, detecting lost samples."
weight = 40

[extra]
nav_title = "Sampled Values"
+++

Sampled Values carry the output of current and voltage transformers to the IEDs that protect
a bay. A merging unit publishes them continuously — 4000 to 14 400 samples a second — and
never stops, because there is no such thing as "no change" for a waveform.

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
Both preferred profiles put exactly 2400 frames per second on the wire — that is what the
ASDU count is chosen for, so a switch sees the same load whichever rate a bay uses.

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

`smpSynch`, `refrTm` and `gmIdentity` come from the clock, not from the samples, and they
change on the order of seconds while frames leave 2400 times a second. So they are setters —
`set_smp_synch`, `set_refr_tm`, `set_gm_identity` — each of which patches every ASDU of the
template in place. Whether the two optional fields exist at all is decided when the publisher
is built, because their presence changes the frame length:

```rust
let mut mu = Publisher::new(
    PublisherConfig::new(header, "MU01", SvProfile::F4800S2I4U4)
        .with_time_fields(/* refrTm */ true, /* gmIdentity */ true),
)?;

// Whenever ptp4l says the clock state moved:
mu.set_smp_synch(if traceable { SmpSynch::Global } else { SmpSynch::None })?;
mu.set_gm_identity(grandmaster_identity);
```

`set_smp_synch` is the one setter that returns a `Result`, because it is the one whose field
can change width. `smpSynch` is `0..254` and the values 5–254 name the local-area clock a
merging unit is locked to; 200 needs two octets where 2 needs one, so crossing that boundary
re-encodes the template instead of writing a value that would come out negative. It happens at
a clock transition, never on the publishing path.

`set_refr_tm` takes the timestamp of the **first sample of the frame** and stamps each ASDU
after it one sample interval later, because the ASDUs of one frame are consecutive samples —
that is what a merging unit sending 2 or 6 of them per frame actually puts on the wire, and
you pass one timestamp rather than six. The arithmetic is done in the wire's own unit of
2⁻²⁴ s, so the first ASDU carries exactly what you handed it, and the offset of ASDU *i* is
computed from *i* rather than accumulated: one sample interval is not a whole number of
2⁻²⁴ s (at 4800 Hz it is 3495.25), and adding a step at a time would drift a quarter of a
unit per ASDU across a six-ASDU frame.

9-2LE sends neither field; IEC 61869-9 streams and anything that wants a subscriber to alarm
on a grandmaster change do.

### How it stays fast

A whole frame — link layer, `savPdu`, every ASDU — is encoded **once** into a template.
Publishing then patches only what changes: each ASDU's `smpCnt` and its sample block. At 2400
frames a second the steady state does no encoding and no allocation.

That is only sound because the encoder writes `smpCnt`, `confRev`, `smpSynch`, `refrTm` and
`gmIdentity` at fixed widths, so no length can shift underneath a patch. And the patch offsets
are not computed by hand: the publisher **decodes the template it just encoded** and takes the
offsets *and widths* the decoder reports, so the two can never disagree about the layout.

The width is chosen for the whole stream's range rather than for the value in front of it,
which matters more than it sounds. A BER INTEGER is **signed**: `smpSynch = 200` in the single
octet a vendor capture shows is the number −56, and a 96 kHz stream's `smpCnt` of 65 535 in two
octets is −1. Wireshark dissects both exactly that way. So each field is written at its
customary width *or one octet more* — the leading zero X.690 asks for — and the publisher sizes
its template from the largest `smpCnt` the profile can reach. Every ordinary value is
byte-identical to what a real merging unit emits; no value is ever negative.

This is checked two ways. A `sv_publisher` fuzz target throws arbitrary sample bytes and
counters at the patching path on both template layouts — with and without the optional clock
fields — decodes the result, and compares field by field; a patch that ever wrote outside its
field shows up immediately. And the Wireshark oracle walks the *declared range* of each field
rather than the values that happen to be typical, asserting that no `smpSynch` and no `smpCnt`
ever dissects as a negative number.

## What the octets of an ASDU mean

An ASDU's `sample` is the data set's members written back to back at the width of each one's
`bType`. Nothing on the wire separates them, and nothing on the wire says what they are —
which is exactly why an ASDU is a constant size, and exactly why a subscriber that has not
been told the shape cannot decode a stream at all.

Most implementations solve that by knowing one shape: 9-2LE's. This one reads the shape out
of the engineering file, so a merging unit with its own data set is not a special case.

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

A layout is a name, a type and an offset per channel; `SampleLayout::write` is the mirror,
for a merging unit filling a block without hand-computing offsets on both sides. Decoding
reads straight out of the frame's octets and allocates nothing, so it belongs on the
receiving thread.

The types are the ones IEC 61850-9-2 writes *inside* an ASDU, which are the widths of the
`bType` and not those of the tagged MMS encoding — `Quality` here is the four-octet word, not
a thirteen-bit string.

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

`samples_per_second` is the value `smpCnt` wraps at, and it is what gap detection is modulo.
Setting it wrong turns every wrap into a spurious gap — the reference 9-2LE capture is a
**60 Hz** stream, so its counter wraps at 4799, not 3999. You do not have to know it by
heart: `IedModel::sv_stream_config` reads it off the `SampledValueControl` (see
[SCL](@/docs/scl.md)), and `ied sv monitor` infers it from the capture.

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

- **`Gap`** — samples were lost. `lost` is how many, which is what a protection algorithm
  needs in order to decide whether it can interpolate or must declare the input invalid.
- **`SyncChanged`** — `smpSynch` changed. Losing global synchronisation matters to any
  algorithm that compares two merging units.
- **`GrandmasterChanged`** — the PTP grandmaster identity changed. This is a real-world root
  cause of sampled-value problems and is worth alarming on.
- **`Stale`** / **`Resumed`** — no frame for `stale_after_ms`. At 4800 frames a second the
  default of 10 ms is already fifty missed frames. Staleness is noticed when the next frame
  *arrives* as well as on a timer tick, so an application driven only by the event stream
  learns that its samples went invalid before it is handed new ones.
- **`SampleLengthMismatch`** — the ASDU is not the length the configured layout describes, so
  this stream is not publishing the data set it was engineered with. The ASDU is dropped
  rather than decoded: naming channels that are not there would be worse than saying nothing.

`ConfRevMismatch`, `IgnoredSimulation` and `SampleLengthMismatch` are edge-triggered:
reported on the transition, counted on every ASDU. Per-ASDU reporting on a misconfigured
14 400 Hz stream would be 14 400 events a second into a queue that then drops the ones that
mattered.

### Counters

`sub.state(i)` gives one stream's counters: frames, ASDUs, gaps, samples lost, `confRev`
drops, layout mismatches, and whether it is currently stale. A frame counts as **one** frame however many ASDUs
it carries — with 61869-9 sending 2 or 6 per frame, conflating the two makes every rate
calculation wrong.

## Verified against hardware

A `Publisher` configured the way a captured merging unit was configured, fed that capture's
own sample blocks, reproduces its frames **byte for byte**. All 10,161 frames of the
reference 9-2LE capture also survive a decode-and-re-encode unchanged — and every one of them
decodes identically through the generic, SCL-described layout and through the hard-coded
`PhsMeas1`, which is what makes the general path trustworthy rather than merely present.

That single assertion covers the profile, the template patching, the ASDU encoding and the
link layer at once — against real hardware output rather than against our own expectations.

## Configuring from SCL

You rarely have to write an `SvProfile` by hand. `IedModel::sv_publisher_config` builds one
from a `SampledValueControl` and its `Communication/SMV` address, and works out the ASDU
sample length by **summing the widths of the data set's members** — so 9-2LE's `PhsMeas1`
comes out at 64 octets because the file says so, not because it is special-cased, and a
merging unit with its own fixed-width data set needs no special case either:

```rust
let model = IedModel::from_scl_file("mu.icd", Some("MU1"))?;
let cfg = model.sv_publisher_config("MU1LD0/LLN0.msvcb01", own_mac, 50)?;  // 50 Hz system
let mut mu = Publisher::new(cfg)?;

// The same file, from the subscribing side — rate, confRev and the channel layout:
let stream = model.sv_stream_config("MU1LD0/LLN0.msvcb01", 50)?;
```

The frequency is a parameter because SCL does not record it, and `smpRate` counts samples
per *cycle* unless `smpMod` says `SmpPerSec`. A control block whose `smpMod`/`smpRate` do not
describe a whole number of samples per second — a `SecPerSmp` stream slower than one sample a
second — is refused rather than turned into a modulus of zero.

`ied sv monitor <capture> --scd <file>` is the same thing from the command line: the file
configures the streams, and every ASDU comes out as named channels.

## Not implemented yet

Unicast sampled values, the IEC 62351-6 authentication extension, and the §6.2.2 replay
state machine (the subscriber tracks continuity, sync and staleness, which is its observable
part, but does not claim conformance to it).
