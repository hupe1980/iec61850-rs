+++
title = "How GOOSE and Sampled Values work"
description = "GOOSE, Sampled Values and the IEC 61850 process bus explained: stNum and sqNum, smpCnt and smpSynch, APPID and multicast MAC ranges, and replay protection."
weight = 20

[extra]
nav_title = "Protocols"
+++

If you already know what a merging unit publishes and why `stNum` matters, skip to
[GOOSE](@/docs/goose.md). This page is the vocabulary the rest of the guide assumes.

## Two buses, three protocols

An IEC 61850 substation carries three kinds of traffic:

| | Carries | Over | Timing |
|---|---|---|---|
| **MMS** (IEC 61850-8-1) | Configuration, measurements, control, reports, files | TCP/IP, port 102 | Milliseconds to seconds |
| **GOOSE** (IEC 61850-8-1) | Protection signals: trips, interlocks, blocking | Raw Ethernet, `0x88B8` | **3 ms** end to end |
| **Sampled Values** (IEC 61850-9-2) | Instrument-transformer currents and voltages | Raw Ethernet, `0x88BA` | 4000–14 400 samples/s |

The **station bus** carries MMS: a SCADA client browsing an IED's data model over six OSI
layers (see [MMS](@/docs/mms.md)). The **process bus** carries GOOSE and Sampled Values:
multicast frames straight over Ethernet, with no IP, no TCP and no acknowledgement. A
publisher therefore repeats itself, and a subscriber decides for itself when the publisher has
gone quiet.

## GOOSE: repeat until something changes

A GOOSE publisher sends the same data set over and over. Two counters describe where it is:

- **`stNum`** — the state number. It increments **only when the data changes**.
- **`sqNum`** — the sequence number within that state. It resets to 0 on a change and
  increments on every repeat.

After a change the publisher bursts: send immediately, then again after a few milliseconds,
then at doubling intervals until it settles back to a slow heartbeat. A trip therefore
arrives several times within the 3 ms budget even if the first copy is lost.

Every frame also carries **`timeAllowedtoLive`**: how long the subscriber should wait before
concluding the publisher is dead. Conventionally it is twice the interval to the next frame,
so losing one frame is survivable and losing two is not. When it elapses, the subscriber must
treat the values it holds as invalid.

## Sampled Values: a metronome

A **merging unit** digitises the current and voltage transformers of a bay and publishes the
samples continuously. There is no "change"; there is only the next sample.

**`smpCnt`** counts samples within a second and wraps at the sample rate — 3999 for 80
samples per cycle at 50 Hz, 4799 at 60 Hz. A step of anything but one means samples were lost,
and the size of the step says how many.

**`smpSynch`** says what the samples are timed against: `0` unsynchronised, `1` a local
clock, `2` a global clock that is time-traceable, and `5`–`254` a specific identified local
clock. Two merging units feeding one differential protection must agree.

Frames may carry several **ASDUs** — several consecutive samples — to keep the frame rate
down. IEC 61869-9 picks the count precisely so the wire always sees 2400 frames a second:
4800 samples/s with 2 ASDUs, or 14 400 with 6.

## Addressing: MAC and APPID, not IP

A process-bus frame is addressed by destination multicast MAC and identified by an **APPID**.
Both come in reserved ranges, and the two most significant bits of the APPID encode which
protocol it is:

| | Multicast MAC | APPID |
|---|---|---|
| GOOSE | `01-0C-CD-01-00-00` … `01-0C-CD-01-01-FF` | `0x0000`–`0x3FFF` |
| Sampled Values | `01-0C-CD-04-00-00` … `01-0C-CD-04-01-FF` | `0x4000`–`0x7FFF` |

Frames are normally 802.1Q-tagged with priority 4, so a switch can give protection traffic
its own queue. `ied scl validate` checks these ranges in an SCL file, which the schema does
not.

## The simulation bit

Testing a protection scheme means injecting frames without disturbing the real bay. Edition 2
gives every process-bus frame a **simulation flag** — bit 15 of the `Reserved1` header field,
mirrored by a field inside the PDU.

The rule is a preference, not a filter. A device whose `LPHD.Sim` is set processes simulated
streams **instead of** the real ones: until a test set speaks it follows the real publisher,
and from the first simulated frame onwards it ignores it. A device with `LPHD.Sim` clear
ignores simulated frames entirely. The rule belongs to the *subscribing* device, so it applies
to sampled values as it does to GOOSE. Only GOOSE mirrors the bit inside the PDU, and a GOOSE
frame whose header bit disagrees with that field is rejected either way.

## Replay protection

IEC 62351-6 requires a conforming subscriber to run a replay state machine **whether or not**
the stream carries cryptographic security — the standard says the algorithms apply
"regardless if the published GOOSE or Sampled Value APDU has security".

The rule is about **liveness**, not about counters:

- While the current state is inside its `timeAllowedtoLive`, a lower `stNum` is a **replay**,
  and so is a `sqNum` that does not advance within the same state.
- Once that `timeAllowedtoLive` has elapsed, nothing is live and the next frame is a new
  state whatever its counters say — a device that reboots begins again, and it may well come
  back on a counter it was already using.

The publisher's timestamp is not consulted: time to live is measured against the subscriber's
own arrival times.

## Sans-IO {#sans-io}

The protocol cores in this library own no socket, spawn no thread and never read a clock.
They take an input with the caller's notion of *now*, produce outputs, and say when they want
to be called again:

```rust
subscriber.on_frame(now, &bytes);
subscriber.on_timeout(now);
while let Some(event) = subscriber.poll_event() { /* … */ }
let wake_at = subscriber.next_timeout();
```

The same code runs under a tokio task, on a bare-metal timer, or inside a deterministic
simulation with no I/O to mock, and it builds `no_std`. There is no trait to implement: every
core exposes the same four inherent methods.

## What the standards are called

Citations in this guide use short forms:

| Short | Document |
|---|---|
| 8-1 | IEC 61850-8-1 Ed 2.1 — mappings to MMS and to Ethernet, including GOOSE |
| 9-2 | IEC 61850-9-2 Ed 2.1 — Sampled Values over Ethernet |
| 9-2LE | The UCA International Users Group implementation guideline, R2-1 |
| 61869-9 | IEC 61869-9 — the digital interface for instrument transformers |
| 6 | IEC 61850-6 — SCL, the configuration language |
| 62351-6 | IEC 62351-6:2020 — security for IEC 61850 profiles |

The standards themselves are copyrighted and are not redistributed with this project.
