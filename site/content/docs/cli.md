+++
title = "Command line"
description = "The ied command line: generate a virtual merging unit, monitor sampled values, decode GOOSE and MMS, browse, read, report and control against a live MMS server, summarise a capture, and validate SCL files."
weight = 60
+++

```bash
cargo install iec61850-rs --features cli
```

One binary, `ied`, with subcommands — the shape `ip`, `tc` and `cargo` already taught your
hands.

Every subcommand works on **capture files**. That is deliberate: it needs no network
interface, no privileges and no particular operating system, which is why all of it is
covered by tests on every push. Live capture arrives with the raw-socket adapters and will
sit behind the same subcommands.

## Generate a stream

`ied mu` is a virtual merging unit. It writes a synthetic three-phase sampled-value stream —
useful for exercising a subscriber, feeding a dissector, or producing a fixture.

```bash
ied mu stream.pcap --profile f4800s2 --frames 2000
# wrote 2000 frames to stream.pcap: 4800 samples/s, 2 ASDU/frame, 2400 frames/s
```

| Option | Default | Meaning |
|---|---|---|
| `--profile` | `le80-50` | `le80-50`, `le80-60`, `le256-50`, `le256-60`, `f4800s2`, `f14400s6` |
| `--frames` | 1000 | Frames to generate |
| `--sv-id` | `MU01` | The `svID` to publish |
| `--appid` | `4000` | APPID, in hex |
| `--freq` | from the profile | Nominal frequency of the waveform, in Hz |
| `--amplitude` | 100000 | Peak of the synthetic sinusoid, in raw units |
| `--gm` | — | Publish `gmIdentity`: eight octets as 16 hex digits |
| `--refr-tm` | off | Publish `refrTm` on every ASDU |

The waveform is three phases 120° apart at nominal frequency, with the currents a tenth of
the voltages. It is not a power-system simulation; it is a signal that exercises the whole
encode path and looks like a merging unit to a dissector.

The 9-2LE profiles count samples per *cycle*, so `le80-60` implies a 60 Hz waveform and
`le80-50` a 50 Hz one; the IEC 61869-9 profiles fix the rate in absolute terms and default to
50 Hz. `--freq` overrides either.

## Monitor sampled values

```bash
$ ied sv monitor stream.pcap
svID=MU01 appid=0x4000 dst=01-0C-CD-04-00-00 confRev=1 smpCnt wraps at 4800 (smpRate)
  frames=2000 asdus=4000 (2/frame) last smpCnt=Some(3999) smpSynch=Some(Global) gaps=0 samples lost=0
```

This runs **the library's own subscriber state machine** over the capture, so what it reports
is what a subscribing IED would see — not a second implementation of the same checks that
could drift from the first.

Per stream: how many frames and ASDUs, how many ASDUs each frame carried, where the sample
counter got to, the synchronisation state, and how many samples went missing. `gaps` counts
discontinuities; `samples lost` counts the samples inside them, which is the number a
protection algorithm would need in order to decide whether it can interpolate. Sync and
grandmaster changes are listed underneath as timestamped events.

Gap detection is modulo the value `smpCnt` wraps at, and the line says where that came from:
`smpRate` when the stream advertises its rate, `observed` when it does not (9-2LE sends no
`smpRate`, so the wrap is taken from the highest counter the capture reached), or `given` when
you pass one.

| Option | Default | Meaning |
|---|---|---|
| `--freq` | 50 | Nominal frequency, for reading `smpRate` as samples per cycle |
| `--rate` | inferred | Samples per second, overriding what the stream advertises |
| `--scd` | — | Configure the streams from an engineering file instead of from the capture |
| `--ied` | all | With `--scd`, only the streams this IED publishes |

### Name the channels, from the engineering file

An ASDU's sample block is the data set's members written back to back with nothing on the
wire to separate them, so without the file it is a run of octets. With it, it is channels:

```bash
$ ied sv monitor stream.pcap --scd bay.scd
MU MULD0/LLN0.msvcb01
  svID=MU01 appid=0x4000 dst=01-0C-CD-04-00-00 smpCnt wraps at 4000 frames=200 asdus=200 gaps=0 samples lost=0
  16 channels, 64 octets per ASDU
  last sample (smpCnt=199):
    LD0/TCTR1.AmpSv.instMag.i                -1837
    LD0/TCTR1.AmpSv.q                        good
    LD0/TVTR1.VolSv.instMag.i                -18376
    LD0/TVTR1.VolSv.q                        good
    …
```

The rate, the `confRev` and the layout all come from the `SampledValueControl` and its data
set, so this works for any fixed-width data set and not only for 9-2LE's. A stream whose
ASDUs are not the length the file describes is reported rather than decoded — it is
publishing something other than what it was engineered to publish, and that is a
commissioning finding.

## Decode GOOSE

```bash
$ ied goose sniff bay.pcap
1332519207018.285ms SEL_351_1CFG/LLN0$GO$NewGOOSEMessage appid=0x0003 stNum=23 sqNum=521 \
    tal=2000ms conf=1 members=1 t=2012-03-23T08:12:20.153232157Z
16 GOOSE frames
```

Each line is one frame: the control-block reference, APPID, both counters, the advertised
`timeAllowedtoLive`, the configuration revision, the data-set member count and the
publisher's timestamp. Frames carrying flags are marked — `sim` for the simulation bit,
`ndsCom` for a publisher that needs commissioning, and `COUNT-MISMATCH` when
`numDatSetEntries` disagrees with what is actually in the frame.

Behind those lines it runs **the library's own subscriber state machine**, one per stream, so
the verdict on a frame is what a subscribing IED would decide about it rather than a second
implementation of the same checks. Anything the state machine rejects is printed where it
happened:

```text
     4.001ms IED1LD0/LLN0$GO$gcbTrip appid=0x0001 stNum=1 sqNum=0 tal=8ms conf=1 members=1 t=…
           ! Invalid(Replay { st_num: 1, sq_num: 0 })
01-0C-CD-01-00-00 IED1LD0/LLN0$GO$gcbTrip appid=0x0001
  accepted=2 states=2 retransmissions=0 replays=1 expiries=0 malformed=0 member-count=0 sim-mismatch=0
  last deltas: stDiff=1 sqDiff=0 arrival=0.001ms t=0.000ms sinceChange=0.001ms
```

The closing per-stream block is the counters plus the five delta features a substation
intrusion-detection system is built on — see [GOOSE](@/docs/goose.md#counters-and-the-numbers-an-ids-wants).
A stream that lost state changes while it was live gets an extra line naming how many, because
that is lost protection signalling rather than a decoding detail.

## Decode MMS

`mms sniff` walks the whole station-bus stack over a capture: TPKT framing, COTP class 0, the
session handshake, the presentation context negotiation, the ACSE association, and then every
MMS service and report with its values.

```bash
$ ied mms sniff station.pcap
     0.552ms -> COTP CR src-ref=0xb001 tpdu-size=1024 tsel [00, 01]->[00, 02]
     0.836ms <- COTP CC dst-ref=0xb001 tpdu-size=1024
     1.463ms -> CP  contexts 1=2.2.1.0.1 3=1.0.9506.2.1
     1.463ms -> AARQ context 1.0.9506.1.1
     1.463ms -> Initiate maxPDU=Some(32000) outstanding 20/20 nesting Some(4) version 1
    11.177ms <- AARE accepted
   113.529ms -> invoke 1 identify AREVA T&D Corporation e-terracomm 2.3.1
   322.359ms -> invoke 4434 data set of 19 member(s)
   572.187ms -> report KIRKLAND/EMS_ANALOG_ICCP_IN (19 values)
23 request(s), 23 response(s), 115 report(s), 823 value(s)
```

The arrow is the direction relative to port 102. Reports repeat, so only the first twenty
lines of them are printed; the summary counts all of them. A PDU that does not decode is
counted and named rather than silently skipped — see [MMS](@/docs/mms.md) for what is
modelled and what is kept as opaque octets.

Unsolicited PDUs go through the **same classifier a live client uses**, so an IEC 61850 report
is printed with its identifier, sequence number and member count, and a command termination is
named as one. The capture above is an ICCP association, and its reports are data-set reports
rather than IEC 61850 reports — which the tool says by *not* claiming otherwise.

## Be a server

An SCL file is a working IED. No generated model, no build step, no second description of the
device to keep in step with the first:

```bash
$ ied sim bay.scd
IED1 on 127.0.0.1:102 — Edition 2.1 — logical device(s) IED1LD0
IED2 on 127.0.0.1:103 — Edition 2.1 — logical device(s) IED2LD0, IED2LD1
serving; ^C to stop
```

Every IED in the file gets its own port. `--ied` serves just one, `--bind` and `--port` choose
where, and `--files DIR` serves a directory through the MMS file services — read-only unless
`--writable`, and sandboxed to that directory either way.

The **edition** in the banner is the file's own: `2003` is Edition 1, `2007B` is Edition 2,
`2007B4` and later Edition 2.1. It decides the report control block's attribute set, so an
Edition 1 file serves a block with no `ResvTms` and no `Owner` — `--edition 1|2|2.1` overrides
it.

```bash
$ ied sim valid2003.scd
IED1 on 127.0.0.1:102 — Edition 1 — logical device(s) IED1CircuitBreaker_CB1, IED1Disconnectors
```

It is a real server: browse it, enable a report control block on it, operate its breaker,
activate a setting group. That is also how the `ied mms` subcommands are tested in CI — one
binary talking to itself over a real association, with no device and no network interface.

```bash
$ ied sim relay.icd --port 10102 &
$ ied mms browse 127.0.0.1:10102
$ ied mms control 127.0.0.1:10102 IED1LD0/CSWI1.Pos true --model direct
```

## Talk to a live server

The `mms` client subcommands open a real association — all six OSI layers, the ACSE handshake
and the MMS `Initiate` — and then ask it something.

```bash
$ ied mms identify 10.0.0.5
vendor    AREVA T&D Corporation
model     e-terracomm
revision  2.3.1
max PDU   32000 octets
outstanding 20

$ ied mms browse 10.0.0.5
IED1LD0
  LLN0$ST$Beh$stVal
  MMXU1$MX$TotW$mag$f
  PTRC1$ST$Tr$general
  data set LLN0$dsTrip
    IED1LD0/PTRC1$ST$Tr$general
  3 variables, 1 data sets

$ ied mms read 10.0.0.5 IED1LD0/MMXU1.TotW.mag.f --fc MX
IED1LD0/MMXU1.TotW.mag.f = 1234.5

$ ied mms write 10.0.0.5 IED1LD0/GGIO1.SPCSO1.stVal true --type bool
IED1LD0/GGIO1.SPCSO1.stVal <- true

$ ied mms rcb 10.0.0.5 IED1LD0/LLN0.urcb01
IED1LD0/LLN0$RP$urcb01
  kind       unbuffered (RP)
  RptID      IED1LD0/LLN0$RP$urcb01
  RptEna     false
  DatSet     IED1LD0/LLN0$dsTrip
  ConfRev    3
  OptFlds    SqNum, TimeOfEntry, DatSet, ReasonCode, ConfRev
  TrgOps     triggers: data change, quality change, GI
  BufTm      0 ms
  IntgPd     0 ms
  SqNum      0
  Resv       false

$ ied mms report 10.0.0.5 --rcb IED1LD0/LLN0.urcb01 --gi --seconds 60
enabled IED1LD0/LLN0$RP$urcb01 — data set IED1LD0/LLN0$dsTrip, triggers: data change, quality change, GI
general interrogation requested
listening for 60 s
report 1 IED1LD0/LLN0$RP$urcb01 sq=1 t=2023-11-14T22:13:20.000Z dataSet=IED1LD0/LLN0$dsTrip confRev=3 — 2 of 2 members
    [0] = true  (general interrogation)
    [1] = Quality { validity: Good, .. }  (general interrogation)

$ ied mms control 10.0.0.5 IED1LD0/CSWI1.Pos true --model sbo-enhanced --interlock
IED1LD0/CSWI1.Pos <- true (command termination + for IED1LD0/CSWI1$CO$Pos$Oper)
```

```bash
$ ied mms type 10.0.0.5 IED1LD0/CSWI1.Pos.Oper --fc CO
struct
  ctlVal       BIT STRING(2)
  origin
    struct
      orCat        INT8
      orIdent      OCTET STRING(-64)
  ctlNum       INT8U
  T            Timestamp
  Test         BOOLEAN
  Check        BIT STRING(2)

$ ied mms files 10.0.0.5
        4096  20240131T101500Z  COMTRADE/rec0001.cfg
      262144  20240131T101502Z  COMTRADE/rec0001.dat
2 file(s)

$ ied mms get 10.0.0.5 COMTRADE/rec0001.cfg rec0001.cfg
4096 octets -> rec0001.cfg

$ ied mms log 10.0.0.5 'IED1LD0/LLN0$GeneralLog' --lcb IED1LD0/LLN0.lcb01
IED1LD0/LLN0$LG$lcb01  enabled
  LogRef  IED1LD0/LLN0$GeneralLog
  DatSet  IED1LD0/LLN0$dsTrip
  TrgOps  triggers: data change, quality change, GI
  oldest  2023-11-14T22:13:20.000Z
  newest  2023-11-14T22:14:20.000Z
2023-11-14T22:13:20.000Z 0000000000000001
    IED1LD0/PTRC1$ST$Tr$general = true
2023-11-14T22:14:20.000Z 0000000000000002  power up
2 entr(y|ies)

$ ied mms sg 10.0.0.5 --activate 2
group 2 activated
IED1LD0/LLN0$SP$SGCB
  NumOfSG 4
  ActSG   2
  EditSG  0
  CnfEdit false
```

`mms type` is `GetVariableAccessAttributes` — the shape a write has to match, read from the
device rather than remembered. `mms get` writes to a file, or to standard output when no
destination is given, and `--max-size` bounds what it will hold. `mms log` prints the entries
oldest first and follows `moreFollows` to the end; `--lcb` also reads the log control block,
which is where a log's own start time comes from. `mms sg` prints the setting group control
block, and `--activate`/`--edit` are the two things you do to one; with no reference it finds
the `SGCB` in the server's first logical device.

`--rcb` enables the control block, `--gi` asks for a general interrogation, and every report
field is decoded rather than printed as a list of anonymous values. A report the server splits
across segments is joined before it is printed. Without `--rcb` the tool
only listens, which is what you want when another client already enabled the block.

A control that the substation **refuses** is an error with a name and a non-zero exit, not a
successful write:

```bash
$ ied mms control 10.0.0.5 IED1LD0/CSWI1.Pos true --model sbo-enhanced
ied: IED1LD0/CSWI1.Pos: refused — BlockedByInterlocking (AddCause 10)
```

The engineering file can supply the addressing, which is the part most often wrong when an
association is refused for no stated reason — and with a host of `-` it supplies the address
too:

```bash
$ ied mms browse - --scd bay.scd --ied IED1
```

The host may omit the port; 102 is the default. A reference is either the dotted ACSI form
with `--fc`, or the MMS `LN$FC$DO$DA` form, which carries its own. `--password` sends the
IEC 61850-8-1 ACSE password; `--local-tsel` and `--remote-tsel` set the OSI transport
selectors when a device wants something other than `0001`.

`browse` follows `moreFollows` paging, so what it prints is the whole model and not the first
page of it.

Every one of these is exercised in CI against [`ied sim`](#be-a-server) — the binary talking
to itself, with no device and no network interface.

## Summarise a capture

```bash
$ ied pcap info bay.pcap
bay.pcap: 79 frames over 8.261 s
  GOOSE 16, sampled values 0, other 63, VLAN-tagged 0
  2 process-bus frames per second
```

What is in the file, and at what rate. The frame rate is the first thing to check when a
process bus misbehaves: a merging unit that should be sending 2400 frames a second and is
sending 1200 has already told you what is wrong.

## Inspect and validate SCL

```bash
$ ied scl show substation.scd IED1
IED IED1 (ACME Relay, config 1.0)
  LD IED1LD0 (inst LD0)
    LN LLN0 [LLN0_T] 2 data objects
      DataSet dsTrip (2 members)
        IED1LD0/PTRC1$ST$Tr$general
        IED1LD0/PTRC1$ST$Tr$q
      GSEControl gcbTrip confRev=3 01-0C-CD-01-00-05 appid=0x0005 vlan=1
      ReportControl brcb01 buffered=true confRev=2 bufTime=50ms
```

`scl validate` loads every IED and reports what the file gets wrong. Not what the XML schema
already catches — what it happily accepts:

```bash
$ ied scl validate bay.scd
bay.scd: SCL 2007B4, 3 IED(s)
  warning: RetransmissionTimes at IED1LD0/LLN0.GCB: GSE without MinTime/MaxTime: the publisher falls back to 4 ms / 1000 ms
  error: MissingDataSet at IED1LD0/LLN0.GCB2: control block without a datSet publishes nothing
  error: Loader(MissingLNodeType) at IED2/CBSW/THARDE1: LNodeType `Dummy.THARDE` not found
  error: UnresolvedSubscription at IED1/Disconnectors/DCCSWI1: control block `IED2CBSW/LLN0.GCB` of `IED2` is missing or has no Communication address
  3 error(s), 1 warning(s)
```

| Finding | What it means |
|---|---|
| `AppidOutOfRange` / `MacOutOfRange` | Outside the range the protocol reserves |
| `DuplicateStream` | Two control blocks on one (MAC, APPID): on the wire that is **one** stream, and every subscriber to either receives both |
| `DuplicateAppid` | One APPID on two addresses — legal, and almost always a copy-and-paste (warning) |
| `MissingDataSet` | A control block naming a data set that does not exist, or none at all |
| `UnresolvedFcda` | A data-set member that does not resolve against the IED's own types |
| `ObjectReferenceTooLong` | Longer than the edition allows (`--edition 1` is stricter than `2.1`) |
| `RetransmissionTimes` | `MinTime` at or above `MaxTime`, or absent (warning) |
| `SampleRate` | A `nofASDU` or `smpRate` that cannot describe a publishable stream, or a sampled-value data set with no fixed-width layout |
| `VlanPriority` | Below 4: it will not get a trip through a loaded switch (warning) |
| `UnresolvedSubscription` | An `ExtRef` bound to something this file does not resolve |

Every finding carries a stable code, so a pipeline can forbid a class of them rather than
grepping prose, and a severity. It exits non-zero on any **error**; warnings alone pass
unless you add `--strict`. That drops straight into a commissioning pipeline or a pre-commit
hook.

| Option | Default | Meaning |
|---|---|---|
| `--freq` | 50 | Nominal frequency, for reading `smpRate` |
| `--edition` | `2.1` | Whose object-reference length limit applies (`1`, `2`, `2.1`) |
| `--strict` | off | Treat warnings as errors |

The same checks are a library function, `scl::validate`, so a build script can run them
without shelling out.

## Resolve what an IED subscribes to

`scl subs` answers the question a subscriber actually has: given this SCD and my name, what
am I supposed to receive and from where?

```bash
$ ied scl subs bay.scd IED2
IED2 subscribes to 1 GOOSE and 1 sampled-value stream(s)
  IED1LD0/LLN0$GO$gcbTrip from IED1 (IED1LD0/LLN0.gcbTrip)
    01-0C-CD-01-00-05 appid=0x0005 confRev=3
    <- PTRC1.Tr.general [BI1]
  MU01 from IED1 (IED1LD0/LLN0.msvcb01)
    01-0C-CD-04-00-01 appid=0x4001 confRev=1 rate=4000/s 2 channels/8 octets per ASDU
    <- TCTR1.AmpSv.instMag.i
```

Each `Inputs/ExtRef` is resolved against the publisher's own control block and
`Communication` address, and grouped by the control block that carries it — with the internal
address each input is wired to in brackets. Bindings that name a `srcCBName` are taken as
written; the ones that name only the signal — the majority in a real SCD — are resolved by
finding which of the publisher's data sets carries that attribute and which control block
publishes it. Bindings that resolve to nothing (a publisher the
file does not hold, a control block with no address) are listed as `unresolved` and the
command exits non-zero, because a dangling binding is a commissioning finding rather than a
detail.

Takes `--freq` for the same reason `mu` does: `smpRate` counts samples per cycle.

## A loop that tests itself

The three commands compose into a check you can run anywhere:

```bash
ied mu /tmp/s.pcap --profile f14400s6 --frames 500   # encode
ied sv monitor /tmp/s.pcap                           # decode
ied sv monitor /tmp/s.pcap --scd bay.scd             # …and name every channel from the SCD
tshark -r /tmp/s.pcap -Y sv                          # and have Wireshark judge it
```

This is what runs in CI on every push. If the encoder and the decoder ever disagree, or if
Wireshark stops accepting what we emit, it fails there rather than in a substation.

## Not implemented yet

Live capture from an interface, and COMTRADE replay in `ied mu`.
