+++
title = "Command line"
description = "The ied command line: generate a virtual merging unit, monitor sampled values, decode GOOSE and MMS, browse, read, report and control against a live MMS server, summarise a capture, and validate SCL files."
weight = 60
+++

```bash
brew install hupe1980/tap/ied               # macOS arm64, Linux x86-64 and arm64
cargo install iec61850-rs --features cli    # from source
```

Each release also has the binaries for Linux (glibc and musl), macOS and Windows, with a
`SHA256SUMS`.

One binary, `ied`, with subcommands. The process-bus subcommands read and write **capture
files** — no interface, no privileges — and, with `--iface`, a **live interface**. The `mms`
subcommands and `sim` use TCP. Every subcommand answers `--help` with its own usage.

## Live interfaces

```bash
sudo setcap cap_net_raw+ep "$(command -v ied)"     # once, instead of running as root

ied goose sniff --iface eth1 --duration 30          # listen, then judge what arrived
ied sv monitor --iface eth1 --scd bay.scd --write sv.pcap
ied mu --iface eth1 --profile le80-60 --frames 48000          # a merging unit on the wire
ied mu --iface eth1 --launch-time                               # paced by the kernel (etf/taprio)
ied goose publish --iface eth1 --scd bay.scd --gocb IED1LD0/LLN0.gcbTrip --value true
ied sim bay.scd --iface eth1                        # enabled GoCBs/MSVCBs publish here
```

A live capture is recorded for `--duration` seconds (default 10) and then judged by exactly
the code that judges a capture file, so both report the same thing about the same frames;
`--write` keeps it. The kernel filters on the GOOSE or SV EtherType and on the IEC multicast
range (or the groups a command joins) before anything reaches `ied`; truncated frames are
counted, not decoded. `--promiscuous` is for port mirrors.

The capability is dropped as soon as the interface is open. On Linux the sockets use a
TPACKET_V3 ring, kernel timestamps and, with `--launch-time`, `SO_TXTIME`; on macOS they use
BPF devices (`/dev/bpf*` access, as Wireshark's ChmodBPF grants). Windows has no live
interface.

## Generate a stream

`ied mu` is a virtual merging unit: it writes a synthetic three-phase sampled-value stream into
a capture.

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

The waveform is three phases 120° apart, currents a tenth of the voltages. The 9-2LE profiles
count samples per cycle, so `le80-60` implies 60 Hz and `le80-50` 50 Hz; the IEC 61869-9
profiles default to 50 Hz. `--freq` overrides either.

## Monitor sampled values

```bash
$ ied sv monitor stream.pcap
svID=MU01 appid=0x4000 dst=01-0C-CD-04-00-00 confRev=1 smpCnt wraps at 4800 (smpRate)
  frames=2000 asdus=4000 (2/frame) last smpCnt=Some(3999) smpSynch=Some(Global) gaps=0 samples lost=0
```

It runs the library's own subscriber state machine over the capture. Per stream: frames,
ASDUs per frame, the last sample counter, the synchronisation state, `gaps` (discontinuities)
and `samples lost` (the samples inside them). Sync and grandmaster changes are listed
underneath as timestamped events.

Gaps are counted modulo the value `smpCnt` wraps at, and the line says where that came from:
`smpRate` when the stream advertises it, `observed` when it does not (9-2LE sends no `smpRate`,
so the highest counter seen is used), or `given` with `--rate`.

| Option | Default | Meaning |
|---|---|---|
| `--freq` | 50 | Nominal frequency, for reading `smpRate` as samples per cycle |
| `--rate` | inferred | Samples per second, overriding what the stream advertises |
| `--scd` | — | Configure the streams from an engineering file instead of from the capture |
| `--ied` | all | With `--scd`, only the streams this IED publishes |

### Name the channels, from the engineering file

With the engineering file, each ASDU's sample block decodes into named channels:

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

The rate, `confRev` and layout come from the `SampledValueControl` and its data set, so any
fixed-width data set works. A stream whose ASDUs are not the length the file describes is
reported, not decoded.

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

The library's subscriber state machine runs per stream, and anything it rejects is printed
where it happened:

```text
     4.001ms IED1LD0/LLN0$GO$gcbTrip appid=0x0001 stNum=1 sqNum=0 tal=8ms conf=1 members=1 t=…
           ! Invalid(Replay { st_num: 1, sq_num: 0 })
01-0C-CD-01-00-00 IED1LD0/LLN0$GO$gcbTrip appid=0x0001
  accepted=2 states=2 retransmissions=0 replays=1 expiries=0 malformed=0 member-count=0 sim-mismatch=0
  last deltas: stDiff=1 sqDiff=0 arrival=0.001ms t=0.000ms sinceChange=0.001ms
```

The closing per-stream block is the counters plus five delta features — see
[GOOSE](@/docs/goose.md#counters-and-the-numbers-an-ids-wants). A stream that lost state
changes while live gets an extra line saying how many.

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

The arrow is the direction relative to port 102. Only the first twenty report lines are
printed; the summary counts all. A PDU that does not decode is counted and named — see
[MMS](@/docs/mms.md) for what is modelled.

Unsolicited PDUs go through the classifier a live client uses: an IEC 61850 report is printed
with its identifier, sequence number and member count, a command termination is named as one.
The capture above is ICCP, so its reports are printed as plain data-set reports.

## Be a server

An SCL file is a working IED:

```bash
$ ied sim bay.scd
IED1 on 127.0.0.1:102 — Edition 2.1 — logical device(s) IED1LD0
IED2 on 127.0.0.1:103 — Edition 2.1 — logical device(s) IED2LD0, IED2LD1
serving; ^C to stop
```

| Option | Default | Meaning |
|---|---|---|
| `--ied` | every IED | Serve only this IED |
| `--bind` | `127.0.0.1` | Address to listen on |
| `--port` | 102 | First port; each further IED takes the next |
| `--files` | — | Serve this directory through the MMS file services, read-only and sandboxed |
| `--writable` | off | Also allow `FileDelete` and receiving files (`SetFile`) in that directory. Refused if the directory holds the SCL file or the `--log-db` path |
| `--password` | none | Require this ACSE password of every association; with `--writable`, only those may send files |
| `--edition` | from the file | `1`, `2` or `2.1` |
| `--log-db` | in memory | Keep the logs in this file across restarts (a directory of `<IED>.redb` files when serving several IEDs) |

The edition is the file's own: `2003` is Edition 1, `2007B` Edition 2, `2007B4` and later
Edition 2.1. An Edition 1 server's report control blocks have no `ResvTms` and no `Owner`.

```bash
$ ied sim valid2003.scd
IED1 on 127.0.0.1:102 — Edition 1 — logical device(s) IED1CircuitBreaker_CB1, IED1Disconnectors
```

Service-tracking objects the file engineers are listed in the banner:

```bash
$ ied sim tracking.icd
IED1 on 127.0.0.1:102 — Edition 2.1 — logical device(s) IED1LD0
  service tracking: IED1LD0/LLN0$SR$GenTrk, IED1LD0/LLN0$SR$UrcbTrk, IED1LD0/LLN0$SR$BrcbTrk,
                    IED1LD0/LLN0$SR$SgcbTrk, IED1LD0/LLN0$SR$SpcTrk, IED1LD0/LLN0$SR$CtlTrk,
                    IED1LD0/LLN0$SR$LocbTrk, IED1LD0/LLN0$SR$LogTrk
serving; ^C to stop
```

It is a full server — browse, report, control, setting groups, files, logs:

```bash
$ ied sim relay.icd --port 10102 &
$ ied mms browse 127.0.0.1:10102
$ ied mms control 127.0.0.1:10102 IED1LD0/CSWI1.Pos true
```

## Talk to a live server

The `mms` subcommands open an association (the OSI stack, ACSE and MMS `Initiate`) and run one
service.

```bash
$ ied mms status 10.0.0.5
logical   state-changes-allowed (0)
physical  operational (0)
healthy   true
capabilities
  IEC 61850-8-1:2011+AMD1:2020

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

$ ied mms read 10.0.0.5 'IED1LD0/MHAI1.HA.phsAHar(2).cVal.mag.f' --fc MX   # one array element
IED1LD0/MHAI1.HA.phsAHar(2).cVal.mag.f = 12.5

$ ied mms write 10.0.0.5 IED1LD0/PTOC1.StrVal.setMag.f 1.20 --type float --fc SP
IED1LD0/PTOC1.StrVal.setMag.f <- 1.2

$ ied mms rcb 10.0.0.5 IED1LD0/LLN0.urcb01
IED1LD0/LLN0$RP$urcb01
  kind       unbuffered (RP)
  RptID      IED1LD0/LLN0$RP$urcb01
  RptEna     false
  DatSet     IED1LD0/LLN0$dsTrip
  ConfRev    3
  OptFlds    SqNum, TimeOfEntry, ReasonCode, DatSet, ConfRev
  TrgOps     triggers: data change, quality change, GI
  BufTm      0 ms
  IntgPd     0 ms
  SqNum      0
  Resv       false

$ ied mms report 10.0.0.5 --rcb IED1LD0/LLN0.urcb01 --gi --seconds 60
enabled IED1LD0/LLN0$RP$urcb01 — data set IED1LD0/LLN0$dsTrip, triggers: data change, quality change, GI
general interrogation requested
listening for 60 s
report 1 IED1LD0/LLN0$RP$urcb01 sq=0 t=2023-11-14T22:13:20.000Z dataSet=IED1LD0/LLN0$dsTrip confRev=3 — 2 of 2 members
    [0] = true  (general interrogation)
    [1] = Quality { validity: Good, .. }  (general interrogation)

$ ied mms control 10.0.0.5 IED1LD0/CSWI1.Pos true --interlock
IED1LD0/CSWI1.Pos <- true (command termination + for IED1LD0/CSWI1$CO$Pos$Oper)
```

With neither `--model` nor `--scd`, `mms control` reads the object's `ctlModel` from the
server first, so a select-before-operate object gets its select.

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

$ ied mms put 10.0.0.5 settings.xml SETTINGS/settings.xml --password s3cret
settings.xml -> SETTINGS/settings.xml (2048 octets)

$ ied mms log 10.0.0.5 'IED1LD0/LLN0$GeneralLog' --lcb IED1LD0/LLN0.lcb01
IED1LD0/LLN0$LG$lcb01  enabled
  LogRef  IED1LD0/LLN0$GeneralLog
  DatSet  IED1LD0/LLN0$dsTrip
  TrgOps  triggers: data change, quality change, GI
  oldest  2023-11-14T22:13:20.000Z
  newest  2023-11-14T22:14:20.000Z
2023-11-14T22:13:20.000Z 0000000000000001  ReasonCode(data_change)
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

- `mms type` is `GetVariableAccessAttributes`.
- `mms get` writes to a file, or to standard output without a destination.
- `mms put` is `SetFile`: the server reads the local file from `ied` as it stores it.
- `mms log` prints entries oldest first, following `moreFollows`, with each entry's reason
  code when recorded; `--lcb` also reads the log control block.
- `mms sg` prints the setting group control block; without a reference it uses the `SGCB` of
  the server's first logical device.
- `mms report --rcb` enables the block and decodes every report field, joining segmented
  reports. Without `--rcb` it only listens.
- `browse` follows `moreFollows` paging to the end.

A refused control is an error with a name and a non-zero exit:

```bash
$ ied mms control 10.0.0.5 IED1LD0/CSWI1.Pos true --model sbo-enhanced
ied: IED1LD0/CSWI1.Pos: refused — BlockedByInterlocking (AddCause 10)
```

`--scd` takes the OSI selectors and AP-title from the engineering file; with a host of `-`, the
IP address too:

```bash
$ ied mms browse - --scd bay.scd --ied IED1
```

The port defaults to 102. A reference is either the dotted ACSI form with `--fc`, or the MMS
`LN$FC$DO$DA` form, which carries its own. Reads default to `ST`; `write` requires `--fc`,
because a conforming server refuses writes to `ST` and `MX` (IEC 61850-7-2 §5.7). Settings are
`SP` or `SE`, configuration `CF`, descriptions `DC`, controls `CO`.

| Option | Default | Meaning |
|---|---|---|
| `--fc` | `ST` for reads | Functional constraint of a dotted reference |
| `--type` | `bool` | How `write` encodes the value: `bool`, `int`, `uint`, `float`, `string` |
| `--password` | — | IEC 61850-8-1 ACSE password |
| `--timeout` | 30 s | How long to wait for an answer |
| `--seconds` | 30 | How long `report` listens |
| `--rcb`, `--buffered`, `--data-set`, `--intg-pd`, `--gi` | — | `report`: block to enable, BR, data set, integrity period, general interrogation |
| `--model` | read from the server | `direct`, `sbo`, `direct-enhanced`, `sbo-enhanced` |
| `--orcat`, `--orident` | `3`, `ied` | Originator category and identifier |
| `--synchro`, `--interlock`, `--test` | off | Control check and test flags |
| `--max-size` | 16 MiB | Largest file `get` reads |
| `--activate`, `--edit` | — | `sg`: activate or reserve a setting group |
| `--lcb`, `--entries` | —, 1000 | `log`: also read the control block; stop after N entries |
| `--scd`, `--ied` | — | Addressing from the engineering file |
| `--local-tsel`, `--remote-tsel` | `0001` | OSI transport selectors |

## Summarise a capture

```bash
$ ied pcap info bay.pcap
bay.pcap: 79 frames over 8.261 s
  GOOSE 16, sampled values 0, other 63, VLAN-tagged 0
  2 process-bus frames per second
```

What the capture contains, and at what rate.

## Inspect and validate SCL

```bash
$ ied scl show substation.scd IED1
IED IED1 (ACME Relay, config 1.0)
  LD IED1LD0 (inst LD0)
    LN LLN0 [LLN0_T] 2 data objects
      DO Mod [INC]
      DO Beh [INS]
      DataSet dsTrip (2 members)
        IED1LD0/PTRC1$ST$Tr$general
        IED1LD0/PTRC1$ST$Tr$q
      GSEControl gcbTrip confRev=3 01-0C-CD-01-00-05 appid=0x0005 vlan=1
      SampledValueControl msvMU multicast smvID=MU01 smpRate=80 nofASDU=1 01-0C-CD-04-00-01 appid=0x4000
      ReportControl brcb01 buffered=true confRev=2 bufTime=50ms
```

The bracketed name beside each data object is its common data class (`DPC`, `MV`, `BTS`, …).

`scl validate` loads every IED and reports engineering errors the XML schema does not catch:

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
| `MissingDataSet` | A control block naming a data set that does not exist, or none at all — a report and log control block is checked as strictly as a publisher |
| `MissingLog` | A `LogControl` whose `logName` names no `Log`: every entry it makes is dropped |
| `ControlServicesMissing` | A `ctlModel` promising a service its type does not declare — select-before-operate with no `SBOw`, or any control model with no `Oper` |
| `ReportTriggers` | An `intgPd` with no integrity trigger, a trigger with no period, or no `TrgOps` at all (warning) |
| `IndexedReportControl` | `RptEnabled max` above one on a block that is not `indexed`: there is one instance whatever the number says, so the file promises clients the device cannot serve (warning) |
| `DuplicateTypeMember` | A type template declares a member name twice (two `DA`s in one `DOType`, two `DO`s in one `LNodeType`); a server would publish two variables of one name |
| `UnresolvedFcda` | A data-set member that does not resolve against the IED's own types |
| `ObjectReferenceTooLong` | Longer than the edition allows (`--edition 1` is stricter than `2.1`) |
| `RetransmissionTimes` | `MinTime` at or above `MaxTime`, or absent (warning) |
| `SampleRate` | A `nofASDU` or `smpRate` that cannot describe a publishable stream, or a sampled-value data set with no fixed-width layout |
| `VlanPriority` | Below 4: it will not get a trip through a loaded switch (warning) |
| `UnresolvedSubscription` | An `ExtRef` bound to something this file does not resolve |

Every finding has a stable code and a severity. The command exits non-zero on any error, and
on warnings with `--strict`.

| Option | Default | Meaning |
|---|---|---|
| `--freq` | 50 | Nominal frequency, for reading `smpRate` |
| `--edition` | `2.1` | Whose object-reference length limit applies (`1`, `2`, `2.1`) |
| `--strict` | off | Treat warnings as errors |

The same checks are the library function `scl::validate`.

## Resolve what an IED subscribes to

`scl subs` lists what an IED receives, and from where:

```bash
$ ied scl subs bay.scd IED2
IED2 subscribes to 1 GOOSE and 1 sampled-value stream(s)
  IED1LD0/LLN0$GO$gcbTrip from IED1 (IED1LD0/LLN0.gcbTrip)
    01-0C-CD-01-00-05 appid=0x0005 confRev=3
    <- PTRC1.Tr.general [BI1]
  MU01 from IED1 (IED1LD0/LLN0.msvcb01)
    01-0C-CD-04-00-01 appid=0x4001 confRev=1 rate=4000/s 2 channels/8 octets per ASDU
    <- TCTR1.AmpSv.instMag.i
supervision:
  IED2LD0/LGOS1 (LGOS) -> IED1LD0/LLN0$GO$gcbTrip
  IED2LD0/LSVS1 (LSVS) -> nothing engineered
```

Each `Inputs/ExtRef` is resolved against the publisher's control block and `Communication`
address and grouped by control block, with the internal address in brackets. A binding without
`srcCBName` is resolved by finding which of the publisher's data sets carries the signal and
which control block publishes it. Bindings that resolve to nothing are listed as `unresolved`
and the command exits non-zero.

`supervision:` lists which `LGOS`/`LSVS` watches which control block (`GoCBRef`/`SvCBRef`);
one that names nothing, or a block this IED does not subscribe to (`[not subscribed]`), is
flagged. `--freq` (default 50) is the nominal frequency for reading `smpRate`.

## Edit SCL

`scl edit` makes one change without reformatting the file; references move with it:

```bash
$ ied scl edit bay.scd rename-ied Pub Bay1 --in-place --who alice --why "bay renumbering"
rename IED Pub → Bay1: 6 change(s)
$ ied scl edit bay.scd gse Bay1 LD0 gcb1 --appid 0042 --vlan 00A --dry-run
--- bay.scd
+++ bay.scd
@@ -17,8 +17,8 @@
 				<GSE ldInst="LD0" cbName="gcb1">
 					<Address>
 						<P type="MAC-Address">01-0C-CD-01-00-01</P>
-						<P type="APPID">0001</P>
-						<P type="VLAN-ID">000</P>
+						<P type="APPID">0042</P>
+						<P type="VLAN-ID">00A</P>
 						<P type="VLAN-PRIORITY">4</P>
 					</Address>
 				</GSE>
set GSE address of Bay1LD0/gcb1: 2 change(s)
```

The six changes of the rename are the IED, its `ConnectedAP`, an `LNode`, a subscriber's
`ExtRef`, an `LGOS` value naming its GOOSE block, and the history item.

| Edit | Arguments |
|---|---|
| `rename-ied` | `<OLD> <NEW>` |
| `remove-ied` | `<NAME>` |
| `gse` | `<IED> <LD> <CB>` with `--mac`, `--appid` (hex), `--vlan` (hex), `--vlan-priority`, `--min-time`/`--max-time` (ms); unset fields keep their value |
| `smv` | `<IED> <LD> <CB>` with `--mac`, `--appid`, `--vlan`, `--vlan-priority` |
| `ap-address` | `<IED> <AP> <P-TYPE> <VALUE>`, e.g. `IP 10.0.0.5` |
| `history` | `--what <TEXT>` (and `--version`, `--revision`, `--who`, `--why`) |

| Option | |
|---|---|
| `-o <FILE>`, `--in-place` | where to write (default stdout); the file is replaced atomically |
| `--dry-run` | print a unified diff and write nothing |
| `--who`, `--why` | also record the edit as a `Header/History` item |
| `--check` | refuse to write if the result has any validation error |
| `--force` | write even if the edit adds validation errors — refused otherwise |
| `--max-size <BYTES>` | refuse larger input before reading it (default 1 GiB) |
| `--freq <50\|60>` | nominal frequency for validation (default 50) |

The file is validated before and after the edit; an edit that adds an error finding is refused
with the finding's code. A failed edit writes nothing.

## Encode, decode, dissect

```bash
ied mu /tmp/s.pcap --profile f14400s6 --frames 500   # encode
ied sv monitor /tmp/s.pcap                           # decode
ied sv monitor /tmp/s.pcap --scd bay.scd             # …and name every channel from the SCD
tshark -r /tmp/s.pcap -Y sv                          # and have Wireshark judge it
```

CI runs this loop on every push.
