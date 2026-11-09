+++
title = "Verification"
description = "How iec61850-rs is tested: vendor captures re-encoded byte for byte, Wireshark and three other stacks as external oracles, adversarial simulation, fuzzing — and what is not proven."
weight = 70
+++

Three kinds of evidence, strongest first:

1. **A verdict from a tool this project did not write** — Wireshark's dissectors.
2. **Agreement with another implementation** — a vendor IED's captured frames; libiec61850,
   IEC61850bean and csp0924's crates, run against this stack in CI in both roles.
3. **This crate's own tests** — which prove consistency, not correctness.

A dissector says whether a PDU is well-formed; only a peer says whether it is the PDU that was
expected, in the order it was expected. Both are used.

## Vendor captures, re-encoded exactly

Every frame of a real capture is decoded, encoded again from the decoded values, and compared
byte for byte.

| Capture | Contents | Result |
|---|---|---|
| Two SEL IEDs exchanging GOOSE | 16 GOOSE frames in 79 | every frame byte-identical |
| A 9-2LE merging unit, 60 Hz | 10,161 frames | every frame byte-identical |
| A real MMS association | 165 packets, six OSI layers | 653 of 656 encodings byte-identical |

The three MMS exceptions are PDUs where the captured server uses a two-octet long-form BER
length that fits in one. This encoder writes the minimum, so they come back shorter; for them
the test asserts that the re-encoding is a fixed point and never longer than the original.

A sampled-value `Publisher`, configured like the captured merging unit and fed its sample
blocks, reproduces the captured frames exactly.

## Client against server, over a socket

The MMS association is one type with a `Role`, so the suite runs the real client against the
real server over a loopback socket. The test server writes seven octets at a time, so a client
that only works when a PDU arrives whole fails. Covered, among others:

- browse, read, write, data-set create/delete, type discovery;
- report control blocks: enable, take-over by a second client, refused reconfiguration while
  enabled, `BufTm` gathering, buffered replay, segmented reports reassembled whole;
- all four control models, interlocking refusals with `AddCause`, `CommandTermination`;
- setting groups, logs queried by time and after an entry;
- file transfer, sandbox escapes refused, and every `frsmID` closed even when a read is
  abandoned.

Every `ied mms` subcommand runs against the same server.

The reference MMS capture is also replayed through **both** roles at once — the captured
server's bytes into this client, the captured client's bytes into this server. The capture is
bidirectional (11 confirmed services one way, 12 the other), and its 115 information reports
are ICCP data-set reports, which the classifier must return as raw values rather than as IEC
61850 reports.

Client-against-server tests prove the two halves agree about the mapping. They do not prove
either half is right; the next two sections do.

## Wireshark as the oracle

Every frame the encoders emit in tests is written to a capture and dissected with `tshark`. A
test fails on any malformed marker or expert error, and on any field that does not dissect to
the value that was put in.

For the station bus, a recording proxy sits in front of a real server while a real client runs
one association through every service — associate, browse, read, write, type discovery, data
sets, reporting with a general interrogation, a control, logs, setting groups, files, release.
The byte stream is dissected as `tpkt`/`cotp`/`ses`/`pres`/`acse`/`mms` and asserted on with
Wireshark's own field names. A second run uses a 900-octet negotiated PDU and a twelve-member
data set of data objects, so segmented, structured reports are dissected too.

The tests walk each field's **declared range**, not typical values. A BER INTEGER is signed, so
`smpSynch` = 200 in one octet would read as −56 and a 96 kHz `smpCnt` of 65,535 in two octets
as −1; the publisher widens such fields by one octet, and the oracle checks the extremes.

Wireshark up to 4.2.2 marks legitimate GOOSE messages malformed ([wireshark#19580]), so the
tests skip on an older `tshark`. CI sets `IEC61850_REQUIRE_TSHARK=1`, which makes a missing or
too-old `tshark` a failure.

[wireshark#19580]: https://gitlab.com/wireshark/wireshark/-/issues/19580

## Three other stacks, in both roles

`tests/interop.rs` runs this crate against three implementations it did not write. Each is a
container image built from a pinned, checksum-verified release, so the suite needs nothing but
Docker; GPL code runs as an external process and is never linked.

| Peer | Direction | What it checks |
|---|---|---|
| [libiec61850](https://github.com/mz-automation/libiec61850) 1.6.2.1 (C) | their client → this server | `Identify`, the sorted namespace, structured reads, type discovery; all four control models with their terminations; reports with GI and integrity; `SetFile`; their log client against both log stores |
| | this client → their server | `Status`, directories, reads, types, data sets, reporting, control, both log queries |
| | both directions | an array element read as one element, at four depths |
| | GOOSE, both directions | their publisher → this subscriber; this publisher → their subscriber, judged valid |
| | SV, both directions | their publisher → this subscriber; a 9-2LE merging unit → their subscriber |
| [IEC61850bean](https://github.com/beanit/iec61850bean) 1.9.0 (Java) | both directions | association, model discovery, reads, a write, reporting with GI, a direct control, file directory |
| [csp0924's crates](https://github.com/csp0924/iec61850-rust) 0.4.0 (Rust) | their client → this server | association, directories, reads, a write, reporting with GI, a direct control |
| | this client → their server | directories, reads, type discovery |

The process-bus runs put `ied` and libiec61850 on one Docker network, each with a raw socket on
its own interface. Every disagreement found, and whose it was, is recorded in
`tests/interop/PEERS.md` in the repository — among them the empty session selector that made
IEC61850bean refuse every association with this crate, now fixed.

Run it with `cargo test --all-features --test interop`. Without Docker the tests skip by name;
`IEC61850_REQUIRE_INTEROP=1`, set in CI, turns the skip into a failure.

## Adversarial simulation

A GOOSE publisher and subscriber run against each other under virtual time, over a network that
loses, delays, duplicates, reorders and replays frames and partitions long enough for the
subscription to expire. 64 seeds in a normal test run, 512 in CI; a failing seed is printed and
replayed with `SIM_SEED=<n>`.

Invariants, asserted from the event stream alone:

1. While live, the subscriber only moves forward in `stNum`; it may go back only after
   `Expired` (the IEC 62351-6 restart rule).
2. It never reports a `stNum` the publisher never published.
3. A live subscription always has a wake-up deadline; an expired one never does.
4. Accepted frames are exactly states plus retransmissions.
5. The publisher never emits a frame its own decoder rejects.
6. A run that delivered nothing fails.

The invariants are mutation-tested: removing the expiry check breaks invariant 1, and accepting
a non-advancing `sqNum` breaks the replay case. A publisher restarting in the middle of a
`stNum` is not generated by the simulation and has focused tests of its own.

## Fuzzing

Ten `cargo-fuzz` targets, each run for 60 seconds on every push:

| Target | Exercises |
|---|---|
| `goose_frame` | frame → PDU → owned → re-encode → decode, plus the subscriber and its timers |
| `sv_frame` | the sampled-value decode path and the multi-stream subscriber |
| `sv_publisher` | arbitrary samples and counters through template patching, on both template layouts, decoded back field by field |
| `ber_data` | every accessor on every TLV, plus a `Value` round trip |
| `scl_load` | the SCL loader on arbitrary bytes |
| `scl_subscriptions` | resolving one IED's `ExtRef`s against the publishers in the same document |
| `pcap_read` | the capture reader |
| `mms_stack` | every OSI layer and MMS from arbitrary bytes, with the MMS encoder required to be a fixed point; decoded reports, `Oper` and `LastApplError` values must re-encode to themselves |
| `mms_association` | the association state machine in both roles, fed seven octets at a time: no panic, a closed association never asks to be woken, `abort` is terminal |
| `mms_server` | arbitrary requests into the ACSI server on two associations; every answer must encode and every report must decode |

Each input a fuzzer has crashed on is committed under `fuzz/regressions/`, named after the bug,
and replayed by `cargo test --test regressions` through the same entry points.

## Zero allocations, counted

A counting `#[global_allocator]` asserts:

| Path | Allocations |
|---|---|
| GOOSE publisher, 1000 retransmissions | 0 |
| GOOSE publisher, 1000 state changes | 0 |
| GOOSE publisher, 1000 `publish_if_changed` comparisons | 0 |
| SV publisher, one second of IEC 61869-9 at 2400 frames/s with `refrTm` | 0 |
| SV publisher, the same second through `publish_repeating` | 0 |
| SV subscriber, that second, decoding every channel of every ASDU | 0 |
| GOOSE subscriber, 100 retransmissions | 0 |

The GOOSE buffers reserve the worst-case encoded width of `stNum`, `sqNum` and
`timeAllowedtoLive` at construction. The GOOSE subscriber allocates on a state change, because
it hands the application owned values.

## Real corpora

- **Vendor captures.** The dataset-driven sample layout must decode all 10,161 captured ASDUs to
  the same sixteen values as the fixed 9-2LE layout.
- **OpenSCD's SCL files.** Every data-set member of every IED whose types resolve must resolve;
  every addressed SV stream's channel layout must match its independently summed ASDU length;
  `valid2007B4.scd` is pinned to its known findings.
- **Hand-written fixtures** are validated against the SCL schema and Wireshark, and include
  data sets of data objects, reports larger than the negotiated PDU, and a setting served under
  two functional constraints.

The captures and OpenSCD files are third-party and not in the repository;
`scripts/fetch-references.sh` downloads them into `$IEC61850_REFERENCE`, and the tests that use
them skip when it is absent.

## Panic-freedom

`#![forbid(unsafe_code)]` across the library. The only target that allows `unsafe` is the
allocation test, for its counting allocator. `unwrap`, `expect`, `panic` and slice indexing are
denied by lint in library code; every malformed input becomes an error with a reason and an
offset.

Decoders enforce limits — nesting depth, data-set members, primitive length, ASDUs per frame —
before allocating. Event queues are bounded and count what they drop.

## Other gates

Every push runs `rustfmt`, `clippy` with warnings denied, a `no_std` build for
`thumbv7em-none-eabihf`, the MSRV (1.85) check, and a build and doctest of every feature on its
own — `std`, `goose`, `sv`, `mms`, `scl`, `pcap`, `client`, `server`, `cli` — and with none.
Documentation is built with warnings denied on the all-features build docs.rs serves.

## What is not proven

- **No conformance certificate.** IEC 61850-10 test procedures, run by UCAIug-accredited
  laboratories, have not been applied.
- **Three peers, not the field.** libiec61850, IEC61850bean and csp0924's crates agree with this
  crate on the scenarios above; a vendor IED may still differ. csp0924's server is covered for
  browse and read only, because it does not take control blocks from the SCL file.
- **Some rules come from secondary sources.** The IEC standards are paywalled; where a rule is
  taken from a public preview, a Wireshark dissector, an open-source implementation or a paper,
  the source code says so. The IEC 62351-6 layer-2 authentication extension (§8.2.2) and the
  sampled-value replay state machine (§6.2.2) are not implemented for that reason. The GOOSE
  replay verdict uses arrival time and the advertised `timeAllowedtoLive`, never the publisher's
  timestamp — a reading of §6.2.1, not a conformance claim.
- **No performance figures.** Nothing has been measured on reference hardware.
- **No hardware timing.** Everything runs on capture files and virtual time.
