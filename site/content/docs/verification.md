+++
title = "Verification"
description = "How iec61850-rs is tested: vendor captures re-encoded byte for byte, Wireshark and libiec61850 as external oracles, adversarial simulation, fuzzing — and what is not proven."
weight = 70
+++

Three kinds of evidence, strongest first:

1. **A verdict from a tool this project did not write** — Wireshark's dissectors.
2. **Agreement with another implementation** — a vendor IED's captured frames; libiec61850's
   client and server, run against this stack in CI.
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

## libiec61850, in both roles

`tests/interop.rs` builds [libiec61850](https://github.com/mz-automation/libiec61850) (C,
GPLv3/commercial) in a CI job and runs:

| Direction | What runs | What it checks |
|---|---|---|
| their client → this server | `mms_utility` | `Identify`, `GetNameList` over the sorted namespace, a structured `Read`, type discovery |
| their client → this server | `client_example_control` | all four control models including both selects, one `CommandTermination+` per enhanced-security command, and the switchgear actually moving |
| their client → this server | `client_example1` | enabling a report control block in one write, general interrogation, integrity reports and their reason codes |
| this client → their server | `server_example_basic_io` | associate, `Status`, both directories, `Read`, `GetVariableAccessAttributes`, data sets, reporting, a control, release |
| this client → their server | `server_example_logging` | the log control block with its buffer cursor, both log queries |
| both directions | `mms_utility -y <index>` and the harmonics model | an array element read as one element, at four depths |

The servers are loaded from libiec61850's own engineering files, read from its tree. The GPL
binaries run as external processes and are never linked.

libiec61850 spells a log control block's buffer cursor `OldEntr`/`NewEntr`; IEC 61850-7-2
spells it `OldEnt`/`NewEnt`. This client asks for both; this server publishes the standard's.

`IEC61850_LIBIEC61850` points at a built checkout and the tests skip without it;
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
- **One interop peer, station bus only.** libiec61850 is the only second stack in CI.
  IEC61850bean and other implementations are not tested against, and GOOSE/SV interop with
  libiec61850 is not tested: the crate has no raw-socket adapter, so the process bus is checked
  with capture files and Wireshark.
- **Some rules come from secondary sources.** The IEC standards are paywalled; where a rule is
  taken from a public preview, a Wireshark dissector, an open-source implementation or a paper,
  the source code says so. The IEC 62351-6 layer-2 authentication extension (§8.2.2) and the
  sampled-value replay state machine (§6.2.2) are not implemented for that reason. The GOOSE
  replay verdict uses arrival time and the advertised `timeAllowedtoLive`, never the publisher's
  timestamp — a reading of §6.2.1, not a conformance claim.
- **No performance figures.** Nothing has been measured on reference hardware.
- **No hardware timing.** Everything runs on capture files and virtual time.
