+++
title = "Verification"
description = "What is proven about iec61850-rs: vendor captures re-encoded byte for byte, Wireshark and libiec61850 as external oracles, adversarial simulation — and what is not proven."
weight = 70
+++

A claim about the wire is worth what its evidence is worth. This page is the evidence, and
the limits of it.

Three kinds of evidence count here, in descending order:

1. **A verdict from a tool this project did not write.** Wireshark's dissectors; one day, a
   laboratory's test set.
2. **Agreement with an implementation that does not share our method.** A vendor IED's own
   frames, captured off a real bus; libiec61850's client and server, driven against this
   stack in CI.
3. **Our own tests.** Useful, but a suite that only compares this crate with itself proves
   consistency, not correctness.

The first two do not overlap, and the gap between them is where most of the defects found so
far have lived. A dissector says whether a PDU is **well-formed**. Only a peer says whether it
is the PDU that was expected, with the arguments and in the order that were expected.

## Vendor captures, re-encoded exactly

The strongest check available without a laboratory: decode every frame of a real capture,
encode it again from the decoded values, and require the same bytes.

| Capture | What is in it | Result |
|---|---|---|
| Two SEL IEDs exchanging GOOSE | 16 GOOSE frames in 79 | every frame re-encodes byte for byte |
| A 9-2LE merging unit, 60 Hz | 10,161 frames | every frame re-encodes byte for byte |
| A real MMS association | 165 packets, six OSI layers | 653 of 656 encodings byte for byte |

For sampled values it goes one step further. A `Publisher`, configured the way the captured
merging unit was configured and fed that capture's own sample blocks, **reproduces its
frames exactly**. One assertion covers the profile, the template patching, the ASDU encoding
and the link layer — against hardware output rather than against our own expectations.

The three MMS encodings that are not identical are the PDUs where that server spends two
octets on a long-form BER length that fits in one. BER permits it, DER does not, and this
encoder writes the minimum — so those come back *shorter* than they arrived, and what is
asserted for them is the next strongest property: the re-encoding is a fixed point, and never
longer than the original.

Byte-identity is a strict test. It catches a tag that should have been primitive, an optional
field emitted where the original omitted it, and a field order that happens to decode either
way. None of those shows up in a round trip that only compares decoded values.

## The stack against itself, over a socket

A capture proves the codecs. It cannot prove *sequencing* — that a client sends its session
CONNECT only after the COTP CC, that the CPA is what establishes an association, that a
response releases the invoke identifier it answers.

The MMS association is **one type with a `Role`**, so the suite runs a real client against a
real server over a loopback socket. The server is a real one, not a stub with canned bytes: it
holds a report control block attribute by attribute, refuses a write to a configured attribute
while reporting is enabled — which is what the standard says and what the client's ordering
rule exists for — builds reports through the same encoder a real server would, answers a
control with a `CommandTermination`, positive or negative with an `AddCause`, splits a report
into one segment per data-set member, hands a file over eight octets at a time, keeps a log and
a setting group control block, and asserts that every `frsmID` it issues is given back.

That covers cases nothing else can reach: a report and a command termination arriving on the
same channel must not consume each other, a `GetNameList` that pages must be followed to the
end, a control the substation refuses must become an error rather than a success, a segmented
report must reach the application whole or not at all, and a file read that is abandoned
halfway must still close its handle — the server fails the test if it does not. The test
server writes **seven octets at a time**, because a client that only works when a PDU arrives
whole works on a bench and nowhere else. The `ied mms` subcommands run against the same server,
so every one of them is covered too — with no vendor device and no network interface.

The reference capture is then replayed through **both** roles at once: the real server's bytes
into our client, the real client's bytes into our server, each required to establish and to
account for every service in the file. That exposed something the codec test could not see: the
capture is **bidirectional**. Both peers issue confirmed services (11 one way, 12 the other)
and both send information reports — which a client-only association type would have been
quietly wrong about.

The same capture pins a **negative**. Its 115 information reports are ICCP data-set reports,
*not* IEC 61850 reports: no `RptID`, no `OptFlds`. The classifier has to hand them back as raw
values rather than inventing a report identifier out of the first one, and a test fails if it
ever starts claiming otherwise.

## Both halves against each other

With the server built, the "own test peer" property reaches the whole stack. The suite loads an
SCL file into a real server on a loopback port and runs the real client against it: browse the
flattened namespace and check it is sorted and complete, read and write through the model,
create and delete a data set, ask what type an `Oper` is, enable a report control block and
watch a change arrive with the right reason code, take that block over from a second client,
refuse a reconfiguration while it is enabled, gather two changes into one report with `BufTm`,
replay a buffered block's entries to a client that was not there, run all four control models,
refuse a select an interlocking hook rejects, activate a setting group, pull a file and fail to
escape its sandbox, and read a log back by time and after an entry.

Be clear about what that is worth. It proves the two halves agree about the **mapping** — that
the names the server publishes are the names the client builds, that `OptFlds` means the same
thing on both sides, that an `AddCause` survives the round trip. It does **not** prove either
half is right: two implementations by one author sharing one codec agree by construction. Only
the interop section below, or a conformance laboratory, moves that. What it does buy is
that a change to either half which breaks the other fails immediately — which is what makes the
mapping safe to refactor.

## Wireshark as the oracle

Every frame the encoders emit in tests is written to a capture and dissected with `tshark`.
The build fails on any malformed marker or expert error, and the decoded field values must be
the ones we put in.

That includes checks we did not write: Wireshark flags a frame whose header simulation bit
disagrees with the PDU's own field, and it knows the GOOSE, Sampled Values, ACSE and MMS
ASN.1 modules independently of us.

### The station bus, too

Client against server is a strong test of *sequencing* and no test at all of *encoding*,
because both ends share one codec. So the station bus has an oracle of its own.

A recording proxy sits in front of a real server; a real client runs one association through
every service the server answers — associate, browse,
read, write, type discovery, data-set create and delete, a report control block with a report
and a general interrogation, a control, a log control block and a log query, setting groups,
files, release — and the byte stream is written out as a TCP capture and handed to `tshark`.
The whole stack has to be there (`tpkt`, `cotp`, `ses`, `pres`, `acse`, `mms`) or the
dissector never reached MMS, and the assertions are Wireshark's own field names — so
"it dissects" cannot quietly mean "it dissects as something else".

It found three malformed PDUs, all invisible for the same reason: the only decoder that had
ever read them was ours.

| What | Why it was wrong |
|---|---|
| `AARE` had no `result-source-diagnostic` | The field is **mandatory** beside `result`, so every association this server accepted was answered with a malformed ACSE PDU |
| `JournalEntry` had no `originatingApplication` | Also mandatory; every log entry the server sent was malformed |
| `FileDirectory`'s `listOfDirectoryEntry` was implicitly tagged | It is the one field of the file services that is not, so the entries belong inside an inner `SEQUENCE`. Our encoder and our decoder agreed perfectly and no third party could read either |

It is now where a new encoding goes *first*. A second oracle test runs a deliberately small
client — a 900-octet PDU — against a twelve-member data set, so the server has to split its
report into segments, and every member of that data set is a data *object* rather than one
attribute, so each is carried as the structure it is. Both shapes would otherwise be read only
by this crate's own client, which is the case the whole page exists to distrust.

**"No malformed marker" is the weak half of the rule.** The strong half is that every field
dissects back to the value we put in. A sampled-value publisher writes `smpCnt`, `confRev` and
`smpSynch` at fixed widths so a template patch cannot shift a length, but a BER INTEGER is
*signed*: `smpSynch` is `0..254` and 5–254 name a local-area clock, so 200 in a single octet is
**−56**, and a 96 kHz stream's `smpCnt` of 65 535 in two octets is **−1**. Both dissect with no
malformed marker, and this crate's own reader reads both back correctly — only a third party's
dissector says otherwise. So the fields widen by one octet when a value would go negative, and
the oracle tests walk each field's *declared range* rather than the typical values.

The general form: **a value both ends of this suite merely agree on is not evidence.** A
report's `TimeOfEntry` is asserted against a clock the test pins, not against the other half of
the crate.

An oracle needs its own version floor. Wireshark up to 4.2.2 — which is what Ubuntu 24.04
ships — asserts `recursion_depth <= 100` on a *legitimate* GOOSE message and marks it
malformed ([wireshark#19580], fixed in 4.2.3), so an older dissector fails correct frames.
The tests skip on a `tshark` older than that rather than believe it, and CI sets
`IEC61850_REQUIRE_TSHARK=1`, which turns "missing or too old" into a failure — an oracle that
can quietly stop running is not one.

[wireshark#19580]: https://gitlab.com/wireshark/wireshark/-/issues/19580

## libiec61850, in both roles

A dissector reads octets. It does not know that a client is unhappy with the *order* a server
answers in, that a service argument the ASN.1 permits is one no device accepts, or that a name
is spelt differently in the field. For that there has to be a second stack, running in **both**
directions.

`tests/interop.rs` builds [libiec61850](https://github.com/mz-automation/libiec61850) (C,
GPLv3/commercial) in a CI job and runs:

| Direction | What runs | What it proves |
|---|---|---|
| their client → this server | `mms_utility` | `Identify`, `GetNameList` over the flattened sorted namespace, a structured `Read`, and the type discovery under it |
| their client → this server | `client_example_control` | all four control models including both selects, and one `CommandTermination+` per enhanced-security command — checked against the switchgear having moved, not only against the printout |
| their client → this server | `client_example1` | enable a report control block in one write, then a general interrogation and integrity reports, with the reason codes their decoder reads back |
| this client → their server | `server_example_basic_io` | associate, `Status`, both directories, `Read`, `GetVariableAccessAttributes`, data sets, reporting, a control, orderly release |
| this client → their server | `server_example_logging` | the log control block including its buffer cursor, and both log queries |
| both directions | `mms_utility -y <index>` and their harmonics model | an **array element** read as one element and not as the whole array — at four depths, which is what puts both `alternateAccess` encodings on the wire |

The models served are **libiec61850's own engineering files**, read out of its tree rather
than copied here: they are under a different licence, and they are documents this project did
not write. (Loading one of them found an error in it — a `LogControl` naming a `Log` the file
does not declare — which is the same evidence running the other way.) The GPL binaries are
executed as an external oracle and never linked.

It has bite, and the shape of what it catches is the argument for it: a rule about the *peer*
rather than about the octets. A type specification's `floating-point` was encoded with the
wrong tags and dissected clean, because Wireshark's MMS module does not model that field at
all. A request for one array element was answered with the whole array — successfully, with
nothing on the wire to say the question had changed.

`IEC61850_LIBIEC61850` points at a built checkout and the tests skip without it;
`IEC61850_REQUIRE_INTEROP=1` turns that skip into a failure, which is what CI sets — the same
rule the `tshark` gate follows, and for the same reason.

## Adversarial simulation

A publisher and a subscriber are driven against each other under virtual time, with a network
that loses, delays, duplicates, reorders and replays frames, and that partitions long enough
for the subscription to expire. Sixty-four seeds in a normal test run; 512 in CI. A failing
seed is printed and replayed with `SIM_SEED=<n>`.

The invariants are asserted from the **event stream alone**, because that is all an
application sees:

1. While the delivered state is live the subscriber only moves forward in `stNum`. It may go
   back only *after* emitting `Expired` — the IEC 62351-6 restart rule.
2. It never reports a `stNum` the publisher never published.
3. A live subscription always has a wake-up deadline; an expired one never does.
4. Accepted frames are exactly states plus retransmissions; nothing is unaccounted for.
5. The publisher never emits a frame its own decoder rejects.
6. A run that delivered nothing fails, rather than passing vacuously.

The invariants are **mutation-tested**. Removing the expiry check on frame arrival breaks
invariant 1 on 10 of 200 seeds; accepting a `sqNum` that does not advance breaks the replay
case. An invariant that cannot fail is worse than no invariant, because it looks like
evidence.

It has a blind spot, and the blind spot is the point of the three focused cases beside it: a
simulated publisher never *restarts in the middle of a `stNum`*, and a real one does. A random
simulation explores the states its generator can reach; the ones it cannot still need a
reader and a named test.

## Fuzzing

Ten `cargo-fuzz` targets, each smoke-run for 60 seconds in CI:

| Target | What it hunts |
|---|---|
| `goose_frame` | Frame → PDU → owned → re-encode → decode, plus the subscriber and its timers |
| `sv_frame` | The sampled-value decode path and the multi-stream subscriber |
| `sv_publisher` | Arbitrary sample bytes and counters through the template patching, on both template layouts — with and without `refrTm` and `gmIdentity` — decoded back and compared field by field; a patch writing outside its field shows up here |
| `ber_data` | Every accessor on every TLV, plus a `Value` round trip |
| `scl_load` | The SCL loader on arbitrary bytes |
| `scl_subscriptions` | Resolving one IED's `ExtRef`s against the publishers in the same document, which walks between IEDs in a way `scl_load` never does |
| `pcap_read` | The capture reader, which is fed files from anywhere |
| `mms_stack` | Every OSI layer from arbitrary bytes: TPKT reassembly across a split, COTP, session, presentation, ACSE, MMS — with the MMS encoder required to be a fixed point |
| `mms_association` | The association state machine in **both** roles, fed a peer's bytes seven at a time: nothing panics, a closed association never asks to be woken again, and `abort` is always terminal |
| `mms_server` | Arbitrary requests into the ACSI server over a real model, on **two** associations so the ownership rules are exercised rather than trivially satisfied. Every answer must *encode* — one that does not is a request a client waits for ever on — and every report the server emits must decode |

`mms_stack` reaches the IEC 61850 layer as well: any information report that decodes as a
report, and any value that decodes as an `Oper` or a `LastApplError`, must re-encode to the
same thing. A report has no tags — which field the third value is depends entirely on
`OptFlds` — so a fixed-point property is the only automatic way to catch one being read at the
wrong offset.

The fixed-point requirement earns its place. It has found three defects no capture contains: a
`Confirmed-ErrorPDU` whose optional `modifierPosition` was skipped *by position* rather than
matched by tag; a `reject-PDU` reason read from a **constructed** `[0]`, the tag that means
`originalInvokeID`; and a confirmed request with a **negative `invokeID`**, which is
`Unsigned32` and which the server's answer has to name. The last two are one lesson from
opposite ends: a range the wire declares is a range the *decoder* has to enforce, because
everything downstream is written assuming it holds.

**A crashing input stops being an artifact once the bug is fixed.** `cargo fuzz` writes one to
`fuzz/artifacts/<target>/crash-<hash>`: gitignored, hash-named, and gone the moment someone
cleans the directory — which is to say the evidence disappears exactly when the bug could come
back. Each is therefore renamed after the bug it found, committed under `fuzz/regressions/`,
and replayed by `cargo test --test regressions` through the same entry points the fuzz target
uses.

## Zero allocations, counted

"The steady state allocates nothing" is the sort of claim that is true when it is written and
quietly false three commits later — a `to_vec()` in an error path, a buffer rebuilt instead
of cleared. A counting `#[global_allocator]` turns it into a number a test asserts on, with
no dependency and nothing to run by hand:

| Path | Allocations |
|---|---|
| GOOSE publisher, 1000 retransmissions | 0 |
| GOOSE publisher, 1000 **state changes** | 0 |
| GOOSE publisher, 1000 `publish_if_changed` comparisons | 0 |
| Sampled-value publisher, one second of IEC 61869-9 at 2400 frames/s with `refrTm` per frame | 0 |
| Sampled-value publisher, the same second through `publish_repeating` | 0 |
| Sampled-value subscriber, receiving that second and decoding **every channel** of every ASDU | 0 |
| GOOSE subscriber, 100 retransmissions | 0 |

Zero is not free. `stNum`, `sqNum` and `timeAllowedtoLive` change encoded width as they grow,
so the GOOSE buffers reserve a computed worst case at construction rather than growing around
the 128th frame; the sampled-value publisher patches a template it encoded once.

The GOOSE *subscriber* is exempt on a state change, by design: it hands the application owned
values. The test measures that boundary rather than pretending it is not there.

## Real corpora, not just fixtures

A hand-written fixture tests what the author already believes. The vendor captures above and
`OpenSCD`'s SCL files are wired into the suite because they test what the author does not.

**The vendor captures are also the oracle for anything that replaces something.** The
dataset-driven sample layout — channels read out of an SCL data set instead of a hard-coded
9-2LE struct — is only a replacement for the hard-coded path if it agrees with it on real
traffic, so all 10,161 captured ASDUs must decode to the same sixteen values through both.
That assertion is what makes the general case trustworthy rather than merely present.

**OpenSCD's SCL files.** Every data-set member of every IED whose types resolve must resolve,
every addressed sampled-value stream must produce a channel layout whose length matches the
ASDU length summed independently, and `valid2007B4.scd` is pinned to the findings it is known
to have, so a new false positive fails the build.

Real files are shaped differently from fixtures. A fixture puts the element being looked up
first; a real `DOType` puts it fourth. **One of seven `ExtRef`s in this corpus carries
`srcCBName`** — which is why subscription resolution has to follow the signal into the
publisher's data sets rather than only read the finished binding.

**A corpus is evidence only about the shapes it contains**, which is why the fixtures written
here are checked against something that was not: the SCL schema, and Wireshark. A data set whose
members are data *objects* rather than single attributes, a report too large for the negotiated
PDU, a setting declared once and served under two functional constraints — each is a shape a
suite written alongside the code will agree with itself about, and each is in the corpus for
that reason.

## Panic-freedom by construction

`#![forbid(unsafe_code)]` across the library, which cannot be opted out of anywhere inside
it. Exactly one target in the repository allows `unsafe`, visibly and with a comment saying
why: the allocation test above, for an allocator that delegates every call to the system one
and adds a relaxed counter. `unwrap`, `expect`, `panic` and slice indexing are
denied by lint in library code, so a decoder cannot reach for them: every malformed byte
becomes an error with a reason and a byte offset.

Decoders enforce limits — nesting depth, data-set members, primitive length, ASDUs per frame
— **before** allocating. Event queues are bounded and count what they drop, so a 4.8 kHz
stream feeding an application that has stopped draining cannot exhaust memory.

## Other gates

Every push runs `clippy -D warnings`, `rustfmt`, a `no_std` build for
`thumbv7em-none-eabihf`, a minimum-supported-Rust-version check, and a build and doctest of
**every feature on its own** — `std`, `goose`, `sv`, `mms`, `scl`, `pcap`, `client`, `server`,
`cli` — and with none of them.

The per-feature build matters: a type in the wrong module compiles perfectly until the module
it borrows from is switched off, and no full-feature run can notice. The no-feature build is
in the matrix for the same reason, and it is what holds the crate to being `no_std` **+
alloc** everywhere.

Documentation is built with `RUSTDOCFLAGS=-D warnings`, on the all-features build that
docs.rs serves and a reader sees. Only there: a link from the crate root to a feature-gated
module cannot resolve in a subset build, and deleting those links to make a subset green
would trade real documentation for a green log.

## What this does **not** prove

**Nothing here has been through a conformance laboratory.** IEC 61850-10 defines the test
procedures and UCA International Users Group accredited laboratories run them; that has not
happened. A certificate says an independent party verified conformance, and this project
cannot claim one.

**Interoperability testing covers one stack, and only the station bus.** libiec61850 runs
against both halves of this one in CI, which is the strongest evidence on this page — but it
is *one* implementation with its own opinions, and agreeing with an opinion is not conformance.
(One of those opinions is visible above: it spells a log control block's buffer cursor
`OldEntr`/`NewEntr` where IEC 61850-7-2 spells it `OldEnt`/`NewEnt`. This client asks for both;
this server publishes the standard's.) A second and third opinion — IEC61850bean in Java,
csp0924's crates in Rust — are not wired up. Neither is the **process bus** half: libiec61850's
GOOSE and SV publishers and subscribers need a raw-socket adapter this crate does not yet have,
so everything on that bus is still capture files and a dissector.

**Several rules are read from secondary sources.** The IEC standards are paywalled. Where a
rule comes from a public preview, a Wireshark dissector, an open-source implementation or a
paper rather than from the clause itself, the source code says so.

Two places where this matters most. The layout of the IEC 62351-6 layer-2 authentication
extension (§8.2.2) is unread, which is part of why that extension is not implemented. And the
public preview of IEC 62351-6:2020 stops partway through §6.2.1: the normative text that the
replay algorithm applies "regardless if the published GOOSE or Sampled Value APDU has
security", the state-machine variables and the key-management behaviour are all quoted from
it, but the security-check half of Figure 2 and the whole sampled-value state machine of
§6.2.2 are not. The GOOSE verdict here is built from the arrival time and the advertised
`timeAllowedtoLive`, never from the publisher's own timestamp; that is a defensible reading
and it is not a conformance claim.

**No performance numbers are published.** The design is built for the process bus — borrowed
buffers, template patching, no allocation in the steady state — but nothing has been measured
on reference hardware, so no figure is claimed.

**No hardware timing.** Everything above runs on capture files and virtual time. How the
library behaves against a real switch, with a real clock, under load, is untested.
